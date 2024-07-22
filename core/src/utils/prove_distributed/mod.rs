use p3_challenger::DuplexChallenger;
use p3_symmetric::Hash;

pub use crate::{air::PublicValues, runtime::Program, stark::RiscvAir};

use crate::{
    io::SP1Stdin,
    runtime::{ExecutionRecord, ExecutionState, Runtime, SP1Context},
    stark::{
        MachineProver, ShardProof, StarkGenericConfig, StarkMachine, StarkProvingKey,
        StarkVerifyingKey,
    },
    utils::{
        baby_bear_poseidon2::{Perm, Val},
        BabyBearPoseidon2, SP1CoreOpts, SP1CoreProverError,
    },
};

mod checkpoints;
mod threads;

pub type CoreSC = BabyBearPoseidon2;

pub type Checkpoint = ExecutionState;
pub type Shard = ExecutionRecord;
pub type ShardsPublicValues = Vec<Val>;
pub type Commitments = Vec<Commitment>;
pub type Commitment = Hash<Val, Val, 8>;
pub type PartialProofs = Vec<ShardProof<BabyBearPoseidon2>>;
pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
pub type Machine = StarkMachine<BabyBearPoseidon2, RiscvAir<Val>>;
pub type ProvingKey = StarkProvingKey<BabyBearPoseidon2>;
pub type VerifyingKey = StarkVerifyingKey<BabyBearPoseidon2>;

// This is the entry point of the orchestrator
// It computes the checkpoints to be sent to the workers
pub fn compute_checkpoints(
    stdin: &SP1Stdin,
    program: &Program,
    nb_workers: usize,
    context: SP1Context,
) -> Result<
    (
        Vec<(Checkpoint, usize)>,
        Checkpoint, // last checlpoint
        Vec<u8>,
        PublicValues<u32, u32>,
        SP1CoreOpts,
        u32, // total nb shards
    ),
    SP1CoreProverError,
> {
    log::info!("Computing checkpoints");
    let opts = SP1CoreOpts::default();

    // Execute the program.
    let mut runtime = Runtime::with_context(program.clone(), opts, context);
    runtime.write_vecs(&stdin.buffer);

    for proof in stdin.proofs.iter() {
        runtime.write_proof(proof.0.clone(), proof.1.clone());
    }

    let mut checkpoints_states = Vec::new();

    // Execute the program, saving checkpoints at the start of every `shard_batch_size` cycle range.
    let create_checkpoints_span = tracing::debug_span!("create checkpoints").entered();

    let (total_nb_shards, public_values_stream, public_values) = loop {
        // Execute the runtime until we reach a checkpoint.
        let (checkpoint, done) = runtime
            .execute_state()
            .map_err(SP1CoreProverError::ExecutionError)?;

        let mut checkpoint_file = tempfile::tempfile().map_err(SP1CoreProverError::IoError)?;

        checkpoint
            .save(&mut checkpoint_file)
            .map_err(SP1CoreProverError::IoError)?;

        checkpoints_states.push(checkpoint_file);

        // If we've reached the final checkpoint, break out of the loop.
        if done {
            break (
                runtime.shard() as usize,
                runtime.state.public_values_stream,
                runtime
                    .records
                    .last()
                    .expect("at least one record")
                    .public_values,
            );
        }
    };

    create_checkpoints_span.exit();

    log::info!(
        "Nb shards: {}",
        checkpoints_states.len() * opts.shard_batch_size
    );

    let nb_checkpoints_per_workers =
        (checkpoints_states.len() as f64 / nb_workers as f64).ceil() as usize;

    let last_checkpoint = checkpoints_states
        .last()
        .map(|file| {
            let mut reader = std::io::BufReader::new(file);

            bincode::deserialize_from(&mut reader).expect("failed to deserialize state")
        })
        .unwrap();

    let checkpoints_states = checkpoints_states
        .chunks(nb_checkpoints_per_workers)
        .map(|files| {
            let mut reader = std::io::BufReader::new(&files[0]);

            let checkpoint =
                bincode::deserialize_from(&mut reader).expect("failed to deserialize state");

            (checkpoint, files.len())
        })
        .collect::<Vec<_>>();

    Ok((
        checkpoints_states,
        last_checkpoint,
        public_values_stream,
        public_values,
        opts,
        total_nb_shards as u32,
    ))
}

// This is the entry point of the worker
// It commits the checkpoints and returns the commitments and the public values of the shards
pub fn commit<P: MachineProver<BabyBearPoseidon2, RiscvAir<Val>>>(
    prover: &P,
    program: &Program,
    checkpoint: Checkpoint,
    nb_checkpoints: usize,
    state: PublicValues<u32, u32>,
    opts: SP1CoreOpts,
    deferred_opt: Option<ExecutionRecord>,
) -> Result<(Commitments, Vec<ShardsPublicValues>, ExecutionRecord), SP1CoreProverError> {
    let mut deferred = deferred_opt
        .clone()
        .unwrap_or_else(|| ExecutionRecord::new(program.clone().into()));

    let scope_span = tracing::Span::current().clone();

    std::thread::scope(move |s| {
        let (records_tx, commitments_handle) = threads::spawn_commit::<
            P,
            (Commitment, ShardsPublicValues),
        >(prover, s, opts, scope_span.clone());

        checkpoints::process(
            prover,
            program,
            checkpoint,
            nb_checkpoints,
            state,
            opts,
            records_tx,
            &mut deferred,
            deferred_opt.is_some(),
        );

        let result_vec = commitments_handle.join().unwrap();
        let (commitments, shards_public_values) = result_vec.into_iter().unzip();

        Ok((commitments, shards_public_values, deferred))
    })
}

// When every worker has committed the shards, the orchestrator can observe the commitments
pub fn observe_commitments<P: MachineProver<BabyBearPoseidon2, RiscvAir<Val>>>(
    prover: &P,
    vk: &StarkVerifyingKey<BabyBearPoseidon2>,
    commitments: Commitments,
    shards_public_values: Vec<ShardsPublicValues>,
) -> Challenger {
    log::info!("Observing commitments");

    let mut challenger = prover.machine().config().challenger();

    vk.observe_into(&mut challenger);

    for (commitment, shard_public_values) in
        commitments.into_iter().zip(shards_public_values.iter())
    {
        prover.update(&mut challenger, commitment, &shard_public_values);
    }

    challenger
}

// The workers can now prove the shards thanks to the challenger sent by the orchestrator
pub fn prove<P: MachineProver<BabyBearPoseidon2, RiscvAir<Val>>>(
    prover: &P,
    program: &Program,
    pk: &StarkProvingKey<BabyBearPoseidon2>,
    checkpoint: Checkpoint,
    nb_checkpoints: usize,
    state: PublicValues<u32, u32>,
    opts: SP1CoreOpts,
    challenger: Challenger,
    deferred_opt: Option<ExecutionRecord>,
) -> Result<(PartialProofs, ExecutionRecord), SP1CoreProverError> {
    // Prove the shards.
    let mut deferred = deferred_opt
        .clone()
        .unwrap_or_else(|| ExecutionRecord::new(program.clone().into()));

    let scope_span = tracing::Span::current().clone();

    std::thread::scope(move |s| {
        let (records_tx, shard_proofs_handle) =
            threads::spawn_prove(prover, s, opts, scope_span.clone(), challenger.clone(), pk);

        checkpoints::process(
            prover,
            program,
            checkpoint,
            nb_checkpoints,
            state,
            opts,
            records_tx,
            &mut deferred,
            deferred_opt.is_some(),
        );

        let shard_proofs = shard_proofs_handle.join().unwrap();

        Ok((shard_proofs, deferred))
    })
}
