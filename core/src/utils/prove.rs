use std::fs::File;
use std::io::{Seek, Write};
use web_time::Instant;

use crate::air::{MachineAir, PublicValues};
use crate::io::{SP1PublicValues, SP1Stdin};
pub use baby_bear_blake3::BabyBearBlake3;
use p3_challenger::CanObserve;
use p3_field::PrimeField32;
use serde::de::DeserializeOwned;
use serde::Serialize;
use size::Size;

use crate::lookup::InteractionBuilder;
use crate::runtime::{ExecutionRecord, ShardingConfig};
use crate::stark::DebugConstraintBuilder;
use crate::stark::ProverConstraintFolder;
use crate::stark::StarkVerifyingKey;
use crate::stark::Val;
use crate::stark::VerifierConstraintFolder;
use crate::stark::{Com, PcsProverData, RiscvAir, ShardProof, StarkProvingKey, UniConfig};
use crate::stark::{MachineRecord, StarkMachine};
use crate::utils::env::shard_batch_size;
use crate::{
    runtime::{Program, Runtime},
    stark::StarkGenericConfig,
    stark::{LocalProver, OpeningProof, ShardMainData},
};

const LOG_DEGREE_BOUND: usize = 31;

/// Runs a program and returns the public values stream.
pub fn run_test_io(
    program: Program,
    inputs: SP1Stdin,
) -> Result<SP1PublicValues, crate::stark::MachineVerificationError<BabyBearPoseidon2>> {
    let runtime = tracing::info_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Runtime::new(program);
        runtime.write_vecs(&inputs.buffer);
        runtime.run();
        runtime
    });
    let public_values = SP1PublicValues::from(&runtime.state.public_values_stream);
    let _ = run_test_core(runtime)?;
    Ok(public_values)
}

pub fn run_test(
    program: Program,
) -> Result<
    crate::stark::MachineProof<BabyBearPoseidon2>,
    crate::stark::MachineVerificationError<BabyBearPoseidon2>,
> {
    let runtime = tracing::info_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Runtime::new(program);
        runtime.run();
        runtime
    });
    run_test_core(runtime)
}

#[allow(unused_variables)]
pub fn run_test_core(
    runtime: Runtime,
) -> Result<
    crate::stark::MachineProof<BabyBearPoseidon2>,
    crate::stark::MachineVerificationError<BabyBearPoseidon2>,
> {
    let config = BabyBearPoseidon2::new();
    let machine = RiscvAir::machine(config);
    let (pk, vk) = machine.setup(runtime.program.as_ref());

    let record = runtime.record;
    run_test_machine(record, machine, pk, vk)
}

#[allow(unused_variables)]
pub fn run_test_machine<SC, A>(
    record: A::Record,
    machine: StarkMachine<SC, A>,
    pk: StarkProvingKey<SC>,
    vk: StarkVerifyingKey<SC>,
) -> Result<crate::stark::MachineProof<SC>, crate::stark::MachineVerificationError<SC>>
where
    A: MachineAir<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + Air<InteractionBuilder<Val<SC>>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    SC: StarkGenericConfig,
    SC::Val: p3_field::PrimeField32,
    SC::Challenger: Clone,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    OpeningProof<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
{
    #[cfg(feature = "debug")]
    {
        let mut challenger_clone = machine.config().challenger();
        let record_clone = record.clone();
        machine.debug_constraints(&pk, record_clone, &mut challenger_clone);
    }
    let stats = record.stats().clone();
    let cycles = stats.get("cpu_events").unwrap();

    let start = Instant::now();
    let mut challenger = machine.config().challenger();
    let proof = machine.prove::<LocalProver<SC, A>>(&pk, record, &mut challenger);
    let time = start.elapsed().as_millis();
    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    let mut challenger = machine.config().challenger();
    machine.verify(&vk, &proof, &mut challenger)?;

    tracing::info!(
        "summary: cycles={}, e2e={}, khz={:.2}, proofSize={}",
        cycles,
        time,
        (*cycles as f64 / time as f64),
        Size::from_bytes(nb_bytes),
    );

    Ok(proof)
}

fn trace_checkpoint(program: Program, file: &File) -> ExecutionRecord {
    let mut reader = std::io::BufReader::new(file);
    let state = bincode::deserialize_from(&mut reader).expect("failed to deserialize state");
    let mut runtime = Runtime::recover(program.clone(), state);
    let (events, _) = tracing::debug_span!("runtime.trace").in_scope(|| runtime.execute_record());
    events
}

fn trace_checkpoint_raw(program: Program, checkpoint: &Vec<u8>) -> ExecutionRecord {
    let state = bincode::deserialize(checkpoint).expect("failed to deserialize state");
    let mut runtime = Runtime::recover(program.clone(), state);
    let (events, _) = tracing::debug_span!("runtime.trace").in_scope(|| runtime.execute_record());
    events
}

fn reset_seek(file: &mut File) {
    file.seek(std::io::SeekFrom::Start(0))
        .expect("failed to seek to start of tempfile");
}

pub fn run_and_prove<SC: StarkGenericConfig + Send + Sync>(
    program: Program,
    stdin: &SP1Stdin,
    config: SC,
) -> (crate::stark::MachineProof<SC>, Vec<u8>)
where
    SC::Challenger: Clone,
    OpeningProof<SC>: Send + Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    let mut challenger = config.challenger();

    let machine = RiscvAir::machine(config);
    let mut runtime = Runtime::new(program.clone());
    runtime.write_vecs(&stdin.buffer);
    for proof in stdin.proofs.iter() {
        runtime.write_proof(proof.0.clone(), proof.1.clone());
    }
    let (pk, vk) = machine.setup(runtime.program.as_ref());
    let should_batch = shard_batch_size() > 0;

    // If we don't need to batch, we can just run the program normally and prove it.
    if !should_batch {
        runtime.run();
        #[cfg(feature = "debug")]
        {
            let record_clone = runtime.record.clone();
            machine.debug_constraints(&pk, record_clone, &mut challenger);
        }
        let public_values = std::mem::take(&mut runtime.state.public_values_stream);
        let proof = prove_core(machine.config().clone(), runtime);
        return (proof, public_values);
    }

    // Execute the program, saving checkpoints at the start of every `shard_batch_size` cycle range.
    let mut cycles = 0;
    let mut prove_time = 0;
    let mut checkpoints = Vec::new();
    let (public_values_stream, public_values) =
        tracing::info_span!("runtime.state").in_scope(|| loop {
            // Get checkpoint + move to next checkpoint, then save checkpoint to temp file
            let (state, done) = runtime.execute_state();
            let mut tempfile = tempfile::tempfile().expect("failed to create tempfile");
            let mut writer = std::io::BufWriter::new(&mut tempfile);
            bincode::serialize_into(&mut writer, &state).expect("failed to serialize state");
            writer.flush().expect("failed to flush writer");
            drop(writer);
            tempfile
                .seek(std::io::SeekFrom::Start(0))
                .expect("failed to seek to start of tempfile");
            checkpoints.push(tempfile);
            if done {
                return (
                    std::mem::take(&mut runtime.state.public_values_stream),
                    runtime.record.public_values,
                );
            }
        });

    // For each checkpoint, generate events, shard them, commit shards, and observe in challenger.
    let sharding_config = ShardingConfig::default();
    let mut shard_main_datas = Vec::new();

    // If there's only one batch, it already must fit in memory so reuse it later in open multi
    // rather than running the runtime again.
    let reuse_shards = checkpoints.len() == 1;
    let mut all_shards = None;

    vk.observe_into(&mut challenger);
    for file in checkpoints.iter_mut() {
        let mut events = trace_checkpoint(program.clone(), file);
        events.public_values = public_values;

        reset_seek(&mut *file);
        cycles += events.cpu_events.len();
        let shards =
            tracing::debug_span!("shard").in_scope(|| machine.shard(events, &sharding_config));
        let (commitments, commit_data) = tracing::info_span!("commit")
            .in_scope(|| LocalProver::commit_shards(&machine, &shards));

        shard_main_datas.push(commit_data);

        if reuse_shards {
            all_shards = Some(shards.clone());
        }

        for (commitment, shard) in commitments.into_iter().zip(shards.iter()) {
            challenger.observe(commitment);
            challenger.observe_slice(&shard.public_values::<SC::Val>()[0..machine.num_pv_elts()]);
        }
    }

    // For each checkpoint, generate events and shard again, then prove the shards.
    let mut shard_proofs = Vec::<ShardProof<SC>>::new();
    for mut file in checkpoints.into_iter() {
        let shards = if reuse_shards {
            Option::take(&mut all_shards).unwrap()
        } else {
            let mut events = trace_checkpoint(program.clone(), &file);
            events.public_values = public_values;
            reset_seek(&mut file);
            tracing::debug_span!("shard").in_scope(|| machine.shard(events, &sharding_config))
        };
        let start = Instant::now();
        let mut new_proofs = shards
            .into_iter()
            .map(|shard| {
                let config = machine.config();
                let shard_data =
                    LocalProver::commit_main(config, &machine, &shard, shard.index() as usize);

                let chip_ordering = shard_data.chip_ordering.clone();
                let ordered_chips = machine
                    .shard_chips_ordered(&chip_ordering)
                    .collect::<Vec<_>>()
                    .to_vec();
                LocalProver::prove_shard(
                    config,
                    &pk,
                    &ordered_chips,
                    shard_data,
                    &mut challenger.clone(),
                )
            })
            .collect::<Vec<_>>();
        prove_time += start.elapsed().as_millis();
        shard_proofs.append(&mut new_proofs);
    }

    let proof = crate::stark::MachineProof::<SC> { shard_proofs };

    // Prove the program.
    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    tracing::info!(
        "summary: cycles={}, e2e={}, khz={:.2}, proofSize={}",
        cycles,
        prove_time,
        (cycles as f64 / prove_time as f64),
        Size::from_bytes(nb_bytes),
    );

    (proof, public_values_stream)
}

pub fn tmp_entry_point<SC: StarkGenericConfig + Send + Sync>(
    program: Program,
    stdin: &SP1Stdin,
    config: SC,
) -> (crate::stark::MachineProof<SC>, Vec<u8>)
where
    SC::Challenger: Clone,
    OpeningProof<SC>: Send + Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    let machine = RiscvAir::machine(config.clone());
    let mut runtime = Runtime::new(program.clone());
    runtime.write_vecs(&stdin.buffer);
    for proof in stdin.proofs.iter() {
        runtime.write_proof(proof.0.clone(), proof.1.clone());
    }

    let mut checkpoints = 0;

    let (public_values_stream, public_values) =
        tracing::info_span!("runtime.state").in_scope(|| loop {
            // Get checkpoint + move to next checkpoint, then save checkpoint to temp file
            let (state, done) = runtime.execute_state();
            /* let mut tempfile = tempfile::tempfile().expect("failed to create tempfile");
            let mut writer = std::io::BufWriter::new(&mut tempfile);
            bincode::serialize_into(&mut writer, &state).expect("failed to serialize state");
            writer.flush().expect("failed to flush writer");
            drop(writer);
            tempfile
                .seek(std::io::SeekFrom::Start(0))
                .expect("failed to seek to start of tempfile");
            checkpoints.push(tempfile); */
            checkpoints += 1;
            if done {
                return (
                    std::mem::take(&mut runtime.state.public_values_stream),
                    runtime.record.public_values,
                );
            }
        });

    println!("NB CHECKPOINTS: {}", checkpoints);

    let mut shard_proofs = Vec::<ShardProof<SC>>::new();

    for i in 0..checkpoints {
        println!("CHECKPOINT {}/{}", i + 1, checkpoints);
        let shard_data_serialized =
            run_and_prove_partial(program.clone(), stdin, config.clone(), i);
        let shard_data: Vec<ShardProof<SC>> = bincode::deserialize(&shard_data_serialized).unwrap();
        shard_proofs.extend(shard_data);
        println!("CHECKPOINT DONE");
    }

    let proof = crate::stark::MachineProof::<SC> { shard_proofs };

    (proof, public_values_stream)
}

pub fn run_and_prove_partial<SC: StarkGenericConfig + Send + Sync>(
    program: Program,
    stdin: &SP1Stdin,
    config: SC,
    checkpoint_num: usize,
) -> Vec<u8>
where
    SC::Challenger: Clone,
    OpeningProof<SC>: Send + Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    let mut challenger = config.challenger();

    let machine = RiscvAir::machine(config);
    let mut runtime = Runtime::new(program.clone());
    runtime.write_vecs(&stdin.buffer);
    for proof in stdin.proofs.iter() {
        runtime.write_proof(proof.0.clone(), proof.1.clone());
    }
    let (pk, vk) = machine.setup(runtime.program.as_ref());
    // let should_batch = shard_batch_size() > 0;

    // If we don't need to batch, we can just run the program normally and prove it.
    /* if !should_batch {
        runtime.run();
        #[cfg(feature = "debug")]
        {
            let record_clone = runtime.record.clone();
            machine.debug_constraints(&pk, record_clone, &mut challenger);
        }
        let public_values = std::mem::take(&mut runtime.state.public_values_stream);
        let proof = prove_core(machine.config().clone(), runtime);
        return (proof, public_values);
    } */

    // Execute the program, saving checkpoints at the start of every `shard_batch_size` cycle range.
    let mut cycles = 0;
    let mut prove_time = 0;
    let mut checkpoints = Vec::new();
    let (public_values_stream, public_values) =
        tracing::info_span!("runtime.state").in_scope(|| loop {
            // Get checkpoint + move to next checkpoint, then save checkpoint to temp file
            let (state, done) = runtime.execute_state();
            let mut tempfile = tempfile::tempfile().expect("failed to create tempfile");
            let mut writer = std::io::BufWriter::new(&mut tempfile);
            bincode::serialize_into(&mut writer, &state).expect("failed to serialize state");
            writer.flush().expect("failed to flush writer");
            drop(writer);
            tempfile
                .seek(std::io::SeekFrom::Start(0))
                .expect("failed to seek to start of tempfile");
            checkpoints.push(tempfile);
            if done {
                return (
                    std::mem::take(&mut runtime.state.public_values_stream),
                    runtime.record.public_values,
                );
            }
        });

    // For each checkpoint, generate events, shard them, commit shards, and observe in challenger.
    let sharding_config = ShardingConfig::default();
    let mut shard_main_datas = Vec::new();

    // If there's only one batch, it already must fit in memory so reuse it later in open multi
    // rather than running the runtime again.
    // let reuse_shards = checkpoints.len() == 1;
    let reuse_shards = false;
    let mut all_shards = None;

    vk.observe_into(&mut challenger);
    for file in checkpoints.iter_mut() {
        let mut events = trace_checkpoint(program.clone(), file);
        events.public_values = public_values;

        reset_seek(&mut *file);
        cycles += events.cpu_events.len();
        let shards =
            tracing::debug_span!("shard").in_scope(|| machine.shard(events, &sharding_config));
        let (commitments, commit_data) = tracing::info_span!("commit")
            .in_scope(|| LocalProver::commit_shards(&machine, &shards));

        shard_main_datas.push(commit_data);

        if reuse_shards {
            all_shards = Some(shards.clone());
        }

        for (commitment, shard) in commitments.into_iter().zip(shards.iter()) {
            challenger.observe(commitment);
            challenger.observe_slice(&shard.public_values::<SC::Val>()[0..machine.num_pv_elts()]);
        }
    }

    // For each checkpoint, generate events and shard again, then prove the shards.
    let mut shard_proofs = Vec::<ShardProof<SC>>::new();
    let mut file = checkpoints.into_iter().nth(checkpoint_num).unwrap();
    let shards = if reuse_shards {
        Option::take(&mut all_shards).unwrap()
    } else {
        let mut events = trace_checkpoint(program.clone(), &file);
        events.public_values = public_values;
        reset_seek(&mut file);
        tracing::debug_span!("shard").in_scope(|| machine.shard(events, &sharding_config))
    };
    let start = Instant::now();
    let mut new_proofs = shards
        .into_iter()
        .map(|shard| {
            let config = machine.config();
            let shard_data =
                LocalProver::commit_main(config, &machine, &shard, shard.index() as usize);

            let chip_ordering = shard_data.chip_ordering.clone();
            let ordered_chips = machine
                .shard_chips_ordered(&chip_ordering)
                .collect::<Vec<_>>()
                .to_vec();
            LocalProver::prove_shard(
                config,
                &pk,
                &ordered_chips,
                shard_data,
                &mut challenger.clone(),
            )
        })
        .collect::<Vec<_>>();
    prove_time += start.elapsed().as_millis();
    shard_proofs.append(&mut new_proofs);

    // let proof = crate::stark::MachineProof::<SC> { shard_proofs };

    // Prove the program.
    let serialized_proof = bincode::serialize(&shard_proofs).unwrap();
    let nb_bytes = serialized_proof.len();

    tracing::info!(
        "summary: cycles={}, e2e={}, khz={:.2}, proofSize={}",
        cycles,
        prove_time,
        (cycles as f64 / prove_time as f64),
        Size::from_bytes(nb_bytes),
    );

    // (serialized_proof, public_values_stream)
    serialized_proof
}

use serde::Deserialize;
// Define ShardData which needs data necessary for each shard processing
// #[derive(Serialize, Deserialize)]
pub struct ShardData {
    pub program: Program,
    pub checkpoint: Vec<u8>,
    pub public_values: PublicValues<u32, u32>,
    // pub pk: StarkProvingKey<SC>,
    // pub config: SC,
}

#[derive(Serialize, Deserialize)]
pub struct ShardProofResult {
    pub shard_proofs: Vec<ShardProofData>,
}

#[derive(Serialize, Deserialize)]
pub struct ShardProofData {
    pub proof: Vec<u8>,
    // pub commitment: Vec<u8>,
}

/* impl ShardData {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn deserialize(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }
} */

impl ShardProofResult {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn deserialize(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }
}

// Use the provided structs in your primary code logic
fn process_shard<SC>(
    shard_data: ShardData,
    _pk: &StarkProvingKey<SC>,
    _machine: &StarkMachine<SC, RiscvAir<<SC as StarkGenericConfig>::Val>>,
    challenger: &mut SC::Challenger,
) -> Result<ShardProofResult, Box<dyn std::error::Error>>
where
    SC: StarkGenericConfig + Send + Sync + Default,
    SC::Challenger: Clone,
    OpeningProof<SC>: Send + Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    let ShardData {
        program,
        checkpoint,
        public_values,
        // pk,
        // config,
    } = shard_data;

    let config = SC::default();

    println!("TRACE CHECKPOINT");
    // Recreate events and reset seek on the checkpoint file
    let mut events = trace_checkpoint_raw(program.clone(), &checkpoint);
    events.public_values = public_values;

    let machine = RiscvAir::machine(config);
    let (pk, vk) = machine.setup(&program);
    // println!("PK SIZE {:#?}", bincode::serialize(&pk).unwrap().len());

    let sharding_config = ShardingConfig::default();

    println!("DEDUCE SHARDS");
    let shards = machine.shard(events, &sharding_config);

    // let (commitments, _commit_data) = LocalProver::commit_shards(&machine, &shards);
    let len = shards.len();

    let shard_proofs = shards
        .into_iter()
        .enumerate()
        .map(|(i, shard)| {
            println!("PROCESSING SHARD {}/{}", i + 1, len);
            let config = machine.config();
            println!("COMMIT");
            let shard_main_data =
                LocalProver::commit_main(config, &machine, &shard, shard.index() as usize);

            println!("ORDERING");
            let chip_ordering = shard_main_data.chip_ordering.clone();
            let ordered_chips = machine
                .shard_chips_ordered(&chip_ordering)
                .collect::<Vec<_>>()
                .to_vec();

            // let commitment = bincode::serialize(&shard_main_data.main_commit).unwrap();

            println!("PROVE");
            let proof = LocalProver::prove_shard(
                config,
                &pk,
                &ordered_chips,
                shard_main_data,
                &mut challenger.clone(),
            );
            println!("PROVE DONE");

            ShardProofData {
                proof: bincode::serialize(&proof).unwrap(),
                // commitment,
            }
        })
        .collect::<Vec<_>>();

    let proof_result = ShardProofResult { shard_proofs };

    Ok(proof_result)
}

fn distribute_shards_to_workers<SC>(
    shards: Vec<ShardData>,
    pk: &StarkProvingKey<SC>,
    machine: &StarkMachine<SC, RiscvAir<<SC as StarkGenericConfig>::Val>>,
    challenger: &mut SC::Challenger,
) -> Vec<ShardProof<SC>>
where
    SC: StarkGenericConfig + Send + Sync + Default,
    SC::Challenger: Clone,
    OpeningProof<SC>: Send + Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    let mut shard_proofs = Vec::new();
    let len = shards.len();
    for (i, shard_data) in shards.into_iter().enumerate() {
        println!("CHECKPOINT {}/{}", i + 1, len);
        let shard_proof = process_shard(shard_data, pk, machine, challenger).unwrap();
        println!("CHECKPOINT PROOF");
        for proof_data in &shard_proof.shard_proofs {
            let proof: ShardProof<SC> = bincode::deserialize(&proof_data.proof).unwrap();
            shard_proofs.push(proof);
        }
    }
    shard_proofs
}

pub fn run_and_prove2<SC: StarkGenericConfig + Send + Sync + Default>(
    program: Program,
    stdin: &SP1Stdin,
    config: SC,
) -> (crate::stark::MachineProof<SC>, Vec<u8>)
where
    SC::Challenger: Clone,
    OpeningProof<SC>: Send + Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    let mut challenger = config.challenger();

    let machine = RiscvAir::machine(config);
    let mut runtime = Runtime::new(program.clone());
    runtime.write_vecs(&stdin.buffer);
    for proof in stdin.proofs.iter() {
        runtime.write_proof(proof.0.clone(), proof.1.clone());
    }
    let (pk, vk) = machine.setup(runtime.program.as_ref());
    let should_batch = shard_batch_size() > 0;

    if !should_batch {
        runtime.run();
        #[cfg(feature = "debug")]
        {
            let record_clone = runtime.record.clone();
            machine.debug_constraints(&pk, record_clone, &mut challenger);
        }
        let public_values = std::mem::take(&mut runtime.state.public_values_stream);
        let proof = prove_core(machine.config().clone(), runtime);
        return (proof, public_values);
    }

    let mut cycles = 0;
    let mut prove_time = 0;
    let mut checkpoints = Vec::new();
    let (public_values_stream, public_values) =
        tracing::info_span!("runtime.state").in_scope(|| loop {
            let (state, done) = runtime.execute_state();
            let checkpoint = bincode::serialize(&state).expect("failed to serialize state");
            checkpoints.push(checkpoint);
            if done {
                return (
                    std::mem::take(&mut runtime.state.public_values_stream),
                    runtime.record.public_values,
                );
            }
        });

    let sharding_config = ShardingConfig::default();
    let mut shard_main_datas = Vec::new();

    let reuse_shards = checkpoints.len() == 1;
    let mut all_shards = None;

    vk.observe_into(&mut challenger);
    for (i, checkpoint_data) in checkpoints.iter().enumerate() {
        let mut events = trace_checkpoint_raw(program.clone(), &checkpoint_data);
        events.public_values = public_values;

        cycles += events.cpu_events.len();
        let shards =
            tracing::debug_span!("shard").in_scope(|| machine.shard(events, &sharding_config));
        let (commitments, commit_data) = tracing::info_span!("commit")
            .in_scope(|| LocalProver::commit_shards(&machine, &shards));

        shard_main_datas.push(commit_data);

        if reuse_shards {
            all_shards = Some(shards.clone());
        }

        for (commitment, shard) in commitments.into_iter().zip(shards.iter()) {
            challenger.observe(commitment);
            challenger.observe_slice(&shard.public_values::<SC::Val>()[0..machine.num_pv_elts()]);
        }
    }

    let shard_proofs: Vec<ShardProof<SC>> = distribute_shards_to_workers::<SC>(
        checkpoints
            .into_iter()
            .map(|checkpoint| ShardData {
                program: program.clone(),
                checkpoint: checkpoint.clone(),
                public_values: public_values.clone(),
                // pk: pk.clone(),
                // config: machine.config().clone(),
            })
            .collect(),
        &pk,
        &machine,
        &mut challenger,
    );

    let proof = crate::stark::MachineProof::<SC> { shard_proofs };

    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    tracing::info!(
        "summary: cycles={}, e2e={}, khz={:.2}, proofSize={}",
        cycles,
        prove_time,
        (cycles as f64 / prove_time as f64),
        Size::from_bytes(nb_bytes),
    );

    (proof, public_values_stream)
}

pub fn prove_core<SC: StarkGenericConfig>(
    config: SC,
    runtime: Runtime,
) -> crate::stark::MachineProof<SC>
where
    SC::Challenger: Clone,
    OpeningProof<SC>: Send + Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    let mut challenger = config.challenger();

    let machine = RiscvAir::machine(config);
    let (pk, _) = machine.setup(runtime.program.as_ref());

    // Prove the program.
    let start = Instant::now();
    let cycles = runtime.state.global_clk;
    let proof = machine.prove::<LocalProver<_, _>>(&pk, runtime.record, &mut challenger);
    let time = start.elapsed().as_millis();
    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    tracing::info!(
        "summary: cycles={}, e2e={}, khz={:.2}, proofSize={}",
        cycles,
        time,
        (cycles as f64 / time as f64),
        Size::from_bytes(nb_bytes),
    );

    proof
}

#[cfg(debug_assertions)]
#[cfg(not(doctest))]
pub fn uni_stark_prove<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    trace: RowMajorMatrix<SC::Val>,
) -> Proof<UniConfig<SC>>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::ProverConstraintFolder<'a, UniConfig<SC>>>
        + for<'a> Air<p3_uni_stark::DebugConstraintBuilder<'a, SC::Val>>,
{
    p3_uni_stark::prove(&UniConfig(config.clone()), air, challenger, trace, &vec![])
}

#[cfg(not(debug_assertions))]
pub fn uni_stark_prove<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    trace: RowMajorMatrix<SC::Val>,
) -> Proof<UniConfig<SC>>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::ProverConstraintFolder<'a, UniConfig<SC>>>,
{
    p3_uni_stark::prove(&UniConfig(config.clone()), air, challenger, trace, &vec![])
}

#[cfg(debug_assertions)]
#[cfg(not(doctest))]
pub fn uni_stark_verify<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    proof: &Proof<UniConfig<SC>>,
) -> Result<(), p3_uni_stark::VerificationError>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::VerifierConstraintFolder<'a, UniConfig<SC>>>
        + for<'a> Air<p3_uni_stark::DebugConstraintBuilder<'a, SC::Val>>,
{
    p3_uni_stark::verify(&UniConfig(config.clone()), air, challenger, proof, &vec![])
}

#[cfg(not(debug_assertions))]
pub fn uni_stark_verify<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    proof: &Proof<UniConfig<SC>>,
) -> Result<(), p3_uni_stark::VerificationError>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::VerifierConstraintFolder<'a, UniConfig<SC>>>,
{
    p3_uni_stark::verify(&UniConfig(config.clone()), air, challenger, proof, &vec![])
}

pub use baby_bear_keccak::BabyBearKeccak;
pub use baby_bear_poseidon2::BabyBearPoseidon2;
use p3_air::Air;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;

pub mod baby_bear_poseidon2 {

    use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::{extension::BinomialExtensionField, Field};
    use p3_fri::{FriConfig, TwoAdicFriPcs};
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::Poseidon2;
    use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use serde::{Deserialize, Serialize};
    use sp1_primitives::RC_16_30;

    use crate::stark::StarkGenericConfig;

    pub type Val = BabyBear;
    pub type Challenge = BinomialExtensionField<Val, 4>;

    pub type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;
    pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    pub type ValMmcs = FieldMerkleTreeMmcs<
        <Val as Field>::Packing,
        <Val as Field>::Packing,
        MyHash,
        MyCompress,
        8,
    >;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    pub type Dft = Radix2DitParallel;
    pub type Challenger = DuplexChallenger<Val, Perm, 16>;
    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

    pub fn my_perm() -> Perm {
        const ROUNDS_F: usize = 8;
        const ROUNDS_P: usize = 13;
        let mut round_constants = RC_16_30.to_vec();
        let internal_start = ROUNDS_F / 2;
        let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
        let internal_round_constants = round_constants
            .drain(internal_start..internal_end)
            .map(|vec| vec[0])
            .collect::<Vec<_>>();
        let external_round_constants = round_constants;
        Perm::new(
            ROUNDS_F,
            external_round_constants,
            Poseidon2ExternalMatrixGeneral,
            ROUNDS_P,
            internal_round_constants,
            DiffusionMatrixBabyBear,
        )
    }

    pub fn default_fri_config() -> FriConfig<ChallengeMmcs> {
        let perm = my_perm();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress));
        let num_queries = match std::env::var("FRI_QUERIES") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => 100,
        };
        FriConfig {
            log_blowup: 1,
            num_queries,
            proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        }
    }

    pub fn compressed_fri_config() -> FriConfig<ChallengeMmcs> {
        let perm = my_perm();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress));
        let num_queries = match std::env::var("FRI_QUERIES") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => 33,
        };
        FriConfig {
            log_blowup: 3,
            num_queries,
            proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        }
    }

    enum BabyBearPoseidon2Type {
        Default,
        Compressed,
    }

    #[derive(Deserialize)]
    #[serde(from = "std::marker::PhantomData<BabyBearPoseidon2>")]
    pub struct BabyBearPoseidon2 {
        pub perm: Perm,
        pcs: Pcs,
        config_type: BabyBearPoseidon2Type,
    }

    impl BabyBearPoseidon2 {
        pub fn new() -> Self {
            let perm = my_perm();
            let hash = MyHash::new(perm.clone());
            let compress = MyCompress::new(perm.clone());
            let val_mmcs = ValMmcs::new(hash, compress);
            let dft = Dft {};
            let fri_config = default_fri_config();
            let pcs = Pcs::new(27, dft, val_mmcs, fri_config);
            Self {
                pcs,
                perm,
                config_type: BabyBearPoseidon2Type::Default,
            }
        }

        pub fn compressed() -> Self {
            let perm = my_perm();
            let hash = MyHash::new(perm.clone());
            let compress = MyCompress::new(perm.clone());
            let val_mmcs = ValMmcs::new(hash, compress);
            let dft = Dft {};
            let fri_config = compressed_fri_config();
            let pcs = Pcs::new(27, dft, val_mmcs, fri_config);
            Self {
                pcs,
                perm,
                config_type: BabyBearPoseidon2Type::Compressed,
            }
        }
    }

    impl Clone for BabyBearPoseidon2 {
        fn clone(&self) -> Self {
            match self.config_type {
                BabyBearPoseidon2Type::Default => Self::new(),
                BabyBearPoseidon2Type::Compressed => Self::compressed(),
            }
        }
    }

    impl Default for BabyBearPoseidon2 {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Implement serialization manually instead of using serde to avoid cloing the config.
    impl Serialize for BabyBearPoseidon2 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            std::marker::PhantomData::<BabyBearPoseidon2>.serialize(serializer)
        }
    }

    impl From<std::marker::PhantomData<BabyBearPoseidon2>> for BabyBearPoseidon2 {
        fn from(_: std::marker::PhantomData<BabyBearPoseidon2>) -> Self {
            Self::new()
        }
    }

    impl StarkGenericConfig for BabyBearPoseidon2 {
        type Val = BabyBear;
        type Domain = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::Domain;
        type Pcs = Pcs;
        type Challenge = Challenge;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }

        fn challenger(&self) -> Self::Challenger {
            Challenger::new(self.perm.clone())
        }
    }
}

pub(super) mod baby_bear_keccak {

    use p3_baby_bear::BabyBear;
    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriConfig, TwoAdicFriPcs};
    use p3_keccak::Keccak256Hash;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use serde::{Deserialize, Serialize};

    use crate::stark::StarkGenericConfig;

    use super::LOG_DEGREE_BOUND;

    pub type Val = BabyBear;

    pub type Challenge = BinomialExtensionField<Val, 4>;

    type ByteHash = Keccak256Hash;
    type FieldHash = SerializingHasher32<ByteHash>;

    type MyCompress = CompressionFunctionFromHasher<u8, ByteHash, 2, 32>;

    pub type ValMmcs = FieldMerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    pub type Dft = Radix2DitParallel;

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

    #[derive(Deserialize)]
    #[serde(from = "std::marker::PhantomData<BabyBearKeccak>")]
    pub struct BabyBearKeccak {
        pcs: Pcs,
    }
    // Implement serialization manually instead of using serde(into) to avoid cloing the config
    impl Serialize for BabyBearKeccak {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            std::marker::PhantomData::<BabyBearKeccak>.serialize(serializer)
        }
    }

    impl From<std::marker::PhantomData<BabyBearKeccak>> for BabyBearKeccak {
        fn from(_: std::marker::PhantomData<BabyBearKeccak>) -> Self {
            Self::new()
        }
    }

    impl BabyBearKeccak {
        #[allow(dead_code)]
        pub fn new() -> Self {
            let byte_hash = ByteHash {};
            let field_hash = FieldHash::new(byte_hash);

            let compress = MyCompress::new(byte_hash);

            let val_mmcs = ValMmcs::new(field_hash, compress);

            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft {};

            let fri_config = FriConfig {
                log_blowup: 1,
                num_queries: 100,
                proof_of_work_bits: 16,
                mmcs: challenge_mmcs,
            };
            let pcs = Pcs::new(LOG_DEGREE_BOUND, dft, val_mmcs, fri_config);

            Self { pcs }
        }
    }

    impl Default for BabyBearKeccak {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Clone for BabyBearKeccak {
        fn clone(&self) -> Self {
            Self::new()
        }
    }

    impl StarkGenericConfig for BabyBearKeccak {
        type Val = Val;
        type Challenge = Challenge;

        type Domain = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::Domain;

        type Pcs = Pcs;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }

        fn challenger(&self) -> Self::Challenger {
            let byte_hash = ByteHash {};
            Challenger::from_hasher(vec![], byte_hash)
        }
    }
}

pub(super) mod baby_bear_blake3 {

    use p3_baby_bear::BabyBear;
    use p3_blake3::Blake3;
    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriConfig, TwoAdicFriPcs};
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use serde::{Deserialize, Serialize};

    use crate::stark::StarkGenericConfig;

    use super::LOG_DEGREE_BOUND;

    pub type Val = BabyBear;

    pub type Challenge = BinomialExtensionField<Val, 4>;

    type ByteHash = Blake3;
    type FieldHash = SerializingHasher32<ByteHash>;

    type MyCompress = CompressionFunctionFromHasher<u8, ByteHash, 2, 32>;

    pub type ValMmcs = FieldMerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    pub type Dft = Radix2DitParallel;

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

    #[derive(Deserialize)]
    #[serde(from = "std::marker::PhantomData<BabyBearBlake3>")]
    pub struct BabyBearBlake3 {
        pcs: Pcs,
    }

    // Implement serialization manually instead of using serde(into) to avoid cloing the config
    impl Serialize for BabyBearBlake3 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            std::marker::PhantomData::<Self>.serialize(serializer)
        }
    }

    impl From<std::marker::PhantomData<BabyBearBlake3>> for BabyBearBlake3 {
        fn from(_: std::marker::PhantomData<BabyBearBlake3>) -> Self {
            Self::new()
        }
    }

    impl Clone for BabyBearBlake3 {
        fn clone(&self) -> Self {
            Self::new()
        }
    }

    impl BabyBearBlake3 {
        pub fn new() -> Self {
            let byte_hash = ByteHash {};
            let field_hash = FieldHash::new(byte_hash);

            let compress = MyCompress::new(byte_hash);

            let val_mmcs = ValMmcs::new(field_hash, compress);

            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft {};

            let num_queries = match std::env::var("FRI_QUERIES") {
                Ok(value) => value.parse().unwrap(),
                Err(_) => 100,
            };
            let fri_config = FriConfig {
                log_blowup: 1,
                num_queries,
                proof_of_work_bits: 16,
                mmcs: challenge_mmcs,
            };
            let pcs = Pcs::new(LOG_DEGREE_BOUND, dft, val_mmcs, fri_config);

            Self { pcs }
        }
    }

    impl Default for BabyBearBlake3 {
        fn default() -> Self {
            Self::new()
        }
    }

    impl StarkGenericConfig for BabyBearBlake3 {
        type Val = Val;
        type Challenge = Challenge;

        type Domain = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::Domain;

        type Pcs = Pcs;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }

        fn challenger(&self) -> Self::Challenger {
            let byte_hash = ByteHash {};
            Challenger::from_hasher(vec![], byte_hash)
        }
    }
}
