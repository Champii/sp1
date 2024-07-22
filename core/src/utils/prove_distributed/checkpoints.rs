use std::sync::{mpsc::SyncSender, Arc};

pub use crate::{air::PublicValues, runtime::Program, stark::RiscvAir};

use crate::{
    runtime::{ExecutionRecord, NoOpSubproofVerifier, Runtime},
    stark::{MachineProver, MachineRecord},
    utils::{baby_bear_poseidon2::Val, BabyBearPoseidon2, SP1CoreOpts},
};

use super::Checkpoint;

fn trace_checkpoint(
    program: Program,
    checkpoint: Checkpoint,
    opts: SP1CoreOpts,
) -> (Vec<ExecutionRecord>, Checkpoint) {
    let mut runtime = Runtime::recover(program, checkpoint, opts);

    runtime.subproof_verifier = Arc::new(NoOpSubproofVerifier);

    let (events, _) =
        tracing::debug_span!("runtime.trace").in_scope(|| runtime.execute_record().unwrap());

    let state = runtime.state.clone();

    (events, state)
}

pub fn process<P: MachineProver<BabyBearPoseidon2, RiscvAir<Val>>>(
    prover: &P,
    program: &Program,
    checkpoint: Checkpoint,
    nb_checkpoints: usize,
    state: PublicValues<u32, u32>,
    opts: SP1CoreOpts,
    records_tx: SyncSender<Vec<ExecutionRecord>>,
    deferred: &mut ExecutionRecord,
    is_deferred: bool,
) {
    if is_deferred {
        process_deferred(program, checkpoint, state, opts, records_tx, deferred);
    } else {
        process_regular(
            prover,
            program,
            checkpoint,
            nb_checkpoints,
            state,
            opts,
            records_tx,
            deferred,
        );
    }
}

fn process_regular<P: MachineProver<BabyBearPoseidon2, RiscvAir<Val>>>(
    prover: &P,
    program: &Program,
    mut checkpoint: Checkpoint,
    nb_checkpoints: usize,
    mut state: PublicValues<u32, u32>,
    opts: SP1CoreOpts,
    records_tx: SyncSender<Vec<ExecutionRecord>>,
    deferred: &mut ExecutionRecord,
) {
    tracing::debug_span!("phase 1 record generator").in_scope(|| {
        let mut processed_checkpoints = 0;

        while processed_checkpoints < nb_checkpoints {
            log::info!(
                "Processing checkpoint {}/{}",
                processed_checkpoints + 1,
                nb_checkpoints
            );
            // Trace the checkpoint and reconstruct the execution records.
            let (mut records, new_checkpoint) = tracing::debug_span!("trace checkpoint")
                .in_scope(|| trace_checkpoint(program.clone(), checkpoint, opts));

            checkpoint = new_checkpoint;

            // Update the public values & prover state for the shards which contain "cpu events".
            for record in records.iter_mut() {
                state.shard += 1;
                state.execution_shard = record.public_values.execution_shard;
                state.start_pc = record.public_values.start_pc;
                state.next_pc = record.public_values.next_pc;
                record.public_values = state;
            }

            // Generate the dependencies.
            tracing::debug_span!("generate dependencies")
                .in_scope(|| prover.machine().generate_dependencies(&mut records, &opts));

            // Defer events that are too expensive to include in every shard.
            for record in records.iter_mut() {
                deferred.append(&mut record.defer());
            }

            // See if any deferred shards are ready to be commited to.
            let mut _deferred = deferred.split(false, opts.split_opts);

            // Update the public values & prover state for the shards which do not contain "cpu events"
            // before committing to them.
            state.execution_shard += 1;

            records_tx.send(records).unwrap();

            processed_checkpoints += 1;
        }
    });
}

fn process_deferred(
    program: &Program,
    checkpoint: Checkpoint,
    mut state: PublicValues<u32, u32>,
    opts: SP1CoreOpts,
    records_tx: SyncSender<Vec<ExecutionRecord>>,
    deferred: &mut ExecutionRecord,
) {
    tracing::debug_span!("phase 1 record generator").in_scope(|| {
        // Trace the checkpoint and reconstruct the execution records.
        let (mut records, _) = tracing::debug_span!("trace checkpoint")
            .in_scope(|| trace_checkpoint(program.clone(), checkpoint, opts));

        // Update the public values & prover state for the shards which contain "cpu events".
        for record in records.iter_mut() {
            // state.shard += 1;
            state.execution_shard = record.public_values.execution_shard;
            state.start_pc = record.public_values.start_pc;
            state.next_pc = record.public_values.next_pc;
            record.public_values = state;
        }

        // See if any deferred shards are ready to be commited to.
        let mut deferred = deferred.split(true, opts.split_opts);

        // Update the public values & prover state for the shards which do not contain "cpu events"
        // before committing to them.

        for record in deferred.iter_mut() {
            state.shard += 1;
            state.previous_init_addr_bits = record.public_values.previous_init_addr_bits;
            state.last_init_addr_bits = record.public_values.last_init_addr_bits;
            state.previous_finalize_addr_bits = record.public_values.previous_finalize_addr_bits;
            state.last_finalize_addr_bits = record.public_values.last_finalize_addr_bits;
            state.start_pc = state.next_pc;
            record.public_values = state;
        }

        records_tx.send(deferred).unwrap();
    });
}
