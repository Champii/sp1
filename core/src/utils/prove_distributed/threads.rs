use std::{
    sync::mpsc::{sync_channel, SyncSender},
    thread::ScopedJoinHandle,
};

use p3_maybe_rayon::prelude::*;

pub use crate::stark::RiscvAir;

use crate::{
    runtime::ExecutionRecord,
    stark::{MachineProver, MachineRecord, ShardProof, StarkProvingKey},
    utils::{baby_bear_poseidon2::Val, BabyBearPoseidon2, SP1CoreOpts},
};

use super::{Challenger, Commitment, ShardsPublicValues};

fn spawn_thread<
    'scope,
    'env,
    P: MachineProver<BabyBearPoseidon2, RiscvAir<Val>>,
    R: Send + 'env,
>(
    prover: &'env P,
    thread_scope: &'scope std::thread::Scope<'scope, 'env>,
    opts: SP1CoreOpts,
    scope_span: tracing::Span,
    closure: impl Fn(&'env P, &ExecutionRecord) -> R + Send + Sync + 'env,
) -> (
    SyncSender<Vec<ExecutionRecord>>,
    ScopedJoinHandle<'scope, Vec<R>>,
) {
    let _span = scope_span.enter();

    // Spawn a thread for commiting to the shards.
    let span = tracing::Span::current().clone();

    let (records_tx, records_rx) =
        sync_channel::<Vec<ExecutionRecord>>(opts.commit_stream_capacity);

    let commitments_handle = thread_scope.spawn(move || {
        let _span = span.enter();

        let mut res_vec = Vec::new();

        tracing::debug_span!("phase 1 commiter").in_scope(|| {
            for records in records_rx.iter() {
                let res: Vec<_> = tracing::debug_span!("batch").in_scope(|| {
                    let span = tracing::Span::current().clone();

                    records
                        .par_iter()
                        .map(|record| {
                            let _span = span.enter();

                            closure(prover, record)
                        })
                        .collect()
                });

                res_vec.extend(res);
            }
        });

        res_vec
    });

    (records_tx, commitments_handle)
}

pub fn spawn_commit<'scope, 'env, P: MachineProver<BabyBearPoseidon2, RiscvAir<Val>>, R>(
    prover: &'env P,
    thread_scope: &'scope std::thread::Scope<'scope, 'env>,
    opts: SP1CoreOpts,
    scope_span: tracing::Span,
) -> (
    SyncSender<Vec<ExecutionRecord>>,
    ScopedJoinHandle<'scope, Vec<(Commitment, ShardsPublicValues)>>,
) {
    spawn_thread(prover, thread_scope, opts, scope_span, |prover, record| {
        (
            prover.commit(record),
            record.public_values::<Val>()[0..prover.machine().num_pv_elts()].to_vec(),
        )
    })
}

pub fn spawn_prove<'scope, 'env, P: MachineProver<BabyBearPoseidon2, RiscvAir<Val>>>(
    prover: &'env P,
    thread_scope: &'scope std::thread::Scope<'scope, 'env>,
    opts: SP1CoreOpts,
    scope_span: tracing::Span,
    challenger: Challenger,
    pk: &'env StarkProvingKey<BabyBearPoseidon2>,
) -> (
    SyncSender<Vec<ExecutionRecord>>,
    ScopedJoinHandle<'scope, Vec<ShardProof<BabyBearPoseidon2>>>,
) {
    spawn_thread(
        prover,
        thread_scope,
        opts,
        scope_span,
        move |prover, record| {
            prover
                .commit_and_open(&pk, record.clone(), &mut challenger.clone())
                .unwrap()
        },
    )
}
