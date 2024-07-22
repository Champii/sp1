use crate::{
    CoreSC, Prover, SP1Proof, SP1ProofKind, SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin,
};
use anyhow::Result;
use sp1_core::{
    self,
    runtime::{Program, SP1Context},
    stark::RiscvAir,
    utils::{
        prove_distributed::{self},
        SP1ProverOpts,
    },
};
use sp1_prover::{components::DefaultProverComponents, SP1Prover, SP1ProvingKey, SP1VerifyingKey};

use crate::install::block_on;

mod worker;

pub use worker::{
    serve_worker, RequestData, WorkerEnvelope, WorkerError, WorkerPool, WorkerProtocol,
    WorkerRequest, WorkerResponse, WorkerSocket,
};

use crate::provers::ProverType;

pub struct DistributedProver {
    local_prover: SP1Prover,
}

impl DistributedProver {
    pub fn new() -> Self {
        let local_prover = SP1Prover::new();

        Self { local_prover }
    }

    pub async fn prove_distributed(
        &self,
        elf: &[u8],
        stdin: SP1Stdin,
    ) -> Result<SP1ProofWithPublicValues> {
        let mut worker_pool = WorkerPool::new().await?;

        let program = Program::from(&elf);
        let config = CoreSC::default();

        let context = sp1_core::runtime::SP1Context::default();

        let machine = RiscvAir::machine(config.clone());
        let (pk, vk) = machine.setup(&program);

        let (
            checkpoints,
            last_checkpoint,
            public_values_stream,
            public_values,
            opts,
            total_nb_shards,
        ) = prove_distributed::compute_checkpoints(&stdin, &program, worker_pool.len(), context)?;

        let (commitments, shards_public_values) = worker_pool
            .commit(
                &self.local_prover.core_prover,
                &program,
                elf,
                checkpoints.clone(),
                last_checkpoint.clone(),
                total_nb_shards,
                public_values,
                opts,
            )
            .await?;

        let challenger = prove_distributed::observe_commitments(
            &self.local_prover.core_prover,
            &vk,
            commitments,
            shards_public_values,
        );

        let shard_proofs = worker_pool
            .prove(
                &self.local_prover.core_prover,
                &program,
                elf,
                &pk,
                checkpoints.clone(),
                last_checkpoint.clone(),
                total_nb_shards,
                public_values,
                opts,
                challenger.clone(),
            )
            .await?;

        Ok(SP1ProofWithPublicValues {
            proof: SP1Proof::Core(shard_proofs),
            stdin,
            public_values: SP1PublicValues::from(&public_values_stream),
            sp1_version: self.version().to_string(),
        })
    }
}

impl Prover<DefaultProverComponents> for DistributedProver {
    fn id(&self) -> ProverType {
        ProverType::Distributed
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.local_prover.setup(elf)
    }

    fn sp1_prover(&self) -> &SP1Prover {
        &self.local_prover
    }

    fn prove<'a>(
        &'a self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        _opts: SP1ProverOpts,
        _context: SP1Context<'a>,
        _kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues> {
        block_on(self.prove_distributed(&pk.elf, stdin))
    }
}
