use anyhow::Result;
use sp1_core::{stark::ShardProof, utils::BabyBearPoseidon2};
use sp1_prover::{SP1Prover, SP1Stdin};

use crate::{
    Prover, SP1CompressedProof, SP1Groth16Proof, SP1PlonkProof, SP1Proof, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1VerifyingKey,
};

/// An implementation of [crate::ProverClient] that can generate end-to-end proofs locally.
pub struct DistributedProver {
    prover: SP1Prover,
}

impl DistributedProver {
    /// Creates a new [DistributedProver].
    pub fn new() -> Self {
        let prover = SP1Prover::new();
        Self { prover }
    }
}

impl Prover for DistributedProver {
    fn id(&self) -> String {
        "local".to_string()
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn sp1_prover(&self) -> &SP1Prover {
        &self.prover
    }

    fn prove(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Proof> {
        let proof = self.prover.prove_core(pk, &stdin);
        Ok(SP1ProofWithPublicValues {
            proof: proof.proof.0,
            stdin: proof.stdin,
            public_values: proof.public_values,
        })
    }

    fn prove_partial(
        &self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        checkpoint_nb: usize,
    ) -> Result<Vec<ShardProof<BabyBearPoseidon2>>> {
        let proof = self.prover.prove_core_partial(pk, &stdin, checkpoint_nb);
        Ok(proof)
    }

    fn prove_compressed(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1CompressedProof> {
        let proof = self.prover.prove_core(pk, &stdin);
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs);
        Ok(SP1CompressedProof {
            proof: reduce_proof.proof,
            stdin,
            public_values,
        })
    }

    fn prove_groth16(&self, pk: &SP1ProvingKey, stdin: SP1Stdin) -> Result<SP1Groth16Proof> {
        sp1_prover::build::get_groth16_artifacts_dir();

        let proof = self.prover.prove_core(pk, &stdin);
        let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        let public_values = proof.public_values.clone();
        let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs);
        let compress_proof = self.prover.shrink(reduce_proof);
        let outer_proof = self.prover.wrap_bn254(compress_proof);
        let artifacts_dir = sp1_prover::build::get_groth16_artifacts_dir();
        let proof = self.prover.wrap_groth16(outer_proof, artifacts_dir);
        Ok(SP1ProofWithPublicValues {
            proof,
            stdin,
            public_values,
        })
    }

    fn prove_plonk(&self, _pk: &SP1ProvingKey, _stdin: SP1Stdin) -> Result<SP1PlonkProof> {
        // let proof = self.prover.prove_core(pk, &stdin);
        // let deferred_proofs = stdin.proofs.iter().map(|p| p.0.clone()).collect();
        // let public_values = proof.public_values.clone();
        // let reduce_proof = self.prover.compress(&pk.vk, proof, deferred_proofs);
        // let compress_proof = self.prover.shrink(&pk.vk, reduce_proof);
        // let outer_proof = self.prover.wrap_bn254(&pk.vk, compress_proof);
        // let proof = self.prover.wrap_plonk(outer_proof, artifacts_dir);
        // Ok(SP1ProofWithPublicValues {
        //     proof,
        //     stdin,
        //     public_values,
        // })
        todo!()
    }
}

impl Default for DistributedProver {
    fn default() -> Self {
        Self::new()
    }
}
