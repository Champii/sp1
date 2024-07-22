use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use sp1_core::{
    air::PublicValues,
    runtime::Program,
    stark::{MachineProver, MachineRecord, RiscvAir},
    utils::{
        baby_bear_poseidon2::Val,
        prove_distributed::{self, ProvingKey},
        BabyBearPoseidon2, SP1CoreOpts,
    },
};
use sp1_core::{
    runtime::ExecutionRecord,
    utils::prove_distributed::{
        Challenger, Checkpoint, Commitments, PartialProofs, ShardsPublicValues,
    },
};
use tokio::sync::RwLock;

use super::{RequestData, WorkerError, WorkerRequest, WorkerResponse, WorkerSocket};

pub struct WorkerPool {
    workers: BTreeMap<usize, Arc<RwLock<WorkerSocket>>>,
}

impl WorkerPool {
    pub async fn new() -> Result<Self, WorkerError> {
        let workers = Self::spawn_workers().await?;

        Ok(Self { workers })
    }

    pub async fn commit<P: MachineProver<BabyBearPoseidon2, RiscvAir<Val>>>(
        &mut self,
        prover: &P,
        program: &Program,
        elf: &[u8],
        checkpoints: Vec<(Checkpoint, usize)>,
        last_checkpoint: Checkpoint,
        total_nb_shards: u32,
        public_values: PublicValues<u32, u32>,
        opts: SP1CoreOpts,
    ) -> Result<(Commitments, Vec<ShardsPublicValues>), WorkerError> {
        let nb_checkpoints_per_worker = checkpoints.first().unwrap().1;

        let requests = checkpoints
            .into_iter()
            .enumerate()
            .map(|(i, (checkpoint, nb_checkpoints))| {
                let state_shard_start =
                    (i * nb_checkpoints_per_worker * opts.shard_batch_size) as u32;

                WorkerRequest::Commit(RequestData {
                    elf: elf.to_vec(),
                    checkpoint,
                    nb_checkpoints,
                    public_values,
                    shard_batch_size: opts.shard_batch_size,
                    shard_size: opts.shard_size,
                    state_shard_start,
                })
            })
            .collect();

        let commitments_response = self.distribute_work(requests).await?;

        let mut commitments_vec = Vec::new();
        let mut shards_public_values_vec = Vec::new();
        let mut deferred = ExecutionRecord::new(program.clone().into());

        for response in commitments_response {
            let WorkerResponse::Commitment {
                commitments,
                shards_public_values,
                deferred: mut deferred_new,
            } = response
            else {
                return Err(WorkerError::InvalidResponse);
            };

            commitments_vec.extend(commitments);
            shards_public_values_vec.extend(shards_public_values);
            deferred.append(&mut deferred_new);
        }

        let mut state = public_values.reset();
        state.shard = total_nb_shards + 1;

        // handle deferred
        let (deferred_commitments, deferred_shards_public_values, _) = prove_distributed::commit(
            prover,
            &program,
            last_checkpoint.clone(),
            1,
            state,
            opts,
            Some(deferred),
        )?;

        commitments_vec.extend(deferred_commitments);
        shards_public_values_vec.extend(deferred_shards_public_values);

        Ok((commitments_vec, shards_public_values_vec))
    }

    pub async fn prove<P: MachineProver<BabyBearPoseidon2, RiscvAir<Val>>>(
        &mut self,
        prover: &P,
        program: &Program,
        elf: &[u8],
        pk: &ProvingKey,
        checkpoints: Vec<(Checkpoint, usize)>,
        last_checkpoint: Checkpoint,
        total_nb_shards: u32,
        public_values: PublicValues<u32, u32>,
        opts: SP1CoreOpts,
        challenger: Challenger,
    ) -> Result<PartialProofs, WorkerError> {
        let nb_checkpoints_per_worker = checkpoints.first().unwrap().1;

        let requests: Vec<_> = checkpoints
            .into_iter()
            .enumerate()
            .map(|(i, (checkpoint, nb_checkpoints))| {
                let state_shard_start =
                    (i * nb_checkpoints_per_worker * opts.shard_batch_size) as u32;

                WorkerRequest::Prove {
                    request_data: RequestData {
                        elf: elf.to_vec(),
                        checkpoint,
                        nb_checkpoints,
                        public_values: public_values.clone(),
                        shard_batch_size: opts.shard_batch_size,
                        shard_size: opts.shard_size,
                        state_shard_start,
                    },
                    challenger: challenger.clone(),
                }
            })
            .collect();

        let proofs_response = self.distribute_work(requests).await?;

        let mut proofs = Vec::new();

        let mut deferred = ExecutionRecord::new(program.clone().into());

        for response in proofs_response {
            let WorkerResponse::Proof(partial_proof, mut deferred_new) = response else {
                return Err(WorkerError::InvalidResponse);
            };

            proofs.extend(partial_proof);
            deferred.append(&mut deferred_new);
        }

        let mut state = public_values.reset();
        state.shard = total_nb_shards + 1;

        // handle deferred
        let (deferred_shard_proof, _) = prove_distributed::prove(
            prover,
            &program,
            &pk,
            last_checkpoint,
            1,
            state,
            opts,
            challenger,
            Some(deferred),
        )?;

        proofs.extend(deferred_shard_proof);

        Ok(proofs)
    }

    async fn distribute_work(
        &mut self,
        requests: Vec<WorkerRequest>,
    ) -> Result<Vec<WorkerResponse>, WorkerError> {
        use tokio::task::JoinSet;

        let mut set = JoinSet::new();

        // Distribute one request to each available workers
        for (request_idx, (request, (worker_idx, worker))) in requests
            .clone()
            .into_iter()
            .zip(self.workers.iter())
            .enumerate()
        {
            let worker = Arc::clone(worker);
            let worker_idx = worker_idx.clone();

            log::info!("Sp1 Distributed: Sending request to worker {}", request_idx);

            set.spawn(async move {
                (
                    request_idx,
                    worker_idx,
                    worker.write().await.request(request).await,
                )
            });
        }

        let mut results = Vec::new();
        let mut available_workers = VecDeque::new();
        let mut requests_to_redistribute = VecDeque::new();
        let mut failed_workers = Vec::new();

        // If there is more requests than workers, we need to redistribute them later
        if requests.len() > self.workers.len() {
            requests_to_redistribute.extend(self.workers.len()..requests.len());
        }

        while let Some(res) = set.join_next().await {
            let (request_idx, worker_idx, out) = res.map_err(|_e| WorkerError::AllWorkersFailed)?;

            match out {
                Ok(response) => {
                    log::info!("Sp1 Distributed: Got response from worker {}", request_idx);

                    results.push((request_idx, response));

                    // If there is another task to redistribute, do it right away
                    if !requests_to_redistribute.is_empty() {
                        let request_idx = requests_to_redistribute.pop_front().unwrap();
                        let request = requests[request_idx].clone();
                        let worker = Arc::clone(self.workers.get(&worker_idx).unwrap());

                        log::info!(
                            "Sp1 Distributed: Redistributing task to worker {}",
                            worker_idx
                        );

                        set.spawn(async move {
                            (
                                request_idx,
                                worker_idx,
                                worker.write().await.request(request).await,
                            )
                        });
                    } else {
                        available_workers.push_back(worker_idx);
                    }
                }
                Err(_e) => {
                    log::warn!("Sp1 Distributed: Worker {} failed", request_idx);

                    failed_workers.push(worker_idx);

                    if failed_workers.len() == self.workers.len() {
                        return Err(WorkerError::AllWorkersFailed);
                    }

                    // If no other workers finished, push back the request to be picked up when a
                    // worker is available
                    if available_workers.is_empty() {
                        requests_to_redistribute.push_back(request_idx);

                        continue;
                    }

                    let worker_id = available_workers.pop_front().unwrap();
                    let request = requests[request_idx].clone();
                    let worker = Arc::clone(self.workers.get(&worker_id).unwrap());

                    log::info!(
                        "Sp1 Distributed: Redistributing task to worker {}",
                        worker_id
                    );

                    set.spawn(async move {
                        (
                            request_idx,
                            worker_id,
                            worker.write().await.request(request).await,
                        )
                    });
                }
            }
        }

        results.sort_by_key(|(i, _)| *i);

        let results = results.into_iter().map(|(_, response)| response).collect();

        // removing the failed workers from the pool
        for worker_id in failed_workers {
            self.workers.remove(&worker_id);
        }

        Ok(results)
    }

    async fn spawn_workers() -> Result<BTreeMap<usize, Arc<RwLock<WorkerSocket>>>, WorkerError> {
        let ip_list_string = std::fs::read_to_string("distributed.json")
            .expect("Sp1 Distributed: Need a `distributed.json` file with a list of IP:PORT");

        let ip_list: Vec<String> = serde_json::from_str(&ip_list_string).expect(
            "Sp1 Distributed: Invalid JSON for `distributed.json`. need an array of IP:PORT",
        );

        let mut workers = BTreeMap::new();

        // try to connect to each worker to make sure they are reachable
        for (i, ip) in ip_list.into_iter().enumerate() {
            let Ok(mut worker) = WorkerSocket::connect(&ip).await else {
                log::warn!("Sp1 Distributed: Worker at {} is not reachable. Removing from the list for this task", ip);

                continue;
            };

            if let Err(_e) = worker
                .request_with_timeout(WorkerRequest::Ping, Duration::from_secs(1))
                .await
            {
                log::warn!("Sp1 Distributed: Worker at {} is not reachable. Removing from the list for this task", ip);

                continue;
            }

            workers.insert(i, Arc::new(RwLock::new(worker)));
        }

        if workers.len() == 0 {
            log::error!("Sp1 Distributed: No reachable workers found. Aborting...");

            return Err(WorkerError::AllWorkersFailed);
        }

        Ok(workers)
    }

    pub fn len(&self) -> usize {
        self.workers.len()
    }
}
