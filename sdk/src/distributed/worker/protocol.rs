use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};
use sp1_core::air::PublicValues;

use sp1_core::runtime::ExecutionRecord;
use sp1_core::utils::prove_distributed::{
    Challenger, Checkpoint, Commitments, PartialProofs, ShardsPublicValues,
};

use super::WorkerError;

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerEnvelope {
    version: u64,
    data: WorkerProtocol,
}

impl WorkerEnvelope {
    pub fn data(self) -> Result<WorkerProtocol, WorkerError> {
        if self.version != include!("./worker.version") {
            return Err(WorkerError::InvalidVersion);
        }

        Ok(self.data)
    }
}

impl From<WorkerProtocol> for WorkerEnvelope {
    fn from(data: WorkerProtocol) -> Self {
        WorkerEnvelope {
            version: include!("./worker.version"),
            data,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerProtocol {
    Request(WorkerRequest),
    Response(WorkerResponse),
}

impl From<WorkerRequest> for WorkerProtocol {
    fn from(req: WorkerRequest) -> Self {
        WorkerProtocol::Request(req)
    }
}

impl From<WorkerResponse> for WorkerProtocol {
    fn from(res: WorkerResponse) -> Self {
        WorkerProtocol::Response(res)
    }
}

impl Display for WorkerProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerProtocol::Request(req) => write!(f, "Request({req})"),
            WorkerProtocol::Response(res) => write!(f, "Response({res})"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkerRequest {
    Ping,
    Commit(RequestData),
    Prove {
        request_data: RequestData,
        challenger: Challenger,
    },
}

impl Display for WorkerRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerRequest::Ping => write!(f, "Ping"),
            WorkerRequest::Commit(_) => {
                write!(f, "Commit")
            }
            WorkerRequest::Prove { .. } => write!(f, "Prove"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestData {
    pub elf: Vec<u8>,
    pub checkpoint: Checkpoint,
    pub nb_checkpoints: usize,
    pub public_values: PublicValues<u32, u32>,
    pub shard_batch_size: usize,
    pub shard_size: usize,
    pub state_shard_start: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkerResponse {
    Pong,
    Commitment {
        commitments: Commitments,
        shards_public_values: Vec<ShardsPublicValues>,
        deferred: ExecutionRecord,
    },
    Proof(PartialProofs, ExecutionRecord),
}

impl Display for WorkerResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerResponse::Pong => write!(f, "Pong"),
            WorkerResponse::Commitment { .. } => write!(f, "Commit"),
            WorkerResponse::Proof(_, _) => write!(f, "Prove"),
        }
    }
}
