use sp1_core::utils::SP1CoreProverError;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum WorkerError {
    #[error("All workers failed")]
    AllWorkersFailed,
    #[error("Worker cannot connect")]
    CannotConnect,
    #[error("Worker request timeout")]
    RequestTimeout,
    #[error("Worker IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Worker Serde error: {0}")]
    Serde(#[from] bincode::Error),
    #[error("Worker invalid version")]
    InvalidVersion,
    #[error("Worker invalid request")]
    InvalidRequest,
    #[error("Worker invalid response")]
    InvalidResponse,
    #[error("Worker proof failed: {0}")]
    Prove(#[from] SP1CoreProverError),
}
