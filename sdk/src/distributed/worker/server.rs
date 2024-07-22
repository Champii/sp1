use super::{
    RequestData, WorkerError, WorkerProtocol, WorkerRequest, WorkerResponse, WorkerSocket,
};
use sp1_core::utils::{
    prove_distributed::{self, Challenger, CoreSC, Program, RiscvAir},
    SP1CoreOpts,
};
use sp1_prover::{components::DefaultProverComponents, SP1Prover};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

pub async fn serve_worker(listen_addr: String, orchestrator_addr: String) {
    tokio::spawn(listen_worker(listen_addr, orchestrator_addr));
}

async fn listen_worker(listen_addr: String, orchestrator_addr: String) {
    info!("Listening as a SP1 worker on: {}", listen_addr);

    let listener = TcpListener::bind(listen_addr).await.unwrap();

    loop {
        let Ok((socket, addr)) = listener.accept().await else {
            error!("Error while accepting connection from orchestrator: Closing socket");

            return;
        };

        if addr.ip().to_string() != orchestrator_addr {
            warn!("Unauthorized orchestrator connection from: {}", addr);

            continue;
        }

        // We purposely don't spawn the task here, as we want to block to limit the number
        // of concurrent connections to one.
        if let Err(e) = handle_worker_socket(WorkerSocket::from_stream(socket)).await {
            error!("Error while handling worker socket: {:?}", e);
        }
    }
}

async fn handle_worker_socket(mut socket: WorkerSocket) -> Result<(), WorkerError> {
    while let Ok(protocol) = socket.receive().await {
        match protocol {
            WorkerProtocol::Request(request) => match request {
                WorkerRequest::Ping => handle_ping(&mut socket).await?,
                WorkerRequest::Commit(request_data) => {
                    handle_commit(&mut socket, request_data).await?
                }
                WorkerRequest::Prove {
                    request_data,
                    challenger,
                } => handle_prove(&mut socket, request_data, challenger).await?,
            },
            _ => Err(WorkerError::InvalidRequest)?,
        }
    }

    Ok(())
}

async fn handle_ping(socket: &mut WorkerSocket) -> Result<(), WorkerError> {
    socket
        .send(WorkerProtocol::Response(WorkerResponse::Pong))
        .await
}

async fn handle_commit(
    socket: &mut WorkerSocket,
    request_data: RequestData,
) -> Result<(), WorkerError> {
    let program = Program::from(&request_data.elf);

    let prover = SP1Prover::<DefaultProverComponents>::new();

    let mut opts = SP1CoreOpts::default();
    opts.shard_batch_size = request_data.shard_batch_size;
    opts.shard_size = request_data.shard_size;

    let mut state = request_data.public_values.reset();
    state.shard = request_data.state_shard_start;

    let (commitments, shards_public_values, deferred) = prove_distributed::commit(
        &prover.core_prover,
        &program,
        request_data.checkpoint,
        request_data.nb_checkpoints,
        state,
        opts,
        None,
    )?;

    socket
        .send(WorkerProtocol::Response(WorkerResponse::Commitment {
            commitments,
            shards_public_values,
            deferred,
        }))
        .await
}

async fn handle_prove(
    socket: &mut WorkerSocket,
    request_data: RequestData,
    challenger: Challenger,
) -> Result<(), WorkerError> {
    let program = Program::from(&request_data.elf);
    let config = CoreSC::default();

    let prover = SP1Prover::<DefaultProverComponents>::new();

    let machine = RiscvAir::machine(config.clone());
    let (pk, _vk) = machine.setup(&program);

    let mut opts = SP1CoreOpts::default();
    opts.shard_batch_size = request_data.shard_batch_size;
    opts.shard_size = request_data.shard_size;

    let mut state = request_data.public_values.reset();
    state.shard = request_data.state_shard_start;

    let (proof, deferred) = prove_distributed::prove(
        &prover.core_prover,
        &program,
        &pk,
        request_data.checkpoint,
        request_data.nb_checkpoints,
        state,
        opts,
        challenger,
        None,
    )?;

    socket
        .send(WorkerProtocol::Response(WorkerResponse::Proof(
            proof, deferred,
        )))
        .await
}
