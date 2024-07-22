use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use super::{WorkerEnvelope, WorkerError, WorkerProtocol, WorkerRequest, WorkerResponse};

pub struct WorkerSocket {
    socket: TcpStream,
}

impl WorkerSocket {
    pub async fn connect(url: &str) -> Result<Self, WorkerError> {
        let connect_future = TcpStream::connect(url);

        let socket = timeout(Duration::from_secs(1), connect_future)
            .await
            .map_err(|_| WorkerError::CannotConnect)??;

        Ok(WorkerSocket::from_stream(socket))
    }

    pub fn from_stream(socket: TcpStream) -> Self {
        WorkerSocket { socket }
    }

    pub async fn send(&mut self, packet: WorkerProtocol) -> Result<(), WorkerError> {
        let envelope: WorkerEnvelope = packet.into();

        let data = bincode::serialize(&envelope)?;

        log::debug!("Sending data with size: {:?}", data.len());

        self.socket.write_u64(data.len() as u64).await?;
        self.socket.write_all(&data).await?;

        Ok(())
    }

    pub async fn receive(&mut self) -> Result<WorkerProtocol, WorkerError> {
        let data = self.read_data().await?;

        let envelope: WorkerEnvelope = bincode::deserialize(&data)?;

        envelope.data()
    }

    async fn read_data(&mut self) -> Result<Vec<u8>, WorkerError> {
        let size = self.socket.read_u64().await? as usize;

        log::debug!("Receiving data with size: {size:?}");

        let mut data = Vec::new();

        let mut buf = [0; 1024];
        let mut total_read = 0;

        loop {
            match self.socket.read(&mut buf).await {
                // socket closed
                Ok(n) if n == 0 => {
                    return Err(WorkerError::IO(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected EOF",
                    )));
                }
                Ok(n) => {
                    data.extend_from_slice(&buf[..n]);

                    total_read += n;

                    if total_read == size {
                        return Ok(data);
                    }

                    // TODO: handle the case where the data is bigger than expected
                }
                Err(e) => {
                    log::error!("failed to read from socket; err = {e:?}");

                    return Err(e.into());
                }
            };
        }
    }

    pub async fn request(&mut self, request: WorkerRequest) -> Result<WorkerResponse, WorkerError> {
        self.send(request.into()).await?;

        let response = self.receive().await?;

        match response {
            WorkerProtocol::Response(response) => Ok(response),
            _ => Err(WorkerError::InvalidResponse),
        }
    }

    pub async fn request_with_timeout(
        &mut self,
        request: WorkerRequest,
        duration: Duration,
    ) -> Result<WorkerResponse, WorkerError> {
        let request_future = self.request(request);

        timeout(duration, request_future)
            .await
            .map_err(|_| WorkerError::RequestTimeout)?
    }
}
