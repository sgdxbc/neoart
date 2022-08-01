use std::{collections::HashMap, future::Future, net::SocketAddr, pin::Pin, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::{
    crypto::{CryptoMessage, Signature},
    meta::{random_id, ClientId, OpNumber, ReplicaId, RequestNumber},
    transport::{Destination::To, Receiver, SignedMessage, Transport},
    App,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    client_id: ClientId,
    request_number: RequestNumber,
    op: Vec<u8>,
}

impl CryptoMessage for Request {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    request_number: RequestNumber,
    result: Vec<u8>,
    signature: Signature,
}

impl AsMut<Signature> for Reply {
    fn as_mut(&mut self) -> &mut Signature {
        &mut self.signature
    }
}

pub struct Client {
    transport: Transport<Self>,
    id: ClientId,
    request_number: RequestNumber,
    invoke: Option<Invoke>,
}

struct Invoke {
    request: Request,
    continuation: oneshot::Sender<Vec<u8>>,
    timer_id: u32,
}

impl Client {
    pub fn new(transport: Transport<Self>) -> Self {
        Self {
            transport,
            id: random_id(),
            request_number: 0,
            invoke: None,
        }
    }
}

impl AsMut<Transport<Self>> for Client {
    fn as_mut(&mut self) -> &mut Transport<Self> {
        &mut self.transport
    }
}

impl crate::Client for Client {
    fn invoke(&mut self, op: &[u8]) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>> {
        assert!(self.invoke.is_none());
        self.request_number += 1;
        let request = Request {
            client_id: self.id,
            request_number: self.request_number,
            op: op.to_vec(),
        };
        let (continuation, result) = oneshot::channel();
        self.invoke = Some(Invoke {
            request,
            timer_id: 0,
            continuation,
        });
        self.send_request();
        Box::pin(async { result.await.unwrap() })
    }
}

impl Receiver for Client {
    type InboundMessage = Reply;
    type OutboundMessage = Request;

    fn receive_message(&mut self, _remote: SocketAddr, message: Self::InboundMessage) {
        if self.invoke.is_none() {
            return;
        }
        if message.request_number != self.invoke.as_ref().unwrap().request.request_number {
            return;
        }
        let invoke = self.invoke.take().unwrap();
        self.transport.cancel_timer(invoke.timer_id);
        invoke.continuation.send(message.result).unwrap();
    }
}

impl Client {
    fn send_request(&mut self) {
        let replica = self.transport.config.replicas[0];
        let request = &self.invoke.as_ref().unwrap().request;
        self.transport.send_message(To(replica), request);
        let request_number = request.request_number;
        let on_resend = move |receiver: &mut Self| {
            assert_eq!(
                receiver.invoke.as_ref().unwrap().request.request_number,
                request_number
            );
            println!(
                "! client {:08x} resend request {}",
                u32::from_ne_bytes(receiver.id),
                request_number
            );
            receiver.send_request();
        };
        self.invoke.as_mut().unwrap().timer_id = self
            .transport
            .create_timer(Duration::from_secs(1), on_resend);
    }
}

pub struct Replica {
    transport: Transport<Self>,
    op_number: OpNumber,
    app: Box<dyn App + Send>,
    client_table: HashMap<ClientId, (RequestNumber, SignedMessage)>,
    log: Vec<LogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogEntry {
    request: Request,
    reply: SignedMessage,
}

impl Replica {
    pub fn new(transport: Transport<Self>, id: ReplicaId, app: impl App + Send + 'static) -> Self {
        assert_eq!(id, 0);
        Self {
            transport,
            op_number: 0,
            app: Box::new(app),
            client_table: HashMap::new(),
            log: Vec::new(),
        }
    }
}

impl AsMut<Transport<Self>> for Replica {
    fn as_mut(&mut self) -> &mut Transport<Self> {
        &mut self.transport
    }
}

impl Receiver for Replica {
    type InboundMessage = Request;
    type OutboundMessage = Reply;

    fn receive_message(&mut self, remote: SocketAddr, message: Self::InboundMessage) {
        if let Some(&(request_number, reply)) = self.client_table.get(&message.client_id) {
            if request_number > message.request_number {
                return;
            }
            if request_number == message.request_number {
                self.transport.send_signed_message(To(remote), reply);
                return;
            }
        }

        self.op_number += 1;
        let result = self.app.replica_upcall(self.op_number, &message.op);
        let reply = self.transport.sign_message(
            0,
            Reply {
                request_number: message.request_number,
                result,
                signature: Signature::from_compact(&[0; 64]).unwrap(),
            },
        );
        self.log.push(LogEntry {
            request: message.clone(),
            reply,
        });
        assert_eq!(self.log.len() as OpNumber, self.op_number);
        self.transport.send_signed_message(To(remote), reply);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use crate::{
        crypto::ExecutorSetting,
        transport::{Concurrent, Run, SimulatedNetwork, TestApp, Transport},
        Client as _,
    };

    use super::{Client, Replica};

    #[tokio::test(start_paused = true)]
    async fn test_single_op() {
        let config = SimulatedNetwork::config(1, 0);
        let mut net = SimulatedNetwork::default();
        let replica = Replica::new(
            Transport::new(
                config.clone(),
                net.insert_socket(config.replicas[0]),
                ExecutorSetting::Inline,
            ),
            0,
            TestApp::default(),
        );
        let mut client = Client::new(Transport::new(
            config.clone(),
            net.insert_socket(SimulatedNetwork::client(0)),
            ExecutorSetting::Inline,
        ));

        let net = Concurrent::run(net);
        let replica = Concurrent::run(replica);
        let result = client.invoke("hello".as_bytes());
        timeout(
            Duration::from_millis(20),
            client.run(async {
                assert_eq!(&result.await, "[1] hello".as_bytes());
            }),
        )
        .await
        .unwrap();

        let replica = replica.join().await;
        net.join().await;
        assert_eq!(replica.log.len(), 1);
    }
}
