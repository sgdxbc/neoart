use std::{collections::HashMap, future::Future, net::SocketAddr, pin::Pin, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::{
    crypto::{Crypto, ExecutorSetting, Signature},
    meta::{deserialize, random_id, serialize, ClientId, OpNumber, ReplicaId, RequestNumber},
    transport::{Receiver, Transport},
    App,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Request {
    client_id: ClientId,
    request_number: RequestNumber,
    op: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    request_number: RequestNumber,
    result: Vec<u8>,
    signature: Signature,
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
    fn transport(&mut self) -> &mut Transport<Self> {
        &mut self.transport
    }

    fn receive_message(&mut self, _remote: SocketAddr, buf: &[u8]) {
        if self.invoke.is_none() {
            return;
        }
        let message: Reply = deserialize(buf);
        if message.request_number != self.invoke.as_ref().unwrap().request.request_number {
            return;
        }
        let invoke = self.invoke.take().unwrap();
        self.transport.cancel_timer(invoke.timer_id);
        invoke.continuation.send(message.result).unwrap();
    }

    type SignedMessage = ();
}

impl Client {
    fn send_request(&mut self) {
        let replica = self.transport.config.replicas[0];
        let request = &self.invoke.as_ref().unwrap().request;
        self.transport
            .send_message(replica, |buf| serialize(buf, request));
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
    crypto: Crypto<Self>,
    op_number: OpNumber,
    app: Box<dyn App + Send>,
    client_table: HashMap<ClientId, Reply>,
    log: Vec<LogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogEntry {
    request: Request,
    reply: Option<Reply>,
}

impl Replica {
    pub fn new(
        transport: Transport<Self>,
        setting: ExecutorSetting,
        id: ReplicaId,
        app: impl App + Send + 'static,
    ) -> Self {
        assert_eq!(id, 0);
        Self {
            crypto: Crypto::new(&transport, id, setting),
            transport,
            op_number: 0,
            app: Box::new(app),
            client_table: HashMap::new(),
            log: vec![],
        }
    }
}

impl Receiver for Replica {
    fn transport(&mut self) -> &mut Transport<Self> {
        &mut self.transport
    }

    fn receive_message(&mut self, remote: SocketAddr, buf: &[u8]) {
        let message: Request = deserialize(buf);
        if let Some(reply) = self.client_table.get(&message.client_id) {
            if reply.request_number > message.request_number {
                return;
            }
            if reply.request_number == message.request_number {
                self.transport
                    .send_message(remote, |buf| serialize(buf, reply));
                return;
            }
        }

        self.op_number += 1;
        self.log.push(LogEntry {
            request: message.clone(),
            reply: None,
        });
        assert_eq!(self.log.len() as OpNumber, self.op_number);
        let result = self.app.replica_upcall(self.op_number, &message.op);
        let reply = Reply {
            request_number: message.request_number,
            result,
            signature: Signature::from_compact(&[0; 64]).unwrap(),
        };

        let client_id = message.client_id;
        let op_number = self.op_number;
        self.crypto.sign(reply, move |receiver, reply| {
            receiver.log[op_number as usize - 1].reply = Some(reply.clone());
            receiver.client_table.insert(client_id, reply.clone());
            receiver
                .transport
                .send_message(remote, |buf| serialize(buf, reply));
        });
    }

    type SignedMessage = Reply;
    fn signature(message: &Self::SignedMessage) -> &Signature {
        &message.signature
    }
    fn set_signature(message: &mut Self::SignedMessage, signature: Signature) {
        message.signature = signature;
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
            Transport::new(config.clone(), net.insert_socket(config.replicas[0])),
            ExecutorSetting::Inline,
            0,
            TestApp::default(),
        );
        let mut client = Client::new(Transport::new(
            config.clone(),
            net.insert_socket(SimulatedNetwork::client(0)),
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
