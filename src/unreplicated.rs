use std::{collections::HashMap, future::Future, net::SocketAddr, pin::Pin, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::{
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
struct Reply {
    request_number: RequestNumber,
    result: Vec<u8>,
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
}

impl Client {
    fn send_request(&mut self) {
        let replica = self.transport.config.replicas()[0];
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
    op_number: OpNumber,
    app: Box<dyn App + Send>,
    client_table: HashMap<ClientId, Reply>,
}

impl Replica {
    pub fn new(transport: Transport<Self>, id: ReplicaId, app: impl App + Send + 'static) -> Self {
        assert_eq!(id, 0);
        Self {
            transport,
            op_number: 0,
            app: Box::new(app),
            client_table: HashMap::new(),
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
        let result = self.app.replica_upcall(self.op_number, &message.op);
        let reply = Reply {
            request_number: message.request_number,
            result,
        };
        self.client_table.insert(message.client_id, reply.clone());
        self.transport
            .send_message(remote, |buf| serialize(buf, reply));
    }
}
