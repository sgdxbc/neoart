use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::SocketAddr,
    pin::Pin,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::{
    crypto::{CryptoMessage, Signature},
    meta::{ClientId, ReplicaId, RequestNumber, ViewNumber, ENTRY_NUMBER},
    transport::{Destination::ToMulticast, InboundAction, InboundMeta, Receiver, Transport},
    App,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Request(Request),               // sent by client
    OrderedRequest(OrderedRequest), // received by replica
    PrepareRequest(PrepareRequest),
    Reply(Reply),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    client_id: ClientId,
    request_number: RequestNumber,
    op: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderedRequest {
    client_id: ClientId,
    request_number: RequestNumber,
    op: Vec<u8>,
    sequence_number: u32,
    // network_signature: Vec<u8>,
    // chaining if needed
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareRequest {
    sequence_number: u32,
    request: Request,
    replica_id: ReplicaId,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    request_number: RequestNumber,
    sequence_number: u32,
    replica_id: ReplicaId,
    result: Vec<u8>,
    signature: Signature,
}

impl CryptoMessage for Message {
    //
}

pub struct Client {
    transport: Transport<Self>,
    id: ClientId,
    request_number: RequestNumber,
    invoke: Option<Invoke>,
}

struct Invoke {
    request: Request,
    result: Vec<u8>,
    sequence_number: u32,
    speculative_replicas: HashSet<ReplicaId>,
    continuation: oneshot::Sender<Vec<u8>>,
    timer_id: u32,
}

impl Client {
    pub fn new(transport: Transport<Self>) -> Self {
        Self {
            id: transport.create_id(),
            transport,
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
            result: Vec::new(),
            speculative_replicas: HashSet::new(),
            sequence_number: 0,
        });
        self.send_request();
        Box::pin(async { result.await.unwrap() })
    }
}

impl Receiver for Client {
    type Message = Message;

    fn receive_message(&mut self, _remote: SocketAddr, message: Self::Message) {
        let message = if let Message::Reply(message) = message {
            message
        } else {
            unreachable!()
        };
        let invoke = if let Some(invoke) = self.invoke.as_mut() {
            invoke
        } else {
            return;
        };
        if message.request_number != invoke.request.request_number {
            return;
        }

        if invoke.speculative_replicas.is_empty() {
            invoke.sequence_number = message.sequence_number;
            invoke.result = message.result.clone();
        } else if (message.sequence_number, &message.result)
            != (invoke.sequence_number, &invoke.result)
        {
            println!("! mismatch sequence number / result");
            return;
        }
        invoke.speculative_replicas.insert(message.replica_id);
        if invoke.speculative_replicas.len() == self.transport.config.f * 2 + 1 {
            let invoke = self.invoke.take().unwrap();
            self.transport.cancel_timer(invoke.timer_id);
            invoke.continuation.send(message.result).unwrap();
        }
    }
}

impl Client {
    fn send_request(&mut self) {
        let request = &self.invoke.as_ref().unwrap().request;
        self.transport
            .send_message(ToMulticast, Message::Request(request.clone()));
        let request_number = request.request_number;
        let on_resend = move |receiver: &mut Self| {
            assert_eq!(
                receiver.invoke.as_ref().unwrap().request.request_number,
                request_number
            );
            println!("! client {} resend request {}", receiver.id, request_number);
            receiver.send_request();
        };
        self.invoke.as_mut().unwrap().timer_id = self
            .transport
            .create_timer(Duration::from_secs(1), on_resend);
    }
}

pub struct Replica {
    transport: Transport<Self>,
    id: ReplicaId,
    view_number: ViewNumber,
    sequence_number: u32,
    app: Box<dyn App + Send>,
    client_table: HashMap<ClientId, Reply>,
    log: Vec<LogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogEntry {
    request: Request,
}

impl Replica {
    pub fn new(transport: Transport<Self>, id: ReplicaId, app: impl App + Send + 'static) -> Self {
        Self {
            transport,
            id,
            view_number: 0,
            sequence_number: 0,
            app: Box::new(app),
            client_table: HashMap::new(),
            log: Vec::with_capacity(ENTRY_NUMBER),
        }
    }
}

impl AsMut<Transport<Self>> for Replica {
    fn as_mut(&mut self) -> &mut Transport<Self> {
        &mut self.transport
    }
}

impl Receiver for Replica {
    type Message = Message;

    fn inbound_action(&self, meta: InboundMeta<'_>, buf: &[u8]) -> InboundAction<Self::Message> {
        println!("{meta:?}");
        InboundAction::Block
    }

    fn receive_message(&mut self, remote: SocketAddr, message: Self::Message) {}
}
