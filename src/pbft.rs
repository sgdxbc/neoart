use std::{collections::HashSet, future::Future, pin::Pin, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::{
    crypto::{CryptoMessage, Signature},
    meta::{ClientId, Digest, OpNumber, ReplicaId, RequestNumber, ViewNumber},
    transport::{
        Destination::{ToAll, ToReplica},
        Node, Transport, TransportMessage,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Request(Request),
    Reply(Reply),
    PrePrepare(PrePrepare, Vec<Request>),
    Prepare(Prepare),
    Commit(Commit),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    client_id: ClientId,
    request_number: RequestNumber,
    op: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    view_number: ViewNumber,
    request_number: RequestNumber,
    client_id: ClientId,
    replica_id: ReplicaId,
    result: Vec<u8>,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrePrepare {
    view_number: ViewNumber,
    op_number: OpNumber,
    digest: Digest,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prepare {
    view_number: ViewNumber,
    op_number: OpNumber,
    digest: Digest,
    replica_id: ReplicaId,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    view_number: ViewNumber,
    op_number: OpNumber,
    digest: Digest,
    replica_id: ReplicaId,
    signature: Signature,
}

impl CryptoMessage for Message {
    fn signature_mut(&mut self) -> &mut Signature {
        match self {
            Self::Request(_) => unreachable!(),
            Self::Reply(Reply { signature, .. })
            | Self::PrePrepare(PrePrepare { signature, .. }, _)
            | Self::Prepare(Prepare { signature, .. })
            | Self::Commit(Commit { signature, .. }) => signature,
        }
    }
}

pub struct Client {
    transport: Transport<Self>,
    id: ClientId,
    request_number: RequestNumber,
    invoke: Option<Invoke>,
    view_number: ViewNumber,
}

struct Invoke {
    request: Request,
    to_all: bool,
    result: Vec<u8>,
    replied_replicas: HashSet<ReplicaId>,
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
            view_number: 0,
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
            to_all: false,
            timer_id: 0,
            continuation,
            result: Vec::new(),
            replied_replicas: HashSet::new(),
        });
        self.send_request();
        Box::pin(async { result.await.unwrap() })
    }
}

impl Node for Client {
    type Message = Message;

    fn receive_message(&mut self, message: TransportMessage<Self::Message>) {
        let message = if let TransportMessage::Allowed(Message::Reply(message)) = message {
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

        // TODO byzantine on first reply
        if invoke.replied_replicas.is_empty() {
            invoke.result = message.result.clone();
        } else if &message.result != &invoke.result {
            println!("! mismatch result");
            return;
        }
        invoke.replied_replicas.insert(message.replica_id);
        if invoke.replied_replicas.len() == self.transport.config.f * 2 + 1 {
            let invoke = self.invoke.take().unwrap();
            self.transport.cancel_timer(invoke.timer_id);
            assert!(message.view_number >= self.view_number);
            self.view_number = message.view_number;
            invoke.continuation.send(message.result).unwrap();
        }
    }
}

impl Client {
    fn send_request(&mut self) {
        let invoke = &self.invoke.as_ref().unwrap();
        // TODO send to all on resend
        self.transport.send_message(
            if invoke.to_all {
                ToAll
            } else {
                ToReplica(self.transport.config.primary(self.view_number))
            },
            Message::Request(invoke.request.clone()),
        );
        let request_number = invoke.request.request_number;
        let on_resend = move |receiver: &mut Self| {
            assert_eq!(
                receiver.invoke.as_ref().unwrap().request.request_number,
                request_number
            );
            println!("! client {} resend request {}", receiver.id, request_number);
            receiver.invoke.as_mut().unwrap().to_all = true;
            receiver.send_request();
        };
        self.invoke.as_mut().unwrap().timer_id = self
            .transport
            .create_timer(Duration::from_secs(1), on_resend);
    }
}
