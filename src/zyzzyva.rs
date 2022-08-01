use std::{
    collections::{HashMap, HashSet},
    future::Future,
    mem::replace,
    net::SocketAddr,
    pin::Pin,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::{
    crypto::{verify_message, CryptoMessage, Signature},
    meta::{
        deserialize, digest, ClientId, Config, Digest, OpNumber, ReplicaId, RequestNumber,
        ViewNumber,
    },
    transport::{
        Destination::{To, ToAll},
        InboundAction, Receiver, SignedMessage, Transport,
    },
    App,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Request(Request),
    OrderReq(OrderReq, Request),
    SpecResponse(SpecResponse, ReplicaId, Vec<u8>, OrderReq),
    Commit(Commit),
    LocalCommit(LocalCommit),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    client_id: ClientId,
    request_number: RequestNumber,
    op: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderReq {
    view_number: ViewNumber,
    op_number: OpNumber,
    history_digest: Digest,
    message_digest: Digest,
    // nondeterministic: (),
    signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecResponse {
    view_number: ViewNumber,
    op_number: OpNumber,
    history_digest: Digest,
    result_digest: Digest,
    client_id: ClientId,
    request_number: RequestNumber,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    client_id: ClientId,
    certificate: CommitCertificate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommitCertificate {
    spec_response: SpecResponse, // signature cleared
    signatures: Vec<(ReplicaId, Signature)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCommit {
    view_number: ViewNumber,
    message_digest: Digest,
    history_digest: Digest,
    replica_id: ReplicaId,
    client_id: ClientId,
    signature: Signature,
}

impl CryptoMessage for Message {
    fn signature_mut(&mut self) -> &mut Signature {
        match self {
            Self::OrderReq(OrderReq { signature, .. }, _)
            | Self::SpecResponse(SpecResponse { signature, .. }, ..)
            | Self::LocalCommit(LocalCommit { signature, .. }) => signature,
            _ => unreachable!(),
        }
    }

    fn digest(&self) -> Digest {
        match self {
            Self::OrderReq(message, _) => digest(message),
            Self::SpecResponse(message, ..) => digest(message),
            _ => digest(self),
        }
    }
}

// for calling `verify_message` below
impl CryptoMessage for SpecResponse {
    fn signature_mut(&mut self) -> &mut Signature {
        &mut self.signature
    }
}

impl Message {
    fn verify_commit(&mut self, config: &Config) -> bool {
        let certificate = if let Self::Commit(message) = self {
            &message.certificate
        } else {
            unreachable!()
        };
        if certificate.signatures.len() < config.f * 2 + 1 {
            return false;
        }
        for &(replica_id, signature) in &certificate.signatures {
            let mut spec_response = SpecResponse {
                signature,
                ..certificate.spec_response
            };
            if !verify_message(
                &mut spec_response,
                &config.keys[replica_id as usize].public_key(),
            ) {
                return false;
            }
        }
        true
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
    certificate: CommitCertificate,
    result: Vec<u8>,
    local_committed: HashSet<ReplicaId>,
    continuation: oneshot::Sender<Vec<u8>>,
    timer_id: u32,
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
        let spec_response = SpecResponse {
            view_number: 0,
            op_number: 0,
            history_digest: Digest::default(),
            result_digest: Digest::default(),
            client_id: ClientId::default(),
            request_number: 0,
            signature: Signature::from_compact(&[0; 32]).unwrap(),
        };
        self.invoke = Some(Invoke {
            request,
            timer_id: 0,
            continuation,
            certificate: CommitCertificate {
                spec_response,
                signatures: Vec::new(),
            },
            local_committed: HashSet::new(),
            result: Vec::new(),
        });
        self.send_request();
        Box::pin(async { result.await.unwrap() })
    }
}

impl Receiver for Client {
    type Message = Message;

    fn receive_message(&mut self, remote: SocketAddr, message: Self::Message) {
        match message {
            Message::SpecResponse(message, replica_id, result, _) => {
                self.handle_spec_response(remote, message, replica_id, result)
            }
            Message::LocalCommit(message) => self.handle_local_commit(remote, message),
            _ => unreachable!(),
        }
    }
}

impl Client {
    fn handle_spec_response(
        &mut self,
        _remote: SocketAddr,
        mut message: SpecResponse,
        replica_id: ReplicaId,
        result: Vec<u8>,
    ) {
        if message.client_id != self.id || message.request_number != self.request_number {
            return;
        }
        let invoke = if let Some(invoke) = self.invoke.as_mut() {
            invoke
        } else {
            return;
        };

        let signature = replace(
            &mut message.signature,
            Signature::from_compact(&[0; 32]).unwrap(),
        );
        if invoke.certificate.signatures.is_empty() {
            invoke.certificate.spec_response = message;
            invoke.result = result;
        } else if message != invoke.certificate.spec_response {
            println!(
                "! client {:08x} mismatched result request {} replica {}",
                u32::from_ne_bytes(self.id),
                message.request_number,
                replica_id
            );
            return;
        }
        if invoke
            .certificate
            .signatures
            .iter()
            .all(|&(id, _)| replica_id != id)
        {
            invoke.certificate.signatures.push((replica_id, signature));
        }
        // TODO Byzantine mode
        if invoke.certificate.signatures.len() == self.transport.config.n {
            let invoke = self.invoke.take().unwrap();
            self.transport.cancel_timer(invoke.timer_id);
            self.view_number = invoke.certificate.spec_response.view_number;
            invoke.continuation.send(invoke.result).unwrap();
        }
    }

    fn handle_local_commit(&mut self, _remote: SocketAddr, message: LocalCommit) {
        if message.client_id != self.id {
            return;
        }
        let invoke = if let Some(invoke) = self.invoke.as_mut() {
            invoke
        } else {
            return;
        };

        invoke.local_committed.insert(message.replica_id);
        if invoke.local_committed.len() == self.transport.config.f * 2 + 1 {
            let invoke = self.invoke.take().unwrap();
            self.transport.cancel_timer(invoke.timer_id);
            self.view_number = message.view_number; // any possible to go backward?
            invoke.continuation.send(invoke.result).unwrap();
        }
    }

    fn send_request(&mut self) {
        let invoke = self.invoke.as_mut().unwrap();
        if invoke.certificate.signatures.len() < self.transport.config.f * 2 + 1 {
            // timer not set already => this is not a resending
            // force broadcasting first request to let replicas learn routing
            if invoke.timer_id == 0 && self.request_number > 1 {
                let primary = self.transport.config.primary(self.view_number);
                self.transport.send_message(
                    To(self.transport.config.replicas[primary as usize]),
                    Message::Request(invoke.request.clone()),
                );
            } else {
                self.transport
                    .send_message(ToAll, Message::Request(invoke.request.clone()));
            }
        } else {
            let commit = Commit {
                client_id: self.id,
                certificate: CommitCertificate {
                    spec_response: invoke.certificate.spec_response.clone(),
                    signatures: invoke.certificate.signatures[..self.transport.config.f * 2 + 1]
                        .to_vec(),
                },
            };
            self.transport.send_message(ToAll, Message::Commit(commit));
        }

        let request_number = self.request_number;
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
        invoke.timer_id = self
            .transport
            .create_timer(Duration::from_secs(1), on_resend);
    }
}

pub struct Replica {
    transport: Transport<Self>,
    id: ReplicaId,
    view_number: ViewNumber,
    op_number: OpNumber, // speculative committed up to
    app: Box<dyn App + Send>,
    client_table: HashMap<ClientId, (RequestNumber, SignedMessage)>, // always SpecResponse
    log: Vec<LogEntry>,
    commit_certificate: CommitCertificate, // highest
    routes: HashMap<ClientId, SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogEntry {
    view_number: ViewNumber,
    request: Request,
    spec_response: SignedMessage,
    message_digest: Digest,
    history_digest: Digest,
}

impl Receiver for Replica {
    type Message = Message;

    fn inbound_action(&self, buf: &[u8]) -> InboundAction<Self::Message> {
        let message = deserialize(buf);
        match message {
            Message::Request(_) => InboundAction::Allow(message),
            Message::OrderReq(OrderReq { view_number, .. }, _) => {
                InboundAction::VerifyReplica(message, self.transport.config.primary(view_number))
            }
            Message::Commit(_) => InboundAction::Verify(message, Message::verify_commit),
            _ => {
                println!("! unexpected {message:?}");
                InboundAction::Block
            }
        }
    }

    fn receive_message(&mut self, remote: SocketAddr, message: Self::Message) {
        match message {
            Message::Request(message) => self.handle_request(remote, message),
            Message::OrderReq(message, request) => self.handle_order_req(remote, message, request),
            Message::Commit(message) => self.handle_commit(remote, message),
            _ => unreachable!(),
        }
    }

    fn on_signed(&mut self, id: SignedMessage) {
        if let Message::OrderReq(message, request) = self.transport.signed_message(id).unwrap() {
            if self.transport.config.primary(self.view_number) == self.id {
                self.spec_commit(message.clone(), request.clone());
            }
        }
    }
}

impl Replica {
    fn handle_request(&mut self, remote: SocketAddr, message: Request) {
        self.routes.insert(message.client_id, remote);
        if let Some(&(request_number, spec_response)) = self.client_table.get(&message.client_id) {
            if message.request_number < request_number {
                return;
            }
            if message.request_number == request_number {
                self.transport
                    .send_signed_message(To(remote), spec_response);
                return;
            }
        }

        if self.transport.config.primary(self.view_number) != self.id {
            todo!()
        }

        self.op_number += 1;
        let message_digest = digest(&message);
        let previous_digest = if self.op_number == 1 {
            Digest::default()
        } else {
            self.log[(self.op_number - 1) as usize].history_digest
        };
        let history_digest = digest([previous_digest, message_digest]);
        let order_req = self.transport.sign_message(
            self.id,
            Message::OrderReq(
                OrderReq {
                    view_number: self.view_number,
                    op_number: self.op_number,
                    message_digest,
                    history_digest,
                    signature: Signature::from_compact(&[0; 32]).unwrap(),
                },
                message,
            ),
        );
        self.transport.send_signed_message(ToAll, order_req);

        // locally speculative commit in `Receiver::on_signed`
    }

    fn handle_order_req(&mut self, _remote: SocketAddr, message: OrderReq, request: Request) {
        if message.message_digest != digest(&request) {
            println!(
                "! OrderReq incorrect message digest op {}",
                message.op_number
            );
            return;
        }
        if message.view_number < self.view_number {
            return;
        }
        if message.view_number > self.view_number {
            todo!()
        }

        if message.op_number != self.op_number + 1 {
            todo!("reorder request")
        }
        let previous_digest = if self.op_number == 0 {
            Digest::default()
        } else {
            self.log[(self.op_number - 1) as usize].history_digest
        };
        if message.history_digest != digest([previous_digest, message.message_digest]) {
            println!(
                "! OrderReq mismatched history digest op {}",
                message.op_number
            );
            return;
        }

        self.op_number += 1;
        self.spec_commit(message, request);
    }

    fn spec_commit(&mut self, message: OrderReq, request: Request) {
        let result = self.app.replica_upcall(self.op_number, &request.op);
        let history_digest = message.history_digest;
        let message_digest = message.message_digest;
        let spec_response = self.transport.sign_message(
            self.id,
            Message::SpecResponse(
                SpecResponse {
                    view_number: self.view_number,
                    op_number: self.op_number,
                    result_digest: digest(&result),
                    history_digest,
                    client_id: request.client_id,
                    request_number: request.request_number,
                    signature: Signature::from_compact(&[0; 32]).unwrap(),
                },
                self.id,
                result,
                message,
            ),
        );
        let client_id = request.client_id;
        self.log.push(LogEntry {
            view_number: self.view_number,
            request,
            spec_response,
            message_digest,
            history_digest,
        });
        self.transport
            .send_signed_message(To(self.routes[&client_id]), spec_response);
    }

    fn handle_commit(&mut self, remote: SocketAddr, message: Commit) {
        let spec_response = &message.certificate.spec_response;
        if self.view_number > spec_response.view_number {
            return;
        }
        if self.view_number < spec_response.view_number {
            todo!()
        }

        let entry = if let Some(entry) = self.log.get_mut((spec_response.op_number - 1) as usize) {
            entry
        } else {
            todo!()
        };
        if spec_response.history_digest != entry.history_digest {
            todo!()
        }

        if spec_response.op_number <= self.commit_certificate.spec_response.op_number {
            return; // should this go above the previous check?
        }
        self.commit_certificate = message.certificate;
        let local_commit = self.transport.sign_message(
            self.id,
            Message::LocalCommit(LocalCommit {
                view_number: self.view_number,
                message_digest: entry.message_digest,
                history_digest: entry.history_digest,
                replica_id: self.id,
                client_id: message.client_id,
                signature: Signature::from_compact(&[0; 32]).unwrap(),
            }),
        );
        self.transport.send_signed_message(To(remote), local_commit);
    }
}
