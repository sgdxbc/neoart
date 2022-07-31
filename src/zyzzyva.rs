use std::{collections::HashSet, future::Future, net::SocketAddr, pin::Pin, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::{
    crypto::Signature,
    meta::{
        deserialize, serialize, ClientId, Digest, OpNumber, ReplicaId, RequestNumber, ViewNumber,
    },
    transport::{Receiver, Transport},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ToReplica {
    Request(Request),
    OrderReq(OrderReq, Request),
    Commit(Commit),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ToClient {
    SpecResponse(SpecResponse, ReplicaId, Vec<u8>, OrderReq),
    LocalCommit(LocalCommit),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Request {
    client_id: ClientId,
    request_number: RequestNumber,
    op: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OrderReq {
    view_number: ViewNumber,
    op_number: OpNumber,
    history_digest: Digest,
    message_digest: Digest,
    // nondeterministic: (),
    signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SpecResponse {
    view_number: ViewNumber,
    op_number: OpNumber,
    history_digest: Digest,
    result_digest: Digest,
    client_id: ClientId,
    request_number: RequestNumber,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Commit {
    client_id: ClientId,
    certificate: CommitCertificate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommitCertificate {
    spec_response: SpecResponse,
    signatures: Vec<(ReplicaId, Signature)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalCommit {
    view_number: ViewNumber,
    message_digest: Digest,
    history_digest: Digest,
    replica_id: ReplicaId,
    client_id: ClientId,
    signature: Signature,
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
    type SignedMessage = ();
    fn transport(&mut self) -> &mut Transport<Self> {
        &mut self.transport
    }

    fn receive_message(&mut self, remote: SocketAddr, buf: &[u8]) {
        match deserialize(buf) {
            ToClient::SpecResponse(message, replica_id, result, _) => {
                self.handle_spec_response(remote, message, replica_id, result)
            }
            ToClient::LocalCommit(message) => self.handle_local_commit(message),
        }
    }
}

impl Client {
    fn handle_spec_response(
        &mut self,
        _remote: SocketAddr,
        message: SpecResponse,
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

        let signature = message.signature;
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

    fn handle_local_commit(&mut self, message: LocalCommit) {
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
            if invoke.timer_id == 0 {
                let primary = self.transport.config.primary(self.view_number);
                self.transport
                    .send_message(self.transport.config.replicas[primary as usize], |buf| {
                        serialize(buf, &invoke.request)
                    });
            } else {
                self.transport
                    .send_message_to_all(|buf| serialize(buf, &invoke.request));
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
            self.transport
                .send_message_to_all(|buf| serialize(buf, commit));
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
