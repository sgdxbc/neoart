use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::{
    common::Reorder,
    crypto::{CryptoMessage, Signature},
    meta::{
        digest, ClientId, Digest, OpNumber, ReplicaId, RequestNumber, ViewNumber, ENTRY_NUMBER,
    },
    transport::{
        Destination::{To, ToAll, ToMulticast, ToReplica},
        InboundAction, InboundPacket, Node, Transport, TransportMessage,
    },
    App,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Request(Request),               // sent by client
    OrderedRequest(OrderedRequest), // received by replica
    MulticastGeneric(MulticastGeneric),
    MulticastVote(MulticastVote),
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
    network_signature: Vec<u8>,
    link_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MulticastGeneric {
    sequence_number: u32,
    digest: Digest,
    quorum_signatures: Vec<(ReplicaId, Signature)>,
    vote_number: u32,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MulticastVote {
    sequence_number: u32,
    digest: Digest, // digest over batched requests
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

impl Message {
    fn has_network_signature(message: &OrderedRequest) -> bool {
        !message.network_signature.iter().all(|&b| b == 0)
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
    app: Box<dyn App + Send>,
    client_table: HashMap<ClientId, Reply>,
    log: Vec<LogEntry>,

    // data path
    // every ordered packet go through following states after entering
    // `receive_message` i.e. received:
    // * verified: after verifying the packet is indeed ordered by sequencer.
    //   this is trivial for signed packets but not for linked unsigned ones.
    //   packets are also reordered according to their ordering here so they are
    //   verified in the order of sequence number
    // * voted: after a quorum vote for the packet (batch) to make sure that
    //   they have received identical ordering. if network is trusted this step
    //   is skipped. packet reaches speculative commit point after being voted
    reorder_ordered_request: Reorder<OrderedRequest>, // received and yet to be reordered
    // state for fast verification
    // in fast path all received messages are assumed to be correct despite some
    // of them has no signature. if the received message contains a link hash
    // that matches previous message's digest, it is qualified for fast verify,
    // and is buffered into `fast_verify`. the message in `fast_verify` is not
    // verified yet, however whenever a signed ordered request is truly verified
    // (automatically upon received), every message inside the buffer which has
    // lower sequence number is immediately verified
    // the protocol must fall back to slow path whenever there is a new message
    // (with or without a signature) received whose link hash does not match
    // previous message's digest. this means either / both of current and
    // previous message is incorrect. All buffered messages then have to be
    // moved into a hash map keyed by message digest (i.e. link hash of
    // successive message) and perform slow verification instead.
    // if network promise to sign every ordered message, then link hash is not
    // required and all messages will bypass verifying stage and directly go
    // into vote buffer. in this case a mismatched link hash will not cause
    // falling back to slow path
    fast_verify: Vec<OrderedRequest>, // received, reordered and yet to be verified
    link_hash: [u8; 32],
    // TODO slow verify buffer
    vote_buffer: Vec<OrderedRequest>, // verified and yet to be voted
    vote_quorums: HashMap<(u32, Digest), HashMap<ReplicaId, Signature>>,
    vote_number: u32, // outstanding voting batch is speculative_number..=vote_number
    speculative_number: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogEntry {
    request: OrderedRequest,
    // history digest
}

impl Replica {
    pub fn new(transport: Transport<Self>, id: ReplicaId, app: impl App + Send + 'static) -> Self {
        // TODO send control packet to reset sequence
        Self {
            transport,
            id,
            view_number: 0,
            app: Box::new(app),
            client_table: HashMap::new(),
            log: Vec::with_capacity(ENTRY_NUMBER),
            reorder_ordered_request: Reorder::new(1),
            fast_verify: Vec::new(),
            link_hash: Default::default(),
            vote_buffer: Vec::new(),
            vote_quorums: HashMap::new(),
            vote_number: 0,
            speculative_number: 0,
        }
    }
}

impl AsMut<Transport<Self>> for Replica {
    fn as_mut(&mut self) -> &mut Transport<Self> {
        &mut self.transport
    }
}

impl Node for Replica {
    type Message = Message;

    fn inbound_action(
        &self,
        packet: InboundPacket<'_, Self::Message>,
    ) -> InboundAction<Self::Message> {
        match packet {
            InboundPacket::OrderedMulticast {
                sequence_number,
                signature,
                link_hash,
                message: Message::Request(message),
                ..
            } => {
                let request = OrderedRequest {
                    client_id: message.client_id,
                    request_number: message.request_number,
                    op: message.op,
                    sequence_number,
                    network_signature: signature.to_vec(),
                    link_hash: *link_hash,
                };
                // TODO verify multicast signature
                InboundAction::Allow(Message::OrderedRequest(request))
            }
            InboundPacket::Unicast {
                message: Message::MulticastVote(message),
                ..
            } => {
                let replica_id = message.replica_id;
                InboundAction::VerifyReplica(Message::MulticastVote(message), replica_id)
            }
            _ => InboundAction::Block,
        }
    }

    fn receive_message(&mut self, message: TransportMessage<Self::Message>) {
        match message {
            TransportMessage::Verified(Message::OrderedRequest(message)) => {
                self.handle_ordered_request(message)
            }
            TransportMessage::Verified(Message::MulticastVote(message)) => {
                self.handle_multicast_vote(message)
            }
            TransportMessage::Verified(Message::MulticastGeneric(message)) => {
                self.handle_multicast_generic(message)
            }
            _ => unreachable!(),
        }
    }
}

impl Replica {
    fn handle_ordered_request(&mut self, message: OrderedRequest) {
        // we don't look up client table at this point, because every ordered
        // request will be assigned to different sequence number even if they
        // contains identical client request. so certain states e.g. reordering
        // buffer must be updated before at most once semantic effects
        // just treat it as the message is still in network stack

        let mut ordered = self
            .reorder_ordered_request
            .insert_reorder(message.sequence_number, message);
        while let Some(request) = ordered {
            // TODO change this to the real digest generated by network
            // however is it a good idea to couple protocol implementation with
            // link hash method?
            // is it ok if we limit all verifiable network ordering to use same
            // link hash method i.e. some kind of sha256? if not, currently this
            // is no information exposed to protocol implementation to indicate
            // what underlying multicast variant is
            let digest = digest(Request {
                client_id: request.client_id,
                request_number: request.request_number,
                op: request.op.clone(),
            });

            if !Message::has_network_signature(&request) {
                if request.link_hash != self.link_hash {
                    todo!()
                    // break
                }

                self.fast_verify.push(request);
            } else {
                // assert every buffered message in `fast_verify` has lower
                // sequence number
                self.vote_buffer.extend(self.fast_verify.drain(..));
                self.vote_buffer.push(request);
                if self.id == self.transport.config.primary(self.view_number)
                    && self.vote_number == self.speculative_number
                {
                    self.close_vote_batch();
                    assert!(self.vote_number > self.speculative_number);
                    let generic = MulticastGeneric {
                        vote_number: self.vote_number,
                        ..MulticastGeneric::default()
                    };
                    self.transport.send_signed_message(
                        ToAll,
                        Message::MulticastGeneric(generic),
                        self.id,
                    );
                    // TODO set timer
                }
            }
            self.link_hash = digest;

            ordered = self.reorder_ordered_request.expect_next();
        }
    }

    fn close_vote_batch(&mut self) {
        assert_eq!(self.id, self.transport.config.primary(self.view_number));
        assert!(
            self.vote_number == self.speculative_number,
            "an outstanding voting is ongoing"
        );

        if let Some(message) = self.vote_buffer.last() {
            assert!(
                Message::has_network_signature(message),
                "vote buffer invariant"
            );
            self.vote_number = message.sequence_number;
        }
    }

    fn handle_multicast_vote(&mut self, message: MulticastVote) {
        // TODO assert is primary

        if message.sequence_number != self.vote_number {
            return;
        }

        let quorum = self
            .vote_quorums
            .entry((message.sequence_number, message.digest))
            .or_default();
        quorum.insert(message.replica_id, message.signature);
        if quorum.len() == self.transport.config.f * 2 + 1 {
            let quorum_signatures = quorum
                .iter()
                .map(|(&id, &signature)| (id, signature))
                .collect();

            self.speculative_number = message.sequence_number;
            self.speculative_commit();
            // send certificate as soon as possible, even when vote batch is
            // empty
            self.close_vote_batch();
            let generic = MulticastGeneric {
                sequence_number: message.sequence_number,
                digest: message.digest,
                quorum_signatures,
                vote_number: self.vote_number,
                signature: Signature::default(),
            };
            self.transport
                .send_signed_message(ToAll, Message::MulticastGeneric(generic), self.id);
            if self.vote_number > self.speculative_number {
                // TODO set timer
            }
        }
    }

    fn speculative_commit(&mut self) {
        let i = self
            .vote_buffer
            // any better way?
            .binary_search_by_key(&self.speculative_number, |message| message.sequence_number)
            .unwrap();
        for request in self.vote_buffer.drain(..=i) {
            // TODO this is too weird
            (|| {
                if let Some(reply) = self.client_table.get(&request.client_id) {
                    if reply.request_number > request.request_number {
                        return;
                    }
                    if reply.request_number == request.request_number {
                        self.transport.send_signed_message(
                            To(request.client_id.0),
                            Message::Reply(reply.clone()),
                            self.id,
                        );
                        return;
                    }
                }

                let op_number = request.sequence_number as OpNumber;
                let result = self.app.replica_upcall(op_number, &request.op);
                let reply = Reply {
                    request_number: request.request_number,
                    result,
                    sequence_number: request.sequence_number,
                    replica_id: self.id,
                    signature: Signature::default(),
                };
                self.client_table.insert(request.client_id, reply.clone());
                self.transport.send_signed_message(
                    To(request.client_id.0),
                    Message::Reply(reply),
                    self.id,
                );
            })();

            self.log.push(LogEntry { request });
        }
    }

    fn handle_multicast_generic(&mut self, message: MulticastGeneric) {
        if message.sequence_number > self.speculative_number {
            // TODO check local digest match certificate
            self.speculative_number = message.sequence_number;
            self.speculative_commit();
        }
        if message.vote_number > self.speculative_number {
            let batch_size = (message.vote_number - self.speculative_number) as usize;
            if self.vote_buffer.len() < batch_size {
                todo!(); // state transfer or silently ignore?
            }
            assert_eq!(
                self.vote_buffer[batch_size - 1].sequence_number,
                message.vote_number
            );
            let vote = MulticastVote {
                sequence_number: message.vote_number,
                digest: digest(&self.vote_buffer[..batch_size as usize]),
                replica_id: self.id,
                signature: Signature::default(),
            };
            self.transport.send_signed_message(
                ToReplica(self.transport.config.primary(self.view_number)),
                Message::MulticastVote(vote),
                self.id,
            );
        }
    }
}
