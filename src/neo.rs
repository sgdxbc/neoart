use std::{
    collections::{HashMap, HashSet},
    future::Future,
    mem::replace,
    pin::Pin,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::{
    common::Reorder,
    crypto::{verify_message, CryptoMessage, Signature},
    meta::{
        digest, ClientId, Config, Digest, OpNumber, ReplicaId, RequestNumber, ViewNumber,
        ENTRY_NUMBER,
    },
    transport::{
        Destination::{To, ToAll, ToMulticast, ToReplica, ToSelf},
        InboundAction, InboundPacket, MulticastVariant, Node, Transport,
        TransportMessage::{self, Allowed, Signed, Verified},
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
    view_number: ViewNumber,
    sequence_number: u32,
    digest: Digest,
    quorum_signatures: Vec<(ReplicaId, Signature)>,
    vote_number: u32,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MulticastVote {
    view_number: ViewNumber,
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
    fn signature_mut(&mut self) -> &mut Signature {
        match self {
            Self::MulticastGeneric(MulticastGeneric { signature, .. })
            | Self::MulticastVote(MulticastVote { signature, .. })
            | Self::Reply(Reply { signature, .. }) => signature,
            _ => unreachable!(),
        }
    }

    fn digest(&self) -> Digest {
        if let Self::OrderedRequest(message) = self {
            digest(Self::Request(Request {
                client_id: message.client_id,
                request_number: message.request_number,
                op: message.op.clone(),
            }))
        } else {
            digest(self)
        }
    }
}

impl Message {
    fn has_network_signature(message: &OrderedRequest) -> bool {
        !message.network_signature.iter().all(|&b| b == 0)
    }

    fn multicast_action(variant: MulticastVariant, message: OrderedRequest) -> InboundAction<Self> {
        assert_eq!(variant, MulticastVariant::HalfSipHash);
        // TODO perform real verification
        if Self::has_network_signature(&message) {
            InboundAction::Allow(Message::OrderedRequest(message))
        } else {
            InboundAction::Block
        }
    }

    fn verify_multicast_generic(message: &mut Message, config: &Config) -> bool {
        if let Message::MulticastGeneric(generic) = message {
            let primary_id = config.primary(generic.view_number);
            if !verify_message(message, &config.keys[primary_id as usize].public_key()) {
                return false;
            }
        } else {
            unreachable!();
        }
        // this so silly = =
        let message = if let Message::MulticastGeneric(generic) = message {
            generic
        } else {
            unreachable!()
        };
        for &(replica_id, signature) in &message.quorum_signatures {
            let vote = MulticastVote {
                view_number: message.view_number,
                sequence_number: message.sequence_number,
                digest: message.digest,
                replica_id,
                signature,
            };
            if !verify_message(
                &mut Message::MulticastVote(vote),
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
        let message = if let Allowed(Message::Reply(message)) = message {
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
                Message::multicast_action(self.transport.multicast_variant(), request)
            }
            InboundPacket::Unicast {
                message: Message::MulticastVote(message),
                ..
            } => {
                // if message.sequence_number != self.vote_number {
                //     return InboundAction::Block;
                // }
                let replica_id = message.replica_id;
                InboundAction::VerifyReplica(Message::MulticastVote(message), replica_id)
            }
            InboundPacket::Unicast {
                message: Message::MulticastGeneric(message),
                ..
            } => InboundAction::Verify(
                Message::MulticastGeneric(message),
                Message::verify_multicast_generic,
            ),
            _ => InboundAction::Block,
        }
    }

    fn receive_message(&mut self, message: TransportMessage<Self::Message>) {
        match message {
            Verified(Message::OrderedRequest(message))
            | Allowed(Message::OrderedRequest(message)) => self.handle_ordered_request(message),
            Verified(Message::MulticastVote(message)) => self.handle_multicast_vote(message),
            // need to be caution to reuse...
            Signed(Message::MulticastVote(message)) => self.handle_multicast_vote(message),
            Verified(Message::MulticastGeneric(message)) => self.handle_multicast_generic(message),
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
            self.verify_ordered_request(request);
            ordered = self.reorder_ordered_request.expect_next();
        }
    }

    fn verify_ordered_request(&mut self, request: OrderedRequest) {
        let digest = match self.transport.multicast_variant() {
            MulticastVariant::Disabled => unreachable!(),
            // should we instead assert that this digest never be used?
            MulticastVariant::HalfSipHash => Digest::default(),
            // Secp256k1
        };
        let link_hash = replace(&mut self.link_hash, digest);
        if !Message::has_network_signature(&request) {
            if request.link_hash == link_hash {
                self.fast_verify.push(request);
                return;
            }
            todo!() // fallback to slow path
        }

        // assert every buffered message in `fast_verify` has lower sequence
        // number
        self.vote_buffer.append(&mut self.fast_verify);
        self.vote_buffer.push(request);
        assert_eq!(
            self.vote_buffer[0].sequence_number,
            self.speculative_number + 1
        );

        // only trigger a new voting round if there is no outstanding voting
        if self.id == self.transport.config.primary(self.view_number)
            && self.vote_number == self.speculative_number
        {
            let nontrivial_batch = self.close_vote_batch();
            assert!(nontrivial_batch);
            let generic = MulticastGeneric {
                vote_number: self.vote_number,
                // there is no higher certificate collected, only an intention
                // of new voting, so a null certificate is acceptable and
                // reducing replica's verifying workload
                ..MulticastGeneric::default()
            };
            self.transport
                .send_signed_message(ToAll, Message::MulticastGeneric(generic), self.id);
            // TODO set timer
            self.send_vote();
        }
    }

    fn close_vote_batch(&mut self) -> bool {
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
        self.vote_number != self.speculative_number
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
            let nontrivial_batch = self.close_vote_batch();
            // send certificate as soon as possible, even when vote batch is
            // empty
            let generic = MulticastGeneric {
                view_number: self.view_number,
                sequence_number: message.sequence_number,
                digest: message.digest,
                quorum_signatures,
                vote_number: self.vote_number,
                signature: Signature::default(),
            };
            self.transport
                .send_signed_message(ToAll, Message::MulticastGeneric(generic), self.id);
            // if there is no voting reply expected do not resend actively
            if nontrivial_batch {
                // TODO set timer
            }
            self.send_vote();
        }
    }

    fn speculative_commit(&mut self) {
        let end_index = (self.speculative_number - self.vote_buffer[0].sequence_number) as usize;
        if end_index >= self.vote_buffer.len() {
            todo!() // query missing ordered requests
        }
        for request in self.vote_buffer.drain(..=end_index) {
            let mut execute = true;
            if let Some(reply) = self.client_table.get(&request.client_id) {
                if reply.request_number > request.request_number {
                    execute = false;
                }
                if reply.request_number == request.request_number {
                    self.transport.send_signed_message(
                        To(request.client_id.0),
                        Message::Reply(reply.clone()),
                        self.id,
                    );
                    execute = false;
                }
            }
            if execute {
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
            }
            self.log.push(LogEntry { request });
        }
    }

    fn handle_multicast_generic(&mut self, message: MulticastGeneric) {
        if message.sequence_number > self.speculative_number {
            // TODO check local digest match certificate
            self.speculative_number = message.sequence_number;
            self.speculative_commit();
        }
        // TODO detect and handle the case where replica misses at least one
        // whole batch
        if message.vote_number > self.vote_number {
            self.vote_number = message.vote_number;
            self.send_vote();
        }
    }

    fn send_vote(&mut self) {
        assert_ne!(self.vote_number, self.speculative_number);
        let batch_size = (self.vote_number - self.speculative_number) as usize;
        if self.vote_buffer.len() < batch_size {
            assert_ne!(self.id, self.transport.config.primary(self.view_number));
            todo!() // query missing sequence number?
        }
        assert_eq!(
            self.vote_buffer[batch_size - 1].sequence_number,
            self.vote_number
        );
        let vote = MulticastVote {
            view_number: self.view_number,
            sequence_number: self.vote_number,
            digest: digest(&self.vote_buffer[..batch_size as usize]),
            replica_id: self.id,
            signature: Signature::default(),
        };
        let primary_id = self.transport.config.primary(self.view_number);
        let destination = if self.id == primary_id {
            ToSelf
        } else {
            ToReplica(primary_id)
        };
        self.transport
            .send_signed_message(destination, Message::MulticastVote(vote), self.id);
    }
}
