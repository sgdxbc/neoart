use std::{
    collections::{HashMap, HashSet},
    env::var,
    future::Future,
    mem::replace,
    pin::Pin,
    time::Duration,
};

use rand::{thread_rng, Rng};
use secp256k1::{hashes::sha256, PublicKey, Secp256k1, VerifyOnly};
use serde::{Deserialize, Serialize};
use tokio::{sync::oneshot, time::Instant};

use crate::{
    common::Reorder,
    crypto::{verify_message, CryptoMessage, Signature},
    meta::{
        digest, ClientId, Config, Digest, OpNumber, ReplicaId, RequestNumber, ViewNumber,
        ENTRY_NUMBER, MULTICAST_CONTROL_RESET_PORT,
    },
    transport::{
        simulated,
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
    network_digest: [u8; 32],
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
        match variant {
            MulticastVariant::Disabled => unreachable!(),
            MulticastVariant::HalfSipHash if Self::has_network_signature(&message) => {
                InboundAction::Allow(Message::OrderedRequest(message))
            }
            MulticastVariant::HalfSipHash => InboundAction::Block,
            MulticastVariant::Secp256k1 if Self::has_network_signature(&message) => {
                // selectively verify part of signatures?
                InboundAction::Verify(
                    Message::OrderedRequest(message),
                    Self::verify_ordered_request_secp256k1,
                )
            }
            MulticastVariant::Secp256k1 => InboundAction::Allow(Message::OrderedRequest(message)),
        }
    }

    fn verify_ordered_request_secp256k1(&mut self, _config: &Config) -> bool {
        let message_digest = self.digest();
        let message = if let Message::OrderedRequest(request) = self {
            request
        } else {
            unreachable!();
        };
        let mut digest_in = [0; 52];
        digest_in[0..32].copy_from_slice(&message.link_hash[..]);
        for (digest_byte, byte) in digest_in[16..48].iter_mut().zip(message_digest.iter()) {
            *digest_byte ^= byte;
        }
        digest_in[48..52].copy_from_slice(&message.sequence_number.to_be_bytes()[..]);
        let network_hash = secp256k1::Message::from_hashed_data::<sha256::Hash>(&digest_in[..]);
        message.network_digest = *network_hash.as_ref();
        thread_local! {
            static SECP: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
        }
        SECP.with(|secp| {
            secp.verify_ecdsa(
                &network_hash,
                &secp256k1::ecdsa::Signature::from_compact(&message.network_signature[..]).unwrap(),
                &PublicKey::from_slice(&[
                    0x4, 0x9a, 0xa2, 0xc, 0x8c, 0x99, 0x79, 0xc2, 0x79, 0x40, 0x14, 0xd0, 0x4f,
                    0x4b, 0x1, 0xdc, 0xd9, 0x77, 0x7d, 0xb, 0xf7, 0x9d, 0xa5, 0x3b, 0x2, 0xdd,
                    0xa9, 0x59, 0x89, 0x49, 0xd2, 0x4f, 0xc7, 0x42, 0xdd, 0x98, 0x75, 0x9b, 0x2b,
                    0xb5, 0xf2, 0xc1, 0x98, 0x4f, 0x84, 0x10, 0x9, 0x74, 0x84, 0xa0, 0xd0, 0x25,
                    0xf4, 0x51, 0x81, 0xd4, 0x2e, 0xc3, 0xc3, 0xd0, 0x8e, 0xe5, 0xea, 0x43, 0x85,
                ])
                .unwrap(),
            )
        })
        .is_ok()
    }

    fn verify_multicast_generic(&mut self, config: &Config) -> bool {
        if let Message::MulticastGeneric(generic) = self {
            let primary_id = config.primary(generic.view_number);
            if !verify_message(self, &config.keys[primary_id as usize].public_key()) {
                return false;
            }
        } else {
            unreachable!();
        }
        // this so silly = =
        let message = if let Message::MulticastGeneric(generic) = self {
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

    enable_vote: bool,
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
    pub fn new(
        mut transport: Transport<Self>,
        id: ReplicaId,
        app: impl App + Send + 'static,
        enable_vote: bool,
    ) -> Self {
        // TODO consider avoid side effect in constructor by adding a dedicated
        // initialization method
        transport.create_timer(Duration::ZERO, |node| {
            node.transport.send_raw(
                (
                    node.transport.config.multicast.ip(),
                    MULTICAST_CONTROL_RESET_PORT,
                ),
                &[],
            );
        });
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
            enable_vote,
            vote_buffer: Vec::new(),
            vote_quorums: HashMap::new(),
            vote_number: if enable_vote { 0 } else { u32::MAX },
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
                    network_digest: Default::default(),
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
            MulticastVariant::Secp256k1 => todo!(),
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
        let sequence_number = request.sequence_number;
        self.vote_buffer.push(request);
        assert_eq!(
            self.vote_buffer[0].sequence_number,
            self.speculative_number + 1
        );
        if !self.enable_vote {
            // TODO bypass vote buffer
            self.speculative_number = sequence_number;
            self.speculative_commit();
        }

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
        assert!(self.enable_vote);

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
                self.send_vote();
            }
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
        assert!(self.enable_vote);
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
        assert!(self.enable_vote);
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

impl Drop for Replica {
    fn drop(&mut self) {
        if self.id == self.transport.config.primary(self.view_number)
            && !self.vote_quorums.is_empty()
        {
            println!(
                "estimated voting batch size {}",
                self.log.len() / self.vote_quorums.len()
            );
        }
    }
}

struct Switch<T = simulated::BasicSwitch> {
    sequence_number: u32,
    config: Config,
    underlying: T,
}

impl<T: AsMut<simulated::BasicSwitch>> AsMut<simulated::BasicSwitch> for Switch<T> {
    fn as_mut(&mut self) -> &mut simulated::BasicSwitch {
        self.underlying.as_mut()
    }
}

impl<T> simulated::Switch for Switch<T>
where
    T: simulated::Switch + AsRef<simulated::BasicSwitch>,
{
    fn handle_packet(&mut self, mut packet: simulated::Packet) {
        let multicast = self.config.multicast;
        if packet.destination == (multicast.ip(), multicast.port() + 1).into() {
            self.sequence_number = 0;
            return;
        }
        if packet.destination != multicast {
            return self.underlying.handle_packet(packet);
        }

        self.sequence_number += 1;
        let n = self.sequence_number;
        if var("NEO_NETLOG").as_deref().unwrap_or("0") != "0" {
            println!(
                "* [{:6?}] [{} -> <multicast>] sequence {n} message length {}",
                Instant::now() - self.underlying.as_ref().epoch,
                packet.source,
                packet.buffer[100..].len()
            );
        }
        packet.buffer[0..4].copy_from_slice(&n.to_be_bytes()[..]);
        // this is synchronized with switch program
        packet.buffer[7] = (n & 0xff) as u8;
        packet.buffer[8] = ((n + 1) & 0xff) as u8;

        // currently implementation is not good at handle multicast that varies
        // to much on arriving time, so simply unify it here
        let delay = Duration::from_millis(thread_rng().gen_range(1..10));
        // TODO more elegant than clone addresses
        for &destination in &self.config.replicas {
            self.underlying.handle_packet(simulated::Packet {
                source: packet.source,
                destination,
                buffer: packet.buffer.clone(),
                delay,
                multicast_outgress: true,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::TryInto, net::SocketAddr, time::Duration};

    use tokio::{task::yield_now, time::timeout};

    use crate::{
        common::TestApp,
        crypto::Executor,
        meta::{ClientId, Config, ReplicaId},
        neo::{Message, OrderedRequest},
        transport::{
            simulated::{BasicSwitch, Network},
            Concurrent,
            MulticastVariant::HalfSipHash,
            Run, Transport,
        },
        Client as _,
    };

    use super::{Client, Replica, Switch};

    struct System {
        net: Concurrent<Network<Switch>>,
        replicas: Vec<Concurrent<Replica>>,
        clients: Vec<Client>,
    }

    impl System {
        async fn new(num_client: usize) -> Self {
            let config = Network::config(4, 1);
            let mut net = Network(Switch {
                sequence_number: 0,
                config: config.clone(),
                underlying: BasicSwitch::default(),
            });
            let clients = (0..num_client)
                .map(|i| {
                    Client::new(Transport::new(
                        config.clone(),
                        net.insert_socket(Network::client(i)),
                        Executor::Inline,
                    ))
                })
                .collect::<Vec<_>>();
            let replicas = (0..4)
                .map(|i| {
                    let mut transport = Transport::new(
                        config.clone(),
                        net.insert_socket(config.replicas[i]),
                        Executor::Inline,
                    );
                    transport
                        .listen_multicast(net.multicast_listener(config.replicas[i]), HalfSipHash);
                    let replica = Replica::new(transport, i as ReplicaId, TestApp::default(), true);
                    Concurrent::run(replica)
                })
                .collect::<Vec<_>>();

            let system = Self {
                net: Concurrent::run(net),
                replicas,
                clients,
            };
            yield_now().await;
            system
        }
    }

    #[tokio::test(start_paused = true)]
    async fn single_op() {
        let mut system = System::new(1).await;
        let result = system.clients[0].invoke("hello".as_bytes());
        timeout(
            Duration::from_millis(40),
            system.clients[0].run(async {
                assert_eq!(&result.await, "[1] hello".as_bytes());
            }),
        )
        .await
        .unwrap();

        let mut commit_count = 1;
        for (i, replica) in system.replicas.into_iter().enumerate() {
            if i == 0 {
                assert_eq!(replica.join().await.log.len(), 1);
            } else {
                commit_count += replica.join().await.log.len();
            }
        }
        assert!(commit_count >= 3);
        system.net.join().await;
    }

    #[test]
    fn verify_secp256k1() {
        const SAMPLE_PACKET: &[u8; 112] = b"\x00\x00\x00\x01\xdc\xe1\xaez\x94\xb50\x1a\x91KT\xcb8\x97v\x1c\x01T\xdf\x86\xd8\xcbf\x1d\x7f\xf0\x92\x99\xd7\x1b\x01`!\xff\x17\x9e\x1a\x93I\xc0\xcc\x9bpv\x18\x120\x0b\xc8\x87\xe7KX\xf9i\x87\xaf\xeb\t\x9b}\rvN\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00e\xfb\xe4\xb6f\x01\x00";
        const SAMPLE_PACKET2: &[u8; 112] = b"\x00\x00\x00\x02\x04\xb0mB6\xa8\x9e\xd0\x1f\xefJe5\xcci\x8c/\xfa\x98\xf6v\x8f\x8e\xfc2a\xbe\x87\xbd\xf6\xa2\n\xc5p:\x82\xf5\xff\x96\x1d\xf7\xd9\x04\xf0cp8;\x18\xb4t\x9a\xf6\xaa`\xa9~f>\x92\x9e\x8d\xfcy\xd6\xa3a\x8a*\\\xfbZ\xcc\xbf[6\x04+f\x11\x02\xe4\x10\xd3\x9e.\xbbU2\xe1\xf2\x07\xf1\xd9\xbc'\x00\x00\x0c\x00\x00e\xfb\xe4\xb6f\x01\x00";
        println!("network digest {:?}", &SAMPLE_PACKET2[68..100]);
        let mut message = Message::OrderedRequest(OrderedRequest {
            request_number: 0,
            client_id: ClientId(SocketAddr::from(([12, 0, 0, 101], 46280)), 102),
            op: Vec::new(),
            sequence_number: 1,
            network_digest: Default::default(),
            network_signature: SAMPLE_PACKET[4..68].to_vec(),
            link_hash: SAMPLE_PACKET[68..100].try_into().unwrap(),
        });
        assert!(message.verify_ordered_request_secp256k1(&Config::default()));
        if let Message::OrderedRequest(message) = message {
            let network_digest: [u8; 32] = SAMPLE_PACKET2[68..100].try_into().unwrap();
            assert_eq!(message.network_digest, network_digest);
        } else {
            unreachable!()
        }
    }
}
