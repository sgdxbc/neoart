use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::{
    crypto::{verify_message, CryptoMessage, Signature},
    meta::{digest, ClientId, Config, Digest, OpNumber, ReplicaId, RequestNumber, ENTRY_NUMBER},
    transport::{
        Destination::{To, ToAll, ToReplica},
        InboundAction,
        InboundPacket::Unicast,
        Node, Transport,
        TransportMessage::{self, Allowed, Verified},
    },
    App, InvokeResult,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Block {
    parent_hash: Digest,
    requests: Vec<Request>,
    quorum_certificate: QuorumCertificate,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct QuorumCertificate {
    object_hash: Digest,
    signatures: Vec<(ReplicaId, Signature)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Request(Request),
    Reply(Reply),
    Proposal(Proposal),
    Vote(Vote),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Request {
    client_id: ClientId,
    request_number: RequestNumber,
    op: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    request_number: RequestNumber,
    result: Vec<u8>,
    replica_id: ReplicaId,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    block: Block,
    proposer: ReplicaId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    block_hash: Digest,
    voter: ReplicaId,
    signature: Signature,
}

impl CryptoMessage for Message {
    fn signature_mut(&mut self) -> &mut Signature {
        match self {
            Self::Request(_) | Self::Proposal(_) => unreachable!(),
            Self::Reply(Reply { signature, .. }) | Self::Vote(Vote { signature, .. }) => signature,
        }
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
        }
    }
}

impl AsMut<Transport<Self>> for Client {
    fn as_mut(&mut self) -> &mut Transport<Self> {
        &mut self.transport
    }
}

impl crate::Client for Client {
    fn invoke(&mut self, op: &[u8]) -> InvokeResult {
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
            replied_replicas: HashSet::new(),
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

        if invoke.replied_replicas.is_empty() {
            invoke.result = message.result.clone();
        } else if message.result != invoke.result {
            println!("! mismatch result");
            return;
        }
        invoke.replied_replicas.insert(message.replica_id);
        if invoke.replied_replicas.len() == self.transport.config.f + 1 {
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
            .send_message(ToAll, Message::Request(request.clone()));
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

type BlockId = usize;
struct HotStuffCore {
    // block0: usize, // fixed zero
    block_lock: BlockId,
    block_execute: BlockId,
    voted_height: OpNumber,
    // (certified block, QC)
    high_quorum_certificate: (BlockId, QuorumCertificate),
    // libhotstuff uses ordered `std::set`, i don't see why
    tails: HashSet<BlockId>,
    id: ReplicaId,
    // command cache is never utilize in libhotstuff so omit it
    storage: Storage,
}

#[derive(Default)]
struct StorageBlock {
    data: Block,
    hash: Digest, // reverse index of `block_ids`
    height: OpNumber,
    status: BlockStatus,
    parent: BlockId,
    quorum_certificate_reference: BlockId,
    // the `self_quorum_certificate` in libhotstuff
    // seems like "self" means this is the QC for this block "itself", different
    // from the reference above
    // since the two elements have very different types here the `self_` is not
    // very necessary
    // notice: reusing `QuorumCertificate` struct as container, which may not
    // be fully collected to become a valid QC (yet)
    quorum_certificate: Option<QuorumCertificate>,
    voted: HashSet<ReplicaId>,
}

struct Storage {
    arena: Vec<StorageBlock>,
    block_ids: HashMap<Digest, BlockId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum BlockStatus {
    Delivering,
    Deciding,
    Decided,
}

impl Default for BlockStatus {
    fn default() -> Self {
        Self::Delivering
    }
}

struct PaceMaker {
    high_quorum_certificate_tail: BlockId,
    manual_round: u32,
    quorum_certificate_finished: bool,
}

pub struct HotStuffBase {
    // TODO fetch context
    transport: Transport<Self>,
    core: HotStuffCore,
    pacemaker: PaceMaker,
    app: Box<dyn App + Send>,

    // block hash => list of messages that cannot make progress without keyed
    // block exist
    // the explicit state of libhotstuff's `blk_fetch_waiting` and
    // `blk_deliver_waiting`, which implicit construct this state with varaible
    // capturing of closures registered to promises
    waiting_messages: HashMap<Digest, Vec<Message>>,
    client_table: HashMap<ClientId, (RequestNumber, Option<Reply>)>,
    pending_requests: Vec<Request>,
}

// HotStuffCore
impl HotStuffBase {
    // storage
    fn add_block(&mut self, mut block: StorageBlock) -> BlockId {
        block.hash = digest(&block.data);
        let block_id = self.core.storage.arena.len();
        self.core.storage.block_ids.insert(block.hash, block_id);
        self.core.storage.arena.push(block);
        block_id
    }

    fn is_block_delivered(&self, hash: &Digest) -> bool {
        if let Some(&block) = self.core.storage.block_ids.get(hash) {
            self.core.storage.arena[block].status != BlockStatus::Delivering
        } else {
            false
        }
    }

    fn on_deliver_block(&mut self, block: BlockId) -> bool {
        let arena = &mut self.core.storage.arena;
        if arena[block].status != BlockStatus::Delivering {
            println!("! attempt to deliver a block twice");
            return false;
        }
        arena[block].parent = self.core.storage.block_ids[&arena[block].data.parent_hash];
        arena[block].height = arena[arena[block].parent].height + 1;

        arena[block].quorum_certificate_reference =
            self.core.storage.block_ids[&arena[block].data.quorum_certificate.object_hash];

        self.core.tails.remove(&arena[block].parent);
        self.core.tails.insert(block);

        arena[block].status = BlockStatus::Deciding;
        true
    }

    fn update_high_quorum_certificate(
        &mut self,
        high_quorum_certificate: BlockId,
        quorum_certificate: QuorumCertificate,
    ) {
        let arena = &self.core.storage.arena;
        assert_eq!(
            arena[high_quorum_certificate].hash,
            quorum_certificate.object_hash
        );
        if arena[high_quorum_certificate].height > arena[self.core.high_quorum_certificate.0].height
        {
            self.core.high_quorum_certificate = (high_quorum_certificate, quorum_certificate);
            self.on_high_quorum_certificate_update(high_quorum_certificate);
        }
    }

    fn update(&mut self, new_block: BlockId) {
        let arena = &self.core.storage.arena;
        // println!("update {:02x?}", arena[new_block].hash);
        let block2 = arena[new_block].quorum_certificate_reference;
        if arena[block2].status == BlockStatus::Decided {
            return;
        }
        self.update_high_quorum_certificate(
            block2,
            arena[new_block].data.quorum_certificate.clone(),
        );

        let arena = &self.core.storage.arena;
        let block1 = arena[block2].quorum_certificate_reference;
        if arena[block1].status == BlockStatus::Decided {
            return;
        }
        if arena[block1].height > arena[self.core.block_lock].height {
            self.core.block_lock = block1;
        }

        let block = arena[block1].quorum_certificate_reference;
        if arena[block].status == BlockStatus::Decided {
            return;
        }

        if block1 != arena[block2].parent || block != arena[block1].parent {
            return;
        }

        let mut commit_blocks = Vec::new();
        let mut b = block;
        while arena[b].height > arena[self.core.block_execute].height {
            commit_blocks.push(b);
            b = arena[b].parent;
        }
        assert_eq!(b, self.core.block_execute);
        for block in commit_blocks.into_iter().rev() {
            // println!("commit {:02x?}", self.core.storage.arena[block].hash);
            self.core.storage.arena[block].status = BlockStatus::Decided;
            self.do_consensus(block);
            for i in 0..self.core.storage.arena[block].data.requests.len() {
                self.do_decide(block, i);
            }
        }
        self.core.block_execute = block;
    }

    fn on_propose(&mut self, requests: Vec<Request>, parent: BlockId) -> BlockId {
        self.core.tails.remove(&parent);
        let data = Block {
            requests,
            parent_hash: self.core.storage.arena[parent].hash,
            quorum_certificate: self.core.high_quorum_certificate.1.clone(),
        };
        let hash = digest(&data);
        let block_new = self.add_block(StorageBlock {
            data: data.clone(),
            quorum_certificate_reference: self.core.high_quorum_certificate.0,
            quorum_certificate: Some(QuorumCertificate {
                object_hash: hash,
                signatures: Vec::new(),
            }),
            ..Default::default()
        });
        self.on_deliver_block(block_new);
        assert!(self.core.storage.arena[block_new].height > self.core.voted_height);
        self.update(block_new);
        let proposal = Proposal {
            proposer: self.core.id,
            block: data,
        };
        self.on_receive_proposal(proposal.clone(), block_new);
        self.on_propose_liveness(block_new);
        self.do_broadcast_proposal(proposal);
        block_new
    }

    fn on_receive_proposal(&mut self, proposal: Proposal, block_new: BlockId) {
        let self_propose = proposal.proposer == self.core.id;
        if !self_propose {
            // sanity check delivered
            assert_eq!(
                self.core.storage.arena[block_new].status,
                BlockStatus::Deciding
            );
            self.update(block_new);
        }
        let mut opinion = false;
        let arena = &self.core.storage.arena;
        if arena[block_new].height > self.core.voted_height {
            if arena[arena[block_new].quorum_certificate_reference].height
                > arena[self.core.block_lock].height
            {
                opinion = true;
                self.core.voted_height = arena[block_new].height;
            } else {
                let mut block = block_new;
                while arena[block].height > arena[self.core.block_lock].height {
                    block = arena[block].parent;
                }
                if block == self.core.block_lock {
                    opinion = true;
                    self.core.voted_height = arena[block_new].height;
                }
            }
        }
        if !self_propose {
            self.on_quorum_certificate_finish(arena[block_new].quorum_certificate_reference);
        }
        self.on_receive_proposal_liveness(block_new);
        if opinion {
            let block_hash = self.core.storage.arena[block_new].hash;
            // println!("vote   {block_hash:02x?}");
            self.do_vote(
                proposal.proposer,
                Vote {
                    voter: self.core.id,
                    block_hash,
                    signature: Signature::default(),
                },
            );
        }
    }

    fn on_receive_vote(&mut self, vote: Vote) {
        let block = self.core.storage.block_ids[&vote.block_hash];
        let arena = &mut self.core.storage.arena;
        let quorum_size = arena[block].voted.len();
        if quorum_size >= self.transport.config.n - self.transport.config.f {
            return;
        }
        if !arena[block].voted.insert(vote.voter) {
            println!(
                "! duplicate vote for {:02x?} from {}",
                vote.block_hash, vote.voter
            );
            return;
        }
        let quorum_certificate = arena[block].quorum_certificate.get_or_insert_with(|| {
            println!("! vote for block not proposed by itself");
            QuorumCertificate {
                object_hash: vote.block_hash,
                signatures: Vec::new(),
            }
        });
        quorum_certificate
            .signatures
            .push((vote.voter, vote.signature));
        if quorum_size + 1 == self.transport.config.n - self.transport.config.f {
            // compute
            let quorum_certificate = quorum_certificate.clone();
            self.update_high_quorum_certificate(block, quorum_certificate);
            self.on_quorum_certificate_finish(block);
        }
    }
}

// PaceMaker
impl HotStuffBase {
    fn check_ancestry(&self, a: BlockId, mut b: BlockId) -> bool {
        let arena = &self.core.storage.arena;
        while arena[b].height > arena[a].height {
            b = arena[b].parent;
        }
        b == a
    }

    fn on_high_quorum_certificate_update(&mut self, high_quorum_certificate: BlockId) {
        self.pacemaker.high_quorum_certificate_tail = high_quorum_certificate;
        for &tail in &self.core.tails {
            let arena = &self.core.storage.arena;
            if self.check_ancestry(high_quorum_certificate, tail)
                && arena[tail].height > arena[self.pacemaker.high_quorum_certificate_tail].height
            {
                self.pacemaker.high_quorum_certificate_tail = tail;
            }
        }
    }

    fn on_propose_liveness(&mut self, block: BlockId) {
        self.pacemaker.high_quorum_certificate_tail = block;
    }

    fn on_receive_proposal_liveness(&mut self, block: BlockId) {
        let high_quorum_certificate = self.core.high_quorum_certificate.0;
        let arena = &self.core.storage.arena;
        if self.check_ancestry(high_quorum_certificate, block)
            && arena[block].height > arena[high_quorum_certificate].height
        {
            self.pacemaker.high_quorum_certificate_tail = block;
        }
    }

    fn get_parent(&self) -> BlockId {
        self.pacemaker.high_quorum_certificate_tail
    }

    // the beat strategy is modified (mostly simplified), to prevent introduce
    // timeout on critical path when concurrent request number is less than
    // batch size
    // in this implementation it is equivalent to next proposing or manual
    // rounds start immediately after new QC get collected
    const MAX_BATCH: usize = 70;
    fn beat(&mut self) {
        // TODO rotating
        if !self.pacemaker.quorum_certificate_finished {
            return;
        }
        if !self.pending_requests.is_empty() {
            self.pacemaker.manual_round = 0;
        } else {
            if self.pacemaker.manual_round == 3 {
                return;
            }
            self.pacemaker.manual_round += 1;
        }

        self.pacemaker.quorum_certificate_finished = false;
        let requests = self
            .pending_requests
            .drain(..usize::min(Self::MAX_BATCH, self.pending_requests.len()))
            .collect();
        let parent = self.get_parent();
        self.on_propose(requests, parent);
    }

    fn on_quorum_certificate_finish(&mut self, block: BlockId) {
        // or simply check whether self is primary?
        if self.core.storage.arena[block].voted.len()
            >= self.transport.config.n - self.transport.config.f
        {
            self.pacemaker.quorum_certificate_finished = true;
            self.beat();
        }
    }

    fn get_proposer(&self) -> ReplicaId {
        0 // TODO rotating
    }
}

// HotStuffBase
impl HotStuffBase {
    fn do_consensus(&mut self, _block: BlockId) {
        // TODO rotate related
    }

    fn do_decide(&mut self, block: BlockId, i: usize) {
        let block = &self.core.storage.arena[block];
        let request = &block.data.requests[i];
        let result = self.app.replica_upcall(block.height, &request.op);
        let reply = Reply {
            request_number: request.request_number,
            result,
            replica_id: self.core.id,
            signature: Signature::default(),
        };
        self.client_table.insert(
            request.client_id,
            (request.request_number, Some(reply.clone())),
        );
        self.transport.send_signed_message(
            To(request.client_id.0),
            Message::Reply(reply),
            self.core.id,
        );
    }

    fn do_broadcast_proposal(&mut self, proposal: Proposal) {
        self.transport
            .send_message(ToAll, Message::Proposal(proposal));
    }

    fn do_vote(&mut self, proposer: ReplicaId, vote: Vote) {
        // PaceMakerRR has a trivial `beat_resp` so simply inline here
        self.transport
            .send_signed_message(ToReplica(proposer), Message::Vote(vote), self.core.id);
    }

    fn propose_handler(&mut self, message: Proposal) {
        let parent_hash = message.block.parent_hash;
        let object_hash = message.block.quorum_certificate.object_hash;
        let block = self.add_block(StorageBlock {
            data: message.block.clone(),
            ..Default::default()
        });
        if !self.is_block_delivered(&parent_hash) {
            println!("! message pending deliver");
            self.waiting_messages
                .entry(parent_hash)
                .or_default()
                .push(Message::Proposal(message));
        } else if !self.core.storage.block_ids.contains_key(&object_hash) {
            unreachable!("expect QC delivered equal or earlier than parent");
        } else {
            assert!(self.on_deliver_block(block));
            self.on_receive_proposal(message, block);

            if let Some(messages) = self
                .waiting_messages
                .remove(&self.core.storage.arena[block].hash)
            {
                for message in messages {
                    self.receive_message(Verified(message)); // careful
                }
            }
        }
    }

    fn vote_handler(&mut self, message: Vote) {
        if self.is_block_delivered(&message.block_hash) {
            self.on_receive_vote(message);
        } else {
            self.waiting_messages
                .entry(message.block_hash)
                .or_default()
                .push(Message::Vote(message));
        }
    }
}

impl Node for HotStuffBase {
    type Message = Message;
    fn inbound_action(
        &self,
        packet: crate::transport::InboundPacket<'_, Self::Message>,
    ) -> InboundAction<Self::Message> {
        let message = if let Unicast { message } = packet {
            message
        } else {
            return InboundAction::Block;
        };
        match message {
            Message::Request(_) => InboundAction::Allow(message),
            Message::Proposal(_) => InboundAction::Verify(message, Message::verify_proposal),
            Message::Vote(Vote { voter, .. }) => InboundAction::VerifyReplica(message, voter),
            _ => InboundAction::Block,
        }
    }

    fn receive_message(&mut self, message: TransportMessage<Self::Message>) {
        match message {
            Allowed(Message::Request(message)) => {
                if let Some((request_number, reply)) = self.client_table.get(&message.client_id) {
                    if request_number > &message.request_number {
                        return;
                    }
                    if request_number == &message.request_number {
                        if let Some(reply) = reply {
                            self.transport.send_signed_message(
                                To(message.client_id.0),
                                Message::Reply(reply.clone()),
                                self.core.id,
                            );
                        }
                        return;
                    }
                }
                self.client_table
                    .insert(message.client_id, (message.request_number, None));

                if self.core.id != self.get_proposer() {
                    return;
                }
                self.pending_requests.push(message);
                self.beat();
            }
            Verified(Message::Proposal(message)) => self.propose_handler(message),
            Verified(Message::Vote(message)) => self.vote_handler(message),
            _ => unreachable!(),
        }
    }
}

pub type Replica = HotStuffBase;
impl Replica {
    const BLOCK_GENESIS: BlockId = 0;
    pub fn new(transport: Transport<Self>, id: ReplicaId, app: impl App + Send + 'static) -> Self {
        let mut arena = Vec::with_capacity(ENTRY_NUMBER);
        arena.push(StorageBlock {
            height: 0,
            status: BlockStatus::Decided,
            ..StorageBlock::default()
        });
        let mut block_ids = HashMap::with_capacity(ENTRY_NUMBER);
        block_ids.insert(Digest::default(), Self::BLOCK_GENESIS);
        Self {
            transport,
            core: HotStuffCore {
                block_lock: Self::BLOCK_GENESIS,
                block_execute: Self::BLOCK_GENESIS,
                voted_height: 0,
                high_quorum_certificate: (0, QuorumCertificate::default()),
                tails: HashSet::new(),
                id,
                storage: Storage { arena, block_ids },
            },
            pacemaker: PaceMaker {
                high_quorum_certificate_tail: Self::BLOCK_GENESIS,
                manual_round: 0,
                quorum_certificate_finished: true,
            },
            app: Box::new(app),
            waiting_messages: HashMap::new(),
            client_table: HashMap::new(),
            pending_requests: Vec::new(),
        }
    }
}

impl AsMut<Transport<Self>> for Replica {
    fn as_mut(&mut self) -> &mut Transport<Self> {
        &mut self.transport
    }
}

impl Drop for Replica {
    fn drop(&mut self) {
        let mut n_block = 0;
        let mut n_op = 0;
        for block in &self.core.storage.arena {
            if block.status != BlockStatus::Decided {
                continue;
            }
            n_block += 1;
            n_op += block.data.requests.len();
        }
        println!("average batch size {}", n_op as f32 / n_block as f32);
    }
}

impl Message {
    fn verify_proposal(&mut self, config: &Config) -> bool {
        let proposal = if let Self::Proposal(proposal) = self {
            proposal
        } else {
            unreachable!()
        };
        // genesis
        if proposal.block.quorum_certificate.object_hash == Digest::default() {
            return true;
        }
        let signatures = &proposal.block.quorum_certificate.signatures;
        if signatures.len() < config.n - config.f {
            return false;
        }
        for &(replica_id, signature) in signatures {
            if !verify_message(
                &mut Message::Vote(Vote {
                    voter: replica_id,
                    block_hash: proposal.block.quorum_certificate.object_hash,
                    signature,
                }),
                &config.keys[replica_id as usize].public_key(),
            ) {
                return false;
            }
        }
        true
    }
}
