//! Transport abstracts underlying details away from protocol implementations,
//! including packet receving and sending, timer management, and efficiently
//! signing and verifying messages with cryptographic.
//!
//! The abstraction is basically following specpaxos codebase. The struct
//! `Transport` interacts with types that implement `Node` in the same way as
//! `Transport` and `TransportReceiver` in spexpaxos. The following describes
//! significant modifications.
//!
//! The original model requires circular mutable references between every
//! receiver and its transport, which is quite awkward in Rust semantic. Instead
//! of one shared transport, in NeoArt every `Receiver` should own a
//! `Transport`. The OS transport is fine to be separated, while the simulated
//! transports need to be connected with each other for packet passing. This is
//! solved by `SimulatedNetwork`.
//!
//! This codebase follows asynchronized programming model. There is no single
//! `transport.run()` as main event loop (there is no single transport already),
//! instead main event loop should be provided by underlying async framework,
//! i.e. Tokio. All `Transport`, `Receiver` and `SimulatedNetwork` implement
//! `Run` trait, which has an async `run` method that enables cooperation. The
//! `Concurrent` wrapper is provided to simplify spawning and joining.
//!
//! A client-side receiver should implement both `Run` and `Client`. Notice that
//! `Client::invoke` method is not an async method, but instead a sync method
//! that returns a `dyn Future`, so it will not "contest" with `Run::run` for
//! `&mut self`. A simple demostration to run a client until invocation is done:
//! ```
//! # use neoart::{common::*, transport::*, unreplicated::*, Client as _};
//! # #[tokio::main]
//! # async fn main() {
//! #     let config = SimulatedNetwork::config(1, 0);
//! #     let mut net = SimulatedNetwork::default();
//! #     let replica = Replica::new(
//! #         Transport::new(
//! #             config.clone(),
//! #             net.insert_socket(config.replicas[0]),
//! #             neoart::crypto::ExecutorSetting::Inline,
//! #         ),
//! #         0,
//! #         TestApp::default(),
//! #     );
//! #     let mut client = Client::new(Transport::new(
//! #         config.clone(),
//! #         net.insert_socket(SimulatedNetwork::client(0)),
//! #         neoart::crypto::ExecutorSetting::Inline,
//! #     ));
//! #     let net = Concurrent::run(net);
//! #     let replica = Concurrent::run(replica);
//! let result = client.invoke("hello".as_bytes());
//! client
//!     .run(async {
//!         println!("{:?}", result.await);
//!     })
//!     .await;
//! #     let replica = replica.join().await;
//! #     net.join().await;
//! # }
//! ```
//!
//! The `Crypto` is intergrated into `Transport` through two sets of interfaces
//! for inbound and outbound messages. Every inbound message must go through
//! verification, where exact policy is returned by `Node::inbound_action`. A
//! replica message basically can be verified by `VerifyReplica` while `Verify`
//! can be used for customized verification. The message will be verified in
//! background worker thread, and be fed into `Node::receive_message` if it is
//! verified. The order of messages passing into `Node::receive_message` could
//! be different to the order observed by `Node::inbound_action`, and both
//! ordering could be different to the sending order on the other side of
//! network.
//!
//! The outbound interface is `Transport::send_signed_message`, which sign the
//! message in background worker thread and send it after signing. The sending
//! semantic is different from plain `Transport::send_message`. The plain
//! interface filters out loopback traffic, while
//! `Transport::send_signed_message` keeps it to allow "recirculated" processing
//! on signed messages. This is basically a design tradeoff, because it is hard
//! to recirculate in the synchronized `Transport::send_message`, while it is
//! also hard to "inline" the receiving logic of the loopback copy with the
//! asynchronized `Transport::send_signed_message`. Notice that the recirculated
//! messages do not go through `Node::inbound_action`, they are always allowed.
//!
//! `Crypto`'s executor has `Inline` and `Rayon` variants. The `Inline` executor
//! finishes cryptographic task on current thread before returning from calling,
//! however because of queueing the packet processing is still not run to
//! completion. It is suitable for testing and client side usage which doesn't
//! actually do any signing or verifying. `Rayon` executor uses a Rayon thread
//! pool and is suitable for benchmarking.

use std::{
    borrow::Borrow,
    collections::HashMap,
    fmt::Write,
    future::{pending, Future},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use rand::{thread_rng, Rng};
use serde::{de::DeserializeOwned, Serialize};
use tokio::{
    net::UdpSocket,
    pin, select, spawn,
    sync::{mpsc, Notify},
    task::JoinHandle,
    time::{sleep, Instant, Sleep},
};

use crate::{
    crypto::{Crypto, CryptoMessage, ExecutorSetting},
    meta::{deserialize, digest, random_id, serialize, ClientId, Config, ReplicaId, ENTRY_NUMBER},
};

#[async_trait]
pub trait Run {
    async fn run(&mut self, close: impl Future<Output = ()> + Send);
}

pub trait Node: Sized {
    type Message: Send + 'static;
    fn inbound_action(
        &self,
        packet: InboundPacket<'_, Self::Message>,
    ) -> InboundAction<Self::Message> {
        if let InboundPacket::Unicast { message, .. } = packet {
            InboundAction::Allow(message)
        } else {
            unreachable!()
        }
    }
    fn receive_message(&mut self, message: TransportMessage<Self::Message>);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundPacket<'a, M> {
    Unicast {
        // remote address if needed
        message: M,
    },
    OrderedMulticast {
        // remote address
        sequence_number: u32,
        signature: &'a [u8],
        link_hash: &'a [u8; 32],
        message: M,
    },
}

impl<'a, M> InboundPacket<'a, M> {
    fn new_unicast(buf: &[u8]) -> Self
    where
        M: DeserializeOwned,
    {
        Self::Unicast {
            message: deserialize(buf),
        }
    }

    fn new_multicast(buf: &'a [u8], variant: MulticastVariant) -> Self
    where
        M: DeserializeOwned,
    {
        assert_eq!(variant, MulticastVariant::HalfSipHash);
        Self::OrderedMulticast {
            sequence_number: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            signature: &buf[4..8],
            link_hash: &[0; 32],
            message: deserialize(&buf[100..]),
        }
    }
}

#[derive(Clone, Copy)]
pub enum InboundAction<M> {
    Allow(M),
    Block,
    VerifyReplica(M, ReplicaId),
    Verify(M, fn(&mut M, &Config) -> bool),
}

#[derive(Clone, Copy)]
pub enum TransportMessage<M> {
    Allowed(M),
    Verified(M),
    Signed(M),
}

pub struct Transport<T: Node> {
    pub config: Config,
    crypto: Crypto<T::Message>,
    crypto_channel: mpsc::Receiver<CryptoEvent<T::Message>>,
    socket: Socket,
    multicast_socket: Socket,
    timer_table: HashMap<u32, Timer<T>>,
    timer_id: u32,
    send_signed: Vec<Destination>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Destination {
    ToNull, // reserved
    ToSelf,
    To(SocketAddr),
    ToReplica(ReplicaId),
    ToAll,
    ToMulticast,
}

pub enum CryptoEvent<M> {
    Verified(M),
    Signed(usize, M),
}

struct Timer<T> {
    sleep: Pin<Box<Sleep>>,
    duration: Duration,
    event: Event<T>,
}

type Event<T> = Box<dyn FnOnce(&mut T) + Send>;

#[derive(Debug)]
pub enum Socket {
    Null,
    Os(UdpSocket),
    Simulated(SimulatedSocket),
}

impl From<&'_ Socket> for SocketAddr {
    fn from(socket: &Socket) -> Self {
        match socket {
            Socket::Null => unreachable!(),
            Socket::Os(socket) => socket.local_addr().unwrap(),
            Socket::Simulated(SimulatedSocket { addr, .. }) => *addr,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastVariant {
    Disabled,
    HalfSipHash,
    // Secp256k1
}

impl<T: Node> Transport<T> {
    pub fn new(config: Config, socket: Socket, setting: ExecutorSetting) -> Self {
        let mut timer_table = HashMap::new();
        // insert a sentinel entry to make sure we get always get a `sleep` to
        // select from timer table in `run`
        timer_table.insert(
            u32::MAX,
            Timer {
                sleep: Box::pin(sleep(Duration::from_secs(3600))),
                duration: Duration::ZERO,
                event: Box::new(|_| unreachable!("you forget to shutdown benchmark for an hour")),
            },
        );
        let (crypto_sender, crypto_channel) = mpsc::channel(1024);
        Self {
            crypto: Crypto::new(config.clone(), setting, crypto_sender),
            config,
            crypto_channel,
            socket,
            multicast_socket: Socket::Null,
            timer_table,
            timer_id: 0,
            send_signed: Vec::with_capacity(ENTRY_NUMBER),
        }
    }

    pub fn listen_multicast(&mut self, socket: Socket, variant: MulticastVariant) {
        assert_eq!(variant, MulticastVariant::HalfSipHash);
        self.multicast_socket = socket;
    }

    pub fn multicast_variant(&self) -> MulticastVariant {
        // TODO
        MulticastVariant::HalfSipHash
    }

    pub fn create_id(&self) -> ClientId {
        random_id((&self.socket).into())
    }

    fn send_message_internal(socket: &Socket, destination: SocketAddr, buf: &[u8]) {
        match socket {
            Socket::Null => unreachable!(),
            Socket::Os(socket) => {
                socket.try_send_to(buf, destination).unwrap();
            }
            Socket::Simulated(SimulatedSocket { addr, network, .. }) => {
                network
                    .try_send(SimulatedMessage {
                        source: *addr,
                        destination,
                        buf: buf.to_vec(),
                    })
                    .map_err(|_| ())
                    .unwrap();
            }
        }
    }

    pub fn send_message(&self, destination: Destination, message: impl Borrow<T::Message>)
    where
        T::Message: Serialize,
    {
        let mut buf = [0; 1400];
        let message_offset = if destination == Destination::ToMulticast {
            100 // 4 bytes sequence, up to 64 bytes signature, 32 bytes hash
        } else {
            0
        };
        let len = serialize(&mut buf[message_offset..], message.borrow()) + message_offset;
        if destination == Destination::ToMulticast {
            let d = digest(&buf[message_offset..len]);
            buf[68..100].copy_from_slice(&d[..]);
        }

        match destination {
            Destination::ToNull | Destination::ToSelf => {
                unreachable!() // really?
            }
            Destination::To(addr) => Self::send_message_internal(&self.socket, addr, &buf[..len]),
            Destination::ToReplica(id) => Self::send_message_internal(
                &self.socket,
                self.config.replicas[id as usize],
                &buf[..len],
            ),
            Destination::ToAll => {
                let local = (&self.socket).into();
                for &address in &self.config.replicas {
                    if address != local {
                        Self::send_message_internal(&self.socket, address, &buf[..len]);
                    }
                }
            }
            Destination::ToMulticast => Self::send_message_internal(
                &self.socket,
                self.config.multicast.unwrap(),
                &buf[..len],
            ),
        }
    }

    pub fn send_buffer(&self, address: impl Into<SocketAddr>, buf: &[u8]) {
        Self::send_message_internal(&self.socket, address.into(), buf);
    }

    pub fn send_signed_message(
        &mut self,
        destination: Destination,
        message: T::Message,
        id: ReplicaId,
    ) where
        T::Message: CryptoMessage + Send + 'static,
    {
        self.crypto.sign(self.send_signed.len(), message, id);
        self.send_signed.push(destination);
    }

    pub fn create_timer(
        &mut self,
        duration: Duration,
        on_timer: impl FnOnce(&mut T) + Send + 'static,
    ) -> u32 {
        self.timer_id += 1;
        let id = self.timer_id;
        self.timer_table.insert(
            id,
            Timer {
                sleep: Box::pin(sleep(duration)),
                duration,
                event: Box::new(on_timer),
            },
        );
        id
    }

    pub fn reset_timer(&mut self, id: u32) {
        let timer = self.timer_table.get_mut(&id).unwrap();
        timer.sleep.as_mut().reset(Instant::now() + timer.duration);
    }

    pub fn cancel_timer(&mut self, id: u32) {
        self.timer_table.remove(&id);
    }
}

impl Socket {
    async fn receive_from(&mut self, buf: &mut [u8]) -> (usize, SocketAddr) {
        match self {
            Self::Null => pending().await,
            Self::Os(socket) => socket.recv_from(buf).await.unwrap(),
            Self::Simulated(SimulatedSocket { inbox, .. }) => {
                let (remote, message) = inbox.recv().await.unwrap();
                buf[..message.len()].copy_from_slice(&message);
                (message.len(), remote)
            }
        }
    }
}

#[async_trait]
impl<T> Run for T
where
    T: Node + AsMut<Transport<T>> + Send,
    T::Message: CryptoMessage + DeserializeOwned,
{
    async fn run(&mut self, close: impl Future<Output = ()> + Send) {
        pin!(close);
        let mut buf = [0; 1400];
        let mut multicast_buf = [0; 1400];
        loop {
            let transport = self.as_mut();
            let (&id, timer) = transport
                .timer_table
                .iter_mut()
                .min_by_key(|(_, timer)| timer.sleep.deadline())
                .unwrap();
            select! {
                _ = &mut close => return,
                _ = timer.sleep.as_mut() => {
                    let timer = self.as_mut().timer_table.remove(&id).unwrap();
                    (timer.event)(self);
                }
                event = transport.crypto_channel.recv() => {
                    handle_crypto_event(self, event.unwrap());
                },
                (len, remote) = transport.socket.receive_from(&mut buf) => {
                    handle_raw_message(self, remote, InboundPacket::new_unicast(&buf[..len]));
                }
                (len, remote) = transport.multicast_socket.receive_from(&mut multicast_buf) => {
                    handle_raw_message(
                        self,
                        remote,
                        InboundPacket::new_multicast(
                            &multicast_buf[..len],
                            MulticastVariant::HalfSipHash,
                        ),
                    );
                }
            }
        }

        fn handle_crypto_event<T>(receiver: &mut T, event: CryptoEvent<T::Message>)
        where
            T: Node + AsMut<Transport<T>>,
            T::Message: Serialize,
        {
            match event {
                CryptoEvent::Verified(message) => {
                    receiver.receive_message(TransportMessage::Verified(message));
                }
                CryptoEvent::Signed(id, message) => match receiver.as_mut().send_signed[id] {
                    Destination::ToNull => {}
                    Destination::ToSelf => {
                        receiver.receive_message(TransportMessage::Signed(message))
                    }
                    destination => receiver.as_mut().send_message(destination, &message),
                },
            }
        }

        fn handle_raw_message<T>(
            receiver: &mut T,
            _remote: SocketAddr,
            buffer: InboundPacket<'_, T::Message>,
        ) where
            T: Node + AsMut<Transport<T>>,
            T::Message: CryptoMessage + Send + 'static,
        {
            match receiver.inbound_action(buffer) {
                InboundAction::Allow(message) => {
                    receiver.receive_message(TransportMessage::Allowed(message));
                }
                InboundAction::Block => {}
                InboundAction::VerifyReplica(message, replica_id) => {
                    receiver.as_mut().crypto.verify_replica(message, replica_id);
                }
                InboundAction::Verify(message, verify) => {
                    receiver.as_mut().crypto.verify(message, verify);
                }
            }
        }
    }
}

pub struct SimulatedNetwork {
    send_channel: (
        mpsc::Sender<SimulatedMessage>,
        mpsc::Receiver<SimulatedMessage>,
    ),
    inboxes: HashMap<SocketAddr, mpsc::Sender<(SocketAddr, Vec<u8>)>>,
    epoch: Instant,
}

struct SimulatedMessage {
    source: SocketAddr,
    destination: SocketAddr,
    buf: Vec<u8>,
}

impl Default for SimulatedNetwork {
    fn default() -> Self {
        Self {
            send_channel: mpsc::channel(64),
            inboxes: HashMap::new(),
            epoch: Instant::now(),
        }
    }
}

#[derive(Debug)]
pub struct SimulatedSocket {
    addr: SocketAddr,
    network: mpsc::Sender<SimulatedMessage>,
    inbox: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
}

impl SimulatedNetwork {
    pub fn insert_socket(&mut self, addr: SocketAddr) -> Socket {
        let (inbox_sender, inbox) = mpsc::channel(64);
        self.inboxes.insert(addr, inbox_sender);
        Socket::Simulated(SimulatedSocket {
            addr,
            network: self.send_channel.0.clone(),
            inbox,
        })
    }

    pub fn config(n: usize, f: usize) -> Config {
        let mut config = String::new();
        writeln!(config, "f {f}").unwrap();
        for i in 0..n {
            writeln!(config, "replica 5.9.0.{i}:2023").unwrap();
        }
        let mut config: Config = config.parse().unwrap();
        config.gen_keys();
        config
    }

    pub fn client(i: usize) -> SocketAddr {
        format!("20.23.7.10:{}", i + 1).parse().unwrap()
    }
}

#[async_trait]
impl Run for SimulatedNetwork {
    async fn run(&mut self, close: impl Future<Output = ()> + Send) {
        pin!(close);
        loop {
            select! {
                _ = &mut close => return,
                message = self.send_channel.1.recv() => {
                    self.handle_message(message.unwrap()).await
                }
            }
        }
    }
}

impl SimulatedNetwork {
    async fn handle_message(&self, message: SimulatedMessage) {
        // TODO filter
        let inbox = self.inboxes[&message.destination].clone();
        let delay = Duration::from_millis(thread_rng().gen_range(1..10));
        let epoch = self.epoch;
        spawn(async move {
            sleep(delay).await;
            println!(
                "* [{:6?}] [{} -> {}] message length {} {}",
                Instant::now() - epoch,
                message.source,
                message.destination,
                message.buf.len(),
                if inbox.send((message.source, message.buf)).await.is_err() {
                    "(failed)"
                } else {
                    ""
                }
            );
        });
    }
}

pub struct Concurrent<T>(Arc<Notify>, JoinHandle<T>);
impl<T> Concurrent<T> {
    pub fn run(mut runnable: T) -> Self
    where
        T: Run + Send + 'static,
    {
        let notify = Arc::new(Notify::new());
        Self(
            notify.clone(),
            spawn(async move {
                runnable.run(notify.notified()).await;
                runnable
            }),
        )
    }

    pub async fn join(self) -> T {
        self.0.notify_one();
        self.1.await.unwrap()
    }
}
