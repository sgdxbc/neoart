//! Transport abstracts underlying details away from protocol implementations,
//! including packet receving and sending, timer management, and efficiently
//! signing and verifying messages with cryptographic.
//!
//! The abstraction is basically following specpaxos codebase. The struct
//! `Transport` interacts with types that implement `Node` in the same way as
//! `Transport` and `TransportReceiver` in spexpaxos. (Rename to `Node` because
//! "receiver" is an overly-used term in Rust libraries.) The following
//! describes significant modifications.
//!
//! The original model requires circular mutable references between every
//! receiver and its transport, which is quite awkward in Rust semantic. Instead
//! of one shared transport, in NeoArt every `Receiver` should own a
//! `Transport`. While the OS transport is fine to be separately-owned, the
//! simulated transports need to be connected with each other for packet
//! passing. And `simulated::Network` is the connector.
//!
//! This codebase follows asynchronized programming model. There is no single
//! `transport.run()` as main event loop (there is no single transport already),
//! instead main event loop should be provided by underlying async framework,
//! i.e. Tokio. All `Transport`, `Receiver` and `simulated::Network` implement
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
//! #     let config = simulated::Network::config(1, 0);
//! #     let mut net = simulated::Network::default();
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
//! #         net.insert_socket(simulated::Network::client(0)),
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
//! The `Crypto` is integrated into `Transport` through two sets of interfaces
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
//! message in background worker thread and send it after signing. If a protocol
//! wants to postprocess a locally-signed message, e.g. insert it into a quorum
//! certificate, the message could be sent to `Destination::ToSelf`, and after
//! signing the message will be "recirculated" to `Node::receive_message` and be
//! wrapped with `TransportMessage::Signed`. `ToSelf` is not allowed for plain
//! `Transport::send_message`.
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
    future::{pending, Future},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::{
    net::UdpSocket,
    pin, select, spawn,
    sync::{mpsc, Notify},
    task::JoinHandle,
    time::{sleep, Instant, Sleep},
};

use crate::{
    crypto::{Crypto, CryptoMessage, Executor},
    meta::{deserialize, digest, random_id, serialize, ClientId, Config, ReplicaId, ENTRY_NUMBER},
};

#[async_trait]
pub trait Run {
    async fn run(&mut self, close: impl Future<Output = ()> + Send);
}

pub trait Node {
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
            // currently messages are unconditionally deserialized upon
            // receiving and panic if the message is malformed. this is not
            // suitable for byzantine system. a better design is to wrap the
            // deserialization result in `Result` to allow error handling
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
    Os(UdpSocket), // both unicast and multicast
    Simulated(simulated::Socket),
    SimulatedMulticast(mpsc::Receiver<simulated::Message>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MulticastVariant {
    Disabled,
    HalfSipHash,
    // Secp256k1
}

impl<T: Node> Transport<T> {
    pub fn new(config: Config, socket: Socket, executor: Executor) -> Self {
        assert!(matches!(socket, Socket::Os(_)) || matches!(socket, Socket::Simulated(_)));

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
        let (crypto_sender, crypto_channel) = mpsc::channel(64);
        Self {
            crypto: Crypto::new(config.clone(), crypto_sender, executor),
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
        assert!(
            matches!((&socket, &self.socket), (Socket::Os(_), Socket::Os(_)))
                || matches!(
                    (&socket, &self.socket),
                    (Socket::SimulatedMulticast(_), Socket::Simulated(_))
                )
        );

        assert_eq!(variant, MulticastVariant::HalfSipHash);
        self.multicast_socket = socket;
    }

    pub fn multicast_variant(&self) -> MulticastVariant {
        // TODO
        MulticastVariant::HalfSipHash
    }

    pub fn create_id(&self) -> ClientId {
        random_id(self.socket.local_address())
    }

    fn send_message_internal(socket: &Socket, destination: SocketAddr, buf: &[u8]) {
        match socket {
            Socket::Null | Socket::SimulatedMulticast(_) => unreachable!(),
            Socket::Os(socket) => {
                socket.try_send_to(buf, destination).unwrap();
            }
            Socket::Simulated(socket) => socket.send_to(destination, buf),
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
                let local = self.socket.local_address();
                for &address in &self.config.replicas {
                    if address != local {
                        Self::send_message_internal(&self.socket, address, &buf[..len]);
                    }
                }
            }
            Destination::ToMulticast => {
                Self::send_message_internal(&self.socket, self.config.multicast, &buf[..len])
            }
        }
    }

    pub fn send_raw(&self, address: impl Into<SocketAddr>, buf: &[u8]) {
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
            Self::Simulated(simulated::Socket { inbox, .. }) | Self::SimulatedMulticast(inbox) => {
                let (remote, message) = inbox.recv().await.unwrap();
                buf[..message.len()].copy_from_slice(&message);
                (message.len(), remote)
            }
        }
    }

    fn local_address(&self) -> SocketAddr {
        match self {
            Socket::Null | Socket::SimulatedMulticast(_) => unreachable!(),
            Socket::Os(socket) => socket.local_addr().unwrap(),
            Socket::Simulated(simulated::Socket { addr, .. }) => *addr,
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

pub mod simulated {
    use std::{
        collections::HashMap,
        future::Future,
        net::SocketAddr,
        sync::{
            atomic::{AtomicBool, Ordering::SeqCst},
            Arc,
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use rand::{thread_rng, Rng};
    use tokio::{
        pin, select, spawn,
        sync::mpsc,
        time::{sleep, Instant},
    };

    use crate::meta::Config;

    pub struct BasicSwitch {
        send_channel: (mpsc::Sender<Packet>, mpsc::Receiver<Packet>),
        inboxes: HashMap<SocketAddr, Inbox>,
        multicast_listeners: HashMap<SocketAddr, mpsc::Receiver<Message>>,
        pub epoch: Instant,
        is_running: Arc<AtomicBool>,
    }
    struct Inbox {
        unicast: mpsc::Sender<Message>,
        multicast: mpsc::Sender<Message>,
    }

    pub type Message = (SocketAddr, Vec<u8>);
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Packet {
        pub source: SocketAddr,
        pub destination: SocketAddr,
        pub buffer: Vec<u8>,
        pub delay: Duration,
        pub multicast_outgress: bool,
    }

    #[derive(Debug)]
    pub struct Socket {
        pub addr: SocketAddr,
        network: mpsc::Sender<Packet>,
        pub inbox: mpsc::Receiver<Message>,
        is_running: Arc<AtomicBool>,
    }

    impl Socket {
        pub fn send_to(&self, destination: SocketAddr, buf: &[u8]) {
            let result = self.network.try_send(Packet {
                source: self.addr,
                destination,
                buffer: buf.to_vec(),
                delay: Duration::from_millis(thread_rng().gen_range(1..10)),
                multicast_outgress: false,
            });
            if result.is_err() {
                println!("! network not available and abort simulation");
                self.is_running.store(false, SeqCst);
            }
        }
    }

    impl Default for BasicSwitch {
        fn default() -> Self {
            Self {
                send_channel: mpsc::channel(64),
                inboxes: HashMap::new(),
                multicast_listeners: HashMap::new(),
                epoch: Instant::now(),
                is_running: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl BasicSwitch {
        fn insert_socket(&mut self, addr: SocketAddr) -> super::Socket {
            let (unicast_sender, unicast) = mpsc::channel(64);
            let (multicast_sender, multicast) = mpsc::channel(64);
            self.inboxes.insert(
                addr,
                Inbox {
                    unicast: unicast_sender,
                    multicast: multicast_sender,
                },
            );
            self.multicast_listeners.insert(addr, multicast);
            super::Socket::Simulated(Socket {
                addr,
                network: self.send_channel.0.clone(),
                inbox: unicast,
                is_running: self.is_running.clone(),
            })
        }

        fn multicast_socket(&mut self, addr: SocketAddr) -> super::Socket {
            super::Socket::SimulatedMulticast(self.multicast_listeners.remove(&addr).unwrap())
        }
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub struct Network<T = BasicSwitch>(pub T);
    impl Network {
        pub fn config(n: usize, f: usize) -> Config {
            let mut config = Config {
                n,
                f,
                replicas: (0..n)
                    .map(|i| SocketAddr::from(([5, 9, 0, i as u8], 2023)))
                    .collect(),
                multicast: SocketAddr::from(([5, 9, 0, 255], 14159)),
                ..Config::default()
            };
            config.gen_keys();
            config
        }

        pub fn client(i: usize) -> SocketAddr {
            SocketAddr::from(([20, 23, 7, 10], i as u16 + 1))
        }
    }

    impl<T> Network<T> {
        pub fn insert_socket(&mut self, addr: SocketAddr) -> super::Socket
        where
            T: AsMut<BasicSwitch>,
        {
            self.0.as_mut().insert_socket(addr)
        }

        pub fn multicast_socket(&mut self, addr: SocketAddr) -> super::Socket
        where
            T: AsMut<BasicSwitch>,
        {
            self.0.as_mut().multicast_socket(addr)
        }
    }

    pub trait Switch {
        fn handle_packet(&mut self, packet: Packet);
    }

    #[async_trait]
    impl<T> super::Run for Network<T>
    where
        T: Switch + AsMut<BasicSwitch> + Send,
    {
        async fn run(&mut self, close: impl Future<Output = ()> + Send) {
            let Self(switch) = self;
            pin!(close);
            switch.as_mut().is_running.store(true, SeqCst);
            while switch.as_mut().is_running.load(SeqCst) {
                select! {
                    _ = &mut close => break,
                    message = switch.as_mut().send_channel.1.recv() => {
                        switch.handle_packet(message.unwrap())
                    }
                }
            }
            switch.as_mut().is_running.store(false, SeqCst);
        }
    }

    impl BasicSwitch {
        pub fn forward_packet(&mut self, message: Packet) {
            let inbox = if message.multicast_outgress {
                self.inboxes[&message.destination].multicast.clone()
            } else {
                self.inboxes[&message.destination].unicast.clone()
            };
            let epoch = self.epoch;
            let is_running = self.is_running.clone();
            spawn(async move {
                sleep(message.delay).await;
                if !is_running.load(SeqCst) {
                    return;
                }
                println!(
                    "* [{:6?}] [{} -> {}] message length {} {}",
                    Instant::now() - epoch,
                    message.source,
                    message.destination,
                    message.buffer.len(),
                    if message.multicast_outgress {
                        "(multicast)"
                    } else {
                        ""
                    }
                );
                if inbox.send((message.source, message.buffer)).await.is_err() {
                    println!("! send failed and abort simulation");
                    // the simulation will end as soon as the first attempt of
                    // sending message into a crashed receiver i.e. the coroutine
                    // thread running it
                    // (it will also end if receiver fail to transmit to network,
                    // but that should not be possible as long as network is
                    // correctly implementated)
                    // this may not be as good as end the simulation as soon as any
                    // receiver crashes, by monitor the liveness of threads, but it
                    // should be mostly the same
                    is_running.store(false, SeqCst);
                }
            });
        }
    }

    impl AsRef<BasicSwitch> for BasicSwitch {
        fn as_ref(&self) -> &BasicSwitch {
            self
        }
    }
    impl AsMut<BasicSwitch> for BasicSwitch {
        fn as_mut(&mut self) -> &mut BasicSwitch {
            self
        }
    }
    impl Switch for BasicSwitch {
        fn handle_packet(&mut self, packet: Packet) {
            self.forward_packet(packet);
        }
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
