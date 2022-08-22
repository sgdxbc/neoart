//! Transport abstracts underlying details away from protocol implementations,
//! including packet receving and sending, timer management, and efficiently
//! signing and verifying messages with cryptographic.
//!
//! The abstraction is basically following specpaxos codebase. The struct
//! `Transport` interacts with types that implement `Receiver` in the same way,
//! as `Transport` and `TransportReceiver` in spexpaxos. The following describes
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
//! `Client::invoke` method is not an async method, but instead return a
//! `Future`, so it will not "contest" with `Run::run` for `&mut self`. A simple
//! demostration to run a client until invocation is done:
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
//! verification, where exact policy is returned by `Receiver::inbound_action`.
//! A replica message basically can be verified by `VerifyReplica` while
//! `Verify` can be used for customization.
//!
//! The outbound interface is `Transport::sign_message` which returns a
//! `SignedMessage`, which represents a `Receiver::Message` that has been
//! submitted for signing. The message will be stored by transport, and be
//! asynchronized signed. `Transport::signed_message` returns `None` before the
//! signing is finished. If certain action is required after the message is
//! signed, it could be put in `Receiver::on_signed`, where it is safe to
//! `unwrap` the result of `signed_message`. It is a common operation to send
//! signed message after signing, so it has been built into transport as
//! `Transport::send_signed_message` method.
//!
//! `Crypto`'s executor has `Inline` and `Rayon` variants. The `Inline` executor
//! finishes cryptographic task on current thread before returning from calling,
//! so e.g. `signed_message` never returns `None`. It is suitable for testing,
//! and client which doesn't actually do any signing or verifying. `Rayon`
//! executor uses a Rayon thread pool and is suitable for benchmarking.

use std::{
    borrow::Borrow, collections::HashMap, fmt::Write, future::Future, net::SocketAddr, pin::Pin,
    sync::Arc, time::Duration,
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
    // latency::{push_latency, Point},
    meta::{deserialize, random_id, serialize, ClientId, Config, ReplicaId, ENTRY_NUMBER},
};

pub trait Receiver: Sized {
    type Message: Send + 'static + DeserializeOwned;
    fn inbound_action(&self, buf: &[u8]) -> InboundAction<Self::Message> {
        InboundAction::Allow(deserialize(buf))
    }
    fn receive_message(&mut self, remote: SocketAddr, message: Self::Message);
    #[allow(unused_variables)]
    fn on_signed(&mut self, signed_message: Self::Message) {
        unreachable!() // really?
    }
}

pub enum InboundAction<M> {
    Allow(M),
    Block,
    VerifyReplica(M, ReplicaId),
    Verify(M, fn(&mut M, &Config) -> bool),
    // verify multicast
}

pub struct Transport<T: Receiver> {
    pub config: Config,
    crypto: Crypto<T::Message>,
    crypto_channel: mpsc::Receiver<CryptoEvent<T::Message>>,
    socket: Socket,
    timer_table: HashMap<u32, Timer<T>>,
    timer_id: u32,
    send_signed: Vec<Destination>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Destination {
    ToNull, // reserved
    To(SocketAddr),
    ToReplica(ReplicaId),
    ToAll,
}

pub enum CryptoEvent<M> {
    Verified(SocketAddr, M),
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
    Os(UdpSocket),
    Simulated(SimulatedSocket),
}

impl<T: Receiver> Transport<T> {
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
        let (crypto_sender, crypto_channel) = mpsc::channel(64);
        Self {
            crypto: Crypto::new(config.clone(), setting, crypto_sender),
            config,
            crypto_channel,
            socket,
            timer_table,
            timer_id: 0,
            send_signed: Vec::with_capacity(ENTRY_NUMBER),
        }
    }

    pub fn create_id(&self) -> ClientId {
        let addr = match &self.socket {
            Socket::Os(socket) => socket.local_addr().unwrap(),
            &Socket::Simulated(SimulatedSocket { addr, .. }) => addr,
        };
        random_id(addr)
    }

    fn send_message_interal(socket: &Socket, destinations: &[SocketAddr], message: impl Serialize) {
        let mut buf = [0; 1400];
        let len = serialize(&mut buf[..], message);
        let local = match socket {
            Socket::Os(socket) => socket.local_addr().unwrap(),
            &Socket::Simulated(SimulatedSocket { addr, .. }) => addr,
        };
        for &destination in destinations {
            if destination == local {
                continue;
            }
            match socket {
                Socket::Os(socket) => {
                    socket.try_send_to(&buf[..len], destination).unwrap();
                }
                Socket::Simulated(SimulatedSocket { addr, network, .. }) => {
                    network
                        .try_send(Message {
                            source: *addr,
                            destination,
                            buf: buf[..len].to_vec(),
                        })
                        .map_err(|_| ())
                        .unwrap();
                }
            }
        }
    }

    pub fn send_message(&self, destination: Destination, message: impl Borrow<T::Message>)
    where
        T::Message: Serialize,
    {
        match destination {
            Destination::ToNull => {
                unreachable!() // really?
            }
            Destination::To(addr) => {
                Self::send_message_interal(&self.socket, &[addr], message.borrow())
            }
            Destination::ToReplica(id) => Self::send_message_interal(
                &self.socket,
                &[self.config.replicas[id as usize]],
                message.borrow(),
            ),
            Destination::ToAll => Self::send_message_interal(
                &self.socket,
                &self.config.replicas[..],
                message.borrow(),
            ),
        }
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
pub trait Run {
    async fn run(&mut self, close: impl Future<Output = ()> + Send);
}

#[async_trait]
impl<T> Run for T
where
    T: Receiver + AsMut<Transport<T>> + Send,
    T::Message: CryptoMessage,
{
    async fn run(&mut self, close: impl Future<Output = ()> + Send) {
        pin!(close);
        let mut buf = [0; 1400];
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
                    handle_raw_message(self, remote, &buf[..len]);
                }
            }

            fn handle_crypto_event<T>(receiver: &mut T, event: CryptoEvent<T::Message>)
            where
                T: Receiver + AsMut<Transport<T>>,
                T::Message: Serialize,
            {
                match event {
                    CryptoEvent::Verified(remote, message) => {
                        receiver.receive_message(remote, message);
                    }
                    CryptoEvent::Signed(id, message) => {
                        let dest = receiver.as_mut().send_signed[id];
                        if !matches!(dest, Destination::ToNull) {
                            receiver.as_mut().send_message(dest, &message);
                        }
                        // TODO Destination::ToReplica(self.id)
                        // we don't have access to self.id here, and extract
                        // replica address from config then compare is too
                        // expensive (and not elegant)
                        if matches!(dest, Destination::ToAll) {
                            receiver.on_signed(message);
                        }
                    }
                }
            }

            fn handle_raw_message<T>(receiver: &mut T, remote: SocketAddr, buf: &[u8])
            where
                T: Receiver + AsMut<Transport<T>>,
                T::Message: CryptoMessage + Send + 'static,
            {
                match receiver.inbound_action(buf) {
                    InboundAction::Allow(message) => {
                        receiver.receive_message(remote, message);
                    }
                    InboundAction::Block => {}
                    InboundAction::VerifyReplica(message, replica_id) => {
                        receiver
                            .as_mut()
                            .crypto
                            .verify_replica(remote, message, replica_id);
                    }
                    InboundAction::Verify(message, verify) => {
                        receiver.as_mut().crypto.verify(remote, message, verify);
                    }
                }
            }
        }
    }
}

pub struct SimulatedNetwork {
    send_channel: (mpsc::Sender<Message>, mpsc::Receiver<Message>),
    inboxes: HashMap<SocketAddr, mpsc::Sender<(SocketAddr, Vec<u8>)>>,
    epoch: Instant,
}

struct Message {
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
    network: mpsc::Sender<Message>,
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
    async fn handle_message(&self, message: Message) {
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
