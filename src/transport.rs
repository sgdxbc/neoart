use std::{
    collections::HashMap, fmt::Write, future::Future, net::SocketAddr, pin::Pin, sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use rand::{thread_rng, Rng};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::{
    net::UdpSocket,
    pin, select, spawn,
    sync::{mpsc, Notify},
    task::JoinHandle,
    time::{sleep, Instant, Sleep},
};

use crate::{
    crypto::{Crypto, CryptoMessage, ExecutorSetting},
    meta::{deserialize, serialize, Config, OpNumber, ReplicaId},
    App,
};

pub trait Receiver: Sized {
    type InboundMessage: Send + 'static + DeserializeOwned;
    type OutboundMessage: Send + 'static;
    fn inbound_action(buf: &[u8]) -> InboundAction<Self::InboundMessage> {
        InboundAction::Allow(deserialize(buf))
    }
    fn receive_message(&mut self, remote: SocketAddr, message: Self::InboundMessage);
}

pub enum InboundAction<M> {
    Allow(M),
    Block,
    Verify(M, ReplicaId),
    // verify multicast
}

pub struct Transport<T: Receiver> {
    pub config: Config,
    crypto: Crypto<T::InboundMessage, T::OutboundMessage>,
    crypto_channel: mpsc::Receiver<CryptoEvent<T::InboundMessage, T::OutboundMessage>>,
    socket: Socket,
    timer_table: HashMap<u32, Timer<T>>,
    timer_id: u32,
    signed_messages: HashMap<SignedMessage, T::OutboundMessage>,
    signed_id: u32,
    send_signed: HashMap<SignedMessage, Destination>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Destination {
    To(SocketAddr),
    ToAll,
}

pub enum CryptoEvent<V, S> {
    Verified(SocketAddr, V),
    Signed(SignedMessage, S),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SignedMessage(u32);

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
            signed_messages: HashMap::new(),
            signed_id: 0,
            send_signed: HashMap::new(),
        }
    }

    fn send_message_interal(socket: &Socket, destinations: &[SocketAddr], message: impl Serialize) {
        let mut buf = [0; 1400];
        let len = serialize(&mut buf, message);
        for &destination in destinations {
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
                        .map_err(|_| panic!())
                        .unwrap();
                }
            }
        }
    }

    pub fn send_message(&self, destination: Destination, message: impl Serialize) {
        match destination {
            Destination::To(addr) => Self::send_message_interal(&self.socket, &[addr], message),
            Destination::ToAll => {
                Self::send_message_interal(&self.socket, &self.config.replicas[..], message)
            }
        }
    }

    pub fn send_signed_message(&mut self, destination: Destination, message: SignedMessage)
    where
        T::OutboundMessage: Serialize,
    {
        if let Some(message) = self.signed_message(message) {
            self.send_message(destination, message);
        } else {
            let dest = self.send_signed.insert(message, destination);
            assert!(dest.is_none());
        }
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

    pub fn sign_message(&mut self, id: ReplicaId, message: T::OutboundMessage) -> SignedMessage
    where
        T::OutboundMessage: CryptoMessage + Send + 'static,
    {
        self.signed_id += 1;
        let signed_id = SignedMessage(self.signed_id);
        self.crypto.sign(signed_id, message, id);
        signed_id
    }

    pub fn signed_message(&self, id: SignedMessage) -> Option<&T::OutboundMessage> {
        self.signed_messages.get(&id)
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
    T::InboundMessage: CryptoMessage,
    T::OutboundMessage: Serialize,
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

            fn handle_crypto_event<T>(
                receiver: &mut T,
                event: CryptoEvent<T::InboundMessage, T::OutboundMessage>,
            ) where
                T: Receiver + AsMut<Transport<T>>,
                T::OutboundMessage: Serialize,
            {
                match event {
                    CryptoEvent::Verified(remote, message) => {
                        receiver.receive_message(remote, message);
                    }
                    CryptoEvent::Signed(id, message) => {
                        if let Some(destination) = receiver.as_mut().send_signed.remove(&id) {
                            receiver.as_mut().send_message(destination, &message);
                        }
                        receiver.as_mut().signed_messages.insert(id, message);
                    }
                }
            }

            fn handle_raw_message<T>(receiver: &mut T, remote: SocketAddr, buf: &[u8])
            where
                T: Receiver + AsMut<Transport<T>>,
                T::InboundMessage: CryptoMessage + Send + 'static,
            {
                match T::inbound_action(buf) {
                    InboundAction::Allow(message) => receiver.receive_message(remote, message),
                    InboundAction::Block => return,
                    InboundAction::Verify(message, replica_id) => {
                        receiver.as_mut().crypto.verify(message, replica_id)
                    }
                }
            }
        }
    }
}

pub struct SimulatedNetwork {
    send_channel: (mpsc::Sender<Message>, mpsc::Receiver<Message>),
    inboxes: HashMap<SocketAddr, mpsc::Sender<(SocketAddr, Vec<u8>)>>,
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
        spawn(async move {
            sleep(delay).await;
            println!(
                "* [{:?}] [{} -> {}] message length {}",
                Instant::now(),
                message.source,
                message.destination,
                message.buf.len()
            );
            inbox.send((message.source, message.buf)).await.unwrap();
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TestApp {
    //
}

impl App for TestApp {
    fn replica_upcall(&mut self, op_number: OpNumber, op: &[u8]) -> Vec<u8> {
        [format!("[{op_number}] ").as_bytes(), op].concat()
    }
}
