use std::{
    collections::HashMap, fmt::Write, future::Future, net::SocketAddr, pin::Pin, sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use rand::{thread_rng, Rng};
use tokio::{
    net::UdpSocket,
    pin, select, spawn,
    sync::{mpsc, Notify},
    task::JoinHandle,
    time::{sleep, Instant, Sleep},
};

use crate::{
    crypto::Signature,
    meta::{Config, OpNumber},
    App,
};

pub trait Receiver: Sized {
    fn receive_message(&mut self, remote: SocketAddr, buf: &[u8]);
    fn transport(&mut self) -> &mut Transport<Self>;
    type SignedMessage;
    #[allow(unused_variables)]
    fn signature(message: &Self::SignedMessage) -> &Signature {
        unimplemented!()
    }
    #[allow(unused_variables)]
    fn set_signature(message: &mut Self::SignedMessage, signature: Signature) {
        unimplemented!()
    }
}

pub struct Transport<T: Receiver> {
    pub config: Config,
    crypto_channel: (mpsc::Sender<CryptoEvent<T>>, mpsc::Receiver<CryptoEvent<T>>),
    socket: Socket,
    timer_table: HashMap<u32, Timer<T>>,
    timer_id: u32,
}

struct Timer<T> {
    sleep: Pin<Box<Sleep>>,
    duration: Duration,
    event: Event<T>,
}

pub type CryptoEvent<T> = (
    <T as Receiver>::SignedMessage,
    Box<dyn FnOnce(&mut T, <T as Receiver>::SignedMessage) + Send>,
);
type Event<T> = Box<dyn FnOnce(&mut T) + Send>;

#[derive(Debug)]
pub enum Socket {
    Os(UdpSocket),
    Simulated(SimulatedSocket),
}

impl<T: Receiver> Transport<T> {
    pub fn new(config: Config, socket: Socket) -> Self {
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
        Self {
            config,
            crypto_channel: mpsc::channel(64),
            socket,
            timer_table,
            timer_id: 0,
        }
    }

    pub fn send_message(
        &mut self,
        destination: SocketAddr,
        message: impl FnOnce(&mut [u8]) -> usize,
    ) {
        let mut buf = [0; 1400];
        let len = message(&mut buf);
        match &self.socket {
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

    pub fn crypto_sender(&self) -> mpsc::Sender<CryptoEvent<T>> {
        self.crypto_channel.0.clone()
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
    T: Receiver + Send,
    T::SignedMessage: Send,
{
    async fn run(&mut self, close: impl Future<Output = ()> + Send) {
        pin!(close);
        let mut buf = [0; 1400];
        loop {
            let transport = self.transport();
            let (&id, timer) = transport
                .timer_table
                .iter_mut()
                .min_by_key(|(_, timer)| timer.sleep.deadline())
                .unwrap();
            select! {
                _ = &mut close => return,
                _ = timer.sleep.as_mut() => {
                    let timer = self.transport().timer_table.remove(&id).unwrap();
                    (timer.event)(self);
                }
                event = transport.crypto_channel.1.recv() => {
                    let (message, on_message) = event.unwrap();
                    on_message(self, message);
                },
                (len, remote) = transport.socket.receive_from(&mut buf) => {
                    self.receive_message(remote, &buf[..len]);
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
