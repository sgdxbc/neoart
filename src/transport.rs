use std::{collections::HashMap, future::Future, net::SocketAddr, pin::Pin, time::Duration};

use async_trait::async_trait;
use tokio::{
    net::UdpSocket,
    pin, select,
    sync::mpsc,
    time::{sleep, Instant, Sleep},
};

use crate::{crypto::Signature, meta::Config};

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
    socket: UdpSocket,
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

impl<T: Receiver> Transport<T> {
    pub fn new(config: Config, socket: UdpSocket) -> Self {
        let mut timer_table = HashMap::new();
        // insert a sentinel entry to make sure we get always get a `sleep` to
        // select from timer table in `run`
        timer_table.insert(
            u32::MAX,
            Timer {
                sleep: Box::pin(sleep(Duration::from_secs(3600))),
                duration: Duration::ZERO,
                event: Box::new(|_| {}),
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
        self.socket.try_send_to(&buf[..len], destination).unwrap();
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
                message = transport.socket.recv_from(&mut buf) => {
                    let (len, remote) = message.unwrap();
                    self.receive_message(remote, &buf[..len]);
                }
            }
        }
    }
}
