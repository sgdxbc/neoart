use std::{collections::HashMap, future::Future, net::SocketAddr, pin::Pin, time::Duration};

use async_trait::async_trait;
use tokio::{
    net::UdpSocket,
    pin, select,
    sync::mpsc,
    time::{sleep, Instant, Sleep},
};

use crate::meta::Config;

pub trait Receiver: Sized {
    fn receive_message(&mut self, remote: SocketAddr, buf: &[u8]);
    fn transport(&mut self) -> &mut Transport<Self>;
}

pub struct Transport<T> {
    pub config: Config,
    event_bus: (mpsc::Sender<Event<T>>, mpsc::Receiver<Event<T>>),
    socket: UdpSocket,
    timer_table: HashMap<u32, Timer<T>>,
    timer_id: u32,
}

type Event<T> = Box<dyn FnOnce(&mut T) + Send>;

struct Timer<T> {
    sleep: Pin<Box<Sleep>>,
    duration: Duration,
    event: Event<T>,
}

impl<T> Transport<T> {
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
            event_bus: mpsc::channel(64),
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
}

#[async_trait]
pub trait Run {
    async fn run(&mut self, close: impl Future<Output = ()> + Send);
}

#[async_trait]
impl<T: Receiver + Send> Run for T {
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
                event = transport.event_bus.1.recv() => event.unwrap()(self),
                message = transport.socket.recv_from(&mut buf) => {
                    let (len, remote) = message.unwrap();
                    self.receive_message(remote, &buf[..len]);
                }
            }
        }
    }
}
