use std::{
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use clap::{clap_derive::ArgEnum, Parser};
use neoart::{
    crypto::{CryptoMessage, ExecutorSetting},
    latency::{merge_latency_with, push_latency, Latency},
    meta::Config,
    transport::{Receiver, Run, Socket, Transport},
    unreplicated, zyzzyva, Client,
};
use tokio::{net::UdpSocket, pin, select, spawn, sync::Notify, time::sleep};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
enum Mode {
    Ur, // unreplicated
    Zyzzyva,
}

#[derive(Parser)]
struct Args {
    #[clap(short, long, arg_enum)]
    mode: Mode,
    #[clap(short = 't', long = "num", default_value_t = 1)]
    n: u32,
}

struct RequestBegin;
struct RequestEnd;

async fn main_internal<T>(
    args: Args,
    new_client: impl FnOnce(Transport<T>) -> T + Clone + Send + 'static,
) where
    T: Receiver + Client + AsMut<Transport<T>> + Send,
    T::Message: CryptoMessage,
{
    let config: Config = include_str!("config.txt").parse().unwrap();

    let notify = Arc::new(Notify::new());
    let throughput = Arc::new(AtomicU32::new(0));
    let clients = (0..args.n)
        .map(|i| {
            let config = config.clone();
            let notify = notify.clone();
            let throughput = throughput.clone();
            let new_client = new_client.clone();
            spawn(async move {
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                socket.writable().await.unwrap();
                let transport = Transport::new(config, Socket::Os(socket), ExecutorSetting::Inline);
                let mut client = new_client(transport);
                let notified = notify.notified();
                pin!(notified);

                let mut closed = false;
                while !closed {
                    push_latency::<RequestBegin>(i);
                    let result = client.invoke(&[]);
                    client
                        .run(async {
                            select! {
                                _ = result => {
                                    push_latency::<RequestEnd>(i);
                                    throughput.fetch_add(1, Ordering::SeqCst);
                                }
                                _ = &mut notified => closed = true,
                            }
                        })
                        .await;
                }
            })
        })
        .collect::<Vec<_>>();

    for _ in 0..10 {
        sleep(Duration::from_secs(1)).await;
        println!(
            "* interval throughput {} ops/sec",
            throughput.swap(0, Ordering::SeqCst)
        );
    }

    notify.notify_waiters();
    for client in clients {
        client.await.unwrap();
    }

    let mut aggregated = Latency::default();
    merge_latency_with(&mut aggregated);
    let mut intervals = aggregated.intervals::<RequestBegin, RequestEnd>();
    if !intervals.is_empty() {
        intervals.sort_unstable();
        println!("* 50th latency: {:?}", intervals[intervals.len() / 2]);
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();
    match args.mode {
        Mode::Ur => main_internal(args, |transport| unreplicated::Client::new(transport)).await,
        Mode::Zyzzyva => main_internal(args, |transport| zyzzyva::Client::new(transport)).await,
    }
}
