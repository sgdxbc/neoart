use std::{
    net::Ipv4Addr,
    str::FromStr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use clap::{clap_derive::ArgEnum, Parser};
use neoart::{
    crypto::{CryptoMessage, ExecutorSetting},
    latency::{
        merge_latency_into, push_latency, Latency,
        Point::{RequestBegin, RequestEnd},
    },
    meta::Config,
    transport::{Receiver, Run, Socket, Transport},
    unreplicated, zyzzyva, Client,
};
use tokio::{
    fs::read_to_string, net::UdpSocket, pin, runtime, select, spawn, sync::Notify, time::sleep,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
enum Mode {
    Ur, // unreplicated
    Zyzzyva,
    ZyzzyvaByz,
}

#[derive(Parser)]
struct Args {
    #[clap(short, long)]
    config: String,
    #[clap(short, long)]
    host: String,
    #[clap(short, long, arg_enum)]
    mode: Mode,
    #[clap(short = 't', long = "num", default_value_t = 1)]
    n: u32,
}

async fn main_internal<T>(
    args: Args,
    new_client: impl FnOnce(Transport<T>) -> T + Clone + Send + 'static,
) where
    T: Receiver + Client + AsMut<Transport<T>> + Send,
    T::Message: CryptoMessage,
{
    let config: Config = read_to_string(args.config).await.unwrap().parse().unwrap();

    let notify = Arc::new(Notify::new());
    let throughput = Arc::new(AtomicU32::new(0));
    let address = (Ipv4Addr::from_str(&args.host).unwrap(), 0);
    let clients = (0..args.n)
        .map(|i| {
            let config = config.clone();
            let notify = notify.clone();
            let throughput = throughput.clone();
            let new_client = new_client.clone();
            spawn(async move {
                let socket = UdpSocket::bind(address).await.unwrap();
                socket.writable().await.unwrap();
                let transport = Transport::new(config, Socket::Os(socket), ExecutorSetting::Inline);
                let mut client = new_client(transport);
                let notified = notify.notified();
                pin!(notified);

                let mut closed = false;
                while !closed {
                    push_latency(RequestBegin(i));
                    let result = client.invoke(&[]);
                    client
                        .run(async {
                            select! {
                                _ = result => {
                                    push_latency(RequestEnd(i));
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

    for _ in 0..20 {
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
}

fn main() {
    let args = Args::parse();
    let num_client = args.n;

    let latency = Arc::new(Mutex::new(Latency::default()));
    runtime::Builder::new_multi_thread()
        .enable_all()
        .on_thread_stop({
            let latency = latency.clone();
            move || merge_latency_into(&mut latency.lock().unwrap())
        })
        .build()
        .unwrap()
        .block_on(async {
            match args.mode {
                Mode::Ur => main_internal(args, unreplicated::Client::new).await,
                Mode::Zyzzyva => {
                    main_internal(args, |transport| zyzzyva::Client::new(transport, false)).await
                }
                Mode::ZyzzyvaByz => {
                    main_internal(args, |transport| zyzzyva::Client::new(transport, true)).await
                }
            }
        });

    let aggregated = &mut latency.lock().unwrap();
    merge_latency_into(aggregated);
    aggregated.sort();
    let mut intervals = Vec::new();
    for i in 0..num_client {
        intervals.extend(aggregated.intervals(RequestBegin(i), RequestEnd(i)));
    }
    if !intervals.is_empty() {
        intervals.sort_unstable();
        println!("* 50th latency: {:?}", intervals[intervals.len() / 2]);
    }
}
