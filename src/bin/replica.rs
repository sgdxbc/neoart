use std::time::Duration;

use clap::{clap_derive::ArgEnum, Parser};
use neoart::{
    crypto::{CryptoMessage, ExecutorSetting},
    latency::{merge_latency_with, Latency},
    meta::{Config, OpNumber, ReplicaId},
    transport::{
        CryptoBegin, CryptoEnd, ReceiveBegin, ReceiveEnd, Receiver, ReceiverBegin, ReceiverEnd,
        Run, SendBegin, SendEnd, Socket, Transport,
    },
    unreplicated, zyzzyva, App,
};
use nix::{
    sched::{sched_setaffinity, CpuSet},
    unistd::Pid,
};
use tokio::{net::UdpSocket, signal::ctrl_c};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
enum Mode {
    Ur, // unreplicated
    Zyzzyva,
}

#[derive(Parser)]
struct Args {
    #[clap(short, long, arg_enum)]
    mode: Mode,
    #[clap(short, long)]
    index: ReplicaId,
    #[clap(short = 't', long = "worker", default_value_t = 0)]
    num_worker: usize,
}

struct Null;
impl App for Null {
    fn replica_upcall(&mut self, _: OpNumber, _: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

async fn main_internal<T>(args: Args, new_replica: impl FnOnce(Transport<T>) -> T)
where
    T: Receiver + AsMut<Transport<T>> + Send,
    T::Message: CryptoMessage,
{
    let mut config: Config = include_str!("config.txt").parse().unwrap();
    config.gen_keys();

    let mut cpu_set = CpuSet::new();
    cpu_set.set(0).unwrap();
    sched_setaffinity(Pid::from_raw(0), &cpu_set).unwrap();

    let socket = UdpSocket::bind(config.replicas[args.index as usize])
        .await
        .unwrap();
    let setting = match args.num_worker {
        0 => ExecutorSetting::Inline,
        n => ExecutorSetting::Rayon(n),
    };

    let transport = Transport::new(config, Socket::Os(socket), setting);
    let mut replica = new_replica(transport);
    replica.run(async { ctrl_c().await.unwrap() }).await;

    println!();
    let mut aggregated = Latency::default();
    merge_latency_with(&mut aggregated);
    println!(
        "receive {:.3?} send {:.3?} crypto {:.3?} receiver {:.3?}",
        aggregated
            .intervals::<ReceiveBegin, ReceiveEnd>()
            .into_iter()
            .skip(1) // before client initialized
            .sum::<Duration>(),
        aggregated
            .intervals::<SendBegin, SendEnd>()
            .into_iter()
            .sum::<Duration>(),
        aggregated
            .intervals::<CryptoBegin, CryptoEnd>()
            .into_iter()
            .sum::<Duration>(),
        aggregated
            .intervals::<ReceiverBegin, ReceiverEnd>()
            .into_iter()
            .sum::<Duration>(),
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();
    let index = args.index;
    match args.mode {
        Mode::Ur => {
            main_internal(args, move |transport| {
                unreplicated::Replica::new(transport, index, Null)
            })
            .await
        }
        Mode::Zyzzyva => {
            main_internal(args, move |transport| {
                zyzzyva::Replica::new(transport, index, Null)
            })
            .await
        }
    }
}
