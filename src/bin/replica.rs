use std::sync::{Arc, Mutex};

use clap::{clap_derive::ArgEnum, Parser};
use neoart::{
    crypto::{CryptoMessage, ExecutorSetting},
    latency::{merge_latency_into, Latency},
    meta::{Config, OpNumber, ReplicaId},
    neo,
    transport::{MulticastVariant, Node, Run, Socket, Transport},
    unreplicated, zyzzyva, App,
};
use nix::{
    sched::{sched_setaffinity, CpuSet},
    unistd::Pid,
};
use serde::de::DeserializeOwned;
use tokio::{fs::read_to_string, net::UdpSocket, signal::ctrl_c};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
enum Mode {
    Ur, // unreplicated
    Zyzzyva,
    Neo,
}

#[derive(Parser)]
struct Args {
    #[clap(short, long)]
    config: String,
    #[clap(short, long, arg_enum)]
    mode: Mode,
    #[clap(short, long)]
    index: ReplicaId,
    #[clap(short = 't', long = "worker", default_value_t = 0)]
    num_worker: usize,
    #[clap(short = 'b', long)]
    enable_batching: bool,
}

struct Null;
impl App for Null {
    fn replica_upcall(&mut self, _: OpNumber, _: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

async fn main_internal<T>(args: Args, new_replica: impl FnOnce(Transport<T>) -> T)
where
    T: Node + AsMut<Transport<T>> + Send,
    T::Message: CryptoMessage + DeserializeOwned,
{
    let mut config: Config = read_to_string(args.config).await.unwrap().parse().unwrap();
    config.gen_keys();

    let mut cpu_set = CpuSet::new();
    cpu_set.set(0).unwrap();
    sched_setaffinity(Pid::from_raw(0), &cpu_set).unwrap();

    let socket = UdpSocket::bind(config.replicas[args.index as usize])
        .await
        .unwrap();
    socket.set_broadcast(true).unwrap();
    socket.writable().await.unwrap();

    let latency = Arc::new(Mutex::new(Latency::default()));
    let setting = match args.num_worker {
        0 => ExecutorSetting::Inline,
        n => ExecutorSetting::Rayon(n, latency.clone()),
    };

    let multicast = config.multicast;
    let mut transport = Transport::new(config, Socket::Os(socket), setting);
    if let Some(multicast) = multicast {
        let socket = UdpSocket::bind((multicast.ip(), multicast.port() + 1))
            .await
            .unwrap();
        transport.listen_multicast(Socket::Os(socket), MulticastVariant::HalfSipHash);
    }

    let mut replica = new_replica(transport);
    replica.run(async { ctrl_c().await.unwrap() }).await;

    println!();
    let aggregated = &mut latency.lock().unwrap();
    merge_latency_into(aggregated);
    aggregated.sort();
    // maybe print it out
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();
    let index = args.index;
    let enable_batching = args.enable_batching;
    match args.mode {
        Mode::Ur => {
            main_internal(args, move |transport| {
                unreplicated::Replica::new(transport, index, Null)
            })
            .await
        }
        Mode::Zyzzyva => {
            main_internal(args, move |transport| {
                zyzzyva::Replica::new(transport, index, Null, enable_batching)
            })
            .await
        }
        Mode::Neo => {
            main_internal(args, move |transport| {
                neo::Replica::new(transport, index, Null)
            })
            .await
        }
    }
}
