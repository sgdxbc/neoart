use std::future::pending;

use clap::{clap_derive::ArgEnum, Parser};
use neoart::{
    crypto::{CryptoMessage, ExecutorSetting},
    meta::{Config, OpNumber, ReplicaId},
    transport::{Receiver, Run, Socket, Transport},
    unreplicated, zyzzyva, App,
};
use tokio::net::UdpSocket;

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
    #[clap(long = "worker", default_value_t = 0)]
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

    let socket = UdpSocket::bind(config.replicas[args.index as usize])
        .await
        .unwrap();
    let setting = match args.num_worker {
        0 => ExecutorSetting::Inline,
        n => ExecutorSetting::Rayon(n),
    };

    let transport = Transport::new(config, Socket::Os(socket), setting);
    let mut replica = new_replica(transport);
    replica.run(pending()).await;
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
