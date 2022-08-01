use std::future::pending;

use neoart::{
    crypto::ExecutorSetting,
    meta::{Config, OpNumber},
    transport::{Run, Socket, Transport},
    unreplicated, App,
};
use tokio::net::UdpSocket;

struct Null;
impl App for Null {
    fn replica_upcall(&mut self, _: OpNumber, _: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut config: Config = "
        f 0
        replica 127.0.0.1:2023
    "
    .parse()
    .unwrap();
    config.gen_keys();

    let socket = UdpSocket::bind(config.replicas[0]).await.unwrap();
    let transport = Transport::new(config, Socket::Os(socket), ExecutorSetting::Rayon(8));
    let mut replica = unreplicated::Replica::new(transport, 0, Null);
    replica.run(pending()).await;
}
