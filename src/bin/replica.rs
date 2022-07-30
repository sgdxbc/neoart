use std::future::pending;

use neoart::{
    meta::{Config, OpNumber},
    transport::{Run, Transport},
    unreplicated, App,
};
use tokio::net::UdpSocket;

struct Null;
impl App for Null {
    fn replica_upcall(&mut self, _: OpNumber, _: &[u8]) -> Vec<u8> {
        vec![]
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let config: Config = "
        f 0
        replica 127.0.0.1:2023
    "
    .parse()
    .unwrap();
    let socket = UdpSocket::bind(config.replicas()[0]).await.unwrap();
    let transport = Transport::new(config, socket);
    let mut replica = unreplicated::Replica::new(transport, 0, Null);
    replica.run(pending()).await;
}
