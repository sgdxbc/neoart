use std::future::pending;

use neoart::{
    crypto::ExecutorSetting,
    meta::{Config, OpNumber},
    transport::{Run, Transport},
    unreplicated, App,
};
use secp256k1::{Secp256k1, SecretKey};
use tokio::net::UdpSocket;

struct Null;
impl App for Null {
    fn replica_upcall(&mut self, _: OpNumber, _: &[u8]) -> Vec<u8> {
        vec![]
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
    config
        .secret_keys
        .push(SecretKey::from_slice(&[0xab; 32]).unwrap());
    config
        .public_keys
        .push(config.secret_keys[0].public_key(&Secp256k1::new()));

    let socket = UdpSocket::bind(config.replicas[0]).await.unwrap();
    let transport = Transport::new(config, socket);
    let mut replica = unreplicated::Replica::new(transport, ExecutorSetting::Rayon(8), 0, Null);
    replica.run(pending()).await;
}
