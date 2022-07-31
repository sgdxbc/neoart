use std::{convert::Infallible, io::Read, net::SocketAddr, str::FromStr};

use bincode::Options;
use rand::random;
use secp256k1::{KeyPair, Secp256k1};
use serde::{de::DeserializeOwned, Serialize};

pub type ClientId = [u8; 4];
pub type ReplicaId = u8;
pub type RequestNumber = u32;
pub type OpNumber = u32;

pub fn random_id() -> ClientId {
    random()
}

pub fn deserialize<M: DeserializeOwned>(buf: impl Read) -> M {
    bincode::options()
        .allow_trailing_bytes()
        .deserialize_from(buf)
        .unwrap()
}

pub fn serialize(mut buf: &mut [u8], message: impl Serialize) -> usize {
    let len = buf.len();
    bincode::options()
        .serialize_into(&mut buf, &message)
        .unwrap();
    len - buf.len()
}

#[derive(Debug, Clone)]
pub struct Config {
    pub n: usize,
    pub f: usize,
    pub replicas: Vec<SocketAddr>,
    pub keys: Vec<KeyPair>,
}

impl FromStr for Config {
    type Err = Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut f = None;
        let mut replicas = vec![];
        for line in s.lines() {
            let line = line.trim_start();
            if let Some(line) = line.strip_prefix('f') {
                f = Some(line.trim_start().parse().unwrap());
            } else if let Some(line) = line.strip_prefix("replica") {
                replicas.push(line.trim_start().parse().unwrap());
            }
        }
        Ok(Self {
            n: replicas.len(),
            f: f.unwrap(),
            replicas,
            keys: vec![],
        })
    }
}

impl Config {
    pub fn gen_keys(&mut self) {
        let secp = Secp256k1::signing_only();
        for i in 0..self.replicas.len() {
            self.keys
                .push(KeyPair::from_seckey_slice(&secp, &[(i + 1) as _; 32]).unwrap());
        }
    }
}
