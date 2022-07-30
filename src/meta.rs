use std::{convert::Infallible, io::Read, net::SocketAddr, str::FromStr};

use bincode::Options;
use rand::random;
use secp256k1::{PublicKey, SecretKey};
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
    pub secret_keys: Vec<SecretKey>,
    pub public_keys: Vec<PublicKey>,
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
            secret_keys: vec![],
            public_keys: vec![],
        })
    }
}
