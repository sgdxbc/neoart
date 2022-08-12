use std::{
    mem::take,
    net::SocketAddr,
    sync::{Arc, Mutex},
    thread::spawn,
};

use nix::{
    sched::{sched_setaffinity, CpuSet},
    unistd::Pid,
};
use rayon::{ThreadPool, ThreadPoolBuilder};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, SignOnly, VerifyOnly};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Sender;

use crate::{
    latency::{merge_latency_into, Latency},
    meta::{digest, Config, Digest, ReplicaId},
    transport::{CryptoEvent, SignedMessage},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Signature(secp256k1::ecdsa::Signature);
impl Default for Signature {
    fn default() -> Self {
        Self(secp256k1::ecdsa::Signature::from_compact(&[0; 64]).unwrap())
    }
}

pub trait CryptoMessage: Serialize {
    fn signature_mut(&mut self) -> &mut Signature {
        unreachable!()
    }

    fn digest(&self) -> Digest {
        digest(self)
    }
}

pub fn verify_message(message: &mut impl CryptoMessage, public_key: &PublicKey) -> bool {
    thread_local! {
        static SECP: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
    }

    let Signature(signature) = take(message.signature_mut());
    let result = SECP
        .with(|secp| {
            secp.verify_ecdsa(
                &Message::from_slice(&message.digest()).unwrap(),
                &signature,
                public_key,
            )
        })
        .is_ok();
    *message.signature_mut() = Signature(signature);
    result
}

#[derive(Debug)]
pub struct Crypto<M> {
    sender: Sender<CryptoEvent<M>>,
    config: Arc<Config>,
    executor: Executor,
}

#[derive(Debug)]
enum Executor {
    Inline,
    Rayon(ThreadPool),
}

#[derive(Debug, Clone)]
pub enum ExecutorSetting {
    Inline,
    Rayon(usize, Arc<Mutex<Latency>>),
}

impl<M> Crypto<M> {
    pub fn new(config: Config, setting: ExecutorSetting, sender: Sender<CryptoEvent<M>>) -> Self {
        let executor = match setting {
            ExecutorSetting::Inline => Executor::Inline,
            ExecutorSetting::Rayon(num_threads, latency) => Executor::Rayon(
                ThreadPoolBuilder::new()
                    .num_threads(num_threads)
                    .spawn_handler(|thread| {
                        let latency = latency.clone();
                        spawn(move || {
                            let mut cpu_set = CpuSet::new();
                            // save cpu#0 for transport + receiver
                            cpu_set.set(thread.index() + 1).unwrap();
                            sched_setaffinity(Pid::from_raw(0), &cpu_set).unwrap();
                            thread.run();
                            merge_latency_into(&mut latency.lock().unwrap());
                        });
                        Ok(())
                    })
                    .build()
                    .unwrap(),
            ),
        };
        Self {
            sender,
            config: Arc::new(config),
            executor,
        }
    }
}

impl<M> Crypto<M> {
    fn verify_internal(
        &mut self,
        remote: SocketAddr,
        message: M,
        verify_message: impl FnOnce(&mut M, &Config) -> bool + Send + 'static,
    ) where
        M: Send + 'static,
    {
        match &self.executor {
            Executor::Inline => {
                Self::verify_task(remote, message, verify_message, &self.config, &self.sender)
            }
            Executor::Rayon(executor) => {
                let config = self.config.clone();
                let sender = self.sender.clone();
                executor.spawn(move || {
                    Self::verify_task(remote, message, verify_message, &config, &sender)
                });
            }
        }
    }

    pub fn verify_replica(&mut self, remote: SocketAddr, message: M, replica_id: ReplicaId)
    where
        M: CryptoMessage + Send + 'static,
    {
        self.verify_internal(remote, message, move |message, config: &Config| {
            verify_message(message, &config.keys[replica_id as usize].public_key())
        });
    }

    pub fn verify(
        &mut self,
        remote: SocketAddr,
        message: M,
        verify_message: fn(&mut M, &Config) -> bool,
    ) where
        M: Send + 'static,
    {
        self.verify_internal(remote, message, verify_message);
    }

    fn verify_task(
        remote: SocketAddr,
        mut message: M,
        verify_message: impl FnOnce(&mut M, &Config) -> bool,
        config: &Config,
        sender: &Sender<CryptoEvent<M>>,
    ) {
        if verify_message(&mut message, config) {
            sender
                .try_send(CryptoEvent::Verified(remote, message))
                .map_err(|_| panic!())
                .unwrap();
        } else {
            println!("! verify signature error");
        }
    }

    pub fn sign(&mut self, signed_id: SignedMessage, message: M, id: ReplicaId)
    where
        M: CryptoMessage + Send + 'static,
    {
        match &self.executor {
            Executor::Inline => Self::sign_task(
                signed_id,
                message,
                &self.config.keys[id as usize].secret_key(),
                &self.sender,
            ),
            Executor::Rayon(executor) => {
                let secret_key = self.config.keys[id as usize].secret_key();
                let sender = self.sender.clone();
                executor.spawn(move || Self::sign_task(signed_id, message, &secret_key, &sender));
            }
        }
    }

    fn sign_task(
        id: SignedMessage,
        mut message: M,
        secret_key: &SecretKey,
        sender: &Sender<CryptoEvent<M>>,
    ) where
        M: CryptoMessage,
    {
        thread_local! {
            static SECP: Secp256k1<SignOnly> = Secp256k1::signing_only();
        }
        let signature = SECP.with(|secp| {
            secp.sign_ecdsa(&Message::from_slice(&message.digest()).unwrap(), secret_key)
        });
        *message.signature_mut() = Signature(signature);
        sender
            .try_send(CryptoEvent::Signed(id, message))
            .map_err(|_| panic!())
            .unwrap();
    }
}
