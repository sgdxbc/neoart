use std::{mem::replace, net::SocketAddr, thread::spawn};

use rayon::{ThreadPool, ThreadPoolBuilder};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, SignOnly, VerifyOnly};
use serde::Serialize;
use tokio::sync::mpsc::Sender;

use crate::{
    meta::{digest, Config, Digest, ReplicaId},
    transport::{CryptoEvent, SignedMessage},
};

pub type Signature = secp256k1::ecdsa::Signature;

pub trait CryptoMessage: Serialize {
    fn signature_mut(&mut self) -> &mut Signature {
        unreachable!()
    }

    fn digest(&self) -> Digest {
        digest(self)
    }
}

#[derive(Debug)]
pub struct Crypto<M> {
    sender: Sender<CryptoEvent<M>>,
    config: Config,
    executor: Executor,
}

#[derive(Debug)]
enum Executor {
    Inline,
    Rayon(ThreadPool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutorSetting {
    Inline,
    Rayon(usize),
}

impl<M> Crypto<M> {
    pub fn new(config: Config, setting: ExecutorSetting, sender: Sender<CryptoEvent<M>>) -> Self {
        let executor = match setting {
            ExecutorSetting::Inline => Executor::Inline,
            ExecutorSetting::Rayon(num_threads) => Executor::Rayon(
                ThreadPoolBuilder::new()
                    .num_threads(num_threads)
                    .spawn_handler(|thread| {
                        // set affinity, etc.
                        spawn(|| thread.run());
                        Ok(())
                    })
                    .build()
                    .unwrap(),
            ),
        };
        Self {
            sender,
            config,
            executor,
        }
    }
}

impl<M> Crypto<M> {
    pub fn verify(&mut self, message: M, id: ReplicaId)
    where
        M: CryptoMessage + Send + 'static,
    {
        match &self.executor {
            Executor::Inline => Self::verify_task(
                self.config.replicas[id as usize],
                message,
                &self.config.keys[id as usize].public_key(),
                &self.sender,
            ),
            Executor::Rayon(executor) => {
                let public_key = self.config.keys[id as usize].public_key();
                let remote = self.config.replicas[id as usize];
                let sender = self.sender.clone();
                executor.spawn(move || Self::verify_task(remote, message, &public_key, &sender));
            }
        }
    }

    fn verify_task(
        remote: SocketAddr,
        mut message: M,
        public_key: &PublicKey,
        sender: &Sender<CryptoEvent<M>>,
    ) where
        M: CryptoMessage,
    {
        thread_local! {
            static SECP: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
        }

        let signature = replace(
            message.signature_mut(),
            Signature::from_compact(&[0; 32]).unwrap(),
        );
        if SECP
            .with(|secp| {
                secp.verify_ecdsa(
                    &Message::from_slice(&message.digest()).unwrap(),
                    &signature,
                    public_key,
                )
            })
            .is_ok()
        {
            *message.signature_mut() = signature;
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
        *message.signature_mut() = signature;
        sender
            .try_send(CryptoEvent::Signed(id, message))
            .map_err(|_| panic!())
            .unwrap();
    }
}
