use std::{mem::replace, net::SocketAddr, thread::spawn};

use rayon::{ThreadPool, ThreadPoolBuilder};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, SignOnly, VerifyOnly};
use serde::Serialize;
use tokio::sync::mpsc::Sender;

use crate::{
    meta::{digest, Config, ReplicaId},
    transport::{CryptoEvent, SignedMessage},
};

pub type Signature = secp256k1::ecdsa::Signature;

pub trait CryptoMessage: Serialize {
    fn signature_mut(&mut self) -> &mut Signature {
        unreachable!()
    }
}

impl<T: Serialize + AsMut<Signature>> CryptoMessage for T {
    fn signature_mut(&mut self) -> &mut Signature {
        self.as_mut()
    }
}

#[derive(Debug)]
pub struct Crypto<V, S> {
    sender: Sender<CryptoEvent<V, S>>,
    config: Config,
    executor: Executor,
}

#[derive(Debug)]
enum Executor {
    Inline,
    Rayon(ThreadPool),
}

pub enum ExecutorSetting {
    Inline,
    Rayon(usize),
}

impl<V, S> Crypto<V, S> {
    pub fn new(
        config: Config,
        setting: ExecutorSetting,
        sender: Sender<CryptoEvent<V, S>>,
    ) -> Self {
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

impl<V, S> Crypto<V, S> {
    pub fn verify(&mut self, message: V, id: ReplicaId)
    where
        V: CryptoMessage + Send + 'static,
        CryptoEvent<V, S>: Send + 'static,
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
        mut message: V,
        public_key: &PublicKey,
        sender: &Sender<CryptoEvent<V, S>>,
    ) where
        V: CryptoMessage,
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
                    &Message::from_slice(&digest(&message)).unwrap(),
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

    pub fn sign(&mut self, signed_id: SignedMessage, message: S, id: ReplicaId)
    where
        S: CryptoMessage + Send + 'static,
        CryptoEvent<V, S>: Send + 'static,
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
        mut message: S,
        secret_key: &SecretKey,
        sender: &Sender<CryptoEvent<V, S>>,
    ) where
        S: CryptoMessage,
    {
        thread_local! {
            static SECP: Secp256k1<SignOnly> = Secp256k1::signing_only();
        }
        let signature = SECP.with(|secp| {
            secp.sign_ecdsa(&Message::from_slice(&digest(&message)).unwrap(), secret_key)
        });
        *message.signature_mut() = signature;
        sender
            .try_send(CryptoEvent::Signed(id, message))
            .map_err(|_| panic!())
            .unwrap();
    }
}
