use std::thread::spawn;

use bincode::Options;
use rayon::{ThreadPool, ThreadPoolBuilder};
use secp256k1::{
    hashes::sha256, KeyPair, Message, PublicKey, Secp256k1, SecretKey, SignOnly, VerifyOnly,
};
use serde::Serialize;
use tokio::sync::mpsc::Sender;

use crate::{
    meta::ReplicaId,
    transport::{CryptoEvent, Receiver, Transport},
};

pub type Signature = secp256k1::ecdsa::Signature;

#[derive(Debug)]
pub struct Crypto<T: Receiver> {
    sender: Sender<CryptoEvent<T>>,
    keys: Vec<KeyPair>,
    replica_id: ReplicaId,
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

impl<T: Receiver> Crypto<T> {
    pub fn new(transport: &Transport<T>, id: ReplicaId, setting: ExecutorSetting) -> Self {
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
            sender: transport.crypto_sender(),
            keys: transport.config.keys.clone(),
            replica_id: id,
            executor,
        }
    }

    pub fn sign(
        &mut self,
        message: T::SignedMessage,
        on_message: impl FnOnce(&mut T, T::SignedMessage) + Send + 'static,
    ) where
        T::SignedMessage: Serialize + Send + 'static,
        T: 'static,
    {
        match &self.executor {
            Executor::Inline => Self::sign_task(
                message,
                on_message,
                &self.keys[self.replica_id as usize].secret_key(),
                &self.sender,
            ),
            Executor::Rayon(executor) => {
                let secret_key = self.keys[self.replica_id as usize].secret_key();
                let sender = self.sender.clone();
                executor.spawn(move || Self::sign_task(message, on_message, &secret_key, &sender))
            }
        }
    }

    fn sign_task(
        mut message: T::SignedMessage,
        on_message: impl FnOnce(&mut T, T::SignedMessage) + Send + 'static,
        secret_key: &SecretKey,
        sender: &Sender<CryptoEvent<T>>,
    ) where
        T::SignedMessage: Serialize,
    {
        thread_local! {
            static SECP: Secp256k1<SignOnly> = Secp256k1::signing_only();
        }
        let digest = Message::from_hashed_data::<sha256::Hash>(
            &bincode::options().serialize(&message).unwrap(),
        );
        let signature = SECP.with(|secp| secp.sign_ecdsa(&digest, secret_key));
        T::set_signature(&mut message, signature);
        sender
            .try_send((message, Box::new(on_message)))
            .map_err(|_| panic!())
            .unwrap();
    }

    pub fn verify(
        &mut self,
        message: T::SignedMessage,
        id: ReplicaId,
        on_message: impl FnOnce(&mut T, T::SignedMessage) + Send + 'static,
    ) where
        T::SignedMessage: Serialize + Send + 'static,
        T: 'static,
    {
        match &self.executor {
            Executor::Inline => Self::verify_task(
                message,
                on_message,
                &self.keys[id as usize].public_key(),
                &self.sender,
            ),
            Executor::Rayon(executor) => {
                let public_key = self.keys[id as usize].public_key();
                let sender = self.sender.clone();
                executor.spawn(move || Self::verify_task(message, on_message, &public_key, &sender))
            }
        }
    }

    fn verify_task(
        message: T::SignedMessage,
        on_message: impl FnOnce(&mut T, T::SignedMessage) + Send + 'static,
        public_key: &PublicKey,
        sender: &Sender<CryptoEvent<T>>,
    ) where
        T::SignedMessage: Serialize,
    {
        thread_local! {
            static SECP: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
        }
        let digest = Message::from_hashed_data::<sha256::Hash>(
            &bincode::options().serialize(&message).unwrap(),
        );
        if SECP
            .with(|secp| secp.verify_ecdsa(&digest, T::signature(&message), public_key))
            .is_ok()
        {
            sender
                .try_send((message, Box::new(on_message)))
                .map_err(|_| panic!())
                .unwrap();
        } else {
            println!("! verify signature error");
        }
    }
}
