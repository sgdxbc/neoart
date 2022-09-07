use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};

use crate::{
    meta::{Config, OpNumber, ReplicaId},
    transport::MulticastVariant,
};

pub mod common;
pub mod crypto;
pub mod latency;
pub mod meta;
pub mod neo;
pub mod transport;
pub mod unreplicated;
pub mod ycsb;
pub mod zyzzyva;

pub trait Client {
    fn invoke(&mut self, op: &[u8]) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>>;
}

pub trait App {
    fn replica_upcall(&mut self, op_number: OpNumber, op: &[u8]) -> Vec<u8>;
    #[allow(unused_variables)]
    fn rollback_upcall(
        &mut self,
        current_number: OpNumber,
        to_number: OpNumber,
        ops: &[(OpNumber, &[u8])],
    ) {
        unimplemented!()
    }
    #[allow(unused_variables)]
    fn commit_upcall(&mut self, op_number: OpNumber) {}
}

/// Common configuration shared by matrix binary and control plane binary.
///
// I guess there is no better place to put sharing pieces so it has to be here
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MatrixArgs {
    pub config: Config,
    pub task: MatrixTask,
    pub replica_id: ReplicaId,
    pub host: [u8; 4],
    pub num_worker: usize,
    pub num_client: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatrixTask {
    Unknown,
    UnreplicatedReplica,
    UnreplicatedClient,
    ZyzzyvaReplica { enable_batching: bool },
    ZyzzyvaClient { assume_byz: bool },
    NeoReplica { variant: MulticastVariant },
    NeoClient,
}
impl Default for MatrixTask {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeServerIn {
    Upgrade(Vec<u8>),
    Restart,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeServerOut {
    Ready,
    Output(String),
}
