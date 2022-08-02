use std::{future::Future, pin::Pin};

use meta::OpNumber;

pub mod common;
pub mod crypto;
pub mod latency;
pub mod meta;
pub mod transport;
pub mod unreplicated;
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
