use std::collections::HashMap;

use crate::{meta::OpNumber, App};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TestApp {
    //
}

impl App for TestApp {
    fn replica_upcall(&mut self, op_number: OpNumber, op: &[u8]) -> Vec<u8> {
        [format!("[{op_number}] ").as_bytes(), op].concat()
    }
}

pub struct Reorder<M> {
    expected: u32,
    messages: HashMap<u32, M>,
}

impl<M> Reorder<M> {
    pub fn new(expected: u32) -> Self {
        Self {
            expected,
            messages: HashMap::new(),
        }
    }

    pub fn insert_reorder(&mut self, order: u32, message: M) -> Option<M> {
        assert!(order >= self.expected);
        if self.expected != order {
            self.messages.insert(order, message);
            None
        } else {
            Some(message)
        }
    }

    pub fn expect_next(&mut self) -> Option<M> {
        self.expected += 1;
        self.messages.remove(&self.expected)
    }
}
