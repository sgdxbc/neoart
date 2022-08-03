use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::meta::{deserialize, serialize, OpNumber};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    Read(String),
    Scan(String, usize),
    Update(String, String),
    Insert(String, String),
    Delete(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Result {
    ReadOk(String),
    ScanOk(Vec<String>),
    UpdateOk,
    InsertOk,
    DeleteOk,
    NotFound,
    // batched?
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct App(BTreeMap<String, String>);
impl crate::App for App {
    fn replica_upcall(&mut self, _: OpNumber, op: &[u8]) -> Vec<u8> {
        let Self(table) = self;
        let result = match deserialize(op) {
            Op::Read(key) => {
                if let Some(value) = table.get(&key).cloned() {
                    Result::ReadOk(value)
                } else {
                    Result::NotFound
                }
            }
            Op::Scan(key, count) => {
                let values = table
                    .range(key..)
                    .map(|(_, value)| value.clone())
                    .take(count)
                    .collect();
                Result::ScanOk(values)
            }
            Op::Update(key, value) => {
                if let Some(value_mut) = table.get_mut(&key) {
                    *value_mut = value;
                    Result::UpdateOk
                } else {
                    Result::NotFound
                }
            }
            Op::Insert(key, value) => {
                table.insert(key, value); // check for override?
                Result::InsertOk
            }
            Op::Delete(key) => {
                if table.remove(&key).is_some() {
                    Result::DeleteOk
                } else {
                    Result::NotFound
                }
            }
        };
        let mut buf = Vec::new();
        serialize(&mut buf, result);
        buf
    }
}
