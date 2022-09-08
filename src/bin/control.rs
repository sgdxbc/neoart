use std::{env::args, iter::once};

use bincode::Options;
use neoart::{
    meta::{ReplicaId, CODE_SERVER_PORT},
    CodeServerIn,
};
use serde::Deserialize;
use tokio::{
    fs::{read, read_to_string},
    io::AsyncWriteExt,
    net::TcpStream,
    spawn,
};
use toml::value::Table;

#[derive(Debug, Deserialize)]
struct Spec {
    task: Table,
    replica: Vec<Table>,
    client: Vec<Table>,
    multicast: Table,
}

#[tokio::main]
async fn main() {
    let spec = toml::from_str::<Spec>(&read_to_string("spec.toml").await.unwrap()).unwrap();
    match args().nth(1).as_deref() {
        Some("put") => put(node_set(&spec)).await,
        Some("run") => {
            let tasks = spec
                .replica
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, node)| {
                    let task = spec.task.clone();
                    spawn(async move { run_replica(&task, index, &node).await })
                })
                .collect::<Vec<_>>();
            for task in tasks {
                task.await.unwrap();
            }
        }
        _ => panic!(),
    }
}

async fn put(nodes: impl Iterator<Item = &Table>) {
    let exe = read("./target/release/matrix").await.unwrap();
    let message = bincode::options()
        .serialize(&CodeServerIn::Upgrade(exe))
        .unwrap();
    let tasks = nodes.map(|node| {
        let control_host = node["control-host"].as_str().unwrap().to_string();
        let message = message.clone();
        spawn(async move {
            let mut code_server = TcpStream::connect((control_host, CODE_SERVER_PORT))
                .await
                .unwrap();
            code_server.write_u32(message.len() as _).await.unwrap();
            code_server.write_all(&message).await.unwrap();
        })
    });
    for task in tasks {
        task.await.unwrap();
    }
}

fn node_set(spec: &Spec) -> Box<dyn Iterator<Item = &Table> + '_> {
    match spec.task["mode"].as_str().unwrap() {
        "ur" => Box::new(once(&spec.replica[0]).chain(spec.client.iter())),
        "zyzzyva" | "neo" => Box::new(spec.replica.iter().chain(spec.client.iter())),
        _ => panic!(),
    }
}

async fn run_replica(task: &Table, index: usize, node: &Table) {
    match task["mode"].as_str().unwrap() {
        "ur" => {}
        _ => panic!(),
    }
}
