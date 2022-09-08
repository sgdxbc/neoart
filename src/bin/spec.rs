use std::{
    env::args,
    io::{stdout, Write},
    net::{Ipv4Addr, SocketAddr},
    process::Stdio,
    time::Duration,
};

use bincode::Options;
use neoart::{
    meta::{
        Config, ReplicaId, ARGS_SERVER_PORT, MULTICAST_CONTROL_RESET_PORT, MULTICAST_PORT,
        REPLICA_PORT,
    },
    transport::MulticastVariant,
    MatrixArgs, MatrixProtocol,
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::Deserialize;
use tokio::{
    fs::{read_to_string, write},
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    process::Command,
    select,
    signal::ctrl_c,
    spawn,
    sync::mpsc,
    task::JoinHandle,
    time::sleep,
};

#[derive(Debug, Clone, Deserialize)]
struct Spec {
    task: Task,
    replica: Vec<Node>,
    client: Vec<Node>,
    multicast: SpecMulticast,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Task {
    mode: String,
    #[serde(default)]
    f: usize,
    assume_byz: bool,
    num_worker: usize,
    num_client: u32,
    batching: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Node {
    control_user: String,
    control_host: String,
    ip: Ipv4Addr,
    link: String,
    #[serde(default)]
    link_speed: String,
    dev_port: u8,
}

#[derive(Debug, Clone, Deserialize)]
struct SpecMulticast {
    ip: Ipv4Addr,
    variant: MulticastVariant,
}

#[tokio::main]
async fn main() {
    let mut spec = toml::from_str::<Spec>(&read_to_string("spec.toml").await.unwrap()).unwrap();
    if args().nth(1).as_deref() == Some("sw") {
        write("sw/neo_s.py", rewrite_sw(spec.clone(), false))
            .await
            .unwrap();
        write("sw/neo_s-sim.py", rewrite_sw(spec.clone(), true))
            .await
            .unwrap();
        return;
    }

    let rebuild = Command::new("cargo")
        .args(["build", "--release", "--bin", "matrix"])
        .spawn()
        .unwrap()
        .wait()
        .await
        .unwrap();
    assert!(rebuild.success());

    if spec.task.f == 0 {
        spec.task.f = if spec.task.mode == "ur" { 0 } else { 1 };
    }
    let n = if spec.task.assume_byz {
        2 * spec.task.f + 1
    } else {
        3 * spec.task.f + 1
    };

    let mut instance_channel = mpsc::channel(1024);
    let replica_tasks = spec
        .replica
        .iter()
        .take(n)
        .enumerate()
        .map(|(index, node)| {
            let spec = spec.clone();
            let node = node.clone();
            let instance_channel = instance_channel.0.clone();
            spawn(async move {
                let matrix = up_node(node.clone(), format!("[{index}]")).await;
                sleep(Duration::from_secs(1)).await;
                let args = replica_args(spec, index);
                instance_channel
                    .send((node.clone(), args.instance_id.clone()))
                    .await
                    .unwrap();
                configure_node(node.clone(), args).await;
                matrix.await.unwrap();
            })
        })
        .collect::<Vec<_>>();
    sleep(Duration::from_secs(1)).await;
    let client_tasks = spec
        .client
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let spec = spec.clone();
            let node = node.clone();
            let instance_channel = instance_channel.0.clone();
            spawn(async move {
                let matrix = up_node(node.clone(), format!("[C]")).await;
                sleep(Duration::from_secs(1)).await;
                let args = client_args(spec, index);
                instance_channel
                    .send((node.clone(), args.instance_id.clone()))
                    .await
                    .unwrap();
                configure_node(node.clone(), args).await;
                matrix.await.unwrap();
            })
        })
        .collect::<Vec<_>>();

    for task in client_tasks {
        select! {
            joined = task => joined.unwrap(),
            _ = ctrl_c() => break,
        }
    }
    println!();
    instance_channel.1.close();
    while let Some((node, instance_id)) = instance_channel.1.recv().await {
        down_node(node, instance_id).await;
    }
    for task in replica_tasks {
        task.await.unwrap();
    }
}

async fn up_node(node: Node, tag: String) -> JoinHandle<()> {
    let rsync = Command::new("rsync")
        .arg("target/release/matrix")
        .arg(format!(
            "{}@{}:neo-matrix",
            node.control_user, node.control_host
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .await
        .unwrap();
    if !rsync.status.success() {
        todo!()
    }

    let mut matrix = Command::new("ssh")
        .arg(format!("{}@{}", node.control_user, node.control_host))
        .arg(format!("./neo-matrix {}", node.control_host))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut matrix_stream = BufReader::new(matrix.stdout.take().unwrap()).lines();
    spawn(async move {
        while let Some(line) = matrix_stream.next_line().await.unwrap() {
            println!("{tag} {line}");
        }
        let status = matrix.wait().await.unwrap();
        if status.success() {
            println!("[S] * node {tag} {status}");
        } else {
            let mut error_string = String::new();
            matrix
                .stderr
                .unwrap()
                .read_to_string(&mut error_string)
                .await
                .unwrap();
            let mut out = stdout().lock();
            writeln!(out, "[S] * node {tag} {status}").unwrap();
            writeln!(out, "{error_string}").unwrap();
            writeln!(out, "--- end of standard error ---").unwrap();
        }
    })
}

async fn down_node(node: Node, instance_id: String) {
    Command::new("ssh")
        .arg(format!("{}@{}", node.control_user, node.control_host))
        .arg(format!("kill -INT $(cat pid.{instance_id})"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
        .wait()
        .await
        .unwrap();
}

async fn configure_node(node: Node, args: MatrixArgs) {
    let message = bincode::options().serialize(&args).unwrap();
    TcpStream::connect((node.control_host, ARGS_SERVER_PORT))
        .await
        .unwrap()
        .write_all(&message)
        .await
        .unwrap();
}

fn config(spec: Spec) -> Config {
    Config {
        n: spec.replica.len(),
        f: spec.task.f,
        replicas: spec
            .replica
            .iter()
            .map(|node| SocketAddr::from((node.ip, REPLICA_PORT)))
            .collect(),
        multicast: SocketAddr::from((spec.multicast.ip, MULTICAST_PORT)),
        ..Config::default()
    }
}

fn instance_id() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect()
}

fn replica_args(spec: Spec, index: usize) -> MatrixArgs {
    MatrixArgs {
        instance_id: instance_id(),
        config: config(spec.clone()),
        protocol: match &*spec.task.mode {
            "ur" => MatrixProtocol::UnreplicatedReplica,
            "zyzzyva" => MatrixProtocol::ZyzzyvaReplica {
                enable_batching: spec.task.batching,
            },
            _ => panic!(),
        },
        replica_id: index as ReplicaId,
        host: String::from("0.0.0.0"),
        num_worker: spec.task.num_worker,
        num_client: 0,
    }
}

fn client_args(spec: Spec, index: usize) -> MatrixArgs {
    MatrixArgs {
        instance_id: instance_id(),
        config: config(spec.clone()),
        protocol: match &*spec.task.mode {
            "ur" => MatrixProtocol::UnreplicatedClient,
            "zyzzyva" => MatrixProtocol::ZyzzyvaClient {
                assume_byz: spec.task.assume_byz,
            },
            _ => panic!(),
        },
        replica_id: 0,
        host: spec.client[index].ip.to_string(),
        num_worker: 0,
        num_client: spec.task.num_client / spec.client.len() as u32,
    }
}

fn rewrite_sw(spec: Spec, simulate: bool) -> String {
    let mut dmac = Vec::new();
    let mut port = Vec::new();
    let mut replicas = Vec::new();
    let mut endpoints = Vec::new();
    for mut node in spec.replica {
        if node.link_speed.is_empty() {
            node.link_speed = String::from("100G");
        }
        dmac.push((node.link, node.dev_port));
        port.push((node.dev_port, node.link_speed));
        replicas.push(node.dev_port);
        endpoints.push(node.dev_port);
    }
    for mut node in spec.client {
        if node.link_speed.is_empty() {
            node.link_speed = String::from("100G");
        }
        dmac.push((node.link, node.dev_port));
        port.push((node.dev_port, node.link_speed));
        endpoints.push(node.dev_port);
    }
    const ENDPOINT_GROUP: u16 = 1;
    const REPLICA_GROUP: u16 = 2;
    const ENDPOINT_NODE: u16 = 1;
    const REPLICA_NODE: u16 = 2;
    let pre_node = [(ENDPOINT_NODE, endpoints), (REPLICA_NODE, replicas)]
        .into_iter()
        .map(|(group_id, ports)| (group_id, 0xffff, ports))
        .collect::<Vec<_>>();
    let pre_mgid = [
        (ENDPOINT_GROUP, vec![ENDPOINT_NODE]),
        (REPLICA_GROUP, vec![REPLICA_NODE]),
    ];

    let sw = include_str!("spec-sw.in.py");
    sw.replace(r#""@@PROGRAM@@""#, "bfrt.neo_s")
        .replace(r#""@@SIMULATE@@""#, if simulate { "True" } else { "False" })
        .replace(r#""@@MULTICAST_PORT@@""#, &MULTICAST_PORT.to_string())
        .replace(
            r#""@@MULTICAST_CONTROL_RESET_PORT@@""#,
            &MULTICAST_CONTROL_RESET_PORT.to_string(),
        )
        .replace(r#""@@DMAC@@""#, &format!("{dmac:?}"))
        .replace(r#""@@PORT@@""#, &format!("{port:?}"))
        .replace(r#""@@ENDPOINT_GROUP@@""#, &ENDPOINT_GROUP.to_string())
        .replace(r#""@@REPLICA_GROUP@@""#, &REPLICA_GROUP.to_string())
        .replace(r#""@@PRE_NODE@@""#, &format!("{pre_node:?}"))
        .replace(r#""@@PRE_MGID@@""#, &format!("{pre_mgid:?}"))
}
