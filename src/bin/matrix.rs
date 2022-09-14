use std::{
    env::args,
    fs::{remove_file, write},
    net::TcpListener,
    process::id,
    sync::{
        atomic::{AtomicU32, Ordering::SeqCst},
        Arc, Mutex,
    },
    time::Duration,
};

use bincode::Options;
use neoart::{
    bin::{MatrixArgs, MatrixProtocol},
    crypto::{CryptoMessage, Executor},
    latency::{
        merge_latency_into, push_latency, Latency,
        Point::{RequestBegin, RequestEnd},
    },
    meta::{OpNumber, ARGS_SERVER_PORT},
    neo,
    transport::{MulticastListener, Node, Run, Socket, Transport},
    unreplicated, zyzzyva, App, Client,
};
use nix::{
    sched::{sched_setaffinity, CpuSet},
    unistd::Pid,
};
use serde::de::DeserializeOwned;
use tokio::{
    net::UdpSocket, pin, runtime, select, signal::ctrl_c, spawn, sync::Notify, time::sleep,
};

// OVERENGINEERING... bypass command line arguments by setting up a server...
// i learned nothing but these bad practice from SDE :|
fn accept_args() -> MatrixArgs {
    let server = TcpListener::bind((
        args().nth(1).as_deref().unwrap_or("0.0.0.0"),
        ARGS_SERVER_PORT,
    ))
    .unwrap();
    let (stream, remote) = server.accept().unwrap();
    println!("* configured by {remote}");
    bincode::options().deserialize_from(&stream).unwrap()
}

fn main() {
    let mut args = accept_args();
    args.config.gen_keys();
    let pid_file = format!("pid.{}", args.instance_id);
    write(&pid_file, id().to_string()).unwrap();

    let latency = Arc::new(Mutex::new(Latency::default()));
    let mut executor = Executor::Inline;
    let runtime = match &args.protocol {
        MatrixProtocol::UnreplicatedClient
        | MatrixProtocol::ZyzzyvaClient { .. }
        | MatrixProtocol::NeoClient => {
            let counter = Arc::new(AtomicU32::new(0));
            runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(20) // because currently client server has isolation
                .on_thread_start({
                    let counter = counter.clone();
                    move || {
                        let mut cpu_set = CpuSet::new();
                        cpu_set.set(counter.fetch_add(1, SeqCst) as _).unwrap();
                        sched_setaffinity(Pid::from_raw(0), &cpu_set).unwrap();
                    }
                })
                .on_thread_stop(move || merge_latency_into(&mut latency.lock().unwrap()))
                .build()
                .unwrap()
        }
        _ => {
            if args.num_worker != 0 {
                executor = Executor::new_rayon(args.num_worker, latency);
            }
            let mut cpu_set = CpuSet::new();
            cpu_set.set(0).unwrap();
            sched_setaffinity(Pid::from_raw(0), &cpu_set).unwrap();
            runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        }
    };
    runtime.block_on(async move {
        match args.protocol {
            MatrixProtocol::UnreplicatedReplica => {
                run_replica(args, executor, |transport| {
                    unreplicated::Replica::new(transport, 0, Null)
                })
                .await
            }
            MatrixProtocol::UnreplicatedClient => run_client(args, unreplicated::Client::new).await,
            MatrixProtocol::ZyzzyvaReplica { enable_batching } => {
                let replica_id = args.replica_id;
                run_replica(args, executor, |transport| {
                    zyzzyva::Replica::new(transport, replica_id, Null, enable_batching)
                })
                .await
            }
            MatrixProtocol::ZyzzyvaClient { assume_byz } => {
                run_client(args, move |transport| {
                    zyzzyva::Client::new(transport, assume_byz)
                })
                .await
            }
            MatrixProtocol::NeoReplica {
                variant,
                enable_vote,
            } => {
                let socket = UdpSocket::bind(args.config.multicast).await.unwrap();
                let replica_id = args.replica_id;
                run_replica(args, executor, |mut transport| {
                    transport.listen_multicast(MulticastListener::Os(socket), variant);
                    neo::Replica::new(transport, replica_id, Null, enable_vote)
                })
                .await
            }
            MatrixProtocol::NeoClient => run_client(args, neo::Client::new).await,
            _ => unreachable!(),
        }
    });

    remove_file(&pid_file).unwrap();
}

struct Null;
impl App for Null {
    fn replica_upcall(&mut self, _: OpNumber, _: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

async fn run_replica<T>(
    args: MatrixArgs,
    executor: Executor,
    new_replica: impl FnOnce(Transport<T>) -> T,
) where
    T: Node + AsMut<Transport<T>> + Send,
    T::Message: CryptoMessage + DeserializeOwned,
{
    let socket = UdpSocket::bind(args.config.replicas[args.replica_id as usize])
        .await
        .unwrap();
    socket.set_broadcast(true).unwrap();
    socket.writable().await.unwrap();
    let transport = Transport::new(args.config, Socket::Os(socket), executor);
    new_replica(transport)
        .run(async { ctrl_c().await.unwrap() })
        .await;
}

async fn run_client<T>(
    args: MatrixArgs,
    new_client: impl FnOnce(Transport<T>) -> T + Clone + Send + 'static,
) where
    T: Node + Client + AsMut<Transport<T>> + Send,
    T::Message: CryptoMessage + DeserializeOwned,
{
    let notify = Arc::new(Notify::new());
    let throughput = Arc::new(AtomicU32::new(0));
    let clients: Vec<tokio::task::JoinHandle<()>> = (0..args.num_client)
        .map(|i| -> tokio::task::JoinHandle<()> {
            let config = args.config.clone();
            let notify = notify.clone();
            let throughput = throughput.clone();
            let new_client = new_client.clone();
            let host = args.host.clone();
            spawn(async move {
                let socket = UdpSocket::bind((host, 0)).await.unwrap();
                socket.set_broadcast(true).unwrap();
                socket.writable().await.unwrap();
                let transport = Transport::new(config, Socket::Os(socket), Executor::Inline);
                let mut client = new_client(transport);
                let notified = notify.notified();
                pin!(notified);

                let mut closed = false;
                while !closed {
                    push_latency(RequestBegin(i));
                    let result = client.invoke(&[]);
                    client
                        .run(async {
                            select! {
                                _ = result => {
                                    push_latency(RequestEnd(i));
                                    throughput.fetch_add(1, SeqCst);
                                }
                                _ = &mut notified => closed = true,
                            }
                        })
                        .await;
                }
            })
        })
        .collect();

    for _ in 0..20 {
        sleep(Duration::from_secs(1)).await;
        println!(
            "* interval throughput {} ops/sec",
            throughput.swap(0, SeqCst)
        );
    }

    notify.notify_waiters();
    for client in clients {
        client.await.unwrap();
    }
}
