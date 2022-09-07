use std::{
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicU32, Ordering::SeqCst},
        Arc, Mutex,
    },
    time::Duration,
};

use bincode::Options;
use neoart::{
    crypto::{CryptoMessage, Executor},
    latency::{
        merge_latency_into, push_latency, Latency,
        Point::{RequestBegin, RequestEnd},
    },
    meta::{OpNumber, ARGS_SERVER_PORT},
    transport::{Node, Run, Socket, Transport},
    unreplicated, zyzzyva, App, Args, Client, Mode,
};
use nix::{
    sched::{sched_setaffinity, CpuSet},
    unistd::Pid,
};
use serde::de::DeserializeOwned;
use tokio::{
    net::UdpSocket, pin, runtime, select, signal::ctrl_c, spawn, sync::Notify, time::sleep,
};

fn main() {
    let server = TcpListener::bind(("0.0.0.0", ARGS_SERVER_PORT)).unwrap();
    let (stream, remote) = server.accept().unwrap();
    println!("* configured by {remote}");
    let args = bincode::options()
        .deserialize_from::<_, Args>(stream)
        .unwrap();
    let latency = Arc::new(Mutex::new(Latency::default()));
    let runtime;
    let executor;
    match &args.mode {
        Mode::UnreplicatedClient | Mode::ZyzzyvaClient { .. } | Mode::NeoClient => {
            runtime = runtime::Builder::new_multi_thread()
                .enable_all()
                .on_thread_stop({
                    let latency = latency.clone();
                    move || merge_latency_into(&mut latency.lock().unwrap())
                })
                .build()
                .unwrap();
            executor = Executor::Inline;
        }
        _ => {
            runtime = runtime::Builder::new_current_thread().build().unwrap();
            if args.num_worker != 0 {
                executor = Executor::new_rayon(args.num_worker, latency);
            } else {
                executor = Executor::Inline;
            }
        }
    }
    runtime.block_on(async move {
        match args.mode {
            Mode::UnreplicatedReplica => {
                run_replica(args, executor, |transport| {
                    unreplicated::Replica::new(transport, 0, Null)
                })
                .await
            }
            Mode::UnreplicatedClient => run_client(args, unreplicated::Client::new).await,
            Mode::ZyzzyvaReplica { enable_batching } => {
                let replica_id = args.replica_id;
                run_replica(args, executor, |transport| {
                    zyzzyva::Replica::new(transport, replica_id, Null, enable_batching)
                })
                .await
            }
            _ => unreachable!(),
        }
    });
}

struct Null;
impl App for Null {
    fn replica_upcall(&mut self, _: OpNumber, _: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

async fn run_replica<T>(args: Args, executor: Executor, new_replica: impl FnOnce(Transport<T>) -> T)
where
    T: Node + AsMut<Transport<T>> + Send,
    T::Message: CryptoMessage + DeserializeOwned,
{
    let mut cpu_set = CpuSet::new();
    cpu_set.set(0).unwrap();
    sched_setaffinity(Pid::from_raw(0), &cpu_set).unwrap();

    let socket = UdpSocket::bind(args.config.replicas[args.replica_id as usize])
        .await
        .unwrap();
    socket.set_broadcast(true).unwrap();
    socket.writable().await.unwrap();

    let multicast = args.config.multicast;
    let mut transport = Transport::new(args.config, Socket::Os(socket), executor);
    if let Mode::NeoReplica { variant, .. } = args.mode {
        let socket = UdpSocket::bind(multicast).await.unwrap();
        transport.listen_multicast(Socket::Os(socket), variant);
    }

    let mut replica = new_replica(transport);
    replica.run(async { ctrl_c().await.unwrap() }).await;
}

async fn run_client<T>(
    args: Args,
    new_client: impl FnOnce(Transport<T>) -> T + Clone + Send + 'static,
) where
    T: Node + Client + AsMut<Transport<T>> + Send,
    T::Message: CryptoMessage + DeserializeOwned,
{
    let notify = Arc::new(Notify::new());
    let throughput = Arc::new(AtomicU32::new(0));
    let address = SocketAddr::from((args.host, 0));
    let clients: Vec<tokio::task::JoinHandle<()>> = (0..args.num_client)
        .map(|i| -> tokio::task::JoinHandle<()> {
            let config = args.config.clone();
            let notify = notify.clone();
            let throughput = throughput.clone();
            let new_client = new_client.clone();
            spawn(async move {
                let socket = UdpSocket::bind(address).await.unwrap();
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
