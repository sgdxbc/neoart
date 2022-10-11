use std::{
    env::args,
    fs::write,
    iter::repeat_with,
    mem::take,
    net::TcpListener,
    process::id,
    sync::{
        atomic::{AtomicU32, Ordering::SeqCst},
        Arc,
    },
    time::{Duration, Instant},
};

use bincode::Options;
use neoart::{
    bin::{MatrixArgs, MatrixProtocol},
    crypto::{CryptoMessage, Executor},
    meta::{Config, OpNumber, ARGS_SERVER_PORT},
    neo, pbft,
    transport::{MulticastListener, Node, Run, Socket, Transport},
    unreplicated, zyzzyva, App, Client,
};
use nix::{
    sched::{sched_setaffinity, CpuSet},
    unistd::Pid,
};
use serde::de::DeserializeOwned;
use tokio::{
    net::UdpSocket,
    pin, runtime, select,
    signal::ctrl_c,
    spawn,
    sync::{Mutex, Notify},
    time::sleep,
};

// OVERENGINEERING... bypass command line arguments by setting up a server...
// i learned nothing but these bad practice from tofino SDE :|
fn accept_args() -> MatrixArgs {
    // using std instead of tokio because bincode not natively support async
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
    // using std instead of tokio because i don't want the whole main become
    // async only become of this
    write(&pid_file, id().to_string()).unwrap();

    let mut executor = Executor::Inline;
    let runtime = match &args.protocol {
        MatrixProtocol::UnreplicatedClient
        | MatrixProtocol::ZyzzyvaClient { .. }
        | MatrixProtocol::NeoClient => {
            runtime::Builder::new_multi_thread()
                .enable_all()
                // .worker_threads(20) // because currently client server has isolation
                .on_thread_start({
                    let counter = Arc::new(AtomicU32::new(0));
                    move || {
                        let mut cpu_set = CpuSet::new();
                        cpu_set.set(counter.fetch_add(1, SeqCst) as _).unwrap();
                        // sched_setaffinity(Pid::from_raw(0), &cpu_set).unwrap();
                    }
                })
                .build()
                .unwrap()
        }
        _ => {
            if args.num_worker != 0 {
                executor = Executor::new_rayon(args.num_worker);
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
            MatrixProtocol::UnreplicatedClient => {
                run_clients(args, unreplicated::Client::new).await
            }
            MatrixProtocol::ZyzzyvaReplica { enable_batching } => {
                let replica_id = args.replica_id;
                run_replica(args, executor, |transport| {
                    zyzzyva::Replica::new(transport, replica_id, Null, enable_batching)
                })
                .await
            }
            MatrixProtocol::ZyzzyvaClient { assume_byz } => {
                run_clients(args, move |transport| {
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
            MatrixProtocol::NeoClient => run_clients(args, neo::Client::new).await,
            MatrixProtocol::PbftReplica { enable_batching } => {
                let replica_id = args.replica_id;
                run_replica(args, executor, |transport| {
                    pbft::Replica::new(transport, replica_id, Null, enable_batching)
                })
                .await
            }
            MatrixProtocol::PbftClient => run_clients(args, pbft::Client::new).await,
            _ => unreachable!(),
        }
    });
}

struct Null;
impl App for Null {
    fn replica_upcall(&mut self, _: OpNumber, _: &[u8]) -> Vec<u8> {
        Vec::default()
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

async fn run_clients<T>(
    args: MatrixArgs,
    new_client: impl FnOnce(Transport<T>) -> T + Clone + Send + 'static,
) where
    T: Node + Client + AsMut<Transport<T>> + Send + 'static,
    T::Message: CryptoMessage + DeserializeOwned,
{
    if args.num_client == 0 {
        return;
    }
    let notify = Arc::new(Notify::new());
    let latencies = Arc::new(Mutex::new(Vec::new()));
    let clients = repeat_with(|| {
        let config = args.config.clone();
        let notify = notify.clone();
        let latencies = latencies.clone();
        let new_client = new_client.clone();
        let host = args.host.clone();
        spawn(run_client(config, notify, latencies, new_client, host))
    })
    .take(args.num_client as _)
    .collect::<Vec<_>>();

    let mut accumulated_latencies = Vec::new();
    for _ in 0..20 {
        sleep(Duration::from_secs(1)).await;
        let latencies = take(&mut *latencies.lock().await);
        println!("* interval throughput {} ops/sec", latencies.len());
        accumulated_latencies.extend(latencies);
    }
    notify.notify_waiters();
    for client in clients {
        client.await.unwrap();
    }

    accumulated_latencies.sort_unstable();
    if !accumulated_latencies.is_empty() {
        println!(
            "50th {:?} 99th {:?}",
            accumulated_latencies[accumulated_latencies.len() / 2],
            accumulated_latencies[accumulated_latencies.len() / 100 * 99]
        );
    }
}

async fn run_client<T>(
    config: Config,
    notify: Arc<Notify>,
    latencies: Arc<Mutex<Vec<Duration>>>,
    new_client: impl FnOnce(Transport<T>) -> T + Send + 'static,
    host: String,
) where
    T: Node + Client + AsMut<Transport<T>> + Send,
    T::Message: CryptoMessage + DeserializeOwned,
{
    let socket = UdpSocket::bind((host, 0)).await.unwrap();
    socket.set_broadcast(true).unwrap();
    socket.writable().await.unwrap();
    let transport = Transport::new(config, Socket::Os(socket), Executor::Inline);
    let mut client = new_client(transport);
    let notified = notify.notified();
    pin!(notified);

    let mut closed = false;
    while !closed {
        let instant = Instant::now();
        let result = client.invoke(&[]);
        client
            .run(async {
                select! {
                    _ = result => {
                        latencies.lock().await.push(Instant::now() - instant);
                    }
                    _ = &mut notified => closed = true,
                }
            })
            .await;
    }
}
