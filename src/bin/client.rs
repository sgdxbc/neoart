use std::{
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use neoart::{
    latency::{merge_latency_with, push_latency, Latency},
    meta::Config,
    transport::{Run, Socket, Transport},
    unreplicated, Client,
};
use tokio::{net::UdpSocket, pin, select, spawn, sync::Notify, time::sleep};

struct RequestBegin;
struct RequestEnd;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let config: Config = "
        f 0
        replica 127.0.0.1:2023
    "
    .parse()
    .unwrap();

    let notify = Arc::new(Notify::new());
    let throughput = Arc::new(AtomicU32::new(0));
    let clients = (0..10)
        .map(|i| {
            let config = config.clone();
            let notify = notify.clone();
            let throughput = throughput.clone();
            spawn(async move {
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                socket.writable().await.unwrap();
                let transport = Transport::new(config, Socket::Os(socket));
                let mut client = unreplicated::Client::new(transport);
                let notified = notify.notified();
                pin!(notified);

                let mut closed = false;
                while !closed {
                    push_latency::<RequestBegin>(i);
                    let result = client.invoke(&[]);
                    client
                        .run(async {
                            select! {
                                _ = result => {
                                    push_latency::<RequestEnd>(i);
                                    throughput.fetch_add(1, Ordering::SeqCst);
                                }
                                _ = &mut notified => closed = true,
                            }
                        })
                        .await;
                }
            })
        })
        .collect::<Vec<_>>();

    for _ in 0..10 {
        sleep(Duration::from_secs(1)).await;
        println!(
            "* interval throughput {} ops/sec",
            throughput.swap(0, Ordering::SeqCst)
        );
    }

    notify.notify_waiters();
    for client in clients {
        client.await.unwrap();
    }

    let mut aggregated = Latency::default();
    merge_latency_with(&mut aggregated);
    let intervals = aggregated.intervals::<RequestBegin, RequestEnd>();
    println!(
        "* average latency: {:?}",
        intervals.iter().sum::<Duration>() / intervals.len() as u32
    );
}
