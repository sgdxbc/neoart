use neoart::{
    meta::Config,
    transport::{Run, Transport},
    unreplicated, Client,
};
use tokio::{net::UdpSocket, spawn};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let config: Config = "
        f 0
        replica 127.0.0.1:2023
    "
    .parse()
    .unwrap();

    let mut clients = vec![];
    for _ in 0..10 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.writable().await.unwrap();
        let transport = Transport::new(config.clone(), socket);
        let mut client = unreplicated::Client::new(transport);
        let result = client.invoke(&[]);
        clients.push(spawn(async move {
            client
                .run(async {
                    result.await;
                })
                .await
        }));
    }
    for client in clients {
        client.await.unwrap();
    }
}
