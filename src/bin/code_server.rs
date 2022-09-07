//! Long-living deamon process, working node side control plane.
//!
//! Code server has three functions:
//! * Update matrix executable
//! * (Re)start matrix executable as subprocess
//! * Capture and upload matrix excutable's output
use std::{process::Stdio, sync::Arc};

use bincode::Options;
use neoart::{meta::CODE_SERVER_PORT, CodeServerIn, CodeServerOut};
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::Command,
    select, spawn,
    sync::{mpsc, oneshot, Notify},
};

#[tokio::main]
async fn main() {
    let server = TcpListener::bind(("0.0.0.0", CODE_SERVER_PORT))
        .await
        .unwrap();
    let mut controller = None;
    let restart = Arc::new(Notify::new());
    let mut output = mpsc::channel(64);
    loop {
        if controller.is_none() {
            let (incoming, remote) = server.accept().await.unwrap();
            println!("* conntected to controller {remote}");
            controller = Some(incoming);
        }
        let stream = controller.as_mut().unwrap();
        let message_length;
        select! {
            length = stream.read_u32() => {
                if let Ok(length) = length {
                    message_length = length;
                } else {
                    controller = None;
                    continue;
                }
            }
            output = output.1.recv() => {
                write_message(stream, CodeServerOut::Output(output.unwrap())).await;
                continue;
            }
        }
        let mut message = vec![0; message_length as usize];
        // assert that a controller never fail in the middle of sending a message
        stream.read_exact(&mut message).await.unwrap();
        match bincode::options().deserialize(&message).unwrap() {
            CodeServerIn::Restart => {
                restart.notify_waiters();
                let ready = oneshot::channel();
                let output = output.0.clone();
                let shutdown = restart.clone();
                spawn(async move {
                    matrix_task(ready.0, shutdown, output).await;
                });
                ready.1.await.unwrap();
                write_message(stream, CodeServerOut::Ready).await;
            }
            CodeServerIn::Upgrade(exe) => fs::write("./neo-matrix", exe).await.unwrap(),
        }
    }
}

async fn write_message(stream: &mut TcpStream, message: CodeServerOut) {
    let message = bincode::options().serialize(&message).unwrap();
    // assert controller never fail at this point
    stream.write_u32(message.len() as _).await.unwrap();
    stream.write_all(&message).await.unwrap();
}

async fn matrix_task(
    ready: oneshot::Sender<()>,
    shutdown: Arc<Notify>,
    output: mpsc::Sender<String>,
) {
    let mut matrix = Command::new("./neo-matrix")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output_lines = BufReader::new(matrix.stdout.take().unwrap()).lines();
    ready.send(()).unwrap();
    loop {
        select! {
            _ = shutdown.notified() => {
                return;
            }
            line = output_lines.next_line() => {
                if let Some(line) = line.unwrap() {
                    output.send(line).await.unwrap();
                } else {
                    println!("* matrix exit status {:?}", matrix.wait().await);
                    return;
                }
            }
        }
    }
}
