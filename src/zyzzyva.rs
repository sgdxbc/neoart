use std::{
    collections::{HashMap, HashSet},
    future::Future,
    mem::take,
    net::SocketAddr,
    pin::Pin,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::{
    common::Reorder,
    crypto::{verify_message, CryptoMessage, Signature},
    meta::{
        deserialize, digest, ClientId, Config, Digest, OpNumber, ReplicaId, RequestNumber,
        ViewNumber,
    },
    transport::{
        Destination::{To, ToAll, ToReplica},
        InboundAction, Receiver, Transport,
    },
    App,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Request(Request),
    OrderReq(OrderReq, Vec<Request>),
    SpecResponse(SpecResponse, ReplicaId, Vec<u8>, OrderReq),
    Commit(Commit),
    LocalCommit(LocalCommit),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    client_id: ClientId,
    request_number: RequestNumber,
    op: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OrderReq {
    view_number: ViewNumber,
    op_number: OpNumber,
    history_digest: Digest,
    message_digest: Digest,
    // nondeterministic: (),
    signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SpecResponse {
    view_number: ViewNumber,
    op_number: OpNumber,
    history_digest: Digest,
    result_digest: Digest,
    client_id: ClientId,
    request_number: RequestNumber,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    client_id: ClientId,
    certificate: CommitCertificate,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CommitCertificate {
    spec_response: SpecResponse, // signature cleared
    signatures: Vec<(ReplicaId, Signature)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCommit {
    view_number: ViewNumber,
    message_digest: Digest,
    history_digest: Digest,
    replica_id: ReplicaId,
    client_id: ClientId,
    signature: Signature,
}

impl CryptoMessage for Message {
    fn signature_mut(&mut self) -> &mut Signature {
        match self {
            Self::OrderReq(OrderReq { signature, .. }, _)
            | Self::SpecResponse(SpecResponse { signature, .. }, ..)
            | Self::LocalCommit(LocalCommit { signature, .. }) => signature,
            _ => unreachable!(),
        }
    }

    fn digest(&self) -> Digest {
        match self {
            Self::OrderReq(message, _) => digest(message),
            Self::SpecResponse(message, ..) => digest(message),
            _ => digest(self),
        }
    }
}

// for calling `verify_message` below
impl CryptoMessage for SpecResponse {
    fn signature_mut(&mut self) -> &mut Signature {
        &mut self.signature
    }
}

impl Message {
    fn verify_commit(&mut self, config: &Config) -> bool {
        let certificate = if let Self::Commit(message) = self {
            &message.certificate
        } else {
            unreachable!()
        };
        if certificate.signatures.len() < config.f * 2 + 1 {
            return false;
        }
        for &(replica_id, signature) in &certificate.signatures {
            let mut spec_response = SpecResponse {
                signature,
                ..certificate.spec_response
            };
            if !verify_message(
                &mut spec_response,
                &config.keys[replica_id as usize].public_key(),
            ) {
                return false;
            }
        }
        true
    }
}

pub struct Client {
    transport: Transport<Self>,
    id: ClientId,
    request_number: RequestNumber,
    invoke: Option<Invoke>,
    view_number: ViewNumber,
    assume_byz: bool,
}

struct Invoke {
    request: Request,
    certificate: CommitCertificate,
    result: Vec<u8>,
    local_committed: HashSet<ReplicaId>,
    continuation: oneshot::Sender<Vec<u8>>,
    timer_id: u32,
}

impl Client {
    pub fn new(transport: Transport<Self>, assume_byz: bool) -> Self {
        Self {
            id: transport.create_id(),
            transport,
            request_number: 0,
            invoke: None,
            view_number: 0,
            assume_byz,
        }
    }
}

impl AsMut<Transport<Self>> for Client {
    fn as_mut(&mut self) -> &mut Transport<Self> {
        &mut self.transport
    }
}

impl crate::Client for Client {
    fn invoke(&mut self, op: &[u8]) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>> {
        assert!(self.invoke.is_none());
        self.request_number += 1;
        let request = Request {
            client_id: self.id,
            request_number: self.request_number,
            op: op.to_vec(),
        };
        let (continuation, result) = oneshot::channel();
        self.invoke = Some(Invoke {
            request,
            timer_id: 0,
            continuation,
            certificate: CommitCertificate::default(),
            local_committed: HashSet::new(),
            result: Vec::new(),
        });
        self.send_request();
        Box::pin(async { result.await.unwrap() })
    }
}

impl Receiver for Client {
    type Message = Message;

    fn receive_message(&mut self, remote: SocketAddr, message: Self::Message) {
        match message {
            Message::SpecResponse(message, replica_id, result, _) => {
                self.handle_spec_response(remote, message, replica_id, result)
            }
            Message::LocalCommit(message) => self.handle_local_commit(remote, message),
            _ => unreachable!(),
        }
    }
}

impl Client {
    fn handle_spec_response(
        &mut self,
        _remote: SocketAddr,
        mut message: SpecResponse,
        replica_id: ReplicaId,
        result: Vec<u8>,
    ) {
        if message.client_id != self.id || message.request_number != self.request_number {
            return;
        }
        let invoke = if let Some(invoke) = self.invoke.as_mut() {
            invoke
        } else {
            return;
        };

        let signature = take(&mut message.signature);
        if invoke.certificate.signatures.is_empty() {
            invoke.certificate.spec_response = message;
            invoke.result = result;
        } else if message != invoke.certificate.spec_response || result != invoke.result {
            println!(
                "! client {} mismatched result request {} replica {}",
                self.id, message.request_number, replica_id
            );
            return;
        }
        if invoke
            .certificate
            .signatures
            .iter()
            .all(|&(id, _)| replica_id != id)
        {
            invoke.certificate.signatures.push((replica_id, signature));
        }

        if self.assume_byz && invoke.certificate.signatures.len() == self.transport.config.f * 2 + 1
        {
            self.transport.cancel_timer(invoke.timer_id);
            self.send_request();
        } else if invoke.certificate.signatures.len() == self.transport.config.n {
            let invoke = self.invoke.take().unwrap();
            self.transport.cancel_timer(invoke.timer_id);
            self.view_number = invoke.certificate.spec_response.view_number;
            invoke.continuation.send(invoke.result).unwrap();
        }
    }

    fn handle_local_commit(&mut self, _remote: SocketAddr, message: LocalCommit) {
        if message.client_id != self.id {
            return;
        }
        let invoke = if let Some(invoke) = self.invoke.as_mut() {
            invoke
        } else {
            return;
        };

        invoke.local_committed.insert(message.replica_id);
        if invoke.local_committed.len() == self.transport.config.f * 2 + 1 {
            let invoke = self.invoke.take().unwrap();
            self.transport.cancel_timer(invoke.timer_id);
            self.view_number = message.view_number; // any possible to go backward?
            invoke.continuation.send(invoke.result).unwrap();
        }
    }

    fn send_request(&mut self) {
        let invoke = self.invoke.as_mut().unwrap();
        if invoke.certificate.signatures.len() < self.transport.config.f * 2 + 1 {
            // timer not set already => this is not a resending
            let destination = if invoke.timer_id == 0 {
                ToReplica(self.transport.config.primary(self.view_number))
            } else {
                ToAll
            };
            self.transport
                .send_message(destination, Message::Request(invoke.request.clone()));
        } else {
            let commit = Commit {
                client_id: self.id,
                certificate: CommitCertificate {
                    spec_response: invoke.certificate.spec_response.clone(),
                    signatures: invoke.certificate.signatures[..self.transport.config.f * 2 + 1]
                        .to_vec(),
                },
            };
            self.transport.send_message(ToAll, Message::Commit(commit));
        }

        let request_number = self.request_number;
        let on_resend = move |receiver: &mut Self| {
            assert_eq!(
                receiver.invoke.as_ref().unwrap().request.request_number,
                request_number
            );
            if request_number != 1 {
                println!("! client {} resend request {}", receiver.id, request_number);
            }
            receiver.send_request();
        };
        invoke.timer_id = self
            .transport
            .create_timer(Duration::from_secs(1), on_resend);
    }
}

pub struct Replica {
    transport: Transport<Self>,
    id: ReplicaId,
    view_number: ViewNumber,
    // the #op that should be speculative committed up to, and the corresponded
    // history hash
    // on primary replica the log record could be a little bit delayed to these
    // because of signing `OrderReq`
    op_number: OpNumber,
    history_digest: Digest,

    app: Box<dyn App + Send>,
    client_table: HashMap<ClientId, (RequestNumber, Option<Message>)>, // always Message::SpecResponse
    log: Vec<LogEntry>,
    commit_certificate: CommitCertificate, // highest
    reorder_order_req: Reorder<(OrderReq, Vec<Request>)>,
    batch_size: usize,
    batch: Vec<Request>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogEntry {
    view_number: ViewNumber,
    requests: Vec<Request>,
    // spec_response: SignedMessage,
    message_digest: Digest,
    history_digest: Digest,
}

impl Replica {
    const BATCH_SIZE: usize = 10; // is there a way to do adaptive batching?

    pub fn new(
        transport: Transport<Self>,
        id: ReplicaId,
        app: impl App + Send + 'static,
        enable_batching: bool,
    ) -> Self {
        Self {
            transport,
            id,
            view_number: 0,
            op_number: 0,
            history_digest: Digest::default(),
            app: Box::new(app),
            client_table: HashMap::new(),
            log: Vec::new(),
            reorder_order_req: Reorder::new(1),
            commit_certificate: CommitCertificate::default(),
            batch_size: if enable_batching { Self::BATCH_SIZE } else { 1 },
            batch: Vec::new(),
        }
    }
}

impl AsMut<Transport<Self>> for Replica {
    fn as_mut(&mut self) -> &mut Transport<Self> {
        &mut self.transport
    }
}

impl Receiver for Replica {
    type Message = Message;

    fn inbound_action(&self, buf: &[u8]) -> InboundAction<Self::Message> {
        let message = deserialize(buf);
        match message {
            Message::Request(_) => InboundAction::Allow(message),
            Message::OrderReq(OrderReq { view_number, .. }, _) => {
                InboundAction::VerifyReplica(message, self.transport.config.primary(view_number))
            }
            // reduce duplicated verification?
            Message::Commit(_) => InboundAction::Verify(message, Message::verify_commit),
            _ => {
                println!("! [{}] unexpected {message:?}", self.id);
                InboundAction::Block
            }
        }
    }

    fn receive_message(&mut self, remote: SocketAddr, message: Self::Message) {
        match message {
            Message::Request(message) => self.handle_request(remote, message),
            Message::OrderReq(message, request) => self.handle_order_req(remote, message, request),
            Message::Commit(message) => self.handle_commit(remote, message),
            _ => unreachable!(),
        }
    }

    fn on_signed(&mut self, message: Message) {
        if matches!(message, Message::OrderReq(..)) {
            self.transport.send_message(ToAll, &message);
        }

        if let Message::OrderReq(message, request) = message {
            // assert_eq!(self.id, self.transport.config.primary(self.view_number));

            let mut ordered = self
                .reorder_order_req
                .insert_reorder(message.op_number, (message.clone(), request.clone()));
            while let Some((message, request)) = ordered {
                // TODO guard view number
                self.spec_commit(message, request);
                ordered = self.reorder_order_req.expect_next();
            }
        }
    }
}

impl Replica {
    fn handle_request(&mut self, remote: SocketAddr, message: Request) {
        if let Some((request_number, spec_response)) = self.client_table.get(&message.client_id) {
            if message.request_number < *request_number {
                return;
            }
            if message.request_number == *request_number {
                if let Some(spec_response) = spec_response {
                    self.transport
                        .send_signed_message(To(remote), spec_response.clone(), self.id);
                }
                return;
            }
        }

        if self.transport.config.primary(self.view_number) != self.id {
            todo!()
        }

        self.client_table
            .insert(message.client_id, (message.request_number, None));
        self.batch.push(message);
        if self.batch.len() < self.batch_size {
            return;
        }

        self.op_number += 1;
        let batch = take(&mut self.batch);
        let message_digest = digest(&batch);
        self.history_digest = digest([self.history_digest, message_digest]);
        self.transport.sign_message(
            self.id,
            Message::OrderReq(
                OrderReq {
                    view_number: self.view_number,
                    op_number: self.op_number,
                    message_digest,
                    history_digest: self.history_digest,
                    signature: Signature::default(),
                },
                batch,
            ),
        );

        // broadcast & locally speculative commit in `Receiver::on_signed`
    }

    fn handle_order_req(&mut self, _remote: SocketAddr, message: OrderReq, request: Vec<Request>) {
        if message.message_digest != digest(&request) {
            println!(
                "! OrderReq incorrect message digest op {}",
                message.op_number
            );
            return;
        }
        if message.view_number < self.view_number {
            return;
        }
        if message.view_number > self.view_number {
            todo!()
        }
        assert_ne!(self.id, self.transport.config.primary(self.view_number));

        let mut ordered = self
            .reorder_order_req
            .insert_reorder(message.op_number, (message, request));
        while let Some((message, request)) = ordered {
            let previous_digest = if self.op_number == 0 {
                Digest::default()
            } else {
                self.log[(self.op_number - 1) as usize].history_digest
            };
            if message.history_digest != digest([previous_digest, message.message_digest]) {
                println!(
                    "! OrderReq mismatched history digest op {}",
                    message.op_number
                );
                break;
            }

            self.op_number += 1;
            self.history_digest = message.history_digest;
            self.spec_commit(message, request);

            ordered = self.reorder_order_req.expect_next();
        }
    }

    fn spec_commit(&mut self, message: OrderReq, batch: Vec<Request>) {
        assert_eq!(message.view_number, self.view_number);

        for request in &batch {
            let result = self.app.replica_upcall(message.op_number, &request.op);
            let spec_response = Message::SpecResponse(
                SpecResponse {
                    view_number: self.view_number,
                    op_number: message.op_number,
                    result_digest: digest(&result),
                    history_digest: message.history_digest,
                    client_id: request.client_id,
                    request_number: request.request_number,
                    signature: Signature::default(),
                },
                self.id,
                result,
                message.clone(),
            );
            let client_id = request.client_id;
            let request_number = request.request_number;
            // is this SpecResponse always up to date?
            self.client_table
                .insert(client_id, (request_number, Some(spec_response.clone())));
            self.transport
                .send_signed_message(To(client_id.0), spec_response, self.id);
        }

        self.log.push(LogEntry {
            view_number: self.view_number,
            requests: batch,
            // spec_response,
            message_digest: message.message_digest,
            history_digest: message.history_digest,
        });
    }

    fn handle_commit(&mut self, remote: SocketAddr, message: Commit) {
        let spec_response = &message.certificate.spec_response;
        if self.view_number > spec_response.view_number {
            return;
        }
        if self.view_number < spec_response.view_number {
            todo!()
        }

        let entry = if let Some(entry) = self.log.get_mut((spec_response.op_number - 1) as usize) {
            entry
        } else {
            todo!()
        };
        if spec_response.history_digest != entry.history_digest {
            todo!()
        }

        if spec_response.op_number > self.commit_certificate.spec_response.op_number {
            self.commit_certificate = message.certificate;
        }
        let local_commit = Message::LocalCommit(LocalCommit {
            view_number: self.view_number,
            message_digest: entry.message_digest,
            history_digest: entry.history_digest,
            replica_id: self.id,
            client_id: message.client_id,
            signature: Signature::default(),
        });
        self.transport
            .send_signed_message(To(remote), local_commit, self.id);
    }
}

#[cfg(test)]
mod tests {
    use std::{str::from_utf8, time::Duration};

    use tokio::{
        spawn,
        task::JoinHandle,
        time::{sleep, timeout},
    };

    use crate::{
        common::TestApp,
        crypto::ExecutorSetting,
        meta::ReplicaId,
        transport::{Concurrent, Run, SimulatedNetwork, Transport},
        zyzzyva::{Client, Replica},
        Client as _,
    };

    struct System {
        net: Concurrent<SimulatedNetwork>,
        replicas: Vec<Concurrent<Replica>>,
        clients: Vec<Client>,
    }

    impl System {
        fn new(num_client: usize, assume_byz: bool, enable_batching: bool) -> Self {
            let config = SimulatedNetwork::config(4, 1);
            let mut net = SimulatedNetwork::default();
            let clients = (0..num_client)
                .map(|i| {
                    Client::new(
                        Transport::new(
                            config.clone(),
                            net.insert_socket(SimulatedNetwork::client(i)),
                            ExecutorSetting::Inline,
                        ),
                        assume_byz,
                    )
                })
                .collect::<Vec<_>>();
            let replicas = (0..4)
                .map(|i| {
                    let replica = Replica::new(
                        Transport::new(
                            config.clone(),
                            net.insert_socket(config.replicas[i]),
                            ExecutorSetting::Inline,
                        ),
                        i as ReplicaId,
                        TestApp::default(),
                        enable_batching,
                    );
                    Concurrent::run(replica)
                })
                .collect::<Vec<_>>();

            Self {
                net: Concurrent::run(net),
                replicas,
                clients,
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn single_op() {
        let mut system = System::new(1, false, false);
        let result = system.clients[0].invoke("hello".as_bytes());
        timeout(
            Duration::from_millis(30),
            system.clients[0].run(async {
                assert_eq!(&result.await, "[1] hello".as_bytes());
            }),
        )
        .await
        .unwrap();

        for replica in system.replicas {
            assert_eq!(replica.join().await.log.len(), 1);
        }
        system.net.join().await;
    }

    fn closed_loop(index: usize, mut client: Client) -> JoinHandle<()> {
        spawn(async move {
            for i in 0.. {
                let result = client.invoke(format!("op{index}-{i}").as_bytes());
                client
                    .run(async move {
                        let result = result.await;
                        assert!(
                            result
                                .strip_suffix(format!("op{index}-{i}").as_bytes())
                                .is_some(),
                            "expect op{index}-{i} get {}",
                            from_utf8(&result).unwrap()
                        );
                    })
                    .await;
            }
        })
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_closed_loop() {
        let num_client = 10;
        let mut system = System::new(num_client, false, false);
        for (index, client) in system.clients.into_iter().enumerate() {
            closed_loop(index, client);
        }
        sleep(Duration::from_secs(1)).await;
        let primary_len = system.replicas.remove(0).join().await.log.len();
        assert!(primary_len >= 1000 / 30 * num_client);
        for replica in system.replicas {
            let backup_len = replica.join().await.log.len();
            // stronger assertions?
            assert!(backup_len <= primary_len);
            assert!(backup_len >= primary_len - num_client);
        }
        system.net.join().await;
    }

    #[tokio::test(start_paused = true)]
    async fn single_op_byzantine() {
        let mut system = System::new(1, true, false);
        system.replicas.remove(3).join().await;
        let result = system.clients[0].invoke("hello".as_bytes());
        timeout(
            Duration::from_millis(50),
            system.clients[0].run(async {
                assert_eq!(&result.await, "[1] hello".as_bytes());
            }),
        )
        .await
        .unwrap();

        for replica in system.replicas {
            assert_eq!(replica.join().await.log.len(), 1);
        }
        system.net.join().await;
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_closed_loop_byzantine() {
        let num_client = 10;
        let mut system = System::new(num_client, true, false);
        system.replicas.remove(3).join().await;
        for (index, client) in system.clients.into_iter().enumerate() {
            closed_loop(index, client);
        }
        sleep(Duration::from_secs(1)).await;
        let primary_len = system.replicas.remove(0).join().await.log.len();
        assert!(primary_len >= 1000 / 50 * num_client);
        for replica in system.replicas {
            let backup_len = replica.join().await.log.len();
            // stronger assertions?
            assert!(backup_len <= primary_len);
            assert!(backup_len >= primary_len - num_client);
        }
        system.net.join().await;
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_closed_loop_batching() {
        let num_client = Replica::BATCH_SIZE * 4;
        let mut system = System::new(num_client, false, true);
        for (index, client) in system.clients.into_iter().enumerate() {
            closed_loop(index, client);
        }
        sleep(Duration::from_secs(1)).await;
        let primary_len = system.replicas.remove(0).join().await.log.len();
        assert!(primary_len >= 1000 / 30 * (num_client / Replica::BATCH_SIZE));
        for replica in system.replicas {
            let backup_len = replica.join().await.log.len();
            // stronger assertions?
            assert!(backup_len <= primary_len);
            assert!(backup_len >= primary_len - num_client);
        }
        system.net.join().await;
    }
}
