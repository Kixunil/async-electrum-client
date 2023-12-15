use bitcoin::blockdata::constants::ChainHash;
use slog::{o, error, debug, trace};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot::Sender as OneShotSender;

#[derive(serde::Serialize)]
struct Request<P> {
    #[serde(rename = "jsonrpc")]
    version: &'static str,
    method: &'static str,
    params: P,
    id: u64,
}

#[derive(serde::Deserialize)]
struct NotificationResponse {
    #[serde(rename = "jsonrpc")]
    #[allow(dead_code)]
    version: JsonRpc2,
    #[serde(flatten)]
    method: NotificationMethod,
}

#[derive(serde::Deserialize)]
struct ResultResponse<Res> {
    #[serde(rename = "jsonrpc")]
    #[allow(dead_code)]
    version: JsonRpc2,
    result: Res,
    id: u64,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum Response {
    Notification(NotificationResponse),
    Success(ResultResponse<serde_json::Value>),
    Error(ErrorResponse),
}

#[derive(serde::Deserialize)]
struct ErrorResponse {
    #[serde(rename = "jsonrpc")]
    #[allow(dead_code)]
    version: JsonRpc2,
    error: ServerError,
    id: u64,
}

#[derive(serde::Deserialize)]
#[derive(Debug)]
struct ServerError {
    code: i64,
    message: String,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "server returned an error with code {}: {}", self.code, self.message)
    }
}

impl std::error::Error for ServerError {}

#[derive(serde::Deserialize)]
struct FeaturesResponse {
    #[serde(deserialize_with = "chain_hash_from_block_hash")]
    genesis_hash: ChainHash,
}

fn chain_hash_from_block_hash<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<ChainHash, D::Error> {
    use serde::Deserialize;
    use bitcoin::hashes::Hash;

    let block_hash = bitcoin::BlockHash::deserialize(deserializer)?;
    Ok(ChainHash::from(block_hash.to_byte_array()))
}

#[derive(serde::Deserialize)]
#[serde(tag = "method", content = "params")]
enum NotificationMethod {
    #[serde(rename = "blockchain.scripthash.subscribe")]
    ScriptHashNotification(ScriptHashNotification),
    #[serde(rename = "blockchain.headers.subscribe")]
    HeaderNotification(HeaderNotification),
}

#[derive(serde::Deserialize)]
pub struct HeaderNotification {
    header: Header,
}

#[derive(serde::Deserialize)]
pub struct Header {
    #[serde(rename = "hex")]
    #[serde(with = "bitcoin::consensus::serde::With::<bitcoin::consensus::serde::Hex<bitcoin::consensus::serde::hex::Lower>>")]
    pub header: bitcoin::block::Header,
    pub height: u64,
}

#[derive(serde_tuple::Serialize_tuple)]
struct ScriptHashSubscribe {
    scripthash: ScriptHash,
}

#[derive(serde::Deserialize)]
struct UnspentResponse {
    height: u64,
    #[serde(rename = "tx_hash")]
    txid: bitcoin::Txid,
    #[serde(rename = "tx_pos")]
    index: u32,
    #[serde(with = "bitcoin::amount::serde::as_sat")]
    value: bitcoin::Amount,
}

#[derive(serde::Deserialize)]
#[serde(transparent)]
struct TransactionResponse(
    #[serde(with = "bitcoin::consensus::serde::With::<bitcoin::consensus::serde::Hex<bitcoin::consensus::serde::hex::Lower>>")]
    bitcoin::Transaction
);

#[derive(serde::Deserialize)]
struct TransactionConfirmationsResponse {
    confirmations: u64,
}

struct JsonRpc2;

impl<'de> serde::Deserialize<'de> for JsonRpc2 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'a> serde::de::Visitor<'a> for Visitor {
            type Value = JsonRpc2;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "JSONRPC version 2")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                if s == "2.0" {
                    Ok(JsonRpc2)
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Str(s), &"version 2"))
                }
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

bitcoin::hashes::hash_newtype! {
    /// Hash of the script pubkey
    #[hash_newtype(backward)]
    pub struct ScriptHash(bitcoin::hashes::sha256::Hash);

    struct Status(bitcoin::hashes::sha256::Hash);
}

impl ScriptHash {
    pub fn new(script_pubkey: &bitcoin::Script) -> Self {
        use bitcoin::hashes::Hash;

        ScriptHash(bitcoin::hashes::sha256::Hash::hash(script_pubkey.as_bytes()))
    }
}

#[derive(serde::Deserialize)]
struct ScriptHashNotification {
    scripthash: ScriptHash,
    status: Option<Status>,
}

#[derive(serde_tuple::Serialize_tuple)]
struct ScriptHashListUnspent {
    scripthash: ScriptHash,
}

enum Command {
    ScriptHashSubscribe(ScriptHashSubscribe, OneShotSender<Result<(), Error>>),
    ScriptHashListUnspent(ScriptHashListUnspent, OneShotSender<Result<Vec<UnspentResponse>, Error>>),
    GetTransaction(GetTransaction, OneShotSender<Result<TransactionResponse, Error>>),
    GetTransactionConfirmations(GetTransaction, OneShotSender<Result<TransactionConfirmationsResponse, Error>>),
    BroadcastTransaction(BroadcastTransaction, OneShotSender<Result<bitcoin::Txid, Error>>),
    GetFeeHistogram([u8; 0], OneShotSender<Result<Vec<FeeItem>, Error>>),
    EstimateFeeRate(EstimateFeeRate, OneShotSender<Result<f64, Error>>),
}

enum CommandResultSender {
    ScriptHashSubscribe(OneShotSender<Result<(), Error>>),
    ScriptHashListUnspent(OneShotSender<Result<Vec<UnspentResponse>, Error>>),
    GetTransaction(OneShotSender<Result<TransactionResponse, Error>>),
    GetTransactionConfirmations(OneShotSender<Result<TransactionConfirmationsResponse, Error>>),
    BroadcastTransaction(OneShotSender<Result<bitcoin::Txid, Error>>),
    GetFeeHistogram(OneShotSender<Result<Vec<FeeItem>, Error>>),
    EstimateFeeRate(OneShotSender<Result<f64, Error>>),
}

#[derive(serde_tuple::Serialize_tuple)]
struct GetTransaction {
    #[serde(rename = "tx_hash")]
    txid: bitcoin::Txid,
    verbose: bool,
}

#[derive(serde_tuple::Serialize_tuple)]
struct BroadcastTransaction {
    #[serde(rename = "raw_tx")]
    #[serde(with = "bitcoin::consensus::serde::With::<bitcoin::consensus::serde::Hex<bitcoin::consensus::serde::hex::Lower>>")]
    transaction: bitcoin::Transaction,
}

#[derive(serde_tuple::Serialize_tuple)]
struct EstimateFeeRate {
    target: u32,
}

#[derive(serde::Deserialize)]
pub struct FeeItem {
    pub fee_rate: u64,
    pub vsize: u64,
}

pub type Error = std::sync::Arc<dyn std::error::Error + Sync + Send>;

#[derive(Clone)]
pub struct Client {
    sender: tokio::sync::mpsc::Sender<Command>,
    network: bitcoin::Network,
}

impl Client {
    pub fn network(&self) -> bitcoin::Network {
        self.network
    }

    pub async fn subscribe(&self, scripthash: ScriptHash) -> Result<(), Error> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.sender.send(Command::ScriptHashSubscribe(ScriptHashSubscribe { scripthash }, sender)).await
            .map_err(|_| into_dyn_err(ChannelClosed))?;
        receiver.await.map_err(into_dyn_err).and_then(std::convert::identity)
    }

    pub async fn list_unspent(&self, scripthash: ScriptHash) -> Result<Vec<Unspent>, Error> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.sender.send(Command::ScriptHashListUnspent(ScriptHashListUnspent { scripthash }, sender)).await
            .map_err(|_| into_dyn_err(ChannelClosed))?;
        let response = receiver.await.map_err(into_dyn_err).and_then(std::convert::identity)?;
        let list = response.into_iter().map(|unspent| {
            Unspent {
                height: unspent.height,
                value: unspent.value,
                out_point: bitcoin::OutPoint {
                    txid: unspent.txid,
                    vout: unspent.index,
                }
            }
        })
        .collect();
        Ok(list)
    }

    pub async fn get_transaction(&self, txid: bitcoin::Txid) -> Result<bitcoin::Transaction, Error> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.sender.send(Command::GetTransaction(GetTransaction { txid, verbose: false }, sender)).await
            .map_err(|_| into_dyn_err(ChannelClosed))?;
        let response = receiver.await.map_err(into_dyn_err).and_then(std::convert::identity)?;
        Ok(response.0)
    }

    pub async fn get_transaction_confirmations(&self, txid: bitcoin::Txid) -> Result<u64, Error> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.sender.send(Command::GetTransactionConfirmations(GetTransaction { txid, verbose: true }, sender)).await
            .map_err(|_| into_dyn_err(ChannelClosed))?;
        let response = receiver.await.map_err(into_dyn_err).and_then(std::convert::identity)?;
        Ok(response.confirmations)
    }

    pub async fn broadcast_transaction(&self, transaction: bitcoin::Transaction) -> Result<(), Error> {
        let expected_txid = transaction.txid();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.sender.send(Command::BroadcastTransaction(BroadcastTransaction { transaction }, sender)).await
            .map_err(|_| into_dyn_err(ChannelClosed))?;
        let response = receiver.await.map_err(into_dyn_err).and_then(std::convert::identity)?;
        if response == expected_txid {
            Ok(())
        } else {
            Err(into_dyn_err(TxidMismatch { expected: expected_txid, got: response }))
        }
    }

    pub async fn get_fee_histogram(&self) -> Result<Vec<FeeItem>, Error> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.sender.send(Command::GetFeeHistogram([], sender)).await
            .map_err(|_| into_dyn_err(ChannelClosed))?;
        receiver.await.map_err(into_dyn_err).and_then(std::convert::identity)
    }

    pub async fn estimate_fee_rate(&self, target: u32) -> Result<bitcoin::FeeRate, Error> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.sender.send(Command::EstimateFeeRate(EstimateFeeRate { target }, sender)).await
            .map_err(|_| into_dyn_err(ChannelClosed))?;
        let fee_rate_btc_kb = receiver.await.map_err(into_dyn_err).and_then(std::convert::identity)?;
        let fee_rate_sat_kwu = fee_rate_btc_kb * (100_000_000.0 / 4.0);
        Ok(bitcoin::FeeRate::from_sat_per_kwu(fee_rate_sat_kwu as u64))
    }
}

#[derive(Debug)]
struct TxidMismatch {
    expected: bitcoin::Txid,
    got: bitcoin::Txid,
}

impl fmt::Display for TxidMismatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unexpected transaction id {}, expected {}", self.got, self.expected)
    }
}

impl std::error::Error for TxidMismatch {}

pub struct Unspent {
    pub height: u64,
    pub out_point: bitcoin::OutPoint,
    pub value: bitcoin::Amount,
}

#[derive(Debug)]
struct ChannelClosed;

impl fmt::Display for ChannelClosed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "channel closed")
    }
}

impl std::error::Error for ChannelClosed {}

pub enum Notification {
    ScriptHash(ScriptHash),
    Header(Header),
    Failure(Error),
}

pub async fn connect(address: SocketAddr, notifications: tokio::sync::mpsc::Sender<Notification>, logger: &slog::Logger) -> Result<(Client, impl std::future::Future<Output=()> + Send + Sync + 'static), Error> {
    use futures::future::Either;
    use futures::stream::StreamExt;
    let logger = logger.new(o!("electrum_address" => address));

    let connection = tokio::net::TcpStream::connect(address).await.map_err(into_dyn_err)?;
    debug!(logger, "Connected to Electrum server");
    let connection = tokio::io::BufStream::new(connection);
    let codec = tokio_util::codec::LinesCodec::new();
    let connection = tokio_util::codec::Framed::new(connection, codec);
    let (mut electrum_sender, electrum_receiver) = connection.split();
    let (control_sender, mut control_receiver) = tokio::sync::mpsc::channel(256);

    let trace_logger = logger.clone();
    let mut electrum_receiver = electrum_receiver
        .inspect(move |message| {
            match message {
                Ok(message) => trace!(trace_logger, "Received message"; "message" => message.clone()),
                Err(_error) => error!(trace_logger, "Failed to receive message"),
            }
        });

    let request = Request {
        version: "2.0",
        method: "server.features",
        params: [""; 0],
        id: 0,
    };
    send_request(&request, &mut electrum_sender).await?;
    let features = electrum_receiver.next().await
        .expect("TODO: handle error properly")
        .map_err(into_dyn_err)?;

    let features = serde_json::from_str::<ResultResponse<FeaturesResponse>>(&features)
        .map_err(into_dyn_err)?;
    let network = features.result.genesis_hash.try_into().map_err(into_dyn_err)?;

    let request = Request {
        version: "2.0",
        method: "blockchain.headers.subscribe",
        params: [""; 0],
        id: 0,
    };
    send_request(&request, &mut electrum_sender).await?;
    // TODO: check result
    let _subscribe_result = electrum_receiver.next().await
        .expect("TODO: handle error properly")
        .map_err(into_dyn_err)?;

    let client = Client {
        sender: control_sender,
        network,
    };
    let control_receiver = futures::stream::poll_fn(move |context| control_receiver.poll_recv(context));

    let processor = async move {
        let mut next_id = 1u64;
        let mut requests = HashMap::new();
        let mut events = futures::stream::select(electrum_receiver.map(Either::Left), control_receiver.map(Either::Right));
        while let Some(event) = events.next().await {
            let result = match event {
                Either::Left(Ok(line)) => {
                    match serde_json::from_str::<Response>(&line) {
                        Ok(Response::Notification(notification)) => {
                            match notification.method {
                                NotificationMethod::ScriptHashNotification(scripthash) => {
                                    // we don't care if the caller is no longer interested.
                                    let _ = notifications.send(Notification::ScriptHash(scripthash.scripthash)).await;
                                    Ok(())
                                },
                                NotificationMethod::HeaderNotification(notification) => {
                                    // we don't care if the caller is no longer interested.
                                    let _ = notifications
                                        .send(Notification::Header(notification.header))
                                        .await;
                                    Ok(())
                                },
                            }
                        }
                        Ok(Response::Success(result)) => {
                            let request = requests.remove(&result.id).expect("unknown id");
                            match request {
                                CommandResultSender::ScriptHashSubscribe(sender) => {
                                    let _ = sender.send(Ok(()));
                                },
                                CommandResultSender::ScriptHashListUnspent(sender) => {
                                    let _ = sender.send(serde_json::from_value(result.result).map_err(into_dyn_err));
                                },
                                CommandResultSender::GetTransaction(sender) => {
                                    let _ = sender.send(serde_json::from_value(result.result).map_err(into_dyn_err));
                                },
                                CommandResultSender::GetTransactionConfirmations(sender) => {
                                    let _ = sender.send(serde_json::from_value(result.result).map_err(into_dyn_err));
                                },
                                CommandResultSender::BroadcastTransaction(sender) => {
                                    let _ = sender.send(serde_json::from_value(result.result).map_err(into_dyn_err));
                                },
                                CommandResultSender::GetFeeHistogram(sender) => {
                                    let _ = sender.send(serde_json::from_value(result.result).map_err(into_dyn_err));
                                },
                                CommandResultSender::EstimateFeeRate(sender) => {
                                    let _ = sender.send(serde_json::from_value(result.result).map_err(into_dyn_err));
                                },
                            }
                            Ok(())
                        },
                        Ok(Response::Error(result)) => {
                            let request = requests.remove(&result.id).expect("unknown id");
                            let error = into_dyn_err(result.error);
                            match request {
                                CommandResultSender::ScriptHashSubscribe(sender) => {
                                    let _ = sender.send(Err(error));
                                },
                                CommandResultSender::ScriptHashListUnspent(sender) => {
                                    let _ = sender.send(Err(error));
                                },
                                CommandResultSender::GetTransaction(sender) => {
                                    let _ = sender.send(Err(error));
                                },
                                CommandResultSender::GetTransactionConfirmations(sender) => {
                                    let _ = sender.send(Err(error));
                                },
                                CommandResultSender::BroadcastTransaction(sender) => {
                                    let _ = sender.send(Err(error));
                                },
                                CommandResultSender::GetFeeHistogram(sender) => {
                                    let _ = sender.send(Err(error));
                                },
                                CommandResultSender::EstimateFeeRate(sender) => {
                                    let _ = sender.send(Err(error));
                                },
                            }
                            Ok(())
                        },
                        Err(error) => {
                            // we don't care if the caller is no longer interested.
                            let _ = notifications.send(Notification::Failure(Arc::new(error))).await;
                            Err(())
                        },
                    }
                },
                Either::Left(Err(error)) => {
                    // we don't care if the caller is no longer interested.
                    let _ = notifications.send(Notification::Failure(Arc::new(error))).await;
                    Err(())
                },
                Either::Right(command) => {
                    match command {
                        Command::ScriptHashSubscribe(request, sender) => {
                            let request = Request {
                                version: "2.0",
                                method: "blockchain.scripthash.subscribe",
                                params: request,
                                id: next_id,
                            };
                            match send_request(&request, &mut electrum_sender).await {
                                Ok(()) => {
                                    let sender = CommandResultSender::ScriptHashSubscribe(sender);
                                    requests.insert(next_id, sender);
                                    next_id = next_id.wrapping_add(1);
                                },
                                Err(error) => {
                                    // we don't care if the caller is no longer interested.
                                    let _ = sender.send(Err(error));
                                },
                            }
                        },
                        Command::ScriptHashListUnspent(request, sender) => {
                            let request = Request {
                                version: "2.0",
                                method: "blockchain.scripthash.listunspent",
                                params: request,
                                id: next_id,
                            };
                            match send_request(&request, &mut electrum_sender).await {
                                Ok(()) => {
                                    let sender = CommandResultSender::ScriptHashListUnspent(sender);
                                    requests.insert(next_id, sender);
                                    next_id = next_id.wrapping_add(1);
                                },
                                Err(error) => {
                                    // we don't care if the caller is no longer interested.
                                    let _ = sender.send(Err(error));
                                },
                            }
                        },
                        Command::GetTransaction(request, sender) => {
                            let request = Request {
                                version: "2.0",
                                method: "blockchain.transaction.get",
                                params: request,
                                id: next_id,
                            };
                            match send_request(&request, &mut electrum_sender).await {
                                Ok(()) => {
                                    let sender = CommandResultSender::GetTransaction(sender);
                                    requests.insert(next_id, sender);
                                    next_id = next_id.wrapping_add(1);
                                },
                                Err(error) => {
                                    // we don't care if the caller is no longer interested.
                                    let _ = sender.send(Err(error));
                                },
                            }
                        },
                        Command::GetTransactionConfirmations(request, sender) => {
                            let request = Request {
                                version: "2.0",
                                method: "blockchain.transaction.get",
                                params: request,
                                id: next_id,
                            };
                            match send_request(&request, &mut electrum_sender).await {
                                Ok(()) => {
                                    let sender = CommandResultSender::GetTransactionConfirmations(sender);
                                    requests.insert(next_id, sender);
                                    next_id = next_id.wrapping_add(1);
                                },
                                Err(error) => {
                                    // we don't care if the caller is no longer interested.
                                    let _ = sender.send(Err(error));
                                },
                            }
                        },
                        Command::BroadcastTransaction(request, sender) => {
                            let request = Request {
                                version: "2.0",
                                method: "blockchain.transaction.broadcast",
                                params: request,
                                id: next_id,
                            };
                            match send_request(&request, &mut electrum_sender).await {
                                Ok(()) => {
                                    let sender = CommandResultSender::BroadcastTransaction(sender);
                                    requests.insert(next_id, sender);
                                    next_id = next_id.wrapping_add(1);
                                },
                                Err(error) => {
                                    // we don't care if the caller is no longer interested.
                                    let _ = sender.send(Err(error));
                                },
                            }
                        },
                        Command::GetFeeHistogram(request, sender) => {
                            let request = Request {
                                version: "2.0",
                                method: "mempool.get_fee_histogram",
                                params: request,
                                id: next_id,
                            };
                            match send_request(&request, &mut electrum_sender).await {
                                Ok(()) => {
                                    let sender = CommandResultSender::GetFeeHistogram(sender);
                                    requests.insert(next_id, sender);
                                    next_id = next_id.wrapping_add(1);
                                },
                                Err(error) => {
                                    // we don't care if the caller is no longer interested.
                                    let _ = sender.send(Err(error));
                                },
                            }
                        },
                        Command::EstimateFeeRate(request, sender) => {
                            let request = Request {
                                version: "2.0",
                                method: "blockchain.estimatefee",
                                params: request,
                                id: next_id,
                            };
                            match send_request(&request, &mut electrum_sender).await {
                                Ok(()) => {
                                    let sender = CommandResultSender::EstimateFeeRate(sender);
                                    requests.insert(next_id, sender);
                                    next_id = next_id.wrapping_add(1);
                                },
                                Err(error) => {
                                    // we don't care if the caller is no longer interested.
                                    let _ = sender.send(Err(error));
                                },
                            }
                        },
                    }
                    Ok(())
                },
            };
            if let Err(_) = result {
                break;
            }
        }
    };

    Ok((client, processor))
}

async fn send_request<R: serde::Serialize>(request: &Request<R>, sender: &mut (impl futures::SinkExt<String, Error=tokio_util::codec::LinesCodecError> + std::marker::Unpin)) -> Result<(), Error> {
    let req_line = serde_json::to_string(request).map_err(into_dyn_err)?;
    sender.send(req_line).await.map_err(into_dyn_err)
}

pub fn into_dyn_err<E: std::error::Error + Send + Sync + 'static>(error: E) -> Error {
    Arc::new(error)
}

#[cfg(test)]
mod tests {
    #[test]
    fn deser_notification_response() {
        serde_json::from_str::<super::Response>(r#"{"jsonrpc":"2.0","method":"blockchain.scripthash.subscribe","params":["c84e74b461e36fd9171da0961ddd514cdb60e6f1e9200630b70754d852c7d630","ec5bc8084c80fdab4fd68e4ecb6d90e87b3aa0fb9b095024278bd16d9787ab78"]}"#).unwrap();
    }

    #[test]
    fn deser_notification_response2() {
        serde_json::from_str::<super::Response>(r#"{"jsonrpc":"2.0","method":"blockchain.scripthash.subscribe","params":["c84e74b461e36fd9171da0961ddd514cdb60e6f1e9200630b70754d852c7d630","8d5a0a399eb5ecf1d968ffef8999c38e874041f2339e35372b2da13e6f61bc16"]}"#).unwrap();
    }

    #[test]
    fn deser_notification() {
        serde_json::from_str::<super::NotificationResponse>(r#"{"jsonrpc":"2.0","method":"blockchain.scripthash.subscribe","params":["c84e74b461e36fd9171da0961ddd514cdb60e6f1e9200630b70754d852c7d630","ec5bc8084c80fdab4fd68e4ecb6d90e87b3aa0fb9b095024278bd16d9787ab78"]}"#).unwrap();
    }

    #[test]
    fn deser_result_response() {
        serde_json::from_str::<super::Response>(r#"{"id":0,"jsonrpc":"2.0","result":{"genesis_hash":"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206","hash_function":"sha256","hosts":{"tcp_port":60401},"protocol_max":"1.4","protocol_min":"1.4","pruning":null,"server_version":"electrs/0.9.3"}}"#).unwrap();
    }
}
