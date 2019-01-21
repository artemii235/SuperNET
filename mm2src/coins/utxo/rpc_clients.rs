use bytes::{BytesMut};
use chain::{OutPoint, Transaction as UtxoTransaction};
use common::{CORE, slurp_req, join_all_sequential};
use common::jsonrpc_client::{JsonRpcClient, JsonRpcResponseFut, JsonRpcRequest, JsonRpcResponse, RpcRes};
use futures::{Async, Future, Poll, Sink};
use futures::sync::mpsc;
use futures_timer::Delay;
use futures_timer::FutureExt;
use gstuff::now_ms;
use hashbrown::HashMap;
use hyper::{Body, Request, StatusCode};
use hyper::header::{AUTHORIZATION};
use keys::Address;
use rpc::v1::types::{H256 as H256Json, Transaction as RpcTransaction, Bytes as BytesJson, VerboseBlockClient};
use script::{Builder};
use serde_json::{self as json, Value as Json};
use serialization::{deserialize};
use sha2::{Sha256, Digest};
use std::{io, thread};
use std::fmt::Debug;
use std::cmp::Ordering;
use std::net::{ToSocketAddrs, SocketAddr};
use std::ops::Deref;
use std::sync::{Mutex, Arc};
use std::time::{Duration};
use tokio::codec::{Encoder, Decoder};
use tokio::net::TcpStream;
use tokio::prelude::*;

#[derive(Debug)]
pub enum UtxoRpcClientEnum {
    Native(NativeClient),
    Electrum(ElectrumClient),
}

impl Deref for UtxoRpcClientEnum {
    type Target = UtxoRpcClientOps;
    fn deref(&self) -> &dyn UtxoRpcClientOps {
        match self {
            &UtxoRpcClientEnum::Native(ref c) => c,
            &UtxoRpcClientEnum::Electrum(ref c) => c,
        }
    }
}

/// Generic unspent info required to build transactions, we need this separate type because native
/// and Electrum provide different list_unspent format.
#[derive(Debug)]
pub struct UnspentInfo {
    pub outpoint: OutPoint,
    pub value: u64,
}

/// Common operations that both types of UTXO clients have but implement them differently
pub trait UtxoRpcClientOps: Debug + 'static {
    fn list_unspent_ordered(&self, address: &Address) -> RpcRes<Vec<UnspentInfo>>;

    fn send_transaction(&self, tx: BytesJson) -> RpcRes<H256Json>;

    fn get_transaction(&self, txid: H256Json) -> RpcRes<RpcTransaction>;

    fn get_block_count(&self) -> RpcRes<u64>;

    fn get_block(&self, height: String) -> RpcRes<VerboseBlockClient>;

    // TODO This operation is synchronous because it's currently simpler to do it this way.
    // Might consider refactoring when async/await is released.
    fn wait_for_payment_spend(&self, tx: &UtxoTransaction, vout: usize, wait_until: u64) -> Result<UtxoTransaction, String>;

    // TODO This operation is synchronous because it's currently simpler to do it this way.
    // Might consider refactoring when async/await is released.
    fn wait_for_confirmations(&self, tx: &UtxoTransaction, confirmations: u32, wait_until: u64) -> Result<(), String> {
        loop {
            if now_ms() / 1000 > wait_until {
                return ERR!("Waited too long until {} for transaction {:?} to be confirmed {} times", wait_until, tx, confirmations);
            }

            let tx: RpcTransaction = try_s!(self.get_transaction(tx.hash().reversed().into()).wait());

            if tx.confirmations >= confirmations {
                return Ok(());
            }

            thread::sleep(Duration::from_secs(10));
        }
    }

    fn display_balance(&self, address: Address) -> RpcRes<f64>;
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
pub struct NativeUnspent {
    pub txid: H256Json,
    pub vout: u32,
    pub address: String,
    pub account: String,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: BytesJson,
    pub amount: f64,
    pub confirmations: u64,
    pub spendable: bool
}

#[derive(Clone, Deserialize, Debug)]
pub struct ValidateAddressRes {
    #[serde(rename = "isvalid")]
    pub is_valid: bool,
    pub address: String,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: BytesJson,
    #[serde(rename = "segid")]
    pub seg_id: Option<u32>,
    #[serde(rename = "ismine")]
    pub is_mine: bool,
    #[serde(rename = "iswatchonly")]
    pub is_watch_only: bool,
    #[serde(rename = "isscript")]
    pub is_script: bool,
    pub account: Option<String>,
}

/// RPC client for UTXO based coins
/// https://bitcoin.org/en/developer-reference#rpc-quick-reference - Bitcoin RPC API reference
/// Other coins have additional methods or miss some of these
/// This description will be updated with more info
#[derive(Clone, Debug)]
pub struct NativeClient {
    /// The uri to send requests to
    pub uri: String,
    /// Value of Authorization header, e.g. "Basic base64(user:password)"
    pub auth: String,
}

impl JsonRpcClient for NativeClient {
    fn version(&self) -> &'static str { "1.0" }

    fn next_id(&self) -> String { "0".into() }

    fn transport(&self, request: JsonRpcRequest) -> JsonRpcResponseFut {
        let request_body = try_fus!(json::to_string(&request));

        let http_request = try_fus!(
            Request::builder()
                    .method("POST")
                    .header(
                        AUTHORIZATION,
                        self.auth.clone()
                    )
                    .uri(self.uri.clone())
                    .body(Body::from(request_body))
        );
        Box::new(slurp_req(http_request).then(move |result| -> Result<JsonRpcResponse, String> {
            let res = try_s!(result);
            let body = try_s!(std::str::from_utf8(&res.2));
            if res.0 != StatusCode::OK {
                return ERR!("Rpc request {:?} failed with HTTP status code {}, response body: {}",
                        request, res.0, body);
            }
            Ok(try_s!(json::from_str(body)))
        }))
    }
}

impl UtxoRpcClientOps for NativeClient {
    fn list_unspent_ordered(&self, address: &Address) -> RpcRes<Vec<UnspentInfo>> {
        let clone = self.clone();
        Box::new(self.list_unspent(0, 999999, vec![address.to_string()]).and_then(move |unspents| {
            let mut futures = vec![];
            for unspent in unspents.iter() {
                let delay_f = Delay::new(Duration::from_millis(10)).map_err(|e| ERRL!("{}", e));
                let tx_id = unspent.txid.clone();
                let vout = unspent.vout as usize;
                let arc = clone.clone();
                // The delay here is required to mitigate "Work queue depth exceeded" error from coin daemon.
                // It happens even when we run requests sequentially.
                // Seems like daemon need some time to clean up it's queue after response is sent.
                futures.push(delay_f.and_then(move |_| arc.output_amount(tx_id, vout)));
            }

            join_all_sequential(futures).map(move |amounts| {
                let zip_iter = amounts.iter().zip(unspents.iter());
                let mut result: Vec<UnspentInfo> = zip_iter.map(|(value, unspent)| UnspentInfo {
                    outpoint: OutPoint {
                        hash: unspent.txid.reversed().into(),
                        index: unspent.vout,
                    },
                    value: *value,
                }).collect();

                result.sort_unstable_by(|a, b| {
                    if a.value < b.value {
                        Ordering::Less
                    } else {
                        Ordering::Greater
                    }
                });
                result
            })
        }))
    }

    fn send_transaction(&self, tx: BytesJson) -> RpcRes<H256Json> {
        self.send_raw_transaction(tx)
    }

    fn get_transaction(&self, txid: H256Json) -> RpcRes<RpcTransaction> {
        self.get_raw_transaction(txid)
    }

    /// https://bitcoin.org/en/developer-reference#getblockcount
    fn get_block_count(&self) -> RpcRes<u64> {
        rpc_func!(self, "getblockcount")
    }

    /// https://bitcoin.org/en/developer-reference#getblock
    /// Always returns verbose block
    fn get_block(&self, height: String) -> RpcRes<VerboseBlockClient> {
        let verbose = true;
        rpc_func!(self, "getblock", height, verbose)
    }

    fn wait_for_payment_spend(&self, tx: &UtxoTransaction, vout: usize, wait_until: u64) -> Result<UtxoTransaction, String> {
        let mut current_height = 0;

        loop {
            if now_ms() / 1000 > wait_until {
                return ERR!("Waited too long until {} for transaction {:?} {} to be spent ", wait_until, tx, vout);
            }

            if current_height == 0 {
                let tx: RpcTransaction = try_s!(self.get_transaction(tx.hash().reversed().into()).wait());

                if tx.confirmations >= 1 {
                    current_height = tx.height;
                    continue;
                }

                thread::sleep(Duration::from_secs(10));
            } else {
                let coin_height = try_s!(self.get_block_count().wait());
                while current_height <= coin_height {
                    let block = try_s!(self.get_block(current_height.to_string()).wait());
                    for tx_hash in block.tx.iter() {
                        let transaction = match self.get_transaction(tx_hash.clone()).wait() {
                            Ok(tx) => tx,
                            Err(_e) => continue
                        };

                        for input in transaction.vin.iter() {
                            if input.txid == tx.hash().reversed().into() && input.vout == vout as u32 {
                                let tx: UtxoTransaction = try_s!(deserialize(transaction.hex.as_slice()).map_err(|e| format!("{:?}", e)));
                                return Ok(tx);
                            }
                        }
                    }

                    current_height += 1;
                }
                thread::sleep(Duration::from_secs(10));
            }
        }
    }

    fn display_balance(&self, address: Address) -> RpcRes<f64> {
        Box::new(self.list_unspent(0, 999999, vec![address.to_string()]).map(|unspents|
            unspents.iter().fold(0., |sum, unspent| sum + unspent.amount)
        ))
    }
}

impl NativeClient {
    /// https://bitcoin.org/en/developer-reference#listunspent
    pub fn list_unspent(&self, min_conf: u64, max_conf: u64, addresses: Vec<String>) -> RpcRes<Vec<NativeUnspent>> {
        rpc_func!(self, "listunspent", min_conf, max_conf, addresses)
    }

    /// https://bitcoin.org/en/developer-reference#importaddress
    pub fn import_address(&self, address: String, label: String, rescan: bool) -> RpcRes<()> {
        rpc_func!(self, "importaddress", address, label, rescan)
    }

    /// https://bitcoin.org/en/developer-reference#validateaddress
    pub fn validate_address(&self, address: String) -> RpcRes<ValidateAddressRes> {
        rpc_func!(self, "validateaddress", address)
    }

    pub fn output_amount(&self, txid: H256Json, index: usize) -> RpcRes<u64> {
        let fut = self.get_raw_transaction(txid);
        Box::new(fut.and_then(move |transaction| {
            let tx: UtxoTransaction = try_s!(deserialize(transaction.hex.as_slice()).map_err(|e| ERRL!("{:?}", e)));
            Ok(tx.outputs[index].value)
        }))
    }

    /// https://bitcoin.org/en/developer-reference#sendrawtransaction
    fn send_raw_transaction(&self, tx: BytesJson) -> RpcRes<H256Json> {
        rpc_func!(self, "sendrawtransaction", tx)
    }

    /// https://bitcoin.org/en/developer-reference#getrawtransaction
    /// Always returns verbose transaction
    fn get_raw_transaction(&self, txid: H256Json) -> RpcRes<RpcTransaction> {
        let verbose = 1;
        rpc_func!(self, "getrawtransaction", txid, verbose)
    }
}

#[derive(Debug, Deserialize)]
struct ElectrumUnspent {
    height: Option<u64>,
    tx_hash: H256Json,
    tx_pos: u32,
    value: u64,
}

#[derive(Debug, Deserialize)]
pub struct ElectrumBlockHeader {
    bits: u64,
    block_height: u64,
    merkle_root: H256Json,
    nonce: H256Json,
    prev_block_hash: H256Json,
    timestamp: u64,
    version: u64,
}

#[derive(Debug, Deserialize)]
struct ElectrumTxHistoryItem {
    height: u64,
    tx_hash: H256Json,
    fee: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ElectrumBalance {
    confirmed: i64,
    unconfirmed: i64,
}

fn sha_256(input: &[u8]) -> Vec<u8> {
    let mut sha = Sha256::new();
    sha.input(input);
    sha.result().to_vec()
}

pub fn electrum_script_hash(script: &[u8]) -> Vec<u8> {
    let mut result = sha_256(script);
    result.reverse();
    result
}

pub fn spawn_electrum(
    addr: &str,
    arc: Arc<Mutex<HashMap<String, JsonRpcResponse>>>,
) -> Box<Future<Item=mpsc::Sender<Vec<u8>>, Error=String>> {
    let mut addr = try_fus!(addr.to_socket_addrs());

    Box::new(electrum_connect(&addr.next().unwrap(), arc).map_err(|e| ERRL!("{}", e)))
}

#[derive(Debug)]
pub struct ElectrumClientImpl {
    results: Arc<Mutex<HashMap<String, JsonRpcResponse>>>,
    senders: Vec<mpsc::Sender<Vec<u8>>>,
    next_id: Mutex<u64>,
}

#[derive(Debug)]
pub struct ElectrumClient(pub Arc<ElectrumClientImpl>);
impl Deref for ElectrumClient {type Target = ElectrumClientImpl; fn deref (&self) -> &ElectrumClientImpl {&*self.0}}

const BLOCKCHAIN_HEADERS_SUB_ID: &'static str = "blockchain.headers.subscribe";

impl JsonRpcClient for ElectrumClientImpl {
    fn version(&self) -> &'static str { "2.0" }

    fn next_id(&self) -> String {
        let mut next = unwrap!(self.next_id.lock());
        *next += 1;
        next.to_string()
    }

    fn transport(&self, request: JsonRpcRequest) -> JsonRpcResponseFut {
        Box::new(electrum_request_multi(request, self.senders.clone(), self.results.clone()))
    }
}

impl UtxoRpcClientOps for ElectrumClient {
    fn list_unspent_ordered(&self, address: &Address) -> RpcRes<Vec<UnspentInfo>> {
        let script = Builder::build_p2pkh(&address.hash);
        let script_hash = electrum_script_hash(&script);
        Box::new(self.scripthash_list_unspent(&hex::encode(script_hash)).map(|unspents| {
            let mut result: Vec<UnspentInfo> = unspents.iter().map(|unspent| UnspentInfo {
                outpoint: OutPoint {
                    hash: unspent.tx_hash.reversed().into(),
                    index: unspent.tx_pos,
                },
                value: unspent.value
            }).collect();

            result.sort_unstable_by(|a, b| {
                if a.value < b.value {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            });
            result
        }))
    }

    /// https://electrumx.readthedocs.io/en/latest/protocol-methods.html#blockchain-transaction-broadcast
    fn send_transaction(&self, tx: BytesJson) -> RpcRes<H256Json> {
        rpc_func!(self, "blockchain.transaction.broadcast", tx)
    }

    /// https://electrumx.readthedocs.io/en/latest/protocol-methods.html#blockchain-transaction-get
    /// returns verbose transaction by default
    fn get_transaction(&self, txid: H256Json) -> RpcRes<RpcTransaction> {
        let verbose = true;
        rpc_func!(self, "blockchain.transaction.get", txid, verbose)
    }

    /// https://bitcoin.org/en/developer-reference#getblockcount
    fn get_block_count(&self) -> RpcRes<u64> {
        let lock = try_fus!(self.results.lock());
        let elem = lock.get(BLOCKCHAIN_HEADERS_SUB_ID);
        match elem {
            Some(response) => {
                let response: ElectrumBlockHeader = try_fus!(json::from_value(response.result.clone()));
                Box::new(futures::future::ok(response.block_height))
            },
            None => Box::new(futures::future::err(ERRL!("{} is not active", BLOCKCHAIN_HEADERS_SUB_ID)))
        }
    }

    /// https://bitcoin.org/en/developer-reference#getblock
    /// Always returns verbose block
    fn get_block(&self, height: String) -> RpcRes<VerboseBlockClient> {
        unimplemented!()
    }

    /// This function is assumed to be used to search for spend of swap payment.
    /// For this case we can just wait that address history contains 2 or more records: the payment itself and spending transaction.
    fn wait_for_payment_spend(&self, transaction: &UtxoTransaction, vout: usize, wait_until: u64) -> Result<UtxoTransaction, String> {
        let script_hash = hex::encode(electrum_script_hash(&transaction.outputs[vout].script_pubkey));

        loop {
            if now_ms() / 1000 > wait_until {
                return ERR!("Waited too long until {} for output {:?} to be spent ", wait_until, transaction.outputs[vout]);
            }

            let history = try_s!(self.scripthash_get_history(&script_hash).wait());
            if history.len() < 2 {
                thread::sleep(Duration::from_secs(10));
                continue;
            }

            for item in history.iter() {
                let tx: RpcTransaction = try_s!(self.get_transaction(item.tx_hash.clone()).wait());
                for input in tx.vin.iter() {
                    if input.txid == transaction.hash().reversed().into() && input.vout == vout as u32 {
                        let tx: UtxoTransaction = try_s!(deserialize(tx.hex.as_slice()).map_err(|e| format!("{:?}", e)));
                        return Ok(tx);
                    }
                }
            }

            thread::sleep(Duration::from_secs(10));
        }
    }

    fn display_balance(&self, address: Address) -> RpcRes<f64> {
        let hash = electrum_script_hash(&Builder::build_p2pkh(&address.hash));
        let hash_str = hex::encode(hash);
        Box::new(self.scripthash_get_balance(&hash_str).map(|result| {
            (result.confirmed as f64 + result.unconfirmed as f64) / 100000000.0
        }))
    }
}

impl ElectrumClientImpl {
    pub fn new() -> ElectrumClientImpl {
        ElectrumClientImpl {
            results: Arc::new(Mutex::new(HashMap::new())),
            senders: vec![],
            next_id: Mutex::new(0),
        }
    }

    pub fn add_server(&mut self, addr: &str) -> Result<(), String> {
        // TODO Have to implement this function as synchronous using .wait to avoid wrapping senders in Mutex/Arc.
        // Consider refactoring when async/await is released.
        let sender = try_s!(spawn_electrum(addr, self.results.clone()).wait());
        self.senders.push(sender);
        Ok(())
    }

    /// https://electrumx.readthedocs.io/en/latest/protocol-methods.html#server-ping
    pub fn server_ping(&self) -> RpcRes<()> {
        rpc_func!(self, "server.ping")
    }

    /// https://electrumx.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-listunspent
    fn scripthash_list_unspent(&self, hash: &str) -> RpcRes<Vec<ElectrumUnspent>> {
        rpc_func!(self, "blockchain.scripthash.listunspent", hash)
    }

    /// https://electrumx.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-get-history
    fn scripthash_get_history(&self, hash: &str) -> RpcRes<Vec<ElectrumTxHistoryItem>> {
        rpc_func!(self, "blockchain.scripthash.get_history", hash)
    }

    /// https://electrumx.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-gethistory
    fn scripthash_get_balance(&self, hash: &str) -> RpcRes<ElectrumBalance> {
        rpc_func!(self, "blockchain.scripthash.get_balance", hash)
    }

    /// https://electrumx.readthedocs.io/en/latest/protocol-methods.html#blockchain-headers-subscribe
    pub fn blockchain_headers_subscribe(&self) -> RpcRes<ElectrumBlockHeader> {
        Box::new(
            electrum_subscribe_multi(
                JsonRpcRequest {
                    jsonrpc: "2.0".into(),
                    id: BLOCKCHAIN_HEADERS_SUB_ID.into(),
                    method: "blockchain.headers.subscribe".into(),
                    params: vec![],
                },
                self.senders.clone(),
                self.results.clone(),
            ).and_then(|result| {
                let response: ElectrumBlockHeader = try_s!(json::from_value(result.result.clone()));
                Ok(response)
            })
        )
    }
}

/// Helper function casting mpsc::Receiver as Stream.
fn rx_to_stream(rx: mpsc::Receiver<Vec<u8>>) -> impl Stream<Item = Vec<u8>, Error = io::Error> {
    rx.map_err(|_| panic!("errors not possible on rx"))
}

fn electrum_process_chunk(chunk: &[u8], arc: Arc<Mutex<HashMap<String, JsonRpcResponse>>>) {
    // we should split the received chunk because we can get several responses in 1 chunk.
    let split = chunk.split(|item| *item == '\n' as u8);

    for chunk in split {
        // split returns empty slice if it ends with separator which is our case
        if chunk.len() > 0 {
            let raw_json: Json = match json::from_slice(chunk) {
                Ok(json) => json,
                Err(e) => {
                    log!([e]);
                    return;
                }
            };

            // detect if we got standard JSONRPC response or subscription response as JSONRPC request
            if raw_json["method"].is_null() && raw_json["params"].is_null() {
                let response: JsonRpcResponse = match json::from_value(raw_json) {
                    Ok(res) => res,
                    Err(e) => {
                        log!([e]);
                        return;
                    }
                };
                (*arc.lock().unwrap()).insert(response.id.to_string(), response);
            } else {
                let request: JsonRpcRequest = match json::from_value(raw_json) {
                    Ok(res) => res,
                    Err(e) => {
                        log!([e]);
                        return;
                    }
                };
                let id = match request.method.as_ref() {
                    BLOCKCHAIN_HEADERS_SUB_ID => BLOCKCHAIN_HEADERS_SUB_ID,
                    _ => {
                        log!("Couldn't get id for request "[request]);
                        return;
                    }
                };

                let response = JsonRpcResponse {
                    id: id.into(),
                    jsonrpc: "2.0".into(),
                    result: request.params[0].clone(),
                    error: Json::Null,
                };

                (*arc.lock().unwrap()).insert(id.into(), response);
            }
        }
    }
}

fn electrum_connect(
    addr: &SocketAddr,
    arc: Arc<Mutex<HashMap<String, JsonRpcResponse>>>,
) -> impl Future<Item=mpsc::Sender<Vec<u8>>, Error=String> {
    let tcp = TcpStream::connect(addr);
    let (tx, rx) = mpsc::channel(0);
    let rx = rx_to_stream(rx);

    tcp
        .map_err(|e| ERRL!("{}", e))
        .and_then(move |stream| {
            try_s!(stream.set_nodelay(true));

            let (sink, stream) = Bytes.framed(stream).split();

            CORE.spawn(|_| {
                rx.forward(sink).then(|result| {
                    if let Err(e) = result {
                        log!("failed to write to socket " [e])
                    }
                    Ok(())
                })
            });

            CORE.spawn(|_| {
                stream
                    .for_each(move |chunk| {
                        electrum_process_chunk(&chunk, arc.clone());
                        futures::future::ok(())
                    })
                    .map_err(|e| { log!([e]); () })
            });
            Ok(tx)
        })
}

/// A simple `Codec` implementation that reads buffer until \n according to Electrum protocol specification:
/// https://electrumx.readthedocs.io/en/latest/protocol-basics.html#message-stream
///
/// Implementation adopted from https://github.com/tokio-rs/tokio/blob/master/examples/connect.rs#L84
pub struct Bytes;

impl Decoder for Bytes {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<BytesMut>> {
        let len = buf.len();
        if len > 0 && buf[len - 1] == '\n' as u8 {
            Ok(Some(buf.split_to(len)))
        } else {
            Ok(None)
        }
    }
}

impl Encoder for Bytes {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn encode(&mut self, data: Vec<u8>, buf: &mut BytesMut) -> io::Result<()> {
        buf.extend_from_slice(&data);
        Ok(())
    }
}

struct ElectrumResponseFut {
    context: Arc<Mutex<HashMap<String, JsonRpcResponse>>>,
    request_id: String,
}

impl Future for ElectrumResponseFut {
    type Item = JsonRpcResponse;
    type Error = String;

    fn poll(&mut self) -> Poll<JsonRpcResponse, String> {
        loop {
            let elem = try_s!(self.context.lock()).remove(&self.request_id);
            if let Some(res) = elem {
                return Ok(Async::Ready(res))
            } else {
                let task = futures::task::current();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(200));
                    task.notify();
                });
                return Ok(Async::NotReady)
            }
        }
    }
}

struct ElectrumSubscriptionFut {
    context: Arc<Mutex<HashMap<String, JsonRpcResponse>>>,
    request_id: String,
}

impl Future for ElectrumSubscriptionFut {
    type Item = JsonRpcResponse;
    type Error = String;

    fn poll(&mut self) -> Poll<JsonRpcResponse, String> {
        loop {
            let lock = try_s!(self.context.lock());
            let elem = lock.get(&self.request_id);
            if let Some(res) = elem {
                return Ok(Async::Ready(res.clone()))
            } else {
                let task = futures::task::current();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(200));
                    task.notify();
                });
                return Ok(Async::NotReady)
            }
        }
    }
}

/// From<io::Error> is required to be implemented by futures-timer timeout.
/// We can't implement it for String directly due to Rust restrictions.
/// So this solution looks like simplest at least for now. We have to remap errors to get proper type.
struct StringError(String);

impl From<std::io::Error> for StringError {
    fn from(e: std::io::Error) -> StringError {
        StringError(ERRL!("{}", e))
    }
}

fn electrum_request(
    request: JsonRpcRequest,
    tx: mpsc::Sender<Vec<u8>>,
    context: Arc<Mutex<HashMap<String, JsonRpcResponse>>>
) -> JsonRpcResponseFut {
    let mut json = try_fus!(json::to_string(&request));
    // Electrum request and responses must end with \n
    // https://electrumx.readthedocs.io/en/latest/protocol-basics.html#message-stream
    json.push('\n');

    let request_id = request.get_id().to_string();
    let send_fut = tx.send(json.into_bytes())
        .map_err(|e| ERRL!("{}", e))
        .and_then(move |_res| {
            ElectrumResponseFut {
                request_id,
                context,
            }
        })
        .map_err(|e| StringError(e))
        .timeout(Duration::from_secs(30));

    Box::new(send_fut.map_err(|e| ERRL!("{}", e.0)))
}

fn electrum_request_multi(
    request: JsonRpcRequest,
    senders: Vec<mpsc::Sender<Vec<u8>>>,
    ctx: Arc<Mutex<HashMap<String, JsonRpcResponse>>>
) -> JsonRpcResponseFut {
    let futures = senders.iter().map(|sender| electrum_request(request.clone(), sender.clone(), ctx.clone()));

    Box::new(futures::future::select_ok(futures)
        .map(|(result, _)| {
            result
        })
        .map_err(|e| ERRL!("{:?}", e)))
}

fn electrum_subscribe(
    request: JsonRpcRequest,
    tx: mpsc::Sender<Vec<u8>>,
    context: Arc<Mutex<HashMap<String, JsonRpcResponse>>>
) -> JsonRpcResponseFut {
    let mut json = try_fus!(json::to_string(&request));
    // Electrum request and responses must end with \n
    // https://electrumx.readthedocs.io/en/latest/protocol-basics.html#message-stream
    json.push('\n');

    let request_id = request.get_id().to_string();
    let send_fut = tx.send(json.into_bytes())
        .map_err(|e| ERRL!("{}", e))
        .and_then(move |_res| -> ElectrumSubscriptionFut {
            ElectrumSubscriptionFut {
                request_id,
                context,
            }
        })
        .map_err(|e| StringError(e))
        .timeout(Duration::from_secs(30));

    Box::new(send_fut.map_err(|e| ERRL!("{}", e.0)))
}

fn electrum_subscribe_multi(
    request: JsonRpcRequest,
    senders: Vec<mpsc::Sender<Vec<u8>>>,
    ctx: Arc<Mutex<HashMap<String, JsonRpcResponse>>>
) -> JsonRpcResponseFut {
    let futures = senders.iter().map(|sender| electrum_subscribe(request.clone(), sender.clone(), ctx.clone()));

    Box::new(futures::future::select_ok(futures)
        .map(|(result, _)| {
            result
        })
        .map_err(|e| ERRL!("{:?}", e)))
}

// TODO these are just helpers functions that I used during development.
// Trade tests also cover these functions, if some of these doesn't work properly trade will fail.
// Maybe we should remove them at all or move to a kind of "helpers" file.
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{encode_config as base64_encode, URL_SAFE};

    #[test]
    #[ignore]
    fn test_electrum_ping() {
        let mut client = ElectrumClient::new();
        client.add_server("electrum1.cipig.net:10022").unwrap();
        client.add_server("electrum2.cipig.net:10022").unwrap();
        client.add_server("electrum3.cipig.net:10022").unwrap();
        log!([client.server_ping().wait().unwrap()]);
    }

    #[test]
    #[ignore]
    fn test_electrum_listunspent() {
        let mut client = ElectrumClient::new();
        client.add_server("electrum1.cipig.net:10022").unwrap();
        client.add_server("electrum2.cipig.net:10022").unwrap();
        client.add_server("electrum3.cipig.net:10022").unwrap();
        let script = Builder::build_p2pkh(&"05aab5342166f8594baf17a7d9bef5d567443327".into()).to_bytes();

        let script_hash = electrum_script_hash(&script);
        let res = client.scripthash_list_unspent(&hex::encode(script_hash)).wait().unwrap();
        log!([res]);
    }

    #[test]
    #[ignore]
    fn test_electrum_transaction_get() {
        let mut client = ElectrumClient::new();
        client.add_server("electrum1.cipig.net:10022").unwrap();
        client.add_server("electrum2.cipig.net:10022").unwrap();
        client.add_server("electrum3.cipig.net:10022").unwrap();

        let res = client.get_transaction("c2e633133449d0f3e1f8ddd79957f97c51a2c7ffd640e02e1731dcde75b2062a".into()).wait().unwrap();
        log!([res]);
    }

    #[test]
    #[ignore]
    fn test_electrum_listunspent_ordered() {
        let mut client = ElectrumClient::new();
        client.add_server("electrum1.cipig.net:10022").unwrap();
        client.add_server("electrum2.cipig.net:10022").unwrap();
        client.add_server("electrum3.cipig.net:10022").unwrap();
        let address: Address = "R9o9xTocqr6CeEDGDH6mEYpwLoMz6jNjMW".into();
        let res = client.list_unspent_ordered(&address).wait().unwrap();
        log!([res]);
    }

    #[test]
    #[ignore]
    fn test_electrum_subsribe() {
        let mut client = ElectrumClient::new();
        client.add_server("electrum1.cipig.net:10001").unwrap();
        client.add_server("electrum2.cipig.net:10001").unwrap();
        client.add_server("electrum3.cipig.net:10001").unwrap();
        let res = client.blockchain_headers_subscribe().wait().unwrap();
        log!([res]);

        loop {
            let res = client.get_block_count().wait().unwrap();
            println!("Block {}", res);
            thread::sleep(Duration::from_secs(10));
        }
    }

    #[test]
    #[ignore]
    fn test_electrum_get_history() {
        let mut client = ElectrumClient::new();
        client.add_server("electrum1.cipig.net:10022").unwrap();
        client.add_server("electrum2.cipig.net:10022").unwrap();
        client.add_server("electrum3.cipig.net:10022").unwrap();
        let script = Builder::build_p2pkh(&"05aab5342166f8594baf17a7d9bef5d567443327".into()).to_bytes();

        let script_hash = electrum_script_hash(&script);
        let res = client.scripthash_get_history(&hex::encode(script_hash)).wait().unwrap();
        log!([res]);
    }

    #[test]
    #[ignore]
    fn test_wait_for_tx_spend_electrum() {
        let mut client = ElectrumClient::new();
        client.add_server("electrum1.cipig.net:10022").unwrap();
        client.add_server("electrum2.cipig.net:10022").unwrap();
        client.add_server("electrum3.cipig.net:10022").unwrap();

        let res = client.get_transaction("f1c49150d561cae69607ae0c761d9cd6b69ca20dafa78158e8ae0b1a1c723381".into()).wait().unwrap();

        let tx: UtxoTransaction = deserialize(res.hex.as_slice()).unwrap();
        let wait = client.wait_for_payment_spend(&tx, 0, now_ms() / 1000 + 1000).unwrap();
        log!([wait]);
    }

    #[test]
    #[ignore]
    fn test_wait_for_tx_spend_native() {
        let client = NativeClient {
            uri: "http://127.0.0.1:8923".to_owned(),
            auth: fomat!("Basic " (base64_encode("user1031481471:pass4421be10fa22e70fca76c4917556f1613cdd1fa83e7c9d04abfd98c3367c6252ba", URL_SAFE))),
        };

        let res = client.get_transaction("f1c49150d561cae69607ae0c761d9cd6b69ca20dafa78158e8ae0b1a1c723381".into()).wait().unwrap();

        let tx: UtxoTransaction = deserialize(res.hex.as_slice()).unwrap();
        let wait = client.wait_for_payment_spend(&tx, 0, now_ms() / 1000 + 1000).unwrap();
        log!([wait]);
    }

    #[test]
    #[ignore]
    fn test_list_unspent_ordered_native() {
        let client = NativeClient {
            uri: "http://127.0.0.1:11608".to_owned(),
            auth: fomat!("Basic " (base64_encode("user693461146:passef3e4fbcee47f264b6bd071def8171800241cedd56705c27905f36dd1df2737f99", URL_SAFE))),
        };

        let res = client.list_unspent_ordered(&"RKGn1jkeS7VNLfwY74esW7a8JFfLNj1Yoo".into()).wait().unwrap();
        log!([res]);
    }
}
