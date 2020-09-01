/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/
//
//  lp_network.rs
//  marketmaker
//
#![allow(uncommon_codepoints)]

use bytes::Bytes;
use common::executor::{spawn, Timer};
#[cfg(not(feature = "native"))] use common::helperᶜ;
use common::mm_ctx::MmArc;
use common::{lp_queue_command, now_float, now_ms, HyRes, QueuedCommand};
use crossbeam::channel;
use futures::channel::oneshot;
use futures::compat::Future01CompatExt;
use futures::future::FutureExt;
use futures::{SinkExt, StreamExt};
use futures01::{future, Future};
use mm2_libp2p::{atomicdex_behaviour::{AdexBehaviourCmd, AdexBehaviourEvent, AdexCmdTx, AdexEventRx, AdexResponse},
                 decode_signed, encode_and_sign, GossipsubMessage, MessageId, PeerId, PublicKey, TOPIC_SEPARATOR};
#[cfg(test)] use mocktopus::macros::*;
use serde_bencode::de::from_bytes as bdecode;
use serde_bencode::ser::to_bytes as bencode;
use serde_json::{self as json, Value as Json};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::mm2::{lp_ordermatch, lp_swap};
use mm2_libp2p::atomicdex_behaviour::AdexResponseChannel;
use serde::de;

#[derive(Eq, Debug, Deserialize, PartialEq, Serialize)]
pub enum P2PRequest {
    Ordermatch(lp_ordermatch::OrdermatchRequest),
}

pub struct P2PContext {
    pub cmd_tx: AdexCmdTx,
}

#[cfg_attr(test, mockable)]
impl P2PContext {
    pub fn new(cmd_tx: AdexCmdTx) -> Self { P2PContext { cmd_tx } }

    pub fn store_to_mm_arc(self, ctx: &MmArc) { *ctx.p2p_ctx.lock().unwrap() = Some(Arc::new(self)) }

    pub fn fetch_from_mm_arc(ctx: &MmArc) -> Arc<Self> {
        ctx.p2p_ctx
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone()
            .downcast()
            .unwrap()
    }
}

pub async fn p2p_event_process_loop(ctx: MmArc, mut rx: AdexEventRx, i_am_relayer: bool) {
    while !ctx.is_stopping() {
        match rx.next().await {
            Some(AdexBehaviourEvent::Message(peer_id, message_id, message)) => {
                process_p2p_message(ctx.clone(), peer_id, message_id, message, i_am_relayer).await
            },
            Some(AdexBehaviourEvent::PeerRequest {
                peer_id,
                request,
                response_channel,
            }) => {
                if let Err(e) = process_p2p_request(ctx.clone(), peer_id, request, response_channel).await {
                    log!("Error on process P2P request: "[e]);
                }
            },
            None => break,
            _ => (),
        }
    }
}

async fn process_p2p_message(
    ctx: MmArc,
    peer_id: PeerId,
    message_id: MessageId,
    message: GossipsubMessage,
    i_am_relayer: bool,
) {
    let mut to_propagate = false;
    for topic in message.topics {
        let mut split = topic.as_str().split(TOPIC_SEPARATOR);
        match split.next() {
            Some(lp_ordermatch::ORDERBOOK_PREFIX) => {
                if lp_ordermatch::process_msg(ctx.clone(), topic.as_str(), peer_id.to_string(), &message.data).await {
                    to_propagate = true;
                }
            },
            Some(lp_swap::SWAP_PREFIX) => {
                lp_swap::process_msg(ctx.clone(), split.next().unwrap_or_default(), &message.data);
                to_propagate = true;
            },
            None | Some(_) => (),
        }
    }
    if to_propagate && i_am_relayer {
        propagate_message(&ctx, message_id, peer_id);
    }
}

async fn process_p2p_request(
    ctx: MmArc,
    _peer_id: PeerId,
    request: Vec<u8>,
    response_channel: AdexResponseChannel,
) -> Result<(), String> {
    let (request, _sig, pubkey) = try_s!(decode_signed::<P2PRequest>(&request));
    let result = match request {
        P2PRequest::Ordermatch(req) => lp_ordermatch::process_peer_request(ctx.clone(), req, pubkey).await,
    };

    let res = match result {
        Ok(Some(response)) => AdexResponse::Ok { response },
        Ok(None) => AdexResponse::None,
        Err(e) => AdexResponse::Err { error: e },
    };

    let mut tx = P2PContext::fetch_from_mm_arc(&ctx).cmd_tx.clone();
    let cmd = AdexBehaviourCmd::SendResponse { res, response_channel };
    tx.send(cmd).await.unwrap();
    Ok(())
}

#[cfg(feature = "native")]
pub fn broadcast_p2p_msg(ctx: &MmArc, topic: String, msg: Vec<u8>) {
    let mut tx = P2PContext::fetch_from_mm_arc(ctx).cmd_tx.clone();
    spawn(async move {
        let cmd = AdexBehaviourCmd::PublishMsg { topic, msg };
        tx.send(cmd).await.unwrap();
    });
}

/// Subscribe to the given `topic`.
///
/// # Safety
///
/// The function locks the [`MmCtx::p2p_ctx`] mutext.
#[cfg(feature = "native")]
pub async fn subscribe_to_topic(ctx: &MmArc, topic: String) {
    let mut tx = P2PContext::fetch_from_mm_arc(ctx).cmd_tx.clone();
    let cmd = AdexBehaviourCmd::Subscribe { topic };
    tx.send(cmd).await.unwrap();
}

#[cfg(feature = "native")]
#[allow(dead_code)]
pub async fn request_any_relay<T: de::DeserializeOwned>(
    ctx: MmArc,
    req: P2PRequest,
) -> Result<Option<(T, PeerId, PublicKey)>, String> {
    let key_pair = ctx.secp256k1_key_pair.or(&&|| panic!());
    let secret = &*key_pair.private().secret;
    let encoded = try_s!(encode_and_sign(&req, secret));

    let (response_tx, response_rx) = oneshot::channel();
    let mut tx = P2PContext::fetch_from_mm_arc(&ctx).cmd_tx.clone();
    let cmd = AdexBehaviourCmd::RequestAnyRelay {
        req: encoded,
        response_tx,
    };
    tx.send(cmd).await.unwrap();
    match try_s!(response_rx.await) {
        Some((from_peer, response)) => {
            let (response, _sig, pubkey) = try_s!(decode_signed::<T>(&response));
            Ok(Some((response, from_peer, pubkey)))
        },
        None => Ok(None),
    }
}

pub enum RelayDecodedResponse<T> {
    Ok((T, PublicKey)),
    None,
    Err(String),
}

#[cfg(feature = "native")]
pub async fn request_relays<T: de::DeserializeOwned>(
    ctx: MmArc,
    req: P2PRequest,
) -> Result<Vec<(PeerId, RelayDecodedResponse<T>)>, String> {
    let key_pair = ctx.secp256k1_key_pair.or(&&|| panic!());
    let secret = &*key_pair.private().secret;
    let encoded = try_s!(encode_and_sign(&req, secret));

    let (response_tx, response_rx) = oneshot::channel();
    let mut tx = P2PContext::fetch_from_mm_arc(&ctx).cmd_tx.clone();
    let cmd = AdexBehaviourCmd::RequestRelays {
        req: encoded,
        response_tx,
    };
    tx.send(cmd).await.unwrap();
    let responses = try_s!(response_rx.await);
    Ok(parse_peers_responses(responses))
}

#[cfg(feature = "native")]
pub async fn request_peers<T: de::DeserializeOwned>(
    ctx: MmArc,
    req: P2PRequest,
    peers: Vec<String>,
) -> Result<Vec<(PeerId, RelayDecodedResponse<T>)>, String> {
    let key_pair = ctx.secp256k1_key_pair.or(&&|| panic!());
    let secret = &*key_pair.private().secret;
    let encoded = try_s!(encode_and_sign(&req, secret));

    let (response_tx, response_rx) = oneshot::channel();
    let mut tx = P2PContext::fetch_from_mm_arc(&ctx).cmd_tx.clone();
    let cmd = AdexBehaviourCmd::RequestPeers {
        req: encoded,
        peers,
        response_tx,
    };
    tx.send(cmd).await.unwrap();
    let responses = try_s!(response_rx.await);
    Ok(parse_peers_responses(responses))
}

#[cfg(feature = "native")]
pub async fn request_one_peer<T: de::DeserializeOwned>(
    ctx: MmArc,
    req: P2PRequest,
    peer: String,
) -> Result<Option<(T, PublicKey)>, String> {
    let mut responses = try_s!(request_peers::<T>(ctx, req, vec![peer]).await);
    if responses.len() != 1 {
        return ERR!("Expected 1 response, found {}", responses.len());
    }
    let (_, response) = responses.remove(0);
    match response {
        RelayDecodedResponse::Ok((response, pubkey)) => Ok(Some((response, pubkey))),
        RelayDecodedResponse::None => Ok(None),
        RelayDecodedResponse::Err(e) => ERR!("{}", e),
    }
}

fn parse_peers_responses<T: de::DeserializeOwned>(
    responses: Vec<(PeerId, AdexResponse)>,
) -> Vec<(PeerId, RelayDecodedResponse<T>)> {
    responses
        .into_iter()
        .map(|(peer_id, res)| {
            let res = match res {
                AdexResponse::Ok { response } => match decode_signed::<T>(&response) {
                    Ok((res, _sig, pubkey)) => RelayDecodedResponse::Ok((res, pubkey)),
                    Err(e) => RelayDecodedResponse::Err(ERRL!("{}", e)),
                },
                AdexResponse::None => RelayDecodedResponse::None,
                AdexResponse::Err { error } => RelayDecodedResponse::Err(error),
            };
            (peer_id, res)
        })
        .collect()
}

#[cfg(feature = "native")]
pub fn propagate_message(ctx: &MmArc, message_id: MessageId, propagation_source: PeerId) {
    let mut tx = P2PContext::fetch_from_mm_arc(ctx).cmd_tx.clone();
    spawn(async move {
        let cmd = AdexBehaviourCmd::PropagateMessage {
            message_id,
            propagation_source,
        };
        tx.send(cmd).await.unwrap();
    });
}

/// Result of `fn dispatcher`.
#[allow(dead_code)]
pub enum DispatcherRes {
    /// `fn dispatcher` has found a Rust handler for the RPC "method".
    Match(HyRes),
    /// No handler found by `fn dispatcher`. Returning the `Json` request in order for it to be handled elsewhere.
    NoMatch,
}

#[derive(Serialize)]
struct CommandForNn {
    result: Json,
    #[serde(rename = "queueid")]
    queue_id: u32,
}

/// Sends a reply to the `cmd.response_sock` peer.
#[allow(dead_code)]
fn reply_to_peer(cmd: QueuedCommand, mut reply: Vec<u8>) -> Result<(), String> {
    if cmd.response_sock >= 0 {
        if cmd.queue_id != 0 {
            let result = try_s!(json::from_slice(&reply));
            let nn_command = CommandForNn {
                queue_id: cmd.queue_id,
                result,
            };

            reply = try_s!(json::to_vec(&nn_command))
        }

        // See also commits ce09bcd and 62f3cba: looks like we need the wired string to be zero-terminated.
        reply.push(0);
    }
    Ok(())
}

/// Run the RPC handler and send it's reply to a peer.
#[allow(dead_code)]
fn rpc_reply_to_peer(handler: HyRes, cmd: QueuedCommand) {
    let f = handler.then(move |r| -> Box<dyn Future<Item = (), Error = ()> + Send> {
        let res = match r {
            Ok(r) => r,
            Err(err) => {
                log!("rpc_reply_to_peer] handler error: "(err));
                return Box::new(future::err(()));
            },
        };
        let body = res.into_body();
        if let Err(err) = reply_to_peer(cmd, body) {
            log!("reply_to_peer error: "(err));
            return Box::new(future::err(()));
        }
        Box::new(future::ok(()))
    });
    spawn(f.compat().map(|_| ()))
}

/// The loop processing seednode activity as message relayer/rebroadcaster
/// Non-blocking mode should be enabled on listener for this to work
#[allow(dead_code)]
pub fn seednode_loop(ctx: MmArc, listener: TcpListener) {
    let mut clients = vec![];
    loop {
        if ctx.is_stopping() {
            break;
        }

        match listener.accept() {
            Ok((stream, addr)) => {
                ctx.log.log(
                    "😀",
                    &[&"incoming_connection", &addr.to_string().as_str()],
                    "New connection...",
                );
                match stream.set_nonblocking(true) {
                    Ok(_) => clients.push((BufReader::new(stream), addr, String::new())),
                    Err(e) => ctx.log.log(
                        "😟",
                        &[&"incoming_connection", &addr.to_string().as_str()],
                        &format!("Error {} setting nonblocking mode", e),
                    ),
                }
            },
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(e) => panic!("encountered IO error: {}", e),
        }

        let mut commands = Vec::new();
        clients = clients
            .drain_filter(|(client, addr, buf)| match client.read_line(buf) {
                Ok(_) => {
                    if !buf.is_empty() {
                        let msgs = buf.split('\n');
                        for msg in msgs {
                            if !msg.is_empty() {
                                commands.push(msg.to_string())
                            }
                        }
                        buf.clear();
                    }
                    true
                },
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
                Err(e) => {
                    ctx.log.log(
                        "😟",
                        &[&"incoming_connection", &addr.to_string().as_str()],
                        &format!("Error {} reading from socket, dropping connection", e),
                    );
                    false
                },
            })
            .collect();
        for msg in commands {
            unwrap!(lp_queue_command(&ctx, msg));
        }

        clients = match ctx.seednode_p2p_channel.1.recv_timeout(Duration::from_millis(1)) {
            Ok(mut msg) => clients
                .drain_filter(|(client, addr, _)| {
                    msg.push(b'\n');
                    match client.get_mut().write(&msg) {
                        Ok(_) => true,
                        Err(e) => {
                            ctx.log.log(
                                "😟",
                                &[&"incoming_connection", &addr.to_string().as_str()],
                                &format!("Error {} writing to socket, dropping connection", e),
                            );
                            false
                        },
                    }
                })
                .collect(),
            Err(channel::RecvTimeoutError::Timeout) => clients,
            Err(channel::RecvTimeoutError::Disconnected) => panic!("seednode_p2p_channel is disconnected"),
        };
    }
}

#[cfg(feature = "native")]
#[allow(dead_code)]
#[allow(unused)]
pub async fn start_relayer_node_loop(
    ctx: &MmArc,
    myipaddr: IpAddr,
    mypubport: u16,
    other_relayers: Option<Vec<String>>,
) -> Result<(), String> {
    log! ("i_am_seed at " (myipaddr) ":" (mypubport));
    /*
    let listener: TcpListener = try_s!(TcpListener::bind(&fomat!((myipaddr) ":" (mypubport))));
    try_s!(listener.set_nonblocking(true));
    try_s!(thread::Builder::new().name("seednode_loop".into()).spawn({
        let ctx = ctx.clone();
        move || relayer_node(ctx, myipaddr, mypubport, other_relayers)
    }));
    */
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
struct StartSeednodeLoopArgs {
    ctx: u32,
    myipaddr: String,
    mypubport: u16,
}

#[cfg(not(feature = "native"))]
pub async fn start_seednode_loop(ctx: &MmArc, myipaddr: IpAddr, mypubport: u16) -> Result<(), String> {
    let args = StartSeednodeLoopArgs {
        ctx: try_s!(ctx.ffi_handle()),
        myipaddr: fomat!((myipaddr)),
        mypubport,
    };
    let args = try_s!(bencode(&args));
    try_s!(helperᶜ("start_seednode_loop", args).await);
    try_s!(start_queue_tap(ctx.clone()));
    Ok(())
}

#[cfg(feature = "native")]
pub async fn start_seednode_loopʰ(req: Bytes) -> Result<Vec<u8>, String> {
    let args: StartSeednodeLoopArgs = try_s!(bdecode(&req));
    let _myipaddr: IpAddr = try_s!(args.myipaddr.parse());
    let ctx = try_s!(MmArc::from_ffi_handle(args.ctx));
    {
        let mut cq = try_s!(ctx.command_queueʰ.lock());
        if cq.is_none() {
            *cq = Some(Vec::new())
        }
    }
    // try_s! (start_relayer_node_loop (&ctx, myipaddr, args.mypubport) .await);
    Ok(Vec::new())
}

#[allow(dead_code)]
struct SeedConnection {
    stream: BufReader<TcpStream>,
    addr: String,
    buf: String,
    last_msg: u64,
}

#[cfg(feature = "native")]
#[allow(unused)]
pub async fn start_client_p2p_loop(ctx: MmArc, relayers: Vec<String>, port: u16) -> Result<(), String> {
    /*
    let (tx, peer_id) = clientnode(ctx.clone(), relayers, port);
    try_s!(ctx.gossip_sub_cmd_queue.pin(tx));
    try_s!(ctx.peer_id.pin(peer_id));

     */
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct StartClientP2pLoopArgs {
    ctx: u32,
    addrs: Vec<String>,
}

/// Ask helper to fetch us the messages broadcasted from the seed nodes.
#[derive(Serialize, Deserialize)]
struct ClientP2pLoopArgs {
    /// The instance running the `client_p2p_loop` for us.
    ctx: u32,
    /// The time ID of the last message we've seen.
    since: u64,
}

#[cfg(not(feature = "native"))]
pub async fn start_client_p2p_loop(ctx: MmArc, addrs: Vec<String>) -> Result<(), String> {
    use common::helperᶜ;

    let ctx_handle = try_s!(ctx.ffi_handle());
    let args = StartClientP2pLoopArgs { ctx: ctx_handle, addrs };
    let args = try_s!(bencode(&args));
    try_s!(helperᶜ("start_client_p2p_loop", args).await);
    try_s!(start_queue_tap(ctx.clone()));
    Ok(())
}

#[cfg(not(feature = "native"))]
fn start_queue_tap(ctx: MmArc) -> Result<(), String> {
    use common::helperᶜ;
    use futures::future::{select, Either};

    let ctx_handle = try_s!(ctx.ffi_handle());

    // Get messages from the helper's `client_p2p_loop` and `seednode_loop`.
    spawn(async move {
        let mut stoppingᶠ = Box::pin(async {
            loop {
                if ctx.is_stopping() {
                    return;
                };
                Timer::sleep(0.2).await
            }
        });
        let mut last_command = 0;
        loop {
            let args = ClientP2pLoopArgs {
                ctx: ctx_handle,
                since: last_command,
            };
            let args = unwrap!(bencode(&args));
            let pollᶠ = Box::pin(helperᶜ("p2p_tap", args));
            let rc = select(pollᶠ, stoppingᶠ).await;
            let res = match rc {
                Either::Left((res, s)) => {
                    stoppingᶠ = s;
                    res
                },
                Either::Right((_r, _s)) => break,
            };

            let res = match res {
                Ok(res) => res,
                Err(err) => {
                    log!("Error invoking the client_p2p_loop helper: "(err));
                    Timer::sleep(2.2).await;
                    continue;
                },
            };
            let commands: Vec<(u64, String)> = unwrap!(bdecode(&res));
            for (ms, msg) in commands {
                //log! ("Received a broadcast command: " (msg));
                last_command = ms;
                unwrap!(lp_queue_command(&ctx, msg));
            }
        }
    });

    Ok(())
}

/// Poll the native helpers for messages coming from the seed nodes.
#[cfg(feature = "native")]
pub async fn p2p_tapʰ(req: Bytes) -> Result<Vec<u8>, String> {
    let args: ClientP2pLoopArgs = try_s!(bdecode(&req));
    let ctx = try_s!(MmArc::from_ffi_handle(args.ctx));

    let start = now_float();

    let broadcasts = loop {
        let tail: Vec<(u64, String)> = {
            let mut cqˡ = try_s!(ctx.command_queueʰ.lock());
            let cq = match &mut *cqˡ {
                Some(ref mut cq) => cq,
                None => return ERR!("!command_queueʰ"),
            };
            let tail = cq.iter().filter(|(tid, _)| *tid > args.since).cloned().collect();
            // The `since` entry itself is *not* removed in order to always have a ground for monotonic increment.
            cq.retain(|(tid, _)| *tid >= args.since);
            tail
        };

        // Naive HTTP Long-polling: if there's nothing to share with the client then busy-wait for more content.
        if !tail.is_empty() || 11. < now_float() - start {
            break tail;
        }
        Timer::sleep(0.1).await
    };

    let res = try_s!(bencode(&broadcasts));
    Ok(res)
}

pub async fn broadcast_p2p_msgʰ(req: Bytes) -> Result<Vec<u8>, String> {
    let args: common::BroadcastP2pMessageArgs = try_s!(bdecode(&req));
    let ctx = try_s!(MmArc::from_ffi_handle(args.ctx));
    ctx.broadcast_p2p_msg("test".into(), args.msg.into_bytes());
    Ok(Vec::new())
}

/// Tells the native helpers to start the client_p2p_loop, collecting messages from the seed nodes.
#[cfg(feature = "native")]
pub async fn start_client_p2p_loopʰ(req: Bytes) -> Result<Vec<u8>, String> {
    let args: StartClientP2pLoopArgs = try_s!(bdecode(&req));
    let ctx = try_s!(MmArc::from_ffi_handle(args.ctx));
    {
        let mut cq = try_s!(ctx.command_queueʰ.lock());
        if cq.is_none() {
            *cq = Some(Vec::new())
        }
    }
    // try_s! (start_client_p2p_loop (ctx, args.addrs[0].clone(), 1000) .await);
    Ok(Vec::new())
}

/// The loop processing client node activity
#[cfg(feature = "native")]
#[allow(dead_code)]
fn client_p2p_loop(ctx: MmArc, addrs: Vec<String>) {
    let mut seed_connections: Vec<SeedConnection> = vec![];
    // ip and last connection attempt timestamp
    let mut addrs: Vec<(String, u64)> = addrs.into_iter().map(|addr| (addr, 0)).collect();

    loop {
        if ctx.is_stopping() {
            break;
        }

        if seed_connections.len() < addrs.len() {
            for (addr, last_attempt) in addrs.iter_mut() {
                let is_connected = seed_connections.iter().find(|conn| &conn.addr == addr);
                if is_connected.is_none() && *last_attempt + 30000 < now_ms() {
                    ctx.log.log("…", &[&"seed_connection", &addr.as_str()], "Connecting…");
                    *last_attempt = now_ms();
                    match TcpStream::connect(&*addr) {
                        Ok(stream) => match stream.set_nonblocking(true) {
                            Ok(_) => {
                                let conn = SeedConnection {
                                    stream: BufReader::new(stream),
                                    addr: (*addr).to_string(),
                                    buf: String::new(),
                                    last_msg: now_ms(),
                                };
                                ctx.log.log("⚡", &[&"seed_connection", &addr.as_str()], "Connected");
                                seed_connections.push(conn);
                            },
                            Err(e) => ctx.log.log(
                                "😟",
                                &[&"seed_connection", &addr.as_str()],
                                &format!("Error {} setting non-blocking mode", e),
                            ),
                        },
                        Err(e) => ctx.log.log(
                            "😟",
                            &[&"seed_connection", &addr.as_str()],
                            &format!("Connection error {}", e),
                        ),
                    }
                }
            }
        }

        let mut commands = Vec::new();
        seed_connections = seed_connections
            .drain_filter(|conn| match conn.stream.read_line(&mut conn.buf) {
                Ok(_) => {
                    if !conn.buf.is_empty() {
                        let msgs = conn.buf.split('\n');
                        for msg in msgs {
                            if !msg.is_empty() {
                                commands.push(msg.to_string())
                            }
                        }
                        conn.buf.clear();
                        conn.last_msg = now_ms();
                    }
                    true
                },
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
                Err(e) => {
                    ctx.log.log(
                        "😟",
                        &[&"seed_connection", &conn.addr.clone().as_str()],
                        &format!("Error {} on reading from socket, dropping connection", e),
                    );
                    false
                },
            })
            .collect();
        for msg in commands {
            unwrap!(lp_queue_command(&ctx, msg));
        }

        seed_connections = match ctx.client_p2p_channel.1.recv_timeout(Duration::from_millis(1)) {
            Ok(mut msg) => seed_connections
                .drain_filter(|conn| {
                    msg.push(b'\n');
                    match conn.stream.get_mut().write(&msg) {
                        Ok(_) => true,
                        Err(e) => {
                            ctx.log.log(
                                "😟",
                                &[&"seed_connection", &conn.addr.clone().as_str()],
                                &format!("Error {} writing to socket, dropping connection", e),
                            );
                            false
                        },
                    }
                })
                .collect(),
            Err(channel::RecvTimeoutError::Timeout) => seed_connections,
            Err(channel::RecvTimeoutError::Disconnected) => panic!("client_p2p_channel is disconnected"),
        };
        seed_connections = seed_connections
            .drain_filter(|conn| {
                if conn.last_msg + 30000 < now_ms() {
                    ctx.log.log(
                        "😟",
                        &[&"seed_connection", &conn.addr.clone().as_str()],
                        "Didn't receive any data in 30 seconds, dropping connection",
                    );
                    false
                } else {
                    true
                }
            })
            .collect();
    }
}
