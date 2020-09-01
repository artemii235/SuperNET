use crate::request_response::{build_request_response_behaviour, PeerRequest, PeerResponse, RequestResponseBehaviour,
                              RequestResponseBehaviourEvent, RequestResponseSender};
use atomicdex_gossipsub::{Gossipsub, GossipsubConfigBuilder, GossipsubEvent, GossipsubMessage, MessageId, Topic,
                          TopicHash};
use futures::{channel::{mpsc::{unbounded, UnboundedReceiver, UnboundedSender},
                        oneshot},
              future::{join_all, poll_fn},
              Future, SinkExt, StreamExt};
use lazy_static::lazy_static;
use libp2p::{core::{ConnectedPoint, Multiaddr, Transport},
             identity,
             ping::{Ping, PingConfig, PingEvent},
             request_response::ResponseChannel,
             swarm::{DisconnectPeerHandler, NetworkBehaviourAction, NetworkBehaviourEventProcess, PollParameters},
             NetworkBehaviour, PeerId};
use log::{debug, error, info};
use std::{collections::{hash_map::{DefaultHasher, HashMap},
                        VecDeque},
          hash::{Hash, Hasher},
          net::IpAddr,
          num::NonZeroU32,
          pin::Pin,
          task::{Context, Poll}};
use tokio::runtime::Runtime;
use void::Void;

pub type AdexCmdTx = UnboundedSender<AdexBehaviourCmd>;
pub type AdexEventRx = UnboundedReceiver<AdexBehaviourEvent>;

#[cfg(test)] mod tests;

struct SwarmRuntime(Runtime);

pub const PEERS_TOPIC: &str = "PEERS";

impl libp2p::core::Executor for &SwarmRuntime {
    fn exec(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) { self.0.spawn(future); }
}

lazy_static! {
    static ref SWARM_RUNTIME: SwarmRuntime = SwarmRuntime(Runtime::new().unwrap());
}

/// Returns info about connected peers
pub async fn get_peers_info(mut cmd_tx: AdexCmdTx) -> HashMap<String, Vec<String>> {
    let (result_tx, rx) = oneshot::channel();
    let cmd = AdexBehaviourCmd::GetPeersInfo { result_tx };
    cmd_tx.send(cmd).await.expect("Rx should be present");
    rx.await.expect("Tx should be present")
}

/// Returns current gossipsub mesh state
pub async fn get_gossip_mesh(mut cmd_tx: AdexCmdTx) -> HashMap<String, Vec<String>> {
    let (result_tx, rx) = oneshot::channel();
    let cmd = AdexBehaviourCmd::GetGossipMesh { result_tx };
    cmd_tx.send(cmd).await.expect("Rx should be present");
    rx.await.expect("Tx should be present")
}

pub async fn get_gossip_peer_topics(mut cmd_tx: AdexCmdTx) -> HashMap<String, Vec<String>> {
    let (result_tx, rx) = oneshot::channel();
    let cmd = AdexBehaviourCmd::GetGossipPeerTopics { result_tx };
    cmd_tx.send(cmd).await.expect("Rx should be present");
    rx.await.expect("Tx should be present")
}

pub async fn get_gossip_topic_peers(mut cmd_tx: AdexCmdTx) -> HashMap<String, Vec<String>> {
    let (result_tx, rx) = oneshot::channel();
    let cmd = AdexBehaviourCmd::GetGossipTopicPeers { result_tx };
    cmd_tx.send(cmd).await.expect("Rx should be present");
    rx.await.expect("Tx should be present")
}

#[derive(Debug)]
pub struct AdexResponseChannel(ResponseChannel<PeerResponse>);

impl From<ResponseChannel<PeerResponse>> for AdexResponseChannel {
    fn from(res: ResponseChannel<PeerResponse>) -> Self { AdexResponseChannel(res) }
}

impl From<AdexResponseChannel> for ResponseChannel<PeerResponse> {
    fn from(res: AdexResponseChannel) -> Self { res.0 }
}

#[derive(Debug)]
pub enum AdexBehaviourCmd {
    Subscribe {
        /// Subscribe to this topic
        topic: String,
    },
    PublishMsg {
        topic: String,
        msg: Vec<u8>,
    },
    /// Request relays sequential until a response is received.
    RequestAnyRelay {
        req: Vec<u8>,
        response_tx: oneshot::Sender<Option<(PeerId, Vec<u8>)>>,
    },
    /// Request given peers and collect all their responses.
    RequestPeers {
        req: Vec<u8>,
        peers: Vec<String>,
        response_tx: oneshot::Sender<Vec<(PeerId, AdexResponse)>>,
    },
    /// Request relays and collect all their responses.
    RequestRelays {
        req: Vec<u8>,
        response_tx: oneshot::Sender<Vec<(PeerId, AdexResponse)>>,
    },
    /// Send a response using a `response_channel`.
    SendResponse {
        /// Response to a request.
        res: AdexResponse,
        /// Pass the same `response_channel` as that was obtained from [`AdexBehaviourEvent::PeerRequest`].
        response_channel: AdexResponseChannel,
    },
    GetPeersInfo {
        result_tx: oneshot::Sender<HashMap<String, Vec<String>>>,
    },
    GetGossipMesh {
        result_tx: oneshot::Sender<HashMap<String, Vec<String>>>,
    },
    GetGossipPeerTopics {
        result_tx: oneshot::Sender<HashMap<String, Vec<String>>>,
    },
    GetGossipTopicPeers {
        result_tx: oneshot::Sender<HashMap<String, Vec<String>>>,
    },
    PropagateMessage {
        message_id: MessageId,
        propagation_source: PeerId,
    },
}

/// The structure is the same as `PeerResponse`,
/// but is used to prevent `PeerResponse` from being used outside the network implementation.
#[derive(Debug, Eq, PartialEq)]
pub enum AdexResponse {
    Ok { response: Vec<u8> },
    None,
    Err { error: String },
}

impl From<PeerResponse> for AdexResponse {
    fn from(res: PeerResponse) -> Self {
        match res {
            PeerResponse::Ok { res } => AdexResponse::Ok { response: res },
            PeerResponse::None => AdexResponse::None,
            PeerResponse::Err { err } => AdexResponse::Err { error: err },
        }
    }
}

impl From<AdexResponse> for PeerResponse {
    fn from(res: AdexResponse) -> Self {
        match res {
            AdexResponse::Ok { response } => PeerResponse::Ok { res: response },
            AdexResponse::None => PeerResponse::None,
            AdexResponse::Err { error } => PeerResponse::Err { err: error },
        }
    }
}

/// The structure consists of GossipsubEvent and RequestResponse events.
/// It is used to prevent the network events from being used outside the network implementation.
#[derive(Debug)]
pub enum AdexBehaviourEvent {
    /// A message has been received.
    /// Derived from GossipsubEvent.
    Message(PeerId, MessageId, GossipsubMessage),
    /// A remote subscribed to a topic.
    Subscribed {
        /// Remote that has subscribed.
        peer_id: PeerId,
        /// The topic it has subscribed to.
        topic: TopicHash,
    },
    /// A remote unsubscribed from a topic.
    Unsubscribed {
        /// Remote that has unsubscribed.
        peer_id: PeerId,
        /// The topic it has subscribed from.
        topic: TopicHash,
    },
    /// A remote peer sent a request and waits for a response.
    PeerRequest {
        /// Remote that sent this request.
        peer_id: PeerId,
        /// The serialized data.
        request: Vec<u8>,
        /// A channel for sending a response to this request.
        /// The channel is used to identify the peer on the network that is waiting for an answer to this request.
        /// See [`AdexBehaviourCmd::SendResponse`].
        response_channel: AdexResponseChannel,
    },
}

impl From<GossipsubEvent> for AdexBehaviourEvent {
    fn from(event: GossipsubEvent) -> Self {
        match event {
            GossipsubEvent::Message(peer_id, message_id, gossipsub_message) => {
                AdexBehaviourEvent::Message(peer_id, message_id, gossipsub_message)
            },
            GossipsubEvent::Subscribed { peer_id, topic } => AdexBehaviourEvent::Subscribed { peer_id, topic },
            GossipsubEvent::Unsubscribed { peer_id, topic } => AdexBehaviourEvent::Unsubscribed { peer_id, topic },
        }
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Void")]
#[behaviour(poll_method = "poll_event")]
pub struct AdexPing {
    ping: Ping,
    #[behaviour(ignore)]
    events: VecDeque<NetworkBehaviourAction<Void, Void>>,
}

impl NetworkBehaviourEventProcess<PingEvent> for AdexPing {
    fn inject_event(&mut self, event: PingEvent) {
        if let Err(e) = event.result {
            info!("Ping error {}. Disconnecting peer {}", e, event.peer);
            self.events.push_back(NetworkBehaviourAction::DisconnectPeer {
                peer_id: event.peer,
                handler: DisconnectPeerHandler::All,
            });
        }
    }
}

impl AdexPing {
    fn poll_event(
        &mut self,
        _cx: &mut Context,
        _params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Void, Void>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}

/// AtomicDEX libp2p Network behaviour implementation
#[derive(NetworkBehaviour)]
pub struct AtomicDexBehaviour {
    #[behaviour(ignore)]
    event_tx: UnboundedSender<AdexBehaviourEvent>,
    #[behaviour(ignore)]
    spawn_fn: fn(Box<dyn Future<Output = ()> + Send + Unpin + 'static>) -> (),
    #[behaviour(ignore)]
    cmd_rx: UnboundedReceiver<AdexBehaviourCmd>,
    gossipsub: Gossipsub,
    request_response: RequestResponseBehaviour,
    ping: AdexPing,
}

impl AtomicDexBehaviour {
    fn notify_on_adex_event(&self, event: AdexBehaviourEvent) {
        let mut tx = self.event_tx.clone();
        self.spawn(async move {
            if let Err(e) = tx.send(event).await {
                error!("{}", e);
            }
        });
    }

    fn spawn(&self, fut: impl Future<Output = ()> + Send + 'static) { (self.spawn_fn)(Box::new(Box::pin(fut))) }

    fn process_cmd(&mut self, cmd: AdexBehaviourCmd) {
        match cmd {
            AdexBehaviourCmd::Subscribe { topic } => {
                let topic = Topic::new(topic);
                self.gossipsub.subscribe(topic);
            },
            AdexBehaviourCmd::PublishMsg { topic, msg } => {
                self.gossipsub.publish(&Topic::new(topic), msg);
            },
            AdexBehaviourCmd::RequestAnyRelay { req, response_tx } => {
                let relays = self.gossipsub.get_mesh_relays();
                // spawn the `request_any_peer` future
                let future = request_any_peer(relays, req, self.request_response.sender(), response_tx);
                self.spawn(future);
            },
            AdexBehaviourCmd::RequestPeers {
                req,
                peers,
                response_tx,
            } => {
                let peers = peers
                    .into_iter()
                    .filter_map(|peer| match peer.parse() {
                        Ok(p) => Some(p),
                        Err(e) => {
                            error!("Error on parse peer id {:?}: {:?}", peer, e);
                            None
                        },
                    })
                    .collect();
                let future = request_peers(peers, req, self.request_response.sender(), response_tx);
                self.spawn(future);
            },
            AdexBehaviourCmd::RequestRelays { req, response_tx } => {
                let relays = self.gossipsub.get_mesh_relays();
                // spawn the `request_peers` future
                let future = request_peers(relays, req, self.request_response.sender(), response_tx);
                self.spawn(future);
            },
            AdexBehaviourCmd::SendResponse { res, response_channel } => {
                self.request_response.send_response(response_channel.into(), res.into());
            },
            AdexBehaviourCmd::GetPeersInfo { result_tx } => {
                let result = self
                    .gossipsub
                    .get_peers_connections()
                    .into_iter()
                    .map(|(peer_id, connected_points)| {
                        let peer_id = peer_id.to_base58();
                        let connected_points = connected_points
                            .into_iter()
                            .map(|point| match point {
                                ConnectedPoint::Dialer { address } => address.to_string(),
                                ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr.to_string(),
                            })
                            .collect();
                        (peer_id, connected_points)
                    })
                    .collect();
                if result_tx.send(result).is_err() {
                    println!("Result rx is dropped");
                }
            },
            AdexBehaviourCmd::GetGossipMesh { result_tx } => {
                let result = self
                    .gossipsub
                    .get_mesh()
                    .iter()
                    .map(|(topic, peers)| {
                        let topic = topic.to_string();
                        let peers = peers.iter().map(|peer| peer.to_string()).collect();
                        (topic, peers)
                    })
                    .collect();
                if result_tx.send(result).is_err() {
                    println!("Result rx is dropped");
                }
            },
            AdexBehaviourCmd::GetGossipPeerTopics { result_tx } => {
                let result = self
                    .gossipsub
                    .get_all_peer_topics()
                    .iter()
                    .map(|(peer, topics)| {
                        let peer = peer.to_string();
                        let topics = topics.iter().map(|topic| topic.to_string()).collect();
                        (peer, topics)
                    })
                    .collect();
                if result_tx.send(result).is_err() {
                    error!("Result rx is dropped");
                }
            },
            AdexBehaviourCmd::GetGossipTopicPeers { result_tx } => {
                let result = self
                    .gossipsub
                    .get_all_topic_peers()
                    .iter()
                    .map(|(topic, peers)| {
                        let topic = topic.to_string();
                        let peers = peers.iter().map(|peer| peer.to_string()).collect();
                        (topic, peers)
                    })
                    .collect();
                if result_tx.send(result).is_err() {
                    error!("Result rx is dropped");
                }
            },
            AdexBehaviourCmd::PropagateMessage {
                message_id,
                propagation_source,
            } => {
                self.gossipsub.propagate_message(&message_id, &propagation_source);
            },
        }
    }
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for AtomicDexBehaviour {
    fn inject_event(&mut self, event: GossipsubEvent) { self.notify_on_adex_event(event.into()); }
}

impl NetworkBehaviourEventProcess<Void> for AtomicDexBehaviour {
    fn inject_event(&mut self, _event: Void) {}
}

impl NetworkBehaviourEventProcess<RequestResponseBehaviourEvent> for AtomicDexBehaviour {
    fn inject_event(&mut self, event: RequestResponseBehaviourEvent) {
        match event {
            RequestResponseBehaviourEvent::InboundRequest {
                peer_id,
                request,
                response_channel,
            } => {
                let event = AdexBehaviourEvent::PeerRequest {
                    peer_id,
                    request: request.req,
                    response_channel: response_channel.into(),
                };
                // forward the event to the AdexBehaviourCmd handler
                self.notify_on_adex_event(event);
            },
        }
    }
}

/// Creates and spawns new AdexBehaviour Swarm returning:
/// 1. tx to send control commands
/// 2. rx emitting gossip events to processing side
/// 3. our peer_id
pub fn start_gossipsub(
    ip: IpAddr,
    port: u16,
    spawn_fn: fn(Box<dyn Future<Output = ()> + Send + Unpin + 'static>) -> (),
    to_dial: Option<Vec<String>>,
    my_privkey: &mut [u8],
    i_am_relay: bool,
) -> (UnboundedSender<AdexBehaviourCmd>, AdexEventRx, PeerId) {
    // Create a random PeerId
    let privkey = identity::secp256k1::SecretKey::from_bytes(my_privkey).unwrap();
    let local_key = identity::Keypair::Secp256k1(privkey.into());
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);

    // Set up an encrypted TCP Transport over the Mplex protocol
    let transport = {
        let tcp = libp2p::tcp::TokioTcpConfig::new().nodelay(true);
        let transport = libp2p::dns::DnsConfig::new(tcp).unwrap();
        let trans_clone = transport.clone();
        transport.or_transport(libp2p::websocket::WsConfig::new(trans_clone))
    };

    let transport = transport
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(libp2p::secio::SecioConfig::new(local_key))
        .multiplex(libp2p::mplex::MplexConfig::new())
        .map(|(peer, muxer), _| (peer, libp2p::core::muxing::StreamMuxerBox::new(muxer)))
        .timeout(std::time::Duration::from_secs(20));

    let (cmd_tx, cmd_rx) = unbounded();
    let (event_tx, event_rx) = unbounded();

    let relayers: Vec<Multiaddr> = to_dial
        .unwrap_or_default()
        .into_iter()
        .map(|addr| parse_relay_address(addr, port))
        .collect();

    // Create a Swarm to manage peers and events
    let mut swarm = {
        // to set default parameters for gossipsub use:
        // let gossipsub_config = gossipsub::GossipsubConfig::default();

        // To content-address message, we can take the hash of message and use it as an ID.
        let message_id_fn = |message: &GossipsubMessage| {
            let mut s = DefaultHasher::new();
            message.data.hash(&mut s);
            message.sequence_number.hash(&mut s);
            MessageId(s.finish().to_string())
        };

        // set custom gossipsub
        let gossipsub_config = GossipsubConfigBuilder::new()
            .message_id_fn(message_id_fn)
            .i_am_relay(i_am_relay)
            .manual_propagation()
            .max_transmit_size(1024 * 1024 - 100)
            .build();
        // build a gossipsub network behaviour
        let gossipsub = Gossipsub::new(local_peer_id.clone(), gossipsub_config, relayers.clone());

        // build a request-response network behaviour
        let request_response = build_request_response_behaviour();

        // use default ping config with 15s interval, 20s timeout and 1 max failure
        let ping = AdexPing {
            ping: Ping::new(PingConfig::new().with_max_failures(unsafe { NonZeroU32::new_unchecked(2) })),
            events: VecDeque::new(),
        };

        let adex_behavior = AtomicDexBehaviour {
            event_tx,
            spawn_fn,
            cmd_rx,
            gossipsub,
            request_response,
            ping,
        };
        libp2p::swarm::SwarmBuilder::new(transport, adex_behavior, local_peer_id.clone())
            .executor(Box::new(&*SWARM_RUNTIME))
            .build()
    };
    swarm.gossipsub.subscribe(Topic::new(PEERS_TOPIC.to_owned()));
    let addr = format!("/ip4/{}/tcp/{}", ip, port);
    libp2p::Swarm::listen_on(&mut swarm, addr.parse().unwrap()).unwrap();
    for relayer in &relayers {
        match libp2p::Swarm::dial_addr(&mut swarm, relayer.clone()) {
            Ok(_) => println!("Dialed {}", relayer),
            Err(e) => println!("Dial {:?} failed: {:?}", relayer, e),
        }
    }

    let polling_fut = poll_fn(move |cx: &mut Context| {
        loop {
            match swarm.cmd_rx.poll_next_unpin(cx) {
                Poll::Ready(Some(cmd)) => swarm.process_cmd(cmd),
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => break,
            }
        }

        loop {
            match swarm.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => println!("Swarm event {:?}", event),
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => break,
            }
        }

        Poll::Pending
    });

    SWARM_RUNTIME.0.spawn(polling_fut);

    (cmd_tx, event_rx, local_peer_id)
}

/// If te `addr` is in the "/ip4/{addr}/tcp/{port}" format then parse the `addr` immediately to the `Multiaddr`,
/// else construct the "/ip4/{addr}/tcp/{port}" from `addr` and `port` values.
#[cfg(test)]
fn parse_relay_address(addr: String, port: u16) -> Multiaddr {
    if addr.contains("/ip4/") && addr.contains("/tcp/") {
        addr.parse().unwrap()
    } else {
        format!("/ip4/{}/tcp/{}", addr, port).parse().unwrap()
    }
}

/// The addr is expected to be an IP of the relay
#[cfg(not(test))]
fn parse_relay_address(addr: String, port: u16) -> Multiaddr { format!("/ip4/{}/tcp/{}", addr, port).parse().unwrap() }

/// Request the peers sequential until a `PeerResponse::Ok()` will not be received.
async fn request_any_peer(
    peers: Vec<PeerId>,
    request_data: Vec<u8>,
    request_response_tx: RequestResponseSender,
    response_tx: oneshot::Sender<Option<(PeerId, Vec<u8>)>>,
) {
    debug!("start request_any_peer loop: peers {}", peers.len());
    for peer in peers {
        match request_one_peer(peer.clone(), request_data.clone(), request_response_tx.clone()).await {
            PeerResponse::Ok { res } => {
                debug!("Received a response from peer {:?}, stop the request loop", peer);
                if response_tx.send(Some((peer, res))).is_err() {
                    error!("Response oneshot channel was closed");
                }
                return;
            },
            PeerResponse::None => {
                debug!("Received None from peer {:?}, request next peer", peer);
            },
            PeerResponse::Err { err } => {
                error!("Error on request {:?} peer: {:?}. Request next peer", peer, err);
            },
        };
    }

    debug!("None of the peers responded to the request");
    if response_tx.send(None).is_err() {
        error!("Response oneshot channel was closed");
    };
}

/// Request the peers and collect all their responses.
async fn request_peers(
    peers: Vec<PeerId>,
    request_data: Vec<u8>,
    request_response_tx: RequestResponseSender,
    response_tx: oneshot::Sender<Vec<(PeerId, AdexResponse)>>,
) {
    debug!("start request_any_peer loop: peers {}", peers.len());
    let mut futures = Vec::with_capacity(peers.len());
    for peer in peers {
        let request_data = request_data.clone();
        let request_response_tx = request_response_tx.clone();
        futures.push(async move {
            let response = request_one_peer(peer.clone(), request_data, request_response_tx).await;
            (peer.clone(), response)
        })
    }

    let responses = join_all(futures)
        .await
        .into_iter()
        .map(|(peer_id, res)| {
            let res: AdexResponse = res.into();
            (peer_id, res)
        })
        .collect();

    if response_tx.send(responses).is_err() {
        error!("Response oneshot channel was closed");
    };
}

async fn request_one_peer(peer: PeerId, req: Vec<u8>, mut request_response_tx: RequestResponseSender) -> PeerResponse {
    // Use the internal receiver to receive a response to this request.
    let (internal_response_tx, internal_response_rx) = oneshot::channel();
    let request = PeerRequest { req };
    request_response_tx
        .send((peer.clone(), request, internal_response_tx))
        .await
        .unwrap();

    match internal_response_rx.await {
        Ok(response) => response,
        Err(e) => PeerResponse::Err {
            err: format!("Error on request the peer {:?}: \"{:?}\". Request next peer", peer, e),
        },
    }
}
