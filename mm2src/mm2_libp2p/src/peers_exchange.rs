use crate::request_response::{Codec, Protocol};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{multiaddr::Multiaddr,
             request_response::{ProtocolSupport, RequestResponse, RequestResponseConfig, RequestResponseEvent,
                                RequestResponseMessage},
             swarm::{NetworkBehaviourAction, NetworkBehaviourEventProcess},
             NetworkBehaviour, PeerId};
use log::error;
use rand::{seq::SliceRandom, thread_rng};
use serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize};
use std::{collections::{HashMap, VecDeque},
          iter};

type PeersExchangeCodec = Codec<PeersExchangeRequest, PeersExchangeResponse>;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct PeerIdSerde(PeerId);

impl From<PeerId> for PeerIdSerde {
    fn from(peer_id: PeerId) -> PeerIdSerde { PeerIdSerde(peer_id) }
}

impl Serialize for PeerIdSerde {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_bytes())
    }
}

impl<'de> Deserialize<'de> for PeerIdSerde {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let peer_id = PeerId::from_bytes(bytes).map_err(|_| serde::de::Error::custom("PeerId::from_bytes error"))?;
        Ok(PeerIdSerde(peer_id))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PeersExchangeRequest {
    GetKnownPeers { num: usize },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PeersExchangeResponse {
    KnownPeers {
        peers: HashMap<PeerIdSerde, Vec<Multiaddr>>,
    },
}

/// Behaviour that requests known peers list from other peers at random
#[derive(NetworkBehaviour)]
pub struct PeersExchange {
    request_response: RequestResponse<PeersExchangeCodec>,
    #[behaviour(ignore)]
    known_peers: Vec<PeerId>,
    #[behaviour(ignore)]
    events: VecDeque<NetworkBehaviourAction<(), ()>>,
}

impl PeersExchange {
    pub fn new() -> Self {
        let codec = Codec::default();
        let protocol = iter::once((Protocol::Version1, ProtocolSupport::Full));
        let config = RequestResponseConfig::default();
        let request_response = RequestResponse::new(codec, protocol, config);
        PeersExchange {
            request_response,
            known_peers: Vec::new(),
            events: VecDeque::new(),
        }
    }

    fn get_random_known_peers(&mut self, num: usize) -> HashMap<PeerIdSerde, Vec<Multiaddr>> {
        let mut result = HashMap::with_capacity(num);
        let mut rng = thread_rng();
        let peer_ids = self.known_peers.choose_multiple(&mut rng, num).cloned();
        for peer_id in peer_ids {
            let addresses = self.request_response.addresses_of_peer(&peer_id);
            result.insert(peer_id.into(), addresses);
        }
        result
    }

    fn forget_peer(&mut self, peer: &PeerId) {
        self.known_peers.retain(|known_peer| known_peer != peer);
        for address in self.request_response.addresses_of_peer(&peer) {
            self.request_response.remove_address(&peer, &address);
        }
    }

    pub fn add_peer_addresses(&mut self, peer: &PeerId, addresses: Vec<Multiaddr>) {
        if !self.known_peers.contains(&peer) && !addresses.is_empty() {
            self.known_peers.push(peer.clone());
        }
        for address in addresses {
            self.request_response.add_address(&peer, address);
        }
    }
}

impl NetworkBehaviourEventProcess<RequestResponseEvent<PeersExchangeRequest, PeersExchangeResponse>> for PeersExchange {
    fn inject_event(&mut self, event: RequestResponseEvent<PeersExchangeRequest, PeersExchangeResponse>) {
        match event {
            RequestResponseEvent::Message { message, .. } => match message {
                RequestResponseMessage::Request { request, channel } => match request {
                    PeersExchangeRequest::GetKnownPeers { num } => {
                        let response = PeersExchangeResponse::KnownPeers {
                            peers: self.get_random_known_peers(num),
                        };
                        self.request_response.send_response(channel, response);
                    },
                },
                RequestResponseMessage::Response { response, .. } => match response {
                    PeersExchangeResponse::KnownPeers { peers } => peers.into_iter().for_each(|(peer, addresses)| {
                        self.add_peer_addresses(&peer.0, addresses);
                    }),
                },
            },
            RequestResponseEvent::OutboundFailure {
                peer,
                request_id,
                error,
            } => {
                error!(
                    "Outbound failure {:?} while requesting {:?} to peer {}",
                    error, request_id, peer
                );
                self.forget_peer(&peer);
            },
            RequestResponseEvent::InboundFailure { peer, error } => {
                error!(
                    "Inbound failure {:?} while processing request from peer {}",
                    error, peer
                );
                self.forget_peer(&peer);
            },
        }
    }
}
