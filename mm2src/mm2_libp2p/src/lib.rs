#![feature(ip)]

mod adex_ping;
pub mod atomicdex_behaviour;
mod peers_exchange;
pub mod request_response;

use secp256k1::{sign, verify, Message as SecpMessage, PublicKey as Secp256k1Pubkey, SecretKey, Signature};
use serde::{de, ser::Serializer, Deserialize, Serialize};
use serde_bytes;
use sha2::{Digest, Sha256};

pub use atomicdex_behaviour::start_gossipsub;
pub use atomicdex_gossipsub::{GossipsubEvent, GossipsubMessage, MessageId};
pub use libp2p::PeerId;

pub fn encode_message<T: Serialize>(message: &T) -> Result<Vec<u8>, rmp_serde::encode::Error> {
    rmp_serde::to_vec(message)
}

pub fn decode_message<'de, T: de::Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, rmp_serde::decode::Error> {
    rmp_serde::from_read_ref(bytes)
}

#[derive(Deserialize, Serialize)]
struct SignedMessageSerdeHelper<'a> {
    pubkey: PublicKey,
    #[serde(with = "serde_bytes")]
    signature: &'a [u8],
    #[serde(with = "serde_bytes")]
    payload: &'a [u8],
}

pub fn encode_and_sign<T: Serialize>(message: &T, secret: &[u8; 32]) -> Result<Vec<u8>, rmp_serde::encode::Error> {
    let secret = SecretKey::parse(secret).unwrap();
    let encoded = encode_message(message)?;
    let sig_hash = SecpMessage::parse(&sha256(&encoded));
    let (sig, _) = sign(&sig_hash, &secret);
    let serialized_sig = sig.serialize();
    let pubkey = PublicKey::from(Secp256k1Pubkey::from_secret_key(&secret));
    let msg = SignedMessageSerdeHelper {
        pubkey,
        signature: &serialized_sig,
        payload: &encoded,
    };
    encode_message(&msg)
}

pub fn decode_signed<'de, T: de::Deserialize<'de>>(
    encoded: &'de [u8],
) -> Result<(T, Signature, PublicKey), rmp_serde::decode::Error> {
    let helper: SignedMessageSerdeHelper = decode_message(encoded)?;
    let signature = Signature::parse_slice(helper.signature)
        .map_err(|e| rmp_serde::decode::Error::Syntax(format!("Failed to parse signature {}", e)))?;
    let sig_hash = SecpMessage::parse(&sha256(&helper.payload));
    match &helper.pubkey {
        PublicKey::Secp256k1(serialized_pub) => {
            if !verify(&sig_hash, &signature, &serialized_pub.0) {
                return Err(rmp_serde::decode::Error::Syntax("Invalid message signature".into()));
            }
        },
    }

    let payload: T = decode_message(helper.payload)?;
    Ok((payload, signature, helper.pubkey))
}

fn sha256(input: impl AsRef<[u8]>) -> [u8; 32] { Sha256::new().chain(input).finalize().into() }

#[derive(Debug)]
pub struct Secp256k1PubkeySerialize(Secp256k1Pubkey);

impl Serialize for Secp256k1PubkeySerialize {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0.serialize_compressed())
    }
}

impl<'de> de::Deserialize<'de> for Secp256k1PubkeySerialize {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        let slice: &[u8] = de::Deserialize::deserialize(deserializer)?;
        let pubkey = Secp256k1Pubkey::parse_slice(slice, None)
            .map_err(|e| de::Error::custom(format!("Error {} parsing pubkey", e)))?;

        Ok(Secp256k1PubkeySerialize(pubkey))
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum PublicKey {
    Secp256k1(Secp256k1PubkeySerialize),
}

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PublicKey::Secp256k1(pubkey) => pubkey.0.serialize_compressed().to_vec(),
        }
    }

    pub fn to_hex(&self) -> String {
        match self {
            PublicKey::Secp256k1(pubkey) => hex::encode(pubkey.0.serialize_compressed().as_ref()),
        }
    }

    pub fn unprefixed(&self) -> [u8; 32] {
        let mut res = [0; 32];
        match self {
            PublicKey::Secp256k1(pubkey) => res.copy_from_slice(&pubkey.0.serialize_compressed()[1..33]),
        }
        res
    }
}

impl From<Secp256k1Pubkey> for PublicKey {
    fn from(pubkey: Secp256k1Pubkey) -> Self { PublicKey::Secp256k1(Secp256k1PubkeySerialize(pubkey)) }
}

pub type TopicPrefix = &'static str;
pub const TOPIC_SEPARATOR: char = '/';

pub fn pub_sub_topic(prefix: TopicPrefix, topic: &str) -> String {
    let mut res = prefix.to_owned();
    res.push(TOPIC_SEPARATOR);
    res.push_str(topic);
    res
}

#[test]
fn signed_message_serde() {
    let mut rng = rand::thread_rng();
    let secret = SecretKey::random(&mut rng);
    let initial_msg = vec![0u8; 32];
    let signed_encoded = encode_and_sign(&initial_msg, &secret.serialize()).unwrap();

    let (decoded, ..) = decode_signed::<Vec<u8>>(&signed_encoded).unwrap();
    assert_eq!(decoded, initial_msg);
}
