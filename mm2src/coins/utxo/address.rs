pub use keys::{Address, AddressHash, KeyPair, Private, Public, Secret};
use script::{Builder, Opcode};

use crate::account::AccountAddressType;
use crate::utxo::dhash160;
use keys::bytes::Bytes;

use super::UtxoCoinConf;

pub fn build_redeem_script(keyhash: &[u8]) -> Bytes {
    let mut redeem_script = Bytes::new_with_len(22);
    redeem_script[0] = Opcode::OP_0 as u8;
    redeem_script[1] = Opcode::OP_PUSHBYTES_20 as u8;
    redeem_script[2..22].clone_from_slice(keyhash);
    redeem_script
}

pub fn build_redeem_script_address(keyhash: &[u8]) -> AddressHash {
    let redeem_script = build_redeem_script(keyhash);
    dhash160(&redeem_script)
}

pub fn build_address(pk: &Public, conf: &UtxoCoinConf) -> Result<Address, String> {
    match conf.account_address_type {
        AccountAddressType::P2PKH => Ok(p2pkh(pk, conf)),
        AccountAddressType::P2SHWPKH => p2shwpkh(pk, conf),
        AccountAddressType::P2WPKH => unimplemented!(),
        AccountAddressType::P2WSH(_) => unimplemented!(),
    }
}

/// Creates a pay to (compressed) public key hash address from a public key
/// This is the preferred non-witness type address
pub fn p2pkh(pk: &Public, conf: &UtxoCoinConf) -> Address {
    Address {
        prefix: conf.pub_addr_prefix,
        t_addr_prefix: conf.pub_t_addr_prefix,
        hash: pk.address_hash(),
        checksum_type: conf.checksum_type,
    }
}

/// Creates a pay to script hash P2SH address from a script
/// This address type was introduced with BIP16 and is the popular type to implement multi-sig these days.
pub fn p2sh(script: &script::Script, conf: &UtxoCoinConf) -> Result<Address, String> {
    let temp = try_s!(script.extract_destinations());
    let sa = temp.get(0).expect("always one");
    Ok(Address {
        prefix: conf.pub_addr_prefix,
        t_addr_prefix: conf.pub_t_addr_prefix,
        hash: sa.hash.clone(),
        checksum_type: conf.checksum_type,
    })
}

/// Create a witness pay to public key address from a public key
/// This is the native segwit address type for an output redeemable with a single signature
///
/// Will only return an Error when an uncompressed public key is provided.
// pub fn p2wpkh(pk: &Public, conf: &UtxoCoinConf) -> Result<Address, String> {
//     if !pk.compressed {
//         return Err(Error::UncompressedPubkey);
//     }

//     let mut hash_engine = WPubkeyHash::engine();
//     pk.write_into(&mut hash_engine).expect("engines don't error");

//     Ok(Address {
//         network: network,
//         payload: Payload::WitnessProgram {
//             version: bech32::u5::try_from_u8(0).expect("0<32"),
//             program: WPubkeyHash::from_engine(hash_engine)[..].to_vec(),
//         },
//     })
// }

/// Create a pay to script address that embeds a witness pay to public key
/// This is a segwit address type that looks familiar (as p2sh) to legacy clients
///
/// Will only return an Error when an uncompressed public key is provided.
pub fn p2shwpkh(pk: &Public, conf: &UtxoCoinConf) -> Result<Address, String> {
    let script_sig = Builder::default()
        .push_opcode(Opcode::from_u8(0u8).expect("zero present"))
        .push_bytes(&pk.address_hash()[..])
        .into_script();
    let to_hash = Bytes::from(script_sig);
    log!({ "p2shwpkh hash payload {:?}", to_hash });
    let hash = dhash160(&to_hash[..]);
    log!({ "hash result {}", hash });
    log!({ "p2sh_addr_prefix {}", conf.p2sh_addr_prefix });
    log!({ "p2sh_t_addr_prefix {}", conf.p2sh_t_addr_prefix });
    Ok(Address {
        prefix: conf.p2sh_addr_prefix,
        t_addr_prefix: conf.p2sh_t_addr_prefix,
        hash,
        checksum_type: conf.checksum_type,
    })
}

// Create a witness pay to script hash address

// pub fn p2wsh(script: &script::Script, conf: &UtxoCoinConf) -> Address {
//     Address {
//         network: network,
//         payload: Payload::WitnessProgram {
//             version: bech32::u5::try_from_u8(0).expect("0<32"),
//             program: WScriptHash::hash(&script[..])[..].to_vec(),
//         },
//     }
// }

// Create a pay to script address that embeds a witness pay to script hash address
// This is a segwit address type that looks familiar (as p2sh) to legacy clients
// pub fn p2shwsh(script: &script::Script, conf: &UtxoCoinConf) -> Address {
//     let ws = script::Builder::new()
//         .push_int(0)
//         .push_slice(&WScriptHash::hash(&script[..])[..])
//         .into_script();

//     Address {
//         network: network,
//         payload: Payload::ScriptHash(ScriptHash::hash(&ws[..])),
//     }
// }

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use crate::utxo::{self, MATURE_CONFIRMATIONS_DEFAULT};
    use bitcrypto::ChecksumType;
    use script::SignatureVersion;

    use super::*;

    fn conf() -> UtxoCoinConf {
        const TEST_COIN_NAME: &'static str = "BTC";
        let checksum_type = ChecksumType::DSHA256;
        UtxoCoinConf {
            is_pos: false,
            requires_notarization: false.into(),
            overwintered: true,
            segwit: utxo::DEFAULT_SUPPORTED_SEGWIT,
            account_address_type: Default::default(),
            tx_version: 4,
            address_format: utxo::UtxoAddressFormat::Standard,
            asset_chain: true,
            p2sh_addr_prefix: 5,
            p2sh_t_addr_prefix: 0,
            pub_addr_prefix: 0,
            pub_t_addr_prefix: 0,
            ticker: TEST_COIN_NAME.into(),
            wif_prefix: 0,
            tx_fee_volatility_percent: utxo::DEFAULT_DYNAMIC_FEE_VOLATILITY_PERCENT,
            version_group_id: 0x892f2085,
            consensus_branch_id: 0x76b809bb,
            zcash: true,
            checksum_type,
            fork_id: 0,
            signature_version: SignatureVersion::Base,
            required_confirmations: 1.into(),
            force_min_relay_fee: false,
            mtp_block_count: NonZeroU64::new(11).unwrap(),
            estimate_fee_mode: None,
            mature_confirmations: MATURE_CONFIRMATIONS_DEFAULT,
            estimate_fee_blocks: 1,
        }
    }

    #[test]
    fn test_p2shwpkh() {
        // stolen from Bitcoin transaction: ad3fd9c6b52e752ba21425435ff3dd361d6ac271531fc1d2144843a9f550ad01
        let pk = hex::decode("026c468be64d22761c30cd2f12cbc7de255d592d7904b1bab07236897cc4c2e766").unwrap();
        let key = Public::from_slice(&pk[..]).unwrap();
        let conf = conf();
        let addr = p2shwpkh(&key, &conf).unwrap();
        assert_eq!(&addr.to_string(), "3QBRmWNqqBGme9er7fMkGqtZtp4gjMFxhE");
        // assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        // roundtrips(&addr);
    }
}
