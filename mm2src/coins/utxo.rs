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
//  utxo.rs
//  marketmaker
//
//  Copyright © 2017-2019 SuperNET. All rights reserved.
//

#![cfg_attr(not(feature = "native"), allow(unused_imports))]

pub mod rpc_clients;
pub mod qrc20;
pub mod qtum;
pub mod tx_cache;
pub mod utxo_common;
pub mod utxo_standard;

use async_trait::async_trait;
use base64::{encode_config as base64_encode, URL_SAFE};
use bigdecimal::BigDecimal;
pub use bitcrypto::{dhash160, ChecksumType, sha256};
use chain::{TransactionOutput, TransactionInput};
use common::{first_char_to_upper, small_rng};
use common::executor::{spawn, Timer};
use common::jsonrpc_client::JsonRpcError;
use common::mm_ctx::MmArc;
#[cfg(feature = "native")]
use dirs::home_dir;
use futures01::{Future};
use futures::compat::Future01CompatExt;
use futures::lock::{Mutex as AsyncMutex};
use keys::{KeyPair, Private, Public, Address, Secret};
use keys::bytes::Bytes;
use num_traits::ToPrimitive;
use primitives::hash::{H256, H264, H512};
use rand::seq::SliceRandom;
use rpc::v1::types::{Bytes as BytesJson, H256 as H256Json, Transaction as RpcTransaction};
use script::{Builder, Opcode, Script, SignatureVersion, TransactionInputSigner};
use serde_json::{self as json, Value as Json};
use serialization::serialize;
use std::convert::TryInto;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64};

pub use chain::Transaction as UtxoTx;

use self::rpc_clients::{ElectrumClient, ElectrumClientImpl, EstimateFeeMethod, NativeClient, UtxoRpcClientEnum, UnspentInfo };
use super::{CoinsContext, FoundSwapTxSpend, HistorySyncState, MarketCoinOps, MmCoin, TradeFee, TradeInfo,
            Transaction, TransactionEnum, TransactionFut, TransactionDetails, WithdrawFee, WithdrawRequest};
use crate::utxo::rpc_clients::{NativeClientImpl, ElectrumRpcRequest};

#[cfg(test)]
pub mod utxo_tests;

const SWAP_TX_SPEND_SIZE: u64 = 305;
const KILO_BYTE: u64 = 1000;
/// https://bitcoin.stackexchange.com/a/77192
const MAX_DER_SIGNATURE_LEN: usize = 72;
const COMPRESSED_PUBKEY_LEN: usize = 33;
const P2PKH_OUTPUT_LEN: u64 = 34;
const MATURE_CONFIRMATIONS_DEFAULT: u32 = 100;

#[cfg(windows)]
#[cfg(feature = "native")]
fn get_special_folder_path() -> PathBuf {
    use libc::c_char;
    use std::ffi::CStr;
    use std::mem::zeroed;
    use std::ptr::null_mut;
    use winapi::um::shlobj::SHGetSpecialFolderPathA;
    use winapi::shared::minwindef::MAX_PATH;
    use winapi::um::shlobj::CSIDL_APPDATA;

    let mut buf: [c_char; MAX_PATH + 1] = unsafe {zeroed()};
    // https://docs.microsoft.com/en-us/windows/desktop/api/shlobj_core/nf-shlobj_core-shgetspecialfolderpatha
    let rc = unsafe {SHGetSpecialFolderPathA (null_mut(), buf.as_mut_ptr(), CSIDL_APPDATA, 1)};
    if rc != 1 {panic! ("!SHGetSpecialFolderPathA")}
    Path::new (unwrap! (unsafe {CStr::from_ptr (buf.as_ptr())} .to_str())) .to_path_buf()
}

#[cfg(not(windows))]
#[cfg(feature = "native")]
fn get_special_folder_path() -> PathBuf {panic!("!windows")}

impl Transaction for UtxoTx {
    fn tx_hex(&self) -> Vec<u8> {
        serialize(self).into()
    }

    fn extract_secret(&self) -> Result<Vec<u8>, String> {
        let script: Script = self.inputs[0].script_sig.clone().into();
        for (i, instr) in script.iter().enumerate() {
            let instruction = instr.unwrap();
            if i == 1 {
                if instruction.opcode == Opcode::OP_PUSHBYTES_32 {
                    return Ok(instruction.data.unwrap().to_vec());
                }
            }
        }
        ERR!("Couldn't extract secret")
    }

    fn tx_hash(&self) -> BytesJson { self.hash().reversed().to_vec().into() }
}

/// Additional transaction data that can't be easily got from raw transaction without calling
/// additional RPC methods, e.g. to get input amount we need to request all previous transactions
/// and check output values
#[derive(Debug)]
pub struct AdditionalTxData {
    received_by_me: u64,
    spent_by_me: u64,
    fee_amount: u64,
}

/// The fee set from coins config
#[derive(Debug)]
enum TxFee {
    /// Tell the coin that it has fixed tx fee not depending on transaction size
    Fixed(u64),
    /// Tell the coin that it should request the fee from daemon RPC and calculate it relying on tx size
    Dynamic(EstimateFeeMethod),
}

/// The actual "runtime" fee that is received from RPC in case of dynamic calculation
#[derive(Debug)]
pub enum ActualTxFee {
    /// fixed tx fee not depending on transaction size
    Fixed(u64),
    /// fee amount per Kbyte received from coin RPC
    Dynamic(u64),
}

/// Fee policy applied on transaction creation
pub enum FeePolicy {
    /// Send the exact amount specified in output(s), fee is added to spent input amount
    SendExact,
    /// Contains the index of output from which fee should be deducted
    DeductFromOutput(usize),
}

#[derive(Debug)]
pub struct UtxoCoinFields {
    ticker: String,
    /// https://en.bitcoin.it/wiki/List_of_address_prefixes
    /// https://github.com/jl777/coins/blob/master/coins
    pub_addr_prefix: u8,
    p2sh_addr_prefix: u8,
    wif_prefix: u8,
    pub_t_addr_prefix: u8,
    p2sh_t_addr_prefix: u8,
    /// True if coins uses Proof of Stake consensus algo
    /// Proof of Work is expected by default
    /// https://en.bitcoin.it/wiki/Proof_of_Stake
    /// https://en.bitcoin.it/wiki/Proof_of_work
    /// The actual meaning of this is nTime field is used in transaction
    is_pos: bool,
    /// Special field for Zcash and it's forks
    /// Defines if Overwinter network upgrade was activated
    /// https://z.cash/upgrade/overwinter/
    overwintered: bool,
    /// The tx version used to detect the transaction ser/de/signing algo
    /// For now it's mostly used for Zcash and forks because they changed the algo in
    /// Overwinter and then Sapling upgrades
    /// https://github.com/zcash/zips/blob/master/zip-0243.rst
    tx_version: i32,
    /// If true - allow coins withdraw to P2SH addresses (Segwit).
    /// the flag will also affect the address that MM2 generates by default in the future
    /// will be the Segwit (starting from 3 for BTC case) instead of legacy
    /// https://en.bitcoin.it/wiki/Segregated_Witness
    segwit: bool,
    /// Default decimals amount is 8 (BTC and almost all other UTXO coins)
    /// But there are forks which have different decimals:
    /// Peercoin has 6
    /// Emercoin has 6
    /// Bitcoin Diamond has 7
    decimals: u8,
    /// Does coin require transactions to be notarized to be considered as confirmed?
    /// https://komodoplatform.com/security-delayed-proof-of-work-dpow/
    requires_notarization: AtomicBool,
    /// RPC client
    pub rpc_client: UtxoRpcClientEnum,
    /// ECDSA key pair
    key_pair: KeyPair,
    /// Lock the mutex when we deal with address utxos
    my_address: Address,
    /// Is current coin KMD asset chain?
    /// https://komodoplatform.atlassian.net/wiki/spaces/KPSD/pages/71729160/What+is+a+Parallel+Chain+Asset+Chain
    asset_chain: bool,
    tx_fee: TxFee,
    /// Transaction version group id for Zcash transactions since Overwinter: https://github.com/zcash/zips/blob/master/zip-0202.rst
    version_group_id: u32,
    /// Consensus branch id for Zcash transactions since Overwinter: https://github.com/zcash/zcash/blob/master/src/consensus/upgrades.cpp#L11
    /// used in transaction sig hash calculation
    consensus_branch_id: u32,
    /// Defines if coin uses Zcash transaction format
    zcash: bool,
    /// Address and privkey checksum type
    checksum_type: ChecksumType,
    /// Fork id used in sighash
    fork_id: u32,
    /// Signature version
    signature_version: SignatureVersion,
    history_sync_state: Mutex<HistorySyncState>,
    required_confirmations: AtomicU64,
    /// if set to true MM2 will check whether calculated fee is lower than relay fee and use
    /// relay fee amount instead of calculated
    /// https://github.com/KomodoPlatform/atomicDEX-API/issues/617
    force_min_relay_fee: bool,
    /// Minimum transaction value at which the value is not less than fee
    dust_amount: u64,
    /// Minimum number of confirmations at which a transaction is considered mature
    mature_confirmations: u32,
}

#[async_trait]
pub trait UtxoCoinCommonOps {
    async fn get_tx_fee(&self) -> Result<ActualTxFee, JsonRpcError>;

    async fn get_htlc_spend_fee(&self) -> Result<u64, String>;

    fn addresses_from_script(&self, script: &Script) -> Result<Vec<Address>, String>;

    fn denominate_satoshis(&self, satoshi: i64) -> f64;

    fn search_for_swap_tx_spend(
        &self,
        time_lock: u32,
        first_pub: &Public,
        second_pub: &Public,
        secret_hash: &[u8],
        tx: &[u8],
        search_from_block: u64,
    ) -> Result<Option<FoundSwapTxSpend>, String>;

    fn my_public_key(&self) -> &Public;
}

#[derive(Clone, Debug)]
pub struct UtxoArc(Arc<UtxoCoinFields>);
impl Deref for UtxoArc {type Target = UtxoCoinFields; fn deref (&self) -> &UtxoCoinFields {&*self.0}}

impl From<UtxoCoinFields> for UtxoArc {
    fn from(coin: UtxoCoinFields) -> UtxoArc {
        UtxoArc(Arc::new(coin))
    }
}

// We can use a shared UTXO lock for all UTXO coins at 1 time.
// It's highly likely that we won't experience any issues with it as we won't need to send "a lot" of transactions concurrently.
lazy_static! {pub static ref UTXO_LOCK: AsyncMutex<()> = AsyncMutex::new(());}

pub trait UtxoArcGetter {
    fn arc(&self) -> &UtxoArc;
}

#[async_trait]
pub trait UtxoArcCommonOps {
    fn send_outputs_from_my_address(&self, outputs: Vec<TransactionOutput>) -> TransactionFut;

    fn validate_payment(
        &self,
        payment_tx: &[u8],
        time_lock: u32,
        first_pub0: &Public,
        second_pub0: &Public,
        priv_bn_hash: &[u8],
        amount: BigDecimal,
    ) -> Box<dyn Future<Item=(), Error=String> + Send>;

    /// Generates unsigned transaction (TransactionInputSigner) from specified utxos and outputs.
    /// This function expects that utxos are sorted by amounts in ascending order
    /// Consider sorting before calling this function
    /// Sends the change (inputs amount - outputs amount) to "my_address"
    /// Also returns additional transaction data
    async fn generate_transaction(
        &self,
        utxos: Vec<UnspentInfo>,
        outputs: Vec<TransactionOutput>,
        fee_policy: FeePolicy,
        fee: Option<ActualTxFee>,
        gas_fee: Option<u64>,
    ) -> Result<(TransactionInputSigner, AdditionalTxData), String>;

    /// Calculates interest if the coin is KMD
    /// Adds the value to existing output to my_script_pub or creates additional interest output
    /// returns transaction and data as is if the coin is not KMD
    async fn calc_interest_if_required(
        &self,
        mut unsigned: TransactionInputSigner,
        mut data: AdditionalTxData,
        my_script_pub: Bytes,
    ) -> Result<(TransactionInputSigner, AdditionalTxData), String>;

    fn p2sh_spending_tx(
        &self,
        prev_transaction: UtxoTx,
        redeem_script: Bytes,
        outputs: Vec<TransactionOutput>,
        script_data: Script,
        sequence: u32,
    ) -> Result<UtxoTx, String>;
}

pub enum VerboseTransactionFrom {
    Cache(RpcTransaction),
    Rpc(RpcTransaction),
}

/// The additional operations on UTXO coin that need to use MarketMaker context.
#[async_trait]
pub trait UtxoMmCoin {
    /// Path to the transaction cache file.
    fn cached_transaction_path(&self, ctx: &MmArc, txid: &H256Json) -> PathBuf {
        ctx.dbdir().join("TX_CACHE").join(format!("{:?}", txid))
    }

    /// Get transaction outputs available to spend.
    async fn ordered_mature_unspents(&self, ctx: &MmArc, address: &Address) -> Result<Vec<UnspentInfo>, String>;

    /// Try load verbose transaction from cache or try to request it from Rpc client.
    async fn get_verbose_transaction_from_cache_or_rpc(&self, ctx: &MmArc, txid: H256Json) -> Result<VerboseTransactionFrom, String>;

    /// Check if the output is spendable (is not coinbase or it has enough confirmations).
    fn is_unspent_mature(&self, output: &RpcTransaction) -> bool;
}

pub fn compressed_key_pair_from_bytes(raw: &[u8], prefix: u8, checksum_type: ChecksumType) -> Result<KeyPair, String> {
    if raw.len() != 32 {
        return ERR!("Invalid raw priv key len {}", raw.len());
    }

    let private = Private {
        prefix,
        compressed: true,
        secret: Secret::from(raw),
        checksum_type,
    };
    Ok(try_s!(KeyPair::from_private(private)))
}

pub fn compressed_pub_key_from_priv_raw(raw_priv: &[u8], sum_type: ChecksumType) -> Result<H264, String> {
    let key_pair: KeyPair = try_s!(compressed_key_pair_from_bytes(raw_priv, 0, sum_type));
    Ok(H264::from(&**key_pair.public()))
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UtxoFeeDetails {
    amount: BigDecimal,
}

#[cfg(feature = "native")]
// https://github.com/KomodoPlatform/komodo/blob/master/zcutil/fetch-params.sh#L5
// https://github.com/KomodoPlatform/komodo/blob/master/zcutil/fetch-params.bat#L4
pub fn zcash_params_path() -> PathBuf {
    if cfg! (windows) {
        // >= Vista: c:\Users\$username\AppData\Roaming
        get_special_folder_path().join("ZcashParams")
    } else if cfg! (target_os = "macos") {
        unwrap!(home_dir()).join("Library").join("Application Support").join("ZcashParams")
    } else {
        unwrap!(home_dir()).join(".zcash-params")
    }
}

#[cfg(feature = "native")]
pub fn coin_daemon_data_dir(name: &str, is_asset_chain: bool) -> PathBuf {
    // komodo/util.cpp/GetDefaultDataDir
    let mut data_dir = match dirs::home_dir() {
        Some (hd) => hd,
        None => Path::new ("/") .to_path_buf()
    };

    if cfg! (windows) {
        // >= Vista: c:\Users\$username\AppData\Roaming
        data_dir = get_special_folder_path();
        if is_asset_chain {
            data_dir.push ("Komodo");
        } else {
            data_dir.push (first_char_to_upper(name));
        }
    } else if cfg! (target_os = "macos") {
        data_dir.push ("Library");
        data_dir.push ("Application Support");
        if is_asset_chain {
            data_dir.push ("Komodo");
        } else {
            data_dir.push (first_char_to_upper(name));
        }
    } else {
        if is_asset_chain {
            data_dir.push (".komodo");
        } else {
            data_dir.push (format!(".{}", name));
        }
    }

    if is_asset_chain {data_dir.push (name)};
    data_dir
}

#[cfg(not(feature = "native"))]
pub fn coin_daemon_data_dir(_name: &str, _is_asset_chain: bool) -> PathBuf {
    unimplemented!()
}

#[cfg(feature = "native")]
/// Returns a path to the native coin wallet configuration.
/// (This path is used in to read the wallet credentials).
/// cf. https://github.com/artemii235/SuperNET/issues/346
fn confpath (coins_en: &Json) -> Result<PathBuf, String> {
    // Documented at https://github.com/jl777/coins#bitcoin-protocol-specific-json
    // "USERHOME/" prefix should be replaced with the user's home folder.
    let confpathˢ = coins_en["confpath"].as_str().unwrap_or ("") .trim();
    if confpathˢ.is_empty() {
        let (name, is_asset_chain) = {
            match coins_en["asset"].as_str() {
                Some(a) => (a, true),
                None => (try_s!(coins_en["name"].as_str().ok_or("'name' field is not found in config")), false),
            }
        };

        let data_dir = coin_daemon_data_dir(name, is_asset_chain);

        let confname = format! ("{}.conf", name);

        return Ok (data_dir.join (&confname[..]))
    }
    let (confpathˢ, rel_to_home) =
        if confpathˢ.starts_with ("~/") {(&confpathˢ[2..], true)}
        else if confpathˢ.starts_with ("USERHOME/") {(&confpathˢ[9..], true)}
        else {(confpathˢ, false)};

    if rel_to_home {
        let home = try_s! (home_dir().ok_or ("Can not detect the user home directory"));
        Ok (home.join (confpathˢ))
    } else {
        Ok (confpathˢ.into())
    }
}

#[cfg(not(feature = "native"))]
fn confpath (_coins_en: &Json) -> Result<PathBuf, String> {unimplemented!()}

/// Attempts to parse native daemon conf file and return rpcport, rpcuser and rpcpassword
#[cfg(feature = "native")]
fn read_native_mode_conf(filename: &dyn AsRef<Path>) -> Result<(Option<u16>, String, String), String> {
    use ini::Ini;

    let conf: Ini = match Ini::load_from_file(&filename) {
        Ok(ini) => ini,
        Err(err) => return ERR!("Error parsing the native wallet configuration '{}': {}", filename.as_ref().display(), err)
    };
    let section = conf.general_section();
    let rpc_port = match section.get("rpcport") {
        Some(port) => port.parse::<u16>().ok(),
        None => None,
    };
    let rpc_user = try_s!(section.get("rpcuser").ok_or(ERRL!("Conf file {} doesn't have the rpcuser key", filename.as_ref().display())));
    let rpc_password = try_s!(section.get("rpcpassword").ok_or(ERRL!("Conf file {} doesn't have the rpcpassword key", filename.as_ref().display())));
    Ok((rpc_port, rpc_user.clone(), rpc_password.clone()))
}

#[cfg(not(feature = "native"))]
fn read_native_mode_conf(_filename: &dyn AsRef<Path>) -> Result<(Option<u16>, String, String), String> {
    unimplemented!()
}

pub async fn utxo_arc_from_conf_and_request(
    ticker: &str,
    conf: &Json,
    req: &Json,
    priv_key: &[u8],
    dust_amount: u64,
) -> Result<UtxoArc, String> {
    let checksum_type = if ticker == "GRS" {
        ChecksumType::DGROESTL512
    } else if ticker == "SMART" {
        ChecksumType::KECCAK256
    } else {
        ChecksumType::DSHA256
    };

    let pub_addr_prefix = conf["pubtype"].as_u64().unwrap_or (if ticker == "BTC" {0} else {60}) as u8;
    let wif_prefix = conf["wiftype"].as_u64().unwrap_or (if ticker == "BTC" {128} else {188}) as u8;

    let private = Private {
        prefix: wif_prefix,
        secret: H256::from(priv_key),
        compressed: true,
        checksum_type,
    };

    let key_pair = try_s!(KeyPair::from_private(private));
    let my_address = Address {
        prefix: pub_addr_prefix,
        t_addr_prefix: conf["taddr"].as_u64().unwrap_or (0) as u8,
        hash: key_pair.public().address_hash(),
        checksum_type,
    };

    let rpc_client = match req["method"].as_str() {
        Some("enable") => {
            if cfg!(feature = "native") {
                let native_conf_path = try_s!(confpath(conf));
                let (rpc_port, rpc_user, rpc_password) = try_s!(read_native_mode_conf(&native_conf_path));
                let auth_str = fomat!((rpc_user)":"(rpc_password));
                let rpc_port = match rpc_port {
                    Some(p) => p,
                    None => try_s!(conf["rpcport"].as_u64().ok_or(ERRL!("Rpc port is not set neither in `coins` file nor in native daemon config"))) as u16,
                };
                let client = Arc::new(NativeClientImpl {
                    coin_ticker: ticker.to_string(),
                    uri: fomat!("http://127.0.0.1:"(rpc_port)),
                    auth: format!("Basic {}", base64_encode(&auth_str, URL_SAFE)),
                });

                UtxoRpcClientEnum::Native(NativeClient(client))
            } else {
                return ERR!("Native UTXO mode is not available in non-native build");
            }
        },
        Some("electrum") => {
            let mut servers: Vec<ElectrumRpcRequest> = try_s!(json::from_value(req["servers"].clone()));
            let mut rng = small_rng();
            servers.as_mut_slice().shuffle(&mut rng);
            let mut client = ElectrumClientImpl::new(ticker.to_string());
            for server in servers.iter() {
                match client.add_server(server) {
                    Ok(_) => (),
                    Err(e) => log!("Error " (e) " connecting to " [server] ". Address won't be used")
                };
            }

            let mut attempts = 0;
            while !client.is_connected().await {
                if attempts >= 10 {
                    return ERR!("Failed to connect to at least 1 of {:?} in 5 seconds.", servers);
                }

                Timer::sleep(0.5).await;
                attempts += 1;
            }

            let client = Arc::new(client);
            // ping the electrum servers every 30 seconds to prevent them from disconnecting us.
            // according to docs server can do it if there are no messages in ~10 minutes.
            // https://electrumx.readthedocs.io/en/latest/protocol-methods.html?highlight=keep#server-ping
            // weak reference will allow to stop the thread if client is dropped
            let weak_client = Arc::downgrade(&client);
            spawn(async move {
                loop {
                    if let Some(client) = weak_client.upgrade() {
                        if let Err(e) = ElectrumClient(client).server_ping().compat().await {
                            log!("Electrum servers " [servers] " ping error " [e]);
                        }
                    } else {
                        log!("Electrum servers " [servers] " ping loop stopped");
                        break;
                    }
                    Timer::sleep(30.).await
                }
            });
            UtxoRpcClientEnum::Electrum(ElectrumClient(client))
        },
        _ => return ERR!("utxo_arc_from_conf_and_request should be called only by enable or electrum requests"),
    };
    let asset_chain = conf["asset"].as_str().is_some();
    let tx_version = conf["txversion"].as_i64().unwrap_or (1) as i32;
    let overwintered = conf["overwintered"].as_u64().unwrap_or (0) == 1;

    let tx_fee = match conf["txfee"].as_u64() {
        None => TxFee::Fixed(1000),
        Some (0) => {
            let fee_method = match &rpc_client {
                UtxoRpcClientEnum::Electrum(_) => EstimateFeeMethod::Standard,
                UtxoRpcClientEnum::Native(client) => try_s!(client.detect_fee_method().compat().await)
            };
            TxFee::Dynamic(fee_method)
        },
        Some (fee) => TxFee::Fixed(fee),
    };
    let version_group_id = match conf["version_group_id"].as_str() {
        Some(mut s) => {
            if s.starts_with("0x") {
                s = &s[2..];
            }
            let bytes = try_s!(hex::decode(s));
            u32::from_be_bytes(try_s!(bytes.as_slice().try_into()))
        },
        None => if tx_version == 3 && overwintered {
            0x03c48270
        } else if tx_version == 4 && overwintered {
            0x892f2085
        } else {
            0
        }
    };

    let consensus_branch_id = match conf["consensus_branch_id"].as_str() {
        Some(mut s) => {
            if s.starts_with("0x") {
                s = &s[2..];
            }
            let bytes = try_s!(hex::decode(s));
            u32::from_be_bytes(try_s!(bytes.as_slice().try_into()))
        },
        None => {
            match tx_version {
                3 => 0x5ba81b19,
                4 => 0x76b809bb,
                _ => 0,
            }
        },
    };

    let decimals = conf["decimals"].as_u64().unwrap_or (8) as u8;

    let (signature_version, fork_id) = if ticker == "BCH" {
        (SignatureVersion::ForkId, 0x40)
    } else {
        (SignatureVersion::Base, 0)
    };
    // should be sufficient to detect zcash by overwintered flag
    let zcash = overwintered;

    let initial_history_state = if req["tx_history"].as_bool().unwrap_or(false) {
        HistorySyncState::NotStarted
    } else {
        HistorySyncState::NotEnabled
    };

    // param from request should override the config
    let required_confirmations = req["required_confirmations"].as_u64().unwrap_or(
        conf["required_confirmations"].as_u64().unwrap_or(1)
    );
    let requires_notarization = req["requires_notarization"].as_bool().unwrap_or(
        conf["requires_notarization"].as_bool().unwrap_or(false)
    ).into();

    let mature_confirmations = conf["mature_confirmations"].as_u64()
        .map(|x| x as u32)
        .unwrap_or(MATURE_CONFIRMATIONS_DEFAULT);

    let coin = UtxoCoinFields {
        ticker: ticker.into(),
        decimals,
        rpc_client,
        key_pair,
        is_pos: conf["isPoS"].as_u64() == Some(1),
        requires_notarization,
        overwintered,
        pub_addr_prefix,
        p2sh_addr_prefix: conf["p2shtype"].as_u64().unwrap_or (if ticker == "BTC" {5} else {85}) as u8,
        pub_t_addr_prefix: conf["taddr"].as_u64().unwrap_or (0) as u8,
        p2sh_t_addr_prefix: conf["taddr"].as_u64().unwrap_or (0) as u8,
        segwit: conf["segwit"].as_bool().unwrap_or (false),
        wif_prefix,
        tx_version,
        my_address: my_address.clone(),
        asset_chain,
        tx_fee,
        version_group_id,
        consensus_branch_id,
        zcash,
        checksum_type,
        signature_version,
        fork_id,
        history_sync_state: Mutex::new(initial_history_state),
        required_confirmations: required_confirmations.into(),
        force_min_relay_fee: conf["force_min_relay_fee"].as_bool().unwrap_or (false),
        dust_amount,
        mature_confirmations,
    };
    Ok(UtxoArc(Arc::new(coin)))
}

/// Function calculating KMD interest
/// https://komodoplatform.atlassian.net/wiki/spaces/KPSD/pages/71729215/What+is+the+5+Komodo+Stake+Reward
/// https://github.com/KomodoPlatform/komodo/blob/master/src/komodo_interest.h
fn kmd_interest(height: u64, value: u64, lock_time: u64, current_time: u64) -> u64 {
    const KOMODO_ENDOFERA: u64 = 7777777;
    const LOCKTIME_THRESHOLD: u64 = 500000000;
    // value must be at least 10 KMD
    if value < 1000000000 { return 0; }
    // interest will stop accrue after block 7777777
    if height >= KOMODO_ENDOFERA { return 0 };
    // interest doesn't accrue for lock_time < 500000000
    if lock_time < LOCKTIME_THRESHOLD { return 0; }
    // current time must be greater than tx lock_time
    if current_time < lock_time { return 0; }

    let mut minutes = (current_time - lock_time) / 60;
    // at least 1 hour should pass
    if minutes < 60 { return 0; }
    // interest stop accruing after 1 year before block 1000000
    if minutes > 365 * 24 * 60 { minutes = 365 * 24 * 60 };
    // interest stop accruing after 1 month past 1000000 block
    if height >= 1000000 && minutes > 31 * 24 * 60 { minutes = 31 * 24 * 60; }
    // next 2 lines ported as is from Komodo codebase
    minutes -= 59;
    (value / 10512000) * minutes
}

/// Denominate BigDecimal amount of coin units to satoshis
pub fn sat_from_big_decimal(amount: &BigDecimal, decimals: u8) -> Result<u64, String> {
    (amount * BigDecimal::from(10u64.pow(decimals as u32))).to_u64().ok_or(ERRL!("Could not get sat from amount {} with decimals {}", amount, decimals))
}

pub(crate) fn sign_tx(
    unsigned: TransactionInputSigner,
    key_pair: &KeyPair,
    prev_script: Script,
    signature_version: SignatureVersion,
    fork_id: u32,
) -> Result<UtxoTx, String> {
    let mut signed_inputs = vec![];
    for (i, _) in unsigned.inputs.iter().enumerate() {
        signed_inputs.push(
            try_s!(p2pkh_spend(&unsigned, i, key_pair, &prev_script, signature_version, fork_id))
        );
    }
    Ok(UtxoTx {
        inputs: signed_inputs,
        n_time: unsigned.n_time,
        outputs: unsigned.outputs.clone(),
        version: unsigned.version,
        overwintered: unsigned.overwintered,
        lock_time: unsigned.lock_time,
        expiry_height: unsigned.expiry_height,
        join_splits: vec![],
        shielded_spends: vec![],
        shielded_outputs: vec![],
        value_balance: 0,
        version_group_id: unsigned.version_group_id,
        binding_sig: H512::default(),
        join_split_sig: H512::default(),
        join_split_pubkey: H256::default(),
        zcash: unsigned.zcash,
        str_d_zeel: unsigned.str_d_zeel,
    })
}

async fn send_outputs_from_my_address_impl<T>(coin: T, outputs: Vec<TransactionOutput>)
                                              -> Result<UtxoTx, String>
    where T: UtxoArcGetter + UtxoArcCommonOps {
    let _utxo_lock = UTXO_LOCK.lock().await;
    // TODO replace list_unspent_ordered with ordered_mature_unspents
    let unspents = try_s!(coin.arc().rpc_client.list_unspent_ordered(&coin.arc().my_address).map_err(|e| ERRL!("{}", e)).compat().await);
    // TODO check for QRC20
    let (unsigned, _) = try_s!(coin.generate_transaction(unspents, outputs, FeePolicy::SendExact, None, None).await);
    let prev_script = Builder::build_p2pkh(&coin.arc().my_address.hash);
    let signed = try_s!(sign_tx(unsigned, &coin.arc().key_pair, prev_script, coin.arc().signature_version, coin.arc().fork_id));
    try_s!(coin.arc().rpc_client.send_transaction(&signed, coin.arc().my_address.clone()).map_err(|e| ERRL!("{}", e)).compat().await);
    Ok(signed)
}

/// Creates signed input spending p2pkh output
fn p2pkh_spend(
    signer: &TransactionInputSigner,
    input_index: usize,
    key_pair: &KeyPair,
    prev_script: &Script,
    signature_version: SignatureVersion,
    fork_id: u32,
) -> Result<TransactionInput, String> {
    let script = Builder::build_p2pkh(&key_pair.public().address_hash());
    if script != *prev_script {
        return ERR!("p2pkh script {} built from input key pair doesn't match expected prev script {}", script, prev_script);
    }
    let sighash_type = 1 | fork_id;
    let sighash = signer.signature_hash(input_index, signer.inputs[input_index].amount, &script, signature_version, sighash_type);

    let script_sig = try_s!(script_sig_with_pub(&sighash, key_pair, fork_id));

    Ok(TransactionInput {
        script_sig,
        sequence: signer.inputs[input_index].sequence,
        script_witness: vec![],
        previous_output: signer.inputs[input_index].previous_output.clone(),
    })
}

fn script_sig_with_pub(message: &H256, key_pair: &KeyPair, fork_id: u32) -> Result<Bytes, String> {
    let sig_script = try_s!(script_sig(message, key_pair, fork_id));

    let builder = Builder::default();

    Ok(builder
        .push_data(&sig_script)
        .push_data(&key_pair.public().to_vec())
        .into_bytes())
}

fn script_sig(message: &H256, key_pair: &KeyPair, fork_id: u32) -> Result<Bytes, String> {
    let signature = try_s!(key_pair.private().sign(message));

    let mut sig_script = Bytes::default();
    sig_script.append(&mut Bytes::from((*signature).to_vec()));
    // Using SIGHASH_ALL only for now
    sig_script.append(&mut Bytes::from(vec![1 | fork_id as u8]));

    Ok(sig_script)
}
