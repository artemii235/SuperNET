use async_trait::async_trait;
use bigdecimal::BigDecimal;
use chain::{Transaction, TransactionOutput};
use common::mm_ctx::MmArc;
use common::mm_number::MmNumber;
use common::jsonrpc_client::{JsonRpcClient, JsonRpcRequest, JsonRpcError, RpcRes};
use crate::{HistorySyncState, FoundSwapTxSpend, MarketCoinOps, MmCoin, SwapOps, TradeFee, TradeInfo,
            TransactionDetails, TransactionEnum, TransactionFut, WithdrawFee, WithdrawRequest};
use crate::eth::{ERC20_CONTRACT, u256_to_big_decimal, wei_from_big_decimal};
use crate::utxo::{sign_tx, utxo_arc_from_conf_and_request, ActualTxFee, AdditionalTxData, FeePolicy, UtxoArc, UtxoArcCommonOps, UtxoArcGetter, UtxoCoinCommonOps, UtxoMmCoin, VerboseTransactionFrom, UtxoFeeDetails, UTXO_LOCK};
use crate::utxo::utxo_common;
use crate::utxo::rpc_clients::{ElectrumClient, UnspentInfo, UtxoRpcClientEnum};
use ethabi::Token;
use ethereum_types::{H160, U256};
use futures::{TryFutureExt, FutureExt};
use futures01::future::Future;
use futures::compat::Future01CompatExt;
use gstuff::now_ms;
use keys::{Address, Public};
use primitives::bytes::Bytes;
use rpc::v1::types::{Bytes as BytesJson, H160 as H160Json, H256 as H256Json, Transaction as RpcTransaction};
use script::{Builder, Opcode, Script, TransactionInputSigner};
use serde_json::{self as json, Value as Json};
use serialization::serialize;
use std::borrow::Cow;
use std::str::FromStr;

const QTUM_MATURE_CONFIRMATIONS: u32 = 500;
const QRC20_GAS_LIMIT_DEFAULT: u64 = 250_000;
const QRC20_GAS_PRICE_DEFAULT: u64 = 40;
const QRC20_DUST: u64 = 0;

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct TokenInfo {
    name: String,
    decimals: u8,
    total_supply: u64,
    symbol: String,
}

#[derive(Debug, Deserialize)]
pub struct ExecutionResult {
    pub output: BytesJson,
}

#[derive(Debug, Deserialize)]
pub struct ContractCallResult {
    address: H160Json,
    #[serde(rename = "executionResult")]
    pub execution_result: ExecutionResult,
}

/// QTUM specific RPC ops
pub trait QtumRpcOps {
    fn blockchain_token_get_info(&self, token_addr: &H160Json) -> RpcRes<TokenInfo>;

    fn blockchain_contract_call(&self, contract_addr: &H160Json, data: BytesJson) -> RpcRes<ContractCallResult>;
}

impl QtumRpcOps for ElectrumClient {
    fn blockchain_token_get_info(&self, token_addr: &H160Json) -> RpcRes<TokenInfo> {
        rpc_func!(self, "blockchain.token.get_info", token_addr)
    }

    //
    fn blockchain_contract_call(&self, contract_addr: &H160Json, data: BytesJson) -> RpcRes<ContractCallResult> {
        let sender = "";
        rpc_func!(self, "blockchain.contract.call", contract_addr, data, sender)
    }
}

pub async fn qrc20_coin_from_conf_and_request(
    ticker: &str,
    conf: &Json,
    req: &Json,
    priv_key: &[u8],
    contract_address: H160,
) -> Result<Qrc20Coin, String> {
    let inner = try_s!(utxo_arc_from_conf_and_request(ticker, conf, req, priv_key, QRC20_DUST).await);
    Ok(Qrc20Coin { utxo_arc: inner, contract_address })
}

#[derive(Clone, Debug)]
pub struct Qrc20Coin {
    pub utxo_arc: UtxoArc,
    pub contract_address: H160,
}

impl UtxoArcGetter for Qrc20Coin {
    fn arc(&self) -> &UtxoArc {
        &self.utxo_arc
    }
}

#[async_trait]
impl UtxoCoinCommonOps for Qrc20Coin {
    async fn get_tx_fee(&self) -> Result<ActualTxFee, JsonRpcError> {
        utxo_common::get_tx_fee(&self.utxo_arc).await
    }

    async fn get_htlc_spend_fee(&self) -> Result<u64, String> {
        utxo_common::get_htlc_spend_fee(self).await
    }

    fn addresses_from_script(&self, script: &Script) -> Result<Vec<Address>, String> {
        utxo_common::addresses_from_script(&self.utxo_arc, script)
    }

    fn denominate_satoshis(&self, satoshi: i64) -> f64 {
        utxo_common::denominate_satoshis(&self.utxo_arc, satoshi)
    }

    fn search_for_swap_tx_spend(
        &self,
        time_lock: u32,
        first_pub: &Public,
        second_pub: &Public,
        secret_hash: &[u8],
        tx: &[u8],
        search_from_block: u64)
        -> Result<Option<FoundSwapTxSpend>, String> {
        utxo_common::search_for_swap_tx_spend(
            &self.utxo_arc,
            time_lock,
            first_pub,
            second_pub,
            secret_hash,
            tx,
            search_from_block)
    }

    fn my_public_key(&self) -> &Public {
        self.utxo_arc.key_pair.public()
    }
}

#[async_trait]
impl UtxoArcCommonOps for Qrc20Coin {
    fn send_outputs_from_my_address(&self, outputs: Vec<TransactionOutput>) -> TransactionFut {
        utxo_common::send_outputs_from_my_address(self.clone(), outputs)
    }

    fn validate_payment(
        &self,
        payment_tx: &[u8],
        time_lock: u32,
        first_pub0: &Public,
        second_pub0: &Public,
        priv_bn_hash: &[u8],
        amount: BigDecimal)
        -> Box<dyn Future<Item=(), Error=String> + Send> {
        utxo_common::validate_payment(
            self.utxo_arc.clone(),
            payment_tx,
            time_lock,
            first_pub0,
            second_pub0,
            priv_bn_hash,
            amount)
    }

    async fn generate_transaction(
        &self,
        utxos: Vec<UnspentInfo>,
        outputs: Vec<TransactionOutput>,
        fee_policy: FeePolicy,
        fee: Option<ActualTxFee>,
        gas_fee: Option<u64>)
        -> Result<(TransactionInputSigner, AdditionalTxData), String> {
        utxo_common::generate_transaction(
            self,
            utxos,
            outputs,
            fee_policy,
            fee,
            gas_fee).await
    }

    async fn calc_interest_if_required(
        &self,
        unsigned: TransactionInputSigner,
        data: AdditionalTxData,
        my_script_pub: Bytes)
        -> Result<(TransactionInputSigner, AdditionalTxData), String> {
        utxo_common::calc_interest_if_required(
            &self.utxo_arc,
            unsigned,
            data,
            my_script_pub).await
    }

    fn p2sh_spending_tx(
        &self,
        prev_transaction: Transaction,
        redeem_script: Bytes,
        outputs: Vec<TransactionOutput>,
        script_data: Script,
        sequence: u32)
        -> Result<Transaction, String> {
        utxo_common::p2sh_spending_tx(
            &self.utxo_arc,
            prev_transaction,
            redeem_script,
            outputs,
            script_data,
            sequence)
    }
}

impl SwapOps for Qrc20Coin {
    fn send_taker_fee(&self, fee_addr: &[u8], amount: BigDecimal) -> TransactionFut {
        utxo_common::send_taker_fee(self, fee_addr, amount)
    }

    fn send_maker_payment(&self, time_lock: u32, taker_pub: &[u8], secret_hash: &[u8], amount: BigDecimal) -> TransactionFut {
        utxo_common::send_maker_payment(self.clone(), time_lock, taker_pub, secret_hash, amount)
    }

    fn send_taker_payment(&self, time_lock: u32, maker_pub: &[u8], secret_hash: &[u8], amount: BigDecimal) -> TransactionFut {
        utxo_common::send_taker_payment(self.clone(), time_lock, maker_pub, secret_hash, amount)
    }

    fn send_maker_spends_taker_payment(
        &self, taker_payment_tx: &[u8], time_lock: u32, taker_pub: &[u8], secret: &[u8])
        -> TransactionFut {
        utxo_common::send_maker_spends_taker_payment(
            self.clone(), taker_payment_tx, time_lock, taker_pub, secret)
    }

    fn send_taker_spends_maker_payment(
        &self, maker_payment_tx: &[u8], time_lock: u32, maker_pub: &[u8], secret: &[u8])
        -> TransactionFut {
        utxo_common::send_taker_spends_maker_payment(
            self.clone(), maker_payment_tx, time_lock, maker_pub, secret)
    }

    fn send_taker_refunds_payment(
        &self, taker_payment_tx: &[u8], time_lock: u32, maker_pub: &[u8], secret_hash: &[u8])
        -> TransactionFut {
        utxo_common::send_taker_refunds_payment(
            self.clone(), taker_payment_tx, time_lock, maker_pub, secret_hash)
    }

    fn send_maker_refunds_payment(
        &self, maker_payment_tx: &[u8], time_lock: u32, taker_pub: &[u8], secret_hash: &[u8])
        -> TransactionFut {
        utxo_common::send_maker_refunds_payment(
            self.clone(), maker_payment_tx, time_lock, taker_pub, secret_hash)
    }

    fn validate_fee(&self, fee_tx: &TransactionEnum, fee_addr: &[u8], amount: &BigDecimal)
                    -> Box<dyn Future<Item=(), Error=String> + Send> {
        utxo_common::validate_fee(self.utxo_arc.clone(), fee_tx, fee_addr, amount)
    }

    fn validate_maker_payment(
        &self, payment_tx: &[u8], time_lock: u32, maker_pub: &[u8], priv_bn_hash: &[u8], amount: BigDecimal)
        -> Box<dyn Future<Item=(), Error=String> + Send> {
        utxo_common::validate_maker_payment(self, payment_tx, time_lock, maker_pub, priv_bn_hash, amount)
    }

    fn validate_taker_payment(
        &self, payment_tx: &[u8], time_lock: u32, taker_pub: &[u8], priv_bn_hash: &[u8], amount: BigDecimal)
        -> Box<dyn Future<Item=(), Error=String> + Send> {
        utxo_common::validate_taker_payment(
            self, payment_tx, time_lock, taker_pub, priv_bn_hash, amount)
    }

    fn check_if_my_payment_sent(
        &self, time_lock: u32, other_pub: &[u8], secret_hash: &[u8], search_from_block: u64)
        -> Box<dyn Future<Item=Option<TransactionEnum>, Error=String> + Send> {
        utxo_common::check_if_my_payment_sent(
            self.clone(), time_lock, other_pub, secret_hash, search_from_block)
    }

    fn search_for_swap_tx_spend_my(
        &self, time_lock: u32, other_pub: &[u8], secret_hash: &[u8], tx: &[u8], search_from_block: u64)
        -> Result<Option<FoundSwapTxSpend>, String> {
        utxo_common::search_for_swap_tx_spend_my(
            self, time_lock, other_pub, secret_hash, tx, search_from_block)
    }

    fn search_for_swap_tx_spend_other(
        &self, time_lock: u32, other_pub: &[u8], secret_hash: &[u8], tx: &[u8], search_from_block: u64)
        -> Result<Option<FoundSwapTxSpend>, String> {
        utxo_common::search_for_swap_tx_spend_other(
            self, time_lock, other_pub, secret_hash, tx, search_from_block)
    }
}

impl MarketCoinOps for Qrc20Coin {
    fn ticker(&self) -> &str {
        &self.utxo_arc.ticker
    }

    fn my_address(&self) -> Cow<str> {
        utxo_common::my_address(&self.utxo_arc)
    }

    fn my_balance(&self) -> Box<dyn Future<Item=BigDecimal, Error=String> + Send> {
        let function = unwrap!(ERC20_CONTRACT.function("balanceOf"));
        let params = unwrap!(function.encode_input(&[
                    Token::Address(self.utxo_arc.my_address.hash.clone().take().into()),
        ]));
        match self.utxo_arc.rpc_client {
            UtxoRpcClientEnum::Electrum(ref electrum) => {
                Box::new(electrum
                    .blockchain_contract_call(&self.contract_address.to_vec().as_slice().into(), params.into())
                    .map_err(|e| ERRL!("{}", e))
                    .and_then(move |balance: ContractCallResult| function.decode_output(&balance.execution_result.output)
                        .map_err(|e| ERRL!("{}", e)))
                    .and_then(|tokens| match tokens[0] {
                        Token::Uint(bal) => Ok(bal),
                        _ => Err(ERRL!("Expected Uint, got {:?}", tokens[0])),
                    })
                    .and_then(|balance| u256_to_big_decimal(balance, 8)))
            }
            _ => Box::new(futures01::future::err(ERRL!("Electrum client expected"))),
        }
    }

    fn send_raw_tx(&self, tx: &str) -> Box<dyn Future<Item=String, Error=String> + Send> {
        utxo_common::send_raw_tx(&self.utxo_arc, tx)
    }

    fn wait_for_confirmations(&self, tx: &[u8], confirmations: u64, requires_nota: bool, wait_until: u64, check_every: u64)
                              -> Box<dyn Future<Item=(), Error=String> + Send> {
        utxo_common::wait_for_confirmations(&self.utxo_arc, tx, confirmations, requires_nota, wait_until, check_every)
    }

    fn wait_for_tx_spend(&self, transaction: &[u8], wait_until: u64, from_block: u64) -> TransactionFut {
        utxo_common::wait_for_tx_spend(&self.utxo_arc, transaction, wait_until, from_block)
    }

    fn tx_enum_from_bytes(&self, bytes: &[u8]) -> Result<TransactionEnum, String> {
        utxo_common::tx_enum_from_bytes(bytes)
    }

    fn current_block(&self) -> Box<dyn Future<Item=u64, Error=String> + Send> {
        utxo_common::current_block(&self.utxo_arc)
    }

    fn address_from_pubkey_str(&self, pubkey: &str) -> Result<String, String> {
        utxo_common::address_from_pubkey_str(&self.utxo_arc, pubkey)
    }

    fn display_priv_key(&self) -> String {
        utxo_common::display_priv_key(&self.utxo_arc)
    }
}

impl MmCoin for Qrc20Coin {
    fn is_asset_chain(&self) -> bool {
        utxo_common::is_asset_chain(&self.utxo_arc)
    }

    fn check_i_have_enough_to_trade(&self, amount: &MmNumber, balance: &MmNumber, trade_info: TradeInfo)
                                    -> Box<dyn Future<Item=(), Error=String> + Send> {
        utxo_common::check_i_have_enough_to_trade(self.clone(), amount, balance, trade_info)
    }

    fn can_i_spend_other_payment(&self) -> Box<dyn Future<Item=(), Error=String> + Send> {
        utxo_common::can_i_spend_other_payment()
    }

    fn withdraw(&self, ctx: &MmArc, req: WithdrawRequest) -> Box<dyn Future<Item=TransactionDetails, Error=String> + Send> {
        Box::new(qrc20_withdraw(self.clone(), ctx.clone(), req).boxed().compat())
    }

    fn decimals(&self) -> u8 {
        utxo_common::decimals(&self.utxo_arc)
    }

    fn process_history_loop(&self, ctx: MmArc) {
        utxo_common::process_history_loop(self, ctx)
    }

    fn tx_details_by_hash(&self, hash: &[u8]) -> Box<dyn Future<Item=TransactionDetails, Error=String> + Send> {
        utxo_common::tx_details_by_hash(self.clone(), hash)
    }

    fn history_sync_status(&self) -> HistorySyncState {
        utxo_common::history_sync_status(&self.utxo_arc)
    }

    fn get_trade_fee(&self) -> Box<dyn Future<Item=TradeFee, Error=String> + Send> {
        utxo_common::get_trade_fee(self.clone())
    }

    fn required_confirmations(&self) -> u64 {
        utxo_common::required_confirmations(&self.utxo_arc)
    }

    fn requires_notarization(&self) -> bool {
        utxo_common::requires_notarization(&self.utxo_arc)
    }

    fn set_required_confirmations(&self, confirmations: u64) {
        utxo_common::set_required_confirmations(&self.utxo_arc, confirmations)
    }

    fn set_requires_notarization(&self, requires_nota: bool) {
        utxo_common::set_requires_notarization(&self.utxo_arc, requires_nota)
    }
}

#[async_trait]
impl UtxoMmCoin for Qrc20Coin {
    async fn ordered_mature_unspents(&self, ctx: &MmArc, address: &Address) -> Result<Vec<UnspentInfo>, String> {
        qtum_ordered_mature_unspents(self, ctx, address).await
    }

    async fn get_verbose_transaction_from_cache_or_rpc(&self, ctx: &MmArc, txid: H256Json) -> Result<VerboseTransactionFrom, String> {
        utxo_common::get_verbose_transaction_from_cache_or_rpc(self, ctx, txid).await
    }
}

async fn qrc20_withdraw(coin: Qrc20Coin, ctx: MmArc, req: WithdrawRequest) -> Result<TransactionDetails, String> {
    let to_addr = try_s!(Address::from_str(&req.to));

    let is_p2pkh = to_addr.prefix == coin.arc().pub_addr_prefix && to_addr.t_addr_prefix == coin.arc().pub_t_addr_prefix;
    let is_p2sh = to_addr.prefix == coin.arc().p2sh_addr_prefix && to_addr.t_addr_prefix == coin.arc().p2sh_t_addr_prefix && coin.arc().segwit;
    if !is_p2pkh && !is_p2sh {
        return ERR!("Address {} has invalid format", to_addr);
    }

    let _utxo_lock = UTXO_LOCK.lock().await;

    // the qrc20_amount is used only within smart contract calls
    let qrc20_amount = if req.max {
        let balance = try_s!(coin.my_balance().compat().await);
        try_s!(wei_from_big_decimal(&balance, coin.arc().decimals))
    } else {
        try_s!(wei_from_big_decimal(&req.amount, coin.arc().decimals))
    };

    let (gas_limit, gas_price) = match req.fee {
        Some(WithdrawFee::Qrc20Gas { gas_limit, gas_price }) => (gas_limit, gas_price),
        Some(_) => return ERR!("Unsupported input fee type"),
        None => (QRC20_GAS_LIMIT_DEFAULT, QRC20_GAS_PRICE_DEFAULT),
    };

    let script_pubkey = try_s!(generate_token_transfer_script_pubkey(
        to_addr.clone(), qrc20_amount, gas_limit, gas_price, &coin.contract_address)).to_bytes();

    // qtum_amount is always 0 for the QRC20, because we should pay only a fee in Qtum to send the QRC20 transaction
    let qtum_amount = 0u64;
    let outputs = vec![TransactionOutput {
        value: qtum_amount,
        script_pubkey,
    }];

    let unspents = try_s!(coin.ordered_mature_unspents(&ctx, &coin.arc().my_address).await.map_err(|e| ERRL!("{}", e)));

    // None seems that the generate_transaction() should request estimated fee for Kbyte
    let actual_tx_fee = None;
    let gas_fee = Some(gas_limit * gas_price);
    let fee_policy = FeePolicy::SendExact;

    let (unsigned, data) = try_s!(coin.generate_transaction(unspents, outputs, fee_policy, actual_tx_fee, gas_fee).await);
    let prev_script = Builder::build_p2pkh(&coin.arc().my_address.hash);
    let signed = try_s!(sign_tx(unsigned, &coin.arc().key_pair, prev_script, coin.arc().signature_version, coin.arc().fork_id));
    let fee_details = UtxoFeeDetails {
        amount: utxo_common::big_decimal_from_sat(data.fee_amount as i64, coin.arc().decimals),
    };
    Ok(TransactionDetails {
        from: vec![coin.arc().my_address.to_string()],
        to: vec![format!("{}", to_addr)],
        total_amount: utxo_common::big_decimal_from_sat(data.spent_by_me as i64, coin.arc().decimals),
        spent_by_me: utxo_common::big_decimal_from_sat(data.spent_by_me as i64, coin.arc().decimals),
        received_by_me: utxo_common::big_decimal_from_sat(data.received_by_me as i64, coin.arc().decimals),
        my_balance_change: utxo_common::big_decimal_from_sat(data.received_by_me as i64 - data.spent_by_me as i64, coin.arc().decimals),
        tx_hash: signed.hash().reversed().to_vec().into(),
        tx_hex: serialize(&signed).into(),
        fee_details: Some(fee_details.into()),
        block_height: 0,
        coin: coin.arc().ticker.clone(),
        internal_id: vec![].into(),
        timestamp: now_ms() / 1000,
    })
}

/// Serialize the `number` similar to BigEndian but in QRC20 specific format.
fn contract_encode_number(number: i64) -> Vec<u8> {
    // | encoded number (0 - 8 bytes) |
    // therefore the max result vector length is 8
    let capacity = 8;
    let mut encoded = Vec::with_capacity(capacity);

    if number == 0 {
        return Vec::new();
    }

    let is_negative = number.is_negative();
    let mut absnum = (number as i128).abs();

    while absnum != 0 {
        // absnum & 0xFF is first lowest byte
        encoded.push((absnum & 0xFF) as u8);
        absnum >>= 8;
    }

    if (encoded.last().unwrap() & 0x80) != 0 {
        encoded.push({ if is_negative { 0x80 } else { 0 } });
    } else if is_negative {
        *encoded.last_mut().unwrap() |= 0x80;
    }

    encoded
}

fn generate_token_transfer_script_pubkey(
    to_addr: Address,
    amount: U256,
    gas_limit: u64,
    gas_price: u64,
    token_addr: &[u8],
) -> Result<Script, String> {
    // AP
    // TODO we should recheck whether Qtum allows to set gas price to zero
    // it is actually valid situation for ETH, such transactions even get mined
    // sometimes: https://etherscan.io/tx/0x4f719da4e138bd8ab929f4110e84d773b57376b37d1c635d26cd263d65da99cb
    // https://medium.com/chainsecurity/zero-gas-price-transactions-what-they-do-who-creates-them-and-why-they-might-impact-scalability-aeb6487b8bb0
    // I suspect that there might be an implementation error in contract_encode_number function in
    // qtum electrum wallet.
    if gas_limit == 0 || gas_price == 0 {
        // this is because the `contract_encode_number` will return an empty bytes
        return ERR!("gas_limit and gas_price cannot be zero");
    }

    if token_addr.is_empty() {
        // this is because the `push_bytes` will panic
        return ERR!("token_addr cannot be empty");
    }

    let gas_limit = contract_encode_number(gas_limit as i64);
    let gas_price = contract_encode_number(gas_price as i64);

    let function = try_s!(ERC20_CONTRACT.function("transfer"));
    let function_call = try_s!(function.encode_input(&[
        Token::Address(to_addr.hash.take().into()),
        Token::Uint(amount)
    ]));

    Ok(Builder::default()
        .push_opcode(Opcode::OP_4)
        .push_bytes(&gas_limit)
        .push_bytes(&gas_price)
        .push_bytes(&function_call)
        .push_bytes(token_addr)
        .push_opcode(Opcode::OP_CALL)
        .into_script())
}

fn can_spend_output(output: &RpcTransaction) -> bool {
    let is_qrc20_coinbase = output.vout.iter().find(|x| x.is_empty()).is_some();
    !is_qrc20_coinbase || output.confirmations >= QTUM_MATURE_CONFIRMATIONS
}

async fn qtum_ordered_mature_unspents<T>(coin: &T, ctx: &MmArc, address: &Address) -> Result<Vec<UnspentInfo>, String>
    where T: UtxoArcGetter + UtxoMmCoin {
    let unspents = try_s!(coin.arc().rpc_client.list_unspent_ordered(address).compat().await);
    let block_count = try_s!(coin.arc().rpc_client.get_block_count().compat().await);

    let mut result = Vec::with_capacity(unspents.len());
    for unspent in unspents {
        let tx_hash: H256Json = unspent.outpoint.hash.reversed().into();
        let tx_info = match coin.get_verbose_transaction_from_cache_or_rpc(ctx, tx_hash.clone()).await {
            Ok(x) => x,
            Err(err) => {
                log!("Error " [err] " getting the transaction " [tx_hash] ", skip the unspent output");
                continue;
            }
        };

        let tx_info = match tx_info {
            VerboseTransactionFrom::Cache(mut tx) => {
                if tx.height.is_none() {
                    tx.height = unspent.height;
                }
                if let Some(tx_height) = tx.height {
                    // refresh confirmations for the cached transaction:
                    // use the up-to-date block_count and tx_height.
                    tx.confirmations = (block_count - tx_height + 1) as u32;
                    assert_ne!(tx.confirmations, 0);
                } else {
                    // else do not skip the transaction with unknown height,
                    // because the transaction may be old enough (tx.confirmations > QTUM_MATURE_CONFIRMATIONS)
                    log!("Warning, unknown transaction (" [tx_hash] ") height");
                }

                tx
            }
            VerboseTransactionFrom::Rpc(tx) => {
                if tx.confirmations == 0 {
                    log!("Skip not mined transaction "[tx_hash]);
                    continue;
                }
                tx
            }
        };

        if can_spend_output(&tx_info) {
            result.push(unspent);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod qtum_tests {
    use crate::{
        eth::u256_to_big_decimal,
        utxo::utxo_tests::electrum_client_for_test,
    };
    use ethabi::Token;
    use keys::Address;
    use rpc::v1::types::{ScriptType, SignedTransactionOutput, TransactionOutputScript};
    use super::*;

    #[test]
    fn blockchain_token_get_info() {
        let client = electrum_client_for_test(&["95.217.83.126:10001"]);
        let addr = hex::decode("d362e096e873eb7907e205fadc6175c6fec7bc44").unwrap();
        let expected_token_info = TokenInfo {
            name: "TEST".into(),
            decimals: 8,
            total_supply: 1000000000000000,
            symbol: "ARTEM".into(),
        };

        let actual_token_info = client.blockchain_token_get_info(&addr.as_slice().into()).wait().unwrap();
        assert_eq!(expected_token_info, actual_token_info);
    }

    #[test]
    fn get_token_balance_using_contract_call() {
        let client = electrum_client_for_test(&["95.217.83.126:10001"]);
        let token_addr = hex::decode("d362e096e873eb7907e205fadc6175c6fec7bc44").unwrap();
        let our_addr: Address = "qKEDGuogDhtH9zBnc71QtqT1KDamaR1KJ3".parse().unwrap();
        log!((our_addr.prefix));
        let function = unwrap!(ERC20_CONTRACT.function("balanceOf"));
        let data = unwrap!(function.encode_input(&[
            Token::Address(our_addr.hash.take().into()),
        ]));
        let balance = client.blockchain_contract_call(&token_addr.as_slice().into(), data.into()).wait().unwrap();
        let tokens = function.decode_output(&balance.execution_result.output).unwrap();
        let balance = match tokens[0] {
            Token::Uint(bal) => bal,
            _ => panic!("Expected Uint, got {:?}", tokens[0]),
        };
        let balance = u256_to_big_decimal(balance, 8).unwrap();
        assert_eq!(balance, "139.00000".parse().unwrap());
    }

    #[test]
    fn test_generate_token_transfer_script_pubkey() {
        // sample QRC20 transfer from https://testnet.qtum.info/tx/51e9cec885d7eb26271f8b1434c000f6cf07aad47671268fc8d36cee9d48f6de
        // the script is a script_pubkey of one of the transaction output
        let expected: Script = "5403a02526012844a9059cbb0000000000000000000000000240b898276ad2cc0d2fe6f527e8e31104e7fde3000000000000000000000000000000000000000000000000000000003b9aca0014d362e096e873eb7907e205fadc6175c6fec7bc44c2".into();
        let to_addr = "qHmJ3KA6ZAjR9wGjpFASn4gtUSeFAqdZgs".into();
        let amount: U256 = 1000000000.into();
        let gas_limit = 2_500_000;
        let gas_price = 40;
        let token_addr = hex::decode("d362e096e873eb7907e205fadc6175c6fec7bc44").unwrap();
        let actual = generate_token_transfer_script_pubkey(
            to_addr,
            amount,
            gas_limit,
            gas_price,
            &token_addr,
        ).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_generate_token_transfer_script_pubkey_err() {
        let to_addr: Address = "qHmJ3KA6ZAjR9wGjpFASn4gtUSeFAqdZgs".into();
        let amount: U256 = 1000000000.into();
        let gas_limit = 2_500_000;
        let gas_price = 40;
        let token_addr = hex::decode("d362e096e873eb7907e205fadc6175c6fec7bc44").unwrap();

        assert!(generate_token_transfer_script_pubkey(
            to_addr.clone(),
            amount,
            0, // gas_limit cannot be zero
            gas_price,
            &token_addr,
        ).is_err());

        assert!(generate_token_transfer_script_pubkey(
            to_addr.clone(),
            amount,
            gas_limit,
            0, // gas_price cannot be zero
            &token_addr,
        ).is_err());

        assert!(generate_token_transfer_script_pubkey(
            to_addr,
            amount,
            gas_limit,
            gas_price,
            &[], // token_addr cannot be empty
        ).is_err());
    }

    #[test]
    fn test_number_serialize() {
        let numbers = vec![
            // left is source number, right is expected encoded array
            (0i64, vec![]),
            (1, vec![1]),
            (-1, vec![129]),
            (40, vec![40]),
            (-40, vec![168]),
            (-127, vec![255]),
            (127, vec![127]),
            (-128, vec![128, 128]),
            (128, vec![128, 0]),
            (255, vec![255, 0]),
            (-255, vec![255, 128]),
            (256, vec![0, 1]),
            (-256, vec![0, 129]),
            (2500000, vec![160, 37, 38]),
            (-2500000, vec![160, 37, 166]),
            (i64::max_value(), vec![255, 255, 255, 255, 255, 255, 255, 127]),
            (i64::min_value(), vec![0, 0, 0, 0, 0, 0, 0, 128, 128]),
            (Opcode::OP_4 as i64, vec![84]),
            (Opcode::OP_CALL as i64, vec![194, 0]),
        ];

        for (actual, expected) in numbers {
            assert_eq!(contract_encode_number(actual), expected);
        }
    }

    #[test]
    fn test_can_spend_output() {
        let mut tx = RpcTransaction {
            hex: Default::default(),
            txid: "47d983175720ba2a67f36d0e1115a129351a2f340bdde6ecb6d6029e138fe920".into(),
            hash: None,
            size: Default::default(),
            vsize: Default::default(),
            version: 2,
            locktime: 0,
            vin: vec![],
            vout: vec![
                // empty output
                SignedTransactionOutput {
                    value: 0.,
                    n: 0,
                    script: TransactionOutputScript {
                        asm: "".into(),
                        hex: "".into(),
                        req_sigs: 0,
                        script_type: ScriptType::NonStandard,
                        addresses: vec![],
                    },
                },
                SignedTransactionOutput {
                    value: 117.02430015,
                    n: 1,
                    script: TransactionOutputScript {
                        asm: "03e71b9c152bb233ddfe58f20056715c51b054a1823e0aba108e6f1cea0ceb89c8 OP_CHECKSIG".into(),
                        hex: "2103e71b9c152bb233ddfe58f20056715c51b054a1823e0aba108e6f1cea0ceb89c8ac".into(),
                        req_sigs: 0,
                        script_type: ScriptType::PubKey,
                        addresses: vec![],
                    },
                },
            ],
            blockhash: "c23882939ff695be36546ea998eb585e962b043396e4d91959477b9796ceb9e1".into(),
            confirmations: 421,
            rawconfirmations: None,
            time: 1590671504,
            blocktime: 1590671504,
            height: None,
        };

        // output is coinbase and has confirmations < QTUM_MATURE_CONFIRMATIONS
        assert_eq!(can_spend_output(&tx), false);

        tx.confirmations = 501;
        // output is coinbase but has confirmations > QTUM_MATURE_CONFIRMATIONS
        assert!(can_spend_output(&tx));

        tx.confirmations = 421;
        // remove empty output
        tx.vout.remove(0);
        // output is not coinbase
        assert!(can_spend_output(&tx));
    }
}
