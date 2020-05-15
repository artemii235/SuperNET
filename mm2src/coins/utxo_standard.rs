use async_trait::async_trait;
use bigdecimal::BigDecimal;
use chain::{TransactionOutput, Transaction};
use common::jsonrpc_client::JsonRpcError;
use common::mm_ctx::MmArc;
use common::mm_number::MmNumber;
use crate::{HistorySyncState, FoundSwapTxSpend, MarketCoinOps, MmCoin, SwapOps, TradeFee, TradeInfo,
            TransactionDetails, TransactionEnum, TransactionFut, WithdrawRequest};
use crate::utxo::{ActualTxFee, AdditionalTxData, FeePolicy, UtxoArc, UtxoArcCommonOps,
                  utxo_arc_from_conf_and_request, UtxoCoinCommonOps};
use crate::utxo::utxo_common;
use crate::utxo::rpc_clients::UnspentInfo;
use futures01::Future;
use keys::{Address, Public};
use primitives::bytes::Bytes;
use script::{Script, TransactionInputSigner};
use serde_json::Value as Json;
use std::borrow::Cow;
use std::ops::Deref;

#[derive(Clone, Debug)]
pub struct UtxoStandardCoin(UtxoArc);

impl Deref for UtxoStandardCoin {
    type Target = UtxoArc;
    fn deref(&self) -> &UtxoArc { &self.0 }
}

impl From<UtxoArc> for UtxoStandardCoin {
    fn from(coin: UtxoArc) -> UtxoStandardCoin {
        UtxoStandardCoin(coin)
    }
}

impl From<UtxoStandardCoin> for UtxoArc {
    fn from(coin: UtxoStandardCoin) -> Self {
        coin.0
    }
}

pub async fn utxo_standard_coin_from_conf_and_request(
    ticker: &str,
    conf: &Json,
    req: &Json,
    priv_key: &[u8],
) -> Result<UtxoStandardCoin, String> {
    let inner = try_s!(utxo_arc_from_conf_and_request(ticker, conf, req, priv_key).await);
    Ok(UtxoStandardCoin(inner))
}

#[async_trait]
impl UtxoCoinCommonOps for UtxoStandardCoin {
    async fn get_tx_fee(&self) -> Result<ActualTxFee, JsonRpcError> {
        utxo_common::get_tx_fee(&self).await
    }

    async fn get_htlc_spend_fee(&self) -> Result<u64, String> {
        utxo_common::get_htlc_spend_fee(self).await
    }

    fn addresses_from_script(&self, script: &Script) -> Result<Vec<Address>, String> {
        utxo_common::addresses_from_script(&self, script)
    }

    fn denominate_satoshis(&self, satoshi: i64) -> f64 {
        utxo_common::denominate_satoshis(&self, satoshi)
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
            &self,
            time_lock,
            first_pub,
            second_pub,
            secret_hash,
            tx,
            search_from_block)
    }

    fn my_public_key(&self) -> &Public {
        self.key_pair.public()
    }
}

#[async_trait]
impl UtxoArcCommonOps for UtxoStandardCoin {
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
            self.0.clone(),
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
        fee: Option<ActualTxFee>)
        -> Result<(TransactionInputSigner, AdditionalTxData), String> {
        utxo_common::generate_transaction(
            self,
            utxos,
            outputs,
            fee_policy,
            fee).await
    }

    async fn calc_interest_if_required(
        &self,
        unsigned: TransactionInputSigner,
        data: AdditionalTxData,
        my_script_pub: Bytes)
        -> Result<(TransactionInputSigner, AdditionalTxData), String> {
        utxo_common::calc_interest_if_required(
            &self,
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
            &self,
            prev_transaction,
            redeem_script,
            outputs,
            script_data,
            sequence)
    }
}

impl SwapOps for UtxoStandardCoin {
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
        utxo_common::validate_fee(self.0.clone(), fee_tx, fee_addr, amount)
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
            self.0.clone(), time_lock, other_pub, secret_hash, search_from_block)
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

impl MarketCoinOps for UtxoStandardCoin {
    fn ticker(&self) -> &str {
        &self.ticker
    }

    fn my_address(&self) -> Cow<str> {
        utxo_common::my_address(&self)
    }

    fn my_balance(&self) -> Box<dyn Future<Item=BigDecimal, Error=String> + Send> {
        utxo_common::my_balance(&self)
    }

    fn send_raw_tx(&self, tx: &str) -> Box<dyn Future<Item=String, Error=String> + Send> {
        utxo_common::send_raw_tx(&self, tx)
    }

    fn wait_for_confirmations(&self, tx: &[u8], confirmations: u64, requires_nota: bool, wait_until: u64, check_every: u64)
                              -> Box<dyn Future<Item=(), Error=String> + Send> {
        utxo_common::wait_for_confirmations(&self, tx, confirmations, requires_nota, wait_until, check_every)
    }

    fn wait_for_tx_spend(&self, transaction: &[u8], wait_until: u64, from_block: u64) -> TransactionFut {
        utxo_common::wait_for_tx_spend(&self, transaction, wait_until, from_block)
    }

    fn tx_enum_from_bytes(&self, bytes: &[u8]) -> Result<TransactionEnum, String> {
        utxo_common::tx_enum_from_bytes(bytes)
    }

    fn current_block(&self) -> Box<dyn Future<Item=u64, Error=String> + Send> {
        utxo_common::current_block(&self)
    }

    fn address_from_pubkey_str(&self, pubkey: &str) -> Result<String, String> {
        utxo_common::address_from_pubkey_str(&self, pubkey)
    }

    fn display_priv_key(&self) -> String {
        utxo_common::display_priv_key(&self)
    }
}

impl MmCoin for UtxoStandardCoin {
    fn is_asset_chain(&self) -> bool {
        utxo_common::is_asset_chain(&self)
    }

    fn check_i_have_enough_to_trade(&self, amount: &MmNumber, balance: &MmNumber, trade_info: TradeInfo)
                                    -> Box<dyn Future<Item=(), Error=String> + Send> {
        utxo_common::check_i_have_enough_to_trade(self.clone(), amount, balance, trade_info)
    }

    fn can_i_spend_other_payment(&self) -> Box<dyn Future<Item=(), Error=String> + Send> {
        utxo_common::can_i_spend_other_payment()
    }

    fn withdraw(&self, req: WithdrawRequest) -> Box<dyn Future<Item=TransactionDetails, Error=String> + Send> {
        utxo_common::withdraw(self.clone(), req)
    }

    fn decimals(&self) -> u8 {
        utxo_common::decimals(&self)
    }

    fn process_history_loop(&self, ctx: MmArc) {
        utxo_common::process_history_loop(self, ctx)
    }

    fn tx_details_by_hash(&self, hash: &[u8]) -> Box<dyn Future<Item=TransactionDetails, Error=String> + Send> {
        utxo_common::tx_details_by_hash(self.clone(), hash)
    }

    fn history_sync_status(&self) -> HistorySyncState {
        utxo_common::history_sync_status(&self)
    }

    fn get_trade_fee(&self) -> Box<dyn Future<Item=TradeFee, Error=String> + Send> {
        utxo_common::get_trade_fee(self.clone())
    }

    fn required_confirmations(&self) -> u64 {
        utxo_common::required_confirmations(&self)
    }

    fn requires_notarization(&self) -> bool {
        utxo_common::requires_notarization(&self)
    }

    fn set_required_confirmations(&self, confirmations: u64) {
        utxo_common::set_required_confirmations(&self, confirmations)
    }

    fn set_requires_notarization(&self, requires_nota: bool) {
        utxo_common::set_requires_notarization(&self, requires_nota)
    }
}
