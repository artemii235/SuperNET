use crate::utxo::rpc_clients::UtxoRpcClientEnum;
use crate::utxo::utxo_common::payment_script;
use crate::utxo::{utxo_common::UtxoArcBuilder, UtxoArc, UtxoCoinBuilder};
use crate::{BalanceFut, CoinBalance, FoundSwapTxSpend, MarketCoinOps, NegotiateSwapContractAddrErr, SwapOps,
            TransactionEnum, TransactionFut};
use bitcrypto::dhash160;
use chain::constants::SEQUENCE_FINAL;
use chain::Transaction as UtxoTx;
use common::mm_ctx::MmArc;
use common::mm_error::prelude::*;
use common::mm_number::{BigDecimal, MmNumber};
use futures::compat::Future01CompatExt;
use futures::{FutureExt, TryFutureExt};
use futures01::Future;
use keys::Public;
use rpc::v1::types::Bytes as BytesJson;
use script::{Builder as ScriptBuilder, Opcode};
use secp256k1_bindings::SecretKey;
use serde_json::Value as Json;
use serialization::deserialize;
use zcash_client_backend::encoding::encode_payment_address;
use zcash_primitives::{consensus,
                       constants::mainnet as z_mainnet_constants,
                       legacy::Script as ZCashScript,
                       sapling::PaymentAddress,
                       transaction::builder::Builder as ZTxBuilder,
                       transaction::components::{Amount, OutPoint as ZCashOutpoint, TxOut},
                       zip32::ExtendedSpendingKey};
use zcash_proofs::prover::LocalTxProver;

mod z_htlc;
use z_htlc::z_send_htlc;

mod z_rpc;
use z_rpc::ZRpcOps;

#[cfg(test)] mod z_coin_tests;

#[derive(Clone, Debug)]
pub struct ZCoin {
    utxo_arc: UtxoArc,
    z_spending_key: ExtendedSpendingKey,
    z_addr: PaymentAddress,
}

impl ZCoin {
    pub fn z_rpc(&self) -> &(dyn ZRpcOps + Send + Sync) { self.utxo_arc.rpc_client.as_ref() }

    pub fn rpc_client(&self) -> &UtxoRpcClientEnum { &self.utxo_arc.rpc_client }
}

#[derive(Debug)]
pub enum ZCoinBuildError {
    BuilderError(String),
    GetAddressError,
}

pub async fn z_coin_from_conf_and_request(
    ctx: &MmArc,
    ticker: &str,
    conf: &Json,
    req: &Json,
    secp_priv_key: &[u8],
    z_spending_key: ExtendedSpendingKey,
) -> Result<ZCoin, MmError<ZCoinBuildError>> {
    let builder = UtxoArcBuilder::new(ctx, ticker, conf, req, secp_priv_key);
    let utxo_arc = builder
        .build()
        .await
        .map_err(|e| MmError::new(ZCoinBuildError::BuilderError(e)))?;

    let (_, z_addr) = z_spending_key
        .default_address()
        .map_err(|_| MmError::new(ZCoinBuildError::GetAddressError))?;
    Ok(ZCoin {
        utxo_arc,
        z_spending_key,
        z_addr,
    })
}

impl MarketCoinOps for ZCoin {
    fn ticker(&self) -> &str { todo!() }

    fn my_address(&self) -> Result<String, String> { todo!() }

    fn my_balance(&self) -> BalanceFut<CoinBalance> {
        let my_address = encode_payment_address(z_mainnet_constants::HRP_SAPLING_PAYMENT_ADDRESS, &self.z_addr);
        let min_conf = 0;
        let fut = self
            .utxo_arc
            .rpc_client
            .as_ref()
            .z_get_balance(&my_address, min_conf)
            // at the moment Z coins do not have an unspendable balance
            .map(|spendable| CoinBalance {
                spendable: spendable.to_decimal(),
                unspendable: BigDecimal::from(0),
            })
            .map_err(|e| e.into());
        Box::new(fut)
    }

    fn base_coin_balance(&self) -> BalanceFut<BigDecimal> { todo!() }

    fn send_raw_tx(&self, _tx: &str) -> Box<dyn Future<Item = String, Error = String> + Send> { todo!() }

    fn wait_for_confirmations(
        &self,
        _tx: &[u8],
        _confirmations: u64,
        _requires_nota: bool,
        _wait_until: u64,
        _check_every: u64,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        todo!()
    }

    fn wait_for_tx_spend(
        &self,
        _transaction: &[u8],
        _wait_until: u64,
        _from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        todo!()
    }

    fn tx_enum_from_bytes(&self, _bytes: &[u8]) -> Result<TransactionEnum, String> { todo!() }

    fn current_block(&self) -> Box<dyn Future<Item = u64, Error = String> + Send> { todo!() }

    fn address_from_pubkey_str(&self, _pubkey: &str) -> Result<String, String> { todo!() }

    fn display_priv_key(&self) -> String { todo!() }

    fn min_tx_amount(&self) -> BigDecimal { todo!() }

    fn min_trading_vol(&self) -> MmNumber { todo!() }
}

impl SwapOps for ZCoin {
    fn send_taker_fee(&self, _fee_addr: &[u8], _amount: BigDecimal) -> TransactionFut { todo!() }

    fn send_maker_payment(
        &self,
        time_lock: u32,
        taker_pub: &[u8],
        secret_hash: &[u8],
        amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        let selfi = self.clone();
        let taker_pub = taker_pub.to_vec();
        let secret_hash = secret_hash.to_vec();
        let fut = async move {
            let utxo_tx = try_s!(z_send_htlc(&selfi, time_lock, &taker_pub, &secret_hash, amount).await);
            Ok(utxo_tx.into())
        };
        Box::new(fut.boxed().compat())
    }

    fn send_taker_payment(
        &self,
        time_lock: u32,
        maker_pub: &[u8],
        secret_hash: &[u8],
        amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        let selfi = self.clone();
        let maker_pub = maker_pub.to_vec();
        let secret_hash = secret_hash.to_vec();
        let fut = async move {
            let utxo_tx = try_s!(z_send_htlc(&selfi, time_lock, &maker_pub, &secret_hash, amount).await);
            Ok(utxo_tx.into())
        };
        Box::new(fut.boxed().compat())
    }

    fn send_maker_spends_taker_payment(
        &self,
        _taker_payment_tx: &[u8],
        _time_lock: u32,
        _taker_pub: &[u8],
        _secret: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        todo!()
    }

    fn send_taker_spends_maker_payment(
        &self,
        maker_payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        secret: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        let tx: UtxoTx = deserialize(maker_payment_tx).unwrap();
        let secret_hash = dhash160(secret);
        let redeem_script = payment_script(
            time_lock,
            &*secret_hash,
            &Public::from_slice(maker_pub).unwrap(),
            self.utxo_arc.key_pair.public(),
        )
        .to_vec();

        let script_data = ScriptBuilder::default()
            .push_data(secret)
            .push_opcode(Opcode::OP_0)
            .into_bytes();
        let selfi = self.clone();
        let fut = async move {
            let current_block = try_s!(selfi.utxo_arc.rpc_client.get_block_count().compat().await) as u32;
            let mut tx_builder = ZTxBuilder::new(consensus::MAIN_NETWORK, current_block.into());

            let secp_secret = SecretKey::from_slice(&*selfi.utxo_arc.key_pair.private().secret).unwrap();

            let outpoint = ZCashOutpoint::new(tx.hash().into(), 0);
            let tx_out = TxOut {
                value: Amount::from_u64(tx.outputs[0].value).unwrap(),
                script_pubkey: ZCashScript(redeem_script.clone()),
            };
            tx_builder
                .add_transparent_input(
                    secp_secret,
                    outpoint,
                    SEQUENCE_FINAL,
                    ZCashScript(script_data.take()),
                    tx_out,
                )
                .unwrap();
            tx_builder
                .add_sapling_output(
                    None,
                    selfi.z_addr,
                    Amount::from_u64(tx.outputs[0].value - 1000).unwrap(),
                    None,
                )
                .unwrap();
            let prover = LocalTxProver::bundled();
            let (zcash_tx, _) = tx_builder.build(consensus::BranchId::Sapling, &prover).unwrap();
            let mut tx_buffer = Vec::with_capacity(1024);
            zcash_tx.write(&mut tx_buffer).unwrap();
            let spend_tx: UtxoTx = deserialize(tx_buffer.as_slice()).expect("librustzcash should produce a valid tx");
            try_s!(
                selfi
                    .utxo_arc
                    .rpc_client
                    .send_raw_transaction(tx_buffer.into())
                    .compat()
                    .await
            );
            Ok(spend_tx.into())
        };
        Box::new(fut.boxed().compat())
    }

    fn send_taker_refunds_payment(
        &self,
        _taker_payment_tx: &[u8],
        _time_lock: u32,
        _maker_pub: &[u8],
        _secret_hash: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        todo!()
    }

    fn send_maker_refunds_payment(
        &self,
        maker_payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        secret_hash: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        let tx: UtxoTx = deserialize(maker_payment_tx).unwrap();
        let redeem_script = payment_script(
            time_lock,
            secret_hash,
            self.utxo_arc.key_pair.public(),
            &Public::from_slice(taker_pub).unwrap(),
        )
        .to_vec();
        let selfi = self.clone();
        let fut = async move {
            let current_block = try_s!(selfi.utxo_arc.rpc_client.get_block_count().compat().await) as u32;
            let mut tx_builder = ZTxBuilder::new(consensus::MAIN_NETWORK, current_block.into());
            tx_builder.set_lock_time(time_lock);

            let secp_secret = SecretKey::from_slice(&*selfi.utxo_arc.key_pair.private().secret).unwrap();

            let outpoint = ZCashOutpoint::new(tx.hash().into(), 0);
            let tx_out = TxOut {
                value: Amount::from_u64(tx.outputs[0].value).unwrap(),
                script_pubkey: ZCashScript(redeem_script.clone()),
            };
            let script_data = ScriptBuilder::default().push_opcode(Opcode::OP_1).into_bytes();
            tx_builder
                .add_transparent_input(
                    secp_secret,
                    outpoint,
                    SEQUENCE_FINAL - 1,
                    ZCashScript(script_data.take()),
                    tx_out,
                )
                .unwrap();
            tx_builder
                .add_sapling_output(
                    None,
                    selfi.z_addr,
                    Amount::from_u64(tx.outputs[0].value - 1000).unwrap(),
                    None,
                )
                .unwrap();
            let prover = LocalTxProver::bundled();
            let (zcash_tx, _) = tx_builder.build(consensus::BranchId::Sapling, &prover).unwrap();
            let mut tx_buffer = Vec::with_capacity(1024);
            zcash_tx.write(&mut tx_buffer).unwrap();
            let refund_tx: UtxoTx = deserialize(tx_buffer.as_slice()).expect("librustzcash should produce a valid tx");
            try_s!(
                selfi
                    .utxo_arc
                    .rpc_client
                    .send_raw_transaction(tx_buffer.into())
                    .compat()
                    .await
            );
            Ok(refund_tx.into())
        };
        Box::new(fut.boxed().compat())
    }

    fn validate_fee(
        &self,
        _fee_tx: &TransactionEnum,
        _expected_sender: &[u8],
        _fee_addr: &[u8],
        _amount: &BigDecimal,
        _min_block_number: u64,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        todo!()
    }

    fn validate_maker_payment(
        &self,
        _payment_tx: &[u8],
        _time_lock: u32,
        _maker_pub: &[u8],
        _priv_bn_hash: &[u8],
        _amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        todo!()
    }

    fn validate_taker_payment(
        &self,
        _payment_tx: &[u8],
        _time_lock: u32,
        _taker_pub: &[u8],
        _priv_bn_hash: &[u8],
        _amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        todo!()
    }

    fn check_if_my_payment_sent(
        &self,
        _time_lock: u32,
        _other_pub: &[u8],
        _secret_hash: &[u8],
        _search_from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Box<dyn Future<Item = Option<TransactionEnum>, Error = String> + Send> {
        todo!()
    }

    fn search_for_swap_tx_spend_my(
        &self,
        _time_lock: u32,
        _other_pub: &[u8],
        _secret_hash: &[u8],
        _tx: &[u8],
        _search_from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        todo!()
    }

    fn search_for_swap_tx_spend_other(
        &self,
        _time_lock: u32,
        _other_pub: &[u8],
        _secret_hash: &[u8],
        _tx: &[u8],
        _search_from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        todo!()
    }

    fn extract_secret(&self, _secret_hash: &[u8], _spend_tx: &[u8]) -> Result<Vec<u8>, String> { todo!() }

    fn negotiate_swap_contract_addr(
        &self,
        _other_side_address: Option<&[u8]>,
    ) -> Result<Option<BytesJson>, MmError<NegotiateSwapContractAddrErr>> {
        Ok(None)
    }
}

#[test]
fn derive_z_key_from_mm_seed() {
    use common::privkey::key_pair_from_seed;
    use zcash_client_backend::encoding::encode_extended_spending_key;

    let seed = "spice describe gravity federal blast come thank unfair canal monkey style afraid";
    let secp_keypair = key_pair_from_seed(seed).unwrap();
    let z_spending_key = ExtendedSpendingKey::master(&*secp_keypair.private().secret);
    let encoded = encode_extended_spending_key(z_mainnet_constants::HRP_SAPLING_EXTENDED_SPENDING_KEY, &z_spending_key);
    assert_eq!(encoded, "secret-extended-key-main1qqqqqqqqqqqqqqytwz2zjt587n63kyz6jawmflttqu5rxavvqx3lzfs0tdr0w7g5tgntxzf5erd3jtvva5s52qx0ms598r89vrmv30r69zehxy2r3vesghtqd6dfwdtnauzuj8u8eeqfx7qpglzu6z54uzque6nzzgnejkgq569ax4lmk0v95rfhxzxlq3zrrj2z2kqylx2jp8g68lqu6alczdxd59lzp4hlfuj3jp54fp06xsaaay0uyass992g507tdd7psua5w6q76dyq3");

    let (_, address) = z_spending_key.default_address().unwrap();
    let encoded_addr = encode_payment_address(z_mainnet_constants::HRP_SAPLING_PAYMENT_ADDRESS, &address);
    assert_eq!(
        encoded_addr,
        "zs182ht30wnnnr8jjhj2j9v5dkx3qsknnr5r00jfwk2nczdtqy7w0v836kyy840kv2r8xle5gcl549"
    );
}
