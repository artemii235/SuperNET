use super::z_rpc::{ZOperationStatus, ZOperationTxid, ZSendManyItem};
use super::ZCoin;
use crate::utxo::rpc_clients::UtxoRpcError;
use crate::utxo::utxo_common::payment_script;
use bigdecimal::BigDecimal;
use bitcrypto::dhash160;
use chain::Transaction as UtxoTx;
use common::executor::Timer;
use common::mm_error::prelude::*;
use derive_more::Display;
use futures::compat::Future01CompatExt;
use keys::{Address, Error as KeysError, Public};
use serialization::deserialize;
use zcash_client_backend::encoding::encode_payment_address;
use zcash_primitives::constants::mainnet as z_mainnet_constants;

#[derive(Debug, Display)]
#[allow(clippy::large_enum_variant)]
pub enum ZSendHtlcError {
    ParseOtherPubFailed(KeysError),
    #[display(fmt = "z operation failed with statuses {:?}", _0)]
    ZOperationFailed(Vec<ZOperationStatus<ZOperationTxid>>),
    ZOperationStatusesEmpty,
    RpcError(UtxoRpcError),
}

impl From<KeysError> for ZSendHtlcError {
    fn from(keys: KeysError) -> ZSendHtlcError { ZSendHtlcError::ParseOtherPubFailed(keys) }
}

impl From<UtxoRpcError> for ZSendHtlcError {
    fn from(rpc: UtxoRpcError) -> ZSendHtlcError { ZSendHtlcError::RpcError(rpc) }
}

pub async fn z_send_htlc(
    coin: &ZCoin,
    time_lock: u32,
    other_pub: &[u8],
    secret_hash: &[u8],
    amount: BigDecimal,
) -> Result<UtxoTx, MmError<ZSendHtlcError>> {
    let taker_pub = Public::from_slice(other_pub).map_to_mm(ZSendHtlcError::from)?;
    let payment_script = payment_script(time_lock, secret_hash, coin.utxo_arc.key_pair.public(), &taker_pub);
    let hash = dhash160(&payment_script);
    let htlc_address = Address {
        prefix: coin.utxo_arc.conf.p2sh_addr_prefix,
        t_addr_prefix: coin.utxo_arc.conf.p2sh_t_addr_prefix,
        hash,
        checksum_type: coin.utxo_arc.conf.checksum_type,
    };

    let from_addr = encode_payment_address(z_mainnet_constants::HRP_SAPLING_PAYMENT_ADDRESS, &coin.z_addr);
    let send_item = ZSendManyItem {
        amount,
        op_return: Some(payment_script.to_vec().into()),
        address: htlc_address.to_string(),
    };

    let op_id = coin.z_rpc().z_send_many(&from_addr, vec![send_item]).compat().await?;

    loop {
        let operation_statuses = coin.z_rpc().z_get_send_many_status(&[&op_id]).compat().await?;

        match operation_statuses.first() {
            Some(ZOperationStatus::Executing { .. }) => {
                Timer::sleep(1.).await;
                continue;
            },
            Some(ZOperationStatus::Failed { .. }) => {
                break Err(MmError::new(ZSendHtlcError::ZOperationFailed(operation_statuses)));
            },
            Some(ZOperationStatus::Success { result, .. }) => {
                let tx_bytes = coin
                    .rpc_client()
                    .get_transaction_bytes(result.txid.clone())
                    .compat()
                    .await?;
                let tx: UtxoTx = deserialize(tx_bytes.0.as_slice()).expect("rpc returns valid tx bytes");
                break Ok(tx);
            },
            None => break Err(MmError::new(ZSendHtlcError::ZOperationStatusesEmpty)),
        }
    }
}
