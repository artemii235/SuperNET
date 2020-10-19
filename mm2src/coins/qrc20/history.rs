use super::*;
use crate::utxo::UtxoFeeDetails;
use crate::TxFeeDetails;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use swap_ops::ContractCallType;

#[derive(Clone, Debug, PartialEq)]
struct TxInternalId {
    tx_hash: H256Json,
    output_index: i64,
    log_index: i64,
}

impl TxInternalId {
    pub fn new(tx_hash: H256Json, output_index: i64, log_index: i64) -> TxInternalId {
        TxInternalId {
            tx_hash,
            output_index,
            log_index,
        }
    }

    pub fn from_bytes(bytes: &BytesJson) -> Result<TxInternalId, String> {
        // H256(32 bytes) + output_index(8 bytes) + log_index(8 bytes)
        const EXPECTED_LEN: usize = 32 + 8 + 8;

        if bytes.len() != EXPECTED_LEN {
            return ERR!("Incorrect bytes len {}, expected {}", bytes.len(), EXPECTED_LEN);
        }

        let tx_hash: H256Json = bytes[0..32].into();

        let buf = bytes[32..].to_vec();
        let mut cursor = Cursor::new(buf);
        let output_index = cursor.read_i64::<BigEndian>().unwrap();
        let log_index = cursor.read_i64::<BigEndian>().unwrap();

        Ok(TxInternalId {
            tx_hash,
            output_index,
            log_index,
        })
    }
}

impl From<TxInternalId> for BytesJson {
    fn from(id: TxInternalId) -> Self {
        let mut bytes = id.tx_hash.0.to_vec();
        bytes
            .write_i64::<BigEndian>(id.output_index)
            .expect("Error on write_i64");
        bytes.write_i64::<BigEndian>(id.log_index).expect("Error on write_i64");
        bytes.into()
    }
}

impl Qrc20Coin {
    pub async fn transfer_details_by_hash(&self, tx_hash: H256Json) -> Result<Vec<TransactionDetails>, String> {
        let electrum = match self.utxo.rpc_client {
            UtxoRpcClientEnum::Electrum(ref rpc) => rpc,
            UtxoRpcClientEnum::Native(_) => return ERR!("Electrum client expected"),
        };
        let receipts = try_s!(electrum.blochchain_transaction_get_receipt(&tx_hash).compat().await);
        // request Qtum transaction details to get a tx_hex, timestamp, block_height and calculate a miner_fee
        let qtum_details = try_s!(utxo_common::tx_details_by_hash(self, &tx_hash.0).await);
        // Deserialize the UtxoTx to get a script pubkey
        let qtum_tx: UtxoTx = try_s!(deserialize(qtum_details.tx_hex.as_slice()).map_err(|e| ERRL!("{:?}", e)));

        let miner_fee = {
            let total_qtum_fee = match qtum_details.fee_details {
                Some(TxFeeDetails::Utxo(UtxoFeeDetails { ref amount })) => amount.clone(),
                Some(ref fee) => return ERR!("Unexpected fee details {:?}", fee),
                None => return ERR!("No Qtum fee details"),
            };
            let total_gas_used = receipts.iter().fold(0, |gas, receipt| gas + receipt.gas_used);
            let total_gas_used = big_decimal_from_sat(total_gas_used, self.utxo.decimals);
            total_qtum_fee - total_gas_used
        };

        let mut details = Vec::new();
        for receipt in receipts {
            let log_details =
                try_s!(self.transfer_details_from_receipt(&qtum_tx, &qtum_details, receipt, miner_fee.clone()));
            details.extend(log_details.into_iter())
        }

        Ok(details)
    }

    fn transfer_details_from_receipt(
        &self,
        qtum_tx: &UtxoTx,
        qtum_details: &TransactionDetails,
        receipt: TxReceipt,
        miner_fee: BigDecimal,
    ) -> Result<Vec<TransactionDetails>, String> {
        let tx_hash: H256Json = qtum_details.tx_hash.as_slice().into();
        if qtum_tx.outputs.len() <= (receipt.output_index as usize) {
            return ERR!(
                "Length of the transaction {:?} outputs less than output_index {}",
                tx_hash,
                receipt.output_index
            );
        }
        let script_pubkey: Script = qtum_tx.outputs[receipt.output_index as usize]
            .script_pubkey
            .clone()
            .into();
        let fee_details = {
            let gas_limit = try_s!(extract_gas_from_script(&script_pubkey, ExtractGasEnum::GasLimit));
            let gas_price = try_s!(extract_gas_from_script(&script_pubkey, ExtractGasEnum::GasPrice));

            let total_gas_fee = utxo_common::big_decimal_from_sat(receipt.gas_used, self.utxo.decimals);
            Qrc20FeeDetails {
                // QRC20 fees are paid in base platform currency (particular in Qtum)
                coin: self.platform.clone(),
                miner_fee,
                gas_limit,
                gas_price,
                total_gas_fee,
            }
        };

        let mut details = Vec::with_capacity(receipt.log.len());
        for (log_index, log_entry) in receipt.log.into_iter().enumerate() {
            if log_entry.topics.len() != 3 {
                continue;
            }
            // the first topic should be ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
            // https://github.com/qtumproject/qtum-electrum/blob/v4.0.2/electrum/wallet.py#L2101
            if log_entry.topics[0] != QRC20_TRANSFER_TOPIC {
                continue;
            }
            if try_s!(log_entry.parse_address()) != self.contract_address {
                continue;
            }

            let (total_amount, from, to) = {
                let (amount, from, to) = try_s!(transfer_event_from_log(&log_entry));
                let amount = try_s!(u256_to_big_decimal(amount, self.decimals()));
                let from = self.utxo_address_from_qrc20(from);
                let to = self.utxo_address_from_qrc20(to);
                (amount, from, to)
            };

            // https://github.com/qtumproject/qtum-electrum/blob/v4.0.2/electrum/wallet.py#L2102
            if from != self.utxo.my_address && to != self.utxo.my_address {
                log!("Address mismatch");
                continue;
            }

            let spent_by_me = if from == self.utxo.my_address {
                total_amount.clone()
            } else {
                0.into()
            };
            let received_by_me = if to == self.utxo.my_address {
                total_amount.clone()
            } else {
                0.into()
            };

            // do not inherit the block_height from qtum_tx (usually it is None)
            let block_height = receipt.block_number as u64;
            let my_balance_change = &received_by_me - &spent_by_me;
            let internal_id = TxInternalId::new(tx_hash.clone(), receipt.output_index, log_index as i64).into();

            let from = if is_sender_contract(&script_pubkey) {
                display_contract_address(from)
            } else {
                try_s!(self.display_address(&from))
            };

            let to = if is_receiver_contract(&script_pubkey) {
                display_contract_address(to)
            } else {
                try_s!(self.display_address(&to))
            };

            details.push(TransactionDetails {
                from: vec![from],
                to: vec![to],
                total_amount,
                spent_by_me,
                received_by_me,
                my_balance_change,
                block_height,
                fee_details: Some(fee_details.clone().into()),
                internal_id,
                ..qtum_details.clone()
            })
        }

        Ok(details)
    }
}

fn is_sender_contract(script_pubkey: &Script) -> bool {
    let contract_call_bytes = match extract_contract_call_from_script(&script_pubkey) {
        Ok(bytes) => bytes,
        Err(e) => {
            log!((e));
            return false;
        },
    };
    let call_type = match ContractCallType::from_script_pubkey(&contract_call_bytes) {
        Ok(Some(t)) => t,
        Ok(None) => return false,
        Err(e) => {
            log!((e));
            return false;
        },
    };
    match call_type {
        ContractCallType::Transfer => false,
        ContractCallType::Erc20Payment => false,
        ContractCallType::ReceiverSpend => true,
        ContractCallType::SenderRefund => true,
    }
}

fn is_receiver_contract(script_pubkey: &Script) -> bool {
    let contract_call_bytes = match extract_contract_call_from_script(&script_pubkey) {
        Ok(bytes) => bytes,
        Err(e) => {
            log!((e));
            return false;
        },
    };
    let call_type = match ContractCallType::from_script_pubkey(&contract_call_bytes) {
        Ok(Some(t)) => t,
        Ok(None) => return false,
        Err(e) => {
            log!((e));
            return false;
        },
    };
    match call_type {
        ContractCallType::Transfer => false,
        ContractCallType::Erc20Payment => true,
        ContractCallType::ReceiverSpend => false,
        ContractCallType::SenderRefund => false,
    }
}

fn display_contract_address(address: UtxoAddress) -> String {
    let address = qrc20_addr_from_utxo_addr(address);
    format!("{:#02x}", address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_internal_id() {
        let tx_hash = hex::decode("39104d29d77ba83c5c6c63ab7a0f096301c443b4538dc6b30140453a40caa80a").unwrap();
        let expected_id = TxInternalId::new(tx_hash.as_slice().into(), 13, 257);
        let actual_bytes: BytesJson = expected_id.clone().into();

        let mut expected_bytes = tx_hash.clone();
        expected_bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 13]);
        expected_bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 1]);
        assert_eq!(actual_bytes, expected_bytes.into());

        let actual_id = TxInternalId::from_bytes(&actual_bytes).unwrap();
        assert_eq!(actual_id, expected_id);
    }
}
