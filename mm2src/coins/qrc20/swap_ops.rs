use super::*;
use crate::qrc20::history::HistoryOrder;
use common::lazy::FindMapLazy;
use history::HistoryBuilder;
use script_pubkey::{extract_contract_call_from_script, extract_token_addr_from_script, is_contract_call};

/// `erc20Payment` call details consist of values obtained from [`TransactionOutput::script_pubkey`] and [`TxReceipt::logs`].
#[derive(Debug, Eq, PartialEq)]
pub struct Erc20PaymentDetails {
    pub output_index: i64,
    pub swap_id: Vec<u8>,
    pub value: U256,
    pub token_address: H160,
    pub swap_contract_address: H160,
    pub sender: H160,
    pub receiver: H160,
    pub secret_hash: Vec<u8>,
    pub timelock: U256,
}

/// `receiverSpend` call details consist of values obtained from [`TransactionOutput::script_pubkey`].
#[derive(Debug)]
pub struct ReceiverSpendDetails {
    pub swap_id: Vec<u8>,
    pub value: U256,
    pub secret: Vec<u8>,
    pub token_address: H160,
    pub sender: H160,
}

impl Qrc20Coin {
    pub async fn send_hash_time_locked_payment(
        &self,
        id: Vec<u8>,
        value: U256,
        time_lock: u32,
        secret_hash: Vec<u8>,
        receiver_addr: H160,
    ) -> Result<TransactionEnum, String> {
        let allowance = try_s!(self.allowance(self.swap_contract_address).await);

        let mut outputs = Vec::default();
        // check if we should reset the allowance to 0 and raise this to the max available value (our balance)
        if allowance < value {
            let balance = try_s!(self.my_balance().compat().await);
            let balance = try_s!(wei_from_big_decimal(&balance, self.utxo.decimals));
            if allowance > U256::zero() {
                // first reset the allowance to the 0
                outputs.push(try_s!(self.approve_output(self.swap_contract_address, 0.into())));
            }
            // set the allowance from 0 to `balance` after the previous output will be executed
            outputs.push(try_s!(self.approve_output(self.swap_contract_address, balance)));
        }

        // when this output is executed, the allowance will be sufficient allready
        outputs.push(try_s!(self.erc20_payment_output(
            id,
            value,
            time_lock,
            &secret_hash,
            receiver_addr
        )));

        self.send_contract_calls(outputs).await
    }

    pub async fn spend_hash_time_locked_payment(
        &self,
        payment_tx: UtxoTx,
        secret: Vec<u8>,
    ) -> Result<TransactionEnum, String> {
        let Erc20PaymentDetails {
            swap_id, value, sender, ..
        } = try_s!(self.erc20_payment_details_from_tx(&payment_tx).await);

        let status = try_s!(self.payment_status(swap_id.clone()).await);
        if status != PAYMENT_STATE_SENT.into() {
            return ERR!("Payment state is not PAYMENT_STATE_SENT, got {}", status);
        }

        let spend_output = try_s!(self.receiver_spend_output(swap_id, value, secret, sender));
        self.send_contract_calls(vec![spend_output]).await
    }

    pub async fn refund_hash_time_locked_payment(&self, payment_tx: UtxoTx) -> Result<TransactionEnum, String> {
        let Erc20PaymentDetails {
            swap_id,
            value,
            receiver,
            secret_hash,
            ..
        } = try_s!(self.erc20_payment_details_from_tx(&payment_tx).await);

        let status = try_s!(self.payment_status(swap_id.clone()).await);
        if status != PAYMENT_STATE_SENT.into() {
            return ERR!("Payment state is not PAYMENT_STATE_SENT, got {}", status);
        }

        let refund_output = try_s!(self.sender_refund_output(swap_id, value, secret_hash, receiver));
        self.send_contract_calls(vec![refund_output]).await
    }

    pub async fn validate_payment(
        &self,
        payment_tx: UtxoTx,
        time_lock: u32,
        sender: H160,
        secret_hash: Vec<u8>,
        amount: BigDecimal,
    ) -> Result<(), String> {
        let erc20_payment = try_s!(self.erc20_payment_details_from_tx(&payment_tx).await);

        let expected_swap_id = qrc20_swap_id(time_lock, &secret_hash);
        if erc20_payment.swap_id != expected_swap_id {
            return ERR!(
                "Invalid 'swap_id' {:?} in swap payment, expected {:?}",
                erc20_payment.swap_id,
                expected_swap_id
            );
        }

        if sender != erc20_payment.sender {
            return ERR!("Payment tx was sent from wrong address, expected {:?}", sender);
        }

        if self.swap_contract_address != erc20_payment.swap_contract_address {
            return ERR!(
                "Payment tx was sent to wrong address, expected {:?}",
                self.swap_contract_address
            );
        }

        let expected_value = try_s!(wei_from_big_decimal(&amount, self.utxo.decimals));
        if expected_value != erc20_payment.value {
            return ERR!(
                "Invalid 'value' {:?} in swap payment, expected {:?}",
                erc20_payment.value,
                expected_value
            );
        }

        if self.contract_address != erc20_payment.token_address {
            return ERR!(
                "Invalid 'token_address' {:?} in swap payment, expected {:?}",
                erc20_payment.token_address,
                self.contract_address
            );
        }

        let expected_receiver = qrc20_addr_from_utxo_addr(self.utxo.my_address.clone());
        if expected_receiver != erc20_payment.receiver {
            return ERR!(
                "Invalid 'receiver' {:?} in swap payment, expected {:?}",
                erc20_payment.receiver,
                expected_receiver
            );
        }

        if secret_hash != erc20_payment.secret_hash {
            return ERR!(
                "Invalid 'secret_hash' {:?} in swap payment, expected {:?}",
                erc20_payment.secret_hash,
                secret_hash
            );
        }

        let expected_timelock = U256::from(time_lock);
        if expected_timelock != erc20_payment.timelock {
            return ERR!(
                "Invalid 'timelock' {:?} in swap payment, expected {:?}",
                erc20_payment.timelock,
                expected_timelock
            );
        }

        Ok(())
    }

    pub async fn validate_fee_impl(
        &self,
        fee_tx_hash: H256Json,
        fee_addr: H160,
        expected_value: U256,
    ) -> Result<(), String> {
        let verbose_tx = match self.utxo.rpc_client {
            UtxoRpcClientEnum::Electrum(ref rpc) => try_s!(rpc.get_verbose_transaction(fee_tx_hash).compat().await),
            UtxoRpcClientEnum::Native(_) => return ERR!("Electrum client expected"),
        };
        let qtum_tx: UtxoTx = try_s!(deserialize(verbose_tx.hex.as_slice()).map_err(|e| ERRL!("{:?}", e)));

        // The transaction could not being mined, just check the transfer tokens.
        let output = qtum_tx
            .outputs
            .first()
            .ok_or(ERRL!("Provided dex fee tx {:?} has no outputs", qtum_tx))?;
        let script_pubkey: Script = output.script_pubkey.clone().into();

        let (receiver, value) = match transfer_call_details_from_script_pubkey(&script_pubkey) {
            Ok((rec, val)) => (rec, val),
            Err(e) => return ERR!("Provided dex fee tx {:?} is incorrect: {}", qtum_tx, e),
        };

        if receiver != fee_addr {
            return ERR!(
                "QRC20 Fee tx was sent to wrong address {:?}, expected {:?}",
                receiver,
                fee_addr
            );
        }

        if value < expected_value {
            return ERR!("QRC20 Fee tx value {} is less than expected {}", value, expected_value);
        }

        let token_addr = try_s!(extract_token_addr_from_script(&script_pubkey));
        if token_addr != self.contract_address {
            return ERR!(
                "QRC20 Fee tx {:?} called wrong smart contract, expected {:?}",
                qtum_tx,
                self.contract_address
            );
        }

        Ok(())
    }

    pub async fn search_for_swap_tx_spend(
        &self,
        time_lock: u32,
        secret_hash: Vec<u8>,
        tx: UtxoTx,
        search_from_block: u64,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        let electrum = match self.utxo.rpc_client {
            UtxoRpcClientEnum::Electrum(ref rpc_cln) => rpc_cln,

            UtxoRpcClientEnum::Native(_) => {
                return ERR!("Native mode not supported");
            },
        };

        let tx_hash = tx.hash().reversed().into();
        let verbose_tx = try_s!(electrum.get_verbose_transaction(tx_hash).compat().await);
        if verbose_tx.confirmations < 1 {
            return ERR!("'erc20Payment' was not confirmed yet. Please wait for at least one confirmation");
        }

        let Erc20PaymentDetails { swap_id, receiver, .. } = try_s!(self.erc20_payment_details_from_tx(&tx).await);
        let expected_swap_id = qrc20_swap_id(time_lock, &secret_hash);
        if expected_swap_id != swap_id {
            return ERR!("Unexpected swap_id {}", hex::encode(swap_id));
        }

        // First try to find a 'receiverSpend' contract call.
        // This means that we should request a transaction history for the possible spender of our payment - [`Erc20PaymentDetails::receiver`].
        let history = try_s!(
            HistoryBuilder::new(self.clone())
                .from_block(search_from_block as i64)
                .address(receiver.clone())
                // current function could be called much later than end of the swap
                .order(HistoryOrder::OldestToNewest)
                .build_utxo_lazy()
                .await
        );
        let found = history
            .into_iter()
            .find_map_lazy(|tx| {
                let tx = tx.ok()?;
                find_receiver_spend_with_swap_id_and_secret_hash(&tx, &expected_swap_id, &secret_hash)
                    // return Some(tx) if the `receiverSpend` was found
                    .map(|_| tx)
            })
            .await;
        if let Some(spent_tx) = found {
            return Ok(Some(FoundSwapTxSpend::Spent(TransactionEnum::UtxoTx(spent_tx))));
        }

        // Else try to find a 'senderRefund' contract call.
        // This means that we should request our transaction history because we could refund the payment already.
        let history = try_s!(
            HistoryBuilder::new(self.clone())
                .from_block(search_from_block as i64)
                // current function could be called much later than end of the swap
                .order(HistoryOrder::OldestToNewest)
                .build_utxo_lazy()
                .await
        );
        let found = history
            .into_iter()
            .find_map_lazy(|tx| {
                let tx = tx.ok()?;
                find_swap_contract_call_with_swap_id(ContractCallType::SenderRefund, &tx, &expected_swap_id)
                    // return Some(tx) if the `senderRefund` was found
                    .map(|_| tx)
            })
            .await;
        if let Some(refunded_tx) = found {
            return Ok(Some(FoundSwapTxSpend::Refunded(TransactionEnum::UtxoTx(refunded_tx))));
        }

        Ok(None)
    }

    pub async fn check_if_my_payment_sent_impl(
        &self,
        swap_id: Vec<u8>,
        search_from_block: i64,
    ) -> Result<Option<TransactionEnum>, String> {
        let status = try_s!(self.payment_status(swap_id.clone()).await);
        if status == PAYMENT_STATE_UNINITIALIZED.into() {
            return Ok(None);
        };

        let history = try_s!(
            HistoryBuilder::new(self.clone())
                .from_block(search_from_block)
                .order(HistoryOrder::OldestToNewest)
                .build_utxo_lazy()
                .await
        );
        let found = history
            .into_iter()
            .find_map_lazy(|tx| {
                let tx = tx.ok()?;
                find_swap_contract_call_with_swap_id(ContractCallType::Erc20Payment, &tx, &swap_id)
                    // return Some(UtxoTx(tx)) if the `erc20Payment` was found
                    .map(|_| TransactionEnum::UtxoTx(tx))
            })
            .await;
        Ok(found)
    }

    pub async fn check_if_my_payment_completed_impl(&self, payment_tx: UtxoTx) -> Result<(), String> {
        let Erc20PaymentDetails { swap_id, .. } = try_s!(self.erc20_payment_details_from_tx(&payment_tx).await);

        let status = try_s!(self.payment_status(swap_id.clone()).await);
        if status != PAYMENT_STATE_SENT.into() {
            return ERR!("Payment state is not PAYMENT_STATE_SENT, got {}", status);
        }

        Ok(())
    }

    pub fn extract_secret_impl(&self, secret_hash: &[u8], spend_tx: &[u8]) -> Result<Vec<u8>, String> {
        let spend_tx: UtxoTx = try_s!(deserialize(spend_tx).map_err(|e| ERRL!("{:?}", e)));
        let spend_tx_hash: H256Json = spend_tx.hash().reversed().into();
        for output in spend_tx.outputs {
            let script_pubkey: Script = output.script_pubkey.into();
            let ReceiverSpendDetails { secret, .. } =
                match receiver_spend_call_details_from_script_pubkey(&script_pubkey) {
                    Ok(details) => details,
                    Err(e) => {
                        log!((e));
                        // try to obtain the details from the next output}
                        continue;
                    },
                };

            let actual_secret_hash = &*dhash160(&secret);
            if actual_secret_hash != secret_hash {
                log!("Warning: invalid 'dhash160(secret)' "[actual_secret_hash]", expected "[secret_hash]);
                continue;
            }

            return Ok(secret);
        }

        ERR!("Couldn't obtain the 'secret' from {:?} tx", spend_tx_hash)
    }

    pub async fn wait_for_tx_spend_impl(
        &self,
        tx: UtxoTx,
        wait_until: u64,
        from_block: u64,
    ) -> Result<TransactionEnum, String> {
        let Erc20PaymentDetails {
            swap_id,
            receiver,
            secret_hash,
            ..
        } = try_s!(self.erc20_payment_details_from_tx(&tx).await);

        loop {
            // Try to find a 'receiverSpend' contract call.
            // This means that we should request a transaction history for the possible spender of our payment - [`Erc20PaymentDetails::receiver`].
            let history = try_s!(
                HistoryBuilder::new(self.clone())
                    .from_block(from_block as i64)
                    .address(receiver.clone())
                    .order(HistoryOrder::NewestToOldest)
                    .build_utxo_lazy()
                    .await
            );
            let found = history
                .into_iter()
                .find_map_lazy(|tx| {
                    let tx = tx.ok()?;
                    find_receiver_spend_with_swap_id_and_secret_hash(&tx, &swap_id, &secret_hash)
                        // return Some(UtxoTx(tx)) if the `receiverSpend` was found
                        .map(|_| TransactionEnum::UtxoTx(tx))
                })
                .await;

            if let Some(spent_tx) = found {
                return Ok(spent_tx);
            }

            if now_ms() / 1000 > wait_until {
                return ERR!("Waited too long until {} for {:?} to be spent ", wait_until, tx);
            }
            Timer::sleep(10.).await;
        }
    }

    async fn allowance(&self, spender: H160) -> Result<U256, String> {
        let tokens = try_s!(
            self.rpc_contract_call(RpcContractCallType::Allowance, &[
                Token::Address(qrc20_addr_from_utxo_addr(self.utxo.my_address.clone())),
                Token::Address(spender),
            ])
            .await
        );

        if tokens.is_empty() {
            return ERR!(r#"Expected U256 as "allowance" result but got nothing"#);
        }

        match tokens[0] {
            Token::Uint(number) => Ok(number),
            _ => ERR!(r#"Expected U256 as "allowance" result but got {:?}"#, tokens),
        }
    }

    async fn payment_status(&self, swap_id: Vec<u8>) -> Result<U256, String> {
        let decoded = try_s!(
            self.rpc_contract_call(RpcContractCallType::Payments, &[Token::FixedBytes(swap_id)])
                .await
        );
        if decoded.len() < 3 {
            return ERR!(
                "Expected at least 3 tokens in \"payments\" call, found {}",
                decoded.len()
            );
        }

        match decoded[2] {
            Token::Uint(state) => Ok(state),
            _ => ERR!("Payment status must be uint, got {:?}", decoded[2]),
        }
    }

    /// Generate a UTXO output with a script_pubkey that calls standard QRC20 `approve` function.
    fn approve_output(&self, spender: H160, amount: U256) -> Result<ContractCallOutput, String> {
        let function = try_s!(ERC20_CONTRACT.function("approve"));
        let params = try_s!(function.encode_input(&[Token::Address(spender), Token::Uint(amount)]));

        let gas_limit = QRC20_GAS_LIMIT_DEFAULT;
        let gas_price = QRC20_GAS_PRICE_DEFAULT;
        let script_pubkey = try_s!(generate_contract_call_script_pubkey(
            &params,
            gas_limit,
            gas_price,
            &self.contract_address
        ))
        .to_bytes();

        Ok(ContractCallOutput {
            value: OUTPUT_QTUM_AMOUNT,
            script_pubkey,
            gas_limit,
            gas_price,
        })
    }

    /// Generate a UTXO output with a script_pubkey that calls EtomicSwap `erc20Payment` function.
    fn erc20_payment_output(
        &self,
        id: Vec<u8>,
        value: U256,
        time_lock: u32,
        secret_hash: &[u8],
        receiver_addr: H160,
    ) -> Result<ContractCallOutput, String> {
        let function = try_s!(SWAP_CONTRACT.function("erc20Payment"));
        let params = try_s!(function.encode_input(&[
            Token::FixedBytes(id),
            Token::Uint(value),
            Token::Address(self.contract_address),
            Token::Address(receiver_addr),
            Token::FixedBytes(secret_hash.to_vec()),
            Token::Uint(U256::from(time_lock))
        ]));

        let gas_limit = QRC20_GAS_LIMIT_DEFAULT;
        let gas_price = QRC20_GAS_PRICE_DEFAULT;
        let script_pubkey = try_s!(generate_contract_call_script_pubkey(
            &params, // params of the function
            gas_limit,
            gas_price,
            &self.swap_contract_address, // address of the contract which function will be called
        ))
        .to_bytes();

        Ok(ContractCallOutput {
            value: OUTPUT_QTUM_AMOUNT,
            script_pubkey,
            gas_limit,
            gas_price,
        })
    }

    /// Generate a UTXO output with a script_pubkey that calls EtomicSwap `receiverSpend` function.
    fn receiver_spend_output(
        &self,
        id: Vec<u8>,
        value: U256,
        secret: Vec<u8>,
        sender_addr: H160,
    ) -> Result<ContractCallOutput, String> {
        let function = try_s!(SWAP_CONTRACT.function("receiverSpend"));
        let params = try_s!(function.encode_input(&[
            Token::FixedBytes(id),
            Token::Uint(value),
            Token::FixedBytes(secret),
            Token::Address(self.contract_address),
            Token::Address(sender_addr)
        ]));

        let gas_limit = QRC20_GAS_LIMIT_DEFAULT;
        let gas_price = QRC20_GAS_PRICE_DEFAULT;
        let script_pubkey = try_s!(generate_contract_call_script_pubkey(
            &params, // params of the function
            gas_limit,
            gas_price,
            &self.swap_contract_address, // address of the contract which function will be called
        ))
        .to_bytes();

        Ok(ContractCallOutput {
            value: OUTPUT_QTUM_AMOUNT,
            script_pubkey,
            gas_limit,
            gas_price,
        })
    }

    fn sender_refund_output(
        &self,
        id: Vec<u8>,
        value: U256,
        secret_hash: Vec<u8>,
        receiver: H160,
    ) -> Result<ContractCallOutput, String> {
        let function = try_s!(SWAP_CONTRACT.function("senderRefund"));

        let params = try_s!(function.encode_input(&[
            Token::FixedBytes(id),
            Token::Uint(value),
            Token::FixedBytes(secret_hash),
            Token::Address(self.contract_address),
            Token::Address(receiver)
        ]));

        let gas_limit = QRC20_GAS_LIMIT_DEFAULT;
        let gas_price = QRC20_GAS_PRICE_DEFAULT;
        let script_pubkey = try_s!(generate_contract_call_script_pubkey(
            &params, // params of the function
            gas_limit,
            gas_price,
            &self.swap_contract_address, // address of the contract which function will be called
        ))
        .to_bytes();

        Ok(ContractCallOutput {
            value: OUTPUT_QTUM_AMOUNT,
            script_pubkey,
            gas_limit,
            gas_price,
        })
    }

    /// Get `erc20Payment` contract call details.
    /// Note returns an error if the contract call was excepted.
    async fn erc20_payment_details_from_tx(&self, qtum_tx: &UtxoTx) -> Result<Erc20PaymentDetails, String> {
        let tx_hash: H256Json = qtum_tx.hash().reversed().into();
        let receipts = match self.utxo.rpc_client {
            UtxoRpcClientEnum::Electrum(ref rpc) => {
                try_s!(rpc.blochchain_transaction_get_receipt(&tx_hash).compat().await)
            },
            UtxoRpcClientEnum::Native(_) => return ERR!("Electrum client expected"),
        };

        for receipt in receipts {
            let output = try_s!(qtum_tx
                .outputs
                .get(receipt.output_index as usize)
                .ok_or(ERRL!("TxReceipt::output_index out of bounds")));
            let script_pubkey: Script = output.script_pubkey.clone().into();
            if !is_contract_call(&script_pubkey) {
                continue;
            }

            let contract_call_bytes = try_s!(extract_contract_call_from_script(&script_pubkey));

            let call_type = try_s!(ContractCallType::from_script_pubkey(&contract_call_bytes));
            match call_type {
                Some(ContractCallType::Erc20Payment) => (),
                _ => continue, // skip non-erc20Payment contract calls
            }

            // check if the contract call was excepted
            match receipt.excepted.clone() {
                Some(ex) if ex != "None" && ex != "none" => {
                    let msg = match receipt.excepted_message {
                        Some(m) => format!(": {}", m),
                        None => String::default(),
                    };
                    return ERR!("'erc20Payment' payment failed with an error: {}{}", ex, msg);
                },
                _ => (),
            }

            let function = try_s!(SWAP_CONTRACT.function("erc20Payment"));
            let decoded = try_s!(function.decode_input(&contract_call_bytes));

            let mut decoded = decoded.into_iter();

            let swap_id = match decoded.next() {
                Some(Token::FixedBytes(id)) => id,
                Some(token) => return ERR!("Payment tx 'swap_id' arg is invalid, found {:?}", token),
                None => return ERR!("Couldn't find 'swap_id' in erc20Payment call"),
            };

            let value = match decoded.next() {
                Some(Token::Uint(value)) => value,
                Some(token) => return ERR!("Payment tx 'value' arg is invalid, found {:?}", token),
                None => return ERR!("Couldn't find 'value' in erc20Payment call"),
            };

            let token_address = match decoded.next() {
                Some(Token::Address(addr)) => addr,
                Some(token) => return ERR!("Payment tx 'token_address' arg is invalid, found {:?}", token),
                None => return ERR!("Couldn't find 'token_address' in erc20Payment call"),
            };

            let receiver = match decoded.next() {
                Some(Token::Address(addr)) => addr,
                Some(token) => return ERR!("Payment tx 'receiver' arg is invalid, found {:?}", token),
                None => return ERR!("Couldn't find 'receiver' in erc20Payment call"),
            };

            let secret_hash = match decoded.next() {
                Some(Token::FixedBytes(hash)) => hash,
                Some(token) => return ERR!("Payment tx 'secret_hash' arg is invalid, found {:?}", token),
                None => return ERR!("Couldn't find 'secret_hash' in erc20Payment call"),
            };

            let timelock = match decoded.next() {
                Some(Token::Uint(t)) => t,
                Some(token) => return ERR!("Payment tx 'timelock' arg is invalid, found {:?}", token),
                None => return ERR!("Couldn't find 'timelock' in erc20Payment call"),
            };

            let (_amount, sender, swap_contract_address) = try_s!(transfer_event_details_from_receipt(&receipt));
            return Ok(Erc20PaymentDetails {
                output_index: receipt.output_index,
                swap_id,
                value,
                token_address,
                swap_contract_address,
                sender,
                receiver,
                secret_hash,
                timelock,
            });
        }
        ERR!("Couldn't find erc20Payment contract call in {:?} tx", tx_hash)
    }
}

/// Get `Transfer` event details from [`TxReceipt::logs`].
/// Note finds first log entry with `Transfer` topic and extract (amount, sender, receiver) from it.
fn transfer_event_details_from_receipt(receipt: &TxReceipt) -> Result<(U256, H160, H160), String> {
    // We can get a log_index from get_history call, but it is overhead to request it on every tx_details_by_hash(),
    // because of this try to find corresponding log entry below
    let log = match receipt.log.iter().find(|log_entry| {
        // we should find a log entry with three and more topics
        if log_entry.topics.len() < 3 {
            return false;
        }
        // the first topic means the type of the contract call
        // https://github.com/qtumproject/qtum-electrum/blob/v4.0.2/electrum/wallet.py#L2101
        log_entry.topics.first().unwrap() == QRC20_TRANSFER_TOPIC
    }) {
        Some(log) => log,
        _ => return ERR!("Couldn't find a log entry that meets the requirements"),
    };

    transfer_event_from_log(log)
}

/// Get `transfer` contract call details from script pubkey.
/// Result - (receiver, amount).
fn transfer_call_details_from_script_pubkey(script_pubkey: &Script) -> Result<(H160, U256), String> {
    if !is_contract_call(&script_pubkey) {
        return ERR!("Expected 'transfer' contract call");
    }

    let contract_call_bytes = try_s!(extract_contract_call_from_script(&script_pubkey));
    let call_type = try_s!(ContractCallType::from_script_pubkey(&contract_call_bytes));
    match call_type {
        Some(ContractCallType::Transfer) => (),
        _ => return ERR!("Expected 'transfer' contract call"),
    }

    let function = try_s!(ERC20_CONTRACT.function("transfer"));
    let decoded = try_s!(function.decode_input(&contract_call_bytes));
    let mut decoded = decoded.into_iter();

    let receiver = match decoded.next() {
        Some(Token::Address(addr)) => addr,
        Some(token) => return ERR!("Transfer 'receiver' arg is invalid, found {:?}", token),
        None => return ERR!("Couldn't find 'receiver' in 'transfer' call"),
    };

    let value = match decoded.next() {
        Some(Token::Uint(value)) => value,
        Some(token) => return ERR!("Transfer 'value' arg is invalid, found {:?}", token),
        None => return ERR!("Couldn't find 'value' in 'transfer' call"),
    };

    Ok((receiver, value))
}

/// Get `receiverSpend` contract call details from script pubkey.
pub fn receiver_spend_call_details_from_script_pubkey(script_pubkey: &Script) -> Result<ReceiverSpendDetails, String> {
    if !is_contract_call(script_pubkey) {
        return ERR!("Expected 'transfer' contract call");
    }

    let contract_call_bytes = try_s!(extract_contract_call_from_script(script_pubkey));
    let call_type = try_s!(ContractCallType::from_script_pubkey(&contract_call_bytes));
    match call_type {
        Some(ContractCallType::ReceiverSpend) => (),
        _ => return ERR!("Expected 'receiverSpend' contract call"),
    }

    let function = try_s!(SWAP_CONTRACT.function("receiverSpend"));
    let decoded = try_s!(function.decode_input(&contract_call_bytes));
    let mut decoded = decoded.into_iter();

    let swap_id = match decoded.next() {
        Some(Token::FixedBytes(id)) => id,
        Some(token) => return ERR!("Payment tx 'swap_id' arg is invalid, found {:?}", token),
        None => return ERR!("Couldn't find 'swap_id' in erc20Payment call"),
    };

    let value = match decoded.next() {
        Some(Token::Uint(value)) => value,
        Some(token) => return ERR!("Payment tx 'value' arg is invalid, found {:?}", token),
        None => return ERR!("Couldn't find 'value' in erc20Payment call"),
    };

    let secret = match decoded.next() {
        Some(Token::FixedBytes(hash)) => hash,
        Some(token) => return ERR!("Payment tx 'secret_hash' arg is invalid, found {:?}", token),
        None => return ERR!("Couldn't find 'secret_hash' in erc20Payment call"),
    };

    let token_address = match decoded.next() {
        Some(Token::Address(addr)) => addr,
        Some(token) => return ERR!("Payment tx 'token_address' arg is invalid, found {:?}", token),
        None => return ERR!("Couldn't find 'token_address' in erc20Payment call"),
    };

    let sender = match decoded.next() {
        Some(Token::Address(addr)) => addr,
        Some(token) => return ERR!("Payment tx 'receiver' arg is invalid, found {:?}", token),
        None => return ERR!("Couldn't find 'receiver' in erc20Payment call"),
    };

    Ok(ReceiverSpendDetails {
        swap_id,
        value,
        secret,
        token_address,
        sender,
    })
}

fn find_receiver_spend_with_swap_id_and_secret_hash(
    tx: &UtxoTx,
    expected_swap_id: &[u8],
    expected_secret_hash: &[u8],
) -> Option<usize> {
    for (output_idx, output) in tx.outputs.iter().enumerate() {
        let script_pubkey: Script = output.script_pubkey.clone().into();
        let ReceiverSpendDetails { swap_id, secret, .. } =
            match receiver_spend_call_details_from_script_pubkey(&script_pubkey) {
                Ok(details) => details,
                Err(_) => {
                    // try to obtain the details from the next output
                    continue;
                },
            };

        if swap_id != expected_swap_id {
            continue;
        }

        let secret_hash = &*dhash160(&secret);
        if secret_hash != expected_secret_hash {
            log!("Warning: invalid 'dhash160(secret)' "[secret_hash]", expected "[expected_secret_hash]);
            continue;
        }

        return Some(output_idx);
    }

    None
}

fn find_swap_contract_call_with_swap_id(
    expected_call_type: ContractCallType,
    tx: &UtxoTx,
    expected_swap_id: &[u8],
) -> Option<usize> {
    let tx_hash: H256Json = tx.hash().reversed().into();

    for (output_idx, output) in tx.outputs.iter().enumerate() {
        let script_pubkey: Script = output.script_pubkey.clone().into();
        if !is_contract_call(&script_pubkey) {
            continue;
        }

        let contract_call_bytes = match extract_contract_call_from_script(&script_pubkey) {
            Ok(bytes) => bytes,
            Err(e) => {
                log!([e]);
                continue;
            },
        };

        let call_type = match ContractCallType::from_script_pubkey(&contract_call_bytes) {
            Ok(Some(t)) => t,
            Ok(None) => continue, // unknown contract call type
            Err(e) => {
                log!([e]);
                continue;
            },
        };
        if call_type != expected_call_type {
            // skip the output
            continue;
        }

        let function = call_type.as_function();
        let decoded = match function.decode_input(&contract_call_bytes) {
            Ok(d) => d,
            Err(e) => {
                log!([e]);
                continue;
            },
        };

        // swap_id is the first in `erc20Payment` call
        let swap_id = match decoded.into_iter().next() {
            Some(Token::FixedBytes(id)) => id,
            Some(token) => {
                log!("Warning: tx "[tx_hash]" 'swap_id' arg is invalid, found "[token]);
                continue;
            },
            None => {
                log!("Warning: couldn't find 'swap_id' in "[tx_hash]);
                continue;
            },
        };

        if swap_id == expected_swap_id {
            return Some(output_idx);
        }
    }

    None
}
