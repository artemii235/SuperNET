use super::*;
use crate::eth::{addr_from_raw_pubkey, u256_to_big_decimal, wei_from_big_decimal, ERC20_CONTRACT, SWAP_CONTRACT};
use crate::{SwapOps, TxFeeDetails, ValidateAddressResult};
use bitcrypto::sha256;
use common::jsonrpc_client::{JsonRpcClient, JsonRpcErrorType, JsonRpcRequest, RpcRes};
use common::mm_metrics::MetricsArc;
use ethabi::Token;
use ethereum_types::{H160, U256};
use futures::{FutureExt, TryFutureExt};
use gstuff::now_ms;
use rpc::v1::types::H160 as H160Json;
use serialization::deserialize;
use std::ops::Neg;
use std::str::FromStr;
use utxo_common::HISTORY_TOO_LARGE_ERROR;

const QRC20_GAS_LIMIT_DEFAULT: u64 = 100_000;
const QRC20_GAS_PRICE_DEFAULT: u64 = 40;
const QRC20_SWAP_GAS_REQUIRED: u64 = 300_000;
const QRC20_DUST: u64 = 0;
const QRC20_TRANSFER_TOPIC: &str = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

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

#[derive(Debug, Deserialize)]
pub struct TxHistoryItem {
    pub tx_hash: H256Json,
    pub height: i64,
    pub log_index: i64,
}

/// The structure is the same as Qtum Core RPC gettransactionreceipt returned data.
/// https://docs.qtum.site/en/Qtum-RPC-API/#gettransactionreceipt
#[derive(Debug, Deserialize)]
pub struct TxReceipt {
    /// Hash of the block this transaction was included within.
    #[serde(rename = "blockHash")]
    block_hash: H256Json,
    /// Number of the block this transaction was included within.
    #[serde(rename = "blockNumber")]
    block_number: i64,
    /// Transaction hash.
    #[serde(rename = "transactionHash")]
    transaction_hash: H256Json,
    /// Index within the block.
    #[serde(rename = "transactionIndex")]
    transaction_index: i64,
    /// Index within the outputs.
    #[serde(rename = "outputIndex")]
    output_index: i64,
    /// 20 bytes，the sender address of this tx.
    from: String,
    /// 20 bytes，the receiver address of this tx. if this  address is created by a contract, return null.
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    /// The total amount of gas used after execution of the current transaction.
    #[serde(rename = "cumulativeGasUsed")]
    cumulative_gas_used: u64,
    /// The gas cost alone to execute the current transaction.
    #[serde(rename = "gasUsed")]
    gas_used: i64,
    /// Contract address created, or `None` if not a deployment.
    #[serde(rename = "contractAddress")]
    contract_address: Option<String>,
    /// Logs generated within this transaction.
    log: Vec<LogEntry>,
    /// Whether corresponding contract call (specified in UTXO outputs[output_index]) was failed.
    /// If None or Some("None") - completed, else failed.
    excepted: Option<String>,
    #[serde(rename = "exceptedMessage")]
    excepted_message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LogEntry {
    /// Contract address.
    address: String,
    /// Vector of 0x-prefixed hex strings with length of 64.
    topics: Vec<String>,
    /// In other words the data means a transaction value.
    data: String,
}

/// QTUM specific RPC ops
pub trait QtumRpcOps {
    /// This can be used to get the basic information(name, decimals, total_supply, symbol) of a QRC20 token.
    /// https://github.com/qtumproject/qtum-electrumx-server/blob/master/docs/qrc20-integration.md#blockchaintokenget_infotoken_address
    fn blockchain_token_get_info(&self, token_addr: &H160Json) -> RpcRes<TokenInfo>;

    fn blockchain_contract_call(&self, contract_addr: &H160Json, data: BytesJson) -> RpcRes<ContractCallResult>;

    /// this can be used to retrieve QRC20 token transfer history, params are the same as blockchain.contract.event.subscribe,
    /// and it returns a list of map{tx_hash, height, log_index}, where log_index is the position for this event log in its transaction.
    /// https://github.com/qtumproject/qtum-electrumx-server/blob/master/docs/qrc20-integration.md#blockchaincontracteventget_historyhash160-contract_addr-topic
    fn blockchain_contract_event_get_history(
        &self,
        address: &H160Json,
        contract_addr: &H160Json,
    ) -> RpcRes<Vec<TxHistoryItem>>;

    fn blochchain_transaction_get_receipt(&self, hash: &H256Json) -> RpcRes<Vec<TxReceipt>>;
}

impl QtumRpcOps for ElectrumClient {
    fn blockchain_token_get_info(&self, token_addr: &H160Json) -> RpcRes<TokenInfo> {
        rpc_func!(self, "blockchain.token.get_info", token_addr)
    }

    fn blockchain_contract_call(&self, contract_addr: &H160Json, data: BytesJson) -> RpcRes<ContractCallResult> {
        let sender = "";
        rpc_func!(self, "blockchain.contract.call", contract_addr, data, sender)
    }

    fn blockchain_contract_event_get_history(
        &self,
        address: &H160Json,
        contract_addr: &H160Json,
    ) -> RpcRes<Vec<TxHistoryItem>> {
        // for QRC20, just use ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
        // (Keccak-256 hash of event Transfer(address indexed _from, address indexed _to, uint256 _value))
        let topic = QRC20_TRANSFER_TOPIC;
        rpc_func!(
            self,
            "blockchain.contract.event.get_history",
            address,
            contract_addr,
            topic
        )
    }

    fn blochchain_transaction_get_receipt(&self, hash: &H256Json) -> RpcRes<Vec<TxReceipt>> {
        rpc_func!(self, "blochchain.transaction.get_receipt", hash)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Qrc20FeeDetails {
    /// Coin name
    coin: String,
    /// Standard UTXO miner fee based on transaction size
    miner_fee: BigDecimal,
    /// in satoshi
    gas_limit: u64,
    gas_price: u64,
    total_gas_fee: BigDecimal,
}

pub async fn qrc20_coin_from_conf_and_request(
    ctx: &MmArc,
    ticker: &str,
    platform: &str,
    conf: &Json,
    req: &Json,
    priv_key: &[u8],
    contract_address: H160,
) -> Result<Qrc20Coin, String> {
    if let Some("enable") = req["method"].as_str() {
        return ERR!("Native mode not supported yet for QRC20");
    }
    let swap_contract_address = match req["swap_contract_address"].as_str() {
        Some(address) => try_s!(qrc20_addr_from_str(address)),
        None => return ERR!("\"swap_contract_address\" field is expected"),
    };
    let inner = try_s!(utxo_arc_from_conf_and_request(ctx, ticker, conf, req, priv_key, QRC20_DUST).await);
    match &inner.address_format {
        UtxoAddressFormat::Standard => (),
        _ => return ERR!("Expect standard UTXO address format"),
    }
    let platform = platform.to_owned();
    Ok(Qrc20Coin {
        utxo_arc: inner,
        platform,
        contract_address,
        swap_contract_address,
    })
}

#[derive(Clone, Debug)]
pub struct Qrc20Coin {
    pub utxo_arc: UtxoArc,
    pub platform: String,
    pub contract_address: H160,
    pub swap_contract_address: H160,
}

impl Qrc20Coin {
    async fn contract_call(&self, func: &str, tokens: &[Token]) -> Result<Vec<Token>, String> {
        let function = try_s!(ERC20_CONTRACT.function(func));
        let params = try_s!(function.encode_input(tokens));

        let electrum = match self.utxo_arc.rpc_client {
            UtxoRpcClientEnum::Electrum(ref electrum) => electrum,
            _ => return ERR!("Electrum client expected"),
        };

        let result: ContractCallResult = try_s!(
            electrum
                .blockchain_contract_call(&self.contract_address.to_vec().as_slice().into(), params.into())
                .compat()
                .await
        );
        Ok(try_s!(function.decode_output(&result.execution_result.output)))
    }

    fn address_from_log_topic(&self, topic: &str) -> Result<Address, String> {
        if topic.len() != 64 {
            return ERR!(
                "Topic {:?} is expected to be H256 encoded topic (with length of 64)",
                topic
            );
        }

        // skip the first 24 characters to parse the last 40 characters to H160.
        // https://github.com/qtumproject/qtum-electrum/blob/v4.0.2/electrum/wallet.py#L2112
        let hash = try_s!(H160Json::from_str(&topic[24..]));

        let utxo = self.as_ref();
        Ok(Address {
            prefix: utxo.pub_addr_prefix,
            t_addr_prefix: utxo.pub_t_addr_prefix,
            hash: hash.into(),
            checksum_type: utxo.checksum_type,
        })
    }

    pub async fn allowance(&self, spender: H160) -> Result<U256, String> {
        let tokens = try_s!(
            self.contract_call("allowance", &[
                Token::Address(qrc20_addr_from_utxo_addr(self.utxo_arc.my_address.clone())),
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

    /// Generate a UTXO output with a script_pubkey that calls standard QRC20 `approve` function.
    pub fn approve_output(&self, spender: H160, amount: U256) -> Result<TransactionOutput, String> {
        let function = try_s!(ERC20_CONTRACT.function("approve"));
        let params = try_s!(function.encode_input(&[Token::Address(spender), Token::Uint(amount)]));

        let script_pubkey = try_s!(generate_contract_call_script_pubkey(
            &params,
            QRC20_GAS_LIMIT_DEFAULT,
            QRC20_GAS_PRICE_DEFAULT,
            &self.contract_address
        ))
        .to_bytes();

        // qtum_amount is always 0 for the QRC20, because we should pay only a fee in Qtum to send the QRC20 transaction
        let qtum_amount = 0;
        Ok(TransactionOutput {
            value: qtum_amount,
            script_pubkey,
        })
    }

    /// Generate a UTXO output with a script_pubkey that calls EtomicSwap `erc20Payment` function.
    pub fn erc20_payment_output(
        &self,
        id: Vec<u8>,
        value: U256,
        time_lock: u32,
        secret_hash: &[u8],
        receiver_addr: H160,
    ) -> Result<TransactionOutput, String> {
        let function = try_s!(SWAP_CONTRACT.function("erc20Payment"));
        let params = try_s!(function.encode_input(&[
            Token::FixedBytes(id),
            Token::Uint(value),
            Token::Address(self.contract_address),
            Token::Address(receiver_addr),
            Token::FixedBytes(secret_hash.to_vec()),
            Token::Uint(U256::from(time_lock))
        ]));

        let script_pubkey = try_s!(generate_contract_call_script_pubkey(
            &params, // params of the function
            QRC20_GAS_LIMIT_DEFAULT,
            QRC20_GAS_PRICE_DEFAULT,
            &self.swap_contract_address, // address of the contract which function will be called
        ))
        .to_bytes();

        // qtum_amount is always 0 for the QRC20, because we should pay only a fee in Qtum to send the QRC20 transaction
        let qtum_amount = 0;
        Ok(TransactionOutput {
            value: qtum_amount,
            script_pubkey,
        })
    }

    /// Generate and send a transaction from the specified UTXO outputs.
    /// Note this function locks the `UTXO_LOCK`.
    pub async fn send_contract_calls(
        &self,
        // TODO replace TransactionOutput with a ContractCallOutput
        outputs: Vec<TransactionOutput>,
    ) -> Result<TransactionEnum, String> {
        let _utxo_lock = UTXO_LOCK.lock().await;

        let (signed, _fee_details) = try_s!(
            self.generate_qrc20_transaction(QRC20_GAS_LIMIT_DEFAULT, QRC20_GAS_PRICE_DEFAULT, outputs)
                .await
        );
        let _tx = try_s!(
            self.utxo_arc
                .rpc_client
                .send_transaction(&signed, self.utxo_arc.my_address.clone())
                .compat()
                .await
        );
        Ok(signed.into())
    }

    /// Generate Qtum UTXO transaction to call QRC20 contract call such as `transfer` or `approve`.
    /// Note: lock the UTXO_LOCK mutex before this function will be called.
    async fn generate_qrc20_transaction(
        &self,
        gas_limit: u64,
        gas_price: u64,
        outputs: Vec<TransactionOutput>,
    ) -> Result<(UtxoTx, Qrc20FeeDetails), String> {
        let unspents = try_s!(self
            .ordered_mature_unspents(&self.utxo_arc.my_address)
            .compat()
            .await
            .map_err(|e| ERRL!("{}", e)));

        // None seems that the generate_transaction() should request estimated fee for Kbyte
        let actual_tx_fee = None;
        // We do one contract call, because of this gas_fee will be (1 * gas_limit * gas_price)
        let gas_fee = gas_limit
            .checked_mul(gas_price)
            .ok_or(ERRL!("too large gas_limit and/or gas_price"))?
            .checked_mul(outputs.len() as u64)
            .ok_or(ERRL!("too large gas_fee"))?;
        let fee_policy = FeePolicy::SendExact;

        let (unsigned, data) = self
            .generate_transaction(unspents, outputs, fee_policy, actual_tx_fee, Some(gas_fee))
            .await
            .map_err(|e| match &e {
                GenerateTransactionError::EmptyUtxoSet => ERRL!("Not enough {} to Pay Fee: {}", self.platform, e),
                GenerateTransactionError::NotSufficientBalance { description } => {
                    ERRL!("Not enough {} to Pay Fee: {}", self.platform, description)
                },
                e => ERRL!("{}", e),
            })?;
        let prev_script = Builder::build_p2pkh(&self.utxo_arc.my_address.hash);
        let signed = try_s!(sign_tx(
            unsigned,
            &self.utxo_arc.key_pair,
            prev_script,
            self.utxo_arc.signature_version,
            self.utxo_arc.fork_id
        ));
        let fee_details = Qrc20FeeDetails {
            // QRC20 fees are paid in base platform currency (in particular Qtum)
            coin: self.platform.clone(),
            miner_fee: utxo_common::big_decimal_from_sat(data.fee_amount as i64, self.utxo_arc.decimals),
            gas_limit,
            gas_price,
            total_gas_fee: utxo_common::big_decimal_from_sat(gas_fee as i64, self.utxo_arc.decimals),
        };
        Ok((signed, fee_details))
    }

    /// Validate swap payment: check if the transaction contains the `expected_swap_function`, in particular `erc20Payment`.
    /// Also check if this contract call completed successfully.
    async fn validate_swap_contract_call(&self, utxo_tx: &UtxoTx, expected_swap_function: &str) -> Result<(), String> {
        let payment_function = try_s!(SWAP_CONTRACT.function(expected_swap_function));
        let payment_call_signature = payment_function.short_signature();

        let mut transfer_outputs = Vec::default();
        // get indexes of outputs whose script pubkeys are `expected_swap_function` contract calls
        for (idx, output) in utxo_tx.outputs.iter().enumerate() {
            let script_pubkey: Script = output.script_pubkey.clone().into();
            if is_contract_call(&script_pubkey) {
                let contract_call = try_s!(extract_contract_call_from_script(&script_pubkey));
                if contract_call.starts_with(&payment_call_signature) {
                    transfer_outputs.push(idx as i64);
                }
            }
        }

        if transfer_outputs.is_empty() {
            return ERR!(
                "Maker payment should contain {:?} contract call. Outputs: {:?}",
                expected_swap_function,
                utxo_tx.outputs
            );
        }
        if transfer_outputs.len() != 1 {
            log!("Count of "[expected_swap_function]" calls is {}, expected 1"[transfer_outputs.len()]);
        }

        let tx_hash = utxo_tx.hash().reversed().into();
        // check if the contract transfer calls have completed successfully
        self.validate_contract_calls(tx_hash, transfer_outputs).await
    }

    /// Validate contract calls: check if the contract calls specified in `outputs` were completed successfully.
    /// `outputs` contains list of indexes of outputs, contract calls of which we should validate.
    async fn validate_contract_calls(&self, hash: H256Json, outputs: Vec<i64>) -> Result<(), String> {
        let receipts = match self.utxo_arc.rpc_client {
            UtxoRpcClientEnum::Electrum(ref rpc) => {
                try_s!(rpc.blochchain_transaction_get_receipt(&hash).compat().await)
            },
            UtxoRpcClientEnum::Native(_) => return ERR!("Electrum client expected"),
        };

        if receipts.is_empty() {
            return ERR!(
                "blochchain.transaction.get_receipt returned empty receipts list for {:?} transaction",
                hash
            );
        }

        for receipt in receipts {
            // Note contract_calls_topics is not expected to be long, we can iterate over the slice
            if !outputs.contains(&receipt.output_index) {
                continue;
            }
            match receipt.excepted {
                Some(ex) if ex == "None" => (), // contract call was completed successfully
                Some(ex) => {
                    let excepted_message = receipt.excepted_message.unwrap_or_default();
                    return ERR!(
                        "Contract call (index {} in outputs) is excepted: {:?}, excepted message: {:?}",
                        receipt.output_index,
                        ex,
                        excepted_message
                    );
                },
                None => (), // contract call was completed successfully
            }
        }

        // all of the contract calls that are expected to be completed successfully were completed successfully
        Ok(())
    }
}

impl AsRef<UtxoArc> for Qrc20Coin {
    fn as_ref(&self) -> &UtxoArc { &self.utxo_arc }
}

#[async_trait]
impl UtxoCoinCommonOps for Qrc20Coin {
    async fn get_tx_fee(&self) -> Result<ActualTxFee, JsonRpcError> { utxo_common::get_tx_fee(&self.utxo_arc).await }

    async fn get_htlc_spend_fee(&self) -> Result<u64, String> { utxo_common::get_htlc_spend_fee(self).await }

    fn addresses_from_script(&self, script: &Script) -> Result<Vec<Address>, String> {
        utxo_common::addresses_from_script(&self.utxo_arc, script)
    }

    fn denominate_satoshis(&self, satoshi: i64) -> f64 { utxo_common::denominate_satoshis(&self.utxo_arc, satoshi) }

    fn search_for_swap_tx_spend(
        &self,
        time_lock: u32,
        first_pub: &Public,
        second_pub: &Public,
        secret_hash: &[u8],
        tx: &[u8],
        search_from_block: u64,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        utxo_common::search_for_swap_tx_spend(
            &self.utxo_arc,
            time_lock,
            first_pub,
            second_pub,
            secret_hash,
            tx,
            search_from_block,
        )
    }

    fn my_public_key(&self) -> &Public { self.utxo_arc.key_pair.public() }

    fn display_address(&self, address: &Address) -> Result<String, String> {
        utxo_common::display_address(&self.utxo_arc, address)
    }

    fn try_address_from_str(&self, from: &str) -> Result<Address, String> {
        utxo_common::try_address_from_str(&self.utxo_arc, from)
    }

    fn address_from_str(&self, address: &str) -> Result<Address, String> {
        utxo_common::address_from_str(&self.utxo_arc, address)
    }

    async fn get_current_mtp(&self) -> Result<u32, String> { utxo_common::get_current_mtp(&self.utxo_arc).await }

    fn is_unspent_mature(&self, output: &RpcTransaction) -> bool {
        qtum::is_qtum_unspent_mature(self.utxo_arc.mature_confirmations, output)
    }
}

#[mockable]
#[async_trait]
#[allow(clippy::forget_ref, clippy::forget_copy)]
impl UtxoArcCommonOps for Qrc20Coin {
    fn validate_payment(
        &self,
        payment_tx: &[u8],
        time_lock: u32,
        first_pub0: &Public,
        second_pub0: &Public,
        priv_bn_hash: &[u8],
        amount: BigDecimal,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        utxo_common::validate_payment(
            self.utxo_arc.clone(),
            payment_tx,
            time_lock,
            first_pub0,
            second_pub0,
            priv_bn_hash,
            amount,
        )
    }

    /// Generate UTXO transaction with specified unspent inputs and specified outputs.
    async fn generate_transaction(
        &self,
        utxos: Vec<UnspentInfo>,
        outputs: Vec<TransactionOutput>,
        fee_policy: FeePolicy,
        fee: Option<ActualTxFee>,
        gas_fee: Option<u64>,
    ) -> Result<(TransactionInputSigner, AdditionalTxData), GenerateTransactionError> {
        utxo_common::generate_transaction(self, utxos, outputs, fee_policy, fee, gas_fee).await
    }

    async fn calc_interest_if_required(
        &self,
        unsigned: TransactionInputSigner,
        data: AdditionalTxData,
        my_script_pub: Bytes,
    ) -> Result<(TransactionInputSigner, AdditionalTxData), String> {
        utxo_common::calc_interest_if_required(self, unsigned, data, my_script_pub).await
    }

    fn p2sh_spending_tx(
        &self,
        prev_transaction: UtxoTx,
        redeem_script: Bytes,
        outputs: Vec<TransactionOutput>,
        script_data: Script,
        sequence: u32,
    ) -> Result<UtxoTx, String> {
        utxo_common::p2sh_spending_tx(
            &self.utxo_arc,
            prev_transaction,
            redeem_script,
            outputs,
            script_data,
            sequence,
        )
    }

    fn ordered_mature_unspents(
        &self,
        address: &Address,
    ) -> Box<dyn Future<Item = Vec<UnspentInfo>, Error = String> + Send> {
        Box::new(
            utxo_common::ordered_mature_unspents(self.clone(), address.clone())
                .boxed()
                .compat(),
        )
    }

    fn get_verbose_transaction_from_cache_or_rpc(
        &self,
        txid: H256Json,
    ) -> Box<dyn Future<Item = VerboseTransactionFrom, Error = String> + Send> {
        Box::new(
            utxo_common::get_verbose_transaction_from_cache_or_rpc(self.clone(), txid)
                .boxed()
                .compat(),
        )
    }

    async fn request_tx_history(&self, metrics: MetricsArc) -> RequestTxHistoryResult {
        let tx_ids = match &self.utxo_arc.rpc_client {
            UtxoRpcClientEnum::Native(_client) => {
                // it should not be happened because qrc20_coin_from_conf_and_request() must not allow enable mode
                return RequestTxHistoryResult::UnknownError(ERRL!("Native mode not supported"));
            },
            UtxoRpcClientEnum::Electrum(client) => {
                let my_address = utxo_addr_into_rpc_format(self.utxo_arc.my_address.clone());
                let contract_addr = qrc20_addr_into_rpc_format(&self.contract_address);

                mm_counter!(metrics, "tx.history.request.count", 1,
                    "coin" => self.utxo_arc.ticker.clone(), "client" => "electrum", "method" => "blockchain.contract.event.get_history");

                let history = match client
                    .blockchain_contract_event_get_history(&my_address, &contract_addr)
                    .compat()
                    .await
                {
                    Ok(value) => value,
                    Err(e) => match &e.error {
                        JsonRpcErrorType::Transport(e) | JsonRpcErrorType::Parse(_, e) => {
                            return RequestTxHistoryResult::Retry {
                                error: ERRL!("Error {} on blockchain_contract_event_get_history", e),
                            };
                        },
                        JsonRpcErrorType::Response(_addr, err) => {
                            if HISTORY_TOO_LARGE_ERROR.eq(err) {
                                return RequestTxHistoryResult::HistoryTooLarge;
                            } else {
                                return RequestTxHistoryResult::Retry {
                                    error: ERRL!("Error {:?} on blockchain_contract_event_get_history", e),
                                };
                            }
                        },
                    },
                };
                mm_counter!(metrics, "tx.history.response.count", 1,
                    "coin" => self.utxo_arc.ticker.clone(), "client" => "electrum", "method" => "blockchain.contract.event.get_history");

                mm_counter!(metrics, "tx.history.response.total_length", history.len() as u64,
                    "coin" => self.utxo_arc.ticker.clone(), "client" => "electrum", "method" => "blockchain.contract.event.get_history");

                // electrum returns the most recent transactions in the end but we need to
                // process them first so rev is required
                history
                    .into_iter()
                    .rev()
                    .map(|item| {
                        let height = if item.height < 0 { 0 } else { item.height as u64 };
                        (item.tx_hash, height)
                    })
                    .collect()
            },
        };
        RequestTxHistoryResult::Ok(tx_ids)
    }
}

impl SwapOps for Qrc20Coin {
    fn send_taker_fee(&self, fee_addr: &[u8], amount: BigDecimal) -> TransactionFut {
        utxo_common::send_taker_fee(self.clone(), fee_addr, amount)
    }

    fn send_maker_payment(
        &self,
        time_lock: u32,
        taker_pub: &[u8],
        secret_hash: &[u8],
        amount: BigDecimal,
    ) -> TransactionFut {
        let taker_addr = try_fus!(addr_from_raw_pubkey(taker_pub));
        let id = qrc20_swap_id(time_lock, secret_hash);
        let value = try_fus!(wei_from_big_decimal(&amount, self.utxo_arc.decimals));
        let secret_hash = Vec::from(secret_hash);
        Box::new(
            qrc20_send_hash_time_locked_payment(self.clone(), id, value, time_lock, secret_hash, taker_addr)
                .boxed()
                .compat(),
        )
    }

    fn send_taker_payment(
        &self,
        time_lock: u32,
        maker_pub: &[u8],
        secret_hash: &[u8],
        amount: BigDecimal,
    ) -> TransactionFut {
        utxo_common::send_taker_payment(self.clone(), time_lock, maker_pub, secret_hash, amount)
    }

    fn send_maker_spends_taker_payment(
        &self,
        taker_payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        secret: &[u8],
    ) -> TransactionFut {
        utxo_common::send_maker_spends_taker_payment(self.clone(), taker_payment_tx, time_lock, taker_pub, secret)
    }

    fn send_taker_spends_maker_payment(
        &self,
        maker_payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        secret: &[u8],
    ) -> TransactionFut {
        utxo_common::send_taker_spends_maker_payment(self.clone(), maker_payment_tx, time_lock, maker_pub, secret)
    }

    fn send_taker_refunds_payment(
        &self,
        taker_payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        secret_hash: &[u8],
    ) -> TransactionFut {
        utxo_common::send_taker_refunds_payment(self.clone(), taker_payment_tx, time_lock, maker_pub, secret_hash)
    }

    fn send_maker_refunds_payment(
        &self,
        maker_payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        secret_hash: &[u8],
    ) -> TransactionFut {
        utxo_common::send_maker_refunds_payment(self.clone(), maker_payment_tx, time_lock, taker_pub, secret_hash)
    }

    fn validate_fee(
        &self,
        fee_tx: &TransactionEnum,
        fee_addr: &[u8],
        amount: &BigDecimal,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        utxo_common::validate_fee(self.utxo_arc.clone(), fee_tx, fee_addr, amount)
    }

    fn validate_maker_payment(
        &self,
        payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        priv_bn_hash: &[u8],
        amount: BigDecimal,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        utxo_common::validate_maker_payment(self, payment_tx, time_lock, maker_pub, priv_bn_hash, amount)
    }

    fn validate_taker_payment(
        &self,
        payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        priv_bn_hash: &[u8],
        amount: BigDecimal,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        utxo_common::validate_taker_payment(self, payment_tx, time_lock, taker_pub, priv_bn_hash, amount)
    }

    fn check_if_my_payment_sent(
        &self,
        time_lock: u32,
        other_pub: &[u8],
        secret_hash: &[u8],
        search_from_block: u64,
    ) -> Box<dyn Future<Item = Option<TransactionEnum>, Error = String> + Send> {
        utxo_common::check_if_my_payment_sent(self.clone(), time_lock, other_pub, secret_hash, search_from_block)
    }

    fn search_for_swap_tx_spend_my(
        &self,
        time_lock: u32,
        other_pub: &[u8],
        secret_hash: &[u8],
        tx: &[u8],
        search_from_block: u64,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        utxo_common::search_for_swap_tx_spend_my(self, time_lock, other_pub, secret_hash, tx, search_from_block)
    }

    fn search_for_swap_tx_spend_other(
        &self,
        time_lock: u32,
        other_pub: &[u8],
        secret_hash: &[u8],
        tx: &[u8],
        search_from_block: u64,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        utxo_common::search_for_swap_tx_spend_other(self, time_lock, other_pub, secret_hash, tx, search_from_block)
    }

    fn wait_for_swap_payment_confirmations(
        &self,
        tx: &[u8],
        confirmations: u64,
        requires_nota: bool,
        wait_until: u64,
        check_every: u64,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        let tx = Vec::from(tx);
        Box::new(
            qrc20_wait_for_swap_payment_confirmations(
                self.clone(),
                tx,
                confirmations,
                requires_nota,
                wait_until,
                check_every,
            )
            .boxed()
            .compat(),
        )
    }
}

impl MarketCoinOps for Qrc20Coin {
    fn ticker(&self) -> &str { &self.utxo_arc.ticker }

    fn my_address(&self) -> Result<String, String> { utxo_common::my_address(self) }

    fn my_balance(&self) -> Box<dyn Future<Item = BigDecimal, Error = String> + Send> {
        Box::new(qrc20_balance(self.clone()).boxed().compat())
    }

    fn base_coin_balance(&self) -> Box<dyn Future<Item = BigDecimal, Error = String> + Send> {
        // use standard UTXO my_balance implementation that returns Qtum balance instead of QRC20
        utxo_common::my_balance(&self.utxo_arc)
    }

    fn send_raw_tx(&self, tx: &str) -> Box<dyn Future<Item = String, Error = String> + Send> {
        utxo_common::send_raw_tx(&self.utxo_arc, tx)
    }

    fn wait_for_confirmations(
        &self,
        tx: &[u8],
        confirmations: u64,
        requires_nota: bool,
        wait_until: u64,
        check_every: u64,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        utxo_common::wait_for_confirmations(
            &self.utxo_arc,
            tx,
            confirmations,
            requires_nota,
            wait_until,
            check_every,
        )
    }

    fn wait_for_tx_spend(&self, transaction: &[u8], wait_until: u64, from_block: u64) -> TransactionFut {
        utxo_common::wait_for_tx_spend(&self.utxo_arc, transaction, wait_until, from_block)
    }

    fn tx_enum_from_bytes(&self, bytes: &[u8]) -> Result<TransactionEnum, String> {
        utxo_common::tx_enum_from_bytes(bytes)
    }

    fn current_block(&self) -> Box<dyn Future<Item = u64, Error = String> + Send> {
        utxo_common::current_block(&self.utxo_arc)
    }

    fn address_from_pubkey_str(&self, pubkey: &str) -> Result<String, String> {
        utxo_common::address_from_pubkey_str(self, pubkey)
    }

    fn display_priv_key(&self) -> String { utxo_common::display_priv_key(&self.utxo_arc) }
}

impl MmCoin for Qrc20Coin {
    fn is_asset_chain(&self) -> bool { utxo_common::is_asset_chain(&self.utxo_arc) }

    fn can_i_spend_other_payment(&self) -> Box<dyn Future<Item = (), Error = String> + Send> {
        let decimals = self.utxo_arc.decimals;
        Box::new(self.base_coin_balance().and_then(move |qtum_balance| {
            let sat_balance = try_s!(wei_from_big_decimal(&qtum_balance, decimals));
            let min_amount = QRC20_SWAP_GAS_REQUIRED * QRC20_GAS_PRICE_DEFAULT;
            log!("sat_balance " [sat_balance] " min_amount " [min_amount]);
            if sat_balance < min_amount.into() {
                return ERR!(
                    "Base coin balance {} is too low to cover gas fee, required {}",
                    qtum_balance,
                    big_decimal_from_sat(min_amount as i64, decimals),
                );
            }
            Ok(())
        }))
    }

    fn wallet_only(&self) -> bool { true }

    fn withdraw(&self, req: WithdrawRequest) -> Box<dyn Future<Item = TransactionDetails, Error = String> + Send> {
        Box::new(qrc20_withdraw(self.clone(), req).boxed().compat())
    }

    fn decimals(&self) -> u8 { utxo_common::decimals(&self.utxo_arc) }

    fn convert_to_address(&self, from: &str, to_address_format: Json) -> Result<String, String> {
        qtum::convert_qtum_address(&self.utxo_arc.ticker, from, to_address_format)
    }

    fn validate_address(&self, address: &str) -> ValidateAddressResult { utxo_common::validate_address(self, address) }

    fn process_history_loop(&self, ctx: MmArc) { utxo_common::process_history_loop(self, ctx) }

    fn tx_details_by_hash(&self, hash: &[u8]) -> Box<dyn Future<Item = TransactionDetails, Error = String> + Send> {
        let hash = H256Json::from(hash);
        Box::new(qrc20_tx_details_by_hash(self.clone(), hash).boxed().compat())
    }

    fn history_sync_status(&self) -> HistorySyncState { utxo_common::history_sync_status(&self.utxo_arc) }

    fn get_trade_fee(&self) -> Box<dyn Future<Item = TradeFee, Error = String> + Send> {
        utxo_common::get_trade_fee(self.clone())
    }

    fn required_confirmations(&self) -> u64 { utxo_common::required_confirmations(&self.utxo_arc) }

    fn requires_notarization(&self) -> bool { utxo_common::requires_notarization(&self.utxo_arc) }

    fn set_required_confirmations(&self, confirmations: u64) {
        utxo_common::set_required_confirmations(&self.utxo_arc, confirmations)
    }

    fn set_requires_notarization(&self, requires_nota: bool) {
        utxo_common::set_requires_notarization(&self.utxo_arc, requires_nota)
    }

    fn my_unspendable_balance(&self) -> Box<dyn Future<Item = BigDecimal, Error = String> + Send> {
        // QRC20 cannot have unspendable balance
        Box::new(futures01::future::ok(0.into()))
    }
}

pub fn qrc20_swap_id(time_lock: u32, secret_hash: &[u8]) -> Vec<u8> {
    let mut input = vec![];
    input.extend_from_slice(&time_lock.to_le_bytes());
    input.extend_from_slice(secret_hash);
    sha256(&input).to_vec()
}

pub fn qrc20_addr_from_str(address: &str) -> Result<H160, String> {
    // use deserialization instead of eth::contract_addr_from_str(),
    // because that function fails on some of the QRC20 contract addresses
    Ok(try_s!(json::from_str(&format!("\"{}\"", address))))
}

pub fn qrc20_addr_from_utxo_addr(address: Address) -> H160 { address.hash.take().into() }

fn utxo_addr_into_rpc_format(address: Address) -> H160Json { address.hash.take().into() }

fn qrc20_addr_into_rpc_format(address: &H160) -> H160Json { address.to_vec().as_slice().into() }

async fn qrc20_withdraw(coin: Qrc20Coin, req: WithdrawRequest) -> Result<TransactionDetails, String> {
    let to_addr = try_s!(Address::from_str(&req.to));
    let is_p2pkh =
        to_addr.prefix == coin.utxo_arc.pub_addr_prefix && to_addr.t_addr_prefix == coin.utxo_arc.pub_t_addr_prefix;
    let is_p2sh = to_addr.prefix == coin.utxo_arc.p2sh_addr_prefix
        && to_addr.t_addr_prefix == coin.utxo_arc.p2sh_t_addr_prefix
        && coin.utxo_arc.segwit;
    if !is_p2pkh && !is_p2sh {
        return ERR!("Address {} has invalid format", to_addr);
    }

    let _utxo_lock = UTXO_LOCK.lock().await;

    let qrc20_balance = try_s!(coin.my_balance().compat().await);

    // the qrc20_amount is used only within smart contract calls
    let qrc20_amount = if req.max {
        let amount = try_s!(wei_from_big_decimal(&qrc20_balance, coin.utxo_arc.decimals));
        if amount.is_zero() {
            return ERR!("Balance is 0");
        }
        amount
    } else {
        let amount = try_s!(wei_from_big_decimal(&req.amount, coin.utxo_arc.decimals));
        if amount.is_zero() {
            return ERR!("The amount {} is too small", req.amount);
        }

        // convert balance from big_decimal to U256 to compare it with the amount
        let balance = try_s!(wei_from_big_decimal(&qrc20_balance, coin.utxo_arc.decimals));
        if amount > balance {
            return ERR!(
                "The amount {} to withdraw is larger than balance {}",
                req.amount,
                qrc20_balance
            );
        }
        amount
    };

    let (gas_limit, gas_price) = match req.fee {
        Some(WithdrawFee::Qrc20Gas { gas_limit, gas_price }) => (gas_limit, gas_price),
        Some(_) => return ERR!("Unsupported input fee type"),
        None => (QRC20_GAS_LIMIT_DEFAULT, QRC20_GAS_PRICE_DEFAULT),
    };

    let script_pubkey = try_s!(generate_token_transfer_script_pubkey(
        qrc20_addr_from_utxo_addr(to_addr.clone()),
        qrc20_amount,
        gas_limit,
        gas_price,
        &coin.contract_address
    ))
    .to_bytes();

    // qtum_amount is always 0 for the QRC20, because we should pay only a fee in Qtum to send the QRC20 transaction
    let qtum_amount = 0u64;
    let outputs = vec![TransactionOutput {
        value: qtum_amount,
        script_pubkey,
    }];

    let (signed, fee_details) = try_s!(coin.generate_qrc20_transaction(gas_limit, gas_price, outputs).await);

    let received_by_me = if to_addr == coin.utxo_arc.my_address {
        req.amount.clone()
    } else {
        0.into()
    };
    let my_balance_change = &received_by_me - &req.amount;
    let my_address = try_s!(coin.my_address());
    let to_address = try_s!(coin.display_address(&to_addr));
    Ok(TransactionDetails {
        from: vec![my_address],
        to: vec![to_address],
        total_amount: req.amount.clone(),
        spent_by_me: req.amount,
        received_by_me,
        my_balance_change,
        tx_hash: signed.hash().reversed().to_vec().into(),
        tx_hex: serialize(&signed).into(),
        fee_details: Some(fee_details.into()),
        block_height: 0,
        coin: coin.utxo_arc.ticker.clone(),
        internal_id: vec![].into(),
        timestamp: now_ms() / 1000,
    })
}

async fn qrc20_tx_details_by_hash(coin: Qrc20Coin, hash: H256Json) -> Result<TransactionDetails, String> {
    // TODO it's required by maker_swap::maker_payment() temporary
    return Ok(try_s!(
        utxo_common::tx_details_by_hash(coin.clone(), &hash.0).compat().await
    ));

    let mut receipts = match coin.as_ref().rpc_client {
        UtxoRpcClientEnum::Electrum(ref rpc) => try_s!(rpc.blochchain_transaction_get_receipt(&hash).compat().await),
        UtxoRpcClientEnum::Native(_) => return ERR!("Electrum client expected"),
    };

    if receipts.len() != 1 {
        return ERR!(
            "blochchain.transaction.get_receipt returned {} receipts for {:?} transaction, expected 1",
            receipts.len(),
            hash
        );
    }

    // receipt is one always
    let receipt = receipts.remove(0);

    // request Qtum transaction details to get a tx_hex, timestamp, block_height and miner_fee
    let qtum_tx = try_s!(utxo_common::tx_details_by_hash(coin.clone(), &hash.0).compat().await);
    let script_pubkey: Script = {
        // Deserialize the UtxoTx to get a script pubkey
        let utxo_tx: UtxoTx = try_s!(deserialize(qtum_tx.tx_hex.as_slice()).map_err(|e| ERRL!("{:?}", e)));
        if utxo_tx.outputs.len() <= (receipt.output_index as usize) {
            return ERR!(
                "Length of the transaction {:?} outputs less than output_index {}",
                qtum_tx.tx_hash,
                receipt.output_index
            );
        }

        utxo_tx.outputs[receipt.output_index as usize]
            .script_pubkey
            .clone()
            .into()
    };

    // We can get a log_index from get_history call, but it is overhead to request it on every tx_details_by_hash(),
    // because of this try to find corresponding log entry below
    let log = match receipt.log.into_iter().find(|log_entry| {
        let contract_address = if log_entry.address.starts_with("0x") {
            log_entry.address.clone()
        } else {
            format!("0x{}", log_entry.address)
        };
        match qrc20_addr_from_str(&contract_address) {
            // contract address from the log entry should be equal to the coin's contract address
            Ok(addr) if addr == coin.contract_address => (),
            Ok(_) => return false,
            Err(e) => {
                log!("Error on parse " [contract_address] " contract address " [e]);
                return false;
            },
        }

        // we find a log entry with three and more topics
        if log_entry.topics.len() < 3 {
            return false;
        }
        // the first topic should be ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
        // https://github.com/qtumproject/qtum-electrum/blob/v4.0.2/electrum/wallet.py#L2101
        log_entry.topics.first().unwrap() == QRC20_TRANSFER_TOPIC
    }) {
        Some(log) => log,
        _ => return ERR!("Couldn't find a log entry that meets the requirements"),
    };

    let amount = try_s!(U256::from_str(&log.data));
    // https://github.com/qtumproject/qtum-electrum/blob/v4.0.2/electrum/wallet.py#L2111
    let total_amount = try_s!(u256_to_big_decimal(amount, coin.decimals()));

    // log.topics[i < 3] is safe because of the checking above
    // https://github.com/qtumproject/qtum-electrum/blob/v4.0.2/electrum/wallet.py#L2112
    let from = try_s!(coin.address_from_log_topic(&log.topics[1]));
    // https://github.com/qtumproject/qtum-electrum/blob/v4.0.2/electrum/wallet.py#L2113
    let to = try_s!(coin.address_from_log_topic(&log.topics[2]));

    let spent_by_me = if from == coin.utxo_arc.my_address {
        total_amount.clone()
    } else {
        0.into()
    };
    let received_by_me = if to == coin.utxo_arc.my_address {
        total_amount.clone()
    } else {
        0.into()
    };

    let from = vec![try_s!(coin.display_address(&from))];
    let to = vec![try_s!(coin.display_address(&to))];

    let total_qtum_fee = match qtum_tx.fee_details {
        Some(TxFeeDetails::Utxo(UtxoFeeDetails { amount })) => amount,
        fee => return ERR!("Unexpected fee details {:?}", fee),
    };

    let fee_details = {
        let gas_limit = try_s!(extract_from_script(&script_pubkey, ExtractEnum::GasLimit));
        let gas_price = try_s!(extract_from_script(&script_pubkey, ExtractEnum::GasPrice));

        let total_gas_fee = utxo_common::big_decimal_from_sat(receipt.gas_used, coin.utxo_arc.decimals);
        Qrc20FeeDetails {
            // QRC20 fees are paid in base platform currency (in particular Qtum)
            coin: coin.platform.clone(),
            miner_fee: &total_qtum_fee - &total_gas_fee,
            gas_limit,
            gas_price,
            total_gas_fee,
        }
    };

    // do not inherit the block_height from qtum_tx (usually it is None)
    let block_height = receipt.block_number as u64;

    let my_balance_change = &received_by_me - &spent_by_me;
    Ok(TransactionDetails {
        from,
        to,
        total_amount,
        spent_by_me,
        received_by_me,
        my_balance_change,
        block_height,
        fee_details: Some(fee_details.into()),
        internal_id: vec![].into(),
        ..qtum_tx
    })
}

async fn qrc20_balance(coin: Qrc20Coin) -> Result<BigDecimal, String> {
    let params = &[Token::Address(qrc20_addr_from_utxo_addr(
        coin.utxo_arc.my_address.clone(),
    ))];
    let tokens = try_s!(coin.contract_call("balanceOf", params).await);

    if tokens.is_empty() {
        return ERR!(r#"Expected Uint as "balanceOf" result but got nothing"#);
    }

    match tokens[0] {
        Token::Uint(bal) => u256_to_big_decimal(bal, coin.utxo_arc.decimals),
        _ => ERR!(r#"Expected Uint as "balanceOf" result but got {:?}"#, tokens),
    }
}

async fn qrc20_send_hash_time_locked_payment(
    coin: Qrc20Coin,
    id: Vec<u8>,
    value: U256,
    time_lock: u32,
    secret_hash: Vec<u8>,
    receiver_addr: H160,
) -> Result<TransactionEnum, String> {
    let allowance = try_s!(coin.allowance(coin.swap_contract_address).await);

    let mut outputs = Vec::default();
    // check if we should reset the allowance to 0 and raise this to the max available value (our balance)
    if allowance < value {
        let balance = try_s!(coin.my_balance().compat().await);
        let balance = try_s!(wei_from_big_decimal(&balance, coin.utxo_arc.decimals));
        // first reset the allowance to the 0
        outputs.push(try_s!(coin.approve_output(coin.swap_contract_address, 0.into())));
        // set the allowance from 0 to `balance` after the previous output will be executed
        outputs.push(try_s!(coin.approve_output(coin.swap_contract_address, balance)));
    }

    // when this output is executed, the allowance will be sufficient allready
    outputs.push(try_s!(coin.erc20_payment_output(
        id,
        value,
        time_lock,
        &secret_hash,
        receiver_addr
    )));

    coin.send_contract_calls(outputs).await
}

async fn qrc20_wait_for_swap_payment_confirmations(
    coin: Qrc20Coin,
    tx: Vec<u8>,
    confirmations: u64,
    requires_nota: bool,
    wait_until: u64,
    check_every: u64,
) -> Result<(), String> {
    let utxo_tx: UtxoTx = try_s!(deserialize(tx.as_slice()).map_err(|e| ERRL!("{:?}", e)));
    try_s!(
        utxo_common::wait_for_confirmations(
            &coin.utxo_arc,
            &tx,
            confirmations,
            requires_nota,
            wait_until,
            check_every,
        )
        .compat()
        .await
    );
    coin.validate_swap_contract_call(&utxo_tx, "erc20Payment").await
}

/// Serialize the `number` similar to BigEndian but in QRC20 specific format.
fn encode_contract_number(number: i64) -> Vec<u8> {
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
        encoded.push({
            if is_negative {
                0x80
            } else {
                0
            }
        });
    } else if is_negative {
        *encoded.last_mut().unwrap() |= 0x80;
    }

    encoded
}

fn decode_contract_number(source: &[u8]) -> Result<i64, String> {
    macro_rules! try_opt {
        ($e: expr) => {
            match $e {
                Some(x) => x,
                _ => return ERR!("Couldn't decode the input {:?}", source),
            }
        };
    }

    if source.is_empty() {
        return Ok(0);
    }

    let mut data = source.to_vec();

    // let last_byte = data.pop().unwrap();
    let mut decoded = 0i128;

    // first pop the data last byte
    let (is_negative, last_byte) = match data.pop().unwrap() {
        // this last byte is the sign byte, pop the real last byte
        0x80 => (true, try_opt!(data.pop())),
        // this last byte is the sign byte, pop the real last byte
        0 => (false, try_opt!(data.pop())),
        // this last byte is real, do XOR on it because it's greater than 0x80
        last_byte if 0x80 < last_byte => (true, last_byte ^ 0x80),
        // this last byte is real, returns it
        last_byte => (false, last_byte),
    };

    // push the last_byte back to the data array
    data.push(last_byte);

    for byte in data.iter().rev() {
        decoded <<= 8;
        decoded |= *byte as i128;
    }

    if is_negative {
        let decoded = decoded.neg();
        Ok(decoded as i64)
    } else {
        Ok(decoded as i64)
    }
}

fn generate_token_transfer_script_pubkey(
    to_addr: H160,
    amount: U256,
    gas_limit: u64,
    gas_price: u64,
    token_addr: &[u8],
) -> Result<Script, String> {
    let function = try_s!(ERC20_CONTRACT.function("transfer"));
    let function_call = try_s!(function.encode_input(&[Token::Address(to_addr), Token::Uint(amount)]));

    generate_contract_call_script_pubkey(&function_call, gas_limit, gas_price, token_addr)
}

/// Generate a script_pubkey contains a `function_call` from the specified `contract_address`.
/// The `contract_address` can be either Token address (QRC20) or Swap contract address (EtomicSwap).
fn generate_contract_call_script_pubkey(
    function_call: &[u8],
    gas_limit: u64,
    gas_price: u64,
    contract_address: &[u8],
) -> Result<Script, String> {
    if gas_limit == 0 || gas_price == 0 {
        // this is because the `contract_encode_number` will return an empty bytes
        return ERR!("gas_limit and gas_price cannot be zero");
    }

    if contract_address.is_empty() {
        // this is because the `push_bytes` will panic
        return ERR!("token_addr cannot be empty");
    }

    let gas_limit = encode_contract_number(gas_limit as i64);
    let gas_price = encode_contract_number(gas_price as i64);

    Ok(Builder::default()
        .push_opcode(Opcode::OP_4)
        .push_bytes(&gas_limit)
        .push_bytes(&gas_price)
        .push_data(function_call)
        .push_bytes(contract_address)
        .push_opcode(Opcode::OP_CALL)
        .into_script())
}

/// The `extract_gas_limit_from_script_pubkey` helper.
#[derive(Clone, Copy, Debug)]
enum ExtractEnum {
    GasLimit = 1,
    GasPrice = 2,
}

/// Check if a given script contains a contract call.
/// First opcode should be OP_4 to be a contract call.
fn is_contract_call(script: &Script) -> bool {
    match script.iter().next() {
        Some(Ok(instr)) => instr.opcode == Opcode::OP_4,
        _ => false,
    }
}

fn extract_from_script(script: &Script, extract: ExtractEnum) -> Result<u64, String> {
    let instruction = try_s!(script
        .iter()
        .enumerate()
        .find_map(|(i, instr)| {
            if i == extract as usize {
                Some(instr.unwrap())
            } else {
                None
            }
        })
        .ok_or(ERRL!("Couldn't extract {:?} from script pubkey", extract)));

    let opcode = instruction.opcode as usize;
    if !(1..75).contains(&opcode) {
        return ERR!("Opcode::OP_PUSHBYTES_[X] expected, found {:?}", instruction.opcode);
    }

    let number = match instruction.data {
        Some(d) => try_s!(decode_contract_number(d)),
        _ => return ERR!("Non-empty instruction data expected"),
    };

    Ok(number as u64)
}

fn extract_contract_call_from_script(script: &Script) -> Result<Bytes, String> {
    const CONTRACT_CALL_IDX: usize = 3;
    let instruction = try_s!(script
        .iter()
        .enumerate()
        .find_map(|(i, instr)| {
            match instr {
                Ok(instr) if i == CONTRACT_CALL_IDX => Some(instr),
                _ => None,
            }
        })
        .ok_or(ERRL!("Couldn't extract {:?} from script pubkey", CONTRACT_CALL_IDX)));

    match instruction.opcode {
        Opcode::OP_PUSHDATA1 | Opcode::OP_PUSHDATA2 | Opcode::OP_PUSHDATA4 => (),
        opcode if (1..75).contains(&(opcode as usize)) => (),
        _ => return ERR!("Unexpected instruction's opcode {}", instruction.opcode),
    }

    instruction
        .data
        .ok_or(ERRL!("An empty contract call data"))
        .map(Bytes::from)
}

#[cfg(test)]
mod qtum_tests {
    use super::*;
    use crate::{eth::u256_to_big_decimal, utxo::utxo_tests::electrum_client_for_test};
    use ethabi::Token;
    use keys::Address;

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

        let actual_token_info = client
            .blockchain_token_get_info(&addr.as_slice().into())
            .wait()
            .unwrap();
        assert_eq!(expected_token_info, actual_token_info);
    }

    #[test]
    fn get_token_balance_using_contract_call() {
        let client = electrum_client_for_test(&["95.217.83.126:10001"]);
        let token_addr = hex::decode("d362e096e873eb7907e205fadc6175c6fec7bc44").unwrap();
        let our_addr: Address = "qKEDGuogDhtH9zBnc71QtqT1KDamaR1KJ3".parse().unwrap();
        log!((our_addr.prefix));
        let function = unwrap!(ERC20_CONTRACT.function("balanceOf"));
        let data = unwrap!(function.encode_input(&[Token::Address(our_addr.hash.take().into()),]));
        let balance = client
            .blockchain_contract_call(&token_addr.as_slice().into(), data.into())
            .wait()
            .unwrap();
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
        let to_addr: Address = "qHmJ3KA6ZAjR9wGjpFASn4gtUSeFAqdZgs".into();
        let to_addr = qrc20_addr_from_utxo_addr(to_addr);
        let amount: U256 = 1000000000.into();
        let gas_limit = 2_500_000;
        let gas_price = 40;
        let token_addr = hex::decode("d362e096e873eb7907e205fadc6175c6fec7bc44").unwrap();
        let actual = generate_token_transfer_script_pubkey(to_addr, amount, gas_limit, gas_price, &token_addr).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_generate_token_transfer_script_pubkey_err() {
        let to_addr: Address = "qHmJ3KA6ZAjR9wGjpFASn4gtUSeFAqdZgs".into();
        let to_addr = qrc20_addr_from_utxo_addr(to_addr);
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
        )
        .is_err());

        assert!(generate_token_transfer_script_pubkey(
            to_addr.clone(),
            amount,
            gas_limit,
            0, // gas_price cannot be zero
            &token_addr,
        )
        .is_err());

        assert!(generate_token_transfer_script_pubkey(
            to_addr,
            amount,
            gas_limit,
            gas_price,
            &[], // token_addr cannot be empty
        )
        .is_err());
    }

    #[test]
    fn test_encode_decode_contract_number() {
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

        for (source, encoded) in numbers {
            println!("{}", source);
            let actual_encoded = encode_contract_number(source);
            assert_eq!(actual_encoded, encoded);
            let actual_decoded = unwrap!(decode_contract_number(&encoded));
            assert_eq!(actual_decoded, source);
        }
    }

    #[test]
    fn test_extract_gas_limit_gas_price() {
        let script: Script = "5403a02526012844a9059cbb0000000000000000000000000240b898276ad2cc0d2fe6f527e8e31104e7fde3000000000000000000000000000000000000000000000000000000003b9aca0014d362e096e873eb7907e205fadc6175c6fec7bc44c2".into();

        let expected_gas_limit = 2_500_000;
        let actual = unwrap!(extract_from_script(&script, ExtractEnum::GasLimit));
        assert_eq!(actual, expected_gas_limit);

        let expected_gas_price = 40;
        let actual = unwrap!(extract_from_script(&script, ExtractEnum::GasPrice));
        assert_eq!(actual, expected_gas_price);
    }

    #[test]
    fn test_extract_contract_call() {
        let script: Script = "5403a02526012844a9059cbb0000000000000000000000000240b898276ad2cc0d2fe6f527e8e31104e7fde3000000000000000000000000000000000000000000000000000000003b9aca0014d362e096e873eb7907e205fadc6175c6fec7bc44c2".into();

        let to_addr: Address = "qHmJ3KA6ZAjR9wGjpFASn4gtUSeFAqdZgs".into();
        let to_addr = qrc20_addr_from_utxo_addr(to_addr);
        let amount: U256 = 1000000000.into();
        let function = ERC20_CONTRACT.function("transfer").unwrap();
        let expected = function
            .encode_input(&[Token::Address(to_addr), Token::Uint(amount)])
            .unwrap();

        let actual = unwrap!(extract_contract_call_from_script(&script));
        assert_eq!(actual.to_vec(), expected);

        // TX b11a262380657310abf01f8abe117da2c2adf788ab1fa0fa29da4ab505fc00c0
        let tx = unwrap!(hex::decode("01000000029ba0865fc62aac1f5f1a4aac3c9f54ff3d74211030bf6eb41e870b30297bd3fc010000006a47304402201808cbc98036ea63d32e858f776c722897d3f4b670744594deba25b69128d0ba02207b3f86f0ab6b6fa0ff581dc7be33af034c6004f3537a2f96c4ddf3ed0130defc012103693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9ffffffff63574ffa1e8edd8af8b08f3c1d8e5f33170772c38631a50ddc29c16d74c762f6020000006b483045022100db6cf963f6be56f7c6004ede74d452b2c5932eb6b12094fe67fa4ff0b6f4406e02207acff9163588a0c58fa009f5e876f90817b4006c303095d9b6425aae2922a485012103693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9ffffffff040000000000000000625403a08601012844095ea7b3000000000000000000000000ba8b71f3544b93e2f681f996da519a98ace0107a000000000000000000000000000000000000000000000000000000000000000014d362e096e873eb7907e205fadc6175c6fec7bc44c20000000000000000625403a08601012844095ea7b3000000000000000000000000ba8b71f3544b93e2f681f996da519a98ace0107a0000000000000000000000000000000000000000000000000000000001312d0014d362e096e873eb7907e205fadc6175c6fec7bc44c20000000000000000e35403a0860101284cc49b415b2a65e285b98480fd7de696e9fb5bcb68ec9468dd906c683e38cabb8f39905675fa0000000000000000000000000000000000000000000000000000000001312d00000000000000000000000000d362e096e873eb7907e205fadc6175c6fec7bc440000000000000000000000000240b898276ad2cc0d2fe6f527e8e31104e7fde30101010101010101010101010101010101010101000000000000000000000000000000000000000000000000000000000000000000000000000000005f6d80b814ba8b71f3544b93e2f681f996da519a98ace0107ac2e52fdd05000000001976a9149e032d4b0090a11dc40fe6c47601499a35d55fbb88ac82816d5f"));
        let utxo_tx: UtxoTx = unwrap!(deserialize(tx.as_slice()));

        // first output in "b11a262380657310abf01f8abe117da2c2adf788ab1fa0fa29da4ab505fc00c0"
        // `approve` to 0 contract call
        let expected = unwrap!(hex::decode("095ea7b3000000000000000000000000ba8b71f3544b93e2f681f996da519a98ace0107a0000000000000000000000000000000000000000000000000000000000000000"));
        let script = utxo_tx.outputs[0].script_pubkey.clone().into();

        let actual = unwrap!(extract_contract_call_from_script(&script));
        assert_eq!(actual.to_vec(), expected);

        // second output in "b11a262380657310abf01f8abe117da2c2adf788ab1fa0fa29da4ab505fc00c0"
        // `approve` to 20000000 contract call
        let expected = unwrap!(hex::decode("095ea7b3000000000000000000000000ba8b71f3544b93e2f681f996da519a98ace0107a0000000000000000000000000000000000000000000000000000000001312d00"));
        let script = utxo_tx.outputs[1].script_pubkey.clone().into();

        let actual = unwrap!(extract_contract_call_from_script(&script));
        assert_eq!(actual.to_vec(), expected);

        // third output in "b11a262380657310abf01f8abe117da2c2adf788ab1fa0fa29da4ab505fc00c0"
        // `erc20Payment` 20000000 amount contract call
        let expected = unwrap!(hex::decode("9b415b2a65e285b98480fd7de696e9fb5bcb68ec9468dd906c683e38cabb8f39905675fa0000000000000000000000000000000000000000000000000000000001312d00000000000000000000000000d362e096e873eb7907e205fadc6175c6fec7bc440000000000000000000000000240b898276ad2cc0d2fe6f527e8e31104e7fde30101010101010101010101010101010101010101000000000000000000000000000000000000000000000000000000000000000000000000000000005f6d80b8"));
        let script = utxo_tx.outputs[2].script_pubkey.clone().into();

        let actual = unwrap!(extract_contract_call_from_script(&script));
        assert_eq!(actual.to_vec(), expected);
    }
}
