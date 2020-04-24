use common::jsonrpc_client::{JsonRpcClient, JsonRpcRequest, RpcRes};
use crate::utxo::rpc_clients::ElectrumClient;
use futures01::future::Future;
use rpc::v1::types::{Bytes as BytesJson, H160 as H160Json};
use serde_json::{self as json, Value as Json};

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

#[cfg(test)]
mod qtum_tests {
    use crate::{
        eth::{ERC20_CONTRACT, u256_to_big_decimal},
        utxo::utxo_tests::electrum_client_for_test
    };
    use ethabi::Token;
    use keys::Address;
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
        let our_addr: Address = "qXxsj5RtciAby9T7m98AgAATL4zTi4UwDG".parse().unwrap();
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
        assert_eq!(balance, "9999989.99999".parse().unwrap());
    }
}
