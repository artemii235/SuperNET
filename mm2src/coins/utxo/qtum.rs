use common::jsonrpc_client::{JsonRpcClient, JsonRpcRequest, RpcRes};
use crate::utxo::rpc_clients::ElectrumClient;
use futures01::future::Future;
use rpc::v1::types::{Bytes as BytesJson, H160 as H160Json};
use serde_json::{self as json, Value as Json};
use keys::Address;
use bigdecimal::BigDecimal;

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

fn generate_token_transfer_script_pubkey(
    to_addr: &Address,
    amount: &BigDecimal,
    gas_limit: u64,
    gas_price: u64,
    token_addr: &[u8],
) -> String {
    use script::Opcode;
    log!([Opcode::OP_CREATE]);
    unimplemented!();
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
    use bigdecimal::BigDecimal;
    use crate::utxo::UtxoTx;

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

    #[test]
    fn generate_transfer_tokens_script_pubkey() {
        // sample QRC20 transfer from https://testnet.qtum.info/tx/71cf16ac4919ffc5f66676c57a465ed0edfe09316d326be094cdb2c8f85ded08
        // port QTUM electrum wallet do_token_pay implementation: https://github.com/qtumproject/qtum-electrum/blob/master/electrum/gui/qt/main_window.py#L3174
        let tx: UtxoTx = "01000000025e84e9fb76904ad52a8f2c3422128bddf5d1e7a9b9d50e30c7671943f04df1200b0000006b483045022100a4038f1c21b30ab833c68be0cc45c5bc57a28d73e9f5f53f962ad1e17fd95a1102204ec10fd460cf58cd078d6faad9a22521cf39325a210dceb9f2d2dc77f89f3e72012103693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9fffffffff2daeef9bc4eac8a4db8362d15be51a4a97968a5bfb3cd7dec4c2c93c49cead4010000006b483045022100e5de2713c9362027f3338d67c207d11e96657c4b55c62ffba6b77fd8ab331a45022004e69afe13fbeb813effec9bc83eb8ff9e15c8551ea9819406054386c26f24f7012103693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9ffffffff020000000000000000625403a02526012844a9059cbb0000000000000000000000000240b898276ad2cc0d2fe6f527e8e31104e7fde3000000000000000000000000000000000000000000000000000000003b9aca0014d362e096e873eb7907e205fadc6175c6fec7bc44c21847efb5000000001976a9149e032d4b0090a11dc40fe6c47601499a35d55fbb88ac00000000".into();
        log!([tx]);

        let expected = "5403a02526012844a9059cbb0000000000000000000000000240b898276ad2cc0d2fe6f527e8e31104e7fde3000000000000000000000000000000000000000000000000000000003b9aca0014d362e096e873eb7907e205fadc6175c6fec7bc44c2";
        let to_addr = "qHmJ3KA6ZAjR9wGjpFASn4gtUSeFAqdZgs".into();
        let amount: BigDecimal = 1.into();
        let gas_limit = 250000;
        let gas_price = 40;
        let token_addr = hex::decode("d362e096e873eb7907e205fadc6175c6fec7bc44").unwrap();
        let actual = generate_token_transfer_script_pubkey(
            &to_addr,
            &amount,
            gas_limit,
            gas_price,
            &token_addr,
        );
        assert_eq!(expected, actual);
    }
}
