use common::jsonrpc_client::{JsonRpcClient, JsonRpcRequest, RpcRes};
use crate::eth::ERC20_CONTRACT;
use crate::utxo::rpc_clients::ElectrumClient;
use ethabi::Token;
use ethereum_types::U256;
use futures01::future::Future;
use keys::Address;
use rpc::v1::types::{Bytes as BytesJson, H160 as H160Json};
use serde_json::{self as json, Value as Json};
use script::{Builder, Opcode, Script};

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

/// Serialize the `number` similar to BigEndian but in QRC20 specific format.
pub fn contract_encode_number(number: i64) -> Vec<u8> {
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

#[cfg(test)]
mod qtum_tests {
    use crate::{
        eth::u256_to_big_decimal,
        utxo::utxo_tests::electrum_client_for_test,
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
}
