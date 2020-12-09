#![feature(custom_test_frameworks)]
#![feature(test)]
#![test_runner(docker_tests_runner)]
#![feature(drain_filter)]
#![feature(non_ascii_idents)]
#![recursion_limit = "512"]

#[cfg(test)] use docker_tests::docker_tests_runner;
#[cfg(test)]
#[macro_use]
extern crate common;
#[cfg(test)]
#[macro_use]
extern crate fomat_macros;
#[cfg(test)]
#[macro_use]
extern crate gstuff;
#[cfg(test)]
#[macro_use]
extern crate lazy_static;
#[cfg(test)]
#[macro_use]
extern crate serde_json;
#[cfg(test)]
#[macro_use]
extern crate serde_derive;
#[cfg(test)]
#[macro_use]
extern crate serialization_derive;
#[cfg(test)] extern crate test;
#[cfg(test)]
#[macro_use]
extern crate unwrap;

#[cfg(test)]
#[path = "mm2.rs"]
pub mod mm2;

fn main() { unimplemented!() }

/// rustfmt cannot resolve the module path within docker_tests.
/// Specify the path manually outside the docker_tests.
#[cfg(rustfmt)]
#[path = "docker_tests/swaps_confs_settings_sync_tests.rs"]
mod swaps_confs_settings_sync_tests;

#[cfg(rustfmt)]
#[path = "docker_tests/swaps_file_lock_tests.rs"]
mod swaps_file_lock_tests;

#[cfg(all(test, feature = "native"))]
mod docker_tests {
    #[rustfmt::skip]
    mod swaps_confs_settings_sync_tests;
    #[rustfmt::skip]
    mod swaps_file_lock_tests;

    use bigdecimal::BigDecimal;
    use bitcrypto::ChecksumType;
    use coins::qrc20::rpc_client::{Qrc20NativeOps, Qrc20NativeWalletOps};
    use coins::qrc20::{qrc20_coin_from_conf_and_request, Qrc20Coin};
    use coins::utxo::qtum::{qtum_coin_from_conf_and_request, QtumCoin};
    use coins::utxo::rpc_clients::{UtxoRpcClientEnum, UtxoRpcClientOps};
    use coins::utxo::utxo_standard::{utxo_standard_coin_from_conf_and_request, UtxoStandardCoin};
    use coins::utxo::{coin_daemon_data_dir, dhash160, sat_from_big_decimal, zcash_params_path, UtxoCoinFields,
                      UtxoCommonOps};
    use coins::{FoundSwapTxSpend, MarketCoinOps, SwapOps};
    use common::block_on;
    use common::{file_lock::FileLock,
                 for_tests::{enable_native, mm_dump, new_mm2_temp_folder_path, MarketMakerIt},
                 mm_ctx::{MmArc, MmCtxBuilder}};
    use ethereum_types::H160;
    use futures01::Future;
    use gstuff::now_ms;
    use keys::{KeyPair, Private};
    use secp256k1::SecretKey;
    use serde_json::{self as json, Value as Json};
    use std::env;
    use std::io::{BufRead, BufReader};
    use std::process::Command;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use test::{test_main, StaticBenchFn, StaticTestFn, TestDescAndFn};
    use testcontainers::clients::Cli;
    use testcontainers::images::generic::{GenericImage, WaitFor};
    use testcontainers::{Container, Docker, Image};

    const QRC20_TOKEN_BYTES: &str = "6080604052600860ff16600a0a633b9aca000260005534801561002157600080fd5b50600054600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550610c69806100776000396000f3006080604052600436106100a4576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806306fdde03146100a9578063095ea7b31461013957806318160ddd1461019e57806323b872dd146101c9578063313ce5671461024e5780635a3b7e421461027f57806370a082311461030f57806395d89b4114610366578063a9059cbb146103f6578063dd62ed3e1461045b575b600080fd5b3480156100b557600080fd5b506100be6104d2565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156100fe5780820151818401526020810190506100e3565b50505050905090810190601f16801561012b5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561014557600080fd5b50610184600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019092919050505061050b565b604051808215151515815260200191505060405180910390f35b3480156101aa57600080fd5b506101b36106bb565b6040518082815260200191505060405180910390f35b3480156101d557600080fd5b50610234600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506106c1565b604051808215151515815260200191505060405180910390f35b34801561025a57600080fd5b506102636109a1565b604051808260ff1660ff16815260200191505060405180910390f35b34801561028b57600080fd5b506102946109a6565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156102d45780820151818401526020810190506102b9565b50505050905090810190601f1680156103015780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561031b57600080fd5b50610350600480360381019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506109df565b6040518082815260200191505060405180910390f35b34801561037257600080fd5b5061037b6109f7565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156103bb5780820151818401526020810190506103a0565b50505050905090810190601f1680156103e85780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561040257600080fd5b50610441600480360381019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610a30565b604051808215151515815260200191505060405180910390f35b34801561046757600080fd5b506104bc600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610be1565b6040518082815260200191505060405180910390f35b6040805190810160405280600881526020017f515243205445535400000000000000000000000000000000000000000000000081525081565b60008260008173ffffffffffffffffffffffffffffffffffffffff161415151561053457600080fd5b60008314806105bf57506000600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054145b15156105ca57600080fd5b82600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508373ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925856040518082815260200191505060405180910390a3600191505092915050565b60005481565b60008360008173ffffffffffffffffffffffffffffffffffffffff16141515156106ea57600080fd5b8360008173ffffffffffffffffffffffffffffffffffffffff161415151561071157600080fd5b610797600260008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205485610c06565b600260008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550610860600160008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205485610c06565b600160008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506108ec600160008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205485610c1f565b600160008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508473ffffffffffffffffffffffffffffffffffffffff168673ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef866040518082815260200191505060405180910390a36001925050509392505050565b600881565b6040805190810160405280600981526020017f546f6b656e20302e31000000000000000000000000000000000000000000000081525081565b60016020528060005260406000206000915090505481565b6040805190810160405280600381526020017f515443000000000000000000000000000000000000000000000000000000000081525081565b60008260008173ffffffffffffffffffffffffffffffffffffffff1614151515610a5957600080fd5b610aa2600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205484610c06565b600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550610b2e600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205484610c1f565b600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508373ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef856040518082815260200191505060405180910390a3600191505092915050565b6002602052816000526040600020602052806000526040600020600091509150505481565b6000818310151515610c1457fe5b818303905092915050565b6000808284019050838110151515610c3357fe5b80915050929150505600a165627a7a723058207f2e5248b61b80365ea08a0f6d11ac0b47374c4dfd538de76bc2f19591bbbba40029";
    const QRC20_SWAP_CONTRACT_BYTES: &str = "608060405234801561001057600080fd5b50611437806100206000396000f3fe60806040526004361061004a5760003560e01c806302ed292b1461004f5780630716326d146100de578063152cf3af1461017b57806346fc0294146101f65780639b415b2a14610294575b600080fd5b34801561005b57600080fd5b506100dc600480360360a081101561007257600080fd5b81019080803590602001909291908035906020019092919080359060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610339565b005b3480156100ea57600080fd5b506101176004803603602081101561010157600080fd5b8101908080359060200190929190505050610867565b60405180846bffffffffffffffffffffffff19166bffffffffffffffffffffffff191681526020018367ffffffffffffffff1667ffffffffffffffff16815260200182600381111561016557fe5b60ff168152602001935050505060405180910390f35b6101f46004803603608081101561019157600080fd5b8101908080359060200190929190803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080356bffffffffffffffffffffffff19169060200190929190803567ffffffffffffffff1690602001909291905050506108bf565b005b34801561020257600080fd5b50610292600480360360a081101561021957600080fd5b81019080803590602001909291908035906020019092919080356bffffffffffffffffffffffff19169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610bd9565b005b610337600480360360c08110156102aa57600080fd5b810190808035906020019092919080359060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080356bffffffffffffffffffffffff19169060200190929190803567ffffffffffffffff169060200190929190505050610fe2565b005b6001600381111561034657fe5b600080878152602001908152602001600020600001601c9054906101000a900460ff16600381111561037457fe5b1461037e57600080fd5b6000600333836003600288604051602001808281526020019150506040516020818303038152906040526040518082805190602001908083835b602083106103db57805182526020820191506020810190506020830392506103b8565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa15801561041d573d6000803e3d6000fd5b5050506040513d602081101561043257600080fd5b8101908080519060200190929190505050604051602001808281526020019150506040516020818303038152906040526040518082805190602001908083835b602083106104955780518252602082019150602081019050602083039250610472565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa1580156104d7573d6000803e3d6000fd5b5050506040515160601b8689604051602001808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660601b81526014018573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660601b8152601401846bffffffffffffffffffffffff19166bffffffffffffffffffffffff191681526014018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660601b8152601401828152602001955050505050506040516020818303038152906040526040518082805190602001908083835b602083106105fc57805182526020820191506020810190506020830392506105d9565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa15801561063e573d6000803e3d6000fd5b5050506040515160601b905060008087815260200190815260200160002060000160009054906101000a900460601b6bffffffffffffffffffffffff1916816bffffffffffffffffffffffff19161461069657600080fd5b6002600080888152602001908152602001600020600001601c6101000a81548160ff021916908360038111156106c857fe5b0217905550600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16141561074e573373ffffffffffffffffffffffffffffffffffffffff166108fc869081150290604051600060405180830381858888f19350505050158015610748573d6000803e3d6000fd5b50610820565b60008390508073ffffffffffffffffffffffffffffffffffffffff1663a9059cbb33886040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b1580156107da57600080fd5b505af11580156107ee573d6000803e3d6000fd5b505050506040513d602081101561080457600080fd5b810190808051906020019092919050505061081e57600080fd5b505b7f36c177bcb01c6d568244f05261e2946c8c977fa50822f3fa098c470770ee1f3e8685604051808381526020018281526020019250505060405180910390a1505050505050565b60006020528060005260406000206000915090508060000160009054906101000a900460601b908060000160149054906101000a900467ffffffffffffffff169080600001601c9054906101000a900460ff16905083565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16141580156108fc5750600034115b801561094057506000600381111561091057fe5b600080868152602001908152602001600020600001601c9054906101000a900460ff16600381111561093e57fe5b145b61094957600080fd5b60006003843385600034604051602001808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660601b81526014018573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660601b8152601401846bffffffffffffffffffffffff19166bffffffffffffffffffffffff191681526014018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660601b8152601401828152602001955050505050506040516020818303038152906040526040518082805190602001908083835b60208310610a6c5780518252602082019150602081019050602083039250610a49565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa158015610aae573d6000803e3d6000fd5b5050506040515160601b90506040518060600160405280826bffffffffffffffffffffffff191681526020018367ffffffffffffffff16815260200160016003811115610af757fe5b81525060008087815260200190815260200160002060008201518160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908360601c021790555060208201518160000160146101000a81548167ffffffffffffffff021916908367ffffffffffffffff160217905550604082015181600001601c6101000a81548160ff02191690836003811115610b9357fe5b02179055509050507fccc9c05183599bd3135da606eaaf535daffe256e9de33c048014cffcccd4ad57856040518082815260200191505060405180910390a15050505050565b60016003811115610be657fe5b600080878152602001908152602001600020600001601c9054906101000a900460ff166003811115610c1457fe5b14610c1e57600080fd5b600060038233868689604051602001808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660601b81526014018573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660601b8152601401846bffffffffffffffffffffffff19166bffffffffffffffffffffffff191681526014018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660601b8152601401828152602001955050505050506040516020818303038152906040526040518082805190602001908083835b60208310610d405780518252602082019150602081019050602083039250610d1d565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa158015610d82573d6000803e3d6000fd5b5050506040515160601b905060008087815260200190815260200160002060000160009054906101000a900460601b6bffffffffffffffffffffffff1916816bffffffffffffffffffffffff1916148015610e10575060008087815260200190815260200160002060000160149054906101000a900467ffffffffffffffff1667ffffffffffffffff164210155b610e1957600080fd5b6003600080888152602001908152602001600020600001601c6101000a81548160ff02191690836003811115610e4b57fe5b0217905550600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff161415610ed1573373ffffffffffffffffffffffffffffffffffffffff166108fc869081150290604051600060405180830381858888f19350505050158015610ecb573d6000803e3d6000fd5b50610fa3565b60008390508073ffffffffffffffffffffffffffffffffffffffff1663a9059cbb33886040518363ffffffff1660e01b8152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200192505050602060405180830381600087803b158015610f5d57600080fd5b505af1158015610f71573d6000803e3d6000fd5b505050506040513d6020811015610f8757600080fd5b8101908080519060200190929190505050610fa157600080fd5b505b7f1797d500133f8e427eb9da9523aa4a25cb40f50ebc7dbda3c7c81778973f35ba866040518082815260200191505060405180910390a1505050505050565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff161415801561101f5750600085115b801561106357506000600381111561103357fe5b600080888152602001908152602001600020600001601c9054906101000a900460ff16600381111561106157fe5b145b61106c57600080fd5b60006003843385888a604051602001808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660601b81526014018573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660601b8152601401846bffffffffffffffffffffffff19166bffffffffffffffffffffffff191681526014018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660601b8152601401828152602001955050505050506040516020818303038152906040526040518082805190602001908083835b6020831061118e578051825260208201915060208101905060208303925061116b565b6001836020036101000a038019825116818451168082178552505050505050905001915050602060405180830381855afa1580156111d0573d6000803e3d6000fd5b5050506040515160601b90506040518060600160405280826bffffffffffffffffffffffff191681526020018367ffffffffffffffff1681526020016001600381111561121957fe5b81525060008089815260200190815260200160002060008201518160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908360601c021790555060208201518160000160146101000a81548167ffffffffffffffff021916908367ffffffffffffffff160217905550604082015181600001601c6101000a81548160ff021916908360038111156112b557fe5b021790555090505060008590508073ffffffffffffffffffffffffffffffffffffffff166323b872dd33308a6040518463ffffffff1660e01b8152600401808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018281526020019350505050602060405180830381600087803b15801561137d57600080fd5b505af1158015611391573d6000803e3d6000fd5b505050506040513d60208110156113a757600080fd5b81019080805190602001909291905050506113c157600080fd5b7fccc9c05183599bd3135da606eaaf535daffe256e9de33c048014cffcccd4ad57886040518082815260200191505060405180910390a1505050505050505056fea265627a7a723158208c83db436905afce0b7be1012be64818c49323c12d451fe2ab6bce76ff6421c964736f6c63430005110032";
    const QTUM_ADDRESS_LABEL: &str = "MM2_ADDRESS_LABEL";

    static mut QICK_TOKEN_ADDRESS: Option<H160> = None;
    static mut QORTY_TOKEN_ADDRESS: Option<H160> = None;
    static mut QRC20_SWAP_CONTRACT_ADDRESS: Option<H160> = None;

    // AP: custom test runner is intended to initialize the required environment (e.g. coin daemons in the docker containers)
    // and then gracefully clear it by dropping the RAII docker container handlers
    // I've tried to use static for such singleton initialization but it turned out that despite
    // rustc allows to use Drop as static the drop fn won't ever be called
    // NB: https://github.com/rust-lang/rfcs/issues/1111
    // the only preparation step required is Zcash params files downloading:
    // Windows - https://github.com/KomodoPlatform/komodo/blob/master/zcutil/fetch-params.bat
    // Linux and MacOS - https://github.com/KomodoPlatform/komodo/blob/master/zcutil/fetch-params.sh
    pub fn docker_tests_runner(tests: &[&TestDescAndFn]) {
        // pretty_env_logger::try_init();
        let docker = Cli::default();
        let mut containers = vec![];
        // skip Docker containers initialization if we are intended to run test_mm_start only
        if std::env::var("_MM2_TEST_CONF").is_err() {
            pull_docker_container("artempikulin/testblockchain");
            remove_docker_containers("artempikulin/testblockchain");

            let utxo_node = utxo_asset_docker_node(&docker, "MYCOIN", 7000);
            let utxo_node1 = utxo_asset_docker_node(&docker, "MYCOIN1", 8000);
            let qtum_node = qtum_docker_node(&docker, 9000);

            let utxo_ops = UtxoAssetDockerOps::from_ticker("MYCOIN");
            let utxo_ops1 = UtxoAssetDockerOps::from_ticker("MYCOIN1");
            let qtum_ops = QtumDockerOps::new();

            utxo_ops.wait_ready();
            utxo_ops1.wait_ready();
            qtum_ops.wait_ready();
            qtum_ops.initialize_contracts();

            containers.push(utxo_node);
            containers.push(utxo_node1);
            containers.push(qtum_node);
        }
        // detect if docker is installed
        // skip the tests that use docker if not installed
        let owned_tests: Vec<_> = tests
            .iter()
            .map(|t| match t.testfn {
                StaticTestFn(f) => TestDescAndFn {
                    testfn: StaticTestFn(f),
                    desc: t.desc.clone(),
                },
                StaticBenchFn(f) => TestDescAndFn {
                    testfn: StaticBenchFn(f),
                    desc: t.desc.clone(),
                },
                _ => panic!("non-static tests passed to lp_coins test runner"),
            })
            .collect();
        let args: Vec<String> = std::env::args().collect();
        let _exit_code = test_main(&args, owned_tests, None);
    }

    fn pull_docker_container(name: &str) {
        Command::new("docker")
            .arg("pull")
            .arg(name)
            .status()
            .expect("Failed to execute docker command");
    }

    fn remove_docker_containers(name: &str) {
        let stdout = Command::new("docker")
            .arg("ps")
            .arg("-f")
            .arg(format!("ancestor={}", name))
            .arg("-q")
            .output()
            .expect("Failed to execute docker command");

        let reader = BufReader::new(stdout.stdout.as_slice());
        let ids: Vec<_> = reader.lines().map(|line| line.unwrap()).collect();
        if !ids.is_empty() {
            Command::new("docker")
                .arg("rm")
                .arg("-f")
                .args(ids)
                .status()
                .expect("Failed to execute docker command");
        }
    }

    trait CoinDockerOps {
        fn rpc_client(&self) -> &UtxoRpcClientEnum;

        fn wait_ready(&self) {
            let timeout = now_ms() + 30000;
            loop {
                match self.rpc_client().get_block_count().wait() {
                    Ok(n) => {
                        if n > 1 {
                            break;
                        }
                    },
                    Err(e) => log!([e]),
                }
                assert!(now_ms() < timeout, "Test timed out");
                thread::sleep(Duration::from_secs(1));
            }
        }
    }

    struct UtxoAssetDockerOps {
        #[allow(dead_code)]
        ctx: MmArc,
        coin: UtxoStandardCoin,
    }

    impl CoinDockerOps for UtxoAssetDockerOps {
        fn rpc_client(&self) -> &UtxoRpcClientEnum { &self.coin.as_ref().rpc_client }
    }

    impl UtxoAssetDockerOps {
        fn from_ticker(ticker: &str) -> UtxoAssetDockerOps {
            let conf = json!({"asset":ticker, "txfee": 1000});
            let req = json!({"method":"enable"});
            let priv_key = unwrap!(hex::decode(
                "809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f"
            ));
            let ctx = MmCtxBuilder::new().into_mm_arc();
            let coin = unwrap!(block_on(utxo_standard_coin_from_conf_and_request(
                &ctx, ticker, &conf, &req, &priv_key,
            )));
            UtxoAssetDockerOps { ctx, coin }
        }
    }

    struct QtumDockerOps {
        #[allow(dead_code)]
        ctx: MmArc,
        coin: QtumCoin,
    }

    impl CoinDockerOps for QtumDockerOps {
        fn rpc_client(&self) -> &UtxoRpcClientEnum { &self.coin.as_ref().rpc_client }
    }

    impl QtumDockerOps {
        fn new() -> QtumDockerOps {
            let ctx = MmCtxBuilder::new().into_mm_arc();
            let name = "qtum";
            let conf = json!({"decimals":8,"name":name});
            let req = json!({
                "method": "enable",
            });
            let priv_key = unwrap!(hex::decode(
                "809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f"
            ));
            let coin = unwrap!(block_on(qtum_coin_from_conf_and_request(
                &ctx, name, &conf, &req, &priv_key
            )));
            QtumDockerOps { ctx, coin }
        }

        fn initialize_contracts(&self) {
            let sender = get_address_by_label(&self.coin, QTUM_ADDRESS_LABEL);
            unsafe {
                QICK_TOKEN_ADDRESS = Some(self.create_contract(&sender, QRC20_TOKEN_BYTES));
                QORTY_TOKEN_ADDRESS = Some(self.create_contract(&sender, QRC20_TOKEN_BYTES));
                QRC20_SWAP_CONTRACT_ADDRESS = Some(self.create_contract(&sender, QRC20_SWAP_CONTRACT_BYTES));
            }
        }

        fn create_contract(&self, sender: &str, hexbytes: &str) -> H160 {
            let bytecode = hex::decode(hexbytes).expect("Hex encoded bytes expected");
            let decimals = self.coin.as_ref().decimals;
            match self.coin.as_ref().rpc_client {
                UtxoRpcClientEnum::Native(ref native) => {
                    let result = native
                        .create_contract_default_gas(&bytecode.into(), sender, decimals)
                        .wait()
                        .expect("!createcontract");
                    result.address.0.into()
                },
                UtxoRpcClientEnum::Electrum(_) => panic!("Native client expected"),
            }
        }
    }

    struct UtxoDockerNode<'a> {
        #[allow(dead_code)]
        container: Container<'a, Cli, GenericImage>,
        #[allow(dead_code)]
        ticker: String,
        #[allow(dead_code)]
        port: u16,
    }

    fn utxo_asset_docker_node<'a>(docker: &'a Cli, ticker: &'static str, port: u16) -> UtxoDockerNode<'a> {
        let args = vec![
            "-v".into(),
            format!("{}:/data/.zcash-params", zcash_params_path().display()),
            "-p".into(),
            format!("127.0.0.1:{}:{}", port, port).into(),
        ];
        let image = GenericImage::new("artempikulin/testblockchain")
            .with_args(args)
            .with_env_var("CLIENTS", "2")
            .with_env_var("CHAIN", ticker)
            .with_env_var("TEST_ADDY", "R9imXLs1hEcU9KbFDQq2hJEEJ1P5UoekaF")
            .with_env_var("TEST_WIF", "UqqW7f766rADem9heD8vSBvvrdfJb3zg5r8du9rJxPtccjWf7RG9")
            .with_env_var(
                "TEST_PUBKEY",
                "021607076d7a2cb148d542fb9644c04ffc22d2cca752f80755a0402a24c567b17a",
            )
            .with_env_var("DAEMON_URL", "http://test:test@127.0.0.1:7000")
            .with_env_var("COIN", "Komodo")
            .with_env_var("COIN_RPC_PORT", port.to_string())
            .with_wait_for(WaitFor::message_on_stdout("config is ready"));
        let container = docker.run(image);
        let mut conf_path = coin_daemon_data_dir(ticker, true);
        unwrap!(std::fs::create_dir_all(&conf_path));
        conf_path.push(format!("{}.conf", ticker));
        Command::new("docker")
            .arg("cp")
            .arg(format!("{}:/data/node_0/{}.conf", container.id(), ticker))
            .arg(&conf_path)
            .status()
            .expect("Failed to execute docker command");
        let timeout = now_ms() + 3000;
        loop {
            if conf_path.exists() {
                break;
            };
            assert!(now_ms() < timeout, "Test timed out");
        }
        UtxoDockerNode {
            container,
            ticker: ticker.into(),
            port,
        }
    }

    fn qtum_docker_node<'a>(docker: &'a Cli, port: u16) -> UtxoDockerNode<'a> {
        let args = vec!["-p".into(), format!("127.0.0.1:{}:{}", port, port).into()];
        // TODO give a name for the image
        let image = GenericImage::new("13c06b060325")
            .with_args(args)
            .with_env_var("CLIENTS", "2")
            .with_env_var("COIN_RPC_PORT", port.to_string())
            .with_env_var("ADDRESS_LABEL", QTUM_ADDRESS_LABEL)
            .with_wait_for(WaitFor::message_on_stdout("config is ready"));
        let container = docker.run(image);

        let name = "qtum";
        let is_asset_chain = false;
        let mut conf_path = coin_daemon_data_dir(name, is_asset_chain);
        unwrap!(std::fs::create_dir_all(&conf_path));
        conf_path.push(format!("{}.conf", name));
        Command::new("docker")
            .arg("cp")
            .arg(format!("{}:/data/node_0/{}.conf", container.id(), name))
            .arg(&conf_path)
            .status()
            .expect("Failed to execute docker command");
        let timeout = now_ms() + 3000;
        loop {
            if conf_path.exists() {
                break;
            };
            assert!(now_ms() < timeout, "Test timed out");
        }
        UtxoDockerNode {
            container,
            ticker: name.to_owned(),
            port,
        }
    }

    lazy_static! {
        static ref COINS_LOCK: Mutex<()> = Mutex::new(());
    }

    // generate random privkey, create a coin and fill it's address with 1000 coins
    fn generate_coin_with_random_privkey(ticker: &str, balance: u64) -> (MmArc, UtxoStandardCoin, [u8; 32]) {
        // prevent concurrent initialization since daemon RPC returns errors if send_to_address
        // is called concurrently (insufficient funds) and it also may return other errors
        // if previous transaction is not confirmed yet
        let ctx = MmCtxBuilder::new().into_mm_arc();
        let _lock = unwrap!(COINS_LOCK.lock());
        let timeout = (now_ms() / 1000) + 120; // timeout if test takes more than 120 seconds to run
        let conf = json!({"asset":ticker,"txversion":4,"overwintered":1,"txfee":1000});
        let req = json!({"method":"enable"});
        let priv_key = SecretKey::random(&mut rand4::thread_rng()).serialize();
        let coin = unwrap!(block_on(utxo_standard_coin_from_conf_and_request(
            &ctx, ticker, &conf, &req, &priv_key
        )));
        import_address(&coin);
        fill_address(&coin, balance, timeout);
        (ctx, coin, priv_key)
    }

    // generate random privkey, create a QRC20 coin and fill it's address with the specified balance
    fn generate_qrc20_coin_with_random_privkey(
        ticker: &str,
        qtum_balance: u64,
        qrc20_balance: u64,
    ) -> (MmArc, Qrc20Coin, [u8; 32]) {
        let (contract_address, swap_contract_address) = unsafe {
            let contract_address = match ticker {
                "QICK" => QICK_TOKEN_ADDRESS
                    .expect("QICK_TOKEN_ADDRESS must be set already")
                    .clone(),
                "QORTY" => QORTY_TOKEN_ADDRESS
                    .expect("QORTY_TOKEN_ADDRESS must be set already")
                    .clone(),
                _ => panic!("Expected QICK or QORTY ticker"),
            };
            (
                contract_address,
                QRC20_SWAP_CONTRACT_ADDRESS
                    .expect("QRC20_SWAP_CONTRACT_ADDRESS must be set already")
                    .clone(),
            )
        };
        // TODO qtum to tQTUM
        let platform = "qtum";
        let ctx = MmCtxBuilder::new().into_mm_arc();
        let _lock = unwrap!(COINS_LOCK.lock());
        let timeout = (now_ms() / 1000) + 40; // timeout if test takes more than 40 seconds to run
        let conf = json!({
            "coin":"QRC20",
            "decimals": 8,
            "required_confirmations":0,
            "pubtype":120,
            "p2shtype":50,
            "wiftype":128,
            "segwit":true,
            "mm2":1,
            "mature_confirmations":500,
        });
        let req = json!({
            "method": "enable",
            "swap_contract_address": format!("{:#02x}", swap_contract_address),
        });
        let priv_key = SecretKey::random(&mut rand4::thread_rng()).serialize();
        let coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
            &ctx,
            ticker,
            platform,
            &conf,
            &req,
            &priv_key,
            contract_address,
        )));

        import_address(&coin);
        fill_address(&coin, qtum_balance, timeout);
        fill_qrc20_address(&coin, qrc20_balance, timeout);
        (ctx, coin, priv_key)
    }

    fn import_address<T>(coin: &T)
    where
        T: MarketCoinOps + AsRef<UtxoCoinFields>,
    {
        match coin.as_ref().rpc_client {
            UtxoRpcClientEnum::Native(ref native) => {
                let my_address = coin.my_address().unwrap();
                unwrap!(native.import_address(&my_address, &my_address, false).wait())
            },
            UtxoRpcClientEnum::Electrum(_) => panic!("Expected NativeClient"),
        }
    }

    /// Get only one address assigned the specified label.
    fn get_address_by_label<T>(coin: T, label: &str) -> String
    where
        T: AsRef<UtxoCoinFields>,
    {
        let native = match coin.as_ref().rpc_client {
            UtxoRpcClientEnum::Native(ref native) => native,
            UtxoRpcClientEnum::Electrum(_) => panic!("NativeClient expected"),
        };
        let mut addresses = native
            .get_addresses_by_label(label)
            .wait()
            .expect("!getaddressesbylabel")
            .into_iter();
        match addresses.next() {
            Some((addr, _purpose)) if addresses.next().is_none() => addr,
            Some(_) => panic!("Expected only one address by {:?}", label),
            None => panic!("Expected one address by {:?}", label),
        }
    }

    fn fill_address<T>(coin: &T, amount: u64, timeout: u64)
    where
        T: MarketCoinOps + AsRef<UtxoCoinFields>,
    {
        let my_address = coin.my_address().unwrap();
        if let UtxoRpcClientEnum::Native(client) = &coin.as_ref().rpc_client {
            unwrap!(client.import_address(&my_address, &my_address, false).wait());
            let hash = client.send_to_address(&my_address, &amount.into()).wait().unwrap();
            let tx_bytes = client.get_transaction_bytes(hash).wait().unwrap();
            unwrap!(coin.wait_for_confirmations(&tx_bytes, 1, false, timeout, 1).wait());
            log!({ "{:02x}", tx_bytes });
            loop {
                let unspents = client
                    .list_unspent(0, std::i32::MAX, vec![my_address.clone()])
                    .wait()
                    .unwrap();
                log!([unspents]);
                if !unspents.is_empty() {
                    break;
                }
                assert!(now_ms() / 1000 < timeout, "Test timed out");
                thread::sleep(Duration::from_secs(1));
            }
        };
    }

    fn fill_qrc20_address(coin: &Qrc20Coin, amount: u64, timeout: u64) {
        let client = match coin.as_ref().rpc_client {
            UtxoRpcClientEnum::Native(ref client) => client,
            UtxoRpcClientEnum::Electrum(_) => panic!("Expected NativeClient"),
        };

        let from_addr = get_address_by_label(coin, QTUM_ADDRESS_LABEL);
        let to_addr = coin.my_qrc20_address();
        let decimals = coin.as_ref().decimals;
        let satoshis = sat_from_big_decimal(&amount.into(), decimals).expect("!sat_from_big_decimal");

        let hash = client
            .transfer_tokens(&coin.contract_address, &from_addr, to_addr, satoshis.into(), decimals)
            .wait()
            .expect("!transfer_tokens")
            .txid;

        let tx_bytes = client.get_transaction_bytes(hash).wait().unwrap();
        log!({ "{:02x}", tx_bytes });
        unwrap!(coin.wait_for_confirmations(&tx_bytes, 1, false, timeout, 1).wait());
    }

    #[test]
    fn test_foo() {
        let (_ctx, coin, _priv_key) = generate_qrc20_coin_with_random_privkey("QICK", 10, 20);
        assert_eq!(coin.my_balance().wait().unwrap(), BigDecimal::from(20));
        assert_eq!(coin.base_coin_balance().wait().unwrap(), BigDecimal::from(10));
    }

    #[test]
    fn test_search_for_swap_tx_spend_native_was_refunded_taker() {
        let timeout = (now_ms() / 1000) + 120; // timeout if test takes more than 120 seconds to run
        let (_ctx, coin, _) = generate_coin_with_random_privkey("MYCOIN", 1000);

        let time_lock = (now_ms() / 1000) as u32 - 3600;
        let tx = coin
            .send_taker_payment(time_lock, &*coin.my_public_key(), &[0; 20], 1.into())
            .wait()
            .unwrap();

        unwrap!(coin.wait_for_confirmations(&tx.tx_hex(), 1, false, timeout, 1).wait());

        let refund_tx = coin
            .send_taker_refunds_payment(&tx.tx_hex(), time_lock, &*coin.my_public_key(), &[0; 20])
            .wait()
            .unwrap();

        unwrap!(coin
            .wait_for_confirmations(&refund_tx.tx_hex(), 1, false, timeout, 1)
            .wait());

        let found = unwrap!(unwrap!(coin.search_for_swap_tx_spend_my(
            time_lock,
            &*coin.my_public_key(),
            &[0; 20],
            &tx.tx_hex(),
            0,
        )));
        assert_eq!(FoundSwapTxSpend::Refunded(refund_tx), found);
    }

    #[test]
    fn test_search_for_swap_tx_spend_native_was_refunded_maker() {
        let timeout = (now_ms() / 1000) + 120; // timeout if test takes more than 120 seconds to run
        let (_ctx, coin, _) = generate_coin_with_random_privkey("MYCOIN", 1000);

        let time_lock = (now_ms() / 1000) as u32 - 3600;
        let tx = coin
            .send_maker_payment(time_lock, &*coin.my_public_key(), &[0; 20], 1.into())
            .wait()
            .unwrap();

        unwrap!(coin.wait_for_confirmations(&tx.tx_hex(), 1, false, timeout, 1).wait());

        let refund_tx = coin
            .send_maker_refunds_payment(&tx.tx_hex(), time_lock, &*coin.my_public_key(), &[0; 20])
            .wait()
            .unwrap();

        unwrap!(coin
            .wait_for_confirmations(&refund_tx.tx_hex(), 1, false, timeout, 1)
            .wait());

        let found = unwrap!(unwrap!(coin.search_for_swap_tx_spend_my(
            time_lock,
            &*coin.my_public_key(),
            &[0; 20],
            &tx.tx_hex(),
            0,
        )));
        assert_eq!(FoundSwapTxSpend::Refunded(refund_tx), found);
    }

    #[test]
    fn test_search_for_taker_swap_tx_spend_native_was_spent_by_maker() {
        let timeout = (now_ms() / 1000) + 120; // timeout if test takes more than 120 seconds to run
        let (_ctx, coin, _) = generate_coin_with_random_privkey("MYCOIN", 1000);
        let secret = [0; 32];

        let time_lock = (now_ms() / 1000) as u32 - 3600;
        let tx = coin
            .send_taker_payment(time_lock, &*coin.my_public_key(), &*dhash160(&secret), 1.into())
            .wait()
            .unwrap();

        unwrap!(coin.wait_for_confirmations(&tx.tx_hex(), 1, false, timeout, 1).wait());

        let spend_tx = coin
            .send_maker_spends_taker_payment(&tx.tx_hex(), time_lock, &*coin.my_public_key(), &secret)
            .wait()
            .unwrap();

        unwrap!(coin
            .wait_for_confirmations(&spend_tx.tx_hex(), 1, false, timeout, 1)
            .wait());

        let found = unwrap!(unwrap!(coin.search_for_swap_tx_spend_my(
            time_lock,
            &*coin.my_public_key(),
            &*dhash160(&secret),
            &tx.tx_hex(),
            0,
        )));
        assert_eq!(FoundSwapTxSpend::Spent(spend_tx), found);
    }

    #[test]
    fn test_search_for_maker_swap_tx_spend_native_was_spent_by_taker() {
        let timeout = (now_ms() / 1000) + 120; // timeout if test takes more than 120 seconds to run
        let (_ctx, coin, _) = generate_coin_with_random_privkey("MYCOIN", 1000);
        let secret = [0; 32];

        let time_lock = (now_ms() / 1000) as u32 - 3600;
        let tx = coin
            .send_maker_payment(time_lock, &*coin.my_public_key(), &*dhash160(&secret), 1.into())
            .wait()
            .unwrap();

        unwrap!(coin.wait_for_confirmations(&tx.tx_hex(), 1, false, timeout, 1).wait());

        let spend_tx = coin
            .send_taker_spends_maker_payment(&tx.tx_hex(), time_lock, &*coin.my_public_key(), &secret)
            .wait()
            .unwrap();

        unwrap!(coin
            .wait_for_confirmations(&spend_tx.tx_hex(), 1, false, timeout, 1)
            .wait());

        let found = unwrap!(unwrap!(coin.search_for_swap_tx_spend_my(
            time_lock,
            &*coin.my_public_key(),
            &*dhash160(&secret),
            &tx.tx_hex(),
            0,
        )));
        assert_eq!(FoundSwapTxSpend::Spent(spend_tx), found);
    }

    // https://github.com/KomodoPlatform/atomicDEX-API/issues/554
    #[test]
    fn order_should_be_cancelled_when_entire_balance_is_withdrawn() {
        let (_ctx, _, priv_key) = generate_coin_with_random_privkey("MYCOIN", 1000);
        let coins = json! ([
            {"coin":"MYCOIN","asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
            {"coin":"MYCOIN1","asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        ]);
        let mut mm_bob = unwrap!(MarketMakerIt::start(
            json! ({
                "gui": "nogui",
                "netid": 9000,
                "dht": "on",  // Enable DHT without delay.
                "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
                "rpcip": env::var ("BOB_TRADE_IP") .ok(),
                "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| unwrap! (s.parse::<i64>())),
                "passphrase": format!("0x{}", hex::encode(priv_key)),
                "coins": coins,
                "rpc_password": "pass",
                "i_am_seed": true,
            }),
            "pass".to_string(),
            None,
        ));
        let (_bob_dump_log, _bob_dump_dashboard) = mm_dump(&mm_bob.log_path);
        unwrap!(block_on(
            mm_bob.wait_for_log(60., |log| log.contains(">>>>>>>>> DEX stats "))
        ));
        log!([block_on(enable_native(&mm_bob, "MYCOIN", vec![]))]);
        log!([block_on(enable_native(&mm_bob, "MYCOIN1", vec![]))]);
        let rc = unwrap!(block_on(mm_bob.rpc(json! ({
            "userpass": mm_bob.userpass,
            "method": "setprice",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
            "price": 1,
            "volume": "999",
        }))));
        assert!(rc.0.is_success(), "!setprice: {}", rc.1);

        thread::sleep(Duration::from_secs(12));

        log!("Get MYCOIN/MYCOIN1 orderbook");
        let rc = unwrap!(block_on(mm_bob.rpc(json! ({
            "userpass": mm_bob.userpass,
            "method": "orderbook",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
        }))));
        assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

        let bob_orderbook: Json = unwrap!(json::from_str(&rc.1));
        log!("orderbook "[bob_orderbook]);
        let asks = bob_orderbook["asks"].as_array().unwrap();
        assert_eq!(asks.len(), 1, "MYCOIN/MYCOIN1 orderbook must have exactly 1 ask");

        let withdraw = unwrap!(block_on(mm_bob.rpc(json! ({
            "userpass": mm_bob.userpass,
            "method": "withdraw",
            "coin": "MYCOIN",
            "max": true,
            "to": "R9imXLs1hEcU9KbFDQq2hJEEJ1P5UoekaF",
        }))));
        assert!(withdraw.0.is_success(), "!withdraw: {}", withdraw.1);

        let withdraw: Json = unwrap!(json::from_str(&withdraw.1));

        let send_raw = unwrap!(block_on(mm_bob.rpc(json! ({
            "userpass": mm_bob.userpass,
            "method": "send_raw_transaction",
            "coin": "MYCOIN",
            "tx_hex": withdraw["tx_hex"],
        }))));
        assert!(send_raw.0.is_success(), "!send_raw: {}", send_raw.1);

        thread::sleep(Duration::from_secs(12));

        log!("Get MYCOIN/MYCOIN1 orderbook");
        let rc = unwrap!(block_on(mm_bob.rpc(json! ({
            "userpass": mm_bob.userpass,
            "method": "orderbook",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
        }))));
        assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

        let bob_orderbook: Json = unwrap!(json::from_str(&rc.1));
        log!("orderbook "(unwrap!(json::to_string(&bob_orderbook))));
        let asks = bob_orderbook["asks"].as_array().unwrap();
        assert_eq!(asks.len(), 0, "MYCOIN/MYCOIN1 orderbook must have exactly 0 asks");

        log!("Get my orders");
        let rc = unwrap!(block_on(mm_bob.rpc(json! ({
            "userpass": mm_bob.userpass,
            "method": "my_orders",
        }))));
        assert!(rc.0.is_success(), "!my_orders: {}", rc.1);
        let orders: Json = unwrap!(json::from_str(&rc.1));
        log!("my_orders "(unwrap!(json::to_string(&orders))));
        assert!(
            unwrap!(orders["result"]["maker_orders"].as_object()).is_empty(),
            "maker_orders must be empty"
        );

        unwrap!(block_on(mm_bob.stop()));
    }

    // https://github.com/KomodoPlatform/atomicDEX-API/issues/471
    #[test]
    fn test_match_and_trade_max() {
        let (_ctx, _, bob_priv_key) = generate_coin_with_random_privkey("MYCOIN", 1000);
        let (_ctx, _, alice_priv_key) = generate_coin_with_random_privkey("MYCOIN1", 2000);
        let coins = json! ([
            {"coin":"MYCOIN","asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
            {"coin":"MYCOIN1","asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        ]);
        let mut mm_bob = unwrap!(MarketMakerIt::start(
            json! ({
                "gui": "nogui",
                "netid": 9000,
                "dht": "on",  // Enable DHT without delay.
                "passphrase": format!("0x{}", hex::encode(bob_priv_key)),
                "coins": coins,
                "rpc_password": "pass",
                "i_am_seed": true,
            }),
            "pass".to_string(),
            None,
        ));
        let (_bob_dump_log, _bob_dump_dashboard) = mm_dump(&mm_bob.log_path);
        unwrap!(block_on(
            mm_bob.wait_for_log(22., |log| log.contains(">>>>>>>>> DEX stats "))
        ));

        let mut mm_alice = unwrap!(MarketMakerIt::start(
            json! ({
                "gui": "nogui",
                "netid": 9000,
                "dht": "on",  // Enable DHT without delay.
                "passphrase": format!("0x{}", hex::encode(alice_priv_key)),
                "coins": coins,
                "rpc_password": "pass",
                "seednodes": vec![format!("{}", mm_bob.ip)],
            }),
            "pass".to_string(),
            None,
        ));
        let (_alice_dump_log, _alice_dump_dashboard) = mm_dump(&mm_alice.log_path);
        unwrap!(block_on(
            mm_alice.wait_for_log(22., |log| log.contains(">>>>>>>>> DEX stats "))
        ));

        log!([block_on(enable_native(&mm_bob, "MYCOIN", vec![]))]);
        log!([block_on(enable_native(&mm_bob, "MYCOIN1", vec![]))]);
        log!([block_on(enable_native(&mm_alice, "MYCOIN", vec![]))]);
        log!([block_on(enable_native(&mm_alice, "MYCOIN1", vec![]))]);
        let rc = unwrap!(block_on(mm_bob.rpc(json! ({
            "userpass": mm_bob.userpass,
            "method": "setprice",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
            "price": 1,
            "max": true,
        }))));
        assert!(rc.0.is_success(), "!setprice: {}", rc.1);

        thread::sleep(Duration::from_secs(12));

        log!("Get MYCOIN/MYCOIN1 orderbook");
        let rc = unwrap!(block_on(mm_bob.rpc(json! ({
            "userpass": mm_bob.userpass,
            "method": "orderbook",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
        }))));
        assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

        let bob_orderbook: Json = unwrap!(json::from_str(&rc.1));
        log!("orderbook "[bob_orderbook]);
        let asks = bob_orderbook["asks"].as_array().unwrap();
        assert_eq!(asks.len(), 1, "MYCOIN/MYCOIN1 orderbook must have exactly 1 ask");
        assert_eq!(asks[0]["maxvolume"], Json::from("999.99999"));

        let rc = unwrap!(block_on(mm_alice.rpc(json! ({
            "userpass": mm_alice.userpass,
            "method": "buy",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
            "price": 1,
            "volume": "999.99999",
        }))));
        assert!(rc.0.is_success(), "!buy: {}", rc.1);

        unwrap!(block_on(mm_bob.wait_for_log(22., |log| {
            log.contains("Entering the maker_swap_loop MYCOIN/MYCOIN1")
        })));
        unwrap!(block_on(mm_alice.wait_for_log(22., |log| {
            log.contains("Entering the taker_swap_loop MYCOIN/MYCOIN1")
        })));
        unwrap!(block_on(mm_bob.stop()));
        unwrap!(block_on(mm_alice.stop()));
    }

    #[test]
    fn test_buy_when_coins_locked_by_other_swap() {
        let (_ctx, _, bob_priv_key) = generate_coin_with_random_privkey("MYCOIN", 1000);
        let (_ctx, _, alice_priv_key) = generate_coin_with_random_privkey("MYCOIN1", 2);
        let coins = json! ([
            {"coin":"MYCOIN","asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
            {"coin":"MYCOIN1","asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        ]);
        let mut mm_bob = unwrap!(MarketMakerIt::start(
            json! ({
                "gui": "nogui",
                "netid": 9000,
                "dht": "on",  // Enable DHT without delay.
                "passphrase": format!("0x{}", hex::encode(bob_priv_key)),
                "coins": coins,
                "rpc_password": "pass",
                "i_am_seed": true,
            }),
            "pass".to_string(),
            None,
        ));
        let (_bob_dump_log, _bob_dump_dashboard) = mm_dump(&mm_bob.log_path);
        unwrap!(block_on(
            mm_bob.wait_for_log(22., |log| log.contains(">>>>>>>>> DEX stats "))
        ));

        let mut mm_alice = unwrap!(MarketMakerIt::start(
            json! ({
                "gui": "nogui",
                "netid": 9000,
                "dht": "on",  // Enable DHT without delay.
                "passphrase": format!("0x{}", hex::encode(alice_priv_key)),
                "coins": coins,
                "rpc_password": "pass",
                "seednodes": vec![format!("{}", mm_bob.ip)],
            }),
            "pass".to_string(),
            None,
        ));
        let (_alice_dump_log, _alice_dump_dashboard) = mm_dump(&mm_alice.log_path);
        unwrap!(block_on(
            mm_alice.wait_for_log(22., |log| log.contains(">>>>>>>>> DEX stats "))
        ));

        log!([block_on(enable_native(&mm_bob, "MYCOIN", vec![]))]);
        log!([block_on(enable_native(&mm_bob, "MYCOIN1", vec![]))]);
        log!([block_on(enable_native(&mm_alice, "MYCOIN", vec![]))]);
        log!([block_on(enable_native(&mm_alice, "MYCOIN1", vec![]))]);
        let rc = unwrap!(block_on(mm_bob.rpc(json! ({
            "userpass": mm_bob.userpass,
            "method": "setprice",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
            "price": 1,
            "max": true,
        }))));
        assert!(rc.0.is_success(), "!setprice: {}", rc.1);

        let rc = unwrap!(block_on(mm_alice.rpc(json! ({
            "userpass": mm_alice.userpass,
            "method": "buy",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
            "price": 1,
            // the result of equation x + x / 777 + 0.00002 = 1
            "volume": {
                "numer":"77698446",
                "denom":"77800000"
            },
        }))));
        assert!(rc.0.is_success(), "!buy: {}", rc.1);

        unwrap!(block_on(mm_bob.wait_for_log(22., |log| {
            log.contains("Entering the maker_swap_loop MYCOIN/MYCOIN1")
        })));
        unwrap!(block_on(mm_alice.wait_for_log(22., |log| {
            log.contains("Entering the taker_swap_loop MYCOIN/MYCOIN1")
        })));

        let rc = unwrap!(block_on(mm_alice.rpc(json! ({
            "userpass": mm_alice.userpass,
            "method": "buy",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
            "price": 1,
            // it is slightly more than previous volume so it should fail
            // because the total sum of used funds will be slightly more than available 2
            "volume": {
                "numer":"77698447",
                "denom":"77800000"
            },
        }))));
        assert!(!rc.0.is_success(), "buy success, but should fail: {}", rc.1);
        assert!(rc.1.contains("is larger than available 1"));
        unwrap!(block_on(mm_bob.stop()));
        unwrap!(block_on(mm_alice.stop()));
    }

    #[test]
    fn test_sell_when_coins_locked_by_other_swap() {
        let (_ctx, _, bob_priv_key) = generate_coin_with_random_privkey("MYCOIN", 1000);
        let (_ctx, _, alice_priv_key) = generate_coin_with_random_privkey("MYCOIN1", 2);
        let coins = json! ([
            {"coin":"MYCOIN","asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
            {"coin":"MYCOIN1","asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        ]);
        let mut mm_bob = unwrap!(MarketMakerIt::start(
            json! ({
                "gui": "nogui",
                "netid": 9000,
                "dht": "on",  // Enable DHT without delay.
                "passphrase": format!("0x{}", hex::encode(bob_priv_key)),
                "coins": coins,
                "rpc_password": "pass",
                "i_am_seed": true,
            }),
            "pass".to_string(),
            None,
        ));
        let (_bob_dump_log, _bob_dump_dashboard) = mm_dump(&mm_bob.log_path);
        unwrap!(block_on(
            mm_bob.wait_for_log(22., |log| log.contains(">>>>>>>>> DEX stats "))
        ));

        let mut mm_alice = unwrap!(MarketMakerIt::start(
            json! ({
                "gui": "nogui",
                "netid": 9000,
                "dht": "on",  // Enable DHT without delay.
                "passphrase": format!("0x{}", hex::encode(alice_priv_key)),
                "coins": coins,
                "rpc_password": "pass",
                "seednodes": vec![format!("{}", mm_bob.ip)],
            }),
            "pass".to_string(),
            None,
        ));
        let (_alice_dump_log, _alice_dump_dashboard) = mm_dump(&mm_alice.log_path);
        unwrap!(block_on(
            mm_alice.wait_for_log(22., |log| log.contains(">>>>>>>>> DEX stats "))
        ));

        log!([block_on(enable_native(&mm_bob, "MYCOIN", vec![]))]);
        log!([block_on(enable_native(&mm_bob, "MYCOIN1", vec![]))]);
        log!([block_on(enable_native(&mm_alice, "MYCOIN", vec![]))]);
        log!([block_on(enable_native(&mm_alice, "MYCOIN1", vec![]))]);
        let rc = unwrap!(block_on(mm_bob.rpc(json! ({
            "userpass": mm_bob.userpass,
            "method": "setprice",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
            "price": 1,
            "max": true,
        }))));
        assert!(rc.0.is_success(), "!setprice: {}", rc.1);

        let rc = unwrap!(block_on(mm_alice.rpc(json! ({
            "userpass": mm_alice.userpass,
            "method": "sell",
            "base": "MYCOIN1",
            "rel": "MYCOIN",
            "price": 1,
            // the result of equation x + x / 777 + 0.00002 = 1
            "volume": {
                "numer":"77698446",
                "denom":"77800000"
            },
        }))));
        assert!(rc.0.is_success(), "!sell: {}", rc.1);

        unwrap!(block_on(mm_bob.wait_for_log(22., |log| {
            log.contains("Entering the maker_swap_loop MYCOIN/MYCOIN1")
        })));
        unwrap!(block_on(mm_alice.wait_for_log(22., |log| {
            log.contains("Entering the taker_swap_loop MYCOIN/MYCOIN1")
        })));

        let rc = unwrap!(block_on(mm_alice.rpc(json! ({
            "userpass": mm_alice.userpass,
            "method": "sell",
            "base": "MYCOIN1",
            "rel": "MYCOIN",
            "price": 1,
            // it is slightly more than previous volume so it should fail
            // because the total sum of used funds will be slightly more than available 2
            "volume": {
                "numer":"77698447",
                "denom":"77800000"
            },
        }))));
        assert!(!rc.0.is_success(), "sell success, but should fail: {}", rc.1);
        assert!(rc.1.contains("is larger than available 1"));
        unwrap!(block_on(mm_bob.stop()));
        unwrap!(block_on(mm_alice.stop()));
    }

    #[test]
    fn test_buy_max() {
        let (_ctx, _, alice_priv_key) = generate_coin_with_random_privkey("MYCOIN1", 1);
        let coins = json! ([
            {"coin":"MYCOIN","asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
            {"coin":"MYCOIN1","asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        ]);
        let mut mm_alice = unwrap!(MarketMakerIt::start(
            json! ({
                "gui": "nogui",
                "netid": 9000,
                "dht": "on",  // Enable DHT without delay.
                "passphrase": format!("0x{}", hex::encode(alice_priv_key)),
                "coins": coins,
                "rpc_password": "pass",
                "i_am_see": true,
            }),
            "pass".to_string(),
            None,
        ));
        let (_alice_dump_log, _alice_dump_dashboard) = mm_dump(&mm_alice.log_path);
        unwrap!(block_on(
            mm_alice.wait_for_log(22., |log| log.contains(">>>>>>>>> DEX stats "))
        ));

        log!([block_on(enable_native(&mm_alice, "MYCOIN", vec![]))]);
        log!([block_on(enable_native(&mm_alice, "MYCOIN1", vec![]))]);
        let rc = unwrap!(block_on(mm_alice.rpc(json! ({
            "userpass": mm_alice.userpass,
            "method": "buy",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
            "price": 1,
            // the result of equation x + x / 777 + 0.00002 = 1
            "volume": {
                "numer":"77698446",
                "denom":"77800000"
            },
        }))));
        assert!(rc.0.is_success(), "!buy: {}", rc.1);

        let rc = unwrap!(block_on(mm_alice.rpc(json! ({
            "userpass": mm_alice.userpass,
            "method": "buy",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
            "price": 1,
            // it is slightly more than previous volume so it should fail
            "volume": {
                "numer":"77698447",
                "denom":"77800000"
            },
        }))));
        assert!(!rc.0.is_success(), "buy success, but should fail: {}", rc.1);
        // assert! (rc.1.contains("MYCOIN1 balance 1 is too low"));
        unwrap!(block_on(mm_alice.stop()));
    }

    #[test]
    fn test_get_max_taker_vol() {
        let (_ctx, _, alice_priv_key) = generate_coin_with_random_privkey("MYCOIN1", 1);
        let coins = json! ([
            {"coin":"MYCOIN","asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
            {"coin":"MYCOIN1","asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        ]);
        let mut mm_alice = unwrap!(MarketMakerIt::start(
            json! ({
                "gui": "nogui",
                "netid": 9000,
                "dht": "on",  // Enable DHT without delay.
                "passphrase": format!("0x{}", hex::encode(alice_priv_key)),
                "coins": coins,
                "rpc_password": "pass",
                "i_am_see": true,
            }),
            "pass".to_string(),
            None,
        ));
        let (_alice_dump_log, _alice_dump_dashboard) = mm_dump(&mm_alice.log_path);
        unwrap!(block_on(
            mm_alice.wait_for_log(22., |log| log.contains(">>>>>>>>> DEX stats "))
        ));

        log!([block_on(enable_native(&mm_alice, "MYCOIN1", vec![]))]);
        let rc = unwrap!(block_on(mm_alice.rpc(json! ({
            "userpass": mm_alice.userpass,
            "method": "max_taker_vol",
            "coin": "MYCOIN1",
        }))));
        assert!(rc.0.is_success(), "!max_taker_vol: {}", rc.1);
        let json: Json = json::from_str(&rc.1).unwrap();
        // the result of equation x + x / 777 + 0.00002 = 1
        assert_eq!(json["result"]["numer"], Json::from("38849223"));
        assert_eq!(json["result"]["denom"], Json::from("38900000"));
        unwrap!(block_on(mm_alice.stop()));
    }

    #[test]
    fn test_set_price_max() {
        let (_ctx, _, alice_priv_key) = generate_coin_with_random_privkey("MYCOIN", 1);
        let coins = json! ([
            {"coin":"MYCOIN","asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
            {"coin":"MYCOIN1","asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        ]);
        let mut mm_alice = unwrap!(MarketMakerIt::start(
            json! ({
                "gui": "nogui",
                "netid": 9000,
                "dht": "on",  // Enable DHT without delay.
                "passphrase": format!("0x{}", hex::encode(alice_priv_key)),
                "coins": coins,
                "rpc_password": "pass",
                "i_am_see": true,
            }),
            "pass".to_string(),
            None,
        ));
        let (_alice_dump_log, _alice_dump_dashboard) = mm_dump(&mm_alice.log_path);
        unwrap!(block_on(
            mm_alice.wait_for_log(22., |log| log.contains(">>>>>>>>> DEX stats "))
        ));

        log!([block_on(enable_native(&mm_alice, "MYCOIN", vec![]))]);
        log!([block_on(enable_native(&mm_alice, "MYCOIN1", vec![]))]);
        let rc = unwrap!(block_on(mm_alice.rpc(json! ({
            "userpass": mm_alice.userpass,
            "method": "setprice",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
            "price": 1,
            // the result of equation x + 0.00001 = 1
            "volume": {
                "numer":"99999",
                "denom":"100000"
            },
        }))));
        assert!(rc.0.is_success(), "!setprice: {}", rc.1);

        let rc = unwrap!(block_on(mm_alice.rpc(json! ({
            "userpass": mm_alice.userpass,
            "method": "setprice",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
            "price": 1,
            // it is slightly more than previous volume so it should fail
            "volume": {
                "numer":"100000",
                "denom":"100000"
            },
        }))));
        assert!(!rc.0.is_success(), "setprice success, but should fail: {}", rc.1);
        unwrap!(block_on(mm_alice.stop()));
    }

    #[test]
    fn swaps_should_stop_on_stop_rpc() {
        let (_ctx, _, bob_priv_key) = generate_coin_with_random_privkey("MYCOIN", 1000);
        let (_ctx, _, alice_priv_key) = generate_coin_with_random_privkey("MYCOIN1", 2000);
        let coins = json! ([
            {"coin":"MYCOIN","asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
            {"coin":"MYCOIN1","asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        ]);
        let mut mm_bob = unwrap!(MarketMakerIt::start(
            json! ({
                "gui": "nogui",
                "netid": 9000,
                "dht": "on",  // Enable DHT without delay.
                "passphrase": format!("0x{}", hex::encode(bob_priv_key)),
                "coins": coins,
                "rpc_password": "pass",
                "i_am_seed": true,
            }),
            "pass".to_string(),
            None,
        ));
        let (_bob_dump_log, _bob_dump_dashboard) = mm_dump(&mm_bob.log_path);
        unwrap!(block_on(
            mm_bob.wait_for_log(22., |log| log.contains(">>>>>>>>> DEX stats "))
        ));

        let mut mm_alice = unwrap!(MarketMakerIt::start(
            json! ({
                "gui": "nogui",
                "netid": 9000,
                "dht": "on",  // Enable DHT without delay.
                "passphrase": format!("0x{}", hex::encode(alice_priv_key)),
                "coins": coins,
                "rpc_password": "pass",
                "seednodes": vec![format!("{}", mm_bob.ip)],
            }),
            "pass".to_string(),
            None,
        ));
        let (_alice_dump_log, _alice_dump_dashboard) = mm_dump(&mm_alice.log_path);
        unwrap!(block_on(
            mm_alice.wait_for_log(22., |log| log.contains(">>>>>>>>> DEX stats "))
        ));

        log!([block_on(enable_native(&mm_bob, "MYCOIN", vec![]))]);
        log!([block_on(enable_native(&mm_bob, "MYCOIN1", vec![]))]);
        log!([block_on(enable_native(&mm_alice, "MYCOIN", vec![]))]);
        log!([block_on(enable_native(&mm_alice, "MYCOIN1", vec![]))]);
        let rc = unwrap!(block_on(mm_bob.rpc(json! ({
            "userpass": mm_bob.userpass,
            "method": "setprice",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
            "price": 1,
            "max": true,
        }))));
        assert!(rc.0.is_success(), "!setprice: {}", rc.1);
        let mut uuids = Vec::with_capacity(3);

        for _ in 0..3 {
            let rc = unwrap!(block_on(mm_alice.rpc(json! ({
                "userpass": mm_alice.userpass,
                "method": "buy",
                "base": "MYCOIN",
                "rel": "MYCOIN1",
                "price": 1,
                "volume": "1",
            }))));
            assert!(rc.0.is_success(), "!buy: {}", rc.1);
            let buy: Json = json::from_str(&rc.1).unwrap();
            uuids.push(buy["result"]["uuid"].as_str().unwrap().to_owned());
        }
        for uuid in uuids.iter() {
            unwrap!(block_on(mm_bob.wait_for_log(22., |log| log.contains(&format!(
                "Entering the maker_swap_loop MYCOIN/MYCOIN1 with uuid: {}",
                uuid
            )))));
            unwrap!(block_on(mm_alice.wait_for_log(22., |log| log.contains(&format!(
                "Entering the taker_swap_loop MYCOIN/MYCOIN1 with uuid: {}",
                uuid
            )))));
        }
        unwrap!(block_on(mm_bob.stop()));
        unwrap!(block_on(mm_alice.stop()));
        for uuid in uuids {
            unwrap!(block_on(mm_bob.wait_for_log_after_stop(22., |log| {
                log.contains(&format!("swap {} stopped", uuid))
            })));
            unwrap!(block_on(mm_alice.wait_for_log_after_stop(22., |log| {
                log.contains(&format!("swap {} stopped", uuid))
            })));
        }
    }
}
