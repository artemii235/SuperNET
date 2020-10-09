use super::rpc_clients::{ElectrumProtocol, ListSinceBlockRes, NetworkInfo};
use super::*;
use crate::utxo::qrc20::{qrc20_addr_from_utxo_addr, qrc20_coin_from_conf_and_request, Qrc20Coin, Qrc20FeeDetails};
use crate::utxo::rpc_clients::UtxoRpcClientOps;
use crate::utxo::utxo_standard::{utxo_standard_coin_from_conf_and_request, UtxoStandardCoin, UTXO_STANDARD_DUST};
use crate::{SwapOps, TxFeeDetails, WithdrawFee};
use bigdecimal::BigDecimal;
use chain::OutPoint;
use common::mm_ctx::MmCtxBuilder;
use common::privkey::key_pair_from_seed;
use common::{block_on, OrdRange};
use ethereum_types::U256;
use futures::future::join_all;
use gstuff::now_ms;
use mocktopus::mocking::*;
use rpc::v1::types::{VerboseBlockClient, H256 as H256Json};
use serialization::deserialize;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

const TEST_COIN_NAME: &'static str = "RICK";

pub fn electrum_client_for_test(servers: &[&str]) -> ElectrumClient {
    let client = ElectrumClientImpl::new(TEST_COIN_NAME.into(), Default::default());
    for server in servers {
        block_on(client.add_server(&ElectrumRpcRequest {
            url: server.to_string(),
            protocol: ElectrumProtocol::TCP,
            disable_cert_verification: false,
        }))
        .unwrap();
    }

    let mut attempts = 0;
    while !block_on(client.is_connected()) {
        if attempts >= 10 {
            panic!("Failed to connect to at least 1 of {:?} in 5 seconds.", servers);
        }

        thread::sleep(Duration::from_millis(500));
        attempts += 1;
    }

    ElectrumClient(Arc::new(client))
}

/// Returned client won't work by default, requires some mocks to be usable
fn native_client_for_test() -> NativeClient {
    NativeClient(Arc::new(NativeClientImpl {
        coin_ticker: "TEST".into(),
        uri: "".into(),
        auth: "".into(),
        event_handlers: vec![],
    }))
}

fn utxo_coin_fields_for_test(rpc_client: UtxoRpcClientEnum, force_seed: Option<&str>) -> UtxoCoinFields {
    let checksum_type = ChecksumType::DSHA256;
    let default_seed = "spice describe gravity federal blast come thank unfair canal monkey style afraid";
    let seed = match force_seed {
        Some(s) => s.into(),
        None => match std::env::var("BOB_PASSPHRASE") {
            Ok(p) => {
                if p.is_empty() {
                    default_seed.into()
                } else {
                    p
                }
            },
            Err(_) => default_seed.into(),
        },
    };
    let key_pair = key_pair_from_seed(&seed).unwrap();
    let my_address = Address {
        prefix: 60,
        hash: key_pair.public().address_hash(),
        t_addr_prefix: 0,
        checksum_type,
    };

    UtxoCoinFields {
        decimals: 8,
        rpc_client,
        key_pair,
        is_pos: false,
        requires_notarization: false.into(),
        overwintered: true,
        segwit: false,
        tx_version: 4,
        my_address,
        address_format: UtxoAddressFormat::Standard,
        asset_chain: true,
        p2sh_addr_prefix: 85,
        p2sh_t_addr_prefix: 0,
        pub_addr_prefix: 60,
        pub_t_addr_prefix: 0,
        ticker: TEST_COIN_NAME.into(),
        wif_prefix: 0,
        tx_fee: TxFee::Fixed(1000),
        version_group_id: 0x892f2085,
        consensus_branch_id: 0x76b809bb,
        zcash: true,
        checksum_type,
        fork_id: 0,
        signature_version: SignatureVersion::Base,
        history_sync_state: Mutex::new(HistorySyncState::NotEnabled),
        required_confirmations: 1.into(),
        force_min_relay_fee: false,
        mtp_block_count: NonZeroU64::new(11).unwrap(),
        estimate_fee_mode: None,
        dust_amount: UTXO_STANDARD_DUST,
        mature_confirmations: MATURE_CONFIRMATIONS_DEFAULT,
        tx_cache_directory: None,
    }
}

fn utxo_coin_from_fields(coin: UtxoCoinFields) -> UtxoStandardCoin {
    let arc: UtxoArc = coin.into();
    arc.into()
}

fn utxo_coin_for_test(rpc_client: UtxoRpcClientEnum, force_seed: Option<&str>) -> UtxoStandardCoin {
    utxo_coin_from_fields(utxo_coin_fields_for_test(rpc_client, force_seed))
}

#[test]
fn test_extract_secret() {
    let tx: UtxoTx = "0100000001de7aa8d29524906b2b54ee2e0281f3607f75662cbc9080df81d1047b78e21dbc00000000d7473044022079b6c50820040b1fbbe9251ced32ab334d33830f6f8d0bf0a40c7f1336b67d5b0220142ccf723ddabb34e542ed65c395abc1fbf5b6c3e730396f15d25c49b668a1a401209da937e5609680cb30bff4a7661364ca1d1851c2506fa80c443f00a3d3bf7365004c6b6304f62b0e5cb175210270e75970bb20029b3879ec76c4acd320a8d0589e003636264d01a7d566504bfbac6782012088a9142fb610d856c19fd57f2d0cffe8dff689074b3d8a882103f368228456c940ac113e53dad5c104cf209f2f102a409207269383b6ab9b03deac68ffffffff01d0dc9800000000001976a9146d9d2b554d768232320587df75c4338ecc8bf37d88ac40280e5c".into();
    let secret = tx.extract_secret().unwrap();
    let expected_secret = hex::decode("9da937e5609680cb30bff4a7661364ca1d1851c2506fa80c443f00a3d3bf7365").unwrap();
    assert_eq!(expected_secret, secret);
}

#[test]
fn test_generate_transaction() {
    let client = electrum_client_for_test(&["electrum1.cipig.net:10017"]);
    let coin = utxo_coin_for_test(client.into(), None);
    let unspents = vec![UnspentInfo {
        value: 10000000000,
        outpoint: OutPoint::default(),
        height: Default::default(),
    }];

    let outputs = vec![TransactionOutput {
        script_pubkey: vec![].into(),
        value: 999,
    }];

    let generated = block_on(coin.generate_transaction(unspents, outputs, FeePolicy::SendExact, None, None));
    // must not allow to use output with value < dust
    unwrap_err!(generated);

    let unspents = vec![UnspentInfo {
        value: 100000,
        outpoint: OutPoint::default(),
        height: Default::default(),
    }];

    let outputs = vec![TransactionOutput {
        script_pubkey: vec![].into(),
        value: 98001,
    }];

    let generated = unwrap!(block_on(coin.generate_transaction(
        unspents,
        outputs,
        FeePolicy::SendExact,
        None,
        None
    )));
    // the change that is less than dust must be included to miner fee
    // so no extra outputs should appear in generated transaction
    assert_eq!(generated.0.outputs.len(), 1);

    assert_eq!(generated.1.fee_amount, 1999);
    assert_eq!(generated.1.received_by_me, 0);
    assert_eq!(generated.1.spent_by_me, 100000);

    let unspents = vec![UnspentInfo {
        value: 100000,
        outpoint: OutPoint::default(),
        height: Default::default(),
    }];

    let outputs = vec![TransactionOutput {
        script_pubkey: Builder::build_p2pkh(&coin.as_ref().my_address.hash).to_bytes(),
        value: 100000,
    }];

    // test that fee is properly deducted from output amount equal to input amount (max withdraw case)
    let generated = unwrap!(block_on(coin.generate_transaction(
        unspents,
        outputs,
        FeePolicy::DeductFromOutput(0),
        None,
        None
    )));
    assert_eq!(generated.0.outputs.len(), 1);

    assert_eq!(generated.1.fee_amount, 1000);
    assert_eq!(generated.1.received_by_me, 99000);
    assert_eq!(generated.1.spent_by_me, 100000);
    assert_eq!(generated.0.outputs[0].value, 99000);

    let unspents = vec![UnspentInfo {
        value: 100000,
        outpoint: OutPoint::default(),
        height: Default::default(),
    }];

    let outputs = vec![TransactionOutput {
        script_pubkey: vec![].into(),
        value: 100000,
    }];

    // test that generate_transaction returns an error when input amount is not sufficient to cover output + fee
    unwrap_err!(block_on(coin.generate_transaction(
        unspents,
        outputs,
        FeePolicy::SendExact,
        None,
        None
    )));
}

#[test]
fn test_addresses_from_script() {
    let client = electrum_client_for_test(&["electrum1.cipig.net:10017", "electrum2.cipig.net:10017"]);
    let coin = utxo_coin_for_test(client.into(), None);
    // P2PKH
    let script: Script = "76a91405aab5342166f8594baf17a7d9bef5d56744332788ac".into();
    let expected_addr: Vec<Address> = vec!["R9o9xTocqr6CeEDGDH6mEYpwLoMz6jNjMW".into()];
    let actual_addr = unwrap!(coin.addresses_from_script(&script));
    assert_eq!(expected_addr, actual_addr);

    // P2SH
    let script: Script = "a914e71a6120653ebd526e0f9d7a29cde5969db362d487".into();
    let expected_addr: Vec<Address> = vec!["bZoEPR7DjTqSDiQTeRFNDJuQPTRY2335LD".into()];
    let actual_addr = unwrap!(coin.addresses_from_script(&script));
    assert_eq!(expected_addr, actual_addr);
}

#[test]
fn test_kmd_interest() {
    let height = Some(1000001);
    let value = 64605500822;
    let lock_time = 1556623906;
    let current_time = 1556623906 + 3600 + 300;

    let expected = 36870;
    let actual = kmd_interest(height, value, lock_time, current_time).unwrap();
    assert_eq!(expected, actual);

    // UTXO amount must be at least 10 KMD to be eligible for interest
    let actual = kmd_interest(height, 999999999, lock_time, current_time);
    assert_eq!(actual, Err(KmdRewardsNotAccruedReason::UtxoAmountLessThanTen));

    // Transaction is not mined yet (height is None)
    let actual = kmd_interest(None, value, lock_time, current_time);
    assert_eq!(actual, Err(KmdRewardsNotAccruedReason::TransactionInMempool));

    // Locktime is not set
    let actual = kmd_interest(height, value, 0, current_time);
    assert_eq!(actual, Err(KmdRewardsNotAccruedReason::LocktimeNotSet));

    // interest will stop accrue after block 7_777_777
    let actual = kmd_interest(Some(7_777_778), value, lock_time, current_time);
    assert_eq!(actual, Err(KmdRewardsNotAccruedReason::UtxoHeightGreaterThanEndOfEra));

    // interest doesn't accrue for lock_time < 500_000_000
    let actual = kmd_interest(height, value, 499_999_999, current_time);
    assert_eq!(actual, Err(KmdRewardsNotAccruedReason::LocktimeLessThanThreshold));

    // current time must be greater than tx lock_time
    let actual = kmd_interest(height, value, lock_time, lock_time - 1);
    assert_eq!(actual, Err(KmdRewardsNotAccruedReason::OneHourNotPassedYet));

    // at least 1 hour should pass
    let actual = kmd_interest(height, value, lock_time, lock_time + 30);
    assert_eq!(actual, Err(KmdRewardsNotAccruedReason::OneHourNotPassedYet));
}

#[test]
fn test_kmd_interest_accrue_stop_at() {
    let lock_time = 1595845640;
    let height = 1000001;

    let expected = lock_time + 31 * 24 * 60 * 60;
    let actual = kmd_interest_accrue_stop_at(height, lock_time);
    assert_eq!(expected, actual);

    let height = 999999;

    let expected = lock_time + 365 * 24 * 60 * 60;
    let actual = kmd_interest_accrue_stop_at(height, lock_time);
    assert_eq!(expected, actual);
}

#[test]
fn test_sat_from_big_decimal() {
    let amount = "0.000001".parse().unwrap();
    let sat = sat_from_big_decimal(&amount, 18).unwrap();
    let expected_sat = 1000000000000;
    assert_eq!(expected_sat, sat);

    let amount = "0.12345678".parse().unwrap();
    let sat = sat_from_big_decimal(&amount, 8).unwrap();
    let expected_sat = 12345678;
    assert_eq!(expected_sat, sat);

    let amount = "1.000001".parse().unwrap();
    let sat = sat_from_big_decimal(&amount, 18).unwrap();
    let expected_sat = 1000001000000000000;
    assert_eq!(expected_sat, sat);

    let amount = 1.into();
    let sat = sat_from_big_decimal(&amount, 18).unwrap();
    let expected_sat = 1000000000000000000;
    assert_eq!(expected_sat, sat);

    let amount = "0.000000000000000001".parse().unwrap();
    let sat = sat_from_big_decimal(&amount, 18).unwrap();
    let expected_sat = 1u64;
    assert_eq!(expected_sat, sat);

    let amount = 1234.into();
    let sat = sat_from_big_decimal(&amount, 9).unwrap();
    let expected_sat = 1234000000000;
    assert_eq!(expected_sat, sat);

    let amount = 1234.into();
    let sat = sat_from_big_decimal(&amount, 0).unwrap();
    let expected_sat = 1234;
    assert_eq!(expected_sat, sat);

    let amount = 1234.into();
    let sat = sat_from_big_decimal(&amount, 1).unwrap();
    let expected_sat = 12340;
    assert_eq!(expected_sat, sat);

    let amount = "1234.12345".parse().unwrap();
    let sat = sat_from_big_decimal(&amount, 1).unwrap();
    let expected_sat = 12341;
    assert_eq!(expected_sat, sat);
}

#[test]
fn test_wait_for_payment_spend_timeout_native() {
    let client = NativeClientImpl {
        coin_ticker: "RICK".into(),
        uri: "http://127.0.0.1:10271".to_owned(),
        auth: fomat!("Basic "(base64_encode(
            "user481805103:pass97a61c8d048bcf468c6c39a314970e557f57afd1d8a5edee917fb29bafb3a43371",
            URL_SAFE
        ))),
        event_handlers: Default::default(),
    };

    static mut OUTPUT_SPEND_CALLED: bool = false;
    NativeClient::find_output_spend.mock_safe(|_, _, _, _| {
        unsafe { OUTPUT_SPEND_CALLED = true };
        MockResult::Return(Box::new(futures01::future::ok(None)))
    });
    let client = UtxoRpcClientEnum::Native(NativeClient(Arc::new(client)));
    let coin = utxo_coin_for_test(client, None);
    let transaction = unwrap!(hex::decode("01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"));
    let wait_until = now_ms() / 1000 - 1;
    let from_block = 1000;

    assert!(coin
        .wait_for_tx_spend(&transaction, wait_until, from_block)
        .wait()
        .is_err());
    assert!(unsafe { OUTPUT_SPEND_CALLED });
}

#[test]
fn test_wait_for_payment_spend_timeout_electrum() {
    static mut OUTPUT_SPEND_CALLED: bool = false;
    ElectrumClient::find_output_spend.mock_safe(|_, _, _, _| {
        unsafe { OUTPUT_SPEND_CALLED = true };
        MockResult::Return(Box::new(futures01::future::ok(None)))
    });

    let client = ElectrumClientImpl::new(TEST_COIN_NAME.into(), Default::default());
    let client = UtxoRpcClientEnum::Electrum(ElectrumClient(Arc::new(client)));
    let coin = utxo_coin_for_test(client, None);
    let transaction = unwrap!(hex::decode("01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"));
    let wait_until = now_ms() / 1000 - 1;
    let from_block = 1000;

    assert!(coin
        .wait_for_tx_spend(&transaction, wait_until, from_block)
        .wait()
        .is_err());
    assert!(unsafe { OUTPUT_SPEND_CALLED });
}

#[test]
fn test_search_for_swap_tx_spend_electrum_was_spent() {
    let secret = [0; 32];
    let client = electrum_client_for_test(&["electrum1.cipig.net:10017", "electrum2.cipig.net:10017"]);
    let coin = utxo_coin_for_test(
        client.into(),
        Some("spice describe gravity federal blast come thank unfair canal monkey style afraid"),
    );

    // raw tx bytes of https://rick.kmd.dev/tx/ba881ecca15b5d4593f14f25debbcdfe25f101fd2e9cf8d0b5d92d19813d4424
    let payment_tx_bytes = unwrap!(hex::decode("0400008085202f8902e115acc1b9e26a82f8403c9f81785445cc1285093b63b6246cf45aabac5e0865000000006b483045022100ca578f2d6bae02f839f71619e2ced54538a18d7aa92bd95dcd86ac26479ec9f802206552b6c33b533dd6fc8985415a501ebec89d1f5c59d0c923d1de5280e9827858012102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ffffffffb0721bf69163f7a5033fb3d18ba5768621d8c1347ebaa2fddab0d1f63978ea78020000006b483045022100a3309f99167982e97644dbb5cd7279b86630b35fc34855e843f2c5c0cafdc66d02202a8c3257c44e832476b2e2a723dad1bb4ec1903519502a49b936c155cae382ee012102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ffffffff0300e1f5050000000017a91443fde927a77b3c1d104b78155dc389078c4571b0870000000000000000166a14b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc64b8cd736000000001976a91405aab5342166f8594baf17a7d9bef5d56744332788acba0ce35e000000000000000000000000000000"));

    // raw tx bytes of https://rick.kmd.dev/tx/cea8028f93f7556ce0ef96f14b8b5d88ef2cd29f428df5936e02e71ca5b0c795
    let spend_tx_bytes = unwrap!(hex::decode("0400008085202f890124443d81192dd9b5d0f89c2efd01f125fecdbbde254ff193455d5ba1cc1e88ba00000000d74730440220519d3eed69815a16357ff07bf453b227654dc85b27ffc22a77abe077302833ec02205c27f439ddc542d332504112871ecac310ea710b99e1922f48eb179c045e44ee01200000000000000000000000000000000000000000000000000000000000000000004c6b6304a9e5e25eb1752102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ac6782012088a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc6882102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ac68ffffffff0118ddf505000000001976a91405aab5342166f8594baf17a7d9bef5d56744332788acbffee25e000000000000000000000000000000"));
    let spend_tx = TransactionEnum::UtxoTx(unwrap!(deserialize(spend_tx_bytes.as_slice())));

    let found = unwrap!(unwrap!(coin.search_for_swap_tx_spend_my(
        1591928233,
        &*coin.my_public_key(),
        &*dhash160(&secret),
        &payment_tx_bytes,
        0
    )));
    assert_eq!(FoundSwapTxSpend::Spent(spend_tx), found);
}

#[test]
fn test_search_for_swap_tx_spend_electrum_was_refunded() {
    let secret = [0; 20];
    let client = electrum_client_for_test(&["electrum1.cipig.net:10017", "electrum2.cipig.net:10017"]);
    let coin = utxo_coin_for_test(
        client.into(),
        Some("spice describe gravity federal blast come thank unfair canal monkey style afraid"),
    );

    // raw tx bytes of https://rick.kmd.dev/tx/78ea7839f6d1b0dafda2ba7e34c1d8218676a58bd1b33f03a5f76391f61b72b0
    let payment_tx_bytes = unwrap!(hex::decode("0400008085202f8902bf17bf7d1daace52e08f732a6b8771743ca4b1cb765a187e72fd091a0aabfd52000000006a47304402203eaaa3c4da101240f80f9c5e9de716a22b1ec6d66080de6a0cca32011cd77223022040d9082b6242d6acf9a1a8e658779e1c655d708379862f235e8ba7b8ca4e69c6012102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ffffffffff023ca13c0e9e085dd13f481f193e8a3e8fd609020936e98b5587342d994f4d020000006b483045022100c0ba56adb8de923975052312467347d83238bd8d480ce66e8b709a7997373994022048507bcac921fdb2302fa5224ce86e41b7efc1a2e20ae63aa738dfa99b7be826012102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ffffffff0300e1f5050000000017a9141ee6d4c38a3c078eab87ad1a5e4b00f21259b10d870000000000000000166a1400000000000000000000000000000000000000001b94d736000000001976a91405aab5342166f8594baf17a7d9bef5d56744332788ac2d08e35e000000000000000000000000000000"));

    // raw tx bytes of https://rick.kmd.dev/tx/65085eacab5af46c24b6633b098512cc455478819f3c40f8826ae2b9c1ac15e1
    let refund_tx_bytes = unwrap!(hex::decode("0400008085202f8901b0721bf69163f7a5033fb3d18ba5768621d8c1347ebaa2fddab0d1f63978ea7800000000b6473044022052e06c1abf639148229a3991fdc6da15fe51c97577f4fda351d9c606c7cf53670220780186132d67d354564cae710a77d94b6bb07dcbd7162a13bebee261ffc0963601514c6b63041dfae25eb1752102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ac6782012088a9140000000000000000000000000000000000000000882102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ac68feffffff0118ddf505000000001976a91405aab5342166f8594baf17a7d9bef5d56744332788ace6fae25e000000000000000000000000000000"));
    let refund_tx = TransactionEnum::UtxoTx(unwrap!(deserialize(refund_tx_bytes.as_slice())));

    let found = unwrap!(unwrap!(coin.search_for_swap_tx_spend_my(
        1591933469,
        coin.as_ref().key_pair.public(),
        &secret,
        &payment_tx_bytes,
        0
    )));
    assert_eq!(FoundSwapTxSpend::Refunded(refund_tx), found);
}

#[test]
fn test_withdraw_impl_set_fixed_fee() {
    UtxoStandardCoin::ordered_mature_unspents.mock_safe(|_, _| {
        let unspents = vec![UnspentInfo {
            outpoint: OutPoint {
                hash: 1.into(),
                index: 0,
            },
            value: 1000000000,
            height: Default::default(),
        }];
        MockResult::Return(Box::new(futures01::future::ok(unspents)))
    });

    let client = NativeClient(Arc::new(NativeClientImpl {
        coin_ticker: TEST_COIN_NAME.into(),
        uri: "http://127.0.0.1".to_owned(),
        auth: fomat!("Basic "(base64_encode(
            "user481805103:pass97a61c8d048bcf468c6c39a314970e557f57afd1d8a5edee917fb29bafb3a43371",
            URL_SAFE
        ))),
        event_handlers: Default::default(),
    }));

    let coin = utxo_coin_for_test(UtxoRpcClientEnum::Native(client), None);

    let withdraw_req = WithdrawRequest {
        amount: 1.into(),
        to: "RQq6fWoy8aGGMLjvRfMY5mBNVm2RQxJyLa".to_string(),
        coin: TEST_COIN_NAME.into(),
        max: false,
        fee: Some(WithdrawFee::UtxoFixed {
            amount: "0.1".parse().unwrap(),
        }),
    };
    let expected = Some(
        UtxoFeeDetails {
            amount: "0.1".parse().unwrap(),
        }
        .into(),
    );
    let tx_details = unwrap!(coin.withdraw(withdraw_req).wait());
    assert_eq!(expected, tx_details.fee_details);
}

#[test]
fn test_withdraw_impl_sat_per_kb_fee() {
    UtxoStandardCoin::ordered_mature_unspents.mock_safe(|_, _| {
        let unspents = vec![UnspentInfo {
            outpoint: OutPoint {
                hash: 1.into(),
                index: 0,
            },
            value: 1000000000,
            height: Default::default(),
        }];
        MockResult::Return(Box::new(futures01::future::ok(unspents)))
    });

    let client = NativeClient(Arc::new(NativeClientImpl {
        coin_ticker: TEST_COIN_NAME.into(),
        uri: "http://127.0.0.1".to_owned(),
        auth: fomat!("Basic "(base64_encode(
            "user481805103:pass97a61c8d048bcf468c6c39a314970e557f57afd1d8a5edee917fb29bafb3a43371",
            URL_SAFE
        ))),
        event_handlers: Default::default(),
    }));

    let coin = utxo_coin_for_test(UtxoRpcClientEnum::Native(client), None);

    let withdraw_req = WithdrawRequest {
        amount: 1.into(),
        to: "RQq6fWoy8aGGMLjvRfMY5mBNVm2RQxJyLa".to_string(),
        coin: TEST_COIN_NAME.into(),
        max: false,
        fee: Some(WithdrawFee::UtxoPerKbyte {
            amount: "0.1".parse().unwrap(),
        }),
    };
    // The resulting transaction size might be 244 or 245 bytes depending on signature size
    // MM2 always expects the worst case during fee calculation
    // 0.1 * 245 / 1000 ~ 0.0245
    let expected = Some(
        UtxoFeeDetails {
            amount: "0.0245".parse().unwrap(),
        }
        .into(),
    );
    let tx_details = unwrap!(coin.withdraw(withdraw_req).wait());
    assert_eq!(expected, tx_details.fee_details);
}

#[test]
fn test_withdraw_impl_sat_per_kb_fee_amount_equal_to_max() {
    UtxoStandardCoin::ordered_mature_unspents.mock_safe(|_, _| {
        let unspents = vec![UnspentInfo {
            outpoint: OutPoint {
                hash: 1.into(),
                index: 0,
            },
            value: 1000000000,
            height: Default::default(),
        }];
        MockResult::Return(Box::new(futures01::future::ok(unspents)))
    });

    let client = NativeClient(Arc::new(NativeClientImpl {
        coin_ticker: TEST_COIN_NAME.into(),
        uri: "http://127.0.0.1".to_owned(),
        auth: fomat!("Basic "(base64_encode(
            "user481805103:pass97a61c8d048bcf468c6c39a314970e557f57afd1d8a5edee917fb29bafb3a43371",
            URL_SAFE
        ))),
        event_handlers: Default::default(),
    }));

    let coin = utxo_coin_for_test(UtxoRpcClientEnum::Native(client), None);

    let withdraw_req = WithdrawRequest {
        amount: "9.9789".parse().unwrap(),
        to: "RQq6fWoy8aGGMLjvRfMY5mBNVm2RQxJyLa".to_string(),
        coin: TEST_COIN_NAME.into(),
        max: false,
        fee: Some(WithdrawFee::UtxoPerKbyte {
            amount: "0.1".parse().unwrap(),
        }),
    };
    let tx_details = unwrap!(coin.withdraw(withdraw_req).wait());
    // The resulting transaction size might be 210 or 211 bytes depending on signature size
    // MM2 always expects the worst case during fee calculation
    // 0.1 * 211 / 1000 = 0.0211
    let expected_fee = Some(
        UtxoFeeDetails {
            amount: "0.0211".parse().unwrap(),
        }
        .into(),
    );
    assert_eq!(expected_fee, tx_details.fee_details);
    let expected_balance_change = BigDecimal::from(-10);
    assert_eq!(expected_balance_change, tx_details.my_balance_change);
}

#[test]
fn test_withdraw_impl_sat_per_kb_fee_amount_equal_to_max_dust_included_to_fee() {
    UtxoStandardCoin::ordered_mature_unspents.mock_safe(|_, _| {
        let unspents = vec![UnspentInfo {
            outpoint: OutPoint {
                hash: 1.into(),
                index: 0,
            },
            value: 1000000000,
            height: Default::default(),
        }];
        MockResult::Return(Box::new(futures01::future::ok(unspents)))
    });

    let client = NativeClient(Arc::new(NativeClientImpl {
        coin_ticker: TEST_COIN_NAME.into(),
        uri: "http://127.0.0.1".to_owned(),
        auth: fomat!("Basic "(base64_encode(
            "user481805103:pass97a61c8d048bcf468c6c39a314970e557f57afd1d8a5edee917fb29bafb3a43371",
            URL_SAFE
        ))),
        event_handlers: Default::default(),
    }));

    let coin = utxo_coin_for_test(UtxoRpcClientEnum::Native(client), None);

    let withdraw_req = WithdrawRequest {
        amount: "9.9789".parse().unwrap(),
        to: "RQq6fWoy8aGGMLjvRfMY5mBNVm2RQxJyLa".to_string(),
        coin: TEST_COIN_NAME.into(),
        max: false,
        fee: Some(WithdrawFee::UtxoPerKbyte {
            amount: "0.09999999".parse().unwrap(),
        }),
    };
    let tx_details = unwrap!(coin.withdraw(withdraw_req).wait());
    // The resulting transaction size might be 210 or 211 bytes depending on signature size
    // MM2 always expects the worst case during fee calculation
    // 0.1 * 211 / 1000 = 0.0211
    let expected_fee = Some(
        UtxoFeeDetails {
            amount: "0.0211".parse().unwrap(),
        }
        .into(),
    );
    assert_eq!(expected_fee, tx_details.fee_details);
    let expected_balance_change = BigDecimal::from(-10);
    assert_eq!(expected_balance_change, tx_details.my_balance_change);
}

#[test]
fn test_withdraw_impl_sat_per_kb_fee_amount_over_max() {
    UtxoStandardCoin::ordered_mature_unspents.mock_safe(|_, _| {
        let unspents = vec![UnspentInfo {
            outpoint: OutPoint {
                hash: 1.into(),
                index: 0,
            },
            value: 1000000000,
            height: Default::default(),
        }];
        MockResult::Return(Box::new(futures01::future::ok(unspents)))
    });

    let client = NativeClient(Arc::new(NativeClientImpl {
        coin_ticker: TEST_COIN_NAME.into(),
        uri: "http://127.0.0.1".to_owned(),
        auth: fomat!("Basic "(base64_encode(
            "user481805103:pass97a61c8d048bcf468c6c39a314970e557f57afd1d8a5edee917fb29bafb3a43371",
            URL_SAFE
        ))),
        event_handlers: Default::default(),
    }));

    let coin = utxo_coin_for_test(UtxoRpcClientEnum::Native(client), None);

    let withdraw_req = WithdrawRequest {
        amount: "9.97939455".parse().unwrap(),
        to: "RQq6fWoy8aGGMLjvRfMY5mBNVm2RQxJyLa".to_string(),
        coin: TEST_COIN_NAME.into(),
        max: false,
        fee: Some(WithdrawFee::UtxoPerKbyte {
            amount: "0.1".parse().unwrap(),
        }),
    };
    unwrap_err!(coin.withdraw(withdraw_req).wait());
}

#[test]
fn test_withdraw_impl_sat_per_kb_fee_max() {
    UtxoStandardCoin::ordered_mature_unspents.mock_safe(|_, _| {
        let unspents = vec![UnspentInfo {
            outpoint: OutPoint {
                hash: 1.into(),
                index: 0,
            },
            value: 1000000000,
            height: Default::default(),
        }];
        MockResult::Return(Box::new(futures01::future::ok(unspents)))
    });

    let client = NativeClient(Arc::new(NativeClientImpl {
        coin_ticker: TEST_COIN_NAME.into(),
        uri: "http://127.0.0.1".to_owned(),
        auth: fomat!("Basic "(base64_encode(
            "user481805103:pass97a61c8d048bcf468c6c39a314970e557f57afd1d8a5edee917fb29bafb3a43371",
            URL_SAFE
        ))),
        event_handlers: Default::default(),
    }));

    let coin = utxo_coin_for_test(UtxoRpcClientEnum::Native(client), None);

    let withdraw_req = WithdrawRequest {
        amount: 0.into(),
        to: "RQq6fWoy8aGGMLjvRfMY5mBNVm2RQxJyLa".to_string(),
        coin: TEST_COIN_NAME.into(),
        max: true,
        fee: Some(WithdrawFee::UtxoPerKbyte {
            amount: "0.1".parse().unwrap(),
        }),
    };
    // The resulting transaction size might be 210 or 211 bytes depending on signature size
    // MM2 always expects the worst case during fee calculation
    // 0.1 * 211 / 1000 = 0.0211
    let expected = Some(
        UtxoFeeDetails {
            amount: "0.0211".parse().unwrap(),
        }
        .into(),
    );
    let tx_details = unwrap!(coin.withdraw(withdraw_req).wait());
    assert_eq!(expected, tx_details.fee_details);
}

/// TODO fix this test
#[test]
fn test_qrc20_withdraw_impl_fee_details() {
    Qrc20Coin::ordered_mature_unspents.mock_safe(|_, _| {
        let unspents = vec![UnspentInfo {
            outpoint: OutPoint {
                hash: 1.into(),
                index: 0,
            },
            value: 1000000000,
            height: Default::default(),
        }];
        MockResult::Return(Box::new(futures01::future::ok(unspents)))
    });

    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });
    let priv_key = [
        3, 98, 177, 3, 108, 39, 234, 144, 131, 178, 103, 103, 127, 80, 230, 166, 53, 68, 147, 215, 42, 216, 144, 72,
        172, 110, 180, 13, 123, 179, 10, 49,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let ctx = MmCtxBuilder::new().into_mm_arc();

    let coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    let withdraw_req = WithdrawRequest {
        amount: 10.into(),
        to: "qHmJ3KA6ZAjR9wGjpFASn4gtUSeFAqdZgs".into(),
        coin: "QRC20".into(),
        max: false,
        fee: Some(WithdrawFee::Qrc20Gas {
            gas_limit: 2_500_000,
            gas_price: 40,
        }),
    };
    let tx_details = unwrap!(coin.withdraw(withdraw_req).wait());

    let expected: Qrc20FeeDetails = unwrap!(json::from_value(json!({
        "coin": "QTUM",
        // (1000 + total_gas_fee) from satoshi,
        // where decimals = 8,
        //       1000 is fixed fee
        "miner_fee": "1.00001",
        "gas_limit": 2_500_000,
        "gas_price": 40,
        // (gas_limit * gas_price) from satoshi in Qtum
        "total_gas_fee": "1",
    })));
    assert_eq!(tx_details.fee_details, Some(TxFeeDetails::Qrc20(expected)));
}

#[test]
fn test_ordered_mature_unspents_without_tx_cache() {
    let client = electrum_client_for_test(&["electrum1.cipig.net:10017", "electrum2.cipig.net:10017"]);
    let coin = utxo_coin_for_test(
        client.into(),
        Some("spice describe gravity federal blast come thank unfair canal monkey style afraid"),
    );
    assert!(coin.as_ref().tx_cache_directory.is_none());
    assert_ne!(
        coin.my_balance().wait().unwrap(),
        0.into(),
        "The test address doesn't have unspent outputs"
    );
    let unspents = unwrap!(coin
        .ordered_mature_unspents(&Address::from("R9o9xTocqr6CeEDGDH6mEYpwLoMz6jNjMW"))
        .wait());
    assert!(!unspents.is_empty());
}

#[test]
fn test_utxo_lock() {
    // send several transactions concurrently to check that they are not using same inputs
    let client = electrum_client_for_test(&["electrum1.cipig.net:10017", "electrum2.cipig.net:10017"]);
    let coin = utxo_coin_for_test(client.into(), None);
    let output = TransactionOutput {
        value: 1000000,
        script_pubkey: Builder::build_p2pkh(&coin.as_ref().my_address.hash).to_bytes(),
    };
    let mut futures = vec![];
    for _ in 0..5 {
        futures.push(send_outputs_from_my_address_impl(coin.clone(), vec![output.clone()]));
    }
    let results = block_on(join_all(futures));
    for result in results {
        unwrap!(result);
    }
}

#[test]
fn list_since_block_btc_serde() {
    // https://github.com/KomodoPlatform/atomicDEX-API/issues/563
    let input = r#"{"lastblock":"000000000000000000066f896cca2a6c667ca85fff28ed6731d64e3c39ecb119","removed":[],"transactions":[{"abandoned":false,"address":"1Q3kQ1jsB2VyH83PJT1NXJqEaEcR6Yuknn","amount":-0.01788867,"bip125-replaceable":"no","blockhash":"0000000000000000000db4be4c2df08790e1027326832cc90889554bbebc69b7","blockindex":437,"blocktime":1572174214,"category":"send","confirmations":197,"fee":-0.00012924,"involvesWatchonly":true,"time":1572173721,"timereceived":1572173721,"txid":"29606e6780c69a39767b56dc758e6af31ced5232491ad62dcf25275684cb7701","vout":0,"walletconflicts":[]},{"address":"1JsAjr6d21j9T8EMsYnQ6GXf1mM523JAv1","amount":0.1995,"bip125-replaceable":"no","blockhash":"0000000000000000000e75b33bbb27e6af2fc3898108c93c03c293fd72a86c6f","blockindex":157,"blocktime":1572179171,"category":"receive","confirmations":190,"label":"","time":1572178251,"timereceived":1572178251,"txid":"da651c6addc8da7c4b2bec21d43022852a93a9f2882a827704b318eb2966b82e","vout":19,"walletconflicts":[]},{"abandoned":false,"address":"14RXkMTyH4NyK48DbhTQyMBoMb2UkbBEPr","amount":-0.0208,"bip125-replaceable":"no","blockhash":"0000000000000000000611bfe0b3f7612239264459f4f6e7169f8d1a67e1b08f","blockindex":286,"blocktime":1572189657,"category":"send","confirmations":178,"fee":-0.0002,"involvesWatchonly":true,"time":1572189100,"timereceived":1572189100,"txid":"8d10920ce70aeb6c7e61c8d47f3cd903fb69946edd08d8907472a90761965943","vout":0,"walletconflicts":[]},{"abandoned":false,"address":"361JVximBAqkLZERT7XB1rykgLePEHAP7B","amount":-0.01801791,"bip125-replaceable":"no","blockhash":"00000000000000000011e9293c1f07f9711e677389ac101b93116d239ac38c33","blockindex":274,"blocktime":1572173649,"category":"send","confirmations":198,"fee":-0.0000965,"involvesWatchonly":true,"label":"361JVximBAqkLZERT7XB1rykgLePEHAP7B","time":1572173458,"timereceived":1572173458,"txid":"7983cae1afeb7fe58e020878aaedea0fee15be9319bc49c81f3b9ad466782950","vout":0,"walletconflicts":[]},{"abandoned":false,"address":"1JsAjr6d21j9T8EMsYnQ6GXf1mM523JAv1","amount":-0.0003447,"bip125-replaceable":"no","blockhash":"00000000000000000011e9293c1f07f9711e677389ac101b93116d239ac38c33","blockindex":274,"blocktime":1572173649,"category":"send","confirmations":198,"fee":-0.0000965,"label":"","time":1572173458,"timereceived":1572173458,"txid":"7983cae1afeb7fe58e020878aaedea0fee15be9319bc49c81f3b9ad466782950","vout":1,"walletconflicts":[]},{"address":"361JVximBAqkLZERT7XB1rykgLePEHAP7B","amount":0.01801791,"bip125-replaceable":"no","blockhash":"00000000000000000011e9293c1f07f9711e677389ac101b93116d239ac38c33","blockindex":274,"blocktime":1572173649,"category":"receive","confirmations":198,"involvesWatchonly":true,"label":"361JVximBAqkLZERT7XB1rykgLePEHAP7B","time":1572173458,"timereceived":1572173458,"txid":"7983cae1afeb7fe58e020878aaedea0fee15be9319bc49c81f3b9ad466782950","vout":0,"walletconflicts":[]},{"address":"1JsAjr6d21j9T8EMsYnQ6GXf1mM523JAv1","amount":0.0003447,"bip125-replaceable":"no","blockhash":"00000000000000000011e9293c1f07f9711e677389ac101b93116d239ac38c33","blockindex":274,"blocktime":1572173649,"category":"receive","confirmations":198,"label":"","time":1572173458,"timereceived":1572173458,"txid":"7983cae1afeb7fe58e020878aaedea0fee15be9319bc49c81f3b9ad466782950","vout":1,"walletconflicts":[]},{"abandoned":false,"address":"3B3q1GTLQQ7Fspo6ATy3cd3tg5yu97hkve","amount":-0.021,"bip125-replaceable":"no","blockhash":"0000000000000000000debf11962f89e2ae08f8ff75803b0da6170af6c5c346b","blockindex":2618,"blocktime":1572188894,"category":"send","confirmations":179,"fee":-0.00016026,"involvesWatchonly":true,"label":"3B3q1GTLQQ7Fspo6ATy3cd3tg5yu97hkve","time":1572186009,"timereceived":1572186009,"txid":"54b159ac3a656bbaaf3bf0263b8deafad03b376ec0c2e9c715d0cf1caaf3495e","vout":0,"walletconflicts":[]},{"abandoned":false,"address":"1JsAjr6d21j9T8EMsYnQ6GXf1mM523JAv1","amount":-0.17868444,"bip125-replaceable":"no","blockhash":"0000000000000000000debf11962f89e2ae08f8ff75803b0da6170af6c5c346b","blockindex":2618,"blocktime":1572188894,"category":"send","confirmations":179,"fee":-0.00016026,"label":"","time":1572186009,"timereceived":1572186009,"txid":"54b159ac3a656bbaaf3bf0263b8deafad03b376ec0c2e9c715d0cf1caaf3495e","vout":1,"walletconflicts":[]},{"address":"3B3q1GTLQQ7Fspo6ATy3cd3tg5yu97hkve","amount":0.021,"bip125-replaceable":"no","blockhash":"0000000000000000000debf11962f89e2ae08f8ff75803b0da6170af6c5c346b","blockindex":2618,"blocktime":1572188894,"category":"receive","confirmations":179,"involvesWatchonly":true,"label":"3B3q1GTLQQ7Fspo6ATy3cd3tg5yu97hkve","time":1572186009,"timereceived":1572186009,"txid":"54b159ac3a656bbaaf3bf0263b8deafad03b376ec0c2e9c715d0cf1caaf3495e","vout":0,"walletconflicts":[]},{"address":"1JsAjr6d21j9T8EMsYnQ6GXf1mM523JAv1","amount":0.17868444,"bip125-replaceable":"no","blockhash":"0000000000000000000debf11962f89e2ae08f8ff75803b0da6170af6c5c346b","blockindex":2618,"blocktime":1572188894,"category":"receive","confirmations":179,"label":"","time":1572186009,"timereceived":1572186009,"txid":"54b159ac3a656bbaaf3bf0263b8deafad03b376ec0c2e9c715d0cf1caaf3495e","vout":1,"walletconflicts":[]},{"abandoned":false,"address":"3AC6k1Y54knEdkgWjX3TjmWGjDHtJCNZZY","amount":-0.17822795,"bip125-replaceable":"no","blockhash":"00000000000000000009a60478f29f4910e29224ea5ed63d77321ac8c624ec45","blockindex":2377,"blocktime":1572190637,"category":"send","confirmations":177,"fee":-0.00009985,"involvesWatchonly":true,"label":"3AC6k1Y54knEdkgWjX3TjmWGjDHtJCNZZY","time":1572189626,"timereceived":1572189626,"txid":"eabc01e45db89ea8cf623f8e22847e4023c69bed3c7d396d573b89dec3fe17a7","vout":0,"walletconflicts":[]},{"abandoned":false,"address":"1JsAjr6d21j9T8EMsYnQ6GXf1mM523JAv1","amount":-0.00035664,"bip125-replaceable":"no","blockhash":"00000000000000000009a60478f29f4910e29224ea5ed63d77321ac8c624ec45","blockindex":2377,"blocktime":1572190637,"category":"send","confirmations":177,"fee":-0.00009985,"label":"","time":1572189626,"timereceived":1572189626,"txid":"eabc01e45db89ea8cf623f8e22847e4023c69bed3c7d396d573b89dec3fe17a7","vout":1,"walletconflicts":[]},{"address":"3AC6k1Y54knEdkgWjX3TjmWGjDHtJCNZZY","amount":0.17822795,"bip125-replaceable":"no","blockhash":"00000000000000000009a60478f29f4910e29224ea5ed63d77321ac8c624ec45","blockindex":2377,"blocktime":1572190637,"category":"receive","confirmations":177,"involvesWatchonly":true,"label":"3AC6k1Y54knEdkgWjX3TjmWGjDHtJCNZZY","time":1572189626,"timereceived":1572189626,"txid":"eabc01e45db89ea8cf623f8e22847e4023c69bed3c7d396d573b89dec3fe17a7","vout":0,"walletconflicts":[]},{"address":"1JsAjr6d21j9T8EMsYnQ6GXf1mM523JAv1","amount":0.00035664,"bip125-replaceable":"no","blockhash":"00000000000000000009a60478f29f4910e29224ea5ed63d77321ac8c624ec45","blockindex":2377,"blocktime":1572190637,"category":"receive","confirmations":177,"label":"","time":1572189626,"timereceived":1572189626,"txid":"eabc01e45db89ea8cf623f8e22847e4023c69bed3c7d396d573b89dec3fe17a7","vout":1,"walletconflicts":[]},{"abandoned":false,"address":"1Q3kQ1jsB2VyH83PJT1NXJqEaEcR6Yuknn","amount":-0.17809412,"bip125-replaceable":"no","blockhash":"000000000000000000125e17a9540ac901d70e92e987d59a1cf87ca36ebca830","blockindex":1680,"blocktime":1572191122,"category":"send","confirmations":176,"fee":-0.00013383,"involvesWatchonly":true,"time":1572190821,"timereceived":1572190821,"txid":"d3579f7be169ea8fd1358d0eda85bad31ce8080a6020dcd224eac8a663dc9bf7","vout":0,"walletconflicts":[]},{"abandoned":false,"address":"326VCyLKV1w4SxeYs81jQU1SC11njcL1eG","amount":-0.039676,"bip125-replaceable":"no","blockhash":"0000000000000000000d61630db06ed5d3054a39bf71a706efeaa9e86866b9d4","blockindex":2193,"blocktime":1572053656,"category":"send","confirmations":380,"fee":-0.00005653,"involvesWatchonly":true,"label":"326VCyLKV1w4SxeYs81jQU1SC11njcL1eG","time":1572052431,"timereceived":1572052431,"txid":"37b57fb36312e21ec7d069a55ab9bffc6abc7fe3731ed38502c5329025a9edf9","vout":0,"walletconflicts":[]},{"abandoned":false,"address":"1JsAjr6d21j9T8EMsYnQ6GXf1mM523JAv1","amount":-0.01845911,"bip125-replaceable":"no","blockhash":"0000000000000000000d61630db06ed5d3054a39bf71a706efeaa9e86866b9d4","blockindex":2193,"blocktime":1572053656,"category":"send","confirmations":380,"fee":-0.00005653,"label":"","time":1572052431,"timereceived":1572052431,"txid":"37b57fb36312e21ec7d069a55ab9bffc6abc7fe3731ed38502c5329025a9edf9","vout":1,"walletconflicts":[]},{"address":"326VCyLKV1w4SxeYs81jQU1SC11njcL1eG","amount":0.039676,"bip125-replaceable":"no","blockhash":"0000000000000000000d61630db06ed5d3054a39bf71a706efeaa9e86866b9d4","blockindex":2193,"blocktime":1572053656,"category":"receive","confirmations":380,"involvesWatchonly":true,"label":"326VCyLKV1w4SxeYs81jQU1SC11njcL1eG","time":1572052431,"timereceived":1572052431,"txid":"37b57fb36312e21ec7d069a55ab9bffc6abc7fe3731ed38502c5329025a9edf9","vout":0,"walletconflicts":[]},{"address":"1JsAjr6d21j9T8EMsYnQ6GXf1mM523JAv1","amount":0.01845911,"bip125-replaceable":"no","blockhash":"0000000000000000000d61630db06ed5d3054a39bf71a706efeaa9e86866b9d4","blockindex":2193,"blocktime":1572053656,"category":"receive","confirmations":380,"label":"","time":1572052431,"timereceived":1572052431,"txid":"37b57fb36312e21ec7d069a55ab9bffc6abc7fe3731ed38502c5329025a9edf9","vout":1,"walletconflicts":[]}]}"#;
    let _res: ListSinceBlockRes = unwrap!(json::from_str(input));
}

#[test]
#[ignore]
fn get_tx_details_doge() {
    let conf = json!(  {
        "coin": "DOGE",
        "name": "dogecoin",
        "fname": "Dogecoin",
        "rpcport": 22555,
        "pubtype": 30,
        "p2shtype": 22,
        "wiftype": 158,
        "txfee": 0,
        "mm2": 1,
        "required_confirmations": 2
    });
    let req = json!({
         "method": "electrum",
         "servers": [{"url":"electrum1.cipig.net:10060"},{"url":"electrum2.cipig.net:10060"},{"url":"electrum3.cipig.net:10060"}]
    });

    let ctx = MmCtxBuilder::new().into_mm_arc();

    use common::executor::spawn;
    let coin = unwrap!(block_on(utxo_standard_coin_from_conf_and_request(
        &ctx, "DOGE", &conf, &req, &[1u8; 32]
    )));

    let coin1 = coin.clone();
    let coin2 = coin.clone();
    let fut1 = async move {
        let block = coin1.current_block().compat().await.unwrap();
        log!((block));
        let hash = hex::decode("99caab76bd025d189f10856dc649aad1a191b1cfd9b139ece457c5fedac58132").unwrap();
        loop {
            let tx_details = coin1.tx_details_by_hash(&hash).compat().await.unwrap();
            log!([tx_details]);
            Timer::sleep(1.).await;
        }
    };
    let fut2 = async move {
        let block = coin2.current_block().compat().await.unwrap();
        log!((block));
        let hash = hex::decode("99caab76bd025d189f10856dc649aad1a191b1cfd9b139ece457c5fedac58132").unwrap();
        loop {
            let tx_details = coin2.tx_details_by_hash(&hash).compat().await.unwrap();
            log!([tx_details]);
            Timer::sleep(1.).await;
        }
    };
    spawn(fut1);
    spawn(fut2);
    loop {}
}

#[test]
// https://github.com/KomodoPlatform/atomicDEX-API/issues/587
fn get_tx_details_coinbase_transaction() {
    let client = electrum_client_for_test(&[
        "electrum1.cipig.net:10018",
        "electrum2.cipig.net:10018",
        "electrum3.cipig.net:10018",
    ]);
    let coin = utxo_coin_for_test(
        client.into(),
        Some("spice describe gravity federal blast come thank unfair canal monkey style afraid"),
    );

    let fut = async move {
        // hash of coinbase transaction https://morty.explorer.dexstats.info/tx/b59b093ed97c1798f2a88ee3375a0c11d0822b6e4468478777f899891abd34a5
        let hash = hex::decode("b59b093ed97c1798f2a88ee3375a0c11d0822b6e4468478777f899891abd34a5").unwrap();

        let tx_details = coin.tx_details_by_hash(&hash).compat().await.unwrap();
        assert!(tx_details.from.is_empty());
    };

    block_on(fut);
}

#[test]
fn test_electrum_rpc_client_error() {
    let client = electrum_client_for_test(&["electrum1.cipig.net:10060"]);

    let empty_hash = H256Json::default();
    let err = unwrap_err!(client.get_verbose_transaction(empty_hash).wait());

    // use the static string instead because the actual error message cannot be obtain
    // by serde_json serialization
    let expected = r#"JsonRpcError { client_info: "coin: RICK", request: JsonRpcRequest { jsonrpc: "2.0", id: "0", method: "blockchain.transaction.get", params: [String("0000000000000000000000000000000000000000000000000000000000000000"), Bool(true)] }, error: Response(electrum1.cipig.net:10060, Object({"code": Number(2), "message": String("daemon error: DaemonError({\'code\': -5, \'message\': \'No such mempool or blockchain transaction. Use gettransaction for wallet transactions.\'})")})) }"#;
    let actual = format!("{}", err);

    assert_eq!(expected, actual);
}

#[test]
fn test_network_info_deserialization() {
    let network_info_kmd = r#"{
        "connections": 1,
        "localaddresses": [],
        "localservices": "0000000070000005",
        "networks": [
            {
                "limited": false,
                "name": "ipv4",
                "proxy": "",
                "proxy_randomize_credentials": false,
                "reachable": true
            },
            {
                "limited": false,
                "name": "ipv6",
                "proxy": "",
                "proxy_randomize_credentials": false,
                "reachable": true
            },
            {
                "limited": true,
                "name": "onion",
                "proxy": "",
                "proxy_randomize_credentials": false,
                "reachable": false
            }
        ],
        "protocolversion": 170007,
        "relayfee": 1e-06,
        "subversion": "/MagicBean:2.0.15-rc2/",
        "timeoffset": 0,
        "version": 2001526,
        "warnings": ""
    }"#;
    json::from_str::<NetworkInfo>(network_info_kmd).unwrap();

    let network_info_btc = r#"{
        "version": 180000,
        "subversion": "\/Satoshi:0.18.0\/",
        "protocolversion": 70015,
        "localservices": "000000000000040d",
        "localrelay": true,
        "timeoffset": 0,
        "networkactive": true,
        "connections": 124,
        "networks": [
            {
                "name": "ipv4",
                "limited": false,
                "reachable": true,
                "proxy": "",
                "proxy_randomize_credentials": false
            },
            {
                "name": "ipv6",
                "limited": false,
                "reachable": true,
                "proxy": "",
                "proxy_randomize_credentials": false
            },
            {
                "name": "onion",
                "limited": true,
                "reachable": false,
                "proxy": "",
                "proxy_randomize_credentials": false
            }
        ],
        "relayfee": 1.0e-5,
        "incrementalfee": 1.0e-5,
        "localaddresses": [
            {
                "address": "96.57.248.252",
                "port": 8333,
                "score": 618294
            }
        ],
        "warnings": ""
    }"#;
    json::from_str::<NetworkInfo>(network_info_btc).unwrap();
}

#[test]
// https://github.com/KomodoPlatform/atomicDEX-API/issues/617
fn test_generate_transaction_relay_fee_is_used_when_dynamic_fee_is_lower() {
    let client = NativeClientImpl {
        coin_ticker: "RICK".into(),
        uri: "http://127.0.0.1:10271".to_owned(),
        auth: fomat!("Basic "(base64_encode(
            "user481805103:pass97a61c8d048bcf468c6c39a314970e557f57afd1d8a5edee917fb29bafb3a43371",
            URL_SAFE
        ))),
        event_handlers: Default::default(),
    };

    static mut GET_RELAY_FEE_CALLED: bool = false;
    NativeClient::get_relay_fee.mock_safe(|_| {
        unsafe { GET_RELAY_FEE_CALLED = true };
        MockResult::Return(Box::new(futures01::future::ok("1.0".parse().unwrap())))
    });
    let client = UtxoRpcClientEnum::Native(NativeClient(Arc::new(client)));
    let mut coin = utxo_coin_fields_for_test(client, None);
    coin.force_min_relay_fee = true;
    let coin = utxo_coin_from_fields(coin);
    let unspents = vec![UnspentInfo {
        value: 1000000000,
        outpoint: OutPoint::default(),
        height: Default::default(),
    }];

    let outputs = vec![TransactionOutput {
        script_pubkey: vec![].into(),
        value: 900000000,
    }];

    let fut = coin.generate_transaction(
        unspents,
        outputs,
        FeePolicy::SendExact,
        Some(ActualTxFee::Dynamic(100)),
        None,
    );
    let generated = unwrap!(block_on(fut));
    assert_eq!(generated.0.outputs.len(), 1);

    // generated transaction fee must be equal to relay fee if calculated dynamic fee is lower than relay
    assert_eq!(generated.1.fee_amount, 100000000);
    assert_eq!(generated.1.received_by_me, 0);
    assert_eq!(generated.1.spent_by_me, 1000000000);
    assert!(unsafe { GET_RELAY_FEE_CALLED });
}

#[test]
// https://github.com/KomodoPlatform/atomicDEX-API/issues/617
fn test_generate_tx_fee_is_correct_when_dynamic_fee_is_larger_than_relay() {
    let client = NativeClientImpl {
        coin_ticker: "RICK".into(),
        uri: "http://127.0.0.1:10271".to_owned(),
        auth: fomat!("Basic "(base64_encode(
            "user481805103:pass97a61c8d048bcf468c6c39a314970e557f57afd1d8a5edee917fb29bafb3a43371",
            URL_SAFE
        ))),
        event_handlers: Default::default(),
    };

    static mut GET_RELAY_FEE_CALLED: bool = false;
    NativeClient::get_relay_fee.mock_safe(|_| {
        unsafe { GET_RELAY_FEE_CALLED = true };
        MockResult::Return(Box::new(futures01::future::ok("0.00001".parse().unwrap())))
    });
    let client = UtxoRpcClientEnum::Native(NativeClient(Arc::new(client)));
    let mut coin = utxo_coin_fields_for_test(client, None);
    coin.force_min_relay_fee = true;
    let coin = utxo_coin_from_fields(coin);
    let unspents = vec![
        UnspentInfo {
            value: 1000000000,
            outpoint: OutPoint::default(),
            height: Default::default(),
        };
        20
    ];

    let outputs = vec![TransactionOutput {
        script_pubkey: vec![].into(),
        value: 19000000000,
    }];

    let fut = coin.generate_transaction(
        unspents,
        outputs,
        FeePolicy::SendExact,
        Some(ActualTxFee::Dynamic(1000)),
        None,
    );
    let generated = unwrap!(block_on(fut));
    assert_eq!(generated.0.outputs.len(), 2);
    assert_eq!(generated.0.inputs.len(), 20);

    // resulting signed transaction size would be 3032 bytes so fee is 3032 sat
    assert_eq!(generated.1.fee_amount, 3032);
    assert_eq!(generated.1.received_by_me, 999996968);
    assert_eq!(generated.1.spent_by_me, 20000000000);
    assert!(unsafe { GET_RELAY_FEE_CALLED });
}

#[test]
fn test_get_median_time_past_from_electrum_kmd() {
    let client = electrum_client_for_test(&[
        "electrum1.cipig.net:10001",
        "electrum2.cipig.net:10001",
        "electrum3.cipig.net:10001",
    ]);

    let mtp = client
        .get_median_time_past(1773390, KMD_MTP_BLOCK_COUNT)
        .wait()
        .unwrap();
    // the MTP is block time of 1773385 in this case
    assert_eq!(1583159915, mtp);
}

#[test]
fn test_get_median_time_past_from_electrum_btc() {
    let client = electrum_client_for_test(&[
        "electrum1.cipig.net:10000",
        "electrum2.cipig.net:10000",
        "electrum3.cipig.net:10000",
    ]);

    let mtp = client.get_median_time_past(632858, KMD_MTP_BLOCK_COUNT).wait().unwrap();
    assert_eq!(1591173041, mtp);
}

#[test]
fn test_get_median_time_past_from_native_has_median_in_get_block() {
    let client = native_client_for_test();
    NativeClientImpl::get_block.mock_safe(|_, block_num| {
        assert_eq!(block_num, "632858".to_string());
        let block_data_str = r#"{"hash":"00000000000000000002eb7892b8fdfd7b8e0f089e5cdf96436de680b7e695e3","confirmations":1,"strippedsize":833287,"size":1493229,"weight":3993090,"height":632858,"version":549453824,"versionHex":"20c00000","merkleroot":"7e20760d227465d2a84fbb2617b2962f77364daa66f06b48d1010fa27923b940","tx":[],"time":1591174568,"mediantime":1591173041,"nonce":"1594651477","bits":"171297f6","difficulty":15138043247082.88,"chainwork":"00000000000000000000000000000000000000000fff2e35384d3c16f53adda4","nTx":1601,"previousblockhash":"00000000000000000009a54084d9f4eafa3ca07af646ff8fa9031d0ac72a92aa"}"#;
        let block_data = json::from_str(block_data_str).unwrap();
        MockResult::Return(
            Box::new(futures01::future::ok(block_data))
        )
    });

    let mtp = client.get_median_time_past(632858, KMD_MTP_BLOCK_COUNT).wait().unwrap();
    assert_eq!(1591173041, mtp);
}

#[test]
fn test_get_median_time_past_from_native_does_not_have_median_in_get_block() {
    let blocks_json_str = r#"
    [
        {"hash":"00000000000000000002eb7892b8fdfd7b8e0f089e5cdf96436de680b7e695e3","confirmations":1,"strippedsize":833287,"size":1493229,"weight":3993090,"height":632858,"version":549453824,"versionHex":"20c00000","merkleroot":"7e20760d227465d2a84fbb2617b2962f77364daa66f06b48d1010fa27923b940","tx":[],"time":1591173090,"nonce":"1594651477","bits":"171297f6","difficulty":15138043247082.88,"chainwork":"00000000000000000000000000000000000000000fff2e35384d3c16f53adda4","nTx":1601,"previousblockhash":"00000000000000000009a54084d9f4eafa3ca07af646ff8fa9031d0ac72a92aa"},
        {"hash":"00000000000000000002eb7892b8fdfd7b8e0f089e5cdf96436de680b7e695e3","confirmations":1,"strippedsize":833287,"size":1493229,"weight":3993090,"height":632857,"version":549453824,"versionHex":"20c00000","merkleroot":"7e20760d227465d2a84fbb2617b2962f77364daa66f06b48d1010fa27923b940","tx":[],"time":1591173080,"nonce":"1594651477","bits":"171297f6","difficulty":15138043247082.88,"chainwork":"00000000000000000000000000000000000000000fff2e35384d3c16f53adda4","nTx":1601,"previousblockhash":"00000000000000000009a54084d9f4eafa3ca07af646ff8fa9031d0ac72a92aa"},
        {"hash":"00000000000000000002eb7892b8fdfd7b8e0f089e5cdf96436de680b7e695e3","confirmations":1,"strippedsize":833287,"size":1493229,"weight":3993090,"height":632856,"version":549453824,"versionHex":"20c00000","merkleroot":"7e20760d227465d2a84fbb2617b2962f77364daa66f06b48d1010fa27923b940","tx":[],"time":1591173070,"nonce":"1594651477","bits":"171297f6","difficulty":15138043247082.88,"chainwork":"00000000000000000000000000000000000000000fff2e35384d3c16f53adda4","nTx":1601,"previousblockhash":"00000000000000000009a54084d9f4eafa3ca07af646ff8fa9031d0ac72a92aa"},
        {"hash":"00000000000000000002eb7892b8fdfd7b8e0f089e5cdf96436de680b7e695e3","confirmations":1,"strippedsize":833287,"size":1493229,"weight":3993090,"height":632855,"version":549453824,"versionHex":"20c00000","merkleroot":"7e20760d227465d2a84fbb2617b2962f77364daa66f06b48d1010fa27923b940","tx":[],"time":1591173058,"nonce":"1594651477","bits":"171297f6","difficulty":15138043247082.88,"chainwork":"00000000000000000000000000000000000000000fff2e35384d3c16f53adda4","nTx":1601,"previousblockhash":"00000000000000000009a54084d9f4eafa3ca07af646ff8fa9031d0ac72a92aa"},
        {"hash":"00000000000000000002eb7892b8fdfd7b8e0f089e5cdf96436de680b7e695e3","confirmations":1,"strippedsize":833287,"size":1493229,"weight":3993090,"height":632854,"version":549453824,"versionHex":"20c00000","merkleroot":"7e20760d227465d2a84fbb2617b2962f77364daa66f06b48d1010fa27923b940","tx":[],"time":1591173050,"nonce":"1594651477","bits":"171297f6","difficulty":15138043247082.88,"chainwork":"00000000000000000000000000000000000000000fff2e35384d3c16f53adda4","nTx":1601,"previousblockhash":"00000000000000000009a54084d9f4eafa3ca07af646ff8fa9031d0ac72a92aa"},
        {"hash":"00000000000000000002eb7892b8fdfd7b8e0f089e5cdf96436de680b7e695e3","confirmations":1,"strippedsize":833287,"size":1493229,"weight":3993090,"height":632853,"version":549453824,"versionHex":"20c00000","merkleroot":"7e20760d227465d2a84fbb2617b2962f77364daa66f06b48d1010fa27923b940","tx":[],"time":1591173041,"nonce":"1594651477","bits":"171297f6","difficulty":15138043247082.88,"chainwork":"00000000000000000000000000000000000000000fff2e35384d3c16f53adda4","nTx":1601,"previousblockhash":"00000000000000000009a54084d9f4eafa3ca07af646ff8fa9031d0ac72a92aa"},
        {"hash":"00000000000000000002eb7892b8fdfd7b8e0f089e5cdf96436de680b7e695e3","confirmations":1,"strippedsize":833287,"size":1493229,"weight":3993090,"height":632852,"version":549453824,"versionHex":"20c00000","merkleroot":"7e20760d227465d2a84fbb2617b2962f77364daa66f06b48d1010fa27923b940","tx":[],"time":1591173040,"nonce":"1594651477","bits":"171297f6","difficulty":15138043247082.88,"chainwork":"00000000000000000000000000000000000000000fff2e35384d3c16f53adda4","nTx":1601,"previousblockhash":"00000000000000000009a54084d9f4eafa3ca07af646ff8fa9031d0ac72a92aa"},
        {"hash":"00000000000000000002eb7892b8fdfd7b8e0f089e5cdf96436de680b7e695e3","confirmations":1,"strippedsize":833287,"size":1493229,"weight":3993090,"height":632851,"version":549453824,"versionHex":"20c00000","merkleroot":"7e20760d227465d2a84fbb2617b2962f77364daa66f06b48d1010fa27923b940","tx":[],"time":1591173039,"nonce":"1594651477","bits":"171297f6","difficulty":15138043247082.88,"chainwork":"00000000000000000000000000000000000000000fff2e35384d3c16f53adda4","nTx":1601,"previousblockhash":"00000000000000000009a54084d9f4eafa3ca07af646ff8fa9031d0ac72a92aa"},
        {"hash":"00000000000000000002eb7892b8fdfd7b8e0f089e5cdf96436de680b7e695e3","confirmations":1,"strippedsize":833287,"size":1493229,"weight":3993090,"height":632850,"version":549453824,"versionHex":"20c00000","merkleroot":"7e20760d227465d2a84fbb2617b2962f77364daa66f06b48d1010fa27923b940","tx":[],"time":1591173038,"nonce":"1594651477","bits":"171297f6","difficulty":15138043247082.88,"chainwork":"00000000000000000000000000000000000000000fff2e35384d3c16f53adda4","nTx":1601,"previousblockhash":"00000000000000000009a54084d9f4eafa3ca07af646ff8fa9031d0ac72a92aa"},
        {"hash":"00000000000000000002eb7892b8fdfd7b8e0f089e5cdf96436de680b7e695e3","confirmations":1,"strippedsize":833287,"size":1493229,"weight":3993090,"height":632849,"version":549453824,"versionHex":"20c00000","merkleroot":"7e20760d227465d2a84fbb2617b2962f77364daa66f06b48d1010fa27923b940","tx":[],"time":1591173037,"nonce":"1594651477","bits":"171297f6","difficulty":15138043247082.88,"chainwork":"00000000000000000000000000000000000000000fff2e35384d3c16f53adda4","nTx":1601,"previousblockhash":"00000000000000000009a54084d9f4eafa3ca07af646ff8fa9031d0ac72a92aa"},
        {"hash":"00000000000000000002eb7892b8fdfd7b8e0f089e5cdf96436de680b7e695e3","confirmations":1,"strippedsize":833287,"size":1493229,"weight":3993090,"height":632848,"version":549453824,"versionHex":"20c00000","merkleroot":"7e20760d227465d2a84fbb2617b2962f77364daa66f06b48d1010fa27923b940","tx":[],"time":1591173030,"nonce":"1594651477","bits":"171297f6","difficulty":15138043247082.88,"chainwork":"00000000000000000000000000000000000000000fff2e35384d3c16f53adda4","nTx":1601,"previousblockhash":"00000000000000000009a54084d9f4eafa3ca07af646ff8fa9031d0ac72a92aa"}
    ]
    "#;

    let blocks: Vec<VerboseBlockClient> = json::from_str(blocks_json_str).unwrap();
    let mut blocks: HashMap<_, _> = blocks
        .into_iter()
        .map(|block| (block.height.unwrap().to_string(), block))
        .collect();
    let client = native_client_for_test();
    NativeClientImpl::get_block.mock_safe(move |_, block_num| {
        let block = blocks.remove(&block_num).unwrap();
        MockResult::Return(Box::new(futures01::future::ok(block)))
    });

    let mtp = client.get_median_time_past(632858, KMD_MTP_BLOCK_COUNT).wait().unwrap();
    assert_eq!(1591173041, mtp);
}

#[test]
fn test_cashaddresses_in_tx_details_by_hash() {
    let conf = json!({
        "coin": "BCH",
        "pubtype": 0,
        "p2shtype": 5,
        "mm2": 1,
        "address_format":{"format":"cashaddress","network":"bchtest"},
    });
    let req = json!({
         "method": "electrum",
         "servers": [{"url":"blackie.c3-soft.com:60001"}, {"url":"bch0.kister.net:51001"}, {"url":"testnet.imaginary.cash:50001"}],
    });

    let ctx = MmCtxBuilder::new().into_mm_arc();

    let coin = unwrap!(block_on(utxo_standard_coin_from_conf_and_request(
        &ctx, "BCH", &conf, &req, &[1u8; 32]
    )));

    let hash = hex::decode("0f2f6e0c8f440c641895023782783426c3aca1acc78d7c0db7751995e8aa5751").unwrap();
    let fut = async {
        let tx_details = coin.tx_details_by_hash(&hash).compat().await.unwrap();
        log!([tx_details]);

        assert!(tx_details
            .from
            .iter()
            .any(|addr| addr == "bchtest:qze8g4gx3z428jjcxzpycpxl7ke7d947gca2a7n2la"));
        assert!(tx_details
            .to
            .iter()
            .any(|addr| addr == "bchtest:qr39na5d25wdeecgw3euh9fkd4ygvd4pnsury96597"));
    };

    block_on(fut);
}

#[test]
fn test_address_from_str_with_cashaddress_activated() {
    let conf = json!({
        "coin": "BCH",
        "pubtype": 0,
        "p2shtype": 5,
        "mm2": 1,
        "address_format":{"format":"cashaddress","network":"bitcoincash"},
    });
    let req = json!({
         "method": "electrum",
         "servers": [{"url":"blackie.c3-soft.com:60001"}, {"url":"bch0.kister.net:51001"}, {"url":"testnet.imaginary.cash:50001"}],
    });

    let ctx = MmCtxBuilder::new().into_mm_arc();

    let coin = unwrap!(block_on(utxo_standard_coin_from_conf_and_request(
        &ctx, "BCH", &conf, &req, &[1u8; 32]
    )));

    assert_eq!(
        coin.address_from_str("bitcoincash:qzxqqt9lh4feptf0mplnk58gnajfepzwcq9f2rxk55"),
        Ok("1DmFp16U73RrVZtYUbo2Ectt8mAnYScpqM".into())
    );

    let error = coin
        .address_from_str("1DmFp16U73RrVZtYUbo2Ectt8mAnYScpqM")
        .err()
        .unwrap();
    assert!(error.contains("Cashaddress address format activated for BCH, but legacy format used instead"));

    // other error on parse
    let error = coin
        .address_from_str("bitcoincash:000000000000000000000000000000000000000000")
        .err()
        .unwrap();
    assert!(error.contains("Checksum verification failed"));
}

#[test]
fn test_address_from_str_with_legacy_address_activated() {
    let conf = json!({
        "coin": "BCH",
        "pubtype": 0,
        "p2shtype": 5,
        "mm2": 1,
    });
    let req = json!({
         "method": "electrum",
         "servers": [{"url":"blackie.c3-soft.com:60001"}, {"url":"bch0.kister.net:51001"}, {"url":"testnet.imaginary.cash:50001"}],
    });

    let ctx = MmCtxBuilder::new().into_mm_arc();

    let coin = unwrap!(block_on(utxo_standard_coin_from_conf_and_request(
        &ctx, "BCH", &conf, &req, &[1u8; 32]
    )));

    let expected = Address::from_cashaddress(
        "bitcoincash:qzxqqt9lh4feptf0mplnk58gnajfepzwcq9f2rxk55",
        coin.as_ref().checksum_type,
        coin.as_ref().pub_addr_prefix,
        coin.as_ref().p2sh_addr_prefix,
    )
    .unwrap();
    assert_eq!(
        coin.address_from_str("1DmFp16U73RrVZtYUbo2Ectt8mAnYScpqM"),
        Ok(expected)
    );

    let error = coin
        .address_from_str("bitcoincash:qzxqqt9lh4feptf0mplnk58gnajfepzwcq9f2rxk55")
        .err()
        .unwrap();
    assert!(error.contains("Legacy address format activated for BCH, but cashaddress format used instead"));

    // other error on parse
    let error = coin
        .address_from_str("0000000000000000000000000000000000")
        .err()
        .unwrap();
    assert!(error.contains("Invalid Address"));
}

#[test]
// https://github.com/KomodoPlatform/atomicDEX-API/issues/673
fn test_network_info_negative_time_offset() {
    let info_str = r#"{"version":1140200,"subversion":"/Shibetoshi:1.14.2/","protocolversion":70015,"localservices":"0000000000000005","localrelay":true,"timeoffset":-1,"networkactive":true,"connections":12,"networks":[{"name":"ipv4","limited":false,"reachable":true,"proxy":"","proxy_randomize_credentials":false},{"name":"ipv6","limited":false,"reachable":true,"proxy":"","proxy_randomize_credentials":false},{"name":"onion","limited":false,"reachable":true,"proxy":"127.0.0.1:9050","proxy_randomize_credentials":true}],"relayfee":1.00000000,"incrementalfee":0.00001000,"localaddresses":[],"warnings":""}"#;
    let _info: NetworkInfo = json::from_str(&info_str).unwrap();
}

#[test]
fn test_unavailable_electrum_proto_version() {
    ElectrumClientImpl::new.mock_safe(|coin_ticker, event_handlers| {
        MockResult::Return(ElectrumClientImpl::with_protocol_version(
            coin_ticker,
            event_handlers,
            OrdRange::new(1.8, 1.9).unwrap(),
        ))
    });

    let conf = json!({"coin":"RICK","asset":"RICK","rpcport":8923});
    let req = json!({
         "method": "electrum",
         "servers": [{"url":"electrum1.cipig.net:10017"}],
    });

    let ctx = MmCtxBuilder::new().into_mm_arc();
    let error = unwrap!(block_on(utxo_standard_coin_from_conf_and_request(
        &ctx, "RICK", &conf, &req, &[1u8; 32]
    ))
    .err());
    log!("Error: "(error));
    assert!(error.contains("There are no Electrums with the required protocol version"));
}

#[test]
fn test_one_unavailable_electrum_proto_version() {
    ElectrumClientImpl::new.mock_safe(|coin_ticker, event_handlers| {
        MockResult::Return(ElectrumClientImpl::with_protocol_version(
            coin_ticker,
            event_handlers,
            OrdRange::new(1.4, 1.4).unwrap(),
        ))
    });

    // check if the electrum-mona.bitbank.cc:50001 doesn't support the protocol version 1.4
    let client = electrum_client_for_test(&["electrum-mona.bitbank.cc:50001"]);
    let result = client
        .server_version(
            "electrum-mona.bitbank.cc:50001",
            "AtomicDEX",
            &OrdRange::new(1.4, 1.4).unwrap(),
        )
        .wait();
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("unsupported protocol version"));

    drop(client);
    log!("Run BTC coin to test the server.version loop");

    let conf = json!({"coin":"BTC","asset":"BTC","rpcport":8332});
    let req = json!({
         "method": "electrum",
         // electrum-mona.bitbank.cc:50001 supports only 1.2 protocol version
         "servers": [{"url":"electrum1.cipig.net:10000"},{"url":"electrum-mona.bitbank.cc:50001"}],
    });

    let ctx = MmCtxBuilder::new().into_mm_arc();
    let coin = unwrap!(block_on(utxo_standard_coin_from_conf_and_request(
        &ctx, "BTC", &conf, &req, &[1u8; 32]
    )));

    block_on(async { Timer::sleep(0.5).await });

    assert!(coin.as_ref().rpc_client.get_block_count().wait().is_ok());
}

#[test]
fn test_unspendable_balance_failed_once() {
    let mut unspents = vec![
        // unspendable balance (8) > balance (7.777)
        vec![
            UnspentInfo {
                outpoint: OutPoint {
                    hash: 1.into(),
                    index: 0,
                },
                value: 500000000,
                height: Default::default(),
            },
            UnspentInfo {
                outpoint: OutPoint {
                    hash: 1.into(),
                    index: 0,
                },
                value: 300000000,
                height: Default::default(),
            },
        ],
        // unspendable balance (7.777) == balance (7.777)
        vec![
            UnspentInfo {
                outpoint: OutPoint {
                    hash: 1.into(),
                    index: 0,
                },
                value: 333300000,
                height: Default::default(),
            },
            UnspentInfo {
                outpoint: OutPoint {
                    hash: 1.into(),
                    index: 0,
                },
                value: 444400000,
                height: Default::default(),
            },
        ],
    ];
    UtxoStandardCoin::ordered_mature_unspents.mock_safe(move |_, _| {
        let unspents = unspents.pop().unwrap();
        MockResult::Return(Box::new(futures01::future::ok(unspents)))
    });

    let conf = json!({"coin":"RICK","asset":"RICK","rpcport":8923});
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"electrum1.cipig.net:10017"}],
    });

    let ctx = MmCtxBuilder::new().into_mm_arc();

    let priv_key = [
        184, 199, 116, 240, 113, 222, 8, 199, 253, 143, 98, 185, 127, 26, 87, 38, 246, 206, 159, 27, 207, 20, 27, 112,
        184, 102, 137, 37, 78, 214, 113, 78,
    ];
    let coin = unwrap!(block_on(utxo_standard_coin_from_conf_and_request(
        &ctx, "RICK", &conf, &req, &priv_key
    )));

    let balance = coin.my_balance().wait().unwrap();
    let expected = "7.777".parse().unwrap();
    assert_eq!(balance, expected);

    let unspendable_balance = coin.my_unspendable_balance().wait().unwrap();
    let expected = "0.000".parse().unwrap();
    assert_eq!(unspendable_balance, expected);
}

#[test]
fn test_unspendable_balance_failed() {
    UtxoStandardCoin::ordered_mature_unspents.mock_safe(move |_, _| {
        let unspents = vec![
            UnspentInfo {
                outpoint: OutPoint {
                    hash: 1.into(),
                    index: 0,
                },
                value: 500000000,
                height: Default::default(),
            },
            UnspentInfo {
                outpoint: OutPoint {
                    hash: 1.into(),
                    index: 0,
                },
                value: 300000000,
                height: Default::default(),
            },
        ];
        MockResult::Return(Box::new(futures01::future::ok(unspents)))
    });

    let conf = json!({"coin":"RICK","asset":"RICK","rpcport":8923});
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"electrum1.cipig.net:10017"}],
    });

    let ctx = MmCtxBuilder::new().into_mm_arc();

    let priv_key = [
        184, 199, 116, 240, 113, 222, 8, 199, 253, 143, 98, 185, 127, 26, 87, 38, 246, 206, 159, 27, 207, 20, 27, 112,
        184, 102, 137, 37, 78, 214, 113, 78,
    ];
    let coin = unwrap!(block_on(utxo_standard_coin_from_conf_and_request(
        &ctx, "RICK", &conf, &req, &priv_key
    )));

    let balance = coin.my_balance().wait().unwrap();
    let expected = "7.777".parse().unwrap();
    assert_eq!(balance, expected);

    let error = coin.my_unspendable_balance().wait().err().unwrap();
    assert!(error.contains("spendable balance 8 more than total balance 7.777"));
}

#[test]
fn test_tx_history_path_colon_should_be_escaped_for_cash_address() {
    let mut coin = utxo_coin_fields_for_test(native_client_for_test().into(), None);
    coin.address_format = UtxoAddressFormat::CashAddress {
        network: "bitcoincash".into(),
    };
    let coin = utxo_coin_from_fields(coin);
    let ctx = MmCtxBuilder::new().into_mm_arc();
    let path = coin.tx_history_path(&ctx);
    assert!(!path.display().to_string().contains(":"));
}

#[test]
fn test_qrc20_tx_details_by_hash() {
    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });
    let priv_key = [
        192, 240, 176, 226, 14, 170, 226, 96, 107, 47, 166, 243, 154, 48, 28, 243, 18, 144, 240, 1, 79, 103, 178, 42,
        32, 161, 106, 119, 241, 227, 42, 102,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let ctx = MmCtxBuilder::new().into_mm_arc();

    let coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    let expected = json!({
        "tx_hex":"0100000001fcaaf1343a392cc96c93ac6f5e84399a69cf52c29ac70254f17ac484169110b7000000006a47304402201b31345c1f377b2a19603d922796726940e4c8068e64e21d551534799ffacaf002207d382f49c9c069dcdd18c90a51687a346a99857ce8b82b91a6cb1ee391811aee012102cd7745ea1c03c9a1ebbcdb7ab9ee19d4e4d306f44665295d996db7c38527da6bffffffff020000000000000000625403a02526012844a9059cbb0000000000000000000000009e032d4b0090a11dc40fe6c47601499a35d55fbb0000000000000000000000000000000000000000000000000000000011e1a30014d362e096e873eb7907e205fadc6175c6fec7bc44c23540a753010000001976a914f36e14131c70e5f15a3f92b1d7e8622a62e570d888ac13f9ff5e",
        "tx_hash":"39104d29d77ba83c5c6c63ab7a0f096301c443b4538dc6b30140453a40caa80a",
        "from":[
            "qfkXE2cNFEwPFQqvBcqs8m9KrkNa9KV4xi"
        ],
        "to":[
            "qXxsj5RtciAby9T7m98AgAATL4zTi4UwDG"
        ],
        "total_amount":"3",
        "spent_by_me":"3",
        "received_by_me":"0",
        "my_balance_change":"-3",
        "block_height":628164,
        "timestamp":1593833808,
        "fee_details":{
            "coin":"QTUM",
            "miner_fee":"1.01526596",
            "gas_limit":2_500_000,
            "gas_price":40,
            "total_gas_fee":"0.00036231",
        },
        "coin":"QRC20",
        "internal_id":""
    });
    let expected = json::from_value(expected).unwrap();

    let hash = hex::decode("39104d29d77ba83c5c6c63ab7a0f096301c443b4538dc6b30140453a40caa80a").unwrap();
    let actual = unwrap!(coin.tx_details_by_hash(&hash).wait());

    let st = json::to_string(&actual).unwrap();
    println!("{}", st);

    assert_eq!(actual, expected);
}

#[test]
fn test_qrc20_can_i_spend_other_payment() {
    ElectrumClient::display_balance.mock_safe(|_, _, decimal| {
        // required more than 12000000 (QRC20_SWAP_GAS_REQUIRED * QRC20_GAS_PRICE_DEFAULT)
        let balance = big_decimal_from_sat(13000000, decimal);
        MockResult::Return(Box::new(futures01::future::ok(balance)))
    });

    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });
    let priv_key = [
        192, 240, 176, 226, 14, 170, 226, 96, 107, 47, 166, 243, 154, 48, 28, 243, 18, 144, 240, 1, 79, 103, 178, 42,
        32, 161, 106, 119, 241, 227, 42, 102,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let ctx = MmCtxBuilder::new().into_mm_arc();

    let coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    let actual = coin.can_i_spend_other_payment().wait();
    assert_eq!(actual, Ok(()));
}

#[test]
fn test_qrc20_can_i_spend_other_payment_err() {
    ElectrumClient::display_balance.mock_safe(|_, _, decimal| {
        // required more than 12000000 (QRC20_SWAP_GAS_REQUIRED * QRC20_GAS_PRICE_DEFAULT)
        let balance = big_decimal_from_sat(10000000, decimal);
        MockResult::Return(Box::new(futures01::future::ok(balance)))
    });

    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });
    let priv_key = [
        192, 240, 176, 226, 14, 170, 226, 96, 107, 47, 166, 243, 154, 48, 28, 243, 18, 144, 240, 1, 79, 103, 178, 42,
        32, 161, 106, 119, 241, 227, 42, 102,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let ctx = MmCtxBuilder::new().into_mm_arc();

    let coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    let error = coin.can_i_spend_other_payment().wait().err().unwrap();
    log!([error]);
    assert!(error.contains("Base coin balance 0.1 is too low to cover gas fee, required 0.12"));
}

#[test]
#[ignore]
fn test_qrc20_send_maker_payment() {
    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });

    let priv_key = [
        3, 98, 177, 3, 108, 39, 234, 144, 131, 178, 103, 103, 127, 80, 230, 166, 53, 68, 147, 215, 42, 216, 144, 72,
        172, 110, 180, 13, 123, 179, 10, 49,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let ctx = MmCtxBuilder::new().into_mm_arc();
    let coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    let timelock = (now_ms() / 1000) as u32 - 200;
    let taker_pub = hex::decode("022b00078841f37b5d30a6a1defb82b3af4d4e2d24dd4204d41f0c9ce1e875de1a").unwrap();
    let secret_hash = &[1; 20];
    let amount = BigDecimal::from_str("0.2").unwrap();
    let payment = coin
        .send_maker_payment(timelock, &taker_pub, secret_hash, amount)
        .wait()
        .unwrap();
    let tx = match payment {
        TransactionEnum::UtxoTx(tx) => tx,
        _ => panic!("Expected UtxoTx"),
    };

    let tx_hash: H256Json = tx.hash().reversed().into();
    log!([tx_hash]);
    let tx_hex = serialize(&tx);
    log!("tx_hex: "[tx_hex]);

    let confirmations = 1;
    let requires_nota = false;
    let wait_until = (now_ms() / 1000) + 240; // timeout if test takes more than 240 seconds to run
    let check_every = 1;
    unwrap!(coin
        .wait_for_confirmations(&tx_hex, confirmations, requires_nota, wait_until, check_every)
        .wait());
}

#[test]
fn test_qrc20_check_if_my_payment_completed() {
    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });

    let priv_key = [
        3, 98, 177, 3, 108, 39, 234, 144, 131, 178, 103, 103, 127, 80, 230, 166, 53, 68, 147, 215, 42, 216, 144, 72,
        172, 110, 180, 13, 123, 179, 10, 49,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let ctx = MmCtxBuilder::new().into_mm_arc();
    let coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    // tx 35e03bc529528a853ee75dde28f27eec8ed7b152b6af7ab6dfa5d55ea46f25ac
    let tx_hex = hex::decode("0100000003b1fcca3d7c15bb7f694b4e58b939b8835bce4d535e8441d41855d9910a33372f020000006b48304502210091342b2251d13ae0796f6ebf563bb861883d652cbee9f5606dd5bb875af84039022077a21545ff6ec69c9c4eca35e1f127a450abc4f4e60dd032724d70910d6b2835012102cd7745ea1c03c9a1ebbcdb7ab9ee19d4e4d306f44665295d996db7c38527da6bffffffff874c96188a610850d4cd2c29a7fd20e5b9eb7f6748970792a74ad189405b7d9b020000006a473044022055dc1bf716880764e9bcbe8dd3aea05f634541648ec4f5d224eba93fedc54f8002205e38b6136adc46ef8ca65c0b0e9390837e539cbb19df451e33a90e534c12da4c012102cd7745ea1c03c9a1ebbcdb7ab9ee19d4e4d306f44665295d996db7c38527da6bffffffffd52e234ead3b8a2a4718cb6fee039fa96862063fccf95149fb11f27a52bcc352010000006a4730440220527ce41324e53c99b827d3f34e7078d991abf339f24108b7e677fff1b6cf0ffa0220690fe96d4fb8f1673458bc08615b5119f354f6cd589754855fe1dba5f82653aa012102cd7745ea1c03c9a1ebbcdb7ab9ee19d4e4d306f44665295d996db7c38527da6bffffffff030000000000000000625403a08601012844095ea7b3000000000000000000000000ba8b71f3544b93e2f681f996da519a98ace0107a0000000000000000000000000000000000000000000000000000000001312d0014d362e096e873eb7907e205fadc6175c6fec7bc44c20000000000000000e35403a0860101284cc49b415b2a756dd4fe3852ea4a0378c5e984ebb5e4bfa01eca31785457d1729d5928198ef00000000000000000000000000000000000000000000000000000000001312d00000000000000000000000000d362e096e873eb7907e205fadc6175c6fec7bc440000000000000000000000000240b898276ad2cc0d2fe6f527e8e31104e7fde30101010101010101010101010101010101010101000000000000000000000000000000000000000000000000000000000000000000000000000000005f686cef14ba8b71f3544b93e2f681f996da519a98ace0107ac21082fb03000000001976a914f36e14131c70e5f15a3f92b1d7e8622a62e570d888acb86d685f").unwrap();
    let timelock = 0; // ignored
    let other_pub = &[0]; // ignored
    let secret_hash = &[1; 20]; // ignored
    unwrap!(
        coin.check_if_my_payment_completed(&tx_hex, timelock, other_pub, secret_hash)
            .wait(),
        r#"Actually "erc20Payment" hasn't been failed, only "approve" call"#
    );

    // tx c2d4e7f21b98e7ff171718ebebfd9b8e6bb294b1ed6a5ab941d2b49db1d66042
    let tx_hex = hex::decode("0100000001f19600483e8e927df7d717ed1797c2bcd14d526a670de00a702ab04fe16b366b030000006b483045022100d1f4a8fc5d42b6c54916f47f80bb47242813a6a25819349dc1625ea93b1659ee022043ec57748244b341dbb764275cc13b6425d8737aad56dac0aeab97b192263ed2012103693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9ffffffff040000000000000000625403a08601012844095ea7b3000000000000000000000000ba8b71f3544b93e2f681f996da519a98ace0107a000000000000000000000000000000000000000000000000000000000000000014d362e096e873eb7907e205fadc6175c6fec7bc44c20000000000000000625403a08601012844095ea7b3000000000000000000000000ba8b71f3544b93e2f681f996da519a98ace0107a0000000000000000000000000000000000000000000000000000000001312d0014d362e096e873eb7907e205fadc6175c6fec7bc44c20000000000000000e35403a0860101284cc49b415b2a90912129915cbfc9e57f3779110c968f83f7efa3c6445fbbc7bd4bb93f20e888000000000000000000000000000000000000000000000000000000000bebc200000000000000000000000000d362e096e873eb7907e205fadc6175c6fec7bc440000000000000000000000000240b898276ad2cc0d2fe6f527e8e31104e7fde30101010101010101010101010101010101010101000000000000000000000000000000000000000000000000000000000000000000000000000000005f6c4efe14ba8b71f3544b93e2f681f996da519a98ace0107ac2ccd80a01000000001976a9149e032d4b0090a11dc40fe6c47601499a35d55fbb88acc94f6c5f").unwrap();
    let err = unwrap!(
        coin.check_if_my_payment_completed(&tx_hex, timelock, other_pub, secret_hash)
            .wait()
            .err(),
        "Expected an error"
    );
    log!("Error: "[err]);
    assert!(err.contains("'erc20Payment' payment failed with an error: Revert"));

    // QTUM tx 8a51f0ffd45f34974de50f07c5bf2f0949da4e88433f8f75191953a442cf9310 without any contract call
    let tx_hex = hex::decode("020000000113640281c9332caeddd02a8dd0d784809e1ad87bda3c972d89d5ae41f5494b85010000006a47304402207c5c904a93310b8672f4ecdbab356b65dd869a426e92f1064a567be7ccfc61ff02203e4173b9467127f7de4682513a21efb5980e66dbed4da91dff46534b8e77c7ef012102baefe72b3591de2070c0da3853226b00f082d72daa417688b61cb18c1d543d1afeffffff020001b2c4000000001976a9149e032d4b0090a11dc40fe6c47601499a35d55fbb88acbc4dd20c2f0000001976a9144208fa7be80dcf972f767194ad365950495064a488ac76e70800").unwrap();
    let err = unwrap!(
        coin.check_if_my_payment_completed(&tx_hex, timelock, other_pub, secret_hash)
            .wait()
            .err(),
        "Expected an error"
    );
    log!("Error: "[err]);
    assert!(err.contains("Couldn't find erc20Payment contract call"));
}

#[test]
fn test_qrc20_validate_maker_payment() {
    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });

    // this priv_key corresponds to "taker_passphrase" passphrase
    let priv_key = [
        24, 181, 194, 193, 18, 152, 142, 168, 71, 73, 70, 244, 9, 101, 92, 168, 243, 61, 132, 48, 25, 39, 103, 92, 29,
        17, 11, 29, 113, 235, 48, 70,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let ctx = MmCtxBuilder::new().into_mm_arc();
    let coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    assert_eq!(coin.utxo_arc.my_address, "qUX9FGHubczidVjWPCUWuwCUJWpkAtGCgf".into());

    // tx_hash: 016a59dd2b181b3906b0f0333d5c7561dacb332dc99ac39679a591e523f2c49a
    let payment_tx = hex::decode("010000000194448324c14fc6b78c7a52c59debe3240fc392019dbd6f1457422e3308ce1e75010000006b483045022100800a4956a30a36708536d98e8ea55a3d0983b963af6c924f60241616e2ff056d0220239e622f8ec8f1a0f5ef0fc93ff094a8e6b5aab964a62bed680b17bf6a848aac012103693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9ffffffff020000000000000000e35403a0860101284cc49b415b2a0c692f2ec8ebab181a79e31b7baab30fef0902e57f901c47a342643eeafa6b510000000000000000000000000000000000000000000000000000000001312d00000000000000000000000000d362e096e873eb7907e205fadc6175c6fec7bc44000000000000000000000000783cf0be521101942da509846ea476e683aad8320101010101010101010101010101010101010101000000000000000000000000000000000000000000000000000000000000000000000000000000005f72ec7514ba8b71f3544b93e2f681f996da519a98ace0107ac201319302000000001976a9149e032d4b0090a11dc40fe6c47601499a35d55fbb88ac40ed725f").unwrap();
    let time_lock = 1601367157;
    // pubkey of "cMhHM3PMpMrChygR4bLF7QsTdenhWpFrrmf2UezBG3eeFsz41rtL" passphrase
    let maker_pub = hex::decode("03693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9").unwrap();
    let secret_hash = &[1; 20];
    let amount = BigDecimal::from_str("0.2").unwrap();

    unwrap!(coin
        .validate_maker_payment(&payment_tx, time_lock, &maker_pub, secret_hash, amount.clone())
        .wait());

    let maker_pub_dif = hex::decode("022b00078841f37b5d30a6a1defb82b3af4d4e2d24dd4204d41f0c9ce1e875de1a").unwrap();
    let error = unwrap!(coin
        .validate_maker_payment(&payment_tx, time_lock, &maker_pub_dif, secret_hash, amount.clone())
        .wait()
        .err());
    log!("error: "[error]);
    assert!(
        error.contains("Payment tx was sent from wrong address, expected 0x783cf0be521101942da509846ea476e683aad832")
    );

    let amount_dif = BigDecimal::from_str("0.3").unwrap();
    let error = unwrap!(coin
        .validate_maker_payment(&payment_tx, time_lock, &maker_pub, secret_hash, amount_dif)
        .wait()
        .err());
    log!("error: "[error]);
    assert!(error.contains("Invalid 'value'"));

    let secret_hash_dif = &[2; 20];
    let error = unwrap!(coin
        .validate_maker_payment(&payment_tx, time_lock, &maker_pub, secret_hash_dif, amount.clone())
        .wait()
        .err());
    log!("error: "[error]);
    assert!(error.contains("Invalid 'secret_hash'"));

    let time_lock_dif = 123;
    let error = unwrap!(coin
        .validate_maker_payment(&payment_tx, time_lock_dif, &maker_pub, secret_hash, amount)
        .wait()
        .err());
    log!("error: "[error]);
    assert!(error.contains("Invalid 'timelock'"));
}

#[test]
#[ignore]
fn test_taker_spends_maker_payment() {
    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });

    // priv_key of qXxsj5RtciAby9T7m98AgAATL4zTi4UwDG
    let priv_key = [
        3, 98, 177, 3, 108, 39, 234, 144, 131, 178, 103, 103, 127, 80, 230, 166, 53, 68, 147, 215, 42, 216, 144, 72,
        172, 110, 180, 13, 123, 179, 10, 49,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let maker_ctx = MmCtxBuilder::new().into_mm_arc();
    let maker_coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &maker_ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    // priv_key of qUX9FGHubczidVjWPCUWuwCUJWpkAtGCgf
    let priv_key = [
        24, 181, 194, 193, 18, 152, 142, 168, 71, 73, 70, 244, 9, 101, 92, 168, 243, 61, 132, 48, 25, 39, 103, 92, 29,
        17, 11, 29, 113, 235, 48, 70,
    ];

    let taker_ctx = MmCtxBuilder::new().into_mm_arc();
    let taker_coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &taker_ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    let bob_balance = taker_coin.my_balance().wait().unwrap();

    let timelock = (now_ms() / 1000) as u32 - 200;
    // pubkey of "taker_passphrase" passphrase and qUX9FGHubczidVjWPCUWuwCUJWpkAtGCgf address
    let taker_pub = hex::decode("022b00078841f37b5d30a6a1defb82b3af4d4e2d24dd4204d41f0c9ce1e875de1a").unwrap();
    // pubkey of "cMhHM3PMpMrChygR4bLF7QsTdenhWpFrrmf2UezBG3eeFsz41rtL" passphrase
    let maker_pub = hex::decode("03693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9").unwrap();
    let secret = &[1; 32];
    let secret_hash = &*dhash160(secret);
    let amount = BigDecimal::from_str("0.2").unwrap();
    let payment = maker_coin
        .send_maker_payment(timelock, &taker_pub, secret_hash, amount.clone())
        .wait()
        .unwrap();
    let tx = match payment {
        TransactionEnum::UtxoTx(tx) => tx,
        _ => panic!("Expected UtxoTx"),
    };

    let payment_tx_hash: H256Json = tx.hash().reversed().into();
    log!("Maker payment: "[payment_tx_hash]);
    let tx_hex = serialize(&tx);

    let confirmations = 1;
    let requires_nota = false;
    let wait_until = (now_ms() / 1000) + 320; // timeout if test takes more than 320 seconds to run
    let check_every = 1;
    unwrap!(taker_coin
        .wait_for_confirmations(&tx_hex, confirmations, requires_nota, wait_until, check_every)
        .wait());

    unwrap!(taker_coin
        .validate_maker_payment(&tx_hex, timelock, &maker_pub, secret_hash, amount.clone())
        .wait());

    let spend = unwrap!(taker_coin
        .send_taker_spends_maker_payment(&tx_hex, timelock, &maker_pub, secret)
        .wait());
    let spend_tx = match spend {
        TransactionEnum::UtxoTx(tx) => tx,
        _ => panic!("Expected UtxoTx"),
    };

    let spend_tx_hash: H256Json = spend_tx.hash().reversed().into();
    log!("Taker spends tx: "[spend_tx_hash]);
    let spend_tx_hex = serialize(&spend_tx);
    let wait_until = (now_ms() / 1000) + 240; // timeout if test takes more than 240 seconds to run
    unwrap!(taker_coin
        .wait_for_confirmations(&spend_tx_hex, confirmations, requires_nota, wait_until, check_every)
        .wait());

    let bob_new_balance = taker_coin.my_balance().wait().unwrap();
    assert_eq!(bob_balance + amount, bob_new_balance);
}

#[test]
#[ignore]
fn test_maker_spends_taker_payment() {
    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });

    // priv_key of qXxsj5RtciAby9T7m98AgAATL4zTi4UwDG
    let priv_key = [
        3, 98, 177, 3, 108, 39, 234, 144, 131, 178, 103, 103, 127, 80, 230, 166, 53, 68, 147, 215, 42, 216, 144, 72,
        172, 110, 180, 13, 123, 179, 10, 49,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let maker_ctx = MmCtxBuilder::new().into_mm_arc();
    let maker_coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &maker_ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    // priv_key of qUX9FGHubczidVjWPCUWuwCUJWpkAtGCgf
    let priv_key = [
        24, 181, 194, 193, 18, 152, 142, 168, 71, 73, 70, 244, 9, 101, 92, 168, 243, 61, 132, 48, 25, 39, 103, 92, 29,
        17, 11, 29, 113, 235, 48, 70,
    ];

    let taker_ctx = MmCtxBuilder::new().into_mm_arc();
    let taker_coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &taker_ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    let maker_balance = maker_coin.my_balance().wait().unwrap();

    let timelock = (now_ms() / 1000) as u32 - 200;
    // pubkey of "taker_passphrase" passphrase and qUX9FGHubczidVjWPCUWuwCUJWpkAtGCgf address
    let taker_pub = hex::decode("022b00078841f37b5d30a6a1defb82b3af4d4e2d24dd4204d41f0c9ce1e875de1a").unwrap();
    // pubkey of "cMhHM3PMpMrChygR4bLF7QsTdenhWpFrrmf2UezBG3eeFsz41rtL" passphrase
    let maker_pub = hex::decode("03693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9").unwrap();
    let secret = &[1; 32];
    let secret_hash = &*dhash160(secret);
    let amount = BigDecimal::from_str("0.2").unwrap();
    let payment = taker_coin
        .send_taker_payment(timelock, &maker_pub, secret_hash, amount.clone())
        .wait()
        .unwrap();
    let tx = match payment {
        TransactionEnum::UtxoTx(tx) => tx,
        _ => panic!("Expected UtxoTx"),
    };

    let payment_tx_hash: H256Json = tx.hash().reversed().into();
    log!("Maker payment: "[payment_tx_hash]);
    let tx_hex = serialize(&tx);

    let confirmations = 1;
    let requires_nota = false;
    let wait_until = (now_ms() / 1000) + 320; // timeout if test takes more than 320 seconds to run
    let check_every = 1;
    unwrap!(maker_coin
        .wait_for_confirmations(&tx_hex, confirmations, requires_nota, wait_until, check_every)
        .wait());

    unwrap!(maker_coin
        .validate_taker_payment(&tx_hex, timelock, &taker_pub, secret_hash, amount.clone())
        .wait());

    let spend = unwrap!(maker_coin
        .send_maker_spends_taker_payment(&tx_hex, timelock, &taker_pub, secret)
        .wait());
    let spend_tx = match spend {
        TransactionEnum::UtxoTx(tx) => tx,
        _ => panic!("Expected UtxoTx"),
    };

    let spend_tx_hash: H256Json = spend_tx.hash().reversed().into();
    log!("Taker spends tx: "[spend_tx_hash]);
    let spend_tx_hex = serialize(&spend_tx);
    let wait_until = (now_ms() / 1000) + 240; // timeout if test takes more than 240 seconds to run
    unwrap!(maker_coin
        .wait_for_confirmations(&spend_tx_hex, confirmations, requires_nota, wait_until, check_every)
        .wait());

    let maker_new_balance = maker_coin.my_balance().wait().unwrap();
    assert_eq!(maker_balance + amount, maker_new_balance);
}

#[test]
#[ignore]
fn test_maker_refunds_payment() {
    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });

    // priv_key of qXxsj5RtciAby9T7m98AgAATL4zTi4UwDG
    let priv_key = [
        3, 98, 177, 3, 108, 39, 234, 144, 131, 178, 103, 103, 127, 80, 230, 166, 53, 68, 147, 215, 42, 216, 144, 72,
        172, 110, 180, 13, 123, 179, 10, 49,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let ctx = MmCtxBuilder::new().into_mm_arc();
    let coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    let expected_balance = unwrap!(coin.my_balance().wait());

    let timelock = (now_ms() / 1000) as u32 - 200;
    // pubkey of "taker_passphrase" passphrase and qUX9FGHubczidVjWPCUWuwCUJWpkAtGCgf address
    let taker_pub = hex::decode("022b00078841f37b5d30a6a1defb82b3af4d4e2d24dd4204d41f0c9ce1e875de1a").unwrap();
    let secret_hash = &[1; 20];
    let amount = BigDecimal::from_str("0.2").unwrap();
    let payment = coin
        .send_maker_payment(timelock, &taker_pub, secret_hash, amount.clone())
        .wait()
        .unwrap();
    let tx = match payment {
        TransactionEnum::UtxoTx(tx) => tx,
        _ => panic!("Expected UtxoTx"),
    };

    let payment_tx_hash: H256Json = tx.hash().reversed().into();
    log!("Maker payment: "[payment_tx_hash]);
    let tx_hex = serialize(&tx);

    let confirmations = 1;
    let requires_nota = false;
    let wait_until = (now_ms() / 1000) + 320; // timeout if test takes more than 320 seconds to run
    let check_every = 1;
    unwrap!(coin
        .wait_for_confirmations(&tx_hex, confirmations, requires_nota, wait_until, check_every)
        .wait());

    let balance_after_payment = unwrap!(coin.my_balance().wait());
    assert_eq!(expected_balance.clone() - amount, balance_after_payment);

    let refund = unwrap!(coin
        .send_maker_refunds_payment(&tx_hex, timelock, &taker_pub, secret_hash)
        .wait());
    let refund_tx = match refund {
        TransactionEnum::UtxoTx(tx) => tx,
        _ => panic!("Expected UtxoTx"),
    };

    let refund_tx_hash: H256Json = refund_tx.hash().reversed().into();
    log!("Taker spends tx: "[refund_tx_hash]);
    let refund_tx_hex = serialize(&refund_tx);
    let wait_until = (now_ms() / 1000) + 240; // timeout if test takes more than 240 seconds to run
    unwrap!(coin
        .wait_for_confirmations(&refund_tx_hex, confirmations, requires_nota, wait_until, check_every)
        .wait());

    let balance_after_refund = unwrap!(coin.my_balance().wait());
    assert_eq!(expected_balance, balance_after_refund);
}

#[test]
#[ignore]
fn test_taker_refunds_payment() {
    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });

    // priv_key of qXxsj5RtciAby9T7m98AgAATL4zTi4UwDG
    let priv_key = [
        3, 98, 177, 3, 108, 39, 234, 144, 131, 178, 103, 103, 127, 80, 230, 166, 53, 68, 147, 215, 42, 216, 144, 72,
        172, 110, 180, 13, 123, 179, 10, 49,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let ctx = MmCtxBuilder::new().into_mm_arc();
    let coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    let expected_balance = unwrap!(coin.my_balance().wait());

    let timelock = (now_ms() / 1000) as u32 - 200;
    // pubkey of "taker_passphrase" passphrase and qUX9FGHubczidVjWPCUWuwCUJWpkAtGCgf address
    let maker_pub = hex::decode("022b00078841f37b5d30a6a1defb82b3af4d4e2d24dd4204d41f0c9ce1e875de1a").unwrap();
    let secret_hash = &[1; 20];
    let amount = BigDecimal::from_str("0.2").unwrap();
    let payment = coin
        .send_taker_payment(timelock, &maker_pub, secret_hash, amount.clone())
        .wait()
        .unwrap();
    let tx = match payment {
        TransactionEnum::UtxoTx(tx) => tx,
        _ => panic!("Expected UtxoTx"),
    };

    let payment_tx_hash: H256Json = tx.hash().reversed().into();
    log!("Maker payment: "[payment_tx_hash]);
    let tx_hex = serialize(&tx);

    let confirmations = 1;
    let requires_nota = false;
    let wait_until = (now_ms() / 1000) + 320; // timeout if test takes more than 320 seconds to run
    let check_every = 1;
    unwrap!(coin
        .wait_for_confirmations(&tx_hex, confirmations, requires_nota, wait_until, check_every)
        .wait());

    let balance_after_payment = unwrap!(coin.my_balance().wait());
    assert_eq!(expected_balance.clone() - amount, balance_after_payment);

    let refund = unwrap!(coin
        .send_taker_refunds_payment(&tx_hex, timelock, &maker_pub, secret_hash)
        .wait());
    let refund_tx = match refund {
        TransactionEnum::UtxoTx(tx) => tx,
        _ => panic!("Expected UtxoTx"),
    };

    let refund_tx_hash: H256Json = refund_tx.hash().reversed().into();
    log!("Taker spends tx: "[refund_tx_hash]);
    let refund_tx_hex = serialize(&refund_tx);
    let wait_until = (now_ms() / 1000) + 240; // timeout if test takes more than 240 seconds to run
    unwrap!(coin
        .wait_for_confirmations(&refund_tx_hex, confirmations, requires_nota, wait_until, check_every)
        .wait());

    let balance_after_refund = unwrap!(coin.my_balance().wait());
    assert_eq!(expected_balance, balance_after_refund);
}

#[test]
fn test_qrc20_check_if_my_payment_sent() {
    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });

    // priv_key of qXxsj5RtciAby9T7m98AgAATL4zTi4UwDG
    let priv_key = [
        3, 98, 177, 3, 108, 39, 234, 144, 131, 178, 103, 103, 127, 80, 230, 166, 53, 68, 147, 215, 42, 216, 144, 72,
        172, 110, 180, 13, 123, 179, 10, 49,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let ctx = MmCtxBuilder::new().into_mm_arc();
    let coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    let time_lock = 1601367157;
    // pubkey of "cMhHM3PMpMrChygR4bLF7QsTdenhWpFrrmf2UezBG3eeFsz41rtL" passphrase
    let maker_pub = hex::decode("03693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9").unwrap();
    let secret_hash = &[1; 20];
    // search from b22ee034e860d89af6e76e54bb7f8efb69d833a8670e61c60e5dfdfaa27db371 transaction
    let search_from_block = 686125;

    // tx_hash: 016a59dd2b181b3906b0f0333d5c7561dacb332dc99ac39679a591e523f2c49a
    let expected_tx = TransactionEnum::UtxoTx("010000000194448324c14fc6b78c7a52c59debe3240fc392019dbd6f1457422e3308ce1e75010000006b483045022100800a4956a30a36708536d98e8ea55a3d0983b963af6c924f60241616e2ff056d0220239e622f8ec8f1a0f5ef0fc93ff094a8e6b5aab964a62bed680b17bf6a848aac012103693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9ffffffff020000000000000000e35403a0860101284cc49b415b2a0c692f2ec8ebab181a79e31b7baab30fef0902e57f901c47a342643eeafa6b510000000000000000000000000000000000000000000000000000000001312d00000000000000000000000000d362e096e873eb7907e205fadc6175c6fec7bc44000000000000000000000000783cf0be521101942da509846ea476e683aad8320101010101010101010101010101010101010101000000000000000000000000000000000000000000000000000000000000000000000000000000005f72ec7514ba8b71f3544b93e2f681f996da519a98ace0107ac201319302000000001976a9149e032d4b0090a11dc40fe6c47601499a35d55fbb88ac40ed725f".into());
    let tx = unwrap!(coin
        .check_if_my_payment_sent(time_lock, &maker_pub, secret_hash, search_from_block)
        .wait());
    assert_eq!(tx, Some(expected_tx));

    let time_lock_dif = 1601367156;
    let tx = unwrap!(coin
        .check_if_my_payment_sent(time_lock_dif, &maker_pub, secret_hash, search_from_block)
        .wait());
    assert_eq!(tx, None);
}

#[test]
fn test_qrc20_send_taker_fee() {
    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });

    // priv_key of qXxsj5RtciAby9T7m98AgAATL4zTi4UwDG
    let priv_key = [
        3, 98, 177, 3, 108, 39, 234, 144, 131, 178, 103, 103, 127, 80, 230, 166, 53, 68, 147, 215, 42, 216, 144, 72,
        172, 110, 180, 13, 123, 179, 10, 49,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let ctx = MmCtxBuilder::new().into_mm_arc();
    let coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    let fee_addr_pub_key = hex::decode("03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06").unwrap();
    let amount = BigDecimal::from_str("0.01").unwrap();
    let tx = unwrap!(coin.send_taker_fee(&fee_addr_pub_key, amount.clone()).wait());
    let tx_hash: H256Json = match tx {
        TransactionEnum::UtxoTx(ref tx) => tx.hash().reversed().into(),
        _ => panic!("Expected UtxoTx"),
    };
    log!("Fee tx "[tx_hash]);

    let result = coin.validate_fee(&tx, &fee_addr_pub_key, &amount).wait();
    assert_eq!(result, Ok(()));
}

#[test]
fn test_qrc20_validate_fee() {
    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });

    // priv_key of qXxsj5RtciAby9T7m98AgAATL4zTi4UwDG
    let priv_key = [
        3, 98, 177, 3, 108, 39, 234, 144, 131, 178, 103, 103, 127, 80, 230, 166, 53, 68, 147, 215, 42, 216, 144, 72,
        172, 110, 180, 13, 123, 179, 10, 49,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let ctx = MmCtxBuilder::new().into_mm_arc();
    let coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    // QRC20 transfer tx "f97d3a43dbea0993f1b7a6a299377d4ee164c84935a1eb7d835f70c9429e6a1d"
    let tx = TransactionEnum::UtxoTx("010000000160fd74b5714172f285db2b36f0b391cd6883e7291441631c8b18f165b0a4635d020000006a47304402205d409e141111adbc4f185ae856997730de935ac30a0d2b1ccb5a6c4903db8171022024fc59bbcfdbba283556d7eeee4832167301dc8e8ad9739b7865f67b9676b226012103693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9ffffffff020000000000000000625403a08601012844a9059cbb000000000000000000000000ca1e04745e8ca0c60d8c5881531d51bec470743f00000000000000000000000000000000000000000000000000000000000f424014d362e096e873eb7907e205fadc6175c6fec7bc44c200ada205000000001976a9149e032d4b0090a11dc40fe6c47601499a35d55fbb88acfe967d5f".into());

    let fee_addr = hex::decode("03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06").unwrap();
    let amount = BigDecimal::from_str("0.01").unwrap();

    let result = coin.validate_fee(&tx, &fee_addr, &amount).wait();
    assert_eq!(result, Ok(()));

    let fee_addr_dif = hex::decode("03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc05").unwrap();
    let err = coin
        .validate_fee(&tx, &fee_addr_dif, &amount)
        .wait()
        .err()
        .expect("Expected an error");
    log!("error: "[err]);
    assert!(err.contains("QRC20 Fee tx was sent to wrong address"));

    let amount_dif = BigDecimal::from_str("0.02").unwrap();
    let err = coin
        .validate_fee(&tx, &fee_addr, &amount_dif)
        .wait()
        .err()
        .expect("Expected an error");
    log!("error: "[err]);
    assert!(err.contains("QRC20 Fee tx value 0.01 is less than expected 0.02"));

    // QTUM tx "8a51f0ffd45f34974de50f07c5bf2f0949da4e88433f8f75191953a442cf9310"
    let tx = TransactionEnum::UtxoTx("020000000113640281c9332caeddd02a8dd0d784809e1ad87bda3c972d89d5ae41f5494b85010000006a47304402207c5c904a93310b8672f4ecdbab356b65dd869a426e92f1064a567be7ccfc61ff02203e4173b9467127f7de4682513a21efb5980e66dbed4da91dff46534b8e77c7ef012102baefe72b3591de2070c0da3853226b00f082d72daa417688b61cb18c1d543d1afeffffff020001b2c4000000001976a9149e032d4b0090a11dc40fe6c47601499a35d55fbb88acbc4dd20c2f0000001976a9144208fa7be80dcf972f767194ad365950495064a488ac76e70800".into());
    let err = coin
        .validate_fee(&tx, &fee_addr, &amount)
        .wait()
        .err()
        .expect("Expected an error");
    log!("error: "[err]);
    assert!(err.contains("Expected 'transfer' contract call"));
}

#[test]
fn test_qrc20_search_for_swap_tx_spend() {
    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });

    // priv_key of qXxsj5RtciAby9T7m98AgAATL4zTi4UwDG
    let priv_key = [
        3, 98, 177, 3, 108, 39, 234, 144, 131, 178, 103, 103, 127, 80, 230, 166, 53, 68, 147, 215, 42, 216, 144, 72,
        172, 110, 180, 13, 123, 179, 10, 49,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let ctx = MmCtxBuilder::new().into_mm_arc();
    let coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    let other_pub = &[0]; //ignored
    let search_from_block = 693000;

    // taker spent maker payment - d3f5dab4d54c14b3d7ed8c7f5c8cc7f47ccf45ce589fdc7cd5140a3c1c3df6e1
    let expected = Ok(Some(FoundSwapTxSpend::Spent(TransactionEnum::UtxoTx("01000000033f56ecafafc8602fde083ba868d1192d6649b8433e42e1a2d79ba007ea4f7abb010000006b48304502210093404e90e40d22730013035d31c404c875646dcf2fad9aa298348558b6d65ba60220297d045eac5617c1a3eddb71d4bca9772841afa3c4c9d6c68d8d2d42ee6de3950121022b00078841f37b5d30a6a1defb82b3af4d4e2d24dd4204d41f0c9ce1e875de1affffffff9cac7fe90d597922a1d92e05306c2215628e7ea6d5b855bfb4289c2944f4c73a030000006b483045022100b987da58c2c0c40ce5b6ef2a59e8124ed4ef7a8b3e60c7fb631139280019bc93022069649bcde6fe4dd5df9462a1fcae40598488d6af8c324cd083f5c08afd9568be0121022b00078841f37b5d30a6a1defb82b3af4d4e2d24dd4204d41f0c9ce1e875de1affffffff70b9870f2b0c65d220a839acecebf80f5b44c3ca4c982fa2fdc5552c037f5610010000006a473044022071b34dd3ebb72d29ca24f3fa0fc96571c815668d3b185dd45cc46a7222b6843f02206c39c030e618d411d4124f7b3e7ca1dd5436775bd8083a85712d123d933a51300121022b00078841f37b5d30a6a1defb82b3af4d4e2d24dd4204d41f0c9ce1e875de1affffffff020000000000000000c35403a0860101284ca402ed292b806a1835a1b514ad643f2acdb5c8db6b6a9714accff3275ea0d79a3f23be8fd00000000000000000000000000000000000000000000000000000000001312d000101010101010101010101010101010101010101010101010101010101010101000000000000000000000000d362e096e873eb7907e205fadc6175c6fec7bc440000000000000000000000009e032d4b0090a11dc40fe6c47601499a35d55fbb14ba8b71f3544b93e2f681f996da519a98ace0107ac2c02288d4010000001976a914783cf0be521101942da509846ea476e683aad83288ac0f047f5f".into()))));
    // maker sent payment - c8112c75be039100c30d71293571f081e189540818ef8e2903ff75d2d556b446
    let tx_hex = hex::decode("0100000001e6b256dd9d390be2ccd8eddaf67a40d1994a983845fb223c102ce8e58eca2b48010000006b4830450221008e8e793ad00ed1d45f4546b9e7b9dc8305d61c384e126c24e7945bd0056df099022077f033cf16535f0d3627548196cd3868d904ca6ccac9d80d56f1f70df6589915012103693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9ffffffff020000000000000000e35403a0860101284cc49b415b2a806a1835a1b514ad643f2acdb5c8db6b6a9714accff3275ea0d79a3f23be8fd00000000000000000000000000000000000000000000000000000000001312d00000000000000000000000000d362e096e873eb7907e205fadc6175c6fec7bc44000000000000000000000000783cf0be521101942da509846ea476e683aad8324b6b2e5444c2639cc0fb7bcea5afba3f3cdce239000000000000000000000000000000000000000000000000000000000000000000000000000000005f7f02c014ba8b71f3544b93e2f681f996da519a98ace0107ac27046a001000000001976a9149e032d4b0090a11dc40fe6c47601499a35d55fbb88ac8b037f5f").unwrap();
    let timelock = 1602159296;
    let secret = &[1; 32];
    let secret_hash = &*dhash160(secret);
    let actual = coin.search_for_swap_tx_spend_my(timelock, other_pub, secret_hash, &tx_hex, search_from_block);
    assert_eq!(actual, expected);

    // maker refunded payment his - df41079d58a13320590476e648d37007459366b0fbfce8d0b72fae502e39cc01
    let expected = Ok(Some(FoundSwapTxSpend::Refunded(TransactionEnum::UtxoTx("010000000191999480813e0284212d08a16b32146e7d32315feaf6489cd3aa696b54e5ce71010000006a4730440220282a32f05a4802caee065ee8d2b08a9b366c26b16d9afb068b3259aa54107b0e0220039c7697620e91096d566ddb6056ad347c395584114f790a2a727db86789c576012103693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9ffffffff020000000000000000c35403a0860101284ca446fc0294796332096ae329d7aa84c52f036bbeb9dd4b872c8d2021ccb8775e23f56a422e0000000000000000000000000000000000000000000000000000000001312d000101010101010101010101010101010101010101000000000000000000000000000000000000000000000000d362e096e873eb7907e205fadc6175c6fec7bc44000000000000000000000000783cf0be521101942da509846ea476e683aad83214ba8b71f3544b93e2f681f996da519a98ace0107ac2d012ac00000000001976a9149e032d4b0090a11dc40fe6c47601499a35d55fbb88ac97067f5f".into()))));
    // maker sent payment - 71cee5546b69aad39c48f6ea5f31327d6e14326ba1082d2184023e8180949991
    let tx_hex = hex::decode("0100000001422dd62a9405fbda1f0e01ed45917cd908a68258a5f5530a1f53c4cd173bc82b010000006a47304402201c2c3b789a651143a657217b5b459027b68a78545a5036e03f90bacbc4cfd8b1022055200a3da6b208dc8763471a87d869d6b045f1dd38f855b0fda0b526f23f88ea012103693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9ffffffff020000000000000000e35403a0860101284cc49b415b2a796332096ae329d7aa84c52f036bbeb9dd4b872c8d2021ccb8775e23f56a422e0000000000000000000000000000000000000000000000000000000001312d00000000000000000000000000d362e096e873eb7907e205fadc6175c6fec7bc44000000000000000000000000783cf0be521101942da509846ea476e683aad8320101010101010101010101010101010101010101000000000000000000000000000000000000000000000000000000000000000000000000000000005f7f059f14ba8b71f3544b93e2f681f996da519a98ace0107ac2b81fe900000000001976a9149e032d4b0090a11dc40fe6c47601499a35d55fbb88ac6a067f5f").unwrap();
    let timelock = 1602160031;
    let secret_hash = &[1; 20];
    let actual = coin.search_for_swap_tx_spend_my(timelock, other_pub, secret_hash, &tx_hex, search_from_block);
    assert_eq!(actual, expected);

    // maker payment hasn't been spent or refunded yet
    let expected = Ok(None);
    // maker sent payment 9fae1771bb542f9860d845091109a6a951f95fc277faebe3ec6ab3e8df9e58b6
    let tx_hex = hex::decode("010000000101cc392e50ae2fb7d0e8fcfbb06693450770d348e67604592033a1589d0741df010000006b483045022100935cf73d2b01a694f4383eb844d5e93e041496b13e6bdf1f7a8f3bb8dd83b50002204952184584460cc1ab979895ec4850ea9e26a7308d231376fc21c133c7eeaf08012103693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9ffffffff020000000000000000e35403a0860101284cc49b415b2a4357ff815e6657ea5b4cf992475e29940b3a4cda9b589d5e5061bb06c1f5bf5a0000000000000000000000000000000000000000000000000000000001312d00000000000000000000000000d362e096e873eb7907e205fadc6175c6fec7bc44000000000000000000000000783cf0be521101942da509846ea476e683aad8320101010101010101010101010101010101010101000000000000000000000000000000000000000000000000000000000000000000000000000000005f7f066014ba8b71f3544b93e2f681f996da519a98ace0107ac2e8056f00000000001976a9149e032d4b0090a11dc40fe6c47601499a35d55fbb88ac2b077f5f").unwrap();
    let timelock = 1602160224;
    let secret_hash = &[1; 20];
    let actual = coin.search_for_swap_tx_spend_my(timelock, other_pub, secret_hash, &tx_hex, search_from_block);
    assert_eq!(actual, expected);
}

#[test]
fn test_qrc20_wait_for_tx_spend() {
    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });

    // priv_key of qXxsj5RtciAby9T7m98AgAATL4zTi4UwDG
    let priv_key = [
        3, 98, 177, 3, 108, 39, 234, 144, 131, 178, 103, 103, 127, 80, 230, 166, 53, 68, 147, 215, 42, 216, 144, 72,
        172, 110, 180, 13, 123, 179, 10, 49,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let maker_ctx = MmCtxBuilder::new().into_mm_arc();
    let maker_coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &maker_ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    // priv_key of qUX9FGHubczidVjWPCUWuwCUJWpkAtGCgf
    let priv_key = [
        24, 181, 194, 193, 18, 152, 142, 168, 71, 73, 70, 244, 9, 101, 92, 168, 243, 61, 132, 48, 25, 39, 103, 92, 29,
        17, 11, 29, 113, 235, 48, 70,
    ];

    let taker_ctx = MmCtxBuilder::new().into_mm_arc();
    let taker_coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &taker_ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    let from_block = maker_coin.current_block().wait().unwrap();

    let timelock = (now_ms() / 1000) as u32 - 200;
    // pubkey of "taker_passphrase" passphrase and qUX9FGHubczidVjWPCUWuwCUJWpkAtGCgf address
    let taker_pub = hex::decode("022b00078841f37b5d30a6a1defb82b3af4d4e2d24dd4204d41f0c9ce1e875de1a").unwrap();
    // pubkey of "cMhHM3PMpMrChygR4bLF7QsTdenhWpFrrmf2UezBG3eeFsz41rtL" passphrase
    let maker_pub = hex::decode("03693bff1b39e8b5a306810023c29b95397eb395530b106b1820ea235fd81d9ce9").unwrap();
    let secret = &[1; 32];
    let secret_hash = &*dhash160(secret);
    let amount = BigDecimal::from_str("0.2").unwrap();
    let payment = maker_coin
        .send_maker_payment(timelock, &taker_pub, secret_hash, amount.clone())
        .wait()
        .unwrap();
    let tx = match payment {
        TransactionEnum::UtxoTx(tx) => tx,
        _ => panic!("Expected UtxoTx"),
    };

    let payment_tx_hash: H256Json = tx.hash().reversed().into();
    log!("Maker payment: "[payment_tx_hash]);
    let tx_hex = serialize(&tx);

    let confirmations = 1;
    let requires_nota = false;
    let wait_until = (now_ms() / 1000) + 320; // timeout if test takes more than 320 seconds to run
    let check_every = 1;
    unwrap!(taker_coin
        .wait_for_confirmations(&tx_hex, confirmations, requires_nota, wait_until, check_every)
        .wait());

    unwrap!(taker_coin
        .validate_maker_payment(&tx_hex, timelock, &maker_pub, secret_hash, amount.clone())
        .wait());

    // first try to check if the wait_for_tx_spend() returns an error correctly
    let wait_until = (now_ms() / 1000) + 11;
    let err = maker_coin
        .wait_for_tx_spend(&tx_hex, wait_until, from_block)
        .wait()
        .expect_err("Expected 'Waited too long' error");
    log!("error: "[err]);
    assert!(err.contains("Waited too long"));

    // also spends the maker payment and try to check if the wait_for_tx_spend() returns the correct tx
    let spend_tx: Arc<Mutex<Option<UtxoTx>>> = Arc::new(Mutex::new(None));

    let tx_hex_c = tx_hex.clone();
    let spend_tx_c = spend_tx.clone();
    let fut = async move {
        Timer::sleep(11.).await;

        let spend = unwrap!(
            taker_coin
                .send_taker_spends_maker_payment(&tx_hex_c, timelock, &maker_pub, secret)
                .compat()
                .await
        );
        let mut lock = spend_tx_c.lock().unwrap();
        match spend {
            TransactionEnum::UtxoTx(tx) => *lock = Some(tx),
            _ => panic!("Expected UtxoTx"),
        }
    };

    spawn(fut);

    let wait_until = (now_ms() / 1000) + 320;
    let found = unwrap!(maker_coin.wait_for_tx_spend(&tx_hex, wait_until, from_block).wait());

    let spend_tx = match spend_tx.lock().unwrap().as_ref() {
        Some(tx) => tx.clone(),
        None => panic!(),
    };

    match found {
        TransactionEnum::UtxoTx(tx) => assert_eq!(tx, spend_tx),
        _ => panic!("Unexpected Transaction type"),
    }
}

#[test]
fn test_qrc20_generate_token_transfer_script_pubkey() {
    let conf = json!({
        "coin":"QRC20",
        "required_confirmations":0,
        "pubtype":120,
        "p2shtype":50,
        "wiftype":128,
        "segwit":true,
        "mm2":1,
        "mature_confirmations":500,
    });
    let req = json!({
        "method": "electrum",
        "servers": [{"url":"95.217.83.126:10001"}],
        "swap_contract_address": "0xba8b71f3544b93e2f681f996da519a98ace0107a",
    });

    // priv_key of qXxsj5RtciAby9T7m98AgAATL4zTi4UwDG
    let priv_key = [
        3, 98, 177, 3, 108, 39, 234, 144, 131, 178, 103, 103, 127, 80, 230, 166, 53, 68, 147, 215, 42, 216, 144, 72,
        172, 110, 180, 13, 123, 179, 10, 49,
    ];
    let contract_address = "0xd362e096e873eb7907e205fadc6175c6fec7bc44".into();

    let ctx = MmCtxBuilder::new().into_mm_arc();
    let coin = unwrap!(block_on(qrc20_coin_from_conf_and_request(
        &ctx,
        "QRC20",
        "QTUM",
        &conf,
        &req,
        &priv_key,
        contract_address
    )));

    // sample QRC20 transfer from https://testnet.qtum.info/tx/51e9cec885d7eb26271f8b1434c000f6cf07aad47671268fc8d36cee9d48f6de
    // the script is a script_pubkey of one of the transaction output
    let expected_script: Script = "5403a02526012844a9059cbb0000000000000000000000000240b898276ad2cc0d2fe6f527e8e31104e7fde3000000000000000000000000000000000000000000000000000000003b9aca0014d362e096e873eb7907e205fadc6175c6fec7bc44c2".into();
    let expected = TransactionOutput {
        value: 0,
        script_pubkey: expected_script.to_bytes(),
    };

    let to_addr: Address = "qHmJ3KA6ZAjR9wGjpFASn4gtUSeFAqdZgs".into();
    let to_addr = qrc20_addr_from_utxo_addr(to_addr);
    let amount: U256 = 1000000000.into();
    let gas_limit = 2_500_000;
    let gas_price = 40;
    let actual = coin
        .transfer_output(to_addr.clone(), amount, gas_limit, gas_price)
        .unwrap();
    assert_eq!(expected, actual);

    assert!(coin
        .transfer_output(
            to_addr.clone(),
            amount,
            0, // gas_limit cannot be zero
            gas_price,
        )
        .is_err());

    assert!(coin
        .transfer_output(
            to_addr.clone(),
            amount,
            gas_limit,
            0, // gas_price cannot be zero
        )
        .is_err());
}

/// TODO remove this test (is used to display signatures of contract functions)
#[test]
fn print_tx() {
    let f = crate::eth::SWAP_CONTRACT.function("erc20Payment").unwrap();
    let params = f.short_signature();
    log!("erc20Payment: "[params]);
    log!("hex(erc20Payment): "[hex::encode(params)]);

    let f = crate::eth::ERC20_CONTRACT.function("transfer").unwrap();
    let params = f.short_signature();
    log!("transfer: "[params]);
    log!("hex(transfer): "[hex::encode(params)]);

    let f = crate::eth::ERC20_CONTRACT.function("approve").unwrap();
    let params = f.short_signature();
    log!("approve: "[params]);
    log!("hex(approve): "[hex::encode(params)]);

    let f = crate::eth::SWAP_CONTRACT.function("receiverSpend").unwrap();
    let params = f.short_signature();
    log!("receiverSpend: "[params]);
    log!("hex(receiverSpend): "[hex::encode(params)]);

    let f = crate::eth::SWAP_CONTRACT.function("senderRefund").unwrap();
    let params = f.short_signature();
    log!("senderRefund: "[params]);
    log!("hex(senderRefund): "[hex::encode(params)]);
}
