
/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

//
//  ordermatch.rs
//  marketmaker
//
use bigdecimal::BigDecimal;
use common::{lp, SMALLVAL, rpc_response, rpc_err_response, HyRes};
use common::mm_ctx::{from_ctx, MmArc, MmWeak};
use coins::{lp_coinfind, MmCoinEnum};
use coins::utxo::{compressed_pub_key_from_priv_raw, ChecksumType};
use futures::future::Future;
use gstuff::now_ms;
use hashbrown::hash_map::{Entry, HashMap};
use libc::{self, c_char};
use num_traits::cast::ToPrimitive;
use portfolio::{Order, OrderAmount, PortfolioContext};
use rpc::v1::types::{H256 as H256Json};
use serde_json::{self as json, Value as Json};
use std::ffi::{CString};
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use uuid::Uuid;

use crate::mm2::lp_swap::{MakerSwap, run_maker_swap, TakerSwap, run_taker_swap};

#[derive(Serialize, Deserialize)]
struct TakerRequest {
    base: String,
    rel: String,
    base_amount: BigDecimal,
    rel_amount: BigDecimal,
    uuid: Uuid,
    method: String,
    sender_pubkey: H256Json,
    dest_pub_key: H256Json,
}

#[derive(Serialize, Deserialize)]
struct TakerConnect {
    taker_order_uuid: Uuid,
    maker_order_uuid: Uuid,
    method: String,
    sender_pubkey: H256Json,
    dest_pub_key: H256Json,
}

#[derive(Clone, Serialize, Deserialize)]
struct MakerReserved {
    base: String,
    rel: String,
    base_amount: BigDecimal,
    rel_amount: BigDecimal,
    taker_order_uuid: Uuid,
    maker_order_uuid: Uuid,
    method: String,
    sender_pubkey: H256Json,
    dest_pub_key: H256Json,
}

#[derive(Serialize, Deserialize)]
struct MakerConnected {
    taker_order_uuid: Uuid,
    maker_order_uuid: Uuid,
    method: String,
    sender_pubkey: H256Json,
    dest_pub_key: H256Json,
}

struct OrdermatchContext {
    pub taker_matches: Mutex<HashMap<Uuid, TakerOrderMatch>>,
    pub maker_matches: Mutex<HashMap<Uuid, MakerOrderMatch>>,
}

impl OrdermatchContext {
    /// Obtains a reference to this crate context, creating it if necessary.
    fn from_ctx (ctx: &MmArc) -> Result<Arc<OrdermatchContext>, String> {
        Ok (try_s! (from_ctx (&ctx.ordermatch_ctx, move || {
            Ok (OrdermatchContext {
                taker_matches: Mutex::new (HashMap::default()),
                maker_matches: Mutex::new (HashMap::default()),
            })
        })))
    }

    /// Obtains a reference to this crate context, creating it if necessary.
    #[allow(dead_code)]
    fn from_ctx_weak (ctx_weak: &MmWeak) -> Result<Arc<OrdermatchContext>, String> {
        let ctx = try_s! (MmArc::from_weak (ctx_weak) .ok_or ("Context expired"));
        Self::from_ctx (&ctx)
    }
}

unsafe fn lp_connect_start_bob(ctx: &MmArc, maker_match: &MakerOrderMatch) -> i32 {
    let mut retval = -1;
    let loop_thread = thread::Builder::new().name("maker_loop".into()).spawn({
        let taker_coin = unwrap!(unwrap! (lp_coinfind (ctx, &maker_match.reserved.rel)));
        let maker_coin = unwrap!(unwrap! (lp_coinfind (ctx, &maker_match.reserved.base)));
        let ctx = ctx.clone();
        let mut alice = lp::bits256::default();
        alice.bytes = maker_match.request.sender_pubkey.0;
        let maker_amount = maker_match.reserved.base_amount.clone();
        let taker_amount = maker_match.reserved.rel_amount.clone();
        let my_persistent_pub = unwrap!(compressed_pub_key_from_priv_raw(&lp::G.LP_privkey.bytes, ChecksumType::DSHA256));
        let uuid = maker_match.request.uuid.to_string();
        move || {
            log!("Entering the maker_swap_loop " (maker_coin.ticker()) "/" (taker_coin.ticker()));
            let maker_swap = MakerSwap::new(
                ctx,
                alice,
                maker_coin,
                taker_coin,
                maker_amount,
                taker_amount,
                my_persistent_pub,
                uuid,
            );
            run_maker_swap(maker_swap);
        }
    });
    match loop_thread {
        Ok(_h) => {
            retval = 0;
        },
        Err(e) => {
            log!({ "Got error launching bob swap loop: {}", e });
        }
    }
    retval
}

unsafe fn lp_connected_alice(ctx: &MmArc, taker_match: &TakerOrderMatch) { // alice
    let alice_loop_thread = thread::Builder::new().name("taker_loop".into()).spawn({
        let ctx = ctx.clone();
        let mut maker = lp::bits256::default();
        maker.bytes = taker_match.reserved.clone().unwrap().sender_pubkey.0;
        let taker_coin = unwrap!(unwrap! (lp_coinfind (&ctx, &taker_match.request.rel)));
        let maker_coin = unwrap!(unwrap! (lp_coinfind (&ctx, &taker_match.request.base)));
        let my_persistent_pub = unwrap!(compressed_pub_key_from_priv_raw(&lp::G.LP_privkey.bytes, ChecksumType::DSHA256));
        let maker_amount = taker_match.reserved.clone().unwrap().base_amount;
        let taker_amount = taker_match.reserved.clone().unwrap().rel_amount;
        let uuid = taker_match.request.uuid.to_string();
        move || {
            log!("Entering the taker_swap_loop " (maker_coin.ticker()) "/" (taker_coin.ticker()));
            let taker_swap = TakerSwap::new(
                ctx,
                maker,
                maker_coin,
                taker_coin,
                maker_amount,
                taker_amount,
                my_persistent_pub,
                uuid,
            );
            run_taker_swap(taker_swap);
        }
    });
    match alice_loop_thread {
        Ok(_) => (),
        Err(e) => {
            log!({ "Got error trying to start taker loop {}", e });
        }
    }
}

pub unsafe fn lp_trades_loop(ctx: MmArc) {
    thread::sleep(Duration::from_secs(5));

    loop {
        if ctx.is_stopping() { break }
        let portfolio_ctx = unwrap!(PortfolioContext::from_ctx(&ctx));
        let mut my_taker_orders = unwrap!(portfolio_ctx.my_taker_orders.lock());
        let mut my_maker_orders = unwrap!(portfolio_ctx.my_maker_orders.lock());
        *my_taker_orders = my_taker_orders.drain().filter_map(|(pair, order)| if order.created_at + 5000 < now_ms() {
            my_maker_orders.insert(pair, order);
            None
        } else {
            Some((pair, order))
        }).collect();
        drop(my_taker_orders);
        drop(my_maker_orders);
        thread::sleep(Duration::from_secs(1));
    }
}

pub unsafe fn lp_trade_command(
    ctx: MmArc,
    json: Json,
) -> i32 {
    let method = json["method"].as_str();
    let ordermatch_ctx = unwrap!(OrdermatchContext::from_ctx(&ctx));
    if method == Some("reserved") {
        let portfolio_ctx = unwrap!(PortfolioContext::from_ctx(&ctx));
        let mut my_taker_orders = unwrap!(portfolio_ctx.my_taker_orders.lock());
        let mut taker_matches = unwrap!(ordermatch_ctx.taker_matches.lock());
        let reserved_msg: MakerReserved = match json::from_value(json.clone()) {
            Ok(r) => r,
            Err(_) => return 1,
        };

        let my_match = match taker_matches.entry(reserved_msg.taker_order_uuid) {
            Entry::Vacant(_) => {
                log!("Our node doesn't have the ordermatch with uuid "(reserved_msg.taker_order_uuid));
                return 1;
            },
            Entry::Occupied(entry) => entry.into_mut()
        };

        if my_match.request.dest_pub_key != H256Json::default() && my_match.request.dest_pub_key != reserved_msg.sender_pubkey {
            log!("got reserved response from different node " (hex::encode(&reserved_msg.sender_pubkey.0)));
            return 1;
        }

        if H256Json::from(lp::G.LP_mypub25519.bytes) == reserved_msg.dest_pub_key {
            let connect = TakerConnect {
                sender_pubkey: H256Json::from(lp::G.LP_mypub25519.bytes),
                dest_pub_key: reserved_msg.sender_pubkey.clone(),
                method: "connect".into(),
                taker_order_uuid: reserved_msg.taker_order_uuid,
                maker_order_uuid: reserved_msg.maker_order_uuid,
            };
            my_taker_orders.remove(&reserved_msg.taker_order_uuid);
            ctx.broadcast_p2p_msg(&unwrap!(json::to_string(&connect)));
            my_match.reserved = Some(reserved_msg);
            my_match.connect = Some(connect);
        }
        return 1;
    }
    if method == Some("connected") {
        let connected: MakerConnected = match json::from_value(json.clone()) {
            Ok(c) => c,
            Err(_) => return 1,
        };
        let mut taker_matches = unwrap!(ordermatch_ctx.taker_matches.lock());
        let my_match = match taker_matches.entry(connected.taker_order_uuid) {
            Entry::Vacant(_) => {
                log!("Our node doesn't have the ordermatch with uuid " (connected.taker_order_uuid));
                return 1;
            },
            Entry::Occupied(entry) => entry.into_mut()
        };
        // alice
        if H256Json::from(lp::G.LP_mypub25519.bytes) == connected.dest_pub_key && H256Json::from(lp::G.LP_mypub25519.bytes) != connected.sender_pubkey {
            lp_connected_alice(
                &ctx,
                my_match,
            );
            // AG: Bob's p2p ID (`LP_mypub25519`) is in `json["srchash"]`.
            log!("CONNECTED.(" (json) ")");
        }
        return 1;
    }
    // bob
    if method == Some("request") {
        let taker_request: TakerRequest = match json::from_value(json.clone()) {
            Ok(r) => r,
            Err(_) => return 1,
        };
        if lp::G.LP_mypub25519.bytes == taker_request.dest_pub_key.0 {
            log!("Skip the request originating from our pubkey");
            return 1;
        }
        let portfolio_ctx = unwrap!(PortfolioContext::from_ctx(&ctx));
        let my_orders = unwrap!(portfolio_ctx.my_maker_orders.lock());

        for (uuid, order) in my_orders.iter() {
            if let OrderMatchResult::Matched((base_amount, rel_amount)) = match_order_and_request(order, &taker_request) {
                let reserved = MakerReserved {
                    dest_pub_key: taker_request.sender_pubkey.clone(),
                    sender_pubkey: lp::G.LP_mypub25519.bytes.into(),
                    base: order.base.clone(),
                    base_amount,
                    rel_amount,
                    rel: order.rel.clone(),
                    method: "reserved".into(),
                    taker_order_uuid: taker_request.uuid,
                    maker_order_uuid: *uuid,
                };
                ctx.broadcast_p2p_msg(&unwrap!(json::to_string(&reserved)));
                let maker_match = MakerOrderMatch {
                    request: taker_request,
                    reserved,
                    connect: None,
                    connected: None,
                };
                let mut maker_matches = unwrap!(ordermatch_ctx.maker_matches.lock());
                maker_matches.insert(maker_match.reserved.taker_order_uuid, maker_match);
                return 1;
            }
        }
    }

    if method == Some("connect") {
        // bob
        let connect_msg: TakerConnect = match json::from_value(json.clone()) {
            Ok(m) => m,
            Err(_) => return 1,
        };
        if lp::G.LP_mypub25519.bytes == connect_msg.dest_pub_key.0 && lp::G.LP_mypub25519.bytes != connect_msg.sender_pubkey.0 {
            let mut maker_matches = unwrap!(ordermatch_ctx.maker_matches.lock());
            let my_match = match maker_matches.entry(connect_msg.taker_order_uuid) {
                Entry::Vacant(_) => {
                    log!("Our node doesn't have the match with uuid " (connect_msg.taker_order_uuid));
                    return 1;
                },
                Entry::Occupied(entry) => entry.into_mut()
            };
            let portfolio_ctx = unwrap!(PortfolioContext::from_ctx(&ctx));
            let mut my_orders = unwrap!(portfolio_ctx.my_maker_orders.lock());
            let my_order = match my_orders.get_mut(&connect_msg.maker_order_uuid) {
                Some(o) => o,
                None => {
                    log!("Our node doesn't have the order with uuid " (connect_msg.maker_order_uuid));
                    return 1;
                },
            };

            let connected = MakerConnected {
                sender_pubkey: lp::G.LP_mypub25519.bytes.into(),
                dest_pub_key: connect_msg.sender_pubkey.clone(),
                taker_order_uuid: connect_msg.taker_order_uuid,
                maker_order_uuid: connect_msg.maker_order_uuid,
                method: "connected".into(),
            };
            ctx.broadcast_p2p_msg(&unwrap!(json::to_string(&connected)));
            my_match.connect = Some(connect_msg);
            my_match.connected = Some(connected);
            my_order.price = 0.into();
            lp_connect_start_bob(&ctx, my_match);
        }
        return 1;
    }
    -1
}

#[derive(Deserialize, Debug)]
pub struct AutoBuyInput {
    base: String,
    rel: String,
    price: BigDecimal,
    volume: BigDecimal,
    timeout: Option<u32>,
    /// Not used. Deprecated.
    duration: Option<u32>,
    // TODO: remove this field on API refactoring, method should be separated from params
    method: String,
    gui: Option<String>,
    #[serde(rename="destpubkey")]
    #[serde(default)]
    dest_pub_key: H256Json
}

pub fn buy(ctx: MmArc, json: Json) -> HyRes {
    let input : AutoBuyInput = try_h!(json::from_value(json.clone()));
    if input.base == input.rel {
        return rpc_err_response(500, "Base and rel must be different coins");
    }
    let rel_coin = try_h!(lp_coinfind(&ctx, &input.rel));
    let rel_coin = match rel_coin {Some(c) => c, None => return rpc_err_response(500, "Rel coin is not found or inactive")};
    let base_coin = try_h!(lp_coinfind(&ctx, &input.base));
    let base_coin: MmCoinEnum = match base_coin {Some(c) => c, None => return rpc_err_response(500, "Base coin is not found or inactive")};
    Box::new(rel_coin.check_i_have_enough_to_trade((input.volume.clone() * input.price.clone()).to_f64().unwrap(), false).and_then(move |_|
        base_coin.can_i_spend_other_payment().and_then(move |_|
            rpc_response(200, try_h!(lp_auto_buy(&ctx, input)))
        )
    ))
}

pub fn sell(ctx: MmArc, json: Json) -> HyRes {
    let input : AutoBuyInput = try_h!(json::from_value(json.clone()));
    if input.base == input.rel {
        return rpc_err_response(500, "Base and rel must be different coins");
    }
    let base_coin = try_h!(lp_coinfind(&ctx, &input.base));
    let base_coin = match base_coin {Some(c) => c, None => return rpc_err_response(500, "Base coin is not found or inactive")};
    let rel_coin = try_h!(lp_coinfind(&ctx, &input.rel));
    let rel_coin = match rel_coin {Some(c) => c, None => return rpc_err_response(500, "Rel coin is not found or inactive")};
    Box::new(base_coin.check_i_have_enough_to_trade(input.volume.to_f64().unwrap(), false).and_then(move |_|
        rel_coin.can_i_spend_other_payment().and_then(move |_|
            rpc_response(200, try_h!(lp_auto_buy(&ctx, input)))
        )
    ))
}

pub struct TakerOrderMatch {
    request: TakerRequest,
    reserved: Option<MakerReserved>,
    connect: Option<TakerConnect>,
    connected: Option<MakerConnected>,
}

pub struct MakerOrderMatch {
    request: TakerRequest,
    reserved: MakerReserved,
    connect: Option<TakerConnect>,
    connected: Option<MakerConnected>,
}

pub fn lp_auto_buy(ctx: &MmArc, input: AutoBuyInput) -> Result<String, String> {
    if input.price < SMALLVAL.into() {
        return ERR!("Price is too low, minimum is {}", SMALLVAL);
    }

    let price = match Some(input.method.as_ref()) {
        Some("buy") => {
            input.price
        },
        Some("sell") => {
            1. / input.price
        },
        _ => return ERR!("Auto buy must be called only from buy/sell RPC methods")
    };

    unsafe {
        let base_str = try_s!(CString::new(input.base.clone()));
        let rel_str = try_s!(CString::new(input.rel.clone()));

        if price <= BigDecimal::default() {
            return ERR!("Resulting price is <= 0");
        }
        if lp::LP_priceinfofind(base_str.as_ptr() as *mut c_char) == null_mut() {
            return ERR!("No price info found for base coin {}", input.base);
        }
        if lp::LP_priceinfofind(rel_str.as_ptr() as *mut c_char) == null_mut() {
            return ERR!("No price info found for rel coin {}", input.rel);
        }

        let portfolio_ctx = try_s!(PortfolioContext::from_ctx(&ctx));
        let mut my_taker_orders = try_s!(portfolio_ctx.my_taker_orders.lock());
        let uuid = Uuid::new_v4();
        if input.method == "buy" {
            my_taker_orders.insert(uuid, Order {
                max_base_vol: OrderAmount::Limit(input.volume.clone()),
                min_base_vol: OrderAmount::Limit(0.into()),
                price: BigDecimal::from(1) / price.clone(),
                created_at: now_ms(),
                base: input.rel.clone(),
                rel: input.base.clone(),
            });
        } else {
            my_taker_orders.insert(uuid, Order {
                max_base_vol: OrderAmount::Limit(input.volume.clone()),
                min_base_vol: OrderAmount::Limit(0.into()),
                price: BigDecimal::from(1),
                created_at: now_ms(),
                base: input.base.clone(),
                rel: input.rel.clone(),
            });
        }
        drop(my_taker_orders);

        let taker_request = TakerRequest {
            base: input.base,
            rel: input.rel,
            base_amount: input.volume.clone(),
            rel_amount: input.volume * price,
            method: "request".into(),
            uuid,
            dest_pub_key: input.dest_pub_key,
            sender_pubkey: H256Json::from(lp::G.LP_mypub25519.bytes),
        };
        ctx.broadcast_p2p_msg(&unwrap!(json::to_string(&taker_request)));
        let ordermatch_ctx = try_s!(OrdermatchContext::from_ctx(&ctx));
        let mut taker_matches = try_s!(ordermatch_ctx.taker_matches.lock());
        taker_matches.insert(uuid, TakerOrderMatch {
            request: taker_request,
            reserved: None,
            connect: None,
            connected: None,
        });
        Ok(json!({
            "result": {
                "uuid": uuid,
            }
        }).to_string())
    }
}

/// Result of match_order_and_request function
#[derive(Debug, PartialEq)]
enum OrderMatchResult {
    /// Order and request matched, contains base and rel resulting amounts
    Matched((BigDecimal, BigDecimal)),
    /// Orders didn't match
    NotMatched,
}

/// Attempts to match the Maker's order and Taker's request
fn match_order_and_request(maker: &Order, taker: &TakerRequest) -> OrderMatchResult {
    let max_maker = match &maker.max_base_vol {
        OrderAmount::Max => unimplemented!(),
        OrderAmount::Limit(amount) => amount,
    };

    let min_maker = match &maker.min_base_vol {
        OrderAmount::Max => unimplemented!(),
        OrderAmount::Limit(amount) => amount,
    };

    if maker.base == taker.base && maker.rel == taker.rel && taker.base_amount <= *max_maker && taker.base_amount >= *min_maker {
        let taker_price = taker.rel_amount.clone() / taker.base_amount.clone();
        if taker_price >= maker.price {
            OrderMatchResult::Matched((taker.base_amount.clone(), taker.base_amount.clone() * maker.price.clone()))
        } else {
            OrderMatchResult::NotMatched
        }
    } else {
        OrderMatchResult::NotMatched
    }
}

#[test]
fn test_match_order_and_request() {
    let maker = Order {
        base: "BASE".into(),
        rel: "REL".into(),
        created_at: now_ms(),
        max_base_vol: OrderAmount::Limit(10.into()),
        min_base_vol: OrderAmount::Limit(0.into()),
        price: 1.into(),
    };

    let request = TakerRequest {
        base: "BASE".into(),
        rel: "REL".into(),
        uuid: Uuid::new_v4(),
        method: "request".into(),
        dest_pub_key: H256Json::default(),
        sender_pubkey: H256Json::default(),
        base_amount: 10.into(),
        rel_amount: 20.into(),
    };

    let actual = match_order_and_request(&maker, &request);
    let expected = OrderMatchResult::Matched((10.into(), 10.into()));
    assert_eq!(expected, actual);

    let maker = Order {
        base: "BASE".into(),
        rel: "REL".into(),
        created_at: now_ms(),
        max_base_vol: OrderAmount::Limit(10.into()),
        min_base_vol: OrderAmount::Limit(0.into()),
        price: "0.5".parse().unwrap(),
    };

    let request = TakerRequest {
        base: "BASE".into(),
        rel: "REL".into(),
        uuid: Uuid::new_v4(),
        method: "request".into(),
        dest_pub_key: H256Json::default(),
        sender_pubkey: H256Json::default(),
        base_amount: 10.into(),
        rel_amount: 20.into(),
    };

    let actual = match_order_and_request(&maker, &request);
    let expected = OrderMatchResult::Matched((10.into(), 5.into()));
    assert_eq!(expected, actual);

    let maker = Order {
        base: "BASE".into(),
        rel: "REL".into(),
        created_at: now_ms(),
        max_base_vol: OrderAmount::Limit(10.into()),
        min_base_vol: OrderAmount::Limit(0.into()),
        price: "0.5".parse().unwrap(),
    };

    let request = TakerRequest {
        base: "BASE".into(),
        rel: "REL".into(),
        uuid: Uuid::new_v4(),
        method: "request".into(),
        dest_pub_key: H256Json::default(),
        sender_pubkey: H256Json::default(),
        base_amount: 10.into(),
        rel_amount: 2.into(),
    };

    let actual = match_order_and_request(&maker, &request);
    let expected = OrderMatchResult::NotMatched;
    assert_eq!(expected, actual);
}
