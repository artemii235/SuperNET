
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
use common::{CJSON, free_c_ptr, lp, SMALLVAL, rpc_response, rpc_err_response, HyRes};
use common::mm_ctx::{from_ctx, MmArc, MmWeak};
use coins::{lp_coinfind, MmCoinEnum};
use coins::utxo::{compressed_pub_key_from_priv_raw, ChecksumType};
use futures::future::Future;
use gstuff::now_ms;
use hashbrown::hash_map::{Entry, HashMap};
use libc::{self, c_char, c_void};
use num_traits::cast::ToPrimitive;
use rpc::v1::types::{H256 as H256Json};
use serde_json::{self as json, Value as Json};
use std::ffi::{CStr, CString};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use uuid::Uuid;

use crate::mm2::lp_swap::{MakerSwap, run_maker_swap, TakerSwap, run_taker_swap};

#[cfg(test)]
#[path = "ordermatch_tests.rs"]
mod ordermatch_tests;

#[derive(Clone, Debug, Deserialize, Serialize)]
enum TakerAction {
    Buy,
    Sell,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TakerRequest {
    base: String,
    rel: String,
    base_amount: BigDecimal,
    rel_amount: BigDecimal,
    action: TakerAction,
    uuid: Uuid,
    method: String,
    sender_pubkey: H256Json,
    dest_pub_key: H256Json,
}

#[derive(Clone)]
struct TakerOrder {
    created_at: u64,
    request: TakerRequest,
    matches: HashMap<Uuid, TakerMatch>
}

/// Result of match_reserved function
#[derive(Debug, PartialEq)]
enum MatchReservedResult {
    /// Order and reserved message matched,
    Matched,
    /// Order and reserved didn't match
    NotMatched,
}

impl TakerOrder {
    fn match_reserved(&self, reserved: &MakerReserved) -> MatchReservedResult {
        match self.request.action {
            TakerAction::Buy => if self.request.base == reserved.base && self.request.rel == reserved.rel
                && self.request.base_amount == reserved.base_amount && reserved.rel_amount <= self.request.rel_amount {
                MatchReservedResult::Matched
            } else {
                MatchReservedResult::NotMatched
            },
            TakerAction::Sell => if self.request.base == reserved.rel && self.request.rel == reserved.base
                && self.request.base_amount == reserved.rel_amount && self.request.rel_amount <= reserved.base_amount {
                MatchReservedResult::Matched
            } else {
                MatchReservedResult::NotMatched
            }
        }
    }
}

#[derive(Clone, Debug)]
/// Market maker order
/// The "action" is missing here because it's easier to always consider maker order as "sell"
/// So upon ordermatch with request we have only 2 combinations "sell":"sell" and "sell":"buy"
/// Adding "action" to maker order will just double possible combinations making order match more complex.
pub struct MakerOrder {
    pub max_base_vol: BigDecimal,
    pub min_base_vol: BigDecimal,
    pub price: BigDecimal,
    pub created_at: u64,
    pub base: String,
    pub rel: String,
    matches: HashMap<Uuid, MakerMatch>
}

impl MakerOrder {
    fn available_amount(&self) -> BigDecimal {
        let reserved: BigDecimal = self.matches.iter().fold(
            0.into(),
            |reserved, (_, order_match)| reserved + &order_match.reserved.base_amount
        );
        &self.max_base_vol - reserved
    }
}

impl Into<MakerOrder> for TakerOrder {
    fn into(self) -> MakerOrder {
        let order = match self.request.action {
            TakerAction::Sell => MakerOrder {
                price: &self.request.rel_amount / &self.request.base_amount,
                max_base_vol: self.request.base_amount,
                min_base_vol: 0.into(),
                created_at: now_ms(),
                base: self.request.base,
                rel: self.request.rel,
                matches: HashMap::new(),
            },
            // The "buy" taker order is recreated with reversed pair as Maker order is always considered as "sell"
            TakerAction::Buy => MakerOrder {
                price: &self.request.base_amount / &self.request.rel_amount,
                max_base_vol: self.request.rel_amount,
                min_base_vol: 0.into(),
                created_at: now_ms(),
                base: self.request.rel,
                rel: self.request.base,
                matches: HashMap::new(),
            },
        };
        order
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TakerConnect {
    taker_order_uuid: Uuid,
    maker_order_uuid: Uuid,
    method: String,
    sender_pubkey: H256Json,
    dest_pub_key: H256Json,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
struct MakerConnected {
    taker_order_uuid: Uuid,
    maker_order_uuid: Uuid,
    method: String,
    sender_pubkey: H256Json,
    dest_pub_key: H256Json,
}

struct OrdermatchContext {
    pub my_maker_orders: Mutex<HashMap<Uuid, MakerOrder>>,
    pub my_taker_orders: Mutex<HashMap<Uuid, TakerOrder>>,
}

impl OrdermatchContext {
    /// Obtains a reference to this crate context, creating it if necessary.
    fn from_ctx (ctx: &MmArc) -> Result<Arc<OrdermatchContext>, String> {
        Ok (try_s! (from_ctx (&ctx.ordermatch_ctx, move || {
            Ok (OrdermatchContext {
                my_taker_orders: Mutex::new (HashMap::default()),
                my_maker_orders: Mutex::new (HashMap::default()),
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

unsafe fn lp_connect_start_bob(ctx: &MmArc, maker_match: &MakerMatch) -> i32 {
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

unsafe fn lp_connected_alice(ctx: &MmArc, taker_match: &TakerMatch) { // alice
    let alice_loop_thread = thread::Builder::new().name("taker_loop".into()).spawn({
        let ctx = ctx.clone();
        let mut maker = lp::bits256::default();
        maker.bytes = taker_match.reserved.sender_pubkey.0;
        let taker_coin = unwrap!(unwrap! (lp_coinfind (&ctx, &taker_match.reserved.rel)));
        let maker_coin = unwrap!(unwrap! (lp_coinfind (&ctx, &taker_match.reserved.base)));
        let my_persistent_pub = unwrap!(compressed_pub_key_from_priv_raw(&lp::G.LP_privkey.bytes, ChecksumType::DSHA256));
        let maker_amount = taker_match.reserved.base_amount.clone();
        let taker_amount = taker_match.reserved.rel_amount.clone();
        let uuid = taker_match.reserved.taker_order_uuid.to_string();
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

pub fn lp_trades_loop(ctx: MmArc) {
    let mut last_price_broadcast = 0;

    loop {
        if ctx.is_stopping() { break }
        let ordermatch_ctx = unwrap!(OrdermatchContext::from_ctx(&ctx));
        let mut my_taker_orders = unwrap!(ordermatch_ctx.my_taker_orders.lock());
        let mut my_maker_orders = unwrap!(ordermatch_ctx.my_maker_orders.lock());
        // move the timed out (5 seconds) taker orders to maker
        *my_taker_orders = my_taker_orders.drain().filter_map(|(uuid, order)| if order.created_at + 5000 < now_ms() {
            if order.matches.is_empty() {
                my_maker_orders.insert(uuid, order.into());
            }
            None
        } else {
            Some((uuid, order))
        }).collect();
        // remove timed out (5 seconds) unfinished matches to unlock the reserved amount
        my_maker_orders.iter_mut().for_each(|(_, order)| {
            order.matches = order.matches.drain().filter(
                |(_, order_match)| order_match.last_updated + 5000 < now_ms() || order_match.connected.is_some()
            ).collect();
        });
        drop(my_taker_orders);
        drop(my_maker_orders);

        if now_ms() > last_price_broadcast + 10000 {
            if let Err(e) = broadcast_my_maker_orders(&ctx) {
                ctx.log.log("", &[&"broadcast_my_maker_orders"], &format!("error {}", e));
            }
            last_price_broadcast = now_ms();
        }
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
        let reserved_msg: MakerReserved = match json::from_value(json.clone()) {
            Ok(r) => r,
            Err(_) => return 1,
        };

        let mut my_taker_orders = unwrap!(ordermatch_ctx.my_taker_orders.lock());
        let my_order = match my_taker_orders.entry(reserved_msg.taker_order_uuid) {
            Entry::Vacant(_) => {
                log!("Our node doesn't have the order with uuid " (reserved_msg.taker_order_uuid));
                return 1;
            },
            Entry::Occupied(entry) => entry.into_mut()
        };

        if my_order.request.dest_pub_key != H256Json::default() && my_order.request.dest_pub_key != reserved_msg.sender_pubkey {
            log!("got reserved response from different node " (hex::encode(&reserved_msg.sender_pubkey.0)));
            return 1;
        }

        // send "connect" message if reserved message targets our pubkey AND
        // reserved amounts match our order AND order is NOT reserved by someone else (empty matches)
        if H256Json::from(lp::G.LP_mypub25519.bytes) == reserved_msg.dest_pub_key
            && my_order.match_reserved(&reserved_msg) == MatchReservedResult::Matched
            && my_order.matches.is_empty() {
            let connect = TakerConnect {
                sender_pubkey: H256Json::from(lp::G.LP_mypub25519.bytes),
                dest_pub_key: reserved_msg.sender_pubkey.clone(),
                method: "connect".into(),
                taker_order_uuid: reserved_msg.taker_order_uuid,
                maker_order_uuid: reserved_msg.maker_order_uuid,
            };
            ctx.broadcast_p2p_msg(&unwrap!(json::to_string(&connect)));
            let taker_match = TakerMatch {
                reserved: reserved_msg,
                connect,
                connected: None,
                last_updated: now_ms(),
            };
            my_order.matches.insert(taker_match.reserved.maker_order_uuid, taker_match);
        }
        return 1;
    }
    if method == Some("connected") {
        let connected: MakerConnected = match json::from_value(json.clone()) {
            Ok(c) => c,
            Err(_) => return 1,
        };
        if H256Json::from(lp::G.LP_mypub25519.bytes) == connected.dest_pub_key && H256Json::from(lp::G.LP_mypub25519.bytes) != connected.sender_pubkey {
            let mut my_taker_orders = unwrap!(ordermatch_ctx.my_taker_orders.lock());
            let my_order = match my_taker_orders.get_mut(&connected.taker_order_uuid) {
                Some(o) => o,
                None => {
                    log!("Our node doesn't have the order with uuid "(connected.taker_order_uuid));
                    return 1;
                },
            };
            let order_match = match my_order.matches.get_mut(&connected.maker_order_uuid) {
                Some(o) => o,
                None => {
                    log!("Our node doesn't have the match with uuid "(connected.maker_order_uuid));
                    return 1;
                }
            };
            order_match.connected = Some(connected);
            order_match.last_updated = now_ms();
            // alice
            lp_connected_alice(
                &ctx,
                order_match,
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
        let ordermatch_ctx = unwrap!(OrdermatchContext::from_ctx(&ctx));
        let mut my_orders = unwrap!(ordermatch_ctx.my_maker_orders.lock());

        for (uuid, order) in my_orders.iter_mut() {
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
                let maker_match = MakerMatch {
                    request: taker_request,
                    reserved,
                    connect: None,
                    connected: None,
                    last_updated: now_ms(),
                };
                order.matches.insert(maker_match.request.uuid, maker_match);
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
            let mut maker_orders = unwrap!(ordermatch_ctx.my_maker_orders.lock());
            let my_order = match maker_orders.get_mut(&connect_msg.maker_order_uuid) {
                Some(o) => o,
                None => {
                    log!("Our node doesn't have the order with uuid " (connect_msg.maker_order_uuid));
                    return 1;
                },
            };
            let order_match = match my_order.matches.get_mut(&connect_msg.taker_order_uuid) {
                Some(o) => o,
                None => {
                    log!("Our node doesn't have the match with uuid " (connect_msg.taker_order_uuid));
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
            order_match.connect = Some(connect_msg);
            order_match.connected = Some(connected);
            lp_connect_start_bob(&ctx, order_match);
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
    Box::new(rel_coin.check_i_have_enough_to_trade((&input.volume * &input.price).to_f64().unwrap(), false).and_then(move |_|
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

/// Created when maker order is matched with taker request
#[derive(Clone, Debug)]
struct MakerMatch {
    request: TakerRequest,
    reserved: MakerReserved,
    connect: Option<TakerConnect>,
    connected: Option<MakerConnected>,
    last_updated: u64,
}

/// Created upon taker request broadcast
#[derive(Clone)]
struct TakerMatch {
    reserved: MakerReserved,
    connect: TakerConnect,
    connected: Option<MakerConnected>,
    last_updated: u64,
}

pub fn lp_auto_buy(ctx: &MmArc, input: AutoBuyInput) -> Result<String, String> {
    if input.price < SMALLVAL.into() {
        return ERR!("Price is too low, minimum is {}", SMALLVAL);
    }

    let action = match Some(input.method.as_ref()) {
        Some("buy") => {
            TakerAction::Buy
        },
        Some("sell") => {
            TakerAction::Sell
        },
        _ => return ERR!("Auto buy must be called only from buy/sell RPC methods")
    };

    let ordermatch_ctx = try_s!(OrdermatchContext::from_ctx(&ctx));
    let mut my_taker_orders = try_s!(ordermatch_ctx.my_taker_orders.lock());
    let uuid = Uuid::new_v4();
    let request = TakerRequest {
        base: input.base,
        rel: input.rel,
        rel_amount: &input.volume * input.price,
        base_amount: input.volume,
        method: "request".into(),
        uuid,
        dest_pub_key: input.dest_pub_key,
        sender_pubkey: H256Json::from(unsafe { lp::G.LP_mypub25519.bytes }),
        action,
    };
    ctx.broadcast_p2p_msg(&unwrap!(json::to_string(&request)));
    my_taker_orders.insert(uuid, TakerOrder {
        created_at: now_ms(),
        matches: HashMap::new(),
        request,
    });
    drop(my_taker_orders);
    Ok(json!({
        "result": {
            "uuid": uuid,
        }
    }).to_string())
}

#[derive(Serialize)]
struct PricePingRequest {
    method: &'static str,
    pubkey: String,
    base: String,
    rel: String,
    price: BigDecimal,
    price64: String,
    timestamp: u64,
    pubsecp: String,
    sig: String,
    // TODO rename, it's called "balance", but it's actual meaning is max available volume to trade
    #[serde(rename="bal")]
    balance: BigDecimal,
}

impl PricePingRequest {
    fn new(ctx: &MmArc, order: &MakerOrder) -> Result<PricePingRequest, String> {
        let base_coin = match try_s!(lp_coinfind(ctx, &order.base)) {
            Some(coin) => coin,
            None => return ERR!("Base coin {} is not found", order.base),
        };

        let _rel_coin = match try_s!(lp_coinfind(ctx, &order.rel)) {
            Some(coin) => coin,
            None => return ERR!("Rel coin {} is not found", order.rel),
        };

        let price64 = (&order.price * BigDecimal::from(100000000.0)).to_u64().unwrap();
        let timestamp = now_ms() / 1000;
        let base_c: CString = try_s!(CString::new(order.base.clone()));
        let rel_c: CString = try_s!(CString::new(order.rel.clone()));

        let sig = unsafe {
            let sig_c = lp::LP_price_sig(timestamp as u32, lp::G.LP_privkey, lp::G.LP_pubsecp.as_mut_ptr(), lp::G.LP_mypub25519,
                                         base_c.as_ptr() as *mut c_char, rel_c.as_ptr() as *mut c_char, price64);
            if sig_c.is_null() {
                return ERR!("Price request signature is null");
            }
            let sig_str = try_s!(CStr::from_ptr(sig_c).to_str()).into();
            free_c_ptr(sig_c as *mut c_void);
            sig_str
        };

        let my_balance = try_s!(base_coin.my_balance().wait());
        let available_amount = order.available_amount();
        let max_volume = if available_amount <= my_balance {
            available_amount
        } else {
            my_balance
        };

        Ok(PricePingRequest {
            method: "postprice",
            pubkey: unsafe { hex::encode(&lp::G.LP_mypub25519.bytes) },
            base: order.base.clone(),
            rel: order.rel.clone(),
            price64: price64.to_string(),
            price: order.price.clone(),
            timestamp,
            pubsecp: unsafe { hex::encode(&lp::G.LP_pubsecp.to_vec()) },
            sig,
            balance: max_volume,
        })
    }
}

fn lp_send_price_ping(req: &PricePingRequest, ctx: &MmArc) -> Result<(), String> {
    let req_string = try_s!(json::to_string(req));
    // TODO this is required to process the set price message on our own node, it's the easiest way now
    //      there might be a better way of doing this so we should consider refactoring
    let c_json = try_s!(CJSON::from_str(&req_string));
    let post_price_res = unsafe { lp::LP_postprice_recv(c_json.0) };
    free_c_ptr(post_price_res as *mut c_void);
    ctx.broadcast_p2p_msg(&req_string);
    Ok(())
}

fn one() -> u8 { 1 }

#[derive(Deserialize)]
struct SetPriceReq {
    base: String,
    rel: String,
    price: BigDecimal,
    volume: BigDecimal,
    #[serde(default = "one")]
    broadcast: u8,
}

pub fn set_price(ctx: MmArc, req: Json) -> HyRes {
    let req: SetPriceReq = try_h!(json::from_value(req));
    if req.base == req.rel {
        return rpc_err_response(500, "Base and rel must be different coins");
    }

    let base_coin = match try_h!(lp_coinfind(&ctx, &req.base)) {
        Some(coin) => coin,
        None => return rpc_err_response(500, &format!("Base coin {} is not found", req.base)),
    };

    let rel_coin: MmCoinEnum = match try_h!(lp_coinfind(&ctx, &req.rel)) {
        Some(coin) => coin,
        None => return rpc_err_response(500, &format!("Rel coin {} is not found", req.rel)),
    };

    Box::new(base_coin.check_i_have_enough_to_trade(req.volume.to_f64().unwrap(), true).and_then(move |_|
        rel_coin.can_i_spend_other_payment().and_then(move |_| {
            if req.broadcast == 1 {
                let ordermatch_ctx = try_h!(OrdermatchContext::from_ctx(&ctx));
                let mut my_orders = try_h!(ordermatch_ctx.my_maker_orders.lock());
                let uuid = Uuid::new_v4();
                my_orders.insert(uuid, MakerOrder {
                    max_base_vol: req.volume,
                    min_base_vol: 0.into(),
                    price: req.price,
                    created_at: now_ms(),
                    base: req.base,
                    rel: req.rel,
                    matches: HashMap::new(),
                });
            }
            rpc_response(200, json!({"result":"success"}).to_string())
        }))
    )
}

pub fn broadcast_my_maker_orders(ctx: &MmArc) -> Result<(), String> {
    let ordermatch_ctx = try_s!(OrdermatchContext::from_ctx(ctx));
    let my_orders = try_s!(ordermatch_ctx.my_maker_orders.lock()).clone();

    for (_, order) in my_orders.iter() {
        let ping = match PricePingRequest::new(ctx, order) {
            Ok(p) => p,
            Err(e) => {
                ctx.log.log("", &[&"broadcast_my_maker_orders", &order.base, &order.rel], &format! ("ping request creation failed {}", e));
                continue;
            },
        };

        if let Err(e) = lp_send_price_ping(&ping, ctx) {
            ctx.log.log("", &[&"broadcast_my_maker_orders", &order.base, &order.rel], &format! ("ping request send failed {}", e));
            continue;
        }
    }
    Ok(())
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
fn match_order_and_request(maker: &MakerOrder, taker: &TakerRequest) -> OrderMatchResult {
    match taker.action {
        TakerAction::Buy => {
            if maker.base == taker.base && maker.rel == taker.rel && taker.base_amount <= maker.available_amount() && taker.base_amount >= maker.min_base_vol {
                let taker_price = &taker.rel_amount / &taker.base_amount;
                if taker_price >= maker.price {
                    OrderMatchResult::Matched((taker.base_amount.clone(), &taker.base_amount * &maker.price))
                } else {
                    OrderMatchResult::NotMatched
                }
            } else {
                OrderMatchResult::NotMatched
            }
        },
        TakerAction::Sell => {
            if maker.base == taker.rel && maker.rel == taker.base && taker.rel_amount <= maker.available_amount() && taker.rel_amount >= maker.min_base_vol {
                let taker_price = &taker.base_amount / &taker.rel_amount;
                if taker_price >= maker.price {
                    OrderMatchResult::Matched((&taker.base_amount / &maker.price, taker.base_amount.clone()))
                } else {
                    OrderMatchResult::NotMatched
                }
            } else {
                OrderMatchResult::NotMatched
            }
        },
    }
}
