
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
use common::{lp, lp_queue_command_for_c, free_c_ptr, SMALLVAL, CJSON, rpc_response, rpc_err_response, HyRes};
use common::for_c::broadcast_p2p_msg_for_c;
use common::mm_ctx::{from_ctx, MmArc, MmWeak};
use coins::{lp_coinfind, MmCoinEnum};
use coins::utxo::{compressed_pub_key_from_priv_raw, ChecksumType};
use futures::future::Future;
use gstuff::now_ms;
use hashbrown::hash_map::{Entry, HashMap};
use libc::{self, c_void, c_char};
use num_traits::cast::ToPrimitive;
use portfolio::{Order, OrderAmount, PortfolioContext};
use rpc::v1::types::{H256 as H256Json};
use serde_json::{self as json, Value as Json};
use std::ffi::{CString, CStr};
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use uuid::Uuid;

use crate::mm2::lp_swap::{MakerSwap, run_maker_swap, TakerSwap, run_taker_swap};

/// Temporary kludge, improving readability of the not-yet-fully-ported code. Should be removed eventually.
macro_rules! c2s {($cs: expr) => {unwrap!(CStr::from_ptr($cs.as_ptr()).to_str())}}

#[link="c"]
extern {
    fn printf(_: *const libc::c_char, ...) -> libc::c_int;
}

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
    uuid: Uuid,
    method: String,
    sender_pubkey: H256Json,
    dest_pub_key: H256Json,
}

#[derive(Serialize, Deserialize)]
struct MakerReserved {
    base: String,
    rel: String,
    base_amount: BigDecimal,
    rel_amount: BigDecimal,
    taker_request_uuid: Uuid,
    method: String,
    sender_pubkey: H256Json,
    dest_pub_key: H256Json,
}

#[derive(Serialize, Deserialize)]
struct MakerConnected {
    taker_request_uuid: Uuid,
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

unsafe fn lp_connect_start_bob(ctx: &MmArc, base: *mut c_char, rel: *mut c_char, qp: *mut lp::LP_quoteinfo) -> i32 {
    let dex_selector = 0;
    let mut retval: i32 = -1;
    let mut pair_str: [c_char; 512] = [0; 512];
    (*qp).quotetime = (now_ms() / 1000) as u32;

    if lp::G.LP_mypub25519 == (*qp).srchash {
        lp::LP_requestinit(&mut (*qp).R, (*qp).srchash, (*qp).desthash, base, (*qp).satoshis, rel, (*qp).destsatoshis, (*qp).timestamp, (*qp).quotetime, dex_selector, (*qp).fill as i32, (*qp).gtc as i32);
        let loop_thread = thread::Builder::new().name("maker_loop".into()).spawn({
            let taker_str = unwrap!(CStr::from_ptr(rel).to_str());
            let taker_coin = unwrap!(unwrap! (lp_coinfind (ctx, taker_str)));
            let maker_str = unwrap!(CStr::from_ptr(base).to_str());
            let maker_coin = unwrap!(unwrap! (lp_coinfind (ctx, maker_str)));
            let ctx = ctx.clone();
            let alice = (*qp).desthash;
            let maker_amount = (*qp).R.srcamount as u64;
            let taker_amount = (*qp).R.destamount as u64;
            let my_persistent_pub = unwrap!(compressed_pub_key_from_priv_raw(&lp::G.LP_privkey.bytes, ChecksumType::DSHA256));
            let uuid = CStr::from_ptr((*qp).uuidstr.as_ptr()).to_string_lossy().into_owned();
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
                let req_json = lp::LP_quotejson(qp);
                lp::LP_swapsfp_update((*qp).R.requestid, (*qp).R.quoteid);
                lp::jaddstr(req_json, b"method\x00".as_ptr() as *mut c_char, b"connected\x00".as_ptr() as *mut c_char);
                lp::jaddstr(req_json, b"pair\x00".as_ptr() as *mut c_char, pair_str.as_mut_ptr());
                broadcast_p2p_msg_for_c((*qp).desthash, lp::jprint(req_json, 0), unwrap!(ctx.ffi_handle()));
                thread::sleep(Duration::from_secs(1));
                printf(b"send CONNECT for %u-%u\n\x00".as_ptr() as *const c_char, (*qp).R.requestid, (*qp).R.quoteid);
                // broadcast_p2p_msg(zero, lp::jprint(req_json, 0));
                if lp::IPC_ENDPOINT >= 0 {
                    lp_queue_command_for_c(null_mut(), lp::jprint(req_json, 0), lp::IPC_ENDPOINT, -1, 0);
                }
                if (*qp).mpnet != 0 && (*qp).gtc == 0 {
                    let msg = lp::jprint(req_json, 0);
                    lp::LP_mpnet_send(0, msg, 1, (*qp).destaddr.as_mut_ptr());
                    free_c_ptr(msg as *mut c_void);
                }
                lp::free_json(req_json);
                retval = 0;
            },
            Err(e) => {
                log!({ "Got error launching bob swap loop: {}", e });
                lp::LP_failedmsg((*qp).R.requestid, (*qp).R.quoteid, -3002.0, (*qp).uuidstr.as_mut_ptr());
            }
        }
    } else {
        lp::LP_failedmsg((*qp).R.requestid, (*qp).R.quoteid, -3004.0, (*qp).uuidstr.as_mut_ptr());
        log!("lp::G.LP_mypub25519 " (lp::G.LP_mypub25519) " != (*qp).srchash " ((*qp).srchash));
    }
    retval
}

unsafe fn lp_connected_alice(ctx: &MmArc, taker_match: TakerOrderMatch) { // alice
    let alice_loop_thread = thread::Builder::new().name("taker_loop".into()).spawn({
        let ctx = ctx.clone();
        let maker = taker_match.reserved.unwrap().sender_pubkey.into();
        let taker_coin = unwrap!(unwrap! (lp_coinfind (&ctx, &taker_match.request.rel)));
        let maker_coin = unwrap!(unwrap! (lp_coinfind (&ctx, &taker_match.request.base)));
        let maker_amount = (*qp).R.srcamount as u64;
        let taker_amount = (*qp).R.destamount as u64;
        let my_persistent_pub = unwrap!(compressed_pub_key_from_priv_raw(&lp::G.LP_privkey.bytes, ChecksumType::DSHA256));
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
        Ok(_h) => {
            let retjson = CJSON(lp::LP_quotejson(qp));
            lp::jaddstr(retjson.0, b"result\x00".as_ptr() as *mut c_char, b"success\x00".as_ptr() as *mut c_char);
            lp::LP_swapsfp_update((*qp).R.requestid, (*qp).R.quoteid);
            if lp::IPC_ENDPOINT >= 0 {
                let msg = lp::jprint(retjson.0, 0);
                lp_queue_command_for_c(null_mut(), msg, lp::IPC_ENDPOINT, -1, 0);
                free_c_ptr(msg as *mut c_void);
            }
        },
        Err(e) => {
            log!({ "Got error trying to start taker loop {}", e });
            lp::LP_aliceid((*qp).tradeid, (*qp).aliceid, b"error9\x00".as_ptr() as *mut c_char, (*qp).R.requestid, (*qp).R.quoteid);
            lp::LP_failedmsg((*qp).R.requestid, (*qp).R.quoteid, -4006.0, (*qp).uuidstr.as_mut_ptr());
        }
    }
}

unsafe fn lp_trades_got_connect(ctx: &MmArc, qp: &lp::LP_quoteinfo) -> Option<lp::LP_quoteinfo> {
    let mut qp = qp.clone();
    let coin = unwrap!(lp_coinfind(ctx, c2s!(qp.srccoin)));
    if coin.is_none() {return None};
    let src_coin = c2s!(qp.srccoin);
    let dest_coin = c2s!(qp.destcoin);
    let portfolio_ctx = unwrap!(PortfolioContext::from_ctx(ctx));
    let mut my_orders = unwrap!(portfolio_ctx.my_maker_orders.lock());

    match my_orders.iter_mut().find(|(_, order)| order.base == src_coin && order.rel == dest_coin) {
        Some((_, order)) => { order.price = 0.into(); },
        None => {
            log!("No order for " (src_coin) "/" (dest_coin));
            return None;
        }
    };
    drop(my_orders);
    //let q_price = lp::LP_trades_pricevalidate(qp, coin, my_price);
    //if q_price < 0. {
    //    log!("Bob q_price is less than zero!");
    //    return null_mut();
    //}
    //if lp::LP_reservation_check((*qp).txid, (*qp).vout, (*qp).desthash) == 0 && lp::LP_reservation_check((*qp).txid2, (*qp).vout2, (*qp).desthash) == 0 {
    // AG: The Alice p2p ID seems to be in the `qp.desthash`.
    log!({"bob {} received CONNECT.({})", lp::G.LP_mypub25519, c2s!(qp.uuidstr[32..])});
    lp_connect_start_bob(&ctx, qp.srccoin.as_mut_ptr(), qp.destcoin.as_mut_ptr(), &mut qp);
    Some(qp)
    //} else {
    //    lp::LP_failedmsg((*qp).R.requestid, (*qp).R.quoteid, -1.0, (*qp).uuidstr.as_mut_ptr());
    //    log!({"connect message from non-reserved ({})", (*qp).aliceid});
    //}
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
    c_json: &CJSON,
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

        let my_match = match taker_matches.entry(reserved_msg.taker_request_uuid) {
            Entry::Vacant(_) => {
                log!("Our node doesn't have the ordermatch with uuid "(reserved_msg.taker_request_uuid));
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
                uuid: reserved_msg.taker_request_uuid,
            };
            my_match.reserved = Some(reserved_msg);
            ctx.broadcast_p2p_msg(&unwrap!(json::to_string(&connect)));
            my_match.connect = Some(connect);
            my_taker_orders.remove(&reserved_msg.taker_request_uuid);
        }
        return 1;
    }
    if method == Some("connected") {
        let connected: MakerConnected = match json::from_value(json.clone()) {
            Ok(c) => c,
            Err(_) => return 1,
        };
        let portfolio_ctx = unwrap!(PortfolioContext::from_ctx(&ctx));
        let mut my_taker_orders = unwrap!(portfolio_ctx.my_taker_orders.lock());
        let mut taker_matches = unwrap!(ordermatch_ctx.taker_matches.lock());
        let my_match = match taker_matches.entry(connected.taker_request_uuid) {
            Entry::Vacant(_) => {
                log!("Our node doesn't have the ordermatch with uuid " (connected.taker_request_uuid));
                return 1;
            },
            Entry::Occupied(entry) => entry.into_mut()
        };
        // alice
        if H256Json::from(lp::G.LP_mypub25519) == connected.dest_pub_key && H256Json::from(lp::G.LP_mypub25519) != connected.sender_pubkey {
            let reserved = my_match.reserved.as_mut().unwrap();
            lp_connected_alice(
                &ctx,
                &mut q,
            );
            // AG: Bob's p2p ID (`LP_mypub25519`) is in `json["srchash"]`.
            log!("CONNECTED.(" (json) ")");
        }
        return 1;
    }
    // bob
    if method == Some("request") {
        let taker_request: TakerRequest = match json::from_value(json) {
            Ok(r) => r,
            Err(_) => return 1,
        };
        if lp::G.LP_mypub25519.bytes == taker_request.dest_pub_key.0 {
            log!("Skip the request originating from our pubkey");
            return 1;
        }
        let portfolio_ctx = unwrap!(PortfolioContext::from_ctx(&ctx));
        let my_orders = unwrap!(portfolio_ctx.my_maker_orders.lock());

        for (_, order) in my_orders.iter() {
            if let OrderMatchResult::Matched((base_amount, rel_amount)) = match_order_and_request(order, &taker_request) {
                let reserved = MakerReserved {
                    dest_pub_key: taker_request.sender_pubkey.clone(),
                    sender_pubkey: lp::G.LP_mypub25519.bytes.into(),
                    base: order.base.clone(),
                    base_amount,
                    rel_amount,
                    rel: order.rel.clone(),
                    method: "reserved".into(),
                    taker_request_uuid: taker_request.uuid.clone(),
                };

                ctx.broadcast_p2p_msg(&unwrap!(json::to_string(&reserved)));
                let maker_match = MakerOrderMatch {
                    request: taker_request,
                    reserved,
                    connect: None,
                    connected: None,
                };
                let mut maker_matches = unwrap!(ordermatch_ctx.maker_matches.lock());
                maker_matches.insert(uuid, maker_match);
                return 1;
            }
        }
    }

    if method == Some("connect") {
        // bob
        if lp::G.LP_mypub25519 == q.srchash && lp::G.LP_mypub25519 != q.desthash {
            let mut maker_matches = unwrap!(ordermatch_ctx.maker_matches.lock());
            let my_match = match maker_matches.entry(uuid) {
                Entry::Vacant(_) => {
                    log!("Our node doesn't have the order with uuid "(uuid));
                    return 1;
                },
                Entry::Occupied(entry) => entry.into_mut()
            };
            if let Some(qp) = lp_trades_got_connect(&ctx, &q) {
                my_match.connect = Some(q);
                my_match.connected = Some(qp);
            }
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
