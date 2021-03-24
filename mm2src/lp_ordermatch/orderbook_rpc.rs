use super::{subscribe_to_orderbook_topic, OrdermatchContext, RpcOrderbookEntry};
use bigdecimal::BigDecimal;
use coins::{address_by_coin_conf_and_pubkey_str, coin_conf};
use common::{mm_ctx::MmArc,
             mm_number::{Fraction, MmNumber},
             now_ms};
use http::Response;
use num_rational::BigRational;
use num_traits::Zero;
use serde_json::{self as json, Value as Json};

#[derive(Deserialize)]
struct OrderbookReq {
    base: String,
    rel: String,
}

construct_detailed!(TotalAsksBaseVol, total_asks_base_vol);
construct_detailed!(TotalAsksRelVol, total_asks_rel_vol);

#[derive(Debug, Serialize)]
pub struct OrderbookResponse {
    #[serde(rename = "askdepth")]
    ask_depth: u32,
    asks: Vec<RpcOrderbookEntry>,
    base: String,
    #[serde(rename = "biddepth")]
    bid_depth: u32,
    bids: Vec<RpcOrderbookEntry>,
    netid: u16,
    #[serde(rename = "numasks")]
    num_asks: usize,
    #[serde(rename = "numbids")]
    num_bids: usize,
    rel: String,
    timestamp: u64,
    #[serde(flatten)]
    total_asks_base: TotalAsksBaseVol,
    #[serde(flatten)]
    total_asks_rel: TotalAsksRelVol,
}

pub async fn orderbook_rpc(ctx: MmArc, req: Json) -> Result<Response<Vec<u8>>, String> {
    let req: OrderbookReq = try_s!(json::from_value(req));
    if req.base == req.rel {
        return ERR!("Base and rel must be different coins");
    }
    let base_coin_conf = coin_conf(&ctx, &req.base);
    if base_coin_conf.is_null() {
        return ERR!("Coin {} is not found in config", req.base);
    }
    let rel_coin_conf = coin_conf(&ctx, &req.rel);
    if rel_coin_conf.is_null() {
        return ERR!("Coin {} is not found in config", req.rel);
    }
    let request_orderbook = true;
    try_s!(subscribe_to_orderbook_topic(&ctx, &req.base, &req.rel, request_orderbook).await);
    let ordermatch_ctx = try_s!(OrdermatchContext::from_ctx(&ctx));
    let orderbook = ordermatch_ctx.orderbook.lock().await;
    let my_pubsecp = hex::encode(&**ctx.secp256k1_key_pair().public());

    let mut asks = match orderbook.unordered.get(&(req.base.clone(), req.rel.clone())) {
        Some(uuids) => {
            let mut orderbook_entries = Vec::new();
            for uuid in uuids {
                let ask = orderbook.order_set.get(uuid).ok_or(ERRL!(
                    "Orderbook::unordered contains {:?} uuid that is not in Orderbook::order_set",
                    uuid
                ))?;

                let address = try_s!(address_by_coin_conf_and_pubkey_str(
                    &req.base,
                    &base_coin_conf,
                    &ask.pubkey
                ));
                let is_mine = my_pubsecp == ask.pubkey;
                orderbook_entries.push(ask.as_rpc_entry_ask(address, is_mine));
            }
            orderbook_entries
        },
        None => Vec::new(),
    };
    asks.sort_unstable_by(|ask1, ask2| ask2.price_rat.cmp(&ask1.price_rat));
    let total_asks_base_vol: MmNumber = asks
        .iter()
        .fold(BigRational::zero(), |total, ask| {
            &total + ask.base_max_volume.as_ratio()
        })
        .into();

    let mut bids = match orderbook.unordered.get(&(req.rel.clone(), req.base.clone())) {
        Some(uuids) => {
            let mut orderbook_entries = vec![];
            for uuid in uuids {
                let bid = orderbook.order_set.get(uuid).ok_or(ERRL!(
                    "Orderbook::unordered contains {:?} uuid that is not in Orderbook::order_set",
                    uuid
                ))?;
                let address = try_s!(address_by_coin_conf_and_pubkey_str(
                    &req.rel,
                    &rel_coin_conf,
                    &bid.pubkey
                ));
                let is_mine = my_pubsecp == bid.pubkey;
                orderbook_entries.push(bid.as_rpc_entry_bid(address, is_mine));
            }
            orderbook_entries
        },
        None => vec![],
    };
    bids.sort_unstable_by(|bid1, bid2| bid2.price_rat.cmp(&bid1.price_rat));

    let response = OrderbookResponse {
        num_asks: asks.len(),
        num_bids: bids.len(),
        ask_depth: 0,
        asks,
        base: req.base,
        bid_depth: 0,
        bids,
        netid: ctx.netid(),
        rel: req.rel,
        timestamp: now_ms() / 1000,
        total_asks_base: total_asks_base_vol.into(),
        total_asks_rel: MmNumber::from(0).into(),
    };
    let response = try_s!(json::to_vec(&response));
    Ok(try_s!(Response::builder().body(response)))
}
