use super::{orderbook_topic_from_base_rel, OrdermatchContext, OrdermatchRequest};
use crate::mm2::lp_network::{request_any_relay, P2PRequest};
use coins::coin_conf;
use common::{log, mm_ctx::MmArc};
use http::Response;
use serde_json::{self as json, Value as Json};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct OrderbookDepthReq {
    pairs: Vec<(String, String)>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PairDepth {
    asks: usize,
    bids: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct OrderbookDepthP2PResponse {
    depth: HashMap<(String, String), PairDepth>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PairWithDepth {
    pair: (String, String),
    depth: PairDepth,
}

pub async fn orderbook_depth_rpc(ctx: MmArc, req: Json) -> Result<Response<Vec<u8>>, String> {
    let ordermatch_ctx = OrdermatchContext::from_ctx(&ctx).unwrap();
    let req: OrderbookDepthReq = try_s!(json::from_value(req));

    let wallet_only_pairs: Vec<_> = req
        .pairs
        .clone()
        .into_iter()
        .filter_map(|pair| {
            let first_pair_coin_conf = coin_conf(&ctx, &pair.0);
            if first_pair_coin_conf["wallet_only"].as_bool().unwrap_or(false) {
                Some(pair)
            } else {
                let second_pair_coin_conf = coin_conf(&ctx, &pair.1);
                if second_pair_coin_conf["wallet_only"].as_bool().unwrap_or(false) {
                    Some(pair)
                } else {
                    None
                }
            }
        })
        .collect();

    if !wallet_only_pairs.is_empty() {
        return ERR!("Pairs {:?} has wallet only coins", wallet_only_pairs);
    }

    let mut result = Vec::with_capacity(req.pairs.len());

    let orderbook = ordermatch_ctx.orderbook.lock().await;

    // the Iter::filter uses &Self::Item, which is undesirable, we need owned pair
    #[allow(clippy::unnecessary_filter_map)]
    let to_request_from_relay: Vec<_> = req
        .pairs
        .into_iter()
        .filter_map(|pair| {
            let topic = orderbook_topic_from_base_rel(&pair.0, &pair.1);
            if orderbook.is_subscribed_to(&topic) {
                let asks = orderbook.unordered.get(&pair).map_or(0, |orders| orders.len());
                let reversed = (pair.1.clone(), pair.0.clone());
                let bids = orderbook.unordered.get(&reversed).map_or(0, |orders| orders.len());
                result.push(PairWithDepth {
                    pair,
                    depth: PairDepth { asks, bids },
                });
                None
            } else {
                Some(pair)
            }
        })
        .collect();

    // avoid locking orderbook for long time during P2P request
    drop(orderbook);
    if !to_request_from_relay.is_empty() {
        let p2p_request = OrdermatchRequest::OrderbookDepth {
            pairs: to_request_from_relay,
        };
        log::debug!("Sending request_any_relay({:?})", p2p_request);
        let p2p_response = try_s!(
            request_any_relay::<OrderbookDepthP2PResponse>(ctx.clone(), P2PRequest::Ordermatch(p2p_request)).await
        );
        log::debug!("Received response {:?}", p2p_response);
        if let Some((response, _)) = p2p_response {
            for (pair, depth) in response.depth {
                result.push(PairWithDepth { pair, depth });
            }
        }
    }

    let res = json!({ "result": result });
    Response::builder()
        .body(json::to_vec(&res).expect("Serialization failed"))
        .map_err(|e| ERRL!("{}", e))
}

pub async fn process_orderbook_depth_p2p_request(
    ctx: MmArc,
    pairs: Vec<(String, String)>,
) -> Result<Option<Vec<u8>>, String> {
    let ordermatch_ctx = OrdermatchContext::from_ctx(&ctx).expect("ordermatch_ctx must exist at this point");
    let orderbook = ordermatch_ctx.orderbook.lock().await;
    let depth = pairs
        .into_iter()
        .map(|pair| {
            let asks = orderbook.unordered.get(&pair).map_or(0, |orders| orders.len());
            let reversed = (pair.1.clone(), pair.0.clone());
            let bids = orderbook.unordered.get(&reversed).map_or(0, |orders| orders.len());
            (pair, PairDepth { asks, bids })
        })
        .collect();
    let response = OrderbookDepthP2PResponse { depth };
    let encoded = rmp_serde::to_vec(&response).expect("rmp_serde::to_vec should not fail here");
    Ok(Some(encoded))
}
