
/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
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
use common::{lp, lp_queue_command_for_c, free_c_ptr, sat_to_f, SATOSHIS, SMALLVAL, CJSON, dstr, rpc_response, rpc_err_response, HyRes};
use common::for_c::broadcast_p2p_msg_for_c;
use common::mm_ctx::{from_ctx, MmArc, MmWeak};
use coins::{lp_coinfind, MmCoinEnum};
use coins::utxo::{compressed_pub_key_from_priv_raw, ChecksumType};
use futures::future::Future;
use gstuff::now_ms;
use hashbrown::hash_map::{Entry, HashMap};
use libc::{self, c_void, c_char, strcpy};
use num_traits::cast::ToPrimitive;
use portfolio::{Order, OrderAmount, PortfolioContext};
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
#[derive(Default, Clone, Copy)]
struct BobCompetition {
    pub alice_id: u64,
    pub best_price: f64,
    pub start_time: u64,
    pub counter: i32,
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

fn lp_base_satoshis(
    relvolume: f64,
    price: f64,
    desttxfee: u64,
) -> u64 {
    //printf("basesatoshis %.8f (rel %.8f / price %.8f)\n",dstr(SATOSHIDEN * ((relvolume) / price) + 2*txfee),relvolume,price);
    if relvolume > desttxfee as f64 / 100000000.0 && price > 1e-15f64 {
        (100000000.0 * (relvolume / price)) as u64
    } else {
        0
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

fn lp_trade(
    qp: *mut lp::LP_quoteinfo,
    price: f64,
    trade_id: u32,
    dest_pub_key: lp::bits256,
    uuid: Uuid,
    ctx: &MmArc,
) -> Result<String, String> {
    unsafe {
        (*qp).aliceid = lp::LP_rand() as u64;
        (*qp).tradeid = if trade_id > 0 {
            trade_id
        } else {
            lp::LP_rand()
        };
        let uuid_str = try_s!(CString::new(uuid.to_string()));
        (*qp).srchash = dest_pub_key;
        strcpy((*qp).uuidstr.as_ptr() as *mut c_char, uuid_str.as_ptr() as *mut c_char);
        (*qp).maxprice = price;
        (*qp).timestamp = (now_ms()  / 1000) as u32;
        lp::LP_query(b"request\x00".as_ptr() as *mut c_char, qp, unwrap!(ctx.ffi_handle()));
        let ordermatch_ctx = try_s!(OrdermatchContext::from_ctx(&ctx));
        let mut taker_matches = try_s!(ordermatch_ctx.taker_matches.lock());
        taker_matches.insert(uuid, TakerOrderMatch {
            request: *qp,
            reserved: None,
            connect: None,
            connected: None,
        });
        lp::LP_Alicemaxprice = (*qp).maxprice;
        log!({"lp_trade] Alice max price: {}", lp::LP_Alicemaxprice});
        lp::LP_Alicedestpubkey = (*qp).srchash;
        if (*qp).gtc == 0 {
            let msg = lp::jprint(lp::LP_quotejson(qp), 1);
            lp::LP_mpnet_send(1, msg, 1, null_mut());
            free_c_ptr(msg as *mut c_void);
        }
        Ok(json!({
            "result": {
                "uuid": uuid,
            }
        }).to_string())
    }
}
/*
int32_t LP_quotecmp(int32_t strictflag,struct LP_quoteinfo *qp,struct LP_quoteinfo *qp2)
{
    if ( lp::bits256_nonz(LP_Alicedestpubkey) != 0 )
    {
        if (bits256_cmp(LP_Alicedestpubkey,qp->srchash) != 0 )
        {
            printf("reject quote from non-matching pubkey\n");
            return(-1);
        } else printf("dont reject quote from destpubkey\n");
    }
    if ( bits256_cmp(qp->desthash,qp2->desthash) == 0 && strcmp(qp->srccoin,qp2->srccoin) == 0 && strcmp(qp->destcoin,qp2->destcoin) == 0 && bits256_cmp(qp->desttxid,qp2->desttxid) == 0 && qp->destvout == qp2->destvout && bits256_cmp(qp->feetxid,qp2->feetxid) == 0 && qp->feevout == qp2->feevout && qp->destsatoshis == qp2->destsatoshis && qp->txfee >= qp2->txfee && qp->desttxfee == qp2->desttxfee )
    {
        if ( strictflag == 0 || (qp->aliceid == qp2->aliceid && qp->R.requestid == qp2->R.requestid && qp->R.quoteid == qp2->R.quoteid && qp->vout == qp2->vout && qp->vout2 == qp2->vout2 && qp->satoshis == qp2->satoshis && bits256_cmp(qp->txid,qp2->txid) == 0 && bits256_cmp(qp->txid2,qp2->txid2) == 0 && bits256_cmp(qp->srchash,qp2->srchash) == 0) )
            return(0);
        else printf("strict compare failure\n");
    }
    return(-1);
}

void LP_alicequery_clear()
{
    memset(&LP_Alicequery,0,sizeof(LP_Alicequery));
    memset(&LP_Alicedestpubkey,0,sizeof(LP_Alicedestpubkey));
    LP_Alicemaxprice = 0.;
    Alice_expiration = 0;
}

int32_t LP_alice_eligible(uint32_t quotetime)
{
    if ( Alice_expiration != 0 && quotetime > Alice_expiration )
    {
        if ( LP_Alicequery.uuidstr[0] != 0 )
            LP_failedmsg(LP_Alicequery.R.requestid,LP_Alicequery.R.quoteid,-9999,LP_Alicequery.uuidstr);
        printf("time expired for Alice_request\n");
        LP_alicequery_clear();
    }
    return(Alice_expiration == 0 || time(NULL) < Alice_expiration);
}

char *LP_cancel_order(char *uuidstr)
{
    int32_t num = 0; cJSON *retjson;
    if ( uuidstr != 0 )
    {
        if ( uuidstr[0] == 'G' )
        {
            struct LP_gtcorder *gtc,*tmp;
            DL_FOREACH_SAFE(GTCorders,gtc,tmp)
            {
                if ( strcmp(gtc->Q.uuidstr,uuidstr) == 0 )
                {
                    retjson = cJSON_CreateObject();
                    jaddstr(retjson,"result","success");
                    jaddstr(retjson,"cancelled",uuidstr);
                    jaddnum(retjson,"pending",gtc->pending);
                    if ( gtc->cancelled == 0 )
                    {
                        gtc->cancelled = (uint32_t)time(NULL);
                        jaddstr(retjson,"status","uuid canceled");
                        LP_failedmsg(gtc->Q.R.requestid,gtc->Q.R.quoteid,-9997,gtc->Q.uuidstr);
                    }
                    else
                    {
                        jaddstr(retjson,"status","uuid already canceled");
                        LP_failedmsg(gtc->Q.R.requestid,gtc->Q.R.quoteid,-9996,gtc->Q.uuidstr);
                    }
                }
            }
            return(clonestr("{\"error\":\"gtc uuid not found\"}"));
        }
        else
        {
            num = LP_trades_canceluuid(uuidstr);
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"result","success");
            jaddnum(retjson,"numentries",num);
            if ( strcmp(LP_Alicequery.uuidstr,uuidstr) == 0 )
            {
                LP_failedmsg(LP_Alicequery.R.requestid,LP_Alicequery.R.quoteid,-9998,LP_Alicequery.uuidstr);
                LP_alicequery_clear();
                jaddstr(retjson,"status","uuid canceled");
            } else jaddstr(retjson,"status","will stop trade negotiation, but if swap started it wont cancel");
        }
        return(jprint(retjson,1));
    }
    return(clonestr("{\"error\":\"uuid not cancellable\"}"));
}
*/
unsafe fn lp_connected_alice(ctx: &MmArc, qp: *mut lp::LP_quoteinfo) { // alice
    if (*qp).desthash != lp::G.LP_mypub25519 {
        lp::LP_aliceid((*qp).tradeid, (*qp).aliceid, b"error1\x00".as_ptr() as *mut c_char, 0, 0);
        lp::LP_failedmsg((*qp).R.requestid, (*qp).R.quoteid, -4000.0, (*qp).uuidstr.as_mut_ptr());
        return;
    }
    printf("CONNECTED mpnet.%d fill.%d gtc.%d numpending.%d tradeid.%u requestid.%u quoteid.%u\n\x00".as_ptr() as *const c_char,
           (*qp).mpnet, (*qp).fill, (*qp).gtc, lp::G.LP_pendingswaps, (*qp).tradeid, (*qp).R.requestid, (*qp).R.quoteid);
    let dex_selector = 0;
    lp::LP_requestinit(&mut (*qp).R, (*qp).srchash, (*qp).desthash, (*qp).srccoin.as_mut_ptr(), (*qp).satoshis, (*qp).destcoin.as_mut_ptr(), (*qp).destsatoshis, (*qp).timestamp, (*qp).quotetime, dex_selector, (*qp).fill as i32, (*qp).gtc as i32);
//printf("calculated requestid.%u quoteid.%u\n",qp->R.requestid,qp->R.quoteid);
    lp::LP_Alicereserved = lp::LP_quoteinfo::default();
    lp::LP_aliceid((*qp).tradeid, (*qp).aliceid, b"connected\x00".as_ptr() as *mut c_char, (*qp).R.requestid, (*qp).R.quoteid);
    /*
    let qprice = lp::LP_quote_validate(&mut autxo, &mut butxo, qp, 0);
    if qprice <= SMALLVAL {
        lp::LP_aliceid((*qp).tradeid, (*qp).aliceid, b"error4\x00".as_ptr() as *mut c_char, 0, 0);
        lp::LP_failedmsg((*qp).R.requestid, (*qp).R.quoteid, qprice, (*qp).uuidstr.as_mut_ptr());
        printf(b"quote %s/%s validate error %.0f\n\x00".as_ptr() as *const c_char, (*qp).srccoin, (*qp).destcoin, qprice);
        return;
    }
    */
    lp::LP_aliceid((*qp).tradeid, (*qp).aliceid, b"started\x00".as_ptr() as *mut c_char, (*qp).R.requestid, (*qp).R.quoteid);
    let alice_loop_thread = thread::Builder::new().name("taker_loop".into()).spawn({
        let ctx = ctx.clone();
        let maker = (*qp).srchash;
        let taker_str = c2s!((*qp).R.dest);
        let taker_coin = unwrap!(unwrap! (lp_coinfind (&ctx, taker_str)));
        let maker_str = c2s!((*qp).R.src);
        let maker_coin = unwrap!(unwrap! (lp_coinfind (&ctx, maker_str)));
        let maker_amount = (*qp).R.srcamount as u64;
        let taker_amount = (*qp).R.destamount as u64;
        let my_persistent_pub = unwrap!(compressed_pub_key_from_priv_raw(&lp::G.LP_privkey.bytes, ChecksumType::DSHA256));
        let uuid = CStr::from_ptr((*qp).uuidstr.as_ptr()).to_string_lossy().into_owned();
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
/*
int32_t LP_aliceonly(char *symbol)
{
    return(0);
}

int32_t LP_validSPV(char *symbol,char *coinaddr,bits256 txid,int32_t vout)
{
    struct electrum_info *ep,*backupep; cJSON *txobj; struct LP_address_utxo *up; struct iguana_info *coin; int32_t height; struct LP_transaction *tx;
    coin = LP_coinfind(symbol);
    if ( coin != 0 && (ep= coin->electrum) != 0 )
    {
        if ( (up= LP_address_utxofind(coin,coinaddr,txid,vout)) == 0 )
        {
            if ( (txobj= electrum_transaction(&height,symbol,ep,&txobj,txid,coinaddr)) != 0 )
                free_json(txobj);
            if ( (tx= LP_transactionfind(coin,txid)) != 0 )
            {
                if ( vout < tx->numvouts && tx->height > 0 )
                {
                    printf("added missing utxo for SPV checking\n");
                    LP_address_utxoadd(0,(uint32_t)time(NULL),"LP_validSPV",coin,coinaddr,txid,vout,tx->outpoints[vout].value,tx->height,-1);
                }
            }
        }
        if ( (up= LP_address_utxofind(coin,coinaddr,txid,vout)) != 0 )
        {
            if ( up->SPV > 0 )
                return(0);
            if ( up->SPV < 0 )
                return(-1);
            if ( (backupep= ep->prev) == 0 )
                backupep = ep;
            up->SPV = LP_merkleproof(coin,coinaddr,backupep,up->U.txid,up->U.height);
            if ( up->SPV < 0 )
                return(-1);
        }
    }
    return(0);
}

double LP_trades_alicevalidate(void *ctx,struct LP_quoteinfo *qp)
{
    double qprice; struct LP_utxoinfo A,B,*autxo,*butxo; char str[65];
    autxo = &A;
    butxo = &B;
    memset(autxo,0,sizeof(*autxo));
    memset(butxo,0,sizeof(*butxo));
    LP_abutxo_set(autxo,butxo,qp);
    if ( (qprice= LP_quote_validate(autxo,butxo,qp,0)) <= SMALLVAL )
    {
        printf("reserved quote validate error %.0f\n",qprice);
        return((int32_t)qprice);
    }
    if ( LP_validSPV(qp->srccoin,qp->coinaddr,qp->txid,qp->vout) < 0 )
    {
        sleep(1);
        if ( LP_validSPV(qp->srccoin,qp->coinaddr,qp->txid,qp->vout) < 0 )
        {
            printf("LP_trades_alicevalidate %s src %s failed SPV check\n",qp->srccoin,bits256_str(str,qp->txid));
            return(-44);
        }
    }
    else if ( LP_validSPV(qp->srccoin,qp->coinaddr,qp->txid2,qp->vout2) < 0 )
    {
        sleep(1);
        if ( LP_validSPV(qp->srccoin,qp->coinaddr,qp->txid2,qp->vout2) < 0 )
        {
            printf("LP_trades_alicevalidate %s src2 %s failed SPV check\n",qp->srccoin,bits256_str(str,qp->txid2));
            return(-55);
        }
    }
    return(qprice);
}
*/
unsafe fn lp_reserved(qp: *mut lp::LP_quoteinfo, ctx: &MmArc) {
    //let price = lp::LP_pricecache(qp, (*qp).srccoin.as_mut_ptr(), (*qp).destcoin.as_mut_ptr(), (*qp).txid, (*qp).vout);
    (*qp).tradeid = lp::LP_Alicequery.tradeid;
    lp::LP_Alicereserved = *qp;
    //printf("send CONNECT\n");
    lp::LP_query(
        b"connect\x00" as *const u8 as *mut libc::c_char,
        qp,
        unwrap!(ctx.ffi_handle())
    );
}
/*
double LP_trades_bobprice(double *bidp,double *askp,struct LP_quoteinfo *qp)
{
    double price; struct iguana_info *coin; char str[65];
    price = LP_myprice(1,bidp,askp,qp->srccoin,qp->destcoin);
    if ( (coin= LP_coinfind(qp->srccoin)) == 0 || price <= SMALLVAL || *askp <= SMALLVAL )
    {
        //printf("this node has no price for %s/%s\n",qp->srccoin,qp->destcoin);
        return(0.);
    }
    price = *askp;
    //printf("MYPRICE %s/%s %.8f vs qprice %.8f\n",qp->srccoin,qp->destcoin,price,(double)qp->destsatoshis/qp->satoshis);
    if ( LP_validSPV(qp->destcoin,qp->destaddr,qp->desttxid,qp->destvout) < 0 )
    {
        printf("LP_trades_bobprice %s dest %s failed SPV check\n",qp->destcoin,bits256_str(str,qp->desttxid));
        return(0.);
    }
    else if (LP_validSPV(qp->destcoin,qp->destaddr,qp->feetxid,qp->feevout) < 0 )
    {
        printf("LP_trades_bobprice %s dexfee %s failed SPV check\n",qp->destcoin,bits256_str(str,qp->feetxid));
        return(0.);
    }
    return(*askp);
}

double LP_trades_pricevalidate(struct LP_quoteinfo *qp,struct iguana_info *coin,double price)
{
    double qprice; struct LP_utxoinfo A,B,*autxo,*butxo;
    autxo = &A;
    butxo = &B;
    memset(autxo,0,sizeof(*autxo));
    memset(butxo,0,sizeof(*butxo));
    LP_abutxo_set(autxo,butxo,qp);
    if ( coin->etomic[0] == 0 && strcmp(qp->coinaddr,coin->smartaddr) != 0 )
    {
        printf("bob is patching qp->coinaddr %s mismatch != %s\n",qp->coinaddr,coin->smartaddr);
        strcpy(qp->coinaddr,coin->smartaddr);
    }
    if ( butxo == 0 || lp::bits256_nonz(butxo->payment.txid) == 0 || lp::bits256_nonz(butxo->deposit.txid) == 0 || butxo->payment.vout < 0 || butxo->deposit.vout < 0 )
    {
        char str[65],str2[65]; printf("couldnt find bob utxos for autxo %s/v%d %s/v%d %.8f -> %.8f\n",bits256_str(str,qp->txid),qp->vout,bits256_str(str2,qp->txid2),qp->vout2,dstr(qp->satoshis),dstr(qp->destsatoshis));
        return(-66);
    }
    if ( (qprice= LP_quote_validate(autxo,butxo,qp,1)) <= SMALLVAL )
    {
        printf("quote %s/%s validate error %.0f\n",qp->srccoin,qp->destcoin,qprice);
        return(-3);
    }
    if ( qprice < (price - 0.00000001) * 0.998)
    {
        printf(" quote price %.8f (%llu/%llu %.8f) too low vs %.8f for %s/%s price %.8f %.8f\n",qprice,(long long)qp->destsatoshis,(long long)(qp->satoshis-qp->txfee),(double)qp->destsatoshis/(qp->satoshis-qp->txfee),price,qp->srccoin,qp->destcoin,price,(price - 0.00000001) * 0.998);
        return(-77);
    }
    return(qprice);
}
*/
unsafe fn lp_trades_gotrequest(ctx: &MmArc, qp: &lp::LP_quoteinfo) -> Option<lp::LP_quoteinfo> {
    let p;
    let qprice;
    let mut str: [c_char; 65] = [0; 65];
    let mut qp = qp.clone();
    // AG: The Alice p2p ID seems to be in the `qp.desthash`.
    printf(b"bob %s received REQUEST.(%s) mpnet.%d fill.%d gtc.%d\n\x00".as_ptr() as *const c_char, lp::bits256_str(str.as_mut_ptr(), lp::G.LP_mypub25519), qp.uuidstr[32..].as_ptr(), qp.mpnet, qp.fill, qp.gtc);
    if lp::G.LP_mypub25519 == qp.desthash {
        log!("Skip the request originating from our pubkey");
        return None;
    }
    let src_coin = c2s!(qp.srccoin);
    let dest_coin = c2s!(qp.destcoin);

    let coin = match unwrap!(lp_coinfind(ctx, src_coin)) {Some(c) => c, None => return None};
    let portfolio_ctx = unwrap!(PortfolioContext::from_ctx(ctx));
    let my_orders = unwrap!(portfolio_ctx.my_maker_orders.lock());

    let my_price = match my_orders.get(&(src_coin.to_string(), dest_coin.to_string())) {
        Some(order) => order.price.to_f64().unwrap(),
        None => {
            log!("No order for " (src_coin) "/" (dest_coin));
            return None;
        }
    };
    drop(my_orders);

    log!({"dest sat {} sat {} tx_fee {}", qp.destsatoshis, qp.satoshis, qp.txfee});
    unwrap!(safecopy!(qp.coinaddr, "{}", coin.my_address()));
    if qp.srchash.nonz() == false || qp.srchash == lp::G.LP_mypub25519 {
        qprice = qp.destsatoshis as f64 / qp.satoshis as f64;
        strcpy(qp.gui.as_mut_ptr(), lp::G.gui.as_ptr());
        qp.srchash = lp::G.LP_mypub25519;
    } else {
        return None;
    }

    if qprice < my_price {
        printf(b"%s/%s ignore as qprice %.8f vs myprice %.8f\n\x00".as_ptr() as *const c_char, qp.srccoin.as_ptr(), qp.destcoin.as_ptr(), qprice, my_price);
        return None;
    }
//LP_RTmetrics_update(qp->srccoin,qp->destcoin);
    if lp::LP_RTmetrics_blacklisted(qp.desthash) >= 0 {
        printf(b"request from blacklisted %s, ignore\n\x00".as_ptr() as *const c_char, lp::bits256_str(str.as_mut_ptr(), qp.desthash));
        return None;
    }
    if qprice >= my_price {
        unwrap!(safecopy!(qp.gui, "{}", c2s!(lp::G.gui)));
        unwrap!(safecopy!(qp.coinaddr, "{}", coin.my_address()));
        qp.srchash = lp::G.LP_mypub25519;
        qp.satoshis = lp_base_satoshis(dstr(qp.destsatoshis as i64, 8), my_price, qp.desttxfee);
        qp.quotetime = (now_ms() / 1000) as u32;
    } else {
        return None;
    }

    if qp.satoshis <= qp.txfee {
        return None;
    }
    p = qp.destsatoshis as f64 / qp.satoshis as f64;
    if lp::LP_trades_pricevalidate(&mut qp, coin.iguana_info(), p) < 0. {
        if qp.fill != 0 {
            return None;
        }
    }

    printf(b"%s/%s qprice %.8f myprice %.8f [%.8f]\n\x00".as_ptr() as *const c_char, qp.srccoin.as_ptr(), qp.destcoin.as_ptr(), qprice, my_price, p);
    let reqjson = lp::LP_quotejson(&mut qp);
    if qp.quotetime == 0 {
        qp.quotetime = (now_ms() / 1000) as u32;
    }
    lp::jaddnum(reqjson, b"quotetime\x00".as_ptr() as *mut c_char, qp.quotetime as f64);
    lp::jaddnum(reqjson, b"pending\x00".as_ptr() as *mut c_char, (qp.timestamp + lp::LP_RESERVETIME) as f64);
    lp::jaddstr(reqjson, b"method\x00".as_ptr() as *mut c_char, b"reserved\x00".as_ptr() as *mut c_char);
    broadcast_p2p_msg_for_c(qp.desthash, lp::jprint(reqjson, 0), unwrap!(ctx.ffi_handle()));
    // let zero = lp::bits256::default();
    // broadcast_p2p_msg(zero, lp::jprint(reqjson, 0));
    if qp.mpnet != 0 && qp.gtc == 0 {
        let msg = lp::jprint(reqjson, 0);
        lp::LP_mpnet_send(0, msg, 1, qp.destaddr.as_mut_ptr());
        free_c_ptr(msg as *mut c_void);
    }
    lp::free_json(reqjson);
    log!({"Send RESERVED id.{}",qp.aliceid});
    Some(qp)
}

unsafe fn lp_trades_got_connect(ctx: &MmArc, qp: &lp::LP_quoteinfo) -> Option<lp::LP_quoteinfo> {
    let mut qp = qp.clone();
    let coin = unwrap!(lp_coinfind(ctx, c2s!(qp.srccoin)));
    if coin.is_none() {return None};
    let src_coin = c2s!(qp.srccoin);
    let dest_coin = c2s!(qp.destcoin);
    let portfolio_ctx = unwrap!(PortfolioContext::from_ctx(ctx));
    let my_orders = unwrap!(portfolio_ctx.my_maker_orders.lock());

    match my_orders.get(&(src_coin.to_string(), dest_coin.to_string())) {
        Some(_) => (),
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
    let dex_selector: i32 = 0;
    let mut q = lp::LP_quoteinfo::default();
    let mut retval: i32 = -1i32;
    let method = json["method"].as_str();
    let ordermatch_ctx = unwrap!(OrdermatchContext::from_ctx(&ctx));
    match method {
        Some("reserved") | Some("connected") | Some("request") | Some("connect") => {
            log!([json]);
            if lp::LP_quoteparse(&mut q, c_json.0) < 0 {
                printf(
                    b"ERROR parsing.(%s)\n\x00" as *const u8 as *const libc::c_char,
                    lp::jprint(c_json.0, 0),
                );
                return 1i32;
            } else if q.satoshis < q.txfee {
                return 1i32;
            } else {
                lp::LP_requestinit(
                    &mut q.R,
                    q.srchash,
                    q.desthash,
                    q.srccoin.as_mut_ptr(),
                    q.satoshis.wrapping_sub(q.txfee),
                    q.destcoin.as_mut_ptr(),
                    q.destsatoshis.wrapping_sub(q.desttxfee),
                    q.timestamp,
                    q.quotetime,
                    dex_selector,
                    q.fill as i32,
                    q.gtc as i32,
                );
                // eat expired packets, some old timestamps floating about?
                if q.uuidstr[0usize] == 0 || q.timestamp > 0 && now_ms() / 1000 > q.timestamp.wrapping_add(30 * 20) as u64 {
                    printf(
                        b"uuid.%s aliceid.%llu is expired by %d\n\x00" as *const u8
                            as *const libc::c_char,
                        q.uuidstr.as_mut_ptr().offset(32isize),
                        q.aliceid as libc::c_longlong,
                        (now_ms() / 1000).wrapping_sub(q.timestamp.wrapping_add(60) as u64));
                    log!("Json " [json]);
                    return 1i32;
                } else {
                    let uuid_str = c2s!(q.uuidstr);
                    let uuid: Uuid = match uuid_str.parse() {
                        Ok(u) => u,
                        Err(e) => {
                            log!("Error " (e) " parsing uuid " (uuid_str));
                            return 1;
                        }
                    };
                    lp::LP_tradecommand_log(c_json.0);
                    //jdouble(argjson,"price");
                    //printf("%s\n",jprint(argjson,0));
                    retval = 1i32;
                    if method == Some("reserved") || method == Some("connected") {
                        let mut taker_matches = unwrap!(ordermatch_ctx.taker_matches.lock());
                        let my_match = match taker_matches.entry(uuid) {
                            Entry::Vacant(_) => {
                                log!("Our node doesn't have the order with uuid "(uuid));
                                return 1;
                            },
                            Entry::Occupied(entry) => entry.into_mut()
                        };
                        if method == Some("reserved") {
                            if my_match.request.srchash != lp::bits256::default() && my_match.request.srchash != q.srchash {
                                log!("got reserved response from different node "(hex::encode(q.srchash.bytes)));
                                return retval;
                            }
                            my_match.reserved = Some(q);
                            // alice
                            if lp::G.LP_mypub25519 == q.desthash && lp::G.LP_mypub25519 != q.srchash {
                                let mut connect_q = my_match.request.clone();
                                connect_q.srchash = q.srchash;
                                my_match.request.srchash = q.srchash;
                                lp_reserved(&mut connect_q, &ctx); // send LP_CONNECT
                                my_match.connect = Some(connect_q);
                            }
                        } else if method == Some("connected") {
                            // alice
                            if lp::G.LP_mypub25519 == q.desthash && lp::G.LP_mypub25519 != q.srchash {
                                lp_connected_alice(
                                    &ctx,
                                    &mut my_match.request,
                                );
                                // AG: Bob's p2p ID (`LP_mypub25519`) is in `json["srchash"]`.
                                log!("CONNECTED.(" (json) ")");
                            }
                        }
                    }
                    let coin = unwrap!(lp_coinfind(&ctx, c2s!(q.srccoin)));
                    if coin.is_none() {
                        //printf("%s is not active\n",Q.srccoin);
                        return retval;
                    } else {
                        // bob
                        if method == Some("request") {
                            if let Some(qp) = lp_trades_gotrequest(&ctx, &q) {
                                let maker_match = MakerOrderMatch {
                                    request: q,
                                    reserved: qp,
                                    connect: None,
                                    connected: None,
                                };
                                let mut maker_matches = unwrap!(ordermatch_ctx.maker_matches.lock());
                                maker_matches.insert(uuid, maker_match);
                            }
                        } else if method == Some("connect") {
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
                        }
                        return retval;
                    }
                }
            }
        },
        _ => return retval
    };
}

#[derive(Deserialize, Debug)]
pub struct AutoBuyInput {
    base: String,
    rel: String,
    price: BigDecimal,
    #[serde(rename="relvolume")]
    #[serde(default)]
    rel_volume: BigDecimal,
    #[serde(rename="basevolume")]
    #[serde(default)]
    base_volume: BigDecimal,
    timeout: Option<u32>,
    /// Not used. Deprecated.
    duration: Option<u32>,
    // TODO: remove this field on API refactoring, method should be separated from params
    method: String,
    gui: Option<String>,
    #[serde(rename="destpubkey")]
    dest_pub_key: Option<String>
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
    Box::new(rel_coin.check_i_have_enough_to_trade(input.rel_volume.to_f64().unwrap(), false).and_then(move |_|
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
    Box::new(rel_coin.check_i_have_enough_to_trade(input.base_volume.to_f64().unwrap(), false).and_then(move |_|
        base_coin.can_i_spend_other_payment().and_then(move |_|
            rpc_response(200, try_h!(lp_auto_buy(&ctx, input)))
        )
    ))
}

pub struct TakerOrderMatch {
    request: lp::LP_quoteinfo,
    reserved: Option<lp::LP_quoteinfo>,
    connect: Option<lp::LP_quoteinfo>,
    connected: Option<lp::LP_quoteinfo>,
}

pub struct MakerOrderMatch {
    request: lp::LP_quoteinfo,
    reserved: lp::LP_quoteinfo,
    connect: Option<lp::LP_quoteinfo>,
    connected: Option<lp::LP_quoteinfo>,
}

pub fn lp_auto_buy(ctx: &MmArc, input: AutoBuyInput) -> Result<String, String> {
    if input.price < SMALLVAL.into() {
        return ERR!("Price is too low, minimum is {}", SMALLVAL);
    }

    let (base, volume, price) = match Some(input.method.as_ref()) {
        Some("buy") => {
            if input.rel_volume <= 0.into() {
                return ERR!("Volume must be greater than 0");
            }
            (try_s!(lp_coinfind(&ctx, &input.base)), input.rel_volume, input.price)
        },
        Some("sell") => {
            if input.base_volume <= 0.into() {
                return ERR!("Volume must be greater than 0");
            }
            (try_s!(lp_coinfind(&ctx, &input.rel)), input.base_volume, 1. / input.price)
        },
        _ => return ERR!("Auto buy must be called only from buy/sell RPC methods")
    };
    let base = match base {Some(c) => c, None => return ERR!("Base coin is not found or inactive")};
    let base_ii = base.iguana_info();

    unsafe {
        let mut tx_fee : u64 = 0;
        let mut dest_tx_fee : u64 = 0;
        let base_str = try_s!(CString::new(input.base.clone()));
        let rel_str = try_s!(CString::new(input.rel.clone()));

        lp::LP_txfees(
            &mut tx_fee as *mut u64,
            &mut dest_tx_fee as *mut u64,
            base_str.as_ptr() as *mut c_char,
            rel_str.as_ptr() as *mut c_char,
        );
        if dest_tx_fee != 0 && dest_tx_fee < 10000 {
            dest_tx_fee = 10000;
        }

        if price <= BigDecimal::default() {
            return ERR!("Resulting price is <= 0");
        }
        if lp::LP_priceinfofind(base_str.as_ptr() as *mut c_char) == null_mut() {
            return ERR!("No price info found for base coin {}", input.base);
        }
        if lp::LP_priceinfofind(rel_str.as_ptr() as *mut c_char) == null_mut() {
            return ERR!("No price info found for rel coin {}", input.rel);
        }

        let dest_satoshis = (BigDecimal::from(SATOSHIS) * volume.clone()).to_u64().unwrap();
        let mut b = lp::LP_utxoinfo::default();

        let best_satoshis = lp_base_satoshis(sat_to_f(dest_satoshis), price.to_f64().unwrap(), dest_tx_fee);
        strcpy(b.coin.as_ptr() as *mut c_char, base_str.as_ptr());
        let mut q = lp::LP_quoteinfo::default();
        if lp::LP_quoteinfoinit(
            &mut q as *mut lp::LP_quoteinfo,
            &mut b as *mut lp::LP_utxoinfo,
            rel_str.as_ptr() as *mut c_char,
            price.to_f64().unwrap(),
            best_satoshis,
            dest_satoshis,
        ) < 0 {
            return ERR!("cant set ordermatch quote");
        }
        if lp::LP_quotedestinfo(
            &mut q as *mut lp::LP_quoteinfo,
            lp::G.LP_mypub25519,
            (*base_ii).smartaddr.as_mut_ptr(),
        ) < 0 {
            return ERR!("cant set ordermatch quote info");
        }
        q.mpnet = lp::G.mpnet;
        let portfolio_ctx = try_s!(PortfolioContext::from_ctx(&ctx));
        let mut my_taker_orders = try_s!(portfolio_ctx.my_taker_orders.lock());
        my_taker_orders.insert((input.base, input.rel), Order {
            max_base_vol: OrderAmount::Limit(volume.clone()),
            min_base_vol: OrderAmount::Limit(0.into()),
            price: BigDecimal::from(1) / price.clone(),
            created_at: now_ms(),
        });
        lp::LP_mypriceset(rel_str.as_ptr() as *mut c_char, base_str.as_ptr() as *mut c_char, 1. / price.to_f64().unwrap(), volume.to_f64().unwrap());
        drop(my_taker_orders);

        let uuid = Uuid::new_v4();
        let dest_pub_key = lp::bits256::default();
        if let Some(pub_key) = input.dest_pub_key {
            let pub_key_str = try_s!(CString::new(pub_key));
            lp::decode_hex(dest_pub_key.bytes.as_ptr() as *mut u8, 32, pub_key_str.as_ptr() as *mut c_char);
        }
        Ok(try_s!(lp_trade(
            &mut q as *mut lp::LP_quoteinfo,
            price.to_f64().unwrap(),
            0,
            dest_pub_key,
            uuid,
            ctx,
        )))
    }
}
