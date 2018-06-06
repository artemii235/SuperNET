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


//#define uthash_malloc(size) iguana_memalloc(&coin->RThashmem,size,1)
//#define uthash_free(ptr,size)

#include "iguana777.h"
#include "exchanges/bitcoin.h"

int32_t iguana_RTunspentind2txid(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *spentheightp,bits256 *txidp,int32_t *voutp,struct iguana_outpoint outpt)
{
    struct iguana_ramchaindata *rdata=0; struct iguana_bundle *bp=0; struct iguana_unspent *U,*u; struct iguana_txid *T,*t; struct iguana_RTunspent *unspent; struct iguana_RTtxid *parent;
    *voutp = *spentheightp = -1;
    memset(txidp,0,sizeof(*txidp));
    if ( outpt.isptr != 0 && (unspent= outpt.ptr) != 0 )
    {
        if ( (parent= unspent->parent) != 0 )
        {
            *txidp = parent->txid;
            *spentheightp = parent->height;
        }
        *voutp = unspent->vout;
        return(0);
    }
    memset(txidp,0,sizeof(*txidp));
    //if ( hdrsi == coin->bundlescount-1 )
    //    rdata = coin->RTramchain.H.data;
    //else if ( (bp= coin->bundles[hdrsi]) != 0 )
    bp = coin->bundles[outpt.hdrsi];
    rdata = bp->ramchain.H.data;
    while ( rdata != 0 && outpt.unspentind > 0 && outpt.unspentind < rdata->numunspents )
    {
        U = RAMCHAIN_PTR(rdata,Uoffset);
        u = &U[outpt.unspentind];
        if ( u->txidind > 0 && u->txidind < rdata->numtxids )
        {
            T = RAMCHAIN_PTR(rdata,Toffset);
            t = &T[u->txidind];
            if ( outpt.unspentind >= t->firstvout )
            {
                *txidp = t->txid;
                *spentheightp = (outpt.hdrsi * coin->chain->bundlesize) + t->bundlei;
                *voutp = outpt.unspentind - t->firstvout;
                return(0);
            }
        }
        else if ( bp == 0 && (bp= coin->bundles[outpt.hdrsi]) != 0 )
            rdata = bp->ramchain.H.data;
        else break;
    }
    return(-1);
}

int32_t iguana_unspentindfind(struct supernet_info *myinfo,struct iguana_info *coin,uint64_t *spentamountp,char *coinaddr,uint8_t *spendscript,int32_t *spendlenp,uint64_t *valuep,int32_t *heightp,bits256 txid,int32_t vout,int32_t lasthdrsi,int32_t mempool)
{
    struct iguana_txid *tp,TX; struct gecko_memtx *memtx; struct iguana_pkhash *P; struct iguana_unspent *U; struct iguana_bundle *bp; struct iguana_ramchaindata *rdata; uint64_t RTspend,value; struct iguana_outpoint spentpt; int32_t firstslot,pkind,hdrsi,firstvout,spentheight,flag=0,unspentind = 0;
    //portable_mutex_lock(&coin->RTmutex);
    if ( valuep != 0 )
        *valuep = 0;
    *spentamountp = 0;
    if ( coinaddr != 0 )
        coinaddr[0] = 0;
    if ( coin->fastfind != 0 && (firstvout= iguana_txidfastfind(coin,heightp,txid,lasthdrsi)) > 0 )
        unspentind = (firstvout + vout);
    else if ( (tp= iguana_txidfind(coin,heightp,&TX,txid,lasthdrsi)) != 0 )
        unspentind = (tp->firstvout + vout);
    if ( coinaddr != 0 && unspentind > 0 && (hdrsi= *heightp/coin->chain->bundlesize) >= 0 && hdrsi < coin->bundlescount && (bp= coin->bundles[hdrsi]) != 0 && (rdata= bp->ramchain.H.data) != 0 && unspentind < rdata->numunspents )
    {
        if ( time(NULL) > bp->lastprefetch+777 )
        {
            //fprintf(stderr,"pf.[%d] ",bp->hdrsi);
            iguana_ramchain_prefetch(coin,&bp->ramchain,0);
            bp->lastprefetch = (uint32_t)time(NULL);
        }
        U = RAMCHAIN_PTR(rdata,Uoffset);
        P = RAMCHAIN_PTR(rdata,Poffset);
        pkind = U[unspentind].pkind;
        if ( pkind > 0 && pkind < rdata->numpkinds )
        {
            RTspend = 0;
            flag++;
            memset(&spentpt,0,sizeof(spentpt));
            spentpt.hdrsi = bp->hdrsi;
            spentpt.unspentind = unspentind;
            bitcoin_address(coinaddr,iguana_addrtype(coin,U[unspentind].type),P[pkind].rmd160,sizeof(P[pkind].rmd160));
            if ( iguana_markedunspents_find(coin,&firstslot,txid,vout) < 0 && iguana_RTspentflag(myinfo,coin,&RTspend,&spentheight,&bp->ramchain,spentpt,0,1,coin->longestchain,U[unspentind].value) == 0 ) //bp == coin->current ? &coin->RTramchain :
            {
                if ( valuep != 0 )
                    *valuep = U[unspentind].value;
                if ( spendscript != 0 && spendlenp != 0 )
                    *spendlenp = iguana_voutscript(coin,bp,spendscript,0,&U[unspentind],&P[pkind],1);
            } else *spentamountp = RTspend;
        }
    }
    if ( flag == 0 && mempool != 0 )
    {
        if ( (memtx= gecko_unspentfind(0,coin,txid)) != 0 && vout < memtx->numoutputs )
        {
            memcpy(&value,gecko_valueptr(memtx,vout),sizeof(value));
            if ( value > 0 )
            {
                *valuep = value;
                if ( spendlenp != 0 )
                {
                    *spendlenp = 1;
                    spendscript = 0;
                    printf("mempool unspentind doesnt support scriptlenp yet\n");
                }
            }
        }
    }
    //portable_mutex_unlock(&coin->RTmutex);
    return(unspentind);
}

char *iguana_RTinputaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,struct iguana_outpoint *spentp,cJSON *vinobj)
{
    bits256 txid; int32_t vout,checkind,height,n; cJSON *txoutjson,*array; char *retstr,_coinaddr[64];
    memset(spentp,0,sizeof(*spentp));
    if ( coinaddr == 0 )
        coinaddr = _coinaddr;
    spentp->hdrsi = -1;
    //printf("%s RTinputaddress.(%s).%d %d\n",coin->symbol,jprint(vinobj,0),coin->FULLNODE,coin->notarychain);
    if ( jobj(vinobj,"txid") != 0 && jobj(vinobj,"vout") != 0 )
    {
        txid = jbits256(vinobj,"txid");
        vout = jint(vinobj,"vout");
        if ( coin->FULLNODE == 0 && coin->notarychain >= 0 )
        {
            if ( (retstr= _dex_gettxout(myinfo,coin->symbol,txid,vout)) != 0 )
            {
                //printf("dexgetO.(%s)\n",retstr);
                if ( (txoutjson= cJSON_Parse(retstr)) != 0 )
                {
                    if ( (array= jarray(&n,txoutjson,"addresses")) != 0 )
                        safecopy(coinaddr,jstri(array,0),64);
                    spentp->value = jdouble(txoutjson,"value") * SATOSHIDEN;
                    free_json(txoutjson);
                }
                free(retstr);
                return(coinaddr);
            } else printf("dexgettxout null retstr\n");
            return(0);
        }
        height = jint(vinobj,"height");
        checkind = jint(vinobj,"checkind");
        if ( (height != 0 && checkind != 0) || iguana_RTunspentindfind(myinfo,coin,spentp,coinaddr,0,0,0,&height,txid,vout,coin->bundlescount-1,0) == 0 )
        {
            return(coinaddr);
        }
        else
        {
            char str[65];
            printf("error finding (%s/%d) height.%d checkind.%d\n",bits256_str(str,txid),vout,height,checkind);
        }
    }
    return(0);
}

cJSON *ramchain_unspentjson(struct iguana_unspent *up,uint32_t unspentind)
{
    cJSON *item = cJSON_CreateObject();
    jaddnum(item,"hdrsi",up->hdrsi);
    jaddnum(item,"pkind",up->pkind);
    jaddnum(item,"unspentind",unspentind);
    jaddnum(item,"prevunspentind",up->prevunspentind);
    jadd64bits(item,"satoshis",up->value);
    jaddnum(item,"txidind",up->txidind);
    jaddnum(item,"vout",up->vout);
    jaddnum(item,"type",up->type);
    jaddnum(item,"fileid",up->fileid);
    jaddnum(item,"scriptpos",up->scriptpos);
    jaddnum(item,"scriptlen",up->scriptlen);
    return(item);
}

cJSON *ramchain_spentjson(struct supernet_info *myinfo,struct iguana_info *coin,int32_t spentheight,bits256 txid,int32_t vout,uint64_t uvalue)
{
    char coinaddr[64]; bits256 hash2,*X; struct iguana_txid T,*tx,*spentT,*spent_tx; struct iguana_bundle *bp; int32_t j,i,ind; struct iguana_block *block; uint64_t value,total = 0; struct iguana_unspent *U,*u; struct iguana_pkhash *P; struct iguana_spend *S,*s; struct iguana_ramchaindata *rdata; cJSON *addrs,*item,*voutobj;
    item = cJSON_CreateObject();
    hash2 = iguana_blockhash(coin,spentheight);
    if ( (block= iguana_blockfind("spent",coin,hash2)) != 0 && (bp= coin->bundles[spentheight/coin->chain->bundlesize]) != 0 && (rdata= bp->ramchain.H.data) != 0 )
    {
        X = RAMCHAIN_PTR(rdata,Xoffset);
        S = RAMCHAIN_PTR(rdata,Soffset);
        U = RAMCHAIN_PTR(rdata,Uoffset);
        P = RAMCHAIN_PTR(rdata,Poffset);
        spentT = RAMCHAIN_PTR(rdata,Toffset);
        for (i=0; i<block->RO.txn_count; i++)
        {
            if ( (tx= iguana_blocktx(coin,&T,block,i)) != 0 )
            {
                s = &S[tx->firstvin];
                for (j=0; j<tx->numvins; j++,s++)
                {
                    if ( s->prevout == vout )
                    {
                        if ( s->external != 0 )
                        {
                            ind = s->spendtxidind & 0xfffffff;
                            if ( bits256_cmp(X[ind],txid) != 0 )
                                continue;
                        }
                        else
                        {
                            spent_tx = &spentT[s->spendtxidind];
                            if ( bits256_cmp(spent_tx->txid,txid) != 0 )
                                continue;
                        }
                        jaddbits256(item,"spentfrom",tx->txid);
                        jaddnum(item,"vin",j);
                        jaddnum(item,"timestamp",tx->timestamp);
                        u = &U[tx->firstvout];
                        addrs = cJSON_CreateArray();
                        for (j=0; j<tx->numvouts; j++,u++)
                        {
                            voutobj = cJSON_CreateObject();
                            bitcoin_address(coinaddr,iguana_addrtype(coin,u->type),P[u->pkind].rmd160,sizeof(P[u->pkind].rmd160));
                            jaddnum(voutobj,coinaddr,dstr(u->value));
                            jaddi(addrs,voutobj);
                            total += u->value;
                        }
                        jadd(item,"vouts",addrs);
                        jaddnum(item,"total",dstr(total));
                        jaddnum(item,"ratio",dstr(uvalue) / dstr(total+coin->txfee));
                        return(item);
                    }
                }
            }
        }
    }
    else
    {
        struct iguana_RTtxid *RTptr,*tmp; struct iguana_RTspend *spend;
        HASH_ITER(hh,coin->RTdataset,RTptr,tmp)
        {
            for (i=0; i<RTptr->numvins; i++)
            {
                if ( (spend= RTptr->spends[i]) != 0 )
                {
                    if ( bits256_cmp(spend->prev_hash,txid) == 0 && spend->prev_vout == vout )
                    {
                        value = iguana_txidamount(myinfo,coin,coinaddr,txid,vout);
                        jaddnum(item,"total",dstr(value));
                        jaddbits256(item,"spentfrom",RTptr->txid);
                        jaddnum(item,"vin",i);
                        addrs = cJSON_CreateArray();
                        voutobj = cJSON_CreateObject();
                        jaddnum(voutobj,coinaddr,dstr(value));
                        jaddi(addrs,voutobj);
                        jadd(item,"vouts",addrs);
                        jaddnum(item,"timestamp",RTptr->timestamp);
                        //printf("Found MATCH! (%s %.8f)\n",coinaddr,dstr(value));
                        return(item);
                    }
                }
            }
        }
    }
    jaddstr(item,"error","couldnt find spent info");
    return(item);
}

cJSON *iguana_RTunspentjson(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_outpoint outpt,bits256 txid,int32_t vout,uint64_t value,struct iguana_unspent *up,uint8_t rmd160[20],char *coinaddr,uint8_t *pubkey33,int32_t spentheight,char *remoteaddr)
{
    /*{
     "txid" : "d54994ece1d11b19785c7248868696250ab195605b469632b7bd68130e880c9a",
     "vout" : 1,
     "address" : "mgnucj8nYqdrPFh2JfZSB1NmUThUGnmsqe",
     "account" : "test label",
     "scriptPubKey" : "76a9140dfc8bafc8419853b34d5e072ad37d1a5159f58488ac",
     "amount" : 0.00010000,
     "confirmations" : 6210,
     "spendable" : true
     },*/
    struct iguana_waccount *wacct; struct iguana_waddress *waddr; int32_t height; char scriptstr[8192],asmstr[sizeof(scriptstr)+1024]; cJSON *item; uint32_t checkind; struct iguana_RTunspent *unspent; struct iguana_block *block;
    item = cJSON_CreateObject();
    jaddbits256(item,"txid",txid);
    jaddnum(item,"vout",vout);
    jaddstr(item,"address",coinaddr);
    if ( outpt.isptr != 0 && (unspent= outpt.ptr) != 0 )
    {
        if ( unspent->scriptlen > 0 )
        {
            init_hexbytes_noT(scriptstr,unspent->script,unspent->scriptlen);
            jaddstr(item,"scriptPubKey",scriptstr);
        }
    }
    else
    {
        if ( iguana_scriptget(coin,scriptstr,asmstr,sizeof(scriptstr),outpt.hdrsi,outpt.unspentind,txid,vout,rmd160,up!=0?up->type:2,pubkey33) != 0 )
            jaddstr(item,"scriptPubKey",scriptstr);
    }
    jaddnum(item,"amount",dstr(value));
    if ( strcmp(coin->symbol,"KMD") == 0 )
        jaddnum(item,"interest",dstr(iguana_interest(myinfo,coin,txid,vout,value)));
    //jaddnum(item,"timestamp",T[up->txidind].timestamp);
    if ( iguana_RTunspentindfind(myinfo,coin,&outpt,0,0,0,0,&height,txid,vout,coin->bundlescount-1,0) == 0 )
    {
        checkind = outpt.unspentind;
        if ( (block= iguana_blockfind("unspentjson",coin,iguana_blockhash(coin,height))) != 0 && block->RO.timestamp != 0 )
            jaddnum(item,"timestamp",block->RO.timestamp);
        jaddnum(item,"height",height);
        jaddnum(item,"confirmations",coin->blocks.hwmchain.height - height + 1);
        jaddnum(item,"checkind",checkind);
    }
    if ( remoteaddr == 0 || remoteaddr[0] == 0 )
    {
        if ( (waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) != 0 )
        {
            jaddstr(item,"account",wacct->account);
            if ( spentheight == 0 )
                jadd(item,"spendable",jtrue());
            else jadd(item,"spendable",jfalse());
        } else jadd(item,"spendable",jfalse());
    }
    if ( spentheight > 0 )
    {
        if ( up != 0 )
            jadd(item,"spent",ramchain_unspentjson(up,outpt.unspentind));
        jaddnum(item,"spentheight",spentheight);
        jadd(item,"dest",ramchain_spentjson(myinfo,coin,spentheight,txid,vout,value));
    }
    else if ( up != 0 )
        jadd(item,"unspent",ramchain_unspentjson(up,outpt.unspentind));
    return(item);
}

struct iguana_pkhash *iguana_pkhashfind(struct iguana_info *coin,struct iguana_ramchain **ramchainp,uint64_t *depositsp,struct iguana_outpoint *lastptp,struct iguana_pkhash *p,uint8_t rmd160[20],int32_t firsti,int32_t endi)
{
    uint8_t *PKbits; struct iguana_pkhash *P; uint32_t pkind,numpkinds,i; struct iguana_bundle *bp; struct iguana_ramchain *ramchain; struct iguana_ramchaindata *rdata; struct iguana_account *ACCTS; struct iguana_RTaddr *RTaddr;
    *depositsp = 0;
    *ramchainp = 0;
    memset(lastptp,0,sizeof(*lastptp));
    if ( firsti == coin->bundlescount && endi == firsti )
    {
        if ( (RTaddr= iguana_RTaddrfind(coin,rmd160,0)) != 0 )
        {
            *depositsp = RTaddr->credits;
            if ( (lastptp->ptr= RTaddr->lastunspent) != 0 )
                lastptp->isptr = 1;
            memcpy(p->rmd160,rmd160,sizeof(p->rmd160));
            p->pkind = 0;
            return(p);
        } else return(0);
    }
    for (i=firsti; i<coin->bundlescount&&i<=endi; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            if ( (0) && coin->RTramchain_busy != 0 )
            {
                printf("iguana_pkhashfind: unexpected access when RTramchain_busy\n");
                return(0);
            }
            ramchain = &bp->ramchain;//(bp != coin->current) ? &bp->ramchain : &coin->RTramchain;
            // prevent remote query access before RTmode
            if ( (rdata= ramchain->H.data) != 0 && time(NULL) > bp->emitfinish+10 )
            {
                numpkinds = rdata->numpkinds;
                PKbits = RAMCHAIN_PTR(rdata,PKoffset);
                P = RAMCHAIN_PTR(rdata,Poffset);
                if ( bp == coin->current )
                    ACCTS = ramchain->A;
                else ACCTS = RAMCHAIN_PTR(rdata,Aoffset);
                if ( (pkind= iguana_sparseaddpk(PKbits,rdata->pksparsebits,rdata->numpksparse,rmd160,P,0,ramchain)) > 0 && pkind < numpkinds )
                {
                    *ramchainp = ramchain;
                    *depositsp = ACCTS[pkind].total;
                    lastptp->hdrsi = bp->hdrsi;
                    lastptp->unspentind = ACCTS[pkind].lastunspentind;
                    //printf("[%d] return pkind.%u of %u P.%p %.8f last.%u ACCTS.%p %p\n",i,pkind,numpkinds,P,dstr(*depositsp),*lastunspentindp,ACCTS,ramchain->A);
                    if ( P != 0 )
                        *p = P[pkind];
                    return(p);
                } else if ( pkind != 0 )
                    printf("[%d] not found pkind.%d vs num.%d RT.%d rdata.%p\n",i,pkind,rdata->numpkinds,bp->isRT,rdata);
            }
            else if ( coin->spendvectorsaved > 1 && bp != coin->current && bp->bundleheight < coin->firstRTheight )
            {
                //printf("%s.[%d] skip null rdata isRT.%d [%d]\n",coin->symbol,i,bp->isRT,coin->current!=0?coin->current->hdrsi:-1);
            }
        }
    }
    return(0);
}

int32_t iguana_uheight(struct iguana_info *coin,int32_t bundleheight,struct iguana_txid *T,int32_t numtxids,struct iguana_unspent *up)
{
    if ( up->txidind > 0 && up->txidind < numtxids )
        return(bundleheight + T[up->txidind].bundlei);
    else return(bundleheight);
}

int32_t iguana_outpt_set(struct iguana_info *coin,struct iguana_outpoint *outpt,struct iguana_unspent *u,uint32_t unspentind,int16_t hdrsi,bits256 txid,int32_t vout,uint8_t *rmd160,uint8_t *pubkey33)
{
    char scriptstr[IGUANA_MAXSCRIPTSIZE*2+1],asmstr[16384];
    memset(outpt,0,sizeof(*outpt));
    outpt->txid = txid;
    outpt->vout = vout;
    outpt->hdrsi = hdrsi;
    outpt->isptr = 0;
    outpt->unspentind = unspentind;
    outpt->value = u->value;
    if ( iguana_scriptget(coin,scriptstr,asmstr,sizeof(scriptstr),outpt->hdrsi,outpt->unspentind,outpt->txid,outpt->vout,rmd160,u->type,pubkey33) != 0 )
    {
        //printf("scriptstr.(%s)\n",scriptstr);
        outpt->spendlen = (int32_t)strlen(scriptstr) >> 1;
        if ( outpt->spendlen < sizeof(outpt->spendscript) )
            decode_hex(outpt->spendscript,outpt->spendlen,scriptstr);
        else
        {
            outpt->spendlen = 0;
            printf("error scriptstr.(%s) is too big for %d\n",scriptstr,(int32_t)sizeof(outpt->spendscript));
            return(-1);
        }
    }
    return(0);
}

int32_t iguana_datachain_scan(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t rmd160[20])
{
    uint64_t deposits,crypto777_payment; struct iguana_outpoint lastpt; uint32_t unspentind; int32_t i,j,num,uheight; struct iguana_bundle *bp; struct iguana_ramchain *ramchain; struct iguana_ramchaindata *rdata; struct iguana_pkhash *P,p; struct iguana_unspent *U,*u; struct iguana_txid *T,*tx;
    for (i=num=0; i<coin->bundlescount&&i*coin->chain->bundlesize<coin->firstRTheight; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            ramchain = 0;
            memset(&lastpt,0,sizeof(lastpt));
            if ( iguana_pkhashfind(coin,&ramchain,&deposits,&lastpt,&p,rmd160,i,i) != 0 )
            {
                if ( ramchain != 0 && (rdata= ramchain->H.data) != 0 )
                {
                    unspentind = lastpt.unspentind;
                    U = RAMCHAIN_PTR(rdata,Uoffset);
                    T = RAMCHAIN_PTR(rdata,Toffset);
                    P = RAMCHAIN_PTR(rdata,Poffset);
                    while ( unspentind > 0 )
                    {
                        tx = &T[U[unspentind].txidind];
                        u = &U[tx->firstvout];
                        uheight = iguana_uheight(coin,ramchain->height,T,rdata->numtxids,u);
                        for (crypto777_payment=j=0; j<tx->numvouts; j++,u++)
                        {
                            crypto777_payment = datachain_update(myinfo,0,coin,tx->timestamp,bp,P[u->pkind].rmd160,crypto777_payment,u->type,uheight,(((uint64_t)bp->hdrsi << 32) | unspentind),u->value,u->fileid,u->scriptpos,u->scriptlen,tx->txid,j);
                        }
                        num++;
                        unspentind = U[unspentind].prevunspentind;
                    }
                }
            }
        }
    }
    // do a RT scan here
    return(num);
}

int32_t iguana_RTscanunspents(struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,cJSON *array,uint64_t *spentp,uint64_t *depositsp,struct iguana_outpoint *unspents,int32_t max,uint8_t *rmd160,char *coinaddr,uint8_t *pubkey33,struct iguana_outpoint lastpt,int32_t lastheight)
{
    int32_t spentheight,n = 0; struct iguana_outpoint outpt; bits256 txid; struct iguana_RTtxid *parent; struct iguana_RTunspent *unspent = lastpt.ptr;
    while ( unspent != 0 )
    {
        if ( lastheight <= 0 || unspent->height < lastheight )
        {
            if ( unspent->spend == 0 )
            {
                spentheight = 0;
                memset(&outpt,0,sizeof(outpt));
                memset(&txid,0,sizeof(txid));
                if ( (parent= unspent->parent) != 0 )
                    txid = parent->txid;
                else printf("unspent has no parent?\n");
                outpt.isptr = 1;
                outpt.ptr = unspent;
                outpt.txid = txid;
                outpt.vout = unspent->vout;
                outpt.value = unspent->value;
                outpt.hdrsi = unspent->height / coin->chain->bundlesize;
                if ( (outpt.spendlen= unspent->scriptlen) > 0 && outpt.spendlen < sizeof(outpt.spendscript) )
                    memcpy(outpt.spendscript,unspent->script,outpt.spendlen);
                else
                {
                    printf("spendscript.%d doesnt fit into %d\n",outpt.spendlen,(int32_t)sizeof(outpt.spendscript));
                    outpt.spendlen = 0;
                }
                if ( array != 0 )
                    jaddi(array,iguana_RTunspentjson(myinfo,coin,outpt,txid,unspent->vout,unspent->value,0,rmd160,coinaddr,pubkey33,spentheight,remoteaddr));
                *depositsp += unspent->value;
                if ( unspents != 0 )
                    unspents[n] = outpt;
                n++;
            } else *spentp += unspent->value;
        }
        unspent = unspent->prevunspent;
    }
    return(n);
}

int64_t iguana_RTpkhashbalance(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *array,uint64_t *spentp,struct iguana_outpoint *unspents,int32_t *nump,struct iguana_ramchain *ramchain,struct iguana_pkhash *p,struct iguana_outpoint lastpt,uint8_t rmd160[20],char *coinaddr,uint8_t *pubkey33,int32_t lastheight,int32_t minconf,int32_t maxconf,char *remoteaddr,int32_t includespent)
{
    struct iguana_unspent *U; struct iguana_utxo *U2; int32_t firstslot,vout,spentflag,max,uheight,spentheight=0; uint32_t pkind=0,unspentind; uint64_t spent = 0,checkval,deposits = 0; struct iguana_txid *T; struct iguana_account *A2; struct iguana_outpoint outpt; struct iguana_ramchaindata *rdata = 0; uint64_t RTspend = 0; bits256 txid;
    max = *nump;
    *spentp = *nump = 0;
    if ( (0) && coin->RTramchain_busy != 0 )
    {
        printf("iguana_pkhashbalance: unexpected access when RTramchain_busy\n");
        return(0);
    }
    if ( ramchain == 0 ) // RT search
    {
        if ( lastpt.isptr != 0 )
        {
            *nump = iguana_RTscanunspents(myinfo,coin,remoteaddr,array,spentp,&deposits,unspents,max,rmd160,coinaddr,pubkey33,lastpt,lastheight);
        }
        else
        {
            printf("iguana_pkhashbalance: unexpected RT non-ptr lastpt\n");
            coin->RTreset_needed = 1;
        }
        return(deposits - *spentp);
    }
    if ( ramchain->Uextras == 0 || (rdata= ramchain->H.data) == 0 )
    {
        if ( ramchain->height < (coin->bundlescount-1)*coin->chain->bundlesize )
        {
            printf("iguana_pkhashbalance.[%d] %d: unexpected null spents.%p or rdata.%p\n",ramchain->height,(coin->bundlescount-1)*coin->chain->bundlesize,ramchain->Uextras,rdata);
        }
        iguana_volatilesmap(myinfo,coin,ramchain);
        if ( ramchain->Uextras == 0 || (rdata= ramchain->H.data) == 0 )
        {
            printf("couldnt map ramchain %d\n",ramchain->height);
            return(0);
        }
    }
    unspentind = lastpt.unspentind;
    U = RAMCHAIN_PTR(rdata,Uoffset);
    T = RAMCHAIN_PTR(rdata,Toffset);
    RTspend = 0;
    if ( lastheight == 0 )
        lastheight = IGUANA_MAXHEIGHT;
    while ( unspentind > 0 )
    {
        uheight = iguana_uheight(coin,ramchain->height,T,rdata->numtxids,&U[unspentind]);
        if ( lastheight <= 0 || uheight < lastheight )
        {
            //printf("u%u ",unspentind);
            deposits += U[unspentind].value;
            txid = T[U[unspentind].txidind].txid;
            vout = unspentind - T[U[unspentind].txidind].firstvout;
            iguana_outpt_set(coin,&outpt,&U[unspentind],unspentind,lastpt.hdrsi,txid,vout,p->rmd160,pubkey33);
            RTspend = 0;
            if ( iguana_markedunspents_find(coin,&firstslot,txid,vout) < 0 && iguana_RTspentflag(myinfo,coin,&RTspend,&spentheight,ramchain,outpt,lastheight,minconf,maxconf,U[unspentind].value) == 0 )
            {
                if ( *nump < max && unspents != 0 )
                    unspents[*nump] = outpt;
                //printf("+%.8f ",dstr(U[unspentind].value));
                (*nump)++;
                spentflag = 0;
            }
            else
            {
                //printf("-%.8f ",dstr(U[unspentind].value));
                spent += U[unspentind].value;
                spentflag = 1;
            }
            if ( array != 0 && (spentflag == 0 || includespent != 0) )
                jaddi(array,iguana_RTunspentjson(myinfo,coin,outpt,T[U[unspentind].txidind].txid,U[unspentind].vout,U[unspentind].value,&U[unspentind],rmd160,coinaddr,pubkey33,spentheight,remoteaddr));
            if ( p->pkind != U[unspentind].pkind )
                printf("warning: [%d] p->pkind.%u vs U->pkind.%u for u%d\n",lastpt.hdrsi,p->pkind,U[unspentind].pkind,unspentind);
        } // else printf("skip uheight.%d lastheight.%d\n",uheight,lastheight);
        pkind = p->pkind;
        unspentind = U[unspentind].prevunspentind;
    }
    if ( lastheight > 0 && (A2= ramchain->A2) != 0 && (U2= ramchain->Uextras) != 0 )
    {
        //S = RAMCHAIN_PTR(rdata,Soffset);
        unspentind = A2[pkind].lastunspentind;
        checkval = 0;
        while ( unspentind > 0 )
        {
            uheight = iguana_uheight(coin,ramchain->height,T,rdata->numtxids,&U[unspentind]);
            if ( uheight < lastheight )
            {
                checkval += U[unspentind].value;
                //printf("u%u %.8f spentflag.%d prev.%u fromheight.%d\n",unspentind,dstr(U[unspentind].value),U2[unspentind].spentflag,U2[unspentind].prevunspentind,U2[unspentind].fromheight);
            }
            unspentind = U2[unspentind].prevunspentind;
        }
        if ( (0) && llabs((int64_t)spent - (int64_t)checkval - (int64_t)RTspend) > SMALLVAL )
            printf("spend %s: [%d] deposits %.8f spent %.8f check %.8f (%.8f) vs A2[%u] %.8f\n",lastheight==IGUANA_MAXHEIGHT?"checkerr":"",lastpt.hdrsi,dstr(deposits),dstr(spent),dstr(checkval)+dstr(RTspend),dstr(*spentp),pkind,dstr(A2[pkind].total));
    }
    (*spentp) = spent;
    //printf("[%d] (%s) spent %.8f, RTspent %.8f deposits %.8f\n",ramchain->height/coin->chain->bundlesize,coinaddr,dstr(spent),dstr(RTspend),dstr(deposits));
    return(deposits - spent);
}

// jl777: todo support notarychain iterate listunspent
int32_t iguana_RTpkhasharray(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *array,int32_t minconf,int32_t maxconf,uint64_t *totalp,struct iguana_pkhash *P,int32_t max,uint8_t rmd160[20],char *coinaddr,uint8_t *pubkey33,int32_t lastheight,struct iguana_outpoint *unspents,int32_t *numunspentsp,int32_t maxunspents,char *remoteaddr,int32_t includespent)
{
    int32_t i,n,m,numunspents; uint64_t spent,deposits,netbalance,total; struct iguana_outpoint lastpt; struct iguana_pkhash *p,_p; struct iguana_ramchain *ramchain; struct iguana_bundle *bp;
    if ( coin->RTheight == 0 )
        return(-1);
    if ( (0) && coin->RTramchain_busy != 0 )
    {
        printf("iguana_pkhasharray: unexpected access when RTramchain_busy\n");
        return(-1);
    }
    numunspents = numunspentsp != 0 ? *numunspentsp : 0;
    if ( lastheight == 0 )
        lastheight = IGUANA_MAXHEIGHT;
    if ( max > coin->bundlescount )
        max = coin->bundlescount;
    //printf("minconf.%d maxconf.%d max.%d addr.%s last.%d maxunspents.%d\n",minconf,maxconf,max,coinaddr,lastheight,maxunspents);
    for (total=n=i=0; i<max+(lastheight>=coin->firstRTheight); i++)
    {
        bp = 0;
        if ( i != max && (bp= coin->bundles[i]) == 0 )
            continue;
        if ( bp != 0 )
        {
            if ( lastheight > 0 && bp->bundleheight > lastheight )
            {
                //printf("lastheight.%d less than %d\n",lastheight,bp->bundleheight+bp->n);
                break;
            }
            if ( (coin->blocks.hwmchain.height - (bp->bundleheight + bp->n - 1)) > maxconf )
            {
                //printf("%d more than minconf.%d\n",(coin->blocks.hwmchain.height - (bp->bundleheight + bp->n - 1)),maxconf);
                continue;
            }
            if ( (coin->blocks.hwmchain.height - bp->bundleheight) < minconf )
            {
                //printf("%d less than minconf.%d\n",(coin->blocks.hwmchain.height - bp->bundleheight),minconf);
                break;
            }
        }
        if ( iguana_pkhashfind(coin,&ramchain,&deposits,&lastpt,P != 0 ? &P[n] : &_p,rmd160,i,i) != 0 )
        {
            m = maxunspents;
            p = (P == 0) ? &_p : &P[n];
            if ( (netbalance= iguana_RTpkhashbalance(myinfo,coin,array,&spent,unspents != 0 ? &unspents[numunspents] : 0,&m,ramchain,p,lastpt,rmd160,coinaddr,pubkey33,lastheight,minconf,maxconf,remoteaddr,includespent)) != deposits-spent && lastheight == IGUANA_MAXHEIGHT && minconf == 1 && maxconf > coin->blocks.hwmchain.height )
            {
                printf("%s pkhash balance mismatch from m.%d check %.8f vs %.8f spent %.8f [%.8f]\n",coin->symbol,m,dstr(netbalance),dstr(deposits),dstr(spent),dstr(deposits)-dstr(spent));
            }
            else
            {
                //printf("%s pkhash balance.[%d] from m.%d check %.8f vs %.8f spent %.8f [%.8f]\n",coinaddr,i,m,dstr(netbalance),dstr(deposits),dstr(spent),dstr(deposits)-dstr(spent));
                total += netbalance;
                n++;
            }
            if ( maxunspents > 0 )
            {
                maxunspents -= m;
                if ( maxunspents <= 0 )
                    break;
            }
            numunspents += m;
            //printf("%d: balance %.8f, lastunspent.%u m.%d num.%d max.%d\n",i,dstr(total),lastunspentind,m,numunspents,maxunspents);
        }
    }
    if ( numunspentsp != 0 )
        *numunspentsp = numunspents;
    //printf("numunspents.%d max.%d\n",numunspents,maxunspents);
    *totalp += total;
    return(n);
}

uint64_t iguana_RTunspents(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *array,int32_t minconf,int32_t maxconf,uint8_t *rmdarray,int32_t numrmds,int32_t lastheight,struct iguana_outpoint *unspents,int32_t *numunspentsp,char *remoteaddr,int32_t includespent)
{
    uint64_t total=0,sum=0; struct iguana_pkhash *P; uint8_t *addrtypes,*pubkeys; int32_t i,j,numunspents,maxunspents,flag = 0; char coinaddr[64];
    //portable_mutex_lock(&coin->RTmutex);
    while ( (0) && coin->RTramchain_busy != 0 )
    {
        fprintf(stderr,"iguana_pkhasharray: %s unexpected access when RTramchain_busy\n",coin->symbol);
        sleep(1);
    }
    numunspents = 0;
    maxunspents = *numunspentsp;
    if ( rmdarray == 0 )
        rmdarray = iguana_walletrmds(myinfo,coin,&numrmds), flag++;
    if ( numrmds > 0 && rmdarray != 0 )
    {
        addrtypes = &rmdarray[numrmds * 20], pubkeys = &rmdarray[numrmds * 21];
        P = calloc(coin->bundlescount,sizeof(*P));
        for (i=0; i<numrmds; i++)
        {
            for (j=0; j<20; j++)
                if ( rmdarray[i*20 + j] != 0 )
                    break;
            if ( j == 20 )
                continue;
            bitcoin_address(coinaddr,addrtypes[i],&rmdarray[i * 20],20);
            *numunspentsp = 0;
            iguana_RTpkhasharray(myinfo,coin,array,minconf,maxconf,&total,P,coin->bundlescount,&rmdarray[i * 20],coinaddr,&pubkeys[33*i],lastheight,unspents != 0 ? &unspents[numunspents] : 0,numunspentsp,maxunspents,remoteaddr,includespent);
            //printf("iguana_unspents: i.%d of %d: %s %.8f numunspents.%d\n",i,numrmds,coinaddr,dstr(total),*numunspentsp);
            maxunspents -= *numunspentsp;
            numunspents += *numunspentsp;
            sum += total;
        }
        //printf("sum %.8f\n",dstr(sum));
        free(P);
    }
    *numunspentsp = numunspents;
    if ( flag != 0 && rmdarray != 0 )
        free(rmdarray);
    //portable_mutex_unlock(&coin->RTmutex);
    return(sum);
}

uint8_t *iguana_rmdarray(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *numrmdsp,cJSON *array,int32_t firsti)
{
    int32_t i,n,flag=0,k,j=0; char *coinaddr,rmdstr[41]; uint8_t addrtype,*addrtypes,*rmdarray = 0;
    *numrmdsp = 0;
    if ( array == 0 || cJSON_GetArraySize(array) == 0 )
        array = iguana_getaddressesbyaccount(myinfo,coin,"*");
    if ( array != 0 && (n= cJSON_GetArraySize(array)) > 0 )
    {
        *numrmdsp = n - firsti;
        rmdarray = calloc(1,(n-firsti) * (21 + 33));
        addrtypes = &rmdarray[(n-firsti) * 20];
        for (i=firsti; i<n; i++)
        {
            if ( (coinaddr= jstr(jitem(array,i),0)) != 0 )
            {
                //printf("(%s %s) ",coinaddr,rmdstr);
                if ( iguana_addressvalidate(coin,&addrtype,coinaddr) < 0 )
                {
                    printf("i.%d illegal coinaddr.(%s) longest.%d\n",i,coinaddr,coin->longestchain);
                    continue;
                }
                bitcoin_addr2rmd160(&addrtypes[j],&rmdarray[20 * j],coinaddr);
                for (k=0; k<20; k++)
                    if ( rmdarray[20 * j + k] != 0 )
                        break;
                if ( k == 20 )
                    continue;
                init_hexbytes_noT(rmdstr,&rmdarray[20 * j],20);
                j++;
            }
        }
        //printf("rmdarray[%d]\n",n);
    }
    if ( flag != 0 )
        free_json(array);
    return(rmdarray);
}

uint64_t *iguana_PoS_weights(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_pkhash **Ptrp,uint64_t *supplyp,int32_t *numacctsp,int32_t *nonzp,int32_t *errsp,int32_t lastheight)
{
    uint64_t balance,total,supply,*weights=0; uint32_t pkind; int32_t j,numrmds,minconf,neg,numunspents,nonz,num=0; struct iguana_bundle *bp; struct iguana_ramchaindata *rdata; struct iguana_pkhash *refP; uint8_t rmd160[20],*rmdarray; cJSON *array; char coinaddr[64]; //struct iguana_account *A2; struct iguana_utxo *U2;
    *supplyp = 0;
    *numacctsp = *nonzp = 0;
    *errsp = 1;
    (*Ptrp) = 0;
    if ( (bp= coin->bundles[lastheight / coin->chain->bundlesize]) == 0 || bp == coin->current )
        return(0);
    if ( (rdata= bp->ramchain.H.data) == 0 )
        return(0);
    (*Ptrp) = refP = RAMCHAIN_PTR(rdata,Poffset);
    if ( (num= rdata->numpkinds) > 0 )
    {
        weights = calloc(num,sizeof(*weights));
        minconf = coin->blocks.hwmchain.height - lastheight;
        for (pkind=1; pkind<num; pkind++)
        {
            total = 0;
            memcpy(rmd160,refP[pkind].rmd160,sizeof(rmd160));
            for (j=0; j<20; j++)
                if ( rmd160[j] != 0 )
                    break;
            if ( j == 20 )
                continue;
            array = cJSON_CreateArray();
            bitcoin_address(coinaddr,coin->chain->pubtype,rmd160,sizeof(rmd160));
            jaddistr(array,coinaddr);
            //bitcoin_address(coinaddr,coin->chain->p2shtype,rmd160,sizeof(rmd160));
            //jaddistr(array,coinaddr);
            if ( (rmdarray= iguana_rmdarray(myinfo,coin,&numrmds,array,0)) != 0 )
            {
                numunspents = 0;
                balance = iguana_RTunspents(myinfo,coin,0,minconf,(1 << 30),rmdarray,numrmds,lastheight,0,&numunspents,0,0);
                free(rmdarray);
                weights[pkind] += balance;
                if ( weights[pkind] != balance )
                    printf("PKIND.%d %s %.8f += %.8f\n",pkind,coinaddr,dstr(weights[pkind]),dstr(balance));
            }
            free_json(array);
        }
    }
    nonz = neg = 0;
    supply = 0;
    for (pkind=1; pkind<num; pkind++)
        if ( weights[pkind] != 0 )
        {
            nonz++;
            if ( weights[pkind] != 0 )
                neg++, weights[pkind] = 0;
            else supply += weights[pkind];
        }
    *numacctsp = num;
    *errsp = neg;
    *nonzp = nonz;
    *supplyp = supply;
    printf("ht.%d [%d] numaddrs.%d nonz.%d neg.%d supply %.8f\n",lastheight,lastheight/coin->chain->bundlesize,num,nonz,neg,dstr(supply));
    return(weights);
}

bits256 iguana_staker_hash2(bits256 refhash2,uint8_t *refrmd160,uint8_t *rmd160,uint64_t weight)
{
    bits256 hash2;
    vcalc_sha256cat(hash2.bytes,refhash2.bytes,sizeof(refhash2),rmd160,20);
    return(mpz_div64(hash2,weight));
}

int _cmp_hashes(const void *a,const void *b)
{
#define hasha (*(bits256 *)a)
#define hashb (*(bits256 *)b)
    return(bits256_cmp(hasha,hashb));
#undef hasha
#undef hashb
}

int32_t iguana_staker_sort(struct iguana_info *coin,bits256 *hash2p,uint8_t *refrmd160,struct iguana_pkhash *refP,uint64_t *weights,int32_t numweights,bits256 *sortbuf)
{
    int32_t i,j,n = 0; bits256 ind,refhash2 = *hash2p;
    memset(sortbuf,0,sizeof(*sortbuf) * 2 * numweights);
    for (i=0; i<numweights; i++)
    {
        if ( weights[i] > 0 )
        {
            memset(&ind,0,sizeof(ind));
            for (j=0; j<20; j++)
                ind.bytes[j] = refP[i].rmd160[j];
            ind.ulongs[3] = weights[i];
            ind.uints[5] = i;
            sortbuf[n << 1] = iguana_staker_hash2(refhash2,refrmd160,ind.bytes,weights[i]);
            sortbuf[(n << 1) + 1] = ind;
            n++;
        }
    }
    if ( n > 0 )
        qsort(sortbuf,n,sizeof(*sortbuf)*2,_cmp_hashes);
    vcalc_sha256cat(hash2p->bytes,refhash2.bytes,sizeof(refhash2),sortbuf[1].bytes,20);
    memcpy(refrmd160,sortbuf[1].bytes,20);
    {
        char str[65],coinaddr[64];
        bitcoin_address(coinaddr,coin->chain->pubtype,refrmd160,20);
        printf("winner.%s %.8f: %s\n",coinaddr,dstr(sortbuf[1].ulongs[3]),bits256_str(str,sortbuf[0]));
    }
    return((int32_t)sortbuf[1].uints[5]);
}

int32_t iguana_markedunspents_find(struct iguana_info *coin,int32_t *firstslotp,bits256 txid,int32_t vout)
{
    int32_t i;
    *firstslotp = -1;
    if ( bits256_nonz(txid) != 0 && vout >= 0 )
    {
        txid.ushorts[15] = vout; // small chance of collision ok due to small timeframe
        for (i=0; i<sizeof(coin->markedunspents)/sizeof(*coin->markedunspents); i++)
        {
            if ( *firstslotp < 0 && bits256_nonz(coin->markedunspents[i]) == 0 )
                *firstslotp = i;
            if ( bits256_cmp(txid,coin->markedunspents[i]) == 0 )
            {
                //printf("%s.v%d marked in slot.[%d]\n",bits256_str(str,txid),vout,i);
                return(i);
            }
        }
    }
    if ( *firstslotp < 0 )
    {
        for (i=0; i<sizeof(coin->markedunspents)/sizeof(*coin->markedunspents); i++)
            if ( bits256_nonz(coin->markedunspents[i]) == 0 )
            {
                *firstslotp = i;
                break;
            }
    }
    //printf("%s.v%d not marked\n",bits256_str(str,txid),vout);
    if ( *firstslotp < 0 )
        *firstslotp = (rand() % (sizeof(coin->markedunspents)/sizeof(*coin->markedunspents)));
    return(-1);
}

void iguana_unspents_mark(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *vins)
{
    int32_t i,n,firstslot; int16_t vout; cJSON *item; bits256 txid; char str[65],fname[1024];
    if ( (n= cJSON_GetArraySize(vins)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(vins,i);
            txid = jbits256(item,"txid");
            vout = jint(item,"vout");
            if ( bits256_nonz(txid) != 0 && vout >= 0 )
            {
                if ( iguana_markedunspents_find(coin,&firstslot,txid,vout) < 0 )
                {
                    if ( firstslot >= 0 )
                    {
                        printf("slot.[%d] <- %s/v%d\n",firstslot,bits256_str(str,txid),vout);
                        coin->markedunspents[firstslot] = txid;
                        coin->markedunspents[firstslot].ushorts[15] = vout;
                        if ( (0) && coin->utxofp == 0 )
                        {
                            sprintf(fname,"%s/%s/utxo.dat",GLOBAL_DBDIR,coin->symbol), OS_compatible_path(fname);
                            if ( (coin->utxofp= fopen(fname,"rb+")) == 0 )
                                coin->utxofp = fopen(fname,"wb");
                            else fseek(coin->utxofp,0,SEEK_END);
                            if ( coin->utxofp != 0 )
                            {
                                fwrite(txid.bytes,1,sizeof(txid),coin->utxofp);
                                fwrite(&vout,1,sizeof(vout),coin->utxofp);
                                fflush(coin->utxofp);
                            }
                        }
                    }
                } else printf("error firstslot.[%d] <- %s/v%d\n",firstslot,bits256_str(str,txid),vout);
            }
        }
    }
}

void iguana_unspents_markinit(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char *filestr,fname[1024]; FILE *fp; long filesize; bits256 filetxid; cJSON *array,*item; int32_t i,filevout,n,firstslot;
return;
    sprintf(fname,"%s/%s/utxo.dat",GLOBAL_DBDIR,coin->symbol), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"rb")) != 0 )
    {
        while ( fread(&filetxid,1,sizeof(filetxid),fp) == sizeof(filetxid) && fread(&filevout,1,sizeof(filevout),fp) == sizeof(filevout) )
        {
            if ( iguana_markedunspents_find(coin,&firstslot,filetxid,filevout) < 0 )
            {
                if ( firstslot >= 0 )
                {
                    //char str[65]; printf("%s slot.[%d] <- %s/v%d\n",fname,firstslot,bits256_str(str,filetxid),filevout);
                    coin->markedunspents[firstslot] = filetxid;
                    coin->markedunspents[firstslot].ushorts[15] = filevout;
                }
            }
        }
        fclose(fp);
    }
    sprintf(fname,"%s/%s/utxo.json",GLOBAL_DBDIR,coin->symbol), OS_compatible_path(fname);
    if ( (filestr= OS_filestr(&filesize,fname)) != 0 )
    {
        if ( (array= cJSON_Parse(filestr)) != 0 )
        {
            printf("iguana_unspents_markinit.(%s)\n",fname);
            if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    filetxid = jbits256i(item,0);
                    filevout = jinti(item,1);
                    char str[65]; printf("[%d] %s %d\n",i,bits256_str(str,filetxid),filevout);
                    if ( iguana_markedunspents_find(coin,&firstslot,filetxid,filevout) < 0 )
                    {
                        if ( firstslot >= 0 )
                        {
                            //char str[65]; printf("slot.[%d] <- %s/v%d\n",firstslot,bits256_str(str,filetxid),filevout);
                            coin->markedunspents[firstslot] = filetxid;
                            coin->markedunspents[firstslot].ushorts[15] = filevout;
                        }
                    }
                }
            }
            free_json(array);
        } else printf("parse error.(%s)\n",filestr);
        free(filestr);
    } else printf("couldnt open.(%s)\n",fname);
}

int32_t iguana_RTunspent_check(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_outpoint outpt)
{
    int32_t firstslot;
    if ( iguana_markedunspents_find(coin,&firstslot,outpt.txid,outpt.vout) < 0 )
        return(0);
    return(-1);
}

int32_t iguana_RTaddr_unspents(struct supernet_info *myinfo,struct iguana_info *coin,uint64_t *sump,struct iguana_outpoint *unspents,int32_t max,char *coinaddr,char *remoteaddr,int32_t lastheight,int32_t includespent)
{
    int32_t n,j,k,numunspents,minconf = 0; uint64_t total; uint8_t rmd160[20],pubkey[65],addrtype;
    total = 0;
    n = numunspents = 0;
    if ( iguana_addressvalidate(coin,&addrtype,coinaddr) < 0 )
    {
        printf("illegal coinaddr.(%s) minconf.%d longest.%d diff.%d\n",coinaddr,minconf,coin->longestchain,coin->blocks.hwmchain.height - minconf);
        return(0);
    }
    bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
    for (j=0; j<20; j++)
        if ( rmd160[j] != 0 )
            break;
    if ( j == 20 )
        return(0);
    iguana_RTpkhasharray(myinfo,coin,0,minconf,coin->longestchain,&total,0,coin->bundlescount,rmd160,coinaddr,pubkey,lastheight,unspents,&n,max-1000,remoteaddr,includespent);
    numunspents = n;
    for (k=0; k<n; k++)
        (*sump) += unspents[k].value;
    return(numunspents);
}

int32_t iguana_RTuvaltxid(struct supernet_info *myinfo,bits256 *txidp,struct iguana_info *coin,struct iguana_outpoint outpt)
{
    struct iguana_bundle *bp; struct iguana_unspent *U,*u; struct iguana_txid *T; struct iguana_ramchain *ramchain; struct iguana_ramchaindata *rdata; struct iguana_RTunspent *unspent; struct iguana_RTtxid *parent;
    if ( outpt.isptr != 0 && (unspent= outpt.ptr) != 0 && (parent= unspent->parent) != 0 )
    {
        *txidp = parent->txid;
        return(unspent->vout);
    }
    if ( (bp= coin->bundles[outpt.hdrsi]) == 0 )
        return(-1);
    ramchain = &bp->ramchain;//(bp == coin->current) ? &coin->RTramchain : &bp->ramchain;
    if ( (rdata= ramchain->H.data) != 0 )
    {
        U = RAMCHAIN_PTR(rdata,Uoffset);
        T = RAMCHAIN_PTR(rdata,Toffset);
        if ( outpt.unspentind > 0 && outpt.unspentind < rdata->numunspents )
        {
            u = &U[outpt.unspentind];
            if ( u->txidind > 0 && u->txidind < rdata->numtxids )
            {
                *txidp = T[u->txidind].txid;
                return(outpt.unspentind - T[u->txidind].firstvout);
            }
        }
    }
    return(-1);
}

uint64_t iguana_unspentavail(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_outpoint outpt,int32_t minconf,int32_t maxconf)
{
    struct iguana_ramchain *ramchain; struct iguana_bundle *bp; uint64_t RTspend=0; int32_t spentheight,spentflag; struct iguana_unspent *U,*u; struct iguana_ramchaindata *rdata;
    if ( (bp= coin->bundles[outpt.hdrsi]) == 0 )
        return(-1);
    ramchain = &bp->ramchain;//(bp == coin->current) ? &coin->RTramchain : &bp->ramchain;
    if ( (rdata= ramchain->H.data) == 0 )
        return(0);
    if ( (spentflag= iguana_RTspentflag(myinfo,coin,&RTspend,&spentheight,ramchain,outpt,0,minconf,maxconf,0)) > 0 )
    {
        printf("[%d].u%d was already spent ht.%d\n",outpt.hdrsi,outpt.unspentind,spentheight);
        return(-1);
    }
    else if ( spentflag == 0 )
    {
        U = RAMCHAIN_PTR(rdata,Uoffset);
        if ( outpt.unspentind > 0 && outpt.unspentind < rdata->numunspents )
        {
            u = &U[outpt.unspentind];
            return(u->value);
        }
        else
        {
            printf("%s illegal unspentind.%u [%d] vs %u [%d]\n",coin->symbol,outpt.unspentind,outpt.hdrsi,rdata->numunspents,bp->hdrsi);
            return(-2);
        }
    }
    else return(0);
}

int32_t iguana_unspentfindjson(cJSON *destarray,cJSON *item)
{
    cJSON *destitem; int32_t i,n;
    if ( (n= cJSON_GetArraySize(destarray)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            destitem = jitem(destarray,i);
            if ( jint(destitem,"vout") == jint(item,"vout") && bits256_cmp(jbits256(destitem,"txid"),jbits256(item,"txid")) == 0 )
                return(i);
        }
    }
    return(-1);
}

cJSON *iguana_RTlistunspent(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *argarray,int32_t minconf,int32_t maxconf,char *remoteaddr,int32_t includespends)
{
    uint64_t total = 0; int32_t i,j,m,n,numrmds,numunspents=0; char *coinaddr,*retstr; uint8_t *rmdarray; cJSON *vals,*unspents,*item,*array,*retjson,*retarray; bits256 hash;
    if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 || coin->notarychain >= 0 )
    {
        retjson = cJSON_CreateArray();
        rmdarray = iguana_rmdarray(myinfo,coin,&numrmds,argarray,0);
        total = iguana_RTunspents(myinfo,coin,retjson,minconf,maxconf,rmdarray,numrmds,(1 << 30),0,&numunspents,remoteaddr,includespends);
        if ( rmdarray != 0 )
            free(rmdarray);
    }
    else
    {
        basilisk_unspents_update(myinfo,coin);
        portable_mutex_lock(&myinfo->bu_mutex);
        if ( (unspents= myinfo->Cunspents) != 0 && (array= jobj(unspents,coin->symbol)) != 0 )
            unspents = jduplicate(array);
        portable_mutex_unlock(&myinfo->bu_mutex);
        retjson = cJSON_CreateArray();
        if ( unspents != 0 )
        {
            if ( (n= cJSON_GetArraySize(unspents)) > 0 && (m= cJSON_GetArraySize(argarray)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(unspents,i);
                    if ( (coinaddr= jstr(item,"address")) != 0 )
                    {
                        for (j=0; j<m; j++)
                            if ( strcmp(coinaddr,jstri(argarray,j)) == 0 )
                            {
                                jaddi(retjson,jduplicate(item));
                                break;
                            }
                    }
                }
            }
            //printf("RET.(%s)\n",jprint(retjson,0));
            free_json(unspents);
        }
        if ( cJSON_GetArraySize(retjson) == 0 && cJSON_GetArraySize(argarray) > 0 )
        {
            memset(hash.bytes,0,sizeof(hash));
            vals = cJSON_CreateObject();
            jaddstr(vals,"coin",coin->symbol);
            jaddnum(vals,"history",1);
            jaddnum(vals,"firstheight",0);
            jaddnum(vals,"fanout",MAX(8,(int32_t)sqrt(myinfo->NOTARY.NUMRELAYS)+1));
            jaddnum(vals,"numrequired",MIN(4,(int32_t)sqrt(myinfo->NOTARY.NUMRELAYS)+1));
            jadd(vals,"addresses",jduplicate(argarray));
            if ( (retstr= basilisk_standardservice("BAL",myinfo,0,hash,vals,"",1)) != 0 )
            {
                if ( (retarray= cJSON_Parse(retstr)) != 0 )
                {
                    if ( (n= cJSON_GetArraySize(retarray)) > 0 )
                    {
                        for (i=0; i<n; i++)
                        {
                            item = jitem(retarray,i);
                            if ( (unspents= jarray(&m,item,"unspents")) != 0 )
                            {
                                for (j=0; j<m; j++)
                                    if ( iguana_unspentfindjson(retjson,jitem(unspents,j)) < 0 )
                                        jaddi(retjson,jduplicate(jitem(unspents,j)));
                            }
                        }
                    }
                    free_json(retarray);
                }
                //printf("LIST.(%s)\n",retstr);
                free(retstr);
            }
            free_json(vals);
        }
    }
    /*{
     "txid" : "d54994ece1d11b19785c7248868696250ab195605b469632b7bd68130e880c9a",
     "vout" : 1,
     "address" : "mgnucj8nYqdrPFh2JfZSB1NmUThUGnmsqe",
     "account" : "test label",
     "scriptPubKey" : "76a9140dfc8bafc8419853b34d5e072ad37d1a5159f58488ac",
     "amount" : 0.00010000,
     "confirmations" : 6210,
     "spendable" : true
     },*/
    return(retjson);
}

int32_t iguana_RTunspentslists(struct supernet_info *myinfo,struct iguana_info *coin,uint64_t *totalp,struct iguana_outpoint *unspents,int32_t max,uint64_t required,int32_t minconf,cJSON *addresses,char *remoteaddr)
{
    uint64_t sum = 0; int32_t i=0,n,firstslot,numunspents,numaddrs; uint8_t pubkey[65]; char *coinaddr,*spendscriptstr; struct iguana_outpoint outpt; cJSON *array,*item;
    *totalp = 0;
    numunspents = 0;
    if ( (numaddrs= cJSON_GetArraySize(addresses)) == 0 )
    {
        printf("null addresses.(%s)\n",jprint(addresses,0));
        return(0);
    }
    memset(pubkey,0,sizeof(pubkey));
    //remains = required * 1.1 + coin->txfee;
    if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 || (coin->FULLNODE == 0 && coin->notarychain >= 0) )
    {
        for (i=numunspents=0; i<numaddrs; i++)
        {
            if ( (coinaddr= jstri(addresses,i)) != 0 )
            {
                numunspents += iguana_RTaddr_unspents(myinfo,coin,&sum,&unspents[numunspents],max-numunspents,coinaddr,remoteaddr,1<<30,0);
            }
        }
    }
    else if ( coin->FULLNODE == 0 && coin->VALIDATENODE == 0 )
    {
        if ( (array= iguana_RTlistunspent(myinfo,coin,addresses,minconf,1<<30,remoteaddr,0)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( iguana_markedunspents_find(coin,&firstslot,jbits256(item,"txid"),jint(item,"vout")) >= 0 )
                        continue;
                    if ( (spendscriptstr= jstr(item,"scriptPubKey")) == 0 )
                    {
                        printf("no spendscriptstr.(%s)\n",jprint(item,0));
                        continue;
                    }
                    iguana_outptset(myinfo,coin,&outpt,jbits256(item,"txid"),jint(item,"vout"),jdouble(item,"amount") * SATOSHIDEN,spendscriptstr);
                    *unspents = outpt;
                    sum += outpt.value;
                    //printf("ITEM.(%s) %.8f\n",jprint(item,0),dstr(outpt.value));
                    unspents++;
                    numunspents++;
                    if ( numunspents >= max )//|| sum > 10*required )
                        break;
                }
            }
            free_json(array);
        }
    }
    else
    {
        for (i=numunspents=0; i<numaddrs; i++)
        {
            if ( (coinaddr= jstri(addresses,i)) != 0 )
            {
                if ( (array= dpow_listunspent(myinfo,coin,coinaddr)) != 0 )
                {
                    if ( (n= cJSON_GetArraySize(array)) > 0 )
                    {
                        for (i=0; i<n; i++)
                        {
                            item = jitem(array,i);
                            if ( is_cJSON_False(jobj(item,"spendable")) != 0 )
                            {
                                //printf("skip unspendable.(%s)\n",jprint(item,0));
                                continue;
                            }
                            if ( (spendscriptstr= jstr(item,"scriptPubKey")) == 0 )
                            {
                                printf("no spendscriptstr.(%s)\n",jprint(item,0));
                                continue;
                            }
                            iguana_outptset(myinfo,coin,&outpt,jbits256(item,"txid"),jint(item,"vout"),jdouble(item,"amount") * SATOSHIDEN,spendscriptstr);
                            *unspents = outpt;
                            sum += outpt.value;
                            unspents++;
                            numunspents++;
                            if ( numunspents >= max )//|| sum > 10*required )
                                break;
                        }
                    }
                    if ( numunspents == 0 )
                        printf("no unspents.(%s)\n",jprint(array,0));
                    free_json(array);
                }
            }
        }
    }
    *totalp = sum;
    coinaddr = addresses != 0 ? jstri(addresses,i) : "";
    printf("numunspents.%d max.%d sum %.8f required %.8f (%s)\n",numunspents,max,dstr(sum),dstr(required),coinaddr);
    return(numunspents);
}

#define UTXOADDR_ITEMSIZE 32
#define iguana_utxotable_numinds(ind) (((ind) == 0xffff) ? coin->utxoaddrlastcount : (coin->utxoaddroffsets[(ind) + 1] - coin->utxoaddroffsets[ind]))

int32_t iguana_rwutxoaddr(int32_t rwflag,uint16_t ind,uint8_t *serialized,struct iguana_utxoaddr *utxoaddr)
{
    uint32_t pkind=0; int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[0],sizeof(utxoaddr->hdrsi),&utxoaddr->hdrsi);
    if ( rwflag == 0 )
    {
        utxoaddr->rmd160[0] = (ind & 0xff);
        utxoaddr->rmd160[1] = ((ind >> 8) & 0xff);
        memcpy(&utxoaddr->rmd160[2],&serialized[2],18);
    } else memcpy(&serialized[2],&utxoaddr->rmd160[2],18);
    len += 18;
    if ( rwflag != 0 )
        pkind = (utxoaddr->pkind & 0x7fffffff) | (utxoaddr->p2sh << 31);
    len += iguana_rwnum(rwflag,&serialized[20],sizeof(pkind),&pkind);
    if ( rwflag == 0 )
    {
        utxoaddr->pkind = pkind & 0x7fffffff;
        utxoaddr->p2sh = (pkind >> 31);
    }
    len += iguana_rwnum(rwflag,&serialized[24],sizeof(utxoaddr->histbalance),&utxoaddr->histbalance);
    return(len);
}

uint64_t iguana_utxoaddrtablefind(struct iguana_info *coin,int16_t search_hdrsi,uint32_t search_pkind,uint8_t rmd160[20])
{
    struct iguana_utxoaddr UA; int32_t ind,num,i; uint8_t *ptr;
    memset(&UA,0,sizeof(UA));
    ind = rmd160[0] + ((uint32_t)rmd160[1] << 8);
    if ( coin->utxoaddroffsets != 0 && (num= iguana_utxotable_numinds(ind)) > 0 )
    {
        for (i=0; i<num; i++)
        {
            ptr = &coin->utxoaddrtable[(coin->utxoaddroffsets[ind] + i) * UTXOADDR_ITEMSIZE];
            iguana_rwutxoaddr(0,ind,ptr,&UA);
            if ( (UA.pkind == search_pkind && UA.hdrsi == search_hdrsi) || memcmp(UA.rmd160,rmd160,20) == 0 )
                return(UA.histbalance);
        }
        //printf("ind.%04x no [%d] p%u after num.%d\n",ind,search_hdrsi,search_pkind,num);
    }
    return(0);
}

struct iguana_utxoaddr *iguana_utxoaddrfind(int32_t createflag,struct iguana_info *coin,int16_t hdrsi,uint32_t pkind,uint8_t rmd160[20],struct iguana_utxoaddr **prevp,int32_t p2shflag)
{
    struct iguana_utxoaddr *utxoaddr; char coinaddr[64];
    HASH_FIND(hh,coin->utxoaddrs,rmd160,sizeof(utxoaddr->rmd160),utxoaddr);
    if ( utxoaddr == 0 && createflag != 0 )
    {
        utxoaddr = calloc(1,sizeof(*utxoaddr));
        ++coin->utxoaddrind;
        utxoaddr->hdrsi = hdrsi;
        if ( (utxoaddr->p2sh= p2shflag) != 0 )
        {
            char coinaddr[64];
            bitcoin_address(coinaddr,coin->chain->p2shtype,rmd160,20);
            //printf("P2SH type.(%s)\n",coinaddr);
        }
        utxoaddr->pkind = pkind;
        if ( coin->utxoaddrtable != 0 && coin->utxoaddroffsets != 0 )
        {
            utxoaddr->searchedhist = 1;
            utxoaddr->histbalance = iguana_utxoaddrtablefind(coin,hdrsi,pkind,rmd160);
        }
        memcpy(utxoaddr->rmd160,rmd160,sizeof(utxoaddr->rmd160));
        HASH_ADD_KEYPTR(hh,coin->utxoaddrs,utxoaddr->rmd160,sizeof(utxoaddr->rmd160),utxoaddr);
        if ( prevp != 0 )
        {
            utxoaddr->hh.prev = *prevp;
            if ( *prevp != 0 )
                (*prevp)->hh.next = utxoaddr;
            *prevp = utxoaddr;
        }
        HASH_FIND(hh,coin->utxoaddrs,rmd160,sizeof(utxoaddr->rmd160),utxoaddr);
        if ( utxoaddr == 0 )
        {
            int32_t i; for (i=0; i<20; i++)
                printf("%02x",utxoaddr->rmd160[i]);
            bitcoin_address(coinaddr,coin->chain->pubtype,utxoaddr->rmd160,sizeof(utxoaddr->rmd160));
            printf(" %d of %d: %s %.8f\n",coin->utxoaddrind,coin->utxodatasize,coinaddr,dstr(utxoaddr->histbalance));
            printf("failed to find just added %d of %d\n",coin->utxoaddrind,coin->utxodatasize);
        }
    }
    return(utxoaddr);
}

uint64_t iguana_bundle_unspents(struct iguana_info *coin,struct iguana_bundle *bp,struct iguana_utxoaddr **prevp)
{
    struct iguana_utxoaddr *utxoaddr; int32_t p2shflag; uint32_t unspentind,pkind; struct iguana_ramchaindata *rdata=0; struct iguana_pkhash *P; struct iguana_unspent *U; struct iguana_utxo *U2=0; uint64_t value,balance = 0;
    if ( bp == 0 || (rdata= bp->ramchain.H.data) == 0 || (U2= bp->ramchain.Uextras) == 0 )
    {
        printf("missing ptr bp.%p rdata.%p U2.%p\n",bp,rdata,U2);
        return(0);
    }
    U = RAMCHAIN_PTR(rdata,Uoffset);
    P = RAMCHAIN_PTR(rdata,Poffset);
    for (unspentind=1; unspentind<rdata->numunspents; unspentind++)
    {
        value = U[unspentind].value;
        //printf("[%d] u%d: (p%u %.8f) from.%d lock.%d prev.%u spent.%d\n",bp->hdrsi,unspentind,U[unspentind].pkind,dstr(value),U2[unspentind].fromheight,U2[unspentind].lockedflag,U2[unspentind].prevunspentind,U2[unspentind].spentflag);
        if ( U2[unspentind].fromheight == 0 && U2[unspentind].lockedflag == 0 && U2[unspentind].prevunspentind == 0 && U2[unspentind].spentflag == 0 && value != 0 )
        {
            if ( value <= 0 )
                printf("[%d] u%u negative value %.8f??\n",bp->hdrsi,unspentind,dstr(value));
            else
            {
                balance += value;
                if ( (pkind= U[unspentind].pkind) < rdata->numpkinds && pkind > 0 )
                {
                    p2shflag = 0;
                    //if ( (p2shflag= (iguana_addrtype(coin,U[unspentind].type) == coin->chain->p2shtype)) != 0 )
                    {
                        char coinaddr[64];
                        bitcoin_address(coinaddr,coin->chain->p2shtype,P[pkind].rmd160,20);
                        if ( U[unspentind].type != IGUANA_SCRIPT_76A988AC && U[unspentind].type != IGUANA_SCRIPT_AC && U[unspentind].type != IGUANA_SCRIPT_76AC )
                        {
                            p2shflag = 1;
                            //printf("%s %.8f P2SH.%d\n",coinaddr,dstr(value),U[unspentind].type);
                        }
                    }
                    if ( (utxoaddr= iguana_utxoaddrfind(1,coin,bp->hdrsi,pkind,P[pkind].rmd160,prevp,p2shflag)) != 0 )
                    {
                        //printf("%.8f ",dstr(value));
                        utxoaddr->histbalance += value;
                    } else printf("cant find pkind.%u for unspentind.%u hdrsi.%d\n",pkind,unspentind,bp->hdrsi);
                } else printf("illegal pkind.%u for unspentind.%u hdrsi.%d\n",pkind,unspentind,bp->hdrsi);
            }
        } // else printf("[%d] u%u spent %.8f\n",bp->hdrsi,unspentind,dstr(value));
    }
    printf("[%d %.8f] ",bp->hdrsi,dstr(balance));
    return(balance);
}

static int _utxoaddr_cmp(const void *a,const void *b)
{
#define item_a ((uint8_t *)a)
#define item_b ((uint8_t *)b)
    uint16_t hdrsi_a,hdrsi_b; uint32_t pkind_a,pkind_b;
    iguana_rwnum(0,&item_a[0],sizeof(hdrsi_a),&hdrsi_a);
    iguana_rwnum(0,&item_a[20],sizeof(pkind_a),&pkind_a);
    iguana_rwnum(0,&item_b[0],sizeof(hdrsi_b),&hdrsi_b);
    iguana_rwnum(0,&item_b[20],sizeof(pkind_b),&pkind_b);
	if ( hdrsi_b > hdrsi_a )
		return(1);
	else if ( hdrsi_b < hdrsi_a )
		return(-1);
    else
    {
        if ( pkind_b > pkind_a )
            return(1);
        else if ( pkind_b < pkind_a )
            return(-1);
        else return(0);
    }
#undef item_a
#undef item_b
}

int32_t iguana_utxoaddr_save(struct iguana_info *coin,char *fname,uint64_t balance,uint32_t *counts,uint32_t *offsets,uint8_t *table)
{
    FILE *fp; bits256 hash; int32_t retval = -1;
    if ( (fp= fopen(fname,"wb")) != 0 )
    {
        fwrite(&balance,1,sizeof(balance),fp);
        fwrite(&counts[0xffff],1,sizeof(counts[0xffff]),fp);
        fwrite(&coin->utxoaddrind,1,sizeof(coin->utxoaddrind),fp);
        vcalc_sha256cat(hash.bytes,(void *)offsets,(int32_t)(0x10000 * sizeof(*offsets)),table,(int32_t)((coin->utxoaddrind+1) * UTXOADDR_ITEMSIZE));
        if ( fwrite(hash.bytes,1,sizeof(hash),fp) == sizeof(hash) )
        {
            if ( fwrite(offsets,1,0x10000 * sizeof(*offsets),fp) == 0x10000 * sizeof(*offsets) )
            {
                if ( fwrite(table,1,(coin->utxoaddrind+1) * UTXOADDR_ITEMSIZE,fp) != (coin->utxoaddrind+1) * UTXOADDR_ITEMSIZE )
                    printf("error writing %s table\n",fname);
                else retval = 0;
            } else printf("error writing %s offsets\n",fname);
        } else printf("error writing %s hash\n",fname);
        fclose(fp);
    } else printf("error creating %s\n",fname);
    return(retval);
}

int32_t iguana_utxoaddr_map(struct iguana_info *coin,char *fname)
{
    uint32_t ind,total=0,offset,size=0,last=0,lastcount=0,count,prevoffset=0;
    if ( (coin->utxoaddrfileptr= OS_mapfile(fname,&coin->utxoaddrfilesize,0)) != 0 && coin->utxoaddrfilesize > sizeof(bits256)+0x10000*sizeof(*coin->utxoaddroffsets) )
    {
        memcpy(&coin->histbalance,coin->utxoaddrfileptr,sizeof(coin->histbalance));
        memcpy(&last,(void *)((long)coin->utxoaddrfileptr+sizeof(uint64_t)),sizeof(last));
        memcpy(&coin->utxoaddrind,(void *)((long)coin->utxoaddrfileptr+sizeof(uint64_t)+sizeof(uint32_t)),sizeof(coin->utxoaddrind));
        memcpy(&coin->utxoaddrhash.bytes,(void *)((long)coin->utxoaddrfileptr+sizeof(uint64_t)+2*sizeof(uint32_t)),sizeof(coin->utxoaddrhash));
#if defined(_M_X64)
		coin->utxoaddroffsets = (void *)((unsigned char *)coin->utxoaddrfileptr + sizeof(uint64_t) + 2 * sizeof(uint32_t) + sizeof(bits256));
#else
        coin->utxoaddroffsets = (void *)((long)coin->utxoaddrfileptr + sizeof(uint64_t) + 2*sizeof(uint32_t) + sizeof(bits256));
#endif
        for (ind=total=count=0; ind<0x10000; ind++)
        {
            if ( (offset= coin->utxoaddroffsets[ind]) != 0 )
            {
                count = offset - prevoffset;
                prevoffset = offset;
                total += count;
            }
        }
        size = (uint32_t)((total+1)*UTXOADDR_ITEMSIZE);
        size += sizeof(uint64_t) + 2*sizeof(uint32_t) + sizeof(bits256);
        size += 0x10000 * sizeof(*coin->utxoaddroffsets);
        if ( size <= coin->utxoaddrfilesize )
        {
            lastcount = (uint32_t)(coin->utxoaddrfilesize - size);
            if ( (lastcount % UTXOADDR_ITEMSIZE) == 0 )
            {
                lastcount /= UTXOADDR_ITEMSIZE;
                coin->utxoaddrlastcount = lastcount;
                coin->utxoaddrtable = (void *)&coin->utxoaddroffsets[0x10000];
                //iguana_utxoaddr_purge(coin);
            }
        }
        printf("%.8f LASTCOUNT %d vs total %d, last %d vs lastcount %d, size.%d %ld\n",dstr(coin->histbalance),coin->utxoaddrlastcount,total,last,lastcount,size,coin->utxoaddrfilesize);
        return(total + 1 + lastcount);
    }
    return(0);
}

void iguana_utxoaddr_purge(struct iguana_info *coin)
{
    struct iguana_utxoaddr *utxoaddr,*tmp;
    if ( coin->utxoaddrs != 0 )
    {
        printf("free %s utxoaddrs\n",coin->symbol);
        HASH_ITER(hh,coin->utxoaddrs,utxoaddr,tmp)
        {
            if ( utxoaddr != 0 )
            {
                HASH_DELETE(hh,coin->utxoaddrs,utxoaddr);
                free(utxoaddr);
            }
        }
        coin->utxoaddrs = 0;
    }
    if ( coin->utxoaddrfileptr != 0 )
    {
        OS_releasemap(coin->utxoaddrfileptr,coin->utxoaddrfilesize);
        coin->utxoaddrfileptr = 0;
        coin->utxoaddrtable = 0;
        coin->utxoaddroffsets = 0;
    }
    memset(coin->utxoaddrhash.bytes,0,sizeof(coin->utxoaddrhash));
    coin->histbalance = 0;
    coin->utxoaddrlastcount = 0;
    coin->utxoaddrind = 0;
    coin->utxoaddrfilesize = 0;
}

int32_t iguana_utxoaddr_check(struct supernet_info *myinfo,struct iguana_info *coin,int32_t lastheight,struct iguana_outpoint *unspents,int32_t max,struct iguana_utxoaddr *utxoaddr)
{
    static int32_t good,bad; static uint64_t total;
    char coinaddr[64]; uint64_t sum,checkbalance; int32_t i,flag=0,numunspents = 0;
    sum = 0;
    bitcoin_address(coinaddr,utxoaddr->p2sh == 0 ? coin->chain->pubtype : coin->chain->p2shtype,utxoaddr->rmd160,sizeof(utxoaddr->rmd160));
    numunspents += iguana_RTaddr_unspents(myinfo,coin,&sum,&unspents[numunspents],max-numunspents,coinaddr,0,lastheight,0);
    if ( (0) && utxoaddr->histbalance != 0 && strcmp(coin->symbol,"BTCD") == 0 )
    {
        total += utxoaddr->histbalance;
        //printf("fiat/revs sendtoaddress %s %.8f # total %.8f\n",coinaddr,dstr(utxoaddr->histbalance),dstr(total));
        printf("fiat/revs sendtoaddress %s %.8f\n",coinaddr,dstr(utxoaddr->histbalance));
        if ( total/SATOSHIDEN > 1308000 )
            printf("error: total %.8f\n",dstr(total));
    }
    if ( sum == utxoaddr->histbalance )
    {
        checkbalance = iguana_utxoaddrtablefind(coin,0,0,utxoaddr->rmd160);
        if ( checkbalance != sum )
            printf("%s checkbalance %.8f vs sum %.8f\n",coinaddr,dstr(checkbalance),dstr(sum));
        flag = 1;
        //break;
    }
    if ( (0) && flag == 0 )//sum != utxoaddr->histbalance || checkbalance != sum )
    {
        bad++;
        for (i=0; i<numunspents; i++)
            printf("(%d %u %.8f) ",unspents[i].hdrsi,unspents[i].unspentind,dstr(unspents[i].value));
        for (i=0; i<20; i++)
            printf("%02x",utxoaddr->rmd160[i]);
        bitcoin_address(coinaddr,coin->chain->pubtype,utxoaddr->rmd160,sizeof(utxoaddr->rmd160));
        printf(" %s: sum %.8f != %.8f %.8f numunspents.%d diff %.8f\n",coinaddr,dstr(sum),dstr(utxoaddr->histbalance),dstr(checkbalance),numunspents,dstr(utxoaddr->histbalance)-dstr(sum));
        return(-1);
    }
    good++;
    if ( ((good + bad) % 1000) == 0 )
        printf("%s total %d utxoaddr validate good.%d bad.%d%s\n",coin->symbol,coin->utxoaddrind,good,bad,strcmp(coin->symbol,"BTC") == 0 ? " | (if this is taking too long, just exit and restart iguana)" : "");
    return(0);
}

int32_t iguana_utxoaddr_validate(struct supernet_info *myinfo,struct iguana_info *coin,int32_t lastheight)
{
    struct iguana_outpoint *unspents; uint8_t *item; struct iguana_bundle *bp; struct iguana_utxoaddr UA; int32_t i,num,max,ind,total,errs=0;
    if ( coin->utxoaddrtable == 0 )
    {
        printf("no utxoaddrtable to validate?\n");
        return(-1);
    }
    for (i=0; i<coin->bundlescount; i++)
        if ( (bp= coin->bundles[i]) != 0 && bp != coin->current )
        {
            iguana_volatilespurge(coin,&bp->ramchain);
            /*sprintf(fname,"%s/%s/accounts/debits.%d",GLOBAL_DBDIR,coin->symbol,bp->bundleheight);
             OS_removefile(fname,0);
             sprintf(fname,"%s/%s/accounts/lastspends.%d",GLOBAL_DBDIR,coin->symbol,bp->bundleheight);
             OS_removefile(fname,0);*/
            iguana_volatilesmap(myinfo,coin,&bp->ramchain);
        }
    total = 0;
    max = 1024 * 1024 * 1024;
    unspents = calloc(1,max);
    max /= sizeof(*unspents);
    memset(&UA,0,sizeof(UA));
    for (ind=0; ind<0x10000; ind++)
    {
        if ( (num= iguana_utxotable_numinds(ind)) > 0 )
        {
            for (i=0; i<num; i++)
            {
                item = &coin->utxoaddrtable[(coin->utxoaddroffsets[ind] + i) * UTXOADDR_ITEMSIZE];
                iguana_rwutxoaddr(0,ind,item,&UA);
                errs += iguana_utxoaddr_check(myinfo,coin,lastheight,unspents,max,&UA);
                total++;
            }
        }
    }
    free(unspents);
    printf("validate errs.%d\n",errs);
    return(errs);
}

uint64_t iguana_RTstart(struct supernet_info *myinfo,struct iguana_info *coin,int32_t height)
{
    //struct iguana_block *block;
    coin->firstRTheight = height;
    iguana_RTreset(coin);
    iguana_RTpurge(coin,coin->firstRTheight);
    basilisk_unspents_update(myinfo,coin);
    return(coin->histbalance);
}

uint64_t iguana_utxoaddr_gen(struct supernet_info *myinfo,struct iguana_info *coin,int32_t maxheight)
{
    char fname[1024],fname2[1024],coinaddr[64],str[65],checkaddr[64]; struct iguana_utxoaddr *utxoaddr,UA,*tmp,*last=0; uint16_t hdrsi; uint8_t *table,item[UTXOADDR_ITEMSIZE]; uint32_t *counts,*offsets,offset,n; int32_t total,errs=0,height=0,ind,tablesize=0; struct iguana_bundle *bp; struct iguana_ramchaindata *rdata=0; uint64_t checkbalance=0,balance = 0;
    for (hdrsi=0; hdrsi<coin->bundlescount-1; hdrsi++)
    {
        if ( (bp= coin->bundles[hdrsi]) != 0 && bp->bundleheight < maxheight )
            height = bp->bundleheight + bp->n;
    }
    sprintf(fname2,"%s/%s/utxoaddrs.%d",GLOBAL_DBDIR,coin->symbol,height), OS_portable_path(fname2);
    if ( iguana_utxoaddr_map(coin,fname2) != 0 )
    {
        if ( (0) && strcmp("BTCD",coin->symbol) == 0 )
            errs = iguana_utxoaddr_validate(myinfo,coin,height);
        printf("nogen %s HIST BALANCE %s %.8f errs %d\n",fname2,bits256_str(str,coin->utxoaddrhash),dstr(coin->histbalance),errs);
        if ( errs == 0 && coin->histbalance > 0 && height > 0 )
            return(iguana_RTstart(myinfo,coin,height));
    }
    printf("utxoaddr_gen.%d\n",maxheight);
    iguana_utxoaddr_purge(coin);
    HASH_ITER(hh,coin->utxoaddrs,utxoaddr,tmp)
    {
        checkbalance += utxoaddr->histbalance;
    }
    printf("balance after purge %.8f\n",dstr(checkbalance));
    for (hdrsi=0; hdrsi<coin->bundlescount-1; hdrsi++)
        if ( (bp= coin->bundles[hdrsi]) != 0 && bp->bundleheight < maxheight && (rdata= bp->ramchain.H.data) != 0 )
        {
            tablesize += rdata->numpkinds;
        }
    printf("allocate UTXOADDRS[%d]\n",tablesize);
    coin->utxodatasize = tablesize;
    coin->utxoaddrind = 0;
    for (hdrsi=0; hdrsi<coin->bundlescount-1; hdrsi++)
    {
        if ( (bp= coin->bundles[hdrsi]) != 0 && bp->bundleheight < maxheight )
        {
            iguana_volatilespurge(coin,&bp->ramchain);
            if ( iguana_volatilesmap(myinfo,coin,&bp->ramchain) != 0 )
                printf("error mapping bundle.[%d]\n",hdrsi);
            else
            {
                balance += iguana_bundle_unspents(coin,bp,&last);
                fprintf(stderr,"(%d %.8f) ",hdrsi,dstr(balance));
                height = bp->bundleheight + bp->n;
            }
        }
    }
    sprintf(fname,"%s/%s/utxoaddrs",GLOBAL_DBDIR,coin->symbol), OS_portable_path(fname);
    fprintf(stderr,"%d bundles for iguana_utxoaddr_gen.[%d] max.%d ht.%d\n",hdrsi,coin->utxoaddrind,coin->utxodatasize,maxheight);
    counts = calloc(0x10000,sizeof(*counts));
    checkbalance = 0;
    HASH_ITER(hh,coin->utxoaddrs,utxoaddr,tmp)
    {
        if ( utxoaddr->histbalance > 0 )
        {
            checkbalance += utxoaddr->histbalance;
            ind = utxoaddr->rmd160[0] + ((uint32_t)utxoaddr->rmd160[1] << 8);
            counts[ind]++;
        } else printf("error neg or zero balance %.8f\n",dstr(utxoaddr->histbalance));
    }
    for (ind=total=0; ind<0x10000; ind++)
        total += counts[ind];
    printf("checkbalance %.8f vs %.8f, total %d\n",dstr(checkbalance),dstr(balance),total);
    if ( checkbalance == balance )
    {
        table = calloc(coin->utxoaddrind+1,UTXOADDR_ITEMSIZE);
        offsets = calloc(0x10000,sizeof(*offsets));
        offset = 0;
        for (ind=0; ind<0x10000; ind++)
        {
            n = counts[ind];
            offsets[ind] = offset;
            counts[ind] = 0;
            offset += n;
        }
        printf("total %d offset %d\n",total,offset);
        total = 0;
        HASH_ITER(hh,coin->utxoaddrs,utxoaddr,tmp)
        {
            if ( utxoaddr->histbalance > 0 )
            {
                bitcoin_address(coinaddr,coin->chain->pubtype,utxoaddr->rmd160,sizeof(utxoaddr->rmd160));
                memset(item,0,UTXOADDR_ITEMSIZE);
                ind = utxoaddr->rmd160[0] + ((uint32_t)utxoaddr->rmd160[1] << 8);
                iguana_rwutxoaddr(1,ind,item,utxoaddr);
                memcpy(&table[(offsets[ind] + counts[ind]) * UTXOADDR_ITEMSIZE],item,UTXOADDR_ITEMSIZE);
                iguana_rwutxoaddr(0,ind,&table[(offsets[ind] + counts[ind]) * UTXOADDR_ITEMSIZE],&UA);
                iguana_rwutxoaddr(1,ind,item,&UA);
                bitcoin_address(checkaddr,coin->chain->pubtype,UA.rmd160,sizeof(UA.rmd160));
                if ( strcmp(checkaddr,coinaddr) != 0 )
                    printf("rw coinaddr error %s != %s\n",coinaddr,checkaddr);
                //else printf("%d: ind.%04x %s %.8f %.8f %d\n",total,ind,coinaddr,dstr(UA.histbalance),dstr(utxoaddr->histbalance),counts[ind]);
                total++;
                if ( memcmp(&table[(offsets[ind] + counts[ind]) * UTXOADDR_ITEMSIZE],item,UTXOADDR_ITEMSIZE) != 0 )
                    printf("rwutxoaddr cmp error\n");
                counts[ind]++;
            } else printf("error neg or zero balance %.8f\n",dstr(utxoaddr->histbalance));
        }
        offset = 1;
        for (ind=0; ind<0x10000; ind++)
            offset += counts[ind];
        if ( offset == coin->utxoaddrind+1 )
        {
            for (ind=0; ind<0x10000; ind++)
            {
                if ( counts[ind] > 0 )
                {
                    qsort(&table[offsets[ind] * UTXOADDR_ITEMSIZE],counts[ind],UTXOADDR_ITEMSIZE,_utxoaddr_cmp);
                    continue;
                    /*for (j=0; j<counts[ind]; j++)
                    {
                        iguana_rwutxoaddr(0,ind,&table[(offsets[ind]+j) * UTXOADDR_ITEMSIZE],&UA);
                        for (k=0; k<20; k++)
                            printf("%02x",UA.rmd160[k]);
                        bitcoin_address(coinaddr,coin->chain->pubtype,UA.rmd160,sizeof(UA.rmd160));
                        //printf(" [%4d] p%-5d %12.8f ind.%04x %d %s\n",UA.hdrsi,UA.pkind,dstr(UA.histbalance),ind,j,coinaddr);
                    }*/
                }
            }
            if ( iguana_utxoaddr_save(coin,fname,balance,counts,offsets,table) == 0 )
            {
                if ( OS_copyfile(fname,fname2,1) < 0 )
                    printf("error copying file %s to %s\n",fname,fname2);
                else
                {
                    for (hdrsi=0; hdrsi<coin->bundlescount-1; hdrsi++)
                    {
                        if ( (bp= coin->bundles[hdrsi]) != 0 && bp->bundleheight < maxheight )
                            bp->balancefinish = (uint32_t)time(NULL);
                    }
                }
            } else printf("error saving %s\n",fname);
        } else printf("table has %d vs %d\n",offset,coin->utxoaddrind+1);
        free(offsets);
        free(table);
        iguana_utxoaddr_purge(coin);
        if ( iguana_utxoaddr_map(coin,fname) != 0 )
        {
            printf("validating %s HIST BALANCE %s %.8f errs %d\n",fname2,bits256_str(str,coin->utxoaddrhash),dstr(coin->histbalance),errs);
            errs = 0;
            if ( (0) && strcmp("BTCD",coin->symbol) == 0 )
                errs = iguana_utxoaddr_validate(myinfo,coin,height);
            printf("gen %s HIST BALANCE %s %.8f errs %d\n",fname2,bits256_str(str,coin->utxoaddrhash),dstr(coin->histbalance),errs);
            if ( errs != 0 || height == 0 )
            {
                printf("delete bad utxoaddr files\n");
                OS_removefile(fname,0);
                OS_removefile(fname2,0);
            } else return(coin->histbalance);//iguana_RTstart(myinfo,coin,height));
        }
    }
    free(counts);
    sprintf(fname,"%s/%s/balancecrc.%d",GLOBAL_DBDIR,coin->symbol,height/coin->chain->bundlesize - 1);
    OS_removefile(fname,0);
    sprintf(fname,"%s/%s/balancecrc.%d",GLOBAL_DBDIR,coin->symbol,height/coin->chain->bundlesize - 2);
    OS_removefile(fname,0);
    printf("return neg one remove %s\n",fname);
    return(0);
}

void iguana_utxoaddrs_purge(struct iguana_info *coin)
{
    struct iguana_utxoaddr *utxoaddr,*tmp;
    coin->RTdebits = coin->RTdebits = 0;
    HASH_ITER(hh,coin->utxoaddrs,utxoaddr,tmp)
    {
        if ( utxoaddr != 0 )
        {
            utxoaddr->histbalance = 0;
            //    utxoaddr->RTcredits = utxoaddr->RTdebits = 0;
        }
    }
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"
#include "../includes/iguana_apideclares2.h"

STRING_AND_INT(iguana,snapshot,symbol,height)
{
    char fname[1024],coinaddr[64]; uint8_t pubtype,p2shtype; struct iguana_info *tmp; int32_t i,ind,num; cJSON *item,*array; struct iguana_utxoaddr UA; uint8_t *ptr;
    if ( (coin= iguana_coinfind(symbol)) != 0 )
    {
        tmp = calloc(1,sizeof(*tmp));
        sprintf(fname,"%s/%s/utxoaddrs.%d",GLOBAL_DBDIR,coin->symbol,height), OS_portable_path(fname);
        pubtype = coin->chain->pubtype;
        p2shtype = coin->chain->p2shtype;
        coin = tmp;
        if ( iguana_utxoaddr_map(coin,fname) != 0 )
        {
            if ( coin->utxoaddroffsets != 0 )
            {
                array = cJSON_CreateArray();
                memset(&UA,0,sizeof(UA));
                for (ind=0; ind<0x10000; ind++)
                {
                    if ( (num= iguana_utxotable_numinds(ind)) > 0 )
                    {
                        for (i=0; i<num; i++)
                        {
                            ptr = &coin->utxoaddrtable[(coin->utxoaddroffsets[ind] + i) * UTXOADDR_ITEMSIZE];
                            iguana_rwutxoaddr(0,ind,ptr,&UA);
                            bitcoin_address(coinaddr,UA.p2sh == 0 ? pubtype : p2shtype,UA.rmd160,sizeof(UA.rmd160));
                            item = cJSON_CreateObject();
                            jaddnum(item,coinaddr,dstr(UA.histbalance));
                            jaddi(array,item);
                        }
                    }
                }
                iguana_utxoaddr_purge(tmp);
                free(tmp);
                return(jprint(array,1));
            }
        }
    }
    return(clonestr("{\"error\":\"couldnt find snapshot file\"}"));
}

INT_ARRAY_STRING(iguana,dividends,height,vals,symbol)
{
    cJSON *array,*retjson,*item,*child,*exclude=0; int32_t i,j,n,execflag=0,flag,iter,numexcluded=0; char buf[1024],*retstr,*field,*prefix="",*suffix=""; uint64_t dustsum=0,excluded=0,total=0,dividend=0,value,val,emit=0,dust=0; double ratio = 1.;
    if ( (retstr= iguana_snapshot(0,0,0,0,symbol,height)) != 0 )
    {
        //printf("SNAPSHOT.(%s)\n",retstr);
        if ( (array= cJSON_Parse(retstr)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) != 0 )
            {
                if ( vals != 0 )
                {
                    exclude = jarray(&numexcluded,vals,"exclude");
                    dust = (uint64_t)(jdouble(vals,"dust") * SATOSHIDEN);
                    dividend = (uint64_t)(jdouble(vals,"dividend") * SATOSHIDEN);
                    if ( jstr(vals,"prefix") != 0 )
                        prefix = jstr(vals,"prefix");
                    if ( jstr(vals,"suffix") != 0 )
                        suffix = jstr(vals,"suffix");
                    execflag = jint(vals,"system");
                }
                for (iter=0; iter<2; iter++)
                {
                    for (i=0; i<n; i++)
                    {
                        flag = 0;
                        item = jitem(array,i);
                        if ( (child= item->child) != 0 )
                        {
                            value = (uint64_t)(child->valuedouble * SATOSHIDEN);
                            if ( (field= get_cJSON_fieldname(child)) != 0 )
                            {
                                for (j=0; j<numexcluded; j++)
                                    if ( strcmp(field,jstri(exclude,j)) == 0 )
                                    {
                                        flag = 1;
                                        break;
                                    }
                            }
                            //printf("(%s %s %.8f) ",jprint(item,0),field,dstr(value));
                            if ( iter == 0 )
                            {
                                if ( flag != 0 )
                                    excluded += value;
                                else total += value;
                            }
                            else
                            {
                                if ( flag == 0 )
                                {
                                    val = ratio * value;
                                    if ( val > dust )
                                    {
                                        sprintf(buf,"%s %s %.8f %s",prefix,field,dstr(val),suffix);
                                        if ( execflag != 0 )
                                        {
                                            if ( system(buf) != 0 )
                                                printf("error system.(%s)\n",buf);
                                        }
                                        else printf("%s\n",buf);
                                        emit += val;
                                    } else dustsum += val;
                                }
                            }
                        }
                    }
                    if ( iter == 0 )
                    {
                        if ( total > 0 )
                        {
                            if ( dividend == 0 )
                                dividend = total;
                            ratio = (double)dividend / total;
                        } else break;
                    }
                }
            }
            free_json(array);
        }
        free(retstr);
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"coin",symbol);
        jaddnum(retjson,"height",height);
        jaddnum(retjson,"total",dstr(total));
        jaddnum(retjson,"excluded",dstr(excluded));
        if ( dust != 0 )
            jaddnum(retjson,"dust",dstr(dust));
        if ( dustsum != 0 )
            jaddnum(retjson,"dustsum",dstr(dustsum));
        jaddnum(retjson,"dividend",dstr(dividend));
        jaddnum(retjson,"dividends",dstr(emit));
        jaddnum(retjson,"ratio",ratio);
        if ( execflag != 0 )
            jaddnum(retjson,"system",execflag);
        if ( prefix[0] != 0 )
            jaddstr(retjson,"prefix",prefix);
        if ( suffix[0] != 0 )
            jaddstr(retjson,"suffix",suffix);
        return(jprint(retjson,1));
    }
    return(clonestr("{\"error\":\"symbol not found\"}"));
}
#include "../includes/iguana_apiundefs.h"
