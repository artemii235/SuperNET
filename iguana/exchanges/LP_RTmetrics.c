
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
//  LP_RTmetrics.c
//  marketmaker
//

struct LP_metricinfo
{
    double metric;
    double price,balance,minvol;
    bits256 pubkey;
    double maxvol;
    int32_t ind,numutxos,age,pendingswaps;
};

#define LP_NUMRT 1024
struct LP_RTmetrics_pendings
{
    char refbase[128],refrel[128];
    int64_t pending_kmdvalue[LP_NUMRT];
    int32_t numswaps,numavoidtxids,numwhitelist,numblacklist,numpendings,pending_swaps[LP_NUMRT];
    bits256 avoidtxids[8192],whitelist[LP_NUMRT],blacklist[LP_NUMRT],pending_pubkeys[LP_NUMRT];
} LP_RTmetrics;

int32_t LP_bits256_find(bits256 *list,int32_t num,bits256 val)
{
    int32_t i;
    if ( bits256_nonz(val) != 0 )
    {
        for (i=0; i<num; i++)
            if ( bits256_cmp(list[i],val) == 0 )
                return(i);
    }
    return(-1);
}

int32_t LP_bits256_add(char *debugstr,bits256 *list,int32_t *nump,int32_t maxnum,bits256 val)
{
    if ( bits256_nonz(val) != 0 && *nump < maxnum )
    {
        if ( LP_bits256_find(list,*nump,val) < 0 )
            list[(*nump)++] = val;
        return(*nump);
    } else printf("%s[%d] overflow\n",debugstr,*nump);
    return(-1);
}

int32_t LP_RTmetrics_avoidadd(bits256 txid)
{
    return(LP_bits256_add("LP_RTmetrics_avoidadd avoidtxids",LP_RTmetrics.avoidtxids,&LP_RTmetrics.numavoidtxids,(int32_t)(sizeof(LP_RTmetrics.avoidtxids)/sizeof(*LP_RTmetrics.avoidtxids)),txid));
}

int32_t LP_RTmetrics_whitelistadd(bits256 pubkey)
{
    return(LP_bits256_add("LP_RTmetrics_whitelistadd whitelist",LP_RTmetrics.whitelist,&LP_RTmetrics.numwhitelist,(int32_t)(sizeof(LP_RTmetrics.whitelist)/sizeof(*LP_RTmetrics.whitelist)),pubkey));
}

int32_t LP_RTmetrics_blacklistadd(bits256 pubkey)
{
    return(LP_bits256_add("LP_RTmetrics_blacklistadd blacklist",LP_RTmetrics.blacklist,&LP_RTmetrics.numblacklist,(int32_t)(sizeof(LP_RTmetrics.blacklist)/sizeof(*LP_RTmetrics.blacklist)),pubkey));
}

int32_t LP_RTmetrics_pendingswap(bits256 pubkey,int64_t kmdvalue)
{
    int32_t ind;
    if ( (ind= LP_bits256_add("LP_RTmetrics_pendingswap",LP_RTmetrics.pending_pubkeys,&LP_RTmetrics.numpendings,(int32_t)(sizeof(LP_RTmetrics.pending_pubkeys)/sizeof(*LP_RTmetrics.pending_pubkeys)),pubkey)) >= 0 )
    {
        LP_RTmetrics.pending_swaps[ind]++;
        LP_RTmetrics.pending_kmdvalue[ind] += kmdvalue;
    }
    return(ind);
}

int32_t LP_RTmetrics_pendingswaps(bits256 pubkey)
{
    int32_t ind;
    if ( (ind= LP_bits256_find(LP_RTmetrics.pending_pubkeys,LP_RTmetrics.numpendings,pubkey)) >= 0 )
        return(LP_RTmetrics.pending_swaps[ind]);
    else return(0);
}

int32_t LP_RTmetrics_avoidtxid(bits256 txid)
{
    return(LP_bits256_find(LP_RTmetrics.avoidtxids,LP_RTmetrics.numavoidtxids,txid));
}

int32_t LP_RTmetrics_whitelisted(bits256 pubkey)
{
    return(LP_bits256_find(LP_RTmetrics.whitelist,LP_RTmetrics.numwhitelist,pubkey));
}

int32_t LP_RTmetrics_blacklisted(bits256 pubkey)
{
    return(LP_bits256_find(LP_RTmetrics.blacklist,LP_RTmetrics.numblacklist,pubkey));
}

void LP_RTmetrics_swapsinfo(char *refbase,char *refrel,cJSON *swaps,int32_t numswaps)
{
    int32_t i; char *base,*rel,*retstr; cJSON *item,*swapjson; bits256 srcpub,destpub; uint64_t aliceid,basesatoshis,relsatoshis; uint32_t requestid,quoteid; double price;
    for (i=0; i<numswaps; i++)
    {
        item = jitem(swaps,i);
        if ( (base= jstr(item,"base")) == 0 )
            base = "";
        if ( (rel= jstr(item,"rel")) == 0 )
            rel = "";
        if ( refbase[0] != 0 && strcmp(base,refbase) != 0 && strcmp(base,refrel) != 0 )
            continue;
        if ( refrel[0] != 0 && strcmp(rel,refbase) != 0 && strcmp(rel,refrel) != 0 )
            continue;
        aliceid = j64bits(item,"aliceid");
        basesatoshis = SATOSHIDEN * jdouble(item,"basevol");
        srcpub = jbits256(item,"src");
        relsatoshis = SATOSHIDEN * jdouble(item,"relvol");
        destpub = jbits256(item,"dest");
        price = jdouble(item,"price");
        requestid = juint(item,"requestid");
        quoteid = juint(item,"quoteid");
        LP_RTmetrics_pendingswap(srcpub,LP_kmdvalue(base,basesatoshis));
        LP_RTmetrics_pendingswap(destpub,LP_kmdvalue(rel,relsatoshis));
        if ( 0 && (retstr= basilisk_swapentry(1,requestid,quoteid,0)) != 0 ) // no need for this
        {
            if ( (swapjson= cJSON_Parse(retstr)) != 0 )
            {
                LP_RTmetrics_avoidadd(jbits256(swapjson,"bobdeposit"));
                LP_RTmetrics_avoidadd(jbits256(swapjson,"alicepayment"));
                LP_RTmetrics_avoidadd(jbits256(swapjson,"bobpayment"));
                LP_RTmetrics_avoidadd(jbits256(swapjson,"paymentspent"));
                LP_RTmetrics_avoidadd(jbits256(swapjson,"Apaymentspent"));
                LP_RTmetrics_avoidadd(jbits256(swapjson,"depositspent"));
                free_json(swapjson);
            }
            free(retstr);
        }
    }
}

/*void LP_RTmetrics_init()
{
    struct LP_pubkey_info *pubp,*tmp; uint32_t futuretime; int32_t i,numswaps; bits256 pubkey,zero; cJSON *statsjson,*swaps;
    memset(&LP_RTmetrics,0,sizeof(LP_RTmetrics));
    HASH_ITER(hh,LP_pubkeyinfos,pubp,tmp)
    {
        if ( pubp->istrusted > 0 )
            LP_RTmetrics_whitelistadd(pubp->pubkey);
        else if ( pubp->istrusted < 0 )
            LP_RTmetrics_blacklistadd(pubp->pubkey);
        pubp->swaps_kmdvalue = 0;
    }
    futuretime = (uint32_t)time(NULL) + 3600*100;
    memset(zero.bytes,0,sizeof(zero));
    if ( (statsjson= LP_statslog_disp(futuretime,futuretime,"",zero,0,0)) != 0 )
    {
        if ( (swaps= jarray(&numswaps,statsjson,"swaps")) != 0 )
        {
            //printf("LP_RTmetrics_update for (%s)\n",jprint(swaps,0));
            if ( numswaps > 0 )
                LP_RTmetrics_swapsinfo("","",swaps,numswaps);
        }
        free_json(statsjson);
    }
    for (i=0; i<LP_RTmetrics.numpendings; i++)
    {
        pubkey = LP_RTmetrics.pending_pubkeys[i];
        if ( LP_RTmetrics.pending_swaps[i] > LP_MAXPENDING_SWAPS )
        {
            char str[65]; printf("%s has %d pending swaps! which is more than %d\n",bits256_str(str,pubkey),LP_RTmetrics.pending_swaps[i],LP_MAXPENDING_SWAPS);
            LP_RTmetrics_blacklistadd(pubkey);
        }
        else if ( (pubp= LP_pubkeyfind(pubkey)) != 0 )
        {
            char str[65]; printf("%s has %d pending swaps %.8f kmdvalue\n",bits256_str(str,pubkey),LP_RTmetrics.pending_swaps[i],dstr(LP_RTmetrics.pending_kmdvalue[i]));
            pubp->swaps_kmdvalue = LP_RTmetrics.pending_kmdvalue[i];
        }
    }
    //printf("%d pubkeys have pending swaps, whitelist.%d blacklist.%d avoidtxids.%d\n",LP_RTmetrics.numpendings,LP_RTmetrics.numwhitelist,LP_RTmetrics.numblacklist,LP_RTmetrics.numavoidtxids);
}*/



double _LP_RTmetric_calc(struct LP_metricinfo *mp,double bestprice,double maxprice,double relvolume)
{
    int32_t n; double metric,origmetric = (mp->price / bestprice);
    metric = origmetric;
    if ( mp->numutxos == 0 || relvolume == 0. || mp->maxvol == 0. || mp->balance == 0. )
    {
        //printf("skip i.%d as no info\n",mp->ind);
        return(metric * 100.);
    }
    if ( relvolume < mp->minvol )
    {
        metric *= (mp->minvol / relvolume);
        //printf("relvolume < minvol %.8f\n",(mp->minvol / relvolume));
    }
    else if ( relvolume > mp->maxvol )
    {
        metric *= (relvolume / mp->maxvol);
        //printf("relvolume > minvol %.8f\n",(relvolume / mp->maxvol));
    }
    if ( relvolume < mp->balance/LP_MINVOL )
    {
        metric *= (mp->balance / relvolume);
        //printf("relvolume < balance %.8f\n",(mp->balance / relvolume));
    }
    else if ( relvolume > mp->balance/mp->numutxos )
    {
        metric *= (relvolume / (mp->balance/mp->numutxos));
        //printf("relvolume < ave %.8f\n",(relvolume / (mp->balance/mp->numutxos)));
    }
    if ( mp->age > LP_ORDERBOOK_DURATION*0.8 )
        metric *= 2;
    else if ( mp->age > 60 )
        metric *= 1.03;
    if ( (n= mp->pendingswaps) > 0 )
        while ( n-- > 0 )
            metric *= 1.1;
    //if ( metric != origmetric )
        printf("i.%d price %.8f orig %.8f -> %.8f relvol %.8f min %.8f max %.8f bal %.8f age.%d pend.%d\n",mp->ind,mp->price,origmetric,metric,relvolume,mp->minvol,mp->maxvol,mp->balance,mp->age,mp->pendingswaps);
    return(metric);
}

void LP_RTmetric_calc(struct LP_metricinfo *sortbuf,int32_t ind,cJSON *item,double bestprice,double maxprice,double relvolume,double prevdepth)
{
    sortbuf[ind].pubkey = jbits256(item,"pubkey");
    sortbuf[ind].price = jdouble(item,"price");
    sortbuf[ind].maxvol = jdouble(item,"maxvolume");
    sortbuf[ind].minvol = jdouble(item,"minvolume");
    sortbuf[ind].balance = jdouble(item,"depth") - prevdepth;
    sortbuf[ind].numutxos = juint(item,"numutxos");
    sortbuf[ind].age = juint(item,"age");
    sortbuf[ind].ind = ind;
    sortbuf[ind].pendingswaps = LP_RTmetrics_pendingswaps(sortbuf[ind].pubkey);
    sortbuf[ind].metric = _LP_RTmetric_calc(&sortbuf[ind],bestprice,maxprice,relvolume);
}

int _increasing_metrics(const void *a,const void *b)
{
#define ptr_a ((struct LP_metricinfo *)a)
#define ptr_b ((struct LP_metricinfo *)b)
    if ( ptr_b->metric > ptr_a->metric )
        return(-1);
    else if ( ptr_b->metric < ptr_a->metric )
        return(1);
    return(0);
#undef ptr_a
#undef ptr_b
}

cJSON *LP_RTmetrics_sort(char *base,char *rel,cJSON *rawasks,int32_t numasks,double maxprice,double relvolume)
{
    cJSON *array=rawasks,*item; int32_t i,num,groupi; double price,prevdepth,bestprice; struct LP_metricinfo *sortbuf;
    groupi = -1;
    bestprice = 0.;
    for (num=i=0; i<numasks; i++)
    {
        item = jitem(rawasks,i);
        price = jdouble(item,"price");
        if ( price > maxprice )
            break;
        if ( i == 0 )
            bestprice = price;
        else if ( price < bestprice*LP_RTMETRICS_TOPGROUP )
            groupi = i;
        num++;
    }
    if ( groupi > 0 )
    {
        sortbuf = calloc(groupi+1,sizeof(*sortbuf));
        prevdepth = 0.;
        for (i=0; i<=groupi; i++)
        {
            item = jitem(rawasks,i);
            LP_RTmetric_calc(sortbuf,i,item,bestprice,maxprice,relvolume,prevdepth);
            prevdepth = jdouble(item,"depth");
            //printf("%.8f ",sortbuf[i].metric);
        }
        qsort(&sortbuf[0].metric,groupi+1,sizeof(*sortbuf),_increasing_metrics);
        array = cJSON_CreateArray();
        for (i=0; i<=groupi; i++)
        {
            printf("(%d <- %d %.3f) ",i,sortbuf[i].ind,sortbuf[i].metric);
            item = jitem(rawasks,sortbuf[i].ind);
            jaddi(array,jduplicate(item));
        }
        for (; i<numasks; i++)
            jaddi(array,jduplicate(jitem(rawasks,i)));
        printf("new ask order for %d of %d, capped at num.%d\n",groupi,numasks,num);
        free(sortbuf);
    }
    return(array);
}
