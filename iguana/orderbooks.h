/******************************************************************************
 * Copyright © 2014-2016 The SuperNET Developers.                             *
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


#ifndef xcode_orderbooks_h
#define xcode_orderbooks_h

char *peggy_contracts[64] =
{
    "BTCD", "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD", // major currencies
    "CNY", "RUB", "MXN", "BRL", "INR", "HKD", "TRY", "ZAR", "PLN", "NOK", "SEK", "DKK", "CZK", "HUF", "ILS", "KRW", "MYR", "PHP", "RON", "SGD", "THB", "BGN", "IDR", "HRK",
    "BTCUSD", "NXTBTC", "SuperNET", "ETHBTC", "LTCBTC", "XMRBTC", "BTSBTC", "XCPBTC",  // BTC priced
    "XAUUSD", "XAGUSD", "XPTUSD", "XPDUSD", "Copper", "NGAS", "UKOil", "USOil", // USD priced
    "Bund", "NAS100", "SPX500", "US30", "EUSTX50", "UK100", "JPN225", "GER30", "SUI30", "AUS200", "HKG33", "XAUUSD", "BTCRUB", "BTCCNY", "BTCUSD" // abstract
};

char *MGWassets[][3] =
{
    { "12659653638116877017", "BTC", "8" },
    { "17554243582654188572", "BTC", "8" }, // assetid, name, decimals
    { "4551058913252105307", "BTC", "8" },
    { "6918149200730574743", "BTCD", "4" },
    { "11060861818140490423", "BTCD", "4" },
    { "13120372057981370228", "BITS", "6" },
    { "16344939950195952527", "DOGE", "4" },
    { "2303962892272487643", "DOGE", "4" },
    { "6775076774325697454", "OPAL", "8" },
    { "7734432159113182240", "VPN", "4" },
    { "9037144112883608562", "VRC", "8" },
    { "1369181773544917037", "BBR", "8" },
    { "17353118525598940144", "DRK", "8" },
    { "2881764795164526882", "LTC", "4" },
    { "7117580438310874759", "BC", "4" },
    { "275548135983837356", "VIA", "4" },
    { "6220108297598959542", "CNMT", "0" },
    { "7474435909229872610", "CNMT", "0" },
};

char *Tradedassets[][4] =
{
    { "6220108297598959542", "CNMT", "0", "poloniex" },
    { "7474435909229872610", "CNMT", "0", "poloniex" },
    { "979292558519844732", "MMNXT", "0", "poloniex" },
    { "12982485703607823902", "XUSD", "0", "poloniex" },
    { "13634675574519917918", "INDEX", "0", "poloniex" },
    { "6932037131189568014", "JLH", "0", "poloniex" },
    { "14273984620270850703", "NXTI", "0", "poloniex" },
    { "12071612744977229797", "UNITY", "4", "poloniex" },
};

char *is_tradedasset(char *exchange,char *assetidstr)
{
    int32_t i;
    for (i=0; i<(int32_t)(sizeof(Tradedassets)/sizeof(*Tradedassets)); i++)
        if ( strcmp(Tradedassets[i][0],assetidstr) == 0 )
        {
            strcpy(exchange,Tradedassets[i][3]);
            return(Tradedassets[i][1]);
        }
    return(0);
}

uint64_t is_MGWcoin(char *name)
{
    int32_t i;
    for (i=0; i<(int32_t)(sizeof(MGWassets)/sizeof(*MGWassets)); i++)
        if ( strcmp(MGWassets[i][1],name) == 0 )
            return(calc_nxt64bits(MGWassets[i][0]));
    return(0);
}

char *is_MGWasset(uint64_t assetid)
{
    int32_t i; char assetidstr[64];
    expand_nxt64bits(assetidstr,assetid);
    for (i=0; i<(int32_t)(sizeof(MGWassets)/sizeof(*MGWassets)); i++)
        if ( strcmp(MGWassets[i][0],assetidstr) == 0 )
            return(MGWassets[i][1]);
    return(0);
}

uint64_t prices777_equiv(uint64_t assetid)
{
    char *str;
    if ( (str= is_MGWasset(assetid)) != 0 )
        return(stringbits(str));
    return(assetid);
}

struct prices777 *prices777_find(int32_t *invertedp,uint64_t baseid,uint64_t relid,char *exchange)
{
    int32_t i; struct prices777 *prices;
    *invertedp = 0;
    for (i=0; i<BUNDLE.num; i++)
    {
        if ( (prices= BUNDLE.ptrs[i]) != 0 && strcmp(prices->exchange,exchange) == 0 )
        {
            //printf("FOUND.(%s)\n",exchange);
            if ( prices777_equiv(prices->baseid) == prices777_equiv(baseid) && prices777_equiv(prices->relid) == prices777_equiv(relid) )
                return(prices);
            else if ( prices777_equiv(prices->relid) == prices777_equiv(baseid) && prices777_equiv(prices->baseid) == prices777_equiv(relid) )
            {
                *invertedp = 1;
                return(prices);
            }
            //else printf("(%llu/%llu) != (%llu/%llu)\n",(long long)baseid,(long long)relid,(long long)prices->baseid,(long long)prices->relid);
        } //else fprintf(stderr,"(%s).%d ",prices->exchange,i);
    }
    //printf("CANTFIND.(%s) %llu/%llu\n",exchange,(long long)baseid,(long long)relid);
    return(0);
}

struct prices777 *prices777_createbasket(int32_t addbasket,char *name,char *base,char *rel,uint64_t baseid,uint64_t relid,struct prices777_basket *basket,int32_t n,char *typestr)
{
    int32_t i,j,m,iter,max = 0; double firstwt,wtsum; struct prices777 *prices,*feature;
    printf("createbasket.%s n.%d (%s/%s)\n",typestr,n,base,rel);
    prices = prices777_initpair(1,typestr,base,rel,0.,name,baseid,relid,n);
    for (iter=0; iter<2; iter++)
    {
        for (i=0; i<n; i++)
        {
            feature = basket[i].prices;
            if ( addbasket*iter != 0 )
            {
                feature->dependents = realloc(feature->dependents,sizeof(*feature->dependents) * (feature->numdependents + 1));
                feature->dependents[feature->numdependents++] = &prices->changed;
                printf("%p i.%d/%d addlink.%s groupid.%d wt.%f (%s.%llu/%llu -> %s.%llu/%llu).%s\n",feature,i,n,feature->exchange,basket[i].groupid,basket[i].wt,feature->contract,(long long)feature->baseid,(long long)feature->relid,prices->contract,(long long)prices->baseid,(long long)prices->relid,prices->exchange);
            }
            if ( basket[i].groupid > max )
                max = basket[i].groupid;
            if ( fabs(basket[i].wt) < SMALLVAL )
            {
                printf("all basket features.%s i.%d must have nonzero wt\n",feature->contract,i);
                free(prices);
                return(0);
            }
            if ( strcmp(feature->base,feature->rel) == 0 || feature->baseid == feature->relid )
            {
                printf("base rel cant be the same (%s %s) %llu %llu\n",feature->base,feature->rel,(long long)feature->baseid,(long long)feature->relid);
                free(prices);
                return(0);
            }
        }
        if ( (max+1) > MAX_GROUPS )
        {
            printf("baskets limited to %d, %d is too many for %s.(%s/%s)\n",MAX_GROUPS,n,name,base,rel);
            return(0);
        }
    }
    prices->numgroups = (max + 1);
    for (j=0; j<prices->numgroups; j++)
    {
        for (firstwt=i=m=0; i<n; i++)
        {
            //printf("i.%d groupid.%d wt %f m.%d\n",i,basket[i].groupid,basket[i].wt,m);
            if ( basket[i].groupid == j )
            {
                if ( firstwt == 0. )
                    prices->groupwts[j] = firstwt = basket[i].wt;
                else if ( basket[i].wt != firstwt )
                {
                    printf("warning features of same group.%d different wt: %d %f != %f\n",j,i,firstwt,basket[i].wt);
                    // free(prices);
                    // return(0);
                }
                m++;
            }
        }
        //printf("m.%d\n",m);
        for (i=0; i<n; i++)
            if ( basket[i].groupid == j )
                basket[i].groupsize = m, printf("basketsize.%d n.%d j.%d groupsize[%d] <- m.%d\n",prices->basketsize,n,j,i,m);
    }
    for (j=0; j<prices->numgroups; j++)
        for (i=0; i<n; i++)
            if ( basket[i].groupid == j )
                prices->basket[prices->basketsize++] = basket[i];
    for (i=-1; i<=1; i+=2)
    {
        for (wtsum=j=m=0; j<prices->numgroups; j++)
        {
            if ( prices->groupwts[j]*i > 0 )
                wtsum += prices->groupwts[j], m++;
        }
        if ( 0 && wtsum != 0. )
        {
            if ( wtsum < 0. )
                wtsum = -wtsum;
            for (j=0; j<prices->numgroups; j++)
                prices->groupwts[j] /= wtsum;
        }
    }
    if ( prices->numgroups == 1 )
        prices->groupwts[0] = 1.;
    for (j=0; j<prices->numgroups; j++)
        printf("%9.6f ",prices->groupwts[j]);
    printf("groupwts %s\n",typestr);
    return(prices);
}

double prices777_price_volume(double *volumep,uint64_t baseamount,uint64_t relamount)
{
    *volumep = (((double)baseamount + 0.000000009999999) / SATOSHIDEN);
    if ( baseamount > 0. )
        return((double)relamount / (double)baseamount);
    else return(0.);
}

void prices777_best_amounts(uint64_t *baseamountp,uint64_t *relamountp,double price,double volume)
{
    double checkprice,checkvol,distA,distB,metric,bestmetric = (1. / SMALLVAL);
    uint64_t baseamount,relamount,bestbaseamount = 0,bestrelamount = 0;
    int32_t i,j;
    baseamount = volume * SATOSHIDEN;
    relamount = ((price * volume) * SATOSHIDEN);
    //*baseamountp = baseamount, *relamountp = relamount;
    //return;
    for (i=-1; i<=1; i++)
        for (j=-1; j<=1; j++)
        {
            checkprice = prices777_price_volume(&checkvol,baseamount+i,relamount+j);
            distA = (checkprice - price);
            distA *= distA;
            distB = (checkvol - volume);
            distB *= distB;
            metric = sqrt(distA + distB);
            if ( metric < bestmetric )
            {
                bestmetric = metric;
                bestbaseamount = baseamount + i;
                bestrelamount = relamount + j;
                //printf("i.%d j.%d metric. %f\n",i,j,metric);
            }
        }
    *baseamountp = bestbaseamount;
    *relamountp = bestrelamount;
}

void prices777_additem(cJSON **highbidp,cJSON **lowaskp,cJSON *bids,cJSON *asks,int32_t ind,cJSON *item,int32_t bidask)
{
    if ( bidask == 0 )
    {
        cJSON_AddItemToArray(bids,item);
        if ( ind == 0 )
            *highbidp = item;
    }
    else
    {
        cJSON_AddItemToArray(asks,item);
        if ( ind == 0 )
            *lowaskp = item;
    }
}

uint64_t calc_qty(uint64_t mult,uint64_t assetid,uint64_t amount)
{
    if ( assetid != NXT_ASSETID )
        return(amount / mult);
    else return(amount);
}

int32_t verify_NXTtx(cJSON *json,uint64_t refasset,uint64_t qty,uint64_t destNXTbits)
{
    int32_t typeval,subtypeval,n = 0;
    uint64_t quantity,price,assetidbits;
    cJSON *attachmentobj;
    char sender[MAX_JSON_FIELD],recipient[MAX_JSON_FIELD],deadline[MAX_JSON_FIELD],feeNQT[MAX_JSON_FIELD],amountNQT[MAX_JSON_FIELD],type[MAX_JSON_FIELD],subtype[MAX_JSON_FIELD],verify[MAX_JSON_FIELD],referencedTransaction[MAX_JSON_FIELD],quantityQNT[MAX_JSON_FIELD],priceNQT[MAX_JSON_FIELD],assetidstr[MAX_JSON_FIELD],sighash[MAX_JSON_FIELD],fullhash[MAX_JSON_FIELD],timestamp[MAX_JSON_FIELD],transaction[MAX_JSON_FIELD];
    if ( json == 0 )
    {
        printf("verify_NXTtx cant parse json\n");
        return(-1);
    }
    if ( extract_cJSON_str(sender,sizeof(sender),json,"sender") > 0 ) n++;
    if ( extract_cJSON_str(recipient,sizeof(recipient),json,"recipient") > 0 ) n++;
    if ( extract_cJSON_str(referencedTransaction,sizeof(referencedTransaction),json,"referencedTransactionFullHash") > 0 ) n++;
    if ( extract_cJSON_str(amountNQT,sizeof(amountNQT),json,"amountNQT") > 0 ) n++;
    if ( extract_cJSON_str(feeNQT,sizeof(feeNQT),json,"feeNQT") > 0 ) n++;
    if ( extract_cJSON_str(deadline,sizeof(deadline),json,"deadline") > 0 ) n++;
    if ( extract_cJSON_str(type,sizeof(type),json,"type") > 0 ) n++;
    if ( extract_cJSON_str(subtype,sizeof(subtype),json,"subtype") > 0 ) n++;
    if ( extract_cJSON_str(verify,sizeof(verify),json,"verify") > 0 ) n++;
    if ( extract_cJSON_str(sighash,sizeof(sighash),json,"signatureHash") > 0 ) n++;
    if ( extract_cJSON_str(fullhash,sizeof(fullhash),json,"fullHash") > 0 ) n++;
    if ( extract_cJSON_str(timestamp,sizeof(timestamp),json,"timestamp") > 0 ) n++;
    if ( extract_cJSON_str(transaction,sizeof(transaction),json,"transaction") > 0 ) n++;
    if ( calc_nxt64bits(recipient) != destNXTbits )
    {
        if ( Debuglevel > 2 )
            fprintf(stderr,"recipient.%s != %llu\n",recipient,(long long)destNXTbits);
        return(-2);
    }
    typeval = myatoi(type,256), subtypeval = myatoi(subtype,256);
    if ( refasset == NXT_ASSETID )
    {
        if ( typeval != 0 || subtypeval != 0 )
        {
            fprintf(stderr,"unexpected typeval.%d subtypeval.%d\n",typeval,subtypeval);
            return(-3);
        }
        if ( qty != calc_nxt64bits(amountNQT) )
        {
            fprintf(stderr,"unexpected qty.%llu vs.%s\n",(long long)qty,amountNQT);
            return(-4);
        }
        return(0);
    }
    else
    {
        if ( typeval != 2 || subtypeval != 1 )
        {
            if ( Debuglevel > 2 )
                fprintf(stderr,"refasset.%llu qty %lld\n",(long long)refasset,(long long)qty);
            return(-11);
        }
        price = quantity = assetidbits = 0;
        attachmentobj = cJSON_GetObjectItem(json,"attachment");
        if ( attachmentobj != 0 )
        {
            if ( extract_cJSON_str(assetidstr,sizeof(assetidstr),attachmentobj,"asset") > 0 )
                assetidbits = calc_nxt64bits(assetidstr);
            //else if ( extract_cJSON_str(assetidstr,sizeof(assetidstr),attachmentobj,"currency") > 0 )
            //    assetidbits = calc_nxt64bits(assetidstr);
            if ( extract_cJSON_str(quantityQNT,sizeof(quantityQNT),attachmentobj,"quantityQNT") > 0 )
                quantity = calc_nxt64bits(quantityQNT);
            //else if ( extract_cJSON_str(quantityQNT,sizeof(quantityQNT),attachmentobj,"units") > 0 )
            //    quantity = calc_nxt64bits(quantityQNT);
            if ( extract_cJSON_str(priceNQT,sizeof(priceNQT),attachmentobj,"priceNQT") > 0 )
                price = calc_nxt64bits(priceNQT);
        }
        if ( assetidbits != refasset )
        {
            fprintf(stderr,"assetidbits %llu != %llu refasset\n",(long long)assetidbits,(long long)refasset);
            return(-12);
        }
        if ( qty != quantity )
        {
            fprintf(stderr,"qty.%llu != %llu\n",(long long)qty,(long long)quantity);
            return(-13);
        }
        return(0);
    }
    return(-1);
}

int32_t InstantDEX_verify(uint64_t destNXTaddr,uint64_t sendasset,uint64_t sendqty,cJSON *txobj,uint64_t recvasset,uint64_t recvqty)
{
    int32_t err;
    // verify recipient, amounts in txobj
     if ( (err= verify_NXTtx(txobj,recvasset,recvqty,destNXTaddr)) != 0 )
    {
        if ( Debuglevel > 2 )
            printf("InstantDEX_verify dest.(%llu) tx mismatch %d (%llu %lld) -> (%llu %lld)\n",(long long)destNXTaddr,err,(long long)sendasset,(long long)sendqty,(long long)recvasset,(long long)recvqty);
        return(-1);
    }
    return(0);
}

cJSON *wallet_swapjson(char *recv,uint64_t recvasset,char *send,uint64_t sendasset,uint64_t orderid,uint64_t quoteid)
{
    return(cJSON_Parse(clonestr("{\"error\":\"notyet\"}")));
#ifdef notyet
    int32_t iter; uint64_t assetid; struct coin777 *coin; struct InstantDEX_quote *iQ;
    char account[128],walletstr[512],*addr,*str; cJSON *walletitem = 0;
    printf("wallet_swapjson is not yet\n");
    if ( (iQ= find_iQ(quoteid)) != 0 && iQ->s.wallet != 0 )
    {
        walletitem = cJSON_Parse(iQ->walletstr);
        //printf("start with (%s)\n",iQ->walletstr);
    }
    for (iter=0; iter<2; iter++)
    {
        addr = 0;
        str = (iter == 0) ? recv : send;
        assetid = (iter == 0) ? recvasset : sendasset;
        if ( (coin= coin777_find(str,1)) != 0 )
        {
            if ( is_NXT_native(assetid) == 0 )
            {
                if ( (walletitem= set_walletstr(walletitem,walletstr,iQ)) != 0 )
                {
                    
                }
            } // else printf("%s is NXT\n",coin->name);
            if ( is_NXT_native(assetid) != 0 )
                addr = SUPERNET.NXTADDR;
            else
            {
                addr = (iter == 0) ? coin->atomicrecv : coin->atomicsend;
                if ( addr[0] == 0 )
                    addr = get_acct_coinaddr(addr,str,coin->serverport,coin->userpass,account);
            }
            if ( addr != 0 )
            {
            } else printf("%s no addr\n",coin->name);
        } else printf("cant find coin.(%s)\n",iter == 0 ? recv : send);
    }
    if ( walletitem == 0 )
        walletitem = cJSON_CreateObject(), jaddstr(walletitem,"error","cant find local coin daemons");
    return(walletitem);
#endif
}

void _prices777_item(cJSON *item,int32_t group,struct prices777 *prices,int32_t bidask,double price,double volume,uint64_t orderid,uint64_t quoteid)
{
    uint64_t baseqty,relqty; int32_t iswallet = 0; char basec,relc; struct InstantDEX_quote *iQ;
    jaddnum(item,"group",group);
    jaddstr(item,"exchange",prices->exchange);
    jaddstr(item,"base",prices->base), jaddstr(item,"rel",prices->rel);
    if ( (iQ= find_iQ(quoteid)) != 0 )
        jadd64bits(item,"offerNXT",iQ->s.offerNXT);
    if ( strcmp(prices->exchange,"nxtae") == 0 || strcmp(prices->exchange,"unconf") == 0 || strcmp(prices->exchange,"InstantDEX") == 0 || strcmp(prices->exchange,"wallet") == 0 )
    {
        jadd64bits(item,prices->type == 5 ? "currency" : "asset",prices->baseid);
        //else if ( quoteid != 0 ) printf("cant find offerNXT.%llu\n",(long long)quoteid);
        jadd64bits(item,"baseid",prices->baseid), jadd64bits(item,"relid",prices->relid);
        iswallet = (strcmp(prices->exchange,"wallet") == 0);
        if ( strcmp(prices->exchange,"InstantDEX") == 0 || iswallet != 0 )
        {
            jaddstr(item,"trade","swap");
            baseqty = calc_qty(prices->basemult,prices->baseid,SATOSHIDEN * volume + 0.5/SATOSHIDEN);
            //printf("baseid.%llu basemult.%llu -> %llu\n",(long long)prices->baseid,(long long)prices->basemult,(long long)baseqty);
            relqty = calc_qty(prices->relmult,prices->relid,SATOSHIDEN * volume * price + 0.5/SATOSHIDEN);
            if ( bidask != 0 )
            {
                basec = '+', relc = '-';
                jadd64bits(item,"recvbase",baseqty);
                jadd64bits(item,"sendrel",relqty);
                if ( iswallet != 0 )
                    jadd(item,"wallet",wallet_swapjson(prices->base,prices->baseid,prices->rel,prices->relid,orderid,quoteid));
            }
            else
            {
                basec = '-', relc = '+';
                jadd64bits(item,"sendbase",baseqty);
                jadd64bits(item,"recvrel",relqty);
                if ( iswallet != 0 )
                    jadd(item,"wallet",wallet_swapjson(prices->rel,prices->relid,prices->base,prices->baseid,orderid,quoteid));
            }
            //printf("(%s %cbaseqty.%llu <-> %s %crelqty.%llu) basemult.%llu baseid.%llu vol %f amount %llu\n",prices->base,basec,(long long)baseqty,prices->rel,relc,(long long)relqty,(long long)prices->basemult,(long long)prices->baseid,volume,(long long)volume*SATOSHIDEN);
        }
        else
        {
            //printf("alternate path\n");
            jaddstr(item,"trade",bidask == 0 ? "sell" : "buy");
        }
    }
    else
    {
        //printf("alternate path\n");
        jaddstr(item,"trade",bidask == 0 ? "sell" : "buy");
        jaddstr(item,"name",prices->contract);
    }
    jaddnum(item,"orderprice",price);
    jaddnum(item,"ordervolume",volume);
    if ( orderid != 0 )
        jadd64bits(item,"orderid",orderid);
    if ( quoteid != 0 )
        jadd64bits(item,"quoteid",quoteid);
}

cJSON *prices777_item(int32_t rootbidask,struct prices777 *prices,int32_t group,int32_t bidask,double origprice,double origvolume,double rootwt,double groupwt,double wt,uint64_t orderid,uint64_t quoteid)
{
    cJSON *item; double price,volume,oppo = 1.;
    item = cJSON_CreateObject();
    jaddstr(item,"basket",rootbidask == 0 ? "bid":"ask");
    //jaddnum(item,"rootwt",rootwt);
    //jaddnum(item,"groupwt",groupwt);
    //jaddnum(item,"wt",wt);
    if ( wt*groupwt < 0. )
        oppo = -1.;
    if ( wt*groupwt < 0 )
    {
        volume = origprice * origvolume;
        price = 1./origprice;
    } else price = origprice, volume = origvolume;
    jaddnum(item,"price",price);
    jaddnum(item,"volume",volume);
    if ( groupwt*wt < 0 )
    {
        volume = origprice * origvolume;
        price = 1./origprice;
    } else price = origprice, volume = origvolume;
    _prices777_item(item,group,prices,bidask,price,volume,orderid,quoteid);
    return(item);
}

cJSON *prices777_tradeitem(int32_t rootbidask,struct prices777 *prices,int32_t group,int32_t bidask,int32_t slot,uint32_t timestamp,double price,double volume,double rootwt,double groupwt,double wt,uint64_t orderid,uint64_t quoteid)
{
    static uint32_t match,error;
    if ( prices->O.timestamp == timestamp )
    {
        //printf("tradeitem.(%s %f %f)\n",prices->exchange,price,volume);
        if ( bidask == 0 && prices->O.book[MAX_GROUPS][slot].bid.s.price == price && prices->O.book[MAX_GROUPS][slot].bid.s.vol == volume )
            match++;
        else if ( bidask != 0 && prices->O.book[MAX_GROUPS][slot].ask.s.price == price && prices->O.book[MAX_GROUPS][slot].ask.s.vol == volume )
            match++;
    }
    else if ( prices->O2.timestamp == timestamp )
    {
        //printf("2tradeitem.(%s %f %f)\n",prices->exchange,price,volume);
        if ( bidask == 0 && prices->O2.book[MAX_GROUPS][slot].bid.s.price == price && prices->O2.book[MAX_GROUPS][slot].bid.s.vol == volume )
            match++;
        else if ( bidask != 0 && prices->O2.book[MAX_GROUPS][slot].ask.s.price == price && prices->O2.book[MAX_GROUPS][slot].ask.s.vol == volume )
            match++;
    } else error++, printf("mismatched tradeitem error.%d match.%d\n",error,match);
    return(prices777_item(rootbidask,prices,group,bidask,price,volume,rootwt,groupwt,wt,orderid,quoteid));
}

cJSON *prices777_tradesequence(struct prices777 *prices,int32_t bidask,struct prices777_order *orders[],double rootwt,double groupwt,double wt,int32_t refgroup)
{
    int32_t i,j,srcslot,srcbidask,err = 0; cJSON *array; struct prices777_order *suborders[MAX_GROUPS];
    struct prices777_order *order; struct prices777 *src;
    array = cJSON_CreateArray();
    for (i=0; i<prices->numgroups; i++)
    {
        order = orders[i];
        groupwt = prices->groupwts[i];
        memset(suborders,0,sizeof(suborders));
        srcbidask = (order->slot_ba & 1); srcslot = order->slot_ba >> 1;
        if ( (src= order->source) != 0 )
        {
            if ( src->basketsize == 0 )
                jaddi(array,prices777_tradeitem(bidask,src,refgroup*10+i,srcbidask,srcslot,order->s.timestamp,order->s.price,order->ratio*order->s.vol,rootwt,groupwt/groupwt,order->wt,order->id,order->s.quoteid));
            else if ( src->O.timestamp == order->s.timestamp )
            {
                for (j=0; j<src->numgroups; j++)
                    suborders[j] = (srcbidask == 0) ? &src->O.book[j][srcslot].bid : &src->O.book[j][srcslot].ask;
                jaddi(array,prices777_tradesequence(src,bidask,suborders,rootwt,groupwt/groupwt,order->wt,refgroup*10 + i));
            }
            else if ( src->O2.timestamp == order->s.timestamp )
            {
                for (j=0; j<src->numgroups; j++)
                    suborders[j] = (srcbidask == 0) ? &src->O2.book[j][srcslot].bid : &src->O2.book[j][srcslot].ask;
                jaddi(array,prices777_tradesequence(src,bidask,suborders,rootwt,groupwt/groupwt,order->wt,refgroup*10 + i));
            }
            else err =  1;
        }
        if ( src == 0 || err != 0 )
        {
            //jaddi(array,prices777_item(prices,bidask,price,volume,wt,orderid));
            //printf("prices777_tradesequence warning cant match timestamp %u (%s %s/%s)\n",order->timestamp,prices->contract,prices->base,prices->rel);
        }
    }
    return(array);
}

void prices777_orderbook_item(struct prices777 *prices,int32_t bidask,struct prices777_order *suborders[],cJSON *array,int32_t invert,int32_t allflag,double origprice,double origvolume,uint64_t orderid,uint64_t quoteid)
{
    cJSON *item,*obj,*tarray,*walletitem; double price,volume; struct InstantDEX_quote *iQ;
    item = cJSON_CreateObject();
    if ( invert != 0 )
        volume = (origvolume * origprice), price = 1./origprice;
    else price = origprice, volume = origvolume;
    if ( strcmp(prices->exchange,"jumblr") == 0 || strcmp(prices->exchange,"pangea") == 0 )
    {
        jaddstr(item,"plugin",prices->exchange), jaddstr(item,"method","start");
        jaddnum(item,"dotrade",1), jaddnum(item,"volume",volume);
        jaddnum(item,"timeout",20000);
        jaddstr(item,"base",prices->base);
        if ( (iQ= find_iQ(quoteid)) != 0 )
            jadd64bits(item,"offerNXT",iQ->s.offerNXT);
        jadd64bits(item,"quoteid",iQ->s.quoteid);
        if ( strcmp(prices->exchange,"pangea") == 0 && iQ->s.wallet != 0 && (walletitem= cJSON_Parse(iQ->walletstr)) != 0 )
            jadd(item,"wallet",walletitem);
        jaddi(array,item);
        return;
    }
    jaddstr(item,"plugin","InstantDEX"), jaddstr(item,"method","tradesequence");
    jaddnum(item,"dotrade",1), jaddnum(item,"price",price), jaddnum(item,"volume",volume);
    //jaddnum(item,"invert",invert), jaddnum(item,"origprice",origprice), jaddnum(item,"origvolume",origvolume);
    //jaddstr(item,"base",prices->base), jaddstr(item,"rel",prices->rel);
    if ( allflag != 0 )
    {
        if ( prices->basketsize == 0 )
        {
            tarray = cJSON_CreateArray();
            obj = cJSON_CreateObject();
            _prices777_item(obj,0,prices,bidask,origprice,origvolume,orderid,quoteid);
            jaddi(tarray,obj);
        } else tarray = prices777_tradesequence(prices,bidask,suborders,invert!=0?-1:1.,1.,1.,0);
        jadd(item,"trades",tarray);
    }
    jaddi(array,item);
}

char *prices777_orderbook_jsonstr(int32_t invert,uint64_t nxt64bits,struct prices777 *prices,struct prices777_basketinfo *OB,int32_t maxdepth,int32_t allflag)
{
    struct prices777_orderentry *gp; struct prices777_order *suborders[MAX_GROUPS]; cJSON *json,*bids,*asks;
    int32_t i,slot; char baserel[64],base[64],rel[64],assetA[64],assetB[64],NXTaddr[64];
    if ( invert == 0 )
        sprintf(baserel,"%s/%s",prices->base,prices->rel);
    else sprintf(baserel,"%s/%s",prices->rel,prices->base);
    if ( Debuglevel > 2 )
        printf("ORDERBOOK %s/%s iQsize.%ld numbids.%d numasks.%d maxdepth.%d (%llu %llu)\n",prices->base,prices->rel,(long)sizeof(struct InstantDEX_quote),OB->numbids,OB->numasks,maxdepth,(long long)prices->baseid,(long long)prices->relid);
    json = cJSON_CreateObject(), bids = cJSON_CreateArray(), asks = cJSON_CreateArray();
    gp = &OB->book[MAX_GROUPS][0];
    memset(suborders,0,sizeof(suborders));
    for (slot=0; (slot<OB->numbids || slot<OB->numasks) && slot<maxdepth; slot++,gp++)
    {
        //printf("slot.%d\n",slot);
        if ( slot < OB->numbids )
        {
            for (i=0; i<prices->numgroups; i++)
                suborders[i] = &OB->book[i][slot].bid;
            prices777_orderbook_item(prices,0,suborders,(invert==0) ? bids : asks,invert,allflag,gp->bid.s.price,gp->bid.s.vol,gp->bid.id,gp->bid.s.quoteid);
        }
        if ( slot < OB->numasks )
        {
            for (i=0; i<prices->numgroups; i++)
                suborders[i] = &OB->book[i][slot].ask;
            prices777_orderbook_item(prices,1,suborders,(invert==0) ? asks : bids,invert,allflag,gp->ask.s.price,gp->ask.s.vol,gp->ask.id,gp->ask.s.quoteid);
        }
    }
    expand_nxt64bits(NXTaddr,nxt64bits);
    if ( invert != 0 )
        strcpy(base,prices->rel), strcpy(rel,prices->base);
    else strcpy(base,prices->base), strcpy(rel,prices->rel);
    expand_nxt64bits(assetA,invert==0 ? prices->baseid : prices->relid);
    expand_nxt64bits(assetB,invert!=0 ? prices->baseid : prices->relid);
    cJSON_AddItemToObject(json,"exchange",cJSON_CreateString(prices->exchange));
    cJSON_AddItemToObject(json,"inverted",cJSON_CreateNumber(invert));
    cJSON_AddItemToObject(json,"contract",cJSON_CreateString(prices->contract));
    cJSON_AddItemToObject(json,"baseid",cJSON_CreateString(assetA));
    if ( assetB[0] != 0 )
        cJSON_AddItemToObject(json,"relid",cJSON_CreateString(assetB));
    cJSON_AddItemToObject(json,"base",cJSON_CreateString(base));
    if ( rel[0] != 0 )
        cJSON_AddItemToObject(json,"rel",cJSON_CreateString(rel));
    cJSON_AddItemToObject(json,"bids",bids);
    cJSON_AddItemToObject(json,"asks",asks);
    if ( invert == 0 )
    {
        cJSON_AddItemToObject(json,"numbids",cJSON_CreateNumber(OB->numbids));
        cJSON_AddItemToObject(json,"numasks",cJSON_CreateNumber(OB->numasks));
        cJSON_AddItemToObject(json,"lastbid",cJSON_CreateNumber(prices->lastbid));
        cJSON_AddItemToObject(json,"lastask",cJSON_CreateNumber(prices->lastask));
    }
    else
    {
        cJSON_AddItemToObject(json,"numbids",cJSON_CreateNumber(OB->numasks));
        cJSON_AddItemToObject(json,"numasks",cJSON_CreateNumber(OB->numbids));
        if ( prices->lastask != 0 )
            cJSON_AddItemToObject(json,"lastbid",cJSON_CreateNumber(1. / prices->lastask));
        if ( prices->lastbid != 0 )
            cJSON_AddItemToObject(json,"lastask",cJSON_CreateNumber(1. / prices->lastbid));
    }
    cJSON_AddItemToObject(json,"NXT",cJSON_CreateString(NXTaddr));
    cJSON_AddItemToObject(json,"timestamp",cJSON_CreateNumber(time(NULL)));
    cJSON_AddItemToObject(json,"maxdepth",cJSON_CreateNumber(maxdepth));
    return(jprint(json,1));
}

void prices777_jsonstrs(struct prices777 *prices,struct prices777_basketinfo *OB)
{
    int32_t allflag; char *strs[4];
    if ( OB->numbids == 0 && OB->numasks == 0 )
    {
        printf("warning: updating null orderbook ignored for %s (%s/%s)\n",prices->contract,prices->base,prices->rel);
        return;
    }
    for (allflag=0; allflag<4; allflag++)
    {
        strs[allflag] = prices777_orderbook_jsonstr(allflag/2,IGUANA_MY64BITS,prices,OB,MAX_DEPTH,allflag%2);
        if ( Debuglevel > 2 )
            printf("strs[%d].(%s) prices.%p\n",allflag,strs[allflag],prices);
    }
    portable_mutex_lock(&prices->mutex);
    for (allflag=0; allflag<4; allflag++)
    {
        if ( prices->orderbook_jsonstrs[allflag/2][allflag%2] != 0 )
            free(prices->orderbook_jsonstrs[allflag/2][allflag%2]);
        prices->orderbook_jsonstrs[allflag/2][allflag%2] = strs[allflag];
    }
    portable_mutex_unlock(&prices->mutex);
}

char *orderbook_clonestr(struct prices777 *prices,int32_t invert,int32_t allflag)
{
    char *str,*clone = 0;
    portable_mutex_lock(&prices->mutex);
    if ( (str= prices->orderbook_jsonstrs[invert][allflag]) != 0 )
        clone = clonestr(str);
    portable_mutex_unlock(&prices->mutex);
    return(clone);
}

void prices777_json_quotes(double *hblap,struct prices777 *prices,cJSON *bids,cJSON *asks,int32_t maxdepth,char *pricefield,char *volfield,uint32_t reftimestamp)
{
    cJSON *item; int32_t i,slot,n=0,m=0,dir,bidask,numitems; uint64_t orderid,quoteid; uint32_t timestamp; double price,volume,hbla = 0.;
    struct prices777_basketinfo OB; struct prices777_orderentry *gp; struct prices777_order *order;
    memset(&OB,0,sizeof(OB));
    if ( reftimestamp == 0 )
        reftimestamp = (uint32_t)time(NULL);
    OB.timestamp = reftimestamp;
    if ( bids != 0 )
    {
        n = cJSON_GetArraySize(bids);
        if ( maxdepth != 0 && n > maxdepth )
            n = maxdepth;
    }
    if ( asks != 0 )
    {
        m = cJSON_GetArraySize(asks);
        if ( maxdepth != 0 && m > maxdepth )
            m = maxdepth;
    }
    for (i=0; i<n||i<m; i++)
    {
        gp = &OB.book[MAX_GROUPS][i];
        gp->bid.source = gp->ask.source = prices;
        for (bidask=0; bidask<2; bidask++)
        {
            price = volume = 0.;
            orderid = quoteid = 0;
            dir = (bidask == 0) ? 1 : -1;
            if ( bidask == 0 && i >= n )
                continue;
            else if ( bidask == 1 && i >= m )
                continue;
            if ( strcmp(prices->exchange,"bter") == 0 && dir < 0 )
                slot = ((bidask==0?n:m) - 1) - i;
            else slot = i;
            timestamp = 0;
            item = jitem(bidask==0?bids:asks,slot);
            if ( pricefield != 0 && volfield != 0 )
                price = jdouble(item,pricefield), volume = jdouble(item,volfield);
            else if ( is_cJSON_Array(item) != 0 && (numitems= cJSON_GetArraySize(item)) != 0 ) // big assumptions about order within nested array!
            {
                price = jdouble(jitem(item,0),0), volume = jdouble(jitem(item,1),0);
                if ( strcmp(prices->exchange,"kraken") == 0 )
                    timestamp = juint(jitem(item,2),0);
                else orderid = j64bits(jitem(item,2),0);
            }
            else continue;
            if ( quoteid == 0 )
                quoteid = orderid;
            if ( price > SMALLVAL && volume > SMALLVAL )
            {
                if ( prices->commission != 0. )
                {
                    //printf("price %f fee %f -> ",price,prices->commission * price);
                    if ( bidask == 0 )
                        price -= prices->commission * price;
                    else price += prices->commission * price;
                    //printf("%f\n",price);
                }
                order = (bidask == 0) ? &gp->bid : &gp->ask;
                order->s.price = price, order->s.vol = volume, order->source = prices, order->s.timestamp = OB.timestamp, order->wt = 1, order->id = orderid, order->s.quoteid = quoteid;
                if ( bidask == 0 )
                    order->slot_ba = (OB.numbids++ << 1);
                else order->slot_ba = (OB.numasks++ << 1) | 1;
                if ( i == 0 )
                {
                    if ( bidask == 0 )
                        prices->lastbid = price;
                    else prices->lastask = price;
                    if ( hbla == 0. )
                        hbla = price;
                    else hbla = 0.5 * (hbla + price);
                }
                if ( Debuglevel > 2 )//|| prices->basketsize > 0 || strcmp("unconf",prices->exchange) == 0 )
                    printf("%d,%d: %-8s %s %5s/%-5s %13.8f vol %13.8f | invert %13.8f vol %13.8f | timestamp.%u\n",OB.numbids,OB.numasks,prices->exchange,dir>0?"bid":"ask",prices->base,prices->rel,price,volume,1./price,volume*price,timestamp);
            }
        }
    }
    if ( hbla != 0. )
        *hblap = hbla;
    prices->O2 = prices->O;
    //prices->O = OB;
    for (i=0; i<MAX_GROUPS; i++)
        memcpy(prices->O.book[i],prices->O.book[i+1],sizeof(prices->O.book[i]));
    memcpy(prices->O.book[MAX_GROUPS],OB.book[MAX_GROUPS],sizeof(OB.book[MAX_GROUPS]));
    prices->O.numbids = OB.numbids, prices->O.numasks = OB.numasks, prices->O.timestamp = OB.timestamp;
}

double prices777_json_orderbook(char *exchangestr,struct prices777 *prices,int32_t maxdepth,cJSON *json,char *resultfield,char *bidfield,char *askfield,char *pricefield,char *volfield)
{
    cJSON *obj = 0,*bidobj=0,*askobj=0; double hbla = 0.; int32_t numasks=0,numbids=0;
    if ( resultfield == 0 )
        obj = json;
    if ( maxdepth == 0 )
        maxdepth = MAX_DEPTH;
    if ( resultfield == 0 || (obj= jobj(json,resultfield)) != 0 )
    {
        bidobj = jarray(&numbids,obj,bidfield);
        askobj = jarray(&numasks,obj,askfield);
        if ( bidobj != 0 || askobj != 0 )
        {
            prices777_json_quotes(&hbla,prices,bidobj,askobj,maxdepth,pricefield,volfield,0);
            prices777_jsonstrs(prices,&prices->O);
        }
    }
    return(hbla);
}

void prices777_hbla(uint64_t *bidorderid,uint64_t *askorderid,int32_t *lowaski,int32_t *highbidi,double *highbid,double *bidvol,double *lowask,double *askvol,double groupwt,int32_t i,int32_t bidask,double price,double vol,uint64_t orderid)
{
    if ( groupwt > SMALLVAL && (*lowask == 0. || price < *lowask) )
        *askorderid = orderid, *lowask = price, *askvol = vol, *lowaski = (i << 1) | bidask;
    else if ( groupwt < -SMALLVAL && (*highbid == 0. || price > *highbid) )
        *bidorderid = orderid, *highbid = price, *bidvol = vol, *highbidi = (i << 1) | bidask;
    //printf("hbla.(%f %f)\n",price,vol);
}

void prices777_setorder(struct prices777_order *order,struct prices777_basket *group,int32_t coordinate,uint64_t orderid,double refprice,double refvol)
{
    int32_t bidask; struct prices777 *prices; double price=0,vol=0;
    bidask = (coordinate & 1), coordinate >>= 1;
    prices = group[coordinate].prices;
    if ( bidask != 0 && group[coordinate].aski < prices->O.numasks )
        price = prices->O.book[MAX_GROUPS][group[coordinate].aski].ask.s.price, vol = prices->O.book[MAX_GROUPS][group[coordinate].aski].ask.s.vol, order->slot_ba = (group[coordinate].aski++ << 1) | 1;
    else if ( group[coordinate].bidi < prices->O.numbids )
        price = prices->O.book[MAX_GROUPS][group[coordinate].bidi].bid.s.price, vol = prices->O.book[MAX_GROUPS][group[coordinate].bidi].bid.s.vol,order->slot_ba = (group[coordinate].bidi++ << 1);
    else printf("illegal coordinate.%d bidask.%d when bidi.%d aski.%d numbids.%d numasks.%d\n",coordinate,bidask,group[coordinate].bidi,group[coordinate].aski,prices->O.numbids,prices->O.numasks);
    order->source = prices;
    order->wt = group[coordinate].wt;
    order->s.timestamp = prices->O.timestamp;
    order->id = orderid;
    if ( order->wt < 0. )
        vol *= price, price = (1. / price);
    if ( fabs(price - refprice) > SMALLVAL || fabs(vol - refvol) > SMALLVAL )
    {
        printf("[ERROR] ");
        printf("%s group.%d (%s/%s) bidask.%d coordinate.%d wt %.8f (%.8f %.8f) vs (%.8f %.8f)\n",prices->exchange,group[coordinate].groupid,prices->base,prices->rel,bidask,coordinate,order->wt,price,vol,refprice,refvol);
    }
}


int32_t prices777_groupbidasks(struct prices777_orderentry *gp,double groupwt,double minvol,struct prices777_basket *group,int32_t groupsize)
{
    int32_t i,highbidi,lowaski; double highbid,lowask,bidvol,askvol,vol,price,polarity; uint64_t bidorderid,askorderid;
    struct prices777 *feature; struct prices777_order *order;
    memset(gp,0,sizeof(*gp));
    highbidi = lowaski = -1;
    for (bidvol=askvol=highbid=lowask=bidorderid=askorderid=i=0; i<groupsize; i++)
    {
        if ( (feature= group[i].prices) != 0 )
        {
            //if ( strcmp(feature->base,group[0].rel) == 0 && strcmp(feature->rel,group[0].base) == 0 )
            //    polarity = -1.;
            //else polarity = 1.;
            //if ( group[i].wt * groupwt < 0 ) fixes supernet/BTC
            //   polarity *= -1;
            polarity = group[i].wt;// * groupwt;
            order = &feature->O.book[MAX_GROUPS][group[i].bidi].bid;
            if ( group[i].bidi < feature->O.numbids && (vol= order->s.vol) > minvol && (price= order->s.price) > SMALLVAL )
            {
                //printf("%d/%d: (%s/%s) %s bidi.%d price.%f polarity.%f groupwt.%f -> ",i,groupsize,feature->base,feature->rel,feature->exchange,group[i].bidi,price,polarity,groupwt);
                if ( polarity < 0. )
                    vol *= price, price = (1. / price);
                prices777_hbla(&bidorderid,&askorderid,&lowaski,&highbidi,&highbid,&bidvol,&lowask,&askvol,-polarity,i,0,price,vol,order->id);
            }
            order = &feature->O.book[MAX_GROUPS][group[i].aski].ask;
            if ( group[i].aski < feature->O.numasks && (vol= order->s.vol) > minvol && (price= order->s.price) > SMALLVAL )
            {
                //printf("%d/%d: (%s/%s) %s aski.%d price.%f polarity.%f groupwt.%f -> ",i,groupsize,feature->base,feature->rel,feature->exchange,group[i].aski,price,polarity,groupwt);
                if ( polarity < 0. )
                    vol *= price, price = (1. / price);
                prices777_hbla(&bidorderid,&askorderid,&lowaski,&highbidi,&highbid,&bidvol,&lowask,&askvol,polarity,i,1,price,vol,order->id);
            }
        } else printf("null feature.%p\n",feature);
    }
    gp->bid.s.price = highbid, gp->bid.s.vol = bidvol, gp->ask.s.price = lowask, gp->ask.s.vol = askvol;
    if ( highbidi >= 0 )
        prices777_setorder(&gp->bid,group,highbidi,bidorderid,highbid,bidvol);
    if ( lowaski >= 0 )
        prices777_setorder(&gp->ask,group,lowaski,askorderid,lowask,askvol);
 // if ( lowaski >= 0 && highbidi >= 0 )
//printf("groupwt %f groupsize.%d %s highbidi.%d %f %f %s lowaski.%d wts.(%f %f)\n",groupwt,groupsize,gp->bid.source->exchange,highbidi,gp->bid.s.price,gp->ask.s.price,gp->ask.source->exchange,lowaski,gp->bid.wt,gp->ask.wt);
    if ( gp->bid.s.price > SMALLVAL && gp->ask.s.price > SMALLVAL )
        return(0);
    return(-1);
}

double prices777_volcalc(double *basevols,uint64_t *baseids,uint64_t baseid,double basevol)
{
    int32_t i;
    //printf("(add %llu %f) ",(long long)baseid,basevol);
    for (i=0; i<MAX_GROUPS*2; i++)
    {
        if ( baseids[i] == baseid )
        {
            if ( basevols[i] == 0. || basevol < basevols[i] )
                basevols[i] = basevol;//, printf("set %llu <= %f ",(long long)baseid,basevol);
           // else printf("missed basevols[%d] %f, ",i,basevols[i]);
            break;
        }
    }
    return(1);
}

double prices777_volratio(double *basevols,uint64_t *baseids,uint64_t baseid,double vol)
{
    int32_t i;
    for (i=0; i<MAX_GROUPS*2; i++)
    {
        if ( baseids[i] == baseid )
        {
            if ( basevols[i] > 0. )
            {
                //printf("(vol %f vs %f) ",vol,basevols[i]);
                if ( vol > basevols[i] )
                    return(basevols[i]/vol);
                else return(1.);
            }
            printf("unexpected zero vol basevols.%d\n",i);
            return(1.);
            break;
        }
    }
    printf("unexpected cant find baseid.%llu\n",(long long)baseid);
    return(1.);
}

double prices777_basket(struct prices777 *prices,int32_t maxdepth)
{
    int32_t i,j,groupsize,slot; uint64_t baseids[MAX_GROUPS*2];
    double basevols[MAX_GROUPS*2],relvols[MAX_GROUPS*2],baseratio,relratio,a,av,b,bv,gap,bid,ask,minvol,bidvol,askvol,hbla = 0.;
    struct prices777_basketinfo OB; uint32_t timestamp; struct prices777 *feature; struct prices777_orderentry *gp;
    a = av = b = bv = 0;
    timestamp = (uint32_t)time(NULL);
    memset(&OB,0,sizeof(OB));
    memset(baseids,0,sizeof(baseids));
    OB.timestamp = timestamp;
    //printf("prices777_basket.(%s) %s (%s/%s) %llu/%llu basketsize.%d\n",prices->exchange,prices->contract,prices->base,prices->rel,(long long)prices->baseid,(long long)prices->relid,prices->basketsize);
    for (i=0; i<prices->basketsize; i++)
    {
        if ( 0 && strcmp(prices->exchange,"active") == 0 && prices->basket[i].prices != 0 )
            printf("%s.group.%d %10s %10s/%10s wt %3.0f %.8f %.8f\n",prices->exchange,i,prices->basket[i].prices->exchange,prices->basket[i].prices->base,prices->basket[i].rel,prices->basket[i].wt,prices->basket[i].prices->O.book[MAX_GROUPS][0].bid.s.price,prices->basket[i].prices->O.book[MAX_GROUPS][0].ask.s.price);
        if ( (feature= prices->basket[i].prices) != 0 )
        {
            if ( 0 && (gap= (prices->lastupdate - feature->lastupdate)) < 0 )
            {
                if ( prices->lastupdate != 0 )
                    printf("you can ignore this harmless warning about unexpected time traveling feature %f vs %f or laggy feature\n",prices->lastupdate,feature->lastupdate);
                return(0.);
            }
        }
        else
        {
            printf("unexpected null basket item %s[%d]\n",prices->contract,i);
            return(0.);
        }
        prices->basket[i].aski = prices->basket[i].bidi = 0;
        for (j=0; j<MAX_GROUPS*2; j++)
        {
            if ( prices->basket[i].prices == 0 || prices->basket[i].prices->baseid == baseids[j] )
                break;
            if ( baseids[j] == 0 )
            {
                baseids[j] = prices->basket[i].prices->baseid;
                break;
            }
        }
        for (j=0; j<MAX_GROUPS*2; j++)
        {
            if ( prices->basket[i].prices == 0 || prices->basket[i].prices->relid == baseids[j] )
                break;
            if ( baseids[j] == 0 )
            {
                baseids[j] = prices->basket[i].prices->relid;
                break;
            }
        }
    }
    //printf("%s basketsize.%d numgroups.%d maxdepth.%d group0size.%d\n",prices->contract,prices->basketsize,prices->numgroups,maxdepth,prices->basket[0].groupsize);
    for (slot=0; slot<maxdepth; slot++)
    {
        memset(basevols,0,sizeof(basevols));
        memset(relvols,0,sizeof(relvols));
        groupsize = prices->basket[0].groupsize;
        minvol = (1. / SATOSHIDEN);
        bid = ask = 1.; bidvol = askvol = 0.;
        for (j=i=0; j<prices->numgroups; j++,i+=groupsize)
        {
            groupsize = prices->basket[i].groupsize;
            gp = &OB.book[j][slot];
            if ( prices777_groupbidasks(gp,prices->groupwts[j],minvol,&prices->basket[i],groupsize) != 0 )
            {
                //printf("prices777_groupbidasks i.%d j.%d error\n",i,j);
                break;
            }
            //printf("%s j%d slot.%d %s numgroups.%d groupsize.%d\n",prices->exchange,j,slot,prices->contract,prices->numgroups,groupsize);
            if ( bid > SMALLVAL && (b= gp->bid.s.price) > SMALLVAL && (bv= gp->bid.s.vol) > SMALLVAL )
            {
                //if ( gp->bid.wt*prices->groupwts[j] < 0 )
                //    bid /= b;
                //else
                    bid *= b;
                prices777_volcalc(basevols,baseids,gp->bid.source->baseid,bv);
                prices777_volcalc(basevols,baseids,gp->bid.source->relid,b*bv);
                //printf("bid %f b %f bv %f %s %s %f\n",bid,b,bv,gp->bid.source->base,gp->bid.source->rel,bv*b);
            } else bid = 0.;
            if ( ask > SMALLVAL && (a= gp->ask.s.price) > SMALLVAL && (av= gp->ask.s.vol) > SMALLVAL )
            {
                //if ( gp->ask.wt*prices->groupwts[j] < 0 )
                //    ask /= a;
                //else
                    ask *= a;
                prices777_volcalc(relvols,baseids,gp->ask.source->baseid,av);
                prices777_volcalc(relvols,baseids,gp->ask.source->relid,a*av);
                //printf("ask %f b %f bv %f %s %s %f\n",ask,a,av,gp->ask.source->base,gp->ask.source->rel,av*a);
            } else ask = 0.;
            if ( Debuglevel > 2 )
                printf("%10s %10s/%10s %s (%s %s) wt:%f %2.0f/%2.0f j.%d: b %.8f %12.6f a %.8f %12.6f, bid %.8f ask %.8f inv %f %f\n",prices->exchange,gp->bid.source->exchange,gp->ask.source->exchange,prices->contract,gp->bid.source->contract,gp->ask.source->contract,prices->groupwts[j],gp->bid.wt,gp->ask.wt,j,b,bv,a,av,bid,ask,1/bid,1/ask);
        }
        for (j=0; j<prices->numgroups; j++)
        {
            gp = &OB.book[j][slot];
            if ( gp->bid.source == 0 || gp->ask.source == 0 )
            {
                printf("%s: (%s/%s) null source slot.%d j.%d\n",prices->exchange,prices->base,prices->rel,slot,j);
                break;
            }
            baseratio = prices777_volratio(basevols,baseids,gp->bid.source->baseid,gp->bid.s.vol);
            relratio = prices777_volratio(basevols,baseids,gp->bid.source->relid,gp->bid.s.vol * gp->bid.s.price);
            gp->bid.ratio = (baseratio < relratio) ? baseratio : relratio;
            if ( j == 0 )
                bidvol = (gp->bid.ratio * gp->bid.s.vol);
            //printf("(%f %f) (%f %f) bid%d bidratio %f bidvol %f ",gp->bid.s.vol,baseratio,gp->bid.s.vol * gp->bid.s.price,relratio,j,gp->bid.ratio,bidvol);
            baseratio = prices777_volratio(relvols,baseids,gp->ask.source->baseid,gp->ask.s.vol);
            relratio = prices777_volratio(relvols,baseids,gp->ask.source->relid,gp->ask.s.vol * gp->ask.s.price);
            gp->ask.ratio = (baseratio < relratio) ? baseratio : relratio;
            if ( j == 0 )
                askvol = (gp->ask.ratio * gp->ask.s.vol);
        }
        if ( j != prices->numgroups )
        {
            //printf("%s: j.%d != numgroups.%d\n",prices->exchange,j,prices->numgroups);
            break;
        }
        for (j=0; j<MAX_GROUPS*2; j++)
        {
            if ( baseids[j] == 0 )
                break;
            //printf("{%llu %f %f} ",(long long)baseids[j],basevols[j],relvols[j]);
        }
        //printf("basevols bidvol %f, askvol %f\n",bidvol,askvol);
        gp = &OB.book[MAX_GROUPS][slot];
        if ( bid > SMALLVAL && bidvol > SMALLVAL )
        {
            if ( slot == 0 )
                prices->lastbid = bid;
            gp->bid.s.timestamp = OB.timestamp, gp->bid.s.price = bid, gp->bid.s.vol = bidvol, gp->bid.slot_ba = (OB.numbids++ << 1);
            gp->bid.source = prices, gp->bid.wt = prices->groupwts[j];
        }
        if ( ask > SMALLVAL && askvol > SMALLVAL )
        {
            if ( slot == 0 )
                prices->lastask = ask;
            gp->ask.s.timestamp = OB.timestamp, gp->ask.s.price = ask, gp->ask.s.vol = askvol, gp->ask.slot_ba = (OB.numasks++ << 1) | 1;
            gp->ask.source = prices, gp->ask.wt = prices->groupwts[j];
        }
        //printf("%s %s slot.%d (%.8f %.6f %.8f %.6f) (%d %d)\n",prices->exchange,prices->contract,slot,gp->bid.s.price,gp->bid.s.vol,gp->ask.s.price,gp->ask.s.vol,OB.numbids,OB.numasks);
    }
    //fprintf(stderr,"%s basket.%s slot.%d numbids.%d numasks.%d %f %f\n",prices->exchange,prices->contract,slot,prices->O.numbids,prices->O.numasks,prices->O.book[MAX_GROUPS][0].bid.s.price,prices->O.book[MAX_GROUPS][0].ask.s.price);
    if ( slot > 0 )
    {
        prices->O2 = prices->O;
        prices->O = OB;
        if ( prices->lastbid > SMALLVAL && prices->lastask > SMALLVAL )
            hbla = 0.5 * (prices->lastbid + prices->lastask);
    }
    return(hbla);
}

struct prices777 *prices777_addbundle(int32_t *validp,int32_t loadprices,struct prices777 *prices,char *exchangestr,uint64_t baseid,uint64_t relid)
{
    int32_t j; struct prices777 *ptr; struct exchange_info *exchange;
    *validp = -1;
    if ( prices != 0 )
    {
        exchangestr = prices->exchange;
        baseid = prices->baseid, relid = prices->relid;
    }
    for (j=0; j<BUNDLE.num; j++)
    {
        if ( (ptr= BUNDLE.ptrs[j]) != 0 && ((ptr->baseid == baseid && ptr->relid == relid) || (ptr->relid == baseid && ptr->baseid == relid)) && strcmp(ptr->exchange,exchangestr) == 0 )
            return(ptr);
    }
    if ( j == BUNDLE.num )
    {
        if ( prices != 0 )
        {
            exchange = &Exchanges[prices->exchangeid];
            if ( loadprices != 0 && exchange->issue.update != 0 )
            {
                portable_mutex_lock(&exchange->mutex);
                (exchange->issue.update)(prices,MAX_DEPTH);
                portable_mutex_unlock(&exchange->mutex);
            }
            printf("total polling.%d added.(%s)\n",BUNDLE.num,prices->contract);
            if ( exchange->polling == 0 )
            {
                printf("First pair for (%s), start polling]\n",exchange_str(prices->exchangeid));
                exchange->polling = 1;
                if ( strcmp(exchange->name,"wallet") != 0 )//&& strcmp(exchange->name,"jumblr") != 0 && strcmp(exchange->name,"pangea") != 0 )
                    iguana_launch(iguana_coinadd("BTCD"),"exchangeloop",(void *)prices777_exchangeloop,&Exchanges[prices->exchangeid],IGUANA_EXCHANGETHREAD);
            }
            BUNDLE.ptrs[BUNDLE.num] = prices;
            printf("prices777_addbundle.(%s) (%s/%s).%s %llu %llu\n",prices->contract,prices->base,prices->rel,prices->exchange,(long long)prices->baseid,(long long)prices->relid);
            BUNDLE.num++;
        } else printf("no prices\n");
        *validp = BUNDLE.num;
        return(prices);
    }
    return(0);
}

int32_t is_native_crypto(char *name,uint64_t bits)
{
    int32_t i,n;
    if ( (n= (int32_t)strlen(name)) > 0 || (n= unstringbits(name,bits)) <= 5 )
    {
        for (i=0; i<n; i++)
        {
            if ( (name[i] >= '0' && name[i] <= '9') || (name[i] >= 'A' && name[i] <= 'Z') )// || (name[i] >= '0' && name[i] <= '9') )
                continue;
            printf("(%s) is not native crypto\n",name);
            return(0);
        }
        printf("(%s) is native crypto\n",name);
        return(1);
    }
    return(0);
}

char *_issue_getAsset(char *assetidstr)
{
    char cmd[4096],*jsonstr;
    //sprintf(cmd,"requestType=getAsset&asset=%s",assetidstr);
    sprintf(cmd,"requestType=getAsset&asset=%s",assetidstr);
    //printf("_cmd.(%s)\n",cmd);
    jsonstr = issue_NXTPOST(cmd);
    //printf("(%s) -> (%s)\n",cmd,jsonstr);
    return(jsonstr);
}

char *_issue_getCurrency(char *assetidstr)
{
    char cmd[4096];
    //sprintf(cmd,"requestType=getAsset&asset=%s",assetidstr);
    sprintf(cmd,"requestType=getCurrency&currency=%s",assetidstr);
    //printf("_cmd.(%s)\n",cmd);
    return(issue_NXTPOST(cmd));
}

int32_t is_mscoin(char *assetidstr)
{
    char *jsonstr; cJSON *json; int32_t retcode = 0;
    if ( (jsonstr= _issue_getCurrency(assetidstr)) != 0 )
    {
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( get_cJSON_int(json,"errorCode") == 0 )
                retcode = 1;
            free_json(json);
        }
        free(jsonstr);
    }
    return(retcode);
}

int32_t get_assetname(char *name,uint64_t assetid)
{
    char assetidstr[64],*jsonstr; cJSON *json;
    name[0] = 0;
    if ( is_native_crypto(name,assetid) != 0 )
        return((int32_t)strlen(name));
    expand_nxt64bits(assetidstr,assetid);
    name[0] = 0;
    if ( (jsonstr= _issue_getAsset(assetidstr)) != 0 )
    {
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            extract_cJSON_str(name,15,json,"name");
            free_json(json);
        }
        free(jsonstr);
    }
    return((int32_t)strlen(assetidstr));
}

uint32_t get_blockutime(uint32_t blocknum)
{
    cJSON *json;
    uint32_t timestamp = 0;
    char cmd[4096],*jsonstr;
    sprintf(cmd,"requestType=getBlock&height=%u",blocknum);
    if ( (jsonstr= issue_NXTPOST(cmd)) != 0 )
    {
        //printf("(%s) -> (%s)\n",cmd,jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (timestamp= juint(json,"timestamp")) != 0 )
                timestamp += NXT_GENESISTIME;
            free_json(json);
        }
        free(jsonstr);
    }
    return(timestamp);
}

uint64_t calc_decimals_mult(int32_t decimals)
{
    int32_t i; uint64_t mult = 1;
    for (i=7-decimals; i>=0; i--)
        mult *= 10;
    return(mult);
}

int32_t _set_assetname(uint64_t *multp,char *buf,char *jsonstr,uint64_t assetid)
{
    int32_t type = 0,decimals = -1; cJSON *json=0; char assetidstr[64],*str;
    *multp = 1;
    buf[0] = 0;
    if ( assetid != 0 )
    {
        //fprintf(stderr,"assetid.%llu\n",(long long)assetid);
        if ( (str= is_MGWasset(assetid)) != 0 )
        {
            strcpy(buf,str);
            return(0);
        }
        if ( is_native_crypto(buf,assetid) != 0 )
        {
            unstringbits(buf,assetid);
            return(0);
        }
    }
    if ( jsonstr == 0 )
    {
        if ( assetid == 0 )
            printf("_set_assetname null assetid\n"), getchar();
        expand_nxt64bits(assetidstr,assetid);
        type = 2;
        if ( (jsonstr= _issue_getAsset(assetidstr)) != 0 )
        {
            //printf("%llu (%s) -> (%s)\n",(long long)assetid,assetidstr,jsonstr);
            if ( (json= cJSON_Parse(jsonstr)) != 0 )
            {
                if ( get_cJSON_int(json,"errorCode") != 0 )
                {
                    free_json(json), free(jsonstr);
                    if ( (jsonstr= _issue_getCurrency(assetidstr)) != 0 )
                    {
                        //printf("(%s) -> (%s)\n",assetidstr,jsonstr);
                        if ( (json= cJSON_Parse(jsonstr)) != 0 )
                        {
                            if ( get_cJSON_int(json,"errorCode") != 0 )
                            {
                                printf("(%s) not asset and not currency (%s)\n",assetidstr,jsonstr);//, getchar();
                                free_json(json), free(jsonstr);
                                return(-1);
                            }
                            type = 5;
                        }
                    }
                }
            }
            free(jsonstr), jsonstr = 0;
        } else return(-1);
    }
    if ( multp != 0 )
        *multp = 0;
    if ( json == 0 )
        json = cJSON_Parse(jsonstr);
    if ( json != 0 )
    {
        if ( get_cJSON_int(json,"errorCode") == 0 )
        {
            decimals = (int32_t)get_cJSON_int(json,"decimals");
            if ( multp != 0 && decimals >= 0 && decimals <= 8 )
                *multp = calc_decimals_mult(decimals);
            if ( extract_cJSON_str(buf,16,json,"name") <= 0 )
                decimals = -1;
            //printf("%s decimals.%d (%s)\n",assetidstr,decimals,buf);
        }
        free_json(json);
    }
    return(type);
}

char *peggy_mapname(char *basebuf,char *relbuf,int32_t i) // sorry it is messy thing
{
    char *base,*rel,buf[16];
    base = rel = 0;
    strcpy(buf,peggy_contracts[i]);
    base = buf, rel = "BTCD";
    if ( strlen(buf) > 3 && strcmp(buf+strlen(buf)-3,"USD") == 0 )
    {
        if ( strcmp(buf,"BTCUSD") == 0 )
            base = "BTC";
        buf[strlen(buf)-3] = 0;
    }
    else if ( strcmp(buf,"Copper") == 0 || strcmp(buf,"NGAS") == 0 || strcmp(buf,"UKOil") == 0 || strcmp(buf,"USOil") == 0 || strcmp(buf,"US30") == 0 || strcmp(buf,"SPX500") == 0 || strcmp(buf,"NAS100") == 0 )
        rel = "USD";
    else if ( strcmp(buf,"Bund") == 0 )
        rel = "yield";
    else if ( strcmp(buf,"EUSTX50") == 0 )
        rel = "EUR";
    else if ( strcmp(buf,"JPN225") == 0 )
        rel = "JPY";
    else if ( strcmp(buf,"UK100") == 0 )
        rel = "GBP";
    else if ( strcmp(buf,"GER30") == 0 )
        rel = "EUR";
    else if ( strcmp(buf,"SUI30") == 0 )
        rel = "CHF";
    else if ( strcmp(buf,"AUS200") == 0 )
        rel = "AUD";
    else if ( strcmp(buf,"HKG33") == 0 )
        rel = "HKD";
    else if ( strlen(buf) > 3 && strcmp(buf+strlen(buf)-3,"BTC") == 0 )
        base = buf, buf[strlen(buf)-3] = 0;
    if ( i == sizeof(peggy_contracts)/sizeof(*peggy_contracts)-1 && strcmp(peggy_contracts[i],"BTCUSD") == 0 )
        base = "BTC", rel = "USD";
    else if ( i == sizeof(peggy_contracts)/sizeof(*peggy_contracts)-2 && strcmp(peggy_contracts[i],"BTCCNY") == 0 )
        base = "BTC", rel = "CNY";
    else if ( i == sizeof(peggy_contracts)/sizeof(*peggy_contracts)-3 && strcmp(peggy_contracts[i],"BTCRUB") == 0 )
        base = "BTC", rel = "RUB";
    else if ( i == sizeof(peggy_contracts)/sizeof(*peggy_contracts)-4 && strcmp(peggy_contracts[i],"XAUUSD") == 0 )
        base = "XAU", rel = "USD";
    else if ( i == 0 )
        base = "BTCD", rel = "maincurrency peggy, price is BTCD/BTC for info only";
    basebuf[0] = relbuf[0] = 0;
    if ( rel != 0 )
        strcpy(relbuf,rel);//, printf("rel.(%s) ",rel);
    if ( base != 0 )
        strcpy(basebuf,base);//, printf("base.(%s) ",base);
    return(basebuf);
}

uint64_t peggy_basebits(char *name)
{
    int32_t i; char basebuf[64],relbuf[64];
    for (i=0; i<64; i++)
    {
        if ( strcmp(name,peggy_contracts[i]) == 0 )
        {
            peggy_mapname(basebuf,relbuf,i);
            return(stringbits(basebuf));
        }
    }
    return(0);
}

uint64_t peggy_relbits(char *name)
{
    int32_t i; char basebuf[64],relbuf[64];
    for (i=0; i<64; i++)
    {
        if ( strcmp(name,peggy_contracts[i]) == 0 )
        {
            peggy_mapname(basebuf,relbuf,i);
            return(stringbits(relbuf));
        }
    }
    return(0);
}

int32_t prices777_key(char *key,char *exchange,char *name,char *base,uint64_t baseid,char *rel,uint64_t relid)
{
    int32_t len,keysize = 0;
    memcpy(&key[keysize],&baseid,sizeof(baseid)), keysize += sizeof(baseid);
    memcpy(&key[keysize],&relid,sizeof(relid)), keysize += sizeof(relid);
    strcpy(&key[keysize],exchange), keysize += strlen(exchange) + 1;
    strcpy(&key[keysize],name), keysize += strlen(name) + 1;
    memcpy(&key[keysize],base,strlen(base)+1), keysize += strlen(base) + 1;
    if ( rel != 0 && (len= (int32_t)strlen(rel)) > 0 )
        memcpy(&key[keysize],rel,len+1), keysize += len+1;
    return(keysize);
}

uint64_t InstantDEX_name(char *key,int32_t *keysizep,char *exchange,char *name,char *base,uint64_t *baseidp,char *rel,uint64_t *relidp)
{
    uint64_t baseid,relid,assetbits = 0; char *s,*str;
    baseid = *baseidp, relid = *relidp;
    //printf(">>>>>> name.(%s) (%s/%s) %llu/%llu\n",name,base,rel,(long long)baseid,(long long)relid);
    if ( strcmp(base,"5527630") == 0 || baseid == 5527630 )
        strcpy(base,"NXT");
    if ( strcmp(rel,"5527630") == 0 || relid == 5527630 )
        strcpy(rel,"NXT");
    if ( relid == 0 && rel[0] != 0 )
    {
        if ( is_decimalstr(rel) != 0 )
            relid = calc_nxt64bits(rel);
        else relid = is_MGWcoin(rel);
    }
    else if ( (str= is_MGWasset(relid)) != 0 )
        strcpy(rel,str);
    if ( baseid == 0 && base[0] != 0 )
    {
        if ( is_decimalstr(base) != 0 )
            baseid = calc_nxt64bits(base);
        else baseid = is_MGWcoin(base);
    }
    else if ( (str= is_MGWasset(baseid)) != 0 )
        strcpy(base,str);
    if ( strcmp("InstantDEX",exchange) == 0 || strcmp("nxtae",exchange) == 0 || strcmp("unconf",exchange) == 0 || (baseid != 0 && relid != 0) )
    {
        if ( strcmp(rel,"NXT") == 0 )
            s = "+", relid = stringbits("NXT"), strcpy(rel,"NXT");
        else if ( strcmp(base,"NXT") == 0 )
            s = "-", baseid = stringbits("NXT"), strcpy(base,"NXT");
        else s = "";
        if ( base[0] == 0 )
        {
            get_assetname(base,baseid);
            //printf("mapped %llu -> (%s)\n",(long long)baseid,base);
        }
        if ( rel[0] == 0 )
        {
            get_assetname(rel,relid);
            //printf("mapped %llu -> (%s)\n",(long long)relid,rel);
        }
        if ( name[0] == 0 )
        {
            if ( relid == NXT_ASSETID )
                sprintf(name,"%llu",(long long)baseid);
            else if ( baseid == NXT_ASSETID )
                sprintf(name,"-%llu",(long long)relid);
            else sprintf(name,"%llu/%llu",(long long)baseid,(long long)relid);
        }
    }
    else
    {
        if ( base[0] != 0 && rel[0] != 0 && baseid == 0 && relid == 0 )
        {
            baseid = peggy_basebits(base), relid = peggy_basebits(rel);
            if ( name[0] == 0 && baseid != 0 && relid != 0 )
            {
                strcpy(name,base); // need to be smarter
                strcat(name,"/");
                strcat(name,rel);
            }
        }
        if ( name[0] == 0 || baseid == 0 || relid == 0 || base[0] == 0 || rel[0] == 0 )
        {
            if ( baseid == 0 && base[0] != 0 )
                baseid = stringbits(base);
            else if ( baseid != 0 && base[0] == 0 )
                sprintf(base,"%llu",(long long)baseid);
            if ( relid == 0 && rel[0] != 0 )
            {
                relid = stringbits(rel);
                printf("set relid.%llu <- (%s)\n",(long long)relid,rel);
            }
            else if ( relid != 0 && rel[0] == 0 )
                sprintf(rel,"%llu",(long long)relid);
            if ( name[0] == 0 )
                strcpy(name,base), strcat(name,"/"), strcat(name,rel);
        }
    }
    *baseidp = baseid, *relidp = relid;
    *keysizep = prices777_key(key,exchange,name,base,baseid,rel,relid);
    //printf("<<<<<<< name.(%s) (%s/%s) %llu/%llu\n",name,base,rel,(long long)baseid,(long long)relid);
    return(assetbits);
}

int32_t create_basketitem(struct prices777_basket *basketitem,cJSON *item,char *refbase,char *refrel,int32_t basketsize)
{
    struct destbuf exchangestr,name,base,rel; char key[512]; uint64_t tmp,baseid,relid; int32_t groupid,keysize,valid; double wt; struct prices777 *prices;
    copy_cJSON(&exchangestr,jobj(item,"exchange"));
    if ( strcmp("jumblr",exchangestr.buf) == 0 || strcmp("pangea",exchangestr.buf) == 0 || strcmp("wallet",exchangestr.buf) == 0 || exchange_find(exchangestr.buf) == 0 )
    {
        printf("create_basketitem: illegal exchange.%s\n",exchangestr.buf);
        return(-1);
    }
    copy_cJSON(&name,jobj(item,"name"));
    copy_cJSON(&base,jobj(item,"base"));
    copy_cJSON(&rel,jobj(item,"rel"));
    if ( (baseid= j64bits(item,"baseid")) != 0 && base.buf[0] == 0 )
    {
        _set_assetname(&tmp,base.buf,0,baseid);
        //printf("GOT.(%s) <- %llu\n",base.buf,(long long)baseid);
    }
    else if ( baseid == 0 )
        baseid = stringbits(base.buf);
    if ( (relid= j64bits(item,"relid")) != 0 && rel.buf[0] == 0 )
    {
        _set_assetname(&tmp,rel.buf,0,relid);
        //printf("GOT.(%s) <- %llu\n",rel.buf,(long long)relid);
    }
    else if ( relid == 0 )
        relid = stringbits(rel.buf);
    groupid = juint(item,"group");
    wt = jdouble(item,"wt");
    if ( wt == 0. )
        wt = 1.;
    if ( strcmp(refbase,rel.buf) == 0 || strcmp(refrel,base.buf) == 0 )
    {
        if ( wt != -1 )
        {
            printf("need to flip wt %f for (%s/%s) ref.(%s/%s)\n",wt,base.buf,rel.buf,refbase,refrel);
            wt = -1.;
        }
    }
    else if ( wt != 1. )
    {
        printf("need to flip wt %f for (%s/%s) ref.(%s/%s)\n",wt,base.buf,rel.buf,refbase,refrel);
        wt = 1.;
    }
    if ( name.buf[0] == 0 )
        sprintf(name.buf,"%s/%s",base.buf,rel.buf);
    if ( base.buf[0] == 0 )
        strcpy(base.buf,refbase);
    if ( rel.buf[0] == 0 )
        strcpy(rel.buf,refrel);
    InstantDEX_name(key,&keysize,exchangestr.buf,name.buf,base.buf,&baseid,rel.buf,&relid);
    printf(">>>>>>>>>> create basketitem.(%s) name.(%s) %s (%s/%s) %llu/%llu wt %f\n",jprint(item,0),name.buf,exchangestr.buf,base.buf,rel.buf,(long long)baseid,(long long)relid,wt);
    if ( (prices= prices777_initpair(1,exchangestr.buf,base.buf,rel.buf,0.,name.buf,baseid,relid,basketsize)) != 0 )
    {
        prices777_addbundle(&valid,0,prices,0,0,0);
        basketitem->prices = prices;
        basketitem->wt = wt;
        basketitem->groupid = groupid;
        strcpy(basketitem->base,base.buf);
        strcpy(basketitem->rel,rel.buf);
        return(0);
    } else printf("couldnt create basketitem\n");
    return(-1);
}

struct prices777 *prices777_makebasket(char *basketstr,cJSON *_basketjson,int32_t addbasket,char *typestr,struct prices777 *ptrs[],int32_t num)
{
    //{"name":"NXT/BTC","base":"NXT","rel":"BTC","basket":[{"exchange":"poloniex"},{"exchange":"btc38"}]}
    int32_t i,j,n,keysize,valid,basketsize,total = 0; struct destbuf refname,refbase,refrel; char key[8192]; uint64_t refbaseid=0,refrelid=0;
    struct prices777_basket *basketitem,*basket = 0; cJSON *basketjson,*array,*item; struct prices777 *prices = 0;
    if ( (basketjson= _basketjson) == 0 && (basketjson= cJSON_Parse(basketstr)) == 0 )
    {
        printf("cant parse basketstr.(%s)\n",basketstr);
        return(0);
    }
    copy_cJSON(&refname,jobj(basketjson,"name"));
    copy_cJSON(&refbase,jobj(basketjson,"base"));
    copy_cJSON(&refrel,jobj(basketjson,"rel"));
    refbaseid = j64bits(basketjson,"baseid");
    refrelid = j64bits(basketjson,"relid");
    if ( (array= jarray(&n,basketjson,"basket")) != 0 )
    {
        printf("MAKE/(%s) n.%d num.%d\n",jprint(basketjson,0),n,num);
        basketsize = (n + num);
        basket = calloc(1,sizeof(*basket) * basketsize);
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            if ( create_basketitem(&basket[total],item,refbase.buf,refrel.buf,basketsize) < 0 )
                printf("warning: >>>>>>>>>>>> skipped create_basketitem %d of %d of %d\n",i,n,basketsize);
            else
            {
                printf("MAKE.%d: (%s) %p.%s\n",total,jprint(item,0),basket[total].prices,basket[total].prices->exchange);
                total++;
            }
        }
        if ( ptrs != 0 && num > 0 )
        {
            for (i=0; i<num; i++)
            {
                basketitem = &basket[total];
                j = 0;
                if ( total > 0 )
                {
                    for (j=0; j<n+i; j++)
                    {
                        if ( basket[j].prices == ptrs[i] )
                        {
                            printf("skip duplicate basket[%d] == ptrs[%d]\n",j,i);
                            break;
                        }
                    }
                }
                if ( j == n+i )
                {
                    basketitem->prices = ptrs[i];
                    if ( strcmp(refbase.buf,ptrs[i]->rel) == 0 || strcmp(refrel.buf,ptrs[i]->base) == 0 )
                        basketitem->wt = -1;
                    else basketitem->wt = 1;
                    basketitem->groupid = 0;
                    strcpy(basketitem->base,ptrs[i]->base);
                    strcpy(basketitem->rel,ptrs[i]->rel);
                    total++;
                    printf("extrai.%d/%d total.%d wt.%f (%s/%s).%s\n",i,num,total,basketitem->wt,ptrs[i]->base,ptrs[i]->rel,ptrs[i]->exchange);
                }
            }
        }
        printf(">>>>> addbasket.%d (%s/%s).%s %llu %llu\n",addbasket,refbase.buf,refrel.buf,typestr,(long long)refbaseid,(long long)refrelid);
        InstantDEX_name(key,&keysize,typestr,refname.buf,refbase.buf,&refbaseid,refrel.buf,&refrelid);
        printf(">>>>> addbasket.%d (%s/%s).%s %llu %llu\n",addbasket,refbase.buf,refrel.buf,typestr,(long long)refbaseid,(long long)refrelid);
        if ( addbasket != 0 )
        {
            prices777_addbundle(&valid,0,0,typestr,refbaseid,refrelid);
            printf("<<<<< created.%s valid.%d refname.(%s) (%s/%s).%s %llu %llu\n",typestr,valid,refname.buf,refbase.buf,refrel.buf,typestr,(long long)refbaseid,(long long)refrelid);
        } else valid = 0;
        if ( valid >= 0 )
        {
            if ( (prices= prices777_createbasket(addbasket,refname.buf,refbase.buf,refrel.buf,refbaseid,refrelid,basket,total,typestr)) != 0 )
            {
                if ( addbasket != 0 )
                    BUNDLE.ptrs[BUNDLE.num] = prices;
                prices->lastprice = prices777_basket(prices,MAX_DEPTH);
                //printf("C.bsize.%d total polling.%d added.(%s/%s).%s updating basket lastprice %f changed.%p %d groupsize.%d numgroups.%d %p\n",total,BUNDLE.num,prices->base,prices->rel,prices->exchange,prices->lastprice,&prices->changed,prices->changed,prices->basket[0].groupsize,prices->numgroups,&prices->basket[0].groupsize);
                BUNDLE.num++;
            }
        } else prices = 0;
        if ( basketjson != _basketjson )
            free_json(basketjson);
        free(basket);
    }
    return(prices);
}

cJSON *inner_json(double price,double vol,uint32_t timestamp,uint64_t quoteid,uint64_t nxt64bits,uint64_t qty,uint64_t pqt,uint64_t baseamount,uint64_t relamount)
{
    cJSON *inner = cJSON_CreateArray();
    char numstr[64];
    sprintf(numstr,"%.8f",price), cJSON_AddItemToArray(inner,cJSON_CreateString(numstr));
    sprintf(numstr,"%.8f",vol), cJSON_AddItemToArray(inner,cJSON_CreateString(numstr));
    sprintf(numstr,"%llu",(long long)quoteid), cJSON_AddItemToArray(inner,cJSON_CreateString(numstr));
    cJSON_AddItemToArray(inner,cJSON_CreateNumber(timestamp));
    sprintf(numstr,"%llu",(long long)nxt64bits), cJSON_AddItemToArray(inner,cJSON_CreateString(numstr));
    sprintf(numstr,"%llu",(long long)qty), cJSON_AddItemToArray(inner,cJSON_CreateString(numstr));
    sprintf(numstr,"%llu",(long long)pqt), cJSON_AddItemToArray(inner,cJSON_CreateString(numstr));
    sprintf(numstr,"%llu",(long long)baseamount), cJSON_AddItemToArray(inner,cJSON_CreateString(numstr));
    sprintf(numstr,"%llu",(long long)relamount), cJSON_AddItemToArray(inner,cJSON_CreateString(numstr));
   // printf("(%s) ",jprint(inner,0));
    return(inner);
}

double prices777_NXT(struct prices777 *prices,int32_t maxdepth)
{
    uint32_t timestamp; int32_t flip,i,n; uint64_t baseamount,relamount,qty,pqt; char url[1024],*str,*cmd,*field;
    cJSON *json,*bids,*asks,*srcobj,*item,*array; double price,vol,hbla = 0.;
    if ( NXT_ASSETID != stringbits("NXT") || (strcmp(prices->rel,"NXT") != 0 && strcmp(prices->rel,"5527630") != 0) )
    {
        printf("NXT_ASSETID.%llu != %llu stringbits rel.%s\n",(long long)NXT_ASSETID,(long long)stringbits("NXT"),prices->rel);//, getchar();
        return(0);
    }
    bids = cJSON_CreateArray(), asks = cJSON_CreateArray();
    for (flip=0; flip<2; flip++)
    {
        /*{
            "offer": "16959774565785265980",
            "expirationHeight": 1000000,
            "accountRS": "NXT-QFAF-GR4F-RBSR-AXW2G",
            "limit": "9000000",
            "currency": "5775213290661997199",
            "supply": "0",
            "account": "9728792749189838093",
            "height": 348856,
            "rateNQT": "650"
        }*/
        if ( prices->type != 5 )
        {
            if ( flip == 0 )
                cmd = "getBidOrders", field = "bidOrders", array = bids;
            else cmd = "getAskOrders", field = "askOrders", array = asks;
            sprintf(url,"requestType=%s&asset=%llu&limit=%d",cmd,(long long)prices->baseid,maxdepth);
        }
        else
        {
            if ( flip == 0 )
                cmd = "getBuyOffers", field = "offers", array = bids;
            else cmd = "getSellOffers", field = "offers", array = asks;
            sprintf(url,"requestType=%s&currency=%llu&limit=%d",cmd,(long long)prices->baseid,maxdepth);
        }
        if ( (str= issue_NXTPOST(url)) != 0 )
        {
            //printf("{%s}\n",str);
            if ( (json= cJSON_Parse(str)) != 0 )
            {
                if ( (srcobj= jarray(&n,json,field)) != 0 )
                {
                    for (i=0; i<n && i<maxdepth; i++)
                    {
                        /*
                         "quantityQNT": "79",
                         "priceNQT": "13499000000",
                         "transactionHeight": 480173,
                         "accountRS": "NXT-FJQN-8QL2-BMY3-64VLK",
                         "transactionIndex": 1,
                         "asset": "15344649963748848799",
                         "type": "ask",
                         "account": "5245394173527769812",
                         "order": "17926122097022414596",
                         "height": 480173
                         */
                        item = cJSON_GetArrayItem(srcobj,i);
                        if ( prices->type != 5 )
                            qty = j64bits(item,"quantityQNT"), pqt = j64bits(item,"priceNQT");
                        else qty = j64bits(item,"limit"), pqt = j64bits(item,"rateNQT");
                        baseamount = (qty * prices->ap_mult), relamount = (qty * pqt);
                        price = prices777_price_volume(&vol,baseamount,relamount);
                        if ( i == 0  )
                        {
                            hbla = (hbla == 0.) ? price : 0.5 * (price + hbla);
                            if ( flip == 0 )
                                prices->lastbid = price;
                            else prices->lastask = price;
                        }
                        //printf("(%llu %llu) %f %f mult.%llu qty.%llu pqt.%llu baseamount.%lld relamount.%lld\n",(long long)prices->baseid,(long long)prices->relid,price,vol,(long long)prices->ap_mult,(long long)qty,(long long)pqt,(long long)baseamount,(long long)relamount);
                        timestamp = get_blockutime(juint(item,"height"));
                        item = inner_json(price,vol,timestamp,j64bits(item,prices->type != 5 ? "order" : "offer"),j64bits(item,"account"),qty,pqt,baseamount,relamount);
                        cJSON_AddItemToArray(array,item);
                    }
                }
                free_json(json);
            }
            free(str);
        } else printf("cant get.(%s)\n",url);
    }
    json = cJSON_CreateObject();
    cJSON_AddItemToObject(json,"bids",bids);
    cJSON_AddItemToObject(json,"asks",asks);
    if ( Debuglevel > 2 )
        printf("NXTAE.(%s)\n",jprint(json,0));
    prices777_json_orderbook("nxtae",prices,maxdepth,json,0,"bids","asks",0,0);
    free_json(json);
    return(hbla);
}

double prices777_unconfNXT(struct prices777 *prices,int32_t maxdepth)
{
    struct destbuf account,txidstr,comment,recipient; char url[1024],*str; uint32_t timestamp; int32_t type,i,subtype,n;
    cJSON *json,*bids,*asks,*array,*txobj,*attachment;
    double price,vol; uint64_t assetid,accountid,quoteid,baseamount,relamount,qty,priceNQT,amount;
    bids = cJSON_CreateArray(), asks = cJSON_CreateArray();
    prices->lastbid = prices->lastask = 0.;
    prices->O.numbids = prices->O.numasks = 0;
    sprintf(url,"requestType=getUnconfirmedTransactions");
    if ( IGUANA_disableNXT == 0 && (str= issue_NXTPOST(url)) != 0 )
    {
        //printf("{%s}\n",str);
        if ( (json= cJSON_Parse(str)) != 0 )
        {
            if ( (array= jarray(&n,json,"unconfirmedTransactions")) != 0 )
            {
                for (i=0; i<n; i++)
                {
      //{"senderPublicKey":"45c9266036e705a9559ccbd2b2c92b28ea6363d2723e8d42433b1dfaa421066c","signature":"9d6cefff4c67f8cf4e9487122e5e6b1b65725815127063df52e9061036e78c0b49ba38dbfc12f03c158697f0af5811ce9398702c4acb008323df37dc55c1b43d","feeNQT":"100000000","type":2,"fullHash":"6a2cd914b9d4a5d8ebfaecaba94ef4e7d2b681c236a4bee56023aafcecd9b704","version":1,"phased":false,"ecBlockId":"887016880740444200","signatureHash":"ba8eee4beba8edbb6973df4243a94813239bf57b91cac744cb8d6a5d032d5257","attachment":{"quantityQNT":"50","priceNQT":"18503000003","asset":"13634675574519917918","version.BidOrderPlacement":1},"senderRS":"NXT-FJQN-8QL2-BMY3-64VLK","subtype":3,"amountNQT":"0","sender":"5245394173527769812","ecBlockHeight":495983,"deadline":1440,"transaction":"15611117574733507690","timestamp":54136768,"height":2147483647},{"senderPublicKey":"c42956d0a9abc5a2e455e69c7e65ff9a53de2b697e913b25fcb06791f127af06","signature":"ca2c3f8e32d3aa003692fef423193053c751235a25eb5b67c21aefdeb7a41d0d37bc084bd2e33461606e25f09ced02d1e061420da7e688306e76de4d4cf90ae0","feeNQT":"100000000","type":2,"fullHash":"51c04de7106a5d5a2895db05305b53dd33fa8b9935d549f765aa829a23c68a6b","version":1,"phased":false,"ecBlockId":"887016880740444200","signatureHash":"d76fce4c081adc29f7e60eba2a930ab5050dd79b6a1355fae04863dddf63730c","attachment":{"version.AskOrderPlacement":1,"quantityQNT":"11570","priceNQT":"110399999","asset":"979292558519844732"},"senderRS":"NXT-ANWW-C5BZ-SGSB-8LGZY","subtype":2,"amountNQT":"0","sender":"8033808554894054300","ecBlockHeight":495983,"deadline":1440,"transaction":"6511477257080258641","timestamp":54136767,"height":2147483647}],"requestProcessingTime":0}
                    
                   /* "senderRS": "NXT-M6QF-Q5WK-2UXK-5D3HR",
                    "subtype": 0,
                    "amountNQT": "137700000000",
                    "sender": "4304363382952792781",
                    "recipientRS": "NXT-6AC7-V9BD-NL5W-5BUWF",
                    "recipient": "3959589697280418117",
                    "ecBlockHeight": 506207,
                    "deadline": 1440,
                    "transaction": "5605109208989354417",
                    "timestamp": 55276659,
                    "height": 2147483647*/
                    if ( (txobj= jitem(array,i)) == 0 )
                        continue;
                    copy_cJSON(&txidstr,cJSON_GetObjectItem(txobj,"transaction"));
                    copy_cJSON(&recipient,cJSON_GetObjectItem(txobj,"recipient"));
                    copy_cJSON(&account,cJSON_GetObjectItem(txobj,"account"));
                    if ( account.buf[0] == 0 )
                        copy_cJSON(&account,cJSON_GetObjectItem(txobj,"sender"));
                    accountid = calc_nxt64bits(account.buf);
                    type = (int32_t)get_API_int(cJSON_GetObjectItem(txobj,"type"),-1);
                    subtype = (int32_t)get_API_int(cJSON_GetObjectItem(txobj,"subtype"),-1);
                    timestamp = juint(txobj,"timestamp");
                    amount = get_API_nxt64bits(cJSON_GetObjectItem(txobj,"amountNQT"));
                    qty = amount = assetid = 0;
                    if ( (attachment= cJSON_GetObjectItem(txobj,"attachment")) != 0 )
                    {
                        assetid = get_API_nxt64bits(cJSON_GetObjectItem(attachment,"asset"));
                        comment.buf[0] = 0;
                        qty = get_API_nxt64bits(cJSON_GetObjectItem(attachment,"quantityQNT"));
                        priceNQT = get_API_nxt64bits(cJSON_GetObjectItem(attachment,"priceNQT"));
                        baseamount = (qty * prices->ap_mult), relamount = (qty * priceNQT);
                        copy_cJSON(&comment,jobj(attachment,"message"));
                        if ( comment.buf[0] != 0 )
                        {
                            int32_t match_unconfirmed(char *sender,char *hexstr,cJSON *txobj,char *txidstr,char *account,uint64_t amount,uint64_t qty,uint64_t assetid,char *recipient);
                            //printf("sender.%s -> recv.(%s)\n",account,recipient);
                            match_unconfirmed(account.buf,comment.buf,txobj,txidstr.buf,account.buf,amount,qty,assetid,recipient.buf);
                        }
                        quoteid = calc_nxt64bits(txidstr.buf);
                        price = prices777_price_volume(&vol,baseamount,relamount);
                        if ( prices->baseid == assetid )
                        {
                            if ( Debuglevel > 2 )
                                printf("unconf.%d subtype.%d %s %llu (%llu %llu) %f %f mult.%llu qty.%llu pqt.%llu baseamount.%lld relamount.%lld\n",i,subtype,txidstr.buf,(long long)prices->baseid,(long long)assetid,(long long)NXT_ASSETID,price,vol,(long long)prices->ap_mult,(long long)qty,(long long)priceNQT,(long long)baseamount,(long long)relamount);
                            if ( subtype == 2 )
                            {
                                array = bids;
                                prices->lastbid = price;
                            }
                            else if ( subtype == 3 )
                            {
                                array = asks;
                                prices->lastask = price;
                            }
                            cJSON_AddItemToArray(array,inner_json(price,vol,timestamp,quoteid,accountid,qty,priceNQT,baseamount,relamount));
                        }
                    }
                }
                free_json(json);
            }
            free(str);
        } else printf("cant get.(%s)\n",url);
    }
    json = cJSON_CreateObject();
    cJSON_AddItemToObject(json,"bids",bids);
    cJSON_AddItemToObject(json,"asks",asks);
    prices777_json_orderbook("unconf",prices,maxdepth,json,0,"bids","asks",0,0);
    if ( Debuglevel > 2 )//|| prices->O.numbids != 0 || prices->O.numasks != 0 )
        printf("%s %s/%s unconf.(%s) %f %f (%d %d)\n",prices->contract,prices->base,prices->rel,jprint(json,0),prices->lastbid,prices->lastask,prices->O.numbids,prices->O.numasks);
    free_json(json);
    return(_pairaved(prices->lastbid,prices->lastask));
}

double prices777_InstantDEX(struct prices777 *prices,int32_t maxdepth)
{
    cJSON *json; double hbla = 0.;
    if ( (json= InstantDEX_orderbook(prices)) != 0 ) // strcmp(prices->exchange,INSTANTDEX_NAME) == 0 &&
    {
        if ( Debuglevel > 2 )
            printf("InstantDEX.(%s)\n",jprint(json,0));
        prices777_json_orderbook("InstantDEX",prices,maxdepth,json,0,"bids","asks",0,0);
        free_json(json);
    }
    return(hbla);
}

#define BASE_ISNXT 1
#define BASE_ISASSET 2
#define BASE_ISNAME 4
#define BASE_ISMGW 8
#define BASE_EXCHANGEASSET 16

int32_t calc_baseflags(char *exchange,char *base,uint64_t *baseidp)
{
    char assetidstr[64],tmpstr[64],*str; uint64_t tmp; int32_t flags = 0;
    exchange[0] = 0;
    printf("calc_baseflags.(%s/%llu) ",base,(long long)*baseidp);
    if ( strcmp(base,"NXT") == 0 || *baseidp == NXT_ASSETID )
        strcpy(base,"NXT"), *baseidp = NXT_ASSETID, flags |= BASE_ISNXT;
    else
    {
        if ( *baseidp == 0 )
        {
            if ( is_decimalstr(base) != 0 )
            {
                *baseidp = calc_nxt64bits(base), flags |= BASE_ISASSET;
                unstringbits(tmpstr,*baseidp);
                if ( (tmp= is_MGWcoin(tmpstr)) != 0 )
                    *baseidp = tmp, flags |= (BASE_EXCHANGEASSET | BASE_ISMGW);
                else
                {
                    printf("set base.(%s) -> %llu\n",base,(long long)*baseidp);
                    if ( (str= is_MGWasset(*baseidp)) != 0 )
                        strcpy(base,str), flags |= (BASE_EXCHANGEASSET | BASE_ISMGW);
                }
            }
            else
            {
                *baseidp = stringbits(base), flags |= BASE_ISNAME;
                printf("stringbits.(%s) -> %llu\n",base,(long long)*baseidp);
            }
        }
        else
        {
            if ( (str= is_MGWasset(*baseidp)) != 0 )
            {
                printf("is MGWasset.(%s)\n",str);
                strcpy(base,str), flags |= (BASE_EXCHANGEASSET | BASE_ISMGW | BASE_ISASSET);
            }
            else
            {
                expand_nxt64bits(assetidstr,*baseidp);
                if ( (str= is_tradedasset(exchange,assetidstr)) != 0 )
                {
                    strcpy(base,str), flags |= (BASE_EXCHANGEASSET | BASE_ISASSET);
                    printf("%s is tradedasset at (%s) %llu\n",assetidstr,str,(long long)*baseidp);
                }
                else
                {
                    unstringbits(tmpstr,*baseidp);
                    if ( (tmp= is_MGWcoin(tmpstr)) != 0 )
                        strcpy(base,tmpstr), *baseidp = tmp, flags |= (BASE_EXCHANGEASSET | BASE_ISMGW | BASE_ISASSET);
                    else
                    {
                        _set_assetname(&tmp,base,0,*baseidp), flags |= BASE_ISASSET;
                        printf("_set_assetname.(%s) from %llu\n",base,(long long)*baseidp);
                    }
                }
            }
        }
        if ( (flags & (BASE_ISASSET|BASE_EXCHANGEASSET|BASE_ISMGW)) == 0 )
            *baseidp = stringbits(base);
    }
    printf("-> flags.%d (%s %llu) %s\n",flags,base,(long long)*baseidp,exchange);
    return(flags);
}

void setitemjson(cJSON *item,char *name,char *base,uint64_t baseid,char *rel,uint64_t relid)
{
    char numstr[64];
    jaddstr(item,"name",name), jaddstr(item,"base",base), jaddstr(item,"rel",rel);
    sprintf(numstr,"%llu",(long long)baseid), jaddstr(item,"baseid",numstr);
    sprintf(numstr,"%llu",(long long)relid), jaddstr(item,"relid",numstr);
}

int32_t nxt_basketjson(cJSON *array,int32_t groupid,int32_t polarity,char *base,uint64_t baseid,char *rel,uint64_t relid,char *refbase,char *refrel)
{
    cJSON *item,*item2,*item3; char name[64]; int32_t dir = 0;
    item = cJSON_CreateObject(), jaddstr(item,"exchange",INSTANTDEX_NXTAENAME);
    item2 = cJSON_CreateObject(), jaddstr(item2,"exchange",INSTANTDEX_NXTAEUNCONF);
    item3 = cJSON_CreateObject(), jaddstr(item3,"exchange",INSTANTDEX_NAME);
    if ( strcmp(base,"NXT") == 0 )
    {
        sprintf(name,"%s/%s",rel,"NXT");
        setitemjson(item,name,rel,relid,"NXT",NXT_ASSETID);
        setitemjson(item2,name,rel,relid,"NXT",NXT_ASSETID);
        setitemjson(item3,name,rel,relid,"NXT",NXT_ASSETID);
    }
    else if ( strcmp(rel,"NXT") == 0 )
    {
        sprintf(name,"%s/%s",base,"NXT");
        setitemjson(item,name,base,baseid,"NXT",NXT_ASSETID);
        setitemjson(item2,name,base,baseid,"NXT",NXT_ASSETID);
        setitemjson(item3,name,base,baseid,"NXT",NXT_ASSETID);
    }
    else
    {
        free_json(item);
        free_json(item2);
        free_json(item3);
        return(0);
    }
    if ( strcmp(refbase,rel) == 0 || strcmp(refrel,base) == 0 )
        dir = -1;
    else dir = 1;
    jaddnum(item,"wt",dir), jaddnum(item2,"wt",dir), jaddnum(item3,"wt",dir);
    jaddnum(item,"group",groupid), jaddnum(item2,"group",groupid), jaddnum(item3,"group",groupid);
    printf("nxt_basketjson (%s/%s) %llu/%llu ref.(%s/%s) dir.%d polarity.%d\n",base,rel,(long long)baseid,(long long)relid,refbase,refrel,dir,polarity);
    jaddi(array,item), jaddi(array,item2), jaddi(array,item3);
    return(dir * polarity);
}

void add_nxtbtc(cJSON *array,int32_t groupid,double wt)
{
    char *btcnxt_xchgs[] = { "poloniex", "bittrex", "btc38" };
    int32_t i; cJSON *item;
    if ( wt != 0 )
    {
        printf("add NXT/BTC\n");
        for (i=0; i<sizeof(btcnxt_xchgs)/sizeof(*btcnxt_xchgs); i++)
        {
            item = cJSON_CreateObject(), jaddstr(item,"exchange",btcnxt_xchgs[i]);
            setitemjson(item,"NXT/BTC","NXT",NXT_ASSETID,"BTC",BTC_ASSETID);
            jaddnum(item,"wt",wt);
            jaddnum(item,"group",groupid);
            jaddi(array,item);
        }
    }
}

int32_t get_duplicates(uint64_t *duplicates,uint64_t baseid)
{
    int32_t i,j,n = 0; char assetidstr[64],name[64]; uint64_t tmp;
    unstringbits(name,baseid);
    if ( (tmp= is_MGWcoin(name)) != 0 )
        baseid = tmp;
    else
    {
        for (i=0; i<(int32_t)(sizeof(Tradedassets)/sizeof(*Tradedassets)); i++)
            if ( strcmp(Tradedassets[i][1],name) == 0 )
            {
                baseid = calc_nxt64bits(Tradedassets[i][0]);
                printf("baseid.%llu <- (%s)\n",(long long)baseid,name);
            }
    }
    expand_nxt64bits(assetidstr,baseid);
    duplicates[n++] = baseid;
    for (i=0; i<(int32_t)(sizeof(Tradedassets)/sizeof(*Tradedassets)); i++)
        if ( strcmp(Tradedassets[i][0],assetidstr) == 0 )
        {
            for (j=0; j<(int32_t)(sizeof(Tradedassets)/sizeof(*Tradedassets)); j++)
            {
                if ( i != j && strcmp(Tradedassets[i][1],Tradedassets[j][1]) == 0 )
                {
                    duplicates[n++] = calc_nxt64bits(Tradedassets[j][0]);
                    printf("found duplicate.%s\n",Tradedassets[j][0]);
                }
            }
            break;
        }
    for (i=0; i<(int32_t)(sizeof(MGWassets)/sizeof(*MGWassets)); i++)
        if ( strcmp(MGWassets[i][0],assetidstr) == 0 )
        {
            for (j=0; j<(int32_t)(sizeof(MGWassets)/sizeof(*MGWassets)); j++)
            {
                if ( i != j && strcmp(MGWassets[i][1],MGWassets[j][1]) == 0 )
                    duplicates[n++] = calc_nxt64bits(MGWassets[j][0]);
            }
            break;
        }
    return(n);
}

cJSON *make_arrayNXT(cJSON *directarray,cJSON **arrayBTCp,char *base,char *rel,uint64_t baseid,uint64_t relid)
{
    cJSON *item,*arrayNXT = 0; char tmpstr[64],baseexchange[64],relexchange[64],*str;
    int32_t wt,baseflags,relflags,i,j,n,m; uint64_t duplicatebases[16],duplicaterels[16];
    baseflags = calc_baseflags(baseexchange,base,&baseid);
    relflags = calc_baseflags(relexchange,rel,&relid);
    sprintf(tmpstr,"%s/%s",base,rel);
    printf("make_arrayNXT base.(%s) %llu rel.(%s) %llu baseflags.%d relflags.%d\n",base,(long long)baseid,rel,(long long)relid,baseflags,relflags);
    item = cJSON_CreateObject(), setitemjson(item,tmpstr,base,baseid,rel,relid);
    jaddstr(item,"exchange",INSTANTDEX_NAME);
    jaddnum(item,"wt",1), jaddnum(item,"group",0), jaddi(directarray,item);
    if ( ((baseflags | relflags) & BASE_ISNXT) != 0 )
    {
        printf("one is NXT\n");
        if ( strcmp(base,"NXT") == 0 )
            n = get_duplicates(duplicatebases,relid), wt = -1, str = rel;
        else n = get_duplicates(duplicatebases,baseid), wt = 1, str = base;
        sprintf(tmpstr,"%s/%s",str,"NXT");
        for (i=0; i<n; i++)
            nxt_basketjson(directarray,0,wt,str,duplicatebases[i],"NXT",NXT_ASSETID,base,rel);
    }
    else if ( (baseflags & BASE_ISASSET) != 0 && (relflags & BASE_ISASSET) != 0 )
    {
        printf("both are assets (%s/%s)\n",base,rel);
        arrayNXT = cJSON_CreateArray();
        n = get_duplicates(duplicatebases,baseid);
        for (i=0; i<n; i++)
            nxt_basketjson(arrayNXT,0,1,base,duplicatebases[i],"NXT",NXT_ASSETID,base,rel);
        if ( strcmp(base,"BTC") == 0 )
            add_nxtbtc(arrayNXT,0,-1);
        sprintf(tmpstr,"%s/%s",rel,"NXT");
        m = get_duplicates(duplicaterels,relid);
        for (j=0; j<m; j++)
            nxt_basketjson(arrayNXT,1,-1,rel,duplicaterels[j],"NXT",NXT_ASSETID,base,rel);
        if ( strcmp(rel,"BTC") == 0 )
            add_nxtbtc(arrayNXT,1,1);
    }
    if ( (baseflags & BASE_EXCHANGEASSET) != 0 || (relflags & BASE_EXCHANGEASSET) != 0 )
    {
        printf("have exchange asset %d %d\n",baseflags,relflags);
        if ( (baseflags & BASE_EXCHANGEASSET) != 0 && (relflags & BASE_EXCHANGEASSET) != 0 )
        {
            printf("both are exchange asset\n");
            if ( *arrayBTCp == 0 )
                *arrayBTCp = cJSON_CreateArray();
            if ( strcmp(base,"BTC") != 0 && strcmp(rel,"BTC") != 0 )
            {
                printf("a both are exchange asset\n");
                item = cJSON_CreateObject(), jaddstr(item,"exchange",baseexchange);
                sprintf(tmpstr,"%s/%s",base,"BTC");
                setitemjson(item,tmpstr,base,baseid,"BTC",stringbits("BTC"));
                jaddi(*arrayBTCp,item);
                item = cJSON_CreateObject(), jaddstr(item,"exchange",relexchange);
                sprintf(tmpstr,"%s/%s",rel,"BTC");
                setitemjson(item,tmpstr,rel,relid,"BTC",stringbits("BTC"));
                jaddnum(item,"wt",-1);
                jaddnum(item,"group",1);
                jaddi(*arrayBTCp,item);
            }
        }
        else if ( (baseflags & BASE_EXCHANGEASSET) != 0 )
        {
            if ( strcmp(base,"BTC") != 0 && strcmp(rel,"BTC") == 0 )
            {
                printf("base.(%s/%s) is exchangeasset\n",base,rel);
                item = cJSON_CreateObject(), jaddstr(item,"exchange",baseexchange);
                sprintf(tmpstr,"%s/%s",base,"BTC");
                setitemjson(item,tmpstr,base,baseid,"BTC",stringbits("BTC"));
                jaddi(directarray,item);
            }
        }
        else
        {
            if ( strcmp(rel,"BTC") != 0 && strcmp(base,"BTC") == 0 )
            {
                printf("rel.(%s/%s) is exchangeasset\n",base,rel);
                item = cJSON_CreateObject(), jaddstr(item,"exchange",relexchange);
                sprintf(tmpstr,"%s/%s",rel,"BTC");
                setitemjson(item,tmpstr,rel,relid,"BTC",stringbits("BTC"));
                jaddnum(item,"wt",-1);
                jaddi(directarray,item);
            }
        }
    }
    return(arrayNXT);
}

int32_t centralexchange_items(int32_t group,double wt,cJSON *array,char *_base,char *_rel,int32_t tradeable,char *refbase,char *refrel)
{
    int32_t exchangeid,inverted,n = 0; char base[64],rel[64],name[64]; cJSON *item;
    for (exchangeid=FIRST_EXTERNAL; exchangeid<MAX_EXCHANGES; exchangeid++)
    {
        strcpy(base,_base), strcpy(rel,_rel);
        if ( Exchanges[exchangeid].name[0] == 0 )
            break;
        //printf("check %s for (%s/%s) group.%d wt.%f\n",Exchanges[exchangeid].name,base,rel,group,wt);
        if ( Exchanges[exchangeid].issue.supports != 0 && (inverted= (*Exchanges[exchangeid].issue.supports)(base,rel)) != 0 && (tradeable == 0 || Exchanges[exchangeid].apikey[0] != 0|| Exchanges[exchangeid].apisecret[0] != 0) )
        {
            if ( array != 0 )
            {
                item = cJSON_CreateObject(), jaddstr(item,"exchange",Exchanges[exchangeid].name);
                //printf("ref.(%s/%s) vs (%s/%s) inverted.%d flipped.%d\n",refbase,refrel,base,rel,inverted,strcmp(refbase,rel) == 0 || strcmp(refrel,base) == 0);
                if ( inverted < 0 )
                    jaddstr(item,"base",rel), jaddstr(item,"rel",base), sprintf(name,"%s/%s",rel,base);
                else jaddstr(item,"base",base), jaddstr(item,"rel",rel), sprintf(name,"%s/%s",base,rel);
                if ( strcmp(refbase,rel) == 0 || strcmp(refrel,base) == 0 )
                    jaddnum(item,"wt",-inverted);
                else jaddnum(item,"wt",inverted);
                jaddstr(item,"name",name), jaddnum(item,"group",group);
                printf("ADDED.%s inverted.%d (%s) ref.(%s/%s)\n",Exchanges[exchangeid].name,inverted,name,refbase,refrel);
                jaddi(array,item);
            }
            n++;
        } //else printf("%s doesnt support.(%s/%s)\n",Exchanges[exchangeid].name,base,rel);
    }
    return(n);
}

cJSON *external_combo(char *base,char *rel,char *coinstr,int32_t tradeable)
{
    cJSON *array = 0;
    printf("check central jumper.(%s) for (%s/%s)\n",coinstr,base,rel);
    //if ( (baseflags & (BASE_ISNAME|BASE_ISMGW)) != 0 && (relflags & (BASE_ISNAME|BASE_ISMGW)) != 0 )
    {
        if ( strcmp(base,coinstr) != 0 && strcmp(rel,coinstr) != 0 && centralexchange_items(0,1,0,base,coinstr,tradeable,base,rel) > 0 && centralexchange_items(0,1,0,rel,coinstr,tradeable,base,rel) > 0 )
        {
            array = cJSON_CreateArray();
            printf("add central jumper.(%s) for (%s/%s)\n",coinstr,base,rel);
            centralexchange_items(0,1,array,base,coinstr,tradeable,base,rel);
            centralexchange_items(1,-1,array,rel,coinstr,tradeable,base,rel);
        }
    }
    return(array);
}

int32_t make_subactive(struct prices777 *baskets[],int32_t n,cJSON *array,char *prefix,char *base,char *rel,uint64_t baseid,uint64_t relid,int32_t maxdepth)
{
    char tmpstr[64],typestr[64]; struct prices777 *basket; cJSON *basketjson;
    basketjson = cJSON_CreateObject();
    sprintf(tmpstr,"%s/%s",base,rel);
    setitemjson(basketjson,tmpstr,base,baseid,rel,relid);
    jadd(basketjson,"basket",array);
    printf("%s BASKETMAKE.(%s)\n",prefix,jprint(basketjson,0));
    sprintf(typestr,"basket%s",prefix);
    if ( (basket= prices777_makebasket(0,basketjson,1,typestr,0,0)) != 0 )
    {
        prices777_basket(basket,maxdepth);
        prices777_jsonstrs(basket,&basket->O);
        printf("add to baskets[%d].%s (%s/%s) (%s)\n",n,basket->exchange,basket->base,basket->rel,basket->contract);
        baskets[n++] = basket;
    }
    free_json(basketjson);
    return(n);
}

char *prices777_activebooks(char *name,char *_base,char *_rel,uint64_t baseid,uint64_t relid,int32_t maxdepth,int32_t allflag,int32_t tradeable)
{
    cJSON *array,*arrayNXT,*arrayBTC,*arrayUSD,*arrayCNY,*basketjson; struct prices777 *active,*basket,*baskets[64];
    int32_t inverted,keysize,baseflags,relflags,n = 0; char tmpstr[64],base[64],rel[64],bexchange[64],rexchange[64],key[512],*retstr = 0;
    memset(baskets,0,sizeof(baskets));
    strcpy(base,_base), strcpy(rel,_rel);
    baseflags = calc_baseflags(bexchange,base,&baseid);
    relflags = calc_baseflags(rexchange,rel,&relid);
    InstantDEX_name(key,&keysize,"active",name,base,&baseid,rel,&relid);
    printf("activebooks (%s/%s) (%llu/%llu)\n",base,rel,(long long)baseid,(long long)relid);
    if ( (active= prices777_find(&inverted,baseid,relid,"active")) == 0 )
    {
        if ( ((baseflags & BASE_ISMGW) != 0 || (baseflags & BASE_ISASSET) == 0) && ((relflags & BASE_ISMGW) != 0 || (relflags & BASE_ISASSET) == 0) )
        {
            if ( (arrayUSD= external_combo(base,rel,"USD",tradeable)) != 0 )
                n = make_subactive(baskets,n,arrayUSD,"USD",base,rel,baseid,relid,maxdepth);
            if ( (arrayCNY= external_combo(base,rel,"CNY",tradeable)) != 0 )
                n = make_subactive(baskets,n,arrayCNY,"CNY",base,rel,baseid,relid,maxdepth);
        }
        arrayBTC = external_combo(base,rel,"BTC",tradeable);
        basketjson = cJSON_CreateObject(), array = cJSON_CreateArray();
        sprintf(tmpstr,"%s/%s",base,rel);
        setitemjson(basketjson,tmpstr,base,baseid,rel,relid);
        //if ( baseflags != BASE_ISASSET && relflags != BASE_ISASSET )
            centralexchange_items(0,1,array,base,rel,tradeable,base,rel);
        if ( (arrayNXT= make_arrayNXT(array,&arrayBTC,base,rel,baseid,relid)) != 0 )
            n = make_subactive(baskets,n,arrayNXT,"NXT",base,rel,baseid,relid,maxdepth);
        if ( arrayBTC != 0 )
            n = make_subactive(baskets,n,arrayBTC,"BTC",base,rel,baseid,relid,maxdepth);
        if ( (basket= prices777_find(&inverted,baseid,relid,"basket")) != 0 )
            baskets[n++] = basket;
        jadd(basketjson,"basket",array);
        printf(" ACTIVE MAKE.(%s)\n",jprint(basketjson,0));
        if ( (active= prices777_makebasket(0,basketjson,1,"active",baskets,n)) != 0 )
        {
            prices777_basket(active,maxdepth);
            prices777_jsonstrs(active,&active->O);
        }
        free_json(array);
    }
    if ( active != 0 && retstr == 0 )
    {
        prices777_basket(active,maxdepth);
        prices777_jsonstrs(active,&active->O);
        if ( (retstr= active->orderbook_jsonstrs[inverted][allflag]) != 0 )
            retstr = clonestr(retstr);
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"null active orderbook\"}");
    return(retstr);
}

cJSON *basketitem_json(struct prices777 *prices)
{
    int32_t i; char numstr[64]; cJSON *json,*array,*item;
    json = cJSON_CreateObject();
    if ( prices != 0 )
    {
        jaddstr(json,"exchange",prices->exchange);
        jaddstr(json,"name",prices->contract);
        jaddstr(json,"base",prices->base);
        sprintf(numstr,"%llu",(long long)prices->baseid), jaddstr(json,"baseid",numstr);
        jaddstr(json,"rel",prices->rel);
        sprintf(numstr,"%llu",(long long)prices->relid), jaddstr(json,"relid",numstr);
        jaddnum(json,"commission",prices->commission);
        if ( prices->basketsize != 0 )
        {
            array = cJSON_CreateArray();
            for (i=0; i<prices->basketsize; i++)
            {
                item = basketitem_json(prices->basket[i].prices);
                if ( prices->basket[i].groupsize != 0 )
                    jaddnum(item,"groupsize",prices->basket[i].groupsize);
                jaddnum(item,"group",prices->basket[i].groupid);
                jaddnum(item,"wt",prices->basket[i].wt);
                jaddi(array,item);
            }
            jadd(json,"basket",array);
        }
    }
    return(json);
}

char *prices777_allorderbooks()
{
    int32_t i; cJSON *json,*array = cJSON_CreateArray();
    for (i=0; i<BUNDLE.num; i++)
        jaddi(array,basketitem_json(BUNDLE.ptrs[i]));
    json = cJSON_CreateObject();
    cJSON_AddItemToObject(json,"orderbooks",array);
    return(jprint(json,1));
}

struct prices777 *prices777_initpair(int32_t needfunc,char *exchange,char *_base,char *_rel,double decay,char *_name,uint64_t baseid,uint64_t relid,int32_t basketsize)
{
    static long allocated;
    struct exchange_funcs funcs[] =
    {
        {"nxtae", prices777_NXT, NXT_supports, NXT_tradestub },
        {"unconf", prices777_unconfNXT, NXT_supports, NXT_tradestub },
        {"InstantDEX", prices777_InstantDEX, InstantDEX_supports, InstantDEX_tradestub },
        {"wallet", prices777_InstantDEX, InstantDEX_supports, InstantDEX_tradestub },
        {"basket", prices777_basket, InstantDEX_supports, InstantDEX_tradestub },
        {"basketNXT", prices777_basket, InstantDEX_supports, InstantDEX_tradestub },
        {"basketBTC", prices777_basket, InstantDEX_supports, InstantDEX_tradestub },
        {"basketUSD", prices777_basket, InstantDEX_supports, InstantDEX_tradestub },
        {"basketCNY", prices777_basket, InstantDEX_supports, InstantDEX_tradestub },
        {"active", prices777_basket, InstantDEX_supports, InstantDEX_tradestub },
        {"peggy", prices777_InstantDEX, InstantDEX_supports, InstantDEX_tradestub },
        {"jumblr", prices777_InstantDEX, InstantDEX_supports },
        {"pangea", prices777_InstantDEX, InstantDEX_supports },
        {"truefx", 0 }, {"ecb", 0 }, {"instaforex", 0 }, {"fxcm", 0 }, {"yahoo", 0 },
        poloniex_funcs, bittrex_funcs, btce_funcs, bitfinex_funcs, btc38_funcs, huobi_funcs,
        lakebtc_funcs, quadriga_funcs, okcoin_funcs, coinbase_funcs, bitstamp_funcs
    };
    int32_t i,rellen; char basebuf[64],relbuf[64],base[64],rel[64],name[64]; struct exchange_info *exchangeptr;
    struct prices777 *prices;
    safecopy(base,_base,sizeof(base));
    safecopy(rel,_rel,sizeof(rel));
    safecopy(name,_name,sizeof(name));
    if ( needfunc < 0 )
    {
        for (i=0; i<sizeof(funcs)/sizeof(*funcs); i++)
        {
            if ( (exchangeptr= find_exchange(0,funcs[i].exchange)) != 0 )
            {
                printf("%p %s set supports.%p %p coinbalance.%p\n",exchangeptr,funcs[i].exchange,funcs[i].supports,funcs[i].trade,funcs[i].parsebalance);
                exchangeptr->issue = funcs[i];
            }
        }
        return(0);
    }
    //printf("init.(%s/%s) name.(%s) %llu %llu\n",base,rel,name,(long long)baseid,(long long)relid);
    if ( strcmp(exchange,"nxtae") == 0 || strcmp(exchange,"unconf") == 0 )//|| strcmp(exchange,"InstantDEX") == 0 )
    {
        if ( strcmp(base,"NXT") == 0 || baseid == NXT_ASSETID )
        {
            strcpy(base,rel), baseid = relid;
            strcpy(rel,"NXT"), relid = NXT_ASSETID;
            printf("flip.(%s/%s) %llu %llu\n",base,rel,(long long)baseid,(long long)relid);
        }
    }
    for (i=0; i<BUNDLE.num; i++)
    {
        if ( strcmp(BUNDLE.ptrs[i]->exchange,exchange) == 0 )
        {
            if ( baseid != 0 && relid != 0 && BUNDLE.ptrs[i]->baseid == baseid && BUNDLE.ptrs[i]->relid == relid )
                return(BUNDLE.ptrs[i]);
            if ( strcmp(BUNDLE.ptrs[i]->origbase,base) == 0 && strcmp(BUNDLE.ptrs[i]->origrel,rel) == 0 )
                return(BUNDLE.ptrs[i]);
        }
    }
    printf("cant find (%s) (%llu) (%llu) (%s) (%s)\n",exchange,(long long)baseid,(long long)relid,base,rel);
    prices = calloc(1,sizeof(*prices) + basketsize*sizeof(*prices->basket));
    // printf("new prices %ld\n",sizeof(*prices));
    strcpy(prices->exchange,exchange), strcpy(prices->contract,name), strcpy(prices->base,base), strcpy(prices->rel,rel);
    prices->baseid = baseid, prices->relid = relid;
    prices->contractnum = InstantDEX_name(prices->key,&prices->keysize,exchange,prices->contract,prices->base,&prices->baseid,prices->rel,&prices->relid);
    portable_mutex_init(&prices->mutex);
    strcpy(prices->origbase,base);
    if ( rel[0] != 0 )
        strcpy(prices->origrel,rel);
    allocated += sizeof(*prices);
    safecopy(prices->exchange,exchange,sizeof(prices->exchange));
    if ( strcmp(exchange,"nxtae") == 0 || strcmp(exchange,"unconf") == 0 || strcmp(exchange,INSTANTDEX_NAME) == 0 )
    {
        char tmp[16];
        _set_assetname(&prices->basemult,tmp,0,prices->baseid);
        _set_assetname(&prices->relmult,tmp,0,prices->relid);
        if ( (prices->relid != NXT_ASSETID && prices->relid < (1LL << (5*8))) || (prices->baseid != NXT_ASSETID && prices->baseid == (1LL << (5*8))) )
        {
            printf("illegal baseid.%llu or relid.%llu\n",(long long)prices->baseid,(long long)prices->relid);
            free(prices);
            return(0);
        }
        //prices->nxtbooks = calloc(1,sizeof(*prices->nxtbooks));
        safecopy(prices->lbase,base,sizeof(prices->lbase)), tolowercase(prices->lbase);
        safecopy(prices->lrel,rel,sizeof(prices->lrel)), tolowercase(prices->lrel);
        rellen = (int32_t)(strlen(prices->rel) + 1);
        tmp[0] = 0;
        prices->type = _set_assetname(&prices->ap_mult,tmp,0,prices->baseid);
        printf("nxtbook.(%s) -> NXT %s %llu/%llu vs (%s) mult.%llu (%llu/%llu)\n",base,prices->contract,(long long)prices->baseid,(long long)prices->relid,tmp,(long long)prices->ap_mult,(long long)prices->basemult,(long long)prices->relmult);
    }
    else
    {
        prices->basemult = prices->relmult = 1;
        safecopy(prices->base,base,sizeof(prices->base)), touppercase(prices->base);
        safecopy(prices->lbase,base,sizeof(prices->lbase)), tolowercase(prices->lbase);
        if ( rel[0] == 0 && prices777_ispair(basebuf,relbuf,base) >= 0 )
        {
            strcpy(base,basebuf), strcpy(rel,relbuf);
            //printf("(%s) is a pair (%s)+(%s)\n",base,basebuf,relbuf);
        }
        if ( rel[0] != 0 )
        {
            rellen = (int32_t)(strlen(rel) + 1);
            safecopy(prices->rel,rel,sizeof(prices->rel)), touppercase(prices->rel);
            safecopy(prices->lrel,rel,sizeof(prices->lrel)), tolowercase(prices->lrel);
            if ( prices->contract[0] == 0 )
            {
                strcpy(prices->contract,prices->base);
                if ( strcmp(prices->rel,&prices->contract[strlen(prices->contract)-3]) != 0 )
                    strcat(prices->contract,"/"), strcat(prices->contract,prices->rel);
            }
            //printf("create base.(%s) rel.(%s)\n",prices->base,prices->rel);
        }
        else
        {
            if ( prices->contract[0] == 0 )
                strcpy(prices->contract,base);
        }
    }
    char str[65]; printf("%s init_pair.(%s) (%s)(%s).%llu -> (%s) keysize.%d crc.%u (baseid.%llu relid.%llu)\n",mbstr(str,allocated),exchange,base,rel,(long long)prices->contractnum,prices->contract,prices->keysize,calc_crc32(0,(void *)prices->key,prices->keysize),(long long)prices->baseid,(long long)prices->relid);
    prices->decay = decay, prices->oppodecay = (1. - decay);
    prices->RTflag = 1;
    if ( (exchangeptr= find_exchange(0,exchange)) != 0 )
    {
        if ( prices->commission == 0. )
            prices->commission = exchangeptr->commission;
        prices->exchangeid = exchangeptr->exchangeid;
        if ( exchangeptr->issue.update == 0 )
        {
            for (i=0; i<sizeof(funcs)/sizeof(*funcs); i++)
            {
                if ( strcmp(exchange,funcs[i].exchange) == 0 )
                {
                    exchangeptr->issue = funcs[i];
                    //printf("return prices.%p\n",prices);
                }
            }
        }
        if ( exchangeptr->refcount == 0 )
        {
            printf("incr refcount.%s from %d\n",exchangeptr->name,exchangeptr->refcount);
            exchangeptr->refcount++;
        }
        return(prices);
    }
    //printf("initialized.(%s).%lld\n",prices->contract,(long long)prices->contractnum);
    return(prices);
}

int32_t is_pair(char *base,char *rel,char *refbase,char *refrel)
{
    if ( strcmp(base,refbase) == 0 && strcmp(rel,refrel) == 0 )
        return(1);
    else if ( strcmp(rel,refbase) == 0 && strcmp(base,refrel) == 0 )
        return(-1);
    return(0);
}

struct prices777 *prices777_poll(char *_exchangestr,char *_name,char *_base,uint64_t refbaseid,char *_rel,uint64_t refrelid)
{
    char exchangestr[64],base[64],rel[64],name[64],key[1024]; uint64_t baseid,relid;
    int32_t keysize,exchangeid,valid; struct exchange_info *exchange; struct prices777 *prices;
    baseid = refbaseid, relid = refrelid;
    strcpy(exchangestr,_exchangestr), strcpy(base,_base), strcpy(rel,_rel), strcpy(name,_name);
    if ( (strcmp(exchangestr,"huobi") == 0 && is_pair(base,rel,"BTC","CNY") == 0 && is_pair(base,rel,"LTC","CNY") == 0) ||
        ((strcmp(exchangestr,"bityes") == 0 || strcmp(exchangestr,"okcoin") == 0) && is_pair(base,rel,"BTC","USD") == 0 && is_pair(base,rel,"LTC","USD") == 0) ||
        ((strcmp(exchangestr,"bitstamp") == 0 || strcmp(exchangestr,"coinbase") == 0) && is_pair(base,rel,"BTC","USD") == 0) ||
        (strcmp(exchangestr,"lakebtc") == 0 && is_pair(base,rel,"BTC","CNY") == 0 && is_pair(base,rel,"BTC","USD") == 0) ||
        (strcmp(exchangestr,"quadriga") == 0 && is_pair(base,rel,"BTC","CAD") == 0 && is_pair(base,rel,"BTC","USD") == 0) ||
        0 )
    {
        printf("%s (%s/%s) is not a supported trading pair\n",exchangestr,base,rel);
        return(0);
    }
    InstantDEX_name(key,&keysize,exchangestr,name,base,&baseid,rel,&relid);
    //printf("call addbundle\n");
    if ( (prices= prices777_addbundle(&valid,0,0,exchangestr,baseid,relid)) != 0 )
    {
        printf("found (%s/%s).%s %llu %llu in slot-> %p\n",base,rel,exchangestr,(long long)baseid,(long long)relid,prices);
        return(prices);
    }
    //printf("call find_exchange\n");
    if ( (exchange= find_exchange(&exchangeid,exchangestr)) == 0 )
    {
        printf("cant add exchange.(%s)\n",exchangestr);
        return(0);
    }
    if ( strcmp(exchangestr,"nxtae") == 0 || strcmp(exchangestr,"unconf") == 0 )
    {
        if ( strcmp(base,"NXT") != 0 && strcmp(rel,"NXT") != 0 )
        {
            printf("nxtae/unconf needs to be relative to NXT (%s/%s) %llu/%llu\n",base,rel,(long long)baseid,(long long)relid);
            return(0);
        }
    }
    if ( (prices= prices777_initpair(1,exchangestr,base,rel,0.,name,baseid,relid,0)) != 0 )
    {
        //printf("call addbundle after initpair\n");
        prices777_addbundle(&valid,1,prices,0,0,0);
    }
    return(prices);
}

int32_t prices777_propagate(struct prices777 *prices)
{
    int32_t i,n = 0;
    for (i=0; i<prices->numdependents; i++)
    {
        n++;
        if ( (*prices->dependents[i]) < 0xff )
            (*prices->dependents[i])++;
        if ( Debuglevel > 2 )
            printf("numdependents.%d of %d %p %d\n",i,prices->numdependents,prices->dependents[i],*prices->dependents[i]);
    }
    return(n);
}

int32_t prices777_updated;
void prices777_basketsloop(void *ptr)
{
    extern int32_t prices777_NXTBLOCK;
    int32_t i,n; uint32_t updated; struct prices777 *prices;
    while ( 1 )
    {
        for (i=n=0; i<BUNDLE.num; i++)
        {
            updated = (uint32_t)time(NULL);
            if ( (prices= BUNDLE.ptrs[i]) != 0 && prices->disabled == 0 && prices->basketsize != 0 )
            {
                if ( prices->changed != 0 )
                {
                    if ( Debuglevel > 2 )
                        printf("%s updating basket(%s) lastprice %.8f changed.%p %d\n",prices->exchange,prices->contract,prices->lastprice,&prices->changed,prices->changed);
                    prices->pollnxtblock = prices777_NXTBLOCK;
                    n++;
                    prices->lastupdate = updated;
                    if ( (prices->lastprice= prices777_basket(prices,MAX_DEPTH)) != 0. )
                    {
                        if ( prices->O.numbids > 0 || prices->O.numasks > 0 )
                        {
                            prices777_jsonstrs(prices,&prices->O);
                            prices777_updated += prices777_propagate(prices);
                        }
                    }
                    prices->changed = 0;
                }
            }
        }
        if ( n == 0 )
            usleep(250000);
        else usleep(10000);
    }
}

void prices777_exchangeloop(void *ptr)
{
    extern int32_t prices777_NXTBLOCK;
    struct prices777 *prices; int32_t i,n,pollflag,isnxtae = 0; double updated = 0.; struct exchange_info *exchange = ptr;
    if ( strcmp(exchange->name,"nxtae") == 0 || strcmp(exchange->name,"unconf") == 0 )
        isnxtae = 1;
    printf("POLL.(%s)\n",exchange->name);
    while ( 1 )
    {
        for (i=n=0; i<BUNDLE.num; i++)
        {
            if ( (prices= BUNDLE.ptrs[i]) != 0 && prices->disabled == 0 && prices->basketsize == 0 && prices->exchangeid == exchange->exchangeid )
            {
                if ( prices->exchangeid == INSTANTDEX_EXCHANGEID && prices->dirty != 0 )
                    pollflag = 1;
                else if ( isnxtae == 0 )
                    pollflag = milliseconds() > (exchange->lastupdate + exchange->pollgap*1000) && milliseconds() > (prices->lastupdate + 1000*IGUANA_EXCHANGEIDLE);
                else if ( (strcmp(exchange->name,"unconf") == 0 && milliseconds() > prices->lastupdate + 5000) || prices->pollnxtblock < prices777_NXTBLOCK || milliseconds() > prices->lastupdate + 1000*IGUANA_EXCHANGEIDLE )
                    pollflag = 1;
                else continue;
                //printf("(%s) pollflag.%d %p\n",exchange->name,pollflag,exchange->issue.update);
                if ( pollflag != 0 && exchange->issue.update != 0 )
                {
                    portable_mutex_lock(&exchange->mutex);
                    prices->lastprice = (*exchange->issue.update)(prices,MAX_DEPTH);
                    portable_mutex_unlock(&exchange->mutex);
                    updated = exchange->lastupdate = milliseconds(), prices->lastupdate = milliseconds();
                    if ( prices->lastprice != 0. )
                    {
                        if ( Debuglevel > 2 && strcmp(exchange->name,"unconf") != 0 )
                            printf("%-8s %8s (%8s %8s) %llu %llu isnxtae.%d poll %u -> %u %.8f hbla %.8f %.8f\n",prices->exchange,prices->contract,prices->base,prices->rel,(long long)prices->baseid,(long long)prices->relid,isnxtae,prices->pollnxtblock,prices777_NXTBLOCK,prices->lastprice,prices->lastbid,prices->lastask);
                        prices777_propagate(prices);
                    }
                    prices->pollnxtblock = prices777_NXTBLOCK;
                    prices->dirty = 0;
                    n++;
                }
                /*if ( 0 && exchange->issue.trade != 0 && exchange->apikey[0] != 0 && exchange->exchangeid >= FIRST_EXTERNAL && time(NULL) > exchange->lastbalancetime+300 )
                 {
                 if ( (json= (*exchange->issue.balances)(exchange)) != 0 )
                 {
                 if ( exchange->balancejson != 0 )
                 free_json(exchange->balancejson);
                 exchange->balancejson = json;
                 }
                 exchange->lastbalancetime = (uint32_t)time(NULL);
                 }*/
            }
        }
        if ( n == 0 )
            sleep(3);
        else sleep(1);
    }
}

int32_t prices777_init(char *jsonstr,int32_t peggyflag)
{
    static int32_t didinit;
    char *btcdexchanges[] = { "poloniex", "bittrex" };//, "bter" };
    char *btcusdexchanges[] = { "bityes", "bitfinex", "bitstamp", "okcoin", "coinbase", "btce", "lakebtc", "kraken" };
    cJSON *json=0,*item,*exchanges; int32_t i,n; char *exchange,*base,*rel,*contract; struct exchange_info *exchangeptr=0; struct destbuf tmp;
    if ( didinit != 0 )
        return(0);
    didinit = 1;
    if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"unconf","BTC","NXT",0,"BTC/NXT",calc_nxt64bits("12659653638116877017"),NXT_ASSETID,0)) != 0 )
        BUNDLE.num++;
    if ( peggyflag != 0 )
    {
        if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"huobi","BTC","USD",0.,0,0,0,0)) != 0 )
            BUNDLE.num++;
        if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"btc38","CNY","NXT",0.,0,0,0,0)) != 0 )
            BUNDLE.num++;
        if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"okcoin","LTC","BTC",0.,0,0,0,0)) != 0 )
            BUNDLE.num++;
        if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"poloniex","LTC","BTC",0.,0,0,0,0)) != 0 )
            BUNDLE.num++;
        if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"poloniex","XMR","BTC",0.,0,0,0,0)) != 0 )
            BUNDLE.num++;
        if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"poloniex","BTS","BTC",0.,0,0,0,0)) != 0 )
            BUNDLE.num++;
        if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,"poloniex","XCP","BTC",0.,0,0,0,0)) != 0 )
            BUNDLE.num++;
        for (i=0; i<sizeof(btcdexchanges)/sizeof(*btcdexchanges); i++)
            if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,btcusdexchanges[i],"BTC","USD",0.,0,0,0,0)) != 0 )
                BUNDLE.num++;
        for (i=0; i<sizeof(btcdexchanges)/sizeof(*btcdexchanges); i++)
            if ( (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,btcdexchanges[i],"BTCD","BTC",0.,0,0,0,0)) != 0 )
                BUNDLE.num++;
    }
    if ( (json= cJSON_Parse(jsonstr)) != 0 && (exchanges= jarray(&n,json,"prices")) != 0 )
    {
        printf("prices has %d items\n",n);
        for (i=0; i<n; i++)
        {
            item = jitem(exchanges,i);
            exchange = jstr(item,"exchange"), base = jstr(item,"base"), rel = jstr(item,"rel");
            if ( (base == 0 || rel == 0) && (contract= jstr(item,"contract")) != 0 )
                rel = 0, base = contract;
            else contract = 0;
            //printf("PRICES[%d] %p %p %p\n",i,exchange,base,rel);
            if ( exchange != 0 && (strcmp(exchange,"bter") == 0 || strcmp(exchange,"exmo") == 0) )
                continue;
            if ( exchange != 0 && (exchangeptr= find_exchange(0,exchange)) != 0 )
            {
                exchangeptr->pollgap = get_API_int(cJSON_GetObjectItem(item,"pollgap"),IGUANA_EXCHANGEIDLE);
                extract_cJSON_str(exchangeptr->apikey,sizeof(exchangeptr->apikey),item,"key");
                if ( exchangeptr->apikey[0] == 0 )
                    extract_cJSON_str(exchangeptr->apikey,sizeof(exchangeptr->apikey),item,"apikey");
                extract_cJSON_str(exchangeptr->userid,sizeof(exchangeptr->userid),item,"userid");
                extract_cJSON_str(exchangeptr->apisecret,sizeof(exchangeptr->apisecret),item,"secret");
                if ( exchangeptr->apisecret[0] == 0 )
                    extract_cJSON_str(exchangeptr->apisecret,sizeof(exchangeptr->apisecret),item,"apisecret");
                if ( exchangeptr->commission == 0. )
                    exchangeptr->commission = jdouble(item,"commission");
                printf("%p ADDEXCHANGE.(%s) [%s, %s, %s] commission %.3f%%\n",exchangeptr,exchange,exchangeptr->apikey,exchangeptr->userid,exchangeptr->apisecret,exchangeptr->commission * 100);
            } else printf(" exchangeptr.%p for (%p)\n",exchangeptr,exchange);
            if ( exchange != 0 && strcmp(exchange,"truefx") == 0 )
            {
                copy_cJSON(&tmp,jobj(item,"truefxuser")), safecopy(BUNDLE.truefxuser,tmp.buf,sizeof(BUNDLE.truefxuser));
                copy_cJSON(&tmp,jobj(item,"truefxpass")), safecopy(BUNDLE.truefxpass,tmp.buf,sizeof(BUNDLE.truefxpass));;
                printf("truefx.(%s %s)\n",BUNDLE.truefxuser,BUNDLE.truefxpass);
            }
            else if ( base != 0 && rel != 0 && base[0] != 0 && rel[0] != 0 && (BUNDLE.ptrs[BUNDLE.num]= prices777_initpair(1,exchange,base,rel,jdouble(item,"decay"),contract,stringbits(base),stringbits(rel),0)) != 0 )
            {
                if ( exchangeptr != 0 && (BUNDLE.ptrs[BUNDLE.num]->commission= jdouble(item,"commission")) == 0. )
                    BUNDLE.ptrs[BUNDLE.num]->commission = exchangeptr->commission;
                printf("SET COMMISSION.%s %f for %s/%s\n",exchange,exchangeptr!=0?exchangeptr->commission:0,base,rel);
                BUNDLE.num++;
            }
        }
    } else printf("(%s) has no prices[]\n",jsonstr);
    if ( json != 0 )
        free_json(json);
    for (i=0; i<MAX_EXCHANGES; i++)
    {
        exchangeptr = &Exchanges[i];
        if ( (exchangeptr->refcount > 0 || strcmp(exchangeptr->name,"unconf") == 0) )//&& strcmp(exchangeptr->name,"pangea") != 0 && strcmp(exchangeptr->name,"jumblr") != 0 )
            iguana_launch(iguana_coinadd("BTCD"),"exchangeloop",(void *)prices777_exchangeloop,exchangeptr,IGUANA_EXCHANGETHREAD);
    }
    return(0);
}

double prices777_yahoo(char *metal)
{
    // http://finance.yahoo.com/webservice/v1/symbols/allcurrencies/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XAU=X/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XAG=X/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XPT=X/quote?format=json
    // http://finance.yahoo.com/webservice/v1/symbols/XPD=X/quote?format=json
    char url[1024],*jsonstr; cJSON *json,*obj,*robj,*item,*field; double price = 0.;
    sprintf(url,"http://finance.yahoo.com/webservice/v1/symbols/%s=X/quote?format=json",metal);
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        //printf("(%s)\n",jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (obj= jobj(json,"list")) != 0 && (robj= jobj(obj,"resources")) != 0 && (item= jitem(robj,0)) != 0 )
            {
                if ( (robj= jobj(item,"resource")) != 0 && (field= jobj(robj,"fields")) != 0 && (price= jdouble(field,"price")) != 0 )
                    price = 1. / price;
            }
            free_json(json);
        }
        free(jsonstr);
    }
    if ( Debuglevel > 2 )
        printf("(%s %f) ",metal,price);
    return(price);
}

cJSON *url_json(char *url)
{
    char *jsonstr; cJSON *json = 0;
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        //printf("(%s) -> (%s)\n",url,jsonstr);
        json = cJSON_Parse(jsonstr);
        free(jsonstr);
    }
    return(json);
}

cJSON *url_json2(char *url)
{
    char *jsonstr; cJSON *json = 0;
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        //printf("(%s) -> (%s)\n",url,jsonstr);
        json = cJSON_Parse(jsonstr);
        free(jsonstr);
    }
    return(json);
}

void prices777_btcprices(int32_t enddatenum,int32_t numdates)
{
    int32_t i,n,year,month,day,seconds,datenum; char url[1024],date[64],*dstr,*str; uint32_t timestamp,utc32[MAX_SPLINES];
    cJSON *coindesk,*quandl,*btcdhist,*bpi,*array,*item;
    double btcddaily[MAX_SPLINES],cdaily[MAX_SPLINES],qdaily[MAX_SPLINES],ask,high,low,bid,close,vol,quotevol,open,price = 0.;
    coindesk = url_json("http://api.coindesk.com/v1/bpi/historical/close.json");
    sprintf(url,"https://poloniex.com/public?command=returnChartData&currencyPair=BTC_BTCD&start=%ld&end=9999999999&period=86400",(long)(time(NULL)-numdates*3600*24));
    if ( (bpi= jobj(coindesk,"bpi")) != 0 )
    {
        datenum = enddatenum;
        memset(utc32,0,sizeof(utc32));
        memset(cdaily,0,sizeof(cdaily));
        if ( datenum == 0 )
        {
            datenum = OS_conv_unixtime(&seconds,(uint32_t)time(NULL));
            printf("got datenum.%d %d %d %d\n",datenum,seconds/3600,(seconds/60)%24,seconds%60);
        }
        for (i=0; i<numdates; i++)
        {
            expand_datenum(date,datenum);
            if ( (price= jdouble(bpi,date)) != 0 )
            {
                utc32[numdates - 1 - i] = OS_conv_datenum(datenum,12,0,0);
                cdaily[numdates - 1 - i] = price * .001;
                //printf("(%s %u %f) ",date,utc32[numdates - 1 - i],price);
            }
            datenum = ecb_decrdate(&year,&month,&day,date,datenum);
        }
        prices777_genspline(&BUNDLE.splines[MAX_CURRENCIES],MAX_CURRENCIES,"coindesk",utc32,cdaily,numdates,cdaily);
        
    } else printf("no bpi\n");
    quandl = url_json("https://www.quandl.com/api/v1/datasets/BAVERAGE/USD.json?rows=64");
    if ( (str= jstr(quandl,"updated_at")) != 0 && (datenum= conv_date(&seconds,str)) > 0 && (array= jarray(&n,quandl,"data")) != 0 )
    {
        printf("datenum.%d data.%d %d\n",datenum,n,cJSON_GetArraySize(array));
        memset(utc32,0,sizeof(utc32)), memset(qdaily,0,sizeof(qdaily));
        for (i=0; i<n&&i<MAX_SPLINES; i++)
        {
            // ["Date","24h Average","Ask","Bid","Last","Total Volume"]
            // ["2015-07-25",289.27,288.84,288.68,288.87,44978.61]
            item = jitem(array,i);
            if ( Debuglevel > 2 )
                printf("(%s) ",cJSON_Print(item));
            if ( (dstr= jstr(jitem(item,0),0)) != 0 && (datenum= conv_date(&seconds,dstr)) > 0 )
            {
                price = jdouble(jitem(item,1),0), ask = jdouble(jitem(item,2),0), bid = jdouble(jitem(item,3),0);
                close = jdouble(jitem(item,4),0), vol = jdouble(jitem(item,5),0);
                if ( Debuglevel > 2 )
                    fprintf(stderr,"%d.[%d %f %f %f %f %f].%d ",i,datenum,price,ask,bid,close,vol,n);
                utc32[numdates - 1 - i] = OS_conv_datenum(datenum,12,0,0), qdaily[numdates - 1 - i] = price * .001;
            }
        }
        prices777_genspline(&BUNDLE.splines[MAX_CURRENCIES+1],MAX_CURRENCIES+1,"quandl",utc32,qdaily,n<MAX_SPLINES?n:MAX_SPLINES,qdaily);
    }
    btcdhist = url_json(url);
    //{"date":1406160000,"high":0.01,"low":0.00125,"open":0.01,"close":0.001375,"volume":1.50179994,"quoteVolume":903.58818412,"weightedAverage":0.00166204},
    if ( (array= jarray(&n,btcdhist,0)) != 0 )
    {
        memset(utc32,0,sizeof(utc32)), memset(btcddaily,0,sizeof(btcddaily));
        //printf("GOT.(%s)\n",cJSON_Print(array));
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            timestamp = juint(item,"date"), high = jdouble(item,"high"), low = jdouble(item,"low"), open = jdouble(item,"open");
            close = jdouble(item,"close"), vol = jdouble(item,"volume"), quotevol = jdouble(item,"quoteVolume"), price = jdouble(item,"weightedAverage");
            //printf("[%u %f %f %f %f %f %f %f]",timestamp,high,low,open,close,vol,quotevol,price);
            if ( Debuglevel > 2 )
                printf("[%u %d %f]",timestamp,OS_conv_unixtime(&seconds,timestamp),price);
            utc32[i] = timestamp - 12*3600, btcddaily[i] = price * 100.;
        }
        if ( Debuglevel > 2 )
            printf("poloniex.%d\n",n);
        prices777_genspline(&BUNDLE.splines[MAX_CURRENCIES+2],MAX_CURRENCIES+2,"btcdhist",utc32,btcddaily,n<MAX_SPLINES?n:MAX_SPLINES,btcddaily);
    }
    // https://poloniex.com/public?command=returnChartData&currencyPair=BTC_BTCD&start=1405699200&end=9999999999&period=86400
}

int32_t prices777_calcmatrix(double matrix[32][32])
{
    int32_t basenum,relnum,nonz,vnum,iter,numbase,numerrs = 0; double sum,vsum,price,price2,basevals[32],errsum=0;
    memset(basevals,0,sizeof(basevals));
    for (iter=0; iter<2; iter++)
    {
        numbase = 32;
        for (basenum=0; basenum<numbase; basenum++)
        {
            for (vsum=sum=vnum=nonz=relnum=0; relnum<numbase; relnum++)
            {
                if ( basenum != relnum )
                {
                    if ( (price= matrix[basenum][relnum]) != 0. )
                    {
                        price /= (MINDENOMS[relnum] * .001);
                        price *= (MINDENOMS[basenum] * .001);
                        if ( iter == 0 )
                            sum += (price), nonz++;//, printf("%.8f ",price);
                        else sum += fabs((price) - (basevals[basenum] / basevals[relnum])), nonz++;
                    }
                    if ( (price2= matrix[relnum][basenum]) != 0. )
                    {
                        price2 *= (MINDENOMS[relnum] * .001);
                        price2 /= (MINDENOMS[basenum] * .001);
                        if ( iter == 0 )
                            vsum += (price2), vnum++;
                        else vsum += fabs(price2 - (basevals[relnum] / basevals[basenum])), vnum++;
                    }
                    //if ( iter == 0 && 1/price2 > price )
                    //    printf("base.%d rel.%d price2 %f vs %f\n",basenum,relnum,1/price2,price);
                }
            }
            if ( iter == 0 )
                sum += 1., vsum += 1.;
            if ( nonz != 0 )
                sum /= nonz;
            if ( vnum != 0 )
                vsum /= vnum;
            if ( iter == 0 )
                basevals[basenum] = (sum + 1./vsum) / 2.;
            else errsum += (sum + vsum)/2, numerrs++;//, printf("(%.8f %.8f) ",sum,vsum);
            //printf("date.%d (%.8f/%d %.8f/%d).%02d -> %.8f\n",i,sum,nonz,vsum,vnum,basenum,basevals[basenum]);
        }
        if ( iter == 0 )
        {
            for (sum=relnum=0; relnum<numbase; relnum++)
                sum += (basevals[relnum]);//, printf("%.8f ",(basevals[relnum]));
            //printf("date.%d sums %.8f and vsums iter.%d\n",i,sum/7,iter);
            sum /= (numbase - 1);
            for (relnum=0; relnum<numbase; relnum++)
                basevals[relnum] /= sum;//, printf("%.8f ",basevals[relnum]);
            //printf("date.%d sums %.8f and vsums iter.%d\n",i,sum,iter);
        }
        else
        {
            for (basenum=0; basenum<numbase; basenum++)
                matrix[basenum][basenum] = basevals[basenum];
        }
    }
    if ( numerrs != 0 )
        errsum /= numerrs;
    return(errsum);
}

int32_t ecb_matrix(double matrix[32][32],char *date)
{
    FILE *fp=0; int32_t n=0,datenum,year=0,seconds,month=0,day=0,loaded = 0; char fname[64],_date[64];
    if ( date == 0 )
        date = _date, memset(_date,0,sizeof(_date));
    sprintf(fname,"ECB/%s",date), iguana_compatible_path(fname);
    if ( date[0] != 0 && (fp= fopen(fname,"rb")) != 0 )
    {
        if ( fread(matrix,1,sizeof(matrix[0][0])*32*32,fp) == sizeof(matrix[0][0])*32*32 )
            loaded = 1;
        else printf("fread error\n");
        fclose(fp);
    } else printf("ecb_matrix.(%s) load error fp.%p\n",fname,fp);
    if ( loaded == 0 )
    {
        datenum = conv_date(&seconds,date);
        year = datenum / 10000, month = (datenum / 100) % 100, day = (datenum % 100);
        if ( (n= prices777_ecb(date,&matrix[0][0],year,month,day)) > 0 )
        {
            sprintf(fname,"ECB/%s",date), iguana_compatible_path(fname);
            if ( (fp= fopen(fname,"wb")) != 0 )
            {
                if ( fwrite(matrix,1,sizeof(matrix[0][0])*32*32,fp) == sizeof(matrix[0][0])*32*32 )
                    loaded = 1;
                fclose(fp);
            }
        } else printf("peggy_matrix error loading %d.%d.%d\n",year,month,day);
    }
    if ( loaded == 0 && n == 0 )
    {
        printf("peggy_matrix couldnt process loaded.%d n.%d\n",loaded,n);
        return(-1);
    }
    //"2000-01-03"
    if ( (datenum= conv_date(&seconds,date)) < 0 )
        return(-1);
    printf("loaded.(%s) nonz.%d (%d %d %d) datenum.%d\n",date,n,year,month,day,datenum);
    return(datenum);
}

void price777_update(double *btcusdp,double *btcdbtcp)
{
    int32_t i,n,seconds,datenum; uint32_t timestamp; char url[1024],*dstr,*str;
    double btcddaily=0.,btcusd=0.,ask,high,low,bid,close,vol,quotevol,open,price = 0.;
    //cJSON *btcdtrades,*btcdtrades2,*,*bitcoincharts,;
    cJSON *quandl,*btcdhist,*array,*item,*bitcoinave,*blockchaininfo,*coindesk=0;
    //btcdtrades = url_json("https://poloniex.com/public?command=returnTradeHistory&currencyPair=BTC_BTCD");
    //btcdtrades2 = url_json("https://bittrex.com/api/v1.1/public/getmarkethistory?market=BTC-BTCD&count=50");
    bitcoinave = url_json("https://api.bitcoinaverage.com/ticker/USD/");
    //bitcoincharts = url_json("http://api.bitcoincharts.com/v1/weighted_prices.json");
    blockchaininfo = url_json("https://blockchain.info/ticker");
    coindesk = url_json("http://api.coindesk.com/v1/bpi/historical/close.json");
    sprintf(url,"https://poloniex.com/public?command=returnChartData&currencyPair=BTC_BTCD&start=%ld&end=9999999999&period=86400",(long)(time(NULL)-2*3600*24));
    quandl = url_json("https://www.quandl.com/api/v1/datasets/BAVERAGE/USD.json?rows=1");
    if ( quandl != 0 && (str= jstr(quandl,"updated_at")) != 0 && (datenum= conv_date(&seconds,str)) > 0 && (array= jarray(&n,quandl,"data")) != 0 )
    {
        //printf("datenum.%d data.%d %d\n",datenum,n,cJSON_GetArraySize(array));
        for (i=0; i<1; i++)
        {
            // ["Date","24h Average","Ask","Bid","Last","Total Volume"]
            // ["2015-07-25",289.27,288.84,288.68,288.87,44978.61]
            item = jitem(array,i);
            if ( (dstr= jstr(jitem(item,0),0)) != 0 && (datenum= conv_date(&seconds,dstr)) > 0 )
            {
                btcusd = price = jdouble(jitem(item,1),0), ask = jdouble(jitem(item,2),0), bid = jdouble(jitem(item,3),0);
                close = jdouble(jitem(item,4),0), vol = jdouble(jitem(item,5),0);
                //fprintf(stderr,"%d.[%d %f %f %f %f %f].%d ",i,datenum,price,ask,bid,close,vol,n);
            }
        }
    }
    price = 0.;
    for (i=n=0; i<BUNDLE.num; i++)
    {
        if ( strcmp(BUNDLE.ptrs[i]->lbase,"btcd") == 0 && strcmp(BUNDLE.ptrs[i]->lrel,"btc") == 0 && BUNDLE.ptrs[i]->lastprice != 0. )
        {
            price += BUNDLE.ptrs[i]->lastprice;
            n++;
        }
    }
    if ( n != 0 )
    {
        price /= n;
        *btcdbtcp = price;
        //printf("set BTCD price %f\n",price);
        BUNDLE.btcdbtc = price;
    }
    else
    {
        btcdhist = url_json(url);
        //{"date":1406160000,"high":0.01,"low":0.00125,"open":0.01,"close":0.001375,"volume":1.50179994,"quoteVolume":903.58818412,"weightedAverage":0.00166204},
        if ( btcdhist != 0 && (array= jarray(&n,btcdhist,0)) != 0 )
        {
            //printf("GOT.(%s)\n",cJSON_Print(array));
            for (i=0; i<1; i++)
            {
                item = jitem(array,i);
                timestamp = juint(item,"date"), high = jdouble(item,"high"), low = jdouble(item,"low"), open = jdouble(item,"open");
                close = jdouble(item,"close"), vol = jdouble(item,"volume"), quotevol = jdouble(item,"quoteVolume"), price = jdouble(item,"weightedAverage");
                //printf("[%u %f %f %f %f %f %f %f]",timestamp,high,low,open,close,vol,quotevol,price);
                //printf("[%u %d %f]",timestamp,OS_conv_unixtime(&seconds,timestamp),price);
                btcddaily = price;
                if ( btcddaily != 0 )
                    BUNDLE.btcdbtc = *btcdbtcp = btcddaily;
            }
            //printf("poloniex.%d\n",n);
        }
        if ( btcdhist != 0 )
            free_json(btcdhist);
    }
    // https://blockchain.info/ticker
    /*
     {
     "USD" : {"15m" : 288.22, "last" : 288.22, "buy" : 288.54, "sell" : 288.57,  "symbol" : "$"},
     "ISK" : {"15m" : 38765.88, "last" : 38765.88, "buy" : 38808.92, "sell" : 38812.95,  "symbol" : "kr"},
     "HKD" : {"15m" : 2234, "last" : 2234, "buy" : 2236.48, "sell" : 2236.71,  "symbol" : "$"},
     "TWD" : {"15m" : 9034.19, "last" : 9034.19, "buy" : 9044.22, "sell" : 9045.16,  "symbol" : "NT$"},
     "CHF" : {"15m" : 276.39, "last" : 276.39, "buy" : 276.69, "sell" : 276.72,  "symbol" : "CHF"},
     "EUR" : {"15m" : 262.46, "last" : 262.46, "buy" : 262.75, "sell" : 262.78,  "symbol" : "€"},
     "DKK" : {"15m" : 1958.92, "last" : 1958.92, "buy" : 1961.1, "sell" : 1961.3,  "symbol" : "kr"},
     "CLP" : {"15m" : 189160.6, "last" : 189160.6, "buy" : 189370.62, "sell" : 189390.31,  "symbol" : "$"},
     "CAD" : {"15m" : 375.45, "last" : 375.45, "buy" : 375.87, "sell" : 375.91,  "symbol" : "$"},
     "CNY" : {"15m" : 1783.67, "last" : 1783.67, "buy" : 1785.65, "sell" : 1785.83,  "symbol" : "¥"},
     "THB" : {"15m" : 10046.98, "last" : 10046.98, "buy" : 10058.14, "sell" : 10059.18,  "symbol" : "฿"},
     "AUD" : {"15m" : 394.77, "last" : 394.77, "buy" : 395.2, "sell" : 395.25,  "symbol" : "$"},
     "SGD" : {"15m" : 395.08, "last" : 395.08, "buy" : 395.52, "sell" : 395.56,  "symbol" : "$"},
     "KRW" : {"15m" : 335991.51, "last" : 335991.51, "buy" : 336364.55, "sell" : 336399.52,  "symbol" : "₩"},
     "JPY" : {"15m" : 35711.99, "last" : 35711.99, "buy" : 35751.64, "sell" : 35755.35,  "symbol" : "¥"},
     "PLN" : {"15m" : 1082.74, "last" : 1082.74, "buy" : 1083.94, "sell" : 1084.06,  "symbol" : "zł"},
     "GBP" : {"15m" : 185.84, "last" : 185.84, "buy" : 186.04, "sell" : 186.06,  "symbol" : "£"},
     "SEK" : {"15m" : 2471.02, "last" : 2471.02, "buy" : 2473.76, "sell" : 2474.02,  "symbol" : "kr"},
     "NZD" : {"15m" : 436.89, "last" : 436.89, "buy" : 437.37, "sell" : 437.42,  "symbol" : "$"},
     "BRL" : {"15m" : 944.91, "last" : 944.91, "buy" : 945.95, "sell" : 946.05,  "symbol" : "R$"},
     "RUB" : {"15m" : 16695.05, "last" : 16695.05, "buy" : 16713.58, "sell" : 16715.32,  "symbol" : "RUB"}
     }*/
    /*{
     "24h_avg": 281.22,
     "ask": 280.12,
     "bid": 279.33,
     "last": 279.58,
     "timestamp": "Sun, 02 Aug 2015 09:36:34 -0000",
     "total_vol": 39625.8
     }*/
    
    if ( bitcoinave != 0 )
    {
        if ( (price= jdouble(bitcoinave,"24h_avg")) > SMALLVAL )
        {
            //printf("bitcoinave %f %f\n",btcusd,price);
            dxblend(&btcusd,price,0.5);
        }
        free_json(bitcoinave);
    }
    if ( quandl != 0 )
        free_json(quandl);
    if ( coindesk != 0 )
        free_json(coindesk);
    if ( blockchaininfo != 0 )
    {
        if ( (item= jobj(blockchaininfo,"USD")) != 0 && item != 0 && (price= jdouble(item,"15m")) > SMALLVAL )
        {
            //printf("blockchaininfo %f %f\n",btcusd,price);
            dxblend(&btcusd,price,0.5);
        }
        free_json(blockchaininfo);
    }
    if ( btcusd != 0 )
        BUNDLE.btcusd = *btcusdp = btcusd;
    
    
    // https://poloniex.com/public?command=returnChartData&currencyPair=BTC_BTCD&start=1405699200&end=9999999999&period=86400
    
    // https://poloniex.com/public?command=returnTradeHistory&currencyPair=BTC_BTCD
    //https://bittrex.com/api/v1.1/public/getmarkethistory?market=BTC-BTCD&count=50
    /*{"success":true,"message":"","result":[{"Id":8551089,"TimeStamp":"2015-07-25T16:00:41.597","Quantity":59.60917089,"Price":0.00642371,"Total":0.38291202,"FillType":"FILL","OrderType":"BUY"},{"Id":8551088,"TimeStamp":"2015-07-25T16:00:41.597","Quantity":7.00000000,"Price":0.00639680,"Total":0.04477760,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8551087,"TimeStamp":"2015-07-25T16:00:41.597","Quantity":6.51000000,"Price":0.00639679,"Total":0.04164310,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8551086,"TimeStamp":"2015-07-25T16:00:41.597","Quantity":6.00000000,"Price":0.00633300,"Total":0.03799800,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8551085,"TimeStamp":"2015-07-25T16:00:41.593","Quantity":4.76833955,"Price":0.00623300,"Total":0.02972106,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8551084,"TimeStamp":"2015-07-25T16:00:41.593","Quantity":5.00000000,"Price":0.00620860,"Total":0.03104300,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8551083,"TimeStamp":"2015-07-25T16:00:41.593","Quantity":4.91803279,"Price":0.00620134,"Total":0.03049839,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8551082,"TimeStamp":"2015-07-25T16:00:41.593","Quantity":4.45166432,"Price":0.00619316,"Total":0.02756986,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8551081,"TimeStamp":"2015-07-25T16:00:41.59","Quantity":2.00000000,"Price":0.00619315,"Total":0.01238630,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547525,"TimeStamp":"2015-07-25T06:20:43.69","Quantity":1.23166045,"Price":0.00623300,"Total":0.00767693,"FillType":"FILL","OrderType":"BUY"},{"Id":8547524,"TimeStamp":"2015-07-25T06:20:43.69","Quantity":5.00000000,"Price":0.00613300,"Total":0.03066500,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547523,"TimeStamp":"2015-07-25T06:20:43.687","Quantity":10.00000000,"Price":0.00609990,"Total":0.06099900,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547522,"TimeStamp":"2015-07-25T06:20:43.687","Quantity":0.12326502,"Price":0.00609989,"Total":0.00075190,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547521,"TimeStamp":"2015-07-25T06:20:43.687","Quantity":3.29000000,"Price":0.00609989,"Total":0.02006863,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547520,"TimeStamp":"2015-07-25T06:20:43.687","Quantity":5.00000000,"Price":0.00604400,"Total":0.03022000,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547519,"TimeStamp":"2015-07-25T06:20:43.683","Quantity":12.80164947,"Price":0.00603915,"Total":0.07731108,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547518,"TimeStamp":"2015-07-25T06:20:43.683","Quantity":10.00000000,"Price":0.00602715,"Total":0.06027150,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547517,"TimeStamp":"2015-07-25T06:20:43.683","Quantity":4.29037397,"Price":0.00600000,"Total":0.02574224,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547516,"TimeStamp":"2015-07-25T06:20:43.683","Quantity":77.55994092,"Price":0.00598921,"Total":0.46452277,"FillType":"PARTIAL_FILL","OrderType":"BUY"},{"Id":8547515,"TimeStamp":"2015-07-25T06:20:43.68","Quantity":0.08645064,"Price":0.00598492,"Total":0.00051740,"FillType":"PARTIAL_FILL","OrderType":"BUY"}]}
     */
    
    // https://api.bitcoinaverage.com/ticker/global/all
    /* {
     "AED": {
     "ask": 1063.28,
     "bid": 1062.1,
     "last": 1062.29,
     "timestamp": "Sat, 25 Jul 2015 17:13:14 -0000",
     "volume_btc": 0.0,
     "volume_percent": 0.0
     },*/
    
    // http://api.bitcoincharts.com/v1/weighted_prices.json
    // {"USD": {"7d": "279.79", "30d": "276.05", "24h": "288.55"}, "IDR": {"7d": "3750799.88", "30d": "3636926.02", "24h": "3860769.92"}, "ILS": {"7d": "1033.34", "30d": "1031.58", "24h": "1092.36"}, "GBP": {"7d": "179.51", "30d": "175.30", "24h": "185.74"}, "DKK": {"30d": "1758.61"}, "CAD": {"7d": "364.04", "30d": "351.27", "24h": "376.12"}, "MXN": {"30d": "4369.33"}, "XRP": {"7d": "35491.70", "30d": "29257.39", "24h": "36979.02"}, "SEK": {"7d": "2484.50", "30d": "2270.94"}, "SGD": {"7d": "381.93", "30d": "373.69", "24h": "393.94"}, "HKD": {"7d": "2167.99", "30d": "2115.77", "24h": "2232.12"}, "AUD": {"7d": "379.42", "30d": "365.85", "24h": "394.93"}, "CHF": {"30d": "250.61"}, "timestamp": 1437844509, "CNY": {"7d": "1724.99", "30d": "1702.32", "24h": "1779.48"}, "LTC": {"7d": "67.46", "30d": "51.97", "24h": "61.61"}, "NZD": {"7d": "425.01", "30d": "409.33", "24h": "437.86"}, "THB": {"30d": "8632.82"}, "EUR": {"7d": "257.32", "30d": "249.88", "24h": "263.42"}, "ARS": {"30d": "3271.98"}, "NOK": {"30d": "2227.54"}, "RUB": {"7d": "16032.32", "30d": "15600.38", "24h": "16443.39"}, "INR": {"30d": "16601.17"}, "JPY": {"7d": "34685.73", "30d": "33617.77", "24h": "35652.79"}, "CZK": {"30d": "6442.13"}, "BRL": {"7d": "946.76", "30d": "900.77", "24h": "964.09"}, "NMC": {"7d": "454.06", "30d": "370.39", "24h": "436.71"}, "PLN": {"7d": "1041.81", "30d": "1024.96", "24h": "1072.49"}, "ZAR": {"30d": "3805.55"}}
}

double blend_price(double *volp,double wtA,cJSON *jsonA,double wtB,cJSON *jsonB)
{
    //A.{"ticker":{"base":"BTS","target":"CNY","price":"0.02958291","volume":"3128008.39295500","change":"0.00019513","markets":[{"market":"BTC38","price":"0.02960000","volume":3051650.682955},{"market":"Bter","price":"0.02890000","volume":76357.71}]},"timestamp":1438490881,"success":true,"error":""}
    // B.{"id":"bts\/cny","price":"0.02940000","price_before_24h":"0.02990000","volume_first":"3048457.6857147217","volume_second":"90629.45859575272","volume_btc":"52.74","best_market":"btc38","latest_trade":"2015-08-02 03:57:38","coin1":"BitShares","coin2":"CNY","markets":[{"market":"btc38","price":"0.02940000","volume":"3048457.6857147217","volume_btc":"52.738317962865"},{"market":"bter","price":"0.04350000","volume":"0","volume_btc":"0"}]}
    double priceA,priceB,priceB24,price,volA,volB; cJSON *obj;
    priceA = priceB = priceB24= price = volA = volB = 0.;
    if ( jsonA != 0 && (obj= jobj(jsonA,"ticker")) != 0 )
    {
        priceA = jdouble(obj,"price");
        volA = jdouble(obj,"volume");
    }
    if ( jsonB != 0 )
    {
        priceB = jdouble(jsonB,"price");
        priceB24 = jdouble(jsonB,"price_before_24h");
        volB = jdouble(jsonB,"volume_first");
    }
    //printf("priceA %f volA %f, priceB %f %f volB %f\n",priceA,volA,priceB,priceB24,volB);
    if ( priceB > SMALLVAL && priceB24 > SMALLVAL )
        priceB = (priceB * .1) + (priceB24 * .9);
    else if ( priceB < SMALLVAL )
        priceB = priceB24;
    if ( priceA*volA < SMALLVAL )
        price = priceB;
    else if ( priceB*volB < SMALLVAL )
        price = priceA;
    else price = (wtA * priceA) + (wtB * priceB);
    *volp = (volA + volB);
    return(price);
}

void _crypto_update(double cryptovols[2][8][2],struct prices777_data *dp,int32_t selector,int32_t peggyflag)
{
    char *cryptonatorA = "https://www.cryptonator.com/api/full/%s-%s"; //unity-btc
    char *cryptocoinchartsB = "http://api.cryptocoincharts.info/tradingPair/%s_%s"; //bts_btc
    char *cryptostrs[9] = { "btc", "nxt", "unity", "eth", "ltc", "xmr", "bts", "xcp", "etc" };
    int32_t iter,i,j; double btcusd,btcdbtc,cnyusd,prices[8][2],volumes[8][2];
    char base[16],rel[16],url[512],*str; cJSON *jsonA,*jsonB;
    if ( peggyflag != 0 )
    {
        cnyusd = BUNDLE.cnyusd;
        btcusd = BUNDLE.btcusd;
        btcdbtc = BUNDLE.btcdbtc;
        //printf("update with btcusd %f btcd %f cnyusd %f cnybtc %f\n",btcusd,btcdbtc,cnyusd,cnyusd/btcusd);
        if ( btcusd < SMALLVAL || btcdbtc < SMALLVAL )
        {
            price777_update(&btcusd,&btcdbtc);
            printf("price777_update with btcusd %f btcd %f\n",btcusd,btcdbtc);
        }
        memset(prices,0,sizeof(prices));
        memset(volumes,0,sizeof(volumes));
        for (j=0; j<sizeof(cryptostrs)/sizeof(*cryptostrs); j++)
        {
            str = cryptostrs[j];
            if ( strcmp(str,"etc") == 0 )
            {
                if ( prices[3][0] > SMALLVAL )
                    break;
                i = 3;
            } else i = j;
            for (iter=0; iter<1; iter++)
            {
                if ( i == 0 && iter == 0 )
                    strcpy(base,"btcd"), strcpy(rel,"btc");
                else strcpy(base,str), strcpy(rel,iter==0?"btc":"cny");
                //if ( selector == 0 )
                {
                    sprintf(url,cryptonatorA,base,rel);
                    jsonA = url_json(url);
                }
                //else
                {
                    sprintf(url,cryptocoinchartsB,base,rel);
                    jsonB = url_json(url);
                }
                prices[i][iter] = blend_price(&volumes[i][iter],0.4,jsonA,0.6,jsonB);
                if ( iter == 1 )
                {
                    if ( btcusd > SMALLVAL )
                    {
                        prices[i][iter] *= cnyusd / btcusd;
                        volumes[i][iter] *= cnyusd / btcusd;
                    } else prices[i][iter] = volumes[i][iter] = 0.;
                }
                cryptovols[0][i][iter] = _pairaved(cryptovols[0][i][iter],prices[i][iter]);
                cryptovols[1][i][iter] = _pairaved(cryptovols[1][i][iter],volumes[i][iter]);
                if ( Debuglevel > 2 )
                    printf("(%f %f).%d:%d ",cryptovols[0][i][iter],cryptovols[1][i][iter],i,iter);
                //if ( cnyusd < SMALLVAL || btcusd < SMALLVAL )
                //    break;
            }
        }
    }
}

void crypto_update(int32_t peggyflag)
{
    _crypto_update(BUNDLE.cryptovols,&BUNDLE.data,1,peggyflag);
    while ( 1 )
    {
        _crypto_update(BUNDLE.cryptovols,&BUNDLE.data,1,peggyflag);
        sleep(100);
    }
}

void prices777_RTupdate(double cryptovols[2][8][2],double RTmetals[4],double *RTprices,struct prices777_data *dp)
{
    char *cryptostrs[8] = { "btc", "nxt", "unity", "eth", "ltc", "xmr", "bts", "xcp" };
    int32_t iter,i,c,baserel,basenum,relnum; double cnyusd,btcusd,btcdbtc,bid,ask,price,vol,prices[8][2],volumes[8][2];
    char base[16],rel[16];
    price777_update(&btcusd,&btcdbtc);
    memset(prices,0,sizeof(prices));
    memset(volumes,0,sizeof(volumes));
    for (i=0; i<sizeof(cryptostrs)/sizeof(*cryptostrs); i++)
        for (iter=0; iter<2; iter++)
            prices[i][iter] = cryptovols[0][i][iter], volumes[i][iter] = cryptovols[1][i][iter];
    if ( prices[0][0] > SMALLVAL )
        dxblend(&btcdbtc,prices[0][0],.9);
    dxblend(&dp->btcdbtc,btcdbtc,.995);
    if ( BUNDLE.btcdbtc < SMALLVAL )
        BUNDLE.btcdbtc = dp->btcdbtc;
    if ( (cnyusd= BUNDLE.cnyusd) > SMALLVAL )
    {
        if ( prices[0][1] > SMALLVAL )
        {
            //printf("cnyusd %f, btccny %f -> btcusd %f %f\n",cnyusd,prices[0][1],prices[0][1]*cnyusd,btcusd);
            btcusd = prices[0][1] * cnyusd;
            if ( dp->btcusd < SMALLVAL )
                dp->btcusd = btcusd;
            else dxblend(&dp->btcusd,btcusd,.995);
            if ( BUNDLE.btcusd < SMALLVAL )
                BUNDLE.btcusd = dp->btcusd;
            if ( BUNDLE.data.btcusd < SMALLVAL )
                BUNDLE.data.btcusd = dp->btcusd;
            printf("cnyusd %f, btccny %f -> btcusd %f %f -> %f %f %f\n",cnyusd,prices[0][1],prices[0][1]*cnyusd,btcusd,dp->btcusd,BUNDLE.btcusd,BUNDLE.data.btcusd);
        }
    }
    for (i=1; i<sizeof(cryptostrs)/sizeof(*cryptostrs); i++)
    {
        if ( (vol= volumes[i][0]+volumes[i][1]) > SMALLVAL )
        {
            price = ((prices[i][0] * volumes[i][0]) + (prices[i][1] * volumes[i][1])) / vol;
            if ( Debuglevel > 2 )
                printf("%s %f v%f + %f v%f -> %f %f\n",cryptostrs[i],prices[i][0],volumes[i][0],prices[i][1],volumes[i][1],price,dp->cryptos[i]);
            dxblend(&dp->cryptos[i],price,.995);
        }
    }
    btcusd = BUNDLE.btcusd;
    btcdbtc = BUNDLE.btcdbtc;
    if ( Debuglevel > 2 )
        printf("    update with btcusd %f btcd %f\n",btcusd,btcdbtc);
    if ( btcusd < SMALLVAL || btcdbtc < SMALLVAL )
    {
        price777_update(&btcusd,&btcdbtc);
        if ( Debuglevel > 2 )
            printf("     price777_update with btcusd %f btcd %f\n",btcusd,btcdbtc);
    } else BUNDLE.btcusd = btcusd, BUNDLE.btcdbtc = btcdbtc;
    for (c=0; c<sizeof(CONTRACTS)/sizeof(*CONTRACTS); c++)
    {
        for (iter=0; iter<3; iter++)
        {
            switch ( iter )
            {
                case 0: bid = dp->tbids[c], ask = dp->tasks[c]; break;
                case 1: bid = dp->fbids[c], ask = dp->fasks[c]; break;
                case 2: bid = dp->ibids[c], ask = dp->iasks[c]; break;
            }
            if ( (price= _pairaved(bid,ask)) > SMALLVAL )
            {
                if ( Debuglevel > 2 )
                    printf("%.6f ",price);
                dxblend(&RTprices[c],price,.995);
                if ( 0 && (baserel= prices777_ispair(base,rel,CONTRACTS[c])) >= 0 )
                {
                    basenum = (baserel >> 8) & 0xff, relnum = baserel & 0xff;
                    if ( basenum < 32 && relnum < 32 )
                    {
                        //printf("%s.%d %f <- %f\n",CONTRACTS[c],c,RTmatrix[basenum][relnum],RTprices[c]);
                        //dxblend(&RTmatrix[basenum][relnum],RTprices[c],.999);
                    }
                }
                if ( strcmp(CONTRACTS[c],"XAUUSD") == 0 )
                    dxblend(&RTmetals[0],price,.995);
            }
        }
    }
    for (i=0; i<sizeof(Yahoo_metals)/sizeof(*Yahoo_metals); i++)
        if ( BUNDLE.data.metals[i] != 0 )
            dxblend(&RTmetals[i],BUNDLE.data.metals[i],.995);
}

int32_t prices777_getmatrix(double *basevals,double *btcusdp,double *btcdbtcp,double Hmatrix[32][32],double *RTprices,char *contracts[],int32_t num,uint32_t timestamp)
{
    int32_t i,j,c; char name[65]; double btcusd,btcdbtc;
    memcpy(Hmatrix,BUNDLE.data.ecbmatrix,sizeof(BUNDLE.data.ecbmatrix));
    prices777_calcmatrix(Hmatrix);
    /*for (i=0; i<32; i++)
     {
     for (j=0; j<32; j++)
     printf("%.6f ",Hmatrix[i][j]);
     printf("%s\n",CURRENCIES[i]);
     }*/
    btcusd = BUNDLE.btcusd;
    btcdbtc = BUNDLE.btcdbtc;
    if ( btcusd > SMALLVAL )
        dxblend(btcusdp,btcusd,.9);
    if ( btcdbtc > SMALLVAL )
        dxblend(btcdbtcp,btcdbtc,.9);
    // char *cryptostrs[8] = { "btc", "nxt", "unity", "eth", "ltc", "xmr", "bts", "xcp" };
    // "BTCUSD", "NXTBTC", "SuperNET", "ETHBTC", "LTCBTC", "XMRBTC", "BTSBTC", "XCPBTC",  // BTC priced
    for (i=0; i<num; i++)
    {
        if ( contracts[i] == 0 )
            continue;
        if ( i == num-1 && strcmp(contracts[i],"BTCUSD") == 0 )
        {
            RTprices[i] = *btcusdp;
            continue;
        }
        else if ( i == num-2 && strcmp(contracts[i],"BTCCNY") == 0 )
        {
            continue;
        }
        else if ( i == num-3 && strcmp(contracts[i],"BTCRUB") == 0 )
        {
            continue;
        }
        else if ( i == num-4 && strcmp(contracts[i],"XAUUSD") == 0 )
        {
            continue;
        }
        if ( strcmp(contracts[i],"NXTBTC") == 0 )
            RTprices[i] = BUNDLE.data.cryptos[1];
        else if ( strcmp(contracts[i],"SuperNET") == 0 )
            RTprices[i] = BUNDLE.data.cryptos[2];
        else if ( strcmp(contracts[i],"ETHBTC") == 0 )
            RTprices[i] = BUNDLE.data.cryptos[3];
        else if ( strcmp(contracts[i],"LTCBTC") == 0 )
            RTprices[i] = BUNDLE.data.cryptos[4];
        else if ( strcmp(contracts[i],"XMRBTC") == 0 )
            RTprices[i] = BUNDLE.data.cryptos[5];
        else if ( strcmp(contracts[i],"BTSBTC") == 0 )
            RTprices[i] = BUNDLE.data.cryptos[6];
        else if ( strcmp(contracts[i],"XCPBTC") == 0 )
            RTprices[i] = BUNDLE.data.cryptos[7];
        else if ( i < 32 )
        {
            basevals[i] = Hmatrix[i][i];
            if ( Debuglevel > 2 )
                printf("(%s %f).%d ",CURRENCIES[i],basevals[i],i);
        }
        else if ( (c= prices777_contractnum(contracts[i],0)) >= 0 )
        {
            RTprices[i] = BUNDLE.data.RTprices[c];
            //if ( is_decimalstr(contracts[i]+strlen(contracts[i])-2) != 0 )
            //    cprices[i] *= .0001;
        }
        else
        {
            for (j=0; j<sizeof(Yahoo_metals)/sizeof(*Yahoo_metals); j++)
            {
                sprintf(name,"%sUSD",Yahoo_metals[j]);
                if ( contracts[i] != 0 && strcmp(name,contracts[i]) == 0 )
                {
                    RTprices[i] = BUNDLE.data.RTmetals[j];
                    break;
                }
            }
        }
        if ( Debuglevel > 2 )
            printf("(%f %f) i.%d num.%d %s %f\n",*btcusdp,*btcdbtcp,i,num,contracts[i],RTprices[i]);
        //printf("RT.(%s %f) ",contracts[i],RTprices[i]);
    }
    return(BUNDLE.data.ecbdatenum);
}

int32_t prices_idle(int32_t peggyflag,int32_t idlegap)
{
    static double lastupdate,lastdayupdate; static int32_t didinit; static portable_mutex_t mutex;
    int32_t i,datenum; struct prices777_data *dp = &BUNDLE.tmp;
    *dp = BUNDLE.data;
    if ( didinit == 0 )
    {
        portable_mutex_init(&mutex);
        prices777_init(BUNDLE.jsonstr,peggyflag);
        didinit = 1;
        if ( peggyflag != 0 )
        {
            int32_t opreturns_init(uint32_t blocknum,uint32_t blocktimestamp,char *path);
            opreturns_init(0,(uint32_t)time(NULL),"peggy");
        }
    }
    if ( peggyflag != 0 && milliseconds() > lastupdate + (1000*idlegap) )
    {
        lastupdate = milliseconds();
        if ( milliseconds() > lastdayupdate + 60000*60 )
        {
            lastdayupdate = milliseconds();
            printf("call ecb_matrix.(%s)\n",dp->edate);
            if ( (datenum= ecb_matrix(dp->ecbmatrix,dp->edate)) > 0 )
            {
                dp->ecbdatenum = datenum;
                dp->ecbyear = dp->ecbdatenum / 10000,  dp->ecbmonth = (dp->ecbdatenum / 100) % 100,  dp->ecbday = (dp->ecbdatenum % 100);
                expand_datenum(dp->edate,datenum);
                memcpy(dp->RTmatrix,dp->ecbmatrix,sizeof(dp->RTmatrix));
            }
        }
        for (i=0; i<sizeof(Yahoo_metals)/sizeof(*Yahoo_metals); i++)
            BUNDLE.data.metals[i] = prices777_yahoo(Yahoo_metals[i]);
        BUNDLE.truefxidnum = prices777_truefx(dp->tmillistamps,dp->tbids,dp->tasks,dp->topens,dp->thighs,dp->tlows,BUNDLE.truefxuser,BUNDLE.truefxpass,(uint32_t)BUNDLE.truefxidnum);
        prices777_fxcm(dp->flhlogmatrix,dp->flogmatrix,dp->fbids,dp->fasks,dp->fhighs,dp->flows);
        prices777_instaforex(dp->ilogmatrix,dp->itimestamps,dp->ibids,dp->iasks);
        double btcdbtc,btcusd;
        price777_update(&btcusd,&btcdbtc);
        if ( btcusd > SMALLVAL )
            dxblend(&dp->btcusd,btcusd,0.99);
        if ( btcdbtc > SMALLVAL )
            dxblend(&dp->btcdbtc,btcdbtc,0.99);
        if ( BUNDLE.data.btcusd == 0 )
            BUNDLE.data.btcusd = dp->btcusd;
        if ( BUNDLE.data.btcdbtc == 0 )
            BUNDLE.data.btcdbtc = dp->btcdbtc;
        if ( dp->ecbmatrix[USD][USD] > SMALLVAL && dp->ecbmatrix[CNY][CNY] > SMALLVAL )
            BUNDLE.cnyusd = (dp->ecbmatrix[CNY][CNY] / dp->ecbmatrix[USD][USD]);
        portable_mutex_lock(&mutex);
        BUNDLE.data = *dp;
        portable_mutex_unlock(&mutex);
        //kv777_write(BUNDLE.kv,"data",5,&BUNDLE.data,sizeof(BUNDLE.data));
        prices777_RTupdate(BUNDLE.cryptovols,BUNDLE.data.RTmetals,BUNDLE.data.RTprices,&BUNDLE.data);
        //printf("update finished\n");
        void peggy();
        peggy();
        didinit = 1;
    }
    return(0);
}

void prices777_sim(uint32_t now,int32_t numiters)
{
    double btca,btcb,btcd,btc,btcdusd,basevals[MAX_CURRENCIES],btcdprices[MAX_CURRENCIES+1];
    int32_t i,j,datenum,seconds; uint32_t timestamp,starttime = (uint32_t)time(NULL);
    for (i=0; i<numiters; i++)
    {
        timestamp = now - (rand() % (3600*24*64));
        btca = 1000. * prices777_splineval(&BUNDLE.splines[MAX_CURRENCIES+0],timestamp,0);
        btcb = 1000. * prices777_splineval(&BUNDLE.splines[MAX_CURRENCIES+1],timestamp,0);
        btc = _pairaved(btca,btcb);
        btcd = .01 * prices777_splineval(&BUNDLE.splines[MAX_CURRENCIES+2],timestamp,0);
        btcdusd = (btc * btcd);
        datenum = OS_conv_unixtime(&seconds,timestamp);
        for (j=0; j<MAX_CURRENCIES; j++)
        {
            basevals[j] = prices777_splineval(&BUNDLE.splines[j],timestamp,0);
            btcdprices[j] = basevals[j] / (btcdusd * basevals[USD]);
        }
        if ( (i % 100000) == 0 )
        {
            printf("%d:%02d:%02d %.8f %.8f -> USD %.8f (EURUSD %.8f %.8f) ",datenum,seconds/3600,(seconds%3600)/60,btc,btcd,btcdusd,btcdprices[EUR]/btcdprices[USD],basevals[EUR]/basevals[USD]);
            for (j=0; j<MAX_CURRENCIES; j++)
                printf("%.8f ",btcdprices[j]);
            printf("\n");
        }
    }
    printf("sim took %ld seconds\n",(long)(time(NULL) - starttime));
}

void prices777_getlist(char *retbuf)
{
    int32_t i,j; struct prices777 *prices; char pair[130],*jsonstr; cJSON *json,*array,*item;
    json = cJSON_CreateObject();
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(CURRENCIES)/sizeof(*CURRENCIES); i++)
        cJSON_AddItemToArray(array,cJSON_CreateString(CURRENCIES[i]));
    cJSON_AddItemToObject(json,"currency",array);
    array = cJSON_CreateArray();
    for (i=0; i<32; i++)
        for (j=0; j<32; j++)
        {
            if ( i != j )
            {
                sprintf(pair,"%s%s",CURRENCIES[i],CURRENCIES[j]);
                cJSON_AddItemToArray(array,cJSON_CreateString(pair));
            }
        }
    cJSON_AddItemToObject(json,"pairs",array);
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(CONTRACTS)/sizeof(*CONTRACTS); i++)
        cJSON_AddItemToArray(array,cJSON_CreateString(CONTRACTS[i]));
    cJSON_AddItemToObject(json,"contract",array);
    array = cJSON_CreateArray();
    for (i=0; i<BUNDLE.num; i++)
    {
        if ( (prices= BUNDLE.ptrs[i]) != 0 )
        {
            item = cJSON_CreateObject();
            cJSON_AddItemToObject(item,prices->exchange,cJSON_CreateString(prices->contract));
            cJSON_AddItemToObject(item,"base",cJSON_CreateString(prices->base));
            if ( prices->rel[0] != 0 )
                cJSON_AddItemToObject(item,"rel",cJSON_CreateString(prices->rel));
            //printf("(%s) (%s) (%s)\n",prices->contract,prices->base,prices->rel);
            cJSON_AddItemToArray(array,item);
        }
    }
    cJSON_AddItemToObject(json,"result",cJSON_CreateString("success"));
    cJSON_AddItemToObject(json,"list",array);
    jsonstr = cJSON_Print(json), _stripwhite(jsonstr,' '), free_json(json);
    strcpy(retbuf,jsonstr), free(jsonstr);
    printf("list -> (%s)\n",retbuf);
}


#endif
