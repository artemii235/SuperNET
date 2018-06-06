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

#include "exchanges777.h"
//#include "peggy.h"

#define EXCHANGE777_DONE 1
#define EXCHANGE777_ISPENDING 2
#define EXCHANGE777_REQUEUE 3

//char *Exchange_names[] = { "poloniex", "bittrex", "btc38",  "huobi", "bitstamp", "bitfinex", "btce", "coinbase", "okcoin", "lakebtc", "quadriga", "truefx", "ecb", "instaforex", "fxcm", "yahoo" };

int32_t instantdex_updatesources(struct exchange_info *exchange,struct exchange_quote *sortbuf,int32_t n,int32_t max,int32_t ind,int32_t dir,struct exchange_quote *quotes,int32_t numquotes,double offset,double factor)
{
    int32_t i; struct exchange_quote *quote;
    //printf("instantdex_updatesources.%s update dir.%d numquotes.%d offset %.6f\n",exchange->name,dir,numquotes,offset);
    for (i=0; i<numquotes; i++)
    {
        quote = &quotes[i << 1];
        if ( quote->price > SMALLVAL )
        {
            //printf("%s n.%d ind.%d i.%d dir.%d price %.8f vol %.8f offset %.6f\n",exchange->name,n,ind,i,dir,quote->price+offset,quote->volume,offset);
            quote->price += offset;
            quote->price /= factor;
            quote->volume *= factor;
            quote->satoshis = quote->price * SATOSHIDEN;
            sortbuf[n] = *quote;
            sortbuf[n].val = ind;
            sortbuf[n].exchangebits = exchange->exchangebits;
            //printf("sortbuf[%d] <-\n",n*2);
            if ( ++n >= max )
                break;
        }
    }
    return(n);
}

double instantdex_aveprice(struct supernet_info *myinfo,struct exchange_quote *sortbuf,int32_t max,double *totalvolp,char *base,char *rel,double basevolume,cJSON *argjson)
{
    char *str; double totalvol,pricesum,hblas[64][2],refbid,refask,factor = 1.; uint32_t timestamp;
    struct exchange_quote quote; int32_t i,n,dir,num,depth = 100;
    struct exchange_info *exchange; struct exchange_request *req,*active[64];
    if ( myinfo == 0 )
        myinfo = SuperNET_MYINFO(0);
    timestamp = (uint32_t)time(NULL);
    if ( basevolume < 0. )
        basevolume = -basevolume, dir = -1;
    else dir = 1;
#ifdef INCLUDE_PAX
    if ( rel == 0 || rel[0] == 0 )
    {
        *totalvolp = 1.;
        return(PAX_aveprice(myinfo,base));
    }
#endif
    memset(sortbuf,0,sizeof(*sortbuf) * max);
    if ( base != 0 && rel != 0 && basevolume > SMALLVAL )
    {
        if ( strcmp(base,"KMD") == 0 )
            base = "BTCD", factor = 50;
        else if ( strcmp(rel,"KMD") == 0 )
            rel = "BTCD", factor = 0.02;
        for (i=num=0; i<myinfo->numexchanges && num < sizeof(active)/sizeof(*active); i++)
        {
            if ( (exchange= myinfo->tradingexchanges[i]) != 0 )
            {
                if ( (req= exchanges777_baserelfind(exchange,base,rel,'M')) == 0 )
                {
                    if ( (str= exchanges777_Qprices(exchange,base,rel,30,1,depth,argjson,1,exchange->commission)) != 0 )
                        free(str);
                    req = exchanges777_baserelfind(exchange,base,rel,'M');
                }
                if ( req == 0 )
                {
                    if ( (*exchange->issue.supports)(exchange,base,rel,argjson) != 0 )
                        printf("unexpected null req.(%s %s) %s\n",base,rel,exchange->name);
                }
                else
                {
                    //printf("active.%s\n",exchange->name);
                    active[num++] = req;
                }
            }
        }
        memset(hblas,0,sizeof(hblas));
        refbid = refask = 0.;
        if ( strcmp(rel,"USD") == 0 )
        {
            for (i=0; i<num; i++)
            {
                if ( active[i]->numbids > 0 && active[i]->numasks > 0 )
                {
                    hblas[i][0] = active[i]->bidasks[0].price;
                    hblas[i][1] = active[i]->bidasks[1].price;
                    if ( active[i]->exchange != 0 && strcmp("poloniex",active[i]->exchange->name) == 0 )
                        refbid = active[i]->bidasks[0].price, refask = active[i]->bidasks[1].price;
                    //printf("(%6f %.6f) ",hblas[i][0],hblas[i][1]);
                }
            }
            //printf(" refbid %.6f refask %.7f\n",refbid,refask);
            if ( refbid != 0. && refask != 0. )
            {
                for (i=0; i<num; i++)
                {
                    if ( hblas[i][0] != 0. && hblas[i][1] != 0. )
                        hblas[i][0] = (refbid - hblas[i][0]), hblas[i][1] = (refask - hblas[i][1]);
                    else memset(hblas[i],0,sizeof(hblas[i]));
                }
            } else memset(hblas,0,sizeof(hblas));
        }
        for (i=n=0; i<num; i++)
        {
            if ( dir < 0 && active[i]->numbids > 0 )
                n = instantdex_updatesources(active[i]->exchange,sortbuf,n,max,i,1,active[i]->bidasks,active[i]->numbids,hblas[i][0],factor);
            else if ( dir > 0 && active[i]->numasks > 0 )
                n = instantdex_updatesources(active[i]->exchange,sortbuf,n,max,i,-1,&active[i]->bidasks[1],active[i]->numasks,hblas[i][1],factor);
        }
        //printf("numexchanges.%d dir.%d %s/%s numX.%d n.%d\n",myinfo->numexchanges,dir,base,rel,num,n);
        if ( dir < 0 )
            revsort64s(&sortbuf[0].satoshis,n,sizeof(*sortbuf));
        else sort64s(&sortbuf[0].satoshis,n,sizeof(*sortbuf));
        //for (i=0; i<n; i++)
        //    printf("%.6f ",sortbuf[i].price);
        //printf("%d prices\n",n);
        for (totalvol=pricesum=i=0; i<n && totalvol < basevolume; i++)
        {
            quote = sortbuf[i];
            //printf("dir.%d n.%d i.%d price %.8f %.8f %.8f\n",dir,n,i,dstr(sortbuf[i].satoshis),sortbuf[i].price,quote.volume);
            if ( quote.satoshis != 0 )
            {
                pricesum += (quote.price * quote.volume);
                totalvol += quote.volume;
                //printf("dir.%d i.%d of %d %12.8f vol %.8f %s | aveprice %.8f total vol %.8f\n",dir,i,n,sortbuf[i].price,quote.volume,active[quote.val]->exchange->name,pricesum/totalvol,totalvol);
            }
        }
        if ( totalvol > 0. )
        {
            *totalvolp = totalvol;
            return(pricesum / totalvol);
        }
    }
    *totalvolp = 0;
    return(0);
}

double instantdex_avehbla(struct supernet_info *myinfo,double retvals[4],char *_base,char *_rel,double basevolume)
{
    double avebid,aveask,bidvol,askvol; struct exchange_quote sortbuf[2560]; cJSON *argjson; char base[64],rel[64];
    if ( retvals == 0 )
        return(0);
    strcpy(base,_base);
    if ( _rel == 0 )
        strcpy(rel,"");
    else strcpy(rel,_rel);
    if ( myinfo == 0 )
        myinfo = SuperNET_MYINFO(0);
    argjson = cJSON_CreateObject();
    aveask = instantdex_aveprice(myinfo,sortbuf,sizeof(sortbuf)/(4*sizeof(*sortbuf)),&askvol,base,rel,basevolume,argjson);
    avebid = instantdex_aveprice(myinfo,sortbuf,sizeof(sortbuf)/(4*sizeof(*sortbuf)),&bidvol,base,rel,-basevolume,argjson);
    free_json(argjson);
    retvals[0] = avebid, retvals[1] = bidvol, retvals[2] = aveask, retvals[3] = askvol;
#ifdef INCLUDE_PAX
    int32_t basenum,relnum; double baseval,relval;
    if ( (basenum= PAX_basenum(base)) >= 0 && (relnum= PAX_basenum(rel)) >= 0 )
    {
        if ( myinfo->PEGS != 0 && (baseval= myinfo->PEGS->data.RTmatrix[basenum][basenum]) != 0. && (relval= myinfo->PEGS->data.RTmatrix[relnum][relnum]) != 0. )
            return(baseval / relval);
    }
#endif
    if ( avebid > SMALLVAL && aveask > SMALLVAL )
        return((avebid + aveask) * .5);
    else return(0);
}

cJSON *exchanges777_allpairs(char *baserels[][2],int32_t num)
{
    int32_t i; char str[32]; cJSON *json,*item,*array = cJSON_CreateArray();
    for (i=0; i<num; i++)
    {
        item = cJSON_CreateArray();
        jaddistr(item,uppercase_str(str,baserels[i][0]));
        jaddistr(item,uppercase_str(str,baserels[i][1]));
        jaddi(array,item);
    }
    json = cJSON_CreateObject();
    jadd(json,"result",array);
    return(json);
}

cJSON *exchanges777_quotejson(struct exchange_quote *quote,int32_t allflag,double pricesum,double totalvol)
{
    cJSON *json; char str[65];
    if ( allflag != 0 )
    {
        json = cJSON_CreateObject();
        if ( totalvol > SMALLVAL )
            pricesum /= totalvol;
        jaddnum(json,"price",quote->price);
        jaddnum(json,"volume",quote->volume);
        jaddnum(json,"aveprice",pricesum);
        jaddnum(json,"cumulative",totalvol);
        if ( quote->timestamp != 0 )
            jaddstr(json,"time",utc_str(str,quote->timestamp));
        if ( quote->orderid != 0 )
            jadd64bits(json,"orderid",quote->orderid);
        //if ( quote->offerNXT != 0 )
        jadd64bits(json,"account",quote->offerNXT);
        return(json);
    } else return(cJSON_CreateNumber(quote->price));
}

char *exchanges777_orderbook_jsonstr(struct exchange_info *exchange,char *_base,char *_rel,struct exchange_quote *bidasks,int32_t maxdepth,int32_t invert,int32_t allflag)
{
    struct exchange_quote *bid,*ask,A,B; cJSON *json,*bids,*asks;
    double highbid,lowask,price,volume,bidsum,asksum,bidvol,askvol;
    uint32_t timestamp;
    int32_t slot,numbids,numasks,enda,endb; char baserel[64],base[64],rel[64],str[65];
    if ( invert == 0 )
    {
        strcpy(base,_base), strcpy(rel,_rel);
        sprintf(baserel,"%s/%s",base,rel);
    }
    else
    {
        strcpy(base,_rel), strcpy(rel,_base);
        sprintf(baserel,"%s/%s",rel,base);
    }
    json = cJSON_CreateObject(), bids = cJSON_CreateArray(), asks = cJSON_CreateArray();
    highbid = lowask = 0.;
    bidsum = asksum = bidvol = askvol = 0.;
    for (slot=numbids=numasks=enda=endb=0; slot<maxdepth && enda+endb!=2; slot++)
    {
        bid = &bidasks[slot << 1], ask = &bidasks[(slot << 1) + 1];
        if ( endb == 0 && (price= bid->price) > SMALLVAL )
        {
            volume = bid->volume;
            if ( invert == 0 )
            {
                bidsum += (price * volume), bidvol += volume;
                //printf("bid %f %f vol %f, cumulative %f %f\n",bid->price,price,volume,bidsum/bidvol,bidvol);
                jaddi(bids,exchanges777_quotejson(bid,allflag,bidsum,bidvol));
                if ( numbids++ == 0 )
                    highbid = price;
            }
            else
            {
                volume *= price;
                price = 1. / price;
                A = *bid;
                A.price = price, A.volume = volume;
                asksum += (price * volume), askvol += volume;
                jaddi(asks,exchanges777_quotejson(&A,allflag,asksum,askvol));
                if ( numasks++ == 0 )
                    lowask = price;
            }
        } else endb = 1;
        if ( enda == 0 && (price= ask->price) > SMALLVAL )
        {
            volume = ask->volume;
            if ( invert == 0 )
            {
                asksum += (price * volume), askvol += volume;
                jaddi(asks,exchanges777_quotejson(ask,allflag,asksum,askvol));
                if ( numasks++ == 0 )
                    lowask = price;
            }
            else
            {
                volume *= price;
                price = 1. / price;
                B = *ask;
                B.price = price, B.volume = volume;
                bidsum += (price * volume), bidvol += volume;
                jaddi(bids,exchanges777_quotejson(&B,allflag,bidsum,bidvol));
                if ( numbids++ == 0 )
                    highbid = price;
            }
        } else enda = 1;
    }
    jaddstr(json,"exchange",exchange->name);
    jaddnum(json,"inverted",invert);
    jaddstr(json,"base",base);
    if ( rel[0] != 0 )
        jaddstr(json,"rel",rel);
    jadd(json,"bids",bids);
    jadd(json,"asks",asks);
    if ( invert == 0 )
    {
        jaddnum(json,"numbids",numbids);
        jaddnum(json,"numasks",numasks);
        if ( highbid > SMALLVAL )
            jaddnum(json,"highbid",highbid);
        if ( lowask > SMALLVAL )
            jaddnum(json,"lowask",lowask);
    }
    else
    {
        jaddnum(json,"numbids",numasks);
        jaddnum(json,"numasks",numbids);
        if ( lowask > SMALLVAL )
            jaddnum(json,"highbid",1. / lowask);
        if ( highbid > SMALLVAL )
            jaddnum(json,"lowask",1. / highbid);
    }
    timestamp = (uint32_t)time(NULL);
    jaddnum(json,"timestamp",timestamp);
    jaddstr(json,"time",utc_str(str,timestamp));
    jaddnum(json,"maxdepth",maxdepth);
    return(jprint(json,1));
}

double exchange_setquote(struct exchange_quote *bidasks,int32_t *numbidsp,int32_t *numasksp,int32_t bidask,int32_t invert,double price,double volume,double commission,uint64_t orderid,uint32_t timestamp,uint64_t offerNXT)
{
    int32_t slot_ba; struct exchange_quote *quote;
    if ( price > SMALLVAL && volume > SMALLVAL )
    {
        if ( invert != 0 )
        {
            bidask = (1 ^ bidask);
            volume *= price;
            price = 1. / price;
        }
        if ( commission != 0. )
        {
            printf("price %f fee %f -> ",price,commission * price);
            if ( bidask == 0 )
                price -= commission * price;
            else price += commission * price;
            printf("%f\n",price);
        }
        quote = (bidask == 0) ? &bidasks[(*numbidsp)<<1] : &bidasks[((*numasksp)<<1) + 1];
        quote->price = price, quote->volume = volume, quote->timestamp = timestamp, quote->orderid = orderid, quote->offerNXT = offerNXT;
        if ( bidask == 0 )
            slot_ba = ((*numbidsp)++ << 1);
        else slot_ba = ((*numasksp)++ << 1) | 1;
        quote->satoshis = (price * SATOSHIDEN);
    }
    return(price);
}

void exchanges777_json_quotes(struct exchange_info *exchange,double commission,char *base,char *rel,double *lastbidp,double *lastaskp,double *hblap,struct exchange_quote *bidasks,cJSON *bids,cJSON *asks,int32_t maxdepth,char *pricefield,char *volfield,uint32_t reftimestamp,int32_t invert)
{
    int32_t i,slot,n=0,m=0,dir,bidask,numitems,numbids,numasks; uint64_t orderid,offerNXT;
    cJSON *item; uint32_t timestamp; double price,volume,hbla = 0.;
    *lastbidp = *lastaskp = 0.;
    numbids = numasks = 0;
    if ( reftimestamp == 0 )
        reftimestamp = (uint32_t)time(NULL);
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
    for (i=0; i<n || i<m; i++)
    {
        for (bidask=0; bidask<2; bidask++)
        {
            offerNXT = orderid = 0;
            price = volume = 0.;
            dir = (bidask == 0) ? 1 : -1;
            if ( bidask == 0 && i >= n )
                continue;
            else if ( bidask == 1 && i >= m )
                continue;
            //if ( strcmp(prices->exchange,"bter") == 0 && dir < 0 )
            //    slot = ((bidask==0?n:m) - 1) - i;
            //else
            slot = i;
            timestamp = 0;
            item = jitem(bidask==0?bids:asks,slot);
            if ( pricefield != 0 && volfield != 0 )
                price = jdouble(item,pricefield), volume = jdouble(item,volfield);
            else if ( is_cJSON_Array(item) != 0 && (numitems= cJSON_GetArraySize(item)) != 0 ) // big assumptions about order within nested array!
            {
                price = jdouble(jitem(item,0),0), volume = jdouble(jitem(item,1),0);
                if ( strcmp(exchange->name,"kraken") == 0 )
                    timestamp = juint(jitem(item,2),0);
                else orderid = j64bits(jitem(item,2),0);
                //printf("{%s} (%.8f %.8f) %f\n",jprint(item,0),price,volume,commission);
            }
            else
            {
                price = jdouble(item,"price");
                volume = jdouble(item,"volume");
                timestamp = juint(item,"timestamp");
                orderid = j64bits(item,"orderid");
                offerNXT = j64bits(item,"account");
            }
            if ( price == 0. || volume == 0. )
                continue;
            if ( price > SMALLVAL && volume > SMALLVAL )
            {
                price = exchange_setquote(bidasks,&numbids,&numasks,bidask,invert,price,volume,commission,orderid,timestamp,offerNXT);
                if ( i == 0 )
                {
                    if ( (bidask ^ invert) == 0 )
                        *lastbidp = price;
                    else *lastaskp = price;
                    if ( hbla == 0. )
                        hbla = price;
                    else hbla = 0.5 * (hbla + price);
                }
                //printf("%d,%d: %-8s %s %5s/%-5s %13.8f vol %13.8f | i %13.8f vol %13.8f | t.%u\n",numbids,numasks,exchange->name,dir>0?"bid":"ask",base,rel,price,volume,1./price,volume*price,timestamp);
            }
        }
    }
    if ( hbla != 0. )
        *hblap = hbla;
}

double exchanges777_json_orderbook(struct exchange_info *exchange,double commission,char *base,char *rel,struct exchange_quote *bidasks,int32_t maxdepth,cJSON *json,char *resultfield,char *bidfield,char *askfield,char *pricefield,char *volfield,int32_t invert)
{
    cJSON *obj = 0,*bidobj=0,*askobj=0; double lastbid,lastask,hbla = 0.; int32_t numasks=0,numbids=0;
    if ( resultfield == 0 )
        obj = json;
    if ( maxdepth == 0 )
        maxdepth = EXCHANGES777_MAXDEPTH;
    if ( resultfield == 0 || (obj= jobj(json,resultfield)) != 0 )
    {
        bidobj = jarray(&numbids,obj,bidfield);
        askobj = jarray(&numasks,obj,askfield);
        if ( bidobj != 0 || askobj != 0 )
        {
            exchanges777_json_quotes(exchange,commission,base,rel,&lastbid,&lastask,&hbla,bidasks,bidobj,askobj,maxdepth,pricefield,volfield,0,invert);
        }
    }
    return(hbla);
}

double exchanges777_standardprices(struct exchange_info *exchange,double commission,char *base,char *rel,char *url,struct exchange_quote *quotes,char *price,char *volume,int32_t maxdepth,char *field,int32_t invert)
{
    char *jsonstr; cJSON *json; double hbla = 0.;
    if ( (jsonstr= issue_curl(url)) != 0 )
    {
        //if ( strcmp(exchangestr,"btc38") == 0 )
        //printf("%f (%s) -> (%s)\n",commission,url,jsonstr);
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            hbla = exchanges777_json_orderbook(exchange,commission,base,rel,quotes,maxdepth,json,field,"bids","asks",price,volume,invert);
            free_json(json);
        }
        free(jsonstr);
    }
    return(hbla);
}

char *exchange_would_submit(char *postreq,char *hdr1,char *hdr2,char *hdr3, char *hdr4)
{
    char *data; cJSON *json;
    json = cJSON_CreateObject();
    jaddstr(json,"post",postreq);
    if ( hdr1[0] != 0 )
        jaddstr(json,"hdr1",hdr1);
    if ( hdr2[0] != 0 )
        jaddstr(json,"hdr2",hdr2);
    if ( hdr3[0] != 0 )
        jaddstr(json,"hdr3",hdr3);
    if ( hdr4[0] != 0 )
        jaddstr(json,"hdr4",hdr4);
    data = jprint(json,1);
    json = 0;
    return(data);
}

uint64_t exchange_nonce(struct exchange_info *exchange)
{
    uint64_t nonce;
    nonce = time(NULL);
    if ( nonce < exchange->lastnonce )
        nonce = exchange->lastnonce + 1;
    exchange->lastnonce = nonce;
    return(nonce);
}

int32_t flip_for_exchange(char *pairstr,char *fmt,char *refstr,int32_t dir,double *pricep,double *volumep,char *base,char *rel)
{
    if ( strcmp(rel,refstr) == 0 )
        sprintf(pairstr,fmt,rel,base);
    else
    {
        if ( strcmp(base,refstr) == 0 )
        {
            sprintf(pairstr,fmt,base,rel);
            dir = -dir;
            *volumep *= *pricep;
            *pricep = (1. / *pricep);
        }
        else sprintf(pairstr,fmt,rel,base);
    }
    return(dir);
}

int32_t flipstr_for_exchange(struct exchange_info *exchange,char *pairstr,char *fmt,int32_t dir,double *pricep,double *volumep,char *_base,char *_rel,cJSON *argjson)
{
    int32_t polarity; char base[64],rel[64];
    strcpy(base,_base), strcpy(rel,_rel);
    tolowercase(base), tolowercase(rel);
    polarity = (*exchange->issue.supports)(exchange,base,rel,argjson);
    if ( dir > 0 )
        sprintf(pairstr,fmt,base,rel);
    else if ( dir < 0 )
    {
        *volumep *= *pricep;
        *pricep = (1. / *pricep);
        sprintf(pairstr,fmt,rel,base);
    }
    return(dir);
}

int32_t cny_flip(char *market,char *coinname,char *base,char *rel,int32_t dir,double *pricep,double *volumep)
{
    char pairstr[512],lbase[32],lrel[32],*refstr=0;
    strcpy(lbase,base), tolowercase(lbase), strcpy(lrel,rel), tolowercase(lrel);
    if ( strcmp(lbase,"cny") == 0 || strcmp(lrel,"cny") == 0 )
    {
        dir = flip_for_exchange(pairstr,"%s_%s","cny",dir,pricep,volumep,lbase,lrel);
        refstr = "cny";
    }
    else if ( strcmp(lbase,"btc") == 0 || strcmp(lrel,"btc") == 0 )
    {
        dir = flip_for_exchange(pairstr,"%s_%s","btc",dir,pricep,volumep,lbase,lrel);
        refstr = "btc";
    }
    if ( market != 0 && coinname != 0 && refstr != 0 )
    {
        strcpy(market,refstr);
        if ( strcmp(lbase,"refstr") != 0 )
            strcpy(coinname,lbase);
        else strcpy(coinname,lrel);
        touppercase(coinname);
    }
    return(dir);
}

char *exchange_extractorderid(int32_t historyflag,char *status,uint64_t quoteid,char *quoteid_field)
{
    cJSON *array,*item,*json; int32_t i,n; uint64_t txid;
    if ( status != 0 )
    {
        if ( (array= cJSON_Parse(status)) != 0 && is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                if ( (txid= juint(item,quoteid_field)) == quoteid )
                {
                    json = cJSON_CreateObject();
                    jaddstr(json,"result",historyflag == 0 ? "order still pending" : "order completed");
                    jadd(json,"order",cJSON_Duplicate(item,1));
                    free_json(array);
                    return(jprint(json,1));
                }
            }
        }
        if ( array != 0 )
            free_json(array);
    }
    return(0);
}

int32_t baserel_polarity(char *pairs[][2],int32_t n,char *_base,char *_rel)
{
    int32_t i; char base[32],rel[32],cmpbase[32],cmprel[32];
    strcpy(base,_base), tolowercase(base);
    strcpy(rel,_rel), tolowercase(rel);
    for (i=0; i<n; i++)
    {
        strcpy(cmpbase,pairs[i][0]), tolowercase(cmpbase);
        strcpy(cmprel,pairs[i][1]), tolowercase(cmprel);
        if ( strcmp(cmpbase,base) == 0 && strcmp(cmprel,rel) == 0 )
            return(1);
        else if ( strcmp(cmpbase,rel) == 0 && strcmp(cmprel,base) == 0 )
            return(-1);
    }
    //printf("%s cant find.(%s/%s) [%s/%s].%d\n",exchange->name,base,rel,pairs[0][0],pairs[0][1],n);
    return(0);
}

// following includes C code directly
#include "exchanges/poloniex.c"
#include "exchanges/bittrex.c"
#include "exchanges/btce.c"
#include "exchanges/bitfinex.c"
#include "exchanges/btc38.c"
#include "exchanges/huobi.c"
#include "exchanges/lakebtc.c"
#include "exchanges/quadriga.c"
#include "exchanges/okcoin.c"
#include "exchanges/coinbase.c"
#include "exchanges/bitstamp.c"

#include "exchanges/truefx.c"
#include "exchanges/PAX.c"
#include "exchanges/fxcm.c"
#include "exchanges/instaforex.c"

#include "exchanges/jumblr.c"
#include "exchanges/bitcoin.c"
#include "exchanges/nxtae.c"
#include "exchanges/unconf.c"

struct exchange_funcs *Exchange_funcs[] =
{
    &truefx_funcs, &instaforex_funcs, &fxcm_funcs, // prices only
    &PAX_funcs, &nxtae_funcs, &bitcoin_funcs, &jumblr_funcs, // special
    &bitfinex_funcs, &huobi_funcs, &lakebtc_funcs, &quadriga_funcs, &okcoin_funcs, // BTC exchanges
    &poloniex_funcs, &bittrex_funcs, &btce_funcs, &btc38_funcs, // altcoin exchanges
    &coinbase_funcs, &bitstamp_funcs // authentication not working yet
};

struct exchange_info *Exchanges[sizeof(Exchange_funcs)/sizeof(*Exchange_funcs)];

int32_t exchanges777_orient(struct exchange_info *exchange,char *base,char *rel,double *pricep,double *volumep,struct exchange_request *req)
{
    int32_t polarity = 1;
    if ( exchange->issue.supports != 0 )
        polarity = (*exchange->issue.supports)(exchange,req->base,req->rel,req->argjson);
    if ( polarity < 0 )
    {
        strcpy(base,req->rel);
        strcpy(rel,req->base);
        if ( volumep != 0 )
            *volumep = (req->price * req->volume);
        if ( pricep != 0 && req->price != 0 )
            *pricep = 1. / req->price;
    }
    else
    {
        strcpy(rel,req->rel);
        strcpy(base,req->base);
        if ( pricep != 0 )
            *pricep = req->price;
        if ( volumep != 0 )
            *volumep = req->volume;
    }
    touppercase(base), touppercase(rel);
    return(polarity);
}

char *exchanges777_process(struct exchange_info *exchange,int32_t *retvalp,struct exchange_request *req)
{
    char base[32],rel[32],*retstr = 0; int32_t polarity; uint64_t orderid; double price,volume,balance; cJSON *balancejson,*retjson;
    *retvalp = EXCHANGE777_DONE;
    switch ( req->func )
    {
        case 'Q': case 'M':
            if ( exchange->issue.price != 0 )
            {
                memset(req->bidasks,0,req->depth * sizeof(*req->bidasks) * 2);
                if ( (polarity= exchanges777_orient(exchange,base,rel,0,0,req)) <= 0 )
                    retstr = clonestr("{\"error\":\"invalid polarity\"}");
                else
                {
                    //printf("polarity.%d %s %s req.(%s %s)\n",polarity,base,rel,req->base,req->rel);
                    (*exchange->issue.price)(exchange,req->base,req->rel,req->bidasks,req->depth,req->commission,req->argjson,req->invert);
                    retstr = exchanges777_orderbook_jsonstr(exchange,base,rel,req->bidasks,req->depth,0,req->allflag);
                }
            }
            break;
        case 'S':
            if ( exchange->issue.supports != 0 )
            {
                polarity = (*exchange->issue.supports)(exchange,req->base,req->rel,req->argjson);
                retjson = cJSON_CreateObject();
                jaddnum(retjson,"result",polarity);
                retstr = jprint(retjson,1);
            }
            break;
        case 'T':
            if ( exchange->issue.trade != 0 )
            {
                polarity = exchanges777_orient(exchange,base,rel,&price,&volume,req);
                orderid = (*exchange->issue.trade)(req->dotrade,&retstr,exchange,base,rel,polarity * req->dir,price,volume,req->argjson);
                if ( retstr == 0 )
                {
                    req->orderid = orderid;
                    retstr = (*exchange->issue.orderstatus)(exchange,req->orderid,req->argjson);
                    /*retjson = cJSON_CreateObject();
                     if ( orderid != 0 )
                     jadd64bits(retjson,"result",orderid);
                     else jaddstr(retjson,"error","no return value from trade call");
                     retstr = jprint(retjson,1);*/
                }
            }
            break;
        case 'B':
            if ( exchange->issue.balances != 0 )
            {
                if ( (balancejson= (*exchange->issue.balances)(exchange,req->argjson)) != 0 )
                {
                    //printf("BALANCE.(%s)\n",jprint(balancejson,0));
                    if ( req->base[0] != 0 && exchange->issue.parsebalance != 0 )
                        retstr = (*exchange->issue.parsebalance)(exchange,&balance,req->base,balancejson);
                    else retstr = jprint(balancejson,0);
                    free_json(balancejson);
                }
            }
            break;
        case 'P':
            if ( exchange->issue.orderstatus != 0 )
                retstr = (*exchange->issue.orderstatus)(exchange,req->orderid,req->argjson);
            break;
        case 'C':
            if ( exchange->issue.cancelorder != 0 )
                retstr = (*exchange->issue.cancelorder)(exchange,req->orderid,req->argjson);
            break;
        case 'O':
            if ( exchange->issue.openorders != 0 )
                retstr = (*exchange->issue.openorders)(exchange,req->argjson);
            break;
        case 'H':
            if ( exchange->issue.tradehistory != 0 )
                retstr = (*exchange->issue.tradehistory)(exchange,req->argjson);
            break;
        case 'W':
            if ( exchange->issue.withdraw != 0 )
                retstr = (*exchange->issue.withdraw)(exchange,req->base,req->volume,req->destaddr,req->argjson);
            break;
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"null return\"}");
    return(retstr);
}

/*void iguana_statemachineupdate(struct supernet_info *myinfo,struct exchange_info *exchange)
{
    int32_t timemod,modwidth = 10; struct iguana_info *coin; struct bitcoin_swapinfo *swap,*tmp; struct iguana_bundlereq *req;
    timemod = time(NULL) % modwidth;
    coin = iguana_coinfind("BTCD");
    portable_mutex_lock(&exchange->mutexS);
    DL_FOREACH_SAFE(exchange->statemachines,swap,tmp)
    {
        if ( swap->dead != 0 || swap->mine.dead != 0 || swap->other.dead != 0 )
            DL_DELETE(exchange->statemachines,swap);
        else if ( (swap->mine.orderid % modwidth) == timemod )
            instantdex_statemachine_iter(myinfo,exchange,swap);
    }
    portable_mutex_unlock(&exchange->mutexS);
    while ( (req= queue_dequeue(&exchange->recvQ,0)) != 0 )
    {
        if ( instantdex_recvquotes(coin,req,req->hashes,req->n) != 0 )
            myfree(req->hashes,(req->n+1) * sizeof(*req->hashes)), req->hashes = 0;
    }
    //iguana_inv2poll(myinfo,coin);
}*/

void exchanges777_loop(void *ptr)
{
    struct supernet_info *myinfo; struct exchange_info *exchange = ptr;
    int32_t flag,retval,i; struct exchange_request *req; char *retstr;
    myinfo = SuperNET_MYINFO(0);
#ifdef INCLUDE_PAX
    /*struct peggy_info *PEGS=0; int32_t peggyflag = 0;
    if ( strcmp(exchange->name,"PAX") == 0 )
    {
        if ( (PEGS= myinfo->PEGS) != 0 )
        {
            exchange->privatedata = PEGS;
            peggyflag = 1;
            _crypto_update(PEGS,PEGS->cryptovols,&PEGS->data,1,peggyflag);
            PEGS->lastupdate = (uint32_t)time(NULL);
        }
    }*/
#endif
    printf("exchanges loop.(%s)\n",exchange->name);
    while ( 1 )
    {
        if ( strcmp("bitcoin",exchange->name) == 0 )
            PAX_idle(myinfo);
        flag = retval = 0;
        retstr = 0;
        if ( (req= queue_dequeue(&exchange->requestQ)) != 0 )
        {
            //printf("dequeued %s.%c\n",exchange->name,req->func);
            if ( req->dead == 0 )
            {
                retstr = exchanges777_process(exchange,&retval,req);
                //printf("retval.%d (%p) retstrp.%p timedout.%u\n",retval,retstr,req->retstrp,req->timedout);
                if ( retval == EXCHANGE777_DONE )
                {
                    if ( retstr != 0 )
                    {
                        if ( req->retstrp != 0 && req->timedout == 0 )
                            *req->retstrp = retstr;
                        else free(retstr);
                        if ( req->timedout != 0 )
                            printf("timedout.%u req finally finished at %u\n",req->timedout,(uint32_t)time(NULL));
                    }
                    free(req);
                    flag++;
                }
                else
                {
                    if ( retstr != 0 )
                        free(retstr);
                    //if ( retval == EXCHANGE777_ISPENDING )
                    //    queue_enqueue("Xpending",&exchange->pendingQ,&req->DL,0), flag++;
                    //else
                    if ( retval == EXCHANGE777_REQUEUE )
                        queue_enqueue("requeue",&exchange->requestQ,&req->DL);
                    else
                    {
                        printf("exchanges777_process: illegal retval.%d\n",retval);
                        free(req);
                    }
                }
            }
            else
            {
                if ( req->retstrp != 0 )
                    *req->retstrp = clonestr("{\"result\":\"request killed\"}");
                free(req);
            }
        }
        tradebot_timeslices(exchange);
        if ( time(NULL) > exchange->lastpoll+exchange->pollgap )
        {
            /*if ( strcmp(exchange->name,"bitcoin") == 0 )
            {
                iguana_statemachineupdate(myinfo,exchange);
                //printf("InstantDEX call update\n");
            }*/
            if ( (req= queue_dequeue(&exchange->pricesQ)) != 0 )
            {
                //printf("check %s pricesQ (%s %s)\n",exchange->name,req->base,req->rel);
                if ( req->dead == 0 )
                {
                    if ( req->base[0] != 0 )
                    {
                        req->timestamp = exchange->lastpoll = (uint32_t)time(NULL);
                        req->exchange = exchange;
                        req->hbla = (*exchange->issue.price)(exchange,req->base,req->rel,req->bidasks,req->depth,req->commission,req->argjson,req->invert);
                        for (i=req->numbids=0; i<req->depth; i++)
                            if ( req->bidasks[i << 1].price > SMALLVAL )
                                req->numbids++;
                        for (i=req->numasks=0; i<req->depth; i++)
                            if ( req->bidasks[(i << 1) + 1].price > SMALLVAL )
                                req->numasks++;
//printf("%-10s %s/%s numbids.%d numasks.%d\n",exchange->name,req->base,req->rel,req->numbids,req->numasks);
                        tradebots_processprices(myinfo,exchange,req->base,req->rel,req->bidasks,req->numbids,req->numasks);
                    }
                    queue_enqueue("pricesQ",&exchange->pricesQ,&req->DL);
                }
                else
                {
                    if ( req->retstrp != 0 )
                        *req->retstrp = clonestr("{\"result\":\"request killed\"}");
                    free(req);
                }
            }
        }
        if ( flag == 0 )
            sleep(exchange->pollgap/2 + 1);
    }
}

struct exchange_request *exchanges777_baserelfind(struct exchange_info *exchange,char *base,char *rel,int32_t func)
{
    struct exchange_request PAD,*req,*retreq=0;
    memset(&PAD,0,sizeof(PAD));
    queue_enqueue("pricesQ",&exchange->pricesQ,&PAD.DL);
    while ( (req= queue_dequeue(&exchange->pricesQ)) != 0 && req != &PAD )
    {
        if ( ((req->invert == 0 && strcmp(base,req->base) == 0 && strcmp(rel,req->rel) == 0) || (req->invert != 0 && strcmp(rel,req->base) == 0 && strcmp(base,req->rel) == 0)) && (func < 0 || req->func == func) )
            retreq = req;
        queue_enqueue("pricesQ",&exchange->pricesQ,&req->DL);
    }
    return(retreq);
}

char *exchanges777_unmonitor(struct exchange_info *exchange,char *base,char *rel)
{
    struct exchange_request *req; char *retstr = 0;
    if ( (req= exchanges777_baserelfind(exchange,base,rel,'M')) != 0 )
    {
        printf("unmonitor.%s (%s %s)\n",exchange->name,base,rel);
        req->dead = (uint32_t)time(NULL);
        retstr = clonestr("{\"result\":\"mark priceQ entry as dead\"}");
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"cant find base/rel pair to unmonitor\"}");
    return(retstr);
}

char *exchanges777_submit(struct exchange_info *exchange,struct exchange_request *req,int32_t func,int32_t maxseconds)
{
    int32_t i; char **retstrp,*retstr;
    req->func = func;
    if ( maxseconds == 0 )
        maxseconds = EXCHANGES777_DEFAULT_TIMEOUT;
    retstrp = req->retstrp;
    //printf("submit to %p\n",&exchange->requestQ);
    queue_enqueue("exchangeQ",&exchange->requestQ,&req->DL);
    for (i=0; i<maxseconds; i++)
    {
        if ( retstrp != 0 && (retstr= *retstrp) != 0 )
        {
            //printf("exchanges777_submit GOT.(%s)\n",retstr);
            free(retstrp);
            return(retstr);
        }
        sleep(1);
    }
    req->timedout = (uint32_t)time(NULL);
    printf("exchanges777_submit timed out.(%c)\n",func);
    return(clonestr("{\"error\":\"request timed out\"}"));
}

char *exchanges777_Qtrade(struct exchange_info *exchange,char *base,char *rel,int32_t maxseconds,int32_t dotrade,int32_t dir,double price,double volume,cJSON *argjson)
{
    struct exchange_request *req; int32_t polarity;
    if ( exchange->issue.supports == 0 )
        return(clonestr("{\"error\":\"no supports function\"}"));
    if ( base[0] == 0 || rel[0] == 0 || (polarity= (*exchange->issue.supports)(exchange,base,rel,argjson)) <= 0 || price < SMALLVAL || volume < SMALLVAL )
        return(clonestr("{\"error\":\"invalid base or rel\"}"));
    req = calloc(1,sizeof(*req));
    req->argjson = argjson; req->retstrp = calloc(1,sizeof(void *));
    safecopy(req->base,base,sizeof(req->base));
    safecopy(req->rel,rel,sizeof(req->rel));
    req->price = price, req->volume = volume, req->dir = dir;
    req->dotrade = dotrade;
    return(exchanges777_submit(exchange,req,'T',maxseconds));
}

char *exchanges777_Qprices(struct exchange_info *exchange,char *base,char *rel,int32_t maxseconds,int32_t allfields,int32_t depth,cJSON *argjson,int32_t monitor,double commission)
{
    struct exchange_request *req; int32_t polarity;
    if ( exchange->issue.supports == 0 )
    {
        printf("%s doesnt have supports func\n",exchange->name);
        return(clonestr("{\"error\":\"no supports function\"}"));
    }
    if ( base[0] == 0 || rel[0] == 0 || (polarity= (*exchange->issue.supports)(exchange,base,rel,argjson)) == 0 )
    {
        printf("%s invalid (%s) or (%s)\n",exchange->name,base,rel);
        return(clonestr("{\"error\":\"invalid base or rel\"}"));
    }
    if ( depth <= 0 )
        depth = 1;
    req = calloc(1,sizeof(*req) + sizeof(*req->bidasks)*depth*2);
    req->argjson = argjson; req->retstrp = calloc(1,sizeof(void *));
    if ( polarity < 0 )
    {
        req->invert = 1;
        safecopy(req->base,rel,sizeof(req->base));
        safecopy(req->rel,base,sizeof(req->rel));
    }
    else
    {
        safecopy(req->base,base,sizeof(req->base));
        safecopy(req->rel,rel,sizeof(req->rel));
    }
    req->depth = depth, req->allflag = allfields;
    if ( (req->commission= commission) == 0. )
        req->commission = exchange->commission;
    if ( monitor == 0 )
    {
        //printf("%s submit (%s) (%s)\n",exchange->name,base,rel);
        return(exchanges777_submit(exchange,req,'Q',maxseconds));
    }
    else
    {
        req->func = 'M';
        //printf("Monitor.%s (%s %s) invert.%d\n",exchange->name,base,rel,req->invert);
        queue_enqueue("pricesQ",&exchange->pricesQ,&req->DL);
        return(clonestr("{\"result\":\"start monitoring\"}"));
    }
}

char *exchanges777_Qrequest(struct exchange_info *exchange,int32_t func,char *base,char *rel,int32_t maxseconds,uint64_t orderid,char *destaddr,double amount,cJSON *argjson)
{
    struct exchange_request *req;
    req = calloc(1,sizeof(*req));
    req->volume = amount;
    safecopy(req->destaddr,destaddr,sizeof(req->destaddr));
    safecopy(req->base,base,sizeof(req->base));
    safecopy(req->rel,rel,sizeof(req->rel));
    req->retstrp = calloc(1,sizeof(void *));
    req->orderid = orderid;
    req->argjson = jduplicate(argjson);
    //printf("Qrequest\n");
    return(exchanges777_submit(exchange,req,func,maxseconds));
}

int32_t exchanges777_id(char *exchangestr)
{
    int32_t i;
    if ( exchangestr != 0 )
    {
        for (i=0; i<sizeof(Exchange_funcs)/sizeof(*Exchange_funcs); i++)
        {
            //printf("%s ",Exchange_funcs[i]->name);
            if ( strcmp(exchangestr,Exchange_funcs[i]->name) == 0 )
                return(i);
        }
        //printf("cant find (%s)\n",exchangestr);
    }
    return(-1);
}

struct exchange_info *exchanges777_findbits(uint64_t exchangebits)
{
    int32_t i;
    for (i=0; i<sizeof(Exchange_funcs)/sizeof(*Exchange_funcs); i++)
    {
        //printf("%s ",Exchange_funcs[i]->name);
        if ( Exchanges[i] != 0 && exchangebits == Exchanges[i]->exchangebits )
            return(Exchanges[i]);
    }
    //printf("cant find (%s)\n",exchangestr);
    return(0);
}

struct exchange_info *exchanges777_find(char *exchangestr)
{
    int32_t exchangeid;
    if ( (exchangeid= exchanges777_id(exchangestr)) >= 0 )
        return(Exchanges[exchangeid]);
    return(0);
}

void iguana_gotquotesM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *quotes,int32_t n)
{
    struct iguana_bundlereq *req; struct exchange_info *exchange = exchanges777_find("bitcoin");
    //printf("got %d quotes from %s\n",n,addr->ipaddr);
    req = iguana_bundlereq(coin,addr,'Q',0,0);
    req->hashes = quotes, req->n = n;
    queue_enqueue("recvQ",&exchange->recvQ,&req->DL);
}

struct exchange_info *exchange_create(char *exchangestr,cJSON *argjson)
{
    static int didinit;
    if ( didinit == 0 )
    {
        int32_t i,j;
        for (i=0; i<sizeof(Exchange_funcs)/sizeof(*Exchange_funcs)-1; i++)
        {
            for (j=i+1; j<sizeof(Exchange_funcs)/sizeof(*Exchange_funcs); j++)
                if ( stringbits((char *)Exchange_funcs[i]->name) == stringbits((char *)Exchange_funcs[j]->name) )
                {
                    printf("FIRST 8 chars of Exchange_func[].name must be unique: %d.(%s) vs %d.(%s)\n",i,Exchange_funcs[i]->name,j,Exchange_funcs[j]->name);
                    iguana_exit(0,0);
                }
        }
        didinit = 1;
    }
    char *key,*secret,*userid,*tradepassword; struct exchange_info *exchange; int32_t i,exchangeid;
    if ( exchangestr == 0 || exchangestr[0] == 0 )
        return(0);
    if ( (exchangeid= exchanges777_id(exchangestr)) < 0 )
    {
        printf("exchange_create: cant find.(%s)\n",exchangestr);
        return(0);
    }
    for (i=0; i<sizeof(Exchange_funcs)/sizeof(*Exchange_funcs); i++)
    {
        if ( strcmp(exchangestr,Exchange_funcs[i]->name) == 0 )
            break;
    }
    if ( i == sizeof(Exchange_funcs)/sizeof(*Exchange_funcs) )
    {
        printf("cant find exchange.(%s)\n",exchangestr);
        return(0);
    }
    exchange = calloc(1,sizeof(*exchange));
    portable_mutex_init(&exchange->mutex);
    portable_mutex_init(&exchange->mutexS);
    portable_mutex_init(&exchange->mutexH);
    portable_mutex_init(&exchange->mutexP);
    portable_mutex_init(&exchange->mutexR);
    portable_mutex_init(&exchange->mutexT);
    exchange->issue = *Exchange_funcs[i];
    iguana_initQ(&exchange->recvQ,"recvQ");
    iguana_initQ(&exchange->pricesQ,"pricesQ");
    iguana_initQ(&exchange->requestQ,"requestQ");
    exchange->exchangeid = exchangeid;
    safecopy(exchange->name,exchangestr,sizeof(exchange->name));
    exchange->exchangebits = stringbits(exchange->name);
    if ( argjson != 0 )
    {
        if ( (exchange->pollgap= juint(argjson,"pollgap")) < EXCHANGES777_MINPOLLGAP )
            exchange->pollgap = EXCHANGES777_MINPOLLGAP;
        if ( (key= jstr(argjson,"apikey")) != 0 || (key= jstr(argjson,"key")) != 0 )
            safecopy(exchange->apikey,key,sizeof(exchange->apikey));
        if ( (secret= jstr(argjson,"apisecret")) != 0 || (secret= jstr(argjson,"secret")) != 0 )
            safecopy(exchange->apisecret,secret,sizeof(exchange->apisecret));
        if ( (userid= jstr(argjson,"userid")) != 0 )
            safecopy(exchange->userid,userid,sizeof(exchange->userid));
        if ( (tradepassword= jstr(argjson,"tradepassword")) != 0 )
            safecopy(exchange->tradepassword,tradepassword,sizeof(exchange->tradepassword));
        if ( (exchange->commission= jdouble(argjson,"commission")) > 0. )
            exchange->commission *= .01;
    }
    printf("ADDEXCHANGE.(%s) [%s, %s, %s] commission %.3f%% -> exchangeid.%d\n",exchangestr,exchange->apikey,exchange->userid,exchange->apisecret,exchange->commission * 100.,exchangeid);
    Exchanges[exchangeid] = exchange;
    //instantdex_FSMinit();
    iguana_launch(0,"exchangeloop",(void *)exchanges777_loop,exchange,IGUANA_EXCHANGETHREAD);
    return(exchange);
}

struct exchange_info *exchanges777_info(char *exchangestr,int32_t sleepflag,cJSON *json,char *remoteaddr)
{
    struct exchange_info *exchange;
    if ( remoteaddr != 0 || exchangestr == 0 )
        return(0);
    if ( (exchange= exchanges777_find(exchangestr)) == 0 )
    {
        if ( (exchange= exchange_create(exchangestr,json)) != 0 )
        {
            if ( sleepflag > 0 )
                sleep(sleepflag);
        }
    }
    if ( (0) && exchange != 0 )
        printf("found exchange.(%s) %p %p %p\n",exchange->name,exchange->issue.supports,exchange->issue.price,exchange->issue.allpairs);
    return(exchange);
}

void exchanges777_init(struct supernet_info *myinfo,cJSON *exchanges,int32_t sleepflag)
{
    int32_t i,n; cJSON *argjson,*item; struct exchange_info *exchange;
    if ( (exchange= exchanges777_find("bitcoin")) == 0 && (exchange= exchange_create("bitcoin",0)) != 0 )
        myinfo->tradingexchanges[myinfo->numexchanges++] = exchange;
    if ( exchanges != 0 )
    {
        n = cJSON_GetArraySize(exchanges);
        for (i=0; i<n; i++)
        {
            item = jitem(exchanges,i);
            if ( (exchange= exchanges777_find(jstr(item,"name"))) == 0 && (exchange= exchange_create(jstr(item,"name"),item)) != 0 )
                myinfo->tradingexchanges[myinfo->numexchanges++] = exchange;
        }
    }
    if ( 1 )
    {
        argjson = cJSON_CreateObject();
        for (i=0; i<sizeof(Exchange_funcs)/sizeof(*Exchange_funcs); i++)
            if ( (exchange= exchanges777_find(Exchange_funcs[i]->name)) == 0 )
            {
                if ( strcmp(Exchange_funcs[i]->name,"PAX") == 0 || strcmp(Exchange_funcs[i]->name,"truefx") == 0 || strcmp(Exchange_funcs[i]->name,"fxcm") == 0 || strcmp(Exchange_funcs[i]->name,"instaforex") == 0 )
                {
                    exchange->pollgap = 60;
                    continue;
                }
                if ( ((exchange= exchanges777_find(Exchange_funcs[i]->name)) == 0 && (exchange= exchange_create(Exchange_funcs[i]->name,0)) != 0) || (exchange= exchanges777_info(Exchange_funcs[i]->name,sleepflag,argjson,0)) != 0 )
                    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange;
            }
        free_json(argjson);
    }
}

cJSON *iguana_pricesarray(struct supernet_info *myinfo,char *exchange,char *base,char *rel,int32_t period,uint32_t start,uint32_t end)
{
    cJSON *array = cJSON_CreateArray();
    return(array);
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"
#include "../includes/iguana_apideclares2.h"

THREE_STRINGS_AND_THREE_INTS(InstantDEX,orderbook,exchange,base,rel,depth,allfields,ignore)
{
    struct exchange_info *ptr;
    if ( remoteaddr == 0 )
    {
        if ( exchange != 0 && exchange[0] != 0 )
        {
            if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
                return(exchanges777_Qprices(ptr,base,rel,juint(json,"maxseconds"),allfields,depth,json,0,ptr->commission));
            else return(clonestr("{\"error\":\"cant find or create exchange\"}"));
        } else return(clonestr("{\"error\":\"no exchange specified\"}"));
    } else return(clonestr("{\"error\":\"no remote for this API\"}"));
}

THREE_STRINGS_AND_THREE_DOUBLES(InstantDEX,buy,exchange,base,rel,price,volume,dotrade)
{
    struct exchange_info *ptr;
    if ( remoteaddr == 0 )
    {
        if ( myinfo->expiration == 0 )
            return(clonestr("{\"error\":\"need to unlock wallet\"}"));
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
            return(exchanges777_Qtrade(ptr,base,rel,juint(json,"maxseconds"),dotrade,1,price,volume,json));
        else return(clonestr("{\"error\":\"cant find or create exchange\"}"));
    } else return(clonestr("{\"error\":\"no remote for this API\"}"));
}

THREE_STRINGS_AND_THREE_DOUBLES(InstantDEX,sell,exchange,base,rel,price,volume,dotrade)
{
    struct exchange_info *ptr;
    if ( remoteaddr == 0 )
    {
        if ( myinfo->expiration == 0 )
            return(clonestr("{\"error\":\"need to unlock wallet\"}"));
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
            return(exchanges777_Qtrade(ptr,base,rel,juint(json,"maxseconds"),dotrade,-1,price,volume,json));
        else return(clonestr("{\"error\":\"cant find or create exchange\"}"));
    } else return(clonestr("{\"error\":\"no remote for this API\"}"));
}

THREE_STRINGS_AND_DOUBLE(InstantDEX,withdraw,exchange,base,destaddr,amount)
{
    struct exchange_info *ptr;
    if ( remoteaddr == 0 )
    {
        if ( myinfo->expiration == 0 )
            return(clonestr("{\"error\":\"need to unlock wallet\"}"));
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
            return(exchanges777_Qrequest(ptr,'W',base,0,juint(json,"maxseconds"),0,destaddr,amount,json));
        else return(clonestr("{\"error\":\"cant find or create exchange\"}"));
    } else return(clonestr("{\"error\":\"no remote for this API\"}"));
}

TWO_STRINGS(InstantDEX,balance,exchange,base)
{
    struct exchange_info *ptr;
    if ( remoteaddr == 0 )
    {
        if ( myinfo->expiration == 0 )
            return(clonestr("{\"error\":\"need to unlock wallet\"}"));
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
            return(exchanges777_Qrequest(ptr,'B',base,0,juint(json,"maxseconds"),0,0,0,json));
        else return(clonestr("{\"error\":\"cant find or create exchange\"}"));
    } else return(clonestr("{\"error\":\"no remote for this API\"}"));
}

TWO_STRINGS(InstantDEX,orderstatus,exchange,orderid)
{
    struct exchange_info *ptr; cJSON *argjson; char *retstr; uint64_t num = 0;
    if ( remoteaddr == 0 )
    {
        if ( myinfo->expiration == 0 )
            return(clonestr("{\"error\":\"need to unlock wallet\"}"));
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
        {
            argjson = cJSON_CreateObject();
            jaddstr(argjson,"uuid",orderid);
            if ( is_decimalstr(orderid) != 0 )
                num = calc_nxt64bits(orderid);
            retstr = exchanges777_Qrequest(ptr,'P',0,0,juint(json,"maxseconds"),num,0,0,argjson);
            free_json(argjson);
            return(retstr);
        }
        else return(clonestr("{\"error\":\"cant find or create exchange\"}"));
    } else return(clonestr("{\"error\":\"no remote for this API\"}"));
}

TWO_STRINGS(InstantDEX,cancelorder,exchange,orderid)
{
    struct exchange_info *ptr; cJSON *argjson; char *retstr; uint64_t num = 0;
    if ( remoteaddr == 0 )
    {
        if ( myinfo->expiration == 0 )
            return(clonestr("{\"error\":\"need to unlock wallet\"}"));
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
        {
            argjson = cJSON_CreateObject();
            jaddstr(argjson,"uuid",orderid);
            if ( is_decimalstr(orderid) != 0 )
                num = calc_nxt64bits(orderid);
            retstr = exchanges777_Qrequest(ptr,'C',0,0,juint(json,"maxseconds"),num,0,0,argjson);
            free_json(argjson);
            return(retstr);
        }
        else return(clonestr("{\"error\":\"cant find or create exchange\"}"));
    } else return(clonestr("{\"error\":\"no remote for this API\"}"));
}

STRING_ARG(InstantDEX,openorders,exchange)
{
    struct exchange_info *ptr;
    if ( remoteaddr == 0 )
    {
        if ( myinfo->expiration == 0 )
            return(clonestr("{\"error\":\"need to unlock wallet\"}"));
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
            return(exchanges777_Qrequest(ptr,'O',0,0,juint(json,"maxseconds"),0,0,0,json));
        else return(clonestr("{\"error\":\"cant find or create exchange\"}"));
    } else return(clonestr("{\"error\":\"no remote for this API\"}"));
}

STRING_ARG(InstantDEX,tradehistory,exchange)
{
    struct exchange_info *ptr;
    if ( remoteaddr == 0 )
    {
        if ( myinfo->expiration == 0 )
            return(clonestr("{\"error\":\"need to unlock wallet\"}"));
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
            return(exchanges777_Qrequest(ptr,'H',0,0,juint(json,"maxseconds"),0,0,0,json));
        else return(clonestr("{\"error\":\"cant find or create exchange\"}"));
    } else return(clonestr("{\"error\":\"no remote for this API\"}"));
}

THREE_STRINGS(InstantDEX,apikeypair,exchange,apikey,apisecret)
{
    struct exchange_info *ptr;
    if ( remoteaddr == 0 )
    {
        if ( myinfo->expiration == 0 )
            return(clonestr("{\"error\":\"need to unlock wallet\"}"));
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
        {
            if ( apikey != 0 && apikey[0] != 0 && apisecret != 0 && apisecret[0] != 0 )
            {
                safecopy(ptr->apikey,apikey,sizeof(ptr->apikey));
                safecopy(ptr->apisecret,apisecret,sizeof(ptr->apisecret));
                return(clonestr("{\"result\":\"set apikey and apisecret\"}"));
            } else return(clonestr("{\"error\":\"need both userid and password\"}"));
        } else return(clonestr("{\"error\":\"cant find or create exchange\"}"));
    } else return(clonestr("{\"error\":\"no remote for this API\"}"));
}

THREE_STRINGS(InstantDEX,setuserid,exchange,userid,tradepassword)
{
    struct exchange_info *ptr;
    if ( remoteaddr == 0 )
    {
        if ( myinfo->expiration == 0 )
            return(clonestr("{\"error\":\"need to unlock wallet\"}"));
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
        {
            safecopy(ptr->userid,userid,sizeof(ptr->userid));
            safecopy(ptr->tradepassword,tradepassword,sizeof(ptr->tradepassword));
            return(clonestr("{\"result\":\"set userid and/or tradepassword\"}"));
        } else return(clonestr("{\"error\":\"cant find or create exchange\"}"));
    } else return(clonestr("{\"error\":\"no remote for this API\"}"));
}

STRING_AND_INT(InstantDEX,pollgap,exchange,pollgap)
{
    struct exchange_info *ptr;
    if ( remoteaddr == 0 )
    {
        if ( myinfo->expiration == 0 )
            return(clonestr("{\"error\":\"need to unlock wallet\"}"));
        if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
        {
            ptr->pollgap = pollgap;
            return(clonestr("{\"result\":\"set pollgap\"}"));
        } else return(clonestr("{\"error\":\"cant find or create exchange\"}"));
    } else return(clonestr("{\"error\":\"no remote for this API\"}"));
}

ZERO_ARGS(InstantDEX,allexchanges)
{
    int32_t i; cJSON *retjson,*array;
    retjson = cJSON_CreateObject(); array = cJSON_CreateArray();
    for (i=0; i<sizeof(Exchange_funcs)/sizeof(*Exchange_funcs); i++)
        jaddistr(array,Exchange_funcs[i]->name);
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}

THREE_STRINGS(InstantDEX,supports,exchange,base,rel)
{
    struct exchange_info *ptr;
    if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 )
        return(exchanges777_Qrequest(ptr,'S',base,rel,juint(json,"maxseconds"),0,0,0,json));
    else return(clonestr("{\"error\":\"cant find or create exchange\"}"));
}

STRING_ARG(InstantDEX,allpairs,exchange)
{
    struct exchange_info *ptr;
    if ( (ptr= exchanges777_info(exchange,1,json,remoteaddr)) != 0 && ptr->issue.allpairs != 0 )
        return((*ptr->issue.allpairs)(ptr,json));
    else return(clonestr("{\"error\":\"cant find or create exchange\"}"));
}

TWO_STRINGS(iguana,rate,base,rel)
{
    cJSON *retjson,*tmpjson; char *retstr,baserel[128],_base[64],_rel[64]; double aveprice = 0.;
    safecopy(_base,base,sizeof(_base));
    safecopy(_rel,rel,sizeof(_rel));
    if ( (retstr= tradebot_aveprice(myinfo,coin,json,remoteaddr,"",_base,_rel,1)) != 0 )
    {
        if ( (tmpjson= cJSON_Parse(retstr)) != 0 )
        {
            aveprice = jdouble(tmpjson,"aveprice");
            retjson = cJSON_CreateObject();
            sprintf(baserel,"%s/%s",_base,_rel);
            jaddnum(retjson,baserel,aveprice);
            jaddstr(retjson,"result","success");
            free_json(tmpjson);
            return(jprint(retjson,1));
        } else return(clonestr("{\"error\":\"error parsing return from aveprice\"}"));
    } else return(clonestr("{\"error\":\"null return from aveprice\"}"));
}

THREE_STRINGS_AND_THREE_INTS(iguana,prices,exchange,base,rel,period,start,end)
{
    cJSON *retjson = cJSON_CreateObject();
    if ( period <= 0 )
        period = 60;
    if ( end <= 0 )
        end = (uint32_t)time(NULL);
    if ( start <= 0 || start >= end )
        start = end - 1024*period;
    jaddstr(retjson,"base",base);
    jaddstr(retjson,"rel",rel);
    jaddstr(retjson,"exchange",exchange[0] != 0 ? exchange : "all");
    jaddstr(retjson,"result","success");
    jaddnum(retjson,"start",start);
    jaddnum(retjson,"end",end);
    jaddnum(retjson,"period",period);
    jadd(retjson,"prices",iguana_pricesarray(myinfo,exchange,base,rel,period,start,end));
    return(jprint(retjson,1));
}

INT_AND_ARRAY(iguana,rates,unused,quotes)
{
    int32_t i,n,len,j,haveslash; char *retstr,*quote,base[64][64],rel[64][64],field[64]; double aveprice; cJSON *tmpjson,*item,*array=0,*retjson = cJSON_CreateObject();
#ifdef INCLUDE_PAX
    char *str; int32_t nonz;
    if ( myinfo->PEGS != 0 && (str= peggy_emitprices(&nonz,myinfo->PEGS,(uint32_t)time(NULL),PEGGY_MAXLOCKDAYS)) != 0 )
        free(str);
#endif
    if ( is_cJSON_Array(quotes) != 0 && (n= cJSON_GetArraySize(quotes)) > 0 )
    {
        if ( n > 64 )
        {
            jaddstr(retjson,"error","only 16 quotes at a time");
            return(jprint(retjson,1));
        }
        memset(base,0,sizeof(base));
        memset(rel,0,sizeof(rel));
        for (i=0; i<n; i++)
        {
            if ( (quote= jstri(quotes,i)) != 0 )
            {
                len = (int32_t)strlen(quote);
                if ( len >= 64 )
                {
                    if ( array != 0 )
                        free_json(array);
                    jaddstr(retjson,"error","quote too long");
                    return(jprint(retjson,1));
                }
                for (j=haveslash=0; j<len; j++)
                {
                    if ( quote[j] == '/' )
                    {
                        haveslash = 1;
                        if ( j > 0 && j < len-1 )
                        {
                            memcpy(base[i],quote,j);
                            base[i][j] = 0;
                            j++;
                            strcpy(rel[i],&quote[j]);
                            break;
                        }
                        else
                        {
                            if ( array != 0 )
                                free_json(array);
                            jaddstr(retjson,"error","no base error in quote item");
                            return(jprint(retjson,1));
                        }
                    }
                }
                if ( j < len || haveslash == 0 )
                {
                    if ( haveslash == 0 )
                        strcpy(base[i],quote);
                    aveprice = 0.;
                    if ( (retstr= tradebot_aveprice(myinfo,coin,json,remoteaddr,"",base[i],rel[i],1)) != 0 )
                    {
                        if ( (tmpjson= cJSON_Parse(retstr)) != 0 )
                        {
                            aveprice = jdouble(tmpjson,"aveprice");
                            //printf("(%s) ",jprint(tmpjson,0));
                            free_json(tmpjson);
                        } else printf("error parsing.(%s)\n",retstr);
                        if ( haveslash == 0 )
                            strcpy(field,base[i]);
                        else sprintf(field,"%s/%s",base[i],rel[i]);
                        item = cJSON_CreateObject();
                        jaddnum(item,field,aveprice);
                        if ( array == 0 )
                            array = cJSON_CreateArray();
                        jaddi(array,item);
                        free(retstr);
                        //printf(" <- aveprice %f\n",aveprice);
                    } else printf("no return from aveprice\n");
                }
                else
                {
                    if ( array != 0 )
                        free_json(array);
                    jaddstr(retjson,"error","syntax error in quote item");
                    return(jprint(retjson,1));
                }
            } else printf("i.%d of %d null quote\n",i,n);
        }
        jaddstr(retjson,"result","success");
        jadd(retjson,"rates",array);
    } else jaddstr(retjson,"error","no quotes array");
    return(jprint(retjson,1));
}
#include "../includes/iguana_apiundefs.h"
