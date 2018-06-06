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

// included from basilisk.c

// deposit address <coin> -> corresponding KMD address, if KMD deposit starts JUMBLR
// jumblr address <coin> is the destination of JUMBLR and JUMBLR BTC (would need tracking to map back to non-BTC)
// <symbol> address <coin> is DEX'ed for <SYMBOL>

// return value convention: -1 error, 0 partial match, >= 1 exact match

int32_t smartaddress_type(char *typestr)
{
    char upper[64];
    if ( strcmp(typestr,"deposit") != 0 && strcmp(typestr,"jumblr") != 0 && strcmp(typestr,"dividend") != 0 && strcmp(typestr,"pangea") != 0 )
    {
        upper[sizeof(upper)-1] = 0;
        strncpy(upper,typestr,sizeof(upper)-1);
        touppercase(upper);
        if ( iguana_coinfind(upper) != 0 )
            return(0);
        else return(-1);
    }
    return(1);
}

bits256 jumblr_privkey(struct supernet_info *myinfo,char *coinaddr,uint8_t pubtype,char *KMDaddr,char *prefix)
{
    bits256 privkey,pubkey; uint8_t pubkey33[33]; char passphrase[sizeof(myinfo->jumblr_passphrase) + 64];
    sprintf(passphrase,"%s%s",prefix,myinfo->jumblr_passphrase);
    if ( myinfo->jumblr_passphrase[0] == 0 )
        strcpy(myinfo->jumblr_passphrase,"password");
    conv_NXTpassword(privkey.bytes,pubkey.bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
    bitcoin_pubkey33(myinfo->ctx,pubkey33,privkey);
    bitcoin_address(coinaddr,pubtype,pubkey33,33);
    bitcoin_address(KMDaddr,60,pubkey33,33);
    //printf("(%s) -> (%s %s)\n",passphrase,coinaddr,KMDaddr);
    return(privkey);
}

cJSON *smartaddress_extrajson(struct smartaddress *ap)
{
    cJSON *retjson = cJSON_CreateObject();
    if ( strcmp(ap->typestr,"dividend") == 0 )
    {
        
    }
    return(retjson);
}

cJSON *smartaddress_json(struct smartaddress *ap)
{
    char coinaddr[64],symbol[64]; uint8_t desttype,tmp,rmd160[20]; int32_t j,n; struct iguana_info *coin,*dest; cJSON *array,*item,*retjson; double amount;
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"type",ap->typestr);
    strcpy(symbol,ap->typestr), touppercase(symbol);
    if ( (dest= iguana_coinfind(symbol)) != 0 )
        desttype = dest->chain->pubtype;
    else desttype = 60;
    if ( (n= ap->numsymbols) > 0 )
    {
        array = cJSON_CreateArray();
        for (j=0; j<n; j++)
        {
            if ( (coin= iguana_coinfind(ap->symbols[j].symbol)) != 0 )
            {
                bitcoin_address(coinaddr,coin->chain->pubtype,ap->pubkey33,33);
                item = cJSON_CreateObject();
                jaddstr(item,"coin",coin->symbol);
                jaddstr(item,"address",coinaddr);
                if ( (amount= ap->symbols[j].srcavail) != 0 )
                    jaddnum(item,"sourceamount",amount);
                if ( dest != 0 )
                {
                    bitcoin_addr2rmd160(&tmp,rmd160,coinaddr);
                    bitcoin_address(coinaddr,desttype,rmd160,20);
                    jaddstr(item,"dest",coinaddr);
                    if ( (amount= ap->symbols[j].destamount) != 0 )
                        jaddnum(item,"destamount",amount);
                    if ( coin->DEXinfo.depositaddr[0] != 0 )
                    {
                        jaddstr(item,"jumblr_deposit",coin->DEXinfo.depositaddr);
                        jaddnum(item,"deposit_avail",coin->DEXinfo.avail);
                    }
                    if ( coin->DEXinfo.jumblraddr[0] != 0 )
                    {
                        jaddstr(item,"jumblr",coin->DEXinfo.jumblraddr);
                        jaddnum(item,"jumblr_avail",coin->DEXinfo.jumblravail);
                    }
                    if ( ap->symbols[j].maxbid != 0. )
                        jaddnum(item,"maxbid",ap->symbols[j].maxbid);
                    if ( ap->symbols[j].minask != 0. )
                        jaddnum(item,"minask",ap->symbols[j].minask);
                }
                jadd(item,"extra",smartaddress_extrajson(ap));
                jaddi(array,item);
            }
        }
        jadd(retjson,"coins",array);
    }
    return(retjson);
}

void smartaddress_symboladd(struct smartaddress *ap,char *symbol,double maxbid,double minask)
{
    char tmp[64]; struct smartaddress_symbol *sp;
    strcpy(tmp,ap->typestr), touppercase(tmp);
    if ( strcmp(tmp,symbol) != 0 )
    {
        ap->symbols = realloc(ap->symbols,(ap->numsymbols+1) * sizeof(*ap->symbols));
        sp = &ap->symbols[ap->numsymbols++];
        memset(sp,0,sizeof(*sp));
        safecopy(sp->symbol,symbol,sizeof(sp->symbol));
        sp->maxbid = maxbid;
        sp->minask = minask;
        printf("symboladd.%d (%s) <- (%s %f %f)\n",ap->numsymbols,ap->typestr,symbol,maxbid,minask);
    }
}

struct smartaddress *smartaddressptr(struct smartaddress_symbol **ptrp,struct supernet_info *myinfo,char *_type,char *_symbol)
{
    char type[64],symbol[64]; int32_t i,j,n; struct smartaddress *ap;
    if ( ptrp != 0 )
        *ptrp = 0;
    strcpy(type,_type), tolowercase(type);
    strcpy(symbol,_symbol), touppercase(symbol);
    for (i=0; i<myinfo->numsmartaddrs; i++)
    {
        ap = &myinfo->smartaddrs[i];
        if ( strcmp(type,ap->typestr) == 0 )
        {
            n = ap->numsymbols;
            for (j=0; j<n; j++)
            {
                if ( strcmp(ap->symbols[j].symbol,symbol) == 0 )
                {
                    if ( ptrp != 0 )
                        *ptrp = &ap->symbols[j];
                    return(ap);
                }
            }
        }
    }
    return(0);
}

void smartaddress_minmaxupdate(struct supernet_info *myinfo,char *_type,char *_symbol,double maxbid,double minask)
{
    struct smartaddress *ap; struct smartaddress_symbol *sp;
    if ( (ap= smartaddressptr(&sp,myinfo,_type,_symbol)) != 0 && sp != 0 )
    {
        dxblend(&sp->maxbid,maxbid,0.5);
        dxblend(&sp->minask,minask,0.5);
    }
}

void smartaddress_availupdate(struct supernet_info *myinfo,char *_type,char *_symbol,double srcavail,double destamount)
{
    struct smartaddress *ap; struct smartaddress_symbol *sp;
    if ( (ap= smartaddressptr(&sp,myinfo,_type,_symbol)) != 0 && sp != 0 )
    {
        if ( srcavail > SMALLVAL )
            sp->srcavail = srcavail;
        if ( destamount > SMALLVAL )
            sp->destamount = destamount;
    }
}

int32_t _smartaddress_add(struct supernet_info *myinfo,bits256 privkey,char *type,char *symbol,double maxbid,double minask)
{
    char coinaddr[64]; uint8_t addrtype,rmd160[20]; struct smartaddress *ap; int32_t i,j,n;
    if ( myinfo->numsmartaddrs < sizeof(myinfo->smartaddrs)/sizeof(*myinfo->smartaddrs) )
    {
        for (i=0; i<myinfo->numsmartaddrs; i++)
        {
            ap = &myinfo->smartaddrs[i];
            if ( strcmp(type,ap->typestr) == 0 && bits256_cmp(ap->privkey,privkey) == 0 )
            {
                n = ap->numsymbols;
                for (j=0; j<n; j++)
                {
                    if ( strcmp(ap->symbols[j].symbol,symbol) == 0 )
                    {
                        ap->symbols[j].maxbid = maxbid;
                        ap->symbols[j].minask = minask;
                        if ( maxbid > SMALLVAL && minask > SMALLVAL && smartaddress_type(type) == 0 )
                            smartaddress_minmaxupdate(myinfo,symbol,type,1./minask,1./maxbid);
                        return(0);
                    }
                }
                smartaddress_symboladd(ap,symbol,maxbid,minask);
                return(i+1);
             }
        }
        ap = &myinfo->smartaddrs[myinfo->numsmartaddrs];
        if ( smartaddress_type(symbol) < 0 )
            return(-1);
        strcpy(ap->typestr,type);
        smartaddress_symboladd(ap,"KMD",0.,0.);
        smartaddress_symboladd(ap,"BTC",0.,0.);
        ap->privkey = privkey;
        bitcoin_pubkey33(myinfo->ctx,ap->pubkey33,privkey);
        calc_rmd160_sha256(ap->rmd160,ap->pubkey33,33);
        ap->pubkey = curve25519(privkey,curve25519_basepoint9());
        char str[65]; printf("pubkey.(%s) ",bits256_str(str,ap->pubkey));
        bitcoin_address(coinaddr,0,ap->pubkey33,33);
        for (i=0; i<20; i++)
            printf("%02x",ap->rmd160[i]);
        bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
        printf(", ");
        for (i=0; i<20; i++)
            printf("%02x",rmd160[i]);
        printf (" <- rmd160 for %d %s\n",myinfo->numsmartaddrs,coinaddr);
        return(++myinfo->numsmartaddrs + 1);
    }
    printf("too many smartaddresses %d vs %d\n",myinfo->numsmartaddrs,(int32_t)(sizeof(myinfo->smartaddrs)/sizeof(*myinfo->smartaddrs)));
    return(-1);
}

int32_t smartaddress_add(struct supernet_info *myinfo,bits256 privkey,char *type,char *symbol,double maxbid,double minask)
{
    int32_t retval;
    portable_mutex_lock(&myinfo->smart_mutex);
    retval = _smartaddress_add(myinfo,privkey,type,symbol,maxbid,minask);
    portable_mutex_unlock(&myinfo->smart_mutex);
    return(retval);
}

int32_t smartaddress_symbolmatch(char *typestr,double *bidaskp,struct smartaddress *ap,char *symbol)
{
    int32_t j,n;
    strcpy(typestr,ap->typestr);
    if ( (n= ap->numsymbols) > 0 )
    {
        for (j=0; j<n; j++)
        {
            if ( strcmp(ap->symbols[j].symbol,symbol) == 0 )
            {
                bidaskp[0] = ap->symbols[j].maxbid;
                bidaskp[1] = ap->symbols[j].minask;
                return(j);
            }
        }
    }
    return(-1);
}

int32_t smartaddress(struct supernet_info *myinfo,char *typestr,double *bidaskp,bits256 *privkeyp,char *symbol,char *coinaddr)
{
    int32_t i,j,retval = -1; uint8_t addrtype,rmd160[20]; struct smartaddress *ap;
    memset(privkeyp,0,sizeof(*privkeyp));
    memset(bidaskp,0,sizeof(*bidaskp) * 2);
    bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
    portable_mutex_lock(&myinfo->smart_mutex);
    for (i=0; i<myinfo->numsmartaddrs; i++)
        if ( memcmp(myinfo->smartaddrs[i].rmd160,rmd160,20) == 0 )
        {
            ap = &myinfo->smartaddrs[i];
            *privkeyp = ap->privkey;
            if ( (j= smartaddress_symbolmatch(typestr,bidaskp,ap,symbol)) >= 0 )
                retval = 0;
            else retval = (i+1);
            break;
        }
    portable_mutex_unlock(&myinfo->smart_mutex);
    for (i=0; i<20; i++)
        printf("%02x",rmd160[i]);
    printf(" <- rmd160 smartaddress cant find (%s) of %d\n",coinaddr,myinfo->numsmartaddrs);
    return(retval);
}

int32_t smartaddress_pubkey(struct supernet_info *myinfo,char *typestr,double *bidaskp,bits256 *privkeyp,char *symbol,bits256 pubkey)
{
    int32_t i,j,retval = -1; struct smartaddress *ap;
    memset(privkeyp,0,sizeof(*privkeyp));
    memset(bidaskp,0,sizeof(*bidaskp) * 2);
    if ( bits256_cmp(myinfo->myaddr.persistent,pubkey) == 0 )
    {
        *privkeyp = myinfo->persistent_priv;
        return(myinfo->numsmartaddrs);
    }
    portable_mutex_lock(&myinfo->smart_mutex);
    for (i=0; i<myinfo->numsmartaddrs; i++)
        if ( bits256_cmp(myinfo->smartaddrs[i].pubkey,pubkey) == 0 )
        {
            ap = &myinfo->smartaddrs[i];
            *privkeyp = ap->privkey;
            if ( (j= smartaddress_symbolmatch(typestr,bidaskp,ap,symbol)) >= 0 )
                retval = 0;
            else retval = (i+1);
            break;
        }
    portable_mutex_unlock(&myinfo->smart_mutex);
    //char str[65]; if ( retval < 0 )
    //    printf("smartaddress_pubkey no match for %s\n",bits256_str(str,pubkey));
    return(retval);
}

int32_t smartaddress_pubkey33(struct supernet_info *myinfo,char *typestr,double *bidaskp,bits256 *privkeyp,char *symbol,uint8_t *pubkey33)
{
    int32_t i,j,retval = -1; struct smartaddress *ap;
    memset(privkeyp,0,sizeof(*privkeyp));
    memset(bidaskp,0,sizeof(*bidaskp) * 2);
    portable_mutex_lock(&myinfo->smart_mutex);
    for (i=0; i<myinfo->numsmartaddrs; i++)
        if ( memcmp(myinfo->smartaddrs[i].pubkey33,pubkey33,33) == 0 )
        {
            ap = &myinfo->smartaddrs[i];
            *privkeyp = ap->privkey;
            if ( (j= smartaddress_symbolmatch(typestr,bidaskp,ap,symbol)) >= 0 )
                retval = 0;
            else retval = (i+1);
            break;
        }
    portable_mutex_unlock(&myinfo->smart_mutex);
    return(retval);
}

void smartaddress_CMCname(char *CMCname,char *symbol)
{
    if ( strcmp(symbol,"KMD") == 0 )
        strcpy(CMCname,"komodo");
    else if ( strcmp(symbol,"BTC") == 0 )
        strcpy(CMCname,"bitcoin");
}

void smartaddress_coinupdate(struct supernet_info *myinfo,char *symbol,double BTC2KMD,double KMDavail,double KMD2USD)
{
    int32_t r; double avebid,aveask,highbid,lowask,CMC_average,changes[3]; struct iguana_info *coin; struct DEXcoin_info *ptr;
    if ( (coin= iguana_coinfind(symbol)) != 0 )
    {
        ptr = &coin->DEXinfo;
        ptr->coin = coin;
        if ( coin->CMCname[0] == 0 )
            smartaddress_CMCname(coin->CMCname,symbol);
        r = (((symbol[0]^symbol[1]^symbol[2])&0x7f) % 15) - 7; // 53 to 67 seconds
        if ( time(NULL) > (ptr->lasttime + 60 + r) )
        {
            if ( strcmp(symbol,ptr->symbol) != 0 )
            {
                safecopy(ptr->symbol,symbol,sizeof(ptr->symbol));
                safecopy(ptr->CMCname,coin->CMCname,sizeof(ptr->CMCname));
            }
            ptr->deposit_privkey = jumblr_privkey(myinfo,ptr->depositaddr,coin->chain->pubtype,ptr->KMDdepositaddr,JUMBLR_DEPOSITPREFIX);
            ptr->jumblr_privkey = jumblr_privkey(myinfo,ptr->jumblraddr,coin->chain->pubtype,ptr->KMDjumblraddr,"");
            ptr->avail = dstr(jumblr_balance(myinfo,coin,ptr->depositaddr));
            ptr->jumblravail = dstr(jumblr_balance(myinfo,ptr->coin,ptr->jumblraddr));
            if ( strcmp(symbol,"USD") == 0 )
            {
                if ( KMD2USD > SMALLVAL )
                {
                    ptr->kmdprice = 1./ KMD2USD;
                    if ( (ptr->BTC2KMD= BTC2KMD) > SMALLVAL )
                        ptr->btcprice = ptr->kmdprice * BTC2KMD;
                }
                printf("USD btcprice %.8f kmdprice %.8f\n",ptr->btcprice,ptr->kmdprice);
            }
            else
            {
                if ( strcmp(symbol,"BTC") == 0 )
                    ptr->btcprice = 1.;
                else if ( coin->CMCname[0] != 0 && (ptr->btcprice == 0. || (ptr->counter++ % 10) == 0) )
                    ptr->btcprice = get_theoretical(&avebid,&aveask,&highbid,&lowask,&CMC_average,changes,coin->CMCname,symbol,"BTC",&ptr->USD_average);
                if ( strcmp("KMD",symbol) == 0 )
                    ptr->kmdprice = 1.;
                else if ( (ptr->BTC2KMD= BTC2KMD) > SMALLVAL )
                    ptr->kmdprice = ptr->btcprice / BTC2KMD;
            }
            ptr->lasttime = (uint32_t)time(NULL);
            printf("%s avail %.8f KMDavail %.8f btcprice %.8f deposit.(%s %s) -> jumblr.(%s %s)\n",symbol,ptr->avail,KMDavail,ptr->btcprice,ptr->depositaddr,ptr->KMDdepositaddr,ptr->jumblraddr,ptr->KMDjumblraddr);
        }
    } // else printf("skip\n");
}

void smartaddress_dex(struct supernet_info *myinfo,char *type,int32_t selector,struct iguana_info *basecoin,char *coinaddr,double maxavail,struct iguana_info *relcoin,double maxbid,double minask,cJSON *extraobj,double maxvol)
{
    double minamount,minbtc,price,avail,vol,btc2kmd,basebtc,relbtc,baseusd,relusd; char *retstr; cJSON *vals; bits256 hash; struct smartaddress *ap;
    basebtc = basecoin->DEXinfo.btcprice;
    relbtc = relcoin->DEXinfo.btcprice;
    baseusd = basecoin->DEXinfo.USD_average;
    relusd = relcoin->DEXinfo.USD_average;
    if ( (btc2kmd= basecoin->DEXinfo.BTC2KMD) < SMALLVAL && (btc2kmd= relcoin->DEXinfo.BTC2KMD) < SMALLVAL )
        return;
    minamount = price = 0.;
    if ( basebtc < SMALLVAL && relbtc < SMALLVAL )
        return;
    if ( myinfo->DEXratio < .95 || myinfo->DEXratio > 1.01 )
        myinfo->DEXratio = 0.995;
    if ( basebtc < SMALLVAL || relbtc < SMALLVAL )
    {
        if ( (price= maxbid) > SMALLVAL )
        {
            if ( basebtc < SMALLVAL )
                basebtc = price * relbtc, printf("calculated basebtc %.8f from (%.8f * %.8f)\n",basebtc,price,relbtc);
            else if ( relbtc < SMALLVAL )
                relbtc = basebtc / price, printf("calculated relbtc %.8f from (%.8f / %.8f)\n",relbtc,basebtc,price); // price * relbtc == basebtc
        }
    } else price = myinfo->DEXratio * (basebtc / relbtc);
    minbtc = btc2kmd * (JUMBLR_INCR + 3*(JUMBLR_INCR * JUMBLR_FEE + JUMBLR_TXFEE));
    if ( minamount == 0. && basebtc > SMALLVAL )
        minamount = (minbtc / basebtc);
    printf("DEX %s/%s maxavail %.8f minbtc %.8f btcprice %.8f -> minamount %.8f price %.8f vs maxbid %.8f DEXratio %.5f DEXpending %.8f\n",basecoin->symbol,relcoin->symbol,maxavail,minbtc,basecoin->DEXinfo.btcprice,minamount,price,maxbid,myinfo->DEXratio,basecoin->DEXinfo.DEXpending);
    if ( minamount > SMALLVAL && maxavail > minamount + basecoin->DEXinfo.DEXpending && (maxbid == 0. || price <= maxbid) )
    {
        avail = (maxavail - basecoin->DEXinfo.DEXpending);
        /*if ( avail >= (100. * minamount) )
            vol = (100. * minamount);
        else if ( avail >= (10. * minamount) )
            vol = (10. * minamount);
        else*/ if ( avail >= minamount )
            vol = minamount;
        else vol = 0.;
        if ( vol > 0. )
        {
            vals = cJSON_CreateObject();
            jaddstr(vals,"source",basecoin->symbol);
            jaddstr(vals,"dest",relcoin->symbol);
            jaddnum(vals,"amount",vol);
            jaddnum(vals,"minprice",price);
            if ( (ap= smartaddressptr(0,myinfo,type,basecoin->symbol)) != 0 )
                jaddbits256(vals,"srchash",ap->pubkey);
            if ( selector != 0 )
            {
                jaddnum(vals,"usejumblr",selector);
                jaddnum(vals,"DEXselector",selector);
            }
            memset(hash.bytes,0,sizeof(hash));
            basecoin->DEXinfo.DEXpending += vol;
            if ( (retstr= InstantDEX_request(myinfo,basecoin,0,0,hash,vals,"")) != 0 )
            {
                printf("request.(%s) -> (%s)\n",jprint(vals,0),retstr);
                free(retstr);
            }
            free_json(vals);
        } else printf("avail %.8f < minamount %.8f\n",avail,minamount);
    } //else printf("failed if check %d %d %d %d\n",minamount > SMALLVAL,maxavail > minamount + basecoin->DEXinfo.DEXpending,maxbid == 0,price <= maxbid);
    /*
    minbtc = (basecoin->DEXinfo.btcprice * 1.2) * (JUMBLR_INCR + 3*(JUMBLR_INCR * JUMBLR_FEE + JUMBLR_TXFEE));
    btcavail = dstr(jumblr_balance(myinfo,coinbtc,kmdcoin->DEXinfo.depositaddr));
    avail = (btcavail - coinbtc->DEXinfo.DEXpending);
    printf("BTC.%d deposits %.8f, min %.8f avail %.8f pending %.8f\n",toKMD,btcavail,minbtc,avail,coinbtc->DEXinfo.DEXpending);
    if ( toKMD == 0 && coinbtc != 0 && btcavail > (minbtc + coinbtc->DEXinfo.DEXpending) )
    {
        if ( vol > 0. )
        {
            vals = cJSON_CreateObject();
            jaddstr(vals,"source","BTC");
            jaddstr(vals,"dest","KMD");
            jaddnum(vals,"amount",vol);
            jaddnum(vals,"minprice",0.985/kmdcoin->DEXinfo.btcprice);
            jaddnum(vals,"usejumblr",1);
            jaddnum(vals,"DEXselector",1);
            memset(hash.bytes,0,sizeof(hash));
            coinbtc->DEXinfo.DEXpending += vol;
            if ( (retstr= InstantDEX_request(myinfo,coinbtc,0,0,hash,vals,"")) != 0 )
            {
                printf("request.(%s) -> (%s)\n",jprint(vals,0),retstr);
                free(retstr);
            }
            free_json(vals);
            // curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"InstantDEX\",\"method\":\"request\",\"vals\":{\"source\":\"KMD\",\"amount\":20,\"dest\":\"USD\",\"minprice\":0.08}}"
        }
    } //else printf("btcavail %.8f pending %.8f\n",btcavail,pending);
    minkmd = 100.;
    avail = (kmdcoin->DEXinfo.KMDavail - kmdcoin->DEXinfo.DEXpending);
    printf("KMD.%d deposits %.8f, min %.8f, avail %.8f  pending %.8f\n",toKMD,kmdcoin->DEXinfo.KMDavail,minkmd,avail,kmdcoin->DEXinfo.DEXpending);
    if ( toKMD != 0 && coinbtc != 0 && kmdcoin->DEXinfo.KMDavail > (minkmd + kmdcoin->DEXinfo.DEXpending) )
    {
        if ( avail > 100.*JUMBLR_INCR )
         vol = 100.*JUMBLR_INCR;
         else if ( avail > 10.*JUMBLR_INCR )
         vol = 10.*JUMBLR_INCR;
         else if ( avail >= JUMBLR_INCR )
             vol = JUMBLR_INCR;
         else vol = 0.;
        if ( vol > 0. )
        {
            vals = cJSON_CreateObject();
            jaddstr(vals,"source","KMD");
            jaddstr(vals,"dest","BTC");
            jaddnum(vals,"amount",vol);
            //jaddnum(vals,"destamount",JUMBLR_INCR*kmdcoin->DEXinfo.btcprice);
            jaddnum(vals,"minprice",0.985 * kmdcoin->DEXinfo.btcprice);
            jaddnum(vals,"usejumblr",2);
            memset(hash.bytes,0,sizeof(hash));
            kmdcoin->DEXinfo.DEXpending += vol;
            jaddnum(vals,"DEXselector",2);
            if ( (retstr= InstantDEX_request(myinfo,coinbtc,0,0,hash,vals,"")) != 0 )
            {
                printf("request.(%s) -> (%s)\n",jprint(vals,0),retstr);
                free(retstr);
            }
            free_json(vals);
        }
    } else printf("kmdavail %.8f pending %.8f\n",kmdcoin->DEXinfo.avail,kmdcoin->DEXinfo.DEXpending);*/
}

void smartaddress_depositjumblr(struct supernet_info *myinfo,char *symbol,char *coinaddr,double maxbid,double minask,cJSON *extraobj)
{
    struct iguana_info *basecoin,*relcoin;
    if ( (basecoin= iguana_coinfind(symbol)) != 0 && (relcoin= iguana_coinfind("KMD")) != 0 )
    {
        if ( strcmp(coinaddr,basecoin->DEXinfo.depositaddr) == 0 )
            smartaddress_dex(myinfo,"deposit",1,basecoin,coinaddr,basecoin->DEXinfo.avail,relcoin,maxbid,minask,extraobj,0.);
        else printf("smartaddress_jumblr.%s: mismatch deposit address (%s) vs (%s)\n",symbol,coinaddr,basecoin->DEXinfo.depositaddr);
    }
}

double smartaddress_jumblrcredit(struct supernet_info *myinfo,char *symbol)
{
    return(0.); // default to BTC conversion for now
}

void smartaddress_jumblr(struct supernet_info *myinfo,char *symbol,char *coinaddr,double maxbid,double minask,cJSON *extraobj)
{
    struct iguana_info *basecoin,*relcoin; double credits = 0.;
    if ( strcmp("BTC",symbol) != 0 )
    {
        if ( (credits= smartaddress_jumblrcredit(myinfo,symbol)) <= 0. )
            return;
    }
    if ( (basecoin= iguana_coinfind("KMD")) != 0 && (relcoin= iguana_coinfind(symbol)) != 0 )
    {
        if ( strcmp(coinaddr,basecoin->DEXinfo.jumblraddr) == 0 )
            smartaddress_dex(myinfo,"jumblr",2,basecoin,coinaddr,basecoin->DEXinfo.jumblravail,relcoin,maxbid,minask,extraobj,credits);
        else printf("smartaddress_jumblr.%s: mismatch jumblr address (%s) vs (%s)\n",symbol,coinaddr,basecoin->DEXinfo.jumblraddr);
    }
}

void smartaddress_dividend(struct supernet_info *myinfo,char *symbol,char *coinaddr,double maxbid,double minask,cJSON *extraobj)
{
    // support list of weighted addresses, including snapshots
}

void smartaddress_pangea(struct supernet_info *myinfo,char *symbol,char *coinaddr,double maxbid,double minask,cJSON *extraobj)
{
    // table deposit
}

void smartaddress_action(struct supernet_info *myinfo,int32_t selector,char *typestr,char *symbol,char *coinaddr,double maxbid,double minask,cJSON *extraobj)
{
    char rel[64]; struct iguana_info *basecoin,*relcoin; double avail;
    if ( strcmp(typestr,"deposit") == 0 && selector == 0 )
        smartaddress_depositjumblr(myinfo,symbol,coinaddr,maxbid,minask,extraobj);
    else if ( strcmp(typestr,"jumblr") == 0 && selector == 0 )
        smartaddress_jumblr(myinfo,symbol,coinaddr,maxbid,minask,extraobj);
    else if ( strcmp(typestr,"dividend") == 0 && selector == 0 )
        smartaddress_dividend(myinfo,symbol,coinaddr,maxbid,minask,extraobj);
    else if ( strcmp(typestr,"pangea") == 0 && selector == 0 )
        smartaddress_pangea(myinfo,symbol,coinaddr,maxbid,minask,extraobj);
    else
    {
        safecopy(rel,typestr,sizeof(rel));
        touppercase(rel);
        if ( (relcoin= iguana_coinfind(rel)) != 0 && (basecoin= iguana_coinfind(symbol)) != 0 )
        {
            if ( myinfo->numswaps == 0 )//|| (basecoin->FULLNODE < 0 && relcoin->FULLNODE < 0) )
            {
                if ( (avail= dstr(jumblr_balance(myinfo,basecoin,coinaddr))) > SMALLVAL )
                {
                    smartaddress_availupdate(myinfo,typestr,symbol,avail,SMALLVAL*0.99);
                    smartaddress_dex(myinfo,typestr,0,basecoin,coinaddr,avail,relcoin,maxbid,minask,extraobj,0.);
                }
            }
        }
    }
}

void smartaddress_update(struct supernet_info *myinfo,int32_t selector)
{
    double maxbid,minask; uint8_t addrtype,rmd160[20]; char *smartstr,*typestr,*symbol,*address,coinaddr[64]; cJSON *smartarray,*extraobj,*item,*array,*coinitem; int32_t iter,i,n,j,m; struct iguana_info *kmdcoin,*coinbtc = 0;
    //printf("smartaddress_update numswaps.%d notary.%d IAMLP.%d %p %p %f\n",myinfo->numswaps,myinfo->IAMNOTARY,myinfo->IAMLP,kmdcoin,coinbtc,kmdcoin->DEXinfo.btcprice);
    if ( myinfo->IAMNOTARY != 0 || myinfo->IAMLP != 0 || myinfo->secret[0] == 0 )
        return;
    kmdcoin = iguana_coinfind("KMD");
    coinbtc = iguana_coinfind("BTC");
    if ( kmdcoin == 0 || coinbtc == 0 )
        return;
    smartaddress_coinupdate(myinfo,"KMD",0.,0.,0.); // must be first
    if ( kmdcoin->DEXinfo.btcprice > SMALLVAL )
    {
        if ( (smartstr= InstantDEX_smartaddresses(myinfo,0,0,0)) != 0 )
        {
            if ( (smartarray= cJSON_Parse(smartstr)) != 0 )
            {
                if ( (n= cJSON_GetArraySize(smartarray)) > 0 )
                {
                    for (iter=0; iter<2; iter++)
                    {
                        for (i=0; i<n; i++)
                        {
                            item = jitem(smartarray,i);
                            if ( (typestr= jstr(item,"type")) != 0 && (array= jarray(&m,item,"coins")) != 0 )
                            {
                                for (j=0; j<m; j++)
                                {
                                    coinitem = jitem(array,j);
                                    if ( (symbol= jstr(coinitem,"coin")) == 0 )
                                        continue;
                                    if ( iter == 0 )
                                        smartaddress_coinupdate(myinfo,symbol,kmdcoin->DEXinfo.btcprice,kmdcoin->DEXinfo.avail,kmdcoin->DEXinfo.USD_average);
                                    else
                                    {
                                        printf("Action.%s (%s)\n",typestr,jprint(coinitem,0));
                                        if ( (address= jstr(coinitem,"address")) != 0 )
                                        {
                                            if ( strcmp(typestr,"jumblr") == 0 )
                                            {
                                                bitcoin_addr2rmd160(&addrtype,rmd160,address);
                                                bitcoin_address(coinaddr,kmdcoin->chain->pubtype,rmd160,20);
                                            } else strcpy(coinaddr,address);
                                            maxbid = jdouble(coinitem,"maxbid");
                                            minask = jdouble(coinitem,"minask");
                                            extraobj = jobj(coinitem,"extra");
                                            smartaddress_action(myinfo,selector,typestr,symbol,coinaddr,maxbid,minask,extraobj);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                free_json(smartarray);
            }
            free(smartstr);
        }
    }
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"
#include "../includes/iguana_apideclares2.h"

ZERO_ARGS(InstantDEX,smartaddresses)
{
    int32_t i; cJSON *retjson = cJSON_CreateArray();
    portable_mutex_lock(&myinfo->smart_mutex);
    for (i=0; i<myinfo->numsmartaddrs; i++)
        jaddi(retjson,smartaddress_json(&myinfo->smartaddrs[i]));
    portable_mutex_unlock(&myinfo->smart_mutex);
    return(jprint(retjson,1));
}

TWO_STRINGS_AND_TWO_DOUBLES(InstantDEX,smartaddress,type,symbol,maxbid,minask)
{
    char prefix[64],coinaddr[64],KMDaddr[64],typestr[64]; double bidask[2]; uint8_t pubkey33[33]; bits256 privkey;
    if ( smartaddress_type(type) < 0 )
        return(clonestr("{\"error\":\"non-supported smartaddress type\"}"));
    if ( iguana_coinfind(symbol) == 0 )
        return(clonestr("{\"error\":\"non-supported smartaddress symbol\"}"));
    if ( strcmp(type,"deposit") == 0 || strcmp(type,"jumblr") == 0 )
    {
        if ( smartaddress_pubkey(myinfo,typestr,bidask,&privkey,symbol,strcmp(type,"deposit") == 0 ? myinfo->jumblr_depositkey : myinfo->jumblr_pubkey) < 0 )
            return(clonestr("{\"error\":\"unexpected missing smartaddress deposit/jumblr\"}"));
    }
    else
    {
        strcpy(prefix,type);
        tolowercase(prefix);
        if ( strcmp(prefix,"btc") == 0 || strcmp(prefix,"kmd") == 0 )
            return(clonestr("{\"success\":\"no need add BTC or KMD to smartaddress\"}"));
        strcat(prefix," ");
        privkey = jumblr_privkey(myinfo,coinaddr,0,KMDaddr,prefix);
    }
    if ( (coin= iguana_coinfind(symbol)) == 0 )
        return(clonestr("{\"error\":\"non-supported smartaddress symbol\"}"));
    bitcoin_pubkey33(myinfo->ctx,pubkey33,privkey);
    bitcoin_address(coinaddr,coin->chain->pubtype,pubkey33,33);
    smartaddress_add(myinfo,privkey,type,symbol,maxbid,minask);
    return(InstantDEX_smartaddresses(myinfo,0,0,0));
}

#include "../includes/iguana_apiundefs.h"
