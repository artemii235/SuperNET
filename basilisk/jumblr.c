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
// connect DEX to jumblr-core

/*
 z_exportkey "zaddr"
 z_exportwallet "filename"
 z_getoperationstatus (["operationid", ... ])
 z_gettotalbalance ( minconf )
 z_importkey "zkey" ( rescan )
 z_importwallet "filename"
 z_listaddresses
 z_sendmany "fromaddress" [{"address":... ,"amount":..., "memo":"<hex>"},...] ( minconf ) ( fee )
 */

#define JUMBLR_ADDR "RGhxXpXSSBTBm9EvNsXnTQczthMCxHX91t"
#define JUMBLR_BTCADDR "18RmTJe9qMech8siuhYfMtHo8RtcN1obC6"

int32_t jumblr_addresstype(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    if ( strcmp(coin->symbol,"KMD") == 0 )
    {
        if ( addr[0] == 'z' && addr[1] == 'c' && strlen(addr) >= 40 )
            return('z');
        else if ( strlen(addr) < 40 )
            return('t');
        else return(-1);
    } else return('t');
}

struct jumblr_item *jumblr_opidfind(struct supernet_info *myinfo,char *opid)
{
    struct jumblr_item *ptr;
    HASH_FIND(hh,myinfo->jumblrs,opid,(int32_t)strlen(opid),ptr);
    return(ptr);
}

struct jumblr_item *jumblr_opidadd(struct supernet_info *myinfo,struct iguana_info *coin,char *opid)
{
    struct jumblr_item *ptr;
    if ( (ptr= jumblr_opidfind(myinfo,opid)) == 0 )
    {
        ptr = calloc(1,sizeof(*ptr));
        safecopy(ptr->opid,opid,sizeof(ptr->opid));
        HASH_ADD_KEYPTR(hh,myinfo->jumblrs,ptr->opid,(int32_t)strlen(ptr->opid),ptr);
        if ( ptr != jumblr_opidfind(myinfo,opid) )
            printf("jumblr_opidadd.(%s) ERROR, couldnt find after add\n",opid);
    }
    return(ptr);
}

char *jumblr_validateaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    char params[1024];
    if ( coin->FULLNODE < 0 )
    {
        sprintf(params,"[\"%s\"]",addr);
        return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"validateaddress",params));
    } else return(_dex_validateaddress(myinfo,coin->symbol,addr));
}

int32_t jumblr_ismine(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    char params[1024],*retstr; cJSON *retjson,*obj; int32_t retval = -1;
    sprintf(params,"[\"%s\"]",addr);
    if ( (retstr= jumblr_validateaddress(myinfo,coin,addr)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (obj= jobj(retjson,"ismine")) != 0 && is_cJSON_True(obj) != 0 )
                retval = 1;
            else retval = 0;
            free_json(retjson);
        }
        free(retstr);
    }
    return(retval);
}

char *jumblr_zgetnewaddress(struct supernet_info *myinfo,struct iguana_info *coin)
{
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_getnewaddress",""));
}

char *jumblr_zlistoperationids(struct supernet_info *myinfo,struct iguana_info *coin)
{
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_listoperationids",""));
}

char *jumblr_zgetoperationresult(struct supernet_info *myinfo,struct iguana_info *coin,char *opid)
{
    char params[1024];
    sprintf(params,"[[\"%s\"]]",opid);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_getoperationresult",params));
}

char *jumblr_zgetoperationstatus(struct supernet_info *myinfo,struct iguana_info *coin,char *opid)
{
    char params[1024];
    sprintf(params,"[[\"%s\"]]",opid);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_getoperationstatus",params));
}

char *jumblr_sendt_to_z(struct supernet_info *myinfo,struct iguana_info *coin,char *taddr,char *zaddr,double amount)
{
    char params[1024]; double fee = (amount-3*JUMBLR_TXFEE) * JUMBLR_FEE;
    if ( jumblr_addresstype(myinfo,coin,zaddr) != 'z' || jumblr_addresstype(myinfo,coin,taddr) != 't' )
        return(clonestr("{\"error\":\"illegal address in t to z\"}"));
    sprintf(params,"[\"%s\", [{\"address\":\"%s\",\"amount\":%.8f}, {\"address\":\"%s\",\"amount\":%.8f}], 1, %.8f]",taddr,zaddr,amount-fee-JUMBLR_TXFEE,JUMBLR_ADDR,fee,JUMBLR_TXFEE);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_sendmany",params));
}

char *jumblr_sendz_to_z(struct supernet_info *myinfo,struct iguana_info *coin,char *zaddrS,char *zaddrD,double amount)
{
    char params[1024]; double fee = (amount-2*JUMBLR_TXFEE) * JUMBLR_FEE;
    if ( jumblr_addresstype(myinfo,coin,zaddrS) != 'z' || jumblr_addresstype(myinfo,coin,zaddrD) != 'z' )
        return(clonestr("{\"error\":\"illegal address in z to z\"}"));
    sprintf(params,"[\"%s\", [{\"address\":\"%s\",\"amount\":%.8f}, {\"address\":\"%s\",\"amount\":%.8f}], 1, %.8f]",zaddrS,zaddrD,amount-fee-JUMBLR_TXFEE,JUMBLR_ADDR,fee,JUMBLR_TXFEE);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_sendmany",params));
}

char *jumblr_sendz_to_t(struct supernet_info *myinfo,struct iguana_info *coin,char *zaddr,char *taddr,double amount)
{
    char params[1024]; double fee = (amount-JUMBLR_TXFEE) * JUMBLR_FEE;
    if ( jumblr_addresstype(myinfo,coin,zaddr) != 'z' || jumblr_addresstype(myinfo,coin,taddr) != 't' )
        return(clonestr("{\"error\":\"illegal address in z to t\"}"));
    sprintf(params,"[\"%s\", [{\"address\":\"%s\",\"amount\":%.8f}, {\"address\":\"%s\",\"amount\":%.8f}], 1, %.8f]",zaddr,taddr,amount-fee-JUMBLR_TXFEE,JUMBLR_ADDR,fee,JUMBLR_TXFEE);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_sendmany",params));
}

char *jumblr_zlistreceivedbyaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    char params[1024];
    sprintf(params,"[\"%s\", 1]",addr);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_listreceivedbyaddress",params));
}

char *jumblr_getreceivedbyaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    char params[1024];
    sprintf(params,"[\"%s\", 1]",addr);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getreceivedbyaddress",params));
}

char *jumblr_importprivkey(struct supernet_info *myinfo,struct iguana_info *coin,char *wifstr)
{
    char params[1024];
    sprintf(params,"[\"%s\", \"\", false]",wifstr);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"importprivkey",params));
}

char *jumblr_zgetbalance(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    char params[1024];
    sprintf(params,"[\"%s\", 1]",addr);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"z_getbalance",params));
}

char *jumblr_listunspent(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    char params[1024];
    if ( coin->FULLNODE == 0 )
        return(dex_listunspent(myinfo,coin,0,0,coin->symbol,coinaddr));
    sprintf(params,"[1, 99999999, [\"%s\"]]",coinaddr);
    return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"listunspent",params));
}

int64_t jumblr_receivedby(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    char *retstr; int64_t total = 0;
    if ( (retstr= jumblr_getreceivedbyaddress(myinfo,coin,addr)) != 0 )
    {
        total = atof(retstr) * SATOSHIDEN;
        free(retstr);
    }
    return(total);
}

int64_t jumblr_balance(struct supernet_info *myinfo,struct iguana_info *coin,char *addr)
{
    char *retstr; double val; cJSON *retjson; int32_t i,n; int64_t balance = 0;
    if ( jumblr_addresstype(myinfo,coin,addr) == 't' )
    {
        if ( coin->FULLNODE < 0 && iguana_isnotarychain(coin->symbol) < 0 )
        {
            if ( (retstr= jumblr_listunspent(myinfo,coin,addr)) != 0 )
            {
                printf("jumblr.[%s].(%s)\n",coin->symbol,retstr);
                if ( (retjson= cJSON_Parse(retstr)) != 0 )
                {
                    if ( (n= cJSON_GetArraySize(retjson)) > 0 )
                        for (i=0; i<n; i++)
                            balance += SATOSHIDEN * jdouble(jitem(retjson,i),"amount");
                    free_json(retjson);
                }
                free(retstr);
            }
        }
        else if ( (retstr= dex_getbalance(myinfo,coin,0,0,coin->symbol,addr)) != 0 )
        {
            //printf("DEX retstr.(%s)\n",retstr);
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                balance = jdouble(retjson,"balance") * SATOSHIDEN;
                //printf("GOT BALANCE %s %.8f\n",coin->symbol,dstr(balance));
                free_json(retjson);
            }
            free(retstr);
        }
    }
    else if ( (retstr= jumblr_zgetbalance(myinfo,coin,addr)) != 0 )
    {
        if ( (val= atof(retstr)) > SMALLVAL )
            balance = val * SATOSHIDEN;
        free(retstr);
    }
    return(balance);
}

int32_t jumblr_itemset(struct jumblr_item *ptr,cJSON *item,char *status)
{
    cJSON *params,*amounts,*dest; char *from,*addr; int32_t i,n; int64_t amount;
    /*"params" : {
     "fromaddress" : "RDhEGYScNQYetCyG75Kf8Fg61UWPdwc1C5",
     "amounts" : [
     {
     "address" : "zc9s3UdkDFTnnwHrMCr1vYy2WmkjhmTxXNiqC42s7BjeKBVUwk766TTSsrRPKfnX31Bbu8wbrTqnjDqskYGwx48FZMPHvft",
     "amount" : 3.00000000
     }
     ],
     "minconf" : 1,
     "fee" : 0.00010000
     }*/
    if ( (params= jobj(item,"params")) != 0 )
    {
        //printf("params.(%s)\n",jprint(params,0));
        if ( (from= jstr(params,"fromaddress")) != 0 )
        {
            safecopy(ptr->src,from,sizeof(ptr->src));
        }
        if ( (amounts= jarray(&n,params,"amounts")) != 0 )
        {
            for (i=0; i<n; i++)
            {
                dest = jitem(amounts,i);
                //printf("%s ",jprint(dest,0));
                if ( (addr= jstr(dest,"address")) != 0 && (amount= jdouble(dest,"amount")*SATOSHIDEN) > 0 )
                {
                    if ( strcmp(addr,JUMBLR_ADDR) == 0 )
                        ptr->fee = amount;
                    else
                    {
                        ptr->amount = amount;
                        safecopy(ptr->dest,addr,sizeof(ptr->dest));
                    }
                }
            }
        }
        ptr->txfee = jdouble(params,"fee") * SATOSHIDEN;
    }
    return(1);
}

void jumblr_opidupdate(struct supernet_info *myinfo,struct iguana_info *coin,struct jumblr_item *ptr)
{
    char *retstr,*status,KMDjumblr[64],KMDdeposit[64],BTCaddr[64]; cJSON *retjson,*item;
    if ( ptr->status == 0 )
    {
        if ( (retstr= jumblr_zgetoperationstatus(myinfo,coin,ptr->opid)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( cJSON_GetArraySize(retjson) == 1 )
                {
                    item = jitem(retjson,0);
                    //printf("%s\n",jprint(item,0));
                    if ( (status= jstr(item,"status")) != 0 )
                    {
                        if ( strcmp(status,"success") == 0 )
                        {
                            ptr->status = jumblr_itemset(ptr,item,status);
                            jumblr_privkey(myinfo,BTCaddr,0,KMDdeposit,JUMBLR_DEPOSITPREFIX);
                            jumblr_privkey(myinfo,BTCaddr,0,KMDjumblr,"");
                            if ( (jumblr_addresstype(myinfo,coin,ptr->src) == 't' && jumblr_addresstype(myinfo,coin,ptr->src) == 'z' && strcmp(ptr->src,KMDdeposit) != 0) || (jumblr_addresstype(myinfo,coin,ptr->src) == 'z' && jumblr_addresstype(myinfo,coin,ptr->src) == 't' && strcmp(ptr->dest,KMDjumblr) != 0) )
                            {
                                printf("a non-jumblr t->z pruned\n");
                                free(jumblr_zgetoperationresult(myinfo,coin,ptr->opid));
                                ptr->status = -1;
                            }

                        }
                        else if ( strcmp(status,"failed") == 0 )
                        {
                            printf("%s failed\n",ptr->opid);
                            free(jumblr_zgetoperationresult(myinfo,coin,ptr->opid));
                            ptr->status = -1;
                        }
                    }
                }
                free_json(retjson);
            }
            free(retstr);
        }
    }
}

void jumblr_prune(struct supernet_info *myinfo,struct iguana_info *coin,struct jumblr_item *ptr)
{
    struct jumblr_item *tmp; char oldsrc[128]; int32_t flag = 1;
    printf("PRUNE %s\n",ptr->opid);
    strcpy(oldsrc,ptr->src);
    free(jumblr_zgetoperationresult(myinfo,coin,ptr->opid));
    while ( flag != 0 )
    {
        flag = 0;
        HASH_ITER(hh,myinfo->jumblrs,ptr,tmp)
        {
            if ( strcmp(oldsrc,ptr->dest) == 0 )
            {
                printf("prune %s (%s -> %s) matched oldsrc\n",ptr->opid,ptr->src,ptr->dest);
                free(jumblr_zgetoperationresult(myinfo,coin,ptr->opid));
                strcpy(oldsrc,ptr->src);
                flag = 1;
                break;
            }
        }
    }
}

void jumblr_opidsupdate(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char *retstr; cJSON *array; int32_t i,n; struct jumblr_item *ptr;
    if ( (retstr= jumblr_zlistoperationids(myinfo,coin)) != 0 )
    {
        if ( (array= cJSON_Parse(retstr)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (ptr= jumblr_opidadd(myinfo,coin,jstri(array,i))) != 0 )
                    {
                        if ( ptr->status == 0 )
                            jumblr_opidupdate(myinfo,coin,ptr);
                        //printf("%d: %s -> %s %.8f\n",ptr->status,ptr->src,ptr->dest,dstr(ptr->amount));
                        if ( jumblr_addresstype(myinfo,coin,ptr->src) == 'z' && jumblr_addresstype(myinfo,coin,ptr->dest) == 't' )
                            jumblr_prune(myinfo,coin,ptr);
                    }
                }
            }
            free_json(array);
        }
        free(retstr);
    }
}

int64_t jumblr_DEXsplit(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *splittxidp,char *coinaddr,bits256 txid,int32_t vout,int64_t remaining,double bigprice,double middleprice,double smallprice,double fees[4],cJSON *privkeys,double esttxfee)
{
    int64_t values[4],outputs[64],value,total,estfee; int32_t i,n,success=0,completed,sendflag,numoutputs = 0; char *retstr; cJSON *retjson,*utxo,*item;
    total = 0;
    estfee = SATOSHIDEN * esttxfee;
    memset(values,0,sizeof(values));
    memset(outputs,0,sizeof(outputs));
    if ( bigprice > SMALLVAL )
        values[0] = SATOSHIDEN * bigprice;
    if ( middleprice > SMALLVAL )
        values[1] = SATOSHIDEN * middleprice;
    if ( smallprice > SMALLVAL )
        values[2] = SATOSHIDEN * smallprice;
    for (i=0; i<4; i++)
    {
        if ( fees[i] > SMALLVAL )
            values[3+i] = SATOSHIDEN * fees[i];
    }
    for (i=0; i<7; i++)
    {
        if ( (value= values[i]) != 0 )
        {
            n = 0;
            while ( n < 10 && remaining > value && numoutputs < sizeof(outputs)/sizeof(*outputs) )
            {
                outputs[numoutputs++] = value;
                remaining -= value;
                total += value;
                printf("%.8f ",dstr(value));
                n++;
            }
        }
    }
    char str[65]; printf("numoutputs.%d total %.8f %s/v%d\n",numoutputs,dstr(total),bits256_str(str,txid),vout);
    if ( numoutputs > 1 ) // no point to make just one
    {
        if ( (retstr= _dex_gettxout(myinfo,coin->symbol,txid,vout)) != 0 )
        {
            item = cJSON_Parse(retstr);
            jaddbits256(item,"txid",txid);
            jaddnum(item,"vout",vout);
            free(retstr);
            if ( item != 0 )
            {
                utxo = cJSON_CreateArray();
                jaddi(utxo,item);
                sendflag = 0;
                ///printf("jitem.(%s)\n",jprint(utxo,0));
                if ( (retstr= iguana_utxorawtx(myinfo,coin,0,coinaddr,coinaddr,outputs,numoutputs,0,&completed,sendflag,utxo,privkeys)) != 0 )
                {
                    if ( completed != 0 )
                    {
                        if ( (retjson= cJSON_Parse(retstr)) != 0 )
                        {
                            if ( jobj(retjson,"error") == 0 && jobj(retjson,"sent") != 0 )
                            {
                                *splittxidp = jbits256(retjson,"sent");
                                success = 1;
                                printf("DEXsplit success %.8f\n",dstr(total));
                            }
                            free_json(retjson);
                        }
                    }
                    free(retstr);
                }
                free_json(utxo);
            }
        }
    }
    return(success * total);
}

double jumblr_DEXutxosize(double *targetvolBp,double *targetvolMp,double *targetvolSp,int32_t isbob,double kmdprice)
{
    double fee,depositfactor = (isbob == 0) ? 1. : 1.2;
    fee = JUMBLR_INCR * JUMBLR_FEE;
    *targetvolBp = depositfactor * kmdprice * ((JUMBLR_INCR + 3*fee)*100 + 3*JUMBLR_TXFEE);
    *targetvolMp = depositfactor * kmdprice * ((JUMBLR_INCR + 3*fee)*10 + 3*JUMBLR_TXFEE);
    *targetvolSp = depositfactor * kmdprice * ((JUMBLR_INCR + 3*fee) + 3*JUMBLR_TXFEE);
    return(depositfactor);
}

int32_t jumblr_DEXutxoind(int32_t *shouldsplitp,double targetvolB,double targetvolM,double targetvolS,double amount,double margin,double dexfeeratio,double esttxfee)
{
    *shouldsplitp = 0;
    if ( amount >= targetvolB )
    {
        if ( amount > margin * (targetvolB + targetvolS) )
            *shouldsplitp = 1;
        return(0);
    }
    else
    {
        if ( amount >= targetvolM )
        {
            if ( amount > margin * (targetvolM + targetvolS) )
                *shouldsplitp = 1;
            return(1);
        }
        else
        {
            if ( amount >= targetvolS )
            {
                if ( amount > margin * targetvolS )
                    *shouldsplitp = 1;
                return(2);
            }
            else if ( amount >= targetvolB/dexfeeratio )
            {
                if ( amount > margin * targetvolB/dexfeeratio )
                    *shouldsplitp = 1;
                return(3);
            }
            else if ( amount >= targetvolM/dexfeeratio )
            {
                if ( amount > margin * targetvolM/dexfeeratio )
                    *shouldsplitp = 1;
                return(4);
            }
            else if ( amount >= targetvolS/dexfeeratio )
            {
                if ( amount > margin * targetvolS/dexfeeratio )
                    *shouldsplitp = 1;
                return(5);
            }
            else if ( amount >= esttxfee )
            {
                if ( amount > esttxfee*4 )
                    *shouldsplitp = 1;
                return(6);
            }
            else return(-1);
        }
    }
}

int32_t jumblr_DEXutxoupdate(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *shouldsplitp,bits256 *splittxidp,char *coinaddr,bits256 privkey,bits256 txid,int32_t vout,uint64_t value,int32_t isbob,double kmdprice,double estfee)
{
    double fees[4],targetvolB,amount,targetvolM,targetvolS,depositfactor,dexfeeratio,margin; int32_t ind = -1,i; cJSON *privkeys; char wifstr[128];
    *shouldsplitp = 0;
    margin = 1.1;
    depositfactor = (isbob == 0) ? 1. : 1.2;
    dexfeeratio = 500.;
    amount = dstr(value);
    memset(splittxidp,0,sizeof(*splittxidp));
    depositfactor = jumblr_DEXutxosize(&targetvolB,&targetvolM,&targetvolS,isbob,kmdprice);
    printf("depositfactor %.8f targetvols %.8f %.8f %.8f\n",depositfactor,targetvolB,targetvolM,targetvolS);
    fees[0] = (margin * targetvolB) / dexfeeratio;
    fees[1] = (margin * targetvolM) / dexfeeratio;
    fees[2] = (margin * targetvolS) / dexfeeratio;
    fees[3] = (strcmp("BTC",coin->symbol) == 0) ? 50000 : 10000;
    for (i=0; i<4; i++)
        if ( fees[i] < 10000 )
            fees[i] = 10000;
    if ( (ind= jumblr_DEXutxoind(shouldsplitp,targetvolB,targetvolM,targetvolS,amount,margin,dexfeeratio,fees[3])) >= 0 )
    {
        printf("shouldsplit.%d ind.%d\n",*shouldsplitp,ind);
        if ( *shouldsplitp != 0 )
        {
            privkeys = cJSON_CreateArray();
            bitcoin_priv2wif(wifstr,privkey,coin->chain->wiftype);
            jaddistr(privkeys,wifstr);
            if ( jumblr_DEXsplit(myinfo,coin,splittxidp,coinaddr,txid,vout,value,margin * targetvolB,margin * targetvolM,margin * targetvolS,fees,privkeys,estfee) > 0 )
                ind = -1;
            else *shouldsplitp = 0;
            free_json(privkeys);
        }
    } // else printf("negative ind\n");
    return(ind);
}

/*struct DEXcoin_info
 {
 bits256 deposit_privkey,jumblr_privkey;
 struct iguana_info *coin;
 cJSON *utxos,*spentutxos,*bigutxos,*normalutxos,*smallutxos,*feeutxos,*otherutxos;
 double btcprice,USD_average,DEXpending,maxbid,minask,avail,KMDavail;
 uint32_t lasttime;
 char CMCname[32],symbol[16],depositaddr[64],KMDdepositaddr[64],KMDjumblraddr[64],jumblraddr[64];
 };*/

int32_t jumblr_utxotxidpending(struct supernet_info *myinfo,bits256 *splittxidp,int32_t *indp,struct iguana_info *coin,bits256 txid,int32_t vout)
{
    int32_t i;
    memset(splittxidp,0,sizeof(*splittxidp));
    for (i=0; i<coin->DEXinfo.numpending; i++)
    {
        if ( coin->DEXinfo.pending[i].vout == vout && bits256_cmp(coin->DEXinfo.pending[i].txid,txid) == 0 )
        {
            *indp = coin->DEXinfo.pending[i].ind;
            *splittxidp = coin->DEXinfo.pending[i].splittxid;
            // printf("jumblr_utxotxidpending found txid in slot.%d\n",i);
            return(i);
        }
    }
    // printf("jumblr_utxotxidpending cant find txid\n");
    return(-1);
}

void jumblr_utxotxidpendingadd(struct supernet_info *myinfo,char *dest,struct iguana_info *coin,bits256 txid,int32_t vout,uint64_t value,bits256 splittxid,int32_t ind,double price,double estfee,int32_t shouldsplit)
{
    struct jumblr_pending pend; cJSON *vals,*retjson; bits256 hash; char *retstr;
    memset(&pend,0,sizeof(pend));
    pend.splittxid = splittxid;
    pend.txid = txid;
    pend.vout = vout;
    pend.ind = ind;
    if ( 0 && myinfo->IAMLP == 0 && shouldsplit == 0 && ind < 3 )
    {
        static uint32_t num;
        if ( num == 0 && price > SMALLVAL )
        {
            num++;
            vals = cJSON_CreateObject();
            jaddstr(vals,"source",coin->symbol);
            jaddstr(vals,"dest",dest);
            jaddnum(vals,"amount",price * 100);//dstr(value) - estfee);
            jaddnum(vals,"minprice",price);
            jaddnum(vals,"usejumblr",1);
            memset(hash.bytes,0,sizeof(hash));
            if ( (retstr= InstantDEX_request(myinfo,coin,0,0,hash,vals,"")) != 0 )
            {
                if ( (retjson= cJSON_Parse(retstr)) != 0 )
                {
                    printf("request.(%s) -> (%s)\n",jprint(vals,0),retstr);
                    free_json(retjson);
                }
                free(retstr);
            }
            free_json(vals);
        }
    }
    coin->DEXinfo.pending = realloc(coin->DEXinfo.pending,sizeof(*coin->DEXinfo.pending) * (1 + coin->DEXinfo.numpending));
    coin->DEXinfo.pending[coin->DEXinfo.numpending++] = pend;
}

void jumblr_utxoupdate(struct supernet_info *myinfo,char *dest,struct iguana_info *coin,double price,char *coinaddr,bits256 privkey,double estfee)
{
    char *retstr; cJSON *array,*item; int32_t shouldsplit,i,n,vout,ind; bits256 txid,splittxid; uint64_t value;
    if ( (retstr= jumblr_listunspent(myinfo,coin,coinaddr)) != 0 )
    {
        //printf("%s.(%s)\n",coin->symbol,retstr);
        if ( (array= cJSON_Parse(retstr)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (item= jitem(array,i)) == 0 )
                        continue;
                    txid = jbits256(item,"txid");
                    vout = jint(item,"vout");
                    value = SATOSHIDEN * jdouble(item,"amount");
                    //printf("price %.8f %llx/v%d %.8f %d of %d\n",price,(long long)txid.txid,vout,dstr(value),i,n);
                    if ( jumblr_utxotxidpending(myinfo,&splittxid,&ind,coin,txid,vout) < 0 )
                    {
                        ind = jumblr_DEXutxoupdate(myinfo,coin,&shouldsplit,&splittxid,coinaddr,privkey,txid,vout,value,myinfo->IAMLP,price,estfee);
                        jumblr_utxotxidpendingadd(myinfo,dest,coin,txid,vout,value,splittxid,ind,price,estfee,shouldsplit);
                    }
                    else
                    {
                        // update status of utxo
                    }
                }
            }
            free_json(array);
        }
        free(retstr);
    }
}

void jumblr_iteration(struct supernet_info *myinfo,struct iguana_info *coin,int32_t selector,int32_t modval)
{
    //static uint32_t lasttime;
    char BTCaddr[64],KMDaddr[64],*zaddr,*retstr; int32_t iter,counter,chosen_one,n; bits256 privkey; uint64_t amount=0,total=0; double fee; struct jumblr_item *ptr,*tmp; uint8_t r,s;
    if ( myinfo->IAMNOTARY != 0 )
        return;
    fee = JUMBLR_INCR * JUMBLR_FEE;
    OS_randombytes(&r,sizeof(r));
//r = 0;
    // randomize size chosen and order of chunks
    if ( strcmp(coin->symbol,"KMD") == 0 && coin->FULLNODE < 0 )
    {
        s = (selector + (r>>1)) % 3;
        //printf("JUMBLR selector.%d modval.%d r.%d\n",selector,modval,r&7);
        switch ( s )
        {
            case 0: // public -> z, need to importprivkey
                jumblr_privkey(myinfo,BTCaddr,0,KMDaddr,JUMBLR_DEPOSITPREFIX);
                if ( (total= jumblr_balance(myinfo,coin,KMDaddr)) >= (JUMBLR_INCR + 3*(fee+JUMBLR_TXFEE))*SATOSHIDEN )
                {
                    if ( (r & 1) == 0 )
                    {
                        if ( (zaddr= jumblr_zgetnewaddress(myinfo,coin)) != 0 )
                        {
                            amount = 0;
                            if ( total >= SATOSHIDEN * ((JUMBLR_INCR + 3*fee)*100 + 3*JUMBLR_TXFEE) )
                                amount = SATOSHIDEN * ((JUMBLR_INCR + 3*fee)*100 + 3*JUMBLR_TXFEE);
                            if ( (r & 2) != 0 && total >= SATOSHIDEN * ((JUMBLR_INCR + 3*fee)*10 + 3*JUMBLR_TXFEE) )
                                amount = SATOSHIDEN * ((JUMBLR_INCR + 3*fee)*10 + 3*JUMBLR_TXFEE);
                            if ( (r & 4) != 0 )
                                amount = SATOSHIDEN * ((JUMBLR_INCR + 3*fee) + 3*JUMBLR_TXFEE);
                            if ( amount > 0 && (retstr= jumblr_sendt_to_z(myinfo,coin,KMDaddr,zaddr,dstr(amount))) != 0 )
                            {
                                printf("sendt_to_z.(%s)\n",retstr);
                                free(retstr);
                            }
                            free(zaddr);
                        } else printf("no zaddr from jumblr_zgetnewaddress\n");
                    }
                } else printf("%s total %.8f vs %.8f\n",KMDaddr,dstr(total),(JUMBLR_INCR + 3*(fee+JUMBLR_TXFEE)));
                break;
            case 1: // z -> z
                jumblr_opidsupdate(myinfo,coin);
                chosen_one = -1;
                for (iter=counter=0; iter<2; iter++)
                {
                    counter = n = 0;
                    HASH_ITER(hh,myinfo->jumblrs,ptr,tmp)
                    {
                        if ( jumblr_addresstype(myinfo,coin,ptr->src) == 't' && jumblr_addresstype(myinfo,coin,ptr->dest) == 'z' )
                        {
                            if ( (r & 1) == 0 && ptr->spent == 0 && (total= jumblr_balance(myinfo,coin,ptr->dest)) >= (fee + JUMBLR_FEE)*SATOSHIDEN )
                            {
                                if ( iter == 1 && counter == chosen_one )
                                {
                                    if ( (zaddr= jumblr_zgetnewaddress(myinfo,coin)) != 0 )
                                    {
                                        if ( (retstr= jumblr_sendz_to_z(myinfo,coin,ptr->dest,zaddr,dstr(total))) != 0 )
                                        {
                                            printf("n.%d counter.%d chosen_one.%d sendz_to_z.(%s)\n",n,counter,chosen_one,retstr);
                                            free(retstr);
                                        }
                                        ptr->spent = (uint32_t)time(NULL);
                                        free(zaddr);
                                        break;
                                    }
                                }
                                counter++;
                            }
                        }
                        n++;
                    }
                    if ( counter == 0 )
                        break;
                    if ( iter == 0 )
                    {
                        OS_randombytes((uint8_t *)&chosen_one,sizeof(chosen_one));
                        if ( chosen_one < 0 )
                            chosen_one = -chosen_one;
                        chosen_one %= counter;
                        printf("jumblr z->z chosen_one.%d of %d, from %d\n",chosen_one,counter,n);
                    }
                }
                break;
            case 2: // z -> public
                if ( myinfo->runsilent == 0 )
                {
                    jumblr_opidsupdate(myinfo,coin);
                    chosen_one = -1;
                    for (iter=0; iter<2; iter++)
                    {
                        counter = n = 0;
                        HASH_ITER(hh,myinfo->jumblrs,ptr,tmp)
                        {
                            if ( jumblr_addresstype(myinfo,coin,ptr->src) == 'z' && jumblr_addresstype(myinfo,coin,ptr->dest) == 'z' )
                            {
                                if ( (r & 1) == 0 && ptr->spent == 0 && (total= jumblr_balance(myinfo,coin,ptr->dest)) >= (fee + JUMBLR_FEE)*SATOSHIDEN )
                                {
                                    if ( iter == 1 && n == chosen_one )
                                    {
                                        privkey = jumblr_privkey(myinfo,BTCaddr,0,KMDaddr,"");
                                        if ( (retstr= jumblr_sendz_to_t(myinfo,coin,ptr->dest,KMDaddr,dstr(total))) != 0 )
                                        {
                                            printf("sendz_to_t.(%s)\n",retstr);
                                            free(retstr);
                                        }
                                        ptr->spent = (uint32_t)time(NULL);
                                        break;
                                    }
                                    counter++;
                                }
                            }
                            n++;
                        }
                        if ( counter == 0 )
                            break;
                        if ( iter == 0 )
                        {
                            OS_randombytes((uint8_t *)&chosen_one,sizeof(chosen_one));
                            if ( chosen_one < 0 )
                                chosen_one = -chosen_one;
                            chosen_one %= counter;
                            printf("jumblr z->t chosen_one.%d of %d, from %d\n",chosen_one,counter,n);
                        }
                    }
                }
                break;
        }
    }
}

