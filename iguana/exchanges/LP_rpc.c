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
//  LP_rpc.c
//  marketmaker
//

char *LP_isitme(char *destip,uint16_t destport)
{
    if ( LP_mypeer != 0 && strcmp(destip,LP_mypeer->ipaddr) == 0 && LP_mypeer->port == destport )
    {
        //printf("no need to notify ourselves\n");
        return(clonestr("{\"result\":\"success\"}"));
    } else return(0);
}

char *LP_apicall(struct iguana_info *coin,char *method,char *params)
{
    cJSON *retjson; char *retstr;
    if ( coin == 0 )
        return(0);
    if ( coin->electrum != 0 )
    {
        if ( (retjson= electrum_submit(coin->symbol,coin->electrum,&retjson,method,params,ELECTRUM_TIMEOUT)) != 0 )
        {
            retstr = jprint(retjson,1);
            //printf("got.%p (%s)\n",retjson,retstr);
            return(retstr);
        } return(clonestr("{\"error\":\"electrum no response\"}"));
    } else return(bitcoind_passthru(coin->symbol,coin->serverport,coin->userpass,method,params));
}

cJSON *bitcoin_json(struct iguana_info *coin,char *method,char *params)
{
    cJSON *retjson = 0; char *retstr;
    // "getinfo", "getrawmempool", "paxprice", "gettxout", "getrawtransaction", "getblock", "listunspent", "listtransactions", "validateaddress", "importprivkey"
    // bitcoind_passthru callers: "importaddress", "estimatefee", "getblockhash", "sendrawtransaction", "signrawtransaction"
    if ( coin != 0 )
    {
        if ( 0 && strcmp(method,"gettxout") == 0 && strcmp("BCH",coin->symbol) == 0 )
            printf("issue.(%s, %s, %s, %s, %s)\n",coin->symbol,coin->serverport,coin->userpass,method,params);
        if ( coin->electrum != 0 && (strcmp(method,"getblock") == 0 || strcmp(method,"paxprice") == 0 || strcmp(method,"getrawmempool") == 0) )
            return(cJSON_Parse("{\"error\":\"illegal electrum call\"}"));
        if ( coin->inactive == 0 || strcmp(method,"getrawtransaction") == 0 || strcmp(method,"getblock") == 0 || strcmp(method,"getinfo") == 0 || strcmp(method,"getblockchaininfo") == 0 || strcmp(method,"importprivkey") == 0 || strcmp(method,"validateaddress") == 0 || strcmp(method,"getaddressinfo") == 0 || strcmp(method,"importaddress") == 0 )
        {
            if ( coin->electrum == 0 )
            {
                retstr = bitcoind_passthru(coin->symbol,coin->serverport,coin->userpass,method,params);
                if ( 0 && strcmp("BCH",coin->symbol) == 0 )
                    printf("%s.(%s %s): %s.%s -> (%s)\n",coin->symbol,coin->serverport,coin->userpass,method,params,retstr!=0?retstr:"");
                if ( retstr != 0 && retstr[0] != 0 )
                {
                    retjson = cJSON_Parse(retstr);
                    free(retstr);
                }
            }
            else
            {
                if ( (retjson= electrum_submit(coin->symbol,coin->electrum,&retjson,method,params,ELECTRUM_TIMEOUT)) != 0 )
                {
                    if ( jobj(retjson,"error") != 0 )
                    {
                        free_json(retjson);
                        retjson = 0;
                    }
                }
            }
        } //else retjson = cJSON_Parse("{\"result\":\"disabled\"}");
    } else printf("bitcoin_json cant talk to NULL coin\n");
    return(retjson);
}

void LP_unspents_mark(char *symbol,cJSON *vins)
{
    //printf("LOCK (%s)\n",jprint(vins,0));
}

int32_t LP_getheight(int32_t *notarizedp,struct iguana_info *coin)
{
    cJSON *retjson; char *retstr; int32_t height;
    *notarizedp = 0;
    if ( coin == 0 )
        return(-1);
    if ( coin->getinfostr[0] == 0 )
        strcpy(coin->getinfostr,"getinfo");
    height = coin->height;
    if ( coin->electrum == 0 && time(NULL) > coin->heighttime+60 && coin->userpass[0] != 0 )
    {
        retstr = bitcoind_passthru(coin->symbol,coin->serverport,coin->userpass,coin->getinfostr,"[]");
        if ( retstr != 0 && retstr[0] != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( jobj(retjson,"error") != 0 && strcmp("getinfo",coin->getinfostr) == 0 )
                {
                    strcpy(coin->getinfostr,"getblockchaininfo");
                    free_json(retjson), retjson = 0;
                    free(retstr);
                    if ( (retstr= bitcoind_passthru(coin->symbol,coin->serverport,coin->userpass,coin->getinfostr,"[]")) != 0 )
                    {
                        retjson = cJSON_Parse(retstr);
                        printf("getblockchaininfo autoissue.(%s)\n",retstr);
                    }
                }
                if ( retjson != 0 )
                {
                    coin->height = height = jint(retjson,"blocks");
                    if ( (*notarizedp= jint(retjson,"notarized")) != 0 && *notarizedp != coin->notarized )
                    {
                        //printf("new notarized %s %d -> %d\n",coin->symbol,coin->notarized,*notarizedp);
                        coin->notarized = *notarizedp;
                        coin->notarizationtxid = jbits256(retjson,"notarizedtxid");
                        coin->notarizedhash = jbits256(retjson,"notarizedhash");
                    }
                    free_json(retjson);
                }
            }
            if ( coin->height > 0 )
                coin->heighttime = (uint32_t)time(NULL);
            free(retstr);
        }
    }
    return(height);
}

uint64_t LP_RTsmartbalance(struct iguana_info *coin)
{
    cJSON *array,*item; char buf[512],*retstr; int32_t i,n; uint64_t valuesum,value; bits256 zero;
    valuesum = 0;
    memset(zero.bytes,0,sizeof(zero));
    sprintf(buf,"[0, 99999999, [\"%s\"]]",coin->smartaddr);
    retstr = bitcoind_passthru(coin->symbol,coin->serverport,coin->userpass,"listunspent",buf);
    if ( retstr != 0 && retstr[0] != 0 )
    {
        array = cJSON_Parse(retstr);
        if ( is_cJSON_Array(array) != 0 && (n= cJSON_GetArraySize(array)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                value = LP_value_extract(item,0,zero);
                valuesum += value;
                //printf("%s -> %.8f\n",jprint(item,0),dstr(value));
            }
        }
        free_json(array);
    }
    return(valuesum);
}

cJSON *LP_getmempool(char *symbol,char *coinaddr,bits256 txid,bits256 txid2)
{
    cJSON *array; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 || (coin->electrum != 0 && coinaddr == 0) )
        return(cJSON_Parse("{\"error\":\"no native coin\"}"));
    if ( coin->electrum == 0 )
        return(bitcoin_json(coin,"getrawmempool","[]"));
    else return(electrum_address_getmempool(symbol,coin->electrum,&array,coinaddr,txid,txid2));
}

cJSON *LP_paxprice(char *fiat)
{
    char buf[128],lfiat[65]; struct iguana_info *coin = LP_coinfind("KMD");
    strcpy(lfiat,fiat);
    tolowercase(lfiat);
    sprintf(buf,"[\"%s\", \"kmd\"]",lfiat);
    return(bitcoin_json(coin,"paxprice",buf));
}

cJSON *LP_gettx(char *debug,char *symbol,bits256 txid,int32_t suppress_errors)
{
    struct iguana_info *coin; char buf[512],str[65]; int32_t height; cJSON *retjson;
    //printf("%s LP_gettx %s %s\n",debug,symbol,bits256_str(str,txid));
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 )
        return(cJSON_Parse("{\"error\":\"no coin\"}"));
    if ( bits256_nonz(txid) == 0 )
        return(cJSON_Parse("{\"error\":\"null txid\"}"));
    if ( coin->electrum == 0 )
    {
        sprintf(buf,"[\"%s\", 1]",bits256_str(str,txid));
        retjson = bitcoin_json(coin,"getrawtransaction",buf);
        return(retjson);
    }
    else
    {
        if ( (retjson= electrum_transaction(&height,symbol,coin->electrum,&retjson,txid,0)) != 0 )
            return(retjson);
        else if ( suppress_errors == 0 )
            printf("failed blockchain.transaction.get %s %s\n",coin->symbol,bits256_str(str,txid));
        return(cJSON_Parse("{\"error\":\"no transaction bytes\"}"));
    }
}

uint32_t LP_locktime(char *symbol,bits256 txid)
{
    cJSON *txobj; uint32_t locktime = 0;
    if ( (txobj= LP_gettx("LP_locktime",symbol,txid,0)) != 0 )
    {
        locktime = juint(txobj,"locktime");
        free_json(txobj);
    }
    return(locktime);
}

cJSON *LP_gettxout_json(bits256 txid,int32_t vout,int32_t height,char *coinaddr,uint64_t value)
{
    cJSON *retjson,*addresses,*sobj;
    retjson = cJSON_CreateObject();
    jaddnum(retjson,"value",dstr(value));
    jaddnum(retjson,"height",height);
    jaddbits256(retjson,"txid",txid);
    jaddnum(retjson,"vout",vout);
    addresses = cJSON_CreateArray();
    jaddistr(addresses,coinaddr);
    sobj = cJSON_CreateObject();
    jaddnum(sobj,"reqSigs",1);
    jaddstr(sobj,"type","pubkey");
    jadd(sobj,"addresses",addresses);
    jadd(retjson,"scriptPubKey",sobj);
    //printf("GETTXOUT.(%s)\n",jprint(retjson,0));
    return(retjson);
}

cJSON *LP_gettxout(char *symbol,char *coinaddr,bits256 txid,int32_t vout)
{
    char buf[128],str[65]; cJSON *item,*array,*vouts,*txobj,*retjson=0; int32_t i,v,height,n; bits256 t,zero; struct iguana_info *coin; struct LP_transaction *tx; struct LP_address_utxo *up;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    if ( (coin= LP_coinfind(symbol)) == 0 )
        return(cJSON_Parse("{\"error\":\"no coin\"}"));
    if ( bits256_nonz(txid) == 0 )
        return(cJSON_Parse("{\"error\":\"null txid\"}"));
    if ( coin->electrum == 0 )
    {
        sprintf(buf,"[\"%s\", %d, true]",bits256_str(str,txid),vout);
        return(bitcoin_json(coin,"gettxout",buf));
    }
    else
    {
        if ( (tx= LP_transactionfind(coin,txid)) != 0 && vout < tx->numvouts )
        {
            if ( tx->outpoints[vout].spendheight > 0 )
                return(0);
            //return(LP_gettxout_json(txid,vout,tx->height,tx->outpoints[vout].coinaddr,tx->outpoints[vout].value));
        }
        if ( coinaddr[0] == 0 )
        {
            if ( (txobj= electrum_transaction(&height,symbol,coin->electrum,&txobj,txid,0)) != 0 )
            {
                if ( (vouts= jarray(&n,txobj,"vout")) != 0 && n > 0 )
                    LP_destaddr(coinaddr,jitem(vouts,vout));
                free_json(txobj);
            }
        }
        if ( coinaddr[0] != 0 )
        {
            if ( (up= LP_address_utxofind(coin,coinaddr,txid,vout)) != 0 )
            {
                if ( up->spendheight > 0 )
                    return(0);
                //return(LP_gettxout_json(txid,vout,up->U.height,coinaddr,up->U.value));
            }
            memset(zero.bytes,0,sizeof(zero));
            if ( (array= electrum_address_listunspent(coin->symbol,0,&array,coinaddr,1,txid,zero)) != 0 )
            {
                //printf("array.(%s)\n",jprint(array,0));
                if ( array != 0 && (n= cJSON_GetArraySize(array)) > 0 )
                {
                    for (i=0; i<n; i++)
                    {
                        item = jitem(array,i);
                        t = jbits256(item,"tx_hash");
                        v = jint(item,"tx_pos");
                        if ( v == vout && bits256_cmp(t,txid) == 0 )
                        {
                            retjson = LP_gettxout_json(txid,vout,jint(item,"height"),coinaddr,j64bits(item,"value"));
                            break;
                        }
                    }
                }
                free_json(array);
                if ( retjson != 0 )
                    return(retjson);
            }
        }
        //printf("couldnt find %s (%s) %s/v%d\n",symbol,coinaddr,bits256_str(str,txid),vout);
        return(cJSON_Parse("{\"error\":\"couldnt get tx\"}"));
    }
}

cJSON *LP_validateaddress(char *symbol,char *address)
{
    char buf[512],coinaddr[64],checkaddr[64],script[128]; int32_t i; uint8_t rmd160[20],addrtype; cJSON *retjson; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 )
        return(cJSON_Parse("{\"error\":\"no coin\"}"));
    if ( coin != 0 && coin->electrum != 0 )
    {
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"address",address);
        bitcoin_addr2rmd160(symbol,coin->taddr,&addrtype,rmd160,address);
        bitcoin_address(symbol,checkaddr,coin->taddr,addrtype,rmd160,20);
        if ( addrtype != coin->pubtype && addrtype != coin->p2shtype )
        {
            jadd(retjson,"isvalid",cJSON_CreateFalse());
            return(retjson);
        }
        jadd(retjson,"isvalid",strcmp(address,checkaddr)==0 ? cJSON_CreateTrue() : cJSON_CreateFalse());
        if ( addrtype == coin->pubtype )
        {
            strcpy(script,"76a914");
            for (i=0; i<20; i++)
                sprintf(&script[i*2+6],"%02x",rmd160[i]);
            script[i*2+6] = 0;
            strcat(script,"88ac");
            jaddstr(retjson,"scriptPubKey",script);
        }
        bitcoin_address(symbol,coinaddr,coin->taddr,coin->pubtype,G.LP_pubsecp,33);
        jadd(retjson,"ismine",strcmp(coinaddr,coin->smartaddr) == 0 ? cJSON_CreateTrue() : cJSON_CreateFalse());
        jadd(retjson,"iswatchonly",cJSON_CreateTrue());
        jadd(retjson,"isscript",addrtype == coin->p2shtype ? cJSON_CreateTrue() : cJSON_CreateFalse());
        return(retjson);
    }
    else
    {
        sprintf(buf,"[\"%s\"]",address);
        if ( coin->validateaddress[0] == 0 )
            strcpy(coin->validateaddress,"validateaddress");
        if ( (retjson= bitcoin_json(coin,coin->validateaddress,buf)) != 0 )
        {
            if ( strcmp(coin->symbol,"BTC") == 0 && jobj(retjson,"error") == 0 && jobj(retjson,"ismine") == 0 && strcmp(coin->validateaddress,"validateaddress") == 0 )
            {
                printf("autochange %s validateaddress -> getaddressinfo\n",coin->symbol);
                strcpy(coin->validateaddress,"getaddressinfo");
                free(retjson);
                return(bitcoin_json(coin,coin->validateaddress,buf));
            }
        }
        return(retjson);
    }
}

int32_t LP_address_ismine(char *symbol,char *address)
{
    int32_t doneflag = 0; cJSON *retjson,*obj;
    if ( symbol == 0 || symbol[0] == 0 )
        return(0);
    if ( (retjson= LP_validateaddress(symbol,address)) != 0 )
    {
        if ( (obj= jobj(retjson,"ismine")) != 0 && is_cJSON_True(obj) != 0 )
        {
            doneflag = 1;
            //printf("%s ismine (%s)\n",address,jprint(retjson,0));
        }
        //printf("%s\n",jprint(retjson,0));
        free_json(retjson);
    }
    return(doneflag);
}

int32_t LP_address_iswatchonly(char *symbol,char *address)
{
    int32_t doneflag = 0; cJSON *retjson,*obj;
    if ( symbol == 0 || symbol[0] == 0 )
        return(0);
    if ( (retjson= LP_validateaddress(symbol,address)) != 0 )
    {
        if ( ((obj= jobj(retjson,"iswatchonly")) != 0 || (obj= jobj(retjson,"watchonly")) != 0) && is_cJSON_True(obj) != 0 )
        {
            doneflag = 1;
            //printf("%s iswatchonly (%s)\n",address,jprint(retjson,0));
        }
        //printf("%s\n",jprint(retjson,0));
        free_json(retjson);
    }
    return(doneflag);
}

int32_t LP_address_isvalid(char *symbol,char *address)
{
    int32_t isvalid = 0; cJSON *retjson;
    if ( symbol == 0 || symbol[0] == 0 )
        return(0);
    if ( (retjson= LP_validateaddress(symbol,address)) != 0 )
    {
        if ( jobj(retjson,"isvalid") != 0 && is_cJSON_True(jobj(retjson,"isvalid")) != 0 )
        {
            isvalid = 1;
            //printf("%s ismine (%s)\n",address,jprint(retjson,0));
        }
        //printf("%s\n",jprint(retjson,0));
        free_json(retjson);
    }
    return(isvalid);
}

cJSON *LP_listunspent(char *symbol,char *coinaddr,bits256 reftxid,bits256 reftxid2)
{
    char buf[128],*retstr; bits256 txid; struct LP_address *ap; cJSON *retjson,*txjson,*array,*item; int32_t i,n,numconfs,vout,usecache=1; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 || (IAMLP == 0 && coin->inactive != 0) )
        return(cJSON_Parse("{\"error\":\"no coin\"}"));
    if ( coin->electrum == 0 )
    {
        if ( (ap= LP_addressfind(coin,coinaddr)) != 0 )
        {
            if ( ap->unspenttime == 0 || strcmp(coin->symbol,"DYN") == 0 )
                usecache = 0;
            else if ( time(NULL) > ap->unspenttime+3 )
                usecache = 0;
            usecache = 0; // disable unspents cache for native
            //printf("%s %s usecache.%d iswatched.%d\n",coin->symbol,coinaddr,usecache,LP_address_iswatchonly(symbol,coinaddr));
            if ( usecache != 0 && (retstr= LP_unspents_filestr(symbol,coinaddr)) != 0 )
            {
                retjson = cJSON_Parse(retstr);
                free(retstr);
                if ( cJSON_GetArraySize(retjson) > 0 )
                    return(retjson);
                else free_json(retjson);
            }
        }
        //printf("%s %s usecache.%d iswatched.%d\n",coin->symbol,coinaddr,usecache,LP_address_iswatchonly(symbol,coinaddr));
        if ( LP_address_ismine(symbol,coinaddr) > 0 || LP_address_iswatchonly(symbol,coinaddr) > 0 )
        {
            if ( strcmp(symbol,"BTC") == 0 )
                numconfs = 0;
            else numconfs = 1;
            sprintf(buf,"[%d, 99999999, [\"%s\"]]",numconfs,coinaddr);
            retjson = bitcoin_json(coin,"listunspent",buf);
//printf("LP_listunspent.(%s %s) -> %s\n",symbol,buf,jprint(retjson,0));
            if ( (n= cJSON_GetArraySize(retjson)) > 0 )
            {
                char str[65];
                array = cJSON_CreateArray();
                for (i=0; i<n; i++)
                {
                    item = jitem(retjson,i);
                    txid = jbits256(item,"txid");
                    vout = jint(item,"vout");
                    if ( (txjson= LP_gettxout(symbol,coinaddr,txid,vout)) != 0 )
                    {
                        jaddi(array,jduplicate(item));
                        free_json(txjson);
                    } //else printf("%s/v%d is spent\n",bits256_str(str,txid),vout);
                }
                free_json(retjson);
                retjson = array;
                retstr = jprint(array,0);
                LP_unspents_cache(coin->symbol,coinaddr,retstr,1);
                free(retstr);
            }
            if ( ap != 0 )
                ap->unspenttime = (uint32_t)time(NULL);
            return(retjson);
        } else return(LP_address_utxos(coin,coinaddr,0));
    } else return(electrum_address_listunspent(symbol,coin->electrum,&retjson,coinaddr,1,reftxid,reftxid2));
}

cJSON *LP_listreceivedbyaddress(char *symbol,char *coinaddr)
{
    char buf[128],*addr; bits256 zero; cJSON *retjson,*array,*item; int32_t i,n; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 || (IAMLP == 0 && coin->inactive != 0) )
        return(cJSON_Parse("{\"error\":\"no coin\"}"));
    memset(zero.bytes,0,sizeof(zero));
    if ( coin->electrum == 0 )
    {
        sprintf(buf,"[1, false, true]");
        if ( (array= bitcoin_json(coin,"listreceivedbyaddress",buf)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( (addr= jstr(item,"address")) != 0 && strcmp(addr,coinaddr) == 0 )
                    {
                        retjson = jduplicate(jobj(item,"txids"));
                        free_json(array);
                        return(retjson);
                    }
                }
            }
            free_json(array);
        }
        return(cJSON_Parse("[]"));
    } else return(electrum_address_gethistory(symbol,coin->electrum,&retjson,coinaddr,zero));
}


cJSON *LP_listtransactions(char *symbol,char *coinaddr,int32_t count,int32_t skip)
{
    char buf[128],*addr; bits256 zero; cJSON *retjson,*array,*item; int32_t i,n; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 || (IAMLP == 0 && coin->inactive != 0) )
        return(cJSON_Parse("{\"error\":\"no coin\"}"));
    memset(zero.bytes,0,sizeof(zero));
    if ( coin->electrum == 0 )
    {
        if ( count == 0 )
            count = 10;
        sprintf(buf,"[\"\", %d, %d, true]",count,skip);
        retjson = cJSON_CreateArray();
        if ( (array= bitcoin_json(coin,"listtransactions",buf)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( (addr= jstr(item,"address")) != 0 && strcmp(addr,coinaddr) == 0 )
                        jaddi(retjson,jduplicate(item));
                }
            }
            free_json(array);
        }
        return(retjson);
    } else return(electrum_address_gethistory(symbol,coin->electrum,&retjson,coinaddr,zero));
}

int64_t LP_listunspent_parseitem(struct iguana_info *coin,bits256 *txidp,int32_t *voutp,int32_t *heightp,cJSON *item)
{
    int64_t satoshis = 0;
    if ( coin->electrum == 0 )
    {
        *txidp = jbits256(item,"txid");
        *voutp = juint(item,"vout");
        satoshis = LP_value_extract(item,0,*txidp);
        *heightp = LP_txheight(coin,*txidp);
    }
    else
    {
        *txidp = jbits256(item,"tx_hash");
        *voutp = juint(item,"tx_pos");
        satoshis = j64bits(item,"value");
        *heightp = jint(item,"height");
    }
    return(satoshis);
}

int32_t LP_listunspent_issue(char *symbol,char *coinaddr,int32_t fullflag,bits256 reftxid,bits256 reftxid2)
{
    struct iguana_info *coin; struct LP_address *ap; int32_t n = 0; cJSON *retjson=0; char *retstr=0;
    if ( symbol == 0 || symbol[0] == 0 )
        return(0);
    if ( (coin= LP_coinfind(symbol)) != 0 )
    {
        if ( coin->electrum != 0 )
        {
            if ( (retjson= electrum_address_listunspent(symbol,coin->electrum,&retjson,coinaddr,fullflag,reftxid,reftxid2)) != 0 )
            {
                n = cJSON_GetArraySize(retjson);
                //printf("LP_listunspent_issue.%s %s.%d %s\n",symbol,coinaddr,n,jprint(retjson,0));
            }
        }
        else
        {
            if ( fullflag == 2 && (ap= LP_addressfind(coin,coinaddr)) != 0 )
                ap->unspenttime = 0;
            retjson = LP_listunspent(symbol,coinaddr,reftxid,reftxid2);
            coin->numutxos = cJSON_GetArraySize(retjson);
            if ( retjson != 0 )
            {
                n = cJSON_GetArraySize(retjson);
                if ( electrum_process_array(coin,0,coinaddr,retjson,1,reftxid,reftxid2) != 0 )
                {
                    //LP_postutxos(symbol,coinaddr); // might be good to not saturate
                }
            }
        }
        //printf("issue listunspent %s (%s)\n",coinaddr,jprint(retjson,0));
        if ( retjson != 0 )
            free_json(retjson);
        if ( retstr != 0 )
            free(retstr);
    }
    return(n);
}

int32_t LP_importaddress(char *symbol,char *address)
{
    char buf[1024],*retstr; cJSON *validatejson; int32_t isvalid=0,doneflag = 0; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(-2);
    coin = LP_coinfind(symbol);
    if ( coin == 0 )
        return(-3);
    //printf("import.(%s %s)\n",symbol,address);
    if ( coin->electrum != 0 )
    {
        /*if ( (retjson= electrum_address_subscribe(symbol,coin->electrum,&retjson,address)) != 0 )
         {
         printf("importaddress.(%s) -> %s\n",address,jprint(retjson,0));
         free_json(retjson);
         }*/
        return(0);
    }
    else
    {
        if ( (validatejson= LP_validateaddress(symbol,address)) != 0 )
        {
            //printf("validated.(%s)\n",jprint(validatejson,0));
            if ( (isvalid= is_cJSON_True(jobj(validatejson,"isvalid")) != 0) != 0 )
            {
                if ( is_cJSON_True(jobj(validatejson,"iswatchonly")) != 0 || is_cJSON_True(jobj(validatejson,"watchonly")) != 0 || is_cJSON_True(jobj(validatejson,"ismine")) != 0 )
                    doneflag = 1;
            }
            free_json(validatejson);
        }
        //printf("%s (%s) isvalid.%d doneflag.%d\n",symbol,address,isvalid,doneflag);
        if ( isvalid == 0 )
            return(-1);
        if ( doneflag != 0 )
            return(0); // success
        sprintf(buf,"[\"%s\", \"%s\", false]",address,address);
        if ( (retstr= bitcoind_passthru(symbol,coin->serverport,coin->userpass,"importaddress",buf)) != 0 )
        {
            printf("importaddress.(%s %s) -> (%s)\n",symbol,address,retstr);
            free(retstr);
        } //else printf("importaddress.(%s %s)\n",symbol,address);
        return(1);
    }
}

cJSON *LP_importprivkey(char *symbol,char *wifstr,char *label,int32_t flag)
{
    static void *ctx;
    char buf[512],address[64]; cJSON *retjson; struct iguana_info *coin; int32_t doneflag = 0;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 )
        return(cJSON_Parse("{\"error\":\"no coin\"}"));
    if ( coin->electrum != 0 )
        return(cJSON_Parse("{\"result\":\"electrum should have local wallet\"}"));
    if ( ctx == 0 )
        ctx = bitcoin_ctx();
    bitcoin_wif2addr(ctx,symbol,coin->wiftaddr,coin->taddr,coin->pubtype,address,wifstr);
#ifdef LP_DONT_IMPORTPRIVKEY
    if ( LP_importaddress(symbol,address) < 0 )
    {
        printf("%s importaddress %s from %s failed, isvalid.%d\n",symbol,address,wifstr,bitcoin_validaddress(symbol,coin->taddr,coin->pubtype,coin->p2shtype,address));
        return(cJSON_Parse("{\"error\":\"couldnt import\"}"));
    } else return(cJSON_Parse("{\"result\":\"success\"}"));
#endif
    if ( (retjson= LP_validateaddress(symbol,address)) != 0 )
    {
        if ( jobj(retjson,"ismine") != 0 && is_cJSON_True(jobj(retjson,"ismine")) != 0 )
        {
            doneflag = 1;
            //printf("%s already ismine\n",address);
        }
        //printf("%s\n",jprint(retjson,0));
        free_json(retjson);
    }
    if ( doneflag == 0 )
    {
        if ( coin->noimportprivkey_flag != 0 )
            sprintf(buf,"[\"%s\"]",wifstr);
        else sprintf(buf,"\"%s\", \"%s\", %s",wifstr,label,flag < 0 ? "false" : "true");
        return(bitcoin_json(coin,"importprivkey",buf));
    } else return(cJSON_Parse("{\"result\":\"success\"}"));
}

cJSON *LP_bitcoinfees()
{
    char *retstr; cJSON *retjson = 0;
    if ( (retstr= issue_curlt("https://bitcoinfees.earn.com/api/v1/fees/recommended",LP_HTTP_TIMEOUT)) != 0 )
    {
        retjson = cJSON_Parse(retstr);
        free(retstr);
    }
    return(retjson);
}

double _LP_getestimatedrate(struct iguana_info *coin)
{
    char buf[512],*retstr=0; int32_t numblocks,err=0; cJSON *errjson,*retjson; double rate = 0.00000005;
    if ( coin->rate < 0. || time(NULL) > coin->ratetime+30 )
    {
        if ( coin->estimatefeestr[0] == 0 )
            strcpy(coin->estimatefeestr,"estimatefee");
        numblocks = 3;//strcmp(coin->symbol,"BTC") == 0 ? 6 : 2;
again:
        if ( coin->electrum == 0 )
        {
            sprintf(buf,"[%d]",numblocks);
            retstr = LP_apicall(coin,coin->estimatefeestr,buf);
        }
        else
        {
            // {"fastestFee":70,"halfHourFee":70,"hourFee":10}
            if ( strcmp(coin->symbol,"BTC") == 0 && (retjson= LP_bitcoinfees()) != 0 )
            {
                int32_t fastest,half,hour,best=0;
                fastest = jint(retjson,"fastestFee");
                half = jint(retjson,"halfHourFee");
                hour = jint(retjson,"hourFee");
                if ( hour*3 > half )
                    best = hour*3;
                else best = half;
                if ( fastest < best )
                    best = fastest;
                retstr = calloc(1,16);
                sprintf(retstr,"%0.8f",((double)best * 1024)/SATOSHIDEN);
                //printf("LP_getestimatedrate (%s) -> %s\n",jprint(retjson,0),retstr);
                free(retjson);
            }
            /*if ( (retjson= electrum_estimatefee(coin->symbol,coin->electrum,&retjson,numblocks)) != 0 )
            {
                retstr = jprint(retjson,1);
                //free_json(retjson), retjson = 0; causes crash?
                printf("estfee numblocks.%d (%s)\n",numblocks,retstr);
            }*/
        }
        if ( retstr != 0 )
        {
            if ( retstr[0] == '{' && (errjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( jobj(errjson,"error") != 0 )
                {
                    rate = 0.;
                    err++;
                }
                if ( strcmp(coin->estimatefeestr,"estimatesmartfee") == 0 && (rate= jdouble(errjson,"feerate")) != 0 )
                {
                    static uint32_t counter;
                    if ( counter++ < 10 )
                        printf("extracted feerate %.8f from estimatesmartfee\n",rate);
                    rate /= 1024.;
                }
                free_json(errjson);
            }
            else if ( retstr[0] != '-' )
                rate = atof(retstr) / 1024.;
            if ( rate != 0. )
            {
                //rate *= 1.25;
                if ( rate < 0.00000005 )
                    rate = 0.00000005;
                if ( fabs(rate - coin->rate) > SMALLVAL )
                    printf("%u t%u estimated rate.(%s) (%s) -> %.8f %.8f\n",(uint32_t)time(NULL),coin->ratetime,coin->symbol,retstr,rate,coin->rate);
                coin->rate = rate;
                coin->ratetime = (uint32_t)time(NULL);
                //printf("set rate %.8f t%u\n",rate,coin->ratetime);
            }
            free(retstr);
            if ( err == 1 && coin->electrum == 0 && strcmp(coin->estimatefeestr,"estimatefee") == 0 )
            {
                strcpy(coin->estimatefeestr,"estimatesmartfee");
                err = 2;
                goto again;
            }
        } else rate = coin->rate;
    } else rate = coin->rate;
    coin->rate = rate;
    return(rate);
}

double LP_getestimatedrate(struct iguana_info *coin)
{
    double rate = 0.00000005;
    if ( coin == 0 )
        return(rate);
    if ( (rate= _LP_getestimatedrate(coin)) <= 0. )
        rate = dstr(coin->txfee) / LP_AVETXSIZE;
    return(rate);
}

char *LP_sendrawtransaction(char *symbol,char *signedtx,int32_t needjson)
{
    cJSON *array,*errobj; char *paramstr,*tmpstr,*retstr=0; int32_t n,alreadyflag = 0; cJSON *retjson; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 || signedtx == 0 || signedtx[0] == 0 )
    {
        printf("LP_sendrawtransaction null symbol %p or signedtx.%p\n",symbol,signedtx);
        return(clonestr("{\"error\":\"invalid param\"}"));
    }
    coin = LP_coinfind(symbol);
    if ( coin == 0 )
    {
        printf("LP_sendrawtransaction null coin\n");
        return(clonestr("{\"error\":\"invalid coin\"}"));
    }
    if ( coin->electrum == 0 )
    {
        array = cJSON_CreateArray();
        jaddistr(array,signedtx);
        paramstr = jprint(array,1);
        retstr = bitcoind_passthru(symbol,coin->serverport,coin->userpass,"sendrawtransaction",paramstr);
        //printf(">>>>>>>>>>> %s dpow_sendrawtransaction.(%s) -> (%s)\n",coin->symbol,paramstr,retstr);
        free(paramstr);
    }
    else
    {
        if ( (retjson= electrum_sendrawtransaction(symbol,coin->electrum,&retjson,signedtx)) != 0 )
        {
            retstr = jprint(retjson,1);
            //electrum sendrawtx (the transaction was rejected by network rules.\n\ntransaction already in block chain)
            if ( strstr(retstr,"already in block") != 0 )
                alreadyflag = 1;
            //printf("electrum sendrawtx.(%s) -> %s already.%d\n",signedtx,retstr,alreadyflag);
            if ( alreadyflag != 0 )
            {
                errobj = cJSON_CreateObject();
                jaddstr(errobj,"error","rejected");
                jaddnum(errobj,"code",-27);
                free(retstr);
                retstr = jprint(errobj,1);
            }
            else
            {
                n = (int32_t)strlen(retstr);
                if ( retstr[0] == '"' && retstr[n-1] == '"' )
                {
                    retstr[n-1] = 0;
                    tmpstr = clonestr(retstr+1);
                    free(retstr);
                    retstr = tmpstr;
                }
            }
        }
    }
    if ( needjson != 0 && is_hexstr(retstr,0) > 0 )
    {
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","success");
        jaddstr(retjson,"txid",retstr);
        free(retstr);
        retstr = jprint(retjson,1);
    }
    return(retstr);
}

char *LP_signrawtx(char *symbol,bits256 *signedtxidp,int32_t *completedp,cJSON *vins,char *rawtx,cJSON *privkeys,struct vin_info *V)
{
    cJSON *array,*json,*retjson; int32_t len; uint8_t *data; char str[65],*paramstr,*retstr,*hexstr,*signedtx=0; struct iguana_msgtx msgtx; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(0);
    coin = LP_coinfind(symbol);
    memset(signedtxidp,0,sizeof(*signedtxidp));
    *completedp = 0;
    if ( coin == 0 )
    {
        printf("LP_signrawtx cant find coin.(%s)\n",symbol);
        return(0);
    }
    //int32_t iguana_signrawtransaction(void *ctx,char *symbol,uint8_t wiftaddr,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,struct iguana_msgtx *msgtx,char **signedtxp,bits256 *signedtxidp,struct vin_info *V,int32_t numinputs,char *rawtx,cJSON *vins,cJSON *privkeysjson)
    memset(&msgtx,0,sizeof(msgtx));
    signedtx = 0;
    memset(signedtxidp,0,sizeof(*signedtxidp));
    //printf("locktime.%u sequenceid.%x rawtx.(%s) vins.(%s)\n",locktime,sequenceid,rawtxbytes,jprint(vins,0));
    if ( (*completedp= iguana_signrawtransaction(coin->ctx,symbol,coin->wiftaddr,coin->taddr,coin->pubtype,coin->p2shtype,coin->isPoS,1000000,&msgtx,&signedtx,signedtxidp,V,16,rawtx,vins,privkeys,coin->zcash)) < 0 )
        //if ( (signedtx= LP_signrawtx(symbol,signedtxidp,&completed,vins,rawtxbytes,privkeys,V)) == 0 )
        printf("couldnt sign transaction.%s %s\n",rawtx,bits256_str(str,*signedtxidp));
    else if ( *completedp == 0 )
    {
        printf("incomplete signing %s (%s)\n",rawtx,jprint(vins,0));
        if ( signedtx != 0 )
            free(signedtx), signedtx = 0;
    } // else printf("basilisk_swap_bobtxspend %s -> %s\n",rawtx,bits256_str(str,*signedtxidp));
    if ( signedtx == 0 )
    {
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"error","couldnt sign tx");
        jaddstr(retjson,"coin",coin->symbol);
        jaddstr(retjson,"rawtx",rawtx);
        jadd(retjson,"vins",vins);
        jadd(retjson,"privkeys",privkeys);
        return(jprint(retjson,1));
    }
    return(signedtx);
    if ( (0) )
    {
        array = cJSON_CreateArray();
        jaddistr(array,rawtx);
        jaddi(array,jduplicate(vins));
        jaddi(array,jduplicate(privkeys));
        paramstr = jprint(array,1);
        //printf("signrawtransaction\n");
        if ( (retstr= bitcoind_passthru(symbol,coin->serverport,coin->userpass,"signrawtransaction",paramstr)) != 0 )
        {
            if ( (json= cJSON_Parse(retstr)) != 0 )
            {
                if ( (hexstr= jstr(json,"hex")) != 0 )
                {
                    len = (int32_t)strlen(hexstr);
                    signedtx = calloc(1,len+1);
                    strcpy(signedtx,hexstr);
                    *completedp = is_cJSON_True(jobj(json,"complete"));
                    len >>= 1;
                    data = malloc(len);
                    decode_hex(data,len,hexstr);
                    *signedtxidp = bits256_calctxid(coin->symbol,data,len);
                }
                //else
                printf("%s signrawtransaction.(%s) params.(%s)\n",coin->symbol,retstr,paramstr);
                free_json(json);
            }
            free(retstr);
        }
        free(paramstr);
        return(signedtx);
    }
}

cJSON *LP_getblock(char *symbol,bits256 txid)
{
    char buf[128],str[65]; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 || coin->electrum != 0 )
        return(cJSON_Parse("{\"error\":\"no native coin\"}"));
    sprintf(buf,"[\"%s\"]",bits256_str(str,txid));
    return(bitcoin_json(coin,"getblock",buf));
}

// not in electrum path
uint64_t LP_txfee(char *symbol)
{
    uint64_t txfee = 0;
    if ( symbol == 0 || symbol[0] == 0 )
        return(LP_MIN_TXFEE);
    if ( strcmp(symbol,"BTC") != 0 )
        txfee = LP_MIN_TXFEE;
    return(txfee);
}

bits256 LP_getbestblockhash(struct iguana_info *coin)
{
    char *retstr; bits256 blockhash;
    memset(blockhash.bytes,0,sizeof(blockhash));
    if ( coin->electrum == 0 )
    {
        if ( (retstr= bitcoind_passthru(coin->symbol,coin->serverport,coin->userpass,"getbestblockhash","")) != 0 )
        {
            if ( is_hexstr(retstr,0) == sizeof(blockhash)*2 )
                decode_hex(blockhash.bytes,sizeof(blockhash),retstr);
            free(retstr);
        }
    } else printf("electrum mode doesnt support block level scanning\n");
    return(blockhash);
}

char *LP_blockhashstr(char *symbol,int32_t height)
{
    char params[64],*retstr; struct iguana_info *coin; //cJSON *array;
    if ( symbol == 0 || symbol[0] == 0 )
        return(0);
    coin = LP_coinfind(symbol);
    if ( coin == 0 || coin->electrum != 0 )
        return(0);
    //array = cJSON_CreateArray();
    //jaddinum(array,height);
    //paramstr = jprint(array,1);
    sprintf(params,"[%d]",height);
    retstr = bitcoind_passthru(symbol,coin->serverport,coin->userpass,"getblockhash",params);
    //free(paramstr);
    //printf("blockhashstr.(%s)\n",retstr);
    return(retstr);
}

cJSON *LP_getblockhashstr(char *symbol,char *blockhashstr)
{
    char buf[128]; struct iguana_info *coin;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 || coin->electrum != 0 )
        return(cJSON_Parse("{\"error\":\"no native coin daemon\"}"));
    sprintf(buf,"[\"%s\"]",blockhashstr);
    return(bitcoin_json(coin,"getblock",buf));
}

uint32_t LP_heighttime(char *symbol,int32_t height)
{
    struct electrum_info *ep; uint32_t timestamp = 0; cJSON *retjson; char *blockhashstr; struct iguana_info *coin = LP_coinfind(symbol);
    if ( coin != 0 )
    {
        if ( (ep= coin->electrum) == 0 )
        {
            if ( (blockhashstr= LP_blockhashstr(symbol,height)) != 0 )
            {
                if ( (retjson= LP_getblockhashstr(symbol,blockhashstr)) != 0 )
                {
                    //printf("%s -> height.(%s)\n",blockhashstr,jprint(retjson,0));
                    timestamp = juint(retjson,"time");
                    free_json(retjson);
                }
                free(blockhashstr);
            }
        }
        else
        {
            if ( (retjson= electrum_getheader(coin->symbol,ep,&retjson,height)) != 0 )
            {
                //printf("%s\n",jprint(retjson,0));
                timestamp = juint(retjson,"timestamp");
                free_json(retjson);
            }
        }
    }
    return(timestamp);
}

cJSON *LP_blockjson(int32_t *heightp,char *symbol,char *blockhashstr,int32_t height)
{
    cJSON *json = 0; int32_t flag = 0; struct iguana_info *coin;
    *heightp = 0;
    if ( symbol == 0 || symbol[0] == 0 )
        return(cJSON_Parse("{\"error\":\"null symbol\"}"));
    coin = LP_coinfind(symbol);
    if ( coin == 0 || coin->electrum != 0 )
    {
        printf("unexpected electrum path for %s\n",symbol);
        return(0);
    }
    if ( blockhashstr == 0 )
        blockhashstr = LP_blockhashstr(symbol,height), flag = 1;
    if ( blockhashstr != 0 )
    {
        if ( (json= LP_getblockhashstr(symbol,blockhashstr)) != 0 )
        {
            if ( *heightp != 0 )
            {
                *heightp = juint(json,"height");
                if ( height >= 0 && *heightp != height )
                {
                    //printf("unexpected height %d vs %d for %s (%s)\n",*heightp,height,blockhashstr,jprint(json,0));
                    *heightp = -1;
                    free_json(json);
                    json = 0;
                }
            }
        }
        if ( flag != 0 && blockhashstr != 0 )
            free(blockhashstr);
    }
    return(json);
}

const char *Notaries_elected[][2] =
{
    { "0_jl777_testA", "03b7621b44118017a16043f19b30cc8a4cfe068ac4e42417bae16ba460c80f3828" },
    { "0_jl777_testB", "02ebfc784a4ba768aad88d44d1045d240d47b26e248cafaf1c5169a42d7a61d344" },
    { "0_kolo_testA", "0287aa4b73988ba26cf6565d815786caf0d2c4af704d7883d163ee89cd9977edec" },
    { "artik_AR", "029acf1dcd9f5ff9c455f8bb717d4ae0c703e089d16cf8424619c491dff5994c90" },
    { "artik_EU", "03f54b2c24f82632e3cdebe4568ba0acf487a80f8a89779173cdb78f74514847ce" },
    { "artik_NA", "0224e31f93eff0cc30eaf0b2389fbc591085c0e122c4d11862c1729d090106c842" },
    { "artik_SH", "02bdd8840a34486f38305f311c0e2ae73e84046f6e9c3dd3571e32e58339d20937" },
    { "badass_EU", "0209d48554768dd8dada988b98aca23405057ac4b5b46838a9378b95c3e79b9b9e" },
    { "badass_NA", "02afa1a9f948e1634a29dc718d218e9d150c531cfa852843a1643a02184a63c1a7" },
    { "badass_SH", "026b49dd3923b78a592c1b475f208e23698d3f085c4c3b4906a59faf659fd9530b" },
    { "crackers_EU", "03bc819982d3c6feb801ec3b720425b017d9b6ee9a40746b84422cbbf929dc73c3" }, // 10
    { "crackers_NA", "03205049103113d48c7c7af811b4c8f194dafc43a50d5313e61a22900fc1805b45" },
    { "crackers_SH", "02be28310e6312d1dd44651fd96f6a44ccc269a321f907502aae81d246fabdb03e" },
    { "durerus_EU", "02bcbd287670bdca2c31e5d50130adb5dea1b53198f18abeec7211825f47485d57" },
    { "etszombi_AR", "031c79168d15edabf17d9ec99531ea9baa20039d0cdc14d9525863b83341b210e9" },
    { "etszombi_EU", "0281b1ad28d238a2b217e0af123ce020b79e91b9b10ad65a7917216eda6fe64bf7" },
    { "etszombi_SH", "025d7a193c0757f7437fad3431f027e7b5ed6c925b77daba52a8755d24bf682dde" },
    { "farl4web_EU", "0300ecf9121cccf14cf9423e2adb5d98ce0c4e251721fa345dec2e03abeffbab3f" },
    { "farl4web_SH", "0396bb5ed3c57aa1221d7775ae0ff751e4c7dc9be220d0917fa8bbdf670586c030" },
    { "fullmoon_AR", "0254b1d64840ce9ff6bec9dd10e33beb92af5f7cee628f999cb6bc0fea833347cc" },
    { "fullmoon_NA", "031fb362323b06e165231c887836a8faadb96eda88a79ca434e28b3520b47d235b" }, // 20
    { "fullmoon_SH", "030e12b42ec33a80e12e570b6c8274ce664565b5c3da106859e96a7208b93afd0d" },
    { "grewal_NA", "03adc0834c203d172bce814df7c7a5e13dc603105e6b0adabc942d0421aefd2132" },
    { "grewal_SH", "03212a73f5d38a675ee3cdc6e82542a96c38c3d1c79d25a1ed2e42fcf6a8be4e68" },
    { "indenodes_AR", "02ec0fa5a40f47fd4a38ea5c89e375ad0b6ddf4807c99733c9c3dc15fb978ee147" },
    { "indenodes_EU", "0221387ff95c44cb52b86552e3ec118a3c311ca65b75bf807c6c07eaeb1be8303c" },
    { "indenodes_NA", "02698c6f1c9e43b66e82dbb163e8df0e5a2f62f3a7a882ca387d82f86e0b3fa988" },
    { "indenodes_SH", "0334e6e1ec8285c4b85bd6dae67e17d67d1f20e7328efad17ce6fd24ae97cdd65e" },
    { "jeezy_EU", "023cb3e593fb85c5659688528e9a4f1c4c7f19206edc7e517d20f794ba686fd6d6" },
    { "jsgalt_NA", "027b3fb6fede798cd17c30dbfb7baf9332b3f8b1c7c513f443070874c410232446" },
    { "karasugoi_NA", "02a348b03b9c1a8eac1b56f85c402b041c9bce918833f2ea16d13452309052a982" }, // 30
    { "kashifali_EU", "033777c52a0190f261c6f66bd0e2bb299d30f012dcb8bfff384103211edb8bb207" },
    { "kolo_AR", "03016d19344c45341e023b72f9fb6e6152fdcfe105f3b4f50b82a4790ff54e9dc6" },
    { "kolo_SH", "02aa24064500756d9b0959b44d5325f2391d8e95c6127e109184937152c384e185" },
    { "metaphilibert_AR", "02adad675fae12b25fdd0f57250b0caf7f795c43f346153a31fe3e72e7db1d6ac6" },
    { "movecrypto_AR", "022783d94518e4dc77cbdf1a97915b29f427d7bc15ea867900a76665d3112be6f3" },
    { "movecrypto_EU", "021ab53bc6cf2c46b8a5456759f9d608966eff87384c2b52c0ac4cc8dd51e9cc42" },
    { "movecrypto_NA", "02efb12f4d78f44b0542d1c60146738e4d5506d27ec98a469142c5c84b29de0a80" },
    { "movecrypto_SH", "031f9739a3ebd6037a967ce1582cde66e79ea9a0551c54731c59c6b80f635bc859" },
    { "muros_AR", "022d77402fd7179335da39479c829be73428b0ef33fb360a4de6890f37c2aa005e" },
    { "noashh_AR", "029d93ef78197dc93892d2a30e5a54865f41e0ca3ab7eb8e3dcbc59c8756b6e355" }, // 40
    { "noashh_EU", "02061c6278b91fd4ac5cab4401100ffa3b2d5a277e8f71db23401cc071b3665546" },
    { "noashh_NA", "033c073366152b6b01535e15dd966a3a8039169584d06e27d92a69889b720d44e1" },
    { "nxtswe_EU", "032fb104e5eaa704a38a52c126af8f67e870d70f82977e5b2f093d5c1c21ae5899" },
    { "polycryptoblog_NA", "02708dcda7c45fb54b78469673c2587bfdd126e381654819c4c23df0e00b679622" },
    { "pondsea_AR", "032e1c213787312099158f2d74a89e8240a991d162d4ce8017d8504d1d7004f735" },
    { "pondsea_EU", "0225aa6f6f19e543180b31153d9e6d55d41bc7ec2ba191fd29f19a2f973544e29d" },
    { "pondsea_NA", "031bcfdbb62268e2ff8dfffeb9ddff7fe95fca46778c77eebff9c3829dfa1bb411" },
    { "pondsea_SH", "02209073bc0943451498de57f802650311b1f12aa6deffcd893da198a544c04f36" },
    { "popcornbag_AR", "02761f106fb34fbfc5ddcc0c0aa831ed98e462a908550b280a1f7bd32c060c6fa3" },
    { "popcornbag_NA", "03c6085c7fdfff70988fda9b197371f1caf8397f1729a844790e421ee07b3a93e8" }, // 50
    { "ptytrader_NA", "0328c61467148b207400b23875234f8a825cce65b9c4c9b664f47410b8b8e3c222" },
    { "ptytrader_SH", "0250c93c492d8d5a6b565b90c22bee07c2d8701d6118c6267e99a4efd3c7748fa4" },
    { "rnr_AR", "029bdb08f931c0e98c2c4ba4ef45c8e33a34168cb2e6bf953cef335c359d77bfcd" },
    { "rnr_EU", "03f5c08dadffa0ffcafb8dd7ffc38c22887bd02702a6c9ac3440deddcf2837692b" },
    { "rnr_NA", "02e17c5f8c3c80f584ed343b8dcfa6d710dfef0889ec1e7728ce45ce559347c58c" },
    { "rnr_SH", "037536fb9bdfed10251f71543fb42679e7c52308bcd12146b2568b9a818d8b8377" },
    { "titomane_AR", "03cda6ca5c2d02db201488a54a548dbfc10533bdc275d5ea11928e8d6ab33c2185" },
    { "titomane_EU", "02e41feded94f0cc59f55f82f3c2c005d41da024e9a805b41105207ef89aa4bfbd" },
    { "titomane_SH", "035f49d7a308dd9a209e894321f010d21b7793461b0c89d6d9231a3fe5f68d9960" },
    { "vanbreuk_EU", "024f3cad7601d2399c131fd070e797d9cd8533868685ddbe515daa53c2e26004c3" }, // 60
    { "xrobesx_NA", "03f0cc6d142d14a40937f12dbd99dbd9021328f45759e26f1877f2a838876709e1" },
    { "xxspot1_XX", "02ef445a392fcaf3ad4176a5da7f43580e8056594e003eba6559a713711a27f955" },
    { "xxspot2_XX", "03d85b221ea72ebcd25373e7961f4983d12add66a92f899deaf07bab1d8b6f5573" }
};

int32_t LP_txhasnotarization(bits256 *notarizedhashp,struct iguana_info *coin,bits256 txid)
{
    cJSON *txobj,*vins,*vin,*vouts,*vout,*spentobj,*sobj; char *hexstr; uint8_t script[1024]; bits256 spenttxid; uint64_t notarymask; int32_t i,j,numnotaries,len,spentvout,numvins,numvouts,hasnotarization = 0;
    memset(notarizedhashp,0,sizeof(*notarizedhashp));
    if ( (txobj= LP_gettx("LP_txhasnotarization",coin->symbol,txid,0)) != 0 )
    {
        if ( (vins= jarray(&numvins,txobj,"vin")) != 0 )
        {
            if ( numvins >= DPOW_MIN_ASSETCHAIN_SIGS )
            {
                notarymask = numnotaries = 0;
                for (i=0; i<numvins; i++)
                {
                    vin = jitem(vins,i);
                    spenttxid = jbits256(vin,"txid");
                    spentvout = jint(vin,"vout");
                    if ( (spentobj= LP_gettx("LP_txhasnotarization",coin->symbol,spenttxid,0)) != 0 )
                    {
                        if ( (vouts= jarray(&numvouts,spentobj,"vout")) != 0 )
                        {
                            if ( spentvout < numvouts )
                            {
                                vout = jitem(vouts,spentvout);
                                if ( (sobj= jobj(vout,"scriptPubKey")) != 0 && (hexstr= jstr(sobj,"hex")) != 0 && (len= is_hexstr(hexstr,0)) == 35*2 )
                                {
                                    len >>= 1;
                                    decode_hex(script,len,hexstr);
                                    if ( script[0] == 33 && script[34] == 0xac )
                                    {
                                        for (j=0; j<sizeof(Notaries_elected)/sizeof(*Notaries_elected); j++)
                                        {
                                            if ( strncmp(Notaries_elected[j][1],hexstr+2,66) == 0 )
                                            {
                                                if ( ((1LL << j) & notarymask) == 0 )
                                                {
                                                    //printf("n%d ",j);
                                                    numnotaries++;
                                                    notarymask |= (1LL << j);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        free_json(spentobj);
                    }
                }
                if ( numnotaries > 0 )
                {
                    if ( numnotaries >= DPOW_MIN_ASSETCHAIN_SIGS )
                        hasnotarization = 1;
                    //printf("numnotaries.%d %s hasnotarization.%d\n",numnotaries,coin->symbol,hasnotarization);
                }
            }
        }
        if ( (vouts= jarray(&numvouts,txobj,"vout")) != 0 )
        {
            vout = jitem(vouts,1);
            if ( (sobj= jobj(vout,"scriptPubKey")) != 0 && (hexstr= jstr(sobj,"hex")) != 0 && (len= is_hexstr(hexstr,0)) >= 35 )
            {
                len >>= 1;
                decode_hex(script,len,hexstr);
                iguana_rwbignum(0,&script[2],32,(uint8_t *)notarizedhashp);
            }
        }
        free_json(txobj);
    }
    return(hasnotarization);
}

int32_t LP_notarization_validate(char *symbol,int32_t notarized,bits256 notarizedhash,bits256 notarizationtxid)
{
    struct iguana_info *coin; int32_t valid = 0; cJSON *blockjson; bits256 notarizedhash2; char str[65],str2[65];
    if ( strcmp(symbol,"KMD") == 0 )
        coin = LP_coinfind("BTC");
    else coin = LP_coinfind("KMD");
    if ( coin != 0 )
    {
        if (LP_txhasnotarization(&notarizedhash2,coin,notarizationtxid) == 0 )
        {
            printf("missing %s notarization txid %s\n",symbol,bits256_str(str,notarizationtxid));
            return(-1);
        }
        else if ( bits256_cmp(notarizedhash,notarizedhash2) != 0 )
        {
            printf("mismatched %s notarizedhash %s vs %s\n",symbol,bits256_str(str,notarizedhash),bits256_str(str2,notarizedhash2));
            return(-1);
        }
    }
    if ( (coin= LP_coinfind(symbol)) != 0 )
    {
        if ( coin->electrum == 0 )
        {
            if ( (blockjson= LP_getblock(coin->symbol,notarizedhash)) != 0 )
            {
                if ( jint(blockjson,"height") != notarized )
                    valid = 1;
                free_json(blockjson);
            }
        }
        else
        {
            if ( (blockjson= electrum_getheader(symbol,coin->electrum,&blockjson,notarized+1)) != 0 )
            {
                notarizedhash2 = jbits256(blockjson,"prev_block_hash");
                if ( bits256_cmp(notarizedhash,notarizedhash2) == 0 )
                    valid = 1;
                free_json(blockjson);
            }
        }
    }
    if ( valid == 1 )
        return(0);
    else return(-1);
}

int32_t LP_hasnotarization(struct iguana_info *coin,cJSON *blockjson)
{
    int32_t i,n,hasnotarization = 0; bits256 txid,notarizedhash; cJSON *txarray;
    if ( (txarray= jarray(&n,blockjson,"tx")) != 0 )
    {
        for (i=0; i<n; i++)
        {
            txid = jbits256i(txarray,i);
            hasnotarization += LP_txhasnotarization(&notarizedhash,coin,txid);
        }
    }
    return(hasnotarization);
}

int32_t LP_notarization_latest(int32_t *bestheightp,struct iguana_info *coin)
{
    cJSON *blockjson; bits256 blockhash; int32_t height=-1,hasnotarization;
    *bestheightp = -1;
    memset(blockhash.bytes,0,sizeof(blockhash));
    while ( 1 )
    {
        if ( bits256_nonz(blockhash) == 0 )
            blockhash = LP_getbestblockhash(coin);
        if ( bits256_nonz(blockhash) != 0 )
        {
            if ( (blockjson= LP_getblock(coin->symbol,blockhash)) != 0 )
            {
                if ( *bestheightp < 0 )
                    *bestheightp = jint(blockjson,"height");
                if ( (hasnotarization= LP_hasnotarization(coin,blockjson)) > 0 )
                {
                    height = jint(blockjson,"height");
                    //char str[65]; printf("%s height.%d\n",bits256_str(str,blockhash),height);
                }
                else
                {
                    blockhash = jbits256(blockjson,"previousblockhash");
                    if ( bits256_nonz(blockhash) == 0 )
                    {
                        //printf("null prev.(%s)\n",jprint(blockjson,0));
                        free_json(blockjson);
                        break;
                    }
                }
                free_json(blockjson);
                if ( height > 0 )
                    break;
            }
        } else break;
    }
    return(height);
}
