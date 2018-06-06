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

// compare multiple rawtx returns

#include "iguana777.h"

char *iguana_APIrequest(struct iguana_info *coin,bits256 blockhash,bits256 txid,int32_t seconds)
{
    int32_t i,len; char *retstr = 0; uint8_t serialized[1024]; char str[65];
    coin->APIblockhash = blockhash;
    coin->APItxid = txid;
    printf("request block.(%s) txid.%llx\n",bits256_str(str,blockhash),(long long)txid.txid);
    if ( (len= iguana_getdata(coin,serialized,MSG_BLOCK,&blockhash,1)) > 0 )
    {
        for (i=0; i<seconds; i++)
        {
            if ( i == 0 )
                iguana_send(coin,0,serialized,len);
            if ( coin->APIblockstr != 0 )
            {
                retstr = coin->APIblockstr;
                coin->APIblockstr = 0;
                memset(&coin->APIblockhash,0,sizeof(coin->APIblockhash));
                memset(&coin->APItxid,0,sizeof(coin->APItxid));
                return(retstr);
            }
            sleep(1);
        }
    }
    return(0);
}

bits256 iguana_str2priv(struct supernet_info *myinfo,struct iguana_info *coin,char *str)
{
    bits256 privkey; int32_t n; uint8_t addrtype; struct iguana_waccount *wacct=0; struct iguana_waddress *waddr;
    memset(&privkey,0,sizeof(privkey));
    if ( str != 0 )
    {
        n = (int32_t)strlen(str) >> 1;
        if ( n == sizeof(bits256) && is_hexstr(str,sizeof(bits256)) > 0 )
            decode_hex(privkey.bytes,sizeof(privkey),str);
        else if ( bitcoin_wif2priv(&addrtype,&privkey,str) != sizeof(bits256) )
        {
            if ( (waddr= iguana_waddresssearch(myinfo,&wacct,str)) != 0 )
                privkey = waddr->privkey;
            else memset(privkey.bytes,0,sizeof(privkey));
        }
    }
    return(privkey);
}

int32_t iguana_pubkeyget(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t *pubkey33,char *str)
{
    bits256 privkey,pubkey; uint8_t pubkeydata[128]; int32_t len,plen= -1; struct iguana_waccount *wacct; struct iguana_waddress *waddr;
    len = (int32_t)strlen(str);
    if ( is_hexstr(str,len) == 0 )
    {
        if ( (waddr= iguana_waddresssearch(myinfo,&wacct,str)) != 0 )
        {
            if ( (plen= bitcoin_pubkeylen(waddr->pubkey)) > 0 )
                memcpy(pubkeydata,waddr->pubkey,plen);
        }
    }
    else
    {
        decode_hex(pubkeydata,len,str);
        plen = bitcoin_pubkeylen(pubkeydata);
    }
    if ( plen <= 0 )
    {
        privkey = iguana_str2priv(myinfo,coin,str);
        if ( bits256_nonz(privkey) == 0 )
            return(-1);
        else
        {
            pubkey = bitcoin_pubkey33(myinfo->ctx,pubkeydata,privkey);
            if ( bits256_nonz(pubkey) == 0 )
                return(-1);
        }
    }
    if ( (plen= bitcoin_pubkeylen(pubkeydata)) > 0 )
        memcpy(pubkey33,pubkeydata,plen);
    return(0);
}

cJSON *iguana_p2shjson(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *retjson,struct iguana_waddress *waddr)
{
    char str[4096]; uint8_t type; struct iguana_waccount *wacct; bits256 debugtxid; struct vin_info V; cJSON *privkeys,*pubkeys,*addresses; int32_t i,plen;
    if ( retjson == 0 )
        retjson = cJSON_CreateObject();
    init_hexbytes_noT(str,waddr->redeemScript,waddr->scriptlen);
    jaddstr(retjson,"redeemScript",str);
    memset(debugtxid.bytes,0,sizeof(debugtxid));
    if ( (type= iguana_calcrmd160(coin,0,&V,waddr->redeemScript,waddr->scriptlen, debugtxid,-1,0xffffffff)) >= 0 )
    {
        privkeys = cJSON_CreateArray();
        pubkeys = cJSON_CreateArray();
        addresses = cJSON_CreateArray();
        for (i=0; i<V.N; i++)
        {
            if ( V.signers[i].coinaddr[0] != 0 && (waddr= iguana_waddresssearch(myinfo,&wacct,V.signers[i].coinaddr)) != 0 && waddr->wifstr[0] != 0 )
                jaddistr(privkeys,waddr->wifstr);
            else jaddistr(privkeys,"");
            if ( (plen= bitcoin_pubkeylen(V.signers[i].pubkey)) > 0 )
            {
                init_hexbytes_noT(str,V.signers[i].pubkey,plen);
                jaddistr(pubkeys,str);
            } else jaddistr(pubkeys,"");
            jaddistr(addresses,V.signers[i].coinaddr);
        }
        jaddstr(retjson,"result",V.coinaddr);
        jaddnum(retjson,"M",V.M);
        jaddnum(retjson,"N",V.N);
        jadd(retjson,"pubkeys",pubkeys);
        jadd(retjson,"privkeys",privkeys);
        jadd(retjson,"addresses",addresses);
    }
    return(retjson);
}

cJSON *iguana_scriptobj(struct iguana_info *coin,uint8_t rmd160[20],char *coinaddr,char *asmstr,uint8_t *script,int32_t scriptlen)
{
    struct vin_info V; int32_t i,plen,asmtype; char pubkeystr[130],rmdstr[41]; cJSON *addrobj,*scriptobj=cJSON_CreateObject();
    if ( (asmtype= iguana_calcrmd160(coin,asmstr,&V,script,scriptlen,rand256(0),1,0xffffffff)) >= 0 )
    {
        if ( asmstr != 0 && asmstr[0] != 0 )
            jaddstr(scriptobj,"asm",asmstr);
        jaddnum(scriptobj,"iguanatype",asmtype);
        jaddnum(scriptobj,"scriptlen",scriptlen);
        jaddnum(scriptobj,"reqSigs",V.M);
        if ( (plen= bitcoin_pubkeylen(V.signers[0].pubkey)) > 0 )
        {
            init_hexbytes_noT(pubkeystr,V.signers[0].pubkey,plen);
            jaddstr(scriptobj,"pubkey",pubkeystr);
            init_hexbytes_noT(rmdstr,V.signers[0].rmd160,20);
            jaddstr(scriptobj,"rmd160",rmdstr);
        }
        addrobj = cJSON_CreateArray();
        for (i=0; i<V.N; i++)
            jaddistr(addrobj,V.signers[i].coinaddr);
        jadd(scriptobj,"addresses",addrobj);
        if ( scriptlen != 0 )
        {
            bitcoin_address(coinaddr,coin->chain->p2shtype,script,scriptlen);
            jaddstr(scriptobj,"p2sh",coinaddr);
        }
        memcpy(rmd160,V.rmd160,20);
    }
    return(scriptobj);
}

int32_t iguana_RTbestunspent(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *aboveip,int64_t *abovep,int32_t *belowip,int64_t *belowp,struct iguana_outpoint *unspents,int32_t numunspents,uint64_t value,int32_t maxmode)
{
    int32_t i,abovei,belowi; int64_t above,below,gap,atx_value,maxvalue = 0;
    abovei = belowi = -1;
    for (above=below=i=0; i<numunspents; i++)
    {
        if ( (atx_value= unspents[i].value) <= 0 )
        {
            //printf("illegal value.%d\n",i);
            continue;
        }
        if ( iguana_RTunspent_check(myinfo,coin,unspents[i]) != 0 )
        {
            //printf("(%d u%d) %.8f already used\n",unspents[i].hdrsi,unspents[i].unspentind,dstr(atx_value));
            continue;
        }
        if ( maxmode == 0 )
        {
            //printf("(%.8f vs %.8f)\n",dstr(atx_value),dstr(value));
            if ( atx_value == value )
            {
                *aboveip = *belowip = i;
                *abovep = *belowp = 0;
                return(i);
            }
            else if ( atx_value > value )
            {
                gap = (atx_value - value);
                if ( above == 0 || gap < above )
                {
                    above = gap;
                    abovei = i;
                }
            } else gap = (value - atx_value);
            if ( below == 0 || gap < below )
            {
                below = gap;
                belowi = i;
            }
        }
        else
        {
            //printf("(%.8f vs %.8f)\n",dstr(atx_value),dstr(maxvalue));
            if ( atx_value > maxvalue )
            {
                maxvalue = atx_value;
                above = (atx_value - value);
                abovei = i;
            }
        }
    }
    *aboveip = abovei;
    *abovep = above;
    *belowip = belowi;
    *belowp = below;
    //printf("above.%d below.%d\n",abovei,belowi);
    return(abovei >= 0 ? abovei : belowi);
}

cJSON *iguana_inputjson(bits256 txid,int32_t vout,uint8_t *spendscript,int32_t spendlen)
{
    char hexstr[IGUANA_MAXSCRIPTSIZE*2 + 1]; cJSON *sobj,*item = cJSON_CreateObject();
    jaddbits256(item,"txid",txid);
    jaddnum(item,"vout",vout);
    sobj = cJSON_CreateObject();
    init_hexbytes_noT(hexstr,spendscript,spendlen);
    jaddstr(sobj,"hex",hexstr);
    jadd(item,"scriptPubKey",sobj);
    return(item);
}

cJSON *iguana_RTinputsjson(struct supernet_info *myinfo,struct iguana_info *coin,uint64_t *totalp,uint64_t amount,struct iguana_outpoint *unspents,int32_t num,int32_t maxmode)
{
    struct iguana_outpoint outpt; cJSON *vins; int32_t abovei,belowi,i,ind; int64_t above,below,total = 0,remains = amount;
    *totalp = 0;
    vins = cJSON_CreateArray();
    for (i=0; i<num; i++)
    {
        below = above = 0;
        if ( iguana_RTbestunspent(myinfo,coin,&abovei,&above,&belowi,&below,unspents,num,remains,maxmode) < 0 )
        {
            printf("error finding unspent i.%d of %d, %.8f vs %.8f\n",i,num,dstr(remains),dstr(amount));
            free_json(vins);
            return(0);
        }
        if ( belowi < 0 || (num == 0 && abovei >= 0) )
            ind = abovei;
        else ind = belowi;
        outpt = unspents[ind];
        memset(&unspents[ind],0,sizeof(unspents[ind]));
        jaddi(vins,iguana_inputjson(outpt.txid,outpt.vout,outpt.spendscript,outpt.spendlen));
        total += outpt.value;
        remains -= outpt.value;
        //printf("%s value %.8f -> remains %.8f\n",coinaddr,dstr(value),dstr(remains));
        if ( remains <= 0 )
            break;
    }
    *totalp = total;
    return(vins);
}

char *iguana_signrawtx(struct supernet_info *myinfo,struct iguana_info *coin,int32_t height,bits256 *signedtxidp,int32_t *completedp,cJSON *vins,char *rawtx,cJSON *privkeys,struct vin_info *V)
{
    char *signedtx = 0; struct iguana_msgtx msgtx; int32_t numinputs,flagV = 0,flag = 0;
    *completedp = 0;
    if ( privkeys == 0 )
        privkeys = iguana_privkeysjson(myinfo,coin,vins), flag = 1;
    if ( (numinputs= cJSON_GetArraySize(vins)) > 0 && privkeys != 0 )
    {
        memset(&msgtx,0,sizeof(msgtx));
        if ( V == 0 )
            V = calloc(numinputs,sizeof(*V)), flagV = 1;
        //printf("SIGN.(%s) priv.(%s) %llx %llx (%s)\n",jprint(vins,0),jprint(privkeys,0),(long long)V->signers[0].privkey.txid,(long long)V->signers[1].privkey.txid,vins!=0?jprint(vins,0):"no vins");
        if ( V != 0 )
        {
            if ( iguana_signrawtransaction(myinfo,coin,height,&msgtx,&signedtx,signedtxidp,V,numinputs,rawtx,vins,privkeys) > 0 )
                *completedp = 1;
            else printf("signrawtransaction incomplete\n");
            //for (i=0; i<msgtx.tx_in; i++)
            //    if ( msgtx.vins[i].redeemscript != 0 )
            //        free(msgtx.vins[i].redeemscript), msgtx.vins[i].redeemscript = 0;
            if ( flagV != 0 )
                free(V);
        }
        if ( flag != 0 )
            free_json(privkeys);
    }
    //char str[65]; printf("completed.%d %s signed.(%s)\n",*completedp,bits256_str(str,*signedtxidp),signedtx!=0?signedtx:"");
    return(signedtx);
}

bits256 iguana_sendrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *signedtx)
{
    bits256 txid,checktxid; uint8_t *serialized; int32_t i,len,n; struct iguana_peer *addr; cJSON *vals; char *str;
    len = (int32_t)strlen(signedtx) >> 1;
    serialized = calloc(1,sizeof(struct iguana_msghdr) + len);
    decode_hex(&serialized[sizeof(struct iguana_msghdr)],len,signedtx);
    txid = bits256_doublesha256(0,&serialized[sizeof(struct iguana_msghdr)],len);
    if ( coin->FULLNODE < 0 || coin->notarychain >= 0 )
    {
        if ( coin->FULLNODE < 0 )
            str = dpow_sendrawtransaction(myinfo,coin,signedtx);
        else str = _dex_sendrawtransaction(myinfo,coin->symbol,signedtx);
        if ( str != 0 )
        {
            if ( is_hexstr(str,0) == sizeof(checktxid)*2 )
            {
                decode_hex(checktxid.bytes,sizeof(checktxid),str);
                if ( bits256_cmp(txid,checktxid) == 0 )
                {
                    free(str);
                    return(txid);
                }
            }
            free(str);
            memset(txid.bytes,0,sizeof(txid));
            return(txid);
        }
    }
    if ( coin->peers != 0 && (n= coin->peers->numranked) > 0 )
    {
        for (i=0; i<8 && i<n; i++)
        {
            if ( (addr= coin->peers->ranked[i]) != 0 && addr->dead == 0 && addr->usock >= 0 )
                iguana_queue_send(addr,0,serialized,"tx",len);
        }
    }
    else
    {
        vals = cJSON_CreateObject();
        jaddstr(vals,"symbol",coin->symbol);
        if ( (str= gecko_sendrawtransaction(myinfo,coin->symbol,serialized,len,txid,vals,signedtx)) != 0 )
            free(str);
        free_json(vals);
    }
    free(serialized);
    return(txid);
}

uint64_t _iguana_interest(uint32_t now,int32_t txheight,uint32_t txlocktime,uint64_t value)
{
    int32_t minutes; uint64_t numerator=0,denominator=0,interest=0; uint32_t activation = 1491350400;
    if ( txheight >= 7777777 )
        return(0);
    if ( (minutes= ((uint32_t)time(NULL) - 60 - txlocktime) / 60) >= 60 )
    {
        if ( minutes > 365 * 24 * 60 )
            minutes = 365 * 24 * 60;
        if ( txheight >= 250000 )
            minutes -= 59;
        denominator = (((uint64_t)365 * 24 * 60) / minutes);
        if ( denominator == 0 )
            denominator = 1; // max KOMODO_INTEREST per transfer, do it at least annually!
        if ( value > 25000LL*SATOSHIDEN && txheight > 155949 )
        {
            numerator = (value / 20); // assumes 5%!
            if ( txheight < 250000 )
                interest = (numerator / denominator);
            else interest = (numerator * minutes) / ((uint64_t)365 * 24 * 60);
        }
        else if ( value >= 10*SATOSHIDEN )
        {
            /*numerator = (value * KOMODO_INTEREST);
            if ( txheight < 250000 || numerator * minutes < 365 * 24 * 60 )
                interest = (numerator / denominator) / SATOSHIDEN;
            else interest = ((numerator * minutes) / ((uint64_t)365 * 24 * 60)) / SATOSHIDEN;*/
            numerator = (value * KOMODO_INTEREST);
            if ( txheight < 250000 || now < activation )
            {
                if ( txheight < 250000 || numerator * minutes < 365 * 24 * 60 )
                    interest = (numerator / denominator) / SATOSHIDEN;
                else interest = ((numerator * minutes) / ((uint64_t)365 * 24 * 60)) / SATOSHIDEN;
            }
            else
            {
                numerator = (value / 20); // assumes 5%!
                interest = ((numerator * minutes) / ((uint64_t)365 * 24 * 60));
                //fprintf(stderr,"interest %llu %.8f <- numerator.%llu minutes.%d\n",(long long)interest,(double)interest/COIN,(long long)numerator,(int32_t)minutes);
            }
        }
        //fprintf(stderr,"komodo_interest.%d %lld %.8f nLockTime.%u tiptime.%u minutes.%d interest %lld %.8f (%llu / %llu)\n",txheight,(long long)value,(double)value/SATOSHIDEN,txlocktime,now,minutes,(long long)interest,(double)interest/SATOSHIDEN,(long long)numerator,(long long)denominator);
    }
    return(interest);
}

uint64_t iguana_interest(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid,int32_t vout,uint64_t value)
{
    char *retstr; int32_t height; cJSON *retjson=0; struct iguana_txid T,*tx; uint64_t interest=0;
    if ( coin->FULLNODE < 0 ) // komodod is running
    {
        if ( (retjson= dpow_gettxout(myinfo,coin,txid,vout)) != 0 )
        {
            interest = jdouble(retjson,"interest") * SATOSHIDEN;
            free_json(retjson);
        }
    }
    else if ( coin->FULLNODE == 0 ) // basilisk mode -> use DEX* API
    {
        if ( (retstr= _dex_gettxout(myinfo,coin->symbol,txid,vout)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                interest = jdouble(retjson,"interest") * SATOSHIDEN;
                free_json(retjson);
            }
            free(retstr);
        }
    }
    else // we have it local
    {
        if ( (tx= iguana_txidfind(coin,&height,&T,txid,coin->bundlescount)) != 0 && tx->locktime > LOCKTIME_THRESHOLD )
        {
            interest = _iguana_interest((uint32_t)time(NULL),coin->longestchain,tx->locktime,value);
        }
    }
    return(interest);
}

uint64_t iguana_interests(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *vins)
{
    int32_t i,n; cJSON *item; uint64_t value,interest = 0;
    if ( is_cJSON_Array(vins) != 0 && (n= cJSON_GetArraySize(vins)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(vins,i);
            if ( (value= jdouble(item,"value")*SATOSHIDEN) == 0 )
                value = jdouble(item,"amount")*SATOSHIDEN;
            interest += iguana_interest(myinfo,coin,jbits256(item,"txid"),jint(item,"vout"),value);
        }
    }
    return(interest);
}

char *iguana_calcrawtx(struct supernet_info *myinfo,struct iguana_info *coin,cJSON **vinsp,cJSON *txobj,int64_t satoshis,char *changeaddr,int64_t txfee,cJSON *addresses,int32_t minconf,uint8_t *opreturn,int32_t oplen,int64_t burnamount,char *remoteaddr,struct vin_info *V,int32_t maxmode)
{
    uint8_t addrtype,rmd160[20],spendscript[IGUANA_MAXSCRIPTSIZE]; char *coinaddr; int32_t allocflag=0,max,i,j,m,n,num,spendlen; char *spendscriptstr,*rawtx=0; bits256 txid; cJSON *vins=0,*array,*item; uint64_t value,avail=0,total,change,interest; struct iguana_outpoint *unspents = 0;
    *vinsp = 0;
    max = 0;//10000;
    satoshis += burnamount;
    if ( (n= cJSON_GetArraySize(addresses)) == 0 )
        return(0);
    for (i=0; i<n; i++)
    {
        coinaddr = jstri(addresses,i);
        if ( (array= basilisk_unspents(myinfo,coin,coinaddr)) != 0 )
        {
            //printf("iguana_calcrawtx unspents.(%s) %s\n",coinaddr,jprint(array,0));
            if ( (m= cJSON_GetArraySize(array)) > 0 )
            {
                for (j=0; j<m; j++)
                {
                    item = jitem(array,j);
                    if ( coin->FULLNODE != 0 && is_cJSON_False(jobj(item,"spendable")) != 0 )
                        continue;
                    if ( (spendscriptstr= jstr(item,"scriptPubKey")) == 0 )
                    {
                        printf("no spendscriptstr %d.(%s)\n",i,jprint(array,0));
                        continue;
                    }
                    if ( strlen(spendscriptstr) != 50 || strncmp("76a914",spendscriptstr,6) != 0 || strcmp("88ac",&spendscriptstr[50-4]) != 0 )
                        continue;
//printf("utxo.(%s)\n",jprint(item,0));
                    unspents = realloc(unspents,(1 + max) * sizeof(*unspents));
                    value = jdouble(item,"amount") * SATOSHIDEN;
                    if ( (0) && jdouble(item,"interest") != 0 )
                        printf("utxo has interest of %.8f\n",jdouble(item,"interest"));
                    iguana_outptset(myinfo,coin,&unspents[max++],jbits256(item,"txid"),jint(item,"vout"),value,spendscriptstr);
                    avail += value;
                }
            }
            free_json(array);
        }
    }
    if ( unspents == 0 )
        return(0);
    num = max;
    /*unspents = calloc(max,sizeof(*unspents));
    if ( (num= iguana_RTunspentslists(myinfo,coin,&avail,unspents,max,satoshis+txfee,minconf,addresses,remoteaddr)) <= 0 )
    {
        free(unspents);
        return(0);
    }*/
    printf("avail %.8f satoshis %.8f, txfee %.8f burnamount %.8f vin0.scriptlen %d num.%d\n",dstr(avail),dstr(satoshis),dstr(txfee),dstr(burnamount),unspents[0].spendlen,num);
    if ( txobj != 0 && avail >= satoshis+txfee )
    {
        if ( (vins= iguana_RTinputsjson(myinfo,coin,&total,satoshis + txfee,unspents,num,maxmode)) != 0 )
        {
            if ( strcmp(coin->symbol,"KMD") == 0 )
            {
                if ( (interest= iguana_interests(myinfo,coin,vins)) != 0 )
                {
                    total += interest;
                    printf("boost total by interest %.8f\n",dstr(interest));
                }
            }
            if ( total < (satoshis + txfee) )
            {
                free_json(vins);
                free(unspents);
                printf("insufficient total %.8f vs (%.8f + %.8f)\n",dstr(total),dstr(satoshis),dstr(txfee));
                return(0);
            }
            if ( (change= (total - (satoshis + txfee))) > 10000 && (changeaddr == 0 || changeaddr[0] == 0) )
            {
                printf("no changeaddr for %.8f\n",dstr(change));
                free_json(vins);
                free(unspents);
                return(0);
            }
            iguana_createvins(myinfo,coin,txobj,vins);
            if ( change > 10000 )
            {
                if ( iguana_addressvalidate(coin,&addrtype,changeaddr) < 0 )
                {
                    free_json(vins);
                    free(unspents);
                    printf("illegal destination address.(%s)\n",changeaddr);
                    return(0);
                }
                bitcoin_addr2rmd160(&addrtype,rmd160,changeaddr);
                spendlen = bitcoin_standardspend(spendscript,0,rmd160);
                bitcoin_txoutput(txobj,spendscript,spendlen,change);
                if ( opreturn != 0 )
                {
                    int32_t i;
                    for (i=0; i<oplen; i++)
                        printf("%02x",opreturn[i]);
                    printf(" <- got opret\n");
                    bitcoin_txoutput(txobj,opreturn,oplen,burnamount);
                }
            }
            printf("total %.8f txfee %.8f change %.8f\n",dstr(total),dstr(txfee),dstr(change));
            if ( vins != 0 && V == 0 )
            {
                V = calloc(cJSON_GetArraySize(vins),sizeof(*V)), allocflag = 1;
                //iguana_vinprivkeys(myinfo,coin,V,vins);
            }
            rawtx = bitcoin_json2hex(myinfo,coin,&txid,txobj,V);
            if ( allocflag != 0 )
                free(V);
        }
    }
    free(unspents);
    *vinsp = vins;
    return(rawtx);
}

char *iguana_calcutxorawtx(struct supernet_info *myinfo,struct iguana_info *coin,cJSON **vinsp,cJSON *txobj,int64_t *outputs,int32_t numoutputs,char *changeaddr,int64_t txfee,cJSON *utxos,char *remoteaddr,struct vin_info *V,int32_t maxmode)
{
    uint8_t addrtype,rmd160[20],spendscript[IGUANA_MAXSCRIPTSIZE]; int32_t allocflag=0,max,i,n,num,spendlen; char *spendscriptstr,*rawtx=0; uint64_t satoshis = 0; bits256 txid; cJSON *sobj,*vins=0,*item; uint64_t value,avail=0,total,change,interests; struct iguana_outpoint *unspents = 0;
    *vinsp = 0;
    max = 0;
    interests = 0;
    for (i=0; i<numoutputs; i++)
        satoshis += outputs[i];
    if ( (n= cJSON_GetArraySize(utxos)) == 0 )
    {
        fprintf(stderr,"iguana_calcutxorawtx: no utxos provided?\n");
        return(0);
    }
    for (i=0; i<n; i++)
    {
        item = jitem(utxos,i);
        if ( (spendscriptstr= jstr(item,"scriptPubKey")) != 0 && is_hexstr(spendscriptstr,0) > 16 )
        {
            
        }
        else if ( (sobj= jobj(item,"scriptPubKey")) == 0 || (spendscriptstr= jstr(sobj,"hex")) == 0 )
        {
            printf("no spendscript (%s)\n",jprint(item,0));
            continue;
        }
        unspents = realloc(unspents,(1 + max) * sizeof(*unspents));
        if ( (value= jdouble(item,"value") * SATOSHIDEN) == 0 )
            value = jdouble(item,"amount") * SATOSHIDEN;
        interests += SATOSHIDEN * jdouble(item,"interest");
        //printf("(%s) ",jprint(item,0));
        iguana_outptset(myinfo,coin,&unspents[max++],jbits256(item,"txid"),jint(item,"vout"),value,spendscriptstr);
        avail += value;
    }
    if ( unspents == 0 )
        return(0);
    num = max;
    printf("avail %.8f interests %.8f satoshis %.8f, txfee %.8f vin0.scriptlen %d\n",dstr(avail),dstr(interests),dstr(satoshis),dstr(txfee),unspents[0].spendlen);
    if ( txobj != 0 && avail >= satoshis+txfee )
    {
        if ( (vins= iguana_RTinputsjson(myinfo,coin,&total,satoshis + txfee,unspents,num,maxmode)) != 0 )
        {
            if ( strcmp(coin->symbol,"KMD") == 0 )
            {
                if ( (interests= iguana_interests(myinfo,coin,vins)) != 0 )
                {
                    total += interests;
                    printf("boost total by interest %.8f\n",dstr(interests));
                }
            }
            if ( total < (satoshis + txfee) )
            {
                free_json(vins);
                free(unspents);
                printf("insufficient total %.8f vs (%.8f + %.8f)\n",dstr(total),dstr(satoshis),dstr(txfee));
                return(0);
            }
            if ( (change= (total - (satoshis + txfee))) > 10000 && (changeaddr == 0 || changeaddr[0] == 0) )
            {
                printf("no changeaddr for %.8f\n",dstr(change));
                free_json(vins);
                free(unspents);
                return(0);
            }
            iguana_createvins(myinfo,coin,txobj,vins);
            if ( change > 10000 )
            {
                if ( iguana_addressvalidate(coin,&addrtype,changeaddr) < 0 )
                {
                    free_json(vins);
                    free(unspents);
                    printf("illegal destination address.(%s)\n",changeaddr);
                    return(0);
                }
                bitcoin_addr2rmd160(&addrtype,rmd160,changeaddr);
                spendlen = bitcoin_standardspend(spendscript,0,rmd160);
                bitcoin_txoutput(txobj,spendscript,spendlen,change);
            }
            if ( vins != 0 && V == 0 )
            {
                V = calloc(cJSON_GetArraySize(vins),sizeof(*V)), allocflag = 1;
                //iguana_vinprivkeys(myinfo,coin,V,vins);
            }
            rawtx = bitcoin_json2hex(myinfo,coin,&txid,txobj,V);
            if ( allocflag != 0 )
                free(V);
        }
    }
    free(unspents);
    *vinsp = vins;
    return(rawtx);
}

void iguana_RTunspentslock(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *vins)
{
    struct iguana_outpoint spentpt; char coinaddr[64]; int32_t i,RTspentflag,num,spentheight,lockedflag;
    if ( coin->MAXPEERS == 1 || coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        num = cJSON_GetArraySize(vins);
        for (i=0; i<num; i++)
        {
            if ( iguana_RTinputaddress(myinfo,coin,coinaddr,&spentpt,jitem(vins,i)) != 0 )
                iguana_RTutxofunc(coin,&spentheight,&lockedflag,spentpt,&RTspentflag,1,0); // last arg should be spentheight
        }
    }
}

char *sendtoaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,char *destaddr,uint64_t satoshis,uint64_t txfee,char *comment,char *comment2,int32_t minconf,char *account)
{
    uint8_t addrtype,spendscript[1024],rmd160[20]; int32_t completed; char *retstr,spendscriptstr[4096],*rawtx=0,*signedtx = 0; bits256 signedtxid,senttxid; cJSON *retjson,*vins,*addresses,*valsobj; uint32_t spendlen,locktime = 0; uint32_t basilisktag; struct vin_info *V = 0;
    //sendtoaddress	<bitcoinaddress> <amount> [comment] [comment-to]	<amount> is a real and is rounded to 8 decimal places. Returns the transaction ID <txid> if successful.	Y
    if ( coin->RTheight == 0 && coin->FULLNODE != 0 )
        return(clonestr("{\"error\":\"need to get to realtime blocks to send transaction\"}"));
    if ( account == 0 || account[0] == 0 )
        account = "*";
    addresses = iguana_getaddressesbyaccount(myinfo,coin,account);
    if ( coin->changeaddr[0] == 0 )
    {
        bitcoin_address(coin->changeaddr,coin->chain->pubtype,myinfo->persistent_pubkey33,33);
        printf("%s change %s\n",coin->symbol,coin->changeaddr);
    }
    if ( destaddr != 0 && destaddr[0] != 0 && satoshis != 0 )
    {
        if ( iguana_addressvalidate(coin,&addrtype,destaddr) < 0 )
            return(clonestr("{\"error\":\"invalid coin address\"}"));
        bitcoin_addr2rmd160(&addrtype,rmd160,destaddr);
        spendlen = bitcoin_standardspend(spendscript,0,rmd160);
        init_hexbytes_noT(spendscriptstr,spendscript,spendlen);
        basilisktag = (uint32_t)rand();
        valsobj = cJSON_CreateObject();
        jadd(valsobj,"addresses",addresses);
        jaddstr(valsobj,"coin",coin->symbol);
        jaddstr(valsobj,"changeaddr",coin->changeaddr);
        jaddstr(valsobj,"spendscript",spendscriptstr);
        jadd64bits(valsobj,"satoshis",satoshis);
        jadd64bits(valsobj,"txfee",txfee);
        jaddnum(valsobj,"minconf",minconf);
        jaddnum(valsobj,"basilisktag",basilisktag);
        jaddnum(valsobj,"locktime",locktime);
        jaddnum(valsobj,"timeout",30000);
        if ( (0) && comment != 0 && is_hexstr(comment,0) > 0 )
            jaddstr(valsobj,"opreturn",comment);
        if ( (retstr= basilisk_bitcoinrawtx(myinfo,coin,remoteaddr,basilisktag,jint(valsobj,"timeout"),valsobj,V)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( (rawtx= jstr(retjson,"rawtx")) != 0 && (vins= jobj(retjson,"vins")) != 0 )
                {
                    if ( (signedtx= iguana_signrawtx(myinfo,coin,coin->blocks.hwmchain.height,&signedtxid,&completed,vins,rawtx,0,V)) != 0 )
                    {
                        iguana_RTunspentslock(myinfo,coin,vins);
                        retjson = cJSON_CreateObject();
                        jaddbits256(retjson,"result",signedtxid);
                        jaddstr(retjson,"signedtx",signedtx);
                        jadd(retjson,"complete",completed != 0 ? jtrue() : jfalse());
                        if ( completed != 0 )
                        {
                            senttxid = iguana_sendrawtransaction(myinfo,coin,signedtx);
                            if ( bits256_cmp(senttxid,signedtxid) == 0 )
                            {
                                jaddstr(retjson,"sendrawtransaction","success");
                                iguana_unspents_mark(myinfo,coin,vins);
                            } else jaddbits256(retjson,"senderror",senttxid);
                        }
                        free_json(vins);
                        free(signedtx);
                        return(jprint(retjson,1));
                    }
                    else
                    {
                        free_json(vins);
                        return(clonestr("{\"error\":\"couldnt sign rawtx\"}"));
                    }
                }
                free_json(retjson);
            }
            free(retstr);
            return(clonestr("{\"error\":\"couldnt create rawtx\"}"));
        } else return(clonestr("{\"error\":\"couldnt create rawtx\"}"));
    }
    return(clonestr("{\"error\":\"need address and amount\"}"));
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"
#include "../includes/iguana_apideclares2.h"

STRING_AND_INT(bitcoinrpc,sendrawtransaction,rawtx,allowhighfees)
{
    cJSON *retjson = cJSON_CreateObject(); bits256 txid;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( coin->notarychain >= 0 && coin->FULLNODE == 0 )
        return(_dex_sendrawtransaction(myinfo,coin->symbol,rawtx));
    txid = iguana_sendrawtransaction(myinfo,coin,rawtx);
    jaddbits256(retjson,"result",txid);
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,submitblock,rawbytes)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    cJSON *retjson = cJSON_CreateObject();
    // send to all peers
    return(jprint(retjson,1));
}

ZERO_ARGS(iguana,makekeypair)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    bits256 privkey; char str[67]; cJSON *retjson = cJSON_CreateObject();
    privkey = rand256(1);
    jaddstr(retjson,"result","success");
    jaddstr(retjson,"privkey",bits256_str(str,privkey));
    jadd(retjson,"rosetta",SuperNET_rosettajson(myinfo,privkey,1));
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,validatepubkey,pubkeystr)
{
    uint8_t pubkey[65],addrtype = 0; int32_t plen; char coinaddr[128],*str; cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    plen = (int32_t)strlen(pubkeystr) >> 1;
    if ( plen >= 33 && plen <= 65 && coin != 0 && coin->chain != 0 )
    {
        addrtype = coin->chain->pubtype;
        decode_hex(pubkey,plen,pubkeystr);
        if ( (str= bitcoin_address(coinaddr,addrtype,pubkey,plen)) != 0 )
        {
            if ( iguana_addressvalidate(coin,&addrtype,coinaddr) < 0 )
                return(clonestr("{\"error\":\"invalid coin address\"}"));
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"result","success");
            jaddstr(retjson,"pubkey",pubkeystr);
            jaddstr(retjson,"address",coinaddr);
            jaddstr(retjson,"coin",coin->symbol);
            return(jprint(retjson,1));
        }
    }
    return(clonestr("{\"error\":\"invalid pubkey\"}"));
}

STRING_ARG(bitcoinrpc,decodescript,scriptstr)
{
    int32_t scriptlen; uint8_t script[IGUANA_MAXSCRIPTSIZE],rmd160[20]; char coinaddr[128],asmstr[IGUANA_MAXSCRIPTSIZE*2+1]; cJSON *scriptobj,*retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( scriptstr != 0 && coin != 0 && (scriptlen= (int32_t)strlen(scriptstr)>>1) < sizeof(script) )
    {
        decode_hex(script,scriptlen,scriptstr);
        if ( (scriptobj= iguana_scriptobj(coin,rmd160,coinaddr,asmstr,script,scriptlen)) != 0 )
            jadd(retjson,"result",scriptobj);
    }
    return(jprint(retjson,1));
}

INT_ARRAY_STRING(bitcoinrpc,createmultisig,M,pubkeys,ignore)
{
    cJSON *retjson,*pkjson,*addresses; uint8_t script[2048],p2sh_rmd160[20]; char pubkeystr[256],msigaddr[64],*pkstr,scriptstr[sizeof(script)*2+1]; struct vin_info V; int32_t i,plen,len,n = cJSON_GetArraySize(pubkeys);
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( n < 0 || n > 16 || M < 0 || M > n )
        return(clonestr("{\"error\":\"illegal number of pubkeys\"}"));
    memset(&V,0,sizeof(V));
    //printf("create M.%d of N.%d (%s)\n",M,n,jprint(pubkeys,0));
    V.M = M, V.N = n;
    pkjson = cJSON_CreateArray();
    addresses = cJSON_CreateArray();
    for (i=0; i<n; i++)
    {
        if ( (pkstr= jstr(jitem(pubkeys,i),0)) != 0 )
        {
            if ( iguana_pubkeyget(myinfo,coin,V.signers[i].pubkey,pkstr) < 0 )
                break;
            if ( (plen= bitcoin_pubkeylen(V.signers[i].pubkey)) <= 0 )
                break;
            bitcoin_address(V.signers[i].coinaddr,coin->chain->pubtype,V.signers[i].pubkey,plen);
            jaddistr(addresses,V.signers[i].coinaddr);
            init_hexbytes_noT(pubkeystr,V.signers[i].pubkey,plen);
            jaddistr(pkjson,pubkeystr);
        } else break;
    }
    retjson = cJSON_CreateObject();
    if ( i == n )
    {
        len = bitcoin_MofNspendscript(p2sh_rmd160,script,0,&V);
        bitcoin_address(msigaddr,coin->chain->p2shtype,p2sh_rmd160,sizeof(p2sh_rmd160));
        jaddstr(retjson,"result","success");
        jaddstr(retjson,"address",msigaddr);
        init_hexbytes_noT(scriptstr,script,len);
        jaddstr(retjson,"redeemScript",scriptstr);
        jaddnum(retjson,"M",M);
        jaddnum(retjson,"N",n);
        jadd(retjson,"pubkeys",pkjson);
        jadd(retjson,"addresses",addresses);
    }
    else
    {
        jaddstr(retjson,"error","couldnt get all pubkeys");
        free_json(pkjson);
    }
    //printf("CREATEMULTISIG.(%s)\n",jprint(retjson,0));
    return(jprint(retjson,1));
}

INT_ARRAY_STRING(bitcoinrpc,addmultisigaddress,M,pubkeys,account) //
{
    cJSON *retjson,*tmpjson,*setjson=0; char *retstr,*str=0,*msigaddr,*redeemScript;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    if ( (retstr= bitcoinrpc_createmultisig(IGUANA_CALLARGS,M,pubkeys,account)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (msigaddr= jstr(retjson,"address")) != 0 )
            {
                if ( (redeemScript= jstr(retjson,"redeemScript")) == 0 || (str= setaccount(myinfo,coin,0,account,msigaddr,redeemScript)) == 0 || (setjson= cJSON_Parse(str)) == 0 || jobj(setjson,"error") != 0 )
                {
                    if ( jobj(retjson,"result") != 0 )
                        jdelete(retjson,"result");
                    if ( jobj(retjson,"error") == 0 )
                        jaddstr(retjson,"error","couldnt add multisig address to account");
                }
                else
                {
                    tmpjson = cJSON_CreateObject();
                    jaddstr(tmpjson,"result",msigaddr);
                    free_json(retjson);
                    free(retstr);
                    retjson = tmpjson;
                }
            }
            if ( setjson != 0 )
                free_json(setjson);
            if ( str != 0 )
                free(str);
            return(jprint(retjson,1));
        } else return(clonestr("{\"error\":\"couldnt parse retstr from createmultisig\"}"));
    } else return(clonestr("{\"error\":\"no retstr from createmultisig\"}"));
}

HASH_AND_TWOINTS(bitcoinrpc,gettxout,txid,vout,mempool)
{
    uint8_t script[IGUANA_MAXSCRIPTSIZE],rmd160[20],pubkey33[33]; char coinaddr[128],asmstr[IGUANA_MAXSCRIPTSIZE*2+1]; struct iguana_bundle *bp; int32_t firstslot,minconf,scriptlen,unspentind,height,spentheight=-1; struct iguana_RTtxid *ptr; uint64_t RTspend,value; struct iguana_ramchaindata *rdata; struct iguana_pkhash *P; struct iguana_txid *T; struct iguana_unspent *U; struct iguana_outpoint outpt; struct iguana_ramchain *ramchain; cJSON *scriptobj,*retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( coin != 0 )
    {
        if ( coin->notarychain >= 0 && coin->FULLNODE == 0 )
            return(_dex_gettxout(myinfo,coin->symbol,txid,vout));
        if ( (value= _RTgettxout(coin,&ptr,&height,&scriptlen,script,rmd160,coinaddr,txid,vout,mempool)) > 0 )
        {
            jaddbits256(retjson,"bestblock",coin->blocks.hwmchain.RO.hash2);
            jaddnum(retjson,"bestheight",coin->blocks.hwmchain.height);
            jaddnum(retjson,"height",height);
            jaddbits256(retjson,"txid",txid);
            jaddnum(retjson,"vout",vout);
            jaddnum(retjson,"confirmations",coin->blocks.hwmchain.height - height + 1);
            jaddnum(retjson,"value",dstr(value));
            jaddnum(retjson,"amount",dstr(value));
            if ( strcmp(coin->symbol,"KMD") == 0 )
                jaddnum(retjson,"interest",dstr(iguana_interest(myinfo,coin,txid,vout,value)));
            if ( (height % coin->chain->bundlesize) == 0 && vout == 0 )
                jadd(retjson,"coinbase",jtrue());
            else jadd(retjson,"coinbase",jfalse());
            asmstr[0] = 0;
            if ( (scriptobj= iguana_scriptobj(coin,rmd160,coinaddr,asmstr,script,scriptlen)) != 0 )
                jadd(retjson,"scriptPubKey",scriptobj);
            return(jprint(retjson,1));
        }
        minconf = (mempool != 0) ? 0 : 1;
        if ( iguana_RTunspentindfind(myinfo,coin,&outpt,0,0,0,0,&height,txid,vout,coin->bundlescount-1,0) == 0 && outpt.isptr == 0 )
        {
            unspentind = outpt.unspentind;
            if ( height >= 0 && height < coin->longestchain && (bp= coin->bundles[height / coin->chain->bundlesize]) != 0 )
            {
                ramchain = &bp->ramchain;
                if ( (rdata= ramchain->H.data) != 0 )
                {
                    U = RAMCHAIN_PTR(rdata,Uoffset);
                    P = RAMCHAIN_PTR(rdata,Poffset);
                    T = RAMCHAIN_PTR(rdata,Toffset);
                    RTspend = 0;
                    memset(&outpt,0,sizeof(outpt));
                    outpt.hdrsi = bp->hdrsi;
                    outpt.unspentind = unspentind;
                    if ( iguana_markedunspents_find(coin,&firstslot,txid,vout) < 0 && iguana_RTspentflag(myinfo,coin,&RTspend,&spentheight,ramchain,outpt,height,minconf,coin->longestchain,U[unspentind].value) == 0 )
                    {
                        jaddbits256(retjson,"bestblock",coin->blocks.hwmchain.RO.hash2);
                        jaddnum(retjson,"bestheight",coin->blocks.hwmchain.height);
                        jaddnum(retjson,"height",height);
                        jaddnum(retjson,"confirmations",coin->blocks.hwmchain.height - height + 1);
                        jaddnum(retjson,"value",dstr(U[unspentind].value));
                        memset(rmd160,0,sizeof(rmd160));
                        memset(pubkey33,0,sizeof(pubkey33));
                        memset(coinaddr,0,sizeof(coinaddr));
                        if ( (scriptlen= iguana_voutscript(coin,bp,script,0,&U[unspentind],&P[U[unspentind].pkind],vout)) > 0 )
                        {
                            if ( (scriptobj= iguana_scriptobj(coin,rmd160,coinaddr,asmstr,script,scriptlen)) != 0 )
                                jadd(retjson,"scriptPubKey",scriptobj);
                        }
                        jadd(retjson,"iguana",iguana_RTunspentjson(myinfo,coin,outpt,T[U[unspentind].txidind].txid,unspentind-T[U[unspentind].txidind].firstvout,U[unspentind].value,&U[unspentind],rmd160,coinaddr,pubkey33,spentheight,remoteaddr));
                        if ( (height % coin->chain->bundlesize) == 0 && vout == 0 )
                            jadd(retjson,"coinbase",jtrue());
                        else jadd(retjson,"coinbase",jfalse());
                    }
                    else
                    {
                        jaddstr(retjson,"error","already spent");
                        jaddnum(retjson,"spentheight",spentheight);
                        jaddnum(retjson,"unspentind",unspentind);
                    }
                }
            }
        }
    }
    return(jprint(retjson,1));
}

bits256 iguana_messagehash2(char *message,char *messagemagic)
{
    int32_t n,len; uint8_t *messagebuf; bits256 hash2;
    n = (int32_t)strlen(message) >> 1;
    len = (int32_t)strlen(messagemagic);
    if ( message[0] == '0' && message[1] == 'x' && is_hexstr(message+2,n-2) > 0 )
    {
        messagebuf = malloc(n-2 + len);
        memcpy(messagebuf,messagemagic,len);
        decode_hex(messagebuf+len,n-2,message+2);
        n--;
    }
    else
    {
        n <<= 1;
        messagebuf = malloc(n + len + 1);
        memcpy(messagebuf,messagemagic,len);
        strcpy((void *)&messagebuf[len],message);
        //printf("MESSAGE.(%s)\n",(void *)messagebuf);
    }
    n += len;
    hash2 = bits256_doublesha256(0,messagebuf,n);
    //for (i=0; i<sizeof(hash2); i++)
    //    revhash2.bytes[i] = hash2.bytes[sizeof(hash2) - 1 - i];
    if ( messagebuf != (void *)message )
        free(messagebuf);
    return(hash2);
}

TWO_STRINGS(bitcoinrpc,signmessage,address,message)
{
    bits256 privkey,hash2; int32_t len,siglen; char sigstr[256],sig65str[256]; uint8_t sig[128]; cJSON *retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    if ( coin != 0 )
    {
        privkey = iguana_str2priv(myinfo,coin,address);
        if ( bits256_nonz(privkey) != 0 )
        {
            hash2 = iguana_messagehash2(message,coin->chain->messagemagic);
            if ( (siglen= bitcoin_sign(coin->ctx,coin->symbol,sig,hash2,privkey,1)) > 0 )
            {
                sigstr[0] = sig65str[0] = 0;
                len = nn_base64_encode(sig,siglen,sig65str,sizeof(sig65str));
                sig65str[len] = 0;
                jaddstr(retjson,"result",sig65str);
            }
        } else jaddstr(retjson,"error","invalid address (can be wif, wallet address or privkey hex)");
    }
    return(jprint(retjson,1));
}

THREE_STRINGS(bitcoinrpc,verifymessage,address,sig,message)
{
    int32_t len,plen; uint8_t sigbuf[256],pubkey[65]; char str[4096]; bits256 hash2; cJSON *retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( strlen(sig) < sizeof(sigbuf)*8/6 )
    {
        len = (int32_t)strlen(sig);
        len = nn_base64_decode(sig,len,sigbuf,sizeof(sigbuf));
        //int32_t i; for (i=0; i<len; i++)
        //    printf("%02x",sigbuf[i]);
        //printf(" siglen.%d [%d] address.(%s) sig.(%s) message.(%s)\n",len,sigbuf[0],address,sig,message);
        hash2 = iguana_messagehash2(message,coin->chain->messagemagic);
        if ( bitcoin_recoververify(myinfo->ctx,coin->symbol,sigbuf,hash2,pubkey,0) == 0 )
            jadd(retjson,"result",jtrue());
        else jadd(retjson,"result",jfalse());
        jaddstr(retjson,"coin",coin->symbol);
        jaddstr(retjson,"address",address);
        jaddstr(retjson,"message",message);
        if ( (plen= bitcoin_pubkeylen(pubkey)) > 0 )
        {
            init_hexbytes_noT(str,pubkey,plen);
            jaddstr(retjson,"pubkey",str);
        }
        init_hexbytes_noT(str,sigbuf,len);
        jaddstr(retjson,"sighex",str);
        jaddbits256(retjson,"messagehash",hash2);
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"sig is too long\"}"));
}

int64_t iguana_txdetails(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *item,bits256 txid,int32_t vout,int32_t height)
{
    struct iguana_block *block; bits256 hash2; uint64_t amount = 0; char coinaddr[64],account[512];
    /*{
     "category": "receive",
     "amount": 0.50000000,
     "label": "",
     "confirmations": 24466,
     "blockhash": "00000000000000000517ce625737579f91162c46ad9eaccad0f52ca13715b156",
     "blockindex": 78,
     "blocktime": 1448045745,
     }*/
    jaddbits256(item,"txid",txid);
    if ( vout >= 0 )
    {
        jaddnum(item,"vout",vout);
        if ( (amount= iguana_txidamount(myinfo,coin,coinaddr,txid,vout)) != 0 )
            jaddnum(item,"amount",dstr(amount));
        jaddstr(item,"category",iguana_txidcategory(myinfo,coin,account,coinaddr,txid,vout));
    }
    else
    {
        if ( vout == -1 )
            jadd(item,"coinbase",jtrue());
        vout = 0;
    }
    if ( account[0] != 0 && jobj(item,"account") == 0 )
        jaddstr(item,"account",account);
    if ( coinaddr[0] != 0 )
        jaddstr(item,"address",coinaddr);
    hash2 = iguana_blockhash(coin,height);
    jaddbits256(item,"blockhash",hash2);
    if ( (block= iguana_blockfind("rawtx",coin,hash2)) != 0 )
        jaddnum(item,"blocktime",block->RO.timestamp);
    jaddnum(item,"height",height);
    jaddnum(item,"confirmations",coin->blocks.hwmchain.height - height);
    return(amount);
}

HASH_AND_INT(bitcoinrpc,getrawtransaction,txid,verbose)
{
    struct iguana_txid *tx,T; char *txbytes; bits256 checktxid; int32_t len=0,height,extralen=65536; cJSON *retjson,*txobj; uint8_t *extraspace; struct iguana_RTtxid *RTptr;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( coin->notarychain >= 0 && coin->FULLNODE == 0 )
        return(_dex_getrawtransaction(myinfo,coin->symbol,txid));
    HASH_FIND(hh,coin->RTdataset,txid.bytes,sizeof(txid),RTptr);
    memset(checktxid.bytes,0,sizeof(checktxid));
    if ( RTptr != 0 && RTptr->rawtxbytes != 0 && RTptr->txlen > 0 )
    {
        checktxid = RTptr->txid;
        height = RTptr->height;
        len = RTptr->txlen;
        memcpy(coin->blockspace,RTptr->rawtxbytes,len);
    }
    else if ( (tx= iguana_txidfind(coin,&height,&T,txid,coin->bundlescount-1)) != 0 )
    {
        len = iguana_ramtxbytes(coin,coin->blockspace,coin->blockspacesize,&checktxid,tx,height,0,0,0);
    }
    retjson = cJSON_CreateObject();
    if ( len > 0 )
    {
        txbytes = calloc(1,len*2+1);
        init_hexbytes_noT(txbytes,coin->blockspace,len);
        if ( verbose != 0 )
        {
            extraspace = calloc(1,extralen);
            txobj = bitcoin_hex2json(coin,coin->blocks.hwmchain.height,&checktxid,0,txbytes,extraspace,extralen,0,0,0);
            free(extraspace);
            free(txbytes);
            if ( txobj != 0 )
            {
                iguana_txdetails(myinfo,coin,txobj,checktxid,-2,height);
                return(jprint(txobj,1));
            }
        }
        jaddstr(retjson,"result",txbytes);
        char str[65]; printf("txbytes.(%s) len.%d (%s) %s\n",txbytes,len,jprint(retjson,0),bits256_str(str,checktxid));
        free(txbytes);
        return(jprint(retjson,1));
    }
    else if ( height >= 0 )
    {
        if ( coin->APIblockstr != 0 )
            jaddstr(retjson,"error","already have pending request");
        else
        {
            int32_t datalen; uint8_t *data; char *blockstr; bits256 blockhash;
            blockhash = iguana_blockhash(coin,height);
            if ( (blockstr= iguana_APIrequest(coin,blockhash,txid,2)) != 0 )
            {
                datalen = (int32_t)(strlen(blockstr) >> 1);
                data = malloc(datalen);
                decode_hex(data,datalen,blockstr);
                if ( (txbytes= iguana_txscan(myinfo,coin,verbose != 0 ? retjson : 0,data,datalen,txid)) != 0 )
                {
                    jaddstr(retjson,"result",txbytes);
                    jaddbits256(retjson,"blockhash",blockhash);
                    jaddnum(retjson,"height",height);
                    free(txbytes);
                }
                else if ( coin->RTheight > 0 )
                    jaddstr(retjson,"error","cant find txid in block");
                else jaddstr(retjson,"error","not in realtime mode yet");
                free(blockstr);
                free(data);
            } else jaddstr(retjson,"error","cant find blockhash");
            return(jprint(retjson,1));
        }
    }
    if ( coin->RTheight > 0 )
        return(clonestr("{\"error\":\"cant find txid\"}"));
    else return(clonestr("{\"error\":\"not in realtime mode yet\"}"));
}

int64_t iguana_lockval(int32_t finalized,int64_t locktime)
{
    int64_t lockval = -1;
    if ( finalized == 0 )
        return(locktime);
    return(lockval);
}

char *iguana_validaterawtx(struct supernet_info *myinfo,struct iguana_info *coin,int32_t height,struct iguana_msgtx *msgtx,uint8_t *extraspace,int32_t extralen,char *rawtx,int32_t mempool,int32_t suppress_pubkeys)
{
    bits256 signedtxid,txid; struct iguana_outpoint outpt; struct iguana_msgvin vin; cJSON *log,*vins,*vouts,*txobj,*retjson; char *checkstr,*signedtx; int32_t plen,finalized = 1,i,len,maxsize,numinputs,numoutputs,complete; struct vin_info *V; uint8_t *serialized,*serialized2; uint32_t sigsize,pubkeysize,p2shsize,suffixlen; int64_t inputsum,outputsum,lockval;
    retjson = cJSON_CreateObject();
    inputsum = outputsum = numinputs = numoutputs = 0;
    if ( rawtx != 0 && rawtx[0] != 0 && coin != 0 )
    {
        if ( (strlen(rawtx) & 1) != 0 )
            return(clonestr("{\"error\":\"rawtx hex has odd length\"}"));
        memset(msgtx,0,sizeof(*msgtx));
        if ( (txobj= bitcoin_hex2json(coin,coin->blocks.hwmchain.height,&msgtx->txid,msgtx,rawtx,extraspace,extralen,0,0,suppress_pubkeys)) != 0 )
        {
            //printf("txobj.(%s)\n",jprint(txobj,0));
            if ( (0) && (checkstr= bitcoin_json2hex(myinfo,coin,&txid,txobj,0)) != 0 )
            {
                // no guarantee byte for byte identical tx is recreated
                if ( strcmp(rawtx,checkstr) != 0 )
                {
                    jaddstr(retjson,"error","converting from hex2json and json2hex mismatch");
                    jaddstr(retjson,"original",rawtx);
                    jaddstr(retjson,"checkstr",checkstr);
                    for (i=0; rawtx[i]!=0 && checkstr[i]!=0; i++)
                        if ( rawtx[i] != checkstr[i] )
                            break;
                    jaddnum(retjson,"mismatch position",i);
                    jadd(retjson,"origtx",txobj);
                    if ( (0) && (txobj= bitcoin_hex2json(coin,coin->blocks.hwmchain.height,&txid,msgtx,checkstr,extraspace,extralen,0,0,suppress_pubkeys)) != 0 )
                        jadd(retjson,"checktx",txobj);
                    free(checkstr);
                    return(jprint(retjson,1));
                }
                free(checkstr);
            }
            if ( (vouts= jarray(&numoutputs,txobj,"vout")) > 0 )
            {
                struct iguana_msgvout vout; uint8_t voutdata[IGUANA_MAXSCRIPTSIZE];
                for (i=0; i<numoutputs; i++)
                {
                    if ( iguana_parsevoutobj(coin,voutdata,sizeof(voutdata),&vout,jitem(vouts,i)) > 0 )
                        outputsum += vout.value;
                }
            }
            if ( (vins= jarray(&numinputs,txobj,"vin")) > 0 )
            {
                maxsize = (int32_t)strlen(rawtx);
                serialized = malloc(maxsize);
                serialized2 = malloc(maxsize);
                len = 0;
                V = calloc(numinputs,sizeof(*V));
                for (i=0; i<numinputs; i++)
                {
                    len += iguana_parsevinobj(myinfo,coin,&serialized[len],maxsize-len,&vin,jitem(vins,i),&V[i]);
                    if ( iguana_RTunspentindfind(myinfo,coin,&outpt,V[i].coinaddr,V[i].spendscript,&V[i].spendlen,&V[i].amount,&V[i].height,msgtx->vins[i].prev_hash,msgtx->vins[i].prev_vout,coin->bundlescount-1,mempool) == 0 )
                    {
                        V[i].suppress_pubkeys = suppress_pubkeys;
                        V[i].unspentind = outpt.unspentind;
                        inputsum += V[i].amount;
                        msgtx->vins[i].spendscript = V[i].spendscript;
                        if ( (msgtx->vins[i].spendlen= V[i].spendlen) == 35 )
                        {
                            if ( (plen= bitcoin_pubkeylen(msgtx->vins[i].spendscript+1)) > 0 )
                            {
                                memcpy(V[i].signers[0].pubkey,msgtx->vins[i].spendscript+1,plen);
                                V[i].suppress_pubkeys = 1;
                            }
                        }
                        V[i].hashtype = iguana_vinscriptparse(coin,&V[i],&sigsize,&pubkeysize,&p2shsize,&suffixlen,msgtx->vins[i].vinscript,msgtx->vins[i].scriptlen);
                        //if ( (V[i].signers[0].siglen= sigsize) > 0 )
                        //    memcpy(V[i].signers[0].sig,msgtx->vins[i].vinscript+1,sigsize);
                        V[i].userdatalen = suffixlen;
                        memcpy(V[i].spendscript,msgtx->vins[i].spendscript,msgtx->vins[i].spendlen);
                        V[i].spendlen = msgtx->vins[i].spendlen;
                        if ( msgtx->vins[i].sequence < IGUANA_SEQUENCEID_FINAL )
                            finalized = 0;
                        if ( V[i].M == 0 )
                            V[i].M = 1;
                        if ( V[i].N < V[i].M )
                            V[i].N = V[i].M;
                        //printf("V %dof%d %.8f (%s) spendscript.[%d] scriptlen.%d\n",V[i].M,V[i].N,dstr(V[i].amount),V[i].coinaddr,V[i].spendlen,V[i].spendlen);
                    } else printf("couldnt find spendscript\n");
                }
                complete = 0;
                bitcoin_verifyvins(coin,height,&signedtxid,&signedtx,msgtx,serialized2,maxsize,V,1,0,suppress_pubkeys);
                msgtx->txid = signedtxid;
                log = cJSON_CreateArray();
                lockval = iguana_lockval(finalized,jint(txobj,"locktime"));
                if ( iguana_interpreter(coin,log,lockval,V,numinputs) < 0 )
                    jaddstr(retjson,"error","interpreter rejects tx");
                else complete = 1;
                jadd(retjson,"interpreter",log);
                jaddnum(retjson,"complete",complete);
                free(serialized), free(serialized2);
                if ( signedtx != 0 )
                    free(signedtx);
            }
        }
        //char str[65]; printf("got txid.(%s)\n",bits256_str(str,txid));
    }
    msgtx->inputsum = inputsum;
    msgtx->numinputs = numinputs;
    msgtx->outputsum = outputsum;
    msgtx->numoutputs = numoutputs;
    msgtx->txfee = (inputsum - outputsum);
    return(jprint(retjson,1));
}

STRING_AND_INT(bitcoinrpc,validaterawtransaction,rawtx,suppress)
{
    uint8_t *extraspace; int32_t extralen=65536; char *retstr; struct iguana_msgtx msgtx;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    extraspace = calloc(1,extralen);
    retstr = iguana_validaterawtx(myinfo,coin,coin->blocks.hwmchain.height,&msgtx,extraspace,extralen,rawtx,0,suppress);
    free(extraspace);
    return(rawtx);
}

int32_t iguana_validatesigs(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t *serialized,int32_t datalen)
{
    uint8_t *extraspace; cJSON *retjson; int32_t extralen=65536; char *retstr,*rawtx; struct iguana_msgtx msgtx; int32_t suppress=0,retval = -1;
    rawtx = calloc(1,datalen*2 + 1);
    init_hexbytes_noT(rawtx,serialized,datalen);
    extraspace = calloc(1,extralen);
    for (suppress=0; suppress<1; suppress++)
    {
        if ( (retstr= iguana_validaterawtx(myinfo,coin,coin->blocks.hwmchain.height,&msgtx,extraspace,extralen,rawtx,0,suppress)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( jobj(retjson,"error") == 0 )
                {
                    retval = 0;
                    //char str[65]; printf("%s %s sigs validated\n",coin->symbol,bits256_str(str,msgtx.txid));
                    coin->sigsvalidated++;
                    break;
                }
                else
                {
                    printf("ERROR.(%s)\n",retstr);
                    coin->sigserrs++;
                }
                free_json(retjson);
            }
            free(retstr);
        }
    }
    free(rawtx);
    free(extraspace);
    return(retval);
}

STRING_AND_INT(bitcoinrpc,decoderawtransaction,rawtx,suppress)
{
    cJSON *txobj = 0; bits256 txid; uint8_t *extraspace; int32_t extralen = 65536;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( rawtx != 0 && rawtx[0] != 0 )
    {
        if ( (strlen(rawtx) & 1) != 0 )
            return(clonestr("{\"error\":\"rawtx hex has odd length\"}"));
        extraspace = calloc(1,extralen);
        txobj = bitcoin_hex2json(coin,coin->blocks.hwmchain.height,&txid,0,rawtx,extraspace,extralen,0,0,suppress);
        free(extraspace);
        //char str[65]; printf("got txid.(%s)\n",bits256_str(str,txid));
    }
    if ( txobj == 0 )
        txobj = cJSON_CreateObject();
    return(jprint(txobj,1));
}

HASH_ARG(bitcoinrpc,gettransaction,txid)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(bitcoinrpc_getrawtransaction(IGUANA_CALLARGS,txid,1));
}

cJSON *iguana_createvins(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *txobj,cJSON *vins)
{
    int32_t i,j,n,vout,p2shlen=0,spendlen=0,height; uint64_t satoshis; char coinaddr[128],pubkeystr[256],scriptstr[IGUANA_MAXSCRIPTSIZE*2],*str,*hexstr; cJSON *pubkeys,*item,*obj,*newvin,*newvins; uint32_t sequenceid; bits256 txid; uint8_t spendscript[IGUANA_MAXSCRIPTSIZE],redeemscript[IGUANA_MAXSCRIPTSIZE]; struct iguana_waccount *wacct; struct iguana_waddress *waddr; struct iguana_outpoint outpt;
    newvins = cJSON_CreateArray();
    if ( (n= cJSON_GetArraySize(vins)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            pubkeys = cJSON_CreateArray();
            newvin = cJSON_CreateObject();
            item = jitem(vins,i);
            txid = jbits256(item,"txid");
            vout = jint(item,"vout");
            jaddbits256(newvin,"txid",txid);
            jaddnum(newvin,"vout",vout);
            p2shlen = spendlen = 0;
            if ( ((str= jstr(item,"scriptPub")) != 0 || (str= jstr(item,"scriptPubKey")) != 0) && is_hexstr(str,(int32_t)strlen(str)) > 0 )
            {
                spendlen = (int32_t)strlen(str) >> 1;
                decode_hex(spendscript,spendlen,str);
            }
            else if ( ((obj= jobj(item,"scriptPub")) != 0 || (obj= jobj(item,"scriptPubKey")) != 0) && (hexstr= jstr(obj,"hex")) != 0 )
            {
                spendlen = (int32_t)strlen(hexstr) >> 1;
                decode_hex(spendscript,spendlen,hexstr);
            }
            if ( coin->FULLNODE == 0 && coin->notarychain >= 0 )
            {
                char *retstr; cJSON *txoutjson,*sobj,*array; int32_t numaddrs;
                if ( (retstr= _dex_gettxout(myinfo,coin->symbol,txid,vout)) != 0 )
                {
                    // {"bestblock":"000000000000000002a530b32efce4cb4ee01b401d58592ce36939d84c9f94b9","confirmations":109,"value":0.00120000,"scriptPubKey":{"asm":"OP_DUP OP_HASH160 971f98b33fb838faee190e2fab799440d8c51702 OP_EQUALVERIFY OP_CHECKSIG","hex":"76a914971f98b33fb838faee190e2fab799440d8c5170288ac","reqSigs":1,"type":"pubkeyhash","addresses":["1En4tL4drN5qAZDtu1BCC7DThj58yrx7cX"]},"version":1,"coinbase":false,"randipbits":847292520,"coin":"BTC","tag":"18220985608713355389"}

                    if ( (txoutjson= cJSON_Parse(retstr)) != 0 )
                    {
                        if ( (sobj= jobj(txoutjson,"scriptPubKey")) != 0 && (array= jarray(&numaddrs,txoutjson,"addresses")) != 0 )
                        {
                            for (j=0; j<numaddrs; j++)
                            {
                                if ( strlen(jstri(array,j)) < sizeof(coinaddr)-1 )
                                {
                                    if ( (waddr= iguana_waddresssearch(myinfo,&wacct,jstri(array,j))) != 0 )
                                    {
                                        init_hexbytes_noT(pubkeystr,waddr->pubkey,bitcoin_pubkeylen(waddr->pubkey));
                                        jaddistr(pubkeys,pubkeystr);
                                        //printf("pubkeys[%d] <- (%s)\n",j,pubkeystr);
                                    }
                                }
                            }
                        }
                        free_json(txoutjson);
                    }
                    free(retstr);
                }
            }
            else if ( iguana_RTunspentindfind(myinfo,coin,&outpt,coinaddr,spendscript,&spendlen,&satoshis,&height,txid,vout,coin->bundlescount-1,0) == 0 )
            {
                //printf("[%d] unspentind.%d (%s) spendlen.%d %.8f\n",height/coin->chain->bundlesize,unspentind,coinaddr,spendlen,dstr(satoshis));
                if ( coinaddr[0] != 0 && (waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) != 0 )
                {
                    init_hexbytes_noT(pubkeystr,waddr->pubkey,bitcoin_pubkeylen(waddr->pubkey));
                    jaddistr(pubkeys,pubkeystr);
                }
            }
            if ( spendlen > 0 )
            {
                init_hexbytes_noT(scriptstr,spendscript,spendlen);
                jaddstr(newvin,"scriptPubKey",scriptstr);
            }
            if ( (str= jstr(item,"redeemScript")) != 0 )
            {
                p2shlen = (int32_t)strlen(str) >> 1;
                decode_hex(redeemscript,p2shlen,str);
                init_hexbytes_noT(scriptstr,redeemscript,p2shlen);
                jaddstr(newvin,"redeemScript",scriptstr);
            }
            if ( jint(txobj,"locktime") > 0 )
                sequenceid = (uint32_t)time(NULL); // any value < 0xfffffffe should be fine
            else
            {
                if ( jobj(item,"sequence") != 0 )
                    sequenceid = juint(item,"sequence");
                else sequenceid = 0xffffffff;
            }
            jaddnum(newvin,"sequence",sequenceid);
            bitcoin_txinput(coin,txobj,txid,vout,sequenceid,spendscript,spendlen,redeemscript,p2shlen,0,0,0,0);
            jadd(newvin,"pubkeys",pubkeys);
            jaddi(newvins,newvin);
        }
    }
    return(newvins);
}

ARRAY_OBJ_INT(bitcoinrpc,createrawtransaction,vins,vouts,locktime)
{
    bits256 txid; int32_t offset,spendlen=0,n; uint8_t addrtype,rmd160[20],spendscript[IGUANA_MAXSCRIPTSIZE]; uint64_t satoshis; char *hexstr,*field,*txstr; cJSON *txobj,*item,*obj,*retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( coin != 0 && (txobj= bitcoin_txcreate(coin->symbol,coin->chain->isPoS,locktime,1,0)) != 0 )
    {
        iguana_createvins(myinfo,coin,txobj,vins);
        if ( (n= cJSON_GetArraySize(vouts)) > 0 )
        {
            if ( is_cJSON_Array(vouts) != 0 && n == 1 && (item= jitem(vouts,0)) != 0 )
                item = item->child;
            else item = vouts->child;
            while ( item != 0 )
            {
                if ( (field= jfieldname(item)) != 0 )
                {
                    if ( strcmp(field,"data") == 0 )
                    {
                        if ( (hexstr= jstr(item,0)) != 0 )
                        {
                            spendlen = (int32_t)strlen(hexstr) >> 1;
                            offset = 0;
                            if ( is_hexstr(hexstr,spendlen) > 0 )
                            {
                                decode_hex(spendscript+4,spendlen,hexstr);
                                spendscript[3] = SCRIPT_OPRETURN;
                                spendlen++;
                                /* 1-75	0x01-0x4b	(special)	data	The next opcode bytes is data to be pushed onto the stack
                                 OP_PUSHDATA1	76	0x4c	(special)	data	The next byte contains the number of bytes to be pushed onto the stack.
                                 OP_PUSHDATA2	77	0x4d*/
                                if ( spendlen < 76 )
                                {
                                    spendscript[2] = spendlen;
                                    offset = 2;
                                    spendlen++;
                                }
                                else if ( spendlen <= 0xff )
                                {
                                    spendscript[2] = spendlen;
                                    spendscript[1] = 0x4c;
                                    offset = 1;
                                    spendlen += 2;
                                }
                                else if ( spendlen <= 0xffff )
                                {
                                    spendscript[2] = ((spendlen >> 8) & 0xff);
                                    spendscript[1] = (spendlen & 0xff);
                                    spendscript[0] = 0x4d;
                                    offset = 0;
                                    spendlen += 3;
                                }
                                else continue;
                                if ( (obj= jobj(item,"amount")) != 0 )
                                    satoshis = jdouble(obj,0) * SATOSHIDEN;
                                else satoshis = 0;
                                bitcoin_txoutput(txobj,spendscript+offset,spendlen,satoshis);
                            }
                        }
                        break;
                    }
                    else
                    {
                        if ( bitcoin_addr2rmd160(&addrtype,rmd160,field) == sizeof(rmd160) )
                        {
                            spendlen = bitcoin_standardspend(spendscript,0,rmd160);
                            satoshis = jdouble(item,0) * SATOSHIDEN;
                            bitcoin_txoutput(txobj,spendscript,spendlen,satoshis);
                        }
                    }
                }
                item = item->next;
            }
        }
        if ( (txstr= bitcoin_json2hex(myinfo,coin,&txid,txobj,0)) != 0 )
        {
            jaddstr(retjson,"result",txstr);
            free(txstr);
        }
    }
    return(jprint(retjson,1));
}

cJSON *iguana_listunspents(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *array,int32_t minconf,int32_t maxconf,char *remoteaddr)
{
    cJSON *retjson; int32_t flag = 0;
    if ( array == 0 || is_cJSON_Array(array) == 0 || cJSON_GetArraySize(array) <= 0 )
    {
        array = iguana_getaddressesbyaccount(myinfo,coin,"*");
        flag = 1;
        //printf("listunspent.(%s)\n",jprint(array,0));
    }
    if ( minconf == 0 )
        minconf = 1;
    if ( maxconf == 0 )
        maxconf = (1 << 30);
    retjson = iguana_RTlistunspent(myinfo,coin,array,minconf,maxconf,remoteaddr,0);
    if ( array != 0 && flag != 0 )
        free_json(array);
    return(retjson);
}

TWOINTS_AND_ARRAY(bitcoinrpc,listunspent,minconf,maxconf,array)
{
    //int32_t numrmds,numunspents=0; uint8_t *rmdarray; cJSON *retjson = cJSON_CreateArray();
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = iguana_listunspents(myinfo,coin,array,minconf,maxconf,remoteaddr);
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,getrawchangeaddress)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    cJSON *retjson = cJSON_CreateObject();
    jaddstr(retjson,"result",coin->changeaddr);
    return(jprint(retjson,1));
}

INT_AND_ARRAY(bitcoinrpc,lockunspent,flag,array)
{
    struct iguana_outpoint outpt; int32_t RTspendflag,vout,i,n,height,spentheight,lockedflag; cJSON *item,*retjson; bits256 txid;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    if ( array != 0 && (n= cJSON_GetArraySize(array)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            if ( jobj(item,"txid") != 0 && jobj(item,"vout") != 0 )
            {
                txid = jbits256(item,"txid");
                vout = jint(item,"vout");
                if ( iguana_RTunspentindfind(myinfo,coin,&outpt,0,0,0,0,&height,txid,vout,coin->bundlescount-1,0) == 0 )
                {
                    //outpt.hdrsi = height / coin->chain->bundlesize;
                    //outpt.unspentind = unspentind;
                    iguana_RTutxofunc(coin,&spentheight,&lockedflag,outpt,&RTspendflag,!flag,0); 
                }
            }
        }
    }
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,listlockunspent)
{
    cJSON *array,*retjson; //int32_t vout; //struct iguana_outpoint outpt;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    array = cJSON_CreateArray();
    retjson = cJSON_CreateObject();
    printf("need to port listlockunspent to new RT method\n");
    jaddstr(retjson,"error","need to port listlockunspent to new RT method");
    /*if ( coin->utxotable != 0 )
    {
        HASH_ITER(hh,coin->utxotable,hhutxo,tmputxo)
        {
            item = cJSON_CreateObject();
            //if ( (vout= iguana_RTuvaltxid(myinfo,&txid,coin,hhutxo->outpt)) >= 0 )
            {
                jaddbits256(item,"txid",txid);
                jaddnum(item,"vout",vout);
                jaddi(array,item);
            }
        }
    }*/
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}

DOUBLE_ARG(bitcoinrpc,settxfee,amount)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    coin->txfee_perkb = amount * SATOSHIDEN;
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",jtrue());
    return(jprint(retjson,1));
}

S_D_SS(bitcoinrpc,sendtoaddress,address,amount,comment,comment2)
{
    char *retstr;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    //iguana_unspentset(myinfo,coin);
    if ( (retstr= sendtoaddress(myinfo,coin,remoteaddr,address,amount * SATOSHIDEN,coin->txfee,comment,comment2,coin->minconfirms,0)) != 0 )
        printf("SEND.(%s)\n",retstr);
    return(retstr);
}

SS_D_I_SS(bitcoinrpc,sendfrom,fromaccount,toaddress,amount,minconf,comment,comment2)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    //iguana_unspentset(myinfo,coin);
    return(sendtoaddress(myinfo,coin,remoteaddr,toaddress,amount * SATOSHIDEN,coin->txfee,comment,comment2,minconf,fromaccount));
}

S_A_I_S(bitcoinrpc,sendmany,fromaccount,payments,minconf,comment)
{
    cJSON *retjson,*item; int32_t i,n; char *coinaddr,*str; int64_t required,val; double amount;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    //iguana_unspentset(myinfo,coin);
    n = cJSON_GetArraySize(payments);
    item = payments->child;
    retjson = cJSON_CreateArray();
    for (required=i=0; i<n; i++)
    {
        if ( item != 0 && (coinaddr= item->string) != 0 )
        {
            amount = jdouble(item,0);
            val = amount * SATOSHIDEN;
            printf("(%s %.8f) ",coinaddr,dstr(val));
            if ( (str= sendtoaddress(myinfo,coin,remoteaddr,coinaddr,val,coin->txfee,comment,"",minconf,fromaccount)) != 0 )
            {
                jaddistr(retjson,str);
            }
            required += val;
        }
        item = item->next;
    }
    printf("required %.8f\n",dstr(required));
    return(jprint(retjson,1));
}

THREE_INTS(iguana,splitfunds,satoshis,duplicates,sendflag)
{
    char *rawtx; uint8_t pubkey33[33]; int32_t completed; cJSON *retjson,*addresses; bits256 signedtxid;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    if ( coin == 0 )
        return(clonestr("{\"error\":\"need active coin\"}"));
    retjson = cJSON_CreateObject();
    bitcoin_pubkey33(myinfo->ctx,pubkey33,myinfo->persistent_priv);
    addresses = iguana_getaddressesbyaccount(myinfo,coin,"*");
    if ( (rawtx= iguana_utxoduplicates(myinfo,coin,pubkey33,satoshis,duplicates,&completed,&signedtxid,sendflag,addresses)) != 0 )
    {
        jaddstr(retjson,"result",rawtx);
        jaddbits256(retjson,"txid",signedtxid);
        jadd(retjson,"completed",completed != 0 ? jtrue() : jfalse());
        free(rawtx);
    } else jaddstr(retjson,"error","couldnt create duplicates tx");
    if ( addresses != 0 )
        free_json(addresses);
    return(jprint(retjson,1));
}

P2SH_SPENDAPI(iguana,spendmsig,activecoin,vintxid,vinvout,destaddress,destamount,destaddress2,destamount2,M,N,pubA,wifA,pubB,wifB,pubC,wifC)
{
    struct vin_info V; uint8_t p2sh_rmd160[20],serialized[2096],spendscript[32],pubkeys[3][65],*pubkeyptrs[3]; int32_t spendlen,height = 0;
    char msigaddr[64],*retstr; cJSON *retjson,*txobj; struct iguana_info *active;
    bits256 signedtxid; char *signedtx;
    struct iguana_msgtx msgtx;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    if ( (active= iguana_coinfind(activecoin)) == 0 )
        return(clonestr("{\"error\":\"activecoin isnt active\"}"));
    if ( M > N || N > 3 )
        return(clonestr("{\"error\":\"illegal M or N\"}"));
    memset(&V,0,sizeof(V));
    txobj = bitcoin_txcreate(active->symbol,active->chain->isPoS,0,coin->chain->normal_txversion,0);
    if ( destaddress[0] != 0 && destamount > 0. )
        bitcoin_txaddspend(active,txobj,destaddress,destamount * SATOSHIDEN);
    if ( destaddress2[0] != 0 && destamount2 > 0. )
        bitcoin_txaddspend(active,txobj,destaddress2,destamount2 * SATOSHIDEN);
    if ( pubA[0] != 0 && (retstr= _setVsigner(active,&V,0,pubA,wifA)) != 0 )
        return(retstr);
    if ( N >= 2 && pubB[0] != 0 && (retstr= _setVsigner(active,&V,1,pubB,wifB)) != 0 )
        return(retstr);
    if ( N == 3 && pubC[0] != 0 && (retstr= _setVsigner(active,&V,2,pubC,wifC)) != 0 )
        return(retstr);
    V.M = M, V.N = N, V.type = IGUANA_SCRIPT_P2SH;
    V.p2shlen = bitcoin_MofNspendscript(p2sh_rmd160,V.p2shscript,0,&V);
    spendlen = bitcoin_p2shspend(spendscript,0,p2sh_rmd160);
    if ( pubA[0] != 0 )
    {
        decode_hex(pubkeys[0],(int32_t)strlen(pubA)>>1,pubA);
        pubkeyptrs[0] = pubkeys[0];
    }
    if ( pubB[0] != 0 )
    {
        decode_hex(pubkeys[1],(int32_t)strlen(pubB)>>1,pubB);
        pubkeyptrs[1] = pubkeys[1];
    }
    if ( pubC[0] != 0 )
    {
        decode_hex(pubkeys[2],(int32_t)strlen(pubC)>>1,pubC);
        pubkeyptrs[2] = pubkeys[2];
    }
    bitcoin_txinput(active,txobj,vintxid,vinvout,0xffffffff,spendscript,spendlen,V.p2shscript,V.p2shlen,pubkeyptrs,N,0,0);
    bitcoin_address(msigaddr,active->chain->p2shtype,V.p2shscript,V.p2shlen);
    retjson = cJSON_CreateObject();
    if ( bitcoin_verifyvins(active,height,&signedtxid,&signedtx,&msgtx,serialized,sizeof(serialized),&V,SIGHASH_ALL,1,V.suppress_pubkeys) == 0 )
    {
        jaddstr(retjson,"result","msigtx");
        if ( signedtx != 0 )
            jaddstr(retjson,"signedtx",signedtx), free(signedtx);
        jaddbits256(retjson,"txid",signedtxid);
    } else jaddstr(retjson,"error","couldnt sign tx");
    jaddstr(retjson,"msigaddr",msigaddr);
    return(jprint(retjson,1));
}

STRING_ARRAY_OBJ_STRING(bitcoinrpc,signrawtransaction,rawtx,vins,privkeys,sighash)
{
    char *signedtx = 0; struct vin_info *V; bits256 signedtxid; int32_t complete,numinputs = 1; struct iguana_msgtx msgtx; cJSON *retjson; int uselessbitcoin_error = 0;
    retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    //printf("rawtx.(%s) vins.(%s) privkeys.(%s) sighash.(%s)\n",rawtx,jprint(vins,0),jprint(privkeys,0),sighash);
    if ( sighash == 0 || sighash[0] == 0 )
        sighash = "ALL";
    if ( strcmp(sighash,"ALL") != 0 )
        jaddstr(retjson,"error","only sighash all (ALL) supported for now");
    if ( (numinputs= cJSON_GetArraySize(vins)) > 0 )
    {
        V = calloc(numinputs,sizeof(*V));
        memset(&msgtx,0,sizeof(msgtx));
        if ( (complete= iguana_signrawtransaction(myinfo,coin,coin->blocks.hwmchain.height,&msgtx,&signedtx,&signedtxid,V,numinputs,rawtx,vins,privkeys)) >= 0 )
        {
            if ( signedtx != 0 )
            {
                jaddstr(retjson,"result",signedtx);
                jadd(retjson,"complete",complete!=0?jtrue():jfalse());
                free(signedtx);
            } else jaddstr(retjson,"error",uselessbitcoin_error != 0 ? "-22" : "no transaction from verifyvins");
        }
        else if ( complete == -2 )
            jaddstr(retjson,"error",uselessbitcoin_error != 0 ? "-22" : "hex2json -> json2hex error");
        else if ( complete == -1 )
            jaddstr(retjson,"error",uselessbitcoin_error != 0 ? "-22" : "couldnt load serialized tx or mismatched numinputs");
        free(V);
        //for (i=0; i<msgtx.tx_in; i++)
        //    if ( msgtx.vins[i].redeemscript != 0 )
        //        free(msgtx.vins[i].redeemscript), msgtx.vins[i].redeemscript = 0;
    } else jaddstr(retjson,"error",uselessbitcoin_error != 0 ? "-22" : "no rawtx or rawtx too big");
    return(jprint(retjson,1));
}
#include "../includes/iguana_apiundefs.h"
