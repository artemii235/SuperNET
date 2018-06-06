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

// deprecated
#include "iguana777.h"

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"
#include "../includes/iguana_apideclares2.h"


STRING_ARG(iguana,peers,activecoin)
{
    if ( coin != 0 )
        return(jprint(iguana_peersjson(coin,0),1));
    else return(clonestr("{\"error\":\"peers needs coin\"}"));
}

STRING_ARG(iguana,getconnectioncount,activecoin)
{
    int32_t i,num = 0; char buf[512];
    if ( coin != 0 && coin->peers != 0 )
    {
        for (i=0; i<sizeof(coin->peers->active)/sizeof(*coin->peers->active); i++)
            if ( coin->peers->active[i].usock >= 0 )
                num++;
        sprintf(buf,"{\"result\":\"%d\"}",num);
        return(clonestr(buf));
    } else return(clonestr("{\"error\":\"getconnectioncount needs coin\"}"));
}

ZERO_ARGS(bitcoinrpc,getdifficulty)
{
    char buf[512];
    if ( coin != 0 )
    {
        sprintf(buf,"{\"result\":\"success\",\"proof-of-work\":\"%.8f\",\"search-interval\": 0}",PoW_from_compact(coin->blocks.hwmchain.RO.bits,coin->chain->unitval));
        return(clonestr(buf));
    } else return(clonestr("{\"error\":\"getdifficulty needs coin\"}"));
}

STRING_ARG(iguana,addcoin,newcoin)
{
    char *symbol,*seedip; int32_t retval;
    if ( (symbol= newcoin) == 0 && coin != 0 )
        symbol = coin->symbol;
    if ( symbol != 0 )
    {
        if ( (seedip= jstr(json,"seedipaddr")) != 0 )
            safecopy(myinfo->seedipaddr,seedip,sizeof(myinfo->seedipaddr));
        printf(">> addcoin.%s seedipaddr.%s\n",symbol,myinfo->seedipaddr);
#ifdef __PNACL__
        //        if ( strcmp(symbol,"BTC") == 0 )
        //            return(clonestr("{\"result\":\"BTC for chrome app is not yet\"}"));
#endif
        if ( (retval= iguana_launchcoin(myinfo,symbol,json,0)) > 0 )
        {
            if ( myinfo->rpcsymbol[0] == 0 )
                safecopy(myinfo->rpcsymbol,symbol,sizeof(myinfo->rpcsymbol));
            return(clonestr("{\"result\":\"coin added\"}"));
        }
        else if ( retval == 0 )
            return(clonestr("{\"result\":\"coin already there\"}"));
        else return(clonestr("{\"error\":\"error adding coin\"}"));
    } else return(clonestr("{\"error\":\"addcoin needs newcoin\"}"));
}

STRING_ARG(iguana,startcoin,activecoin)
{
    if ( coin != 0 )
    {
        coin->active = 1;
        return(clonestr("{\"result\":\"coin started\"}"));
    } else return(clonestr("{\"error\":\"startcoin needs coin\"}"));
}

STRING_ARG(iguana,stopcoin,activecoin)
{
    if ( activecoin[0] != 0 )
        coin = iguana_coinfind(activecoin);
    if ( coin != 0 )
    {
        coin->active = 0;
        //iguana_coinpurge(coin);
        return(clonestr("{\"result\":\"coin stopped\"}"));
    } else return(clonestr("{\"error\":\"stopcoin needs coin\"}"));
}

STRING_ARG(iguana,pausecoin,activecoin)
{
    if ( coin != 0 )
    {
        coin->active = 0;
        return(clonestr("{\"result\":\"coin paused\"}"));
    } else return(clonestr("{\"error\":\"pausecoin needs coin\"}"));
}

TWO_STRINGS(iguana,addnode,activecoin,ipaddr)
{
    struct iguana_peer *addr; int32_t i,n;
    if ( coin == 0 )
        coin = iguana_coinfind(activecoin);
    if ( coin != 0 && strcmp(coin->symbol,"RELAY") == 0 )
        basilisk_addrelay_info(myinfo,0,(uint32_t)calc_ipbits(ipaddr),GENESIS_PUBKEY);
    printf("coin.%p.[%s] addnode.%s -> %s\n",coin,coin!=0?coin->symbol:"",activecoin,ipaddr);
    if ( coin != 0 && coin->peers != 0 && ipaddr != 0 && is_ipaddr(ipaddr) != 0 )
    {
        //iguana_possible_peer(coin,ipaddr);
        if ( (addr= iguana_peerslot(coin,(uint32_t)calc_ipbits(ipaddr),1)) != 0 )
        {
            addr->supernet = 1;
            if ( addr->usock >= 0 )
            {
                if ( (n= coin->peers->numranked) != 0 )
                {
                    for (i=0; i<n; i++)
                    {
                        if ( addr == coin->peers->ranked[i] )
                            break;
                    }
                    if ( i == n )
                    {
                        if ( i == IGUANA_MAXPEERS )
                            i--;
                        else coin->peers->numranked = n+1;
                        coin->peers->ranked[i] = addr;
                        addr->recvblocks = coin->peers->ranked[0]->recvblocks + 100;
                        addr->recvtotal = coin->peers->ranked[0]->recvtotal*1.1 + 100;
                        printf("set (%s) -> slot.%d numranked.%d\n",ipaddr,i,coin->peers->numranked);
                    } else printf("(%s) is already peer.%d\n",ipaddr,i);
                }
                return(clonestr("{\"result\":\"peer was already connected\"}"));
            }
            if ( addr->pending == 0 )
            {
                addr->pending = (uint32_t)time(NULL);
                iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
                return(clonestr("{\"result\":\"addnode submitted\"}"));
            } else return(clonestr("{\"result\":\"addnode connection was already pending\"}"));
        } else return(clonestr("{\"result\":\"addnode cant find peer slot\"}"));
    }
    else if ( coin == 0 )
        return(clonestr("{\"error\":\"addnode needs active coin, do an addcoin first\"}"));
    else return(clonestr("{\"error\":\"addnode needs ipaddr\"}"));
}

TWO_STRINGS(iguana,persistent,activecoin,ipaddr)
{
    int32_t i;
    if ( coin != 0 && coin->peers != 0 && ipaddr != 0 )
    {
        for (i=0; i<IGUANA_MAXPEERS; i++)
        {
            if ( strcmp(coin->peers->active[i].ipaddr,ipaddr) == 0 )
            {
                coin->peers->active[i].persistent_peer = juint(json,"interval")+3;
                return(clonestr("{\"result\":\"node marked as persistent\"}"));
            }
        }
        return(clonestr("{\"result\":\"node wasnt active\"}"));
    } else return(clonestr("{\"error\":\"persistent needs coin and ipaddr\"}"));
}

TWO_STRINGS(iguana,removenode,activecoin,ipaddr)
{
    int32_t i;
    if ( coin != 0 && coin->peers != 0 && ipaddr != 0 )
    {
        for (i=0; i<IGUANA_MAXPEERS; i++)
        {
            if ( strcmp(coin->peers->active[i].ipaddr,ipaddr) == 0 )
            {
                coin->peers->active[i].rank = 0;
                coin->peers->active[i].dead = (uint32_t)time(NULL);
                return(clonestr("{\"result\":\"node marked as dead\"}"));
            }
        }
        return(clonestr("{\"result\":\"node wasnt active\"}"));
    } else return(clonestr("{\"error\":\"removenode needs coin and ipaddr\"}"));
}

TWO_STRINGS(iguana,oneshot,activecoin,ipaddr)
{
    if ( coin != 0 && ipaddr != 0 )
    {
        iguana_possible_peer(coin,ipaddr);
        return(clonestr("{\"result\":\"addnode submitted\"}"));
    } else return(clonestr("{\"error\":\"addnode needs coin and ipaddr\"}"));
}

cJSON *iguana_peerjson(struct iguana_info *coin,struct iguana_peer *addr)
{
    cJSON *array,*json = cJSON_CreateObject();
    jaddstr(json,"ipaddr",addr->ipaddr);
    if ( addr->supernet != 0 )
        jaddstr(json,"ipaddr",addr->ipaddr);
    jaddstr(json,"supernet","yes");
    jaddnum(json,"protover",addr->protover);
    jaddnum(json,"relay",addr->relayflag);
    jaddnum(json,"height",addr->height);
    jaddnum(json,"rank",addr->rank);
    jaddnum(json,"usock",addr->usock);
    if ( addr->dead != 0 )
        jaddnum(json,"dead",addr->dead);
    jaddnum(json,"ready",addr->ready);
    jaddnum(json,"recvblocks",addr->recvblocks);
    jaddnum(json,"recvtotal",addr->recvtotal);
    jaddnum(json,"lastcontact",addr->lastcontact);
    if ( addr->numpings > 0 )
        jaddnum(json,"aveping",addr->pingsum/addr->numpings);
    array = cJSON_CreateObject();
    jaddnum(array,"version",addr->msgcounts.version);
    jaddnum(array,"verack",addr->msgcounts.verack);
    jaddnum(array,"getaddr",addr->msgcounts.getaddr);
    jaddnum(array,"addr",addr->msgcounts.addr);
    jaddnum(array,"inv",addr->msgcounts.inv);
    jaddnum(array,"getdata",addr->msgcounts.getdata);
    jaddnum(array,"notfound",addr->msgcounts.notfound);
    jaddnum(array,"getblocks",addr->msgcounts.getblocks);
    jaddnum(array,"getheaders",addr->msgcounts.getheaders);
    jaddnum(array,"headers",addr->msgcounts.headers);
    jaddnum(array,"tx",addr->msgcounts.tx);
    jaddnum(array,"block",addr->msgcounts.block);
    jaddnum(array,"mempool",addr->msgcounts.mempool);
    jaddnum(array,"ping",addr->msgcounts.ping);
    jaddnum(array,"pong",addr->msgcounts.pong);
    jaddnum(array,"reject",addr->msgcounts.reject);
    jaddnum(array,"filterload",addr->msgcounts.filterload);
    jaddnum(array,"filteradd",addr->msgcounts.filteradd);
    jaddnum(array,"filterclear",addr->msgcounts.filterclear);
    jaddnum(array,"merkleblock",addr->msgcounts.merkleblock);
    jaddnum(array,"alert",addr->msgcounts.alert);
    jadd(json,"msgcounts",array);
    return(json);
}

cJSON *iguana_peersjson(struct iguana_info *coin,int32_t addronly)
{
    cJSON *retjson,*array; int32_t i; struct iguana_peer *addr;
    if ( coin == 0 || coin->peers == 0 )
        return(0);
    array = cJSON_CreateArray();
    for (i=0; i<coin->MAXPEERS; i++)
    {
        addr = &coin->peers->active[i];
        if ( addr->usock >= 0 && addr->ipbits != 0 && addr->ipaddr[0] != 0 )
        {
            if ( addronly != 0 )
                jaddistr(array,addr->ipaddr);
            else jaddi(array,iguana_peerjson(coin,addr));
        }
    }
    if ( addronly == 0 )
    {
        retjson = cJSON_CreateObject();
        jadd(retjson,"peers",array);
        jaddnum(retjson,"maxpeers",coin->MAXPEERS);
        jaddstr(retjson,"coin",coin->symbol);
        return(retjson);
    }
    else return(array);
}

TWO_STRINGS(iguana,nodestatus,activecoin,ipaddr)
{
    int32_t i; struct iguana_peer *addr;
    if ( coin != 0 && coin->peers != 0 && ipaddr != 0 )
    {
        for (i=0; i<coin->MAXPEERS; i++)
        {
            addr = &coin->peers->active[i];
            if ( strcmp(addr->ipaddr,ipaddr) == 0 )
                return(jprint(iguana_peerjson(coin,addr),1));
        }
        return(clonestr("{\"result\":\"nodestatus couldnt find ipaddr\"}"));
    } else return(clonestr("{\"error\":\"nodestatus needs ipaddr\"}"));
}

STRING_AND_INT(iguana,maxpeers,activecoin,max)
{
    cJSON *retjson; int32_t i; struct iguana_peer *addr;
    if ( coin != 0 && coin->peers != 0 )
    {
        retjson = cJSON_CreateObject();
        if ( max > IGUANA_MAXPEERS )
            max = IGUANA_MAXPEERS;
        if ( max > coin->MAXPEERS )
        {
            for (i=max; i<coin->MAXPEERS; i++)
                if ( (addr= coin->peers->ranked[i]) != 0 )
                    addr->dead = 1;
        }
        coin->MAXPEERS = max;
        jaddnum(retjson,"maxpeers",coin->MAXPEERS);
        jaddstr(retjson,"coin",coin->symbol);
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"maxpeers needs coin\"}"));
}

char *hmac_dispatch(char *(*hmacfunc)(char *dest,char *key,int32_t key_size,char *message),char *name,char *message,char *password)
{
    char hexstr[1025]; cJSON *json;
    if ( message != 0 && password != 0 && message[0] != 0 && password[0] != 0 )
    {
        memset(hexstr,0,sizeof(hexstr));
        (*hmacfunc)(hexstr,password,password==0?0:(int32_t)strlen(password),message);
        json = cJSON_CreateObject();
        jaddstr(json,"result","hmac calculated");
        jaddstr(json,"message",message);
        jaddstr(json,name,hexstr);
        return(jprint(json,1));
    } else return(clonestr("{\"error\":\"hmac needs message and passphrase\"}"));
}

char *hash_dispatch(void (*hashfunc)(char *hexstr,uint8_t *buf,uint8_t *msg,int32_t len),char *name,char *message)
{
    char hexstr[65537]; uint8_t databuf[32768]; cJSON *json;
    if ( message != 0 && message[0] != 0 )
    {
        memset(hexstr,0,sizeof(hexstr));
        (*hashfunc)(hexstr,databuf,(uint8_t *)message,(int32_t)strlen(message));
        json = cJSON_CreateObject();
        jaddstr(json,"result","hash calculated");
        jaddstr(json,"message",message);
        jaddstr(json,name,hexstr);
        return(jprint(json,1));
    } else return(clonestr("{\"error\":\"hash needs message\"}"));
}

TWO_HASHES(hash,curve25519_pair,element,scalar)
{
    cJSON *retjson = cJSON_CreateObject();
    jaddbits256(retjson,"result",curve25519(element,scalar));
    return(jprint(retjson,1));
}

STRING_ARG(hash,NXT,passphrase) { return(hash_dispatch(calc_NXTaddr,"NXT",passphrase)); }
STRING_ARG(hash,curve25519,pubkey) { return(hash_dispatch(calc_curve25519_str,"curve25519",pubkey)); }
STRING_ARG(hash,crc32,message) { return(hash_dispatch(calc_crc32str,"crc32",message)); }
STRING_ARG(hash,base64_encode,message) { return(hash_dispatch(calc_base64_encodestr,"base64_encode",message)); }
STRING_ARG(hash,base64_decode,message) { return(hash_dispatch(calc_base64_decodestr,"base64_decode",message)); }
STRING_ARG(hash,rmd160_sha256,message) { return(hash_dispatch(rmd160ofsha256,"rmd160_sha256",message)); }
STRING_ARG(hash,sha256_sha256,message) { return(hash_dispatch(sha256_sha256,"sha256_sha256",message)); }
STRING_ARG(hash,hex,message) { return(hash_dispatch(calc_hexstr,"hex",message)); }
STRING_ARG(hash,unhex,message) { return(hash_dispatch(calc_unhexstr,"unhex",message)); }

STRING_ARG(hash,sha224,message) { return(hash_dispatch(calc_sha224,"sha224",message)); }
STRING_ARG(hash,sha256,message) { return(hash_dispatch(vcalc_sha256,"sha256",message)); }
STRING_ARG(hash,sha384,message) { return(hash_dispatch(calc_sha384,"sha384",message)); }
STRING_ARG(hash,sha512,message) { return(hash_dispatch(calc_sha512,"sha512",message)); }
STRING_ARG(hash,rmd128,message) { return(hash_dispatch(calc_rmd128,"rmd128",message)); }
STRING_ARG(hash,rmd160,message) { return(hash_dispatch(calc_rmd160,"rmd160",message)); }
STRING_ARG(hash,rmd256,message) { return(hash_dispatch(calc_rmd256,"rmd256",message)); }
STRING_ARG(hash,rmd320,message) { return(hash_dispatch(calc_rmd320,"rmd320",message)); }
STRING_ARG(hash,sha1,message) { return(hash_dispatch(calc_sha1,"sha1",message)); }
STRING_ARG(hash,md2,message) { return(hash_dispatch(calc_md2str,"md2",message)); }
STRING_ARG(hash,md4,message) { return(hash_dispatch(calc_md4str,"md4",message)); }
STRING_ARG(hash,md5,message) { return(hash_dispatch(calc_md5str,"md5",message)); }
STRING_ARG(hash,tiger192_3,message) { return(hash_dispatch(calc_tiger,"tiger",message)); }
STRING_ARG(hash,whirlpool,message) { return(hash_dispatch(calc_whirlpool,"whirlpool",message)); }
TWO_STRINGS(hmac,sha224,message,passphrase) { return(hmac_dispatch(hmac_sha224_str,"sha224",message,passphrase)); }
TWO_STRINGS(hmac,sha256,message,passphrase) { return(hmac_dispatch(hmac_sha256_str,"sha256",message,passphrase)); }
TWO_STRINGS(hmac,sha384,message,passphrase) { return(hmac_dispatch(hmac_sha384_str,"sha384",message,passphrase)); }
TWO_STRINGS(hmac,sha512,message,passphrase) { return(hmac_dispatch(hmac_sha512_str,"sha512",message,passphrase)); }
TWO_STRINGS(hmac,rmd128,message,passphrase) { return(hmac_dispatch(hmac_rmd128_str,"rmd128",message,passphrase)); }
TWO_STRINGS(hmac,rmd160,message,passphrase) { return(hmac_dispatch(hmac_rmd160_str,"rmd160",message,passphrase)); }
TWO_STRINGS(hmac,rmd256,message,passphrase) { return(hmac_dispatch(hmac_rmd256_str,"rmd256",message,passphrase)); }
TWO_STRINGS(hmac,rmd320,message,passphrase) { return(hmac_dispatch(hmac_rmd320_str,"rmd320",message,passphrase)); }
TWO_STRINGS(hmac,sha1,message,passphrase) { return(hmac_dispatch(hmac_sha1_str,"sha1",message,passphrase)); }
TWO_STRINGS(hmac,md2,message,passphrase) { return(hmac_dispatch(hmac_md2_str,"md2",message,passphrase)); }
TWO_STRINGS(hmac,md4,message,passphrase) { return(hmac_dispatch(hmac_md4_str,"md4",message,passphrase)); }
TWO_STRINGS(hmac,md5,message,passphrase) { return(hmac_dispatch(hmac_md5_str,"md5",message,passphrase)); }
TWO_STRINGS(hmac,tiger192_3,message,passphrase) { return(hmac_dispatch(hmac_tiger_str,"tiger",message,passphrase)); }
TWO_STRINGS(hmac,whirlpool,message,passphrase) { return(hmac_dispatch(hmac_whirlpool_str,"whirlpool",message,passphrase)); }

STRING_ARG(SuperNET,bitcoinrpc,setcoin)
{
    char buf[1024];
    if ( setcoin != 0 && setcoin[0] != 0 )
    {
        strcpy(myinfo->rpcsymbol,setcoin);
        touppercase(myinfo->rpcsymbol);
        printf("bitcoinrpc.%s\n",myinfo->rpcsymbol);
        if ( iguana_launchcoin(myinfo,myinfo->rpcsymbol,json,0) < 0 )
            return(clonestr("{\"error\":\"error creating coin\"}"));
        else
        {
            sprintf(buf,"{\"result\":\"success\",\"setcoin\":\"%s\"}",setcoin);
            return(clonestr(buf));
        }
    } else return(clonestr("{\"error\":\"bitcoinrpc needs setcoin value\"}"));
}

ZERO_ARGS(SuperNET,help)
{
    cJSON *helpjson,*retjson;
    if ( (helpjson= SuperNET_helpjson()) != 0 )
    {
        retjson = cJSON_CreateObject();
        jadd(retjson,"result",helpjson);
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"cant get helpjson\"}"));
}

TWO_STRINGS(SuperNET,html,agentform,htmlfile)
{
    char *htmlstr; cJSON *retjson; int32_t max = 4*1024*1024;
    if ( htmlfile == 0 || htmlfile[0] == 0 )
        htmlfile = "forms.html";
    //if ( (fp= fopen(htmlfile,"w")) == 0 )
    //    printf("error opening htmlfile.(%s)\n",htmlfile);
    htmlstr = malloc(max);
    htmlstr = SuperNET_htmlstr(htmlfile,htmlstr,max,agentform);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result",htmlstr);
    free(htmlstr);
    //if ( fp != 0 )
    //    fclose(fp);
    return(jprint(retjson,1));
}

#undef IGUANA_ARGS
#undef _IGUANA_APIDEC_H_
#include "../includes/iguana_apiundefs.h"

