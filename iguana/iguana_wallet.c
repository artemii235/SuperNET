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

#include "iguana777.h"
#include "exchanges/bitcoin.h"

void scrubfree(char *sensitivestr)
{
    long len,i;
    if ( sensitivestr != 0 )
    {
        len = strlen(sensitivestr);
        memset(sensitivestr,0,len);
        for (i=0; i<len; i++)
            sensitivestr[i] = rand();
        free(sensitivestr);
    }
}

struct iguana_waddress *iguana_waddressfind(struct supernet_info *myinfo,struct iguana_waccount *wacct,char *coinaddr)
{
    struct iguana_waddress *waddr,*tmp; uint8_t addrtype,rmd160[20];
    bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
    //calc_rmd160_sha256(rmd160,pubkey33,33);
    HASH_FIND(hh,wacct->waddr,rmd160,sizeof(rmd160),waddr);
    if ( waddr == 0 )
    {
        HASH_ITER(hh,wacct->waddr,waddr,tmp)
        {
            //printf("%s ",waddr->coinaddr);
        }
        //printf("not in %s\n",wacct->account);
    }
    //if ( waddr != 0 && coin != 0 && strcmp(coin->symbol,waddr->symbol) != 0 )
    //    return(0);
    //printf("%s (%s).%d in (%s)\n",waddr==0?"couldnt find":"found",coinaddr,len,wacct->account);
    return(waddr);
}

struct iguana_waddress *iguana_waddressalloc(uint8_t addrtype,char *symbol,char *coinaddr,char *redeemScript)
{
    struct iguana_waddress *waddr; int32_t scriptlen;
    scriptlen = (redeemScript != 0) ? ((int32_t)strlen(redeemScript) >> 1) : 0;
    waddr = mycalloc('w',1,sizeof(*waddr) + scriptlen);
    waddr->addrtype = addrtype;
    strcpy(waddr->coinaddr,coinaddr);
    bitcoin_addr2rmd160(&addrtype,waddr->rmd160,coinaddr);
    strcpy(waddr->symbol,symbol);
    if ( (waddr->scriptlen= scriptlen) != 0 )
        decode_hex(waddr->redeemScript,scriptlen,redeemScript);
    return(waddr);
}

struct iguana_waccount *iguana_waccountfind(struct supernet_info *myinfo,char *account)
{
    struct iguana_waccount *wacct = 0;
    if ( account != 0 )
        HASH_FIND(hh,myinfo->wallet,account,strlen(account)+1,wacct);
    //printf("waccountfind.(%s) -> wacct.%p\n",account,wacct);
    return(wacct);
}

struct iguana_waccount *iguana_waccountcreate(struct supernet_info *myinfo,char *account)
{
    struct iguana_waccount *wacct=0,*ptr; int32_t len;
    if ( account != 0 )
    {
        if ( account[0] == 0 )
            account = "default";
        len = (int32_t)strlen(account)+1;
        HASH_FIND(hh,myinfo->wallet,account,len,wacct);
        if ( wacct == 0 )
        {
            wacct = mycalloc('w',1,sizeof(*wacct) + len);
            strcpy(wacct->account,account);
            HASH_ADD_KEYPTR(hh,myinfo->wallet,wacct->account,len,wacct);
            //printf("waccountcreate.(%s) -> wacct.%p\n",account,wacct);
            if ( (ptr= iguana_waccountfind(myinfo,account)) != wacct )
            {
                printf("ERROR: iguana_waccountcreate verify error %p vs %p\n",ptr,wacct);
                HASH_FIND(hh,myinfo->wallet,account,len,wacct);
                printf("HASH_FIND.%p\n",wacct);
                getchar();
            }
            myinfo->dirty = (uint32_t)time(NULL);
        }
    }
    return(wacct);
}

struct iguana_waddress *iguana_waddresscreate(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,char *coinaddr,char *redeemScript)
{
    struct iguana_waddress *waddr,*ptr; uint8_t rmd160[20],addrtype;
    bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
    if ( wacct == 0 )
        wacct = iguana_waccountcreate(myinfo,"");
    HASH_FIND(hh,wacct->waddr,rmd160,sizeof(rmd160),waddr);
    if ( waddr == 0 )
    {
        if ( (waddr= iguana_waddressalloc(redeemScript==0?coin->chain->pubtype : coin->chain->p2shtype,coin->symbol,coinaddr,redeemScript)) != 0 )
        {
            HASH_ADD_KEYPTR(hh,wacct->waddr,waddr->rmd160,sizeof(waddr->rmd160),waddr);
            myinfo->dirty = (uint32_t)time(NULL);
            printf("create (%s)scriptlen.%d -> (%s)\n",coinaddr,waddr->scriptlen,wacct->account);
        } else printf("error iguana_waddressalloc null waddr\n");
    } //else printf("have (%s) in (%s)\n",coinaddr,wacct->account);
    if ( (ptr= iguana_waddressfind(myinfo,wacct,coinaddr)) != waddr )
        printf("iguana_waddresscreate verify error %p vs %p\n",ptr,waddr);
    return(waddr);
}

struct iguana_waddress *iguana_waddressadd(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,struct iguana_waddress *addwaddr,char *redeemScript)
{
    struct iguana_waddress *waddr,*ptr; uint8_t rmd160[20],addrtype;
    //printf("search for (%s)\n",addwaddr->coinaddr);
    bitcoin_addr2rmd160(&addrtype,rmd160,addwaddr->coinaddr);
    HASH_FIND(hh,wacct->waddr,rmd160,sizeof(rmd160),waddr);
    if ( waddr == 0 )
    {
        if ( (waddr= iguana_waddressalloc(addrtype,coin->symbol,addwaddr->coinaddr,redeemScript)) == 0 )
        {
            printf("error iguana_waddressalloc null waddr\n");
            return(0);
        }
    } //else printf("have (%s) in (%s)\n",waddr->coinaddr,wacct->account);
    if ( waddr != 0 && waddr != addwaddr )
    {
        myinfo->dirty = (uint32_t)time(NULL);
        waddr->wiftype = coin->chain->wiftype;
        if ( redeemScript != 0 && (addwaddr->scriptlen= (int32_t)strlen(redeemScript) >> 1) != 0 )
        {
            if ( waddr->scriptlen != addwaddr->scriptlen )
            {
                if ( waddr->scriptlen < addwaddr->scriptlen )
                {
                    printf("unexpected waddr->scriptlen mismatch\n");
                }
                waddr->scriptlen = addwaddr->scriptlen;
                decode_hex(waddr->redeemScript,waddr->scriptlen,redeemScript);
            }
            waddr->addrtype = addrtype;//coin->chain->p2shtype;
            memset(&waddr->privkey,0,sizeof(waddr->privkey));
            memset(waddr->pubkey,0,sizeof(waddr->pubkey));
            calc_rmd160_sha256(waddr->rmd160,waddr->redeemScript,waddr->scriptlen);
        }
        else
        {
            waddr->addrtype = addrtype;//coin->chain->pubtype;
            waddr->wiftype = addwaddr->wiftype;
            //if ( bits256_nonz(waddr->privkey) == 0 )
                waddr->privkey = addwaddr->privkey;
            //if ( addwaddr->wifstr[0] != 0 )
                strcpy(waddr->wifstr,addwaddr->wifstr);
            memcpy(waddr->rmd160,rmd160,sizeof(waddr->rmd160));
            if ( addwaddr->pubkey[0] == 0 )
                bitcoin_pubkey33(myinfo->ctx,addwaddr->pubkey,addwaddr->privkey);
            calc_rmd160_sha256(rmd160,addwaddr->pubkey,bitcoin_pubkeylen(addwaddr->pubkey));
            if ( memcmp(rmd160,waddr->rmd160,sizeof(waddr->rmd160)) == 0 )
                memcpy(waddr->pubkey,addwaddr->pubkey,sizeof(waddr->pubkey));
        }
        bitcoin_address(waddr->coinaddr,waddr->addrtype,waddr->rmd160,sizeof(waddr->rmd160));
        myinfo->dirty = (uint32_t)time(NULL);
    }
    if ( (ptr= iguana_waddressfind(myinfo,wacct,waddr->coinaddr)) == 0 )
    {
        HASH_ADD_KEYPTR(hh,wacct->waddr,waddr->rmd160,sizeof(waddr->rmd160),waddr);
        myinfo->dirty = (uint32_t)time(NULL);
        //int32_t i; for (i=0; i<20; i++)
        //    printf("%02x",waddr->rmd160[i]);
        //printf(" add (%s) scriptlen.%d -> (%s) wif.(%s)\n",waddr->coinaddr,waddr->scriptlen,wacct->account,waddr->wifstr);
    }
    else
    {
        waddr = ptr;
        printf("(%s) already in account.(%s)\n",waddr->coinaddr,wacct->account);
    }
    if ( waddr != 0 && waddr->symbol[0] == 0 )
        strcpy(waddr->symbol,coin->symbol);
    return(waddr);
}

struct iguana_waddress *iguana_waddressdelete(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,char *coinaddr)
{
    struct iguana_waddress *waddr = 0; uint8_t rmd160[20],addrtype;
    bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
    HASH_FIND(hh,wacct->waddr,rmd160,sizeof(rmd160),waddr);
    if ( waddr != 0 )
    {
        HASH_DELETE(hh,wacct->waddr,waddr);
        myinfo->dirty = (uint32_t)time(NULL);
    }
    return(waddr);
}

struct iguana_waddress *iguana_waddresssearch(struct supernet_info *myinfo,struct iguana_waccount **wacctp,char *coinaddr)
{
    struct iguana_waccount *wacct,*tmp; struct iguana_waddress *waddr;
    HASH_ITER(hh,myinfo->wallet,wacct,tmp)
    {
        if ( (waddr= iguana_waddressfind(myinfo,wacct,coinaddr)) != 0 )
        {
            if ( waddr != 0 && bits256_nonz(waddr->privkey) != 0 && waddr->wifstr[0] == 0 )
            {
                printf("coinaddr.(%s) no wifstr\n",coinaddr);
                //if ( bitcoin_priv2wif(waddr->wifstr,waddr->privkey,coin->chain->wiftype) > 0 )
                //{
                //}
            }
            (*wacctp) = wacct;
            return(waddr);
        } //else printf("not in (%s)\n",wacct->account);
    }
    (*wacctp) = 0;
    return(0);
}

struct iguana_waddress *iguana_waddresscalc(struct supernet_info *myinfo,uint8_t pubtype,uint8_t wiftype,struct iguana_waddress *waddr,bits256 privkey)
{
    waddr->privkey = privkey;
    bitcoin_pubkey33(myinfo->ctx,waddr->pubkey,waddr->privkey);
    calc_rmd160_sha256(waddr->rmd160,waddr->pubkey,33);
    bitcoin_address(waddr->coinaddr,pubtype,waddr->rmd160,sizeof(waddr->rmd160));
    if ( bits256_nonz(privkey) != 0 )
    {
        myinfo->dirty = (uint32_t)time(NULL);
        if ( bitcoin_priv2wif(waddr->wifstr,waddr->privkey,wiftype) > 0 )
        {
            waddr->wiftype = wiftype;
            waddr->addrtype = pubtype;
            return(waddr);
        }
    } else printf("waddress_calc.(%s) null privkey\n",waddr->coinaddr);
    return(0);
}

struct iguana_waddress *iguana_waccountswitch(struct supernet_info *myinfo,struct iguana_info *coin,char *account,char *coinaddr,char *redeemScript)
{
    struct iguana_waccount *wacct = 0; struct iguana_waddress addr,*waddr = 0; int32_t flag = 0;
    if ( (waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) != 0 && wacct != 0 )
    {
        if ( strcmp(wacct->account,account) != 0 )
        {
            addr = *waddr;
            flag = 1;
            iguana_waddressdelete(myinfo,coin,wacct,coinaddr);
            waddr = 0;
        }
    }
    if ( (wacct= iguana_waccountcreate(myinfo,account)) != 0 )
    {
        if ( waddr == 0 )
            waddr = iguana_waddresscreate(myinfo,coin,wacct,coinaddr,redeemScript);
        if ( waddr != 0 )
        {
            if ( redeemScript == 0 )
                iguana_waddresscalc(myinfo,coin->chain->pubtype,coin->chain->wiftype,waddr,addr.privkey);
            strcpy(waddr->coinaddr,coinaddr);
            waddr = iguana_waddressadd(myinfo,coin,wacct,waddr,redeemScript);
            if ( flag != 0 )
                waddr->privkey = addr.privkey;
        } else waddr = 0;
    }
    myinfo->dirty = (uint32_t)time(NULL);
    return(waddr);
}

uint8_t *iguana_walletrmds(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *numrmdsp)
{
    int32_t iter,n,m; struct iguana_waccount *acct,*tmp; uint8_t *pubkeys=0,*addrtypes=0,*rmdarray = 0; struct iguana_waddress *waddr,*tmp2;
    for (iter=n=m=0; iter<2; iter++)
    {
        HASH_ITER(hh,myinfo->wallet,acct,tmp)
        {
            HASH_ITER(hh,acct->waddr,waddr,tmp2)
            {
                if ( iter == 0 )
                    n++;
                else if ( addrtypes != 0 && pubkeys != 0 && m < n )
                {
                    addrtypes[m] = waddr->addrtype;
                    memcpy(&rmdarray[m * 20],waddr->rmd160,20);
                    memcpy(&pubkeys[m * 33],waddr->pubkey,33);
                    m++;
                }
            }
        }
        if ( iter == 0 )
        {
            rmdarray = calloc(n,20 + 1 + 33);
            addrtypes = &rmdarray[n * 20];
            pubkeys = &rmdarray[n * 21];
        }
    }
    return(rmdarray);
}

cJSON *iguana_getaddressesbyaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *account)
{
    struct iguana_waccount *subset,*tmp; char refaddr[64],coinaddr[64]; struct iguana_waddress *waddr,*tmp2; cJSON *retjson,*array;
    if ( coin == 0 )
        return(0);
    retjson = cJSON_CreateObject();
    array = cJSON_CreateArray();
    if ( account == 0 || account[0] == 0 )
        account = "*";
    if ( strcmp("*",account) != 0 )
    {
        if ( (subset= iguana_waccountfind(myinfo,account)) != 0 )
        {
            HASH_ITER(hh,subset->waddr,waddr,tmp2)
            {
                bitcoin_address(coinaddr,coin->chain->pubtype,waddr->rmd160,20);
                printf("%s ",coinaddr);
                jaddistr(array,coinaddr);
            }
        } else jaddstr(retjson,"result","cant find account");
    }
    else
    {
        bitcoin_address(refaddr,coin->chain->pubtype,myinfo->persistent_pubkey33,33);
        HASH_ITER(hh,myinfo->wallet,subset,tmp)
        {
            HASH_ITER(hh,subset->waddr,waddr,tmp2)
            {
                bitcoin_address(coinaddr,coin->chain->pubtype,waddr->rmd160,20);
                jaddistr(array,coinaddr);
                if ( strcmp(coinaddr,refaddr) == 0 )
                    refaddr[0] = 0;
            }
        }
        if ( refaddr[0] != 0 )
            jaddistr(array,refaddr);
    }
    return(array);
}

struct iguana_waddress *iguana_ismine(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,uint8_t addrtype,uint8_t pubkey[65],uint8_t rmd160[20])
{
    struct iguana_waccount *wacct; struct iguana_waddress *waddr = 0;
    if ( bitcoin_address(coinaddr,addrtype,rmd160,20) > 0 )
        waddr = iguana_waddresssearch(myinfo,&wacct,coinaddr);
    return(waddr);
}

int32_t iguana_addressvalidate(struct iguana_info *coin,uint8_t *addrtypep,char *address)
{
    char checkaddr[64]; uint8_t rmd160[20];
    *addrtypep = 0;
    memset(rmd160,0,sizeof(rmd160));
    bitcoin_addr2rmd160(addrtypep,rmd160,address);
    //int32_t i; for (i=0; i<20; i++)
    //    printf("%02x",rmd160[i]); // 764692cd5473f62ffa8a93e55d876f567623de07
    //printf(" rmd160 addrtype.%02x\n",*addrtypep);
    if ( bitcoin_address(checkaddr,*addrtypep,rmd160,20) == checkaddr && strcmp(address,checkaddr) == 0 && (*addrtypep == coin->chain->pubtype || *addrtypep == coin->chain->p2shtype) )
        return(0);
    else
    {
        //printf(" checkaddr.(%s) address.(%s) type.%02x vs (%02x %02x)\n",checkaddr,address,*addrtypep,coin->chain->pubtype,coin->chain->p2shtype);
        return(-1);
    }
}

cJSON *iguana_waddressjson(struct iguana_info *coin,cJSON *item,struct iguana_waddress *waddr)
{
    char str[256],redeemScript[4096],coinaddr[64];
    if ( item == 0 )
        item = cJSON_CreateObject();
    bitcoin_address(coinaddr,coin->chain->pubtype,waddr->rmd160,20);
    jaddstr(item,"address",coinaddr);
    //jaddstr(item,"privkey",bits256_str(str,waddr->privkey));
    //jaddstr(item,"wif",waddr->wifstr);
    init_hexbytes_noT(str,waddr->rmd160,20);
    jaddstr(item,"rmd160",str);
    jaddstr(item,"coin",coin != 0 ? coin->symbol : waddr->symbol);
    if ( waddr->scriptlen > 0 )
    {
        init_hexbytes_noT(redeemScript,waddr->redeemScript,waddr->scriptlen);
        jaddstr(item,"redeemScript",redeemScript);
    }
    else
    {
        init_hexbytes_noT(str,waddr->pubkey,33);
        jaddstr(item,"pubkey",str);
    }
    return(item);
}

char *setaccount(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waddress **waddrp,char *account,char *coinaddr,char *redeemScript)
{
    uint8_t addrtype; struct iguana_waddress *waddr=0;
    if ( waddrp != 0 )
        *waddrp = 0;
    if ( coinaddr != 0 && coinaddr[0] != 0 && account != 0 && account[0] != 0 )
    {
        if ( iguana_addressvalidate(coin,&addrtype,coinaddr) < 0 )
            return(clonestr("{\"error\":\"invalid coin address\"}"));
        if ( (waddr= iguana_waccountswitch(myinfo,coin,account,coinaddr,redeemScript)) != 0 )
        {
            if ( waddrp != 0 )
                *waddrp = waddr;
            return(clonestr("{\"result\":\"success\"}"));
        } else return(clonestr("{\"error\":\"couldnt set account\"}"));
    }
    return(clonestr("{\"error\":\"need address and account\"}"));
}

char *getaccount(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    struct iguana_waccount *wacct; struct iguana_waddress *waddr; uint8_t addrtype; cJSON *retjson;
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"wallet must be unlocked to see accounts\"}"));
    if ( iguana_addressvalidate(coin,&addrtype,coinaddr) < 0 )
        return(clonestr("{\"error\":\"invalid coin address\"}"));
    if ( (waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) == 0 )
        return(clonestr("{\"result\":\"no account for address\"}"));
    if ( wacct != 0 )
    {
        retjson = iguana_waddressjson(coin,0,waddr);
        jaddstr(retjson,"account",wacct->account);
        jaddstr(retjson,"result","success");
        return(jprint(retjson,1));
    } else return(clonestr("{\"result\":\"\"}"));
}

char *jsuccess()
{
    cJSON *retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    return(jprint(retjson,1));
}

char *iguana_addressconv(struct iguana_info *coin,char *destaddr,struct iguana_info *other,int32_t isp2sh,uint8_t rmd160[20])
{
    if ( bitcoin_address(destaddr,isp2sh != 0 ? other->chain->pubtype : other->chain->p2shtype,rmd160,20) == destaddr )
        return(destaddr);
    else return(0);
}

int32_t iguana_loginsave(struct supernet_info *myinfo,struct iguana_info *coin,char *newstr)
{
    cJSON *loginjson; char *passphrase,destfname[1024];
    if ( (loginjson= cJSON_Parse(newstr)) != 0 )
    {
        if ( (passphrase= jstr(loginjson,"passphrase")) != 0 )
        {
            _SuperNET_encryptjson(myinfo,destfname,passphrase,0,myinfo->permanentfile,0,loginjson);
            //printf("loginsave.(%s) <= (%s)\n",destfname,newstr);
            //iguana_walletlock(myinfo);
        }
        free_json(loginjson);
        return(0);
    } return(-1);
}

char *iguana_walletvalue(char *buf,struct iguana_waddress *waddr)
{
    if ( waddr->scriptlen > 0 )
        init_hexbytes_noT(buf,waddr->redeemScript,waddr->scriptlen);
    else init_hexbytes_noT(buf,waddr->privkey.bytes,sizeof(waddr->privkey));
    //char str[65]; printf("%s -> walletvalue.(%s)\n",bits256_str(str,waddr->privkey),buf);
    return(buf);
}
                         
int32_t iguana_payloadupdate(struct supernet_info *myinfo,struct iguana_info *coin,char *retstr,struct iguana_waddress *waddr,char *account)
{
    cJSON *retjson,*accountobj,*payload; char rmdstr[41],*newstr,*valuestr,valuebuf[IGUANA_MAXSCRIPTSIZE*2+1]; int32_t retval = -1;
    if ( (retjson= cJSON_Parse(retstr)) != 0 )
    {
        if ( account == 0 || account[0] == 0 )
            account = "default";
        payload = cJSON_DetachItemFromObject(retjson,"wallet");
        //printf("PAYLOAD.(%s)\n",jprint(payload,0));
        if ( payload == 0 )
            payload = cJSON_CreateObject();
        if ( waddr != 0 && (valuestr= iguana_walletvalue(valuebuf,waddr)) != 0 )
        {
            init_hexbytes_noT(rmdstr,waddr->rmd160,20);
            if ( (accountobj= jobj(payload,account)) != 0 && jobj(accountobj,rmdstr) != 0 )
            {
                free_json(retjson);
                free_json(payload);
                return(0);
            }
            if ( accountobj == 0 )
            {
                accountobj = cJSON_CreateObject();
                jadd(payload,account,accountobj);
                //printf("ADDACCOUNT.(%s)\n",jprint(accountobj,0));
            }
            jaddstr(accountobj,rmdstr,valuestr);
        }
        jadd(retjson,"wallet",payload);
        newstr = jprint(retjson,1);
        retval = iguana_loginsave(myinfo,coin,newstr);
        free(newstr);
    } else printf("iguana_payloadupdate: error parsing.(%s)\n",retstr);
    return(retval);
}

cJSON *iguana_payloadmerge(cJSON *loginjson,cJSON *importjson)
{
    cJSON *retjson,*item,*obj; char *field;
    if ( loginjson == 0 )
        return(importjson);
    else if ( importjson == 0 )
        return(loginjson);
    retjson = jduplicate(loginjson);
    item = importjson->child;
    while ( item != 0 )
    {
        if ( (field= jfieldname(item)) != 0 )
        {
            if ( (obj= jobj(retjson,field)) == 0 )
            {
                if ( strlen(field) == 20*2 )
                    jadd(retjson,field,item);
                else jadd(retjson,field,item);
            }
        }
        item = item->next;
    }
    return(retjson);
}

cJSON *iguana_walletadd(struct supernet_info *myinfo,struct iguana_waddress **waddrp,struct iguana_info *coin,char *retstr,char *account,struct iguana_waddress *refwaddr,int32_t setcurrent,char *redeemScript)
{
    cJSON *retjson=0; struct iguana_waccount *wacct; struct iguana_waddress *waddr=0;
    printf("walletaddr.(%s)\n",retstr);
    if ( (wacct= iguana_waccountfind(myinfo,account)) == 0 )
        wacct = iguana_waccountcreate(myinfo,account);
    if ( wacct != 0 )
    {
        //waddr = iguana_waddressfind(myinfo,wacct,refwaddr->coinaddr);
        waddr = iguana_waddressadd(myinfo,coin,wacct,refwaddr,redeemScript);
        if ( setcurrent != 0 )
            wacct->current = waddr;
        if ( iguana_payloadupdate(myinfo,coin,retstr,waddr,account) < 0 )
        {
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"error","couldnt update wallet payload");
        }
        else
        {
            retjson = iguana_waddressjson(coin,retjson,waddr);
            jaddstr(retjson,"account",account);
            jaddstr(retjson,"result","success");
        }
    }
    if ( waddrp != 0 )
        (*waddrp) = waddr;
    return(retjson);
}

cJSON *iguana_walletjson(struct supernet_info *myinfo)
{
    struct iguana_waccount *wacct,*tmp; struct iguana_waddress *waddr,*tmp2; cJSON *wallet,*account; char valuebuf[IGUANA_MAXSCRIPTSIZE*2+1],rmdstr[128];
    wallet = cJSON_CreateObject();
    HASH_ITER(hh,myinfo->wallet,wacct,tmp)
    {
        account = cJSON_CreateObject();
        HASH_ITER(hh,wacct->waddr,waddr,tmp2)
        {
            if ( bits256_nonz(waddr->privkey) == 0 && waddr->scriptlen == 0 )
            {
                //free_json(account);
                //free_json(wallet);
                //printf("found a null privkey in wallet, abort saving\n");
                //return(0);
            }
            init_hexbytes_noT(rmdstr,waddr->rmd160,sizeof(waddr->rmd160));
            jaddstr(account,rmdstr,iguana_walletvalue(valuebuf,waddr));
        }
        jadd(wallet,wacct->account,account);
    }
    return(wallet);
}

char *iguana_walletfields(struct iguana_info *coin,int32_t *p2shflagp,char *wifstr,char *address,char *fieldstr,char *valuestr)
{
    uint8_t rmd160[20],addrtype,script[IGUANA_MAXSCRIPTSIZE]; int32_t len; bits256 privkey;
    *p2shflagp = 0;
    if ( fieldstr != 0 && valuestr != 0 )
    {
        len = is_hexstr(fieldstr,0);
        if ( len > 0 )
        {
            if ( len == 20*2 )
                decode_hex(rmd160,sizeof(rmd160),fieldstr);
            else
            {
                len >>= 1;
                decode_hex(script,len,valuestr);
                calc_rmd160_sha256(rmd160,script,len);
                bitcoin_address(address,coin->chain->p2shtype,rmd160,20);
                *p2shflagp = 1;
                return(valuestr);
            }
        } else bitcoin_addr2rmd160(&addrtype,rmd160,fieldstr);
        privkey = bits256_conv(valuestr);
        bitcoin_priv2wif(wifstr,privkey,coin->chain->wiftype);
        bitcoin_address(address,coin->chain->pubtype,rmd160,20);
        return(wifstr);
    }
    return(0);
}

int32_t iguana_walletemit(struct supernet_info *myinfo,char *fname,struct iguana_info *coin,cJSON *array)
{
    cJSON *item,*child; char str[65],wifstr[128],*account,coinaddr[64],*privstr; int32_t i,n,p2shflag; FILE *fp;
    if ( (fp= fopen(fname,"wb")) == 0 )
        return(-1);
    n = cJSON_GetArraySize(array);
    item = array->child;
    for (i=0; i<n; i++)
    {
        if ( item != 0 && (account= item->string) != 0 )
        {
            child = item->child;
            while ( child != 0 )
            {
                if ( (privstr= iguana_walletfields(coin,&p2shflag,wifstr,coinaddr,child->string,child->valuestring)) != 0 )
                    fprintf(fp,"%s %s %32s=%d # addr=%s\n",privstr,utc_str(str,(uint32_t)time(NULL)),account,i+1,coinaddr);
                child = child->next;
            }
            //printf("account.(%s)\n",account);
        }
        item = item->next;
    }
    fclose(fp);
    return(0);
}

char *walleterrstr[] = { "P2SH_withpriv", "P2SH_withpub", "rmd160_mismatch", "pubkey_mismatch", "missing_pubkey", "account_mismatch" };

uint8_t iguana_waddrvalidate(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,struct iguana_waddress *waddr,int32_t repairflag,int32_t *errors)
{
    struct iguana_waccount *checkwacct; struct iguana_waddress *checkwaddr; uint8_t checkpub[33],rmd160[20],addrtype,checktype,plen,flag=0; int32_t i;
    if ( waddr != 0 )
    {
        if ( (checkwaddr= iguana_waddresssearch(myinfo,&checkwacct,waddr->coinaddr)) != waddr || checkwacct != wacct )
        {
            //errors[5]++;
            //flag |= (5 << 0);
            //if ( repairflag > 0 )
            {
                //printf("waddrvalidate: need to manually setaccount to fix mismatch (%s:%s) <- (%s:%s)\n",checkwacct != 0 ? checkwacct->account : "",checkwaddr != 0 ? checkwaddr->coinaddr : "",wacct != 0 ? wacct->account : "",waddr->coinaddr);
            }
        }
        if ( waddr->scriptlen > 0 )
        {
            checktype = coin->chain->p2shtype;
            if ( bits256_nonz(waddr->privkey) != 0 )
            {
                errors[0]++;
                flag |= (1 << 0);
                if ( repairflag > 0 )
                {
                    myinfo->dirty = (uint32_t)time(NULL);
                    memset(&waddr->privkey,0,sizeof(waddr->privkey));
                }
            }
            if ( waddr->pubkey[0] == 0 )
                bitcoin_pubkey33(myinfo->ctx,waddr->pubkey,waddr->privkey);
            if ( bitcoin_pubkeylen(waddr->pubkey) > 0 )
            {
                errors[1]++;
                flag |= (1 << 1);
                if ( repairflag > 0 )
                {
                    myinfo->dirty = (uint32_t)time(NULL);
                    memset(waddr->pubkey,0,sizeof(waddr->pubkey));
                }
            }
        }
        else checktype = coin->chain->pubtype;
        if ( bitcoin_addr2rmd160(&addrtype,rmd160,waddr->coinaddr) != sizeof(rmd160) || addrtype != checktype || memcmp(rmd160,waddr->rmd160,sizeof(rmd160)) != 0 )
        {
            errors[2]++;
            flag |= (1 << 2);
            if ( repairflag > 0 )
            {
                myinfo->dirty = (uint32_t)time(NULL);
                waddr->addrtype = checktype;
                memcpy(waddr->rmd160,rmd160,sizeof(rmd160));
            }
        }
        if ( waddr->scriptlen == 0 )
        {
            if ( bits256_nonz(waddr->privkey) != 0 )
            {
                bitcoin_pubkey33(myinfo->ctx,checkpub,waddr->privkey);
                if ( memcmp(checkpub,waddr->pubkey,sizeof(checkpub)) != 0 )
                {
                    errors[3]++;
                    flag |= (1 << 3);
                    if ( repairflag > 0 )
                    {
                        myinfo->dirty = (uint32_t)time(NULL);
                        memcpy(waddr->pubkey,checkpub,sizeof(checkpub));
                    }
                }
            }
            if ( waddr->pubkey[0] == 0 )
                bitcoin_pubkey33(myinfo->ctx,waddr->pubkey,waddr->privkey);
            if ( (plen= bitcoin_pubkeylen(waddr->pubkey)) > 0 )
            {
                calc_rmd160_sha256(rmd160,waddr->pubkey,plen);
                if ( memcmp(rmd160,waddr->rmd160,sizeof(rmd160)) != 0 )
                {
                    for (i=0; i<20; i++)
                        if ( waddr->rmd160[i] != 0 )
                            break;
                    if ( i != 20 )
                    {
                        errors[4]++;
                        flag |= (1 << 4);
                        if ( repairflag > 0 )
                        {
                            printf("waddrvalidate unrecoverable error: cant determine pubkey from rmd160\n");
                        }
                    }
                    else
                    {
                        memcpy(waddr->rmd160,rmd160,20);
                        bitcoin_address(waddr->coinaddr,coin->chain->pubtype,rmd160,sizeof(rmd160));
                        myinfo->dirty = (uint32_t)time(NULL);
                    }
                }
            }
        }
    }
    return(flag);
}

cJSON *iguana_walletiterate(struct supernet_info *myinfo,struct iguana_info *coin,int32_t flag,cJSON *array,int32_t *goodp,int32_t *badp,int32_t *errors)
{
    struct iguana_waccount *wacct,*tmp,*checkwacct; struct iguana_waddress *checkwaddr,*waddr=0,*tmp2; uint8_t persistent_rmd160[20],errorflags; int32_t i,persistent_flag=0,good=0,bad=0,_errors[8]; cJSON *item; char coinaddr[64],*retstr;
    if ( errors == 0 )
        errors = _errors;
    if ( myinfo->expiration != 0 )
        calc_rmd160_sha256(persistent_rmd160,myinfo->persistent_pubkey33,33);
    else memset(persistent_rmd160,0,sizeof(persistent_rmd160));
    portable_mutex_lock(&myinfo->bu_mutex);
    HASH_ITER(hh,myinfo->wallet,wacct,tmp)
    {
        HASH_ITER(hh,wacct->waddr,waddr,tmp2)
        {
            if ( flag < 0 )
            {
                memset(&waddr->privkey,0,sizeof(waddr->privkey));
                memset(waddr->wifstr,0,sizeof(waddr->wifstr));
                for (i=0; i<sizeof(waddr->privkey); i++)
                    waddr->privkey.bytes[i] = rand();
                for (i=0; i<sizeof(waddr->wifstr); i++)
                    waddr->wifstr[i] = rand();
                if ( flag < -1 )
                {
                    HASH_DELETE(hh,wacct->waddr,waddr);
                    myfree(waddr,sizeof(*waddr) + waddr->scriptlen);
                }
            }
            else
            {
                wacct->current = waddr;
                if ( (errorflags= iguana_waddrvalidate(myinfo,coin,wacct,waddr,flag,errors)) != 0 )
                {
                    bad++;
                    if ( array != 0 && (item= cJSON_CreateObject()) != 0 )
                    {
                        bitcoin_address(coinaddr,coin->chain->pubtype,waddr->rmd160,20);
                        jaddnum(item,coinaddr,errorflags);
                        jaddi(array,item);
                    }
                } else good++;
                if ( myinfo->expiration != 0 && persistent_flag == 0 && memcmp(waddr->rmd160,persistent_rmd160,20) == 0 )
                {
                    persistent_flag = 1;
                    bitcoin_address(coinaddr,coin->chain->pubtype,waddr->rmd160,20);
                    printf("FOUND PERSISTENT.%s in %s\n",coinaddr,wacct->account);
                }
            }
        }
        if ( flag < -1 )
        {
            HASH_DELETE(hh,myinfo->wallet,wacct);
            myfree(wacct,(int32_t)(sizeof(*wacct) + strlen(wacct->account) + 1));
        }
    }
    if ( myinfo->expiration != 0 )
    {
        if ( flag >= 0 && persistent_flag == 0 )
        {
            bitcoin_address(coinaddr,coin->chain->pubtype,persistent_rmd160,20);
            if ( (retstr= setaccount(myinfo,coin,0,"default",coinaddr,0)) != 0 )
            {
                free(retstr);
                if ( (waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) != 0 )
                {
                    memcpy(waddr->rmd160,persistent_rmd160,20);
                    memcpy(waddr->pubkey,myinfo->persistent_pubkey33,33);
                    waddr->privkey = myinfo->persistent_priv;
                    strcpy(waddr->coinaddr,coinaddr);
                    if ( (checkwaddr= iguana_waddresssearch(myinfo,&checkwacct,waddr->coinaddr)) != waddr || checkwacct != wacct )
                        ;
                }
            }
            printf("persistent address not found in wallet, autoadd.(%s)\n",coinaddr);
        }
        else if ( persistent_flag != 0 && (0) )
            printf("found persistent address in wallet\n");
    }
    portable_mutex_unlock(&myinfo->bu_mutex);
    if ( goodp != 0 )
        *goodp = good;
    if ( badp != 0 )
        *badp = bad;
    if ( iguana_waddresssearch(myinfo,&wacct,myinfo->myaddr.BTCD) != 0 )
    {
        //printf("found persistent address.(%s)\n",myinfo->myaddr.BTCD);
    }
    return(array);
}

char *iguana_walletscan(struct supernet_info *myinfo,struct iguana_info *coin,int32_t repairflag)
{
    cJSON *retjson; int32_t i,good,bad,errors[8];
    memset(errors,0,sizeof(errors));
    good = bad = 0;
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",iguana_walletiterate(myinfo,coin,repairflag,cJSON_CreateArray(),&good,&bad,errors));
    jaddnum(retjson,"good",good);
    jaddnum(retjson,"bad",bad);
    for (i=0; i<sizeof(errors)/sizeof(errors); i++)
    {
        if ( errors[i] != 0 )
            jaddnum(retjson,walleterrstr[i],errors[i]);
    }
    return(jprint(retjson,1));
}

void iguana_walletinitcheck(struct supernet_info *myinfo,struct iguana_info *coin)
{
    cJSON *payload,*item,*array,*child; char *account,coinaddr[128],*privstr,wifstr[128]; int32_t i,p2shflag,n; struct iguana_waccount *wacct; struct iguana_waddress waddr; bits256 privkey;
    if ( myinfo->wallet == 0 && myinfo->decryptstr != 0 && (payload= cJSON_Parse(myinfo->decryptstr)) != 0 )
    {
        //printf("WALLET.(%s)\n",myinfo->decryptstr);
        if ( (array= jobj(payload,"wallet")) != 0 )
        {
            n = cJSON_GetArraySize(array);
            //printf("item.(%s) size.%d\n",jprint(array,0),n);
            item = array->child;
            for (i=0; i<n; i++)
            {
                if ( item != 0 && (account= item->string) != 0 )
                {
                    child = item->child;
                    while ( child != 0 )
                    {
                        if ( (wacct= iguana_waccountcreate(myinfo,account)) != 0 )
                        {
                            if ( (privstr= iguana_walletfields(coin,&p2shflag,wifstr,coinaddr,child->string,child->valuestring)) != 0 )
                            {
                                memset(&waddr,0,sizeof(waddr));
                                strcpy(waddr.coinaddr,coinaddr);
                                if ( p2shflag != 0 )
                                    iguana_waddressadd(myinfo,coin,wacct,&waddr,child->valuestring);
                                else
                                {
                                    privkey = bits256_conv(child->valuestring);
                                    if ( iguana_waddresscalc(myinfo,coin->chain->pubtype,coin->chain->wiftype,&waddr,privkey) != 0 )
                                    {
                                        iguana_waddressadd(myinfo,coin,wacct,&waddr,0);
                                        printf("(%s) ",waddr.coinaddr);
                                    } //else printf("walletinitcheck: error waddresscalc\n");
                                }
                            }
                        }
                        child = child->next;
                    }
                    printf("account.(%s)\n",account);
                }
                item = item->next;
            }
        }
        free_json(payload);
        scrubfree(myinfo->decryptstr);
        myinfo->decryptstr = 0;
        myinfo->dirty = 0;
    }
    //printf("call walletiterate from initcheck.%p\n",myinfo->decryptstr);
    iguana_walletiterate(myinfo,coin,1,0,0,0,0);
}

void iguana_walletlock(struct supernet_info *myinfo,struct iguana_info *coin)
{
    if ( coin != 0 )
        memset(coin->changeaddr,0,sizeof(coin->changeaddr));
    memset(&myinfo->persistent_priv,0,sizeof(myinfo->persistent_priv));
    memset(&myinfo->persistent_pubkey33,0,sizeof(myinfo->persistent_pubkey33));
    memset(myinfo->secret,0,sizeof(myinfo->secret));
    memset(myinfo->jumblr_passphrase,0,sizeof(myinfo->jumblr_passphrase));
    memset(&myinfo->jumblr_depositkey,0,sizeof(myinfo->jumblr_depositkey));
    memset(&myinfo->jumblr_pubkey,0,sizeof(myinfo->jumblr_pubkey));
    memset(myinfo->permanentfile,0,sizeof(myinfo->permanentfile));
    if ( myinfo->decryptstr != 0 )
        scrubfree(myinfo->decryptstr), myinfo->decryptstr = 0;
    memset(myinfo->handle,0,sizeof(myinfo->handle));
    memset(myinfo->myaddr.NXTADDR,0,sizeof(myinfo->myaddr.NXTADDR));
    myinfo->myaddr.nxt64bits = 0;
    myinfo->expiration = 0;
    iguana_walletiterate(myinfo,coin,-2,0,0,0,0);
}

int64_t iguana_waccountbalance(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,int32_t minconf,int32_t lastheight)
{
    int64_t balance; int32_t numrmds=0,numunspents = 0; uint8_t *rmdarray=0;
    if ( minconf == 0 )
        minconf = 1;
    rmdarray = iguana_rmdarray(myinfo,coin,&numrmds,iguana_getaddressesbyaccount(myinfo,coin,wacct->account),0);
    balance = iguana_RTunspents(myinfo,coin,0,minconf,(1 << 30),rmdarray,numrmds,lastheight,0,&numunspents,0,0);
    if ( rmdarray != 0 )
        free(rmdarray);
    return(balance);
}

int64_t oldiguana_waccountbalance(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_waccount *wacct,int32_t minconf,int32_t lastheight)
{
    int64_t balance=0; int32_t i,n; cJSON *addrs=0;
    if ( minconf == 0 )
        minconf = 1;
    if ( (addrs= iguana_getaddressesbyaccount(myinfo,coin,wacct->account)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(addrs)) > 0 )
        {
            for (i=0; i<n; i++)
                balance += iguana_RTbalance(coin,jstri(addrs,i));
        }
    }
    return(balance);
}

cJSON *iguana_privkeysjson(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *vins)
{
    int32_t i,n,numinputs,scriptlen; struct iguana_waddress *waddr; struct iguana_waccount *wacct; char *addresses,*address,*scripthexstr,coinaddr[64]; cJSON *scriptobj,*privkeys,*item; uint8_t spendscript[IGUANA_MAXSCRIPTSIZE];
    privkeys = cJSON_CreateArray();
    if ( (numinputs= cJSON_GetArraySize(vins)) > 0 )
    {
        addresses = calloc(numinputs,64);
        for (i=n=0; i<numinputs; i++)
        {
            address = 0;
            item = jitem(vins,i);
            if ( (address= jstr(item,"address")) == 0 )
            {
                if ( (scripthexstr= jstr(item,"spendscript")) == 0 )
                {
                    if ( (scriptobj= jobj(item,"scriptPubKey")) != 0 )
                        scripthexstr = jstr(scriptobj,"hex");
                }
                if ( scripthexstr != 0 )
                {
                    scriptlen = (int32_t)strlen(scripthexstr) >> 1;
                    decode_hex(spendscript,scriptlen,scripthexstr);
                    address = iguana_scriptaddress(coin,coinaddr,spendscript,scriptlen);
                }
            }
            //if ( (address= iguana_RTinputaddress(myinfo,coin,coinaddr,&spentpt,jitem(vins,i))) != 0 )
            if ( address != 0 )
            {
                strcpy(&addresses[64 * n++],address);
            } //else printf("cant get address from.(%s)\n",jprint(item,0));
        }
        for (i=0; i<n; i++)
        {
            if ( (waddr= iguana_waddresssearch(myinfo,&wacct,&addresses[i * 64])) != 0 )
            {
                //printf("%s ",waddr->wifstr);
                jaddistr(privkeys,waddr->wifstr);
            }
            else printf("cant find waddr for %s\n",&addresses[i*64]);
        }
        free(addresses);
    }
    return(privkeys);
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"
#include "../includes/iguana_apideclares2.h"

int64_t iguana_addressreceived(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *json,char *remoteaddr,cJSON *txids,cJSON *vouts,cJSON *unspents,cJSON *spends,char *coinaddr,int32_t minconf,int32_t firstheight)
{
    int64_t balance = 0; cJSON *unspentsjson,*balancejson,*item; int32_t i,n; char *balancestr;
    if ( (balancestr= iguana_balance(IGUANA_CALLARGS,coin->symbol,coinaddr,1<<30,minconf)) != 0 )
    {
        //printf("balancestr.(%s) (%s) firstheight.%d\n",balancestr,coinaddr,firstheight);
        if ( (balancejson= cJSON_Parse(balancestr)) != 0 )
        {
            balance = jdouble(balancejson,"balance") * SATOSHIDEN;
            if ( (txids != 0 || vouts != 0 || unspents != 0 || spends != 0) && (unspentsjson= jarray(&n,balancejson,"unspents")) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(unspentsjson,i);
                    if ( juint(item,"height") >= firstheight )
                    {
                        if ( txids != 0 )
                            jaddibits256(txids,jbits256(item,"txid"));
                        if ( vouts != 0 )
                            jaddinum(vouts,jint(item,"vout"));
                        if ( unspents != 0 && jobj(item,"spent") == 0 && jobj(item,"dest") == 0 )
                            jaddi(unspents,jduplicate(item));
                        if ( spends != 0 && (jobj(item,"spent") != 0 || jobj(item,"dest") != 0) )
                            jaddi(spends,jduplicate(item));
                    }
                }
            }
            free_json(balancejson);
        }
        free(balancestr);
    }
    //if ( spends != 0 )
    //    printf("SPENDS.(%s)\n",jprint(spends,0));
    //if ( unspents != 0 )
    //    printf("UNSPENTS.(%s)\n",jprint(unspents,0));
    return(balance);
}

char *getnewaddress(struct supernet_info *myinfo,struct iguana_waddress **waddrp,struct iguana_info *coin,char *account,char *retstr)
{
    struct iguana_waddress addr; cJSON *retjson;
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    if ( retstr != 0 )
    {
        memset(&addr,0,sizeof(addr));
        if ( iguana_waddresscalc(myinfo,coin->chain->pubtype,coin->chain->wiftype,&addr,bitcoin_randkey(myinfo->ctx)) != 0 )
            retjson = iguana_walletadd(myinfo,waddrp,coin,retstr,account,&addr,1,0);
        else return(clonestr("{\"error\":\"couldnt calculate waddr\"}"));
    } else return(clonestr("{\"error\":\"no wallet data, did you remember to do encryptwallet onetime?\"}"));
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,validateaddress,address)
{
    cJSON *retjson; uint8_t addrtype,rmd160[20],pubkey[65]; char coinaddr[64],str[256];
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( iguana_addressvalidate(coin,&addrtype,address) < 0 )
        return(clonestr("{\"error\":\"invalid coin address\"}"));
    bitcoin_addr2rmd160(&addrtype,rmd160,address);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jaddnum(retjson,"addrtype",addrtype);
    init_hexbytes_noT(str+6,rmd160,sizeof(rmd160));
    jaddstr(retjson,"rmd160",str+6);
    memcpy(str,"76a914",6);
    strcat(str,"88ac");
    jaddstr(retjson,"scriptPubKey",str);
    jadd(retjson,"isscript",(addrtype == coin->chain->p2shtype) ? jtrue() : jfalse());
    if ( iguana_ismine(myinfo,coin,coinaddr,addrtype,pubkey,rmd160) != 0 )
    {
        init_hexbytes_noT(str,pubkey,bitcoin_pubkeylen(pubkey));
        jaddstr(retjson,"pubkey",str);
        cJSON_AddTrueToObject(retjson,"ismine");
    } else cJSON_AddFalseToObject(retjson,"ismine");
    jaddstr(retjson,coin->symbol,coinaddr);
    //portable_mutex_lock(&myinfo->allcoins_mutex);
    /*HASH_ITER(hh,myinfo->allcoins,other,tmp)
    {
        if ( strcmp(other->symbol,coin->symbol) != 0 )
        {
            iguana_addressconv(coin,str,other,addrtype == coin->chain->p2shtype,rmd160);
            jaddstr(retjson,other->symbol,str);
        }
    }*/
    //portable_mutex_unlock(&myinfo->allcoins_mutex);
    return(jprint(retjson,1));
}

double _max100(double val)
{
    if ( val < 0. )
        return(0.);
    else if ( val > 100. )
        return(100.);
    else return(val);
}

cJSON *iguana_getinfo(struct supernet_info *myinfo,struct iguana_info *coin)
{
    int32_t i; char *retstr; struct iguana_peer *addr; cJSON *array,*retjson = cJSON_CreateObject();
    if ( coin != 0 )
    {
        if ( coin->notarychain >= 0 )
        {
            if ( (retstr= _dex_getinfo(myinfo,coin->symbol)) != 0 )
            {
                retjson = cJSON_Parse(retstr);
                free(retstr);
                return(retjson);
            } else return(cJSON_Parse("{\"error\":\"null return\"}"));
        }
        jaddstr(retjson,"result","success");
        jaddnum(retjson,"protocolversion",PROTOCOL_VERSION);
        jaddnum(retjson,"kbfee",dstr(coin->txfee_perkb));
        jaddnum(retjson,"txfee",dstr(coin->txfee));
        if ( coin->bundlescount > 1 )
        {
            jaddnum(retjson,"bundles",_max100(100. * (double)(iguana_emitfinished(myinfo,coin,0))/(coin->longestchain/coin->chain->bundlesize)));
            jaddnum(retjson,"utxo",_max100(100. * (double)(iguana_utxofinished(coin))/(coin->longestchain/coin->chain->bundlesize)));
            jaddnum(retjson,"balances",_max100(100. * (double)(iguana_balancefinished(coin))/(coin->longestchain/coin->chain->bundlesize)));
            jaddnum(retjson,"validated",_max100(100. * (double)(iguana_validated(coin))/(coin->longestchain/coin->chain->bundlesize)));
        }
        jaddnum(retjson,"firstRTheight",coin->firstRTheight);
        jaddnum(retjson,"RTheight",coin->RTheight);
        jaddnum(retjson,"blocks",coin->blocks.hwmchain.height);
        jaddnum(retjson,"longestchain",coin->longestchain);
        jaddnum(retjson,"port",coin->chain->portp2p);
        if ( coin->peers != 0 )
        {
            array = cJSON_CreateArray();
            for (i=0; i<IGUANA_MAXPEERS; i++)
            {
                addr = &coin->peers->active[i];
                if ( addr->usock >= 0 && addr->supernet != 0 && addr->ipaddr[0] != 0 )
                {
                    jaddistr(array,addr->ipaddr);
                    if ( strcmp(coin->symbol,"RELAY") == 0 )
                        basilisk_addrelay_info(myinfo,0,(uint32_t)calc_ipbits(addr->ipaddr),GENESIS_PUBKEY);
                }
            }
            jadd(retjson,"supernet",array);
            jaddnum(retjson,"connections",coin->peers->numranked);
        }
        jaddnum(retjson,"RELAY",coin->FULLNODE);
        jaddnum(retjson,"difficulty",coin->blocks.hwmchain.PoW);
        jaddstr(retjson,"status",coin->statusstr);
        jaddstr(retjson,"coin",coin->symbol);
    }
    return(retjson);
}

ZERO_ARGS(bitcoinrpc,getinfo)
{
    struct basilisk_item Lptr,*ptr; int32_t incr,i,j,m,n,longest; cJSON *valsobj,*getinfoobj=0,*array,*item,*fullnodes;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 || coin->notarychain >= 0 )
        return(jprint(iguana_getinfo(myinfo,coin),1));
    else
    {
        valsobj = cJSON_CreateObject();
        ptr = basilisk_getinfo(&Lptr,myinfo,coin,remoteaddr,0,5000,valsobj);
        free_json(valsobj);
        if ( ptr != 0 && ptr->retstr != 0 )
        {
            if ( (array= cJSON_Parse(ptr->retstr)) != 0 )
            {
                if ( is_cJSON_Array(array) != 0 )
                {
                    getinfoobj = jduplicate(jitem(array,0));
                    longest = 0;
                    if ( coin->FULLNODE == 0 && coin->VALIDATENODE == 0 && (n= cJSON_GetArraySize(array)) > 0 )
                    {
                        jdelete(getinfoobj,"longestchain");
                        for (i=0; i<n; i++)
                        {
                            item = jitem(array,i);
                            if ( juint(item,"longestchain") > longest )
                                longest = juint(item,"longestchain");
                            if ( juint(item,"RTheight") > coin->RTheight )
                            {
                                coin->RTheight = juint(item,"RTheight");
                                coin->firstRTheight = juint(item,"firstRTheight");
                                printf("set RTheight.%d 1st %d\n",coin->RTheight,coin->firstRTheight);
                            }
                            if ( (fullnodes= jarray(&m,item,"supernet")) != 0 )
                            {
                                incr = 1;
                                if ( strcmp(coin->symbol,"RELAY") == 0 )
                                {
                                    for (j=0; j<m; j++)
                                        basilisk_addrelay_info(myinfo,0,(uint32_t)calc_ipbits(jstri(fullnodes,j)),GENESIS_PUBKEY);
                                    incr = sqrt(m);
                                    if ( incr < 1 )
                                        incr = 1, j = 0;
                                    else j = (myinfo->myaddr.pubkey.uints[0] % incr);
                                } else j = 0;
                                for (; j<m; j+=incr)
                                {
                                    //fprintf(stderr,"[%s] ",jstri(fullnodes,j));
                                    iguana_launchpeer(coin,jstri(fullnodes,j),1);
                                }
                            }
                        }
                        if ( jobj(getinfoobj,"longestchain") != 0 )
                            jdelete(getinfoobj,"longestchain");
                        jaddnum(getinfoobj,"longestchain",longest);
                    }
                }
                else
                {
                    ptr->finished = OS_milliseconds();
                    return(jprint(array,1));
                }
                free_json(array);
            }
            ptr->finished = OS_milliseconds();
            if ( getinfoobj != 0 )
                return(jprint(getinfoobj,1));
        }
    }
    return(clonestr("{\"error\":\"null basilisk_getinfo\"}"));
}

TWO_STRINGS(bitcoinrpc,setaccount,address,account)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    return(setaccount(myinfo,coin,0,account,address,0));
}

STRING_ARG(bitcoinrpc,getaccount,address)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(getaccount(myinfo,coin,address));
}

STRING_ARG(bitcoinrpc,getnewaddress,account)
{
    char *retstr,*newretstr; struct iguana_waddress *waddr;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    if ( (retstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,myinfo->password)) != 0 )
    {
        free(retstr);
        retstr = myinfo->decryptstr, myinfo->decryptstr = 0;
        newretstr = getnewaddress(myinfo,&waddr,coin,account,retstr);
        if ( retstr != 0 )
            scrubfree(retstr);
        return(newretstr);
    }
    else return(clonestr("{\"error\":\"no wallet payload\"}"));
}

struct iguana_waddress *iguana_getaccountaddress(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *json,char *remoteaddr,char *coinaddr,char *account)
{
    char *newstr,*retstr; int32_t i,n,flag=0; struct iguana_waccount *wacct; struct iguana_waddress *waddr=0; cJSON *unspents,*item;
    coinaddr[0] = 0;
    if ( (wacct= iguana_waccountfind(myinfo,account)) == 0 )
        wacct = iguana_waccountcreate(myinfo,account);
    if ( wacct != 0 )
    {
        portable_mutex_lock(&myinfo->bu_mutex);
        if ( myinfo->Cunspents != 0 && (unspents= jobj(myinfo->Cunspents,coin->symbol)) != 0 )
        {
            flag = 0;
            if ( (n= cJSON_GetArraySize(unspents)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(unspents,i);
                    if ( jstr(item,"address") != 0 && strcmp(jstr(item,"address"),coinaddr) == 0 )
                    {
                        flag = 1;
                        printf("found unspent for.(%s)\n",coinaddr);
                        break;
                    }
                }
            }
        }
        portable_mutex_unlock(&myinfo->bu_mutex);
        if ( flag != 0 || (waddr= wacct->current) == 0 )
        {
            if ( (retstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,myinfo->password)) != 0 )
            {
                free(retstr);
                retstr = myinfo->decryptstr, myinfo->decryptstr = 0;
                newstr = getnewaddress(myinfo,&waddr,coin,account,retstr);
                if ( retstr != 0 )
                    scrubfree(retstr);
                retstr = newstr;
            } else return(0);
        }
    }
    if ( waddr != 0 )
    {
        bitcoin_address(coinaddr,coin->chain->pubtype,waddr->rmd160,20);
        return(waddr);
    }
    return(0);
}

STRING_ARG(bitcoinrpc,getaccountaddress,account)
{
    char coinaddr[64]; struct iguana_waddress *waddr=0; cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    if ( account != 0 && account[0] != 0 )
    {
        if ( (waddr= iguana_getaccountaddress(myinfo,coin,json,remoteaddr,coinaddr,account)) != 0 )
            retjson = iguana_waddressjson(coin,0,waddr);
        else return(clonestr("{\"error\":\"couldnt create address\"}"));
        jaddstr(retjson,"account",account);
        jaddstr(retjson,"result","success");
        return(jprint(retjson,1));
    }
    return(clonestr("{\"error\":\"no account specified\"}"));
}

ZERO_ARGS(bitcoinrpc,walletlock)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    iguana_walletlock(myinfo,coin);
    return(jsuccess());
}

TWOSTRINGS_AND_INT(bitcoinrpc,walletpassphrase,password,permanentfile,timeout)
{
    char *retstr,*tmpstr; cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( timeout <= 0 )
        return(clonestr("{\"error\":\"timeout must be positive\"}"));
    if ( password == 0 || password[0] == 0 )
    {
        if ( (password= jstr(json,"passphrase")) == 0 || password[0] == 0 )
            return(clonestr("{\"error\":\"must have password field\"}"));
    }
    iguana_walletlock(myinfo,coin);
    myinfo->expiration = (uint32_t)time(NULL) + timeout;
    strcpy(myinfo->secret,password);
    strcpy(myinfo->password,password);
    if ( permanentfile != 0 )
        strcpy(myinfo->permanentfile,permanentfile);
    if ( (retstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,myinfo->password)) != 0 )
        free(retstr);
    retstr = SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,myinfo->password);
    myinfo->expiration = (uint32_t)time(NULL) + timeout;
    iguana_walletinitcheck(myinfo,coin);
    if ( coin != 0 )
    {
        bitcoin_address(coin->changeaddr,coin->chain->pubtype,myinfo->persistent_pubkey33,33);
        if ( coin->FULLNODE < 0 )
        {
            char wifstr[64]; int32_t destvalid = 0; cJSON *ismine;
            if ( (tmpstr= dpow_validateaddress(myinfo,coin,coin->changeaddr)) != 0 )
            {
                retjson = cJSON_Parse(tmpstr);
                if ( (ismine= jobj(json,"ismine")) != 0 && is_cJSON_True(ismine) != 0 )
                    destvalid = 1;
                else destvalid = 0;
                free(tmpstr);
                free(retjson);
                tmpstr = 0;
            }
            if ( destvalid == 0 )
            {
                bitcoin_priv2wif(wifstr,myinfo->persistent_priv,coin->chain->wiftype);
                jumblr_importprivkey(myinfo,coin,wifstr);
            }
        }
    }
    if ( bits256_nonz(myinfo->persistent_priv) != 0 )
    {
        char *jumblrstr,jumblr_passphrase[1024],coinaddr[64],KMDaddr[64]; bits256 privkey;
        sprintf(jumblr_passphrase,"jumblr %s",password);
        if ( (jumblrstr= jumblr_setpassphrase(myinfo,0,0,0,jumblr_passphrase)) != 0 )
            free(jumblrstr);
        privkey = jumblr_privkey(myinfo,coinaddr,0,KMDaddr,"kmd ");
        smartaddress_add(myinfo,privkey,"kmd","BTC",0.,0.);
        privkey = jumblr_privkey(myinfo,coinaddr,0,KMDaddr,"btc ");
        smartaddress_add(myinfo,privkey,"btc","KMD",0.,0.);
    }
    return(retstr);
}

THREE_STRINGS(bitcoinrpc,encryptwallet,passphrase,password,permanentfile)
{
    char *retstr,buf[128],wifstr[128]; cJSON *retjson; int32_t need_KMD = 0,need_BTC = 0,need_GAME = 0;
    if ( remoteaddr != 0 || coin == 0 )
        return(clonestr("{\"error\":\"no remote encrypt or no coin\"}"));
    iguana_walletlock(myinfo,coin);
    if ( password == 0 || password[0] == 0 )
        password = passphrase;
    if ( passphrase == 0 || passphrase[0] == 0 )
        passphrase = password;
    if ( passphrase == 0 )
        passphrase = "";
    if ( password == 0 )
        password = "";
    strcpy(myinfo->secret,passphrase);
    strcpy(myinfo->password,password);
    if ( permanentfile != 0 )
        strcpy(myinfo->permanentfile,permanentfile);
    retstr = SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,myinfo->password);
    //myinfo->expiration = (uint32_t)time(NULL) + 3600*24;
    struct iguana_waddress waddr; struct iguana_waccount *wacct;
    memset(&waddr,0,sizeof(waddr));
    if ( (wacct= iguana_waccountcreate(myinfo,"default")) != 0 )
    {
        if ( iguana_waddresscalc(myinfo,coin->chain->pubtype,coin->chain->wiftype,&waddr,myinfo->persistent_priv) != 0 )
            iguana_waddressadd(myinfo,coin,wacct,&waddr,0);
        else printf("couldnt waddresscalc persistent\n");
    } else printf("coildnt create default account\n");
    if ( waddr.wifstr[0] != 0 && bits256_nonz(waddr.privkey) != 0 && (retjson= cJSON_Parse(retstr)) != 0 )
    {
        free(retstr);
        bitcoin_priv2wif(wifstr,waddr.privkey,coin->chain->wiftype);
        jaddbits256(retjson,"privkey",waddr.privkey);
        sprintf(buf,"%swif",coin->symbol);
        jaddstr(retjson,buf,wifstr);
        if ( strcmp(coin->symbol,"KMD") != 0 )
            need_KMD = 1;
        if ( strcmp(coin->symbol,"BTC") != 0 )
            need_BTC = 1;
        if ( strcmp(coin->symbol,"GAME") != 0 )
            need_GAME = 1;
        if ( need_KMD != 0 && (coin= iguana_coinfind("KMD")) != 0 )
        {
            bitcoin_priv2wif(wifstr,waddr.privkey,coin->chain->wiftype);
            jaddstr(retjson,"KMDwif",wifstr);
        }
        if ( (coin= iguana_coinfind("LTC")) != 0 )
        {
            bitcoin_priv2wif(wifstr,waddr.privkey,coin->chain->wiftype);
            jaddstr(retjson,"LTCwif",wifstr);
            bitcoin_priv2wiflong(wifstr,waddr.privkey,coin->chain->wiftype);
            jaddstr(retjson,"LTCwiflong",wifstr);
        }
        if ( need_BTC != 0 )
        {
            bitcoin_priv2wif(wifstr,waddr.privkey,128);
            jaddstr(retjson,"BTCwif",wifstr);
        }
        if ( need_GAME != 0 && (coin= iguana_coinfind("GAME")) != 0 )
        {
            bitcoin_priv2wif(wifstr,waddr.privkey,coin->chain->wiftype);
            jaddstr(retjson,"GAMEwif",wifstr);
        }
        /*if ( (dexstr= _dex_importaddress(myinfo,coin->symbol,waddr.coinaddr)) != 0 )
        {
            if ( (dexjson= cJSON_Parse(dexstr)) != 0 )
                jadd(retjson,"deximport",dexjson);
            free(dexstr);
        }*/
        retstr = jprint(retjson,1);
    }
    //iguana_walletinitcheck(myinfo,coin);
    myinfo->dirty = (uint32_t)time(NULL);
    myinfo->expiration = 0;
    return(retstr);
}

FOUR_STRINGS(bitcoinrpc,walletpassphrasechange,oldpassword,newpassword,oldpermanentfile,newpermanentfile)
{
    char destfname[1024],*tmpstr,*loginstr,*passphrase,*retstr = 0; cJSON *tmpjson,*loginjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( (tmpstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,oldpassword,oldpermanentfile,oldpassword)) != 0 )
    {
        free(tmpstr);
        tmpstr = myinfo->decryptstr, myinfo->decryptstr = 0;
        if ( (tmpjson= cJSON_Parse(tmpstr)) != 0 )
        {
            if ( (loginstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,newpassword,newpermanentfile,newpassword)) != 0 )
            {
                if ( myinfo->decryptstr != 0 && (loginjson= cJSON_Parse(myinfo->decryptstr)) != 0 )
                {
                    if ( (passphrase= jstr(loginjson,"passphrase")) != 0 )
                    {
                        _SuperNET_encryptjson(myinfo,destfname,passphrase,0,newpermanentfile,0,loginjson);
                        //iguana_walletlock(myinfo);
                        retstr = SuperNET_login(IGUANA_CALLARGS,myinfo->handle,newpassword,newpermanentfile,newpassword);
                        myinfo->dirty = (uint32_t)time(NULL);
                    }
                    free_json(loginjson);
                }
                free(loginstr);
            }
            free_json(tmpjson);
        }
        if ( tmpstr != 0 )
            scrubfree(tmpstr);
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"need to call walletpassphrasechange again\"}");
    return(retstr);
}

TWOSTRINGS_AND_INT(bitcoinrpc,importaddress,address,account,rescan)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( coin != 0 && coin->notarychain >= 0 && coin->FULLNODE == 0 && address != 0 && account != 0 )
    {
        if ( strcmp(address,account) != 0 )
            return(clonestr("{\"error\":\"only special account == address supported\"}"));
        else return(_dex_importaddress(myinfo,coin->symbol,address));
    }
    return(0);
}

TWOSTRINGS_AND_INT(bitcoinrpc,importprivkey,wif,account,rescan)
{
    bits256 privkey; char *retstr,*str; cJSON *retjson; struct iguana_waddress addr,*waddr; struct iguana_waccount *wacct = 0; uint8_t type,redeemScript[4096]; int32_t len; struct vin_info V; bits256 debugtxid;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    if ( wif == 0 )
        return(clonestr("{\"error\":\"missing wif\"}"));
    myinfo->expiration++;
    if ( account == 0 || account[0] == 0 )
        account = "default";
    len = (int32_t)strlen(wif);
    memset(debugtxid.bytes,0,sizeof(debugtxid));
    if ( is_hexstr(wif,len) > 0 )
    {
        len >>= 1;
        decode_hex(redeemScript,len,wif);
        if ( (type= iguana_calcrmd160(coin,0,&V,redeemScript,len,debugtxid,-1,0xffffffff)) == IGUANA_SCRIPT_P2SH || type == IGUANA_SCRIPT_1of1 || V.N > 1 )
        {
            if ( (str= setaccount(myinfo,coin,&waddr,account,V.coinaddr,wif)) != 0 )
                free(str);
            retjson = iguana_p2shjson(myinfo,coin,0,waddr);
            return(jprint(retjson,1));
        }
    }
    privkey = iguana_str2priv(myinfo,coin,wif);
    //char str2[65]; printf("wif.%s -> %s\n",wif,bits256_str(str2,privkey));
    if ( bits256_nonz(privkey) == 0 )
        return(clonestr("{\"error\":\"illegal privkey\"}"));
    memset(&addr,0,sizeof(addr));
    if ( iguana_waddresscalc(myinfo,coin->chain->pubtype,coin->chain->wiftype,&addr,privkey) != 0 )
    {
        if ( myinfo->expiration == 0 )
            return(clonestr("{\"error\":\"need to unlock wallet\"}"));
        if ( (waddr= iguana_waddresssearch(myinfo,&wacct,addr.coinaddr)) != 0 )
        {
            //waddr = iguana_waccountswitch(myinfo,coin,account,addr.coinaddr,0);
            waddr->privkey = privkey;
            myinfo->dirty = 0;
            return(clonestr("{\"result\":\"privkey already in wallet\"}"));
        } else waddr = &addr;
        myinfo->expiration++;
        if ( (retstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,myinfo->password)) != 0 )
        {
            free(retstr);
            retstr = myinfo->decryptstr, myinfo->decryptstr = 0;
            iguana_waddresscalc(myinfo,coin->chain->pubtype,coin->chain->wiftype,waddr,privkey);
            iguana_waccountswitch(myinfo,coin,account,waddr->coinaddr,0);
            waddr->privkey = privkey;
            retjson = iguana_walletadd(myinfo,0,coin,retstr,account,waddr,0,0);
            if ( retstr != 0 )
                scrubfree(retstr);
            return(jprint(retjson,1));
        } else printf("null return from SuperNET_login\n");
    }
    return(clonestr("{\"error\":\"cant calculate waddress\"}"));
}

STRING_ARG(bitcoinrpc,dumpprivkey,address)
{
    cJSON *retjson; int32_t len,p2shflag=0; struct iguana_waddress *waddr; struct iguana_waccount *wacct; uint8_t addrtype,type,redeemScript[IGUANA_MAXSCRIPTSIZE]; char *coinaddr; struct vin_info V; bits256 debugtxid;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    len = (int32_t)strlen(address);
    coinaddr = address;
    memset(debugtxid.bytes,0,sizeof(debugtxid));
    if ( is_hexstr(address,len) > 0 )
    {
        len >>= 1;
        decode_hex(redeemScript,len,address);
        if ( (type= iguana_calcrmd160(coin,0,&V,redeemScript,len,debugtxid,-1,0xffffffff)) == IGUANA_SCRIPT_P2SH || type == IGUANA_SCRIPT_1of1 || V.N > 1 )
        {
            p2shflag = 1;
            coinaddr = V.coinaddr;
        }
    }
    if ( strlen(coinaddr) > sizeof(V.coinaddr) || iguana_addressvalidate(coin,&addrtype,coinaddr) < 0 )
        return(clonestr(p2shflag == 0 ? "{\"error\":\"invalid address\"}" : "{\"error\":\"invalid P2SH address\"}"));
    if ( (waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) != 0 )
    {
        if ( (waddr->wifstr[0] != 0 || waddr->scriptlen > 0) )
        {
            retjson = cJSON_CreateObject();
            if ( waddr->scriptlen == 0 && waddr->wifstr[0] != 0 )
                jaddstr(retjson,"result",waddr->wifstr);
            else iguana_p2shjson(myinfo,coin,retjson,waddr);
            return(jprint(retjson,1));
        } else return(clonestr("{\"error\":\"no privkey for address\"}"));
    } else return(clonestr("{\"error\":\"couldnt find address in wallet\"}"));
}

STRING_ARG(bitcoinrpc,dumpwallet,filename)
{
    char *retstr,*walletstr; cJSON *retjson,*walletobj,*strobj;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    if ( myinfo->expiration != 0 )
    {
        myinfo->expiration++;
        if ( (retstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,myinfo->password)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( (walletstr= myinfo->decryptstr) != 0 )
                {
                    myinfo->decryptstr = 0;
                    if ( (strobj= cJSON_Parse(walletstr)) != 0 )
                    {
                        if ( (walletobj= jobj(strobj,"wallet")) != 0 )
                            jadd(retjson,"wallet",jduplicate(walletobj));
                        if ( (0) && (walletobj= iguana_walletjson(myinfo)) != 0 )
                            jadd(retjson,"memory",walletobj);
                        free_json(strobj);
                    }
                    scrubfree(walletstr);
                }
                return(jprint(retjson,1));
            } else printf("cant parse retstr.(%s)\n",retstr);
        } else return(clonestr("{\"error\":\"couldnt decrypt wallet\"}"));
    }
    return(clonestr("{\"error\":\"wallet is locked, cant backup\"}"));
}

STRING_ARG(bitcoinrpc,backupwallet,filename)
{
    char *loginstr,*retstr = 0; cJSON *retjson,*payload;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    if ( myinfo->expiration != 0 )
    {
        myinfo->expiration++;
        if ( (loginstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,myinfo->password)) != 0 )
        {
            retstr = clonestr("{\"error\":\"couldnt backup wallet\"}");
            if ( myinfo->decryptstr != 0 )
            {
                free(loginstr);
                loginstr = myinfo->decryptstr, myinfo->decryptstr = 0;
            }
            if ( (retjson= cJSON_Parse(loginstr)) != 0 )
            {
                if ( (payload= jobj(retjson,"wallet")) != 0 && iguana_walletemit(myinfo,filename,coin,payload) == 0 )
                    retstr = clonestr("{\"result\":\"wallet backup saved\"}");
                free_json(retjson);
            } else printf("couldnt parse.(%s)\n",loginstr);
            if ( loginstr != 0 )
                scrubfree(loginstr);
            return(retstr);
        } else return(clonestr("{\"error\":\"no wallet payload\"}"));
    } else return(clonestr("{\"error\":\"need to unlock wallet\"}"));
}

STRING_ARG(bitcoinrpc,importwallet,filename)
{
    cJSON *retjson = 0,*importjson,*loginjson = 0; long filesize; char *importstr,*loginstr;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    if ( myinfo->expiration != 0 )
    {
        myinfo->expiration++;
        if ( (importstr= OS_filestr(&filesize,filename)) != 0 )
        {
            if ( (importjson= cJSON_Parse(importstr)) != 0 )
            {
                if ( (loginstr= SuperNET_login(IGUANA_CALLARGS,myinfo->handle,myinfo->secret,myinfo->permanentfile,myinfo->password)) != 0 )
                {
                    free(loginstr);
                    loginstr = myinfo->decryptstr, myinfo->decryptstr = 0;
                    loginjson = cJSON_Parse(loginstr);
                    if ( loginstr != 0 )
                        scrubfree(loginstr);
                }
                retjson = iguana_payloadmerge(loginjson,importjson);
                if ( importjson != 0 && importjson != retjson )
                    free_json(importjson);
                if ( loginjson != 0 && loginjson != retjson )
                    free_json(loginjson);
            }
            else
            {
                free(importstr);
                return(clonestr("{\"error\":\"couldnt parse import file\"}"));
            }
            return(clonestr("{\"result\":\"wallet imported\"}"));
        } else return(clonestr("{\"error\":\"couldnt open import file\"}"));
    }
    return(clonestr("{\"error\":\"need to unlock wallet\"}"));
}

ZERO_ARGS(bitcoinrpc,checkwallet)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    return(iguana_walletscan(myinfo,coin,1));
}

ZERO_ARGS(bitcoinrpc,repairwallet)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    myinfo->expiration++;
    return(iguana_walletscan(myinfo,coin,0));
}

// multiple address
STRING_AND_THREEINTS(bitcoinrpc,getbalance,account,minconf,includeempty,lastheight)
{
    int64_t balance; int32_t numunspents,numrmds=0; uint8_t *rmdarray=0; cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    if ( account == 0 )
        account = "*";
    if ( minconf == 0 )
        minconf = 1;
    //if ( strcmp(account,"*") != 0 )
        rmdarray = iguana_rmdarray(myinfo,coin,&numrmds,iguana_getaddressesbyaccount(myinfo,coin,account),0);
    numunspents = 0;
    balance = iguana_RTunspents(myinfo,coin,0,minconf,(1 << 30),rmdarray,numrmds,lastheight,0,&numunspents,remoteaddr,0);
    if ( rmdarray != 0 )
        free(rmdarray);
    retjson = cJSON_CreateObject();
    printf("%s balance %.8f\n",coin->symbol,dstr(balance));
    jaddnum(retjson,"result",dstr(balance));
    return(jprint(retjson,1));
}

STRING_ARG(bitcoinrpc,getaddressesbyaccount,account)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",iguana_getaddressesbyaccount(myinfo,coin,account));
    return(jprint(retjson,1));
}

STRING_AND_INT(bitcoinrpc,getreceivedbyaccount,account,minconf)
{
    cJSON *retjson; struct iguana_waccount *wacct; int64_t balance;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    retjson = cJSON_CreateObject();
    if ( (wacct= iguana_waccountfind(myinfo,account)) != 0 )
    {
        balance = iguana_waccountbalance(myinfo,coin,wacct,minconf,0);
        jaddnum(retjson,"result",dstr(balance));
    }
    return(jprint(retjson,1));
}

STRING_AND_THREEINTS(bitcoinrpc,listtransactions,account,count,skip,includewatchonly)
{ 
    cJSON *retjson,*retarray,*txids,*vouts,*item,*array; int32_t vout,i,j,total,m,n = 0; struct iguana_waccount *wacct=0; char *coinaddr; bits256 txid;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    retjson = cJSON_CreateObject();
    retarray = cJSON_CreateArray();
    if ( account == 0 || account[0] == 0 || (wacct= iguana_waccountfind(myinfo,account)) != 0 )
    {
        if ( (array= iguana_getaddressesbyaccount(myinfo,coin,account)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                total = 0;
                for (i=0; i<n; i++)
                {
                    if ( (coinaddr= jstr(jitem(array,i),0)) != 0 )
                    {
                        vouts = cJSON_CreateArray();
                        txids = cJSON_CreateArray();
                        iguana_addressreceived(myinfo,coin,0,remoteaddr,txids,vouts,0,0,coinaddr,1,0);
                        if ( (m= cJSON_GetArraySize(txids)) > 0 )
                        {
                            for (j=0; j<m; j++,total++)
                            {
                                txid = jbits256(jitem(txids,j),0);
                                vout = jint(jitem(vouts,j),0);
                                if ( skip < -count )
                                    break;
                                else
                                {
                                    skip--;
                                    if ( skip <= 0 )
                                    {
                                        /*{
                                          "category": "receive",
                                         "amount": 0.50000000,
                                         "label": "",
                                         "confirmations": 24466,
                                         "blockhash": "00000000000000000517ce625737579f91162c46ad9eaccad0f52ca13715b156",
                                         "blockindex": 78,
                                         "blocktime": 1448045745,
                                         }*/
                                        item = cJSON_CreateObject();
                                        if ( wacct != 0 )
                                            jaddstr(item,"account",wacct->account);
                                        iguana_txdetails(myinfo,coin,item,txid,vout,iguana_txidheight(myinfo,coin,txid));
                                        jaddi(retarray,item);
                                    }
                                }
                            }
                        }
                        free_json(txids);
                    }
                }
            }
        }
    }
    jadd(retjson,"result",retarray);
    return(jprint(retjson,1));
}

THREE_INTS(bitcoinrpc,listreceivedbyaccount,minconf,includeempty,watchonly)
{
    cJSON *retjson,*item,*array; struct iguana_waccount *wacct,*tmp; int64_t balance;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    array = cJSON_CreateArray();
    HASH_ITER(hh,myinfo->wallet,wacct,tmp)
    {
        balance = iguana_waccountbalance(myinfo,coin,wacct,minconf,0);
        item = cJSON_CreateObject();
        jaddstr(item,"account",wacct->account);
        jaddnum(item,"amount",dstr(balance));
        //jaddnum(item,"confirmations",coin->blocks.hwmchain.height - wacct->mostrecent);
        jaddi(array,item);
    }
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}

THREE_INTS(bitcoinrpc,listreceivedbyaddress,minconf,includeempty,flag)
{
    cJSON *retjson,*item,*array,*txids,*vouts; struct iguana_waccount *wacct,*tmp; struct iguana_waddress *waddr,*tmp2; uint8_t addrtype; char coinaddr[64];
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    //if ( myinfo->expiration == 0 )
    //    return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    array = cJSON_CreateArray();
    HASH_ITER(hh,myinfo->wallet,wacct,tmp)
    {
        HASH_ITER(hh,wacct->waddr,waddr,tmp2)
        {
            item = cJSON_CreateObject();
            addrtype = (waddr->scriptlen > 0) ? coin->chain->p2shtype : coin->chain->pubtype;
            bitcoin_address(coinaddr,addrtype,waddr->rmd160,20);
            jaddstr(item,"address",coinaddr);
            txids = cJSON_CreateArray();
            vouts = cJSON_CreateArray();
            jaddnum(item,"amount",dstr(iguana_addressreceived(myinfo,coin,0,remoteaddr,txids,vouts,0,0,coinaddr,minconf,0)));
            jadd(item,"txids",txids);
            jadd(item,"vouts",vouts);
            jaddi(array,item);
        }
    }
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}

STRING_AND_INT(bitcoinrpc,getreceivedbyaddress,address,minconf)
{
    char *balancestr; cJSON *balancejson,*retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    //if ( myinfo->expiration == 0 )
    //    return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    if ( (balancestr= iguana_balance(IGUANA_CALLARGS,coin->symbol,address,-1,minconf)) != 0 )
    {
        if ( (balancejson= cJSON_Parse(balancestr)) != 0 )
        {
            jaddnum(retjson,"result",jdouble(balancejson,"balance"));
            free_json(balancejson);
        }
    }
    if ( jobj(retjson,"result") == 0 )
        jaddstr(retjson,"error","couldnt get received by address");
    return(jprint(retjson,1));
}

TWO_INTS(bitcoinrpc,listaccounts,minconf,includewatchonly)
{
    cJSON *retjson,*array; int64_t balance; struct iguana_waccount *wacct,*tmp;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    array = cJSON_CreateObject();
    HASH_ITER(hh,myinfo->wallet,wacct,tmp)
    {
        balance = iguana_waccountbalance(myinfo,coin,wacct,minconf,0);
        jaddnum(array,wacct->account,dstr(balance));
    }
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}

#include "../includes/iguana_apiundefs.h"

