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

#ifndef INCLUDE_KMDLOOKUP_H
#define INCLUDE_KMDLOOKUP_H

#define KMD_EXPLORER_LAG 6

struct kmd_voutinfo
{
    bits256 spendtxid;
    uint64_t amount;
    uint16_t spendvini;
    uint8_t type_rmd160[21], pad;
} PACKED;

struct kmd_transaction
{
    bits256 txid; int32_t height,numvouts,numvins; uint32_t timestamp;
    struct kmd_voutinfo vouts[];
} PACKED;

struct kmd_transactionhh
{
    UT_hash_handle hh;
    struct kmd_transaction *tx;
    long fpos;
    int32_t numvouts,numvins;
    struct kmd_transactionhh *ptrs[];
};

struct kmd_addresshh
{
    UT_hash_handle hh;
    struct kmd_transactionhh *prev,*lastprev;
    uint8_t type_rmd160[21], pad;
};

struct kmd_addresshh *_kmd_address(struct iguana_info *coin,uint8_t type_rmd160[21])
{
    struct kmd_addresshh *addr;
    portable_mutex_lock(&coin->kmdmutex);
    HASH_FIND(hh,coin->kmd_addresses,type_rmd160,21,addr);
    portable_mutex_unlock(&coin->kmdmutex);
    if ( addr != 0 && 0 )
    {
        char coinaddr[64];
        bitcoin_address(coinaddr,type_rmd160[0],&type_rmd160[1],20);
        printf("%s found (%s) %02x\n",coin->symbol,coinaddr,type_rmd160[0]);
    }
    return(addr);
}

struct kmd_addresshh *_kmd_addressadd(struct iguana_info *coin,uint8_t type_rmd160[21])
{
    struct kmd_addresshh *addr;
    addr = calloc(1,sizeof(*addr));
    memcpy(addr->type_rmd160,type_rmd160,21);
    if ( 0 )
    {
        char coinaddr[64];
        bitcoin_address(coinaddr,type_rmd160[0],&type_rmd160[1],20);
        printf("%s NEW ADDRESS.(%s) %02x\n",coin->symbol,coinaddr,type_rmd160[0]);
    }
    portable_mutex_lock(&coin->kmdmutex);
    HASH_ADD_KEYPTR(hh,coin->kmd_addresses,addr->type_rmd160,21,addr);
    portable_mutex_unlock(&coin->kmdmutex);
    return(addr);
}

struct kmd_addresshh *kmd_address(struct iguana_info *coin,char *coinaddr)
{
    uint8_t type_rmd160[21];
    bitcoin_addr2rmd160(&type_rmd160[0],&type_rmd160[1],coinaddr);
    return(_kmd_address(coin,type_rmd160));
}

struct kmd_transactionhh *kmd_transaction(struct iguana_info *coin,bits256 txid)
{
    struct kmd_transactionhh *tx;
    portable_mutex_lock(&coin->kmdmutex);
    HASH_FIND(hh,coin->kmd_transactions,txid.bytes,sizeof(txid),tx);
    portable_mutex_unlock(&coin->kmdmutex);
    return(tx);
}

int32_t kmd_transactionvin(struct iguana_info *coin,bits256 spendtxid,int32_t vini,bits256 txid,int32_t vout)
{
    struct kmd_transactionhh *ptr,*spendptr=0;
    if ( bits256_nonz(txid) == 0 || vout < 0 )
        return(0); // coinbase must be
    if ( (ptr= kmd_transaction(coin,txid)) != 0 && vout < ptr->numvouts && (spendptr= kmd_transaction(coin,spendtxid)) != 0 )
    {
        ptr->ptrs[(vout<<1) + 1] = spendptr;
        if ( bits256_cmp(ptr->tx->vouts[vout].spendtxid,spendtxid) != 0 || ptr->tx->vouts[vout].spendvini != vini )
        {
            if ( bits256_nonz(ptr->tx->vouts[vout].spendtxid) != 0 )
                printf("ht.%d vout.%d overwriting nonz spend\n",ptr->tx->height,vout);
            //uint8_t type_rmd160[21]; char str[65];
            //bitcoin_addr2rmd160(&type_rmd160[0],&type_rmd160[1],"RR5yAkzaxJeCVTwvpgCGsNcSPAZjeq3av4");
            //if ( memcmp(type_rmd160,ptr->tx->vouts[vout].type_rmd160,21) == 0 )
            //    printf("RR5yAkzaxJeCVTwvpgCGsNcSPAZjeq3av4 %p vout.%d spend %.8f by %s/%d %p\n",ptr,vout,dstr(ptr->tx->vouts[vout].amount),bits256_str(str,spendtxid),vini,spendptr);
            ptr->tx->vouts[vout].spendtxid = spendtxid;
            ptr->tx->vouts[vout].spendvini = vini;
        }
        return(0);
    }
    char str[65]; printf("%s.vin error %s vout.%d of %d vs ptr %p [%d] spent.%p\n",coin->symbol,bits256_str(str,txid),vout,ptr!=0?ptr->numvouts:-1,ptr,ptr!=0?ptr->numvouts:-1,spendptr);
    return(-1);
}

void kmd_transactionvout(struct iguana_info *coin,struct kmd_transactionhh *ptr,int32_t vout,uint64_t amount,uint8_t type_rmd160[21],bits256 spendtxid,int32_t spendvini)
{
    struct kmd_addresshh *addr; struct kmd_transaction *tx = 0;
    if ( 0 )
    {
        char coinaddr[64],str[65];
        bitcoin_address(coinaddr,type_rmd160[0],&type_rmd160[1],20);
        if ( strcmp(coinaddr,"RCsKEQ3r5Xxw4ZtK4CH9VzvfGpTFMdPpsh") == 0 )
            printf("%s ht.%d %s VOUT %d %.8f\n",coinaddr,ptr->tx->height,bits256_str(str,ptr->tx->txid),vout,dstr(amount));
    }
    if ( vout < ptr->numvouts && (tx= ptr->tx) != 0 )
    {
        tx->vouts[vout].spendtxid = spendtxid;
        tx->vouts[vout].spendvini = spendvini;
        tx->vouts[vout].amount = amount;
        memcpy(tx->vouts[vout].type_rmd160,type_rmd160,21);
        if ( (addr= _kmd_address(coin,type_rmd160)) == 0 )
            addr = _kmd_addressadd(coin,type_rmd160);
        if ( addr != 0 )
        {
            if ( addr->prev != ptr )
            {
                ptr->ptrs[vout << 1] = addr->prev;
                addr->lastprev = addr->prev;
                addr->prev = ptr;
            }
            else
            {
                //printf("tricky case same address in different vouts, make sure backlink is right\n");
                ptr->ptrs[vout<<1] = addr->lastprev;
            }
        } else printf("kmd_transactionvout unexpected null addr\n");
    } else printf("vout.%d wont fit into numvouts.[%d] or null tx.%p\n",vout,ptr->numvouts,tx);
}

struct kmd_transactionhh *kmd_transactionadd(struct iguana_info *coin,struct kmd_transaction *tx,int32_t numvouts,int32_t numvins)
{
    struct kmd_transactionhh *ptr; //char str[65];
    if ( (ptr= kmd_transaction(coin,tx->txid)) == 0 )
    {
        ptr = calloc(1,sizeof(*ptr) + (sizeof(*ptr->ptrs)*numvouts*2));
        ptr->numvouts = numvouts;
        ptr->numvins = numvins;
        ptr->tx = tx;
        portable_mutex_lock(&coin->kmdmutex);
        //char str[65]; printf("%s ht.%d u.%u NEW TXID.(%s) vouts.[%d]\n",coin->symbol,tx->height,tx->timestamp,bits256_str(str,tx->txid),numvouts);
        HASH_ADD_KEYPTR(hh,coin->kmd_transactions,tx->txid.bytes,sizeof(tx->txid),ptr);
        portable_mutex_unlock(&coin->kmdmutex);
    } // else printf("warning adding already existing txid %s\n",bits256_str(str,tx->txid));
    return(ptr);
}

struct kmd_transaction *kmd_transactionalloc(bits256 txid,int32_t height,uint32_t timestamp,int32_t numvouts,int32_t numvins)
{
    struct kmd_transaction *tx;
    tx = calloc(1,sizeof(*tx) + sizeof(struct kmd_voutinfo)*numvouts);
    tx->numvouts = numvouts;
    tx->numvins = numvins;
    tx->txid = txid;
    tx->height = height;
    tx->timestamp = timestamp;
    return(tx);
}

void kmd_flushfiles(struct iguana_info *coin)
{
    if ( coin->kmd_txidfp != 0 )
        fflush(coin->kmd_txidfp);
    if ( coin->kmd_spendfp != 0 )
        fflush(coin->kmd_spendfp);
}

FILE *kmd_txidinit(struct iguana_info *coin)
{
    int32_t i; FILE *fp; char fname[1024]; struct kmd_transactionhh *ptr; struct kmd_transaction T,*tx; struct kmd_voutinfo V; long lastpos=0;
    sprintf(fname,"%s/TRANSACTIONS/%s",GLOBAL_DBDIR,coin->symbol);
    if ( (fp= fopen(fname,"rb+")) != 0 )
    {
        while ( fread(&T,1,sizeof(T),fp) == sizeof(T) )
        {
            if ( (tx= kmd_transactionalloc(T.txid,T.height,T.timestamp,T.numvouts,T.numvins)) != 0 )
            {
                //char str[65]; printf("INIT %s.[%d] vins.[%d] ht.%d %u\n",bits256_str(str,T.txid),T.numvouts,T.numvins,T.height,T.timestamp);
                if ( (ptr= kmd_transactionadd(coin,tx,T.numvouts,T.numvins)) != 0 )
                {
                    if ( ptr != kmd_transaction(coin,tx->txid) )
                        printf("%s ERROR: %p != %p for ht.%d\n",coin->symbol,ptr,kmd_transaction(coin,tx->txid),tx->height);
                    ptr->fpos = lastpos;
                    ptr->numvins = T.numvins;
                    ptr->numvouts = T.numvouts;
                    for (i=0; i<T.numvouts; i++)
                    {
                        if ( fread(&V,1,sizeof(V),fp) == sizeof(V) )
                        {
                            kmd_transactionvout(coin,ptr,i,V.amount,V.type_rmd160,V.spendtxid,V.spendvini);
                        }
                        else
                        {
                            printf("%s error loading vout.%d ht.%d\n",coin->symbol,i,T.height);
                            break;
                        }
                    }
                    if ( i == T.numvouts )
                    {
                        lastpos = ftell(fp);
                        if ( T.height > coin->kmd_height )
                            coin->kmd_height = T.height;
                    } else break;
                }
            } else break;
        }
        printf("%s finished txidinit fpos %ld vs lastpos %ld\n",coin->symbol,ftell(fp),lastpos);
        fseek(fp,lastpos,SEEK_SET);
    } else fp = fopen(fname,"wb+");
    return(fp);
}

FILE *kmd_spendinit(struct iguana_info *coin)
{
    int32_t i,numvins,spentvout; FILE *fp; char fname[1024],str[65]; bits256 txid,spenttxid; struct kmd_transactionhh *ptr,*tmp; struct kmd_voutinfo *vptr; long lastpos=0;
    sprintf(fname,"%s/TRANSACTIONS/%s.spends",GLOBAL_DBDIR,coin->symbol);
    if ( (fp= fopen(fname,"rb+")) != 0 )
    {
        while ( fread(&txid,1,sizeof(txid),fp) == sizeof(txid) )
        {
            if ( fread(&numvins,1,sizeof(numvins),fp) == sizeof(numvins) )
            {
                for (i=0; i<numvins; i++)
                {
                    if ( fread(&spenttxid,1,sizeof(spenttxid),fp) == sizeof(spenttxid) &&
                        fread(&spentvout,1,sizeof(spentvout),fp) == sizeof(spentvout) )
                    {
                        if ( kmd_transactionvin(coin,txid,i,spenttxid,spentvout) < 0 )
                        {
                            printf("%s error adding spend %s %d of %d\n",coin->symbol,bits256_str(str,txid),i,numvins);
                            //break;
                        }
                    } else break;
                }
                if ( i == numvins )
                    lastpos = ftell(fp);
                else break;
            } else break;
        }
        printf("%s finished spendinit fpos %ld vs lastpos %ld\n",coin->symbol,ftell(fp),lastpos);
        fseek(fp,lastpos,SEEK_SET);
        HASH_ITER(hh,coin->kmd_transactions,ptr,tmp)
        {
            //printf("scan for spends ht.%d\n",ptr->tx->height);
            for (i=0; i<ptr->numvouts; i++)
            {
                vptr = &ptr->tx->vouts[i];
                if ( vptr->spendvini >= 0 && bits256_nonz(vptr->spendtxid) != 0 )
                {
                    if ( ptr->ptrs[(i<<1) + 1] != kmd_transaction(coin,vptr->spendtxid) )
                    {
                        printf("%s mismatch %s spend.%d %p %p\n",coin->symbol,bits256_str(str,vptr->spendtxid),i,ptr->ptrs[(i<<1) + 1],kmd_transaction(coin,vptr->spendtxid));
                    }
                }
            }
        }
    } else fp = fopen(fname,"wb+");
    return(fp);
}

cJSON *kmd_transactionjson(int32_t height,struct kmd_transactionhh *ptr,char *typestr)
{
    int32_t i; char coinaddr[64]; cJSON *item,*array,*obj = cJSON_CreateObject();
    array = cJSON_CreateArray();
    jaddstr(obj,"type",typestr);
    jaddbits256(obj,"txid",ptr->tx->txid);
    jaddnum(obj,"height",ptr->tx->height);
    jaddnum(obj,"timestamp",ptr->tx->timestamp);
    for (i=0; i<ptr->numvouts; i++)
    {
        item = cJSON_CreateObject();
        bitcoin_address(coinaddr,ptr->tx->vouts[i].type_rmd160[0],&ptr->tx->vouts[i].type_rmd160[1],20);
        jaddnum(item,coinaddr,dstr(ptr->tx->vouts[i].amount));
        jaddi(array,item);
    }
    jadd(obj,"vouts",array);
    return(obj);
}

cJSON *kmd_unspentjson(struct supernet_info *myinfo,struct iguana_info *coin,int32_t height,struct kmd_transaction *tx,int32_t vout,int32_t is_listunspent)
{
    char *script; cJSON *sobj,*txout,*item = cJSON_CreateObject();
    jaddstr(item,"type","received");
    jaddnum(item,"confirmations",height - tx->height);
    jaddnum(item,"height",tx->height);
    jaddnum(item,"timestamp",tx->timestamp);
    jaddbits256(item,"txid",tx->txid);
    jaddnum(item,"vout",vout);
    jaddnum(item,"amount",dstr(tx->vouts[vout].amount));
    if ( strcmp(coin->symbol,"KMD") == 0 )
        jaddnum(item,"interest",dstr(_iguana_interest((uint32_t)time(NULL),coin->longestchain,tx->timestamp,tx->vouts[vout].amount)));
    if ( is_listunspent != 0 )
    {
        //char str[65]; printf("get spendscriptstr for %s/v%d\n",bits256_str(str,tx->txid),vout);
        if ( (txout= dpow_gettxout(myinfo,coin,tx->txid,vout)) != 0 )
        {
            //printf("got.(%s)\n",jprint(txout,0));
            if ( (sobj= jobj(txout,"scriptPubKey")) != 0 && (script= jstr(sobj,"hex")) != 0 )
                jaddstr(item,"scriptPubKey",script);
            free_json(txout);
        }
    }
    return(item);
}

cJSON *kmd_spentjson(int32_t height,struct kmd_transaction *tx,int32_t vout,struct kmd_transactionhh *spent)
{
    cJSON *item = cJSON_CreateObject();
    jaddstr(item,"type","sent");
    jaddnum(item,"confirmations",height - tx->height);
    jaddnum(item,"height",tx->height);
    jaddnum(item,"timestamp",tx->timestamp);
    jaddbits256(item,"txid",tx->txid);
    jaddnum(item,"vout",vout);
    jaddnum(item,"amount",dstr(tx->vouts[vout].amount));
    jaddbits256(item,"spendtxid",tx->vouts[vout].spendtxid);
    jaddnum(item,"vin",tx->vouts[vout].spendvini);
    if ( spent != 0 )
    {
        jadd(item,"paid",kmd_transactionjson(height,spent,"paid"));
    }
    return(item);
}

int32_t kmd_height(struct iguana_info *coin)
{
    char params[64],*curlstr; cJSON *curljson; int32_t height = 0;
    strcpy(params,"[]");
    if ( (curlstr= bitcoind_getinfo(coin->symbol,coin->chain->serverport,coin->chain->userpass,coin->getinfostr)) != 0 )
    {
        if ( (curljson= cJSON_Parse(curlstr)) != 0 )
        {
            height = juint(curljson,"blocks");
            //printf("kmd_height.%d (%s)\n",height,jprint(curljson,0));
            free_json(curljson);
        }
        free(curlstr);
    }
    return(height);
}

cJSON *kmd_gettxin(struct iguana_info *coin,bits256 txid,int32_t vout)
{
    struct kmd_transactionhh *ptr,*spendptr; struct kmd_transaction *tx; cJSON *retjson;
    if ( (ptr= kmd_transaction(coin,txid)) != 0 && (tx= ptr->tx) != 0 )
    {
        if ( vout >= ptr->numvouts )
            return(cJSON_Parse("{\"error\":\"vout too big\"}"));
        if ( (spendptr= ptr->ptrs[(vout << 1) + 1]) != 0 )
        {
            retjson = cJSON_CreateObject();
            jaddstr(retjson,"result","success");
            jaddstr(retjson,"status","spent");
            jaddnum(retjson,"height",tx->height);
            jaddnum(retjson,"timestamp",tx->timestamp);
            jaddbits256(retjson,"txid",txid);
            jaddnum(retjson,"vout",vout);
            jaddnum(retjson,"value",dstr(tx->vouts[vout].amount));
            jaddbits256(retjson,"spendtxid",tx->vouts[vout].spendtxid);
            jaddnum(retjson,"vin",tx->vouts[vout].spendvini);
        } else return(cJSON_Parse("{\"result\":\"success\",\"status\":\"unspent\"}"));
    }
    return(cJSON_Parse("{\"error\":\"txid not found\"}"));
}

cJSON *kmd_listaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,int32_t mode,cJSON *array)
{
    struct kmd_addresshh *addr; struct kmd_transactionhh *ptr=0,*spent,*prev=0; uint8_t type_rmd160[21]; int32_t i; char *retstr; cJSON *retjson;
    if ( array == 0 )
        array = cJSON_CreateArray();
    //printf("%s listaddress.(%s)\n",coin->symbol,coinaddr);
    if ( (retstr= bitcoinrpc_validateaddress(myinfo,coin,0,0,coinaddr)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( jobj(retjson,"error") != 0 && is_cJSON_False(jobj(retjson,"error")) == 0 )
            {
                printf("%s\n",retstr);
                free(retstr);
                return(retjson);
            }
            free_json(retjson);
        }
        free(retstr);
    }
    /*if ( time(NULL) > coin->kmd_lasttime+30 )
    {
        coin->kmd_lasttime = (uint32_t)time(NULL);
        if ( (height= kmd_height(coin)) > coin->kmd_height+KMD_EXPLORER_LAG*2 )
        {
            printf("height.%d > kmd_height.%d\n",height,coin->kmd_height);
            return(cJSON_Parse("[]"));
        }
    }*/
    if ( strcmp("1111111111111111111114oLvT2",coinaddr) == 0 ) // null rmd160 from coinbase
        return(cJSON_Parse("[]"));
    bitcoin_addr2rmd160(&type_rmd160[0],&type_rmd160[1],coinaddr);
    if ( (addr= _kmd_address(coin,type_rmd160)) != 0 && (ptr= addr->prev) != 0 && ptr->tx != 0 )
    {
        while ( ptr != 0 )
        {
            prev = 0;
            for (i=0; i<ptr->numvouts; i++)
            {
                if ( memcmp(ptr->tx->vouts[i].type_rmd160,type_rmd160,21) == 0 )
                {
                    spent = ptr->ptrs[(i<<1) + 1];
                    //if ( strcmp("RFpYbieWuKm2ZsTaKeWkrrEdeSkVzhqX8x",coinaddr) == 0 )
                    //    printf("mode.%d [%d] %s ht.%d amount %.8f spent.%p\n",mode,coin->kmd_height,coinaddr,ptr->tx->height,dstr(ptr->tx->vouts[i].amount),spent);
                    if ( (mode == 0 && spent == 0) || (mode == 1 && spent != 0) || mode == 2 )
                    {
                        //if ( fulltx == 0 )
                        {
                            if ( mode == 0 )
                                jaddi(array,kmd_unspentjson(myinfo,coin,coin->kmd_height,ptr->tx,i,1));
                            else if ( mode == 1 )
                                jaddi(array,kmd_spentjson(coin->kmd_height,ptr->tx,i,spent));
                            else if ( mode == 2 )
                            {
                                if ( spent != 0 )
                                    jaddi(array,kmd_spentjson(coin->kmd_height,ptr->tx,i,spent));
                                else jaddi(array,kmd_unspentjson(myinfo,coin,coin->kmd_height,ptr->tx,i,0));
                            }
                        }
                        /*else if ( flag == 0 )
                        {
                            if ( mode == 0 )
                                jaddi(array,kmd_transactionjson(coin->kmd_height,ptr,"received"));
                            else if ( mode == 1 )
                            {
                                jaddi(array,kmd_transactionjson(coin->kmd_height,ptr,"received"));
                                jaddi(array,kmd_transactionjson(coin->kmd_height,spent,"sent"));
                            }
                            else if ( mode == 2 )
                            {
                                if ( spent != 0 )
                                    jaddi(array,kmd_transactionjson(coin->kmd_height,ptr,"spent"));
                                else jaddi(array,kmd_transactionjson(coin->kmd_height,ptr,"received"));
                            }
                            flag = 1;
                        }*/
                    }
                    if ( ptr->ptrs[i<<1] != 0 )
                    {
                        if ( prev == 0 )
                            prev = ptr->ptrs[i<<1];
                        else if ( prev != ptr->ptrs[i<<1] )
                            printf("%s ht.%d prev.%p != %p\n",coinaddr,ptr->tx->height,prev,ptr->ptrs[i<<1]);
                    }
                }
            }
            ptr = prev;
        }
    } //else printf("no valid entry for (%s) %p %p\n",coinaddr,addr,ptr);
    return(array);
}

cJSON *kmd_listunspent(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    cJSON *retjson;
    retjson = kmd_listaddress(myinfo,coin,coinaddr,0,0);
    //printf("KMD utxos.(%s)\n",jprint(retjson,0));
    return(retjson);
}

cJSON *kmd_listspent(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    return(kmd_listaddress(myinfo,coin,coinaddr,1,0));
}

cJSON *kmd_listtransactions(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,int32_t count,int32_t skip)
{
    cJSON *array = cJSON_CreateArray();
    //if ( (height= kmd_height(coin)) > coin->kmd_height+KMD_EXPLORER_LAG )
    //    return(cJSON_Parse("[]"));
    if ( count == 0 )
        count = 100;
    array = kmd_listaddress(myinfo,coin,coinaddr,0,0);
    array = kmd_listaddress(myinfo,coin,coinaddr,1,array);
    return(array);
}

int64_t _kmd_getbalance(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,uint64_t *receivedp,uint64_t *sentp,uint64_t *interestp)
{
    int32_t iter,i,n; cJSON *array,*item; uint64_t value;
    for (iter=1; iter<=2; iter++)
    {
        if ( (array= kmd_listaddress(myinfo,coin,coinaddr,iter,0)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( (value= jdouble(item,"amount")*SATOSHIDEN) != 0 || (value= jdouble(item,"value")*SATOSHIDEN) != 0 )
                    {
                        if ( iter == 2 )
                        {
                            *receivedp += value;
                            *interestp += jdouble(item,"interest") * SATOSHIDEN;
                        } else *sentp += value;
                    }
                }
            }
            free_json(array);
        }
    }
    return(*receivedp - *sentp);
}

cJSON *kmd_getbalance(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    cJSON *retjson; double netbalance=0.,fbalance; uint64_t interest,i,s,r,sent=0,received=0; int64_t balance=0; struct kmd_addresshh *addr,*tmp; char address[64]; int32_t height = coin->kmd_height+1;
    retjson = cJSON_CreateObject();
    fbalance = 0.;
    interest = 0;
    if ( strcmp(coinaddr,"*") == 0 )
    {
        HASH_ITER(hh,coin->kmd_addresses,addr,tmp)
        {
            bitcoin_address(address,addr->type_rmd160[0],&addr->type_rmd160[1],20);
            s = r = i = 0;
            balance += _kmd_getbalance(myinfo,coin,address,&r,&s,&i);
            netbalance += dstr(r);
            netbalance -= dstr(s);
            if ( (r - s) > 100000*SATOSHIDEN )
                printf("{\"address\":\"%s\",\"received\":%.8f,\"sent\":%.8f,\"balance\":%.8f,\"supply\":%.8f,\"supplyf\":%.8f,\"interest\":%.8f}\n",address,dstr(r),dstr(s),dstr(r)-dstr(s),dstr(balance),netbalance,dstr(interest));
            received += r;
            sent += s;
            interest += i;
        }
        if ( strcmp("KMD",coin->symbol) == 0 )
            jaddnum(retjson,"interestpaid",dstr(balance) - 100000000 - (height*3));
    }
    else
    {
        balance = _kmd_getbalance(myinfo,coin,coinaddr,&received,&sent,&interest);
        netbalance = dstr(balance);
    }
    jaddstr(retjson,"result","success");
    jaddnum(retjson,"received",dstr(received));
    jaddnum(retjson,"sent",dstr(sent));
    //if ( fabs(netbalance*SATOSHIDEN - balance) > 1 )
        jaddnum(retjson,"balancef",netbalance+1./(SATOSHIDEN*2)-SMALLVAL);
    //else
    jaddnum(retjson,"balance",dstr(balance));
    jaddnum(retjson,"interest",dstr(interest));
    jaddnum(retjson,"height",height);
    if ( strcmp("KMD",coin->symbol) == 0 )
        jaddnum(retjson,"mined",height*3);
    return(retjson);
}

char *kmd_bitcoinblockhashstr(char *coinstr,char *serverport,char *userpass,int32_t height)
{
    char numstr[128],*blockhashstr=0; bits256 hash2; struct iguana_info *coin;
    sprintf(numstr,"%d",height);
    if ( (blockhashstr= bitcoind_passthru(coinstr,serverport,userpass,"getblockhash",numstr)) == 0 )
        return(0);
    hash2 = bits256_conv(blockhashstr);
    if ( blockhashstr == 0 || blockhashstr[0] == 0 || bits256_nonz(hash2) == 0 )
    {
        printf("%s couldnt get blockhash for %u, probably curl is disabled %p\n",coinstr,height,blockhashstr);
        if ( blockhashstr != 0 )
            free(blockhashstr);
        if ( height == 0 )
        {
            if ( (coin= iguana_coinfind(coinstr)) != 0 )
            {
                bits256_str(numstr,*(bits256 *)coin->chain->genesis_hashdata);
                return(clonestr(numstr));
            }
        }
        return(0);
    }
    return(blockhashstr);
}

cJSON *kmd_blockjson(int32_t *heightp,char *coinstr,char *serverport,char *userpass,char *blockhashstr,int32_t height)
{
    cJSON *json = 0; int32_t flag = 0; char buf[1024],*blocktxt = 0;
    if ( blockhashstr == 0 )
        blockhashstr = kmd_bitcoinblockhashstr(coinstr,serverport,userpass,height), flag = 1;
    if ( blockhashstr != 0 )
    {
        sprintf(buf,"\"%s\"",blockhashstr);
        blocktxt = bitcoind_passthru(coinstr,serverport,userpass,"getblock",buf);
        //printf("get_blockjson.(%d %s) %s\n",height,blockhashstr,blocktxt);
        if ( blocktxt != 0 && blocktxt[0] != 0 && (json= cJSON_Parse(blocktxt)) != 0 && heightp != 0 )
            if ( (*heightp= juint(json,"height")) != height )
                *heightp = -1;
        if ( flag != 0 && blockhashstr != 0 )
            free(blockhashstr);
        if ( blocktxt != 0 )
            free(blocktxt);
    }
    return(json);
}

int32_t _kmd_bitcoinscan(struct iguana_info *coin)
{
    int32_t h,num=0,loadheight,lag,i,n,j,iter,numtxids,numvins,numvouts,flag=0,height=-1; cJSON *txjson,*vouts,*vins,*blockjson,*txids,*vout,*vin,*sobj,*addresses; bits256 zero,txid; char *curlstr,params[128],str[65]; struct kmd_transactionhh *ptr; struct kmd_transaction *tx; uint8_t type_rmd160[21];
    if ( coin->kmd_didinit == 0 )
    {
        if ( (coin->kmd_txidfp= kmd_txidinit(coin)) == 0 )
            printf("error initializing %s.kmd txid\n",coin->symbol);
        else if ( (coin->kmd_spendfp= kmd_spendinit(coin)) == 0 )
            printf("error initializing %s.kmd spend\n",coin->symbol);
        coin->kmd_didinit = 1;
    }
    height = kmd_height(coin);
    loadheight = coin->kmd_height+1;
    //if ( strcmp(coin->symbol,"LTC") == 0 )
    //    lag = 3;
    //else
        lag = (strcmp(coin->symbol,"KMD") == 0 ? KMD_EXPLORER_LAG : 2);
    while ( loadheight < height-lag )
    {
        flag = 0;
        if ( (loadheight % 10000) == 0 )
            printf("loading %s ht.%d vs height.%d - lag.%d kmdheight.%d\n",coin->symbol,loadheight,height,lag,coin->kmd_height);//,jprint(kmd_getbalance(coin,"*"),1));
        if ( (blockjson= kmd_blockjson(&h,coin->symbol,coin->chain->serverport,coin->chain->userpass,0,loadheight)) != 0 )
        {
            if ( (txids= jarray(&numtxids,blockjson,"tx")) != 0 )
            {
                for (iter=0; iter<2; iter++)
                for (i=0; i<numtxids; i++)
                {
                    memset(&zero,0,sizeof(zero));
                    txid = jbits256(jitem(txids,i),0);
                    if ( iter == 0 && kmd_transaction(coin,txid) != 0 )
                    {
                        //printf("already have txid.%s\n",bits256_str(str,txid));
                        continue;
                    }
                    sprintf(params,"[\"%s\", 1]",bits256_str(str,txid));
                    if ( (curlstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getrawtransaction",params)) != 0 )
                    {
                        if ( (txjson= cJSON_Parse(curlstr)) != 0 )
                        {
                            if ( bits256_cmp(txid,jbits256(txjson,"txid")) != 0 )
                            {
                                printf("%s txid mismatch error ht.%d i.%d\n",coin->symbol,loadheight,i);
                                continue;
                            }
                            vouts = jarray(&numvouts,txjson,"vout");
                            vins = jarray(&numvins,txjson,"vin");
                            tx = 0;
                            ptr = 0;
                            if ( iter == 0 )
                            {
                                if ( (tx= kmd_transactionalloc(txid,loadheight,jint(txjson,"blocktime"),numvouts,numvins)) != 0 )
                                        ptr = kmd_transactionadd(coin,tx,numvouts,numvins);
                                else printf("error init tx ptr.%p tx.%p\n",ptr,tx);
                            }
                            else
                            {
                                if ( (ptr= kmd_transaction(coin,txid)) != 0 )
                                    tx = ptr->tx;
                            }
                            if ( ptr != 0 && tx != 0 )
                            {
                                if ( iter == 0 )
                                {
                                    sobj = addresses = 0;
                                    for (j=0; j<numvouts; j++)
                                    {
                                        vout = jitem(vouts,j);
                                        if ( (sobj= jobj(vout,"scriptPubKey")) != 0 && (addresses= jarray(&n,sobj,"addresses")) != 0 )
                                        {
                                            bitcoin_addr2rmd160(&type_rmd160[0],&type_rmd160[1],jstri(addresses,0));
                                            kmd_transactionvout(coin,ptr,j,jdouble(vout,"value")*SATOSHIDEN,type_rmd160,zero,-1);
                                            //fprintf(stderr,"%.8f ",jdouble(vout,"value"));
                                        } // else printf("missing sobj.%p or addresses.%p (%s)\n",sobj,addresses,jprint(vout,0)); //likely OP_RETURN
                                        sobj = addresses = 0;
                                    }
                                    //fprintf(stderr,"numvouts.%d ht.%d %s\n",numvouts,height,coin->symbol);
                                    if ( coin->kmd_txidfp != 0 )
                                    {
                                        ptr->fpos = ftell(coin->kmd_txidfp);
                                        fwrite(tx,1,sizeof(*tx) + tx->numvouts*sizeof(*tx->vouts),coin->kmd_txidfp);
                                        fflush(coin->kmd_txidfp);
                                    }
                                }
                                else
                                {
                                    if ( coin->kmd_spendfp != 0 )
                                    {
                                        fwrite(&txid,1,sizeof(txid),coin->kmd_spendfp);
                                        fwrite(&numvins,1,sizeof(numvins),coin->kmd_spendfp);
                                        fflush(coin->kmd_spendfp);
                                    }
                                    for (j=0; j<numvins; j++)
                                    {
                                        bits256 spenttxid; int32_t spentvout;
                                        vin = jitem(vins,j);
                                        spenttxid = jbits256(vin,"txid");
                                        spentvout = jint(vin,"vout");
                                        //if ( bits256_nonz(spenttxid) == 0 || spentvout < 0 )
                                        //    printf("null spenttxid ht.%d j.%d spentvout.%d\n",loadheight,j,spentvout);
                                        if ( kmd_transactionvin(coin,txid,j,spenttxid,spentvout) < 0 )
                                        {
                                            printf("error i.%d of numvins.%d (%s)\n",j,numvins,jprint(vin,0));
                                            flag++;
                                        }
                                        if ( coin->kmd_spendfp != 0 )
                                        {
                                            fwrite(&spenttxid,1,sizeof(spenttxid),coin->kmd_spendfp);
                                            fwrite(&spentvout,1,sizeof(spentvout),coin->kmd_spendfp);
                                            fflush(coin->kmd_spendfp);
                                        }
                                    }
                                }
                            } else printf("incomplete at ht.%d i.%d %p %p\n",loadheight,i,ptr,tx);
                            free_json(txjson);
                        } else printf("parseerror.(%s)\n",curlstr);
                        free(curlstr);
                    }
                }
                num++;
                kmd_flushfiles(coin);
            }
            free_json(blockjson);
        }
        if ( flag != 0 || num > 100 )
            break;
        coin->kmd_height = loadheight++;
    }
    return(num);
}

void kmd_bitcoinscan()
{
    char *retstr; cJSON *array; int32_t i,n; struct iguana_info *coin; // scan allcoins also
    if ( (retstr= dpow_notarychains(0,0,0,0)) != 0 )
    {
        if ( (array= cJSON_Parse(retstr)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (coin= iguana_coinfind(jstri(array,i))) != 0 && strcmp(coin->symbol,"BTC") != 0 )
                    {
                        //if ( strcmp("KMD",coin->symbol) == 0 )
                            _kmd_bitcoinscan(coin);
                        sleep(1);
                    }
                }
            }
            free_json(array);
        }
        free(retstr);
    }
}

#endif
