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

// verify undo cases for hhutxo, and all 4 permutations of setting

#include "iguana777.h"

//#define FAST_UTHASH
#ifdef FAST_UTHASH
#undef uthash_malloc
#undef uthash_free
#define uthash_malloc(size) ((coin->RTHASHMEM.ptr == 0) ? mycalloc('u',1,size) : iguana_memalloc(&coin->RTHASHMEM,size,1))
#define uthash_free(mem,size) ((coin->RTHASHMEM.ptr == 0) ? myfree(mem,size) : 0)
#endif

void iguana_RTtxid_free(struct iguana_RTtxid *RTptr)
{
    int32_t i; struct iguana_RTspend *spend;
    for (i=0; i<RTptr->numvouts; i++)
        if ( RTptr->unspents[i] != 0 )
            free(RTptr->unspents[i]);
    for (i=0; i<RTptr->numvins; i++)
    {
        if ( (spend= RTptr->spends[i]) != 0 )
        {
            if ( spend->bundle_unspent != 0 )
                free(spend->bundle_unspent);
            free(spend);
        }
    }
    if ( RTptr->rawtxbytes != 0 )
        free(RTptr->rawtxbytes);
    free(RTptr);
}

void iguana_RTdataset_free(struct iguana_info *coin)
{
    struct iguana_RTtxid *RTptr,*tmp; struct iguana_RTaddr *RTaddr,*tmp2;
    HASH_ITER(hh,coin->RTdataset,RTptr,tmp)
    {
        HASH_DELETE(hh,coin->RTdataset,RTptr);
        iguana_RTtxid_free(RTptr);
    }
    HASH_ITER(hh,coin->RTaddrs,RTaddr,tmp2)
    {
        HASH_DELETE(hh,coin->RTaddrs,RTaddr);
        free(RTaddr);
    }
    iguana_hhutxo_purge(coin);
    iguana_memreset(&coin->RTHASHMEM);
}

void iguana_RTreset(struct iguana_info *coin)
{
    iguana_utxoaddrs_purge(coin);
    //iguana_utxoupdate(coin,-1,0,0,0,0,-1,0); // free hashtables
    coin->lastRTheight = 0;
    iguana_RTdataset_free(coin);
#ifdef FAST_UTHASH
    if ( coin->RTHASHMEM.ptr == 0 )
        iguana_meminit(&coin->RTHASHMEM,"RTHASHMEM",0,1024*1024*1024,0);
    iguana_memreset(&coin->RTHASHMEM);
#endif
    printf("%s RTreset %d\n",coin->symbol,coin->RTheight);
    coin->RTheight = coin->firstRTheight;
    coin->RTcredits = coin->RTdebits = 0;
}

struct iguana_RTaddr *iguana_RTaddrfind(struct iguana_info *coin,uint8_t *rmd160,char *coinaddr)
{
    struct iguana_RTaddr *RTaddr; int32_t len; char _coinaddr[64];
    if ( coinaddr == 0 )
    {
        coinaddr = _coinaddr;
        bitcoin_address(coinaddr,coin->chain->pubtype,rmd160,20);
    }
    len = (int32_t)strlen(coinaddr);
    HASH_FIND(hh,coin->RTaddrs,coinaddr,len,RTaddr);
    return(RTaddr);
}

int64_t iguana_RTbalance(struct iguana_info *coin,char *coinaddr)
{
    struct iguana_RTaddr *RTaddr; uint8_t addrtype,rmd160[20]; int32_t len;
    len = (int32_t)strlen(coinaddr);
    HASH_FIND(hh,coin->RTaddrs,coinaddr,len,RTaddr);
    if ( RTaddr != 0 )
        return(RTaddr->credits - RTaddr->debits + RTaddr->histbalance);
    else
    {
        bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
        return(iguana_utxoaddrtablefind(coin,-1,-1,rmd160));
    }
}

int64_t iguana_RTnetbalance(struct iguana_info *coin)
{
    struct iguana_RTaddr *RTaddr,*tmp; int64_t RTdebits,RTcredits;
    RTdebits = RTcredits = 0;
    HASH_ITER(hh,coin->RTaddrs,RTaddr,tmp)
    {
        RTcredits += RTaddr->credits;
        RTdebits += RTaddr->debits;
    }
    if ( RTcredits != coin->RTcredits || RTdebits != coin->RTdebits )
        printf("RTnetbalance mismatch (%.8f %.8f) != (%.8f %.8f)\n",dstr(RTcredits),dstr(RTdebits),dstr(coin->RTcredits),dstr(coin->RTdebits));
    return(RTcredits - RTdebits);
}

int32_t iguana_RTbalance_verify(char *str,struct iguana_info *coin)
{
    int64_t balance;
    balance = iguana_RTnetbalance(coin);
    if ( balance != (coin->RTcredits - coin->RTdebits) )
    {
        printf("%s RTbalance %.8f != %.8f (%.8f - %.8f)\n",str,dstr(balance),dstr(coin->RTcredits - coin->RTdebits),dstr(coin->RTcredits),dstr(coin->RTdebits));
        return(-1);
    }
    return(0);
}

void iguana_RTcoinaddr(struct iguana_info *coin,struct iguana_RTtxid *RTptr,struct iguana_block *block,int64_t polarity,char *coinaddr,uint8_t *rmd160,int32_t spendflag,int64_t value,struct iguana_RTunspent *unspent)
{
    struct iguana_RTaddr *RTaddr; int32_t len = (int32_t)strlen(coinaddr);
    HASH_FIND(hh,coin->RTaddrs,coinaddr,len,RTaddr);
    if ( RTaddr == 0 )
    {
        RTaddr = calloc(1,sizeof(*RTaddr));
        strncpy(RTaddr->coinaddr,coinaddr,len);
        RTaddr->histbalance = iguana_utxoaddrtablefind(coin,-1,-1,rmd160);
        HASH_ADD_KEYPTR(hh,coin->RTaddrs,RTaddr->coinaddr,len,RTaddr);
    }
    if ( spendflag != 0 )
    {
        RTaddr->debits += polarity * value;
        coin->RTdebits += polarity * value;
    }
    else
    {
        RTaddr->credits += polarity * value;
        coin->RTcredits += polarity * value;
        if ( polarity > 0 )
        {
            //printf("%s lastunspent[%d] <- %p\n",coinaddr,RTaddr->numunspents,unspent);
            RTaddr->numunspents++;
            unspent->prevunspent = RTaddr->lastunspent;
            RTaddr->lastunspent = unspent;
        }
        else if ( polarity < 0 )
        {
            //printf("%s lastunspent[%d] -> last.%p %p\n",coinaddr,RTaddr->numunspents,RTaddr->lastunspent,unspent);
            if ( RTaddr->lastunspent == unspent )
            {
                RTaddr->lastunspent = unspent->prevunspent;
                free(unspent);
            } else printf("lastunspent.%p != %p\n",RTaddr->lastunspent,unspent);
            //RTaddr->unspents[i] = RTaddr->unspents[--RTaddr->numunspents];
        }
    }
    //printf("%s %.8f [%.8f - %.8f] -> %.8f\n",coinaddr,dstr(value),dstr(coin->RTcredits),dstr(coin->RTdebits),dstr(coin->histbalance)+dstr(coin->RTcredits)-dstr(coin->RTdebits));
    if ( (0) && strcmp("BTC",coin->symbol) != 0 && strcmp("LTC",coin->symbol) != 0 && strcmp("DOGE",coin->symbol) != 0 )
        printf("%lld %s %.8f h %.8f, cr %.8f deb %.8f [%.8f] numunspents.%d %p\n",(long long)polarity,coinaddr,dstr(value),dstr(RTaddr->histbalance),dstr(RTaddr->credits),dstr(RTaddr->debits),dstr(RTaddr->credits)-dstr(RTaddr->debits)+dstr(RTaddr->histbalance),RTaddr->numunspents,unspent);
}

struct iguana_RTunspent *iguana_RTunspent_create(uint8_t *rmd160,int64_t value,uint8_t *script,int32_t scriptlen,struct iguana_RTtxid *parent,int32_t vout)
{
    struct iguana_RTunspent *unspent;
    unspent = calloc(1,sizeof(*unspent) + scriptlen);
    unspent->value = value;
    if ( (unspent->parent= parent) != 0 )
        unspent->height = parent->height;
    else unspent->height = -1;
    unspent->vout = vout;
    unspent->scriptlen = scriptlen;
    memcpy(unspent->rmd160,rmd160,sizeof(unspent->rmd160));
    memcpy(unspent->script,script,scriptlen);
    return(unspent);
}

void iguana_RTunspent(struct iguana_info *coin,struct iguana_RTtxid *RTptr,struct iguana_block *block,int64_t polarity,char *coinaddr,uint8_t *rmd160,int32_t type,uint8_t *script,int32_t scriptlen,bits256 txid,int32_t vout,int64_t value)
{
    int32_t i; struct iguana_RTunspent *unspent; char str[65];
    //printf("iguana_RTunspent.%lld %s vout.%d %.8f\n",(long long)polarity,coinaddr,vout,dstr(value));
    //fprintf(stderr,"+");
    if ( RTptr != 0 )
    {
        if ( bits256_cmp(RTptr->txid,txid) == 0 )
        {
            if ( (unspent= RTptr->unspents[vout]) == 0 )
            {
                if ( polarity > 0 )
                {
                    unspent = iguana_RTunspent_create(rmd160,value,script,scriptlen>0?scriptlen:0,RTptr,vout);
                    RTptr->unspents[vout] = unspent;
                } else printf("iguana_RTunspent missing vout.%d ptr\n",vout);
            }
            else
            {
                if ( memcmp(rmd160,unspent->rmd160,sizeof(unspent->rmd160)) != 0 || value != unspent->value || scriptlen != unspent->scriptlen || memcmp(unspent->script,script,scriptlen) != 0 )
                {
                    printf("iguana_RTunspent.%d of %d mismatch %s\n",vout,RTptr->numvouts,bits256_str(str,RTptr->txid));
                    return;
                }
            }
            iguana_RTcoinaddr(coin,RTptr,block,polarity,coinaddr,unspent->rmd160,0,value,unspent);
            if ( polarity < 0 )
                RTptr->unspents[vout] = 0;
        } else printf("iguana_RTunspent txid mismatch %llx != %llx\n",(long long)RTptr->txid.txid,(long long)txid.txid);
    }
    else
    {
        for (i=0; i<20; i++)
            printf("%02x",rmd160[i]);
        printf(" %s vout.%d %.8f %lld\n",coinaddr,vout,dstr(value),(long long)polarity);
    }
    //fprintf(stderr,",");
}

void iguana_RTvout_create(struct iguana_info *coin,int64_t polarity,struct iguana_RTtxid *RTptr,struct iguana_block *block,bits256 txid,int32_t j,struct iguana_msgvout *vout)
{
    int32_t scriptlen,type,k; uint8_t *script; struct vin_info V; char coinaddr[64];
    script = vout->pk_script;
    scriptlen = vout->pk_scriptlen;
    type = iguana_calcrmd160(coin,0,&V,script,scriptlen,txid,j,0xffffffff);
    if ( (type == 12 && scriptlen == 0) || (type == 1 && bitcoin_pubkeylen(script+1) <= 0) )
    {
        for (k=0; k<scriptlen; k++)
            printf("%02x",script[k]);
        printf(" script type.%d scriptlen.%d\n",type,scriptlen);
    }
    bitcoin_address(coinaddr,coin->chain->pubtype,V.rmd160,sizeof(V.rmd160));
    iguana_RTunspent(coin,RTptr,block,polarity,coinaddr,V.rmd160,type,script,scriptlen,txid,j,vout->value);
}

void iguana_RTspend_create(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_RTtxid *RTptr,struct iguana_block *block,int64_t polarity,uint8_t *script,int32_t scriptlen,bits256 txid,int32_t vini,bits256 prev_hash,int32_t prev_vout)
{
    struct iguana_RTspend *spend; struct iguana_RTtxid *spentRTptr; struct iguana_RTunspent *unspent=0; char str[65],str2[65],coinaddr[64]; uint8_t addrtype,rmd160[20],spendscript[IGUANA_MAXSCRIPTSIZE]; uint32_t unspentind; int32_t spendlen,height; uint64_t RTspent,value; struct iguana_outpoint spentpt;
    //printf("RTspend %s vini.%d spend.(%s/v%d) %lld\n",bits256_str(str,txid),vini,bits256_str(str2,prev_hash),prev_vout,(long long)polarity);
    if ( vini == 0 && bits256_nonz(prev_hash) == 0 && prev_vout < 0 )
        return;
    //fprintf(stderr,"-");
    if ( RTptr != 0 )
    {
        if ( bits256_cmp(RTptr->txid,txid) == 0 )
        {
            if ( (spend= RTptr->spends[vini]) == 0 )
            {
                if ( polarity > 0 )
                {
                    spend = calloc(1,sizeof(*spend) + scriptlen);
                    spend->prev_hash = prev_hash;
                    spend->prev_vout = prev_vout;
                    spend->scriptlen = scriptlen;
                    memcpy(spend->vinscript,script,scriptlen);
                    RTptr->spends[vini] = spend;
                } else printf("iguana_RTspend missing vini.%d ptr\n",vini);
            }
            else
            {
                if ( bits256_cmp(prev_hash,spend->prev_hash) != 0 || prev_vout != spend->prev_vout || scriptlen != spend->scriptlen || memcmp(spend->vinscript,script,scriptlen) != 0 )
                {
                    printf("RTspend.%d of %d mismatch %s\n",vini,RTptr->numvins,bits256_str(str,RTptr->txid));
                    return;
                }
            }
            if ( bits256_nonz(prev_hash) != 0 && prev_vout >= 0 )
            {
                HASH_FIND(hh,coin->RTdataset,prev_hash.bytes,sizeof(prev_hash),spentRTptr);
                if ( spentRTptr != 0 )
                {
                    if ( (unspent= spentRTptr->unspents[prev_vout]) == 0 )
                    {
                        printf("iguana_RTspend null unspent.(%s).%d\n",bits256_str(str,prev_hash),prev_vout);
                    }
                }
                else
                {
                    if ( (unspentind= iguana_unspentindfind(myinfo,coin,&RTspent,coinaddr,spendscript,&spendlen,&value,&height,prev_hash,prev_vout,coin->bundlescount,0)) == 0 )
                        printf("iguana_RTspend cant find spentRTptr.(%s) search history\n",bits256_str(str,prev_hash));
                    else
                    {
                        int32_t spentheight,lockedflag,RTspentflag;
                        bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
                        unspent = iguana_RTunspent_create(rmd160,value,spendscript,spendlen>0?spendlen:0,0,prev_vout);
                        memset(&spentpt,0,sizeof(spentpt));
                        spentpt.txid = prev_hash;
                        spentpt.vout = prev_vout;
                        spentpt.unspentind = unspentind;
                        spentpt.hdrsi = height / coin->chain->bundlesize;
                        spentpt.value = value;
                        iguana_RTutxofunc(coin,&spentheight,&lockedflag,spentpt,&RTspentflag,0,RTptr->height);
                        spend->bundle_unspent = unspent;
                    }
                }
                if ( unspent != 0 )
                {
                    if ( polarity < 0 )
                        unspent->spend = 0;
                    bitcoin_address(coinaddr,coin->chain->pubtype,unspent->rmd160,sizeof(unspent->rmd160));
                    iguana_RTcoinaddr(coin,RTptr,block,polarity,coinaddr,unspent->rmd160,1,unspent->value,unspent);
                    if ( polarity > 0 )
                        unspent->spend = spend;
                }
            }
        } else printf("iguana_RTspend txid mismatch %llx != %llx\n",(long long)RTptr->txid.txid,(long long)txid.txid);
    } else printf("null rtptr? %s vini.%d spend.(%s/v%d) %lld\n",bits256_str(str,txid),vini,bits256_str(str2,prev_hash),prev_vout,(long long)polarity);
    //fprintf(stderr,",");
}

struct iguana_RTtxid *iguana_RTtxid_create(struct iguana_info *coin,struct iguana_block *block,int64_t polarity,int32_t txi,int32_t txn_count,bits256 txid,int32_t numvouts,int32_t numvins,uint32_t locktime,uint32_t version,uint32_t timestamp,uint8_t *serialized,int32_t txlen)
{
    struct iguana_RTtxid *RTptr; char str[65];
    if ( block == 0 || block->height < coin->firstRTheight || block->height >= coin->firstRTheight+sizeof(coin->RTblocks)/sizeof(*coin->RTblocks) )
    {
        printf("iguana_RTtxid_create: illegal block height.%d\n",block!=0?block->height:-1);
        return(0);
    }
    //fprintf(stderr,"t");
    HASH_FIND(hh,coin->RTdataset,txid.bytes,sizeof(txid),RTptr);
    if ( RTptr == 0 )
    {
        RTptr = calloc(1,sizeof(*RTptr) + sizeof(void *)*numvins + sizeof(void *)*numvouts);
        RTptr->txi = txi, RTptr->txn_count = txn_count;
        RTptr->coin = coin;
        RTptr->block = block;
        RTptr->height = block->height;
        RTptr->txid = txid;
        RTptr->txn_count = txn_count;
        RTptr->numvouts = numvouts;
        RTptr->numvins = numvins;
        RTptr->locktime = locktime;
        RTptr->version = version;
        RTptr->timestamp = timestamp;
        RTptr->unspents = (void *)&RTptr->spends[numvins];
        if ( txlen > 0 && txlen < IGUANA_MAXPACKETSIZE )
        {
            RTptr->rawtxbytes = malloc(txlen);
            RTptr->txlen = txlen;
            memcpy(RTptr->rawtxbytes,serialized,txlen);
        }
        HASH_ADD_KEYPTR(hh,coin->RTdataset,RTptr->txid.bytes,sizeof(RTptr->txid),RTptr);
        bits256_str(str,txid);
        if ( (0) && strcmp("BTC",coin->symbol) != 0 )
            printf("%s.%d txid.(%s) vouts.%d vins.%d version.%d lock.%u t.%u %lld\n",coin->symbol,block->height,str,numvouts,numvins,version,locktime,timestamp,(long long)polarity);
    }
    else if ( RTptr->txn_count != txn_count || RTptr->numvouts != numvouts || RTptr->numvins != numvins )
    {
        printf("%s inconsistent counts.(%d %d %d) vs (%d %d %d)\n",bits256_str(str,txid),RTptr->txn_count,RTptr->numvouts,RTptr->numvins,txn_count,numvouts,numvins);
        return(0);
    }
    //fprintf(stderr," %d ",txi);
    //if ( txi == txn_count-1 )
    //    fprintf(stderr," ht.%d\n",block->height);
    return(RTptr);
}

int32_t iguana_RTramchaindata(struct supernet_info *myinfo,struct iguana_info *coin,int64_t polarity,struct iguana_block *block,struct iguana_msgtx *txarray,int32_t txn_count)
{
    struct iguana_msgtx *tx; struct iguana_RTtxid *RTptr; int32_t i,j;
    if ( block->RO.txn_count != txn_count )
    {
        printf("txn_count mismatch ht.%d %d != %d\n",block->height,block->RO.txn_count,txn_count);
        return(-1);
    }
    if ( polarity > 0 )
    {
        for (i=0; i<txn_count; i++)
        {
            tx = &txarray[i];
            RTptr = iguana_RTtxid_create(coin,block,polarity,i,txn_count,tx->txid,tx->tx_out,tx->tx_in,tx->lock_time,tx->version,tx->timestamp,tx->serialized,tx->allocsize);
            for (j=0; j<tx->tx_out; j++)
                iguana_RTvout_create(coin,polarity,RTptr,block,tx->txid,j,&tx->vouts[j]);
            for (j=0; j<tx->tx_in; j++)
                iguana_RTspend_create(myinfo,coin,RTptr,block,polarity,tx->vins[j].vinscript,tx->vins[j].scriptlen,tx->txid,j,tx->vins[j].prev_hash,tx->vins[j].prev_vout);
        }
    }
    else
    {
        for (i=txn_count-1; i>=0; i--)
        {
            tx = &txarray[i];
            RTptr = iguana_RTtxid_create(coin,block,polarity,i,txn_count,tx->txid,tx->tx_out,tx->tx_in,tx->lock_time,tx->version,tx->timestamp,tx->serialized,tx->allocsize);
            for (j=tx->tx_in-1; j>=0; j--)
            {
                iguana_RTspend_create(myinfo,coin,RTptr,block,polarity,tx->vins[j].vinscript,tx->vins[j].scriptlen,tx->txid,j,tx->vins[j].prev_hash,tx->vins[j].prev_vout);
            }
            for (j=tx->tx_out-1; j>=0; j--)
                iguana_RTvout_create(coin,polarity,RTptr,block,tx->txid,j,&tx->vouts[j]);
        }
    }
    return(0);
}

int64_t _RTgettxout(struct iguana_info *coin,struct iguana_RTtxid **ptrp,int32_t *heightp,int32_t *scriptlenp,uint8_t *script,uint8_t *rmd160,char *coinaddr,bits256 txid,int32_t vout,int32_t mempool)
{
    int32_t scriptlen; int64_t value = 0; struct iguana_RTtxid *RTptr; struct iguana_RTunspent *unspent = 0;
    HASH_FIND(hh,coin->RTdataset,txid.bytes,sizeof(txid),RTptr);
    *ptrp = RTptr;
    *heightp = -1;
    if ( scriptlenp == 0 )
        scriptlenp = &scriptlen;
    *scriptlenp = 0;
    memset(rmd160,0,20);
    coinaddr[0] = 0;
    if ( RTptr != 0 )// && (RTptr->height <= coin->blocks.hwmchain.height || mempool != 0) )
    {
        if ( vout >= 0 && vout < RTptr->txn_count && (unspent= RTptr->unspents[vout]) != 0 )
        {
            *heightp = RTptr->height;
            if ( script != 0 && unspent->spend == 0 && (*scriptlenp= unspent->scriptlen) > 0 )
                memcpy(script,unspent->script,*scriptlenp);
            memcpy(rmd160,unspent->rmd160,sizeof(unspent->rmd160));
            bitcoin_address(coinaddr,coin->chain->pubtype,rmd160,sizeof(unspent->rmd160));
            value = unspent->value;
        } else printf("vout.%d error %p\n",vout,unspent);
    }
    return(value);
}

int32_t _iguana_RTunspentfind(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *txidp,int32_t *voutp,uint8_t *spendscript,struct iguana_outpoint outpt,int64_t value)
{
    int32_t spendlen = 0; struct iguana_RTunspent *unspent; struct iguana_RTtxid *parent;
    if ( outpt.isptr != 0 && (unspent= outpt.ptr) != 0 && (parent= unspent->parent) != 0 )
    {
        if ( value != unspent->value )
            printf("_iguana_RTunspentfind: mismatched value %.8f != %.8f\n",dstr(value),dstr(unspent->value));
        if ( (spendlen= unspent->scriptlen) > 0 )
            memcpy(spendscript,unspent->script,spendlen);
        *txidp = parent->txid;
        *voutp = unspent->vout;
    }
    return(spendlen);
}

int32_t iguana_RTunspentindfind(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_outpoint *outpt,char *coinaddr,uint8_t *spendscript,int32_t *spendlenp,uint64_t *valuep,int32_t *heightp,bits256 txid,int32_t vout,int32_t lasthdrsi,int32_t mempool)
{
    char _coinaddr[64]; struct iguana_RTtxid *ptr; uint8_t rmd160[20]; uint64_t value,RTspend; uint32_t unspentind;
    if ( coinaddr == 0 )
        coinaddr = _coinaddr;
    memset(outpt,0,sizeof(*outpt));
    if ( (value= _RTgettxout(coin,&ptr,heightp,spendlenp,spendscript,rmd160,coinaddr,txid,vout,mempool)) > 0 )
    {
        outpt->ptr = ptr;
        if ( valuep != 0 )
        {
            *valuep = value;
            outpt->value = *valuep;
        }
        return(0);
    }
    else
    {
        if ( (unspentind= iguana_unspentindfind(myinfo,coin,&RTspend,coinaddr,spendscript,spendlenp,valuep,heightp,txid,vout,lasthdrsi,mempool)) != 0 )
        {
            char str[65];
            if ( unspentind == 0xffffffff )
                printf("neg 1 unspentind? %s/v%d\n",bits256_str(str,txid),vout);
            if ( valuep != 0 && *valuep == 0 )
                *valuep = RTspend;
            outpt->hdrsi = *heightp / coin->chain->bundlesize;
            outpt->unspentind = unspentind;
            if ( valuep != 0 )
                outpt->value = *valuep;
            return(0);
        }
        return(-1);
    }
}

int32_t iguana_outptset(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_outpoint *outpt,bits256 txid,int32_t vout,int64_t value,char *spendscriptstr)
{
    int32_t spendlen;
    memset(outpt,0,sizeof(*outpt));
    spendlen = (int32_t)strlen(spendscriptstr) >> 1;
    if ( spendlen > sizeof(outpt->spendscript) )
        return(-1);
    outpt->spendlen = spendlen;
    decode_hex(outpt->spendscript,spendlen,spendscriptstr);
    outpt->txid = txid;
    outpt->vout = vout;
    outpt->value = value;
    return(0);
}

int32_t iguana_txidheight(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid)
{
    struct iguana_outpoint outpt; int32_t spendlen,height = 0; uint64_t value; char coinaddr[64]; uint8_t spendscript[IGUANA_MAXSCRIPTSIZE];
    iguana_RTunspentindfind(myinfo,coin,&outpt,coinaddr,spendscript,&spendlen,&value,&height,txid,0,(coin->firstRTheight/coin->chain->bundlesize) - 1,0);
    return(height);
}

int64_t iguana_txidamount(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,bits256 txid,int32_t vout)
{
    struct iguana_outpoint outpt; int32_t spendlen,height = 0; uint64_t value; uint8_t spendscript[IGUANA_MAXSCRIPTSIZE];
    iguana_RTunspentindfind(myinfo,coin,&outpt,coinaddr,spendscript,&spendlen,&value,&height,txid,vout,(coin->firstRTheight/coin->chain->bundlesize) - 1,0);
    return(value);
}

char *iguana_txidcategory(struct supernet_info *myinfo,struct iguana_info *coin,char *account,char *coinaddr,bits256 txid,int32_t vout)
{
    struct iguana_outpoint outpt; struct iguana_waccount *wacct; struct iguana_waddress *waddr; int32_t ismine=0,spendlen,height = 0; uint64_t value; uint8_t spendscript[IGUANA_MAXSCRIPTSIZE];
    coinaddr[0] = 0;
    iguana_RTunspentindfind(myinfo,coin,&outpt,coinaddr,spendscript,&spendlen,&value,&height,txid,vout,(coin->firstRTheight/coin->chain->bundlesize) - 1,0);
    account[0] = 0;
    if ( coinaddr[0] != 0 )
    {
        if ( (waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) != 0 )
        {
            if ( waddr->scriptlen != 0 )
                return("isp2sh");
            else if ( waddr->wifstr[0] != 0 )
                ismine = 1;
            if ( wacct != 0 )
                strcpy(account,wacct->account);
        }
    } else account[0] = 0;
    if ( value != 0 )
    {
        if ( spendlen == 0 )
        {
            if ( ismine != 0 )
                return("send");
            else return("spent");
        }
        else
        {
            if ( ismine != 0 )
                return("receive");
            else return("unspent");
        }
    } else return("unknown");
}

int32_t iguana_scriptsigextract(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t *script,int32_t maxsize,bits256 txid,int32_t vini)
{
    return(-1);
}

int32_t iguana_vinifind(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *spentfrom,bits256 txid,int32_t vout)
{
    int32_t vini = -1; //char *txbytes; char str[65]; cJSON *txobj;
    memset(spentfrom,0,sizeof(*spentfrom));
    /*if ( (txbytes= iguana_txbytes(myinfo,swap->bobcoin,txid)) != 0 )
    {
        if ( (txobj= iguana_hex2json(myinfo,swap->bobcoin,txbytes)) != 0 )
        {
            if ( (vins= jarray(&n,txobj,"vins")) != 0 && vini < n )
            {
                
            } else printf("iguana_vinifind no vins.%p or illegal vini.%d vs n.%d\n",txobj,vini,n);
            free_json(txobj);
        } else printf("iguana_vinifind couldnt parse %s.(%s)\n",swap->bobcoin->symbol,txbytes);
        free(txbytes);
    } else printf("iguana_vinifind cant get txbytes for %s.(%s)\n",swap->bobcoin->symbol,bits256_str(str,txid));*/
    return(vini);
}

void iguana_RTunmap(uint8_t *ptr,uint32_t len)
{
    OS_releasemap(&ptr[-2*sizeof(len)],len+2*sizeof(len));
}

void *iguana_RTrawdata(struct iguana_info *coin,bits256 hash2,uint8_t *data,int32_t *recvlenp,int32_t *numtxp,int32_t checkonly)
{
    FILE *fp; char fname[1024],str[65]; long filesize; int32_t len; uint8_t *ptr; uint32_t i,nonz,checknumtx,checklen;
    sprintf(fname,"%s/%s/RT/%s.raw",GLOBAL_TMPDIR,coin->symbol,bits256_str(str,hash2));
    OS_compatible_path(fname);
    if ( *recvlenp == -1 )
        OS_removefile(fname,0);
    else
    {
        if ( (checkonly != 0 || *recvlenp > 0) && (fp= fopen(fname,"rb")) != 0 )
        {
            fseek(fp,0,SEEK_END);
            filesize = ftell(fp);
            rewind(fp);
            if ( fread(&len,1,sizeof(len),fp) == sizeof(len) && len == filesize-sizeof(int32_t)*2 )
            {
                fclose(fp);
                //printf("already have %s\n",bits256_str(str,hash2));
                *recvlenp = 0;
                if ( checkonly != 0 )
                    return((void *)"already have rawdata");
                return(0);
            }
            printf("malformed delete.(%s) len.%d filesize.%ld\n",fname,len,filesize);
            fclose(fp);
            OS_removefile(fname,0);
        }
        else if ( checkonly == 0 )
        {
            if ( *recvlenp > 0 )
            {
                if ( coin->RTheight == 0 && coin->blocks.hwmchain.height < coin->longestchain-coin->chain->bundlesize && iguana_utxofinished(coin) < coin->bundlescount-3 )
                {
                    //printf("skip %s\n",bits256_str(str,hash2));
                    return(0);
                }
                if ( (fp= fopen(fname,"wb")) != 0 )
                {
                    if ( fwrite(recvlenp,1,sizeof(*recvlenp),fp) != sizeof(*recvlenp) || fwrite(numtxp,1,sizeof(*numtxp),fp) != sizeof(*numtxp) || fwrite(data,1,*recvlenp,fp) != *recvlenp )
                        printf("error writing %s len.%d numtx.%d\n",bits256_str(str,hash2),*recvlenp,*numtxp);
                    fclose(fp);
                    //printf("numtx.%d len.%d %s hwm.%d L.%d\n",*numtxp,*recvlenp,fname,coin->blocks.hwmchain.height,coin->longestchain);
                } else printf("couldnt create %s\n",fname);
            }
            else if ( (ptr= OS_mapfile(fname,&filesize,0)) != 0 )
            {
                memcpy(&checklen,ptr,sizeof(checklen));
                memcpy(&checknumtx,&ptr[sizeof(checklen)],sizeof(checknumtx));
                *numtxp = checknumtx;
                if ( checklen == (int32_t)(filesize - sizeof(checklen) - sizeof(checknumtx)) )//&& checknumtx == *numtxp )
                {
                    for (i=nonz=0; i<checklen; i++)
                        if ( ptr[2*sizeof(checklen) + i] != 0 )
                            nonz++;
                    *recvlenp = (int32_t)(filesize - sizeof(checklen) - sizeof(checknumtx));
                    return(&ptr[sizeof(*recvlenp) + sizeof(checknumtx)]);
                } else printf("checklen.%d vs %d, checknumtx %d vs %d\n",checklen,(int32_t)(filesize - sizeof(checklen) - sizeof(checknumtx)),checknumtx,*numtxp);
            }
            else if ( (0) )
            {
                OS_removefile(fname,0);
                printf("(%s) removed to suppress errors\n",fname);
            }
        }
    }
    return(0);
}

void iguana_RTpurge(struct iguana_info *coin,int32_t lastheight)
{
    int32_t hdrsi,bundlei,height,numtx=0,recvlen=-1,width=50000; struct iguana_bundle *bp;
    printf("start RTpurge from %d\n",lastheight - width);
    for (height=lastheight-width; height<lastheight; height++)
    {
        if ( height < 0 )
            height = 0;
        hdrsi = (height / coin->chain->bundlesize);
        bundlei = (height % coin->chain->bundlesize);
        if ( (bp= coin->bundles[hdrsi]) != 0 && bits256_nonz(bp->hashes[bundlei]) != 0 )
            iguana_RTrawdata(coin,bp->hashes[bundlei],0,&recvlen,&numtx,0); // delete file
    }
    printf("end %s RTpurge.%d\n",coin->symbol,lastheight);
}

int32_t iguana_RTiterate(struct supernet_info *myinfo,struct iguana_info *coin,int32_t offset,struct iguana_block *block,int64_t polarity)
{
    struct iguana_txblock txdata; uint8_t *serialized; struct iguana_bundle *bp; int32_t hdrsi,bundlei,height,i,n,numtx,num,len; int32_t recvlen = 0;
    if ( (numtx= coin->RTnumtx[offset]) == 0 || (serialized= coin->RTrawdata[offset]) == 0 || (recvlen= coin->RTrecvlens[offset]) == 0 )
    {
        //char str[65];
        //printf("errs.%d cant load %s ht.%d polarity.%lld numtx.%d %p recvlen.%d\n",errs,bits256_str(str,block->RO.hash2),block->height,(long long)polarity,coin->RTnumtx[offset],coin->RTrawdata[offset],coin->RTrecvlens[offset]);
        coin->RTrecvlens[offset] = 0;
        coin->RTrawdata[offset] = iguana_RTrawdata(coin,block->RO.hash2,0,&coin->RTrecvlens[offset],&coin->RTnumtx[offset],0);
        if ( (numtx= coin->RTnumtx[offset]) == 0 || (serialized= coin->RTrawdata[offset]) == 0 || (recvlen= coin->RTrecvlens[offset]) == 0 )
        {
            //char str[65]; printf("%s cant load %s ht.%d polarity.%lld numtx.%d %p recvlen.%d\n",coin->symbol,bits256_str(str,block->RO.hash2),block->height,(long long)polarity,coin->RTnumtx[offset],coin->RTrawdata[offset],coin->RTrecvlens[offset]);
            struct iguana_peer *addr; // int32_t errs = 0;
            iguana_blockhashset("RTblock",coin,coin->firstRTheight+offset,block->RO.hash2,1);
            if ( (bp= coin->bundles[block->hdrsi]) != 0 )
            {
                bp->issued[block->bundlei] = 0;
                bp->blocks[block->bundlei] = block;
                bp->hashes[block->bundlei] = block->RO.hash2;
                block->height = coin->firstRTheight+offset;
                if ( coin->peers != 0 )
                {
                    if ( coin->peers->numranked > 0 )
                    {
                        for (i=0; i<coin->peers->numranked&&i<8; i++)
                            if ( (addr= coin->peers->ranked[i]) != 0 )
                            {
                                iguana_sendblockreqPT(coin,addr,coin->bundles[block->hdrsi],block->bundlei,block->RO.hash2,1);
                            }
                    } else iguana_updatemetrics(myinfo,coin);
                }
            }
            iguana_blockQ("RTiterate",coin,bp,block->bundlei,block->RO.hash2,1);
            num = 0;
            for (height=block->height+1; height<=coin->blocks.hwmchain.height; height++)
            {
                hdrsi = (height / coin->chain->bundlesize);
                bundlei = (height % coin->chain->bundlesize);
                if ( (bp= coin->bundles[hdrsi]) != 0 && (block= bp->blocks[bundlei]) != 0 )
                {
                    recvlen = 0;
                    if ( iguana_RTrawdata(coin,block->RO.hash2,0,&recvlen,&numtx,0) == 0 )
                    {
                        num++;
                        iguana_blockQ("RTiterate",coin,0,-1,block->RO.hash2,1);
                        if ( (0) && coin->peers != 0 && (n= coin->peers->numranked) > 0 )
                        {
                            if ( (addr= coin->peers->ranked[rand() % n]) != 0 )
                                iguana_sendblockreqPT(coin,addr,0,-1,block->RO.hash2,1);
                        }
                    }
                }
            }
            //printf("issue missing %d to ht.%d\n",num,height);
            return(-1);
        }
    }
    char str[65];
    if ( block->height > coin->maxRTheight )
    {
        coin->maxRTheight = block->height;
        printf("%s.%d %.8f [%.8f %.8f] RTiterate.%lld %d tx.%d len.%d %s\n",coin->symbol,block->height,dstr(coin->histbalance)+dstr(coin->RTcredits)-dstr(coin->RTdebits),dstr(coin->RTcredits),dstr(coin->RTdebits),(long long)polarity,offset,coin->RTnumtx[offset],coin->RTrecvlens[offset],bits256_str(str,block->RO.hash2));
    }
    if ( coin->RTrawmem.ptr == 0 )
        iguana_meminit(&coin->RTrawmem,"RTrawmem",0,IGUANA_MAXPACKETSIZE * 2,0);
    memset(&txdata,0,sizeof(txdata));
    iguana_memreset(&coin->RTrawmem);
    if ( (n= iguana_gentxarray(myinfo,coin,&coin->RTrawmem,&txdata,&len,serialized,recvlen)) > 0 )
    {
        iguana_RTramchaindata(myinfo,coin,polarity,block,coin->RTrawmem.ptr,numtx);
        return(0);
    } else printf("gentxarray n.%d RO.txn_count.%d recvlen.%d\n",n,numtx,recvlen);
    iguana_RTreset(coin);
    return(-1);
}

struct iguana_block *iguana_RTblock(struct iguana_info *coin,int32_t height)
{
    int32_t offset; struct iguana_block *block;
    offset = height - coin->firstRTheight;
    //printf("%s iguana_RTblock.%d offset.%d\n",coin->symbol,height,offset);
    if ( offset < sizeof(coin->RTblocks)/sizeof(*coin->RTblocks) )
    {
        if ( (block= coin->RTblocks[offset]) != 0 )
        {
            if ( block->height != coin->firstRTheight+offset )
            {
                printf("block height mismatch patch %d != %d\n",block->height,coin->firstRTheight+offset);
                block->height = coin->firstRTheight+offset;
            }
            return(block);
        }
    }
    else printf("RTblock offset.%d too big\n",offset);
    return(0);
}

int32_t iguana_RTblockadd(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_block *block)
{
    int32_t offset;
    if ( block != 0 )
    {
        offset = block->height - coin->firstRTheight;
        if ( coin->RTrawdata[offset] == 0 )
            coin->RTrawdata[offset] = iguana_RTrawdata(coin,block->RO.hash2,0,&coin->RTrecvlens[offset],&coin->RTnumtx[offset],0);
        //printf("%s RTblockadd.%d offset.%d numtx.%d len.%d\n",coin->symbol,block->height,offset,coin->RTnumtx[offset],coin->RTrecvlens[offset]);
        block->RO.txn_count = coin->RTnumtx[offset];
        coin->RTblocks[offset] = block;
        if ( iguana_RTiterate(myinfo,coin,offset,block,1) < 0 )
            return(-1);
    }
    return(0);
}

int32_t iguana_RTblocksub(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_block *block)
{
    int32_t offset;
    if ( block != 0 )
    {
        offset = block->height - coin->firstRTheight;
        block->RO.txn_count = coin->RTnumtx[offset];
        printf("%s RTblocksub.%d offset.%d\n",coin->symbol,block->height,offset);
        if ( iguana_RTiterate(myinfo,coin,offset,block,-1) < 0 )
            return(-1);
        if ( coin->RTrawdata[offset] != 0 && coin->RTrecvlens[offset] != 0 )
            iguana_RTunmap(coin->RTrawdata[offset],coin->RTrecvlens[offset]);
        coin->RTrawdata[offset] = 0;
        coin->RTrecvlens[offset] = 0;
        coin->RTnumtx[offset] = 0;
        coin->RTblocks[offset] = 0;
    }
    return(0);
}

void iguana_RTnewblock(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_block *block)
{
    int32_t i,n,height,hdrsi,bundlei; struct iguana_block *addblock=0,*subblock=0; struct iguana_bundle *bp;
    if ( coin->RTreset_needed != 0 )
    {
        printf("RTreset_needed -> RTreset\n");
        iguana_RTreset(coin);
        coin->RTreset_needed = 0;
    }
    iguana_RTbalance_verify("start iterate",coin);
    /*if ( strcmp(coin->symbol,"BTC") != 0 && strcmp(coin->symbol,"LTC") != 0 )
     {
     if ( block->height < coin->firstRTheight+coin->minconfirms )
     return;
     if ( (block= iguana_blockfind("RTnew",coin,iguana_blockhash(coin,block->height-coin->minconfirms))) == 0 )
     return;
     }*/
    if ( block->height < coin->firstRTheight || block->height >= coin->firstRTheight+sizeof(coin->RTblocks)/sizeof(*coin->RTblocks) )
    {
        if ( (0) && coin->firstRTheight > 0 )
            printf("iguana_RTnewblock illegal blockheight.%d\n",block->height);
        return;
    }
    if ( block != 0 && coin->RTheight > 0 && coin->utxoaddrtable != 0 )//&& coin->RTheight <= coin->blocks.hwmchain.height )
    {
        /*if ( block->height < (coin->RTheight - coin->minconfirms) )
        {
            printf("ht.%d > RT.%d - %d\n",block->height,coin->RTheight,coin->minconfirms);
            return;
        }*/
        if ( (block= iguana_blockfind("RTnew",coin,iguana_blockhash(coin,block->height-coin->minconfirms+1))) == 0 )
            return;
        // error check to bundle boundary
        portable_mutex_lock(&coin->RTmutex);
        if ( block->height > coin->lastRTheight )
        {
            n = (block->height - coin->RTheight) + 1;
            for (i=0; i<n; i++)
            {
                height = (coin->RTheight + i);
                hdrsi = (height / coin->chain->bundlesize);
                bundlei = (height % coin->chain->bundlesize);
                if ( (bp= coin->bundles[hdrsi]) != 0 && (addblock= bp->blocks[bundlei]) != 0 && addblock->height == coin->RTheight+i )
                {
                    if ( iguana_RTblockadd(myinfo,coin,addblock) < 0 )
                        break;
                    //if ( iguana_RTblocksub(myinfo,coin,addblock) < 0 )
                    //    break;
                    //if ( iguana_RTblockadd(myinfo,coin,addblock) < 0 )
                    //    break;
                    coin->lastRTheight = addblock->height;
                }
                else
                {
                    char str[65];
                    if ( addblock != 0 )
                        bits256_str(str,addblock->RO.hash2);
                    else str[0] = 0;
                    printf("mismatched RTaddblock at i.%d RTheight.%d vs %p %d %s\n",i,coin->RTheight,addblock,addblock!=0?addblock->height:-1,str);
                    iguana_blockunmark(coin,addblock,bp,bundlei,0);
                    break;
                }
            }
            coin->RTheight += i;
            //if ( coin->RTheight != coin->lastRTheight+1 )
            //    printf("ERROR: ");
            //printf("%s >= RTnewblock RTheight %d prev %d\n",coin->symbol,coin->RTheight,coin->lastRTheight);
        }
        else if ( block->height == coin->lastRTheight )
        {
            if ( (subblock= iguana_RTblock(coin,block->height)) != 0 && subblock != block )
            {
                if ( iguana_RTblocksub(myinfo,coin,subblock) < 0 || iguana_RTblockadd(myinfo,coin,block) < 0 )
                {
                    printf("error unwinding to current %d\n",coin->RTheight);
                    portable_mutex_unlock(&coin->RTmutex);
                    return;
                }
                printf("%s == RTnewblock RTheight %d prev %d\n",coin->symbol,coin->RTheight,coin->lastRTheight);
            }
        }
        else
        {
            char str[65]; printf("reorg RTheight.%d vs block.%d %s\n",coin->RTheight,block->height,bits256_str(str,block->RO.hash2));
            iguana_RTreset(coin);
            /*while ( coin->RTheight > block->height )
             {
             if ( iguana_RTblocksub(myinfo,coin,iguana_RTblock(coin,coin->RTheight-1)) < 0 )
             {
             printf("error subtracting %d\n",coin->RTheight-1);
             coin->lastRTheight = coin->RTheight-1;
             portable_mutex_unlock(&coin->RTmutex);
             return;
             }
             coin->RTheight--;
             }
             if ( iguana_RTblockadd(myinfo,coin,block) < 0 )
             {
             printf("error adding %d\n",block->height);
             portable_mutex_unlock(&coin->RTmutex);
             return;
             }
             coin->lastRTheight = block->height;
             coin->RTheight = coin->lastRTheight+1;*/
        }
        portable_mutex_unlock(&coin->RTmutex);
    }
    iguana_RTbalance_verify("end iterate",coin);
}
