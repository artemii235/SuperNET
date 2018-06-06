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

// included from gecko.c

uint32_t gecko_earliest_blocktime(int32_t estblocktime,uint32_t prevtimestamp)
{
    uint32_t timestamp,now = (uint32_t)time(NULL);
    if ( prevtimestamp == 0 )
        prevtimestamp = now;
    timestamp = (prevtimestamp + ((estblocktime << 1) / 3));
    if ( timestamp <= prevtimestamp )
        timestamp = prevtimestamp + 1;
    return(timestamp);
}

int32_t gecko_blocknonce_verify(struct iguana_info *virt,uint8_t *serialized,int32_t datalen,uint32_t nBits,uint32_t timestamp,uint32_t prevtimestamp)
{
    bits256 threshold,hash2;
    //printf("time.%u prev.%u\n",timestamp,prevtimestamp);
    if ( timestamp != 0 && prevtimestamp != 0 )
    {
        if ( prevtimestamp != 0 && timestamp < gecko_earliest_blocktime(virt->chain->estblocktime,prevtimestamp)  )
        {
            printf("reject timestamp prev.%u %u earliest.%u\n",prevtimestamp,timestamp,gecko_earliest_blocktime(virt->chain->estblocktime,prevtimestamp));
            return(-1);
        }
        if ( timestamp > time(NULL) + GECKO_MAXFUTUREBLOCK )
        {
            printf("reject future timestamp.%u vs %u\n",timestamp,(uint32_t)time(NULL));
            return(-1);
        }
    }
    if ( nBits >= GECKO_EASIESTDIFF )
        nBits = GECKO_EASIESTDIFF;
    threshold = bits256_from_compact(nBits);
    hash2 = iguana_calcblockhash(virt->symbol,virt->chain->hashalgo,serialized,datalen);
    if ( bits256_cmp(threshold,hash2) > 0 )
    {
        //printf("nonce worked crc.%x\n",calc_crc32(0,serialized,datalen));
        return(1);
    }
    else
    {
        char str[65],str2[65];
        printf("nonce failed crc.%x nBits.%08x %s vs %s\n",calc_crc32(0,serialized,datalen),nBits,bits256_str(str,threshold),bits256_str(str2,hash2));
    }
    return(-1);
}

uint32_t gecko_nBits(struct iguana_info *virt,uint32_t *prevtimestampp,struct iguana_block *block,int32_t n)
{
    uint32_t nBits = GECKO_DEFAULTDIFF,starttime=0,endtime=0,est; struct iguana_block *prev=0; int32_t i,diff; bits256 targetval;
    *prevtimestampp = 0;
    if ( virt->chain->estblocktime == 0 )
        return(GECKO_EASIESTDIFF);
    for (i=0; i<n; i++)
    {
        if ( (prev= iguana_blockfind("geckotx",virt,block->RO.prev_block)) == 0 || prev->height == 0 )
        {
            i++;
            break;
        }
        if ( i == 0 )
        {
            *prevtimestampp = endtime = prev->RO.timestamp;
            nBits = prev->RO.bits;
        }
        starttime = prev->RO.timestamp;
        block = prev;
    }
    if ( starttime != 0 && endtime > starttime && i > 1 )
    {
        diff = (endtime - starttime);
        est = virt->chain->estblocktime * i;
        targetval = bits256_from_compact(nBits);
        if ( diff > est )
        {
            targetval = bits256_ave(targetval,bits256_ave(targetval,bits256_rshift(targetval)));
        }
        else if ( diff < est )
        {
            if ( nBits == GECKO_EASIESTDIFF )
                return(GECKO_EASIESTDIFF);
            targetval = bits256_ave(targetval,bits256_ave(targetval,bits256_lshift(targetval)));
        }
        //printf("diff.%d est.%d nBits.%08x <- %08x\n",diff,virt->chain->estblocktime * i,bits256_to_compact(targetval),nBits);
        nBits = bits256_to_compact(targetval);
    }
    if ( nBits > GECKO_EASIESTDIFF )
    {
        //printf("nBits.%08x vs easiest %08x\n",nBits,GECKO_EASIESTDIFF);
        nBits = GECKO_EASIESTDIFF;
    }
    return(nBits);
}

int32_t gecko_delayedPoW(struct supernet_info *myinfo,struct iguana_info *btcd,int32_t isPoS,uint8_t *coinbase,bits256 *btcdhashp,uint32_t timestamp,int32_t height)
{
    int32_t len = 0; //bits256 btchash;
    memset(btcdhashp,0,sizeof(*btcdhashp));
    len += iguana_rwnum(1,&coinbase[len],sizeof(height),(void *)&height);
    coinbase[len++] = 0;
    if ( (isPoS & 7) != 0 )
    {
        /**btcdhashp = gecko_hashstampscalc(myinfo,btcd,&btchash,timestamp);
        if ( (isPoS & 2) != 0 && (bits256_cmp(*btcdhashp,GENESIS_PUBKEY) == 0 || bits256_nonz(*btcdhashp) == 0) )
            return(-1);
        if ( (isPoS & 4) != 0 && (bits256_cmp(btchash,GENESIS_PUBKEY) == 0 || bits256_nonz(btchash) == 0) )
            return(-1);*/
        //len += iguana_rwbignum(1,&coinbase[len],sizeof(*btcdhashp),btcdhashp->bytes);
        //len += iguana_rwbignum(1,&coinbase[len],sizeof(btchash),btchash.bytes);
    }
    return(len);
}

int32_t iguana_coinbase(int32_t isPoS,uint32_t txversion,uint8_t *serialized,uint32_t timestamp,bits256 prev_hash,uint8_t *coinbasescript,uint32_t coinbaselen,uint8_t *minerpayment,uint32_t minerpaymentlen,int64_t blockreward,bits256 *txidp)
{
    int32_t len = 0,rwflag=1; uint32_t prev_vout,sequence,lock_time; char txidstr[65]; struct iguana_msgtx msg;
    memset(&msg,0,sizeof(msg));
    msg.tx_out = (blockreward > 0) ? 1 : 0;
    msg.tx_in = 1;
    sequence = prev_vout = -1;
    lock_time = 0;
    msg.version = txversion;
    msg.timestamp = timestamp;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg.version),&msg.version);
    if ( isPoS != 0 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg.timestamp),&msg.timestamp);
    {
        len += iguana_rwvarint32(rwflag,&serialized[len],&msg.tx_in);
        // tx_in times
        len += iguana_rwbignum(rwflag,&serialized[len],sizeof(prev_hash),prev_hash.bytes);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(prev_vout),&prev_vout);
        len += iguana_rwvarint32(rwflag,&serialized[len],&coinbaselen);
        len += iguana_rwmem(rwflag,&serialized[len],coinbaselen,coinbasescript);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(sequence),&sequence);
    }
    {
        len += iguana_rwvarint32(rwflag,&serialized[len],&msg.tx_out);
        // tx_out times
        if ( msg.tx_out > 0 )
        {
            len += iguana_rwnum(rwflag,&serialized[len],sizeof(blockreward),&blockreward);
            len += iguana_rwvarint32(rwflag,&serialized[len],&minerpaymentlen);
            len += iguana_rwmem(rwflag,&serialized[len],minerpaymentlen,minerpayment);
        }
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(lock_time),&lock_time);
    *txidp = bits256_doublesha256(txidstr,serialized,len);
    return(len);
}

char *gecko_coinbasestr(struct supernet_info *myinfo,struct iguana_info *virt,bits256 *txidp,uint32_t timestamp,uint8_t *minerpubkey,uint64_t blockreward,uint8_t *data,int32_t datalen,bits256 coinbasespend)
{
    char *rawtx=0; uint8_t minerpayment[512],serialized[8192]; int32_t minerpaymentlen=0,len=0;
    if ( blockreward > 0 )
        minerpaymentlen = bitcoin_pubkeyspend(minerpayment,0,minerpubkey);
    len = iguana_coinbase(virt->chain->isPoS,virt->chain->normal_txversion,serialized,timestamp,coinbasespend,data,datalen,minerpayment,minerpaymentlen,blockreward,txidp);
    if ( len > 0 )
    {
        rawtx = malloc(len*2 + 1);
        init_hexbytes_noT(rawtx,serialized,len);
    }
    return(rawtx);
}

char *gecko_blockconstruct(struct supernet_info *myinfo,struct iguana_info *virt,struct iguana_block *newblock,uint32_t *noncep,struct gecko_memtx **txptrs,int32_t txn_count,uint8_t *coinbase,int32_t coinbaselen,bits256 coinbasespend,double expiration,uint8_t *minerpubkey,int64_t blockreward)
{
    struct iguana_info *btcd; uint8_t serialized[sizeof(*newblock)],space[16384]; int32_t i,n,len,totaltxlen=0; char *coinbasestr,str[65],str2[65],*blockstr=0; bits256 *txids=0,txspace[256],threshold,hash2; struct gecko_memtx *memtx;
    if ( (btcd= iguana_coinfind("BTCD")) == 0 )
    {
        printf("basilisk needs BTCD\n");
        return(0);
    }
    if ( txn_count+2 < sizeof(space)/sizeof(*space) )
    {
        txids = txspace;
        memset(txids,0,sizeof(*txids) * (txn_count+2));
    } else txids = calloc(txn_count+2,sizeof(*txids));
    if ( txn_count > 0 )
    {
        for (i=0; i<txn_count; i++)
        {
            if ( (memtx= txptrs[i]) != 0 )
            {
                totaltxlen += memtx->datalen;
                txids[i + 1] = memtx->txid;
                printf("memtxid.%s\n",bits256_str(str,memtx->txid));
            }
        }
    }
    if ( (coinbasestr= gecko_coinbasestr(myinfo,virt,&txids[0],newblock->RO.timestamp,minerpubkey,blockreward,coinbase,coinbaselen,coinbasespend)) != 0 )
    {
        newblock->RO.merkle_root = iguana_merkle("GECKO",txids,txn_count + 1);
        newblock->RO.txn_count = (txn_count + 1);
        if ( txn_count > 0 )
        {
            printf("%s %s\n",bits256_str(str,txids[0]),bits256_str(str2,txids[1]));
        }
        if ( newblock->RO.bits >= GECKO_EASIESTDIFF )
            newblock->RO.bits = GECKO_EASIESTDIFF;
        threshold = bits256_from_compact(newblock->RO.bits);
        if ( (newblock->RO.nonce= *noncep) == 0 )
        {
            struct iguana_msgzblock zmsg; struct iguana_msgblock *msg = (void *)&zmsg;
            memset(&zmsg,0,sizeof(zmsg));
            msg->H.version = newblock->RO.version;
            msg->H.prev_block = newblock->RO.prev_block;
            msg->H.merkle_root = newblock->RO.merkle_root;
            msg->H.timestamp = newblock->RO.timestamp;
            msg->H.bits = newblock->RO.bits;
            for (i=0; i<GECKO_MAXMINERITERS; i++)
            {
                OS_randombytes((void *)noncep,sizeof(*noncep));
                msg->H.nonce = *noncep;
                //n = iguana_serialize_block(virt->chain,&hash2,serialized,newblock);
                //char str[65]; printf("nonce.%08x %s\n",newblock->RO.nonce,bits256_str(str,newblock->RO.hash2));
                len = iguana_rwblockhdr(1,virt->chain->zcash,serialized,&zmsg);
                hash2 = iguana_calcblockhash(virt->symbol,virt->chain->hashalgo,serialized,len);
                if ( bits256_cmp(threshold,hash2) > 0 )
                {
                    //printf("FOUND NONCE %d iterations\n",i+1);
                    newblock->RO.hash2 = hash2;
                    break;
                }
                if ( newblock->height != 0 && OS_milliseconds() > expiration )
                {
                    //printf("time limit exceeded %u %d iterations\n",virt->blocks.hwmchain.RO.timestamp,i+1);
                    free(coinbasestr);
                    if ( txids != txspace )
                        free(txids);
                    return(0);
                }
            }
        }
        newblock->RO.nonce = *noncep;
        n = iguana_serialize_block(myinfo,virt->chain,&newblock->RO.hash2,serialized,newblock);
        while ( 1 && time(NULL) <= newblock->RO.timestamp + GECKO_MAXFUTUREBLOCK )
        {
            //printf("wait for block to be close enough to now: lag %ld\n",time(NULL) - newblock->RO.timestamp);
            sleep(1);
        }
        //if ( gecko_blocknonce_verify(virt,serialized,n,newblock->RO.bits,newblock->RO.timestamp,virt->blocks.hwmchain.RO.timestamp) >= 0 )
        if ( bits256_cmp(threshold,newblock->RO.hash2) > 0 )
        {
            blockstr = calloc(1,strlen(coinbasestr) + (totaltxlen+n)*2 + 1);
            init_hexbytes_noT(blockstr,serialized,n);
            printf("block.(%s) coinbase.(%s) lens.%ld\n",blockstr,coinbasestr,(strlen(blockstr)+strlen(coinbasestr))/2);
            strcat(blockstr,coinbasestr);
            len = (int32_t)strlen(blockstr);
            for (i=0; i<txn_count; i++)
            {
                if ( (memtx= txptrs[i]) != 0 )
                {
                    init_hexbytes_noT(&blockstr[len],gecko_txdata(memtx),memtx->datalen);
                    len += memtx->datalen << 1;
                    printf(" txi.%d (%s)\n",i,&blockstr[len]);
                }
            }
        } else printf("nonce failure\n");
        free(coinbasestr);
    }
    if ( txids != txspace )
        free(txids);
    return(blockstr);
}

char *gecko_createblock(struct supernet_info *myinfo,int32_t estblocktime,uint32_t prevtimestamp,struct iguana_info *btcd,int32_t isPoS,struct iguana_block *newblock,char *symbol,struct gecko_memtx **txptrs,int32_t txn_count,int32_t maxmillis,uint8_t *minerpubkey,int64_t blockreward)
{
    bits256 btcdhash; uint8_t coinbase[512]; int32_t coinbaselen; uint32_t nonce; double expiration = OS_milliseconds() + maxmillis;
    //char str[65]; printf("create prev.(%s) %p\n",bits256_str(str,newblock->RO.prev_block),&newblock->RO.prev_block);
    if ( btcd != 0 )
    {
        newblock->RO.timestamp = gecko_earliest_blocktime(estblocktime,prevtimestamp);
        if ( (coinbaselen= gecko_delayedPoW(myinfo,btcd,isPoS,coinbase,&btcdhash,newblock->RO.timestamp,newblock->height)) < 0 )
        {
            printf("error generating coinbase for height.%d\n",newblock->height);
            return(0);
        }
        nonce = 0;
        return(gecko_blockconstruct(myinfo,btcd,newblock,&nonce,txptrs,txn_count,coinbase,coinbaselen,btcdhash,expiration,minerpubkey,blockreward));
    } else return(0);
}

cJSON *gecko_paymentsobj(struct supernet_info *myinfo,cJSON *txjson,cJSON *valsobj,int32_t reusedaddrs)
{
    cJSON *item,*array; char *coinaddr; uint64_t satoshis; uint8_t addrtype,pubkey33[33],rmd160[20],outputscript[512]; int32_t i,n,scriptlen; uint32_t locktime,txversion; struct iguana_waddress *waddr; struct iguana_waccount *wacct;
    locktime = jint(valsobj,"locktime");
    if ( (txversion= juint(valsobj,"txversion")) == 0 )
        txversion = (locktime == 0) ? IGUANA_NORMAL_TXVERSION : IGUANA_LOCKTIME_TXVERSION;
    if ( txjson == 0 )
        txjson = bitcoin_txcreate("gecko",1,locktime,txversion,juint(valsobj,"timestamp"));
    if ( (array= jarray(&n,valsobj,"payments")) != 0 && n > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            if ( (coinaddr= jfieldname(item)) != 0 && (satoshis= j64bits(item,coinaddr)) > 0 )
            {
                printf("payment.%s <- %.8f\n",coinaddr,dstr(satoshis));
                bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr);
                scriptlen = 0;
                if ( reusedaddrs == 0 )
                {
                    if ( (waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) != 0 )
                    {
                        if ( bitcoin_pubkeylen(waddr->pubkey) > 0 )
                            scriptlen = bitcoin_pubkeyspend(outputscript,0,pubkey33);
                    }
                }
                if ( scriptlen == 0 )
                    scriptlen = bitcoin_standardspend(outputscript,0,rmd160);
                bitcoin_txoutput(txjson,outputscript,scriptlen,satoshis);
            }
        }
    }
    return(txjson);
}

int32_t gecko_blocksubmit(struct supernet_info *myinfo,struct iguana_info *btcd,struct iguana_info *virt,char *blockstr,bits256 hash2,int32_t height)
{
    uint8_t *data,space[16384],*allocptr=0; int32_t i,len,numranked=0; struct iguana_peers *peers; struct iguana_peer *addr;
    //printf("submit.(%s)\n",blockstr);
    if ( (peers= virt->peers) == 0 || (numranked= peers->numranked) <= 0 )
    {
        if ( basilisk_blocksubmit(myinfo,btcd,virt,0,blockstr,hash2,height) < 0 )//(NUMRELAYS >> 1) )
            return(-1);
    }
    else // physical node for geckochain
    {
        if ( (data= get_dataptr(sizeof(struct iguana_msghdr),&allocptr,&len,space,sizeof(space),blockstr)) != 0 )
        {
            for (i=0; i<numranked; i++)
            {
                if ( (addr= peers->ranked[i]) != 0 && addr->usock >= 0 && addr->supernet != 0 )
                    iguana_queue_send(addr,0,data,"block",len);
            }
        }
        if ( allocptr != 0 )
            free(allocptr);
    }
    return(0);
}

void gecko_miner(struct supernet_info *myinfo,struct iguana_info *btcd,struct iguana_info *virt,int32_t maxmillis,uint8_t *minerpubkey33)
{
    struct iguana_zblock newblock; uint32_t prevtimestamp,nBits; int64_t reward = 0; int32_t txn_count; char *blockstr,*space[256]; struct gecko_memtx **txptrs; void *ptr; //struct iguana_bundle *bp;
#ifndef __APPLE__
    int32_t i,gap;
    if ( virt->virtualchain == 0 || myinfo->NOTARY.RELAYID < 0 || myinfo->NOTARY.NUMRELAYS < 1 )
    {
        //printf("skip non-virtual chain.%s\n",virt->symbol);
        return;
    }
    if ( virt->blocks.hwmchain.height < virt->longestchain-1 )
        return;
    if ( myinfo->IAMNOTARY != 0 && (virt->blocks.hwmchain.height % myinfo->NOTARY.NUMRELAYS) != myinfo->NOTARY.RELAYID )
    {
        //if ( NUMRELAYS < 3 )
        //    return;
        gap = (int32_t)(time(NULL) - virt->blocks.hwmchain.RO.timestamp) / 60;//virt->chain->estblocktime;
        for (i=0; i<gap; i++)
        {
            if ( myinfo->IAMNOTARY != 0 && ((virt->blocks.hwmchain.height+i) % myinfo->NOTARY.NUMRELAYS) == myinfo->NOTARY.RELAYID )
                break;
        }
        if ( i == gap )
            return;
        printf("backup block generator RELAYID.%d gap.%d ht.%d i.%d num.%d\n",myinfo->NOTARY.RELAYID,gap,virt->blocks.hwmchain.height,i,myinfo->NOTARY.NUMRELAYS);
    }
#endif
    /*if ( virt->newblockstr != 0 )
    {
        gecko_blocksubmit(myinfo,btcd,virt,virt->newblockstr,virt->newblock.RO.hash2,virt->newblock.height);
        memset(&virt->newblock,0,sizeof(virt->newblock));
        free(virt->newblockstr);
        virt->newblockstr = 0;
        return;
    }*/
    memset(&newblock,0,sizeof(newblock));
    newblock.height = virt->blocks.hwmchain.height + 1;
    newblock.RO.prev_block = virt->blocks.hwmchain.RO.hash2;
    newblock.RO.version = GECKO_DEFAULTVERSION;
    newblock.RO.allocsize = iguana_ROallocsize(virt);
    if ( (nBits= gecko_nBits(virt,&prevtimestamp,(void *)&newblock,GECKO_DIFFITERS)) != 0 )
    {
        if ( (newblock.RO.bits= nBits) > GECKO_EASIESTDIFF )
            newblock.RO.bits = GECKO_EASIESTDIFF;
        char str[65]; printf("mine.%s %s nBits.%x ht.%d maxmillis.%d\n",virt->symbol,bits256_str(str,bits256_from_compact(newblock.RO.bits)),nBits,newblock.height,maxmillis);
        txptrs = gecko_mempool_txptrs(myinfo,virt,&reward,&txn_count,&ptr,space,(int32_t)(sizeof(space)/sizeof(*space)),newblock.height);
        //char str[65]; printf("HWM.%s %p\n",bits256_str(str,newblock.RO.prev_block),&newblock.RO.prev_block);
        if ( (blockstr= gecko_createblock(myinfo,virt->chain->estblocktime,prevtimestamp,btcd,virt->chain->isPoS,(void *)&newblock,virt->symbol,txptrs,txn_count,maxmillis,minerpubkey33,reward)) != 0 )
        {
            char str[65];
            printf("tx0.%s\n",bits256_str(str,newblock.RO.merkle_root));
            printf(">>>>>>>>>>>>>>>>> MINED %s.%x %s %u %d %.8f %d\n",virt->symbol,newblock.RO.bits,bits256_str(str,newblock.RO.hash2),newblock.RO.timestamp,newblock.height,dstr(reward),newblock.RO.txn_count);
            if ( gecko_blocksubmit(myinfo,btcd,virt,blockstr,newblock.RO.hash2,newblock.height) == 0 )
                free(blockstr);
            else
            {
                //virt->newblockstr = blockstr;
                //virt->newblock = newblock;
                free(blockstr);
            }
        } else printf("didnt find %s.block\n",virt->symbol);
        if ( txptrs != (void *)space )
            free(txptrs);
    }
}

