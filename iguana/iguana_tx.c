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

#if defined(_M_X64)
 /*
 * because we have no choice but to pass the value as parameters
 * we need 64bit to hold 64bit memory address, thus changing
 * to uint64_t instead of long in win x64
 * @author - fadedreamz@gmail.com
 */
int32_t iguana_scriptdata(struct iguana_info *coin,uint8_t *scriptspace,uint64_t fileptr[2],char *fname,uint64_t scriptpos,int32_t scriptlen)
#else
int32_t iguana_scriptdata(struct iguana_info *coin, uint8_t *scriptspace, long fileptr[2], char *fname, uint64_t scriptpos, int32_t scriptlen)
#endif
{
    FILE *fp; long err; uint8_t *ptr; int32_t i,retval = scriptlen;
#ifndef __PNACL__
    if ( scriptpos < 0xffffffff )
    {
        if ( fileptr[0] == 0 )
#if defined(_M_X64)
            fileptr[0] = (uint64_t)OS_mapfile(fname,&fileptr[1],0);
#else
			fileptr[0] = (long)OS_mapfile(fname, &fileptr[1], 0);
#endif
        if ( fileptr[0] != 0 )
        {
            if ( (scriptpos + scriptlen) <= fileptr[1] )
            {
                ptr = (void *)(fileptr[0] + (uint32_t)scriptpos);
                //memcpy(scriptspace,ptr,scriptlen);
                for (i=0; i<scriptlen; i++)
                    scriptspace[i] = ptr[i];
                return(retval);
            }
            else if ( (0) )
            {
                printf("munmap (%s)\n",fname);
                munmap((void *)fileptr[0],fileptr[1]);
                fileptr[0] = fileptr[1] = 0;
            }
        }
    }
#else
    static portable_mutex_t mutex;
    portable_mutex_lock(&mutex);
#endif
    if ( (fp= fopen(fname,"rb")) != 0 )
    {
        fseek(fp,scriptpos,SEEK_SET);
        if ( (err= fread(scriptspace,1,scriptlen,fp)) != scriptlen )
        {
            retval = -1;
            printf("%s script[%d] offset.%llu err.%ld\n",fname,scriptlen,(long long)scriptpos,err);
        } //else printf("%s script[%d] offset.%llu read.%ld\n",fname,scriptlen,(long long)scriptpos,err);
        fclose(fp);
    } else retval = -1;
#ifdef __PNACL__
    portable_mutex_unlock(&mutex);
#endif
    return(retval);
}

int32_t iguana_vinset(struct iguana_info *coin,uint8_t *scriptspace,int32_t height,struct iguana_msgvin *vin,struct iguana_txid *tx,int32_t i)
{
    struct iguana_spend *s,*S; uint32_t spendind,unspentind; bits256 *X; struct iguana_bundle *bp;
    struct iguana_ramchaindata *rdata=0; struct iguana_txid *T; char fname[1024]; int32_t scriptlen,err = 0; struct iguana_ramchain *ramchain;
    memset(vin,0,sizeof(*vin));
    if ( height >= 0 && height < coin->chain->bundlesize*coin->bundlescount && (bp= coin->bundles[height / coin->chain->bundlesize]) != 0 )
    {
        ramchain = &bp->ramchain;//(bp == coin->current) ? &coin->RTramchain : &bp->ramchain;
        if ( ((rdata= ramchain->H.data) != 0 || ((bp == coin->current && (rdata= ramchain->H.data) != 0))) && i < tx->numvins )
        //if ( (rdata= ramchain->H.data) != 0 && i < rdata->numspends )
        {
            S = RAMCHAIN_PTR(rdata,Soffset);
            X = RAMCHAIN_PTR(rdata,Xoffset);
            T = RAMCHAIN_PTR(rdata,Toffset);
            spendind = (tx->firstvin + i);
            s = &S[spendind];
            vin->sequence = s->sequenceid;
            vin->prev_vout = s->prevout;
            if ( s->prevout < 0 )
                ;
            if ( s->scriptpos != 0 && s->scriptlen > 0 )
            {
                iguana_vinsfname(coin,bp->ramchain.from_ro,fname,s->fileid);
                if ( (scriptlen= iguana_scriptdata(coin,scriptspace,coin->vinptrs[s->fileid],fname,s->scriptpos,s->scriptlen)) != s->scriptlen )
                    printf("err.%d getting %d bytes from fileid.%u[%u] %s for s%d\n",err,(int32_t)s->scriptlen,(uint32_t)s->scriptpos,(uint32_t)s->fileid,fname,spendind);
            }
            vin->scriptlen = s->scriptlen;
            vin->vinscript = scriptspace;
            iguana_ramchain_spendtxid(coin,&unspentind,&vin->prev_hash,T,rdata->numtxids,X,rdata->numexternaltxids,s);
        } else printf("null rdata.%p error height.%d i.%d\n",rdata,height,i);
    } else printf("error getting rdata.%p height.%d\n",rdata,height);
    if ( err != 0 )
        return(-err);
    else return(vin->scriptlen);
}

int32_t iguana_voutscript(struct iguana_info *coin,struct iguana_bundle *bp,uint8_t *scriptspace,char *asmstr,struct iguana_unspent *u,struct iguana_pkhash *p,int32_t txi)
{
    struct vin_info V; char fname[1024],coinaddr[65]; int32_t scriptlen = -1;
    if ( u->scriptpos > 0 && u->scriptlen > 0 )
    {
        iguana_voutsfname(coin,bp->ramchain.from_ro,fname,u->fileid);
        if ( (int32_t)(scriptlen= iguana_scriptdata(coin,scriptspace,coin->voutptrs[u->fileid],fname,u->scriptpos,u->scriptlen)) != (int32_t)u->scriptlen )
            printf("scriptlen.%d != %d bytes from fileid.%d[%d] %s for type.%d\n",scriptlen,u->scriptlen,u->fileid,u->scriptpos,fname,u->type);
        if ( scriptlen < 0 )
            scriptlen = 0;
    }
    else
    {
        memset(&V,0,sizeof(V));
        scriptlen = iguana_scriptgen(coin,&V.M,&V.N,coinaddr,scriptspace,asmstr,p->rmd160,u->type,(const struct vin_info *)&V,txi);
    }
    return(scriptlen);
}

int32_t iguana_voutset(struct iguana_info *coin,uint8_t *scriptspace,char *asmstr,int32_t height,struct iguana_msgvout *vout,struct iguana_txid *tx,int32_t i)
{
    struct iguana_ramchaindata *rdata=0; uint32_t unspentind,scriptlen = 0; struct iguana_bundle *bp;
    struct iguana_unspent *u,*U; struct iguana_pkhash *P; struct iguana_ramchain *ramchain=0; int32_t err = 0;
    memset(vout,0,sizeof(*vout));
    if ( height >= 0 && height < coin->chain->bundlesize*coin->bundlescount && (bp= coin->bundles[height / coin->chain->bundlesize]) != 0  )
    {
        ramchain = &bp->ramchain;//(bp == coin->current) ? &coin->RTramchain : &bp->ramchain;
        if ( ((rdata= ramchain->H.data) != 0 || ((bp == coin->current && (rdata= ramchain->H.data) != 0))) && i < tx->numvouts )
        {
            U = RAMCHAIN_PTR(rdata,Uoffset);
            P = RAMCHAIN_PTR(rdata,Poffset);
            //U = (void *)(long)((long)rdata + rdata->Uoffset);
            //P = (void *)(long)((long)rdata + rdata->Poffset);
            unspentind = (tx->firstvout + i);
            u = &U[unspentind];
            if ( u->vout != i || u->hdrsi != height / coin->chain->bundlesize ) //u->txidind != tx->txidind ||
            {
                static uint32_t counter;
                if ( counter++ < 3 )
                    printf("%s.[%d].%d iguana_voutset: vout mismatch t%d u%u || %d vs %d, type.%d scriptpos.%d scriptlen.%d\n",coin->symbol,height/coin->chain->bundlesize,u->hdrsi,u->txidind,unspentind,u->vout,i,u->type,u->scriptpos,u->scriptlen);
                return(-1);
            }
            vout->value = u->value;
            vout->pk_script = scriptspace;
            scriptlen = iguana_voutscript(coin,bp,scriptspace,asmstr,u,&P[u->pkind],i);
        } else printf("iguana_voutset unexpected path [%d] rdata.%p i.%d %d\n",bp->hdrsi,rdata,i,tx->numvouts);
    } else printf("vout error getting rdata.%p height.%d\n",rdata,height);
    vout->pk_scriptlen = scriptlen;
    if ( err != 0 )
        return(-err);
    else return(scriptlen);
}

struct iguana_txid *iguana_blocktx(struct iguana_info *coin,struct iguana_txid *tx,struct iguana_block *block,int32_t i)
{
    struct iguana_bundle *bp; uint32_t txidind;
    if ( i >= 0 && i < block->RO.txn_count )
    {
        if ( block->height >= 0 && block->bundlei >= 0 && block->bundlei < coin->chain->bundlesize )
        {
            if ( (bp= coin->bundles[block->hdrsi]) != 0 )
            {
                if ( (txidind= block->RO.firsttxidind) == bp->firsttxidinds[block->bundlei] )
                {
                    if ( iguana_bundletx(coin,bp,block->bundlei,tx,txidind+i) == tx )
                        return(tx);
                    printf("error getting txidind.%d + i.%d from hdrsi.%d\n",txidind,i,block->hdrsi);
                    return(0);
                } else printf("iguana_blocktx null txidind [%d:%d] i.%d txidind.%d vs %d\n",block->hdrsi,block->bundlei,i,txidind,bp->firsttxidinds[block->bundlei]);
            } else printf("iguana_blocktx no bp.[%d]\n",block->hdrsi);
        } else printf("%s blocktx illegal height.%d or [%d:%d]\n",coin->symbol,block->height,block->hdrsi,block->bundlei);
    } else printf("i.%d vs txn_count.%d\n",i,block->RO.txn_count);
    return(0);
}

int32_t iguana_ramtxbytes(struct iguana_info *coin,uint8_t *serialized,int32_t maxlen,bits256 *txidp,struct iguana_txid *tx,int32_t height,struct iguana_msgvin *vins,struct iguana_msgvout *vouts,int32_t validatesigs)
{
    int32_t i,rwflag=1,len = 0; char asmstr[512],txidstr[65];
    uint32_t numvins,numvouts,version,locktime,timestamp=0; struct iguana_msgvin vin; struct iguana_msgvout vout; uint8_t space[IGUANA_MAXSCRIPTSIZE];
    if ( rwflag != 0 )
    {
        version = tx->version;
        locktime = tx->locktime;
        timestamp = tx->timestamp;
        numvins = tx->numvins;
        numvouts = tx->numvouts;
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(version),&version);
    if ( coin->chain->isPoS != 0 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(timestamp),&timestamp);
    len += iguana_rwvarint32(rwflag,&serialized[len],&numvins);
    memset(&vin,0,sizeof(vin));
    for (i=0; i<numvins; i++)
    {
        if ( vins == 0 )
        {
            if ( iguana_vinset(coin,space,height,&vin,tx,i) < 0 )
            {
                printf("iguana_ramtxbytes vinset error %d of %d\n",i,numvins);
                return(0);
            }
        } else vin = vins[i];
        len += iguana_rwvin(rwflag,coin,0,&serialized[len],&vin,i);
        if ( len > maxlen )
            break;
    }
    if ( len > maxlen )
    {
        printf("len.%d > maxlen.%d\n",len,maxlen);
        return(0);
    }
    len += iguana_rwvarint32(rwflag,&serialized[len],&numvouts);
    for (i=0; i<numvouts; i++)
    {
        if ( vouts == 0 )
        {
            if ( iguana_voutset(coin,space,asmstr,height,&vout,tx,i) < 0 )
            {
                static uint32_t counter;
                if ( counter++ < 10 )
                    printf("iguana_ramtxbytes voutset error %d of %d\n",i,numvouts);
                return(0);
            }
        } else vout = vouts[i];
        len += iguana_rwvout(rwflag,0,&serialized[len],&vout);
        if ( len > maxlen )
            break;
    }
    if ( len > maxlen )
    {
        printf("len.%d > maxlenB.%d\n",len,maxlen);
        return(0);
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(locktime),&locktime);
    if ( rwflag == 0 )
    {
        tx->version = version;
        tx->timestamp = timestamp;
        tx->numvins = numvins;
        tx->numvouts = numvouts;
        tx->locktime = locktime;
    }
    *txidp = bits256_doublesha256(txidstr,serialized,len);
    if ( memcmp(txidp,tx->txid.bytes,sizeof(*txidp)) != 0 )
    {
        for (i=0; i<len; i++)
            printf("%02x",serialized[i]);
        char str[65],str2[65]; printf("\nrw.%d numvins.%d numvouts.%d error generating txbytes txid %s vs %s\n",rwflag,numvins,numvouts,bits256_str(str,*txidp),bits256_str(str2,tx->txid));
        return(-1);
    }
    return(len);
}

int32_t iguana_peerblockrequest(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t *blockspace,int32_t max,struct iguana_peer *addr,bits256 hash2,int32_t validatesigs)
{
#if defined(_M_X64)
	/*
	* because we have no choice but to access the memory address
	* we need 64bit to correctly hold 64bit memory address, thus changing
	* to uint64_t instead of long in win x64
	* @author - fadedreamz@gmail.com
	*/
	struct iguana_txid *tx, T; bits256 checktxid; int32_t i, len, total, bundlei = -2; struct iguana_block *block; struct iguana_msgzblock zmsgB; bits256 *tree, checkhash2, merkle_root; struct iguana_bundle *bp = 0; uint64_t tmp; char str[65]; struct iguana_ramchaindata *rdata;
#else
    struct iguana_txid *tx,T; bits256 checktxid; int32_t i,len,total,bundlei=-2; struct iguana_block *block; struct iguana_msgzblock zmsgB; bits256 *tree,checkhash2,merkle_root; struct iguana_bundle *bp=0; long tmp; char str[65]; struct iguana_ramchaindata *rdata;
#endif
    if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,hash2)) != 0 && bundlei >= 0 && bundlei < bp->n )
    {
        if ( (rdata= bp->ramchain.H.data) == 0 )//&& bp == coin->current )
        {
            //printf("iguana_peerblockrequest no ramchain data [%d] use RTcache\n",bp->hdrsi);
            //rdata = coin->RTramchain.H.data;
            return(-1);
        }
        if ( (block= bp->blocks[bundlei]) != 0 && rdata != 0 )
        {
            iguana_blockunconv(coin->chain->zcash,coin->chain->auxpow,&zmsgB,(void *)block,0);
            zmsgB.txn_count = block->RO.txn_count;
            total = iguana_rwblock(myinfo,coin->symbol,coin->chain->zcash,coin->chain->auxpow,coin->chain->hashalgo,1,&checkhash2,&blockspace[sizeof(struct iguana_msghdr) + 0],&zmsgB,max);
            if ( bits256_cmp(checkhash2,block->RO.hash2) != 0 )
            {
                //static int counter;
                //if ( counter++ < 100 )
                    printf("iguana_peerblockrequest: blockhash mismatch ht.%d\n",bp->bundleheight+bundlei);
                return(-1);
            }
            for (i=0; i<block->RO.txn_count; i++)
            {
                if ( (tx= iguana_blocktx(coin,&T,block,i)) != 0 )
                {
                    //printf("ht.%d [%d:%d] txi.%d i.%d o.%d %s\n",block->height,block->hdrsi,block->bundlei,i,tx->numvins,tx->numvouts,bits256_str(str,tx->txid));
                    if ( (len= iguana_ramtxbytes(coin,&blockspace[sizeof(struct iguana_msghdr) + total],max - total,&checktxid,tx,block->height,0,0,validatesigs)) > 0 )//&& bits256_cmp(checktxid,T.txid) == 0 )
                        total += len;
                    else
                    {
                        static uint32_t counter;
                        char str[65],str2[65];
                        if ( counter++ < 100 )
                        {
                            for (i=0; i<len&&i<64; i++)
                                printf("%02x",blockspace[sizeof(struct iguana_msghdr)+i]);
                            printf(" len.%d error getting txi.%d [%d:%d] cmp.%s %s\n",len,i,bp->hdrsi,bundlei,bits256_str(str,checktxid),bits256_str(str2,T.txid));
                        }
                        break;
                    }
                }
                else
                {
                    printf("%s null tx error getting txi.%d [%d:%d]\n",coin->symbol,i,bp->hdrsi,bundlei);
                    break;
                }
            }
            if ( i == block->RO.txn_count )
            {
#if defined(_M_X64)
				/*
				* because we have no choice but to access the memory address
				* we need 64bit to correctly hold 64bit memory address, thus changing
				* to uint64_t instead of long in win x64
				* @author - fadedreamz@gmail.com
				*/
				tmp = (uint64_t)&blockspace[sizeof(struct iguana_msghdr) + total + sizeof(bits256)];
#else
                tmp = (long)&blockspace[sizeof(struct iguana_msghdr) + total + sizeof(bits256)];
#endif
                tmp &= ~(sizeof(bits256) - 1);
                tree = (void *)tmp;
                for (i=0; i<block->RO.txn_count; i++)
                {
                    if ( (tx= iguana_blocktx(coin,&T,block,i)) != 0 )
                        tree[i] = T.txid;
                    else break;
                }
                if ( i == block->RO.txn_count )
                {
                    merkle_root = iguana_merkle(coin->symbol,tree,block->RO.txn_count);
                    if ( bits256_cmp(merkle_root,block->RO.merkle_root) == 0 )
                    {
                        if ( addr != 0 && addr->lastsent != block->height )
                        {
                            addr->lastsent = block->height;
                            printf("Sendlen.%d block.%d %s to %s\n",total,block->height,bits256_str(str,block->RO.hash2),addr->ipaddr);
                            if ( (0) )
                            {
                                struct iguana_txblock txdata; int32_t checklen; static struct OS_memspace RAWMEM;
                                if ( RAWMEM.ptr == 0 )
                                    iguana_meminit(&RAWMEM,addr->ipaddr,0,IGUANA_MAXPACKETSIZE * 2,0);
                                else iguana_memreset(&RAWMEM);
                                memset(&txdata,0,sizeof(txdata));
                                int32_t i;
                                for (i=0; i<total; i++)
                                {
                                    if ( i == 81 )
                                        printf(" ");
                                    printf("%02x",blockspace[i + sizeof(struct iguana_msghdr)]);
                                }
                                printf(" blocksize.%d\n",total);
                                for (i=0; i<16; i++)
                                    printf("%02x",blockspace[i + sizeof(struct iguana_msghdr)+81]);
                                printf(" txhdr\n");
                                if ( (checklen= iguana_gentxarray(myinfo,coin,&RAWMEM,&txdata,&checklen,&blockspace[sizeof(struct iguana_msghdr)],total)) != total && checklen != total-1 )
                                    printf("Error reconstructing txarray checklen.%d total.%d\n",checklen,total);
                            }
                            return(iguana_queue_send(addr,0,blockspace,"block",total));
                        }
                        else
                        {
                            //printf("validated.[%d:%d] len.%d\n",bp->hdrsi,bundlei,total);
                            return(total);
                        }
                    } else printf("iguana_peerblockrequest: %s error %s merkle cmp tx.[%d] for ht.%d\n",coin->symbol,bits256_str(str,block->RO.hash2),i,bp->bundleheight+bundlei);
                } else printf("iguana_peerblockrequest: error merkle verify tx.[%d] for ht.%d\n",i,bp->bundleheight+bundlei);
            }
            else
            {
                static uint32_t counter;
                if ( counter++ < 10 )
                    printf("%s iguana_peerblockrequest: error getting tx.[%d] for ht.%d block.%p main.%d ht.%d\n",coin->symbol,i,bp->bundleheight+bundlei,block,block!=0?block->mainchain:-1,block!=0?block->height:-1);
            }
        }
        else
        {
            if ( coin->virtualchain != 0 )
                ;
            /*if ( block != 0 )
                printf("iguana_peerblockrequest: block.%p ht.%d mainchain.%d [%d:%d] from %s bp.%p rdata.%p\n",block,block->height,block->mainchain,bp->hdrsi,bundlei,addr!=0?addr->ipaddr:"local",bp,bp!=0?rdata:0);
            else printf("iguana_peerblockrequest: block.%p [%d:%d]\n",block,bp->hdrsi,bundlei);*/
        }
    } //else printf("iguana_peerblockrequest: cant find %s\n",bits256_str(str,hash2));
    return(-1);
}

cJSON *iguana_blockjson(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_block *block,int32_t txidsflag)
{
    char str[65],hexstr[1024]; int32_t i,len,size; struct iguana_txid *tx,T; struct iguana_msgzblock zmsg; struct iguana_msgblock *msg = (void *)&zmsg; struct iguana_zblock *zblock;
    bits256 hash2,nexthash2; uint8_t serialized[1024]; cJSON *array,*json = cJSON_CreateObject();
    jaddstr(json,"result","success");
    jaddstr(json,"hash",bits256_str(str,block->RO.hash2));
    jaddnum(json,"height",block->height);
    //jaddnum(json,"ipbits",block->fpipbits);
    jaddstr(json,"merkleroot",bits256_str(str,block->RO.merkle_root));
    jaddstr(json,"previousblockhash",bits256_str(str,block->RO.prev_block));
    if ( block->height > 0 )
    {
        nexthash2 = iguana_blockhash(coin,block->height+1);
        if ( bits256_nonz(nexthash2) != 0 )
            jaddstr(json,"nextblockhash",bits256_str(str,nexthash2));
    }
    jaddnum(json,"timestamp",block->RO.timestamp);
    jaddstr(json,"utc",utc_str(str,block->RO.timestamp));
    jaddnum(json,"nonce",block->RO.nonce);
    jaddnum(json,"version",block->RO.version);
    jaddnum(json,"numvouts",block->RO.numvouts);
    jaddnum(json,"numvins",block->RO.numvins);
    jaddnum(json,"recvlen",block->RO.recvlen);
    jaddnum(json,"hdrsi",block->hdrsi);
    jaddnum(json,"difficulty",PoW_from_compact(block->RO.bits,coin->chain->unitval));
    jaddnum(json,"bundlei",block->bundlei);
    jaddnum(json,"mainchain",block->mainchain);
    jaddnum(json,"valid",block->valid);
    jaddnum(json,"txn_count",block->RO.txn_count);
    
    jaddnum(json,"nBits",block->RO.bits);
    serialized[0] = ((uint8_t *)&block->RO.bits)[3];
    serialized[1] = ((uint8_t *)&block->RO.bits)[2];
    serialized[2] = ((uint8_t *)&block->RO.bits)[1];
    serialized[3] = ((uint8_t *)&block->RO.bits)[0];
    init_hexbytes_noT(hexstr,serialized,sizeof(uint32_t));
    jaddstr(json,"nBitshex",hexstr);
    if ( block->RO.allocsize == sizeof(struct iguana_zblock) )
    {
        zblock = (void *)block;
        memset(&zmsg,0,sizeof(zmsg));
        zmsg.zH.version = zblock->RO.version;
        zmsg.zH.merkle_root = zblock->RO.merkle_root;
        zmsg.zH.timestamp = zblock->RO.timestamp;
        zmsg.zH.bits = zblock->RO.bits;
        zmsg.zH.bignonce = zblock->zRO.bignonce;
        if ( iguana_rwvarint32(1,zmsg.zH.var_numelements,&zblock->zRO.numelements) != sizeof(zmsg.zH.var_numelements) )
            printf("unexpected varint size for zmsg.zH.numelements <- %d\n",zblock->zRO.numelements);
        for (i=0; i<ZCASH_SOLUTION_ELEMENTS; i++)
            zmsg.zH.solution[i] = zblock->zRO.solution[i];
        zmsg.txn_count = 0;//block->RO.txn_count;
        len = iguana_rwblock(myinfo,coin->symbol,coin->chain->zcash,coin->chain->auxpow,coin->chain->hashalgo,1,&hash2,serialized,&zmsg,IGUANA_MAXPACKETSIZE*2);
    }
    else
    {
        memset(msg,0,sizeof(&msg));
        msg->H.version = block->RO.version;
        msg->H.prev_block = block->RO.prev_block;
        msg->H.merkle_root = block->RO.merkle_root;
        msg->H.timestamp = block->RO.timestamp;
        msg->H.bits = block->RO.bits;
        msg->H.nonce = block->RO.nonce;
        msg->txn_count = 0;//block->RO.txn_count;
        len = iguana_rwblock(myinfo,coin->symbol,coin->chain->zcash,coin->chain->auxpow,coin->chain->hashalgo,1,&hash2,serialized,&zmsg,IGUANA_MAXPACKETSIZE*2);
    }
    init_hexbytes_noT(hexstr,serialized,len);
    jaddstr(json,"blockheader",hexstr);
    if ( txidsflag != 0 )
    {
        array = cJSON_CreateArray();
        for (i=0; i<block->RO.txn_count; i++)
        {
            if ( (tx= iguana_blocktx(coin,&T,block,i)) != 0 )
                jaddistr(array,bits256_str(str,tx->txid));
        }
        jadd(json,"tx",array);
        //printf("add txids[%d]\n",block->txn_count);
    }
    if ( (size= iguana_peerblockrequest(myinfo,coin,coin->blockspace,coin->blockspacesize,0,block->RO.hash2,0)) < 0 )
        jaddstr(json,"error","couldnt generate raw bytes for block");
    else jaddnum(json,"size",size);
    return(json);
}

