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

static uint16_t iguana_primes[] = { 65353, 65357, 65371, 65381, 65393, 65407, 65413, 65419, 65423, 65437, 65447, 65449, 65479, 65497, 65519, 65521 };


struct iguana_bloominds iguana_calcbloom(bits256 hash2)
{
    int32_t i,j,k; struct iguana_bloominds bit;
    memset(&bit,0,sizeof(bit));
    k = (int32_t)(sizeof(bit)/sizeof(uint16_t)) - 1;
    j = 15;
    for (i=0; i<sizeof(bit)/sizeof(uint16_t); i++,j--,k--)
        bit.inds[i] = (hash2.ushorts[j] % iguana_primes[k]);//, printf("%d ",bit.inds[i]);
    //printf("bit.inds\n");
    return(bit);
}

struct iguana_bloominds iguana_bloomset(struct iguana_info *coin,struct iguana_bloom16 *bloom,int32_t incr,struct iguana_bloominds bit)
{
    int32_t i,alreadyset;
    for (alreadyset=i=0; i<sizeof(bit)/sizeof(uint16_t); i++,bloom+=incr)
    {
        if ( GETBIT(bloom->hash2bits,bit.inds[i]) == 0 )
            SETBIT(bloom->hash2bits,bit.inds[i]);
        else alreadyset++;
    }
    if ( alreadyset == i )
        printf("iguana_bloomset: collision\n");
    return(bit);
}

int32_t iguana_bloomfind(struct iguana_info *coin,struct iguana_bloom16 *bloom,int32_t incr,struct iguana_bloominds bit)
{
    int32_t i;
    coin->bloomsearches++;
    for (i=0; i<sizeof(bit)/sizeof(uint16_t); i++,bloom+=incr)
        if ( GETBIT(bloom->hash2bits,bit.inds[i]) == 0 )
            return(-1);
    coin->bloomhits++;
    return(0);
}

int32_t iguana_bundlescan(struct iguana_info *coin,struct iguana_bundle *bp,bits256 hash2)
{
    int32_t bundlei;
    for (bundlei=0; bundlei<bp->n; bundlei++)
    {
        if ( memcmp(hash2.bytes,bp->hashes[bundlei].bytes,sizeof(hash2)) == 0 )
        {
            //char str[65]; printf("hdrsi.%d scan.%s found %d of %d\n",bp->hdrsi,bits256_str(str,hash2),bundlei,bp->n);
            return(bundlei);
        }
    }
    return(-2);
}

struct iguana_bundle *iguana_bundlefind(struct iguana_info *coin,struct iguana_bundle **bpp,int32_t *bundleip,bits256 hash2)
{
    int32_t i; struct iguana_bloominds bit; struct iguana_bundle *bp = *bpp;
    bit = iguana_calcbloom(hash2);
    if ( bp == 0 )
    {
        for (i=coin->bundlescount-1; i>=0; i--)
        //for (i=0; i<coin->bundlescount; i++)
        {
            if ( (bp= coin->bundles[i]) != 0 )
            {
                if ( iguana_bloomfind(coin,&bp->bloom,0,bit) == 0 )
                {
                    *bpp = bp;
                    if ( (*bundleip= iguana_bundlescan(coin,bp,hash2)) < 0 )
                    {
                        //printf("bloom miss\n");
                        coin->bloomfalse++;
                    } else return(bp);
                } //else printf("no bloom\n");
            }
        }
        *bundleip = -2;
        *bpp = 0;
        return(0);
    }
    else if ( iguana_bloomfind(coin,&bp->bloom,0,bit) == 0 )
    {
        if ( (*bundleip= iguana_bundlescan(coin,bp,hash2)) >= 0 )
        {
            *bpp = bp;
            return(bp);
        } else printf("scan miss\n");
    }
    *bpp = 0;
    *bundleip = -2;
    return(0);
}

bits256 *iguana_bundleihash2p(struct iguana_info *coin,int32_t *isinsidep,struct iguana_bundle *bp,int32_t bundlei)
{
    *isinsidep = 0;
    if ( bundlei >= 0 && bundlei < coin->chain->bundlesize )
    {
        *isinsidep = 1;
        return(&bp->hashes[bundlei]);
    }
    else if ( bundlei == -1 )
        return(&bp->prevbundlehash2);
    else if ( bundlei == coin->chain->bundlesize)
        return(&bp->nextbundlehash2);
    else return(0);
}

int32_t iguana_hash2set(struct iguana_info *coin,char *debugstr,struct iguana_bundle *bp,int32_t bundlei,bits256 newhash2)
{
    int32_t isinside,checki,retval = -1; bits256 *orighash2p = 0; struct iguana_bundle *checkbp; char str[65]; struct iguana_bloominds bit;
    if ( bp == 0 )
        return(-1);
    if ( bp->n <= bundlei )
    {
        printf("hash2set.%s [%d] of %d <- %s\n",debugstr,bundlei,bp->n,bits256_str(str,newhash2));
        bp->n = coin->chain->bundlesize;
    }
    if ( bits256_nonz(newhash2) == 0 || (orighash2p= iguana_bundleihash2p(coin,&isinside,bp,bundlei)) == 0 )
    {
        printf("iguana_hash2set warning: bundlei.%d newhash2.%s orighash2p.%p\n",bundlei,bits256_str(str,newhash2),orighash2p);
        //*orighash2p = newhash2;
      //getchar();
        return(-1);
    }
    if ( bits256_nonz(*orighash2p) > 0 && memcmp(newhash2.bytes,orighash2p,sizeof(bits256)) != 0 )
    {
        static uint32_t counter;
        if ( counter++ < 3 )
        {
            char str2[65],str3[65];
            bits256_str(str2,*orighash2p), bits256_str(str3,newhash2);
            printf("WARNING iguana_hash2set overwrite %s [%s] %s with %s [%d:%d]\n",coin->symbol,debugstr,str2,str3,bp->hdrsi,bundlei);
        }
        //*orighash2p = newhash2;
        return(-1);
    }
    if ( isinside != 0 )
    {
        bit = iguana_calcbloom(newhash2);
        if ( iguana_bloomfind(coin,&bp->bloom,0,bit) < 0 )
        {
           // printf("bloomset (%s) -> [%d:%d]\n",bits256_str(str,newhash2),bp->hdrsi,bundlei);
            iguana_bloomset(coin,&bp->bloom,0,bit);
            if ( (0) )
            {
                int32_t i;
                if ( iguana_bloomfind(coin,&bp->bloom,0,bit) < 0 )
                {
                    for (i=0; i<8; i++)
                        printf("%d ",bit.inds[i]);
                    printf("cant bloomfind just bloomset\n");
                }
                else
                {
                    *orighash2p = newhash2;
                    checkbp = bp, checki = -2;
                    if ( iguana_bundlefind(coin,&checkbp,&checki,newhash2) == 0 || checki != bundlei )
                    {
                        printf("cant iguana_bundlefind just added.(%s) bundlei.%d %p vs checki.%d %p\n",bits256_str(str,newhash2),bundlei,bp,checki,checkbp);
                    }
                    else if ( (coin->bloomsearches % 100000) == 0 )
                        printf("BLOOM SUCCESS %.2f%% FP.%d/%d collisions.%d\n",100.*(double)coin->bloomhits/coin->bloomsearches,(int32_t)coin->bloomfalse,(int32_t)coin->bloomsearches,(int32_t)coin->collisions);
                }
            }
        } //else printf("bloom found\n");
        retval = 0;
    } else retval = (bundlei >= 0 && bundlei < coin->chain->bundlesize) ? 0 : 1;
    //printf("set [%d] <- %s\n",bundlei,bits256_str(str,newhash2));
    /*if ( bits256_cmp(*orighash2p,newhash2) != 0 )
    {
        if ( bits256_nonz(*orighash2p) != 0 && bp->bundleheight+bundlei <= coin->blocks.hwmchain.height )
        {
            printf("changing [%d:%d] -> %d < hwmheight %d\n",bp->hdrsi,bundlei,bp->bundleheight+bundlei,coin->blocks.hwmchain.height);
            if ( bp->bundleheight+bundlei > 0 )
            {
                printf("REORG %d blocks\n",coin->blocks.hwmchain.height - (bp->bundleheight+bundlei));
            }
        }
        *orighash2p = newhash2;
    }*/
    return(retval);
}

int32_t iguana_bundlehash2add(struct iguana_info *coin,struct iguana_block **blockp,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2)
{
    struct iguana_block *block =0; struct iguana_bundle *otherbp;
    int32_t otherbundlei,setval,bundlesize,err = 0;
    if ( blockp != 0 )
        *blockp = 0;
    if ( bp == 0 || bits256_nonz(hash2) == 0 )
    {
        static uint32_t counter;
        if ( counter++ < 100 )
            printf("iguana_bundlehash2add %s null hash2 bp.%p\n",coin->symbol,bp);
        return(-1111);
    }
    if ( bits256_nonz(hash2) != 0 && (block= iguana_blockhashset("bundlehash2add",coin,-1,hash2,1)) != 0 )
    {
        if ( bp->blocks[bundlei] != 0 && bp->blocks[bundlei] != block )
        {
            if ( block->mainchain != 0 && (block->height % coin->chain->bundlesize) == bundlei && (block->height / coin->chain->bundlesize) == bp->hdrsi )
            {
                char str[65],str2[65];
                printf("bundle block override [%d:%d] %s <- %s\n",bp->hdrsi,bundlei,bits256_str(str,bp->blocks[bundlei]->RO.hash2),bits256_str(str2,block->RO.hash2));
                bp->blocks[bundlei] = block;
                bp->hashes[bundlei] = block->RO.hash2;
            }
            else if ( block->mainchain == 0 )
            {
                /*if ( coin->RTheight > 0 && bp->bundleheight+bundlei > coin->firstRTheight )
                {
                    if ( bundlei > 1 )
                        bundlei -= 2;
                    if ( bp->bundleheight+bundlei > coin->blocks.hwmchain.height && (block= iguana_blockfind("reset",coin,bp->hashes[0])) != 0 )
                    {
                        iguana_blockzcopy(coin->chain->zcash,(void *)&coin->blocks.hwmchain,block);
                        printf("RESET HWM to %d ht.%d\n",bp->bundleheight+bundlei,block->height);
                        return(-1);
                    } //else printf("couldnt find block at %d\n",bp->bundleheight+bundlei);
                }
                //else if ( bundlei > 0 )
                if ( bp->blocks[bundlei] != 0 )
                {
                    printf("bp.[%d]->blocks[%d] mismatch %p != %p\n",bp->hdrsi,bundlei,bp->blocks[bundlei],block);
                    bp->blocks[bundlei] = 0;
                }*/
                iguana_blockunmark(coin,block,bp,bundlei,1);
                return(-1);
            }
        }
        if ( (0) && bits256_nonz(bp->hashes[bundlei]) != 0 && bits256_cmp(bp->hashes[bundlei],block->RO.hash2) != 0 )
        {
            //char str[65],str2[65];
            //printf("B bp.[%d]->hashes[%d] mismatch %s != %s%s\n",bp->hdrsi,bundlei,bits256_str(str,bp->hashes[bundlei]),bits256_str(str2,block->RO.hash2),block->mainchain?".main":"");
            iguana_blockunmark(coin,block,bp,bundlei,1);
            bp->blocks[bundlei] = 0;
            //if ( block->mainchain != 0 )
            //    bp->hashes[bundlei] = block->RO.hash2;
            return(-1);
        }
        /*if ( (block->hdrsi != bp->hdrsi || block->bundlei != bundlei) && (block->hdrsi != 0 || block->bundlei != 0) )
        {
            return(-2);
        }*/
        bundlesize = coin->chain->bundlesize;
        if ( bp->n > bundlesize )
        {
            printf("bp->n.%d is too big\n",bp->n);
            return(0);
        }
        if ( bundlei >= bp->n && bundlei < coin->chain->bundlesize )
            bp->n = bundlesize;//(bundlei < bundlesize-1) ? bundlesize : (bundlei + 1);
        if ( (setval= iguana_hash2set(coin,"blockadd",bp,bundlei,hash2)) == 0 )
        {
            if ( block->bundlei >= 0 && ((block->hdrsi != bp->hdrsi || block->bundlei != bundlei) && (block->hdrsi != 0 || block->bundlei != 0)) )
            {
                //char str[65]; printf("blockadd warning: %d[%d] main.%d prevent <- %d[%d] %s\n",block->hdrsi,block->bundlei,block->mainchain,bp->hdrsi,bundlei,bits256_str(str,hash2));
                //iguana_blockunmark(coin,block,bp,bundlei,block->mainchain != 0);
                err |= 2;
                return(-1);
                //exit(-1);
            }
            else
            {
                char str[65];
                block->hdrsi = bp->hdrsi;
                block->bundlei = bundlei;
                bp->hashes[bundlei] = block->RO.hash2;
                if ( bp->speculative != 0 && bundlei < bp->numspec )
                    bp->speculative[bundlei] = bp->hashes[bundlei];
                if ( bp->blocks[bundlei] == 0 )
                    bp->blocks[bundlei] = block;
                else if ( bp->blocks[bundlei] != block )
                    printf(">>>>>>>>>>>>>> bundlehash2.(%s) ht.(%d %d) block.%p there\n",bits256_str(str,hash2),bp->bundleheight,bundlei,bp->blocks[bundlei]);
                otherbp = 0, otherbundlei = -2;
                if ( (otherbp= iguana_bundlefind(coin,&otherbp,&otherbundlei,hash2)) != 0 || (bundlei % (bundlesize-1)) == 0)
                {
                    if ( bundlei == 0 && (otherbundlei == -2 || otherbundlei == bundlesize-1) )
                    {
                        if ( otherbp != 0 && iguana_hash2set(coin,"blockadd0_prev",bp,-1,otherbp->hashes[0]) != 0 )
                            err |= 4;
                        if ( otherbp != 0 && iguana_hash2set(coin,"blockadd0_next",otherbp,bundlesize,bp->hashes[0]) != 0 )
                            err |= 8;
                    }
                    else if ( bundlei == bundlesize-1 && (otherbundlei == -2 || otherbundlei == 0) )
                    {
                        if ( otherbp != 0 && iguana_hash2set(coin,"blockaddL_prev",otherbp,-1,bp->hashes[0]) != 0 )
                            err |= 16;
                        if ( otherbp != 0 && iguana_hash2set(coin,"blockaddL_next",bp,bundlesize,otherbp->hashes[0]) != 0 )
                            err |= 32;
                    }
                    //else printf("blockadd warning: %d[%d] bloomfound %d[%d]\n",bp->hdrsi,bundlei,otherbp!=0?otherbp->hdrsi:-1,otherbundlei);
                }
            }
        }
        else if ( setval == 1 )
        {
            if ( bundlei == -1 && iguana_hash2set(coin,"blockadd_m1",bp,-1,hash2) != 0 )
                err |= 4;
            if ( bundlei == bundlesize && iguana_hash2set(coin,"blockaddL_m1",bp,bundlesize,hash2) != 0 )
                err |= 4;
        }
        else if ( setval < 0 )
        {
            static uint32_t counter;
            if ( counter++ < 100 )
                printf("%s neg setval error\n",coin->symbol);
            err |= 64;
        }
        if ( err == 0 && blockp != 0 )
            *blockp = block;
    } else err |= 128;
    if ( err != 0 )
    {
        static uint32_t counter;
        if ( counter++ < 10 )
            printf("bundlehash2add err.%d\n",err);
        //return(0);
    }
    return(-err);
}

struct iguana_bundle *iguana_bundlecreate(struct iguana_info *coin,int32_t *bundleip,int32_t bundleheight,bits256 bundlehash2,bits256 allhash,int32_t issueflag)
{
    char str[65]; struct iguana_bundle *prevbp,*bp = 0;
    if ( bits256_nonz(bundlehash2) > 0 )
    {
        bits256_str(str,bundlehash2);
        bp = 0, *bundleip = -2;
        if ( iguana_bundlefind(coin,&bp,bundleip,bundlehash2) != 0 )
        {
            if ( bp->bundleheight >= 0 && bp->bundleheight != (bundleheight - *bundleip) )
            {
                printf("bundlecreate warning: bp->bundleheight %d != %d (bundleheight %d - %d bundlei)\n",bp->bundleheight,(bundleheight - *bundleip),bundleheight,*bundleip);
                return(0);
            }
            else if ( bits256_nonz(bp->allhash) == 0 )
                bp->allhash = allhash;
            return(bp);
        }
        bp = mycalloc('b',1,sizeof(*bp));
        bp->n = coin->chain->bundlesize;
        bp->hdrsi = bundleheight / coin->chain->bundlesize;
        bp->bundleheight = bundleheight;
        bp->allhash = allhash;
        iguana_hash2set(coin,"create",bp,0,bundlehash2);
        if ( iguana_bundlehash2add(coin,0,bp,0,bundlehash2) == 0 )
        {
            bp->coin = coin;
            bp->avetime = coin->avetime * 2.;
            coin->bundles[bp->hdrsi] = bp;
            if ( bp->hdrsi > 0 )
            {
                if ( (prevbp= coin->bundles[bp->hdrsi-1]) != 0 )
                {
                    prevbp->nextbp = bp;
                    prevbp->nextbundlehash2 = bundlehash2;
                }
            }
            *bundleip = 0;
            bits256_str(str,bundlehash2);
            char dirname[1024]; int32_t subdir;
            subdir = bp->bundleheight / IGUANA_SUBDIRDIVISOR;
            sprintf(dirname,"%s/%s/%d",GLOBAL_TMPDIR,coin->symbol,subdir), OS_ensure_directory(dirname);
            sprintf(dirname,"%s/%s/%d/%d",GLOBAL_TMPDIR,coin->symbol,subdir,bp->bundleheight), OS_ensure_directory(dirname);
            //sprintf(dirname,"DB/%s/%d",coin->symbol,bp->bundleheight), OS_ensure_directory(dirname);
            //printf("%s ht.%d alloc.[%d] new hdrs.%s\n",coin->symbol,bp->bundleheight,coin->bundlescount,bits256_str(str,bp->hashes[0]));
            iguana_bundlehash2add(coin,0,bp,0,bundlehash2);
            if ( issueflag != 0 )
            {
                iguana_blockQ("bundlecreate",coin,bp,0,bundlehash2,1);
                //queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(str),1);
            }
            if ( bp->hdrsi >= coin->bundlescount )
                coin->bundlescount = (bp->hdrsi + 1);
        }
        else
        {
            printf("error adding bundlehash2 bundleheight.%d\n",bundleheight);
            myfree(bp,sizeof(*bp));
            bp = 0;
        }
        return(bp);
    } else printf("cant create bundle with zerohash\n");
    //else printf("iguana_hdrscreate cant find hdr with %s or %s\n",bits256_str(bundlehash2),bits256_str2(firstblockhash2));
    return(0);
}

int32_t iguana_bundlefname(struct iguana_info *coin,struct iguana_bundle *bp,char *fname)
{
    int32_t hdrsi; static bits256 zero;
    iguana_peerfname(coin,&hdrsi,"DB",fname,0,bp->hashes[0],zero,bp->n,1);
    if ( hdrsi == bp->hdrsi )
        return(0);
    else
    {
        fname[0] = 0;
        return(-1);
    }
}

struct iguana_txid *iguana_bundletx(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,struct iguana_txid *tx,int32_t txidind)
{
    static const bits256 zero;
    int32_t hdrsi,iter; struct iguana_txid *T; int64_t Toffset; char fname[1024]; FILE *fp; struct iguana_ramchaindata rdata,*rptr;
    portable_mutex_lock(&coin->special_mutex);
    if ( (rptr= bp->ramchain.H.data) != 0 )//|| (bp == coin->current && (rptr= coin->RTramchain.H.data) != 0) )
    {
        T = RAMCHAIN_PTR(rptr,Toffset);
        *tx = T[txidind];
        portable_mutex_unlock(&coin->special_mutex);
        return(tx);
    }
    portable_mutex_unlock(&coin->special_mutex);
    printf("bundletx without ramchain\n");
    for (iter=0; iter<2; iter++)
    {
        iguana_peerfname(coin,&hdrsi,iter==0?"DB/ro":"DB",fname,0,bp->hashes[0],zero,bp->n,1);
        if ( (fp= fopen(fname,"rb")) != 0 )
        {
#if defined(_M_X64)
			fseek(fp, (uint64_t)&rdata.Toffset - (uint64_t)&rdata, SEEK_SET);
#else
            fseek(fp,(long)&rdata.Toffset - (long)&rdata,SEEK_SET);
#endif
            if ( fread(&Toffset,1,sizeof(Toffset),fp) == sizeof(Toffset) )
            {
                fseek(fp,Toffset + sizeof(struct iguana_txid) * txidind,SEEK_SET);
                if ( fread(tx,1,sizeof(*tx),fp) == sizeof(*tx) )
                {
                    fclose(fp);
                    return(tx);
                } else printf("bundletx read error\n");
            } else printf("bundletx Toffset read error\n");
            fclose(fp);
        }
    }
    printf("bundletx couldnt open.(%s)\n",fname);
    return(0);
}

char *iguana_bundleaddrs(struct iguana_info *coin,int32_t hdrsi)
{
    uint8_t *PKbits; struct iguana_pkhash *P; uint32_t pkind,numpkinds; struct iguana_bundle *bp; struct iguana_ramchain *ramchain; struct iguana_ramchaindata *rdata; cJSON *retjson; char rmdstr[41];
    if ( (bp= coin->bundles[hdrsi]) != 0 )
    {
        if ( (0) && coin->RTramchain_busy != 0 )
        {
            printf("iguana_bundleaddrs: unexpected access when RTramchain_busy\n");
            return(0);
        }
        ramchain = &bp->ramchain;//(bp->isRT != 0) ? &bp->ramchain : &coin->RTramchain;
        if ( (rdata= ramchain->H.data) != 0 )
        {
            numpkinds = rdata->numpkinds;//(bp->isRT != 0) ? rdata->numpkinds : ramchain->pkind;
            retjson = cJSON_CreateArray();
            PKbits = RAMCHAIN_PTR(rdata,PKoffset);
            P = RAMCHAIN_PTR(rdata,Poffset);
            for (pkind=0; pkind<numpkinds; pkind++,P++)
            {
                init_hexbytes_noT(rmdstr,P->rmd160,20);
                jaddistr(retjson,rmdstr);
            }
            return(jprint(retjson,1));
        }
        //iguana_bundleQ(coin,bp,bp->n);
        return(clonestr("{\"error\":\"no bundle data\"}"));
    } return(clonestr("{\"error\":\"no bundle\"}"));
}

void iguana_bundlepurgefiles(struct iguana_info *coin,struct iguana_bundle *bp)
{
    static const bits256 zero;
    char fname[1024]; FILE *fp; int32_t recvlen,numtx,subdir,hdrsi,j,lasti,i,m = 0; uint32_t ipbits = 0;
    if ( coin->current != 0 )
        lasti = coin->current->hdrsi;
    else lasti = 0;
    if ( coin->virtualchain != 0 || (bp->purgetime == 0 && time(NULL) > bp->emitfinish+600 && bp->hdrsi < lasti-2) )
    {
        for (j=m=0; j<bp->n; j++)
        {
            portable_mutex_lock(&coin->RTmutex);
            recvlen = -1;
            iguana_RTrawdata(coin,bp->hashes[j],0,&recvlen,&numtx,0); // delete file
            portable_mutex_unlock(&coin->RTmutex);
            if ( iguana_peerfname(coin,&hdrsi,GLOBAL_TMPDIR,fname,ipbits,bp->hashes[j],zero,1,1) >= 0 )
            {
                if ( (fp= fopen(fname,"rb")) != 0 )
                {
                    //printf("purge.(%s)\n",fname);
                    fclose(fp);
                    if ( OS_removefile(fname,0) > 0 )
                    {
                        if ( coin->peers != 0 )
                            coin->peers->numfiles--;
                        m++;
                    }
                }
            }
            else printf("error removing.(%s)\n",fname);
        }
        subdir = bp->bundleheight / IGUANA_SUBDIRDIVISOR;
        sprintf(fname,"%s/%s/%d/%d",GLOBAL_TMPDIR,coin->symbol,subdir,bp->bundleheight), OS_remove_directory(fname);
        //printf("purged hdrsi.[%d] subdir.%d lag.%ld\n",bp->hdrsi,subdir,time(NULL) - bp->emitfinish);
        bp->purgetime = (uint32_t)time(NULL);
        if ( (0) )
        {
            for (i=subdir*IGUANA_SUBDIRDIVISOR; i<(subdir+1)*IGUANA_SUBDIRDIVISOR; i++)
            {
                if ( (bp= coin->bundles[i]) != 0 && time(NULL) < bp->emitfinish+10 )
                {
                    printf("subdir.%d [%d] emit not confirmed\n",subdir,i);
                    return;
                }
            }
            printf("remove subdir.%d\n",subdir);
            sprintf(fname,"%s/%s/%d",GLOBAL_TMPDIR,coin->symbol,subdir), OS_remove_directory(fname);
        }
    }
}

uint8_t iguana_recentpeers(struct iguana_info *coin,int32_t *capacityp,struct iguana_peer *peers[])
{
    struct iguana_peer *addr; uint8_t m; int32_t capacity,i,n;
    if ( coin->peers == 0 )
        return(0);
    n = coin->peers->numranked;
    for (i=m=capacity=0; i<n&&m<0xff; i++)
    {
        if ( (addr= coin->peers->ranked[i]) != 0 && addr->dead == 0 && addr->usock >= 0 && addr->msgcounts.verack != 0 && addr->pendblocks < coin->MAXPENDINGREQUESTS )
        {
            if ( peers != 0 )
                peers[m] = addr;
            m++;
            capacity += (coin->MAXPENDINGREQUESTS - addr->pendblocks);
        }
    }
    *capacityp = capacity;
    return(m);
}

struct iguana_block *iguana_bundleblock(struct iguana_info *coin,bits256 *hash2p,struct iguana_bundle *bp,int32_t i)
{
    struct iguana_bundle *nextbp; struct iguana_block *block = 0;
    memset(hash2p,0,sizeof(*hash2p));
    if ( bp == 0 )
        return(0);
    if ( i == bp->n )
    {
        if ( bits256_nonz(bp->nextbundlehash2) != 0 )
        {
            if ( bp->hdrsi < coin->bundlescount && (nextbp= coin->bundles[bp->hdrsi+1]) != 0 )
            {
                *hash2p = nextbp->hashes[0];
                return(nextbp->blocks[0]);
            }
        } else return(0);
    }
    if ( (block= bp->blocks[i]) != 0 && bits256_nonz(block->RO.hash2) != 0 )
    {
        *hash2p = block->RO.hash2;
        return(block);
    }
    else if ( bp->speculative != 0 && bits256_nonz(bp->speculative[i]) != 0 )
    {
        *hash2p = bp->speculative[i];
        //block = bp->blocks[i];//iguana_blockfind("speculative",coin,bp->speculative[i]);
        //char str[65]; printf("[%d:%d] %s\n",bp->hdrsi,i,bits256_str(str,*hash2p));
    }
    return(block);
}

/*int32_t iguana_sendhashes(struct iguana_info *coin,struct iguana_peer *addr,int32_t msgtype,bits256 hashes[],int32_t n,int32_t priority)
{
    int32_t len; uint8_t *serialized;
    if ( addr->usock >= 0 && addr->dead == 0 && priority > 1 )
    {
        serialized = malloc((sizeof(int32_t) + sizeof(*hashes))*n + 1024);
        if ( (len= iguana_getdata(coin,serialized,MSG_BLOCK,hashes,n)) > 0 )
        {
            if ( len > (sizeof(int32_t) + sizeof(*hashes))*n + 1024 )
            {
                printf("FATAL ERROR iguana_sendhashes: len.%d size.%ld\n",len,(sizeof(int32_t) + sizeof(*hashes))*n + 1024);
 iguana_exit(myinfo);
            }
            iguana_send(coin,addr,serialized,len);
            coin->numreqsent += n;
            addr->pendblocks += n;
            addr->pendtime = (uint32_t)time(NULL);
            printf("sendhashes[%d] -> %s\n",n,addr->ipaddr);
        } else n = 0;
        free(serialized);
    }
    else
    {
        int32_t i;
        for (i=0; i<n; i++)
        {
            //if ( priority == 1 )
                iguana_sendblockreqPT(coin,addr,0,-1,hashes[i],0);
            //else iguana_blockQ("sendhash",coin,0,-1,hashes[i],1);
        }
        printf("sendhashes[%d]\n",n);
    }
    return(n);
}*/

int32_t iguana_bundleissuemissing(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp,int32_t priority,double mult)
{
    int32_t i,max,nonz,starti,lasti,firsti,lag,num,n=0; uint32_t now; bits256 hash2; double aveduration; struct iguana_peer *addr; char str[65]; //struct iguana_block *block;
    if ( coin->peers == 0 )
    {
        printf("%s has no peers\n",coin->symbol);
        return(0);
    }
    starti = coin->current == 0 ? 0 : coin->current->hdrsi;
    lasti = coin->lastpending == 0 ? coin->bundlescount-1 : coin->lastpending->hdrsi;
    if ( bp->hdrsi < starti || bp->hdrsi > lasti || bp->emitfinish != 0 )//|| ((priority > 0 || bp == coin->current) && time(NULL) < bp->missingstime+3) )
    {
        //printf("bp->hdrsi %d < %d starti || bp->hdrsi %d  > %d lasti || bp->emitfinish %d != 0\n",bp->hdrsi,starti,bp->hdrsi,lasti,bp->emitfinish);
        return(0);
    }
    bp->missingstime = (uint32_t)time(NULL);
    if ( bp->durationscount != 0 )
    {
        aveduration = (double)bp->totaldurations / bp->durationscount;
        if ( (rand() % 100000) == 0 )
            printf("priority.%d [%d] durations %.2f counts[%d %d] \n",priority,bp->hdrsi,aveduration,(int32_t)bp->durationscount,bp->duplicatescount);
    } else aveduration = IGUANA_DEFAULTLAG;
    lag = aveduration * mult;
    if ( bp != coin->current && lag < 60 )
        lag = 60;
    else if ( lag < 30 )
        lag = 30;
    if ( strcmp(coin->symbol,"BTC") != 0 )
        lag /= 10;
    if ( (num= coin->peers->numranked) == 0 )
        iguana_updatemetrics(myinfo,coin);
    if ( (num= coin->peers->numranked) != 0 )
    {
        if ( num > 64 )
            max = log2(num * num) + 1;
        else max = num;
        if ( max < IGUANA_MINPEERS )
            max = IGUANA_MINPEERS;
        if ( max > num )
            max = num;
        now = (uint32_t)time(NULL);
        lasti = firsti = -1;
        for (i=nonz=0; i<bp->n; i++)
        {
            //if ( (block= bp->blocks[i]) != 0 && block->txvalid != 0 && block->mainchain != 0 )
            //    continue;
            if ( GETBIT(bp->haveblock,i) != 0 )
                continue;
            nonz++;
            if ( firsti < 0 )
                firsti = i;
            lasti = i;
            if ( 1 )
            {
                iguana_bundleblock(coin,&hash2,bp,i);
                if ( bits256_nonz(hash2) != 0 )
                {
                     if ( (addr= coin->peers->ranked[rand() % max]) != 0 && addr->usock >= 0 && addr->dead == 0 && addr->msgcounts.verack > 0 )
                    {
                        iguana_sendblockreqPT(coin,0,bp,i,hash2,0);
                    }
                    struct iguana_blockreq *req = 0;
                    req = mycalloc('y',1,sizeof(*req));
                    req->hash2 = hash2;
                    req->bp = bp;
                    req->height = bp->bundleheight + i;
                    req->bundlei = i;
                    queue_enqueue("missing",&coin->priorityQ,&req->DL);
                    bp->issued[i] = 1;
                    n++;
                    if ( (0) && bp == coin->current )
                        printf("%s issuemissing.[%d:%d]\n",bits256_str(str,hash2),bp->hdrsi,i);
               } //else printf("[z%d] ",i);
            } //else printf("%d ",now - (bp->issued[i]+lag));
        }
        if ( firsti >= 0 )//&& bp == coin->current )
        {
            if ( (0) && bp == coin->current )
                printf("%s [%d] first missing.%d of %d\n",bits256_str(str,hash2),bp->hdrsi,firsti,nonz);
            iguana_bundleblock(coin,&hash2,bp,firsti);
            if ( bits256_nonz(hash2) != 0 )
            {
                if ( (addr= coin->peers->ranked[rand() % max]) != 0 && addr->usock >= 0 && addr->dead == 0 && addr->msgcounts.verack > 0 )
                {
                    //if ( bp == coin->current )
                      //  printf("iguana_bundleissuemissing.[%d:%d]\n",bp->hdrsi,i);
                    n++;
                    //printf("send reqPT [%d:%d]\n",bp->hdrsi,firsti);
                    iguana_sendblockreqPT(coin,0,bp,firsti,hash2,0);
                }
            } // else printf("no hash for [%d:%d]\n",bp->hdrsi,firsti);
        }
    }
    //if ( n > 0 || bp == coin->current )
    //    printf("issue.[%d] %d priority.%d\n",bp->hdrsi,n,priority);
    return(n);
}

int32_t iguana_blast(struct iguana_info *coin,struct iguana_peer *addr)
{
    struct iguana_bundle *bp,*lastbp; double aveduration; bits256 hash2; uint32_t now; int32_t i,m,ind,range,n = 0; struct iguana_blockreq *req = 0;
    m = 0;
    if ( (bp= coin->current) != 0 && (lastbp= coin->lastpending) != 0 && (range= (lastbp->hdrsi - bp->hdrsi + 1)) > 0 )
    {
        ind = bp->hdrsi + (addr->addrind % range);
        while ( ind < coin->bundlescount && n < IGUANA_PENDINGREQUESTS )
        {
            now = (uint32_t)time(NULL);
            if ( (bp= coin->bundles[ind++]) != 0 )
            {
                if ( bp == coin->current )
                    aveduration = 1;
                else
                {
                    if ( bp->durationscount != 0 )
                        aveduration = (double)bp->totaldurations / bp->durationscount;
                    else aveduration = IGUANA_DEFAULTLAG;
                }
                for (i=0; i<bp->n && n<IGUANA_PENDINGREQUESTS; i++)
                    if ( GETBIT(bp->haveblock,i) == 0 && now > bp->issued[i]+aveduration )
                    {
                        iguana_bundleblock(coin,&hash2,bp,i);
                        if ( bits256_nonz(hash2) != 0 )
                        {
                            n++;
                            bp->issued[i] = 0;
                            req = mycalloc('y',1,sizeof(*req));
                            req->hash2 = hash2;
                            req->bp = bp;
                            req->height = bp->bundleheight + i;
                            req->bundlei = i;
                            queue_enqueue("blast",&coin->priorityQ,&req->DL);
                        }
                    }
                if ( n > m )
                {
                    //printf("%s blasted.%d -> [%d]\n",addr->ipaddr,n-m,bp->hdrsi);
                    m = n;
                }
            }
        }
    }
    return(n);
}

int32_t iguana_bundleready(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp,int32_t requiredflag)
{
    static bits256 zero;
    int32_t i,ready,valid; char fname[1024]; struct iguana_block *block; int32_t sum[0x100],counts[0x100]; struct iguana_blockRO *B; struct iguana_bundle *nextbp; void *ptr; long filesize; struct iguana_ramchain R; bits256 prevhash2;
    memset(sum,0,sizeof(sum));
    memset(counts,0,sizeof(counts));
    if ( (0) && bp->queued == 0 )
    {
        for (i=ready=0; i<bp->n; i++)
            if ( (block= bp->blocks[i]) == 0 )
                break;
        if ( i < bp->n )
        {
            if ( (nextbp= coin->bundles[bp->hdrsi+1]) != 0 && (block= nextbp->blocks[0]) != 0 )
            {
                prevhash2 = block->RO.prev_block;
                for (i=bp->n-1; i>=0; i--)
                {
                    char str[65]; printf("[%d:%d] %s\n",bp->hdrsi,i,bits256_str(str,prevhash2));
                    if ( bp->blocks[i] == 0 && bits256_nonz(prevhash2) != 0 )
                    {
                        bp->hashes[i] = prevhash2;
                        bp->blocks[i] = iguana_blockhashset("ready",coin,bp->bundleheight+i,prevhash2,1);
                        iguana_hash2set(coin,"ready",bp,i,prevhash2);
                        prevhash2 = zero;
                        if ( (ptr= iguana_bundlefile(coin,fname,&filesize,bp,i,0)) != 0 )
                        {
                            if ( iguana_mapchaininit(fname,coin,&R,bp,i,block,ptr,filesize) >= 0 )
                            {
                                B = RAMCHAIN_PTR(R.H.data,Boffset);
                                //B = (void *)(long)((long)R.H.data + R.H.data->Boffset);
                                prevhash2 = B[0].prev_block;
                            }
                            munmap(ptr,filesize);
                        }
                    }
                    if ( bits256_nonz(prevhash2) == 0 )
                        break;
                }
                printf("reverse linked to [%d:%d]\n",bp->hdrsi,i);
            }
        }
    }
    for (i=ready=0; i<bp->n; i++)
    {
        if ( (block= bp->blocks[i]) != 0 )
        {
            if ( block->lag != 0 && block->peerid != 0 )
            {
                sum[block->peerid] += block->lag;
                counts[block->peerid]++;
            }
            //printf("(%x:%x) ",(uint32_t)block->RO.hash2.ulongs[3],(uint32_t)bp->hashes[i].ulongs[3]);
            if ( block->txvalid == 0 || block->fpipbits == 0 || block->fpos < 0 || (bp->bundleheight+i > 0 && bits256_nonz(block->RO.prev_block) == 0) || iguana_blockvalidate(myinfo,coin,&valid,block,1) < 0 )
            {
                char str[65];
                if ( requiredflag != 0 )
                    printf(">>>>>>> block contents error at ht.%d [%d:%d]\n",bp->bundleheight+i,bp->hdrsi,i);
                if ( (0) && bits256_nonz(block->RO.hash2) != 0 )
                    printf("patch.%d and reissue prev.%s  %d\n",bp->bundleheight+i,bits256_str(str,block->RO.prev_block),i);
                iguana_blockunmark(coin,block,bp,i,1);
            }
            else
            {
//#ifndef __PNACL__
                int32_t checki,hdrsi; FILE *fp;
                fname[0] = 0;
                checki = iguana_peerfname(coin,&hdrsi,GLOBAL_TMPDIR,fname,0,block->RO.hash2,zero,1,0);
                if ( hdrsi == bp->hdrsi && checki == i && (fp= fopen(fname,"rb")) != 0 )
                {
                    fseek(fp,0,SEEK_END);
                    if ( ftell(fp) > sizeof(struct iguana_ramchaindata) )
                    {
                        //printf("[%d:%d] %s %ld\n",bp->hdrsi,i,fname,ftell(fp));
                        ready++;
                    }
                    fclose(fp);
                }
                else if ( (0) )
//#endif
                {
                    iguana_blockunmark(coin,block,bp,i,1);
                    if ( (0) && requiredflag != 0 )
                        printf("not ready altpath.(%d %d %d %d %d) [%d:%d]\n",block->txvalid == 0,block->fpipbits == 0 ,block->fpos < 0,(bp->bundleheight+i > 0 && bits256_nonz(block->RO.prev_block) == 0),iguana_blockvalidate(myinfo,coin,&valid,block,1) < 0,bp->hdrsi,i);
                }
                else
                {
                    //iguana_blockunmark(coin,block,bp,i,0);
                    //printf("cant find (%s)\n",fname);
                }
            }
        }
        else
        {
            if ( requiredflag != 0 )
                printf("no block at [%d:%d]\n",bp->hdrsi,i);
            iguana_blockunmark(coin,block,bp,i,bp->queued != 0);
            if ( bp->queued != 0 )
            {
                //printf("error getting block (%d:%d) %p\n",bp->hdrsi,i,block);
                return(-1);
            }
        }
    }
    return(ready);
}

int32_t iguana_bundlehdr(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp,int32_t starti)
{
    int32_t i,dist,counter=0; char str[65];
    if ( (0) && bp->isRT == 0 && (bp->hdrsi == coin->bundlescount-1 || bp == coin->current) )
        printf("hdr ITERATE.%d bundle.%d vs %d: h.%d n.%d r.%d s.%d c.%d finished.%d spec.%p[%d]\n",bp->hdrsi,bp->bundleheight,coin->longestchain-coin->chain->bundlesize,bp->numhashes,bp->n,bp->numrecv,bp->numsaved,bp->numcached,bp->emitfinish,bp->speculative,bp->numspec);
    dist = 30 + (coin->current != 0 ? bp->hdrsi - coin->current->hdrsi : 0);
    if ( bp == coin->current )
        dist = 3;
    if ( time(NULL) > bp->hdrtime+dist && (bp == coin->current || bp->hdrsi >= coin->bundlescount-2 || (strcmp("BTC",coin->symbol) != 0 && bp->numhashes < bp->n && (bp->speculative == 0 || bp->hdrsi >= coin->longestchain/bp->n))) )
    {
        bp->hdrtime = (uint32_t)time(NULL);
        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(bits256_str(str,bp->hashes[0])));
    }
    if ( time(NULL) > bp->hdrtime+dist && strcmp("BTC",coin->symbol) != 0 && (bp == coin->current || bp->hdrsi == coin->bundlescount-1) && bits256_nonz(bp->nextbundlehash2) == 0 )
    {
        if ( bp->numhashes < bp->n && bp->numcached < bp->n )
        {
            //printf("issue current hdr.[%d]\n",bp->hdrsi);
            for (i=0; i<bp->n; i++)
                if ( GETBIT(bp->haveblock,i) == 0 )
                    bp->issued[i] = 0;
            bp->hdrtime = (uint32_t)time(NULL);
            queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(bits256_str(str,bp->hashes[0])));
        }
        iguana_bundleissuemissing(myinfo,coin,bp,3,3.);
        /*if ( bp == coin->current )
        {
            mult = 1.;
            printf("iguana_bundlehdr.[%d] %d %s\n",bp->hdrsi,bp->numspec,bits256_str(str,bp->hashes[0]));
        }*/
    }
    return(counter);
}

int32_t iguana_setmaxbundles(struct iguana_info *coin)
{
    double completed;
    if ( coin->current != 0 && coin->bundlescount != 0 )
    {
        completed = sqrt(((double)coin->current->hdrsi + 1) / coin->bundlescount);
        coin->MAXBUNDLES = (double)(coin->endPEND - coin->startPEND)*completed + coin->startPEND;
        //printf("MAXBUNDLES %d (%d -> %d) completed %.3f\n",coin->MAXBUNDLES,coin->startPEND,coin->endPEND,completed);
    }
    return(coin->MAXBUNDLES);
}

int32_t iguana_bundletweak(struct iguana_info *coin,struct iguana_bundle *bp)
{
    struct iguana_bundle *lastbp; int32_t i,pending;
    if ( coin->current == bp )
        coin->current = coin->bundles[bp->hdrsi+1];
    if ( (lastbp= coin->current) != 0 )
    {
        for (pending=0,i=lastbp->hdrsi+1; i<coin->bundlescount; i++)
        {
            if ( (lastbp= coin->bundles[i]) != 0 && lastbp->emitfinish == 0 )
            {
                if ( ++pending == coin->MAXBUNDLES )
                    break;
            }
        }
        coin->lastpending = lastbp;
    }
    iguana_setmaxbundles(coin);
    return(coin->MAXBUNDLES);
}

int64_t iguana_bundlecalcs(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp,int32_t lag)
{
    int32_t bundlei,numhashes,numsaved,numrecv,numcached,minrequests; int64_t datasize; struct iguana_block *block;
    if ( bp->emitfinish > 0 && (bp->ramchain.H.data != 0 || iguana_bundleready(myinfo,coin,bp,0) == bp->n)  )
    {
        memset(bp->haveblock,0xff,sizeof(bp->haveblock));
        bp->numhashes = bp->numsaved = bp->numcached = bp->numrecv = bp->n;
        return(bp->datasize);
    }
    memset(bp->haveblock,0,sizeof(bp->haveblock));
    datasize = numhashes = numsaved = numrecv = numcached = minrequests = 0;
    for (bundlei=0; bundlei<bp->n; bundlei++)
    {
        if ( bits256_nonz(bp->hashes[bundlei]) != 0 )
        {
            numhashes++;
            if ( bp->speculativecache[bundlei] != 0 )
                numcached++;
            if ( (block= bp->blocks[bundlei]) != 0 )
            {
                if ( bits256_cmp(block->RO.hash2,bp->hashes[bundlei]) == 0 )
                {
                    //if ( bp->minrequests == 0 || (block->numrequests > 0 && block->numrequests < bp->minrequests) )
                    //    bp->minrequests = block->numrequests;
                    if ( block->fpipbits != 0 && block->txvalid != 0 && block->fpos >= 0 && (bp->bundleheight+bundlei == 0 || bits256_nonz(block->RO.prev_block) != 0) )
                    {
                        SETBIT(bp->haveblock,bundlei);
                        numsaved++;
                    }
                    if ( block->RO.recvlen != 0 )
                    {
                        numrecv++;
                        datasize += block->RO.recvlen;
                    }
                }
                else if ( (0) && bits256_nonz(block->RO.hash2) != 0 && bits256_nonz(bp->hashes[bundlei]) != 0 )
                {
                    printf("hash mismatch [%d:%d]\n",bp->hdrsi,bundlei);
                    iguana_blockunmark(coin,block,bp,bundlei,1);
                    if ( bundlei < coin->chain->bundlesize-1 )
                    {
                        if ( (block= iguana_blockfind("mismatch",coin,bp->hashes[bundlei+1])) != 0 )
                        {
                            if ( block->mainchain != 0 )
                            {
                                bp->hashes[bundlei] = block->RO.prev_block;
                                printf("patch [%d:%d] from next block\n",bp->hdrsi,bundlei);
                            }
                        }
                    }
                }
            } //else printf("[null %d:%d] ",bp->hdrsi,bundlei);
        }
    }
    bp->numcached = numcached;
    if ( (0) && bp->numcached != numsaved )
        printf("[%d] emit.%u ramchain.%p numcached.%d vs numsaved.%d numhashes.%d\n",bp->hdrsi,bp->emitfinish,bp->ramchain.H.data,bp->numcached,numsaved,numhashes);
    bp->datasize = datasize;
    bp->numhashes = numhashes;
    bp->numsaved = numsaved;
    bp->numrecv = numrecv;
    bp->minrequests = minrequests;
    bp->estsize = ((int64_t)bp->datasize * bp->n) / (bp->numrecv+1);
    return(bp->estsize);
}

/*int32_t iguana_bundlefinish(struct iguana_info *coin,struct iguana_bundle *bp)
 {
 struct iguana_bundle *prevbp; int32_t i;
 #ifdef IGUANA_SERIALIZE_SPENDVECTORGEN
 if ( ((prevbp= coin->current) != 0 && prevbp->hdrsi < (coin->longestchain / coin->chain->bundlesize)) || coin->numemit < prevbp->hdrsi )
 return(0);
 #endif
    for (i=0; i<bp->hdrsi; i++)
        if ( (prevbp= coin->bundles[i]) == 0 || prevbp->emitfinish <= 1 || (prevbp->utxofinish == 0 && prevbp->tmpspends == 0) )
            break;
    if ( bp->hdrsi < coin->blocks.hwmchain.height/coin->chain->bundlesize && i >= bp->hdrsi-(IGUANA_NUMHELPERS>>1) && time(NULL) > bp->emitfinish+3 )
    {
        //printf("[%d] vs %d i.%d vs %d emitted.%ld (%d %d %d) s.%u f.%u\n",bp->hdrsi,coin->blocks.hwmchain.height/coin->chain->bundlesize,i,bp->hdrsi-IGUANA_NUMHELPERS/2,time(NULL) - bp->emitfinish,bp->hdrsi < coin->blocks.hwmchain.height/coin->chain->bundlesize,i >= bp->hdrsi-IGUANA_NUMHELPERS, time(NULL) > bp->emitfinish,bp->startutxo,bp->utxofinish);
        if ( bp->startutxo == 0 )
        {
            bp->startutxo = (uint32_t)time(NULL);
            //printf("spendvectorsQ.%d\n",bp->hdrsi);
            iguana_spendvectorsQ(coin,bp);
        }
        else if ( bp->utxofinish != 0 )
        {
            if ( bp->balancefinish == 0 )
                iguana_balancesQ(coin,bp);
        }
        return(1);
    }
    //else printf("%u notready.%d postfinish.%d startutxo.%u prevbp.%d %u current.%d\n",(uint32_t)time(NULL),bp->hdrsi,i,bp->startutxo,prevbp!=0?prevbp->hdrsi:-1,prevbp!=0?prevbp->emitfinish:0,coin->current!=0?coin->current->hdrsi:-1);
    return(0);
}*/

int32_t iguana_bundlefinalize(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp,struct OS_memspace *mem,struct OS_memspace *memB)
{
    int32_t i; struct iguana_bundle *tmpbp; struct iguana_blockreq *breq;
    if ( coin->firstRTheight == 0 && iguana_bundleready(myinfo,coin,bp,0) == bp->n )
    {
        printf(">>>>>>>>>>>>>> EMIT.[%3d] %s | 1st.%-3d h.%-3d c.%-3d s.[%3d] maxB.%d NET.(h%d b%d) %u:%02u\n",bp->hdrsi,coin->symbol,coin->current!=0?coin->current->hdrsi:-1,coin->current!=0?coin->current->numhashes:-1,coin->current!=0?coin->current->numcached:-1,coin->current!=0?coin->current->numsaved:-1,coin->MAXBUNDLES,HDRnet,queue_size(&coin->priorityQ),(uint32_t)(time(NULL)-coin->startutc)/60,(uint32_t)(time(NULL)-coin->startutc)%60);
        if ( queue_size(&coin->priorityQ) > 10000 )
        {
            while ( (breq= queue_dequeue(&coin->priorityQ)) != 0 )
                myfree(breq,sizeof(*breq));
            //printf("cleared priorityQ\n");
        }
        if ( bp->emitfinish != 0 )
        {
            printf("already EMIT for bundle.%d\n",bp->hdrsi);
            //return(0);
        }
        bp->emitfinish = 1;
        usleep(100000); // make sure new incoming packet didnt overwrite
        if ( iguana_bundleready(myinfo,coin,bp,1) == bp->n )
        {
            usleep(100000); // make sure new incoming packet didnt overwrite
            coin->emitbusy++;
            if ( iguana_bundlesaveHT(myinfo,coin,mem,memB,bp,(uint32_t)time(NULL)) == 0 )
            {
                //fprintf(stderr,"emitQ done coin.%p bp.[%d] ht.%d\n",coin,bp->hdrsi,bp->bundleheight);
                bp->emitfinish = (uint32_t)time(NULL) + 1;
                iguana_bundletweak(coin,bp);
                coin->numemitted++;
                for (i=0; i<bp->n; i++)
                    iguana_hash2set(coin,"bundlefinalize",bp,i,bp->hashes[i]);
                /*if ( bp->hdrsi == 0 && iguana_peerblockrequest(coin,coin->blockspace,coin->blockspacesize,0,bp->hashes[0],1) > 0 )
                    printf("GENESIS block validated\n");
                else printf("GENESIS didnt validate bp.%p\n",bp);*/
                //if ( strcmp("BTC",coin->symbol) != 0 )
                coin->RTheight = coin->firstRTheight = 0;
                //coin->spendvectorsaved = 0;
                for (i=0; i<coin->bundlescount; i++)
                    if ( (tmpbp= coin->bundles[i]) != 0 )
                        tmpbp->converted = tmpbp->balancefinish = 0;
#ifdef __PNACL__
                iguana_bundlevalidate(myinfo,coin,bp,1);
#endif
            }
            else
            {
                fprintf(stderr,"emitQ done coin.%p bp.[%d] ht.%d error\n",coin,bp->hdrsi,bp->bundleheight);
                bp->emitfinish = 0;
                coin->emitbusy--;
                return(0);
            }
            coin->emitbusy--;
        }
        else
        {
            bp->emitfinish = 0;
            printf("interloper! [%d] save interupted, will retry next iteration\n",bp->hdrsi);
        }
        return(1);
    }
    else
    {
        //printf("bundlefinalize.[%d] not ready\n",bp->hdrsi);
        //iguana_bundleremove(coin,bp->hdrsi,1);
    }
    return(0);
}

int32_t iguana_bundleiters(struct supernet_info *myinfo,struct iguana_info *coin,struct OS_memspace *mem,struct OS_memspace *memB,struct iguana_bundle *bp,int32_t timelimit,int32_t lag)
{
    int32_t range,starti,lasti,retval=0,max,counter = 0; struct iguana_bundle *currentbp,*lastbp;
    if ( coin->started == 0 || coin->active == 0 )
    {
        printf("%s not ready yet\n",coin->symbol);
        bp->nexttime = (uint32_t)time(NULL) + 1;
        iguana_bundleQ(myinfo,coin,bp,1000);
        return(retval);
    }
    if ( coin->current == 0 )
        coin->current = coin->bundles[0];
    range = coin->MAXBUNDLES;
    currentbp = coin->current;
    lastbp = coin->lastpending;
    starti = currentbp == 0 ? 0 : currentbp->hdrsi;
    lasti = lastbp == 0 ? coin->bundlescount-1 : lastbp->hdrsi;
    range = lasti - starti + 1;
    iguana_bundlecalcs(myinfo,coin,bp,lag);
    if ( coin->blockdepth == 0 && coin->blockdepth == 0 && bp->hdrsi == coin->bundlescount-1 )
        iguana_autoextend(myinfo,coin,bp);
    if ( (0) && bp->hdrsi == 0 )
        printf("ITER utxo.%u now.%u spec.%-4d bundle.%-4d h.%-4d r.%-4d s.%-4d F.%d T.%d issued.%d mb.%d/%d\n",bp->utxofinish,(uint32_t)time(NULL),bp->numspec,bp->bundleheight/coin->chain->bundlesize,bp->numhashes,bp->numrecv,bp->numsaved,bp->emitfinish,timelimit,counter,coin->MAXBUNDLES,coin->bundlescount);
    bp->nexttime = (uint32_t)time(NULL) + ((bp->hdrsi > starti) ? 0 : -2);
    if ( bp->hdrsi == coin->bundlescount-1 || (bp->numhashes < bp->n && bp->bundleheight < coin->longestchain-coin->chain->bundlesize) )
        iguana_bundlehdr(myinfo,coin,bp,starti);
    else if ( bp->emitfinish == 0 && bp->numsaved >= bp->n )
    {
        if ( coin->virtualchain != 0 )//|| iguana_bundlefinalize(myinfo,coin,bp,mem,memB) > 0 )
        {
            //printf("bundlefinalized done.[%d]\n",bp->hdrsi);
            return(0);
        }
        retval = 1;
    }
    else if ( bp->hdrsi == starti || (bp->hdrsi >= starti && bp->hdrsi <= starti+range) )
    {
        max = bp->n;
        counter = iguana_bundleissuemissing(myinfo,coin,bp,1,3.);
        if ( (0) && counter > 0 )
            printf("starti.%d range.%d now.%u spec.%-4d bundle.%-4d h.%-4d r.%-4d s.%-4d F.%d T.%d issued.%d mb.%d/%d\n",starti,range,(uint32_t)time(NULL),bp->numspec,bp->bundleheight/coin->chain->bundlesize,bp->numhashes,bp->numrecv,bp->numsaved,bp->emitfinish,timelimit,counter,coin->MAXBUNDLES,coin->bundlescount);
    } else bp->nexttime++;
    if ( (0) && bp->emitfinish <= 1 )
        iguana_bundleQ(myinfo,coin,bp,1000);
    else
    {
        //printf("[%d] not queued\n",bp->hdrsi);
        bp->queued = 0;
    }
    return(retval);
}

/*static int _decreasing_double(const void *a,const void *b)
{
#define double_a (*(double *)a)
#define double_b (*(double *)b)
	if ( double_b > double_a )
		return(1);
	else if ( double_b < double_a )
		return(-1);
	return(0);
#undef double_a
#undef double_b
}

static int32_t revsortds(double *buf,uint32_t num,int32_t size)
{
	qsort(buf,num,size,_decreasing_double);
	return(0);
}*/

int32_t iguana_cacheprocess(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei)
{
    int32_t recvlen; struct iguana_msghdr H; uint8_t *data; struct iguana_block *block;
    if ( (data= bp->speculativecache[bundlei]) != 0 && bp->speculative != 0 && (block= iguana_blockfind("cacheprocess",coin,bp->speculative[bundlei])) != 0 && block->processed == 0 )
    {
        block->processed = 1;
        bp->speculativecache[bundlei] = 0;
        iguana_bundlehash2add(coin,0,bp,bundlei,block->RO.hash2);
        recvlen = *(int32_t *)data;
        //char str[65]; printf("iguana_cacheprocess [%d:%d] %s fp.%x len.%d:%d\n",bp->hdrsi,bundlei,bits256_str(str,bp->hashes[bundlei]),block->fpipbits,block->RO.recvlen,recvlen);
        memset(&H,0,sizeof(H));
        if ( iguana_sethdr(&H,coin->chain->netmagic,"block",&data[sizeof(recvlen)],recvlen) > 0 )
        {
            iguana_peer_meminit(coin,&coin->internaladdr);
            if ( iguana_msgparser(myinfo,coin,&coin->internaladdr,&coin->internaladdr.RAWMEM,&coin->internaladdr.TXDATA,&coin->internaladdr.HASHMEM,&H,&data[sizeof(recvlen)],recvlen,1) < 0 )
                printf("error parsing speculativecache.[%d:%d]\n",bp->hdrsi,bundlei);
        }
        free(data);
        return(recvlen);
    }
    return(-1);
}

void iguana_unstickhdr(struct iguana_info *coin,struct iguana_bundle *bp,int32_t lag)
{
    int32_t datalen,m,i; uint8_t serialized[512]; char str[65]; struct iguana_peer *addr;
    if ( coin->peers == 0 )
        return;
    if ( (m= coin->peers->numranked) > 0 && bp->numhashes < bp->n && bp->hdrsi < coin->longestchain/coin->chain->bundlesize && time(NULL) > bp->unsticktime+lag )
    {
        for (i=0; i<10; i++)
        if ( (addr= coin->peers->ranked[rand() % m]) != 0 && addr->usock >= 0 && addr->dead == 0 && (datalen= iguana_gethdrs(coin,serialized,coin->chain->gethdrsmsg,bits256_str(str,bp->hashes[0]))) > 0 )
        {
            //printf("UNSTICK HDR.[%d]\n",bp->hdrsi);
            iguana_send(coin,addr,serialized,datalen);
            addr->pendhdrs++;
            bp->unsticktime = (uint32_t)time(NULL);
            break;
        }
    }
}

void iguana_bundlemissings(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp,uint32_t now)
{
    int32_t mult = 7,n=0,priority = 1;
    if ( now > bp->missingstime+13 )
    {
        if ( coin->current != 0 )
        {
            mult = bp->hdrsi - coin->current->hdrsi;
            if ( mult < 4 )
                mult = 4;
            else if ( mult > 7 )
                mult = 7;
        } else mult = 2;
        if ( coin->bandwidth < .7*coin->maxbandwidth )
        {
            mult--;
            if ( coin->bandwidth < .6*coin->maxbandwidth )
            {
                if ( coin->bandwidth < .5*coin->maxbandwidth )
                {
                    mult--;
                    if ( coin->bandwidth < .4*coin->maxbandwidth )
                    {
                        mult--;
                        if ( coin->bandwidth < .3*coin->maxbandwidth )
                        {
                            mult--;
                            if ( coin->bandwidth < 0.25*coin->maxbandwidth )
                                priority = 3;
                        }
                    }
                }
            }
            if ( mult < 1 )
                mult = 1;
        }
        if ( (n= iguana_bundleissuemissing(myinfo,coin,bp,priority,mult)) > 0 )
        {
            //printf("bundle.[%d] n.%d issued.%d lag.%d\n",bp->hdrsi,n,bp->numissued,now-bp->missingstime);
            bp->numissued += n;
            bp->missingstime = (uint32_t)time(NULL);
        }
    }
}

int32_t iguana_bundlehash2_check(struct iguana_info *coin,bits256 hash2)
{
    struct iguana_bundle *bp; int32_t j,flag=0; struct iguana_block *block;
    if ( bits256_nonz(hash2) == 0 )
        return(-1);
    if ( (bp= coin->current) != 0 )
    {
        for (j=0; j<bp->n; j++)
        {
            if ( j < bp->numspec && bp->speculative != 0 && bits256_cmp(bp->speculative[j],hash2) == 0 )
            {
                flag = 1;
                if ( (block= iguana_blockfind("hashspec",coin,hash2)) != 0 )
                {
                    if ( block->mainchain != 0 && block->txvalid != 0 && block->hdrsi != bp->hdrsi )
                    {
                        printf("found [%d:%d] in [%d:%d]'s place\n",block->hdrsi,block->bundlei,bp->hdrsi,j);
                        memset(&bp->speculative[j],0,sizeof(bp->speculative[j]));
                    }
                }
                break;
            }
            if ( bits256_cmp(bp->hashes[j],hash2) == 0 )
            {
                flag = 1;
                if ( (block= iguana_blockfind("hashspec",coin,hash2)) != 0 )
                {
                    if ( block->mainchain != 0 && block->txvalid != 0 && block->hdrsi != bp->hdrsi )
                    {
                        printf("found [%d:%d] in [%d:%d]'s place\n",block->hdrsi,block->bundlei,bp->hdrsi,j);
                        memset(&bp->hashes[j],0,sizeof(bp->hashes[j]));
                        bp->blocks[j] = 0;
                    }
                }
                break;
            }
        }
    }
    return(flag);
}

void iguana_bundlestats(struct supernet_info *myinfo,struct iguana_info *coin,char *str,int32_t lag)
{
    int32_t i,n,m,j,numv,numconverted,count,starti,lasti,pending,capacity,displag,numutxo,numbalances,numrecv,done,numhashes,numcached,numsaved,numemit,numbQ=0; struct iguana_block *block; bits256 hash2; struct iguana_blockreq *breq;
    int64_t spaceused=0,estsize = 0; struct iguana_bundle *currentbp,*lastbp,*bp,*lastpending = 0,*firstgap = 0; uint32_t now;
    if ( coin->bundlescount <= 0 )
        return;
    now = (uint32_t)time(NULL);
    displag = (now - coin->lastdisp);
    numrecv = numhashes = numcached = numconverted = numsaved = numemit = done = numutxo = numbalances = 0;
    count = coin->bundlescount;
    currentbp = coin->current;
    lastbp = coin->lastpending;
    starti = currentbp == 0 ? 0 : currentbp->hdrsi;
    lasti = lastbp == 0 ? coin->bundlescount-1 : lastbp->hdrsi;
    iguana_recentpeers(coin,&capacity,0);
        //sortbuf = calloc(count,sizeof(*sortbuf)*2);
    for (i=n=m=numv=pending=0; i<count; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            if ( bp->converted != 0 )
                numconverted++;
            if ( bp->queued != 0 )
                numbQ++;
            if ( bp == coin->current && coin->blocks.hwmchain.height >= bp->bundleheight && coin->blocks.hwmchain.height < bp->bundleheight+bp->n )
            {
                for (j=coin->blocks.hwmchain.height-bp->bundleheight+1; j<=bp->n; j++)
                {
                    if ( (block= iguana_bundleblock(coin,&hash2,bp,j)) == 0 && bits256_nonz(hash2) != 0 )
                        block = iguana_blockfind("bundlestats",coin,hash2);
                    if ( block == 0 || bits256_nonz(block->RO.prev_block) == 0 || _iguana_chainlink(myinfo,coin,block) == 0 )
                        break;
                }
            }
            if ( bp->emitfinish > 1 )
            {
                for (j=0; j<bp->n; j++)
                {
                    if ( bp->blocks[j] == 0 && bits256_nonz(bp->hashes[j]) != 0 )
                        bp->blocks[j] = iguana_blockfind("bundlestats2",coin,bp->hashes[j]);
                }
            }
            else
            {
                if ( coin->enableCACHE != 0 )
                {
                    for (j=0; j<bp->n; j++)
                    {
                        if ( ((block= bp->blocks[j]) == 0 || bp == coin->current) && bp->speculativecache[j] != 0 )
                        {
                            if ( (block != 0 || (block= iguana_blockhashset("bundlestats3",coin,-1,bp->speculative[j],1)) != 0) && block->processed == 0 )
                                iguana_cacheprocess(myinfo,coin,bp,j);
                            numcached++;
                        }
                        if ( block != 0 && block->issued > 1 )
                            bp->issued[j] = block->issued;
                    }
                }
                if ( bp->hdrsi >= starti && bp->hdrsi < lasti )
                    iguana_bundlemissings(myinfo,coin,bp,now);
            }
            bp->metric = coin->bundlescount - bp->hdrsi;
            if ( done > coin->bundlescount*IGUANA_HEADPERCENTAGE && bp->hdrsi > coin->bundlescount*IGUANA_TAILPERCENTAGE )
                bp->metric *= 1000;
            iguana_bundlecalcs(myinfo,coin,bp,lag);
            estsize += bp->estsize;
            numhashes += bp->numhashes;
            numcached += bp->numcached;
            numrecv += bp->numrecv;
            numsaved += bp->numsaved;
            if ( bp->utxofinish > 1 )
                numutxo++;
            if ( bp->balancefinish > 1 )
                numbalances++;
            if ( bp->validated > 1 )
                numv++;
            if ( bp->emitfinish == 0 && bp->ramchain.H.data != 0 )
                bp->emitfinish = (uint32_t)time(NULL);
            if ( bp->emitfinish >= 1 )
            {
                if ( bp->emitfinish == 1 )
                    done++;
                else
                {
                    numemit++;
                    //printf("finished.[%d]\n",bp->hdrsi);
                    iguana_bundlepurgefiles(coin,bp);
                }
            }
            else
            {
                if ( firstgap == 0 && bp->queued == 0 && bp->numsaved < bp->n )
                    iguana_bundleQ(myinfo,coin,bp,1000);
                if ( firstgap == 0 && bp->numsaved < bp->n && bp->numcached < bp->n && (bp->ramchain.H.data == 0 || bp->hdrsi == coin->longestchain/coin->chain->bundlesize || iguana_bundleready(myinfo,coin,bp,bp->numsaved == bp->n) != bp->n) )
                {
                    //printf("firstgap <- [%d] emit.%u bp->n.%d numsaved.%d numcached.%d numhashes.%d\n",bp->hdrsi,bp->emitfinish,bp->n,bp->numsaved,bp->numcached,bp->numhashes);
                    firstgap = bp;
                }
                //else printf("[%d] emit.%u bp->n.%d numsaved.%d numcached.%d numhashes.%d\n",bp->hdrsi,bp->emitfinish,bp->n,bp->numsaved,bp->numcached,bp->numhashes);

                if ( bp->emitfinish == 0 )
                {
                    if ( lastpending == 0 && bp->queued == 0 )
                        iguana_bundleQ(myinfo,coin,bp,1000);
                    if ( firstgap != 0 && bp->numsaved < bp->n && ++pending == coin->MAXBUNDLES )
                    {
                        lastpending = bp;
                        //printf("SET MAXBUNDLES.%d pend.%d\n",bp->hdrsi,pending);
                    }
                    spaceused += bp->estsize;
                    //sortbuf[m*2] = bp->metric;
                    //sortbuf[m*2 + 1] = i;
                    m++;
                    if ( (0) && lastpending == 0 )
                        printf("%d ",bp->numsaved);
                }
            }
        }
    }
    coin->numremain = n;
    coin->blocksrecv = numrecv;
    uint64_t tmp; int32_t diff,p = 0; struct tai difft,t = tai_now();
    if ( coin->peers != 0 )
    {
        for (i=0; i<IGUANA_MAXPEERS; i++)
            if ( coin->peers->active[i].usock > 0 )
                p++;
    }
    diff = (int32_t)time(NULL) - coin->startutc;
    difft.x = (t.x - coin->starttime.x), difft.millis = (t.millis - coin->starttime.millis);
    tmp = (difft.millis * 1000000);
    tmp %= 1000000000;
    difft.millis = ((double)tmp / 1000000.);
    if ( (bp= firstgap) != 0 )
    {
        if ( bp != coin->current )
        {
            printf("%s new 1st.%d\n",coin->symbol,bp->hdrsi);
            iguana_bundleissuemissing(myinfo,coin,bp,3,1.);
            if ( bp->queued == 0 )
                iguana_bundleQ(myinfo,coin,bp,0);
        }
        for (i=j=0; i<bp->n; i++)
            if ( GETBIT(bp->haveblock,i) == 0 )
                bp->issued[i] = 0, j++;
        n = iguana_bundleissuemissing(myinfo,coin,bp,3,1.);
        //printf("issued 1st.[%d] %d of %d\n",bp->hdrsi,n,j);
    }
    if ( (coin->current= firstgap) == 0 )
    {
        firstgap = coin->current = (coin->bundlescount > 0) ? coin->bundles[coin->bundlescount-1] : coin->bundles[0];
        //printf("bundlescount.%d %p[%d]\n",coin->bundlescount,coin->current,coin->current->hdrsi);
    }
    if ( lastpending != 0 )
    {
        if ( lastpending->hdrsi+done > coin->bundlescount-1 )
            lastpending = coin->bundles[coin->bundlescount-1];
        else lastpending = coin->bundles[lastpending->hdrsi+done];
        coin->lastpending = lastpending;
    } else coin->lastpending = coin->bundles[coin->bundlescount - 1];
    coin->numsaved = numsaved;
    coin->numemit = numemit;
    coin->spaceused = spaceused;
    coin->numverified = numv;
    char str5[65]; int32_t smetric;
    if ( (bp= firstgap) != 0 && bp->hdrsi < coin->bundlescount-1 ) // coin->isRT
    {
        smetric = (bp->hdrsi * 10000) + bp->numsaved + bp->numhashes + bp->numcached;
        if ( coin->stuckmonitor != smetric )
        {
            coin->stuckmonitor = smetric;
            coin->stucktime = (uint32_t)time(NULL);
            coin->stuckiters = 0;
        }
        else if ( coin->stucktime != 0 )
        {
            int32_t n,lag; //priority=3,
            lag = (int32_t)time(NULL) - coin->stucktime;
            //printf("NONZ stucktime.%u lag.%d iters.%d vs %d metric.%d\n",coin->stucktime,lag,coin->stuckiters,lag/coin->MAXSTUCKTIME,smetric);
            if ( (lag/coin->MAXSTUCKTIME) > coin->stuckiters )
            {
                //printf("UNSTICK\n");
                iguana_unstickhdr(coin,bp,6);
                coin->stuckiters = (int32_t)(lag/coin->MAXSTUCKTIME);
                if ( coin->stuckiters > 2 )
                {
                    while ( (breq= queue_dequeue(&coin->blocksQ)) != 0 )
                        myfree(breq,sizeof(*breq));
                    while ( (breq= queue_dequeue(&coin->priorityQ)) != 0 )
                        myfree(breq,sizeof(*breq));
                    for (i=0; i<bp->n; i++)
                    {
                        if ( (block= bp->blocks[i]) != 0 && block->txvalid == 0 )
                            iguana_blockQ("stuck",coin,bp,i,block->RO.hash2,1);
                    }
                }
                for (i=0; i<bp->n; i++)
                    if ( GETBIT(bp->haveblock,i) == 0 )
                        bp->issued[i] = 0;
                if (  (n= iguana_bundleissuemissing(myinfo,coin,bp,3,1.)) > 0 )
                    printf("%s issued %d priority requests [%d] to unstick stuckiters.%d lag.%d\n",coin->symbol,n,bp->hdrsi,coin->stuckiters,lag);
                //else printf("no bundlerequests issued\n");
            }
        } //else printf("stuck metric.%d\n",smetric);
    }
    if ( coin->isRT != 0 || (firstgap != 0 && firstgap->hdrsi == coin->bundlescount-1) )
        coin->stucktime = coin->stuckiters = 0;
    if ( coin->stucktime != 0 && time(NULL)-coin->stucktime > coin->maxstuck )
        coin->maxstuck = (uint32_t)time(NULL) - coin->stucktime;
    sprintf(str,"%s.RT%d u.%d+c.%d b.%d v.%d (%d+%d/%d 1st.%d).s%d to %d N[%d] h.%d r.%d c.%d s.%d d.%d E.%d maxB.%d peers.%d/%d Q.(%d %d) (L.%d %d:%d) M.%d %s ledger.%08llx supply %.8f sigs %u:%u",coin->symbol,coin->RTheight,numutxo,numconverted,numbalances,iguana_validated(coin),firstgap!=0?firstgap->numcached:-1,firstgap!=0?firstgap->numsaved:-1,firstgap!=0?firstgap->numhashes:-1,firstgap!=0?firstgap->hdrsi:-1,firstgap!=0?firstgap->numspec:-1,coin->lastpending!=0?coin->lastpending->hdrsi:0,count,numhashes,coin->blocksrecv,numcached,numsaved,done,numemit,coin->MAXBUNDLES,p,coin->MAXPEERS,queue_size(&coin->priorityQ),queue_size(&coin->blocksQ),coin->longestchain,coin->longestchain/coin->chain->bundlesize,coin->longestchain%coin->chain->bundlesize,coin->blocks.hwmchain.height,bits256_str(str5,coin->blocks.hwmchain.RO.hash2),(long long)coin->utxoaddrhash.txid,dstr(coin->histbalance)+dstr(coin->RTcredits)-dstr(coin->RTdebits),coin->sigserrs,coin->sigsvalidated);
//if( strcmp("BTC",coin->symbol) == 0 )
//    printf("%s\n",str);
    if ( coin->current != 0 && coin->current->hdrsi == coin->longestchain/coin->chain->bundlesize && numemit == coin->current->hdrsi && numutxo == coin->bundlescount-1 )
    {
        //printf("have all utxo, generate balances\n");
    }
    // u.202 b.0/202 v.202/202
    if ( coin->current != 0 && numutxo == coin->bundlescount-1 && numutxo == coin->current->hdrsi && numbalances == 0 && numconverted == numutxo )
    {
        for (j=0; j<n; j++)
        {
            if ( (bp= coin->bundles[j]) != 0 )
            {
                //printf("bundleQ.[%d]\n",j);
                bp->balancefinish = bp->startutxo = 0;
                bp->utxofinish = 1;
                iguana_bundleQ(myinfo,coin,bp,1000);
            }
        }
    }
    //sprintf(str+strlen(str),"%s.%-2d %s time %.2f files.%d Q.%d %d\n",coin->symbol,flag,str,(double)(time(NULL)-coin->starttime)/60.,coin->peers.numfiles,queue_size(&coin->priorityQ),queue_size(&coin->blocksQ));
    if ( time(NULL) > coin->lastdisp+30 && (strcmp(str,coin->lastdispstr) != 0 || time(NULL) > coin->lastdisp+60) )
    {
        static FILE *logfp;
        if ( logfp == 0 )
            logfp = fopen("debug.log","wb");
        if ( logfp != 0 )
        {
            fprintf(logfp,"%s bQ.%d %d:%02d:%02d stuck.%d max.%d\n",str,numbQ,(int32_t)difft.x/3600,(int32_t)(difft.x/60)%60,(int32_t)difft.x%60,coin->stucktime!=0?(uint32_t)time(NULL) - coin->stucktime:0,coin->maxstuck);
            fflush(logfp);
        }
        if ( coin->RTheight == 0 )
            printf("%s bQ.%d %d:%02d:%02d stuck.%d max.%d\n",str,numbQ,(int32_t)difft.x/3600,(int32_t)(difft.x/60)%60,(int32_t)difft.x%60,coin->stucktime!=0?(uint32_t)time(NULL) - coin->stucktime:0,coin->maxstuck);
        strcpy(coin->lastdispstr,str);
        if ( (rand() % 100) == 0 )
            myallocated(0,0);
        coin->lastdisp = (uint32_t)time(NULL);
    }
    if ( (0) && (bp= coin->current) != 0 && coin->RTheight >= bp->bundleheight && coin->RTheight < bp->bundleheight+bp->n )
    {
        for (i=coin->RTheight-bp->bundleheight; i<bp->n; i++)
        {
            iguana_bundlehash2_check(coin,bp->hashes[i]);
            if ( bp->speculative != 0 )
                iguana_bundlehash2_check(coin,bp->speculative[i]);
        }
    }
    iguana_setmaxbundles(coin);
    strcpy(coin->statusstr,str);
    coin->estsize = estsize;
    if ( queue_size(&coin->priorityQ) > 10000 )
    {
        while ( (breq= queue_dequeue(&coin->priorityQ)) != 0 )
            myfree(breq,sizeof(*breq));
        //printf("cleared priorityQ\n");
    }
}

