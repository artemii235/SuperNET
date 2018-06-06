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

static inline int32_t _iguana_spendvectorconv(struct iguana_spendvector *ptr,struct iguana_unspent *u,int32_t numpkinds,int32_t hdrsi,uint32_t unspentind)
{
    uint32_t spent_pkind = 0;
    if ( (spent_pkind= u->pkind) != 0 && spent_pkind < numpkinds )
    {
        ptr->pkind = spent_pkind;
        ptr->value = u->value;
        ptr->tmpflag = 0;
        return(spent_pkind);
    } else printf("spendvectorconv [%d] u%d pkind.%u/num %u\n",hdrsi,unspentind,u->pkind,numpkinds);
    return(0);
}

uint32_t iguana_spendvectorconv(struct iguana_info *coin,struct iguana_spendvector *ptr,struct iguana_bundle *bp)
{
    static uint64_t count,converted,errs;
    struct iguana_bundle *spentbp; struct iguana_unspent *spentU; uint32_t spent_pkind;
    count++;
    if ( 0 && (count % 1000000) == 0 )
        printf("iguana_spendvectorconv.[%llu] errs.%llu converted.%llu %.2f%%\n",(long long)count,(long long)errs,(long long)converted,100. * (long long)converted/count);
    if ( ptr->tmpflag != 0 )
    {
        if ( ptr->hdrsi >= 0 && ptr->hdrsi < coin->bundlescount && (spentbp= coin->bundles[ptr->hdrsi]) != 0 )
        {
            spentU = RAMCHAIN_PTR(spentbp->ramchain.H.data,Uoffset);
            //spentU = (void *)(long)((long)spentbp->ramchain.H.data + spentbp->ramchain.H.data->Uoffset);
            if ( (spent_pkind= _iguana_spendvectorconv(ptr,&spentU[ptr->unspentind],spentbp->ramchain.H.data->numpkinds,ptr->hdrsi,ptr->unspentind)) != 0 )
                converted++;
            else printf("illegal [%d].u%u pkind.%u vs %u\n",ptr->hdrsi,ptr->unspentind,spent_pkind,spentbp->ramchain.H.data->numpkinds);
        } else printf("illegal [%d].u%u\n",ptr->hdrsi,ptr->unspentind);
        errs++;
        return(0);
    } //else printf("[%d] tmpflag.%d u%d %.8f p%u\n",ptr->hdrsi,ptr->tmpflag,ptr->unspentind,dstr(ptr->value),ptr->pkind);
    return(ptr->pkind);
}

int32_t iguana_spendvectorsave(struct iguana_info *coin,struct iguana_bundle *bp,struct iguana_ramchain *ramchain,struct iguana_spendvector *ptr,int32_t emit,int32_t n)
{
    int32_t i,retval = -1; FILE *fp; char fname[1024],str[65]; long fsize; bits256 zero,sha256;
    if ( ptr == 0 || (bp->hdrsi != 0 && ptr == bp->ramchain.Xspendinds) )
    {
        //printf("iguana_spendvectorsave.[%d] ptr.%p Xspendinds\n",bp->hdrsi,ptr);
        return(0);
    }
    memset(zero.bytes,0,sizeof(zero));
    for (i=0; i<emit; i++)
        if ( iguana_spendvectorconv(coin,&ptr[i],bp) == 0 )
        {
            printf("iguana_spendvectorconv error [%d] at %d of %d/%d\n",bp->hdrsi,i,emit,n);
            return(-1);
        }
    sprintf(fname,"%s/%s/spends/%s.%d",GLOBAL_DBDIR,coin->symbol,bits256_str(str,bp->hashes[0]),bp->bundleheight);
    vcalc_sha256(0,sha256.bytes,(void *)ptr,(int32_t)(sizeof(*ptr) * emit));
    if ( (fp= fopen(fname,"wb")) != 0 )
    {
        if ( fwrite(sha256.bytes,1,sizeof(sha256),fp) != sizeof(sha256) )
            printf("error writing hash for %d -> (%s)\n",(int32_t)(sizeof(*ptr) * emit),fname);
        else if ( emit != 0 && fwrite(ptr,sizeof(*ptr),emit,fp) != emit )
            printf("error writing %d of %d -> (%s)\n",emit,n,fname);
        else
        {
            retval = 0;
            fsize = ftell(fp);
            fclose(fp), fp = 0;
            bp->Xvalid = 0;
            if ( iguana_Xspendmap(coin,ramchain,bp) < 0 )
                printf("error mapping Xspendmap.(%s)\n",fname);
            else
            {
                //printf("created.(%s) %p[%d]\n",fname,bp->ramchain.Xspendinds,bp->ramchain.numXspends);
                retval = 0;
            }
        }
        if ( fp != 0 )
            fclose(fp);
        //int32_t i; for (i=0; i<ramchain->numXspends; i++)
        //    printf("(%d u%d) ",ramchain->Xspendinds[i].hdrsi,ramchain->Xspendinds[i].ind);
        //printf("filesize %ld Xspendptr.%p %p num.%d\n",fsize,ramchain->Xspendptr,ramchain->Xspendinds,ramchain->numXspends);
    } else printf("iguana_spendvectors: Error creating.(%s)\n",fname);
    return(retval);
}

struct iguana_bundle *iguana_externalspent(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *prevhashp,uint32_t *unspentindp,struct iguana_ramchain *ramchain,int32_t spent_hdrsi,struct iguana_spend *s,int32_t prefetchflag)
{
    int32_t prev_vout,height,hdrsi; uint32_t sequenceid,unspentind; char str[65]; struct iguana_bundle *spentbp=0; struct iguana_txid *T,TX,*tp; bits256 *X; bits256 prev_hash; struct iguana_ramchaindata *rdata;
    if ( (rdata= ramchain->H.data) != 0 )
    {
        X = RAMCHAIN_PTR(rdata,Xoffset);
        T = RAMCHAIN_PTR(rdata,Toffset);
        sequenceid = s->sequenceid;
        hdrsi = spent_hdrsi;
        *unspentindp = 0;
        memset(prevhashp,0,sizeof(*prevhashp));
        if ( s->prevout < 0 )
        {
            //printf("n.%d coinbase at spendind.%d firstvin.%d -> firstvout.%d -> unspentind\n",m,spendind,nextT->firstvin,nextT->firstvout);
            //nextT++;
            //m++;
            return(0);
        }
        else
        {
            prev_vout = s->prevout;
            iguana_ramchain_spendtxid(coin,&unspentind,&prev_hash,T,rdata->numtxids,X,rdata->numexternaltxids,s);
            *prevhashp = prev_hash;
            *unspentindp = unspentind;
            if ( unspentind == 0 )
            {
                //double duration,startmillis = OS_milliseconds();
                if ( (tp= iguana_txidfind(coin,&height,&TX,prev_hash,spent_hdrsi-1)) != 0 )
                {
                    *unspentindp = unspentind = TX.firstvout + ((prev_vout > 0) ? prev_vout : 0);
                    hdrsi = height / coin->chain->bundlesize;
                    if ( hdrsi >= 0 && hdrsi < coin->bundlescount && (spentbp= coin->bundles[hdrsi]) != 0 )
                    {
                        //printf("%s height.%d firstvout.%d prev.%d ->U%d\n",bits256_str(str,prev_hash),height,TX.firstvout,prev_vout,unspentind);
                        /*now = (uint32_t)time(NULL);
                         duration = (OS_milliseconds() - startmillis);
                         if ( 0 && ((uint64_t)coin->txidfind_num % 1000000) == 1 )
                         printf("%p iguana_txidfind.[%.0f] ave %.2f micros, total %.2f seconds | duration %.3f millis\n",spentbp->ramchain.txbits,coin->txidfind_num,(coin->txidfind_totalmillis*1000.)/coin->txidfind_num,coin->txidfind_totalmillis/1000.,duration);
                         coin->txidfind_totalmillis += duration;
                         coin->txidfind_num += 1.;*/
                        if ( 1 && coin->PREFETCHLAG > 0 )
                        {
                            if ( spentbp->lastprefetch == 0 )
                            {
                                iguana_ramchain_prefetch(coin,&spentbp->ramchain,prefetchflag);
                                spentbp->lastprefetch = (uint32_t)time(NULL);
                            }
                            /*else if ( 0 && (rand() % IGUANA_NUMHELPERS) == 0 && (duration > 10 || duration > (10 * coin->txidfind_totalmillis)/coin->txidfind_num) )
                             {
                             printf("slow txidfind %.2f vs %.2f prefetch[%d] from.[%d] lag.%ld last.%u\n",duration,coin->txidfind_totalmillis/coin->txidfind_num,spentbp->hdrsi,ramchain->height/coin->chain->bundlesize,time(NULL) - spentbp->lastprefetch,spentbp->lastprefetch);
                             iguana_ramchain_prefetch(coin,ramchain,1);
                             //spentbp->lastprefetch = now;
                             }*/
                        }
                    }
                    else
                    {
                        printf("illegal hdrsi.%d prev_hash.(%s) for bp.[%d]\n",hdrsi,bits256_str(str,prev_hash),spent_hdrsi);
                        iguana_exit(myinfo,0);
                        return(0);
                    }
                }
                else
                {
                    printf("cant find prev_hash.(%s) for bp.[%d]\n",bits256_str(str,prev_hash),spent_hdrsi);
                    if ( spent_hdrsi < coin->current->hdrsi )
                    {
                        //iguana_bundleremove(coin,spent_hdrsi,1);
                        iguana_exit(myinfo,coin->bundles[spent_hdrsi]);
                    }
                    coin->RTdatabad = 1;
                    return(0);
                }
            } else printf("external spent unexpected nonz unspentind [%d]\n",spent_hdrsi);
        }
        if ( (spentbp= coin->bundles[hdrsi]) == 0 || hdrsi > spent_hdrsi )
            printf("%s illegal hdrsi.%d when [%d] spentbp.%p\n",coin->symbol,hdrsi,spent_hdrsi,spentbp);
        else if ( unspentind == 0 || unspentind >= spentbp->ramchain.H.data->numunspents )
            printf("%s illegal unspentind.%d vs max.%d spentbp.%p[%d]\n",coin->symbol,unspentind,spentbp->ramchain.H.data->numunspents,spentbp,hdrsi);
        else return(spentbp);
        //iguana_bundleremove(coin,spent_hdrsi,1);
        iguana_exit(myinfo,coin->bundles[spent_hdrsi]);
    }
    //exit(-1);
    return(0);
}

struct iguana_bundle *iguana_fastexternalspent(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *prevhashp,uint32_t *unspentindp,struct iguana_ramchain *ramchain,int32_t spent_hdrsi,struct iguana_spend *s)
{
    int32_t prev_vout,height,hdrsi,unspentind; uint32_t ind; uint64_t RTspent;
    struct iguana_txid *T; bits256 *X; bits256 prev_hash; struct iguana_ramchaindata *rdata;
    if ( (rdata= ramchain->H.data) == 0 )
        return(0);
    hdrsi = spent_hdrsi;
    *unspentindp = 0;
    memset(prevhashp,0,sizeof(*prevhashp));
    if ( (prev_vout= s->prevout) >= 0 )
    {
        ind = s->spendtxidind & ~(1 << 31);
        if ( s->external != 0 )
        {
            if ( ind < rdata->numexternaltxids )
            {
                char str[65]; //double duration,startmillis = OS_milliseconds();
                X = RAMCHAIN_PTR(rdata,Xoffset);
                //X = (void *)(long)((long)rdata + rdata->Xoffset);
                *prevhashp = prev_hash = X[ind];
                if ( (unspentind= iguana_unspentindfind(myinfo,coin,&RTspent,0,0,0,0,&height,prev_hash,prev_vout,spent_hdrsi-1,0)) > 0 )
                    //if ( (firstvout= iguana_txidfastfind(coin,&height,prev_hash,spent_hdrsi-1)) > 0 )
                {
                    /*duration = (OS_milliseconds() - startmillis);
                     if ( ((uint64_t)coin->txidfind_num % 100) == 1 )
                     printf("[%d] iguana_fasttxidfind.[%.0f] ave %.2f micros, total %.2f seconds | duration %.3f millis\n",spent_hdrsi,coin->txidfind_num,(coin->txidfind_totalmillis*1000.)/coin->txidfind_num,coin->txidfind_totalmillis/1000.,duration);
                     coin->txidfind_totalmillis += duration;
                     coin->txidfind_num += 1.;*/
                    *unspentindp = unspentind;//firstvout + prev_vout;
                    hdrsi = height / coin->chain->bundlesize;
                    if ( hdrsi >= 0 && hdrsi < coin->bundlescount )
                        return(coin->bundles[hdrsi]);
                }
                else
                {
                    printf("couldnt fastfind (%s)\n",bits256_str(str,prev_hash));
                }
            } else return(0);
        }
        else if ( ind < rdata->numtxids )
        {
            T = RAMCHAIN_PTR(rdata,Toffset);
            //T = (void *)(long)((long)rdata + rdata->Toffset);
            *prevhashp = T[ind].txid;
            *unspentindp = T[ind].firstvout + s->prevout;
            return(coin->bundles[hdrsi]);
        }
    }
    return(0);
}

int32_t iguana_spendvectors(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp,struct iguana_ramchain *ramchain,int32_t starti,int32_t numblocks,int32_t convertflag,int32_t iterate)
{
    static uint64_t total,emitted;
    int32_t iter,spendind=0,n=0,txidind,errs=0,emit=0,i,j,k; double startmillis; bits256 prevhash;
    uint32_t spent_unspentind=0,spent_pkind,now,starttime; struct iguana_ramchaindata *rdata;
    struct iguana_bundle *spentbp; struct iguana_blockRO *B; struct iguana_spendvector *ptr;
    struct iguana_unspent *u,*spentU;  struct iguana_txid *T; char str[65];
    struct iguana_spend *S,*s; //void *fastfind = 0;
    //printf("iguana_spendvectors.[%d] gen.%d ramchain data.%p txbits.%p\n",bp->hdrsi,bp->bundleheight,rdata,ramchain->txbits);
    if ( ramchain->H.data == 0 )
    {
        printf("AUTO volatilesalloc [%d]\n",bp->hdrsi);
        iguana_volatilesalloc(coin,ramchain,0);
    }
    if ( (rdata= ramchain->H.data) == 0 || (n= rdata->numspends) < 1 )
    {
        printf("iguana_spendvectors.[%d]: no rdata.%p %d\n",bp->hdrsi,rdata,n);
        return(0);
    }
    B = RAMCHAIN_PTR(rdata,Boffset);
    S = RAMCHAIN_PTR(rdata,Soffset);
    T = RAMCHAIN_PTR(rdata,Toffset);
    if ( ramchain->Xspendinds != 0 )
    {
        bp->tmpspends = ramchain->Xspendinds;
        bp->numtmpspends = ramchain->numXspends;
        bp->utxofinish = (uint32_t)time(NULL);
        bp->balancefinish = 0;
        //printf("iguana_spendvectors.[%d]: already have Xspendinds[%d]\n",bp->hdrsi,ramchain->numXspends);
        return(0);
    }
    bp->startutxo = (uint32_t)time(NULL);
    ptr = mycalloc('x',sizeof(*ptr),n);
    total += n;
    startmillis = OS_milliseconds();
    if ( (0) && strcmp(coin->symbol,"BTC") == 0 )
        printf("start UTXOGEN.%d max.%d ptr.%p millis.%.3f\n",bp->bundleheight,n,ptr,startmillis);
    starttime = (uint32_t)time(NULL);
    iguana_ramchain_prefetch(coin,&bp->ramchain,3);
    for (iter=0; iter<=iterate; iter++)
    {
        if ( iterate != 0 )
        {
            //fastfind = coin->fast[iter];
            //coin->fast[iter] = calloc(1,coin->fastsizes[iter]);
            //memcpy(coin->fast[iter],fastfind,coin->fastsizes[iter]);
        }
        //need zB[]?
        txidind = B[starti].firsttxidind;
        spendind = B[starti].firstvin;
        for (i=starti; i<numblocks; i++)
        {
            if ( txidind != B[i].firsttxidind || spendind != B[i].firstvin )
            {
                printf("spendvectors: txidind %u != %u B[%d].firsttxidind || spendind %u != %u B[%d].firstvin\n",txidind,B[i].firsttxidind,i,spendind,B[i].firstvin,i);
                myfree(ptr,sizeof(*ptr) * n);
                return(-1);
            }
            for (j=0; j<B[i].txn_count && errs==0; j++,txidind++)
            {
                now = (uint32_t)time(NULL);
                if ( txidind != T[txidind].txidind || spendind != T[txidind].firstvin )
                {
                    printf("spendvectors: txidind %u != %u nextT[txidind].firsttxidind || spendind %u != %u nextT[txidind].firstvin\n",txidind,(uint32_t)T[txidind].txidind,spendind,(uint32_t)T[txidind].firstvin);
                    myfree(ptr,sizeof(*ptr) * n);
                    return(-1);
                }
                for (k=0; k<T[txidind].numvins && errs==0; k++,spendind++)
                {
#ifdef __APPLE__
                    if ( bp == coin->current && (spendind % 10000) == 0 )
                        printf("iter.%02x [%-3d:%4d] spendvectors elapsed t.%-3d spendind.%d\n",iter,bp->hdrsi,i,(uint32_t)time(NULL)-starttime,spendind);
#endif
                    u = 0;
                    spentbp = 0;
                    s = &S[spendind];
                    if ( s->external != 0 && s->prevout >= 0 )
                    {
                        if ( coin->fastfind != 0 )
                        {
                            spentbp = iguana_fastexternalspent(myinfo,coin,&prevhash,&spent_unspentind,ramchain,bp->hdrsi,s);
                        }
                        else if ( spentbp == 0 )
                        {
                            if ( (spentbp= iguana_externalspent(myinfo,coin,&prevhash,&spent_unspentind,ramchain,bp->hdrsi,s,2)) != 0 )
                            {
                                if ( coin->fastfind != 0 )
                                    printf("found prevhash using slow, not fast\n");
                            }
                        }
                        if ( iterate != 0 && (spentbp == 0 || spentbp->hdrsi != iter) )
                            continue;
                        if ( bits256_nonz(prevhash) == 0 )
                            continue;
                        if ( spentbp != 0 && spentbp->ramchain.H.data != 0 )
                        {
                            if ( spentbp == bp )
                            {
                                char str[65];
                                printf("unexpected spendbp: height.%d bp.[%d] U%d <- S%d.[%d] [ext.%d %s prev.%d]\n",bp->bundleheight+i,spentbp->hdrsi,spent_unspentind,spendind,bp->hdrsi,s->external,bits256_str(str,prevhash),s->prevout);
                                errs++;
                                break;
                            }
                            if ( convertflag != 0 )
                            {
                                if ( coin->PREFETCHLAG > 0 && now >= spentbp->lastprefetch+coin->PREFETCHLAG )
                                {
                                    //printf("prefetch[%d] from.[%d] lag.%d\n",spentbp->hdrsi,bp->hdrsi,now - spentbp->lastprefetch);
                                    iguana_ramchain_prefetch(coin,&spentbp->ramchain,2);
                                    spentbp->lastprefetch = now;
                                }
                                spentU = RAMCHAIN_PTR(spentbp->ramchain.H.data,Uoffset);
                                //spentU = (void *)(long)((long)spentbp->ramchain.H.data + spentbp->ramchain.H.data->Uoffset);
                                u = &spentU[spent_unspentind];
                                if ( (spent_pkind= u->pkind) != 0 && spent_pkind < spentbp->ramchain.H.data->numpkinds )
                                {
                                    memset(&ptr[emit],0,sizeof(ptr[emit]));
                                    if ( (ptr[emit].unspentind= spent_unspentind) != 0 && spentbp->hdrsi < bp->hdrsi )
                                    {
                                        ptr[emit].fromheight = bp->bundleheight + i;
                                        ptr[emit].hdrsi = spentbp->hdrsi;
                                        ptr[emit].pkind = spent_pkind;
                                        ptr[emit].value = u->value;
                                        //printf("ht.%d [%d] SPENDVECTOR u%d %.8f p%u\n",ptr[emit].fromheight,ptr[emit].hdrsi,ptr[emit].unspentind,dstr(ptr[emit].value),ptr[emit].pkind);
                                        //printf("(%d u%d).%d ",spentbp->hdrsi,unspentind,emit);
                                        emit++;
                                    }
                                    else
                                    {
                                        printf("spendvectors: null unspentind for spendind.%d hdrsi.%d [%d]\n",spendind,spentbp->hdrsi,bp->hdrsi);
                                        errs++;
                                        break;
                                    }
                                }
                                else
                                {
                                    errs++;
                                    printf("spendvectors: unresolved spendind.%d hdrsi.%d\n",spendind,bp->hdrsi);
                                    break;
                                }
                            }
                            else
                            {
                                memset(&ptr[emit],0,sizeof(ptr[emit]));
                                ptr[emit].hdrsi = spentbp->hdrsi;
                                ptr[emit].unspentind = spent_unspentind;
                                ptr[emit].fromheight = bp->bundleheight + i;
                                ptr[emit].tmpflag = 1;
                                if ( (0) && bp == coin->current )
                                    printf("fromht.%d spends [%d] TMPVECTOR u%d s%u\n",ptr[emit].fromheight,ptr[emit].hdrsi,ptr[emit].unspentind,spendind);
                                emit++;
                            }
                        }
                        else
                        {
                            errs++;
                            printf("spendvectors: error resolving external spendind.%d hdrsi.%d\n",spendind,bp->hdrsi);
                            break;
                        }
                    }
                }
            }
        }
        /*if ( iterate != 0 )
         {
         free(coin->fast[iter]);
         coin->fast[iter] = fastfind;
         }*/
        if ( txidind != rdata->numtxids && txidind != ramchain->H.txidind )
        {
            printf("spendvectors: numtxid.%d != bp numtxids %d/%d\n",txidind,ramchain->H.txidind,rdata->numtxids);
            errs++;
        }
        if ( spendind != rdata->numspends && spendind != ramchain->H.spendind )
        {
            printf("spendvectors: spendind.%d != bp numspends %d/%d\n",spendind,ramchain->H.spendind,rdata->numspends);
            errs++;
        }
    }
    if ( errs == 0 && emit >= 0 )
    {
        emitted += emit;
        if ( convertflag == 0 )
        {
            if ( bp->tmpspends != 0 )
            {
                if ( bp->tmpspends != ramchain->Xspendinds && emit > 0 )
                {
                    // printf("spendvectors: RT [%d] numtmpspends.%d vs starti.%d emit.%d\n",bp->hdrsi,bp->numtmpspends,starti,emit);
                    bp->tmpspends = myrealloc('x',bp->tmpspends,sizeof(*ptr)*bp->numtmpspends,sizeof(*ptr)*(bp->numtmpspends+emit));
                    memcpy(&bp->tmpspends[bp->numtmpspends],ptr,sizeof(*ptr)*emit);
                    bp->numtmpspends += emit;
                }
            }
            else if ( emit > 0 )
            {
                bp->tmpspends = myrealloc('x',ptr,sizeof(*ptr)*n,sizeof(*ptr)*emit);
                bp->numtmpspends = emit;
                //printf("ALLOC tmpspends.[%d]\n",bp->hdrsi);
                ptr = 0;
            }
            if ( (0) && bp == coin->current )
                printf("spendvectors.[%d]: tmpspends.%p[%d] after += emit.%d X.%p\n",bp->hdrsi,bp->tmpspends,bp->numtmpspends,emit,bp->ramchain.Xspendinds);
        } else errs = -iguana_spendvectorsave(coin,bp,ramchain,ptr!=0?ptr:bp->tmpspends,emit,n);
    }
    if ( ptr != 0 )
        myfree(ptr,sizeof(*ptr) * n);
    //if ( bp != coin->current )
    printf("%s UTXO [%4d].%-6d dur.%-2d [%8.3f] vec %-6d err.%d [%5.2f%%] %7d %9s of %d\n",coin->symbol,bp->hdrsi,bp->numtmpspends,(uint32_t)time(NULL)-starttime,OS_milliseconds()-startmillis,spendind,errs,100.*(double)emitted/(total+1),emit,mbstr(str,sizeof(*ptr) * emit),n);
    return(-errs);
}

int32_t iguana_balancegen(struct iguana_info *coin,int32_t incremental,struct iguana_bundle *bp,int32_t starti,int32_t endheight,int32_t startemit)
{
    uint32_t spent_unspentind,spent_pkind,unspentind,txidind,h,i,j,endi,k,now; uint64_t spent_value;
    struct iguana_ramchain *ramchain; struct iguana_ramchaindata *rdata;
    struct iguana_spendvector *spend; struct iguana_unspent *spentU,*u,*U; struct iguana_spendvector *Xspendinds;
    struct iguana_txid *T; struct iguana_blockRO *B; struct iguana_bundle *spentbp; struct iguana_pkhash *P; //struct iguana_utxoaddr *utxoaddr;
    int32_t spent_hdrsi,spendind,n,numXspends,errs=0,emit=0; struct iguana_spend *S,*s;
    /*if ( (starti % coin->chain->bundlesize) != 0 || (endheight % coin->chain->bundlesize) != coin->chain->bundlesize-1 )
        ramchain = &coin->RTramchain;
    else*/ ramchain = &bp->ramchain;
    starti %= coin->chain->bundlesize;
    if ( (rdata= ramchain->H.data) == 0 || (n= rdata->numspends) < 1 )
        return(-1);
    S = RAMCHAIN_PTR(rdata,Soffset);
    B = RAMCHAIN_PTR(rdata,Boffset);
    T = RAMCHAIN_PTR(rdata,Toffset);
    U = RAMCHAIN_PTR(rdata,Uoffset);
    P = RAMCHAIN_PTR(rdata,Poffset);
    //S = (void *)(long)((long)rdata + rdata->Soffset);
    //B = (void *)(long)((long)rdata + rdata->Boffset);
    //T = (void *)(long)((long)rdata + rdata->Toffset);
    numXspends = ramchain->numXspends;
    if ( (Xspendinds= ramchain->Xspendinds) == 0 )
    {
        numXspends = bp->numtmpspends;
        if ( (Xspendinds= bp->tmpspends) == 0 )
        {
            //printf("iguana_balancegen.%d: no Xspendinds[%d]\n",bp->hdrsi,numXspends);
            numXspends = iguana_Xspendmap(coin,ramchain,bp);
            numXspends = ramchain->numXspends;
            //printf("Xspendinds.%p[%d]\n",Xspendinds,numXspends);
            //return(-1);
        }
    }
    endi = (endheight % coin->chain->bundlesize);
    txidind = B[starti].firsttxidind;
    spendind = B[starti].firstvin;
    unspentind = B[starti].firstvout;
    emit = startemit;
    if ( (0) && (coin->RTheight == 0 || bp->bundleheight+bp->n < coin->RTheight) )
        fprintf(stderr,"BALANCEGEN.[%d] %p[%d] starti.%d s%d <-> endi.%d s%d startemit.%d\n",bp->hdrsi,Xspendinds,numXspends,starti,spendind,endi,B[endi].firstvin+B[endi].numvins,startemit);
    for (i=starti; i<=endi; i++)
    {
        now = (uint32_t)time(NULL);
        if ( (0) && bp == coin->current )
            printf("hdrs.[%d] B[%d] 1st txidind.%d txn_count.%d firstvin.%d firstvout.%d\n",bp->hdrsi,i,B[i].firsttxidind,B[i].txn_count,B[i].firstvin,B[i].firstvout);
        if ( txidind != B[i].firsttxidind || spendind != B[i].firstvin || unspentind != B[i].firstvout )
        {
            printf("balancegen: txidind %u != %u B[%d].firsttxidind || spendind %u != %u B[%d].firstvin errs.%d (%u != %u)\n",txidind,B[i].firsttxidind,i,spendind,B[i].firstvin,i,errs,unspentind,B[i].firstvout);
            return(-1);
        }
        for (j=0; j<B[i].txn_count && errs==0; j++,txidind++)
        {
            now = (uint32_t)time(NULL);
            if ( txidind != T[txidind].txidind || spendind != T[txidind].firstvin || unspentind != T[txidind].firstvout )
            {
                printf("balancegen: txidind %u != %u T[txidind].firsttxidind || spendind %u != %u T[txidind].firstvin errs.%d (%d %d)\n",txidind,(uint32_t)T[txidind].txidind,spendind,(uint32_t)T[txidind].firstvin,errs,unspentind,B[i].firstvout);
                return(-1);
            }
            if ( (0) && bp == coin->current )
                printf("starti.%d txidind.%d txi.%d numvins.%d spendind.%d\n",i,txidind,j,T[txidind].numvins,spendind);
            /*if ( bp == coin->current )//ramchain == &coin->RTramchain )
            {
                for (k=0; k<T[txidind].numvouts && errs==0; k++,unspentind++)
                {
                    u = &U[unspentind];
                    if ( (utxoaddr= iguana_utxoaddrfind(1,coin,bp->hdrsi,u->pkind,P[u->pkind].rmd160,&coin->RTprev)) != 0 )
                    {
                        utxoaddr->RTcredits += u->value;
                        coin->RTcredits += u->value;
                        //printf("[%d] u%u += %.8f\n",bp->hdrsi,u->pkind,dstr(u->value));
                    } else printf("cant find utxoaddr\n");
                }
            } else */
            unspentind += T[txidind].numvouts;
            for (k=0; k<T[txidind].numvins && errs==0; k++,spendind++)
            {
                s = &S[spendind];
                h = spent_hdrsi = -1;
                spent_value = 0;
                spent_unspentind = spent_pkind = 0;
                if ( s->external != 0 && s->prevout >= 0 )
                {
                    if ( emit >= numXspends )
                        errs++;
                    else if ( Xspendinds != 0 )
                    {
                        spend = &Xspendinds[emit++];
                        spent_unspentind = spend->unspentind;
                        spent_value = spend->value;
                        spent_pkind = spend->pkind;
                        spent_hdrsi = spend->hdrsi;
                        h = spend->fromheight;
                    }
                    if ( (0) && bp == coin->current )
                        printf("external prevout.%d (emit.%d numX.%d) %p u%d p%d errs.%d spent_hdrsi.%d s%u\n",s->prevout,emit,numXspends,Xspendinds,spent_unspentind,spent_pkind,errs,spent_hdrsi,spendind);
                }
                else if ( s->prevout >= 0 )
                {
                    h = bp->bundleheight + i;
                    spent_hdrsi = bp->hdrsi;
                    if ( s->spendtxidind != 0 && s->spendtxidind < rdata->numtxids )
                    {
                        spent_unspentind = T[s->spendtxidind].firstvout + s->prevout;
                        spentU = RAMCHAIN_PTR(rdata,Uoffset);
                        u = &spentU[spent_unspentind];
                        if ( (spent_pkind= u->pkind) != 0 && spent_pkind < rdata->numpkinds )
                            spent_value = u->value;
                        // printf("internal spend.%d spendtxidind.%d 1st.%d U.(prevout.%d u%u pkind.%u %.8f)\n",spendind,txidind,T[s->spendtxidind].firstvout,s->prevout,spent_unspentind,u->pkind,dstr(u->value));*/
                    }
                    else //if ( i > 0 || j > 0 || k > 0 )
                    {
                        printf("iguana_balancegen [%d] txidind overflow %u vs %u (%d %d %d)\n",bp->hdrsi,s->spendtxidind,rdata->numtxids,i,j,k);
                        errs++;
                    }
                }
                else continue;
                spentbp = 0;
                if ( (spentbp= coin->bundles[spent_hdrsi]) != 0 && spent_unspentind > 0 && spent_pkind > 0 )
                {
                    if ( (0) && bp == coin->current )
                        printf("[%d] spendind.%u -> [%d] u%d\n",bp->hdrsi,spendind,spent_hdrsi,spent_unspentind);
                    if ( iguana_volatileupdate(coin,incremental,&spentbp->ramchain,spent_hdrsi,spent_unspentind,spent_pkind,spent_value,spendind,h) < 0 ) //(spentbp == coin->current) ? &coin->RTramchain : 
                        errs++;
                }
                else //if ( Xspendinds != 0 )
                {
                    errs++;
                    printf("iguana_balancegen: X%p[%d] spendind.%u external.%d error spentbp.%p with unspentind.%d pkind.%u [%d] (%d %d %d)\n",Xspendinds,numXspends,spendind,s->external,spentbp,spent_unspentind,spent_pkind,spent_hdrsi,i,j,k);
                }
            }
        }
    }
    if ( txidind != ramchain->H.data->numtxids && (bp != coin->current || txidind != ramchain->H.txidind) )
    {
        printf("numtxid.%d != bp numtxids %d/%d\n",txidind,ramchain->H.txidind,ramchain->H.data->numtxids);
        errs++;
    }
    if ( spendind != rdata->numspends && (bp != coin->current || spendind != ramchain->H.spendind) )
    {
        printf("spendind.%d != bp numspends %d/%d\n",spendind,ramchain->H.spendind,ramchain->H.data->numspends);
        errs++;
    }
    if ( emit != numXspends )
    {
        printf("iguana_balancegen: emit %d != %d ramchain->numXspends\n",emit,numXspends);
        errs++;
    }
    if ( errs == 0 )
        bp->balancefinish = (uint32_t)time(NULL);
    //printf(">>>>>>>> balances.%d done errs.%d spendind.%d\n",bp->hdrsi,errs,n);
    return(-errs);
}

void iguana_truncatebalances(struct iguana_info *coin)
{
    int32_t i; struct iguana_bundle *bp;
    for (i=0; i<coin->balanceswritten; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            bp->balancefinish = 0;
            bp->Xvalid = 0;
            iguana_volatilespurge(coin,&bp->ramchain);
        }
    }
    coin->balanceswritten = 0;
}

int32_t iguana_volatilesinit(struct supernet_info *myinfo,struct iguana_info *coin)
{
    bits256 balancehash,allbundles; struct iguana_utxo *Uptr; struct iguana_account *Aptr;
    struct sha256_vstate vstate,bstate; int32_t i,n,from_ro,numpkinds,numunspents; struct iguana_bundle *bp; struct iguana_block *block;
    uint32_t crc,filecrc; FILE *fp; char crcfname[512],str[65],str2[65],buf[2048];
    from_ro = 1;
    for (i=n=0; i<coin->bundlescount; i++)
    {
        if ( (bp= coin->bundles[i]) == 0 )
            continue;
        iguana_volatilesmap(myinfo,coin,&bp->ramchain);
        if ( bp->ramchain.H.data != 0 )
        {
            if ( bp->startutxo == 0 )
                bp->startutxo = (uint32_t)time(NULL) - 60;
            //if ( bp->utxofinish == 0 )
            //    bp->utxofinish = (uint32_t)time(NULL);
            n++;
        }
        if ( bp->utxofinish <= 1 || (i > 0 && bp->utxofinish <= 1) )
        {
            //printf("hdrsi.[%d] emitfinish.%u utxofinish.%u\n",i,bp->emitfinish,bp->utxofinish);
            continue;
        }
        if ( from_ro != 0 && (bp->ramchain.from_ro == 0 || (bp->hdrsi > 0 && bp->ramchain.from_roX == 0) || bp->ramchain.from_roA == 0 || bp->ramchain.from_roU == 0) )
        {
            printf("from_ro.[%d] %d %d %d %d\n",bp->hdrsi,bp->ramchain.from_ro,bp->ramchain.from_roX,bp->ramchain.from_roA,bp->ramchain.from_roU);
            from_ro = 0;
        }
    }
    printf("n.%d bundlescount.%d volatilesinit %d vs %d\n",n,i,(coin->longestchain-coin->chain->minconfirms)/coin->chain->bundlesize,n);
    if ( (coin->longestchain-coin->chain->minconfirms)/coin->chain->bundlesize > n )
    {
        printf("SKIP checking volatile files %d >= %d\n",(coin->longestchain-coin->chain->minconfirms)/coin->chain->bundlesize,n);
        iguana_bundlestats(myinfo,coin,buf,IGUANA_DEFAULTLAG);
        return(coin->bundlescount);
    }
    /*if ( i < coin->balanceswritten-1 )
    {
        printf("TRUNCATE balances written.%d -> %d\n",coin->balanceswritten,i);
        iguana_truncatebalances(coin);
    }
    else*/
    {
        coin->balanceswritten = i;
        //printf("verify crc and sha256 hash for %d of %d\n",i,coin->balanceswritten);
        vupdate_sha256(balancehash.bytes,&vstate,0,0);
        vupdate_sha256(allbundles.bytes,&bstate,0,0);
        filecrc = 0;
        sprintf(crcfname,"%s/%s/balancecrc.%d",GLOBAL_DBDIR,coin->symbol,coin->balanceswritten);
        if ( (fp= fopen(crcfname,"rb")) != 0 )
        {
            if ( fread(&filecrc,1,sizeof(filecrc),fp) != sizeof(filecrc) )
                filecrc = 0;
            else if ( fread(&balancehash,1,sizeof(balancehash),fp) != sizeof(balancehash) )
                filecrc = 0;
            else if ( memcmp(&balancehash,&coin->balancehash,sizeof(balancehash)) != 0 )
                filecrc = 0;
            else if ( fread(&allbundles,1,sizeof(allbundles),fp) != sizeof(allbundles) )
                filecrc = 0;
            else if ( memcmp(&allbundles,&coin->allbundles,sizeof(allbundles)) != 0 )
                filecrc = 0;
            fclose(fp);
        }
        if ( filecrc != 0 )
            printf("%s have filecrc.%08x for %s milli.%.0f from_ro.%d\n",coin->symbol,filecrc,bits256_str(str,balancehash),OS_milliseconds(),from_ro);
        if ( from_ro == 0 || filecrc == 0 )
        {
            if ( filecrc == 0 )
            {
                vupdate_sha256(balancehash.bytes,&vstate,0,0);
                vupdate_sha256(allbundles.bytes,&bstate,0,0);
            }
            for (i=crc=0; i<coin->balanceswritten; i++)
            {
                numpkinds = numunspents = 0;
                Aptr = 0, Uptr = 0;
                if ( (bp= coin->bundles[i]) != 0 && bp->ramchain.H.data != 0 && (numpkinds= bp->ramchain.H.data->numpkinds) > 0 && (numunspents= bp->ramchain.H.data->numunspents) > 0 && (Aptr= bp->ramchain.A2) != 0 && (Uptr= bp->ramchain.Uextras) != 0 )
                {
                    if ( (bp->bundleheight % 10000) == 0 )
                        fprintf(stderr,".");
                    if ( filecrc == 0 )
                    {
                        //fprintf(stderr,"balancehash add [%d]\n",bp->hdrsi);
                        vupdate_sha256(balancehash.bytes,&vstate,(void *)Aptr,sizeof(*Aptr) * numpkinds);
                        vupdate_sha256(balancehash.bytes,&vstate,(void *)Uptr,sizeof(*Uptr) * numunspents);
                        vupdate_sha256(allbundles.bytes,&bstate,(void *)bp->hashes,sizeof(bp->hashes[0]) * bp->n);
                    }
                    crc = calc_crc32(crc,(void *)Aptr,(int32_t)(sizeof(*Aptr) * numpkinds));
                    crc = calc_crc32(crc,(void *)Uptr,(int32_t)(sizeof(*Uptr) * numunspents));
                    crc = calc_crc32(crc,(void *)bp->hashes,(int32_t)(sizeof(bp->hashes[0]) * bp->n));
                } //else printf("missing hdrs.[%d] data.%p num.(%u %d) %p %p\n",i,bp->ramchain.H.data,numpkinds,numunspents,Aptr,Uptr);
            }
        } else crc = filecrc;
        printf("%s millis %.0f from_ro.%d written.%d crc.%08x/%08x balancehash.(%s) vs (%s)\n",coin->symbol,OS_milliseconds(),from_ro,coin->balanceswritten,crc,filecrc,bits256_str(str,balancehash),bits256_str(str2,coin->balancehash));
        if ( (filecrc != 0 && filecrc != crc) || memcmp(balancehash.bytes,coin->balancehash.bytes,sizeof(balancehash)) != 0 || memcmp(allbundles.bytes,coin->allbundles.bytes,sizeof(allbundles)) != 0 )
        {
            printf("%s balancehash or crc.(%x %x) mismatch or allbundles.(%llx %llx) mismatch\n",coin->symbol,crc,filecrc,(long long)allbundles.txid,(long long)coin->allbundles.txid);
            iguana_truncatebalances(coin);
            OS_removefile(crcfname,0);
        }
        else
        {
            printf("%s MATCHED balancehash numhdrsi.%d crc.%08x LONGEST.%d\n",coin->symbol,coin->balanceswritten,crc,coin->longestchain);
            if ( (fp= fopen(crcfname,"wb")) != 0 )
            {
                if ( fwrite(&crc,1,sizeof(crc),fp) != sizeof(crc) || fwrite(&balancehash,1,sizeof(balancehash),fp) != sizeof(balancehash) || fwrite(&allbundles,1,sizeof(allbundles),fp) != sizeof(allbundles) )
                    printf("error writing.(%s)\n",crcfname);
                fclose(fp);
                //if ( strcmp("BTC",coin->symbol) == 0 )
                {
                    if ( (coin->longestchain-coin->chain->minconfirms)/coin->chain->bundlesize < coin->bundlescount )
                    {
                        for (i=0; i<coin->bundlescount-1; i++)
                        {
                            if ( (bp= coin->bundles[i]) != 0 )
                            {
                                bp->converted = bp->balancefinish = bp->validated = bp->utxofinish = (uint32_t)time(NULL);
                            }
                        }
                        coin->matchedfiles = 1;
                        coin->spendvectorsaved = (uint32_t)time(NULL);
                        coin->spendvalidated = 0;
                        printf("LONGEST.%d %s UTXOGEN spendvectorsaved <- %u\n",coin->longestchain,coin->symbol,coin->spendvectorsaved);
                        iguana_utxoaddr_gen(myinfo,coin,(coin->bundlescount - 1) * coin->chain->bundlesize);
                    } else printf("(coin->longestchain+coin->chain->minconfirms)/coin->chain->bundlesize %d >= %d coin->bundlescount\n",(coin->longestchain+coin->chain->minconfirms)/coin->chain->bundlesize,coin->bundlescount);
                }
            }
            else
            {
                printf("volatileinit: cant create.(%s)\n",crcfname);
                return(-1);
            }
        }
    }
    //if ( (coin->RTheight= (coin->balanceswritten-1) * coin->chain->bundlesize) > coin->longestchain )
    //    coin->longestchain = coin->RTheight;
    iguana_bundlestats(myinfo,coin,buf,IGUANA_DEFAULTLAG);
    if ( (bp= coin->bundles[coin->bundlescount-1]) != 0 && (block= bp->blocks[bp->n-1]) != 0 )
    {
        if ( block->height > coin->blocks.hwmchain.height )
        {
            char str[65];
            printf("set hwmchain.%d <- %s %p\n",block->height,bits256_str(str,bp->hashes[bp->n-1]),block);
            iguana_blockzcopy(coin->chain->zcash,(void *)&coin->blocks.hwmchain,block);
        }
    }
    if ( iguana_fastfindinit(coin) == 0 )
        iguana_fastfindcreate(coin);
    iguana_datachain_scan(myinfo,coin,CRYPTO777_RMD160);
    printf("end %s volatilesinit\n",coin->symbol);
    return(coin->bundlescount);
}

void iguana_initfinal(struct supernet_info *myinfo,struct iguana_info *coin,bits256 lastbundle)
{
    int32_t i,hdrsi,bundlei,height; struct iguana_bundle *bp; bits256 hash2; struct iguana_block *block; char hashstr[65];
    if ( bits256_nonz(lastbundle) > 0 )
    {
        init_hexbytes_noT(hashstr,lastbundle.bytes,sizeof(bits256));
        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hashstr));
    }
    for (i=0; i<coin->bundlescount-1; i++)
    {
        if ( (bp= coin->bundles[i]) == 0 || bp->utxofinish <= 1 )
        {
            printf("%s initfinal break.[%d]: bp.%p or emit.%u utxofinish.%u\n",coin->symbol,i,bp,bp!=0?bp->emitfinish:-1,bp!=0?bp->utxofinish:-1);
            break;
        }
        if ( i == 0 )
            bp->utxofinish = bp->startutxo = (uint32_t)time(NULL);
    }
    if ( i < coin->bundlescount-1 )
    {
        printf("%s spendvectors.[%d] max.%d missing, will regen all of them\n",coin->symbol,i,coin->bundlescount-1);
        for (i=0; i<coin->bundlescount-1; i++)
        {
            if ( (bp= coin->bundles[i]) != 0 )
                bp->utxofinish = bp->startutxo = bp->emitfinish = bp->converted = bp->balancefinish = bp->validated = 0;
        }
    }
    else
    {
        for (i=0; i<coin->bundlescount-1; i++)
        {
            if ( (bp= coin->bundles[i]) != 0 )
                bp->converted = (uint32_t)time(NULL);
        }
    }
    printf("%s i.%d bundlescount.%d\n",coin->symbol,i,coin->bundlescount);
    //if ( coin->balanceswritten > 1 )
        coin->balanceswritten = iguana_volatilesinit(myinfo,coin);
    /*if ( coin->balanceswritten > 1 )
    {
        //for (i=0; i<coin->balanceswritten; i++)
        for (i=0; i<coin->bundlescount; i++)
        {
            if ( (bp= coin->bundles[i]) != 0 )
                iguana_bundlevalidate(myinfo,coin,bp,0);
            //printf("%d ",i);
            //iguana_validateQ(coin,coin->bundles[i]);
        }
    }*/
    printf("%s i.%d balanceswritten.%d\n",coin->symbol,i,coin->balanceswritten);
    /*if ( coin->balanceswritten < coin->bundlescount )
    {
        for (i=0*coin->balanceswritten; i<coin->bundlescount; i++)
        {
            if ( (bp= coin->bundles[i]) != 0 && bp->queued == 0 )
            {
                //printf("%d ",i);
                iguana_bundleQ(myinfo,coin,bp,1000);
            }
        }
        printf("iguana_bundlesQ %d to %d\n",coin->balanceswritten,coin->bundlescount);
    }
    if ( (coin->origbalanceswritten= coin->balanceswritten) > 0 )
        iguana_volatilesinit(myinfo,coin);*/
    iguana_savehdrs(coin);
    iguana_fastlink(coin,coin->balanceswritten * coin->chain->bundlesize - 1);
    iguana_walkchain(coin,0);
    hash2 = iguana_blockhash(coin,coin->balanceswritten * coin->chain->bundlesize);
    if ( bits256_nonz(hash2) != 0 && (block= iguana_blockfind("initfinal",coin,hash2)) != 0 )
    {
        for (height=0; height<coin->bundlescount*coin->chain->bundlesize; height++)
        {
            if ( _iguana_chainlink(myinfo,coin,block) == 0 )
                break;
            if ( coin->virtualchain == 0 )
                break;
            bundlei = (height % coin->chain->bundlesize);
            hdrsi = (height / coin->chain->bundlesize);
            if ( (bp= coin->bundles[hdrsi]) == 0 || (block= bp->blocks[bundlei]) == 0 )
                break;
        }
        printf("%s height.%d hwm.%d\n",coin->symbol,height,coin->blocks.hwmchain.height);
    }
}

int32_t iguana_balanceflush(struct supernet_info *myinfo,struct iguana_info *coin,int32_t refhdrsi)
{
    int32_t hdrsi,numpkinds,iter,numhdrsi,i,numunspents,err; struct iguana_bundle *bp;
    char fname[1024],fname2[1024],destfname[1024]; bits256 balancehash,allbundles; FILE *fp,*fp2;
    struct iguana_utxo *Uptr; struct iguana_account *Aptr; struct sha256_vstate vstate,bstate;
    vupdate_sha256(balancehash.bytes,&vstate,0,0);
    numhdrsi = refhdrsi;
    vupdate_sha256(balancehash.bytes,&vstate,0,0);
    vupdate_sha256(allbundles.bytes,&bstate,0,0);
    for (iter=0; iter<3; iter++)
    {
        for (hdrsi=0; hdrsi<numhdrsi; hdrsi++)
        {
            Aptr = 0;
            Uptr = 0;
            numunspents = numpkinds = 0;
            if ( (bp= coin->bundles[hdrsi]) == 0 )
                continue;
            if ( bp != 0 && bp->ramchain.H.data != 0 && (numpkinds= bp->ramchain.H.data->numpkinds) > 0 && (numunspents= bp->ramchain.H.data->numunspents) > 0 && (Aptr= bp->ramchain.A2) != 0 && (Uptr= bp->ramchain.Uextras) != 0 )
            {
                sprintf(fname,"%s/%s/debits.%d_N%d",GLOBAL_TMPDIR,coin->symbol,bp->hdrsi,numhdrsi);
                sprintf(fname2,"%s/%s/lastspends.%d_N%d",GLOBAL_TMPDIR,coin->symbol,bp->hdrsi,numhdrsi);
                if ( iter == 0 )
                {
                    vupdate_sha256(balancehash.bytes,&vstate,(void *)Aptr,sizeof(*Aptr)*numpkinds);
                    vupdate_sha256(balancehash.bytes,&vstate,(void *)Uptr,sizeof(*Uptr)*numunspents);
                    vupdate_sha256(allbundles.bytes,&bstate,(void *)bp->hashes,sizeof(bp->hashes[0])*bp->n);
                }
                else if ( iter == 1 )
                {
                    if ( (fp= fopen(fname,"wb")) != 0 && (fp2= fopen(fname2,"wb")) != 0 )
                    {
                        err = -1;
                        if ( fwrite(&numhdrsi,1,sizeof(numhdrsi),fp) == sizeof(numhdrsi) && fwrite(&numhdrsi,1,sizeof(numhdrsi),fp2) == sizeof(numhdrsi) && fwrite(balancehash.bytes,1,sizeof(balancehash),fp) == sizeof(balancehash) && fwrite(balancehash.bytes,1,sizeof(balancehash),fp2) == sizeof(balancehash) && fwrite(allbundles.bytes,1,sizeof(allbundles),fp) == sizeof(allbundles) && fwrite(allbundles.bytes,1,sizeof(allbundles),fp2) == sizeof(allbundles) )
                        {
                            if ( numpkinds == 0 || fwrite(Aptr,sizeof(*Aptr),numpkinds,fp) == numpkinds )
                            {
                                if ( numunspents == 0 || fwrite(Uptr,sizeof(*Uptr),numunspents,fp2) == numunspents )
                                {
                                    err = 0;
                                    if ( (hdrsi % 100) == 0 )
                                        printf("[%d] of %d saved (%s) and (%s)\n",hdrsi,numhdrsi,fname,fname2);
                                }
                            }
                        }
                        if ( err != 0 )
                        {
                            printf("balanceflush.%s error iter.%d hdrsi.%d\n",coin->symbol,iter,hdrsi);
                            fclose(fp);
                            fclose(fp2);
                            return(-1);
                        }
                        fclose(fp), fclose(fp2);
                    }
                    else
                    {
                        printf("error opening %s or %s %p\n",fname,fname2,fp);
                        if ( fp != 0 )
                            fclose(fp);
                    }
                }
                else if ( iter == 2 )
                {
                    sprintf(destfname,"%s/%s/accounts/debits.%d",GLOBAL_DBDIR,coin->symbol,bp->bundleheight);
                    OS_removefile(destfname,0);
                    OS_renamefile(fname,destfname);
                    /*if ( OS_copyfile(fname,destfname,1) < 0 )
                    {
                        printf("balances error copying (%s) -> (%s)\n",fname,destfname);
                        return(-1);
                    }*/
                    sprintf(destfname,"%s/%s/accounts/lastspends.%d",GLOBAL_DBDIR,coin->symbol,bp->bundleheight);
                    OS_removefile(destfname,0);
                    OS_renamefile(fname2,destfname);
                    /*if ( OS_copyfile(fname2,destfname,1) < 0 )
                    {
                        printf("balances error copying (%s) -> (%s)\n",fname2,destfname);
                        return(-1);
                    }*/
                    if ( (hdrsi % 100) == 0 )
                        printf("%s -> %s\n",fname,destfname);
                    //OS_removefile(fname,0);
                    //OS_removefile(fname2,0);
                }
                if ( bp->ramchain.allocatedA2 == 0 || bp->ramchain.allocatedU2 == 0 )
                {
                    printf("account.[%d] files not allocated %u %u\n",bp->hdrsi,(uint32_t)bp->ramchain.allocatedA2,(uint32_t)bp->ramchain.allocatedU2);
                    //break;
                }
            }
            else if ( hdrsi > 0 && hdrsi != coin->bundlescount && (coin->current == 0 || hdrsi != coin->current->hdrsi ) )
            {
                printf("balanceflush num.%d iter.%d error loading [%d] Aptr.%p Uptr.%p numpkinds.%u numunspents.%u\n",coin->bundlescount,iter,hdrsi,Aptr,Uptr,numpkinds,numunspents);
                return(-1);
            }
        }
    }
    coin->allbundles = allbundles;
    coin->balancehash = balancehash;
    coin->balanceswritten = numhdrsi;
    if ( 1 )
    {
        for (hdrsi=0; hdrsi<numhdrsi-1; hdrsi++)
            if ( (bp= coin->bundles[hdrsi]) == 0 && bp != coin->current )
            {
                iguana_volatilespurge(coin,&bp->ramchain);
                if ( iguana_volatilesmap(myinfo,coin,&bp->ramchain) != 0 )
                    printf("error mapping bundle.[%d]\n",hdrsi);
            }
    }
    char str[65]; printf("BALANCES WRITTEN for %d orig.%d bundles %s\n",coin->balanceswritten,coin->origbalanceswritten,bits256_str(str,coin->balancehash));
    //iguana_utxoaddr_gen(myinfo,coin,(coin->balanceswritten - 1) * coin->chain->bundlesize);
    if ( (0) && coin->balanceswritten > coin->origbalanceswritten+10 ) // strcmp(coin->symbol,"BTC") == 0 &&
    {
        coin->active = 0;
        coin->started = 0;
        if ( coin->peers != 0 )
            for (i=0; i<IGUANA_MAXPEERS; i++)
                coin->peers->active[i].dead = (uint32_t)time(NULL);
#ifdef __linux__
        char cmd[1024];
        sprintf(cmd,"mksquashfs %s/%s %s.%d -comp xz",GLOBAL_DBDIR,coin->symbol,coin->symbol,coin->balanceswritten);
        if ( system(cmd) != 0 )
            printf("error system(%s)\n",cmd);
        else
        {
            sprintf(cmd,"sudo umount %s/ro/%s",GLOBAL_DBDIR,coin->symbol);
            if ( system(cmd) != 0 )
                printf("error system(%s)\n",cmd);
            else
            {
                sprintf(cmd,"sudo mount %s.%d %s/ro/%s -t squashfs -o loop",coin->symbol,coin->balanceswritten,GLOBAL_DBDIR,coin->symbol);
                if ( system(cmd) != 0 )
                    printf("error system(%s)\n",cmd);
            }
        }
#endif
        iguana_exit(myinfo,0);
    }
    coin->balanceswritten = iguana_volatilesinit(myinfo,coin);
    //printf("flush free\n");
    iguana_RTdataset_free(coin);
    //iguana_RTramchainfree(coin,bp);
    return(coin->balanceswritten);
}

int32_t iguana_spendvectorsaves(struct iguana_info *coin)
{
    int32_t i,j,n,iter; struct iguana_bundle *bp; struct iguana_ramchaindata *rdata;
    if ( coin->spendvectorsaved > 1 )
        return(0);
    coin->spendvectorsaved = 1;
    n = coin->bundlescount - 1;
    printf("SAVE SPEND VECTORS %d of %d\n",n,coin->bundlescount);
    for (iter=0; iter<2; iter++)
    {
        for (i=0; i<n; i++)
        {
            if ( (bp= coin->bundles[i]) != 0 )
            {
                if ( iter == 0 )
                {
                    if ( bp->tmpspends != 0 )//bp->ramchain.Xspendinds == 0 &&
                    {
                        for (j=0; j<bp->numtmpspends; j++)
                            if ( bp->tmpspends[j].tmpflag != 0 )
                            {
                                printf("%s vectorsave.[%d] vec.%d still has tmpflag\n",coin->symbol,i,j);
                                return(-1);
                            }
                    }
                }
                else if ( (rdata= bp->ramchain.H.data) != 0 && iguana_spendvectorsave(coin,bp,&bp->ramchain,bp->tmpspends,bp->numtmpspends,rdata->numspends) == 0 )
                {
                    if ( bp->tmpspends != 0 && bp->numtmpspends > 0 && bp->tmpspends != bp->ramchain.Xspendinds )
                        myfree(bp->tmpspends,sizeof(*bp->tmpspends) * bp->numtmpspends);
                    bp->numtmpspends = 0;
                    bp->tmpspends = 0;
                }
            }
        }
    }
    coin->spendvectorsaved = (uint32_t)time(NULL);
    coin->spendvalidated = 0;
    return(0);
}

int32_t iguana_spendvectorconvs(struct iguana_info *coin,struct iguana_bundle *spentbp,int32_t starti)
{
    struct iguana_bundle *bp; int16_t spent_hdrsi; uint32_t numpkinds; struct iguana_unspent *spentU; struct iguana_spendvector *vec; int32_t i,converted,j,n = coin->bundlescount; struct iguana_ramchain *ramchain; struct iguana_ramchaindata *rdata = 0;
    if ( (rdata= spentbp->ramchain.H.data) == 0 )
    {
        //if ( spentbp == coin->current )
        printf("iguana_spendvectorconvs: [%d] null rdata.%p\n",spentbp->hdrsi,rdata);
        return(-1);
    }
    spent_hdrsi = spentbp->hdrsi;
    ramchain = &spentbp->ramchain;
    numpkinds = rdata->numpkinds;
    spentU = RAMCHAIN_PTR(rdata,Uoffset);
    //spentU = (void *)(long)((long)rdata + rdata->Uoffset);
    for (i=converted=0; i<n; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 && bp->tmpspends != 0 )
        {
            for (j=0; j<bp->numtmpspends; j++)
            {
                vec = &bp->tmpspends[j];
                if ( vec->hdrsi == spent_hdrsi )
                {
                    if ( vec->tmpflag == 0 )
                    {
                        if ( bp->tmpspends != bp->ramchain.Xspendinds && bp != coin->current )
                            printf("unexpected null tmpflag [%d] j.%d spentbp.[%d]\n",bp->hdrsi,j,spentbp->hdrsi);
                    }
                    else
                    {
                        if ( _iguana_spendvectorconv(vec,&spentU[vec->unspentind],numpkinds,vec->hdrsi,vec->unspentind) != 0 )
                            converted++;
                        else
                        {
                            printf("iguana_spendvectorconv.[%d] error [%d] at %d of T[%d/%d] [%d] u%u p%u\n",spentbp->hdrsi,bp->hdrsi,j,bp->numtmpspends,n,vec->hdrsi,vec->unspentind,spentU[vec->unspentind].pkind);
                            return(-1);
                        }
                    }
                }
            }
        }
        else if ( bp->hdrsi < coin->bundlescount-1 )
        {
            //printf("iguana_spendvectorconvs: [%d] null bp.%p\n",i,bp);
        }
    }
    spentbp->converted = (uint32_t)time(NULL);
    //printf("spendvectorconvs.[%d] converted.%d\n",refbp->hdrsi,converted);
    return(converted);
}

int32_t iguana_convert(struct iguana_info *coin,int32_t helperid,struct iguana_bundle *bp,int32_t RTflag,int32_t starti)
{
    static int64_t total[256],depth;
    int32_t i,n,m,max,converted; int64_t total_tmpspends,sum; double startmillis = OS_milliseconds();
    depth++;
    if ( (converted= iguana_spendvectorconvs(coin,bp,starti)) < 0 )
    {
        printf("error iguana_convert.[%d]\n",bp->hdrsi);
        return(0);
    }
    else
    {
        n = coin->bundlescount;
        for (i=m=total_tmpspends=0; i<n; i++)
        {
            if ( coin->bundles[i] != 0 )
            {
                total_tmpspends += coin->bundles[i]->numtmpspends;
                if ( coin->bundles[i]->converted > 1 )
                    m++;
            }
        }
        max = (int32_t)(sizeof(total) / sizeof(*total));
        total[helperid % max] += converted;
        for (i=sum=0; i<max; i++)
            sum += total[i];
        if ( (0) && converted != 0 && bp != coin->current )
            printf("[%4d] millis %7.3f converted.%-7d balance calc.%-4d of %4d | total.%llu of %llu depth.%d\n",bp->hdrsi,OS_milliseconds()-startmillis,converted,m,n,(long long)sum,(long long)total_tmpspends,(int32_t)depth);
    }
    depth--;
    return(converted);
}

int32_t iguana_bundlevalidate(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp,int32_t forceflag)
{
    static int32_t totalerrs,totalvalidated;
    FILE *fp; char fname[1024]; uint8_t *blockspace; uint32_t now = (uint32_t)time(NULL);
    int32_t i,max,len,errs = 0; struct sha256_vstate vstate; bits256 validatehash; int64_t total = 0;
    if ( coin->chain->zcash != 0 )
    {
        static uint32_t counter;
        if ( (0) && counter++ < 3 )
            printf("need to process joinsplits before can validate.%s\n",coin->symbol);
        bp->validated = (uint32_t)time(NULL);
        forceflag = 1;
        //return(bp->n);
    }
    if ( (coin->MAXPEERS > 1 && coin->VALIDATENODE == 0 && coin->FULLNODE == 0) || bp->ramchain.from_ro != 0 )//|| bp == coin->current )
    {
        bp->validated = (uint32_t)time(NULL);
        return(bp->n);
    }
    if ( bp->validated <= 1 || forceflag != 0 )
    {
        //printf("validate.[%d] forceflag.%d\n",bp->hdrsi,forceflag);
        vupdate_sha256(validatehash.bytes,&vstate,0,0);
        sprintf(fname,"%s/%s/validated/%d",GLOBAL_DBDIR,coin->symbol,bp->bundleheight);
        //printf("validatefname.(%s)\n",fname);
        if ( (fp= fopen(fname,"rb")) != 0 )
        {
            if ( forceflag == 0 )
            {
                if ( fread(&bp->validated,1,sizeof(bp->validated),fp) != sizeof(bp->validated) ||fread(&total,1,sizeof(total),fp) != sizeof(total) || fread(&validatehash,1,sizeof(validatehash),fp) != sizeof(validatehash) )
                {
                    printf("error reading.(%s)\n",fname);
                    total = bp->validated = 0;
                } //else printf("(%s) total.%d validated.%u\n",fname,(int32_t)total,bp->validated);
            } else OS_removefile(fname,1);
            fclose(fp);
        }
        if ( forceflag != 0 || bp->validated <= 1 )
        {
            if ( coin->chain->zcash == 0 )
            {
                max = coin->blockspacesize;
                blockspace = calloc(1,max);
                iguana_volatilespurge(coin,&bp->ramchain);
                iguana_volatilesmap(myinfo,coin,&bp->ramchain);
                for (i=0; i<bp->n; i++)
                {
                    char str[65];
                    if ( coin->chain->fixit != 0 )
                        printf("validate %s.[%d:%d] %s\n",coin->symbol,bp->hdrsi,i,bits256_str(str,bp->hashes[i]));
                    if ( (len= iguana_peerblockrequest(myinfo,coin,blockspace,max,0,bp->hashes[i],1)) < 0 )
                    {
                        errs++;
                        //fprintf(stderr,"-%s.[%d:%d] ",coin->symbol,bp->hdrsi,i);
                        //printf("bundlevalidate: %s delete [%d:%d]\n",coin->symbol,bp->hdrsi,i);
                        iguana_blockunmark(coin,bp->blocks[i],bp,i,1);
                        totalerrs++;
                    }
                    else
                    {
                        vupdate_sha256(validatehash.bytes,&vstate,bp->hashes[i].bytes,sizeof(bp->hashes[i]));
                        total += len, totalvalidated++;
                    }
                }
                free(blockspace);
                printf("%s %s VALIDATED.[%d] ht.%d duration.%d errs.%d total.%lld %u | total errs.%d validated.%d %llx\n",coin->symbol,errs!=0?"NOT":"",bp->hdrsi,bp->bundleheight,(uint32_t)time(NULL) - now,errs,(long long)total,bp->validated,totalerrs,totalvalidated,(long long)validatehash.txid);
            }
            if ( errs == 0 )
                bp->validated = (uint32_t)time(NULL);
            else bp->validated = bp->startutxo = bp->utxofinish = 0;
            //iguana_volatilesmap(coin,&bp->ramchain);
            //if ( bp == coin->current )
            //    coin->RTdatabad = -1;
        }
        if ( errs == 0 && fp == 0 )
        {
            if ( (fp= fopen(fname,"wb")) != 0 )
            {
                if ( fwrite(&bp->validated,1,sizeof(bp->validated),fp) != sizeof(bp->validated) || fwrite(&total,1,sizeof(total),fp) != sizeof(total) || fwrite(&validatehash,1,sizeof(validatehash),fp) != sizeof(validatehash) )
                    printf("error saving.(%s) total.%lld\n",fname,(long long)total);
                fclose(fp);
            }
        }
        bp->validatehash = validatehash;
    } // else printf("skip validate.[%d] validated.%u force.%d\n",bp->hdrsi,bp->validated,forceflag);
    if ( errs != 0 )
    {
        printf("%s remove.[%d]\n",coin->symbol,bp->hdrsi);
        iguana_bundleremove(coin,bp->hdrsi,0);
        return(-errs);
    }
    return(bp->n - errs);
}
