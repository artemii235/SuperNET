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

int32_t iguana_alloctxbits(struct iguana_info *coin,struct iguana_ramchain *ramchain)
{
    static int64_t total; struct iguana_ramchaindata *rdata;
    if ( (0) && ramchain->txbits == 0 && (rdata= ramchain->H.data) != 0 )
    {
        int32_t tlen; uint8_t *TXbits;
        TXbits = RAMCHAIN_PTR(rdata,TXoffset);
        //TXbits = (uint8_t *)((long)rdata + rdata->TXoffset);
        tlen = (int32_t)hconv_bitlen(rdata->numtxsparse * rdata->txsparsebits);
        ramchain->txbits = calloc(1,tlen);
        memcpy(ramchain->txbits,TXbits,tlen);
        total += tlen;
        char str[65]; printf("%s alloc.[%d] txbits.%p[%d] total %s\n",coin->symbol,rdata->height/coin->chain->bundlesize,ramchain->txbits,tlen,mbstr(str,total));
        return(tlen);
    }
    return(-1);
}

int32_t iguana_alloccacheT(struct iguana_info *coin,struct iguana_ramchain *ramchain)
{
    static int64_t total; struct iguana_ramchaindata *rdata;
    if ( ramchain->cacheT == 0 && (rdata= ramchain->H.data) != 0 )
    {
        int32_t i,tlen; struct iguana_txid *T;
        T = RAMCHAIN_PTR(rdata,Toffset);
        //T = (void *)((long)rdata + rdata->Toffset);
        tlen = sizeof(*T) * rdata->numtxids;
        if ( (ramchain->cacheT= calloc(1,tlen)) != 0 )
        {
            //memcpy(ramchain->cacheT,T,tlen);
            for (i=0; i<rdata->numtxids; i++)
                ramchain->cacheT[i] = T[i];
        } else ramchain->cacheT = T;
        total += tlen;
        char str[65]; printf("alloc.[%d] cacheT.%p[%d] total %s\n",rdata->height/coin->chain->bundlesize,ramchain->cacheT,tlen,mbstr(str,total));
        return(tlen);
    }
    return(-1);
}

uint32_t iguana_sparseadd(uint8_t *bits,uint32_t ind,int32_t width,uint32_t tablesize,uint8_t *key,int32_t keylen,uint32_t setind,void *refdata,int32_t refsize,struct iguana_ramchain *ramchain,uint32_t maxitems)
{
    static uint8_t masks[8] = { 1, 2, 4, 8, 16, 32, 64, 128 };
    struct iguana_ramchaindata *rdata;
    int32_t i,j,x,n,modval; int64_t bitoffset; uint8_t *ptr; uint32_t *table,retval = 0;
    if ( tablesize == 0 )
    {
        printf("iguana_sparseadd tablesize zero illegal\n");
        return(0);
    }
    if ( (0) && setind == 0 )
    {
        char str[65];
        for (i=n=0; i<tablesize; i++)
        {
            bitoffset = (i * width);
            ptr = &bits[bitoffset >> 3];
            modval = (bitoffset & 7);
            for (x=j=0; j<width; j++,modval++)
            {
                if ( modval >= 8 )
                    ptr++, modval = 0;
                x <<= 1;
                x |= (*ptr & masks[modval]) >> modval;
            }
            if ( x != 0 )
                printf("%s ",bits256_str(str,*(bits256 *)((long)refdata + x*refsize))), n++;
        }
        printf("tableentries.%d\n",n);
    }
    //if ( setind == 0 )
    //    ramchain->sparsesearches++;
    //else ramchain->sparseadds++;
    if ( (0) && (rdata= ramchain->H.data) != 0 && (ramchain->sparsesearches % 1000000) == 0 )
        printf("[%3d] %7d.[%-2d %8d] %5.3f adds.(%-10ld %10ld) search.(hits.%-10ld %10ld) %5.2f%% max.%ld\n",ramchain->height/rdata->numblocks,ramchain->height,width,tablesize,(double)(ramchain->sparseadditers + ramchain->sparsesearchiters)/(1+ramchain->sparsesearches+ramchain->sparseadds),ramchain->sparseadds,ramchain->sparseadditers,ramchain->sparsehits,ramchain->sparsesearches,100.*(double)ramchain->sparsehits/(1+ramchain->sparsesearches),ramchain->sparsemax+1);
    if ( width == 32 )
    {
        table = (uint32_t *)bits;
        for (i=0; i<tablesize; i++,ind++)
        {
            if ( ind >= tablesize )
                ind = 0;
            if ( (x= table[ind]) == 0 )
            {
                //if ( ++i > ramchain->sparsemax )
                //    ramchain->sparsemax = i;
                if ( (retval= setind) != 0 )
                {
                    //ramchain->sparseadditers += i;
                    table[ind] = setind;
                } //else ramchain->sparsesearchiters += i;
                return(setind);
            }
            else if ( x < maxitems && memcmp((void *)(long)((long)refdata + x*refsize),key,keylen) == 0 )
            {
                if ( setind != 0 && setind != x )
                    printf("sparseadd index collision setind.%d != x.%d refsize.%d keylen.%d\n",setind,x,refsize,keylen);
                //ramchain->sparsehits++;
                //if ( ++i > ramchain->sparsemax )
                //    ramchain->sparsemax = i;
                //ramchain->sparseadditers += i;
                return(x);
            }
        }
    }
    else
    {
        bitoffset = (ind * width);
        if ( (0) && setind == 0 )
            printf("tablesize.%d width.%d bitoffset.%d\n",tablesize,width,(int32_t)bitoffset);
        for (i=0; i<tablesize; i++,ind++,bitoffset+=width)
        {
            if ( ind >= tablesize )
            {
                ind = 0;
                bitoffset = 0;
            }
            x = 0;
            if ( width == 32 )
                memcpy(&x,&bits[bitoffset >> 3],4);
            else if ( width == 16 )
                memcpy(&x,&bits[bitoffset >> 3],2);
            else if ( width != 8 )
            {
                ptr = &bits[bitoffset >> 3];
                modval = (bitoffset & 7);
                if ( (0) && setind == 0 )
                    printf("tablesize.%d width.%d bitoffset.%d modval.%d i.%d\n",tablesize,width,(int32_t)bitoffset,modval,i);
                for (x=j=0; j<width; j++,modval++)
                {
                    if ( modval >= 8 )
                        ptr++, modval = 0;
                    x <<= 1;
                    x |= (*ptr & masks[modval]) >> modval;
                }
            }
            else x = bits[bitoffset >> 3];
            if ( (0) && setind == 0 )
                printf("x.%d\n",x);
            if ( x == 0 )
            {
                if ( (x= setind) == 0 )
                {
                    //ramchain->sparsesearchiters += (i+1);
                    return(0);
                }
                //else ramchain->sparseadditers += (i+1);
                if ( width == 32 )
                    memcpy(&bits[bitoffset >> 3],&setind,4);
                else if ( width == 16 )
                    memcpy(&bits[bitoffset >> 3],&setind,2);
                else if ( width != 8 )
                {
                    ptr = &bits[(bitoffset+width-1) >> 3];
                    modval = ((bitoffset+width-1) & 7);
                    for (j=0; j<width; j++,x>>=1,modval--)
                    {
                        if ( modval < 0 )
                            ptr--, modval = 7;
                        if ( (x & 1) != 0 )
                            *ptr |= masks[modval];
                    }
                }
                else bits[bitoffset >> 3] = setind;
                if ( (0) )
                {
                    for (x=j=0; j<width; j++)
                    {
                        x <<= 1;
                        x |= GETBIT(bits,bitoffset+width-1-j) != 0;
                    }
                    //if ( x != setind )
                    printf("x.%u vs setind.%d ind.%d bitoffset.%d, width.%d\n",x,setind,ind,(int32_t)bitoffset,width);
                }
                //if ( i > ramchain->sparsemax )
                //    ramchain->sparsemax = i;
                return(setind);
            }
			// fadedreamz@gmail.com
#if defined(_M_X64)
			/*
			* calculate the address in a portable manner
			* in all platform sizeof(char) / sizeof(uchar) == 1
			* @author - fadedreamz@gmail.com
			*/
			else if (x < maxitems && memcmp((void *)((unsigned char *)refdata + x*refsize), key, keylen) == 0)
#else
            else if ( x < maxitems && memcmp((void *)(long)((long)refdata + x*refsize),key,keylen) == 0 )
#endif
            {
                if ( setind == 0 )
                    ramchain->sparsehits++;
                else if ( setind != x )
                    printf("sparseadd index collision setind.%d != x.%d refsize.%d keylen.%d\n",setind,x,refsize,keylen);
                if ( i > ramchain->sparsemax )
                    ramchain->sparsemax = i;
                return(x);
            }
        }
    }
    return(0);
}

uint32_t iguana_sparseaddtx(uint8_t *bits,int32_t width,uint32_t tablesize,bits256 txid,struct iguana_txid *T,uint32_t txidind,struct iguana_ramchain *ramchain)
{
    uint32_t ind,retval=0; struct iguana_ramchaindata *rdata = ramchain->H.data;
    if ( tablesize > 0 )
    {
        //char str[65]; printf("sparseaddtx %s txidind.%d bits.%p\n",bits256_str(str,txid),txidind,bits);
        ind = (txid.ulongs[0] ^ txid.ulongs[1] ^ txid.ulongs[2] ^ txid.ulongs[3]) % tablesize;
        if ( rdata != 0 && (retval= iguana_sparseadd(bits,ind,width,tablesize,txid.bytes,sizeof(txid),txidind,T,sizeof(*T),ramchain,rdata->numtxids)) != 0 )
        {
            char str[65];
            if ( txidind != 0 && retval != txidind )
                printf("sparse tx collision %s %u vs %u\n",bits256_str(str,txid),retval,txidind);
            return(retval);
        }
    }
    return(retval);
}

uint32_t iguana_sparseaddpk(uint8_t *bits,int32_t width,uint32_t tablesize,uint8_t rmd160[20],struct iguana_pkhash *P,uint32_t pkind,struct iguana_ramchain *ramchain)
{
    uint32_t ind,key2; uint64_t key0,key1; struct iguana_ramchaindata *rdata;
    if ( (rdata= ramchain->H.data) != 0 && tablesize > 0 )
    {
        //int32_t i; for (i=0; i<20; i++)
        //    printf("%02x",rmd160[i]);
        //printf(" sparseaddpk pkind.%d bits.%p\n",pkind,bits);
        memcpy(&key0,rmd160,sizeof(key0));
        memcpy(&key1,&rmd160[sizeof(key0)],sizeof(key1));
        memcpy(&key2,&rmd160[sizeof(key0) + sizeof(key1)],sizeof(key2));
        ind = (key0 ^ key1 ^ key2) % tablesize;
        return(iguana_sparseadd(bits,ind,width,tablesize,rmd160,20,pkind,P,sizeof(*P),ramchain,rdata->numpkinds));
    } else return(0);
}

int32_t iguana_ramchain_spendtxid(struct iguana_info *coin,uint32_t *unspentindp,bits256 *txidp,struct iguana_txid *T,int32_t numtxids,bits256 *X,int32_t numexternaltxids,struct iguana_spend *s)
{
    uint32_t ind,external;
    *unspentindp = 0;
    memset(txidp,0,sizeof(*txidp));
    ind = s->spendtxidind;
    external = (ind >> 31) & 1;
    ind &= ~(1 << 31);
    //printf("s.%p ramchaintxid vout.%x spendtxidind.%d isext.%d ext.%d ind.%d\n",s,s->prevout,ind,s->external,external,ind);
    if ( s->prevout < 0 )
        return(-1);
    if ( s->external != 0 && s->external == external && ind < numexternaltxids )
    {
        //printf("ind.%d X.%p[%d]\n",ind,X,numexternaltxids);
        *txidp = X[ind];
        return(s->prevout);
    }
    else if ( s->external == 0 && s->external == external && ind < numtxids )
    {
        *txidp = T[ind].txid;
        *unspentindp = T[ind].firstvout + s->prevout;
        return(s->prevout);
    }
    return(-2);
}

struct iguana_txid *iguana_txidfind(struct iguana_info *coin,int32_t *heightp,struct iguana_txid *tx,bits256 txid,int32_t lasthdrsi)
{
    uint8_t *TXbits; struct iguana_txid *T; uint32_t txidind; int32_t i;
    struct iguana_bundle *bp; struct iguana_ramchain *ramchain; struct iguana_ramchaindata *rdata; //struct iguana_block *block;
    *heightp = -1;
    memset(tx,0,sizeof(*tx));
    if ( lasthdrsi < 0 )
        return(0);
    for (i=lasthdrsi; i>=0; i--)
    {
        if ( (bp= coin->bundles[i]) != 0 && (bp == coin->current || bp->emitfinish > 1) )
        {
            ramchain = &bp->ramchain;//(bp == coin->current) ? &coin->RTramchain : &bp->ramchain;
            if ( (rdata= ramchain->H.data) != 0 )
            {
                if ( (TXbits= ramchain->txbits) == 0 )
                {
                    if ( coin->fastfind == 0 && bp != coin->current )
                        iguana_alloctxbits(coin,ramchain);
                    if ( (TXbits= ramchain->txbits) == 0 )
                    {
                        //printf("use memory mapped.[%d]\n",rdata->height/coin->chain->bundlesize);
                        TXbits = RAMCHAIN_PTR(rdata,TXoffset);
                        //TXbits = (void *)(long)((long)rdata + rdata->TXoffset);
                    }
                }
                if ( (T= ramchain->cacheT) == 0 )
                {
                    //if ( coin->fastfind == 0 )
                    //    iguana_alloccacheT(coin,ramchain);
                    //if ( (T= ramchain->cacheT) == 0 )
                    T = RAMCHAIN_PTR(rdata,Toffset);
                    //T = (void *)(long)((long)rdata + rdata->Toffset);
                }
                if ( (txidind= iguana_sparseaddtx(TXbits,rdata->txsparsebits,rdata->numtxsparse,txid,T,0,ramchain)) > 0 )
                {
                    //printf("found txidind.%d\n",txidind);
                    if ( bits256_cmp(txid,T[txidind].txid) == 0 )
                    {
                        if ( (0) )
                        {
                            int32_t j; struct iguana_block *block;
                            for (j=0; j<bp->n; j++)
                                if ( (block= bp->blocks[j]) != 0 && txidind >= block->RO.firsttxidind && txidind < block->RO.firsttxidind+block->RO.txn_count )
                                    break;
                            if ( j < bp->n )
                            {
                                if ( j != T[txidind].bundlei )
                                    printf("bundlei mismatch j.%d != %u\n",j,(uint32_t)T[txidind].bundlei);
                                else
                                {
                                    *heightp = bp->bundleheight + T[txidind].bundlei;
                                    //printf("found height.%d\n",*heightp);
                                    *tx = T[txidind];
                                    return(tx);
                                }
                            }
                        }
                        else
                        {
                            *heightp = bp->bundleheight + T[txidind].bundlei;
                            //printf("found height.%d\n",*heightp);
                            *tx = T[txidind];
                            //printf("[%d] txidind.%d 1st.(%d %d)\n",bp->hdrsi,txidind,tx->firstvout,tx->firstvin);
                            return(tx);
                        }
                    }
                    char str[65],str2[65]; printf("iguana_txidfind mismatch.[%d:%u] %d %s vs %s\n",bp->hdrsi,(uint32_t)T[txidind].extraoffset,txidind,bits256_str(str,txid),bits256_str(str2,T[txidind].txid));
                    return(0);
                }
            }
        }
    }
    return(0);
}

int32_t iguana_txidfastfind(struct iguana_info *coin,int32_t *heightp,bits256 txid,int32_t lasthdrsi)
{
    uint8_t *sorted,*item; int32_t i,j,val,num,tablesize,*hashtable; uint32_t firstvout;
    if ( (sorted= coin->fast[txid.bytes[31]]) != 0 )
    {
        memcpy(&num,sorted,sizeof(num));
        memcpy(&tablesize,&sorted[sizeof(num)],sizeof(tablesize));
        if ( (hashtable= coin->fasttables[txid.bytes[31]]) == 0 )
        {
            hashtable = (int32_t *)((long)sorted + (1 + num)*16);
            //printf("backup hashtable\n");
        }
        val = (txid.uints[4] % tablesize);
        for (j=0; j<tablesize; j++,val++)
        {
            if ( val >= tablesize )
                val = 0;
            if ( (i= hashtable[val]) == 0 )
                return(0);
            else
            {
                if ( i > num )
                {
                    printf("illegal val.%d vs num.%d tablesize.%d fastfind.%02x\n",i,num,tablesize,txid.bytes[31]);
                    return(0);
                }
                else
                {
                    item = (void *)((long)sorted + i*16);
                    if ( memcmp(&txid.txid,item,sizeof(uint64_t)) == 0 )
                    {
                        memcpy(&firstvout,&item[sizeof(uint64_t)],sizeof(firstvout));
                        memcpy(heightp,&item[sizeof(uint64_t) + sizeof(firstvout)],sizeof(*heightp));
                        //printf("i.%d val.%d height.%d firstvout.%d j.%d\n",i,val,*heightp,firstvout,j);
                        if ( *heightp >= (lasthdrsi+1)*coin->chain->bundlesize )
                        {
                            printf("txidfastfind: unexpected height.%d with lasthdrsi.%d\n",*heightp,lasthdrsi);
                            return(0);
                        }
                        return(firstvout);
                    }
                    else if ( (0) )
                    {
                        int32_t k;
                        for (k=-16; k<0; k++)
                            printf("%02x ",item[k]);
                        printf("<");
                        for (k=0; k<16; k++)
                            printf("%02x ",item[k]);
                        printf(">");
                        for (k=16; k<32; k++)
                            printf("%02x ",item[k]);
                        printf("\n");
                        printf("txid.%llx vs item.%llx ht.%d 1st.%d\n",(long long)txid.txid,*(long long *)item,*(int32_t *)&item[sizeof(uint64_t)],*(int32_t *)&item[sizeof(uint64_t)+sizeof(uint32_t)]);
                    }
                }
            }
        }
    }
    return(0);
}

int32_t iguana_fastfindadd(struct iguana_info *coin,bits256 txid,int32_t height,uint32_t firstvout)
{
    FILE *fp;
    if ( bits256_nonz(txid) != 0 && (fp= coin->fastfps[txid.bytes[31]]) != 0 )
    {
        txid.uints[6] = firstvout;
        txid.uints[7] = height;
        if ( fwrite(&txid,1,sizeof(txid),fp) == sizeof(txid) )
            return(1);
    }
    return(0);
}

int64_t iguana_fastfindinitbundle(struct iguana_info *coin,struct iguana_bundle *bp,int32_t iter)
{
    int32_t i; struct iguana_txid *T; struct iguana_ramchaindata *rdata; int64_t n = 0;
    if ( (rdata= bp->ramchain.H.data) != 0 )
    {
        T = RAMCHAIN_PTR(rdata,Toffset);
        //T = (void *)(long)((long)rdata + rdata->Toffset);
        n = rdata->numtxids;
        if ( iter == 1 )
        {
            for (i=0; i<n; i++)
                iguana_fastfindadd(coin,T[i].txid,bp->bundleheight + T[i].bundlei,T[i].firstvout);
            fprintf(stderr,"[%d:%u] ",bp->hdrsi,(int32_t)n);
        }
    }
    return(n);
}

static int _bignum_cmp(const void *a,const void *b)
{
    uint8_t *biga,*bigb; int32_t i,diff;
    biga = (uint8_t *)a;
    bigb = (uint8_t *)b;
    for (i=0; i<32; i++)
    {
        if ( (diff= (biga[i] - bigb[i])) > 0 )
            return(1);
        else if ( diff < 0 )
            return(-1);
    }
    return(0);
}

int32_t iguana_fastfindreset(struct iguana_info *coin)
{
    int32_t i,n = 0;
    for (i=0; i<0x100; i++)
    {
        if ( coin->fast[i] != 0 )
            munmap(coin->fast[i],coin->fastsizes[i]), n++;
        if( coin->fasttables[i] != 0 )
            free(coin->fasttables[i]);
        coin->fast[i] = 0;
        coin->fastsizes[i] = 0;
        coin->fasttables[i] = 0;
    }
    coin->fastfind = 0;
    return(n);
}

uint32_t iguana_fastfindinit(struct iguana_info *coin)
{
    int32_t i,iter,num,tablesize,*hashtable; uint8_t *sorted; char fname[1024];
    //if ( strcmp("BTC",coin->symbol) != 0 )
    //    return(0);
    if ( coin->fastfind != 0 )
        return(coin->fastfind);
    for (iter=0; iter<2; iter++)
    {
        for (i=0; i<0x100; i++)
        {
            sprintf(fname,"DB/%s%s/fastfind/%02x.all",iter!=0?"ro/":"",coin->symbol,i), OS_compatible_path(fname);
            if ( (coin->fast[i]= OS_mapfile(fname,&coin->fastsizes[i],0)) == 0 )
                break;
            else
            {
                fprintf(stderr,".");
                sorted = coin->fast[i];
                if ( (0) )
                {
                    coin->fast[i] = calloc(1,coin->fastsizes[i]);
                    memcpy(coin->fast[i],sorted,coin->fastsizes[i]);
                    munmap(sorted,coin->fastsizes[i]);
                }
                sorted = coin->fast[i];
                memcpy(&num,sorted,sizeof(num));
                memcpy(&tablesize,&sorted[sizeof(num)],sizeof(tablesize));
                if ( (num+1)*16 + tablesize*sizeof(*hashtable) == coin->fastsizes[i] )
                {
                    hashtable = (int32_t *)((long)sorted + (1 + num)*16);
                    if ( (0) )
                    {
                        coin->fasttables[i] = calloc(tablesize,sizeof(*hashtable));
                        memcpy(coin->fasttables[i],hashtable,tablesize * sizeof(*hashtable));
                    }
                }
                else
                {
                    printf("size error num.%d tablesize.%d -> %u vs %ld\n",num,tablesize,(int32_t)((num+1)*16 + tablesize*sizeof(*hashtable)),coin->fastsizes[i]);
                    break;
                }
            }
        }
        if ( i == 0x100 )
        {
            coin->fastfind = (uint32_t)time(NULL);
            printf("initialized fastfind.%s iter.%d\n",coin->symbol,iter);
            return(coin->fastfind);
        } else iguana_fastfindreset(coin);
    }
    return(0);
}

int64_t iguana_fastfindcreate(struct iguana_info *coin)
{
    int32_t i,j,val,iter,errs,num,ind,tablesize,*hashtable; bits256 *sortbuf,hash2; long allocsize; struct iguana_bundle *bp; char fname[512]; uint8_t buf[16]; int64_t total = 0;
    if ( coin->current != 0 && coin->bundlescount == coin->current->hdrsi+1 )
    {
        sprintf(fname,"DB/%s/fastfind",coin->symbol), OS_ensure_directory(fname);
        for (i=0; i<0x100; i++)
        {
            sprintf(fname,"DB/%s/fastfind/%02x",coin->symbol,i), OS_compatible_path(fname);
            if ( (coin->fastfps[i]= fopen(fname,"wb")) == 0 )
                break;
        }
        if ( i == 0x100 )
        {
            for (iter=0; iter<2; iter++)
            {
                total = 0;
                for (i=0; i<coin->bundlescount-1; i++)
                    if ( (bp= coin->bundles[i]) != 0 )
                        total += iguana_fastfindinitbundle(coin,bp,iter);
                printf("iguana_fastfindinit iter.%d total.%lld\n",iter,(long long)total);
            }
            for (i=errs=0; i<0x100; i++)
            {
                fclose(coin->fastfps[i]), coin->fastfps[i] = 0;
                sprintf(fname,"DB/%s/fastfind/%02x",coin->symbol,i), OS_compatible_path(fname);
                //printf("%s\n",fname);
                if ( (sortbuf= OS_filestr(&allocsize,fname)) != 0 )
                {
                    OS_removefile(fname,0);
                    num = (int32_t)allocsize/sizeof(bits256);
                    qsort(sortbuf,num,sizeof(bits256),_bignum_cmp);
                    strcat(fname,".all");
                    if ( (coin->fastfps[i]= fopen(fname,"wb")) != 0 )
                    {
                        tablesize = (num << 1);
                        hashtable = calloc(sizeof(*hashtable),tablesize);
                        for (ind=1; ind<=num; ind++)
                        {
                            hash2 = sortbuf[ind-1];
                            val = (hash2.uints[4] % tablesize);
                            for (j=0; j<tablesize; j++,val++)
                            {
                                if ( val >= tablesize )
                                    val = 0;
                                if ( hashtable[val] == 0 )
                                {
                                    hashtable[val] = ind;
                                    break;
                                }
                            }
                        }
                        memset(&hash2,0,sizeof(hash2));
                        hash2.uints[0] = num;
                        hash2.uints[1] = tablesize;
                        for (j=0; j<=num; j++)
                        {
                            memcpy(buf,&hash2.txid,sizeof(hash2.txid));
                            memcpy(&buf[sizeof(hash2.txid)],&hash2.uints[6],sizeof(hash2.uints[6]));
                            memcpy(&buf[sizeof(hash2.txid) + sizeof(hash2.uints[6])],&hash2.uints[7],sizeof(hash2.uints[7]));
                            fwrite(buf,1,sizeof(buf),coin->fastfps[i]);
                            //fwrite(hash2,1,sizeof(hash2),coin->fastfps[i]);
                            if ( j < num )
                            {
                                hash2 = sortbuf[j];
                                //char str[65]; printf("%d %s\n",j,bits256_str(str,hash2));
                            }
                        }
                        if ( fwrite(hashtable,sizeof(*hashtable),tablesize,coin->fastfps[i]) == tablesize )
                        {
                            fclose(coin->fastfps[i]), coin->fastfps[i] = 0;
                            if ( (coin->fast[i]= OS_mapfile(fname,&coin->fastsizes[i],0)) != 0 )
                            {
                            } else errs++;
                            printf("%s fastfind.[%02x] num.%d tablesize.%d errs.%d %p[%ld]\n",fname,i,num,tablesize,errs,coin->fast[i],coin->fastsizes[i]);
                        }
                        else
                        {
                            printf("error saving (%s)\n",fname);
                            OS_removefile(fname,0);
                            fclose(coin->fastfps[i]), coin->fastfps[i] = 0;
                        }
                        free(hashtable);
                    } else printf("couldnt overwrite (%s)\n",fname);
                    free(sortbuf);
                } else printf("couldnt load sortbuf (%s)\n",fname);
            }
            printf("initialized with errs.%d\n",errs);
            if ( errs == 0 )
                coin->fastfind = (uint32_t)time(NULL);
        }
    }
    return(total);
}

struct iguana_monitorinfo *iguana_monitorfind(struct iguana_info *coin,bits256 txid)
{
    int32_t i;
    for (i=0; i<sizeof(coin->monitoring)/sizeof(*coin->monitoring); i++)
        if ( bits256_cmp(coin->monitoring[i].txid,txid) == 0 )
            return(&coin->monitoring[i]);
    return(0);
}

struct iguana_monitorinfo *iguana_txidreport(struct iguana_info *coin,bits256 txid,struct iguana_peer *addr)
{
    struct iguana_monitorinfo *ptr; //char str[65];
    if ( (ptr= iguana_monitorfind(coin,txid)) != 0 )
    {
        if ( GETBIT(ptr->peerbits,addr->addrind) == 0 )
        {
            char str[65]; printf("%s reports %s\n",addr->ipaddr,bits256_str(str,txid));
            SETBIT(ptr->peerbits,addr->addrind);
            ptr->numreported++;
        }
    } // else printf("%s txid.%s not being monitored\n",coin->symbol,bits256_str(str,txid));
    return(0);
}

struct iguana_monitorinfo *iguana_txidmonitor(struct iguana_info *coin,bits256 txid)
{
    int32_t i; struct iguana_monitorinfo *ptr;
    if ( (ptr= iguana_monitorfind(coin,txid)) == 0 )
    {
        for (i=0; i<sizeof(coin->monitoring)/sizeof(*coin->monitoring); i++)
            if ( bits256_nonz(coin->monitoring[i].txid) == 0 )
            {
                memset(&coin->monitoring[i],0,sizeof(coin->monitoring[i]));
                coin->monitoring[i].txid = txid;
                return(ptr);
            }
    }
    printf("no monitoring slots left\n");
    return(0);
}

double iguana_txidstatus(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid)
{
    struct iguana_outpoint outpt; int32_t height,firstvout,numranked; struct iguana_monitorinfo *ptr; char str[65];
    if ( coin != 0 && coin->peers != 0 && (numranked= coin->peers->numranked) > 0 )
    {
        if ( iguana_RTunspentindfind(myinfo,coin,&outpt,0,0,0,0,&height,txid,0,coin->bundlescount-1,0) == 0 )
        {
            firstvout = outpt.unspentind;
            if ( (ptr= iguana_monitorfind(coin,txid)) != 0 )
                memset(ptr,0,sizeof(*ptr));
            return((double)coin->longestchain - height);
        }
        if ( (ptr= iguana_monitorfind(coin,txid)) != 0 )
            return((double)ptr->numreported / numranked);
        else
        {
            printf("iguana_txidstatus: unexpected missing %s %s\n",coin->symbol,bits256_str(str,txid));
            iguana_txidmonitor(coin,txid);
        }
    }
    return(0.);
}

