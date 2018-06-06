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

//  ramcoder based on arcode.c from Michael Dipperstein

#ifdef DEFINES_ONLY
#ifndef crypto777_ramcoder_h
#define crypto777_ramcoder_h
#include <stdio.h>
#include "../crypto777/OS_portable.h"
#include "../includes/curve25519.h"


#define RAMMASK_BIT(x) ((uint16_t)(1 << ((8 * sizeof(uint16_t)) - (1 + (x)))))
#define RAMCODER_FINALIZE 1
#define RAMCODER_PUTBITS 2
#define RAMCODER_MAXSYMBOLS 0x100

#define SETBIT(bits,bitoffset) (((uint8_t *)bits)[(bitoffset) >> 3] |= (1 << ((bitoffset) & 7)))
#define GETBIT(bits,bitoffset) (((uint8_t *)bits)[(bitoffset) >> 3] & (1 << ((bitoffset) & 7)))

int32_t ramcoder_decode(struct ramcoder *coder,int32_t updateprobs,HUFF *hp);
int32_t ramcoder_decoder(struct ramcoder *coder,int32_t updateprobs,uint8_t *buf,int32_t maxlen,HUFF *hp,bits256 *seed);
#define ramcoder_encode(val,coder,hp) ramcoder_update(val,coder,1,RAMCODER_PUTBITS,hp)
int32_t ramcoder_encoder(struct ramcoder *coder,int32_t updateprobs,uint8_t *buf,int32_t len,HUFF *hp,uint64_t *histo,bits256 *seed);
int32_t ramcoder_update(int symbol,struct ramcoder *coder,int32_t updateprobs,int32_t putflags,HUFF *hp);
int32_t init_ramcoder(struct ramcoder *coder,HUFF *hp,bits256 *seed);
int32_t ramcoder_emit(HUFF *hp,struct ramcoder *coder,int32_t updateprobs,uint8_t *buf,int32_t len);

int32_t ramcoder_decompress(uint8_t *data,int32_t maxlen,uint8_t *bits,uint32_t numbits,bits256 seed);
int32_t ramcoder_compress(uint8_t *bits,int32_t maxlen,uint8_t *data,int32_t datalen,bits256 seed);
uint64_t hconv_bitlen(uint64_t bitlen);
void _init_HUFF(HUFF *hp,int32_t allocsize,void *buf);

#endif
#else
#ifndef crypto777_ramcoder_c
#define crypto777_ramcoder_c

#ifndef crypto777_ramcoder_h
#define DEFINES_ONLY
#include "ramcoder.c"
#undef DEFINES_ONLY
#endif
static const uint8_t huffmasks[8] = { (1<<0), (1<<1), (1<<2), (1<<3), (1<<4), (1<<5), (1<<6), (1<<7) };
static const uint8_t huffoppomasks[8] = { ~(1<<0), ~(1<<1), ~(1<<2), ~(1<<3), ~(1<<4), ~(1<<5), ~(1<<6), (uint8_t)~(1<<7) };

void _init_HUFF(HUFF *hp,int32_t allocsize,void *buf) {  hp->buf = hp->ptr = buf, hp->allocsize = allocsize, hp->bitoffset = 0; }

uint64_t hconv_bitlen(uint64_t bitlen)
{
    uint64_t len;
    len = (bitlen >> 3);
    if ( (bitlen & 7) != 0 )
        len++;
    return(len);
}

int32_t hupdate_internals(HUFF *hp)
{
    int32_t retval = 0;
    if ( (hp->bitoffset >> 3) > hp->allocsize )
    {
        printf("hupdate_internals: ERROR: bitoffset.%d -> %d >= allocsize.%d\n",hp->bitoffset,hp->bitoffset>>3,hp->allocsize);
        //getchar();
        hp->bitoffset = (hp->allocsize << 3) - 1;
        retval = -1;
    }
    if ( hp->bitoffset > hp->endpos )
        hp->endpos = hp->bitoffset;
    hp->ptr = &hp->buf[hp->bitoffset >> 3];
    hp->maski = (hp->bitoffset & 7);
    return(retval);
}

int32_t hseek(HUFF *hp,int32_t offset,int32_t mode)
{
    if ( mode == SEEK_END )
        hp->bitoffset = (offset + hp->endpos);
    else if ( mode == SEEK_SET )
        hp->bitoffset = offset;
    else hp->bitoffset += offset;
    if ( hupdate_internals(hp) < 0 )
    {
        printf("hseek.%d: illegal offset.%d %d >= allocsize.%d\n",mode,offset,offset>>3,hp->allocsize);
        return(-1);
    }
    return(0);
}

void hclear(HUFF *hp,int32_t clearbuf)
{
    hp->bitoffset = 0;
    hupdate_internals(hp);
    hp->endpos = 0;
    if ( clearbuf != 0 )
        memset(hp->buf,0,hp->allocsize);
}

int32_t hgetbit(HUFF *hp)
{
    int32_t bit = 0;
    //printf("hp.%p ptr.%ld buf.%ld maski.%d\n",hp,(long)hp->ptr-(long)hp->buf,(long)hp->buf-(long)hp,hp->maski);
    if ( hp->bitoffset < hp->endpos )
    {
        if ( (*hp->ptr & huffmasks[hp->maski++]) != 0 )
            bit = 1;
        hp->bitoffset++;
        if ( hp->maski == 8 )
            hp->maski = 0, hp->ptr++;
        //fprintf(stderr,"<-%d ",bit);
        return(bit);
    }
    //printf("hgetbit past EOF: %d >= %d\n",hp->bitoffset,hp->endpos);//, getchar();
    return(-1);
}

int32_t hputbit(HUFF *hp,int32_t bit)
{
    //fprintf(stderr,"->%d ",bit);
    if ( bit != 0 )
        *hp->ptr |= huffmasks[hp->maski];
    else *hp->ptr &= huffoppomasks[hp->maski];
    if ( ++hp->maski >= 8 )
        hp->maski = 0, hp->ptr++;
    if ( ++hp->bitoffset > hp->endpos )
        hp->endpos = hp->bitoffset;
    if ( (hp->bitoffset>>3) >= hp->allocsize )
    {
        printf("hwrite: bitoffset.%d >= allocsize.%d\n",hp->bitoffset,hp->allocsize);
        hp->bitoffset--;
        hupdate_internals(hp);
        return(-1);
    }
    return(0);
}

int32_t hwrite(uint64_t codebits,int32_t numbits,HUFF *hp)
{
    int32_t i;
    for (i=0; i<numbits; i++,codebits>>=1)
        if ( hputbit(hp,codebits & 1) < 0 )
            return(-1);
    return(numbits);
}

uint64_t hread(int32_t *numbitsp,int32_t numbits,HUFF *hp)
{
    int32_t i,bit; uint64_t codebits = 0;
    for (i=0; i<numbits; i++)
    {
        codebits <<= 1;
        if ( (bit= hgetbit(hp)) < 0 )
            break;
        codebits |= bit;
    }
    *numbitsp = i;
    return(codebits);
}

int32_t hmemcpy(void *dest,void *src,HUFF *hp,int32_t datalen)
{
    if ( (hp->bitoffset & 7) != 0 || ((hp->bitoffset>>3) + datalen) > hp->allocsize )
    {
        printf("misaligned hmemcpy bitoffset.%d or overflow allocsize %d vs %d\n",hp->bitoffset,hp->allocsize,((hp->bitoffset>>3) + datalen));
        getchar();
        return(-1);
    }
    if ( dest != 0 && src == 0 )
        memcpy(dest,hp->ptr,datalen);
    else if ( dest == 0 && src != 0 )
        memcpy(hp->ptr,src,datalen);
    else
    {
        printf("invalid hmemcpy with both dest.%p and src.%p\n",dest,src);
        return(-1);
    }
    hp->ptr += datalen;
    hp->bitoffset += (datalen << 3);
    if ( hp->bitoffset > hp->endpos )
        hp->endpos = hp->bitoffset;
    return(datalen);
}

int32_t hcalc_bitsize(uint64_t x)
{
    uint64_t mask = ((uint64_t)1 << 63);
    int32_t i;
    if ( x == 0 )
        return(1);
    for (i=63; i>=0; i--,mask>>=1)
    {
        if ( (mask & x) != 0 )
            return(i+1);
    }
    return(-1);
}

int32_t init_ramcoder(struct ramcoder *coder,HUFF *hp,bits256 *seed)
{
    int32_t i,precision,numbits = 0;
    if ( coder->lastsymbol == 0 )
        coder->lastsymbol = RAMCODER_MAXSYMBOLS, coder->upper_lastsymbol = (coder->lastsymbol + 1);
    coder->cumulativeProb = coder->lower = coder->code = coder->underflowBits = coder->ranges[0] = 0;
    for (i=1; i<=coder->upper_lastsymbol; i++)
    {
        coder->ranges[i] = coder->ranges[i - 1] + 1 + 256*((i <= sizeof(seed)*8) ? (GETBIT(seed->bytes,i-1) != 0) : 0);
        //printf("%d ",coder->ranges[i]);
    }
    for (i=1; i<=coder->upper_lastsymbol; i++)
        coder->cumulativeProb += (coder->ranges[i] - coder->ranges[i - 1]);
    precision = (8 * sizeof(uint16_t));
    coder->upper = (1LL << precision) - 1;
    if ( hp != 0 )
    {
        for (i=0; i<precision; i++,numbits++)
            coder->code = (coder->code << 1) | hgetbit(hp);
        //coder->code = hread(&numbits,precision,hp), coder->code <<= (precision - numbits);
        //printf("set code %x\n",coder->code);
    }
    //printf("cumulative.%d code.%x numbits.%d\n",coder->cumulativeProb,coder->code,numbits);
    return(numbits);
}

int32_t ramcoder_state(struct ramcoder *coder)
{
    if ( (coder->upper & RAMMASK_BIT(0)) == (coder->lower & RAMMASK_BIT(0)) )
        return(0);
    else if ( (coder->lower & RAMMASK_BIT(1)) && (coder->upper & RAMMASK_BIT(1)) == 0 )
        return(1);
    else return(-1);
}

void ramcoder_normalize(struct ramcoder *coder) { coder->lower &= ~(RAMMASK_BIT(0) | RAMMASK_BIT(1)), coder->upper |= RAMMASK_BIT(1); }

void ramcoder_shiftbits(struct ramcoder *coder) { coder->lower <<= 1, coder->upper <<= 1, coder->upper |= 1; }

int32_t ramcoder_putbits(HUFF *hp,struct ramcoder *coder,int32_t flushflag)
{
    int32_t numbits = 0;
    while ( 1 )
    {
        switch ( ramcoder_state(coder) )
        {
            case 1:  coder->underflowBits++, ramcoder_normalize(coder); break;
            case 0:
                if ( hputbit(hp,(coder->upper & RAMMASK_BIT(0)) != 0) < 0 )
                    return(-1);
                numbits++;
                //printf("%d> ",(coder->upper & RAMMASK_BIT(0)) != 0);
                while ( coder->underflowBits > 0 )
                {
                    if ( hputbit(hp,(coder->upper & RAMMASK_BIT(0)) == 0) < 0 )
                        return(-1);
                    numbits++;
                    //printf("%d> ",(coder->upper & RAMMASK_BIT(0)) == 0);
                    coder->underflowBits--;
                }
                break;
            default:
                if ( flushflag != 0 )
                {
                    if ( hputbit(hp,(coder->lower & RAMMASK_BIT(1)) != 0) < 0 )
                        return(-1);
                    numbits++;
                    for (coder->underflowBits++; coder->underflowBits>0; coder->underflowBits--)
                    {
                        if ( hputbit(hp,(coder->lower & RAMMASK_BIT(1)) == 0) < 0 )
                            return(-1);
                        numbits++;
                    }
                }
                return(numbits);
                break;
        }
        ramcoder_shiftbits(coder);
    }
}

int32_t ramcoder_getbits(HUFF *hp,struct ramcoder *coder)
{
    int32_t nextBit,numbits = 0;
    while ( 1 )
    {
        switch ( ramcoder_state(coder) )
        {
            case 0: break; // MSBs match, allow them to be shifted out
            case 1: ramcoder_normalize(coder), coder->code ^= RAMMASK_BIT(1); break;
            default:  return(numbits); break;
        }
        ramcoder_shiftbits(coder);
        coder->code <<= 1;
        if ( (nextBit= hgetbit(hp)) >= 0 )
            coder->code |= nextBit;//, printf("<%c",'0'+nextBit);
        else return(-1);
        numbits++;
    }
}

int32_t ramdecoder_bsearch(uint16_t probability,struct ramcoder *coder)
{
    int32_t last,middle,first = 0;
    last = coder->upper_lastsymbol;
    while ( last >= first )
    {
        middle = first + ((last - first) / 2);
        //printf("[%d %d] ",coder->ranges[middle],coder->ranges[middle+1]);
        if ( probability < coder->ranges[middle] )
            last = middle - 1;
        else if ( probability >= coder->ranges[middle + 1] )
            first = middle + 1;
        else return(middle);
    }
    printf("Unknown Symbol: %llu (max: %llu)\n",(long long)probability,(long long)coder->ranges[coder->upper_lastsymbol]);
    return(-1);
}

int32_t ramcoder_update(int symbol,struct ramcoder *coder,int32_t updateprobs,int32_t putflags,HUFF *hp)
{
    uint32_t range; uint16_t i,original,delta;
//printf("putflags.%d %p: upper %llu lower %llu code.%x cumulative.%d | symbol.%d\n",putflags,coder,(long long)coder->upper,(long long)coder->lower,coder->code,coder->cumulativeProb,symbol);
    range = (uint32_t)(coder->upper - coder->lower) + 1;
    coder->upper = coder->lower + (uint16_t)(((uint32_t)coder->ranges[symbol + 1] * range)/ coder->cumulativeProb) - 1;
    coder->lower = coder->lower + (uint16_t)(((uint32_t)coder->ranges[symbol] * range) / coder->cumulativeProb);
    if ( updateprobs != 0 )
    {
        coder->cumulativeProb++;
        for (i=(symbol+1); i<=coder->upper_lastsymbol; i++)
            coder->ranges[i]++;
        if ( coder->cumulativeProb >= (1 << ((8 * sizeof(uint16_t)) - 2)) )
        {
            original = coder->cumulativeProb = 0;
            for (i=1; i<=coder->upper_lastsymbol; i++)
            {
                delta = coder->ranges[i] - original, original = coder->ranges[i];
                if ( delta <= 2 )
                    coder->ranges[i] = coder->ranges[i - 1] + 1;
                else coder->ranges[i] = coder->ranges[i - 1] + (delta / 2);
                coder->cumulativeProb += (coder->ranges[i] - coder->ranges[i - 1]);
            }
        }
        coder->counter++;
    } else printf("unexpected non-update ramcoder\n");
    if ( coder->lower > coder->upper )
        printf("ramcoderupdate: coder->lower %llu > %llu coder->upper\n",(long long)coder->lower,(long long)coder->upper);
    return((putflags != 0) ? ramcoder_putbits(hp,coder,putflags & RAMCODER_FINALIZE) : ramcoder_getbits(hp,coder));
}

int32_t ramcoder_emit(HUFF *hp,struct ramcoder *coder,int32_t updateprobs,uint8_t *buf,int32_t len)
{
    int32_t i,n,numbits = 0;
    for (i=0; i<len; i++)
    {
        if ( coder->histo != 0 )
            coder->histo[buf[i]]++;
        if ( (n= ramcoder_update(buf[i],coder,updateprobs,RAMCODER_PUTBITS,hp)) < 0 )
            return(-1);
        numbits += n;
    }
    return(numbits);
}

int32_t ramcoder_encoder(struct ramcoder *coder,int32_t updateprobs,uint8_t *buf,int32_t len,HUFF *hp,uint64_t *histo,bits256 *seed)
{
    int32_t i,threshold; uint8_t _coder[sizeof(*coder) + (RAMCODER_MAXSYMBOLS+2)*sizeof(coder->ranges[0])];
    if ( coder == 0 )
    {
        memset(_coder,0,sizeof(_coder));
        hrewind(hp);
        coder = (struct ramcoder *)_coder;
        coder->histo = histo;
        init_ramcoder(coder,0,seed);
        if ( ramcoder_emit(hp,coder,updateprobs,buf,len) < 0 )
            return(-1);
        if ( ramcoder_update(coder->lastsymbol,coder,updateprobs,RAMCODER_PUTBITS,hp) < 0 )
            return(-1);
        if ( ramcoder_update(coder->lastsymbol,coder,updateprobs,RAMCODER_PUTBITS|RAMCODER_FINALIZE,hp) < 0 )
            return(-1);
    }
    else if ( ramcoder_emit(hp,coder,updateprobs,buf,len) < 0 )
        return(-1);
    memset(seed,0,sizeof(*seed));
    threshold = coder->cumulativeProb / coder->upper_lastsymbol;
    for (i=1; i<=coder->upper_lastsymbol; i++)
        if ( (coder->ranges[i] - coder->ranges[i - 1]) > threshold )
            SETBIT(seed->bytes,i-1);
    return(hp->bitoffset);
}

int32_t ramcoder_decode(struct ramcoder *coder,int32_t updateprobs,HUFF *hp)
{
    int32_t ind;
#define RAMDECODER_UNSCALED(coder) ((((uint32_t)coder->code - coder->lower) + 1) * (uint32_t)coder->cumulativeProb - 1) / (((uint32_t)coder->upper - coder->lower) + 1)
    if ( (ind= ramdecoder_bsearch(RAMDECODER_UNSCALED(coder),coder)) < 0 || ind == coder->lastsymbol )
        return(-1);
    if ( ramcoder_update(ind,coder,updateprobs,0,hp) < 0 )
        return(-1);
    return(ind);
}

int32_t ramcoder_decoder(struct ramcoder *coder,int32_t updateprobs,uint8_t *buf,int32_t maxlen,HUFF *hp,bits256 *seed)
{
    uint8_t _coder[sizeof(*coder) + (RAMCODER_MAXSYMBOLS+2)*sizeof(coder->ranges[0])];
    int32_t val,n = 0,numbits = 0;
    if ( coder == 0 )
    {
        memset(_coder,0,sizeof(_coder));
        coder = (struct ramcoder *)_coder;
        hrewind(hp);
        numbits = init_ramcoder(coder,hp,seed);
    }
    while ( n < maxlen )
    {
        if ( (val= ramcoder_decode(coder,updateprobs,hp)) < 0 )
            return(n);
        buf[n++] = val;
    }
    return(n);
}

int32_t ramcoder_compress(uint8_t *bits,int32_t maxlen,uint8_t *data,int32_t datalen,bits256 origseed)
{
    uint64_t histo[256]; bits256 seed; char str[65]; int32_t numbits; HUFF H,*hp = &H;
    _init_HUFF(hp,maxlen,bits);
    memset(histo,0,sizeof(histo));
    seed = origseed;
    if ( ramcoder_encoder(0,1,data,datalen,hp,histo,&seed) < 0 )
        return(-1);
    printf("seed.%s\n",bits256_str(str,seed));
    numbits = hp->bitoffset;
    if ( (1) )
    {
        void *malloc(size_t); void free(void *);
        int32_t i,checklen; uint8_t *checkbuf;
        checkbuf = malloc(datalen*2);
        seed = origseed;
        hrewind(hp);
        checklen = ramcoder_decoder(0,1,checkbuf,datalen*2,hp,&seed);
        if ( checklen != datalen || memcmp(checkbuf,data,datalen) != 0 )
        {
            for (i=0; i<datalen; i++)
                printf("%02x ",data[i]);
            printf("datalen.%d\n",datalen);
            for (i=0; i<=numbits/8; i++)
                printf("%02x ",bits[i]);
            printf("bitoffset.%d\n",numbits);
            for (i=0; i<checklen; i++)
                printf("%02x ",checkbuf[i]);
            printf("checklen.%d\n",checklen);
            getchar();
        } else printf("CODEC passed datalen.%d -> numbits %d %d origseed.%s\n",datalen,numbits,numbits/8,bits256_str(str,origseed));
        free(checkbuf);
    }
    return(numbits);
}

int32_t ramcoder_decompress(uint8_t *data,int32_t maxlen,uint8_t *bits,uint32_t numbits,bits256 seed)
{
    HUFF H,*hp = &H;
    _init_HUFF(hp,(uint32_t)hconv_bitlen(numbits),bits);
    hp->endpos = numbits;
    hrewind(hp);
    return(ramcoder_decoder(0,1,data,maxlen,hp,&seed));
}

#endif
#endif
