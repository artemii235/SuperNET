
/*
 * This file is Copyright Daniel Silverstone <dsilvers@digital-scurf.org> 2006,2015
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include "iguana777.h"
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_schnorr.h"
#include "secp256k1/include/secp256k1_rangeproof.h"

// ------------------------------------------------------[ Preparation ]----

static gfshare_ctx *_gfshare_ctx_init_core(uint8_t *sharenrs,uint32_t sharecount,uint8_t threshold,uint32_t size,void *space,int32_t spacesize)
{
    gfshare_ctx *ctx; int32_t allocsize;
    allocsize = (int32_t)(sizeof(struct _gfshare_ctx) + threshold * size);
    if ( allocsize > spacesize )
    {
        printf("malloc allocsize %d vs spacesize.%d\n",allocsize,spacesize);
        ctx = malloc(allocsize);
        if( ctx == NULL )
            return NULL; // errno should still be set from XMALLOC()
        ctx->allocsize = allocsize;
    } else ctx = space;
    memset(ctx,0,allocsize);
    ctx->sharecount = sharecount;
    ctx->threshold = threshold;
    ctx->size = size;
    memcpy(ctx->sharenrs,sharenrs,sharecount);
    ctx->buffersize = threshold * size;
    return(ctx);
}

// Initialise a gfshare context for producing shares
gfshare_ctx *gfshare_ctx_initenc(uint8_t *sharenrs,uint32_t sharecount,uint8_t threshold,uint32_t size,void *space,int32_t spacesize)
{
    uint32_t i;
    for (i=0; i<sharecount; i++)
    {
        if ( sharenrs[i] == 0 )
        {
            // can't have x[i] = 0 - that would just be a copy of the secret, in
            // theory (in fact, due to the way we use exp/log for multiplication and
            // treat log(0) as 0, it ends up as a copy of x[i] = 1)
            errno = EINVAL;
            return NULL;
        }
    }
    return(_gfshare_ctx_init_core(sharenrs,sharecount,threshold,size,space,spacesize));
}

// Initialise a gfshare context for recombining shares
gfshare_ctx *gfshare_ctx_initdec(uint8_t *sharenrs,uint32_t sharecount,uint32_t size,void *space,int32_t spacesize)
{
    gfshare_ctx *ctx = _gfshare_ctx_init_core(sharenrs,sharecount,sharecount,size,space,spacesize);
    if ( ctx != NULL )
        ctx->threshold = 0;
    return(ctx);
}

// Free a share context's memory
void gfshare_ctx_free(gfshare_ctx *ctx)
{
    OS_randombytes(ctx->buffer,ctx->buffersize);
    OS_randombytes(ctx->sharenrs,ctx->sharecount);
    if ( ctx->allocsize != 0 )
    {
        OS_randombytes((uint8_t *)ctx,sizeof(struct _gfshare_ctx));
        free(ctx);
    }
    OS_randombytes((uint8_t *)ctx,sizeof(struct _gfshare_ctx));
}

// --------------------------------------------------------[ Splitting ]----

// Provide a secret to the encoder. (this re-scrambles the coefficients)
void gfshare_ctx_enc_setsecret(gfshare_ctx *ctx,uint8_t *secret)
{
    memcpy(ctx->buffer + ((ctx->threshold-1) * ctx->size),secret,ctx->size);
    OS_randombytes(ctx->buffer,(ctx->threshold-1) * ctx->size);
}

// Extract a share from the context. 'share' must be preallocated and at least 'size' bytes long. 'sharenr' is the index into the 'sharenrs' array of the share you want.
void gfshare_ctx_encgetshare(uint8_t *_logs,uint8_t *_exps,gfshare_ctx *ctx,uint8_t sharenr,uint8_t *share)
{
    uint32_t pos,coefficient,ilog = _logs[ctx->sharenrs[sharenr]];
    uint8_t *share_ptr,*coefficient_ptr = ctx->buffer;
    for (pos=0; pos<ctx->size; pos++)
        share[pos] = *(coefficient_ptr++);
    for (coefficient=1; coefficient<ctx->threshold; coefficient++)
    {
        share_ptr = share;
        for (pos=0; pos<ctx->size; pos++)
        {
            uint8_t share_byte = *share_ptr;
            if ( share_byte != 0 )
                share_byte = _exps[ilog + _logs[share_byte]];
            *share_ptr++ = share_byte ^ *coefficient_ptr++;
        }
    }
}

// ----------------------------------------------------[ Recombination ]----

// Inform a recombination context of a change in share indexes
void gfshare_ctx_dec_newshares(gfshare_ctx *ctx,uint8_t *sharenrs)
{
    memcpy(ctx->sharenrs,sharenrs,ctx->sharecount);
}

// Provide a share context with one of the shares. The 'sharenr' is the index into the 'sharenrs' array
void gfshare_ctx_dec_giveshare(gfshare_ctx *ctx,uint8_t sharenr,uint8_t *share)
{
    memcpy(ctx->buffer + (sharenr * ctx->size),share,ctx->size);
}

// Extract the secret by interpolating the shares. secretbuf must be allocated and at least 'size' bytes
void gfshare_ctx_decextract(uint8_t *_logs,uint8_t *_exps,gfshare_ctx *ctx,uint8_t *secretbuf)
{
    uint32_t i,j; uint8_t *secret_ptr,*share_ptr,sharei,sharej;
    for (i=0; i<ctx->size; i++)
        secretbuf[i] = 0;
    for (i=0; i<ctx->sharecount; i++)
    {
        // Compute L(i) as per Lagrange Interpolation
        unsigned Li_top = 0, Li_bottom = 0;
        if ( (sharei= ctx->sharenrs[i]) != 0 )
        {
            for (j=0; j<ctx->sharecount; j++)
            {
                if ( i != j && sharei != (sharej= ctx->sharenrs[j]) )
                {
                    if ( sharej == 0 )
                        continue; // skip empty share
                    Li_top += _logs[sharej];
                    if ( Li_top >= 0xff )
                        Li_top -= 0xff;
                    Li_bottom += _logs[sharei ^ sharej];
                    if ( Li_bottom >= 0xff )
                        Li_bottom -= 0xff;
                }
            }
            if ( Li_bottom  > Li_top )
                Li_top += 0xff;
            Li_top -= Li_bottom; // Li_top is now log(L(i))
            secret_ptr = secretbuf, share_ptr = ctx->buffer + (ctx->size * i);
            for (j=0; j<ctx->size; j++)
            {
                if ( *share_ptr != 0 )
                    *secret_ptr ^= _exps[Li_top + _logs[*share_ptr]];
                share_ptr++, secret_ptr++;
            }
        }
    }
}

int32_t gfshare_test(struct supernet_info *myinfo,int32_t M,int32_t N,int32_t datasize)
{
    int ok = 1, i,k;
    uint8_t * secret = malloc(datasize);
    uint8_t *shares[255];
    uint8_t *recomb = malloc(datasize);
    uint8_t space[8192],sharenrs[255],newsharenrs[255];// = (uint8_t *)strdup("0124z89abehtr");
    gfshare_ctx *G;
    for (i=0; i<N; i++)
    {
        sharenrs[i] = i+1;
        shares[i] = malloc(datasize);
    }
    init_sharenrs(sharenrs,0,N,N);
    /* Stage 1, make a secret */
    for( i = 0; i < datasize; ++i )
        secret[i] = (rand() & 0xff00) >> 8;
    /* Stage 2, split it N ways with a threshold of M */
    G = gfshare_ctx_initenc( sharenrs, N, M, datasize,space,sizeof(space) );
    gfshare_ctx_enc_setsecret( G, secret );
    for (i=0; i<N; i++)
        gfshare_ctx_encgetshare(myinfo->logs,myinfo->exps, G, i, shares[i] );
    gfshare_ctx_free( G );
    /* Prep the decode shape */
    uint8_t save[255];
    memcpy(save,sharenrs,sizeof(sharenrs));
    G = gfshare_ctx_initdec( sharenrs, N, datasize,space,sizeof(space) );
    for (k=0; k<10; k++)
    {
        memcpy(sharenrs,save,sizeof(sharenrs));
        memset(newsharenrs,0,N);
        int32_t j,r,m;
        m = M + (rand() % (N-M+1));
        for (i=0; i<m && i<N; i++)
        {
            r = rand() % N;
            while ( (j= sharenrs[r]) == 0 || newsharenrs[r] != 0 )
                r = rand() % N;
            newsharenrs[r] = j;
            sharenrs[r] = 0;
        }
        for (i=0; i<N; i++)
        {
            if ( newsharenrs[i] != 0 )
            {
                fprintf(stderr,"%d ",newsharenrs[i]);
                gfshare_ctx_dec_giveshare( G, i, shares[i] );
            }
            //newsharenrs[i] = sharenrs[i];
        }
        gfshare_ctx_dec_newshares( G, newsharenrs );
        gfshare_ctx_decextract(myinfo->logs,myinfo->exps, G, recomb );
        for (i=0; i<datasize; i++)
            if ( secret[i] != recomb[i] )
                ok = 0;
        printf("m.%d M.%-3d N.%-3d ok.%d datalen.%d\n",m,M,N,ok,datasize);
    }
    free(recomb), free(secret);
    for (i=0; i<N; i++)
        free(shares[i]);
    return ok!=1;
}

void *bitcoin_ctx()
{
    void *ptr;
    ptr = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pedersen_context_initialize(ptr);
    secp256k1_rangeproof_context_initialize(ptr);
    return(ptr);
}

void iguana_fixsecp(struct supernet_info *myinfo)
{
    myinfo->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pedersen_context_initialize(myinfo->ctx);
    secp256k1_rangeproof_context_initialize(myinfo->ctx);
}

void libgfshare_init(struct supernet_info *myinfo,uint8_t _logs[256],uint8_t _exps[510])
{
    uint32_t i,x = 1;
    myinfo->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pedersen_context_initialize(myinfo->ctx);
    secp256k1_rangeproof_context_initialize(myinfo->ctx);
    for (i=0; i<255; i++)
    {
        _exps[i] = x;
        _logs[x] = i;
        x <<= 1;
        if ( x & 0x100 )
            x ^= 0x11d; // Unset the 8th bit and mix in 0x1d
    }
    for (i=255; i<510; i++)
        _exps[i] = _exps[i % 255];
    _logs[0] = 0; // can't log(0) so just set it neatly to 0
    if ( (0) )
    {
        void test_mofn(struct supernet_info *myinfo);
        gfshare_test(myinfo,6,11,32);
        test_mofn(myinfo);
        getchar();
    }
}

// Construct and write out the tables for the gfshare code
int maingen(int argc,char **argv)
{
    uint8_t logs[256],exps[255]; uint32_t i;
    libgfshare_init(0,logs,exps);
    // The above generation algorithm clearly demonstrates that
    // logs[exps[i]] == i for 0 <= i <= 254
    // exps[logs[i]] == i for 1 <= i <= 255
    // Spew out the tables
    fprintf(stdout, "\
            /*\n\
            * This file is autogenerated by gfshare_maketable.\n\
            */\n\
            \n\
            static uint8_t logs[256] = {\n  ");
    for ( i = 0; i < 256; ++i )
    {
        fprintf(stdout, "0x%02x", logs[i]);
        if( i == 255 )
            fprintf(stdout, " };\n");
        else if( (i % 8) == 7 )
            fprintf(stdout, ",\n  ");
        else
            fprintf(stdout, ", ");
    }
    // The exp table we output from 0 to 509 because that way when we
    // do the lagrange interpolation we don't have to be quite so strict
    // with staying inside the field which makes it quicker
    fprintf(stdout, "\
            \n\
            static uint8_t exps[510] = {\n  ");
    for ( i = 0; i < 510; ++i )
    {
        fprintf(stdout, "0x%02x", exps[i % 255]); /* exps[255]==exps[0] */
        if ( i == 509 )
            fprintf(stdout, " };\n");
        else if( (i % 8) == 7)
            fprintf(stdout, ",\n  ");
        else
            fprintf(stdout, ", ");
    }
    return 0;
}

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

int32_t init_sharenrs(uint8_t sharenrs[255],uint8_t *orig,int32_t m,int32_t n)
{
    uint8_t *randvals,valid[255];
    int32_t i,j,r,remains,orign;
    if ( m > n || n >= 0xff ) // reserve 255 for illegal sharei
    {
        printf("illegal M.%d of N.%d\n",m,n);
        return(-1);
    }
    randvals = calloc(1,65536);
    OS_randombytes(randvals,65536);
    if ( orig == 0 && n == m )
    {
        memset(sharenrs,0,n);
        for (i=0; i<255; i++)
            valid[i] = (i + 1);
        remains = orign = 255;
        for (i=0; i<n; i++)
        {
            r = (randvals[i] % remains);
            sharenrs[i] = valid[r];
            printf("%d ",sharenrs[i]);
            valid[r] = valid[--remains];
        }
        printf("FULL SET\n");
    }
    else
    {
        memcpy(valid,orig,n);
        memset(sharenrs,0,n);
        for (i=0; i<n; i++)
            printf("%d ",valid[i]);
        printf("valid\n");
        for (i=0; i<m; i++)
        {
            r = rand() % n;
            while ( (j= valid[r]) == 0 )
            {
                //printf("i.%d j.%d m.%d n.%d r.%d\n",i,j,m,n,r);
                r = rand() % n;
            }
            sharenrs[i] = j;
            valid[r] = 0;
        }
        for (i=0; i<n; i++)
            printf("%d ",valid[i]);
        printf("valid\n");
        for (i=0; i<m; i++)
            printf("%d ",sharenrs[i]);
        printf("sharenrs vals m.%d of n.%d\n",m,n);
        //getchar();
    }
    free(randvals);
    for (i=0; i<m; i++)
    {
        for (j=0; j<m; j++)
        {
            if ( i == j )
                continue;
            if ( sharenrs[i] != 0 && sharenrs[i] == sharenrs[j] )
            {
                printf("FATAL: duplicate entry sharenrs[%d] %d vs %d sharenrs[%d]\n",i,sharenrs[i],sharenrs[j],j);
                return(-1);
            }
        }
    }
    return(0);
}

uint8_t *recoverdata(struct supernet_info *myinfo,uint8_t *shares[],uint8_t *sharenrs,int32_t M,uint8_t *recover,int32_t datasize,int32_t N)
{
    void *G; int32_t i,m=0; uint8_t recovernrs[255],space[8192];
    memset(recovernrs,0,sizeof(recovernrs));
    for (i=0; i<N; i++)
        if ( shares[i] != 0 )
            recovernrs[i] = sharenrs[i], m++;
    if ( m >= M )
    {
        G = gfshare_ctx_initdec(recovernrs,N,datasize,space,sizeof(space));
        for (i=0; i<N; i++)
            if ( shares[i] != 0 )
                gfshare_ctx_dec_giveshare(G,i,shares[i]);
        gfshare_ctx_dec_newshares(G,recovernrs);
        gfshare_ctx_decextract(myinfo->logs,myinfo->exps,G,recover);
        gfshare_ctx_free(G);
        return(recover);
    } else return(0);
}

void calc_share(struct supernet_info *myinfo,uint8_t *buffer,int32_t size,int32_t M,uint32_t ilog,uint8_t *share)
{
    uint32_t pos,coefficient; uint8_t *share_ptr,share_byte;
    for (pos=0; pos<size; pos++)
        share[pos] = *(buffer++);
    for (coefficient=1; coefficient<M; coefficient++)
    {
        share_ptr = share;
        for (pos=0; pos<size; pos++)
        {
            share_byte = *share_ptr;
            if ( share_byte != 0 )
                share_byte = myinfo->exps[ilog + myinfo->logs[share_byte]];
            *share_ptr++ = (share_byte ^ *buffer++);
        }
    }
}

void calc_shares(struct supernet_info *myinfo,uint8_t *shares,uint8_t *secret,int32_t size,int32_t width,int32_t M,int32_t N,uint8_t *sharenrs,uint8_t *space,int32_t spacesize)
{
    int32_t i; uint8_t *buffer;
    if ( M*width > spacesize )
    {
        buffer = calloc(M,width);
        printf("calloc M.%d width.%d\n",M,width);
    } else buffer = space;
    memset(shares,0,N * width);
    memcpy(buffer + ((M - 1) * size),secret,size);
    OS_randombytes(buffer,(M - 1) * size);
    for (i=0; i<N; i++)
    {
        calc_share(myinfo,buffer,size,M,myinfo->logs[sharenrs[i]],&shares[i * width]);
        //printf("(%03d %08x) ",sharenrs[i],calc_crc32(0,&shares[i * width],size));
    }
    if ( buffer != space )
        free(buffer);
}

int32_t calc_sharenrs(uint8_t *sharenrs,int32_t N,uint8_t *data,int32_t datasize)
{
    bits256 hash,hash2; uint8_t r; int32_t i,j,n = sizeof(hash);
    vcalc_sha256(0,hash.bytes,data,datasize);
    vcalc_sha256(0,hash2.bytes,hash.bytes,sizeof(hash));
    for (i=0; i<N; i++)
    {
        while ( 1 )
        {
            if ( n >= sizeof(hash) )
            {
                vcalc_sha256(0,hash.bytes,hash2.bytes,sizeof(hash2));
                vcalc_sha256(0,hash2.bytes,hash.bytes,sizeof(hash));
                n = 0;
            }
            r = hash2.bytes[n++];
            if ( (sharenrs[i]= r) == 0 || sharenrs[i] == 0xff )
                continue;
            for (j=0; j<i; j++)
                if ( sharenrs[j] == sharenrs[i] )
                    break;
            if ( j == i )
                break;
        }
        //printf("%3d ",sharenrs[i]);
    }
    return(N);
}

int32_t calcmofn(struct supernet_info *myinfo,uint8_t *allshares,uint8_t *sharenrs,int32_t M,uint8_t *data,int32_t datasize,int32_t N)
{
    uint8_t space[8192];
    calc_sharenrs(sharenrs,N,data,datasize);
    calc_shares(myinfo,allshares,(void *)data,datasize,datasize,M,N,sharenrs,space,sizeof(space));
    return(datasize);
}

struct mofn256_info
{
    bits256 secret;
    uint8_t *sharenrs;
    int32_t M,N,allocsize;
    bits256 allshares[];
};

int32_t mofn256_size(uint8_t M,uint8_t N)
{
    int32_t allocsize;
    allocsize = ((int32_t)(sizeof(struct mofn256_info) + sizeof(bits256) * N + N));
    if ( (allocsize & 0xf) != 0 )
        allocsize += 0x10 - (allocsize & 0xf);
    return(allocsize);
}

struct mofn256_info *mofn256_init(struct supernet_info *myinfo,bits256 secret,uint8_t M,uint8_t N,int32_t calcflag,uint8_t *space,int32_t spacesize)
{
    int32_t allocsize; struct mofn256_info *mofn = 0;
    if ( M > N || N == 0 || N == 0xff )
        return(0);
    allocsize = mofn256_size(M,N);
    if ( allocsize > spacesize )
    {
        mofn = calloc(1,allocsize);
        mofn->allocsize = allocsize;
    }
    else
    {
        mofn = (void *)space;
        memset(mofn,0,allocsize);
    }
    mofn->M = M;
    mofn->N = N;
    mofn->sharenrs = (void *)&mofn->allshares[N];
    if ( calcflag != 0 )
    {
        mofn->secret = secret;
        calcmofn(myinfo,mofn->allshares[0].bytes,mofn->sharenrs,M,secret.bytes,sizeof(secret),N);
    }
    return(mofn);
}

bits256 mofn256_recover(struct supernet_info *myinfo,struct mofn256_info *mofn)
{
    uint8_t *shares[255]; bits256 recover; int32_t i;
    for (i=0; i<mofn->N; i++)
    {
        if ( bits256_nonz(mofn->allshares[i]) != 0 )
            shares[i] = mofn->allshares[i].bytes;
        else shares[i] = 0;
    }
    if ( recoverdata(myinfo,shares,mofn->sharenrs,mofn->M,recover.bytes,sizeof(recover),mofn->N) == 0 )
        memset(recover.bytes,0,sizeof(recover));
    return(recover);
}

int32_t test_mofn256(struct supernet_info *myinfo,int32_t M,int32_t N)
{
    uint8_t space[8192]; char str[65],str2[65]; struct mofn256_info *mofn,*cmp; bits256 secret,recover; int32_t i,allocsize,retval,m = 0;
    allocsize = mofn256_size(M,N);
    cmp = mofn256_init(myinfo,GENESIS_PUBKEY,M,N,0,space,sizeof(space));
    secret = rand256(0);
    mofn = mofn256_init(myinfo,secret,M,N,1,&space[allocsize],sizeof(space) - allocsize);
    memcpy(cmp->sharenrs,mofn->sharenrs,mofn->N);
    for (i=0; i<N; i++)
        if ( (rand() % 100) < 50 )
            cmp->allshares[i] = mofn->allshares[i], m++;
    recover = mofn256_recover(myinfo,cmp);
    retval = -1 * (bits256_cmp(recover,mofn->secret) != 0);
    if ( bits256_cmp(recover,mofn->secret) != 0 )
    {
        if ( m >= M )
            printf("%s %s error m.%d vs M.%d N.%d\n",bits256_str(str,secret),bits256_str(str2,recover),m,mofn->M,mofn->N);
    }
#if defined(_M_X64)
	if (((uint64_t)mofn - (uint64_t)space) >= sizeof(space) || ((uint64_t)mofn - (uint64_t)space) < 0)
		free(mofn);
	if (((uint64_t)cmp - (uint64_t)space) >= sizeof(space) || ((uint64_t)cmp - (uint64_t)space) < 0)
		free(cmp);
#else
    if ( ((long)mofn - (long)space) >= sizeof(space) || ((long)mofn - (long)space) < 0 )
        free(mofn);
    if ( ((long)cmp - (long)space) >= sizeof(space) || ((long)cmp - (long)space) < 0 )
        free(cmp);
#endif
    return(retval);
}

#define N 11
#define M 6
void test_mofn(struct supernet_info *myinfo)
{
    bits256 allshares[N],secret,recover; uint8_t *shares[N],sharenrs[N]; int32_t i,j,m;
    secret = rand256(0);
    srand(secret.uints[0]);
    calcmofn(myinfo,allshares[0].bytes,sharenrs,M,secret.bytes,sizeof(secret),N);
    for (i=0; i<10000; i++)
    {
        memset(shares,0,sizeof(shares));
        for (j=m=0; j<N; j++)
            if ( (rand() % 100) < 55 )
                shares[j] = allshares[j].bytes, m++;
        if ( recoverdata(myinfo,shares,sharenrs,M,recover.bytes,sizeof(secret),N) != 0 )
        {
            if ( memcmp(secret.bytes,recover.bytes,sizeof(secret)) != 0 )
                printf("FAILED m.%d M.%d N.%d\n",m,M,N);
            else if ( (0) )
            {
                char str[65];
                printf("%s PASSED m.%d M.%d N.%d\n",bits256_str(str,recover),m,M,N);
            }
        } //else printf("not enough shares m.%d M.%d N.%d\n",m,M,N);
    }
    printf("finished %d tests\n",i);
    for (i=0; i<10000; i++)
        test_mofn256(myinfo,M,N);
    printf("finished %d tests256\n",i);
}
#undef M
#undef N

#define SECP_ENSURE_CTX int32_t flag = 0; if ( ctx == 0 ) { ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY); secp256k1_pedersen_context_initialize(ctx); secp256k1_rangeproof_context_initialize(ctx); flag++; } else flag = 0; if ( ctx != 0 )
#define ENDSECP_ENSURE_CTX if ( flag != 0 ) secp256k1_context_destroy(ctx);

int32_t iguana_schnorr_peersign(void *ctx,uint8_t *allpub33,uint8_t *partialsig64,int32_t peeri,bits256 mypriv,bits256 privnonce,bits256 *nonces,int32_t n,bits256 msg256)
{
    secp256k1_pubkey Rall,ALL,PUBS[256],*PUBptrs[256]; int32_t i,num,retval = -1; size_t plen; uint8_t pubkey[33];
    pubkey[0] = 2;
    SECP_ENSURE_CTX
    {
        for (i=num=0; i<n; i++)
        {
            plen = 33;
            memcpy(pubkey+1,nonces[i].bytes,32);
            if ( secp256k1_ec_pubkey_parse(ctx,&PUBS[i],pubkey,plen) == 0 )
                printf("error extracting pubkey.%d of %d\n",i,n);
            if ( i != peeri )
                PUBptrs[num++] = &PUBS[i];
        }
        PUBptrs[num] = &PUBS[peeri];
        if ( secp256k1_ec_pubkey_combine(ctx,&ALL,(void *)PUBptrs,num+1) != 0 )
        {
            plen = 33;
            secp256k1_ec_pubkey_serialize(ctx,allpub33,&plen,&ALL,SECP256K1_EC_COMPRESSED);
            //for (i=0; i<33; i++)
            //    printf("%02x",allpub33[i]);
            //printf("\n");
        } else printf("error combining ALL\n");
        if ( secp256k1_ec_pubkey_combine(ctx,&Rall,(void *)PUBptrs,num) != 0 )
        {
            if ( secp256k1_schnorr_partial_sign(ctx,partialsig64,msg256.bytes,mypriv.bytes,&Rall,privnonce.bytes) == 0 )
                printf("iguana_schnorr_peersign: err %d of num.%d\n",peeri,n);
            else retval = 0;
        } else printf("error parsing pubkey.%d\n",peeri);
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

bits256 iguana_schnorr_noncepair(void *ctx,bits256 *pubkey,uint8_t odd_even,bits256 msg256,bits256 privkey,int32_t maxj)
{
    bits256 privnonce; int32_t j; uint8_t pubkey33[33];
    memset(privnonce.bytes,0,sizeof(privnonce));
    for (j=0; j<maxj; j++)
    {
        privnonce = bitcoin_schnorr_noncepair(ctx,pubkey33,msg256,privkey);
        if ( pubkey33[0] == (odd_even + 2) )
        {
            memcpy(pubkey->bytes,pubkey33+1,32);
            break;
        }
    }
    if ( j == maxj )
    {
        printf("couldnt generate even noncepair\n");
        iguana_exit(0,0);
    }
    return(privnonce);
}

struct schnorr_info
{
    bits256 msg256,privkey,pubkey,privnonce,pubnonce,serhash2;
    int32_t M,N; uint32_t msgid;
    uint8_t sig64[64],combinedsig64[64],allpub[33],combined_allpub[33];
    uint16_t ind,nonz;
    bits256 *pubkeys,*pubnonces;
    uint8_t serialized[65 + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(bits256)*4];
    uint8_t sigs[];
};

int32_t schnorr_rwinitdata(int32_t rwflag,uint8_t *serialized,uint16_t *indp,uint32_t *msgidp,bits256 hashes[4])
{
    int32_t i,j,len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(*indp),indp);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(*msgidp),msgidp);
    for (j=0; j<4; j++)
        for (i=0; i<32; i++)
            iguana_rwnum(rwflag,&serialized[len++],1,&hashes[j].bytes[i]);
    return(len);
}

struct schnorr_info *schnorr_init(struct supernet_info *myinfo,uint32_t msgid,uint16_t ind,int32_t M,int32_t N,void *space,int32_t spacesize,bits256 msg256)
{
    uint8_t *serialized; bits256 hashes[4]; int32_t len,odd_even = 0; struct schnorr_info *si = space;
    si->pubnonces = (void *)&si->sigs[N * 64];
    si->pubkeys = &si->pubnonces[N];
    si->M = M;
    si->N = N;
    si->ind = ind;
    si->msgid = msgid;
    si->msg256 = msg256;
    si->pubkey = bitcoin_pub256(myinfo->ctx,&si->privkey,odd_even);
    si->privnonce = iguana_schnorr_noncepair(myinfo->ctx,&si->pubnonce,odd_even,msg256,si->privkey,100);
    len = 0;
    serialized = &si->serialized[65];
    hashes[0] = myinfo->myaddr.persistent;
    hashes[1] = si->pubkey;
    hashes[2] = si->pubnonce;
    hashes[3] = msg256;
    len = schnorr_rwinitdata(1,serialized,&ind,&msgid,hashes);
    blockhash_sha256(si->serhash2.bytes,serialized,len);
    if ( bitcoin_sign(myinfo->ctx,"SCHNORR",si->serialized,si->serhash2,myinfo->persistent_priv,1) != 65 )
        printf("error signing schnorr initdata\n");
    return(si);
}

int32_t schnorr_update(struct supernet_info *myinfo,struct schnorr_info *si,uint8_t *serialized,int32_t recvlen)
{
    int32_t len; uint16_t ind; uint32_t msgid; bits256 hashes[4];
    // verify compact sig
    len = schnorr_rwinitdata(0,&serialized[65],&ind,&msgid,hashes);
    // verify persistent pubkey matches ind
    if ( bits256_cmp(hashes[3],si->msg256) == 0 && msgid == si->msgid && bits256_nonz(si->pubkeys[ind]) == 0 && bits256_nonz(si->pubnonces[ind]) == 0 )
    {
        si->pubkeys[ind] = hashes[1];
        si->pubnonces[ind] = hashes[2];
        if ( ++si->nonz >= si->M )
        {
            iguana_schnorr_peersign(myinfo->ctx,si->allpub,si->sig64,si->ind,si->privkey,si->privnonce,si->pubnonces,si->M,si->msg256);
            // broadcast si->sig64 + ind + msgid
        }
    }
    return(si->M);
}

/*{
    if ( bitcoin_schnorr_combine(myinfo->ctx,si->combinedsig64,si->combined_allpub,si->sigs,si->M,si->msg256) < 0 )
        printf("error combining k.%d sig64 iter.%d\n",k,iter);
    if ( bitcoin_schnorr_verify(myinfo->ctx,si->combinedsig64,si->msg256,si->combined_allpub,33) < 0 )
        printf("allpub2 error verifying combined sig k.%d\n",k);
}*/

void iguana_schnorr(struct supernet_info *myinfo)
{
    uint8_t allpubs[256][33],allpub[33],allpub2[33],sig64s[256][64],sig64[64],*sigs[256]; bits256 msg256,privnonces[256],signers,privkeys[256],pubkeys[256],pubkeysB[256],nonces[256]; int32_t i,iter,n,k,maxj = 100;
    OS_randombytes((void *)&n,sizeof(n));
    srand(n);
    n = 1 + (rand() % 255);
    // generate onetime keypairs
    for (i=0; i<n; i++)
        pubkeys[i] = bitcoin_pub256(myinfo->ctx,&privkeys[i],0);
    msg256 = rand256(0);
    for (i=0; i<n; i++)
        privnonces[i] = iguana_schnorr_noncepair(myinfo->ctx,&nonces[i],0,msg256,privkeys[i],maxj);
    for (i=0; i<n; i++)
        iguana_schnorr_peersign(myinfo->ctx,allpubs[i],sig64s[i],i,privkeys[i],privnonces[i],nonces,n,msg256);
    for (iter=0; iter<1; iter++)
    {
        memset(signers.bytes,0,sizeof(signers));
        for (i=k=0; i<n; i++)
        {
            if ( (rand() % 100) < 50 )
            {
                printf("%2d ",i);
                sigs[k] = sig64s[i];
                pubkeysB[k] = pubkeys[i];
                k++;
                SETBIT(signers.bytes,i);
            }
        }
        if ( bitcoin_schnorr_combine(myinfo->ctx,sig64,allpub2,sigs,k,msg256) < 0 )
            printf("error combining k.%d sig64 iter.%d\n",k,iter);
        else if ( bitcoin_schnorr_verify(myinfo->ctx,sig64,msg256,allpub2,33) < 0 )
            printf("allpub2 error verifying combined sig k.%d\n",k);
        else if ( (0) ) // doesnt replicate with subsets
        {
            if ( bitcoin_pubkey_combine(myinfo->ctx,allpub,0,pubkeys,n,0,0) == 0 )
            {
                if ( memcmp(allpub,allpubs[0],33) != 0 )
                {
                    printf("\n");
                    for (k=0; k<33; k++)
                        printf("%02x",allpubs[0][k]);
                    printf(" combined\n");
                    for (k=0; k<33; k++)
                        printf("%02x",allpub[k]);
                    printf(" allpub, ");
                    printf("allpub mismatch iter.%d i.%d n.%d\n",iter,i,n);
                } else printf("validated iter.%d k.%d %llx\n",iter,k,(long long)signers.txid);
            } //else printf("error combining\n");
        } else printf("passed n.%d\n",n);
    }
}
