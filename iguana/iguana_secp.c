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

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../includes/curve25519.h"
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_ecdh.h"
#include "secp256k1/include/secp256k1_schnorr.h"
#include "secp256k1/include/secp256k1_rangeproof.h"
#include "secp256k1/include/secp256k1_recovery.h"

SECP256K1_API extern const secp256k1_nonce_function secp256k1_nonce_function_rfc6979;

#define bits256_nonz(a) (((a).ulongs[0] | (a).ulongs[1] | (a).ulongs[2] | (a).ulongs[3]) != 0)

#define SECP_ENSURE_CTX int32_t flag = 0; if ( ctx == 0 ) { ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY); secp256k1_pedersen_context_initialize(ctx); secp256k1_rangeproof_context_initialize(ctx); flag++; } else flag = 0; if ( ctx != 0 )
#define ENDSECP_ENSURE_CTX if ( flag != 0 ) secp256k1_context_destroy(ctx);

int32_t bitcoin_pubkeylen(const uint8_t *pubkey)
{
    if ( pubkey[0] == 2 || pubkey[0] == 3 )
        return(33);
    else if ( pubkey[0] == 4 )
        return(65);
    else
    {
        //printf("illegal pubkey.[%02x] %llx\n",pubkey[0],*(long long *)pubkey);
        return(-1);
    }
}

bits256 bitcoin_randkey(secp256k1_context *ctx)
{
    int32_t i; bits256 privkey;
    SECP_ENSURE_CTX
    {
        for (i=0; i<100; i++)
        {
            privkey = rand256(0);
            if ( secp256k1_ec_seckey_verify(ctx,privkey.bytes) != 0 )
            {
                ENDSECP_ENSURE_CTX
                return(privkey);
            }
        }
        ENDSECP_ENSURE_CTX
    }
    fprintf(stderr,"couldnt generate valid bitcoin privkey. something is REALLY wrong. exiting\n");
    exit(-1);
}

bits256 bitcoin_pubkey33(secp256k1_context *ctx,uint8_t *data,bits256 privkey)
{
    size_t plen; bits256 pubkey; secp256k1_pubkey secppub;
    memset(pubkey.bytes,0,sizeof(pubkey));
    SECP_ENSURE_CTX
    {
        if ( secp256k1_ec_seckey_verify(ctx,privkey.bytes) == 0 )
        {
            //printf("bitcoin_sign illegal privkey\n");
            return(pubkey);
        }
        if ( secp256k1_ec_pubkey_create(ctx,&secppub,privkey.bytes) != 0 )
        {
            plen = 33;
            secp256k1_ec_pubkey_serialize(ctx,data,&plen,&secppub,SECP256K1_EC_COMPRESSED);
            if ( plen == 33 )
                memcpy(pubkey.bytes,data+1,sizeof(pubkey));
        }
        ENDSECP_ENSURE_CTX
    }
    return(pubkey);
}

bits256 bitcoin_pub256(void *ctx,bits256 *privkeyp,uint8_t odd_even)
{
    bits256 pub256; uint8_t pubkey[33]; int32_t i;
    for (i=0; i<100; i++)
    {
        *privkeyp = rand256(0);
        pub256 = bitcoin_pubkey33(ctx,pubkey,*privkeyp);
        if ( pubkey[0] == odd_even+2 )
            return(pub256);
    }
    printf("bitcoin_pub256 couldnt generate pubkey.%d\n",odd_even+2);
    memset(pub256.bytes,0,sizeof(pub256));
    return(pub256);
}

int32_t bitcoin_sign(void *ctx,char *symbol,uint8_t *sig,bits256 txhash2,bits256 privkey,int32_t recoverflag)
{
    int32_t fCompressed = 1;
    secp256k1_ecdsa_signature SIG; secp256k1_ecdsa_recoverable_signature rSIG; bits256 extra_entropy,seed; int32_t recid,retval = -1; size_t siglen = 72; secp256k1_pubkey SECPUB,CHECKPUB;
    seed = rand256(0);
    extra_entropy = rand256(0);
    SECP_ENSURE_CTX
    {
        if ( secp256k1_ec_seckey_verify(ctx,privkey.bytes) == 0 )
        {
            //printf("bitcoin_sign illegal privkey\n");
            return(-1);
        }
        if ( secp256k1_context_randomize(ctx,seed.bytes) != 0 )
        {
            if ( recoverflag != 0 )
            {
                if ( secp256k1_ecdsa_sign_recoverable(ctx,&rSIG,txhash2.bytes,privkey.bytes,secp256k1_nonce_function_rfc6979,extra_entropy.bytes) != 0 )
                {
                    recid = -1;
                    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx,sig+1,&recid,&rSIG);
                    if ( secp256k1_ecdsa_recover(ctx,&SECPUB,&rSIG,txhash2.bytes) != 0 )
                    {
                        if ( secp256k1_ec_pubkey_create(ctx,&CHECKPUB,privkey.bytes) != 0 )
                        {
                            if ( memcmp(&SECPUB,&CHECKPUB,sizeof(SECPUB)) == 0 )
                            {
                                sig[0] = 27 + recid + (fCompressed != 0 ? 4 : 0);
                                retval = 64 + 1;
                                //size_t i,plen = 33; uint8_t pubkey[33];
                                //secp256k1_ec_pubkey_serialize(ctx,pubkey,&plen,&CHECKPUB,SECP256K1_EC_COMPRESSED);
                                //for (i=0; i<33; i++)
                                //    printf("%02x",pubkey[i]);
                                //printf(" bitcoin_sign's pubkey\n");

                            } //else printf("secpub mismatch\n");
                        } else printf("pubkey create error\n");
                    } //else printf("recover error\n");
                } else printf("secp256k1_ecdsa_sign_recoverable error\n");
            }
            else
            {
                if ( secp256k1_ecdsa_sign(ctx,&SIG,txhash2.bytes,privkey.bytes,secp256k1_nonce_function_rfc6979,extra_entropy.bytes) != 0 )
                {
                    if ( secp256k1_ecdsa_signature_serialize_der(ctx,sig,&siglen,&SIG) != 0 )
                        retval = (int32_t)siglen;
                }
            }
        }
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_recoververify(void *ctx,char *symbol,uint8_t *sig,bits256 messagehash2,uint8_t *pubkey,size_t plen)
{
    int32_t retval = -1; secp256k1_pubkey PUB; secp256k1_ecdsa_signature SIG; secp256k1_ecdsa_recoverable_signature rSIG;
    pubkey[0] = 0;
    SECP_ENSURE_CTX
    {
        if ( plen == 0 )
        {
            plen = (sig[0] <= 31) ? 65 : 33;
            sig++;
        }
        secp256k1_ecdsa_recoverable_signature_parse_compact(ctx,&rSIG,sig,0);
        secp256k1_ecdsa_recoverable_signature_convert(ctx,&SIG,&rSIG);
        if ( secp256k1_ecdsa_recover(ctx,&PUB,&rSIG,messagehash2.bytes) != 0 )
        {
            plen = 33;
            memset(pubkey,0,33);
            secp256k1_ec_pubkey_serialize(ctx,pubkey,&plen,&PUB,SECP256K1_EC_COMPRESSED);//plen == 65 ? SECP256K1_EC_UNCOMPRESSED : SECP256K1_EC_COMPRESSED);
            if ( secp256k1_ecdsa_verify(ctx,&SIG,messagehash2.bytes,&PUB) != 0 )
            {
                retval = 0;
                /*if ( pubkey[0] == 4 ) // experimentally looks like 04 is set
                    pubkey[0] = 2;
                else if ( pubkey[0] != 2 )
                    pubkey[0] = 3;*/
            } else printf("secp256k1_ecdsa_verify error\n");
        } else printf("secp256k1_ecdsa_recover error\n");
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_verify(void *ctx,uint8_t *sig,int32_t siglen,bits256 txhash2,uint8_t *pubkey,int32_t plen)
{
    int32_t retval = -1; secp256k1_pubkey PUB; secp256k1_ecdsa_signature SIG;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_ec_pubkey_parse(ctx,&PUB,pubkey,plen) != 0 )
        {
            secp256k1_ecdsa_signature_parse_der(ctx,&SIG,sig,siglen);
            if ( secp256k1_ecdsa_verify(ctx,&SIG,txhash2.bytes,&PUB) != 0 )
                retval = 0;
        }
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

bits256 bitcoin_sharedsecret(void *ctx,bits256 privkey,uint8_t *pubkey,int32_t plen)
{
    int32_t retval = -1; bits256 shared; secp256k1_pubkey PUB;
    memset(shared.bytes,0,sizeof(shared));
    SECP_ENSURE_CTX
    {
        if ( secp256k1_ec_pubkey_parse(ctx,&PUB,pubkey,plen) != 0 )
        {
            if ( secp256k1_ecdh(ctx,shared.bytes,&PUB,privkey.bytes) != 0 )
                retval = 0;
            else memset(shared.bytes,0,sizeof(shared));
        }
        ENDSECP_ENSURE_CTX
    }
    return(shared);
}

int32_t bitcoin_schnorr_sign(void *ctx,uint8_t *sig64,bits256 txhash2,bits256 privkey)
{
    int32_t retval = -1; bits256 seed;
    SECP_ENSURE_CTX
    {
        seed = rand256(0);
        if ( secp256k1_schnorr_sign(ctx,sig64,txhash2.bytes,privkey.bytes,secp256k1_nonce_function_rfc6979,seed.bytes) != 0 )
            retval = 0;
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_schnorr_verify(void *ctx,uint8_t *sig64,bits256 txhash2,uint8_t *pubkey,int32_t plen)
{
    int32_t retval = -1; secp256k1_pubkey PUB;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_ec_pubkey_parse(ctx,&PUB,pubkey,plen) != 0 )
        {
            if ( secp256k1_schnorr_verify(ctx,sig64,txhash2.bytes,&PUB) != 0 )
                retval = 0;
        }
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_schnorr_recover(void *ctx,uint8_t *pubkey,uint8_t *sig64,bits256 txhash2)
{
    int32_t retval = -1; secp256k1_pubkey PUB; size_t plen;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_schnorr_recover(ctx,&PUB,sig64,txhash2.bytes) != 0 )
        {
            plen = 33;
            secp256k1_ec_pubkey_serialize(ctx,pubkey,&plen,&PUB,SECP256K1_EC_COMPRESSED);
            retval = 0;
        }
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

bits256 bitcoin_schnorr_noncepair(void *ctx,uint8_t *pubnonce,bits256 txhash2,bits256 privkey) //exchange
{
    int32_t retval = -1; size_t plen; secp256k1_pubkey PUB; bits256 privnonce,seed;
    memset(privnonce.bytes,0,sizeof(privnonce));
    pubnonce[0] = 0;
    SECP_ENSURE_CTX
    {
        seed = rand256(0);
        if ( secp256k1_schnorr_generate_nonce_pair(ctx,&PUB,privnonce.bytes,txhash2.bytes,privkey.bytes,secp256k1_nonce_function_rfc6979,seed.bytes) != 0 )
        {
            plen = 33;
            secp256k1_ec_pubkey_serialize(ctx,pubnonce,&plen,&PUB,SECP256K1_EC_COMPRESSED);
            retval = 0;
        }
        ENDSECP_ENSURE_CTX
    }
    return(privnonce);
}

int32_t bitcoin_pubkey_combine(void *ctx,uint8_t *combined_pub,uint8_t *skipkey,bits256 *evenkeys,int32_t n,bits256 *oddkeys,int32_t m)
{
    int32_t i,num,iter,max,retval = -1; uint8_t pubkey[33]; size_t plen; secp256k1_pubkey PUBall,*PUBptrs[256],PUBkeys[256];
    SECP_ENSURE_CTX
    {
        if ( n+m > 0 && n+m < sizeof(PUBptrs)/sizeof(*PUBptrs) )
        {
            for (iter=num=0; iter<2; iter++)
            {
                if ( (max= (iter == 0) ? n : m) != 0 )
                {
                    for (i=0; i<max; i++)
                    {
                        PUBptrs[num] = &PUBkeys[num];
                        pubkey[0] = 2 + iter;
                        memcpy(pubkey+1,((iter == 0) ? evenkeys : oddkeys)[i].bytes,32);
                        if ( skipkey != 0 && memcmp(pubkey,skipkey,33) == 0 )
                        {
                            //printf("skipkey.%d\n",i);
                            continue;
                        }
                        if ( secp256k1_ec_pubkey_parse(ctx,PUBptrs[num],pubkey,33) == 0 )
                        {
                            int32_t j; for (j=0; j<33; j++)
                                printf("%02x",pubkey[j]);
                            printf(" error parsing pubkey iter.%d num.%d i.%d\n",iter,num,i);
                            break;
                        }
                        num++;
                    }
                }
            }
            if ( secp256k1_ec_pubkey_combine(ctx,&PUBall,(void *)PUBptrs,num) != 0 )
            {
                plen = 33;
                secp256k1_ec_pubkey_serialize(ctx,combined_pub,&plen,&PUBall,SECP256K1_EC_COMPRESSED);
                retval = 0;
            }
        }
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_schnorr_partialsign(void *ctx,uint8_t *sig64,uint8_t *combined_pub,bits256 txhash2,bits256 privkey,bits256 privnonce,uint8_t *pubptrs[],int32_t n) // generate and exchange
{
    int32_t bitcoin_pubkeylen(const uint8_t *pubkey);
    int32_t i,retval = -1; secp256k1_pubkey PUBall,**PUBptrs; size_t plen;
    SECP_ENSURE_CTX
    {
        PUBptrs = calloc(n,sizeof(*PUBptrs));
        for (i=0; i<n; i++)
        {
            PUBptrs[i] = calloc(1,sizeof(secp256k1_pubkey));
            if ( secp256k1_ec_pubkey_parse(ctx,PUBptrs[i],pubptrs[i],bitcoin_pubkeylen(pubptrs[i])) != 0 )
                break;
        }
        if ( n > 0 && secp256k1_ec_pubkey_combine(ctx,&PUBall,(void *)PUBptrs,n) != 0 )
        {
            plen = 33;
            if ( secp256k1_schnorr_partial_sign(ctx,sig64,txhash2.bytes,privkey.bytes,&PUBall,privnonce.bytes) != 0 )
            {
                secp256k1_ec_pubkey_serialize(ctx,combined_pub,&plen,&PUBall,SECP256K1_EC_COMPRESSED);
                retval = 0;
            }
        }
        free(PUBptrs);
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_schnorr_combine(void *ctx,uint8_t *sig64,uint8_t *allpub,uint8_t **sigs,int32_t n,bits256 txhash2)
{
    int32_t rc,retval = -1;
    SECP_ENSURE_CTX
    {
        if ( (rc= secp256k1_schnorr_partial_combine(ctx,sig64,(void *)sigs,n)) != 0 )
        {
            if ( bitcoin_schnorr_recover(ctx,allpub,sig64,txhash2) == 0 )
            {
                if ( bitcoin_schnorr_verify(ctx,sig64,txhash2,allpub,33) == 0 )
                    retval = 0;
            }
        }
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_pederson_commit(void *ctx,uint8_t *commit,bits256 blind,uint64_t value)
{
    int32_t retval = -1;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_pedersen_commit(ctx,commit,blind.bytes,value) != 0 )
            retval = 0;
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

bits256 bitcoin_pederson_blindsum(void *ctx,bits256 **blindptrs,int32_t n,int32_t numpos)
{
    bits256 blind_out;
    memset(blind_out.bytes,0,sizeof(blind_out));
    SECP_ENSURE_CTX
    {
        if ( secp256k1_pedersen_blind_sum(ctx,blind_out.bytes,(void *)blindptrs,n,numpos) == 0 )
            memset(blind_out.bytes,0,sizeof(blind_out));
        ENDSECP_ENSURE_CTX
    }
    return(blind_out);
}

int32_t bitcoin_pederson_tally(void *ctx,uint8_t **commits,int32_t n,int32_t numpos,int64_t excess)
{
    int32_t retval = -1;
    SECP_ENSURE_CTX
    {
        printf("bitcoin_pederson_tally: n.%d numpos.%d excess %lld\n",n,numpos,(long long)excess);
        if ( secp256k1_pedersen_verify_tally(ctx,(void *)commits,numpos,(void *)&commits[numpos],n - numpos,excess) != 0 )
            retval = 0;
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_rangeproof_message(void *ctx,uint8_t *blind_out,uint8_t *message,uint64_t *valuep,bits256 nonce,uint64_t *min_valuep,uint64_t *max_valuep,uint8_t *commit,uint8_t *proof,int32_t prooflen)
{
    int32_t outlen = 0,retval = -1;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_rangeproof_rewind(ctx,blind_out,valuep,message,&outlen,nonce.bytes,min_valuep,max_valuep,commit,proof,prooflen) != 0 )
            retval = outlen;
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

uint64_t bitcoin_rangeverify(void *ctx,int32_t *exponentp,int32_t *mantissap,uint64_t *min_valuep,uint8_t *commit,uint8_t *proof,int32_t prooflen)
{
    uint64_t max_value,retval = 0;
    max_value = *min_valuep = *exponentp = *mantissap = 0;
    if ( secp256k1_rangeproof_info(ctx,exponentp,mantissap,min_valuep,&max_value,proof,prooflen) != 0 )
    {
        if ( commit != 0 )
        {
            if ( secp256k1_rangeproof_verify(ctx,min_valuep,&max_value,commit,proof,prooflen) != 0 )
                retval = max_value;
        } else retval = max_value;
    }
    return(retval);
}

int32_t bitcoin_rangeproof(void *ctx,uint8_t *proof,uint8_t *commit,bits256 blind,bits256 nonce,uint64_t value,uint64_t min_value,int32_t exponent,int32_t min_bits)
{
    int32_t prooflen=0  ,retval = -1;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_rangeproof_sign(ctx,proof,&prooflen,min_value,commit,blind.bytes,nonce.bytes,exponent,min_bits,value) != 0 )
            retval = prooflen;
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t iguana_pederson_test(void *ctx)
{
    uint8_t commits[100][33],*commitptrs[100],proofs[100][5138]; uint16_t vouts[100]; int64_t min_value,values[100],totalpos,totalneg; bits256 txids[100],nonces[100],blinds[100],*blindptrs[100],blindsum; int32_t prooflens[100],i,r,pos,neg,numpos,exponent,min_bits,n,N = 100;
    srand(100);
    for (i=numpos=n=0; i<N; i++)
    {
        values[i] = rand();
        vouts[i] = (rand() % 300);
        txids[i] = rand256(0);
        nonces[i] = rand256(0);
        blinds[i] = rand256(0);
        if ( bitcoin_pederson_commit(ctx,commits[i],blinds[i],values[i]) < 0 )
            break;
        if ( ((r= rand()) % 2) == 0 )
            values[i] = -values[i];
        else
        {
            exponent = 0;
            min_bits = 64;
            min_value = 0;
            prooflens[i] = bitcoin_rangeproof(ctx,proofs[i],commits[i],blinds[i],nonces[i],values[i],min_value,exponent,min_bits);
            printf("%d ",prooflens[i]);
            numpos++;
        }
        n++;
    }
    if ( i != N )
    {
        printf("commit failure i.%d of N.%d\n",i,N);
        return(-1);
    }
    for (totalpos=i=pos=0; i<N; i++)
    {
        if ( values[i] > 0 )
        {
            commitptrs[pos] = commits[i];
            blindptrs[pos] = &blinds[i];
            totalpos += values[i];
            pos++;
        }
    }
    if ( pos != numpos )
    {
        printf("pos.%d != numpos.%d\n",pos,numpos);
        return(-1);
    }
    for (totalneg=i=neg=0; i<N; i++)
    {
        if ( values[i] < 0 )
        {
            commitptrs[numpos + neg] = commits[i];
            blindptrs[numpos + neg] = &blinds[i];
            totalneg -= values[i];
            neg++;
        }
    }
    if ( numpos+neg != N )
    {
        printf("numpos.%d + neg.%d != N.%d\n",numpos,neg,N);
        return(-1);
    }
    blindsum = bitcoin_pederson_blindsum(ctx,blindptrs,N,numpos);
    if ( bits256_nonz(blindsum) == 0 )
    {
        printf("error doing blindsum numpos.%d N.%d\n",numpos,N);
        return(-2);
    }
    if ( bitcoin_pederson_tally(ctx,commitptrs,N,numpos,totalneg - totalpos) == 0 )
    {
        printf("error doing pederson tally\n");
        return(-3);
    } else printf("pederson tally matches\n");
    return(0);
}

int32_t iguana_schnorr_test(void *ctx)
{
    bits256 privnonces[100],privkeys[100],txhash2; uint8_t *sigs[100],allpub[100][33],sig64[100][64],allsig64[100][64],combined_pub[100][33],pubnonces[100][33],*pubptrs[100]; int32_t i,j,N,n,errs = 0;
    iguana_pederson_test(ctx);
    SECP_ENSURE_CTX
    {
        N = 100;
        txhash2 = rand256(0);
        for (i=0; i<N; i++)
        {
            privkeys[i] = bitcoin_randkey(ctx);
            privnonces[i] = bitcoin_schnorr_noncepair(ctx,pubnonces[i],txhash2,privkeys[i]);
        }
        if ( i != N )
        {
            printf("error getting nonce pair\n");
            exit(-1);
        }
        for (i=0; i<N; i++)
        {
            for (j=n=0; j<N; j++)
                if ( j != i )
                    pubptrs[n++] = pubnonces[j];
            if ( N > 1 )
            {
                if ( bitcoin_schnorr_partialsign(ctx,sig64[i],combined_pub[i],txhash2,privkeys[i],privnonces[i],pubptrs,N-1) < 0 )
                    errs++;
            }
            else
            {
                if ( bitcoin_schnorr_sign(ctx,sig64[0],txhash2,privkeys[0]) < 0 )
                    errs++;
            }
        }
        if ( errs != 0 )
            printf("partialsign errs.%d\n",errs);
        for (i=0; i<N; i++)
        {
            sigs[i] = sig64[i];
            continue;
            //for (j=0; j<64; j++)
            //    printf("%02x",sig64[i][j]);
            //printf(" sig[%d]\n",i);
        }
        for (i=0; i<N; i++)
        {
            if ( bitcoin_schnorr_combine(ctx,allsig64[i],allpub[i],sigs,N,txhash2) < 0 )
                errs++;
            else if ( memcmp(allpub[i],allpub[0],33) != 0 )
                errs++;
            else if ( memcmp(allsig64[i],allsig64[0],33) != 0 )
                errs++;
        }
        if ( errs != 0 )
            printf("combine errs.%d\n",errs);
        if ( bitcoin_schnorr_verify(ctx,allsig64[0],txhash2,allpub[0],33) < 0 )
            errs++;
        printf("schnorr errs.%d\n",errs);
        ENDSECP_ENSURE_CTX
    }
    return(errs);
}


/*
 We start by reminding the reader how confidential transactions work. First, the
 amounts are coded by the following equation:
 
 C = r*G + v*H
 
 where C is a Pedersen commitment, G and H are fixed nothing-up-my-sleeve elliptic
 curve group generators, v is the amount, and r is a secret random blinding key.
 
 Attached to this output is a rangeproof which proves that v is in [0, 2^64], so
 that user cannot exploit the blinding to produce overflow attacks, etc.
 
 To validate a transaction, the verifer will add commitments for all outputs, plus
 f*H (f here is the transaction fee which is given explicitly) and subtracts all
 input commitments. The result must be 0, which proves that no amount was created
 or destroyed overall.
 
 We note that to create such a transaction, the user must know the sum of all the
 values of r for commitments entries. Therefore, the r-values (and their sums) act
 as secret keys. If we can make the r output values known only to the recipient,
 then we have an authentication system! Unfortunately, if we keep the rule that
 commits all add to 0, this is impossible, because the sender knows the sum of
 all _his_ r values, and therefore knows the receipient's r values sum to the
 negative of that. So instead, we allow the transaction to sum to a nonzero value
 k*G, and require a signature of an empty string with this as key, to prove its
 amount component is zero.
 
 We let transactions have as many k*G values as they want, each with a signature,
 and sum them during verification.
 
 To create transactions sender and recipient do following ritual:
 
 1. Sender and recipient agree on amount to be sent. Call this b.
 
 2. Sender creates transaction with all inputs and change output(s), and gives
 recipient the total blinding factor (r-value of change minus r-values of
 inputs) along with this transaction. So the commitments sum to r*G - b*H.
 
 3. Recipient chooses random r-values for his outputs, and values that sum
 to b minus fee, and adds these to transaction (including range proof).
 Now the commitments sum to k*G - fee*H for some k that only recipient
 knows.
 
 4. Recipient attaches signature with k to the transaction, and the explicit
 fee. It has done.
 */

void test_mimblewimble(void *ctx)
{
    uint8_t commits[100][33],*commitptrs[100]; int64_t inputs[8],inputsum,amount,change,txfee,totalpos,totalneg; bits256 nonces[100],blinds[100],*blindptrs[100],blindsum; int32_t i,r,numinputs;
    OS_randombytes((void *)&r,sizeof(r));
    srand(r);
    inputs[0] = 100000000;
    numinputs = 1;
    inputsum = 0;
    for (i=0; i<numinputs; i++)
        inputsum += inputs[i];
    txfee = 10000;
    amount = 100000000 / 10;
    change = inputsum - txfee - amount;
    totalpos = change;
    totalneg = inputsum;
    for (i=0; i<numinputs+2; i++)
    {
        nonces[i] = rand256(0);
        blinds[i] = rand256(0);
        commitptrs[i] = commits[i];
        blindptrs[i] = &blinds[i];
    }
    if ( bitcoin_pederson_commit(ctx,commits[0],blinds[0],change) < 0  )
    {
        printf("error getting change commit\n");
        return;
    }
    for (i=1; i<=numinputs; i++)
    {
        if ( bitcoin_pederson_commit(ctx,commits[i],blinds[i],-inputs[i]) < 0 )
        {
            printf("error getting input.(%d) commit\n",i);
            return;
        }
    }
    
    blindsum = bitcoin_pederson_blindsum(ctx,blindptrs,numinputs+1,1);
    if ( bits256_nonz(blindsum) == 0 )
    {
        printf("error doing blindsum\n");
        return;
    }
    if ( bitcoin_pederson_tally(ctx,commitptrs,numinputs+1,1,totalneg - totalpos) == 0 )
    {
        printf("error doing pederson tally\n");
        return;
    } else printf("pederson tally matches\n");
    getchar();
}
