
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
//
//  LP_secp.c
//  marketmaker
//


#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../includes/curve25519.h"
#include "../secp256k1/include/secp256k1.h"
#include "../secp256k1/include/secp256k1_ecdh.h"
#include "../secp256k1/include/secp256k1_schnorr.h"
#include "../secp256k1/include/secp256k1_rangeproof.h"
#include "../secp256k1/include/secp256k1_recovery.h"

SECP256K1_API extern const secp256k1_nonce_function secp256k1_nonce_function_rfc6979;

#define bits256_nonz(a) (((a).ulongs[0] | (a).ulongs[1] | (a).ulongs[2] | (a).ulongs[3]) != 0)

#define SECP_ENSURE_CTX int32_t flag = 0; if ( ctx == 0 ) { ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY); secp256k1_pedersen_context_initialize(ctx); secp256k1_rangeproof_context_initialize(ctx); flag++; } else flag = 0; if ( ctx != 0 )
#define ENDSECP_ENSURE_CTX if ( flag != 0 ) secp256k1_context_destroy(ctx);

void *bitcoin_ctx()
{
    void *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pedersen_context_initialize(ctx);
    secp256k1_rangeproof_context_initialize(ctx);
    return(ctx);
}

bits256 bitcoin_pubkey33(void *ctx,uint8_t *data,bits256 privkey)
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
    secp256k1_ecdsa_signature SIG,SIGOUT; void *funcp; secp256k1_ecdsa_recoverable_signature rSIG; bits256 extra_entropy,seed; uint8_t *entropy; int32_t recid,retval = -1; size_t siglen = 72; secp256k1_pubkey SECPUB,CHECKPUB;
    seed = rand256(0);
    extra_entropy = rand256(0);
    SECP_ENSURE_CTX
    {
        funcp = secp256k1_nonce_function_rfc6979;
        if ( secp256k1_ec_seckey_verify(ctx,privkey.bytes) == 0 )
        {
            printf("bitcoin_sign illegal privkey\n");
            return(-1);
        }
        if ( strcmp(symbol,"BCH") == 0 || strcmp(symbol,"BTG") == 0 || strcmp(symbol,"CMM") == 0 )
        {
            //char str[65]; printf("BCH/BTG deterministic signature %s\n",bits256_str(str,txhash2));
            funcp = 0;
            entropy = 0;
        } else entropy = extra_entropy.bytes;
        if ( secp256k1_context_randomize(ctx,seed.bytes) != 0 )
        {
            if ( recoverflag != 0 )
            {
                if ( secp256k1_ecdsa_sign_recoverable(ctx,&rSIG,txhash2.bytes,privkey.bytes,funcp,entropy) != 0 )
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
                if ( secp256k1_ecdsa_sign(ctx,&SIG,txhash2.bytes,privkey.bytes,funcp,entropy) != 0 )
                {
                    secp256k1_ecdsa_signature_normalize(ctx,&SIGOUT,&SIG);
                        if ( secp256k1_ecdsa_signature_serialize_der(ctx,sig,&siglen,&SIGOUT) != 0 )
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
        } else printf("error parsing pubkey\n");
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}

int32_t bitcoin_expandcompressed(void *ctx,uint8_t *bigpubkey,uint8_t *pub33)
{
    int32_t retval = -1; secp256k1_pubkey PUB; size_t plen = 65;
    SECP_ENSURE_CTX
    {
        if ( secp256k1_ec_pubkey_parse(ctx,&PUB,pub33,33) != 0 )
        {
            secp256k1_ec_pubkey_serialize(ctx,bigpubkey,&plen,&PUB,SECP256K1_EC_UNCOMPRESSED);
            retval = 0;
        }
        ENDSECP_ENSURE_CTX
    }
    return(retval);
}


