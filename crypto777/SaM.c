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

//  based on SaM code by Come-from-Beyond

#ifdef DEFINES_ONLY
#ifndef crypto777_SaM_h
#define crypto777_SaM_h
#include <stdio.h>
#include <memory.h>
#include <time.h>

#define TRIT signed char

#define TRIT_FALSE 1
#define TRIT_UNKNOWN 0
#define TRIT_TRUE -1

#define SAM_HASH_SIZE 243
#define SAM_STATE_SIZE (SAM_HASH_SIZE * 3)
#define SAM_NUMBER_OF_ROUNDS 9
#define SAM_DELTA 254

#define SAMHIT_LIMIT ((uint64_t)1594323 * 4782969) //7625597484987LL // 3 ** 27
#define MAX_CRYPTO777_HIT (((uint64_t)1 << 62) / 1000)

//#include "bits777.c"
//#include "utils777.c"
#include <stdlib.h>
#include "../includes/curve25519.h"
#define MAX_INPUT_SIZE ((int32_t)(65536 - sizeof(bits256) - 2*sizeof(uint32_t)))

struct SaM_info {  bits384 bits; TRIT trits[SAM_STATE_SIZE],hash[SAM_HASH_SIZE]; };
struct SaMhdr { bits384 sig; uint32_t timestamp,nonce; uint8_t numrounds,leverage; };

void SaM_Initialize(struct SaM_info *state);
int32_t SaM_Absorb(struct SaM_info *state,const uint8_t *input,uint32_t inputSize,const uint8_t *input2,uint32_t inputSize2);
bits384 SaM_emit(struct SaM_info *state);
bits384 SaM_encrypt(uint8_t *dest,uint8_t *src,int32_t len,bits384 password,uint32_t timestamp);
uint64_t SaM_threshold(int32_t leverage);
uint64_t SaM(bits384 *sigp,uint8_t *input,int32_t inputSize,uint8_t *input2,int32_t inputSize2);
uint32_t SaM_nonce(void *data,int32_t datalen,int32_t leverage,int32_t maxmillis,uint32_t nonce);
//uint64_t SaMnonce(bits384 *sigp,uint32_t *noncep,uint8_t *buf,int32_t len,uint64_t threshold,uint32_t rseed,int32_t maxmillis);
#endif
#else
#ifndef crypto777_SaM_c
#define crypto777_SaM_c

#ifndef crypto777_SaM_h
#define DEFINES_ONLY
#include "SaM.c"
#undef DEFINES_ONLY
#endif

static int32_t SAM_INDICES[SAM_STATE_SIZE];

void SaM_PrepareIndices()
{
	int32_t i,nextIndex,currentIndex = 0;
	for (i=0; i<SAM_STATE_SIZE; i++)
    {
		nextIndex = (currentIndex + SAM_DELTA) % SAM_STATE_SIZE;
		SAM_INDICES[i] = nextIndex;
		currentIndex = nextIndex;
	}
}

TRIT SaM_Bias(const TRIT a, const TRIT b) { return a == 0 ? 0 : (a == -b ? a : -a); }
TRIT SaM_Sum(const TRIT a, const TRIT b) { return a == b ? -a : (a + b); }

void SaM_SplitAndMerge(struct SaM_info *state)
{
    static const TRIT SAMSUM[3][3] = { { 1, -1, 0, }, { -1, 0, 1, }, { 0, 1, -1, } };
    static const TRIT SAMBIAS[3][3] = { { 1, 1, -1, }, { 0, 0, 0, }, { 1, -1, -1, } };
	struct SaM_info leftPart,rightPart;
	int32_t i,nextIndex,round,currentIndex = 0;
	for (round=0; round<SAM_NUMBER_OF_ROUNDS; round++)
    {
		for (i=0; i<SAM_STATE_SIZE; i++)
        {
			nextIndex = SAM_INDICES[i];
			//leftPart.trits[i] = SaM_Bias(state->trits[currentIndex],state->trits[nextIndex]);
			//rightPart.trits[i] = SaM_Bias(state->trits[nextIndex],state->trits[currentIndex]);
			leftPart.trits[i] = SAMBIAS[state->trits[currentIndex]+1][1+state->trits[nextIndex]];
			rightPart.trits[i] = SAMBIAS[state->trits[nextIndex]+1][1+state->trits[currentIndex]];
			currentIndex = nextIndex;
		}
		for (i=0; i<SAM_STATE_SIZE; i++)
        {
			nextIndex = SAM_INDICES[i];
			//state->trits[i] = SaM_Sum(leftPart.trits[currentIndex],rightPart.trits[nextIndex]);
			state->trits[i] = SAMSUM[leftPart.trits[currentIndex]+1][1+rightPart.trits[nextIndex]];
			currentIndex = nextIndex;
		}
	}
}

void SaM_Initialize(struct SaM_info *state)
{
    int32_t i;
    for (i=SAM_HASH_SIZE; i<SAM_STATE_SIZE; i++)
		state->trits[i] = (i & 1) ? TRIT_FALSE : TRIT_TRUE;
}

void SaM_Squeeze(struct SaM_info *state,TRIT *output)
{
	memcpy(output,state->trits,SAM_HASH_SIZE * sizeof(TRIT));
	SaM_SplitAndMerge(state);
}

void _SaM_Absorb(struct SaM_info *state,const TRIT *input,const int32_t inputSize)
{
	int32_t size,i,remainder = inputSize;
	do
    {
		size = remainder >= SAM_HASH_SIZE ? SAM_HASH_SIZE : remainder;
		memcpy(state->trits,&input[inputSize - remainder],size);
		remainder -= SAM_HASH_SIZE;
        if ( size < SAM_HASH_SIZE )
            for (i=size; i<SAM_HASH_SIZE; i++)
                state->trits[i] = (i & 1) ? TRIT_FALSE : TRIT_TRUE;
		SaM_SplitAndMerge(state);
	} while ( remainder > 0 );
}

int32_t SaM_Absorb(struct SaM_info *state,const uint8_t *input,uint32_t inputSize,const uint8_t *input2,uint32_t inputSize2)
{
    //TRIT output[(MAX_INPUT_SIZE + sizeof(struct SaMhdr)) << 3];
    TRIT *trits,tritbuf[4096];
    int32_t i,size,n = 0;
    /*if ( inputSize + inputSize2 > sizeof(output) )
    {
        printf("SaM overflow (%d + %d) > %ld\n",inputSize,inputSize2,sizeof(output));
        if ( inputSize > MAX_INPUT_SIZE )
            inputSize = MAX_INPUT_SIZE;
        inputSize2 = 0;
    }*/
    size = (inputSize + inputSize2) << 3;
    trits = (size < sizeof(tritbuf)) ? tritbuf : malloc(size);
    if ( input != 0 && inputSize != 0 )
    {
        for (i=0; i<(inputSize << 3); i++)
            trits[n++] = ((input[i >> 3] & (1 << (i & 7))) != 0);
    }
    if ( input2 != 0 && inputSize2 != 0 )
    {
        for (i=0; i<(inputSize2 << 3); i++)
            trits[n++] = ((input2[i >> 3] & (1 << (i & 7))) != 0);
    }
    _SaM_Absorb(state,trits,n);
    if ( trits != tritbuf )
        free(trits);
    return(n);
}

static TRIT InputA[] = { 0 }; // zero len
static TRIT OutputA[] = { 1, -1, 1, 1, -1, -1, 0, -1, 0, 0, 0, 1, -1, 0, 1, 1, 0, -1, 1, 0, 0, 0, 1, 1, -1, -1, 0, 0, 1, -1, -1, 0, 0, -1, 1, -1, 0, 0, -1, -1, -1, -1, 0, 0, 0, -1, 1, 0, 1, 0, -1, -1, -1, -1, 0, 1, -1, 1, -1, 0, 1, 1, 0, 0, -1, 0, 1, 1, -1, 1, 0, 0, 0, 1, 0, -1, 1, 1, 0, -1, -1, 1, 1, -1, 1, 1, 1, 1, -1, 0, 1, -1, 1, -1, 0, 0, 1, 1, 1, 1, -1, 1, 1, -1, 0, 0, 1, 1, 0, 0, -1, 1, 1, -1, 0, 0, -1, 0, 0, 1, 0, 0, 0, -1, 1, -1, 0, 1, -1, 0, -1, 1, 1, 1, -1, 0, 1, 1, -1, -1, 0, 0, 1, -1, -1, -1, 0, -1, -1, 1, 1, 0, 1, 0, 1, -1, 1, -1, -1, 0, 0, -1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, -1, 1, -1, 0, 0, 1, 0, -1, -1, -1, 1, -1, 1, -1, -1, 1, 0, 1, -1, 1, -1, 1, -1, 1, 0, 1, 0, 1, -1, -1, -1, -1, 1, 0, 0, -1, -1, 1, 0, 1, 1, -1, 1, -1, -1, -1, 0, 0, -1, 0, 1, 1, 1, 0, 1, 1, -1, 1, 1, 0, 1, 1, 1, 0, -1, 0, 0, -1, -1, -1 };

static TRIT InputB[] = { 0 };
static TRIT OutputB[] = { -1, -1, -1, 1, 0, 0, 1, 1, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 0, 1, 1, 0, -1, 1, 0, 1, 0, 1, -1, 0, -1, 0, 0, -1, 1, -1, -1, 0, 0, 1, -1, -1, 0, 0, -1, 1, 1, 0, 1, 0, 0, 1, -1, 1, 0, -1, -1, 1, -1, 0, -1, 1, -1, 0, 0, 0, 1, -1, 0, 1, -1, 1, 1, 1, 1, -1, 1, -1, -1, 1, 0, 1, -1, -1, -1, 0, 1, 0, 0, -1, 1, 1, 0, 0, -1, 1, 1, 0, -1, -1, 0, 0, 0, -1, 1, 0, -1, 0, -1, 0, -1, 0, -1, 0, 1, 0, 1, 0, -1, 1, 0, -1, 1, 1, -1, 1, 0, 1, -1, -1, 1, 1, 0, -1, 0, -1, -1, -1, 1, -1, -1, 1, 1, 1, 1, 1, -1, -1, 1, 0, 0, 0, 0, -1, -1, 1, 1, 1, -1, 1, 0, -1, 1, 0, 1, 0, 0, -1, -1, 1, 1, 0, 0, 1, 0, 0, 0, 0, -1, 1, 0, 0, 1, 1, 0, -1, 1, -1, 1, 0, -1, 0, 0, 1, -1, -1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, -1, 1, -1, 1, 1, 1, -1, 0, 1, 0, -1, 1, 0, 1, 1, 0, -1, 1, 1, -1, 0, -1, 1, 1, 0, -1, -1, -1, -1, 1, 0, 0, -1, -1, -1, 0, 1 };

static TRIT InputC[] = { 1 };
static TRIT OutputC[] = { 1, -1, 1, 1, -1, -1, 0, -1, 0, 0, 0, 1, -1, 0, 1, 1, 0, -1, 1, 0, 0, 0, 1, 1, -1, -1, 0, 0, 1, -1, -1, 0, 0, -1, 1, -1, 0, 0, -1, -1, -1, -1, 0, 0, 0, -1, 1, 0, 1, 0, -1, -1, -1, -1, 0, 1, -1, 1, -1, 0, 1, 1, 0, 0, -1, 0, 1, 1, -1, 1, 0, 0, 0, 1, 0, -1, 1, 1, 0, -1, -1, 1, 1, -1, 1, 1, 1, 1, -1, 0, 1, -1, 1, -1, 0, 0, 1, 1, 1, 1, -1, 1, 1, -1, 0, 0, 1, 1, 0, 0, -1, 1, 1, -1, 0, 0, -1, 0, 0, 1, 0, 0, 0, -1, 1, -1, 0, 1, -1, 0, -1, 1, 1, 1, -1, 0, 1, 1, -1, -1, 0, 0, 1, -1, -1, -1, 0, -1, -1, 1, 1, 0, 1, 0, 1, -1, 1, -1, -1, 0, 0, -1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, -1, 1, -1, 0, 0, 1, 0, -1, -1, -1, 1, -1, 1, -1, -1, 1, 0, 1, -1, 1, -1, 1, -1, 1, 0, 1, 0, 1, -1, -1, -1, -1, 1, 0, 0, -1, -1, 1, 0, 1, 1, -1, 1, -1, -1, -1, 0, 0, -1, 0, 1, 1, 1, 0, 1, 1, -1, 1, 1, 0, 1, 1, 1, 0, -1, 0, 0, -1, -1, -1 };

static TRIT InputD[] = { -1 };
static TRIT OutputD[] = { -1, 0, 0, 1, 1, 0, -1, 1, 1, 0, 1, 0, -1, 1, -1, 0, 0, 1, 0, -1, 0, -1, 1, 1, 1, 1, -1, 1, -1, 1, -1, 0, 0, 0, -1, -1, 1, 1, -1, 1, -1, 0, -1, 1, -1, 0, 0, -1, 0, 0, 0, -1, -1, 0, -1, 1, -1, 1, 1, 0, -1, 1, -1, 0, 0, 1, -1, 1, -1, 0, 0, 1, 1, -1, -1, -1, -1, 1, 0, 0, -1, 0, 0, -1, 0, 0, 1, -1, -1, -1, -1, 1, 1, 0, 0, -1, 1, -1, 1, 0, 0, -1, 1, -1, 0, 1, 1, -1, 1, -1, 0, -1, -1, 0, 0, 0, -1, 0, 0, -1, 1, -1, 0, -1, 1, -1, 1, 1, -1, -1, 0, 0, 0, -1, 1, -1, 1, -1, 1, 1, 1, 1, -1, 0, -1, 0, 1, 0, 0, -1, 1, -1, 0, 1, 0, 1, 1, -1, 0, 1, 1, 0, 0, -1, -1, -1, -1, 0, 1, 0, -1, -1, 0, 0, 1, 1, 1, 0, 0, -1, 1, -1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, -1, -1, 0, -1, -1, 0, -1, -1, 1, 0, 0, -1, -1, 1, 0, 0, 0, 1, 1, 0, -1, 1, -1, -1, 1, -1, -1, 1, 1, 0, 1, 0, 0, 0, -1, 1, 0, -1, -1, 0, 1, -1, 0, 0, 0, -1, -1, 1, 1 };

static TRIT InputE[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
static TRIT OutputE[] = { 0, 1, 0, 1, -1, -1, 1, -1, -1, 0, 0, 1, 1, -1, -1, -1, 0, 1, 0, 0, -1, -1, 1, 1, 1, -1, 0, -1, -1, -1, -1, -1, 1, -1, -1, -1, 0, 0, 1, 1, 0, 1, -1, -1, 0, -1, -1, 1, 1, 1, -1, 1, 1, 0, -1, 0, 1, -1, 1, -1, 1, 1, -1, 1, 0, -1, -1, -1, 0, 0, 1, 1, 0, -1, 0, 0, -1, 0, 0, 1, 1, -1, 0, 1, -1, -1, 1, -1, 1, -1, 0, 1, -1, 1, 0, 1, -1, -1, -1, 0, 1, -1, 0, 1, -1, 1, 0, -1, 1, -1, 1, 0, -1, -1, 1, 0, 1, 0, 0, 1, 1, 1, -1, 1, -1, -1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, -1, -1, 1, 0, 0, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, 1, 0, 0, 1, 0, -1, -1, 0, 0, -1, -1, 1, -1, 0, -1, 1, -1, 0, 1, -1, 0, 1, 1, -1, 1, -1, 1, -1, 0, 0, 0, -1, 0, -1, 1, -1, 1, 1, 1, 1, 1, 0, -1, 0, -1, -1, 0, 0, -1, -1, 1, -1, -1, -1, 1, 0, 0, 0, 1, 0, 1, 0, 1, -1, 0, -1, -1, 1, -1, -1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, -1, -1, -1, -1, 1, 0, -1, 0, 0 };

bits384 SaM_emit(struct SaM_info *state)
{
    // i.12 531441 81bf1 0.68% numbits.19 mask.7ffff -> bias -0.0005870312
    TRIT *ptr;
    uint64_t bits64;
    uint32_t i,j,rawbits,bits19[20],mask = 0x7ffff;
	SaM_Squeeze(state,state->hash);
    ptr = state->hash;
    for (i=0; i<SAM_HASH_SIZE/12; i++)
    {
        for (j=rawbits=0; j<12; j++)
            rawbits = (rawbits * 3 + *ptr++ + 1);
        bits19[i] = ((((uint64_t)rawbits<<19)/531441) & mask); // 3^12 == 531441 //bits19[i] = (rawbits & mask);
        //printf("%05x ",bits19[i]);
    }
    for (i*=12,rawbits=0; i<SAM_HASH_SIZE; i++) // 3 trits -> 27
        rawbits = (rawbits * 3 + *ptr++ + 1);
    rawbits = (((rawbits<<4)/27) & 0xf);
    //printf("%x -> Sam_emit\n",rawbits);
    for (bits64=i=0; i<20; i++)
    {
        memcpy(&state->bits.bytes[i*sizeof(uint16_t)],&bits19[i],sizeof(uint16_t));
        bits64 = (bits64 << 3) | ((bits19[i] >> 16) & 7);
    }
    bits64 = (bits64 << 4) | (rawbits & 0xf);
    memcpy(&state->bits.bytes[40],&bits64,sizeof(uint64_t));
    return(state->bits);
}

int32_t _SaM_test(char *msg,TRIT *testvector,int32_t n,TRIT *checkvals)
{
    struct SaM_info state; int32_t i,errs;
    SaM_Initialize(&state);
    _SaM_Absorb(&state,testvector,n);
    SaM_emit(&state);
    for (i=errs=0; i<243; i++)
    {
        if ( state.hash[i] != checkvals[i] )
            errs++;
    }
    if ( errs != 0 )
    {
        for (i=0; i<243; i++)
            printf("%2d, ",state.hash[i]);
        printf("\nSaM_test.%s errs.%d vs output\n",msg,errs);
    }
    return(errs);
}

/*int32_t bitweight(uint64_t x)
{
    int i,wt = 0;
    for (i=0; i<64; i++)
        if ( (1LL << i) & x )
            wt++;
    return(wt);
}*/
int32_t bitweight(uint64_t x);
#define SETBIT(bits,bitoffset) (((uint8_t *)bits)[(bitoffset) >> 3] |= (1 << ((bitoffset) & 7)))
#define GETBIT(bits,bitoffset) (((uint8_t *)bits)[(bitoffset) >> 3] & (1 << ((bitoffset) & 7)))
#define CLEARBIT(bits,bitoffset) (((uint8_t *)bits)[(bitoffset) >> 3] &= ~(1 << ((bitoffset) & 7)))

double OS_milliseconds();

int32_t SaM_test()
{
    int32_t i,j,wt,iter,totalset,totalclr,setcount[48*8],clrcount[48*8],histo[16]; bits256 seed;
    struct SaM_info state;
    uint8_t buf[4096*2],bits[2][10][48]; char trits[243];
    double startmilli = OS_milliseconds();
    for (i=0; i<sizeof(trits); i++)
        trits[i] = (rand() % 3) - 1;
    SaM_Initialize(&state);
    for (i=0; i<100000; i++)
    {
        _SaM_Absorb(&state,(void *)trits,sizeof(trits));
    }
    SaM_emit(&state);
    printf("per SaM %.3f\n",(OS_milliseconds() - startmilli) / i);
    getchar();
    
    for (i=0; i<1000; i++)
    {
        _SaM_test("A",InputA,0,OutputA);
        _SaM_test("B",InputB,sizeof(InputB),OutputB);
        _SaM_test("C",InputC,sizeof(InputC),OutputC);
        _SaM_test("D",InputD,sizeof(InputD),OutputD);
        _SaM_test("E",InputE,sizeof(InputE),OutputE);
    }
    printf("per SaM %.3f\n",((time(NULL) * 1000) - startmilli) / (5 * i));
    memset(seed.bytes,0,sizeof(seed));
    memcpy(seed.bytes,(uint8_t *)"12345678901",11);
    for (i=0; i<243*2; i++)
        buf[i] = 0;
    OS_randombytes(buf,sizeof(buf));
    for (iter=0; iter<2; iter++)
    {
        memset(&state,0,sizeof(state));
        SaM_Initialize(&state);
        SaM_Absorb(&state,buf,243*2,0,0);
        memset(setcount,0,sizeof(setcount));
        memset(clrcount,0,sizeof(clrcount));
        memset(histo,0,sizeof(histo));
        for (i=0; i<5; i++)
        {
            if ( (0) && (i % 100) == 99 )
            {
                for (j=0; j<32; j++)
                    seed.bytes[j] = rand() >> 8;
                SaM_Absorb(&state,seed.bytes,sizeof(seed),0,0);
            }
            memset(bits[iter][i],0,sizeof(bits[iter][i]));
            SaM_emit(&state);
            memcpy(bits[iter][i],state.bits.bytes,sizeof(bits[iter][i]));
            for (j=0; j<48; j++)
            {
                histo[bits[iter][i][j] & 0xf]++;
                histo[(bits[iter][i][j]>>4) & 0xf]++;
                printf("%02x ",bits[iter][i][j]);
            }
            printf("\n");
            for (j=0; j<48*8; j++)
            {
                if ( GETBIT(bits[iter][i],j) != 0 )
                    setcount[j]++;
                else clrcount[j]++;
            }
        }
        for (i=0; i<16; i++)
            printf("%8d ",histo[i]);
        printf("hex histogram\n");
        seed.bytes[0] ^= 1;
        buf[0] ^= 1;
    }
    for (i=0; i<5; i++)
    {
        for (j=wt=0; j<48; j++)
        {
            wt += bitweight(bits[0][i][j] ^ bits[1][i][j]);
            printf("%02x",bits[0][i][j] ^ bits[1][i][j]);
        }
        printf(" i.%d diff.%d\n",i,wt);
    }
    //set.19090245 clr.19309755 -0.0057
    //total set.19200072 clr.19199928 0.0000037500
    // total set.19191713 clr.19208287 -0.0004316146
    for (totalset=totalclr=j=0; j<48*8; j++)
    {
        totalset += setcount[j];
        totalclr += clrcount[j];
        printf("%.2f ",(double)(setcount[j]-clrcount[j])/i);
    }
    printf("total set.%d clr.%d %.10f\n",totalset,totalclr,(double)(totalset-totalclr)/(totalset+totalclr));
    return(0);
}

bits384 SaM_encrypt(uint8_t *dest,uint8_t *src,int32_t len,bits384 password,uint32_t timestamp)
{
    bits384 xorpad; int32_t i;  struct SaM_info XORpad;
    SaM_Initialize(&XORpad), SaM_Absorb(&XORpad,password.bytes,sizeof(password),(void *)&timestamp,sizeof(timestamp));
    memset(xorpad.bytes,0,sizeof(xorpad));
    while ( len >= 0 )
    {
        SaM_emit(&XORpad);
        for (i=0; i<sizeof(xorpad) && len>=0; i++,len--)
        {
            xorpad.bytes[i] = (XORpad.bits.bytes[i] ^ *src++);
            if ( dest != 0 )
                *dest++ = xorpad.bytes[i];
        }
    }
    return(xorpad);
}

uint64_t SaM_hit(struct SaM_info *state)
{
    int32_t i; uint64_t hit = 0;
    for (i=0; i<27; i++)
 		hit = (hit * 3 + state->hash[i] + 1);
    return(hit);
}

uint64_t SaM(bits384 *sigp,uint8_t *input,int32_t inputSize,uint8_t *input2,int32_t inputSize2)
{
    int32_t verify_SaM(TRIT *newhash,uint8_t *buf,const int n);
    struct SaM_info state;
    SaM_Initialize(&state);
    SaM_Absorb(&state,input,inputSize,input2,inputSize2);
    //printf("len.%d: ",inputSize+inputSize2);
    *sigp = SaM_emit(&state);
    //if ( 0 && input2 == 0 && numrounds == SAM_MAGIC_NUMBER )
    //    verify_SaM(state.hash,(uint8_t *)input,inputSize);
    return(SaM_hit(&state));
}

uint64_t SaM_threshold(int32_t leverage)
{
    int32_t i;
    uint64_t threshold,divisor = 1;
    if ( leverage > 26 )
        leverage = 26;
    for (i=0; i<leverage; i++)
        divisor *= 3;
    threshold = (SAMHIT_LIMIT / divisor);
    return(threshold);
}

#include <stdlib.h>

uint32_t SaM_nonce(void *data,int32_t datalen,int32_t leverage,int32_t maxmillis,uint32_t nonce)
{
    uint64_t hit,threshold; bits384 sig; double endmilli;
    if ( leverage != 0 )
    {
        threshold = SaM_threshold(leverage);
        if ( maxmillis == 0 )
        {
            if ( (hit= SaM(&sig,data,datalen,(void *)&nonce,sizeof(nonce))) >= threshold )
            {
                printf("nonce failure hit.%llu >= threshold.%llu | leverage.%d nonce.%u\n",(long long)hit,(long long)threshold,leverage,nonce);
                if ( (threshold - hit) > ((uint64_t)1L << 32) )
                    return(0xffffffff);
                else return((uint32_t)(threshold - hit));
            }
        }
        else
        {
            endmilli = (OS_milliseconds() + maxmillis);
            while ( OS_milliseconds() < endmilli )
            {
                OS_randombytes((void *)&nonce,sizeof(nonce));
                if ( (hit= SaM(&sig,data,datalen,(void *)&nonce,sizeof(nonce))) < threshold )
                {
                    printf("-> nonce.%u leverage.%d | hit.%llu < threshold.%llu\n",nonce,leverage,(long long)hit,(long long)threshold);
                    SaM_nonce(data,datalen,leverage,0,nonce);
                    return(nonce);
                }
            }
        }
    }
    return(0);
}

/*uint64_t SaMnonce(bits384 *sigp,uint32_t *noncep,uint8_t *buf,int32_t len,uint64_t threshold,uint32_t rseed,int32_t maxmillis)
{
    uint64_t hit = SAMHIT_LIMIT;
    double startmilli = 0;
    if ( maxmillis == 0 )
    {
        hit = calc_SaM(sigp,buf,len,0,0);
        if ( hit >= threshold )
        {
            printf("nonce failure hit.%llu >= threshold.%llu\n",(long long)hit,(long long)threshold);
            return(threshold - hit);
        }
        else return(0);
    }
    else startmilli = milliseconds();
    while ( hit >= threshold )
    {
        if ( rseed == 0 )
            randombytes((uint8_t *)noncep,sizeof(*noncep));
        else _randombytes((uint8_t *)noncep,sizeof(*noncep),rseed);
        hit = calc_SaM(sigp,buf,len,0,0);
        //printf("%llu %.2f%% (%s) len.%d numrounds.%lld threshold.%llu seed.%u\n",(long long)hit,100.*(double)hit/threshold,(char *)buf,len,(long long)numrounds,(long long)threshold,rseed);
        if ( maxmillis != 0 && milliseconds() > (startmilli + maxmillis) )
            return(0);
        if ( rseed != 0 )
            rseed = (uint32_t)(sigp->txid ^ hit);
    }
    //printf("%5.1f %14llu %7.2f%% numrounds.%lld threshold.%llu seed.%u\n",milliseconds()-startmilli,(long long)hit,100.*(double)hit/threshold,(long long)numrounds,(long long)threshold,rseed);
    return(hit);
}*/

#ifdef include_vps
// from Come-from-Beyond
#define HASH_SIZE 32

#define DAILY 0
#define WEEKLY 1
#define MONTHLY 2
#define YEARLY 3

#define MAX_NUMBER_OF_POOLS 1000
#define MAX_NUMBER_OF_TOKENS 1000
#define MAX_NUMBER_OF_UNITS 1000000
#define MAX_NUMBER_OF_SUPERVISORS 1000000

#define MAX_TOKEN_LIFESPAN 36500

unsigned int numberOfPools = 0;
struct Pool {
    
	signed long reserve;
	unsigned long quorum, decisionThreshold;
    
} pools[MAX_NUMBER_OF_POOLS];

unsigned int numberOfTokens = 0;
struct Token {
    
	BOOL enabled;
	unsigned int pool;
	unsigned long curSupply, maxSupply; // Defines max %% of total coin supply that can be locked
	signed int fadeRate; // Per day in 1/1000th (zero - to keep value const; negative - for deflation; positive - for inflation)
	unsigned int decreaseLimits[YEARLY + 1], increaseLimits[YEARLY + 1]; // In 1/1000th
	unsigned long unitSize; // Locked amount
	unsigned short minLockPeriod, maxLockPeriod; // In days
	unsigned char minExtraLockPeriod, maxExtraLockPeriod; // In days
	unsigned char redemptionGap; // In days
	unsigned long day0Offset; // UNIX time
	unsigned long prices[MAX_TOKEN_LIFESPAN]; // In main currency units
    
} tokens[MAX_NUMBER_OF_TOKENS];

unsigned int numberOfUnits = 0;
struct Unit {
    
	unsigned long id;
	unsigned int token;
	unsigned long account;
	signed int fadeRate;
	unsigned long size;
	unsigned long timestamp;
	unsigned char lockPeriodHash[HASH_SIZE];
	unsigned short minLockPeriod, maxLockPeriod;
	unsigned char extraLockPeriod;
	unsigned char redemptionGap;
    
} units[MAX_NUMBER_OF_UNITS];

unsigned int numberOfSupervisors = 0;
struct Supervisor {
    
	unsigned long id;
	signed long rating;
	unsigned int activity;
    
} supervisors[MAX_NUMBER_OF_SUPERVISORS];

struct Vote {
    
	unsigned long supervisorId;
	unsigned long price;
	unsigned long tolerance;
	unsigned long weight;
	unsigned long bet;
};

unsigned char random() {
    
	return 42; // TODO: Replace with a better RNG
}

void hash(unsigned char* data, unsigned int dataSize, unsigned char* hash) {
    
	// TODO: Invoke SHA-256
}

unsigned int addPool(unsigned long quorum, unsigned long decisionThreshold) {
	// Returns the index of the new pool
    
	if (numberOfPools >= MAX_NUMBER_OF_POOLS) {
        
		// TODO: Throw exception
	}
    
	pools[numberOfPools].reserve = 0;
	pools[numberOfPools].quorum = quorum;
	pools[numberOfPools].decisionThreshold = decisionThreshold;
    
	return numberOfPools++;
}

unsigned int addToken(unsigned int pool,
                      unsigned long maxSupply,
                      signed int fadeRate,
                      unsigned int* decreaseLimits, unsigned int* increaseLimits,
                      unsigned long unitSize,
                      unsigned short minLockPeriod, unsigned short maxLockPeriod,
                      unsigned char minExtraLockPeriod, unsigned char maxExtraLockPeriod,
                      unsigned char redemptionGap,
                      unsigned long day0Offset,
                      unsigned long initialPrice) {
	// Returns the index of the new token
    
	if (numberOfTokens >= MAX_NUMBER_OF_TOKENS) {
        
		// TODO: Throw exception
	}
    
	if (pool >= numberOfPools) {
        
		// TODO: Throw exception
	}
    
	if (minLockPeriod > maxLockPeriod || minExtraLockPeriod > maxExtraLockPeriod) {
        
		// TODO: Throw exception
	}
    
	tokens[numberOfTokens].enabled = TRUE;
	tokens[numberOfTokens].pool = pool;
	tokens[numberOfTokens].curSupply = 0;
	tokens[numberOfTokens].maxSupply = maxSupply;
	tokens[numberOfTokens].fadeRate = fadeRate;
	memcpy(tokens[numberOfTokens].decreaseLimits, decreaseLimits, sizeof(tokens[numberOfTokens].decreaseLimits));
	memcpy(tokens[numberOfTokens].increaseLimits, increaseLimits, sizeof(tokens[numberOfTokens].increaseLimits));
	tokens[numberOfTokens].unitSize = unitSize;
	tokens[numberOfTokens].minLockPeriod = minLockPeriod;
	tokens[numberOfTokens].maxLockPeriod = maxLockPeriod;
	tokens[numberOfTokens].minExtraLockPeriod = minExtraLockPeriod;
	tokens[numberOfTokens].maxExtraLockPeriod = maxExtraLockPeriod;
	tokens[numberOfTokens].redemptionGap = redemptionGap;
	tokens[numberOfTokens].day0Offset = day0Offset;
    
	memset(tokens[numberOfTokens].prices, 0, sizeof(tokens[numberOfTokens].prices));
	tokens[numberOfTokens].prices[0] = initialPrice;
    
	return numberOfTokens++;
}

void enableToken(unsigned int token) {
    
	tokens[token].enabled = TRUE;
}

void disableToken(unsigned int token) {
    
	tokens[token].enabled = FALSE;
}

void changeFadeRate(unsigned int token, signed int newFadeRate) {
    
	tokens[token].fadeRate = newFadeRate;
}

void changeUnitSize(unsigned int token, unsigned long newUnitSize) {
    
	tokens[token].unitSize = newUnitSize;
}

void changeLockPeriods(unsigned int token, unsigned short newMinLockPeriod, unsigned short newMaxLockPeriod) {
    
	tokens[token].minLockPeriod = newMinLockPeriod;
	tokens[token].maxLockPeriod = newMaxLockPeriod;
}

void changeExtraLockPeriods(unsigned int token, unsigned char newMinExtraLockPeriod, unsigned char newMaxExtraLockPeriod) {
    
	tokens[token].minExtraLockPeriod = newMinExtraLockPeriod;
	tokens[token].maxExtraLockPeriod = newMaxExtraLockPeriod;
}

void changeRedemptionGap(unsigned int token, unsigned char newRedemptionGap) {
    
	tokens[token].redemptionGap = newRedemptionGap;
}

void getLockPeriodHashAndPrefix(unsigned short lockPeriod, unsigned char* lockPeriodHash, unsigned char* lockPeriodPrefix) {
    
	unsigned char buffer[HASH_SIZE];
	int i;
	for (i = 0; i < HASH_SIZE - sizeof(lockPeriod); i++) {
        
		buffer[i] = random();
	}
	*((unsigned short*)&buffer[i]) = lockPeriod; // WARNING: Depends on endianness!
	hash(buffer, sizeof(buffer), lockPeriodHash);
	memcpy(lockPeriodPrefix, buffer, i);
}

unsigned long getLastPrice(unsigned int token, unsigned long time) {
    
	for (int i = (time - tokens[token].day0Offset) / (24 * 60 * 60 * 1000) + 1; i-- > 0;) {
        
		if (tokens[token].prices[i] > 0) {
            
			return tokens[token].prices[i];
		}
	}
}

unsigned int addUnit(unsigned long id,
                     unsigned int token,
                     unsigned long account,
                     unsigned long time,
                     unsigned char* lockPeriodHash,
                     unsigned short minLockPeriod, unsigned short maxLockPeriod,
                     unsigned long seed,
                     unsigned long mainCurrencyUnitSize) {
	// Returns the index of the new unit
    
	if (numberOfUnits >= MAX_NUMBER_OF_UNITS) {
        
		// TODO: Throw exception
	}
    
	if (token >= numberOfTokens) {
        
		// TODO: Throw exception
	}
    
	if (tokens[token].enabled == FALSE) {
        
		// TODO: Throw exception
	}
    
	units[numberOfUnits].id = id;
	units[numberOfUnits].token = token;
	units[numberOfUnits].account = account;
	units[numberOfUnits].fadeRate = tokens[token].fadeRate;
	units[numberOfUnits].size = tokens[token].unitSize;
	units[numberOfUnits].timestamp = time;
	memcpy(units[numberOfUnits].lockPeriodHash, lockPeriodHash, HASH_SIZE);
	units[numberOfUnits].minLockPeriod = minLockPeriod;
	units[numberOfUnits].maxLockPeriod = maxLockPeriod;
	units[numberOfUnits].extraLockPeriod = seed % (tokens[token].maxExtraLockPeriod - tokens[token].minExtraLockPeriod + 1) + tokens[token].minExtraLockPeriod;
	units[numberOfUnits].redemptionGap = tokens[token].redemptionGap;
    
	pools[tokens[token].pool].reserve += units[numberOfUnits].size * getLastPrice(token, time) / mainCurrencyUnitSize; // WARNING: May overflow!
    
	return numberOfUnits++;
}

unsigned long redeemUnit(unsigned long id, unsigned long account, unsigned short lockPeriod, unsigned char* lockPeriodPrefix, unsigned long time, unsigned long mainCurrencyUnitSize) {
	// Returns amount to add to the account balance
    
	for (int i = 0; i < numberOfUnits; i++) {
        
		if (units[i].id == id) {
            
			if (units[i].account == account) {
                
				unsigned char buffer[HASH_SIZE];
				memcpy(buffer, lockPeriodPrefix, HASH_SIZE - sizeof(lockPeriod));
				*((unsigned short*)&buffer[HASH_SIZE - sizeof(lockPeriod)]) = lockPeriod; // WARNING: Depends on endianness!
				unsigned char lockPeriodHash[HASH_SIZE];
				hash(buffer, sizeof(buffer), lockPeriodHash);
				for (int j = 0; j < HASH_SIZE; j++) {
                    
					if (lockPeriodHash[j] != units[i].lockPeriodHash[j]) {
                        
						return 0;
					}
				}
                
				if (lockPeriod < units[i].minLockPeriod || lockPeriod > units[i].maxLockPeriod) {
                    
					return 0;
				}
                
				unsigned int delta = (time - units[i].timestamp) / (24 * 60 * 60 * 1000);
				if (delta < lockPeriod + units[i].extraLockPeriod || delta > lockPeriod + units[i].extraLockPeriod + units[i].redemptionGap) {
                    
					return 0;
				}
                
				unsigned long amount = units[i].size * getLastPrice(units[i].token, units[i].timestamp + (lockPeriod + units[i].extraLockPeriod) * 24 * 60 * 60 * 1000) / mainCurrencyUnitSize; // WARNING: May overflow!
				for (int j = lockPeriod + units[i].extraLockPeriod; j-- > 0; ) {
                    
					amount = amount * (1000 - units[i].fadeRate) / 1000; // WARNING: Do not use floating-point math!
				}
				if (pools[tokens[units[i].token].pool].reserve < amount) {
                    
					amount = pools[tokens[units[i].token].pool].reserve;
				}
				pools[tokens[units[i].token].pool].reserve -= amount;
                
				memcpy(&units[i], &units[--numberOfUnits], sizeof(Unit));
                
				return amount;
			}
            
			break;
		}
	}
    
	return 0;
}

void salvageExpiredUnits(unsigned long time) {
    
	for (int i = numberOfUnits; i-- > 0; ) {
        
		if ((time - units[i].timestamp) / (24 * 60 * 60 * 1000) > units[i].maxLockPeriod + units[i].extraLockPeriod + units[i].redemptionGap) {
            
			memcpy(&units[i], &units[--numberOfUnits], sizeof(Unit));
		}
	}
}

unsigned int addSupervisor(unsigned long id) {
	// Returns the index of the new supervisor
    
	if (numberOfSupervisors >= MAX_NUMBER_OF_SUPERVISORS) {
        
		// TODO: Throw exception
	}
    
	supervisors[numberOfSupervisors].id = id;
	supervisors[numberOfSupervisors].rating = 0;
	supervisors[numberOfSupervisors].activity = 0;
    
	return numberOfSupervisors++;
}

Supervisor* getSupervisor(unsigned long id) {
    
	for (int i = 0; i < numberOfSupervisors; i++) {
        
		if (supervisors[i].id == id) {
            
			return &supervisors[i];
		}
	}
    
	return NULL;
}

BOOL castSupervisorVotes(unsigned int token, unsigned long time, Vote* votes, unsigned int numberOfVotes, unsigned long* prizes) {
	// Returns if a new price has been set
    
	unsigned long totalWeight = 0;
	unsigned long totalBet = 0;
	for (int i = 0; i < numberOfVotes; i++) {
        
		totalWeight += votes[i].weight;
		getSupervisor(votes[i].supervisorId)->activity++;
		totalBet += votes[i].bet;
	}
    
	if (totalWeight < pools[tokens[token].pool].quorum) {
        
		return FALSE;
	}
    
	unsigned long prices[MAX_NUMBER_OF_SUPERVISORS];
	unsigned long weights[MAX_NUMBER_OF_SUPERVISORS];
	for (int i = 0; i < numberOfVotes; i++) {
        
		int j;
		for (j = 0; j < i; j++) {
            
			if (prices[j] > votes[i].price) {
                
				break;
			}
			memmove(&prices[j + 1], &prices[j], (i - j) * sizeof(Vote));
			memmove(&weights[j + 1], &weights[j], (i - j) * sizeof(Vote));
			prices[j] = votes[i].price;
			weights[j] = votes[i].weight;
		}
	}
    
	unsigned long newPrice = 0;
	for (int i = 0; i < numberOfVotes; i++) {
        
		unsigned long weight = 0;
		unsigned long bet = 0;
		for (int j = 0; j < numberOfVotes; j++) {
            
			signed long delta = votes[i].price - votes[j].price;
			if (delta < 0) {
                
				delta = -delta;
			}
            
			if (delta <= votes[j].tolerance) {
                
				weight += votes[j].weight;
				bet += votes[j].bet;
			}
		}
		if (weight > totalWeight / 2) {
            
			newPrice = votes[i].price;
            
			unsigned long totalPrize = 0;
			for (int j = 0; j < numberOfVotes; j++) {
                
				signed long delta = votes[i].price - votes[j].price;
				if (delta < 0) {
                    
					delta = -delta;
				}
                
				if (delta <= votes[j].tolerance) {
                    
					getSupervisor(votes[j].supervisorId)->rating++;
					if (prizes != NULL) {
                        
						prizes[j] = votes[j].bet + (votes[j].bet * (totalBet - bet) / bet);
						totalPrize += prizes[j];
					}
                    
				} else {
                    
					if (prizes != NULL) {
                        
						prizes[j] = 0;
					}
				}
			}
            
			if (prizes != NULL) {
                
				pools[tokens[token].pool].reserve += totalBet - totalPrize;
			}
            
			break;
		}
	}
    
	if (newPrice == 0) {
        
		return FALSE;
        
	} else {
        
		unsigned long lastPrice = getLastPrice(token, time);
		if (newPrice < lastPrice) {
            
			if ((lastPrice - newPrice) * 1000 / lastPrice > tokens[token].decreaseLimits[DAILY]) {
                
				newPrice = lastPrice - tokens[token].decreaseLimits[DAILY] * lastPrice / 1000;
			}
            
			lastPrice = getLastPrice(token, time - 7L * 24 * 60 * 60 * 1000);
			if ((lastPrice - newPrice) * 1000 / lastPrice > tokens[token].decreaseLimits[WEEKLY]) {
                
				newPrice = lastPrice - tokens[token].decreaseLimits[WEEKLY] * lastPrice / 1000;
			}
            
			lastPrice = getLastPrice(token, time - 30L * 24 * 60 * 60 * 1000);
			if ((lastPrice - newPrice) * 1000 / lastPrice > tokens[token].decreaseLimits[MONTHLY]) {
                
				newPrice = lastPrice - tokens[token].decreaseLimits[MONTHLY] * lastPrice / 1000;
			}
            
			lastPrice = getLastPrice(token, time - 365L * 24 * 60 * 60 * 1000);
			if ((lastPrice - newPrice) * 1000 / lastPrice > tokens[token].decreaseLimits[YEARLY]) {
                
				newPrice = lastPrice - tokens[token].decreaseLimits[YEARLY] * lastPrice / 1000;
			}
            
		} else {
            
			if ((newPrice - lastPrice) * 1000 / lastPrice > tokens[token].increaseLimits[DAILY]) {
                
				newPrice = lastPrice + tokens[token].increaseLimits[DAILY] * lastPrice / 1000;
			}
            
			lastPrice = getLastPrice(token, time - 7L * 24 * 60 * 60 * 1000);
			if ((newPrice - lastPrice) * 1000 / lastPrice > tokens[token].increaseLimits[WEEKLY]) {
                
				newPrice = lastPrice + tokens[token].increaseLimits[WEEKLY] * lastPrice / 1000;
			}
            
			lastPrice = getLastPrice(token, time - 30L * 24 * 60 * 60 * 1000);
			if ((newPrice - lastPrice) * 1000 / lastPrice > tokens[token].increaseLimits[MONTHLY]) {
                
				newPrice = lastPrice + tokens[token].increaseLimits[MONTHLY] * lastPrice / 1000;
			}
            
			lastPrice = getLastPrice(token, time - 365L * 24 * 60 * 60 * 1000);
			if ((newPrice - lastPrice) * 1000 / lastPrice > tokens[token].increaseLimits[YEARLY]) {
                
				newPrice = lastPrice + tokens[token].increaseLimits[YEARLY] * lastPrice / 1000;
			}
		}
        
		tokens[token].prices[(time - tokens[token].day0Offset) / (24 * 60 * 60 * 1000)] = newPrice;
        
		return TRUE;
	}
}
#endif

char bits2trits[256][5] = {
    {0, 0, 0, 0, 0},
    {1, 0, 0, 0, 0},
    {-1, 1, 0, 0, 0},
    {0, 1, 0, 0, 0},
    {1, 1, 0, 0, 0},
    {-1, -1, 1, 0, 0},
    {0, -1, 1, 0, 0},
    {1, -1, 1, 0, 0},
    {-1, 0, 1, 0, 0},
    {0, 0, 1, 0, 0},
    {1, 0, 1, 0, 0},
    {-1, 1, 1, 0, 0},
    {0, 1, 1, 0, 0},
    {1, 1, 1, 0, 0},
    {-1, -1, -1, 1, 0},
    {0, -1, -1, 1, 0},
    {1, -1, -1, 1, 0},
    {-1, 0, -1, 1, 0},
    {0, 0, -1, 1, 0},
    {1, 0, -1, 1, 0},
    {-1, 1, -1, 1, 0},
    {0, 1, -1, 1, 0},
    {1, 1, -1, 1, 0},
    {-1, -1, 0, 1, 0},
    {0, -1, 0, 1, 0},
    {1, -1, 0, 1, 0},
    {-1, 0, 0, 1, 0},
    {0, 0, 0, 1, 0},
    {1, 0, 0, 1, 0},
    {-1, 1, 0, 1, 0},
    {0, 1, 0, 1, 0},
    {1, 1, 0, 1, 0},
    {-1, -1, 1, 1, 0},
    {0, -1, 1, 1, 0},
    {1, -1, 1, 1, 0},
    {-1, 0, 1, 1, 0},
    {0, 0, 1, 1, 0},
    {1, 0, 1, 1, 0},
    {-1, 1, 1, 1, 0},
    {0, 1, 1, 1, 0},
    {1, 1, 1, 1, 0},
    {-1, -1, -1, -1, 1},
    {0, -1, -1, -1, 1},
    {1, -1, -1, -1, 1},
    {-1, 0, -1, -1, 1},
    {0, 0, -1, -1, 1},
    {1, 0, -1, -1, 1},
    {-1, 1, -1, -1, 1},
    {0, 1, -1, -1, 1},
    {1, 1, -1, -1, 1},
    {-1, -1, 0, -1, 1},
    {0, -1, 0, -1, 1},
    {1, -1, 0, -1, 1},
    {-1, 0, 0, -1, 1},
    {0, 0, 0, -1, 1},
    {1, 0, 0, -1, 1},
    {-1, 1, 0, -1, 1},
    {0, 1, 0, -1, 1},
    {1, 1, 0, -1, 1},
    {-1, -1, 1, -1, 1},
    {0, -1, 1, -1, 1},
    {1, -1, 1, -1, 1},
    {-1, 0, 1, -1, 1},
    {0, 0, 1, -1, 1},
    {1, 0, 1, -1, 1},
    {-1, 1, 1, -1, 1},
    {0, 1, 1, -1, 1},
    {1, 1, 1, -1, 1},
    {-1, -1, -1, 0, 1},
    {0, -1, -1, 0, 1},
    {1, -1, -1, 0, 1},
    {-1, 0, -1, 0, 1},
    {0, 0, -1, 0, 1},
    {1, 0, -1, 0, 1},
    {-1, 1, -1, 0, 1},
    {0, 1, -1, 0, 1},
    {1, 1, -1, 0, 1},
    {-1, -1, 0, 0, 1},
    {0, -1, 0, 0, 1},
    {1, -1, 0, 0, 1},
    {-1, 0, 0, 0, 1},
    {0, 0, 0, 0, 1},
    {1, 0, 0, 0, 1},
    {-1, 1, 0, 0, 1},
    {0, 1, 0, 0, 1},
    {1, 1, 0, 0, 1},
    {-1, -1, 1, 0, 1},
    {0, -1, 1, 0, 1},
    {1, -1, 1, 0, 1},
    {-1, 0, 1, 0, 1},
    {0, 0, 1, 0, 1},
    {1, 0, 1, 0, 1},
    {-1, 1, 1, 0, 1},
    {0, 1, 1, 0, 1},
    {1, 1, 1, 0, 1},
    {-1, -1, -1, 1, 1},
    {0, -1, -1, 1, 1},
    {1, -1, -1, 1, 1},
    {-1, 0, -1, 1, 1},
    {0, 0, -1, 1, 1},
    {1, 0, -1, 1, 1},
    {-1, 1, -1, 1, 1},
    {0, 1, -1, 1, 1},
    {1, 1, -1, 1, 1},
    {-1, -1, 0, 1, 1},
    {0, -1, 0, 1, 1},
    {1, -1, 0, 1, 1},
    {-1, 0, 0, 1, 1},
    {0, 0, 0, 1, 1},
    {1, 0, 0, 1, 1},
    {-1, 1, 0, 1, 1},
    {0, 1, 0, 1, 1},
    {1, 1, 0, 1, 1},
    {-1, -1, 1, 1, 1},
    {0, -1, 1, 1, 1},
    {1, -1, 1, 1, 1},
    {-1, 0, 1, 1, 1},
    {0, 0, 1, 1, 1},
    {1, 0, 1, 1, 1},
    {-1, 1, 1, 1, 1},
    {0, 1, 1, 1, 1},
    {1, 1, 1, 1, 1},
    {2, 2, 2, 2, 2},
    {2, 2, 2, 2, 2},
    {2, 2, 2, 2, 2},
    {2, 2, 2, 2, 2},
    {2, 2, 2, 2, 2},
    {2, 2, 2, 2, 2},
    {2, 2, 2, 2, 2},
    {2, 2, 2, 2, 2},
    {2, 2, 2, 2, 2},
    {2, 2, 2, 2, 2},
    {2, 2, 2, 2, 2},
    {2, 2, 2, 2, 2},
    {2, 2, 2, 2, 2},
    {-1, -1, -1, -1, -1},
    {0, -1, -1, -1, -1},
    {1, -1, -1, -1, -1},
    {-1, 0, -1, -1, -1},
    {0, 0, -1, -1, -1},
    {1, 0, -1, -1, -1},
    {-1, 1, -1, -1, -1},
    {0, 1, -1, -1, -1},
    {1, 1, -1, -1, -1},
    {-1, -1, 0, -1, -1},
    {0, -1, 0, -1, -1},
    {1, -1, 0, -1, -1},
    {-1, 0, 0, -1, -1},
    {0, 0, 0, -1, -1},
    {1, 0, 0, -1, -1},
    {-1, 1, 0, -1, -1},
    {0, 1, 0, -1, -1},
    {1, 1, 0, -1, -1},
    {-1, -1, 1, -1, -1},
    {0, -1, 1, -1, -1},
    {1, -1, 1, -1, -1},
    {-1, 0, 1, -1, -1},
    {0, 0, 1, -1, -1},
    {1, 0, 1, -1, -1},
    {-1, 1, 1, -1, -1},
    {0, 1, 1, -1, -1},
    {1, 1, 1, -1, -1},
    {-1, -1, -1, 0, -1},
    {0, -1, -1, 0, -1},
    {1, -1, -1, 0, -1},
    {-1, 0, -1, 0, -1},
    {0, 0, -1, 0, -1},
    {1, 0, -1, 0, -1},
    {-1, 1, -1, 0, -1},
    {0, 1, -1, 0, -1},
    {1, 1, -1, 0, -1},
    {-1, -1, 0, 0, -1},
    {0, -1, 0, 0, -1},
    {1, -1, 0, 0, -1},
    {-1, 0, 0, 0, -1},
    {0, 0, 0, 0, -1},
    {1, 0, 0, 0, -1},
    {-1, 1, 0, 0, -1},
    {0, 1, 0, 0, -1},
    {1, 1, 0, 0, -1},
    {-1, -1, 1, 0, -1},
    {0, -1, 1, 0, -1},
    {1, -1, 1, 0, -1},
    {-1, 0, 1, 0, -1},
    {0, 0, 1, 0, -1},
    {1, 0, 1, 0, -1},
    {-1, 1, 1, 0, -1},
    {0, 1, 1, 0, -1},
    {1, 1, 1, 0, -1},
    {-1, -1, -1, 1, -1},
    {0, -1, -1, 1, -1},
    {1, -1, -1, 1, -1},
    {-1, 0, -1, 1, -1},
    {0, 0, -1, 1, -1},
    {1, 0, -1, 1, -1},
    {-1, 1, -1, 1, -1},
    {0, 1, -1, 1, -1},
    {1, 1, -1, 1, -1},
    {-1, -1, 0, 1, -1},
    {0, -1, 0, 1, -1},
    {1, -1, 0, 1, -1},
    {-1, 0, 0, 1, -1},
    {0, 0, 0, 1, -1},
    {1, 0, 0, 1, -1},
    {-1, 1, 0, 1, -1},
    {0, 1, 0, 1, -1},
    {1, 1, 0, 1, -1},
    {-1, -1, 1, 1, -1},
    {0, -1, 1, 1, -1},
    {1, -1, 1, 1, -1},
    {-1, 0, 1, 1, -1},
    {0, 0, 1, 1, -1},
    {1, 0, 1, 1, -1},
    {-1, 1, 1, 1, -1},
    {0, 1, 1, 1, -1},
    {1, 1, 1, 1, -1},
    {-1, -1, -1, -1, 0},
    {0, -1, -1, -1, 0},
    {1, -1, -1, -1, 0},
    {-1, 0, -1, -1, 0},
    {0, 0, -1, -1, 0},
    {1, 0, -1, -1, 0},
    {-1, 1, -1, -1, 0},
    {0, 1, -1, -1, 0},
    {1, 1, -1, -1, 0},
    {-1, -1, 0, -1, 0},
    {0, -1, 0, -1, 0},
    {1, -1, 0, -1, 0},
    {-1, 0, 0, -1, 0},
    {0, 0, 0, -1, 0},
    {1, 0, 0, -1, 0},
    {-1, 1, 0, -1, 0},
    {0, 1, 0, -1, 0},
    {1, 1, 0, -1, 0},
    {-1, -1, 1, -1, 0},
    {0, -1, 1, -1, 0},
    {1, -1, 1, -1, 0},
    {-1, 0, 1, -1, 0},
    {0, 0, 1, -1, 0},
    {1, 0, 1, -1, 0},
    {-1, 1, 1, -1, 0},
    {0, 1, 1, -1, 0},
    {1, 1, 1, -1, 0},
    {-1, -1, -1, 0, 0},
    {0, -1, -1, 0, 0},
    {1, -1, -1, 0, 0},
    {-1, 0, -1, 0, 0},
    {0, 0, -1, 0, 0},
    {1, 0, -1, 0, 0},
    {-1, 1, -1, 0, 0},
    {0, 1, -1, 0, 0},
    {1, 1, -1, 0, 0},
    {-1, -1, 0, 0, 0},
    {0, -1, 0, 0, 0},
    {1, -1, 0, 0, 0},
    {-1, 0, 0, 0, 0}
};

#endif
#endif
