
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
//  LP_bitcoin.c
//  marketmaker
//

union iguana_stacknum { int32_t val; int64_t val64; uint8_t rmd160[20]; bits256 hash2; uint8_t pubkey[33]; uint8_t sig[74]; };
struct iguana_stackdata { uint8_t *data; uint16_t size; union iguana_stacknum U; };

char *bitcoin_base58encode(char *coinaddr,uint8_t *data,int32_t datalen);
int32_t bitcoin_base58decode(uint8_t *data,char *coinaddr);

#define IGUANA_MAXSCRIPTSIZE 10001
#define IGUANA_SEQUENCEID_FINAL 0xfffffffe

#define IGUANA_SCRIPT_NULL 0
#define IGUANA_SCRIPT_76AC 1
#define IGUANA_SCRIPT_76A988AC 2
#define IGUANA_SCRIPT_P2SH 3
#define IGUANA_SCRIPT_OPRETURN 4
#define IGUANA_SCRIPT_3of3 5
#define IGUANA_SCRIPT_2of3 6
#define IGUANA_SCRIPT_1of3 7
#define IGUANA_SCRIPT_2of2 8
#define IGUANA_SCRIPT_1of2 9
#define IGUANA_SCRIPT_MSIG 10
#define IGUANA_SCRIPT_DATA 11
#define IGUANA_SCRIPT_AC 12
#define IGUANA_SCRIPT_1of1 13
#define IGUANA_SCRIPT_STRANGE 15

#define MAX_SCRIPT_ELEMENT_SIZE 520
#define MAX_OPS_PER_SCRIPT 201 // Maximum number of non-push operations per script
#define MAX_PUBKEYS_PER_MULTISIG 20 // Maximum number of public keys per multisig

#define IGUANA_MAXSTACKITEMS ((int32_t)(IGUANA_MAXSCRIPTSIZE / sizeof(uint32_t)))
#define IGUANA_MAXSTACKDEPTH 128
struct iguana_interpreter
{
    int32_t active,ifdepth,elsedepth,codeseparator,stackdepth,altstackdepth,maxstackdepth;
    int8_t lastpath[IGUANA_MAXSTACKDEPTH];
    cJSON *logarray;
    struct iguana_stackdata stack[];
};
static struct bitcoin_opcode { UT_hash_handle hh; uint8_t opcode,flags,stackitems; int8_t extralen; } *OPTABLE; static char *OPCODES[0x100]; static int32_t OPCODELENS[0x100];

#define SIGHASH_ALL 1
#define SIGHASH_NONE 2
#define SIGHASH_SINGLE 3
#define SIGHASH_ANYONECANPAY 0x80

#define SCRIPT_OP_NOP 0x00
#define SCRIPT_OP_TRUE 0x51
#define SCRIPT_OP_2 0x52
#define SCRIPT_OP_3 0x53
#define SCRIPT_OP_4 0x54
#define SCRIPT_OP_IF 0x63
#define SCRIPT_OP_ELSE 0x67
#define SCRIPT_OP_RETURN 0x6a
#define SCRIPT_OP_DUP 0x76
#define SCRIPT_OP_ENDIF 0x68
#define SCRIPT_OP_DROP 0x75
#define SCRIPT_OP_EQUALVERIFY 0x88
#define SCRIPT_OP_SHA256 0xa8
#define SCRIPT_OP_HASH160 0xa9

#define SCRIPT_OP_EQUAL 0x87
#define SCRIPT_OP_CHECKSIG 0xac
#define SCRIPT_OP_CHECKMULTISIG 0xae
#define SCRIPT_OP_CHECKSEQUENCEVERIFY	0xb2
#define SCRIPT_OP_CHECKLOCKTIMEVERIFY 0xb1
#define IGUANA_OP_0 0x00
#define IGUANA_OP_PUSHDATA1 0x4c
#define IGUANA_OP_PUSHDATA2 0x4d
#define IGUANA_OP_PUSHDATA4 0x4e
#define IGUANA_OP_1NEGATE 0x4f
#define IGUANA_OP_1 0x51
#define IGUANA_OP_16 0x60
#define IGUANA_OP_NOP 0x61
#define IGUANA_OP_IF 0x63
#define IGUANA_OP_NOTIF 0x64
#define IGUANA_OP_ELSE 0x67
#define IGUANA_OP_ENDIF 0x68
#define IGUANA_OP_VERIFY 0x69
#define IGUANA_OP_RETURN 0x6a

#define IGUANA_OP_TOALTSTACK 0x6b
#define IGUANA_OP_FROMALTSTACK 0x6c
#define IGUANA_OP_2DROP 0x6d
#define IGUANA_OP_2DUP 0x6e
#define IGUANA_OP_3DUP 0x6f
#define IGUANA_OP_2OVER 0x70
#define IGUANA_OP_2ROT 0x71
#define IGUANA_OP_2SWAP 0x72
#define IGUANA_OP_IFDUP 0x73
#define IGUANA_OP_DEPTH 0x74
#define IGUANA_OP_DROP 0x75
#define IGUANA_OP_DUP 0x76
#define IGUANA_OP_NIP 0x77
#define IGUANA_OP_OVER 0x78
#define IGUANA_OP_PICK 0x79
#define IGUANA_OP_ROLL 0x7a
#define IGUANA_OP_ROT 0x7b
#define IGUANA_OP_SWAP 0x7c
#define IGUANA_OP_TUCK 0x7d

#define IGUANA_OP_SIZE 0x82
#define IGUANA_OP_EQUAL 0x87
#define IGUANA_OP_EQUALVERIFY 0x88

#define IGUANA_OP_1ADD 0x8b
#define IGUANA_OP_1SUB 0x8c
#define IGUANA_OP_NEGATE 0x8f
#define IGUANA_OP_ABS 0x90
#define IGUANA_OP_NOT 0x91
#define IGUANA_OP_0NOTEQUAL 0x92
#define IGUANA_OP_ADD 0x93
#define IGUANA_OP_SUB 0x94

#define IGUANA_OP_BOOLAND 0x9a
#define IGUANA_OP_BOOLOR 0x9b
#define IGUANA_OP_NUMEQUAL 0x9c
#define IGUANA_OP_NUMEQUALVERIFY 0x9d
#define IGUANA_OP_NUMNOTEQUAL 0x9e
#define IGUANA_OP_LESSTHAN 0x9f
#define IGUANA_OP_GREATERTHAN 0xa0
#define IGUANA_OP_LESSTHANOREQUAL 0xa1
#define IGUANA_OP_GREATERTHANOREQUAL 0xa2
#define IGUANA_OP_MIN 0xa3
#define IGUANA_OP_MAX 0xa4
#define IGUANA_OP_WITHIN 0xa5

#define IGUANA_OP_RIPEMD160 0xa6
#define IGUANA_OP_SHA1 0xa7
#define IGUANA_OP_SHA256 0xa8
#define IGUANA_OP_HASH160 0xa9
#define IGUANA_OP_HASH256 0xaa
#define IGUANA_OP_CODESEPARATOR 0xab
#define IGUANA_OP_CHECKSIG 0xac
#define IGUANA_OP_CHECKSIGVERIFY 0xad
#define IGUANA_OP_CHECKMULTISIG 0xae
#define IGUANA_OP_CHECKMULTISIGVERIFY 0xaf

#define IGUANA_OP_NOP1 0xb0
#define IGUANA_OP_CHECKLOCKTIMEVERIFY 0xb1
#define IGUANA_OP_CHECKSEQUENCEVERIFY 0xb2
#define IGUANA_OP_NOP10 0xb9

#define IGUANA_OP_COMBINEPUBKEYS 0xc0
#define IGUANA_OP_CHECKSCHNORR 0xc1
#define IGUANA_OP_CHECKSCHNORRVERIFY 0xc2

// https://github.com/TierNolan/bips/blob/cpkv/bip-cprkv.mediawiki
#define IGUANA_OP_CHECKPRIVATEKEY 0xc3
#define IGUANA_OP_CHECKPRIVATEKEYVERIFY 0xc4

#define IGUANA_NOPFLAG 1
#define IGUANA_ALWAYSILLEGAL 2
#define IGUANA_EXECUTIONILLEGAL 4
#define IGUANA_POSTVERIFY 8
#define IGUANA_CRYPTOFLAG 16
#define IGUANA_MATHFLAG 32
#define IGUANA_CONTROLFLAG 64
#define IGUANA_STACKFLAG 128

enum opcodetype
{
    // push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_TRUE=OP_1,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,
    
    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,
    
    // stack ops
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,
    
    // splice ops
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,
    
    // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,
    
    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,
    
    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,
    
    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,
    
    OP_WITHIN = 0xa5,
    
    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,
    
    // expansion
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY  = 0xb1,
    OP_CHECKSEQUENCEVERIFY   = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,
    
    OP_COMBINEPUBKEYS = 0xc0,
    OP_CHECKSCHNORR = 0xc1,
    OP_CHECKSCHNORRVERIFY = 0xc2,
    OP_CHECKPRIVATEKEY = 0xc3,
    OP_CHECKPRIVATEKEYVERIFY = 0xc4,
    
    // template matching params
    //OP_SMALLINTEGER = 0xfa,
    //OP_PUBKEYS = 0xfb,
    //OP_PUBKEYHASH = 0xfd,
    //OP_PUBKEY = 0xfe,
    
    OP_INVALIDOPCODE = 0xff,
};

int32_t iguana_rwnum(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp)
{
    int32_t i; uint64_t x;
    if ( rwflag == 0 )
    {
        x = 0;
        for (i=len-1; i>=0; i--)
        {
            x <<= 8;
            x |= serialized[i];
        }
        switch ( len )
        {
            case 1: *(uint8_t *)endianedp = (uint8_t)x; break;
            case 2: *(uint16_t *)endianedp = (uint16_t)x; break;
            case 4: *(uint32_t *)endianedp = (uint32_t)x; break;
            case 8: *(uint64_t *)endianedp = (uint64_t)x; break;
        }
    }
    else
    {
        x = 0;
        switch ( len )
        {
            case 1: x = *(uint8_t *)endianedp; break;
            case 2: x = *(uint16_t *)endianedp; break;
            case 4: x = *(uint32_t *)endianedp; break;
            case 8: x = *(uint64_t *)endianedp; break;
        }
        for (i=0; i<len; i++,x >>= 8)
            serialized[i] = (uint8_t)(x & 0xff);
    }
    return(len);
}

int32_t iguana_rwbignum(int32_t rwflag,uint8_t *serialized,int32_t len,uint8_t *endianedp)
{
    int32_t i;
    if ( rwflag == 0 )
    {
        for (i=0; i<len; i++)
            endianedp[i] = serialized[len - 1 - i];
    }
    else
    {
        for (i=0; i<len; i++)
            serialized[i] = endianedp[len - 1 - i];
    }
    return(len);
}

uint8_t *iguana_varint16(int32_t rwflag,uint8_t *serialized,uint16_t *varint16p)
{
    uint16_t n = 0;
    if ( rwflag == 0 )
    {
        n = *serialized++;
        n |= ((int32_t)*serialized++ << 8);
        *varint16p = n;
    }
    else
    {
        n = *varint16p;
        *serialized++ = (uint8_t)n & 0xff;
        *serialized++ = (uint8_t)(n >> 8) & 0xff;
    }
    return(serialized);
}

uint8_t *iguana_varint32(int32_t rwflag,uint8_t *serialized,uint16_t *varint16p)
{
    serialized = iguana_varint16(rwflag,serialized,varint16p);
    serialized = iguana_varint16(rwflag,serialized,&varint16p[1]);
    return(serialized);
}

uint8_t *iguana_varint64(int32_t rwflag,uint8_t *serialized,uint32_t *varint32p)
{
    serialized = iguana_varint32(rwflag,serialized,(uint16_t *)varint32p);
    serialized = iguana_varint32(rwflag,serialized,(uint16_t *)&varint32p[1]);
    return(serialized);
}

int32_t iguana_rwvarint(int32_t rwflag,uint8_t *serialized,uint64_t *varint64p)
{
    uint64_t n; int32_t vlen = 1;
    if ( rwflag == 0 )
    {
        *varint64p = 0;
        if ( (n= *serialized++) >= 0xfd )
        {
            if ( n == 0xfd )
            {
                n = 0;
                iguana_varint16(rwflag,serialized,(uint16_t *)&n);
                vlen += 2;
            }
            else if ( n == 0xfe )
            {
                n = 0;
                iguana_varint32(rwflag,serialized,(uint16_t *)&n);
                vlen += 4;
            }
            else if ( n == 0xff )
            {
                n = 0;
                iguana_varint64(rwflag,serialized,(uint32_t *)&n);
                vlen += 8;
            }
        }
        *varint64p = n;
    }
    else
    {
        n = *varint64p;
        if ( n < 0xfd )
            *serialized++ = (uint8_t)n;
        else if ( n <= 0xffff )
        {
            *serialized++ = 0xfd;
            iguana_varint16(rwflag,serialized,(uint16_t *)varint64p);
            vlen += 2;
        }
        else if ( n <= 0xffffffff )
        {
            *serialized++ = 0xfe;
            iguana_varint32(rwflag,serialized,(uint16_t *)varint64p);
            vlen += 4;
        }
        else
        {
            *serialized++ = 0xff;
            iguana_varint64(rwflag,serialized,(uint32_t *)varint64p);
            vlen += 8;
        }
    }
    return(vlen);
}

int32_t iguana_rwvarint32(int32_t rwflag,uint8_t *serialized,uint32_t *int32p)
{
    int32_t len; uint64_t x = 0;
    if ( rwflag != 0 )
        x = *int32p;
    len = iguana_rwvarint(rwflag,serialized,&x);
    if ( rwflag == 0 )
        *int32p = (int32_t)x;
    return(len);
}

int32_t iguana_rwvarstr(int32_t rwflag,uint8_t *serialized,int32_t maxlen,char *endianedp)
{
    int32_t vlen; uint64_t n;
    if ( rwflag == 0 )
    {
        vlen = iguana_rwvarint(rwflag,serialized,&n);
        memcpy(endianedp,&serialized[vlen],n);
        ((uint8_t *)endianedp)[n] = 0;
    }
    else
    {
        n = strlen(endianedp);
        if ( n > maxlen )
            n = maxlen;
        vlen = iguana_rwvarint(rwflag,serialized,&n);
        memcpy(&serialized[vlen],endianedp,n);
    }
    return((int32_t)(n + vlen));
}

int32_t iguana_rwmem(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp)
{
    if ( rwflag == 0 )
        memcpy(endianedp,serialized,len);
    else memcpy(serialized,endianedp,len);
    return(len);
}

const char *get_opname(uint8_t *stackitemsp,uint8_t *flagsp,int32_t *extralenp,enum opcodetype opcode)
{
    *extralenp = 0;
    switch ( opcode )
    {
            // push value
        case OP_0            : return "0";
        case OP_PUSHDATA1    : *extralenp = 1; return "OP_PUSHDATA1";
        case OP_PUSHDATA2    : *extralenp = 2; return "OP_PUSHDATA2";
        case OP_PUSHDATA4    : *flagsp = IGUANA_EXECUTIONILLEGAL; return "OP_PUSHDATA4";
        case OP_1NEGATE      : return "-1";
        case OP_RESERVED     : *flagsp = IGUANA_EXECUTIONILLEGAL; return "OP_RESERVED";
        case OP_1            : return "1";
        case OP_2            : return "2";
        case OP_3            : return "3";
        case OP_4            : return "4";
        case OP_5            : return "5";
        case OP_6            : return "6";
        case OP_7            : return "7";
        case OP_8            : return "8";
        case OP_9            : return "9";
        case OP_10           : return "10";
        case OP_11           : return "11";
        case OP_12           : return "12";
        case OP_13           : return "13";
        case OP_14           : return "14";
        case OP_15           : return "15";
        case OP_16           : return "16";
            
            // control
        case OP_NOP          : *flagsp = IGUANA_NOPFLAG; return "OP_NOP";
        case OP_VER          : *flagsp = IGUANA_EXECUTIONILLEGAL; return "OP_VER";
        case OP_IF           : *flagsp = IGUANA_CONTROLFLAG; *stackitemsp = 1; return "OP_IF";
        case OP_NOTIF        : *flagsp = IGUANA_CONTROLFLAG; *stackitemsp = 1; return "OP_NOTIF";
        case OP_VERIF        : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_VERIF";
        case OP_VERNOTIF     : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_VERNOTIF";
        case OP_ELSE         : *flagsp = IGUANA_CONTROLFLAG; return "OP_ELSE";
        case OP_ENDIF        : *flagsp = IGUANA_CONTROLFLAG; return "OP_ENDIF";
        case OP_VERIFY       : *flagsp = IGUANA_POSTVERIFY; return "OP_VERIFY";
        case OP_RETURN       : *flagsp = IGUANA_CONTROLFLAG; return "OP_RETURN";
            
            // stack ops
        case OP_TOALTSTACK   : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 1; return "OP_TOALTSTACK";
        case OP_FROMALTSTACK : *flagsp = IGUANA_STACKFLAG; return "OP_FROMALTSTACK";
        case OP_2DROP        : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 2; return "OP_2DROP";
        case OP_2DUP         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 2; return "OP_2DUP";
        case OP_3DUP         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 3; return "OP_3DUP";
        case OP_2OVER        : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 4; return "OP_2OVER";
        case OP_2ROT         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 6; return "OP_2ROT";
        case OP_2SWAP        : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 4; return "OP_2SWAP";
        case OP_IFDUP        : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 1; return "OP_IFDUP";
        case OP_DEPTH        : *flagsp = IGUANA_STACKFLAG; return "OP_DEPTH";
        case OP_DROP         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 1; return "OP_DROP";
        case OP_DUP          : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 1; return "OP_DUP";
        case OP_NIP          : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 2; return "OP_NIP";
        case OP_OVER         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 2; return "OP_OVER";
        case OP_PICK         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 1; return "OP_PICK";
        case OP_ROLL         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 1; return "OP_ROLL";
        case OP_ROT          : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 3; return "OP_ROT";
        case OP_SWAP         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 2; return "OP_SWAP";
        case OP_TUCK         : *flagsp = IGUANA_STACKFLAG; *stackitemsp = 2; return "OP_TUCK";
            
            // splice ops
        case OP_CAT          : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_CAT";
        case OP_SUBSTR       : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_SUBSTR";
        case OP_LEFT         : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_LEFT";
        case OP_RIGHT        : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_RIGHT";
        case OP_SIZE         : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_SIZE";
            
            // bit logic
        case OP_INVERT       : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_INVERT";
        case OP_AND          : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_AND";
        case OP_OR           : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_OR";
        case OP_XOR          : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_XOR";
        case OP_EQUAL        : *stackitemsp = 2; return "OP_EQUAL";
        case OP_EQUALVERIFY  : *stackitemsp = 2; *flagsp = IGUANA_POSTVERIFY; return "OP_EQUALVERIFY";
        case OP_RESERVED1    : *flagsp = IGUANA_EXECUTIONILLEGAL; return "OP_RESERVED1";
        case OP_RESERVED2    : *flagsp = IGUANA_EXECUTIONILLEGAL; return "OP_RESERVED2";
            
            // numeric
        case OP_1ADD         : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 1; return "OP_1ADD";
        case OP_1SUB         : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 1; return "OP_1SUB";
        case OP_2MUL         : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_2MUL";
        case OP_2DIV         : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_2DIV";
        case OP_NEGATE       : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 1; return "OP_NEGATE";
        case OP_ABS          : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 1; return "OP_ABS";
        case OP_NOT          : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 1; return "OP_NOT";
        case OP_0NOTEQUAL    : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 1; return "OP_0NOTEQUAL";
        case OP_ADD          : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_ADD";
        case OP_SUB          : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_SUB";
        case OP_MUL          : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_MUL";
        case OP_DIV          : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_DIV";
        case OP_MOD          : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_MOD";
        case OP_LSHIFT       : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_LSHIFT";
        case OP_RSHIFT       : *flagsp = IGUANA_ALWAYSILLEGAL; return "OP_RSHIFT";
        case OP_BOOLAND      : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_BOOLAND";
        case OP_BOOLOR       : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_BOOLOR";
        case OP_NUMEQUAL     : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_NUMEQUAL";
        case OP_NUMEQUALVERIFY: *flagsp = IGUANA_MATHFLAG | IGUANA_POSTVERIFY; *stackitemsp = 2; return "OP_NUMEQUALVERIFY";
        case OP_NUMNOTEQUAL  : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_NUMNOTEQUAL";
        case OP_LESSTHAN     : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_LESSTHAN";
        case OP_GREATERTHAN  : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_GREATERTHAN";
        case OP_LESSTHANOREQUAL: *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_LESSTHANOREQUAL";
        case OP_GREATERTHANOREQUAL: *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_GREATERTHANOREQUAL";
        case OP_MIN          : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_MIN";
        case OP_MAX          : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 2; return "OP_MAX";
        case OP_WITHIN       : *flagsp = IGUANA_MATHFLAG; *stackitemsp = 3; return "OP_WITHIN";
            
            // crypto
        case OP_RIPEMD160    : *stackitemsp = 1; *flagsp = IGUANA_CRYPTOFLAG; return "OP_RIPEMD160";
        case OP_SHA1         : *stackitemsp = 1; *flagsp = IGUANA_CRYPTOFLAG; return "OP_SHA1";
        case OP_SHA256       : *stackitemsp = 1; *flagsp = IGUANA_CRYPTOFLAG; return "OP_SHA256";
        case OP_HASH160      : *stackitemsp = 1; *flagsp = IGUANA_CRYPTOFLAG; return "OP_HASH160";
        case OP_HASH256      : *stackitemsp = 1; *flagsp = IGUANA_CRYPTOFLAG; return "OP_HASH256";
        case OP_CODESEPARATOR: return "OP_CODESEPARATOR";
        case OP_CHECKSIG     : *stackitemsp = 2; *flagsp = IGUANA_CRYPTOFLAG; return "OP_CHECKSIG";
        case OP_CHECKSIGVERIFY: *stackitemsp = 2; *flagsp = IGUANA_CRYPTOFLAG | IGUANA_POSTVERIFY; return "OP_CHECKSIGVERIFY";
        case OP_CHECKMULTISIG:       *flagsp = IGUANA_CRYPTOFLAG; return "OP_CHECKMULTISIG";
        case OP_CHECKMULTISIGVERIFY: *flagsp = IGUANA_CRYPTOFLAG | IGUANA_POSTVERIFY; return "OP_CHECKMULTISIGVERIFY";
        case OP_COMBINEPUBKEYS:     *flagsp = IGUANA_CRYPTOFLAG; return "OP_COMBINEPUBKEYS";
        case OP_CHECKSCHNORR:  *stackitemsp = 3; *flagsp = IGUANA_CRYPTOFLAG; return "OP_CHECKSCHNORR";
        case OP_CHECKSCHNORRVERIFY: *stackitemsp = 3; *flagsp = IGUANA_CRYPTOFLAG | IGUANA_POSTVERIFY; return "OP_CHECKSCHNORRVERIFY";
        case OP_CHECKPRIVATEKEY: *stackitemsp = 2; *flagsp = IGUANA_CRYPTOFLAG; return "OP_CHECKPRIVATEKEY";
        case OP_CHECKPRIVATEKEYVERIFY: *stackitemsp = 2; *flagsp = IGUANA_CRYPTOFLAG | IGUANA_POSTVERIFY; return "OP_CHECKPRIVATEKEYVERIFY";
            
            // expanson
        case OP_NOP1         : *flagsp = IGUANA_NOPFLAG; return "OP_NOP1";
        case OP_CHECKLOCKTIMEVERIFY: *stackitemsp = 1; return "OP_CHECKLOCKTIMEVERIFY";
        case OP_CHECKSEQUENCEVERIFY: *stackitemsp = 1; return "OP_CHECKSEQUENCEVERIFY";
        case OP_NOP4         : *flagsp = IGUANA_NOPFLAG; return "OP_NOP4";
        case OP_NOP5         : *flagsp = IGUANA_NOPFLAG; return "OP_NOP5";
        case OP_NOP6         : *flagsp = IGUANA_NOPFLAG; return "OP_NOP6";
        case OP_NOP7         : *flagsp = IGUANA_NOPFLAG; return "OP_NOP7";
        case OP_NOP8         : *flagsp = IGUANA_NOPFLAG; return "OP_NOP8";
        case OP_NOP9         : *flagsp = IGUANA_NOPFLAG; return "OP_NOP9";
        case OP_NOP10        : *flagsp = IGUANA_NOPFLAG; return "OP_NOP10";
            
        case OP_INVALIDOPCODE: return "OP_INVALIDOPCODE";
        default: return "OP_UNKNOWN";
    }
}

void iguana_optableinit()
{
    int32_t i,extralen; uint8_t stackitems,flags; char *opname; struct bitcoin_opcode *op;
    if ( OPTABLE == 0 )
    {
        for (i=0; i<0x100; i++)
            OPCODES[i] = "OP_UNKNOWN";
        for (i=0; i<0x100; i++)
        {
            extralen = stackitems = flags = 0;
            opname = (char *)get_opname(&stackitems,&flags,&extralen,i);
            if ( strcmp("OP_UNKNOWN",opname) != 0 )
            {
                op = calloc(1,sizeof(*op));
                HASH_ADD_KEYPTR(hh,OPTABLE,opname,strlen(opname),op);
                //printf("{%-16s %02x} ",opname,i);
                op->opcode = i;
                op->flags = flags;
                op->stackitems = stackitems;
                op->extralen = extralen;
                OPCODES[i] = (char *)op->hh.key;
                OPCODELENS[i] = (int32_t)strlen(OPCODES[i]);
            }
        }
        //printf("bitcoin opcodes\n");
    }
}

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

int32_t iguana_expandscript(char *asmstr,int32_t maxlen,uint8_t *script,int32_t scriptlen)
{
    int32_t len,n,j,i = 0; uint8_t opcode; uint32_t val,extraflag;
    iguana_optableinit();
    asmstr[0] = len = 0;
    while ( i < scriptlen )
    {
        val = extraflag = 0;
        opcode = script[i++];
        if ( opcode > 0 && opcode < 76 )
        {
            for (j=0; j<opcode; j++)
                sprintf(&asmstr[len],"%02x",script[i++]), len += 2;
        }
        else if ( opcode >= IGUANA_OP_1 && opcode <= IGUANA_OP_16 )
        {
            sprintf(&asmstr[len],"%d",opcode - IGUANA_OP_1 + 1);
            len += strlen(&asmstr[len]);
        }
        else if ( opcode == IGUANA_OP_0 )
        {
            strcpy(&asmstr[len],"OP_FALSE");
            len += 8;
        }
        else if ( opcode == IGUANA_OP_1NEGATE )
        {
            asmstr[len++] = '-';
            asmstr[len++] = '1';
        }
        else
        {
            //printf("dest.%p <- %p %02x\n",&asmstr[len],OPCODES[opcode],opcode);
            strcpy(&asmstr[len],OPCODES[opcode]);
            len += OPCODELENS[opcode];
        }
        if ( i < scriptlen )
            asmstr[len++] = ' ';
        if ( opcode == IGUANA_OP_PUSHDATA1 )
        {
            n = script[i++];
            for (j=0; j<n; j++)
                sprintf(&asmstr[len],"%02x",script[i++]), len += 2;
            extraflag = 1;
        }
        else if ( opcode == IGUANA_OP_PUSHDATA2 )
        {
            n = script[i++];
            n = (n << 8) | script[i++];
            if ( n+len < maxlen )
            {
                for (j=0; j<n; j++)
                    sprintf(&asmstr[len],"%02x",script[i++]), len += 2;
                extraflag = 1;
            } else return(-1);
        }
        else if ( opcode == IGUANA_OP_PUSHDATA4 )
        {
            n = script[i++];
            n = (n << 8) | script[i++];
            n = (n << 8) | script[i++];
            n = (n << 8) | script[i++];
            if ( n < IGUANA_MAXSCRIPTSIZE )
            {
                for (j=0; j<n; j++)
                    sprintf(&asmstr[len],"%02x",script[i++]), len += 2;
                extraflag = 1;
            } else return(-1);
        }
        if ( extraflag != 0 && i < scriptlen )
            asmstr[len++] = ' ';
    }
    asmstr[len] = 0;
    return(len);
}

static inline int32_t is_delim(int32_t c)
{
    if ( c == 0 || c == ' ' || c == '\t' || c == '\r' || c == '\n' )
        return(1);
    else return(0);
}

static struct iguana_stackdata iguana_pop(struct iguana_interpreter *stacks)
{
    struct iguana_stackdata Snum;
    Snum = stacks->stack[--stacks->stackdepth];
    memset(&stacks->stack[stacks->stackdepth],0,sizeof(Snum));
    return(Snum);
}

static int32_t iguana_altpush(struct iguana_interpreter *stacks,struct iguana_stackdata Snum)
{
    stacks->stack[2*IGUANA_MAXSTACKITEMS - ++stacks->altstackdepth] = Snum;
    return(stacks->altstackdepth);
}

static struct iguana_stackdata iguana_altpop(struct iguana_interpreter *stacks)
{
    struct iguana_stackdata Snum,*ptr;
    ptr = &stacks->stack[2*IGUANA_MAXSTACKITEMS - --stacks->altstackdepth];
    Snum = *ptr;
    memset(ptr,0,sizeof(Snum));
    return(Snum);
}

static struct iguana_stackdata iguana_clone(struct iguana_stackdata Snum)
{
    struct iguana_stackdata clone;
    clone = Snum;
    if ( Snum.data != 0 )
    {
        clone.data = malloc(Snum.size);
        memcpy(clone.data,Snum.data,Snum.size);
    }
    return(clone);
}

static int32_t iguana_isnonz(struct iguana_stackdata Snum)
{
    uint8_t *buf; int32_t i;
    if ( Snum.size == sizeof(int32_t) )
        return(Snum.U.val != 0);
    else if ( Snum.size == sizeof(int64_t) )
        return(Snum.U.val64 != 0);
    else if ( Snum.size == 20 )
        buf = Snum.U.rmd160;
    else if ( Snum.size == sizeof(bits256) )
        buf = Snum.U.hash2.bytes;
    else if ( Snum.size == 33 )
        buf = Snum.U.pubkey;
    else if ( Snum.size < 74 )
        buf = Snum.U.sig;
    else buf = Snum.data;
    for (i=0; i<Snum.size; i++)
        if ( buf[i] != 0 )
            return(1);
    return(0);
}

static int64_t iguana_num(struct iguana_stackdata Snum)
{
    if ( Snum.size == sizeof(int32_t) )
        return(Snum.U.val);
    else if ( Snum.size == sizeof(int64_t) )
        return(Snum.U.val64);
    else return(0);
}

static int32_t iguana_pushdata(struct iguana_interpreter *stacks,int64_t num64,uint8_t *numbuf,int32_t numlen)
{
    struct iguana_stackdata Snum; cJSON *item = 0; char tmpstr[2048]; int32_t num = (int32_t)num64;
    if ( stacks->lastpath[stacks->ifdepth] < 0 )
        return(0);
    //printf("PUSH.(%lld %p %d)\n",(long long)num64,numbuf,numlen);
    if ( stacks->maxstackdepth > 0 )
    {
        if ( numbuf != 0 )
        {
            int32_t i; for (i=0; i<numlen; i++)
                printf("%02x",numbuf[i]);
        } else printf("%lld",(long long)num64);
        printf(" PUSHDATA len.%d\n",numlen);
        if ( stacks->stackdepth < stacks->maxstackdepth )
        {
            if ( stacks->logarray != 0 )
                item = cJSON_CreateObject();
            memset(&Snum,0,sizeof(Snum));
            if ( numbuf != 0 )
            {
                if ( numlen <= sizeof(int32_t) )
                {
                    iguana_rwnum(1,(void *)&num,numlen,numbuf);
                    numlen = sizeof(num);
                    Snum.U.val = num;
                }
                else if ( numlen <= sizeof(int64_t) )
                {
                    iguana_rwnum(1,(void *)&num64,numlen,numbuf);
                    numlen = sizeof(num64);
                    Snum.U.val64 = num64;
                }
                else if ( numlen == 20 )
                    memcpy(Snum.U.rmd160,numbuf,20);
                else if ( numlen == sizeof(bits256) )
                    iguana_rwbignum(1,Snum.U.hash2.bytes,sizeof(Snum.U.hash2),numbuf);
                else if ( numlen == 33 )
                    memcpy(Snum.U.pubkey,numbuf,numlen);
                else if ( numlen < 74 )
                    memcpy(Snum.U.sig,numbuf,numlen);
                else
                {
                    Snum.data = malloc(numlen);
                    memcpy(Snum.data,numbuf,numlen);
                    if ( item != 0 )
                        jaddnum(item,"push",numlen);
                }
                Snum.size = numlen;
                if ( item != 0 )
                {
                    init_hexbytes_noT(tmpstr,numbuf,numlen);
                    jaddstr(item,"push",tmpstr);
                }
            }
            else if ( num64 <= 0xffffffff ) // what about negative numbers?
            {
                Snum.U.val = num, Snum.size = sizeof(num);
                if ( item != 0 )
                    jaddnum(item,"push",Snum.U.val);
            }
            else
            {
                Snum.U.val64 = num64, Snum.size = sizeof(num64);
                if ( item != 0 )
                    jaddnum(item,"push",Snum.U.val64);
            }
            if ( item != 0 )
            {
                jaddnum(item,"depth",stacks->stackdepth);
                if ( stacks->logarray != 0 )
                    jaddi(stacks->logarray,item);
            }
            stacks->stack[stacks->stackdepth++] = Snum;
        } else return(-1);
    } else stacks->stackdepth++;
    return(0);
}

int32_t iguana_databuf(uint8_t *databuf,struct iguana_stackdata Snum)
{
    if ( Snum.size == 4 )
        memcpy(databuf,&Snum.U.val,4);
    else if ( Snum.size == 8 )
        memcpy(databuf,&Snum.U.val64,8);
    else if ( Snum.size == 20 )
        memcpy(databuf,&Snum.U.rmd160,20);
    else if ( Snum.size == 32 )
        memcpy(databuf,&Snum.U.hash2.bytes,32);
    else if ( Snum.size == 33 )
        memcpy(databuf,&Snum.U.pubkey,33);
    else if ( Snum.size < 74 )
        memcpy(databuf,&Snum.U.sig,Snum.size);
    else memcpy(databuf,&Snum.data,Snum.size);
    return(Snum.size);
}

static int32_t iguana_cmp(struct iguana_stackdata *a,struct iguana_stackdata *b)
{
    if ( a->size == b->size )
    {
        if ( a->size == 4 )
            return(a->U.val != b->U.val);
        else if ( a->size == 8 )
            return(a->U.val64 != b->U.val64);
        else if ( a->size == 20 )
            return(memcmp(a->U.rmd160,b->U.rmd160,sizeof(a->U.rmd160)));
        else if ( a->size == 32 )
            return(memcmp(a->U.hash2.bytes,b->U.hash2.bytes,sizeof(a->U.hash2)));
        else if ( a->size == 33 )
            return(memcmp(a->U.pubkey,b->U.pubkey,33));
        else if ( a->size < 74 )
            return(memcmp(a->U.sig,b->U.sig,a->size));
        else return(memcmp(a->data,b->data,sizeof(a->size)));
    }
    return(-1);
}

static int32_t iguana_dataparse(struct iguana_interpreter *stacks,uint8_t *script,int32_t k,char *str,int32_t *lenp)
{
    int32_t n,c,len; char tmp[4];
    *lenp = 0;
    c = str[0];
    n = is_hexstr(str,0);
    if ( n > 0 )
    {
        if ( (n & 1) != 0 )
            len = (n+1) >> 1;
        else len = n >> 1;
        if ( len > 0 && len < 76 )
        {
            if ( len == 1 )
            {
                if ( n == 1 )
                {
                    tmp[0] = '0';
                    tmp[1] = c;
                    tmp[2] = 0;
                    decode_hex(&script[k],1,tmp), (*lenp) = 1;
                    iguana_pushdata(stacks,script[k],0,0);
                    if ( script[k] != 0 )
                        script[k++] += (IGUANA_OP_1 - 1);
                    return(k);
                }
                else if ( n == 2 && c == '1' && str[1] == '0' && is_delim(str[2]) != 0 )
                {
                    script[k++] = (IGUANA_OP_1 - 1) + 0x10, (*lenp) = 2;
                    iguana_pushdata(stacks,0x10,0,0);
                    return(k);
                }
                else if ( n == 2 && c == '8' && is_delim(str[2]) != 0 )
                {
                    if ( str[1] == '1' )
                    {
                        script[k++] = IGUANA_OP_1NEGATE, (*lenp) = 2;
                        iguana_pushdata(stacks,-1,0,0);
                        return(k);
                    }
                    else if ( str[1] == '0' )
                    {
                        script[k++] = IGUANA_OP_0, (*lenp) = 2;
                        iguana_pushdata(stacks,0,0,0);
                        return(k);
                    }
                }
            }
            if ( len != 0 )
                script[k++] = len;
        }
        else if ( len <= 0xff )
        {
            script[k++] = IGUANA_OP_PUSHDATA1;
            script[k++] = len;
        }
        else if ( len <= 0xffff )
        {
            if ( len <= MAX_SCRIPT_ELEMENT_SIZE )
            {
                script[k++] = IGUANA_OP_PUSHDATA2;
                script[k++] = (len & 0xff);
                script[k++] = ((len >> 8) & 0xff);
            }
            else
            {
                printf("len.%d > MAX_SCRIPT_ELEMENT_SIZE.%d, offset.%d\n",len,MAX_SCRIPT_ELEMENT_SIZE,k);
                return(-1);
            }
        }
        else
        {
            printf("len.%d > MAX_SCRIPT_ELEMENT_SIZE.%d, offset.%d\n",len,MAX_SCRIPT_ELEMENT_SIZE,k);
            return(-1);
        }
        if ( len != 0 )
        {
            uint8_t *numstart; int32_t numlen;
            numstart = &script[k], numlen = len;
            if ( (n & 1) != 0 )
            {
                tmp[0] = '0';
                tmp[1] = c;
                tmp[2] = 0;
                decode_hex(&script[k++],1,tmp), *lenp = 1;
                len--;
            }
            if ( len != 0 )
            {
                decode_hex(&script[k],len,str), (*lenp) += (len << 1);
                k += len;
            }
            iguana_pushdata(stacks,0,numstart,numlen);
        }
        return(k);
    }
    return(0);
}

void iguana_stack(struct iguana_interpreter *stacks,struct iguana_stackdata *args,int32_t num,char *pushstr,char *clonestr)
{
    int32_t i,c;
    while ( (c= *pushstr++) != 0 )
        stacks->stack[stacks->stackdepth++] = args[c - '0'];
    while ( (c= *clonestr++) != 0 )
        stacks->stack[stacks->stackdepth++] = iguana_clone(args[c - '0']);
    if ( num > 0 )
    {
        for (i=0; i<num; i++)
            memset(&args[i],0,sizeof(args[i]));
    }
}

int32_t iguana_checksig(void *ctx,struct iguana_stackdata pubkeyarg,struct iguana_stackdata sigarg,bits256 sigtxid)
{
    uint8_t pubkey[MAX_SCRIPT_ELEMENT_SIZE],sig[MAX_SCRIPT_ELEMENT_SIZE]; int32_t retval,plen,siglen;
    plen = iguana_databuf(pubkey,pubkeyarg);
    siglen = iguana_databuf(sig,sigarg);
    if ( bitcoin_pubkeylen(pubkey) == plen && plen > 0 && siglen > 0 && siglen < 74 )
    {
        if ( (retval= (bitcoin_verify(ctx,sig,siglen-1,sigtxid,pubkey,plen) == 0)) == 0 )
        {
        }
        if ( (0) )
        {
            int32_t i; char str[65];
            for (i=0; i<siglen; i++)
                printf("%02x",sig[i]);
            printf(" sig, ");
            for (i=0; i<plen; i++)
                printf("%02x",pubkey[i]);
            printf(" checksig sigtxid.%s, retval.%d\n",bits256_str(str,sigtxid),retval);
        }
        return(retval);
    }
    return(0);
}

int32_t iguana_checkprivatekey(void *ctx,struct iguana_stackdata pubkeyarg,struct iguana_stackdata privkeyarg)
{
    uint8_t pubkey[MAX_SCRIPT_ELEMENT_SIZE],privkey[MAX_SCRIPT_ELEMENT_SIZE],checkpub[33]; int32_t plen,privlen;
    plen = iguana_databuf(pubkey,pubkeyarg);
    privlen = iguana_databuf(privkey,privkeyarg);
    if ( bitcoin_pubkeylen(pubkey) == plen && plen > 0 && privlen == 32 )
    {
        bitcoin_pubkey33(ctx,checkpub,*(bits256 *)privkey);
        return(memcmp(checkpub,pubkey,33) == 0);
    }
    return(0);
}

int32_t iguana_checkschnorrsig(void *ctx,int64_t M,struct iguana_stackdata pubkeyarg,struct iguana_stackdata sigarg,bits256 sigtxid)
{
    /*uint8_t combined_pub[MAX_SCRIPT_ELEMENT_SIZE],sig[MAX_SCRIPT_ELEMENT_SIZE]; int32_t plen,siglen;
    plen = iguana_databuf(combined_pub,pubkeyarg);
    siglen = iguana_databuf(sig,sigarg);
    if ( bitcoin_pubkeylen(combined_pub) == 33 && siglen == 64 )
        return(bitcoin_schnorr_verify(ctx,sig,sigtxid,combined_pub,33) == 0);*/
    return(0);
}

int32_t iguana_checkmultisig(void *ctx,struct iguana_interpreter *stacks,int32_t M,int32_t N,bits256 txhash2)
{
    int32_t i,j=0,len,n,m,valid=0,numsigners = 0,siglens[MAX_PUBKEYS_PER_MULTISIG]; uint8_t pubkeys[MAX_PUBKEYS_PER_MULTISIG][MAX_SCRIPT_ELEMENT_SIZE],sigs[MAX_PUBKEYS_PER_MULTISIG][MAX_SCRIPT_ELEMENT_SIZE];
    if ( M <= N && N <= MAX_PUBKEYS_PER_MULTISIG )
    {
        if ( stacks->stackdepth <= 0 )
            return(0);
        n = (int32_t)iguana_num(iguana_pop(stacks));
        if ( n != N )
        {
            printf("iguana_checkmultisig n.%d != N.%d\n",n,N);
            return(0);
        }
        //printf("n.%d stackdepth.%d\n",n,stacks->stackdepth);
        for (i=0; i<N; i++)
        {
            if ( stacks->stackdepth <= 0 )
                return(0);
            len = iguana_databuf(pubkeys[i],iguana_pop(stacks));
            if ( len == bitcoin_pubkeylen(pubkeys[i]) )
            {
                numsigners++;
                //for (j=0; j<33; j++)
                //    printf("%02x",pubkeys[i][j]);
                //printf(" <- pubkey.[%d]\n",i);
            }
            else
            {
                printf("nonpubkey on stack\n");
                return(0);
                memcpy(sigs[0],pubkeys[i],len);
                siglens[0] = len;
                break;
            }
        }
        if ( stacks->stackdepth <= 0 )
            return(0);
        m = (int32_t)iguana_num(iguana_pop(stacks));
        //printf("m.%d stackdepth.%d\n",m,stacks->stackdepth);
        
        if ( m != M )
        {
            printf("iguana_checkmultisig m.%d != M.%d\n",m,M);
            return(0);
        }
        for (i=0; i<numsigners; i++)
        {
            if ( stacks->stackdepth <= 0 )
                return(0);
            siglens[i] = iguana_databuf(sigs[i],iguana_pop(stacks));
            if ( siglens[i] <= 0 || siglens[i] > 74 )
                break;
            //for (j=0; j<siglens[i]; j++)
            //    printf("%02x",sigs[i][j]);
            //printf(" <- sigs[%d]\n",i);
        }
        if ( i == numsigners )
        {
            //char str[65]; printf("depth.%d sigtxid.(%s)\n",stacks->stackdepth,bits256_str(str,txhash2));
            if ( stacks->stackdepth > 0 )
                iguana_pop(stacks); // for backward compatibility
            j = numsigners-1;
            for (i=numsigners-1; i>=0; i--)
            {
                for (; j>=0; j--)
                {
                    if ( bitcoin_verify(ctx,sigs[i],siglens[i]-1,txhash2,pubkeys[j],bitcoin_pubkeylen(pubkeys[j])) == 0 )
                    {
                        if ( ++valid >= M )
                            return(1);
                        j--;
                        break;
                    }
                }
            }
        }
    }
    printf("checkmultisig: valid.%d j.%d M.%d N.%d numsigners.%d\n",valid,j,M,N,numsigners);
    return(0);
}

#define LOCKTIME_THRESHOLD 500000000
int32_t iguana_checklocktimeverify(void *ctx,int64_t tx_lockval,uint32_t nSequence,struct iguana_stackdata Snum)
{
    int64_t nLockTime = iguana_num(Snum);
    if ( nLockTime < 0 || tx_lockval < 0 )
    {
        printf("CLTV.0 nLockTime.%lld tx_lockval.%lld\n",(long long)nLockTime,(long long)tx_lockval);
        return(-1);
    }
    else if ( ((tx_lockval < LOCKTIME_THRESHOLD && nLockTime < LOCKTIME_THRESHOLD) ||
               (tx_lockval >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD)) == 0 )
    {
        printf("CLTV.1 nLockTime.%lld tx_lockval.%lld\n",(long long)nLockTime,(long long)tx_lockval);
        return(-1);
    }
    else if ( nLockTime > tx_lockval )
    {
        printf("CLTV.2 nLockTime.%lld tx_lockval.%lld\n",(long long)nLockTime,(long long)tx_lockval);
        return(-1);
    }
    return(0);
}

int32_t iguana_checksequenceverify(void *ctx,int64_t nLockTime,uint32_t nSequence,struct iguana_stackdata Snum)
{
    return(0);
}

cJSON *iguana_spendasm(uint8_t *spendscript,int32_t spendlen)
{
    char asmstr[IGUANA_MAXSCRIPTSIZE*2+1]; cJSON *spendasm = cJSON_CreateObject();
    iguana_expandscript(asmstr,sizeof(asmstr),spendscript,spendlen);
    //int32_t i; for (i=0; i<spendlen; i++)
    //    printf("%02x",spendscript[i]);
    //printf(" -> (%s)\n",asmstr);
    jaddstr(spendasm,"interpreter",asmstr);
    return(spendasm);
}

int32_t bitcoin_assembler(void *ctx,cJSON *logarray,uint8_t script[IGUANA_MAXSCRIPTSIZE],cJSON *interpreter,int32_t interpret,int64_t nLockTime,struct vin_info *V)
{
    struct bitcoin_opcode *op; cJSON *array = 0; struct iguana_interpreter STACKS,*stacks = &STACKS;
    struct iguana_stackdata args[MAX_PUBKEYS_PER_MULTISIG];
    uint8_t databuf[MAX_SCRIPT_ELEMENT_SIZE]; char *asmstr,*str,*hexstr; cJSON *item;
    int32_t c,numops,dlen,plen,numvars,numused,numargs=0,i,j,k,n=0,len,datalen,errs=0; int64_t val;
    iguana_optableinit();
    if ( (asmstr= jstr(interpreter,"interpreter")) == 0 || asmstr[0] == 0 )
        return(0);
    if ( (numvars= juint(interpreter,"numvars")) > 0 )
    {
        if ( (array= jarray(&n,interpreter,"args")) == 0 || (interpret != 0 && n != numvars) )
            return(-2);
    }
    str = asmstr;
    if ( interpret != 0 )
    {
        stacks = calloc(1,sizeof(*stacks) + sizeof(*stacks->stack)*2*IGUANA_MAXSTACKITEMS);
        stacks->maxstackdepth = IGUANA_MAXSTACKITEMS;
        if ( (stacks->logarray= logarray) != 0 )
            item = cJSON_CreateObject();
        else item = 0;
        if ( V->M == 0 && V->N == 0 )
            V->N = V->M = 1;
        for (i=0; i<V->N; i++)
        {
            if ( V->signers[i].siglen != 0 )
            {
                iguana_pushdata(stacks,0,V->signers[i].sig,V->signers[i].siglen);
                if ( bitcoin_pubkeylen(V->signers[i].pubkey) <= 0 )
                {
                    printf("missing pubkey.[%d]\n",i);
                    free(stacks);
                    return(-1);
                }
                //printf("pushdata siglen.%d depth.%d\n",V->signers[i].siglen,stacks->stackdepth);
            }
        }
        for (i=0; i<V->N; i++)
        {
            if ( V->signers[i].siglen != 0 )
            {
                plen = bitcoin_pubkeylen(V->signers[i].pubkey);
                if ( V->suppress_pubkeys == 0 && (V->spendscript[0] != plen || V->spendscript[V->spendlen - 1] != IGUANA_OP_CHECKSIG || bitcoin_pubkeylen(&V->spendscript[1]) <= 0) )
                {
                    iguana_pushdata(stacks,0,V->signers[i].pubkey,plen);
                    //printf(">>>>>>>>> suppress.%d pushdata [%02x %02x] plen.%d depth.%d\n",V->suppress_pubkeys,V->signers[i].pubkey[0],V->signers[i].pubkey[1],plen,stacks->stackdepth);
                } // else printf("<<<<<<<<<< skip pubkey push %d script[0].%d spendlen.%d depth.%d\n",plen,V->spendscript[0],V->spendlen,stacks->stackdepth);
            }
        }
        if ( V->userdatalen != 0 )
        {
            len = 0;
            while ( len < V->userdatalen )
            {
                dlen = V->userdata[len++];
                if ( dlen > 0 && dlen < 76 )
                    iguana_pushdata(stacks,0,&V->userdata[len],dlen), len += dlen;
                else if ( dlen >= IGUANA_OP_1 && dlen <= IGUANA_OP_16 )
                {
                    dlen -= (IGUANA_OP_1 - 1);
                    iguana_pushdata(stacks,dlen,0,0);
                }
                else if ( dlen == IGUANA_OP_PUSHDATA1 )
                {
                    iguana_pushdata(stacks,V->userdata[len++],0,0);
                }
                else if ( dlen == IGUANA_OP_PUSHDATA2 )
                {
                    iguana_pushdata(stacks,V->userdata[len] + ((int32_t)V->userdata[len+1]<<8),0,0);
                    len += 2;
                }
                else if ( dlen == IGUANA_OP_0 )
                    iguana_pushdata(stacks,0,0,0);
                else if ( dlen == IGUANA_OP_1NEGATE )
                    iguana_pushdata(stacks,-1,0,0);
                else
                {
                    printf("invalid data opcode %02x\n",dlen);
                    free(stacks);
                    return(-1);
                }
                //printf("user data stackdepth.%d dlen.%d\n",stacks->stackdepth,dlen);
            }
            if ( len != V->userdatalen )
            {
                printf("mismatched userdatalen %d vs %d\n",len,V->userdatalen);
                free(stacks);
                return(-1);
            }
        }
        if ( item != 0 && stacks->logarray != 0 )
        {
            jaddstr(item,"spendasm",asmstr);
            jaddi(stacks->logarray,item);
        }
        if ( V->extras != 0 )
        {
            if ( (n= cJSON_GetArraySize(V->extras)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (hexstr= jstr(jitem(V->extras,i),0)) != 0 && (len= is_hexstr(hexstr,0)) > 0 )
                    {
                        len >>= 1;
                        decode_hex(databuf,len,hexstr);
                        iguana_pushdata(stacks,0,databuf,len);
                    }
                }
            }
        }
    } else memset(stacks,0,sizeof(*stacks));
    stacks->lastpath[0] = 1;
    k = numops = numused = 0;
    script[k] = 0;
    while ( (c= *str++) != 0 )
    {
        if ( is_delim(c) != 0 )
        {
            //if ( c == 0 )
            //    break;
            continue;
        }
        if ( c == '/' && *str == '/' ) // support //
            break;
        else if ( c == '-' && *str == '1' && is_delim(str[1]) != 0 )
        {
            script[k++] = IGUANA_OP_1NEGATE, str += 3; // OP_1NEGATE;
            iguana_pushdata(stacks,-1,0,0);
            continue;
        }
        else if ( c == '%' && *str == 's' )
        {
            str++;
            if ( numused < numvars && (hexstr= jstr(jitem(array,numused++),0)) != 0 )
            {
                if ( (n= iguana_dataparse(stacks,script,k,str,&len)) > 0 )
                {
                    k += n;
                    continue;
                }
            }
            printf("dataparse error.%d, numused.%d >= numvars.%d\n",n,numused,numvars);
            errs++;
            break;
        }
        else
        {
            str--;
            if ( (n= iguana_dataparse(stacks,script,k,str,&len)) > 0 )
            {
                k = n;
                str += len;
                continue;
            }
            else if ( n < 0 )
            {
                printf("dataparse negative n.%d\n",n);
                errs++;
                break;
            }
        }
        for (j=0; j<32; j++)
            if ( is_delim(str[j]) != 0 )
                break;
        if ( j == 32 )
        {
            printf("too long opcode.%s at offset.%ld\n",str,(long)str-(long)asmstr);
            errs++;
            break;
        }
        HASH_FIND(hh,OPTABLE,str,j,op);
        printf("{%s}\n",str);
        str += j;
        if ( op != 0 )
        {
            if ( numargs > 0 )
            {
                for (i=0; i<numargs; i++)
                    if ( args[i].data != 0 )
                    {
                        printf("filter free\n");
                        free(args[i].data);
                    }
            }
            memset(args,0,sizeof(args));
            numargs = 0;
            script[k++] = op->opcode;
            if ( (op->flags & IGUANA_CONTROLFLAG) != 0 )
            {
                //printf("control opcode depth.%d\n",stacks->stackdepth);
                switch ( op->opcode )
                {
                    case IGUANA_OP_IF: case IGUANA_OP_NOTIF:
                        if ( stacks->ifdepth >= IGUANA_MAXSTACKDEPTH )
                        {
                            printf("ifdepth.%d >= MAXSTACKDEPTH.%d\n",stacks->ifdepth,IGUANA_MAXSTACKDEPTH);
                            errs++;
                        }
                        else
                        {
                            if ( stacks->stackdepth <= 0 )
                            {
                                printf("if invalid stackdepth %d\n",stacks->stackdepth);
                                errs++;
                            }
                            else
                            {
                                args[0] = iguana_pop(stacks);
                                if ( iguana_isnonz(args[0]) == (op->opcode == IGUANA_OP_IF) )
                                {
                                    val = 1;
                                    //printf("OP_IF enabled depth.%d\n",stacks->stackdepth);
                                }
                                else
                                {
                                    val = -1;
                                    //printf("OP_IF disabled depth.%d\n",stacks->stackdepth);
                                }
                                stacks->lastpath[++stacks->ifdepth] = val;
                            }
                        }
                        break;
                    case IGUANA_OP_ELSE:
                        /*if ( stacks->stackdepth <= 0 )
                         {
                         printf("else invalid stackdepth %d\n",stacks->stackdepth);
                         errs++;
                         }
                         else*/
                    {
                        if ( stacks->ifdepth <= stacks->elsedepth )
                        {
                            printf("unhandled opcode.%02x stacks->ifdepth %d <= %d stacks->elsedepth\n",op->opcode,stacks->ifdepth,stacks->elsedepth);
                            errs++;
                        }
                        stacks->lastpath[stacks->ifdepth] *= -1;
                        //printf("OP_ELSE status.%d depth.%d\n",stacks->lastpath[stacks->ifdepth],stacks->stackdepth);
                    }
                        break;
                    case IGUANA_OP_ENDIF:
                        if ( stacks->ifdepth <= 0 )
                        {
                            printf("endif without if offset.%ld\n",(long)str-(long)asmstr);
                            errs++;
                        }
                        stacks->ifdepth--;
                        //printf("OP_ENDIF status.%d depth.%d\n",stacks->lastpath[stacks->ifdepth],stacks->stackdepth);
                        break;
                    case IGUANA_OP_VERIFY:
                        break;
                    case IGUANA_OP_RETURN:
                        iguana_pushdata(stacks,0,0,0);
                        errs++;
                        break;
                }
                if ( errs != 0 )
                    break;
                continue;
            }
            if ( stacks->lastpath[stacks->ifdepth] != 0 )
            {
                if ( stacks->lastpath[stacks->ifdepth] < 0 )
                {
                    //printf("SKIP opcode.%02x depth.%d\n",op->opcode,stacks->stackdepth);
                    if ( stacks->logarray )
                        jaddistr(stacks->logarray,"skip");
                    continue;
                }
                //printf("conditional opcode.%02x stackdepth.%d\n",op->opcode,stacks->stackdepth);
            }
            if ( op->opcode <= IGUANA_OP_16 || ++numops <= MAX_OPS_PER_SCRIPT )
            {
                if ( (op->flags & IGUANA_ALWAYSILLEGAL) != 0 )
                {
                    printf("disabled opcode.%s at offset.%ld\n",str,(long)str-(long)asmstr);
                    errs++;
                    break;
                }
                else if ( op->extralen > 0 )
                {
                    if ( is_delim(*str) != 0 )
                        str++;
                    if ( is_hexstr(str,0) != (op->extralen<<1) )
                    {
                        printf("expected extralen.%d of hex, got.(%s) at offset.%ld\n",op->extralen,str,(long)str-(long)asmstr);
                        errs++;
                        break;
                    }
                    decode_hex(&script[k],op->extralen,str), str += (op->extralen << 1);
                    if ( op->extralen == 1 )
                        iguana_pushdata(stacks,script[k],0,0);
                    else if ( op->extralen == 2 )
                        iguana_pushdata(stacks,script[k] + ((uint32_t)script[k]<<8),0,0);
                    k += op->extralen;
                    continue;
                }
                if ( interpret == 0 || V == 0 )
                    continue;
                if ( (op->flags & IGUANA_NOPFLAG) != 0 )
                    continue;
                if ( (numargs= op->stackitems) > 0 )
                {
                    if ( stacks->stackdepth < op->stackitems )
                    {
                        //printf("stackdepth.%d needed.%d (%s) at offset.%ld\n",stacks->stackdepth,op->stackitems,str,(long)str-(long)asmstr);
                        errs++;
                        break;
                    }
                    for (i=0; i<numargs; i++)
                        args[numargs - 1 - i] = iguana_pop(stacks);
                }
                //printf("%02x: numargs.%d depth.%d\n",op->opcode,numargs,stacks->stackdepth);
                if ( stacks->logarray != 0 )
                {
                    char tmpstr[1096];
                    item = cJSON_CreateObject();
                    array = cJSON_CreateArray();
                    for (i=0; i<numargs; i++)
                    {
                        datalen = iguana_databuf(databuf,args[i]);
                        init_hexbytes_noT(tmpstr,databuf,datalen);
                        jaddistr(array,tmpstr);
                    }
                    jadd(item,(char *)op->hh.key,array);
                    jaddi(stacks->logarray,item);
                }
                if ( (op->flags & IGUANA_EXECUTIONILLEGAL) != 0 )
                {
                    printf("opcode not allowed to run.%s at %ld\n",(char *)op->hh.key,(long)str-(long)asmstr);
                    errs++;
                    break;
                }
                else if ( op->opcode == IGUANA_OP_EQUALVERIFY || op->opcode == IGUANA_OP_EQUAL )
                {
                    if ( iguana_cmp(&args[0],&args[1]) == 0 )
                        iguana_pushdata(stacks,1,0,0);
                    else
                    {
                        iguana_pushdata(stacks,0,0,0);
                       for (i=0; i<args[0].size; i++)
                            printf("%02x",args[0].U.pubkey[i]);
                        printf(" <- args[0]\n");
                        for (i=0; i<args[1].size; i++)
                            printf("%02x",args[1].U.pubkey[i]);
                        printf(" <- args[1]\n");
                        printf("OP_EQUAL.%02x %d vs %d\n",op->opcode,args[0].size,args[1].size);
                    }
                }
                else if ( (op->flags & IGUANA_CRYPTOFLAG) != 0 )
                {
                    uint8_t rmd160[20],revdatabuf[MAX_SCRIPT_ELEMENT_SIZE]; bits256 hash;
                    datalen = iguana_databuf(databuf,args[0]);
                    for (i=0; i<datalen; i++)
                        revdatabuf[i] = databuf[datalen-1-i];
                    switch ( op->opcode )
                    {
                        case IGUANA_OP_RIPEMD160:
                            calc_rmd160(0,rmd160,databuf,datalen);
                            iguana_pushdata(stacks,0,rmd160,sizeof(rmd160));
                            break;
                        case IGUANA_OP_SHA1:
                            calc_sha1(0,rmd160,databuf,datalen);
                            iguana_pushdata(stacks,0,rmd160,sizeof(rmd160));
                            break;
                        case IGUANA_OP_HASH160:
                            /*if ( datalen == 32 )
                             {
                             revcalc_rmd160_sha256(rmd160,*(bits256 *)databuf);
                             printf("SPECIAL CASE REVERSE\n");
                             } else
                             for (i=0; i<32; i++)
                             printf("%02x",databuf[i]);
                             printf(" <- databuf\n");
                             for (i=0; i<32; i++)
                             printf("%02x",revdatabuf[i]);
                             printf(" <- revdatabuf\n");
                             calc_rmd160_sha256(rmd160,revdatabuf,datalen);
                             for (i=0; i<20; i++)
                             printf("%02x",rmd160[i]);
                             printf(" <- rmd160 revdatabuf\n");
                             revcalc_rmd160_sha256(rmd160,*(bits256 *)databuf);
                             for (i=0; i<20; i++)
                             printf("%02x",rmd160[i]);
                             printf(" <- rmd160 special\n");
                             calc_rmd160_sha256(rmd160,databuf,datalen);
                             for (i=0; i<20; i++)
                             printf("%02x",rmd160[i]);
                             printf(" <- rmd160 databuf\n");*/
                            if ( datalen == 32 )
                                calc_rmd160_sha256(rmd160,revdatabuf,datalen);
                            else calc_rmd160_sha256(rmd160,databuf,datalen);
                            iguana_pushdata(stacks,0,rmd160,sizeof(rmd160));
                            break;
                        case IGUANA_OP_SHA256:
                            vcalc_sha256(0,hash.bytes,databuf,datalen);
                            for (i=0; i<datalen; i++)
                                printf("%02x",databuf[i]);
                            printf(" -> sha256 %s\n",bits256_str(str,hash));
                            iguana_pushdata(stacks,0,hash.bytes,sizeof(hash));
                            break;
                        case IGUANA_OP_HASH256:
                            hash = bits256_doublesha256(0,databuf,datalen);
                            iguana_pushdata(stacks,0,hash.bytes,sizeof(hash));
                            break;
                        case IGUANA_OP_CHECKSIG: case IGUANA_OP_CHECKSIGVERIFY:
                            iguana_pushdata(stacks,iguana_checksig(ctx,args[1],args[0],V->sigtxid),0,0);
                            break;
                        case IGUANA_OP_CHECKMULTISIG: case IGUANA_OP_CHECKMULTISIGVERIFY:
                            iguana_pushdata(stacks,iguana_checkmultisig(ctx,stacks,V->M,V->N,V->sigtxid),0,0);
                            break;
                        case IGUANA_OP_CHECKSCHNORR: case IGUANA_OP_CHECKSCHNORRVERIFY:
                            iguana_pushdata(stacks,iguana_checkschnorrsig(ctx,iguana_num(args[2]),args[1],args[0],V->sigtxid),0,0);
                            break;
                        case IGUANA_OP_CHECKPRIVATEKEY: case IGUANA_OP_CHECKPRIVATEKEYVERIFY:
                            iguana_pushdata(stacks,iguana_checkprivatekey(ctx,args[1],args[0]),0,0);
                            break;
                    }
                }
                else if ( op->opcode == IGUANA_OP_CHECKLOCKTIMEVERIFY ) // former OP_NOP2
                {
                    if ( V->ignore_cltverr == 0 && iguana_checklocktimeverify(ctx,nLockTime,V->sequence,args[0]) < 0 )
                    {
                        iguana_stack(stacks,args,1,"0","");
                        errs++;
                        break;
                    }
                    iguana_stack(stacks,args,1,"0","");
                    continue;
                }
                else if ( op->opcode == IGUANA_OP_CHECKSEQUENCEVERIFY ) // former OP_NOP3
                {
                    if ( iguana_checksequenceverify(ctx,nLockTime,V->sequence,args[0]) < 0 )
                    {
                        iguana_stack(stacks,args,1,"0","");
                        errs++;
                        break;
                    }
                    iguana_stack(stacks,args,1,"0","");
                    continue;
                }
                else if ( (op->flags & IGUANA_STACKFLAG) != 0 )
                {
                    val = 0;
                    if ( op->opcode == IGUANA_OP_PICK || op->opcode == IGUANA_OP_ROLL )
                    {
                        if ( interpret != 0 && stacks->stackdepth < (val= iguana_num(args[0])) )
                        {
                            printf("stack not deep enough %d < %lld\n",stacks->stackdepth,(long long)iguana_num(args[0]));
                            errs++;
                            break;
                        }
                        if ( op->opcode == IGUANA_OP_PICK )
                        {
                            stacks->stack[stacks->stackdepth] = iguana_clone(stacks->stack[stacks->stackdepth - 1 - val]);
                            stacks->stackdepth++;
                        }
                        else
                        {
                            args[1] = stacks->stack[stacks->stackdepth - 1 - val];
                            for (i=(int32_t)(stacks->stackdepth-1-val); i<stacks->stackdepth-1; i++)
                                stacks->stack[i] = stacks->stack[i+1];
                            stacks->stack[stacks->stackdepth - 1] = args[1];
                        }
                    }
                    else
                    {
                        switch ( op->opcode )
                        {
                            case IGUANA_OP_TOALTSTACK:
                                if ( stacks->altstackdepth < stacks->maxstackdepth )
                                {
                                    iguana_altpush(stacks,args[0]);
                                    memset(&args[0],0,sizeof(args[0]));
                                }
                                else
                                {
                                    printf("altstack overflow %d vs %d\n",stacks->altstackdepth,stacks->maxstackdepth);
                                    errs++;
                                }
                                break;
                            case IGUANA_OP_FROMALTSTACK:
                                stacks->stack[stacks->stackdepth++] = iguana_altpop(stacks);
                                break;
                            case IGUANA_OP_DEPTH: iguana_pushdata(stacks,stacks->stackdepth,0,0); break;
                            case IGUANA_OP_DROP: case IGUANA_OP_2DROP: break;
                            case IGUANA_OP_3DUP:  iguana_stack(stacks,args,3,"012","012"); break;
                            case IGUANA_OP_2OVER: iguana_stack(stacks,args,4,"0123","01"); break;
                            case IGUANA_OP_2ROT:  iguana_stack(stacks,args,6,"234501",""); break;
                            case IGUANA_OP_2SWAP: iguana_stack(stacks,args,4,"2301",""); break;
                            case IGUANA_OP_IFDUP:
                                if ( iguana_isnonz(args[0]) != 0 )
                                    iguana_stack(stacks,args,0,"","0");
                                iguana_stack(stacks,args,1,"0","");
                                break;
                            case IGUANA_OP_DUP:   iguana_stack(stacks,args,1,"0","0"); break;
                            case IGUANA_OP_2DUP:  iguana_stack(stacks,args,2,"01","01"); break;
                            case IGUANA_OP_NIP:
                                if ( args[0].data != 0 )
                                    free(args[0].data);
                                iguana_stack(stacks,args,2,"1","");
                                break;
                            case IGUANA_OP_OVER:  iguana_stack(stacks,args,2,"01","0"); break;
                            case IGUANA_OP_ROT:   iguana_stack(stacks,args,3,"120",""); break;
                            case IGUANA_OP_SWAP:  iguana_stack(stacks,args,2,"10",""); break;
                            case IGUANA_OP_TUCK:  iguana_stack(stacks,args,2,"10","1"); break;
                        }
                    }
                }
                else if ( (op->flags & IGUANA_MATHFLAG) != 0 )
                {
                    int64_t numA=0,numB=0,numC=0;
                    for (i=0; i<op->stackitems; i++)
                    {
                        if ( args[i].size != sizeof(int32_t) )
                            break;
                        if ( i == 0 )
                            numA = iguana_num(args[i]);
                        else if ( i == 1 )
                            numB = iguana_num(args[i]);
                        else if ( i == 2 )
                            numC = iguana_num(args[i]);
                    }
                    if ( i != op->stackitems )
                    {
                        printf("math script non-int32_t arg[%d] of %d\n",i,op->stackitems);
                        errs++;
                        break;
                    }
                    switch ( op->opcode )
                    {
                        case IGUANA_OP_1ADD:   iguana_pushdata(stacks,numA + 1,0,0); break;
                        case IGUANA_OP_1SUB:   iguana_pushdata(stacks,numA - 1,0,0); break;
                        case IGUANA_OP_NEGATE: iguana_pushdata(stacks,-numA,0,0); break;
                        case IGUANA_OP_ABS:    iguana_pushdata(stacks,numA<0?-numA:numA,0,0); break;
                        case IGUANA_OP_NOT:    iguana_pushdata(stacks,numA == 0,0,0); break;
                        case IGUANA_OP_0NOTEQUAL: iguana_pushdata(stacks,numA != 0,0,0); break;
                        case IGUANA_OP_ADD:    iguana_pushdata(stacks,numA + numB,0,0); break;
                        case IGUANA_OP_SUB:    iguana_pushdata(stacks,numA - numB,0,0); break;
                        case IGUANA_OP_BOOLAND:iguana_pushdata(stacks,numA != 0 && numB != 0,0,0); break;
                        case IGUANA_OP_BOOLOR: iguana_pushdata(stacks,numA != 0 || numB != 0,0,0); break;
                        case IGUANA_OP_NUMEQUAL: case IGUANA_OP_NUMEQUALVERIFY:
                            iguana_pushdata(stacks,numA == numB,0,0); break;
                        case IGUANA_OP_NUMNOTEQUAL:iguana_pushdata(stacks,numA != numB,0,0); break;
                        case IGUANA_OP_LESSTHAN:   iguana_pushdata(stacks,numA < numB,0,0); break;
                        case IGUANA_OP_GREATERTHAN:iguana_pushdata(stacks,numA > numB,0,0); break;
                        case IGUANA_OP_LESSTHANOREQUAL:iguana_pushdata(stacks,numA <= numB,0,0); break;
                        case IGUANA_OP_GREATERTHANOREQUAL:iguana_pushdata(stacks,numA >= numB,0,0); break;
                        case IGUANA_OP_MIN: iguana_pushdata(stacks,numA <= numB ? numA : numB,0,0); break;
                        case IGUANA_OP_MAX: iguana_pushdata(stacks,numA >= numB ? numA : numB,0,0); break;
                        case IGUANA_OP_WITHIN: iguana_pushdata(stacks,numB <= numA && numA < numC,0,0); break;
                    }
                }
                else if ( op->opcode == IGUANA_OP_CODESEPARATOR )
                {
                    if ( stacks != 0 )
                        stacks->codeseparator = k;
                    continue;
                }
                else
                {
                    printf("unhandled opcode.%02x (%s)\n",op->opcode,str);
                    errs++;
                    break;
                }
                if ( (op->flags & IGUANA_POSTVERIFY) != 0 )
                {
                    if ( stacks->stackdepth < 1 )
                    {
                        printf("empty stack at offset.%ld\n",(long)str - (long)asmstr);
                        errs++;
                        break;
                    }
                    if ( iguana_isnonz(stacks->stack[stacks->stackdepth-1]) == 0 )
                        break;
                    iguana_pop(stacks);
                }
            }
            else
            {
                printf("too many ops opcode.%s at offset.%ld\n",str,(long)str - (long)asmstr);
                errs++;
                break;
            }
        }
        else
        {
            printf("unknown opcode.%s at offset.%ld\n",str,(long)str - (long)asmstr);
            errs++;
            break;
        }
    }
    if ( stacks != &STACKS )
    {
        if ( jobj(interpreter,"result") != 0 )
            jdelete(interpreter,"result");
        if ( stacks->stackdepth <= 0 )
        {
            errs++;
            printf("empty stack error\n");
            jaddstr(interpreter,"error","empty stack");
            jadd(interpreter,"result",jfalse());
        }
        else if ( iguana_isnonz(stacks->stack[--stacks->stackdepth]) != 0 )
        {
            //printf("Evaluate true, depth.%d errs.%d k.%d\n",stacks->stackdepth,errs,k);
            if ( errs == 0 )
                jadd(interpreter,"result",jtrue());
            else jadd(interpreter,"result",jfalse());
        }
        else
        {
            jadd(interpreter,"result",jfalse());
            printf("Evaluate FALSE, depth.%d errs.%d [0] size.%d val.%d\n",stacks->stackdepth,errs,stacks->stack[0].size,stacks->stack[0].U.val);
            errs++;
            if ( stacks->logarray != 0 )
                printf("LOG.(%s)\n\n",jprint(stacks->logarray,0));
        }
        if ( numargs > 0 )
        {
            for (i=0; i<numargs; i++)
                if ( args[i].data != 0 )
                {
                    printf("filter free\n");
                    //free(args[i].U.data);
                }
        }
        free(stacks);
    }
    if ( errs == 0 )
        return(k);
    else return(-errs);
}

/*void calc_rmd160_sha256(uint8_t rmd160[20],uint8_t *data,int32_t datalen)
{
    bits256 hash;
    vcalc_sha256(0,hash.bytes,data,datalen);
    calc_rmd160(0,rmd160,hash.bytes,sizeof(hash));
}*/

void revcalc_rmd160_sha256(uint8_t rmd160[20],bits256 revhash)
{
    bits256 hash; int32_t i;
    for (i=0; i<32; i++)
        hash.bytes[i] = revhash.bytes[31-i];
    calc_rmd160_sha256(rmd160,hash.bytes,sizeof(hash));
}

bits256 revcalc_sha256(bits256 revhash)
{
    bits256 hash,dest; int32_t i;
    for (i=0; i<32; i++)
        hash.bytes[i] = revhash.bytes[31-i];
    vcalc_sha256(0,dest.bytes,hash.bytes,sizeof(hash));
    return(dest);
}

int32_t bitcoin_pubkeyspend(uint8_t *script,int32_t n,uint8_t pubkey[66])
{
    int32_t plen = bitcoin_pubkeylen(pubkey);
    script[n++] = plen;
    memcpy(&script[n],pubkey,plen);
    n += plen;
    script[n++] = SCRIPT_OP_CHECKSIG;
    return(n);
}

int32_t bitcoin_p2shspend(uint8_t *script,int32_t n,uint8_t rmd160[20])
{
    script[n++] = SCRIPT_OP_HASH160;
    script[n++] = 0x14; memcpy(&script[n],rmd160,0x14); n += 0x14;
    script[n++] = SCRIPT_OP_EQUAL;
    return(n);
}

int32_t bitcoin_secret160verify(uint8_t *script,int32_t n,uint8_t secret160[20])
{
    script[n++] = IGUANA_OP_SIZE; // add SIZE 32 EQUALVERIFY
    script[n++] = 1;
    script[n++] = 32;
    script[n++] = SCRIPT_OP_EQUALVERIFY;
    script[n++] = SCRIPT_OP_HASH160;
    script[n++] = 0x14;
    memcpy(&script[n],secret160,0x14);
    n += 0x14;
    script[n++] = SCRIPT_OP_EQUALVERIFY;
    return(n);
}

int32_t bitcoin_secret256spend(uint8_t *script,int32_t n,bits256 secret)
{
    script[n++] = SCRIPT_OP_SHA256;
    script[n++] = 0x20;
    memcpy(&script[n],secret.bytes,0x20);
    n += 0x20;
    script[n++] = SCRIPT_OP_EQUAL;
    return(n);
}

// OP_DUP OP_HASH160 <hash of pubkey> OP_EQUALVERIFY OP_CHECKSIG
int32_t bitcoin_standardspend(uint8_t *script,int32_t n,uint8_t rmd160[20])
{
    script[n++] = SCRIPT_OP_DUP;
    script[n++] = SCRIPT_OP_HASH160;
    script[n++] = 0x14; memcpy(&script[n],rmd160,0x14); n += 0x14;
    script[n++] = SCRIPT_OP_EQUALVERIFY;
    script[n++] = SCRIPT_OP_CHECKSIG;
    return(n);
}

int32_t bitcoin_checklocktimeverify(uint8_t *script,int32_t n,uint32_t locktime)
{
    script[n++] = 4;
    script[n++] = locktime & 0xff, locktime >>= 8;
    script[n++] = locktime & 0xff, locktime >>= 8;
    script[n++] = locktime & 0xff, locktime >>= 8;
    script[n++] = locktime & 0xff;
    script[n++] = SCRIPT_OP_CHECKLOCKTIMEVERIFY;
    script[n++] = SCRIPT_OP_DROP;
    return(n);
}

int32_t bitcoin_timelockspend(uint8_t *script,int32_t n,uint8_t rmd160[20],uint32_t timestamp)
{
    n = bitcoin_checklocktimeverify(script,n,timestamp);
    n = bitcoin_standardspend(script,n,rmd160);
    return(n);
}

int32_t bitcoin_performancebond(uint8_t p2sh_rmd160[20],uint8_t *script,int32_t n,uint32_t unlocktimestamp,uint8_t *cltvpub33,uint8_t *elsepub33)
{
    script[n++] = SCRIPT_OP_IF;
    n = bitcoin_checklocktimeverify(script,n,unlocktimestamp);
    n = bitcoin_pubkeyspend(script,n,cltvpub33);
    script[n++] = SCRIPT_OP_ELSE;
    n = bitcoin_pubkeyspend(script,n,elsepub33);
    script[n++] = SCRIPT_OP_ENDIF;
    calc_rmd160_sha256(p2sh_rmd160,script,n);
    return(n);
}

int32_t bitcoin_MofNspendscript(uint8_t p2sh_rmd160[20],uint8_t *script,int32_t n,const struct vin_info *vp)
{
    int32_t i,plen;
    script[n++] = 0x50 + vp->M;
    for (i=0; i<vp->N; i++)
    {
        if ( (plen= bitcoin_pubkeylen(vp->signers[i].pubkey)) < 0 )
            return(-1);
        script[n++] = plen;
        memcpy(&script[n],vp->signers[i].pubkey,plen);
        n += plen;
    }
    script[n++] = 0x50 + vp->N;
    script[n++] = SCRIPT_OP_CHECKMULTISIG;
    calc_rmd160_sha256(p2sh_rmd160,script,n);
    return(n);
}

int32_t bitcoin_p2shscript(uint8_t *script,int32_t n,const uint8_t *p2shscript,const int32_t p2shlen)
{
    if ( p2shlen >= 0xfd )
    {
        script[n++] = 0x4d;
        script[n++] = (p2shlen & 0xff);
        script[n++] = ((p2shlen >> 8) & 0xff);
    }
    else if ( p2shlen > 76 )
    {
        script[n++] = 0x4c;
        script[n++] = p2shlen;
    } else script[n++] = p2shlen;
    memcpy(&script[n],p2shscript,p2shlen), n += p2shlen;
    return(n);
}

char *bitcoind_passthru(char *coinstr,char *serverport,char *userpass,char *method,char *params)
{
    if ( userpass[0] == 0 )
        return(clonestr("{\"error\":\"no rpcusername rpcpassword in coin.conf\"}"));
    return(bitcoind_RPC(0,coinstr,serverport,userpass,method,params,4));
}

char *bitcoind_passthrut(char *coinstr,char *serverport,char *userpass,char *method,char *params,int32_t timeout)
{
    return(bitcoind_RPC(0,coinstr,serverport,userpass,method,params,timeout));
}

bits256 bits256_calcaddrhash(char *symbol,uint8_t *serialized,int32_t  len)
{
    bits256 hash;
    memset(hash.bytes,0,sizeof(hash));
    if ( strcmp(symbol,"GRS") != 0 )
    {
        if ( strcmp(symbol,"SMART") != 0 )
            hash = bits256_doublesha256(0,serialized,len);
        else HashKeccak(hash.bytes,serialized,len);
    }
    else
    {
        HashGroestl(hash.bytes,serialized,len);
        /*int32_t i; char str[65];
        for (i=0; i<len; i++)
            printf("%02x",serialized[i]);
        printf(" HashGroestl %d -> %s\n",len,bits256_str(str,hash));*/
    }
    return(hash);
}

int32_t bitcoin_addr2rmd160(char *symbol,uint8_t taddr,uint8_t *addrtypep,uint8_t rmd160[20],char *coinaddr)
{
    bits256 hash; uint8_t *buf,_buf[26],data5[128],rmd21[21]; char prefixaddr[64],hrp[64]; int32_t len,len5,offset;
    *addrtypep = 0;
    memset(rmd160,0,20);
    if ( coinaddr == 0 || coinaddr[0] == 0 )
        return(0);
    if ( coinaddr[0] == '0' && coinaddr[1] == 'x' && is_hexstr(coinaddr+2,0) == 40 ) // for ETH
    {
        decode_hex(rmd160,20,coinaddr+2); // not rmd160 hash but hopefully close enough;
        return(20);
    }
    if ( strcmp(symbol,"BCH") == 0 )//&& strlen(coinaddr) == 42 )
    {
        char *bchprefix = "bitcoincash:";
        if ( strncmp(coinaddr,bchprefix,strlen(bchprefix)) != 0 )
        {
            strcpy(prefixaddr,bchprefix);
            strcat(prefixaddr,coinaddr);
        } else strcpy(prefixaddr,coinaddr);
        if ( bech32_decode(hrp,data5,&len5,prefixaddr) == 0 )
        {
            printf("bitcoin_addr2rmd160 bech32_decode error.(%s)\n",prefixaddr);
            return(0);
        }
        len = 0;
        if ( bech32_convert_bits(rmd21,&len,8,data5,len5,5,0) == 0 )
            printf("error converting data5\n");
        *addrtypep = rmd21[0] == 0 ? 0 : 5;
        memcpy(rmd160,&rmd21[1],20);
        return(20);
    }
    offset = 1 + (taddr != 0);
    memset(rmd160,0,20);
    *addrtypep = 0;
    buf = _buf;
    if ( (len= bitcoin_base58decode(buf,coinaddr)) >= 4 )
    {
        // validate with trailing hash, then remove hash
        hash = bits256_calcaddrhash(symbol,buf,20+offset);
        *addrtypep = (taddr == 0) ? *buf : buf[1];
        memcpy(rmd160,buf+offset,20);
        if ( (buf[20+offset]&0xff) == hash.bytes[31] && (buf[21+offset]&0xff) == hash.bytes[30] && (buf[22+offset]&0xff) == hash.bytes[29] && (buf[23+offset]&0xff) == hash.bytes[28] )
        {
            //printf("coinaddr.(%s) valid checksum addrtype.%02x\n",coinaddr,*addrtypep);
            return(20);
        }
        else if ( (strcmp(symbol,"GRS") == 0 || strcmp(symbol,"SMART") == 0) && (buf[20+offset]&0xff) == hash.bytes[0] && (buf[21+offset]&0xff) == hash.bytes[1] && (buf[22+offset]&0xff) == hash.bytes[2] && (buf[23+offset]&0xff) == hash.bytes[3] )
            return(20);
        else if ( strcmp(symbol,"BTC") != 0 || *addrtypep == 0 || *addrtypep == 5 )
        {
            int32_t i;
            //if ( len > 20 )
            //    hash = bits256_calcaddrhash(symbol,buf,len);
            for (i=0; i<len; i++)
                printf("%02x ",hash.bytes[i]);
            char str[65]; printf("\n%s addrtype.%d taddr.%02x checkhash.(%s) len.%d mismatch %02x %02x %02x %02x vs %02x %02x %02x %02x (%s)\n",symbol,*addrtypep,taddr,coinaddr,len,buf[len-1]&0xff,buf[len-2]&0xff,buf[len-3]&0xff,buf[len-4]&0xff,hash.bytes[31],hash.bytes[30],hash.bytes[29],hash.bytes[28],bits256_str(str,hash));
        }
    }
    return(0);
}

char *bitcoin_address(char *symbol,char *coinaddr,uint8_t taddr,uint8_t addrtype,uint8_t *pubkey_or_rmd160,int32_t len)
{
    static void *ctx;
    int32_t offset,i,len5; char prefixed[64]; uint8_t data[64],data5[64],bigpubkey[65]; bits256 hash; struct iguana_info *coin;
#ifndef NOTETOMIC
    if ( (coin= LP_coinfind(symbol)) != 0 && coin->etomic[0] != 0 )
    {
        if ( len == 20 )
        {
            strcpy(coinaddr,"0x");
            init_hexbytes_noT(coinaddr+2,pubkey_or_rmd160,20);
            return(coinaddr);
        }
        else if ( len == 33 || len == 65 )
        {
            if ( len == 33 )
            {
                if ( ctx == 0 )
                    ctx = bitcoin_ctx();
                bitcoin_expandcompressed(ctx,bigpubkey,pubkey_or_rmd160);
                LP_etomic_pub2addr(coinaddr,bigpubkey+1);
                /*for (i=0; i<33; i++)
                    printf("%02x",pubkey_or_rmd160[i]);
                printf(" compressed -> ");
                for (i=0; i<65; i++)
                    printf("%02x",bigpubkey[i]);
                printf(" -> %s\n",coinaddr);*/
            }
            else LP_etomic_pub2addr(coinaddr,pubkey_or_rmd160+1);
            return(coinaddr);
        }
    }
#endif
    coinaddr[0] = 0;
    offset = 1 + (taddr != 0);
    if ( len != 20 )
    {
        calc_rmd160_sha256(data+offset,pubkey_or_rmd160,len);
        //for (i=0; i<20; i++)
        //    printf("%02x",data[offset+i]);
        //printf(" rmd160\n");
    }
    else memcpy(data+offset,pubkey_or_rmd160,20);
    if ( strcmp(symbol,"BCH") == 0 )
    {
        len5 = 0;
        if ( addrtype == 0 )
            data[0] = (0 << 3);
        else data[0] = (1 << 3);
        bech32_convert_bits(data5,&len5,5,data,21,8,1);
        if ( bech32_encode(prefixed,"bitcoincash",data5,len5) == 0 )
            return(0);
        for (i=0; prefixed[i]!=0; i++)
            if ( prefixed[i] == ':' )
                break;
        if ( prefixed[i] != ':' )
            return(0);
        strcpy(coinaddr,&prefixed[i+1]);
        return(coinaddr);
    }
    if ( taddr != 0 )
    {
        data[0] = taddr;
        data[1] = addrtype;
    } else data[0] = addrtype;
    hash = bits256_calcaddrhash(symbol,data,20+offset);
    if ( strcmp(symbol,"GRS") != 0 && strcmp(symbol,"SMART") != 0 )
    {
        for (i=0; i<4; i++)
            data[20+offset+i] = hash.bytes[31-i];
    }
    else
    {
        for (i=0; i<4; i++)
            data[20+offset+i] = hash.bytes[i];
    }
    if ( (coinaddr= bitcoin_base58encode(coinaddr,data,24+offset)) != 0 )
    {
        //printf("coinaddr.%p %s\n",coinaddr,coinaddr!=0?coinaddr:"null");
    } else printf("null coinaddr taddr.%02x\n",taddr);
    return(coinaddr);
}

void bitcoin_priv2pub(void *ctx,char *symbol,uint8_t *pubkey33,char *coinaddr,bits256 privkey,uint8_t taddr,uint8_t addrtype)
{
    bits256 pub;
    memset(pubkey33,0,33);
    coinaddr[0] = 0;
    crypto_box_priv2pub(pub.bytes,privkey.bytes);
    bitcoin_pubkey33(ctx,pubkey33,privkey);
    bitcoin_address(symbol,coinaddr,taddr,addrtype,pubkey33,33);
}

int32_t bitcoin_validaddress(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,char *coinaddr)
{
    uint8_t rmd160[20],addrtype; char checkaddr[64],checkaddr2[64];
    if ( coinaddr == 0 || coinaddr[0] == 0 )
        return(-1);
    else if ( bitcoin_addr2rmd160(symbol,taddr,&addrtype,rmd160,coinaddr) < 0 )
    {
        printf("bitcoin_validaddress addr2rmd160 error\n");
        return(-1);
    }
    else if ( addrtype != pubtype && addrtype != p2shtype )
        return(-1);
    else if ( bitcoin_address(symbol,checkaddr,addrtype,taddr,rmd160,sizeof(rmd160)) != checkaddr || strcmp(checkaddr,coinaddr) != 0 )
    {
        bitcoin_addr2rmd160(symbol,taddr,&addrtype,rmd160,coinaddr);
        bitcoin_address(symbol,checkaddr2,addrtype,taddr,rmd160,sizeof(rmd160));
        printf("%s pubtype.%d taddr.%d bitcoin_validaddress checkaddr.%s != %s, checkaddr2.(%s)\n",symbol,pubtype,taddr,checkaddr,coinaddr,checkaddr2);
        return(-1);
    }
    return(0);
}

int32_t base58encode_checkbuf(char *symbol,uint8_t taddr,uint8_t addrtype,uint8_t *data,int32_t data_len)
{
    uint8_t i,offset; bits256 hash;
    offset = 1 + (taddr != 0);
    if ( taddr != 0 )
    {
        data[0] = taddr;
        data[1] = addrtype;
    } else data[0] = addrtype;
    //for (i=0; i<data_len+1; i++)
    //    printf("%02x",data[i]);
    //printf(" extpriv -> ");
    hash = bits256_calcaddrhash(symbol,data,(int32_t)data_len+offset);
    //for (i=0; i<32; i++)
    //    printf("%02x",hash.bytes[i]);
    //printf(" checkhash\n");
    if ( strcmp(symbol,"GRS") != 0 && strcmp(symbol,"SMART") != 0 )
    {
        for (i=0; i<4; i++)
            data[data_len+i+offset] = hash.bytes[31-i];
    }
    else
    {
        for (i=0; i<4; i++)
            data[data_len+i+offset] = hash.bytes[i];
    }
    return(data_len + 4 + offset);
}

int32_t bitcoin_wif2priv(char *symbol,uint8_t wiftaddr,uint8_t *addrtypep,bits256 *privkeyp,char *wifstr)
{
    int32_t offset,len = -1; bits256 hash; uint8_t buf[256],*ptr;
    offset = 1 + (wiftaddr != 0);
    memset(buf,0,sizeof(buf));
    memset(privkeyp,0,sizeof(*privkeyp));
    if ( (len= bitcoin_base58decode(buf,wifstr)) >= 4 )
    {
        if ( len >= 32+offset )
        {
            memcpy(privkeyp,buf+offset,32);
            /*if ( len > 32+offset )
                printf("wif %s: extra byte %d len.%d vs %d addrtype.%d\n",wifstr,buf[32+offset],len,32+offset,(wiftaddr == 0) ? buf[0] : buf[1]);
            else printf("%s is for uncompressed\n",wifstr);*/
        }
        else
        {
            printf("wif %s -> buf too short len.%d\n",wifstr,len);
            return(-1);
        }
        ptr = buf;
        hash = bits256_calcaddrhash(symbol,ptr,len - 4);
        *addrtypep = (wiftaddr == 0) ? *ptr : ptr[1];
        if ( (ptr[len - 4]&0xff) == hash.bytes[31] && (ptr[len - 3]&0xff) == hash.bytes[30] &&(ptr[len - 2]&0xff) == hash.bytes[29] && (ptr[len - 1]&0xff) == hash.bytes[28] )
        {
            //int32_t i; for (i=0; i<len; i++)
            //    printf("%02x ",ptr[i]);
            //printf(" ptr, hash.%02x %02x %02x %02x ",hash.bytes[28],hash.bytes[29],hash.bytes[30],hash.bytes[31]);
            //printf("wifstr.(%s) valid len.%d\n",wifstr,len);
            return(32);
        }
        else if ( (strcmp(symbol,"GRS") == 0 || strcmp(symbol,"SMART") == 0) && (ptr[len - 4]&0xff) == hash.bytes[0] && (ptr[len - 3]&0xff) == hash.bytes[1] &&(ptr[len - 2]&0xff) == hash.bytes[2] && (ptr[len - 1]&0xff) == hash.bytes[3] )
            return(32);
        else if ( 0 ) // gets errors when len is 37
        {
            int32_t i; for (i=0; i<len; i++)
                printf("%02x ",buf[i]);
            printf(" buf, hash.%02x %02x %02x %02x len.%d\n",hash.bytes[28],hash.bytes[29],hash.bytes[30],hash.bytes[31],len);
        }
    }
    return(-1);
}

int32_t bitcoin_wif2addr(void *ctx,char *symbol,uint8_t wiftaddr,uint8_t taddr,uint8_t pubtype,char *coinaddr,char *wifstr)
{
    bits256 privkey; int32_t len; uint8_t addrtype,pubkey33[33];
    if ( strcmp(symbol,"BCH") == 0 )
        symbol = "BTC";
    coinaddr[0] = 0;
    if ( (len= bitcoin_wif2priv(symbol,wiftaddr,&addrtype,&privkey,wifstr)) == sizeof(privkey) )
    {
        bitcoin_priv2pub(ctx,symbol,pubkey33,coinaddr,privkey,taddr,pubtype);
        //printf("priv2pub returns.(%s)\n",coinaddr);
        return(0);
    } else printf("wif2priv returns len.%d\n",len);
    return(-1);
}

int32_t bitcoin_priv2wif(char *symbol,uint8_t wiftaddr,char *wifstr,bits256 privkey,uint8_t addrtype)
{
    uint8_t data[128]; int32_t offset,len = 32;
    if ( wiftaddr != 0 )
    {
        //data[0] = wiftaddr;
        //data[1] = addrtype;
        offset = 2;
    }
    else
    {
        //data[0] = addrtype;
        offset = 1;
    }
    memcpy(data+offset,privkey.bytes,len);
    data[offset + len++] = 1;
    len = base58encode_checkbuf(symbol,wiftaddr,addrtype,data,len);
    if ( bitcoin_base58encode(wifstr,data,len) == 0 ) // skips last byte?
    {
        char str[65]; printf("error making wif from %s\n",bits256_str(str,privkey));
        return(-1);
    }
    if ( 0 )
    {
        uint8_t checktype; bits256 checkpriv; char str[65],str2[65];
        if ( bitcoin_wif2priv(symbol,wiftaddr,&checktype,&checkpriv,wifstr) == sizeof(bits256) )
        {
            if ( checktype != addrtype || bits256_cmp(checkpriv,privkey) != 0 )
                printf("(%s) -> wif.(%s) addrtype.%02x -> %02x (%s)\n",bits256_str(str,privkey),wifstr,addrtype,checktype,bits256_str(str2,checkpriv));
        }
    }
    return((int32_t)strlen(wifstr));
}

int32_t bitcoin_priv2wiflong(char *symbol,uint8_t wiftaddr,char *wifstr,bits256 privkey,uint8_t addrtype)
{
    uint8_t data[128]; int32_t offset,len = 32;
    offset = 1 + (wiftaddr != 0);
    memcpy(data+offset,privkey.bytes,sizeof(privkey));
    len = base58encode_checkbuf(symbol,wiftaddr,addrtype,data,len);
    if ( bitcoin_base58encode(wifstr,data,len) == 0 )
        return(-1);
    if ( 0 )
    {
        uint8_t checktype; bits256 checkpriv; char str[65],str2[65];
        if ( bitcoin_wif2priv(symbol,wiftaddr,&checktype,&checkpriv,wifstr) == sizeof(bits256) )
        {
            if ( checktype != addrtype || bits256_cmp(checkpriv,privkey) != 0 )
                printf("(%s) -> wif.(%s) addrtype.%02x -> %02x (%s)\n",bits256_str(str,privkey),wifstr,addrtype,checktype,bits256_str(str2,checkpriv));
        }
    }
    return((int32_t)strlen(wifstr));
}

char *_setVsigner(char *symbol,uint8_t wiftaddr,uint8_t pubtype,struct vin_info *V,int32_t ind,char *pubstr,char *wifstr)
{
    uint8_t addrtype;
    decode_hex(V->signers[ind].pubkey,(int32_t)strlen(pubstr)/2,pubstr);
    bitcoin_wif2priv(symbol,wiftaddr,&addrtype,&V->signers[ind].privkey,wifstr);
    if ( addrtype != pubtype )
        return(clonestr("{\"error\":\"invalid wifA\"}"));
    else return(0);
}

uint8_t iguana_addrtype(uint8_t pubtype,uint8_t p2shtype,uint8_t script_type)
{
    if ( script_type == IGUANA_SCRIPT_76A988AC || script_type == IGUANA_SCRIPT_AC || script_type == IGUANA_SCRIPT_76AC )
        return(pubtype);
    else
    {
        //printf("P2SH type.%d\n",script_type);
        return(p2shtype);
    }
}

int32_t iguana_scriptgen(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,int32_t *Mp,int32_t *nump,char *coinaddr,uint8_t *script,char *asmstr,uint8_t rmd160[20],uint8_t type,const struct vin_info *vp,int32_t txi)
{
    uint8_t addrtype; char rmd160str[41],pubkeystr[256]; int32_t plen,i,m,n,flag = 0,scriptlen = 0;
    m = n = 0;
    if ( asmstr != 0 )
        asmstr[0] = 0;
    addrtype = iguana_addrtype(pubtype,p2shtype,type);
    if ( type == IGUANA_SCRIPT_76A988AC || type == IGUANA_SCRIPT_AC || type == IGUANA_SCRIPT_76AC || type == IGUANA_SCRIPT_P2SH )
    {
        init_hexbytes_noT(rmd160str,rmd160,20);
        bitcoin_address(symbol,coinaddr,taddr,addrtype,rmd160,20);
    }
    switch ( type )
    {
        case IGUANA_SCRIPT_NULL:
            if ( asmstr != 0 )
                strcpy(asmstr,txi == 0 ? "coinbase " : "PoSbase ");
            flag++;
            coinaddr[0] = 0;
            break;
        case IGUANA_SCRIPT_76AC:
        case IGUANA_SCRIPT_AC:
            if ( (plen= bitcoin_pubkeylen(vp->signers[0].pubkey)) < 0 )
                return(0);
            init_hexbytes_noT(pubkeystr,(uint8_t *)vp->signers[0].pubkey,plen);
            if ( asmstr != 0 )
            {
                if ( type == IGUANA_SCRIPT_76AC )
                    strcpy(asmstr,"OP_DUP ");
                sprintf(asmstr + strlen(asmstr),"%s OP_CHECKSIG // %s",pubkeystr,coinaddr);
            }
            if ( type == IGUANA_SCRIPT_76AC )
                script[scriptlen++] = 0x76;
            scriptlen = bitcoin_pubkeyspend(script,scriptlen,(uint8_t *)vp->signers[0].pubkey);
            //printf("[%02x] type.%d scriptlen.%d\n",vp->signers[0].pubkey[0],type,scriptlen);
            break;
        case IGUANA_SCRIPT_76A988AC:
            if ( asmstr != 0 )
                sprintf(asmstr,"OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG // %s",rmd160str,coinaddr);
            scriptlen = bitcoin_standardspend(script,0,rmd160);
            break;
        case IGUANA_SCRIPT_P2SH:
            if ( asmstr != 0 )
                sprintf(asmstr,"OP_HASH160 %s OP_EQUAL // %s",rmd160str,coinaddr);
            scriptlen = bitcoin_p2shspend(script,0,rmd160);
            break;
        case IGUANA_SCRIPT_OPRETURN:
            if ( asmstr != 0 )
                strcpy(asmstr,"OP_RETURN ");
            bitcoin_address(symbol,coinaddr,taddr,addrtype,(uint8_t *)&vp->spendscript[0],vp->spendlen);
            flag++;
            break;
        case IGUANA_SCRIPT_3of3: m = 3, n = 3; break;
        case IGUANA_SCRIPT_2of3: m = 2, n = 3; break;
        case IGUANA_SCRIPT_1of3: m = 1, n = 3; break;
        case IGUANA_SCRIPT_2of2: m = 2, n = 2; break;
        case IGUANA_SCRIPT_1of2: m = 1, n = 2; break;
        case IGUANA_SCRIPT_1of1: m = 1, n = 1; break;
        case IGUANA_SCRIPT_MSIG: m = vp->M, n = vp->N; break;
        case IGUANA_SCRIPT_DATA:
            if ( asmstr != 0 )
                strcpy(asmstr,"DATA ONLY");
            bitcoin_address(symbol,coinaddr,taddr,addrtype,(uint8_t *)&vp->spendscript[0],vp->spendlen);
            flag++;
            break;
        case IGUANA_SCRIPT_STRANGE:
            if ( asmstr != 0 )
                strcpy(asmstr,"STRANGE SCRIPT ");
            bitcoin_address(symbol,coinaddr,taddr,addrtype,(uint8_t *)&vp->spendscript[0],vp->spendlen);
            flag++;
            break;
        default: break;//printf("unexpected script type.%d\n",type); break;
    }
    if ( n > 0 )
    {
        scriptlen = bitcoin_MofNspendscript(rmd160,script,0,vp);
        bitcoin_address(symbol,coinaddr,taddr,p2shtype,script,scriptlen);
        if ( asmstr != 0 )
        {
            sprintf(asmstr,"%d ",m);
            for (i=0; i<n; i++)
            {
                if ( (plen= bitcoin_pubkeylen(vp->signers[i].pubkey)) > 0 )
                {
                    init_hexbytes_noT(asmstr + strlen(asmstr),(uint8_t *)vp->signers[i].pubkey,plen);
                    if ( asmstr != 0 )
                        strcat(asmstr," ");
                }
                else if ( asmstr != 0 )
                    strcat(asmstr,"NOPUBKEY ");
                sprintf(asmstr + strlen(asmstr),"%d // M.%d of N.%d [",n,m,n);
                for (i=0; i<n; i++)
                    sprintf(asmstr + strlen(asmstr),"%s%s",vp->signers[i].coinaddr,i<n-1?" ":"");
            }
            strcat(asmstr,"]\n");
        }
    }
    if ( flag != 0 && asmstr != 0 && vp->spendlen > 0 )
        init_hexbytes_noT(asmstr + strlen(asmstr),(uint8_t *)vp->spendscript,vp->spendlen);
    *Mp = m, *nump = n;
    return(scriptlen);
}

int32_t bitcoin_scriptget(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,uint32_t *hashtypep,uint32_t *sigsizep,uint32_t *pubkeysizep,uint8_t **userdatap,uint32_t *userdatalenp,struct vin_info *vp,uint8_t *scriptsig,int32_t len,int32_t spendtype,int32_t zcash)
{
    int32_t j,n,siglen,plen; uint8_t *p2shscript;
    j = n = 0;
    *userdatap = 0;
    *userdatalenp = *pubkeysizep = *sigsizep = 0;
    *hashtypep = LP_sighash(symbol,zcash);
    while ( (siglen= scriptsig[n]) >= 70 && siglen <= 73 && n+siglen < len && j < 16 )
    {
        vp->signers[j].siglen = siglen;
        memcpy(vp->signers[j].sig,&scriptsig[n+1],siglen);
        if ( j == 0 )
            *hashtypep = vp->signers[j].sig[siglen-1];
        else if ( vp->signers[j].sig[siglen-1] != (*hashtypep & (~SIGHASH_FORKID)) )
        {
            //printf("SIGHASH.%d  mismatch %d vs %d\n",j,vp->signers[j].sig[siglen-1],*hashtypep);
            break;
        }
        (*sigsizep) += siglen;
        //printf("sigsize %d [%02x]\n",*sigsizep,vp->signers[j].sig[siglen-1]);
        n += (siglen + 1);
        j++;
        if ( spendtype == 0 && j > 1 )
            spendtype = IGUANA_SCRIPT_MSIG;
    }
    vp->numsigs = j;
    vp->type = spendtype;
    if ( j == 0 )
    {
        //*userdatalenp = len;
        vp->spendlen = len;
        return(vp->spendlen);
    }
    j = 0;
    while ( ((plen= scriptsig[n]) == 33 || plen == 65) && j < 16 && plen+n <= len )
    {
        memcpy(vp->signers[j].pubkey,&scriptsig[n+1],plen);
        calc_rmd160_sha256(vp->signers[j].rmd160,vp->signers[j].pubkey,plen);
        if ( j == 0 )
            memcpy(vp->rmd160,vp->signers[j].rmd160,20);
        n += (plen + 1);
        (*pubkeysizep) += plen;
        j++;
    }
    vp->numpubkeys = j;
    *userdatap = &scriptsig[n];
    if ( len > n )
        *userdatalenp = (len - n);
    p2shscript = 0;
    while ( n < len )
    {
        if ( n+2 < len && (scriptsig[n] == 0x4c || scriptsig[n] == 0x4d) )
        {
            if ( scriptsig[n] == 0x4c )
                vp->p2shlen = scriptsig[n+1], n += 2;
            else vp->p2shlen = ((uint32_t)scriptsig[n+1] + ((uint32_t)scriptsig[n+2] << 8)), n += 3;
            //printf("p2sh opcode.%02x %02x %02x scriptlen.%d\n",scriptsig[n],scriptsig[n+1],scriptsig[n+2],vp->p2shlen);
            if ( vp->p2shlen < IGUANA_MAXSCRIPTSIZE && n+vp->p2shlen <= len )
            {
                p2shscript = &scriptsig[n];
                memcpy(vp->p2shscript,&scriptsig[n],vp->p2shlen);
                n += vp->p2shlen;
                vp->type = IGUANA_SCRIPT_P2SH;
            } else vp->p2shlen = 0;
        }
    }
    if ( *userdatap == p2shscript )
        *userdatap = 0;
    vp->spendlen = iguana_scriptgen(symbol,taddr,pubtype,p2shtype,&vp->M,&vp->N,vp->coinaddr,vp->spendscript,0,vp->rmd160,vp->type,(const struct vin_info *)vp,vp->vin.prev_vout);
    return(vp->spendlen);
}

int32_t _iguana_calcrmd160(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,struct vin_info *vp)
{
    static uint8_t zero_rmd160[20];
    char hexstr[8192]; uint8_t *script,type; int32_t i,n,m,plen;
    if ( vp->N == 0 )
        vp->N = 1;
    if ( vp->M == 0 )
        vp->M = 1;
    type = IGUANA_SCRIPT_STRANGE;
    init_hexbytes_noT(hexstr,vp->spendscript,vp->spendlen);
    //char str[65]; printf("script.(%s).%d in %s len.%d plen.%d spendlen.%d cmp.%d\n",hexstr,vp->spendlen,bits256_str(str,vp->vin.prev_hash),vp->spendlen,bitcoin_pubkeylen(&vp->spendscript[1]),vp->spendlen,vp->spendscript[vp->spendlen-1] == SCRIPT_OP_CHECKSIG);
    if ( vp->spendlen == 0 )
    {
        if ( zero_rmd160[0] == 0 )
        {
            calc_rmd160_sha256(zero_rmd160,vp->spendscript,vp->spendlen);
            //vcalc_sha256(0,sha256,vp->spendscript,vp->spendlen); // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            //calc_rmd160(0,zero_rmd160,sha256,sizeof(sha256)); // b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
            init_hexbytes_noT(hexstr,zero_rmd160,20);
        }
        memcpy(vp->rmd160,zero_rmd160,sizeof(zero_rmd160));
        return(IGUANA_SCRIPT_NULL);
    }
    else if ( vp->spendscript[0] == SCRIPT_OP_RETURN )
        type = IGUANA_SCRIPT_OPRETURN;
    else if ( vp->spendscript[0] == SCRIPT_OP_DUP && vp->spendscript[1] == SCRIPT_OP_HASH160 && vp->spendscript[2] == 20 && vp->spendscript[vp->spendscript[2]+3] == SCRIPT_OP_EQUALVERIFY && vp->spendscript[vp->spendscript[2]+4] == SCRIPT_OP_CHECKSIG )
    {
        //printf("IGUANA_SCRIPT_76A988AC plen.%d vs %d vp->spendlen\n",vp->spendscript[2]+4,vp->spendlen);
        // 76a9145f69cb73016264270dae9f65c51f60d0e4d6fd4488ac
        memcpy(vp->rmd160,&vp->spendscript[3],20);
        if ( (plen= vp->spendscript[2]+5) != vp->spendlen )
        {
            return(IGUANA_SCRIPT_STRANGE);
            /*while ( plen < vp->spendlen )
             if ( vp->spendscript[plen++] != 0x61 ) // nop
             return(IGUANA_SCRIPT_STRANGE);*/
        }
        return(IGUANA_SCRIPT_76A988AC);
    }
    // 21035f1321ed17d387e4433b2fa229c53616057964af065f98bfcae2233c5108055eac
    else if ( vp->spendscript[0] == SCRIPT_OP_DUP && (plen= bitcoin_pubkeylen(&vp->spendscript[2])) > 0 && vp->spendscript[vp->spendlen-1] == SCRIPT_OP_CHECKSIG && vp->spendscript[0] == plen && vp->spendlen == plen+3 )
    {
        memcpy(vp->signers[0].pubkey,&vp->spendscript[2],plen);
        calc_rmd160_sha256(vp->rmd160,vp->signers[0].pubkey,plen);
        //printf("found IGUANA_SCRIPT_76AC\n");
        return(IGUANA_SCRIPT_76AC);
    }
    else if ( (plen= bitcoin_pubkeylen(&vp->spendscript[1])) > 0 && vp->spendscript[vp->spendlen-1] == SCRIPT_OP_CHECKSIG && vp->spendscript[0] == plen && vp->spendlen == plen+2 )
    {
        memcpy(vp->signers[0].pubkey,&vp->spendscript[1],plen);
        calc_rmd160_sha256(vp->rmd160,vp->signers[0].pubkey,plen);
        //printf("found IGUANA_SCRIPT_AC\n");
        return(IGUANA_SCRIPT_AC);
    }
    else if ( vp->spendscript[0] == SCRIPT_OP_HASH160 && vp->spendscript[1] == 0x14 && vp->spendlen == 23 && vp->spendscript[22] == SCRIPT_OP_EQUAL )
    {
        memcpy(vp->rmd160,vp->spendscript+2,20);
        return(IGUANA_SCRIPT_P2SH);
    }
    else if ( vp->spendlen > 34 && vp->spendscript[vp->spendlen-1] == SCRIPT_OP_CHECKMULTISIG && (n= vp->spendscript[vp->spendlen-2]) >= 0x51 && n <= 0x60 && (m= vp->spendscript[0]) >= 0x51 && m <= n ) // m of n multisig
    {
        m -= 0x50, n -= 0x50;
        script = vp->spendscript+1;
        for (i=0; i<n; i++,script += plen)
        {
            plen = *script++;
            if ( bitcoin_pubkeylen(script) != plen )
            {
                static int32_t counter;
                if ( counter++ < 3 )
                    printf("multisig.%d of %d: invalid pubkey[%02x] len %d\n",i,n,script[0],bitcoin_pubkeylen(script));
                return(-1);
            }
            memcpy(vp->signers[i].pubkey,script,plen);
            calc_rmd160_sha256(vp->signers[i].rmd160,vp->signers[i].pubkey,plen);
            bitcoin_address(symbol,vp->signers[i].coinaddr,taddr,pubtype,vp->signers[i].pubkey,plen);
        }
        if ( (int32_t)((long)script - (long)vp->spendscript) == vp->spendlen-2 )
        {
            vp->N = n;
            vp->M = m;
            //printf("M.%d N.%d\n",m,n);
        }
        calc_rmd160_sha256(vp->rmd160,vp->spendscript,vp->spendlen);
        if ( n == 3 )
        {
            if ( m == 3 )
                return(IGUANA_SCRIPT_3of3);
            else if ( m == 2 )
                return(IGUANA_SCRIPT_2of3);
            else if ( m == 1 )
                return(IGUANA_SCRIPT_1of3);
        }
        else if ( n == 2 )
        {
            if ( m == 2 )
                return(IGUANA_SCRIPT_2of2);
            else if ( m == 1 )
                return(IGUANA_SCRIPT_1of2);
        }
        else if ( m == 1 && n == 1 )
            return(IGUANA_SCRIPT_1of1);
        //printf("strange msig M.%d of N.%d\n",m,n);
        return(IGUANA_SCRIPT_MSIG);
    }
    else if ( vp->spendlen == vp->spendscript[0]+1 )
    {
        //printf("just data.%d\n",vp->spendlen);
        memcpy(vp->rmd160,zero_rmd160,sizeof(zero_rmd160));
        return(IGUANA_SCRIPT_DATA);
    }
    if ( type != IGUANA_SCRIPT_OPRETURN && type != IGUANA_SCRIPT_DATA )
    {
        if ( vp->spendlen > 0 && vp->spendlen < sizeof(hexstr)/2-1 )
        {
            static FILE *fp;
            init_hexbytes_noT(hexstr,vp->spendscript,vp->spendlen);
            //char str[65]; printf("unparsed script.(%s).%d in %s len.%d\n",hexstr,vp->spendlen,bits256_str(str,vp->vin.prev_hash),vp->spendlen);
            if ( 1 && fp == 0 )
                fp = fopen("unparsed.txt","w");
            if ( fp != 0 )
                fprintf(fp,"%s\n",hexstr), fflush(fp);
        } else sprintf(hexstr,"pkscript overflowed %ld\n",(long)sizeof(hexstr));
    }
    calc_rmd160_sha256(vp->rmd160,vp->spendscript,vp->spendlen);
    return(type);
}

int32_t iguana_calcrmd160(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,char *asmstr,struct vin_info *vp,uint8_t *pk_script,int32_t pk_scriptlen,bits256 debugtxid,int32_t vout,uint32_t sequence)
{
    int32_t scriptlen; uint8_t script[IGUANA_MAXSCRIPTSIZE];
    memset(vp,0,sizeof(*vp));
    vp->vin.prev_hash = debugtxid, vp->vin.prev_vout = vout;
    vp->spendlen = pk_scriptlen;
    vp->vin.sequence = sequence;
    memcpy(vp->spendscript,pk_script,pk_scriptlen);
    if ( (vp->type= _iguana_calcrmd160(symbol,taddr,pubtype,p2shtype,vp)) >= 0 )
    {
        scriptlen = iguana_scriptgen(symbol,taddr,pubtype,p2shtype,&vp->M,&vp->N,vp->coinaddr,script,asmstr,vp->rmd160,vp->type,(const struct vin_info *)vp,vout);
        if ( vp->M == 0 && vp->N == 0 )
        {
            vp->M = vp->N = 1;
            strcpy(vp->signers[0].coinaddr,vp->coinaddr);
            memcpy(vp->signers[0].rmd160,vp->rmd160,20);
        }
        if ( scriptlen != pk_scriptlen || (scriptlen != 0 && memcmp(script,pk_script,scriptlen) != 0) )
        {
            if ( vp->type != IGUANA_SCRIPT_OPRETURN && vp->type != IGUANA_SCRIPT_DATA && vp->type != IGUANA_SCRIPT_STRANGE )
            {
                int32_t i;
                printf("\n--------------------\n");
                for (i=0; i<scriptlen; i++)
                    printf("%02x ",script[i]);
                printf("script.%d\n",scriptlen);
                for (i=0; i<pk_scriptlen; i++)
                    printf("%02x ",pk_script[i]);
                printf("original script.%d\n",pk_scriptlen);
                printf("iguana_calcrmd160 type.%d error regenerating scriptlen.%d vs %d\n\n",vp->type,scriptlen,pk_scriptlen);
            }
        }
    }
    return(vp->type);
}

cJSON *bitcoin_txscript(char *asmstr,char **vardata,int32_t numvars)
{
    int32_t i; cJSON *scriptjson,*array;
    scriptjson = cJSON_CreateObject();
    if ( asmstr != 0 )
        jaddstr(scriptjson,"asm",asmstr);
    jaddnum(scriptjson,"numvars",numvars);
    if ( numvars > 0 )
    {
        array = cJSON_CreateArray();
        for (i=0; i<numvars; i++)
            jaddistr(array,vardata[i]);
        jadd(scriptjson,"args",array);
    }
    return(scriptjson);
}

cJSON *iguana_scriptpubkeys(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,uint8_t *script,int32_t scriptlen,bits256 txid,int16_t vout,uint32_t sequenceid)
{
    int32_t type,i,n,plen; struct vin_info V; cJSON *pubkeys; char pubkeystr[256];
    pubkeys = cJSON_CreateArray();
    if ( (type= iguana_calcrmd160(symbol,taddr,pubtype,p2shtype,0,&V,script,scriptlen,txid,vout,sequenceid)) >= 0 )
    {
        if ( (n= V.N) == 0 )
            n = 1;
        for (i=0; i<n; i++)
        {
            if ( (plen= bitcoin_pubkeylen(V.signers[i].pubkey)) > 0 )
                init_hexbytes_noT(pubkeystr,V.signers[i].pubkey,plen);
            else pubkeystr[0] = 0;
            jaddistr(pubkeys,pubkeystr);
        }
    }
    return(pubkeys);
}

void iguana_addscript(cJSON *dest,uint8_t *script,int32_t scriptlen,char *fieldname)
{
    char *scriptstr,scriptbuf[8192+256]; int32_t maxlen; cJSON *scriptobj;
    if ( scriptlen < 0 || scriptlen > IGUANA_MAXSCRIPTSIZE || scriptlen > sizeof(scriptbuf) )
        return;
    scriptstr = scriptbuf, maxlen = sizeof(scriptbuf);
    init_hexbytes_noT(scriptstr,script,scriptlen);
    //if ( strcmp(fieldname,"userdata") == 0 )
    //    printf("SCRIPT_USERDATA.(%s)\n",scriptstr);
    if ( strcmp(fieldname,"coinbase") == 0 )
        jaddstr(dest,"coinbase",scriptstr);
    else
    {
        scriptobj = cJSON_CreateObject();
        jaddstr(scriptobj,"hex",scriptstr);
        iguana_expandscript(scriptstr,maxlen,script,scriptlen);
        if ( scriptstr[0] != 0 )
            jaddstr(scriptobj,"asm",scriptstr);
        if ( scriptstr != scriptbuf )
            free(scriptstr);
        jadd(dest,fieldname,scriptobj);
    }
}

cJSON *iguana_pubkeysjson(uint8_t *pubkeyptrs[],int32_t numpubkeys)
{
    int32_t i,plen; char pubkeystr[256]; cJSON *pubkeysjson = cJSON_CreateArray();
    for (i=0; i<numpubkeys; i++)
    {
        if ( pubkeyptrs != 0 && (plen= bitcoin_pubkeylen(pubkeyptrs[i])) > 0 )
            init_hexbytes_noT(pubkeystr,pubkeyptrs[i],plen);
        else pubkeystr[0] = 0;
        jaddistr(pubkeysjson,pubkeystr);
    }
    return(pubkeysjson);
}

cJSON *bitcoin_txinput(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,cJSON *txobj,bits256 txid,int32_t vout,uint32_t sequenceid,uint8_t *spendscript,int32_t spendlen,uint8_t *redeemscript,int32_t p2shlen,uint8_t *pubkeys[],int32_t numpubkeys,uint8_t *sig,int32_t siglen)
{
    cJSON *item,*vins; char p2shscriptstr[IGUANA_MAXSCRIPTSIZE*2+1]; uint8_t *script,len=0;
    vins = jduplicate(jobj(txobj,"vin"));
    jdelete(txobj,"vin");
    item = cJSON_CreateObject();
    if ( sig != 0 && siglen > 0 )
        iguana_addscript(item,sig,siglen,"scriptSig");
    if ( spendscript != 0 && spendscript > 0 )
    {
        iguana_addscript(item,spendscript,spendlen,"scriptPubKey");
        script = spendscript, len = spendlen;
    }
    else if ( redeemscript != 0 && p2shlen > 0 )
    {
        init_hexbytes_noT(p2shscriptstr,redeemscript,p2shlen);
        jaddstr(item,"redeemScript",p2shscriptstr);
        script = redeemscript, len = p2shlen;
    } else script = 0;
    if ( script != 0 && numpubkeys == 0 )
        jadd(item,"pubkeys",iguana_scriptpubkeys(symbol,taddr,pubtype,p2shtype,script,len,txid,vout,sequenceid));
    else if ( pubkeys != 0 && numpubkeys > 0 )
        jadd(item,"pubkeys",iguana_pubkeysjson(pubkeys,numpubkeys));
    jaddbits256(item,"txid",txid);
    jaddnum(item,"vout",vout);
    jaddnum(item,"sequence",sequenceid);
    jaddi(vins,item);
    jadd(txobj,"vin",vins);
    //printf("addvin -> (%s)\n",jprint(txobj,0));
    return(txobj);
}

cJSON *bitcoin_txcreate(char *symbol,int32_t isPoS,int64_t locktime,uint32_t txversion,uint32_t timestamp)
{
    cJSON *json = cJSON_CreateObject();
    jaddnum(json,"version",txversion);
    if ( locktime == 0 && strcmp(symbol,"KMD") == 0 )
        locktime = (uint32_t)time(NULL);
    jaddnum(json,"locktime",locktime);
    if ( isPoS != 0 )
        jaddnum(json,"timestamp",timestamp == 0 ? time(NULL) : timestamp);
    jadd(json,"vin",cJSON_CreateArray());
    jadd(json,"vout",cJSON_CreateArray());
    return(json);
}

cJSON *bitcoin_txoutput(cJSON *txobj,uint8_t *paymentscript,int32_t len,uint64_t satoshis)
{
    char *hexstr; cJSON *item,*skey,*vouts = jduplicate(jobj(txobj,"vout"));
    jdelete(txobj,"vout");
    item = cJSON_CreateObject();
    jadd64bits(item,"satoshis",satoshis);
    skey = cJSON_CreateObject();
    hexstr = malloc(len*2 + 1);
    init_hexbytes_noT(hexstr,paymentscript,len);
    jaddstr(skey,"hex",hexstr);
    //printf("addoutput.(%s %s)\n",hexstr,jprint(skey,0));
    free(hexstr);
    jadd(item,"scriptPubKey",skey);
    jaddi(vouts,item);
    jadd(txobj,"vout",vouts);
    return(txobj);
}

int32_t bitcoin_txaddspend(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,cJSON *txobj,char *destaddress,uint64_t satoshis)
{
    uint8_t outputscript[128],addrtype,rmd160[20]; int32_t scriptlen;
    if ( bitcoin_validaddress(symbol,taddr,pubtype,p2shtype,destaddress) == 0 && satoshis != 0 )
    {
        bitcoin_addr2rmd160(symbol,taddr,&addrtype,rmd160,destaddress);
        scriptlen = bitcoin_standardspend(outputscript,0,rmd160);
        bitcoin_txoutput(txobj,outputscript,scriptlen,satoshis);
        return(0);
    } else return(-1);
}

int32_t iguana_vinparse(int32_t rwflag,uint8_t *serialized,struct iguana_msgvin *msg)
{
    int32_t p2shlen,len = 0; uint32_t tmp;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->prev_hash),msg->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->prev_vout),&msg->prev_vout);
    //char str[65]; printf("prev_hash.(%s) v%d\n",bits256_str(str,msg->prev_hash),msg->prev_vout);
    if ( rwflag == 1 )
    {
        tmp = msg->scriptlen + msg->userdatalen + msg->p2shlen;
        if ( msg->p2shlen != 0 )
        {
            if ( msg->p2shlen < 76 )
                tmp++;
            else if ( msg->p2shlen < 0x100 )
                tmp += 2;
            else tmp += 3;
        }
    }
    len += iguana_rwvarint32(rwflag,&serialized[len],&tmp);
    if ( rwflag == 0 )
    {
        /*if ( msg->p2shlen != 0 )
         {
         if ( msg->p2shlen < 76 )
         tmp++;
         else if ( msg->p2shlen < 0x100 )
         tmp += 2;
         else tmp += 3;
         }*/
        msg->scriptlen = tmp;
    }
    if ( msg->scriptlen > IGUANA_MAXSCRIPTSIZE )
    {
        printf("iguana_vinparse illegal scriptlen.%d\n",msg->scriptlen);
        return(-1);
    }
    //printf("len.%d scriptlen.%d user.%d p2sh.%d\n",len,msg->scriptlen,msg->userdatalen,msg->p2shlen);
    if ( rwflag == 0 )
    {
        msg->vinscript = &serialized[len];
        len += msg->scriptlen;
    }
    else
    {
        if ( msg->vinscript != 0 && msg->scriptlen > 0 )
            memcpy(&serialized[len],msg->vinscript,msg->scriptlen), len += msg->scriptlen; // pubkeys here
        if ( msg->userdatalen > 0 && msg->userdata != 0 )
        {
            //printf("userdata.%d scriptlen.%d\n",msg->userdatalen,msg->scriptlen);
            memcpy(&serialized[len],msg->userdata,msg->userdatalen);
            len += msg->userdatalen;
        }
        if ( (p2shlen= msg->p2shlen) > 0 && msg->redeemscript != 0 )
        {
            if ( p2shlen < 76 )
                serialized[len++] = p2shlen;
            else if ( p2shlen <= 0xff )
            {
                serialized[len++] = 0x4c;
                serialized[len++] = p2shlen;
            }
            else if ( p2shlen <= 0xffff )
            {
                serialized[len++] = 0x4d;
                serialized[len++] = (p2shlen & 0xff);
                serialized[len++] = ((p2shlen >> 8) & 0xff);
            } else return(-1);
            memcpy(&serialized[len],msg->redeemscript,p2shlen), len += p2shlen;
            if ( (0) )
            {
                int32_t j;
                for (j=0; j<p2shlen; j++)
                    printf("%02x",msg->redeemscript[j]);
                printf(" p2shlen.%d %x\n",p2shlen,p2shlen);
            }
        }
    }
    //printf("sequence starts.%d %08x\n",len,*(int32_t *)&serialized[len]);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->sequence),&msg->sequence);
    if ( (0) )
    {
        int32_t i; char str[65];
        for (i=0; i<len; i++)
            printf("%02x",serialized[i]);
        printf(" %08x prev_hash.(%s) vout.%d [%p] scriptlen.%d rwflag.%d\n",msg->sequence,bits256_str(str,msg->prev_hash),msg->prev_vout,msg->vinscript,msg->scriptlen,rwflag);
    }
    return(len);
}

int32_t iguana_voutparse(int32_t rwflag,uint8_t *serialized,struct iguana_msgvout *msg)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->value),&msg->value);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->pk_scriptlen);
    if ( msg->pk_scriptlen > IGUANA_MAXSCRIPTSIZE )
    {
        printf("iguana_voutparse illegal scriptlen.%d\n",msg->pk_scriptlen);
        return(-1);
    }
    if ( rwflag == 0 )
        msg->pk_script = &serialized[len];
    else if ( msg->pk_scriptlen > 0 )
    {
        memcpy(&serialized[len],msg->pk_script,msg->pk_scriptlen);
        if ( (0) )
        {
            int32_t i;
            for (i=0; i<msg->pk_scriptlen; i++)
                printf("%02x",msg->pk_script[i]);
            printf(" [%p] scriptlen.%d rwflag.%d %.8f\n",msg->pk_script,msg->pk_scriptlen,rwflag,dstr(msg->value));
        }
    } // else serialized[len++] = 0;
    len += msg->pk_scriptlen;
    return(len);
}

cJSON *iguana_vinjson(struct iguana_msgvin *vin,bits256 sigtxid)
{
    char str[65]; int32_t vout; cJSON *json = cJSON_CreateObject();
    vout = vin->prev_vout;
    jaddnum(json,"sequence",vin->sequence);
    if ( vout < 0 && bits256_nonz(vin->prev_hash) == 0 )
        iguana_addscript(json,vin->vinscript,vin->scriptlen,"coinbase");
    else
    {
        jaddstr(json,"txid",bits256_str(str,vin->prev_hash));
        jaddnum(json,"vout",vout);
        if ( bits256_nonz(sigtxid) != 0 )
            jaddbits256(json,"sigtxid",sigtxid);
        if ( vin->scriptlen > 0 && vin->vinscript != 0 ) // sigs
            iguana_addscript(json,vin->vinscript,vin->scriptlen,"scriptSig");
        if ( vin->userdatalen > 0 && vin->userdata != 0 )
            iguana_addscript(json,vin->userdata,vin->userdatalen,"userdata");
        if ( vin->p2shlen > 0 && vin->redeemscript != 0 )
            iguana_addscript(json,vin->redeemscript,vin->p2shlen,"redeemScript");
        if ( vin->spendlen > 0 && vin->spendscript != 0 )
            iguana_addscript(json,vin->spendscript,vin->spendlen,"scriptPubKey");
    }
    return(json);
}

int32_t iguana_parsehexstr(uint8_t **destp,uint16_t *lenp,uint8_t *dest2,int32_t *len2p,uint8_t *serialized,char *hexstr)
{
    int32_t n;
    n = (int32_t)strlen(hexstr) >> 1;
    //printf("addhex.(%s) %d\n",hexstr,n);
    if ( serialized == 0 )
    {
        if ( (serialized= *destp) == 0 )
            printf("iguana_parsehexstr null serialized and destp\n");
    }
    if ( serialized != 0 )
    {
        decode_hex(serialized,n,hexstr);
        *destp = serialized;
        *lenp = n;
        if ( dest2 != 0 && len2p != 0 )
        {
            *len2p = n;
            memcpy(dest2,serialized,n);
        }
    }
    return(n);
}

int32_t iguana_scriptnum(uint8_t opcode)
{
    if ( opcode == 0x00 )
        return(0);
    else if ( opcode >= 0x51 && opcode < 0x60 )
        return(opcode - 0x50);
    else return(-1);
}

int32_t iguana_parsevinobj(uint8_t *serialized,int32_t maxsize,struct iguana_msgvin *vin,cJSON *vinobj,struct vin_info *V)
{
    //struct iguana_outpoint outpt; struct iguana_waddress *waddr; struct iguana_waccount *wacct;
    uint8_t lastbyte; uint32_t tmp=0; int32_t i,n,starti,suppress_pubkeys,siglen,plen,m,endi,rwflag=1,len = 0; char *userdata=0,*pubkeystr,*hexstr = 0,*redeemstr = 0,*spendstr = 0; cJSON *scriptjson = 0,*obj,*pubkeysjson = 0;
    //printf("PARSEVIN.(%s) vin.%p\n",jprint(vinobj,0),vin);
    if ( V == 0 )
        memset(vin,0,sizeof(*vin));
    vin->prev_vout = -1;
    suppress_pubkeys = juint(vinobj,"suppress");
    if ( jobj(vinobj,"sequence") != 0 )
        vin->sequence = juint(vinobj,"sequence");
    else vin->sequence = 0xffffffff;
    if ( (hexstr= jstr(vinobj,"coinbase")) == 0 )
    {
        vin->prev_hash = jbits256(vinobj,"txid");
        //char str[65]; printf("vin->prev_hash.(%s)\n",bits256_str(str,vin->prev_hash));
        vin->prev_vout = jint(vinobj,"vout");
        if ( (scriptjson= jobj(vinobj,"scriptSig")) != 0 )
            hexstr = jstr(scriptjson,"hex");
        if ( ((spendstr= jstr(vinobj,"scriptPub")) == 0 && (spendstr= jstr(vinobj,"scriptPubKey")) == 0) || is_hexstr(spendstr,(int32_t)strlen(spendstr)) <= 0 )
        {
            if ( (obj= jobj(vinobj,"scriptPub")) != 0 || (obj= jobj(vinobj,"scriptPubKey")) != 0 )
            {
                spendstr = jstr(obj,"hex");
                if ( spendstr[0] != 0 )
                {
                    lastbyte = _decode_hex(&spendstr[strlen(spendstr)-2]);
                    //if ( lastbyte == SCRIPT_OP_CHECKMULTISIG )
                    //    need_op0 = 1;
                    if ( V != 0 )
                    {
                        V->spendlen = (int32_t)strlen(spendstr) >> 1;
                        decode_hex(V->spendscript,V->spendlen,spendstr);
                    }
                }
            }
        }
        if ( (redeemstr= jstr(vinobj,"redeemScript")) == 0 || is_hexstr(redeemstr,(int32_t)strlen(redeemstr)) <= 0 )
        {
            if ( (obj= jobj(vinobj,"redeemScript")) != 0 )
            {
                redeemstr = jstr(obj,"hex");
                lastbyte = _decode_hex(&redeemstr[strlen(redeemstr)-2]);
                //if ( lastbyte == SCRIPT_OP_CHECKMULTISIG )
                //    need_op0 = 1;
            }
        }
        if ( (userdata= jstr(vinobj,"userdata")) == 0 || is_hexstr(userdata,(int32_t)strlen(userdata)) <= 0 )
        {
            if ( (obj= jobj(vinobj,"userdata")) != 0 )
                userdata = jstr(obj,"hex");
        }
    }
    //char str[65]; printf("rw.%d prevhash.(%s)\n",rwflag,bits256_str(str,vin->prev_hash));
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(vin->prev_hash),vin->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(vin->prev_vout),&vin->prev_vout);
    if ( V != 0 )
    {
        V->suppress_pubkeys = suppress_pubkeys;
        if ( vin->vinscript == 0 && V->spendlen == 0 )
        {
            /*if ( iguana_RTunspentindfind(coin,&outpt,V->coinaddr,spendscript,&spendlen,&V->amount,&V->height,vin->prev_hash,vin->prev_vout,coin->bundlescount-1,0) == 0 )
            {
                V->unspentind = outpt.unspentind;
                if ( V->coinaddr[0] != 0 && (waddr= iguana_waddresssearch(&wacct,V->coinaddr)) != 0 )
                {
                    plen = bitcoin_pubkeylen(waddr->pubkey);
                    for (z=0; z<plen; z++)
                        V->signers[0].pubkey[z] = waddr->pubkey[z];
                }
                //printf("V %.8f (%s) spendscript.[%d]\n",dstr(V->amount),V->coinaddr,V->spendlen);
            }
            if ( spendlen != 0 && V->spendlen == 0 )
            {
                V->spendlen = spendlen;
                memcpy(V->spendscript,spendscript,spendlen);
            }*/
        }
    }
    tmp = IGUANA_MAXSCRIPTSIZE;
    starti = len;
    len += iguana_rwvarint32(rwflag,&serialized[len],&tmp);
    endi = len;
    //printf("rwflag.%d len.%d tmp.%d\n",rwflag,len,tmp);
    //if ( need_op0 != 0 )
    //    serialized[len++] = 0; // hack for bug for bug backward compatibility
    if ( hexstr != 0 )
    {
        n = (int32_t)strlen(hexstr) >> 1;
        //printf("add.(%s) offset.%d\n",hexstr,len);
        vin->vinscript = &serialized[len];
        decode_hex(&serialized[len],n,hexstr);
        vin->scriptlen = n;// + need_op0;
        if ( V != 0 )
        {
            i = m = 0;
            while ( m < n )
            {
                siglen = serialized[len + m++];
                //if ( i == 0 && m == 1 && siglen == 0 ) // multisig backward compatible
                //    continue;
                if ( ((serialized[len + m + siglen - 1] & ~SIGHASH_FORKID) & 0xff) == SIGHASH_ALL )
                    memcpy(V->signers[i++].sig,&serialized[len + m],siglen);
                if ( (0) )
                {
                    int32_t j;
                    for (j=0; j<siglen; j++)
                        printf("%02x",serialized[len + m + j]);
                    printf(" (%d) parsedvin\n",siglen);
                }
                m += siglen;
                i++;
            }
            if ( m != n )
                printf("ERROR: (%s) len.%d n.%d i.%d\n",hexstr,m,n,i);
        }
        len += n;
    } //else printf("iguana_parsevinobj: hex script missing (%s)\n",jprint(vinobj,0));
    if ( (pubkeysjson= jarray(&n,vinobj,"pubkeys")) != 0 && vin->vinscript != 0 )
    {
        /*if ( vin->vinscript == 0 )
         {
         vin->vinscript = serialized;
         vin->vinscript[0] = 0;
         vin->scriptlen = 1;
         }*/
        for (i=0; i<n; i++)
        {
            if ( (pubkeystr= jstr(jitem(pubkeysjson,i),0)) != 0 && (plen= (int32_t)strlen(pubkeystr) >> 1) > 0 )
            {
                if ( V != 0 )
                {
                    memcpy(V->signers[i].pubkey,&vin->vinscript[vin->scriptlen],plen);
                    if ( V->spendlen == 35 && V->spendscript[0] == 33 && V->spendscript[34] == 0xac )
                        suppress_pubkeys = 1;
                }
                if ( suppress_pubkeys == 0 )
                {
                    printf("addpub.(%s)\n",pubkeystr);
                    vin->vinscript[vin->scriptlen++] = plen;
                    decode_hex(&vin->vinscript[vin->scriptlen],plen,pubkeystr);
                    vin->scriptlen += plen;
                    serialized[len++] = plen;
                    memcpy(&serialized[len],&vin->vinscript[vin->scriptlen],plen), len += plen;
                }
            }
        }
    }
    //printf("userdata len.%d: ",len);
    if ( userdata != 0 )
    {
        n = iguana_parsehexstr(&vin->userdata,&vin->userdatalen,V!=0?V->userdata:0,V!=0?&V->userdatalen:0,&serialized[len],userdata);
        //printf("parsed userdata.%d\n",n);
        len += n;
    }
    //printf("redeemlen.%d: ",len);
    if ( redeemstr != 0 )
    {
        n = (int32_t)strlen(redeemstr) >> 1;
        if ( n < 76 )
            serialized[len++] = n;
        else if ( n <= 0xff )
        {
            serialized[len++] = 0x4c;
            serialized[len++] = n;
        }
        else
        {
            serialized[len++] = 0x4d;
            serialized[len++] = n & 0xff;
            serialized[len++] = (n >> 8) & 0xff;
        }
        n = iguana_parsehexstr(&vin->redeemscript,&vin->p2shlen,V!=0?V->p2shscript:0,V!=0?&V->p2shlen:0,&serialized[len],redeemstr);
        len += n;
        if ( vin->redeemscript[vin->p2shlen-1] == SCRIPT_OP_CHECKMULTISIG )
        {
            V->M = iguana_scriptnum(vin->redeemscript[0]);
            V->N = iguana_scriptnum(vin->redeemscript[vin->p2shlen-2]);
        }
    }
    tmp = (len - endi);
    if ( tmp < 0xfd )
    {
        serialized[starti] = tmp;
        for (i=starti+1; i<starti+1+tmp; i++)
            serialized[i] = serialized[i+2];
        //printf("tmp.%d (len.%d - starti.%d) i.%d\n",tmp,len,starti,i);
        len -= 2;
    }
    else
    {
        //for (i=0; i<len; i++)
        //    printf("%02x",serialized[i]);
        //printf(" <- offset.%d tmp.%d starti.%d\n",len,tmp,starti);
        serialized[starti+1] = (tmp & 0xff);
        serialized[starti+2] = ((tmp >> 8) & 0xff);
    }
    //printf("len.%d tmp.%d output sequence.[%d] <- %x\n",len,tmp,len,vin->sequence);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(vin->sequence),&vin->sequence);
    if ( spendstr != 0 )
    {
        if ( V != 0 )
        {
            if ( V->spendlen == 0 )
            {
                V->spendlen = (int32_t)strlen(spendstr) >> 1;
                decode_hex(V->spendscript,V->spendlen,spendstr);
            }
            if ( vin->spendscript == 0 )
                vin->spendscript = V->spendscript;
        }
        if ( vin->spendlen == 0 && vin->spendscript != 0 )
        {
            vin->spendlen = (int32_t)strlen(spendstr) >> 1;
            decode_hex(vin->spendscript,vin->spendlen,spendstr);
        }
        //printf("serialized.%p len.%d\n",serialized,len);
        //n = iguana_parsehexstr(&vin->spendscript,&vin->spendlen,V!=0?V->spendscript:0,V!=0?&V->spendlen:0,&serialized[len],spendstr);
        //len += n;
    }
    return(len);
}

int32_t iguana_parsevoutobj(uint8_t *serialized,int32_t maxsize,struct iguana_msgvout *vout,cJSON *voutobj)
{
    int32_t n,len = 0,rwflag = 1; cJSON *skey; char *hexstr;
    memset(vout,0,sizeof(*vout));
    if ( jobj(voutobj,"satoshis") != 0 )
        vout->value = j64bits(voutobj,"satoshis");
    else vout->value = jdouble(voutobj,"value") * SATOSHIDEN;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(vout->value),&vout->value);
    if ( (skey= jobj(voutobj,"scriptPubKey")) != 0 )
    {
        if ( (hexstr= jstr(skey,"hex")) != 0 )
        {
            n = (int32_t)strlen(hexstr) >> 1;
            vout->pk_scriptlen = n;
            len += iguana_rwvarint32(rwflag,&serialized[len],&vout->pk_scriptlen);
            decode_hex(&serialized[len],n,hexstr);
            vout->pk_script = &serialized[len];
            len += n;
        } // else serialized[len++] = 0;
    } //else serialized[len++] = 0;
    return(len);
}

cJSON *iguana_voutjson(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,struct iguana_msgvout *vout,int32_t txi,bits256 txid)
{
    // 035f1321ed17d387e4433b2fa229c53616057964af065f98bfcae2233c5108055e OP_CHECKSIG
    char scriptstr[IGUANA_MAXSCRIPTSIZE+1]; int32_t i,m,n,scriptlen,asmtype; struct vin_info *vp;
    uint8_t space[8192]; cJSON *addrs,*skey,*json = cJSON_CreateObject();
    vp = calloc(1,sizeof(*vp));
    jadd64bits(json,"satoshis",vout->value);
    jaddnum(json,"value",dstr(vout->value));
    jaddnum(json,"n",txi);
    //"scriptPubKey":{"asm":"OP_DUP OP_HASH160 5f69cb73016264270dae9f65c51f60d0e4d6fd44 OP_EQUALVERIFY OP_CHECKSIG","reqSigs":1,"type":"pubkeyhash","addresses":["RHyh1V9syARTf2pyxibz7v27D5paBeWza5"]}
    if ( vout->pk_script != 0 && vout->pk_scriptlen*2+1 < sizeof(scriptstr) )
    {
        memset(vp,0,sizeof(*vp));
        if ( (asmtype= iguana_calcrmd160(symbol,taddr,pubtype,p2shtype,0,vp,vout->pk_script,vout->pk_scriptlen,txid,txi,0xffffffff)) >= 0 )
        {
            skey = cJSON_CreateObject();
            scriptlen = iguana_scriptgen(symbol,taddr,pubtype,p2shtype,&m,&n,vp->coinaddr,space,0,vp->rmd160,asmtype,vp,txi);
            //if ( asmstr[0] != 0 )
            //    jaddstr(skey,"asm",asmstr);
            addrs = cJSON_CreateArray();
            if ( vp->N == 1 )
            {
                if ( asmtype == 2 )
                {
                    jaddnum(skey,"reqSigs",1);
                    jaddstr(skey,"type","pubkeyhash");
                }
                if ( vp->coinaddr[0] != 0 )
                    jaddistr(addrs,vp->coinaddr);
            }
            else
            {
                jaddnum(skey,"reqSigs",vp->M);
                for (i=0; i<vp->N; i++)
                {
                    //btc_convrmd160(coinaddr,coin->chain->pubtype,V.signers[i].pubkey);
                    jaddistr(addrs,vp->signers[i].coinaddr);
                }
            }
            jadd(skey,"addresses",addrs);
            init_hexbytes_noT(scriptstr,vout->pk_script,vout->pk_scriptlen);
            if ( scriptstr[0] != 0 )
                jaddstr(skey,"hex",scriptstr);
            jadd(json,"scriptPubKey",skey);
        }
    }
    free(vp);
    return(json);
}

void iguana_vinobjset(struct iguana_msgvin *vin,cJSON *item,uint8_t *spendscript,int32_t maxsize)
{
    char *redeemstr,*hexstr=0; cJSON *sobj;
    if ( (redeemstr= jstr(item,"redeemScript")) != 0 && is_hexstr(redeemstr,0) > 0 )
    {
        vin->p2shlen = (int32_t)strlen(redeemstr) >> 1;
        vin->spendlen = vin->p2shlen;
        vin->redeemscript = calloc(1,vin->p2shlen);
        decode_hex(vin->redeemscript,vin->p2shlen,redeemstr);
        hexstr = redeemstr;
        //printf("VINOBJSET.(%s)\n",redeemstr);
    }
    else if ( (sobj= jobj(item,"scriptPubKey")) != 0 && (hexstr= jstr(sobj,"hex")) != 0 && is_hexstr(hexstr,0) > 0 && (vin->spendlen == 0 || vin->spendscript == 0) )
    {
        vin->spendlen = (int32_t)strlen(hexstr) >> 1;
    }
    if ( hexstr != 0 && vin->spendlen != 0 )
    {
        if ( vin->spendlen < maxsize )
        {
            if ( vin->spendscript == 0 )
                vin->spendscript = spendscript;
            decode_hex(vin->spendscript,vin->spendlen,hexstr);
        }
    }
}

int32_t iguana_vinarray_check(cJSON *vinarray,bits256 txid,int32_t vout)
{
    bits256 array_txid; cJSON *item; int32_t array_vout,i,n = cJSON_GetArraySize(vinarray);
    for (i=0; i<n; i++)
    {
        item = jitem(vinarray,i);
        array_txid = jbits256(item,"txid");
        array_vout = jint(item,"vout");
        if ( bits256_cmp(array_txid,txid) == 0 && array_vout == vout )
        {
            printf("vinarray.[%d] duplicate\n",i);
            return(i);
        }
    }
    return(-1);
}

int32_t iguana_rwmsgtx(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,int32_t rwflag,cJSON *json,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msg,bits256 *txidp,char *vpnstr,uint8_t *extraspace,int32_t extralen,cJSON *vins,int32_t suppress_pubkeys,int32_t zcash);

bits256 bitcoin_sigtxid(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,uint8_t *serialized,int32_t maxlen,struct iguana_msgtx *msgtx,int32_t vini,uint8_t *spendscript,int32_t spendlen,uint64_t spendamount,uint32_t hashtype,char *vpnstr,int32_t suppress_pubkeys,int32_t zcash)
{
    int32_t i,len,sbtcflag = 0,btcpflag=0; bits256 sigtxid,txid,revsigtxid; struct iguana_msgtx dest;
    dest = *msgtx;
    dest.vins = calloc(dest.tx_in,sizeof(*dest.vins));
    dest.vouts = calloc(dest.tx_out,sizeof(*dest.vouts));
    memcpy(dest.vins,msgtx->vins,dest.tx_in * sizeof(*dest.vins));
    memcpy(dest.vouts,msgtx->vouts,dest.tx_out * sizeof(*dest.vouts));
    memset(sigtxid.bytes,0,sizeof(sigtxid));
    if ( strcmp(symbol,"SBTC") == 0 )
        sbtcflag = 1;
    else if ( strcmp(symbol,"BTCP") == 0 )
        btcpflag = 1;
    // else printf("normal symbol.(%s)\n",symbol);
    if ( ((hashtype & ~SIGHASH_FORKID) & 0xff) != SIGHASH_ALL )
    {
        printf("currently only SIGHASH_ALL supported, not %d\n",hashtype);
        return(sigtxid);
    }
    if ( (hashtype & SIGHASH_FORKID) == 0 || sbtcflag != 0 || btcpflag != 0 )
    {
        for (i=0; i<dest.tx_in; i++)
        {
            if ( i == vini )
            {
                dest.vins[i].vinscript = spendscript;
                dest.vins[i].scriptlen = spendlen;
                //int32_t j; for (j=0; j<spendlen; j++)
                //    printf("%02x",spendscript[j]);
                //printf(" tmpscript.%d vini.%d\n",spendlen,vini);
            }
            else
            {
                dest.vins[i].vinscript = (uint8_t *)"";
                dest.vins[i].scriptlen = 0;
            }
            dest.vins[i].p2shlen = 0;
            dest.vins[i].redeemscript = 0;
            dest.vins[i].userdata = 0;
            dest.vins[i].userdatalen = 0;
        }
        len = iguana_rwmsgtx(symbol,taddr,pubtype,p2shtype,isPoS,height,1,0,serialized,maxlen,&dest,&txid,vpnstr,0,0,0,suppress_pubkeys,zcash);
        if ( len > 0 )
        {
#ifdef BTC2_VERSION
            if ( height >= BTC2_HARDFORK_HEIGHT )
                hashtype |= (0x777 << 20);
#endif
            if ( btcpflag != 0 )
            {
                hashtype = 0x2a41;
                //printf("BTCP detected: hardcode hashtype to %08x\n",hashtype);
            }
            len += iguana_rwnum(1,&serialized[len],sizeof(hashtype),&hashtype);
            if ( sbtcflag != 0 )
            {
                serialized[len++] = 4;
                memcpy(&serialized[len],"sbtc",4);
                len += 4;
            }
        }
        revsigtxid = bits256_calctxid(symbol,serialized,len);
        for (i=0; i<sizeof(revsigtxid); i++)
            sigtxid.bytes[31-i] = revsigtxid.bytes[i];
    }
    else
    {
        /*
         https://github.com/Bitcoin-UAHF/spec/blob/master/replay-protected-sighash.md
        CHashWriter ss(SER_GETHASH, 0);
        // Version
        ss << txTo.nVersion;
        // Input prevouts/nSequence (none/all, depending on flags)
        ss << hashPrevouts;
        ss << hashSequence;
        // The input being signed (replacing the scriptSig with scriptCode +
        // amount). The prevout may already be contained in hashPrevout, and the
        // nSequence may already be contain in hashSequence.
        ss << txTo.vin[nIn].prevout;
        ss << static_cast<const CScriptBase &>(scriptCode);
        ss << amount;
        ss << txTo.vin[nIn].nSequence;
        // Outputs (none/one/all, depending on flags)
        ss << hashOutputs;
        // Locktime
        ss << txTo.nLockTime;
        // Sighash type
        ss << ((GetForkId() << 8) | nHashType);
        return ss.GetHash();
    }
    Computation of midstates:
    
    uint256 GetPrevoutHash(const CTransaction &txTo) {
        CHashWriter ss(SER_GETHASH, 0);
        for (unsigned int n = 0; n < txTo.vin.size(); n++) {
            ss << txTo.vin[n].prevout;
        }
        
        return ss.GetHash();
    }
    
    uint256 GetSequenceHash(const CTransaction &txTo) {
        CHashWriter ss(SER_GETHASH, 0);
        for (unsigned int n = 0; n < txTo.vin.size(); n++) {
            ss << txTo.vin[n].nSequence;
        }
        
        return ss.GetHash();
    }
    
    uint256 GetOutputsHash(const CTransaction &txTo) {
        CHashWriter ss(SER_GETHASH, 0);
        for (unsigned int n = 0; n < txTo.vout.size(); n++) {
            ss << txTo.vout[n];
        }
        
        return ss.GetHash();
    }
    */
        bits256 prevouthash,seqhash,outputhash;
        for (i=len=0; i<dest.tx_in; i++)
        {
            len += iguana_rwbignum(1,&serialized[len],sizeof(dest.vins[i].prev_hash),dest.vins[i].prev_hash.bytes);
            len += iguana_rwnum(1,&serialized[len],sizeof(dest.vins[i].prev_vout),&dest.vins[i].prev_vout);
        }
        prevouthash = bits256_doublesha256(0,serialized,len);
        
        for (i=len=0; i<dest.tx_in; i++)
            len += iguana_rwnum(1,&serialized[len],sizeof(dest.vins[i].sequence),&dest.vins[i].sequence);
        seqhash = bits256_doublesha256(0,serialized,len);
        
        for (i=len=0; i<dest.tx_out; i++)
            len += iguana_voutparse(1,&serialized[len],&dest.vouts[i]);
        outputhash = bits256_doublesha256(0,serialized,len);

        //char str[65]; printf("prevouthash.%s ",bits256_str(str,prevouthash));
        //printf("seqhash.%s ",bits256_str(str,seqhash));
        //printf("outputhash.%s ",bits256_str(str,outputhash));
        //printf("vini.%d prev.%s/v%d\n",vini,bits256_str(str,dest.vins[vini].prev_hash),dest.vins[vini].prev_vout);
        /*01000000
        997c1040c67ee2f9ab21abf7457f7aec4503970e974e532b6578f326c270b7eb
        445066705e799022b7095f7ceca255149f43acfc47e7f59e551f7bce2930b13b
        b19ce2c564f7dc57b3f95593e2b287c72d388e86de12dc562d9f8a6bea65b310 01000000
        1976a91459fdba29ea85c65ad90f6d38f7a6646476b26b1688ac
        5be9290000000000
        ffffffff
        a919fd9f636c08f4989be95c999230408dbc0f602c3f000bcedba9d5bbe98914
        00000000
        41000000*/
        /*
         01000000 ss.write size.4
        ebb770c226f378652b534e970e970345ec7a7f45f7ab21abf9e27ec640107c99 ss.write size.32
        3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044 ss.write size.32
        10b365ea6b8a9f2d56dc12de868e382dc787b2e29355f9b357dcf764c5e29cb1 ss.write size.32
        01000000 ss.write size.4
        19 ss.write size.1
        76a91459fdba29ea85c65ad90f6d38f7a6646476b26b1688ac ss.write size.25
        76a91459fdba29ea85c65ad90f6d38f7a6646476b26b1688ac scriptCode
        5be9290000000000 ss.write size.8
        ffffffff ss.write size.4
        hashtype.41 locktime.0 seq.ffffffff amount 29e95b
        1489e9bbd5a9dbce0b003f2c600fbc8d403092995ce99b98f4086c639ffd19a9 ss.write size.32
        00000000 ss.write size.4
        41000000 ss.write size.4
        -> sighash.fc55acc3666c43b8f75908ca06ea2d343cd09eb846f14c5d7d0748a11e081a9d*/
        len = 0;
        len += iguana_rwnum(1,&serialized[len],sizeof(dest.version),&dest.version);
        len += iguana_rwbignum(1,&serialized[len],sizeof(prevouthash),prevouthash.bytes);
        len += iguana_rwbignum(1,&serialized[len],sizeof(seqhash),seqhash.bytes);
        len += iguana_rwbignum(1,&serialized[len],sizeof(dest.vins[vini].prev_hash),dest.vins[vini].prev_hash.bytes);
        len += iguana_rwnum(1,&serialized[len],sizeof(dest.vins[vini].prev_vout),&dest.vins[vini].prev_vout);
        serialized[len++] = spendlen;
        memcpy(&serialized[len],spendscript,spendlen), len += spendlen;
        len += iguana_rwnum(1,&serialized[len],sizeof(spendamount),&spendamount);
        len += iguana_rwnum(1,&serialized[len],sizeof(dest.vins[vini].sequence),&dest.vins[vini].sequence);
        len += iguana_rwbignum(1,&serialized[len],sizeof(outputhash),outputhash.bytes);
        len += iguana_rwnum(1,&serialized[len],sizeof(dest.lock_time),&dest.lock_time);
        len += iguana_rwnum(1,&serialized[len],sizeof(hashtype),&hashtype);
        //for (i=0; i<len; i++)
        //    printf("%02x",serialized[i]);
        revsigtxid = bits256_doublesha256(0,serialized,len);
        //printf(" B path version.%08x spendamount %.8f locktime %u hashtype %08x %s\n",dest.version,dstr(spendamount),dest.lock_time,hashtype,bits256_str(str,revsigtxid));
        for (i=0; i<sizeof(revsigtxid); i++)
            sigtxid.bytes[31-i] = revsigtxid.bytes[i];
        //sigtxid = revsigtxid;
    }
    //char str[65]; printf("SIGTXID.(%s) numvouts.%d\n",bits256_str(str,sigtxid),dest.tx_out);
    free(dest.vins);
    free(dest.vouts);
    return(sigtxid);
}

int32_t iguana_rwjoinsplit(int32_t rwflag,uint8_t *serialized,struct iguana_msgjoinsplit *msg)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->vpub_old),&msg->vpub_old);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->vpub_new),&msg->vpub_new);
    
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->anchor),msg->anchor.bytes);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->nullifiers[0]),msg->nullifiers[0].bytes);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->nullifiers[1]),msg->nullifiers[1].bytes);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->commitments[0]),msg->commitments[0].bytes);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->commitments[1]),msg->commitments[1].bytes);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->ephemeralkey),msg->ephemeralkey.bytes);
    if ( rwflag == 1 )
        memcpy(&serialized[len],msg->ciphertexts,sizeof(msg->ciphertexts));
    else memcpy(msg->ciphertexts,&serialized[len],sizeof(msg->ciphertexts));
    len += sizeof(msg->ciphertexts);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->randomseed),msg->randomseed.bytes);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->vmacs[0]),msg->vmacs[0].bytes);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->vmacs[1]),msg->vmacs[1].bytes);
    if ( rwflag == 1 )
        memcpy(&serialized[len],msg->zkproof,sizeof(msg->zkproof));
    else memcpy(msg->zkproof,&serialized[len],sizeof(msg->zkproof));
    len += sizeof(msg->zkproof);
    return(len);
}

uint32_t LP_sighash(char *symbol,int32_t zcash)
{
    uint32_t sighash;
    sighash = SIGHASH_ALL;
    if ( zcash == LP_IS_BITCOINCASH )
        sighash |= SIGHASH_FORKID;
    else if ( zcash == LP_IS_BITCOINGOLD )
    {
        sighash |= SIGHASH_FORKID;
        sighash |= (LP_IS_BITCOINGOLD << 8);
    }
    else if ( strcmp(symbol,"SBTC") == 0 || strcmp(symbol,"BTCP") == 0 )
        sighash |= SIGHASH_FORKID;
    return(sighash);
}

int32_t iguana_rwmsgtx(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,int32_t rwflag,cJSON *json,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msg,bits256 *txidp,char *vpnstr,uint8_t *extraspace,int32_t extralen,cJSON *vins,int32_t suppress_pubkeys,int32_t zcash)
{
    int32_t i,j,n,segtxlen,len = 0,extraused=0; uint32_t tmp,segitems; uint8_t *segtx=0,segwitflag=0,spendscript[IGUANA_MAXSCRIPTSIZE],*txstart = serialized,*sigser=0; uint64_t spendamount; cJSON *vinarray=0,*voutarray=0; bits256 sigtxid;
    
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->version);
    if ( json != 0 )
    {
        jaddnum(json,"version",msg->version);
        vinarray = cJSON_CreateArray();
        voutarray = cJSON_CreateArray();
        if ( rwflag == 0 )
            sigser = calloc(1,maxsize*2);
        //printf("json.%p array.%p sigser.%p\n",json,vinarray,sigser);
    }
    //printf("version.%d\n",msg->version);
    if ( isPoS != 0 )
    {
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->timestamp),&msg->timestamp);
        //char str[65]; printf("version.%d timestamp.%08x %u %s\n",msg->version,msg->timestamp,msg->timestamp,utc_str(str,msg->timestamp));
        if ( json != 0 )
            jaddnum(json,"timestamp",msg->timestamp);
    }
    if ( rwflag == 0 && zcash == 0 )
    {
        /*
         normal: nVersion|txins|txouts|nLockTime.
         segwit
         nVersion|marker|flag|txins|txouts|witness|nLockTime
         Format of nVersion, txins, txouts, and nLockTime are same as the original format
         The marker MUST be 0x00
         The flag MUST be 0x01
         */
        if ( serialized[len] == 0x00 && (segwitflag= serialized[len+1]) == 0x01 )
        {
            len += 2;
            //printf("SEGWIT transaction\n");
        }
    }
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_in);
    if ( rwflag == 0 )
    {
        if ( msg->vins == 0 )
        {
            if ( sizeof(struct iguana_msgvin)*msg->tx_in > extralen )
            {
                printf("(size.%d * tx_in.%d) > extralen.%d\n",(int32_t)sizeof(struct iguana_msgvin),msg->tx_in,extralen);
                return(-1);
            }
            msg->vins = (struct iguana_msgvin *)extraspace;
            extraused += (sizeof(struct iguana_msgvin) * msg->tx_in);
        } else printf("unexpected non-null msg->vins.%p\n",msg->vins);
        memset(msg->vins,0,sizeof(struct iguana_msgvin) * msg->tx_in);
    }
    for (i=0; i<msg->tx_in; i++)
    {
        //printf("vin.%d starts offset.%d numvins.%d\n",i,len,msg->tx_in);
        if ( vins != 0 && jitem(vins,i) != 0 )
            iguana_vinobjset(&msg->vins[i],jitem(vins,i),spendscript,sizeof(spendscript));
        if ( (n= iguana_vinparse(rwflag,&serialized[len],&msg->vins[i])) < 0 )
            return(-1);
        //printf("serialized vin.[%02x %02x %02x]\n",serialized[len],serialized[len+1],serialized[len+2]);
        if ( msg->vins[i].spendscript == spendscript )
            msg->vins[i].spendscript = 0;
        //printf("vin.%d n.%d len.%d\n",i,n,len);
        len += n;
        if ( len > maxsize )
        {
            printf("invalid tx_in.%d len.%d vs maxsize.%d\n",msg->tx_in,len,maxsize);
            return(-1);
        }
    }
    //for (i=-3; i<7; i++)
    //    printf("%02x",serialized[len+i]);
    //printf(" prev 3 bytes before tx_out rw.%d\n",rwflag);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_out);
    if ( rwflag == 0 )
    {
        if ( msg->vouts == 0 )
        {
            if ( (extraused & 0xf) != 0 )
                extraused += 0xf - (extraused & 0xf);
            if ( extraused + sizeof(struct iguana_msgvout)*msg->tx_out > extralen )
            {
                printf("extraused.%d + tx_out.%d > extralen.%d\n",extraused,msg->tx_out,extralen);
                return(-1);
            }
            msg->vouts = (struct iguana_msgvout *)&extraspace[extraused];
            extraused += (sizeof(struct iguana_msgvout) * msg->tx_out);
        } else printf("unexpected non-null msg->vouts %p\n",msg->vouts);
        memset(msg->vouts,0,sizeof(struct iguana_msgvout) * msg->tx_out);
    }
    for (i=0; i<msg->tx_out; i++)
    {
        //printf("rwflag.%d vout.%d starts %d numvouts.%d\n",rwflag,i,len,msg->tx_out);
        if ( (n= iguana_voutparse(rwflag,&serialized[len],&msg->vouts[i])) < 0 )
            return(-1);
        len += n;
        if ( len > maxsize )
        {
            printf("invalidC tx_out.%d of %d len.%d vs maxsize.%d n.%d\n",i,msg->tx_out,len,maxsize,n);
            return(-1);
        }
        if ( voutarray != 0 )
            jaddi(voutarray,iguana_voutjson(symbol,taddr,pubtype,p2shtype,&msg->vouts[i],i,*txidp));
    }
    if ( segwitflag != 0 )
    {
        segtxlen = len - 2 + sizeof(msg->lock_time);
        segtx = malloc(segtxlen);
        memcpy(segtx,serialized,sizeof(int32_t));
        memcpy(&segtx[sizeof(int32_t)],&serialized[sizeof(int32_t)+2],len-2-sizeof(int32_t));
        
        //printf("tx_out %d, tx_in %d %02x %02x %02x\n",msg->tx_out,msg->tx_in,serialized[len],serialized[len+1],serialized[len+2]);
        if ( rwflag != 0 )
            printf("unsupported rwflag.%d when segwitflag\n",rwflag);
        else
        {
            for (i=0; i<msg->tx_in; i++)
            {
                len += iguana_rwvarint32(rwflag,&serialized[len],&segitems);
                //printf("vini.%d (%d:",i,segitems);
                for (j=0; j<segitems; j++)
                {
                    len += iguana_rwvarint32(rwflag,&serialized[len],&tmp);
                    //printf(" %d",tmp);
                    if ( len+tmp >= maxsize )
                    {
                        printf("vini.%d of %d, j.%d of segitems.%d overflowed %d+%d >= max.%d\n",i,msg->tx_in,j,segitems,len,tmp,maxsize);
                        break;
                    } else len += tmp;
                }
                //printf("), ");
            }
            memcpy(&segtx[segtxlen-sizeof(int32_t)],&serialized[len],sizeof(int32_t));
            *txidp = bits256_calctxid(symbol,segtx,segtxlen);
            free(segtx);
            //char str[65]; printf("witness sum %d vs max.%d txid %s\n",len,maxsize,bits256_str(str,txid));
        }
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->lock_time),&msg->lock_time);
    //printf("lock_time.%08x len.%d\n",msg->lock_time,len);
    if ( zcash == LP_IS_ZCASHPROTOCOL && msg->version > 1 )
    {
        uint32_t numjoinsplits; struct iguana_msgjoinsplit joinsplit; uint8_t joinsplitpubkey[33],joinsplitsig[64];
        len += iguana_rwvarint32(rwflag,&serialized[len],&numjoinsplits);
        if ( numjoinsplits > 0 )
        {
            for (i=0; i<numjoinsplits; i++)
                len += iguana_rwjoinsplit(rwflag,&serialized[len],&joinsplit);
            if ( rwflag != 0 )
            {
                memset(joinsplitpubkey,0,sizeof(joinsplitpubkey)); // for now
                memset(joinsplitsig,0,sizeof(joinsplitsig)); // set to actuals
                memcpy(&serialized[len],joinsplitpubkey+1,32), len += 32;
                memcpy(&serialized[len],joinsplitsig,64), len += 64;
            }
            else
            {
                joinsplitpubkey[0] = 0x02; // need to verify its not 0x03
                memcpy(joinsplitpubkey+1,&serialized[len],32), len += 32;
                memcpy(joinsplitsig,&serialized[len],64), len += 64;
            }
        }
    }
    if ( sigser != 0 && vinarray != 0 )
    {
        for (i=0; i<msg->tx_in; i++)
        {
            memset(sigtxid.bytes,0,sizeof(sigtxid));
            if ( vins != 0 && jitem(vins,i) != 0 )
            {
                uint32_t sighash;
                iguana_vinobjset(&msg->vins[i],jitem(vins,i),spendscript,sizeof(spendscript));
                sighash = LP_sighash(symbol,zcash);
                spendamount = LP_outpoint_amount(symbol,msg->vins[i].prev_hash,msg->vins[i].prev_vout);
                sigtxid = bitcoin_sigtxid(symbol,taddr,pubtype,p2shtype,isPoS,height,sigser,maxsize*2,msg,i,msg->vins[i].spendscript,msg->vins[i].spendlen,spendamount,sighash,vpnstr,suppress_pubkeys,zcash);
                //printf("after vini.%d vinscript.%p spendscript.%p spendlen.%d (%s)\n",i,msg->vins[i].vinscript,msg->vins[i].spendscript,msg->vins[i].spendlen,jprint(jitem(vins,i),0));
                if ( iguana_vinarray_check(vinarray,msg->vins[i].prev_hash,msg->vins[i].prev_vout) < 0 )
                    jaddi(vinarray,iguana_vinjson(&msg->vins[i],sigtxid));
                if ( msg->vins[i].spendscript == spendscript )
                    msg->vins[i].spendscript = 0;
            } else if ( iguana_vinarray_check(vinarray,msg->vins[i].prev_hash,msg->vins[i].prev_vout) < 0 )
                jaddi(vinarray,iguana_vinjson(&msg->vins[i],sigtxid));
        }
        free(sigser);
        jadd(json,"vin",vinarray);
        msg->tx_in = cJSON_GetArraySize(vinarray);
        jaddnum(json,"numvins",msg->tx_in);
    }
    if ( voutarray != 0 )
    {
        jadd(json,"vout",voutarray);
        jaddnum(json,"numvouts",msg->tx_out);
    }
    if ( segwitflag == 0 )
        *txidp = bits256_calctxid(symbol,txstart,len);
    if ( json != 0 )
    {
        jaddnum(json,"locktime",msg->lock_time);
        jaddnum(json,"size",len);
        jaddbits256(json,"txid",*txidp);
        //printf("TX.(%s) %p\n",jprint(json,0),json);
    }
    msg->allocsize = len;
    return(len);
}

bits256 iguana_parsetxobj(char *symbol,uint8_t isPoS,int32_t *txstartp,uint8_t *serialized,int32_t maxsize,struct iguana_msgtx *msg,cJSON *txobj,struct vin_info *V)
{
    int32_t i,n,numvins,numvouts,len = 0,rwflag=1; cJSON *array=0; bits256 txid; char vpnstr[64];
    memset(&txid,0,sizeof(txid));
    memset(msg,0,sizeof(*msg));
    *txstartp = 0;
    if ( txobj == 0 )
        return(txid);
    vpnstr[0] = 0;
    if ( (msg->version= juint(txobj,"version")) == 0 )
        msg->version = 1;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->version);
    if ( isPoS != 0 )
    {
        if ( (msg->timestamp= juint(txobj,"timestamp")) == 0 )
            msg->timestamp = (uint32_t)time(NULL);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->timestamp),&msg->timestamp);
    }
    if ( (array= jarray(&numvins,txobj,"vin")) != 0 )
    {
        msg->tx_in = numvins;
        len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_in);
        if ( len + sizeof(struct iguana_msgvin)*msg->tx_in > maxsize )
            return(txid);
        maxsize -= (sizeof(struct iguana_msgvin) * msg->tx_in);
        msg->vins = (struct iguana_msgvin *)&serialized[maxsize];
        memset(msg->vins,0,sizeof(struct iguana_msgvin) * msg->tx_in);
        if ( msg->tx_in > 0 && msg->tx_in*sizeof(struct iguana_msgvin) < maxsize )
        {
            for (i=0; i<msg->tx_in; i++)
            {
                n = iguana_parsevinobj(&serialized[len],maxsize,&msg->vins[i],jitem(array,i),V!=0?&V[i]:0);
                //for (j=0; j<8; j++)
                //    printf("%02x",serialized[len+j]);
                //char str[65]; printf(" <- vinobj.%d starts offset.%d %s\n",i,len,bits256_str(str,msg->vins[i].prev_hash));
                len += n;
            }
        }
    }
    if ( (array= jarray(&numvouts,txobj,"vout")) != 0 )
    {
        msg->tx_out = numvouts;
        len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_out);
        if ( len + sizeof(struct iguana_msgvout)*msg->tx_out > maxsize )
            return(txid);
        maxsize -= (sizeof(struct iguana_msgvout) * msg->tx_out);
        msg->vouts = (struct iguana_msgvout *)&serialized[maxsize];
        memset(msg->vouts,0,sizeof(struct iguana_msgvout) * msg->tx_out);
        if ( msg->tx_out > 0 && msg->tx_out*sizeof(struct iguana_msgvout) < maxsize )
        {
            for (i=0; i<msg->tx_out; i++)
            {
                //printf("parsetxobj parsevout.%d starts %d\n",i,len);
                len += iguana_parsevoutobj(&serialized[len],maxsize,&msg->vouts[i],jitem(array,i));
            }
        }
    }
    msg->lock_time = jint(txobj,"locktime");
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->lock_time),&msg->lock_time);
    //msg->txid = jbits256(txobj,"txid");
    *txstartp = 0;
    msg->allocsize = len;
    msg->txid = txid = bits256_calctxid(symbol,serialized,len);
    return(txid);
}

char *iguana_rawtxbytes(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,cJSON *json,struct iguana_msgtx *msgtx,int32_t suppress_pubkeys,int32_t zcash)
{
    int32_t n; char *txbytes = 0,vpnstr[64]; uint8_t *serialized;
    serialized = malloc(IGUANA_MAXPACKETSIZE);
    vpnstr[0] = 0;
    //char str[65]; printf("%d of %d: %s\n",i,msg.txn_count,bits256_str(str,tx.txid));
    if ( (n= iguana_rwmsgtx(symbol,taddr,pubtype,p2shtype,isPoS,height,1,json,serialized,IGUANA_MAXPACKETSIZE,msgtx,&msgtx->txid,vpnstr,0,0,0,suppress_pubkeys,zcash)) > 0 )
    {
        txbytes = malloc(n*2+1);
        init_hexbytes_noT(txbytes,serialized,n);
    }
    free(serialized);
    return(txbytes);
}

char *bitcoin_json2hex(char *symbol,uint8_t isPoS,bits256 *txidp,cJSON *txjson,struct vin_info *V)
{
    int32_t txstart; uint8_t *serialized; struct iguana_msgtx msgtx; char *txbytes = 0;
    if ( txjson == 0 )
    {
        memset(txidp,0,sizeof(*txidp));
        return(0);
    }
    serialized = malloc(IGUANA_MAXPACKETSIZE*1.5);
    *txidp = iguana_parsetxobj(symbol,isPoS,&txstart,serialized,IGUANA_MAXPACKETSIZE*1.5,&msgtx,txjson,V);
    if ( msgtx.allocsize > 0 )
    {
        txbytes = malloc(msgtx.allocsize*2 + 1);
        init_hexbytes_noT(txbytes,&serialized[txstart],msgtx.allocsize);
    } else printf("bitcoin_txtest: zero msgtx allocsize.(%s)\n",jprint(txjson,0));
    free(serialized);
    return(txbytes);
}

cJSON *bitcoin_data2json(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,bits256 *txidp,struct iguana_msgtx *msgtx,uint8_t *extraspace,int32_t extralen,uint8_t *serialized,int32_t len,cJSON *vins,int32_t suppress_pubkeys,int32_t zcash)
{
    int32_t n; char vpnstr[64]; struct iguana_msgtx M; cJSON *txobj;
    if ( serialized == 0 )
        return(0);
    txobj = cJSON_CreateObject();
    if ( msgtx == 0 )
        msgtx = &M;
    memset(msgtx,0,sizeof(M));
    vpnstr[0] = 0;
    memset(txidp,0,sizeof(*txidp));
    if ( (n= iguana_rwmsgtx(symbol,taddr,pubtype,p2shtype,isPoS,height,0,txobj,serialized,len,msgtx,txidp,vpnstr,extraspace,extralen,vins,suppress_pubkeys,zcash)) <= 0 )
    {
        printf("errortxobj.(%s)\n",jprint(txobj,0));
        free_json(txobj);
        txobj = cJSON_CreateObject();
        jaddstr(txobj,"error","couldnt decode transaction");
    }
    //printf("msgtx.(%s)\n",jprint(txobj,0));
    if ( n != len )
    {
        int32_t i;
        for (i=0; i<len&&i<n; i++)
            printf("%02x",serialized[i]);
        printf(" data2json n.%d vs len.%d\n",n,len);
    }
    return(txobj);
}

cJSON *bitcoin_hex2json(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,bits256 *txidp,struct iguana_msgtx *msgtx,char *txbytes,uint8_t *extraspace,int32_t extralen,uint8_t *origserialized,cJSON *vins,int32_t suppress_pubkeys,int32_t zcash)
{
    int32_t len; uint8_t *serialized; cJSON *txobj;
    if ( txbytes == 0 )
        return(0);
    len = (int32_t)strlen(txbytes) >> 1;
    if ( (serialized= origserialized) == 0 )
        serialized = calloc(1,len+4096);
    decode_hex(serialized,len,txbytes);
    txobj = bitcoin_data2json(symbol,taddr,pubtype,p2shtype,isPoS,height,txidp,msgtx,extraspace,extralen,serialized,len,vins,suppress_pubkeys,zcash);
    if ( serialized != origserialized )
        free(serialized);
    return(txobj);
}
