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
#include "exchanges/bitcoin.h"
#include "mini-gmp.h"

#define MAX_SCRIPT_ELEMENT_SIZE 520
#define MAX_OPS_PER_SCRIPT 201 // Maximum number of non-push operations per script
#define MAX_PUBKEYS_PER_MULTISIG 20 // Maximum number of public keys per multisig

#define IGUANA_MAXSTACKITEMS ((int32_t)(IGUANA_MAXSCRIPTSIZE / sizeof(uint32_t)))
#define IGUANA_MAXSTACKDEPTH 128

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

static inline int32_t is_delim(int32_t c)
{
    if ( c == 0 || c == ' ' || c == '\t' || c == '\r' || c == '\n' )
        return(1);
    else return(0);
}

union iguana_stacknum { int32_t val; int64_t val64; uint8_t rmd160[20]; bits256 hash2; uint8_t pubkey[33]; uint8_t sig[74]; };
struct iguana_stackdata { uint8_t *data; uint16_t size; union iguana_stacknum U; };

struct iguana_interpreter
{
    int32_t active,ifdepth,elsedepth,codeseparator,stackdepth,altstackdepth,maxstackdepth;
    int8_t lastpath[IGUANA_MAXSTACKDEPTH];
    cJSON *logarray;
    struct iguana_stackdata stack[];
};
static struct bitcoin_opcode { UT_hash_handle hh; uint8_t opcode,flags,stackitems; int8_t extralen; } *OPTABLE; static char *OPCODES[0x100]; static int32_t OPCODELENS[0x100];

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
        /*if ( numbuf != 0 )
        {
            int32_t i; for (i=0; i<numlen; i++)
                printf("%02x",numbuf[i]);
        } else printf("%lld",(long long)num64);
        printf(" PUSHDATA len.%d\n",numlen);*/
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

int32_t iguana_checksig(struct iguana_info *coin,struct iguana_stackdata pubkeyarg,struct iguana_stackdata sigarg,bits256 sigtxid)
{
    uint8_t pubkey[MAX_SCRIPT_ELEMENT_SIZE],sig[MAX_SCRIPT_ELEMENT_SIZE]; int32_t retval,plen,siglen;
    plen = iguana_databuf(pubkey,pubkeyarg);
    siglen = iguana_databuf(sig,sigarg);
    if ( bitcoin_pubkeylen(pubkey) == plen && plen > 0 && siglen > 0 && siglen < 74 )
    {
        if ( (retval= (bitcoin_verify(coin->ctx,sig,siglen-1,sigtxid,pubkey,plen) == 0)) == 0 )
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

int32_t iguana_checkprivatekey(struct iguana_info *coin,struct iguana_stackdata pubkeyarg,struct iguana_stackdata privkeyarg)
{
    uint8_t pubkey[MAX_SCRIPT_ELEMENT_SIZE],privkey[MAX_SCRIPT_ELEMENT_SIZE],checkpub[33]; int32_t plen,privlen;
    plen = iguana_databuf(pubkey,pubkeyarg);
    privlen = iguana_databuf(privkey,privkeyarg);
    if ( bitcoin_pubkeylen(pubkey) == plen && plen > 0 && privlen == 32 )
    {
        bitcoin_pubkey33(coin->ctx,checkpub,*(bits256 *)privkey);
        return(memcmp(checkpub,pubkey,33) == 0);
    }
    return(0);
}

int32_t iguana_checkschnorrsig(struct iguana_info *coin,int64_t M,struct iguana_stackdata pubkeyarg,struct iguana_stackdata sigarg,bits256 sigtxid)
{
    uint8_t combined_pub[MAX_SCRIPT_ELEMENT_SIZE],sig[MAX_SCRIPT_ELEMENT_SIZE]; int32_t plen,siglen;
    plen = iguana_databuf(combined_pub,pubkeyarg);
    siglen = iguana_databuf(sig,sigarg);
    if ( bitcoin_pubkeylen(combined_pub) == 33 && siglen == 64 )
        return(bitcoin_schnorr_verify(coin->ctx,sig,sigtxid,combined_pub,33) == 0);
    return(0);
}

int32_t iguana_checkmultisig(struct iguana_info *coin,struct iguana_interpreter *stacks,int32_t M,int32_t N,bits256 txhash2)
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
                    if ( bitcoin_verify(coin->ctx,sigs[i],siglens[i]-1,txhash2,pubkeys[j],bitcoin_pubkeylen(pubkeys[j])) == 0 )
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
int32_t iguana_checklocktimeverify(struct iguana_info *coin,int64_t tx_lockval,uint32_t nSequence,struct iguana_stackdata Snum)
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

int32_t iguana_checksequenceverify(struct iguana_info *coin,int64_t nLockTime,uint32_t nSequence,struct iguana_stackdata Snum)
{
    return(0);
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

int32_t iguana_expandscript(struct iguana_info *coin,char *asmstr,int32_t maxlen,uint8_t *script,int32_t scriptlen)
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

cJSON *iguana_spendasm(struct iguana_info *coin,uint8_t *spendscript,int32_t spendlen)
{
    char asmstr[IGUANA_MAXSCRIPTSIZE*2+1]; cJSON *spendasm = cJSON_CreateObject();
    iguana_expandscript(coin,asmstr,sizeof(asmstr),spendscript,spendlen);
    //int32_t i; for (i=0; i<spendlen; i++)
    //    printf("%02x",spendscript[i]);
    //printf(" -> (%s)\n",asmstr);
    jaddstr(spendasm,"interpreter",asmstr);
    return(spendasm);
}

int32_t bitcoin_assembler(struct iguana_info *coin,cJSON *logarray,uint8_t script[IGUANA_MAXSCRIPTSIZE],cJSON *interpreter,int32_t interpret,int64_t nLockTime,struct vin_info *V)
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
        //printf("{%s}\n",str);
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
                            iguana_pushdata(stacks,iguana_checksig(coin,args[1],args[0],V->sigtxid),0,0);
                            break;
                        case IGUANA_OP_CHECKMULTISIG: case IGUANA_OP_CHECKMULTISIGVERIFY:
                            iguana_pushdata(stacks,iguana_checkmultisig(coin,stacks,V->M,V->N,V->sigtxid),0,0);
                            break;
                        case IGUANA_OP_CHECKSCHNORR: case IGUANA_OP_CHECKSCHNORRVERIFY:
                            iguana_pushdata(stacks,iguana_checkschnorrsig(coin,iguana_num(args[2]),args[1],args[0],V->sigtxid),0,0);
                            break;
                        case IGUANA_OP_CHECKPRIVATEKEY: case IGUANA_OP_CHECKPRIVATEKEYVERIFY:
                            iguana_pushdata(stacks,iguana_checkprivatekey(coin,args[1],args[0]),0,0);
                            break;
                    }
                }
                else if ( op->opcode == IGUANA_OP_CHECKLOCKTIMEVERIFY ) // former OP_NOP2
                {
                    if ( V->ignore_cltverr == 0 && iguana_checklocktimeverify(coin,nLockTime,V->sequence,args[0]) < 0 )
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
                    if ( iguana_checksequenceverify(coin,nLockTime,V->sequence,args[0]) < 0 )
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
            printf("Evaluate FALSE, depth.%d errs.%d [0] size.%d num.%d\n",stacks->stackdepth,errs,stacks->stack[0].size,stacks->stack[0].U.val);
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

