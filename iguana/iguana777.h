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

/*
 adding assetchain coin: copy genCOIN to SuperNET/iguana/coins, make a _7776 variant with RELAY=-1 and VALIDATE=0
 copy that into basilisk as coin, changing RELAY -> 0
 */

/*
 To add a new dPoW'ed assetchain with DEX* API support:
 1. add to komodo/src: assetchains, assetchains.old, dpowassets, fiat-cli
 2. add to end of NOTARY_CURRENCIES[] array in fundnotaries (iguana_notary.c)
 3. create fiat/<ac_name>
 4. add to m_notary coins/<ac_name> get gen_acname  from where komodod was launched, change RELAY:-1 and port to 7776 and make <ac_name>_7776 variant
 5. make coins/basilisk/<ac_name>
 6. launch from a single node with -gen, launch a second node using -addnode=<ipaddr of 1st node> but without -gen
 7. from a single node, fundnotaries <ac_name> to get notaries able to dPoW
 8. m_splitfunds
 
 */

#ifndef iguana777_net_h
#define iguana777_net_h

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32
#define WIN32
#endif
#endif

#if (defined(_WIN32) || defined(__WIN32__)) && \
!defined(WIN32) && !defined(__SYMBIAN32__)
#ifndef WIN32
#define WIN32
#endif
#endif

#ifdef WIN32
#define __MINGW


#else
#ifndef __MINGW
#include <arpa/inet.h>
#endif
#endif

#define LOCKTIME_THRESHOLD 500000000
#define KOMODO_INTEREST ((uint64_t)(0.05 * SATOSHIDEN))   // 5% CANNOT CHANGE as komodo_interest.h div 20

//#define BTC2_VERSION
#define BTC2_HARDFORK_HEIGHT 444444
#define BTC2_SIGHASH_FORKID 0xcf
#define BTC2_NETMAGIC 0xaabbccdd
#define BTC2_DEFAULT_PORT 8222
#define BTC2_DIFF_WINDOW 60

/*#ifdef __APPLE__
#define ISNOTARYNODE 1
#include "nn.h"
#include "bus.h"
#else*/
//#ifdef __APPLE__
#if defined(__APPLE__) || defined(WIN32) || defined(USE_STATIC_NANOMSG)
#include "../crypto777/nanosrc/nn.h"
#include "../crypto777/nanosrc/bus.h"
#include "../crypto777/nanosrc/pubsub.h"
#include "../crypto777/nanosrc/pipeline.h"
#include "../crypto777/nanosrc/reqrep.h"
#include "../crypto777/nanosrc/tcp.h"
#else
#include "/usr/local/include/nanomsg/nn.h"
#include "/usr/local/include/nanomsg/bus.h"
#include "/usr/local/include/nanomsg/pubsub.h"
#include "/usr/local/include/nanomsg/pipeline.h"
#include "/usr/local/include/nanomsg/reqrep.h"
#include "/usr/local/include/nanomsg/tcp.h"
#endif

struct supernet_info;
struct exchange_info;

#include "../crypto777/OS_portable.h"
#include "../datachain/datachain.h"

#include "../includes/iguana_defines.h"
#include "../includes/iguana_types.h"
#include "../includes/iguana_structs.h"
#include "../basilisk/basilisk.h"
#include "dPoW.h"

struct supernet_address
{
    bits256 pubkey,iphash,persistent;
    uint32_t selfipbits,myipbits; int32_t confirmed,totalconfirmed; uint64_t nxt64bits;
    char NXTADDR[32],BTC[64],BTCD[64];
};

struct smartaddress_symbol { double maxbid,minask,srcavail,destamount; char symbol[16]; };

struct smartaddress
{
    bits256 privkey,pubkey;
    int32_t numsymbols;
    uint8_t pubkey33[33],rmd160[20];
    char typestr[16];
    struct smartaddress_symbol *symbols;
};

struct pending_trade { UT_hash_handle hh; double basevolume,relvolume,dir; char base[32],rel[32]; };

#define PSOCK_IDLETIMEOUT 600
struct psock { uint32_t lasttime; int32_t pullsock,pubsock; uint16_t pushport,subport; };

#define JUMBLR_DEPOSITPREFIX "deposit "
struct jumblr_item
{
    UT_hash_handle hh;
    int64_t amount,fee,txfee;
    uint32_t spent,pad;
    char opid[64],src[128],dest[128],status;
};

struct liquidity_info
{
    char base[16],rel[16],exchange[16];
    uint64_t assetid;
    double profit,refprice,bid,ask,minvol,maxvol,totalvol;
};

struct message_info { int32_t msgcount; bits256 refhash,msghashes[64]; uint32_t timestamps[64]; };

struct supernet_info
{
    struct supernet_address myaddr;
    bits256 persistent_priv,privkey,jumblr_pubkey,jumblr_depositkey;
    uint8_t persistent_pubkey33[33];
    char ipaddr[64],NXTAPIURL[512],secret[4096],password[4096],rpcsymbol[64],handle[1024],permanentfile[1024],jumblr_passphrase[1024];
    char *decryptstr;
    void (*liquidity_command)(struct supernet_info *myinfo,char *base,bits256 hash,cJSON *vals);
    double (*liquidity_active)(struct supernet_info *myinfo,double *refpricep,char *exchange,char *base,char *rel,double volume);
    int32_t maxdelay,IAMRELAY,IAMNOTARY,IAMLP,publicRPC,basilisk_busy,genesisresults,remoteorigin;
    uint32_t expiration,dirty,DEXactive,DEXpoll,totalcoins,nanoinit,lastdexrequestid,dexcrcs[1024];
    uint16_t argport,rpcport;
    struct basilisk_info basilisks;
    struct jumblr_item *jumblrs;
    struct exchange_info *tradingexchanges[SUPERNET_MAXEXCHANGES]; int32_t numexchanges;
    struct iguana_waccount *wallet;
    struct iguana_info *allcoins; int32_t allcoins_being_added,allcoins_numvirts;
    portable_mutex_t bu_mutex,allcoins_mutex,gecko_mutex,basilisk_mutex,DEX_mutex,DEX_reqmutex,DEX_swapmutex,smart_mutex,MoM_mutex;
    struct queueitem *DEX_quotes; cJSON *Cunspents,*Cspends;
    struct basilisk_swap *swaps[256]; int32_t numswaps;
    struct basilisk_message *messagetable; portable_mutex_t messagemutex; queue_t msgQ,p2pQ;
    void *ctx;
    uint8_t *pingbuf;
    struct basilisk_request DEXaccept;
    FILE *dexfp;
    struct dpow_info *DPOWS[8192]; int32_t numdpows,dpowsock,dexsock,pubsock,repsock,subsock,reqsock;
    struct delayedPoW_info dPoW;
    struct basilisk_spend *spends; int32_t numspends;
    char bindaddr[64];
    char blocktrail_apikey[256];
	struct peggy_info *PEGS;
    void *PAXDATA;
    struct liquidity_info linfos[512]; cJSON *liquidity_currencies; struct pending_trade *trades; portable_mutex_t pending_mutex;
    struct komodo_notaries NOTARY;
    char seedipaddr[64]; uint32_t dpowipbits[128]; int32_t numdpowipbits; portable_mutex_t notarymutex,dpowmutex;
#ifdef NOTARY_TESTMODE
    char dexseed_ipaddrs[1][64];
#else
    char dexseed_ipaddrs[8][64];
#endif
    uint32_t dexipbits[128]; int32_t numdexipbits; portable_mutex_t dexmutex;
    // compatibility
    bits256 pangea_category,instantdex_category;
    uint8_t logs[256],exps[510];
    struct message_info msgids[8192];
    double *svmfeatures;
    uint16_t psockport,numpsocks; struct psock *PSOCKS; portable_mutex_t psockmutex;
    uint8_t notaries[64][33]; int32_t numnotaries,DEXEXPLORER;
    FILE *swapsfp;
    double DEXratio;
    struct smartaddress smartaddrs[64]; int32_t numsmartaddrs,cancelrefresh,runsilent,DEXtrades;
    int32_t nosplit;
};

struct basilisk_swapmessage
{
    bits256 srchash,desthash;
    uint32_t crc32,msgbits,quoteid,datalen;
    uint8_t *data;
};

struct basilisk_swap
{
    struct supernet_info *myinfoptr; struct iguana_info *bobcoin,*alicecoin;
    void (*balancingtrade)(struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t iambob);
    int32_t subsock,pushsock,connected,aliceunconf,depositunconf,paymentunconf; uint32_t lasttime,aborted;
    FILE *fp;
    bits256 persistent_privkey,persistent_pubkey;
    struct basilisk_swapinfo I;
    struct basilisk_rawtx bobdeposit,bobpayment,alicepayment,myfee,otherfee,aliceclaim,alicespend,bobreclaim,bobspend,bobrefund,alicereclaim;
    bits256 privkeys[INSTANTDEX_DECKSIZE];
    struct basilisk_swapmessage *messages; int32_t nummessages;
    char Bdeposit[64],Bpayment[64];
    uint64_t otherdeck[INSTANTDEX_DECKSIZE][2],deck[INSTANTDEX_DECKSIZE][2];
    uint8_t persistent_pubkey33[33],pad[15],verifybuf[65536];

};

#include "../includes/iguana_funcs.h"
#include "../includes/iguana_globals.h"
#include "../gecko/gecko.h"

#ifndef MAX
#define MAX(a,b) ((a) >= (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#endif
