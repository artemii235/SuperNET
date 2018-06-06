
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
//  LP_include.h
//  marketmaker
//

#ifndef LP_INCLUDE_H
#define LP_INCLUDE_H

#ifndef LP_TECHSUPPORT
#define LP_TECHSUPPORT 1
#endif

#define LP_DONT_CMDCHANNEL

#ifdef FROMGUI
#define printf dontprintf
//#define fprintf fdontprintf dont do this!

void dontprintf(char *formatstr,...) {}
//void fdontprintf(FILE *fp,char *formatstr,...) {}
#endif

#define LP_MAJOR_VERSION "0"
#define LP_MINOR_VERSION "1"
#define LP_BUILD_NUMBER "27774"
#define LP_BARTERDEX_VERSION 1
#define LP_MAGICBITS 1

#define LP_DONT_IMPORTPRIVKEY

#ifdef FROM_JS
#include <emscripten.h>
#define sleep(x) emscripten_usleep((x) * 1000000)
void emscripten_usleep(int32_t x); // returns immediate, no sense for sleeping
#define usleep(x) emscripten_usleep(x)
// ./autogen.sh
// emconfigure ./configure CFLAGS="-s PTHREAD_POOL_SIZE=8 -s USE_PTHREADS=1 -O2"
// Edit src/core/sock.c and add here #include <limits.h> for INT_MAX support
// emmake make
// cp .libs/libnanomsg.a ~/SuperNET/OSlibs/js
#endif
//#define LP_STRICTPEERS

//#define LP_DISABLE_DISTCOMBINE

#define LP_MAXVINS 64
#define LP_HTTP_TIMEOUT 3 // 1 is too small due to edge cases of time(NULL)
#define LP_AUTOTRADE_TIMEOUT 30
#define LP_RESERVETIME (LP_AUTOTRADE_TIMEOUT * 3)
#define ELECTRUM_TIMEOUT 13
#define LP_ELECTRUM_KEEPALIVE 60
#define LP_ELECTRUM_MAXERRORS 777
#define LP_MEMPOOL_TIMEINCR 10
#define LP_SCREENWIDTH 1024

#define LP_MIN_PEERS 8
#define LP_MAX_PEERS 32

#define LP_MAXDESIRED_UTXOS (IAMLP != 0 ? 256 : 64)
#define LP_MINDESIRED_UTXOS (IAMLP != 0 ? 64 : 16)
#define LP_DUSTCOMBINE_THRESHOLD 1000000

// RTmetrics
#define LP_RTMETRICS_TOPGROUP 1.01
//#define LP_MAXPENDING_SWAPS 13
#define LP_CLIENT_STATSPARSE (90 * 1024 * 1024)

#define LP_COMMAND_SENDSOCK NN_PUSH
#define LP_COMMAND_RECVSOCK NN_PULL

#define DPOW_MIN_ASSETCHAIN_SIGS 11
#define LP_ENCRYPTED_MAXSIZE (16384 + 2 + crypto_box_NONCEBYTES + crypto_box_ZEROBYTES)

#define LP_MAXPUBKEY_ERRORS 10
#define PSOCK_KEEPALIVE 3600
#define MAINLOOP_PERSEC 100
#define MAX_PSOCK_PORT 60000
#define MIN_PSOCK_PORT 10000
#define LP_GETINFO_INCR 30
#define LP_ORDERBOOK_DURATION 180

#define LP_MAXPEER_ERRORS 3
#define LP_MINPEER_GOOD 20
#define LP_PEERGOOD_ERRORDECAY 0.9

#define LP_SWAPSTEP_TIMEOUT 30
#define LP_MIN_TXFEE 1000
#define LP_MINVOL 100
#define LP_MINCLIENTVOL 1000
#define LP_MINSIZE_TXFEEMULT 10
#define LP_REQUIRED_TXFEE 0.75

#define LP_DEXFEE(destsatoshis) ((destsatoshis) / INSTANTDEX_INSURANCEDIV)
#define LP_DEPOSITSATOSHIS(satoshis) ((satoshis) + (satoshis >> 3))

#define INSTANTDEX_DECKSIZE 1000
#define INSTANTDEX_LOCKTIME (3600*2 + 300*2)
#define INSTANTDEX_INSURANCEDIV 777
#define INSTANTDEX_PUBKEY "03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06"
#define INSTANTDEX_RMD160 "ca1e04745e8ca0c60d8c5881531d51bec470743f"
#define JUMBLR_RMD160 "5177f8b427e5f47342a4b8ab5dac770815d4389e"
#define TIERNOLAN_RMD160 "daedddd8dbe7a2439841ced40ba9c3d375f98146"
#define INSTANTDEX_BTC "1KRhTPvoxyJmVALwHFXZdeeWFbcJSbkFPu"
#define INSTANTDEX_KMD "RThtXup6Zo7LZAi8kRWgjAyi1s4u6U9Cpf"
#define BOTS_BONDADDRESS "RNdqHx26GWy9bk8MtmH1UiXjQcXE4RKK2P"
#define BOTS_BONDPUBKEY33 "03e641d22e1ff5a7d45c8880537e0b0a114d7b9fee2c18a6b4a8a80b6285292990"
#define LP_WEEKMULTBAD (7 * 24 * 2600)
#define LP_WEEKMULT (7 * 24 * 3600)
#define LP_FIRSTWEEKTIME 1510790400 // must be 0 mod LP_WEEKMULT

//#define BASILISK_DISABLEWAITTX
//#define BASILISK_DISABLESENDTX
#define LP_RPCPORT 7783

#define LP_PROPAGATION_SLACK 100 // txid ordering is not enforced, so getting extra recent txid
#define LP_AVETXSIZE 256
#define LP_CACHEDURATION 60
#define BASILISK_DEFAULT_NUMCONFIRMS 1
#define BASILISK_DEFAULT_MAXCONFIRMS 6
#define DEX_SLEEP 3
#define BASILISK_KEYSIZE ((int32_t)(2*sizeof(bits256)+sizeof(uint32_t)*2))

#define LP_IS_ZCASHPROTOCOL 1
#define LP_IS_BITCOINCASH 2
#define LP_IS_BITCOINGOLD 79

#define SIGHASH_FORKID 0x40
#define ZKSNARK_PROOF_SIZE 296
#define ZCASH_SOLUTION_ELEMENTS 1344

#define LP_REQUEST 0
#define LP_RESERVED 1
#define LP_CONNECT 2
#define LP_CONNECTED 3

#define LP_DONTCHANGE_ERRMSG0 "couldnt find coin locally installed"
#define LP_DONTCHANGE_ERRMSG1 "coin is disabled"

extern char GLOBAL_DBDIR[];
extern int32_t IAMLP;

struct iguana_msgvin
{
    bits256 prev_hash;
    uint8_t *vinscript,*userdata,*spendscript,*redeemscript;
    uint32_t prev_vout,sequence; uint16_t scriptlen,p2shlen,userdatalen,spendlen;
};

struct iguana_msgvout { uint64_t value; uint32_t pk_scriptlen; uint8_t *pk_script; };

struct iguana_msgtx
{
    uint32_t version,tx_in,tx_out,lock_time;
    struct iguana_msgvin *vins;
    struct iguana_msgvout *vouts;
    bits256 txid;
    int32_t allocsize,timestamp,numinputs,numoutputs;
    int64_t inputsum,outputsum,txfee;
    uint8_t *serialized;
};

struct iguana_msgjoinsplit
{
    uint64_t vpub_old,vpub_new;
    bits256 anchor,nullifiers[2],commitments[2],ephemeralkey;
    bits256 randomseed,vmacs[2];
    uint8_t zkproof[ZKSNARK_PROOF_SIZE];
    uint8_t ciphertexts[2][601];
};

struct vin_signer { bits256 privkey; char coinaddr[64]; uint8_t siglen,sig[80],rmd160[20],pubkey[66]; };

struct vin_info
{
    struct iguana_msgvin vin; uint64_t amount; cJSON *extras; bits256 sigtxid;
    int32_t M,N,validmask,spendlen,type,p2shlen,numpubkeys,numsigs,height,userdatalen,suppress_pubkeys,ignore_cltverr;
    uint32_t sequence,unspentind,hashtype; struct vin_signer signers[16]; char coinaddr[65];
    uint8_t rmd160[20],spendscript[10000],p2shscript[10000],userdata[10000];
};

/*struct basilisk_swapmessage
{
    bits256 srchash,desthash;
    uint32_t crc32,msgbits,quoteid,datalen;
    uint8_t *data;
};*/

struct basilisk_swap;

struct basilisk_rawtxinfo
{
    char destaddr[64],ethTxid[75];
    bits256 txid,signedtxid,actualtxid;
    int64_t amount,change,inputsum;
    int32_t redeemlen,datalen,completed,vintype,vouttype,numconfirms,spendlen,secretstart,suppress_pubkeys;
    uint32_t locktime,crcs[2];
    uint8_t addrtype,pubkey33[33],rmd160[20];
};

struct basilisk_request
{
    uint32_t requestid,timestamp,quoteid,quotetime; // 0 to 15
    int64_t srcamount,unused; // 16 to 31
    bits256 srchash; // 32 to 63
    bits256 desthash;
    char src[68],dest[68];
    uint64_t destamount;
    int32_t optionhours,DEXselector;
};

struct basilisk_rawtx
{
    char name[32],symbol[65];
    struct iguana_msgtx msgtx;
    struct basilisk_rawtxinfo I;
    char vinstr[8192],p2shaddr[64];
    cJSON *vins;
    bits256 utxotxid; int32_t utxovout;
    uint8_t txbytes[16384],spendscript[512],redeemscript[1024],extraspace[4096],pubkey33[33];
};

struct basilisk_swapinfo
{
    struct basilisk_request req;
    char bobstr[128],alicestr[128],bobtomic[64],alicetomic[64],etomicsrc[65],etomicdest[65];
    bits256 myhash,otherhash,orderhash;
    uint32_t statebits,otherstatebits,started,expiration,finished,dead,reftime,putduration,callduration;
    int32_t bobconfirms,aliceconfirms,iambob,reclaimed,bobspent,alicespent,pad,aliceistrusted,bobistrusted,otheristrusted,otherstrust,alicemaxconfirms,bobmaxconfirms;
    int64_t alicesatoshis,bobsatoshis,bobinsurance,aliceinsurance,Atxfee,Btxfee;
    
    bits256 myprivs[2],mypubs[2],otherpubs[2],pubA0,pubA1,pubB0,pubB1,privAm,pubAm,privBn,pubBn;
    uint32_t crcs_mypub[2],crcs_mychoosei[2],crcs_myprivs[2],crcs_mypriv[2];
    int32_t choosei,otherchoosei,cutverified,otherverifiedcut,numpubs,havestate,otherhavestate,pad2;
    uint8_t secretAm[20],secretBn[20];
    uint8_t secretAm256[32],secretBn256[32];
    uint8_t userdata_aliceclaim[256],userdata_aliceclaimlen;
    uint8_t userdata_alicereclaim[256],userdata_alicereclaimlen;
    uint8_t userdata_alicespend[256],userdata_alicespendlen;
    uint8_t userdata_bobspend[256],userdata_bobspendlen;
    uint8_t userdata_bobreclaim[256],userdata_bobreclaimlen;
    uint8_t userdata_bobrefund[256],userdata_bobrefundlen;
};

#define BASILISK_ALICESPEND 0
#define BASILISK_BOBSPEND 1
#define BASILISK_BOBPAYMENT 2
#define BASILISK_ALICEPAYMENT 3
#define BASILISK_BOBDEPOSIT 4
#define BASILISK_OTHERFEE 5
#define BASILISK_MYFEE 6
#define BASILISK_BOBREFUND 7
#define BASILISK_BOBRECLAIM 8
#define BASILISK_ALICERECLAIM 9
#define BASILISK_ALICECLAIM 10
//0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0
static char *txnames[] = { "alicespend", "bobspend", "bobpayment", "alicepayment", "bobdeposit", "otherfee", "myfee", "bobrefund", "bobreclaim", "alicereclaim", "aliceclaim" };

struct LP_swap_remember
{
    bits256 pubA0,pubB0,pubB1,privAm,privBn,paymentspent,Apaymentspent,depositspent,myprivs[2],txids[sizeof(txnames)/sizeof(*txnames)];
    uint64_t Atxfee,Btxfee,srcamount,destamount,aliceid;
    int64_t values[sizeof(txnames)/sizeof(*txnames)];
    uint32_t finishtime,tradeid,requestid,quoteid,plocktime,dlocktime,expiration,state,otherstate;
    int32_t iambob,finishedflag,origfinishedflag,Predeemlen,Dredeemlen,sentflags[sizeof(txnames)/sizeof(*txnames)];
    uint8_t secretAm[20],secretAm256[32],secretBn[20],secretBn256[32],Predeemscript[1024],Dredeemscript[1024],pubkey33[33],other33[33];
    char uuidstr[65],Agui[65],Bgui[65],gui[65],src[65],dest[65],bobtomic[128],alicetomic[128],etomicsrc[65],etomicdest[65],destaddr[64],Adestaddr[64],Sdestaddr[64],alicepaymentaddr[64],bobpaymentaddr[64],bobdepositaddr[64],alicecoin[65],bobcoin[65],*txbytes[sizeof(txnames)/sizeof(*txnames)],bobDepositEthTx[75],bobPaymentEthTx[75],alicePaymentEthTx[75];
};

struct LP_outpoint
{
    bits256 spendtxid;
    uint64_t value,interest;
    int32_t spendvini,spendheight;
    char coinaddr[64];
};

struct LP_transaction
{
    UT_hash_handle hh;
    bits256 txid;
    long fpos;
    int32_t height,numvouts,numvins,len,SPV;
    uint8_t *serialized;
    struct LP_outpoint outpoints[];
};

struct iguana_info
{
    UT_hash_handle hh;
    portable_mutex_t txmutex,addrmutex,addressutxo_mutex; struct LP_transaction *transactions; struct LP_address *addresses;
    uint64_t txfee;
    int32_t numutxos,notarized,longestchain,firstrefht,firstscanht,lastscanht,height; uint16_t busport,did_addrutxo_reset;
    uint32_t txversion,dPoWtime,lastautosplit,lastresetutxo,loadedcache,electrumlist,lastunspent,importedprivkey,lastpushtime,lastutxosync,addr_listunspent_requested,lastutxos,updaterate,counter,inactive,lastmempool,lastgetinfo,ratetime,heighttime,lastmonitor,obooktime;
    uint8_t pubtype,p2shtype,isPoS,wiftype,wiftaddr,taddr,noimportprivkey_flag,userconfirms,isassetchain,maxconfirms;
    char symbol[128],smartaddr[64],userpass[1024],serverport[128],instantdex_address[64],estimatefeestr[32],getinfostr[32],etomic[64],validateaddress[64];
    // portfolio
    double price_kmd,force,perc,goal,goalperc,relvolume,rate;
    void *electrum; void *ctx;
    uint64_t maxamount,kmd_equiv,balanceA,balanceB,valuesumA,valuesumB;
    uint8_t pubkey33[33],zcash;
    int32_t privkeydepth;
    bits256 cachedtxid,notarizationtxid; uint8_t *cachedtxiddata; int32_t cachedtxidlen;
    bits256 cachedmerkle,notarizedhash; int32_t cachedmerkleheight;
};

struct _LP_utxoinfo { bits256 txid; uint64_t value; int32_t vout,height; };

struct LP_utxostats { uint32_t sessionid,lasttime,errors,swappending,spentflag,lastspentcheck,bestflag; };

struct LP_utxobob { struct _LP_utxoinfo utxo,deposit; };

struct LP_utxoalice { struct _LP_utxoinfo utxo,fee; };

//struct LP_utxoswap { bits256 otherpubkey; uint64_t satoshis; };

struct LP_utxoinfo
{
    UT_hash_handle hh,hh2;
    bits256 pubkey;
    struct _LP_utxoinfo payment,deposit,fee;
    struct LP_utxostats T;
    int64_t swap_satoshis;
    //struct LP_utxoswap S;
    int32_t iambob,iamlp;
    uint8_t key[sizeof(bits256) + sizeof(int32_t)];
    uint8_t key2[sizeof(bits256) + sizeof(int32_t)];
    char coin[65],coinaddr[64],gui[16];//spendscript[256];
};

struct LP_address_utxo
{
    struct LP_address_utxo *next,*prev;
    struct _LP_utxoinfo U;
    int32_t SPV,spendheight;
    //uint32_t timestamp;
};

struct LP_address
{
    UT_hash_handle hh;
    struct LP_address_utxo *utxos;
    bits256 pubkey;
    int64_t balance,total,instantdex_credits;
    uint32_t timestamp,n,unspenttime,instantdextime;
    int32_t unspentheight;
    char coinaddr[64];
    uint8_t pubsecp[33],didinstantdex;
};

struct LP_peerinfo
{
    UT_hash_handle hh;
    bits256 pubkey;
    uint64_t ip_port;
    uint32_t recvtime,numrecv,ipbits,errortime,errors,numpeers,needping,lasttime,connected,lastutxos,lastpeers,diduquery,good,sessionid;
    int32_t pushsock,subsock,isLP,pairsock;
    uint16_t port,netid;
    char ipaddr[64];
};

struct LP_quoteinfo
{
    struct basilisk_request R;
    bits256 srchash,desthash,txid,txid2,desttxid,feetxid,privkey;
    int64_t othercredits;
    uint64_t satoshis,txfee,destsatoshis,desttxfee,aliceid;
    uint32_t timestamp,quotetime,tradeid;
    int32_t vout,vout2,destvout,feevout,pair;
    char srccoin[65],coinaddr[64],destcoin[65],destaddr[64],gui[64],etomicsrc[65],etomicdest[65],uuidstr[65];
};

struct LP_endpoint { int32_t pair; char ipaddr[64]; uint16_t port; };

struct basilisk_swap
{
    void *ctx; //struct LP_utxoinfo *utxo;
    struct LP_endpoint N;
    void (*balancingtrade)(struct basilisk_swap *swap,int32_t iambob);
    int32_t subsock,pushsock,connected,aliceunconf,depositunconf,paymentunconf;
    uint32_t lasttime,aborted,tradeid,received;
    FILE *fp;
    bits256 persistent_privkey,persistent_pubkey;
    struct basilisk_swapinfo I;
    struct basilisk_rawtx bobdeposit,bobpayment,alicepayment,myfee,otherfee,aliceclaim,alicespend,bobreclaim,bobspend,bobrefund,alicereclaim;
    bits256 privkeys[INSTANTDEX_DECKSIZE];
    //struct basilisk_swapmessage *messages; int32_t nummessages,sentflag;
    char Bdeposit[64],Bpayment[64],uuidstr[65];
    uint64_t aliceid,otherdeck[INSTANTDEX_DECKSIZE][2],deck[INSTANTDEX_DECKSIZE][2];
    uint8_t persistent_pubkey33[33],persistent_other33[33],changermd160[20],pad[15],verifybuf[100000];
};

struct LP_pubkey_quote
{
    struct LP_pubkey_quote *next,*prev;
    float price;
    uint32_t maxutxo,aveutxo;
    uint8_t baseind,relind,numutxos,scale;
};

struct LP_swapstats
{
    UT_hash_handle hh;
    struct LP_quoteinfo Q;
    bits256 bobdeposit,alicepayment,bobpayment,paymentspent,Apaymentspent,depositspent;
    int32_t bobdeposit_ht,alicepayment_ht,bobpayment_ht,paymentspent_ht,Apaymentspent_ht,depositspent_ht;
    double qprice;
    uint64_t aliceid;
    int32_t bobneeds_dPoW,aliceneeds_dPoW;
    uint32_t ind,methodind,finished,expired,lasttime,dPoWfinished;
    char alicegui[65],bobgui[65];
};

struct LP_pubswap { struct LP_pubswap *next,*prev; struct LP_swapstats *swap; };

#define LP_MAXPRICEINFOS 256
struct LP_pubkey_info
{
    UT_hash_handle hh;
    bits256 pubkey;
    struct LP_pubkey_quote *quotes;
    struct LP_pubswap *bobswaps,*aliceswaps;
    int64_t dynamictrust,unconfcredits;
    uint32_t timestamp,numerrors,lasttime,slowresponse;
    int32_t istrusted,pairsock;
    uint8_t rmd160[20],sig[65],pubsecp[33],siglen;
};

struct electrum_info
{
    queue_t sendQ,pendingQ;
    portable_mutex_t mutex,txmutex;
    struct electrum_info *prev;
    int32_t bufsize,sock,*heightp,numerrors;
    struct iguana_info *coin;
    uint32_t stratumid,lasttime,keepalive,pending,*heighttimep;
    char ipaddr[64],symbol[66];
    uint16_t port;
    uint8_t buf[];
};

struct LP_trade
{
    struct LP_trade *next,*prev;
    UT_hash_handle hh;
    uint64_t aliceid;
    int64_t besttrust,bestunconfcredits;
    double bestprice;
    uint32_t negotiationdone,bestresponse,connectsent,firsttime,lasttime,firstprocessed,lastprocessed,newtime,cancelled;
    char pairstr[64],funcid,iambob;
    struct LP_quoteinfo Qs[4],Q;
};

uint32_t LP_sighash(char *symbol,int32_t zcash);
int32_t LP_pubkey_sigcheck(struct LP_pubkey_info *pubp,cJSON *item);
int32_t LP_pubkey_sigadd(cJSON *item,uint32_t timestamp,bits256 priv,bits256 pub,uint8_t *rmd160,uint8_t *pubsecp);
int32_t LP_quoteparse(struct LP_quoteinfo *qp,cJSON *argjson);
struct LP_address *LP_address(struct iguana_info *coin,char *coinaddr);
void LP_swap_coinaddr(struct iguana_info *coin,char *coinaddr,uint64_t *valuep,uint8_t *data,int32_t datalen,int32_t vout);
void basilisk_dontforget_update(struct basilisk_swap *swap,struct basilisk_rawtx *rawtx);
uint32_t basilisk_requestid(struct basilisk_request *rp);
uint32_t basilisk_quoteid(struct basilisk_request *rp);
struct basilisk_swap *LP_swapinit(int32_t iambob,int32_t optionduration,bits256 privkey,struct basilisk_request *rp,struct LP_quoteinfo *qp,int32_t dynamictrust);
char *bitcoind_passthru(char *coinstr,char *serverport,char *userpass,char *method,char *params);
uint32_t LP_swapdata_rawtxsend(int32_t pairsock,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx,uint32_t nextbits,int32_t suppress_swapsend);
int32_t LP_rawtx_spendscript(struct basilisk_swap *swap,int32_t height,struct basilisk_rawtx *rawtx,int32_t v,uint8_t *recvbuf,int32_t recvlen,int32_t suppress_pubkeys);
void LP_quotesinit(char *base,char *rel);
int32_t LP_forward(void *ctx,char *myipaddr,int32_t pubsock,bits256 pubkey,char *jsonstr,int32_t freeflag);
struct LP_peerinfo *LP_peerfind(uint32_t ipbits,uint16_t port);
uint64_t LP_value_extract(cJSON *obj,int32_t addinterest,bits256 txid);
int32_t LP_swap_getcoinaddr(char *symbol,char *coinaddr,bits256 txid,int32_t vout);
char *LP_command_process(void *ctx,char *myipaddr,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen,int32_t stats_JSONonly);
int64_t LP_kmdvalue(char *symbol,int64_t satoshis);
int64_t LP_komodo_interest(bits256 txid,int64_t value);
void LP_availableset(bits256 txid,int32_t vout);
int32_t LP_iseligible(uint64_t *valp,uint64_t *val2p,int32_t iambob,char *symbol,bits256 txid,int32_t vout,uint64_t satoshis,bits256 txid2,int32_t vout2);
int32_t LP_pullsock_check(void *ctx,char **retstrp,char *myipaddr,int32_t pubsock,int32_t pullsock);
int64_t LP_listunspent_parseitem(struct iguana_info *coin,bits256 *txidp,int32_t *voutp,int32_t *heightp,cJSON *item);
void LP_unspents_cache(char *symbol,char *addr,char *arraystr,int32_t updatedflag);
uint16_t LP_psock_get(char *connectaddr,char *publicaddr,int32_t ispaired,int32_t cmdchannel,char *ipaddr);
void LP_failedmsg(uint32_t requestid,uint32_t quoteid,double val,char *uuidstr);
//void LP_utxo_clientpublish(struct LP_utxoinfo *utxo);
//int32_t LP_coinbus(uint16_t coin_busport);
int32_t LP_nanomsg_recvs(void *ctx);
int32_t LP_numconfirms(char *symbol,char *coinaddr,bits256 txid,int32_t vout,int32_t mempool);
void LP_aliceid(uint32_t tradeid,uint64_t aliceid,char *event,uint32_t requestid,uint32_t quoteid);
void LP_autoprices_update(char *method,char *base,double basevol,char *rel,double relvol);
cJSON *LP_cache_transaction(struct iguana_info *coin,bits256 txid,uint8_t *serialized,int32_t len);
uint64_t LP_balance(uint64_t *valuep,int32_t iambob,char *symbol,char *coinaddr);
cJSON *LP_transaction_fromdata(struct iguana_info *coin,bits256 txid,uint8_t *serialized,int32_t len);
uint64_t LP_RTsmartbalance(struct iguana_info *coin);
int32_t LP_getheight(int32_t *notarizedp,struct iguana_info *coin);
int32_t LP_reserved_msg(int32_t priority,char *base,char *rel,bits256 pubkey,char *msg);
struct iguana_info *LP_coinfind(char *symbol);
int32_t LP_crc32find(int32_t *duplicatep,int32_t ind,uint32_t crc32);
char *LP_pricepings(void *ctx,char *myipaddr,int32_t pubsock,char *base,char *rel,double price);
int32_t LP_merkleproof(struct iguana_info *coin,char *coinaddr,struct electrum_info *ep,bits256 txid,int32_t height);
cJSON *electrum_address_gethistory(char *symbol,struct electrum_info *ep,cJSON **retjsonp,char *addr,bits256 reftxid);
cJSON *LP_myzdebits();
int32_t LP_opreturn_decrypt(uint16_t *ind16p,uint8_t *decoded,uint8_t *encoded,int32_t encodedlen,char *passphrase);
int32_t LP_opreturn_encrypt(uint8_t *dest,int32_t maxsize,uint8_t *data,int32_t datalen,char *passphrase,uint16_t ind16);
void LP_pendswap_add(uint32_t expiration,uint32_t requestid,uint32_t quoteid);
int32_t _LP_utxos_remove(bits256 txid,int32_t vout);
int32_t LP_utxos_remove(bits256 txid,int32_t vout);
struct LP_transaction *LP_transactionadd(struct iguana_info *coin,bits256 txid,int32_t height,int32_t numvouts,int32_t numvins);
char *bitcoin_address(char *symbol,char *coinaddr,uint8_t taddr,uint8_t addrtype,uint8_t *pubkey_or_rmd160,int32_t len);
void LP_tradebot_finished(uint32_t tradeid,uint32_t requestid,uint32_t quoteid);
uint64_t LP_txfeecalc(struct iguana_info *coin,uint64_t txfee,int32_t txlen);
struct LP_address *_LP_address(struct iguana_info *coin,char *coinaddr);
struct LP_address *_LP_addressfind(struct iguana_info *coin,char *coinaddr);
struct LP_address *_LP_addressadd(struct iguana_info *coin,char *coinaddr);
int32_t iguana_signrawtransaction(void *ctx,char *symbol,uint8_t wiftaddr,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,struct iguana_msgtx *msgtx,char **signedtxp,bits256 *signedtxidp,struct vin_info *V,int32_t numinputs,char *rawtx,cJSON *vins,cJSON *privkeysjson,int32_t zcash);
//void LP_butxo_swapfields_set(struct LP_utxoinfo *butxo);
struct LP_address_utxo *LP_address_utxofind(struct iguana_info *coin,char *coinaddr,bits256 txid,int32_t vout);
int64_t LP_myzcredits();
void HashKeccak(uint8_t *hash,void *data,size_t len);
void test_validate(struct iguana_info *coin,char *signedtx);
void LP_instantdex_depositadd(char *coinaddr,bits256 txid);
int64_t LP_instantdex_creditcalc(struct iguana_info *coin,int32_t dispflag,bits256 txid,char *refaddr,char *origcoinaddr);
void LP_ports(uint16_t *pullportp,uint16_t *pubportp,uint16_t *busportp,uint16_t netid);
int32_t LP_destaddr(char *destaddr,cJSON *item);
int32_t LP_waitmempool(char *symbol,char *coinaddr,bits256 txid,int32_t vout,int32_t duration);
cJSON *LP_statslog_disp(uint32_t starttime,uint32_t endtime,char *refgui,bits256 refpubkey,char *refbase,char *refrel);
uint32_t LP_claimtime(struct iguana_info *coin,uint32_t expiration);
uint32_t LP_heighttime(char *symbol,int32_t height);
uint64_t LP_unspents_load(char *symbol,char *addr);
int32_t LP_validSPV(char *symbol,char *coinaddr,bits256 txid,int32_t vout);
struct LP_transaction *LP_transactionfind(struct iguana_info *coin,bits256 txid);
cJSON *LP_transactioninit(struct iguana_info *coin,bits256 txid,int32_t iter,cJSON *txobj);
int32_t LP_mempoolscan(char *symbol,bits256 searchtxid);
int32_t LP_txheight(struct iguana_info *coin,bits256 txid);
int32_t LP_numpeers();
double LP_CMCbtcprice(double *price_usdp,char *symbol);
char *basilisk_swapentry(int32_t fastflag,uint32_t requestid,uint32_t quoteid,int32_t forceflag);
int64_t LP_KMDvalue(struct iguana_info *coin,int64_t balance);
int32_t LP_address_utxoadd(int32_t skipsearch,uint32_t timestamp,char *debug,struct iguana_info *coin,char *coinaddr,bits256 txid,int32_t vout,uint64_t value,int32_t height,int32_t spendheight);
void LP_smartutxos_push(struct iguana_info *coin);
void LP_cacheptrs_init(struct iguana_info *coin);
cJSON *LP_address_utxos(struct iguana_info *coin,char *coinaddr,int32_t electrumret);
cJSON *LP_gettxout(char *symbol,char *coinaddr,bits256 txid,int32_t vout);
void LP_postutxos(char *symbol,char *coinaddr);
int32_t LP_listunspent_both(char *symbol,char *coinaddr,int32_t fullflag);
uint16_t LP_randpeer(char *destip);
void LP_tradebot_pauseall();
int32_t LP_etomic_pub2addr(char *coinaddr,uint8_t pub64[64]);
void LP_portfolio_reset();
int32_t LP_autoref_clear(char *base,char *rel);
int32_t bitcoin_addr2rmd160(char *symbol,uint8_t taddr,uint8_t *addrtypep,uint8_t rmd160[20],char *coinaddr);
struct LP_pubkey_info *LP_pubkeyadd(bits256 pubkey);
uint32_t LP_atomic_locktime(char *base,char *rel);
struct LP_pubkey_info *LP_pubkeyfind(bits256 pubkey);
char *issue_LP_psock(char *destip,uint16_t destport,int32_t ispaired,int32_t cmdchannel);
char *LP_unspents_filestr(char *symbol,char *addr);
cJSON *bitcoin_data2json(char *symbol,uint8_t taddr,uint8_t pubtype,uint8_t p2shtype,uint8_t isPoS,int32_t height,bits256 *txidp,struct iguana_msgtx *msgtx,uint8_t *extraspace,int32_t extralen,uint8_t *serialized,int32_t len,cJSON *vins,int32_t suppress_pubkeys,int32_t zcash);
//int32_t LP_butxo_findeither(bits256 txid,int32_t vout);
cJSON *LP_listunspent(char *symbol,char *coinaddr,bits256 reftxid,bits256 reftxid2);
int32_t LP_gettx_presence(int32_t *numconfirmsp,char *symbol,bits256 expectedtxid,char *coinaddr);
double LP_getestimatedrate(struct iguana_info *coin);
struct LP_utxoinfo *_LP_utxofind(int32_t iambob,bits256 txid,int32_t vout);
struct LP_utxoinfo *_LP_utxo2find(int32_t iambob,bits256 txid,int32_t vout);
int64_t LP_dynamictrust(int64_t credits,bits256 pubkey,int64_t kmdvalue);
struct LP_address *LP_addressfind(struct iguana_info *coin,char *coinaddr);
int64_t LP_outpoint_amount(char *symbol,bits256 txid,int32_t vout);
void LP_initpeers(int32_t pubsock,struct LP_peerinfo *mypeer,char *myipaddr,uint16_t myport,uint16_t netid,char *seednode);
int32_t LP_trades_canceluuid(char *uuidstr);
int _decreasing_uint64(const void *a,const void *b);
int32_t LP_alice_eligible(uint32_t quotetime);
int32_t LP_is_slowcoin(char *symbol);

void LP_listunspent_query(char *symbol,char *coinaddr);
int32_t bitcoin_priv2wif(char *symbol,uint8_t wiftaddr,char *wifstr,bits256 privkey,uint8_t addrtype);
int bech32_convert_bits(uint8_t *out,int32_t *outlen,int outbits,const uint8_t *in,int32_t inlen,int inbits,int pad);
int bech32_decode(char *hrp,uint8_t *data,int32_t *data_len,const char *input);
int bech32_encode(char *output,const char *hrp,const uint8_t *data,int32_t data_len);
void HashGroestl(void * buf, const void * pbegin, int len);
bits256 LP_privkey(char *symbol,char *coinaddr,uint8_t taddr);

#endif
