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

#ifndef H_BASILISK_H
#define H_BASILISK_H

//#define BASILISK_DISABLESENDTX
//#define BASILISK_DISABLEWAITTX

#include "../iguana/iguana777.h"

#define BASILISK_TIMEOUT 3000
#define BASILISK_MINFANOUT 8
#define BASILISK_MAXFANOUT 64
#define BASILISK_DEFAULTDIFF 0x1effffff
#define BASILISK_DEXDURATION 300
#define BASILISK_MSGDURATION 30
#define BASILISK_AUCTION_DURATION 5

#define BASILISK_MAXFUTUREBLOCK 60
#define BASILISK_HDROFFSET ((int32_t)(sizeof(bits256)+sizeof(struct iguana_msghdr)+sizeof(uint32_t)))

#define INSTANTDEX_DECKSIZE 1000
#define INSTANTDEX_LOCKTIME (3600*2 + 300*2)
#define INSTANTDEX_INSURANCEDIV 777
#define INSTANTDEX_PUBKEY "03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06"
#define INSTANTDEX_RMD160 "ca1e04745e8ca0c60d8c5881531d51bec470743f"
#define JUMBLR_RMD160 "5177f8b427e5f47342a4b8ab5dac770815d4389e"
#define TIERNOLAN_RMD160 "daedddd8dbe7a2439841ced40ba9c3d375f98146"
#define INSTANTDEX_BTC "1KRhTPvoxyJmVALwHFXZdeeWFbcJSbkFPu"
#define INSTANTDEX_BTCD "RThtXup6Zo7LZAi8kRWgjAyi1s4u6U9Cpf"

#define JUMBLR_INCR 99.65
#define JUMBLR_FEE 0.001
#define JUMBLR_TXFEE 0.01

struct basilisk_swap;

struct basilisk_rawtxinfo
{
    char destaddr[64],coinstr[16];
    bits256 txid,signedtxid,actualtxid;
    uint64_t amount,change,inputsum;
    int32_t redeemlen,datalen,completed,vintype,vouttype,numconfirms,spendlen,secretstart,suppress_pubkeys;
    uint32_t locktime,crcs[2];
    uint8_t addrtype,pubkey33[33],rmd160[20];
};

struct basilisk_rawtx
{
    char name[32];
    struct iguana_msgtx msgtx;
    struct basilisk_rawtxinfo I;
    struct iguana_info *coin;
    char vinstr[8192],p2shaddr[64];
    cJSON *vins;
    uint8_t txbytes[16384],spendscript[512],redeemscript[1024],extraspace[4096];
};

struct basilisk_swapinfo
{
    struct basilisk_request req;
    char bobstr[64],alicestr[64];
    bits256 myhash,otherhash,orderhash;
    uint32_t statebits,otherstatebits,started,expiration,finished,dead,reftime,putduration,callduration;
    int32_t bobconfirms,aliceconfirms,iambob,reclaimed,bobspent,alicespent,pad;
    uint64_t alicesatoshis,bobsatoshis,bobinsurance,aliceinsurance;
    
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

struct basilisk_value { bits256 txid; int64_t value; int32_t height; int16_t vout; char coinaddr[64]; };

struct basilisk_item
{
    struct queueitem DL; UT_hash_handle hh;
    double expiration,finished; cJSON *results[64];
    uint32_t submit,basilisktag,numresults,numsent,numrequired,nBits,duration;
    char symbol[32],CMD[4],remoteaddr[64],*retstr;
};

#define BASILISK_KEYSIZE ((int32_t)(2*sizeof(bits256)+sizeof(uint32_t)*2))
struct basilisk_message
{
    struct queueitem DL; UT_hash_handle hh;
    uint32_t expiration,duration,datalen;
    uint8_t keylen,broadcast,key[BASILISK_KEYSIZE];
    uint8_t data[];
};

struct basilisk_info
{
    //queue_t resultsQ,submitQ;
    void *launched; //portable_mutex_t *mutex;
    struct basilisk_item *issued;
    struct basilisk_value values[8192]; int32_t numvalues;
};

void basilisk_msgprocess(struct supernet_info *myinfo,void *addr,uint32_t senderipbits,char *type,uint32_t basilisktag,uint8_t *data,int32_t datalen);
int32_t basilisk_sendcmd(struct supernet_info *myinfo,char *destipaddr,char *type,uint32_t *basilisktagp,int32_t encryptflag,int32_t delaymillis,uint8_t *data,int32_t datalen,int32_t fanout,uint32_t nBits); // data must be offset by sizeof(iguana_msghdr)+sizeof(basilisktag)

void basilisks_init(struct supernet_info *myinfo);
void basilisk_p2p(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,char *senderip,uint8_t *data,int32_t datalen,char *type,int32_t encrypted);
uint8_t *basilisk_jsondata(int32_t extraoffset,uint8_t **ptrp,uint8_t *space,int32_t spacesize,int32_t *datalenp,char *symbol,cJSON *sendjson,uint32_t basilisktag);

uint8_t *SuperNET_ciphercalc(void **ptrp,int32_t *cipherlenp,bits256 *privkeyp,bits256 *destpubkeyp,uint8_t *data,int32_t datalen,uint8_t *space2,int32_t space2size);
void *SuperNET_deciphercalc(void **ptrp,int32_t *msglenp,bits256 privkey,bits256 srcpubkey,uint8_t *cipher,int32_t cipherlen,uint8_t *buf,int32_t bufsize);
uint8_t *get_dataptr(int32_t hdroffset,uint8_t **ptrp,int32_t *datalenp,uint8_t *space,int32_t spacesize,char *hexstr);
char *basilisk_addhexstr(char **ptrp,cJSON *valsobj,char *strbuf,int32_t strsize,uint8_t *data,int32_t datalen);
char *basilisk_standardservice(char *CMD,struct supernet_info *myinfo,void *_addr,bits256 hash,cJSON *valsobj,char *hexstr,int32_t blockflag); // client side
char *basilisk_respond_mempool(struct supernet_info *myinfo,char *CMD,void *_addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk);
char *basilisk_addrelay_info(struct supernet_info *myinfo,uint8_t *pubkey33,uint32_t ipbits,bits256 pubkey);

void basilisk_request_goodbye(struct supernet_info *myinfo);
int32_t basilisk_update(char *symbol,uint32_t reftimestamp);
void basilisk_seqresult(struct supernet_info *myinfo,char *retstr);
struct iguana_info *basilisk_geckochain(struct supernet_info *myinfo,char *symbol,char *chainname,cJSON *valsobj);
void basilisk_alicepayment(struct supernet_info *myinfo,struct basilisk_swap *swap,struct iguana_info *coin,struct basilisk_rawtx *alicepayment,bits256 pubAm,bits256 pubBn);
void basilisk_rawtx_setparms(char *name,uint32_t quoteid,struct basilisk_rawtx *rawtx,struct iguana_info *coin,int32_t numconfirms,int32_t vintype,uint64_t satoshis,int32_t vouttype,uint8_t *pubkey33,int32_t jumblrflag);
void basilisk_setmyid(struct supernet_info *myinfo);
int32_t basilisk_rwDEXquote(int32_t rwflag,uint8_t *serialized,struct basilisk_request *rp);
cJSON *basilisk_requestjson(struct basilisk_request *rp);
int32_t basilisk_bobscripts_set(struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t depositflag,int32_t genflag);
void basilisk_txlog(struct supernet_info *myinfo,struct basilisk_swap *swap,struct basilisk_rawtx *rawtx,int32_t delay);
int32_t basilisk_messagekey(uint8_t *key,uint32_t channel,uint32_t msgid,bits256 srchash,bits256 desthash);
cJSON *basilisk_unspents(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr);
char *basilisk_sendrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *signedtx);

#endif
