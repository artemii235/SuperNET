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

#ifndef INCLUDE_DPOW_H
#define INCLUDE_DPOW_H

//#define DPOW_MAXMOMDEPTH (1440 * 7)

#define DPOW_FIRSTRATIFY 1000

#define DPOW_MAXFREQ 100
#define DPOW_CHECKPOINTFREQ 10
#define DPOW_MINSIGS 13
#define DPOW_MIN_ASSETCHAIN_SIGS 11
//#define DPOW_M(bp) ((bp)->minsigs)  // (((bp)->numnotaries >> 1) + 1)
#define DPOW_MODIND(bp,offset) (((((bp)->height / DPOW_CHECKPOINTFREQ) % (bp)->numnotaries) + (offset)) % (bp)->numnotaries)
#define DPOW_VERSION 0x1782
#define DPOW_UTXOSIZE dpow_utxosize(coin->symbol) //10000
#define DPOW_MINOUTPUT 6000
#define DPOW_DURATION 1200
#define DPOW_RATIFYDURATION (3600 * 24)

//#define DPOW_ENTRIESCHANNEL ('e' | ('n' << 8) | ('t' << 16) | ('r' << 24))
//#define DPOW_BTCENTRIESCHANNEL (~DPOW_ENTRIESCHANNEL)
//#define DPOW_UTXOCHANNEL ('d' | ('P' << 8) | ('o' << 16) | ('W' << 24))
#define DPOW_SIGCHANNEL ('s' | ('i' << 8) | ('g' << 16) | ('s' << 24))
#define DPOW_SIGBTCCHANNEL (~DPOW_SIGCHANNEL)
#define DPOW_TXIDCHANNEL ('t' | ('x' << 8) | ('i' << 16) | ('d' << 24))
#define DPOW_BTCTXIDCHANNEL (~DPOW_TXIDCHANNEL)


#define DPOW_FIFOSIZE 64
#define DPOW_MAXTX 8192
#define DPOW_THIRDPARTY_CONFIRMS 0
#define DPOW_KOMODOCONFIRMS 10
#define DPOW_BTCCONFIRMS 1
#define DPOW_MAXRELAYS 64
#define DPOW_MAXSIGLEN 128

#define DEX_VERSION 0x0106
#define DPOW_SOCKPORT 7775
#define DEX_SOCK 7774
#define PUB_SOCK 7773
#define REP_SOCK 7772

#define DPOW_EPOCHDURATION 600

struct dpow_coinentry
{
    bits256 prev_hash;
    uint8_t siglens[DPOW_MAXRELAYS],sigs[DPOW_MAXRELAYS][DPOW_MAXSIGLEN];
    int32_t prev_vout;
};

struct dpow_utxoentry
{
    bits256 srchash,desthash,commit,hashmsg;
    uint64_t recvmask,othermasks[DPOW_MAXRELAYS];
    int32_t srcvout,destvout,height;
    int8_t bestk; uint8_t pubkey[33];
};

struct dpow_entry
{
    bits256 commit,beacon,ratifysrcutxo,ratifydestutxo;
    uint64_t masks[2][DPOW_MAXRELAYS],recvmask,othermask,bestmask,ratifyrecvmask,ratifybestmask;
    int32_t height; uint32_t pendingcrcs[2],paxwdcrc;
    uint16_t ratifysrcvout,ratifydestvout;
    int8_t bestk,ratifybestk;
    uint8_t pubkey[33],ratifysigs[2][DPOW_MAXSIGLEN],ratifysiglens[2];
    struct dpow_coinentry src,dest;
};

struct dpow_sigentry
{
    bits256 beacon;
    uint64_t mask;
    int32_t refcount;
    uint8_t senderind,lastk,siglen,sig[DPOW_MAXSIGLEN],senderpub[33];
};

struct komodo_notaries
{
    struct basilisk_relay RELAYS[DPOW_MAXRELAYS];
    int32_t NUMRELAYS,RELAYID;
};

struct dpow_hashheight { bits256 hash; int32_t height; };

struct dpow_checkpoint
{
    struct dpow_hashheight blockhash,approved;
    bits256 miner; uint32_t blocktime,timestamp;
};

struct dpow_recvdata { uint64_t recvmask,bestmask; int8_t bestk; };

struct dpow_block
{
    bits256 hashmsg,desttxid,srctxid,beacon,commit,MoM;
    struct iguana_info *srccoin,*destcoin; char *opret_symbol;
    uint64_t destsigsmasks[DPOW_MAXRELAYS],srcsigsmasks[DPOW_MAXRELAYS];
    uint64_t recvmask,bestmask,ratifybestmask,ratifyrecvmask,pendingbestmask,pendingratifybestmask,ratifysigmasks[2];
    struct dpow_recvdata recv[64];
    struct dpow_entry notaries[DPOW_MAXRELAYS];
    uint32_t MoMdepth,state,starttime,timestamp,waiting,sigcrcs[2],txidcrcs[2],utxocrcs[2],lastepoch,paxwdcrc,lastnanosend;
    int32_t rawratifiedlens[2],height,numnotaries,numerrors,completed,minsigs,duration,numratified,isratify,require0,scores[DPOW_MAXRELAYS];
    int8_t myind,bestk,ratifybestk,pendingbestk,pendingratifybestk,matches,bestmatches;
    cJSON *ratified;
    uint16_t CCid;
    uint8_t ratified_pubkeys[DPOW_MAXRELAYS][33],ratifysigs[2][DPOW_MAXSIGLEN],ratifysiglens[2];
    char handles[DPOW_MAXRELAYS][32];
    char signedtx[32768]; uint8_t ratifyrawtx[2][32768]; uint32_t pendingcrcs[2];
};

struct pax_transaction
{
    UT_hash_handle hh;
    bits256 txid;
    uint64_t komodoshis,fiatoshis;
    int32_t marked,height,kmdheight;
    uint16_t vout;
    char symbol[16],coinaddr[64]; uint8_t rmd160[20],shortflag;
};

struct dpow_info
{
    char symbol[16],dest[16]; uint8_t minerkey33[33],minerid; uint64_t lastrecvmask;
    struct dpow_checkpoint checkpoint,last,destchaintip,srcfifo[DPOW_FIFOSIZE],destfifo[DPOW_FIFOSIZE];
    struct dpow_hashheight approved[DPOW_FIFOSIZE],notarized[DPOW_FIFOSIZE];
    bits256 activehash,lastnotarized,srctx[DPOW_MAXTX],desttx[DPOW_MAXTX];
    uint32_t SRCREALTIME,lastsrcupdate,destupdated,srcconfirms,numdesttx,numsrctx,lastsplit,cancelratify;
    int32_t lastheight,maxblocks,SRCHEIGHT,DESTHEIGHT,prevDESTHEIGHT,SHORTFLAG,ratifying,minsigs,freq;
    struct pax_transaction *PAX;
    uint32_t fullCCid;
    portable_mutex_t paxmutex,dexmutex;
    uint32_t ipbits[128],numipbits;
    struct dpow_block **blocks,*currentbp;
};

struct komodo_ccdatapair { int32_t notarization_height; uint32_t MoMoMoffset; };

struct komodo_ccdataMoMoM
{
    bits256 MoMoM;
    int32_t kmdstarti,kmdendi,MoMoMdepth,numpairs,len;
    struct komodo_ccdatapair *pairs;
};

uint64_t dpow_notarybestk(uint64_t refmask,struct dpow_block *bp,int8_t *lastkp);
int32_t dpow_paxpending(struct supernet_info *myinfo,uint8_t *hex,int32_t hexsize,uint32_t *paxwdcrcp,bits256 MoM,uint32_t MoMdepth,uint16_t CCid,int32_t src_or_dest,struct dpow_block *bp);
void dex_updateclient(struct supernet_info *myinfo);
char *dex_reqsend(struct supernet_info *myinfo,char *handler,uint8_t *data,int32_t datalen,int32_t M,char *field);
char *basilisk_respond_addmessage(struct supernet_info *myinfo,uint8_t *key,int32_t keylen,uint8_t *data,int32_t datalen,int32_t sendping,uint32_t duration);
int32_t dpow_getchaintip(struct supernet_info *myinfo,bits256 *merklerootp,bits256 *blockhashp,uint32_t *blocktimep,bits256 *txs,uint32_t *numtxp,struct iguana_info *coin);
void dpow_send(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,bits256 srchash,bits256 desthash,uint32_t channel,uint32_t msgbits,uint8_t *data,int32_t datalen);
int32_t dpow_nanomsg_update(struct supernet_info *myinfo);
int32_t dpow_haveutxo(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *txidp,int32_t *voutp,char *coinaddr,char *srccoin);
void komodo_assetcoins(int32_t fullnode,uint64_t mask);
int32_t iguana_isnotarychain(char *symbol);

cJSON *dpow_getinfo(struct supernet_info *myinfo,struct iguana_info *coin);
cJSON *dpow_gettransaction(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid);
cJSON *dpow_getblock(struct supernet_info *myinfo,struct iguana_info *coin,bits256 blockhash);
bits256 dpow_getblockhash(struct supernet_info *myinfo,struct iguana_info *coin,int32_t height);
bits256 dpow_getbestblockhash(struct supernet_info *myinfo,struct iguana_info *coin);
char *dpow_sendrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *signedtx);
cJSON *dpow_gettxout(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid,int32_t vout);
char *dpow_importaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *address);
char *dpow_validateaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *address);
cJSON *dpow_listunspent(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr);
cJSON *dpow_listtransactions(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,int32_t count,int32_t skip);
char *dpow_alladdresses(struct supernet_info *myinfo,struct iguana_info *coin);
cJSON *dpow_kvupdate(struct supernet_info *myinfo,struct iguana_info *coin,char *key,char *value,int32_t flags);
cJSON *dpow_kvsearch(struct supernet_info *myinfo,struct iguana_info *coin,char *key);
void init_alladdresses(struct supernet_info *myinfo,struct iguana_info *coin);
cJSON *dpow_getmessage(struct supernet_info *myinfo,char *jsonstr);
cJSON *dpow_addmessage(struct supernet_info *myinfo,char *jsonstr);
cJSON *dpow_psock(struct supernet_info *myinfo,char *jsonstr);

char *_dex_getinfo(struct supernet_info *myinfo,char *symbol);
char *_dex_getrawtransaction(struct supernet_info *myinfo,char *symbol,bits256 txid);
char *_dex_getblock(struct supernet_info *myinfo,char *symbol,bits256 hash2);
char *_dex_getblockhash(struct supernet_info *myinfo,char *symbol,int32_t height);
char *_dex_getbestblockhash(struct supernet_info *myinfo,char *symbol);
char *_dex_sendrawtransaction(struct supernet_info *myinfo,char *symbol,char *signedtx);
char *_dex_gettxout(struct supernet_info *myinfo,char *symbol,bits256 txid,int32_t vout);
char *_dex_gettxin(struct supernet_info *myinfo,char *symbol,bits256 txid,int32_t vout);
char *_dex_importaddress(struct supernet_info *myinfo,char *symbol,char *address);
char *_dex_validateaddress(struct supernet_info *myinfo,char *symbol,char *address);
char *_dex_getmessage(struct supernet_info *myinfo,char *jsonstr);
char *_dex_listunspent(struct supernet_info *myinfo,char *symbol,char *address);
char *_dex_listunspent2(struct supernet_info *myinfo,char *symbol,char *address);
char *_dex_listspent(struct supernet_info *myinfo,char *symbol,char *address);
char *_dex_getbalance(struct supernet_info *myinfo,char *symbol,char *address);
char *_dex_listtransactions(struct supernet_info *myinfo,char *symbol,char *coinaddr,int32_t count,int32_t skip);
char *_dex_listtransactions2(struct supernet_info *myinfo,char *symbol,char *coinaddr,int32_t count,int32_t skip);
char *_dex_alladdresses(struct supernet_info *myinfo,char *symbol);
int32_t _dex_getheight(struct supernet_info *myinfo,char *symbol);
char *_dex_getnotaries(struct supernet_info *myinfo,char *symbol);
char *_dex_kvupdate(struct supernet_info *myinfo,char *symbol,char *key,char *value,int32_t flags);
char *_dex_kvsearch(struct supernet_info *myinfo,char *symbol,char *key);
char *_dex_psock(struct supernet_info *myinfo,char *jsonstr);

int32_t komodo_notaries(char *symbol,uint8_t pubkeys[64][33],int32_t height);
cJSON *dpow_checkaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *address);

void dex_channelsend(struct supernet_info *myinfo,bits256 srchash,bits256 desthash,uint32_t channel,uint32_t msgid,uint8_t *data,int32_t datalen);
void kmd_bitcoinscan();
cJSON *kmd_getbalance(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr);
struct iguana_info *iguana_coinfind(char *symbol);
cJSON *kmd_listtransactions(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,int32_t count,int32_t skip);
cJSON *kmd_listunspent(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr);
cJSON *kmd_listspent(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr);
cJSON *kmd_gettxin(struct iguana_info *coin,bits256 txid,int32_t vout);

cJSON *dpow_listspent(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr);
cJSON *dpow_getbalance(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr);
cJSON *dpow_gettxin(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid,int32_t vout);


#endif
