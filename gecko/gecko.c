
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

// + code mempool and tx (payment and opreturn protocol)
// + debug remote <-> server and p2p network
// port DEX to use geckochain
// debug DEXchain
// debug network port mode
// debug virtual + network port mode

// debug genesis balances
// debug reorgs, detect when network is forked


// code subchains synchronized with parent chain
// port pangea to use gecko with subchains
// debug pangea

// debug delayed PoW, code BTCD -> BTC, delegate selection using virtual coin stakes
// code datachain
//

#include "../iguana/iguana777.h"
#include "gecko_delayedPoW.c"
#include "gecko_headers.c"
#include "gecko_mempool.c"
#include "gecko_miner.c"
#include "gecko_blocks.c"

void gecko_iteration(struct supernet_info *myinfo,struct iguana_info *btcd,struct iguana_info *virt,int32_t maxmillis)
{
    char mineraddr[64]; int32_t hwmhdrsi,longesthdrsi; struct iguana_bundle *bp;
    hwmhdrsi = virt->blocks.hwmchain.height / virt->chain->bundlesize;
    longesthdrsi = virt->longestchain / virt->chain->bundlesize;
    if ( (bp= virt->bundles[hwmhdrsi]) != 0 )
    {
        //iguana_RTspendvectors(myinfo,virt,bp);
        //iguana_RTramchainalloc("RTbundle",virt,bp);
        //iguana_update_balances(virt);
        //iguana_realtime_update(myinfo,virt);
    }
    if ( (0) && hwmhdrsi <= longesthdrsi )//&& virt->blocks.hwmchain.height < virt->longestchain-1 )
    {
        if ( time(NULL) > virt->hdrstime+3 )
        {
            fprintf(stderr,"request %s headers\n",virt->symbol);
            gecko_requesthdrs(myinfo,virt,hwmhdrsi);
            //fprintf(stderr,"R");
            virt->hdrstime = (uint32_t)time(NULL);
        }
    }
    if ( (0) && btcd->FULLNODE != 0 )//&& virt->blocks.hwmchain.height >= virt->longestchain-virt->chain->bundlesize )
    {
        bitcoin_address(mineraddr,virt->chain->pubtype,myinfo->persistent_pubkey33,33);
        //fprintf(stderr,"mine.%s %s\n",virt->symbol,mineraddr);
        gecko_miner(myinfo,btcd,virt,maxmillis,myinfo->persistent_pubkey33);
    }
}

int32_t iguana_ROallocsize(struct iguana_info *virt)
{
    return(virt->chain->zcash != 0 ? sizeof(struct iguana_zblock) : sizeof(struct iguana_block));
}

bits256 calc_categoryhashes(bits256 *subhashp,char *category,char *subcategory)
{
    bits256 categoryhash;
    if ( category == 0 || category[0] == 0 || strcmp(category,"broadcast") == 0 )
        categoryhash = GENESIS_PUBKEY;
    else vcalc_sha256(0,categoryhash.bytes,(uint8_t *)category,(int32_t)strlen(category));
    if ( subhashp != 0 )
    {
        if ( subcategory == 0 || subcategory[0] == 0 || strcmp(subcategory,"broadcast") == 0 )
            *subhashp = GENESIS_PUBKEY;
        else vcalc_sha256(0,subhashp->bytes,(uint8_t *)subcategory,(int32_t)strlen(subcategory));
    }
    return(categoryhash);
}

struct gecko_chain *category_find(bits256 categoryhash,bits256 subhash)
{
    struct gecko_chain *cat=0,*sub = 0; bits256 hash;
    HASH_FIND(hh,Categories,categoryhash.bytes,sizeof(categoryhash),cat);
    if ( cat != 0 )
    {
        if ( bits256_nonz(subhash) > 0 && memcmp(GENESIS_PUBKEY.bytes,subhash.bytes,sizeof(subhash)) != 0 )
        {
            hash = subhash;
            HASH_FIND(hh,cat->subchains,hash.bytes,sizeof(hash),sub);
            if ( sub != 0 )
                return(sub);
        }
        return(cat);
    } //else printf("category_find.(%s) not found\n",bits256_str(str,categoryhash));//, getchar();
    return(0);
}

queue_t *category_Q(struct gecko_chain **catptrp,bits256 categoryhash,bits256 subhash)
{
    struct gecko_chain *cat;
    *catptrp = 0;
    if ( (cat= category_find(categoryhash,subhash)) != 0 )
    {
        *catptrp = cat;
        return(&cat->Q);
    }
    else return(0);
}

void *category_subscribe(struct supernet_info *myinfo,bits256 chainhash,bits256 keyhash)
{
    struct gecko_chain *chain,*subchain; bits256 hash;
    portable_mutex_lock(&myinfo->gecko_mutex);
    HASH_FIND(hh,Categories,chainhash.bytes,sizeof(chainhash),chain);
    if ( chain == 0 )
    {
        chain = mycalloc('c',1,sizeof(*chain));
        chain->hash = hash = chainhash;
        //char str[65]; printf("ADD cat.(%s)\n",bits256_str(str,chainhash));
        HASH_ADD(hh,Categories,hash,sizeof(hash),chain);
    }
    if ( bits256_nonz(keyhash) > 0 && memcmp(GENESIS_PUBKEY.bytes,keyhash.bytes,sizeof(keyhash)) != 0 && chain != 0 )
    {
        HASH_FIND(hh,chain->subchains,keyhash.bytes,sizeof(keyhash),subchain);
        if ( subchain == 0 )
        {
            subchain = mycalloc('c',1,sizeof(*subchain));
            subchain->hash = hash = keyhash;
            //char str[65],str2[65]; printf("subadd.(%s) -> (%s)\n",bits256_str(str,keyhash),bits256_str(str2,chainhash));
            HASH_ADD(hh,chain->subchains,hash,sizeof(hash),subchain);
        }
    }
    portable_mutex_unlock(&myinfo->gecko_mutex);
    return(chain);
}

struct gecko_chain *gecko_chain(struct supernet_info *myinfo,char chainname[GECKO_MAXNAMELEN],cJSON *valsobj)
{
    char *chainstr,*keystr; bits256 keyhash,chainhash; struct gecko_chain *chain;
    chainname[0] = 0;
    if ( (chainstr= jstr(valsobj,"symbol")) == 0 )
        return(0);
    if ( (keystr= jstr(valsobj,"name")) != 0 )
        vcalc_sha256(0,keyhash.bytes,(uint8_t *)keystr,(int32_t)strlen(keystr));
    else keyhash = GENESIS_PUBKEY;
    vcalc_sha256(0,chainhash.bytes,(uint8_t *)chainstr,(int32_t)strlen(chainstr));
    if ( (chain= category_subscribe(myinfo,chainhash,keyhash)) == 0 )
        return(0);
    safecopy(chainname,chainstr,30), chainname[30] = 0;
    if ( keystr != 0 )
    {
        strcat(chainname,".");
        safecopy(chainname+strlen(chainname),keystr,GECKO_MAXNAMELEN-1-strlen(chainname));
    }
    return(chain);
}

struct iguana_info *basilisk_geckochain(struct supernet_info *myinfo,char *symbol,char *chainname,cJSON *valsobj)
{
    int32_t n,datalen,hdrsize,len=0; struct iguana_info *virt=0; char *hexstr; uint8_t hexbuf[8192],*ptr,*serialized; struct iguana_peer *addr; struct iguana_txblock txdata;
    portable_mutex_lock(&myinfo->gecko_mutex);
    printf("basilisk_geckochain symbol.%s chain.%s (%s)\n",symbol,chainname,jprint(valsobj,0));
    if ( iguana_coinfind(symbol) == 0 && (hexstr= jstr(valsobj,"genesisblock")) != 0 && (virt= iguana_coinadd(symbol,chainname,valsobj,1)) != 0 )
    {
        safecopy(virt->name,chainname,sizeof(virt->name));
        virt->chain = calloc(1,sizeof(*virt->chain));
        virt->enableCACHE = 1;
        serialized = get_dataptr(BASILISK_HDROFFSET,&ptr,&datalen,hexbuf,sizeof(hexbuf),hexstr);
        iguana_chaininit(myinfo,virt->chain,1,valsobj);
        //if ( virt->FULLNODE >= 0 )
        //    virt->chain->userpass[0] = 0;
        virt->chain->isPoS = 1;
        hdrsize = (virt->chain->zcash != 0) ? sizeof(struct iguana_msgzblockhdr) : sizeof(struct iguana_msgblockhdr);
        if ( gecko_blocknonce_verify(virt,serialized,hdrsize,virt->chain->nBits,0,0) > 0 )
        {
            virt->chain->genesishash2 = iguana_calcblockhash(symbol,virt->chain->hashalgo,serialized,hdrsize);
            memcpy(virt->chain->genesis_hashdata,virt->chain->genesishash2.bytes,sizeof(virt->chain->genesishash2));
            if ( ptr != 0 )
                free(ptr);
            if ( virt->TXMEM.ptr == 0 )
                iguana_meminit(&virt->TXMEM,virt->name,0,IGUANA_MAXPACKETSIZE * 2,0);
            virt->chain->genesis_hex = clonestr(hexstr);
            virt->MAXPEERS = 0;
            virt->FULLNODE = 1;
            virt->virtualchain = 1;
            addr = &virt->internaladdr;
            strcpy(virt->VALIDATEDIR,GLOBAL_VALIDATEDIR);
            printf("GLOBAL_VALIDATEDIR.(%s) (%s)\n",GLOBAL_VALIDATEDIR,virt->VALIDATEDIR);
            iguana_callcoinstart(myinfo,virt);
            iguana_initpeer(virt,addr,calc_ipbits("127.0.0.1"));
            iguana_peerslotinit(virt,addr,IGUANA_MAXPEERS,addr->ipbits);
            if ( addr->blockspace == 0 )
                addr->blockspace = calloc(1,IGUANA_MAXPACKETSIZE + 8192);
            if ( addr->RAWMEM.ptr == 0 )
                iguana_meminit(&addr->RAWMEM,virt->symbol,0,IGUANA_MAXPACKETSIZE * 2,0);
            if ( addr->TXDATA.ptr == 0 )
                iguana_meminit(&addr->TXDATA,"txdata",0,IGUANA_MAXPACKETSIZE * 2,0);
            if ( addr->HASHMEM.ptr == 0 )
                iguana_meminit(&addr->HASHMEM,"HASHPTRS",0,256,0);//IGUANA_MAXPACKETSIZE*16,0);
            iguana_bundlesload(myinfo,virt);
            if ( virt->blocks.hwmchain.height == 0 )
            {
                memset(&txdata,0,sizeof(txdata));
                if ( (n= iguana_gentxarray(myinfo,virt,&virt->TXMEM,&txdata,&len,serialized,datalen) == datalen) || n == datalen-1 )
                {
                    txdata.zblock.height = 0;
                    txdata.zblock.RO.allocsize = iguana_ROallocsize(virt);
                    gecko_hwmset(myinfo,virt,&txdata,virt->TXMEM.ptr,serialized,datalen,txdata.numtxids,0);
                }
            }
            virt->started = virt;
            virt->active = (uint32_t)time(NULL);
            iguana_datachain_scan(myinfo,virt,CRYPTO777_RMD160);
        } else printf("error validating nonce\n");
    }
    portable_mutex_unlock(&myinfo->gecko_mutex);
    return(virt);
}

char *basilisk_standardreturn(char *CMD,char *type,struct iguana_info *virt,uint8_t *serialized,int32_t datalen,bits256 hash)
{
    char space[16384],*allocstr = 0; cJSON *retjson = cJSON_CreateObject();
    if ( datalen > 0 && basilisk_addhexstr(&allocstr,retjson,space,sizeof(space),serialized,datalen) != 0 )
    {
        jaddstr(retjson,"CMD",CMD);
        jaddstr(retjson,"type",type);
        jaddstr(retjson,"symbol",virt->symbol);
        jaddnum(retjson,"hwm",virt->blocks.hwmchain.height);
        jaddnum(retjson,"datalen",datalen);
        jaddbits256(retjson,"chaintip",virt->blocks.hwmchain.RO.hash2);
        jaddbits256(retjson,"hash",hash);
    } else jaddstr(retjson,"error","no data to send");
    if ( allocstr != 0 )
        free(allocstr);
    return(jprint(retjson,1));
}

char *basilisk_respond_geckoget(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash2,int32_t from_basilisk)
{
    int32_t (*getfunc)(struct supernet_info *myinfo,struct iguana_info *virt,uint8_t *serialized,int32_t maxsize,cJSON *valsobj,bits256 hash2);
    uint8_t *serialized; int32_t maxsize; char *symbol,*type; struct iguana_info *virt;
    if ( (type= jstr(valsobj,"type")) != 0 )
    {
        if ( strcmp(type,"HDR") == 0 )
            getfunc = basilisk_respond_geckogetheaders;
        else if ( strcmp(type,"BLK") == 0 )
            getfunc = basilisk_respond_geckogetblock;
        else if ( strcmp(type,"GTX") == 0 )
            getfunc = basilisk_respond_geckogettx;
        else return(clonestr("{\"error\":\"invalid geckoget type, mustbe (HDR or BLK or GTX)\"}"));
        if ( (serialized= ((struct iguana_peer *)addr)->blockspace) == 0 )
            return(clonestr("{\"error\":\"peer has no blockspace\"}"));
        maxsize = IGUANA_MAXPACKETSIZE;
        if ( (symbol= jstr(valsobj,"symbol")) != 0 && (virt= iguana_coinfind(symbol)) != 0 )
        {
            datalen = (*getfunc)(myinfo,virt,serialized,maxsize,valsobj,hash2);
            printf("return datalen.%d for %s\n",datalen,type);
            return(basilisk_standardreturn(CMD,type,virt,serialized,datalen,hash2));
        } else return(clonestr("{\"error\":\"couldt find gecko chain\"}"));
    } else return(clonestr("{\"error\":\"invalid geckoget type, mustbe (HDR or BLK or GTX)\"}"));
}

char *gecko_sendrawtransaction(struct supernet_info *myinfo,char *symbol,uint8_t *data,int32_t datalen,bits256 txid,cJSON *vals,char *signedtx)
{
    char *retstr = 0; struct iguana_info *virt,*btcd = iguana_coinfind("BTCD");
    virt = iguana_coinfind(symbol);
    if ( btcd != 0 && (btcd->FULLNODE != 0 || btcd->VALIDATENODE != 0) )
    {
        basilisk_wait(myinfo,virt);
        retstr = basilisk_respond_geckotx(myinfo,"GTX",0,0,0,vals,data,datalen,txid,0);
    }
    if ( retstr == 0 )
        retstr = basilisk_standardservice("GTX",myinfo,0,txid,vals,signedtx,1);
    return(retstr);
}



