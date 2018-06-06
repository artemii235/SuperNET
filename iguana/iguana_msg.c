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

int32_t iguana_rwaddr(int32_t rwflag,uint8_t *serialized,struct iguana_msgaddress *addr,int32_t protover)
{
    int32_t len = 0;
	if ( protover >= CADDR_TIME_VERSION )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(addr->nTime),&addr->nTime);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(addr->nServices),&addr->nServices);
    len += iguana_rwmem(rwflag,&serialized[len],sizeof(addr->ip),&addr->ip);
    if ( rwflag != 0 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(addr->port),&addr->port);
    else
    {
        addr->port = (uint16_t)serialized[len++] << 8;
        addr->port += (uint16_t)serialized[len++];
    }
    return(len);
}

int32_t iguana_rwversion(int32_t rwflag,uint8_t *serialized,struct iguana_msgversion *msg,char *ipaddr,int32_t readsize)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->nVersion),&msg->nVersion);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->nServices),&msg->nServices);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->nTime),&msg->nTime);
    len += iguana_rwaddr(rwflag,&serialized[len],&msg->addrTo,MIN_PROTO_VERSION);
    len += iguana_rwaddr(rwflag,&serialized[len],&msg->addrFrom,MIN_PROTO_VERSION);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->nonce),&msg->nonce);
    len += iguana_rwvarstr(rwflag,&serialized[len],sizeof(msg->strSubVer),msg->strSubVer);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->nStartingHeight),&msg->nStartingHeight);
    if ( readsize == 117 )
    {
        uint32_t iVer = 1132,v_Network_id=1; uint16_t wPort=1920,wCtPort=0,wPrPort=0; uint8_t bIsGui=0;
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(iVer),&iVer);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(v_Network_id),&v_Network_id);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(wPort),&wPort);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(bIsGui),&bIsGui);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(wCtPort),&wCtPort);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(wPrPort),&wPrPort);
        /*int iVer = BitNet_Version;
         unsigned short wPort = GetListenPort();
         unsigned char bIsGui = 0;	// 2014.12.18 add
         unsigned short wCtPort = 0;
         unsigned short wPrPort = 0;
         vRecv >> iVer;
         pfrom->vBitNet.v_iVersion = iVer;
         vRecv >> pfrom->vBitNet.;
         if (!vRecv.empty()){ vRecv >> pfrom->vBitNet.v_ListenPort; }
         if (!vRecv.empty()){ vRecv >> pfrom->vBitNet.v_IsGuiNode; }	//-- 2014.12.18 add
         if (!vRecv.empty()){ vRecv >> pfrom->vBitNet.v_iVpnServiceCtrlPort; }	//-- 2014.12.28 add
         if (!vRecv.empty()){ vRecv >> pfrom->vBitNet.v_P2P_proxy_port; }	    //-- 2014.12.28 add
         */
        printf("iVer.%d v_Network_id.%d wPort.%u bIsGui.%d wCtPort.%u wPrPort.%u\n",iVer,v_Network_id,wPort,bIsGui,wCtPort,wPrPort);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->relayflag),&msg->relayflag);
    }
    else if ( msg->nVersion > 70002 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->relayflag),&msg->relayflag);
    //if ( rwflag == 0 )
    //printf("readsize.%d %-15s v.%llu srv.%llx %u ht.%llu [%s].R%d nonce.%llx\n",readsize,ipaddr,(long long)msg->nVersion,(long long)msg->nServices,(uint32_t)msg->nTime,(long long)msg->nStartingHeight,msg->strSubVer,msg->relayflag,(long long)msg->nonce);
    return(len);
}

int32_t iguana_rwmerklebranch(int32_t rwflag,uint8_t *serialized,struct iguana_msgmerkle *msg)
{
    int32_t i,len = 0;
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->branch_length);
    if ( msg->branch_length < sizeof(msg->branch_hash)/sizeof(*msg->branch_hash) )
    {
        for (i=0; i<msg->branch_length; i++)
        {
            len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->branch_hash[i]),msg->branch_hash[i].bytes);
        }
    } else return(1000000);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->branch_side_mask),&msg->branch_side_mask);
    //printf("branch_length.%d side_mask.%x\n",msg->branch_length,msg->branch_side_mask);
    return(len);
}

int32_t iguana_rwzsolution(int32_t rwflag,uint8_t *serialized,uint8_t *solution,int32_t n)
{
    int32_t i,len = 0;
    for (i=0; i<n; i++)
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(solution[i]),&solution[i]);
    return(len);
}

int32_t iguana_rwblockhdr(int32_t rwflag,uint8_t zcash,uint8_t *serialized,struct iguana_msgzblock *zmsg)
{
    struct iguana_msgzblockhdr zH; uint32_t tmp; struct iguana_msgblock *msg = (void *)zmsg; int32_t len = 0;
    if ( zcash == 0 )
    {
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->H.version),&msg->H.version);
        len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->H.prev_block),msg->H.prev_block.bytes);
        len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->H.merkle_root),msg->H.merkle_root.bytes);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->H.timestamp),&msg->H.timestamp);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->H.bits),&msg->H.bits);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->H.nonce),&msg->H.nonce);
    }
    else
    {
        if ( rwflag != 0 )
            zH = zmsg->zH;
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(zH.version),&zH.version);
        len += iguana_rwbignum(rwflag,&serialized[len],sizeof(zH.prev_block),zH.prev_block.bytes);
        len += iguana_rwbignum(rwflag,&serialized[len],sizeof(zH.merkle_root),zH.merkle_root.bytes);
        len += iguana_rwbignum(rwflag,&serialized[len],sizeof(zH.reserved),zH.reserved.bytes);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(zH.timestamp),&zH.timestamp);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(zH.bits),&zH.bits);
        len += iguana_rwbignum(rwflag,&serialized[len],sizeof(zH.bignonce),zH.bignonce.bytes);
        //char str[65]; printf("prev.(%s) len.%d [%d %d %d]\n",bits256_str(str,msg->H.prev_block),len,serialized[len],serialized[len+1],serialized[len+2]);
        if ( rwflag != 0 )
            memcpy(&serialized[len],zH.var_numelements,sizeof(zH.var_numelements));
        else memcpy(zH.var_numelements,&serialized[len],sizeof(zH.var_numelements));
        //printf("numelements: (%02x %02x %02x)\n",serialized[len],serialized[len+1],serialized[len+2]);
        len += sizeof(zH.var_numelements);
        if ( iguana_rwvarint32(0,zH.var_numelements,(uint32_t *)&tmp) != sizeof(zH.var_numelements) )
            printf("rw.%d unexpected varint size for zmsg.zH.numelements <- %d %d %d\n",rwflag,zH.var_numelements[0],zH.var_numelements[1],zH.var_numelements[2]);
        if ( tmp != ZCASH_SOLUTION_ELEMENTS )
        {
            int32_t i; for (i=0; i<157; i++)
                printf("%02x",serialized[i]);
            printf(" rw.%d unexpected ZCASH_SOLUTION_ELEMENTS, (%02x %02x %02x) expected %d tmp.%d len.%d\n",rwflag,zH.var_numelements[0],zH.var_numelements[1],zH.var_numelements[2],ZCASH_SOLUTION_ELEMENTS,tmp,len);
            return(-1);
        }
        len += iguana_rwzsolution(rwflag,&serialized[len],zH.solution,tmp);
        if ( rwflag == 0 )
            zmsg->zH = zH;
    }
    return(len);
}

int32_t iguana_eatauxpow(struct supernet_info *myinfo,int32_t rwflag,char *symbol,uint8_t zcash,uint8_t *serialized,int32_t maxlen)
{
    int32_t len = 0; void *ptr; struct iguana_msgtx msg; struct OS_memspace MEM; bits256 auxhash2,coinbasetxid; struct iguana_msgmerkle *coinbase_branch,*blockchain_branch; struct iguana_msgblock parentblock; struct iguana_info *coin;
    if ( rwflag == 0 && (coin= iguana_coinfind(symbol)) != 0 && coin->chain->auxpow != 0 )
    {
        memset(&msg,0,sizeof(msg));
        coinbase_branch = calloc(1,sizeof(*coinbase_branch));
        blockchain_branch = calloc(1,sizeof(*blockchain_branch));
        memset(&parentblock,0,sizeof(parentblock));
        memset(&MEM,0,sizeof(MEM));
        ptr = calloc(1,1000000);
        iguana_meminit(&MEM,"auxpow",ptr,1000000,0);
        len += iguana_rwtx(myinfo,coin->chain->zcash,rwflag,coin,&MEM,&serialized[len],&msg,(int32_t)MEM.totalsize,&coinbasetxid,coin->chain->isPoS,0);
        if ( len > maxlen )
            return(-1);
        len += iguana_rwbignum(rwflag,&serialized[len],sizeof(auxhash2),auxhash2.bytes);
        if ( len > maxlen )
            return(-1);
        len += iguana_rwmerklebranch(rwflag,&serialized[len],coinbase_branch);
        if ( len > maxlen )
            return(-1);
        len += iguana_rwmerklebranch(rwflag,&serialized[len],blockchain_branch);
        if ( len > maxlen )
            return(-1);
        len += iguana_rwblockhdr(rwflag,zcash,&serialized[len],(void *)&parentblock);
        if ( len > maxlen )
            return(-1);
        free(ptr);
        free(coinbase_branch);
        free(blockchain_branch);
    }
    return(len);
}

int32_t iguana_blockhdrsize(char *symbol,uint8_t zcash,uint8_t auxpow)
{
    int32_t len = 0;
    if ( zcash == 0 )
    {
        if ( auxpow == 0 )
            return(sizeof(struct iguana_msgblockhdr));
        //if ( (len= iguana_eatauxpow(0,symbol,&serialized[sizeof(struct iguana_msgblockhdr)],(int32_t)(maxlen-sizeof(struct iguana_msgblockhdr)))) > 0 )
        return(sizeof(struct iguana_msgblockhdr) + len);
        //else
        return(-1);
    } else return((int32_t)(sizeof(struct iguana_msgzblockhdr) + auxpow*sizeof(bits256)));
}

int32_t iguana_rwblock(struct supernet_info *myinfo,char *symbol,uint8_t zcash,uint8_t auxpow,int32_t (*hashalgo)(uint8_t *blockhashp,uint8_t *serialized,int32_t len),int32_t rwflag,bits256 *hash2p,uint8_t *serialized,struct iguana_msgzblock *zmsg,int32_t maxlen)
{
    int32_t len = 0; uint64_t x; struct iguana_msgblock *msg = (void *)zmsg;
    if ( (len= iguana_rwblockhdr(rwflag,zcash,serialized,zmsg)) < 0 )
    {
        int32_t i;
        for (i=0; i<maxlen&&i<sizeof(struct iguana_zblock); i++)
            printf("%02x",serialized[i]);
        printf(" error rw.%d blockhdr zcash.%d\n",rwflag,zcash);
        return(-1);
    }
    *hash2p = iguana_calcblockhash(symbol,hashalgo,serialized,len);
    if ( auxpow != 0 && (msg->H.version & 0x100) != 0 )
        len += iguana_eatauxpow(myinfo,rwflag,symbol,zcash,&serialized[len],maxlen-len);
    if ( rwflag == 1 )
    {
        if ( zcash == 0 )
            x = msg->txn_count;
        else x = zmsg->txn_count;
    }
    //char str[65],str2[65]; printf("zcash.%d len.%d: block version.%d timestamp.%u bits.%x nonce.%u prev.(%s) %llx  hash2.%s zlen.%d\n",zcash,len,msg->H.version,msg->H.timestamp,msg->H.bits,msg->H.nonce,bits256_str(str,msg->H.prev_block),(long long)msg->H.merkle_root.txid,bits256_str(str2,*hash2p),(int32_t)sizeof(struct iguana_msgzblockhdr));
    len += iguana_rwvarint(rwflag,&serialized[len],&x);
    if ( rwflag == 0 )
    {
        char str[65];
        bits256_str(str,*hash2p);
        if ( x < 65536 )
        {
            if ( zcash != 0 )
                zmsg->txn_count = (uint16_t)x;
            else msg->txn_count = (uint16_t)x;
        } else printf("txn_count overflow.%lld for %s\n",(long long)x,str);
    }
    //  ? 	txns 	tx[] 	Block transactions, in format of "tx" command
    return(len);
}

int32_t iguana_serialize_block(struct supernet_info *myinfo,struct iguana_chain *chain,bits256 *hash2p,uint8_t serialized[sizeof(struct iguana_msgzblock)],struct iguana_block *block)
{
    struct iguana_msgzblock zmsg; struct iguana_msgblock *msg = (void *)&zmsg; struct iguana_zblock *zblock; int32_t i,len;
    if ( chain->zcash == 0 )
    {
        memset(msg,0,sizeof(*msg));
        msg->H.version = block->RO.version;
        msg->H.prev_block = block->RO.prev_block;
        msg->H.merkle_root = block->RO.merkle_root;
        msg->H.timestamp = block->RO.timestamp;
        msg->H.bits = block->RO.bits;
        msg->H.nonce = block->RO.nonce;
        msg->txn_count = block->RO.txn_count;
        len = iguana_rwblock(myinfo,chain->symbol,chain->zcash,chain->auxpow,chain->hashalgo,1,hash2p,serialized,(void *)msg,IGUANA_MAXPACKETSIZE);
    }
    else
    {
        memset(&zmsg,0,sizeof(zmsg));
        zblock = (void *)block;
        zmsg.zH.version = zblock->RO.version;
        zmsg.zH.prev_block = zblock->RO.prev_block;
        zmsg.zH.merkle_root = zblock->RO.merkle_root;
        zmsg.zH.timestamp = zblock->RO.timestamp;
        zmsg.zH.bits = zblock->RO.bits;
        zmsg.zH.bignonce = zblock->zRO.bignonce;
        if ( iguana_rwvarint32(1,zmsg.zH.var_numelements,(uint32_t *)&zblock->zRO.numelements) != sizeof(zmsg.zH.var_numelements) )
        {
            // printf("unexpected varint size for zmsg.zH.numelements <- %d %d %d\n",zmsg.zH.var_numelements[0],zmsg.zH.var_numelements[1],zmsg.zH.var_numelements[2]);
        }
        if ( zblock->zRO.numelements == ZCASH_SOLUTION_ELEMENTS )
        {
            for (i=0; i<ZCASH_SOLUTION_ELEMENTS; i++)
                zmsg.zH.solution[i] = zblock->zRO.solution[i];
            zmsg.txn_count = block->RO.txn_count;
            len = iguana_rwblock(myinfo,chain->symbol,chain->zcash,chain->auxpow,chain->hashalgo,1,hash2p,serialized,(void *)&zmsg,IGUANA_MAXPACKETSIZE);
        } else return(-1);
    }
    return(len);
}

int32_t iguana_rwblockhash(int32_t rwflag,uint8_t *serialized,uint32_t *nVersionp,uint32_t *varintp,bits256 *hashes,bits256 *stophash)
{
    int32_t i,len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(*nVersionp),nVersionp);
    len += iguana_rwvarint32(rwflag,&serialized[len],varintp);
    if ( *varintp < IGUANA_MAXBUNDLESIZE+1 )
    {
        for (i=0; i<*varintp; i++)
            len += iguana_rwbignum(rwflag,&serialized[len],sizeof(hashes[i]),hashes[i].bytes);
        len += iguana_rwbignum(rwflag,&serialized[len],sizeof(*stophash),stophash->bytes);
        //for (i=0; i<len; i++)
        //    printf("%02x ",serialized[i]);
        //printf("rwblockhash len.%d\n",len);
    } else printf("iguana_rwblockhash: illegal varint.%d\n",*varintp);
    return(len);
}

int32_t iguana_rwmsgalert(struct iguana_info *coin,int32_t rwflag,uint8_t *serialized,struct iguana_msgalert *msg)
{
    bits256 alerthash2; int32_t i,plen,isvalid,len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->version);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->relayuntil),&msg->relayuntil);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->expiration),&msg->expiration);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->ID),&msg->ID);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->cancel),&msg->cancel);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->numcancellist);
    if ( msg->numcancellist != 0 )
    {
        for (i=0; i<msg->numcancellist; i++)
            len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->list[i]);
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->minver),&msg->minver);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->maxver),&msg->maxver);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->setsubvervar);
    len += iguana_rwvarstr(rwflag,&serialized[len],sizeof(msg->subver),msg->subver);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->priority),&msg->priority);
    len += iguana_rwvarstr(rwflag,&serialized[len],sizeof(msg->comment),msg->comment);
    len += iguana_rwvarstr(rwflag,&serialized[len],sizeof(msg->statusbar),msg->statusbar);
    len += iguana_rwvarstr(rwflag,&serialized[len],sizeof(msg->reserved),msg->reserved);
    alerthash2 = bits256_doublesha256(0,serialized,len);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->siglen),&msg->siglen);
    if ( msg->siglen >= 70 && msg->siglen < 74 )
    {
        if ( rwflag == 0 )
            memcpy(msg->sig,&serialized[len],msg->siglen);
        else memcpy(&serialized[len],msg->sig,msg->siglen);
        len += msg->siglen;
        plen = bitcoin_pubkeylen(coin->chain->alertpubkey);
        isvalid = (bitcoin_verify(coin->ctx,msg->sig,msg->siglen,alerthash2,coin->chain->alertpubkey,plen) == 0);
        for (i=0; i<msg->siglen; i++)
            printf("%02x",msg->sig[i]);
        printf(" %s\n",isvalid != 0 ? "VALIDSIG" : "SIGERROR");
        for (i=0; i<plen; i++)
            printf("%02x",coin->chain->alertpubkey[i]);
        char str[65]; printf(" alertpubkey.%d, alerthash2.%s\n",plen,bits256_str(str,alerthash2));
    } else msg->siglen = 0;
    //printf("  ALERT v.%d relay.%lld expires.%lld ID.%d cancel.%d numlist.%d minver.%d maxver.%d subver.(%s) priority.%d comment.(%s) STATUS.(%s) reserved.(%s)\n",msg->version,(long long)msg->relayuntil,(long long)msg->expiration,msg->ID,msg->cancel,msg->numcancellist,msg->minver,msg->maxver,msg->subver,msg->priority,msg->comment,msg->statusbar,msg->reserved);
    return(len);
}

/*int32_t iguana_request_data(struct iguana_info *coin,struct iguana_peer *addr,bits256 *hashes,int32_t n,uint32_t type,int32_t forceflag)
 {
 uint32_t len,i; uint8_t serialized[sizeof(struct iguana_msghdr) + (sizeof(uint32_t) + sizeof(bits256))*32 + sizeof(uint64_t)];
 if ( addr == 0 )
 return(-1);
 len = iguana_rwvarint32(1,&serialized[sizeof(struct iguana_msghdr)],(uint32_t *)&n);
 for (i=0; i<n; i++)
 {
 len += iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(uint32_t),&type);
 len += iguana_rwbignum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(bits256),hashes[i].bytes);
 }
 //printf("iguana_request_data.%d %s ht.%d\n",n,bits256_str(hashes[0]),iguana_height(coin,hashes[0]));
 addr->getdatamillis = milliseconds();
 len = iguana_queue_send(addr,0,serialized,"getdata",len,iguana_height(coin,hashes[n-1]),forceflag);
 return(len);
 }*/

void iguana_gotversion(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgversion *vers)
{
    uint8_t serialized[sizeof(struct iguana_msghdr)];
    //printf("gotversion from %s: starting height.%d services.%llx proto.%d (%s)\n",addr->ipaddr,vers->nStartingHeight,(long long)vers->nServices,vers->nVersion,vers->strSubVer);
    if ( strncmp(vers->strSubVer,"/iguana",strlen("/iguana")) == 0 )
        addr->supernet = 1, addr->basilisk = 0;
    else if ( strncmp(vers->strSubVer,"/basilisk",strlen("/basilisk")) == 0 )
    {
        addr->basilisk = 1, addr->supernet = 0;
    }
    //if ( (vers->nServices & NODE_NETWORK) != 0 )
    {
        addr->protover = (vers->nVersion < PROTOCOL_VERSION) ? vers->nVersion : PROTOCOL_VERSION;
        //printf("(%s) proto.%d -> %d\n",addr->ipaddr,vers->nVersion,addr->protover);
        addr->relayflag = vers->relayflag;
        addr->height = vers->nStartingHeight;
        addr->relayflag = 1;
        iguana_gotdata(coin,addr,addr->height);
    }
    iguana_queue_send(addr,0,serialized,"verack",0);
    if ( addr->supernet != 0 || addr->basilisk != 0 )
       printf("height.%d nServices.%lld nonce.%llu %srelay node.(%s) supernet.%d basilisk.%d longest.%u\n",vers->nStartingHeight,(long long)vers->nServices,(long long)vers->nonce,addr->relayflag==0?"non-":"",addr->ipaddr,addr->supernet,addr->basilisk,vers->nStartingHeight);
    if ( (int32_t)vers->nStartingHeight > coin->longestchain )
    {
        if ( coin->badlongestchain != 0 && (int32_t)vers->nStartingHeight >= coin->badlongestchain )
        {
            printf("peer.(%s) gives badlongestchain.%d\n",addr->ipaddr,vers->nStartingHeight);
            addr->dead = 1;
        } //else coin->longestchain = vers->nStartingHeight;
    }
    if ( addr->msgcounts.verack == 0 && time(NULL) > addr->ready+600 )
        iguana_send_version(coin,addr,coin->myservices);
    iguana_queue_send(addr,0,serialized,"getaddr",0);
}

int32_t iguana_send_version(struct iguana_info *coin,struct iguana_peer *addr,uint64_t myservices)
{
  	int32_t len; struct iguana_msgversion msg; uint8_t serialized[sizeof(struct iguana_msghdr)+sizeof(msg)];
    memset(&msg,0,sizeof(msg));
	msg.nVersion = coin->chain->protover;//PROTOCOL_VERSION;
	msg.nServices = (myservices & NODE_NETWORK);
	msg.nTime = (int64_t)time(NULL);
	msg.nonce = coin->instance_nonce;
    if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
        sprintf(msg.strSubVer,"/iguana 0.00/");
    else sprintf(msg.strSubVer,"/basilisk 0.00/");
    //printf("SEND.(%s) -> (%s)\n",msg.strSubVer,addr->ipaddr);
    //sprintf(msg.strSubVer,"/Satoshi:0.10.0/");
	msg.nStartingHeight = coin->blocks.hwmchain.height;
    iguana_gotdata(coin,addr,msg.nStartingHeight);
    len = iguana_rwversion(1,&serialized[sizeof(struct iguana_msghdr)],&msg,addr->ipaddr,0);
    return(iguana_queue_send(addr,0,serialized,"version",len));
}

int32_t iguana_send_VPNversion(struct iguana_info *coin,struct iguana_peer *addr,uint64_t myservices)
{
  	int32_t len; struct iguana_VPNversion msg; uint8_t serialized[sizeof(struct iguana_msghdr)+sizeof(msg)];
    memset(&msg,0,sizeof(msg));
	msg.nVersion = PROTOCOL_VERSION;
	msg.nServices = (myservices & NODE_NETWORK);
	msg.nTime = (int64_t)time(NULL);
	msg.nonce = 0;//coin->instance_nonce;
    if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
        sprintf(msg.strSubVer,"/iguana 0.00/");
    else sprintf(msg.strSubVer,"/basilisk 0.00/");
	msg.nStartingHeight = coin->blocks.hwmchain.height;
    len = iguana_rwversion(1,&serialized[sizeof(struct iguana_msghdr)],(void *)&msg,addr->ipaddr,117);
    return(iguana_queue_send(addr,0,serialized,"version",len));
}

void iguana_supernet_ping(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr)
{
    if ( addr->supernet != 0 || addr->basilisk != 0 )
    {
        //if ( coin->FULLNODE > 0 )
        //    basilisk_relays_send(myinfo,addr);
        //printf("send getpeers to %s\n",addr->ipaddr);
        //printf("maybe send basilisk ping here?\n");
        //iguana_send_supernet(addr,SUPERNET_GETPEERSTR,0);
    }
}

void iguana_gotverack(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr)
{
    uint8_t serialized[sizeof(struct iguana_msghdr)];
    if ( addr != 0 )
    {
        if ( addr->supernet != 0 || addr->basilisk != 0 )
            printf(">>>>>>>>>> supernet.%d basilisk.%d gotverack from %s\n",addr->supernet,addr->basilisk,addr->ipaddr);
        addr->A.nTime = (uint32_t)time(NULL);
        iguana_queue_send(addr,0,serialized,"getaddr",0);
        iguana_supernet_ping(myinfo,coin,addr);
    }
}

void iguana_gotaddr(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgaddress *A)
{
    char ipaddr[64],ipport[64]; uint32_t ipbits; uint16_t port;
    iguana_rwnum(0,&A->ip[12],sizeof(uint32_t),&ipbits);
    iguana_rwnum(0,(void *)&A->port,sizeof(uint16_t),&port);
    expand_ipbits(ipaddr,ipbits);
    if ( port != 0 )
        sprintf(ipport,"%s:%d",ipaddr,port);
    if ( (0) )
    {
        int32_t i;
        printf("{{");
        for (i=0; i<16; i++)
            printf("0x%02x%s",A->ip[i],i<15?",":"");
        printf("}, 14631},\n");
    }
    if ( strcmp(coin->symbol,"BTC") != 0 || (rand() % 10) == 0 )
        iguana_possible_peer(coin,ipport);
    if ( (0) && strcmp("TAZ",coin->symbol) == 0 )
        printf("iguana_gotaddr: %s from %s\n",ipaddr,addr->ipaddr);
}

void iguana_gotping(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,uint64_t nonce,uint8_t *data)
{
    int32_t len; uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(nonce)];
    len = iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr)],sizeof(uint64_t),&nonce);
    if ( memcmp(data,&serialized[sizeof(struct iguana_msghdr)],sizeof(nonce)) != 0 )
        printf("ping ser error %llx != %llx\n",(long long)nonce,*(long long *)data);
    iguana_queue_send(addr,0,serialized,"pong",len);
    iguana_supernet_ping(myinfo,coin,addr);
}

int32_t iguana_send_ping(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr)
{
  	int32_t len; uint64_t nonce; uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(nonce)];
    if ( coin->FULLNODE <= 0 )
        return(0);
    if ( addr->msgcounts.verack == 0 )
    {
        if ( strcmp(addr->ipaddr,myinfo->ipaddr) != 0 )
        {
            printf("%s send version instead of ping to %s\n",coin->symbol,addr->ipaddr);
            return(iguana_send_version(coin,addr,coin->myservices));
        }
    }
    if ( (nonce= addr->pingnonce) == 0 )
    {
        OS_randombytes((uint8_t *)&nonce,sizeof(nonce));
        addr->pingnonce = ((nonce & 0xffffffff) << 32) | ((uint32_t)addr->ipbits & 0xffffffff);
        addr->pingtime = (uint32_t)time(NULL);
    }
    //printf("pingnonce.%llx from (%s)\n",(long long)nonce,addr->ipaddr);
    iguana_queue_send(addr,0,serialized,"getaddr",0);
    len = iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr)],sizeof(uint64_t),&nonce);
    iguana_supernet_ping(myinfo,coin,addr);
    //if ( myinfo->IAMRELAY != 0 )
    //    basilisk_relays_send(myinfo,addr);
    return(iguana_queue_send(addr,0,serialized,"ping",len));
}

int32_t iguana_send_ConnectTo(struct iguana_info *coin,struct iguana_peer *addr)
{
  	int32_t len; uint32_t r; uint16_t port = 1920; uint8_t serialized[sizeof(struct iguana_msghdr) + 6];
    r = rand();
    len = iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr)],sizeof(uint32_t),&r);
    len += iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr)+len],sizeof(port),&port);
    return(iguana_queue_send(addr,0,serialized,"ConnectTo",len));
}

void iguana_gotpong(struct iguana_info *coin,struct iguana_peer *addr,uint64_t nonce)
{
    if ( addr->sendmillis != 0 )
    {
        addr->pingtime = (OS_milliseconds() - addr->sendmillis) + 1;
        addr->pingsum += addr->pingtime, addr->numpings++;
        //printf("%s pingtime %.0f numpings.%d [%.3f] ",addr->ipaddr,addr->pingtime,addr->numpings,addr->pingsum/addr->numpings);
    }
    if ( nonce != addr->pingnonce )
    {
        // printf("pong received invalid pingnonce (%s) %llx vs %llx\n",addr->ipaddr,(long long)addr->pingnonce,(long long)nonce);
    } else printf("(%s) pong verified with pingnonce.%llx\n",addr->ipaddr,(long long)addr->pingnonce);
    addr->pingnonce = 0;
    addr->sendmillis = 0;
}

int32_t iguana_gethdrs(struct iguana_info *coin,uint8_t *serialized,char *cmd,char *hashstr)
{
    uint32_t len,n; bits256 hash2; bits256 zero;
    decode_hex(hash2.bytes,sizeof(hash2),hashstr);
    memset(zero.bytes,0,sizeof(zero));
    n = 0;
    len = iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr)],sizeof(uint32_t),&n);
    n++;
    len += iguana_rwvarint32(1,&serialized[sizeof(struct iguana_msghdr) + len],(uint32_t *)&n);
    len += iguana_rwbignum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(bits256),hash2.bytes);
    len += iguana_rwbignum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(bits256),(uint8_t *)zero.bytes);
    return(iguana_sethdr((void *)serialized,coin->chain->netmagic,cmd,&serialized[sizeof(struct iguana_msghdr)],len));
}

int32_t iguana_getdata(struct iguana_info *coin,uint8_t *serialized,int32_t type,bits256 *hashes,int32_t n)
{
    uint32_t len,i; //bits256 hash2;
    len = iguana_rwvarint32(1,&serialized[sizeof(struct iguana_msghdr)],(uint32_t *)&n);
    for (i=0; i<n; i++)
    {
        len += iguana_rwnum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(uint32_t),&type);
        len += iguana_rwbignum(1,&serialized[sizeof(struct iguana_msghdr) + len],sizeof(bits256),hashes[i].bytes);
    }
    return(iguana_sethdr((void *)serialized,coin->chain->netmagic,"getdata",&serialized[sizeof(struct iguana_msghdr)],len));
}

int32_t debugtest;
int32_t iguana_rwvin(int32_t rwflag,struct iguana_info *coin,struct OS_memspace *mem,uint8_t *serialized,struct iguana_msgvin *msg,int32_t vini)
{
    int32_t len = 0; uint32_t tmp;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->prev_hash),msg->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->prev_vout),&msg->prev_vout);
    if ( rwflag == 1 )
        tmp = msg->scriptlen;
    len += iguana_rwvarint32(rwflag,&serialized[len],&tmp);
    if ( rwflag == 0 )
    {
        msg->scriptlen = tmp;
        if ( msg->scriptlen < IGUANA_MAXSCRIPTSIZE )
            msg->vinscript = iguana_memalloc(mem,msg->scriptlen,1);
        else return(0);
    }
    len += iguana_rwmem(rwflag,&serialized[len],msg->scriptlen,msg->vinscript);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->sequence),&msg->sequence);
    if ( debugtest != 0 )
    {
        char str[65]; printf("MSGvin.(%s/v%d) script[%d]\n",bits256_str(str,msg->prev_hash),msg->prev_vout,msg->scriptlen);
        int i; for (i=0; i<msg->scriptlen; i++)
            printf("%02x ",msg->vinscript[i]);
        printf(" vinscriptlen.%d, prevhash.%llx prev_vout.%d | ",msg->scriptlen,(long long)msg->prev_hash.txid,msg->prev_vout);
    }
    return(len);
}

int32_t iguana_rwvout(int32_t rwflag,struct OS_memspace *mem,uint8_t *serialized,struct iguana_msgvout *msg)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->value),&msg->value);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->pk_scriptlen);
    if ( msg->pk_scriptlen > IGUANA_MAXSCRIPTSIZE )
        return(0);
    if ( rwflag == 0 )
        msg->pk_script = iguana_memalloc(mem,msg->pk_scriptlen,1);
    len += iguana_rwmem(rwflag,&serialized[len],msg->pk_scriptlen,msg->pk_script);
    if ( debugtest != 0 )
    {
        printf("(%.8f scriptlen.%d) ",dstr(msg->value),msg->pk_scriptlen);
        int i; for (i=0; i<msg->pk_scriptlen; i++)
            printf("%02x",msg->pk_script[i]);
        printf("\n");
    }
    return(len);
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

int32_t iguana_rwtx(struct supernet_info *myinfo,uint8_t zcash,int32_t rwflag,struct iguana_info *coin,struct OS_memspace *mem,uint8_t *serialized,struct iguana_msgtx *msg,int32_t maxsize,bits256 *txidp,int32_t hastimestamp,int32_t isvpncoin)
{
    int32_t i,n,len = 0; uint8_t *txstart = serialized; char txidstr[65];
    if ( maxsize < sizeof(msg->version) )
        return(-1);
    msg->serialized = serialized;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->version);
    if ( hastimestamp != 0 )
    {
        if ( maxsize-len < sizeof(msg->timestamp) )
            return(-1);
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->timestamp),&msg->timestamp);
    }
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_in);
    if ( rwflag == 0 && msg->tx_in > 0 )
        msg->vins = iguana_memalloc(mem,msg->tx_in * sizeof(*msg->vins),1);
    if ( maxsize-len <= 0 )
        return(-1);
    for (i=0; i<msg->tx_in; i++)
    {
        if ( len+sizeof(bits256)+sizeof(int32_t) > maxsize )
        {
            {
                printf("invalid tx_in.%d len.%d vs maxsize.%d before\n",msg->tx_in,len,maxsize);
                return(-1);
            }
        }
        if ( (n= iguana_rwvin(rwflag,coin,mem,&serialized[len],&msg->vins[i],i)) >= 0 )
            len += n;
        if ( n < 0 || len+sizeof(int32_t) > maxsize )
        {
            printf("invalid tx_in.%d len.%d vs maxsize.%d\n",msg->tx_in,len,maxsize);
            return(-1);
        }
    }
    //for (i=-3; i<7; i++)
    //    printf("%02x",serialized[len+i]);
    //printf(" prev 3 bytes before tx_out\n");
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_out);
    if ( len + msg->tx_out*8 > maxsize )
    {
        printf("invalidA tx_out.%d len.%d vs maxsize.%d\n",msg->tx_out,len,maxsize);
        return(-1);
    }
 //printf("numvouts.%d ",msg->tx_out);
    if ( rwflag == 0 && msg->tx_out > 0 )
        msg->vouts = iguana_memalloc(mem,msg->tx_out * sizeof(*msg->vouts),1);
    for (i=0; i<msg->tx_out; i++)
    {
        if ( (n= iguana_rwvout(rwflag,mem,&serialized[len],&msg->vouts[i])) > 0 )
            len += n;
        if ( n <= 0 || len > maxsize )
        {
            printf("invalidB tx_out.%d len.%d vs maxsize.%d\n",msg->tx_out,len,maxsize);
            return(-1);
        }
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->lock_time),&msg->lock_time);
    if ( isvpncoin != 0 )
    {
        uint16_t ddosflag=0;
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(ddosflag),&ddosflag);
        for (; serialized[len]!=0&&len<maxsize; len++) // eat null terminated string
            ;
    }
    if ( zcash != 0 && msg->version > 1 )
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
        if ( (0) )
        {
            *txidp = bits256_doublesha256(txidstr,txstart,len);
            char str[65];
            printf("[%ld] numjoinsplits.%d version.%d numvins.%d numvouts.%d locktime.%u %s\n",sizeof(joinsplit),numjoinsplits,msg->version,msg->tx_in,msg->tx_out,msg->lock_time,bits256_str(str,*txidp));
        }
    }
    *txidp = bits256_doublesha256(txidstr,txstart,len);
    msg->allocsize = len;
    if ( coin->VALIDATENODE > 1 && rwflag == 0 && coin->RTheight > 0  )
    {
        int32_t sigsvalid; struct iguana_block *block;
        if ( (block= iguana_blockfind("sig",coin,msg->txid)) != 0 && block->sigsvalid != 0 )
            sigsvalid = 1;
        else if ( iguana_validatesigs(myinfo,coin,txstart,len) == 0 )
            sigsvalid = 1;
        else
        {
            static FILE *fp;
            if ( block != 0 )
                block->sigsvalid = 1;
            if ( fp == 0 )
                fp = fopen("validates","wb");
            if ( fp != 0 )
            {
                char str[65];
                printf("error %s validating\n",bits256_str(str,*txidp));
                for (i=0; i<len; i++)
                {
                    printf("%02x",txstart[i]);
                    fprintf(fp,"%02x",txstart[i]);
                }
                printf(" len.%d\n\n",len);
                fprintf(fp,"\n");
                fflush(fp);
            }
        }
        //return(0);
    }
    return(len);
}

char *iguana_txscan(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *json,uint8_t *data,int32_t recvlen,bits256 txid)
{
    struct iguana_msgtx tx; bits256 hash2; struct iguana_zblock *zblock; struct iguana_block *block; struct iguana_msgzblock zmsg; struct iguana_msgblock *msg = (void *)&zmsg;
    int32_t i,n,len,txn_count,extralen = 65356; char *txbytes,vpnstr[64]; uint8_t *extraspace,blockspace[sizeof(*block)+sizeof(struct iguana_zblock)];
    zblock = (void *)blockspace;
    block = (void *)blockspace;
    memset(&zmsg,0,sizeof(zmsg));
    vpnstr[0] = 0;
    extraspace = calloc(1,extralen);
    if ( coin->chain->zcash == 0 )
    {
        len = iguana_rwblock(myinfo,coin->symbol,coin->chain->zcash,coin->chain->auxpow,coin->chain->hashalgo,0,&hash2,data,(void *)msg,recvlen);
        iguana_blockconv(coin->chain->zcash,coin->chain->auxpow,(void *)block,(void *)msg,hash2,-1);
        txn_count = msg->txn_count;
    }
    else
    {
        len = iguana_rwblock(myinfo,coin->symbol,coin->chain->zcash,coin->chain->auxpow,coin->chain->hashalgo,0,&hash2,data,(void *)&zmsg,recvlen);
        iguana_blockconv(coin->chain->zcash,coin->chain->auxpow,zblock,&zmsg,hash2,-1);
        txn_count = zmsg.txn_count;
    }
    for (i=0; i<txn_count; i++)
    {
        if ( (n= iguana_rwmsgtx(coin,coin->blocks.hwmchain.height,0,0,&data[len],recvlen - len,&tx,&tx.txid,vpnstr,extraspace,extralen,0,0)) < 0 )
            break;
        char str[65]; printf("%d of %d: %s len.%d\n",i,txn_count,bits256_str(str,tx.txid),len);
        if ( bits256_cmp(txid,tx.txid) == 0 )
        {
            if ( (n= iguana_rwmsgtx(coin,coin->blocks.hwmchain.height,0,json,&data[len],recvlen - len,&tx,&tx.txid,vpnstr,extraspace,extralen,0,0)) > 0 )
            {
                txbytes = malloc(n*2+1);
                init_hexbytes_noT(txbytes,&data[len],n);
                free(extraspace);
                return(txbytes);
            }
        }
        len += n;
    }
    return(0);
}

int32_t iguana_gentxarray(struct supernet_info *myinfo,struct iguana_info *coin,struct OS_memspace *mem,struct iguana_txblock *txdata,int32_t *lenp,uint8_t *data,int32_t recvlen)
{
    struct iguana_msgtx *tx; bits256 hash2; struct iguana_msgzblock zmsg; int32_t txn_count,i,n,hdrlen,len,numvouts,numvins; char str[65];
    memset(&zmsg,0,sizeof(zmsg));
    len = iguana_rwblock(myinfo,coin->symbol,coin->chain->zcash,coin->chain->auxpow,coin->chain->hashalgo,0,&hash2,data,(void *)&zmsg,recvlen);
    hdrlen = len;
    if ( len > recvlen )
    {
        printf("gentxarray error len.%d > recvlen.%d\n",len,recvlen);
        return(-1);
    }
    txn_count = iguana_blockconv(coin->chain->zcash,coin->chain->auxpow,(void *)&txdata->zblock,&zmsg,hash2,-1);
    numvins = numvouts = 0;
    if ( txn_count > 0 )
    {
        tx = iguana_memalloc(mem,txn_count*sizeof(*tx),1);
        for (i=0; i<txn_count; i++)
        {
            if ( len+32 > recvlen )
            {
                printf("gentxarrayB error len.%d > recvlen.%d\n",len,recvlen);
                return(-1);
            }
            if ( (n= iguana_rwtx(myinfo,coin->chain->zcash,0,coin,mem,&data[len],&tx[i],recvlen - len,&tx[i].txid,coin->chain->isPoS,strcmp(coin->symbol,"VPN")==0)) < 0 )
            {
                //for (i=0; i<recvlen-hdrlen; i++)
                //    printf("%02x",data[hdrlen+i]);
                printf(" <- gentxarrayC error i.%d len.%d > recvlen.%d, n.%d hdrlen.%d\n",i,len,recvlen,n,hdrlen);
                return(-1);
            }
            numvouts += tx[i].tx_out;
            numvins += tx[i].tx_in;
            len += n;
        }
        if ( coin->chain->isPoS != 0 && len != recvlen && data[len] == (recvlen - len - 1) )
        {
            //printf("\n>>>>>>>>>>> len.%d vs recvlen.%d [%d]\n",len,recvlen,data[len]);
            memcpy(txdata->space,&data[len],recvlen-len);
            len += (recvlen-len);
            txdata->extralen = (recvlen - len);
        } else txdata->extralen = 0;
    }
    if ( coin->chain->auxpow != 0 && len != recvlen )
        printf("numtx.%d %s hdrlen.%d len.%d vs recvlen.%d v.%08x\n",txn_count,bits256_str(str,hash2),hdrlen,len,recvlen,txdata->zblock.RO.version);
    txdata->recvlen = len;
    txdata->numtxids = txn_count;
    txdata->numunspents = numvouts;
    txdata->numspends = numvins;
    return(len);
}

int32_t iguana_send_hashes(struct iguana_info *coin,char *command,struct iguana_peer *addr,bits256 stophash,bits256 *hashes,int32_t n)
{
  	uint32_t len,nVersion,varint; int32_t retval = -1; uint8_t *serialized; long size;
    size = sizeof(struct iguana_msghdr) + sizeof(uint64_t) + 1 + sizeof(bits256)*(n+1);
    if ( (varint= n) <= IGUANA_MAXINV )
    {
        serialized = mycalloc('h',1,size);
        nVersion = 0;
        len = iguana_rwblockhash(1,&serialized[sizeof(struct iguana_msghdr)],&nVersion,&varint,hashes,&stophash);
        //printf("%s send_hashes.%d %s height.%d\n",addr->ipaddr,n,bits256_str(hashes[0]),iguana_height(coin,hashes[0]));
        retval = iguana_queue_send(addr,0,serialized,command,len);
        myfree(serialized,size);
    } else printf("iguana_send_hashes: unexpected n.%d\n",n);
    return(retval);
}

int32_t iguana_intvectors(struct iguana_info *coin,struct iguana_peer *addr,int32_t processflag,uint8_t *data,int32_t datalen) // other side needs to be a bit smart about what hashes are sents in
{
    uint32_t type; bits256 *txids=0,*quotes=0,*blockhashes=0,hash; int32_t i,n,q,m,len; uint64_t x;
    len = n = m = q = 0;
    len += iguana_rwvarint(0,&data[len],&x);
    for (i=0; i<x; i++)
    {
        len += iguana_rwnum(0,&data[len],sizeof(uint32_t),&type);
        len += iguana_rwbignum(0,&data[len],sizeof(bits256),hash.bytes);
        if ( type == MSG_TX )
        {
            if ( txids == 0 )
                txids = mycalloc('t',(int32_t)x+1,sizeof(*txids));
            txids[m++] = hash;
            if ( (rand() % 1000) == 0 && i == x-1 )
                printf("%s %d of %d: tx.%llx len.%d\n",addr->ipaddr,i,(int32_t)x,(long long)hash.txid,len);
        }
        else if ( type == MSG_BLOCK )
        {
            if ( blockhashes == 0 )
            {
                blockhashes = mycalloc('f',(int32_t)x+1,sizeof(*blockhashes));
                n = 1;
            }
            blockhashes[n++] = hash;
        }
        /*else if ( type == MSG_QUOTE )
        {
            if ( quotes == 0 )
            {
                quotes = mycalloc('q',(int32_t)x+1,sizeof(*quotes));
                q = 1;
            }
            quotes[q++] = hash;
        }*/
        else if ( type == MSG_FILTERED_BLOCK )
            printf(" %d of %d: merkle.%llx\n",i,(int32_t)x,(long long)hash.txid);
        else printf("what type is %d\n",type);
    }
    if ( n > 0 )
    {
        if ( n != x+1 )
        {
            printf("n.%d != x.%d -> realloc blockhashes\n",n,(int32_t)x+1);
            blockhashes = myrealloc('f',blockhashes,(int32_t)((x+1)*sizeof(*blockhashes)),n*sizeof(*blockhashes));
        } // else printf("n.%d == x.%d\n",n,(int32_t)x);
        if ( processflag != 0 )
            iguana_gotblockhashesM(coin,addr,blockhashes,n), blockhashes = 0;
    }
    if ( m > 0 )
    {
        if ( m != x )
            txids = myrealloc('t',txids,(int32_t)((x+1)*sizeof(*txids)),(m+1)*sizeof(*txids));
        if ( processflag != 0 )
            iguana_gottxidsM(coin,addr,txids,m), txids = 0;
    }
    if ( q > 0 )
    {
        if ( q != x )
            quotes = myrealloc('q',quotes,(int32_t)((x+1)*sizeof(*quotes)),(q+1)*sizeof(*quotes));
        if ( processflag != 0 )
            iguana_gotquotesM(coin,addr,quotes,q), quotes = 0;
    }
    if ( txids != 0 )
        myfree(txids,sizeof(*txids) * (x+1));
    if ( blockhashes != 0 )
        myfree(blockhashes,sizeof(*blockhashes) * (x+1));
    return(len);
    //printf("intvectors.%c recvlen.%d\n",intvectors,recvlen);
}

int32_t iguana_msgparser(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,struct OS_memspace *rawmem,struct OS_memspace *txmem,struct OS_memspace *hashmem,struct iguana_msghdr *H,uint8_t *data,int32_t recvlen,int32_t fromcache)
{
    uint8_t serialized[16384]; char *ipaddr; int32_t i,n=0,retval=-1,ishost,srvmsg,bloom,sendlen=0,intvectors,len= -100; uint64_t nonce,x;  bits256 hash2;
    bloom = intvectors = srvmsg = -1;
    if ( strncmp(H->command+1,"uperNET",strlen("uperNET")) == 0 || strncmp(H->command,"uperNet",strlen("uperNet")) == 0 )
    {
        if ( addr != 0 )
        {
            if ( H->command[0] == 'S' )
                addr->supernet = 1, addr->basilisk = 0;
            else if ( H->command[0] == 's' )
                addr->basilisk = 1, addr->supernet = 0;
            ipaddr = addr->ipaddr;
        } else ipaddr = 0;
        len = recvlen;
        //printf("GOT.(%s) len.%d from %s\n",H->command,recvlen,addr->ipaddr);
        basilisk_p2p(myinfo,coin,addr,ipaddr,data,recvlen,&H->command[strlen("SuperNET")],H->command[6] == 'e' && H->command[7] == 't');
        return(0);
    }
    if ( addr != 0 )
    {
        if ( (0) && addr->msgcounts.verack == 0 )
            printf("iguana_msgparser verack.%d from (%s) parse.(%s) len.%d\n",addr->msgcounts.verack,addr->ipaddr,H->command,recvlen);
        //iguana_peerblockrequest(coin,addr->blockspace,IGUANA_MAXPACKETSIZE,addr,iguana_blockhash(coin,100),0);
        addr->lastcontact = (uint32_t)time(NULL);
        strcpy(addr->lastcommand,H->command);
        retval = 0;
        if ( (ishost= (strcmp(H->command,"getblocks") == 0)) || strcmp(H->command,"block") == 0 )
        {
            if ( addr != 0 && rawmem->ptr != 0 )
            {
                struct iguana_txblock txdata;
                iguana_memreset(rawmem), iguana_memreset(txmem);
                memset(&txdata,0,sizeof(txdata));
                if ( ishost == 0 )
                {
                    if ( coin->chain->debug != 0 )
                    {
                        int32_t i,max;
                        max = coin->chain->zcash == 0 ? 80 : sizeof(struct iguana_msgzblockhdr);
                        for (i=0; i<max; i++)
                            printf("%02x",data[i]);
                        printf(" block.[%d]\n",max);
                    }
                    addr->msgcounts.block++;
                    if ( (n= iguana_gentxarray(myinfo,coin,rawmem,&txdata,&len,data,recvlen)) == recvlen || n == recvlen-1 )
                    {
                        len = n;
                        iguana_gotblockM(myinfo,coin,addr,&txdata,rawmem->ptr,H,data,recvlen,fromcache,0*coin->chain->zcash);
                    }
                    else
                    {
                        //for (i=0; i<recvlen; i++)
                        //    printf("%02x",data[i]);
                        printf(" parse error block txn_count.%d, n.%d len.%d vs recvlen.%d from.(%s)\n",txdata.zblock.RO.txn_count,n,len,recvlen,addr->ipaddr);
                    }
                }
                else
                {
                    len = iguana_peergetrequest(myinfo,coin,addr,data,recvlen,1);
                    //printf("peergetrequest len.%d\n",len);
                }
            } else printf("command.(%s) addr.%p rawmemptr.%p\n",H->command,addr,rawmem->ptr);
        }
        else if ( (ishost= (strncmp(H->command,"inv",3) == 0)) || strncmp(H->command,"getdata",7) == 0 )
        {
            if ( addr != 0 )
            {
                if ( ishost == 0 )
                {
                    addr->msgcounts.getdata++;
                    len = iguana_peerdatarequest(coin,addr,data,recvlen);
                }
                else
                {
                    intvectors = 'I', addr->msgcounts.inv++;
                    if ( (0) && strcmp(H->command,"inv2") == 0 )
                        printf("GOT INV2.%d\n",recvlen);
                    len = iguana_intvectors(coin,addr,1,data,recvlen); // indirectly issues getdata
                }
            }
        }
        else if ( (ishost= (strcmp(H->command,"getheaders") == 0)) || strcmp(H->command,"headers") == 0 )
        {
            struct iguana_msgzblock zmsg; struct iguana_msgblock *msg = (void *)&zmsg; struct iguana_zblock *zblocks; uint32_t tmp,n=0;
            len = 0;
            if ( addr != 0 && recvlen >= sizeof(bits256) && strcmp("RELAY",coin->symbol) != 0 )
            {
                if ( ishost == 0 )
                {
                    len = iguana_rwvarint32(0,data,&n);
                    if ( n <= IGUANA_MAXINV )
                    {
                        bits256 auxhash2,prevhash2; struct iguana_msgtx *tx; struct iguana_msgmerkle *coinbase_branch=0,*blockchain_branch=0; struct iguana_msgblock parentblock;
                        if ( rawmem->totalsize == 0 )
                            iguana_meminit(rawmem,"bighdrs",0,IGUANA_MAXPACKETSIZE * 3,0);
                        memset(prevhash2.bytes,0,sizeof(prevhash2));
                        zblocks = mycalloc('z',1,(int32_t)(sizeof(struct iguana_zblock) * n));
                        //printf("%s got %d headers len.%d\n",coin->symbol,n,recvlen);
                        for (i=0; i<n; i++)
                        {
                            if ( coin->chain->auxpow != 0 )
                            {
                                if ( coinbase_branch == 0 )
                                    coinbase_branch = calloc(1,sizeof(*coinbase_branch));
                                if ( blockchain_branch == 0 )
                                    blockchain_branch = calloc(1,sizeof(*blockchain_branch));
                                tmp = iguana_rwblockhdr(0,coin->chain->zcash,&data[len],(void *)msg);
                                hash2 = iguana_calcblockhash(coin->symbol,coin->chain->hashalgo,&data[len],tmp);
                                len += tmp;
                                if ( (msg->H.version & 0x100) != 0 )
                                {
                                    iguana_memreset(rawmem);
                                    tx = iguana_memalloc(rawmem,sizeof(*tx),1);
                                    len += iguana_rwtx(myinfo,coin->chain->zcash,0,coin,rawmem,&data[len],tx,recvlen-len,&tx->txid,coin->chain->isPoS,strcmp(coin->symbol,"VPN")==0);
                                    len += iguana_rwbignum(0,&data[len],sizeof(auxhash2),auxhash2.bytes);
                                    len += iguana_rwmerklebranch(0,&data[len],coinbase_branch);
                                    len += iguana_rwmerklebranch(0,&data[len],blockchain_branch);
                                    len += iguana_rwblockhdr(0,coin->chain->zcash,&data[len],(void *)&parentblock);
                                }
                                len += iguana_rwvarint32(0,&data[len],&tmp);
                                char str[65],str2[65];
                                if ( (0) && coin->chain->auxpow != 0 )
                                    printf("%d %d of %d: %s %s v.%08x numtx.%d cmp.%d\n",len,i,n,bits256_str(str,hash2),bits256_str(str2,zmsg.zH.prev_block),zmsg.zH.version,tmp,bits256_cmp(prevhash2,zmsg.zH.prev_block));
                            }
                            else len += iguana_rwblock(myinfo,coin->chain->symbol,coin->chain->zcash,coin->chain->auxpow,coin->chain->hashalgo,0,&hash2,&data[len],(void *)&zmsg,recvlen);
                            iguana_blockconv(coin->chain->zcash,coin->chain->auxpow,(void *)&zblocks[i],&zmsg,hash2,-1);
                            prevhash2 = hash2;
                        }
                        if ( coinbase_branch != 0 )
                            free(coinbase_branch);
                        if ( blockchain_branch != 0 )
                            free(blockchain_branch);
                        if ( iguana_gotheadersM(coin,addr,zblocks,n) < 0 )
                            myfree(zblocks,(int32_t)(sizeof(struct iguana_zblock) * n));
                        if ( len == recvlen && addr != 0 )
                            addr->msgcounts.headers++;
                    } else printf("got unexpected n.%d for headers\n",n);
                }
                else if ( addr->headerserror == 0 )
                {
                    len = iguana_peergetrequest(myinfo,coin,addr,data,recvlen,0);
                }
            }
        }
        else if ( (ishost= (strcmp(H->command,"version") == 0)) || strcmp(H->command,"verack") == 0 )
        {
            if ( addr != 0 )
            {
                if ( ishost != 0 )
                {
                    struct iguana_msgversion recvmv;
                    len = iguana_rwversion(0,data,&recvmv,addr->ipaddr,recvlen);
                    if ( len <= recvlen )
                        iguana_gotversion(myinfo,coin,addr,&recvmv);
                    addr->msgcounts.version++;
                }
                else
                {
                    iguana_gotverack(myinfo,coin,addr);
                    addr->msgcounts.verack++;
                    len = 0;
                }
            }
        }
        else if ( (ishost= (strcmp(H->command,"ping") == 0)) || strcmp(H->command,"pong") == 0 )
        {
            len = 0;
            if ( recvlen == sizeof(uint64_t) && addr != 0 )
            {
                len = iguana_rwnum(0,data,sizeof(uint64_t),&nonce);
                if ( addr != 0 )
                {
                    //printf("%u got nonce.%llx from %s\n",(uint32_t)time(NULL),(long long)nonce,addr->ipaddr);
                    if ( ishost != 0 )
                    {
                        iguana_gotping(myinfo,coin,addr,nonce,data);
                        addr->msgcounts.ping++;
                    }
                    else
                    {
                        iguana_gotpong(coin,addr,nonce);
                        addr->msgcounts.pong++;
                    }
                    iguana_queue_send(addr,0,serialized,"getaddr",0);
                }
            }
        }
        else if ( (ishost= (strcmp(H->command,"getaddr") == 0)) || strcmp(H->command,"addr") == 0 )
        {
            struct iguana_msgaddress A;
            //printf("iguana_msgparser from (%s) parse.(%s) len.%d\n",addr->ipaddr,H->command,recvlen);
            if ( addr != 0 )
            {
                if ( ishost == 0 )
                {
                    //for (i=0; i<recvlen; i++)
                    //    printf("%02x",data[i]);
                    //printf(" addr recvlen.%d\n",recvlen);
                    len = iguana_rwvarint(0,data,&x);
                    for (i=0; i<x; i++)
                    {
                        memset(&A,0,sizeof(A));
                        len += iguana_rwaddr(0,&data[len],&A,CADDR_TIME_VERSION);//(int32_t)addr->protover);
                        iguana_gotaddr(coin,addr,&A);
                    }
                    if ( len == recvlen )
                    {
                        addr->lastgotaddr = (uint32_t)time(NULL);
                        addr->msgcounts.addr++;
                    }
                }
                else
                {
                    len = 0;
                    if ( (sendlen= iguana_peeraddrrequest(coin,addr,&addr->blockspace[sizeof(H)],IGUANA_MAXPACKETSIZE)) > 0 )
                    {
                        if ( (0) )
                        {
                            int32_t checklen; uint32_t checkbits; char checkaddr[64];
                            checklen = iguana_rwvarint(0,&addr->blockspace[sizeof(H)],&x);
                            printf("\nSENDING:\n");
                            for (i=0; i<sendlen; i++)
                                printf("%02x",addr->blockspace[sizeof(H)+i]);
                            printf(" %p addr sendlen.%d N.%d\n",&addr->blockspace[sizeof(H)],sendlen,(int32_t)x);
                            for (i=0; i<x; i++)
                            {
                                memset(&A,0,sizeof(A));
                                checklen += iguana_rwaddr(0,&addr->blockspace[sizeof(H) + checklen],&A,CADDR_TIME_VERSION);
                                iguana_rwnum(0,&A.ip[12],sizeof(uint32_t),&checkbits);
                                expand_ipbits(checkaddr,checkbits);
                                printf("checkaddr.(%s:%02x%02x) ",checkaddr,((uint8_t *)&A.port)[1],((uint8_t *)&A.port)[0]);
                            }
                            printf("x.%d\n",(int32_t)x);
                        }
                        retval = iguana_queue_send(addr,0,addr->blockspace,"addr",sendlen);
                    }
                    addr->msgcounts.getaddr++;
                }
            }
            //printf("%s -> addr recvlen.%d num.%d\n",addr->ipaddr,recvlen,(int32_t)x);
        }
        else if ( strcmp(H->command,"notfound") == 0 )
        {
            if ( addr != 0 )
            {
                printf("%s SERVER notfound\n",addr->ipaddr);
                intvectors = 'N', addr->msgcounts.notfound++;
                len = iguana_intvectors(coin,addr,1,data,recvlen);
            }
        }
        else if ( strcmp(H->command,"mempool") == 0 )
        {
            if ( addr != 0 )
            {
                printf("%s SERVER mempool\n",addr->ipaddr);
                srvmsg = 'M', addr->msgcounts.mempool++;
            }
        }
        else if ( strcmp(H->command,"tx") == 0 )
        {
            struct iguana_msgtx *tx;
            iguana_memreset(rawmem);
            tx = iguana_memalloc(rawmem,sizeof(*tx),1);//mycalloc('u',1,sizeof(*tx));
            len = iguana_rwtx(myinfo,coin->chain->zcash,0,coin,rawmem,data,tx,recvlen,&tx->txid,coin->chain->isPoS,strcmp(coin->symbol,"VPN")==0);
            if ( addr != 0 )
            {
                iguana_gotunconfirmedM(coin,addr,tx,data,recvlen);
                printf("tx recvlen.%d vs len.%d\n",recvlen,len);
                addr->msgcounts.tx++;
            }
        }
        else if ( addr != 0 && strcmp(H->command,"ConnectTo") == 0 )
        {
            iguana_queue_send(addr,0,serialized,"getaddr",0);
            len = 6;
        }
        else if ( strcmp(H->command,"reject") == 0 )
        {
            if ( addr != 0 )
            {
                if ( strncmp((char *)data+1,"headers",7) == 0 )
                    addr->headerserror++;
                else
                {
                    for (i=0; i<recvlen&&i<100; i++)
                        printf("%02x ",data[i]);
                    printf("%s reject.(%s) recvlen.%d %s proto.%d\n",coin->symbol,data+1,recvlen,addr->ipaddr,addr->protover);
                    addr->msgcounts.reject++;
                }
            }
            len = recvlen;
        }
        else if ( strcmp(H->command,"alert") == 0 )
        {
            struct iguana_msgalert alert;
            memset(&alert,0,sizeof(alert));
            len = iguana_rwmsgalert(coin,0,data,&alert);
            if ( len == recvlen && addr != 0 )
                addr->msgcounts.alert++;
        }
        else if ( addr != 0 )
        {
            if ( strcmp(H->command,"filterload") == 0 ) // for bloom
                bloom = 'L', addr->msgcounts.filterload++;
            else if ( strcmp(H->command,"filteradd") == 0 ) // for bloom
                bloom = 'A', addr->msgcounts.filteradd++;
            else if ( strcmp(H->command,"filterclear") == 0 ) // for bloom
                bloom = 'C', addr->msgcounts.filterclear++;
            else if ( strcmp(H->command,"merkleblock") == 0 ) // for bloom
                bloom = 'M', addr->msgcounts.merkleblock++;
        }
        if ( bloom >= 0 || srvmsg >= 0 )
            len = recvlen; // just mark as valid
        if ( len != recvlen && len != recvlen-1 && len != recvlen-2 )
        {
            //printf("error.(%s) (%s): len.%d != recvlen.%d\n",H->command,addr->ipaddr,len,recvlen);
            //for (i=0; i<len; i++)
            //    printf("%02x",data[i]);
            if ( len != 0 && strcmp(H->command,"addr") != 0 && (coin->chain->auxpow == 0 || strcmp(H->command,"headers") != 0) && strcmp(H->command,"alert") != 0 )
                printf("%s %s.%s len mismatch %d != %d\n",coin->symbol,addr!=0?addr->ipaddr:"local",H->command,len,recvlen);
        }
        else if ( len != recvlen && recvlen > 1 )
        {
            //printf("%s extra byte.[%02x] command.%s len.%d recvlen.%d\n",addr->ipaddr,data[recvlen-1],H->command,len,recvlen);
            //retval = -1;
        }
    }
    return(retval);
}
