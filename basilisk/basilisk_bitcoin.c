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

/*struct bitcoin_rawtxdependents
{
    int64_t spentsatoshis,outputsum,cost,change;
    int32_t numptrs,numresults;
    char **results,*coinaddrs;
    struct basilisk_item *ptrs[];
};*/

#ifdef bitcoincancalculatebalances
char *bitcoin_balance(struct iguana_info *coin,char *coinaddr,int32_t lastheight,int32_t minconf)
{
    int32_t i,n,height,maxconf=1<<30; int64_t balance = 0; char params[512],*curlstr; cJSON *array,*retjson,*curljson;
    retjson = cJSON_CreateObject();
    if ( (curlstr= bitcoind_getinfo(coin->symbol,coin->chain->serverport,coin->chain->userpass,coin->getinfostr)) != 0 )
    {
        if ( (curljson= cJSON_Parse(curlstr)) != 0 )
        {
            if ( (height= juint(curljson,"blocks")) > lastheight )
                maxconf = height - lastheight;
            free_json(curljson);
        }
        free(curlstr);
    }
    sprintf(params,"%d, %d, [\"%s\"]",minconf,maxconf,coinaddr);
    if ( (curlstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"listunspent",params)) != 0 )
    {
        if ( (array= cJSON_Parse(curlstr)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                    balance += SATOSHIDEN * jdouble(jitem(array,i),"satoshis");
            }
            free_json(array);
        }
        free(curlstr);
    }
    jaddnum(retjson,"balance",dstr(balance));
    return(jprint(retjson,1));
}

int64_t bitcoin_value(struct iguana_info *coin,bits256 txid,int16_t vout,char *coinaddr)
{
    char params[512],str[65]; char *curlstr; cJSON *txobj,*vouts,*item,*sobj,*addrs; int32_t j,m,n; int64_t value = 0;
    sprintf(params,"[\"%s\", 1]",bits256_str(str,txid));
    if ( (curlstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getrawtransaction",params)) != 0 )
    {
        if ( (txobj= cJSON_Parse(curlstr)) != 0 )
        {
            if ( (vouts= jarray(&n,txobj,"vout")) != 0 && vout < n )
            {
                item = jitem(vouts,vout);
                if ( (sobj= jobj(item,"scriptPubKey")) != 0 && (addrs= jarray(&m,sobj,"addresses")) != 0 )
                {
                    for (j=0; j<m; j++)
                    {
                        if ( strcmp(jstri(addrs,j),coinaddr) == 0 )
                        {
                            value = SATOSHIDEN * jdouble(item,"satoshis");
                            break;
                        }
                    }
                }
            }
            free_json(txobj);
        }
        free(curlstr);
    }
    return(value);
}

char *basilisk_bitcoinblockhashstr(char *coinstr,char *serverport,char *userpass,int32_t height)
{
    char numstr[128],*blockhashstr=0; bits256 hash2; struct iguana_info *coin;
    sprintf(numstr,"%d",height);
    if ( (blockhashstr= bitcoind_passthru(coinstr,serverport,userpass,"getblockhash",numstr)) == 0 )
        return(0);
    hash2 = bits256_conv(blockhashstr);
    if ( blockhashstr == 0 || blockhashstr[0] == 0 || bits256_nonz(hash2) == 0 )
    {
        printf("couldnt get blockhash for %u, probably curl is disabled\n",height);
        if ( blockhashstr != 0 )
            free(blockhashstr);
        if ( height == 0 )
        {
            if ( (coin= iguana_coinfind(coinstr)) != 0 )
            {
                bits256_str(numstr,*(bits256 *)coin->chain->genesis_hashdata);
                return(clonestr(numstr));
            }
        }
        return(0);
    }
    return(blockhashstr);
}

int32_t basilisk_blockhashes(struct iguana_info *coin,int32_t height,int32_t n)
{
    char *blockhashstr; struct iguana_block *block,*checkblock; struct iguana_bundle *bp=0; int32_t bundlei,checki,h,i,num = 0; bits256 zero,hash2;
    h = height;
    for (i=0; i<n; i++,h++)
    {
        hash2 = iguana_blockhash(coin,h);
        if ( 0 && (block= iguana_blockfind("basilisk",coin,hash2)) != 0 && block->height == h && block->mainchain != 0 )
            continue;
        if ( (blockhashstr= basilisk_bitcoinblockhashstr(coin->symbol,coin->chain->serverport,coin->chain->userpass,h)) != 0 && bits256_nonz(hash2) != 0 )
        {
            hash2 = bits256_conv(blockhashstr);
            memset(zero.bytes,0,sizeof(zero));
            block = iguana_blockhashset("remote",coin,h,hash2,1);
            if ( (bundlei= (h % coin->chain->bundlesize)) == 0 )
                bp = iguana_bundlecreate(coin,&checki,h,hash2,zero,1);
            iguana_bundlehash2add(coin,&checkblock,bp,bundlei,hash2);
            if ( block != checkblock )
                printf("bp.%p block mismatch %p %p at ht.%d bundlei.%d\n",bp,block,checkblock,h,bundlei);
            else
            {
                block->mainchain = 1;
                char str[65]; printf("%s ht.%d\n",bits256_str(str,hash2),h);
                num++;
            }
            free(blockhashstr);
        }
    }
    return(num);
}

int32_t basilisk_blockheight(struct iguana_info *coin,bits256 hash2)
{
    char buf[128],str[65],*blocktxt; cJSON *blockjson; int32_t height=-1;
    sprintf(buf,"\"%s\"",bits256_str(str,hash2));
    if ( (blocktxt= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getblock",buf)) != 0 )
    {
        if ( (blockjson= cJSON_Parse(blocktxt)) != 0 )
        {
            height = jint(blockjson,"height");
            free_json(blockjson);
        }
        free(blocktxt);
    }
    return(height);
}

cJSON *bitcoin_blockjson(int32_t *heightp,char *coinstr,char *serverport,char *userpass,char *blockhashstr,int32_t height)
{
    cJSON *json = 0; int32_t flag = 0; char buf[1024],*blocktxt = 0;
    if ( blockhashstr == 0 )
        blockhashstr = basilisk_bitcoinblockhashstr(coinstr,serverport,userpass,height), flag = 1;
    if ( blockhashstr != 0 )
    {
        sprintf(buf,"\"%s\"",blockhashstr);
        blocktxt = bitcoind_passthru(coinstr,serverport,userpass,"getblock",buf);
        //printf("get_blockjson.(%d %s) %s\n",height,blockhashstr,blocktxt);
        if ( blocktxt != 0 && blocktxt[0] != 0 && (json= cJSON_Parse(blocktxt)) != 0 && heightp != 0 )
            if ( (*heightp= juint(json,"height")) != height )
                *heightp = -1;
        if ( flag != 0 && blockhashstr != 0 )
            free(blockhashstr);
        if ( blocktxt != 0 )
            free(blocktxt);
    }
    return(json);
}

int32_t basilisk_bitcoinscan(struct iguana_info *coin,uint8_t origblockspace[IGUANA_MAXPACKETSIZE],struct OS_memspace *rawmem)
{
    struct iguana_txblock txdata; struct iguana_block B; int32_t len,starti,h,num=0,loadheight,hexlen,datalen,n,i,numtxids,flag=0,j,height=-1; cJSON *curljson,*blockjson,*txids; char *bitstr,*curlstr,params[128],str[65]; struct iguana_msghdr H; struct iguana_msgblock *msg; uint8_t *blockspace,revbits[4],bitsbuf[4]; bits256 hash2,checkhash2;
    strcpy(params,"[]");
    if ( (curlstr= bitcoind_getinfo(coin->symbol,coin->chain->serverport,coin->chain->userpass,coin->getinfostr)) != 0 )
    {
        if ( (curljson= cJSON_Parse(curlstr)) != 0 )
        {
            height = juint(curljson,"blocks");
            free_json(curljson);
        }
        free(curlstr);
    }
    loadheight = coin->blocks.hwmchain.height;
    basilisk_blockhashes(coin,loadheight,coin->chain->bundlesize);
    for (j=0; j<coin->chain->bundlesize; j++)
    {
        if ( loadheight == 0 )
        {
            loadheight++;
            continue;
        }
        basilisk_blockhashes(coin,loadheight,1);
        flag = 0;
        if ( (blockjson= bitcoin_blockjson(&h,coin->symbol,coin->chain->serverport,coin->chain->userpass,0,loadheight)) != 0 )
        {
            blockspace = origblockspace;
            memset(&B,0,sizeof(B));
            B.RO.version = juint(blockjson,"version");
            B.RO.prev_block = jbits256(blockjson,"previousblockhash");
            B.RO.merkle_root = jbits256(blockjson,"merkleroot");
            B.RO.timestamp = juint(blockjson,"time");
            if ( (bitstr= jstr(blockjson,"nBits")) != 0 )
            {
                decode_hex(revbits,sizeof(uint32_t),bitstr);
                for (i=0; i<4; i++)
                    bitsbuf[i] = revbits[3 - i];
                memcpy(&B.RO.bits,bitsbuf,sizeof(B.RO.bits));
            }
            printf("need to handle zcash/auxpow\n");
            B.RO.nonce = juint(blockjson,"nonce");
            //char str[65],str2[65];
            //printf("v.%d t.%u bits.%08x nonce.%x %s %s\n",B.RO.version,B.RO.timestamp,B.RO.bits,B.RO.nonce,bits256_str(str,B.RO.prev_block),bits256_str(str2,B.RO.merkle_root));
            iguana_serialize_block(coin->chain,&checkhash2,blockspace,&B);
             msg = (void *)blockspace;
            //printf("(%s)\n",jprint(blockjson,0));
            checkhash2 = iguana_calcblockhash(coin->symbol,coin->chain->hashalgo,blockspace,sizeof(*msg)-4);
            if ( jstr(blockjson,"hash") != 0 )
                hash2 = bits256_conv(jstr(blockjson,"hash"));
            else memset(hash2.bytes,0,sizeof(hash2));
            //printf("%s vs %s %ld\n",bits256_str(str,hash2),bits256_str(str2,checkhash2),sizeof(*msg)-4);
            datalen = 80;
            if ( (txids= jarray(&numtxids,blockjson,"tx")) != 0 )
            {
                msg->txn_count = numtxids;
                if ( numtxids < 0xfd )
                    blockspace[datalen++] = numtxids;
                else
                {
                    blockspace[datalen++] = 0xfd;
                    blockspace[datalen++] = numtxids & 0xff;
                    blockspace[datalen++] = numtxids >> 8;
                }
                starti = datalen;
                for (i=0; i<numtxids; i++)
                {
                    sprintf(params,"[\"%s\"]",bits256_str(str,jbits256(jitem(txids,i),0)));
                    if ( (curlstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getrawtransaction",params)) != 0 )
                    {
                        //printf("%s txid.%d\n",curlstr,i);
                        if ( (hexlen= is_hexstr(curlstr,0)) > 1 )
                        {
                            hexlen >>= 1;
                            decode_hex(&blockspace[datalen],hexlen,curlstr);
                            datalen += hexlen;
                        }
                        free(curlstr);
                    }
                }
                num++;
                coin->blocks.pending++;
                if ( rawmem->ptr == 0 )
                    iguana_meminit(rawmem,"basilisk",0,IGUANA_MAXPACKETSIZE*3,0);
                else iguana_memreset(rawmem);
                memset(&txdata,0,sizeof(txdata));
                memset(&H,0,sizeof(H));
                if ( (n= iguana_gentxarray(coin,rawmem,&txdata,&len,blockspace,datalen)) == datalen || n == datalen-1 )
                {
                    len = n;
                    iguana_gotblockM(coin,0,&txdata,rawmem->ptr,&H,blockspace,datalen,0);
                    flag = 1;
                    //if ( (rand() % 1000) == 0 )
                        printf("%s h.%-7d len.%-6d | HWM.%d\n",coin->symbol,h,datalen,coin->blocks.hwmchain.height);
                }
                else
                {
                    printf(" parse error block.%d txn_count.%d, n.%d len.%d vs datalen.%d\n",loadheight,txdata.block.RO.txn_count,n,len,datalen);
                }
            }
            free_json(blockjson);
        }
        loadheight++;
        if ( flag == 0 )
            break;
    }
    if ( coin->blocks.pending > 0 )
        coin->blocks.pending--;
    return(num);
}
#endif

int32_t basilisk_bitcoinavail(struct iguana_info *coin)
{
    if ( coin->VALIDATENODE > 0 || coin->FULLNODE > 0 )
        return(1);
    //else if ( coin->chain->serverport[0] != 0 )
    //    return(1);
    else return(0);
}

void *basilisk_bitcoinbalances(struct basilisk_item *Lptr,struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,uint32_t basilisktag,int32_t timeoutmillis,cJSON *vals)
{
    int64_t balance,total = 0; int32_t i,j,n,hist; char *str; cJSON *spends,*unspents,*retjson,*item,*addresses,*array = cJSON_CreateArray();
    spends = unspents = 0;
    if ( (hist= juint(vals,"history")) != 0 )
    {
        if ( (hist & 1) != 0 )
            unspents = cJSON_CreateArray();
        if ( (hist & 2) != 0 )
            spends = cJSON_CreateArray();
    }
    //printf("hist.%d (%s) %p %p\n",hist,jprint(vals,0),unspents,spends);
    if ( (addresses= jarray(&n,vals,"addresses")) != 0 )
    {
        for (i=0; i<n; i++)
        {
            if ( (str= jstri(addresses,i)) != 0 )
            {
                for (j=0; j<n; j++)
                    if ( jstri(addresses,j) != 0 && strcmp(jstri(addresses,j),str) == 0 )
                        break;
                if ( j == n )
                    continue;
                balance = iguana_addressreceived(myinfo,coin,vals,remoteaddr,0,0,unspents,spends,str,juint(vals,"minconf"),0);//juint(vals,"firstheight"));
                item = cJSON_CreateObject();
                jaddnum(item,str,dstr(balance));
                jaddstr(item,"address",str);
                jaddi(array,item);
                total += balance;
            }
            //printf("%.8f ",dstr(balance));
        }
    }
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jaddstr(retjson,"ipaddr",myinfo->ipaddr);
    jaddnum(retjson,"total",dstr(total));
    jaddnum(retjson,"balance",dstr(total));
    jadd(retjson,"addresses",array);
    if ( unspents != 0 )
        jadd(retjson,"unspents",unspents);
    if ( spends != 0 )
        jadd(retjson,"spends",spends);
    jaddnum(retjson,"RTheight",coin->RTheight);
    jaddnum(retjson,"longest",coin->longestchain);
    jaddnum(retjson,"lag",coin->longestchain- coin->RTheight);
//printf("BAL.(%s)\n",jprint(retjson,0));
    Lptr->retstr = jprint(retjson,1);
    return(Lptr);
}

char *basilisk_valuestr(struct iguana_info *coin,char *coinaddr,uint64_t value,int32_t height,bits256 txid,int16_t vout)
{
    cJSON *retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jaddstr(retjson,"address",coinaddr);
    jadd64bits(retjson,"satoshis",value);
    jaddnum(retjson,"amount",dstr(value));
    jaddnum(retjson,"value",dstr(value));
    jaddnum(retjson,"height",height);
    jaddnum(retjson,"numconfirms",coin->blocks.hwmchain.height - height + 1);
    jaddbits256(retjson,"txid",txid);
    jaddnum(retjson,"vout",vout);
    jaddstr(retjson,"coin",coin->symbol);
    return(jprint(retjson,1));
}

double basilisk_bitcoin_valuemetric(struct supernet_info *myinfo,struct basilisk_item *ptr,char *resultstr)
{
    struct basilisk_value *v; cJSON *resultarg; int32_t ind;
    if ( (ind= myinfo->basilisks.numvalues) >= sizeof(myinfo->basilisks.values)/sizeof(*myinfo->basilisks.values) )
        ind = (rand() % (sizeof(myinfo->basilisks.values)/sizeof(*myinfo->basilisks.values)));
    else myinfo->basilisks.numvalues++;
    v = &myinfo->basilisks.values[ind];
    if ( (resultarg= cJSON_Parse(resultstr)) != 0 )
    {
        safecopy(v->coinaddr,jstr(resultarg,"address"),sizeof(v->coinaddr));
        v->value = j64bits(resultarg,"satoshis");
        v->txid = jbits256(resultarg,"txid");
        v->vout = jint(resultarg,"vout");
        v->height = jint(resultarg,"height");
    }
    return(ind + 1);
}

void *basilisk_bitcoinvalue(struct basilisk_item *Lptr,struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,uint32_t basilisktag,int32_t timeoutmillis,cJSON *valsobj)
{
    int32_t i,j,height,vout,numsent; cJSON *retjson; struct basilisk_item *ptr; char coinaddr[64],str[65]; struct basilisk_value *v; uint64_t value = 0; bits256 txid; struct iguana_outpoint outpt;
    if ( valsobj == 0 )
        return(clonestr("{\"error\":\"null valsobj\"}"));
    if ( myinfo->IAMNOTARY != 0 && myinfo->NOTARY.RELAYID >= 0 )
        return(0);
    txid = jbits256(valsobj,"txid");
    vout = jint(valsobj,"vout");
    if ( coin != 0 && basilisk_bitcoinavail(coin) != 0 )
    {
        if ( (coin->VALIDATENODE > 0 || coin->FULLNODE > 0) )//&& coinaddr != 0 && coinaddr[0] != 0 )
        {
            if ( iguana_RTunspentindfind(myinfo,coin,&outpt,coinaddr,0,0,&value,&height,txid,vout,coin->bundlescount,0) == 0 )
            {
                //printf("bitcoinvalue found iguana\n");
                Lptr->retstr = basilisk_valuestr(coin,coinaddr,value,height,txid,vout);
                return(Lptr);
            } else printf("unspentind cant find %s vout.%d\n",bits256_str(str,txid),vout);
        } //else return(bitcoin_value(coin,txid,vout,coinaddr));
        Lptr->retstr = clonestr("{\"error\":\"basilisk value missing address\"}");
        return(Lptr);
    }
    //printf("Scan basilisks values\n");
    if ( (v= myinfo->basilisks.values) != 0 )
    {
        for (i=0; i<myinfo->basilisks.numvalues; i++,v++)
        {
            if ( v->vout == vout && bits256_cmp(txid,v->txid) == 0 && strcmp(v->coinaddr,coinaddr) == 0 )
            {
                printf("bitcoinvalue local ht.%d %s %.8f\n",v->height,v->coinaddr,dstr(v->value));
                ptr = basilisk_issueremote(myinfo,0,&numsent,"VAL",coin->symbol,1,valsobj,juint(valsobj,"fanout"),juint(valsobj,"numrequired"),basilisktag,timeoutmillis,0,basilisk_valuestr(coin,v->coinaddr,v->value,v->height,txid,vout),0,0,BASILISK_DEFAULTDIFF); // this completes immediate
                //queue_enqueue("submitQ",&myinfo->basilisks.submitQ,&ptr->DL,0);
                if ( ptr->numresults > 0 )
                {
                    retjson = cJSON_CreateArray();
                    for (j=0; j<ptr->numresults; j++)
                        jaddi(retjson,ptr->results[j]), ptr->results[j] = 0;
                    ptr->retstr = jprint(retjson,1);
                    //printf("numresults.%d (%p)\n",ptr->numresults,ptr);
                }
                return(ptr);
            }
        }
    }
    printf("bitcoinvalue issue remote tag.%u\n",basilisktag);
    ptr = basilisk_issueremote(myinfo,0,&numsent,"VAL",coin->symbol,1,valsobj,juint(valsobj,"fanout"),juint(valsobj,"numrequired"),basilisktag,timeoutmillis,0,0,0,0,BASILISK_DEFAULTDIFF);
    if ( ptr->numresults > 0 )
    {
        retjson = cJSON_CreateArray();
        for (j=0; j<ptr->numresults; j++)
            jaddi(retjson,ptr->results[j]), ptr->results[j] = 0;
        ptr->retstr = jprint(retjson,1);
        //printf("numresults.%d (%p)\n",ptr->numresults,ptr);
    }
    //queue_enqueue("submitQ",&myinfo->basilisks.submitQ,&ptr->DL,0);
    return(ptr);
}

void *basilisk_getinfo(struct basilisk_item *Lptr,struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,uint32_t basilisktag,int32_t timeoutmillis,cJSON *valsobj)
{
    struct basilisk_item *ptr; cJSON *infojson,*retjson; int32_t j,numsent,fanout,numrequired;
    if ( valsobj == 0 )
        return(clonestr("{\"error\":\"null valsobj\"}"));
    if ( (myinfo->IAMNOTARY != 0 || myinfo->NOTARY.RELAYID >= 0) && strcmp(coin->symbol,"RELAY") != 0 )
        return(0);
    if ( coin->VALIDATENODE > 0 || coin->FULLNODE > 0 || coin->notarychain >= 0 )
    {
        infojson = iguana_getinfo(myinfo,coin);
        Lptr->retstr = jprint(infojson,1);
        return(Lptr);
    }
    if ( (fanout= juint(valsobj,"fanout")) < 8 )
        fanout = 8;
    if ( (numrequired= juint(valsobj,"numrequired")) < fanout )
    {
        jaddnum(valsobj,"numrequired",fanout);
        numrequired = 1;
    }
    ptr = basilisk_issueremote(myinfo,0,&numsent,"INF",coin->symbol,1,valsobj,fanout,numrequired,basilisktag,timeoutmillis,0,0,0,0,BASILISK_DEFAULTDIFF);
    if ( ptr->numresults > 0 )
    {
        retjson = cJSON_CreateArray();
        for (j=0; j<ptr->numresults; j++)
            jaddi(retjson,ptr->results[j]), ptr->results[j] = 0;
        ptr->retstr = jprint(retjson,1);
        //printf("numresults.%d (%p)\n",ptr->numresults,ptr);
    }
    return(ptr);
}

int64_t iguana_getestimatedfee(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char *retstr; cJSON *retjson; double x; int64_t txfeeperbyte = 200;
    if ( (retstr= _dex_getinfo(myinfo,coin->symbol)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (x= jdouble(retjson,"estimatefee")) > SMALLVAL )
                txfeeperbyte = 1 + (x * SATOSHIDEN) / 1024;
            printf("SET txfeeperbyte %lld (%s)\n",(long long)txfeeperbyte,retstr);
            free(retjson);
        }
        free(retstr);
    }
    return(txfeeperbyte);
}

int32_t basilisk_voutvin_validate(struct iguana_info *coin,char *rawtx,uint64_t inputsum,uint64_t amount,uint64_t txfee)
{
    //static int counter;
    //if ( counter++ < 10 )
    //    printf("validate.(%s) vout's vin\n",rawtx);
    if ( rawtx != 0 )
    {
        return(0); // convert rawtx, add up outputs, verify totals
    }
    return(-1);
}

int32_t basilisk_vins_validate(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *retjson,uint64_t amount,uint64_t txfee)
{
    cJSON *vins,*item,*argjson,*valuearray; uint64_t value,inputsum=0; int32_t j,i=-1,vout,retval=-1,numvins=0; bits256 txid; char *valstr;
    if ( retjson != 0 )
    {
        if ( (vins= jarray(&numvins,retjson,"vins")) != 0 )
        {
            for (i=0; i<numvins; i++)
            {
                item = jitem(vins,i);
                txid = jbits256(item,"txid");
                vout = jint(item,"vout");
                argjson = cJSON_CreateObject();
                jaddbits256(argjson,"txid",txid);
                jaddnum(argjson,"vout",vout);
                jaddstr(argjson,"coin",coin->symbol);
                retval = -1;
                if ( (valstr= basilisk_value(myinfo,coin,0,0,myinfo->myaddr.persistent,argjson,0)) != 0 )
                {
                    //printf("valstr.(%d) %s\n",i,valstr);
                    if ( (valuearray= cJSON_Parse(valstr)) != 0 )
                    {
                        if ( is_cJSON_Array(valuearray) != 0 )
                        {
                            for (j=0; j<cJSON_GetArraySize(valuearray); j++)
                            {
                                item = jitem(valuearray,j);
                                if ( jobj(item,"error") == 0 && (value= j64bits(item,"satoshis")) != 0 )
                                {
                                    inputsum += value;
                                    retval = 0;
                                    break;
                                }
                            }
                        }
                        else
                        {
                            if ( jobj(valuearray,"error") == 0 && (value= j64bits(valuearray,"satoshis")) != 0 )
                            {
                                inputsum += value;
                                retval = 0;
                            }
                        }
                        free_json(valuearray);
                    }
                    free(valstr);
                }
                if ( retval < 0 )
                    break;
            }
        }
        if ( i != numvins || basilisk_voutvin_validate(coin,jstr(retjson,"rawtx"),inputsum,amount,txfee) < 0 )
            retval = -1;
        else retval = 0;
    }
    return(retval);
}

int64_t iguana_esttxfee(struct supernet_info *myinfo,struct iguana_info *coin,char *rawtx,char *signedtx,int32_t numvins)
{
    int64_t txfee = 0;
    if ( coin->estimatedfee == 0 )
        coin->estimatedfee = iguana_getestimatedfee(myinfo,coin);
    if ( signedtx != 0 )
    {
        txfee = coin->estimatedfee * (strlen(signedtx)/2 + numvins);
        free(signedtx);
    }
    else if ( rawtx != 0 )
    {
        txfee = coin->estimatedfee * (strlen(rawtx)/2 + numvins * 110);
        free(rawtx);
    }
    return(txfee);
}

char *iguana_utxoduplicates(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t *pubkey33,uint64_t satoshis,int32_t duplicates,int32_t *completedp,bits256 *signedtxidp,int32_t sendflag,cJSON *addresses)
{
    uint8_t script[35]; int64_t txfee; int32_t i,spendlen; cJSON *txobj=0,*vins=0; char *rawtx=0,*signedtx=0,changeaddr[64];
    *completedp = 0;
    if ( signedtxidp != 0 )
        memset(signedtxidp,0,sizeof(*signedtxidp));
    bitcoin_address(changeaddr,coin->chain->pubtype,myinfo->persistent_pubkey33,33);
    txfee = (coin->txfee + duplicates*coin->txfee/10);
    if ( strcmp(coin->symbol,"GAME") == 0 )
        printf("GAME txfee %.8f\n",dstr(txfee));
    if ( (txobj= bitcoin_txcreate(coin->symbol,coin->chain->isPoS,0,1,0)) != 0 )
    {
        if ( duplicates <= 0 )
            duplicates = 1;
        spendlen = bitcoin_pubkeyspend(script,0,pubkey33);
        for (i=0; i<duplicates; i++)
            bitcoin_txoutput(txobj,script,spendlen,satoshis);
        rawtx = iguana_calcrawtx(myinfo,coin,&vins,txobj,satoshis * duplicates,changeaddr,txfee,addresses,0,0,0,0,"127.0.0.1",0,1);
        if ( strcmp(coin->chain->symbol,"BTC") == 0 && cJSON_GetArraySize(vins) > duplicates/2 )
        {
            free(rawtx);
            rawtx = 0;
            fprintf(stderr,"No point to recycle utxo when trying to create utxo duplicates, numvins.%d vs duplicates.%d\n",cJSON_GetArraySize(vins),duplicates);
            free_json(vins);
            return(rawtx);
        }
        //printf("%s splitfunds tx.(%s) vins.(%s)\n",coin->symbol,rawtx,jprint(vins,0));
        if ( signedtxidp != 0 )
        {
            if ( (signedtx= iguana_signrawtx(myinfo,coin,0,signedtxidp,completedp,vins,rawtx,0,0)) != 0 )
            {
                if ( *completedp != 0 )
                {
                    printf("splitfunds %s signedtx.(%s)\n",coin->symbol,signedtx);
                    if ( sendflag != 0 )
                        iguana_sendrawtransaction(myinfo,coin,signedtx);
                    free(rawtx);
                    rawtx = signedtx, signedtx = 0;
                }
            } else printf("error signing raw %s utxoduplicates tx\n",coin->symbol);
        }
    }
    if ( vins != 0 )
        free_json(vins);
    if ( txobj != 0 )
        free_json(txobj);
    return(rawtx);
}

int64_t iguana_verifytimelock(struct supernet_info *myinfo,struct iguana_info *coin,uint32_t timelocked,char *destaddr,bits256 txid,int32_t vout)
{
    uint8_t script[35],script2[35],p2shscript[128],rmd160[20],addrtype; char *retstr,*spendscriptstr; int32_t p2shlen,spendlen; cJSON *sobj,*txout=0; int64_t value = 0;
    bitcoin_addr2rmd160(&addrtype,rmd160,destaddr);
    if ( addrtype != coin->chain->pubtype )
        return(-1);
    p2shlen = bitcoin_timelockspend(p2shscript,0,rmd160,timelocked);
    calc_rmd160(0,rmd160,p2shscript,p2shlen);
    spendlen = bitcoin_p2shspend(script,0,rmd160);
    if ( coin->FULLNODE != 0 )
        txout = dpow_gettxout(myinfo,coin,txid,vout);
    else if ( (retstr= _dex_gettxout(myinfo,coin->symbol,txid,vout)) != 0 )
    {
        txout = cJSON_Parse(retstr);
        free(retstr);
    }
    if ( txout != 0 )
    {
        if ( (sobj= jobj(txout,"scriptPubKey")) != 0 && (spendscriptstr= jstr(sobj,"hex")) == 0 )
        {
            if ( strlen(spendscriptstr) == spendlen*2 )
            {
                decode_hex(script2,spendlen,spendscriptstr);
                if ( memcmp(script,script2,spendlen) != 0 )
                    return(-2);
                value = SATOSHIDEN * jdouble(txout,"value");
            } else return(-4);
        }
        free_json(txout);
        return(value);
    } return(-2);
}

char *iguana_utxorawtx(struct supernet_info *myinfo,struct iguana_info *coin,int32_t timelock,char *destaddr,char *changeaddr,int64_t *satoshis,int32_t numoutputs,uint64_t txfee,int32_t *completedp,int32_t sendflag,cJSON *utxos,cJSON *privkeys)
{
    uint8_t script[35],p2shscript[128],rmd160[20],addrtype; bits256 txid; int32_t i,p2shlen,iter,spendlen; cJSON *retjson,*txcopy,*txobj=0,*vins=0; char *rawtx=0,*signedtx=0; uint32_t timelocked = 0;
    *completedp = 0;
    if ( iguana_addressvalidate(coin,&addrtype,destaddr) < 0 || iguana_addressvalidate(coin,&addrtype,changeaddr) < 0 )
        return(clonestr("{\"error\":\"invalid coin address\"}"));
    bitcoin_addr2rmd160(&addrtype,rmd160,changeaddr);
    if ( addrtype != coin->chain->pubtype )
        return(clonestr("{\"error\":\"invalid changeaddr type\"}"));
    bitcoin_addr2rmd160(&addrtype,rmd160,destaddr);
    if ( addrtype != coin->chain->pubtype )
        return(clonestr("{\"error\":\"invalid dest address type\"}"));
    if ( txfee == 0 && strcmp(coin->symbol,"BTC") != 0 && (txfee= coin->txfee) == 0 )
        txfee = coin->chain->txfee;
    retjson = cJSON_CreateObject();
    if ( (txobj= bitcoin_txcreate(coin->symbol,coin->chain->isPoS,0,1,0)) != 0 )
    {
        if ( timelock == 0 )
            spendlen = bitcoin_standardspend(script,0,rmd160);
        else
        {
            timelocked = (uint32_t)(time(NULL)+timelock);
            if ( (timelocked % 3600) != 0 )
                timelocked += (3600 - (timelocked % 3600));
            p2shlen = bitcoin_timelockspend(p2shscript,0,rmd160,timelocked);
            calc_rmd160(0,rmd160,p2shscript,p2shlen);
            spendlen = bitcoin_p2shspend(script,0,rmd160);
            printf("timelock.%d spend timelocked %u\n",timelock,timelocked);
        }
        for (i=0; i<numoutputs; i++)
            if ( satoshis[i] > 0 )
                bitcoin_txoutput(txobj,script,spendlen,satoshis[i]);
        for (iter=0; iter<2; iter++)
        {
            txcopy = jduplicate(txobj);
            if ( (rawtx= iguana_calcutxorawtx(myinfo,coin,&vins,txobj,satoshis,numoutputs,changeaddr,txfee,utxos,"",0,0)) != 0 )
            {
                if ( iter == 1 || txfee != 0 )
                    jaddstr(retjson,"rawtx",rawtx);
                if ( (signedtx= iguana_signrawtx(myinfo,coin,0,&txid,completedp,vins,rawtx,privkeys,0)) != 0 )
                {
                    if ( (iter == 1 || txfee != 0) && *completedp != 0 )
                    {
                        jaddbits256(retjson,"txid",txid);
                        jaddstr(retjson,"signedtx",signedtx);
                        if ( sendflag != 0 )
                        {
                            txid = iguana_sendrawtransaction(myinfo,coin,signedtx);
                            jaddbits256(retjson,"sent",txid);
                        } else printf("dont send signedtx.(%s)\n",signedtx);
                    }
                } else printf("error signing raw utxorawtx tx\n");
            } else printf("null rawtx from calcutxorawtx\n");
            if ( txfee != 0 )
            {
                free_json(txcopy);
                break;
            }
            else // must be BTC and txfee == 0
            {
                txfee = iguana_esttxfee(myinfo,coin,rawtx,signedtx,cJSON_GetArraySize(vins));
                free_json(vins);
                rawtx = signedtx = 0;
                vins = 0;
                *completedp = 0;
                txobj = txcopy;
            }
        }
    }
    if ( timelock != 0 )
    {
        jaddnum(retjson,"timelock",timelock);
        jaddnum(retjson,"timelocked",timelocked);
    }
    jaddstr(retjson,"result","success");
    if ( *completedp != 0 )
        jadd(retjson,"completed",jtrue());
    else jadd(retjson,"completed",jfalse());
    if ( vins != 0 )
        free_json(vins);
    if ( txobj != 0 )
        free_json(txobj);
    if ( rawtx != 0 )
    {
        jaddstr(retjson,"rawtx",rawtx);
        free(rawtx);
    }
    if ( signedtx != 0 )
    {
        jaddstr(retjson,"signedtx",signedtx);
        free(signedtx);
    }
    return(jprint(retjson,1));
}

char *basilisk_bitcoinrawtx(struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,uint32_t basilisktag,int32_t timeoutmillis,cJSON *valsobj,struct vin_info *V)
{
    uint8_t buf[4096]; int32_t oplen,offset,minconf,spendlen; cJSON *vins,*addresses,*txobj = 0; uint32_t locktime; char *opreturn,*spendscriptstr,*changeaddr,*rawtx = 0; int64_t amount,txfee,burnamount;
    if ( valsobj == 0 )
        return(clonestr("{\"error\":\"null valsobj\"}"));
    //if ( myinfo->IAMNOTARY != 0 || myinfo->NOTARY.RELAYID >= 0 )
    //    return(clonestr("{\"error\":\"special relays only do OUT and MSG\"}"));
    vins = 0;
    changeaddr = jstr(valsobj,"changeaddr");
    if ( (amount= j64bits(valsobj,"satoshis")) == 0 )
        amount = jdouble(valsobj,"value") * SATOSHIDEN;
    if ( (txfee= j64bits(valsobj,"txfee")) == 0 )
    {
        //if ( strcmp(coin->symbol,"BTC") != 0 )
        {
            txfee = coin->chain->txfee;
            if ( txfee < 50000 )
                txfee = 50000;
        }
    }
    spendscriptstr = jstr(valsobj,"spendscript");
    minconf = juint(valsobj,"minconf");
    locktime = jint(valsobj,"locktime");
    if ( (addresses= jobj(valsobj,"addresses")) == 0 )
    {
        addresses = iguana_getaddressesbyaccount(myinfo,coin,"*");
        jadd(valsobj,"addresses",addresses);
    }
    printf("use addresses.(%s) (%s)\n",jprint(addresses,0),spendscriptstr!=0?spendscriptstr:"no script");
    //printf("(%s) vals.(%s) change.(%s) spend.%s\n",coin->symbol,jprint(valsobj,0),changeaddr,spendscriptstr);
    if ( changeaddr == 0 || changeaddr[0] == 0 || spendscriptstr == 0 || spendscriptstr[0] == 0 )
        return(clonestr("{\"error\":\"invalid changeaddr or spendscript or addresses\"}"));
    if ( coin != 0 )
    {
        if ( (txobj= bitcoin_txcreate(coin->symbol,coin->chain->isPoS,locktime,locktime==0?coin->chain->normal_txversion:coin->chain->locktime_txversion,juint(valsobj,"timestamp"))) != 0 )
        {
            spendlen = (int32_t)strlen(spendscriptstr) >> 1;
            decode_hex(buf,spendlen,spendscriptstr);
            bitcoin_txoutput(txobj,buf,spendlen,amount);
            burnamount = offset = oplen = 0;
            if ( (opreturn= jstr(valsobj,"opreturn")) != 0 && (oplen= is_hexstr(opreturn,0)) > 0 )
            {
                oplen >>= 1;
                if ( (strcmp("BTC",coin->symbol) == 0 && oplen < 76) || coin->chain->do_opreturn == 0 )
                {
                    decode_hex(&buf[sizeof(buf) - oplen],oplen,opreturn);
                    spendlen = datachain_datascript(coin,buf,&buf[sizeof(buf) - oplen],oplen);
                    if ( (burnamount= SATOSHIDEN * jdouble(valsobj,"burn")) < 10000 )
                    {
                        //burnamount = 10000;
                        printf("low burnamount %.8f\n",dstr(burnamount));
                    }
                    bitcoin_txoutput(txobj,buf,spendlen,burnamount);
                    oplen = 0;
                } else oplen = datachain_opreturnscript(coin,buf,opreturn,oplen);
            }
            rawtx = iguana_calcrawtx(myinfo,coin,&vins,txobj,amount,changeaddr,txfee,addresses,minconf,oplen!=0?buf:0,oplen+offset,burnamount,remoteaddr,V,1);
            if ( txfee == 0 )
            {
                txfee = iguana_esttxfee(myinfo,coin,rawtx,0,vins != 0 ? cJSON_GetArraySize(vins): 0);
                if ( vins != 0 )
                    free_json(vins), vins = 0;
                rawtx = iguana_calcrawtx(myinfo,coin,&vins,txobj,amount,changeaddr,txfee,addresses,minconf,oplen!=0?buf:0,oplen+offset,burnamount,remoteaddr,V,1);
                printf("new txfee %.8f (%s)\n",dstr(txfee),rawtx);
            }
            //printf("generated.(%s) vins.(%s)\n",rawtx!=0?rawtx:"",vins!=0?jprint(vins,0):"");
        }
        if ( rawtx != 0 )
        {
            if ( vins != 0 )
            {
                free_json(txobj);
                valsobj = cJSON_CreateObject();
                jadd(valsobj,"vins",vins);
                jaddstr(valsobj,"rawtx",rawtx);
                jaddstr(valsobj,"coin",coin->symbol);
                free(rawtx);
                return(jprint(valsobj,1));
            } else free(rawtx);
        }
        if ( txobj != 0 )
            free_json(txobj);
        if ( vins != 0 )
            free_json(vins);
        return(clonestr("{\"error\":\"couldnt create rawtx\"}"));
    }
    return(clonestr("{\"error\":\"dont have coin to create rawtx\"}"));
}

/*
 both fees are standard payments: OP_DUP OP_HASH160 FEE_RMD160 OP_EQUALVERIFY OP_CHECKSIG
 
 Alice altpayment: OP_2 <alice_pubM> <bob_pubN> OP_2 OP_CHECKMULTISIG
 
 Bob deposit:
 OP_IF
 <now + INSTANTDEX_LOCKTIME*2> OP_CLTV OP_DROP <alice_pubA0> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(bob_privN)> OP_EQUALVERIFY <bob_pubB0> OP_CHECKSIG
 OP_ENDIF
 
 Bob paytx:
 OP_IF
 <now + INSTANTDEX_LOCKTIME> OP_CLTV OP_DROP <bob_pubB1> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY <alice_pubA0> OP_CHECKSIG
 OP_ENDIF
 
 Naming convention are pubAi are alice's pubkeys (seems only pubA0 and not pubA1)
 pubBi are Bob's pubkeys
 
 privN is Bob's privkey from the cut and choose deck as selected by Alice
 privM is Alice's counterpart
 pubN and pubM are the corresponding pubkeys for these chosen privkeys
 
 Alice timeout event is triggered if INSTANTDEX_LOCKTIME elapses from the start of a FSM instance. Bob timeout event is triggered after INSTANTDEX_LOCKTIME*2
 */


#ifdef oldway

int32_t instantdex_feetxverify(struct supernet_info *myinfo,struct iguana_info *coin,struct basilisk_swap *swap,cJSON *argjson)
{
    cJSON *txobj; bits256 txid; uint32_t n; int32_t i,retval = -1,extralen=65536; int64_t insurance; uint64_t r;
    struct iguana_msgtx msgtx; uint8_t script[512],serialized[8192],*extraspace=0; char coinaddr[64];
    if ( swap->otherfee != 0 )
    {
        extraspace = calloc(1,extralen);
        if ( (txobj= bitcoin_hex2json(coin,&txid,&msgtx,swap->otherfee->txbytes,extraspace,extralen,serialized)) != 0 )
        {
            r = swap->other.orderid;
            if ( strcmp(coin->symbol,"BTC") == 0 )
                insurance = swap->insurance + swap->bobcoin->chain->txfee;
            else insurance = swap->altinsurance + swap->alicecoin->chain->txfee;
            n = instantdex_outputinsurance(coinaddr,coin->chain->pubtype,script,insurance,r,r * (strcmp("BTC",coin->symbol) == 0));
            if ( n == msgtx.vouts[0].pk_scriptlen )
            {
                if ( memcmp(script,msgtx.vouts[0].pk_script,n) == 0 )
                {
                    printf("feetx script verified.(%s)\n",swap->otherfee->txbytes);
                    retval = 0;
                }
                else
                {
                    for (i=0; i<n; i++)
                        printf("%02x",script[i]);
                    printf(" fee script\n");
                    for (i=0; i<n; i++)
                        printf("%02x",msgtx.vouts[0].pk_script[i]);
                    printf(" feetx mismatched\n");
                    printf("FEETX.(%s)\n",jprint(txobj,0));
                }
            } else printf("pk_scriptlen %d mismatch %d\n",msgtx.vouts[0].pk_scriptlen,n);
            free_json(txobj);
        } else printf("error converting (%s) txobj\n",swap->otherfee->txbytes);
    } else printf("no feetx to verify\n");
    if ( extraspace != 0 )
        free(extraspace);
    return(retval);
}

struct bitcoin_statetx *instantdex_bobtx(struct supernet_info *myinfo,struct basilisk_swap *swap,struct iguana_info *coin,int64_t amount,int32_t depositflag)
{
    int32_t n,secretstart; struct bitcoin_statetx *ptr = 0; uint8_t script[1024]; uint32_t locktime; int64_t satoshis; char scriptstr[512];
    if ( coin == 0 )
        return(0);
    satoshis = amount + depositflag*swap->insurance*100 + swap->bobcoin->chain->txfee;
    n = instantdex_bobscript(script,0,&locktime,&secretstart,swap,depositflag);
    if ( n < 0 )
    {
        printf("instantdex_bobtx couldnt generate bobscript deposit.%d\n",depositflag);
        return(0);
    }
    printf("locktime.%u amount %.8f satoshis %.8f\n",locktime,dstr(amount),dstr(satoshis));
    init_hexbytes_noT(scriptstr,script,n);
    if ( (ptr= instantdex_signtx(depositflag != 0 ? "deposit" : "payment",myinfo,coin,locktime,scriptstr,satoshis,coin->txfee,swap->mine.minconfirms,swap->mine.offer.myside)) != 0 )
    {
        bitcoin_address(ptr->destaddr,coin->chain->p2shtype,script,n);
        printf("BOBTX.%d (%s) -> %s\n",depositflag,ptr->txbytes,ptr->destaddr);
    } else printf("sign error for bottx\n");
    return(ptr);
}

int32_t instantdex_paymentverify(struct supernet_info *myinfo,struct iguana_info *coin,struct basilisk_swap *swap,cJSON *argjson,int32_t depositflag)
{
    cJSON *txobj; bits256 txid; uint32_t n,locktime; int32_t i,secretstart,retval = -1,extralen=65536; uint64_t x;
    struct iguana_msgtx msgtx; uint8_t script[512],serialized[8192],*extraspace=0; int64_t amount;
    if ( coin != 0 && swap->deposit != 0 )
    {
        amount = swap->BTCsatoshis + depositflag*swap->insurance*100 + swap->bobcoin->chain->txfee;
        if ( (n= instantdex_bobscript(script,0,&locktime,&secretstart,swap,depositflag)) <= 0 )
            return(retval);
        extraspace = calloc(1,extralen);
        if ( (txobj= bitcoin_hex2json(coin,&txid,&msgtx,swap->deposit->txbytes,extraspace,extralen,serialized)) != 0 )
        {
            memcpy(&script[secretstart],&msgtx.vouts[0].pk_script[secretstart],20);
            printf("locktime.%u amount %.8f satoshis %.8f\n",locktime,dstr(amount),dstr(amount));
            if ( msgtx.lock_time == locktime && msgtx.vouts[0].value == amount && n == msgtx.vouts[0].pk_scriptlen )
            {
                if ( memcmp(script,msgtx.vouts[0].pk_script,n) == 0 )
                {
                    iguana_rwnum(0,&script[secretstart],sizeof(x),&x);
                    printf("deposit script verified\n");
                    if ( x == swap->otherdeck[swap->choosei][0] )
                        retval = 0;
                    else printf("deposit script verified but secret mismatch x.%llx vs otherdeck %llx\n",(long long)x,(long long)swap->otherdeck[swap->choosei][0]);
                }
                else
                {
                    for (i=0; i<n; i++)
                        printf("%02x ",script[i]);
                    printf("script\n");
                    for (i=0; i<n; i++)
                        printf("%02x ",msgtx.vouts[0].pk_script[i]);
                    printf("deposit\n");
                }
            }
            free_json(txobj);
        }
    }
    if ( extraspace != 0 )
        free(extraspace);
    return(retval);
}

int32_t instantdex_altpaymentverify(struct supernet_info *myinfo,struct iguana_info *coin,struct basilisk_swap *swap,cJSON *argjson)
{
    cJSON *txobj; bits256 txid; uint32_t n; int32_t i,retval = -1,extralen = 65536;
    struct iguana_msgtx msgtx; uint8_t script[512],serialized[8192],*extraspace=0; char *altmsigaddr=0,msigaddr[64];
    if ( swap->altpayment != 0 && (altmsigaddr= jstr(argjson,"altmsigaddr")) != 0 )
    {
        extraspace = calloc(1,extralen);
        if ( (txobj= bitcoin_hex2json(coin,&txid,&msgtx,swap->altpayment->txbytes,extraspace,extralen,serialized)) != 0 )
        {
            n = instantdex_alicescript(script,0,msigaddr,coin->chain->p2shtype,swap->pubAm,swap->pubBn);
            if ( strcmp(msigaddr,altmsigaddr) == 0 && n == msgtx.vouts[0].pk_scriptlen )
            {
                if ( memcmp(script,msgtx.vouts[0].pk_script,n) == 0 )
                {
                    printf("altpayment script verified\n");
                    retval = 0;
                }
                else
                {
                    for (i=0; i<n; i++)
                        printf("%02x ",script[i]);
                    printf(" altscript\n");
                    for (i=0; i<n; i++)
                        printf("%02x ",msgtx.vouts[0].pk_script[i]);
                    printf(" altpayment\n");
                }
            } else printf("msig mismatch.(%s %s) or n.%d != %d\n",msigaddr,altmsigaddr,n,msgtx.vouts[0].pk_scriptlen);
            free_json(txobj);
        } else printf("bitcoin_hex2json error\n");
    } else printf("no altpayment.%p or no altmsig.%s\n",swap->altpayment,altmsigaddr!=0?altmsigaddr:"");
    if ( extraspace != 0 )
        free(extraspace);
    return(retval);
}

struct bitcoin_statetx *instantdex_alicetx(struct supernet_info *myinfo,struct iguana_info *alicecoin,char *msigaddr,bits256 pubAm,bits256 pubBn,int64_t amount,struct basilisk_swap *swap)
{
    int32_t n; uint8_t script[1024]; char scriptstr[2048]; struct bitcoin_statetx *ptr = 0;
    if ( alicecoin != 0 )
    {
        if ( bits256_nonz(pubAm) == 0 || bits256_nonz(pubBn) == 0 )
        {
            printf("instantdex_bobtx null pubAm.%llx or pubBn.%llx\n",(long long)pubAm.txid,(long long)pubBn.txid);
            return(0);
        }
        n = instantdex_alicescript(script,0,msigaddr,alicecoin->chain->p2shtype,pubAm,pubBn);
        init_hexbytes_noT(scriptstr,script,n);
        if ( (ptr= instantdex_signtx("altpayment",myinfo,alicecoin,0,scriptstr,amount,alicecoin->txfee,swap->mine.minconfirms,swap->mine.offer.myside)) != 0 )
        {
            strcpy(ptr->destaddr,msigaddr);
            printf("ALICETX (%s) -> %s\n",ptr->txbytes,ptr->destaddr);
        }
    }
    return(ptr);
}

cJSON *BTC_makeclaimfunc(struct supernet_info *myinfo,struct exchange_info *exchange,struct basilisk_swap *swap,cJSON *argjson,cJSON *newjson,uint8_t **serdatap,int32_t *serdatalenp)
{
    int32_t got_payment=1,bob_reclaimed=0;
    *serdatap = 0, *serdatalenp = 0;
    if ( instantdex_isbob(swap) == 0 )
    {
        // [BLOCKING: payfound] now Alice's turn to make sure payment is confrmed and send in claim or see bob's reclaim and reclaim
        if ( got_payment != 0 )
        {
            //swap->privAm = swap->privkeys[swap->otherchoosei];
            // sign if/else payment
        }
        else if ( bob_reclaimed != 0 )
        {
            
        }
    }
    else
    {
        // [BLOCKING: privM] Bob waits for privM either from Alice or alt blockchain
        if ( bits256_nonz(swap->privAm) != 0 )
        {
            // a multisig tx for alicecoin
        }
    }
    return(newjson);
}
#endif

int32_t basilisk_unspentfind(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *txidp,int32_t *voutp,uint8_t *spendscript,struct iguana_outpoint outpt,int64_t value)
{
    struct iguana_waccount *wacct,*tmp; struct iguana_waddress *waddr,*tmp2;
    memset(txidp,0,sizeof(*txidp));
    *voutp = -1;
    portable_mutex_lock(&myinfo->bu_mutex);
    HASH_ITER(hh,myinfo->wallet,wacct,tmp)
    {
        HASH_ITER(hh,wacct->waddr,waddr,tmp2)
        {
            printf("need to port basilisk_unspentfind\n");
        }
    }
    portable_mutex_unlock(&myinfo->bu_mutex);
    return(-1);
}

cJSON *basilisk_jsonmerge(char *symbol,cJSON *array)
{
    int32_t i,j,n,m; cJSON *jobj,*iobj,*dest = cJSON_CreateArray();
    if ( dest != 0 && (n= cJSON_GetArraySize(array)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            m = cJSON_GetArraySize(dest);
            iobj = jitem(array,i);
            for (j=0; j<m; j++)
            {
                jobj = jitem(dest,j);
                if ( bits256_cmp(jbits256(jobj,"txid"),jbits256(iobj,"txid")) == 0 && jint(jobj,"vout") == jint(iobj,"vout") )
                {
                    //printf("(%s) == (%s)\n",jprint(iobj,0),jprint(jobj,0));
                    break;
                }
            }
            if ( j == m )
            {
                jaddi(dest,jduplicate(iobj));
                //printf("add.(%s) ",jprint(iobj,0));
            } //else printf("j.%d != m.%d\n",j,m);
        }
    }
    return(dest);
}

void basilisk_unspent_update(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *json)
{
    cJSON *unspents,*spends,*item; int32_t n; char *address; //struct iguana_waccount *wacct; struct iguana_waddress *waddr=0;
    if ( (spends= jarray(&n,json,"spends")) != 0 && n > 0 )
    {
        item = jitem(spends,0);
        if ( (address= jstr(item,"address")) != 0 )//&& (waddr= iguana_waddresssearch(myinfo,&wacct,address)) != 0 )
        {
            if ( myinfo->Cspends == 0 )
                myinfo->Cspends = cJSON_CreateObject();
            if ( jobj(myinfo->Cspends,coin->symbol) != 0 )
                jdelete(myinfo->Cspends,coin->symbol);
            jadd(myinfo->Cspends,coin->symbol,basilisk_jsonmerge(coin->symbol,spends));
            //printf("S.(%s)\n",jprint(waddr->Cspends,0));
        }
        //printf("merge spends.(%s)\n",jprint(spends,0));
    }
    if ( (unspents= jarray(&n,json,"unspents")) != 0 && n > 0 )
    {
        item = jitem(unspents,0);
        if ( (address= jstr(item,"address")) != 0 )//&& (waddr= iguana_waddresssearch(myinfo,&wacct,address)) != 0 )
        {
            if ( myinfo->Cunspents == 0 )
                myinfo->Cunspents = cJSON_CreateObject();
            if ( jobj(myinfo->Cunspents,coin->symbol) != 0 )
                jdelete(myinfo->Cunspents,coin->symbol);
            jadd(myinfo->Cunspents,coin->symbol,basilisk_jsonmerge(coin->symbol,unspents));
            //printf("U.(%s)\n",jprint(myinfo->Cunspents,0));
        }
        //printf("merge unspents.(%s)\n",jprint(unspents,0));
    }
}

void basilisk_unspents_process(struct supernet_info *myinfo,struct iguana_info *coin,char *retstr)
{
    cJSON *retarray; int32_t i,n;
    portable_mutex_lock(&myinfo->bu_mutex);
    if ( myinfo->Cspends != 0 )
        free_json(myinfo->Cspends), myinfo->Cspends = 0;
    if ( myinfo->Cunspents != 0 )
        free_json(myinfo->Cunspents), myinfo->Cunspents = 0;
    if ( (retarray= cJSON_Parse(retstr)) != 0 )
    {
        if ( is_cJSON_Array(retarray) != 0 )
        {
            n = cJSON_GetArraySize(retarray);
            for (i=0; i<n; i++)
                basilisk_unspent_update(myinfo,coin,jitem(retarray,i));
        } else basilisk_unspent_update(myinfo,coin,retarray);
        free_json(retarray);
    }
    portable_mutex_unlock(&myinfo->bu_mutex);
}

cJSON *basilisk_balance_valsobj(struct supernet_info *myinfo,struct iguana_info *coin)
{
    int32_t oldest,i,RTheight; cJSON *vals;
    for (i=oldest=0; i<BASILISK_MAXRELAYS; i++)
        if ( (RTheight= coin->relay_RTheights[i]) != 0 && (oldest == 0 || RTheight < oldest) )
            oldest = RTheight;
    vals = cJSON_CreateObject();
    jaddnum(vals,"firstheight",oldest);
    jaddnum(vals,"history",3);
    jaddstr(vals,"coin",coin->symbol);
    return(vals);
}

void basilisk_unspents_update(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char *retstr; cJSON *vals;
    if ( (vals= basilisk_balance_valsobj(myinfo,coin)) != 0 && (retstr= basilisk_balances(myinfo,coin,0,0,GENESIS_PUBKEY,vals,"")) != 0 )
    {
        basilisk_unspents_process(myinfo,coin,retstr);
        free(retstr);
    }
    free_json(vals);
}
