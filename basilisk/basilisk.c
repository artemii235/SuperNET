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

#include "../iguana/iguana777.h"
#include "../iguana/exchanges777.h"

typedef char *basilisk_servicefunc(struct supernet_info *myinfo,char *CMD,void *addr,char *remoteaddr,uint32_t basilisktag,cJSON *valsobj,uint8_t *data,int32_t datalen,bits256 hash,int32_t from_basilisk);

int32_t basilisk_notarycmd(char *cmd)
{
    //&& strcmp(cmd,"DEX") != 0 && strcmp(cmd,"ACC") != 0 && strcmp(cmd,"RID") != 0 &&
    if ( strcmp(cmd,"PIN") != 0 && strcmp(cmd,"OUT") != 0 && strcmp(cmd,"MSG") != 0 && strcmp(cmd,"VOT") != 0 )
        return(0);
    else return(1);
}

/*int32_t basilisk_specialrelay_CMD(char *CMD)
{
    if ( strcmp(CMD,"OUT") == 0 || strcmp(CMD,"MSG") == 0 || strcmp(CMD,"BLK") == 0 || strcmp(CMD,"MEM") == 0 || strcmp(CMD,"GTX") == 0 || strcmp(CMD,"RID") == 0 )
        return(1);
    else return(0);
}*/

cJSON *basilisk_utxosweep(struct supernet_info *myinfo,char *symbol,int64_t *satoshis,uint64_t limit,int32_t maxvins,char *coinaddr)
{
    int32_t i,n,numvins = 0; char *retstr; uint64_t value,biggest = 0; struct iguana_info *coin=0; cJSON *item,*biggestitem=0,*array,*utxos = 0;
    coin = iguana_coinfind(symbol);
    if ( (retstr= dex_listunspent(myinfo,coin,0,0,symbol,coinaddr)) != 0 )
    {
        //printf("(%s)\n",retstr);
        if ( (array= cJSON_Parse(retstr)) != 0 )
        {
            n = cJSON_GetArraySize(array);
            for (i=0; i<n; i++)
            {
                item = jitem(array,i);
                if ( (value= SATOSHIDEN*jdouble(item,"amount")) != 0 || (value= SATOSHIDEN*jdouble(item,"value")) != 0 )
                {
                    //fprintf(stderr,"%.8f ",dstr(value));
                    if ( value <= limit )
                    {
                        //fprintf(stderr,"< ");
                        if ( utxos == 0 )
                            utxos = cJSON_CreateArray();
                        if ( numvins < maxvins )
                        {
                            jaddi(utxos,jduplicate(item));
                            numvins++;
                        }
                    }
                    else if ( value > biggest )
                    {
                        //fprintf(stderr,"biggest! ");
                        if ( biggestitem != 0 )
                            free_json(biggestitem);
                        biggestitem = jduplicate(item);
                        *satoshis = biggest = value;
                    } //else fprintf(stderr,"> ");
                }
            }
            free_json(array);
            if ( utxos == 0 && biggestitem != 0 )
            {
                fprintf(stderr,"add biggest.(%s)\n",jprint(biggestitem,0));
                jaddi(utxos,biggestitem);
            }
        }
        free(retstr);
    }
    return(utxos);
}

uint32_t basilisk_calcnonce(struct supernet_info *myinfo,uint8_t *data,int32_t datalen,uint32_t nBits)
{
    int32_t i,numiters = 0; bits256 hash,hash2,threshold; uint32_t basilisktag;
    vcalc_sha256(0,hash.bytes,data,datalen);
    if ( nBits >= GECKO_EASIESTDIFF )
        threshold = bits256_from_compact(GECKO_EASIESTDIFF);
    else threshold = bits256_from_compact(nBits);
    for (i=0; i<numiters; i++)
    {
        //OS_randombytes((void *)hash.uints,sizeof(basilisktag));
        hash.uints[0] = rand();
        vcalc_sha256(0,hash2.bytes,hash.bytes,sizeof(hash));
        if ( bits256_cmp(threshold,hash2) > 0 )
            break;
    }
    iguana_rwnum(0,(void *)hash.uints,sizeof(basilisktag),&basilisktag);
    iguana_rwnum(1,&data[-(int32_t)sizeof(basilisktag)],sizeof(basilisktag),&basilisktag);
    //char str[65],str2[65]; printf("found hash after numiters.%d %s vs %s basilisktag.%u\n",numiters,bits256_str(str,threshold),bits256_str(str2,hash2),basilisktag);
    return(basilisktag);
}

char *basilisk_addhexstr(char **ptrp,cJSON *valsobj,char *strbuf,int32_t strsize,uint8_t *data,int32_t datalen)
{
    *ptrp = 0;
    if ( data != 0 && datalen > 0 )
    {
        if ( valsobj != 0 && jobj(valsobj,"data") != 0 )
        {
            printf("basilisk_addhexstr warning: already have data object\n");
            jdelete(valsobj,"data");
        }
        if ( (datalen<<1)+1 > strsize )
        {
            strbuf = calloc(1,(datalen << 1) + 1);
            *ptrp = (void *)strbuf;
        }
        init_hexbytes_noT(strbuf,data,datalen);
        if ( valsobj != 0 )
            jaddstr(valsobj,"data",strbuf);
    } else return(0);
    return(strbuf);
}

uint8_t *get_dataptr(int32_t hdroffset,uint8_t **ptrp,int32_t *datalenp,uint8_t *space,int32_t spacesize,char *hexstr)
{
    *ptrp = 0; uint8_t *data = 0;
    if ( hexstr != 0 && (*datalenp= is_hexstr(hexstr,0)) > 0 )
    {
        *datalenp >>= 1;
        if ( (*datalenp+hdroffset) <= spacesize )
        {
            memset(space,0,hdroffset);
            data = &space[hdroffset];
        } else *ptrp = data = calloc(1,*datalenp + hdroffset);
        decode_hex(&data[hdroffset],*datalenp,hexstr);
    }
    if ( data != 0 )
        return(&data[hdroffset]);
    else return(data);
}

uint8_t *basilisk_jsondata(int32_t extraoffset,uint8_t **ptrp,uint8_t *space,int32_t spacesize,int32_t *datalenp,char *symbol,cJSON *sendjson,uint32_t basilisktag)
{
    char *sendstr,*hexstr=0; uint8_t *data,hexspace[4096],*allocptr=0,*hexdata=0; int32_t datalen,hexlen=0;
    if ( jobj(sendjson,"symbol") == 0 )
        jaddstr(sendjson,"symbol",symbol);
    if ( (hexstr= jstr(sendjson,"data")) != 0 )
    {
        hexdata = get_dataptr(0,&allocptr,&hexlen,hexspace,sizeof(hexspace),hexstr);
        //printf("jsondata.%s from sendjson\n",hexstr);
        jdelete(sendjson,"data");
    }
    *ptrp = 0;
    sendstr = jprint(sendjson,0);
    datalen = (int32_t)strlen(sendstr) + 1;
    if ( (datalen + extraoffset + BASILISK_HDROFFSET + hexlen) <= spacesize )
        data = space;
    else
    {
        data = calloc(1,datalen + extraoffset + BASILISK_HDROFFSET + hexlen);
        *ptrp = data;
    }
    data += extraoffset + BASILISK_HDROFFSET;
    memcpy(data,sendstr,datalen);
    //printf("jsondata.(%s) + hexlen.%d\n",sendstr,hexlen);
    free(sendstr);
    if ( hexlen > 0 && hexdata != 0 )
    {
        //int32_t i; for (i=0; i<hexlen; i++)
        //    printf("%02x",hexdata[i]);
        //printf(" <- hexdata\n");
        memcpy(&data[datalen],hexdata,hexlen);
        datalen += hexlen;
    }
    *datalenp = datalen;
    if ( allocptr != 0 )
        free(allocptr);
    return(data);
}

struct basilisk_item *basilisk_itemcreate(struct supernet_info *myinfo,char *CMD,char *symbol,uint32_t basilisktag,int32_t numrequired,cJSON *vals,int32_t timeoutmillis,void *metricfunc)
{
    struct basilisk_item *ptr;
    ptr = calloc(1,sizeof(*ptr));
    ptr->basilisktag = basilisktag;
    if ( (ptr->numrequired= numrequired) == 0 )
        ptr->numrequired = 1;
    strcpy(ptr->CMD,CMD);
    safecopy(ptr->symbol,symbol,sizeof(ptr->symbol));
    ptr->duration = timeoutmillis;
    ptr->expiration = OS_milliseconds() + timeoutmillis;
    //printf("itemcreate.%p %s %f timeout.%d\n",ptr,CMD,OS_milliseconds(),timeoutmillis);
    return(ptr);
}

int32_t basilisk_sendcmd(struct supernet_info *myinfo,char *destipaddr,char *type,uint32_t *basilisktagp,int32_t encryptflag,int32_t delaymillis,uint8_t *data,int32_t datalen,int32_t fanout,uint32_t nBits) // data must be offset by sizeof(iguana_msghdr)+sizeof(basilisktag)
{
    int32_t i,l,s,valid,val,n=0,retval = -1; char cmd[12]; struct iguana_info *coin,*tmp; struct iguana_peer *addr; bits256 hash; uint32_t *alreadysent,r;
    if ( fanout <= 0 )
        fanout = sqrt(myinfo->NOTARY.NUMRELAYS) + 1;
    else if ( fanout > BASILISK_MAXFANOUT )
        fanout = BASILISK_MAXFANOUT;
    if ( type == 0 )
        type = "INF";
    if ( strlen(type) > 3 )
    {
        printf("basilisk_sendcmd illegal type(%s)\n",type);
        return(-1);
    }
    if ( destipaddr != 0 )
    {
        if ( destipaddr[0] == 0 )
        {
            destipaddr = 0; // broadcast
        }
        else if ( strcmp(destipaddr,"127.0.0.1") == 0 || strcmp(destipaddr,myinfo->ipaddr) == 0 )
        {
            printf("return after locally basilisk_msgprocess\n");
            hash = GENESIS_PUBKEY;
            basilisk_msgprocess(myinfo,0,0,type,*basilisktagp,data,datalen);
            return(0);
        }
    }
    iguana_rwnum(1,&data[-(int32_t)sizeof(*basilisktagp)],sizeof(*basilisktagp),basilisktagp);
    if ( *basilisktagp == 0 )
    {
        if ( nBits != 0 )
            *basilisktagp = basilisk_calcnonce(myinfo,data,datalen,nBits);
        else *basilisktagp = rand();
        iguana_rwnum(1,&data[-(int32_t)sizeof(*basilisktagp)],sizeof(*basilisktagp),basilisktagp);
    }
    data -= sizeof(*basilisktagp), datalen += sizeof(*basilisktagp);
    memset(cmd,0,sizeof(cmd));
    sprintf(cmd,"SuperNET%s",type);
    if ( destipaddr != 0 )
    {
        cmd[6] = 'E', cmd[7] = 'T';
        HASH_ITER(hh,myinfo->allcoins,coin,tmp)
        {
            if (  coin->peers == 0 )
                continue;
            if ( coin->FULLNODE == 0 && coin->VALIDATENODE == 0 )
                cmd[0] = 's';
            else cmd[0] = 'S';
            for (i=0; i<IGUANA_MAXPEERS; i++)
            {
                addr = &coin->peers->active[i];
                if ( addr->usock >= 0 && strcmp(addr->ipaddr,destipaddr) == 0 )
                {
                    return(iguana_queue_send(addr,delaymillis,&data[-(int32_t)sizeof(struct iguana_msghdr)],cmd,datalen));
                }
            }
        }
        return(-1);
    }
    if ( basilisk_notarycmd(type) != 0 && myinfo->NOTARY.NUMRELAYS == 0 )
    {
        //printf("no notary nodes to send (%s) to\n",type);
        return(-1);
    }
    //portable_mutex_lock(&myinfo->allcoins_mutex);
    //dex_reqsend(myinfo,&data[-(int32_t)sizeof(struct iguana_msghdr)],datalen);
    alreadysent = calloc(IGUANA_MAXPEERS * IGUANA_MAXCOINS,sizeof(*alreadysent));
    HASH_ITER(hh,myinfo->allcoins,coin,tmp)
    {
        if (  coin->peers == 0 )
            continue;
        if ( basilisk_notarycmd(type) != 0 && strcmp(coin->symbol,"RELAY") != 0 )
            continue;
        if ( coin->FULLNODE == 0 && coin->VALIDATENODE == 0 )
            cmd[0] = 's';
        else cmd[0] = 'S';
        r = rand() % IGUANA_MAXPEERS;
        for (l=0; l<IGUANA_MAXPEERS; l++)
        {
            i = (l + r) % IGUANA_MAXPEERS;
            addr = &coin->peers->active[i];
            if ( addr->supernet != 0 || addr->basilisk != 0 )
                valid = 1;
            else valid = 0;
            if ( addr->usock >= 0 )
            {
                s = 0;
                valid = (addr->supernet != 0);
                if ( basilisk_notarycmd(type) != 0 || (strcmp(type,"INF") == 0 && strcmp(coin->symbol,"RELAY") == 0) )
                {
                    valid = 0;
                    /*OS_randombytes((void *)&r2,sizeof(r2));
                    if ( (r2 % myinfo->NOTARY.NUMRELAYS) >= sqrt(myinfo->NOTARY.NUMRELAYS) )
                    {
                        printf("fanout.%d s.%d n.%d skip %s\n",fanout,s,n,addr->ipaddr);
                        continue;
                    }*/
                    for (s=0; s<myinfo->NOTARY.NUMRELAYS; s++)
                        if ( addr->ipbits != myinfo->myaddr.myipbits && myinfo->NOTARY.RELAYS[s].ipbits == addr->ipbits )
                            break;
                    if ( s == myinfo->NOTARY.NUMRELAYS )
                    {
                        //printf("skip non-relay.(%s)\n",addr->ipaddr);
                        continue;
                    }
                    valid = 1;
                    //printf("send to other relay.(%s)\n",addr->ipaddr);
                }
                for (s=0; s<n; s++)
                    if ( alreadysent[s] == addr->ipbits )
                    {
                        //printf("already sent to %s\n",addr->ipaddr);
                        continue;
                    }
                if ( s == n && valid == 1 && (destipaddr == 0 || strcmp(addr->ipaddr,destipaddr) == 0) )
                {
                    val = 0;
                    //fprintf(stderr,">>> (%s).%u ",addr->ipaddr,coin->chain->portp2p);
                    //printf("n.%d/fanout.%d i.%d l.%d [%s].tag%u send %s [%x] datalen.%d addr->supernet.%u basilisk.%u to (%s).%d destip.%s\n",n,fanout,i,l,cmd,*(uint32_t *)data,type,*(int32_t *)&data[datalen-4],datalen,addr->supernet,addr->basilisk,addr->ipaddr,addr->A.port,destipaddr!=0?destipaddr:"broadcast");
                    if ( encryptflag != 0 && bits256_nonz(addr->pubkey) != 0 )
                    {
                        void *ptr; uint8_t *cipher,space[8192]; int32_t cipherlen; bits256 privkey;
                        cmd[6] = 'e', cmd[7] = 't';
                        memset(privkey.bytes,0,sizeof(privkey));
                        if ( (cipher= SuperNET_ciphercalc(&ptr,&cipherlen,&privkey,&addr->pubkey,data,datalen,space,sizeof(space))) != 0 )
                        {
                            if ( (val= iguana_queue_send(addr,delaymillis,&cipher[-(int32_t)sizeof(struct iguana_msghdr)],cmd,cipherlen)) >= cipherlen )
                                alreadysent[n++] = (uint32_t)addr->ipbits;
                            if ( ptr != 0 )
                                free(ptr);
                        }
                    }
                    else
                    {
                        cmd[6] = 'E', cmd[7] = 'T';
                        if ( (val= iguana_queue_send(addr,delaymillis,&data[-(int32_t)sizeof(struct iguana_msghdr)],cmd,datalen)) >= datalen )
                        {
                            alreadysent[n++] = (uint32_t)addr->ipbits;
                            if ( n >= IGUANA_MAXPEERS*IGUANA_MAXCOINS )
                                break;
                        }
                    }
                    if ( destipaddr != 0 || (fanout > 0 && n >= fanout) )
                    {
                        free(alreadysent);
                        return(val);
                    }
                    else if ( val > retval )
                        retval = val;
                }
            }
        }
        if ( n >= IGUANA_MAXPEERS*IGUANA_MAXCOINS )
            break;
    }
    //portable_mutex_unlock(&myinfo->allcoins_mutex);
    free(alreadysent);
    return(n);
}

void basilisk_sendback(struct supernet_info *myinfo,char *origCMD,char *symbol,char *remoteaddr,uint32_t basilisktag,char *retstr)
{
    uint8_t *data,space[4096],*allocptr; struct iguana_info *virt; cJSON *valsobj; int32_t datalen,encryptflag=0,delaymillis=0;
    //printf("%s retstr.(%s) -> remote.(%s) basilisktag.%u\n",origCMD,retstr,remoteaddr,basilisktag);
    if ( retstr != 0 && remoteaddr != 0 && remoteaddr[0] != 0 && strcmp(remoteaddr,"127.0.0.1") != 0 )
    {
        if ( (valsobj= cJSON_Parse(retstr)) != 0 )
        {
            jaddstr(valsobj,"origcmd",origCMD);
            jaddstr(valsobj,"symbol",symbol);
            if ( myinfo->ipaddr[0] != 0 )
                jaddstr(valsobj,"relay",myinfo->ipaddr);
            jaddnum(valsobj,"timestamp",(uint32_t)time(NULL));
            if ( (virt= iguana_coinfind(symbol)) != 0 )
            {
                jaddnum(valsobj,"hwm",virt->blocks.hwmchain.height);
                if ( bits256_nonz(virt->blocks.hwmchain.RO.hash2) != 0 )
                    jaddbits256(valsobj,"chaintip",virt->blocks.hwmchain.RO.hash2);
            }
            data = basilisk_jsondata(sizeof(struct iguana_msghdr),&allocptr,space,sizeof(space),&datalen,symbol,valsobj,basilisktag);
            //printf("sendback.%d -> %s\n",datalen,remoteaddr);
            basilisk_sendcmd(myinfo,remoteaddr,"RET",&basilisktag,encryptflag,delaymillis,data,datalen,0,0);
            if ( allocptr != 0 )
                free(allocptr);
            free_json(valsobj);
        }
    }
}

struct basilisk_item *basilisk_issueremote(struct supernet_info *myinfo,struct iguana_peer *addr,int32_t *numsentp,char *CMD,char *symbol,int32_t blockflag,cJSON *valsobj,int32_t fanout,int32_t numrequired,uint32_t basilisktag,int32_t timeoutmillis,void *deprecated_dontuse,char *retstr,int32_t encryptflag,int32_t delaymillis,uint32_t nBits)
{
    struct basilisk_item *pending; uint8_t *allocptr,*data,space[4096]; int32_t datalen;
    pending = basilisk_itemcreate(myinfo,CMD,symbol,basilisktag,numrequired,valsobj,timeoutmillis,0);
    pending->nBits = nBits;
    *numsentp = 0;
    if ( retstr != 0 )
    {
        pending->retstr = retstr;
        pending->numresults = pending->numrequired;
    }
    else
    {
        valsobj = jduplicate(valsobj);
        data = basilisk_jsondata(sizeof(struct iguana_msghdr),&allocptr,space,sizeof(space),&datalen,symbol,valsobj,basilisktag);
        free_json(valsobj), valsobj = 0;
        *numsentp = pending->numsent = basilisk_sendcmd(myinfo,addr != 0 ? addr->ipaddr : 0,CMD,&pending->basilisktag,encryptflag,delaymillis,data,datalen,fanout,pending->nBits);
        if ( blockflag != 0 )
        {
            portable_mutex_lock(&myinfo->basilisk_mutex);
            HASH_ADD(hh,myinfo->basilisks.issued,basilisktag,sizeof(basilisktag),pending);
            portable_mutex_unlock(&myinfo->basilisk_mutex);
            if ( pending->expiration <= OS_milliseconds() )
                pending->expiration = OS_milliseconds() + pending->duration;
            strcpy(pending->symbol,"RELAY");
            strcpy(pending->CMD,CMD);
            //printf("block for %f\n",pending->expiration - OS_milliseconds());
            while ( OS_milliseconds() < pending->expiration )
            {
                portable_mutex_lock(&myinfo->basilisk_mutex);
                if ( pending->numresults >= pending->numrequired )
                {
                    portable_mutex_unlock(&myinfo->basilisk_mutex);
                    //printf("%p <<<<<<<<<<<<< numresults.%d vs numrequired.%d\n",pending,pending->numresults,pending->numrequired);
                    break;
                }
                portable_mutex_unlock(&myinfo->basilisk_mutex);
                usleep(10000);
            }
        }
        if ( allocptr != 0 )
            free(allocptr);
    }
    return(pending);
}

struct basilisk_item *basilisk_requestservice(struct supernet_info *myinfo,struct iguana_peer *addr,char *CMD,int32_t blockflag,cJSON *valsobj,bits256 hash,uint8_t *data,int32_t datalen,uint32_t nBits)
{
    int32_t minfanout,numrequired,timeoutmillis,numsent,delaymillis,encryptflag,fanout; struct basilisk_item *ptr; char buf[4096],*symbol,*str = 0; struct iguana_info *virt;
    //printf("request.(%s)\n",jprint(valsobj,0));
    basilisk_addhexstr(&str,valsobj,buf,sizeof(buf),data,datalen);
    if ( str != 0 )
        free(str);
    if ( bits256_nonz(hash) == 0 || (bits256_cmp(hash,GENESIS_PUBKEY) != 0 && bits256_nonz(hash) != 0) )
    {
        if ( jobj(valsobj,"hash") != 0 )
            jdelete(valsobj,"hash");
        jaddbits256(valsobj,"hash",hash);
    }
    if ( (timeoutmillis= jint(valsobj,"timeout")) == 0 )
        timeoutmillis = BASILISK_TIMEOUT;
    minfanout = sqrt(myinfo->NOTARY.NUMRELAYS)+1;
    if ( minfanout < 8 )
        minfanout = 8;
    if ( jobj(valsobj,"fanout") == 0 )
        fanout = minfanout;
    else fanout = jint(valsobj,"fanout");
    if ( fanout < minfanout )
        fanout = minfanout;
    if ( (numrequired= jint(valsobj,"numrequired")) <= 0 )
        numrequired = MIN(fanout/2,sqrt(myinfo->NOTARY.NUMRELAYS)+1);
    if ( (symbol= jstr(valsobj,"coin")) != 0 || (symbol= jstr(valsobj,"symbol")) != 0 )
    {
        if ( (virt= iguana_coinfind(symbol)) != 0 )
        {
            jaddstr(valsobj,"symbol",symbol);
            jaddnum(valsobj,"longest",virt->longestchain);
            jaddnum(valsobj,"hwm",virt->blocks.hwmchain.height);
        }
    }
    if ( symbol == 0 )
        symbol = "RELAY";
    encryptflag = jint(valsobj,"encrypt");
    delaymillis = jint(valsobj,"delay");
    ptr = basilisk_issueremote(myinfo,addr,&numsent,CMD,symbol,blockflag,valsobj,fanout,numrequired,0,timeoutmillis,0,0,encryptflag,delaymillis,nBits);
    return(ptr);
}

char *basilisk_standardservice(char *CMD,struct supernet_info *myinfo,void *_addr,bits256 hash,cJSON *valsobj,char *hexstr,int32_t blockflag) // client side
{
    uint32_t nBits = 0; uint8_t space[4096],*allocptr=0,*data = 0; struct basilisk_item *ptr; int32_t i,datalen = 0; cJSON *retjson; char *retstr=0;
    if ( myinfo->IAMNOTARY != 0 && myinfo->NOTARY.RELAYID >= 0 && (strcmp(CMD,"INF") != 0 && basilisk_notarycmd(CMD) == 0) )
        return(clonestr("{\"error\":\"unsupported special relay command\"}"));
    data = get_dataptr(BASILISK_HDROFFSET,&allocptr,&datalen,space,sizeof(space),hexstr);
//printf("request.(%s)\n",jprint(valsobj,0));
    ptr = basilisk_requestservice(myinfo,_addr,CMD,blockflag,valsobj,hash,data,datalen,nBits);
    if ( allocptr != 0 )
        free(allocptr);
    if ( ptr != 0 )
    {
        if ( (retstr= ptr->retstr) != 0 )
            ptr->retstr = 0;
        else
        {
            if ( ptr->numresults > 0 )
            {
                retjson = cJSON_CreateArray();
                for (i=0; i<ptr->numresults; i++)
                    jaddi(retjson,ptr->results[i]), ptr->results[i] = 0;
                //printf("numresults.%d (%p)\n",ptr->numresults,ptr);
            }
            else
            {
                retjson = cJSON_CreateObject();
                if ( ptr->numsent > 0 )
                {
                    //queue_enqueue("submitQ",&myinfo->basilisks.submitQ,&ptr->DL,0);
                    jaddstr(retjson,"result","error");
                    jaddnum(retjson,"packetsize",ptr->numsent);
                } else jaddstr(retjson,"error","didnt find any nodes to send to");
            }
            retstr = jprint(retjson,1);
        }
        ptr->finished = OS_milliseconds() + 10000;
    }
    if ( (0) && strcmp("MSG",CMD) == 0 )
        printf("%s.(%s) -> (%s)\n",CMD,jprint(valsobj,0),retstr!=0?retstr:"");
    return(retstr);
}

int32_t basilisk_relayid(struct supernet_info *myinfo,uint32_t ipbits)
{
    int32_t j;
    for (j=0; j<myinfo->NOTARY.NUMRELAYS; j++)
        if ( myinfo->NOTARY.RELAYS[j].ipbits == ipbits )
            return(j);
    return(-1);
}

#include "basilisk_bitcoin.c"
#include "basilisk_nxt.c"
#include "basilisk_ether.c"
#include "basilisk_waves.c"
#include "basilisk_lisk.c"
#include "smartaddress.c"

#include "basilisk_MSG.c"
#include "tradebots_marketmaker.c"
#include "tradebots_liquidity.c"
#include "basilisk_tradebot.c"
#include "basilisk_swap.c"
#include "basilisk_DEX.c"
#include "basilisk_ping.c"
#include "basilisk_vote.c"
#include "basilisk_CMD.c"
#include "jumblr.c"

void basilisk_functions(struct iguana_info *coin,int32_t protocol)
{
    coin->protocol = protocol;
    switch ( protocol )
    {
        /*case IGUANA_PROTOCOL_BITCOIN:
            coin->basilisk_balances = basilisk_bitcoinbalances;
            coin->basilisk_rawtx = basilisk_bitcoinrawtx;
            //coin->basilisk_rawtxmetric = basilisk_bitcoin_rawtxmetric;
            coin->basilisk_value = basilisk_bitcoinvalue;
            coin->basilisk_valuemetric = basilisk_bitcoin_valuemetric;
            break;
        case IGUANA_PROTOCOL_IOTA:
            coin->basilisk_balances = basilisk_iotabalances;
            coin->basilisk_rawtx = basilisk_iotarawtx;
            break;
        case IGUANA_PROTOCOL_NXT:
            coin->basilisk_balances = basilisk_nxtbalances;
            coin->basilisk_rawtx = basilisk_nxtrawtx;
            break;
        case IGUANA_PROTOCOL_ETHER:
            coin->basilisk_balances = basilisk_etherbalances;
            coin->basilisk_rawtx = basilisk_etherrawtx;
            break;
        case IGUANA_PROTOCOL_WAVES:
            coin->basilisk_balances = basilisk_wavesbalances;
            coin->basilisk_rawtx = basilisk_wavesrawtx;
            break;
        case IGUANA_PROTOCOL_LISK:
            coin->basilisk_balances = basilisk_liskbalances;
            coin->basilisk_rawtx = basilisk_liskrawtx;
            break;*/
    }
}

int32_t basilisk_hashes_send(struct supernet_info *myinfo,struct iguana_info *virt,struct iguana_peer *addr,char *CMD,bits256 *hashes,int32_t num)
{
    bits256 hash; uint8_t *serialized; int32_t i,len = 0; char *str=0,*retstr,*hexstr,space[4096]; bits256 txid; cJSON *vals;
    if ( virt != 0 && addr != 0 )
    {
        memset(hash.bytes,0,sizeof(hash));
        serialized = (void *)hashes;
        for (i=0; i<num; i++)
        {
            txid = hashes[i];
            len += iguana_rwbignum(1,&serialized[len],sizeof(txid),txid.bytes);
        }
        if ( (hexstr= basilisk_addhexstr(&str,0,space,sizeof(space),serialized,len)) != 0 )
        {
            vals = cJSON_CreateObject();
            jaddstr(vals,"symbol",virt->symbol);
            if ( (retstr= basilisk_standardservice(CMD,myinfo,addr,hash,vals,hexstr,0)) != 0 )
                free(retstr);
            free_json(vals);
            if ( str != 0 )
                free(str);
        }
        return(0);
    } else return(-1);
}

void basilisk_geckoresult(struct supernet_info *myinfo,char *remoteaddr,char *retstr,uint8_t *data,int32_t datalen)
{
    struct iguana_info *virt; char *symbol,*str,*type; cJSON *retjson; bits256 hash2;
    if ( retstr != 0 && (retjson= cJSON_Parse(retstr)) != 0 )
    {
        if ( (symbol= jstr(retjson,"symbol")) != 0 && (virt= iguana_coinfind(symbol)) != 0 )
        {
            if ( data != 0 )
            {
                str = 0;
                if ( (type= jstr(retjson,"type")) != 0 )
                {
                    hash2 = jbits256(retjson,"hash");
                    if ( strcmp(type,"HDR") == 0 && virt->virtualchain != 0 )
                        str = gecko_headersarrived(myinfo,virt,remoteaddr,data,datalen,hash2);
                    else if ( strcmp(type,"MEM") == 0 && virt->virtualchain != 0 )
                        str = gecko_mempoolarrived(myinfo,virt,remoteaddr,data,datalen,hash2);
                    else if ( strcmp(type,"BLK") == 0 && virt->virtualchain != 0 )
                        str = gecko_blockarrived(myinfo,virt,remoteaddr,data,datalen,hash2,0);
                    else if ( strcmp(type,"GTX") == 0 && virt->virtualchain != 0 )
                        str = gecko_txarrived(myinfo,virt,remoteaddr,data,datalen,hash2);
                }
                if ( str != 0 )
                    free(str);
            }
        }
        free_json(retjson);
    }
}

void basilisk_result(struct supernet_info *myinfo,char *remoteaddr,uint32_t basilisktag,cJSON *vals,uint8_t *data,int32_t datalen)
{
    char *retstr,CMD[16]; struct basilisk_item *pending; cJSON *item;
    if ( vals != 0 )
    {
        retstr = jprint(vals,0);
        safecopy(CMD,jstr(vals,"origcmd"),sizeof(CMD));
        //if ( 0 && strcmp("RID",CMD) != 0 )
        //printf("(%s) -> Q.%u results vals.(%s)\n",CMD,basilisktag,retstr);//(int32_t)strlen(retstr));
        if ( strcmp(CMD,"GET") == 0 )
            basilisk_geckoresult(myinfo,remoteaddr,retstr,data,datalen);
        else
        {
            portable_mutex_lock(&myinfo->basilisk_mutex);
            HASH_FIND(hh,myinfo->basilisks.issued,&basilisktag,sizeof(basilisktag),pending);
            portable_mutex_unlock(&myinfo->basilisk_mutex);
            if ( pending != 0 && retstr != 0 )
            {
                if ( (item= cJSON_Parse(retstr)) != 0 )
                {
                    if ( jobj(item,"myip") == 0 )
                        jaddstr(item,"myip",remoteaddr);
                    if ( pending->numresults < sizeof(pending->results)/sizeof(*pending->results) )
                    {
                        //printf("%p.(%s).%d\n",pending,jprint(item,0),pending->numresults);
                        pending->results[pending->numresults++] = item;
                    }
                } else printf("couldnt parse.(%s)\n",retstr);
            } //else printf("couldnt find issued.%u\n",basilisktag);
        }
        free(retstr);
    }
}

void basilisk_wait(struct supernet_info *myinfo,struct iguana_info *coin)
{
    if ( coin != 0 )
    {
        while ( coin->basilisk_busy != 0 )
            usleep(1000);
    }
    else
    {
        while ( myinfo->basilisk_busy != 0 )
            usleep(1000);
    }
}

void basilisk_msgprocess(struct supernet_info *myinfo,void *_addr,uint32_t senderipbits,char *type,uint32_t basilisktag,uint8_t *data,int32_t datalen)
{
    cJSON *valsobj; char *symbol,*retstr=0,remoteaddr[64],CMD[4],cmd[4]; int32_t height,origlen,from_basilisk,i,timeoutmillis,flag,numrequired,jsonlen; uint8_t *origdata; struct iguana_info *coin=0; bits256 hash; struct iguana_peer *addr = _addr;
    static basilisk_servicefunc *basilisk_services[][2] =
    {
        { (void *)"OUT", &basilisk_respond_OUT },       // send MSG to hash/id/num
        { (void *)"MSG", &basilisk_respond_MSG },       // get MSG (hash, id, num)
        { (void *)"ADD", &basilisk_respond_addrelay },  // relays register with each other bus
        { (void *)"VOT", &basilisk_respond_VOT },       // VOTE handler for something
        //{ (void *)"PIN", &basilisk_respond_PIN },
        
        // encrypted data for jumblr
        { (void *)"HOP", &basilisk_respond_forward },    // message forwarding
        { (void *)"BOX", &basilisk_respond_mailbox },    // create/send/check mailbox pubkey
        
        // small virtual private network
        { (void *)"VPN", &basilisk_respond_VPNcreate },  // create virtual network's hub via privkey
        { (void *)"ARC", &basilisk_respond_VPNjoin },    // join
        { (void *)"GAB", &basilisk_respond_VPNmessage }, // private message
        { (void *)"SAY", &basilisk_respond_VPNbroadcast }, // broadcast
        { (void *)"EAR", &basilisk_respond_VPNreceive }, // network receive (via poll)
        { (void *)"END", &basilisk_respond_VPNlogout },  // logout
         
        //{ (void *)"DEX", &basilisk_respond_DEX },
        //{ (void *)"RID", &basilisk_respond_RID },
        //{ (void *)"ACC", &basilisk_respond_ACC },
        { (void *)"BYE", &basilisk_respond_goodbye },    // disconnect
        
        // gecko chains
        { (void *)"GET", &basilisk_respond_geckoget },      // requests headers, block or tx
        { (void *)"HDR", &basilisk_respond_geckoheaders },  // reports headers
        { (void *)"BLK", &basilisk_respond_geckoblock },    // reports virtchain block
        { (void *)"MEM", &basilisk_respond_mempool },       // reports virtchain mempool
        { (void *)"GTX", &basilisk_respond_geckotx },       // reports virtchain tx
        
        // coin services
        { (void *)"VAL", &basilisk_respond_value },
        { (void *)"BAL", &basilisk_respond_balances },
        { (void *)"INF", &basilisk_respond_getinfo },
    };
    strncpy(CMD,type,3), CMD[3] = cmd[3] = 0;
    if ( isupper((int32_t)CMD[0]) != 0 && isupper((int32_t)CMD[1]) != 0 && isupper((int32_t)CMD[2]) != 0 )
        from_basilisk = 1;
    else from_basilisk = 0;
    origdata = data;
    origlen = datalen;
    for (i=0; i<3; i++)
    {
        CMD[i] = toupper((int32_t)CMD[i]);
        cmd[i] = tolower((int32_t)CMD[i]);
    }
    if ( myinfo->IAMNOTARY != 0 )//RELAYID >= 0 )
    {
        if ( basilisk_notarycmd(CMD) == 0 && strcmp(CMD,"INF") != 0 )
            return;
    } else if ( basilisk_notarycmd(CMD) != 0 )
        return;
    symbol = "RELAY";
    if ( senderipbits == 0 )
        expand_ipbits(remoteaddr,myinfo->myaddr.myipbits);
    else expand_ipbits(remoteaddr,senderipbits);
    if ( (valsobj= cJSON_Parse((char *)data)) != 0 )
    {
        if ( jobj(valsobj,"coin") != 0 )
            coin = iguana_coinfind(jstr(valsobj,"coin"));
        else if ( jobj(valsobj,"symbol") != 0 )
            coin = iguana_coinfind(jstr(valsobj,"symbol"));
        if ( coin != 0 )
        {
            if ( (height= juint(valsobj,"hwm")) > 0 )
            {
                if ( height > addr->height )
                    addr->height = height;
                if ( height > coin->longestchain )
                    coin->longestchain = height;
            }
        }
        if ( strcmp(type,"RET") == 0 )
        {
            basilisk_result(myinfo,remoteaddr,basilisktag,valsobj,data,datalen);
            return;
        }
    }
    else
    {
        printf("unexpected binary packet datalen.%d\n",datalen);
        return;
    }
    for (i=flag=0; i<sizeof(basilisk_services)/sizeof(*basilisk_services); i++) // iguana node
        if ( strcmp((char *)basilisk_services[i][0],type) == 0 )
        {
            flag = 1;
            break;
        }
    if ( flag == 0 )
        return;
    myinfo->basilisk_busy = 1;
    if ( valsobj != 0 )
    {
        jsonlen = (int32_t)strlen((char *)data) + 1;
        if ( datalen > jsonlen )
            data += jsonlen, datalen -= jsonlen;
        else data = 0, datalen = 0;
        if ( coin == 0 )
            coin = iguana_coinfind(symbol);
        if ( coin != 0 )
        {
            symbol = coin->symbol;
            coin->basilisk_busy = 1;
        }
        hash = jbits256(valsobj,"hash");
        timeoutmillis = jint(valsobj,"timeout");
        if ( (numrequired= jint(valsobj,"numrequired")) == 0 )
            numrequired = sqrt(myinfo->NOTARY.NUMRELAYS)+1;
        if ( senderipbits != 0 )
            expand_ipbits(remoteaddr,senderipbits);
        else remoteaddr[0] = 0;
        for (i=0; i<sizeof(basilisk_services)/sizeof(*basilisk_services); i++) // iguana node
        {
            if ( strcmp((char *)basilisk_services[i][0],type) == 0 )
            {
                if ( (coin != 0 && coin->FULLNODE > 0) || myinfo->NOTARY.RELAYID >= 0 ) // iguana node
                {
                    //printf("\n call %s from_basilisk.%d (%s)\n",addr->ipaddr,from_basilisk,type);
                    if ( (retstr= (*basilisk_services[i][1])(myinfo,type,addr,remoteaddr,basilisktag,valsobj,data,datalen,hash,from_basilisk)) != 0 )
                    {
                        //printf("%s from_basilisk.%d ret.(%s)\n",addr->ipaddr,from_basilisk,retstr);
                        //if ( from_basilisk != 0 || strcmp(CMD,"GET") == 0 )
                            basilisk_sendback(myinfo,CMD,symbol,remoteaddr,basilisktag,retstr);
                        if ( retstr != 0 )
                            free(retstr);
                        break;
                    } else printf("services null return\n");
                } else printf("non-relay got %s unhandled.(%s)\n",coin!=0?coin->symbol:"",type);
            }
        }
        free_json(valsobj);
    }
    if ( coin != 0 )
        coin->basilisk_busy = 0;
    myinfo->basilisk_busy = 0;
}

int32_t basilisk_p2pQ_process(struct supernet_info *myinfo,int32_t maxiters)
{
    struct basilisk_p2pitem *ptr; char senderip[64]; uint32_t n=0,basilisktag,len;
    while ( n < maxiters && (ptr= queue_dequeue(&myinfo->p2pQ)) != 0 )
    {
        len = 0;
        expand_ipbits(senderip,ptr->ipbits);
        //printf("p2p.%d from.(%s) %c%c%c datalen.%d\n",n,senderip,ptr->type[0],ptr->type[1],ptr->type[2],ptr->datalen);
        if ( ptr->type[0] == 'P' && ptr->type[1] == 'I' && ptr->type[2] == 'N' )
        {
            if ( myinfo->NOTARY.RELAYID >= 0 )
            {
                //printf("process ping\n");
                basilisk_ping_process(myinfo,ptr->addr,ptr->ipbits,ptr->data,ptr->datalen);
                //printf("done process ping\n");
            }
        }
        else
        {
            len += iguana_rwnum(0,ptr->data,sizeof(basilisktag),&basilisktag);
            if ( (0) && myinfo->IAMLP == 0 )
                printf("RELAYID.%d ->received.%d basilisk_p2p.(%s) from %s tag.%u\n",myinfo->NOTARY.RELAYID,ptr->datalen,ptr->type,senderip,basilisktag);
            basilisk_msgprocess(myinfo,ptr->addr,ptr->ipbits,ptr->type,basilisktag,&ptr->data[len],ptr->datalen - len);
            if ( (0) && myinfo->IAMLP == 0 )
                printf("processed.%s from %s\n",ptr->type,senderip);
        }
        free(ptr);
        n++;
    }
    return(n);
}

struct basilisk_p2pitem *basilisk_p2pitem_create(struct iguana_info *coin,struct iguana_peer *addr,char *type,uint32_t ipbits,uint8_t *data,int32_t datalen)
{
    struct basilisk_p2pitem *ptr;
    ptr = calloc(1,sizeof(*ptr) + datalen + 16);
    ptr->coin = coin;
    ptr->addr = addr;
    ptr->ipbits = ipbits;
    ptr->datalen = datalen;
    safecopy(ptr->type,type,sizeof(ptr->type));
    memcpy(ptr->data,data,datalen);
    return(ptr);
}

void basilisk_p2p(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,char *senderip,uint8_t *data,int32_t datalen,char *type,int32_t encrypted)
{
    uint32_t ipbits; int32_t msglen; void *ptr = 0; uint8_t space[4096]; bits256 senderpub;
    ipbits = (uint32_t)calc_ipbits(senderip);
    if ( encrypted != 0 )
    {
        printf("encrypted p2p\n");
        memset(senderpub.bytes,0,sizeof(senderpub));
        if ( (data= SuperNET_deciphercalc(&ptr,&msglen,myinfo->privkey,senderpub,data,datalen,space,sizeof(space))) == 0 )
        {
            printf("basilisk_p2p decrytion error\n");
            return;
        } else datalen = msglen;
        if ( ptr != 0 )
            free(ptr);
    }
    if ( senderip != 0 && senderip[0] != 0 && strcmp(senderip,"127.0.0.1") != 0 )
        ipbits = (uint32_t)calc_ipbits(senderip);
    else ipbits = myinfo->myaddr.myipbits;
    ptr = basilisk_p2pitem_create(coin,addr,type,ipbits,data,datalen);
    queue_enqueue("p2pQ",&myinfo->p2pQ,ptr);
}

int32_t basilisk_issued_purge(struct supernet_info *myinfo,int32_t timepad)
{
    struct basilisk_item *tmp,*pending; cJSON *item; int32_t i,n = 0; double startmilli = OS_milliseconds();
    portable_mutex_lock(&myinfo->basilisk_mutex);
    HASH_ITER(hh,myinfo->basilisks.issued,pending,tmp)
    {
        if ( pending != 0 && ((pending->finished > 0 && startmilli > pending->finished) || startmilli > pending->expiration+timepad) )
        {
            HASH_DELETE(hh,myinfo->basilisks.issued,pending);
            //printf("%f > %f (%d) clear pending.%p numresults.%d %p\n",startmilli,pending->expiration+timepad,timepad,pending,pending->numresults,pending->retstr);
            for (i=0; i<pending->numresults; i++)
                if ( (item= pending->results[i]) != 0 )
                    free_json(item);
            if ( pending->retstr != 0 )
                free(pending->retstr);
            memset(pending,0,sizeof(*pending));
            free(pending);
            n++;
        }
    }
    portable_mutex_unlock(&myinfo->basilisk_mutex);
    return(n);
}

void basilisks_loop(void *arg)
{
    static uint32_t counter;
    struct iguana_info *relay; struct supernet_info *myinfo = arg; int32_t i,iter; double startmilli,endmilli; struct dpow_info *dp;
    iter = 0;
    relay = iguana_coinfind("RELAY");
    printf("start basilisk loop\n");
    while ( 1 )
    {
        if ( relay == 0 )
            relay = iguana_coinfind("RELAY");
        startmilli = OS_milliseconds();
        endmilli = startmilli + 1000;
//fprintf(stderr,"A ");
        basilisk_issued_purge(myinfo,600000);
//fprintf(stderr,"B ");
        basilisk_p2pQ_process(myinfo,777);
//fprintf(stderr,"C ");
        if ( myinfo->IAMNOTARY != 0 )
        {
            if ( relay != 0 )
            {
//fprintf(stderr,"D ");
                basilisk_ping_send(myinfo,relay);
            }
            counter++;
//fprintf(stderr,"E ");
            if ( myinfo->numdpows == 1 )
            {
                iguana_dPoWupdate(myinfo,myinfo->DPOWS[0]);
                endmilli = startmilli + 100;
            }
            else if ( myinfo->numdpows > 1 )
            {
                dp = myinfo->DPOWS[counter % myinfo->numdpows];
                iguana_dPoWupdate(myinfo,dp);
                //if ( (counter % myinfo->numdpows) != 0 )
                {
                    //fprintf(stderr,"F ");
                    iguana_dPoWupdate(myinfo,myinfo->DPOWS[0]);
                }
                endmilli = startmilli + 30;
            }
//fprintf(stderr,"F ");
        }
        else
        {
//fprintf(stderr,"G ");
            dex_updateclient(myinfo);
            if ( myinfo->IAMLP != 0 )
                endmilli = startmilli + 500;
            else endmilli = startmilli + 1000;
        }
        if ( myinfo->expiration != 0 && (myinfo->dexsock >= 0 || myinfo->IAMLP != 0 || myinfo->DEXactive > time(NULL)) )
        {
//fprintf(stderr,"H ");
            for (i=0; i<100; i++)
                if ( basilisk_requests_poll(myinfo) <= 0 )
                    break;
        }
//printf("RELAYID.%d endmilli %f vs now %f\n",myinfo->NOTARY.RELAYID,endmilli,startmilli);
        while ( OS_milliseconds() < endmilli )
            usleep(10000);
//printf("finished waiting numdpow.%d\n",myinfo->numdpows);
        iter++;
    }
}

void basilisks_init(struct supernet_info *myinfo)
{
    iguana_initQ(&myinfo->p2pQ,"p2pQ");
    iguana_initQ(&myinfo->msgQ,"messageQ");
    portable_mutex_init(&myinfo->bu_mutex);
    portable_mutex_init(&myinfo->allcoins_mutex);
    portable_mutex_init(&myinfo->basilisk_mutex);
    portable_mutex_init(&myinfo->smart_mutex);
    portable_mutex_init(&myinfo->DEX_mutex);
    portable_mutex_init(&myinfo->DEX_swapmutex);
    portable_mutex_init(&myinfo->DEX_reqmutex);
    portable_mutex_init(&myinfo->gecko_mutex);
    portable_mutex_init(&myinfo->messagemutex);
    myinfo->basilisks.launched = iguana_launch(iguana_coinfind("BTCD"),"basilisks_loop",basilisks_loop,myinfo,IGUANA_PERMTHREAD);
    printf("Basilisk initialized\n");
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"
#include "../includes/iguana_apideclares2.h"

TWO_STRINGS(tradebot,gensvm,base,rel)
{
#ifdef _WIN
    return(clonestr("{\"error\":\"windows doesnt support SVM\"}"));
#else
    int32_t numfeatures = 317*61;
    struct tradebot_arbpair *pair;
    if ( base[0] != 0 && rel[0] != 0 && (pair= tradebots_arbpair_find(base,rel)) != 0 && pair->fp != 0 )
    {
        tradebots_calcanswers(pair);
        ocas_gen(pair->refc,numfeatures,0,(int32_t)(ftell(pair->fp) / sizeof(pair->rawfeatures)));
        return(clonestr("{\"result\":\"success\"}"));
    } else return(clonestr("{\"error\":\"cant find arbpair\"}"));
#endif
}

ZERO_ARGS(tradebot,openliquidity)
{
    int32_t i; cJSON *array = cJSON_CreateArray();
    for (i=0; i<sizeof(myinfo->linfos)/sizeof(*myinfo->linfos); i++)
    {
        if ( myinfo->linfos[i].base[0] != 0 )
            jaddi(array,linfo_json(&myinfo->linfos[i]));
    }
    return(jprint(array,1));
}

ZERO_ARGS(tradebot,allbalances)
{
    int32_t i,n; double value,pending; char *base; cJSON *item,*balances = cJSON_CreateObject();
    if ( myinfo->liquidity_currencies == 0 )
        myinfo->liquidity_currencies = cJSON_Parse("[\"KMD\", \"BTC\"]");
    if ( myinfo->liquidity_currencies != 0 && (n= cJSON_GetArraySize(myinfo->liquidity_currencies)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            base = jstri(myinfo->liquidity_currencies,i);
            value = tradebot_balance(myinfo,base);
            pending = tradebot_pending(myinfo,base);
            item = cJSON_CreateObject();
            jaddnum(item,"value",value);
            jaddnum(item,"pending",pending);
            jadd(balances,base,item);
        }
    }
    return(jprint(balances,1));
}

ZERO_ARGS(tradebot,anchor)
{
    FILE *fp; char *anchorstr,fname[512]; cJSON *anchor; int32_t retval = -1;
    if ( (anchorstr= tradebot_allbalances(myinfo,0,0,0)) != 0 )
    {
        if ( (anchor= cJSON_Parse(anchorstr)) != 0 )
        {
            if ( jobj(anchor,"error") == 0 )
            {
                sprintf(fname,"%s/anchor",GLOBAL_DBDIR), OS_compatible_path(fname);
                if ( (fp= fopen(fname,"wb")) != 0 )
                {
                    if ( fwrite(anchorstr,1,strlen(anchorstr)+1,fp) == strlen(anchorstr)+1 )
                        retval = 0;
                    fclose(fp);
                }
            }
        }
        free(anchorstr);
    }
    if ( retval == 0 )
        return(clonestr("{\"result\":\"success\"}"));
    else return(clonestr("{\"error\":\"couldnt make anchor file\"}"));
}

ZERO_ARGS(tradebot,portfolio)
{
    char *currentstr,*anchorstr,fname[512]; long fsize; cJSON *current,*anchor=0,*portfolio=0;
    if ( (currentstr= tradebot_allbalances(myinfo,0,0,0)) != 0 )
    {
        if ( (current= cJSON_Parse(currentstr)) != 0 )
        {
            sprintf(fname,"%s/anchor",GLOBAL_DBDIR), OS_compatible_path(fname);
            if ( (anchorstr= OS_filestr(&fsize,fname)) != 0 )
            {
                anchor = cJSON_Parse(anchorstr);
                free(anchorstr);
            }
            if ( anchor == 0 )
                anchor = cJSON_Parse("{}");
            portfolio = tradebot_balancesdiff(myinfo,current,anchor);
            free_json(current);
        }
        free(currentstr);
    }
    if ( portfolio == 0 )
        return(clonestr("{\"result\":\"success\"}"));
    else return(jprint(portfolio,1));
}

ARRAY_OBJ_INT(tradebot,goals,currencies,vals,targettime)
{
    static bits256 zero; char *targetcoin; int32_t i,n;
    if ( currencies != 0 && vals != 0 )
    {
        // init things so automatically updates refli.bid and refli.ask
        // volume range with margin
        // currency percentage value in BTC? target distribution, max percentage, min percentage`
        // min price to sell, max price to buy, max volume
        n = cJSON_GetArraySize(currencies);
        for (i=0; i<n; i++)
        {
            targetcoin = jstri(currencies,i);
            tradebot_liquidity_command(myinfo,targetcoin,zero,vals);
        }
        return(clonestr("{\"result\":\"success\"}"));
    } else return(clonestr("{\"error\":\"no currencies or vals\"}"));
}

HASH_ARRAY_STRING(basilisk,getmessage,hash,vals,hexstr)
{
    uint32_t msgid,width,channel; char *retstr;
    if ( bits256_cmp(GENESIS_PUBKEY,jbits256(vals,"srchash")) == 0 )
        jaddbits256(vals,"srchash",hash);
    if ( bits256_cmp(GENESIS_PUBKEY,jbits256(vals,"desthash")) == 0 )
        jaddbits256(vals,"desthash",myinfo->myaddr.persistent);
    if ( (msgid= juint(vals,"msgid")) == 0 )
    {
        msgid = (uint32_t)time(NULL);
        jdelete(vals,"msgid");
        jaddnum(vals,"msgid",msgid);
    }
    if ( myinfo->NOTARY.RELAYID >= 0 || myinfo->dexsock >= 0 || myinfo->subsock >= 0 )
    {
        channel = juint(vals,"channel");
        width = juint(vals,"width");
        retstr = basilisk_iterate_MSG(myinfo,channel,msgid,jbits256(vals,"srchash"),jbits256(vals,"desthash"),width);
        //printf("getmessage.(%s)\n",retstr);
        return(retstr);
    }
    //printf("getmessage not relay.%d dexsock.%d subsock.%d\n",myinfo->NOTARY.RELAYID,myinfo->dexsock,myinfo->subsock);
    return(basilisk_standardservice("MSG",myinfo,0,jbits256(vals,"desthash"),vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,sendmessage,hash,vals,hexstr)
{
    int32_t keylen,datalen,allocsize = 65536; uint8_t key[BASILISK_KEYSIZE],*space,*space2,*data,*ptr = 0; char *retstr=0;
    space = calloc(1,allocsize);
    space2 = calloc(1,allocsize);
    data = get_dataptr(BASILISK_HDROFFSET,&ptr,&datalen,&space[BASILISK_KEYSIZE],allocsize-BASILISK_KEYSIZE,hexstr);
    if ( myinfo->subsock >= 0 || myinfo->dexsock >= 0 || (myinfo->IAMNOTARY != 0 && myinfo->NOTARY.RELAYID >= 0) )
    {
        keylen = basilisk_messagekey(key,juint(vals,"channel"),juint(vals,"msgid"),jbits256(vals,"srchash"),jbits256(vals,"desthash"));
        if ( data != 0 )
        {
            retstr = basilisk_respond_addmessage(myinfo,key,keylen,data,datalen,0,juint(vals,"duration"));
        } else printf("no get_dataptr\n");
        if ( retstr != 0 )
            free(retstr);
    } //else printf("not notary.%d relayid.%d\n",myinfo->IAMNOTARY,myinfo->NOTARY.RELAYID);
    if ( vals != 0 && juint(vals,"fanout") == 0 )
        jaddnum(vals,"fanout",MAX(8,(int32_t)sqrt(myinfo->NOTARY.NUMRELAYS)+2));
    if ( BASILISK_KEYSIZE+datalen < allocsize )
    {
        memcpy(space2,key,BASILISK_KEYSIZE);
        if ( data != 0 && datalen != 0 )
            memcpy(&space2[BASILISK_KEYSIZE],data,datalen);
        dex_reqsend(myinfo,"DEX",space2,datalen+BASILISK_KEYSIZE,1,"");
    } else printf("sendmessage space too small error for %d\n",datalen);
    free(space);
    free(space2);
    if ( ptr != 0 )
        free(ptr);
    return(basilisk_standardservice("OUT",myinfo,0,jbits256(vals,"desthash"),vals,hexstr,0));
}

HASH_ARRAY_STRING(basilisk,value,hash,vals,hexstr)
{
    char *retstr=0,*symbol,*coinaddr,*infostr; cJSON *retjson,*sobj,*info,*addrs,*txoutjson,*txjson,*array; uint32_t basilisktag,blocktime,numtx=0; bits256 txid,blockhash,merkleroot; struct basilisk_item *ptr,Lptr; uint64_t value; int32_t timeoutmillis,vout,height,n,m;
    if ( vals == 0 )
        return(clonestr("{\"error\":\"null valsobj\"}"));
    //if ( myinfo->IAMNOTARY != 0 || myinfo->NOTARY.RELAYID >= 0 )
    //    return(clonestr("{\"error\":\"special relays only do OUT and MSG\"}"));
    //if ( coin == 0 )
    {
        if ( (symbol= jstr(vals,"symbol")) != 0 || (symbol= jstr(vals,"coin")) != 0 )
            coin = iguana_coinfind(symbol);
    }
    if ( jobj(vals,"fanout") == 0 )
        jaddnum(vals,"fanout",MAX(5,(int32_t)sqrt(myinfo->NOTARY.NUMRELAYS)+1));
    txid = jbits256(vals,"txid");
    vout = jint(vals,"vout");
    if ( coin != 0 )
    {
        if ( coin->FULLNODE < 0 )
        {
            if ( (txoutjson= dpow_gettxout(myinfo,coin,txid,vout)) != 0 )
            {
                if ( (value= SATOSHIDEN*jdouble(txoutjson,"value")) == 0 )
                    value = SATOSHIDEN*jdouble(txoutjson,"amount");
                if ( (coinaddr= jstr(txoutjson,"address")) == 0 )
                {
                    if ( (sobj= jobj(txoutjson,"scriptPubKey")) != 0 && (addrs= jarray(&n,sobj,"addresses")) != 0 && n > 0 )
                        coinaddr = jstri(addrs,0);
                    printf("no address, check addrs %p coinaddr.%p\n",sobj,coinaddr);
                }
                if ( coinaddr != 0 && value != 0 )
                {
                    retjson = cJSON_CreateObject();
                    jaddstr(retjson,"result","success");
                    jaddstr(retjson,"address",coinaddr);
                    jadd64bits(retjson,"satoshis",value);
                    jaddnum(retjson,"value",dstr(value));
                    jaddnum(retjson,"amount",dstr(value));
                    height = dpow_getchaintip(myinfo,&merkleroot,&blockhash,&blocktime,0,&numtx,coin);
                    jaddnum(retjson,"height",height);
                    jaddnum(retjson,"numconfirms",jint(txoutjson,"confirmations"));
                    jaddbits256(retjson,"txid",txid);
                    jaddnum(retjson,"vout",vout);
                    jaddstr(retjson,"coin",coin->symbol);
                }
                else
                {
                    printf("missing fields.(%s)\n",jprint(txoutjson,0));
                    free_json(txoutjson);
                    return(clonestr("{\"error\":\"return from gettxout missing fields\"}"));
                }
                free_json(txoutjson);
                return(jprint(retjson,1));
            } //else return(clonestr("{\"error\":\"null return from gettxout\"}"));
        }
        else
        {
            if ( (basilisktag= juint(vals,"basilisktag")) == 0 )
                basilisktag = rand();
            if ( (timeoutmillis= juint(vals,"timeout")) <= 0 )
                timeoutmillis = BASILISK_TIMEOUT;
            if ( coin->FULLNODE > 0 && (ptr= basilisk_bitcoinvalue(&Lptr,myinfo,coin,remoteaddr,basilisktag,timeoutmillis,vals)) != 0 )
            {
                retstr = ptr->retstr, ptr->retstr = 0;
                ptr->finished = OS_milliseconds() + 10000;
                return(retstr);
            }
        }
    }
    if ( myinfo->reqsock >= 0 )
    {
        if ( (retstr= _dex_getrawtransaction(myinfo,symbol,txid)) != 0 )
        {
            if ( (txoutjson= cJSON_Parse(retstr)) != 0 )
            {
                //printf("TX.(%s)\n",jprint(txoutjson,0));
                retjson = cJSON_CreateObject();
                jaddstr(retjson,"result","success");
                jaddnum(retjson,"numconfirms",jint(txoutjson,"confirmations"));
                if ( (height= jint(txoutjson,"height")) == 0 && coin != 0 )
                    height = coin->longestchain - jint(txoutjson,"confirmations");
                jaddnum(retjson,"height",height);
                if ( (array= jarray(&n,txoutjson,"vout")) != 0 && vout < n && (txjson= jitem(array,vout)) != 0 )
                {
                    //printf("txjson.(%s)\n",jprint(txjson,0));
                    if ( (value= jdouble(txjson,"value") * SATOSHIDEN) != 0 )
                    {
                        if ( (sobj= jobj(txjson,"scriptPubKey")) != 0 && (addrs= jarray(&m,sobj,"addresses")) != 0 && (coinaddr= jstri(addrs,0)) != 0 )
                            jaddstr(retjson,"address",coinaddr);
                        jadd64bits(retjson,"satoshis",value);
                        jaddnum(retjson,"value",dstr(value));
                        if ( (infostr= _dex_getinfo(myinfo,symbol)) != 0 )
                        {
                            if ( (info= cJSON_Parse(infostr)) != 0 )
                            {
                                if ( (height= jint(info,"blocks")) > 0 )
                                {
                                    height -= jint(txoutjson,"confirmations");
                                    jaddnum(retjson,"height",height);
                                }
                                free_json(info);
                            }
                            free(infostr);
                        }
                        jaddbits256(retjson,"txid",txid);
                        jaddnum(retjson,"vout",vout);
                        jaddstr(retjson,"coin",symbol);
                        free(retstr);
                        free_json(txoutjson);
                        return(jprint(retjson,1));
                    }
                }
                free_json(txoutjson);
                return(jprint(retjson,1));
            }
            return(retstr);
        }
    }
    return(basilisk_standardservice("VAL",myinfo,0,hash,vals,hexstr,1));
}

HASH_ARRAY_STRING(basilisk,rawtx,hash,vals,hexstr)
{
    char *retstr=0,*symbol; uint32_t basilisktag; int32_t timeoutmillis,i,retval = -1; uint64_t amount,txfee; cJSON *retarray;
    if ( vals == 0 )
        return(clonestr("{\"error\":\"null valsobj\"}"));
    //if ( coin == 0 )
    {
        if ( (symbol= jstr(vals,"symbol")) != 0 || (symbol= jstr(vals,"coin")) != 0 )
            coin = iguana_coinfind(symbol);
    }
    if ( jobj(vals,"numrequired") == 0 )
        jaddnum(vals,"numrequired",MIN(3,(int32_t)sqrt(myinfo->NOTARY.NUMRELAYS)+1));
    if ( jobj(vals,"fanout") == 0 )
        jaddnum(vals,"fanout",MAX(3,(int32_t)sqrt(myinfo->NOTARY.NUMRELAYS)+1));
    if ( coin != 0 )
    {
        //if ( juint(vals,"burn") == 0 )
        //    jaddnum(vals,"burn",0.0001);
        if ( (basilisktag= juint(vals,"basilisktag")) == 0 )
            basilisktag = rand();
        if ( (timeoutmillis= juint(vals,"timeout")) <= 0 )
            timeoutmillis = BASILISK_TIMEOUT;
        if ( (retstr= basilisk_bitcoinrawtx(myinfo,coin,remoteaddr,basilisktag,timeoutmillis,vals,0)) != 0 )
        {
            printf("rawtx.(%s)\n",retstr);
            if ( (amount= j64bits(vals,"satoshis")) == 0 )
                amount = jdouble(vals,"value") * SATOSHIDEN;
            if ( (txfee= j64bits(vals,"txfee")) == 0 )
                txfee = coin->chain->txfee;
            if ( txfee == 0 )
                txfee = 10000;
            retval = -1;
            if ( (retarray= cJSON_Parse(retstr)) != 0 )
            {
                if ( is_cJSON_Array(retarray) != 0 )
                {
                    for (i=0; i<cJSON_GetArraySize(retarray); i++)
                    {
                        if ( basilisk_vins_validate(myinfo,coin,jitem(retarray,i),amount,txfee) == 0 )
                        {
                            retval = 0;
                            break;
                        }
                    }
                } else retval = basilisk_vins_validate(myinfo,coin,retarray,amount,txfee);
                if ( retval < 0 )
                {
                    printf("ERROR.(%s)\n",retstr);
                    free(retstr);
                    retstr = clonestr("{\"error\":\"invalid vin in rawtx\"}");
                }
            }
        }
    } else retstr = clonestr("{\"error\":\"no coin specified or found\"}");
    return(retstr);
}

STRING_ARG(jumblr,setpassphrase,passphrase)
{
    cJSON *retjson,*tmp; char KMDaddr[64],BTCaddr[64],wifstr[64],*smartaddrs; bits256 privkey; struct iguana_info *coinbtc;
    if ( passphrase == 0 || passphrase[0] == 0 || (coin= iguana_coinfind("KMD")) == 0 )//|| coin->FULLNODE >= 0 )
        return(clonestr("{\"error\":\"no passphrase or no native komodod\"}"));
    else
    {
        safecopy(myinfo->jumblr_passphrase,passphrase,sizeof(myinfo->jumblr_passphrase));
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","success");
        privkey = jumblr_privkey(myinfo,BTCaddr,0,KMDaddr,JUMBLR_DEPOSITPREFIX);
        smartaddress_add(myinfo,privkey,"deposit","KMD",0.,0.);
        myinfo->jumblr_depositkey = curve25519(privkey,curve25519_basepoint9());
        bitcoin_priv2wif(wifstr,privkey,coin->chain->wiftype);
        if ( coin->FULLNODE < 0 )
            jumblr_importprivkey(myinfo,coin,wifstr);
        jaddstr(retjson,"KMDdeposit",KMDaddr);
        jaddstr(retjson,"BTCdeposit",BTCaddr);
        if ( (coinbtc= iguana_coinfind("BTC")) != 0 )
        {
            bitcoin_priv2wif(wifstr,privkey,coinbtc->chain->wiftype);
            if ( coinbtc->FULLNODE < 0 )
                jumblr_importprivkey(myinfo,coinbtc,wifstr);
            jaddnum(retjson,"BTCdeposits",dstr(jumblr_balance(myinfo,coinbtc,BTCaddr)));
        }
        privkey = jumblr_privkey(myinfo,BTCaddr,0,KMDaddr,"");
        smartaddress_add(myinfo,privkey,"jumblr","KMD",0.,0.);
        myinfo->jumblr_pubkey = curve25519(privkey,curve25519_basepoint9());
        jaddstr(retjson,"KMDjumblr",KMDaddr);
        jaddstr(retjson,"BTCjumblr",BTCaddr);
        if ( coinbtc != 0 )
            jaddnum(retjson,"BTCjumbled",dstr(jumblr_balance(myinfo,coinbtc,BTCaddr)));
        if ( (smartaddrs= InstantDEX_smartaddresses(myinfo,0,0,0)) != 0 )
        {
            if ( (tmp= cJSON_Parse(smartaddrs)) != 0 )
                jadd(retjson,"smartaddresses",tmp);
            free(smartaddrs);
        }
        return(jprint(retjson,1));
    }
}

ZERO_ARGS(jumblr,runsilent)
{
    myinfo->runsilent = 1;
    return(clonestr("{\"result\":\"success\",\"mode\":\"runsilent\"}"));
}

ZERO_ARGS(jumblr,totransparent)
{
    myinfo->runsilent = 0;
    return(clonestr("{\"result\":\"success\",\"mode\":\"totransparent\"}"));
}

ZERO_ARGS(jumblr,status)
{
    cJSON *retjson; char KMDaddr[64],BTCaddr[64]; struct jumblr_item *ptr,*tmp; struct iguana_info *coinbtc; int64_t received,deposited,jumblred,step_t2z,step_z2z,step_z2t,finished,pending,maxval,minval;
    if ( strcmp(coin->symbol,"KMD") == 0 && coin->FULLNODE < 0 && myinfo->jumblr_passphrase[0] != 0 )
    {
        jumblr_opidsupdate(myinfo,coin);
        retjson = cJSON_CreateObject();
        step_t2z = step_z2z = step_z2t = deposited = finished = pending = 0;
        jumblr_privkey(myinfo,BTCaddr,0,KMDaddr,JUMBLR_DEPOSITPREFIX);
        jaddstr(retjson,"mode",myinfo->runsilent == 0 ? "totransparent" : "runsilent");
        jaddstr(retjson,"KMDdeposit",KMDaddr);
        jaddstr(retjson,"BTCdeposit",BTCaddr);
        if ( (coinbtc= iguana_coinfind("BTC")) != 0 )
            jaddnum(retjson,"BTCdeposits",dstr(jumblr_balance(myinfo,coinbtc,BTCaddr)));
        received = jumblr_receivedby(myinfo,coin,KMDaddr);
        deposited = jumblr_balance(myinfo,coin,KMDaddr);
        jumblr_privkey(myinfo,BTCaddr,0,KMDaddr,"");
        jaddstr(retjson,"KMDjumblr",KMDaddr);
        jaddstr(retjson,"BTCjumblr",BTCaddr);
        if ( coinbtc != 0 )
            jaddnum(retjson,"BTCjumbled",dstr(jumblr_balance(myinfo,coinbtc,BTCaddr)));
        finished = jumblr_receivedby(myinfo,coin,KMDaddr);
        jumblred = jumblr_balance(myinfo,coin,KMDaddr);
        HASH_ITER(hh,myinfo->jumblrs,ptr,tmp)
        {
            if ( strlen(ptr->src) >= 40 )
            {
                if ( strlen(ptr->dest) >= 40 )
                    step_z2z += ptr->amount;
                else step_z2t += ptr->amount;
            } else step_t2z += ptr->amount;
        }
        jaddstr(retjson,"result","success");
        jaddnum(retjson,"deposits",dstr(deposited));
        jaddnum(retjson,"t_to_z",dstr(step_t2z));
        jaddnum(retjson,"z_to_z",dstr(step_z2z));
        jaddnum(retjson,"z_to_t",dstr(step_z2t));
        maxval = MAX(step_t2z,MAX(step_z2z,step_z2t));
        minval = MIN(step_t2z,MIN(step_z2z,step_z2t));
        if ( maxval > minval )
        {
            pending = (maxval - minval);
            if ( pending < finished*.1 )
                pending = 0;
        }
        jaddnum(retjson,"pending",dstr(pending));
        jaddnum(retjson,"jumbled",dstr(jumblred));
        jaddnum(retjson,"received",dstr(received));
        jaddnum(retjson,"finished",dstr(finished));
        return(jprint(retjson,1));
    }
    else
    {
        printf("(%s) (%s) %d\n",coin->symbol,myinfo->jumblr_passphrase,coin->FULLNODE);
        return(clonestr("{\"error\":\"jumblr status no passphrase or no native komodod\"}"));
    }
}

HASH_ARRAY_STRING(basilisk,balances,hash,vals,hexstr)
{
    char *retstr=0,*symbol; uint32_t basilisktag; struct basilisk_item *ptr,Lptr; int32_t timeoutmillis;
    if ( myinfo->NOTARY.RELAYID >= 0 )
        return(clonestr("{\"error\":\"special relays only do OUT and MSG\"}"));
    if ( vals == 0 )
        return(clonestr("{\"error\":\"need vals object\"}"));
    if ( (symbol= jstr(vals,"symbol")) != 0 || (symbol= jstr(vals,"coin")) != 0 )
        coin = iguana_coinfind(symbol);
    if ( jobj(vals,"history") == 0 )
        jaddnum(vals,"history",3);
    if ( jobj(vals,"fanout") == 0 )
        jaddnum(vals,"fanout",MAX(8,(int32_t)sqrt(myinfo->NOTARY.NUMRELAYS)+1));
    if ( jobj(vals,"numrequired") == 0 )
        jaddnum(vals,"numrequired",MIN(juint(vals,"fanout")/2,(int32_t)sqrt(myinfo->NOTARY.NUMRELAYS)));
    if ( jobj(vals,"addresses") == 0 )
    {
        jadd(vals,"addresses",iguana_getaddressesbyaccount(myinfo,coin,"*"));
        //printf("added all %s addresses: %s\n",coin->symbol,jprint(vals,0));
    } //else printf("have addresses.(%s)\n",jprint(jobj(vals,"addresses"),0));
    if ( (basilisktag= juint(vals,"basilisktag")) == 0 )
        basilisktag = rand();
    if ( (timeoutmillis= juint(vals,"timeout")) <= 0 )
        timeoutmillis = BASILISK_TIMEOUT;
    if ( coin != 0 )
    {
        if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 || coin->notarychain >= 0 )
        {
            if ( (ptr= basilisk_bitcoinbalances(&Lptr,myinfo,coin,remoteaddr,basilisktag,timeoutmillis,vals)) != 0 )
            {
                retstr = ptr->retstr, ptr->retstr = 0;
                ptr->finished = OS_milliseconds() + 10000;
                return(retstr);
            }
            return(clonestr("{\"error\":\"no result\"}"));
        }
    } else printf("no coin\n");
    if ( (retstr= basilisk_standardservice("BAL",myinfo,0,hash,vals,hexstr,1)) != 0 )
    {
        basilisk_unspents_process(myinfo,coin,retstr);
    }
    return(retstr);
}

HASH_ARRAY_STRING(basilisk,history,hash,vals,hexstr)
{
    int64_t total = 0; int32_t i,n; char *symbol; cJSON *retjson,*unspents,*spends,*array; //struct basilisk_spend *s; struct basilisk_unspent *bu; int32_t i; struct iguana_waccount *wacct,*tmp; struct iguana_waddress *waddr,*tmp2; 
    if ( vals == 0 )
        return(clonestr("{\"error\":\"need vals object\"}"));
    //if ( coin == 0 )
    {
        if ( (symbol= jstr(vals,"symbol")) != 0 || (symbol= jstr(vals,"coin")) != 0 )
            coin = iguana_coinfind(symbol);
    }
    if ( coin == 0 )
        return(clonestr("{\"error\":\"couldnt find coin\"}"));
    unspents = cJSON_CreateArray();
    spends = cJSON_CreateArray();
    portable_mutex_lock(&myinfo->bu_mutex);
    //HASH_ITER(hh,myinfo->wallet,wacct,tmp)
    {
        //HASH_ITER(hh,wacct->waddr,waddr,tmp2)
        {
            if ( myinfo->Cunspents != 0 )
            {
                //printf("Cunspents.(%s)\n",jprint(waddr->Cunspents,0));
                if ( (array= jobj(myinfo->Cunspents,coin->symbol)) != 0 )
                {
                    if ( (n= cJSON_GetArraySize(array)) > 0 )
                    {
                        for (i=0; i<n; i++)
                            total += jdouble(jitem(array,i),"amount") * SATOSHIDEN;
                    }
                    jaddi(unspents,jduplicate(array));
                }
            }
            if ( myinfo->Cspends != 0 )
            {
                //printf("Cspends.(%s)\n",jprint(waddr->Cspends,0));
                if ( (array= jobj(myinfo->Cspends,coin->symbol)) != 0  )
                    jaddi(spends,jduplicate(array));
            }
        }
    }
    portable_mutex_unlock(&myinfo->bu_mutex);
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jadd(retjson,"unspents",unspents);
    jadd(retjson,"spends",spends);
    jaddstr(retjson,"coin",coin->symbol);
    jaddnum(retjson,"balance",dstr(total));
    //printf("return history balance %s %.8f\n",coin->symbol,dstr(total));
    return(jprint(retjson,1));
}

INT_ARG(passthru,paxfiats,mask)
{
    if ( mask == 0 )
        mask = -1;
    komodo_assetcoins(-1,mask);
    return(clonestr("{\"result\":\"success\"}"));
}

INT_ARG(basilisk,paxfiats,mask)
{
    if ( mask == 0 )
        mask = -1;
    komodo_assetcoins(0,mask);
    return(clonestr("{\"result\":\"success\"}"));
}

INT_ARG(iguana,paxfiats,mask)
{
    if ( mask == 0 )
        mask = -1;
    komodo_assetcoins(1,mask);
    return(clonestr("{\"result\":\"success\"}"));
}

int32_t utxocmp(cJSON *utxo,cJSON *utxo2)
{
    bits256 txid,txid2; int32_t vout=-1,vout2=-1;
    //printf("cmp (%s) vs (%s)\n",jprint(utxo,0),jprint(utxo2,0));
    txid = jbits256(utxo,"txid");
    vout = jint(utxo,"vout");
    txid2 = jbits256(utxo2,"txid");
    vout2 = jint(utxo2,"vout");
    if ( bits256_cmp(txid,txid2) == 0 && vout == vout2 )
        return(0);
    else return(-1);
}

ZERO_ARGS(basilisk,cancelrefresh)
{
    myinfo->cancelrefresh = 1;
    return(clonestr("{\"result\":\"refresh cancel started\"}"));
}

TWO_STRINGS(basilisk,refresh,symbol,address)
{
    cJSON *array=0,*array2=0,*array3,*item,*item2; char *retstr; int32_t i,j,n,m,vout; bits256 txid;
    myinfo->cancelrefresh = 0;
    if ( symbol != 0 && iguana_isnotarychain(symbol) >= 0 && address != 0 && address[0] != 0 )
    {
        if ( (retstr= _dex_listunspent(myinfo,symbol,address)) != 0 )
        {
            array = cJSON_Parse(retstr);
            free(retstr);
        }
        if ( (retstr= _dex_listunspent2(myinfo,symbol,address)) != 0 )
        {
            if ( array == 0 )
                array = cJSON_Parse(retstr);
            else array2 = cJSON_Parse(retstr);
            free(retstr);
        }
        if ( array != 0 && array2 != 0 ) // merge
        {
            m = cJSON_GetArraySize(array2);
            array3 = jduplicate(array);
            n = cJSON_GetArraySize(array3);
            //printf("MERGE %s and %s\n",jprint(array,0),jprint(array2,0));
            for (j=0; j<m; j++)
            {
                if ( myinfo->cancelrefresh != 0 )
                    break;
                item2 = jitem(array2,j);
                for (i=0; i<n; i++)
                    if ( utxocmp(jitem(array,i),item2) == 0 )
                        break;
                if ( i == n )
                {
                    //printf("FOUND NEW %s\n",jprint(item2,0));
                    jaddi(array3,jduplicate(item2));
                }
            }
            free_json(array);
            free_json(array2), array2 = 0;
            array = array3, array3 = 0;
        }
        if ( array != 0 ) // gettxout
        {
            n = cJSON_GetArraySize(array);
            array3 = cJSON_CreateArray();
            for (i=0; i<n; i++)
            {
                if ( myinfo->cancelrefresh != 0 )
                    break;
                item = jitem(array,i);
                txid = jbits256(item,"txid");
                vout = jint(item,"vout");
                if ( (retstr= _dex_gettxout(myinfo,symbol,txid,vout)) != 0 )
                {
                    if ( (item2= cJSON_Parse(retstr)) != 0 )
                    {
                        if ( jdouble(item2,"value") > 0 )
                        {
                            jaddbits256(item2,"txid",txid);
                            jaddnum(item2,"vout",vout);
                            jaddnum(item2,"amount",jdouble(item2,"value"));
                            //printf("%s\n",jprint(item2,0));
                            jaddi(array3,item2);
                        }
                        else free_json(item2);
                    }
                    free(retstr);
                }
            }
            free_json(array);
            myinfo->cancelrefresh = 0;
            return(jprint(array3,1));
        } else return(clonestr("[]"));
    }
    myinfo->cancelrefresh = 0;
    return(clonestr("{\"error\":\"invalid coin or address specified\"}"));
}

STRING_ARRAY_OBJ_STRING(basilisk,utxorawtx,symbol,utxos,vals,ignore)
{
    char *destaddr,*changeaddr; int64_t satoshis,txfee; int32_t completed,sendflag,timelock;
    timelock = jint(vals,"timelock");
    sendflag = jint(vals,"sendflag");
    satoshis = jdouble(vals,"amount") * SATOSHIDEN;
    destaddr = jstr(vals,"destaddr");
    changeaddr = jstr(vals,"changeaddr");
    if ( destaddr != 0 && changeaddr != 0 && symbol != 0 && (coin= iguana_coinfind(symbol)) != 0 )
    {
        txfee = jdouble(vals,"txfee") * SATOSHIDEN;
        return(iguana_utxorawtx(myinfo,coin,timelock,destaddr,changeaddr,&satoshis,1,txfee,&completed,sendflag,utxos,0));
    }
    return(clonestr("{\"error\":\"invalid coin or address specified\"}"));
}

HASH_ARRAY_STRING(basilisk,utxocombine,ignore,vals,symbol)
{
    char *coinaddr,*retstr=0; cJSON *utxos; int64_t satoshis,limit,txfee; int32_t maxvins,completed,sendflag,timelock;
    timelock = 0;
    if ( (maxvins= jint(vals,"maxvins")) == 0 )
        maxvins = 20;
    sendflag = jint(vals,"sendflag");
    coinaddr = jstr(vals,"coinaddr");
    limit = jdouble(vals,"maxamount") * SATOSHIDEN;
    if ( limit > 0 && symbol != 0 && symbol[0] != 0 && (utxos= basilisk_utxosweep(myinfo,symbol,&satoshis,limit,maxvins,coinaddr)) != 0 && cJSON_GetArraySize(utxos) > 0 )
    {
        if ( coinaddr != 0 && symbol != 0 && (coin= iguana_coinfind(symbol)) != 0 )
        {
            txfee = jdouble(vals,"txfee") * SATOSHIDEN;
            retstr = iguana_utxorawtx(myinfo,coin,timelock,coinaddr,coinaddr,&satoshis,1,txfee,&completed,sendflag,utxos,0);
        }
        free_json(utxos);
    }
    if ( retstr == 0 )
        return(clonestr("{\"error\":\"invalid coin or address specified or no available utxos\"}"));
    return(retstr);
}

//int64_t iguana_verifytimelock(struct supernet_info *myinfo,struct iguana_info *coin,uint32_t timelocked,char *destaddr,bits256 txid,int32_t vout)
THREE_STRINGS_AND_DOUBLE(tradebot,aveprice,comment,base,rel,basevolume)
{
    double retvals[4],aveprice; cJSON *retjson = cJSON_CreateObject();
    aveprice = instantdex_avehbla(myinfo,retvals,base,rel,basevolume);
    jaddstr(retjson,"result","success");
    jaddnum(retjson,"aveprice",aveprice);
    jaddnum(retjson,"avebid",retvals[0]);
    jaddnum(retjson,"bidvol",retvals[1]);
    jaddnum(retjson,"aveask",retvals[2]);
    jaddnum(retjson,"askvol",retvals[3]);
    return(jprint(retjson,1));
}

ZERO_ARGS(InstantDEX,allcoins)
{
    struct iguana_info *tmp; cJSON *native,*notarychains,*basilisk,*virtual,*full,*retjson = cJSON_CreateObject();
    full = cJSON_CreateArray();
    native = cJSON_CreateArray();
    basilisk = cJSON_CreateArray();
    virtual = cJSON_CreateArray();
    notarychains = cJSON_CreateArray();
    HASH_ITER(hh,myinfo->allcoins,coin,tmp)
    {
        if ( coin->FULLNODE < 0 )
            jaddistr(native,coin->symbol);
        //else if ( coin->virtualchain != 0 )
        //    jaddistr(virtual,coin->symbol);
        else if ( coin->FULLNODE > 0 )//|| coin->VALIDATENODE > 0 )
            jaddistr(full,coin->symbol);
        //else if ( coin->notarychain >= 0 )
        //    jaddistr(notarychains,coin->symbol);
        else jaddistr(basilisk,coin->symbol);
    }
    jadd(retjson,"native",native);
    jadd(retjson,"basilisk",basilisk);
    jadd(retjson,"full",full);
    //jadd(retjson,"virtual",virtual);
    //jadd(retjson,"notarychains",notarychains);
    return(jprint(retjson,1));
}

STRING_ARG(InstantDEX,available,source)
{
    uint64_t total = 0; int32_t i,n=0; char coinaddr[64]; cJSON *item,*unspents,*retjson = 0;
    if ( source != 0 && source[0] != 0 && (coin= iguana_coinfind(source)) != 0 )
    {
        if ( myinfo->expiration != 0 )
        {
            bitcoin_address(coinaddr,coin->chain->pubtype,myinfo->persistent_pubkey33,33);
            if ( (unspents= basilisk_unspents(myinfo,coin,coinaddr)) != 0 )
            {
                //printf("available.(%s)\n",jprint(unspents,0));
                if ( (n= cJSON_GetArraySize(unspents)) > 0 )
                {
                    for (i=0; i<n; i++)
                    {
                        item = jitem(unspents,i);
                        //if ( is_cJSON_True(jobj(item,"spendable")) != 0 )
                        total += jdouble(item,"amount") * SATOSHIDEN;
                        //printf("(%s) -> %.8f\n",jprint(item,0),dstr(total));
                    }
                }
                free_json(unspents);
            }
            retjson = cJSON_CreateObject();
            jaddnum(retjson,"result",dstr(total));
            printf(" n.%d total %.8f (%s)\n",n,dstr(total),jprint(retjson,0));
            return(jprint(retjson,1));
        }
        printf("InstantDEX_available: need to unlock wallet\n");
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    }
    printf("InstantDEX_available: %s is not active\n",source!=0?source:"");
    return(clonestr("{\"error\":\"specified coin is not active\"}"));
}

HASH_ARRAY_STRING(InstantDEX,request,hash,vals,hexstr)
{
    uint8_t serialized[512]; bits256 privkey; char buf[512],BTCaddr[64],KMDaddr[64]; struct basilisk_request R; int32_t jumblr,iambob,optionhours; cJSON *reqjson; uint32_t datalen=0,DEX_channel; struct iguana_info *bobcoin,*alicecoin;
    myinfo->DEXactive = (uint32_t)time(NULL) + 3*BASILISK_TIMEOUT + 60;
    jadd64bits(vals,"minamount",jdouble(vals,"minprice") * jdouble(vals,"amount") * SATOSHIDEN);
    if ( jobj(vals,"desthash") == 0 )
        jaddbits256(vals,"desthash",hash);
    jadd64bits(vals,"satoshis",jdouble(vals,"amount") * SATOSHIDEN);
    jadd64bits(vals,"destsatoshis",jdouble(vals,"destamount") * SATOSHIDEN);
    jaddnum(vals,"timestamp",time(NULL));
    if ( (jumblr= jint(vals,"usejumblr")) != 0 )
        privkey = jumblr_privkey(myinfo,BTCaddr,0,KMDaddr,jumblr == 1 ? JUMBLR_DEPOSITPREFIX : "");
    else privkey = myinfo->persistent_priv;
    hash = curve25519(privkey,curve25519_basepoint9());
    if ( jobj(vals,"srchash") == 0 )
        jaddbits256(vals,"srchash",hash);
    printf("service.(%s)\n",jprint(vals,0));
    memset(&R,0,sizeof(R));
    if ( basilisk_request_create(&R,vals,hash,juint(vals,"timestamp"),juint(vals,"DEXselector")) == 0 )
    {
        iambob = bitcoin_coinptrs(hash,&bobcoin,&alicecoin,R.src,R.dest,privkey,GENESIS_PUBKEY);
        if ( (optionhours= jint(vals,"optionhours")) != 0 )
        {
            printf("iambob.%d optionhours.%d R.requestid.%u vs calc %u, q.%u\n",iambob,R.optionhours,R.requestid,basilisk_requestid(&R),R.quoteid);
            if ( iambob != 0 && optionhours > 0 )
            {
                sprintf(buf,"{\"error\":\"illegal call option request hours.%d when iambob.%d\"}",optionhours,iambob);
                printf("ERROR.(%s)\n",buf);
                return(clonestr(buf));
            }
            else if ( iambob == 0 && optionhours < 0 )
            {
                sprintf(buf,"{\"error\":\"illegal put option request hours.%d when iambob.%d\"}",optionhours,iambob);
                printf("ERROR.(%s)\n",buf);
                return(clonestr(buf));
            }
        }
        //if ( myinfo->IAMNOTARY != 0 || myinfo->NOTARY.RELAYID >= 0 )
        //    R.relaybits = myinfo->myaddr.myipbits;
        if ( (reqjson= basilisk_requestjson(&R)) != 0 )
            free_json(reqjson);
        datalen = basilisk_rwDEXquote(1,serialized,&R);
        //int32_t i; for (i=0; i<sizeof(R); i++)
        //    printf("%02x",((uint8_t *)&R)[i]);
        printf(" R.requestid.%u vs calc %u, q.%u datalen.%d\n",R.requestid,basilisk_requestid(&R),R.quoteid,datalen);
        basilisk_rwDEXquote(0,serialized,&R);
    } else printf("error creating request\n");
    if ( datalen > 0 )
    {
        uint32_t msgid;//,crc=0,crcs[2],numiters = 0; uint8_t buf[4096];
        memset(hash.bytes,0,sizeof(hash));
        msgid = (uint32_t)time(NULL);
        DEX_channel = 'D' + ((uint32_t)'E' << 8) + ((uint32_t)'X' << 16);
        myinfo->DEXtrades++; // not exact but allows a one side initiated self-trade
        basilisk_channelsend(myinfo,hash,hash,DEX_channel,msgid,serialized,datalen,60);
        sleep(3);
        /*while ( numiters < 10 && (crc= basilisk_crcsend(myinfo,0,buf,sizeof(buf),hash,myinfo->myaddr.persistent,DEX_channel,msgid,serialized,datalen,crcs)) == 0 )
         {
         //printf("didnt get back what was sent\n");
         sleep(3);
         basilisk_channelsend(myinfo,myinfo->myaddr.persistent,hash,DEX_channel,msgid,serialized,datalen,60);
         numiters++;
         }*/
        //if ( crc != 0 )//basilisk_channelsend(myinfo,R.srchash,R.desthash,DEX_channel,(uint32_t)time(NULL),serialized,datalen,30) == 0 )
        return(clonestr("{\"result\":\"DEX message sent\"}"));
        //else return(clonestr("{\"error\":\"DEX message couldnt be sent\"}"));
    }
    return(clonestr("{\"error\":\"DEX message not sent\"}"));
}

INT_ARG(InstantDEX,automatched,requestid)
{
    // return quoteid
    myinfo->DEXactive = (uint32_t)time(NULL) + INSTANTDEX_LOCKTIME;
    return(clonestr("{\"result\":\"automatched not yet\"}"));
}

int32_t InstantDEX_incoming_func(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    //int32_t i;
    //for (i=0; i<datalen; i++)
    //    printf("%02x",data[i]);
    //printf(" <- incoming\n");
    return(0);
}

int32_t InstantDEX_process_channelget(struct supernet_info *myinfo,void *ptr,int32_t (*internal_func)(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen),uint32_t channel,uint32_t msgid,uint8_t *data,int32_t datalen,uint32_t expiration,uint32_t duration)
{
    return((*internal_func)(myinfo,ptr,data,datalen));
}

INT_ARG(InstantDEX,incoming,requestid)
{
    static uint32_t counter;
    cJSON *retjson,*retarray; bits256 zero; uint32_t DEX_channel,msgid,now,n = myinfo->numsmartaddrs+1; int32_t retval,width,drift=3; bits256 pubkey; uint8_t data[32768];
    now = (uint32_t)time(NULL);
    memset(&zero,0,sizeof(zero));
    width = (now - myinfo->DEXpoll) + 2*drift;
    if ( width < (drift+1) )
        width = 2*drift+1;
    else if ( width > 64 )
        width = 64;
    if ( (counter % n) == n-1 )
        pubkey = myinfo->myaddr.persistent;
    else pubkey = myinfo->smartaddrs[counter % n].pubkey;
    counter++;
    myinfo->DEXpoll = now;
    retjson = cJSON_CreateObject();
    DEX_channel = 'D' + ((uint32_t)'E' << 8) + ((uint32_t)'X' << 16);
    msgid = (uint32_t)time(NULL) + drift;
    if ( (retarray= basilisk_channelget(myinfo,zero,pubkey,DEX_channel,msgid,width)) != 0 )
    {
        //printf("GOT.(%s)\n",jprint(retarray,0));
        if ( (retval= basilisk_process_retarray(myinfo,0,InstantDEX_process_channelget,data,sizeof(data),DEX_channel,msgid,retarray,InstantDEX_incoming_func)) > 0 )
        {
            jaddstr(retjson,"result","success");
        } else jaddstr(retjson,"error","cant process InstantDEX retarray");
        jadd(retjson,"responses",retarray);
    }
    else
    {
        jaddstr(retjson,"error","cant do InstantDEX channelget");
        //char str[65]; printf("error channelget %s %x\n",bits256_str(str,pubkey),msgid);
    }
    return(jprint(retjson,1));
}

/*TWO_INTS(InstantDEX,swapstatus,requestid,quoteid)
 {
 cJSON *vals; char *retstr;
 myinfo->DEXactive = (uint32_t)time(NULL) + INSTANTDEX_LOCKTIME;
 //if ( myinfo->IAMLP != 0 )
 //    return(basilisk_respond_swapstatus(myinfo,myinfo->myaddr.persistent,requestid,quoteid));
 //else
 {
 vals = cJSON_CreateObject();
 jaddnum(vals,"requestid",(uint32_t)requestid);
 jaddnum(vals,"quoteid",(uint32_t)quoteid);
 jaddbits256(vals,"hash",myinfo->myaddr.persistent);
 retstr = basilisk_standardservice("SWP",myinfo,0,myinfo->myaddr.persistent,vals,"",1);
 free_json(vals);
 return(retstr);
 }
 }*/

TWO_INTS(InstantDEX,accept,requestid,quoteid)
{
    cJSON *vals; char *retstr;
    myinfo->DEXactive = (uint32_t)time(NULL) + INSTANTDEX_LOCKTIME;
    if ( myinfo->IAMLP != 0 || myinfo->dexsock >= 0 || myinfo->subsock >= 0 )
        return(basilisk_respond_accept(myinfo,myinfo->persistent_priv,requestid,quoteid,&myinfo->DEXaccept));
    else
    {
        vals = cJSON_CreateObject();
        jaddnum(vals,"quoteid",(uint32_t)quoteid);
        jaddnum(vals,"requestid",(uint32_t)requestid);
        retstr = basilisk_standardservice("ACC",myinfo,0,myinfo->myaddr.persistent,vals,"",1);
        free_json(vals);
        return(retstr);
    }
}

ZERO_ARGS(InstantDEX,init)
{
    basilisk_swaps_init(myinfo);
    return(clonestr("{\"result\":\"success\"}"));
}

ZERO_ARGS(InstantDEX,getswaplist)
{
    return(basilisk_swaplist(myinfo));
}

DOUBLE_ARG(InstantDEX,DEXratio,ratio)
{
    if ( ratio < 0.95 || ratio > 1.01 )
        return(clonestr("{\"result\":\"error\",\"description\":\"DEXratio must be between 0.95 and 1.01\"}"));
    myinfo->DEXratio = ratio;
    return(clonestr("{\"result\":\"success\"}"));
}
#include "../includes/iguana_apiundefs.h"
