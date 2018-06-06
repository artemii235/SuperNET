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

// included from basilisk.c
// requestid is invariant for a specific request
// quoteid is invariant for a specific request after dest fields are set

#ifdef ENABLE_DEXPING
int32_t basilisk_ping_processDEX(struct supernet_info *myinfo,uint32_t senderipbits,uint8_t *data,int32_t datalen)
{
    int32_t i,n,len=0; struct basilisk_relay *relay; struct basilisk_request R; uint8_t clen,serialized[256]; uint16_t sn; uint32_t crc;
    portable_mutex_lock(&myinfo->DEX_reqmutex);
    len += iguana_rwnum(0,&data[len],sizeof(sn),&sn);
    if ( (relay= basilisk_request_ensure(myinfo,senderipbits,sn)) != 0 )
    {
        relay->numrequests = 0;
        for (i=0; i<sn; i++)
        {
            clen = data[len++];
            if ( len+clen <= datalen )
            {
                if ( relay->numrequests < relay->maxrequests )
                {
                    memcpy(serialized,&data[len],clen);
                    printf("ping processDEX\n");
                    n = basilisk_rwDEXquote(0,serialized,&R);
                    if ( n != clen )
                        printf("n.%d clen.%d\n",n,clen);
                    len += clen;
                    crc = basilisk_requestid(&R);
                    if ( crc == R.requestid )
                    {
                        relay->requests[relay->numrequests++] = R;
                        //printf("[(%s %.8f) -> (%s %.8f) r.%u q.%u] ",R.src,dstr(R.srcamount),R.dest,dstr(R.destamount),R.requestid,R.quoteid);
                    } else printf("crc.%u error vs %u\n",crc,R.requestid);
                } else printf("relay num.%d >= max.%d\n",relay->numrequests,relay->maxrequests);
            } else len += clen;
        }
    }
    else
    {
        for (i=0; i<sn; i++)
        {
            if ( len+clen <= datalen )
            {
                clen = data[len++];
                len += clen;
            }
        }
    }
    portable_mutex_unlock(&myinfo->DEX_reqmutex);
    return(len);
}

int32_t basilisk_ping_genDEX(struct supernet_info *myinfo,uint8_t *data,int32_t maxlen)
{
    struct queueitem *item,*tmp; uint8_t clen; int32_t i,datalen = 0; uint16_t sn; uint32_t timestamp,now;
    datalen += sizeof(uint16_t);
    i = 0;
    now = (uint32_t)time(NULL);
    portable_mutex_lock(&myinfo->DEX_mutex);
    DL_FOREACH_SAFE(myinfo->DEX_quotes,item,tmp)
    {
        memcpy(&clen,&item[1],sizeof(clen));
        if ( datalen+clen < maxlen )
        {
            memcpy(&data[datalen],&item[1],clen+1), datalen += (clen + 1);
            i++;
        }
        iguana_rwnum(0,(void *)((long)&item[1] + 1 + sizeof(uint32_t)),sizeof(timestamp),&timestamp);
        if ( now > timestamp + BASILISK_DEXDURATION )
        {
            DL_DELETE(myinfo->DEX_quotes,item);
            free(item);
        } //else printf("now.%u vs timestamp.%u, lag.%d\n",now,timestamp,now-timestamp);
    }
    portable_mutex_unlock(&myinfo->DEX_mutex);
    sn = i;
    iguana_rwnum(1,data,sizeof(sn),&sn); // fill in at beginning
    return(datalen);
}
#endif

int32_t basilisk_rwDEXquote(int32_t rwflag,uint8_t *serialized,struct basilisk_request *rp)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->requestid),&rp->requestid);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->timestamp),&rp->timestamp); // must be 2nd
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->quoteid),&rp->quoteid);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->quotetime),&rp->quotetime);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->optionhours),&rp->optionhours);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->srcamount),&rp->srcamount);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->minamount),&rp->minamount);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(rp->srchash),rp->srchash.bytes);
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(rp->desthash),rp->desthash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->destamount),&rp->destamount);
    if ( rwflag != 0 )
    {
        memcpy(&serialized[len],rp->src,sizeof(rp->src)), len += sizeof(rp->src);
        memcpy(&serialized[len],rp->dest,sizeof(rp->dest)), len += sizeof(rp->dest);
    }
    else
    {
        memcpy(rp->src,&serialized[len],sizeof(rp->src)), len += sizeof(rp->src);
        memcpy(rp->dest,&serialized[len],sizeof(rp->dest)), len += sizeof(rp->dest);
    }
    //len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->DEXselector),&rp->DEXselector);
    //len += iguana_rwnum(rwflag,&serialized[len],sizeof(rp->extraspace),&rp->extraspace);
    if ( rp->quoteid != 0 && basilisk_quoteid(rp) != rp->quoteid )
        printf(" basilisk_rwDEXquote.%d: quoteid.%u mismatch calc %u rp.%p\n",rwflag,rp->quoteid,basilisk_quoteid(rp),rp);
    if ( basilisk_requestid(rp) != rp->requestid )
        printf(" basilisk_rwDEXquote.%d: requestid.%u mismatch calc %u rp.%p\n",rwflag,rp->requestid,basilisk_requestid(rp),rp);
    return(len);
}

uint32_t basilisk_request_enqueue(struct supernet_info *myinfo,struct basilisk_request *rp)
{
    uint8_t serialized[256]; int32_t len; struct queueitem *item;
    //printf(" basilisk_request_enqueue\n");
    len = basilisk_rwDEXquote(1,serialized+1,rp);
    if ( (item= calloc(1,sizeof(*item) + len + 1)) != 0 )
    {
        serialized[0] = len;
        memcpy(&item[1],serialized,len + 1);
        portable_mutex_lock(&myinfo->DEX_mutex);
        DL_APPEND(myinfo->DEX_quotes,item);
        portable_mutex_unlock(&myinfo->DEX_mutex);
        //printf("ENQUEUE.%u calc.%u\n",rp->requestid,basilisk_requestid(rp));
        return(rp->requestid);
    }
    return(0);
}

cJSON *basilisk_requestjson(struct basilisk_request *rp)
{
    cJSON *item = cJSON_CreateObject();
    /*if ( rp->relaybits != 0 )
    {
        expand_ipbits(ipaddr,rp->relaybits);
        jaddstr(item,"relay",ipaddr);
    }*/
    jaddbits256(item,"srchash",rp->srchash);
    if ( bits256_nonz(rp->desthash) != 0 )
        jaddbits256(item,"desthash",rp->desthash);
    jaddstr(item,"src",rp->src);
    if ( rp->srcamount != 0 )
        jadd64bits(item,"srcamount",rp->srcamount);
    if ( rp->minamount != 0 )
        jadd64bits(item,"minamount",rp->minamount);
    jaddstr(item,"dest",rp->dest);
    if ( rp->destamount != 0 )
    {
        //jadd64bits(item,"destamount",rp->destamount);
        jadd64bits(item,"destsatoshis",rp->destamount);
        //printf("DESTSATOSHIS.%llu\n",(long long)rp->destamount);
    }
    jaddnum(item,"quotetime",rp->quotetime);
    jaddnum(item,"timestamp",rp->timestamp);
    jaddnum(item,"requestid",rp->requestid);
    jaddnum(item,"quoteid",rp->quoteid);
    //jaddnum(item,"DEXselector",rp->DEXselector);
    jaddnum(item,"optionhours",rp->optionhours);
    jaddnum(item,"profit",(double)rp->profitmargin / 1000000.);
    if ( rp->quoteid != 0 && basilisk_quoteid(rp) != rp->quoteid )
        printf("quoteid mismatch %u vs %u\n",basilisk_quoteid(rp),rp->quoteid);
    if ( basilisk_requestid(rp) != rp->requestid )
        printf("requestid mismatch %u vs calc %u\n",rp->requestid,basilisk_requestid(rp));
    {
        int32_t i; struct basilisk_request R;
        if ( basilisk_parsejson(&R,item) != 0 )
        {
            if ( memcmp(&R,rp,sizeof(*rp)-sizeof(uint32_t)) != 0 )
            {
                for (i=0; i<sizeof(*rp); i++)
                    printf("%02x",((uint8_t *)rp)[i]);
                printf(" <- rp.%p\n",rp);
                for (i=0; i<sizeof(R); i++)
                    printf("%02x",((uint8_t *)&R)[i]);
                printf(" <- R mismatch\n");
                for (i=0; i<sizeof(R); i++)
                    if ( ((uint8_t *)rp)[i] != ((uint8_t *)&R)[i] )
                        printf("(%02x %02x).%d ",((uint8_t *)rp)[i],((uint8_t *)&R)[i],i);
                printf("mismatches\n");
            } //else printf("matched JSON conv %u %u\n",basilisk_requestid(&R),basilisk_requestid(rp));
        }
    }
    return(item);
}

int32_t basilisk_request_create(struct basilisk_request *rp,cJSON *valsobj,bits256 desthash,uint32_t timestamp,int32_t DEXselector)
{
    char *dest,*src; uint32_t i;
    memset(rp,0,sizeof(*rp));
    if ( (dest= jstr(valsobj,"dest")) != 0 && (src= jstr(valsobj,"source")) != 0 && (rp->srcamount= j64bits(valsobj,"satoshis")) != 0 )
    {
        if ( (rp->destamount= j64bits(valsobj,"destsatoshis")) != 0 )
        {
            rp->desthash = desthash;
            for (i=0; i<4; i++)
                if ( rp->desthash.ulongs[i] != 0 )
                    break;
            if ( i != 4 )
                rp->destamount = 0;
        }
        rp->minamount = j64bits(valsobj,"minamount");
        rp->timestamp = timestamp;
        rp->srchash = jbits256(valsobj,"srchash");
        rp->optionhours = jint(valsobj,"optionhours");
        rp->profitmargin = jdouble(valsobj,"profit") * 1000000;
        //rp->DEXselector = DEXselector;
        strncpy(rp->src,src,sizeof(rp->src)-1);
        strncpy(rp->dest,dest,sizeof(rp->dest)-1);
        //if ( jstr(valsobj,"relay") != 0 )
        //    rp->relaybits = (uint32_t)calc_ipbits(jstr(valsobj,"relay"));
        rp->requestid = basilisk_requestid(rp);
        //printf("set requestid <- %u\n",rp->requestid);
        if ( rp->destamount != 0 && bits256_nonz(rp->desthash) != 0 )
        {
            rp->quoteid = basilisk_quoteid(rp);
            //printf("set quoteid.%u\n",rp->quoteid);
        }
        //printf("create.%u calc.%u\n",rp->requestid,basilisk_requestid(rp));
        return(0);
    }
    return(-1);
}

char *basilisk_start(struct supernet_info *myinfo,bits256 privkey,struct basilisk_request *_rp,uint32_t statebits,int32_t optionduration)
{
    cJSON *retjson; char typestr[64]; bits256 tmpprivkey; double bidasks[2]; struct basilisk_request *rp=0; int32_t i,srcmatch,destmatch;
    if ( _rp->requestid == myinfo->lastdexrequestid )
    {
        printf("filter duplicate r%u\n",_rp->requestid);
        return(clonestr("{\"error\":\"filter duplicate requestid\"}"));
    }
    srcmatch = smartaddress_pubkey(myinfo,typestr,bidasks,&tmpprivkey,_rp->src,_rp->srchash) >= 0;
    destmatch = smartaddress_pubkey(myinfo,typestr,bidasks,&tmpprivkey,_rp->dest,_rp->desthash) >= 0;
    char str[65],str2[65]; printf("%s srcmatch.%d %s destmatch.%d\n",bits256_str(str,_rp->srchash),srcmatch,bits256_str(str2,_rp->desthash),destmatch);
    if ( srcmatch != 0 || destmatch != 0 )
    {
        for (i=0; i<myinfo->numswaps; i++)
            if ( myinfo->swaps[i]->I.req.requestid == _rp->requestid )
            {
                printf("basilisk_thread_start error trying to start requestid.%u which is already started\n",rp->requestid);
                break;
            }
        if ( i == myinfo->numswaps )
        {
            rp = calloc(1,sizeof(*rp));
            *rp = *_rp;
            printf("START thread to complete %u/%u for (%s %.8f) <-> (%s %.8f) q.%u\n",rp->requestid,rp->quoteid,rp->src,dstr(rp->srcamount),rp->dest,dstr(rp->destamount),rp->quoteid);
            myinfo->lastdexrequestid = rp->requestid;
            if ( basilisk_thread_start(myinfo,privkey,rp,statebits,optionduration,0) != 0 )
            {
                basilisk_request_enqueue(myinfo,rp);
                return(clonestr("{\"result\":\"started atomic swap thread\"}"));
            } else return(clonestr("{\"error\":\"couldnt atomic swap thread\"}"));
        }
        else
        {
            printf("trying to start already pending swap.r%u\n",rp->requestid);
            return(clonestr("{\"error\":\"cant start pending swap\"}"));
        }
    }
    else if ( myinfo->IAMLP != 0 )
    {
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","basilisk node needs to start atomic thread locally");
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"unexpected basilisk_start not mine and amrelay\"}"));
}

int32_t basilisk_requests_poll(struct supernet_info *myinfo)
{
    static uint32_t lastpoll;
    char *retstr,typestr[64]; uint8_t data[32768]; cJSON *outerarray,*retjson; uint32_t msgid,channel; int32_t datalen,i,n,retval = 0; struct basilisk_request issueR; bits256 privkey; double bidasks[2],hwm = 0.;
    if ( myinfo->IAMNOTARY != 0 || time(NULL) < lastpoll+5 || (myinfo->IAMLP == 0 && myinfo->DEXactive < time(NULL)) )
        return(retval);
    lastpoll = (uint32_t)time(NULL);
    memset(&issueR,0,sizeof(issueR));
    memset(&myinfo->DEXaccept,0,sizeof(myinfo->DEXaccept));
    //printf("Call incoming\n");
    if ( (retstr= InstantDEX_incoming(myinfo,0,0,0,0)) != 0 )
    {
        //printf("poll.(%s)\n",retstr);
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (outerarray= jarray(&n,retjson,"responses")) != 0 )
            {
                retval++;
                for (i=0; i<n; i++)
                    hwm = basilisk_process_results(myinfo,&issueR,jitem(outerarray,i),hwm);
            } //else hwm = basilisk_process_results(myinfo,&issueR,outerarray,hwm);
            free_json(retjson);
        }
        free(retstr);
    } else printf("null incoming\n");
    channel = 'D' + ((uint32_t)'E' << 8) + ((uint32_t)'X' << 16);
    if ( hwm > 0. )
    {
        myinfo->DEXaccept = issueR;
        if ( smartaddress_pubkey(myinfo,typestr,bidasks,&privkey,issueR.src,issueR.srchash) >= 0 )
        {
            if ( myinfo->DEXtrades > 0 )
            {
                dex_channelsend(myinfo,issueR.srchash,issueR.desthash,channel,0x4000000,(void *)&issueR.requestid,sizeof(issueR.requestid)); // 60
                dpow_nanomsg_update(myinfo);
                dex_updateclient(myinfo);
                if ( (retstr= basilisk_start(myinfo,privkey,&issueR,1,issueR.optionhours * 3600)) != 0 )
                    free(retstr);
            }
        }
        else if ( myinfo->IAMLP != 0 && issueR.requestid != myinfo->lastdexrequestid )//if ( issueR.quoteid == 0 )
        {
            issueR.quoteid = basilisk_quoteid(&issueR);
            issueR.desthash = myinfo->myaddr.persistent;
            datalen = basilisk_rwDEXquote(1,data,&issueR);
            msgid = (uint32_t)time(NULL);
            printf("other req hwm %f >>>>>>>>>>> send response (%llx -> %llx) last.%u r.%u quoteid.%u\n",hwm,(long long)issueR.desthash.txid,(long long)issueR.srchash.txid,myinfo->lastdexrequestid,issueR.requestid,issueR.quoteid);
            dex_channelsend(myinfo,issueR.desthash,issueR.srchash,channel,msgid,data,datalen); //INSTANTDEX_LOCKTIME*2
            dpow_nanomsg_update(myinfo);
            dex_updateclient(myinfo);
            if ( (retstr= basilisk_start(myinfo,myinfo->persistent_priv,&issueR,0,issueR.optionhours * 3600)) != 0 )
                free(retstr);
        } //else printf("basilisk_requests_poll unexpected hwm issueR\n");
    }
    return(retval);
}

struct basilisk_relay *basilisk_request_ensure(struct supernet_info *myinfo,uint32_t senderipbits,int32_t numrequests)
{
    int32_t j; struct basilisk_relay *relay = 0;
    if ( (j= basilisk_relayid(myinfo,senderipbits)) >= 0 )
    {
        relay = &myinfo->NOTARY.RELAYS[j];
        if ( numrequests > relay->maxrequests )
        {
            relay->maxrequests = numrequests;
            relay->requests = realloc(relay->requests,sizeof(*relay->requests) * numrequests);
        }
    }
    return(relay);
}

static int _cmp_requests(const void *a,const void *b)
{
#define uint32_a (*(struct basilisk_request *)a).requestid
#define uint32_b (*(struct basilisk_request *)b).requestid
	if ( uint32_b > uint32_a )
		return(1);
	else if ( uint32_b < uint32_a )
		return(-1);
    else
    {
#undef uint32_a
#undef uint32_b
#define uint32_a (*(struct basilisk_request *)a).quoteid
#define uint32_b (*(struct basilisk_request *)b).quoteid
        if ( uint32_b > uint32_a )
            return(1);
        else if ( uint32_b < uint32_a )
            return(-1);
    }
	return(0);
#undef uint32_a
#undef uint32_b
}

struct basilisk_request *_basilisk_requests_uniq(struct supernet_info *myinfo,int32_t *nump,uint8_t *space,int32_t spacesize,struct basilisk_request *refrp)
{
    int32_t i,j,n,k,m; struct basilisk_relay *relay; struct basilisk_request *requests,*rp;
    m = 0;
    if ( refrp != 0 )
        m = 1;
    for (j=0; j<myinfo->NOTARY.NUMRELAYS; j++)
        m += myinfo->NOTARY.RELAYS[j].numrequests;
    if ( m*sizeof(*requests) <= spacesize )
        requests = (void *)space;
    else requests = calloc(m,sizeof(*requests));
    if ( refrp != 0 )
    {
        requests[0] = *refrp;
        //for (i=0; i<sizeof(*refrp); i++)
        //    printf("%02x",((uint8_t *)refrp)[i]);
        //printf(" uniq\n");
    }
    if ( refrp != 0 )
        m = 1;
    else m = 0;
    for (j=0; j<myinfo->NOTARY.NUMRELAYS; j++)
    {
        relay = &myinfo->NOTARY.RELAYS[j];
        if ( (n= relay->numrequests) > 0 )
        {
            for (i=0; i<n; i++)
            {
                rp = &relay->requests[i];
                for (k=0; k<m; k++)
                    if ( memcmp(&requests[k],rp,sizeof(requests[k])) == 0 )
                        break;
                if ( k == m )
                {
                    //requests[m].relaybits = relay->ipbits;
                    requests[m++] = *rp;
                }
            }
        }
    }
    qsort(requests,m,sizeof(*requests),_cmp_requests);
    *nump = m;
    return(requests);
}

/*char *basilisk_respond_swapstatus(struct supernet_info *myinfo,bits256 hash,uint32_t requestid,uint32_t quoteid)
{
    cJSON *array,*retjson;
    array = cJSON_CreateArray();
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}*/

char *basilisk_respond_requests(struct supernet_info *myinfo,bits256 hash,uint32_t requestid,uint32_t quoteid,struct basilisk_request *refrp)
{
    int32_t i,qflag,num=0; cJSON *retjson,*array; struct basilisk_request *requests,*rp; uint8_t space[4096];
    array = cJSON_CreateArray();
    portable_mutex_lock(&myinfo->DEX_reqmutex);
    if ( (requests= _basilisk_requests_uniq(myinfo,&num,space,sizeof(space),refrp)) != 0 )
    {
        for (i=0; i<num; i++)
        {
            rp = &requests[i];
            if ( quoteid == 0 || (quoteid == rp->quoteid && (bits256_cmp(hash,rp->srchash) == 0 || bits256_cmp(hash,rp->desthash) == 0)) )
                qflag = 1;
            else qflag = 0;
            //int32_t j; for (j=0; j<sizeof(*rp); j++)
            //    printf("%02x",((uint8_t *)rp)[j]);
            //printf(" rp[%d] of %d qflag.%d\n",i,num,qflag);
            if ( requestid == 0 || (rp->requestid == requestid && qflag != 0) )
                jaddi(array,basilisk_requestjson(rp));
        }
    }
    portable_mutex_unlock(&myinfo->DEX_reqmutex);
    if ( requests != (void *)space )
        free(requests);
    retjson = cJSON_CreateObject();
    jadd(retjson,"result",array);
    return(jprint(retjson,1));
}

char *basilisk_respond_accept(struct supernet_info *myinfo,bits256 privkey,uint32_t requestid,uint32_t quoteid,struct basilisk_request *refrp)
{
    int32_t i,num=0; char *retstr=0; struct basilisk_request *requests,*rp; uint8_t space[4096];
    portable_mutex_lock(&myinfo->DEX_reqmutex);
    if ( (requests= _basilisk_requests_uniq(myinfo,&num,space,sizeof(space),refrp)) != 0 )
    {
        for (i=0; i<num; i++)
        {
            rp = &requests[i];
            if ( rp->requestid == requestid && rp->quoteid == quoteid )
            {
                printf("start from accept\n");
                retstr = basilisk_start(myinfo,privkey,rp,1,0);
                break;
            }
        }
    }
    portable_mutex_unlock(&myinfo->DEX_reqmutex);
    if ( requests != (void *)space )
        free(requests);
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"couldnt find to requestid to choose\"}");
    return(retstr);
}

cJSON *basilisk_unspents(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    cJSON *unspents=0,*array=0,*json,*ismine; char *retstr; int32_t valid = 0;
    if ( coin->FULLNODE > 0 )
    {
        array = cJSON_CreateArray();
        jaddistr(array,coinaddr);
        unspents = iguana_listunspents(myinfo,coin,array,0,0,"");
        free_json(array);
    }
    else
    {
        if ( coin->FULLNODE < 0 && (retstr= dpow_validateaddress(myinfo,coin,coinaddr)) != 0 )
        {
            json = cJSON_Parse(retstr);
            if ( (ismine= jobj(json,"ismine")) != 0 && is_cJSON_True(ismine) != 0 )
                valid = 1;
            free(retstr);
        }
        if ( coin->FULLNODE == 0 || valid == 0 )
        {
            if ( (retstr= dex_listunspent(myinfo,coin,0,0,coin->symbol,coinaddr)) != 0 )
            {
                unspents = cJSON_Parse(retstr);
                free(retstr);
            }
        } else unspents = dpow_listunspent(myinfo,coin,coinaddr);
    }
    return(unspents);
}

char *basilisk_sendrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *signedtx)
{
    char *retstr,buf[65]; bits256 txid;
    if ( coin->FULLNODE > 0 )
    {
        txid = iguana_sendrawtransaction(myinfo,coin,signedtx);
        if ( bits256_nonz(txid) )
        {
            bits256_str(buf,txid);
            retstr = clonestr(buf);
        } else retstr = clonestr("{\"error\":\"couldnt validate or send signedtx\"}");
    }
    else if ( coin->FULLNODE == 0 )
    {
        retstr = _dex_sendrawtransaction(myinfo,coin->symbol,signedtx);
    }
    else retstr = dpow_sendrawtransaction(myinfo,coin,signedtx);
    return(retstr);
}

