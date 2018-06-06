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

cJSON *basilisk_rawtxobj(struct supernet_info *myinfo,struct basilisk_swap *swap,struct basilisk_rawtx *rawtx)
{
    char hexstr[sizeof(rawtx->I)*2+1+4096]; cJSON *obj = cJSON_CreateObject();
    jaddstr(obj,"name",rawtx->name);
    init_hexbytes_noT(hexstr,(void *)&rawtx->I,sizeof(rawtx->I));
    jaddstr(obj,"info",hexstr);
    if ( rawtx->I.datalen < sizeof(hexstr)/2 )
    {
        init_hexbytes_noT(hexstr,(void *)rawtx->txbytes,rawtx->I.datalen);
        jaddstr(obj,"txbytes",hexstr);
    }
    return(obj);
}

struct basilisk_rawtx *basilisk_nameconv(struct supernet_info *myinfo,struct basilisk_swap *swap,char *name)
{
    if ( strcmp("myfee",name) == 0 )
        return(&swap->myfee);
    else if ( strcmp("otherfee",name) == 0 )
        return(&swap->otherfee);
    else if ( strcmp("bobdeposit",name) == 0 )
        return(&swap->bobdeposit);
    else if ( strcmp("bobrefund",name) == 0 )
        return(&swap->bobrefund);
    else if ( strcmp("aliceclaim",name) == 0 )
        return(&swap->aliceclaim);
    else if ( strcmp("bobpayment",name) == 0 )
        return(&swap->bobpayment);
    else if ( strcmp("alicespend",name) == 0 )
        return(&swap->alicespend);
    else if ( strcmp("bobreclaim",name) == 0 )
        return(&swap->bobreclaim);
    else if ( strcmp("alicepayment",name) == 0 )
        return(&swap->alicepayment);
    else if ( strcmp("bobspend",name) == 0 )
        return(&swap->bobspend);
    else if ( strcmp("alicereclaim",name) == 0 )
        return(&swap->alicereclaim);
    else return(0);
}

int32_t basilisk_txitem(struct supernet_info *myinfo,struct basilisk_swap *swap,cJSON *obj)
{
    char *hexstr,*name; struct basilisk_rawtx *rawtx = 0;
    if ( (name= jstr(obj,"name")) == 0 || (rawtx= basilisk_nameconv(myinfo,swap,name)) == 0 )
    {
        printf("basilisk_txitem illegal name.(%s)\n",name);
        return(-1);
    }
    if ( rawtx != 0 && (hexstr= jstr(obj,"info")) != 0 && strlen(hexstr) == sizeof(rawtx->I)*2 )
    {
        decode_hex((void *)&rawtx->I,sizeof(rawtx->I),hexstr);
        if ( (hexstr= jstr(obj,"txbytes")) != 0 && strlen(hexstr) == rawtx->I.datalen*2 )
        {
            /*if ( rawtx->txbytes == 0 )
            {
                printf("free (%s) txbytes\n",name);
                free(rawtx->txbytes);
            }
            rawtx->txbytes = calloc(1,rawtx->I.datalen);*/
            decode_hex((void *)rawtx->txbytes,rawtx->I.datalen,hexstr);
        }
        printf("PROCESS.(%s)\n",jprint(obj,0));
        return(0);
    }
    return(-1);
}

cJSON *basilisk_swapobj(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    char hexstr[sizeof(swap->I)*2+1]; cJSON *obj = cJSON_CreateObject();
    init_hexbytes_noT(hexstr,(void *)&swap->I,sizeof(swap->I));
    jaddstr(obj,"name","swap");
    jaddnum(obj,"requestid",swap->I.req.requestid);
    jaddnum(obj,"quoteid",swap->I.req.quoteid);
    jadd(obj,"req",basilisk_requestjson(&swap->I.req));
    jaddstr(obj,"info",hexstr);
    //printf("strlen(hexstr) swap->I %d vs %d\n",(int32_t)strlen(hexstr),(int32_t)sizeof(swap->I)*2);
    return(obj);
}

int32_t basilisk_swapconv(struct supernet_info *myinfo,struct basilisk_swap *swap,cJSON *obj)
{
    char *hexstr;
    if ( (hexstr= jstr(obj,"info")) != 0 && strlen(hexstr) == sizeof(swap->I)*2 )
    {
        decode_hex((void *)&swap->I,sizeof(swap->I),hexstr);
        if ( juint(obj,"requestid") == swap->I.req.requestid && juint(obj,"quoteid") == swap->I.req.quoteid )
            return(0);
        printf("swapconv mismatched req/quote %d %d, %d %d\n",juint(obj,"requestid"),swap->I.req.requestid,juint(obj,"quoteid"),swap->I.req.quoteid);
    } //else printf("no info field in swap obj.(%s) len.%d vs %d\n",jprint(obj,0),(int32_t)strlen(hexstr),(int32_t)sizeof(swap->I)*2);
    return(-1);
}

struct basilisk_swap *basilisk_swapstore(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    // save based on requestid/quoteid
    return(swap);
}

struct basilisk_swap *basilisk_swapload(struct supernet_info *myinfo,struct basilisk_swap *swap,uint32_t requestid,uint32_t quoteid)
{
    // set swap fields and return it if found
    return(0);
}

void basilisk_swapstart(struct supernet_info *myinfo) // scan saved tmpswap, purge if complete, else Q
{
    // for resuming pending swaps
}

void basilisk_txlog(struct supernet_info *myinfo,struct basilisk_swap *swap,struct basilisk_rawtx *rawtx,int32_t delay)
{
    char fname[1024],*jsonstr; long filesize; cJSON *item,*dexobj = 0; int32_t i,n,pending; struct basilisk_swap tmpswap,*swapptr;
    sprintf(fname,"%s/DEX.log",GLOBAL_DBDIR), OS_compatible_path(fname);
    if ( myinfo->dexfp == 0 )
    {
        if ( (jsonstr= OS_filestr(&filesize,fname)) != 0 )
        {
            jsonstr[strlen(jsonstr)-1] = ']';
            if ( jsonstr[strlen(jsonstr)-2] == ',' )
                jsonstr[strlen(jsonstr)-2] = ' ';
            if ( jsonstr[strlen(jsonstr)-3] == ',' )
                jsonstr[strlen(jsonstr)-3] = ' ';
            if ( (dexobj= cJSON_Parse(jsonstr)) != 0 )
            {
                if ( is_cJSON_Array(dexobj) != 0 && (n= cJSON_GetArraySize(dexobj)) > 0 )
                {
                    pending = 0;
                    memset(&tmpswap,0,sizeof(tmpswap));
                    swapptr = 0;
                    for (i=0; i<n; i++)
                    {
                        item = jitem(dexobj,i);
                        if ( jstr(item,"name") != 0 && strcmp(jstr(item,"name"),"swap") == 0 )
                        {
                            if ( basilisk_swapconv(myinfo,&tmpswap,item) == 0 )
                                swapptr = basilisk_swapstore(myinfo,&tmpswap);
                        }
                        else if ( swapptr != 0 )
                        {
                            if ( swapptr->I.req.requestid == juint(item,"requestid") && swapptr->I.req.quoteid == juint(item,"quoteid") )
                                basilisk_txitem(myinfo,swapptr,item);
                        }
                        else if ( (swapptr= basilisk_swapload(myinfo,&tmpswap,juint(item,"requestid"),juint(item,"quoteid"))) != 0 )
                            basilisk_txitem(myinfo,swapptr,item);
                    }
                    basilisk_swapstart(myinfo);
                }
                free_json(dexobj);
                dexobj = 0;
            } else printf("basilisk_txlog error parsing.(%s)\n",jsonstr);
            free(jsonstr);
        }
        if ( (myinfo->dexfp= fopen(fname,"rb+")) != 0 )
            fseek(myinfo->dexfp,0,SEEK_END);
        else if ( (myinfo->dexfp= fopen(fname,"wb")) != 0 )
            fprintf(myinfo->dexfp,"[\n");
    }
    if ( rawtx != 0 )
    {
        // delay -1 -> dont issue, else submit after block timestamp is delay after swap->started
        dexobj = basilisk_rawtxobj(myinfo,swap,rawtx);
    }
    else if ( swap != 0 )
        dexobj = basilisk_swapobj(myinfo,swap);
    if ( dexobj != 0 && (jsonstr= jprint(dexobj,1)) != 0 )
    {
        //printf("%s\n",jsonstr);
        if ( myinfo->dexfp != 0 )
        {
            fprintf(myinfo->dexfp,"%s,\n",jsonstr);
            fflush(myinfo->dexfp);
        }
        free(jsonstr);
    }
}

uint32_t basilisk_requestid(struct basilisk_request *rp)
{
    struct basilisk_request R;
    R = *rp;
    R.requestid = R.quoteid = R.quotetime = 0;
    R.destamount = R.profitmargin = 0;
    //R.relaybits = 0;
    memset(R.desthash.bytes,0,sizeof(R.desthash.bytes));
    if ( 0 )
    {
        int32_t i;
        for (i=0; i<sizeof(R); i++)
            printf("%02x",((uint8_t *)&R)[i]);
        printf(" <- crc.%u\n",calc_crc32(0,(void *)&R,sizeof(R)));
        char str[65],str2[65]; printf("B REQUESTID: t.%u r.%u q.%u %s %.8f %s -> %s %.8f %s crc.%u\n",R.timestamp,R.requestid,R.quoteid,R.src,dstr(R.srcamount),bits256_str(str,R.srchash),R.dest,dstr(R.destamount),bits256_str(str2,R.desthash),calc_crc32(0,(void *)&R,sizeof(R)));
    }
    return(calc_crc32(0,(void *)&R,sizeof(R)));
}

uint32_t basilisk_quoteid(struct basilisk_request *rp)
{
    struct basilisk_request R;
    R = *rp;
    R.requestid = R.quoteid = R.profitmargin = 0; //R.relaybits =
    return(calc_crc32(0,(void *)&R,sizeof(R)));
}

struct basilisk_request *basilisk_parsejson(struct basilisk_request *rp,cJSON *reqjson)
{
    uint32_t requestid,quoteid;
    memset(rp,0,sizeof(*rp));
    rp->srchash = jbits256(reqjson,"srchash");
    rp->desthash = jbits256(reqjson,"desthash");
    rp->srcamount = j64bits(reqjson,"srcamount");
    rp->minamount = j64bits(reqjson,"minamount");
    //rp->destamount = j64bits(reqjson,"destamount");
    rp->destamount = j64bits(reqjson,"destsatoshis");
    //printf("parse DESTSATOSHIS.%llu (%s)\n",(long long)rp->destamount,jprint(reqjson,0));
    requestid = juint(reqjson,"requestid");
    quoteid = juint(reqjson,"quoteid");
    //if ( jstr(reqjson,"relay") != 0 )
    //    rp->relaybits = (uint32_t)calc_ipbits(jstr(reqjson,"relay"));
    rp->timestamp = juint(reqjson,"timestamp");
    rp->quotetime = juint(reqjson,"quotetime");
    safecopy(rp->src,jstr(reqjson,"src"),sizeof(rp->src));
    safecopy(rp->dest,jstr(reqjson,"dest"),sizeof(rp->dest));
    if ( quoteid != 0 )
    {
        rp->quoteid = basilisk_quoteid(rp);
        if ( quoteid != rp->quoteid )
            printf("basilisk_parsejson quoteid.%u != %u error\n",quoteid,rp->quoteid);
    }
    rp->requestid = basilisk_requestid(rp);
    if ( requestid != rp->requestid )
    {
        int32_t i; for (i=0; i<sizeof(*rp); i++)
            printf("%02x",((uint8_t *)rp)[i]);
        printf(" basilisk_parsejson.(%s) requestid.%u != %u error\n",jprint(reqjson,0),requestid,rp->requestid);
    }
    return(rp);
}

struct basilisk_swap *basilisk_request_started(struct supernet_info *myinfo,uint32_t requestid)
{
    int32_t i; struct basilisk_swap *active = 0;
    portable_mutex_lock(&myinfo->DEX_swapmutex);
    for (i=0; i<myinfo->numswaps; i++)
        if ( myinfo->swaps[i]->I.req.requestid == requestid )
        {
            //printf("REQUEST STARTED.[%d] <- req.%u\n",i,requestid);
            active = myinfo->swaps[i];
            break;
        }
    portable_mutex_unlock(&myinfo->DEX_swapmutex);
    return(active);
}

int32_t basilisk_request_cmpref(struct basilisk_request *ref,struct basilisk_request *rp)
{
    if ( bits256_cmp(rp->srchash,ref->srchash) != 0 || memcmp(rp->src,ref->src,sizeof(ref->src)) != 0 || memcmp(rp->dest,ref->dest,sizeof(ref->dest)) != 0 || rp->srcamount != ref->srcamount || rp->timestamp != ref->timestamp )
    {
        printf("basilisk_request_listprocess mismatched hash\n");
        return(-1);
    } else return(0);
}

double basilisk_request_listprocess(struct supernet_info *myinfo,struct basilisk_request *issueR,struct basilisk_request *list,int32_t n)
{
    int32_t i,noquoteflag=0,havequoteflag=0,myrequest=0,maxi=-1; int64_t balance=0,destamount,minamount = 0,maxamount = 0; bits256 privkey; uint32_t pendingid=0; struct basilisk_swap *active; double metric = 0.,bidasks[2]; char typestr[64];
    memset(issueR,0,sizeof(*issueR));
    minamount = list[0].minamount;
    //printf("need to verify null quoteid is list[0] requestid.%u quoteid.%u\n",list[0].requestid,list[0].quoteid);
    if ( (active= basilisk_request_started(myinfo,list[0].requestid)) != 0 )
    {
        if ( active->I.req.quoteid != 0 )
            return(0.);
        pendingid = active->I.req.quoteid;
    }
    if ( smartaddress_pubkey(myinfo,typestr,bidasks,&privkey,list[0].src,list[0].srchash) >= 0 )
        myrequest = 1;
    for (i=0; i<n; i++)
    {
        if ( basilisk_request_cmpref(&list[0],&list[i]) != 0 )
            return(-1);
        if ( list[i].quoteid != 0 )
        {
            if ( smartaddress_pubkey(myinfo,typestr,bidasks,&privkey,list[i].dest,list[i].desthash) >= 0 )
                myrequest |= 2;
            havequoteflag++;
            if ( pendingid == 0 )
            {
                if ( list[i].destamount > maxamount )
                {
                    maxamount = list[i].destamount;
                    //printf("set maxamount %llu\n",(long long)maxamount);
                    maxi = i;
                }
            }
            else if ( active != 0 && pendingid == list[i].quoteid )
            {
            }
        } else noquoteflag++;
    }
    struct iguana_info *coin; char coinaddr[64]; double retvals[4],refprice=0.,profitmargin,aveprice,destvolume;
    destvolume = dstr(maxamount);
    //printf("destvolume <- %.8f\n",dstr(destvolume));
    if ( fabs(destvolume) < SMALLVAL )
    {
        if ( (destvolume= dstr(minamount)) == 0 )
        {
            aveprice = instantdex_avehbla(myinfo,retvals,list[0].src,list[0].dest,1.3 * dstr(list[0].srcamount));
            destvolume = aveprice * dstr(list[0].srcamount);
            printf("set destvolume %.8f\n",destvolume);
        } // else printf("destvolume %.8f <- minamount\n",destvolume);
    }
    printf("<<<<<<< %s -> %s myrequest.%d pendingid.%u noquoteflag.%d havequoteflag.%d maxi.%d %.8f destvol %.8f\n",list[0].src,list[0].dest,myrequest,pendingid,noquoteflag,havequoteflag,maxi,dstr(maxamount),destvolume);
    if ( myinfo->IAMLP != 0 && myrequest == 0 && pendingid == 0 && noquoteflag != 0 && ((profitmargin= tradebot_liquidity_active(myinfo,&refprice,"DEX",list[0].src,list[0].dest,destvolume)) > 0. || refprice != 0.) )
    {
        if ( profitmargin == 0. || (aveprice= instantdex_avehbla(myinfo,retvals,list[0].src,list[0].dest,.1 * dstr(list[0].srcamount))) == 0. || refprice > aveprice )
            aveprice = refprice;
        if ( fabs(aveprice) < SMALLVAL )
            return(0);
        if ( strcmp("BTC",list[0].src) == 0 )
            aveprice = (1. / aveprice);
        //retvals[0] = avebid, retvals[1] = bidvol, retvals[2] = aveask, retvals[3] = askvol;
        destamount = (1.0 - profitmargin) * aveprice * list[0].srcamount;
        if ( destamount > minamount )
            destamount = minamount + ((destamount - minamount) * (1 + (rand() % 100))) / 100.;
        printf("%s/%s pm %f aveprice %f src %.8f dest %.8f avebid %f bidvol %f, aveask %f askvol %f\n",list[0].src,list[0].dest,profitmargin,aveprice,dstr(list[0].srcamount),dstr(destamount),retvals[0],retvals[1],retvals[2],retvals[3]);
        if ( (coin= iguana_coinfind(list[0].dest)) != 0 )
        {
            bitcoin_address(coinaddr,coin->chain->pubtype,myinfo->persistent_pubkey33,33);
            balance = jumblr_balance(myinfo,coin,coinaddr);
            printf("%s %s balance %.8f destamount %.8f aveprice %.8f maxamount %.8f minamount %.8f\n",list[0].dest,coinaddr,dstr(balance),dstr(destamount),aveprice,dstr(maxamount),dstr(minamount));
        }
        /*if ( (retstr= InstantDEX_available(myinfo,iguana_coinfind(list[0].dest),0,0,list[0].dest)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                balance = jdouble(retjson,"result") * SATOSHIDEN;
                free_json(retjson);
            }
            free(retstr);
        }*/
        if ( balance > destamount && (int64_t)destamount > 0 && destamount >= minamount ) // max?
        {
            metric = 1.;
            *issueR = list[0];
            issueR->desthash = myinfo->myaddr.persistent;
            issueR->destamount = destamount;
            issueR->quotetime = (uint32_t)time(NULL);
            issueR->profitmargin = (uint32_t)(profitmargin * 1000000);
        }
    }
    else if ( myrequest != 0 && pendingid == 0 && maxi >= 0 ) // automatch best quote
    {
        if ( minamount != 0 && maxamount >= minamount )//&& time(NULL) > list[0].timestamp+BASILISK_AUCTION_DURATION )
        {
            *issueR = list[maxi];
            for (i=0; i<sizeof(*issueR); i++)
                printf("%02x",((uint8_t *)issueR)[i]);
            printf(" automatch[%d] r.%u quoteid.%u triggered %.8f >= %.8f\n",maxi,list[maxi].requestid,list[maxi].quoteid,dstr(maxamount),dstr(minamount));
            if ( minamount > 0 )
                metric = (dstr(maxamount) / dstr(minamount)) - 1.;
            else metric = 1.;
        }
    }
    return(metric);
}

double basilisk_process_results(struct supernet_info *myinfo,struct basilisk_request *issueR,cJSON *retjson,double hwm)
{
    cJSON *array,*item; uint8_t *hexdata,*allocptr,hexspace[32768]; char *hexstr; int32_t i,hexlen,n,m,nonz; struct basilisk_request tmpR,R,refR,list[BASILISK_MAXRELAYS]; double metric=0.;
    memset(&refR,0,sizeof(refR));
    memset(&R,0,sizeof(R));
//printf("process.(%s)\n",jprint(retjson,0));
    if ( (array= jarray(&n,retjson,"messages")) != 0 )
    {
        for (i=nonz=m=0; i<n; i++)
        {
            item = jitem(array,i);
            if ( jobj(item,"error") == 0 )
            {
                if ( (hexstr= jstr(item,"data")) != 0 )
                {
                    if ( (hexdata= get_dataptr(0,&allocptr,&hexlen,hexspace,sizeof(hexspace),hexstr)) != 0 )
                    {
                        memset(&R,0,sizeof(R));
                        basilisk_rwDEXquote(0,hexdata,&R);
                        //printf("[%d].(%s)\n",i,jprint(basilisk_requestjson(&R),1));
                    }
                } else basilisk_parsejson(&R,item);
                if ( nonz != 0 )
                {
                    if ( refR.requestid == R.requestid )
                        list[m++] = R;
                    else
                    {
                        if ( (metric= basilisk_request_listprocess(myinfo,&tmpR,list,m)) > hwm )
                        {
                            *issueR = tmpR;
                            hwm = metric;
                            refR = tmpR;
                            printf("SET HWM\n");
                        }
                        m = 0;
                    }
                }
                nonz++;
                if ( m < sizeof(list)/sizeof(*list) )
                {
                    //basilisk_parsejson(&list[m++],item);
                    list[m++] = R;
                }
            }
        }
        //printf("process_results n.%d m.%d nonz.%d\n",n,m,nonz);
        if ( m > 0 && m < sizeof(list)/sizeof(*list) )
            if ( (metric= basilisk_request_listprocess(myinfo,&tmpR,list,m)) > hwm )
            {
                *issueR = tmpR, hwm = metric;
                //printf("set hwm\n");
                //for (i=0; i<sizeof(*issueR); i++)
                //    printf("%02x",((uint8_t *)issueR)[i]);
                //printf("\n");
            }
    }
    return(hwm);
}

