
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
//  LP_forwarding.c
//  marketmaker
//

cJSON *LP_dereference(cJSON *argjson,char *excludemethod)
{
    cJSON *reqjson = 0;
    if ( jstr(argjson,"method2") != 0 && strncmp(excludemethod,jstr(argjson,"method2"),strlen(excludemethod)) != 0 )
    {
        reqjson = jduplicate(argjson);
        jdelete(reqjson,"method");
        jaddstr(reqjson,"method",jstr(argjson,"method2"));
    }
    return(reqjson);
}

/*
struct LP_forwardinfo
{
    UT_hash_handle hh;
    bits256 pubkey;
    char pushaddr[64];
    int32_t pushsock;
    uint32_t lasttime,hello;
} *LP_forwardinfos;
#define LP_KEEPALIVE (3600 * 24)

struct LP_forwardinfo *LP_forwardfind(bits256 pubkey)
{
    struct LP_forwardinfo *ptr=0;
    portable_mutex_lock(&LP_forwardmutex);
    HASH_FIND(hh,LP_forwardinfos,&pubkey,sizeof(pubkey),ptr);
    portable_mutex_unlock(&LP_forwardmutex);
    if ( ptr != 0 && ptr->lasttime > time(NULL)-LP_KEEPALIVE )
        return(ptr);
    else return(0);
}

char *LP_lookup(bits256 pubkey)
{
    if ( bits256_nonz(pubkey) == 0 )
        return(clonestr("{\"result\":\"illegal pubkey\"}"));
    if ( LP_forwardfind(pubkey) != 0 )
        return(clonestr("{\"result\":\"success\",\"forwarding\":1}"));
    else return(clonestr("{\"result\":\"notfound\"}"));
}

int32_t LP_hello(struct LP_forwardinfo *ptr)
{
    int32_t i,n=10; char msg[512]; struct nn_pollfd pfd;
    if ( bits256_cmp(ptr->pubkey,LP_mypubkey) != 0 )
    {
        pfd.fd = ptr->pushsock;
        pfd.events = NN_POLLOUT;
        for (i=0; i<n; i++)
        {
            if ( nn_poll(&pfd,1,1) > 0 )
            {
                sprintf(msg,"{\"method\":\"hello\",\"from\":\"%s\"}",LP_mypeer != 0 ? LP_mypeer->ipaddr : "");
                //printf("HELLO sent.%d bytes to %s on i.%d\n",LP_send(ptr->pushsock,msg,0),ptr->pushaddr,i);
                ptr->hello = (uint32_t)time(NULL);
                return(i);
            }
        }
        //printf("%d iterations on nn_poll and %s pushsock still not ready\n",i,ptr->pushaddr);
        return(-1);
    }
    return(0);
}

int32_t LP_hellos()
{
    struct LP_forwardinfo *ptr,*tmp; int32_t nonz = 0;
    HASH_ITER(hh,LP_forwardinfos,ptr,tmp)
    {
        if ( ptr->hello == 0 && LP_hello(ptr) >= 0 )
            nonz++;
    }
    return(nonz);
}

int32_t LP_pushsock_create(struct LP_forwardinfo *ptr,char *pushaddr)
{
    int32_t pushsock,timeout;
    if ( (pushsock= nn_socket(AF_SP,LP_COMMAND_SENDSOCK)) < 0 )
    {
        printf("LP_pushsock_create couldnt allocate socket for %s\n",pushaddr);
        return(-1);
    }
    else if ( nn_connect(pushsock,pushaddr) < 0 )
    {
        nn_close(pushsock);
        printf("LP_pushsock_create couldnt connect to %s\n",pushaddr);
        return(-1);
    }
    timeout = 1;
    nn_setsockopt(pushsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
    nn_setsockopt(pushsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
    if ( ptr != 0 )
        LP_hello(ptr);
    return(pushsock);
}

char *LP_register(bits256 pubkey,char *ipaddr,uint16_t port)
{
    struct LP_forwardinfo *ptr=0; int32_t pushsock; char pushaddr[64];
    if ( ipaddr == 0 || ipaddr[0] == 0 || is_ipaddr(ipaddr) == 0 || bits256_nonz(pubkey) == 0 )
        return(clonestr("{\"result\":\"illegal ipaddr or null pubkey\"}"));
    nanomsg_transportname(0,pushaddr,ipaddr,port);
    //char str[65]; printf("register.(%s) %s\n",pushaddr,bits256_str(str,pubkey));
    if ( (ptr= LP_forwardfind(pubkey)) != 0 )
    {
        ptr->lasttime = (uint32_t)time(NULL);
        if ( ptr->pushsock >= 0 )
        {
            if ( strcmp(pushaddr,ptr->pushaddr) != 0 )
            {
                nn_close(ptr->pushsock);
                if ( LP_psockmark(ptr->pushaddr) < 0 )
                {
                    //printf("cant mark (%s)\n",ptr->pushaddr);
                }
                char str[65]; printf("%u recreate pushsock for %s <- %s %s\n",(uint32_t)time(NULL),ptr->pushaddr,pushaddr,bits256_str(str,pubkey));
                strcpy(ptr->pushaddr,pushaddr);
                if ( (ptr->pushsock= LP_pushsock_create(ptr,pushaddr)) < 0 )
                    return(clonestr("{\"result\":\"success\",\"status\":\"couldnt recreate pushsock\",\"registered\":0}"));
            } //else printf("no need to create identical endpoint\n");
        }
        return(clonestr("{\"result\":\"success\",\"status\":\"already registered\",\"registered\":1}"));
    }
    else if ( (pushsock= LP_pushsock_create(0,pushaddr)) < 0 )
        return(clonestr("{\"result\":\"success\",\"status\":\"couldnt create pushsock\"}"));
    else
    {
        ptr = calloc(1,sizeof(*ptr));
        ptr->pubkey = pubkey;
        strcpy(ptr->pushaddr,pushaddr);
        ptr->pushsock = pushsock;
        ptr->lasttime = (uint32_t)time(NULL);
        portable_mutex_lock(&LP_forwardmutex);
        HASH_ADD_KEYPTR(hh,LP_forwardinfos,&ptr->pubkey,sizeof(ptr->pubkey),ptr);
        portable_mutex_unlock(&LP_forwardmutex);
        //char str[65]; printf("registered (%s) -> (%s) pushsock.%d\n",bits256_str(str,pubkey),pushaddr,ptr->pushsock);
        LP_hello(ptr);
        return(LP_lookup(pubkey));
    }
}

int32_t LP_forwarding_register(bits256 pubkey,char *publicaddr,uint16_t publicport,int32_t max)
{
    char *argstr,ipaddr[64]; cJSON *argjson; struct LP_peerinfo *peer,*tmp; int32_t j,n=0,arglen;
    if ( publicaddr == 0 || publicaddr[0] == 0 || bits256_nonz(pubkey) == 0 )
    {
        char str[65]; printf("LP_forwarding_register illegal publicaddr.(%s):%u or null pubkey (%s)\n",publicaddr,publicport,bits256_str(str,pubkey));
        return(0);
    }
    for (j=0; publicaddr[j]!=0; j++)
        if ( publicaddr[j] >= '0' && publicaddr[j] <= '9' )
            break;
    parse_ipaddr(ipaddr,publicaddr+j);
    argjson = cJSON_CreateObject();
    jaddstr(argjson,"agent","stats");
    jaddstr(argjson,"method","register");
    jaddbits256(argjson,"client",pubkey);
    jaddstr(argjson,"pushaddr",ipaddr);
    jaddnum(argjson,"pushport",publicport);
    argstr = jprint(argjson,1);
    arglen = (int32_t)strlen(argstr) + 1;
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        if ( strcmp(LP_myipaddr,peer->ipaddr) == 0 )
            continue;
        if ( peer->pushsock >= 0 )
        {
            if ( LP_send(peer->pushsock,argstr,arglen,0) != arglen )
            {
                if ( strncmp(peer->ipaddr,"5.9.253",strlen("5.9.253")) == 0 )
                    printf("error registering with %s:%u\n",peer->ipaddr,peer->port);
            }
            n++;
        }
        //printf("register.(%s) %s %u with (%s)\n",publicaddr,ipaddr,publicport,peer->ipaddr);
    }
    free(argstr);
    return(n);
}

char *LP_registerall(int32_t numnodes)
{
    int32_t i,maxnodes,n=0; cJSON *retjson;
    if ( numnodes < sizeof(default_LPnodes)/sizeof(*default_LPnodes) )
        numnodes = (int32_t)(sizeof(default_LPnodes)/sizeof(*default_LPnodes));
    if ( (maxnodes= LP_numpeers()) < numnodes )
        numnodes = maxnodes;
    for (i=0; i<numnodes; i++)
        if ( (n= LP_forwarding_register(LP_mypubkey,LP_publicaddr,LP_publicport,numnodes)) >= numnodes )
            break;
    retjson = cJSON_CreateObject();
    if ( i == numnodes )
        jaddstr(retjson,"error","not enough nodes");
    jaddnum(retjson,"numnodes",numnodes);
    jaddnum(retjson,"registered",n);
    jaddnum(retjson,"iters",i);
    return(jprint(retjson,1));
}

char *LP_forwardhex(void *ctx,int32_t pubsock,bits256 pubkey,char *hexstr)
{
    struct LP_forwardinfo *ptr=0; uint8_t *data; int32_t datalen=0,sentbytes=0; char *msg,*retstr=0; cJSON *retjson=0,*argjson=0,*reqjson=0;
    if ( hexstr == 0 || hexstr[0] == 0 )
        return(clonestr("{\"result\":\"nohex\"}"));
    datalen = (int32_t)strlen(hexstr) >> 1;
    data = malloc(datalen);
    decode_hex(data,datalen,hexstr);
    if ( (argjson= cJSON_Parse((char *)data)) != 0 )
        reqjson = LP_dereference(argjson,"forward");
    if ( bits256_nonz(pubkey) == 0 || bits256_cmp(pubkey,LP_mypubkey) == 0 )
    {
        if ( reqjson != 0 )
        {
            retstr = LP_command_process(ctx,LP_mypeer != 0 ? LP_mypeer->ipaddr : "127.0.0.1",LP_mypubsock,reqjson,0,0,LP_profitratio - 1.);
            //printf("LP_forwardhex.(%s) -> (%s)\n",jprint(reqjson,0),retstr!=0?retstr:"");
            if ( pubsock >= 0 )
            {
                msg = jprint(reqjson,0);
                LP_send(pubsock,msg,(int32_t)strlen(msg)+1,0);
            }
        } else printf("LP_forwardhex couldnt parse (%s)\n",(char *)data);
    }
    else if ( (ptr= LP_forwardfind(pubkey)) != 0 )
    {
        if ( ptr->pushsock >= 0 )
        {
            printf("%s forwardhex.(%s)\n",ptr->pushaddr,(char *)data);
            sentbytes = LP_send(ptr->pushsock,(char *)data,datalen,0);
        }
        retjson = cJSON_CreateObject();
        if ( sentbytes >= 0 )
        {
            jaddstr(retjson,"result","success");
            if ( sentbytes == datalen )
                jaddnum(retjson,"forwarded",sentbytes);
            else if ( sentbytes == 0 )
                jaddnum(retjson,"queued",sentbytes);
            else jaddnum(retjson,"mismatch",sentbytes);
            retstr = jprint(retjson,1);
        }
        else
        {
            jaddstr(retjson,"error","send error");
            jaddnum(retjson,"sentbytes",sentbytes);
            jaddnum(retjson,"datalen",datalen);
            jaddnum(retjson,"hello",ptr->hello);
            retstr = jprint(retjson,1);
        }
    }
    else
    {
        char str[65]; printf("couldnt find %s to forward to\n",bits256_str(str,pubkey));
        if ( pubsock >= 0 )
        {
            msg = jprint(reqjson,0);
            LP_send(pubsock,msg,(int32_t)strlen(msg)+1,1);
        }
        retstr = clonestr("{\"result\":\"notfound\"}");
    }
    free(data);
    if ( reqjson != 0 )
        free_json(reqjson);
    if ( argjson != 0 )
        free_json(argjson);
    return(retstr);
}

int32_t LP_forward(void *ctx,char *myipaddr,int32_t pubsock,bits256 pubkey,char *jsonstr,int32_t freeflag)
{
    struct LP_forwardinfo *ptr; struct LP_peerinfo *peer,*tmp; char *msg,*hexstr,*retstr; int32_t len,n=0,mlen; cJSON *reqjson,*argjson;
    if ( jsonstr == 0 || jsonstr[0] == 0 )
        return(-1);
    len = (int32_t)strlen(jsonstr) + 1;
    if ( bits256_nonz(pubkey) != 0 )
    {
        if ( bits256_cmp(pubkey,LP_mypubkey) == 0 )
        {
            printf("GOT FORWARDED.(%s)\n",myipaddr);
            if ( (argjson= cJSON_Parse(jsonstr)) != 0 )
            {
                if ( (retstr= LP_command_process(ctx,myipaddr,pubsock,argjson,0,0)) != 0 )
                    free(retstr);
                free_json(argjson);
            }
            if ( freeflag != 0 )
                free(jsonstr);
            return(1);
        }
        else if ( IAMLP != 0 && (ptr= LP_forwardfind(pubkey)) != 0 && ptr->pushsock >= 0 )
        {
            printf("GOT FORWARDED.(%s) -> pushsock.%d\n",jsonstr,ptr->pushsock);
            if ( LP_send(ptr->pushsock,jsonstr,len,freeflag) == len )
                return(1);
        }
    }
    hexstr = malloc(len*2 + 1);
    init_hexbytes_noT(hexstr,(uint8_t *)jsonstr,len);
    if ( freeflag != 0 )
        free(jsonstr);
    reqjson = cJSON_CreateObject();
    jaddstr(reqjson,"method","forwardhex");
    jaddstr(reqjson,"hex",hexstr);
    free(hexstr);
    msg = jprint(reqjson,1);
    mlen = (int32_t)strlen(msg) + 1;
    HASH_ITER(hh,LP_peerinfos,peer,tmp)
    {
        //printf("found LPnode.(%s) forward.(%s)\n",peer->ipaddr,msg);
        if ( LP_send(peer->pushsock,msg,mlen,0) == mlen )
            n++;
        if ( n >= 8 )//sizeof(default_LPnodes)/sizeof(*default_LPnodes) )
            break;
    }
    if ( msg != 0 )
        free(msg);
    if ( n == 0 )
        return(-1);
    else return(n-1);
}


char *LP_broadcasted(cJSON *argjson)
{
    printf("RECV BROADCAST.(%s)\n",jprint(argjson,0));
    return(clonestr("{\"result\":\"need to update broadcast messages\"}"));
}
*/

