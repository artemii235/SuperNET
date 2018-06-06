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
//  main.c
//  stats
//
//  Copyright © 2017 SuperNET. All rights reserved.
//



#include <stdio.h>
#include <stdint.h>
#include "../../crypto777/OS_portable.h"
#define IGUANA_MAXRPCTHREADS 1

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define STATS_DESTDIR "/var/www/html"
#define STATS_DEST "/var/www/html/DEXstats.json"
#include "DEXstats.h"
char *stats_JSON(void *ctx,int32_t fastflag,char *myipaddr,int32_t mypubsock,cJSON *argjson,char *remoteaddr,uint16_t port);
void LP_queuecommand(char **retstrp,char *buf,int32_t responsesock,int32_t stats_JSONonly,uint32_t queueid);
extern uint32_t DOCKERFLAG;
extern char LP_myipaddr[];

char *stats_validmethods[] =
{
    "psock", "ticker", "balances", "getprice", "notify", "getpeers",  // from issue_  "uitem", "listunspent",
    "orderbook", "statsdisp", "fundvalue", "help", "getcoins", "pricearray", "balance", "tradesarray"
};

int32_t LP_valid_remotemethod(cJSON *argjson)
{
    char *method; int32_t i;
    if ( DOCKERFLAG != 0 )
        return(1);
    if ( (method= jstr(argjson,"method")) != 0 )
    {
        for (i=0; i<sizeof(stats_validmethods)/sizeof(*stats_validmethods); i++)
            if ( strcmp(method,stats_validmethods[i]) == 0 )
                return(1);
        printf("got invalid method.%s remotely\n",method);
    }
    return(-1);
}

#ifndef _WIN32
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0x4000	// Do not generate SIGPIPE
#endif
#else
#define MSG_NOSIGNAL	0
#endif

#define GLOBAL_HELPDIR "/root/SuperNET/iguana/help"

char CURRENCIES[][8] = { "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD", // major currencies
    "CNY", "RUB", "MXN", "BRL", "INR", "HKD", "TRY", "ZAR", "PLN", "NOK", "SEK", "DKK", "CZK", "HUF", "ILS", "KRW", "MYR", "PHP", "RON", "SGD", "THB", "BGN", "IDR", "HRK", // end of currencies
};

char ASSETCHAINS_SYMBOL[65] = { "KV" };

struct komodo_state
{
    bits256 NOTARIZED_HASH,NOTARIZED_DESTTXID;
    int32_t SAVEDHEIGHT,CURRENT_HEIGHT,NOTARIZED_HEIGHT;
    uint32_t SAVEDTIMESTAMP;
    uint64_t deposited,issued,withdrawn,approved,redeemed,shorted;
    struct notarized_checkpoint *NPOINTS; int32_t NUM_NPOINTS;
    struct komodo_event **Komodo_events; int32_t Komodo_numevents;
    uint32_t RTbufs[64][3]; uint64_t RTmask;
};

struct komodo_state KOMODO_STATE[2];

int32_t iguana_socket(int32_t bindflag,char *hostname,uint16_t port)
{
    int32_t opt,sock,result; char ipaddr[64],checkipaddr[64]; struct timeval timeout;
    struct sockaddr_in saddr; socklen_t addrlen,slen;
    addrlen = sizeof(saddr);
    struct hostent *hostent;
    
    /**
     * gethostbyname() is deprecated and cause crash on x64 windows
     * the solution is to implement similar functionality by using getaddrinfo()
     * it is standard posix function and is correctly supported in win32/win64/linux
     * @author - fadedreamz@gmail.com
     */

#if defined(_M_X64)
    struct addrinfo *addrresult = NULL;
    struct addrinfo *returnptr = NULL;
    struct addrinfo hints;
    struct sockaddr_in * sockaddr_ipv4;
    int retVal;
    int found = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
#endif

    if ( parse_ipaddr(ipaddr,hostname) != 0 )
        port = parse_ipaddr(ipaddr,hostname);
    
#if defined(_M_X64)
    retVal = getaddrinfo(ipaddr, NULL, &hints, &addrresult);
    for (returnptr = addrresult; returnptr != NULL && found == 0; returnptr = returnptr->ai_next) {
        switch (returnptr->ai_family) {
            case AF_INET:
                sockaddr_ipv4 = (struct sockaddr_in *) returnptr->ai_addr;
                // we want to break from the loop after founding the first ipv4 address
                found = 1;
                break;
        }
    }
    
    // if we iterate through the loop and didn't find anything,
    // that means we failed in the dns lookup
    if (found == 0) {
        printf("getaddrinfo(%s) returned error\n", hostname);
        freeaddrinfo(addrresult);
        return(-1);
    }
#else
    hostent = gethostbyname(ipaddr);
    if ( hostent == NULL )
    {
        printf("gethostbyname(%s) returned error: %d port.%d ipaddr.(%s)\n",hostname,errno,port,ipaddr);
        return(-1);
    }
#endif
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    //#ifdef _WIN32
    //   saddr.sin_addr.s_addr = (uint32_t)calc_ipbits("127.0.0.1");
    //#else
    
#if defined(_M_X64)
    saddr.sin_addr.s_addr = sockaddr_ipv4->sin_addr.s_addr;
    // graceful cleanup
    sockaddr_ipv4 = NULL;
    freeaddrinfo(addrresult);
#else
    memcpy(&saddr.sin_addr.s_addr,hostent->h_addr_list[0],hostent->h_length);
#endif
    expand_ipbits(checkipaddr,saddr.sin_addr.s_addr);
    if ( strcmp(ipaddr,checkipaddr) != 0 )
        printf("bindflag.%d iguana_socket mismatch (%s) -> (%s)?\n",bindflag,checkipaddr,ipaddr);
    //#endif
    if ( (sock= socket(AF_INET,SOCK_STREAM,0)) < 0 )
    {
        if ( errno != ETIMEDOUT )
            printf("socket() failed: %s errno.%d", strerror(errno),errno);
        return(-1);
    }
    opt = 1;
    slen = sizeof(opt);
    //printf("set keepalive.%d\n",setsockopt(sock,SOL_SOCKET,SO_KEEPALIVE,(void *)&opt,slen));
#ifndef _WIN32
    if ( 1 )//&& bindflag != 0 )
    {
        opt = 0;
        getsockopt(sock,SOL_SOCKET,SO_KEEPALIVE,(void *)&opt,&slen);
        opt = 1;
        //printf("keepalive.%d\n",opt);
    }
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(void *)&opt,sizeof(opt));
#ifdef __APPLE__
    setsockopt(sock,SOL_SOCKET,SO_NOSIGPIPE,&opt,sizeof(opt));
#endif
#endif
    if ( bindflag == 0 )
    {
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(void *)&timeout,sizeof(timeout));
        result = connect(sock,(struct sockaddr *)&saddr,addrlen);
        if ( result != 0 )
        {
            if ( errno != ECONNRESET && errno != ENOTCONN && errno != ECONNREFUSED && errno != ETIMEDOUT && errno != EHOSTUNREACH )
            {
                //printf("%s(%s) port.%d failed: %s sock.%d. errno.%d\n",bindflag!=0?"bind":"connect",hostname,port,strerror(errno),sock,errno);
            }
            if ( sock >= 0 )
                closesocket(sock);
            return(-1);
        }
        timeout.tv_sec = 10000000;
        timeout.tv_usec = 0;
        setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(void *)&timeout,sizeof(timeout));
    }
    else
    {
        while ( (result= bind(sock,(struct sockaddr*)&saddr,addrlen)) != 0 )
        {
            if ( errno == EADDRINUSE )
            {
                sleep(1);
                printf("ERROR BINDING PORT.%d. this is normal tcp timeout, unless another process is using port\n",port);
                sleep(3);
                printf("%s(%s) port.%d try again: %s sock.%d. errno.%d\n",bindflag!=0?"bind":"connect",hostname,port,strerror(errno),sock,errno);
                if ( bindflag == 1 )
                {
                    closesocket(sock);
                    return(-1);
                }
                sleep(13);
                //continue;
            }
            if ( errno != ECONNRESET && errno != ENOTCONN && errno != ECONNREFUSED && errno != ETIMEDOUT && errno != EHOSTUNREACH )
            {
                printf("%s(%s) port.%d failed: %s sock.%d. errno.%d\n",bindflag!=0?"bind":"connect",hostname,port,strerror(errno),sock,errno);
                closesocket(sock);
                return(-1);
            }
        }
        if ( listen(sock,512) != 0 )
        {
            printf("listen(%s) port.%d failed: %s sock.%d. errno.%d\n",hostname,port,strerror(errno),sock,errno);
            if ( sock >= 0 )
                closesocket(sock);
            return(-1);
        }
    }
#ifdef __APPLE__
    //timeout.tv_sec = 0;
    //timeout.tv_usec = 30000;
    //setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(void *)&timeout,sizeof(timeout));
    timeout.tv_sec = 0;
    timeout.tv_usec = 10000;
    setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,(void *)&timeout,sizeof(timeout));
#endif
    return(sock);
}

int32_t Supernet_lineparse(char *key,int32_t keymax,char *value,int32_t valuemax,char *src)
{
    int32_t a,b,c,n = 0; //char *origkey=key,*origvalue=value;
    key[0] = value[0] = 0;
    while ( (c= src[n]) == ' ' || c == '\t' || c == '\n' || c == '\t' )
        n++;
    while ( (c= src[n]) != ':' && c != 0 )
    {
        *key++ = c;
        //printf("(%c) ",c);
        if ( ++n >= keymax-1 )
        {
            *key = 0;
            printf("lineparse overflow key.(%s)\n",src);
            return(-1);
        }
    }
    *key = 0;
    //printf("-> key.(%s)\n",origkey);
    if ( src[n] != ':' )
        return(n);
    n++;
    while ( (c= src[n]) == ' ' || c == '\t' )
        n++;
    while ( (c= src[n]) != 0 && c != '\r' && c != '\n' )
    {
        if ( c == '%' && (a= src[n+1]) != 0 && (b= src[n+2]) != 0 )
            c = ((unhex(a) << 4) | unhex(b)), n += 2;
        *value++ = c;
        n++;
        if ( n >= valuemax-1 )
        {
            *value = 0;
            printf("lineparse overflow.(%s)\n",src);
            return(-1);
        }
    }
    *value = 0;
    if ( src[n] != 0 )
    {
        n++;
        while ( (c= src[n]) == '\r' || c == '\n' )
            n++;
    }
    //printf("key.(%s) value.(%s)\n",origkey,origvalue);
    return(n);
}

cJSON *SuperNET_urlconv(char *value,int32_t bufsize,char *urlstr)
{
    int32_t i,n,totallen,datalen,len = 0; cJSON *json,*array; char key[8192],*data;
    json = cJSON_CreateObject();
    array = cJSON_CreateArray();
    totallen = (int32_t)strlen(urlstr);
    while ( 1 )
    {
        for (i=len; urlstr[i]!=0; i++)
            if ( urlstr[i] == '\r' || urlstr[i] == '\n' )
                break;
        if ( i == len && (urlstr[len] == '\r' || urlstr[len] == '\n') )
        {
            len++;
            continue;
        }
        urlstr[i] = 0;
        //printf("URLSTR[%d]=%s\n",i,&urlstr[len]);
        if ( (n= Supernet_lineparse(key,sizeof(key),value,bufsize,&urlstr[len])) > 0 )
        {
            if ( value[0] != 0 )
                jaddstr(json,key,value);
            else jaddistr(array,key);
            len += (n + 1);
            if ( (strcmp(key,"Content-Length") == 0 || strcmp(key,"content-length") == 0) && (datalen= atoi(value)) > 0 )
            {
                data = &urlstr[totallen - datalen];
                data[-1] = 0;
                //printf("post.(%s) (%c)\n",data,data[0]);
                jaddstr(json,"POST",data);
            }
        } else break;
    }
    jadd(json,"lines",array);
    //printf("urlconv.(%s)\n",jprint(json,0));
    return(json);
}

extern void *bitcoin_ctx();
extern int32_t IPC_ENDPOINT;
extern portable_mutex_t LP_gcmutex,LP_commandmutex;
extern struct rpcrequest_info *LP_garbage_collector;
uint16_t RPC_port;
static int32_t spawned,maxspawned;

char *stats_rpcparse(char *retbuf,int32_t bufsize,int32_t *jsonflagp,int32_t *postflagp,char *urlstr,char *remoteaddr,char *filetype,uint16_t port)
{
    static void *ctx;
    cJSON *tokens,*argjson,*origargjson,*tmpjson=0,*json = 0; long filesize; char symbol[64],buf[4096],*userpass=0,urlmethod[16],*data,url[8192],furl[8192],*retstr=0,*filestr,*token = 0; int32_t i,j,n,num=0; uint32_t queueid;
    if ( ctx == 0 )
        ctx = bitcoin_ctx();
    for (i=0; i<sizeof(urlmethod)-1&&urlstr[i]!=0&&urlstr[i]!=' '; i++)
        urlmethod[i] = urlstr[i];
    urlmethod[i++] = 0;
    n = i;
    //printf("URLMETHOD.(%s)\n",urlmethod);
    *postflagp = (strcmp(urlmethod,"POST") == 0);
    //printf("POST.%d rpcparse.(%s)\n",*postflagp,urlstr);
    for (i=0; i<sizeof(url)-1&&urlstr[n+i]!=0&&urlstr[n+i]!=' '; i++)
        url[i] = urlstr[n+i];
    url[i++] = 0;
    n += i;
    j = i = 0;
    filetype[0] = 0;
    //printf("url.(%s) method.(%s)\n",&url[i],urlmethod);
    snprintf(furl,sizeof(furl),"%s",url+1);
    if ( strcmp(&url[i],"/") == 0 && strcmp(urlmethod,"GET") == 0 )
    {
        *jsonflagp = 1;
        if ( (filestr= OS_filestr(&filesize,"index7779.html")) == 0 )
            return(clonestr("{\"error\":\"cant find index7779\"}"));
        else return(filestr);
    }
    /*else if ( (filestr= OS_filestr(&filesize,furl)) != 0 ) allows arbitrary file access!
    {
        *jsonflagp = 1;
        for (i=(int32_t)strlen(url)-1; i>0; i--)
            if ( url[i] == '.' || url[i] == '/' )
                break;
        if ( url[i] == '.' )
            strcpy(filetype,url+i+1);
        //printf("return filetype.(%s) size.%ld\n",filetype,filesize);
        return(filestr);
    }*/
    if ( strncmp(&url[i],"/api",strlen("/api")) == 0 )
    {
        *jsonflagp = 1;
        i += strlen("/api");
    } else *jsonflagp = 0;
    if ( strcmp(url,"/favicon.ico") == 0 )
    {
        *jsonflagp = 1;
        return(0);
    }
    if ( url[i] != '/' )
        token = &url[i];
    n = i;
    tokens = cJSON_CreateArray();
    for (; url[i]!=0; i++)
    {
        //printf("i.%d (%c)\n",i,url[i]);
        if ( url[i] == '/' )
        {
            url[i] = 0;
            if ( token != 0 )
            {
                //printf("TOKEN.(%s) i.%d\n",token,i);
                jaddistr(tokens,token);
                num++;
            }
            token = &url[i+1];
            i++;
            //printf("new token.(%s) i.%d\n",token,i+1);
            continue;
        }
    }
    if ( token != 0 )
    {
        //printf("add token.(%s)\n",token);
        jaddistr(tokens,token);
        num++;
    }
    argjson = cJSON_CreateObject();
    if ( num > 0 )
        jaddstr(argjson,"agent",jstri(tokens,0));
    if ( num > 1 )
        jaddstr(argjson,"method",jstri(tokens,1));
    if ( (json= SuperNET_urlconv(retbuf,bufsize,urlstr+n)) != 0 )
    {
        jadd(json,"tokens",tokens);
        jaddstr(json,"urlmethod",urlmethod);
        if ( (data= jstr(json,"POST")) != 0 )
        {
            free_json(argjson);
            argjson = cJSON_Parse(data);
            //printf("data.(%s)\n",data);
        }
        if ( argjson != 0 )
        {
            userpass = jstr(argjson,"userpass");
            //printf("userpass.(%s)\n",userpass);
            if ( (n= cJSON_GetArraySize(tokens)) > 0 )
            {
                if ( n > 1 )
                {
                    if ( jstri(tokens,1) != 0 )
                    {
                        char *key,*value;
                        strcpy(buf,jstri(tokens,1));
                        key = value = 0;
                        i = 0;
                        for (; buf[i]!=0; i++)
                        {
                            if ( buf[i] == '?' )
                            {
                                buf[i] = 0;
                                jdelete(argjson,"method");
                                jaddstr(argjson,"method",buf);
                                i++;
                                key = &buf[i];
                                break;
                            }
                        }
                        while ( buf[i] != 0 )
                        {
                            //printf("iter.[%s]\n",&buf[i]);
                            if ( buf[i] != 0 && key != 0 )
                            {
                                for (; buf[i]!=0; i++)
                                {
                                    if ( buf[i] == '=' )
                                    {
                                        buf[i] = 0;
                                        i++;
                                        //printf("got key.(%s)\n",key);
                                        value = &buf[i];
                                        break;
                                    }
                                }
                                if ( buf[i] != 0 && value != 0 )
                                {
                                    for (; buf[i]!=0; i++)
                                    {
                                        if ( buf[i] == '&' )
                                        {
                                            buf[i] = 0;
                                            jaddstr(argjson,key,value);
                                            i++;
                                            //printf("got value.(%s)\n",value);
                                            value = 0;
                                            key = &buf[i];
                                            break;
                                        }
                                        else if ( buf[i] == '+' )
                                            buf[i] = ' ';
                                    }
                                }
                            }
                        }
                        if ( key != 0 && value != 0 )
                            jaddstr(argjson,key,value);
                    }
                    else
                    {
                        //jdelete(argjson,"method");
                        //jaddstr(argjson,"method",buf);
                    }
                }
                for (i=2; i<n; i++)
                {
                    if ( i == n-1 )
                        jaddstr(argjson,"data",jstri(tokens,i));
                    else
                    {
                        if ( strcmp(jstri(tokens,i),"coin") == 0 && strlen(jstri(tokens,i+1)) < sizeof(symbol)-1 )
                        {
                            strcpy(symbol,jstri(tokens,i+1));
                            touppercase(symbol);
                            jaddstr(argjson,jstri(tokens,i),symbol);
                        } else jaddstr(argjson,jstri(tokens,i),jstri(tokens,i+1));
                        i++;
                    }
                }
            }
            if ( is_cJSON_Array(argjson) != 0 && (n= cJSON_GetArraySize(argjson)) > 0 )
            {
                cJSON *retitem,*retarray = cJSON_CreateArray();
                origargjson = argjson;
                symbol[0] = 0;
                for (i=0; i<n; i++) // array cmd path doesnt support event streaming
                {
                    argjson = jitem(origargjson,i);
                    if ( userpass != 0 && jstr(argjson,"userpass") == 0 )
                        jaddstr(argjson,"userpass",userpass);
                    //printf("after urlconv.(%s) argjson.(%s)\n",jprint(json,0),jprint(argjson,0));
#ifdef FROM_MARKETMAKER
                    if ( strcmp(remoteaddr,"127.0.0.1") == 0 || LP_valid_remotemethod(argjson) > 0 )
                    {
                        //buf = jprint(argjson,0);
                        //LP_queuecommand(&retstr,buf,-1,1);
                        //free(buf);
                        //while ( retstr == 0 )
                        //    usleep(10000);
                        if ( (retstr= stats_JSON(ctx,0,"127.0.0.1",-1,argjson,remoteaddr,port)) != 0 )
                        {
                            if ( (retitem= cJSON_Parse(retstr)) != 0 )
                                jaddi(retarray,retitem);
                            free(retstr);
                        }
                    } else retstr = clonestr("{\"error\":\"invalid remote method\"}");
#else
                    //buf = jprint(argjson,0);
                    //LP_queuecommand(&retstr,buf,-1,1);
                    //free(buf);
                    //while ( retstr == 0 )
                    //    usleep(10000);
                    if ( (retstr= stats_JSON(ctx,0,LP_myipaddr,-1,argjson,remoteaddr,port)) != 0 )
                    {
                        if ( (retitem= cJSON_Parse(retstr)) != 0 )
                            jaddi(retarray,retitem);
                        free(retstr);
                    }
#endif
                    //printf("(%s) {%s} -> (%s) postflag.%d (%s)\n",urlstr,jprint(argjson,0),jprint(json,0),*postflagp,retstr);
                }
                free_json(origargjson);
                retstr = jprint(retarray,1);
            }
            else
            {
                cJSON *arg; char *buf,*method; int32_t fastflag;
                if ( jstr(argjson,"agent") != 0 && strcmp(jstr(argjson,"agent"),"bitcoinrpc") != 0 && jobj(argjson,"params") != 0 )
                {
                    arg = jobj(argjson,"params");
                    if ( is_cJSON_Array(arg) != 0 && cJSON_GetArraySize(arg) == 1 )
                        arg = jitem(arg,0);
                } else arg = argjson;
                //printf("ARGJSON.(%s)\n",jprint(arg,0));
                if ( userpass != 0 && jstr(arg,"userpass") == 0 )
                    jaddstr(arg,"userpass",userpass);
                if ( (fastflag= jint(arg,"fast")) == 0 )
                {
                    if ( (method= jstr(arg,"method")) != 0 && (strcmp(method,"orderbook") == 0 || strcmp(method,"portfolio") == 0) )
                        fastflag = 1*0;
                }
                if ( fastflag == 0 )
                    portable_mutex_lock(&LP_commandmutex);
#ifdef FROM_MARKETMAKER
                if ( strcmp(remoteaddr,"127.0.0.1") == 0 || LP_valid_remotemethod(arg) > 0 )
                {
                    if ( IPC_ENDPOINT >= 0 && (queueid= juint(arg,"queueid")) > 0 )
                    {
                        buf = jprint(arg,0);
                        //printf("Q command\n");
                        LP_queuecommand(&retstr,buf,IPC_ENDPOINT,1,queueid);
                        free(buf);
                        retstr = clonestr("{\"result\":\"success\",\"status\":\"queued\"}");
                    } else retstr = stats_JSON(ctx,jint(arg,"fast"),"127.0.0.1",-1,arg,remoteaddr,port);
                } else retstr = clonestr("{\"error\":\"invalid remote method\"}");
#else
                if ( IPC_ENDPOINT >= 0 && (queueid= juint(arg,"queueid")) > 0 )
                {
                    buf = jprint(arg,0);
                    LP_queuecommand(&retstr,buf,IPC_ENDPOINT,1,queueid);
                    free(buf);
                } else retstr = stats_JSON(ctx,jint(arg,"fast"),LP_myipaddr,-1,arg,remoteaddr,port);
#endif
                if ( fastflag == 0 )
                    portable_mutex_unlock(&LP_commandmutex);
            }
            free_json(argjson);
        }
        free_json(json);
        if ( tmpjson != 0 )
            free(tmpjson);
//printf("stats_JSON rpc return.(%s)\n",retstr);
        return(retstr);
    }
    free_json(argjson);
    if ( tmpjson != 0 )
        free_json(tmpjson);
    if ( tokens != 0 )
        free_json(tokens);
    *jsonflagp = 1;
    return(clonestr("{\"error\":\"couldnt process packet\"}"));
}

int32_t iguana_getcontentlen(char *buf,int32_t recvlen)
{
    char *str,*clenstr = "Content-Length: ",*clenstr2 = "content-length: "; int32_t len = -1;
    if ( (str= strstr(buf,clenstr)) != 0 || (str= strstr(buf,clenstr2)) != 0 )
    {
        //printf("strstr.(%s)\n",str);
        str += strlen(clenstr);
        len = atoi(str);
        //printf("len.%d\n",len);
    }
    return(len);
}

int32_t iguana_getheadersize(char *buf,int32_t recvlen)
{
    char *str,*delim = "\r\n\r\n";
    if ( (str= strstr(buf,delim)) != 0 )
        return((int32_t)(((long)str - (long)buf) + strlen(delim)));
    return(recvlen);
}

void LP_rpc_processreq(void *_ptr)
{
    char filetype[128],content_type[128];
    int32_t recvlen,flag,postflag=0,contentlen,remains,sock,numsent,jsonflag=0,hdrsize,len;
    char helpname[512],remoteaddr[64],*buf,*retstr,space[8192],space2[32786],*jsonbuf; struct rpcrequest_info *req = _ptr;
    uint32_t ipbits,i,size = IGUANA_MAXPACKETSIZE + 512;
    ipbits = req->ipbits;;
    expand_ipbits(remoteaddr,ipbits);
    sock = req->sock;
    recvlen = flag = 0;
    retstr = 0;
    jsonbuf = calloc(1,size);
    remains = size-1;
    buf = jsonbuf;
    if ( spawned < 0 )
        spawned = 0;
    spawned++;
    if ( spawned > maxspawned )
    {
        printf("max rpc threads spawned and alive %d <- %d\n",maxspawned,spawned);
        maxspawned = spawned;
    }
    while ( remains > 0 )
    {
        //printf("flag.%d remains.%d recvlen.%d\n",flag,remains,recvlen);
        if ( (len= (int32_t)recv(sock,buf,remains,0)) < 0 )
        {
            if ( errno == EAGAIN )
            {
                printf("EAGAIN for len %d, remains.%d\n",len,remains);
                usleep(10000);
            }
            //printf("errno.%d len.%d remains.%d\n",errno,len,remains);
            break;
        }
        else
        {
            //printf("received len.%d\n%s\n",len,buf);
            if ( len > 0 )
            {
                buf[len] = 0;
                if ( recvlen == 0 )
                {
                    if ( (contentlen= iguana_getcontentlen(buf,recvlen)) > 0 )
                    {
                        hdrsize = iguana_getheadersize(buf,recvlen);
                        if ( hdrsize > 0 )
                        {
                            if ( len < (hdrsize + contentlen) )
                            {
                                remains = (hdrsize + contentlen) - len;
                                buf = &buf[len];
                                flag = 1;
                                //printf("got.(%s) %d remains.%d of len.%d contentlen.%d hdrsize.%d remains.%d\n",buf,recvlen,remains,len,contentlen,hdrsize,(hdrsize+contentlen)-len);
                                continue;
                            }
                        }
                    }
                }
                recvlen += len;
                remains -= len;
                buf = &buf[len];
                if ( flag == 0 || remains <= 0 )
                    break;
            }
            else
            {
                usleep(10000);
                printf("got.(%s) %d remains.%d of total.%d\n",jsonbuf,recvlen,remains,len);
                if ( flag == 0 )
                    break;
            }
        }
    }
    content_type[0] = 0;
    if ( recvlen > 0 )
    {
        jsonflag = postflag = 0;
        retstr = stats_rpcparse(space,size,&jsonflag,&postflag,jsonbuf,remoteaddr,filetype,req->port);
        if ( filetype[0] != 0 )
        {
            static cJSON *mimejson; char *tmp,*typestr=0; long tmpsize;
            sprintf(helpname,"%s/mime.json",GLOBAL_HELPDIR);
            if ( (tmp= OS_filestr(&tmpsize,helpname)) != 0 )
            {
                mimejson = cJSON_Parse(tmp);
                free(tmp);
            }
            if ( mimejson != 0 )
            {
                if ( (typestr= jstr(mimejson,filetype)) != 0 )
                    sprintf(content_type,"Content-Type: %s\r\n",typestr);
            } else printf("parse error.(%s)\n",tmp);
            //printf("filetype.(%s) json.%p type.%p tmp.%p [%s]\n",filetype,mimejson,typestr,tmp,content_type);
        }
    }
    if ( retstr != 0 )
    {
        char *response,hdrs[1024];
        //printf("RETURN.(%s) jsonflag.%d postflag.%d\n",retstr,jsonflag,postflag);
        if ( jsonflag != 0 || postflag != 0 )
        {
            if ( strlen(retstr)+1024+1+1 < sizeof(space2) )
                response = space2;
            else
            {
                response = malloc(strlen(retstr)+1024+1+1);
                //printf("alloc response.%p\n",response);
            }
            sprintf(hdrs,"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Methods: GET, POST\r\nCache-Control :  no-cache, no-store, must-revalidate\r\n%sContent-Length : %8d\r\n\r\n",content_type,(int32_t)strlen(retstr)+1);
            response[0] = '\0';
            strcat(response,hdrs);
            strcat(response,retstr);
            strcat(response,"\n");
            if ( retstr != space )
            {
                //printf("free retstr0.%p\n",retstr);
                free(retstr);
            }
            retstr = response;
            //printf("RET.(%s)\n",retstr);
        }
        remains = (int32_t)strlen(retstr);
        i = 0;
        while ( remains > 0 )
        {
            if ( (numsent= (int32_t)send(sock,&retstr[i],remains,MSG_NOSIGNAL)) < 0 )
            {
                if ( errno != EAGAIN && errno != EWOULDBLOCK )
                {
                    //printf("%s: %s numsent.%d vs remains.%d len.%d errno.%d (%s) usock.%d\n",retstr,ipaddr,numsent,remains,recvlen,errno,strerror(errno),sock);
                    break;
                }
            }
            else if ( remains > 0 )
            {
                remains -= numsent;
                i += numsent;
                if ( remains > 0 )
                    printf("iguana sent.%d remains.%d of recvlen.%d (%s)\n",numsent,remains,recvlen,jsonbuf);
            }
        }
        if ( retstr != space && retstr != space2 )
        {
            //printf("free retstr.%p\n",retstr);
            free(retstr);
        }
    }
    //free(space);
    //printf("free jsonbuf.%p\n",jsonbuf);
    free(jsonbuf);
    closesocket(sock);
    if ( 1 )
    {
        portable_mutex_lock(&LP_gcmutex);
        DL_APPEND(LP_garbage_collector,req);
        portable_mutex_unlock(&LP_gcmutex);
    }
    else
    {
        //printf("free req.%p\n",req);
        free(req);
    }
    if ( spawned > 0 )
        spawned--;
}

extern int32_t IAMLP,LP_STOP_RECEIVED;
//int32_t LP_bindsock_reset,LP_bindsock = -1;

void stats_rpcloop(void *args)
{
    uint16_t port; int32_t retval,sock=-1,bindsock=-1; socklen_t clilen; struct sockaddr_in cli_addr; uint32_t ipbits,localhostbits; struct rpcrequest_info *req;
    if ( (port= *(uint16_t *)args) == 0 )
        port = 7779;
    printf("Start stats_rpcloop.%u\n",port);
    localhostbits = (uint32_t)calc_ipbits("127.0.0.1");
    //initial_bindsock_reset = LP_bindsock_reset;
    while ( LP_STOP_RECEIVED == 0 )//LP_bindsock_reset == initial_bindsock_reset )
    {
        //printf("LP_bindsock.%d\n",LP_bindsock);
        if ( bindsock < 0 )
        {
            while ( (bindsock= iguana_socket(1,"0.0.0.0",port)) < 0 )
                usleep(10000);
#ifndef _WIN32
            //fcntl(bindsock, F_SETFL, fcntl(bindsock, F_GETFL, 0) | O_NONBLOCK);
#endif
            //if ( counter++ < 1 )
                printf(">>>>>>>>>> DEX stats 127.0.0.1:%d bind sock.%d DEX stats API enabled at unixtime.%u <<<<<<<<<\n",port,bindsock,(uint32_t)time(NULL));
        }
        //printf("after sock.%d\n",sock);
        clilen = sizeof(cli_addr);
        sock = accept(bindsock,(struct sockaddr *)&cli_addr,&clilen);
        if ( sock < 0 )
        {
            printf("iguana_rpcloop ERROR on accept port.%u usock.%d errno %d %s\n",port,sock,errno,strerror(errno));
            closesocket(bindsock);
            bindsock = -1;
            continue;
        }
        memcpy(&ipbits,&cli_addr.sin_addr.s_addr,sizeof(ipbits));
//printf("port.%u got incoming from %x\n",port,ipbits);
        if ( DOCKERFLAG != 0 && (DOCKERFLAG == 1 || ipbits == DOCKERFLAG) )
            ipbits = localhostbits;
        if ( port == RPC_port && ipbits != localhostbits )
        {
            //printf("port.%u RPC_port.%u ipbits %x != %x\n",port,RPC_port,ipbits,localhostbits);
            closesocket(sock);
            continue;
        }
        req = calloc(1,sizeof(*req));
        //printf("LP_rpc_processreq req.%p\n",req);
        req->sock = sock;
        req->ipbits = ipbits;
        req->port = port;
        if ( 1 || spawned >= (IGUANA_MAXRPCTHREADS-1) )
            LP_rpc_processreq(req);
        // this might lead to "cant open file errors"
        else if ( (retval= OS_thread_create(&req->T,NULL,(void *)LP_rpc_processreq,req)) != 0 )
        {
            printf("error launching rpc handler on port %d, retval.%d\n",port,retval);
            LP_rpc_processreq(req);
       }
    }
    printf("i got killed\n");
}

#ifndef FROM_MARKETMAKER

portable_mutex_t LP_commandmutex;
uint16_t LP_RPCPORT = 7763;

void stats_kvjson(FILE *logfp,int32_t height,int32_t savedheight,uint32_t timestamp,char *key,cJSON *kvjson,bits256 pubkey,bits256 sigprev)
{
    struct tai T; int32_t seconds,datenum,n;
    datenum = OS_conv_unixtime(&T,&seconds,timestamp);
    jaddstr(kvjson,"key",key);
    jaddnum(kvjson,"datenum",datenum);
    jaddnum(kvjson,"hour",seconds/3600);
    jaddnum(kvjson,"seconds",seconds % 3600);
    jaddnum(kvjson,"height",height);
    //printf("(%s)\n",jprint(kvjson,0));
    if ( logfp != 0 )
    {
        stats_priceupdate(datenum,seconds/3600,seconds % 3600,timestamp,height,key,jstr(kvjson,"pubkey"),jarray(&n,kvjson,"trade"));
        fprintf(logfp,"%s\n",jprint(kvjson,0));
        fflush(logfp);
    }
}

void komodo_kvupdate(FILE *logfp,struct komodo_state *sp,int32_t ht,bits256 txid,int32_t vout,uint8_t *opretbuf,int32_t opretlen,uint64_t value)
{
    //static bits256 zeroes;
    uint32_t flags; bits256 pubkey,sig; cJSON *kvjson; char decodestr[10000]; int32_t i,hassig,coresize,haspubkey,height; uint16_t keylen,valuesize; uint8_t *key,*valueptr; // bits256 refpubkey; int32_t refvaluesize,kvheight; uint16_t newflag = 0; uint8_t keyvalue[10000];
    iguana_rwnum(0,&opretbuf[1],sizeof(keylen),&keylen);
    iguana_rwnum(0,&opretbuf[3],sizeof(valuesize),&valuesize);
    iguana_rwnum(0,&opretbuf[5],sizeof(height),&height);
    iguana_rwnum(0,&opretbuf[9],sizeof(flags),&flags);
    key = &opretbuf[13];
    if ( keylen+13 > opretlen )
    {
        printf("komodo_kvupdate: keylen.%d + 13 > opretlen.%d\n",keylen,opretlen);
        return;
    }
    valueptr = &key[keylen];
    coresize = (int32_t)(sizeof(flags)+sizeof(height)+sizeof(keylen)+sizeof(valuesize)+keylen+valuesize+1);
    if ( opretlen == coresize || opretlen == coresize+sizeof(bits256) || opretlen == coresize+2*sizeof(bits256) )
    {
        memset(&pubkey,0,sizeof(pubkey));
        memset(&sig,0,sizeof(sig));
        if ( (haspubkey= (opretlen >= coresize+sizeof(bits256))) != 0 )
        {
            for (i=0; i<32; i++)
                ((uint8_t *)&pubkey)[i] = opretbuf[coresize+i];
        }
        if ( (hassig= (opretlen == coresize+sizeof(bits256)*2)) != 0 )
        {
            for (i=0; i<32; i++)
                ((uint8_t *)&sig)[i] = opretbuf[coresize+sizeof(bits256)+i];
        }
        /*if ( (refvaluesize= komodo_kvsearch((bits256 *)&refpubkey,height,&flags,&kvheight,&keyvalue[keylen],key,keylen)) >= 0 )
        {
            if ( memcmp(&zeroes,&refpubkey,sizeof(refpubkey)) != 0 )
            {
                if ( komodo_kvsigverify(keyvalue,keylen+refvaluesize,refpubkey,sig) < 0 )
                {
                    //printf("komodo_kvsigverify error [%d]\n",coresize-13);
                    return;
                }
            }
        }*/
        //for (i=0; i<coresize; i++)
        //    printf("%c",(char)valueptr[i]);
        decode_hex((uint8_t *)decodestr,coresize/2,(char *)valueptr);
        if ( (kvjson= cJSON_Parse(decodestr)) != 0 )
        {
            //char str[65];
            //for (i=0; i<keylen; i++)
            //    putchar((char)key[i]);
            //printf(" -> ");
            //printf(" (%s) [%d] %s/v%d ht.%d height.%d\n",decodestr,valuesize,bits256_str(str,txid),vout,ht,height);
            key[keylen] = 0;
            stats_kvjson(logfp,ht,sp->SAVEDHEIGHT,sp->SAVEDTIMESTAMP,(char *)key,kvjson,pubkey,sig);
            free_json(kvjson);
        }
    }
}

void komodo_eventadd_opreturn(FILE *logfp,struct komodo_state *sp,char *symbol,int32_t height,bits256 txid,uint64_t value,uint16_t vout,uint8_t *opretbuf,uint16_t opretlen)
{
    if ( sp != 0 )
    {
        if ( opretbuf[0] == 'K' && opretlen != 40 )
        {
            komodo_kvupdate(logfp,sp,height,txid,vout,opretbuf,opretlen,value);
        }
    }
}

void komodo_setkmdheight(struct komodo_state *sp,int32_t kmdheight,uint32_t timestamp)
{
    if ( sp != 0 )
    {
        if ( kmdheight > sp->SAVEDHEIGHT )
        {
            sp->SAVEDHEIGHT = kmdheight;
            sp->SAVEDTIMESTAMP = timestamp;
            //printf("ht.%d t.%u\n",kmdheight,timestamp);
        }
        if ( kmdheight > sp->CURRENT_HEIGHT )
            sp->CURRENT_HEIGHT = kmdheight;
    }
}

void komodo_eventadd_kmdheight(struct komodo_state *sp,char *symbol,int32_t height,int32_t kmdheight,uint32_t timestamp)
{
    uint32_t buf[2];
    if ( kmdheight > 0 )
    {
        buf[0] = (uint32_t)kmdheight;
        buf[1] = timestamp;
        //komodo_eventadd(sp,height,symbol,KOMODO_EVENT_KMDHEIGHT,(uint8_t *)buf,sizeof(buf));
        if ( sp != 0 )
            komodo_setkmdheight(sp,kmdheight,timestamp);
    }
    else
    {
        kmdheight = -kmdheight;
        //komodo_eventadd(sp,height,symbol,KOMODO_EVENT_REWIND,(uint8_t *)&height,sizeof(height));
        //if ( sp != 0 )
        //    komodo_event_rewind(sp,symbol,height);
    }
}

void stats_pricefeed(struct komodo_state *sp,char *symbol,int32_t ht,uint32_t *pvals,int32_t numpvals)
{
    struct tai T; int32_t seconds,datenum; cJSON *argjson;
    if ( ht > 300000 && pvals[32] != 0 )
    {
        datenum = OS_conv_unixtime(&T,&seconds,sp->SAVEDTIMESTAMP);
        //printf("(%s)\n",jprint(kvjson,0));
        argjson = cJSON_CreateArray();
        jaddistr(argjson,"KMD");
        jaddinum(argjson,1);
        jaddistr(argjson,"BTC");
        jaddinum(argjson,dstr(pvals[32]) / 10000.);
        stats_priceupdate(datenum,seconds/3600,seconds % 3600,sp->SAVEDTIMESTAMP,sp->SAVEDHEIGHT,0,0,argjson);
        free_json(argjson);
    }
}

int32_t komodo_parsestatefile(FILE *logfp,struct komodo_state *sp,FILE *fp,char *symbol,int32_t iter)
{
    static int32_t errs;
    int32_t func,ht,notarized_height,num,matched=0; bits256 notarized_hash,notarized_desttxid; uint8_t pubkeys[64][33];
    if ( (func= fgetc(fp)) != EOF )
    {
        if ( ASSETCHAINS_SYMBOL[0] == 0 && strcmp(symbol,"KMD") == 0 )
            matched = 1;
        else matched = (strcmp(symbol,ASSETCHAINS_SYMBOL) == 0);
        if ( fread(&ht,1,sizeof(ht),fp) != sizeof(ht) )
            errs++;
        //printf("fpos.%ld func.(%d %c) ht.%d ",ftell(fp),func,func,ht);
        if ( func == 'P' )
        {
            if ( (num= fgetc(fp)) <= 64 )
            {
                if ( fread(pubkeys,33,num,fp) != num )
                    errs++;
                else
                {
                    //printf("updated %d pubkeys at %s ht.%d\n",num,symbol,ht);
                    //if ( (KOMODO_EXTERNAL_NOTARIES != 0 && matched != 0) || (strcmp(symbol,"KMD") == 0 && KOMODO_EXTERNAL_NOTARIES == 0) )
                     //   komodo_eventadd_pubkeys(sp,symbol,ht,num,pubkeys);
                }
            } else printf("illegal num.%d\n",num);
        }
        else if ( func == 'N' )
        {
            if ( fread(&notarized_height,1,sizeof(notarized_height),fp) != sizeof(notarized_height) )
                errs++;
            if ( fread(&notarized_hash,1,sizeof(notarized_hash),fp) != sizeof(notarized_hash) )
                errs++;
            if ( fread(&notarized_desttxid,1,sizeof(notarized_desttxid),fp) != sizeof(notarized_desttxid) )
                errs++;
            //if ( matched != 0 ) global independent states -> inside *sp
            //komodo_eventadd_notarized(sp,symbol,ht,dest,notarized_hash,notarized_desttxid,notarized_height);
        }
        else if ( func == 'U' ) // deprecated
        {
            uint8_t n,nid; bits256 hash; uint64_t mask;
            n = fgetc(fp);
            nid = fgetc(fp);
            //printf("U %d %d\n",n,nid);
            if ( fread(&mask,1,sizeof(mask),fp) != sizeof(mask) )
                errs++;
            if ( fread(&hash,1,sizeof(hash),fp) != sizeof(hash) )
                errs++;
            //if ( matched != 0 )
            //    komodo_eventadd_utxo(sp,symbol,ht,nid,hash,mask,n);
        }
        else if ( func == 'K' )
        {
            int32_t kheight;
            if ( fread(&kheight,1,sizeof(kheight),fp) != sizeof(kheight) )
                errs++;
            //if ( matched != 0 ) global independent states -> inside *sp
            //printf("%s.%d load[%s] ht.%d\n",ASSETCHAINS_SYMBOL,ht,symbol,kheight);
            komodo_eventadd_kmdheight(sp,symbol,ht,kheight,0);
        }
        else if ( func == 'T' )
        {
            int32_t kheight,ktimestamp;
            if ( fread(&kheight,1,sizeof(kheight),fp) != sizeof(kheight) )
                errs++;
            if ( fread(&ktimestamp,1,sizeof(ktimestamp),fp) != sizeof(ktimestamp) )
                errs++;
            //if ( matched != 0 ) global independent states -> inside *sp
            //printf("%s.%d load[%s] ht.%d t.%u\n",ASSETCHAINS_SYMBOL,ht,symbol,kheight,ktimestamp);
            komodo_eventadd_kmdheight(sp,symbol,ht,kheight,ktimestamp);
        }
        else if ( func == 'R' )
        {
            uint16_t olen,v; uint64_t ovalue; bits256 txid; uint8_t opret[16384];
            if ( fread(&txid,1,sizeof(txid),fp) != sizeof(txid) )
                errs++;
            if ( fread(&v,1,sizeof(v),fp) != sizeof(v) )
                errs++;
            if ( fread(&ovalue,1,sizeof(ovalue),fp) != sizeof(ovalue) )
                errs++;
            if ( fread(&olen,1,sizeof(olen),fp) != sizeof(olen) )
                errs++;
            if ( olen < sizeof(opret) )
            {
                if ( fread(opret,1,olen,fp) != olen )
                    errs++;
                if ( (0) && matched != 0 )
                {
                    int32_t i;  for (i=0; i<olen; i++)
                        printf("%02x",opret[i]);
                    printf(" %s.%d load[%s] opret[%c] len.%d %.8f\n",ASSETCHAINS_SYMBOL,ht,symbol,opret[0],olen,(double)ovalue/SATOSHIDEN);
                }
                komodo_eventadd_opreturn(logfp,sp,symbol,ht,txid,ovalue,v,opret,olen); // global shared state -> global PAX
            } else
            {
                int32_t i;
                for (i=0; i<olen; i++)
                    fgetc(fp);
                //printf("illegal olen.%u\n",olen);
            }
        }
        else if ( func == 'D' )
        {
            printf("unexpected function D[%d]\n",ht);
        }
        else if ( func == 'V' )
        {
            int32_t numpvals; uint32_t pvals[128];
            numpvals = fgetc(fp);
            if ( numpvals*sizeof(uint32_t) <= sizeof(pvals) && fread(pvals,sizeof(uint32_t),numpvals,fp) == numpvals )
            {
                if ( iter == 1 )
                {
                    //printf("load[%s] prices %d\n",symbol,ht);
                    stats_pricefeed(sp,symbol,ht,pvals,numpvals);
                }
                //if ( matched != 0 ) global shared state -> global PVALS
                 //printf("load pvals ht.%d numpvals.%d\n",ht,numpvals);
            } else printf("error loading pvals[%d]\n",numpvals);
        }
        else printf("[%s] %s illegal func.(%d %c)\n",ASSETCHAINS_SYMBOL,symbol,func,func);
        return(func);
    } else return(-1);
}

int32_t stats_stateupdate(FILE *logfp,char *destdir,char *statefname,int32_t maxseconds,char *komodofile)
{
    static long lastpos[2];
    char symbol[65],base[65]; int32_t iter,n; FILE *fp; uint32_t starttime; struct komodo_state *sp;
    starttime = (uint32_t)time(NULL);
    strcpy(base,"KV");
    strcpy(symbol,"KV");
    n = 0;
    for (iter=0; iter<2; iter++)
    {
        sp = &KOMODO_STATE[iter];
        if ( (fp= fopen(iter == 0 ? statefname : komodofile,"rb")) != 0 )
        {
            fseek(fp,0,SEEK_END);
            if ( ftell(fp) > lastpos[iter] )
            {
                fseek(fp,lastpos[iter],SEEK_SET);
                while ( komodo_parsestatefile(logfp,sp,fp,symbol,iter) >= 0 && n < 100000 )
                {
                    if ( n == 99999 )
                    {
                        if ( time(NULL) < starttime+maxseconds )
                            n = 0;
                        else break;
                    }
                    n++;
                }
                lastpos[iter] = ftell(fp);
            }
            fclose(fp);
        }
        strcpy(base,"KMD");
        strcpy(symbol,"KMD");
    }
    return(n);
}

char *stats_update(FILE *logfp,char *destdir,char *statefname,char *komodofname)
{
    int32_t i;
    cJSON *retjson = cJSON_CreateArray();
    for (i=0; i<100; i++)
        if ( stats_stateupdate(logfp,destdir,statefname,10,komodofname) <= 0 )
            break;
    return(jprint(retjson,1));
}

#ifndef FROM_PRIVATEBET
int main(int argc, const char * argv[])
{
    struct tai T; uint32_t timestamp; struct DEXstats_disp prices[365]; int32_t i,n,seconds,leftdatenum; FILE *fp,*logfp; char *filestr,*retstr,*statefname,logfname[512],komodofile[512]; uint16_t port = LP_RPCPORT;
    if ( argc < 2 )
    {
        statefname = "/root/.komodo/KV/komodostate";
        strcpy(komodofile,"/root/.komodo/komodostate");
    }
    else
    {
        statefname = (char *)argv[1];
        strcpy(komodofile,statefname);
        n = (int32_t)strlen(komodofile);
        for (i=0; i<=strlen("komodostate"); i++)
            komodofile[n-14+i] = komodofile[n-11+i];
        printf("komodofile.(%s)\n",komodofile);
    }
    sprintf(logfname,"%s/logfile",STATS_DESTDIR), OS_portable_path(logfname);
    logfp = fopen(logfname,"wb");
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)stats_rpcloop,(void *)&port) != 0 )
    {
        printf("error launching stats rpcloop for port.%u\n",port);
        exit(-1);
    }
    printf("DEX stats running\n");
    while ( LP_STOP_RECEIVED == 0 )
    {
        if ( (filestr= stats_update(logfp,STATS_DEST,statefname,komodofile)) != 0 )
        {
            timestamp = (uint32_t)time(NULL);
            leftdatenum = OS_conv_unixtime(&T,&seconds,timestamp - 30*24*3600);
            //printf("%u: leftdatenum.%d %s\n",timestamp,leftdatenum,filestr);
            memset(prices,0,sizeof(prices));
            if ( (retstr= stats_prices("KMD","BTC",prices,leftdatenum,30+1)) != 0 )
            {
                //printf("%s\n",retstr);
                free(retstr);
            }
            if ( (fp= fopen(STATS_DEST,"wb")) != 0 )
            {
                fwrite(filestr,1,strlen(filestr)+1,fp);
                fclose(fp);
            }
            free(filestr);
        }
        sleep(60);
    }
    return 0;
}
#endif
#endif
