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

#define CHROMEAPP_NAME iguana
#define CHROMEAPP_STR "iguana"
#define CHROMEAPP_CONF "iguana.config"
#define CHROMEAPP_MAIN iguana_main
#define CHROMEAPP_JSON iguana_JSON
#define CHROMEAPP_HANDLER Handler_iguana
#define ACTIVELY_DECLARE
#define HAVE_STRUCT_TIMESPEC
#include "../pnacl_main.h"
#include "iguana777.h"


struct iguana_jsonitem { struct queueitem DL; struct supernet_info *myinfo; uint32_t fallback,expired,allocsize; char *retjsonstr; char remoteaddr[64]; uint16_t port; char jsonstr[]; };

uint16_t SuperNET_API2num(char *agent,char *method)
{
    int32_t i,n = 0; cJSON *item;
    if ( agent != 0 && method != 0 && API_json != 0 && (n= cJSON_GetArraySize(API_json)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(API_json,i);
            if ( strcmp(agent,jstr(item,"agent")) == 0 && strcmp(method,jstr(item,"method")) == 0 )
                return((i << 5) | (SUPERNET_APIVERSION & 0x1f));
        }
    }
    return(-1);
}

int32_t SuperNET_num2API(char *agent,char *method,uint16_t num)
{
    int32_t n,apiversion; cJSON *item;
    if ( (apiversion= (num & 0x1f)) != SUPERNET_APIVERSION )
    {
        printf("need to make sure all released api help returns are indexed here!\n");
        return(-1);
    }
    num >>= 5;
    if ( API_json != 0 && (n= cJSON_GetArraySize(API_json)) > 0 && num < n )
    {
        item = jitem(API_json,num);
        strcpy(agent,jstr(item,"agent"));
        strcpy(method,jstr(item,"method"));
        return(num);
    }
    return(-1);
}

int32_t SuperNET_str2hex(uint8_t *hex,char *str)
{
    int32_t len;
    len = (int32_t)strlen(str)+1;
    decode_hex(hex,len,str);
    return(len);
}

void SuperNET_hex2str(char *str,uint8_t *hex,int32_t len)
{
     init_hexbytes_noT(str,hex,len);
}

void *bitcoin_ctx();
struct supernet_info *SuperNET_MYINFO(char *passphrase)
{
    //int32_t i;
    if ( MYINFO.ctx == 0 )
    {
        //for (i=0; i<sizeof(MYINFO.ctx)/sizeof(*MYINFO.ctx); i++)
        //    MYINFO.ctx[i] = bitcoin_ctx();
        OS_randombytes(MYINFO.privkey.bytes,sizeof(MYINFO.privkey));
        MYINFO.myaddr.pubkey = curve25519(MYINFO.privkey,curve25519_basepoint9());
        printf("SuperNET_MYINFO: generate session keypair\n");
        MYINFO.NOTARY.RELAYID = -1;
    }
    if ( passphrase == 0 || passphrase[0] == 0 )
        return(&MYINFO);
    else
    {
        // search saved accounts
    }
    return(&MYINFO);
    return(0);
}

struct supernet_info *SuperNET_MYINFOfind(int32_t *nump,bits256 pubkey)
{
    int32_t i;
    *nump = 0;
    if ( MYINFOS != 0 )
    {
        for (i=0; MYINFOS[i]!=0; i++)
        {
            *nump = i;
            if ( bits256_cmp(pubkey,MYINFOS[i]->myaddr.persistent) == 0 )
                return(MYINFOS[i]);
        }
        *nump = i;
    }
    return(0);
}

int32_t SuperNET_MYINFOS(struct supernet_info **myinfos,int32_t max)
{
    int32_t i = 0;
    if ( MYINFOS != 0 )
    {
        for (i=0; i<max; i++)
            if ( (myinfos[i]= MYINFOS[i]) == 0 )
                break;
    }
    return(i);
}

void SuperNET_MYINFOadd(struct supernet_info *myinfo)
{
    int32_t num;
    if ( SuperNET_MYINFOfind(&num,myinfo->myaddr.persistent) == 0 )
    {
        MYINFOS = realloc(MYINFOS,(num + 2) * sizeof(*MYINFOS));
        char str[65]; printf("MYNFOadd[%d] <- %s\n",num,bits256_str(str,myinfo->myaddr.persistent));
        MYINFOS[num] = calloc(1,sizeof(*myinfo));
        *MYINFOS[num] = *myinfo;
        MYINFOS[++num] = 0;
    }
}

char *iguana_JSON(void *_myinfo,void *_coin,char *jsonstr,uint16_t port)
{
    char *retstr=0; cJSON *json; struct supernet_info *myinfo = _myinfo; struct iguana_info *coin = _coin;
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( myinfo == 0 )
            myinfo = SuperNET_MYINFO(0);
        retstr = SuperNET_JSON(myinfo,coin,json,"127.0.0.1",port);
        free_json(json);
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"null return from iguana_JSON\"}");
    return(retstr);
}

char *SuperNET_jsonstr(struct supernet_info *myinfo,char *jsonstr,char *remoteaddr,uint16_t port)
{
    cJSON *json; char *agent,*method,*retstr = 0;
    //printf("SuperNET_jsonstr.(%s)\n",jsonstr);
    if ( (json= cJSON_Parse(jsonstr)) != 0 )
    {
        method = jstr(json,"method");
        if ( (agent= jstr(json,"agent")) != 0 && method != 0 && jobj(json,"params") == 0 )
            retstr = SuperNET_parser(myinfo,agent,method,json,remoteaddr);
        else if ( method != 0 && is_bitcoinrpc(myinfo,method,remoteaddr) >= 0 )
            retstr = iguana_bitcoinRPC(myinfo,method,json,remoteaddr,port);
        else retstr = clonestr("{\"error\":\"need both agent and method\"}");
        free_json(json);
    } else retstr = clonestr("{\"error\":\"couldnt parse SuperNET_JSON\"}");
    //printf("SuperNET_jsonstr ret.(%s)\n",retstr);
    return(retstr);
}

int32_t iguana_jsonQ(struct supernet_info *myinfo,struct iguana_info *coin)
{
    struct iguana_jsonitem *ptr; char *str; queue_t *finishedQ,*jsonQ;
    if ( coin == 0 )
    {
        finishedQ = &FINISHED_Q;
        jsonQ = &JSON_Q;
    }
    else
    {
        finishedQ = &coin->finishedQ;
        jsonQ = &coin->jsonQ;
    }
    if ( COMMANDLINE_ARGFILE != 0 )
    {
        ptr = calloc(1,sizeof(*ptr) + strlen(COMMANDLINE_ARGFILE) + 1);
        ptr->myinfo = myinfo;//SuperNET_MYINFO(0);
        strcpy(ptr->jsonstr,COMMANDLINE_ARGFILE);
        free(COMMANDLINE_ARGFILE);
        COMMANDLINE_ARGFILE = 0;
        if ( (ptr->retjsonstr= SuperNET_jsonstr(ptr->myinfo,ptr->jsonstr,ptr->remoteaddr,ptr->port)) == 0 )
            ptr->retjsonstr = clonestr("{\"error\":\"null return from iguana_jsonstr\"}");
        printf("COMMANDLINE_ARGFILE.(%s) -> (%s) %.0f\n",ptr->jsonstr,ptr->retjsonstr!=0?ptr->retjsonstr:"null return",OS_milliseconds());
        queue_enqueue("finishedQ",finishedQ,&ptr->DL);
        return(1);
    }
    if ( (ptr= queue_dequeue(finishedQ)) != 0 )
    {
        if ( ptr->expired != 0 )
        {
            if ( (str= ptr->retjsonstr) != 0 )
            {
                ptr->retjsonstr = 0;
                free(str);
            }
            printf("garbage collection: expired.(%s)\n",ptr->jsonstr);
            myfree(ptr,ptr->allocsize);
        } else queue_enqueue("finishedQ",finishedQ,&ptr->DL);
    }
    if ( (ptr= queue_dequeue(jsonQ)) != 0 )
    {
        if ( (ptr->retjsonstr= SuperNET_jsonstr(ptr->myinfo,ptr->jsonstr,ptr->remoteaddr,ptr->port)) == 0 )
            ptr->retjsonstr = clonestr("{\"error\":\"null return from iguana_jsonstr\"}");
        //printf("finished.(%s) -> (%s) %.0f\n",ptr->jsonstr,ptr->retjsonstr!=0?ptr->retjsonstr:"null return",OS_milliseconds());
        queue_enqueue("finishedQ",finishedQ,&ptr->DL);
        return(1);
    }
    return(0);
}

char *iguana_blockingjsonstr(struct supernet_info *myinfo,struct iguana_info *coin,char *jsonstr,uint64_t tag,int32_t maxmillis,char *remoteaddr,uint16_t port)
{
    queue_t *Q; struct iguana_jsonitem *ptr; int32_t len,allocsize; double expiration;
    expiration = OS_milliseconds() + maxmillis;
    //printf("blocking case.(%s) %.0f maxmillis.%d\n",jsonstr,OS_milliseconds(),maxmillis);
    len = (int32_t)strlen(jsonstr);
    allocsize = sizeof(*ptr) + len + 1;
    ptr = mycalloc('J',1,allocsize);
    ptr->allocsize = allocsize;
    ptr->myinfo = myinfo;
    ptr->port = port;
    ptr->retjsonstr = 0;
    safecopy(ptr->remoteaddr,remoteaddr,sizeof(ptr->remoteaddr));
    memcpy(ptr->jsonstr,jsonstr,len+1);
    if ( coin == 0 || coin->FULLNODE < 0 || (coin->FULLNODE == 0 && coin->VALIDATENODE == 0) )
        Q = &JSON_Q;
    else Q = &coin->jsonQ;
    queue_enqueue("jsonQ",Q,&ptr->DL);
    while ( OS_milliseconds() < expiration )
    {
        usleep(100);
        if ( ptr->retjsonstr != 0 )
        {
            //printf("got blocking retjsonstr.(%s) delete allocsize.%d:%d\n",retjsonstr,allocsize,ptr->allocsize);
            queue_delete(coin != 0 ? &coin->finishedQ : &FINISHED_Q,&ptr->DL,ptr->allocsize,1);
            return(ptr->retjsonstr);
        }
        usleep(1000);
    }
    //printf("(%s) expired\n",jsonstr);
    ptr->expired = (uint32_t)time(NULL);
    return(clonestr("{\"error\":\"iguana jsonstr expired\"}"));
}

int32_t iguana_immediate(struct iguana_info *coin,int32_t immedmillis)
{
    double endmillis;
    if ( immedmillis > 60000 )
        immedmillis = 60000;
    endmillis = OS_milliseconds() + immedmillis;
    while ( 1 )
    {
        if ( coin->busy_processing == 0 )
            break;
        usleep(100);
        if ( OS_milliseconds() > endmillis )
            break;
    }
    return(coin->busy_processing == 0);
}

char *SuperNET_processJSON(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *json,char *remoteaddr,uint16_t port)
{
    cJSON *retjson; uint64_t tag; uint32_t timeout,immedmillis; char *jsonstr,*retjsonstr,*retstr = 0; //*hexmsg,*method,
    //char str[65]; printf("processJSON %p %s\n",&myinfo->privkey,bits256_str(str,myinfo->privkey));
    if ( json != 0 )
    {
        if ( jobj(json,"tag") == 0 || (tag= j64bits(json,"tag")) == 0 )
        {
            OS_randombytes((uint8_t *)&tag,sizeof(tag));
            jadd64bits(json,"tag",tag);
        }
        if ( (timeout= juint(json,"timeout")) == 0 )
            timeout = IGUANA_JSONTIMEOUT;
        /*if ( (method= jstr(json,"method")) != 0 && strcmp(method,"DHT") == 0 && remoteaddr != 0 && (hexmsg= jstr(json,"hexmsg")) != 0 )
        {
            //printf("hexmsgprocess myinfo.%p\n",myinfo);
            SuperNET_hexmsgprocess(myinfo,0,json,hexmsg,remoteaddr);
            return(clonestr("{\"result\":\"processed remote DHT\"}"));
        }*/
        jsonstr = jprint(json,0);
        //printf("RPC? (%s)\n",jsonstr);
        if ( (immedmillis= juint(json,"immediate")) != 0 || ((remoteaddr == 0 || remoteaddr[0] == 0) && port == myinfo->rpcport) )
        {
            if ( coin != 0 )
            {
                if ( immedmillis == 0 || iguana_immediate(coin,immedmillis) != 0 )
                    retjsonstr = SuperNET_jsonstr(myinfo,jsonstr,remoteaddr,port);
                else retjsonstr = clonestr("{\"error\":\"coin is busy processing\"}");
            } else retjsonstr = SuperNET_jsonstr(myinfo,jsonstr,remoteaddr,port);
        } else retjsonstr = iguana_blockingjsonstr(myinfo,coin,jsonstr,tag,timeout,remoteaddr,port);
        if ( retjsonstr != 0 )
        {
            if ( (retjsonstr[0] == '{' || retjsonstr[0] == '[') && (retjson= cJSON_Parse(retjsonstr)) != 0 )
            {
                if ( is_cJSON_Array(retjson) == 0 )
                {
                    if ( jobj(retjson,"tag") == 0 || j64bits(retjson,"tag") != tag )
                    {
                        if ( jobj(retjson,"tag") != 0 )
                            jdelete(retjson,"tag");
                        jadd64bits(retjson,"tag",tag);
                    }
                    retstr = jprint(retjson,1);
                    free(retjsonstr);//,strlen(retjsonstr)+1);
                    //printf("retstr.(%s) retjsonstr.%p retjson.%p\n",retstr,retjsonstr,retjson);
                } else retstr = retjsonstr;
            } else retstr = retjsonstr;
        }
        free(jsonstr);
    } else retstr = clonestr("{\"error\":\"cant parse JSON\"}");
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"null return\"}");
    //printf("processJSON.(%s)\n",retstr);
    return(retstr);
}

char *SuperNET_JSON(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *json,char *remoteaddr,uint16_t port)
{
    int32_t autologin = 0; uint32_t timestamp; char *retstr=0,*agent=0,*method=0,*userpass; uint64_t tag;
//printf("SuperNET_JSON.(%s)\n",jprint(json,0));
    if ( remoteaddr != 0 && strcmp(remoteaddr,"127.0.0.1") == 0 )
        remoteaddr = 0;
    if ( (agent = jstr(json,"agent")) == 0 )
        agent = "bitcoinrpc";
    if ( (method= jstr(json,"method")) == 0 )
    {
        printf("no method in request.(%s)\n",jprint(json,0));
        return(clonestr("{\"error\":\"no method\"}"));
    }
    if ( strcmp(method,"login") == 0 || strcmp(method,"logout") == 0 )
        return(clonestr("{\"error\":\"login and logout are internal only functions\"}"));
    if ( remoteaddr == 0 )
    {
        if ( jobj(json,"timestamp") != 0 )
            jdelete(json,"timestamp");
        timestamp = (uint32_t)time(NULL);
        jaddnum(json,"timestamp",timestamp);
    }
    if ( jobj(json,"tag") == 0 || (tag= j64bits(json,"tag")) == 0 )
    {
        OS_randombytes((uint8_t *)&tag,sizeof(tag));
        jadd64bits(json,"tag",tag);
    }
    if ( coin != 0 && coin->FULLNODE >= 0 && coin->chain->userpass[0] != 0 )
    {
        if ( (userpass= jstr(json,"userpass")) == 0 || strcmp(userpass,coin->chain->userpass) != 0 )
        {
            printf("iguana authentication error {%s} (%s) != (%s)\n",jprint(json,0),userpass,coin->chain->userpass);
            return(clonestr("{\"error\":\"authentication error\"}"));
        }
    }
    if ( (retstr= SuperNET_processJSON(myinfo,coin,json,remoteaddr,port)) == 0 )
        printf("null retstr from SuperNET_JSON\n");
    if ( autologin != 0 )
        SuperNET_logout(myinfo,0,json,remoteaddr);
    return(retstr);
}

void iguana_exit(struct supernet_info *myinfo,struct iguana_bundle *bp)
{
    static int exiting;
    int32_t i,j,iter; struct iguana_info *coin,*tmp;
    if ( exiting != 0 )
        while ( 1 )
            sleep(1);
    exiting = 1;
    if ( myinfo == 0 )
        myinfo = SuperNET_MYINFO(0);
    printf("start EXIT\n");
    for (iter=0; iter<3; iter++)
    {
        if ( iter == 0 )
            basilisk_request_goodbye(myinfo);
        else
        {
            HASH_ITER(hh,myinfo->allcoins,coin,tmp)
            {
                if ( coin->peers != 0 )
                {
                    for (j=0; j<IGUANA_MAXPEERS; j++)
                    {
                        switch ( iter )
                        {
                            case 1: coin->peers->active[j].dead = (uint32_t)time(NULL); break;
                            case 2:
                                if ( coin->peers->active[j].usock >= 0 )
                                    closesocket(coin->peers->active[j].usock);
                                break;
                        }
                    }
                }
            }
        }
        sleep(3);
    }
    printf("sockets closed\n");
    if ( bp != 0 )
        iguana_bundleremove(bp->coin,bp->hdrsi,1);
    for (i=0; i<10; i++)
    {
        printf("need to exit, please restart after shutdown in %d seconds, or just ctrl-C\n",10-i);
        sleep(1);
    }
    exit(0);
}

#ifndef _WIN32
#include <signal.h>
void sigint_func() { printf("\nSIGINT\n"); iguana_exit(0,0); }
void sigillegal_func() { printf("\nSIGILL\n"); iguana_exit(0,0); }
void sighangup_func() { printf("\nSIGHUP\n"); iguana_exit(0,0); }
void sigkill_func() { printf("\nSIGKILL\n"); iguana_exit(0,0); }
void sigabort_func() { printf("\nSIGABRT\n"); iguana_exit(0,0); }
void sigquit_func() { printf("\nSIGQUIT\n"); iguana_exit(0,0); }
void sigchild_func() { printf("\nSIGCHLD\n"); signal(SIGCHLD,sigchild_func); }
void sigalarm_func() { printf("\nSIGALRM\n"); signal(SIGALRM,sigalarm_func); }
void sigcontinue_func() { printf("\nSIGCONT\n"); signal(SIGCONT,sigcontinue_func); }
#endif

void iguana_signalsinit()
{
#ifndef _WIN32
    signal(SIGABRT,sigabort_func);
    signal(SIGINT,sigint_func);
    signal(SIGILL,sigillegal_func);
    signal(SIGHUP,sighangup_func);
    //signal(SIGKILL,sigkill_func);
    signal(SIGQUIT,sigquit_func);
    signal(SIGCHLD,sigchild_func);
    signal(SIGALRM,sigalarm_func);
    signal(SIGCONT,sigcontinue_func);
#endif
}

// mksquashfs DB/BTC BTC.squash -b 1048576 -> 19GB?
// mksquashfs DB/BTC BTC.lzo -comp lzo -b 1048576 -> takes a really long time -> 20GB
// mksquashfs DB/BTC BTC.xz -b 1048576 -comp xz -Xdict-size 512K -> takes a long time -> 16GB
// mksquashfs DB/BTC BTC.xz1m -b 1048576 -comp xz -Xdict-size 1024K -> takes a long time ->
/*
 mksquashfs DB/BTC BTC.xz -comp xz
 mksquashfs DB/BTC BTC.xzs -b 16384 -comp xz -Xdict-size 8K
 mksquashfs DB/BTC BTC.xz1m -b 1048576 -comp xz -Xdict-size 1024K
 mksquashfs DB/BTC BTC.xz8k -comp xz -Xdict-size 8K
mksquashfs DB/BTC BTC.lzo -comp lzo
mksquashfs DB/BTC BTC.lzo1m -comp lzo -b 1048576
mksquashfs DB/BTC BTC.squash
mksquashfs DB/BTC BTC.squash1M -b 1048576
 
rm BTC.xz; mksquashfs DB/BTC BTC.xz -comp xz -b 1048576 -comp xz -Xdict-size 1024K
 sudo mount BTC.xz DB/ro/BTC -t squashfs -o loop
 https://github.com/vasi/squashfuse
*/

void DEX_explorerloop(void *ptr)
{
    struct supernet_info *myinfo = ptr;
    while ( 1 )
    {
        if ( myinfo->DEXEXPLORER != 0 )
        {
            kmd_bitcoinscan();
        }
        usleep(100000);
    }
}

void mainloop(struct supernet_info *myinfo)
{
    struct iguana_info *coin; int32_t counter=0,depth; double lastmilli = 0;
    sleep(3);
    printf("mainloop\n");
    while ( 1 )
    {
        //printf("main iteration\n");
        if ( 1 )
        {
            if ( OS_milliseconds() > lastmilli+100 )
            {
                //fprintf(stderr,".");
                counter++;
                coin = 0;
                depth = 0;
                //printf("check jsonQ\n");
                while ( iguana_jsonQ(myinfo,0) != 0 )
                    ;
                lastmilli = OS_milliseconds();
            }
            usleep(30000);
        }
        //pangea_queues(SuperNET_MYINFO(0));
        //if ( flag == 0 )
        //    usleep(100000 + isRT*100000 + (numpeers == 0)*1000000);
        //iguana_jsonQ(); // cant do this here safely, need to send to coin specific queue
    }
}

void iguana_accounts(char *keytype)
{
    long filesize; cJSON *json,*array,*item,*posting,*auths,*json2; int32_t i,n,m; char *str,*str2,*postingkey,*name,*key,fname[128],cmd[512]; FILE *postingkeys;
    if ( (str= OS_filestr(&filesize,"accounts.txt")) != 0 )
    {
        if ( (json= cJSON_Parse(str)) != 0 )
        {
            if ( (array= jarray(&n,json,"result")) != 0 && (postingkeys= fopen("keys.c","wb")) != 0 )
            {
                fprintf(postingkeys,"char *%skeys[][2] = {\n",keytype);
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( (name= jstr(item,"name")) != 0 && (posting= jobj(item,keytype)) != 0 )
                    {
                        if ( (auths= jarray(&m,posting,"key_auths")) != 0 )
                        {
                            item = jitem(auths,0);
                            if ( is_cJSON_Array(item) != 0 && (key= jstri(item,0)) != 0 )
                            {
                                sprintf(fname,"/tmp/%s",name);
                                sprintf(cmd,"curl --url \"http://127.0.0.1:8091\" --data \"{\\\"id\\\":444,\\\"method\\\":\\\"get_private_key\\\",\\\"params\\\":[\\\"%s\\\"]}\" > %s",key,fname);
                                if ( system(cmd) != 0 )
                                    printf("Error issuing.(%s)\n",cmd);
                                if ( (str2= OS_filestr(&filesize,fname)) != 0 )
                                {
                                    if ( (json2= cJSON_Parse(str2)) != 0 )
                                    {
                                        if ( (postingkey= jstr(json2,"result")) != 0 )
                                            fprintf(postingkeys,"{ \"%s\", \"%s\" },",name,postingkey);
                                        else printf("no result in (%s)\n",jprint(json2,0));
                                        free_json(json2);
                                    } else printf("couldnt parse (%s)\n",str2);
                                    free(str2);
                                } else printf("couldnt load (%s)\n",fname);
                            }
                        }
                    }
                }
                fprintf(postingkeys,"\n};\n");
                fclose(postingkeys);
            }
            free_json(json);
        }
        free(str);
    }
}

void iguana_appletests(struct supernet_info *myinfo)
{
    char *str;
    //iguana_chaingenesis(1,1403138561,0x1e0fffff,8359109,bits256_conv("fd1751cc6963d88feca94c0d01da8883852647a37a0a67ce254d62dd8c9d5b2b")); // BTCD
    if ( (0) )
    {
    char genesisblock[1024];
    //iguana_chaingenesis("VPN",0,bits256_conv("00000ac7d764e7119da60d3c832b1d4458da9bc9ef9d5dd0d91a15f690a46d99"),genesisblock,"scrypt",1,1409839200,0x1e0fffff,64881664,bits256_conv("698a93a1cacd495a7a4fb3864ad8d06ed4421dedbc57f9aaad733ea53b1b5828")); // VPN
    
    iguana_chaingenesis(myinfo,"LTC",0,0,0,bits256_conv("12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2"),genesisblock,"sha256",1,1317972665,0x1e0ffff0,2084524493,bits256_conv("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9")); // LTC
        //char *Str = "01000000f615f7ce3b4fc6b8f61e8f89aedb1d0852507650533a9e3b10b9bbcc30639f279fcaa86746e1ef52d3edb3c4ad8259920d509bd073605c9bf1d59983752a6b06b817bb4ea78e011d012d59d4";
        // https://litecoin.info/Scrypt  0000000110c8357966576df46f3b802ca897deb7ad18b12f1c24ecff6386ebd9
        //uint8_t buf[1000]; bits256 shash,hash2; char str[65],str2[65];
        //decode_hex(buf,(int32_t)strlen(Str)>>1,Str);
        //calc_scrypthash(shash.uints,buf);
        //blockhash_sha256(&hash2,buf,80);
        //printf("shash -> %s sha256x2 %s\n",bits256_str(str,shash),bits256_str(str2,hash2));
    getchar();
    }
    if ( 1 )
    {
        /*int32_t i; ;bits256 hash2; uint8_t pubkey[33];
        double startmillis = OS_milliseconds();
        for (i=0; i<1000; i++)
            hash2 = curve25519_shared(hash2,rand256(0));
        printf("curve25519 elapsed %.3f for %d iterations\n",OS_milliseconds() - startmillis,i);
        startmillis = OS_milliseconds();
        bitcoin_pubkey33(myinfo->ctx,pubkey,hash2);
        for (i=0; i<1000; i++)
            bitcoin_sharedsecret(myinfo->ctx,hash2,pubkey,33);
        printf("secp256k1 elapsed %.3f for %d iterations\n",OS_milliseconds() - startmillis,i);
       getchar();**/
        if ( (0) && (str= SuperNET_JSON(myinfo,iguana_coinfind("BTCD"),cJSON_Parse("{\"protover\":70002,\"RELAY\":1,\"VALIDATE\":1,\"portp2p\":14631,\"rpc\":14632,\"agent\":\"iguana\",\"method\":\"addcoin\",\"startpend\":512,\"endpend\":512,\"services\":129,\"maxpeers\":8,\"newcoin\":\"BTCD\",\"active\":1,\"numhelpers\":1,\"poll\":100}"),0,myinfo->rpcport)) != 0 )
        {
            free(str);
            if ( 1 && (str= SuperNET_JSON(myinfo,iguana_coinfind("BTC"),cJSON_Parse("{\"portp2p\":8333,\"RELAY\":0,\"VALIDATE\":0,\"agent\":\"iguana\",\"method\":\"addcoin\",\"startpend\":1,\"endpend\":1,\"services\":128,\"maxpeers\":8,\"newcoin\":\"BTC\",\"active\":0,\"numhelpers\":1,\"poll\":100}"),0,myinfo->rpcport)) != 0 )
            {
                free(str);
                if ( (0) && (str= SuperNET_JSON(myinfo,iguana_coinfind("BTCD"),cJSON_Parse("{\"agent\":\"SuperNET\",\"method\":\"login\",\"handle\":\"alice\",\"password\":\"alice\",\"passphrase\":\"alice\"}"),0,myinfo->rpcport)) != 0 )
                {
                    free(str);
                    if ( (str= SuperNET_JSON(myinfo,iguana_coinfind("BTCD"),cJSON_Parse("{\"agent\":\"SuperNET\",\"method\":\"login\",\"handle\":\"bob\",\"password\":\"bob\",\"passphrase\":\"bob\"}"),0,myinfo->rpcport)) != 0 )
                        free(str);
                }
            }
        }
        sleep(1);
    }
}

int32_t iguana_commandline(struct supernet_info *myinfo,char *arg)
{
    cJSON *argjson,*array; char *coinargs,*argstr=0,*str; int32_t i,n; long filesize = 0;
    if ( arg == 0 )
        arg = "iguana.conf";
    else if ( (COMMANDLINE_ARGFILE= OS_filestr(&filesize,arg)) != 0 )
    {
        if ( (argjson= cJSON_Parse(COMMANDLINE_ARGFILE)) == 0 )
        {
            printf("couldnt parse %s: (%s) after initialized\n",arg,COMMANDLINE_ARGFILE);
            free(COMMANDLINE_ARGFILE);
            COMMANDLINE_ARGFILE = 0;
        }
        else
        {
            IGUANA_NUMHELPERS = juint(argjson,"numhelpers");
            myinfo->remoteorigin = juint(argjson,"remoteorigin");
            free_json(argjson);
            printf("Will run (%s) after initialized with %d threads\n",COMMANDLINE_ARGFILE,IGUANA_NUMHELPERS);
        }
    }
    else if ( arg != 0 )
    {
        if ( arg[0] == '{' || arg[0] == '[' )
            argstr = arg;
        //else argstr = OS_filestr(&filesize,arg);
        if ( argstr != 0 && (argjson= cJSON_Parse(argstr)) != 0 )
        {
            IGUANA_NUMHELPERS = juint(argjson,"numhelpers");
            if ( (myinfo->rpcport= juint(argjson,"port")) == 0 )
                myinfo->rpcport = IGUANA_RPCPORT;
            if ( (myinfo->publicRPC= juint(argjson,"publicRPC")) != 0 && myinfo->publicRPC != myinfo->rpcport )
                myinfo->publicRPC = 0;
            if ( jstr(argjson,"rpccoin") != 0 )
                safecopy(myinfo->rpcsymbol,jstr(argjson,"rpccoin"),sizeof(myinfo->rpcsymbol));
            safecopy(Userhome,jstr(argjson,"userhome"),sizeof(Userhome));
            if ( jstr(argjson,"tmpdir") != 0 )
            {
                safecopy(GLOBAL_TMPDIR,jstr(argjson,"tmpdir"),sizeof(GLOBAL_TMPDIR));
                printf("GLOBAL tmpdir.(%s)\n",GLOBAL_TMPDIR);
            }
            printf("call argv JSON.(%s)\n",(char *)arg);
            SuperNET_JSON(myinfo,0,argjson,0,myinfo->rpcport);
            if ( (coinargs= SuperNET_keysinit(myinfo,arg)) != 0 )
                iguana_launch(0,"iguana_coins",iguana_coins,coinargs,IGUANA_PERMTHREAD);
            if ( (array= jarray(&n,argjson,"commands")) != 0 )
            {
                for (i=0; i<n; i++)
                    if ( (str= SuperNET_JSON(myinfo,0,jitem(array,i),0,myinfo->rpcport)) != 0 )
                        free(str);
            }
            free_json(argjson);
            if ( (0) )
            {
                uint32_t buf[81],c;
                OS_randombytes((void *)buf,sizeof(buf));
                printf("(");
                for (i=0; i<81; i++)
                {
                    c = buf[i] % 27;
                    if ( c == 26 )
                        c = '9';
                    else c += 'a';
                    printf("%c",c);
                }
                printf(") <- IOTA random passphrase\n");
            }
        } //else printf("error parsing.(%s)\n",(char *)argstr);
        //if ( argstr != arg )
        //    free(argstr);
    }
    return(COMMANDLINE_ARGFILE != 0);
}

void iguana_ensuredirs()
{
    char dirname[512];
    sprintf(dirname,"%s",GLOBAL_HELPDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s",GLOBAL_GENESISDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s",GLOBAL_CONFSDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/SWAPS",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/TRANSACTIONS",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/purgeable",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s",GLOBAL_TMPDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s",GLOBAL_VALIDATEDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/ECB",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/BTC",GLOBAL_VALIDATEDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/BTCD",GLOBAL_VALIDATEDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"SVM"), OS_ensure_directory(dirname);
    sprintf(dirname,"SVM/rawfeatures"), OS_ensure_directory(dirname);
    sprintf(dirname,"SVM/models"), OS_ensure_directory(dirname);
}

void iguana_Qinit()
{
    iguana_initQ(&helperQ,"helperQ");
    iguana_initQ(&JSON_Q,"jsonQ");
    iguana_initQ(&FINISHED_Q,"finishedQ");
    iguana_initQ(&bundlesQ,"bundlesQ");
    iguana_initQ(&emitQ,"emitQ");
    //iguana_initQ(&TerminateQ,"TerminateQ");
}

void iguana_helpinit(struct supernet_info *myinfo)
{
    char *tmpstr = 0;
    if ( (tmpstr= SuperNET_JSON(myinfo,0,cJSON_Parse("{\"agent\":\"SuperNET\",\"method\":\"help\"}"),0,myinfo->rpcport)) != 0 )
    {
        if ( (API_json= cJSON_Parse(tmpstr)) != 0 && (API_json= jobj(API_json,"result")) != 0 )
            API_json = jobj(API_json,"API");
        else printf("couldnt parse tmpstr\n");
        free(tmpstr);
    }
    printf("generated API_json tmpstr.%p\n",tmpstr);
}

void iguana_urlinit(struct supernet_info *myinfo,int32_t ismainnet,int32_t usessl)
{
    int32_t iter,j; FILE *fp; char line[4096],NXTaddr[64]; uint8_t pubkey[32];
    strcpy(myinfo->NXTAPIURL,"http://127.0.0.1:7876/nxt");
    for (iter=0; iter<2; iter++)
    {
        if ( (fp= fopen(iter == 0 ? "nxtpasswords" : "fimpasswords","rb")) != 0 )
        {
            while ( fgets(line,sizeof(line),fp) > 0 )
            {
                j = (int32_t)strlen(line) - 1;
                line[j] = 0;
                calc_NXTaddr(NXTaddr,pubkey,(uint8_t *)line,j);
                printf("FORGING %s (%s)\n",NXTaddr,issue_startForging(myinfo,line));
            }
            fclose(fp);
        }
        strcpy(myinfo->NXTAPIURL,"http://127.0.0.1:7886/nxt");
    }
    if ( usessl == 0 )
        strcpy(myinfo->NXTAPIURL,"http://127.0.0.1:");
    else strcpy(myinfo->NXTAPIURL,"https://127.0.0.1:");
    if ( ismainnet != 0 )
        strcat(myinfo->NXTAPIURL,"7876/nxt");
    else strcat(myinfo->NXTAPIURL,"6876/nxt");
}

void jumblr_loop(void *ptr)
{
    struct iguana_info *coin; uint32_t t,n=0; struct supernet_info *myinfo = ptr; int32_t mult = 10;
    printf("JUMBLR loop\n");
    while ( myinfo->IAMNOTARY == 0 )
    {
        if ( (coin= iguana_coinfind("KMD")) != 0 )
        {
            n++;
            if ( (n % 3) == 0 )
                smartaddress_update(myinfo,(n/3) & 1);
            if ( myinfo->jumblr_passphrase[0] != 0 && coin->FULLNODE < 0 )
            {
                // if BTC has arrived in destination address, invoke DEX -> BTC
                t = (uint32_t)time(NULL);
                if ( (t % (120 * mult)) < 60 )
                {
                    // if BTC has arrived in deposit address, invoke DEX -> KMD
                    jumblr_iteration(myinfo,coin,(t % (360 * mult)) / (120 * mult),t % (120 * mult));
                }
                //printf("t.%u %p.%d %s\n",t,coin,coin!=0?coin->FULLNODE:0,myinfo->jumblr_passphrase);
            }
        }
        sleep(55);
    }
}

void iguana_launchdaemons(struct supernet_info *myinfo)
{
    int32_t i; char *helperargs,helperstr[512];
    if ( IGUANA_NUMHELPERS == 0 )//|| COMMANDLINE_ARGFILE != 0 )
        IGUANA_NUMHELPERS = 1;
    for (i=0; i<IGUANA_NUMHELPERS; i++)
    {
        sprintf(helperstr,"{\"helperid\":%d}",i);
        helperargs = clonestr(helperstr);
        printf("helper launch[%d] of %d (%s)\n",i,IGUANA_NUMHELPERS,helperstr);
        iguana_launch(0,"iguana_helper",iguana_helper,helperargs,IGUANA_PERMTHREAD);
    }
    if ( COMMANDLINE_ARGFILE == 0 )
        iguana_launch(0,"rpcloop",iguana_rpcloop,myinfo,IGUANA_PERMTHREAD); // limit to oneprocess
    printf("launch mainloop\n");
    // disable basilisk: OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)DEX_explorerloop,(void *)myinfo);
    OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)jumblr_loop,(void *)myinfo);
    OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)dpow_psockloop,(void *)myinfo);
    mainloop(myinfo);
}

int32_t iguana_isbigendian()
{
    int32_t i,littleendian,bigendian; uint64_t val = 0x0001020304050607;
    for (i=bigendian=littleendian=0; i<sizeof(val); i++)
    {
        if ( ((uint8_t *)&val)[i] == i )
            bigendian++;
        else if ( ((uint8_t *)&val)[sizeof(val)-1-i] == i )
            littleendian++;
    }
    if ( littleendian == sizeof(val) )
        return(0);
    else if ( bigendian == sizeof(val) )
        return(1);
    else return(-1);
}

void *SuperNET_deciphercalc(void **ptrp,int32_t *msglenp,bits256 privkey,bits256 srcpubkey,uint8_t *cipher,int32_t cipherlen,uint8_t *buf,int32_t bufsize)
{
    uint8_t *origptr,*nonce,*message; void *retptr;
    if ( bits256_nonz(privkey) == 0 )
        privkey = GENESIS_PRIVKEY;
    *ptrp = 0;
    if ( cipherlen > bufsize )
    {
        message = calloc(1,cipherlen);
        *ptrp = (void *)message;
    }
    else message = buf;
    origptr = cipher;
    if ( bits256_nonz(srcpubkey) == 0 )
    {
        memcpy(srcpubkey.bytes,cipher,sizeof(srcpubkey));
        char str[65]; printf("use attached pubkey.(%s)\n",bits256_str(str,srcpubkey));
        cipher += sizeof(srcpubkey);
        cipherlen -= sizeof(srcpubkey);
    }
    nonce = cipher;
    cipher += crypto_box_NONCEBYTES, cipherlen -= crypto_box_NONCEBYTES;
    *msglenp = cipherlen - crypto_box_ZEROBYTES;
    if ( (retptr= _SuperNET_decipher(nonce,cipher,message,cipherlen,srcpubkey,privkey)) == 0 )
    {
        *msglenp = -1;
        free(*ptrp);
    }
    return(retptr);
}

uint8_t *SuperNET_ciphercalc(void **ptrp,int32_t *cipherlenp,bits256 *privkeyp,bits256 *destpubkeyp,uint8_t *data,int32_t datalen,uint8_t *space2,int32_t space2size)
{
    bits256 mypubkey; uint8_t *buf,*nonce,*cipher,*origptr,space[8192]; int32_t onetimeflag=0,allocsize;
    *ptrp = 0;
    allocsize = (datalen + crypto_box_NONCEBYTES + crypto_box_ZEROBYTES);
    if ( bits256_nonz(*destpubkeyp) == 0 || memcmp(destpubkeyp->bytes,GENESIS_PUBKEY.bytes,sizeof(*destpubkeyp)) == 0 )
    {
        *destpubkeyp = GENESIS_PUBKEY;
        onetimeflag = 2; // prevent any possible leakage of privkey by encrypting to known destpub
    }
    if ( bits256_nonz(*privkeyp) == 0 )
        onetimeflag = 1;
    if ( onetimeflag != 0 )
    {
        crypto_box_keypair(mypubkey.bytes,privkeyp->bytes);
        allocsize += sizeof(bits256);
    }
    if ( allocsize > sizeof(space) )
        buf = calloc(1,allocsize);
    else buf = space;
    if ( allocsize+sizeof(struct iguana_msghdr) > space2size )
    {
        cipher = calloc(1,allocsize + sizeof(struct iguana_msghdr));
        *ptrp = (void *)cipher;
    } else cipher = space2;
    cipher = &cipher[sizeof(struct iguana_msghdr)];
    origptr = nonce = cipher;
    if ( onetimeflag != 0 )
    {
        memcpy(cipher,mypubkey.bytes,sizeof(mypubkey));
        nonce = &cipher[sizeof(mypubkey)];
    }
    OS_randombytes(nonce,crypto_box_NONCEBYTES);
    cipher = &nonce[crypto_box_NONCEBYTES];
    _SuperNET_cipher(nonce,cipher,(void *)data,datalen,*destpubkeyp,*privkeyp,buf);
    if ( buf != space )
        free(buf);
    *cipherlenp = allocsize;
    return(origptr);
}

cJSON *SuperNET_rosettajson(struct supernet_info *myinfo,bits256 privkey,int32_t showprivs)
{
    uint8_t rmd160[20],pub[33]; uint64_t nxt64bits; bits256 pubkey;
    char str2[41],wifbuf[64],pbuf[65],addr[64],str[128],coinwif[16]; cJSON *retjson; struct iguana_info *coin,*tmp;
    pubkey = acct777_pubkey(privkey);
    nxt64bits = acct777_nxt64bits(pubkey);
    retjson = cJSON_CreateObject();
    jaddbits256(retjson,"pubkey",pubkey);
    RS_encode(str,nxt64bits);
    jaddstr(retjson,"RS",str);
    jadd64bits(retjson,"NXT",nxt64bits);
    bitcoin_pubkey33(0,pub,privkey);
    init_hexbytes_noT(str,pub,33);
    jaddstr(retjson,"btcpubkey",str);
    calc_OP_HASH160(str2,rmd160,str);
    jaddstr(retjson,"rmd160",str2);
    if ( showprivs != 0 )
        jaddstr(retjson,"privkey",bits256_str(pbuf,privkey));
    HASH_ITER(hh,myinfo->allcoins,coin,tmp)
    {
        if ( coin != 0 && coin->symbol[0] != 0 )
        {
            if ( bitcoin_address(addr,coin->chain->pubtype,pub,33) != 0 )
            {
                jaddstr(retjson,coin->symbol,addr);
                sprintf(coinwif,"%swif",coin->symbol);
                if ( showprivs != 0 )
                {
                    bitcoin_priv2wif(wifbuf,privkey,coin->chain->wiftype);
                    jaddstr(retjson,coinwif,wifbuf);
                }
            }
        }
    }
    /*if ( bitcoin_address(addr,0,pub,33) != 0 )
    {
        jaddstr(retjson,"BTC",addr);
        if ( showprivs != 0 )
        {
            bitcoin_priv2wif(wifbuf,privkey,128);
            jaddstr(retjson,"BTCwif",wifbuf);
        }
    }
    if ( bitcoin_address(addr,60,pub,33) != 0 )
    {
        jaddstr(retjson,"BTCD",addr);
        if ( showprivs != 0 )
        {
            bitcoin_priv2wif(wifbuf,privkey,188);
            jaddstr(retjson,"BTCDwif",wifbuf);
        }
    }*/
    if ( showprivs != 0 )
        jaddbits256(retjson,"privkey",privkey);
    return(retjson);
}

cJSON *SuperNET_peerarray(struct iguana_info *coin,int32_t max,int32_t supernetflag)
{
    int32_t i,r,j,n = 0; struct iguana_peer *addr; cJSON *array = cJSON_CreateArray();
    if ( coin->peers == 0 )
        return(array);
    r = rand();
    for (j=0; j<IGUANA_MAXPEERS; j++)
    {
        i = (r + j) % IGUANA_MAXPEERS;
        addr = &coin->peers->active[i];
        if ( addr->usock >= 0 && supernetflag == (addr->supernet != 0) )
        {
            jaddistr(array,addr->ipaddr);
            if ( ++n >= max )
                break;
        }
    }
    if ( n == 0 )
    {
        free_json(array);
        return(0);
    }
    return(array);
}

int32_t SuperNET_coinpeers(struct iguana_info *coin,cJSON *SNjson,cJSON *rawjson,int32_t max)
{
    cJSON *array,*item;
    if ( (array= SuperNET_peerarray(coin,max,1)) != 0 )
    {
        max -= cJSON_GetArraySize(array);
        item = cJSON_CreateObject();
        jaddstr(item,"coin",coin->symbol);
        jadd(item,"peers",array);
        jaddi(SNjson,item);
    }
    if ( max > 0 && (array= SuperNET_peerarray(coin,max,0)) != 0 )
    {
        max -= cJSON_GetArraySize(array);
        item = cJSON_CreateObject();
        jaddstr(item,"coin",coin->symbol);
        jadd(item,"peers",array);
        jaddi(rawjson,item);
    }
    return(max);
}

void SuperNET_remotepeer(struct supernet_info *myinfo,struct iguana_info *coin,char *symbol,char *ipaddr,int32_t supernetflag)
{
    uint64_t ipbits; struct iguana_peer *addr;
    ipbits = calc_ipbits(ipaddr);
    printf("got %s remotepeer.(%s) supernet.%d\n",symbol,ipaddr,supernetflag);
    if ( supernetflag != 0 && (uint32_t)myinfo->myaddr.selfipbits != (uint32_t)ipbits )
    {
        if ( (addr= iguana_peerslot(coin,ipbits,0)) != 0 )
        {
            printf("launch startconnection to supernet peer.(%s)\n",ipaddr);
            iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
            return;
        }
    }
    iguana_possible_peer(coin,ipaddr);
}

void SuperNET_parsepeers(struct supernet_info *myinfo,cJSON *array,int32_t n,int32_t supernetflag)
{
    int32_t i,j,m; cJSON *coinarray,*item; char *symbol,*ipaddr; struct iguana_info *ptr;
    if ( array != 0 && n > 0 )
    {
        for (i=0; i<n; i++)
        {
            if ( (item= jitem(array,i)) != 0 && (symbol= jstr(item,"coin")) != 0 )
            {
                ptr = iguana_coinfind(symbol);
                if ( (coinarray= jarray(&m,item,"peers")) != 0 )
                {
                    for (j=0; j<m; j++)
                    {
                        if ( (ipaddr= jstr(jitem(coinarray,j),0)) != 0 )
                            SuperNET_remotepeer(myinfo,ptr,symbol,ipaddr,supernetflag);
                        else printf("no ipaddr[%d] of %d\n",j,m);
                    }
                }
                printf("parsed.%d %s.peers supernet.%d\n",m,symbol,supernetflag);
            }
        }
    }
}

#include "../includes/iguana_apidefs.h"
#include "../includes/iguana_apideclares.h"
#include "../includes/iguana_apideclares2.h"

STRING_ARG(iguana,initfastfind,activecoin)
{
    if ( (coin= iguana_coinfind(activecoin)) != 0 )
    {
        iguana_fastfindcreate(coin);
        return(clonestr("{\"result\":\"fast find initialized\"}"));
    } else return(clonestr("{\"error\":\"no coin to initialize\"}"));
}

TWO_STRINGS_AND_TWO_DOUBLES(iguana,balance,activecoin,address,lastheightd,minconfd)
{
    int32_t lastheight,minconf,maxconf=1<<30; cJSON *array,*retjson = cJSON_CreateObject();
    if ( activecoin != 0 && activecoin[0] != 0 )
        coin = iguana_coinfind(activecoin);
    if ( coin != 0 )
    {
        if ( (minconf= minconfd) <= 0 )
            minconf = 1;
        lastheight = lastheightd;
        jaddstr(retjson,"address",address);
        if ( bitcoin_validaddress(coin,address) < 0 )
        {
            jaddstr(retjson,"error","illegal address");
            return(jprint(retjson,1));
        }
        jadd64bits(retjson,"RTbalance",iguana_RTbalance(coin,address));
        array = cJSON_CreateArray();
        jaddistr(array,address);
        jadd(retjson,"unspents",iguana_RTlistunspent(myinfo,coin,array,minconf,maxconf,remoteaddr,1));
        free_json(array);
        if ( lastheight > 0 )
            jaddnum(retjson,"RTheight",coin->RTheight);
    }
    return(jprint(retjson,1));
}

STRING_ARG(iguana,validate,activecoin)
{
    int32_t i,total,validated; struct iguana_bundle *bp; cJSON *retjson;
    if ( (coin= iguana_coinfind(activecoin)) != 0 )
    {
        for (i=total=validated=0; i<coin->bundlescount; i++)
            if ( (bp= coin->bundles[i]) != 0 )
            {
                validated += iguana_bundlevalidate(myinfo,coin,bp,1);
                total += bp->n;
            }
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","validation run");
        jaddstr(retjson,"coin",coin->symbol);
        jaddnum(retjson,"validated",validated);
        jaddnum(retjson,"total",total);
        jaddnum(retjson,"bundles",coin->bundlescount);
        jaddnum(retjson,"accuracy",(double)validated/total);
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"no active coin\"}"));
}

STRING_ARG(iguana,removecoin,activecoin)
{
    struct iguana_bundle *bp; int32_t i,height; char fname[1024];
    if ( (coin= iguana_coinfind(activecoin)) != 0 )
    {
        coin->active = 0;
        coin->started = 0;
        if ( (0) )
        {
            for (i=0; i<IGUANA_MAXPEERS; i++)
            {
                sprintf(fname,"%s/%s/vouts/%04d.vouts",GLOBAL_DBDIR,coin->symbol,i), OS_removefile(fname,0);
                sprintf(fname,"%s/%s/%04d.vins",coin->VALIDATEDIR,coin->symbol,i), OS_removefile(fname,0);
            }
            sprintf(fname,"%s/%s/vouts/*",GLOBAL_DBDIR,coin->symbol), OS_removefile(fname,0);
            sprintf(fname,"%s/%s/*",coin->VALIDATEDIR,coin->symbol), OS_removefile(fname,0);
            for (i=0; i<coin->bundlescount; i++)
            {
                sprintf(fname,"%s/%s/balancecrc.%d",GLOBAL_DBDIR,coin->symbol,i), OS_removefile(fname,0);
                if ( (bp= coin->bundles[i]) != 0 )
                {
                    iguana_bundlepurgefiles(coin,bp);
                    iguana_bundleremove(coin,bp->hdrsi,1);
                }
            }
            for (height=0; height<coin->longestchain; height+=IGUANA_SUBDIRDIVISOR)
            {
                sprintf(fname,"%s/%s/%d",GLOBAL_DBDIR,coin->symbol,height/IGUANA_SUBDIRDIVISOR);
                OS_remove_directory(fname);
            }
            sprintf(fname,"%s/%s/*",GLOBAL_DBDIR,coin->symbol), OS_remove_directory(fname);
        }
        return(clonestr("{\"result\":\"success\"}"));
    }
    return(clonestr("{\"error\":\"no active coin\"}"));
}

INT_ARG(bitcoinrpc,getblockhash,height)
{
    cJSON *retjson;
    if ( coin->notarychain >= 0 && coin->FULLNODE == 0 )
        return(_dex_getblockhash(myinfo,coin->symbol,height));
    retjson = cJSON_CreateObject();
    jaddbits256(retjson,"result",iguana_blockhash(coin,height));
    return(jprint(retjson,1));
}

HASH_AND_TWOINTS(bitcoinrpc,getblock,blockhash,verbose,remoteonly)
{
    char *blockstr,*datastr; struct iguana_msgblock msg; struct iguana_block *block; cJSON *retjson; bits256 txid; int32_t len;
    if ( coin->notarychain >= 0 && coin->FULLNODE == 0 )
        return(_dex_getblock(myinfo,coin->symbol,blockhash));
    retjson = cJSON_CreateObject();
    memset(&msg,0,sizeof(msg));
    if ( remoteonly == 0 && (block= iguana_blockfind("getblockRPC",coin,blockhash)) != 0 )
    {
        if ( verbose != 0 )
            return(jprint(iguana_blockjson(myinfo,coin,block,1),1));
        else
        {
            if ( (len= iguana_peerblockrequest(myinfo,coin,coin->blockspace,coin->blockspacesize,0,blockhash,0)) > 0 )
            {
                datastr = malloc(len*2 + 1);
                init_hexbytes_noT(datastr,coin->blockspace,len);
                jaddstr(retjson,"result",datastr);
                free(datastr);
                return(jprint(retjson,1));
            }
            jaddstr(retjson,"error","error getting rawblock");
        }
    }
    else if ( coin->APIblockstr != 0 )
        jaddstr(retjson,"error","already have pending request");
    else
    {
        memset(txid.bytes,0,sizeof(txid));
        if ( (blockstr= iguana_APIrequest(coin,blockhash,txid,5)) != 0 )
        {
            jaddstr(retjson,"result",blockstr);
            free(blockstr);
        } else jaddstr(retjson,"error","cant find blockhash");
    }
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,getbestblockhash)
{
    cJSON *retjson;
    if ( coin->notarychain >= 0 && coin->FULLNODE == 0 )
        return(_dex_getbestblockhash(myinfo,coin->symbol));
    retjson = cJSON_CreateObject();
    char str[65]; jaddstr(retjson,"result",bits256_str(str,coin->blocks.hwmchain.RO.hash2));
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,getblockcount)
{
    cJSON *retjson = cJSON_CreateObject();
    //printf("result %d\n",coin->blocks.hwmchain.height);
    jaddnum(retjson,"result",coin->blocks.hwmchain.height);
    return(jprint(retjson,1));
}

STRING_AND_INT(iguana,bundleaddresses,activecoin,height)
{
    struct iguana_info *ptr;
    if ( (ptr= iguana_coinfind(activecoin)) != 0 )
        return(iguana_bundleaddrs(ptr,height / coin->chain->bundlesize));
    else return(clonestr("{\"error\":\"activecoin is not active\"}"));
}

STRING_AND_INT(iguana,PoSweights,activecoin,height)
{
    struct iguana_info *ptr; int32_t num,nonz,errs,bundleheight; struct iguana_pkhash *refP; uint64_t *weights,supply; cJSON *retjson;
    if ( (ptr= iguana_coinfind(activecoin)) != 0 )
    {
        //for (bundleheight=coin->chain->bundlesize; bundleheight<height; bundleheight+=coin->chain->bundlesize)
        {
            bundleheight = (height / ptr->chain->bundlesize) * ptr->chain->bundlesize;
            if ( (weights= iguana_PoS_weights(myinfo,ptr,&refP,&supply,&num,&nonz,&errs,bundleheight)) != 0 )
            {
                retjson = cJSON_CreateObject();
                jaddstr(retjson,"result",errs == 0 ? "success" : "error");
                jaddnum(retjson,"bundleheight",bundleheight);
                jaddnum(retjson,"numaddresses",num);
                jaddnum(retjson,"nonzero",nonz);
                jaddnum(retjson,"errors",errs);
                jaddnum(retjson,"supply",dstr(supply));
                free(weights);
                return(jprint(retjson,1));
            } else return(clonestr("{\"error\":\"iguana_PoS_weights returned null\"}"));
        }
    }
    return(clonestr("{\"error\":\"activecoin is not active\"}"));
}

STRING_ARG(iguana,stakers,activecoin)
{
    struct iguana_info *ptr; int32_t i,datalen,pkind,hdrsi; bits256 hash2; struct iguana_bundle *bp; cJSON *retjson,*array; struct iguana_pkhash *refP; struct iguana_ramchaindata *rdata; char coinaddr[64]; uint8_t refrmd160[20]; bits256 *sortbuf;
    if ( (ptr= iguana_coinfind(activecoin)) != 0 && ptr->RTheight > ptr->chain->bundlesize )
    {
        hdrsi = (ptr->RTheight / ptr->chain->bundlesize) - 1;
        if ( (bp= ptr->bundles[hdrsi]) != 0 && bp->weights != 0 && (rdata= bp->ramchain.H.data) != 0 && bp->weights != 0 )
        {
            sortbuf = calloc(bp->numweights,2 * sizeof(*sortbuf));
            for (i=datalen=0; i<bp->numweights; i++)
                datalen += iguana_rwnum(1,&((uint8_t *)sortbuf)[datalen],sizeof(bp->weights[i]),(void *)&bp->weights[i]);
            hash2 = bits256_doublesha256(0,(uint8_t *)sortbuf,datalen);
            refP = RAMCHAIN_PTR(rdata,Poffset);
            retjson = cJSON_CreateObject();
            array = cJSON_CreateArray();
            memset(refrmd160,0,sizeof(refrmd160));
            for (i=0; i<ptr->chain->bundlesize; i++)
            {
                if ( (pkind= iguana_staker_sort(ptr,&hash2,refrmd160,refP,bp->weights,bp->numweights,sortbuf)) > 0 )
                {
                    bitcoin_address(coinaddr,ptr->chain->pubtype,refP[pkind].rmd160,sizeof(refP[pkind].rmd160));
                    jaddistr(array,coinaddr);
                } else jaddistr(array,"error");
            }
            jaddstr(retjson,"result","success");
            jadd(retjson,"stakers",array);
            return(jprint(retjson,1));
        } else return(clonestr("{\"error\":\"iguana_stakers needs PoSweights and weights\"}"));
    }
    return(clonestr("{\"error\":\"activecoin is not active\"}"));
}

STRING_AND_INT(iguana,bundlehashes,activecoin,height)
{
    struct iguana_info *ptr; struct iguana_bundle *bp; int32_t i,hdrsi; cJSON *retjson,*array; struct iguana_ramchaindata *rdata;
    if ( (ptr= iguana_coinfind(activecoin)) != 0 )
    {
        hdrsi = height / coin->chain->bundlesize;
        if ( hdrsi < coin->bundlescount && hdrsi >= 0 && (bp= coin->bundles[hdrsi]) != 0 )
        {
            if ( (rdata= bp->ramchain.H.data) != 0 )
            {
                array = cJSON_CreateArray();
                for (i=0; i<IGUANA_NUMLHASHES; i++)
                    jaddinum(array,rdata->lhashes[i].txid);
                retjson = cJSON_CreateObject();
                jaddstr(retjson,"result","success");
                jaddbits256(retjson,"sha256",rdata->sha256);
                jadd(retjson,"bundlehashes",array);
                return(jprint(retjson,1));
            } else return(clonestr("{\"error\":\"ramchain not there\"}"));
        } else return(clonestr("{\"error\":\"height is too big\"}"));
    } else return(clonestr("{\"error\":\"activecoin is not active\"}"));
}

// low priority RPC

HASH_AND_TWOINTS(bitcoinrpc,listsinceblock,blockhash,target,flag)
{
    /*"transactions" : [
     {
     "account" : "doc test",
     "address" : "mmXgiR6KAhZCyQ8ndr2BCfEq1wNG2UnyG6",
     "category" : "receive",
     "amount" : 0.10000000,
     "vout" : 0,
     "confirmations" : 76478,
     "blockhash" : "000000000017c84015f254498c62a7c884a51ccd75d4dd6dbdcb6434aa3bd44d",
     "blockindex" : 1,
     "blocktime" : 1399294967,
     "txid" : "85a98fdf1529f7d5156483ad020a51b7f3340e47448cf932f470b72ff01a6821",
     "walletconflicts" : [
     ],
     "time" : 1399294967,
     "timereceived" : 1418924714
     },*/
    cJSON *retjson = cJSON_CreateObject();
    jaddstr(retjson,"error","low priority RPC not implemented");
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,gettxoutsetinfo)
{
    cJSON *retjson = cJSON_CreateObject();
    jaddstr(retjson,"error","low priority RPC not implemented");
    return(jprint(retjson,1));
}

ZERO_ARGS(bitcoinrpc,listaddressgroupings)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(clonestr("{\"error\":\"low priority RPC not implemented\"}"));
}

SS_D_I_S(bitcoinrpc,move,fromaccount,toaccount,amount,minconf,comment)
{
    cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( myinfo->expiration == 0 )
        return(clonestr("{\"error\":\"need to unlock wallet\"}"));
    retjson = cJSON_CreateObject();
    return(jprint(retjson,1));
}

ZERO_ARGS(pax,start)
{
    void PAX_init();
    PAX_init();
    return(clonestr("{\"result\":\"PAX_init called\"}"));
}

STRING_AND_TWOINTS(mouse,change,name,x,y)
{
    printf("mouse (%s) x.%d y.%d\n",name,x,y);
    return(clonestr("{\"result\":\"changed\"}"));
}

STRING_ARG(mouse,leave,name)
{
    printf("mouse (%s) leave\n",name);
    return(clonestr("{\"result\":\"left\"}"));
}

STRING_AND_TWOINTS(mouse,click,name,x,y)
{
    printf("mouse (%s) x.%d y.%d click\n",name,x,y);
    return(clonestr("{\"result\":\"click\"}"));
}

STRING_AND_INT(keyboard,key,name,c)
{
    printf(" KEY.(%s) c.%d (%c)\n",name,c,c);
    return(clonestr("{\"result\":\"key\"}"));
}

STRING_AND_TWOINTS(mouse,image,name,x,y)
{
    printf("mouse CREATE (%s) x.%d y.%d\n",name,x,y);
    return(clonestr("{\"result\":\"opened\"}"));
}

STRING_ARG(mouse,close,name)
{
    printf("mouse CLOSE (%s)\n",name);
    return(clonestr("{\"result\":\"closed\"}"));
}

HASH_ARRAY_STRING(basilisk,geckotx,hash,vals,hexstr)
{
    struct iguana_info *btcd; char *retstr=0,*symbol; uint8_t *data,*allocptr,space[4096]; int32_t datalen; bits256 txid;
    if ( (btcd= iguana_coinfind("BTCD")) != 0 && (symbol= jstr(vals,"symbol")) != 0 )
    {
        if ( (data= get_dataptr(BASILISK_HDROFFSET,&allocptr,&datalen,space,sizeof(space),hexstr)) != 0 )
        {
            txid = bits256_doublesha256(0,data,datalen);
            retstr = gecko_sendrawtransaction(myinfo,symbol,data,datalen,txid,vals,hexstr);
        } else retstr = clonestr("{\"error\":\"no tx submitted\"}");
        if ( allocptr != 0 )
            free(allocptr);
        if ( retstr == 0 )
            retstr = clonestr("{\"error\":\"couldnt create geckotx\"}");
        return(retstr);
    } return(clonestr("{\"error\":\"need symbol and chain and BTCD to create new gecko tx\"}"));
}

HASH_ARRAY_STRING(basilisk,geckoblock,hash,vals,hexstr)
{
    return(clonestr("{\"error\":\"geckoblock is an internal reporting function\"}"));
}

HASH_ARRAY_STRING(basilisk,geckoheaders,hash,vals,hexstr)
{
    return(clonestr("{\"error\":\"geckoheaders is an internal reporting function\"}"));
}

HASH_ARRAY_STRING(basilisk,geckoget,hash,vals,hexstr)
{
    struct iguana_info *btcd,*virt; char *symbol;
    if ( (btcd= iguana_coinfind("BTCD")) != 0 && (symbol= jstr(vals,"symbol")) != 0 )
    {
        if ( (virt= iguana_coinfind(symbol)) != 0 )
        {
            basilisk_wait(myinfo,virt);
            return(basilisk_respond_geckoget(myinfo,"GET",&coin->internaladdr,remoteaddr,0,vals,0,0,hash,0));
        } else return(clonestr("{\"error\":\"geckoget needs virtualchain\"}"));
    }
    return(clonestr("{\"error\":\"geckoget needs BTCD\"}"));
}

TWO_STRINGS(SuperNET,decryptjson,password,permanentfile)
{
    char pass[8192],fname2[1023],destfname[1024]; cJSON *retjson; bits256 wallethash,wallet2priv;
    safecopy(pass,password,sizeof(pass));
    safecopy(fname2,permanentfile,sizeof(fname2));
    wallethash = wallet2priv = GENESIS_PRIVKEY;
    if ( strlen(pass) == sizeof(wallethash)*2 && is_hexstr(pass,(int32_t)sizeof(bits256)*2) > 0 )
        wallethash = bits256_conv(pass);
    if ( strlen(fname2) == sizeof(wallet2priv)*2 && is_hexstr(fname2,(int32_t)sizeof(bits256)*2) > 0 )
        wallet2priv = bits256_conv(fname2);
    if ( (retjson= SuperNET_decryptedjson(destfname,pass,sizeof(pass),wallethash,fname2,sizeof(fname2),wallet2priv)) != 0 )
    {
        //printf("decrypt pass.(%s) fname2.(%s) -> destfname.(%s)\n",pass,fname2,destfname);
        //obj = jduplicate(jobj(retjson,"payload"));
        //jdelete(retjson,"payload");
        //jadd(retjson,"result",obj);
        return(jprint(retjson,1));
    } else return(clonestr("{\"error\":\"couldnt decrypt json file\"}"));
}

THREE_STRINGS(SuperNET,encryptjson,password,permanentfile,payload)
{
    char destfname[4096],pass[8192],fname2[1023]; cJSON *argjson,*retjson = cJSON_CreateObject();
    safecopy(pass,password,sizeof(pass));
    safecopy(fname2,permanentfile,sizeof(fname2));
    argjson = jduplicate(json);
    //printf("argjson.(%s)\n",jprint(argjson,0));
    jdelete(argjson,"agent");
    jdelete(argjson,"method");
    jdelete(argjson,"password");
    jdelete(argjson,"permanentfile");
    jdelete(argjson,"timestamp");
    jdelete(argjson,"tag");
    if ( _SuperNET_encryptjson(myinfo,destfname,pass,sizeof(pass),fname2,sizeof(fname2),argjson) == 0 )
    {
        jaddstr(retjson,"result","success");
        jaddstr(retjson,"filename",destfname);
    } else jaddstr(retjson,"error","couldnt encrypt json file");
    free_json(argjson);
    return(jprint(retjson,1));
}


STRING_ARG(SuperNET,addr2rmd160,address)
{
    uint8_t addrtype,rmd160[20]; char rmdstr[41]; cJSON *retjson;
    bitcoin_addr2rmd160(&addrtype,rmd160,address);
    init_hexbytes_noT(rmdstr,rmd160,sizeof(rmd160));
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result",rmdstr);
    jaddnum(retjson,"addrtype",addrtype);
    jaddstr(retjson,"address",address);
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,rmd160conv,rmd160)
{
    uint8_t rmdbuf[20]; char coinaddr[64],p2shaddr[64]; cJSON *retjson = cJSON_CreateObject();
    if ( rmd160 != 0 && strlen(rmd160) == 40 )
    {
        decode_hex(rmdbuf,20,rmd160);
        bitcoin_address(coinaddr,coin->chain->pubtype,rmdbuf,20);
        bitcoin_address(p2shaddr,coin->chain->p2shtype,rmdbuf,20);
        jaddstr(retjson,"result","success");
        jaddstr(retjson,"address",coinaddr);
        jaddstr(retjson,"p2sh",p2shaddr);
    }
    return(jprint(retjson,1));
}

HASH_AND_INT(SuperNET,priv2pub,privkey,addrtype)
{
    cJSON *retjson; bits256 pub; uint8_t pubkey[33]; char coinaddr[64],pubkeystr[67];
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    crypto_box_priv2pub(pub.bytes,privkey.bytes);
    jaddbits256(retjson,"curve25519",pub);
    pub = bitcoin_pubkey33(myinfo->ctx,pubkey,privkey);
    init_hexbytes_noT(pubkeystr,pubkey,33);
    jaddstr(retjson,"secp256k1",pubkeystr);
    bitcoin_address(coinaddr,addrtype,pubkey,33);
    jaddstr(retjson,"result",coinaddr);
    return(jprint(retjson,1));
}

ZERO_ARGS(SuperNET,keypair)
{
    cJSON *retjson; bits256 pubkey,privkey;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = cJSON_CreateObject();
    crypto_box_keypair(pubkey.bytes,privkey.bytes);
    jaddstr(retjson,"result","generated keypair");
    jaddbits256(retjson,"privkey",privkey);
    jaddbits256(retjson,"pubkey",pubkey);
    return(jprint(retjson,1));
}

TWOHASHES_AND_STRING(SuperNET,decipher,privkey,srcpubkey,cipherstr)
{
    int32_t cipherlen=0,msglen; char *retstr; cJSON *retjson; void *ptr = 0; uint8_t *cipher,*message,space[8192];
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( cipherstr != 0 )
        cipherlen = (int32_t)strlen(cipherstr) >> 1;
    if ( cipherlen < crypto_box_NONCEBYTES )
        return(clonestr("{\"error\":\"cipher is too short\"}"));
    cipher = calloc(1,cipherlen);
    decode_hex(cipher,cipherlen,cipherstr);
    if ( (message= SuperNET_deciphercalc(&ptr,&msglen,privkey,srcpubkey,cipher,cipherlen,space,sizeof(space))) != 0 )
    {
        message[msglen] = 0;
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","deciphered message");
        jaddstr(retjson,"message",(char *)message);
        retstr = jprint(retjson,1);
        if ( ptr != 0 )
            free(ptr);
    } else retstr = clonestr("{\"error\":\"couldnt decipher message\"}");
    return(retstr);
}

TWOHASHES_AND_STRING(SuperNET,cipher,privkey,destpubkey,message)
{
    cJSON *retjson; char *retstr,*hexstr,space[8129]; uint8_t space2[8129];
    uint8_t *cipher; int32_t cipherlen,onetimeflag; bits256 origprivkey; void *ptr = 0;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( (cipher= SuperNET_ciphercalc(&ptr,&cipherlen,&privkey,&destpubkey,(uint8_t *)message,(int32_t)strlen(message)+1,space2,sizeof(space2))) != 0 )
    {
        if ( cipherlen > sizeof(space)/2 )
            hexstr = calloc(1,(cipherlen<<1)+1);
        else hexstr = (void *)space;
        init_hexbytes_noT(hexstr,cipher,cipherlen);
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result",hexstr);
        onetimeflag = memcmp(origprivkey.bytes,privkey.bytes,sizeof(privkey));
        if ( onetimeflag != 0 )
        {
            //jaddbits256(retjson,"onetime_privkey",privkey);
            jaddbits256(retjson,"onetime_pubkey",destpubkey);
            if ( onetimeflag == 2 )
                jaddstr(retjson,"warning","onetime keypair was used to broadcast");
        }
        retstr = jprint(retjson,1);
        if ( hexstr != (void *)space )
            free(hexstr);
        if ( ptr != 0 )
            free(ptr);
        return(retstr);
    }
    printf("error encrypting message.(%s)\n",message);
    return(clonestr("{\"error\":\"cant encrypt message\"}"));
}

bits256 SuperNET_pindecipher(IGUANA_ARGS,char *pin,char *privcipher)
{
    cJSON *testjson; char *mstr,*cstr; bits256 privkey,pinpriv,pinpub;
    conv_NXTpassword(pinpriv.bytes,pinpub.bytes,(uint8_t *)pin,(int32_t)strlen(pin));
    privkey = GENESIS_PRIVKEY;
    if ( (cstr= SuperNET_decipher(IGUANA_CALLARGS,pinpriv,pinpub,privcipher)) != 0 )
    {
        if ( (testjson= cJSON_Parse(cstr)) != 0 )
        {
            if ( (mstr= jstr(testjson,"message")) != 0 && strlen(mstr) == sizeof(bits256)*2 )
            {
                decode_hex(privkey.bytes,sizeof(privkey),mstr);
            } else printf("error cant find message privcipher\n");
            free_json(testjson);
        } else printf("Error decipher.(%s)\n",cstr);
        free(cstr);
    } else printf("null return from deciphering privcipher\n");
    return(privkey);
}

THREE_STRINGS(SuperNET,rosetta,passphrase,pin,showprivkey)
{
    uint8_t flag = 0; uint64_t nxt64bits; bits256 check,privkey,pubkey,pinpriv,pinpub;
    char str[128],privcipher[512],*privcipherstr,*cstr; cJSON *retjson;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    nxt64bits = conv_NXTpassword(privkey.bytes,pubkey.bytes,(uint8_t *)passphrase,(int32_t)strlen(passphrase));
    if ( showprivkey != 0 && strcmp(showprivkey,"yes") == 0 )
        flag = 1;
    privcipher[0] = 0;
    conv_NXTpassword(pinpriv.bytes,pinpub.bytes,(uint8_t *)pin,(int32_t)strlen(pin));
    if ( (cstr= SuperNET_cipher(IGUANA_CALLARGS,pinpriv,pinpub,bits256_str(str,privkey))) != 0 )
    {
        if ( (retjson= cJSON_Parse(cstr)) != 0 )
        {
            if ( (privcipherstr= jstr(retjson,"result")) != 0 )
                strcpy(privcipher,privcipherstr);
            free_json(retjson);
        } else printf("error parsing cipher retstr.(%s)\n",cstr);
        free(cstr);
    } else printf("error SuperNET_cipher null return\n");
    retjson = SuperNET_rosettajson(myinfo,privkey,flag);
    jaddstr(retjson,"privcipher",privcipher);
    check = SuperNET_pindecipher(IGUANA_CALLARGS,pin,privcipher);
    if ( memcmp(check.bytes,privkey.bytes,sizeof(check)) != 0 )
    {
        jaddbits256(retjson,"deciphered",check);
        jaddstr(retjson,"error","cant recreate privkey from (pin + privcipher)");
    }
    else if ( flag != 0 )
        jaddbits256(retjson,"deciphered",check);
    if ( jobj(retjson,"error") == 0 )
        jaddstr(retjson,"result","use pin and privcipher to access wallet");
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,broadcastcipher,message)
{
    bits256 zero;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    memset(zero.bytes,0,sizeof(zero));
    return(SuperNET_cipher(IGUANA_CALLARGS,zero,zero,message));
}

STRING_ARG(SuperNET,broadcastdecipher,message)
{
    bits256 zero;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    memset(zero.bytes,0,sizeof(zero));
    return(SuperNET_decipher(IGUANA_CALLARGS,zero,zero,message));
}

HASH_AND_STRING(SuperNET,multicastcipher,pubkey,message)
{
    bits256 zero;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    memset(zero.bytes,0,sizeof(zero));
    return(SuperNET_cipher(IGUANA_CALLARGS,zero,pubkey,message));
}

HASH_AND_STRING(SuperNET,multicastdecipher,privkey,cipherstr)
{
    bits256 zero;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    memset(zero.bytes,0,sizeof(zero));
    return(SuperNET_decipher(IGUANA_CALLARGS,privkey,zero,cipherstr));
}

ZERO_ARGS(SuperNET,stop)
{
    if ( remoteaddr == 0 || strncmp(remoteaddr,"127.0.0.1",strlen("127.0.0.1")) == 0 )
    {
        iguana_exit(myinfo,0);
        return(clonestr("{\"result\":\"exit started\"}"));
    } else return(clonestr("{\"error\":\"cant do a remote stop of this node\"}"));
}

TWO_ARRAYS(SuperNET,mypeers,supernet,rawpeers)
{
    SuperNET_parsepeers(myinfo,supernet,cJSON_GetArraySize(supernet),1);
    SuperNET_parsepeers(myinfo,rawpeers,cJSON_GetArraySize(rawpeers),0);
    return(clonestr("{\"result\":\"peers parsed\"}"));
}

STRING_ARG(SuperNET,getpeers,activecoin)
{
    int32_t max = 64; struct iguana_info *tmp; cJSON *SNjson,*rawjson,*retjson = cJSON_CreateObject();
    SNjson = cJSON_CreateArray();
    rawjson = cJSON_CreateArray();
    if ( coin != 0 )
        max = SuperNET_coinpeers(coin,SNjson,rawjson,max);
    else
    {
        //portable_mutex_lock(&myinfo->allcoins_mutex);
        HASH_ITER(hh,myinfo->allcoins,coin,tmp)
        {
            max = SuperNET_coinpeers(coin,SNjson,rawjson,max);
        }
        //portable_mutex_unlock(&myinfo->allcoins_mutex);
    }
    if ( max != 64 )
    {
        jaddstr(retjson,"agent","SuperNET");
        jaddstr(retjson,"method","mypeers");
        jadd(retjson,"supernet",SNjson);
        jadd(retjson,"rawpeers",rawjson);
    }
    else
    {
        jaddstr(retjson,"error","no peers");
        free_json(SNjson);
        free_json(rawjson);
    }
    return(jprint(retjson,1));
}

/*TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(SuperNET,DHT,hexmsg,destip,categoryhash,subhash,maxdelay,broadcast)
 {
 if ( remoteaddr != 0 )
 return(clonestr("{\"error\":\"cant remote DHT\"}"));
 else if ( hexmsg == 0 || is_hexstr(hexmsg,(int32_t)strlen(hexmsg)) <= 0 )
 return(clonestr("{\"error\":\"hexmsg missing or not in hex\"}"));
 return(SuperNET_DHTencode(myinfo,destip,categoryhash,subhash,hexmsg,maxdelay,broadcast,juint(json,"plaintext")!=0));
 }*/

HASH_AND_STRING(SuperNET,saveconf,wallethash,confjsonstr)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(clonestr("{\"result\":\"saveconf here\"}"));
}

HASH_ARRAY_STRING(SuperNET,layer,mypriv,otherpubs,str)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    return(clonestr("{\"result\":\"layer encrypt here\"}"));
}

/*TWO_STRINGS(SuperNET,categoryhashes,category,subcategory)
{
    bits256 categoryhash,subhash; cJSON *retjson = cJSON_CreateObject();
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    jaddstr(retjson,"result","category hashes calculated");
    jaddbits256(retjson,"categoryhash",categoryhash);
    jaddbits256(retjson,"subhash",subhash);
    return(jprint(retjson,1));
}

TWO_STRINGS(SuperNET,subscribe,category,subcategory)
{
    bits256 categoryhash,subhash;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    if ( category_subscribe(myinfo,categoryhash,subhash) != 0 )
        return(clonestr("{\"result\":\"subscribed\"}"));
    else return(clonestr("{\"error\":\"couldnt subscribe\"}"));
}

TWO_STRINGS(SuperNET,gethexmsg,category,subcategory)
{
    bits256 categoryhash,subhash; struct category_msg *m; char *hexstr; cJSON *retjson; struct private_chain *cat;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    if ( (m= category_gethexmsg(myinfo,&cat,categoryhash,subhash)) != 0 )
    {
        hexstr = calloc(1,m->len*2+1);
        init_hexbytes_noT(hexstr,m->msg,m->len);
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result",hexstr);
        free(hexstr);
        return(jprint(retjson,1));
    } else return(clonestr("{\"result\":\"no message\"}"));
}

THREE_STRINGS(SuperNET,posthexmsg,category,subcategory,hexmsg)
{
    bits256 categoryhash,subhash;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    category_posthexmsg(myinfo,categoryhash,subhash,hexmsg,tai_now(),remoteaddr);
    return(clonestr("{\"result\":\"posted message\"}"));
}

THREE_STRINGS(SuperNET,announce,category,subcategory,message)
{
    bits256 categoryhash,subhash;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    return(SuperNET_categorymulticast(myinfo,0,categoryhash,subhash,message,juint(json,"maxdelay"),juint(json,"broadcast"),juint(json,"plaintext"),json,remoteaddr));
}

THREE_STRINGS(SuperNET,survey,category,subcategory,message)
{
    bits256 categoryhash,subhash;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    categoryhash = calc_categoryhashes(&subhash,category,subcategory);
    return(SuperNET_categorymulticast(myinfo,1,categoryhash,subhash,message,juint(json,"maxdelay"),juint(json,"broadcast"),juint(json,"plaintext"),json,remoteaddr));
}*/

STRING_ARG(SuperNET,wif2priv,wif)
{
    bits256 privkey; char str[65]; uint8_t privkeytype; cJSON *retjson = cJSON_CreateObject();
    if ( bitcoin_wif2priv(&privkeytype,&privkey,wif) == sizeof(privkey) )
    {
        jaddstr(retjson,"result","success");
        jaddstr(retjson,"privkey",bits256_str(str,privkey));
        jaddnum(retjson,"type",privkeytype);
    } else jaddstr(retjson,"error","couldnt convert wif");
    return(jprint(retjson,1));
}

STRING_AND_INT(SuperNET,priv2wif,priv,wiftype)
{
    bits256 privkey; char wifstr[65]; cJSON *retjson = cJSON_CreateObject();
    if ( is_hexstr(priv,0) == sizeof(bits256)*2 )
    {
        //wiftype = coin != 0 ? coin->chain->wiftype : 0x80;
        decode_hex(privkey.bytes,sizeof(privkey),priv);
        if ( bitcoin_priv2wif(wifstr,privkey,wiftype&0xff) > 0 )
        {
            jaddstr(retjson,"result","success");
            jaddstr(retjson,"privkey",priv);
            jaddnum(retjson,"type",wiftype);
            jaddstr(retjson,"wif",wifstr);
        } else jaddstr(retjson,"error","couldnt convert privkey");
    } else jaddstr(retjson,"error","non 32 byte hex privkey");
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,myipaddr,ipaddr)
{
    cJSON *retjson = cJSON_CreateObject();
    myinfo->NOTARY.RELAYID = -1;
    if ( myinfo->ipaddr[0] == 0 )
    {
        if ( is_ipaddr(ipaddr) != 0 )
        {
            strcpy(myinfo->ipaddr,ipaddr);
            myinfo->myaddr.myipbits = (uint32_t)calc_ipbits(ipaddr);
            printf("SET MYIPADDR.(%s)\n",ipaddr);
            basilisk_setmyid(myinfo);
        }
    }
    jaddstr(retjson,"result",myinfo->ipaddr);
    if ( myinfo->IAMNOTARY != 0 && myinfo->NOTARY.RELAYID >= 0 )
    {
        jaddnum(retjson,"relayid",myinfo->NOTARY.RELAYID);
        jaddnum(retjson,"numrelays",myinfo->NOTARY.NUMRELAYS);
    }
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,setmyipaddr,ipaddr)
{
    cJSON *retjson = cJSON_CreateObject();
    if ( is_ipaddr(ipaddr) != 0 )
    {
        strcpy(myinfo->ipaddr,ipaddr);
        basilisk_setmyid(myinfo);
        jaddstr(retjson,"result",myinfo->ipaddr);
    } else jaddstr(retjson,"error","illegal ipaddr");
    return(jprint(retjson,1));
}

STRING_ARG(SuperNET,utime2utc,utime)
{
    uint32_t utc = 0; cJSON *retjson = cJSON_CreateObject();
    utc = OS_conv_utime(utime);
    char str[65]; printf("utime.%s -> %u -> %s\n",utime,utc,utc_str(str,utc));
    jaddnum(retjson,"result",utc);
    return(jprint(retjson,1));
}

INT_ARG(SuperNET,utc2utime,utc)
{
    char str[65]; cJSON *retjson = cJSON_CreateObject();
    jaddstr(retjson,"result",utc_str(str,utc));
    return(jprint(retjson,1));
}

ZERO_ARGS(SuperNET,logout)
{
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    iguana_walletlock(myinfo,coin);
    return(clonestr("{\"result\":\"logged out\"}"));
}

ZERO_ARGS(SuperNET,activehandle)
{
    cJSON *retjson; char BTCaddr[64],KMDaddr[64];
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    retjson = SuperNET_rosettajson(myinfo,myinfo->persistent_priv,0);
    jaddstr(retjson,"result","success");
    jaddstr(retjson,"handle",myinfo->handle);
    if ( myinfo->ipaddr[0] != 0 )
        jaddstr(retjson,"myip",myinfo->ipaddr);
    if ( myinfo->IAMRELAY != 0 )
        jaddnum(retjson,"notary",myinfo->NOTARY.RELAYID);
    jaddbits256(retjson,"persistent",myinfo->myaddr.persistent);
    if ( myinfo->expiration != 0 )
    {
        jaddstr(retjson,"status","unlocked");
        jaddnum(retjson,"duration",myinfo->expiration - time(NULL));
    } else jaddstr(retjson,"status","locked");
    if ( myinfo->jumblr_passphrase[0] != 0 )
    {
        jumblr_privkey(myinfo,BTCaddr,0,KMDaddr,JUMBLR_DEPOSITPREFIX);
        jaddstr(retjson,"BTCdeposit","notyet");
        jaddstr(retjson,"KMDdeposit",KMDaddr);
        jumblr_privkey(myinfo,BTCaddr,0,KMDaddr,"");
        jaddstr(retjson,"BTCjumblr","notyet");
        jaddstr(retjson,"KMDjumblr",KMDaddr);
    }
    SuperNET_MYINFOadd(myinfo);
    return(jprint(retjson,1));
}

struct supernet_info *SuperNET_accountfind(cJSON *json)
{
    int32_t num; char *decryptstr; struct supernet_info M,*myinfo; struct iguana_info *coin = 0;
    char *password,*permanentfile,*passphrase,*remoteaddr,*perspriv;
    myinfo = 0;
    if ( (password= jstr(json,"password")) == 0 )
        password = "";
    if ( (permanentfile= jstr(json,"permanentfile")) == 0 )
        permanentfile = "";
    if ( (passphrase= jstr(json,"passphrase")) == 0 )
        passphrase = "";
    remoteaddr = jstr(json,"remoteaddr");
    if ( (passphrase == 0 || passphrase[0] == 0) && (decryptstr= SuperNET_decryptjson(IGUANA_CALLARGS,password,permanentfile)) != 0 )
    {
        if ( (json= cJSON_Parse(decryptstr)) != 0 )
        {
            memset(&M,0,sizeof(M));
            if ( (perspriv= jstr(json,"persistent_priv")) != 0 && strlen(perspriv) == sizeof(bits256)*2 )
            {
                M.persistent_priv = bits256_conv(perspriv);
                SuperNET_setkeys(&M,0,0,0);
                if ( (myinfo = SuperNET_MYINFOfind(&num,M.myaddr.persistent)) != 0 )
                {
                    //printf("found account.(%s) %s %llu\n",myinfo!=0?myinfo->handle:"",M.myaddr.NXTADDR,(long long)M.myaddr.nxt64bits);
                    return(myinfo);
                }
            }
            else if ( (passphrase= jstr(json,"result")) != 0 || (passphrase= jstr(json,"passphrase")) != 0 )
            {
                SuperNET_setkeys(&M,passphrase,(int32_t)strlen(passphrase),1);
                if ( (myinfo= SuperNET_MYINFOfind(&num,M.myaddr.persistent)) != 0 )
                {
                    //printf("found account.(%s) %s %llu\n",myinfo!=0?myinfo->handle:"",M.myaddr.NXTADDR,(long long)M.myaddr.nxt64bits);
                    return(myinfo);
                }
            } else printf("no passphrase in (%s)\n",jprint(json,0));
            free_json(json);
        } else printf("cant parse.(%s)\n",decryptstr);
        free(decryptstr);
    }
    return(SuperNET_MYINFO(0));
}

FOUR_STRINGS(SuperNET,login,handle,password,permanentfile,passphrase)
{
    char *str,*decryptstr = 0; cJSON *argjson,*item,*walletitem;
    if ( remoteaddr != 0 )
        return(clonestr("{\"error\":\"no remote\"}"));
    if ( handle != 0 && handle[0] != 0 )
        safecopy(myinfo->handle,handle,sizeof(myinfo->handle));
    else memset(myinfo->handle,0,sizeof(myinfo->handle));
    if ( password == 0 || password[0] == 0 )
        password = passphrase;
    /*if ( password != 0 && password[0] != 0 )
     safecopy(myinfo->secret,password,sizeof(myinfo->secret));
     else if ( passphrase != 0 && passphrase[0] != 0 )
     safecopy(myinfo->secret,passphrase,sizeof(myinfo->secret));*/
    if ( permanentfile != 0 )
        safecopy(myinfo->permanentfile,permanentfile,sizeof(myinfo->permanentfile));
    if ( (decryptstr= SuperNET_decryptjson(IGUANA_CALLARGS,password,myinfo->permanentfile)) != 0 )
    {
        //printf("decryptstr.(%s)\n",decryptstr);
        if ( (argjson= cJSON_Parse(decryptstr)) != 0 )
        {
            if ( jobj(argjson,"error") == 0 )
            {
                //printf("decrypted.(%s) exp.%u pass.(%s)\n",decryptstr,myinfo->expiration,password);
                if ( myinfo->decryptstr != 0 )
                    free(myinfo->decryptstr);
                myinfo->decryptstr = decryptstr;
                if ( (passphrase= jstr(argjson,"passphrase")) != 0 )
                {
                    SuperNET_setkeys(myinfo,passphrase,(int32_t)strlen(passphrase),1);
                    free_json(argjson);
                    myinfo->expiration = (uint32_t)(time(NULL) + 3600);
                    return(SuperNET_activehandle(IGUANA_CALLARGS));
                }
                else
                {
                    free_json(argjson);
                    return(clonestr("{\"error\":\"cant find passphrase in decrypted json\"}"));
                }
            } else free_json(argjson);
        }
        else
        {
            free(decryptstr);
            return(clonestr("{\"error\":\"cant parse decrypted json\"}"));
        }
    }
    else if ( myinfo->decryptstr != 0 )
    {
        free(myinfo->decryptstr);
        myinfo->decryptstr = 0;
    }
    if ( passphrase != 0 && passphrase[0] != 0 )
    {
        SuperNET_setkeys(myinfo,passphrase,(int32_t)strlen(passphrase),1);
        if ( myinfo->decryptstr != 0 && (argjson= cJSON_Parse(myinfo->decryptstr)) != 0 )
        {
            if ( jobj(argjson,"passphrase") != 0 )
                jdelete(argjson,"passphrase");
            if ( jobj(argjson,"error") != 0 )
                jdelete(argjson,"error");
        }
        else
        {
            char rmd160str[41],str[65]; uint8_t rmd160[20];
            item = cJSON_CreateObject();
            calc_rmd160_sha256(rmd160,myinfo->persistent_pubkey33,33);
            init_hexbytes_noT(rmd160str,rmd160,20);
            jaddstr(item,rmd160str,bits256_str(str,myinfo->persistent_priv));
            walletitem = cJSON_CreateObject();
            jadd(walletitem,"default",item);
            argjson = cJSON_CreateObject();
            jadd(argjson,"wallet",walletitem);
            myinfo->dirty = (uint32_t)time(NULL);
        }
        jaddstr(argjson,"passphrase",passphrase);
        if ( (str= SuperNET_encryptjson(myinfo,coin,argjson,remoteaddr,password,myinfo->permanentfile,myinfo->decryptstr == 0 ? "" : myinfo->decryptstr)) != 0 )
            free(str);
        myinfo->expiration = (uint32_t)(time(NULL) + 3600);
        return(SuperNET_activehandle(IGUANA_CALLARGS));
    } else return(clonestr("{\"error\":\"need passphrase or wallet doesnt exist\"}"));
    return(SuperNET_activehandle(IGUANA_CALLARGS));
}

#include "../includes/iguana_apiundefs.h"

void komodo_ICO_batch(cJSON *array,int32_t batchid)
{
    int32_t i,n,iter; cJSON *item; uint64_t kmdamount,revsamount; char *coinaddr,cmd[512]; double totalKMD,totalREVS; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    if ( myinfo->rpcport == 0 )
        myinfo->rpcport = 7778;
    if ( (n= cJSON_GetArraySize(array)) > 0 )
    {
        totalKMD = totalREVS = 0;
        for (iter=0; iter<1; iter++)
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            if ( (coinaddr= jstr(item,"kmd_address")) != 0 && (kmdamount= SATOSHIDEN * jdouble(item,"kmd_amount")) > 0 )
            {
                if ( (revsamount= SATOSHIDEN * jdouble(item,"revs_amount")) > 0 )
                {
                    printf("# %s KMD %.8f",coinaddr,dstr(kmdamount));
                    printf(", REVS %.8f\n",dstr(revsamount));
                    sprintf(cmd,"fiat/revs sendtoaddress %s %.8f",coinaddr,dstr(revsamount));
                    if ( (iter>>1) == 1 )
                    {
                        if ( dstr(revsamount) >= 1. && (iter & 1) == 0 )
                        {
                            printf("curl --url \"http://127.0.0.1:%u\" --data \"{\\\"agent\\\":\\\"dex\\\",\\\"method\\\":\\\"importaddress\\\",\\\"address\\\":\\\"%s\\\",\\\"symbol\\\":\\\"REVS\\\"}\" # %.8f\n",myinfo->rpcport,coinaddr,dstr(revsamount));
                            printf("sleep 3\n");
                        } else printf("sleep 1\n");
                        if ( (iter & 1) != 0 )
                        {
                            printf("%s\n",cmd);
                            totalREVS += dstr(revsamount);
                        }
                    }
                }
                else
                {
                    if ( iter >= 2 )
                        continue;
                }
                sprintf(cmd,"./komodo-cli sendtoaddress %s %.8f",coinaddr,dstr(kmdamount));
                if ( (iter>>1) == 0 )
                {
                    printf("# %s KMD %.8f\n",coinaddr,dstr(kmdamount));
                    if ( (iter & 1) == 0 )
                    {
                        if ( (0) )
                        {
                            printf("curl --url \"http://127.0.0.1:%u\" --data \"{\\\"agent\\\":\\\"dex\\\",\\\"method\\\":\\\"importaddress\\\",\\\"address\\\":\\\"%s\\\",\\\"symbol\\\":\\\"KMD\\\"}\" # %.8f\n",myinfo->rpcport,coinaddr,dstr(kmdamount));
                            printf("sleep 3\n");
                        } else printf("curl --url \"http://127.0.0.1:%u\" --data \"{\\\"agent\\\":\\\"dex\\\",\\\"method\\\":\\\"listunspent\\\",\\\"address\\\":\\\"%s\\\",\\\"symbol\\\":\\\"KMD\\\"}\"\n",myinfo->rpcport,coinaddr);
                    }
                    else
                    {
                        printf("%s\n",cmd);
                        totalKMD += dstr(kmdamount);
                        printf("sleep 3\n");
                    }
                    printf("echo  \"%.8f <- expected amount %s\"\n\n",dstr(kmdamount),coinaddr);
                }
            }
        }
        printf("\n# total KMD %.8f REVS %.8f\n",totalKMD,totalREVS);
    }
    getchar();
}

void komodo_REVS_merge(char *str,char *str2)
{
    char line[1024],line2[1024],*coinaddr; int32_t i,n=0,m=0,k=0; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    while ( 1 )
    {
        if ( str[n] == 0 || str2[m] == 0 )
            break;
        for (i=0; str[n]!='\n'; n++,i++)
            line[i] = str[n];
        line[i] = 0;
        n++;
        for (i=0; str2[m]!='\n'; m++,i++)
            line2[i] = str2[m];
        line2[i] = 0;
        m++;
        //if ( is_hexstr(line2,0) != 64 )
        {
            //printf("%d: (%s) (%s)\n",k,line,line2);
            coinaddr = &line[strlen("fiat/revs sendtoaddress ")];
            for (i=0; coinaddr[i]!=' '; i++)
                ;
            coinaddr[i] = 0;
            if ( atof(&coinaddr[i+1]) > 1 )
            {
                printf("curl --url \"http://127.0.0.1:%u\" --data \"{\\\"agent\\\":\\\"dex\\\",\\\"method\\\":\\\"importaddress\\\",\\\"address\\\":\\\"%s\\\",\\\"symbol\\\":\\\"REVS\\\"}\" # %.8f\n",myinfo->rpcport,coinaddr,atof(coinaddr+i+1));
                printf("sleep 3\n");
            }
            k++;
        }
    }
    getchar();
}

int32_t komodo_initjson(char *fname);

void iguana_main(void *arg)
{
    int32_t usessl = 0,ismainnet = 1, do_OStests = 0; struct supernet_info *myinfo; char *elected = "elected";
    if ( (IGUANA_BIGENDIAN= iguana_isbigendian()) > 0 )
        printf("BIGENDIAN\n");
    else if ( IGUANA_BIGENDIAN == 0 )
        printf("LITTLE ENDIAN arg.%p\n",arg);
    else printf("ENDIAN ERROR\n");
    mycalloc(0,0,0);
#ifdef __APPLE__
    char *batchstr,*batchstr2; cJSON *batchjson; long batchsize; char fname[512],fname2[512]; int32_t batchid = 18;
    sprintf(fname,"REVS.raw"), sprintf(fname2,"REVS.rawtxids");
    if ( (0) && (batchstr= OS_filestr(&batchsize,fname)) != 0 && (batchstr2= OS_filestr(&batchsize,fname2)) != 0 )
    {
        komodo_REVS_merge(batchstr,batchstr2);
    }
    sprintf(fname,"batch%d.txt",batchid);
    if ( 1 && (batchstr= OS_filestr(&batchsize,fname)) != 0 )
    {
        if ( (batchjson= cJSON_Parse(batchstr)) != 0 )
        {
            komodo_ICO_batch(batchjson,batchid);
            free_json(batchjson);
        }
        free(batchstr);
    }
#endif
    myinfo = SuperNET_MYINFO(0);
    myinfo->rpcport = IGUANA_RPCPORT;
    decode_hex(CRYPTO777_RMD160,20,CRYPTO777_RMD160STR);
    decode_hex(CRYPTO777_PUBSECP33,33,CRYPTO777_PUBSECPSTR);
    iguana_ensuredirs();
    iguana_Qinit();
    libgfshare_init(myinfo,myinfo->logs,myinfo->exps);
    myinfo->dpowsock = myinfo->dexsock = myinfo->pubsock = myinfo->subsock = myinfo->reqsock = myinfo->repsock = -1;
    myinfo->psockport = 30000;
    if ( arg != 0 )
    {
        if ( strcmp((char *)arg,"OStests") == 0 )
            do_OStests = 1;
        else if ( strcmp((char *)arg,"stats") == 0 )
        {
            void iguana_notarystats(int32_t totals[64],int32_t dispflag);
            int32_t totals[64];
            memset(totals,0,sizeof(totals));
            iguana_notarystats(totals,1);
            exit(0);
        }
        else if ( strncmp((char *)arg,"-port=",6) == 0 )
        {
            myinfo->rpcport = atoi(&((char *)arg)[6]);
            printf("OVERRIDE IGUANA port <- %u\n",myinfo->rpcport);
        }
        else if ( strncmp((char *)arg,"notary",strlen("notary")) == 0 ) // must be second to last
        {
            if ( strcmp((char *)arg,"notary_nosplit") == 0 )
                myinfo->nosplit = 1;
            myinfo->rpcport = IGUANA_NOTARYPORT;
            myinfo->IAMNOTARY = 1;
            myinfo->DEXEXPLORER = 0;//1; disable as SPV is used now
        }
        else
        {
            myinfo->rpcport = IGUANA_NOTARYPORT;
            myinfo->IAMNOTARY = 1;
            myinfo->DEXEXPLORER = 0;//1; disable as SPV is used now
            elected = (char *)arg;
        }
    }
    if ( komodo_initjson(elected) < 0 )
    {
        printf("didnt find any elected notaries JSON in (%s)\n",elected);
        exit(-1);
    }
    dex_init(myinfo);
#ifdef IGUANA_OSTESTS
    do_OStests = 1;
#endif
    if ( do_OStests != 0 )
    {
        int32_t iguana_OStests();
        int32_t retval = iguana_OStests();
        printf("OStests retval %d\n",retval);
        return;
    }
    strcpy(myinfo->rpcsymbol,"BTCD");
    iguana_urlinit(myinfo,ismainnet,usessl);
    portable_mutex_init(&myinfo->pending_mutex);
    portable_mutex_init(&myinfo->MoM_mutex);
    portable_mutex_init(&myinfo->dpowmutex);
    portable_mutex_init(&myinfo->notarymutex);
    portable_mutex_init(&myinfo->psockmutex);
#if LIQUIDITY_PROVIDER
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create(clonestr("nxtae"),0);
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create(clonestr("bitcoin"),0);
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create(clonestr("poloniex"),0);
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create(clonestr("bittrex"),0);
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create(clonestr("btc38"),0);
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create(clonestr("huobi"),0);
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create(clonestr("coinbase"),0);
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create(clonestr("lakebtc"),0);
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create(clonestr("quadriga"),0);
    // prices reversed? myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create(clonestr("okcoin"),0);
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create(clonestr("btce"),0);
    myinfo->tradingexchanges[myinfo->numexchanges++] = exchange_create(clonestr("bitstamp"),0);
#endif
    if ( myinfo->IAMNOTARY == 0 )
    {
        if ( iguana_commandline(myinfo,arg) == 0 )
        {
            iguana_helpinit(myinfo);
            //iguana_relays_init(myinfo);
            basilisks_init(myinfo);
#ifdef __APPLE__
            iguana_appletests(myinfo);
#endif
            /*char *retstr;
            if ( (retstr= _dex_getnotaries(myinfo,"KMD")) != 0 )
            {
                printf("INITIAL NOTARIES.(%s)\n",retstr);
                free(retstr);
            }*/
        }
    }
    else
    {
        basilisks_init(myinfo);
    }
    iguana_launchdaemons(myinfo);
}

// features
// komodod convert passphrase to privkey
// Z -> Z
// iguana init nanomsg in own thread
