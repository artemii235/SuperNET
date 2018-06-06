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
//  marketmaker
//
//  Copyright © 2017 SuperNET. All rights reserved.
//


void PNACL_message(char *arg,...)
{
    
}
#define FROM_MARKETMAKER

#include <stdio.h>
#include <stdint.h>
// #include "lib.h"
#ifndef NATIVE_WINDOWS
#include "OS_portable.h"
#else
#include "../../crypto777/OS_portable.h"
#endif // !_WIN_32

uint32_t DOCKERFLAG;
#define MAX(a,b) ((a) > (b) ? (a) : (b))
char *stats_JSON(void *ctx,int32_t fastflag,char *myipaddr,int32_t pubsock,cJSON *argjson,char *remoteaddr,uint16_t port);
#include "stats.c"
void LP_priceupdate(char *base,char *rel,double price,double avebid,double aveask,double highbid,double lowask,double PAXPRICES[32]);

//defined(__APPLE__) ||
#ifdef FROM_JS // defined(WIN32) || defined(USE_STATIC_NANOMSG)
#include "../../crypto777/nanosrc/nn.h"
#include "../../crypto777/nanosrc/bus.h"
#include "../../crypto777/nanosrc/pubsub.h"
#include "../../crypto777/nanosrc/pipeline.h"
#include "../../crypto777/nanosrc/reqrep.h"
#include "../../crypto777/nanosrc/tcp.h"
#include "../../crypto777/nanosrc/pair.h"
#else
#if defined(WIN32) || defined(USE_STATIC_NANOMSG)
	#include "../../crypto777/nanosrc/nn.h"
	#include "../../crypto777/nanosrc/bus.h"
	#include "../../crypto777/nanosrc/pubsub.h"
	#include "../../crypto777/nanosrc/pipeline.h"
	#include "../../crypto777/nanosrc/reqrep.h"
	#include "../../crypto777/nanosrc/tcp.h"
    #include "../../crypto777/nanosrc/pair.h"
    #include "../../crypto777/nanosrc/ws.h"
#else
	#include "/usr/local/include/nanomsg/nn.h"
	#include "/usr/local/include/nanomsg/bus.h"
	#include "/usr/local/include/nanomsg/pubsub.h"
	#include "/usr/local/include/nanomsg/pipeline.h"
	#include "/usr/local/include/nanomsg/reqrep.h"
	#include "/usr/local/include/nanomsg/tcp.h"
    #include "/usr/local/include/nanomsg/pair.h"
    #include "/usr/local/include/nanomsg/ws.h"
#endif
#endif
#ifndef NN_WS_MSG_TYPE
#define NN_WS_MSG_TYPE 1
#endif


#include "LP_nativeDEX.c"

void LP_ports(uint16_t *pullportp,uint16_t *pubportp,uint16_t *busportp,uint16_t netid)
{
    int32_t netmod,netdiv; uint16_t otherports;
    *pullportp = *pubportp = *busportp = 0;
    if ( netid < 0 )
        netid = 0;
    else if ( netid > (65535-40-LP_RPCPORT)/4 )
    {
        printf("netid.%d overflow vs max netid.%d 14420?\n",netid,(65535-40-LP_RPCPORT)/4);
        exit(-1);
    }
    if ( netid != 0 )
    {
        netmod = (netid % 10);
        netdiv = (netid / 10);
        otherports = (netdiv * 40) + (LP_RPCPORT + netmod);
    } else otherports = LP_RPCPORT;
    *pullportp = otherports + 10;
    *pubportp = otherports + 20;
    *busportp = otherports + 30;
    printf("RPCport.%d remoteport.%d, nanoports %d %d %d\n",RPC_port,RPC_port-1,*pullportp,*pubportp,*busportp);
}

void LP_main(void *ptr)
{
    char *passphrase; double profitmargin; uint16_t netid=0,port,pullport,pubport,busport; cJSON *argjson = ptr;
    if ( (passphrase= jstr(argjson,"passphrase")) != 0 )
    {
        profitmargin = jdouble(argjson,"profitmargin");
        LP_profitratio += profitmargin;
        if ( (port= juint(argjson,"rpcport")) < 1000 )
            port = LP_RPCPORT;
        if ( jobj(argjson,"netid") != 0 )
            netid = juint(argjson,"netid");
        LP_ports(&pullport,&pubport,&busport,netid);
        LPinit(port,pullport,pubport,busport,passphrase,jint(argjson,"client"),jstr(argjson,"userhome"),argjson);
    }
}

int32_t ensure_writable(char *dirname)
{
    char fname[512],str[65],str2[65]; bits256 r,check; FILE *fp;
    OS_randombytes(r.bytes,sizeof(r));
    sprintf(fname,"%s/checkval",dirname), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"wb")) == 0 )
    {
        printf("FATAL ERROR cant create %s\n",fname);
        fprintf(stderr,"FATAL ERROR cant create %s\n",fname);
        return(-1);
    }
    else if ( fwrite(r.bytes,1,sizeof(r),fp) != sizeof(r) )
    {
        printf("FATAL ERROR error writing %s\n",fname);
        fprintf(stderr,"FATAL ERROR writing %s\n",fname);
        return(-1);
    }
    else
    {
        fclose(fp);
        if ( (fp= fopen(fname,"rb")) == 0 )
        {
            printf("FATAL ERROR cant open %s\n",fname);
            fprintf(stderr,"FATAL ERROR cant open %s\n",fname);
            return(-1);
        }
        else if ( fread(check.bytes,1,sizeof(check),fp) != sizeof(check) )
        {
            printf("FATAL ERROR error reading %s\n",fname);
            fprintf(stderr,"FATAL ERROR reading %s\n",fname);
            return(-1);
        }
        else if ( memcmp(check.bytes,r.bytes,sizeof(r)) != 0 )
        {
            printf("FATAL ERROR error comparint %s %s vs %s\n",fname,bits256_str(str,r),bits256_str(str2,check));
            fprintf(stderr,"FATAL ERROR error comparint %s %s vs %s\n",fname,bits256_str(str,r),bits256_str(str2,check));
            return(-1);
        }
        fclose(fp);
    }
    return(0);
}

int main(int argc, const char * argv[])
{
    char dirname[512]; double incr; cJSON *retjson;
    OS_init();
    if ( strstr(argv[0],"btc2kmd") != 0 && argv[1] != 0 )
    {
        bits256 privkey,checkkey; uint8_t tmptype; char kmdwif[64],str[65],str2[65],*retstr;
        if ( LP_wifstr_valid("BTC",(char *)argv[1]) > 0 )
        {
            bitcoin_wif2priv("BTC",0,&tmptype,&privkey,(char *)argv[1]);
            bitcoin_priv2wif("KMD",0,kmdwif,privkey,188);
            bitcoin_wif2priv("KMD",0,&tmptype,&checkkey,kmdwif);
            if ( bits256_cmp(privkey,checkkey) == 0 )
                printf("BTC %s -> KMD %s: privkey %s\n",argv[1],kmdwif,bits256_str(str,privkey));
            else printf("ERROR BTC %s %s != KMD %s %s\n",argv[1],bits256_str(str,privkey),kmdwif,bits256_str(str2,checkkey));
        }
        else
        {
            if ( (retstr= LP_convaddress("BTC",(char *)argv[1],"KMD")) != 0 )
                printf("%s\n",retstr);
        }
        exit(0);
    }
    else if ( argv[1] != 0 && strcmp(argv[1],"events") == 0 )
    {
        int32_t len,bufsize = 1000000; void *ptr; char *buf;
        if ( (IPC_ENDPOINT= nn_socket(AF_SP,NN_PAIR)) >= 0 )
        {
            if ( nn_connect(IPC_ENDPOINT,"ws://127.0.0.1:5555") >= 0 )
            {
                buf = calloc(1,bufsize);
                while ( 1 )
                {
                    if ( (len= nn_recv(IPC_ENDPOINT,&ptr,NN_MSG,0)) > 0 )
                    {
                        if ( len < bufsize )
                        {
                            memcpy(buf,ptr,len);
                            buf[len] = 0;
                            printf("%s\n",(char *)buf);
                        }
                        nn_freemsg(ptr);
                    }
                }
            } else printf("nn_connect error to IPC_ENDPOINT\n");
        } else printf("error opening IPC_ENDPOINT\n");
    }
    else if ( argv[1] != 0 && strcmp(argv[1],"hush") == 0 )
    {
        uint32_t timestamp; char str[65],wifstr[128]; bits256 privkey; int32_t i;
        timestamp = (uint32_t)time(NULL);
        //printf("start hush vanitygen t.%u\n",timestamp);
        for (i=0; i<1000000000; i++)
        {
            OS_randombytes(privkey.bytes,sizeof(privkey));
            privkey.bytes[0] = 0x0e;
            privkey.bytes[1] = 0x5b;
            privkey.bytes[2] = 0xf9;
            privkey.bytes[3] = 0xc6;
            privkey.bytes[4] = 0x06;
            privkey.bytes[5] = 0xdd;
            privkey.bytes[6] = 0xbb;
            bitcoin_priv2wiflong("HUSH",0xab,wifstr,privkey,0x36);
            if ( wifstr[2] == 'x' && wifstr[4] == 'H' && wifstr[5] == 'u' && wifstr[6] == 's' )//&& wifstr[3] == 'x' )
            {
                if ( wifstr[7] == 'h' && wifstr[8] == 'L' && wifstr[9] == 'i' )
                {
                    //printf("i.%d %s -> wif.%s\n",i,bits256_str(str,privkey),wifstr);
                    if ( wifstr[10] == 's' && wifstr[11] == 't' )
                    {
                        printf("{\"iters\":%d,\"privkey\":\"%s\",\"wif\":\"%s\"}\n",i,bits256_str(str,privkey),wifstr);
                        break;
                    }
                }
            } //else printf("failed %s\n",wifstr);
        }
        //printf("done hush vanitygen done %u elapsed %d\n",(uint32_t)time(NULL),(uint32_t)time(NULL) - timestamp);
        exit(0);
    }
    else if ( argv[1] != 0 && strcmp(argv[1],"vanity") == 0 && argv[2] != 0 )
    {
        uint32_t timestamp; uint8_t pubkey33[33]; char str[65],coinaddr[64],wifstr[128]; bits256 privkey; int32_t i,len; void *ctx;
        ctx = bitcoin_ctx();
        len = (int32_t)strlen(argv[2]);
        timestamp = (uint32_t)time(NULL);
        printf("start vanitygen (%s).%d t.%u\n",argv[2],len,timestamp);
        for (i=0; i<1000000000; i++)
        {
            OS_randombytes(privkey.bytes,sizeof(privkey));
            bitcoin_priv2pub(ctx,"KMD",pubkey33,coinaddr,privkey,0,60);
            if ( strncmp(coinaddr+1,argv[2],len-1) == 0 )
            {
                bitcoin_priv2wif("KMD",0,wifstr,privkey,188);
                printf("i.%d %s -> %s wif.%s\n",i,bits256_str(str,privkey),coinaddr,wifstr);
                if ( coinaddr[1+len-1] == argv[2][len-1] )
                    break;
            } //else printf("failed %s\n",wifstr);
        }
        printf("done vanitygen.(%s) done %u elapsed %d\n",argv[2],(uint32_t)time(NULL),(uint32_t)time(NULL) - timestamp);
        exit(0);
    }
    else if ( argv[1] != 0 && strcmp(argv[1],"airdropH") == 0 && argv[2] != 0 )
    {
        FILE *fp; double val,total = 0.; uint8_t checktype,addrtype,rmd160[21],checkrmd160[21]; char *floatstr,*addrstr,buf[256],checkaddr[64],coinaddr[64],manystrs[64][128],cmd[64*128]; int32_t n,i,num; char *flag;
        if ( (fp= fopen(argv[2],"rb")) != 0 )
        {
            num = 0;
            while ( fgets(buf,sizeof(buf),fp) > 0 )
            {
                if ( (n= (int32_t)strlen(buf)) > 0 )
                    buf[--n] = 0;
                flag = 0;
                for (i=0; i<n; i++)
                {
                    if ( buf[i] == ',' )
                    {
                        buf[i] = 0;
                        flag = &buf[i+1];
                        break;
                    }
                }
                if ( flag != 0 )
                {
                    addrstr = flag, floatstr = buf;
                    //addrstr = buf, floatstr = flag;
                    //bitcoin_addr2rmd160("HUSH",28,&addrtype,rmd160,buf);
                    bitcoin_addr2rmd160("BTC",0,&addrtype,rmd160,addrstr);
                    bitcoin_address("KMD",coinaddr,0,addrtype == 0 ? 60 : 85,rmd160,20);
                    bitcoin_addr2rmd160("KMD",0,&checktype,checkrmd160,coinaddr);
                    //bitcoin_address("HUSH",checkaddr,28,checktype == 60 ? 184 : 189,checkrmd160,20);
                    bitcoin_address("BTC",checkaddr,0,checktype == 60 ? 0 : 5,checkrmd160,20);
                    if ( memcmp(rmd160,checkrmd160,20) != 0 || strcmp(addrstr,checkaddr) != 0 )
                    {
                        for (i=0; i<20; i++)
                            printf("%02x",rmd160[i]);
                        printf(" vs. ");
                        for (i=0; i<20; i++)
                            printf("%02x",checkrmd160[i]);
                        printf(" address calc error (%s).%d -> (%s).%d -> (%s) %.8f?\n",addrstr,addrtype,coinaddr,checktype,checkaddr,atof(floatstr));
                    }
                    else
                    {
                        val = atof(floatstr);
                        sprintf(manystrs[num++],"\\\"%s\\\":%0.8f",coinaddr,val);
                        if ( num >= sizeof(manystrs)/sizeof(*manystrs) )
                        {
                            sprintf(cmd,"fiat/btch sendmany \\\"\\\" \"{");
                            for (i=0; i<num; i++)
                                sprintf(cmd + strlen(cmd),"%s%s",manystrs[i],i<num-1?",":"");
                            strcat(cmd,"}\" 0");
                            printf("%s\nsleep 3\n",cmd);
                            num = 0;
                            memset(manystrs,0,sizeof(manystrs));
                        }
                        total += val;
                        //printf("(%s).%d (%s) <- %.8f (%s) total %.8f\n",addrstr,addrtype,coinaddr,val,floatstr,total);
                    }
                } else printf("parse error for (%s)\n",buf);
            }
            if ( num > 0 )
            {
                sprintf(cmd,"fiat/btch sendmany \\\"\\\" \"{");
                for (i=0; i<num; i++)
                    sprintf(cmd + strlen(cmd),"%s%s",manystrs[i],i<num-1?",":"");
                strcat(cmd,"}\" 0");
                printf("%s\n",cmd);
                num = 0;
                memset(manystrs,0,sizeof(manystrs));
            }
            printf("close (%s) total %.8f\n",argv[2],total);
            fclose(fp);
        } else printf("couldnt open (%s)\n",argv[2]);
        exit(0);
    }
    sprintf(dirname,"%s",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    if ( ensure_writable(dirname) < 0 )
    {
        printf("couldnt write to (%s)\n",dirname);
        exit(0);
    }
    sprintf(dirname,"%s/SWAPS",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    if ( ensure_writable(dirname) < 0 )
    {
        printf("couldnt write to (%s)\n",dirname);
        exit(0);
    }
    sprintf(dirname,"%s/PRICES",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    if ( ensure_writable(dirname) < 0 )
    {
        printf("couldnt write to (%s)\n",dirname);
        exit(0);
    }
    sprintf(dirname,"%s/UNSPENTS",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    if ( ensure_writable(dirname) < 0 )
    {
        printf("couldnt write to (%s)\n",dirname);
        exit(0);
    }
#ifdef FROM_JS
    argc = 2;
    retjson = cJSON_Parse("{\"client\":1,\"passphrase\":\"test\"}");
    printf("calling LP_main(%s)\n",jprint(retjson,0));
    LP_main(retjson);
    emscripten_set_main_loop(LP_fromjs_iter,1,0);
#else
    if ( argc == 1 )
    {
        //LP_privkey_tests();
        LP_NXT_redeems();
        sleep(3);
        return(0);
    }
    if ( argc > 1 && (retjson= cJSON_Parse(argv[1])) != 0 )
    {
        if ( jint(retjson,"docker") == 1 )
            DOCKERFLAG = 1;
        else if ( jstr(retjson,"docker") != 0 )
            DOCKERFLAG = (uint32_t)calc_ipbits(jstr(retjson,"docker"));
        //if ( jobj(retjson,"passphrase") != 0 )
        //    jdelete(retjson,"passphrase");
        //if ( (passphrase= jstr(retjson,"passphrase")) == 0 )
        //    jaddstr(retjson,"passphrase","default");
        if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_main,(void *)retjson) != 0 )
        {
            printf("error launching LP_main (%s)\n",jprint(retjson,0));
            exit(-1);
        } //else printf("(%s) launched.(%s)\n",argv[1],passphrase);
        incr = 100.;
        while ( LP_STOP_RECEIVED == 0 )
            sleep(100000);
    } else printf("couldnt parse.(%s)\n",argv[1]);
#endif
    return 0;
}
