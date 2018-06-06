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

#define issue_curl(cmdstr) bitcoind_RPC(0,"curl",cmdstr,0,0,0,0)

uint64_t dpow_utxosize(char *symbol)
{
    if ( strcmp(symbol,"GAME") == 0 )
        return(100000);
    else return(10000);
}

char *bitcoind_getinfo(char *symbol,char *serverport,char *userpass,char *getinfostr)
{
    char buf[1],*retstr; cJSON *retjson;
    buf[0] = 0;
    if ( getinfostr[0] == 0 )
        strcpy(getinfostr,"getinfo");
    retstr = bitcoind_passthru(symbol,serverport,userpass,getinfostr,buf);
    if ( (retjson= cJSON_Parse(retstr)) != 0 )
    {
        if ( jobj(retjson,"error") != 0 && strcmp(getinfostr,"getinfo") == 0 )
        {
            strcpy(getinfostr,"getblockchaininfo");
            free(retstr);
            retstr = bitcoind_passthru(symbol,serverport,userpass,getinfostr,buf);
            printf("switch to getblockchaininfo -> (%s)\n",retstr);
        }
        free(retjson);
    }
    return(retstr);
}

cJSON *dpow_getinfo(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char buf[128],*retstr=0; cJSON *json = 0;
    if ( coin->FULLNODE < 0 )
    {
        buf[0] = 0;
        retstr = bitcoind_getinfo(coin->symbol,coin->chain->serverport,coin->chain->userpass,coin->getinfostr);
        usleep(10000);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        retstr = bitcoinrpc_getinfo(myinfo,coin,0,0);
    }
    else
    {
        return(0);
    }
    if ( retstr != 0 )
    {
        json = cJSON_Parse(retstr);
        free(retstr);
        if ( strcmp(coin->symbol,"BTC") == 0 )
        {
            sprintf(buf,"[%d]",2);
            if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"estimatefee",buf)) != 0 )
            {
                if ( atof(retstr) > SMALLVAL )
                    jaddnum(json,"estimatefee",atof(retstr));
                free(retstr);
            }
        }
    }
    return(json);
}

uint32_t dpow_CCid(struct supernet_info *myinfo,struct iguana_info *coin)
{
    uint32_t CCid = 0; cJSON *retjson;
    if ( (retjson= dpow_getinfo(myinfo,coin)) != 0 )
    {
        CCid = juint(retjson,"CCid");
        free_json(retjson);
    }
    return(CCid);
}

char *Notaries_elected[65][2];
//char *seeds[] = { "78.47.196.146", "5.9.102.210", "149.56.29.163", "191.235.80.138", "88.198.65.74", "94.102.63.226", "129.232.225.202", "104.255.64.3", "52.72.135.200", "149.56.28.84", "103.18.58.150", "221.121.144.140", "123.249.79.12", "103.18.58.146", "27.50.93.252", "176.9.0.233", "94.102.63.227", "167.114.227.223", "27.50.68.219", "192.99.233.217", "94.102.63.217", "45.64.168.216" };
int32_t Notaries_numseeds;// = (int32_t)(sizeof(seeds)/sizeof(*seeds))
int32_t Notaries_num,Notaries_BTCminsigs = DPOW_MINSIGS;
int32_t Notaries_minsigs = DPOW_MIN_ASSETCHAIN_SIGS;
uint16_t Notaries_port = DPOW_SOCKPORT;
char *Notaries_seeds[65];

int32_t komodo_initjson(char *fname)
{
    char *fstr,*field,*hexstr; cJSON *argjson,*array,*item; long fsize; uint16_t port; int32_t i,n,num,retval = -1;
    //for (i=0; i<Notaries_numseeds; i++)
    //    Notaries_seeds[i] = seeds[i];
    if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
    {
        if ( (argjson= cJSON_Parse(fstr)) != 0 )
        {
            if ( (port= juint(argjson,"port")) != 0 )
                Notaries_port = port;
            if ( (num= juint(argjson,"BTCminsigs")) > Notaries_BTCminsigs )
                Notaries_BTCminsigs = num;
            Notaries_minsigs = juint(argjson,"minsigs");
            if ( (array= jarray(&n,argjson,"seeds")) != 0 && n <= 64 )
            {
                for (i=0; i<n&&i<64; i++)
                {
                    Notaries_seeds[i] = clonestr(jstri(array,i));
                    printf("%s ",Notaries_seeds[i]);
                }
                Notaries_numseeds = i;
                printf("Notaries_numseeds.%d\n",Notaries_numseeds);
            }
            if ( (array= jarray(&n,argjson,"notaries")) != 0 && n <= 64 )
            {
                for (i=0; i<n&&i<64; i++)
                {
                    item = jitem(array,i);
                    field = jfieldname(item);
                    if ( (hexstr= jstr(item,field)) != 0 && is_hexstr(hexstr,0) == 66 )
                    {
                        Notaries_elected[i][0] = clonestr(field);
                        Notaries_elected[i][1] = clonestr(hexstr);
                        //printf("%d of %d: %s %s\n",i,n,field,hexstr);
                    }
                    else
                    {
                        printf("couldnt find (%s) in %s or non-hex (%s)\n",field,jprint(item,0),hexstr!=0?hexstr:"");
                        break;
                    }
                }
                if ( i == n )
                {
                    Notaries_num = n;
                    retval = 0;
                    printf("numnotaries %d, port.%d minsigs.%d BTCminsigs.%d\n",Notaries_num,Notaries_port,Notaries_BTCminsigs,Notaries_minsigs);
                }
            }
            free_json(argjson);
        }
        free(fstr);
    }
    return(retval);
}

int32_t komodo_notaries(char *symbol,uint8_t pubkeys[64][33],int32_t height)
{
    int32_t i; //,num=-1; struct iguana_info *coin; char params[256],*retstr,*pubkeystr; cJSON *retjson,*item,*array;
    if ( Notaries_num > 0 )
    {
        for (i=0; i<Notaries_num; i++)
            decode_hex(pubkeys[i],33,Notaries_elected[i][1]);
        return(Notaries_num);
    } else return(-1);
    /*if ( (coin= iguana_coinfind(symbol)) != 0 )
    {
        if ( height < 0 )
        {
            if ( (retjson= dpow_getinfo(SuperNET_MYINFO(0),coin)) != 0 )
            {
                height = jint(retjson,"blocks") - 1;
                free_json(retjson);
//printf("komodo_notaries height.%d\n",height);
            }
        }
        if ( height >= 180000 )
        {
            for (i=0; i<sizeof(Notaries_elected)/sizeof(*Notaries_elected); i++)
                decode_hex(pubkeys[i],33,(char *)Notaries_elected[i][1]);
            return(i);
        }
        if ( coin->FULLNODE < 0 )
        {
            sprintf(params,"[\"%d\"]",height);
            if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"notaries",params)) != 0 )
            {
                if ( (retjson= cJSON_Parse(retstr)) != 0 )
                {
//printf("%s\n",retstr);
                    if ( (array= jarray(&num,retjson,"notaries")) != 0 )
                    {
                        if ( num > 64 )
                        {
                            printf("warning: numnotaries.%d? > 64?\n",num);
                            num = 64;
                        }
                        for (i=0; i<num; i++)
                        {
                            item = jitem(array,i);
                            if ( (pubkeystr= jstr(item,"pubkey")) != 0 && strlen(pubkeystr) == 66 )
                                decode_hex(pubkeys[i],33,pubkeystr);
                            else printf("error i.%d of %d (%s)\n",i,num,pubkeystr!=0?pubkeystr:"");
                        }
                        //printf("notaries.[%d] <- ht.%d\n",num,height);
                    }
                    free_json(retjson);
                }
                free(retstr);
            }
        }
    }
    //printf("komodo_notaries returns.%d\n",num);
    return(num);*/
}

bits256 dpow_getbestblockhash(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char *retstr; bits256 blockhash;
    memset(blockhash.bytes,0,sizeof(blockhash));
    if ( coin->FULLNODE < 0 )
    {
        if ( coin->lastbesthashtime+2 > time(NULL) && bits256_nonz(coin->lastbesthash) != 0 )
            return(coin->lastbesthash);
        if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getbestblockhash","")) != 0 )
        {
            if ( 0 && strcmp(coin->symbol,"USD") == 0 )
                printf("%s getbestblockhash.(%s)\n",coin->symbol,retstr);
            if ( is_hexstr(retstr,0) == sizeof(blockhash)*2 )
                decode_hex(blockhash.bytes,sizeof(blockhash),retstr);
            free(retstr);
        }
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        blockhash = coin->blocks.hwmchain.RO.hash2;
    }
    else
    {
        
    }
    if ( bits256_nonz(blockhash) != 0 )
    {
        coin->lastbesthash = blockhash;
        coin->lastbesthashtime = (uint32_t)time(NULL);
    }
    return(blockhash);
}

cJSON *issue_calcMoM(struct iguana_info *coin,int32_t height,int32_t MoMdepth)
{
    char buf[128],*retstr=0; cJSON *retjson = 0;
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"[\"%d\", \"%d\"]",height,MoMdepth);
        if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"calc_MoM",buf)) != 0 )
        {
            retjson = cJSON_Parse(retstr);
            //printf("MoM.%s -> %s\n",buf,retstr);
            free(retstr);
        }
    }
    return(retjson);
}

cJSON *dpow_MoMoMdata(struct iguana_info *coin,char *symbol,int32_t kmdheight,uint16_t CCid)
{
    char buf[128],*retstr=0; cJSON *retjson = 0; struct iguana_info *src;
    if ( coin->FULLNODE < 0 && strcmp(coin->symbol,"KMD") == 0 && (src= iguana_coinfind(symbol)) != 0 )
    {
        sprintf(buf,"[\"%s\", \"%d\", \"%d\"]",symbol,kmdheight,CCid);
        if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"MoMoMdata",buf)) != 0 )
        {
            retjson = cJSON_Parse(retstr);
            printf("%s kmdheight.%d CCid.%u MoMoM.%s -> %s\n",symbol,kmdheight,CCid,buf,retstr);
            free(retstr);
        }
        usleep(10000);
    }
    return(retjson);
}

int32_t dpow_paxpending(struct supernet_info *myinfo,uint8_t *hex,int32_t hexsize,uint32_t *paxwdcrcp,bits256 MoM,uint32_t MoMdepth,uint16_t CCid,int32_t src_or_dest,struct dpow_block *bp)
{
    struct iguana_info *coin,*kmdcoin=0; char *retstr,*hexstr; cJSON *retjson,*infojson; int32_t kmdheight=0,hexlen=0,n=0; uint32_t paxwdcrc;
    paxwdcrc = 0;
    if ( strcmp(bp->srccoin->symbol,"GAME") != 0 || src_or_dest != 0 )
    {
        n += iguana_rwbignum(1,&hex[n],sizeof(MoM),MoM.bytes);
        MoMdepth = (MoMdepth & 0xffff) | ((uint32_t)CCid<<16);
        n += iguana_rwnum(1,&hex[n],sizeof(MoMdepth),(uint32_t *)&MoMdepth);
        if ( strncmp(bp->srccoin->symbol,"TXSCL",5) == 0 && src_or_dest == 0 && strcmp(bp->destcoin->symbol,"KMD") == 0 )
        {
            kmdcoin = bp->destcoin;
            if ( (infojson= dpow_getinfo(myinfo,kmdcoin)) != 0 )
            {
                kmdheight = jint(infojson,"blocks");
                free_json(infojson);
            }
            if ( (retjson= dpow_MoMoMdata(kmdcoin,bp->srccoin->symbol,kmdheight,bp->CCid)) != 0 )
            {
                if ( (hexstr= jstr(retjson,"data")) != 0 && (hexlen= (int32_t)strlen(hexstr)) > 0 && n+hexlen/2 <= hexsize )
                {
                    hexlen >>= 1;
                    printf("add MoMoMdata.(%s)\n",hexstr);
                    decode_hex(&hex[n],hexlen,hexstr), n += hexlen;
                }
                free_json(retjson);
            }
        }
        paxwdcrc = calc_crc32(0,hex,n) & 0xffffff00;
        paxwdcrc |= (n & 0xff);
        if ( hexlen > 0 )
            printf("%s.ht.%d opretlen.%d src_or_dest.%d dest.(%s) lastbest.%d paxwdcrc.%x\n",bp->srccoin->symbol,bp->height,n,src_or_dest,bp->destcoin->symbol,kmdcoin!=0?((kmdcoin->lastbestheight/10)*10 - 5):-1,paxwdcrc);
    }
    *paxwdcrcp = paxwdcrc;
    return(n);
    if ( (coin= iguana_coinfind("KMD")) != 0 )
    {
        if ( coin->FULLNODE < 0 )
        {
            if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"paxpending","")) != 0 )
            {
                if ( (retjson= cJSON_Parse(retstr)) != 0 )
                {
                    if ( (hexstr= jstr(retjson,"withdraws")) != 0 && (n= is_hexstr(hexstr,0)) > 1 )
                    {
                        n >>= 1;
                        //printf("PAXPENDING.(%s)\n",hexstr);
                        decode_hex(hex,n,hexstr);
                        paxwdcrc = calc_crc32(0,hex,n) & 0xffffff00;
                        paxwdcrc |= (n & 0xff);
                    }
                    free_json(retjson);
                } else printf("dpow_paxpending: parse error.(%s)\n",retstr);
                free(retstr);
            } else printf("dpow_paxpending: paxwithdraw null return\n");
        } else printf("dpow_paxpending: KMD FULLNODE.%d\n",coin->FULLNODE);
    } else printf("dpow_paxpending: cant find KMD\n");
    if ( *paxwdcrcp != paxwdcrc )
        *paxwdcrcp = paxwdcrc;
    return(n);
}

bits256 dpow_getblockhash(struct supernet_info *myinfo,struct iguana_info *coin,int32_t height)
{
    char buf[128],*retstr=0; bits256 blockhash;
    memset(blockhash.bytes,0,sizeof(blockhash));
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"%d",height);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getblockhash",buf);
        //printf("%s ht.%d -> getblockhash.(%s)\n",coin->symbol,height,retstr);
        usleep(10000);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        printf("test iguana mode getblockhash\n");
        retstr = bitcoinrpc_getblockhash(myinfo,coin,0,0,height);
    }
    else
    {
        return(blockhash);
    }
    if ( retstr != 0 )
    {
        if ( strlen(retstr) == 64 )
            decode_hex(blockhash.bytes,32,retstr);
        free(retstr);
    }
    return(blockhash);
}

cJSON *dpow_getblock(struct supernet_info *myinfo,struct iguana_info *coin,bits256 blockhash)
{
    char buf[128],str[65],*retstr=0; cJSON *json = 0;
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"\"%s\"",bits256_str(str,blockhash));
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getblock",buf);
        if ( 0 && strcmp(coin->symbol,"USD") == 0 )
            printf("%s getblock.(%s)\n",coin->symbol,retstr);
        usleep(10000);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        retstr = bitcoinrpc_getblock(myinfo,coin,0,0,blockhash,1,0);
    }
    else
    {
        return(0);
    }
    if ( retstr != 0 )
    {
        json = cJSON_Parse(retstr);
        free(retstr);
    }
    return(json);
}

int32_t dpow_is015(char *symbol)
{
    if ( strcmp("CHIPS",symbol) == 0 || strcmp("GAME",symbol) == 0 ) //strcmp("BTC",symbol) == 0 || 
        return(1);
    else return(0);
}

char *dpow_validateaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *address)
{
    char buf[128],*retstr=0; cJSON *retjson;
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"\"%s\"",address);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,coin->validateaddress,buf);
//printf("%s %s %s %s %s\n",coin->symbol,coin->chain->serverport,coin->chain->userpass,coin->validateaddress,buf);
        //printf("%s -> (%s)\n",buf,retstr!=0?retstr:"null");
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( dpow_is015(coin->symbol) != 0 && jobj(retjson,"error") == 0 && jobj(retjson,"ismine") == 0 && strcmp(coin->validateaddress,"validateaddress") == 0 )
            {
                printf("autochange %s validateaddress -> getaddressinfo\n",coin->symbol);
                strcpy(coin->validateaddress,"getaddressinfo");
                free_json(retjson);
                free(retjson);
                return(bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,coin->validateaddress,buf));
            }
            free_json(retjson);
        }
        usleep(10000);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        retstr = bitcoinrpc_validateaddress(myinfo,coin,0,0,address);
    }
    else
    {
        return(0);
    }
    return(retstr);
}

cJSON *dpow_gettxout(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid,int32_t vout)
{
    char buf[128],str[65],*retstr=0; cJSON *json = 0;
    sprintf(buf,"\"%s\", %d",bits256_str(str,txid),vout);
    if ( coin->FULLNODE < 0 )
    {
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"gettxout",buf);
        usleep(10000);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        printf("need to test following call\n");
        retstr = bitcoinrpc_gettxout(myinfo,coin,0,buf,txid,1,0); // untested
    }
    else
    {
        return(0);
    }
    if ( retstr != 0 )
    {
        json = cJSON_Parse(retstr);
        free(retstr);
    }
    //printf("dpow_gettxout.(%s)\n",retstr);
    return(json);
}

char *dpow_decoderawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *rawtx)
{
    char *retstr,*paramstr; cJSON *array;
    if ( coin->FULLNODE < 0 )
    {
        array = cJSON_CreateArray();
        jaddistr(array,rawtx);
        paramstr = jprint(array,1);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"decoderawtransaction",paramstr);
        //printf("%s decoderawtransaction.(%s) <- (%s)\n",coin->symbol,retstr,paramstr);
        free(paramstr);
        usleep(10000);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        retstr = bitcoinrpc_decoderawtransaction(myinfo,coin,0,0,rawtx,1);
    }
    else
    {
        return(0);
    }
    return(retstr);
}

cJSON *dpow_gettransaction(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid)
{
    char buf[128],str[65],*retstr=0; cJSON *json = 0;
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"[\"%s\", 1]",bits256_str(str,txid));
        if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"getrawtransaction",buf)) != 0 )
        {
        }
        usleep(10000);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        retstr = bitcoinrpc_getrawtransaction(myinfo,coin,0,0,txid,1);
    }
    else
    {
        return(0);
    }
    if ( retstr != 0 )
    {
        json = cJSON_Parse(retstr);
        free(retstr);
    }
    return(json);
}

cJSON *dpow_listunspent(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    char buf[128],*retstr; cJSON *array,*json = 0;
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"1, 99999999, [\"%s\"]",coinaddr);
        if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"listunspent",buf)) != 0 )
        {
            json = cJSON_Parse(retstr);
            //printf("%s (%s) listunspent.(%s)\n",coin->symbol,buf,retstr);
            free(retstr);
        } else printf("%s null retstr from (%s)n",coin->symbol,buf);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        array = cJSON_CreateArray();
        jaddistr(array,coinaddr);
        json = iguana_listunspents(myinfo,coin,array,1,coin->longestchain,"");
        free_json(array);
    }
    else
    {
        return(0);
    }
    return(json);
}

cJSON *dpow_listspent(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    if ( myinfo->DEXEXPLORER != 0 )
        return(kmd_listspent(myinfo,coin,coinaddr));
    else
    {
        return(0);
    }
}

cJSON *dpow_getbalance(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr)
{
    if ( myinfo->DEXEXPLORER != 0 )
        return(kmd_getbalance(myinfo,coin,coinaddr));
    else
    {
        return(0);
    }
}

cJSON *dpow_gettxin(struct supernet_info *myinfo,struct iguana_info *coin,bits256 txid,int32_t vout)
{
    if ( myinfo->DEXEXPLORER != 0 )
        return(kmd_gettxin(coin,txid,vout));
    else
    {
        return(0);
    }
}

cJSON *dpow_listtransactions(struct supernet_info *myinfo,struct iguana_info *coin,char *coinaddr,int32_t count,int32_t skip)
{
    char buf[128],*retstr; cJSON *json = 0;
    if ( coin->FULLNODE < 0 )
    {
        if ( count == 0 )
            count = 100;
        sprintf(buf,"[\"%s\", %d, %d, true]",coinaddr,count,skip);
        if ( (retstr= bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"listtransactions",buf)) != 0 )
        {
            //printf("LIST.(%s)\n",retstr);
            json = cJSON_Parse(retstr);
            free(retstr);
            return(json);
        } else printf("%s null retstr from (%s)n",coin->symbol,buf);
    }
    return(0);
}

char *dpow_signrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *rawtx,cJSON *vins)
{
    cJSON *array,*privkeys,*item,*retjson; char *wifstr,*str,*paramstr,*retstr; uint8_t script[256]; int32_t i,n,len,hashtype; struct vin_info V; struct iguana_waddress *waddr; struct iguana_waccount *wacct;
    if ( coin->FULLNODE < 0 )
    {
        array = cJSON_CreateArray();
        jaddistr(array,rawtx);
        jaddi(array,jduplicate(vins));
        paramstr = jprint(array,1);
        //printf("signrawtransaction\n");
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,coin->signtxstr,paramstr);
        if ( strcmp(coin->signtxstr,"signrawtransaction") == 0 && (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( jobj(retjson,"error") != 0 && dpow_is015(coin->symbol) != 0 )
            {
                strcpy(coin->signtxstr,"signrawtransactionwithwallet");
                free(retstr);
                retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,coin->signtxstr,paramstr);
            }
            free_json(retjson);
        }
        //printf("%s signrawtransaction.(%s) params.(%s)\n",coin->symbol,retstr,paramstr);
        free(paramstr);
        usleep(10000);
        return(retstr);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        privkeys = cJSON_CreateArray();
        if ( (n= cJSON_GetArraySize(vins)) > 0 )
        {
            for (i=0; i<n; i++)
            {
                wifstr = "";
                item = jitem(vins,i);
                if ( (str= jstr(item,"scriptPubkey")) != 0 && is_hexstr(str,0) > 0 && strlen(str) < sizeof(script)*2 )
                {
                    len = (int32_t)strlen(str) >> 1;
                    decode_hex(script,len,str);
                    V.spendlen = len;
                    memcpy(V.spendscript,script,len);
                    if ( (hashtype= _iguana_calcrmd160(coin,&V)) >= 0 && V.coinaddr[0] != 0 )
                    {
                        if ( (waddr= iguana_waddresssearch(myinfo,&wacct,V.coinaddr)) != 0 )
                        {
                            if ( bits256_nonz(waddr->privkey) != 0 )
                            {
                                if ( bitcoin_priv2wif(waddr->wifstr,waddr->privkey,coin->chain->wiftype) > 0 )
                                {
                                    wifstr = waddr->wifstr;
                                }
                            }
                        }
                    }
                }
                jaddistr(privkeys,wifstr);
            }
        }
        retstr = bitcoinrpc_signrawtransaction(myinfo,coin,0,0,rawtx,vins,privkeys,"ALL");
        //printf("call sign.(%s) vins.(%s) privs.(%s) -> (%s)\n",rawtx,jprint(vins,0),jprint(privkeys,0),retstr);
        free_json(privkeys);
        return(retstr);
    }
    else
    {
        return(0);
    }
}

cJSON *dpow_kvupdate(struct supernet_info *myinfo,struct iguana_info *coin,char *key,char *value,int32_t flags)
{
    char params[IGUANA_MAXSCRIPTSIZE+256],*retstr; cJSON *retjson;
    if ( coin->FULLNODE < 0 )
    {
        sprintf(params,"[\"%s\", \"%s\", \"%d\"]",key,value,flags);
        //printf("KVUPDATE.%s\n",params);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"kvupdate",params);
        if ( (retjson= cJSON_Parse(retstr)) == 0 )
        {
            free(retstr);
            return(cJSON_Parse("{\"error\":\"couldnt parse kvupdate return\"}"));
        }
        free(retstr);
        return(retjson);
    } else return(cJSON_Parse("{\"error\":\"only native komodod supports KV\"}"));
}

cJSON *dpow_kvsearch(struct supernet_info *myinfo,struct iguana_info *coin,char *key)
{
    char params[IGUANA_MAXSCRIPTSIZE+256],*retstr; cJSON *retjson;
    if ( coin->FULLNODE < 0 )
    {
        sprintf(params,"[\"%s\"]",key);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"kvsearch",params);
        if ( (retjson= cJSON_Parse(retstr)) == 0 )
        {
            free(retstr);
            return(cJSON_Parse("{\"error\":\"couldnt parse kvupdate return\"}"));
        }
        free(retstr);
        return(retjson);
    } else return(cJSON_Parse("{\"error\":\"only native komodod supports KV\"}"));
}


char *dpow_sendrawtransaction(struct supernet_info *myinfo,struct iguana_info *coin,char *signedtx)
{
    bits256 txid; cJSON *json,*array; char *paramstr,*retstr;
    if ( coin->FULLNODE < 0 )
    {
        array = cJSON_CreateArray();
        jaddistr(array,signedtx);
        paramstr = jprint(array,1);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"sendrawtransaction",paramstr);
        printf(">>>>>>>>>>> %s dpow_sendrawtransaction (%s)\n",coin->symbol,retstr);
        free(paramstr);
        return(retstr);
    }
    else if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
    {
        txid = iguana_sendrawtransaction(myinfo,coin,signedtx);
        json = cJSON_CreateObject();
        jaddbits256(json,"result",txid);
        return(jprint(json,1));
    }
    else
    {
        return(0);
    }
}

char *dpow_alladdresses(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char *retstr,fname[1024]; long filesize;
    sprintf(fname,"%s/alladdresses.%s",GLOBAL_CONFSDIR,coin->symbol), OS_compatible_path(fname);
    retstr = OS_filestr(&filesize,fname);
    return(retstr);
}

void update_alladdresses(struct supernet_info *myinfo,struct iguana_info *coin,char *address)
{
    struct hashstr_item *hashstr,*tmp; cJSON *alljson; char *outstr,*instr,fname[1024]; int32_t i,n,saveflag = 0;
    HASH_FIND(hh,coin->alladdresses,address,strlen(address),hashstr);
    if ( hashstr == 0 )
    {
        hashstr = calloc(1,sizeof(*hashstr));
        strncpy(hashstr->address,address,sizeof(hashstr->address));
        HASH_ADD_KEYPTR(hh,coin->alladdresses,hashstr->address,strlen(address),hashstr);
        saveflag = 1;
    }
    if ( saveflag != 0 )
    {
        FILE *fp;
        if ( (instr= dpow_alladdresses(myinfo,coin)) != 0 )
        {
            if ( (alljson= cJSON_Parse(instr)) != 0 )
            {
                n = cJSON_GetArraySize(alljson);
                for (i=0; i<n; i++)
                {
                    address = jstri(alljson,i);
                    HASH_FIND(hh,coin->alladdresses,address,strlen(address),hashstr);
                    if ( hashstr == 0 )
                    {
                        hashstr = calloc(1,sizeof(*hashstr));
                        strncpy(hashstr->address,address,sizeof(hashstr->address));
                        HASH_ADD_KEYPTR(hh,coin->alladdresses,hashstr->address,strlen(address),hashstr);
                    }
                }
                free_json(alljson);
            }
            free(instr);
        }
        alljson = cJSON_CreateArray();
        HASH_ITER(hh,coin->alladdresses,hashstr,tmp)
        {
            jaddistr(alljson,hashstr->address);
        }
        outstr = jprint(alljson,0);
        sprintf(fname,"%s/alladdresses.%s",GLOBAL_CONFSDIR,coin->symbol), OS_compatible_path(fname);
        if ( (fp= fopen(fname,"wb")) != 0 )
        {
            fwrite(outstr,1,strlen(outstr)+1,fp);
            fclose(fp);
            printf("importaddress.(%s) -> alladdresses.%s\n",address,coin->symbol);
        }
        free(outstr);
    }
}

cJSON *dpow_checkaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *address)
{
    int32_t isvalid=0,doneflag=0; char *retstr; cJSON *validatejson,*retjson = cJSON_CreateObject();
    if ( (retstr= dpow_validateaddress(myinfo,coin,address)) != 0 )
    {
        if ( (validatejson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (isvalid= is_cJSON_True(jobj(validatejson,"isvalid")) != 0) != 0 )
            {
                if ( is_cJSON_True(jobj(validatejson,"iswatchonly")) != 0 || is_cJSON_True(jobj(validatejson,"ismine")) != 0 )
                    doneflag = 1;
            }
            free_json(validatejson);
        }
        free(retstr);
        retstr = 0;
    }
    if ( isvalid == 0 )
        jaddstr(retjson,"error","invalid address");
    else if ( doneflag != 0 )
    {
        jaddstr(retjson,"coin",coin->symbol);
        jaddstr(retjson,"address",address);
    }
    return(retjson);
}

char *dpow_importaddress(struct supernet_info *myinfo,struct iguana_info *coin,char *address)
{
    char buf[1024],*retstr; cJSON *validatejson; int32_t isvalid=0,doneflag = 0;
    if ( (retstr= dpow_validateaddress(myinfo,coin,address)) != 0 )
    {
        if ( (validatejson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (isvalid= is_cJSON_True(jobj(validatejson,"isvalid")) != 0) != 0 )
            {
                if ( is_cJSON_True(jobj(validatejson,"iswatchonly")) != 0 || is_cJSON_True(jobj(validatejson,"ismine")) != 0 )
                    doneflag = 1;
            }
            free_json(validatejson);
        }
        free(retstr);
        retstr = 0;
    }
    if ( isvalid == 0 )
        return(clonestr("{\"isvalid\":false}"));
    update_alladdresses(myinfo,coin,address);
    if ( doneflag != 0 )
        return(0); // success
    if ( coin->FULLNODE < 0 )
    {
        sprintf(buf,"[\"%s\", \"%s\", false]",address,address);
        retstr = bitcoind_passthru(coin->symbol,coin->chain->serverport,coin->chain->userpass,"importaddress",buf);
        printf("%s importaddress.(%s) -> (%s)\n",coin->symbol,address,retstr);
        return(retstr);
    }
    else return(0);
}

void init_alladdresses(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char *alladdresses,*retstr; cJSON *alljson; int32_t i,n;
    if ( (alladdresses= dpow_alladdresses(myinfo,coin)) != 0 )
    {
        printf("(%s) ALL.(%s)\n",coin->symbol,alladdresses);
        if ( (alljson= cJSON_Parse(alladdresses)) != 0 )
        {
            if ( is_cJSON_Array(alljson) != 0 && (n= cJSON_GetArraySize(alljson)) > 0 )
            {
                for (i=0; i<n; i++)
                    if ( (retstr= dpow_importaddress(myinfo,coin,jstri(alljson,i))) != 0 )
                        free(retstr);
            }
            free_json(alljson);
        }
        free(alladdresses);
    }
}

int32_t dpow_getchaintip(struct supernet_info *myinfo,bits256 *merklerootp,bits256 *blockhashp,uint32_t *blocktimep,bits256 *txs,uint32_t *numtxp,struct iguana_info *coin)
{
    int32_t n,i,height = -1,maxtx = *numtxp; bits256 besthash,oldhash; cJSON *array,*json;
    *numtxp = *blocktimep = 0;
    oldhash = coin->lastbesthash;
    *blockhashp = besthash = dpow_getbestblockhash(myinfo,coin);
    if ( bits256_nonz(besthash) != 0 && bits256_cmp(oldhash,besthash) != 0 )
    {
        if ( (json= dpow_getblock(myinfo,coin,besthash)) != 0 )
        {
            if ( (height= juint(json,"height")) != 0 && (*blocktimep= juint(json,"time")) != 0 )
            {
                *merklerootp = jbits256(json,"merkleroot");
                //if ( bits256_nonz(*merklerootp) == 0 )
                //    printf("block has no merkle? (%s)\n",jprint(json,0));
                coin->lastbestheight = height;
                if ( height > coin->longestchain )
                    coin->longestchain = height;
                if ( txs != 0 && numtxp != 0 && (array= jarray(&n,json,"tx")) != 0 )
                {
                    for (i=0; i<n&&i<maxtx; i++)
                        txs[i] = jbits256i(array,i);
                    if ( 0 && strcmp(coin->symbol,"USD") == 0 )
                        printf("dpow_getchaintip %s ht.%d time.%u numtx.%d\n",coin->symbol,height,*blocktimep,n);
                    *numtxp = n;
                }
            } else height = -1;
            free_json(json);
        }
    }
    return(coin->lastbestheight);
}

int32_t dpow_vini_ismine(struct supernet_info *myinfo,struct dpow_info *dp,cJSON *item)
{
    cJSON *sobj; char *hexstr; int32_t len; uint8_t data[35];
    if ( (sobj= jobj(item,"scriptPubKey")) != 0 && (hexstr= jstr(sobj,"hex")) != 0 )
    {
        len = (int32_t)strlen(hexstr) >> 1;
        if ( len <= sizeof(data) )
        {
            decode_hex(data,len,hexstr);
            if ( len == 35 && data[34] == CHECKSIG && data[0] == 33 && memcmp(data+1,dp->minerkey33,33) == 0 )
                return(0);
        }
    }
    return(-1);
}

int32_t dpow_haveutxo(struct supernet_info *myinfo,struct iguana_info *coin,bits256 *txidp,int32_t *voutp,char *coinaddr,char *srccoin)
{
    int32_t vout,haveutxo = 0; uint32_t i,j,n,r; bits256 txid; cJSON *unspents,*item; uint64_t satoshis; char *str,*address; uint8_t script[35];
    memset(txidp,0,sizeof(*txidp));
    *voutp = -1;
    if ( (unspents= dpow_listunspent(myinfo,coin,coinaddr)) != 0 )
    {
        if ( (n= cJSON_GetArraySize(unspents)) > 0 )
        {
            /*{
             "txid" : "34bc21b40d6baf38e2db5be5353dd0bcc9fe416485a2a68753541ed2f9c194b1",
             "vout" : 0,
             "address" : "RFBmvBaRybj9io1UpgWM4pzgufc3E4yza7",
             "scriptPubKey" : "21039a3f7373ae91588b9edd76a9088b2871f62f3438d172b9f18e0581f64887404aac",
             "amount" : 3.00000000,
             "confirmations" : 4282,
             "spendable" : true
             },*/
            //r = 0;
            //memcpy(&r,coin->symbol,3);
            //r = calc_crc32(0,(void *)&r,sizeof(r));
            OS_randombytes((uint8_t *)&r,sizeof(r));
            for (j=0; j<n; j++)
            {
                i = (r + j) % n;
                if ( (item= jitem(unspents,i)) == 0 )
                    continue;
                if ( is_cJSON_False(jobj(item,"spendable")) != 0 )
                    continue;
                if ( (satoshis= SATOSHIDEN * jdouble(item,"amount")) == 0 )
                    satoshis= SATOSHIDEN * jdouble(item,"value");
                if ( satoshis == DPOW_UTXOSIZE && (address= jstr(item,"address")) != 0 && strcmp(address,coinaddr) == 0 )
                {
                    if ( (str= jstr(item,"scriptPubKey")) != 0 && is_hexstr(str,0) == sizeof(script)*2 )
                    {
                        txid = jbits256(item,"txid");
                        vout = jint(item,"vout");
                        if ( bits256_nonz(txid) != 0 && vout >= 0 )
                        {
                            if ( *voutp < 0 || (rand() % (n/2+1)) == 0 )
                            {
                                *voutp = vout;
                                *txidp = txid;
                            }
                            haveutxo++;
                        }
                    }
                }
            }
            if ( haveutxo == 0 )
                printf("no (%s -> %s) utxo: need to fund address.(%s) or wait for splitfund to confirm\n",srccoin,coin->symbol,coinaddr);
        } //else printf("null utxo array size\n");
        free_json(unspents);
    } else printf("null return from dpow_listunspent\n");
    if ( 0 && haveutxo > 0 )
        printf("%s haveutxo.%d\n",coin->symbol,haveutxo);
    return(haveutxo);
}

char *dpow_issuemethod(char *userpass,char *method,char *params,uint16_t port)
{
    char url[512],*retstr=0,*retstr2=0,postdata[8192];
    if ( params == 0 || params[0] == 0 )
        params = (char *)"[]";
    if ( strlen(params) < sizeof(postdata)-128 )
    {
        sprintf(url,(char *)"http://127.0.0.1:%u",port);
        sprintf(postdata,"{\"method\":\"%s\",\"params\":%s}",method,params);
        //printf("postdata.(%s) USERPASS.(%s)\n",postdata,KMDUSERPASS);
        retstr2 = bitcoind_RPC(&retstr,(char *)"debug",url,userpass,method,params,0);
    }
    return(retstr2);
}

uint64_t dpow_paxprice(uint64_t *seedp,int32_t height,char *base,char *rel,uint64_t basevolume)
{
    char params[512],*retstr; uint64_t satoshis = 0; cJSON *retjson,*result; struct iguana_info *kmdcoin;
    kmdcoin = iguana_coinfind("KMD");
    *seedp = 0;
    sprintf(params,"[\"%s\", \"%s\", \"%d\", \"%.8f\"]",base,rel,height,(double)basevolume/SATOSHIDEN);
    if ( kmdcoin != 0 && (retstr= dpow_issuemethod(kmdcoin->chain->userpass,"paxprice",params,kmdcoin->chain->rpcport)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (result= jobj(retjson,"result")) != 0 )
            {
                satoshis = jdouble(result,"relvolume") * SATOSHIDEN;
                *seedp = j64bits(result,"seed");
            }
            free_json(retjson);
        }
        //printf("dpow_paxprice.(%s) -> %s %.8f\n",params,retstr,dstr(satoshis));
    }
    return(satoshis);
}

#define KOMODO_PUBTYPE 60

int32_t PAX_pubkey(int32_t rwflag,uint8_t *pubkey33,uint8_t *addrtypep,uint8_t rmd160[20],char fiat[4],uint8_t *shortflagp,int64_t *fiatoshisp)
{
    if ( rwflag != 0 )
    {
        memset(pubkey33,0,33);
        pubkey33[0] = 0x02 | (*shortflagp != 0);
        memcpy(&pubkey33[1],fiat,3);
        iguana_rwnum(rwflag,&pubkey33[4],sizeof(*fiatoshisp),(void *)fiatoshisp);
        pubkey33[12] = *addrtypep;
        memcpy(&pubkey33[13],rmd160,20);
    }
    else
    {
        *shortflagp = (pubkey33[0] == 0x03);
        memcpy(fiat,&pubkey33[1],3);
        fiat[3] = 0;
        iguana_rwnum(rwflag,&pubkey33[4],sizeof(*fiatoshisp),(void *)fiatoshisp);
        if ( *shortflagp != 0 )
            *fiatoshisp = -(*fiatoshisp);
        *addrtypep = pubkey33[12];
        memcpy(rmd160,&pubkey33[13],20);
    }
    return(33);
}

uint64_t PAX_fiatdest(uint64_t *seedp,int32_t tokomodo,char *destaddr,uint8_t pubkey33[33],char *coinaddr,int32_t kmdheight,char *origbase,int64_t fiatoshis)
{
    uint8_t shortflag=0; char base[4]; int32_t i; uint8_t addrtype,rmd160[20]; int64_t komodoshis=0;
    for (i=0; i<3; i++)
        base[i] = toupper((int32_t)origbase[i]);
    base[i] = 0;
    if ( strcmp(base,"KMD") == 0 )
        return(0);
    if ( fiatoshis < 0 )
        shortflag = 1, fiatoshis = -fiatoshis;
    komodoshis = dpow_paxprice(seedp,kmdheight,base,(char *)"KMD",(uint64_t)fiatoshis);
    if ( bitcoin_addr2rmd160(&addrtype,rmd160,coinaddr) == 20 )
    {
        PAX_pubkey(1,pubkey33,&addrtype,rmd160,base,&shortflag,tokomodo != 0 ? &komodoshis : &fiatoshis);
        bitcoin_address(destaddr,KOMODO_PUBTYPE,pubkey33,33);
    }
    return(komodoshis);
}

int32_t dpow_scriptitemlen(int32_t *opretlenp,uint8_t *script)
{
    int32_t opretlen,len = 0;
    if ( (opretlen= script[len++]) >= 0x4c )
    {
        if ( opretlen == 0x4c )
            opretlen = script[len++];
        else if ( opretlen == 0x4d )
        {
            opretlen = script[len++];
            opretlen = (opretlen << 8) | script[len++];
        }
    }
    *opretlenp = opretlen;
    return(len);
}

cJSON *dpow_paxjson(struct pax_transaction *pax)
{
    uint8_t addrtype,rmd160[20]; int32_t i; char rmdstr[41]; cJSON *item = cJSON_CreateObject();
    if ( pax != 0 )
    {
        jaddbits256(item,"prev_hash",pax->txid);
        jaddnum(item,"prev_vout",pax->vout);
        if ( pax->shortflag != 0 )
            jaddnum(item,"short",pax->shortflag);
        jaddnum(item,pax->symbol,dstr(pax->fiatoshis));
        jaddstr(item,"fiat",pax->symbol);
        jaddnum(item,"kmdheight",pax->kmdheight);
        jaddnum(item,"height",pax->height);
        jaddnum(item,"KMD",dstr(pax->komodoshis));
        jaddstr(item,"address",pax->coinaddr);
        bitcoin_addr2rmd160(&addrtype,rmd160,pax->coinaddr);
        for (i=0; i<20; i++)
            sprintf(&rmdstr[i<<1],"%02x",rmd160[i]);
        rmdstr[40] = 0;
        jaddstr(item,"rmd160",rmdstr);
    }
    return(item);
}

uint64_t dpow_paxtotal(struct dpow_info *dp)
{
    struct pax_transaction *pax,*tmp; uint64_t total = 0;
    pthread_mutex_lock(&dp->paxmutex);
    /*if ( dp->PAX != 0 )
    {
        tmp = 0;
        pax= dp->PAX->hh.next;
        while ( pax != 0 && pax != tmp )
        {
            if ( pax->marked == 0 )
                total += pax->komodoshis;
            tmp = pax;
            pax = pax->hh.next;
        }
    }*/
    HASH_ITER(hh,dp->PAX,pax,tmp)
    {
        if ( pax->marked == 0 )
            total += pax->komodoshis;
    }
    pthread_mutex_unlock(&dp->paxmutex);
    return(total);
}

struct pax_transaction *dpow_paxfind(struct dpow_info *dp,struct pax_transaction *space,bits256 txid,uint16_t vout)
{
    struct pax_transaction *pax;
    pthread_mutex_lock(&dp->paxmutex);
    HASH_FIND(hh,dp->PAX,&txid,sizeof(txid),pax);
    if ( pax != 0 )
        memcpy(space,pax,sizeof(*pax));
    pthread_mutex_unlock(&dp->paxmutex);
    return(pax);
}

struct pax_transaction *dpow_paxmark(struct dpow_info *dp,struct pax_transaction *space,bits256 txid,uint16_t vout,int32_t mark)
{
    struct pax_transaction *pax;
    pthread_mutex_lock(&dp->paxmutex);
    HASH_FIND(hh,dp->PAX,&txid,sizeof(txid),pax);
    if ( pax == 0 )
    {
        pax = (struct pax_transaction *)calloc(1,sizeof(*pax));
        pax->txid = txid;
        pax->vout = vout;
        HASH_ADD_KEYPTR(hh,dp->PAX,&pax->txid,sizeof(pax->txid),pax);
    }
    if ( pax != 0 )
    {
        pax->marked = mark;
        int32_t i; for (i=0; i<32; i++)
            printf("%02x",((uint8_t *)&txid)[i]);
        printf(" paxmark.ht %d vout%d\n",mark,vout);
        memcpy(space,pax,sizeof(*pax));
    }
    pthread_mutex_unlock(&dp->paxmutex);
    return(pax);
}

cJSON *dpow_withdraws_pending(struct dpow_info *dp)
{
    struct pax_transaction *pax,*tmp; cJSON *retjson = cJSON_CreateArray();
    pthread_mutex_lock(&dp->paxmutex);
    /*if ( dp->PAX != 0 )
    {
        tmp = 0;
        pax = dp->PAX->hh.next;
        while ( pax != 0 && pax != tmp )
        {
            if ( pax->marked == 0 )
                jaddi(retjson,dpow_paxjson(pax));
            tmp = pax;
            pax = pax->hh.next;
        }
    }*/
    HASH_ITER(hh,dp->PAX,pax,tmp)
    {
        if ( pax->marked == 0 )
            jaddi(retjson,dpow_paxjson(pax));
    }
    pthread_mutex_unlock(&dp->paxmutex);
    return(retjson);
}

void dpow_issuer_withdraw(struct dpow_info *dp,char *coinaddr,uint64_t fiatoshis,int32_t shortflag,char *symbol,uint64_t komodoshis,uint8_t *rmd160,bits256 txid,uint16_t vout,int32_t kmdheight,int32_t height) // assetchain context
{
    struct pax_transaction *pax;
    pthread_mutex_lock(&dp->paxmutex);
    HASH_FIND(hh,dp->PAX,&txid,sizeof(txid),pax);
    if ( pax == 0 )
    {
        pax = (struct pax_transaction *)calloc(1,sizeof(*pax));
        pax->txid = txid;
        pax->vout = vout;
        HASH_ADD_KEYPTR(hh,dp->PAX,&pax->txid,sizeof(pax->txid),pax);
    }
    pthread_mutex_unlock(&dp->paxmutex);
    if ( coinaddr != 0 )
    {
        strcpy(pax->coinaddr,coinaddr);
        pax->komodoshis = komodoshis;
        pax->shortflag = shortflag;
        strcpy(pax->symbol,symbol);
        pax->fiatoshis = fiatoshis;
        memcpy(pax->rmd160,rmd160,20);
        pax->kmdheight = kmdheight;
        pax->height = height;
        if ( pax->marked == 0 )
            printf("ADD WITHDRAW %s %.8f -> %s %.8f TO PAX kht.%d ht.%d\n",symbol,dstr(pax->fiatoshis),coinaddr,dstr(pax->komodoshis),kmdheight,height);
        else printf("MARKED WITHDRAW %s %.8f -> %s %.8f TO PAX kht.%d ht.%d\n",symbol,dstr(pax->fiatoshis),coinaddr,dstr(pax->komodoshis),kmdheight,height);
    }
    else
    {
        pax->marked = height;
        printf("MARK WITHDRAW ht.%d\n",height);
    }
}

void dpow_issuer_voutupdate(struct dpow_info *dp,char *symbol,int32_t isspecial,int32_t height,int32_t txi,bits256 txid,int32_t vout,int32_t numvouts,int64_t fiatoshis,uint8_t *script,int32_t len)
{
    char base[16],destaddr[64],coinaddr[64]; uint8_t addrtype,shortflag,rmd160[20],pubkey33[33]; int64_t checktoshis,komodoshis; uint64_t seed; struct pax_transaction space; int32_t i,kmdheight,opretlen,offset = 0;
    if ( script[offset++] == 0x6a )
    {
        memset(base,0,sizeof(base));
        offset += dpow_scriptitemlen(&opretlen,&script[offset]);
        if ( script[offset] == 'W' && strcmp(dp->symbol,"KMD") != 0 )
        {
            // if valid add to pricefeed for issue
            printf("notary vout.%s ht.%d txi.%d vout.%d %.8f opretlen.%d\n",symbol,height,txi,vout,dstr(fiatoshis),opretlen);
            if ( opretlen == 38 ) // any KMD tx
            {
                offset++;
                offset += PAX_pubkey(0,&script[offset],&addrtype,rmd160,base,&shortflag,&komodoshis);
                iguana_rwnum(0,&script[offset],sizeof(kmdheight),&kmdheight);
                if ( komodoshis < 0 )
                    komodoshis = -komodoshis;
                bitcoin_address(coinaddr,addrtype,rmd160,20);
                checktoshis = PAX_fiatdest(&seed,1,destaddr,pubkey33,coinaddr,kmdheight,base,fiatoshis);
                for (i=0; i<32; i++)
                    printf("%02x",((uint8_t *)&txid)[i]);
                printf(" <- txid.v%u ",vout);
                for (i=0; i<33; i++)
                    printf("%02x",pubkey33[i]);
                printf(" checkpubkey fiat %.8f check %.8f vs komodoshis %.8f dest.(%s) kmdheight.%d ht.%d seed.%llu\n",dstr(fiatoshis),dstr(checktoshis),dstr(komodoshis),destaddr,kmdheight,height,(long long)seed);
                if ( shortflag == 0 )
                {
                    if ( seed == 0 || checktoshis >= komodoshis )
                    {
                        if ( dpow_paxfind(dp,&space,txid,vout) == 0 )
                            dpow_issuer_withdraw(dp,coinaddr,fiatoshis,shortflag,base,komodoshis,rmd160,txid,vout,kmdheight,height);
                    }
                }
                else // short
                {
                    printf("shorting not yet, wait for pax2\n");
                    /*for (i=0; i<opretlen; i++)
                        printf("%02x",script[i]);
                    printf(" opret[%c] fiatoshis %.8f vs check %.8f\n",script[0],dstr(fiatoshis),dstr(checktoshis));
                    if ( seed == 0 || fiatoshis < checktoshis )
                    {
                        
                    }*/
                }
            }
        }
        else if ( script[offset] == 'X' && strcmp(dp->symbol,"KMD") == 0 )
        {
            printf("WITHDRAW issued ht.%d txi.%d vout.%d %.8f\n",height,txi,vout,dstr(fiatoshis));
            if ( opretlen == 46 ) // any KMD tx
            {
                offset++;
                offset += PAX_pubkey(0,&script[offset],&addrtype,rmd160,base,&shortflag,&fiatoshis);
                iguana_rwnum(0,&script[offset],sizeof(kmdheight),&kmdheight);
                iguana_rwnum(0,&script[offset],sizeof(height),&height);
                if ( fiatoshis < 0 )
                    fiatoshis = -fiatoshis;
                bitcoin_address(coinaddr,addrtype,rmd160,20);
                checktoshis = PAX_fiatdest(&seed,1,destaddr,pubkey33,coinaddr,kmdheight,base,fiatoshis);
                for (i=0; i<32; i++)
                    printf("%02x",((uint8_t *)&txid)[i]);
                printf(" <- txid.v%u ",vout);
                for (i=0; i<33; i++)
                    printf("%02x",pubkey33[i]);
                printf(" checkpubkey check %.8f v %.8f dest.(%s) height.%d\n",dstr(checktoshis),dstr(fiatoshis),destaddr,height);
                if ( shortflag == 0 )
                {
                    if ( seed == 0 || checktoshis > fiatoshis )
                    {
                        dpow_paxmark(dp,&space,txid,vout,height);
                    }
                }
                else
                {
                    printf("shorting not yet, wait for pax2\n");
                }
            }
        }
    }
}

int32_t dpow_issuer_tx(int32_t *isspecialp,struct dpow_info *dp,struct iguana_info *coin,int32_t height,int32_t txi,char *txidstr,uint32_t port)
{
    char *retstr,params[256],*hexstr; uint8_t script[16384]; cJSON *json,*oldpub,*newpub,*result,*vouts,*item,*sobj; int32_t vout,n,len,retval = -1; uint64_t value; bits256 txid;
    sprintf(params,"[\"%s\", 1]",txidstr);
    *isspecialp = 0;
    if ( (retstr= dpow_issuemethod(coin->chain->userpass,(char *)"getrawtransaction",params,port)) != 0 )
    {
        if ( (json= cJSON_Parse(retstr)) != 0 )
        {
            //printf("TX.(%s)\n",retstr);
            if ( (result= jobj(json,(char *)"result")) != 0 )
            {
                oldpub = jobj(result,(char *)"vpub_old");
                newpub = jobj(result,(char *)"vpub_new");
                retval = 0;
                if ( oldpub == 0 && newpub == 0 && (vouts= jarray(&n,result,(char *)"vout")) != 0 )
                {
                    txid = jbits256(result,(char *)"txid");
                    for (vout=0; vout<n; vout++)
                    {
                        item = jitem(vouts,vout);
                        value = SATOSHIDEN * jdouble(item,(char *)"value");
                        if ( (sobj= jobj(item,(char *)"scriptPubKey")) != 0 )
                        {
                            if ( (hexstr= jstr(sobj,(char *)"hex")) != 0 )
                            {
                                len = (int32_t)strlen(hexstr) >> 1;
                                if ( vout == 0 && ((memcmp(&hexstr[2],CRYPTO777_PUBSECPSTR,66) == 0 && len == 35) || (memcmp(&hexstr[6],CRYPTO777_RMD160STR,40) == 0 && len == 25)) )
                                    *isspecialp = 1;
                                else if ( len <= sizeof(script) )
                                {
                                    decode_hex(script,len,hexstr);
                                    dpow_issuer_voutupdate(dp,coin->symbol,*isspecialp,height,txi,txid,vout,n,value,script,len);
                                }
                            }
                        }
                    }
                }
            } else printf("error getting txids.(%s)\n",retstr);
            free_json(json);
        }
        free(retstr);
    }
    return(retval);
}

int32_t dpow_issuer_block(struct dpow_info *dp,struct iguana_info *coin,int32_t height,uint16_t port)
{
    char *retstr,*retstr2,params[128],*txidstr; int32_t i,isspecial,n,retval = -1; cJSON *json,*tx=0,*result=0,*result2;
    sprintf(params,"[%d]",height);
    if ( (retstr= dpow_issuemethod(coin->chain->userpass,(char *)"getblockhash",params,port)) != 0 )
    {
        if ( (result= cJSON_Parse(retstr)) != 0 )
        {
            if ( (txidstr= jstr(result,(char *)"result")) != 0 && strlen(txidstr) == 64 )
            {
                sprintf(params,"[\"%s\"]",txidstr);
                if ( (retstr2= dpow_issuemethod(coin->chain->userpass,(char *)"getblock",params,port)) != 0 )
                {
                    //printf("getblock.(%s)\n",retstr2);
                    if ( (json= cJSON_Parse(retstr2)) != 0 )
                    {
                        if ( (result2= jobj(json,(char *)"result")) != 0 && (tx= jarray(&n,result2,(char *)"tx")) != 0 )
                        {
                            for (i=0; i<n; i++)
                                if ( dpow_issuer_tx(&isspecial,dp,coin,height,i,jstri(tx,i),port) < 0 )
                                    break;
                            if ( i == n )
                                retval = 0;
                            else printf("dpow_issuer_block ht.%d error i.%d vs n.%d\n",height,i,n);
                        } else printf("cant get result.%p or tx.%p\n",result,tx);
                        free_json(json);
                    } else printf("cant parse2.(%s)\n",retstr2);
                    free(retstr2);
                } else printf("error getblock %s\n",params);
            } else printf("strlen.%ld (%s)\n",strlen(txidstr),txidstr);
            free_json(result);
        } else printf("couldnt parse.(%s)\n",retstr);
        free(retstr);
    } else printf("error from getblockhash %d\n",height);
    return(retval);
}

int32_t dpow_issuer_iteration(struct dpow_info *dp,struct iguana_info *coin,int32_t height,uint32_t *isrealtimep)
{
    char *retstr; int32_t i,currentheight=0; cJSON *infoobj,*result; uint16_t port = coin->chain->rpcport;
    if ( height <= 0 )
        height = 1;
    *isrealtimep = 0;
    if ( coin->getinfostr[0] == 0 )
        strcpy(coin->getinfostr,"getinfo");
    if ( (retstr= dpow_issuemethod(coin->chain->userpass,(char *)coin->getinfostr,0,port)) != 0 )
    {
        if ( (infoobj= cJSON_Parse(retstr)) != 0 )
        {
            if ( (result= jobj(infoobj,(char *)"result")) != 0 && (currentheight= jint(result,(char *)"blocks")) != 0 )
            {
                for (i=0; i<500 && height<=currentheight; i++,height++)
                {
                    /*fprintf(stderr,"%s.%d ",coin->symbol,height);
                    if ( (height % 10) == 0 )
                    {
                        if ( (height % 100) == 0 )
                            fprintf(stderr,"%s.%d ",coin->symbol,height);
                        memset(&zero,0,sizeof(zero));
                        komodo_stateupdate(height,0,0,0,zero,0,0,0,0,height,0,0,0,0,0);
                    }*/
                    if ( dpow_issuer_block(dp,coin,height,port) < 0 )
                    {
                        printf("error height %d\n",height);
                        break;
                    }
                    usleep(10000);
                }
                if ( height >= currentheight )
                    *isrealtimep = (uint32_t)time(NULL);
            }
            free_json(infoobj);
        }
        //printf("GETINFO.(%s)\n",retstr);
        free(retstr);
    }
    else
    {
        printf("error from %s height.%d currentheight.%d\n",coin->symbol,height,currentheight);
        usleep(100000);
    }
    //printf("[%s -> %s] %s ht.%d current.%d\n",dp->symbol,dp->dest,coin->symbol,height,currentheight);
    return(height);
}

