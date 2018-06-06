
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
//  LP_NXT.c
//  marketmaker
//


char *NXTnodes[] = { "62.75.159.113", "91.44.203.238", "82.114.88.225", "78.63.207.76", "188.174.110.224", "91.235.72.49", "213.144.130.91", "209.222.98.250", "216.155.128.10", "178.33.203.157", "162.243.122.251", "69.163.47.173", "193.151.106.129", "78.94.2.74", "192.3.196.10", "173.33.112.87", "104.198.173.28", "35.184.154.126", "174.140.167.239", "23.88.113.131", "198.71.84.173", "178.150.207.53", "23.88.61.53", "192.157.233.106", "192.157.241.212", "23.89.192.88", "23.89.200.27", "192.157.241.139", "23.89.200.63", "23.89.192.98", "163.172.214.102", "176.9.85.5", "80.150.243.88", "80.150.243.92", "80.150.243.98", "109.70.186.198", "146.148.84.237", "104.155.56.82", "104.197.157.140", "37.48.73.249", "146.148.77.226", "84.57.170.200", "107.161.145.131", "80.150.243.97", "80.150.243.93", "80.150.243.100", "80.150.243.95", "80.150.243.91", "80.150.243.99", "80.150.243.96", "93.231.187.177", "212.237.23.85", "35.158.179.254", "46.36.66.41", "185.170.113.79", "163.172.68.112", "78.47.35.210", "77.90.90.75", "94.177.196.134", "212.237.22.215", "94.177.234.11", "167.160.180.199", "54.68.189.9", "94.159.62.14", "195.181.221.89", "185.33.145.94", "195.181.209.245", "195.181.221.38", "195.181.221.162", "185.33.145.12", "185.33.145.176", "178.79.128.235", "94.177.214.120", "94.177.199.41", "94.177.214.200", "94.177.213.201", "212.237.13.162", "195.181.221.236", "195.181.221.185", "185.28.103.187", "185.33.146.244", "217.61.123.71", "195.181.214.45", "195.181.212.99", "195.181.214.46", "195.181.214.215", "195.181.214.68", "217.61.123.118", "195.181.214.79", "217.61.123.14", "217.61.124.100", "195.181.214.111", "85.255.0.176", "81.2.254.116", "217.61.123.184", "195.181.212.231", "94.177.214.110", "195.181.209.164", "104.129.56.238", "85.255.13.64", "167.160.180.206", "217.61.123.226", "167.160.180.208", "93.186.253.127", "212.237.6.208", "94.177.207.190", "217.61.123.119", "85.255.1.245", "217.61.124.157", "37.59.57.141", "167.160.180.58", "104.223.53.14", "217.61.124.69", "195.181.212.103", "85.255.13.141", "104.207.133.204", "71.90.7.107", "107.150.18.108", "23.94.134.161", "80.150.243.13", "80.150.243.11", "185.81.165.52", "80.150.243.8" };

static char *assetids[][4] =
{
    { "13502152099823770958", "SUPERNETx2", "10000", "10000" },
    { "12071612744977229797", "SUPERNET", "10000", "10000" },
    { "12071612744977229797", "UNITY", "10000", "10000" },
    { "15344649963748848799", "DEX", "1", "100000000" },
    { "6883271355794806507", "PANGEA", "10000", "10000" },
    { "17911762572811467637", "JUMBLR", "10000", "10000" },
    { "17083334802666450484", "BET", "10000", "10000" },
    { "13476425053110940554", "CRYPTO", "1000", "100000" },
    { "6932037131189568014", "HODL", "1", "100000000" },
    //{ "3006420581923704757", "SHARK", "10000", "10000" },
    { "3006420581923704757", "MSHARK", "10", "10000000" },
    { "17571711292785902558", "BOTS", "1", "100000000" },
    { "10524562908394749924", "MGW", "1", "100000000" },
    { "8217222248380501882", "MESH", "10000", "10000" },
    { "15641806960898178066", "TOKEN", "1", "100000000" },
};

void LP_sendtoaddress_line(char *validaddress,char *assetname,uint64_t satoshis,uint64_t txnum)
{
    char line[1024],lowerstr[64];
    if ( strcmp(assetname,"SUPERNETx2") == 0 )
    {
        sprintf(line,"fiat/supernet sendtoaddress %s %.8f # txnum.%llu",validaddress,dstr(satoshis),(long long)txnum);
        printf("%s\n",line);
        sprintf(line,"fiat/revs sendtoaddress %s %.8f # txnum.%llu",validaddress,dstr(satoshis),(long long)txnum);
    }
    else
    {
        if ( strcmp(assetname,"TOKEN") == 0 )
            strcpy(lowerstr,"supernet");
        else strcpy(lowerstr,assetname);
        tolowercase(lowerstr);
        sprintf(line,"sleep 1; fiat/%s sendtoaddress %s %.8f # txnum.%llu",lowerstr,validaddress,dstr(satoshis),(long long)txnum);
    }
    printf("%s\n",line);
}

uint64_t LP_assetid_mult(int32_t *assetindp,char *name,uint64_t assetid)
{
    int32_t i; uint64_t mult = 0;
    name[0] = 0;
    *assetindp = -1;
    for (i=0; i<sizeof(assetids)/sizeof(*assetids); i++)
    {
        if ( assetid == calc_nxt64bits(assetids[i][0]) )
        {
            *assetindp = i;
            mult = atoi(assetids[i][3]);
            strcpy(name,assetids[i][1]);
            break;
        }
    }
    return(mult);
}

cJSON *LP_NXT_message(char *method,uint64_t txnum,char *passphrase)
{
    char url[1024],*retstr; cJSON *retjson = 0;
    sprintf(url,"http://127.0.0.1:7876/nxt?requestType=%s&transaction=%llu&secretPhrase=%s",method,(long long)txnum,passphrase);
    //printf("issue.(%s)\n",url);
    if ( (retstr= issue_curlt(url,LP_HTTP_TIMEOUT)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            
        }
        free(retstr);
    }
    return(retjson);
}

cJSON *LP_NXT_decrypt(uint64_t txnum,char *account,char *data,char *nonce,char *passphrase)
{
    char url[1024],*retstr; cJSON *retjson = 0;
    if ( account != 0 && data != 0 && nonce != 0 && passphrase != 0 )
    {
        sprintf(url,"http://127.0.0.1:7876/nxt?requestType=readMessage&transaction=%llu&secretPhrase=%s",(long long)txnum,passphrase);
        if ( (retstr= issue_curlt(url,LP_HTTP_TIMEOUT)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                
            }
            free(retstr);
        }
    }
    return(retjson);
}

int64_t NXTventure_qty(uint64_t assetid)
{
    char url[1024],*retstr; uint64_t qty=0; cJSON *retjson;
    sprintf(url,"http://127.0.0.1:7876/nxt?requestType=getAccountAssets&account=NXT-XRK4-5HYK-5965-9FH4Z&includeAssetInfo=true");
    if ( (retstr= issue_curlt(url,LP_HTTP_TIMEOUT)) != 0 )
    {
        printf("NXT_venture_qty(%s)\n",retstr);
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            free_json(retjson);
        }
        free(retstr);
    }
    //NXT_venture_qty({"accountAssets":[{"quantityQNT":"3900000000","unconfirmedQuantityQNT":"3900000000","decimals":4,"name":"ATOMIC","asset":"11694807213441909013"},{"quantityQNT":"2900000000","unconfirmedQuantityQNT":"2900000000","decimals":8,"name":"NSC","asset":"6775372232354238105"},{"quantityQNT":"750000000","unconfirmedQuantityQNT":"750000000","decimals":4,"name":"omnigames","asset":"7441230892853180965"},{"quantityQNT":"607438148","unconfirmedQuantityQNT":"607438148","decimals":4,"name":"ARDR","asset":"12422608354438203866"},{"quantityQNT":"451991779","unconfirmedQuantityQNT":"451991779","decimals":4,"name":"SuperNET","asset":"12071612744977229797"},{"quantityQNT":"146960000","unconfirmedQuantityQNT":"146960000","decimals":4,"name":"Privatebet","asset":"17083334802666450484"},{"quantityQNT":"79500188","unconfirmedQuantityQNT":"79500188","decimals":3,"name":"crypto777","asset":"13476425053110940554"},{"quantityQNT":"1495473","unconfirmedQuantityQNT":"1495473","decimals":0,"name":"jl777hodl","asset":"6932037131189568014"},{"quantityQNT":"500000","unconfirmedQuantityQNT":"500000","decimals":0,"name":"Boost","asset":"9719950459730291994"},{"quantityQNT":"200000","unconfirmedQuantityQNT":"200000","decimals":0,"name":"NXTforex","asset":"15245281832566929110"},{"quantityQNT":"150000","unconfirmedQuantityQNT":"150000","decimals":0,"name":"NXTsharks","asset":"8049009002993773168"},{"quantityQNT":"100000","unconfirmedQuantityQNT":"100000","decimals":5,"name":"solarweb","asset":"13604572534081373849"},{"quantityQNT":"75000","unconfirmedQuantityQNT":"75000","decimals":0,"name":"SNN","asset":"15113552914305929842"},{"quantityQNT":"57299","unconfirmedQuantityQNT":"57299","decimals":2,"name":"SLEUTH","asset":"4174874835406708311"},{"quantityQNT":"18801","unconfirmedQuantityQNT":"18801","decimals":2,"name":"BTCDdev","asset":"15131486578879082754"},{"quantityQNT":"18767","unconfirmedQuantityQNT":"18767","decimals":2,"name":"longzai","asset":"10955830010602647139"},{"quantityQNT":"13000","unconfirmedQuantityQNT":"13000","decimals":0,"name":"NXTventure","asset":"16212446818542881180"},{"quantityQNT":"7250","unconfirmedQuantityQNT":"7250","decimals":0,"name":"InstantDEX","asset":"15344649963748848799"},{"quantityQNT":"2873","unconfirmedQuantityQNT":"2873","decimals":4,"name":"EDinar","asset":"17740527756732147253"},{"quantityQNT":"39","unconfirmedQuantityQNT":"39","decimals":0,"name":"JebBush","asset":"1929419574701797581"},{"quantityQNT":"30","unconfirmedQuantityQNT":"30","decimals":0,"name":"Hilary","asset":"11814755740231942504"}],"requestProcessingTime":1})
    return(qty);
}

void *curl_post(void **cHandlep,char *url,char *userpass,char *postfields,char *hdr0,char *hdr1,char *hdr2,char *hdr3);

void NXTventure_liquidation()
{
    /*{"quantityQNT":"607438148","unconfirmedQuantityQNT":"607438148","decimals":4,"name":"ARDR","asset":""},
     {"quantityQNT":"451991779","unconfirmedQuantityQNT":"451991779","decimals":4,"name":"SuperNET","asset":"12071612744977229797"},
     {"quantityQNT":"146960000","unconfirmedQuantityQNT":"146960000","decimals":4,"name":"Privatebet","asset":"17083334802666450484"},
     {"quantityQNT":"79500188","unconfirmedQuantityQNT":"79500188","decimals":3,"name":"crypto777","asset":"13476425053110940554"},
     {"quantityQNT":"1495473","unconfirmedQuantityQNT":"1495473","decimals":0,"name":"jl777hodl","asset":"6932037131189568014"},
     {"quantityQNT":"7250","unconfirmedQuantityQNT":"7250","decimals":0,"name":"InstantDEX","asset":"15344649963748848799"},*/
    char *assetids[][4] =
    {
        { "12422608354438203866", "607438148", "ARDR", "10000" },
        { "12071612744977229797", "451991779", "SuperNET", "10000" },
        { "17083334802666450484", "146960000", "Privatebet", "10000" },
        { "13476425053110940554", "79500188", "crypto777", "1000" },
        { "6932037131189568014", "1495473", "jl777hodl", "1" },
        { "15344649963748848799", "7250", "InstantDEX", "1" },
    };
    void *cHandle=0; char *retstr,*retstr2,url[1024],*account; uint64_t txid,qty,qtyA,assetid,sum; double ratio; cJSON *array,*retjson2,*item,*retjson; int32_t i,j,decimals,numassetids=(int32_t)(sizeof(assetids)/sizeof(*assetids)),n=0;
    char *passphrase = "";
    sprintf(url,"http://127.0.0.1:7876/nxt?requestType=getAssetAccounts&asset=16212446818542881180");
    if ( (retstr= issue_curlt(url,LP_HTTP_TIMEOUT)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (array= jarray(&n,retjson,"accountAssets")) != 0 )
            {
                for (j=0; j<numassetids; j++)
                {
                    assetid = calc_nxt64bits(assetids[j][0]);
                    qtyA = calc_nxt64bits(assetids[j][1]);
                    decimals = (int32_t)calc_nxt64bits(assetids[j][3]);
                    printf("distribute %llu QNT of %s assetid %llu %.8f\n",(long long)qtyA,assetids[j][2],(long long)assetid,(double)qtyA / decimals);
                    sum = 0;
                    for (i=0; i<n; i++)
                    {
                        item = jitem(array,i);
                        qty = j64bits(item,"quantityQNT");
                        ratio = (double)qty / (1000000. - 13000.);
                        if ( (account= jstr(item,"accountRS")) != 0 && qtyA*ratio >= 1 )
                        {
                            if ( strcmp(account,"NXT-XRK4-5HYK-5965-9FH4Z") != 0 )
                            {
                                sum += (long long)(qtyA * ratio);
                                sprintf(url,"requestType=transferAsset&secretPhrase=%s&recipient=%s&asset=%llu&quantityQNT=%llu&feeNQT=100000000&deadline=60",passphrase,account,(long long)assetid,(long long)(qtyA * ratio));
                                if ( (retstr2= curl_post(&cHandle,"http://127.0.0.1:7876/nxt","",url,"","","","")) != 0 )
                                {
                                    if ( (retjson2= cJSON_Parse(retstr2)) != 0 )
                                    {
                                        txid = j64bits(retjson2,"transaction");
                                        printf("%s %.6f %8llu QNT %s -> %llu %.8f txid %llu\n",account,ratio,(long long)qtyA,assetids[j][2],(long long)(qtyA * ratio),((double)(long long)(qtyA * ratio))/decimals,(long long)txid);
                                        free_json(retjson2);
                                    }
                                    free(retstr2);
                                }
                                usleep(250000);
                            }
                        }
                    }
                    printf("%s distribution total %llu QNT %.8f\n",assetids[j][2],(long long)sum,(double)sum/decimals);
                }
            }
            free_json(retjson);
        }
        printf("NXTventure assethodlers.%d\n",n);
        free(retstr);
    }
}

cJSON *LP_NXT_redeems()
{
    char url[1024],*retstr,*recv,*method,*msgstr,assetname[128]; uint64_t totals[2][sizeof(assetids)/sizeof(*assetids)],mult,txnum,assetid,qty; int32_t i,ind,numtx=0,past_marker=0; cJSON *item,*attach,*decjson,*array,*msgjson,*encjson,*retjson=0;
    uint64_t txnum_marker = calc_nxt64bits("2675953695997905027"); // 4114304329372848717, 8537615468620726612"); // set to most recent processed
    uint64_t txnum_marker2 = calc_nxt64bits("7256847492742571143"); // dont change, end marker
    char *passphrase = "";
    char *account = "NXT-MRBN-8DFH-PFMK-A4DBM";
    memset(totals,0,sizeof(totals));
    sprintf(url,"http://127.0.0.1:7876/nxt?requestType=getBlockchainTransactions&account=%s",account);
    //printf("calling (%s)\n",url);
    if ( (retstr= issue_curlt(url,LP_HTTP_TIMEOUT)) != 0 )
    {
        //printf("got.(%s)\n",retstr);
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (array= jarray(&numtx,retjson,"transactions")) != 0 )
            {
                for (i=0; i<numtx; i++)
                {
                    msgjson = encjson = decjson = 0;
                    txnum = assetid = qty = 0;
                    item = jitem(array,i);
                    msgstr = jstr(item,"message");
                    txnum = j64bits(item,"transaction");
                    if ( txnum == txnum_marker )
                        past_marker = 1;
                    //printf("%d: %s\n",i,jprint(item,0));
                    if ( (recv= jstr(item,"recipientRS")) != 0 && strcmp(recv,"NXT-MRBN-8DFH-PFMK-A4DBM") == 0 )
                    {
                        if ( (attach= jobj(item,"attachment")) != 0 && jint(attach,"version.AssetTransfer") == 1 )
                        {
                            assetid = j64bits(attach,"asset");
                            qty = j64bits(attach,"quantityQNT");
                            //printf("txnum.%llu (%s)\n",(long long)txnum,jprint(attach,0));
                            if ( (msgstr == 0 || msgstr[0] == 0) && jint(attach,"version.PrunablePlainMessage") == 1 )
                            {
                                method = "getPrunableMessage";
                                if ( (msgjson= LP_NXT_message(method,txnum,"test")) != 0 )
                                {
                                    msgstr = jstr(msgjson,"message");
                                    //printf("%d method.(%s) (%s)\n",i,method,msgstr);
                                }
                            }
                            if ( msgstr == 0 || msgstr[0] == 0 )
                                msgstr = jstr(attach,"message");
                            if ( msgstr == 0 || msgstr[0] == 0 )
                            {
                                
                                if ( (encjson= jobj(attach,"encryptedMessage")) != 0 )
                                {
                                    msgstr = "encryptedMessage";//jstr(encjson,"data");
                                    if ( (decjson= LP_NXT_decrypt(txnum,account,jstr(encjson,"data"),jstr(encjson,"nonce"),passphrase)) != 0 )
                                    {
                                        //printf("%s\n",jprint(decjson,0));
                                        if ( jstr(decjson,"decryptedMessage") != 0 )
                                            msgstr = jstr(decjson,"decryptedMessage");
                                    }
                                }
                            }
                        }
                        mult = LP_assetid_mult(&ind,assetname,assetid);
                        if ( ind >= 0 )
                            totals[past_marker][ind] += qty * mult;
                        if ( msgstr != 0 && assetname[0] != 0 && qty != 0 )
                        {
                            char validaddress[64]; int32_t z,n;
                            n = (int32_t)strlen(msgstr);
                            for (z=0; z<n; z++)
                            {
                                if ( msgstr[z] == 'R' )
                                    break;
                            }
                            memset(validaddress,0,sizeof(validaddress));
                            if ( n-z >= 34 )
                                strncpy(validaddress,&msgstr[z],34);
                            if ( txnum == calc_nxt64bits("4545341872872347590") )
                                strcpy(validaddress,"RKuwq4oi4mqQ2V4r54mPEthn3TBrEwu2Ni");
                            if ( past_marker == 0 )
                            {
                                if ( strlen(validaddress) == 34 || strlen(validaddress) == 33 )
                                {
                                    //printf("%-4d: (%34s) <- %13.5f %10s tx.%llu past_marker.%d\n",i,validaddress,dstr(qty * mult),assetname,(long long)txnum,past_marker);
                                    LP_sendtoaddress_line(validaddress,assetname,(qty * mult),txnum);
                                } else printf("%-4d: (%34s) <- %13.5f %10s tx.%llu\n",i,msgstr!=0?msgstr:jprint(item,0),dstr(qty * mult),assetname,(long long)txnum);
                            }
                        }
                        if ( msgjson != 0 )
                            free_json(msgjson);
                        if ( decjson != 0 )
                            free_json(decjson);
                    }
                    if ( txnum == txnum_marker2 )
                        break;
                }
            }
            //free_json(retjson);
        }
        free(retstr);
    } else printf("null return from NXT api call\n");
    printf("\nTotal redeemed.%d\n",numtx);
    for (past_marker=0; past_marker<2; past_marker++)
    {
        for (i=0; i<sizeof(totals[0])/sizeof(*totals[0]); i++)
        {
            if ( totals[past_marker][i] != 0 )
                printf("%-10s %13.5f past_marker.%d\n",assetids[i][1],dstr(totals[past_marker][i]),past_marker);
        }
        printf("\n>>>>>>>>>> already processed:\n");
    }
    return(retjson);
}

cJSON *LP_assethbla(char *assetid)
{
    char url[1024],*retstr; int32_t n; cJSON *array,*bid=0,*ask=0,*retjson;
    sprintf(url,"http://%s:7876/nxt?requestType=getBidOrders&asset=%s&firstIndex=0&lastIndex=0",NXTnodes[LP_rand() % (sizeof(NXTnodes)/sizeof(*NXTnodes))],assetid);
    if ( (retstr= issue_curlt(url,LP_HTTP_TIMEOUT)) != 0 )
    {
        bid = cJSON_Parse(retstr);
        free(retstr);
    }
    sprintf(url,"http://%s:7876/nxt?requestType=getAskOrders&asset=%s&firstIndex=0&lastIndex=0",NXTnodes[LP_rand() % (sizeof(NXTnodes)/sizeof(*NXTnodes))],assetid);
    if ( (retstr= issue_curlt(url,LP_HTTP_TIMEOUT)) != 0 )
    {
        ask = cJSON_Parse(retstr);
        free(retstr);
    }
    retjson = cJSON_CreateObject();
    if ( bid != 0 && ask != 0 )
    {
        if ( (array= jarray(&n,bid,"bidOrders")) != 0 )
            jadd(retjson,"bid",jduplicate(jitem(array,0)));
        if ( (array= jarray(&n,ask,"askOrders")) != 0 )
            jadd(retjson,"ask",jduplicate(jitem(array,0)));
    }
    if ( bid != 0 )
        free_json(bid);
    if ( ask != 0 )
        free_json(ask);
    return(retjson);
}

