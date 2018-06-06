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

#define WHITELIST_IPADDR ""

#include "iguana777.h"
//#include "SuperNET.h"

#define RPCARGS struct supernet_info *myinfo,uint16_t port,struct iguana_info *coin,cJSON *params[],int32_t n,cJSON *json,char *remoteaddr,cJSON *array,char *userpass
#define GLUEARGS cJSON *json,struct supernet_info *myinfo,uint16_t port,struct iguana_info *coin,char *remoteaddr,cJSON *params[],char *userpass

#define CALLGLUE myinfo,port,coin,remoteaddr,params,userpass

char *sglue(GLUEARGS,char *agent,char *method)
{
    char *retstr,*rpcretstr,*walletstr,checkstr[65],dcheckstr[65]; cJSON *retjson,*tmpjson,*result,*error,*wallet; int32_t i,j,len; int64_t val; double dval;
    if ( json == 0 )
        json = cJSON_CreateObject();
//printf("userpass.(%s)\n",userpass);
    jaddstr(json,"agent",agent);
    jaddstr(json,"method",method);
    if ( coin != 0 )
        jaddstr(json,"coin",coin->symbol);
    if ( userpass != 0 )
        jaddstr(json,"userpass",userpass);
    if ( coin != 0 && coin->FULLNODE >= 0 && coin->chain->userpass[0] != 0 )
    {
        if ( userpass == 0 || strcmp(userpass,coin->chain->userpass) != 0 )
        {
            printf("iguana authentication error {%s} (%s) != (%s)\n",jprint(json,0),userpass,coin->chain->userpass);
            return(clonestr("{\"error\":\"authentication error\"}"));
        }
    }
    if ( myinfo->expiration != 0 && time(NULL) > myinfo->expiration )
        iguana_walletlock(myinfo,0);
    if ( (retstr= SuperNET_JSON(myinfo,coin,json,remoteaddr,port)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( myinfo->dirty != 0 && myinfo->secret[0] != 0 )
            {
                if ( (wallet= iguana_walletjson(myinfo)) != 0 )
                {
                    if ( (walletstr= SuperNET_login(myinfo,coin,json,remoteaddr,myinfo->handle,myinfo->secret,myinfo->permanentfile,0)) != 0 )
                    {
                        free(walletstr);
                        walletstr = myinfo->decryptstr, myinfo->decryptstr = 0;
                        if ( walletstr != 0 && (tmpjson= cJSON_Parse(walletstr)) != 0 )
                        {
                            jdelete(tmpjson,"wallet");
                            jadd(tmpjson,"wallet",wallet);
                            if ( iguana_payloadupdate(myinfo,coin,jprint(tmpjson,1),0,0) == 0 )
                            {
                                //printf("wallet updated\n");
                                myinfo->dirty = 0;
                            } else printf("iguana_payloadupdate error\n");
                        } else printf("error parsing decryptstr\n");
                        if ( walletstr != 0 )
                            free(walletstr);
                    } else printf("ERROR: dirty wallet is unsaved, iguana_payloadupdate error\n");
                } else printf("ERROR: dirty wallet is unsaved, unlock wallet\n");
            }
            if ( jobj(retjson,"tag") != 0 )
                jdelete(retjson,"tag");
            ///printf("RPCret.(%s) n.%d\n",jprint(retjson,0),cJSON_GetArraySize(retjson));
            result = cJSON_GetObjectItem(retjson,"result");
            error = cJSON_GetObjectItem(retjson,"error");
            if ( result != 0 && cJSON_GetArraySize(retjson) == 1 )
            {
                if ( (error == 0 || (error->type&0xff) == cJSON_NULL) && (result->type&0xff) != cJSON_NULL )
                {
                    rpcretstr = cJSON_Print(result);
                    len = (int32_t)strlen(rpcretstr);
                    if ( rpcretstr[0] == '"' && rpcretstr[len-1] == '"' )
                    {
                        for (i=1,j=0; i<len-1; i++,j++)
                            rpcretstr[j] = rpcretstr[i];
                        //rpcretstr[j++] = '\n';
                        rpcretstr[j] = 0;
                        free_json(retjson);
                        free(retstr);
                        return(rpcretstr);
                    }
                    else
                    {
                        dval = atof(rpcretstr);
                        sprintf(dcheckstr,"%.8f",dval);
                        val = atol(rpcretstr);
                        sprintf(checkstr,"%lld",(long long)val);
                        if ( strcmp(checkstr,rpcretstr) == 0 || strcmp(dcheckstr,rpcretstr) == 0 )
                        {
                            free_json(retjson);
                            free(retstr);
                            return(rpcretstr);
                        }
                    }
                    free(rpcretstr);
                }
                else if ( (error->type&0xff) != cJSON_NULL || (result->type&0xff) != cJSON_NULL )
                    printf("<<<<<<<<<<< bitcoind_RPC: post_process_bitcoind_RPC error.%s\n",retstr);
            }
            free_json(retjson);
        }
    }
    //free_json(json);
    return(retstr);
}

char *sglue1(GLUEARGS,char *agent,char *method,char *field,cJSON *obj)
{
    if ( json == 0 )
        json = cJSON_CreateObject();
    if ( obj != 0 && field != 0 )
        jadd(json,field,obj);
    params[0] = 0;
    //printf("sglue1.(%s)\n",jprint(json,0));
    return(sglue(json,CALLGLUE,agent,method));
}

char *sglueN(GLUEARGS,char *agent,char *method,char *field,double num)
{
    if ( json == 0 )
        json = cJSON_CreateObject();
    jaddnum(json,field,num);
    return(sglue(json,CALLGLUE,agent,method));
}

char *sglue2(GLUEARGS,char *agent,char *method,char *field0,cJSON *obj0,char *field1,cJSON *obj1)
{
    if ( json == 0 )
        json = cJSON_CreateObject();
    if ( obj1 != 0 && field1 != 0 )
        jadd(json,field1,obj1);
    params[1] = 0;
    //printf("sglue2.(%s)\n",jprint(json,0));
    return(sglue1(json,CALLGLUE,agent,method,field0,obj0));
}

char *sglue3(GLUEARGS,char *agent,char *method,char *field0,cJSON *obj0,char *field1,cJSON *obj1,char *field2,cJSON *obj2)
{
    if ( json == 0 )
        json = cJSON_CreateObject();
    if ( obj2 != 0 && field2 != 0 )
        jadd(json,field2,obj2);
    params[2] = 0;
    //printf("sglue3.(%s)\n",jprint(json,0));
    return(sglue2(json,CALLGLUE,agent,method,field0,obj0,field1,obj1));
}

char *sglue4(GLUEARGS,char *agent,char *method,char *field0,cJSON *obj0,char *field1,cJSON *obj1,char *field2,cJSON *obj2,char *field3,cJSON *obj3)
{
    if ( json == 0 )
        json = cJSON_CreateObject();
    if ( obj3 != 0 && field3 != 0 )
        jadd(json,field3,obj3);
    params[3] = 0;
    return(sglue3(json,CALLGLUE,agent,method,field0,obj0,field1,obj1,field2,obj2));
}

char *sglue5(GLUEARGS,char *agent,char *method,char *field0,cJSON *obj0,char *field1,cJSON *obj1,char *field2,cJSON *obj2,char *field3,cJSON *obj3,char *field4,cJSON *obj4)
{
    if ( json == 0 )
        json = cJSON_CreateObject();
    if ( obj4 != 0 && field4 != 0 )
        jadd(json,field4,obj4);
    params[4] = 0;
    return(sglue4(json,CALLGLUE,agent,method,field0,obj0,field1,obj1,field2,obj2,field3,obj3));
}

char *sglue6(GLUEARGS,char *agent,char *method,char *field0,cJSON *obj0,char *field1,cJSON *obj1,char *field2,cJSON *obj2,char *field3,cJSON *obj3,char *field4,cJSON *obj4,char *field5,cJSON *obj5)
{
    if ( json == 0 )
        json = cJSON_CreateObject();
    if ( obj5 != 0 && field5 != 0 )
        jadd(json,field5,obj5);
    params[5] = 0;
    return(sglue5(json,CALLGLUE,agent,method,field0,obj0,field1,obj1,field2,obj2,field3,obj3,field4,obj4));
}

// misc
static char *help(RPCARGS)
{
    return(sglue(0,CALLGLUE,"SuperNET","help"));
}

static char *stop(RPCARGS)
{
    return(sglue(0,CALLGLUE,"iguana","pausecoin"));
}

static char *sendalert(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"iguana","sendalert","message",params[0]));
}

static char *SuperNET(RPCARGS)
{
    return(SuperNET_JSON(myinfo,coin,json,remoteaddr,port));
}

static char *getrawmempool(RPCARGS)
{
    return(sglue(0,CALLGLUE,"iguana","getrawmempool"));
}

// peers
static char *getconnectioncount(RPCARGS)
{
    return(sglue(0,CALLGLUE,"iguana","getconnectioncount"));
}

static char *getpeerinfo(RPCARGS)
{
    return(sglue(0,CALLGLUE,"iguana","peers"));
}

static char *addnode(RPCARGS)
{
    char *mode,*cmd = 0;
    if ( (mode= jstr(params[1],0)) != 0 )
    {
        if ( strcmp(mode,"add") == 0 )
            cmd = "addnode";
        else if ( strcmp(mode,"remove") == 0 )
            cmd = "removenode";
        else if ( strcmp(mode,"onetry") == 0 )
            cmd = "onetry";
        if ( cmd != 0 )
            return(sglue1(0,CALLGLUE,"iguana",cmd,"ipaddr",params[0]));
    }
    // addnode	<node> <add/remove/onetry>	version 0.8 Attempts add or remove <node> from the addnode list or try a connection to <node> once.	N
    return(clonestr("{\"error\":\"invalid addnode parameter\"}"));
}

// address and pubkeys
static char *validateaddress(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","validateaddress","address",params[0]));
}

static char *validatepubkey(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","validatepubkey","pubkey",params[0]));
}

static char *createmultisig(RPCARGS)
{
    return(sglue2(0,CALLGLUE,"bitcoinrpc","createmultisig","M",params[0],"pubkeys",params[1]));
}

static char *addmultisigaddress(RPCARGS)
{
    return(sglue3(0,CALLGLUE,"bitcoinrpc","addmultisigaddress","M",params[0],"pubkeys",params[1],"account",params[2]));
}

// blockchain
static char *getinfo(RPCARGS)
{
    return(sglue(0,CALLGLUE,"bitcoinrpc","getinfo"));
}

static char *getbestblockhash(RPCARGS)
{
    return(sglue(0,CALLGLUE,"bitcoinrpc","getbestblockhash"));
}

static char *getblockcount(RPCARGS)
{
    return(sglue(0,CALLGLUE,"bitcoinrpc","getblockcount"));
}

static char *getdifficulty(RPCARGS)
{
    return(sglue(0,CALLGLUE,"bitcoinrpc","getdifficulty"));
}

static char *getblock(RPCARGS)
{
    cJSON *obj;
    if ( params[1] == 0 )
        params[1] = cJSON_CreateNumber(1);
    else
    {
        obj = params[1];
        if ( is_cJSON_False(params[1]) != 0 )
            params[1] = cJSON_CreateNumber(0);
        else params[1] = cJSON_CreateNumber(1);
        free_json(obj);
    }
    return(sglue3(0,CALLGLUE,"bitcoinrpc","getblock","blockhash",params[0],"verbose",params[1],"remoteonly",params[2]));
}

static char *getblockhash(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","getblockhash","height",params[0]));
}

static char *gettransaction(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","gettransaction","txid",params[0]));
}

static char *listtransactions(RPCARGS)
{
    return(sglue3(0,CALLGLUE,"bitcoinrpc","listtransactions","account",params[0],"count",params[1],"from",params[2]));
}

static char *getreceivedbyaddress(RPCARGS)
{
    return(sglue2(0,CALLGLUE,"bitcoinrpc","getreceivedbyaddress","address",params[0],"minconfs",params[1]));
}

static char *listreceivedbyaddress(RPCARGS)
{
    return(sglue2(0,CALLGLUE,"bitcoinrpc","listreceivedbyaddress","minconf",params[0],"includeempty",params[1]));
}

static char *listsinceblock(RPCARGS)
{
    return(sglue2(0,CALLGLUE,"bitcoinrpc","listsinceblock","blockhash",params[0],"target",params[1]));
}

// waccount and waddress funcs
static char *getreceivedbyaccount(RPCARGS)
{
    return(sglue2(0,CALLGLUE,"bitcoinrpc","getreceivedbyaccount","account",params[0],"minconfs",params[1]));
}

static char *listreceivedbyaccount(RPCARGS)
{
    return(sglue2(0,CALLGLUE,"bitcoinrpc","listreceivedbyaccount","account",params[0],"includeempty",params[1]));
}

static char *getnewaddress(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","getnewaddress","account",params[0]));
}

static char *vanitygen(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","vanitygen","vanity",params[0]));
}

static char *makekeypair(RPCARGS)
{
    return(sglue(0,CALLGLUE,"bitcoinrpc","makekeypair"));
}

static char *getaccountaddress(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","getaccountaddress","account",params[0]));
}

static char *setaccountrpc(RPCARGS)
{
    return(sglue2(0,CALLGLUE,"bitcoinrpc","setaccount","address",params[0],"account",params[1]));
}

static char *getaccount(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","getaccount","address",params[0]));
}

static char *getaddressesbyaccount(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","getaddressesbyaccount","account",params[0]));
}

static char *listaddressgroupings(RPCARGS)
{
    return(sglue(0,CALLGLUE,"bitcoinrpc","listaddressgroupings"));
}

static char *getbalance(RPCARGS)
{
    return(sglue2(0,CALLGLUE,"bitcoinrpc","getbalance","account",params[0],"minconf",params[1]));
}

// wallet
static char *listaccounts(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","listaccounts","minconf",params[0]));
}

static char *dumpprivkey(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","dumpprivkey","address",params[0]));
}

static char *importaddress(RPCARGS)
{
    return(sglue3(0,CALLGLUE,"bitcoinrpc","importaddress","address",params[0],"account",params[1],"rescan",params[2]));
}

static char *importprivkey(RPCARGS)
{
    return(sglue3(0,CALLGLUE,"bitcoinrpc","importprivkey","wif",params[0],"account",params[1],"rescan",params[2]));
}

static char *dumpwallet(RPCARGS)
{
    return(sglue(0,CALLGLUE,"bitcoinrpc","dumpwallet"));
}

static char *importwallet(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","importwallet","wallet",params[0]));
}

static char *walletpassphrase(RPCARGS)
{
    /*cJSON *a,*b,*c;
    a = jduplicate(params[0]);
    b = jduplicate(params[2]);
    c = jduplicate(params[1]);
    sglue3(0,CALLGLUE,"bitcoinrpc","walletpassphrase","password",a,"permanentfile",b,"timeout",c);
    */
    return(sglue3(0,CALLGLUE,"bitcoinrpc","walletpassphrase","password",params[0],"permanentfile",params[2],"timeout",params[1]));
}

static char *walletpassphrasechange(RPCARGS)
{
return(sglue4(0,CALLGLUE,"bitcoinrpc","walletpassphrasechange","oldpassphrase",params[0],"newpassphrase",params[1],"oldpermanentfile",params[2],"oldpermanentfile",params[3]));
}

static char *walletlock(RPCARGS)
{
    return(sglue(0,CALLGLUE,"bitcoinrpc","walletlock"));
}

static char *encryptwallet(RPCARGS)
{
    return(sglue2(0,CALLGLUE,"bitcoinrpc","encryptwallet","passphrase",params[0],"password",params[1]));
}

static char *checkwallet(RPCARGS)
{
    return(sglue(0,CALLGLUE,"bitcoinrpc","checkwallet"));
}

static char *repairwallet(RPCARGS)
{
    return(sglue(0,CALLGLUE,"bitcoinrpc","repairwallet"));
}

static char *backupwallet(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","backupwallet","filename",params[0]));
}

// messages
static char *signmessage(RPCARGS)
{
    return(sglue2(0,CALLGLUE,"bitcoinrpc","signmessage","address",params[0],"message",params[1]));
}

static char *verifymessage(RPCARGS)
{
    return(sglue3(0,CALLGLUE,"bitcoinrpc","verifymessage","address",params[0],"sig",params[1],"message",params[2]));
}

// unspents
static char *listunspent(RPCARGS)
{
    return(sglue3(0,CALLGLUE,"bitcoinrpc","listunspent","minconf",params[0],"maxconf",params[1],"array",params[2]));
}

static char *lockunspent(RPCARGS)
{
    return(sglue2(0,CALLGLUE,"bitcoinrpc","lockunspent","flag",params[0],"array",params[1]));
}

static char *listlockunspent(RPCARGS)
{
    return(sglue(0,CALLGLUE,"bitcoinrpc","listlockunspent"));
}

static char *gettxout(RPCARGS)
{
    return(sglue3(0,CALLGLUE,"bitcoinrpc","gettxout","txid",params[0],"vout",params[1],"mempool",params[2]));
}

static char *gettxoutsetinfo(RPCARGS)
{
    return(sglue(0,CALLGLUE,"bitcoinrpc","gettxoutsetinfo"));
}

// payments
static char *sendtoaddress(RPCARGS)
{
    return(sglue4(0,CALLGLUE,"bitcoinrpc","sendtoaddress","address",params[0],"amount",params[1],"comment",params[2],"comment2",params[3]));
}

static char *movecmd(RPCARGS)
{
    return(sglue5(0,CALLGLUE,"bitcoinrpc","move","fromaccount",params[0],"toaccount",params[1],"amount",params[2],"minconf",params[3],"comment",params[4]));
}

static char *sendfrom(RPCARGS)
{
    return(sglue6(0,CALLGLUE,"bitcoinrpc","sendfrom","fromaccount",params[0],"toaddress",params[1],"amount",params[2],"minconf",params[3],"comment",params[4],"comment2",params[5]));
}

static char *sendmany(RPCARGS)
{
    return(sglue4(0,CALLGLUE,"bitcoinrpc","sendmany","fromaccount",params[0],"payments",params[1],"minconf",params[2],"comment",params[3]));
}

static char *settxfee(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","settxfee","amount",params[0]));
}

// rawtransaction
static char *getrawtransaction(RPCARGS)
{
    return(sglue2(0,CALLGLUE,"bitcoinrpc","getrawtransaction","txid",params[0],"verbose",params[1]));
}

static char *createrawtransaction(RPCARGS)
{
    return(sglue3(0,CALLGLUE,"bitcoinrpc","createrawtransaction","vins",params[0],"vouts",params[1],"locktime",params[2]));
}

static char *decoderawtransaction(RPCARGS)
{
    return(sglue2(0,CALLGLUE,"bitcoinrpc","decoderawtransaction","rawtx",params[0],"suppress",params[1]));
}

static char *validaterawtransaction(RPCARGS)
{
    return(sglue2(0,CALLGLUE,"bitcoinrpc","validaterawtransaction","rawtx",params[0],"suppress",params[1]));
}

static char *decodescript(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","decodescript","scriptstr",params[0]));
}

static char *signrawtransaction(RPCARGS)
{
    return(sglue4(0,CALLGLUE,"bitcoinrpc","signrawtransaction","rawtx",params[0],"vins",params[1],"privkeys",params[2],"sighash",params[3]));
}

static char *sendrawtransaction(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","sendrawtransaction","rawtx",params[0]));
}

static char *getrawchangeaddress(RPCARGS)
{
    return(sglue1(0,CALLGLUE,"bitcoinrpc","getrawchangeaddress","account",params[0]));
}

#define true 1
#define false 0
struct RPC_info { char *name; char *(*rpcfunc)(RPCARGS); int32_t flag0,remoteflag; } RPCcalls[] =
{
    { "validatepubkey",         &validatepubkey,         true,   true },
    { "makekeypair",            &makekeypair,            false,  false },
    { "listunspent",            &listunspent,            false,  false },
    { "getblockhash",           &getblockhash,           false,  true },
    { "walletpassphrase",       &walletpassphrase,       true,   false },
    { "SuperNET",               &SuperNET,               false,  true },
  //{ "SuperNETb",              &SuperNET,               false,  true },
    { "help",                   &help,                   true,   false },
    { "stop",                   &stop,                   true,   true },
    { "getbestblockhash",       &getbestblockhash,       true,   true },
    { "getblockcount",          &getblockcount,          true,   true },
    { "getdifficulty",          &getdifficulty,          true,   true },
    { "getconnectioncount",     &getconnectioncount,     true,   true },
    { "getpeerinfo",            &getpeerinfo,            true,   true },
    { "getinfo",                &getinfo,                true,   true },
    { "getnewaddress",          &getnewaddress,          true,   false },
    { "getnewpubkey",           &makekeypair,            true,   false },
    { "getaccountaddress",      &getaccountaddress,      true,   false },
    { "setaccount",             &setaccountrpc,             true,   false },
    { "getaccount",             &getaccount,             false,  false },
    { "getaddressesbyaccount",  &getaddressesbyaccount,  true,   false },
    { "sendtoaddress",          &sendtoaddress,          false,  false },
    { "getreceivedbyaddress",   &getreceivedbyaddress,   false,  false },
    { "getreceivedbyaccount",   &getreceivedbyaccount,   false,  false },
    { "listreceivedbyaddress",  &listreceivedbyaddress,  false,  false },
    { "listreceivedbyaccount",  &listreceivedbyaccount,  false,  false },
    { "backupwallet",           &backupwallet,           true,   false },
    { "walletpassphrasechange", &walletpassphrasechange, false,  false },
    { "walletlock",             &walletlock,             true,   false },
    { "encryptwallet",          &encryptwallet,          false,  false },
    { "validateaddress",        &validateaddress,        true,   true },
    { "getbalance",             &getbalance,             false,  false },
    { "move",                   &movecmd,                false,  false },
    { "sendfrom",               &sendfrom,               false,  false },
    { "sendmany",               &sendmany,               false,  false },
    { "addmultisig",            &addmultisigaddress,     false,  false },
    { "addmultisigaddress",     &addmultisigaddress,     false,  false },
    { "getblock",               &getblock,               false,  true },
    { "gettransaction",         &gettransaction,         false,  true },
    { "listtransactions",       &listtransactions,       false,  false },
    { "listaddressgroupings",   &listaddressgroupings,   false,  false },
    { "signmessage",            &signmessage,            false,  false },
    { "verifymessage",          &verifymessage,          false,  false },
    { "listaccounts",           &listaccounts,           false,  false },
    { "settxfee",               &settxfee,               false,  false },
    { "listsinceblock",         &listsinceblock,         false,  false },
    { "dumpprivkey",            &dumpprivkey,            false,  false },
    { "dumpwallet",             &dumpwallet,             true,   false },
    { "importwallet",           &importwallet,           false,  false },
    { "importprivkey",          &importprivkey,          false,  false },
    { "importaddress",          &importaddress,          false,  false },
    { "getrawtransaction",      &getrawtransaction,      false,  false },
    { "createrawtransaction",   &createrawtransaction,   false,  false },
    { "validaterawtransaction", &validaterawtransaction,   false,  true },
    { "decoderawtransaction",   &decoderawtransaction,   false,  true },
    { "decodescript",           &decodescript,           false,  true },
    { "signrawtransaction",     &signrawtransaction,     false,  false },
    { "sendrawtransaction",     &sendrawtransaction,     false,  true },
    { "checkwallet",            &checkwallet,            false,  false },
    { "repairwallet",           &repairwallet,           false,  false },
    { "sendalert",              &sendalert,              false,  false },
    //
    { "createmultisig",         &createmultisig,         false,  false },
    { "addnode",                &addnode,                false,  false },
    { "getrawmempool",          &getrawmempool,          false,  true },
    { "getrawchangeaddress",    &getrawchangeaddress,    false,  false },
    { "listlockunspent",        &listlockunspent,        false,  false },
    { "lockunspent",            &lockunspent,            false,  false },
    { "gettxout",               &gettxout,               false,  true },
    { "gettxoutsetinfo",        &gettxoutsetinfo,        false,  true },
    { "vanitygen",              &vanitygen,              false,  false }
#ifdef PEGGY
    //{ "peggytx",                &peggytx,                true,   false },
    //{ "peggypayments",          &peggypayments,          true,   false },
    //{ "getpeggyblock",          &getpeggyblock,          true,   false },
#endif
    //{ "resendtx",               &resendtx,               false,  true},
 // { "addredeemscript",        &addredeemscript,        false,  false },
    //  { "getrawmempool",          &getrawmempool,          true,   false },
    //    { "getdifficulty",          &getdifficulty,          true,   false },
    //    { "getsubsidy",             &getsubsidy,             true,   false },
    //    { "getmininginfo",          &getmininginfo,          true,   false },
    //    { "getstakinginfo",         &getstakinginfo,         true,   false },
    // { "getblockbynumber",       &getblockbynumber,       false,  false },
    //{ "getwork",                &getwork,                true,   false },
    //{ "getworkex",              &getworkex,              true,   false },
    // { "keypoolrefill",          &keypoolrefill,          true,   false },
    //{ "getblocktemplate",       &getblocktemplate,       true,   false },
    //{ "submitblock",            &submitblock,            false,  false },
    // { "getcheckpoint",          &getcheckpoint,          true,   false },
    // { "reservebalance",         &reservebalance,         false,  true},
};

int32_t is_bitcoinrpc(struct supernet_info *myinfo,char *method,char *remoteaddr)
{
    int32_t i;
    for (i=0; i<sizeof(RPCcalls)/sizeof(*RPCcalls); i++)
    {
        if ( strcmp(RPCcalls[i].name,method) == 0 )
        {
            if ( remoteaddr == 0 || remoteaddr[0] == 0 || strncmp(remoteaddr,"127.0.0.",strlen("127.0.0.")) == 0 )
            return(1);
            if ( RPCcalls[i].remoteflag != 0 && myinfo->publicRPC != 0 )
                return(i);
        }
    }
    return(-1);
}

char *iguana_bitcoinrpc(struct supernet_info *myinfo,uint16_t port,struct iguana_info *coin,char *method,cJSON *params[16],int32_t n,cJSON *json,char *remoteaddr,cJSON *array)
{
    int32_t i;
    for (i=0; i<sizeof(RPCcalls)/sizeof(*RPCcalls); i++)
    {
        if ( strcmp(RPCcalls[i].name,method) == 0 )
            return((*RPCcalls[i].rpcfunc)(myinfo,port,coin,params,n,json,remoteaddr,array,jstr(json,"userpass")));
    }
    return(clonestr("{\"error\":\"invalid coin address\"}"));
}
struct iguana_info *iguana_coinchoose(struct supernet_info *myinfo,char *symbol,cJSON *json,uint16_t port)
{
    int32_t i,c; struct iguana_info *tmp,*coin = 0;
    if ( port == myinfo->rpcport )
    {
        if ( jstr(json,"coin") == 0 )
        {
            strcpy(symbol,myinfo->rpcsymbol);
            if ( symbol[0] == 0 )
            {
                c = 'B';
                sprintf(symbol,"%c%c%c%c",c,'T',c+1,c+2);
            }
        }
        else
        {
            safecopy(symbol,jstr(json,"coin"),sizeof(symbol));
            for (i=0; symbol[i]!=0; i++)
                symbol[i] = toupper((int32_t)symbol[i]);
        }
    }
    else
    {
        //portable_mutex_lock(&myinfo->allcoins_mutex);
        HASH_ITER(hh,myinfo->allcoins,coin,tmp)
        {
            if ( coin->chain->rpcport == port )
                break;
            else coin = 0;
        }
        //portable_mutex_unlock(&myinfo->allcoins_mutex);
    }
    if ( coin == 0 && symbol[0] != 0 )
        coin = iguana_coinfind(symbol);
    return(coin);
}

char *iguana_bitcoinRPC(struct supernet_info *myinfo,char *method,cJSON *json,char *remoteaddr,uint16_t port)
{
    cJSON *params[16],*array; struct iguana_info *coin = 0; char symbol[16],*userpass; uint32_t immed; int32_t i,n; char *retstr = 0;
    symbol[0] = 0;
    memset(params,0,sizeof(params));
//printf("bitcoinRPC.(%s)\n",jprint(json,0));
    if ( json != 0 )
    {
        userpass = jstr(json,"userpass");
        coin = iguana_coinchoose(myinfo,symbol,json,port);
        if ( myinfo->rpcsymbol[0] == 0 )
            strcpy(myinfo->rpcsymbol,symbol);
        if ( coin != 0 )
            safecopy(symbol,coin->symbol,sizeof(symbol));
        //printf("method.(%s) (%s) remote.(%s) symbol.(%s)\n",method,jprint(json,0),remoteaddr,symbol);
        if ( method != 0 && symbol[0] != 0 && (coin != 0 || (coin= iguana_coinfind(symbol)) != 0) )
        {
            if ( (immed= juint(json,"immediate")) != 0 )
            {
                if ( iguana_immediate(coin,immed) == 0 )
                    return(clonestr("{\"error\":\"coin is busy processing\"}"));
            }
            if ( (array= jarray(&n,json,"params")) == 0 )
            {
                i = 0, n = 0;
            }
            else if ( n > 0 )
            {
                //printf("n.%d (%s)\n",n,jstr(array,0));
                for (i=n-1; i>=0; i--)
                {
                    params[i] = cJSON_DetachItemFromArray(array,i);//;
                    //printf("add params[%d] of %d <- (%s) %p.(%p %p)\n",i,n,jprint(params[i],0),params[i],params[i]->next,params[i]->prev);
                }
            }
            retstr = iguana_bitcoinrpc(myinfo,myinfo->rpcport,coin,method,params,n,json,remoteaddr,array);
            if ( n > 0 )
                for (i=0; i<n; i++)
                    if ( params[i] != 0 )
                        free_json(params[i]);
        }
    }
    if ( retstr == 0 )
        retstr = clonestr("{\"error\":\"null return from iguana_bitcoinRPC\"}");
    return(retstr);
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
            if ( strcmp(key,"Content-Length") == 0 && (datalen= atoi(value)) > 0 )
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

char *SuperNET_rpcparse(struct supernet_info *myinfo,char *retbuf,int32_t bufsize,int32_t *jsonflagp,int32_t *postflagp,char *urlstr,char *remoteaddr,char *filetype,uint16_t port)
{
    cJSON *tokens,*argjson,*origargjson,*tmpjson=0,*json = 0; long filesize; struct iguana_info *coin = 0;
    char symbol[64],buf[4096],*originstr,*fieldstr,*userpass=0,urlmethod[16],*data,url[8192],furl[8192],*retstr,*filestr,*token = 0; int32_t i,j,n,iter,num=0;
//printf("rpcparse.(%s)\n",urlstr);
    if ( myinfo->remoteorigin == 0 )
    {
        for (iter=0; iter<2; iter++)
        {
            fieldstr = (iter == 0) ? "Origin: " : "Referer: ";
            n = (int32_t)(strlen(urlstr) - strlen(fieldstr));
            for (i=0; i<n; i++)
                if ( strncmp(fieldstr,&urlstr[i],strlen(fieldstr)) == 0 )
                {
                    originstr = &urlstr[i + strlen(fieldstr)];
                    if ( strncmp(originstr,"http://127.0.0.",strlen("http://127.0.0.")) == 0 )
                        originstr = "http://127.0.0.1:";
                    else if ( strncmp(originstr,"agama://",strlen("agama://")) == 0 )
                        originstr = "http://127.0.0.1:";
                    else if ( strncmp(originstr,"file://127.0.0.",strlen("file://127.0.0.")) == 0 )
                        originstr = "http://127.0.0.1:";
                    else if ( strncmp(originstr,"chrome-extension://",strlen("chrome-extension://")) == 0 )
                        originstr = "http://127.0.0.1:";
                    else if ( strncmp("null",originstr,strlen("null")) != 0 && strncmp("http://localhost:",originstr,strlen("http://localhost:")) != 0 && strncmp("http://127.0.0.1:",originstr,strlen("http://127.0.0.1:")) != 0 && strncmp("http://easydex.supernet.org",originstr,strlen("http://easydex.supernet.org")) != 0 )
                    {
                        printf("remote %s REJECT.(%s)\n",fieldstr,urlstr);
                        return(clonestr("{\"error\":\"remote origin not enabled\"}"));
                    } //else printf("allow file://\n");
                    break;
                }
        }
    }
    for (i=0; i<sizeof(urlmethod)-1&&urlstr[i]!=0&&urlstr[i]!=' '; i++)
        urlmethod[i] = urlstr[i];
    urlmethod[i++] = 0;
    n = i;
    //printf("URLMETHOD.(%s)\n",urlmethod);
    *postflagp = (strcmp(urlmethod,"POST") == 0);
    for (i=0; i<sizeof(url)-1&&urlstr[n+i]!=0&&urlstr[n+i]!=' '; i++)
        url[i] = urlstr[n+i];
    url[i++] = 0;
    n += i;
    j = i = 0;
    filetype[0] = 0;
    //printf("url.(%s) method.(%s)\n",&url[i],urlmethod);
#ifdef __PNACL__
    snprintf(furl,sizeof(furl),"%s/%s",GLOBAL_DBDIR,url+1);
#else
    snprintf(furl,sizeof(furl),"%s",url+1);
#endif
    if ( strcmp(&url[i],"/") == 0 && strcmp(urlmethod,"GET") == 0 )
    {
        static int counter;
        *jsonflagp = 1;
        if ( counter++ == 0 || (filestr= OS_filestr(&filesize,"index7778.html")) == 0 )
        {
            printf("call htmlstr\n");
            if ( (filestr= SuperNET_htmlstr("index7778.html",retbuf,bufsize,0)) != 0 )
                printf("created index7778.html size %d\n",(int32_t)strlen(filestr));
            else printf("got null filestr\n");
        }
        if ( filestr != 0 )
            return(filestr);
        else return(clonestr("{\"error\":\"cant find index7778\"}"));
    }
    else if ( (filestr= OS_filestr(&filesize,furl)) != 0 )
    {
        *jsonflagp = 1;
        for (i=(int32_t)strlen(url)-1; i>0; i--)
            if ( url[i] == '.' || url[i] == '/' )
                break;
        if ( url[i] == '.' )
            strcpy(filetype,url+i+1);
        //printf("return filetype.(%s) size.%ld\n",filetype,filesize);
        return(filestr);
    }
    if ( strncmp(&url[i],"/api",strlen("/api")) == 0 )
    {
        *jsonflagp = 1;
        i += strlen("/api");
    } else *jsonflagp = 0;
    if ( strncmp(&url[i],"/bitmap",strlen("/bitmap")) == 0 )
    {
        i += strlen("/bitmap");
        *jsonflagp = 2;
        if ( url[i] == '/' )
            i++;
        iguana_bitmap(retbuf,bufsize,&url[i]);
        return(retbuf);
    }
    //printf("URL.(%s)\n",url);
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
        if ( (data= jstr(json,"POST")) == 0 || (argjson= cJSON_Parse(data)) == 0 )
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
        }
        if ( is_cJSON_Array(argjson) != 0 && (n= cJSON_GetArraySize(argjson)) > 0 )
        {
            cJSON *retitem,*retarray = cJSON_CreateArray();
            origargjson = argjson;
            symbol[0] = 0;
            for (i=0; i<n; i++)
            {
                argjson = jitem(origargjson,i);
                if ( userpass != 0 && jstr(argjson,"userpass") == 0 )
                    jaddstr(argjson,"userpass",userpass);
//printf("after urlconv.(%s) argjson.(%s)\n",jprint(json,0),jprint(argjson,0));
                coin = iguana_coinchoose(myinfo,symbol,argjson,port);
                if ( (retstr= SuperNET_JSON(myinfo,coin,argjson,remoteaddr,port)) != 0 )
                {
                    if ( (retitem= cJSON_Parse(retstr)) != 0 )
                        jaddi(retarray,retitem);
                    free(retstr);
                }
                //printf("(%s) {%s} -> (%s) postflag.%d (%s)\n",urlstr,jprint(argjson,0),cJSON_Print(json),*postflagp,retstr);
            }
            free_json(origargjson);
            retstr = jprint(retarray,1);
        }
        else
        {
            cJSON *arg;
            if ( jstr(argjson,"agent") != 0 && strcmp(jstr(argjson,"agent"),"bitcoinrpc") != 0 && jobj(argjson,"params") != 0 )
            {
                arg = jobj(argjson,"params");
                if ( is_cJSON_Array(arg) != 0 && cJSON_GetArraySize(arg) == 1 )
                    arg = jitem(arg,0);
            } else arg = argjson;
            //printf("ARGJSON.(%s)\n",jprint(arg,0));
            coin = iguana_coinchoose(myinfo,symbol,arg,port);
            if ( userpass != 0 && jstr(arg,"userpass") == 0 )
                jaddstr(arg,"userpass",userpass);
            retstr = SuperNET_JSON(myinfo,coin,arg,remoteaddr,port);
        }
        free_json(argjson);
        free_json(json);
        if ( tmpjson != 0 )
            free(tmpjson);
        return(retstr);
    }
    free_json(argjson);
    if ( tmpjson != 0 )
        free(tmpjson);
    *jsonflagp = 1;
    return(clonestr("{\"error\":\"couldnt process packet\"}"));
}

int32_t iguana_getcontentlen(char *buf,int32_t recvlen)
{
    char *str,*clenstr = "Content-Length: "; int32_t len = -1;
    if ( (str= strstr(buf,clenstr)) != 0 )
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

void iguana_rpcloop(void *args)
{
    static char *jsonbuf;
    uint16_t port; struct supernet_info *myinfo = args; char filetype[128],content_type[128];
    int32_t recvlen,flag,bindsock,postflag=0,contentlen,sock,remains,numsent,jsonflag=0,hdrsize,len;
    socklen_t clilen; char helpname[512],remoteaddr[64],*buf,*retstr,*space;//,*retbuf; ,n,i,m
    struct sockaddr_in cli_addr; uint32_t ipbits,i,size = IGUANA_WIDTH*IGUANA_HEIGHT*16 + 512;
    if ( (port= myinfo->argport) == 0 )
        port = myinfo->rpcport;
    else myinfo->argport = 0;
    if ( jsonbuf == 0 )
        jsonbuf = calloc(1,IGUANA_MAXPACKETSIZE);
    while ( (bindsock= iguana_socket(1,"127.0.0.1",port)) < 0 )
    {
        //if ( coin->MAXPEERS == 1 )
        //    break;
        //exit(-1);
        sleep(3);
    }
    printf(">>>>>>>>>> iguana_rpcloop 127.0.0.1:%d bind sock.%d iguana API enabled <<<<<<<<<\n",port,bindsock);
    fflush(stdout);
    space = calloc(1,size);
    while ( bindsock >= 0 )
    {
        clilen = sizeof(cli_addr);
        //printf("ACCEPT (%s:%d) on sock.%d\n","127.0.0.1",port,bindsock);
        sock = accept(bindsock,(struct sockaddr *)&cli_addr,&clilen);
        if ( sock < 0 )
        {
            //printf("iguana_rpcloop ERROR on accept usock.%d errno %d %s\n",sock,errno,strerror(errno));
            continue;
        }
        memcpy(&ipbits,&cli_addr.sin_addr.s_addr,sizeof(ipbits));
        expand_ipbits(remoteaddr,ipbits);
        if ( strcmp(WHITELIST_IPADDR,remoteaddr) == 0 || strncmp(remoteaddr,"127.0.0.",strlen("127.0.0.")) == 0 )
            strcpy(remoteaddr,"127.0.0.1");
        else printf("remote RPC request from (%s) %x\n",remoteaddr,ipbits);

        memset(jsonbuf,0,IGUANA_MAXPACKETSIZE);
        remains = (int32_t)(IGUANA_MAXPACKETSIZE - 1);
        buf = jsonbuf;
        recvlen = flag = 0;
        retstr = 0;
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
                break;
            }
            else
            {
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
                //printf("got.(%s) %d remains.%d of total.%d\n",jsonbuf,recvlen,remains,len);
                //retstr = iguana_rpcparse(space,size,&postflag,jsonbuf);
                    if ( flag == 0 )
                        break;
                }
            }
        }
        content_type[0] = 0;
        if ( recvlen > 0 )
        {
            retstr = SuperNET_rpcparse(myinfo,space,size,&jsonflag,&postflag,jsonbuf,remoteaddr,filetype,port);
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
            //printf("RETURN.(%s)\n",retstr);
            if ( jsonflag != 0 || postflag != 0 )
            {
                response = malloc(strlen(retstr)+1024+1+1);
                sprintf(hdrs,"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Methods: GET, POST\r\nCache-Control :  no-cache, no-store, must-revalidate\r\n%sContent-Length : %8d\r\n\r\n",content_type,(int32_t)strlen(retstr));
                response[0] = '\0';
                strcat(response,hdrs);
                strcat(response,retstr);
                strcat(response,"\n");
                if ( retstr != space )
                    free(retstr);
                retstr = response;
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
                        printf("iguana sent.%d remains.%d of len.%d\n",numsent,remains,recvlen);
                }
            }
            if ( retstr != space)
                free(retstr);
        }
        closesocket(sock);
    }
}
