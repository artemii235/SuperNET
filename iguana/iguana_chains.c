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

#include "iguana777.h"
#define PUBKEY_ADDRESS_BTC 0
#define SCRIPT_ADDRESS_BTC 5
#define PRIVKEY_ADDRESS_BTC 128
#define PUBKEY_ADDRESS_BTCD 60
#define SCRIPT_ADDRESS_BTCD 85
#define PRIVKEY_ADDRESS_BTCD 188
#define PUBKEY_ADDRESS_TEST 111
#define SCRIPT_ADDRESS_TEST 196
#define PRIVKEY_ADDRESS_TEST 239

static struct iguana_chain Chains[] =
{
	/*//[CHAIN_TESTNET3] =
    {
		//CHAIN_TESTNET3,
        "testnet3", "tBTC", "Bitcoin Signed Message:\n", // strMessageMagic
		PUBKEY_ADDRESS_TEST, SCRIPT_ADDRESS_TEST, PRIVKEY_ADDRESS_TEST,
		"\x0b\x11\x09\x07",
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
        18333,18334,0,
    },*/
    // curl --data '{"jsonrpc": "2.0", "method": "get_order_book", "params": [], "id": 1}' http://127.0.0.1:8090/rpc
    //[CHAIN_BITCOIN] =
    {
		//CHAIN_BITCOIN,
        "Bitcoin", "BTC", "Bitcoin Signed Message:\n", // strMessageMagic
		0, 5, 0x80,
		"\xf9\xbe\xb4\xd9",
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
        8333,8332,0,0x1d,
        { { 210000, (50 * SATOSHIDEN) }, { 420000, (50 * SATOSHIDEN) / 2 }, { 630000, (50 * SATOSHIDEN) / 4 },{ 840000, (50 * SATOSHIDEN) / 8 },
        }
	},
	//[CHAIN_BTCD] =
    {
		//CHAIN_BTCD,
        "BitcoinDark", "BTCD", "BitcoinDark Signed Message:\n", // strMessageMagic
		PUBKEY_ADDRESS_BTCD, SCRIPT_ADDRESS_BTCD, PRIVKEY_ADDRESS_BTCD,
		"\xe4\xc2\xd8\xe6",
        "0000044966f40703b516c5af180582d53f783bfd319bb045e2dc3e05ea695d46",
        "0100000000000000000000000000000000000000000000000000000000000000000000002b5b9d8cdd624d25ce670a7aa34726858388da010d4ca9ec8fd86369cc5117fd0132a253ffff0f1ec58c7f0000",
        //       "0100000000000000000000000000000000000000000000000000000000000000000000002b5b9d8cdd624d25ce670a7aa34726858388da010d4ca9ec8fd86369cc5117fd0132a253ffff0f1ec58c7f0001010000000132a253010000000000000000000000000000000000000000000000000000000000000000ffffffff4100012a3d3138204a756e652032303134202d204269746f696e20796f75722077617920746f206120646f75626c6520657370726573736f202d20636e6e2e636f6dffffffff010000000000000000000000000000",
        14631,14632,1,0x1e,
        { { 12000, (80 * SATOSHIDEN) }, }
    },
    //curl --url "http://127.0.0.1:7778" --data "{\"RELAY\":1,\"VALIDATE\":1,\"prefetchlag\":-1,\"poll\":10,\"active\":1,\"agent\":\"iguana\",\"method\":\"addcoin\",\"startpend\":8,\"endpend\":8,\"services\":129,\"maxpeers\":256,\"newcoin\":\"VPN\",\"name\":\"VPNcoin\",\"hasheaders\":1,\"useaddmultisig\":0,\"txhastimestamp\":1,\"minoutput\":10000,\"minconfirms\":2,\"txfee_satoshis\":\"10000\",\"genesishash\":\"00000ac7d764e7119da60d3c832b1d4458da9bc9ef9d5dd0d91a15f690a46d99\",\"genesis\":{\"version\":1,\"timestamp\":1409839200,\"nBits\":\"1e0fffff\",\"nonce\":64881664,\"merkle_root\":\"698a93a1cacd495a7a4fb3864ad8d06ed4421dedbc57f9aaad733ea53b1b5828\"},\"protover\":70002,\"netmagic\":\"fbc0b6db\",\"p2p\":1920,\"rpc\":1921,\"pubval\":71,\"p2shval\":5,\"wifval\":199}"
    
    //iguana_chaingenesis("VPN",0,bits256_conv("00000ac7d764e7119da60d3c832b1d4458da9bc9ef9d5dd0d91a15f690a46d99"),genesisblock,"scrypt",1,1409839200,0x1e0fffff,64881664,bits256_conv("698a93a1cacd495a7a4fb3864ad8d06ed4421dedbc57f9aaad733ea53b1b5828")); // VPN

	/*//[CHAIN_VPN] =
    {
        "VPNcoin", "VPN", "VPNcoin Signed Message:\n", // strMessageMagic
		71, 5, 199, // PUBKEY_ADDRESS + SCRIPT_ADDRESS addrman.h, use wif2priv API on any valid wif
		"\xfb\xc0\xb6\xdb", // pchMessageStart main.cpp
        //"aaea16b9b820180153d9cd069dbfd54764f07cb49c71987163132a72d568cb14",
        "00000ac7d764e7119da60d3c832b1d4458da9bc9ef9d5dd0d91a15f690a46d99", // hashGenesisBlock main.h
        "01000000000000000000000000000000000000000000000000000000000000000000000028581b3ba53e73adaaf957bced1d42d46ed0d84a86b34f7a5a49cdcaa1938a6940540854ffff0f1e78b20100010100000040540854010000000000000000000000000000000000000000000000000000000000000000ffffffff2404ffff001d01041c5468752c20342053657020323031342031323a30303a303020474d54ffffffff01000000000000000000000000000000",
        1920,1921,1,0x1e // port and rpcport vpncoin.conf
    },
	
    //[CHAIN_LTC] =
    {
        "Litecoin", "LTC", "Litecoin Signed Message:\n",
		0, 5, 176, // PUBKEY_ADDRESS + SCRIPT_ADDRESS addrman.h, use wif2priv API on any valid wif
		"\xfb\xc0\xb6\xdb", // pchMessageStart main.cpp
        //"12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2",
        "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2",
        //010000000000000000000000000000000000000000000000000000000000000000000000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97b9aa8e4ef0ff0f1ecd513f7c
     "010000000000000000000000000000000000000000000000000000000000000000000000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97b9aa8e4ef0ff0f1ecd513f7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4804ffff001d0104404e592054696d65732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997320566973696f6e6172792c2044696573206174203536ffffffff0100f2052a010000004341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac00000000",
        9333,9334,0,0x1e // port and rpcport litecoin.conf
    },*/
};

/*
// PUBKEY_ADDRESS + SCRIPT_ADDRESS addrman.h
// PRIVKEY_ADDRESS use wif2priv API on any valid wif
// networkmagic pchMessageStart main.cpp
// genesis block from any blockexplorer, calendar strings can be converted by utime2utc
{
    "name":"BitcoinDark","symbol":"BTCD",
    "PUBKEY_ADDRESS":60,"SCRIPT_ADDRESS":85,"PRIVKEY_ADDRESS":188,
    "networkmagic":"e4c2d8e6","portp2p:14631,"portrpc":14632,"txhastimestamp":1,
    "genesis":{"version":1,"timestamp":1403138561,"nBits":"1e0fffff","nonce":8359109,"hash":"0000044966f40703b516c5af180582d53f783bfd319bb045e2dc3e05ea695d46","merkle":"fd1751cc6963d88feca94c0d01da8883852647a37a0a67ce254d62dd8c9d5b2b"}
}*/


int32_t blockhash_sha256(uint8_t *blockhashp,uint8_t *serialized,int32_t len)
{
    bits256 hash;
    vcalc_sha256(0,hash.bytes,serialized,len);
    vcalc_sha256(0,blockhashp,hash.bytes,sizeof(hash));
    return(sizeof(bits256));
}

int32_t blockhash_scrypt(uint8_t *blockhashp,uint8_t *serialized,int32_t len)
{
    if ( len == 80 )
    {
        calc_scrypthash((uint32_t *)blockhashp,serialized);
        //*(bits256 *)blockhashp = scrypt_blockhash(serialized);
        //int32_t i; for (i=0; i<32; i++)
        //    printf("%02x",blockhashp[i]);
        //printf(" scrypt\n");
    } else memset(blockhashp,0,sizeof(*blockhashp));
    return(sizeof(bits256));
}

blockhashfunc iguana_hashalgo(char *hashalgostr)
{
return(blockhash_sha256); // all coins seem to use this for genesis
    /*if ( hashalgostr == 0 || hashalgostr[0] == 0 || strcmp(hashalgostr,"sha256") == 0 )
        return(blockhash_sha256);
    else if ( strcmp(hashalgostr,"scrypt") == 0 )
        return(blockhash_scrypt);
    else printf("unsupported blockhash algo.(%s)\n",hashalgostr);
    return(0);*/
}

bits256 iguana_calcblockhash(char *symbol,int32_t (*hashalgo)(uint8_t *blockhashp,uint8_t *serialized,int32_t len),uint8_t *serialized,int32_t len)
{
    bits256 tmp,hash2; int32_t i;
    memset(&hash2,0,sizeof(hash2));
    if ( (*hashalgo)(tmp.bytes,serialized,len) != sizeof(bits256) )
        memset(tmp.bytes,0,sizeof(hash2));
    else if ( hashalgo == blockhash_sha256 )
    {
        for (i=0; i<32; i++)
            hash2.bytes[i] = tmp.bytes[31 - i];
    } else return(tmp);
    /*if ( hashalgo == blockhash_scrypt )
    {
        char str[65]; bits256 checkhash2; struct iguana_msgblock msg; struct iguana_block *block; struct iguana_info *coin;
        if ( (coin= iguana_coinfind(symbol)) != 0 )
        {
            iguana_rwblock(symbol,hashalgo,0,&checkhash2,serialized,&msg);
            if ( (block= iguana_blockfind("hashalgo",coin,msg.H.prev_block)) != 0 )
            {
                hash2 = iguana_blockhash(coin,block->height+1);
                printf("sethash2.(%s)\n",bits256_str(str,hash2));
            }
        }
    }*/
    return(hash2);
}

bits256 iguana_chaingenesis(struct supernet_info *myinfo,char *symbol,uint8_t zcash,uint8_t auxpow,int32_t (*hashalgo)(uint8_t *blockhashp,uint8_t *serialized,int32_t len),bits256 genesishash,char *genesisblock,char *hashalgostr,int32_t version,uint32_t timestamp,uint32_t nBits,uint32_t nonce,bits256 merkle_root)
{
    struct iguana_msgzblock zmsg; struct iguana_msgblock *msg = (void *)&zmsg; int32_t len; bits256 hash2; char blockhashstr[256]; uint8_t serialized[8192];
    memset(&zmsg,0,sizeof(zmsg));
    msg->H.version = version;
    msg->H.merkle_root = merkle_root;
    msg->H.timestamp = timestamp;
    msg->H.bits = nBits;
    msg->H.nonce = nonce;
    if ( zcash != 0 )
        printf("need to handle zcash genesis\n");
    if ( hashalgostr != 0 && strcmp(hashalgostr,"sha256") != 0 )
        hashalgo = iguana_hashalgo(hashalgostr);
    else hashalgo = blockhash_sha256;
    len = iguana_rwblock(myinfo,symbol,zcash,auxpow,hashalgo,1,&hash2,serialized,&zmsg,sizeof(1024));
    blockhashstr[0] = 0;
    init_hexbytes_noT(blockhashstr,hash2.bytes,sizeof(hash2));
    char str[65],str2[65];
    if ( bits256_cmp(genesishash,hash2) != 0 )
        printf("WARNING: genesishash.(%s) mismatch vs calc.(%s)\n",bits256_str(str,genesishash),bits256_str(str2,hash2));
    init_hexbytes_noT(genesisblock,serialized,len);
    //printf("v.%d t.%u %s nBits.%08x nonce.%u merkle.(%s) genesis.(%s) hash2.(%s) blockhash.(%s) size.%d\n",version,timestamp,utc_str(str3,timestamp),nBits,nonce,bits256_str(str2,merkle_root),genesisblock,bits256_str(str,hash2),blockhashstr,(int32_t)strlen(genesisblock)/2);
    return(hash2);
}

char *parse_conf_line(char *line,char *field)
{
    line += strlen(field);
    while ( (*line) != '=' && (*line) != 0 )
        line++;
    if ( *line == 0 )
        return(0);
    if ( *line == '=' )
        line++;
    _stripwhite(line,0);
    if ( Debuglevel > 0 )
        printf("[%s]\n",line);
    return(clonestr(line));
}

char *default_coindir(char *confname,char *coinstr)
{
    int32_t i;
#ifdef __APPLE__
    char *coindirs[][3] = { {"BTC","Bitcoin","bitcoin"}, {"BTCD","BitcoinDark"}, {"LTC","Litecoin","litecoin"}, {"VRC","Vericoin","vericoin"}, {"OPAL","OpalCoin","opalcoin"}, {"BITS","Bitstar","bitstar"}, {"DOGE","Dogecoin","dogecoin"}, {"DASH","Dash","dash"}, {"BC","Blackcoin","blackcoin"}, {"FIBRE","Fibre","fibre"}, {"VPN","Vpncoin","vpncoin"} };
#else
    char *coindirs[][3] = { {"BTC",".bitcoin"}, {"BTCD",".BitcoinDark"}, {"LTC",".litecoin"}, {"VRC",".vericoin"}, {"OPAL",".opalcoin"}, {"BITS",".Bitstar"}, {"DOGE",".dogecoin"}, {"DASH",".dash"}, {"BC",".blackcoin"}, {"FIBRE",".Fibre"}, {"VPN",".vpncoin"} };
#endif
    for (i=0; i<(int32_t)(sizeof(coindirs)/sizeof(*coindirs)); i++)
        if ( strcmp(coindirs[i][0],coinstr) == 0 )
        {
            if ( coindirs[i][2] != 0 )
                strcpy(confname,coindirs[i][2]);
            else strcpy(confname,coindirs[i][1] + (coindirs[i][1][0] == '.'));
            return(coindirs[i][1]);
        }
    return(coinstr);
}

void set_coinconfname(char *fname,char *coinstr,char *userhome,char *coindir,char *confname)
{
    char buf[64];
    if ( coindir == 0 || coindir[0] == 0 || confname == 0 || confname[0] == 0 )
        coindir = default_coindir(buf,coinstr);
    else buf[0] = 0;
    if ( confname == 0 || confname[0] == 0 )
    {
        confname = buf;
        sprintf(confname,"%s.conf",buf);
    }
    printf("userhome.(%s) coindir.(%s) confname.(%s)\n",userhome,coindir,confname);
#ifdef WIN32
    if ( userhome == 0 || userhome[0] == 0 )
        sprintf(fname,"%s/%s",coindir,confname);
    else
#endif
        sprintf(fname,"%s/%s/%s",userhome,coindir,confname);
}

uint16_t extract_userpass(char *serverport,char *userpass,char *coinstr,char *userhome,char *coindir,char *confname)
{
    FILE *fp; uint16_t port = 0;
    char fname[2048],line[1024],*rpcuser,*rpcpassword,*rpcport,*str;
    if ( strcmp(coinstr,"NXT") == 0 || coindir == 0 || confname == 0 || coindir[0] == 0 || confname[0] == 0 )
        return(0);
    serverport[0] = userpass[0] = 0;
    set_coinconfname(fname,coinstr,userhome,coindir,confname);
    printf("set_coinconfname.(%s) <- (%s)\n",fname,confname);
    if ( (fp= fopen(OS_compatible_path(fname),"r")) != 0 )
    {
        if ( Debuglevel > 1 )
            printf("extract_userpass from (%s)\n",fname);
        rpcuser = rpcpassword = rpcport = 0;
        while ( fgets(line,sizeof(line),fp) != 0 )
        {
            if ( line[0] == '#' )
                continue;
            //printf("line.(%s) %p %p\n",line,strstr(line,"rpcuser"),strstr(line,"rpcpassword"));
            if ( (str= strstr(line,"rpcuser")) != 0 )
                rpcuser = parse_conf_line(str,"rpcuser");
            else if ( (str= strstr(line,"rpcpassword")) != 0 )
                rpcpassword = parse_conf_line(str,"rpcpassword");
            else if ( (str= strstr(line,"rpcport")) != 0 )
                rpcport = parse_conf_line(str,"rpcport");
        }
        if ( rpcuser != 0 && rpcpassword != 0 )
        {
            if ( userpass[0] == 0 )
                sprintf(userpass,"%s:%s",rpcuser,rpcpassword);
        }
        if ( rpcport != 0 )
        {
            port = atoi(rpcport);
            if ( serverport[0] == 0 )
                sprintf(serverport,"127.0.0.1:%s",rpcport);
            free(rpcport);
        }
        if ( 0 && Debuglevel > 1 )
            printf("-> (%s):(%s) userpass.(%s) serverport.(%s)\n",rpcuser,rpcpassword,userpass,serverport);
        if ( rpcuser != 0 )
            free(rpcuser);
        if ( rpcpassword != 0 )
            free(rpcpassword);
        fclose(fp);
    } else printf("extract_userpass cant open.(%s)\n",fname);
    return(port);
}

void iguana_chainparms(struct supernet_info *myinfo,struct iguana_chain *chain,cJSON *argjson)
{
    extern char Userhome[];
    char *path,conf[512],*hexstr,genesisblock[1024]; uint16_t port; cJSON *rpair,*genesis,*rewards,*item; int32_t i,n,m; uint32_t nBits; uint8_t tmp[4];
    //printf("chainparams.(%s)\n",jprint(argjson,0));
    if ( strcmp(chain->symbol,"NXT") != 0 )
    {
        if ( strcmp(chain->symbol,"BTCD") == 0 )
            chain->pubtype = 60, chain->p2shtype = 85, chain->portp2p = 14631, chain->rpcport = 14632;
        else if ( strcmp(chain->symbol,"BTC") == 0 )
            chain->pubtype = 0, chain->p2shtype = 5, chain->portp2p = 8333, chain->rpcport = 8332;
        else chain->do_opreturn = juint(argjson,"do_opreturn");
        if ( (chain->minoutput= j64bits(argjson,"minoutput")) == 0 )
            chain->minoutput = 10000;
        chain->minconfirms = juint(argjson,"minconfirms");
        if ( (chain->estblocktime= juint(argjson,"estblocktime")) == 0 )
            chain->estblocktime = juint(argjson,"blocktime");
        if ( chain->estblocktime == 0 )
            chain->estblocktime = 60;
        path = jstr(argjson,"path");
        if ( jobj(argjson,"conf") == 0 )
            conf[0] = 0;
        else safecopy(conf,jstr(argjson,"conf"),sizeof(conf));
        safecopy(chain->name,jstr(argjson,"name"),sizeof(chain->name));
        //chain->dust = j64bits(argjson,"dust");
        if ( jobj(argjson,"txfee_satoshis") != 0 )
            chain->txfee = j64bits(argjson,"txfee_satoshis");
        if ( chain->txfee == 0 )
            chain->txfee = (uint64_t)(SATOSHIDEN * jdouble(argjson,"txfee"));
        chain->use_addmultisig = juint(argjson,"useaddmultisig");
        if ( (port= extract_userpass(chain->serverport,chain->userpass,chain->symbol,chain->userhome,path,conf)) != 0 )
            chain->rpcport = port;
        //if ( conf[0] != 0 )
            printf("PATH.(%s) CONF.(%s) txfee %.8f\n",path!=0?path:"",conf,dstr(chain->txfee));
        if ( juint(argjson,"p2p") != 0 )
            chain->portp2p = juint(argjson,"p2p");
        else chain->portp2p = juint(argjson,"portp2p");
        if ( jstr(argjson,"rpchost") != 0 )
            safecopy(chain->serverport,jstr(argjson,"rpchost"),sizeof(chain->serverport));
        if ( jstr(argjson,"userpass") != 0 )
            safecopy(chain->userpass,jstr(argjson,"userpass"),sizeof(chain->userpass));
        chain->rpcport = juint(argjson,"rpcport");
        if ( chain->rpcport == 0 && (chain->rpcport= juint(argjson,"rpc")) == 0 && strcmp(chain->symbol,"RELAY") != 0 )
        {
            if ( chain->portp2p != 0 )
                chain->rpcport = chain->portp2p-1;
        }
        if ( chain->portp2p == 0 )
        {
            if ( strcmp("BTC",chain->symbol) == 0 )
                chain->portp2p = 8333;
            else if ( strcmp("BTCD",chain->symbol) == 0 )
                chain->portp2p = 14631;
        }
        if ( chain->rpcport == 0 )
        {
            if ( strcmp("BTC",chain->symbol) == 0 )
                chain->rpcport = 8332;
            else if ( strcmp("BTCD",chain->symbol) == 0 )
                chain->rpcport = 14632;
        }
        chain->zcash = juint(argjson,"zcash");
        if ( chain->havecltv == 0 )
            chain->havecltv = juint(argjson,"havecltv") || chain->zcash;
        chain->debug = juint(argjson,"debug");
        chain->fixit = juint(argjson,"fixit");
        if ( (chain->normal_txversion= juint(argjson,"normal_txversion")) == 0 )
            chain->normal_txversion = IGUANA_NORMAL_TXVERSION;
        if ( (chain->locktime_txversion= juint(argjson,"locktime_txversion")) == 0 )
            chain->locktime_txversion = IGUANA_LOCKTIME_TXVERSION;
        if ( jobj(argjson,"isPoS") != 0 )
            chain->isPoS = juint(argjson,"isPoS");
        if ( jstr(argjson,"userhome") != 0 )
            strcpy(chain->userhome,jstr(argjson,"userhome"));
        else strcpy(chain->userhome,Userhome);
        if ( (chain->protover= juint(argjson,"protover")) == 0 )
            chain->protover = PROTOCOL_VERSION;
        chain->auxpow = juint(argjson,"auxpow");
        if ( (chain->targetspacing= jint(argjson,"targetspacing")) == 0 )
            chain->targetspacing = NTARGETSPACING;
        if ( (chain->targettimespan= jint(argjson,"targettimespan")) == 0 )
            chain->targettimespan = NTARGETSPACING * 60;
        if ( jobj(argjson,"halving") != 0 )
            chain->halvingduration = juint(argjson,"halving");
        else chain->halvingduration = 210000;
        if ( jobj(argjson,"reward") != 0 )
            chain->initialreward = jdouble(argjson,"reward") * SATOSHIDEN;
        else chain->initialreward = 50 * SATOSHIDEN;
        if ( chain->serverport[0] == 0 )
            sprintf(chain->serverport,"127.0.0.1:%u",chain->rpcport);
        if ( strcmp(chain->symbol,"BTC") != 0 && strcmp(chain->symbol,"BTCD") != 0 )
        {
            chain->pubtype = juint(argjson,"pubval");
            chain->p2shtype = juint(argjson,"p2shval");
            chain->wiftype = juint(argjson,"wifval");
            if ( chain->pubtype == 0 && chain->p2shtype == 0 && chain->wiftype == 0 )
            {
                if ( (hexstr= jstr(argjson,"pubval")) != 0 && strlen(hexstr) == 2 )
                    decode_hex((uint8_t *)&chain->pubtype,1,hexstr);
                if ( (hexstr= jstr(argjson,"scriptval")) != 0 && strlen(hexstr) == 2 )
                    decode_hex((uint8_t *)&chain->p2shtype,1,hexstr);
                else if ( (hexstr= jstr(argjson,"p2shval")) != 0 && strlen(hexstr) == 2 )
                    decode_hex((uint8_t *)&chain->p2shtype,1,hexstr);
                if ( (hexstr= jstr(argjson,"wifval")) != 0 && strlen(hexstr) == 2 )
                    decode_hex((uint8_t *)&chain->wiftype,1,hexstr);
            }
        }
        printf("MINCONFIRMS.%d addrtypes.(%02x %02x %02x) (%d %d %d)\n",chain->minconfirms,chain->pubtype,chain->p2shtype,chain->wiftype,chain->pubtype,chain->p2shtype,chain->wiftype);
        if ( (hexstr= jstr(argjson,"netmagic")) != 0 && strlen(hexstr) == 8 )
            decode_hex((uint8_t *)chain->netmagic,4,hexstr);
        if ( (hexstr= jstr(argjson,"unitval")) != 0 && strlen(hexstr) == 2 )
            decode_hex((uint8_t *)&chain->unitval,1,hexstr);
        if ( (hexstr= jstr(argjson,"alertpubkey")) != 0 && (strlen(hexstr)>>1) <= sizeof(chain->alertpubkey) )
            decode_hex((uint8_t *)chain->alertpubkey,(int32_t)strlen(hexstr)>>1,hexstr);
        if ( (hexstr= jstr(argjson,"genesishash")) != 0 )
        {
            chain->genesis_hash = mycalloc('G',1,strlen(hexstr)+1);
            strcpy(chain->genesis_hash,hexstr);
        }
        if ( (genesis= jobj(argjson,"genesis")) != 0 )
        {
            chain->hashalgo = iguana_hashalgo(jstr(genesis,"hashalgo"));
            decode_hex(chain->genesishash2.bytes,sizeof(chain->genesishash2),chain->genesis_hash);
            if ( jstr(genesis,"nBits") != 0 )
            {
                decode_hex((void *)&tmp,sizeof(tmp),jstr(genesis,"nBits"));
                ((uint8_t *)&nBits)[0] = tmp[3];
                ((uint8_t *)&nBits)[1] = tmp[2];
                ((uint8_t *)&nBits)[2] = tmp[1];
                ((uint8_t *)&nBits)[3] = tmp[0];
            } else nBits = 0x1e00ffff;
            chain->nBits = nBits;
            chain->unitval = (nBits >> 24);
            printf("NETMAGIC %08x unitval.%02x nBits.%08x\n",*(uint32_t *)chain->netmagic,chain->unitval,chain->nBits);
            chain->genesishash2 = iguana_chaingenesis(myinfo,chain->symbol,chain->zcash,chain->auxpow,chain->hashalgo,chain->genesishash2,genesisblock,jstr(genesis,"hashalgo"),juint(genesis,"version"),juint(genesis,"timestamp"),nBits,juint(genesis,"nonce"),jbits256(genesis,"merkle_root"));
            memcpy(chain->genesis_hashdata,chain->genesishash2.bytes,32);
            char str[65]; init_hexbytes_noT(str,chain->genesis_hashdata,32);
            chain->genesis_hash = clonestr(str);
            chain->genesis_hex = clonestr(genesisblock);
        }
        else
        {
            if ( jstr(argjson,"nBits") != 0 )
            {
                decode_hex((void *)&tmp,sizeof(tmp),jstr(argjson,"nBits"));
                ((uint8_t *)&nBits)[0] = tmp[3];
                ((uint8_t *)&nBits)[1] = tmp[2];
                ((uint8_t *)&nBits)[2] = tmp[1];
                ((uint8_t *)&nBits)[3] = tmp[0];
            } else nBits = 0x1e00ffff;
            chain->nBits = nBits;
            chain->unitval = (nBits >> 24);
            printf("NETMAGIC -> %08x unitval.%02x (%s) -> tmp.%08x nBits.%08x\n",*(uint32_t *)chain->netmagic,chain->unitval,jstr(argjson,"nBits"),*(uint32_t *)tmp,chain->nBits);
            if ( (hexstr= jstr(argjson,"genesisblock")) != 0 )
            {
                uint8_t hexbuf[1024],*ptr,*data; int32_t datalen,hdrsize;
                hdrsize = chain->zcash != 0 ? sizeof(struct iguana_msgzblockhdr) : sizeof(struct iguana_msgblockhdr);
                chain->genesis_hex = clonestr(hexstr);
                data = get_dataptr(BASILISK_HDROFFSET,&ptr,&datalen,hexbuf,sizeof(hexbuf),hexstr);
                chain->genesishash2 = iguana_calcblockhash(chain->symbol,chain->hashalgo,data,hdrsize);
                memcpy(chain->genesis_hashdata,chain->genesishash2.bytes,32);
                //char str[65]; printf("%s -> calculated %s from %d datalen\n",hexstr,bits256_str(str,chain->genesishash2),hdrsize);
                if ( ptr != 0 )
                    free(ptr);
            }
        }
        if ( (rewards= jarray(&n,argjson,"rewards")) != 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(rewards,i);
                if ( (rpair= jarray(&m,item,0)) != 0 && m == 0 )
                {
                    chain->rewards[i][0] = j64bits(jitem(rpair,0),0);
                    chain->rewards[i][1] = j64bits(jitem(rpair,1),0);
                }
            }
        }
        sprintf(chain->messagemagic,"%s Signed Message:\n",chain->name);
        printf("COIN.%s serverport.(%s) RPCport.%u P2P.%u magic.%08x txfee %.8f\n",chain->symbol,chain->serverport,chain->rpcport,chain->portp2p,*(uint32_t *)chain->netmagic,dstr(chain->txfee));
    }
}

void iguana_chaininit(struct supernet_info *myinfo,struct iguana_chain *chain,int32_t hasheaders,cJSON *argjson)
{
    int32_t i;
    if ( chain->hashalgo != 0 )
        return;
    if ( strcmp(chain->symbol,"BTCD") == 0 )
    {
        chain->numPoStargets = 1;
        chain->PoSheights[0] = 0;
        memset(&chain->PoStargets[0],0xff,sizeof(bits256));
        for (i=0; i<20; i++)
            chain->PoStargets[0] = bits256_rshift(chain->PoStargets[0]);
        chain->PoWtarget = bits256_from_compact(0x1e0fffff);
    }
    chain->hasheaders = hasheaders;
    chain->hashalgo = blockhash_sha256; // most all coins seem to use this for blockchain
    if ( strcmp(chain->symbol,"BTC") == 0 )
    {
        chain->unitval = 0x1d;
        chain->txfee = 50000;
        chain->havecltv = 1;
    }
    else chain->txfee = 10000;
    if ( chain->unitval == 0 )
        chain->unitval = 0x1e;
    if ( argjson != 0 )
        iguana_chainparms(myinfo,chain,argjson);
    if ( hasheaders != 0 )
    {
        strcpy(chain->gethdrsmsg,"getheaders");
        chain->bundlesize = _IGUANA_HDRSCOUNT;
    }
    else
    {
        strcpy(chain->gethdrsmsg,"getblocks");
        chain->bundlesize = _IGUANA_BLOCKHASHES;
    }
    if ( chain->zcash != 0 )
        chain->bundlesize = 160;
    if ( strcmp(chain->symbol,"BTC") == 0 )
        chain->bundlesize = 100;
    decode_hex((uint8_t *)chain->genesis_hashdata,32,(char *)chain->genesis_hash);
    if ( chain->rpcport == 0 && strcmp(chain->symbol,"RELAY") != 0 )
        chain->rpcport = chain->portp2p + 1;
}

struct iguana_chain *iguana_chainfind(struct supernet_info *myinfo,char *name,cJSON *argjson,int32_t createflag)
{
    struct iguana_chain *chain; uint32_t i;
    for (i=0; i<sizeof(Chains)/sizeof(*Chains); i++)
    {
		chain = &Chains[i];
        //printf("chain.(%s).%s vs %s.%d\n",chain->genesis_hash,chain->name,name,strcmp(name,chain->name));
		if ( chain->name[0] == 0 || chain->genesis_hash == 0 )
        {
            if ( createflag != 0 && argjson != 0 )
            {
                iguana_chaininit(myinfo,chain,strcmp(chain->symbol,"BTCD") != 0,argjson);
                return(chain);
            }
  			continue;
        }
		if ( strcmp(name,chain->symbol) == 0 )
        {
            iguana_chaininit(myinfo,chain,strcmp(chain->symbol,"BTCD") != 0,argjson);
            return(chain);
        }
	}
    chain = calloc(1,sizeof(*chain));
    strcpy(chain->name,name);
    strcpy(chain->symbol,name);
    iguana_chaininit(myinfo,chain,1,argjson);
    return(chain);
}

struct iguana_chain *iguana_findmagic(struct supernet_info *myinfo,uint8_t netmagic[4])
{
    struct iguana_chain *chain; uint8_t i;
	for (i=0; i<sizeof(Chains)/sizeof(*Chains); i++)
    {
		chain = &Chains[i];
		if ( chain->name[0] == 0 || chain->genesis_hash == 0 )
			continue;
		if ( memcmp(netmagic,chain->netmagic,4) == 0 )
			return(iguana_chainfind(myinfo,(char *)chain->symbol,0,0));
	}
	return NULL;
}

uint64_t iguana_miningreward(struct iguana_info *coin,uint32_t blocknum)
{
    int32_t i; uint64_t reward = 50LL * SATOSHIDEN;
    for (i=0; i<sizeof(coin->chain->rewards)/sizeof(*coin->chain->rewards); i++)
    {
        //printf("%d: %u %.8f\n",i,(int32_t)coin->chain->rewards[i][0],dstr(coin->chain->rewards[i][1]));
        if ( blocknum >= coin->chain->rewards[i][0] )
            reward = coin->chain->rewards[i][1];
        else break;
    }
    return(reward);
}

struct iguana_chain *iguana_createchain(struct supernet_info *myinfo,cJSON *json)
{
    char *symbol,*name; struct iguana_chain *chain = 0;
    if ( ((symbol= jstr(json,"newcoin")) != 0 || (symbol= jstr(json,"name")) != 0) && strlen(symbol) < 8 )
    {
        chain = mycalloc('C',1,sizeof(*chain));
        strcpy(chain->symbol,symbol);
        if ( (name= jstr(json,"description")) != 0 && strlen(name) < 32 )
            strcpy(chain->name,name);
        iguana_chaininit(myinfo,chain,juint(json,"hasheaders"),json);
    }
    return(chain);
}
