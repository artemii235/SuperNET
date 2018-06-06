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

/*
 resume handling: list of tx broadcast, tx pending + required items, reconnect state machine or have statemachine assume off by one or state/otherstate specific handling
make sure to broadcast deposit before claiming refund, or to just skip it if neither is done
*/

#define DEX_SLEEP 10
#define BASILISK_DEFAULT_NUMCONFIRMS 5

// Todo: monitor blockchains, ie complete extracting scriptsig
// mode to autocreate required outputs
// more better LP commands

// depends on just three external functions:
//     - basilisk_sendrawtransaction(myinfo,coin,signedtx);
//     - basilisk_value(myinfo,rawtx->coin,0,0,myinfo->myaddr.persistent,argjson,0)
//      basilisk_bitcoinrawtx(myinfo,rawtx->coin,"",basilisktag,jint(valsobj,"timeout"),valsobj,V)


// included from basilisk.c
/* https://bitcointalk.org/index.php?topic=1340621.msg13828271#msg13828271
 https://bitcointalk.org/index.php?topic=1364951
 Tier Nolan's approach is followed with the following changes:
 a) instead of cutting 1000 keypairs, only INSTANTDEX_DECKSIZE are a
 b) instead of sending the entire 256 bits, it is truncated to 64 bits. With odds of collision being so low, it is dwarfed by the ~0.1% insurance factor.
 c) D is set to ~100x the insurance rate of 1/777 12.87% + BTC amount
 d) insurance is added to Bob's payment, which is after the deposit and bailin
 e) BEFORE Bob broadcasts deposit, Alice broadcasts BTC denominated fee in cltv so if trade isnt done fee is reclaimed
 */

//#define DISABLE_CHECKSIG // unsolved MITM (evil peer)

/*
 both fees are standard payments: OP_DUP OP_HASH160 FEE_RMD160 OP_EQUALVERIFY OP_CHECKSIG
 
 Alice altpayment: OP_2 <alice_pubM> <bob_pubN> OP_2 OP_CHECKMULTISIG
 
 Bob deposit:
 #ifndef DISABLE_CHECKSIG
 OP_IF
 <now + INSTANTDEX_LOCKTIME*2> OP_CLTV OP_DROP <alice_pubA0> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(bob_privN)> OP_EQUALVERIFY <bob_pubB0> OP_CHECKSIG
 OP_ENDIF
 #else
 OP_IF
 <now + INSTANTDEX_LOCKTIME*2> OP_CLTV OP_DROP OP_SHA256 <sha256(alice_privA0)> OP_EQUAL
 OP_ELSE
 OP_HASH160 <hash(bob_privN)> OP_EQUALVERIFY OP_SHA256 <sha256(bob_privB0)> OP_EQUAL
 OP_ENDIF
#endif
 
 Bob paytx:
 #ifndef DISABLE_CHECKSIG
 OP_IF
 <now + INSTANTDEX_LOCKTIME> OP_CLTV OP_DROP <bob_pubB1> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY <alice_pubA0> OP_CHECKSIG
 OP_ENDIF
 #else
 OP_IF
 <now + INSTANTDEX_LOCKTIME> OP_CLTV OP_DROP OP_SHA256 <sha256(bob_privB1)> OP_EQUAL
 OP_ELSE
 OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY OP_SHA256 <sha256(alice_privA0)> OP_EQUAL
 OP_ENDIF
 #endif
 
 Naming convention are pubAi are alice's pubkeys (seems only pubA0 and not pubA1)
 pubBi are Bob's pubkeys
 
 privN is Bob's privkey from the cut and choose deck as selected by Alice
 privM is Alice's counterpart
 pubN and pubM are the corresponding pubkeys for these chosen privkeys
 
 Alice timeout event is triggered if INSTANTDEX_LOCKTIME elapses from the start of a FSM instance. Bob timeout event is triggered after INSTANTDEX_LOCKTIME*2
 */

/*
Bob sends bobdeposit and waits for alicepayment to confirm before sending bobpayment
Alice waits for bobdeposit to confirm and sends alicepayment

Alice spends bobpayment immediately divulging privAm
Bob spends alicepayment immediately after getting privAm and divulges privBn

Bob will spend bobdeposit after end of trade or INSTANTDEX_LOCKTIME, divulging privBn
Alice spends alicepayment as soon as privBn is seen

Bob will spend bobpayment after INSTANTDEX_LOCKTIME
Alice spends bobdeposit in 2*INSTANTDEX_LOCKTIME
*/

//Bobdeposit includes a covered put option for alicecoin, duration INSTANTDEX_LOCKTIME
//alicepayment includes a covered call option for alicecoin, duration (2*INSTANTDEX_LOCKTIME - elapsed)


/* in case of following states, some funds remain unclaimable, but all identified cases are due to one or both sides not spending when they were the only eligible party:
 
 Bob failed to claim deposit during exclusive period and since alice put in the claim, the alicepayment is unspendable. if alice is nice, she can send privAm to Bob.
Apaymentspent.(0000000000000000000000000000000000000000000000000000000000000000) alice.0 bob.0
paymentspent.(f91da4e001360b95276448e7b01904d9ee4d15862c5af7f5c7a918df26030315) alice.0 bob.1
depositspent.(f34e04ad74e290f63f3d0bccb7d0d50abfa54eea58de38816fdc596a19767add) alice.1 bob.0

 */

int32_t basilisk_istrustedbob(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    // for BTC and if trusted LP
    return(0);
}

int32_t basilisk_priviextract(struct supernet_info *myinfo,struct iguana_info *coin,char *name,bits256 *destp,uint8_t secret160[20],bits256 srctxid,int32_t srcvout)
{
    bits256 txid,privkey; char str[65]; int32_t i,vini,scriptlen; uint8_t rmd160[20],scriptsig[IGUANA_MAXSCRIPTSIZE];
    memset(privkey.bytes,0,sizeof(privkey));
    // use dex_listtransactions!
    if ( (vini= iguana_vinifind(myinfo,coin,&txid,srctxid,srcvout)) >= 0 )
    {
        if ( (scriptlen= iguana_scriptsigextract(myinfo,coin,scriptsig,sizeof(scriptsig),txid,vini)) > 32 )
        {
            for (i=0; i<32; i++)
                privkey.bytes[i] = scriptsig[scriptlen - 33 + i];
            revcalc_rmd160_sha256(rmd160,privkey);//.bytes,sizeof(privkey));
            if ( memcmp(secret160,rmd160,sizeof(rmd160)) == sizeof(rmd160) )
            {
                *destp = privkey;
                printf("basilisk_priviextract found privi %s (%s)\n",name,bits256_str(str,privkey));
                return(0);
            }
        }
    }
    return(-1);
}

void revcalc_rmd160_sha256(uint8_t rmd160[20],bits256 revhash)
{
    bits256 hash; int32_t i;
    for (i=0; i<32; i++)
        hash.bytes[i] = revhash.bytes[31-i];
    calc_rmd160_sha256(rmd160,hash.bytes,sizeof(hash));
}

bits256 revcalc_sha256(bits256 revhash)
{
    bits256 hash,dest; int32_t i;
    for (i=0; i<32; i++)
        hash.bytes[i] = revhash.bytes[31-i];
    vcalc_sha256(0,dest.bytes,hash.bytes,sizeof(hash));
    return(dest);
}

#define SCRIPT_OP_IF 0x63
#define SCRIPT_OP_ELSE 0x67
#define SCRIPT_OP_ENDIF 0x68

bits256 basilisk_revealkey(bits256 privkey,bits256 pubkey)
{
    bits256 reveal;
#ifdef DISABLE_CHECKSIG
    vcalc_sha256(0,reveal.bytes,privkey.bytes,sizeof(privkey));
    //reveal = revcalc_sha256(privkey);
    char str[65],str2[65]; printf("priv.(%s) -> reveal.(%s)\n",bits256_str(str,privkey),bits256_str(str2,reveal));
#else
    reveal = pubkey;
#endif
    return(reveal);
}

int32_t basilisk_swap_bobredeemscript(int32_t depositflag,int32_t *secretstartp,uint8_t *redeemscript,uint32_t locktime,bits256 pubA0,bits256 pubB0,bits256 pubB1,bits256 privAm,bits256 privBn,uint8_t *secretAm,uint8_t *secretAm256,uint8_t *secretBn,uint8_t *secretBn256)
{
    int32_t i,n=0; bits256 cltvpub,destpub,privkey; uint8_t pubkeyA[33],pubkeyB[33],secret160[20],secret256[32];
    if ( depositflag != 0 )
    {
        pubkeyA[0] = 0x02, cltvpub = pubA0;
        pubkeyB[0] = 0x03, destpub = pubB0;
        privkey = privBn;
        memcpy(secret160,secretBn,20);
        memcpy(secret256,secretBn256,32);
    }
    else
    {
        pubkeyA[0] = 0x03, cltvpub = pubB1;
        pubkeyB[0] = 0x02, destpub = pubA0;
        privkey = privAm;
        memcpy(secret160,secretAm,20);
        memcpy(secret256,secretAm256,32);
    }
    //for (i=0; i<32; i++)
    //    printf("%02x",secret256[i]);
    //printf(" <- secret256 depositflag.%d nonz.%d\n",depositflag,bits256_nonz(privkey));
    if ( bits256_nonz(cltvpub) == 0 || bits256_nonz(destpub) == 0 )
        return(-1);
    for (i=0; i<20; i++)
        if ( secret160[i] != 0 )
            break;
    if ( i == 20 )
        return(-1);
    memcpy(pubkeyA+1,cltvpub.bytes,sizeof(cltvpub));
    memcpy(pubkeyB+1,destpub.bytes,sizeof(destpub));
    redeemscript[n++] = SCRIPT_OP_IF;
    n = bitcoin_checklocktimeverify(redeemscript,n,locktime);
#ifdef DISABLE_CHECKSIG
    n = bitcoin_secret256spend(redeemscript,n,cltvpub);
#else
    n = bitcoin_pubkeyspend(redeemscript,n,pubkeyA);
#endif
    redeemscript[n++] = SCRIPT_OP_ELSE;
    if ( secretstartp != 0 )
        *secretstartp = n + 2;
    if ( 1 )
    {
        if ( 1 && bits256_nonz(privkey) != 0 )
        {
            uint8_t bufA[20],bufB[20];
            revcalc_rmd160_sha256(bufA,privkey);
            calc_rmd160_sha256(bufB,privkey.bytes,sizeof(privkey));
            /*if ( memcmp(bufA,secret160,sizeof(bufA)) == 0 )
                printf("MATCHES BUFA\n");
            else if ( memcmp(bufB,secret160,sizeof(bufB)) == 0 )
                printf("MATCHES BUFB\n");
            else printf("secret160 matches neither\n");
            for (i=0; i<20; i++)
                printf("%02x",bufA[i]);
            printf(" <- revcalc\n");
            for (i=0; i<20; i++)
                printf("%02x",bufB[i]);
            printf(" <- calc\n");*/
            memcpy(secret160,bufB,20);
        }
        n = bitcoin_secret160verify(redeemscript,n,secret160);
    }
    else
    {
        redeemscript[n++] = 0xa8;//IGUANA_OP_SHA256;
        redeemscript[n++] = 0x20;
        memcpy(&redeemscript[n],secret256,0x20), n += 0x20;
        redeemscript[n++] = 0x88; //SCRIPT_OP_EQUALVERIFY;
    }
#ifdef DISABLE_CHECKSIG
    n = bitcoin_secret256spend(redeemscript,n,destpub);
#else
    n = bitcoin_pubkeyspend(redeemscript,n,pubkeyB);
#endif
    redeemscript[n++] = SCRIPT_OP_ENDIF;
    return(n);
}

int32_t basilisk_bobscript(uint8_t *rmd160,uint8_t *redeemscript,int32_t *redeemlenp,uint8_t *script,int32_t n,uint32_t *locktimep,int32_t *secretstartp,struct basilisk_swapinfo *swap,int32_t depositflag)
{
    if ( depositflag != 0 )
        *locktimep = swap->started + swap->putduration + swap->callduration;
    else *locktimep = swap->started + swap->putduration;
    *redeemlenp = n = basilisk_swap_bobredeemscript(depositflag,secretstartp,redeemscript,*locktimep,swap->pubA0,swap->pubB0,swap->pubB1,swap->privAm,swap->privBn,swap->secretAm,swap->secretAm256,swap->secretBn,swap->secretBn256);
    if ( n > 0 )
    {
        calc_rmd160_sha256(rmd160,redeemscript,n);
        n = bitcoin_p2shspend(script,0,rmd160);
        //for (i=0; i<n; i++)
        //    printf("%02x",script[i]);
        //char str[65]; printf(" <- redeem.%d bobtx dflag.%d %s\n",n,depositflag,bits256_str(str,cltvpub));
    }
    return(n);
}

int32_t basilisk_alicescript(uint8_t *redeemscript,int32_t *redeemlenp,uint8_t *script,int32_t n,char *msigaddr,uint8_t altps2h,bits256 pubAm,bits256 pubBn)
{
    uint8_t p2sh160[20]; struct vin_info V;
    memset(&V,0,sizeof(V));
    memcpy(&V.signers[0].pubkey[1],pubAm.bytes,sizeof(pubAm)), V.signers[0].pubkey[0] = 0x02;
    memcpy(&V.signers[1].pubkey[1],pubBn.bytes,sizeof(pubBn)), V.signers[1].pubkey[0] = 0x03;
    V.M = V.N = 2;
    *redeemlenp = bitcoin_MofNspendscript(p2sh160,redeemscript,n,&V);
    bitcoin_address(msigaddr,altps2h,p2sh160,sizeof(p2sh160));
    n = bitcoin_p2shspend(script,0,p2sh160);
    //for (i=0; i<*redeemlenp; i++)
    //    printf("%02x",redeemscript[i]);
    //printf(" <- redeemscript alicetx\n");
    return(n);
}

int32_t basilisk_confirmsobj(cJSON *item)
{
    int32_t height,numconfirms;
    height = jint(item,"height");
    numconfirms = jint(item,"numconfirms");
    if ( height > 0 && numconfirms >= 0 )
        return(numconfirms);
    printf("basilisk_confirmsobj height.%d numconfirms.%d (%s)\n",height,numconfirms,jprint(item,0));
    return(-1);
}

int32_t basilisk_numconfirms(struct supernet_info *myinfo,struct basilisk_swap *swap,struct basilisk_rawtx *rawtx)
{
    cJSON *argjson,*valuearray=0; char *valstr; int32_t i,n,retval = -1;
#ifdef BASILISK_DISABLEWAITTX
    return(100);
#endif
    argjson = cJSON_CreateObject();
    jaddbits256(argjson,"txid",rawtx->I.actualtxid);
    jaddnum(argjson,"vout",0);
    jaddstr(argjson,"coin",rawtx->coin->symbol);
    if ( (valstr= basilisk_value(myinfo,rawtx->coin,0,0,swap->persistent_pubkey,argjson,0)) != 0 )
    {
        char str[65]; printf("basilisk_numconfirms required.%d %s %s valstr.(%s)\n",rawtx->I.numconfirms,rawtx->name,bits256_str(str,rawtx->I.actualtxid),valstr);
        //basilisk_numconfirms required.0 alicespend 29a2a6b4a61b1da82096d533c71b6762d61a82ca771a633269d97c0ccb94fe85 valstr.({"result":"success","numconfirms":0,"address":"1JGvZ67oTdM7kCya4J8kj1uErbSRAoq3wH","satoshis":"1413818","value":0.01413818,"height":462440,"txid":"29a2a6b4a61b1da82096d533c71b6762d61a82ca771a633269d97c0ccb94fe85","vout":0,"coin":"BTC"})

        if ( (valuearray= cJSON_Parse(valstr)) != 0 )
        {
            if ( valstr[0] == '[' && is_cJSON_Array(valuearray) != 0 )
            {
                n = cJSON_GetArraySize(valuearray);
                for (i=0; i<n; i++)
                {
                    printf("i.%d of n.%d\n",i,n);
                    if ( (retval= basilisk_confirmsobj(jitem(valuearray,i))) >= 0 )
                        break;
               }
            } else retval = basilisk_confirmsobj(valuearray);
            free_json(valuearray);
        } else printf("parse error\n");
        free(valstr);
    }
    free_json(argjson);
    printf("numconfirms.%d returned\n",retval);
    return(retval);
}

bits256 basilisk_swap_broadcast(char *name,struct supernet_info *myinfo,struct basilisk_swap *swap,struct iguana_info *coin,uint8_t *data,int32_t datalen)
{
    bits256 txid; char *signedtx,*retstr; int32_t i;
    memset(txid.bytes,0,sizeof(txid));
    if ( data != 0 && datalen != 0 )
    {
        char str[65];
#ifdef BASILISK_DISABLESENDTX
        txid = bits256_doublesha256(0,data,datalen);
        printf("%s <- dont sendrawtransaction (%s)\n",name,bits256_str(str,txid));
        return(txid);
#endif
        signedtx = malloc(datalen*2 + 1);
        init_hexbytes_noT(signedtx,data,datalen);
        for (i=0; i<3; i++)
        {
            if ( (retstr= basilisk_sendrawtransaction(myinfo,coin,signedtx)) != 0 )
            {
                if ( is_hexstr(retstr,0) == 64 )
                {
                    decode_hex(txid.bytes,32,retstr);
                    free(retstr);
                    printf("sendrawtransaction %s.(%s)\n",name,bits256_str(str,txid));
                    break;
                }
                else
                {
                    printf("sendrawtransaction %s error.(%s)\n",name,retstr);
                    free(retstr);
                }
            } else printf("sendrawtransaction %s got null return\n",name);
        }
        free(signedtx);
    }
    return(txid);
}

int32_t _basilisk_rawtx_sign(struct supernet_info *myinfo,int32_t height,uint32_t timestamp,uint32_t locktime,uint32_t sequenceid,struct basilisk_rawtx *dest,struct basilisk_rawtx *rawtx,bits256 privkey,bits256 *privkey2,uint8_t *userdata,int32_t userdatalen,int32_t ignore_cltverr)
{
    char *rawtxbytes=0,*signedtx=0,hexstr[999],wifstr[128]; cJSON *txobj,*vins,*item,*sobj,*privkeys; int32_t needsig=1,retval = -1; struct vin_info *V;
    V = calloc(256,sizeof(*V));
    V[0].signers[0].privkey = privkey;
    bitcoin_pubkey33(myinfo->ctx,V[0].signers[0].pubkey,privkey);
    privkeys = cJSON_CreateArray();
    bitcoin_priv2wif(wifstr,privkey,rawtx->coin->chain->wiftype);
    jaddistr(privkeys,wifstr);
    if ( privkey2 != 0 )
    {
        V[0].signers[1].privkey = *privkey2;
        bitcoin_pubkey33(myinfo->ctx,V[0].signers[1].pubkey,*privkey2);
        bitcoin_priv2wif(wifstr,*privkey2,rawtx->coin->chain->wiftype);
        jaddistr(privkeys,wifstr);
        V[0].N = V[0].M = 2;
        //char str[65]; printf("add second privkey.(%s) %s\n",jprint(privkeys,0),bits256_str(str,*privkey2));
    } else V[0].N = V[0].M = 1;
    V[0].suppress_pubkeys = dest->I.suppress_pubkeys;
    V[0].ignore_cltverr = ignore_cltverr;
    if ( dest->I.redeemlen != 0 )
        memcpy(V[0].p2shscript,dest->redeemscript,dest->I.redeemlen), V[0].p2shlen = dest->I.redeemlen;
    txobj = bitcoin_txcreate(rawtx->coin->symbol,rawtx->coin->chain->isPoS,locktime,userdata == 0 ? 1 : 1,timestamp);//rawtx->coin->chain->locktime_txversion);
    vins = cJSON_CreateArray();
    item = cJSON_CreateObject();
    if ( userdata != 0 && userdatalen > 0 )
    {
        memcpy(V[0].userdata,userdata,userdatalen);
        V[0].userdatalen = userdatalen;
        init_hexbytes_noT(hexstr,userdata,userdatalen);
        jaddstr(item,"userdata",hexstr);
#ifdef DISABLE_CHECKSIG
        needsig = 0;
#endif
    }
    //printf("rawtx B\n");
    if ( bits256_nonz(rawtx->I.actualtxid) != 0 )
        jaddbits256(item,"txid",rawtx->I.actualtxid);
    else jaddbits256(item,"txid",rawtx->I.signedtxid);
    jaddnum(item,"vout",0);
    sobj = cJSON_CreateObject();
    init_hexbytes_noT(hexstr,rawtx->spendscript,rawtx->I.spendlen);
    jaddstr(sobj,"hex",hexstr);
    jadd(item,"scriptPubKey",sobj);
    jaddnum(item,"suppress",dest->I.suppress_pubkeys);
    jaddnum(item,"sequence",sequenceid);
    if ( (dest->I.redeemlen= rawtx->I.redeemlen) != 0 )
    {
        init_hexbytes_noT(hexstr,rawtx->redeemscript,rawtx->I.redeemlen);
        memcpy(dest->redeemscript,rawtx->redeemscript,rawtx->I.redeemlen);
        jaddstr(item,"redeemScript",hexstr);
    }
    jaddi(vins,item);
    jdelete(txobj,"vin");
    jadd(txobj,"vin",vins);
    //printf("basilisk_rawtx_sign locktime.%u/%u for %s spendscript.%s -> %s, suppress.%d\n",rawtx->I.locktime,dest->I.locktime,rawtx->name,hexstr,dest->name,dest->I.suppress_pubkeys);
    txobj = bitcoin_txoutput(txobj,dest->spendscript,dest->I.spendlen,dest->I.amount);
    if ( (rawtxbytes= bitcoin_json2hex(myinfo,rawtx->coin,&dest->I.txid,txobj,V)) != 0 )
    {
        //printf("rawtx.(%s) vins.%p\n",rawtxbytes,vins);
        if ( needsig == 0 )
            signedtx = rawtxbytes;
        if ( signedtx != 0 || (signedtx= iguana_signrawtx(myinfo,rawtx->coin,height,&dest->I.signedtxid,&dest->I.completed,vins,rawtxbytes,privkeys,V)) != 0 )
        {
            dest->I.datalen = (int32_t)strlen(signedtx) >> 1;
            if ( dest->I.datalen <= sizeof(dest->txbytes) )
                decode_hex(dest->txbytes,dest->I.datalen,signedtx);
            else printf("DEX tx is too big %d vs %d\n",dest->I.datalen,(int32_t)sizeof(dest->txbytes));
            if ( signedtx != rawtxbytes )
                free(signedtx);
            if ( dest->I.completed != 0 )
                retval = 0;
            else printf("couldnt complete sign transaction %s\n",rawtx->name);
        } else printf("error signing\n");
        free(rawtxbytes);
    } else printf("error making rawtx\n");
    free_json(privkeys);
    free_json(txobj);
    free(V);
    return(retval);
}

int32_t basilisk_rawtx_sign(struct supernet_info *myinfo,int32_t height,struct basilisk_swap *swap,struct basilisk_rawtx *dest,struct basilisk_rawtx *rawtx,bits256 privkey,bits256 *privkey2,uint8_t *userdata,int32_t userdatalen,int32_t ignore_cltverr)
{
    uint32_t timestamp,locktime=0,sequenceid = 0xffffffff;
    timestamp = swap->I.started;
    if ( dest == &swap->aliceclaim )
        locktime = swap->bobdeposit.I.locktime + 1, sequenceid = 0;
    else if ( dest == &swap->bobreclaim )
        locktime = swap->bobpayment.I.locktime + 1, sequenceid = 0;
    return(_basilisk_rawtx_sign(myinfo,height,timestamp,locktime,sequenceid,dest,rawtx,privkey,privkey2,userdata,userdatalen,ignore_cltverr));
}

cJSON *basilisk_privkeyarray(struct supernet_info *myinfo,struct iguana_info *coin,cJSON *vins)
{
    cJSON *privkeyarray,*item,*sobj; struct iguana_waddress *waddr; struct iguana_waccount *wacct; char coinaddr[64],account[128],wifstr[64],str[65],typestr[64],*hexstr; uint8_t script[1024]; int32_t i,n,len,vout; bits256 txid,privkey; double bidasks[2];
    privkeyarray = cJSON_CreateArray();
    //printf("%s persistent.(%s) (%s) change.(%s) scriptstr.(%s)\n",coin->symbol,myinfo->myaddr.BTC,coinaddr,coin->changeaddr,scriptstr);
    if ( (n= cJSON_GetArraySize(vins)) > 0 )
    {
        for (i=0; i<n; i++)
        {
            item = jitem(vins,i);
            txid = jbits256(item,"txid");
            vout = jint(item,"vout");
            if ( bits256_nonz(txid) != 0 && vout >= 0 )
            {
                iguana_txidcategory(myinfo,coin,account,coinaddr,txid,vout);
                if ( coinaddr[0] == 0 && (sobj= jobj(item,"scriptPubKey")) != 0 && (hexstr= jstr(sobj,"hex")) != 0 && is_hexstr(hexstr,0) > 0 )
                {
                    len = (int32_t)strlen(hexstr) >> 1;
                    if ( len < (sizeof(script) << 1) )
                    {
                        decode_hex(script,len,hexstr);
                        if ( len == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 )
                            bitcoin_address(coinaddr,coin->chain->pubtype,script+3,20);
                    }
                }
                if ( coinaddr[0] != 0 )
                {
                    if ( (waddr= iguana_waddresssearch(myinfo,&wacct,coinaddr)) != 0 )
                    {
                        bitcoin_priv2wif(wifstr,waddr->privkey,coin->chain->wiftype);
                        jaddistr(privkeyarray,waddr->wifstr);
                    }
                    else if ( smartaddress(myinfo,typestr,bidasks,&privkey,coin->symbol,coinaddr) >= 0 )
                    {
                        bitcoin_priv2wif(wifstr,privkey,coin->chain->wiftype);
                        jaddistr(privkeyarray,wifstr);
                    }
                    else printf("cant find (%s) in wallet\n",coinaddr);
                } else printf("cant coinaddr from (%s).v%d\n",bits256_str(str,txid),vout);
            } else printf("invalid txid/vout %d of %d\n",i,n);
        }
    }
    return(privkeyarray);
}

int32_t basilisk_rawtx_return(struct supernet_info *myinfo,int32_t height,struct basilisk_rawtx *rawtx,cJSON *item,int32_t lockinputs,struct vin_info *V)
{
    char *signedtx,*txbytes; cJSON *vins,*privkeyarray; int32_t i,n,retval = -1;
    if ( (txbytes= jstr(item,"rawtx")) != 0 && (vins= jobj(item,"vins")) != 0 )
    {
        privkeyarray = basilisk_privkeyarray(myinfo,rawtx->coin,vins);
        if ( (signedtx= iguana_signrawtx(myinfo,rawtx->coin,height,&rawtx->I.signedtxid,&rawtx->I.completed,vins,txbytes,privkeyarray,V)) != 0 )
        {
            if ( lockinputs != 0 )
            {
                //printf("lockinputs\n");
                iguana_RTunspentslock(myinfo,rawtx->coin,vins);
                if ( (n= cJSON_GetArraySize(vins)) != 0 )
                {
                    bits256 txid; int32_t vout;
                    for (i=0; i<n; i++)
                    {
                        item = jitem(vins,i);
                        txid = jbits256(item,"txid");
                        vout = jint(item,"vout");
                    }
                }
            }
            rawtx->I.datalen = (int32_t)strlen(signedtx) >> 1;
            //rawtx->txbytes = calloc(1,rawtx->I.datalen);
            decode_hex(rawtx->txbytes,rawtx->I.datalen,signedtx);
            //printf("%s SIGNEDTX.(%s)\n",rawtx->name,signedtx);
            free(signedtx);
            retval = 0;
        } else printf("error signrawtx\n"); //do a very short timeout so it finishes via local poll
        free_json(privkeyarray);
    }
    return(retval);
}

int32_t _basilisk_rawtx_gen(char *str,struct supernet_info *myinfo,uint32_t swapstarted,uint8_t *pubkey33,int32_t iambob,int32_t lockinputs,struct basilisk_rawtx *rawtx,uint32_t locktime,uint8_t *script,int32_t scriptlen,int64_t txfee,int32_t minconf,int32_t delay)
{
    char *retstr,*jsonstr,scriptstr[1024],coinaddr[64]; uint32_t basilisktag; int32_t flag,i,n,retval = -1; cJSON *addresses,*valsobj,*retarray=0; struct vin_info *V;
    //bitcoin_address(coinaddr,rawtx->coin->chain->pubtype,myinfo->persistent_pubkey33,33);
    if ( rawtx->coin->changeaddr[0] == 0 )
    {
        bitcoin_address(rawtx->coin->changeaddr,rawtx->coin->chain->pubtype,pubkey33,33);
        printf("set change address.(%s)\n",rawtx->coin->changeaddr);
    }
    init_hexbytes_noT(scriptstr,script,scriptlen);
    basilisktag = (uint32_t)rand();
    valsobj = cJSON_CreateObject();
    jaddstr(valsobj,"coin",rawtx->coin->symbol);
    jaddstr(valsobj,"spendscript",scriptstr);
    jaddstr(valsobj,"changeaddr",rawtx->coin->changeaddr);
    jadd64bits(valsobj,"satoshis",rawtx->I.amount);
    if ( strcmp(rawtx->coin->symbol,"BTC") == 0 && txfee > 0 && txfee < 50000 )
        txfee = 50000;
    jadd64bits(valsobj,"txfee",txfee);
    jaddnum(valsobj,"minconf",minconf);
    if ( locktime == 0 )
        locktime = (uint32_t)time(NULL) - 777;
    jaddnum(valsobj,"locktime",locktime);
    jaddnum(valsobj,"timeout",30000);
    jaddnum(valsobj,"timestamp",swapstarted+delay);
    addresses = cJSON_CreateArray();
    bitcoin_address(coinaddr,rawtx->coin->chain->pubtype,pubkey33,33);
    jaddistr(addresses,coinaddr);
    jadd(valsobj,"addresses",addresses);
    rawtx->I.locktime = locktime;
    printf("%s locktime.%u\n",rawtx->name,locktime);
    V = calloc(256,sizeof(*V));
    if ( (retstr= basilisk_bitcoinrawtx(myinfo,rawtx->coin,"",basilisktag,jint(valsobj,"timeout"),valsobj,V)) != 0 )
    {
        printf("%s %s basilisk_bitcoinrawtx.(%s) txfee %.8f\n",rawtx->name,str,retstr,dstr(txfee));
        flag = 0;
        if ( (retarray= cJSON_Parse(retstr)) != 0 )
        {
            if ( is_cJSON_Array(retarray) != 0 )
            {
                n = cJSON_GetArraySize(retarray);
                for (i=0; i<n; i++)
                {
                    if ( (retval= basilisk_rawtx_return(myinfo,rawtx->coin->longestchain,rawtx,jitem(retarray,i),lockinputs,V)) == 0 )
                    {
                        rawtx->vins = jduplicate(jobj(jitem(retarray,i),"vins"));
                        jsonstr = jprint(rawtx->vins,0);
                        safecopy(rawtx->vinstr,jsonstr,sizeof(rawtx->vinstr));
                        free(jsonstr);
                        break;
                    }
                }
            }
            else
            {
                retval = basilisk_rawtx_return(myinfo,rawtx->coin->longestchain,rawtx,retarray,lockinputs,V);
                rawtx->vins = jduplicate(jobj(retarray,"vins"));
                jsonstr = jprint(rawtx->vins,0);
                safecopy(rawtx->vinstr,jsonstr,sizeof(rawtx->vinstr));
                free(jsonstr);
            }
            free(retarray);
        } else printf("error parsing.(%s)\n",retstr);
        free(retstr);
    } else printf("error creating %s %s\n",iambob != 0 ? "BOB" : "ALICE",rawtx->name);
    free_json(valsobj);
    free(V);
    return(retval);
}

int32_t basilisk_rawtx_gen(char *str,struct supernet_info *myinfo,uint32_t swapstarted,uint8_t *pubkey33,int32_t iambob,int32_t lockinputs,struct basilisk_rawtx *rawtx,uint32_t locktime,uint8_t *script,int32_t scriptlen,int64_t txfee,int32_t minconf,int32_t delay)
{
    int32_t retval,len; uint64_t newtxfee; struct iguana_info *coin;
    if ( (coin= rawtx->coin) == 0 || strcmp(coin->symbol,"BTC") != 0 )
        return(_basilisk_rawtx_gen(str,myinfo,swapstarted,pubkey33,iambob,lockinputs,rawtx,locktime,script,scriptlen,txfee,minconf,delay));
    retval = _basilisk_rawtx_gen(str,myinfo,swapstarted,pubkey33,iambob,0,rawtx,locktime,script,scriptlen,txfee,minconf,delay);
    len = rawtx->I.datalen;
    if ( coin->estimatedfee == 0 )
        coin->estimatedfee = iguana_getestimatedfee(myinfo,coin);
    newtxfee = coin->estimatedfee * len;
    if ( newtxfee > txfee )
    {
        retval = _basilisk_rawtx_gen(str,myinfo,swapstarted,pubkey33,iambob,lockinputs,rawtx,locktime,script,scriptlen,newtxfee,minconf,delay);
        printf("txfee %.8f -> newtxfee %.8f\n",dstr(txfee),dstr(newtxfee));
    }
    return(retval);
}

struct basilisk_rawtx *basilisk_swapdata_rawtx(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx)
{
    if ( rawtx->I.datalen != 0 && rawtx->I.datalen <= maxlen )
    {
        memcpy(data,rawtx->txbytes,rawtx->I.datalen);
        return(rawtx);
    }
    return(0);
}

int32_t basilisk_verify_otherfee(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    struct basilisk_swap *swap = ptr;
    // add verification and broadcast
    //swap->otherfee.txbytes = calloc(1,datalen);
    memcpy(swap->otherfee.txbytes,data,datalen);
    swap->otherfee.I.datalen = datalen;
    swap->otherfee.I.actualtxid = swap->otherfee.I.signedtxid = bits256_doublesha256(0,data,datalen);
    basilisk_txlog(myinfo,swap,&swap->otherfee,-1);
    return(0);
}

int32_t basilisk_rawtx_spendscript(struct basilisk_swap *swap,int32_t height,struct basilisk_rawtx *rawtx,int32_t v,uint8_t *recvbuf,int32_t recvlen,int32_t suppress_pubkeys)
{
    int32_t datalen=0,retval=-1,hexlen,n; uint8_t *data; cJSON *txobj,*skey,*vouts,*vout; char *hexstr; bits256 txid;
    datalen = recvbuf[0];
    datalen += (int32_t)recvbuf[1] << 8;
    if ( datalen > 65536 )
        return(-1);
    rawtx->I.redeemlen = recvbuf[2];
    data = &recvbuf[3];
    if ( rawtx->I.redeemlen > 0 && rawtx->I.redeemlen < 0x100 )
        memcpy(rawtx->redeemscript,&data[datalen],rawtx->I.redeemlen);
    //printf("recvlen.%d datalen.%d redeemlen.%d\n",recvlen,datalen,rawtx->redeemlen);
    if ( rawtx->I.datalen == 0 )
    {
        //rawtx->txbytes = calloc(1,datalen);
        memcpy(rawtx->txbytes,data,datalen);
        rawtx->I.datalen = datalen;
    }
    else if ( datalen != rawtx->I.datalen || memcmp(rawtx->txbytes,data,datalen) != 0 )
    {
        int32_t i; for (i=0; i<datalen; i++)
            printf("%02x",data[i]);
        printf(" <- received\n");
        for (i=0; i<rawtx->I.datalen; i++)
            printf("%02x",rawtx->txbytes[i]);
        printf(" <- rawtx\n");
        printf("%s rawtx data compare error, len %d vs %d <<<<<<<<<< warning\n",rawtx->name,rawtx->I.datalen,datalen);
        return(-1);
    }
    txid = bits256_doublesha256(0,data,datalen);
    char str[65]; printf("rawtx.%s txid %s\n",rawtx->name,bits256_str(str,txid));
    if ( bits256_cmp(txid,rawtx->I.actualtxid) != 0 && bits256_nonz(rawtx->I.actualtxid) == 0 )
        rawtx->I.actualtxid = txid;
    if ( (txobj= bitcoin_data2json(rawtx->coin,height,&rawtx->I.signedtxid,&rawtx->msgtx,rawtx->extraspace,sizeof(rawtx->extraspace),data,datalen,0,suppress_pubkeys)) != 0 )
    {
        rawtx->I.actualtxid = rawtx->I.signedtxid;
        //char str[65]; printf("got txid.%s (%s)\n",bits256_str(str,rawtx->signedtxid),jprint(txobj,0));
        rawtx->I.locktime = rawtx->msgtx.lock_time;
        if ( (vouts= jarray(&n,txobj,"vout")) != 0 && v < n )
        {
            vout = jitem(vouts,v);
            if ( j64bits(vout,"satoshis") == rawtx->I.amount && (skey= jobj(vout,"scriptPubKey")) != 0 && (hexstr= jstr(skey,"hex")) != 0 )
            {
                if ( (hexlen= (int32_t)strlen(hexstr) >> 1) < sizeof(rawtx->spendscript) )
                {
                    decode_hex(rawtx->spendscript,hexlen,hexstr);
                    rawtx->I.spendlen = hexlen;
                    bitcoin_address(rawtx->p2shaddr,rawtx->coin->chain->p2shtype,rawtx->spendscript,hexlen);
                    if ( swap != 0 )
                        basilisk_txlog(swap->myinfoptr,swap,rawtx,-1); // bobdeposit, bobpayment or alicepayment
                    retval = 0;
                }
            } else printf("%s ERROR.(%s)\n",rawtx->name,jprint(txobj,0));
        }
        free_json(txobj);
    }
    return(retval);
}

void basilisk_swap_coinaddr(struct supernet_info *myinfo,struct basilisk_swap *swap,struct iguana_info *coin,char *coinaddr,uint8_t *data,int32_t datalen)
{
    cJSON *txobj,*vouts,*vout,*addresses,*item,*skey; uint8_t extraspace[8192]; bits256 signedtxid; struct iguana_msgtx msgtx; char *addr; int32_t n,m,suppress_pubkeys = 0;
    if ( (txobj= bitcoin_data2json(coin,coin->longestchain,&signedtxid,&msgtx,extraspace,sizeof(extraspace),data,datalen,0,suppress_pubkeys)) != 0 )
    {
        //char str[65]; printf("got txid.%s (%s)\n",bits256_str(str,signedtxid),jprint(txobj,0));
        if ( (vouts= jarray(&n,txobj,"vout")) != 0 && n > 0 )
        {
            vout = jitem(vouts,0);
            //printf("VOUT.(%s)\n",jprint(vout,0));
            if ( (skey= jobj(vout,"scriptPubKey")) != 0 && (addresses= jarray(&m,skey,"addresses")) != 0 )
            {
                item = jitem(addresses,0);
                //printf("item.(%s)\n",jprint(item,0));
                if ( (addr= jstr(item,0)) != 0 )
                {
                    safecopy(coinaddr,addr,64);
                    //printf("extracted.(%s)\n",coinaddr);
                }
            }
        }
        free_json(txobj);
    }
}

int32_t basilisk_swapuserdata(uint8_t *userdata,bits256 privkey,int32_t ifpath,bits256 signpriv,uint8_t *redeemscript,int32_t redeemlen)
{
    int32_t i,len = 0;
#ifdef DISABLE_CHECKSIG
    userdata[len++] = sizeof(signpriv);
    for (i=0; i<sizeof(privkey); i++)
        userdata[len++] = signpriv.bytes[i];
#endif
    if ( bits256_nonz(privkey) != 0 )
    {
        userdata[len++] = sizeof(privkey);
        for (i=0; i<sizeof(privkey); i++)
            userdata[len++] = privkey.bytes[i];
    }
    userdata[len++] = 0x51 * ifpath; // ifpath == 1 -> if path, 0 -> else path
    return(len);
}

/*    Bob deposit:
 OP_IF
 <now + INSTANTDEX_LOCKTIME*2> OP_CLTV OP_DROP <alice_pubA0> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(bob_privN)> OP_EQUALVERIFY <bob_pubB0> OP_CHECKSIG
 OP_ENDIF*/

void basilisk_dontforget_userdata(char *userdataname,FILE *fp,uint8_t *script,int32_t scriptlen)
{
    int32_t i; char scriptstr[513];
    if ( scriptlen != 0 )
    {
        for (i=0; i<scriptlen; i++)
            sprintf(&scriptstr[i << 1],"%02x",script[i]);
        scriptstr[i << 1] = 0;
        fprintf(fp,"\",\"%s\":\"%s\"",userdataname,scriptstr);
    }
}

void basilisk_dontforget(struct supernet_info *myinfo,struct basilisk_swap *swap,struct basilisk_rawtx *rawtx,int32_t locktime,bits256 triggertxid)
{
    char zeroes[32],fname[512],str[65],coinaddr[64],secretAmstr[41],secretAm256str[65],secretBnstr[41],secretBn256str[65],*tmp; FILE *fp; int32_t i,len; uint8_t redeemscript[256],script[256];
    sprintf(fname,"%s/SWAPS/%u-%u.%s",GLOBAL_DBDIR,swap->I.req.requestid,swap->I.req.quoteid,rawtx->name), OS_compatible_path(fname);
    coinaddr[0] = secretAmstr[0] = secretAm256str[0] = secretBnstr[0] = secretBn256str[0] = 0;
    memset(zeroes,0,sizeof(zeroes));
    if ( rawtx != 0 && (fp= fopen(fname,"wb")) != 0 )
    {
        fprintf(fp,"{\"name\":\"%s\",\"coin\":\"%s\"",rawtx->name,rawtx->coin->symbol);
        if ( rawtx->I.datalen > 0 )
        {
             fprintf(fp,",\"tx\":\"");
            for (i=0; i<rawtx->I.datalen; i++)
                fprintf(fp,"%02x",rawtx->txbytes[i]);
            fprintf(fp,"\",\"txid\":\"%s\"",bits256_str(str,bits256_doublesha256(0,rawtx->txbytes,rawtx->I.datalen)));
            if ( rawtx == &swap->bobdeposit || rawtx == &swap->bobpayment )
            {
                basilisk_swap_coinaddr(myinfo,swap,swap->bobcoin,coinaddr,rawtx->txbytes,rawtx->I.datalen);
                if ( coinaddr[0] != 0 )
                {
                    if ( swap->bobcoin != 0 && swap->bobcoin->FULLNODE < 0 )
                    {
                        if ( (tmp= dpow_importaddress(myinfo,swap->bobcoin,coinaddr)) != 0 )
                            free(tmp);
                    }
                    if ( rawtx == &swap->bobdeposit )
                        safecopy(swap->Bdeposit,coinaddr,sizeof(swap->Bdeposit));
                    else safecopy(swap->Bpayment,coinaddr,sizeof(swap->Bpayment));
                }
            }
        }
        if ( swap->Bdeposit[0] != 0 )
            fprintf(fp,",\"%s\":\"%s\"","Bdeposit",swap->Bdeposit);
        if ( swap->Bpayment[0] != 0 )
            fprintf(fp,",\"%s\":\"%s\"","Bpayment",swap->Bpayment);
        fprintf(fp,",\"expiration\":%u",swap->I.expiration);
        fprintf(fp,",\"iambob\":%d",swap->I.iambob);
        fprintf(fp,",\"bobcoin\":\"%s\"",swap->bobcoin->symbol);
        fprintf(fp,",\"alicecoin\":\"%s\"",swap->alicecoin->symbol);
        fprintf(fp,",\"lock\":%u",locktime);
        fprintf(fp,",\"amount\":%.8f",dstr(rawtx->I.amount));
        if ( bits256_nonz(triggertxid) != 0 )
            fprintf(fp,",\"trigger\":\"%s\"",bits256_str(str,triggertxid));
        if ( bits256_nonz(swap->I.pubAm) != 0 && bits256_nonz(swap->I.pubBn) != 0 )
        {
            basilisk_alicescript(redeemscript,&len,script,0,coinaddr,swap->alicecoin->chain->p2shtype,swap->I.pubAm,swap->I.pubBn);
            if ( swap->alicecoin != 0 && swap->alicecoin->FULLNODE < 0 )
            {
                if ( (tmp= dpow_importaddress(myinfo,swap->alicecoin,coinaddr)) != 0 )
                    free(tmp);
            }
            fprintf(fp,",\"Apayment\":\"%s\"",coinaddr);
        }
        /*basilisk_dontforget_userdata("Aclaim",fp,swap->I.userdata_aliceclaim,swap->I.userdata_aliceclaimlen);
        basilisk_dontforget_userdata("Areclaim",fp,swap->I.userdata_alicereclaim,swap->I.userdata_alicereclaimlen);
        basilisk_dontforget_userdata("Aspend",fp,swap->I.userdata_alicespend,swap->I.userdata_alicespendlen);
        basilisk_dontforget_userdata("Bspend",fp,swap->I.userdata_bobspend,swap->I.userdata_bobspendlen);
        basilisk_dontforget_userdata("Breclaim",fp,swap->I.userdata_bobreclaim,swap->I.userdata_bobreclaimlen);
        basilisk_dontforget_userdata("Brefund",fp,swap->I.userdata_bobrefund,swap->I.userdata_bobrefundlen);*/
        fprintf(fp,"}\n");
        fclose(fp);
    }
    sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,swap->I.req.requestid,swap->I.req.quoteid), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"wb")) != 0 )
    {
        fprintf(fp,"{\"src\":\"%s\",\"srcamount\":%.8f,\"dest\":\"%s\",\"destamount\":%.8f,\"requestid\":%u,\"quoteid\":%u,\"iambob\":%d,\"state\":%u,\"otherstate\":%u,\"expiration\":%u,\"dlocktime\":%u,\"plocktime\":%u",swap->I.req.src,dstr(swap->I.req.srcamount),swap->I.req.dest,dstr(swap->I.req.destamount),swap->I.req.requestid,swap->I.req.quoteid,swap->I.iambob,swap->I.statebits,swap->I.otherstatebits,swap->I.expiration,swap->bobdeposit.I.locktime,swap->bobpayment.I.locktime);
        if ( memcmp(zeroes,swap->I.secretAm,20) != 0 )
        {
            init_hexbytes_noT(secretAmstr,swap->I.secretAm,20);
            fprintf(fp,",\"secretAm\":\"%s\"",secretAmstr);
        }
        if ( memcmp(zeroes,swap->I.secretAm256,32) != 0 )
        {
            init_hexbytes_noT(secretAm256str,swap->I.secretAm256,32);
            fprintf(fp,",\"secretAm256\":\"%s\"",secretAm256str);
        }
        if ( memcmp(zeroes,swap->I.secretBn,20) != 0 )
        {
            init_hexbytes_noT(secretBnstr,swap->I.secretBn,20);
            fprintf(fp,",\"secretBn\":\"%s\"",secretBnstr);
        }
        if ( memcmp(zeroes,swap->I.secretBn256,32) != 0 )
        {
            init_hexbytes_noT(secretBn256str,swap->I.secretBn256,32);
            fprintf(fp,",\"secretBn256\":\"%s\"",secretBn256str);
        }
        for (i=0; i<2; i++)
            if ( bits256_nonz(swap->I.myprivs[i]) != 0 )
                fprintf(fp,",\"myprivs%d\":\"%s\"",i,bits256_str(str,swap->I.myprivs[i]));
        if ( bits256_nonz(swap->I.privAm) != 0 )
            fprintf(fp,",\"privAm\":\"%s\"",bits256_str(str,swap->I.privAm));
        if ( bits256_nonz(swap->I.privBn) != 0 )
            fprintf(fp,",\"privBn\":\"%s\"",bits256_str(str,swap->I.privBn));
        if ( bits256_nonz(swap->I.pubA0) != 0 )
            fprintf(fp,",\"pubA0\":\"%s\"",bits256_str(str,swap->I.pubA0));
        if ( bits256_nonz(swap->I.pubB0) != 0 )
            fprintf(fp,",\"pubB0\":\"%s\"",bits256_str(str,swap->I.pubB0));
        if ( bits256_nonz(swap->I.pubB1) != 0 )
            fprintf(fp,",\"pubB1\":\"%s\"",bits256_str(str,swap->I.pubB1));
        if ( bits256_nonz(swap->bobdeposit.I.actualtxid) != 0 )
            fprintf(fp,",\"Bdeposit\":\"%s\"",bits256_str(str,swap->bobdeposit.I.actualtxid));
        if ( bits256_nonz(swap->bobrefund.I.actualtxid) != 0 )
            fprintf(fp,",\"Brefund\":\"%s\"",bits256_str(str,swap->bobrefund.I.actualtxid));
        if ( bits256_nonz(swap->aliceclaim.I.actualtxid) != 0 )
            fprintf(fp,",\"Aclaim\":\"%s\"",bits256_str(str,swap->aliceclaim.I.actualtxid));
        
        if ( bits256_nonz(swap->bobpayment.I.actualtxid) != 0 )
            fprintf(fp,",\"Bpayment\":\"%s\"",bits256_str(str,swap->bobpayment.I.actualtxid));
        if ( bits256_nonz(swap->alicespend.I.actualtxid) != 0 )
            fprintf(fp,",\"Aspend\":\"%s\"",bits256_str(str,swap->alicespend.I.actualtxid));
        if ( bits256_nonz(swap->bobreclaim.I.actualtxid) != 0 )
            fprintf(fp,",\"Breclaim\":\"%s\"",bits256_str(str,swap->bobreclaim.I.actualtxid));

        if ( bits256_nonz(swap->alicepayment.I.actualtxid) != 0 )
            fprintf(fp,",\"Apayment\":\"%s\"",bits256_str(str,swap->alicepayment.I.actualtxid));
        if ( bits256_nonz(swap->bobspend.I.actualtxid) != 0 )
            fprintf(fp,",\"Bspend\":\"%s\"",bits256_str(str,swap->bobspend.I.actualtxid));
        if ( bits256_nonz(swap->alicereclaim.I.actualtxid) != 0 )
            fprintf(fp,",\"Areclaim\":\"%s\"",bits256_str(str,swap->alicereclaim.I.actualtxid));
        
        if ( bits256_nonz(swap->otherfee.I.actualtxid) != 0 )
            fprintf(fp,",\"otherfee\":\"%s\"",bits256_str(str,swap->otherfee.I.actualtxid));
        if ( bits256_nonz(swap->myfee.I.actualtxid) != 0 )
            fprintf(fp,",\"myfee\":\"%s\"",bits256_str(str,swap->myfee.I.actualtxid));
        fprintf(fp,",\"dest33\":\"");
        for (i=0; i<33; i++)
            fprintf(fp,"%02x",swap->persistent_pubkey33[i]);
        fprintf(fp,"\"}\n");
        fclose(fp);
    }
}

void basilisk_dontforget_update(struct supernet_info *myinfo,struct basilisk_swap *swap,struct basilisk_rawtx *rawtx)
{
    bits256 triggertxid;
    memset(triggertxid.bytes,0,sizeof(triggertxid));
    if ( rawtx == 0 )
    {
        basilisk_dontforget(myinfo,swap,0,0,triggertxid);
        return;
    }
    if ( rawtx == &swap->myfee )
        basilisk_dontforget(myinfo,swap,&swap->myfee,0,triggertxid);
    else if ( rawtx == &swap->otherfee )
        basilisk_dontforget(myinfo,swap,&swap->otherfee,0,triggertxid);
    else if ( rawtx == &swap->bobdeposit )
    {
        basilisk_dontforget(myinfo,swap,&swap->bobdeposit,0,triggertxid);
        basilisk_dontforget(myinfo,swap,&swap->bobrefund,swap->bobdeposit.I.locktime,triggertxid);
    }
    else if ( rawtx == &swap->bobrefund )
        basilisk_dontforget(myinfo,swap,&swap->bobrefund,swap->bobdeposit.I.locktime,triggertxid);
    else if ( rawtx == &swap->aliceclaim )
    {
        basilisk_dontforget(myinfo,swap,&swap->bobrefund,0,triggertxid);
        basilisk_dontforget(myinfo,swap,&swap->aliceclaim,0,swap->bobrefund.I.actualtxid);
    }
    else if ( rawtx == &swap->alicepayment )
    {
        basilisk_dontforget(myinfo,swap,&swap->alicepayment,0,swap->bobdeposit.I.actualtxid);
    }
    else if ( rawtx == &swap->bobspend )
    {
        basilisk_dontforget(myinfo,swap,&swap->alicepayment,0,swap->bobdeposit.I.actualtxid);
        basilisk_dontforget(myinfo,swap,&swap->bobspend,0,swap->alicepayment.I.actualtxid);
    }
    else if ( rawtx == &swap->alicereclaim )
    {
        basilisk_dontforget(myinfo,swap,&swap->alicepayment,0,swap->bobdeposit.I.actualtxid);
        basilisk_dontforget(myinfo,swap,&swap->alicereclaim,0,swap->bobrefund.I.actualtxid);
    }
    else if ( rawtx == &swap->bobpayment )
    {
        basilisk_dontforget(myinfo,swap,&swap->bobpayment,0,triggertxid);
        basilisk_dontforget(myinfo,swap,&swap->bobreclaim,swap->bobpayment.I.locktime,triggertxid);
    }
    else if ( rawtx == &swap->alicespend )
    {
        basilisk_dontforget(myinfo,swap,&swap->bobpayment,0,triggertxid);
        basilisk_dontforget(myinfo,swap,&swap->alicespend,0,triggertxid);
    }
    else if ( rawtx == &swap->bobreclaim )
        basilisk_dontforget(myinfo,swap,&swap->bobreclaim,swap->bobpayment.I.locktime,triggertxid);
}

int32_t basilisk_verify_bobdeposit(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    uint8_t userdata[512]; int32_t i,retval,len = 0; static bits256 zero; struct basilisk_swap *swap = ptr;
    if ( basilisk_rawtx_spendscript(swap,swap->bobcoin->longestchain,&swap->bobdeposit,0,data,datalen,0) == 0 )
    {
        swap->bobdeposit.I.signedtxid = basilisk_swap_broadcast(swap->bobdeposit.name,myinfo,swap,swap->bobdeposit.coin,swap->bobdeposit.txbytes,swap->bobdeposit.I.datalen);
        if ( bits256_nonz(swap->bobdeposit.I.signedtxid) != 0 )
            swap->depositunconf = 1;
        basilisk_dontforget_update(myinfo,swap,&swap->bobdeposit);
        len = basilisk_swapuserdata(userdata,zero,1,swap->I.myprivs[0],swap->bobdeposit.redeemscript,swap->bobdeposit.I.redeemlen);
        memcpy(swap->I.userdata_aliceclaim,userdata,len);
        swap->I.userdata_aliceclaimlen = len;
        if ( (retval= basilisk_rawtx_sign(myinfo,swap->bobcoin->longestchain,swap,&swap->aliceclaim,&swap->bobdeposit,swap->I.myprivs[0],0,userdata,len,1)) == 0 )
        {
            for (i=0; i<swap->bobdeposit.I.datalen; i++)
                printf("%02x",swap->bobdeposit.txbytes[i]);
            printf(" <- bobdeposit\n");
            for (i=0; i<swap->aliceclaim.I.datalen; i++)
                printf("%02x",swap->aliceclaim.txbytes[i]);
            printf(" <- aliceclaim\n");
            basilisk_txlog(myinfo,swap,&swap->aliceclaim,swap->I.putduration+swap->I.callduration);
            return(retval);
        }
    }
    printf("error with bobdeposit\n");
    return(-1);
}

int32_t basilisk_bobdeposit_refund(struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t delay)
{
    uint8_t userdata[512]; int32_t i,retval,len = 0; char str[65];
    len = basilisk_swapuserdata(userdata,swap->I.privBn,0,swap->I.myprivs[0],swap->bobdeposit.redeemscript,swap->bobdeposit.I.redeemlen);
    memcpy(swap->I.userdata_bobrefund,userdata,len);
    swap->I.userdata_bobrefundlen = len;
    if ( (retval= basilisk_rawtx_sign(myinfo,swap->bobcoin->longestchain,swap,&swap->bobrefund,&swap->bobdeposit,swap->I.myprivs[0],0,userdata,len,0)) == 0 )
    {
        for (i=0; i<swap->bobrefund.I.datalen; i++)
            printf("%02x",swap->bobrefund.txbytes[i]);
        printf(" <- bobrefund.(%s)\n",bits256_str(str,swap->bobrefund.I.txid));
        basilisk_txlog(myinfo,swap,&swap->bobrefund,delay);
        return(retval);
    }
    return(-1);
}

/*Bob paytx:
 OP_IF
 <now + INSTANTDEX_LOCKTIME> OP_CLTV OP_DROP <bob_pubB1> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY <alice_pubA0> OP_CHECKSIG
 OP_ENDIF*/

int32_t basilisk_bobpayment_reclaim(struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t delay)
{
    uint8_t userdata[512]; int32_t i,retval,len = 0; static bits256 zero;
    printf("basilisk_bobpayment_reclaim\n");
    len = basilisk_swapuserdata(userdata,zero,1,swap->I.myprivs[1],swap->bobpayment.redeemscript,swap->bobpayment.I.redeemlen);
    memcpy(swap->I.userdata_bobreclaim,userdata,len);
    swap->I.userdata_bobreclaimlen = len;
    if ( (retval= basilisk_rawtx_sign(myinfo,swap->bobcoin->longestchain,swap,&swap->bobreclaim,&swap->bobpayment,swap->I.myprivs[1],0,userdata,len,1)) == 0 )
    {
        for (i=0; i<swap->bobreclaim.I.datalen; i++)
            printf("%02x",swap->bobreclaim.txbytes[i]);
        printf(" <- bobreclaim\n");
        basilisk_txlog(myinfo,swap,&swap->bobreclaim,delay);
        return(retval);
    }
    return(-1);
}

int32_t basilisk_verify_bobpaid(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    uint8_t userdata[512]; int32_t i,retval,len = 0; bits256 revAm; struct basilisk_swap *swap = ptr;
    memset(revAm.bytes,0,sizeof(revAm));
    if ( basilisk_rawtx_spendscript(swap,swap->bobcoin->longestchain,&swap->bobpayment,0,data,datalen,0) == 0 )
    {
        swap->bobpayment.I.signedtxid = basilisk_swap_broadcast(swap->bobpayment.name,myinfo,swap,swap->bobpayment.coin,swap->bobpayment.txbytes,swap->bobpayment.I.datalen);
        if ( bits256_nonz(swap->bobpayment.I.signedtxid) != 0 )
            swap->paymentunconf = 1;
        basilisk_dontforget_update(myinfo,swap,&swap->bobpayment);
        for (i=0; i<32; i++)
            revAm.bytes[i] = swap->I.privAm.bytes[31-i];
        len = basilisk_swapuserdata(userdata,revAm,0,swap->I.myprivs[0],swap->bobpayment.redeemscript,swap->bobpayment.I.redeemlen);
        memcpy(swap->I.userdata_alicespend,userdata,len);
        swap->I.userdata_alicespendlen = len;
        char str[65],str2[65]; printf("bobpaid privAm.(%s) myprivs[0].(%s)\n",bits256_str(str,swap->I.privAm),bits256_str(str2,swap->I.myprivs[0]));
        if ( (retval= basilisk_rawtx_sign(myinfo,swap->bobcoin->longestchain,swap,&swap->alicespend,&swap->bobpayment,swap->I.myprivs[0],0,userdata,len,1)) == 0 )
        {
            for (i=0; i<swap->bobpayment.I.datalen; i++)
                printf("%02x",swap->bobpayment.txbytes[i]);
            printf(" <- bobpayment\n");
            for (i=0; i<swap->alicespend.I.datalen; i++)
                printf("%02x",swap->alicespend.txbytes[i]);
            printf(" <- alicespend\n\n");
            swap->I.alicespent = 1;
            basilisk_txlog(myinfo,swap,&swap->alicespend,-1);
            return(retval);
        }
    }
    return(-1);
}

void basilisk_alicepayment(struct supernet_info *myinfo,struct basilisk_swap *swap,struct iguana_info *coin,struct basilisk_rawtx *alicepayment,bits256 pubAm,bits256 pubBn)
{
    alicepayment->I.spendlen = basilisk_alicescript(alicepayment->redeemscript,&alicepayment->I.redeemlen,alicepayment->spendscript,0,alicepayment->I.destaddr,coin->chain->p2shtype,pubAm,pubBn);
    basilisk_rawtx_gen("alicepayment",myinfo,swap->I.started,swap->persistent_pubkey33,0,1,alicepayment,alicepayment->I.locktime,alicepayment->spendscript,alicepayment->I.spendlen,coin->chain->txfee,1,0);
}

int32_t basilisk_alicepayment_spend(struct supernet_info *myinfo,struct basilisk_swap *swap,struct basilisk_rawtx *dest)
{
    int32_t i,retval;
    printf("alicepayment_spend\n");
    swap->alicepayment.I.spendlen = basilisk_alicescript(swap->alicepayment.redeemscript,&swap->alicepayment.I.redeemlen,swap->alicepayment.spendscript,0,swap->alicepayment.I.destaddr,swap->alicecoin->chain->p2shtype,swap->I.pubAm,swap->I.pubBn);
    printf("alicepayment_spend len.%d\n",swap->alicepayment.I.spendlen);
    if ( swap->I.iambob == 0 )
    {
        memcpy(swap->I.userdata_alicereclaim,swap->alicepayment.redeemscript,swap->alicepayment.I.spendlen);
        swap->I.userdata_alicereclaimlen = swap->alicepayment.I.spendlen;
    }
    else
    {
        memcpy(swap->I.userdata_bobspend,swap->alicepayment.redeemscript,swap->alicepayment.I.spendlen);
        swap->I.userdata_bobspendlen = swap->alicepayment.I.spendlen;
    }
    if ( (retval= basilisk_rawtx_sign(myinfo,swap->alicecoin->longestchain,swap,dest,&swap->alicepayment,swap->I.privAm,&swap->I.privBn,0,0,1)) == 0 )
    {
        for (i=0; i<dest->I.datalen; i++)
            printf("%02x",dest->txbytes[i]);
        printf(" <- msigspend\n\n");
        if ( dest == &swap->bobspend )
            swap->I.bobspent = 1;
        basilisk_txlog(myinfo,swap,dest,0); // bobspend or alicereclaim
        return(retval);
    }
    return(-1);
}

int32_t basilisk_verify_alicepaid(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    struct basilisk_swap *swap = ptr;
    if ( basilisk_rawtx_spendscript(swap,swap->alicecoin->longestchain,&swap->alicepayment,0,data,datalen,0) == 0 )
    {
        swap->alicepayment.I.signedtxid = basilisk_swap_broadcast(swap->alicepayment.name,myinfo,swap,swap->alicepayment.coin,swap->alicepayment.txbytes,swap->alicepayment.I.datalen);
        if ( bits256_nonz(swap->alicepayment.I.signedtxid) != 0 )
            swap->aliceunconf = 1;
        basilisk_dontforget_update(myinfo,swap,&swap->alicepayment);
        return(0);
    }
    else return(-1);
}

int32_t basilisk_verify_pubpair(int32_t *wrongfirstbytep,struct basilisk_swap *swap,int32_t ind,uint8_t pub0,bits256 pubi,uint64_t txid)
{
    if ( pub0 != (swap->I.iambob ^ 1) + 0x02 )
    {
        (*wrongfirstbytep)++;
        printf("wrongfirstbyte[%d] %02x\n",ind,pub0);
        return(-1);
    }
    else if ( swap->otherdeck[ind][1] != pubi.txid )
    {
        printf("otherdeck[%d] priv ->pub mismatch %llx != %llx\n",ind,(long long)swap->otherdeck[ind][1],(long long)pubi.txid);
        return(-1);
    }
    else if ( swap->otherdeck[ind][0] != txid )
    {
        printf("otherdeck[%d] priv mismatch %llx != %llx\n",ind,(long long)swap->otherdeck[ind][0],(long long)txid);
        return(-1);
    }
    return(0);
}

int32_t basilisk_bobscripts_set(struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t depositflag,int32_t genflag)
{
    int32_t i,j; //char str[65];
    if ( genflag != 0 && swap->I.iambob == 0 )
        printf("basilisk_bobscripts_set WARNING: alice generating BOB tx\n");
    if ( depositflag == 0 )
    {
        swap->bobpayment.I.spendlen = basilisk_bobscript(swap->bobpayment.I.rmd160,swap->bobpayment.redeemscript,&swap->bobpayment.I.redeemlen,swap->bobpayment.spendscript,0,&swap->bobpayment.I.locktime,&swap->bobpayment.I.secretstart,&swap->I,0);
        bitcoin_address(swap->bobpayment.p2shaddr,swap->bobcoin->chain->p2shtype,swap->bobpayment.redeemscript,swap->bobpayment.I.redeemlen);
        //for (i=0; i<swap->bobpayment.redeemlen; i++)
        //    printf("%02x",swap->bobpayment.redeemscript[i]);
        //printf(" <- bobpayment.%d\n",i);
        if ( genflag != 0 && bits256_nonz(*(bits256 *)swap->I.secretBn256) != 0 && swap->bobpayment.I.datalen == 0 )
        {
            for (i=0; i<3; i++)
            {
                //if ( swap->bobpayment.txbytes != 0 && swap->bobpayment.I.spendlen != 0 )
                //    break;
                basilisk_rawtx_gen("payment",myinfo,swap->I.started,swap->persistent_pubkey33,1,1,&swap->bobpayment,swap->bobpayment.I.locktime,swap->bobpayment.spendscript,swap->bobpayment.I.spendlen,swap->bobpayment.coin->chain->txfee,1,0);
                if ( swap->bobpayment.I.spendlen == 0 || swap->bobpayment.I.datalen == 0 )
                {
                    printf("error bob generating %p payment.%d\n",swap->bobpayment.txbytes,swap->bobpayment.I.spendlen);
                    sleep(DEX_SLEEP);
                }
                else
                {
                    for (j=0; j<swap->bobpayment.I.datalen; j++)
                        printf("%02x",swap->bobpayment.txbytes[j]);
                    //printf(" <- bobpayment.%d\n",swap->bobpayment.datalen);
                    //for (j=0; j<swap->bobpayment.redeemlen; j++)
                    //    printf("%02x",swap->bobpayment.redeemscript[j]);
                    //printf(" <- redeem.%d\n",swap->bobpayment.redeemlen);
                    printf(" <- GENERATED BOB PAYMENT.%d\n",swap->bobpayment.I.datalen);
                    iguana_unspents_mark(myinfo,swap->bobcoin,swap->bobpayment.vins);
                    basilisk_bobpayment_reclaim(myinfo,swap,swap->I.callduration);
                    printf("bobscripts set completed\n");
                    return(0);
                }
            }
        }
    }
    else
    {
        swap->bobdeposit.I.spendlen = basilisk_bobscript(swap->bobdeposit.I.rmd160,swap->bobdeposit.redeemscript,&swap->bobdeposit.I.redeemlen,swap->bobdeposit.spendscript,0,&swap->bobdeposit.I.locktime,&swap->bobdeposit.I.secretstart,&swap->I,1);
        bitcoin_address(swap->bobdeposit.p2shaddr,swap->bobcoin->chain->p2shtype,swap->bobdeposit.redeemscript,swap->bobdeposit.I.redeemlen);
        if ( genflag != 0 && (swap->bobdeposit.I.datalen == 0 || swap->bobrefund.I.datalen == 0) )
        {
            for (i=0; i<3; i++)
            {
                //if ( swap->bobdeposit.txbytes != 0 && swap->bobdeposit.I.spendlen != 0 )
                //    break;
                basilisk_rawtx_gen("deposit",myinfo,swap->I.started,swap->persistent_pubkey33,1,1,&swap->bobdeposit,swap->bobdeposit.I.locktime,swap->bobdeposit.spendscript,swap->bobdeposit.I.spendlen,swap->bobdeposit.coin->chain->txfee,1,0);
                if ( swap->bobdeposit.I.datalen == 0 || swap->bobdeposit.I.spendlen == 0 )
                {
                    printf("error bob generating %p deposit.%d\n",swap->bobdeposit.txbytes,swap->bobdeposit.I.spendlen);
                    sleep(DEX_SLEEP);
                }
                else
                {
                    for (j=0; j<swap->bobdeposit.I.datalen; j++)
                        printf("%02x",swap->bobdeposit.txbytes[j]);
                    printf(" <- GENERATED BOB DEPOSIT.%d\n",swap->bobdeposit.I.datalen);
                    //for (j=0; j<swap->bobdeposit.redeemlen; j++)
                    //    printf("%02x",swap->bobdeposit.redeemscript[j]);
                    //printf(" <- redeem.%d\n",swap->bobdeposit.redeemlen);
                    //printf("GENERATED BOB DEPOSIT\n");
                    iguana_unspents_mark(myinfo,swap->bobcoin,swap->bobdeposit.vins);
                    basilisk_bobdeposit_refund(myinfo,swap,swap->I.putduration);
                    printf("bobscripts set completed\n");
                    return(0);
                }
            }
        }
        //for (i=0; i<swap->bobdeposit.redeemlen; i++)
        //    printf("%02x",swap->bobdeposit.redeemscript[i]);
        //printf(" <- bobdeposit.%d\n",i);
    }
    return(0);
}

int32_t basilisk_verify_privi(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t j,wrongfirstbyte,len = 0; bits256 privkey,pubi; char str[65],str2[65]; uint8_t secret160[20],pubkey33[33]; uint64_t txid; struct basilisk_swap *swap = ptr;
    memset(privkey.bytes,0,sizeof(privkey));
    if ( datalen == sizeof(bits256) )
    {
        for (j=0; j<32; j++)
            privkey.bytes[j] = data[len++];
        revcalc_rmd160_sha256(secret160,privkey);//.bytes,sizeof(privkey));
        memcpy(&txid,secret160,sizeof(txid));
        pubi = bitcoin_pubkey33(myinfo->ctx,pubkey33,privkey);
        if ( basilisk_verify_pubpair(&wrongfirstbyte,swap,swap->I.choosei,pubkey33[0],pubi,txid) == 0 )
        {
            if ( swap->I.iambob != 0 )
            {
                swap->I.privAm = privkey;
                vcalc_sha256(0,swap->I.secretAm256,privkey.bytes,sizeof(privkey));
                printf("set privAm.%s %s\n",bits256_str(str,swap->I.privAm),bits256_str(str2,*(bits256 *)swap->I.secretAm256));
                basilisk_bobscripts_set(myinfo,swap,0,1);
            }
            else
            {
                swap->I.privBn = privkey;
                vcalc_sha256(0,swap->I.secretBn256,privkey.bytes,sizeof(privkey));
                printf("set privBn.%s %s\n",bits256_str(str,swap->I.privBn),bits256_str(str2,*(bits256 *)swap->I.secretBn256));
            }
            basilisk_dontforget_update(myinfo,swap,0);
            char str[65]; printf("privi verified.(%s)\n",bits256_str(str,privkey));
            return(0);
        }
    }
    return(-1);
}

int32_t basilisk_process_swapverify(struct supernet_info *myinfo,void *ptr,int32_t (*internal_func)(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen),uint32_t channel,uint32_t msgid,uint8_t *data,int32_t datalen,uint32_t expiration,uint32_t duration)
{
    struct basilisk_swap *swap = ptr;
    if ( internal_func != 0 )
        return((*internal_func)(myinfo,swap,data,datalen));
    else return(0);
}

void basilisk_swapgotdata(struct supernet_info *myinfo,struct basilisk_swap *swap,uint32_t crc32,bits256 srchash,bits256 desthash,uint32_t quoteid,uint32_t msgbits,uint8_t *data,int32_t datalen,int32_t reinit)
{
    int32_t i; struct basilisk_swapmessage *mp;
    for (i=0; i<swap->nummessages; i++)
        if ( crc32 == swap->messages[i].crc32 && msgbits == swap->messages[i].msgbits && bits256_cmp(srchash,swap->messages[i].srchash) == 0 && bits256_cmp(desthash,swap->messages[i].desthash) == 0 )
            return;
    //printf(" new message.[%d] datalen.%d Q.%x msg.%x [%llx]\n",swap->nummessages,datalen,quoteid,msgbits,*(long long *)data);
    swap->messages = realloc(swap->messages,sizeof(*swap->messages) * (swap->nummessages + 1));
    mp = &swap->messages[swap->nummessages++];
    mp->crc32 = crc32;
    mp->srchash = srchash;
    mp->desthash = desthash;
    mp->msgbits = msgbits;
    mp->quoteid = quoteid;
    mp->data = malloc(datalen);
    mp->datalen = datalen;
    memcpy(mp->data,data,datalen);
    if ( reinit == 0 && swap->fp != 0 )
    {
        fwrite(mp,1,sizeof(*mp),swap->fp);
        fwrite(data,1,datalen,swap->fp);
        fflush(swap->fp);
    }
}

FILE *basilisk_swap_save(struct supernet_info *myinfo,struct basilisk_swap *swap,bits256 privkey,struct basilisk_request *rp,uint32_t statebits,int32_t optionduration,int32_t reinit)
{
    FILE *fp=0; /*char fname[512];
    sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,rp->requestid,rp->quoteid), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"rb+")) == 0 )
    {
        if ( (fp= fopen(fname,"wb+")) != 0 )
        {
            fwrite(privkey.bytes,1,sizeof(privkey),fp);
            fwrite(rp,1,sizeof(*rp),fp);
            fwrite(&statebits,1,sizeof(statebits),fp);
            fwrite(&optionduration,1,sizeof(optionduration),fp);
            fflush(fp);
        }
    }
    else if ( reinit != 0 )
    {
    }*/
    return(fp);
}

int32_t basilisk_swap_load(uint32_t requestid,uint32_t quoteid,bits256 *privkeyp,struct basilisk_request *rp,uint32_t *statebitsp,int32_t *optiondurationp)
{
    FILE *fp=0; char fname[512]; int32_t retval = -1;
    sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"rb+")) != 0 )
    {
        if ( fread(privkeyp,1,sizeof(*privkeyp),fp) == sizeof(*privkeyp) &&
            fread(rp,1,sizeof(*rp),fp) == sizeof(*rp) &&
            fread(statebitsp,1,sizeof(*statebitsp),fp) == sizeof(*statebitsp) &&
            fread(optiondurationp,1,sizeof(*optiondurationp),fp) == sizeof(*optiondurationp) )
            retval = 0;
        fclose(fp);
    }
    return(retval);
}

struct basilisk_swap *basilisk_thread_start(struct supernet_info *myinfo,bits256 privkey,struct basilisk_request *rp,uint32_t statebits,int32_t optionduration,int32_t reinit);

void basilisk_swaps_init(struct supernet_info *myinfo)
{
    char fname[512]; uint32_t iter,swapcompleted,requestid,quoteid,optionduration,statebits; FILE *fp; bits256 privkey;struct basilisk_request R; struct basilisk_swapmessage M; struct basilisk_swap *swap = 0;
    sprintf(fname,"%s/SWAPS/list",GLOBAL_DBDIR), OS_compatible_path(fname);
    if ( (myinfo->swapsfp= fopen(fname,"rb+")) != 0 )
    {
        while ( fread(&requestid,1,sizeof(requestid),myinfo->swapsfp) == sizeof(requestid) && fread(&quoteid,1,sizeof(quoteid),myinfo->swapsfp) == sizeof(quoteid) )
        {
            sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
            printf("%s\n",fname);
            if ( (fp= fopen(fname,"rb+")) != 0 ) // check to see if completed
            {
                memset(&M,0,sizeof(M));
                swapcompleted = 1;
                for (iter=0; iter<2; iter++)
                {
                    if ( fread(privkey.bytes,1,sizeof(privkey),fp) == sizeof(privkey) &&
                            fread(&R,1,sizeof(R),fp) == sizeof(R) &&
                            fread(&statebits,1,sizeof(statebits),fp) == sizeof(statebits) &&
                            fread(&optionduration,1,sizeof(optionduration),fp) == sizeof(optionduration) )
                    {
                        while ( 0 && fread(&M,1,sizeof(M),fp) == sizeof(M) )
                        {
                            M.data = 0;
                            //printf("entry iter.%d crc32.%x datalen.%d\n",iter,M.crc32,M.datalen);
                            if ( M.datalen < 100000 )
                            {
                                M.data = malloc(M.datalen);
                                if ( fread(M.data,1,M.datalen,fp) == M.datalen )
                                {
                                    if ( calc_crc32(0,M.data,M.datalen) == M.crc32 )
                                    {
                                        if ( iter == 1 )
                                        {
                                            if ( swap == 0 )
                                            {
                                                swap = basilisk_thread_start(myinfo,privkey,&R,statebits,optionduration,1);
                                                swap->I.choosei = swap->I.otherchoosei = -1;
                                            }
                                            if ( swap != 0 )
                                                basilisk_swapgotdata(myinfo,swap,M.crc32,M.srchash,M.desthash,M.quoteid,M.msgbits,M.data,M.datalen,1);
                                        }
                                    } else printf("crc mismatch %x vs %x\n",calc_crc32(0,M.data,M.datalen),M.crc32);
                                } else printf("error reading M.datalen %d\n",M.datalen);
                                free(M.data), M.data = 0;
                            }
                        }
                    }
                    if ( swapcompleted != 0 )
                        break;
                    rewind(fp);
                }
            }
        }
    } else myinfo->swapsfp = fopen(fname,"wb+");
}

void basilisk_psockinit(struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t amlp);

int32_t basilisk_swapget(struct supernet_info *myinfo,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t maxlen,int32_t (*basilisk_verify_func)(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen))
{
    uint8_t *ptr; bits256 srchash,desthash; uint32_t crc32,_msgbits,quoteid; int32_t i,size,offset,retval = -1; struct basilisk_swapmessage *mp = 0;
    while ( (size= nn_recv(swap->subsock,&ptr,NN_MSG,0)) >= 0 )
    {
        swap->lasttime = (uint32_t)time(NULL);
        memset(srchash.bytes,0,sizeof(srchash));
        memset(desthash.bytes,0,sizeof(desthash));
        //printf("gotmsg.[%d] crc.%x\n",size,crc32);
        offset = 0;
        for (i=0; i<32; i++)
             srchash.bytes[i] = ptr[offset++];
        for (i=0; i<32; i++)
            desthash.bytes[i] = ptr[offset++];
        offset += iguana_rwnum(0,&ptr[offset],sizeof(uint32_t),&quoteid);
        offset += iguana_rwnum(0,&ptr[offset],sizeof(uint32_t),&_msgbits);
        if ( size > offset )
        {
            crc32 = calc_crc32(0,&ptr[offset],size-offset);
            if ( size > offset )
            {
                //printf("size.%d offset.%d datalen.%d\n",size,offset,size-offset);
                basilisk_swapgotdata(myinfo,swap,crc32,srchash,desthash,quoteid,_msgbits,&ptr[offset],size-offset,0);
            }
        }
        else if ( bits256_nonz(srchash) == 0 && bits256_nonz(desthash) == 0 )
        {
            if ( swap->aborted == 0 )
            {
                swap->aborted = (uint32_t)time(NULL);
                printf("got abort signal from other side\n");
            }
        } else printf("basilisk_swapget: got strange packet\n");
        if ( ptr != 0 )
            nn_freemsg(ptr), ptr = 0;
    }
    //char str[65],str2[65];
    for (i=0; i<swap->nummessages; i++)
    {
        //printf("%d: %s vs %s\n",i,bits256_str(str,swap->messages[i].srchash),bits256_str(str2,swap->messages[i].desthash));
        if ( bits256_cmp(swap->messages[i].desthash,swap->I.myhash) == 0 )
        {
            if ( swap->messages[i].msgbits == msgbits )
            {
                if ( swap->I.iambob == 0 && swap->lasttime != 0 && time(NULL) > swap->lasttime+360 )
                {
                    printf("nothing received for a while from Bob, try new sockets\n");
                    if ( swap->pushsock >= 0 ) //
                        nn_close(swap->pushsock), swap->pushsock = -1;
                    if ( swap->subsock >= 0 ) //
                        nn_close(swap->subsock), swap->subsock = -1;
                    swap->connected = 0;
                    basilisk_psockinit(myinfo,swap,swap->I.iambob != 0);
                }
                mp = &swap->messages[i];
                if ( msgbits != 0x80000000 )
                    break;
            }
        }
    }
    if ( mp != 0 )
        retval = (*basilisk_verify_func)(myinfo,swap,mp->data,mp->datalen);
    //printf("mine/other %s vs %s\n",bits256_str(str,swap->I.myhash),bits256_str(str2,swap->I.otherhash));
    return(retval);
}

uint32_t basilisk_swapsend(struct supernet_info *myinfo,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t datalen,uint32_t nextbits,uint32_t crcs[2])
{
    uint8_t *buf; int32_t sentbytes,offset=0,i;
    buf = malloc(datalen + sizeof(msgbits) + sizeof(swap->I.req.quoteid) + sizeof(bits256)*2);
    for (i=0; i<32; i++)
        buf[offset++] = swap->I.myhash.bytes[i];
    for (i=0; i<32; i++)
        buf[offset++] = swap->I.otherhash.bytes[i];
    offset += iguana_rwnum(1,&buf[offset],sizeof(swap->I.req.quoteid),&swap->I.req.quoteid);
    offset += iguana_rwnum(1,&buf[offset],sizeof(msgbits),&msgbits);
    if ( datalen > 0 )
        memcpy(&buf[offset],data,datalen), offset += datalen;
    if ( (sentbytes= nn_send(swap->pushsock,buf,offset,0)) != offset )
    {
        printf("sentbytes.%d vs offset.%d\n",sentbytes,offset);
        if ( sentbytes < 0 )
        {
            if ( swap->pushsock >= 0 )
                nn_close(swap->pushsock), swap->pushsock = -1; //,
            if ( swap->subsock >= 0 ) //
                nn_close(swap->subsock), swap->subsock = -1;
            swap->connected = swap->I.iambob != 0 ? -1 : 0;
            swap->aborted = (uint32_t)time(NULL);
        }
    }
    //else printf("send.[%d] %x offset.%d datalen.%d [%llx]\n",sentbytes,msgbits,offset,datalen,*(long long *)data);
    free(buf);
    return(nextbits);
}

void basilisk_swap_sendabort(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    uint32_t msgbits = 0; uint8_t buf[sizeof(msgbits) + sizeof(swap->I.req.quoteid) + sizeof(bits256)*2]; int32_t sentbytes,offset=0;
    memset(buf,0,sizeof(buf));
    offset += iguana_rwnum(1,&buf[offset],sizeof(swap->I.req.quoteid),&swap->I.req.quoteid);
    offset += iguana_rwnum(1,&buf[offset],sizeof(msgbits),&msgbits);
    if ( (sentbytes= nn_send(swap->pushsock,buf,offset,0)) != offset )
    {
        if ( sentbytes < 0 )
        {
            if ( swap->pushsock >= 0 ) //
                nn_close(swap->pushsock), swap->pushsock = -1;
            if ( swap->subsock >= 0 ) //
                nn_close(swap->subsock), swap->subsock = -1;
            swap->connected = 0;
        }
    } else printf("basilisk_swap_sendabort\n");
}

int32_t basilisk_privBn_extract(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    if ( basilisk_priviextract(myinfo,swap->bobcoin,"privBn",&swap->I.privBn,swap->I.secretBn,swap->bobrefund.I.actualtxid,0) == 0 )
    {
        printf("extracted privBn from blockchain\n");
    }
    else if ( basilisk_swapget(myinfo,swap,0x40000000,data,maxlen,basilisk_verify_privi) == 0 )
    {
    }
    if ( bits256_nonz(swap->I.privBn) != 0 && swap->alicereclaim.I.datalen == 0 )
    {
        char str[65]; printf("got privBn.%s\n",bits256_str(str,swap->I.privBn));
        return(basilisk_alicepayment_spend(myinfo,swap,&swap->alicereclaim));
    }
    return(-1);
}

int32_t basilisk_privAm_extract(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    if ( basilisk_priviextract(myinfo,swap->bobcoin,"privAm",&swap->I.privAm,swap->I.secretAm,swap->bobpayment.I.actualtxid,0) == 0 )
    {
        printf("extracted privAm from blockchain\n");
    }
    if ( bits256_nonz(swap->I.privAm) != 0 && swap->bobspend.I.datalen == 0 )
    {
        char str[65]; printf("got privAm.%s\n",bits256_str(str,swap->I.privAm));
        return(basilisk_alicepayment_spend(myinfo,swap,&swap->bobspend));
    }
    return(-1);
}

bits256 instantdex_derivekeypair(void *ctx,bits256 *newprivp,uint8_t pubkey[33],bits256 privkey,bits256 orderhash)
{
    bits256 sharedsecret;
    sharedsecret = curve25519_shared(privkey,orderhash);
    vcalc_sha256cat(newprivp->bytes,orderhash.bytes,sizeof(orderhash),sharedsecret.bytes,sizeof(sharedsecret));
    return(bitcoin_pubkey33(ctx,pubkey,*newprivp));
}

int32_t instantdex_pubkeyargs(void *ctx,struct basilisk_swap *swap,int32_t numpubs,bits256 privkey,bits256 hash,int32_t firstbyte)
{
    char buf[3]; int32_t i,n,m,len=0; bits256 pubi,reveal; uint64_t txid; uint8_t secret160[20],pubkey[33];
    sprintf(buf,"%c0",'A' - 0x02 + firstbyte);
    if ( numpubs > 2 )
    {
        if ( swap->I.numpubs+2 >= numpubs )
            return(numpubs);
        //fprintf(stderr,">>>>>> start generating %s\n",buf);
    }
    for (i=n=m=0; i<numpubs*100 && n<numpubs; i++)
    {
        pubi = instantdex_derivekeypair(ctx,&privkey,pubkey,privkey,hash);
        //fprintf(stderr,"i.%d n.%d numpubs.%d %02x vs %02x\n",i,n,numpubs,pubkey[0],firstbyte);
        if ( pubkey[0] != firstbyte )
            continue;
        if ( n < 2 )
        {
            if ( bits256_nonz(swap->I.mypubs[n]) == 0 )
            {
                swap->I.myprivs[n] = privkey;
                memcpy(swap->I.mypubs[n].bytes,pubkey+1,sizeof(bits256));
                reveal = basilisk_revealkey(privkey,swap->I.mypubs[n]);
                if ( swap->I.iambob != 0 )
                {
                    if ( n == 0 )
                        swap->I.pubB0 = reveal;
                    else if ( n == 1 )
                        swap->I.pubB1 = reveal;
                }
                else if ( swap->I.iambob == 0 )
                {
                    if ( n == 0 )
                        swap->I.pubA0 = reveal;
                    else if ( n == 1 )
                        swap->I.pubA1 = reveal;
                }
            }
        }
        if ( m < INSTANTDEX_DECKSIZE )
        {
            swap->privkeys[m] = privkey;
            revcalc_rmd160_sha256(secret160,privkey);//.bytes,sizeof(privkey));
            memcpy(&txid,secret160,sizeof(txid));
            len += iguana_rwnum(1,(uint8_t *)&swap->deck[m][0],sizeof(txid),&txid);
            len += iguana_rwnum(1,(uint8_t *)&swap->deck[m][1],sizeof(pubi.txid),&pubi.txid);
            m++;
            if ( m > swap->I.numpubs )
                swap->I.numpubs = m;
        }
        n++;
    }
    if ( n > 2 || m > 2 )
        printf("n.%d m.%d len.%d numpubs.%d\n",n,m,len,swap->I.numpubs);
    return(n);
}

void basilisk_rawtx_setparms(char *name,uint32_t quoteid,struct basilisk_rawtx *rawtx,struct iguana_info *coin,int32_t numconfirms,int32_t vintype,uint64_t satoshis,int32_t vouttype,uint8_t *pubkey33,int32_t jumblrflag)
{
    strcpy(rawtx->name,name);
    rawtx->coin = coin;
    strcpy(rawtx->I.coinstr,coin->symbol);
    rawtx->I.numconfirms = numconfirms;
    if ( (rawtx->I.amount= satoshis) < 50000 )
        rawtx->I.amount = 50000;
    rawtx->I.vintype = vintype; // 0 -> std, 2 -> 2of2, 3 -> spend bobpayment, 4 -> spend bobdeposit
    rawtx->I.vouttype = vouttype; // 0 -> fee, 1 -> std, 2 -> 2of2, 3 -> bobpayment, 4 -> bobdeposit
    if ( rawtx->I.vouttype == 0 )
    {
        if ( strcmp(coin->symbol,"BTC") == 0 && (quoteid % 10) == 0 )
            decode_hex(rawtx->I.rmd160,20,TIERNOLAN_RMD160);
        else decode_hex(rawtx->I.rmd160,20,INSTANTDEX_RMD160);
        bitcoin_address(rawtx->I.destaddr,rawtx->coin->chain->pubtype,rawtx->I.rmd160,20);
    }
    if ( pubkey33 != 0 )
    {
        memcpy(rawtx->I.pubkey33,pubkey33,33);
        bitcoin_address(rawtx->I.destaddr,rawtx->coin->chain->pubtype,rawtx->I.pubkey33,33);
        bitcoin_addr2rmd160(&rawtx->I.addrtype,rawtx->I.rmd160,rawtx->I.destaddr);
    }
    if ( rawtx->I.vouttype <= 1 && rawtx->I.destaddr[0] != 0 )
    {
        rawtx->I.spendlen = bitcoin_standardspend(rawtx->spendscript,0,rawtx->I.rmd160);
        printf("%s spendlen.%d %s <- %.8f\n",name,rawtx->I.spendlen,rawtx->I.destaddr,dstr(rawtx->I.amount));
    } else printf("%s vouttype.%d destaddr.(%s)\n",name,rawtx->I.vouttype,rawtx->I.destaddr);
}

int32_t bitcoin_coinptrs(bits256 pubkey,struct iguana_info **bobcoinp,struct iguana_info **alicecoinp,char *src,char *dest,bits256 srchash,bits256 desthash)
{
    struct iguana_info *coin = iguana_coinfind(src);
    if ( coin == 0 || iguana_coinfind(dest) == 0 )
        return(0);
    *bobcoinp = *alicecoinp = 0;
    *bobcoinp = iguana_coinfind(dest);
    *alicecoinp = iguana_coinfind(src);
    if ( bits256_cmp(pubkey,srchash) == 0 )
    {
        if ( strcmp(src,(*bobcoinp)->symbol) == 0 )
            return(1);
        else if ( strcmp(dest,(*alicecoinp)->symbol) == 0 )
            return(-1);
        else return(0);
    }
    else if ( bits256_cmp(pubkey,desthash) == 0 )
    {
        if ( strcmp(src,(*bobcoinp)->symbol) == 0 )
            return(-1);
        else if ( strcmp(dest,(*alicecoinp)->symbol) == 0 )
            return(1);
        else return(0);
    }
    return(0);
}

void basilisk_swap_saveupdate(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    FILE *fp; char fname[512];
    sprintf(fname,"%s/SWAPS/%u-%u.swap",GLOBAL_DBDIR,swap->I.req.requestid,swap->I.req.quoteid), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"wb")) != 0 )
    {
        fwrite(&swap->I,1,sizeof(swap->I),fp);
        /*fwrite(&swap->bobdeposit,1,sizeof(swap->bobdeposit),fp);
        fwrite(&swap->bobpayment,1,sizeof(swap->bobpayment),fp);
        fwrite(&swap->alicepayment,1,sizeof(swap->alicepayment),fp);
        fwrite(&swap->myfee,1,sizeof(swap->myfee),fp);
        fwrite(&swap->otherfee,1,sizeof(swap->otherfee),fp);
        fwrite(&swap->aliceclaim,1,sizeof(swap->aliceclaim),fp);
        fwrite(&swap->alicespend,1,sizeof(swap->alicespend),fp);
        fwrite(&swap->bobreclaim,1,sizeof(swap->bobreclaim),fp);
        fwrite(&swap->bobspend,1,sizeof(swap->bobspend),fp);
        fwrite(&swap->bobrefund,1,sizeof(swap->bobrefund),fp);
        fwrite(&swap->alicereclaim,1,sizeof(swap->alicereclaim),fp);*/
        fwrite(swap->privkeys,1,sizeof(swap->privkeys),fp);
        fwrite(swap->otherdeck,1,sizeof(swap->otherdeck),fp);
        fwrite(swap->deck,1,sizeof(swap->deck),fp);
        fclose(fp);
    }
}

int32_t basilisk_swap_loadtx(struct basilisk_rawtx *rawtx,FILE *fp,char *bobcoinstr,char *alicecoinstr)
{
    if ( fread(rawtx,1,sizeof(*rawtx),fp) == sizeof(*rawtx) )
    {
        rawtx->coin = 0;
        rawtx->vins = 0;
        if ( strcmp(rawtx->I.coinstr,bobcoinstr) == 0 || strcmp(rawtx->I.coinstr,alicecoinstr) == 0 )
        {
            rawtx->coin = iguana_coinfind(rawtx->I.coinstr);
            if ( rawtx->vinstr[0] != 0 )
                rawtx->vins = cJSON_Parse(rawtx->vinstr);
            printf("loaded.%s len.%d\n",rawtx->name,rawtx->I.datalen);
            return(0);
        }
    }
    return(-1);
}

struct basilisk_swap *bitcoin_swapinit(struct supernet_info *myinfo,bits256 privkey,uint8_t *pubkey33,bits256 pubkey25519,struct basilisk_swap *swap,int32_t optionduration,uint32_t statebits,int32_t reinit)
{
    FILE *fp; char fname[512]; uint8_t *alicepub33=0,*bobpub33=0; int32_t errs=0,jumblrflag,x = -1;
    if ( reinit != 0 )
    {
        sprintf(fname,"%s/SWAPS/%u-%u.swap",GLOBAL_DBDIR,swap->I.req.requestid,swap->I.req.quoteid), OS_compatible_path(fname);
        printf("reinit.(%s)\n",fname);
        if ( (fp= fopen(fname,"rb")) != 0 )
        {
            if ( fread(&swap->I,1,sizeof(swap->I),fp) != sizeof(swap->I) )
                errs++;
            if ( swap->bobcoin == 0 )
                swap->bobcoin = iguana_coinfind(swap->I.req.dest);
            if ( swap->alicecoin == 0 )
                swap->alicecoin = iguana_coinfind(swap->I.req.src);
            if ( swap->alicecoin != 0 && swap->bobcoin != 0 )
            {
                /*basilisk_swap_loadtx(&swap->bobdeposit,fp,swap->bobcoin->symbol,swap->alicecoin->symbol);
                basilisk_swap_loadtx(&swap->bobpayment,fp,swap->bobcoin->symbol,swap->alicecoin->symbol);
                basilisk_swap_loadtx(&swap->alicepayment,fp,swap->bobcoin->symbol,swap->alicecoin->symbol);
                basilisk_swap_loadtx(&swap->myfee,fp,swap->bobcoin->symbol,swap->alicecoin->symbol);
                basilisk_swap_loadtx(&swap->otherfee,fp,swap->bobcoin->symbol,swap->alicecoin->symbol);
                basilisk_swap_loadtx(&swap->aliceclaim,fp,swap->bobcoin->symbol,swap->alicecoin->symbol);
                basilisk_swap_loadtx(&swap->alicespend,fp,swap->bobcoin->symbol,swap->alicecoin->symbol);
                basilisk_swap_loadtx(&swap->bobreclaim,fp,swap->bobcoin->symbol,swap->alicecoin->symbol);
                basilisk_swap_loadtx(&swap->bobspend,fp,swap->bobcoin->symbol,swap->alicecoin->symbol);
                basilisk_swap_loadtx(&swap->bobrefund,fp,swap->bobcoin->symbol,swap->alicecoin->symbol);
                basilisk_swap_loadtx(&swap->alicereclaim,fp,swap->bobcoin->symbol,swap->alicecoin->symbol);*/
            } else printf("missing coins (%p %p)\n",swap->bobcoin,swap->alicecoin);
            if ( fread(swap->privkeys,1,sizeof(swap->privkeys),fp) != sizeof(swap->privkeys) )
                errs++;
            if ( fread(swap->otherdeck,1,sizeof(swap->otherdeck),fp) != sizeof(swap->otherdeck) )
                errs++;
            if ( fread(swap->deck,1,sizeof(swap->deck),fp) != sizeof(swap->deck) )
                errs++;
            fclose(fp);
        } else printf("cant find.(%s)\n",fname);
    }
    else
    {
        swap->I.putduration = swap->I.callduration = INSTANTDEX_LOCKTIME;
        if ( optionduration < 0 )
            swap->I.putduration -= optionduration;
        else if ( optionduration > 0 )
            swap->I.callduration += optionduration;
        swap->I.bobsatoshis = swap->I.req.destamount;
        swap->I.alicesatoshis = swap->I.req.srcamount;
        if ( (swap->I.bobinsurance= (swap->I.bobsatoshis / INSTANTDEX_INSURANCEDIV)) < 50000 )
            swap->I.bobinsurance = 50000;
        if ( (swap->I.aliceinsurance= (swap->I.alicesatoshis / INSTANTDEX_INSURANCEDIV)) < 50000 )
            swap->I.aliceinsurance = 50000;
        strcpy(swap->I.bobstr,swap->I.req.dest);
        strcpy(swap->I.alicestr,swap->I.req.src);
        swap->I.started = (uint32_t)time(NULL);
        swap->I.expiration = swap->I.req.timestamp + swap->I.putduration + swap->I.callduration;
        OS_randombytes((uint8_t *)&swap->I.choosei,sizeof(swap->I.choosei));
        if ( swap->I.choosei < 0 )
            swap->I.choosei = -swap->I.choosei;
        swap->I.choosei %= INSTANTDEX_DECKSIZE;
        swap->I.otherchoosei = -1;
        swap->I.myhash = pubkey25519;
        if ( statebits != 0 )
        {
            swap->I.iambob = 0;
            swap->I.otherhash = swap->I.req.desthash;
        }
        else
        {
            swap->I.iambob = 1;
            swap->I.otherhash = swap->I.req.srchash;
        }
        if ( bits256_nonz(privkey) == 0 || (x= instantdex_pubkeyargs(myinfo->ctx,swap,2 + INSTANTDEX_DECKSIZE,privkey,swap->I.orderhash,0x02+swap->I.iambob)) != 2 + INSTANTDEX_DECKSIZE )
        {
            char str[65]; printf("couldnt generate privkeys %d %s\n",x,bits256_str(str,privkey));
            return(0);
        }
    }
    swap->bobcoin = iguana_coinfind(swap->I.req.dest);
    swap->alicecoin = iguana_coinfind(swap->I.req.src);
    if ( swap->bobcoin == 0 || swap->alicecoin == 0 )
    {
        printf("missing bobcoin.%p or missing alicecoin.%p src.%p dest.%p\n",swap->bobcoin,swap->alicecoin,iguana_coinfind(swap->I.req.src),iguana_coinfind(swap->I.req.dest));
        free(swap);
        return(0);
    }
    if ( strcmp("BTC",swap->bobcoin->symbol) == 0 )
    {
        swap->I.bobconfirms = (1*0 + sqrt(dstr(swap->I.bobsatoshis) * .1));
        swap->I.aliceconfirms = MIN(BASILISK_DEFAULT_NUMCONFIRMS,swap->I.bobconfirms * 3);
    }
    else if ( strcmp("BTC",swap->alicecoin->symbol) == 0 )
    {
        swap->I.aliceconfirms = (1*0 + sqrt(dstr(swap->I.alicesatoshis) * .1));
        swap->I.bobconfirms = MIN(BASILISK_DEFAULT_NUMCONFIRMS,swap->I.bobconfirms * 3);
    }
    else
    {
        swap->I.bobconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
        swap->I.aliceconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
    }
    /*if ( swap->I.bobconfirms == 0 )
        swap->I.bobconfirms = swap->bobcoin->chain->minconfirms;
    if ( swap->I.aliceconfirms == 0 )
        swap->I.aliceconfirms = swap->alicecoin->chain->minconfirms;*/
    jumblrflag = (bits256_cmp(pubkey25519,myinfo->jumblr_pubkey) == 0 || bits256_cmp(pubkey25519,myinfo->jumblr_depositkey) == 0);
    printf(">>>>>>>>>> jumblrflag.%d <<<<<<<<< use smart address, %.8f bobconfs.%d, %.8f aliceconfs.%d\n",jumblrflag,dstr(swap->I.bobsatoshis),swap->I.bobconfirms,dstr(swap->I.alicesatoshis),swap->I.aliceconfirms);
    if ( swap->I.iambob != 0 )
    {
        basilisk_rawtx_setparms("myfee",swap->I.req.quoteid,&swap->myfee,swap->bobcoin,0,0,swap->I.bobsatoshis/INSTANTDEX_INSURANCEDIV,0,0,jumblrflag);
        basilisk_rawtx_setparms("otherfee",swap->I.req.quoteid,&swap->otherfee,swap->alicecoin,0,0,swap->I.alicesatoshis/INSTANTDEX_INSURANCEDIV,0,0,jumblrflag);
        bobpub33 = pubkey33;
    }
    else
    {
        basilisk_rawtx_setparms("otherfee",swap->I.req.quoteid,&swap->otherfee,swap->bobcoin,0,0,swap->I.bobsatoshis/INSTANTDEX_INSURANCEDIV,0,0,jumblrflag);
        basilisk_rawtx_setparms("myfee",swap->I.req.quoteid,&swap->myfee,swap->alicecoin,0,0,swap->I.alicesatoshis/INSTANTDEX_INSURANCEDIV,0,0,jumblrflag);
        alicepub33 = pubkey33;
    }
    basilisk_rawtx_setparms("bobdeposit",swap->I.req.quoteid,&swap->bobdeposit,swap->bobcoin,swap->I.bobconfirms,0,swap->I.bobsatoshis + (swap->I.bobsatoshis>>3) + swap->bobcoin->txfee,4,0,jumblrflag);
    basilisk_rawtx_setparms("bobrefund",swap->I.req.quoteid,&swap->bobrefund,swap->bobcoin,1,4,swap->I.bobsatoshis + (swap->I.bobsatoshis>>3),1,bobpub33,jumblrflag);
    swap->bobrefund.I.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("aliceclaim",swap->I.req.quoteid,&swap->aliceclaim,swap->bobcoin,1,4,swap->I.bobsatoshis + (swap->I.bobsatoshis>>3),1,alicepub33,jumblrflag);
    swap->aliceclaim.I.suppress_pubkeys = 1;
    swap->aliceclaim.I.locktime = swap->I.started + swap->I.putduration+swap->I.callduration + 1;

    basilisk_rawtx_setparms("bobpayment",swap->I.req.quoteid,&swap->bobpayment,swap->bobcoin,swap->I.bobconfirms,0,swap->I.bobsatoshis + swap->bobcoin->txfee,3,0,jumblrflag);
    basilisk_rawtx_setparms("alicespend",swap->I.req.quoteid,&swap->alicespend,swap->bobcoin,swap->I.bobconfirms,3,swap->I.bobsatoshis,1,alicepub33,jumblrflag);
    swap->alicespend.I.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("bobreclaim",swap->I.req.quoteid,&swap->bobreclaim,swap->bobcoin,swap->I.bobconfirms,3,swap->I.bobsatoshis,1,bobpub33,jumblrflag);
    swap->bobreclaim.I.suppress_pubkeys = 1;
    swap->bobreclaim.I.locktime = swap->I.started + swap->I.putduration + 1;
    basilisk_rawtx_setparms("alicepayment",swap->I.req.quoteid,&swap->alicepayment,swap->alicecoin,swap->I.aliceconfirms,0,swap->I.alicesatoshis+swap->alicecoin->txfee,2,0,jumblrflag);
    basilisk_rawtx_setparms("bobspend",swap->I.req.quoteid,&swap->bobspend,swap->alicecoin,swap->I.aliceconfirms,2,swap->I.alicesatoshis,1,bobpub33,jumblrflag);
    swap->bobspend.I.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("alicereclaim",swap->I.req.quoteid,&swap->alicereclaim,swap->alicecoin,swap->I.aliceconfirms,2,swap->I.alicesatoshis,1,alicepub33,jumblrflag);
    swap->alicereclaim.I.suppress_pubkeys = 1;
    printf("IAMBOB.%d\n",swap->I.iambob);

    return(swap);
}
// end of alice/bob code

void basilisk_rawtx_purge(struct basilisk_rawtx *rawtx)
{
    if ( rawtx->vins != 0 )
        free_json(rawtx->vins);
    //if ( rawtx->txbytes != 0 )
    //    free(rawtx->txbytes), rawtx->txbytes = 0;
}

void basilisk_swap_finished(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    int32_t i;
    swap->I.finished = (uint32_t)time(NULL);
    // save to permanent storage
    basilisk_rawtx_purge(&swap->bobdeposit);
    basilisk_rawtx_purge(&swap->bobpayment);
    basilisk_rawtx_purge(&swap->alicepayment);
    basilisk_rawtx_purge(&swap->myfee);
    basilisk_rawtx_purge(&swap->otherfee);
    basilisk_rawtx_purge(&swap->aliceclaim);
    basilisk_rawtx_purge(&swap->alicespend);
    basilisk_rawtx_purge(&swap->bobreclaim);
    basilisk_rawtx_purge(&swap->bobspend);
    basilisk_rawtx_purge(&swap->bobrefund);
    basilisk_rawtx_purge(&swap->alicereclaim);
    for (i=0; i<swap->nummessages; i++)
        if ( swap->messages[i].data != 0 )
            free(swap->messages[i].data), swap->messages[i].data = 0;
    free(swap->messages), swap->messages = 0;
    swap->nummessages = 0;
}

void basilisk_swap_purge(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    int32_t i,n;
    // while still in orderbook, wait
    //return;
    portable_mutex_lock(&myinfo->DEX_swapmutex);
    n = myinfo->numswaps;
    for (i=0; i<n; i++)
        if ( myinfo->swaps[i] == swap )
        {
            myinfo->swaps[i] = myinfo->swaps[--myinfo->numswaps];
            myinfo->swaps[myinfo->numswaps] = 0;
            basilisk_swap_finished(myinfo,swap);
            break;
        }
    portable_mutex_unlock(&myinfo->DEX_swapmutex);
}

int32_t basilisk_verify_otherstatebits(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t retval; struct basilisk_swap *swap = ptr;
    if ( datalen == sizeof(swap->I.otherstatebits) )
    {
        retval = iguana_rwnum(0,data,sizeof(swap->I.otherstatebits),&swap->I.otherstatebits);
        return(retval);
    } else return(-1);
}

int32_t basilisk_verify_statebits(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t retval = -1; uint32_t statebits; struct basilisk_swap *swap = ptr;
    if ( datalen == sizeof(swap->I.statebits) )
    {
        retval = iguana_rwnum(0,data,sizeof(swap->I.statebits),&statebits);
        if ( statebits != swap->I.statebits )
        {
            printf("statebits.%x != %x\n",statebits,swap->I.statebits);
            return(-1);
        }
    }
    return(retval);
}

int32_t basilisk_verify_choosei(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t otherchoosei=-1,i,len = 0; struct basilisk_swap *swap = ptr;
    if ( datalen == sizeof(otherchoosei)+sizeof(bits256)*2 )
    {
        len += iguana_rwnum(0,data,sizeof(otherchoosei),&otherchoosei);
        if ( otherchoosei >= 0 && otherchoosei < INSTANTDEX_DECKSIZE )
        {
            //printf("otherchoosei.%d\n",otherchoosei);
            swap->I.otherchoosei = otherchoosei;
            if ( swap->I.iambob != 0 )
            {
                for (i=0; i<32; i++)
                    swap->I.pubA0.bytes[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->I.pubA1.bytes[i] = data[len++];
                char str[65]; printf("GOT pubA0/1 %s\n",bits256_str(str,swap->I.pubA0));
            }
            else
            {
                for (i=0; i<32; i++)
                    swap->I.pubB0.bytes[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->I.pubB1.bytes[i] = data[len++];
            }
            return(0);
        }
    }
    printf("illegal otherchoosei.%d datalen.%d vs %d\n",otherchoosei,datalen,(int32_t)(sizeof(otherchoosei)+sizeof(bits256)*2));
    return(-1);
}

int32_t basilisk_swapdata_deck(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,datalen = 0;
    for (i=0; i<sizeof(swap->deck)/sizeof(swap->deck[0][0]); i++)
        datalen += iguana_rwnum(1,&data[datalen],sizeof(swap->deck[i>>1][i&1]),&swap->deck[i>>1][i&1]);
    return(datalen);
}

int32_t basilisk_verify_otherdeck(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t i,len = 0; struct basilisk_swap *swap = ptr;
    for (i=0; i<sizeof(swap->otherdeck)/sizeof(swap->otherdeck[0][0]); i++)
        len += iguana_rwnum(0,&data[len],sizeof(swap->otherdeck[i>>1][i&1]),&swap->otherdeck[i>>1][i&1]);
    return(0);
}

int32_t basilisk_verify_privkeys(struct supernet_info *myinfo,void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t i,j,wrongfirstbyte=0,errs=0,len = 0; bits256 otherpriv,pubi; uint8_t secret160[20],otherpubkey[33]; uint64_t txid; struct basilisk_swap *swap = ptr;
    //printf("verify privkeys choosei.%d otherchoosei.%d datalen.%d vs %d\n",swap->choosei,swap->otherchoosei,datalen,(int32_t)sizeof(swap->privkeys)+20+32);
    memset(otherpriv.bytes,0,sizeof(otherpriv));
    if ( swap->I.cutverified == 0 && swap->I.otherchoosei >= 0 && datalen == sizeof(swap->privkeys)+20+2*32 )
    {
        for (i=errs=0; i<sizeof(swap->privkeys)/sizeof(*swap->privkeys); i++)
        {
            for (j=0; j<32; j++)
                otherpriv.bytes[j] = data[len++];
            if ( i != swap->I.choosei )
            {
                pubi = bitcoin_pubkey33(myinfo->ctx,otherpubkey,otherpriv);
                revcalc_rmd160_sha256(secret160,otherpriv);//.bytes,sizeof(otherpriv));
                memcpy(&txid,secret160,sizeof(txid));
                errs += basilisk_verify_pubpair(&wrongfirstbyte,swap,i,otherpubkey[0],pubi,txid);
            }
        }
        if ( errs == 0 && wrongfirstbyte == 0 )
        {
            swap->I.cutverified = 1, printf("CUT VERIFIED\n");
            if ( swap->I.iambob != 0 )
            {
                for (i=0; i<32; i++)
                    swap->I.pubAm.bytes[i] = data[len++];
                for (i=0; i<20; i++)
                    swap->I.secretAm[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->I.secretAm256[i] = data[len++];
                basilisk_bobscripts_set(myinfo,swap,1,1);
            }
            else
            {
                for (i=0; i<32; i++)
                    swap->I.pubBn.bytes[i] = data[len++];
                for (i=0; i<20; i++)
                    swap->I.secretBn[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->I.secretBn256[i] = data[len++];
                //basilisk_bobscripts_set(myinfo,swap,0);
            }
        } else printf("failed verification: wrong firstbyte.%d errs.%d\n",wrongfirstbyte,errs);
    }
    //printf("privkeys errs.%d wrongfirstbyte.%d\n",errs,wrongfirstbyte);
    return(errs);
}

uint32_t basilisk_swapdata_rawtxsend(struct supernet_info *myinfo,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx,uint32_t nextbits,int32_t suppress_swapsend)
{
    uint8_t sendbuf[32768]; int32_t sendlen;
    if ( basilisk_swapdata_rawtx(myinfo,swap,data,maxlen,rawtx) != 0 )
    {
        if ( bits256_nonz(rawtx->I.signedtxid) != 0 && bits256_nonz(rawtx->I.actualtxid) == 0 )
        {
            char str[65],str2[65];
            rawtx->I.actualtxid = basilisk_swap_broadcast(rawtx->name,myinfo,swap,rawtx->coin,rawtx->txbytes,rawtx->I.datalen);
            if ( bits256_cmp(rawtx->I.actualtxid,rawtx->I.signedtxid) != 0 )
            {
                printf("%s rawtxsend %s vs %s\n",rawtx->name,bits256_str(str,rawtx->I.signedtxid),bits256_str(str2,rawtx->I.actualtxid));
                rawtx->I.actualtxid = rawtx->I.signedtxid;
            }
            if ( bits256_nonz(rawtx->I.actualtxid) != 0 && msgbits != 0 )
            {
                sendlen = 0;
                sendbuf[sendlen++] = rawtx->I.datalen & 0xff;
                sendbuf[sendlen++] = (rawtx->I.datalen >> 8) & 0xff;
                sendbuf[sendlen++] = rawtx->I.redeemlen;
                memcpy(&sendbuf[sendlen],rawtx->txbytes,rawtx->I.datalen), sendlen += rawtx->I.datalen;
                if ( rawtx->I.redeemlen > 0 && rawtx->I.redeemlen < 0x100 )
                {
                    memcpy(&sendbuf[sendlen],rawtx->redeemscript,rawtx->I.redeemlen);
                    sendlen += rawtx->I.redeemlen;
                }
                basilisk_dontforget_update(myinfo,swap,rawtx);
                //printf("sendlen.%d datalen.%d redeemlen.%d\n",sendlen,rawtx->datalen,rawtx->redeemlen);
                if ( suppress_swapsend == 0 )
                    return(basilisk_swapsend(myinfo,swap,msgbits,sendbuf,sendlen,nextbits,rawtx->I.crcs));
                else
                {
                    printf("suppress swapsend %x\n",msgbits);
                    return(0);
                }
            }
        }
        return(nextbits);
    } else if ( swap->I.iambob == 0 )
        printf("error from basilisk_swapdata_rawtx.%s %p len.%d\n",rawtx->name,rawtx->txbytes,rawtx->I.datalen);
    return(0);
}

void basilisk_sendpubkeys(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t datalen;
    datalen = basilisk_swapdata_deck(myinfo,swap,data,maxlen);
    printf("send deck.%d\n",datalen);
    swap->I.statebits |= basilisk_swapsend(myinfo,swap,0x02,data,datalen,0x01,swap->I.crcs_mypub);
}

int32_t basilisk_checkdeck(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    if ( (swap->I.statebits & 0x02) == 0 )
    {
        //printf("check for other deck\n");
        if ( basilisk_swapget(myinfo,swap,0x02,data,maxlen,basilisk_verify_otherdeck) == 0 )
            swap->I.statebits |= 0x02;
        else return(-1);
    }
    return(0);
}

void basilisk_sendstate(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t datalen=0;
    datalen = iguana_rwnum(1,data,sizeof(swap->I.statebits),&swap->I.statebits);
    basilisk_swapsend(myinfo,swap,0x80000000,data,datalen,0,0);
}

void basilisk_sendchoosei(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,datalen; char str[65];
    datalen = iguana_rwnum(1,data,sizeof(swap->I.choosei),&swap->I.choosei);
    if ( swap->I.iambob != 0 )
    {
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubB0.bytes[i];
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubB1.bytes[i];
        printf("SEND pubB0/1 %s\n",bits256_str(str,swap->I.pubB0));
    }
    else
    {
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubA0.bytes[i];
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubA1.bytes[i];
        printf("SEND pubA0/1 %s\n",bits256_str(str,swap->I.pubA0));
    }
    swap->I.statebits |= basilisk_swapsend(myinfo,swap,0x08,data,datalen,0x04,swap->I.crcs_mychoosei);
}

void basilisk_waitchoosei(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    uint8_t pubkey33[33]; char str[65],str2[65];
    //printf("check otherchoosei\n");
    if ( basilisk_swapget(myinfo,swap,0x08,data,maxlen,basilisk_verify_choosei) == 0 )
    {
        if ( swap->I.iambob != 0 )
        {
            if ( bits256_nonz(swap->I.privBn) == 0 )
            {
                swap->I.privBn = swap->privkeys[swap->I.otherchoosei];
                memset(&swap->privkeys[swap->I.otherchoosei],0,sizeof(swap->privkeys[swap->I.otherchoosei]));
                revcalc_rmd160_sha256(swap->I.secretBn,swap->I.privBn);//.bytes,sizeof(swap->privBn));
                vcalc_sha256(0,swap->I.secretBn256,swap->I.privBn.bytes,sizeof(swap->I.privBn));
                swap->I.pubBn = bitcoin_pubkey33(myinfo->ctx,pubkey33,swap->I.privBn);
                printf("set privBn.%s %s\n",bits256_str(str,swap->I.privBn),bits256_str(str2,*(bits256 *)swap->I.secretBn256));
                basilisk_bobscripts_set(myinfo,swap,1,1);
             }
        }
        else
        {
            if ( bits256_nonz(swap->I.privAm) == 0 )
            {
                swap->I.privAm = swap->privkeys[swap->I.otherchoosei];
                memset(&swap->privkeys[swap->I.otherchoosei],0,sizeof(swap->privkeys[swap->I.otherchoosei]));
                revcalc_rmd160_sha256(swap->I.secretAm,swap->I.privAm);//.bytes,sizeof(swap->privAm));
                vcalc_sha256(0,swap->I.secretAm256,swap->I.privAm.bytes,sizeof(swap->I.privAm));
                swap->I.pubAm = bitcoin_pubkey33(myinfo->ctx,pubkey33,swap->I.privAm);
                char str[65],str2[65]; printf("set privAm.%s %s\n",bits256_str(str,swap->I.privAm),bits256_str(str2,*(bits256 *)swap->I.secretAm256));
                //basilisk_bobscripts_set(myinfo,swap,0);
            }
        }
        swap->I.statebits |= 0x08;
    }
}

void basilisk_sendmostprivs(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,j,datalen;
    datalen = 0;
    for (i=0; i<sizeof(swap->privkeys)/sizeof(*swap->privkeys); i++)
    {
        for (j=0; j<32; j++)
            data[datalen++] = (i == swap->I.otherchoosei) ? 0 : swap->privkeys[i].bytes[j];
    }
    if ( swap->I.iambob != 0 )
    {
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubBn.bytes[i];
        for (i=0; i<20; i++)
            data[datalen++] = swap->I.secretBn[i];
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.secretBn256[i];
    }
    else
    {
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubAm.bytes[i];
        for (i=0; i<20; i++)
            data[datalen++] = swap->I.secretAm[i];
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.secretAm256[i];
    }
    //printf("send privkeys.%d\n",datalen);
    swap->I.statebits |= basilisk_swapsend(myinfo,swap,0x20,data,datalen,0x10,swap->I.crcs_myprivs);
}

int32_t basilisk_swapiteration(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t j,datalen,retval = 0; uint32_t savestatebits=0,saveotherbits=0;
    if ( swap->I.iambob != 0 )
        swap->I.statebits |= 0x80;
    while ( swap->aborted == 0 && ((swap->I.otherstatebits & 0x80) == 0 || (swap->I.statebits & 0x80) == 0) && retval == 0 && time(NULL) < swap->I.expiration )
    {
        if ( swap->connected == 0 )
            basilisk_psockinit(myinfo,swap,swap->I.iambob != 0);
        printf("D r%u/q%u swapstate.%x otherstate.%x remaining %d\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits,swap->I.otherstatebits,(int32_t)(swap->I.expiration-time(NULL)));
        if ( swap->I.iambob != 0 && (swap->I.statebits & 0x80) == 0 ) // wait for fee
        {
            if ( basilisk_swapget(myinfo,swap,0x80,data,maxlen,basilisk_verify_otherfee) == 0 )
            {
                // verify and submit otherfee
                swap->I.statebits |= 0x80;
                basilisk_sendstate(myinfo,swap,data,maxlen);
            }
        }
        else if ( swap->I.iambob == 0 )
            swap->I.statebits |= 0x80;
        basilisk_sendstate(myinfo,swap,data,maxlen);
        basilisk_swapget(myinfo,swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
        if ( (swap->I.otherstatebits & 0x80) != 0 && (swap->I.statebits & 0x80) != 0 )
            break;
        if ( swap->I.statebits == savestatebits && swap->I.otherstatebits == saveotherbits )
            sleep(DEX_SLEEP + (swap->I.iambob == 0)*1);
        savestatebits = swap->I.statebits;
        saveotherbits = swap->I.otherstatebits;
        basilisk_swapget(myinfo,swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
        basilisk_sendstate(myinfo,swap,data,maxlen);
        if ( (swap->I.otherstatebits & 0x80) == 0 )
            basilisk_swapdata_rawtxsend(myinfo,swap,0x80,data,maxlen,&swap->myfee,0x40,0);
    }
    basilisk_swap_saveupdate(myinfo,swap);
    while ( swap->aborted == 0 && retval == 0 && time(NULL) < swap->I.expiration )  // both sides have setup required data and paid txfee
    {
        basilisk_swap_saveupdate(myinfo,swap);
        if ( swap->connected == 0 )
            basilisk_psockinit(myinfo,swap,swap->I.iambob != 0);
        //if ( (rand() % 30) == 0 )
            printf("E r%u/q%u swapstate.%x otherstate.%x remaining %d\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits,swap->I.otherstatebits,(int32_t)(swap->I.expiration-time(NULL)));
        if ( swap->I.iambob != 0 )
        {
            //printf("BOB\n");
            if ( (swap->I.statebits & 0x100) == 0 )
            {
                printf("send bobdeposit\n");
                swap->I.statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x200,data,maxlen,&swap->bobdeposit,0x100,0);
            }
            // [BLOCKING: altfound] make sure altpayment is confirmed and send payment
            else if ( (swap->I.statebits & 0x1000) == 0 )
            {
                printf("check alicepayment\n");
                if ( basilisk_swapget(myinfo,swap,0x1000,data,maxlen,basilisk_verify_alicepaid) == 0 )
                {
                    swap->I.statebits |= 0x1000;
                    printf("got alicepayment aliceconfirms.%d\n",swap->I.aliceconfirms);
                }
            }
            else if ( (swap->I.statebits & 0x2000) == 0 )
            {
                if ( (swap->I.aliceconfirms == 0 && swap->aliceunconf != 0) || basilisk_numconfirms(myinfo,swap,&swap->alicepayment) >= swap->I.aliceconfirms )
                {
                    swap->I.statebits |= 0x2000;
                    printf("alicepayment confirmed\n");
                }
            }
            else if ( (swap->I.statebits & 0x4000) == 0 )
            {
                basilisk_bobscripts_set(myinfo,swap,0,1);
                printf("send bobpayment\n");
                swap->I.statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x8000,data,maxlen,&swap->bobpayment,0x4000,0);
            }
            // [BLOCKING: privM] Bob waits for privAm either from Alice or alice blockchain
            else if ( (swap->I.statebits & 0xc0000) != 0xc0000 )
            {
                if ( basilisk_swapget(myinfo,swap,0x40000,data,maxlen,basilisk_verify_privi) == 0 || basilisk_privAm_extract(myinfo,swap) == 0 ) // divulges privAm
                {
                    //printf("got privi spend alicepayment, dont divulge privBn until bobspend propagated\n");
                    basilisk_alicepayment_spend(myinfo,swap,&swap->bobspend);
                    if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->bobspend,0x40000,1) == 0 )
                        printf("Bob error spending alice payment\n");
                    else
                    {
                        tradebot_swap_balancingtrade(myinfo,swap,1);
                        printf("Bob spends alicepayment aliceconfirms.%d\n",swap->I.aliceconfirms);
                        swap->I.statebits |= 0x40000;
                        if ( basilisk_numconfirms(myinfo,swap,&swap->bobspend) >= swap->I.aliceconfirms )
                        {
                            printf("bobspend confirmed\n");
                            swap->I.statebits |= 0x80000;
                            printf("Bob confirming spend of Alice's payment\n");
                            sleep(DEX_SLEEP);
                        }
                        retval = 1;
                    }
                }
            }
            if ( swap->bobpayment.I.locktime != 0 && time(NULL) > swap->bobpayment.I.locktime )
            {
                // submit reclaim of payment
                printf("bob reclaims bobpayment\n");
                swap->I.statebits |= (0x40000 | 0x80000);
                if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->bobreclaim,0,0) == 0 )
                    printf("Bob error reclaiming own payment after alice timed out\n");
                else
                {
                    printf("Bob reclaimed own payment\n");
                    while ( 0 && (swap->I.statebits & 0x100000) == 0 ) // why wait for own tx?
                    {
                        if ( basilisk_numconfirms(myinfo,swap,&swap->bobreclaim) >= 1 )
                        {
                            printf("bobreclaim confirmed\n");
                            swap->I.statebits |= 0x100000;
                            printf("Bob confirms reclain of payment\n");
                            break;
                        }
                    }
                    retval = 1;
                }
            }
        }
        else
        {
            //printf("ALICE\n");
            // [BLOCKING: depfound] Alice waits for deposit to confirm and sends altpayment
            if ( (swap->I.statebits & 0x200) == 0 )
            {
                printf("checkfor deposit\n");
                if ( basilisk_swapget(myinfo,swap,0x200,data,maxlen,basilisk_verify_bobdeposit) == 0 )
                {
                    // verify deposit and submit, set confirmed height
                    printf("got bobdeposit\n");
                    swap->I.statebits |= 0x200;
                } else printf("no valid deposit\n");
            }
            else if ( (swap->I.statebits & 0x400) == 0 )
            {
                if ( basilisk_istrustedbob(myinfo,swap) != 0 || (swap->I.bobconfirms == 0 && swap->depositunconf != 0) || basilisk_numconfirms(myinfo,swap,&swap->bobdeposit) >= swap->I.bobconfirms )
                {
                    printf("bobdeposit confirmed\n");
                    swap->I.statebits |= 0x400;
                }
            }
            else if ( (swap->I.statebits & 0x800) == 0 )
            {
                printf("send alicepayment\n");
                swap->I.statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x1000,data,maxlen,&swap->alicepayment,0x800,0);
            }
            // [BLOCKING: payfound] make sure payment is confrmed and send in spend or see bob's reclaim and claim
            else if ( (swap->I.statebits & 0x8000) == 0 )
            {
                if ( basilisk_swapget(myinfo,swap,0x8000,data,maxlen,basilisk_verify_bobpaid) == 0 )
                {
                    printf("got bobpayment\n");
                    tradebot_swap_balancingtrade(myinfo,swap,0);
                    // verify payment and submit, set confirmed height
                    swap->I.statebits |= 0x8000;
                }
            }
            else if ( (swap->I.statebits & 0x10000) == 0 )
            {
                if ( basilisk_istrustedbob(myinfo,swap) != 0 || (swap->I.bobconfirms == 0 && swap->paymentunconf != 0) || basilisk_numconfirms(myinfo,swap,&swap->bobpayment) >= swap->I.bobconfirms )
                {
                    printf("bobpayment confirmed\n");
                    swap->I.statebits |= 0x10000;
                }
            }
            else if ( (swap->I.statebits & 0x20000) == 0 )
            {
                printf("alicespend bobpayment\n");
                if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->alicespend,0x20000,0) != 0 )//&& (swap->aliceunconf != 0 || basilisk_numconfirms(myinfo,swap,&swap->alicespend) > 0) )
                {
                    swap->I.statebits |= 0x20000;
                }
            }
            else if ( (swap->I.statebits & 0x40000) == 0 )
            {
                int32_t numconfs;
                if ( (numconfs= basilisk_numconfirms(myinfo,swap,&swap->alicespend)) >= swap->I.bobconfirms )
                {
                    for (j=datalen=0; j<32; j++)
                        data[datalen++] = swap->I.privAm.bytes[j];
                    printf("send privAm %x\n",swap->I.statebits);
                    swap->I.statebits |= basilisk_swapsend(myinfo,swap,0x40000,data,datalen,0x20000,swap->I.crcs_mypriv);
                    printf("Alice confirms spend of Bob's payment\n");
                    retval = 1;
                } else printf("alicespend numconfs.%d < %d\n",numconfs,swap->I.bobconfirms);
            }
            if ( swap->bobdeposit.I.locktime != 0 && time(NULL) > swap->bobdeposit.I.locktime )
            {
                printf("Alice claims deposit\n");
                if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->aliceclaim,0,0) == 0 )
                    printf("Alice couldnt claim deposit\n");
                else
                {
                    printf("Alice claimed deposit\n");
                    retval = 1;
                }
            }
            else if ( swap->aborted != 0 || basilisk_privBn_extract(myinfo,swap,data,maxlen) == 0 )
            {
                printf("Alice reclaims her payment\n");
                swap->I.statebits |= 0x40000000;
                if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->alicereclaim,0x40000000,0) == 0 )
                    printf("Alice error sending alicereclaim\n");
                else
                {
                    printf("Alice reclaimed her payment\n");
                    retval = 1;
                }
            }
        }
        if ( (rand() % 30) == 0 )
            printf("finished swapstate.%x other.%x\n",swap->I.statebits,swap->I.otherstatebits);
        if ( swap->I.statebits == savestatebits && swap->I.otherstatebits == saveotherbits )
            sleep(DEX_SLEEP + (swap->I.iambob == 0)*1);
        savestatebits = swap->I.statebits;
        saveotherbits = swap->I.otherstatebits;
        basilisk_sendstate(myinfo,swap,data,maxlen);
        basilisk_swapget(myinfo,swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
    }
    return(retval);
}

int32_t swapcompleted(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    if ( swap->I.iambob != 0 )
        return(swap->I.bobspent);
    else return(swap->I.alicespent);
}

cJSON *swapjson(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    cJSON *retjson = cJSON_CreateObject();
    return(retjson);
}

void basilisk_psockinit(struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t amlp)
{
    char keystr[64],databuf[1024],pubkeystr[128],*retstr,*retstr2,*datastr,*pushaddr=0,*subaddr=0; cJSON *retjson,*addrjson; uint8_t data[512]; int32_t datalen,timeout,pushsock = -1,subsock = -1;
    if ( swap->connected == 1 )
        return;
    if ( swap->pushsock < 0 && swap->subsock < 0 && (pushsock= nn_socket(AF_SP,NN_PUSH)) >= 0 && (subsock= nn_socket(AF_SP,NN_SUB)) >= 0 )
    {
        timeout = 1000;
        nn_setsockopt(pushsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
        timeout = 1;
        nn_setsockopt(subsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
        nn_setsockopt(subsock,NN_SUB,NN_SUB_SUBSCRIBE,"",0);
        swap->pushsock = pushsock;
        swap->subsock = subsock;
    }
    if ( (subsock= swap->subsock) < 0 || (pushsock= swap->pushsock) < 0 )
    {
        printf("error getting nn_sockets\n");
        return;
    }
    sprintf(keystr,"%08x-%08x",swap->I.req.requestid,swap->I.req.quoteid);
    if ( swap->connected == 0 && (retstr= _dex_kvsearch(myinfo,"KV",keystr)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (datastr= jstr(retjson,"value")) != 0 )
            {
                datalen = (int32_t)strlen(datastr) >> 1;
                decode_hex((uint8_t *)databuf,datalen,datastr);
                if ( (addrjson= cJSON_Parse(databuf)) != 0 )
                {
                    pushaddr = jstr(addrjson,"push");
                    subaddr = jstr(addrjson,"sub");
                    if ( pushaddr != 0 && subaddr != 0 )
                    {
                        printf("KV decoded (%s and %s) %d %d\n",pushaddr,subaddr,swap->pushsock,swap->subsock);
                        if ( nn_connect(swap->pushsock,pushaddr) >= 0 && nn_connect(swap->subsock,subaddr) >= 0 )
                            swap->connected = 1;
                    }
                    free_json(addrjson);
                }
            }
            free_json(retjson);
        }
        printf("KVsearch.(%s) -> (%s) connected.%d socks.(%d %d) amlp.%d\n",keystr,retstr,swap->connected,swap->pushsock,swap->subsock,amlp);
        free(retstr);
    }
    printf("connected.%d amlp.%d subsock.%d pushsock.%d\n",swap->connected,amlp,subsock,pushsock);
    if ( swap->connected <= 0 && amlp != 0 && subsock >= 0 && pushsock >= 0 )
    {
        if ( (retstr= _dex_psock(myinfo,"{}")) != 0 )
        {
            printf("psock returns.(%s)\n",retstr);
            // {"result":"success","pushaddr":"tcp://5.9.102.210:30002","subaddr":"tcp://5.9.102.210:30003","randipbits":3606291758,"coin":"KMD","tag":"6952562460568228137"}
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                pushaddr = jstr(retjson,"pushaddr");
                subaddr = jstr(retjson,"subaddr");
                if ( pushaddr != 0 && subaddr != 0 )
                {
                    if ( nn_connect(pushsock,pushaddr) >= 0 )
                    {
                        printf("connected to %d pushaddr.(%s)\n",pushsock,pushaddr);
                        if ( nn_connect(subsock,subaddr) >= 0 )
                        {
                            swap->connected = 1;
                            init_hexbytes_noT(pubkeystr,myinfo->persistent_pubkey33,33);
                            sprintf((char *)data,"{\"push\":\"%s\",\"sub\":\"%s\",\"trade\":[\"%s\", %.8f, \"%s\", %.8f],\"pub\":\"%s\"}",pushaddr,subaddr,swap->I.req.src,dstr(swap->I.req.srcamount),swap->I.req.dest,dstr(swap->I.req.destamount),pubkeystr);
                            datalen = (int32_t)strlen((char *)data) + 1;
                            printf("datalen.%d (%s)\n",datalen,(char *)data);
                            init_hexbytes_noT(databuf,data,datalen);
                            printf("%s -> %s\n",keystr,databuf);
                            if ( (retstr2= _dex_kvupdate(myinfo,"KV",keystr,databuf,1)) != 0 )
                            {
                                printf("KVupdate.(%s)\n",retstr2);
                                free(retstr2);
                            }
                        } else printf("nn_connect error to %d subaddr.(%s)\n",subsock,subaddr);
                    } else printf("nn_connect error to %d pushaddr.(%s)\n",pushsock,pushaddr);
                }
                else printf("missing addr (%p) (%p) (%s)\n",pushaddr,subaddr,jprint(retjson,0));
                free_json(retjson);
            } else printf("Error parsing psock.(%s)\n",retstr);
            free(retstr);
        } else printf("error issuing _dex_psock\n");
    }
}

int32_t basilisk_alicetxs(struct supernet_info *myinfo,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,retval = -1;
    printf("alicetxs\n");
    for (i=0; i<3; i++)
    {
        if ( swap->alicepayment.I.datalen == 0 )
            basilisk_alicepayment(myinfo,swap,swap->alicepayment.coin,&swap->alicepayment,swap->I.pubAm,swap->I.pubBn);
        if ( swap->alicepayment.I.datalen == 0 || swap->alicepayment.I.spendlen == 0 )
        {
            printf("error alice generating payment.%d\n",swap->alicepayment.I.spendlen);
            sleep(20);
        }
        else
        {
            retval = 0;
            for (i=0; i<swap->alicepayment.I.datalen; i++)
                printf("%02x",swap->alicepayment.txbytes[i]);
            printf(" ALICE PAYMENT created\n");
            iguana_unspents_mark(myinfo,swap->alicecoin,swap->alicepayment.vins);
            basilisk_txlog(myinfo,swap,&swap->alicepayment,-1);
            break;
        }
    }
    if ( swap->myfee.I.datalen == 0 )
    {
        printf("generate fee\n");
        if ( basilisk_rawtx_gen("myfee",myinfo,swap->I.started,swap->persistent_pubkey33,swap->I.iambob,1,&swap->myfee,0,swap->myfee.spendscript,swap->myfee.I.spendlen,swap->myfee.coin->chain->txfee,1,0) == 0 )
        {
            swap->I.statebits |= basilisk_swapdata_rawtxsend(myinfo,swap,0x80,data,maxlen,&swap->myfee,0x40,0);
            iguana_unspents_mark(myinfo,swap->I.iambob!=0?swap->bobcoin:swap->alicecoin,swap->myfee.vins);
            basilisk_txlog(myinfo,swap,&swap->myfee,-1);
            for (i=0; i<swap->myfee.I.spendlen; i++)
                printf("%02x",swap->myfee.txbytes[i]);
            printf(" fee %p %x\n",swap->myfee.txbytes,swap->I.statebits);
            swap->I.statebits |= 0x40;
        }
        else
        {
            printf("error creating myfee\n");
            return(-2);
        }
    }
    if ( swap->alicepayment.I.datalen != 0 && swap->alicepayment.I.spendlen > 0 && swap->myfee.I.datalen != 0 && swap->myfee.I.spendlen > 0 )
        return(0);
    return(-1);
}

void basilisk_swaploop(void *_swap)
{
    uint8_t *data; uint32_t expiration,savestatebits=0,saveotherbits=0; uint32_t channel; int32_t iters,retval=0,j,datalen,maxlen; struct supernet_info *myinfo; struct basilisk_swap *swap = _swap;
    myinfo = swap->myinfoptr;
    fprintf(stderr,"start swap\n");
    maxlen = 1024*1024 + sizeof(*swap);
    data = malloc(maxlen);
    expiration = (uint32_t)time(NULL) + 300;
    myinfo->DEXactive = expiration;
    channel = 'D' + ((uint32_t)'E' << 8) + ((uint32_t)'X' << 16);
    while ( swap->aborted == 0 && (swap->I.statebits & (0x08|0x02)) != (0x08|0x02) && time(NULL) < expiration )
    {
        dex_channelsend(myinfo,swap->I.req.srchash,swap->I.req.desthash,channel,0x4000000,(void *)&swap->I.req.requestid,sizeof(swap->I.req.requestid)); //,60);
        if ( swap->connected == 0 )
            basilisk_psockinit(myinfo,swap,swap->I.iambob != 0);
        if ( swap->connected > 0 )
        {
            printf("A r%u/q%u swapstate.%x\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits);
            basilisk_sendstate(myinfo,swap,data,maxlen);
            basilisk_sendpubkeys(myinfo,swap,data,maxlen); // send pubkeys
            if ( basilisk_checkdeck(myinfo,swap,data,maxlen) == 0) // check for other deck 0x02
                basilisk_sendchoosei(myinfo,swap,data,maxlen);
            basilisk_waitchoosei(myinfo,swap,data,maxlen); // wait for choosei 0x08
            if ( (swap->I.statebits & (0x08|0x02)) == (0x08|0x02) )
                break;
        }
        if ( swap->I.statebits == savestatebits && swap->I.otherstatebits == saveotherbits )
            sleep(DEX_SLEEP + (swap->I.iambob == 0)*1);
        savestatebits = swap->I.statebits;
        saveotherbits = swap->I.otherstatebits;
    }
    if ( swap->connected == 0 )
    {
        printf("couldnt establish connection\n");
        retval = -1;
    }
    while ( swap->aborted == 0 && retval == 0 && (swap->I.statebits & 0x20) == 0 )
    {
        if ( swap->connected == 0 )
            basilisk_psockinit(myinfo,swap,swap->I.iambob != 0);
        printf("B r%u/q%u swapstate.%x\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits);
        basilisk_sendstate(myinfo,swap,data,maxlen);
        basilisk_sendchoosei(myinfo,swap,data,maxlen);
        basilisk_sendmostprivs(myinfo,swap,data,maxlen);
        if ( basilisk_swapget(myinfo,swap,0x20,data,maxlen,basilisk_verify_privkeys) == 0 )
        {
            swap->I.statebits |= 0x20;
            break;
        }
        if ( swap->I.statebits == savestatebits && swap->I.otherstatebits == saveotherbits )
            sleep(DEX_SLEEP + (swap->I.iambob == 0)*1);
        savestatebits = swap->I.statebits;
        saveotherbits = swap->I.otherstatebits;
        if ( time(NULL) > expiration )
            break;
    }
    myinfo->DEXactive = swap->I.expiration;
    if ( time(NULL) >= expiration )
    {
        retval = -1;
        myinfo->DEXactive = 0;
    }
    if ( swap->aborted != 0 )
    {
        printf("swap aborted before tx sent\n");
        retval = -1;
    }
    printf("C r%u/q%u swapstate.%x retval.%d\n",swap->I.req.requestid,swap->I.req.quoteid,swap->I.statebits,retval);
    iters = 0;
    while ( swap->aborted == 0 && retval == 0 && (swap->I.statebits & 0x40) == 0 && iters++ < 10 ) // send fee
    {
        if ( swap->connected == 0 )
            basilisk_psockinit(myinfo,swap,swap->I.iambob != 0);
        //printf("sendstate.%x\n",swap->I.statebits);
        basilisk_sendstate(myinfo,swap,data,maxlen);
        //printf("swapget\n");
        basilisk_swapget(myinfo,swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
        //printf("after swapget\n");
        if ( swap->I.iambob != 0 && swap->bobdeposit.I.datalen == 0 )
        {
            printf("bobscripts set\n");
            if ( basilisk_bobscripts_set(myinfo,swap,1,1) < 0 )
            {
                sleep(DEX_SLEEP);
                printf("bobscripts set error\n");
                continue;
            }
        }
        if ( swap->I.iambob == 0 )
        {
            /*for (i=0; i<20; i++)
                printf("%02x",swap->secretAm[i]);
            printf(" <- secretAm\n");
            for (i=0; i<32; i++)
                printf("%02x",swap->secretAm256[i]);
            printf(" <- secretAm256\n");
            for (i=0; i<32; i++)
                printf("%02x",swap->pubAm.bytes[i]);
            printf(" <- pubAm\n");
            for (i=0; i<20; i++)
                printf("%02x",swap->secretBn[i]);
            printf(" <- secretBn\n");
            for (i=0; i<32; i++)
                printf("%02x",swap->secretBn256[i]);
            printf(" <- secretBn256\n");
            for (i=0; i<32; i++)
                printf("%02x",swap->pubBn.bytes[i]);
            printf(" <- pubBn\n");
            for (i=0; i<32; i++)
                printf("%02x",swap->pubA0.bytes[i]);
            printf(" <- pubA0\n");
            for (i=0; i<32; i++)
                printf("%02x",swap->pubA1.bytes[i]);
            printf(" <- pubA1\n");
            for (i=0; i<32; i++)
                printf("%02x",swap->pubB0.bytes[i]);
            printf(" <- pubB0\n");
            for (i=0; i<32; i++)
                printf("%02x",swap->pubB1.bytes[i]);
            printf(" <- pubB1\n");*/
            if ( (retval= basilisk_alicetxs(myinfo,swap,data,maxlen)) != 0 )
            {
                printf("basilisk_alicetxs error\n");
                break;
            }
        }
    }
    if ( swap->I.iambob == 0 && (swap->I.statebits & 0x40) == 0 )
    {
        printf("couldnt send fee\n");
        retval = -8;
    }
    if ( retval == 0 )
    {
        if ( swap->I.iambob == 0 && (swap->myfee.I.datalen == 0 || swap->alicepayment.I.datalen == 0 || swap->alicepayment.I.datalen == 0) )
        {
            printf("ALICE's error %d %d %d\n",swap->myfee.I.datalen,swap->alicepayment.I.datalen,swap->alicepayment.I.datalen);
            retval = -7;
        }
        else if ( swap->I.iambob != 0 && swap->bobdeposit.I.datalen == 0 ) //swap->bobpayment.I.datalen == 0
        {
            printf("BOB's error %d %d %d\n",swap->myfee.I.datalen,swap->bobpayment.I.datalen,swap->bobdeposit.I.datalen);
            retval = -7;
        }
    }
    while ( swap->aborted == 0 && retval == 0 && basilisk_swapiteration(myinfo,swap,data,maxlen) == 0 )
    {
        if ( swap->I.statebits == savestatebits && swap->I.otherstatebits == saveotherbits )
            sleep(DEX_SLEEP + (swap->I.iambob == 0)*1);
        savestatebits = swap->I.statebits;
        saveotherbits = swap->I.otherstatebits;
        basilisk_sendstate(myinfo,swap,data,maxlen);
        basilisk_swapget(myinfo,swap,0x80000000,data,maxlen,basilisk_verify_otherstatebits);
        basilisk_swap_saveupdate(myinfo,swap);
        if ( time(NULL) > swap->I.expiration )
            break;
    }
    if ( swap->I.iambob != 0 && swap->bobdeposit.I.datalen != 0 && bits256_nonz(swap->bobdeposit.I.actualtxid) != 0 )
    {
        printf("BOB waiting for confirm state.%x\n",swap->I.statebits);
        sleep(60); // wait for confirm/propagation of msig
        printf("BOB reclaims refund\n");
        basilisk_bobdeposit_refund(myinfo,swap,0);
        if ( basilisk_swapdata_rawtxsend(myinfo,swap,0,data,maxlen,&swap->bobrefund,0x40000000,0) == 0 ) // use secretBn
        {
            printf("Bob submit error getting refund of deposit\n");
        }
        else
        {
            // maybe wait for bobrefund to be confirmed
            for (j=datalen=0; j<32; j++)
                data[datalen++] = swap->I.privBn.bytes[j];
            basilisk_swapsend(myinfo,swap,0x40000000,data,datalen,0x40000000,swap->I.crcs_mypriv);
        }
        basilisk_swap_saveupdate(myinfo,swap);
    }
    if ( retval != 0 )
        basilisk_swap_sendabort(myinfo,swap);
    printf("end of atomic swap\n");
    if ( swapcompleted(myinfo,swap) > 0 ) // only if swap completed
    {
        if ( swap->I.iambob != 0 )
            tradebot_pendingadd(myinfo,swapjson(myinfo,swap),swap->I.req.src,dstr(swap->I.req.srcamount),swap->I.req.dest,dstr(swap->I.req.destamount));
        else tradebot_pendingadd(myinfo,swapjson(myinfo,swap),swap->I.req.dest,dstr(swap->I.req.destamount),swap->I.req.src,dstr(swap->I.req.srcamount));
    }
    printf("%s swap finished statebits %x\n",swap->I.iambob!=0?"BOB":"ALICE",swap->I.statebits);
    basilisk_swap_purge(myinfo,swap);
    free(data);
}

cJSON *basilisk_swapjson(struct supernet_info *myinfo,struct basilisk_swap *swap)
{
    cJSON *item = cJSON_CreateObject();
    jaddnum(item,"requestid",swap->I.req.requestid);
    jaddnum(item,"quoteid",swap->I.req.quoteid);
    jaddnum(item,"state",swap->I.statebits);
    jaddnum(item,"otherstate",swap->I.otherstatebits);
    jadd(item,"request",basilisk_requestjson(&swap->I.req));
    return(item);
}

struct basilisk_swap *basilisk_thread_start(struct supernet_info *myinfo,bits256 privkey,struct basilisk_request *rp,uint32_t statebits,int32_t optionduration,int32_t reinit)
{
    int32_t i,m,n,iter; uint8_t pubkey33[33]; bits256 pubkey25519; uint32_t channel,starttime; cJSON *retarray,*item,*msgobj; struct iguana_info *coin; double pending=0.; struct basilisk_swap *swap = 0;
    // statebits 1 -> client, 0 -> LP
    if ( myinfo->numswaps > 0 )
    {
        if ( (coin= iguana_coinfind(rp->src)) == 0 || coin->FULLNODE >= 0 )
        {
            printf("dont have SRC coin.%s or not native and already swap pending\n",rp->src);
            return(0);
        }
        if ( (coin= iguana_coinfind(rp->dest)) == 0 || coin->FULLNODE >= 0 )
        {
            printf("dont have DEST coin.%s or not native and already swap pending\n",rp->dest);
            return(0);
        }
    }
    portable_mutex_lock(&myinfo->DEX_swapmutex);
    for (i=0; i<myinfo->numswaps; i++)
        if ( myinfo->swaps[i]->I.req.requestid == rp->requestid )
        {
            printf("basilisk_thread_start error trying to start requestid.%u which is already started\n",rp->requestid);
            break;
        }
    if ( i == myinfo->numswaps && i < sizeof(myinfo->swaps)/sizeof(*myinfo->swaps) )
    {
        swap = calloc(1,sizeof(*swap));
        swap->subsock = swap->pushsock = -1;
        vcalc_sha256(0,swap->I.orderhash.bytes,(uint8_t *)rp,sizeof(*rp));
        swap->I.req = *rp;
        swap->myinfoptr = myinfo;
        printf("basilisk_thread_start request.%u statebits.%d (%s/%s) reinit.%d\n",rp->requestid,statebits,rp->src,rp->dest,reinit);
        bitcoin_pubkey33(myinfo->ctx,pubkey33,privkey);
        pubkey25519 = curve25519(privkey,curve25519_basepoint9());
        swap->persistent_pubkey = pubkey25519;
        swap->persistent_privkey = privkey;
        memcpy(swap->persistent_pubkey33,pubkey33,33);
        m = n = 0;
        if ( bitcoin_swapinit(myinfo,privkey,pubkey33,pubkey25519,swap,optionduration,statebits,reinit) != 0 )
        {
            for (iter=0; iter<16; iter++)
            {
                basilisk_psockinit(myinfo,swap,statebits == 0);
                sleep(3);
                if ( swap->connected > 0 )
                    break;
                sleep(10);
                /*basilisk_sendstate(myinfo,swap,data,sizeof(data));
                basilisk_swapget(myinfo,swap,0x80000000,data,sizeof(data),basilisk_verify_statebits);
                if ( swap->connected > 0 )
                    break;
                printf("loopback didntwork with %d %d\n",swap->pushsock,swap->subsock);*/
            }
            if ( reinit != 0 )
            {
                if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)basilisk_swaploop,(void *)swap) != 0 )
                {
                    
                }
                myinfo->swaps[myinfo->numswaps++] = swap;
            }
            else
            {
                starttime = (uint32_t)time(NULL);
                printf("statebits.%x m.%d n.%d\n",statebits,m,n);
                while ( statebits == 0 && m <= n/2 && time(NULL) < starttime+7*BASILISK_MSGDURATION )
                {
                    uint32_t msgid; uint8_t data[1024]; int32_t datalen;
                    m = n = 0;
                    sleep(DEX_SLEEP);
                    printf("waiting for offer to be accepted\n");
                    channel = 'D' + ((uint32_t)'E' << 8) + ((uint32_t)'X' << 16);
                    datalen = basilisk_rwDEXquote(1,data,rp);
                    msgid = (uint32_t)time(NULL);
                    printf("other req.%d >>>>>>>>>>> send response (%llx -> %llx) last.%u r.%u quoteid.%u\n",i,(long long)rp->desthash.txid,(long long)rp->srchash.txid,myinfo->lastdexrequestid,rp->requestid,rp->quoteid);
                    dex_channelsend(myinfo,rp->desthash,rp->srchash,channel,msgid,data,datalen);
                    if ( (retarray= basilisk_channelget(myinfo,rp->srchash,rp->desthash,channel,0x4000000,30)) != 0 )
                    {
                        if ( is_cJSON_Array(retarray) != 0 && (n= cJSON_GetArraySize(retarray)) > 0 )
                        {
                            for (i=0; i<n; i++)
                            {
                                item = jitem(retarray,i);
                                if ( (msgobj= jarray(&n,item,"messages")) != 0 && n > 0 )
                                {
                                    item = jitem(msgobj,0);
                                    if ( jobj(item,"data") != 0 && jobj(item,"key") != 0 )
                                        m++;
                                    else printf("(%s)\n",jprint(item,0));
                                } //else printf("msgobj.%p m.%d n.%d\n",msgobj,m,n);
                            }
                        }
                    } else printf("no retarray\n");
                }
                printf("LAUNCH check.%d m.%d\n",statebits,m);
                if ( statebits != 0 || m > 0 )//n/2 )
                {
                    //for (i=0; i<sizeof(swap->I.req); i++)
                    //    fprintf(stderr,"%02x",((uint8_t *)&swap->I.req)[i]);
                    fprintf(stderr," M.%d N.%d launch.%d %d %p reinit.%d\n",m,n,myinfo->numswaps,(int32_t)(sizeof(myinfo->swaps)/sizeof(*myinfo->swaps)),&swap->I.req,reinit);
                    if ( (swap->fp= basilisk_swap_save(myinfo,swap,privkey,rp,statebits,optionduration,reinit)) != 0 )
                    {
                    }
                    if ( reinit == 0 )
                    {
                        if ( myinfo->swapsfp == 0 )
                        {
                            char fname[512];
                            sprintf(fname,"%s/SWAPS/list",GLOBAL_DBDIR), OS_compatible_path(fname);
                            if ( (myinfo->swapsfp= fopen(fname,"rb+")) == 0 )
                                myinfo->swapsfp = fopen(fname,"wb+");
                            else fseek(myinfo->swapsfp,0,SEEK_END);
                            printf("LIST fp.%p\n",myinfo->swapsfp);
                        }
                        if ( myinfo->swapsfp != 0 )
                        {
                            fwrite(&rp->requestid,1,sizeof(rp->requestid),myinfo->swapsfp);
                            fwrite(&rp->quoteid,1,sizeof(rp->quoteid),myinfo->swapsfp);
                            fflush(myinfo->swapsfp);
                        }
                    }
                    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)basilisk_swaploop,(void *)swap) != 0 )
                    {
                        
                    }
                    myinfo->swaps[myinfo->numswaps++] = swap;
                }
                else
                {
                    if ( statebits != 0 )
                    {
                        if ( (coin= iguana_coinfind(rp->src)) != 0 )
                        {
                            
                        }
                    }
                    printf("%u/%u offer wasnt accepted statebits.%d m.%d n.%d pending %.8f\n",rp->requestid,rp->quoteid,statebits,m,n,pending);
                }
            }
        }
    }
    portable_mutex_unlock(&myinfo->DEX_swapmutex);
    return(swap);
}

/////////////// remember functions

cJSON *basilisk_nullretjson(cJSON *retjson)
{
    char *outstr;
    if ( retjson != 0 )
    {
        outstr = jprint(retjson,0);
        if ( strcmp(outstr,"{}") == 0 )
        {
            free_json(retjson);
            retjson = 0;
        }
        free(outstr);
    }
    return(retjson);
}

cJSON *basilisk_swapgettxout(struct supernet_info *myinfo,char *symbol,bits256 trigger,int32_t vout)
{
    char *retstr; cJSON *retjson=0; struct iguana_info *coin;
    if ( ((coin= iguana_coinfind(symbol)) == 0 || coin->FULLNODE == 0) && iguana_isnotarychain(symbol) >= 0 )
    {
        if ( (retstr= dex_gettxout(myinfo,0,0,0,trigger,symbol,vout)) != 0 )
        {
            //printf("dexgettxout.(%s)\n",retstr);
            retjson = cJSON_Parse(retstr);
            free(retstr);
        }
        if ( 0 && strcmp("BTC",symbol) == 0 )
            printf("%s gettxout.(%s)\n",symbol,jprint(retjson,0));
    }
    else
    {
        retjson = dpow_gettxout(myinfo,coin,trigger,vout);
        //printf("need to verify passthru has this info\n");
        //printf("dpowgettxout.(%s)\n",jprint(retjson,0));
    }
    return(basilisk_nullretjson(retjson));
}

cJSON *basilisk_swapgettx(struct supernet_info *myinfo,char *symbol,bits256 txid)
{
    char *retstr; cJSON *retjson=0; struct iguana_info *coin;
    if ( ((coin= iguana_coinfind(symbol)) == 0 || coin->FULLNODE == 0) && iguana_isnotarychain(symbol) >= 0 )
    {
        if ( (retstr= dex_gettransaction(myinfo,0,0,0,txid,symbol)) != 0 )
        {
            retjson = cJSON_Parse(retstr);
            free(retstr);
        }
        //if ( strcmp("BTC",symbol) == 0 )
        //    printf("%s gettx.(%s)\n",symbol,jprint(retjson,0));
    } else retjson = dpow_gettransaction(myinfo,coin,txid);
    return(basilisk_nullretjson(retjson));
}

int32_t basilisk_swap_txdestaddr(char *destaddr,bits256 txid,int32_t vout,cJSON *txobj)
{
    int32_t n,m,retval = -1; cJSON *vouts,*item,*addresses,*skey; char *addr;
    if ( (vouts= jarray(&n,txobj,"vout")) != 0 && vout < n )
    {
        item = jitem(vouts,vout);
        if ( (skey= jobj(item,"scriptPubKey")) != 0 && (addresses= jarray(&m,skey,"addresses")) != 0 )
        {
            item = jitem(addresses,0);
            if ( (addr= jstr(item,0)) != 0 )
            {
                safecopy(destaddr,addr,64);
                retval = 0;
            }
            //printf("item.(%s) -> dest.(%s)\n",jprint(item,0),destaddr);
        }
    }
    return(retval);
}

int32_t basilisk_swap_getcoinaddr(struct supernet_info *myinfo,char *symbol,char *coinaddr,bits256 txid,int32_t vout)
{
    cJSON *retjson;
    coinaddr[0] = 0;
    if ( (retjson= basilisk_swapgettx(myinfo,symbol,txid)) != 0 )
    {
        basilisk_swap_txdestaddr(coinaddr,txid,vout,retjson);
        free_json(retjson);
    }
    return(coinaddr[0] != 0);
}

int32_t basilisk_swap_getsigscript(struct supernet_info *myinfo,char *symbol,uint8_t *script,int32_t maxlen,bits256 txid,int32_t vini)
{
    cJSON *retjson,*vins,*item,*skey; int32_t n,scriptlen = 0; char *hexstr;
    if ( (retjson= basilisk_swapgettx(myinfo,symbol,txid)) != 0 )
    {
        if ( (vins= jarray(&n,retjson,"vin")) != 0 && vini < n )
        {
            item = jitem(vins,vini);
            if ( (skey= jobj(item,"scriptSig")) != 0 && (hexstr= jstr(skey,"hex")) != 0 && (scriptlen= (int32_t)strlen(hexstr)) < maxlen*2 )
            {
                scriptlen >>= 1;
                decode_hex(script,scriptlen,hexstr);
                //char str[65]; printf("%s/v%d sigscript.(%s)\n",bits256_str(str,txid),vini,hexstr);
            }
        }
        free_json(retjson);
    }
    return(scriptlen);
}

int64_t basilisk_txvalue(struct supernet_info *myinfo,char *symbol,bits256 txid,int32_t vout)
{
    cJSON *txobj,*vouts,*item; int32_t n; int64_t value = 0;
    //char str[65]; printf("%s txvalue.(%s)\n",symbol,bits256_str(str,txid));
    if ( (txobj= basilisk_swapgettx(myinfo,symbol,txid)) != 0 )
    {
        //printf("txobj.(%s)\n",jprint(txobj,0));
        if ( (vouts= jarray(&n,txobj,"vout")) != 0 )
        {
            item = jitem(vouts,vout);
            if ( (value= jdouble(item,"amount") * SATOSHIDEN) == 0 )
                value = jdouble(item,"value") * SATOSHIDEN;
        }
        free_json(txobj);
    }
    return(value);
}

bits256 dex_swap_spendtxid(struct supernet_info *myinfo,char *symbol,char *destaddr,char *coinaddr,bits256 utxotxid,int32_t vout)
{
    char *retstr,*addr; cJSON *array,*item,*array2; int32_t i,n,m; bits256 spendtxid,txid;
    memset(&spendtxid,0,sizeof(spendtxid));
    if ( (retstr= dex_listtransactions(myinfo,0,0,0,symbol,coinaddr,100,0)) != 0 )
    {
        if ( (array= cJSON_Parse(retstr)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (item= jitem(array,i)) == 0 )
                        continue;
                    txid = jbits256(item,"txid");
                    if ( bits256_nonz(txid) == 0 )
                    {
                        if ( (array2= jarray(&m,item,"inputs")) != 0 && m == 1 )
                        {
                            //printf("found inputs with %s\n",bits256_str(str,spendtxid));
                            txid = jbits256(jitem(array2,0),"output_hash");
                            if ( bits256_cmp(txid,utxotxid) == 0 )
                            {
                                //printf("matched %s\n",bits256_str(str,txid));
                                if ( (array2= jarray(&m,item,"outputs")) != 0 && m == 1 && (addr= jstr(jitem(array2,0),"address")) != 0 )
                                {
                                    spendtxid = jbits256(item,"hash");
                                    strcpy(destaddr,addr);
                                    //printf("set spend addr.(%s) <- %s\n",addr,jprint(item,0));
                                    break;
                                }
                            }
                        }
                    }
                    else if ( bits256_cmp(txid,utxotxid) == 0 )
                    {
                        spendtxid = jbits256(item,"spendtxid");
                        if ( bits256_nonz(spendtxid) != 0 )
                        {
                            basilisk_swap_getcoinaddr(myinfo,symbol,destaddr,spendtxid,0);
                            //char str[65]; printf("found spendtxid.(%s) -> %s\n",bits256_str(str,spendtxid),destaddr);
                            break;
                        }
                    }
                }
            }
            free_json(array);
        }
        free(retstr);
    }
    return(spendtxid);
}
    
bits256 basilisk_swap_spendtxid(struct supernet_info *myinfo,char *symbol,char *destaddr,bits256 utxotxid,int32_t vout)
{
    bits256 spendtxid,txid; char *catstr,*addr; cJSON *array,*item,*item2,*txobj,*vins; int32_t i,n,m; char coinaddr[64],str[65]; struct iguana_info *coin = iguana_coinfind(symbol);
    // listtransactions or listspents
    destaddr[0] = 0;
    coinaddr[0] = 0;
    memset(&spendtxid,0,sizeof(spendtxid));
    //char str[65]; printf("swap %s spendtxid.(%s)\n",symbol,bits256_str(str,utxotxid));
    if ( (coin == 0 || coin->FULLNODE >= 0) && iguana_isnotarychain(symbol) >= 0 )
    {
        //[{"type":"sent","confirmations":379,"height":275311,"timestamp":1492084664,"txid":"8703c5517bc57db38134058370a14e99b8e662b99ccefa2061dea311bbd02b8b","vout":0,"amount":117.50945263,"spendtxid":"cf2509e076fbb9b22514923df916b7aacb1391dce9c7e1460b74947077b12510","vin":0,"paid":{"type":"paid","txid":"cf2509e076fbb9b22514923df916b7aacb1391dce9c7e1460b74947077b12510","height":275663,"timestamp":1492106024,"vouts":[{"RUDpN6PEBsE7ZFbGjUxk1W3QVsxnjBLYw6":117.50935263}]}}]
        basilisk_swap_getcoinaddr(myinfo,symbol,coinaddr,utxotxid,vout);
        if ( coinaddr[0] != 0 )
            spendtxid = dex_swap_spendtxid(myinfo,symbol,destaddr,coinaddr,utxotxid,vout);
    }
    else if ( coin != 0 )
    {
        if ( (array= dpow_listtransactions(myinfo,coin,destaddr,1000,0)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (item= jitem(array,i)) == 0 )
                        continue;
                    txid = jbits256(item,"txid");
                    if ( vout == juint(item,"vout") && bits256_cmp(txid,utxotxid) == 0 && (addr= jstr(item,"address")) != 0 )
                    {
                        if ( (catstr= jstr(item,"category")) != 0 )
                        {
                            if (strcmp(catstr,"send") == 0 )
                            {
                                strncpy(destaddr,addr,63);
                                //printf("(%s) <- (%s) item.%d.[%s]\n",destaddr,coinaddr,i,jprint(item,0));
                                if ( coinaddr[0] != 0 )
                                    break;
                            }
                            if (strcmp(catstr,"receive") == 0 )
                            {
                                strncpy(coinaddr,addr,63);
                                //printf("receive dest.(%s) <- (%s)\n",destaddr,coinaddr);
                                if ( destaddr[0] != 0 )
                                    break;
                            }
                        }
                    }
                }
            }
            free_json(array);
        }
        if ( destaddr[0] != 0 )
        {
            if ( (array= dpow_listtransactions(myinfo,coin,destaddr,1000,0)) != 0 )
            {
                if ( (n= cJSON_GetArraySize(array)) > 0 )
                {
                    for (i=0; i<n; i++)
                    {
                        if ( (item= jitem(array,i)) == 0 )
                            continue;
                        if ( (catstr= jstr(item,"category")) != 0 && strcmp(catstr,"send") == 0 )
                        {
                            txid = jbits256(item,"txid");
                            if ( (txobj= dpow_gettransaction(myinfo,coin,txid)) != 0 )
                            {
                                if ( (vins= jarray(&m,txobj,"vin")) != 0 && m > jint(item,"vout") )
                                {
                                    item2 = jitem(vins,jint(item,"vout"));
                                    if ( bits256_cmp(utxotxid,jbits256(item2,"txid")) == 0 && vout == jint(item2,"vout") )
                                    {
                                        spendtxid = txid;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if ( i == n )
                        printf("dpowlist: native couldnt find spendtxid for %s\n",bits256_str(str,utxotxid));
                }
                free_json(array);
            }
            if ( bits256_nonz(spendtxid) != 0 )
                return(spendtxid);
        }
        if ( iguana_isnotarychain(symbol) >= 0 )
        {
            basilisk_swap_getcoinaddr(myinfo,symbol,coinaddr,utxotxid,vout);
            printf("fallback use DEX for native (%s) (%s)\n",coinaddr,bits256_str(str,utxotxid));
            if ( coinaddr[0] != 0 )
            {
                spendtxid = dex_swap_spendtxid(myinfo,symbol,destaddr,coinaddr,utxotxid,vout);
                printf("spendtxid.(%s)\n",bits256_str(str,spendtxid));
            }
        }
    }
    return(spendtxid);
}

bits256 basilisk_swap_sendrawtransaction(struct supernet_info *myinfo,char *txname,char *symbol,char *txbytes)
{
    char *retstr; bits256 txid; int32_t i,sentflag = 0;
    memset(&txid,0,sizeof(txid));
    for (i=0; i<3; i++)
    {
        if ( (retstr= _dex_sendrawtransaction(myinfo,symbol,txbytes)) != 0 )
        {
            if ( is_hexstr(retstr,0) == 64 )
            {
                decode_hex(txid.bytes,32,retstr);
                sentflag = 1;
            }
            char str[65]; printf("[%s] %s RETSTR.(%s) %s.%s\n",txname,txbytes,retstr,symbol,bits256_str(str,txid));
            free(retstr);
        }
        if ( sentflag != 0 )
            break;
    }
    return(txid);
}

char *basilisk_swap_bobtxspend(char *name,struct supernet_info *myinfo,char *symbol,bits256 privkey,bits256 *privkey2p,uint8_t *redeemscript,int32_t redeemlen,uint8_t *userdata,int32_t userdatalen,bits256 utxotxid,int32_t vout,uint8_t *pubkey33,int32_t finalseqid,uint32_t expiration,int64_t *destamountp)
{
    char *rawtxbytes=0,*signedtx=0,str[65],hexstr[999],wifstr[128],destaddr[64]; uint8_t spendscript[512],addrtype,rmd160[20]; cJSON *utxoobj,*txobj,*vins,*item,*sobj,*privkeys; int32_t height,completed,spendlen,ignore_cltverr=1,suppress_pubkeys=1; struct vin_info *V; uint32_t timestamp,locktime = 0,sequenceid = 0xffffffff * finalseqid; struct iguana_info *coin; bits256 txid,signedtxid; uint64_t destamount;
    *destamountp = 0;
    if ( finalseqid == 0 )
        locktime = expiration;
    //printf("bobtxspend.%s redeem.[%d]\n",symbol,redeemlen);
    if ( redeemlen < 0 || (coin= iguana_coinfind(symbol)) == 0 )
        return(0);
    if ( (utxoobj= basilisk_swapgettxout(myinfo,symbol,utxotxid,vout)) == 0 )
    {
        printf("basilisk_swap_bobtxspend.%s utxo already spent or doesnt exist\n",name);
        return(0);
    }
    if ( (destamount= jdouble(utxoobj,"amount")*SATOSHIDEN) == 0 && (destamount= jdouble(utxoobj,"value")*SATOSHIDEN) == 0 )
    {
        printf("%s %s basilisk_swap_bobtxspend.%s strange utxo.(%s)\n",symbol,bits256_str(str,utxotxid),name,jprint(utxoobj,0));
        free_json(utxoobj);
        return(0);
    } else free_json(utxoobj);
    *destamountp = destamount;
    if ( destamount > 10000 )
        destamount -= 10000;
    if ( strcmp(symbol,"BTC") == 0 )
    {
        if ( destamount > 40000 )
            destamount -= 40000;
    }
    height = coin->longestchain;
    timestamp = (uint32_t)time(NULL);
    V = calloc(256,sizeof(*V));
    privkeys = cJSON_CreateArray();
    if ( privkey2p != 0 )
    {
        V[0].signers[1].privkey = *privkey2p;
        bitcoin_pubkey33(myinfo->ctx,V[0].signers[1].pubkey,*privkey2p);
        bitcoin_priv2wif(wifstr,*privkey2p,coin->chain->wiftype);
        jaddistr(privkeys,wifstr);
        V[0].N = V[0].M = 2;
    } else V[0].N = V[0].M = 1;
    V[0].signers[0].privkey = privkey;
    bitcoin_pubkey33(myinfo->ctx,V[0].signers[0].pubkey,privkey);
    bitcoin_priv2wif(wifstr,privkey,coin->chain->wiftype);
    jaddistr(privkeys,wifstr);
    V[0].suppress_pubkeys = suppress_pubkeys;
    V[0].ignore_cltverr = ignore_cltverr;
    if ( redeemlen != 0 )
        memcpy(V[0].p2shscript,redeemscript,redeemlen), V[0].p2shlen = redeemlen;
    txobj = bitcoin_txcreate(coin->symbol,coin->chain->isPoS,locktime,1,timestamp);
    vins = cJSON_CreateArray();
    item = cJSON_CreateObject();
    if ( userdata != 0 && userdatalen > 0 )
    {
        memcpy(V[0].userdata,userdata,userdatalen);
        V[0].userdatalen = userdatalen;
        init_hexbytes_noT(hexstr,userdata,userdatalen);
        jaddstr(item,"userdata",hexstr);
    }
    jaddbits256(item,"txid",utxotxid);
    jaddnum(item,"vout",vout);
    sobj = cJSON_CreateObject();
    bitcoin_address(destaddr,coin->chain->pubtype,pubkey33,33);
    bitcoin_addr2rmd160(&addrtype,rmd160,destaddr);
    /*int32_t i;
    for (i=0; i<33; i++)
        printf("%02x",pubkey33[i]);
    printf(" pubkey33 ->\n");
    for (i=0; i<20; i++)
        printf("%02x",rmd160[i]);
    printf(" destaddr.(%s)\n",destaddr);
    calc_rmd160_sha256(rmd160,pubkey33,33);
    for (i=0; i<20; i++)
        printf("%02x",rmd160[i]);
    printf(" <- vs direct calc\n");*/
    spendlen = bitcoin_standardspend(spendscript,0,rmd160);
    init_hexbytes_noT(hexstr,spendscript,spendlen);
    jaddstr(sobj,"hex",hexstr);
    jadd(item,"scriptPubKey",sobj);
    jaddnum(item,"suppress",suppress_pubkeys);
    jaddnum(item,"sequence",sequenceid);
    if ( redeemlen != 0 )
    {
        init_hexbytes_noT(hexstr,redeemscript,redeemlen);
        jaddstr(item,"redeemScript",hexstr);
    }
    jaddi(vins,item);
    jdelete(txobj,"vin");
    jadd(txobj,"vin",vins);
    txobj = bitcoin_txoutput(txobj,spendscript,spendlen,destamount);
    if ( (rawtxbytes= bitcoin_json2hex(myinfo,coin,&txid,txobj,V)) != 0 )
    {
        //printf("locktime.%u sequenceid.%x rawtx.(%s) vins.(%s)\n",locktime,sequenceid,rawtxbytes,jprint(vins,0));
        if ( (signedtx= iguana_signrawtx(myinfo,coin,height,&signedtxid,&completed,vins,rawtxbytes,privkeys,V)) == 0 )
            printf("couldnt sign transaction\n");
        else if ( completed == 0 )
            printf("incomplete signing\n");
        else printf("%s -> %s\n",name,bits256_str(str,signedtxid));
        free(rawtxbytes);
    } else printf("error making rawtx\n");
    free_json(privkeys);
    free_json(txobj);
    free(V);
    return(signedtx);
}

char *basilisk_swap_Aspend(char *name,struct supernet_info *myinfo,char *symbol,bits256 privAm,bits256 privBn,bits256 utxotxid,int32_t vout,uint8_t pubkey33[33],uint32_t expiration,int64_t *destamountp)
{
    char msigaddr[64],*signedtx = 0; int32_t spendlen,redeemlen; uint8_t tmp33[33],redeemscript[512],spendscript[128]; bits256 pubAm,pubBn; struct iguana_info *coin = iguana_coinfind(symbol);
    if ( coin != 0 && bits256_nonz(privAm) != 0 && bits256_nonz(privBn) != 0 )
    {
        pubAm = bitcoin_pubkey33(myinfo->ctx,tmp33,privAm);
        pubBn = bitcoin_pubkey33(myinfo->ctx,tmp33,privBn);
        //char str[65];
        //printf("pubAm.(%s)\n",bits256_str(str,pubAm));
        //printf("pubBn.(%s)\n",bits256_str(str,pubBn));
        spendlen = basilisk_alicescript(redeemscript,&redeemlen,spendscript,0,msigaddr,coin->chain->p2shtype,pubAm,pubBn);
        //char str[65]; printf("%s utxo.(%s) redeemlen.%d spendlen.%d\n",msigaddr,bits256_str(str,utxotxid),redeemlen,spendlen);
        /*rev = privAm;
        for (i=0; i<32; i++)
            privAm.bytes[i] = rev.bytes[31 - i];
        rev = privBn;
        for (i=0; i<32; i++)
            privBn.bytes[i] = rev.bytes[31 - i];*/
        signedtx = basilisk_swap_bobtxspend(name,myinfo,symbol,privAm,&privBn,redeemscript,redeemlen,0,0,utxotxid,vout,pubkey33,1,expiration,destamountp);
    }
    return(signedtx);
}

bits256 basilisk_swap_privbob_extract(struct supernet_info *myinfo,char *symbol,bits256 spendtxid,int32_t vini,int32_t revflag)
{
    bits256 privkey; int32_t i,scriptlen,siglen; uint8_t script[1024]; // from Bob refund of Bob deposit
    memset(&privkey,0,sizeof(privkey));
    if ( (scriptlen= basilisk_swap_getsigscript(myinfo,symbol,script,(int32_t)sizeof(script),spendtxid,vini)) > 0 )
    {
        siglen = script[0];
        for (i=0; i<32; i++)
        {
            if ( revflag != 0 )
                privkey.bytes[31 - i] = script[siglen+2+i];
            else privkey.bytes[i] = script[siglen+2+i];
        }
        char str[65]; printf("extracted privbob.(%s)\n",bits256_str(str,privkey));
    }
    return(privkey);
}

bits256 basilisk_swap_privBn_extract(struct supernet_info *myinfo,bits256 *bobrefundp,char *bobcoin,bits256 bobdeposit,bits256 privBn)
{
    char destaddr[64];
    if ( bits256_nonz(privBn) == 0 )
    {
        if ( bits256_nonz(bobdeposit) != 0 )
            *bobrefundp = basilisk_swap_spendtxid(myinfo,bobcoin,destaddr,bobdeposit,0);
        if ( bits256_nonz(*bobrefundp) != 0 )
            privBn = basilisk_swap_privbob_extract(myinfo,bobcoin,*bobrefundp,0,0);
    }
    return(privBn);
}

bits256 basilisk_swap_spendupdate(struct supernet_info *myinfo,char *symbol,int32_t *sentflags,bits256 *txids,int32_t utxoind,int32_t alicespent,int32_t bobspent,int32_t vout,char *aliceaddr,char *bobaddr)
{
    bits256 spendtxid,txid; char destaddr[64];
    txid = txids[utxoind];
    memset(&spendtxid,0,sizeof(spendtxid));
    /*if ( aliceaddr != 0 )
        printf("aliceaddr.(%s)\n",aliceaddr);
    if ( bobaddr != 0 )
        printf("bobaddr.(%s)\n",bobaddr);*/
    if ( bits256_nonz(txid) != 0 )
    {
        //char str[65];
        spendtxid = basilisk_swap_spendtxid(myinfo,symbol,destaddr,txid,vout);
        if ( bits256_nonz(spendtxid) != 0 )
        {
            sentflags[utxoind] = 1;
            if ( aliceaddr != 0 && strcmp(destaddr,aliceaddr) == 0 )
            {
                //printf("ALICE spent.(%s) -> %s\n",bits256_str(str,txid),destaddr);
                sentflags[alicespent] = 1;
                txids[alicespent] = spendtxid;
            }
            else if ( bobaddr != 0 && strcmp(destaddr,bobaddr) == 0 )
            {
                //printf("BOB spent.(%s) -> %s\n",bits256_str(str,txid),destaddr);
                sentflags[bobspent] = 1;
                txids[bobspent] = spendtxid;
            }
            else
            {
                //printf("OTHER dest spent.(%s) -> %s\n",bits256_str(str,txid),destaddr);
                if ( aliceaddr != 0 )
                {
                    sentflags[bobspent] = 1;
                    txids[bobspent] = spendtxid;
                }
                else if ( bobaddr != 0 )
                {
                    sentflags[alicespent] = 1;
                    txids[alicespent] = spendtxid;
                }
            }
        }
    } else printf("utxoind.%d null txid\n",utxoind);
    return(spendtxid);
}

#define BASILISK_ALICESPEND 0
#define BASILISK_BOBSPEND 1
#define BASILISK_BOBPAYMENT 2
#define BASILISK_ALICEPAYMENT 3
#define BASILISK_BOBDEPOSIT 4
#define BASILISK_OTHERFEE 5
#define BASILISK_MYFEE 6
#define BASILISK_BOBREFUND 7
#define BASILISK_BOBRECLAIM 8
#define BASILISK_ALICERECLAIM 9
#define BASILISK_ALICECLAIM 10
//0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0
char *txnames[] = { "alicespend", "bobspend", "bobpayment", "alicepayment", "bobdeposit", "otherfee", "myfee", "bobrefund", "bobreclaim", "alicereclaim", "aliceclaim" };

int32_t basilisk_isbobcoin(int32_t iambob,int32_t ind)
{
    switch ( ind  )
    {
        case BASILISK_MYFEE: return(iambob); break;
        case BASILISK_OTHERFEE: return(!iambob); break;
        case BASILISK_BOBSPEND:
        case BASILISK_ALICEPAYMENT:
        case BASILISK_ALICERECLAIM:
        case BASILISK_ALICECLAIM: return(0);
            break;
        case BASILISK_BOBDEPOSIT:
        case BASILISK_ALICESPEND:
        case BASILISK_BOBPAYMENT:
        case BASILISK_BOBREFUND:
        case BASILISK_BOBRECLAIM: return(1);
            break;
       default: return(-1); break;
    }
}

// add blocktrail presence requirement for BTC
int32_t basilisk_swap_isfinished(int32_t iambob,bits256 *txids,int32_t *sentflags,bits256 paymentspent,bits256 Apaymentspent,bits256 depositspent)
{
    int32_t i,n = 0;
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
        if ( i != BASILISK_OTHERFEE && i != BASILISK_MYFEE && sentflags[i] != 0 )
            n++;
    if ( n == 0 )
    {
        printf("if nothing sent, it is finished\n");
        return(1);
    }
    if ( iambob != 0 )
    {
        if ( bits256_nonz(txids[BASILISK_BOBDEPOSIT]) == 0 && sentflags[BASILISK_BOBDEPOSIT] == 0 )
            return(1);
        else if ( bits256_nonz(txids[BASILISK_BOBPAYMENT]) == 0 && sentflags[BASILISK_BOBPAYMENT] == 0 )
        {
            if ( bits256_nonz(depositspent) != 0 )
                return(1);
        }
        else if ( bits256_nonz(paymentspent) != 0 )
            return(1);
    }
    else
    {
        if ( bits256_nonz(txids[BASILISK_ALICEPAYMENT]) == 0 && sentflags[BASILISK_ALICEPAYMENT] == 0 )
            return(1);
        else
        {
            if ( sentflags[BASILISK_ALICERECLAIM] != 0 || sentflags[BASILISK_ALICESPEND] != 0 )
                return(1);
            else if ( sentflags[BASILISK_BOBSPEND] != 0 ) // without ALICECLAIM this is loss due to inactivity
                return(1);
        }
    }
    return(0);
}

cJSON *basilisk_remember(struct supernet_info *myinfo,int64_t *KMDtotals,int64_t *BTCtotals,uint32_t requestid,uint32_t quoteid)
{
    FILE *fp; struct iguana_info *coin; int32_t sentflags[sizeof(txnames)/sizeof(*txnames)],i,n,j,len,needflag,secretstart,redeemlen,addflag,origfinishedflag = 0,finishedflag = 0,iambob = -1; int64_t srcamount,destamount=0,value,values[sizeof(txnames)/sizeof(*txnames)]; uint8_t secretAm[20],secretAm256[32],secretBn[20],secretBn256[32],pubkey33[33],redeemscript[1024],userdata[1024]; uint32_t plocktime,dlocktime,expiration=0,r,q,state,otherstate; char *secretstr,*srcstr,*deststr,str[65],src[64],dest[64],fname[512],*fstr,*dest33,*symbol,*txname,*Adest,*Bdest,*AAdest,*ABdest,destaddr[64],Adestaddr[64],alicecoin[64],bobcoin[64],*txbytes[sizeof(txnames)/sizeof(*txnames)]; long fsize; cJSON *txobj,*item,*sentobj,*array; bits256 checktxid,txid,pubA0,pubB0,pubB1,privAm,privBn,paymentspent,Apaymentspent,depositspent,zero,privkey,rev,myprivs[2],txids[sizeof(txnames)/sizeof(*txnames)];
    memset(values,0,sizeof(values));
    memset(txids,0,sizeof(txids));
    memset(secretAm,0,sizeof(secretAm));
    memset(secretAm256,0,sizeof(secretAm256));
    memset(secretBn,0,sizeof(secretBn));
    memset(secretBn256,0,sizeof(secretBn256));
    memset(pubkey33,0,sizeof(pubkey33));
    memset(txbytes,0,sizeof(txbytes));
    memset(sentflags,0,sizeof(sentflags));
    memset(myprivs,0,sizeof(myprivs));
    Apaymentspent = paymentspent = depositspent = rev = zero = pubA0 = pubB0 = pubB1 = privAm = privBn = myprivs[0];
    plocktime = dlocktime = 0;
    src[0] = dest[0] = bobcoin[0] = alicecoin[0] = 0;
    sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
    if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
    {
        if ( (item= cJSON_Parse(fstr)) != 0 )
        {
            iambob = jint(item,"iambob");
            if ( (secretstr= jstr(item,"secretAm")) != 0 && strlen(secretstr) == 40 )
                decode_hex(secretAm,20,secretstr);
            if ( (secretstr= jstr(item,"secretAm256")) != 0 && strlen(secretstr) == 64 )
                decode_hex(secretAm256,32,secretstr);
            if ( (secretstr= jstr(item,"secretBn")) != 0 && strlen(secretstr) == 40 )
                decode_hex(secretBn,20,secretstr);
            if ( (secretstr= jstr(item,"secretBn256")) != 0 && strlen(secretstr) == 64 )
                decode_hex(secretBn256,32,secretstr);
            if ( (srcstr= jstr(item,"src")) != 0 )
                safecopy(src,srcstr,sizeof(src));
            if ( (deststr= jstr(item,"dest")) != 0 )
                safecopy(dest,deststr,sizeof(dest));
            if ( (dest33= jstr(item,"dest33")) != 0 && strlen(dest33) == 66 )
            {
                decode_hex(pubkey33,33,dest33);
                //for (i=0; i<33; i++)
                //    printf("%02x",pubkey33[i]);
                //printf(" <- %s dest33\n",dest33);
            }
            plocktime = juint(item,"plocktime");
            dlocktime = juint(item,"dlocktime");
            r = juint(item,"requestid");
            q = juint(item,"quoteid");
            pubA0 = jbits256(item,"pubA0");
            pubB0 = jbits256(item,"pubB0");
            pubB1 = jbits256(item,"pubB1");
            privkey = jbits256(item,"myprivs0");
            if ( bits256_nonz(privkey) != 0 )
                myprivs[0] = privkey;
            privkey = jbits256(item,"myprivs1");
            if ( bits256_nonz(privkey) != 0 )
                myprivs[1] = privkey;
            privkey = jbits256(item,"privAm");
            if ( bits256_nonz(privkey) != 0 )
            {
                privAm = privkey;
                //printf("set privAm <- %s\n",bits256_str(str,privAm));
            }
            privkey = jbits256(item,"privBn");
            if ( bits256_nonz(privkey) != 0 )
            {
                privBn = privkey;
                //printf("set privBn <- %s\n",bits256_str(str,privBn));
            }
            expiration = juint(item,"expiration");
            state = jint(item,"state");
            otherstate = jint(item,"otherstate");
            srcamount = SATOSHIDEN * jdouble(item,"srcamount");
            destamount = SATOSHIDEN * jdouble(item,"destamount");
            txids[BASILISK_BOBDEPOSIT] = jbits256(item,"Bdeposit");
            txids[BASILISK_BOBREFUND] = jbits256(item,"Brefund");
            txids[BASILISK_ALICECLAIM] = jbits256(item,"Aclaim");
            txids[BASILISK_BOBPAYMENT] = jbits256(item,"Bpayment");
            txids[BASILISK_ALICESPEND] = jbits256(item,"Aspend");
            txids[BASILISK_BOBRECLAIM] = jbits256(item,"Breclaim");
            txids[BASILISK_ALICEPAYMENT] = jbits256(item,"Apayment");
            txids[BASILISK_BOBSPEND] = jbits256(item,"Bspend");
            txids[BASILISK_ALICERECLAIM] = jbits256(item,"Areclaim");
            txids[BASILISK_MYFEE] = jbits256(item,"myfee");
            txids[BASILISK_OTHERFEE] = jbits256(item,"otherfee");
            free_json(item);
        }
        free(fstr);
    }
    sprintf(fname,"%s/SWAPS/%u-%u.finished",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
    if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
    {
        //printf("%s -> (%s)\n",fname,fstr);
        if ( (txobj= cJSON_Parse(fstr)) != 0 )
        {
            paymentspent = jbits256(txobj,"paymentspent");
            Apaymentspent = jbits256(txobj,"Apaymentspent");
            depositspent = jbits256(txobj,"depositspent");
            if ( (array= jarray(&n,txobj,"values")) != 0 )
                for (i=0; i<n&&i<sizeof(txnames)/sizeof(*txnames); i++)
                    values[i] = SATOSHIDEN * jdouble(jitem(array,i),0);
            if ( (array= jarray(&n,txobj,"sentflags")) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (txname= jstri(array,i)) != 0 )
                    {
                        for (j=0; j<sizeof(txnames)/sizeof(*txnames); j++)
                            if ( strcmp(txname,txnames[j]) == 0 )
                            {
                                sentflags[j] = 1;
                                //printf("finished.%s\n",txnames[j]);
                                break;
                            }
                    }
                }
            }
        }
        origfinishedflag = finishedflag = 1;
        free(fstr);
    }
    if ( iambob < 0 )
        return(0);
    item = cJSON_CreateObject();
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
    {
        needflag = addflag = 0;
        sprintf(fname,"%s/SWAPS/%u-%u.%s",GLOBAL_DBDIR,requestid,quoteid,txnames[i]), OS_compatible_path(fname);
        if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
        {
            if ( finishedflag == 0 )
                printf("%s\n",fname);
            //printf("%s -> (%s)\n",fname,fstr);
            if ( (txobj= cJSON_Parse(fstr)) != 0 )
            {
                //printf("TXOBJ.(%s)\n",jprint(txobj,0));
                iambob = jint(txobj,"iambob");
                txid = jbits256(txobj,"txid");
                if ( bits256_nonz(txid) == 0 )
                    continue;
                txids[i] = txid;
                if ( jobj(txobj,"tx") != 0 )
                {
                    txbytes[i] = clonestr(jstr(txobj,"tx"));
                    //printf("[%s] TX.(%s)\n",txnames[i],txbytes[i]);
                }
                if ( (value= jdouble(txobj,"amount") * SATOSHIDEN) == 0 )
                    value = jdouble(txobj,"value") * SATOSHIDEN;
                values[i] = value;
                if ( (symbol= jstr(txobj,"coin")) != 0 )
                {
                    if ( i == BASILISK_ALICESPEND || i == BASILISK_BOBPAYMENT || i == BASILISK_BOBDEPOSIT || i == BASILISK_BOBREFUND || i == BASILISK_BOBRECLAIM || i == BASILISK_ALICECLAIM )
                        safecopy(bobcoin,symbol,sizeof(bobcoin));
                    else if ( i == BASILISK_BOBSPEND || i == BASILISK_ALICEPAYMENT || i == BASILISK_ALICERECLAIM )
                        safecopy(alicecoin,symbol,sizeof(alicecoin));
                    if ( finishedflag == 0 )
                    {
                        if ( (sentobj= basilisk_swapgettx(myinfo,symbol,txid)) == 0 )
                        {
                            //printf("%s %s ready to broadcast\n",symbol,bits256_str(str2,txid));
                        }
                        else
                        {
                            checktxid = jbits256(sentobj,"txid");
                            if ( bits256_nonz(checktxid) == 0 )
                                checktxid = jbits256(sentobj,"hash");
                            if ( bits256_cmp(checktxid,txid) == 0 )
                            {
                                //printf(">>>>>> %s txid %s\n",jprint(sentobj,0),bits256_str(str,txid));
                                sentflags[i] = 1;
                            }
                            free_json(sentobj);
                        }
                        printf("%s %s %.8f\n",txnames[i],bits256_str(str,txid),dstr(value));
                    }
                }
            } //else printf("no symbol\n");
            free(fstr);
        } else if ( finishedflag == 0 )
            printf("%s not finished\n",fname);
    }
    //printf("iambob.%d src.%s dest.%s bob.%s alice.%s pubA0.(%s)\n",iambob,src,dest,bobcoin,alicecoin,bits256_str(str,pubA0));
    Adestaddr[0] = destaddr[0] = 0;
    Adest = Bdest = AAdest = ABdest = 0;
    if ( bobcoin[0] == 0 || alicecoin[0] == 0 )
        return(0);
    //printf("privAm.(%s) %p/%p\n",bits256_str(str,privAm),Adest,AAdest);
    //printf("privBn.(%s) %p/%p\n",bits256_str(str,privBn),Bdest,ABdest);
    if ( finishedflag == 0 && bobcoin[0] != 0 && alicecoin[0] != 0 )
    {
        if ( iambob == 0 )
        {
            if ( (coin= iguana_coinfind(alicecoin)) != 0 )
            {
                bitcoin_address(Adestaddr,coin->chain->pubtype,pubkey33,33);
                AAdest = Adestaddr;
            }
            if ( (coin= iguana_coinfind(bobcoin)) != 0 )
            {
                bitcoin_address(destaddr,coin->chain->pubtype,pubkey33,33);
                Adest = destaddr;
            }
        }
        else
        {
            if ( (coin= iguana_coinfind(bobcoin)) != 0 )
            {
                bitcoin_address(destaddr,coin->chain->pubtype,pubkey33,33);
                Bdest = destaddr;
            }
            if ( (coin= iguana_coinfind(alicecoin)) != 0 )
            {
                bitcoin_address(Adestaddr,coin->chain->pubtype,pubkey33,33);
                ABdest = Adestaddr;
            }
        }
        if ( sentflags[BASILISK_ALICEPAYMENT] == 0 && bits256_nonz(txids[BASILISK_ALICEPAYMENT]) != 0 )
        {
            printf("txbytes.%p Apayment.%s\n",txbytes[BASILISK_ALICEPAYMENT],bits256_str(str,txids[BASILISK_ALICEPAYMENT]));
            if ( txbytes[BASILISK_ALICEPAYMENT] != 0 )
                sentflags[BASILISK_ALICEPAYMENT] = 1;
            else if ( (sentobj= basilisk_swapgettx(myinfo,alicecoin,txids[BASILISK_ALICEPAYMENT])) != 0 )
            {
                sentflags[BASILISK_ALICEPAYMENT] = 1;
                free_json(sentobj);
            }
        }
        paymentspent = basilisk_swap_spendupdate(myinfo,bobcoin,sentflags,txids,BASILISK_BOBPAYMENT,BASILISK_ALICESPEND,BASILISK_BOBRECLAIM,0,Adest,Bdest);
        Apaymentspent = basilisk_swap_spendupdate(myinfo,alicecoin,sentflags,txids,BASILISK_ALICEPAYMENT,BASILISK_ALICERECLAIM,BASILISK_BOBSPEND,0,AAdest,ABdest);
        depositspent = basilisk_swap_spendupdate(myinfo,bobcoin,sentflags,txids,BASILISK_BOBDEPOSIT,BASILISK_ALICECLAIM,BASILISK_BOBREFUND,0,Adest,Bdest);
        finishedflag = basilisk_swap_isfinished(iambob,txids,sentflags,paymentspent,Apaymentspent,depositspent);
        if ( iambob == 0 )
        {
            if ( sentflags[BASILISK_ALICESPEND] == 0 )
            {
                if ( sentflags[BASILISK_BOBPAYMENT] != 0 && bits256_nonz(paymentspent) == 0 )
                {
                    //if ( txbytes[BASILISK_ALICESPEND] == 0 )
                    {
                        if ( bits256_nonz(txids[BASILISK_BOBPAYMENT]) != 0 )
                        {
                            // alicespend
                            for (j=0; j<32; j++)
                                rev.bytes[j] = privAm.bytes[31 - j];
                            revcalc_rmd160_sha256(secretAm,rev);//privAm);
                            vcalc_sha256(0,secretAm256,rev.bytes,sizeof(rev));
                            redeemlen = basilisk_swap_bobredeemscript(0,&secretstart,redeemscript,plocktime,pubA0,pubB0,pubB1,rev,privBn,secretAm,secretAm256,secretBn,secretBn256);
                            len = basilisk_swapuserdata(userdata,rev,0,myprivs[0],redeemscript,redeemlen);
                            printf("alicespend len.%d redeemlen.%d\n",len,redeemlen);
                            if ( (txbytes[BASILISK_ALICESPEND]= basilisk_swap_bobtxspend("alicespend",myinfo,bobcoin,myprivs[0],0,redeemscript,redeemlen,userdata,len,txids[BASILISK_BOBPAYMENT],0,pubkey33,1,expiration,&values[BASILISK_ALICESPEND])) != 0 )
                                printf("alicespend.(%s)\n",txbytes[BASILISK_ALICESPEND]);
                        }
                    }
                    if ( txbytes[BASILISK_ALICESPEND] != 0 )
                    {
                        txids[BASILISK_ALICESPEND] = basilisk_swap_sendrawtransaction(myinfo,"alicespend",bobcoin,txbytes[BASILISK_ALICESPEND]);
                        if ( bits256_nonz(txids[BASILISK_ALICESPEND]) != 0 ) // tested
                        {
                            sentflags[BASILISK_ALICESPEND] = 1;
                            paymentspent = txids[BASILISK_ALICESPEND];
                        }
                    }
                }
            }
            if ( sentflags[BASILISK_ALICECLAIM] == 0 && sentflags[BASILISK_BOBDEPOSIT] != 0 && bits256_nonz(txids[BASILISK_BOBDEPOSIT]) != 0 && bits256_nonz(depositspent) == 0 )
            {
                if ( time(NULL) > expiration )
                {
                    //if ( txbytes[BASILISK_ALICECLAIM] == 0 )
                    {
                        redeemlen = basilisk_swap_bobredeemscript(1,&secretstart,redeemscript,dlocktime,pubA0,pubB0,pubB1,privAm,zero,secretAm,secretAm256,secretBn,secretBn256);
                        if ( redeemlen > 0 )
                        {
                            len = basilisk_swapuserdata(userdata,zero,1,myprivs[0],redeemscript,redeemlen);
                            if ( (txbytes[BASILISK_ALICECLAIM]= basilisk_swap_bobtxspend("aliceclaim",myinfo,bobcoin,myprivs[0],0,redeemscript,redeemlen,userdata,len,txids[BASILISK_BOBDEPOSIT],0,pubkey33,0,expiration,&values[BASILISK_ALICECLAIM])) != 0 )
                                printf("privBn.(%s) aliceclaim.(%s)\n",bits256_str(str,privBn),txbytes[BASILISK_ALICECLAIM]);
                        }
                    }
                    if ( txbytes[BASILISK_ALICECLAIM] != 0 )
                    {
                        txids[BASILISK_ALICECLAIM] = basilisk_swap_sendrawtransaction(myinfo,"aliceclaim",bobcoin,txbytes[BASILISK_ALICECLAIM]);
                        if ( bits256_nonz(txids[BASILISK_ALICECLAIM]) != 0 ) // tested
                        {
                            sentflags[BASILISK_ALICECLAIM] = 1;
                            depositspent = txids[BASILISK_ALICECLAIM];
                        }
                    }
                } else printf("now %u before expiration %u\n",(uint32_t)time(NULL),expiration);
            }
            if ( sentflags[BASILISK_ALICEPAYMENT] != 0 && bits256_nonz(Apaymentspent) == 0 && sentflags[BASILISK_ALICECLAIM] == 0 )
            {
                //if ( txbytes[BASILISK_ALICERECLAIM] == 0 )
                {
                    privBn = basilisk_swap_privBn_extract(myinfo,&txids[BASILISK_BOBREFUND],bobcoin,txids[BASILISK_BOBDEPOSIT],privBn);
                    if ( bits256_nonz(txids[BASILISK_ALICEPAYMENT]) != 0 && bits256_nonz(privAm) != 0 && bits256_nonz(privBn) != 0 )
                    {
                        if ( (txbytes[BASILISK_ALICERECLAIM]= basilisk_swap_Aspend("alicereclaim",myinfo,alicecoin,privAm,privBn,txids[BASILISK_ALICEPAYMENT],0,pubkey33,expiration,&values[BASILISK_ALICERECLAIM])) != 0 )
                            printf("privBn.(%s) alicereclaim.(%s)\n",bits256_str(str,privBn),txbytes[BASILISK_ALICERECLAIM]);
                    }
                }
                if ( txbytes[BASILISK_ALICERECLAIM] != 0 )
                {
                    txids[BASILISK_ALICERECLAIM] = basilisk_swap_sendrawtransaction(myinfo,"alicereclaim",alicecoin,txbytes[BASILISK_ALICERECLAIM]);
                    if ( bits256_nonz(txids[BASILISK_ALICERECLAIM]) != 0 ) // tested
                    {
                        sentflags[BASILISK_ALICERECLAIM] = 1;
                        Apaymentspent = txids[BASILISK_ALICERECLAIM];
                    }
                }
            }
        }
        else if ( iambob == 1 )
        {
            if ( sentflags[BASILISK_BOBSPEND] == 0 && bits256_nonz(Apaymentspent) == 0 )
            {
                printf("try to bobspend aspend.%s have privAm.%d\n",bits256_str(str,txids[BASILISK_ALICESPEND]),bits256_nonz(privAm));
                if ( bits256_nonz(txids[BASILISK_ALICESPEND]) != 0 || bits256_nonz(privAm) != 0 )
                {
                    //if ( txbytes[BASILISK_BOBSPEND] == 0 )
                    {
                        if ( bits256_nonz(privAm) == 0 )
                        {
                            privAm = basilisk_swap_privbob_extract(myinfo,bobcoin,txids[BASILISK_ALICESPEND],0,1);
                        }
                        if ( bits256_nonz(privAm) != 0 && bits256_nonz(privBn) != 0 )
                        {
                            if ( (txbytes[BASILISK_BOBSPEND]= basilisk_swap_Aspend("bobspend",myinfo,alicecoin,privAm,privBn,txids[BASILISK_ALICEPAYMENT],0,pubkey33,expiration,&values[BASILISK_BOBSPEND])) != 0 )
                                printf("bobspend.(%s)\n",txbytes[BASILISK_BOBSPEND]);
                        }
                    }
                    if ( txbytes[BASILISK_BOBSPEND] != 0 )
                    {
                        txids[BASILISK_BOBSPEND] = basilisk_swap_sendrawtransaction(myinfo,"bobspend",alicecoin,txbytes[BASILISK_BOBSPEND]);
                        if ( bits256_nonz(txids[BASILISK_BOBSPEND]) != 0 ) // tested
                        {
                            sentflags[BASILISK_BOBSPEND] = 1;
                            Apaymentspent = txids[BASILISK_BOBSPEND];
                        }
                    }
                }
            }
            if ( sentflags[BASILISK_BOBRECLAIM] == 0 && sentflags[BASILISK_BOBPAYMENT] != 0 && bits256_nonz(txids[BASILISK_BOBPAYMENT]) != 0 && time(NULL) > expiration && bits256_nonz(paymentspent) == 0 )
            {
                //if ( txbytes[BASILISK_BOBRECLAIM] == 0 )
                {
                    // bobreclaim
                    redeemlen = basilisk_swap_bobredeemscript(0,&secretstart,redeemscript,plocktime,pubA0,pubB0,pubB1,zero,privBn,secretAm,secretAm256,secretBn,secretBn256);
                    if ( redeemlen > 0 )
                    {
                        len = basilisk_swapuserdata(userdata,zero,1,myprivs[1],redeemscript,redeemlen);
                        if ( (txbytes[BASILISK_BOBRECLAIM]= basilisk_swap_bobtxspend("bobrefund",myinfo,bobcoin,myprivs[1],0,redeemscript,redeemlen,userdata,len,txids[BASILISK_BOBPAYMENT],0,pubkey33,0,expiration,&values[BASILISK_BOBRECLAIM])) != 0 )
                        {
                            int32_t z;
                            for (z=0; z<20; z++)
                                printf("%02x",secretAm[z]);
                            printf(" secretAm, myprivs[1].(%s) bobreclaim.(%s)\n",bits256_str(str,myprivs[1]),txbytes[BASILISK_BOBRECLAIM]);
                        }
                    }
                }
                if ( txbytes[BASILISK_BOBRECLAIM] != 0 )
                {
                    txids[BASILISK_BOBRECLAIM] = basilisk_swap_sendrawtransaction(myinfo,"bobreclaim",bobcoin,txbytes[BASILISK_BOBRECLAIM]);
                    if ( bits256_nonz(txids[BASILISK_BOBRECLAIM]) != 0 ) // tested
                    {
                        sentflags[BASILISK_BOBRECLAIM] = 1;
                        paymentspent = txids[BASILISK_BOBRECLAIM];
                    }
                }
            }
            if ( sentflags[BASILISK_BOBREFUND] == 0 && sentflags[BASILISK_BOBDEPOSIT] != 0 && bits256_nonz(txids[BASILISK_BOBDEPOSIT]) != 0 && bits256_nonz(depositspent) == 0 )
            {
                if ( bits256_nonz(paymentspent) != 0 || time(NULL) > expiration )
                {
                    printf("do the refund!\n");
                    //if ( txbytes[BASILISK_BOBREFUND] == 0 )
                    {
                        revcalc_rmd160_sha256(secretBn,privBn);
                        vcalc_sha256(0,secretBn256,privBn.bytes,sizeof(privBn));
                        redeemlen = basilisk_swap_bobredeemscript(1,&secretstart,redeemscript,dlocktime,pubA0,pubB0,pubB1,privAm,privBn,secretAm,secretAm256,secretBn,secretBn256);
                        len = basilisk_swapuserdata(userdata,privBn,0,myprivs[0],redeemscript,redeemlen);
                        if ( (txbytes[BASILISK_BOBREFUND]= basilisk_swap_bobtxspend("bobrefund",myinfo,bobcoin,myprivs[0],0,redeemscript,redeemlen,userdata,len,txids[BASILISK_BOBDEPOSIT],0,pubkey33,1,expiration,&values[BASILISK_BOBREFUND])) != 0 )
                            printf("pubB1.(%s) bobrefund.(%s)\n",bits256_str(str,pubB1),txbytes[BASILISK_BOBREFUND]);
                    }
                    if ( txbytes[BASILISK_BOBREFUND] != 0 )
                    {
                        txids[BASILISK_BOBREFUND] = basilisk_swap_sendrawtransaction(myinfo,"bobrefund",bobcoin,txbytes[BASILISK_BOBREFUND]);
                        if ( bits256_nonz(txids[BASILISK_BOBREFUND]) != 0 ) // tested
                        {
                            sentflags[BASILISK_BOBREFUND] = 1;
                            depositspent = txids[BASILISK_BOBREFUND];
                        }
                    }
                } else printf("time %u vs expiration %u\n",(uint32_t)time(NULL),expiration);
            }
        }
    }
    //printf("finish.%d iambob.%d REFUND %d %d %d %d\n",finishedflag,iambob,sentflags[BASILISK_BOBREFUND] == 0,sentflags[BASILISK_BOBDEPOSIT] != 0,bits256_nonz(txids[BASILISK_BOBDEPOSIT]) != 0,bits256_nonz(depositspent) == 0);
    if ( sentflags[BASILISK_ALICESPEND] != 0 || sentflags[BASILISK_BOBRECLAIM] != 0 )
        sentflags[BASILISK_BOBPAYMENT] = 1;
    if ( sentflags[BASILISK_ALICERECLAIM] != 0 || sentflags[BASILISK_BOBSPEND] != 0 )
        sentflags[BASILISK_ALICEPAYMENT] = 1;
    if ( sentflags[BASILISK_ALICECLAIM] != 0 || sentflags[BASILISK_BOBREFUND] != 0 )
        sentflags[BASILISK_BOBDEPOSIT] = 1;
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
        if ( bits256_nonz(txids[i]) != 0 && values[i] == 0 )
            values[i] = basilisk_txvalue(myinfo,basilisk_isbobcoin(iambob,i) ? bobcoin : alicecoin,txids[i],0);
     if ( origfinishedflag == 0 )
    {
        printf("iambob.%d Apaymentspent.(%s) alice.%d bob.%d %s %.8f\n",iambob,bits256_str(str,Apaymentspent),sentflags[BASILISK_ALICERECLAIM],sentflags[BASILISK_BOBSPEND],alicecoin,dstr(values[BASILISK_ALICEPAYMENT]));
        printf("paymentspent.(%s) alice.%d bob.%d %s %.8f\n",bits256_str(str,paymentspent),sentflags[BASILISK_ALICESPEND],sentflags[BASILISK_BOBRECLAIM],bobcoin,dstr(values[BASILISK_BOBPAYMENT]));
        printf("depositspent.(%s) alice.%d bob.%d %s %.8f\n",bits256_str(str,depositspent),sentflags[BASILISK_ALICECLAIM],sentflags[BASILISK_BOBREFUND],bobcoin,dstr(values[BASILISK_BOBDEPOSIT]));
    }
    values[BASILISK_OTHERFEE] = 0;
    if ( iambob == 0 )
    {
        if ( strcmp(alicecoin,"BTC") == 0 )
        {
            BTCtotals[BASILISK_ALICEPAYMENT] -= values[BASILISK_ALICEPAYMENT] * sentflags[BASILISK_ALICEPAYMENT];
            BTCtotals[BASILISK_ALICERECLAIM] += values[BASILISK_ALICEPAYMENT] * sentflags[BASILISK_ALICERECLAIM];
            BTCtotals[BASILISK_MYFEE] -= values[BASILISK_MYFEE] * sentflags[BASILISK_MYFEE];
        }
        else if ( strcmp(alicecoin,"KMD") == 0 )
        {
            KMDtotals[BASILISK_ALICEPAYMENT] -= values[BASILISK_ALICEPAYMENT] * sentflags[BASILISK_ALICEPAYMENT];
            KMDtotals[BASILISK_ALICERECLAIM] += values[BASILISK_ALICEPAYMENT] * sentflags[BASILISK_ALICERECLAIM];
            KMDtotals[BASILISK_MYFEE] -= values[BASILISK_MYFEE] * sentflags[BASILISK_MYFEE];
        }
        if ( strcmp(bobcoin,"KMD") == 0 )
        {
            KMDtotals[BASILISK_ALICESPEND] += values[BASILISK_BOBPAYMENT] * sentflags[BASILISK_ALICESPEND];
            KMDtotals[BASILISK_ALICECLAIM] += values[BASILISK_BOBDEPOSIT] * sentflags[BASILISK_ALICECLAIM];
        }
        else if ( strcmp(bobcoin,"BTC") == 0 )
        {
            BTCtotals[BASILISK_ALICESPEND] += values[BASILISK_BOBPAYMENT] * sentflags[BASILISK_ALICESPEND];
            BTCtotals[BASILISK_ALICECLAIM] += values[BASILISK_BOBDEPOSIT] * sentflags[BASILISK_ALICECLAIM];
        }
    }
    else
    {
        if ( strcmp(bobcoin,"BTC") == 0 )
        {
            BTCtotals[BASILISK_BOBPAYMENT] -= values[BASILISK_BOBPAYMENT] * sentflags[BASILISK_BOBPAYMENT];
            BTCtotals[BASILISK_BOBDEPOSIT] -= values[BASILISK_BOBDEPOSIT] * sentflags[BASILISK_BOBDEPOSIT];
            BTCtotals[BASILISK_BOBREFUND] += values[BASILISK_BOBREFUND] * sentflags[BASILISK_BOBREFUND];
            BTCtotals[BASILISK_BOBRECLAIM] += values[BASILISK_BOBRECLAIM] * sentflags[BASILISK_BOBRECLAIM];
            BTCtotals[BASILISK_MYFEE] -= values[BASILISK_MYFEE] * sentflags[BASILISK_MYFEE];
        }
        else if ( strcmp(bobcoin,"KMD") == 0 )
        {
            KMDtotals[BASILISK_BOBPAYMENT] -= values[BASILISK_BOBPAYMENT] * sentflags[BASILISK_BOBPAYMENT];
            KMDtotals[BASILISK_BOBDEPOSIT] -= values[BASILISK_BOBDEPOSIT] * sentflags[BASILISK_BOBDEPOSIT];
            KMDtotals[BASILISK_BOBREFUND] += values[BASILISK_BOBDEPOSIT] * sentflags[BASILISK_BOBREFUND];
            KMDtotals[BASILISK_BOBRECLAIM] += values[BASILISK_BOBPAYMENT] * sentflags[BASILISK_BOBRECLAIM];
            KMDtotals[BASILISK_MYFEE] -= values[BASILISK_MYFEE] * sentflags[BASILISK_MYFEE];
        }
        if ( strcmp(alicecoin,"KMD") == 0 )
        {
            KMDtotals[BASILISK_BOBSPEND] += values[BASILISK_BOBSPEND] * sentflags[BASILISK_BOBSPEND];
        }
        else if ( strcmp(alicecoin,"BTC") == 0 )
        {
            BTCtotals[BASILISK_BOBSPEND] += values[BASILISK_ALICEPAYMENT] * sentflags[BASILISK_BOBSPEND];
        }
    }
    finishedflag = basilisk_swap_isfinished(iambob,txids,sentflags,paymentspent,Apaymentspent,depositspent);
    jaddnum(item,"requestid",requestid);
    jaddnum(item,"quoteid",quoteid);
    jadd(item,"txs",array);
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
    {
        if ( sentflags[i] != 0 )
            jaddistr(array,txnames[i]);
        if ( txbytes[i] != 0 )
            free(txbytes[i]);
    }
    jadd(item,"sentflags",array);
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
        jaddinum(array,dstr(values[i]));
    jadd(item,"values",array);
    jaddstr(item,"result","success");
    if ( finishedflag != 0 )
        jaddstr(item,"status","finished");
    else jaddstr(item,"status","pending");
    bits256_str(str,paymentspent), jaddbits256(item,"paymentspent",paymentspent);
    bits256_str(str,Apaymentspent), jaddbits256(item,"Apaymentspent",Apaymentspent);
    bits256_str(str,depositspent), jaddbits256(item,"depositspent",depositspent);
    if ( origfinishedflag == 0 && finishedflag != 0 )
    {
        //printf("SWAP %u-%u finished!\n",requestid,quoteid);
        sprintf(fname,"%s/SWAPS/%u-%u.finished",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
        if ( (fp= fopen(fname,"wb")) != 0 )
        {
            char *itemstr;
            itemstr = jprint(item,0);
            fprintf(fp,"%s\n",itemstr);
            free(itemstr);
            fclose(fp);
        }
    }
    return(item);
}

char *basilisk_swaplist(struct supernet_info *myinfo)
{
    char fname[512],*status; FILE *fp; cJSON *item,*retjson,*array,*totalsobj; uint32_t quoteid,requestid; int64_t KMDtotals[16],BTCtotals[16],Btotal,Ktotal; int32_t i;
    memset(KMDtotals,0,sizeof(KMDtotals));
    memset(BTCtotals,0,sizeof(BTCtotals));
    //,statebits; int32_t optionduration; struct basilisk_request R; bits256 privkey;
    retjson = cJSON_CreateObject();
    array = cJSON_CreateArray();
    sprintf(fname,"%s/SWAPS/list",GLOBAL_DBDIR), OS_compatible_path(fname);
    if ( (fp= fopen(fname,"rb")) != 0 )
    {
        struct basilisk_swap *swap; int32_t flag = 0;
        while ( fread(&requestid,1,sizeof(requestid),fp) == sizeof(requestid) && fread(&quoteid,1,sizeof(quoteid),fp) == sizeof(quoteid) )
        {
            flag = 0;
            for (i=0; i<myinfo->numswaps; i++)
                if ( (swap= myinfo->swaps[i]) != 0 && swap->I.req.requestid == requestid && swap->I.req.quoteid == quoteid )
                {
                    jaddi(array,basilisk_swapjson(myinfo,swap));
                    flag = 1;
                    break;
                }
            if ( flag == 0 )
            {
                if ( (item= basilisk_remember(myinfo,KMDtotals,BTCtotals,requestid,quoteid)) != 0 )
                {
                    jaddi(array,item);
                    if ( 1 && (status= jstr(item,"status")) != 0 && strcmp(status,"pending") == 0 )
                        break;
                }
            }
        }
        fclose(fp);
    }
    jaddstr(retjson,"result","success");
    jadd(retjson,"swaps",array);
    if ( cJSON_GetArraySize(array) > 0 )
    {
        totalsobj = cJSON_CreateObject();
        for (Btotal=i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
            if ( BTCtotals[i] != 0 )
                jaddnum(totalsobj,txnames[i],dstr(BTCtotals[i])), Btotal += BTCtotals[i];
        jadd(retjson,"BTCtotals",totalsobj);
        totalsobj = cJSON_CreateObject();
        for (Ktotal=i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
            if ( KMDtotals[i] != 0 )
                jaddnum(totalsobj,txnames[i],dstr(KMDtotals[i])), Ktotal += KMDtotals[i];
        jadd(retjson,"KMDtotals",totalsobj);
        jaddnum(retjson,"KMDtotal",dstr(Ktotal));
        jaddnum(retjson,"BTCtotal",dstr(Btotal));
        if ( Ktotal > 0 && Btotal < 0 )
            jaddnum(retjson,"avebuy",(double)-Btotal/Ktotal);
        else if ( Ktotal < 0 && Btotal > 0 )
                jaddnum(retjson,"avesell",(double)-Btotal/Ktotal);
    }
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(myinfo->linfos)/sizeof(*myinfo->linfos); i++)
    {
        if ( myinfo->linfos[i].base[0] != 0 && myinfo->linfos[i].rel[0] != 0 )
            jaddi(array,linfo_json(&myinfo->linfos[i]));
    }
    jadd(retjson,"quotes",array);
    return(jprint(retjson,1));
}


