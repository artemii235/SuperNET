
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
//  LP_swap.c
//  marketmaker
//



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

/*
 both fees are standard payments: OP_DUP OP_HASH160 FEE_RMD160 OP_EQUALVERIFY OP_CHECKSIG
 
 
 Bob deposit:
 OP_IF
 <now + LOCKTIME*2> OP_CLTV OP_DROP <alice_pubA0> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(bob_privN)> OP_EQUALVERIFY <bob_pubB0> OP_CHECKSIG
 OP_ENDIF
 
 Alice altpayment: OP_2 <alice_pubM> <bob_pubN> OP_2 OP_CHECKMULTISIG

 Bob paytx:
 OP_IF
 <now + LOCKTIME> OP_CLTV OP_DROP <bob_pubB1> OP_CHECKSIG
 OP_ELSE
 OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY <alice_pubA0> OP_CHECKSIG
 OP_ENDIF
 
 Naming convention are pubAi are alice's pubkeys (seems only pubA0 and not pubA1)
 pubBi are Bob's pubkeys
 
 privN is Bob's privkey from the cut and choose deck as selected by Alice
 privM is Alice's counterpart
 pubN and pubM are the corresponding pubkeys for these chosen privkeys
 
 Alice timeout event is triggered if INSTANTDEX_LOCKTIME elapses from the start of a FSM instance. Bob timeout event is triggered after INSTANTDEX_LOCKTIME*2
 
 Based on https://gist.github.com/markblundeberg/7a932c98179de2190049f5823907c016 and to enable bob to spend alicepayment when alice does a claim for bob deposit, the scripts are changed to the following:
 
 Bob deposit:
 OP_IF
 OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY <now + INSTANTDEX_LOCKTIME*2> OP_CLTV OP_DROP <alice_pubA0> OP_CHECKSIG
 OP_ELSE
 OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <hash(bob_privN)> OP_EQUALVERIFY <bob_pubB0> OP_CHECKSIG
 OP_ENDIF
 
 Bob paytx:
 OP_IF
 <now + INSTANTDEX_LOCKTIME> OP_CLTV OP_DROP <bob_pubB1> OP_CHECKSIG
 OP_ELSE
 OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <hash(alice_privM)> OP_EQUALVERIFY <alice_pubA0> OP_CHECKSIG
 OP_ENDIF

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
#define TX_WAIT_TIMEOUT 1800 // hard to increase this without hitting protocol limits (2/4 hrs)

uint32_t LP_atomic_locktime(char *base,char *rel)
{
    if ( strcmp(base,"BTC") == 0 && strcmp(rel,"BTC") == 0 )
        return(INSTANTDEX_LOCKTIME * 10);
    else if ( LP_is_slowcoin(base) > 0 || LP_is_slowcoin(rel) > 0 )
        return(INSTANTDEX_LOCKTIME * 4);
    else return(INSTANTDEX_LOCKTIME);
}

void basilisk_rawtx_purge(struct basilisk_rawtx *rawtx)
{
    if ( rawtx->vins != 0 )
        free_json(rawtx->vins), rawtx->vins = 0;
    //if ( rawtx->txbytes != 0 )
    //    free(rawtx->txbytes), rawtx->txbytes = 0;
}

void basilisk_swap_finished(struct basilisk_swap *swap)
{
    /*int32_t i;
    if ( swap->utxo != 0 && swap->sentflag == 0 )
    {
        LP_availableset(swap->utxo);
        swap->utxo = 0;
        //LP_butxo_swapfields_set(swap->utxo);
    }
    swap->I.finished = (uint32_t)time(NULL);*/
    if ( swap->I.finished == 0 )
    {
        if ( swap->I.iambob != 0 )
        {
            LP_availableset(swap->bobdeposit.utxotxid,swap->bobdeposit.utxovout);
            LP_availableset(swap->bobpayment.utxotxid,swap->bobpayment.utxovout);
        }
        else
        {
            LP_availableset(swap->alicepayment.utxotxid,swap->alicepayment.utxovout);
            LP_availableset(swap->myfee.utxotxid,swap->myfee.utxovout);
        }
    }
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
    /*for (i=0; i<swap->nummessages; i++)
        if ( swap->messages[i].data != 0 )
            free(swap->messages[i].data), swap->messages[i].data = 0;
    free(swap->messages), swap->messages = 0;
    swap->nummessages = 0;*/
    if ( swap->N.pair >= 0 )
        nn_close(swap->N.pair), swap->N.pair = -1;
}

uint32_t basilisk_quoteid(struct basilisk_request *rp)
{
    struct basilisk_request R;
    R = *rp;
    R.unused = R.requestid = R.quoteid = R.DEXselector = 0;
    return(calc_crc32(0,(void *)&R,sizeof(R)));
}

uint32_t basilisk_requestid(struct basilisk_request *rp)
{
    struct basilisk_request R;
    R = *rp;
    R.requestid = R.quoteid = R.quotetime = R.DEXselector = 0;
    R.destamount = R.unused = 0;
    memset(R.desthash.bytes,0,sizeof(R.desthash.bytes));
    if ( 0 )
    {
        int32_t i;
        for (i=0; i<sizeof(R); i++)
            printf("%02x",((uint8_t *)&R)[i]);
        printf(" <- crc.%u\n",calc_crc32(0,(void *)&R,sizeof(R)));
        char str[65],str2[65]; printf("B REQUESTID: t.%u r.%u q.%u %s %.8f %s -> %s %.8f %s crc.%u q%u\n",R.timestamp,R.requestid,R.quoteid,R.src,dstr(R.srcamount),bits256_str(str,R.srchash),R.dest,dstr(R.destamount),bits256_str(str2,R.desthash),calc_crc32(0,(void *)&R,sizeof(R)),basilisk_quoteid(&R));
    }
    return(calc_crc32(0,(void *)&R,sizeof(R)));
}

int32_t LP_pubkeys_data(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,datalen = 0;
    datalen += iguana_rwnum(1,&data[datalen],sizeof(swap->I.req.requestid),&swap->I.req.requestid);
    datalen += iguana_rwnum(1,&data[datalen],sizeof(swap->I.req.quoteid),&swap->I.req.quoteid);
    data[datalen++] = swap->I.aliceconfirms;
    data[datalen++] = swap->I.bobconfirms;
    data[datalen++] = swap->I.alicemaxconfirms;
    data[datalen++] = swap->I.bobmaxconfirms;
    data[datalen++] = swap->I.otheristrusted;
    for (i=0; i<33; i++)
        data[datalen++] = swap->persistent_pubkey33[i];
    for (i=0; i<sizeof(swap->deck)/sizeof(swap->deck[0][0]); i++)
        datalen += iguana_rwnum(1,&data[datalen],sizeof(swap->deck[i>>1][i&1]),&swap->deck[i>>1][i&1]);
    //printf("send >>>>>>>>> r.%u q.%u datalen.%d\n",swap->I.req.requestid,swap->I.req.quoteid,datalen);
    return(datalen);
}

int32_t LP_pubkeys_verify(struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    uint32_t requestid,quoteid; int32_t i,nonz=0,alicemaxconfirms,bobmaxconfirms,aliceconfirms,bobconfirms,len = 0; uint8_t other33[33];
    if ( datalen == sizeof(swap->otherdeck)+38+sizeof(uint32_t)*2 )
    {
        len += iguana_rwnum(0,&data[len],sizeof(requestid),&requestid);
        len += iguana_rwnum(0,&data[len],sizeof(quoteid),&quoteid);
        if ( requestid != swap->I.req.requestid || quoteid != swap->I.req.quoteid )
        {
            printf("SWAP requestid.%u quoteid.%u mismatch received r.%u q.%u\n",swap->I.req.requestid,swap->I.req.quoteid,requestid,quoteid);
            return(-1);
        }
        aliceconfirms = data[len++];
        bobconfirms = data[len++];
        alicemaxconfirms = data[len++];
        bobmaxconfirms = data[len++];
        if ( aliceconfirms != swap->I.aliceconfirms || bobconfirms != swap->I.bobconfirms )
        {
            printf("MISMATCHED required confirms me.(%d %d) vs (%d %d) max.(%d %d) othermax.(%d %d)\n",swap->I.aliceconfirms,swap->I.bobconfirms,aliceconfirms,bobconfirms,swap->I.alicemaxconfirms,swap->I.bobmaxconfirms,alicemaxconfirms,bobmaxconfirms);
            if ( alicemaxconfirms > swap->I.alicemaxconfirms )
                alicemaxconfirms = swap->I.alicemaxconfirms;
            if ( bobmaxconfirms > swap->I.bobmaxconfirms )
                bobmaxconfirms = swap->I.bobmaxconfirms;
            if ( swap->I.aliceconfirms < aliceconfirms )
                swap->I.aliceconfirms = aliceconfirms;
            if ( swap->I.bobconfirms < bobconfirms )
                swap->I.bobconfirms = bobconfirms;
            if ( swap->I.aliceconfirms > swap->I.alicemaxconfirms || swap->I.bobconfirms > swap->I.bobmaxconfirms )
            {
                printf("numconfirms (%d %d) exceeds max (%d %d)\n",swap->I.aliceconfirms,swap->I.bobconfirms,swap->I.alicemaxconfirms,swap->I.bobmaxconfirms);
                return(-1);
            }
        }
        if ( (swap->I.otherstrust= data[len++]) != 0 )
        {
            if ( swap->I.otheristrusted != 0 )
            {
                swap->I.aliceconfirms = swap->I.bobconfirms = 0;
                printf("mutually trusted swap, adjust required confirms to: alice.%d bob.%d\n",swap->I.aliceconfirms,swap->I.bobconfirms);
            }
        }
        printf("NUMCONFIRMS for SWAP alice.%d bob.%d, otheristrusted.%d othertrusts.%d\n",swap->I.aliceconfirms,swap->I.bobconfirms,swap->I.otheristrusted,swap->I.otherstrust);
        for (i=0; i<33; i++)
            if ( (other33[i]= data[len++]) != 0 )
                nonz++;
        if ( nonz > 8 )
            memcpy(swap->persistent_other33,other33,33);
        for (i=0; i<sizeof(swap->otherdeck)/sizeof(swap->otherdeck[0][0]); i++)
            len += iguana_rwnum(0,&data[len],sizeof(swap->otherdeck[i>>1][i&1]),&swap->otherdeck[i>>1][i&1]);
        return(0);
    }
    printf("pubkeys verify size mismatch %d != %d\n",datalen,(int32_t)(sizeof(swap->otherdeck)+38+sizeof(uint32_t)*2));
    return(-1);
}

int32_t LP_choosei_data(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
{
    int32_t i,datalen; //char str[65];
    datalen = iguana_rwnum(1,data,sizeof(swap->I.choosei),&swap->I.choosei);
    if ( swap->I.iambob != 0 )
    {
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubB0.bytes[i];
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubB1.bytes[i];
        //printf("SEND pubB0/1 %s\n",bits256_str(str,swap->I.pubB0));
    }
    else
    {
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubA0.bytes[i];
        for (i=0; i<32; i++)
            data[datalen++] = swap->I.pubA1.bytes[i];
        //printf("SEND pubA0/1 %s\n",bits256_str(str,swap->I.pubA0));
    }
    return(datalen);
}

int32_t LP_choosei_verify(struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    int32_t otherchoosei=-1,i,len = 0; uint8_t pubkey33[33];
    if ( datalen == sizeof(otherchoosei)+sizeof(bits256)*2 )
    {
        len += iguana_rwnum(0,data,sizeof(otherchoosei),&otherchoosei);
        if ( otherchoosei >= 0 && otherchoosei < INSTANTDEX_DECKSIZE )
        {
            swap->I.otherchoosei = otherchoosei;
            if ( swap->I.iambob != 0 )
            {
                for (i=0; i<32; i++)
                    swap->I.pubA0.bytes[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->I.pubA1.bytes[i] = data[len++];
                //printf("GOT pubA0/1 %s\n",bits256_str(str,swap->I.pubA0));
                swap->I.privBn = swap->privkeys[swap->I.otherchoosei];
                memset(&swap->privkeys[swap->I.otherchoosei],0,sizeof(swap->privkeys[swap->I.otherchoosei]));
                revcalc_rmd160_sha256(swap->I.secretBn,swap->I.privBn);//.bytes,sizeof(swap->privBn));
                vcalc_sha256(0,swap->I.secretBn256,swap->I.privBn.bytes,sizeof(swap->I.privBn));
                swap->I.pubBn = bitcoin_pubkey33(swap->ctx,pubkey33,swap->I.privBn);
                //printf("set privBn.%s %s\n",bits256_str(str,swap->I.privBn),bits256_str(str2,*(bits256 *)swap->I.secretBn256));
                //basilisk_bobscripts_set(swap,1,1);
            }
            else
            {
                for (i=0; i<32; i++)
                    swap->I.pubB0.bytes[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->I.pubB1.bytes[i] = data[len++];
                //printf("GOT pubB0/1 %s\n",bits256_str(str,swap->I.pubB0));
                swap->I.privAm = swap->privkeys[swap->I.otherchoosei];
                memset(&swap->privkeys[swap->I.otherchoosei],0,sizeof(swap->privkeys[swap->I.otherchoosei]));
                revcalc_rmd160_sha256(swap->I.secretAm,swap->I.privAm);//.bytes,sizeof(swap->privAm));
                vcalc_sha256(0,swap->I.secretAm256,swap->I.privAm.bytes,sizeof(swap->I.privAm));
                swap->I.pubAm = bitcoin_pubkey33(swap->ctx,pubkey33,swap->I.privAm);
                //printf("set privAm.%s %s\n",bits256_str(str,swap->I.privAm),bits256_str(str2,*(bits256 *)swap->I.secretAm256));
                swap->bobdeposit.I.pubkey33[0] = 2;
                swap->bobpayment.I.pubkey33[0] = 2;
                for (i=0; i<32; i++)
                    swap->bobpayment.I.pubkey33[i+1] = swap->bobdeposit.I.pubkey33[i+1] = swap->I.pubA0.bytes[i];
                //printf("SET bobdeposit pubkey33.(02%s)\n",bits256_str(str,swap->I.pubA0));
                //basilisk_bobscripts_set(swap,0);
            }
            return(0);
        }
    }
    printf("illegal otherchoosei.%d datalen.%d vs %d\n",otherchoosei,datalen,(int32_t)(sizeof(otherchoosei)+sizeof(bits256)*2));
    return(-1);
}

int32_t LP_mostprivs_data(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen)
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
    return(datalen);
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

int32_t basilisk_verify_privi(void *ptr,uint8_t *data,int32_t datalen)
{
    int32_t j,wrongfirstbyte,len = 0; bits256 privkey,pubi; char str[65],str2[65]; uint8_t secret160[20],pubkey33[33]; uint64_t txid; struct basilisk_swap *swap = ptr;
    memset(privkey.bytes,0,sizeof(privkey));
    if ( datalen == sizeof(bits256) )
    {
        for (j=0; j<32; j++)
            privkey.bytes[j] = data[len++];
        revcalc_rmd160_sha256(secret160,privkey);//.bytes,sizeof(privkey));
        memcpy(&txid,secret160,sizeof(txid));
        pubi = bitcoin_pubkey33(swap->ctx,pubkey33,privkey);
        if ( basilisk_verify_pubpair(&wrongfirstbyte,swap,swap->I.choosei,pubkey33[0],pubi,txid) == 0 )
        {
            if ( swap->I.iambob != 0 )
            {
                swap->I.privAm = privkey;
                vcalc_sha256(0,swap->I.secretAm256,privkey.bytes,sizeof(privkey));
                printf("set privAm.%s %s\n",bits256_str(str,swap->I.privAm),bits256_str(str2,*(bits256 *)swap->I.secretAm256));
                basilisk_bobscripts_set(swap,0,1);
            }
            else
            {
                swap->I.privBn = privkey;
                vcalc_sha256(0,swap->I.secretBn256,privkey.bytes,sizeof(privkey));
                printf("set privBn.%s %s\n",bits256_str(str,swap->I.privBn),bits256_str(str2,*(bits256 *)swap->I.secretBn256));
            }
            basilisk_dontforget_update(swap,0);
            char str[65]; printf("privi verified.(%s)\n",bits256_str(str,privkey));
            return(0);
        } else printf("pubpair doesnt verify privi\n");
    } else printf("verify privi size mismatch %d != %d\n",datalen,(int32_t)sizeof(bits256));
    return(-1);
}

int32_t LP_mostprivs_verify(struct basilisk_swap *swap,uint8_t *data,int32_t datalen)
{
    int32_t i,j,wrongfirstbyte=0,errs=0,len = 0; bits256 otherpriv,pubi; uint8_t secret160[20],otherpubkey[33]; uint64_t txid;
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
                pubi = bitcoin_pubkey33(swap->ctx,otherpubkey,otherpriv);
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
                //basilisk_bobscripts_set(swap,1,1);
            }
            else
            {
                for (i=0; i<32; i++)
                    swap->I.pubBn.bytes[i] = data[len++];
                for (i=0; i<20; i++)
                    swap->I.secretBn[i] = data[len++];
                for (i=0; i<32; i++)
                    swap->I.secretBn256[i] = data[len++];
                //basilisk_bobscripts_set(swap,0);
            }
        } else printf("failed verification: wrong firstbyte.%d errs.%d\n",wrongfirstbyte,errs);
    }
    //printf("privkeys errs.%d wrongfirstbyte.%d\n",errs,wrongfirstbyte);
    return(errs);
}

int32_t LP_waitfor(int32_t pairsock,struct basilisk_swap *swap,int32_t timeout,int32_t (*verify)(struct basilisk_swap *swap,uint8_t *data,int32_t datalen))
{
    struct nn_pollfd pfd; void *data; int32_t datalen,retval = -1; uint32_t expiration = (uint32_t)time(NULL) + timeout;
    while ( time(NULL) < expiration )
    {
        memset(&pfd,0,sizeof(pfd));
        pfd.fd = pairsock;
        pfd.events = NN_POLLIN;
        if ( nn_poll(&pfd,1,1) > 0 )
        {
            //printf("start wait\n");
            if ( (datalen= nn_recv(pairsock,&data,NN_MSG,0)) >= 0 )
            {
                //printf("wait for got.%d\n",datalen);
                retval = (*verify)(swap,data,datalen);
                swap->received = (uint32_t)time(NULL);
                nn_freemsg(data);
                //printf("retval.%d\n",retval);
                return(retval);
            } // else printf("error nn_recv\n");
        }
    }
    printf("waitfor timedout aliceid.%llu requestid.%u quoteid.%u\n",(long long)swap->aliceid,swap->I.req.requestid,swap->I.req.quoteid);
    return(retval);
}

int32_t swap_nn_send(int32_t sock,uint8_t *data,int32_t datalen,uint32_t flags,int32_t timeout)
{
    struct nn_pollfd pfd; int32_t i;
    for (i=0; i<timeout*1000; i++)
    {
        memset(&pfd,0,sizeof(pfd));
        pfd.fd = sock;
        pfd.events = NN_POLLOUT;
        if ( nn_poll(&pfd,1,1) > 0 )
            return(nn_send(sock,data,datalen,flags));
        usleep(1000);
    }
    return(-1);
}

int32_t LP_waitsend(char *statename,int32_t timeout,int32_t pairsock,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen,int32_t (*verify)(struct basilisk_swap *swap,uint8_t *data,int32_t datalen),int32_t (*datagen)(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen))
{
    int32_t datalen,sendlen,retval = -1;
    //printf("waitsend.%s timeout.%d\n",statename,timeout);
    if ( LP_waitfor(pairsock,swap,timeout,verify) == 0 )
    {
        //printf("waited for %s\n",statename);
        if ( (datalen= (*datagen)(swap,data,maxlen)) > 0 )
        {
            if ( (sendlen= swap_nn_send(pairsock,data,datalen,0,timeout)) == datalen )
            {
                //printf("sent.%d after waitfor.%s\n",sendlen,statename);
                retval = 0;
            } else printf("send %s error\n",statename);
        } else printf("%s datagen no data\n",statename);
    } else printf("didnt get valid data after %d\n",timeout);
    return(retval);
}

int32_t LP_sendwait(char *statename,int32_t timeout,int32_t pairsock,struct basilisk_swap *swap,uint8_t *data,int32_t maxlen,int32_t (*verify)(struct basilisk_swap *swap,uint8_t *data,int32_t datalen),int32_t (*datagen)(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen))
{
    int32_t datalen,sendlen,retval = -1;
    //printf("sendwait.%s\n",statename);
    if ( (datalen= (*datagen)(swap,data,maxlen)) > 0 )
    {
        //printf("generated %d for %s, timeout.%d\n",datalen,statename,timeout);
        if ( (sendlen= swap_nn_send(pairsock,data,datalen,0,timeout)) == datalen )
        {
            //printf("sendwait.%s sent %d\n",statename,sendlen);
            if ( LP_waitfor(pairsock,swap,timeout,verify) == 0 )
            {
                //printf("waited! sendwait.%s sent %d\n",statename,sendlen);
                retval = 0;
            } else printf("didnt get %s\n",statename);
        } else printf("send %s error\n",statename);
    } else printf("no datagen for %s\n",statename);
    return(retval);
}

void LP_swapsfp_update(uint32_t requestid,uint32_t quoteid)
{
    static FILE *swapsfp;
    portable_mutex_lock(&LP_listmutex);
    if ( swapsfp == 0 )
    {
        char fname[512];
        sprintf(fname,"%s/SWAPS/list",GLOBAL_DBDIR), OS_compatible_path(fname);
        if ( (swapsfp= fopen(fname,"rb+")) == 0 )
            swapsfp = fopen(fname,"wb+");
        else fseek(swapsfp,0,SEEK_END);
        //printf("LIST fp.%p\n",swapsfp);
    }
    if ( swapsfp != 0 )
    {
        fwrite(&requestid,1,sizeof(requestid),swapsfp);
        fwrite(&quoteid,1,sizeof(quoteid),swapsfp);
        fflush(swapsfp);
    }
    portable_mutex_unlock(&LP_listmutex);
}

struct basilisk_rawtx *LP_swapdata_rawtx(struct basilisk_swap *swap,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx)
{
    if ( rawtx->I.datalen != 0 && rawtx->I.datalen <= maxlen )
    {
        memcpy(data,rawtx->txbytes,rawtx->I.datalen);
        return(rawtx);
    }
    printf("swapdata rawtx has null txbytes\n");
    return(0);
}

int32_t LP_rawtx_spendscript(struct basilisk_swap *swap,int32_t height,struct basilisk_rawtx *rawtx,int32_t v,uint8_t *recvbuf,int32_t recvlen,int32_t suppress_pubkeys)
{
    bits256 otherhash,myhash,txid; int64_t txfee,val; int32_t i,offset=0,datalen=0,retval=-1,hexlen,n; uint8_t *data; cJSON *txobj,*skey,*vouts,*vout; char *hexstr,bobstr[65],alicestr[65],redeemaddr[64],checkaddr[64]; uint32_t quoteid,msgbits; struct iguana_info *coin;
    LP_etomicsymbol(bobstr,swap->I.bobtomic,swap->I.bobstr);
    LP_etomicsymbol(alicestr,swap->I.alicetomic,swap->I.alicestr);
    if ( (coin= LP_coinfind(rawtx->symbol)) == 0 )
    {
        printf("LP_rawtx_spendscript couldnt find coin.(%s)\n",rawtx->symbol);
        return(-1);
    }
    for (i=0; i<32; i++)
        otherhash.bytes[i] = recvbuf[offset++];
    for (i=0; i<32; i++)
        myhash.bytes[i] = recvbuf[offset++];

    offset += iguana_rwnum(0,&recvbuf[offset],sizeof(quoteid),&quoteid);
    offset += iguana_rwnum(0,&recvbuf[offset],sizeof(msgbits),&msgbits);
    datalen = recvbuf[offset++];
    datalen += (int32_t)recvbuf[offset++] << 8;
    if ( datalen > 1024 )
    {
        printf("LP_rawtx_spendscript %s datalen.%d too big\n",rawtx->name,datalen);
        return(-1);
    }
    rawtx->I.redeemlen = recvbuf[offset++];
#ifndef NOTETOMIC
    uint8arrayToHex(rawtx->I.ethTxid, &recvbuf[offset], 32);
    printf("ETH txid received: %s\n", rawtx->I.ethTxid);
#endif
    offset += 32;
    data = &recvbuf[offset];
    if ( rawtx->I.redeemlen > 0 && rawtx->I.redeemlen < 0x100 )
    {
        memcpy(rawtx->redeemscript,&data[datalen],rawtx->I.redeemlen);
        //for (i=0; i<rawtx->I.redeemlen; i++)
        //    printf("%02x",rawtx->redeemscript[i]);
        bitcoin_address(coin->symbol,redeemaddr,coin->taddr,coin->p2shtype,rawtx->redeemscript,rawtx->I.redeemlen);
        //printf(" received redeemscript.(%s) %s taddr.%d\n",redeemaddr,coin->symbol,coin->taddr);
        LP_swap_coinaddr(coin,checkaddr,0,data,datalen,0);
        if ( strcmp(redeemaddr,checkaddr) != 0 )
        {
            printf("REDEEMADDR MISMATCH??? %s != %s\n",redeemaddr,checkaddr);
            return(-1);
        }
    }
    //printf("recvlen.%d datalen.%d redeemlen.%d\n",recvlen,datalen,rawtx->redeemlen);
    if ( rawtx->I.datalen == 0 )
    {
        //for (i=0; i<datalen; i++)
        //    printf("%02x",data[i]);
        //printf(" <- received\n");
        memcpy(rawtx->txbytes,data,datalen);
        rawtx->I.datalen = datalen;
    }
    else if ( datalen != rawtx->I.datalen || memcmp(rawtx->txbytes,data,datalen) != 0 )
    {
        for (i=0; i<rawtx->I.datalen; i++)
            printf("%02x",rawtx->txbytes[i]);
        printf(" <- rawtx\n");
        printf("%s rawtx data compare error, len %d vs %d <<<<<<<<<< warning\n",rawtx->name,rawtx->I.datalen,datalen);
        return(-1);
    }


    if ( recvlen != datalen+rawtx->I.redeemlen + 107 )
        printf("RECVLEN %d != %d + %d\n",recvlen,datalen,rawtx->I.redeemlen);
    txid = bits256_calctxid(coin->symbol,data,datalen);
    //char str[65]; printf("rawtx.%s txid %s\n",rawtx->name,bits256_str(str,txid));
    if ( bits256_cmp(txid,rawtx->I.actualtxid) != 0 && bits256_nonz(rawtx->I.actualtxid) == 0 )
        rawtx->I.actualtxid = txid;
    if ( (txobj= bitcoin_data2json(coin->symbol,coin->taddr,coin->pubtype,coin->p2shtype,coin->isPoS,height,&rawtx->I.signedtxid,&rawtx->msgtx,rawtx->extraspace,sizeof(rawtx->extraspace),data,datalen,0,suppress_pubkeys,coin->zcash)) != 0 )
    {
        rawtx->I.actualtxid = rawtx->I.signedtxid;
        rawtx->I.locktime = rawtx->msgtx.lock_time;
        if ( (vouts= jarray(&n,txobj,"vout")) != 0 && v < n )
        {
            vout = jitem(vouts,v);
            if ( strcmp("BTC",coin->symbol) == 0 && rawtx == &swap->otherfee )
                txfee = LP_MIN_TXFEE;
            else
            {
                if ( strcmp(coin->symbol,bobstr) == 0 )
                    txfee = swap->I.Btxfee;
                else if ( strcmp(coin->symbol,alicestr) == 0 )
                    txfee = swap->I.Atxfee;
                else txfee = LP_MIN_TXFEE;
            }
            if ( rawtx->I.amount > 2*txfee)
                val = rawtx->I.amount-2*txfee;
            else val = 1;
            if ( j64bits(vout,"satoshis") >= val && (skey= jobj(vout,"scriptPubKey")) != 0 && (hexstr= jstr(skey,"hex")) != 0 )
            {
                if ( (hexlen= (int32_t)strlen(hexstr) >> 1) < sizeof(rawtx->spendscript) )
                {
                    decode_hex(rawtx->spendscript,hexlen,hexstr);
                    rawtx->I.spendlen = hexlen;
                    //if ( swap != 0 )
                    //    basilisk_txlog(swap->myinfoptr,swap,rawtx,-1); // bobdeposit, bobpayment or alicepayment
                    retval = 0;
                    if ( rawtx == &swap->otherfee )
                    {
                        LP_swap_coinaddr(coin,rawtx->p2shaddr,0,data,datalen,0);
                        //printf("got %s txid.%s (%s) -> %s\n",rawtx->name,bits256_str(str,rawtx->I.signedtxid),jprint(txobj,0),rawtx->p2shaddr);
                    } else bitcoin_address(coin->symbol,rawtx->p2shaddr,coin->taddr,coin->p2shtype,rawtx->spendscript,hexlen);
                }
            } else printf("%s satoshis %.8f ERROR.(%s) txfees.[%.8f %.8f: %.8f] amount.%.8f -> %.8f\n",rawtx->name,dstr(j64bits(vout,"satoshis")),jprint(txobj,0),dstr(swap->I.Atxfee),dstr(swap->I.Btxfee),dstr(txfee),dstr(rawtx->I.amount),dstr(rawtx->I.amount)-dstr(txfee));
        }
        free_json(txobj);
    }
    return(retval);
}

uint32_t LP_swapdata_rawtxsend(int32_t pairsock,struct basilisk_swap *swap,uint32_t msgbits,uint8_t *data,int32_t maxlen,struct basilisk_rawtx *rawtx,uint32_t nextbits,int32_t suppress_swapsend)
{
    uint8_t sendbuf[32768]; int32_t sendlen,retval = -1;
    if ( LP_swapdata_rawtx(swap,data,maxlen,rawtx) != 0 )
    {
        if ( bits256_nonz(rawtx->I.signedtxid) != 0 && bits256_nonz(rawtx->I.actualtxid) == 0 )
        {
            basilisk_dontforget_update(swap,rawtx);
            rawtx->I.actualtxid = LP_broadcast_tx(rawtx->name,rawtx->symbol,rawtx->txbytes,rawtx->I.datalen);
            if ( bits256_cmp(rawtx->I.actualtxid,rawtx->I.signedtxid) != 0 )
            {
                char str[65],str2[65];
                printf("%s rawtxsend.[%d] %s vs %s\n",rawtx->name,rawtx->I.datalen,bits256_str(str,rawtx->I.signedtxid),bits256_str(str2,rawtx->I.actualtxid));
                if ( bits256_nonz(rawtx->I.signedtxid) != 0 )
                    rawtx->I.actualtxid = rawtx->I.signedtxid;
                else rawtx->I.signedtxid = rawtx->I.actualtxid;
            }
            if ( bits256_nonz(rawtx->I.actualtxid) != 0 && msgbits != 0 )
            {
#ifndef NOTETOMIC
                if ( swap->I.bobtomic[0] != 0 || swap->I.alicetomic[0] != 0 )
                {
                    char *ethTxId = sendEthTx(swap, rawtx);
                    if (ethTxId != NULL) {
                        strcpy(rawtx->I.ethTxid, ethTxId);
                        free(ethTxId);
                    } else {
                        printf("Error sending ETH tx\n");
                        return(-1);
                    }
                }
#endif
                sendlen = 0;
                sendbuf[sendlen++] = rawtx->I.datalen & 0xff;
                sendbuf[sendlen++] = (rawtx->I.datalen >> 8) & 0xff;
                sendbuf[sendlen++] = rawtx->I.redeemlen;
                if ( rawtx->I.ethTxid[0] != 0 && strlen(rawtx->I.ethTxid) == 66  )
                {
                    uint8_t ethTxidBytes[32];
                    // ETH txid always starts with 0x
                    decode_hex(ethTxidBytes, 32, rawtx->I.ethTxid + 2);
                    memcpy(&sendbuf[sendlen], ethTxidBytes, 32);
                }
                else
                {
                    // fill with zero bytes to always have fixed message size
                    memset(&sendbuf[sendlen], 0, 32);
                }
                sendlen += 32;
                //int32_t z; for (z=0; z<rawtx->I.datalen; z++) printf("%02x",rawtx->txbytes[z]); printf(" >>>>>>> send.%d %s\n",rawtx->I.datalen,rawtx->name);
                //printf("datalen.%d redeemlen.%d\n",rawtx->I.datalen,rawtx->I.redeemlen);
                memcpy(&sendbuf[sendlen],rawtx->txbytes,rawtx->I.datalen), sendlen += rawtx->I.datalen;
                if ( rawtx->I.redeemlen > 0 && rawtx->I.redeemlen < 0x100 )
                {
                    memcpy(&sendbuf[sendlen],rawtx->redeemscript,rawtx->I.redeemlen);
                    sendlen += rawtx->I.redeemlen;
                }

                basilisk_dontforget_update(swap,rawtx);
                //printf("sendlen.%d datalen.%d redeemlen.%d\n",sendlen,rawtx->datalen,rawtx->redeemlen);
                if ( suppress_swapsend == 0 )
                {
                    retval = LP_swapsend(pairsock,swap,msgbits,sendbuf,sendlen,nextbits,rawtx->I.crcs);
                    if ( LP_waitmempool(rawtx->symbol,rawtx->I.destaddr,rawtx->I.signedtxid,0,LP_SWAPSTEP_TIMEOUT*10) < 0 )
                    {
                        char str[65]; printf("failed to find %s %s %s in the mempool?\n",rawtx->name,rawtx->I.destaddr,bits256_str(str,rawtx->I.actualtxid));
                        retval = -1;
                    }
                    return(retval);
                }
                else
                {
                    printf("suppress swapsend %x\n",msgbits);
                    return(0);
                }
            }
        }
        return(nextbits);
    } //else if ( swap->I.iambob == 0 )
        printf("error from basilisk_swapdata_rawtx.%s %p len.%d\n",rawtx->name,rawtx->txbytes,rawtx->I.datalen);
    return(0);
}

uint32_t LP_swapwait(uint32_t expiration,uint32_t requestid,uint32_t quoteid,int32_t duration,int32_t sleeptime)
{
    char *retstr; uint32_t finished = 0; cJSON *retjson=0;
    if ( sleeptime != 0 )
    {
        printf("wait %d:%d for SWAP.(r%u/q%u) to complete\n",duration,sleeptime,requestid,quoteid);
        sleep(sleeptime/3);
    }
    while ( expiration == 0 || time(NULL) < expiration )
    {
        if ( (retstr= basilisk_swapentry(0,requestid,quoteid,1)) != 0 )
        {
            if ( (retjson= cJSON_Parse(retstr)) != 0 )
            {
                if ( jstr(retjson,"status") != 0 && strcmp(jstr(retjson,"status"),"finished") == 0 )
                {
                    finished = (uint32_t)time(NULL);
                    free(retstr), retstr = 0;
                    break;
                }
                else if ( expiration != 0 && time(NULL) > expiration )
                    printf("NOT FINISHED.(%s)\n",jprint(retjson,0));
                free_json(retjson), retjson = 0;
            }
            free(retstr);
        }
        if ( sleeptime != 0 )
            sleep(sleeptime);
        if ( duration < 0 )
            break;
    }
    if ( retjson != 0 )
    {
        free_json(retjson);
        if ( (retstr= basilisk_swapentry(0,requestid,quoteid,1)) != 0 )
        {
            printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>\nSWAP completed! %u-%u %s\n",requestid,quoteid,retstr);
            free(retstr);
        }
        return(finished);
    }
    else
    {
        if ( expiration != 0 && time(NULL) > expiration )
            printf("\nSWAP did not complete! %u-%u %s\n",requestid,quoteid,jprint(retjson,0));
        if ( duration > 0 )
            LP_pendswap_add(expiration,requestid,quoteid);
        return(0);
    }
}

int32_t LP_calc_waittimeout(char *symbol)
{
    int32_t waittimeout = TX_WAIT_TIMEOUT;
    if ( strcmp(symbol,"BTC") == 0 )
        waittimeout *= 8;
    else if ( LP_is_slowcoin(symbol) != 0 )
        waittimeout *= 4;
    return(waittimeout);
}

void LP_bobloop(void *_swap)
{
    uint8_t *data; char bobstr[65],alicestr[65]; int32_t bobwaittimeout,alicewaittimeout,maxlen,m,n,err=0; uint32_t expiration; struct basilisk_swap *swap = _swap;
    G.LP_pendingswaps++;
    //printf("start swap iambob\n");
    LP_etomicsymbol(bobstr,swap->I.bobtomic,swap->I.bobstr);
    LP_etomicsymbol(alicestr,swap->I.alicetomic,swap->I.alicestr);
    maxlen = 1024*1024 + sizeof(*swap);
    data = malloc(maxlen);
    expiration = (uint32_t)time(NULL) + LP_SWAPSTEP_TIMEOUT;
    bobwaittimeout = LP_calc_waittimeout(bobstr);
    alicewaittimeout = LP_calc_waittimeout(alicestr);
    if ( swap != 0 )
    {
        if ( LP_waitsend("pubkeys",120,swap->N.pair,swap,data,maxlen,LP_pubkeys_verify,LP_pubkeys_data) < 0 )
            err = -2000, printf("error waitsend pubkeys\n");
        else if ( LP_waitsend("choosei",LP_SWAPSTEP_TIMEOUT,swap->N.pair,swap,data,maxlen,LP_choosei_verify,LP_choosei_data) < 0 )
            err = -2001, printf("error waitsend choosei\n");
        else if ( LP_waitsend("mostprivs",LP_SWAPSTEP_TIMEOUT,swap->N.pair,swap,data,maxlen,LP_mostprivs_verify,LP_mostprivs_data) < 0 )
            err = -2002, printf("error waitsend mostprivs\n");
        else if ( basilisk_bobscripts_set(swap,1,1) < 0 )
            err = -2003, printf("error bobscripts deposit\n");
        else
        {
            uint8_t error = 0;
            swap->bobrefund.utxovout = 0;
            swap->bobrefund.utxotxid = swap->bobdeposit.I.signedtxid;
            basilisk_bobdeposit_refund(swap,swap->I.putduration);
            //printf("depositlen.%d\n",swap->bobdeposit.I.datalen);
            //LP_swapsfp_update(&swap->I.req);
            LP_swap_critical = (uint32_t)time(NULL);
            LP_unavailableset(swap->bobdeposit.utxotxid,swap->bobdeposit.utxovout,(uint32_t)time(NULL)+60,swap->I.otherhash);
            if ( LP_waitfor(swap->N.pair,swap,bobwaittimeout,LP_verify_otherfee) < 0 )
            {
                error = 1;
                err = -2004, printf("error waiting for alicefee\n");
            }
            if ( error == 0 )
            {
                if ( LP_swapdata_rawtxsend(swap->N.pair,swap,0x200,data,maxlen,&swap->bobdeposit,0x100,0) == 0 )
                {
                    error = 1;
                    err = -2005, printf("error sending bobdeposit\n");
                }
            }
            LP_unavailableset(swap->bobpayment.utxotxid,swap->bobpayment.utxovout,(uint32_t)time(NULL)+60,swap->I.otherhash);
            if ( error == 0 && LP_waitfor(swap->N.pair,swap,bobwaittimeout + alicewaittimeout,LP_verify_alicepayment) < 0 )
            {
                error = 1;
                err = -2006, printf("error waiting for alicepayment\n");
            }
            if (error == 0)
            {
                LP_swap_critical = (uint32_t)time(NULL);
                if ( basilisk_bobscripts_set(swap,0,1) < 0 )
                    err = -2007, printf("error bobscripts payment\n");
                else
                {
                    m = swap->I.aliceconfirms;
                    while ( (n= LP_numconfirms(alicestr,swap->alicepayment.I.destaddr,swap->alicepayment.I.signedtxid,0,1)) < m ) // sync with alice
                    {
                        LP_unavailableset(swap->bobpayment.utxotxid,swap->bobpayment.utxovout,(uint32_t)time(NULL)+60,swap->I.otherhash);
                        LP_swap_critical = (uint32_t)time(NULL);
                        char str[65];printf("%d wait for alicepayment %s numconfs.%d %s %s\n",n,swap->alicepayment.I.destaddr,m,alicestr,bits256_str(str,swap->alicepayment.I.signedtxid));
                        sleep(10);
                    }
                    LP_swap_critical = (uint32_t)time(NULL);
                    if ( LP_swapdata_rawtxsend(swap->N.pair,swap,0x8000,data,maxlen,&swap->bobpayment,0x4000,0) == 0 ) {
                        err = -2008, printf("error sending bobpayment\n");
                    }
                    //if ( LP_waitfor(swap->N.pair,swap,10,LP_verify_alicespend) < 0 )
                    //    printf("error waiting for alicespend\n");
                    //swap->sentflag = 1;
                    swap->bobreclaim.utxovout = 0;
                    swap->bobreclaim.utxotxid = swap->bobpayment.I.signedtxid;
                    basilisk_bobpayment_reclaim(swap,swap->I.callduration);
                    if ( swap->N.pair >= 0 )
                        nn_close(swap->N.pair), swap->N.pair = -1;
                }
            }
        }
    } else printf("swap timed out\n");
    LP_swap_endcritical = (uint32_t)time(NULL);
    if ( err < 0 )
        LP_failedmsg(swap->I.req.requestid,swap->I.req.quoteid,err,swap->uuidstr);
    sleep(13);
    LP_pendswap_add(swap->I.expiration,swap->I.req.requestid,swap->I.req.quoteid);
    //swap->I.finished = LP_swapwait(swap->I.expiration,swap->I.req.requestid,swap->I.req.quoteid,LP_atomic_locktime(swap->I.bobstr,swap->I.alicestr)*3,swap->I.aliceconfirms == 0 ? 3 : 30);
    basilisk_swap_finished(swap);
    free(swap);
    free(data);
    G.LP_pendingswaps--;
}

void LP_aliceloop(void *_swap)
{
    uint8_t *data; char bobstr[65],alicestr[65]; int32_t bobwaittimeout,alicewaittimeout,maxlen,n,m,err=0; uint32_t expiration; struct basilisk_swap *swap = _swap;
    G.LP_pendingswaps++;
    LP_etomicsymbol(bobstr,swap->I.bobtomic,swap->I.bobstr);
    LP_etomicsymbol(alicestr,swap->I.alicetomic,swap->I.alicestr);
    maxlen = 1024*1024 + sizeof(*swap);
    data = malloc(maxlen);
    expiration = (uint32_t)time(NULL) + LP_SWAPSTEP_TIMEOUT;
    bobwaittimeout = LP_calc_waittimeout(bobstr);
    alicewaittimeout = LP_calc_waittimeout(alicestr);
    if ( swap != 0 )
    {
        printf("start swap iamalice pair.%d\n",swap->N.pair);
        if ( LP_sendwait("pubkeys",120,swap->N.pair,swap,data,maxlen,LP_pubkeys_verify,LP_pubkeys_data) < 0 )
            err = -1000, printf("error LP_sendwait pubkeys\n");
        else if ( LP_sendwait("choosei",LP_SWAPSTEP_TIMEOUT,swap->N.pair,swap,data,maxlen,LP_choosei_verify,LP_choosei_data) < 0 )
            err = -1001, printf("error LP_sendwait choosei\n");
        else if ( LP_sendwait("mostprivs",LP_SWAPSTEP_TIMEOUT,swap->N.pair,swap,data,maxlen,LP_mostprivs_verify,LP_mostprivs_data) < 0 )
            err = -1002, printf("error LP_sendwait mostprivs\n");
        else if ( basilisk_alicetxs(swap->N.pair,swap,data,maxlen) != 0 )
            err = -1003, printf("basilisk_alicetxs error\n");
        else
        {
            //LP_swapsfp_update(&swap->I.req);
            LP_swap_critical = (uint32_t)time(NULL);
            if ( LP_swapdata_rawtxsend(swap->N.pair,swap,0x80,data,maxlen,&swap->myfee,0x40,0) == 0 )
                err = -1004, printf("error sending alicefee\n");
            else if ( LP_waitfor(swap->N.pair,swap,bobwaittimeout,LP_verify_bobdeposit) < 0 )
                err = -1005, printf("error waiting for bobdeposit\n");
            else
            {
                m = swap->I.bobconfirms;
                LP_unavailableset(swap->alicepayment.utxotxid,swap->alicepayment.utxovout,(uint32_t)time(NULL)+60,swap->I.otherhash);
                while ( (n= LP_numconfirms(bobstr,swap->bobdeposit.I.destaddr,swap->bobdeposit.I.signedtxid,0,1)) < m )
                {
                    LP_swap_critical = (uint32_t)time(NULL);
                    char str[65];printf("%d wait for bobdeposit %s numconfs.%d %s %s\n",n,swap->bobdeposit.I.destaddr,m,bobstr,bits256_str(str,swap->bobdeposit.I.signedtxid));
                    sleep(10);
                }
                if ( LP_swapdata_rawtxsend(swap->N.pair,swap,0x1000,data,maxlen,&swap->alicepayment,0x800,0) == 0 )
                    err = -1006, printf("error sending alicepayment\n");
                else
                {
                    m = swap->I.aliceconfirms;
                    while ( (n= LP_numconfirms(alicestr,swap->alicepayment.I.destaddr,swap->alicepayment.I.signedtxid,0,1)) < m )
                    {
                        LP_swap_critical = (uint32_t)time(NULL);
                        char str[65];printf("%d wait for alicepayment %s numconfs.%d %s %s\n",n,swap->alicepayment.I.destaddr,m,alicestr,bits256_str(str,swap->alicepayment.I.signedtxid));
                        sleep(10);
                    }
                    //swap->sentflag = 1;
                    LP_swap_critical = (uint32_t)time(NULL);
                    if ( LP_waitfor(swap->N.pair,swap,bobwaittimeout,LP_verify_bobpayment) < 0 )
                        err = -1007, printf("error waiting for bobpayment\n");
                    else
                    {
                        LP_swap_endcritical = (uint32_t)time(NULL);
                        while ( (n= LP_numconfirms(bobstr,swap->bobpayment.I.destaddr,swap->bobpayment.I.signedtxid,0,1)) < swap->I.bobconfirms )
                        {
                            char str[65];printf("%d wait for bobpayment %s numconfs.%d %s %s\n",n,swap->bobpayment.I.destaddr,swap->I.bobconfirms,bobstr,bits256_str(str,swap->bobpayment.I.signedtxid));
                            sleep(10);
                        }
                        if ( swap->N.pair >= 0 )
                            nn_close(swap->N.pair), swap->N.pair = -1;
                    }
                }
            }
        }
    }
    LP_swap_endcritical = (uint32_t)time(NULL);
    if ( err < 0 )
        LP_failedmsg(swap->I.req.requestid,swap->I.req.quoteid,err,swap->uuidstr);
    sleep(13);
    LP_pendswap_add(swap->I.expiration,swap->I.req.requestid,swap->I.req.quoteid);
    //swap->I.finished = LP_swapwait(swap->I.expiration,swap->I.req.requestid,swap->I.req.quoteid,LP_atomic_locktime(swap->I.bobstr,swap->I.alicestr)*3,swap->I.aliceconfirms == 0 ? 3 : 30);
    basilisk_swap_finished(swap);
    free(swap);
    free(data);
    G.LP_pendingswaps--;
}

bits256 instantdex_derivekeypair(void *ctx,bits256 *newprivp,uint8_t pubkey[33],bits256 privkey,bits256 orderhash)
{
    bits256 sharedsecret;
    sharedsecret = curve25519_shared(privkey,orderhash);
    vcalc_sha256cat(newprivp->bytes,orderhash.bytes,sizeof(orderhash),sharedsecret.bytes,sizeof(sharedsecret));
    return(bitcoin_pubkey33(ctx,pubkey,*newprivp));
}

bits256 basilisk_revealkey(bits256 privkey,bits256 pubkey)
{
    return(pubkey);
}

int32_t instantdex_pubkeyargs(struct basilisk_swap *swap,int32_t numpubs,bits256 privkey,bits256 hash,int32_t firstbyte)
{
    char buf[3]; int32_t i,n,m,len=0; bits256 pubi,reveal; uint64_t txid; uint8_t secret160[20],pubkey[33];
    sprintf(buf,"%c0",'A' - 0x02 + firstbyte);
    if ( numpubs > 2 )
    {
        if ( swap->I.numpubs+2 >= numpubs )
            return(numpubs);
        //printf(">>>>>> start generating %s\n",buf);
    }
    for (i=n=m=0; i<numpubs*100 && n<numpubs; i++)
    {
        pubi = instantdex_derivekeypair(swap->ctx,&privkey,pubkey,privkey,hash);
        //printf("i.%d n.%d numpubs.%d %02x vs %02x\n",i,n,numpubs,pubkey[0],firstbyte);
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
    //if ( n > 2 || m > 2 )
    //    printf("n.%d m.%d len.%d numpubs.%d\n",n,m,len,swap->I.numpubs);
    return(n);
}

void basilisk_rawtx_setparms(char *name,uint32_t quoteid,struct basilisk_rawtx *rawtx,struct iguana_info *coin,int32_t numconfirms,int32_t vintype,uint64_t satoshis,int32_t vouttype,uint8_t *pubkey33,int32_t jumblrflag)
{
#ifdef BASILISK_DISABLEWAITTX
    numconfirms = 0;
#endif
    strcpy(rawtx->name,name);
    //printf("set coin.%s %s -> %s\n",coin->symbol,coin->smartaddr,name);
    strcpy(rawtx->symbol,coin->symbol);
    rawtx->I.numconfirms = numconfirms;
    if ( (rawtx->I.amount= satoshis) < LP_MIN_TXFEE )
        rawtx->I.amount = LP_MIN_TXFEE;
    rawtx->I.vintype = vintype; // 0 -> std, 2 -> 2of2, 3 -> spend bobpayment, 4 -> spend bobdeposit
    rawtx->I.vouttype = vouttype; // 0 -> fee, 1 -> std, 2 -> 2of2, 3 -> bobpayment, 4 -> bobdeposit
    if ( rawtx->I.vouttype == 0 )
    {
        if ( strcmp(coin->symbol,"BTC") == 0 && (quoteid % 10) == 0 )
            decode_hex(rawtx->I.rmd160,20,TIERNOLAN_RMD160);
        else decode_hex(rawtx->I.rmd160,20,INSTANTDEX_RMD160);
        bitcoin_address(coin->symbol,rawtx->I.destaddr,coin->taddr,coin->pubtype,rawtx->I.rmd160,20);
    }
    if ( pubkey33 != 0 )
    {
        memcpy(rawtx->I.pubkey33,pubkey33,33);
        bitcoin_address(coin->symbol,rawtx->I.destaddr,coin->taddr,coin->pubtype,rawtx->I.pubkey33,33);
        bitcoin_addr2rmd160(coin->symbol,coin->taddr,&rawtx->I.addrtype,rawtx->I.rmd160,rawtx->I.destaddr);
    }
    if ( rawtx->I.vouttype <= 1 && rawtx->I.destaddr[0] != 0 )
    {
        rawtx->I.spendlen = bitcoin_standardspend(rawtx->spendscript,0,rawtx->I.rmd160);
        //printf("%s spendlen.%d %s <- %.8f\n",name,rawtx->I.spendlen,rawtx->I.destaddr,dstr(rawtx->I.amount));
    } //else printf("%s vouttype.%d destaddr.(%s)\n",name,rawtx->I.vouttype,rawtx->I.destaddr);
}

struct basilisk_swap *bitcoin_swapinit(bits256 privkey,uint8_t *pubkey33,bits256 pubkey25519,struct basilisk_swap *swap,int32_t optionduration,uint32_t statebits,struct LP_quoteinfo *qp,int32_t dynamictrust)
{
    //FILE *fp; char fname[512];
    uint8_t *alicepub33=0,*bobpub33=0; int32_t jumblrflag=-2,x = -1; struct iguana_info *bobcoin,*alicecoin; char bobstr[65],alicestr[65];
    strcpy(swap->I.etomicsrc,qp->etomicsrc);
    strcpy(swap->I.etomicdest,qp->etomicdest);
    strcpy(swap->I.bobstr,swap->I.req.src);
    strcpy(swap->I.alicestr,swap->I.req.dest);
    LP_etomicsymbol(bobstr,swap->I.bobtomic,swap->I.bobstr);
    LP_etomicsymbol(alicestr,swap->I.alicetomic,swap->I.alicestr);
    if ( (alicecoin= LP_coinfind(alicestr)) == 0 )
    {
        printf("missing alicecoin src.%p dest.%p\n",LP_coinfind(alicestr),LP_coinfind(bobstr));
        free(swap);
        return(0);
    }
    if ( (bobcoin= LP_coinfind(bobstr)) == 0 )
    {
        printf("missing bobcoin src.%p dest.%p\n",LP_coinfind(swap->I.req.src),LP_coinfind(swap->I.req.dest));
        free(swap);
        return(0);
    }
    if ( alicecoin == 0 || bobcoin == 0 )
    {
        printf("couldnt find ETOMIC\n");
        free(swap);
        return(0);
    }
    if ( (swap->I.Atxfee= qp->desttxfee) < 0 )
    {
        printf("bitcoin_swapinit %s Atxfee %.8f rejected\n",swap->I.req.dest,dstr(swap->I.Atxfee));
        free(swap);
        return(0);
    }
    if ( (swap->I.Btxfee= qp->txfee) < 0 )
    {
        printf("bitcoin_swapinit %s Btxfee %.8f rejected\n",swap->I.req.src,dstr(swap->I.Btxfee));
        free(swap);
        return(0);
    }
    swap->I.putduration = swap->I.callduration = LP_atomic_locktime(bobstr,alicestr);
    if ( optionduration < 0 )
        swap->I.putduration -= optionduration;
    else if ( optionduration > 0 )
        swap->I.callduration += optionduration;
    if ( (swap->I.bobsatoshis= swap->I.req.srcamount) <= 0 )
    {
        printf("bitcoin_swapinit %s bobsatoshis %.8f rejected\n",swap->I.req.src,dstr(swap->I.bobsatoshis));
        free(swap);
        return(0);
    }
    if ( (swap->I.alicesatoshis= swap->I.req.destamount) <= 0 )
    {
        printf("bitcoin_swapinit %s alicesatoshis %.8f rejected\n",swap->I.req.dest,dstr(swap->I.alicesatoshis));
        free(swap);
        return(0);
    }
    if ( (swap->I.bobinsurance= (swap->I.bobsatoshis / INSTANTDEX_INSURANCEDIV)) < LP_MIN_TXFEE )
        swap->I.bobinsurance = LP_MIN_TXFEE;
    if ( (swap->I.aliceinsurance= (swap->I.alicesatoshis / INSTANTDEX_INSURANCEDIV)) < LP_MIN_TXFEE )
        swap->I.aliceinsurance = LP_MIN_TXFEE;
    swap->I.started = qp->timestamp;//(uint32_t)time(NULL);
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
        swap->I.aliceistrusted = 1;
        if ( dynamictrust == 0 && LP_pubkey_istrusted(swap->I.req.srchash) != 0 )
            dynamictrust = 1;
        swap->I.otheristrusted = swap->I.bobistrusted = dynamictrust;
    }
    else
    {
        swap->I.iambob = 1;
        swap->I.otherhash = swap->I.req.srchash;
        swap->I.bobistrusted = 1;
        if ( dynamictrust == 0 && LP_pubkey_istrusted(swap->I.req.desthash) != 0 )
            dynamictrust = 1;
        swap->I.otheristrusted = swap->I.aliceistrusted = dynamictrust;
    }
    if ( bits256_nonz(privkey) == 0 || (x= instantdex_pubkeyargs(swap,2 + INSTANTDEX_DECKSIZE,privkey,swap->I.orderhash,0x02+swap->I.iambob)) != 2 + INSTANTDEX_DECKSIZE )
    {
        char str[65]; printf("couldnt generate privkeys %d %s\n",x,bits256_str(str,privkey));
        free(swap);
        return(0);
    }
    if ( strcmp("BTC",bobstr) == 0 )
    {
        swap->I.bobconfirms = 1;//(1 + sqrt(dstr(swap->I.bobsatoshis) * .1));
        swap->I.aliceconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
    }
    else if ( strcmp("BTC",alicestr) == 0 )
    {
        swap->I.aliceconfirms = 1;//(1 + sqrt(dstr(swap->I.alicesatoshis) * .1));
        swap->I.bobconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
    }
    else
    {
        swap->I.bobconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
        swap->I.aliceconfirms = BASILISK_DEFAULT_NUMCONFIRMS;
    }
    if ( bobcoin->userconfirms > 0 )
        swap->I.bobconfirms = bobcoin->userconfirms;
    if ( alicecoin->userconfirms > 0 )
        swap->I.aliceconfirms = alicecoin->userconfirms;
    if ( (swap->I.bobmaxconfirms= bobcoin->maxconfirms) == 0 )
        swap->I.bobmaxconfirms = BASILISK_DEFAULT_MAXCONFIRMS;
    if ( (swap->I.alicemaxconfirms= alicecoin->maxconfirms) == 0 )
        swap->I.alicemaxconfirms = BASILISK_DEFAULT_MAXCONFIRMS;
    if ( swap->I.bobconfirms > swap->I.bobmaxconfirms )
        swap->I.bobconfirms = swap->I.bobmaxconfirms;
    if ( swap->I.aliceconfirms > swap->I.alicemaxconfirms )
        swap->I.aliceconfirms = swap->I.alicemaxconfirms;
    if ( bobcoin->isassetchain != 0 ) {
        if (strcmp(bobstr, "ETOMIC") != 0) {
            swap->I.bobconfirms = BASILISK_DEFAULT_MAXCONFIRMS / 2;
        } else {
            swap->I.bobconfirms = 1;
        }
    }
    if ( alicecoin->isassetchain != 0 ) {
        if (strcmp(alicestr, "ETOMIC") != 0) {
            swap->I.aliceconfirms = BASILISK_DEFAULT_MAXCONFIRMS / 2;
        } else {
            swap->I.aliceconfirms = 1;
        }
    }
    if ( strcmp("BAY",swap->I.req.src) != 0 && strcmp("BAY",swap->I.req.dest) != 0 )
    {
        swap->I.bobconfirms *= !swap->I.bobistrusted;
        swap->I.aliceconfirms *= !swap->I.aliceistrusted;
    }
    printf(">>>>>>>>>> jumblrflag.%d <<<<<<<<< r.%u q.%u, %.8f bobconfs.%d, %.8f aliceconfs.%d taddr.%d %d\n",jumblrflag,swap->I.req.requestid,swap->I.req.quoteid,dstr(swap->I.bobsatoshis),swap->I.bobconfirms,dstr(swap->I.alicesatoshis),swap->I.aliceconfirms,bobcoin->taddr,alicecoin->taddr);
    if ( swap->I.etomicsrc[0] != 0 || swap->I.etomicdest[0] != 0 )
        printf("etomic src (%s %s) dest (%s %s)\n",swap->I.bobtomic,swap->I.etomicsrc,swap->I.alicetomic,swap->I.etomicdest);
    if ( swap->I.iambob != 0 )
    {
        basilisk_rawtx_setparms("myfee",swap->I.req.quoteid,&swap->myfee,bobcoin,0,0,LP_DEXFEE(swap->I.bobsatoshis) + 0*bobcoin->txfee,0,0,jumblrflag);
        basilisk_rawtx_setparms("otherfee",swap->I.req.quoteid,&swap->otherfee,alicecoin,0,0,LP_DEXFEE(swap->I.alicesatoshis) + 0*alicecoin->txfee,0,0,jumblrflag);
        bobpub33 = pubkey33;
    }
    else
    {
        basilisk_rawtx_setparms("otherfee",swap->I.req.quoteid,&swap->otherfee,bobcoin,0,0,LP_DEXFEE(swap->I.bobsatoshis) + 0*bobcoin->txfee,0,0,jumblrflag);
        basilisk_rawtx_setparms("myfee",swap->I.req.quoteid,&swap->myfee,alicecoin,0,0,LP_DEXFEE(swap->I.alicesatoshis) + 0*alicecoin->txfee,0,0,jumblrflag);
        alicepub33 = pubkey33;
    }
    swap->myfee.I.locktime = swap->I.started + 1;
    swap->otherfee.I.locktime = swap->I.started + 1;
    basilisk_rawtx_setparms("bobdeposit",swap->I.req.quoteid,&swap->bobdeposit,bobcoin,swap->I.bobconfirms,0,LP_DEPOSITSATOSHIS(swap->I.bobsatoshis) + 2*bobcoin->txfee,4,0,jumblrflag);
    basilisk_rawtx_setparms("bobrefund",swap->I.req.quoteid,&swap->bobrefund,bobcoin,1,4,LP_DEPOSITSATOSHIS(swap->I.bobsatoshis),1,bobpub33,jumblrflag);
    swap->bobrefund.I.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("aliceclaim",swap->I.req.quoteid,&swap->aliceclaim,bobcoin,1,4,LP_DEPOSITSATOSHIS(swap->I.bobsatoshis),1,alicepub33,jumblrflag);
    swap->aliceclaim.I.suppress_pubkeys = 1;
    swap->aliceclaim.I.locktime = swap->I.started + swap->I.putduration+swap->I.callduration + 1;
    
    basilisk_rawtx_setparms("bobpayment",swap->I.req.quoteid,&swap->bobpayment,bobcoin,swap->I.bobconfirms,0,swap->I.bobsatoshis + 2*bobcoin->txfee,3,0,jumblrflag);
    basilisk_rawtx_setparms("alicespend",swap->I.req.quoteid,&swap->alicespend,bobcoin,swap->I.bobconfirms,3,swap->I.bobsatoshis,1,alicepub33,jumblrflag);
    swap->alicespend.I.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("bobreclaim",swap->I.req.quoteid,&swap->bobreclaim,bobcoin,swap->I.bobconfirms,3,swap->I.bobsatoshis,1,bobpub33,jumblrflag);
    swap->bobreclaim.I.suppress_pubkeys = 1;
    swap->bobreclaim.I.locktime = swap->I.started + swap->I.putduration + 1;
    basilisk_rawtx_setparms("alicepayment",swap->I.req.quoteid,&swap->alicepayment,alicecoin,swap->I.aliceconfirms,0,swap->I.alicesatoshis + 2*alicecoin->txfee,2,0,jumblrflag);
    basilisk_rawtx_setparms("bobspend",swap->I.req.quoteid,&swap->bobspend,alicecoin,swap->I.aliceconfirms,2,swap->I.alicesatoshis,1,bobpub33,jumblrflag);
    swap->bobspend.I.suppress_pubkeys = 1;
    basilisk_rawtx_setparms("alicereclaim",swap->I.req.quoteid,&swap->alicereclaim,alicecoin,swap->I.aliceconfirms,2,swap->I.alicesatoshis,1,alicepub33,jumblrflag);
    swap->alicereclaim.I.suppress_pubkeys = 1;
    swap->bobpayment.utxotxid = qp->txid, swap->bobpayment.utxovout = qp->vout;
    swap->bobdeposit.utxotxid = qp->txid2, swap->bobdeposit.utxovout = qp->vout2;
    swap->alicepayment.utxotxid = qp->desttxid, swap->alicepayment.utxovout = qp->destvout;
    LP_mark_spent(bobstr,qp->txid,qp->vout);
    LP_mark_spent(bobstr,qp->txid2,qp->vout2);
    LP_mark_spent(alicestr,qp->desttxid,qp->destvout);
    if ( swap->I.iambob != 0 )
        swap->otherfee.utxotxid = qp->feetxid, swap->otherfee.utxovout = qp->feevout;
    else
    {
        swap->myfee.utxotxid = qp->feetxid, swap->myfee.utxovout = qp->feevout;
        LP_mark_spent(swap->I.alicestr,qp->feetxid,qp->feevout);
    }
    //char str[65],str2[65],str3[65]; printf("IAMBOB.%d %s %s %s [%s %s]\n",swap->I.iambob,bits256_str(str,qp->txid),bits256_str(str2,qp->txid2),bits256_str(str3,qp->feetxid),bobstr,alicestr);
    return(swap);
}

struct basilisk_swap *LP_swapinit(int32_t iambob,int32_t optionduration,bits256 privkey,struct basilisk_request *rp,struct LP_quoteinfo *qp,int32_t dynamictrust)
{
    static void *ctx;
    struct basilisk_swap *swap; bits256 pubkey25519; uint8_t pubkey33[33];
    if ( ctx == 0 )
        ctx = bitcoin_ctx();
    swap = calloc(1,sizeof(*swap));
    memcpy(swap->uuidstr,qp->uuidstr,sizeof(swap->uuidstr));
    swap->aliceid = LP_aliceid_calc(qp->desttxid,qp->destvout,qp->feetxid,qp->feevout);
    swap->I.req.quoteid = rp->quoteid;
    swap->ctx = ctx;
    vcalc_sha256(0,swap->I.orderhash.bytes,(uint8_t *)rp,sizeof(*rp));
    swap->I.req = *rp;
    G.LP_skipstatus[G.LP_numskips] = ((uint64_t)rp->requestid << 32) | rp->quoteid;
    if ( G.LP_numskips < sizeof(G.LP_skipstatus)/sizeof(*G.LP_skipstatus) )
        G.LP_numskips++;
    //printf("LP_swapinit request.%u iambob.%d (%s/%s) quoteid.%u\n",rp->requestid,iambob,rp->src,rp->dest,rp->quoteid);
    bitcoin_pubkey33(swap->ctx,pubkey33,privkey);
    pubkey25519 = curve25519(privkey,curve25519_basepoint9());
    swap->persistent_pubkey = pubkey25519;
    swap->persistent_privkey = privkey;
    memcpy(swap->persistent_pubkey33,pubkey33,33);
    calc_rmd160_sha256(swap->changermd160,pubkey33,33);
    if ( bitcoin_swapinit(privkey,pubkey33,pubkey25519,swap,optionduration,!iambob,qp,dynamictrust) == 0 )
    {
        printf("error doing swapinit\n");
        free(swap);
        swap = 0;
    }
    return(swap);
}

