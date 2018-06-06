
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
//  LP_remember.c
//  marketmaker
//
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

void basilisk_dontforget(struct basilisk_swap *swap,struct basilisk_rawtx *rawtx,int32_t locktime,bits256 triggertxid)
{
    char zeroes[32],fname[512],str[65],coinaddr[64],secretAmstr[41],secretAm256str[65],secretBnstr[41],secretBn256str[65]; FILE *fp; int32_t i,len; uint8_t redeemscript[256],script[256]; struct iguana_info *bobcoin,*alicecoin;
    sprintf(fname,"%s/SWAPS/%u-%u.%s",GLOBAL_DBDIR,swap->I.req.requestid,swap->I.req.quoteid,rawtx->name), OS_compatible_path(fname);
    bobcoin = LP_coinfind(swap->I.bobstr);
    alicecoin = LP_coinfind(swap->I.alicestr);
    coinaddr[0] = secretAmstr[0] = secretAm256str[0] = secretBnstr[0] = secretBn256str[0] = 0;
    memset(zeroes,0,sizeof(zeroes));
    if ( alicecoin != 0 && bobcoin != 0 && rawtx != 0 && (fp= fopen(fname,"wb")) != 0 )
    {
        fprintf(fp,"{\"name\":\"%s\",\"coin\":\"%s\"",rawtx->name,rawtx->symbol);
        if ( rawtx->I.datalen > 0 )
        {
            fprintf(fp,",\"tx\":\"");
            for (i=0; i<rawtx->I.datalen; i++)
                fprintf(fp,"%02x",rawtx->txbytes[i]);
            fprintf(fp,"\",\"txid\":\"%s\"",bits256_str(str,bits256_calctxid(rawtx->symbol,rawtx->txbytes,rawtx->I.datalen)));
            if ( rawtx == &swap->bobdeposit || rawtx == &swap->bobpayment )
            {
                LP_swap_coinaddr(bobcoin,coinaddr,0,rawtx->txbytes,rawtx->I.datalen,0);
                if ( coinaddr[0] != 0 )
                {
                    LP_importaddress(swap->I.bobstr,coinaddr);
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
        fprintf(fp,",\"uuid\":\"%s\"",swap->uuidstr);
        fprintf(fp,",\"iambob\":%d",swap->I.iambob);
        fprintf(fp,",\"bobcoin\":\"%s\"",swap->I.bobstr);
        if ( swap->I.bobtomic[0] != 0 )
            fprintf(fp,",\"bobtomic\":\"%s\"",swap->I.bobtomic);
        if ( swap->I.etomicsrc[0] != 0 )
            fprintf(fp,",\"etomicsrc\":\"%s\"",swap->I.etomicsrc);
        if (swap->bobdeposit.I.ethTxid[0] != 0) {
            fprintf(fp,",\"bobDepositEthTx\":\"%s\"", swap->bobdeposit.I.ethTxid);
        }
        if (swap->bobpayment.I.ethTxid[0] != 0) {
            fprintf(fp,",\"bobPaymentEthTx\":\"%s\"", swap->bobpayment.I.ethTxid);
        }
        if (swap->alicepayment.I.ethTxid[0] != 0) {
            fprintf(fp,",\"alicePaymentEthTx\":\"%s\"", swap->alicepayment.I.ethTxid);
        }

        fprintf(fp,",\"alicecoin\":\"%s\"",swap->I.alicestr);
        if ( swap->I.alicetomic[0] != 0 )
            fprintf(fp,",\"alicetomic\":\"%s\"",swap->I.alicetomic);
        if ( swap->I.etomicdest[0] != 0 )
            fprintf(fp,",\"etomicdest\":\"%s\"",swap->I.etomicdest);
        fprintf(fp,",\"lock\":%u",locktime);
        fprintf(fp,",\"amount\":%.8f",dstr(rawtx->I.amount));
        if ( bits256_nonz(triggertxid) != 0 )
            fprintf(fp,",\"trigger\":\"%s\"",bits256_str(str,triggertxid));
        if ( bits256_nonz(swap->I.pubAm) != 0 && bits256_nonz(swap->I.pubBn) != 0 )
        {
            basilisk_alicescript(alicecoin->symbol,redeemscript,&len,script,0,coinaddr,alicecoin->taddr,alicecoin->p2shtype,swap->I.pubAm,swap->I.pubBn);
            LP_importaddress(swap->I.alicestr,coinaddr);
            fprintf(fp,",\"Apayment\":\"%s\"",coinaddr);
        }
        if ( rawtx->I.redeemlen > 0 )
        {
            char scriptstr[2049];
            init_hexbytes_noT(scriptstr,rawtx->redeemscript,rawtx->I.redeemlen);
            fprintf(fp,",\"redeem\":\"%s\"",scriptstr);
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
        fprintf(fp,"{\"tradeid\":%u,\"aliceid\":\"%llu\",\"src\":\"%s\",\"srcamount\":%.8f,\"dest\":\"%s\",\"destamount\":%.8f,\"requestid\":%u,\"quoteid\":%u,\"iambob\":%d,\"state\":%u,\"otherstate\":%u,\"expiration\":%u,\"dlocktime\":%u,\"plocktime\":%u,\"Atxfee\":%llu,\"Btxfee\":%llu",swap->tradeid,(long long)swap->aliceid,swap->I.req.src,dstr(swap->I.req.srcamount),swap->I.req.dest,dstr(swap->I.req.destamount),swap->I.req.requestid,swap->I.req.quoteid,swap->I.iambob,swap->I.statebits,swap->I.otherstatebits,swap->I.expiration,swap->bobdeposit.I.locktime,swap->bobpayment.I.locktime,(long long)swap->I.Atxfee,(long long)swap->I.Btxfee);
        if ( swap->I.iambob == 0 )
            fprintf(fp,",\"Agui\":\"%s\"",G.gui);
        else fprintf(fp,",\"Bgui\":\"%s\"",G.gui);
        fprintf(fp,",\"gui\":\"%s\"",G.gui);
        fprintf(fp,",\"uuid\":\"%s\"",swap->uuidstr);
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
        fprintf(fp,",\"other33\":\"");
        for (i=0; i<33; i++)
            fprintf(fp,"%02x",swap->persistent_other33[i]);
        fprintf(fp,"\",\"dest33\":\"");
        for (i=0; i<33; i++)
            fprintf(fp,"%02x",swap->persistent_pubkey33[i]);
        fprintf(fp,"\"}\n");
        fclose(fp);
    }
}

void basilisk_dontforget_update(struct basilisk_swap *swap,struct basilisk_rawtx *rawtx)
{
    bits256 triggertxid;
    memset(triggertxid.bytes,0,sizeof(triggertxid));
    if ( rawtx == 0 )
    {
        basilisk_dontforget(swap,0,0,triggertxid);
        return;
    }
    if ( rawtx == &swap->myfee )
        basilisk_dontforget(swap,&swap->myfee,0,triggertxid);
    else if ( rawtx == &swap->otherfee )
        basilisk_dontforget(swap,&swap->otherfee,0,triggertxid);
    else if ( rawtx == &swap->bobdeposit )
    {
        basilisk_dontforget(swap,&swap->bobdeposit,0,triggertxid);
        basilisk_dontforget(swap,&swap->bobrefund,swap->bobdeposit.I.locktime,triggertxid);
    }
    else if ( rawtx == &swap->bobrefund )
        basilisk_dontforget(swap,&swap->bobrefund,swap->bobdeposit.I.locktime,triggertxid);
    else if ( rawtx == &swap->aliceclaim )
    {
        basilisk_dontforget(swap,&swap->bobrefund,0,triggertxid);
        basilisk_dontforget(swap,&swap->aliceclaim,0,swap->bobrefund.I.actualtxid);
    }
    else if ( rawtx == &swap->alicepayment )
    {
        basilisk_dontforget(swap,&swap->alicepayment,0,swap->bobdeposit.I.actualtxid);
    }
    else if ( rawtx == &swap->bobspend )
    {
        basilisk_dontforget(swap,&swap->alicepayment,0,swap->bobdeposit.I.actualtxid);
        basilisk_dontforget(swap,&swap->bobspend,0,swap->alicepayment.I.actualtxid);
    }
    else if ( rawtx == &swap->alicereclaim )
    {
        basilisk_dontforget(swap,&swap->alicepayment,0,swap->bobdeposit.I.actualtxid);
        basilisk_dontforget(swap,&swap->alicereclaim,0,swap->bobrefund.I.actualtxid);
    }
    else if ( rawtx == &swap->bobpayment )
    {
        basilisk_dontforget(swap,&swap->bobpayment,0,triggertxid);
        basilisk_dontforget(swap,&swap->bobreclaim,swap->bobpayment.I.locktime,triggertxid);
    }
    else if ( rawtx == &swap->alicespend )
    {
        basilisk_dontforget(swap,&swap->bobpayment,0,triggertxid);
        basilisk_dontforget(swap,&swap->alicespend,0,triggertxid);
    }
    else if ( rawtx == &swap->bobreclaim )
        basilisk_dontforget(swap,&swap->bobreclaim,swap->bobpayment.I.locktime,triggertxid);
    if ( IPC_ENDPOINT >= 0 )
    {
        char fname[512],*fstr,*outstr; long fsize; cJSON *reqjson;
        sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,swap->I.req.requestid,swap->I.req.quoteid), OS_compatible_path(fname);
        if ( rawtx != 0 )
            sprintf(fname+strlen(fname),".%s",rawtx->name);
        if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
        {
            if ( (reqjson= cJSON_Parse(fstr)) != 0 )
            {
                if ( jobj(reqjson,"method") != 0 )
                    jdelete(reqjson,"method");
                jaddstr(reqjson,"method","update");
                if ( jobj(reqjson,"update") != 0 )
                    jdelete(reqjson,"update");
                if ( rawtx != 0 )
                    jaddstr(reqjson,"update",rawtx->name);
                else jaddstr(reqjson,"update","main");
                jaddnum(reqjson,"requestid",swap->I.req.requestid);
                jaddnum(reqjson,"quoteid",swap->I.req.quoteid);
                outstr = jprint(reqjson,1);
                LP_queuecommand(0,outstr,IPC_ENDPOINT,-1,0);
                free(outstr);
            }
            free(fstr);
        }
    }
}

bits256 basilisk_swap_privbob_extract(char *symbol,bits256 spendtxid,int32_t vini,int32_t revflag)
{
    bits256 privkey; int32_t i,scriptlen,siglen; uint8_t script[1024]; // from Bob refund of Bob deposit
    memset(&privkey,0,sizeof(privkey));
    if ( (scriptlen= basilisk_swap_getsigscript(symbol,script,(int32_t)sizeof(script),spendtxid,vini)) > 0 )
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

bits256 basilisk_swap_privBn_extract(bits256 *bobrefundp,char *bobcoin,bits256 bobdeposit,bits256 privBn)
{
    char destaddr[64];
    destaddr[0] = 0;
    if ( bits256_nonz(privBn) == 0 )
    {
        if ( bits256_nonz(bobdeposit) != 0 )
            *bobrefundp = LP_swap_spendtxid(bobcoin,destaddr,bobdeposit,0);
        if ( bits256_nonz(*bobrefundp) != 0 )
            privBn = basilisk_swap_privbob_extract(bobcoin,*bobrefundp,0,0);
    }
    return(privBn);
}

bits256 basilisk_swap_spendupdate(int32_t iambob,char *symbol,char *spentaddr,int32_t *sentflags,bits256 *txids,int32_t utxoind,int32_t alicespent,int32_t bobspent,int32_t utxovout,char *aliceaddr,char *bobaddr,char *Adest,char *dest)
{
    bits256 spendtxid,txid; char destaddr[64],str[65]; int32_t i,n,j,numvins,numvouts; struct iguana_info *coin; cJSON *array,*txobj,*vins,*vin,*vouts;
    memset(&spendtxid,0,sizeof(spendtxid));
    destaddr[0] = 0;
    if ( (coin= LP_coinfind(symbol)) == 0 )
        return(spendtxid);
    //printf("spentaddr.%s aliceaddr.%s bobaddr.%s Adest.%s Bdest.%s\n",spentaddr,aliceaddr,bobaddr,Adest,dest);
    if ( coin->electrum != 0 )
    {
        if ( (array= electrum_address_gethistory(symbol,coin->electrum,&array,spentaddr,txids[utxoind])) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) > 0 )
            {
                for (i=0; i<n; i++)
                {
                    txid = jbits256(jitem(array,i),"tx_hash");
                    if ( 0 && utxoind == BASILISK_BOBPAYMENT )
                        printf("i.%d of %d: %s\n",i,n,bits256_str(str,txid));
                    if ( bits256_cmp(txid,txids[utxoind]) != 0 )
                    {
                        if ( (txobj= LP_gettx("basilisk_swap_spendupdate",symbol,txid,1)) != 0 )
                        {
                            if ( (vins= jarray(&numvins,txobj,"vin")) != 0 )
                            {
                                for (j=0; j<numvins; j++)
                                {
                                    vin = jitem(vins,j);
                                    if ( 0 && utxoind == BASILISK_BOBPAYMENT )
                                        printf("vini.%d %s\n",j,jprint(vin,0));
                                    if ( utxovout == jint(vin,"vout") && bits256_cmp(txids[utxoind],jbits256(vin,"txid")) == 0 )
                                    {
                                        if ( (vouts= jarray(&numvouts,txobj,"vout")) != 0 )
                                            LP_destaddr(destaddr,jitem(vouts,0));
                                        free_json(txobj);
                                        if ( bobaddr != 0 && (strcmp(destaddr,bobaddr) == 0 || strcmp(dest,destaddr) == 0) )
                                        {
                                            sentflags[bobspent] = 1;
                                            sentflags[alicespent] = 0;
                                            txids[bobspent] = spendtxid;
                                            //printf("bobspent.[%d] <- 1\n",bobspent);
                                        }
                                        else if ( aliceaddr != 0 && (strcmp(destaddr,aliceaddr) == 0 || strcmp(Adest,destaddr) == 0) )
                                        {
                                            sentflags[alicespent] = 1;
                                            sentflags[bobspent] = 0;
                                            txids[alicespent] = spendtxid;
                                        }
                                        //else printf("unknown spender\n");
                                        sentflags[utxoind] = 1;
                                        if ( 0 && utxoind == BASILISK_BOBPAYMENT )
                                            printf("found match destaddr.(%s)\n",destaddr);
                                        return(txid);
                                    }
                                }
                            }
                            free_json(txobj);
                        }
                    }
                }
            }
            //printf("processed history.(%s) %s\n",jprint(array,0),bits256_str(str,txids[utxoind]));
            free_json(array);
        }
    }
    else
    {
        if ( iambob != 0 )
            strcpy(destaddr,aliceaddr);
        else strcpy(destaddr,bobaddr);
    }
    txid = txids[utxoind];
    if ( bits256_nonz(txid) != 0 )//&& sentflags[utxoind] != 0 )
    {
        spendtxid = LP_swap_spendtxid(symbol,destaddr,txid,utxovout);
        if ( bits256_nonz(spendtxid) != 0 )
        {
            sentflags[utxoind] = 1;
            if ( 0 && utxoind == BASILISK_BOBPAYMENT )
                printf("utxoind.%d Alice.(%s %s) Bob.(%s %s) vs destaddr.(%s)\n",utxoind,aliceaddr,Adest,bobaddr,dest,destaddr);
            if ( aliceaddr != 0 && (strcmp(destaddr,aliceaddr) == 0 || strcmp(Adest,destaddr) == 0) )
            {
                if ( 0 && utxoind == BASILISK_BOBPAYMENT )
                    printf("ALICE spent.(%s) -> %s\n",bits256_str(str,txid),destaddr);
                sentflags[alicespent] = 1;
                sentflags[bobspent] = 0;
                txids[alicespent] = spendtxid;
            }
            else if ( bobaddr != 0 && (strcmp(destaddr,bobaddr) == 0 || strcmp(dest,destaddr) == 0) )
            {
                if ( 0 && utxoind == BASILISK_BOBPAYMENT )
                    printf("BOB spent.(%s) -> %s\n",bits256_str(str,txid),destaddr);
                sentflags[bobspent] = 1;
                sentflags[alicespent] = 0;
                txids[bobspent] = spendtxid;
            }
            else
            {
                if ( 0 && utxoind == BASILISK_BOBPAYMENT )
                    printf("OTHER dest spent.(%s) -> %s\n",bits256_str(str,txid),destaddr);
                if ( iambob == 0 )
                {
                    sentflags[bobspent] = 1;
                    sentflags[alicespent] = 0;
                    txids[bobspent] = spendtxid;
                }
                else 
                {
                    sentflags[alicespent] = 1;
                    sentflags[bobspent] = 0;
                    txids[alicespent] = spendtxid;
                }
            }
        }
        else if ( 0 && utxoind == BASILISK_BOBPAYMENT )
            printf("no spend of %s/v%d detected\n",bits256_str(str,txid),utxovout);
    } //else printf("utxoind.%d null txid\n",utxoind);
    return(spendtxid);
}

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

int32_t basilisk_swap_isfinished(uint32_t requestid,uint32_t quoteid,uint32_t expiration,int32_t iambob,bits256 *txids,int32_t *sentflags,bits256 paymentspent,bits256 Apaymentspent,bits256 depositspent,uint32_t lockduration)
{
    int32_t i,n = 0; uint32_t now = (uint32_t)time(NULL);
    if ( bits256_nonz(paymentspent) != 0 && bits256_nonz(Apaymentspent) != 0 && bits256_nonz(depositspent) != 0 )
        return(1);
    else if ( sentflags[BASILISK_BOBPAYMENT] == 0 && bits256_nonz(txids[BASILISK_BOBPAYMENT]) == 0 && bits256_nonz(Apaymentspent) != 0 && bits256_nonz(depositspent) != 0 )
        return(1);
    else if ( sentflags[BASILISK_BOBPAYMENT] == 0 && bits256_nonz(txids[BASILISK_BOBPAYMENT]) == 0 && sentflags[BASILISK_ALICEPAYMENT] == 0 && bits256_nonz(txids[BASILISK_ALICEPAYMENT]) == 0 && bits256_nonz(depositspent) != 0 )
        return(1);
    else if ( sentflags[BASILISK_BOBPAYMENT] != 0 && sentflags[BASILISK_ALICEPAYMENT] != 0 && sentflags[BASILISK_BOBDEPOSIT] != 0 && sentflags[BASILISK_BOBRECLAIM] != 0 )
    {
        if ( sentflags[BASILISK_ALICECLAIM] != 0 )
        {
            if ( iambob != 0 )
            {
                printf("used to be edge case unspendable alicepayment %u-%u\n",requestid,quoteid);
                return(0);
            } else return(1);
        }
    }
    if ( now > expiration - lockduration )
    {
        if ( bits256_nonz(paymentspent) != 0 )
            n++;
        if ( bits256_nonz(Apaymentspent) != 0 )
            n++;
        if ( bits256_nonz(depositspent) != 0 )
            n++;
        for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
        {
            if ( i != BASILISK_OTHERFEE && i != BASILISK_MYFEE && sentflags[i] != 0 )
            {
                if ( bits256_nonz(txids[i]) != 0 )
                    n++;
            }
        }
        if ( n == 0 )
        {
            //printf("if nothing sent, it is finished\n");
            return(1);
        }
    }
    if ( iambob != 0 )
    {
        if ( (sentflags[BASILISK_BOBSPEND] != 0 || sentflags[BASILISK_BOBRECLAIM] != 0) && sentflags[BASILISK_BOBREFUND] != 0 )
            return(1);
        else if ( (bits256_nonz(txids[BASILISK_BOBPAYMENT]) == 0 || sentflags[BASILISK_BOBPAYMENT] == 0) && sentflags[BASILISK_BOBREFUND] != 0 )
            return(1);
        else if ( now > expiration )
        {
            if ( bits256_nonz(txids[BASILISK_BOBDEPOSIT]) == 0 && sentflags[BASILISK_BOBDEPOSIT] == 0 )
                return(1);
            else if ( bits256_nonz(txids[BASILISK_BOBPAYMENT]) == 0 || sentflags[BASILISK_BOBPAYMENT] == 0 )
            {
                if ( bits256_nonz(depositspent) != 0 )
                {
                    //if ( bits256_nonz(Apaymentspent) == 0 && sentflags[BASILISK_BOBREFUND] == 0 )
                    //    printf("used to be bob was too late in claiming bobrefund %u-%u\n",requestid,quoteid);
                    return(0);
                }
            }
            //else if ( bits256_nonz(Apaymentspent) != 0 )
            //    return(1);
            else if ( bits256_nonz(Apaymentspent) != 0 && bits256_nonz(paymentspent) != 0 && bits256_nonz(depositspent) != 0 )
                return(1);
        }
    }
    else
    {
        if ( sentflags[BASILISK_ALICESPEND] != 0 || sentflags[BASILISK_ALICERECLAIM] != 0 || sentflags[BASILISK_ALICECLAIM] != 0 )
            return(1);
        else if ( now > expiration )
        {
            if ( sentflags[BASILISK_ALICEPAYMENT] == 0 )
            {
                if ( bits256_nonz(txids[BASILISK_ALICEPAYMENT]) == 0 )
                    return(1);
                else if ( sentflags[BASILISK_BOBREFUND] != 0 ) //sentflags[BASILISK_BOBPAYMENT] != 0
                    return(1);
            }
            else
            {
                if ( sentflags[BASILISK_ALICESPEND] != 0 )
                    return(1);
                else if ( sentflags[BASILISK_ALICERECLAIM] != 0 )
                    return(1);
                else if ( sentflags[BASILISK_ALICECLAIM] != 0 ) //got deposit! happy alice
                    return(1);
            }
        }
    }
    return(0);
}

uint32_t LP_extract(uint32_t requestid,uint32_t quoteid,char *rootfname,char *field)
{
    char fname[1024],*filestr,*redeemstr; long fsize; int32_t len; uint32_t t=0; cJSON *json; uint8_t redeem[1024];
    if ( strcmp(field,"dlocktime") == 0 )
        sprintf(fname,"%s.bobdeposit",rootfname);
    else if ( strcmp(field,"plocktime") == 0 )
        sprintf(fname,"%s.bobpayment",rootfname);
    if ( (filestr= OS_filestr(&fsize,fname)) != 0 )
    {
        if ( (json= cJSON_Parse(filestr)) != 0 )
        {
            if ( (redeemstr= jstr(json,"redeem")) != 0 && (len= (int32_t)strlen(redeemstr)) <= sizeof(redeem)*2 )
            {
                len >>= 1;
                decode_hex(redeem,len,redeemstr);
                t = redeem[5];
                t = (t << 8) | redeem[4];
                t = (t << 8) | redeem[3];
                t = (t << 8) | redeem[2];
                //printf("extracted timestamp.%u\n",t);
            }
            free_json(json);
        }
        free(filestr);
    }
    return(t);
}

void LP_totals_update(int32_t iambob,char *alicecoin,char *bobcoin,int64_t *KMDtotals,int64_t *BTCtotals,int32_t *sentflags,int64_t *values) // update to handle all coins
{
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
}

cJSON *LP_swap_json(struct LP_swap_remember *rswap)
{
    cJSON *item,*array; int32_t i;
    item = cJSON_CreateObject();
    if ( LP_swap_endcritical < LP_swap_critical )
    {
        jaddstr(item,"warning","swaps in critical section, dont exit now");
        jaddnum(item,"critical",LP_swap_critical);
        jaddnum(item,"endcritical",LP_swap_endcritical);
    }
    jaddstr(item,"uuid",rswap->uuidstr);
    jaddnum(item,"expiration",rswap->expiration);// - INSTANTDEX_LOCKTIME*2);
    jaddnum(item,"tradeid",rswap->tradeid);
    jaddnum(item,"requestid",rswap->requestid);
    jaddnum(item,"quoteid",rswap->quoteid);
    jaddnum(item,"iambob",rswap->iambob);
    jaddstr(item,"Bgui",rswap->Bgui);
    jaddstr(item,"Agui",rswap->Agui);
    jaddstr(item,"gui",rswap->gui);
    jaddstr(item,"bob",rswap->src);
    if ( rswap->bobtomic[0] != 0 )
        jaddstr(item,"bobtomic",rswap->bobtomic);
    if ( rswap->etomicsrc[0] != 0 )
        jaddstr(item,"etomicsrc",rswap->etomicsrc);
    jaddnum(item,"srcamount",dstr(rswap->srcamount));
    jaddnum(item,"bobtxfee",dstr(rswap->Btxfee));
    jaddstr(item,"alice",rswap->dest);
    if ( rswap->alicetomic[0] != 0 )
        jaddstr(item,"alicetomic",rswap->alicetomic);
    if ( rswap->etomicdest[0] != 0 )
        jaddstr(item,"etomicdest",rswap->etomicdest);
    jaddnum(item,"destamount",dstr(rswap->destamount));
    jaddnum(item,"alicetxfee",dstr(rswap->Atxfee));
    jadd64bits(item,"aliceid",rswap->aliceid);
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
    {
        if ( rswap->sentflags[i] != 0 )
            jaddistr(array,txnames[i]);
        if ( rswap->txbytes[i] != 0 )
            free(rswap->txbytes[i]), rswap->txbytes[i] = 0;
    }
    jadd(item,"sentflags",array);
    array = cJSON_CreateArray();
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
        jaddinum(array,dstr(rswap->values[i]));
    jadd(item,"values",array);
    jaddstr(item,"result","success");
    if ( rswap->finishedflag != 0 )
    {
        jaddstr(item,"status","finished");
        jaddnum(item,"finishtime",rswap->finishtime);
    }
    else jaddstr(item,"status","pending");
    jaddbits256(item,"bobdeposit",rswap->txids[BASILISK_BOBDEPOSIT]);
    jaddbits256(item,"alicepayment",rswap->txids[BASILISK_ALICEPAYMENT]);
    jaddbits256(item,"bobpayment",rswap->txids[BASILISK_BOBPAYMENT]);
    jaddbits256(item,"paymentspent",rswap->paymentspent);
    jaddbits256(item,"Apaymentspent",rswap->Apaymentspent);
    jaddbits256(item,"depositspent",rswap->depositspent);
    return(item);
}

int32_t LP_rswap_init(struct LP_swap_remember *rswap,uint32_t requestid,uint32_t quoteid,int32_t forceflag)
{
    char fname[1024],*fstr,*secretstr,*srcstr,*deststr,*dest33,*txname; long fsize; cJSON *item,*txobj,*array; bits256 privkey; struct iguana_info *coin; uint32_t r,q; int32_t i,j,n; uint8_t other33[33]; uint32_t lockduration;
    memset(rswap,0,sizeof(*rswap));
    rswap->requestid = requestid;
    rswap->quoteid = quoteid;
    sprintf(fname,"%s/SWAPS/%u-%u",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
    if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
    {
        if ( (item= cJSON_Parse(fstr)) != 0 )
        {
            rswap->iambob = jint(item,"iambob");
            safecopy(rswap->uuidstr,jstr(item,"uuid"),sizeof(rswap->uuidstr));
            safecopy(rswap->Bgui,jstr(item,"Bgui"),sizeof(rswap->Bgui));
            safecopy(rswap->Agui,jstr(item,"Agui"),sizeof(rswap->Agui));
            safecopy(rswap->gui,jstr(item,"gui"),sizeof(rswap->gui));
            safecopy(rswap->bobtomic,jstr(item,"bobtomic"),sizeof(rswap->bobtomic));
            safecopy(rswap->alicetomic,jstr(item,"alicetomic"),sizeof(rswap->alicetomic));
            rswap->tradeid = juint(item,"tradeid");
            rswap->aliceid = j64bits(item,"aliceid");
            if ( (secretstr= jstr(item,"secretAm")) != 0 && strlen(secretstr) == 40 )
                decode_hex(rswap->secretAm,20,secretstr);
            if ( (secretstr= jstr(item,"secretAm256")) != 0 && strlen(secretstr) == 64 )
                decode_hex(rswap->secretAm256,32,secretstr);
            if ( (secretstr= jstr(item,"secretBn")) != 0 && strlen(secretstr) == 40 )
                decode_hex(rswap->secretBn,20,secretstr);
            if ( (secretstr= jstr(item,"secretBn256")) != 0 && strlen(secretstr) == 64 )
                decode_hex(rswap->secretBn256,32,secretstr);
            if ( (srcstr= jstr(item,"src")) != 0 )
                safecopy(rswap->src,srcstr,sizeof(rswap->src));
            if ( (deststr= jstr(item,"dest")) != 0 )
                safecopy(rswap->dest,deststr,sizeof(rswap->dest));
            if ( (dest33= jstr(item,"dest33")) != 0 && strlen(dest33) == 66 )
            {
                decode_hex(rswap->pubkey33,33,dest33);
                if ( rswap->iambob != 0 && (coin= LP_coinfind(rswap->src)) != 0 )
                    bitcoin_address(coin->symbol,rswap->destaddr,coin->taddr,coin->pubtype,rswap->pubkey33,33);
                else if ( rswap->iambob == 0 && (coin= LP_coinfind(rswap->dest)) != 0 )
                    bitcoin_address(coin->symbol,rswap->Adestaddr,coin->taddr,coin->pubtype,rswap->pubkey33,33);
                //for (i=0; i<33; i++)
                //    printf("%02x",pubkey33[i]);
                //printf(" <- %s dest33\n",dest33);
            }
            if ( (dest33= jstr(item,"other33")) != 0 && strlen(dest33) == 66 )
            {
                decode_hex(other33,33,dest33);
                for (i=0; i<33; i++)
                    if ( other33[i] != 0 )
                        break;
                if ( i < 33 )
                    memcpy(rswap->other33,other33,33);
                if ( rswap->iambob != 0 && (coin= LP_coinfind(rswap->dest)) != 0 )
                    bitcoin_address(coin->symbol,rswap->Adestaddr,coin->taddr,coin->pubtype,rswap->other33,33);
                else if ( rswap->iambob == 0 && (coin= LP_coinfind(rswap->src)) != 0 )
                    bitcoin_address(coin->symbol,rswap->destaddr,coin->taddr,coin->pubtype,rswap->other33,33);
                //printf("(%s, %s) <- %s other33\n",rswap->destaddr,rswap->Adestaddr,dest33);
            }
            if ( (rswap->plocktime= juint(item,"plocktime")) == 0 )
                rswap->plocktime = LP_extract(requestid,quoteid,fname,"plocktime");
            if ( (rswap->dlocktime= juint(item,"dlocktime")) == 0 )
                rswap->dlocktime = LP_extract(requestid,quoteid,fname,"dlocktime");
            r = juint(item,"requestid");
            q = juint(item,"quoteid");
            rswap->Atxfee = j64bits(item,"Atxfee");
            rswap->Btxfee = j64bits(item,"Btxfee");
            rswap->pubA0 = jbits256(item,"pubA0");
            rswap->pubB0 = jbits256(item,"pubB0");
            rswap->pubB1 = jbits256(item,"pubB1");
            privkey = jbits256(item,"myprivs0");
            if ( bits256_nonz(privkey) != 0 )
                rswap->myprivs[0] = privkey;
            privkey = jbits256(item,"myprivs1");
            if ( bits256_nonz(privkey) != 0 )
                rswap->myprivs[1] = privkey;
            privkey = jbits256(item,"privAm");
            if ( bits256_nonz(privkey) != 0 )
            {
                rswap->privAm = privkey;
                //printf("set privAm <- %s\n",bits256_str(str,privAm));
            }
            privkey = jbits256(item,"privBn");
            if ( bits256_nonz(privkey) != 0 )
            {
                rswap->privBn = privkey;
                //printf("set privBn <- %s\n",bits256_str(str,privBn));
            }
            rswap->expiration = juint(item,"expiration");
            rswap->state = jint(item,"state");
            rswap->otherstate = jint(item,"otherstate");
            rswap->srcamount = SATOSHIDEN * jdouble(item,"srcamount");
            rswap->destamount = SATOSHIDEN * jdouble(item,"destamount");
            rswap->txids[BASILISK_BOBDEPOSIT] = jbits256(item,"Bdeposit");
            rswap->txids[BASILISK_BOBREFUND] = jbits256(item,"Brefund");
            rswap->txids[BASILISK_ALICECLAIM] = jbits256(item,"Aclaim");
            rswap->txids[BASILISK_BOBPAYMENT] = jbits256(item,"Bpayment");
            rswap->txids[BASILISK_ALICESPEND] = jbits256(item,"Aspend");
            rswap->txids[BASILISK_BOBRECLAIM] = jbits256(item,"Breclaim");
            rswap->txids[BASILISK_ALICEPAYMENT] = jbits256(item,"Apayment");
            rswap->txids[BASILISK_BOBSPEND] = jbits256(item,"Bspend");
            rswap->txids[BASILISK_ALICERECLAIM] = jbits256(item,"Areclaim");
            rswap->txids[BASILISK_MYFEE] = jbits256(item,"myfee");
            rswap->txids[BASILISK_OTHERFEE] = jbits256(item,"otherfee");
            free_json(item);
        } else printf("couldnt parse.(%s)\n",fstr);
        free(fstr);
    } // else printf("cant open.(%s)\n",fname);
    sprintf(fname,"%s/SWAPS/%u-%u.finished",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
    if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
    {
        //printf("%s -> (%s)\n",fname,fstr);
        if ( (txobj= cJSON_Parse(fstr)) != 0 )
        {
            rswap->paymentspent = jbits256(txobj,"paymentspent");
            rswap->Apaymentspent = jbits256(txobj,"Apaymentspent");
            rswap->depositspent = jbits256(txobj,"depositspent");
            if ( (array= jarray(&n,txobj,"values")) != 0 )
                for (i=0; i<n&&i<sizeof(txnames)/sizeof(*txnames); i++)
                    rswap->values[i] = SATOSHIDEN * jdouble(jitem(array,i),0);
            if ( (array= jarray(&n,txobj,"sentflags")) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( (txname= jstri(array,i)) != 0 )
                    {
                        for (j=0; j<sizeof(txnames)/sizeof(*txnames); j++)
                            if ( strcmp(txname,txnames[j]) == 0 )
                            {
                                rswap->sentflags[j] = 1;
                                //printf("finished.%s\n",txnames[j]);
                                break;
                            }
                    }
                }
            }
            free_json(txobj);
        }
        lockduration = LP_atomic_locktime(rswap->bobcoin,rswap->alicecoin);
        rswap->origfinishedflag = basilisk_swap_isfinished(requestid,quoteid,rswap->expiration,rswap->iambob,rswap->txids,rswap->sentflags,rswap->paymentspent,rswap->Apaymentspent,rswap->depositspent,lockduration);
        rswap->finishedflag = rswap->origfinishedflag;
        if ( forceflag != 0 )
            rswap->finishedflag = rswap->origfinishedflag = 0;
        free(fstr);
    }
    return(rswap->iambob);
}

int32_t _LP_refht_update(struct iguana_info *coin,bits256 txid,int32_t refht)
{
    refht -= 9;
    if ( refht > 10 && (coin->firstrefht == 0 || refht < coin->firstrefht) )
    {
        char str[65]; printf(">>>>>>>>. 1st refht %s %s <- %d, scan %d %d\n",coin->symbol,bits256_str(str,txid),refht,coin->firstscanht,coin->lastscanht);
        if ( coin->firstscanht == 0 || refht < coin->firstscanht )
            coin->firstscanht = coin->lastscanht = refht;
        coin->firstrefht = refht;
        return(1);
    }
    return(0);
}

int32_t LP_refht_update(char *symbol,bits256 txid)
{
    int32_t refht; struct iguana_info *coin;
    if ( (coin= LP_coinfind(symbol)) != 0 && coin->electrum == 0 )
    {
        if ( (refht= LP_txheight(coin,txid)) > 0 && refht > 0 )
            return(_LP_refht_update(coin,txid,refht));
    }
    return(0);
}

int32_t LP_swap_load(struct LP_swap_remember *rswap,int32_t forceflag)
{
    int32_t i,needflag,addflag; long fsize; char fname[1024],*fstr,*symbol,*rstr; cJSON *txobj,*sentobj,*fileobj; bits256 txid,checktxid; uint64_t value;
    rswap->iambob = -1;
    sprintf(fname,"%s/SWAPS/%u-%u.finished",GLOBAL_DBDIR,rswap->requestid,rswap->quoteid), OS_compatible_path(fname);
    if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
    {
        if ( (fileobj= cJSON_Parse(fstr)) != 0 )
        {
            rswap->finishtime = juint(fileobj,"finishtime");
            if ( forceflag == 0 )
                rswap->origfinishedflag = rswap->finishedflag = 1;
            free_json(fileobj);
        }
        free(fstr);
    }
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
    {
        needflag = addflag = 0;
        sprintf(fname,"%s/SWAPS/%u-%u.%s",GLOBAL_DBDIR,rswap->requestid,rswap->quoteid,txnames[i]), OS_compatible_path(fname);
        if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
        {
            if ( 0 && rswap->finishedflag == 0 )
                printf("%s\n",fname);
            //printf("%s -> (%s)\n",fname,fstr);
            if ( (txobj= cJSON_Parse(fstr)) != 0 )
            {
                //printf("TXOBJ.(%s)\n",jprint(txobj,0));
                if ( jobj(txobj,"iambob") != 0 )
                    rswap->iambob = jint(txobj,"iambob");
                txid = jbits256(txobj,"txid");
                if ( bits256_nonz(txid) == 0 )
                {
                    free(fstr);
                    free_json(txobj);
                    continue;
                }

                if (jstr(txobj,"etomicsrc") != 0) {
                    strcpy(rswap->etomicsrc,jstr(txobj,"etomicsrc"));
                }

                if (jstr(txobj,"etomicdest") != 0) {
                    strcpy(rswap->etomicdest,jstr(txobj,"etomicdest"));
                }

                if (jstr(txobj,"bobDepositEthTx") != 0) {
                    strcpy(rswap->bobDepositEthTx, jstr(txobj,"bobDepositEthTx"));
                }

                if (jstr(txobj,"bobPaymentEthTx") != 0) {
                    strcpy(rswap->bobPaymentEthTx, jstr(txobj,"bobPaymentEthTx"));
                }

                if (jstr(txobj,"alicePaymentEthTx") != 0) {
                    strcpy(rswap->alicePaymentEthTx, jstr(txobj,"alicePaymentEthTx"));
                }

                if (jstr(txobj,"bobtomic") != 0) {
                    strcpy(rswap->bobtomic, jstr(txobj,"bobtomic"));
                }

                if (jstr(txobj,"alicetomic") != 0) {
                    strcpy(rswap->alicetomic, jstr(txobj,"alicetomic"));
                }

                rswap->txids[i] = txid;
                if ( jstr(txobj,"Apayment") != 0 )
                    safecopy(rswap->alicepaymentaddr,jstr(txobj,"Apayment"),sizeof(rswap->alicepaymentaddr));
                if ( jstr(txobj,"Bpayment") != 0 )
                    safecopy(rswap->bobpaymentaddr,jstr(txobj,"Bpayment"),sizeof(rswap->bobpaymentaddr));
                if ( jstr(txobj,"Bdeposit") != 0 )
                    safecopy(rswap->bobdepositaddr,jstr(txobj,"Bdeposit"),sizeof(rswap->bobdepositaddr));
                if ( jobj(txobj,"tx") != 0 )
                {
                    rswap->txbytes[i] = clonestr(jstr(txobj,"tx"));
                    //printf("[%s] TX.(%s)\n",txnames[i],txbytes[i]);
                }
                if ( strcmp(txnames[i],"bobpayment") == 0 && (rstr= jstr(txobj,"redeem")) != 0 && (rswap->Predeemlen= is_hexstr(rstr,0)) > 0 )
                {
                    rswap->Predeemlen >>= 1;
                    decode_hex(rswap->Predeemscript,rswap->Predeemlen,rstr);
                    //printf("%p Predeemscript.(%s)\n",rswap->Predeemscript,rstr);
                }
                else if ( strcmp(txnames[i],"bobdeposit") == 0 && (rstr= jstr(txobj,"redeem")) != 0 && (rswap->Dredeemlen= is_hexstr(rstr,0)) > 0 )
                {
                    rswap->Dredeemlen >>= 1;
                    decode_hex(rswap->Dredeemscript,rswap->Dredeemlen,rstr);
                }
                rswap->values[i] = value = LP_value_extract(txobj,1,txid);
                if ( (symbol= jstr(txobj,"src")) != 0 )
                {
                    safecopy(rswap->src,symbol,sizeof(rswap->src));
                    if ( rswap->iambob >= 0 )
                    {
                        if ( rswap->iambob > 0 )
                            safecopy(rswap->bobcoin,symbol,sizeof(rswap->bobcoin));
                        else safecopy(rswap->alicecoin,symbol,sizeof(rswap->alicecoin));
                    }
                }
                if ( (symbol= jstr(txobj,"dest")) != 0 )
                {
                    safecopy(rswap->dest,symbol,sizeof(rswap->dest));
                    if ( rswap->iambob >= 0 )
                    {
                        if ( rswap->iambob == 0 )
                            safecopy(rswap->bobcoin,symbol,sizeof(rswap->bobcoin));
                        else safecopy(rswap->alicecoin,symbol,sizeof(rswap->alicecoin));
                    }
                }
                if ( (symbol= jstr(txobj,"coin")) != 0 )
                {
                    if ( i == BASILISK_ALICESPEND || i == BASILISK_BOBPAYMENT || i == BASILISK_BOBDEPOSIT || i == BASILISK_BOBREFUND || i == BASILISK_BOBRECLAIM || i == BASILISK_ALICECLAIM )
                        safecopy(rswap->bobcoin,symbol,sizeof(rswap->bobcoin));
                    else if ( i == BASILISK_BOBSPEND || i == BASILISK_ALICEPAYMENT || i == BASILISK_ALICERECLAIM )
                        safecopy(rswap->alicecoin,symbol,sizeof(rswap->alicecoin));
                    if ( rswap->finishedflag == 0 )
                    {
                        if ( (sentobj= LP_gettx("LP_remember",symbol,txid,1)) == 0 )
                        {
                            //char str2[65]; printf("%s %s ready to broadcast %s r%u q%u\n",symbol,bits256_str(str2,txid),txnames[i],rswap->requestid,rswap->quoteid);
                        }
                        else
                        {
                            checktxid = jbits256(sentobj,"txid");
                            if ( bits256_nonz(checktxid) == 0 )
                                checktxid = jbits256(sentobj,"hash");
                            LP_refht_update(symbol,txid);
                            if ( bits256_cmp(checktxid,txid) == 0 )
                            {
                                //printf(">>>>>> %s txid %s\n",jprint(sentobj,0),bits256_str(str,txid));
                                rswap->sentflags[i] = 1;
                            }
                            free_json(sentobj);
                        }
                        //printf("%s %s %.8f\n",txnames[i],bits256_str(str,txid),dstr(value));
                    }
                }

                free_json(txobj);
            } //else printf("no symbol\n");
            free(fstr);
        } else if ( 0 && rswap->finishedflag == 0 )
            printf("%s not finished\n",fname);
    }
    if ( rswap->bobcoin[0] == 0 )
        strcpy(rswap->bobcoin,rswap->src);
    if ( rswap->alicecoin[0] == 0 )
        strcpy(rswap->alicecoin,rswap->dest);
    if ( rswap->src[0] == 0 )
        strcpy(rswap->src,rswap->bobcoin);
    if ( rswap->dest[0] == 0 )
        strcpy(rswap->dest,rswap->alicecoin);
    return(rswap->finishedflag);
}

void LP_txbytes_update(char *name,char *symbol,char *txbytes,bits256 *txidp,bits256 *ptr,int32_t *flagp)
{
    bits256 zero;
    memset(zero.bytes,0,sizeof(zero));
    if ( txbytes != 0 )
    {
        *txidp = LP_broadcast(name,symbol,txbytes,zero);
        if ( bits256_nonz(*txidp) != 0 )
        {
            *flagp = 1;
            if ( ptr != 0 )
                *ptr = *txidp;
        }
    }
}

int32_t LP_rswap_checktx(struct LP_swap_remember *rswap,char *symbol,int32_t txi)
{
    int32_t ht; struct iguana_info *coin; //char str[65];
    if ( rswap->sentflags[txi] == 0 && bits256_nonz(rswap->txids[txi]) != 0 )
    {
        if ( (coin= LP_coinfind(symbol)) != 0 )
        {
            if ( (ht= LP_txheight(coin,rswap->txids[txi])) > 0 )
            {
                rswap->sentflags[txi] = 1;
                _LP_refht_update(coin,rswap->txids[txi],ht);
            } else LP_refht_update(symbol,rswap->txids[txi]);
            //printf("[%s] %s txbytes.%p %s ht.%d\n",txnames[txi],txnames[txi],rswap->txbytes[txi],bits256_str(str,rswap->txids[txi]),ht);
        }
    } //else printf("sent.%d %s txi.%d\n",rswap->sentflags[txi],bits256_str(str,rswap->txids[txi]),txi);
    return(0);
}

int32_t LP_spends_set(struct LP_swap_remember *rswap)
{
    int32_t numspent = 0;
    if ( bits256_nonz(rswap->paymentspent) == 0 )
    {
        if ( bits256_nonz(rswap->txids[BASILISK_ALICESPEND]) != 0 )
            rswap->paymentspent = rswap->txids[BASILISK_ALICESPEND];
        else rswap->paymentspent = rswap->txids[BASILISK_BOBRECLAIM];
    } else numspent++;
    if ( bits256_nonz(rswap->depositspent) == 0 )
    {
        if ( bits256_nonz(rswap->txids[BASILISK_BOBREFUND]) != 0 )
            rswap->depositspent = rswap->txids[BASILISK_BOBREFUND];
        else rswap->depositspent = rswap->txids[BASILISK_ALICECLAIM];
    } else numspent++;
    if ( bits256_nonz(rswap->Apaymentspent) == 0 )
    {
        if ( bits256_nonz(rswap->txids[BASILISK_BOBSPEND]) != 0 )
            rswap->Apaymentspent = rswap->txids[BASILISK_BOBSPEND];
        else rswap->Apaymentspent = rswap->txids[BASILISK_ALICERECLAIM];
    } else numspent++;
    return(numspent);
}

cJSON *basilisk_remember(int32_t fastflag,int64_t *KMDtotals,int64_t *BTCtotals,uint32_t requestid,uint32_t quoteid,int32_t forceflag,int32_t pendingonly)
{
    static void *ctx;
    struct LP_swap_remember rswap; int32_t i,j,flag,numspent,len,secretstart,redeemlen; char str[65],*srcAdest,*srcBdest,*destAdest,*destBdest,otheraddr[64],*fstr,fname[512],bobtomic[128],alicetomic[128],bobstr[65],alicestr[65]; cJSON *item,*txoutobj,*retjson; bits256 rev,revAm,signedtxid,zero,deadtxid; uint32_t claimtime,lockduration; struct iguana_info *bob=0,*alice=0; uint8_t redeemscript[1024],userdata[1024]; long fsize;
    sprintf(fname,"%s/SWAPS/%u-%u.finished",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
    if ( (fstr= OS_filestr(&fsize,fname)) != 0 )
    {
        if ( (retjson= cJSON_Parse(fstr)) != 0 )
        {
            free(fstr);
            if ( pendingonly != 0 )
                free_json(retjson), retjson = 0;
            return(retjson);
        }
        free(fstr);
    }
    if ( ctx == 0 )
        ctx = bitcoin_ctx();
    if ( requestid == 0 || quoteid == 0 )
        return(cJSON_Parse("{\"error\":\"null requestid or quoteid\"}"));
    if ( (rswap.iambob= LP_rswap_init(&rswap,requestid,quoteid,forceflag)) < 0 )
        return(cJSON_Parse("{\"error\":\"couldnt initialize rswap, are all coins active?\"}"));
    decode_hex(deadtxid.bytes,32,"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    LP_swap_load(&rswap,forceflag);
    memset(zero.bytes,0,sizeof(zero));
    otheraddr[0] = 0;
    claimtime = (uint32_t)time(NULL) - 777;
    srcAdest = srcBdest = destAdest = destBdest = 0;
    alice = LP_coinfind(rswap.alicecoin);
    bob = LP_coinfind(rswap.bobcoin);
    LP_etomicsymbol(bobstr,bobtomic,rswap.src);
    LP_etomicsymbol(alicestr,alicetomic,rswap.dest);
    lockduration = LP_atomic_locktime(rswap.bobcoin,rswap.alicecoin);
    if ( rswap.bobcoin[0] == 0 || rswap.alicecoin[0] == 0 || strcmp(rswap.bobcoin,bobstr) != 0 || strcmp(rswap.alicecoin,alicestr) != 0 )
    {
        //printf("legacy r%u-q%u DB SWAPS.(%u %u) %llu files BOB.(%s) Alice.(%s) src.(%s) dest.(%s)\n",requestid,quoteid,rswap.requestid,rswap.quoteid,(long long)rswap.aliceid,rswap.bobcoin,rswap.alicecoin,rswap.src,rswap.dest);
        cJSON *retjson = cJSON_CreateObject();
        jaddstr(retjson,"error","swap never started");
        jaddstr(retjson,"uuid",rswap.uuidstr);
        jaddstr(retjson,"status","finished");
        jaddstr(retjson,"bob",rswap.bobcoin);
        jaddstr(retjson,"src",rswap.src);
        jaddstr(retjson,"alice",rswap.alicecoin);
        jaddstr(retjson,"dest",rswap.dest);
        jaddnum(retjson,"requestid",requestid);
        jaddnum(retjson,"quoteid",quoteid);
        return(retjson);
        //return(cJSON_Parse("{\"error\":\"mismatched bob/alice vs src/dest coins??\"}"));
    }
    rswap.Atxfee = LP_txfeecalc(alice,rswap.Atxfee,0);
    rswap.Btxfee = LP_txfeecalc(bob,rswap.Btxfee,0);
    if ( rswap.iambob == 0 )
    {
        if ( alice != 0 )
        {
            bitcoin_address(alice->symbol,otheraddr,alice->taddr,alice->pubtype,rswap.other33,33);
            destBdest = otheraddr;
            destAdest = rswap.Adestaddr;
            if ( LP_TECHSUPPORT == 0 && strcmp(alice->smartaddr,rswap.Adestaddr) != 0 )
            {
                printf("this isnt my swap! alice.(%s vs %s)\n",alice->smartaddr,rswap.Adestaddr);
                cJSON *retjson = cJSON_CreateObject();
                jaddstr(retjson,"error","swap for different account");
                jaddstr(retjson,"uuid",rswap.uuidstr);
                jaddstr(retjson,"alice",alice->symbol);
                jaddstr(retjson,"aliceaddr",alice->smartaddr);
                jaddstr(retjson,"dest",rswap.dest);
                jaddnum(retjson,"requestid",requestid);
                jaddnum(retjson,"quoteid",quoteid);
                return(retjson);
            }
            if ( 0 && alice->electrum == 0 && alice->lastscanht < alice->longestchain+1 )
            {
                printf("need to scan %s first\n",alice->symbol);
                cJSON *retjson = cJSON_CreateObject();
                jaddstr(retjson,"error","need to scan coin first");
                jaddstr(retjson,"uuid",rswap.uuidstr);
                jaddstr(retjson,"coin",alice->symbol);
                jaddnum(retjson,"scanned",alice->lastscanht);
                jaddnum(retjson,"longest",alice->longestchain);
                jaddnum(retjson,"requestid",requestid);
                jaddnum(retjson,"quoteid",quoteid);
                return(retjson);
            }
        }
        if ( (bob= LP_coinfind(rswap.bobcoin)) != 0 )
        {
            bitcoin_address(bob->symbol,rswap.Sdestaddr,bob->taddr,bob->pubtype,rswap.pubkey33,33);
            srcAdest = rswap.Sdestaddr;
        }
        srcBdest = rswap.destaddr;
    }
    else
    {
        if ( bob != 0 )
        {
            bitcoin_address(bob->symbol,otheraddr,bob->taddr,bob->pubtype,rswap.other33,33);
            srcAdest = otheraddr;
            srcBdest = rswap.destaddr;
            if ( LP_TECHSUPPORT == 0 && strcmp(bob->smartaddr,rswap.destaddr) != 0 )
            {
                printf("this isnt my swap! bob.(%s vs %s)\n",bob->smartaddr,rswap.destaddr);
                cJSON *retjson = cJSON_CreateObject();
                jaddstr(retjson,"error","swap for different account");
                jaddstr(retjson,"uuid",rswap.uuidstr);
                jaddstr(retjson,"bob",bob->symbol);
                jaddstr(retjson,"bobaddr",bob->smartaddr);
                jaddstr(retjson,"src",rswap.src);
                jaddnum(retjson,"requestid",requestid);
                jaddnum(retjson,"quoteid",quoteid);
                return(retjson);
            }
            if ( 0 && bob->electrum == 0 && bob->lastscanht < bob->longestchain+1 )
            {
                printf("need to scan %s first\n",bob->symbol);
                cJSON *retjson = cJSON_CreateObject();
                jaddstr(retjson,"error","need to scan coin first");
                jaddstr(retjson,"uuid",rswap.uuidstr);
                jaddstr(retjson,"coin",bob->symbol);
                jaddnum(retjson,"scanned",bob->lastscanht);
                jaddnum(retjson,"longest",bob->longestchain);
                jaddnum(retjson,"requestid",requestid);
                jaddnum(retjson,"quoteid",quoteid);
                return(retjson);
            }
        }
        if ( (alice= LP_coinfind(rswap.alicecoin)) != 0 )
        {
            bitcoin_address(alice->symbol,rswap.Sdestaddr,alice->taddr,alice->pubtype,rswap.pubkey33,33);
            destBdest = rswap.Sdestaddr;
        }
        destAdest = rswap.Adestaddr;
    }
    if ( bob == 0 || alice == 0 )
    {
        printf("Bob.%p is null or Alice.%p is null\n",bob,alice);
        return(cJSON_Parse("{\"error\":\"null bob or alice coin\"}"));
    }
    if ( alice->inactive != 0 || bob->inactive != 0 )
    {
        printf("Alice.%s inactive.%u or Bob.%s inactive.%u\n",rswap.alicecoin,alice->inactive,rswap.bobcoin,bob->inactive);
        return(cJSON_Parse("{\"error\":\"inactive bob or alice coin\"}"));
    }
    //printf("src.(Adest %s, Bdest %s), dest.(Adest %s, Bdest %s)\n",srcAdest,srcBdest,destAdest,destBdest);
    //printf("iambob.%d finishedflag.%d %s %.8f txfee, %s %.8f txfee\n",rswap.iambob,rswap.finishedflag,rswap.alicecoin,dstr(rswap.Atxfee),rswap.bobcoin,dstr(rswap.Btxfee));
    //printf("privAm.(%s) %p/%p\n",bits256_str(str,rswap.privAm),Adest,AAdest);
    //printf("privBn.(%s) %p/%p\n",bits256_str(str,rswap.privBn),Bdest,ABdest);
    if ( fastflag == 0 && rswap.finishedflag == 0 && rswap.bobcoin[0] != 0 && rswap.alicecoin[0] != 0 )
    {
        portable_mutex_lock(&LP_swaplistmutex);
      //printf("ALICE.(%s) 1st refht %s <- %d, scan %d %d\n",rswap.Adestaddr,alice->symbol,alice->firstrefht,alice->firstscanht,alice->lastscanht);
        //printf("BOB.(%s) 1st refht %s <- %d, scan %d %d\n",rswap.destaddr,bob->symbol,bob->firstrefht,bob->firstscanht,bob->lastscanht);
        LP_rswap_checktx(&rswap,rswap.alicecoin,BASILISK_ALICEPAYMENT);
        LP_rswap_checktx(&rswap,rswap.bobcoin,BASILISK_BOBPAYMENT);
        LP_rswap_checktx(&rswap,rswap.bobcoin,BASILISK_BOBDEPOSIT);
        rswap.paymentspent = basilisk_swap_spendupdate(rswap.iambob,rswap.bobcoin,rswap.bobpaymentaddr,rswap.sentflags,rswap.txids,BASILISK_BOBPAYMENT,BASILISK_ALICESPEND,BASILISK_BOBRECLAIM,0,srcAdest,srcBdest,rswap.Adestaddr,rswap.destaddr);
        rswap.Apaymentspent = basilisk_swap_spendupdate(rswap.iambob,rswap.alicecoin,rswap.alicepaymentaddr,rswap.sentflags,rswap.txids,BASILISK_ALICEPAYMENT,BASILISK_ALICERECLAIM,BASILISK_BOBSPEND,0,destAdest,destBdest,rswap.Adestaddr,rswap.destaddr);
        rswap.depositspent = basilisk_swap_spendupdate(rswap.iambob,rswap.bobcoin,rswap.bobdepositaddr,rswap.sentflags,rswap.txids,BASILISK_BOBDEPOSIT,BASILISK_ALICECLAIM,BASILISK_BOBREFUND,0,srcAdest,srcBdest,rswap.Adestaddr,rswap.destaddr);
        rswap.finishedflag = basilisk_swap_isfinished(requestid,quoteid,rswap.expiration,rswap.iambob,rswap.txids,rswap.sentflags,rswap.paymentspent,rswap.Apaymentspent,rswap.depositspent,lockduration);
        LP_spends_set(&rswap);
        if ( rswap.iambob == 0 )
        {
            if ( rswap.sentflags[BASILISK_ALICESPEND] == 0 )
            {
                if ( rswap.sentflags[BASILISK_BOBPAYMENT] != 0 && bits256_nonz(rswap.paymentspent) == 0 )
                {
                    flag = 0;
                    if ( bob->electrum == 0 )
                    {
                        if ( (txoutobj= LP_gettxout(rswap.bobcoin,rswap.bobpaymentaddr,rswap.txids[BASILISK_BOBPAYMENT],0)) != 0 )
                            free_json(txoutobj), flag = 0;
                        else flag = -1, rswap.paymentspent = deadtxid;
                    }
                    if ( flag == 0 )
                    {
                        if ( bits256_nonz(rswap.txids[BASILISK_BOBPAYMENT]) != 0 )
                        {
                            // alicespend
                            memset(rev.bytes,0,sizeof(rev));
                            for (j=0; j<32; j++)
                                rev.bytes[j] = rswap.privAm.bytes[31 - j];
                            redeemlen = basilisk_swap_bobredeemscript(0,&secretstart,redeemscript,rswap.plocktime,rswap.pubA0,rswap.pubB0,rswap.pubB1,rev,rswap.privBn,rswap.secretAm,rswap.secretAm256,rswap.secretBn,rswap.secretBn256);
                            if ( rswap.Predeemlen != 0 )
                            {
                                if ( rswap.Predeemlen != redeemlen || memcmp(redeemscript,rswap.Predeemscript,redeemlen) != 0 )
                                    printf("Predeemscript error len %d vs %d, cmp.%d\n",rswap.Predeemlen,redeemlen,memcmp(redeemscript,rswap.Predeemscript,redeemlen));
                                //else printf("Predeem matches\n");
                            } else printf("%p Predeemscript missing\n",rswap.Predeemscript);
                            len = basilisk_swapuserdata(userdata,rev,0,rswap.myprivs[0],redeemscript,redeemlen);
                            if ( 0 )
                            {
                                uint8_t secretAm[20];
                                calc_rmd160_sha256(secretAm,rswap.privAm.bytes,sizeof(rswap.privAm));
                                for (j=0; j<20; j++)
                                    printf("%02x",secretAm[j]);
                                printf(" secretAm, privAm %s alicespend len.%d redeemlen.%d\n",bits256_str(str,rswap.privAm),len,redeemlen);
                            }
                            claimtime = LP_claimtime(bob,rswap.plocktime - 777);
                            if ( (rswap.txbytes[BASILISK_ALICESPEND]= basilisk_swap_bobtxspend(&signedtxid,rswap.Btxfee,"alicespend",rswap.bobcoin,bob->wiftaddr,bob->taddr,bob->pubtype,bob->p2shtype,bob->isPoS,bob->wiftype,ctx,rswap.myprivs[0],0,redeemscript,redeemlen,userdata,len,rswap.txids[BASILISK_BOBPAYMENT],0,0,rswap.pubkey33,1,claimtime,&rswap.values[BASILISK_ALICESPEND],0,0,rswap.bobpaymentaddr,1,bob->zcash)) != 0 )
                            {
                                //printf("alicespend.(%s)\n",rswap.txbytes[BASILISK_ALICESPEND]);
#ifndef NOTETOMIC
                                if ( rswap.bobtomic[0] != 0 )
                                {
                                    char *aliceSpendEthTxId = LP_etomicalice_spends_bob_payment(&rswap);
                                    if (aliceSpendEthTxId != NULL) {
                                        free(aliceSpendEthTxId);
                                    } else {
                                        printf("Alice spend ETH tx send failed!\n");
                                    }
                                }
#endif
                            }
                        }
                        LP_txbytes_update("alicespend",rswap.bobcoin,rswap.txbytes[BASILISK_ALICESPEND],&rswap.txids[BASILISK_ALICESPEND],&rswap.paymentspent,&rswap.sentflags[BASILISK_ALICESPEND]);
                    }
                }
            }
            if ( rswap.sentflags[BASILISK_ALICECLAIM] == 0 && (rswap.sentflags[BASILISK_BOBDEPOSIT] != 0 || bits256_nonz(rswap.txids[BASILISK_BOBDEPOSIT]) != 0) && bits256_nonz(rswap.depositspent) == 0 )
            {
                if ( time(NULL) > rswap.dlocktime+777 )
                {
                    flag = 0;
                    if ( bob->electrum == 0 )
                    {
                        if ( (txoutobj= LP_gettxout(rswap.bobcoin,rswap.bobdepositaddr,rswap.txids[BASILISK_BOBDEPOSIT],0)) != 0 )
                            free_json(txoutobj), flag = 0;
                        else flag = -1, rswap.depositspent = deadtxid;
                    }
                    if ( flag == 0 )
                    {
                        if ( rswap.Dredeemlen != 0 )
                            redeemlen = rswap.Dredeemlen, memcpy(redeemscript,rswap.Dredeemscript,rswap.Dredeemlen);
                        else
                            redeemlen = basilisk_swap_bobredeemscript(1,&secretstart,redeemscript,rswap.dlocktime,rswap.pubA0,rswap.pubB0,rswap.pubB1,rswap.privAm,zero,rswap.secretAm,rswap.secretAm256,rswap.secretBn,rswap.secretBn256);
                        /*if ( rswap.Dredeemlen != 0 )
                        {
                            if ( rswap.Dredeemlen != redeemlen || memcmp(redeemscript,rswap.Dredeemscript,redeemlen) != 0 )
                                printf("Dredeemscript error len %d vs %d, cmp.%d\n",rswap.Dredeemlen,redeemlen,memcmp(redeemscript,rswap.Dredeemscript,redeemlen));
                        } else printf("%p Dredeemscript missing\n",rswap.Dredeemscript);*/
                        if ( redeemlen > 0 )
                        {
                            memset(revAm.bytes,0,sizeof(revAm));
                            for (i=0; i<32; i++)
                                revAm.bytes[i] = rswap.privAm.bytes[31-i];
                            len = basilisk_swapuserdata(userdata,revAm,1,rswap.myprivs[0],redeemscript,redeemlen);
                            claimtime = LP_claimtime(bob,rswap.dlocktime);
                            if ( (rswap.txbytes[BASILISK_ALICECLAIM]= basilisk_swap_bobtxspend(&signedtxid,rswap.Btxfee,"aliceclaim",rswap.bobcoin,bob->wiftaddr,bob->taddr,bob->pubtype,bob->p2shtype,bob->isPoS,bob->wiftype,ctx,rswap.myprivs[0],0,redeemscript,redeemlen,userdata,len,rswap.txids[BASILISK_BOBDEPOSIT],0,0,rswap.pubkey33,0,claimtime,&rswap.values[BASILISK_ALICECLAIM],0,0,rswap.bobdepositaddr,1,bob->zcash)) != 0 )
                            {
                                //printf("dlocktime.%u claimtime.%u aliceclaim.(%s)\n",rswap.dlocktime,claimtime,rswap.txbytes[BASILISK_ALICECLAIM]);
#ifndef NOTETOMIC
                                if ( rswap.bobtomic[0] != 0 )
                                {
                                    char *aliceClaimsEthTxId = LP_etomicalice_claims_bob_deposit(&rswap);
                                    if (aliceClaimsEthTxId != NULL) {
                                        free(aliceClaimsEthTxId);
                                    } else {
                                        printf("Alice Bob deposit claim ETH tx failed!\n");
                                    }
                                }
#endif
                            }
                        }
                        LP_txbytes_update("aliceclaim",rswap.bobcoin,rswap.txbytes[BASILISK_ALICECLAIM],&rswap.txids[BASILISK_ALICECLAIM],&rswap.depositspent,&rswap.sentflags[BASILISK_ALICECLAIM]);
                    }
                } //else printf("now %u before expiration %u\n",(uint32_t)time(NULL),rswap.expiration);
            }
            if ( (rswap.sentflags[BASILISK_ALICEPAYMENT] != 0 || bits256_nonz(rswap.txids[BASILISK_ALICEPAYMENT]) != 0)&& bits256_nonz(rswap.Apaymentspent) == 0 && rswap.sentflags[BASILISK_ALICERECLAIM] == 0 )
            {
                flag = 0;
                if ( alice->electrum == 0 )
                {
                    if ( (txoutobj= LP_gettxout(rswap.alicecoin,rswap.alicepaymentaddr,rswap.txids[BASILISK_ALICEPAYMENT],0)) != 0 )
                        free_json(txoutobj), flag = 0;
                    else flag = -1, rswap.Apaymentspent = deadtxid;
                }
                if ( flag == 0 )
                {
                    rswap.privBn = basilisk_swap_privBn_extract(&rswap.txids[BASILISK_BOBREFUND],rswap.bobcoin,rswap.txids[BASILISK_BOBDEPOSIT],rswap.privBn);
                    if ( bits256_nonz(rswap.txids[BASILISK_ALICEPAYMENT]) != 0 && bits256_nonz(rswap.privAm) != 0 && bits256_nonz(rswap.privBn) != 0 )
                    {
                        if ( (rswap.txbytes[BASILISK_ALICERECLAIM]= basilisk_swap_Aspend("alicereclaim",rswap.alicecoin,rswap.Atxfee,alice->wiftaddr,alice->taddr,alice->pubtype,alice->p2shtype,alice->isPoS,alice->wiftype,ctx,rswap.privAm,rswap.privBn,rswap.txids[BASILISK_ALICEPAYMENT],0,rswap.pubkey33,rswap.expiration,&rswap.values[BASILISK_ALICERECLAIM],rswap.alicepaymentaddr,alice->zcash)) != 0 ) {
                            printf("alicereclaim.(%s)\n", rswap.txbytes[BASILISK_ALICERECLAIM]);
#ifndef NOTETOMIC
                            if ( rswap.alicetomic[0] != 0 )
                            {
                                char *aliceReclaimEthTx = LP_etomicalice_reclaims_payment(&rswap);
                                free(aliceReclaimEthTx);
                            }
#endif
                        }
                    }
                    LP_txbytes_update("alicereclaim",rswap.alicecoin,rswap.txbytes[BASILISK_ALICERECLAIM],&rswap.txids[BASILISK_ALICERECLAIM],&rswap.Apaymentspent,&rswap.sentflags[BASILISK_ALICERECLAIM]);
                }
            }
        }
        else if ( rswap.iambob == 1 )
        {
            if ( rswap.sentflags[BASILISK_BOBSPEND] == 0 && bits256_nonz(rswap.Apaymentspent) == 0 )
            {
                //printf("try to bobspend aspend.%s have privAm.%d aspent.%d\n",bits256_str(str,rswap.txids[BASILISK_ALICESPEND]),bits256_nonz(rswap.privAm),rswap.sentflags[BASILISK_ALICESPEND]);
                if ( rswap.sentflags[BASILISK_ALICESPEND] != 0 || bits256_nonz(rswap.paymentspent) != 0 || bits256_nonz(rswap.privAm) != 0 || bits256_nonz(rswap.depositspent) != 0 )
                {
                    flag = 0;
                    if ( alice->electrum == 0 )
                    {
                        if ( (txoutobj= LP_gettxout(rswap.alicecoin,rswap.alicepaymentaddr,rswap.txids[BASILISK_ALICEPAYMENT],0)) != 0 )
                            free_json(txoutobj), flag = 0;
                        else flag = -1, rswap.Apaymentspent = deadtxid;
                    }
                    //printf("flag.%d apayment.%s\n",flag,bits256_str(str,rswap.paymentspent));
                    if ( flag == 0 )
                    {
                        if ( bits256_nonz(rswap.privAm) == 0 )
                        {
                            rswap.privAm = basilisk_swap_privbob_extract(rswap.bobcoin,rswap.paymentspent,0,1);
                            if ( bits256_nonz(rswap.privAm) == 0 && bits256_nonz(rswap.depositspent) != 0 )
                            {
                                rswap.privAm = basilisk_swap_privbob_extract(rswap.bobcoin,rswap.depositspent,0,1);
                                //printf("try to bobspend aspend.%s have privAm.%d\n",bits256_str(str,rswap.depositspent),bits256_nonz(rswap.privAm));
                            }
                        }
                        if ( bits256_nonz(rswap.privAm) != 0 && bits256_nonz(rswap.privBn) != 0 )
                        {
                            if ( (rswap.txbytes[BASILISK_BOBSPEND]= basilisk_swap_Aspend("bobspend",rswap.alicecoin,rswap.Atxfee,alice->wiftaddr,alice->taddr,alice->pubtype,alice->p2shtype,alice->isPoS,alice->wiftype,ctx,rswap.privAm,rswap.privBn,rswap.txids[BASILISK_ALICEPAYMENT],0,rswap.pubkey33,rswap.expiration,&rswap.values[BASILISK_BOBSPEND],rswap.alicepaymentaddr,alice->zcash)) != 0 )
                            {
#ifndef NOTETOMIC
                                if ( rswap.alicetomic[0] != 0 )
                                {
                                    char *bobSpendEthTx = LP_etomicbob_spends_alice_payment(&rswap);
                                    if (bobSpendEthTx != NULL) {
                                        free(bobSpendEthTx);
                                    } else {
                                        printf("Bob spends Alice payment ETH tx send failed!\n");
                                    }
                                }
#endif
                                //printf("bobspend.(%s)\n",rswap.txbytes[BASILISK_BOBSPEND]);
                            }
                        }
                        LP_txbytes_update("bobspend",rswap.alicecoin,rswap.txbytes[BASILISK_BOBSPEND],&rswap.txids[BASILISK_BOBSPEND],&rswap.Apaymentspent,&rswap.sentflags[BASILISK_BOBSPEND]);
                    }
                }
            }
            if ( rswap.sentflags[BASILISK_BOBRECLAIM] == 0 && (rswap.sentflags[BASILISK_BOBPAYMENT] != 0 || bits256_nonz(rswap.txids[BASILISK_BOBPAYMENT]) != 0) && bits256_nonz(rswap.paymentspent) == 0 )
            {
                flag = 0;
                if ( bob->electrum == 0 )
                {
                    if ( (txoutobj= LP_gettxout(rswap.bobcoin,rswap.bobpaymentaddr,rswap.txids[BASILISK_BOBPAYMENT],0)) != 0 )
                        free_json(txoutobj), flag = 0;
                    else flag = -1, rswap.paymentspent = deadtxid;
                }
                if ( flag == 0 && time(NULL) > rswap.plocktime+777 )
                {
                    // bobreclaim
                    redeemlen = basilisk_swap_bobredeemscript(0,&secretstart,redeemscript,rswap.plocktime,rswap.pubA0,rswap.pubB0,rswap.pubB1,zero,rswap.privBn,rswap.secretAm,rswap.secretAm256,rswap.secretBn,rswap.secretBn256);
                    if ( redeemlen > 0 )
                    {
                        len = basilisk_swapuserdata(userdata,zero,1,rswap.myprivs[1],redeemscript,redeemlen);
                        claimtime = LP_claimtime(bob,rswap.plocktime - 777);
                        if ( (rswap.txbytes[BASILISK_BOBRECLAIM]= basilisk_swap_bobtxspend(&signedtxid,rswap.Btxfee,"bobreclaim",rswap.bobcoin,bob->wiftaddr,bob->taddr,bob->pubtype,bob->p2shtype,bob->isPoS,bob->wiftype,ctx,rswap.myprivs[1],0,redeemscript,redeemlen,userdata,len,rswap.txids[BASILISK_BOBPAYMENT],0,0,rswap.pubkey33,0,claimtime,&rswap.values[BASILISK_BOBRECLAIM],0,0,rswap.bobpaymentaddr,1,bob->zcash)) != 0 )
                        {
#ifndef NOTETOMIC
                            if ( rswap.bobtomic[0] != 0 )
                            {
                                char *bobReclaimEthTx = LP_etomicbob_reclaims_payment(&rswap);
                                if (bobReclaimEthTx != NULL) {
                                    free(bobReclaimEthTx);
                                } else {
                                    printf("Bob reclaims payment ETH tx send failed!\n");
                                }
                            }
#endif
                            //int32_t z;
                            //for (z=0; z<20; z++)
                            //    printf("%02x",rswap.secretAm[z]);
                            //printf(" secretAm, myprivs[1].(%s) bobreclaim.(%s)\n",bits256_str(str,rswap.myprivs[1]),rswap.txbytes[BASILISK_BOBRECLAIM]);
                        }
                    }
                    LP_txbytes_update("bobreclaim",rswap.bobcoin,rswap.txbytes[BASILISK_BOBRECLAIM],&rswap.txids[BASILISK_BOBRECLAIM],&rswap.paymentspent,&rswap.sentflags[BASILISK_BOBRECLAIM]);
                }
                else if ( flag == 0 )
                {
                    //printf("bobpayment: now.%u < expiration %u\n",(uint32_t)time(NULL),rswap.expiration);
                }
            }
            if ( rswap.sentflags[BASILISK_BOBREFUND] == 0 && (rswap.sentflags[BASILISK_BOBDEPOSIT] != 0 || bits256_nonz(rswap.txids[BASILISK_BOBDEPOSIT]) != 0) && bits256_nonz(rswap.depositspent) == 0 )
            {
                //printf("bobdeposit.%d depositspent.%d paymentspent.%d\n",rswap.sentflags[BASILISK_BOBDEPOSIT],bits256_nonz(rswap.depositspent),bits256_nonz(rswap.paymentspent));
                flag = 0;
                if ( bob->electrum == 0 )
                {
                    if ( (txoutobj= LP_gettxout(rswap.bobcoin,rswap.bobdepositaddr,rswap.txids[BASILISK_BOBDEPOSIT],0)) != 0 )
                        free_json(txoutobj), flag = 0;
                    else flag = -1, rswap.depositspent = deadtxid;
                }
                //printf("lockduration.%d plocktime.%u lag.%d\n",lockduration,rswap.plocktime,(int32_t)(time(NULL) - (rswap.plocktime-lockduration+1800)));
                if ( flag == 0 && (
                                   bits256_nonz(rswap.Apaymentspent) != 0 ||
                                   time(NULL) > rswap.dlocktime-777 ||
                                   (bits256_nonz(rswap.txids[BASILISK_ALICEPAYMENT]) == 0 && time(NULL) > rswap.plocktime-777) ||
                                   (bits256_nonz(rswap.txids[BASILISK_BOBPAYMENT]) != 0 && rswap.sentflags[BASILISK_BOBPAYMENT] == 0 && time(NULL) > rswap.plocktime-lockduration+1800) || // failed bobpayment
                                   (bits256_nonz(rswap.txids[BASILISK_BOBPAYMENT]) == 0 && time(NULL) > rswap.dlocktime-3*lockduration/2)
                                   ) )
                {
                    //printf("do the refund! paymentspent.%s now.%u vs expiration.%u\n",bits256_str(str,rswap.paymentspent),(uint32_t)time(NULL),rswap.expiration);
                    //if ( txbytes[BASILISK_BOBREFUND] == 0 )
                    {
                        revcalc_rmd160_sha256(rswap.secretBn,rswap.privBn);
                        vcalc_sha256(0,rswap.secretBn256,rswap.privBn.bytes,sizeof(rswap.privBn));
                        redeemlen = basilisk_swap_bobredeemscript(1,&secretstart,redeemscript,rswap.dlocktime,rswap.pubA0,rswap.pubB0,rswap.pubB1,rswap.privAm,rswap.privBn,rswap.secretAm,rswap.secretAm256,rswap.secretBn,rswap.secretBn256);
                        len = basilisk_swapuserdata(userdata,rswap.privBn,0,rswap.myprivs[0],redeemscript,redeemlen);
                        claimtime = LP_claimtime(bob,rswap.plocktime - 777);
                        if ( (rswap.txbytes[BASILISK_BOBREFUND]= basilisk_swap_bobtxspend(&signedtxid,rswap.Btxfee,"bobrefund",rswap.bobcoin,bob->wiftaddr,bob->taddr,bob->pubtype,bob->p2shtype,bob->isPoS,bob->wiftype,ctx,rswap.myprivs[0],0,redeemscript,redeemlen,userdata,len,rswap.txids[BASILISK_BOBDEPOSIT],0,0,rswap.pubkey33,1,claimtime,&rswap.values[BASILISK_BOBREFUND],0,0,rswap.bobdepositaddr,1,bob->zcash)) != 0 )
                        {
#ifndef NOTETOMIC
                            if ( rswap.bobtomic[0] != 0 )
                            {
                                char *bobRefundsEthTx = LP_etomicbob_refunds_deposit(&rswap);
                                if (bobRefundsEthTx != NULL) {
                                    free(bobRefundsEthTx);
                                } else {
                                    printf("Bob refunds deposit ETH tx send failed!\n");
                                }
                            }
#endif
                            //printf("pubB1.(%s) bobrefund.(%s)\n",bits256_str(str,rswap.pubB1),rswap.txbytes[BASILISK_BOBREFUND]);
                        }
                    }
                    LP_txbytes_update("bobrefund",rswap.bobcoin,rswap.txbytes[BASILISK_BOBREFUND],&rswap.txids[BASILISK_BOBREFUND],&rswap.depositspent,&rswap.sentflags[BASILISK_BOBREFUND]);
                }
                else if ( 0 && flag == 0 )
                    printf("bobrefund's time %u vs expiration %u\n",(uint32_t)time(NULL),rswap.expiration);
            }
        }
        portable_mutex_unlock(&LP_swaplistmutex);
    }
    //printf("finish.%d iambob.%d REFUND %d %d %d %d\n",finishedflag,iambob,sentflags[BASILISK_BOBREFUND] == 0,sentflags[BASILISK_BOBDEPOSIT] != 0,bits256_nonz(txids[BASILISK_BOBDEPOSIT]) != 0,bits256_nonz(depositspent) == 0);
    if ( rswap.sentflags[BASILISK_ALICESPEND] != 0 || rswap.sentflags[BASILISK_BOBRECLAIM] != 0 )
        rswap.sentflags[BASILISK_BOBPAYMENT] = 1;
    if ( rswap.sentflags[BASILISK_ALICERECLAIM] != 0 || rswap.sentflags[BASILISK_BOBSPEND] != 0 )
        rswap.sentflags[BASILISK_ALICEPAYMENT] = 1;
    if ( rswap.sentflags[BASILISK_ALICECLAIM] != 0 || rswap.sentflags[BASILISK_BOBREFUND] != 0 )
        rswap.sentflags[BASILISK_BOBDEPOSIT] = 1;
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
        if ( bits256_nonz(rswap.txids[i]) != 0 && rswap.values[i] == 0 )
            rswap.values[i] = basilisk_txvalue(basilisk_isbobcoin(rswap.iambob,i) ? rswap.bobcoin : rswap.alicecoin,rswap.txids[i],0);
    if ( 0 && rswap.origfinishedflag == 0 )
    {
        printf("iambob.%d Apaymentspent.(%s) alice.%d bob.%d %s %.8f\n",rswap.iambob,bits256_str(str,rswap.Apaymentspent),rswap.sentflags[BASILISK_ALICERECLAIM],rswap.sentflags[BASILISK_BOBSPEND],rswap.alicecoin,dstr(rswap.values[BASILISK_ALICEPAYMENT]));
        printf("paymentspent.(%s) alice.%d bob.%d %s %.8f\n",bits256_str(str,rswap.paymentspent),rswap.sentflags[BASILISK_ALICESPEND],rswap.sentflags[BASILISK_BOBRECLAIM],rswap.bobcoin,dstr(rswap.values[BASILISK_BOBPAYMENT]));
        printf("depositspent.(%s) alice.%d bob.%d %s %.8f\n",bits256_str(str,rswap.depositspent),rswap.sentflags[BASILISK_ALICECLAIM],rswap.sentflags[BASILISK_BOBREFUND],rswap.bobcoin,dstr(rswap.values[BASILISK_BOBDEPOSIT]));
    }
    LP_totals_update(rswap.iambob,rswap.alicecoin,rswap.bobcoin,KMDtotals,BTCtotals,rswap.sentflags,rswap.values);
    if ( (numspent= LP_spends_set(&rswap)) == 3 )
        rswap.finishedflag = 1;
    else rswap.finishedflag = basilisk_swap_isfinished(requestid,quoteid,rswap.expiration,rswap.iambob,rswap.txids,rswap.sentflags,rswap.paymentspent,rswap.Apaymentspent,rswap.depositspent,lockduration);
    if ( rswap.origfinishedflag == 0 && rswap.finishedflag != 0 )
    {
        char fname[1024],*itemstr; FILE *fp;
        LP_numfinished++;
        printf("SWAP %u-%u finished LP_numfinished.%d !\n",requestid,quoteid,LP_numfinished);
        if ( rswap.finishtime == 0 )
            rswap.finishtime = (uint32_t)time(NULL);
        if ( rswap.tradeid != 0 )
            LP_tradebot_finished(rswap.tradeid,rswap.requestid,rswap.quoteid);
        sprintf(fname,"%s/SWAPS/%u-%u.finished",GLOBAL_DBDIR,rswap.requestid,rswap.quoteid), OS_compatible_path(fname);
        item = LP_swap_json(&rswap);
        if ( (fp= fopen(fname,"wb")) != 0 )
        {
            jaddstr(item,"method","tradestatus");
            jaddnum(item,"finishtime",rswap.finishtime);
            if ( jobj(item,"gui") == 0 )
                jaddstr(item,"gui",G.gui);
            //jaddbits256(item,"srchash",rswap.Q.srchash);
            //jaddbits256(item,"desthash",rswap.desthash);
            itemstr = jprint(item,0);
            fprintf(fp,"%s\n",itemstr);
            LP_tradecommand_log(item);
            LP_reserved_msg(1,rswap.src,rswap.dest,zero,clonestr(itemstr));
            sleep(1);
            LP_reserved_msg(0,rswap.src,rswap.dest,zero,itemstr);
            //LP_broadcast_message(LP_mypubsock,rswap.src,rswap.dest,zero,itemstr);
            fclose(fp);
        }
    } else item = LP_swap_json(&rswap);
    for (i=0; i<sizeof(txnames)/sizeof(*txnames); i++)
        if ( rswap.txbytes[i] != 0 )
            free(rswap.txbytes[i]), rswap.txbytes[i] = 0;
    if ( pendingonly != 0 && rswap.origfinishedflag != 0 )
    {
        free_json(item);
        item = 0;
    }
    return(item);
}

void for_satinder()
{
    void *ctx; char *signedtx,*paymentaddr,*rscript; int32_t redeemlen,len; uint8_t pubkey33[33],redeemscript[512],userdata[512]; uint32_t expiration; bits256 zero,priv1,signedtxid,utxotxid; int64_t satoshis; struct iguana_info *coin;
    ctx = bitcoin_ctx();
    coin = LP_coinfind("ZEC");
    expiration = 1511219708;
    rscript = "63048543135ab1752103b1168377dec884dc7d615c64e0963a5efeaf3c34f8c88be04dec2ee5cc0608c0ac67a914fcfc9291cad04225e574b374516656f80b991c808821021a53a4a59017258f12b6a293fee7644dff98899d3e4a8917b4b3204ee50995a1ac68";
    redeemlen = (int32_t)strlen(rscript)/2;
    decode_hex(redeemscript,redeemlen,rscript);
    decode_hex(utxotxid.bytes,32,"ef5b1d463715e6b5bd51c3161147f1aabebc7f3f88438cbdc744590c2b9856e6");
    decode_hex(pubkey33,33,"02ebc786cb83de8dc3922ab83c21f3f8a2f3216940c3bf9da43ce39e2a3a882c92");
    paymentaddr = "t1Y9ukZMkNAYonCFVp3jSdx7NT8dEsXss7k";
    satoshis = 1344 * SATOSHIDEN - 10000;
    memset(zero.bytes,0,sizeof(zero));
    decode_hex(priv1.bytes,32,"00000000000000000000000000000000bebc7f3f88438cbdc744590c2b9856e6"); // need to put the actual privkey here
    len = basilisk_swapuserdata(userdata,zero,1,priv1,redeemscript,redeemlen);
    if ( (signedtx= basilisk_swap_bobtxspend(&signedtxid,coin->txfee,"satinder",coin->symbol,coin->wiftaddr,coin->taddr,coin->pubtype,coin->p2shtype,coin->isPoS,coin->wiftype,ctx,priv1,0,redeemscript,redeemlen,userdata,len,utxotxid,0,0,pubkey33,0,expiration,&satoshis,0,0,paymentaddr,1,coin->zcash)) != 0 )
    {
        char str[65]; printf("satinder %s signedtx.(%s)\n",bits256_str(str,signedtxid),signedtx);
    } else printf("error with satinder tx\n");
}

char *basilisk_swaplist(int32_t fastflag,uint32_t origrequestid,uint32_t origquoteid,int32_t forceflag,int32_t pendingonly)
{
    uint64_t ridqids[4096],ridqid; char fname[512]; FILE *fp; cJSON *item,*retjson,*array,*totalsobj; uint32_t r,q,quoteid,requestid; int64_t KMDtotals[LP_MAXPRICEINFOS],BTCtotals[LP_MAXPRICEINFOS],Btotal,Ktotal; int32_t i,j,count=0;
    //portable_mutex_lock(&LP_swaplistmutex);
    memset(ridqids,0,sizeof(ridqids));
    memset(KMDtotals,0,sizeof(KMDtotals));
    memset(BTCtotals,0,sizeof(BTCtotals));
    //,statebits; int32_t optionduration; struct basilisk_request R; bits256 privkey;
    retjson = cJSON_CreateObject();
    array = cJSON_CreateArray();
    if ( origrequestid != 0 && origquoteid != 0 )
    {
        //printf("orig req.%u q.%u\n",origrequestid,origquoteid);
        if ( (item= basilisk_remember(fastflag,KMDtotals,BTCtotals,origrequestid,origquoteid,forceflag,0)) != 0 )
            jaddi(array,item);
        //printf("got.(%s)\n",jprint(item,0));
    }
    else
    {
        sprintf(fname,"%s/SWAPS/list",GLOBAL_DBDIR), OS_compatible_path(fname);
        if ( (fp= fopen(fname,"rb")) != 0 )
        {
            //struct basilisk_swap *swap;
            int32_t flag = 0;
            while ( fread(&requestid,1,sizeof(requestid),fp) == sizeof(requestid) && fread(&quoteid,1,sizeof(quoteid),fp) == sizeof(quoteid) )
            {
                flag = 0;
                if ( pendingonly == 0 )
                {
                    for (i=0; i<G.LP_numskips; i++)
                    {
                        r = (uint32_t)(G.LP_skipstatus[i] >> 32);
                        q = (uint32_t)G.LP_skipstatus[i];
                        if ( r == requestid && q == quoteid )
                        {
                            item = cJSON_CreateObject();
                            jaddstr(item,"status","realtime");
                            jaddnum(item,"requestid",r);
                            jaddnum(item,"quoteid",q);
                            jaddi(array,item);
                            flag = 1;
                            break;
                        }
                    }
                }
                if ( flag == 0 )
                {
                    ridqid = ((uint64_t)requestid << 32) | quoteid;
                    for (j=0; j<count; j++)
                        if ( ridqid == ridqids[j] )
                            break;
                    if ( j == count )
                    {
                        if ( count < sizeof(ridqids)/sizeof(*ridqids) )
                            ridqids[count++] = ridqid;
                        if ( (item= basilisk_remember(fastflag,KMDtotals,BTCtotals,requestid,quoteid,0,pendingonly)) != 0 )
                            jaddi(array,item);
                    }
                }
            }
            fclose(fp);
        }
    }
    jaddstr(retjson,"result","success");
    jadd(retjson,"swaps",array);
    if ( 0 && cJSON_GetArraySize(array) > 0 )
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
    //portable_mutex_unlock(&LP_swaplistmutex);
    return(jprint(retjson,1));
}

char *basilisk_swapentry(int32_t fastflag,uint32_t requestid,uint32_t quoteid,int32_t forceflag)
{
    cJSON *item; int64_t KMDtotals[LP_MAXPRICEINFOS],BTCtotals[LP_MAXPRICEINFOS];
    memset(KMDtotals,0,sizeof(KMDtotals));
    memset(BTCtotals,0,sizeof(BTCtotals));
    if ( (item= basilisk_remember(fastflag,KMDtotals,BTCtotals,requestid,quoteid,forceflag,0)) != 0 )
        return(jprint(item,1));
    else return(clonestr("{\"error\":\"cant find requestid-quoteid\"}"));
}

char *LP_kickstart(uint32_t requestid,uint32_t quoteid)
{
    char fname[512];
    sprintf(fname,"%s/SWAPS/%u-%u.finished",GLOBAL_DBDIR,requestid,quoteid), OS_compatible_path(fname);
    OS_portable_removefile(fname);
    return(basilisk_swapentry(0,requestid,quoteid,1));
}
           
extern struct LP_quoteinfo LP_Alicequery;
extern uint32_t Alice_expiration;

char *LP_recent_swaps(int32_t limit,char *uuidstr)
{
    char fname[512],*retstr,*base,*rel,*statusstr; long fsize,offset; FILE *fp; int32_t baseind,relind,i=0; uint32_t requestid,quoteid; cJSON *array,*item,*retjson,*subitem,*swapjson; int64_t KMDtotals[LP_MAXPRICEINFOS],BTCtotals[LP_MAXPRICEINFOS]; double srcamount,destamount,netamounts[LP_MAXPRICEINFOS];
    memset(KMDtotals,0,sizeof(KMDtotals));
    memset(BTCtotals,0,sizeof(BTCtotals));
    memset(netamounts,0,sizeof(netamounts));
    if ( limit <= 0 )
        limit = 3;
    sprintf(fname,"%s/SWAPS/list",GLOBAL_DBDIR), OS_compatible_path(fname);
    array = cJSON_CreateArray();
    if ( (fp= fopen(fname,"rb")) != 0 )
    {
        fseek(fp,0,SEEK_END);
        fsize = ftell(fp);
        offset = (sizeof(requestid) + sizeof(quoteid));
        while ( offset <= fsize && i < limit )
        {
            i++;
            offset = i * (sizeof(requestid) + sizeof(quoteid));
            fseek(fp,fsize-offset,SEEK_SET);
            if ( ftell(fp) == fsize-offset )
            {
                if ( fread(&requestid,1,sizeof(requestid),fp) == sizeof(requestid) && fread(&quoteid,1,sizeof(quoteid),fp) == sizeof(quoteid) )
                {
                    item = cJSON_CreateArray();
                    jaddinum(item,requestid);
                    jaddinum(item,quoteid);
                    if ( (retstr= basilisk_swapentry(1,requestid,quoteid,0)) != 0 )
                    {
                        if ( (swapjson= cJSON_Parse(retstr)) != 0 )
                        {
                            base = jstr(swapjson,"bob");
                            rel = jstr(swapjson,"alice");
                            statusstr = jstr(swapjson,"status");
                            baseind = relind = -1;
                            if ( base != 0 && rel != 0 && statusstr != 0 && strcmp(statusstr,"finished") == 0 && (baseind= LP_priceinfoind(base)) >= 0 && (relind= LP_priceinfoind(rel)) >= 0 )
                            {
                                srcamount = jdouble(swapjson,"srcamount");
                                destamount = jdouble(swapjson,"destamount");
                                if ( jint(swapjson,"iambob") != 0 )
                                    srcamount = -srcamount;
                                else destamount = -destamount;
                                if ( srcamount != 0. && destamount != 0. )
                                {
                                    netamounts[baseind] += srcamount;
                                    netamounts[relind] += destamount;
                                    subitem = cJSON_CreateObject();
                                    jaddnum(subitem,base,srcamount);
                                    jaddnum(subitem,rel,destamount);
                                    jaddnum(subitem,"price",-destamount/srcamount);
                                    jaddi(item,subitem);
                                }
                            } //else printf("base.%p rel.%p statusstr.%p baseind.%d relind.%d\n",base,rel,statusstr,baseind,relind);
                            free_json(swapjson);
                        } else printf("error parsing.(%s)\n",retstr);
                        free(retstr);
                    }
                    jaddi(array,item);
                } else break;
            } else break;
        }
        fclose(fp);
    }
    retjson = cJSON_CreateObject();
    jaddstr(retjson,"result","success");
    jadd(retjson,"swaps",array);
    array = cJSON_CreateArray();
    for (i=0; i<LP_MAXPRICEINFOS; i++)
    {
        if ( netamounts[i] != 0. )
        {
            item = cJSON_CreateObject();
            jaddnum(item,LP_priceinfostr(i),netamounts[i]);
            jaddi(array,item);
        }
    }
    jadd(retjson,"netamounts",array);
    if ( time(NULL) < Alice_expiration )
    {
        item = cJSON_CreateObject();
        if ( uuidstr != 0 )
            jaddstr(item,"uuid",uuidstr);
        jaddnum(item,"expiration",Alice_expiration);
        jaddnum(item,"timeleft",Alice_expiration-time(NULL));
        jaddnum(item,"tradeid",LP_Alicequery.tradeid);
        jaddnum(item,"requestid",LP_Alicequery.R.requestid);
        jaddnum(item,"quoteid",LP_Alicequery.R.quoteid);
        jaddstr(item,"bob",LP_Alicequery.srccoin);
        jaddstr(item,"base",LP_Alicequery.srccoin);
        jaddnum(item,"basevalue",dstr(LP_Alicequery.satoshis));
        jaddstr(item,"alice",LP_Alicequery.destcoin);
        jaddstr(item,"rel",LP_Alicequery.destcoin);
        jaddnum(item,"relvalue",dstr(LP_Alicequery.destsatoshis));
        jaddbits256(item,"desthash",G.LP_mypub25519);
        jadd64bits(item,"aliceid",LP_aliceid_calc(LP_Alicequery.desttxid,LP_Alicequery.destvout,LP_Alicequery.feetxid,LP_Alicequery.feevout));
        jadd(retjson,"pending",item);
    } else Alice_expiration = 0;
    if ( uuidstr != 0 )
        jaddstr(retjson,"uuid",uuidstr);
    return(jprint(retjson,1));
}

uint64_t basilisk_swap_addarray(cJSON *item,char *refbase,char *refrel)
{
    char *base,*rel; uint32_t requestid,quoteid; uint64_t ridqid = 0;
    base = jstr(item,"bob");
    rel = jstr(item,"alice");
    if ( refrel == 0 || refrel[0] == 0 )
    {
        if ( (base != 0 && strcmp(base,refbase) == 0) || (rel != 0 && strcmp(rel,refbase) == 0) )
            ridqid = 1;
    }
    else if ( (base != 0 && strcmp(base,refbase) == 0) && (rel != 0 && strcmp(rel,refrel) == 0) )
        ridqid = 1;
    if ( ridqid != 0 )
    {
        requestid = juint(item,"requestid");
        quoteid = juint(item,"quoteid");
        ridqid = ((uint64_t)requestid << 32) | quoteid;
        //printf("%u %u -> %16llx\n",requestid,quoteid,(long long)ridqid);
    }
    return(ridqid);
}

char *basilisk_swapentries(int32_t fastflag,char *refbase,char *refrel,int32_t limit)
{
    uint64_t ridqids[1024],ridqid; char *liststr,*retstr2; cJSON *retjson,*array,*pending,*swapjson,*item,*retarray; int32_t i,j,n,count = 0; uint32_t requestid,quoteid;
    if ( limit <= 0 )
        limit = 10;
    memset(ridqids,0,sizeof(ridqids));
    retarray = cJSON_CreateArray();
    if ( (liststr= basilisk_swaplist(fastflag,0,0,0,0)) != 0 )
    {
        //printf("swapentry.(%s)\n",liststr);
        if ( (retjson= cJSON_Parse(liststr)) != 0 )
        {
            if ( (array= jarray(&n,retjson,"swaps")) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    if ( (ridqid= basilisk_swap_addarray(item,refbase,refrel)) > 0 )
                    {
                        if ( count < sizeof(ridqids)/sizeof(*ridqids) )
                        {
                            ridqids[count++] = ridqid;
                            //printf("add ridqid.%16llx\n",(long long)ridqid);
                        }
                        jaddi(retarray,jduplicate(item));
                    }
                }
            }
            free_json(retjson);
            retjson = 0;
        }
        free(liststr);
    }
    if ( (liststr= LP_recent_swaps(limit,0)) != 0 )
    {
        if ( (retjson= cJSON_Parse(liststr)) != 0 )
        {
            if ( (array= jarray(&n,retjson,"swaps")) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    requestid = juint(jitem(item,0),0);
                    quoteid = juint(jitem(item,1),0);
                    ridqid = ((uint64_t)requestid << 32) | quoteid;
                    for (j=0; j<count; j++)
                        if ( ridqid == ridqids[j] )
                            break;
                    if ( j == count )
                    {
                        printf("j.%d count.%d %u %u ridqid.%16llx\n",j,count,requestid,quoteid,(long long)ridqid);
                        if ( (retstr2= basilisk_swapentry(1,requestid,quoteid,0)) != 0 )
                        {
                            if ( (swapjson= cJSON_Parse(retstr2)) != 0 )
                            {
                                if ( (ridqid= basilisk_swap_addarray(swapjson,refbase,refrel)) > 0 )
                                {
                                    if ( count < sizeof(ridqids)/sizeof(*ridqids) )
                                        ridqids[count++] = ridqid;
                                    jaddi(retarray,swapjson);
                                } else free_json(swapjson);
                            }
                            free(retstr2);
                        }
                    }
                }
            }
            if ( (pending= jobj(retjson,"pending")) != 0 )
            {
                requestid = juint(pending,"requestid");
                quoteid = juint(pending,"quoteid");
                j = 0;
                if ( (ridqid= ((uint64_t)requestid << 32) | quoteid) != 0 )
                {
                    for (j=0; j<count; j++)
                        if ( ridqid == ridqids[j] )
                            break;
                }
                if ( ridqid == 0 || j == count )
                {
                    if ( basilisk_swap_addarray(pending,refbase,refrel) > 0 )
                        jaddi(retarray,jduplicate(pending));
                }
            }
            free_json(retjson);
        }
        free(liststr);
    }
    return(jprint(retarray,1));
}

int32_t LP_pendingswap(uint32_t requestid,uint32_t quoteid)
{
    cJSON *retjson,*array,*pending,*item; uint32_t r,q; char *retstr; int32_t i,n,retval = 0;
    if ( (retstr= LP_recent_swaps(1000,0)) != 0 )
    {
        if ( (retjson= cJSON_Parse(retstr)) != 0 )
        {
            if ( (array= jarray(&n,retjson,"swaps")) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(array,i);
                    r = juint(jitem(item,0),0);
                    q = juint(jitem(item,1),0);
                    if ( r == requestid && q == quoteid )
                    {
                        retval = 1;
                        break;
                    }
                }
            }
            if ( retval == 0 )
            {
                if ( (pending= jobj(retjson,"pending")) != 0 )
                {
                    r = juint(pending,"requestid");
                    q = juint(pending,"quoteid");
                    if ( r == requestid && q == quoteid )
                        retval = 1;
                }
            }
            free_json(retjson);
        }
        free(retstr);
    }
    return(retval);
}
