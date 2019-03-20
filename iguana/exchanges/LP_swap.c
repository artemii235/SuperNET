
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

/*
void basilisk_swap_finished(struct basilisk_swap *swap)
{
*/
    /*int32_t i;
    if ( swap->utxo != 0 && swap->sentflag == 0 )
    {
        LP_availableset(swap->utxo);
        swap->utxo = 0;
        //LP_butxo_swapfields_set(swap->utxo);
    }
    swap->I.finished = (uint32_t)time(NULL);*/
/*
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
*/
    /*for (i=0; i<swap->nummessages; i++)
        if ( swap->messages[i].data != 0 )
            free(swap->messages[i].data), swap->messages[i].data = 0;
    free(swap->messages), swap->messages = 0;
    swap->nummessages = 0;*/
/*
    if ( swap->N.pair >= 0 )
        nn_close(swap->N.pair), swap->N.pair = -1;
}
*/
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
