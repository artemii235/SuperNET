
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
//  LP_ordermatch.c
//  marketmaker
//
struct LP_quoteinfo LP_Alicequery,LP_Alicereserved;
double LP_Alicemaxprice;
bits256 LP_Alicedestpubkey,LP_bobs_reserved;
uint32_t Alice_expiration,Bob_expiration;
struct { uint64_t aliceid; double bestprice; uint32_t starttime,counter; } Bob_competition[512];


void LP_failedmsg(uint32_t requestid,uint32_t quoteid,double val,char *uuidstr)
{
    char *msg; cJSON *retjson;
    if ( IPC_ENDPOINT >= 0 )
    {
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"method","failed");
        jaddstr(retjson,"uuid",uuidstr);
        jaddnum(retjson,"error",val);
        jaddnum(retjson,"requestid",requestid);
        jaddnum(retjson,"quoteid",quoteid);
        msg = jprint(retjson,1);
        LP_queuecommand(0,msg,IPC_ENDPOINT,-1,0);
        free(msg);
    }
}

double LP_bob_competition(int32_t *counterp,uint64_t aliceid,double price,int32_t counter)
{
    int32_t i,firsti = -1; uint32_t now = (uint32_t)time(NULL);
    *counterp = 0;
    for (i=0; i<sizeof(Bob_competition)/sizeof(*Bob_competition); i++)
    {
        if ( Bob_competition[i].aliceid == aliceid )
        {
            if ( counter < 0 || now > Bob_competition[i].starttime+LP_AUTOTRADE_TIMEOUT )
            {
                //printf("aliceid.%llu expired\n",(long long)aliceid);
                Bob_competition[i].bestprice = 0.;
                Bob_competition[i].starttime = now;
                Bob_competition[i].counter = 0;
            }
            if ( price != 0. && (Bob_competition[i].bestprice == 0. || price < Bob_competition[i].bestprice) )
            {
                Bob_competition[i].bestprice = price;
                //printf("Bob competition aliceid.%llu <- bestprice %.8f\n",(long long)aliceid,price);
            }
            Bob_competition[i].counter += counter;
            *counterp = Bob_competition[i].counter;
            return(Bob_competition[i].bestprice);
        }
        else if ( Bob_competition[i].aliceid == 0 )
            firsti = i;
    }
    if ( firsti < 0 )
        firsti = (LP_rand() % (sizeof(Bob_competition)/sizeof(*Bob_competition)));
    Bob_competition[firsti].starttime = (uint32_t)time(NULL);
    Bob_competition[firsti].counter = counter;
    Bob_competition[firsti].aliceid = aliceid;
    Bob_competition[firsti].bestprice = price;
    *counterp = counter;
    //printf("Bob competition aliceid.%llu %.8f\n",(long long)aliceid,price);
    return(price);
}

uint64_t LP_txfeecalc(struct iguana_info *coin,uint64_t txfee,int32_t txlen)
{
    if ( coin != 0 )
    {
        if ( strcmp(coin->symbol,"BTC") == 0 )
        {
            if ( txlen == 0 )
                txlen = LP_AVETXSIZE;
            coin->rate = LP_getestimatedrate(coin);
            if ( (txfee= SATOSHIDEN * coin->rate * txlen) <= 20000 )
            {
                //coin->rate = -1.;
                coin->rate = _LP_getestimatedrate(coin);
                if ( (txfee= SATOSHIDEN * coin->rate * txlen) <= 20000 )
                    txfee = 20000;
            }
        } else txfee = coin->txfee;
        if ( txfee < LP_MIN_TXFEE )
            txfee = LP_MIN_TXFEE;
    }
    return(txfee);
}

int32_t LP_quote_checkmempool(struct LP_quoteinfo *qp,struct LP_utxoinfo *autxo,struct LP_utxoinfo *butxo)
{
    int32_t selector,spendvini; bits256 spendtxid;
    if ( butxo != 0 && (selector= LP_mempool_vinscan(&spendtxid,&spendvini,qp->srccoin,qp->coinaddr,qp->txid,qp->vout,qp->txid2,qp->vout2)) >= 0 )
    {
        char str[65]; printf("LP_tradecommand selector.%d in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
        return(-1);
    }
    if ( autxo != 0 && (selector= LP_mempool_vinscan(&spendtxid,&spendvini,qp->destcoin,qp->destaddr,qp->desttxid,qp->destvout,qp->feetxid,qp->feevout)) >= 0 )
    {
        char str[65]; printf("LP_tradecommand dest selector.%d in mempool %s vini.%d",selector,bits256_str(str,spendtxid),spendvini);
        return(-1);
    }
    return(0);
}

double LP_quote_validate(struct LP_utxoinfo *autxo,struct LP_utxoinfo *butxo,struct LP_quoteinfo *qp,int32_t iambob)
{
    double qprice=0.; char str[65],srccoin[65],destcoin[65],bobtomic[64],alicetomic[64]; cJSON *txout; uint64_t txfee,desttxfee,srcvalue=0,srcvalue2=0,destvalue=0,destvalue2=0;
    LP_etomicsymbol(srccoin,bobtomic,qp->srccoin);
    LP_etomicsymbol(destcoin,alicetomic,qp->destcoin);
  //printf(">>>>>>> quote satoshis.(%.8f %.8f) %s %.8f -> %s %.8f\n",dstr(qp->satoshis),dstr(qp->destsatoshis),qp->srccoin,dstr(qp->satoshis),qp->destcoin,dstr(qp->destsatoshis));
    if ( butxo != 0 )
    {
        if ( LP_iseligible(&srcvalue,&srcvalue2,1,srccoin,qp->txid,qp->vout,qp->satoshis,qp->txid2,qp->vout2) == 0 )
        {
            //printf("bob not eligible %s (%.8f %.8f)\n",jprint(LP_quotejson(qp),1),dstr(srcvalue),dstr(srcvalue2));
            return(-2);
        }
        if ( (txout= LP_gettxout(srccoin,qp->coinaddr,qp->txid,qp->vout)) != 0 )
            free_json(txout);
        else
        {
            printf("%s %s payment %s/v%d is spent\n",srccoin,qp->coinaddr,bits256_str(str,qp->txid),qp->vout);
            return(-21);
        }
        if ( (txout= LP_gettxout(srccoin,qp->coinaddr,qp->txid2,qp->vout2)) != 0 )
            free_json(txout);
        else
        {
            printf("%s %s deposit %s/v%d is spent\n",srccoin,qp->coinaddr,bits256_str(str,qp->txid2),qp->vout2);
            return(-22);
        }
        if ( bits256_cmp(butxo->deposit.txid,qp->txid2) != 0 || butxo->deposit.vout != qp->vout2 )
        {
            char str[65],str2[65]; printf("%s != %s v%d != %d\n",bits256_str(str,butxo->deposit.txid),bits256_str(str2,qp->txid2),butxo->deposit.vout,qp->vout2);
            return(-6);
        }
        if ( strcmp(butxo->coinaddr,qp->coinaddr) != 0 )
        {
            printf("(%s) != (%s)\n",butxo->coinaddr,qp->coinaddr);
            return(-7);
        }
    }
    if ( autxo != 0 )
    {
        if ( LP_iseligible(&destvalue,&destvalue2,0,destcoin,qp->desttxid,qp->destvout,qp->destsatoshis,qp->feetxid,qp->feevout) == 0 )
        {
            //alice not eligible 0.36893923 -> dest 0.55020000 1.49130251 (0.61732249 0.00104324) 14b8b74808d2d34a70e5eddd1cad47d855858f8b23cac802576d4d37b5f8af8f/v1 abec6e76169bcb738235ca67fab02cc55390f39e422aa71f1badf8747c290cc4/v1
            char str[65],str2[65]; printf("alice not eligible %.8f -> dest %.8f %.8f (%.8f %.8f) %s/v%d %s/v%d\n",dstr(qp->satoshis),dstr(qp->destsatoshis),(double)qp->destsatoshis/qp->satoshis,dstr(destvalue),dstr(destvalue2),bits256_str(str,qp->desttxid),qp->destvout,bits256_str(str2,qp->feetxid),qp->feevout);
            return(-3);
        }
        if ( (txout= LP_gettxout(destcoin,qp->destaddr,qp->desttxid,qp->destvout)) != 0 )
            free_json(txout);
        else
        {
            printf("%s %s Apayment %s/v%d is spent\n",destcoin,qp->destaddr,bits256_str(str,qp->desttxid),qp->destvout);
            return(-23);
        }
        if ( (txout= LP_gettxout(destcoin,qp->destaddr,qp->feetxid,qp->feevout)) != 0 )
            free_json(txout);
        else
        {
            printf("%s %s dexfee %s/v%d is spent\n",destcoin,qp->destaddr,bits256_str(str,qp->feetxid),qp->feevout);
            return(-24);
        }
    }
    //printf("checked autxo and butxo\n");
    if ( LP_quote_checkmempool(qp,autxo,butxo) < 0 )
        return(-4);
    if ( iambob == 0 && autxo != 0 )
    {
        if ( bits256_cmp(autxo->fee.txid,qp->feetxid) != 0 || autxo->fee.vout != qp->feevout )
            return(-9);
        if ( strcmp(autxo->coinaddr,qp->destaddr) != 0 )
            return(-10);
    }
    if ( autxo != 0 && destvalue < qp->desttxfee+qp->destsatoshis )
    {
        printf("destvalue %.8f  destsatoshis %.8f is too small txfee %.8f?\n",dstr(destvalue),dstr(qp->destsatoshis),dstr(qp->desttxfee));
        return(-11);
    }
    if ( butxo != 0 && srcvalue < qp->txfee+qp->satoshis )
    {
        printf("srcvalue %.8f [%.8f] satoshis %.8f is too small txfee %.8f?\n",dstr(srcvalue),dstr(srcvalue) - dstr(qp->txfee+qp->satoshis),dstr(qp->satoshis),dstr(qp->txfee));
        return(-33);
    }
    LP_txfees(&txfee,&desttxfee,qp->srccoin,qp->destcoin);
    if ( txfee < qp->txfee )
        txfee = qp->txfee;
    if ( desttxfee < qp->desttxfee )
        desttxfee = qp->desttxfee;
    if ( qp->satoshis != 0 )
        qprice = ((double)qp->destsatoshis / (qp->satoshis-qp->txfee));
    //printf("qprice %.8f <- %.8f/%.8f txfees.(%.8f %.8f) vs (%.8f %.8f)\n",qprice,dstr(qp->destsatoshis),dstr(qp->satoshis),dstr(qp->txfee),dstr(qp->desttxfee),dstr(txfee),dstr(desttxfee));
    if ( qp->txfee < LP_REQUIRED_TXFEE*txfee || qp->desttxfee < LP_REQUIRED_TXFEE*desttxfee )
    {
        printf("error -14: txfee %.8f < %.8f or desttxfee %.8f < %.8f\n",dstr(qp->txfee),dstr(LP_REQUIRED_TXFEE*txfee),dstr(qp->desttxfee),dstr(LP_REQUIRED_TXFEE*desttxfee));
        return(-14);
    }
    if ( butxo != 0 )
    {
        if ( qp->satoshis < (srcvalue / LP_MINVOL) || srcvalue < qp->txfee*LP_MINSIZE_TXFEEMULT )
        {
            printf("utxo payment %.8f is less than %f covered by Q %.8f or <10x txfee %.8f [%d %d]\n",dstr(srcvalue),1./LP_MINVOL,dstr(qp->satoshis),dstr(qp->txfee),qp->satoshis < (srcvalue / LP_MINVOL),srcvalue < qp->txfee*LP_MINSIZE_TXFEEMULT);
            return(-12);
        }
    }
    if ( autxo != 0 )
    {
        if ( qp->destsatoshis < (destvalue / LP_MINCLIENTVOL) || destvalue < qp->desttxfee*LP_MINSIZE_TXFEEMULT )
        {
            printf("destsatoshis %.8f is less than %f of value %.8f or < 10x txfee %.8f\n",dstr(qp->destsatoshis),1./LP_MINCLIENTVOL,dstr(destvalue),dstr(qp->desttxfee));
            return(-13);
        }
    }
    return(qprice);
}

int32_t LP_arrayfind(cJSON *array,bits256 txid,int32_t vout)
{
    int32_t i,n = cJSON_GetArraySize(array); cJSON *item;
    for (i=0; i<n; i++)
    {
        item = jitem(array,i);
        if ( vout == jint(item,"vout") && bits256_cmp(txid,jbits256(item,"txid")) == 0 )
            return(i);
    }
    return(-1);
}

int32_t LP_nanobind(void *ctx,char *pairstr)
{
    int32_t i,r,pairsock = -1; uint16_t mypullport; char bindaddr[128];
    if ( LP_canbind != 0 )
    {
        if ( (pairsock= nn_socket(AF_SP,NN_PAIR)) < 0 )
            printf("error creating utxo->pair\n");
        else
        {
            for (i=0; i<10000; i++)
            {
                r = (10000 + (LP_rand() % 50000)) & 0xffff;
                if ( LP_fixed_pairport != 0 )
                    r = LP_fixed_pairport;
                nanomsg_transportname(0,pairstr,LP_myipaddr,r);
                nanomsg_transportname(1,bindaddr,LP_myipaddr,r);
                if ( nn_bind(pairsock,bindaddr) >= 0 )
                {
                    //timeout = 1;
                    //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
                    //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
                    //printf("nanobind %s to %d\n",pairstr,pairsock);
                    return(pairsock);
                } // else printf("error binding to %s for %s\n",bindaddr,pairstr);
                if ( LP_fixed_pairport != 0 )
                    break;
            }
            printf("%d ports all used\n",i);
            nn_close(pairsock);
            pairsock = -1;
        }
    } else pairsock = LP_initpublicaddr(ctx,&mypullport,pairstr,"127.0.0.1",0,1);
    return(pairsock);
}

int32_t LP_nearest_utxovalue(struct iguana_info *coin,char *coinaddr,struct LP_address_utxo **utxos,int32_t n,uint64_t targetval)
{
    int32_t i,replacei,bestheight,mini = -1; struct LP_address_utxo *up,*bestup; struct electrum_info *backupep=0,*ep; int64_t dist,bestdist; uint64_t mindist = (1LL << 60);
    if ( (ep= coin->electrum) != 0 )
    {
        if ( (backupep= ep->prev) == 0 )
            backupep = ep;
    }
    //printf("LP_nearest_utxovalue %s %s utxos[%d] target %.8f\n",coin->symbol,coinaddr,n,dstr(targetval));
    for (i=0; i<n; i++)
    {
        if ( (up= utxos[i]) != 0 )
        {
            dist = (up->U.value - targetval);
            //printf("nearest i.%d target %.8f val %.8f dist %.8f mindist %.8f mini.%d spent.%d\n",i,dstr(targetval),dstr(up->U.value),dstr(dist),dstr(mindist),mini,up->spendheight);
            if ( up->spendheight <= 0 )
            {
                if ( dist >= 0 && dist < mindist )
                {
                    //printf("(%.8f %.8f %.8f).%d ",dstr(up->U.value),dstr(dist),dstr(mindist),mini);
                    mini = i;
                    mindist = dist;
                }
            }
        }
    }
    if ( mini >= 0 && (bestup= utxos[mini]) != 0 )
    {
        bestdist = (bestup->U.value - targetval);
        replacei = -1;
        bestheight = bestup->U.height;
        for (i=0; i<n; i++)
        {
            if ( i != mini && (up= utxos[i]) != 0 )
            {
                dist = (up->U.value - targetval);
                if ( dist > 0 && up->U.height < bestheight )
                {
                    if ( (double)dist/bestdist < sqrt(((double)bestheight - up->U.height)/1000) )
                    {
                        replacei = i;
                        bestheight = up->U.height;
                    } //else printf("almost ratio %.3f dist %.8f vs best %.8f, ht %d vs best ht %d\n",(double)dist/bestdist,dstr(dist),dstr(bestdist),up->U.height,bestheight);
                }
            }
        }
        if ( replacei >= 0 )
        {
            //printf("REPLACE bestdist %.8f height %d with dist %.8f height %d\n",dstr(bestdist),bestup->U.height,dstr(utxos[replacei]->U.value - targetval),utxos[replacei]->U.height);
            return(replacei);
        }
    }
    //printf("return mini.%d\n",mini);
    return(mini);
}

void LP_butxo_set(struct LP_utxoinfo *butxo,int32_t iambob,struct iguana_info *coin,struct LP_address_utxo *up,struct LP_address_utxo *up2,int64_t satoshis)
{
    butxo->pubkey = G.LP_mypub25519;
    safecopy(butxo->coin,coin->symbol,sizeof(butxo->coin));
    safecopy(butxo->coinaddr,coin->smartaddr,sizeof(butxo->coinaddr));
    butxo->payment.txid = up->U.txid;
    butxo->payment.vout = up->U.vout;
    butxo->payment.value = up->U.value;
    if ( (butxo->iambob= iambob) != 0 )
    {
        butxo->deposit.txid = up2->U.txid;
        butxo->deposit.vout = up2->U.vout;
        butxo->deposit.value = up2->U.value;
    }
    else
    {
        butxo->fee.txid = up2->U.txid;
        butxo->fee.vout = up2->U.vout;
        butxo->fee.value = up2->U.value;
    }
    butxo->swap_satoshis = satoshis;
}

void LP_abutxo_set(struct LP_utxoinfo *autxo,struct LP_utxoinfo *butxo,struct LP_quoteinfo *qp)
{
    if ( butxo != 0 )
    {
        memset(butxo,0,sizeof(*butxo));
        butxo->pubkey = qp->srchash;
        safecopy(butxo->coin,qp->srccoin,sizeof(butxo->coin));
        safecopy(butxo->coinaddr,qp->coinaddr,sizeof(butxo->coinaddr));
        butxo->payment.txid = qp->txid;
        butxo->payment.vout = qp->vout;
        //butxo->payment.value = qp->value;
        butxo->iambob = 1;
        butxo->deposit.txid = qp->txid2;
        butxo->deposit.vout = qp->vout2;
        //butxo->deposit.value = up2->U.value;
        butxo->swap_satoshis = qp->satoshis;
    }
    if ( autxo != 0 )
    {
        memset(autxo,0,sizeof(*autxo));
        autxo->pubkey = qp->desthash;
        safecopy(autxo->coin,qp->destcoin,sizeof(autxo->coin));
        safecopy(autxo->coinaddr,qp->destaddr,sizeof(autxo->coinaddr));
        autxo->payment.txid = qp->desttxid;
        autxo->payment.vout = qp->destvout;
        //autxo->payment.value = qp->value;
        autxo->iambob = 0;
        autxo->fee.txid = qp->feetxid;
        autxo->fee.vout = qp->feevout;
        //autxo->deposit.value = up2->U.value;
        autxo->swap_satoshis = qp->destsatoshis;
    }
}

uint64_t LP_basesatoshis(double relvolume,double price,uint64_t txfee,uint64_t desttxfee)
{
    //printf("basesatoshis %.8f (rel %.8f / price %.8f)\n",dstr(SATOSHIDEN * ((relvolume) / price) + 2*txfee),relvolume,price);
    if ( relvolume > dstr(desttxfee) && price > SMALLVAL )
        return(SATOSHIDEN * (relvolume / price) + 2*txfee);
    else return(0);
}

struct LP_utxoinfo *LP_address_myutxopair(struct LP_utxoinfo *butxo,int32_t iambob,struct LP_address_utxo **utxos,int32_t max,struct iguana_info *coin,char *coinaddr,uint64_t txfee,double relvolume,double price,uint64_t desttxfee)
{
    struct LP_address *ap; uint64_t fee,targetval,targetval2; int32_t m,mini; struct LP_address_utxo *up,*up2; double ratio;
    if ( coin->etomic[0] != 0 )
    {
        if ( (coin= LP_coinfind("ETOMIC")) != 0 )
            coinaddr = coin->smartaddr;
    }
    if ( coin == 0 )
        return(0);
    memset(butxo,0,sizeof(*butxo));
    if ( iambob != 0 )
    {
        targetval = LP_basesatoshis(relvolume,price,txfee,desttxfee) + 3*txfee;
        targetval2 = (targetval / 8) * 9 + 3*txfee;
        fee = txfee;
        ratio = LP_MINVOL;
    }
    else
    {
        targetval = relvolume*SATOSHIDEN + 3*desttxfee;
        targetval2 = (targetval / 777) + 3*desttxfee;
        fee = desttxfee;
        ratio = LP_MINCLIENTVOL;
    }
    if ( coin != 0 && (ap= LP_address(coin,coinaddr)) != 0 )
    {
        if ( (m= LP_address_utxo_ptrs(coin,iambob,utxos,max,ap,coinaddr)) > 1 )
        {
            if ( 0 )
            {
                int32_t i;
                for (i=0; i<m; i++)
                    if ( utxos[i]->U.value >= targetval )
                        printf("%.8f ",dstr(utxos[i]->U.value));
                printf("targetval %.8f vol %.8f price %.8f txfee %.8f %s %s\n",dstr(targetval),relvolume,price,dstr(fee),coin->symbol,coinaddr);
            }
            while ( 1 )
            {
                mini = -1;
                if ( targetval != 0 && (mini= LP_nearest_utxovalue(coin,coinaddr,utxos,m,targetval+fee)) >= 0 )
                {
                    up = utxos[mini];
                    utxos[mini] = 0;
                    //printf("found mini.%d %.8f for targetval %.8f -> targetval2 %.8f, ratio %.2f\n",mini,dstr(up->U.value),dstr(targetval),dstr(targetval2),(double)up->U.value/targetval);
                    if ( (double)up->U.value/targetval < ratio-1 )
                        
                    {
                        if ( 0 )
                        {
                            int32_t i;
                            for (i=0; i<m; i++)
                                if ( utxos[i] != 0 && utxos[i]->U.value >= targetval2 )
                                    printf("%.8f ",dstr(utxos[i]->U.value));
                            printf("targetval2 %.8f vol %.8f price %.8f txfee %.8f %s %s\n",dstr(targetval2),relvolume,price,dstr(fee),coin->symbol,coinaddr);
                        }
                        if ( (mini= LP_nearest_utxovalue(coin,coinaddr,utxos,m,(targetval2+2*fee) * 1.01)) >= 0 )
                        {
                            if ( up != 0 && (up2= utxos[mini]) != 0 )
                            {
                                LP_butxo_set(butxo,iambob,coin,up,up2,targetval);
                                return(butxo);
                            } else printf("cant find utxos[mini %d]\n",mini);
                        } //else printf("cant find targetval2 %.8f\n",dstr(targetval2));
                    } //else printf("failed ratio test %.8f\n",(double)up->U.value/targetval);
                } else if ( targetval != 0 && mini >= 0 )
                    printf("targetval %.8f mini.%d\n",dstr(targetval),mini);
                if ( targetval == 0 || mini < 0 )
                    break;
            }
        } //else printf("no %s %s utxos pass LP_address_utxo_ptrs filter %.8f %.8f\n",coin->symbol,coinaddr,dstr(targetval),dstr(targetval2));
    }
    printf("address_myutxopair couldnt find %s %s targets %.8f %.8f\n",coin->symbol,coinaddr,dstr(targetval),dstr(targetval2));
    return(0);
}

int32_t LP_connectstartbob(void *ctx,int32_t pubsock,char *base,char *rel,double price,struct LP_quoteinfo *qp)
{
    char pairstr[512],otheraddr[64]; cJSON *reqjson; bits256 privkey; int32_t i,pair=-1,retval = -1,DEXselector = 0; int64_t dtrust; struct basilisk_swap *swap; struct iguana_info *ecoin,*coin,*kmdcoin;
    qp->quotetime = (uint32_t)time(NULL);
    if ( (coin= LP_coinfind(qp->srccoin)) == 0 )
    {
        printf("cant find coin.%s\n",qp->srccoin);
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,-3000,qp->uuidstr);
        return(-1);
    }
    privkey = LP_privkey(coin->symbol,coin->smartaddr,coin->taddr);
    if ( coin->etomic[0] != 0 )
    {
        if ( (ecoin= LP_coinfind("ETOMIC")) != 0 )
            privkey = LP_privkey(ecoin->symbol,ecoin->smartaddr,ecoin->taddr);
    }
    if ( bits256_nonz(privkey) != 0 && bits256_cmp(G.LP_mypub25519,qp->srchash) == 0 )
    {
        LP_requestinit(&qp->R,qp->srchash,qp->desthash,base,qp->satoshis-qp->txfee,rel,qp->destsatoshis-qp->desttxfee,qp->timestamp,qp->quotetime,DEXselector);
        dtrust = LP_dynamictrust(qp->othercredits,qp->desthash,LP_kmdvalue(qp->destcoin,qp->destsatoshis));
        if ( (swap= LP_swapinit(1,0,privkey,&qp->R,qp,dtrust > 0)) == 0 )
        {
            printf("cant initialize swap\n");
            LP_failedmsg(qp->R.requestid,qp->R.quoteid,-3001,qp->uuidstr);
            return(-1);
        }
        if ( (pair= LP_nanobind(ctx,pairstr)) >= 0 )
        {
            swap->N.pair = pair;
            if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_bobloop,(void *)swap) == 0 )
            {
                reqjson = LP_quotejson(qp);
                LP_swapsfp_update(qp->R.requestid,qp->R.quoteid);
                jaddstr(reqjson,"method","connected");
                jaddstr(reqjson,"pair",pairstr);
                if ( (kmdcoin= LP_coinfind("KMD")) != 0 )
                    jadd(reqjson,"proof",LP_instantdex_txids(0,kmdcoin->smartaddr));
                //char str[65]; printf("BOB pubsock.%d binds to %d (%s)\n",pubsock,pair,bits256_str(str,qp->desthash));
                LP_importaddress(qp->destcoin,qp->destaddr);
                LP_otheraddress(qp->srccoin,otheraddr,qp->destcoin,qp->destaddr);
                LP_importaddress(qp->srccoin,otheraddr);
                bits256 zero;
                memset(zero.bytes,0,sizeof(zero));
                for (i=0; i<1; i++)
                {
                    LP_reserved_msg(1,qp->srccoin,qp->destcoin,qp->desthash,jprint(reqjson,0));
                    break;
                    sleep(10);
                    if ( swap->received != 0 )
                    {
                        printf("swap %u-%u has started t%u\n",swap->I.req.requestid,swap->I.req.quoteid,swap->received);
                        break;
                    }
                    printf("bob tries %u-%u again i.%d\n",swap->I.req.requestid,swap->I.req.quoteid,i);
                    LP_reserved_msg(1,qp->srccoin,qp->destcoin,zero,jprint(reqjson,0));
                }
                sleep(1);
                printf("send CONNECT for %u-%u\n",qp->R.requestid,qp->R.quoteid);
                LP_reserved_msg(1,qp->srccoin,qp->destcoin,zero,jprint(reqjson,0));
                if ( IPC_ENDPOINT >= 0 )
                    LP_queuecommand(0,jprint(reqjson,1),IPC_ENDPOINT,-1,0);
                else free_json(reqjson);
                retval = 0;
            }
            else
            {
                LP_failedmsg(qp->R.requestid,qp->R.quoteid,-3002,qp->uuidstr);
                printf("error launching swaploop\n");
            }
        }
        else
        {
            LP_failedmsg(qp->R.requestid,qp->R.quoteid,-3003,qp->uuidstr);
            printf("couldnt bind to any port %s\n",pairstr);
        }
    }
    else
    {
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,-3004,qp->uuidstr);
        printf("cant find privkey for %s\n",coin->smartaddr);
    }
    if ( retval < 0 )
    {
        if ( pair >= 0 )
            nn_close(pair);
        LP_availableset(qp->txid,qp->vout);
        LP_availableset(qp->txid2,qp->vout2);
    }
    return(retval);
}

char *LP_trade(void *ctx,char *myipaddr,int32_t mypubsock,struct LP_quoteinfo *qp,double maxprice,int32_t timeout,int32_t duration,uint32_t tradeid,bits256 destpubkey,char *uuidstr)
{
    double price;
    price = 0.;
    memset(qp->txid.bytes,0,sizeof(qp->txid));
    qp->txid2 = qp->txid;
    qp->aliceid = LP_aliceid_calc(qp->desttxid,qp->destvout,qp->feetxid,qp->feevout);
    if ( (qp->tradeid= tradeid) == 0 )
        qp->tradeid = LP_rand();
    qp->srchash = destpubkey;
    strncpy(qp->uuidstr,uuidstr,sizeof(qp->uuidstr)-1);
    LP_query(ctx,myipaddr,mypubsock,"request",qp);
    LP_Alicequery = *qp, LP_Alicemaxprice = maxprice, Alice_expiration = qp->timestamp + timeout, LP_Alicedestpubkey = destpubkey;
    char str[65]; printf("LP_trade %s/%s %.8f vol %.8f dest.(%s) maxprice %.8f etomicdest.(%s) uuid.%s\n",qp->srccoin,qp->destcoin,dstr(qp->satoshis),dstr(qp->destsatoshis),bits256_str(str,LP_Alicedestpubkey),maxprice,qp->etomicdest,qp->uuidstr);
    return(LP_recent_swaps(0,uuidstr));
}

int32_t LP_quotecmp(int32_t strictflag,struct LP_quoteinfo *qp,struct LP_quoteinfo *qp2)
{
    if ( bits256_nonz(LP_Alicedestpubkey) != 0 )
    {
        if (bits256_cmp(LP_Alicedestpubkey,qp->srchash) != 0 )
        {
            printf("reject quote from non-matching pubkey\n");
            return(-1);
        } else printf("dont reject quote from destpubkey\n");
    }
    if ( bits256_cmp(qp->desthash,qp2->desthash) == 0 && strcmp(qp->srccoin,qp2->srccoin) == 0 && strcmp(qp->destcoin,qp2->destcoin) == 0 && bits256_cmp(qp->desttxid,qp2->desttxid) == 0 && qp->destvout == qp2->destvout && bits256_cmp(qp->feetxid,qp2->feetxid) == 0 && qp->feevout == qp2->feevout && qp->destsatoshis == qp2->destsatoshis && qp->txfee >= qp2->txfee && qp->desttxfee == qp2->desttxfee )
    {
        if ( strictflag == 0 || (qp->aliceid == qp2->aliceid && qp->R.requestid == qp2->R.requestid && qp->R.quoteid == qp2->R.quoteid && qp->vout == qp2->vout && qp->vout2 == qp2->vout2 && qp->satoshis == qp2->satoshis && bits256_cmp(qp->txid,qp2->txid) == 0 && bits256_cmp(qp->txid2,qp2->txid2) == 0 && bits256_cmp(qp->srchash,qp2->srchash) == 0) )
            return(0);
        else printf("strict compare failure\n");
    }
    return(-1);
}

void LP_alicequery_clear()
{
    memset(&LP_Alicequery,0,sizeof(LP_Alicequery));
    memset(&LP_Alicedestpubkey,0,sizeof(LP_Alicedestpubkey));
    LP_Alicemaxprice = 0.;
    Alice_expiration = 0;
}

int32_t LP_alice_eligible(uint32_t quotetime)
{
    if ( Alice_expiration != 0 && quotetime > Alice_expiration )
    {
        if ( LP_Alicequery.uuidstr[0] != 0 )
            LP_failedmsg(LP_Alicequery.R.requestid,LP_Alicequery.R.quoteid,-9999,LP_Alicequery.uuidstr);
        printf("time expired for Alice_request\n");
        LP_alicequery_clear();
    }
    return(Alice_expiration == 0 || time(NULL) < Alice_expiration);
}

char *LP_cancel_order(char *uuidstr)
{
    int32_t num = 0; cJSON *retjson;
    if ( uuidstr != 0 )
    {
        num = LP_trades_canceluuid(uuidstr);
        retjson = cJSON_CreateObject();
        jaddstr(retjson,"result","success");
        jaddnum(retjson,"numentries",num);
        if ( strcmp(LP_Alicequery.uuidstr,uuidstr) == 0 )
        {
            LP_failedmsg(LP_Alicequery.R.requestid,LP_Alicequery.R.quoteid,-9998,LP_Alicequery.uuidstr);
            LP_alicequery_clear();
            jaddstr(retjson,"status","uuid canceled");
        } else jaddstr(retjson,"status","will stop trade negotiation, but if swap started it wont cancel");
        return(jprint(retjson,1));
    }
    return(clonestr("{\"error\":\"uuid not cancellable\"}"));
}

char *LP_connectedalice(struct LP_quoteinfo *qp,char *pairstr) // alice
{
    cJSON *retjson; char otheraddr[64],*msg; double bid,ask,price,qprice; int32_t pairsock = -1; int32_t DEXselector = 0; struct LP_utxoinfo *autxo,A,B,*butxo; struct basilisk_swap *swap; struct iguana_info *coin;
    if ( bits256_cmp(qp->desthash,G.LP_mypub25519) != 0 )
    {
        LP_aliceid(qp->tradeid,qp->aliceid,"error1",0,0);
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4000,qp->uuidstr);
        return(clonestr("{\"result\",\"update stats\"}"));
    }
    printf("CONNECTED numpending.%d tradeid.%u requestid.%u quoteid.%u pairstr.%s\n",G.LP_pendingswaps,qp->tradeid,qp->R.requestid,qp->R.quoteid,pairstr!=0?pairstr:"");
    LP_requestinit(&qp->R,qp->srchash,qp->desthash,qp->srccoin,qp->satoshis-qp->txfee,qp->destcoin,qp->destsatoshis-qp->desttxfee,qp->timestamp,qp->quotetime,DEXselector);
    //printf("calculated requestid.%u quoteid.%u\n",qp->R.requestid,qp->R.quoteid);
    memset(&LP_Alicereserved,0,sizeof(LP_Alicereserved));
    LP_aliceid(qp->tradeid,qp->aliceid,"connected",qp->R.requestid,qp->R.quoteid);
    autxo = &A;
    butxo = &B;
    memset(autxo,0,sizeof(*autxo));
    memset(butxo,0,sizeof(*butxo));
    LP_abutxo_set(autxo,butxo,qp);
    if ( (qprice= LP_quote_validate(autxo,butxo,qp,0)) <= SMALLVAL )
    {
        LP_availableset(qp->desttxid,qp->vout);
        LP_availableset(qp->feetxid,qp->feevout);
        LP_aliceid(qp->tradeid,qp->aliceid,"error4",0,0);
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,qprice,qp->uuidstr);
        printf("quote %s/%s validate error %.0f\n",qp->srccoin,qp->destcoin,qprice);
        return(clonestr("{\"error\":\"quote validation error\"}"));
    }
    if ( LP_myprice(&bid,&ask,qp->srccoin,qp->destcoin) <= SMALLVAL || bid <= SMALLVAL )
    {
        printf("this node has no price for %s/%s (%.8f %.8f)\n",qp->destcoin,qp->srccoin,bid,ask);
        LP_availableset(qp->desttxid,qp->vout);
        LP_availableset(qp->feetxid,qp->feevout);
        LP_aliceid(qp->tradeid,qp->aliceid,"error5",0,0);
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4002,qp->uuidstr);
        return(clonestr("{\"error\":\"no price set\"}"));
    }
    //LP_RTmetrics_update(qp->srccoin,qp->destcoin);
    printf("%s/%s bid %.8f ask %.8f values %.8f %.8f\n",qp->srccoin,qp->destcoin,bid,ask,dstr(butxo->payment.value),dstr(butxo->deposit.value));
    price = bid;
    if ( (coin= LP_coinfind(qp->destcoin)) == 0 )
    {
        LP_aliceid(qp->tradeid,qp->aliceid,"error6",0,0);
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4003,qp->uuidstr);
        return(clonestr("{\"error\":\"cant get alicecoin\"}"));
    }
    qp->privkey = LP_privkey(coin->symbol,qp->destaddr,coin->taddr);
    if ( bits256_nonz(qp->privkey) != 0 )//&& qp->quotetime >= qp->timestamp-3 )
    {
        retjson = cJSON_CreateObject();
        if ( (swap= LP_swapinit(0,0,qp->privkey,&qp->R,qp,LP_dynamictrust(qp->othercredits,qp->srchash,LP_kmdvalue(qp->srccoin,qp->satoshis)) > 0)) == 0 )
        {
            jaddstr(retjson,"error","couldnt swapinit");
            LP_availableset(qp->desttxid,qp->vout);
            LP_availableset(qp->feetxid,qp->feevout);
            LP_aliceid(qp->tradeid,qp->aliceid,"error7",qp->R.requestid,qp->R.quoteid);
            LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4004,qp->uuidstr);
            return(jprint(retjson,1));
        }
        if ( pairstr == 0 || pairstr[0] == 0 || (pairsock= nn_socket(AF_SP,NN_PAIR)) < 0 )
        {
            LP_aliceid(qp->tradeid,qp->aliceid,"error8",qp->R.requestid,qp->R.quoteid);
            LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4005,qp->uuidstr);
            jaddstr(retjson,"error","couldnt create pairsock");
        }
        else if ( nn_connect(pairsock,pairstr) >= 0 )
        {
            //timeout = 1;
            //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
            //nn_setsockopt(pairsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
            swap->tradeid = qp->tradeid;
            swap->N.pair = pairsock;
            //autxo->S.swap = swap;
            //swap->utxo = autxo;
            LP_importaddress(qp->srccoin,qp->coinaddr);
            LP_otheraddress(qp->destcoin,otheraddr,qp->srccoin,qp->coinaddr);
            LP_importaddress(qp->srccoin,otheraddr);
            LP_aliceid(qp->tradeid,qp->aliceid,"started",qp->R.requestid,qp->R.quoteid);
            printf("alice pairstr.(%s) pairsock.%d pthread_t %ld\n",pairstr,pairsock,sizeof(pthread_t));
            if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)LP_aliceloop,(void *)swap) == 0 )
            {
                retjson = LP_quotejson(qp);
                jaddstr(retjson,"result","success");
                LP_swapsfp_update(qp->R.requestid,qp->R.quoteid);
                if ( IPC_ENDPOINT >= 0 )
                {
                    msg = jprint(retjson,0);
                    LP_queuecommand(0,msg,IPC_ENDPOINT,-1,0);
                    free(msg);
                }
                //jaddnum(retjson,"requestid",qp->R.requestid);
                //jaddnum(retjson,"quoteid",qp->R.quoteid);
            }
            else
            {
                LP_aliceid(qp->tradeid,qp->aliceid,"error9",qp->R.requestid,qp->R.quoteid);
                jaddstr(retjson,"error","couldnt aliceloop");
                LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4006,qp->uuidstr);
            }
        }
        else
        {
            LP_aliceid(qp->tradeid,qp->aliceid,"error10",qp->R.requestid,qp->R.quoteid);
            printf("connect error %s\n",nn_strerror(nn_errno()));
            LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4007,qp->uuidstr);
        }
        //printf("connected result.(%s)\n",jprint(retjson,0));
        if ( jobj(retjson,"error") != 0 )
        {
            LP_availableset(qp->desttxid,qp->vout);
            LP_availableset(qp->feetxid,qp->feevout);
        }
        return(jprint(retjson,1));
    }
    else
    {
        LP_availableset(qp->desttxid,qp->vout);
        LP_availableset(qp->feetxid,qp->feevout);
        LP_aliceid(qp->tradeid,qp->aliceid,"error11",0,0);
        printf("no privkey found coin.%s %s taddr.%u\n",qp->destcoin,qp->destaddr,coin->taddr);
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,-4008,qp->uuidstr);
        return(clonestr("{\"error\",\"no privkey\"}"));
    }
}

int32_t LP_aliceonly(char *symbol)
{
    return(0);
}

int32_t LP_validSPV(char *symbol,char *coinaddr,bits256 txid,int32_t vout)
{
    struct electrum_info *ep,*backupep; cJSON *txobj; struct LP_address_utxo *up; struct iguana_info *coin; int32_t height; struct LP_transaction *tx;
    coin = LP_coinfind(symbol);
    if ( coin != 0 && (ep= coin->electrum) != 0 )
    {
        if ( (up= LP_address_utxofind(coin,coinaddr,txid,vout)) == 0 )
        {
            if ( (txobj= electrum_transaction(&height,symbol,ep,&txobj,txid,coinaddr)) != 0 )
                free_json(txobj);
            if ( (tx= LP_transactionfind(coin,txid)) != 0 )
            {
                if ( vout < tx->numvouts && tx->height > 0 )
                {
                    printf("added missing utxo for SPV checking\n");
                    LP_address_utxoadd(0,(uint32_t)time(NULL),"LP_validSPV",coin,coinaddr,txid,vout,tx->outpoints[vout].value,tx->height,-1);
                }
            }
        }
        if ( (up= LP_address_utxofind(coin,coinaddr,txid,vout)) != 0 )
        {
            if ( up->SPV > 0 )
                return(0);
            if ( up->SPV < 0 )
                return(-1);
            if ( (backupep= ep->prev) == 0 )
                backupep = ep;
            up->SPV = LP_merkleproof(coin,coinaddr,backupep,up->U.txid,up->U.height);
            if ( up->SPV < 0 )
                return(-1);
        }
    }
    return(0);
}

double LP_trades_alicevalidate(void *ctx,struct LP_quoteinfo *qp)
{
    double qprice; struct LP_utxoinfo A,B,*autxo,*butxo; char str[65];
    autxo = &A;
    butxo = &B;
    memset(autxo,0,sizeof(*autxo));
    memset(butxo,0,sizeof(*butxo));
    LP_abutxo_set(autxo,butxo,qp);
    if ( (qprice= LP_quote_validate(autxo,butxo,qp,0)) <= SMALLVAL )
    {
        printf("reserved quote validate error %.0f\n",qprice);
        return((int32_t)qprice);
    }
    if ( LP_validSPV(qp->srccoin,qp->coinaddr,qp->txid,qp->vout) < 0 )
    {
        sleep(1);
        if ( LP_validSPV(qp->srccoin,qp->coinaddr,qp->txid,qp->vout) < 0 )
        {
            printf("LP_trades_alicevalidate %s src %s failed SPV check\n",qp->srccoin,bits256_str(str,qp->txid));
            return(-44);
        }
    }
    else if ( LP_validSPV(qp->srccoin,qp->coinaddr,qp->txid2,qp->vout2) < 0 )
    {
        sleep(1);
        if ( LP_validSPV(qp->srccoin,qp->coinaddr,qp->txid2,qp->vout2) < 0 )
        {
            printf("LP_trades_alicevalidate %s src2 %s failed SPV check\n",qp->srccoin,bits256_str(str,qp->txid2));
            return(-55);
        }
    }
    return(qprice);
}

void LP_reserved(void *ctx,char *myipaddr,int32_t mypubsock,struct LP_quoteinfo *qp)
{
    double price=0.,maxprice = LP_Alicemaxprice;
    //if ( LP_quotecmp(0,qp,&LP_Alicequery) == 0 )
    {
        price = LP_pricecache(qp,qp->srccoin,qp->destcoin,qp->txid,qp->vout);
        if ( LP_pricevalid(price) > 0 && maxprice > SMALLVAL && price <= maxprice )
        {
            qp->tradeid = LP_Alicequery.tradeid;
            LP_Alicereserved = *qp;
            LP_alicequery_clear();
            //printf("send CONNECT\n");
            LP_query(ctx,myipaddr,mypubsock,"connect",qp);
        } else printf("LP_reserved %llu price %.8f vs maxprice %.8f\n",(long long)qp->aliceid,price,maxprice);
    } //else printf("probably a timeout, reject reserved due to not eligible.%d or mismatched quote price %.8f vs maxprice %.8f\n",LP_alice_eligible(qp->quotetime),price,maxprice);
}

double LP_trades_bobprice(double *bidp,double *askp,struct LP_quoteinfo *qp)
{
    double price; struct iguana_info *coin; char str[65];
    price = LP_myprice(bidp,askp,qp->srccoin,qp->destcoin);
    if ( (coin= LP_coinfind(qp->srccoin)) == 0 || price <= SMALLVAL || *askp <= SMALLVAL )
    {
        //printf("this node has no price for %s/%s\n",qp->srccoin,qp->destcoin);
        return(0.);
    }
    price = *askp;
    //printf("MYPRICE %s/%s %.8f vs qprice %.8f\n",qp->srccoin,qp->destcoin,price,(double)qp->destsatoshis/qp->satoshis);
    if ( LP_validSPV(qp->destcoin,qp->destaddr,qp->desttxid,qp->destvout) < 0 )
    {
        printf("LP_trades_bobprice %s dest %s failed SPV check\n",qp->destcoin,bits256_str(str,qp->desttxid));
        return(0.);
    }
    else if (LP_validSPV(qp->destcoin,qp->destaddr,qp->feetxid,qp->feevout) < 0 )
    {
        printf("LP_trades_bobprice %s dexfee %s failed SPV check\n",qp->destcoin,bits256_str(str,qp->feetxid));
        return(0.);
    }
    return(*askp);
}

double LP_trades_pricevalidate(struct LP_quoteinfo *qp,struct iguana_info *coin,double price)
{
    double qprice; struct LP_utxoinfo A,B,*autxo,*butxo;
    autxo = &A;
    butxo = &B;
    memset(autxo,0,sizeof(*autxo));
    memset(butxo,0,sizeof(*butxo));
    LP_abutxo_set(autxo,butxo,qp);
    if ( coin->etomic[0] == 0 && strcmp(qp->coinaddr,coin->smartaddr) != 0 )
    {
        printf("bob is patching qp->coinaddr %s mismatch != %s\n",qp->coinaddr,coin->smartaddr);
        strcpy(qp->coinaddr,coin->smartaddr);
    }
    if ( butxo == 0 || bits256_nonz(butxo->payment.txid) == 0 || bits256_nonz(butxo->deposit.txid) == 0 || butxo->payment.vout < 0 || butxo->deposit.vout < 0 )
    {
        char str[65],str2[65]; printf("couldnt find bob utxos for autxo %s/v%d %s/v%d %.8f -> %.8f\n",bits256_str(str,qp->txid),qp->vout,bits256_str(str2,qp->txid2),qp->vout2,dstr(qp->satoshis),dstr(qp->destsatoshis));
        return(-66);
    }
    if ( (qprice= LP_quote_validate(autxo,butxo,qp,1)) <= SMALLVAL )
    {
        printf("quote %s/%s validate error %.0f\n",qp->srccoin,qp->destcoin,qprice);
        return(-3);
    }
    if ( qprice < (price - 0.00000001) * 0.998 )
    {
        printf(" quote price %.8f (%llu/%llu %.8f) too low vs %.8f for %s/%s price %.8f %.8f\n",qprice,(long long)qp->destsatoshis,(long long)(qp->satoshis-qp->txfee),(double)qp->destsatoshis/(qp->satoshis-qp->txfee),price,qp->srccoin,qp->destcoin,price,(price - 0.00000001) * 0.998);
        return(-77);
    }
    return(qprice);
}

struct LP_quoteinfo *LP_trades_gotrequest(void *ctx,struct LP_quoteinfo *qp,struct LP_quoteinfo *newqp,char *pairstr)
{
    double price=0.,p=0.,qprice,myprice,bestprice,range,bid,ask; struct iguana_info *coin,*othercoin; struct LP_utxoinfo A,B,*autxo,*butxo; cJSON *reqjson; char str[65]; struct LP_address_utxo *utxos[4096]; int32_t i,r,counter,max = (int32_t)(sizeof(utxos)/sizeof(*utxos));
    *newqp = *qp;
    qp = newqp;
//printf("bob %s received REQUEST.(%s)\n",bits256_str(str,G.LP_mypub25519),qp->uuidstr+32);
    if ( (coin= LP_coinfind(qp->srccoin)) == 0 || (othercoin= LP_coinfind(qp->destcoin)) == 0 )
        return(0);
    if ( (myprice= LP_trades_bobprice(&bid,&ask,qp)) == 0. )
    {
        printf("myprice %.8f bid %.8f ask %.8f\n",myprice,bid,ask);
        return(0);
    }
    autxo = &A;
    butxo = &B;
    memset(autxo,0,sizeof(*autxo));
    memset(butxo,0,sizeof(*butxo));
    LP_abutxo_set(autxo,butxo,qp);
    strcpy(qp->coinaddr,coin->smartaddr);
    if ( bits256_nonz(qp->srchash) == 0 || bits256_cmp(qp->srchash,G.LP_mypub25519) == 0 )
    {
        qprice = (double)qp->destsatoshis / (qp->satoshis - qp->txfee);
        strcpy(qp->gui,G.gui);
        if ( coin->etomic[0] != 0 )
            strcpy(qp->etomicsrc,coin->smartaddr);
        else if ( othercoin->etomic[0] != 0 )
            strcpy(qp->etomicsrc,othercoin->smartaddr);
        if ( coin->etomic[0] != 0 )//|| othercoin->etomic[0] != 0 )
        {
            struct iguana_info *ecoin;
            if ( (ecoin= LP_coinfind("ETOMIC")) != 0 )
                strcpy(qp->coinaddr,ecoin->smartaddr);
            else
            {
                printf("ETOMIC coin not found\n");
                return(0);
            }
        }
        strcpy(butxo->coinaddr,qp->coinaddr);
        qp->srchash = G.LP_mypub25519;
        memset(&qp->txid,0,sizeof(qp->txid));
        memset(&qp->txid2,0,sizeof(qp->txid2));
        qp->vout = qp->vout2 = -1;
    } else return(0);
    if ( qprice >= myprice )
    {
        r = (LP_rand() % 90) + 10;
        range = (qprice - myprice);
        price = myprice + ((r * range) / 100.);
        bestprice = LP_bob_competition(&counter,qp->aliceid,price,0);
        printf("%llu >>>>>>> myprice %.8f qprice %.8f r.%d range %.8f -> %.8f, bestprice %.8f counter.%d\n",(long long)qp->aliceid,myprice,qprice,r,range,price,bestprice,counter);
        if ( counter > 3 && price > bestprice+SMALLVAL ) // skip if late or bad price
            return(0);
    }
    else
    {
        //printf("ignore as qprice %.8f vs myprice %.8f\n",qprice,myprice);
        return(0);
    }
    //LP_RTmetrics_update(qp->srccoin,qp->destcoin);
    if ( LP_RTmetrics_blacklisted(qp->desthash) >= 0 )
    {
        printf("request from blacklisted %s, ignore\n",bits256_str(str,qp->desthash));
        return(0);
    }
    //printf("LP_address_utxo_reset.%s\n",coin->symbol);
    //LP_address_utxo_reset(coin);
    //printf("done LP_address_utxo_reset.%s\n",coin->symbol);
    if ( coin->etomic[0] != 0 )
        strcpy(qp->etomicsrc,coin->smartaddr);
    else if ( othercoin->etomic[0] != 0 )
        strcpy(qp->etomicsrc,othercoin->smartaddr);
    if ( coin->etomic[0] != 0 )//|| othercoin->etomic[0] != 0 )
    {
        struct iguana_info *ecoin;
        if ( (ecoin= LP_coinfind("ETOMIC")) != 0 )
            strcpy(qp->coinaddr,ecoin->smartaddr);
        else
        {
            printf("ETOMIC coin not found\n");
            return(0);
        }
    }
    i = 0;
    while ( i < 33 && price >= myprice )
    {
        if ( (butxo= LP_address_myutxopair(butxo,1,utxos,max,LP_coinfind(qp->srccoin),qp->coinaddr,qp->txfee,dstr(qp->destsatoshis),price,qp->desttxfee)) != 0 )
        {
            strcpy(qp->gui,G.gui);
            strcpy(qp->coinaddr,coin->smartaddr);
            qp->srchash = G.LP_mypub25519;
            qp->txid = butxo->payment.txid;
            qp->vout = butxo->payment.vout;
            qp->txid2 = butxo->deposit.txid;
            qp->vout2 = butxo->deposit.vout;
            qp->satoshis = butxo->swap_satoshis;// + qp->txfee;
            qp->quotetime = (uint32_t)time(NULL);
        }
        else
        {
            printf("i.%d cant find utxopair aliceid.%llu %s/%s %.8f -> relvol %.8f\n",i,(long long)qp->aliceid,qp->srccoin,qp->destcoin,dstr(LP_basesatoshis(dstr(qp->destsatoshis),price,qp->txfee,qp->desttxfee)),dstr(qp->destsatoshis));
            return(0);
        }
        if ( qp->satoshis <= qp->txfee )
            return(0);
        p = (double)qp->destsatoshis / (qp->satoshis - qp->txfee);
        if ( LP_trades_pricevalidate(qp,coin,p) < 0. )
            return(0);
        if ( i == 0 && p < myprice )
        {
            price = qprice;
            printf("reset price <- qprice %.8f\n",qprice);
        }
        else
        {
            if ( qprice >= p )
                break;
            price *= 0.995;
        }
        i++;
    }
    printf("%s/%s i.%d qprice %.8f myprice %.8f price %.8f [%.8f]\n",qp->srccoin,qp->destcoin,i,qprice,myprice,price,p);
    if ( LP_allocated(qp->txid,qp->vout) == 0 && LP_allocated(qp->txid2,qp->vout2) == 0 )
    {
        //printf("found unallocated txids\n");
        reqjson = LP_quotejson(qp);
        LP_unavailableset(qp->txid,qp->vout,qp->timestamp + LP_RESERVETIME,qp->desthash);
        LP_unavailableset(qp->txid2,qp->vout2,qp->timestamp + LP_RESERVETIME,qp->desthash);
        if ( qp->quotetime == 0 )
            qp->quotetime = (uint32_t)time(NULL);
        jaddnum(reqjson,"quotetime",qp->quotetime);
        jaddnum(reqjson,"pending",qp->timestamp + LP_RESERVETIME);
        jaddstr(reqjson,"method","reserved");
        LP_reserved_msg(1,qp->srccoin,qp->destcoin,qp->desthash,jprint(reqjson,0));
        bits256 zero;
        memset(zero.bytes,0,sizeof(zero));
        LP_reserved_msg(1,qp->srccoin,qp->destcoin,zero,jprint(reqjson,0));
        free_json(reqjson);
        //printf("Send RESERVED id.%llu\n",(long long)qp->aliceid);
        return(qp);
    } else printf("request processing selected ineligible utxos?\n");
    return(0);
}

struct LP_quoteinfo *LP_trades_gotreserved(void *ctx,struct LP_quoteinfo *qp,struct LP_quoteinfo *newqp)
{
    char *retstr; double qprice;
    //char str[65]; printf("alice %s received RESERVED.(%s) %.8f\n",bits256_str(str,G.LP_mypub25519),qp->uuidstr+32,(double)qp->destsatoshis/(qp->satoshis+1));
    *newqp = *qp;
    qp = newqp;
    if ( (qprice= LP_trades_alicevalidate(ctx,qp)) > 0. )
    {
        //printf("got qprice %.8f\n",qprice);
        LP_aliceid(qp->tradeid,qp->aliceid,"reserved",0,0);
        if ( (retstr= LP_quotereceived(qp)) != 0 )
            free(retstr);
        return(qp);
    } else LP_failedmsg(qp->R.requestid,qp->R.quoteid,qprice,qp->uuidstr);
    return(0);
}

struct LP_quoteinfo *LP_trades_gotconnect(void *ctx,struct LP_quoteinfo *qp,struct LP_quoteinfo *newqp,char *pairstr)
{
    double myprice,qprice,bid,ask; struct iguana_info *coin;
    *newqp = *qp;
    qp = newqp;
    if ( (coin= LP_coinfind(qp->srccoin)) == 0 )
       return(0);
    if ( (myprice= LP_trades_bobprice(&bid,&ask,qp)) == 0. )
        return(0);
    if ( (qprice= LP_trades_pricevalidate(qp,coin,myprice)) < 0. )
        return(0);
    if ( LP_reservation_check(qp->txid,qp->vout,qp->desthash) == 0 && LP_reservation_check(qp->txid2,qp->vout2,qp->desthash) == 0  )
    {
        char str[65]; printf("bob %s received CONNECT.(%s)\n",bits256_str(str,G.LP_mypub25519),qp->uuidstr+32);
        LP_connectstartbob(ctx,LP_mypubsock,qp->srccoin,qp->destcoin,qprice,qp);
        return(qp);
    }
    else
    {
        LP_failedmsg(qp->R.requestid,qp->R.quoteid,-1,qp->uuidstr);
        printf("connect message from non-reserved (%llu)\n",(long long)qp->aliceid);
    }
    return(0);
}

struct LP_quoteinfo *LP_trades_gotconnected(void *ctx,struct LP_quoteinfo *qp,struct LP_quoteinfo *newqp,char *pairstr)
{
    char *retstr; int32_t changed; double val;
    //char str[65]; printf("alice %s received CONNECTED.(%llu)\n",bits256_str(str,G.LP_mypub25519),(long long)qp->aliceid);
    *newqp = *qp;
    qp = newqp;
    if ( (val= LP_trades_alicevalidate(ctx,qp)) > 0. )
    {
        //printf("CONNECTED ALICE uuid.%s\n",qp->uuidstr);
        LP_aliceid(qp->tradeid,qp->aliceid,"connected",0,0);
        if ( (retstr= LP_connectedalice(qp,pairstr)) != 0 )
            free(retstr);
        LP_mypriceset(&changed,qp->destcoin,qp->srccoin,0.);
        LP_alicequery_clear();
        return(qp);
    } else LP_failedmsg(qp->R.requestid,qp->R.quoteid,val,qp->uuidstr);
    //printf("LP_trades_alicevalidate error\n");
    return(0);
}

int32_t LP_trades_bestpricecheck(void *ctx,struct LP_trade *tp)
{
    double qprice; int32_t flag = 0; struct LP_quoteinfo Q; int64_t dynamictrust; char *retstr; struct LP_pubkey_info *pubp;
    Q = tp->Q;
    //printf("check bestprice %.8f vs new price %.8f\n",tp->bestprice,(double)Q.destsatoshis/Q.satoshis);
    if ( Q.satoshis != 0 && (pubp= LP_pubkeyadd(Q.srchash)) != 0 )//(qprice= LP_trades_alicevalidate(ctx,&Q)) > 0. )
    {
        qprice = (double)Q.destsatoshis / (Q.satoshis - Q.txfee);
        LP_aliceid(Q.tradeid,tp->aliceid,"reserved",0,0);
        if ( (retstr= LP_quotereceived(&Q)) != 0 )
            free(retstr);
        //LP_trades_gotreserved(ctx,&Q,&tp->Qs[LP_RESERVED]);
        dynamictrust = LP_dynamictrust(Q.othercredits,Q.srchash,LP_kmdvalue(Q.srccoin,Q.satoshis));
        if ( tp->bestprice == 0. )
            flag = 1;
        else if ( qprice < tp->bestprice && pubp->slowresponse <= tp->bestresponse*1.05 )
            flag = 1;
        else if ( qprice < tp->bestprice*1.01 && dynamictrust > tp->besttrust && pubp->slowresponse <= tp->bestresponse*1.1 )
            flag = 1;
        else if ( qprice <= tp->bestprice && pubp->unconfcredits > tp->bestunconfcredits && pubp->slowresponse <= tp->bestresponse )
            flag = 1;
        if ( flag != 0 )
        {
            tp->Qs[LP_CONNECT] = tp->Q;
            tp->bestprice = qprice;
            tp->besttrust = dynamictrust;
            tp->bestunconfcredits = pubp->unconfcredits;
            tp->bestresponse = pubp->slowresponse;
            printf("aliceid.%llu got new bestprice %.8f dynamictrust %.8f (unconf %.8f) slowresponse.%d\n",(long long)tp->aliceid,tp->bestprice,dstr(dynamictrust),dstr(tp->bestunconfcredits),tp->bestresponse);
            return(qprice);
        } //else printf("qprice %.8f dynamictrust %.8f not good enough\n",qprice,dstr(dynamictrust));
    } else printf("alice didnt validate\n");
    return(0);
}

int32_t LP_trades_canceluuid(char *uuidstr)
{
    int32_t num = 0; struct LP_trade *qtp,*tp,*tmp;
    HASH_ITER(hh,LP_trades,tp,tmp)
    {
        if ( strcmp(tp->Q.uuidstr,uuidstr) == 0 )
        {
            tp->cancelled = (uint32_t)time(NULL);
            num++;
        }
    }
    DL_FOREACH_SAFE(LP_tradesQ,qtp,tmp)
    {
        if ( strcmp(qtp->Q.uuidstr,uuidstr) == 0 )
        {
            qtp->cancelled = (uint32_t)time(NULL);
            num++;
        }
    }
    if ( num > 0 )
        fprintf(stderr,"uuid.%s %d cancelled\n",uuidstr,num);
    return(num);
}

void LP_tradesloop(void *ctx)
{
    struct LP_trade *qtp,*tp,*tmp; struct LP_quoteinfo *qp,Q; uint32_t now; int32_t timeout,funcid,flag,nonz; struct iguana_info *coin; struct LP_pubkey_info *pubp;
    strcpy(LP_tradesloop_stats.name,"LP_tradesloop");
    LP_tradesloop_stats.threshold = 30000;
    sleep(5);
    while ( LP_STOP_RECEIVED == 0 )
    {
        LP_millistats_update(&LP_tradesloop_stats);
        nonz = 0;
        HASH_ITER(hh,LP_trades,tp,tmp)
        {
            if ( tp->negotiationdone != 0 || tp->cancelled != 0 )
                continue;
            //printf("check %s\n",tp->Q.uuidstr+32);
            timeout = LP_AUTOTRADE_TIMEOUT;
            if ( (coin= LP_coinfind(tp->Q.srccoin)) != 0 && coin->electrum != 0 )
                timeout += LP_AUTOTRADE_TIMEOUT * .5;
            if ( (coin= LP_coinfind(tp->Q.destcoin)) != 0 && coin->electrum != 0 )
                timeout += LP_AUTOTRADE_TIMEOUT * .5;
            now = (uint32_t)time(NULL);
            if ( now > tp->lastprocessed )
            {
                if ( tp->iambob == 0 )
                {
                    if ( tp->bestprice > 0. )
                    {
                        if ( tp->connectsent == 0 )
                        {
                            LP_Alicemaxprice = tp->bestprice;
                            LP_reserved(ctx,LP_myipaddr,LP_mypubsock,&tp->Qs[LP_CONNECT]); // send LP_CONNECT
                            tp->connectsent = now;
                            //printf("send LP_connect aliceid.%llu %.8f\n",(long long)tp->aliceid,tp->bestprice);
                        }
                        else if ( now < tp->firstprocessed+timeout && ((tp->firstprocessed - now) % 20) == 19 )
                        {
                            //LP_Alicemaxprice = tp->bestprice;
                            //LP_reserved(ctx,LP_myipaddr,LP_mypubsock,&tp->Qs[LP_CONNECT]); // send LP_CONNECT
                            //printf("mark slow LP_connect aliceid.%llu %.8f\n",(long long)tp->aliceid,tp->bestprice);
                            if ( (pubp= LP_pubkeyfind(tp->Qs[LP_CONNECT].srchash)) != 0 )
                                pubp->slowresponse++;
                        }
                    }
                }
            }
        }
        now = (uint32_t)time(NULL);
        HASH_ITER(hh,LP_trades,tp,tmp)
        {
            timeout = LP_AUTOTRADE_TIMEOUT;
            if ( (coin= LP_coinfind(tp->Q.srccoin)) != 0 && coin->electrum != 0 )
                timeout += LP_AUTOTRADE_TIMEOUT * .5;
            if ( (coin= LP_coinfind(tp->Q.destcoin)) != 0 && coin->electrum != 0 )
                timeout += LP_AUTOTRADE_TIMEOUT * .5;
            if ( now > tp->firstprocessed+timeout*10 || tp->cancelled != 0 )
            {
                //printf("purge swap aliceid.%llu\n",(long long)tp->aliceid);
                portable_mutex_lock(&LP_tradesmutex);
                HASH_DELETE(hh,LP_trades,tp);
                portable_mutex_unlock(&LP_tradesmutex);
                free(tp);
            }
        }
        DL_FOREACH_SAFE(LP_tradesQ,qtp,tmp)
        {
            now = (uint32_t)time(NULL);
            Q = qtp->Q;
            funcid = qtp->funcid;
//printf("dequeue %p funcid.%d aliceid.%llu iambob.%d\n",qtp,funcid,(long long)qtp->aliceid,qtp->iambob);
            portable_mutex_lock(&LP_tradesmutex);
            DL_DELETE(LP_tradesQ,qtp);
            HASH_FIND(hh,LP_trades,&qtp->aliceid,sizeof(qtp->aliceid),tp);
            if ( tp != 0 && tp->cancelled != 0 )
                
            {
                fprintf(stderr,"purging cancelled %s funcid.%d\n",tp->Q.uuidstr,tp->funcid);
                HASH_DELETE(hh,LP_trades,tp);
                free(tp);
                continue;
            }
            if ( tp == 0 )
            {
                if ( now > Q.timestamp+LP_AUTOTRADE_TIMEOUT*2 || qtp->cancelled != 0 ) // eat expired
                    free(qtp);
                else
                {
                    tp = qtp;
                    HASH_ADD(hh,LP_trades,aliceid,sizeof(tp->aliceid),tp);
                    portable_mutex_unlock(&LP_tradesmutex);
                    if ( tp->iambob != 0 && funcid == LP_REQUEST ) // bob maybe sends LP_RESERVED
                    {
                        if ( (qp= LP_trades_gotrequest(ctx,&Q,&tp->Qs[LP_REQUEST],tp->pairstr)) != 0 )
                            tp->Qs[LP_RESERVED] = Q;
                    }
                    else if ( tp->iambob == 0 && funcid == LP_RESERVED ) // alice maybe sends LP_CONNECT
                    {
                        LP_trades_bestpricecheck(ctx,tp);
                    }
                    else if ( tp->iambob == 0 && funcid == LP_CONNECTED )
                    {
                        tp->negotiationdone = now;
                        //printf("alice sets negotiationdone.%u\n",now);
                        LP_trades_gotconnected(ctx,&tp->Q,&tp->Qs[LP_CONNECTED],tp->pairstr);
                    }
                    nonz++;
                    tp->firstprocessed = tp->lastprocessed = (uint32_t)time(NULL);
                    if ( funcid == LP_CONNECT && tp->negotiationdone == 0 ) // bob all done
                    {
                        tp->negotiationdone = now;
                        //printf("bob sets negotiationdone.%u\n",now);
                        LP_trades_gotconnect(ctx,&tp->Q,&tp->Qs[LP_CONNECT],tp->pairstr);
                    }
                }
                continue;
            }
            portable_mutex_unlock(&LP_tradesmutex);
            tp->Q = qtp->Q;
            if ( qtp->iambob == tp->iambob && qtp->pairstr[0] != 0 )
                safecopy(tp->pairstr,qtp->pairstr,sizeof(tp->pairstr));
//printf("finished dequeue %p funcid.%d aliceid.%llu iambob.%d/%d done.%u\n",qtp,funcid,(long long)qtp->aliceid,qtp->iambob,tp->iambob,tp->negotiationdone);
            free(qtp);
            flag = 0;
            if ( tp->iambob == 0 )
            {
                if ( funcid == LP_RESERVED )
                {
                    if ( tp->connectsent == 0 )
                        flag = LP_trades_bestpricecheck(ctx,tp);
                }
                else if ( funcid == LP_CONNECTED && tp->negotiationdone == 0 ) // alice all done  tp->connectsent != 0 &&
                {
                    flag = 1;
                    tp->negotiationdone = now;
                    LP_trades_gotconnected(ctx,&tp->Q,&tp->Qs[LP_CONNECTED],tp->pairstr);
                }
            }
            else
            {
                if ( funcid == LP_REQUEST ) // bob maybe sends LP_RESERVED
                {
                    if ( (qp= LP_trades_gotrequest(ctx,&Q,&tp->Qs[LP_REQUEST],tp->pairstr)) != 0 )
                    {
                        tp->Qs[LP_RESERVED] = Q;
                        flag = 1;
                    }
                }
                else if ( funcid == LP_CONNECT && tp->negotiationdone == 0 ) // bob all done
                {
                    flag = 1;
                    tp->negotiationdone = now;
                    //printf("bob sets negotiationdone.%u\n",now);
                    LP_trades_gotconnect(ctx,&tp->Q,&tp->Qs[LP_CONNECT],tp->pairstr);
                }
            }
            if ( flag != 0 )
            {
                tp->lastprocessed = (uint32_t)time(NULL);
                nonz++;
            }
        }
        if ( nonz == 0 )
            sleep(1);
    }
}

void LP_tradecommandQ(struct LP_quoteinfo *qp,char *pairstr,int32_t funcid)
{
    struct LP_trade *qtp; uint64_t aliceid; int32_t iambob;
    if ( funcid < 0 || funcid >= sizeof(qtp->Qs)/sizeof(*qtp->Qs) )
        return;
    if ( funcid == LP_REQUEST || funcid == LP_CONNECT )
        iambob = 1;
    else iambob = 0;
    aliceid = qp->aliceid;
    portable_mutex_lock(&LP_tradesmutex);
    qtp = calloc(1,sizeof(*qtp));
    qtp->funcid = funcid;
    qtp->iambob = iambob;
    qtp->aliceid = aliceid;
    qtp->newtime = (uint32_t)time(NULL);
    qtp->Q = *qp;
    if ( pairstr != 0 )
        safecopy(qtp->pairstr,pairstr,sizeof(qtp->pairstr));
    DL_APPEND(LP_tradesQ,qtp);
    portable_mutex_unlock(&LP_tradesmutex);
    //printf("queue.%d uuid.(%s)\n",funcid,qtp->Q.uuidstr);
}

int32_t LP_tradecommand(void *ctx,char *myipaddr,int32_t pubsock,cJSON *argjson,uint8_t *data,int32_t datalen)
{
    int32_t Qtrades = 1;
    char *method,str[65]; int32_t i,num,DEXselector = 0; uint64_t aliceid; double qprice,bestprice,price,bid,ask; cJSON *proof; uint64_t rq; struct iguana_info *coin; struct LP_quoteinfo Q,Q2; int32_t counter,retval=-1;
    if ( (method= jstr(argjson,"method")) != 0 && (strcmp(method,"reserved") == 0 ||strcmp(method,"connected") == 0 || strcmp(method,"request") == 0 || strcmp(method,"connect") == 0) )
    {
        if ( LP_quoteparse(&Q,argjson) < 0 )
        {
            printf("ERROR parsing.(%s)\n",jprint(argjson,0));
            return(1);
        }
        if ( Q.satoshis < Q.txfee )
            return(1);
        LP_requestinit(&Q.R,Q.srchash,Q.desthash,Q.srccoin,Q.satoshis-Q.txfee,Q.destcoin,Q.destsatoshis-Q.desttxfee,Q.timestamp,Q.quotetime,DEXselector);
        rq = ((uint64_t)Q.R.requestid << 32) | Q.R.quoteid;
        if ( Q.uuidstr[0] == 0 || (Q.timestamp > 0 && time(NULL) > Q.timestamp + LP_AUTOTRADE_TIMEOUT*20) ) // eat expired packets, some old timestamps floating about?
        {
            printf("uuid.%s aliceid.%llu is expired by %d\n",Q.uuidstr+32,(long long)Q.aliceid,(uint32_t)time(NULL) - (Q.timestamp + LP_AUTOTRADE_TIMEOUT*20));
            return(1);
        }
        LP_tradecommand_log(argjson);
        qprice = (double)Q.destsatoshis / (Q.satoshis - Q.txfee); //jdouble(argjson,"price");
        //printf("%s\n",jprint(argjson,0));
        printf("%-4d uuid.%32s %12s %5s/%-5s %12.8f -> %12.8f (%11.8f) | RT.%d %d n%d\n",(uint32_t)time(NULL) % 3600,Q.uuidstr+32,method,Q.srccoin,Q.destcoin,dstr(Q.satoshis),dstr(Q.destsatoshis),qprice,LP_RTcount,LP_swapscount,G.netid);
        retval = 1;
        aliceid = j64bits(argjson,"aliceid");
        if ( strcmp(method,"reserved") == 0 )
        {
            bestprice = LP_bob_competition(&counter,aliceid,qprice,1);
            //printf("%s lag %ld: aliceid.%llu price %.8f -> bestprice %.8f Alice max %.8f\n",jprint(argjson,0),Q.quotetime - (time(NULL)-20),(long long)aliceid,qprice,bestprice,LP_Alicemaxprice);
            if ( 1 )
            {
                if ( LP_Alicemaxprice == 0. )
                    return(retval);
                if ( bits256_nonz(LP_Alicedestpubkey) != 0 )
                {
                    if (bits256_cmp(LP_Alicedestpubkey,Q.srchash) != 0 )
                    {
                        printf("got reserved response from different node %s\n",bits256_str(str,Q.srchash));
                        return(retval);
                    } else printf("got reserved response from destpubkey %s\n",bits256_str(str,Q.srchash));
                }
            }
            if ( bits256_cmp(G.LP_mypub25519,Q.desthash) == 0 && bits256_cmp(G.LP_mypub25519,Q.srchash) != 0 && (Q.vout != Q.vout2 || bits256_cmp(Q.txid,Q.txid2) != 0) ) // alice
            {
                if ( Qtrades == 0 )
                {
                    if ( Q.quotetime > time(NULL)-20 && LP_alice_eligible(Q.quotetime) > 0 )
                    {
                        LP_trades_gotreserved(ctx,&Q,&Q2);
                        if ( LP_quotecmp(0,&Q,&LP_Alicequery) == 0 )
                            LP_reserved(ctx,LP_myipaddr,LP_mypubsock,&Q);
                    }
                } else LP_tradecommandQ(&Q,jstr(argjson,"pair"),LP_RESERVED);
            }
        }
        else if ( strcmp(method,"connected") == 0 )
        {
            bestprice = LP_bob_competition(&counter,aliceid,qprice,1000);
            if ( bits256_cmp(G.LP_mypub25519,Q.desthash) == 0 && bits256_cmp(G.LP_mypub25519,Q.srchash) != 0 ) // alice
            {
                static uint64_t rqs[1024];
                for (i=0; i<sizeof(rqs)/sizeof(*rqs); i++)
                    if ( rq == rqs[i] )
                        return(retval);
                for (i=0; i<sizeof(rqs)/sizeof(*rqs); i++)
                    if ( rqs[i] == 0 )
                        break;
                if ( i == sizeof(rqs)/sizeof(*rqs) )
                    i = (rand() % (sizeof(rqs)/sizeof(*rqs)));
                rqs[i] = rq;
//printf("CONNECTED.(%s)\n",jprint(argjson,0));
                if ( (proof= jarray(&num,argjson,"proof")) != 0 && num > 0 )
                    Q.othercredits = LP_instantdex_proofcheck(Q.srccoin,Q.coinaddr,proof,num);
                if ( Qtrades == 0 )
                    LP_trades_gotconnected(ctx,&Q,&Q2,jstr(argjson,"pair"));
                else LP_tradecommandQ(&Q,jstr(argjson,"pair"),LP_CONNECTED);
            }
        }
        price = LP_myprice(&bid,&ask,Q.srccoin,Q.destcoin);
        if ( (coin= LP_coinfind(Q.srccoin)) == 0 || coin->inactive != 0 )
        {
            //printf("%s is not active\n",Q.srccoin);
            return(retval);
        }
        if ( price <= SMALLVAL || ask <= SMALLVAL )
        {
            //printf("this node has no price for %s/%s\n",Q.srccoin,Q.destcoin);
            return(retval);
        }
        if ( LP_aliceonly(Q.srccoin) > 0 )
        {
            printf("{\"error\":\"GAME can only be alice coin\"}\n");
            return(retval);
        }
        if ( strcmp(method,"request") == 0 ) // bob
        {
            //if ( LP_Alicemaxprice != 0. )
            //    return(retval);
            if ( Q.destvout != Q.feevout || bits256_cmp(Q.desttxid,Q.feetxid) != 0 )
            {
                bestprice = LP_bob_competition(&counter,aliceid,qprice,-1);
                if ( Qtrades == 0 )//|| (bits256_cmp(Q.srchash,G.LP_mypub25519) == 0 && bits256_cmp(G.LP_mypub25519,Q.desthash) != 0) )
                    LP_trades_gotrequest(ctx,&Q,&Q2,jstr(argjson,"pair"));
                else LP_tradecommandQ(&Q,jstr(argjson,"pair"),LP_REQUEST);
            }
        }
        else if ( strcmp(method,"connect") == 0 )
        {
            LP_bob_competition(&counter,aliceid,qprice,1000);
            if ( bits256_cmp(G.LP_mypub25519,Q.srchash) == 0 && bits256_cmp(G.LP_mypub25519,Q.desthash) != 0 ) // bob
            {
                static uint64_t rqs[1024];
                for (i=0; i<sizeof(rqs)/sizeof(*rqs); i++)
                    if ( rq == rqs[i] )
                        return(retval);
                for (i=0; i<sizeof(rqs)/sizeof(*rqs); i++)
                    if ( rqs[i] == 0 )
                        break;
                if ( i == sizeof(rqs)/sizeof(*rqs) )
                    i = (rand() % (sizeof(rqs)/sizeof(*rqs)));
                rqs[i] = rq;
                //printf("CONNECT.(%s)\n",jprint(argjson,0));
                if ( (proof= jarray(&num,argjson,"proof")) != 0 && num > 0 )
                    Q.othercredits = LP_instantdex_proofcheck(Q.destcoin,Q.destaddr,proof,num);
                if ( Qtrades == 0 )
                    LP_trades_gotconnect(ctx,&Q,&Q2,jstr(argjson,"pair"));
                else LP_tradecommandQ(&Q,jstr(argjson,"pair"),LP_CONNECT);
            }
        }
        return(retval);
    }
    return(retval);
}

char *LP_autobuy(void *ctx,int32_t fomoflag,char *myipaddr,int32_t mypubsock,char *base,char *rel,double maxprice,double relvolume,int32_t timeout,int32_t duration,char *gui,uint32_t nonce,bits256 destpubkey,uint32_t tradeid,char *uuidstr)
{
    uint64_t desttxfee,txfee,balance; uint32_t lastnonce; int64_t bestsatoshis=0,destsatoshis; struct iguana_info *basecoin,*relcoin; struct LP_utxoinfo *autxo,B,A; struct LP_quoteinfo Q; bits256 pubkeys[100]; struct LP_address_utxo *utxos[4096]; int32_t num=0,maxiters=100,i,max=(int32_t)(sizeof(utxos)/sizeof(*utxos)); char _uuidstr[65];
    basecoin = LP_coinfind(base);
    relcoin = LP_coinfind(rel);
    if ( gui == 0 )
        gui = "nogui";
    if ( basecoin == 0 || basecoin->inactive != 0 || relcoin == 0 || relcoin->inactive != 0 )
        return(clonestr("{\"error\":\"base or rel not found or inactive\"}"));
    if ( LP_aliceonly(base) > 0 )
        return(clonestr("{\"error\":\"GAME can only be alice coin\"}"));
    printf("LP_autobuy %s/%s price %.8f vol %.8f nonce %u\n",base,rel,maxprice,relvolume,nonce);
    if ( (lastnonce= LP_lastnonce) != 0 && nonce <= lastnonce )
    {
        printf("nonce.%u not bigger than lastnonce.%u\n",nonce,lastnonce);
        return(clonestr("{\"error\":\"invalid nonce\"}"));
    }
    LP_lastnonce = nonce;
    if ( duration <= 0 )
        duration = LP_ORDERBOOK_DURATION;
    if ( timeout <= 0 )
        timeout = LP_AUTOTRADE_TIMEOUT;
    if ( basecoin->electrum != 0 && relcoin->electrum != 0 )
    {
        if ( timeout < 2*LP_AUTOTRADE_TIMEOUT )
            timeout = 2*LP_AUTOTRADE_TIMEOUT;
    }
    else if ( basecoin->electrum != 0 || relcoin->electrum != 0 )
    {
        if ( timeout < 1.5*LP_AUTOTRADE_TIMEOUT )
            timeout = 1.5*LP_AUTOTRADE_TIMEOUT;
    }
    if ( time(NULL) < Alice_expiration )
    {
        cJSON *retjson = cJSON_CreateObject();
        jaddstr(retjson,"error","only one pending request at a time");
        jaddnum(retjson,"wait",Alice_expiration-time(NULL));
        return(jprint(retjson,1));
    } else LP_alicequery_clear();
    if ( relcoin->etomic[0] != 0 )
        LP_address_utxo_reset(&num,LP_coinfind("ETOMIC"));
    else
    {
        LP_address_utxo_reset(&num,relcoin);
        if ( num <= 1 )
        {
            if ( time(NULL) > relcoin->lastautosplit+300 )
            {
                relcoin->lastautosplit = (uint32_t)time(NULL);
                return(LP_autosplit(relcoin));
            }
            return(clonestr("{\"error\":\"not enough utxo, please make more deposits\"}"));
        }
    }
    LP_txfees(&txfee,&desttxfee,base,rel);
    if ( txfee != 0 && txfee < 10000 )
        txfee = 10000;
    if ( desttxfee != 0 && desttxfee < 10000 )
        desttxfee = 10000;
    if ( fomoflag != 0 )
    {
        uint64_t median,minutxo,maxutxo;
        maxprice = 0.; // fomo -> price is 1. and needs to be set
        LP_address_minmax(0,&median,&minutxo,&maxutxo,relcoin,relcoin->smartaddr); // limit to largest utxo
        if ( maxutxo > 0 )
        {
            relvolume = MIN(relvolume,dstr(maxutxo) - dstr(desttxfee)*3);
            printf("maxutxo %.8f relvolume %.8f desttxfee %.8f\n",dstr(maxutxo),relvolume,dstr(desttxfee));
            maxprice = LP_fomoprice(base,rel,&relvolume);
            printf("fomoprice %.8f relvolume %.8f\n",maxprice,relvolume);
            if ( maxprice == 0. )
                return(clonestr("{\"error\":\"no orderbook entry found to handle request\"}"));
        } else printf("no utxo available\n");
    }
    if ( maxprice <= 0. || relvolume <= 0. || LP_priceinfofind(base) == 0 || LP_priceinfofind(rel) == 0 )
        return(clonestr("{\"error\":\"invalid parameter\"}"));
    if ( strcmp("BTC",rel) == 0 )
        maxprice *= 1.01;
    else maxprice *= 1.001;
    memset(pubkeys,0,sizeof(pubkeys));
    destsatoshis = SATOSHIDEN * relvolume + 2*desttxfee;
    autxo = 0;
    for (i=0; i<maxiters; i++)
    {
        memset(&A,0,sizeof(A));
        if ( (autxo= LP_address_myutxopair(&A,0,utxos,max,relcoin,relcoin->smartaddr,txfee,dstr(destsatoshis),maxprice,desttxfee)) != 0 )
            break;
        destsatoshis *= 0.98;
        if ( destsatoshis < desttxfee*LP_MINSIZE_TXFEEMULT )
            break;
    }
    if ( destsatoshis < desttxfee*LP_MINSIZE_TXFEEMULT || i == maxiters )
    {
        return(clonestr("{\"error\":\"cant find a deposit that is close enough in size. make another deposit that is just a bit larger than what you want to trade\"}"));
    }
    printf("bestfit.[%d] selected alice (%.8f %.8f) for %.8f sats %.8f\n",i,dstr(autxo->payment.value),dstr(autxo->fee.value),dstr(destsatoshis),dstr(autxo->swap_satoshis));
    if ( destsatoshis - desttxfee < autxo->swap_satoshis )
    {
        destsatoshis -= desttxfee;
        autxo->swap_satoshis = destsatoshis;
        //printf("first path dest %.8f from %.8f\n",dstr(destsatoshis),dstr(autxo->swap_satoshis));
    }
    else if ( autxo->swap_satoshis - desttxfee < destsatoshis )
    {
        autxo->swap_satoshis -= desttxfee;
        destsatoshis = autxo->swap_satoshis;
        printf("second path dest %.8f from %.8f\n",dstr(destsatoshis),dstr(autxo->swap_satoshis));
    }
    if ( destsatoshis < (autxo->payment.value / LP_MINCLIENTVOL) || autxo->payment.value < desttxfee*LP_MINSIZE_TXFEEMULT )
    {
        printf("destsatoshis %.8f vs utxo %.8f this would have triggered an quote error -13\n",dstr(destsatoshis),dstr(autxo->payment.value));
        return(clonestr("{\"error\":\"cant find a deposit that is close enough in size. make another deposit that is a bit larger than what you want to trade\"}"));
    }
    bestsatoshis = 1.001 * LP_basesatoshis(dstr(destsatoshis),maxprice,txfee,desttxfee);
    memset(&B,0,sizeof(B));
    strcpy(B.coin,base);
    if ( LP_quoteinfoinit(&Q,&B,rel,maxprice,bestsatoshis,destsatoshis) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote\"}"));
    if ( LP_quotedestinfo(&Q,autxo->payment.txid,autxo->payment.vout,autxo->fee.txid,autxo->fee.vout,G.LP_mypub25519,autxo->coinaddr) < 0 )
        return(clonestr("{\"error\":\"cant set ordermatch quote info\"}"));
    if ( relcoin->etomic[0] != 0 || basecoin->etomic[0] != 0 )
    {
        struct iguana_info *coin;
        if ( relcoin->etomic[0] != 0 )
            strcpy(Q.etomicdest,relcoin->smartaddr);
        else if (basecoin->etomic[0] != 0 )
        {
            strcpy(Q.etomicdest,basecoin->smartaddr);
            //printf("Q.etomicdest (%s)\n",Q.etomicdest);
        }
        if ( relcoin->etomic[0] != 0 )
        {
            if ((coin= LP_coinfind("ETOMIC")) != 0 )
                strcpy(Q.destaddr,coin->smartaddr);
            else return(clonestr("{\"error\":\"cant find ETOMIC\"}"));
        }
    }
    int32_t changed;
    LP_mypriceset(&changed,rel,base,1. / maxprice);
    LP_mypriceset(&changed,base,rel,0.);
    if ( uuidstr == 0 || uuidstr[0] == 0 )
    {
        uint8_t uuidhash[256]; bits256 hash; uint64_t millis; int32_t len = 0;
        memcpy(uuidhash,&G.LP_mypub25519,sizeof(bits256)), len += sizeof(bits256);
        millis = OS_milliseconds();
        memcpy(&uuidhash[len],&millis,sizeof(millis)), len += sizeof(millis);
        memcpy(&uuidhash[len],base,(int32_t)strlen(base)), len += (int32_t)strlen(base);
        memcpy(&uuidhash[len],rel,(int32_t)strlen(rel)), len += (int32_t)strlen(rel);
        vcalc_sha256(0,hash.bytes,uuidhash,len);
        uuidstr = _uuidstr;
        bits256_str(uuidstr,hash);
        //char str[65]; printf("%s %llu %s %s -> uuid.%s\n",bits256_str(str,G.LP_mypub25519),(long long)millis,base,rel,uuidstr);
    }
    return(LP_trade(ctx,myipaddr,mypubsock,&Q,maxprice,timeout,duration,tradeid,destpubkey,uuidstr));
}


