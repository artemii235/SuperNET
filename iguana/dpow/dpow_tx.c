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

#define DPOW_BLACKLIST -100000

void dpow_bestmask_update(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,uint8_t nn_senderind,int8_t nn_bestk,uint64_t nn_bestmask,uint64_t nn_recvmask)
{
    int32_t startscore;
    if ( nn_senderind < 0 || nn_senderind >= bp->numnotaries )
        return;
    bp->notaries[nn_senderind].bestk = nn_bestk;
    bp->notaries[nn_senderind].bestmask = nn_bestmask;
    bp->notaries[nn_senderind].recvmask |= nn_recvmask;
    startscore = bp->scores[nn_senderind];
    if ( bp->bestk >= 0 )
    {
        if ( nn_bestk < 0 )
            bp->scores[nn_senderind] -= 10;
        else if ( nn_bestk != bp->bestk )
            bp->scores[nn_senderind]--;
        else if ( nn_bestmask != bp->bestmask )
            bp->scores[nn_senderind]--;
        else if ( bp->scores[nn_senderind] < 1 )
            bp->scores[nn_senderind] = 1;
        else bp->scores[nn_senderind]++;
        if ( startscore > DPOW_BLACKLIST && bp->scores[nn_senderind] <= DPOW_BLACKLIST )
            printf(">>>>>>>>>>>>> nn_senderind.%d %llx MIA, skip this node for now\n",nn_senderind,(long long)(1LL << nn_senderind));
    }
}

uint64_t dpow_lastk_mask(struct dpow_block *bp,int8_t *lastkp)
{
    int32_t j,m,k; uint64_t mask = bp->require0;
    *lastkp = -1;
    m = bp->require0;
    for (j=0; j<bp->numnotaries; j++)
    {
        k = DPOW_MODIND(bp,j);
        if ( (bp->require0 == 0 || k != 0) && bp->scores[k] < DPOW_BLACKLIST )
            continue;
        if ( bits256_nonz(bp->notaries[k].src.prev_hash) != 0 && bits256_nonz(bp->notaries[k].dest.prev_hash) != 0 )
        {
            bp->recvmask |= (1LL << k);
            mask |= (1LL << k);
            if ( ++m == bp->minsigs )
            {
                *lastkp = k;
                break;
            }
        }
    }
    return(mask);
}

int32_t dpow_bestk(struct dpow_block *bp,uint64_t *maskp)
{
    int8_t lastk; uint64_t mask;
    *maskp = 0;
    mask = dpow_lastk_mask(bp,&lastk);
    if ( lastk < 0 )
        return(-1);
    *maskp = mask;
    return(lastk);
}

uint64_t dpow_ratifybest(uint64_t refmask,struct dpow_block *bp,int8_t *lastkp)
{
    int32_t m,j,k; uint64_t bestmask,mask = bp->require0;
    bestmask = 0;
    *lastkp = -1;
    for (m=j=0; j<bp->numnotaries; j++)
    {
        k = (j + ((uint32_t)time(NULL) / DPOW_EPOCHDURATION)) % bp->numnotaries;//DPOW_MODIND(bp,j);
        if ( bp->require0 != 0 && k == 0 )
            continue;
        if ( bits256_nonz(bp->notaries[k].ratifysrcutxo) != 0 && bits256_nonz(bp->notaries[k].ratifydestutxo) != 0 )
        {
            mask |= (1LL << k);
            if ( ++m == bp->minsigs-bp->require0 )
            {
                *lastkp = k;
                bestmask = mask | bp->require0;
                //printf("m.%d == minsigs.%d (%d %llx)\n",m,bp->minsigs,k,(long long)bestmask);
            }
        }
    }
    return(bestmask);
}

uint64_t dpow_notarybestk(uint64_t refmask,struct dpow_block *bp,int8_t *lastkp)
{
    int32_t m,j,k,z,n; int8_t bestk = -1; uint64_t bestmask,mask = 0;//bp->require0;
    bestmask = 0;
    for (m=j=0; j<bp->numnotaries; j++)
    {
        //k = (j + ((uint32_t)time(NULL) / 180)) % bp->numnotaries;
        k = (j + (bp->height/DPOW_CHECKPOINTFREQ)) % bp->numnotaries;
        //if ( bp->require0 != 0 && k == 0 )
        //    continue;
        if ( bits256_nonz(bp->notaries[k].src.prev_hash) != 0 && bits256_nonz(bp->notaries[k].dest.prev_hash) != 0 && bp->paxwdcrc == bp->notaries[k].paxwdcrc )
        {
            for (z=n=0; z<bp->numnotaries; z++)
                if ( (bp->notaries[z].recvmask & (1LL << k)) != 0 )
                    n++;
            if ( n >= bp->numnotaries/2 )
            {
                mask |= (1LL << k);
                if ( ++m == bp->minsigs )//-bp->require0 )
                {
                    bestk = k;
                    bestmask = mask;// | bp->require0;
                    //printf("m.%d == minsigs.%d (%d %llx)\n",m,bp->minsigs,k,(long long)bestmask);
                }
            }
        }
    }
    if ( bestk >= 0 )
        *lastkp = bestk;
    return(bestmask);
}

uint64_t dpow_maskmin(uint64_t refmask,struct dpow_block *bp,int8_t *lastkp)
{
    int32_t j,m,k; uint64_t bestmask,mask = 0;//bp->require0;
    bestmask = 0;
    *lastkp = -1;
    m = 0;//bp->require0;
    for (j=0; j<bp->numnotaries; j++)
    {
        k = DPOW_MODIND(bp,j);
        //if ( (bp->require0 == 0 || k != 0) && bp->scores[k] < DPOW_BLACKLIST )
        //    continue;
        if ( bits256_nonz(bp->notaries[k].src.prev_hash) != 0 && bits256_nonz(bp->notaries[k].dest.prev_hash) != 0 && bp->paxwdcrc == bp->notaries[k].paxwdcrc )
        {
            mask |= (1LL << k);
            if ( ++m == bp->minsigs )
            {
                *lastkp = k;
                bestmask = mask;
            }
        }
    }
    bp->recvmask |= mask;
    if ( *lastkp >= 0 )
    {
        for (mask=j=0; j<bp->numnotaries; j++)
        {
            if ( bp->notaries[j].src.siglens[*lastkp] > 0 )
                mask |= (1LL << j);
        }
        bp->srcsigsmasks[*lastkp] |= mask;
        for (mask=j=0; j<bp->numnotaries; j++)
        {
            if ( bp->notaries[j].dest.siglens[*lastkp] > 0 )
                mask |= (1LL << j);
        }
        bp->destsigsmasks[*lastkp] |= mask;
   }
    return(bestmask);
}

struct dpow_block *dpow_heightfind(struct supernet_info *myinfo,struct dpow_info *dp,int32_t height)
{
    int32_t r,h,incr = 100000; struct dpow_block *bp = 0;
    if ( height > dp->maxblocks )
    {
        if ( dp->maxblocks+incr < height+10000 )
            incr = (height+10000) - dp->maxblocks;
        dp->blocks = realloc(dp->blocks,sizeof(*dp->blocks) * (dp->maxblocks + incr));
        memset(&dp->blocks[dp->maxblocks],0,sizeof(*dp->blocks) * incr);
        dp->maxblocks += incr;
    }
    if ( height < dp->maxblocks )
        bp = dp->blocks!=0 ? dp->blocks[height] : 0;
    if ( bp == 0 && height < DPOW_FIRSTRATIFY )
    {
        r = (rand() % DPOW_FIRSTRATIFY);
        for (h=0; h<DPOW_FIRSTRATIFY; h++)
        {
            height = (r + h) % DPOW_FIRSTRATIFY;
            if ( (bp= dp->blocks[height]) != 0 )
                return(bp);
        }
    }
    if ( bp != 0 && bp->state == 0xffffffff )
        bp = 0;
    return(bp);
}

int32_t dpow_voutstandard(struct supernet_info *myinfo,struct dpow_block *bp,uint8_t *serialized,int32_t m,int32_t src_or_dest,uint8_t pubkeys[][33],int32_t numratified)
{
    uint32_t paxwdcrc=0,locktime=0,numvouts; struct iguana_info *coin; uint64_t satoshis,satoshisB; int32_t i,n=0,opretlen,len=0; uint8_t opret[16384],data[16384],extras[16384];
    numvouts = 2;
    if ( pubkeys == 0 || numratified <= 0 )
    {
        if ( src_or_dest != 0 )
            coin = bp->destcoin;
        else coin = bp->srccoin;
        satoshis = DPOW_UTXOSIZE * m * .76;
        if ( (satoshisB= DPOW_UTXOSIZE * m - 10000) < satoshis )
            satoshis = satoshisB;
    }
    else
    {
        satoshis = DPOW_MINOUTPUT;
        numvouts += numratified;
    }
    len += iguana_rwvarint32(1,&serialized[len],&numvouts);
    len += iguana_rwnum(1,&serialized[len],sizeof(satoshis),&satoshis);
    serialized[len++] = 35;
    serialized[len++] = 33;
    decode_hex(&serialized[len],33,CRYPTO777_PUBSECPSTR), len += 33;
    serialized[len++] = CHECKSIG;
    if ( pubkeys != 0 && numratified != 0 )
    {
        satoshis = DPOW_MINOUTPUT;
        for (i=0; i<numratified; i++)
        {
            len += iguana_rwnum(1,&serialized[len],sizeof(satoshis),&satoshis);
            serialized[len++] = 35;
            serialized[len++] = 33;
            memcpy(&serialized[len],pubkeys[i],33), len += 33;
            serialized[len++] = CHECKSIG;
        }
        printf("numvouts.%d len.%d RATIFY vouts\n",numvouts,len);
    }
    if ( bp->MoMdepth > 0 && strcmp(bp->destcoin->symbol,"KMD") == 0 ) // || strcmp(bp->srccoin->symbol,"KMD") == 0) )
    {
        n = dpow_paxpending(myinfo,extras,sizeof(extras),&paxwdcrc,bp->MoM,bp->MoMdepth,bp->CCid,src_or_dest,bp);
    }
    satoshis = 0;
    len += iguana_rwnum(1,&serialized[len],sizeof(satoshis),&satoshis);
    if ( bp->isratify != 0 )
        opretlen = dpow_rwopret(1,opret,&bp->hashmsg,&bp->height,bp->srccoin->symbol,0,0,bp,src_or_dest);
    else opretlen = dpow_rwopret(1,opret,&bp->hashmsg,&bp->height,bp->srccoin->symbol,extras,n,bp,src_or_dest);
    if ( opretlen < 0 )
    {
        printf("negative opretlen.%d src_or_dest.%d\n",opretlen,src_or_dest);
        return(-1);
    }
    opretlen = dpow_opreturnscript(data,opret,opretlen);
    if ( opretlen < 0xfd )
        serialized[len++] = opretlen;
    else
    {
        serialized[len++] = 0xfd;
        serialized[len++] = opretlen & 0xff;
        serialized[len++] = (opretlen >> 8) & 0xff;
    }
    memcpy(&serialized[len],data,opretlen), len += opretlen;
    len += iguana_rwnum(1,&serialized[len],sizeof(locktime),&locktime);
    return(len);
}

bits256 dpow_notarytx(struct supernet_info *myinfo,char *signedtx,int32_t *numsigsp,int32_t isPoS,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,int32_t usesigs,int32_t src_or_dest,uint8_t pubkeys[][33],int32_t numratified)
{
    uint32_t k,m,numsigs,version,vout,crcval,sequenceid = 0xffffffff; bits256 zero; int32_t n,siglen,len; uint8_t serialized[32768],*sig; bits256 txid; struct dpow_entry *ep; struct dpow_coinentry *cp;
    signedtx[0] = 0;
    *numsigsp = 0;
    memset(zero.bytes,0,sizeof(zero));
    len = numsigs = 0;
    version = 1;
    len += iguana_rwnum(1,&serialized[len],sizeof(version),&version);
    if ( isPoS != 0 )
        len += iguana_rwnum(1,&serialized[len],sizeof(bp->timestamp),&bp->timestamp);
    m = bp->minsigs;
    len += iguana_rwvarint32(1,&serialized[len],(uint32_t *)&m);
    for (k=m=0; k<bp->numnotaries; k++)
    {
        siglen = 0;
        sig = 0;
        if ( ((1LL << k) & bestmask) != 0 )
        {
            if ( pubkeys != 0 && numratified > 0 )
            {
                if ( src_or_dest != 0 )
                {
                    txid = bp->notaries[k].ratifydestutxo;
                    vout = bp->notaries[k].ratifydestvout;
                }
                else
                {
                    txid = bp->notaries[k].ratifysrcutxo;
                    vout = bp->notaries[k].ratifysrcvout;
                }
                if ( bestk >= 0 )
                {
                    siglen = bp->notaries[k].ratifysiglens[src_or_dest];
                    sig = bp->notaries[k].ratifysigs[src_or_dest];
                }
                //char str[65]; printf("j.%d k.%d m.%d vin.(%s) v%d siglen.%d\n",j,k,m,bits256_str(str,txid),vout,siglen);
            }
            else
            {
                ep = &bp->notaries[k];
                cp = (src_or_dest != 0) ? &bp->notaries[k].dest : &bp->notaries[k].src;
                if ( bits256_nonz(cp->prev_hash) == 0 )
                {
                    printf("null prevhash k.%d m.%d src_or_dest.%d\n",k,m,src_or_dest);
                    return(zero);
                }
                txid = cp->prev_hash;
                vout = cp->prev_vout;
                if ( bestk >= 0 )
                {
                    siglen = cp->siglens[bestk];
                    sig = cp->sigs[bestk];
                }
            }
            len += iguana_rwbignum(1,&serialized[len],sizeof(txid),txid.bytes);
            len += iguana_rwnum(1,&serialized[len],sizeof(vout),&vout);
            if ( usesigs != 0 && bestk >= 0 )
            {
                len += iguana_rwvarint32(1,&serialized[len],(uint32_t *)&siglen);
                if ( siglen > 0 && siglen <= sizeof(cp->sigs[bestk]) )
                {
                    memcpy(&serialized[len],sig,siglen);
                    len += siglen;
                    numsigs++;
                } else printf("Missing sig from k.%d\n",k);
            } else serialized[len++] = 0;
            len += iguana_rwnum(1,&serialized[len],sizeof(sequenceid),&sequenceid);
            //printf("height.%d mod.%d VINI.%d <- i.%d j.%d\n",height,height % numnotaries,m,i,j);
            m++;
            if ( m == bp->minsigs )//&& k == bestk )
                break;
        }
    }
    if ( (n= dpow_voutstandard(myinfo,bp,&serialized[len],m,src_or_dest,pubkeys,numratified)) < 0 )
    {
        printf("error dpow_voutstandard m.%d src_or_dest.%d\n",m,src_or_dest);
        return(zero);
    }
    len += n;
    init_hexbytes_noT(signedtx,serialized,len);
    //printf("notarytx.(%s) opretlen.%d\n",signedtx,opretlen);
    if ( usesigs == 0 && bestk >= 0 )
    {
        crcval = calc_crc32(0,bp->ratifyrawtx[src_or_dest],bp->rawratifiedlens[src_or_dest]);
        if ( crcval != bp->pendingcrcs[src_or_dest] )
        {
            printf("new crcval.[%d] %x != %x\n",src_or_dest,crcval,bp->pendingcrcs[src_or_dest]);
            bp->pendingcrcs[src_or_dest] = crcval;
        }
        bp->notaries[bp->myind].pendingcrcs[src_or_dest] = bp->pendingcrcs[src_or_dest];
    }
    *numsigsp = numsigs;
    return(bits256_doublesha256(0,serialized,len));
}

cJSON *dpow_vins(struct iguana_info *coin,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,int32_t usesigs,int32_t src_or_dest,int32_t useratified)
{
    int32_t k,m; bits256 txid; uint16_t vout; uint8_t script[35]; char scriptstr[256]; cJSON *vins=0,*item; struct dpow_entry *ep; struct dpow_coinentry *cp;
    vins = cJSON_CreateArray();
    for (m=k=0; k<bp->numnotaries; k++)
    {
        if ( ((1LL << k) & bestmask) != 0 )
        {
            ep = &bp->notaries[k];
            if ( useratified != 0 )
            {
                if ( src_or_dest != 0 )
                {
                    txid = bp->notaries[k].ratifydestutxo;
                    vout = bp->notaries[k].ratifydestvout;
                }
                else
                {
                    txid = bp->notaries[k].ratifysrcutxo;
                    vout = bp->notaries[k].ratifysrcvout;
                }
            }
            else
            {
                cp = (src_or_dest != 0) ? &bp->notaries[k].dest : &bp->notaries[k].src;
                txid = cp->prev_hash;
                vout = cp->prev_vout;
            }
            if ( bits256_nonz(txid) != 0 )
            {
                item = cJSON_CreateObject();
                jaddbits256(item,"txid",txid);
                jaddnum(item,"vout",vout);
                if ( k == 0 && bp->require0 != 0 )
                {
                    script[0] = 0x76;
                    script[1] = 0xa9;
                    script[2] = 0x14;
                    calc_rmd160_sha256(&script[3],ep->pubkey,33); // 8ee61a3161993f4f7b7081259bf5f3322d65d3f8
                    script[23] = 0x88;
                    script[24] = 0xac;
                    init_hexbytes_noT(scriptstr,script,25);
                    /*int32_t z;
                    for (z=0; z<25; z++)
                        printf("%02x",script[z]);
                    printf(" <- script0\n");*/
                }
                else
                {
                    script[0] = 33;
                    memcpy(script+1,ep->pubkey,33);
                    script[34] = CHECKSIG;
                    init_hexbytes_noT(scriptstr,script,35);
                }
                jaddstr(item,"scriptPubKey",scriptstr);
                jaddi(vins,item);
                //printf("height.%d mod.%d VINI.%d <- i.%d j.%d\n",height,height % numnotaries,m,i,j);
                m++;
                if ( m == bp->minsigs )//&& k == bestk )
                    break;
            }
            else
            {
                printf("null txid slot k.%d m.%d minsigs.%d\n",k,m,bp->minsigs);
                free_json(vins);
                return(0);
            }
        }
    }
    return(vins);
}

void dpow_rawtxsign(struct supernet_info *myinfo,struct dpow_info *dp,struct iguana_info *coin,struct dpow_block *bp,char *rawtx,cJSON *vins,int8_t bestk,uint64_t bestmask,int32_t myind,int32_t src_or_dest)
{
    int32_t j,m=0,valid,retval=-1; char *jsonstr,*signedtx,*rawtx2,*sigstr,*pubstr; cJSON *signobj,*vinitem,*sobj,*txobj2,*item,*vin; uint8_t pubkey33[33]; bits256 srchash; struct dpow_entry *ep; struct dpow_coinentry *cp;
    if ( bestk < 0 )
        return;
    for (j=0; j<sizeof(srchash); j++)
        srchash.bytes[j] = dp->minerkey33[j+1];
    memset(srchash.bytes,0,sizeof(srchash));
    m = 0;
    ep = &bp->notaries[myind];
    cp = (src_or_dest != 0) ? &bp->notaries[myind].dest : &bp->notaries[myind].src;
    if ( (jsonstr= dpow_signrawtransaction(myinfo,coin,rawtx,vins)) != 0 )
    {
        if ( (signobj= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( ((signedtx= jstr(signobj,"hex")) != 0 || (signedtx= jstr(signobj,"result")) != 0) && (rawtx2= dpow_decoderawtransaction(myinfo,coin,signedtx)) != 0 )
            {
                if ( (txobj2= cJSON_Parse(rawtx2)) != 0 )
                {
                    if ( (vin= jarray(&m,txobj2,"vin")) != 0 )
                    {
                        for (j=0; j<m; j++)
                        {
                            item = jitem(vin,j);
                            vinitem = jitem(vins,j);
                            if ( (sobj= jobj(item,"scriptSig")) != 0 && (sigstr= jstr(sobj,"hex")) != 0 && strlen(sigstr) > 32 )
                            {
                                valid = 0;
                                if ( dp->ratifying != 0 && j == 0 && bp->myind == 0 )
                                    valid = 1;
                                else if ( (pubstr= jstr(vinitem,"scriptPubKey")) != 0 && is_hexstr(pubstr,0) == 70 )
                                {
                                    decode_hex(pubkey33,33,&pubstr[2]);
                                    if ( memcmp(pubkey33,dp->minerkey33,33) == 0 )
                                        valid = 1;
                                    else
                                    {
                                        int32_t z;
                                        for (z=0; z<33; z++)
                                            printf("%02x",dp->minerkey33[z]);
                                        printf(" minerkey33 doesnt match\n");
                                        for (z=0; z<33; z++)
                                            printf("%02x",pubkey33[z]);
                                        printf(" scriptPubKey\n");
                                    }
                                }
                                if ( valid != 0 )
                                {
                                    printf("bestk.%d %llx %s height.%d mod.%d VINI.%d myind.%d MINE.(%s) j.%d\n",bestk,(long long)bestmask,(src_or_dest != 0) ? bp->destcoin->symbol : bp->srccoin->symbol,bp->height,DPOW_MODIND(bp,0),j,myind,jprint(item,0),j);
                                    cp->siglens[bestk] = (int32_t)strlen(sigstr) >> 1;
                                    if ( src_or_dest != 0 )
                                        bp->destsigsmasks[bestk] |= (1LL << myind);
                                    else bp->srcsigsmasks[bestk] |= (1LL << myind);
                                    decode_hex(cp->sigs[bestk],cp->siglens[bestk],sigstr);
                                    ep->masks[src_or_dest][bestk] = bestmask;
                                    ep->beacon = bp->beacon;
                                    dpow_sigsend(myinfo,dp,bp,myind,bestk,bestmask,srchash,src_or_dest != 0 ? DPOW_SIGBTCCHANNEL : DPOW_SIGCHANNEL);
                                    retval = 0;
                                    break;
                                } else printf("sig.%d of %d didnt match pubkey? (%s)\n",j,m,jprint(vinitem,0));
                            } //else printf("notmine.(%s)\n",jprint(item,0));
                        }
                    } else printf("no vin[] (%s)\n",jprint(txobj2,0));
                    free_json(txobj2);
                } else printf("cant parse.(%s)\n",rawtx2);
                free(rawtx2);
            } else printf("error decoding (%s) %s\n",signedtx==0?"":signedtx,jsonstr);
            free_json(signobj);
        } else printf("error parsing.(%s)\n",jsonstr);
        free(jsonstr);
    } else printf("%s null signature in dpow_rawtxsign\n",dp->symbol);
}

int32_t dpow_signedtxgen(struct supernet_info *myinfo,struct dpow_info *dp,struct iguana_info *coin,struct dpow_block *bp,int8_t bestk,uint64_t bestmask,int32_t myind,uint32_t deprec,int32_t src_or_dest,int32_t useratified)
{
    int32_t j,m,numsigs,len,siglen,retval=-1; char rawtx[32768],*jsonstr,*rawtx2,*signedtx,*sigstr; cJSON *item,*sobj,*vins,*vin,*txobj2,*signobj; bits256 txid,srchash,zero; struct dpow_entry *ep;
    ep = &bp->notaries[myind];
    memset(&zero,0,sizeof(zero));
    if ( bestk < 0 )
        return(-1);
    for (j=0; j<sizeof(srchash); j++)
        srchash.bytes[j] = dp->minerkey33[j+1];
    if ( (vins= dpow_vins(coin,bp,bestk,bestmask,1,src_or_dest,useratified)) != 0 )
    {
        txid = dpow_notarytx(myinfo,rawtx,&numsigs,coin->chain->isPoS,bp,bestk,bestmask,0,src_or_dest,bp->numratified!=0?bp->ratified_pubkeys:0,useratified*bp->numratified);
        //char str[65]; printf("%s signedtxgen %s src_or_dest.%d (%d %llx) useratified.%d raw.(%s)\n",dp->symbol,bits256_str(str,txid),src_or_dest,bestk,(long long)bestmask,useratified,rawtx);
        if ( bits256_nonz(txid) != 0 && rawtx[0] != 0 ) // send tx to share utxo set
        {
            if ( useratified != 0 )
            {
                len = (int32_t)strlen(rawtx) >> 1;
                if ( len <= sizeof(bp->ratifyrawtx[src_or_dest]) )
                {
                    decode_hex(bp->ratifyrawtx[src_or_dest],len,rawtx),bp->rawratifiedlens[src_or_dest] = len;
                }
                if ( (jsonstr= dpow_signrawtransaction(myinfo,coin,rawtx,vins)) != 0 )
                {
                    if ( (signobj= cJSON_Parse(jsonstr)) != 0 )
                    {
                        if ( ((signedtx= jstr(signobj,"hex")) != 0 || (signedtx= jstr(signobj,"result")) != 0) && (rawtx2= dpow_decoderawtransaction(myinfo,coin,signedtx)) != 0 )
                        {
                            if ( (txobj2= cJSON_Parse(rawtx2)) != 0 )
                            {
                                if ( (vin= jarray(&m,txobj2,"vin")) != 0 )
                                {
                                    for (j=0; j<m; j++)
                                    {
                                        item = jitem(vin,j);
                                        if ( (sobj= jobj(item,"scriptSig")) != 0 && (sigstr= jstr(sobj,"hex")) != 0 && strlen(sigstr) > 32 )
                                        {
                                            siglen = (int32_t)strlen(sigstr) >> 1;
                                            bp->ratifysiglens[src_or_dest] = siglen;
                                            decode_hex(bp->ratifysigs[src_or_dest],siglen,sigstr);
                                            bp->notaries[bp->myind].ratifysiglens[src_or_dest] = siglen;
                                            memcpy(bp->notaries[bp->myind].ratifysigs[src_or_dest],bp->ratifysigs[src_or_dest],siglen);
                                            bp->ratifysigmasks[src_or_dest] |= (1LL << bp->myind);
                                            printf("RATIFYSIG[%d] <- set notaryid.%d siglen.%d (%s).%d\n",src_or_dest,bp->myind,bp->ratifysiglens[src_or_dest],sigstr,siglen);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    printf("signrawtransaction error vins.(%s) rawtx.(%s)\n",jprint(vins,0),rawtx);
                }
            } else dpow_rawtxsign(myinfo,dp,coin,bp,rawtx,vins,bestk,bestmask,myind,src_or_dest);
        } else printf("signedtxgen zero txid or null rawtx\n");
        free_json(vins);
    }
    else if ( (bestmask & bp->recvmask) != bestmask )
        printf("signedtxgen error generating vins bestk.%d %llx recv.%llx need to recv %llx\n",bestk,(long long)bestmask,(long long)bp->recvmask,(long long)(bestmask & ~bp->recvmask));
    return(retval);
}

void dpow_sigscheck(struct supernet_info *myinfo,struct dpow_info *dp,struct dpow_block *bp,int32_t myind,int32_t src_or_dest,int8_t bestk,uint64_t bestmask,uint8_t pubkeys[64][33],int32_t numratified)
{
    bits256 txid,srchash,zero,signedtxid; struct iguana_info *coin; int32_t j,len,numsigs; char *retstr=0,str[65],str2[65]; uint8_t txdata[32768]; uint32_t channel,state;
    coin = (src_or_dest != 0) ? bp->destcoin : bp->srccoin;
    memset(zero.bytes,0,sizeof(zero));
    memset(txid.bytes,0,sizeof(txid));
    channel = (src_or_dest != 0) ? DPOW_SIGBTCCHANNEL : DPOW_SIGCHANNEL;
    if ( bestk >= 0 && bp->state != 0xffffffff && coin != 0 )
    {
        dpow_notarytx(myinfo,bp->signedtx,&numsigs,coin->chain->isPoS,bp,bestk,bestmask,0,src_or_dest,pubkeys,numratified); // setcrcval
        signedtxid = dpow_notarytx(myinfo,bp->signedtx,&numsigs,coin->chain->isPoS,bp,bestk,bestmask,1,src_or_dest,pubkeys,numratified);
        if ( strcmp("GAME",coin->symbol) == 0 )
            printf("src_or_dest.%d bestk.%d %llx %s numsigs.%d signedtx.(%s)\n",src_or_dest,bestk,(long long)bestmask,bits256_str(str,signedtxid),numsigs,bp->signedtx);
        bp->state = 1;
        if ( bits256_nonz(signedtxid) != 0 && numsigs == bp->minsigs )
        {
            if ( (retstr= dpow_sendrawtransaction(myinfo,coin,bp->signedtx)) != 0 )
            {
                //printf("sendrawtransaction.(%s)\n",retstr);
                if ( is_hexstr(retstr,0) == sizeof(txid)*2 )
                {
                    decode_hex(txid.bytes,sizeof(txid),retstr);
                    if ( bits256_cmp(txid,signedtxid) == 0 )
                    {
                        if ( src_or_dest != 0 )
                        {
                            bp->desttxid = txid;
                            dpow_signedtxgen(myinfo,dp,bp->srccoin,bp,bestk,bestmask,myind,DPOW_SIGCHANNEL,0,numratified != 0);
                        } else bp->srctxid = txid;
                        len = (int32_t)strlen(bp->signedtx) >> 1;
                        decode_hex(txdata+32,len,bp->signedtx);
                        for (j=0; j<sizeof(srchash); j++)
                            txdata[j] = txid.bytes[j];
                        state = src_or_dest != 0 ? 1000 : 0xffffffff;
                        if ( bp->state < state )
                        {
                            bp->state = state;
                            dpow_send(myinfo,dp,bp,txid,bp->hashmsg,(src_or_dest != 0) ? DPOW_BTCTXIDCHANNEL : DPOW_TXIDCHANNEL,bp->height,txdata,len+32);
                            printf("complete statemachine.%s ht.%d state.%d (%x %x)\n",coin->symbol,bp->height,bp->state,bp->hashmsg.uints[0],txid.uints[0]);
                        }
                    } else printf("sendtxid mismatch got %s instead of %s\n",bits256_str(str,txid),bits256_str(str2,signedtxid));
                }
                else
                {
                    bp->state = 0xffffffff;
                    printf("dpow_sigscheck: mismatched txid.%s vs %s\n",bits256_str(str,txid),retstr);
                }
                free(retstr);
                retstr = 0;
            }
            else
            {
                printf("NULL return from sendrawtransaction. abort\n");
                bp->state = 0xffffffff;
            }
        } else printf("numsigs.%d vs required.%d\n",numsigs,bp->minsigs);
    }
}

