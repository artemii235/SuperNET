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

#include "../iguana/iguana777.h"
#include "datachain_events.c"

uint32_t datachain_checkpoint(struct supernet_info *myinfo,struct iguana_info *coin,uint32_t lastcheckpoint,uint32_t timestamp,bits256 merkle,int32_t lastheight,bits256 lasthash2)
{
    char str[65],str2[65]; struct iguana_info *btc = iguana_coinfind("BTC");
    printf("datachain_checkpoint.%s for %s.%u to %u lastheight.%d %s\n",bits256_str(str,merkle),coin->symbol,lastcheckpoint,timestamp,lastheight,bits256_str(str2,lasthash2));
    if ( myinfo->IAMNOTARY != 0 && (lastheight % myinfo->NOTARY.NUMRELAYS) == myinfo->NOTARY.RELAYID )
    {
        // if designated relay, submit checkpoint -> add ip/relayid to opreturn
        //
        if ( strcmp(coin->symbol,"BTCD") == 0 )
        {
            if ( btc != 0 )
            {
                
            }
        }
        else
        {
        }
    }
    return(timestamp);
}

int32_t datachain_events_rewind(struct supernet_info *myinfo,int32_t ordered,struct datachain_info *dPoW,int32_t height,uint32_t hdrsi,uint32_t unspentind)
{
    uint64_t hdrsi_unspentind; int32_t i;
    printf("datachain_events_rewind\n");
    if ( dPoW->numevents > 0 )
    {
        datachain_events_sort(dPoW);
        hdrsi_unspentind = ((uint64_t)hdrsi << 32) | unspentind;
        for (i=dPoW->numevents-1; i>=0; i--)
            if ( hdrsi_unspentind > dPoW->events[i]->hdrsi_unspentind )
                break;
        printf("dPoW rewind %d to %d\n",dPoW->numevents,i+1);
        dPoW->numevents = i+1;
    }
    return(dPoW->numevents);
}

int32_t datachain_checkpoint_update(struct supernet_info *myinfo,struct iguana_info *coin,uint32_t timestamp)
{
    int32_t i,num,n,lastheight; bits256 *tree,hash2,lasthash2,merkle; struct iguana_block *block;
    //printf("datachain_checkpoint_update\n");
    if ( coin->lastcheckpoint <= coin->blocks.hwmchain.height )
    {
        num = (coin->blocks.hwmchain.height - coin->lastcheckpoint) + 1;
        tree = (bits256 *)coin->blockspace;
        if ( num <= IGUANA_MAXPACKETSIZE/(sizeof(bits256) * 2) )
        {
            lastheight = -1;
            memset(lasthash2.bytes,0,sizeof(lasthash2));
            for (i=n=0; i<num; i++)
            {
                hash2 = iguana_blockhash(coin,coin->lastcheckpoint + i);
                if ( bits256_nonz(hash2) != 0 )
                {
                    if ( (block= iguana_blockfind("datachain",coin,hash2)) != 0 && block->height == coin->lastcheckpoint + i && block->mainchain != 0 && block->RO.timestamp < timestamp )
                    {
                        tree[n++] = hash2;
                        lastheight = block->height;
                        lasthash2 = hash2;
                    }
                    else break;
                }
                else
                {
                    printf("got zero blockhash for %s.[%d]\n",coin->symbol,coin->lastcheckpoint + i);
                    break;
                }
            }
            if ( n > 0 && lastheight >= 0 && bits256_nonz(lasthash2) != 0 )
            {
                merkle = iguana_merkle(coin->symbol,tree,num);
                coin->lastcheckpoint = datachain_checkpoint(myinfo,coin,coin->lastcheckpoint,timestamp,merkle,lastheight,lasthash2);
            }
        }
    }
    return(coin->lastcheckpoint);
}

void datachain_BTC_clock(struct supernet_info *myinfo,int32_t ordered,struct iguana_info *btc,int32_t height,uint32_t hdrsi,uint32_t unspentind,uint32_t timestamp)
{
    int32_t retval; struct iguana_info *btcd = iguana_coinfind("BTCD");
    //printf("datachain_BTC_clock\n");
    if ( (retval= datachain_eventadd(myinfo,ordered,&myinfo->dPoW.BTC,DATACHAIN_ISBTC,0)) < 0 )
    {
        myinfo->dPoW.BTC.numevents = datachain_events_rewind(myinfo,ordered,&myinfo->dPoW.BTC,height,hdrsi,unspentind);
    }
    else if ( retval > 0 )
    {
        if ( ordered != 0 && btcd != 0 && btcd->started != 0 && btcd->active != 0 )
        {
            // new BTC block actions, ie gather BTCD hashes for checkpoint
            btcd->lastcheckpoint = datachain_checkpoint_update(myinfo,btcd,timestamp);
            printf("NEWBLOCK.%s ht.%d\n",btc->symbol,height);
        }
    }
}

void datachain_KOMODO_newblock(struct supernet_info *myinfo,int32_t ordered,struct iguana_info *btcd,int32_t height,uint32_t hdrsi,uint32_t unspentind,uint32_t timestamp)
{
    int32_t retval; struct iguana_info *virt,*tmp;
    //printf("datachain_KOMODO_newblock\n");
    if ( (retval= datachain_eventadd(myinfo,ordered,&myinfo->dPoW.BTCD,DATACHAIN_ISKOMODO,0)) < 0 )
    {
        myinfo->dPoW.BTCD.numevents = datachain_events_rewind(myinfo,ordered,&myinfo->dPoW.BTCD,height,hdrsi,unspentind);
    }
    else if ( retval > 0 )
    {
        // new BTCD block actions, ie gather all virtual hashes for checkpoint
        if ( ordered != 0 )
        {
            HASH_ITER(hh,myinfo->allcoins,virt,tmp)
            {
                if ( virt->started != 0 && virt->active != 0 && virt->virtualchain != 0 )
                    virt->lastcheckpoint = datachain_checkpoint_update(myinfo,virt,timestamp);
            }
            //printf("NEWBLOCK.%s ht.%d\n",btcd->symbol,height);
        }
    }
}

void datachain_virt_newblock(struct supernet_info *myinfo,int32_t ordered,struct iguana_info *virt,int32_t height,uint32_t hdrsi,uint32_t unspentind,uint32_t timestamp)
{
    int32_t retval;
    printf("datachain_virt_newblock\n");
    if ( (retval= datachain_eventadd(myinfo,ordered,&virt->dPoW,0,0)) < 0 )
    {
        virt->dPoW.numevents = datachain_events_rewind(myinfo,ordered,&virt->dPoW,height,hdrsi,unspentind);
    }
    else if ( retval > 0 )
    {
        // new virt block actions, maybe nothing to do?
        if ( ordered != 0 )
            printf("NEWBLOCK.%s ht.%d\n",virt->symbol,height);
    }
}

int32_t datachain_datascript(struct iguana_info *coin,uint8_t *script,uint8_t *data,int32_t datalen)
{
    int32_t i,pkey0,plen,len = 0; uint8_t p2sh_rmd160[20]; struct vin_info V;
    memset(&V,0,sizeof(V));
    if ( len < 32*3 )
        pkey0 = 2, plen = 32;
    else pkey0 = 4, plen = 64;
    V.M = V.N = (datalen / plen) + ((datalen % plen) != 0);
    for (i=0; i<V.N; i++)
    {
        V.signers[i].pubkey[0] = pkey0;
        memcpy(V.signers[i].pubkey+1,&data[len],plen), len += plen;
    }
    return(bitcoin_MofNspendscript(p2sh_rmd160,script,0,&V));
}

int32_t datachain_datascript_decode(uint8_t *opreturn,uint8_t *script,int32_t scriptlen,struct vin_info *vp,int32_t type)
{
    int32_t plen,i,oplen=0;
    //for (i=0; i<scriptlen; i++)
    //    printf("%02x",script[i]);
    //printf(" <- MofNscript\n");
    for (i=0; i<vp->N; i++)
    {
        if ( (plen= bitcoin_pubkeylen(vp->signers[i].pubkey)) > 32 )
            memcpy(&opreturn[oplen],vp->signers[i].pubkey+1,plen-1), oplen += (plen - 1);
    }
    return(oplen);
}

int32_t datachain_opreturnscript(struct iguana_info *coin,uint8_t *script,char *datastr,int32_t datalen)
{
    int32_t offset = 0;
    script[offset++] = 0x6a;
    if ( datalen >= 0x4c )
    {
        if ( datalen > 0xff )
        {
            script[offset++] = 0x4d;
            script[offset++] = datalen & 0xff;
            script[offset++] = (datalen >> 8) & 0xff;
        }
        else
        {
            script[offset++] = 0x4c;
            script[offset++] = datalen;
        }
    } else script[offset++] = datalen;
    decode_hex(&script[offset],datalen,datastr);
    return(datalen + offset);
}

int32_t datachain_opreturn_decode(uint8_t *opreturn,uint8_t *script,int32_t scriptlen)
{
    int32_t datalen,len = 1;
    if ( (datalen= script[len++]) >= 76 )
    {
        if ( datalen == 0x4c )
            datalen = script[len++];
        else if ( datalen == 0x4d )
        {
            datalen = script[len++];
            datalen = (datalen << 8) | script[len++];
        }
    }
    memcpy(opreturn,&script[len],datalen);
    if ( len+datalen == scriptlen )
        return(datalen);
    else return(-1);
}

void datachain_opreturn(struct supernet_info *myinfo,int32_t ordered,struct iguana_info *coin,uint32_t timestamp,int32_t btc_or_btcd,int64_t crypto777_payment,int64_t burned,int32_t height,uint64_t hdrsi_unspentind,uint8_t *opreturn,int32_t oplen)
{
    uint32_t hdrsi,unspentind; struct datachain_event *event;
    hdrsi = (uint32_t)(hdrsi_unspentind >> 32);
    unspentind = (uint32_t)hdrsi_unspentind;
    //printf("datachain_opreturn\n");
    if ( btc_or_btcd == DATACHAIN_ISBTC ) // BTC
    {
        if ( opreturn == 0 )
            datachain_BTC_clock(myinfo,ordered,coin,height,hdrsi,unspentind,timestamp);
        else
        {
            if ( (event= datachain_event_create(coin,crypto777_payment,burned,height,hdrsi,unspentind,opreturn,oplen)) != 0 )
                datachain_eventadd(myinfo,ordered,&myinfo->dPoW.BTC,btc_or_btcd,event);
        }
    }
    else if ( btc_or_btcd == DATACHAIN_ISKOMODO ) // BTCD
    {
        if ( opreturn == 0 )
            datachain_KOMODO_newblock(myinfo,ordered,coin,height,hdrsi,unspentind,timestamp);
        else
        {
            if ( (event= datachain_event_create(coin,crypto777_payment,burned,height,hdrsi,unspentind,opreturn,oplen)) != 0 )
                datachain_eventadd(myinfo,ordered,&myinfo->dPoW.BTCD,btc_or_btcd,event);
        }
    }
    else
    {
        if ( opreturn == 0 )
            datachain_virt_newblock(myinfo,ordered,coin,height,hdrsi,unspentind,timestamp);
        else
        {
            if ( (event= datachain_event_create(coin,crypto777_payment,burned,height,hdrsi,unspentind,opreturn,oplen)) != 0 )
                datachain_eventadd(myinfo,ordered,&coin->dPoW,btc_or_btcd,event);
        }
    }
    if ( opreturn != 0 )
    {
        int32_t i;
        for (i=0; i<oplen; i++)
            printf("%02x",opreturn[i]);
        printf(" <- opreturn.%s len.%d ht.%d [%d] u.%u 777 %.8f burn %.8f\n",coin->symbol,oplen,height,hdrsi,unspentind,dstr(crypto777_payment),dstr(burned));
    }
}

int32_t iguana_opreturn(struct supernet_info *myinfo,int32_t ordered,struct iguana_info *coin,uint32_t timestamp,struct iguana_bundle *bp,int64_t crypto777_payment,int32_t height,uint64_t hdrsi_unspentind,int64_t burned,uint32_t fileid,uint64_t scriptpos,uint32_t scriptlen)
{
    uint8_t type,scriptspace[IGUANA_MAXSCRIPTSIZE],opreturn[8192]; char fname[1024]; uint32_t oplen=0; int32_t btc_or_btcd=0,len = -1; struct vin_info V;
    //printf("iguana_opreturn\n");
    if ( strcmp("BTC",coin->symbol) == 0 )
        btc_or_btcd = DATACHAIN_ISBTC;
    else if ( strcmp("BTCD",coin->symbol) == 0 )
        btc_or_btcd = DATACHAIN_ISKOMODO;
    else if ( coin->virtualchain == 0 )
        return(-1);
    if ( height < bp->bundleheight || height >= bp->bundleheight+coin->chain->bundlesize )
    {
        printf("iguana_opreturn illegal height %d for [%d] %d\n",height,bp->hdrsi,bp->bundleheight);
        return(-1);
    }
    if ( crypto777_payment == 0 && burned == 0 && scriptlen == 0 && fileid == 0 && scriptpos == 0 )
    {
        datachain_opreturn(myinfo,ordered,coin,timestamp,btc_or_btcd,crypto777_payment,burned,height,hdrsi_unspentind,0,0);
        return(0);
    }
    if ( scriptpos > 0 && scriptlen > 0 )
    {
        iguana_voutsfname(coin,bp->ramchain.from_ro,fname,fileid);
        if ( (len= iguana_scriptdata(coin,scriptspace,coin->voutptrs[fileid],fname,scriptpos,scriptlen)) == scriptlen )
        {
            memset(&V,0,sizeof(V));
            V.spendlen = scriptlen;
            memcpy(V.spendscript,scriptspace,scriptlen);
            type = _iguana_calcrmd160(coin,&V);
            if ( type == IGUANA_SCRIPT_OPRETURN )
                oplen = datachain_opreturn_decode(opreturn,scriptspace,scriptlen);
            else oplen = datachain_datascript_decode(opreturn,scriptspace,scriptlen,&V,type);
            datachain_opreturn(myinfo,ordered,coin,timestamp,btc_or_btcd,crypto777_payment,burned,height,hdrsi_unspentind,opreturn,oplen);
            return(oplen);
        } else printf("iguana_opreturn error: %d bytes from fileid.%d[%d] %s for scriptlen.%d\n",len,fileid,(uint32_t)scriptpos,fname,scriptlen);
    }
    return(-1);
}

void datachain_update_spend(struct supernet_info *myinfo,int32_t ordered,struct iguana_info *coin,uint32_t timestamp,struct iguana_bundle *bp,int32_t height,bits256 txid,int32_t vout,uint8_t rmd160[20],int64_t value)
{
    if ( strcmp("BTC",coin->symbol) == 0 )
        datachain_update_txidvout(myinfo,ordered,coin,&myinfo->dPoW.BTC,DATACHAIN_ISBTC,height,txid,vout,rmd160,value);
    else if ( strcmp("BTCD",coin->symbol) == 0 )
        datachain_update_txidvout(myinfo,ordered,coin,&myinfo->dPoW.BTCD,DATACHAIN_ISKOMODO,height,txid,vout,rmd160,value);
    else datachain_update_txidvout(myinfo,ordered,coin,&coin->dPoW,0,height,txid,vout,rmd160,value);
}

int64_t datachain_update(struct supernet_info *myinfo,int32_t ordered,struct iguana_info *coin,uint32_t timestamp,struct iguana_bundle *bp,uint8_t rmd160[20],int64_t crypto777_payment,uint8_t type,int32_t height,uint64_t hdrsi_unspentind,int64_t value,uint32_t fileid,uint64_t scriptpos,int32_t scriptlen,bits256 txid,int32_t vout)
{
    if ( (0) )
    {
        if ( memcmp(rmd160,CRYPTO777_RMD160,20) == 0 )
        {
            crypto777_payment += value;
            //printf("datachain_update crypto777 %.8f += %.8f\n",dstr(crypto777_payment),dstr(value));
        }
        else if ( crypto777_payment != 0 && (type == IGUANA_SCRIPT_OPRETURN || type == IGUANA_SCRIPT_3of3 || type == IGUANA_SCRIPT_2of2 || type == IGUANA_SCRIPT_1of1) )
        {
            //printf("datachain_update opreturn\n");
            iguana_opreturn(myinfo,ordered,coin,timestamp,bp,crypto777_payment,height,hdrsi_unspentind,value,fileid,scriptpos,scriptlen);
        } else datachain_update_spend(myinfo,ordered,coin,timestamp,bp,height,txid,vout,rmd160,value);
        return(crypto777_payment);
    }
    return(0);
}
