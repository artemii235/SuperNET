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
#include "exchanges777.h"
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_schnorr.h"
#include "secp256k1/include/secp256k1_rangeproof.h"

const char *Hardcoded_coins[][3] = { { "BTC", "bitcoin", "0" }, { "BTCD", "BitcoinDark", "129" },  { "VPN", "VPNcoin", "129" }, { "LTC", "litecoin", "129" } , { "endmarker", "", "" } };

struct iguana_info *iguana_coinfind(char *symbol)
{
    struct iguana_info *coin=0; uint32_t symbolcrc; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    while ( myinfo->allcoins_being_added != 0 )
    {
        sleep(1);
        if ( myinfo->allcoins_being_added != 0 )
            printf("wait for coinadd to complete, OK if rare\n");
        sleep(1);
    }
    symbolcrc = calc_crc32(0,symbol,(int32_t)strlen(symbol));
    //portable_mutex_lock(&myinfo->allcoins_mutex);
        HASH_FIND(hh,myinfo->allcoins,&symbolcrc,sizeof(coin->symbolcrc),coin);
    //portable_mutex_unlock(&myinfo->allcoins_mutex);
    return(coin);
}

struct iguana_info *iguana_coinadd(char *symbol,char *name,cJSON *argjson,int32_t virtcoin)
{
    struct iguana_info *coin; uint32_t symbolcrc; char *privatechain; int32_t j; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    if ( (coin= iguana_coinfind(symbol)) == 0 )
    {
        if ( (coin= iguana_coinfind(symbol)) == 0 )
        {
            myinfo->allcoins_being_added = 1;
            coin = mycalloc('C',1,sizeof(*coin));
            strcpy(coin->getinfostr,"getinfo");
            strcpy(coin->validateaddress,"validateaddress");
            strcpy(coin->estimatefeestr,"estimatefee");
            strcpy(coin->signtxstr,"signrawtransaction");
            coin->blockspacesize = IGUANA_MAXPACKETSIZE + 8192;
            coin->blockspace = calloc(1,coin->blockspacesize);
            if ( virtcoin != 0 || ((privatechain= jstr(argjson,"geckochain")) != 0 && privatechain[0] != 0) )
            {
                myinfo->allcoins_numvirts++;
                coin->virtualchain = 1;
            }
            else
            {
                coin->chain = iguana_chainfind(myinfo,(char *)symbol,argjson,1);
                //if ( coin->FULLNODE >= 0 )
                //    coin->chain->userpass[0] = 0;
                coin->peers = calloc(1,sizeof(*coin->peers));
                for (j=0; j<IGUANA_MAXPEERS; j++)
                {
                    coin->peers->active[j].usock = -1;
                    strcpy(coin->peers->active[j].coinname,name);
                    strcpy(coin->peers->active[j].symbol,symbol);
                }
            }
            if ( (coin->protocol= juint(argjson,"protocol")) == 0 )
                coin->protocol = IGUANA_PROTOCOL_BITCOIN;
            coin->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
            secp256k1_pedersen_context_initialize(coin->ctx);
            secp256k1_rangeproof_context_initialize(coin->ctx);
            strcpy(coin->name,name);
            strcpy(coin->symbol,symbol);
            iguana_initcoin(coin,argjson);
            basilisk_functions(coin,coin->protocol);
            printf("ADD ALLCOINS.(%s) name.(%s) size %ld numvirts.%d\n",symbol,name,sizeof(*coin),myinfo->allcoins_numvirts);
            coin->symbolcrc = symbolcrc = calc_crc32(0,symbol,(int32_t)strlen(symbol));
            //portable_mutex_lock(&myinfo->allcoins_mutex);
            coin->coinid = myinfo->totalcoins++;
            HASH_ADD(hh,myinfo->allcoins,symbolcrc,sizeof(coin->symbolcrc),coin);
            //portable_mutex_unlock(&myinfo->allcoins_mutex);
            struct iguana_info *virt,*tmp;
            HASH_ITER(hh,myinfo->allcoins,virt,tmp)
            {
                printf("%s ",virt->symbol);
            }
            printf("allcoins\n");
            myinfo->allcoins_being_added = 0;
        }
        if ( (coin= iguana_coinfind(symbol)) == 0 )
            printf("error finding justadded.(%s)\n",symbol);
    }
    return(coin);
}

void iguana_recvalloc(struct iguana_info *coin,int32_t numitems)
{
    //coin->blocks.ptrs = myrealloc('W',coin->blocks.ptrs,coin->blocks.ptrs==0?0:coin->blocks.maxbits * sizeof(*coin->blocks.ptrs),numitems * sizeof(*coin->blocks.ptrs));
    //coin->blocks.RO = myrealloc('W',coin->blocks.RO,coin->blocks.RO==0?0:coin->blocks.maxbits * sizeof(*coin->blocks.RO),numitems * sizeof(*coin->blocks.RO));
    //printf("realloc waitingbits.%d -> %d\n",coin->blocks.maxbits,numitems);
    //coin->blocks.maxbits = numitems;
}

double iguana_metric(struct iguana_peer *addr,uint32_t now,double decay)
{
    int32_t duration; double metric = addr->recvblocks * addr->recvtotal;
    addr->recvblocks *= decay;
    addr->recvtotal *= decay;
    if ( now >= addr->ready && addr->ready != 0 )
        duration = (now - addr->ready + 1);
    else duration = 1;
    if ( metric < SMALLVAL && duration > 300 )
        metric = 0.001;
    else metric /= duration;
    return(metric);
}

int32_t iguana_peermetrics(struct supernet_info *myinfo,struct iguana_info *coin)
{
    int32_t i,ind,n; double *sortbuf,sum; uint32_t now; struct iguana_peer *addr,*slowest = 0;
    //printf("peermetrics\n");
    sortbuf = mycalloc('s',coin->MAXPEERS,sizeof(double)*2);
    coin->peers->mostreceived = 0;
    now = (uint32_t)time(NULL);
    for (i=n=0; i<coin->MAXPEERS; i++)
    {
        addr = &coin->peers->active[i];
        if ( addr->usock < 0 || addr->dead != 0 || addr->ready == 0 || addr->ipbits == 0 )
            continue;
        addr->pendblocks >>= 1;
        addr->pendhdrs >>= 1;
        if ( addr->recvblocks > coin->peers->mostreceived )
            coin->peers->mostreceived = addr->recvblocks;
        //printf("[%.0f %.0f] ",addr->recvblocks,addr->recvtotal);
        sortbuf[n*2 + 0] = iguana_metric(addr,now,.995);
        sortbuf[n*2 + 1] = i;
        n++;
    }
    if ( n > 0 )
    {
        revsortds(sortbuf,n,sizeof(double)*2);
        portable_mutex_lock(&coin->peers_mutex);
        for (sum=i=0; i<n; i++)
        {
            if ( i < coin->MAXPEERS )
            {
                coin->peers->topmetrics[i] = sortbuf[i*2];
                ind = (int32_t)sortbuf[i*2 +1];
                coin->peers->ranked[i] = addr = &coin->peers->active[ind];
                if ( sortbuf[i*2] > SMALLVAL && (double)i/n > .8 && (time(NULL) - addr->ready) > 77 )
                    slowest = coin->peers->ranked[i];
                //printf("(%.5f %s) ",sortbuf[i*2],coin->peers->ranked[i]->ipaddr);
                coin->peers->ranked[i]->rank = i + 1;
                sum += coin->peers->topmetrics[i];
            }
        }
        coin->peers->numranked = n;
        portable_mutex_unlock(&coin->peers_mutex);
        //printf("peer metrics NUMRANKED.%d\n",n);
        if ( i > 0 )
        {
            coin->peers->avemetric = (sum / i);
            if ( i >= 7*(coin->MAXPEERS/8) && slowest != 0 )
            {
                printf("prune slowest peer.(%s) numranked.%d MAXpeers->%d\n",slowest->ipaddr,n,coin->MAXPEERS);
                slowest->dead = 1;
            }
        }
    }
    myfree(sortbuf,coin->MAXPEERS * sizeof(double) * 2);
    return(coin->peers->mostreceived);
}

void *iguana_kviAddriterator(struct iguana_info *coin,struct iguanakv *kv,struct iguana_kvitem *item,uint64_t args,void *key,void *value,int32_t valuesize)
{
    char ipaddr[64]; int32_t i; FILE *fp = (FILE *)(long)args; struct iguana_peer *addr; struct iguana_iAddr *iA = value;
    if ( fp != 0 && iA != 0 && iA->numconnects > 0 && iA->lastconnect > time(NULL)-IGUANA_RECENTPEER )
    {
        for (i=0; i<coin->peers->numranked; i++)
            if ( (addr= coin->peers->ranked[i]) != 0 && addr->ipbits == iA->ipbits )
                break;
        if ( i == coin->peers->numranked )
        {
            expand_ipbits(ipaddr,iA->ipbits);
            fprintf(fp,"%s\n",ipaddr);
        }
    }
    return(0);
}

uint32_t iguana_updatemetrics(struct supernet_info *myinfo,struct iguana_info *coin)
{
    char fname[512],tmpfname[512],oldfname[512],ipaddr[64]; int32_t i,j; struct iguana_peer *addr,*tmpaddr; FILE *fp;
    iguana_peermetrics(myinfo,coin);
    sprintf(fname,"%s/%s_peers.txt",GLOBAL_CONFSDIR,coin->symbol), OS_compatible_path(fname);
    sprintf(oldfname,"%s/%s_oldpeers.txt",GLOBAL_CONFSDIR,coin->symbol), OS_compatible_path(oldfname);
    sprintf(tmpfname,"%s/%s/peers.txt",GLOBAL_TMPDIR,coin->symbol), OS_compatible_path(tmpfname);
    if ( (fp= fopen(tmpfname,"w")) != 0 )
    {
        for (i=0; i<coin->peers->numranked; i++)
        {
            if ( (addr= coin->peers->ranked[i]) != 0 && addr->relayflag != 0 && strcmp(addr->ipaddr,"127.0.0.1") != 0 )
            {
                for (j=0; j<coin->peers->numranked; j++)
                {
                    if ( i != j && (tmpaddr= coin->peers->ranked[j]) != 0 && (uint32_t)addr->ipbits == (uint32_t)tmpaddr->ipbits )
                        break;
                }
                if ( j == coin->peers->numranked )
                {
                    expand_ipbits(ipaddr,(uint32_t)addr->ipbits);
                    fprintf(fp,"%s\n",ipaddr);
                    if ( (0) && addr->msgcounts.verack == 0 )
                    {
                        printf("iguana_sendblockreq (%s) addrind.%d hasn't verack'ed yet\n",addr->ipaddr,addr->addrind);
                        iguana_send_version(coin,addr,coin->myservices);
                    }
                }
            }
        }
        if ( ftell(fp) > OS_filesize(fname) )
        {
            printf("new peers.txt %ld vs (%s) %ld (%s)\n",ftell(fp),fname,(long)OS_filesize(fname),GLOBAL_CONFSDIR);
            fclose(fp);
            OS_renamefile(fname,oldfname);
            OS_renamefile(tmpfname,fname);
            //OS_copyfile(tmpfname,fname,1);
        } else fclose(fp);
    }
    else
    {
        printf("iguana_updatemetrics: couldnt create.(%s)\n",tmpfname);
        return(0);
    }
    return((uint32_t)time(NULL));
}

void iguana_emitQ(struct iguana_info *coin,struct iguana_bundle *bp)
{
    struct iguana_helper *ptr;
    ptr = mycalloc('i',1,sizeof(*ptr));
    ptr->allocsize = sizeof(*ptr);
    ptr->coin = coin;
    ptr->bp = bp, ptr->hdrsi = bp->hdrsi;
    ptr->type = 'E';
    ptr->starttime = (uint32_t)time(NULL);
    //printf("%s EMIT.%d[%d] emitfinish.%u\n",coin->symbol,ptr->hdrsi,bp->n,bp->emitfinish);
    queue_enqueue("emitQ",&emitQ,&ptr->DL);
}

void iguana_bundleQ(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_bundle *bp,int32_t timelimit)
{
    struct iguana_helper *ptr; struct iguana_bundle *tmp; int32_t i,n = 0;
    if ( (0) && bp->queued == 0 && bp->emitfinish <= 1 && iguana_bundleready(myinfo,coin,bp,0) == bp->n )
        printf("bundle.[%d] is ready\n",bp->hdrsi);
    if ( bp->queued != 0 )
        return;
    for (i=n=0; i<coin->bundlescount; i++)
    {
        if ( (tmp= coin->bundles[i]) != 0 && tmp->queued != 0 )
            n++;
    }
    if ( n < coin->MAXBUNDLES )
    {
        bp->queued = (uint32_t)time(NULL);
        ptr = mycalloc('q',1,sizeof(*ptr));
        ptr->allocsize = sizeof(*ptr);
        ptr->coin = coin;
        ptr->bp = bp, ptr->hdrsi = bp->hdrsi;
        ptr->type = 'B';
        ptr->starttime = (uint32_t)time(NULL);
        ptr->timelimit = timelimit;
        coin->numbundlesQ++;
        // printf("%s.%d %p bundle.%d[%d] ht.%d emitfinish.%u\n",coin->symbol,n,bp,ptr->hdrsi,bp->n,bp->bundleheight,bp->emitfinish);
        queue_enqueue("bundlesQ",&bundlesQ,&ptr->DL);
    }
    else
    {
        bp->queued = 0;
        //printf("MAXBUNDLES.%d reached.%d\n",coin->MAXBUNDLES,n);
    }
}

void iguana_validateQ(struct iguana_info *coin,struct iguana_bundle *bp)
{
    /*struct iguana_helper *ptr;
    //if ( bp->validated <= 1 )
    {
        ptr = mycalloc('i',1,sizeof(*ptr));
        ptr->allocsize = sizeof(*ptr);
        ptr->coin = coin;
        ptr->bp = bp, ptr->hdrsi = bp->hdrsi;
        ptr->type = 'V';
        ptr->starttime = (uint32_t)time(NULL);
        ptr->timelimit = 0;
        bp->validated = 1;
        //printf("VALIDATE Q %s bundle.%d[%d] utxofinish.%u balancefinish.%u\n",coin->symbol,ptr->hdrsi,bp->n,bp->utxofinish,bp->balancefinish);
        queue_enqueue("validateQ",&validateQ,&ptr->DL,0);
    }*/
}

int32_t iguana_emitfinished(struct supernet_info *myinfo,struct iguana_info *coin,int32_t queueincomplete)
{
    struct iguana_bundle *bp; int32_t i,n = 0;
    for (i=0; i<coin->bundlescount-1; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            if ( bp->emitfinish == 0 && bp->ramchain.H.data != 0 )
                bp->emitfinish = (uint32_t)time(NULL);
            if ( bp->emitfinish > 1 )
                n++;
            //printf("%u ",bp->emitfinish);
            //else if ( bp->emitfinish == 0 && bp->queued == 0 )
            //    iguana_bundleQ(myinfo,coin,bp,1000);
        }
    }
    //printf("emitfinished.%d\n",n);
    return(n);
}

int32_t iguana_utxofinished(struct iguana_info *coin)
{
    struct iguana_bundle *bp; int32_t i,n = 0;
    for (i=0; i<coin->bundlescount-1; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 && bp->utxofinish > 1 )
            n++;
    }
    return(n);
}

int32_t iguana_convertfinished(struct iguana_info *coin)
{
    struct iguana_bundle *bp; int32_t i,n = 0;
    for (i=0; i<coin->bundlescount-1; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 && bp->converted > 1 )
            n++;
    }
    return(n);
}

int32_t iguana_balancefinished(struct iguana_info *coin)
{
    struct iguana_bundle *bp; int32_t i,n = 0;
    for (i=0; i<coin->bundlescount-1; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 && bp->balancefinish > 1 )
            n++;
    }
    return(n);
}

int32_t iguana_validated(struct iguana_info *coin)
{
    struct iguana_bundle *bp; int32_t i,n = 0;
    for (i=0; i<coin->bundlescount-1; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 && bp->validated > 1 )
            n++;
    }
    return(n);
}

int32_t iguana_helperA(struct supernet_info *myinfo,struct iguana_info *coin,int32_t helperid,struct iguana_bundle *bp,int32_t convertflag)
{
    int32_t retval,numXspends,num = 0;
    if ( bp == 0 )
    {
        printf("iguana_helperA unexpected null bp\n");
        return(-1);
    }
    //printf("helperid.%d validate gen utxo.[%d] utxofinish.%u\n",helperid,bp->hdrsi,bp->utxofinish);
    if ( iguana_bundlevalidate(myinfo,coin,bp,0) == bp->n ) //
    {
        retval = 0;
        if ( bp->utxofinish > 1 || (retval= iguana_spendvectors(myinfo,coin,bp,&bp->ramchain,0,bp->n,convertflag,0)) >= 0 )
        {
            if ( retval > 0 )
            {
                numXspends = iguana_Xspendmap(coin,&bp->ramchain,bp);
                printf("GENERATED UTXO.%d for ht.%d duration %d seconds numXspends.%d\n",bp->hdrsi,bp->bundleheight,(uint32_t)time(NULL) - bp->startutxo,numXspends);
                num++;
            }
            bp->utxofinish = (uint32_t)time(NULL);
        } else printf("UTXO gen.[%d] utxo error\n",bp->hdrsi);
    }
    else
    {
        printf("error validating.[%d], restart iguana\n",bp->hdrsi);
        iguana_exit(myinfo,bp);
    }
    return(num);
}

int32_t iguana_helperB(struct iguana_info *coin,int32_t helperid,struct iguana_bundle *bp,int32_t convertflag)
{
    if ( bp == 0 )
    {
        printf("iguana_helperB unexpected null bp\n");
        return(-1);
    }
    //if ( bp != coin->current )
    {
        iguana_ramchain_prefetch(coin,&bp->ramchain,7);
        if ( convertflag == 0 )
        {
            bp->converted = 1;
            iguana_convert(coin,helperid,bp,0,0);
        }
        bp->converted = (uint32_t)time(NULL);
        return(1);
    }
    return(0);
}

int32_t iguana_utxogen(struct supernet_info *myinfo,struct iguana_info *coin,int32_t helperid,int32_t convertflag);

void iguana_update_balances(struct supernet_info *myinfo,struct iguana_info *coin)
{
    int32_t i,hdrsi,max,retval,numXspends,convertflag = 1; struct iguana_bundle *bp; char fname[1024];
    if ( coin->RTheight > 0 )
    {
        printf("Need to restart iguana to generate new balances files\n");
        printf("RT dataset can expand past bundle boundary, so no need to update balance files now\n");
        return;
    }
    max = coin->bundlescount;
    if ( coin->bundles[max-1] == coin->current || coin->bundles[max-1] == 0 || (coin->bundles[max-1] != 0 && coin->bundles[max-1]->utxofinish <= 1) )
        max--;
    if ( 1 && coin->chain->zcash != 0 )
    {
        coin->spendvectorsaved = 0;
        for (i=0; i<coin->bundlescount-1; i++)
        {
            if ( (bp= coin->bundles[i]) == 0 )
                continue;
            if ( (retval= iguana_spendvectors(myinfo,coin,bp,&bp->ramchain,0,bp->n,convertflag,0)) >= 0 ) //bp->utxofinish > 1 || 
            {
                if ( retval > 0 )
                {
                    numXspends = iguana_Xspendmap(coin,&bp->ramchain,bp);
                    printf("GENERATED UTXO.%d for ht.%d duration %d seconds numX.%d\n",bp->hdrsi,bp->bundleheight,(uint32_t)time(NULL) - bp->startutxo,numXspends);
                }
                bp->utxofinish = (uint32_t)time(NULL);
            }
        }
    }
    coin->spendvectorsaved = (uint32_t)time(NULL);
    //if ( coin->chain->zcash != 0 )
    //    iguana_utxogen(myinfo,coin,0,1);
    if ( iguana_balancefinished(coin) < max && iguana_spendvectorsaves(coin) == 0 ) //
    {
        if ( coin->origbalanceswritten <= 1 )
            hdrsi = 0;
        else hdrsi = coin->origbalanceswritten;
        for (i=0; i<max; i++)
            if ( (bp= coin->bundles[i]) != 0 && bp != coin->current )
            {
                iguana_volatilespurge(coin,&bp->ramchain);
                sprintf(fname,"%s/%s/accounts/debits.%d",GLOBAL_DBDIR,coin->symbol,bp->bundleheight);
                OS_removefile(fname,0);
                sprintf(fname,"%s/%s/accounts/lastspends.%d",GLOBAL_DBDIR,coin->symbol,bp->bundleheight);
                OS_removefile(fname,0);
                iguana_volatilesalloc(coin,&bp->ramchain,0);//i < hdrsi);
                //iguana_Xspendmap(coin,&bp->ramchain,bp);
            }
        printf("accounts files purged\n");
        sleep(3);
        for (hdrsi=0; hdrsi<max; hdrsi++)
        {
            if ( (bp= coin->bundles[hdrsi]) != 0 )
            {
                if ( bp != coin->current )
                {
                    //iguana_ramchain_prefetch(coin,&bp->ramchain,3);
                    if ( iguana_balancegen(coin,0,bp,0,coin->chain->bundlesize-1,0) == 0 )
                    {
                        fprintf(stderr,"%d ",hdrsi);
                        bp->balancefinish = (uint32_t)time(NULL);
                    }
                    else printf("balancegen error.[%d]\n",bp->hdrsi);
                }
            } else printf("null bp.[%d]\n",hdrsi);
        }
        //if ( max != coin->origbalanceswritten )
        {
            coin->balanceflush = max+1;
            while ( coin->balanceflush != 0 )
                sleep(3);
        }// else printf("skip flush when max.%d and orig.%d\n",max,coin->origbalanceswritten);
    }
    else
    {
        for (i=0; i<max; i++)
            if ( (bp= coin->bundles[i]) != 0 && bp != coin->current )
            {
                iguana_volatilespurge(coin,&bp->ramchain);
                iguana_volatilesmap(myinfo,coin,&bp->ramchain);
            }
    }
}

int32_t iguana_utxogen(struct supernet_info *myinfo,struct iguana_info *coin,int32_t helperid,int32_t convertflag)
{
    int32_t hdrsi,n,i,max,incr,num = 0; struct iguana_bundle *bp;
    if ( coin->spendvectorsaved > 1 )
    {
        printf("skip utxogen as spendvectorsaved.%u\n",coin->spendvectorsaved);
        return(0);
    }
    incr = IGUANA_NUMHELPERS;
    max = coin->bundlescount;
    if ( coin->bundles[max-1] == coin->current || coin->bundles[max-1] == 0 || (coin->bundles[max-1] != 0 && coin->bundles[max-1]->utxofinish <= 1) )
        max--;
    //printf("helperid.%d start %s utxogen bundlescount.%d max.%d\n",helperid,coin->symbol,coin->bundlescount,max);
    if ( helperid < incr )
    {
        for (hdrsi=helperid; hdrsi<max; hdrsi+=incr)
        {
            coin->bundles[hdrsi]->utxofinish = 1;
            num += iguana_helperA(myinfo,coin,helperid,coin->bundles[hdrsi],convertflag);
        }
    }
    while ( (n= iguana_utxofinished(coin)) < max )
    {
        printf("helperid.%d %s utxofinished.%d vs %d\n",helperid,coin->symbol,n,max);
        sleep(IGUANA_NUMHELPERS+3);
    }
    /*if ( helperid < incr )
    {
        for (hdrsi=helperid; hdrsi<max; hdrsi+=incr)
        {
            if ( (bp= coin->bundles[hdrsi]) == 0 )
            {
                printf("unexpected null bp for [%d]\n",hdrsi);
                continue;
            }
            if ( iguana_bundlevalidate(myinfo,coin,bp,0) != bp->n )
            {
                printf("validate.[%d] error. refresh page or restart iguana and it should regenerate\n",bp->hdrsi);
     iguana_exit(myinfo);
            } // else printf("%s helperid.%d validated.[%d]\n",coin->symbol,helperid,hdrsi);
        }
    }
    while ( iguana_validated(coin) < max || iguana_utxofinished(coin) < max )
    {
        printf("%s helperid.%d waiting for spendvectorsaved.%u v.%d u.%d b.%d vs max.%d\n",coin->symbol,helperid,coin->spendvectorsaved,iguana_validated(coin),iguana_utxofinished(coin),iguana_balancefinished(coin),max);
        sleep(2*IGUANA_NUMHELPERS+3);
    }*/
    if ( convertflag == 0 )
    {
        if ( helperid < incr )
        {
            for (hdrsi=helperid; hdrsi<max; hdrsi+=incr)
                num += iguana_helperB(coin,helperid,coin->bundles[hdrsi],convertflag);
        }
        while ( (n= iguana_convertfinished(coin)) < max )
        {
            //printf("helperid.%d convertfinished.%d vs max %d bundlescount.%d\n",helperid,n,max,coin->bundlescount);
            sleep(IGUANA_NUMHELPERS+3);
        }
    }
    if ( helperid == 0 )
    {
        printf("%s start iguana_update_balances\n",coin->symbol);
        iguana_update_balances(myinfo,coin);
        printf("%s iguana_update_balances completed\n",coin->symbol);
        if ( 1 )
        {
            for (i=0; i<max; i++)
                if ( (bp= coin->bundles[i]) != 0 )
                {
                    iguana_volatilespurge(coin,&bp->ramchain);
                    iguana_volatilesmap(myinfo,coin,&bp->ramchain);
                }
        }
    }
    while ( iguana_balancefinished(coin) < max || coin->balanceflush != 0 )
        sleep(3);
    //printf("helper.%d check validates\n",helperid);
    //incr = IGUANA_NUMHELPERS;
    //incr = 1;
    if ( helperid == 0 )
    {
        coin->spendvectorsaved = (uint32_t)time(NULL);
        coin->spendvalidated = 0;
        printf("%s UTXOGEN spendvectorsaved <- %u\n",coin->symbol,coin->spendvectorsaved);
        if ( iguana_utxoaddr_gen(myinfo,coin,(coin->bundlescount - 1) * coin->chain->bundlesize) == 0 )
        {
            printf("retry utxoaddr_gen\n");
            if ( iguana_utxoaddr_gen(myinfo,coin,(coin->bundlescount - 1) * coin->chain->bundlesize) == 0 )
            {
                printf("restart iguana: fatal error generating ledger file for %s\n",coin->symbol);
                iguana_exit(myinfo,0);
            }
        }
    }
    else
    {
        while ( coin->spendvectorsaved <= 1 )
            sleep(IGUANA_NUMHELPERS+3);
    }
    printf("%s helper.%d helperdone\n",coin->symbol,helperid);
    return(num);
}

int32_t iguana_coin_mainiter(struct supernet_info *myinfo,struct iguana_info *coin,int32_t *numpeersp,struct OS_memspace *mem,struct OS_memspace *memB)
{
    int32_t n,j,isRT = 0; struct iguana_bundle *bp;
    if ( coin->RTheight == 0 && coin->firstRTheight == 0 && coin->current != 0 && coin->active != 0 && coin->started != 0 )
    {
        isRT *= (coin->RTheight > 0);
        if ( coin->peers != 0 )
            *numpeersp += coin->peers->numranked;
        if ( (0) && (rand() % 10) == 0 )
            printf("%s main.%u vs %u, svs %u %d vs %d\n",coin->symbol,(uint32_t)time(NULL),coin->startutc+10,coin->spendvectorsaved ,coin->blocks.hwmchain.height/coin->chain->bundlesize,(coin->longestchain-coin->minconfirms)/coin->chain->bundlesize);
        if ( time(NULL) > coin->startutc+60 )
        {
            //if ( (bp= coin->current) != 0 && bp->numsaved >= coin->chain->bundlesize && bp->startutxo == 0 )
            //    iguana_bundlefinalize(myinfo,coin,bp,mem,memB);
            n = coin->bundlescount-1;
            if ( coin->matchedfiles == 0 && coin->spendvectorsaved == 0 && coin->blocks.hwmchain.height/coin->chain->bundlesize >= (coin->longestchain-coin->chain->bundlesize)/coin->chain->bundlesize )
            {
                //printf("%s n.%d emitfinished.%d coin->spendvectorsaved %d\n",coin->symbol,n,iguana_emitfinished(myinfo,coin,1),coin->spendvectorsaved);
                if ( iguana_emitfinished(myinfo,coin,1) >= n )
                {
                    /*if ( coin->PREFETCHLAG >= 0 && coin->fastfind == 0 )
                    {
                        for (j=0; j<n; j++)
                            if ( coin->bundles[j] != 0 )
                                iguana_alloctxbits(coin,&coin->bundles[j]->ramchain);
                        sleep(3);
                    }*/
                    if ( iguana_utxofinished(coin) < n )//|| iguana_balancefinished(coin) < n || iguana_validated(coin) < n) )
                    {
                        //printf("About to generate tables\n"), getchar();
                        iguana_fastfindreset(coin);
                        iguana_fastfindcreate(coin);
                        if ( coin->fastfind == 0 )
                        {
                            for (j=0; j<n; j++)
                                if ( coin->bundles[j] != 0 )
                                    iguana_alloctxbits(coin,&coin->bundles[j]->ramchain);
                            sleep(3);
                        }
                        coin->spendvectorsaved = 1;
                        printf("update volatile data, need.%d vs utxo.%d balances.%d validated.%d\n",n,iguana_utxofinished(coin),iguana_balancefinished(coin),iguana_validated(coin));
                    }
                    else
                    {
                        iguana_update_balances(myinfo,coin);
                        coin->spendvectorsaved = (uint32_t)time(NULL);
                        printf("already done UTXOGEN (%d %d %d) n.%d\n",iguana_utxofinished(coin),iguana_validated(coin),iguana_balancefinished(coin),n);
                    }
                }
            }
        }
        if ( (bp= coin->current) != 0 && coin->stucktime != 0 && coin->isRT == 0 && coin->RTheight == 0 && (time(NULL) - coin->stucktime) > coin->MAXSTUCKTIME )
        {
            if ( (0) )
            {
                printf("%s is stuck too long, restarting due to %d\n",coin->symbol,bp->hdrsi);
                if ( coin->started != 0 )
                {
                    iguana_coinpurge(coin);
                    sleep(3);
                    while ( coin->started == 0 )
                    {
                        printf("wait for coin to reactivate\n");
                        sleep(1);
                    }
                    sleep(3);
                }
            }
        }
    }
    return(isRT);
}

void iguana_helper(void *arg)
{
    static uint64_t helperidbits;
    cJSON *argjson=0; int32_t iter,n,i,j,retval,numpeers,polltimeout,type,helperid=rand(),flag,allcurrent,idle=0;
    struct iguana_helper *ptr; struct iguana_info *coin,*tmp; struct OS_memspace MEM,*MEMB; struct iguana_bundle *bp; struct supernet_info *myinfo = SuperNET_MYINFO(0);
    helperid %= 64;
    if ( arg != 0 && (argjson= cJSON_Parse(arg)) != 0 )
        helperid = juint(argjson,"helperid");
    if ( ((1 << helperid) & helperidbits) != 0 )
    {
        printf("SKIP duplicate helper.%d\n",helperid);
        return;
    }
    helperidbits |= (1 << helperid);
    if ( IGUANA_NUMHELPERS < 2 )
        type = 3;
    else type = (1 << (helperid % 2));
    if ( argjson != 0 )
        free_json(argjson);
    printf("HELPER.%d started arg.(%s) type.%d\n",helperid,(char *)(arg!=0?arg:0),type);
    memset(&MEM,0,sizeof(MEM));
    MEMB = mycalloc('b',IGUANA_MAXBUNDLESIZE,sizeof(*MEMB));
    sleep(2);
    while ( 1 )
    {
        //printf("helperid.%d top of loop\n",helperid);
        flag = 0;
        allcurrent = 1;
        polltimeout = 100;
        //portable_mutex_lock(&myinfo->allcoins_mutex);
        numpeers = 0;
        HASH_ITER(hh,myinfo->allcoins,coin,tmp)
        {
            if ( coin->firstRTheight == 0 )
            {
                if ( coin->spendvectorsaved == 1 )//&& coin->chain->zcash == 0 )
                    iguana_utxogen(myinfo,coin,helperid,1);
                else if ( coin->spendvectorsaved > 1 && (coin->spendvalidated & (1 << helperid)) == 0 )
                {
                    //printf("%s spendvectorsaved.%u helperid.%d validate\n",coin->symbol,coin->spendvectorsaved,helperid);
                    for (j=helperid; j<coin->bundlescount-1; j+=IGUANA_NUMHELPERS)
                        if ( (bp= coin->bundles[j]) != 0 )
                            iguana_bundlevalidate(myinfo,coin,bp,0);
                    coin->spendvalidated |= (1 << helperid);
                    //printf("DONE %s spendvectorsaved.%u helperid.%d validate\n",coin->symbol,coin->spendvectorsaved,helperid);
                }
                else
                {
                    for (j=helperid; j<coin->bundlescount; j+=IGUANA_NUMHELPERS)
                    {
                        if ( (bp= coin->bundles[j]) != 0 )
                        {
                            if ( bp->emitfinish == 0 && bp->numsaved >= coin->chain->bundlesize && iguana_bundleready(myinfo,coin,bp,0) == bp->n )
                                iguana_bundlefinalize(myinfo,coin,bp,&MEM,MEMB);
                            if ( bp->emitfinish != 0 && time(NULL) > bp->emitfinish+60 )
                            {
                                if ( bp->validated == 0 )
                                {
                                    for (i=0; i<j; i++)
                                        if ( coin->bundles[i] == 0 || coin->bundles[i]->validated <= 1 )
                                            break;
                                    if ( i == j )
                                        iguana_bundlevalidate(myinfo,coin,bp,0);
                                }
                                if ( bp->validated > 1 )//&& coin->chain->zcash == 0 )
                                {
                                    for (i=0; i<j; i++)
                                        if ( coin->bundles[i] == 0 || coin->bundles[i]->utxofinish <= 1 )
                                            break;
                                    retval = 1;
                                    if ( bp->utxofinish == 0 )
                                    {
                                        bp->startutxo = (uint32_t)time(NULL);
                                        if ( (retval= iguana_spendvectors(myinfo,coin,bp,&bp->ramchain,0,bp->n,1,0)) >= 0 )
                                        {
                                            if ( retval > 0 )
                                            {
                                                printf("  GENERATED UTXO.%d for ht.%d duration %d seconds\n",bp->hdrsi,bp->bundleheight,(uint32_t)time(NULL) - bp->startutxo);
                                                bp->utxofinish = (uint32_t)time(NULL);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if ( (helperid % IGUANA_NUMHELPERS) == (coin->coinid % IGUANA_NUMHELPERS) )
                    iguana_coin_mainiter(myinfo,coin,&numpeers,&MEM,MEMB);
            }
        }
        //portable_mutex_unlock(&myinfo->allcoins_mutex);
        n = queue_size(&bundlesQ);
        for (iter=0; iter<n; iter++)
        {
            if ( (ptr= queue_dequeue(&bundlesQ)) != 0 )
            {
                idle = 0;
                coin = ptr->coin;
                if ( (bp= ptr->bp) != 0 && coin != 0 )
                {
                    if ( coin->polltimeout < polltimeout )
                        polltimeout = coin->polltimeout;
                    if ( coin->current != 0 && coin->current->hdrsi != coin->bundlescount-1 )
                        allcurrent = 0;
                    //printf("h.%d [%d] bundleQ size.%d lag.%ld\n",helperid,bp->hdrsi,queue_size(&bundlesQ),time(NULL) - bp->nexttime);
                    coin->numbundlesQ--;
                    if ( bp->startutxo == 0 && coin->started != 0 && time(NULL) > bp->nexttime && coin->active != 0 )
                    {
                        flag += iguana_bundleiters(myinfo,ptr->coin,&MEM,MEMB,bp,ptr->timelimit,IGUANA_DEFAULTLAG);
                    }
                    else
                    {
                        //printf("skip.[%d] nexttime.%u lag.%ld coin->active.%d\n",bp->hdrsi,bp->nexttime,time(NULL)-bp->nexttime,coin->active);
                        allcurrent--;
                        iguana_bundleQ(myinfo,coin,bp,1000);
                    }
                }
                else //if ( coin->active != 0 )
                    printf("helper missing param? %p %p %u\n",ptr->coin,bp,ptr->timelimit);
                myfree(ptr,ptr->allocsize);
            } else break;
        }
        if ( queue_size(&bundlesQ) > 1 )
            allcurrent = 0;
        if ( flag != 0 )
            usleep(polltimeout * 100 + 1);
        else if ( allcurrent > 0 )
        {
            //printf("bundlesQ allcurrent\n");
            usleep(polltimeout * 10000);
        } else usleep(polltimeout * 10000);
    }
}

void iguana_callcoinstart(struct supernet_info *myinfo,struct iguana_info *coin)
{
    struct iguana_bundle *bp; struct iguana_peer *addr; int32_t bundlei; bits256 zero; char dirname[512],*symbol;
    iguana_rwiAddrind(coin,0,0,0);
    //for (i=0; i<sizeof(*coin->chain); i++)
    //    printf("%02x",((uint8_t *)coin->chain)[i]);
    char str[65]; printf(" netmagic.%08x init.(%s) maxpeers.%d maxrecvcache.%s services.%llx MAXMEM.%s polltimeout.%d cache.%d pend.(%d -> %d)\n",*(uint32_t *)coin->chain->netmagic,coin->symbol,coin->MAXPEERS,mbstr(str,coin->MAXRECVCACHE),(long long)coin->myservices,mbstr(str,coin->MAXMEM),coin->polltimeout,coin->enableCACHE,coin->startPEND,coin->endPEND);
    symbol = coin->symbol;
    sprintf(dirname,"%s/ro",GLOBAL_DBDIR), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/ro/%s",GLOBAL_DBDIR,symbol), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/%s",GLOBAL_DBDIR,symbol), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/purgeable/%s",GLOBAL_DBDIR,symbol), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/%s/validated",GLOBAL_DBDIR,symbol), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/%s/accounts",GLOBAL_DBDIR,symbol), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/%s/spends",GLOBAL_DBDIR,symbol), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/%s/vouts",GLOBAL_DBDIR,symbol), OS_ensure_directory(dirname);
    if ( coin->VALIDATEDIR[0] != 0 )
    {
        sprintf(dirname,"%s",coin->VALIDATEDIR), OS_ensure_directory(dirname);
        sprintf(dirname,"%s/%s",coin->VALIDATEDIR,symbol), OS_ensure_directory(dirname);
    }
    sprintf(dirname,"%s/%s",GLOBAL_TMPDIR,symbol), OS_ensure_directory(dirname);
    sprintf(dirname,"%s/%s/RT",GLOBAL_TMPDIR,coin->symbol), OS_ensure_directory(dirname);
    printf("CALL MARKINIT.%s\n",coin->symbol);
    iguana_unspents_markinit(myinfo,coin);
    iguana_coinstart(myinfo,coin,coin->initialheight,coin->mapflags);
    coin->chain->minconfirms = coin->minconfirms;
    coin->started = coin;
    coin->startutc = (uint32_t)time(NULL);
    memset(zero.bytes,0,sizeof(zero));
    if ( (bp= iguana_bundlecreate(coin,&bundlei,0,*(bits256 *)coin->chain->genesis_hashdata,zero,1)) != 0 )
        bp->bundleheight = 0;
    if ( coin->FULLNODE != 0 )
        coin->notarychain = -1;
    addr = &coin->peers->active[IGUANA_MAXPEERS-2];
    iguana_initpeer(coin,addr,(uint32_t)calc_ipbits(coin->seedipaddr));
    printf("SEED_IPADDR initpeer.(%s) notarychain.%d\n",addr->ipaddr,coin->notarychain);
    iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
}

void iguana_coinloop(void *arg)
{
    struct supernet_info *myinfo; int32_t flag,i,j,n; struct iguana_peer *addr; bits256 zero; uint32_t now; struct iguana_info *coin,**coins = arg;
    myinfo = SuperNET_MYINFO(0);
    n = (int32_t)(long)coins[0];
    coins++;
    coin = coins[0];
    if ( (coin->notarychain= iguana_isnotarychain(coin->symbol)) >= 0 )
    {
        coin->VALIDATENODE = 0;
        coin->DEXEXPLORER = myinfo->DEXEXPLORER;
    }
    //if ( coin->FULLNODE > 0 )
    //    coin->notarychain = -1;
    printf("begin coinloop[%d] %s notarychain.%d DEXEXPLORER.%d\n",n,coin->symbol,coin->notarychain,coin->DEXEXPLORER);
    memset(zero.bytes,0,sizeof(zero));
    while ( 1 )
    {
        flag = 0;
        for (i=0; i<n; i++)
        {
            if ( (coin= coins[i]) != 0 )
            {
                if ( coin->didaddresses == 0 )
                {
                    coin->didaddresses = 1;
                    if ( coin->notarychain >= 0 && myinfo->IAMNOTARY != 0 )
                        init_alladdresses(myinfo,coin);
                }
                if ( coin->FULLNODE < 0 )//|| (coin->notarychain >= 0 && coin->FULLNODE == 0) )
                {
                    continue;
                }
                /*if ( strcmp(coin->symbol,"RELAY") == 0 )
                {
                    if ( myinfo->expiration != 0 && (myinfo->IAMLP != 0 || myinfo->DEXactive > now) )
                        basilisk_requests_poll(myinfo);
                }*/
                if ( n > 1 && coin->RTheight > 0 && (rand() % 10) != 0 )
                    continue;
                if ( coin->peers == 0 )
                {
                    printf("FATAL lack of peers struct\n");
                    iguana_exit(myinfo,0);
                }
                if ( coin->virtualchain == 0 )
                {
                    if ( coin->MAXPEERS > IGUANA_MAXPEERS )
                        coin->MAXPEERS = IGUANA_MAXPEERS;
                    if ( coin->MAXPEERS > 1 && coin->MAXPEERS < IGUANA_MINPEERS )
                        coin->MAXPEERS = IGUANA_MAXPEERS;
#ifdef __PNACL__
                    if ( coin->MAXPEERS > 64 )
                        coin->MAXPEERS = 64;
#endif
                }
                if ( coin->started == 0 && coin->active != 0 )
                {
                    iguana_callcoinstart(myinfo,coin);
                    /*if ( 0 && strcmp("BTC",coin->symbol) == 0 )
                    {
                        char *txstr = "0100000001d378ebd1b0c230b4d078288cf95fe28d7b3032d28c47de22ed6140d845dcb01f00000000d147304402204dd322834ff15cf1526dae3940521bb504b365b194515725d9c0f81dfbeae68d02205fb8fd269e3f2ddf7d0a17b056d2904ce572b8f22edeb39cd4c209fcf5244645011d74c7e7d8a2041be600e74708276d79ff001e754269b6e868ccf517f87f3d004c674c6763040cd6e557b175210326af93b75917b4903d7acdf8e2a560357ce18b7615cc7de02ade4f62861a57dfac67a9149c41c06aac6a7fcfd29eef87c4a633b9126b8b09882102a9669e63ef1ab04913615c2f3887ea3584f81e5f08feee9535b19ab3739d8afdac68ffffffff01127b0000000000001976a914b7128d2ee837cf03e30a2c0e3e0181f7b9669bb688ac00000000";
                        cJSON *txobj = cJSON_Parse("{\"version\":1,\"locktime\":1474666158,\"vin\":[{\"userdata\":\"51\",\"txid\":\"fc97c3675c83c09723e0b14292ddec73820cb7352166ace4fe81ed62568315f2\",\"vout\":0,\"scriptPubKey\":{\"hex\":\"a914b7a2e599edb55d3f78ebcbfd49e82dd9a12adc2487\"},\"suppress\":1,\"sequence\":0,\"redeemScript\":\"6304ae9ee557b1752102a9669e63ef1ab04913615c2f3887ea3584f81e5f08feee9535b19ab3739d8afdac67a914adfad35d6646a0514011ba6ab53462319b651f96882103225046c9947222ab04acdefe2ed5dec4dcb593c5e6ae58e2c61c7ace14d81b70ac68\"}],\"vout\":[{\"satoshis\":\"36042\",\"scriptPubkey\":{\"hex\":\"76a914b7128d2ee837cf03e30a2c0e3e0181f7b9669bb688ac\"}}]}");
                        cJSON *txobj4 = cJSON_Parse("{\"version\":1,\"locktime\":0,\"timestamp\":1474721847,\"vin\":[{\"txid\":\"a18e779a1daf22e9c427dc01dea0c268345a6b619da2eb7cdefd692719bdafdc\",\"vout\":0,\"scriptPubKey\":{\"hex\":\"a9149a8254cc4499a340209e7ca699fe6a096f79b31087\"},\"suppress\":1,\"redeemScript\":\"522102f563272bd62384d1813c1d30e774e6da6efa5822178a3ab64d6f3ed9e4cfb77e210387edb0a5895e772788c3e010b46c6145a0bafe862f098d6b74dc2f443408827b52ae\"}],\"vout\":[{\"satoshis\":\"9990000\",\"scriptPubkey\":{\"hex\":\"76a9148ee61a3161993f4f7b7081259bf5f3322d65d3f888ac\"}}]}");
                        cJSON *privkeys = cJSON_Parse("[\"UwqPATeGVau5GeevspxCsvjnusCrEkU8To8NKLv91GU4mbZCQKeT\", \"Uu4AEVHrgFv4trDfj24kDTgKhaEdDkV7sNpH8MgTKTxEATF9YEcv\"]");
                        cJSON *txobj2 = cJSON_Parse("{\"version\":1,\"locktime\":0,\"vin\":[{\"userdata\":\"20491d74c7e7d8a2041be600e74708276d79ff001e754269b6e868ccf517f87f3d00\",\"txid\":\"1fb0dc45d84061ed22de478cd232307b8de25ff98c2878d0b430c2b0d1eb78d3\",\"vout\":0,\"scriptPubKey\":{\"hex\":\"a9144bf88c2ce8b9a40e3863bf1d4a5fb443d3e1bfe487\"},\"suppress\":1,\"redeemScript\":\"63040cd6e557b175210326af93b75917b4903d7acdf8e2a560357ce18b7615cc7de02ade4f62861a57dfac67a9149c41c06aac6a7fcfd29eef87c4a633b9126b8b09882102a9669e63ef1ab04913615c2f3887ea3584f81e5f08feee9535b19ab3739d8afdac68\"}],\"vout\":[{\"satoshis\":\"31506\",\"scriptPubkey\":{\"hex\":\"76a914b7128d2ee837cf03e30a2c0e3e0181f7b9669bb688ac\"}}]}");
                        cJSON *txobj3 = cJSON_Parse("{\"version\":1,\"timestamp\":1474672690,\"vin\":[{\"sequence\":4294967214,\"txid\":\"119ec1a65f530c751e53b4af0505e960cf47680859c5f3ee3981ebe883207186\",\"vout\":0,\"scriptSig\":{\"hex\":\"483045022100880a1e3eafade4d4a24dd0bde2f31178d43978beacd63da1ee54760e0651f3b2022061dd05a66b65dc40fb729d95d2205dbf054ceb0bc4eb55c42088d0684a4c5a6701483045022100b4498798fc3a61de0b6df83ea4f6b67f89c5683124c2a3a981bd070826d7d1590220121d73d362b796583baa73c8c78eb851f78dc8f1cc75cb5bb3dfb14d6b843742012102ed1e99e73093c70c6156bce5954cb3e04215405ac06aa525ff942b74b8416efc2103a013a5f01afb3f0f00a657bb76fb30fd38437c80b52d9248b50738c96902e78747522102ed1e99e73093c70c6156bce5954cb3e04215405ac06aa525ff942b74b8416efc2103a013a5f01afb3f0f00a657bb76fb30fd38437c80b52d9248b50738c96902e78752ae\",\"asm\":\"3045022100880a1e3eafade4d4a24dd0bde2f31178d43978beacd63da1ee54760e0651f3b2022061dd05a66b65dc40fb729d95d2205dbf054ceb0bc4eb55c42088d0684a4c5a6701 3045022100b4498798fc3a61de0b6df83ea4f6b67f89c5683124c2a3a981bd070826d7d1590220121d73d362b796583baa73c8c78eb851f78dc8f1cc75cb5bb3dfb14d6b84374201 02ed1e99e73093c70c6156bce5954cb3e04215405ac06aa525ff942b74b8416efc 03a013a5f01afb3f0f00a657bb76fb30fd38437c80b52d9248b50738c96902e787 522102ed1e99e73093c70c6156bce5954cb3e04215405ac06aa525ff942b74b8416efc2103a013a5f01afb3f0f00a657bb76fb30fd38437c80b52d9248b50738c96902e78752ae\"}}],\"numvins\":1}");
                        cJSON *txobj5 = cJSON_Parse("{\"version\":1,\"locktime\":0,\"vin\":[{\"userdata\":\"204b0b2033ca8888a52554e0312f72849c72897ef8500e6019a46fd9e51e39816d00\",\"txid\":\"e4a22b8f7d63ed1cdcece6269acde409c2f6d473595f22875baf64b686762ce1\",\"vout\":0,\"scriptPubKey\":{\"hex\":\"a91478d98e781618f50be5fa6e340aba02026737888487\"},\"suppress\":1,\"redeemScript\":\"63048615e757b1752102a9669e63ef1ab04913615c2f3887ea3584f81e5f08feee9535b19ab3739d8afdac67a91417f583c86c4ea3d7cd7776b1ac95fb430722a6f3882103225046c9947222ab04acdefe2ed5dec4dcb593c5e6ae58e2c61c7ace14d81b70ac68\"}],\"vout\":[{\"satoshis\":\"36010\",\"scriptPubkey\":{\"hex\":\"76a9148ee61a3161993f4f7b7081259bf5f3322d65d3f888ac\"}}]}");
                        cJSON *txobj7 = cJSON_Parse("{\"version\":1,\"locktime\":0,\"vin\":[{\"userdata\":\"204b0b2033ca8888a52554e0312f72849c72897ef8500e6019a46fd9e51e39816d00\",\"txid\":\"e4a22b8f7d63ed1cdcece6269acde409c2f6d473595f22875baf64b686762ce1\",\"vout\":0,\"scriptPubKey\":{\"hex\":\"a91478d98e781618f50be5fa6e340aba02026737888487\"},\"suppress\":1,\"redeemScript\":\"63048615e757b1752102a9669e63ef1ab04913615c2f3887ea3584f81e5f08feee9535b19ab3739d8afdac67a91417f583c86c4ea3d7cd7776b1ac95fb430722a6f3882103225046c9947222ab04acdefe2ed5dec4dcb593c5e6ae58e2c61c7ace14d81b70ac68\"}],\"vout\":[{\"satoshis\":\"36010\",\"scriptPubkey\":{\"hex\":\"76a9148ee61a3161993f4f7b7081259bf5f3322d65d3f888ac\"}}]}");
                        //0100000001e12c7686b664af5b87225f5973d4f6c209e4cd9a26e6ecdc1ced637d8f2ba2e400000000d147304402200c7c428181b4a87f60e6a6a40dc14000a54e4286dc0c2c72a5f7b649591144d102206b7b376190e857c18c5764070e9d378b09aa0405cda691a1b68df7a2a6ccc2da01204b0b2033ca8888a52554e0312f72849c72897ef8500e6019a46fd9e51e39816d004c6763048615e757b1752102a9669e63ef1ab04913615c2f3887ea3584f81e5f08feee9535b19ab3739d8afdac67a91417f583c86c4ea3d7cd7776b1ac95fb430722a6f3882103225046c9947222ab04acdefe2ed5dec4dcb593c5e6ae58e2c61c7ace14d81b70ac68ffffffff01aa8c0000000000001976a9148ee61a3161993f4f7b7081259bf5f3322d65d3f888ac00000000
                        struct vin_info V[3]; int32_t completed; char *signedtx; bits256 txid,signedtxid,checktxid; uint8_t *extraspace; struct iguana_info *coin = iguana_coinfind("BTC");
                        memset(V,0,sizeof(V));
                        cJSON *tx = txobj7;
                        char *txbytes = bitcoin_json2hex(myinfo,coin,&txid,tx,V);
                        printf("rawtx.(%s)\n",txbytes);
                        extraspace = calloc(1,65536);
                        txobj = bitcoin_hex2json(coin,coin->blocks.hwmchain.height,&checktxid,0,txbytes,extraspace,65536,0,jobj(tx,"vin"),1);
                        printf("\nTXOBJ.(%s)\n\n",jprint(txobj,0));
                        if ( (signedtx= iguana_signrawtx(myinfo,coin,1000000,&signedtxid,&completed,jobj(txobj,"vin"),txbytes,privkeys,V)) != 0 )
                            printf("signedtx.(%s)\n",signedtx);
                        free(extraspace);
                        //getchar();
                    }*/
                }
                now = (uint32_t)time(NULL);
                coin->idletime = 0;
                if ( coin->started != 0 && coin->active != 0 && (coin->notarychain < 0 || coin->FULLNODE == 0) )
                {
                    //printf("%s numranked.%d isRT.%d numsaved.%d M.%d L.%d numverified.%d hdrsi.%d\n",coin->symbol,coin->peers->numranked,coin->isRT,coin->numsaved,coin->blocks.hwmchain.height,coin->longestchain,coin->numverified,coin->current!=0?coin->current->hdrsi:-1);
                    if ( coin->peers->numranked > 4 && coin->isRT == 0 && now > coin->startutc+77 && coin->numsaved >= (coin->longestchain/coin->chain->bundlesize)*coin->chain->bundlesize && coin->blocks.hwmchain.height >= coin->longestchain-30 )
                    {
                        //fprintf(stderr,">>>>>>> %s isRT blockrecv.%d.%d\n",coin->symbol,coin->blocksrecv,coin->longestchain);
                        //coin->isRT = 1;
                        if ( coin->polltimeout > 100 )
                            coin->polltimeout = 100;
                        if ( coin->MAXPEERS > IGUANA_MINPEERS )
                            coin->MAXPEERS = IGUANA_MINPEERS;
                    }
                    if ( myinfo->NOTARY.RELAYID < 0 )
                    {
                        if ( coin->bindsock >= 0 )
                        {
                            if ( coin->MAXPEERS > 1 && coin->peers->numranked < IGUANA_MAXPEERS/2 && now > coin->lastpossible+2 )
                            {
                                //fprintf(stderr,"check possible\n");
                                if ( coin->peers->numranked > 0 && (now % 60) == 0 )
                                    iguana_send_ping(myinfo,coin,coin->peers->ranked[rand() % coin->peers->numranked]);
                                coin->lastpossible = iguana_possible_peer(coin,0); // tries to connect to new peers
                            }
                        }
                        else
                        {
                            if ( coin->MAXPEERS > 1 && coin->peers->numranked < ((7*coin->MAXPEERS)>>3) && now > coin->lastpossible+10 )
                            {
                                if ( coin->peers != 0 )
                                {
                                    for (j=0; j<IGUANA_MAXPEERS; j++)
                                    {
                                        i = rand() % IGUANA_MAXPEERS;
                                        addr = &coin->peers->active[(i+j) % IGUANA_MAXPEERS];
                                        if ( addr->usock >= 0 && addr->msgcounts.verack == 0 )
                                        {
                                            //printf("i.%d j.%d mainloop %s\n",i,j,addr->ipaddr);
                                            iguana_send_version(coin,addr,coin->myservices);
                                            break;
                                        }
                                    }
                                }
                                if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
                                {
                                    if ( coin->peers->numranked > 0 )
                                        iguana_send_ping(myinfo,coin,coin->peers->ranked[rand() % coin->peers->numranked]);
                                }
                                coin->lastpossible = iguana_possible_peer(coin,0); // tries to connect to new peers
                            }
                        }
                        if ( coin->MAXPEERS > 1 && now > coin->peers->lastmetrics+10 )
                        {
                            coin->peers->lastmetrics = iguana_updatemetrics(myinfo,coin); // ranks peers
                        }
                    }
                    if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 || coin->MAXPEERS == 1 )
                    {
                        //portable_mutex_lock(&coin->allcoins_mutex);
                        coin->busy_processing = 1;
                        flag += iguana_processrecv(myinfo,coin);
                        coin->busy_processing = 0;
                        //portable_mutex_unlock(&coin->allcoins_mutex);
                        /*if ( strcmp(coin->symbol,"BTCD") == 0 && coin->RTheight > 0 && coin->RTheight > coin->chain->bundlesize )
                        {
                            int32_t hdrsi,nonz,errs; struct iguana_pkhash *refP; struct iguana_bundle *bp;
                            hdrsi = (coin->RTheight / coin->chain->bundlesize) - 1;
                            if ( 0 && (bp= coin->bundles[hdrsi]) != 0 && bp->weights == 0 )
                                bp->weights = iguana_PoS_weights(myinfo,coin,&refP,&bp->supply,&bp->numweights,&nonz,&errs,bp->bundleheight);
                        }*/
                    }
                }
                coin->idletime = (uint32_t)time(NULL);
                iguana_jsonQ(myinfo,coin);
            }
        }
        //iguana_jsonQ();
        //printf("%s flag.%d isRT.%d polltimeout.%d numranked.%d\n",coin->symbol,flag,coin->isRT,coin->polltimeout,coin->peers->numranked);
        /*if ( flag == 0 && coin->isRT == 0 && coin->peers != 0 )
            usleep(coin->polltimeout*1000 + (coin->peers->numranked == 0)*1000000);
        else if ( coin->current != 0 && coin->current->hdrsi == coin->longestchain/coin->chain->bundlesize )
            usleep(coin->polltimeout*5000 + 90000 + (coin->peers->numranked == 0)*1000000);
        else usleep(coin->polltimeout*1000);*/
        if ( flag == 0 )
            usleep(100000);
    }
}

void iguana_coinargs(char *symbol,int64_t *maxrecvcachep,int32_t *minconfirmsp,int32_t *maxpeersp,int32_t *initialheightp,uint64_t *servicesp,int32_t *maxrequestsp,int32_t *maxbundlesp,cJSON *json)
{
    if ( (*maxrecvcachep= j64bits(json,"maxrecvcache")) != 0 )
        *maxrecvcachep *= 1024 * 1024 * 1024L;
    *minconfirmsp = juint(json,"minconfirms");
    *maxpeersp = juint(json,"maxpeers");
    *maxrequestsp = juint(json,"maxrequests");
    *maxbundlesp = juint(json,"maxbundles");
    if ( (*initialheightp= juint(json,"initialheight")) == 0 )
        *initialheightp = (strcmp(symbol,"BTC") == 0) ? 400000 : 100000;
    *servicesp = j64bits(json,"services");
}

void iguana_nameset(char name[64],char *symbol,cJSON *json)
{
    if ( strcmp("BTC",symbol) == 0 )
        strcpy(name,"Bitcoin");
    else if ( strcmp("BTCD",symbol) == 0 )
        strcpy(name,"BitcoinDark");
    else
    {
        name[0] = 0;
        if ( json != 0 )
            safecopy(name,jstr(json,"name"),64);
        if ( name[0] == 0 )
            strcpy(name,symbol);
    }
}

struct iguana_info *iguana_setcoin(char *symbol,void *launched,int32_t maxpeers,int64_t maxrecvcache,uint64_t services,int32_t initialheight,int32_t maphash,int32_t minconfirms,int32_t maxrequests,int32_t maxbundles,cJSON *json,int32_t virtcoin)
{
    struct iguana_chain *iguana_createchain(cJSON *json);
    struct supernet_info *myinfo = SuperNET_MYINFO(0);
    struct iguana_info *coin; int32_t j,m,mult,maxval,mapflags; char name[64]; cJSON *peers;
    mapflags = IGUANA_MAPRECVDATA | maphash*IGUANA_MAPTXIDITEMS | maphash*IGUANA_MAPPKITEMS | maphash*IGUANA_MAPBLOCKITEMS | maphash*IGUANA_MAPPEERITEMS;
    iguana_nameset(name,symbol,json);
    if ( (coin= iguana_coinfind(symbol)) == 0 )
        coin = iguana_coinadd(symbol,name,json,virtcoin);
    //printf("ensure directories maxval.%d mult.%d start.%d end.%d\n",maxval,mult,coin->startPEND,coin->endPEND);
    mult = (strcmp("BTC",coin->symbol) != 0) ? 32 : 512;
    maxval = IGUANA_MAXPENDBUNDLES;
    if ( coin->virtualchain == 0 )
    {
        if ( (coin->MAXPEERS= maxpeers) <= 0 )
            coin->MAXPEERS = (strcmp(symbol,"BTC") == 0) ? 128 : 64;
        if ( (coin->MAXRECVCACHE= maxrecvcache) == 0 )
            coin->MAXRECVCACHE = IGUANA_MAXRECVCACHE;
        if ( (coin->MAXPENDINGREQUESTS= maxrequests) <= 0 )
            coin->MAXPENDINGREQUESTS = (strcmp(symbol,"BTC") == 0) ? IGUANA_BTCPENDINGREQUESTS : IGUANA_PENDINGREQUESTS;
        if ( jobj(json,"prefetchlag") != 0 )
            coin->PREFETCHLAG = jint(json,"prefetchlag");
        else if ( strcmp("BTC",coin->symbol) == 0 )
            coin->PREFETCHLAG = 13;
        else coin->PREFETCHLAG = -1;
        if ( (coin->MAXSTUCKTIME= juint(json,"maxstuck")) == 0 )
            coin->MAXSTUCKTIME = _IGUANA_MAXSTUCKTIME;
        if ( myinfo != 0 && myinfo->seedipaddr[0] != 0 )
            safecopy(coin->seedipaddr,myinfo->seedipaddr,sizeof(coin->seedipaddr));
        if ( (coin->startPEND= juint(json,"startpend")) == 0 )
        {
            if ( strcmp("BTCD",coin->symbol) == 0 )
                coin->startPEND = 500;
            else coin->startPEND = IGUANA_MAXPENDBUNDLES*mult;
        }
        if ( coin->startPEND > maxval*mult )
            coin->startPEND = maxval*mult;
        else if ( coin->startPEND < 2 )
            coin->startPEND = 2;
        coin->MAXBUNDLES = coin->startPEND;
        if ( (coin->endPEND= juint(json,"endpend")) == 0 )
        {
            if ( strcmp("BTCD",coin->symbol) == 0 )
                coin->endPEND = 500;
            else coin->endPEND = IGUANA_MINPENDBUNDLES*mult;
        }
        if ( coin->endPEND > maxval*mult )
            coin->endPEND = maxval*mult;
        else if ( coin->endPEND < 2 )
            coin->endPEND = 2;
#ifdef __PNACL__
        coin->startPEND =  coin->endPEND = 1;
#endif
    } else coin->MAXPEERS = 0;
    coin->notarychain = iguana_isnotarychain(coin->symbol);
    coin->myservices = services;
    coin->initialheight = initialheight;
    coin->mapflags = mapflags;
    coin->protocol = IGUANA_PROTOCOL_BITCOIN;
    if ( (coin->txfee= jdouble(json,"txfee") * SATOSHIDEN) == 0 )
        coin->txfee = 10000;
    if ( (coin->txfee_perkb= j64bits(json,"txfee_perkb")) < coin->txfee/8 )
        coin->txfee_perkb = coin->txfee / 8;
    coin->MAXMEM = juint(json,"RAM");
    if ( coin->MAXMEM == 0 )
        coin->MAXMEM = IGUANA_DEFAULTRAM;
    coin->MAXMEM *= (1024L * 1024 * 1024);
    coin->enableCACHE = 0;//(strcmp("BTCD",coin->symbol) == 0);
    if ( jobj(json,"cache") != 0 )
        coin->enableCACHE = juint(json,"cache");
    if ( (coin->polltimeout= juint(json,"poll")) <= 0 )
        coin->polltimeout = IGUANA_DEFAULT_POLLTIMEOUT;
    coin->active = juint(json,"active");
    if ( (coin->minconfirms= minconfirms) == 0 )
        coin->minconfirms = (strcmp(symbol,"BTC") == 0) ? 3 : 10;
    if ( jobj(json,"RELAY") != 0 )
        coin->FULLNODE = jint(json,"RELAY");
    else coin->FULLNODE = (strcmp(coin->symbol,"BTCD") == 0);
    if ( jobj(json,"VALIDATE") != 0 )
        coin->VALIDATENODE = juint(json,"VALIDATE");
    else coin->VALIDATENODE = (strcmp(coin->symbol,"BTCD") == 0);
    if ( coin->VALIDATENODE > 0 || coin->FULLNODE > 0 )
        SuperNET_MYINFO(0)->IAMRELAY++;
    if ( coin->chain == 0 && (coin->chain= iguana_createchain(json)) == 0 )
    {
        printf("cant initialize chain.(%s)\n",jstr(json,0));
        strcpy(coin->name,"illegalcoin");
        //if ( coin->FULLNODE >= 0 )
        //    coin->chain->userpass[0] = 0;
        coin->symbol[0] = 0;
        return(0);
    }
#ifdef __PNACL
    coin->VALIDATENODE = coin->FULLNODE = 0;
#endif
    if ( jobj(json,"validatedir") != 0 )
        safecopy(coin->VALIDATEDIR,jstr(json,"validatedir"),sizeof(coin->VALIDATEDIR));
    else strcpy(coin->VALIDATEDIR,GLOBAL_VALIDATEDIR);
    if ( (peers= jarray(&m,json,"peers")) != 0 )
    {
        for (j=0; j<m; j++)
        {
            printf("%s ",jstr(jitem(peers,j),0));
            iguana_possible_peer(coin,jstr(jitem(peers,j),0));
        }
        printf("addnodes.%d\n",m);
    }
    char str[65];
    if ( coin->virtualchain == 0 )
        printf("pend.(%d -> %d) MAXMEM.%s enablecache.%d VALIDATEDIR.(%s) VALIDATE.%d RELAY.%d\n",coin->startPEND,coin->endPEND,mbstr(str,coin->MAXMEM),coin->enableCACHE,coin->VALIDATEDIR,coin->VALIDATENODE,coin->FULLNODE);
    return(coin);
}

int32_t iguana_launchcoin(struct supernet_info *myinfo,char *symbol,cJSON *json,int32_t virtcoin)
{
    int32_t maxpeers,maphash,initialheight,minconfirms,maxrequests,maxbundles; char name[64]; int64_t maxrecvcache; uint64_t services; struct iguana_info **coins,*coin;
    if ( symbol == 0 )
        return(-1);
    if ( (coin= iguana_coinfind(symbol)) != 0 )
        return(0);
    iguana_nameset(name,symbol,json);
    printf("launchcoin.%s name.%s\n",symbol,name);
    if ( (coin= iguana_coinadd(symbol,name,json,virtcoin)) == 0 )
        return(-1);
    if ( myinfo->rpcsymbol[0] == 0 || iguana_coinfind(myinfo->rpcsymbol) == 0 )
        strcpy(myinfo->rpcsymbol,symbol);
    if ( coin->launched == 0 )
    {
        if ( juint(json,"GBavail") < 8 )
            maphash = IGUANA_MAPHASHTABLES;
        else maphash = 0;
        iguana_coinargs(symbol,&maxrecvcache,&minconfirms,&maxpeers,&initialheight,&services,&maxrequests,&maxbundles,json);
        coins = mycalloc('A',1+1,sizeof(*coins));
        if ( (coin= iguana_setcoin(symbol,coins,maxpeers,maxrecvcache,services,initialheight,maphash,minconfirms,maxrequests,maxbundles,json,virtcoin)) != 0 )
        {
            if ( iguana_isnotarychain(coin->symbol) < 0 || coin->FULLNODE >= 0 )
            {
                coins[0] = (void *)((long)1);
                coins[1] = coin;
                printf("launch.%p coinloop for.%s services.%llx started.%p peers.%p\n",coin,coin->symbol,(long long)services,coin->started,coin->peers);
                coin->launched = iguana_launch(coin,"iguana_coinloop",iguana_coinloop,coins,IGUANA_PERMTHREAD);
            }
            coin->active = 1;
            coin->started = 0;
            return(1);
        }
        else
        {
            printf("launchcoin: couldnt initialize.(%s)\n",symbol);
            myfree(coins,sizeof(*coins) * 2);
            return(-1);
        }
    }
    return(0);
}

void iguana_optableinit();

void iguana_coins(void *arg)
{
    struct iguana_info **coins,*coin; char *jsonstr,*symbol; cJSON *array,*item,*json;
    int32_t i,n,maxpeers,maphash,initialheight,minconfirms,maxrequests,maxbundles;
    int64_t maxrecvcache; uint64_t services; struct vin_info V; struct supernet_info *myinfo;
    myinfo = SuperNET_MYINFO(0);
    iguana_optableinit();
    memset(&V,0,sizeof(V));
    if ( (jsonstr= arg) != 0 && (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (array= jarray(&n,json,"coins")) == 0 )
        {
            if ( (symbol= jstr(json,"coin")) != 0 && strncmp(symbol,"BTC",3) == 0 )
            {
                coins = mycalloc('A',1+1,sizeof(*coins));
                if ( (coins[1]= iguana_setcoin(symbol,coins,0,0,0,0,0,0,0,0,json,0)) != 0 )
                {
                    _iguana_calcrmd160(coins[1],&V);
                    coins[0] = (void *)((long)1);
                    iguana_coinloop(coins);
                }
                else
                {
                    printf("iguana_coins: couldnt initialize.(%s)\n",symbol);
                    return;
                }
            } else printf("no coins[] array in JSON.(%s) only BTCD and BTC can be quicklaunched\n",jsonstr);
            free_json(json);
            return;
        }
        coins = mycalloc('A',n+1,sizeof(*coins));
        if ( juint(json,"GBavail") < 8 )
            maphash = IGUANA_MAPHASHTABLES;
        else maphash = 0;
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            if ( (symbol= jstr(item,"name")) == 0 || strlen(symbol) > 8 )
            {
                printf("skip strange coin.(%s)\n",symbol);
                continue;
            }
            iguana_coinargs(symbol,&maxrecvcache,&minconfirms,&maxpeers,&initialheight,&services,&maxrequests,&maxbundles,item);
            coins[1 + i] = coin = iguana_setcoin(symbol,coins,maxpeers,maxrecvcache,services,initialheight,maphash,minconfirms,maxrequests,maxbundles,item,0);
            if ( coin == 0 )
            {
                printf("iguana_coins: couldnt initialize.(%s)\n",symbol);
                return;
            }
        }
        coins[0] = (void *)((long)n);
        iguana_coinloop(coins);
    }
}

char *busdata_sync(uint32_t *noncep,char *jsonstr,char *broadcastmode,char *destNXTaddr)
{
    printf("busdata_sync.(%s)\n",jsonstr);
    return(0);
}

