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

// included from basilisk.c
/*
 In order to provide liquidity from central exchanges, we need to issue balancing trades, however to do this properly, we need to know what the desired balance is. If unspecified, then a neutral balance is assumed.
 The liquidity_info interface is quite flexible, there is a single function liquidity_active() which returns non-zero if the LP node should respond. The model is that the liquidity_command() is used to configure the liquidity_active()'s response.
 In order for dynamic adaptiveness to work, the liquidity_command/liquidity_active needs to interact with the balancing.
 A simplistic default trio of functions are provided, but any level of complexity is possible with the liquidity interface.
 */

#define TRADEBOTS_NUMANSWERS 8
#define TRADEBOTS_NUMDECAYS 8
#define TRADEBOTS_RAWFEATURESINCR 7
#define TRADEBOTS_MAXPAIRS 1024

#define _OCAS_PLUS_INF (-log(0.0))
double OCAS_PLUS_INF,OCAS_NEG_INF;

double Tradebots_decays[TRADEBOTS_NUMDECAYS] = { 0.5, 0.666, 0.8, 0.9, 0.95, 0.99, 0.995, 0.999 };
int32_t Tradebots_answergaps[TRADEBOTS_NUMANSWERS] = { 60, 60, 120, 120, 240, 240, 720, 720 };

struct tradebot_arbentry
{
    char exchange[16];
    double price,volume,profitmargin;
    uint32_t timestamp;
};

struct tradebot_arbexchange
{
    char name[16];
    struct tradebot_arbentry trades[2];
};

struct tradebot_arbpair
{
    char base[32],rel[32];
    uint32_t lasttime,lastanswertime; FILE *fp;
    int32_t numexchanges,counter,btccounter,usdcounter,cnycounter,refc;
    double highbid,lowask,hblavolume,btcbid,btcask,btcvol,usdbid,usdask,usdvol,cnybid,cnyask,cnyvol;
    double bidaves[TRADEBOTS_NUMDECAYS],askaves[TRADEBOTS_NUMDECAYS];
    double bidslopes[TRADEBOTS_NUMDECAYS],askslopes[TRADEBOTS_NUMDECAYS];
    struct tradebot_arbexchange exchanges[16];
    uint8_t dirmasks[2],slopedirs[2];
    char *svmpairs[TRADEBOTS_MAXPAIRS][2];
    int32_t RTgood[TRADEBOTS_NUMANSWERS],RTbad[TRADEBOTS_NUMANSWERS],numrawfeatures,numsvmfeatures,numpairs;
    float rawfeatures[TRADEBOTS_NUMANSWERS+64],prevrawfeatures[60 * TRADEBOTS_NUMANSWERS+64],*svms; // svms is coeffs vector[TRADEBOTS_NUMANSWERS]
    float RTpreds[TRADEBOTS_NUMANSWERS],svmpreds[TRADEBOTS_NUMANSWERS],answers[TRADEBOTS_NUMANSWERS];
};
struct tradebot_arbpair Arbpairs[TRADEBOTS_MAXPAIRS],*Pair_NXTBTC,*Pair_BTCUSD,*Pair_BTCCNY;
int32_t Tradebot_numarbpairs;

struct tradebot_arbpair *tradebots_arbpair_find(char *base,char *rel)
{
    int32_t i;
    for (i=0; i<Tradebot_numarbpairs; i++)
        if ( strcmp(Arbpairs[i].base,base) == 0 && strcmp(Arbpairs[i].rel,rel) == 0 )
            return(&Arbpairs[i]);
    return(0);
}

int32_t tradebots_calcrawfeatures(struct tradebot_arbpair *pair)
{
    int32_t starti,i,n = 0; double ave; uint32_t timestamp;
    n = TRADEBOTS_NUMANSWERS;
    for (i=59; i>0; i--)
        memcpy(&pair->prevrawfeatures[i*72],&pair->prevrawfeatures[(i-1)*72],sizeof(pair->rawfeatures));
    memcpy(pair->prevrawfeatures,pair->rawfeatures,sizeof(pair->rawfeatures));
    memset(pair->rawfeatures,0,sizeof(pair->rawfeatures));
    if ( fabs(pair->highbid) < SMALLVAL || fabs(pair->lowask) < SMALLVAL )
        return(-1);
    ave = _pairaved(pair->highbid,pair->lowask);
    timestamp = (uint32_t)time(NULL);
    n = TRADEBOTS_NUMANSWERS;
    memcpy(&pair->rawfeatures[TRADEBOTS_NUMANSWERS],&timestamp,sizeof(*pair->rawfeatures)), n++;
    pair->rawfeatures[n++] = pair->highbid;
    pair->rawfeatures[n++] = pair->lowask;
    pair->rawfeatures[n++] = pair->hblavolume / ave;
    n = TRADEBOTS_RAWFEATURESINCR + TRADEBOTS_NUMANSWERS;
    for (i=0; i<TRADEBOTS_NUMDECAYS; i++)
    {
        if ( fabs(pair->bidaves[i]) < SMALLVAL || fabs(pair->askaves[i]) < SMALLVAL )
            return(-1);
        starti = n;
        pair->rawfeatures[n++] = (pair->bidaves[i] / ave) - 1.;
        pair->rawfeatures[n++] = (pair->askaves[i] / ave) - 1.;
        pair->rawfeatures[n++] = 10000. * (pair->bidslopes[i] / ave);
        pair->rawfeatures[n++] = 10000. * (pair->askslopes[i] / ave);
        if ( n < starti+TRADEBOTS_RAWFEATURESINCR )
            n = starti+TRADEBOTS_RAWFEATURESINCR;
    }
    if ( pair->fp != 0 )
    {
        if ( fwrite(pair->rawfeatures,1,sizeof(pair->rawfeatures),pair->fp) != sizeof(pair->rawfeatures) )
            printf("fwrite error for %s/%s rawfeatures[%d]\n",pair->base,pair->rel,n);
        else fflush(pair->fp);
    }
    if ( n > sizeof(pair->rawfeatures)/sizeof(*pair->rawfeatures) )
    {
        printf("n.%d too many for rawfeatures %d\n",n,(int32_t)(sizeof(pair->rawfeatures)/sizeof(*pair->rawfeatures)));
        exit(-1);
    }
    return(n);
}

uint32_t tradebots_featureset(double *highbidp,double *lowaskp,double *avep,double *volp,double *bidaves,double *askaves,double *bidslopes,double *askslopes,float *rawfeatures)
{
    uint32_t timestamp; int32_t i,n,starti;
    memcpy(&timestamp,&rawfeatures[TRADEBOTS_NUMANSWERS],sizeof(timestamp));
    n = TRADEBOTS_NUMANSWERS + 1;
    *highbidp = rawfeatures[n++];
    *lowaskp = rawfeatures[n++];
    *avep = _pairaved(*highbidp,*lowaskp);
    *volp = rawfeatures[n++];
    //printf("[%9.6f %9.6f] vol %f t.%u\n",*highbidp,*lowaskp,*volp,timestamp);
    n = TRADEBOTS_RAWFEATURESINCR + TRADEBOTS_NUMANSWERS;
    for (i=0; i<TRADEBOTS_NUMDECAYS; i++)
    {
        starti = n;
        bidaves[i] = rawfeatures[n++];
        askaves[i] = rawfeatures[n++];
        bidslopes[i] = rawfeatures[n++];
        askslopes[i] = rawfeatures[n++];
        if ( n < starti+TRADEBOTS_RAWFEATURESINCR )
            n = starti+TRADEBOTS_RAWFEATURESINCR;
    }
    return(timestamp);
}

struct tradebot_arbpair *tradebots_arbpair_create(char *base,char *rel)
{
    struct tradebot_arbpair *pair; char fname[1024]; double ave;
    if ( Tradebot_numarbpairs < sizeof(Arbpairs)/sizeof(*Arbpairs) )
    {
        printf("new pair.%d (%s/%s)\n",Tradebot_numarbpairs,base,rel);
        pair = &Arbpairs[Tradebot_numarbpairs];
        pair->refc = Tradebot_numarbpairs++;
        strcpy(pair->rel,rel);
        strcpy(pair->base,base);
        if ( strcmp(base,"NXT") == 0 && strcmp(rel,"BTC") == 0 )
            Pair_NXTBTC = pair, printf("Pair_NXTBTC <- %p\n",pair);
        else if ( strcmp(base,"BTC") == 0 && strcmp(rel,"USD") == 0 )
            Pair_BTCUSD = pair;
        else if ( strcmp(base,"BTC") == 0 && strcmp(rel,"CNY") == 0 )
            Pair_BTCCNY = pair;
        sprintf(fname,"SVM/rawfeatures/%s_%s",base,rel);
        pair->fp = OS_appendfile(fname);
        if ( (ftell(pair->fp) % sizeof(pair->rawfeatures)) != 0 )
        {
            printf("misalinged rawfeatures %d %d\n",(uint32_t)ftell(pair->fp),(uint32_t)(ftell(pair->fp) % sizeof(pair->rawfeatures)));
        }
        fseek(pair->fp,(ftell(pair->fp) / sizeof(pair->rawfeatures)) * sizeof(pair->rawfeatures) - sizeof(pair->rawfeatures),SEEK_SET);
        if ( fread(pair->rawfeatures,1,sizeof(pair->rawfeatures),pair->fp) == sizeof(pair->rawfeatures) )
        {
            pair->lasttime = tradebots_featureset(&pair->highbid,&pair->lowask,&ave,&pair->hblavolume,pair->bidaves,pair->askaves,pair->bidslopes,pair->askslopes,pair->rawfeatures);
            printf("%s/%s [%.8f %.8f] %u\n",pair->base,pair->rel,pair->highbid,pair->lowask,pair->lasttime);
        }
        return(pair);
    } else return(0);
}

int32_t tradebots_expandrawfeatures(double *svmfeatures,float *rawfeatures,uint32_t reftimestamp,float *refrawfeatures)
{
    double factor,highbid,lowask,ave,vol,bidaves[TRADEBOTS_NUMDECAYS],askaves[TRADEBOTS_NUMDECAYS],bidslopes[TRADEBOTS_NUMDECAYS],askslopes[TRADEBOTS_NUMDECAYS];
    double refhighbid,reflowask,refave,refvol,refbidaves[TRADEBOTS_NUMDECAYS],refaskaves[TRADEBOTS_NUMDECAYS],refbidslopes[TRADEBOTS_NUMDECAYS],refaskslopes[TRADEBOTS_NUMDECAYS];
    uint32_t timestamp; int32_t i,j,starti,n = 0;
    tradebots_featureset(&refhighbid,&reflowask,&refave,&refvol,refbidaves,refaskaves,refbidslopes,refaskslopes,refrawfeatures);
    timestamp = tradebots_featureset(&highbid,&lowask,&ave,&vol,bidaves,askaves,bidslopes,askslopes,rawfeatures);
    if ( timestamp == 0 || reftimestamp == 0 || timestamp >= reftimestamp+60 )
    {
        //printf("tradebots_expandrawfeatures: timestamp.%u vs reftimestamp.%u\n",timestamp,reftimestamp);
        return(-1);
    }
    factor = sqrt(reftimestamp - timestamp);
    if ( factor > 60. )
        factor = 60.;
    else if ( factor < 1. )
        factor = 1.;
    factor = 1. / factor;
    if ( refhighbid == 0. || highbid == 0. || lowask == 0. || reflowask == 0. )
    {
        //printf("tradebots_expandrawfeatures: (%f %f) ref (%f %f)\n",highbid,lowask,refhighbid,reflowask);
        return(-1);
    }
    svmfeatures[n++] = highbid;
    svmfeatures[n++] = (highbid / ave) - 1.;
    svmfeatures[n++] = lowask;
    svmfeatures[n++] = (lowask / ave) - 1.;
    svmfeatures[n++] = (lowask - highbid);
    svmfeatures[n++] = (lowask - highbid) / ave;
    svmfeatures[n++] = vol;
    starti = n;
    svmfeatures[n++] = refhighbid;
    svmfeatures[n++] = (refhighbid / refave) - 1.;
    svmfeatures[n++] = reflowask;
    svmfeatures[n++] = (reflowask / refave) - 1.;
    svmfeatures[n++] = (reflowask - refhighbid);
    svmfeatures[n++] = (reflowask - refhighbid) / refave;
    svmfeatures[n++] = refvol;
    for (i=0; i<starti; i++)
        svmfeatures[n++] = (svmfeatures[i] - svmfeatures[i+starti]);
    for (i=0; i<TRADEBOTS_NUMDECAYS; i++)
    {
        svmfeatures[n++] = bidaves[i];
        svmfeatures[n++] = askaves[i];
        svmfeatures[n++] = bidslopes[i];
        svmfeatures[n++] = askslopes[i];
        
        svmfeatures[n++] = bidaves[i] - refbidaves[i];
        svmfeatures[n++] = bidaves[i] - refaskaves[i];
        
        svmfeatures[n++] = (askaves[i] - bidaves[i]);
        svmfeatures[n++] = askaves[i] - refaskaves[i];
        svmfeatures[n++] = askaves[i] - refbidaves[i];
        
        svmfeatures[n++] = bidslopes[i] - refbidslopes[i];
        svmfeatures[n++] = bidslopes[i] - refaskslopes[i];
      
        svmfeatures[n++] = (askslopes[i] - bidslopes[i]);
        svmfeatures[n++] = askslopes[i] - refaskslopes[i];
        svmfeatures[n++] = askslopes[i] - refbidslopes[i];
        
        svmfeatures[n++] = (askaves[i] - bidaves[i]) - (refaskaves[i] - refbidaves[i]);
        svmfeatures[n++] = (askslopes[i] - bidslopes[i]) - (refaskslopes[i] - refbidslopes[i]);
        for (j=i+1; j<TRADEBOTS_NUMDECAYS; j++)
        {
            svmfeatures[n++] = (bidaves[i] - bidaves[j]);
            svmfeatures[n++] = (askaves[i] - askaves[j]);
            svmfeatures[n++] = (askaves[i] - bidaves[j]);
            svmfeatures[n++] = (bidslopes[i] - bidslopes[j]);
            svmfeatures[n++] = (askslopes[i] - askslopes[j]);
            svmfeatures[n++] = (askslopes[i] - bidslopes[j]);
        }
    }
    //if ( fabs(factor - 1.) > SMALLVAL )
    {
        for (i=starti; i<n; i++)
            if ( svmfeatures[i] != 0.f )
            {
                //svmfeatures[i] *= factor;
                if ( svmfeatures[i] > 0. )
                    svmfeatures[i] = cbrt(svmfeatures[i]);
                else svmfeatures[i] = -cbrt(-svmfeatures[i]);
            }
    }
    return(n);
}

int32_t tradebots_calcsvmfeatures(double *svmfeatures,struct tradebot_arbpair *pair,float *rawfeatures,float *prevrawfeatures)
{
    int32_t i,j,n,numpairfeatures,flag; struct tradebot_arbpair *ptr; uint32_t reftimestamp;
    memcpy(&reftimestamp,&rawfeatures[TRADEBOTS_NUMANSWERS],sizeof(reftimestamp));
    if ( reftimestamp == 0 )
    {
        printf("reftimestamp.%u is illegal\n",reftimestamp);
        return(-1);
    }
    numpairfeatures = n = tradebots_expandrawfeatures(svmfeatures,prevrawfeatures,reftimestamp,rawfeatures);
    if ( n <= 0 )
        return(-1);
    for (i=0; i<60; i++,n+=numpairfeatures)
        tradebots_expandrawfeatures(&svmfeatures[n],&prevrawfeatures[i*72],reftimestamp,rawfeatures);
    if ( 0 && pair->numsvmfeatures != (1+pair->numpairs)*n )
    {
        for (i=0; i<pair->numpairs; i++) // need to do lookups
        {
            flag = -1;
            if ( (ptr= tradebots_arbpair_find(pair->svmpairs[i][0],pair->svmpairs[i][1])) != 0 )
                flag = tradebots_expandrawfeatures(&svmfeatures[n],ptr->rawfeatures,reftimestamp,rawfeatures);
            if ( flag < 0 )
            {
                for (j=0; j<numpairfeatures; j++)
                    svmfeatures[n++] = 0.;
            } else n += flag;
        }
    }
    return(n);
}

int32_t tradebots_calcpreds(float *RTpreds,struct tradebot_arbpair *pair,double *svmfeatures)
{
    int32_t i,j,n=0; double feature,preds[TRADEBOTS_NUMANSWERS];
    memset(preds,0,sizeof(preds));
    if ( pair->svms != 0 )
    {
        for (i=n=0; i<pair->numsvmfeatures; i++)
        {
            feature = svmfeatures[i];
            for (j=0; j<TRADEBOTS_NUMANSWERS; j++)
                preds[j] += feature * pair->svms[n++];
        }
    }
    return(n);
}

void tradebots_calcanswers(struct tradebot_arbpair *pair)
{
    double highbid,lowask,futurebid,futureask,ave,vol,bidaves[TRADEBOTS_NUMDECAYS],askaves[TRADEBOTS_NUMDECAYS],bidslopes[TRADEBOTS_NUMDECAYS],askslopes[TRADEBOTS_NUMDECAYS];
    float rawfeatures[sizeof(pair->rawfeatures)/sizeof(*pair->rawfeatures)],futuremin=0,futuremax=0,minval=0,maxval=0,*hblas = 0;
    uint32_t timestamp,firsttime = 0; long fpos,savepos; int32_t flag,i,iter,j,ind,maxi=0;
    OCAS_PLUS_INF = _OCAS_PLUS_INF; OCAS_NEG_INF = -_OCAS_PLUS_INF;
    if ( pair->fp != 0 )
    {
        for (iter=0; iter<2; iter++)
        {
            rewind(pair->fp);
            fpos = 0;
            while ( fread(rawfeatures,1,sizeof(pair->rawfeatures),pair->fp) == sizeof(pair->rawfeatures) )
            {
                savepos = ftell(pair->fp);
                timestamp = tradebots_featureset(&highbid,&lowask,&ave,&vol,bidaves,askaves,bidslopes,askslopes,rawfeatures);
                //printf("timestamp.%u firsttime.%u\n",timestamp,firsttime);
                if ( timestamp == 0 )
                    continue;
                if ( firsttime == 0 )
                {
                    firsttime = timestamp;
                    maxi = (int32_t)((time(NULL) - firsttime) / 60 + 1);
                    hblas = calloc(maxi,sizeof(*hblas)*2);
                    printf("HBLAS[%d] allocated\n",maxi);
                }
                if ( (i= (timestamp - firsttime)/60) >= 0 && i < maxi )
                {
                    if ( iter == 0 )
                    {
                        if ( hblas[i << 1] == 0 )
                        {
                            hblas[i << 1] = highbid;
                            hblas[(i << 1) + 1] = lowask;
                        }
                        else
                        {
                            _xblend(&hblas[i << 1],highbid,0.5);
                            _xblend(&hblas[(i << 1) + 1],lowask,0.5);
                        }
                    }
                    else
                    {
                        highbid = hblas[i << 1];
                        lowask = hblas[(i << 1) + 1];
                        if ( fabs(highbid) > SMALLVAL && fabs(lowask) > SMALLVAL )
                        {
                            memset(pair->answers,0,sizeof(pair->answers));
                            flag = 0;
                            for (j=0; j<TRADEBOTS_NUMANSWERS; j++)
                            {
                                ind = i + Tradebots_answergaps[j];
                                if ( ind < maxi )
                                {
                                    if ( (j & 1) != 0 )
                                        pair->answers[j] = _pairaved(futuremax,futuremin) - _pairaved(minval,maxval);
                                    else
                                    {
                                        futurebid = hblas[ind << 1];
                                        futureask = hblas[(ind << 1) + 1];
                                        minval = MIN(highbid,lowask);
                                        maxval = MAX(highbid,lowask);
                                        futuremin = MIN(futurebid,futureask);
                                        futuremax = MAX(futurebid,futureask);
                                        if ( futuremin > maxval )
                                        {
                                            if ( futuremax < minval )
                                                printf("%s/%s A%d: highly volatile minmax.(%f %f) -> (%f %f) %d of %d\n",pair->base,pair->rel,j,minval,maxval,futuremin,futuremax,i,maxi);
                                            else
                                            {
                                                pair->answers[j] = (futuremin - maxval);
                                                flag++;
                                            }
                                        }
                                        else if ( futuremax < minval )
                                            pair->answers[j] = (futuremax - minval), flag++;
                                        //printf("i.%d j.%d gap.%d ind.%d answer %9.6f (%f %f) -> (%f %f)\n",i,j,Tradebots_answergaps[j],ind,pair->answers[j],minval,maxval,futuremin,futuremax);
                                    }
                                }
                            }
                            if ( flag != 0 )
                            {
                                fseek(pair->fp,fpos,SEEK_SET);
                                if ( fwrite(pair->answers,1,sizeof(pair->answers),pair->fp) != sizeof(pair->answers) )
                                    printf("error writing answers for %s/%s t%u i.%d of %d\n",pair->base,pair->rel,timestamp,i,maxi);
                                else if ( 0 )
                                {
                                    for (j=0; j<TRADEBOTS_NUMANSWERS; j++)
                                        printf("%9.6f ",pair->answers[j]);
                                    printf("%s/%s answers %d of %d\n",pair->base,pair->rel,i,maxi);
                                }
                                fseek(pair->fp,savepos,SEEK_SET);
                            }
                        }
                    }
                }
                fpos = ftell(pair->fp);
            }
            if ( iter == 0 )
            {
                if ( hblas == 0 )
                    break;
                highbid = hblas[0];
                lowask = hblas[1];
                for (i=1; i<maxi; i++)
                {
                    if ( fabs(hblas[i << 1]) > SMALLVAL && fabs(hblas[(i << 1) + 1]) > SMALLVAL )
                    {
                        highbid = hblas[i << 1];
                        lowask = hblas[(i << 1) + 1];
                    }
                    else
                    {
                        hblas[i << 1] = highbid;
                        hblas[(i << 1) + 1] = lowask;
                    }
                    //printf("%9.6f ",_pairaved(highbid,lowask));
                }
                //printf("maxi.%d\n",maxi);
            }
        }
        if ( hblas != 0 )
            free(hblas);
    }
    if ( pair->fp != 0 && (ftell(pair->fp) % sizeof(pair->rawfeatures)) != 0 )
        printf("ERROR: %s/%s not on feature boundary\n",pair->base,pair->rel);
}

double get_yval(double *answerp,int32_t selector,int32_t ind,int32_t refc,int32_t answerind)
{
    float answer; struct tradebot_arbpair *pair; long savepos;
    pair = &Arbpairs[refc];
    if ( pair->fp != 0 )
    {
        savepos = ftell(pair->fp);
        fseek(pair->fp,ind*sizeof(pair->rawfeatures)+answerind*sizeof(*pair->rawfeatures),SEEK_SET);
        if ( fread(&answer,1,sizeof(answer),pair->fp) != sizeof(answer) )
            answer = 0;
        fseek(pair->fp,savepos,SEEK_SET);
        if ( isnan(answer) != 0 )
            return(0);
        answer /= 10.;
        /*if ( answer > .01 )
            answer = .01;
        else if ( answer < -.01 )
            answer = -.01;
        if ( answerp != 0 )
            *answerp = answer;
       */
        if ( answer > 0. )
            answer = sqrt(answer);
        else answer = -sqrt(-answer);
        *answerp = answer;
        /*if ( answer > 0. )
            return(1.);
        else if ( answer < 0. )
            return(-1.);*/
        return(answer);
    }
	return(0.);
}

float *get_features(int32_t numfeatures,int32_t refc,int32_t ind)
{
    struct tradebot_arbpair *pair; long savepos; int32_t i,n; double svmfeatures[32768];
    float rawfeatures[sizeof(pair->rawfeatures)],prevrawfeatures[60 * sizeof(pair->rawfeatures)],*svmf=0;
    pair = &Arbpairs[refc];
    pair->numsvmfeatures = numfeatures;
    if ( pair->fp != 0 && ind > 61 )
    {
        savepos = ftell(pair->fp);
        fseek(pair->fp,(ind-60)*sizeof(pair->rawfeatures),SEEK_SET);
        if ( fread(prevrawfeatures,60,sizeof(pair->rawfeatures),pair->fp) == sizeof(pair->rawfeatures) && fread(&rawfeatures,1,sizeof(pair->rawfeatures),pair->fp) == sizeof(pair->rawfeatures) )
        {
            n = tradebots_calcsvmfeatures(svmfeatures,pair,rawfeatures,prevrawfeatures);
            //int32_t nonz; for (i=nonz=0; i<n; i++)
            //    if ( svmfeatures[i] != 0 )
            //        nonz++;
            //printf("%d ",nonz);
            //    printf("%9.6f ",rawfeatures[i]);
            //printf("rawfeatures[%d] -> %d\n",ind,n);
            if ( n != pair->numsvmfeatures )
            {
                //printf("unexpected numsvmfeatures refc.%d ind.%d %d vs %d\n",refc,ind,n,pair->numsvmfeatures);
                return(0);
            }
            svmf = calloc(n,sizeof(*svmf));
            for (i=0; i<n; i++)
                svmf[i] = svmfeatures[i];
        }
        fseek(pair->fp,savepos,SEEK_SET);
    }
    return(svmf);
}

/*double set_ocas_model(int refc,int answerind,double *W,double W0,int numfeatures,int firstweekind,int len,int bad,double dist,double predabs,int posA,int negA,double answerabs,double aveanswer)
{
    int32_t i,nonz=0;
    for (i=0; i<numfeatures; i++)
        if ( W[i] != 0. )
            nonz++;//, printf("%.6f ",W[i]);
    printf("model.%d W0 %.7f numfeatures.%d nonz.%d\n",answerind,W0,numfeatures,nonz);
    return(W0);
}*/

void tradebots_modelfname(char *modelname,char *base,char *rel,int32_t answerind,int32_t numfeatures)
{
	sprintf(modelname,"SVM/models/%s_%s_%d.A%d",base,rel,numfeatures,answerind);
    OS_portable_path(modelname);
}

double load_model(register int *posAp,register int *negAp,register double *W,register int refc,register int answerind,register int numfeatures)
{
	int32_t j; FILE *fp; double perc; char modelname[512];
    tradebots_modelfname(modelname,Arbpairs[refc].base,Arbpairs[refc].rel,answerind,numfeatures);
	if ( (fp= fopen(modelname,"rb")) != 0 )
	{
		//printf("load file\n");
		j = (int)fread(W,sizeof(*W),numfeatures+1,fp);
		//fread(&W0,1,sizeof(W0),fp);
		if ( fread(&perc,1,sizeof(perc),fp) == sizeof(perc) )
			j++;
		if ( fread(posAp,1,sizeof(*posAp),fp) == sizeof(*posAp) )
			j++;
		if ( fread(negAp,1,sizeof(*negAp),fp) == sizeof(*negAp) )
			j++;
		fclose(fp);
		//printf("loaded %s bias %9.6f | %5.2f%%\n",modelname,W[numfeatures],perc);
		return(perc);
	}
#ifndef DISABLE_EXISTINGMODEL
	else if ( 0 )
	{
        tradebots_modelfname(modelname,Arbpairs[refc].base,Arbpairs[refc].rel,answerind,numfeatures);
		if ( (fp= fopen(modelname,"rb")) != 0 )
		{
			j = (int)fread(W,sizeof(*W),numfeatures+1,fp);
			if ( fread(&perc,1,sizeof(perc),fp) == sizeof(perc) )
				j++;
			if ( fread(posAp,1,sizeof(*posAp),fp) == sizeof(*posAp) )
				j++;
			if ( fread(negAp,1,sizeof(*negAp),fp) == sizeof(*negAp) )
				j++;
			fclose(fp);
			printf("Using backup model for %s/%s loaded %s bias %9.6f | %5.2f%%\n",Arbpairs[refc].base,Arbpairs[refc].rel,modelname,W[numfeatures],perc);
			return(perc * .9);
		}
	}
#endif
	else printf("couldn't load (%s)\n",modelname);
	return(-1);
}

int save_model(int refc,int answerind,double *W,int numfeatures,double W0,double perc,int posA,int negA)
{
	FILE *fp; char modelname[512];
    tradebots_modelfname(modelname,Arbpairs[refc].base,Arbpairs[refc].rel,answerind,numfeatures);
    printf("save model.(%s)\n",modelname);
	if ( (fp= fopen(modelname,"wb")) != 0 )
	{
		//printf("save %s %.f%% posA.%d negA.%d\n",modelname,perc,posA,negA);
		fwrite(W,sizeof(*W),numfeatures,fp);
		fwrite(&W0,1,sizeof(W0),fp);
		fwrite(&perc,1,sizeof(perc),fp);
		fwrite(&posA,1,sizeof(posA),fp);
		fwrite(&negA,1,sizeof(negA),fp);
		fclose(fp);
		return(0);
	}
	return(-1);
}

double init_model(double *percp,double *W,double *oldW,int c,int answerind,int numfeatures)
{
	int32_t j,posA,negA,nonz=0; double *bestmodel=0;
	memset(oldW,0,sizeof(*oldW)*numfeatures);
	memset(W,0,sizeof(*W)*numfeatures);
    if ( load_model(&posA,&negA,W,c,answerind,numfeatures) > 0 )
    {
        bestmodel = W;
        if ( bestmodel != 0 )
        {
            for (j=0; j<=numfeatures; j++)
            {
                if ( bestmodel[j] != 0 )
                    nonz++;
                oldW[j] = W[j];
            }
            if ( nonz != 0 )
                return(bestmodel[numfeatures]);
        }
	}
	return(0.);
}

double set_ocas_model(int refc,int answerind,double *W,double W0,int numfeatures,int firstweekind,int len,int bad,double dist,double predabs,int posA,int negA,double answerabs,double aveanswer)
{
	double perc = (100. * (double)(len - bad)) / len;
#ifndef DISABLE_EXISTINGMODEL
	int32_t _posA,_negA; double *tmpW,fileperc;
    tmpW = calloc(numfeatures+2,sizeof(*tmpW));
	if ( (fileperc= load_model(&_posA,&_negA,tmpW,refc,answerind,numfeatures)) > perc )
	{
		if ( (_posA+_negA) != 0 && _posA >= posA && _negA >= negA )
		{
			memcpy(W,tmpW,sizeof(*W)*numfeatures);
			printf("%s/%s.A%02d numfeatures.%d posA.%d negA.%d saved model %f is better than %f +A%d -A%d\n",Arbpairs[refc].base,Arbpairs[refc].rel,answerind,numfeatures,_posA,_negA,fileperc,perc,posA,negA);
            W0 = tmpW[numfeatures];
            free(tmpW);
			return(tmpW[numfeatures]);
		}
	}
    free(tmpW);
#endif
	save_model(refc,answerind,W,numfeatures,W0,perc,posA,negA);
	return(W0);
}

#ifndef _WIN
#include "tradebots_SVM.h"
#endif

static char *assetids[][2] =
{
    { "12071612744977229797", "UNITY" },
    { "15344649963748848799", "DEX" },
    { "6883271355794806507", "PANGEA" },
    { "17911762572811467637", "JUMBLR" },
    { "17083334802666450484", "BET" },
    { "13476425053110940554", "CRYPTO" },
    { "6932037131189568014", "HODL" },
    { "3006420581923704757", "SHARK" },
    { "17571711292785902558", "BOTS" },
    { "10524562908394749924", "MGW" },
};

uint64_t NXT_assetidfind(char *base)
{
    int32_t i;
    for (i=0; i<sizeof(assetids)/sizeof(*assetids); i++)
        if ( strcmp(assetids[i][1],base) == 0 )
            return(calc_nxt64bits(assetids[i][0]));
    return(0);
}

char *NXT_assetnamefind(char *base)
{
    int32_t i;
    for (i=0; i<sizeof(assetids)/sizeof(*assetids); i++)
        if ( strcmp(assetids[i][0],base) == 0 )
            return(assetids[i][1]);
    return(0);
}

void tradebot_arbentry(struct tradebot_arbentry *arb,char *exchange,double price,double volume,uint32_t timestamp,double profitmargin)
{
    if ( arb->exchange[0] == 0 )
        strcpy(arb->exchange,exchange);
    if ( strcmp(arb->exchange,exchange) == 0 )
    {
        arb->price = price;
        arb->volume = volume;
        arb->timestamp = timestamp;
        arb->profitmargin = profitmargin;
    } else printf("mismatched arbexchange? (%s vs %s)\n",arb->exchange,exchange);
}

struct tradebot_arbexchange *tradebots_arbexchange_find(struct tradebot_arbpair *pair,char *exchange)
{
    int32_t i;
    if ( pair->numexchanges > sizeof(pair->exchanges)/sizeof(*pair->exchanges) )
    {
        printf("data corruption pair.%p %s %s/%s numexchanges.%d\n",pair,exchange,pair->base,pair->rel,pair->numexchanges);
        return(0);
    }
    for (i=0; i<pair->numexchanges; i++)
        if ( strcmp(pair->exchanges[i].name,exchange) == 0 )
            return(&pair->exchanges[i]);
    return(0);
}

struct tradebot_arbexchange *tradebots_arbexchange_create(struct tradebot_arbpair *pair,char *exchange)
{
    if ( pair->numexchanges < sizeof(pair->exchanges)/sizeof(*pair->exchanges) )
    {
        strcpy(pair->exchanges[pair->numexchanges].name,exchange);
        return(&pair->exchanges[pair->numexchanges++]);
    } else return(0);
}

void tradebot_arbcandidate(struct supernet_info *myinfo,char *exchange,int32_t tradedir,char *base,char *rel,double price,double volume,uint32_t timestamp,double profitmargin)
{
    int32_t i,offset,flag; double highbid,lowask,lastbid,lastask,arbval; uint32_t now;
    struct tradebot_arbentry *bid,*ask; struct tradebot_arbexchange *arbex; struct tradebot_arbpair *pair = 0;
    if ( strcmp(rel,"BTC") != 0 && strcmp(rel,"NXT") != 0 && strcmp(rel,"USD") != 0 && strcmp(rel,"CNY") != 0 )
    {
        printf("reject non-BTC arbcandidate (%s/%s)\n",base,rel);
        return;
    }
    offset = (tradedir > 0) ? 0 : 1;
    if ( (pair= tradebots_arbpair_find(base,rel)) == 0 )
        pair = tradebots_arbpair_create(base,rel);
    if ( pair == 0 )
    {
        printf("cant get pair for %s %s/%s\n",exchange,base,rel);
        return;
    }
    if ( (arbex= tradebots_arbexchange_find(pair,exchange)) == 0 )
        arbex = tradebots_arbexchange_create(pair,exchange);
    if ( arbex != 0 )
    {
        //printf("cand.%d %16s %s %12.6f (%5s/%-5s) at %12.8f profit %.03f\n",pair->numexchanges,exchange,tradedir<0?"ask":"bid",volume,base,rel,price,profitmargin);
        tradebot_arbentry(&arbex->trades[offset],exchange,price,volume,timestamp,profitmargin);
        bid = ask = 0;
        pair->highbid = pair->lowask = highbid = lowask = 0.;
        now = (uint32_t)time(NULL);
        //if ( pair->numexchanges >= 2 )
        {
            for (i=0; i<pair->numexchanges; i++)
            {
                arbex = &pair->exchanges[i];
                if ( arbex->trades[0].price != 0. && (highbid == 0. || arbex->trades[0].price >= highbid) )
                {
                    bid = &arbex->trades[0];
                    if ( now > bid->timestamp+30 )
                        bid->price = 0.;
                    else highbid = bid->price;
                }
                if ( arbex->trades[1].price != 0. && (lowask == 0. || arbex->trades[1].price <= lowask) )
                {
                    ask = &arbex->trades[1];
                    if ( now > ask->timestamp+30 )
                        ask->price = 0.;
                    else lowask = ask->price;
                }
                //printf("%p %s %s %f %f -> %p %p %f %f (%f %f)\n",pair,pair->base,arbex->name,arbex->trades[0].price,arbex->trades[1].price,bid,ask,highbid,lowask,pair->highbid,pair->lowask);
            }
            flag = 0;
            if ( Pair_NXTBTC != 0 && pair->btccounter != Pair_NXTBTC->counter )
                flag |= 1;
            if ( Pair_BTCUSD != 0 && pair->usdcounter != Pair_BTCUSD->counter )
                flag |= 2;
            if ( Pair_BTCCNY != 0 && pair->cnycounter != Pair_BTCCNY->counter )
                flag |= 4;
            //printf("%s %s/%s flag.%d (%d %d) %p %p\n",exchange,base,rel,flag,pair->btccounter,Pair_NXTBTC!=0?Pair_NXTBTC->counter:-1,bid,ask);
            if ( bid != 0 && ask != 0 && bid->price != 0. && ask->price != 0 && (now - bid->timestamp) < 30 && (now - ask->timestamp) < 30 && (fabs(bid->price - pair->highbid) > SMALLVAL || fabs(ask->price - pair->lowask) > SMALLVAL || (strcmp(pair->rel,"NXT") == 0 && flag != 0)) )
            {
                pair->counter++;
                pair->hblavolume = volume = MIN(bid->volume,ask->volume);
                arbval = lastbid = lastask = 0.;
                memset(pair->dirmasks,0,sizeof(pair->dirmasks));
                memset(pair->slopedirs,0,sizeof(pair->slopedirs));
                if ( strcmp(pair->rel,"NXT") == 0 )
                {
                    if ( Pair_NXTBTC != 0 && Pair_NXTBTC->highbid != 0. && Pair_NXTBTC->lowask != 0. )
                    {
                        pair->btccounter = Pair_NXTBTC->counter;
                        pair->btcbid = highbid * Pair_NXTBTC->highbid;
                        pair->btcask = lowask * Pair_NXTBTC->lowask;
                        pair->btcvol = volume * _pairaved(pair->btcbid,pair->btcask);
                    }
                }
                else if ( strcmp(pair->rel,"BTC") == 0 )
                {
                    pair->btcbid = highbid;
                    pair->btcask = lowask;
                    pair->btcvol = volume;
                }
                if ( strcmp(pair->rel,"USD") == 0 )
                {
                    pair->usdbid = highbid;
                    pair->usdask = lowask;
                    pair->usdvol = volume;
                }
                if ( strcmp(pair->rel,"CNY") == 0 )
                {
                    pair->cnybid = highbid;
                    pair->cnyask = lowask;
                    pair->cnyvol = volume;
                }
                if ( pair->btcbid != 0. && pair->btcask != 0. )
                {
                    if ( strcmp(pair->rel,"USD") != 0 && Pair_BTCUSD != 0 && Pair_BTCUSD->highbid != 0. && Pair_BTCUSD->lowask != 0. )
                    {
                        pair->usdcounter = Pair_BTCUSD->counter;
                        pair->usdbid = pair->btcbid * Pair_BTCUSD->highbid;
                        pair->usdask = pair->btcask * Pair_BTCUSD->lowask;
                        pair->usdvol = pair->btcvol * _pairaved(pair->usdbid,pair->usdask);
                    }
                    if ( strcmp(pair->rel,"CNY") != 0 && Pair_BTCCNY != 0 && Pair_BTCCNY->highbid != 0. && Pair_BTCCNY->lowask != 0. )
                    {
                        pair->cnycounter = Pair_BTCCNY->counter;
                        pair->cnybid = pair->btcbid * Pair_BTCCNY->highbid;
                        pair->cnyask = pair->btcask * Pair_BTCCNY->lowask;
                        pair->cnyvol = pair->btcvol * _pairaved(pair->cnybid,pair->cnyask);
                    }
                }
                for (i=0; i<TRADEBOTS_NUMDECAYS; i++)
                {
                    if ( (pair->bidslopes[i]= dxblend(&pair->bidaves[i],highbid,Tradebots_decays[i])) > 0. )
                        pair->slopedirs[0] |= (1 << i);
                    if ( (pair->askslopes[i]= dxblend(&pair->askaves[i],lowask,Tradebots_decays[i])) > 0. )
                        pair->slopedirs[1] |= (1 << i);
                    lastbid = pair->bidaves[i];
                    lastask = pair->askaves[i];
                    //printf("(%.8f %.8f) ",lastbid,lastask);
                }
                for (i=0; i<TRADEBOTS_NUMDECAYS; i++)
                {
                    if ( i == 0 )
                    {
                        if ( highbid > lastbid )
                            pair->dirmasks[0] |= (1 << i);
                        if ( lowask > lastask )
                            pair->dirmasks[1] |= (1 << i);
                    }
                    else
                    {
                        if ( pair->bidaves[i-1] > lastbid )
                            pair->dirmasks[0] |= (1 << i);
                        if ( pair->askaves[i-1] > lastask )
                            pair->dirmasks[1] |= (1 << i);
                    }
                }
                //printf("%12.6f %7s/%-3s %8s %14.8f %8s %14.8f spread %6.2f%% %02x:%02x %02x:%02x %d\n",volume,base,rel,bid->exchange,highbid,ask->exchange,lowask,100.*(lowask-highbid)/_pairaved(highbid,lowask),pair->dirmasks[0],pair->slopedirs[0],pair->dirmasks[1],pair->slopedirs[1],pair->counter);
                //printf("BTC.(%.8f %.8f) %.8f %.8f USD.(%.4f %.4f) CNY.(%.3f %.3f)\n",pair->btcbid,pair->btcask,Pair_BTCUSD!=0?Pair_BTCUSD->highbid:0,Pair_BTCUSD!=0?Pair_BTCUSD->lowask:0,pair->usdbid,pair->usdask,pair->cnybid,pair->cnyask);
            }
            if ( highbid != 0 )
                pair->highbid = highbid;
            if ( lowask != 0 )
                pair->lowask = lowask;
            //printf(">>>>>>> %s (%s/%s) BTC %.8f %.8f v%f counter.%d btc.%d (%d)\n",exchange,pair->base,pair->rel,pair->btcbid,pair->btcask,pair->btcvol,pair->counter,pair->btccounter,Pair_NXTBTC!=0?Pair_NXTBTC->counter:-1);
            if ( bid != 0 && ask != 0 && highbid != 0. && lowask != 0. && highbid > lowask && strcmp(bid->exchange,ask->exchange) != 0 && strcmp(rel,"BTC") == 0 )
            {
                volume = MIN(bid->volume,ask->volume);
                if ( volume*_pairaved(highbid,lowask) > 0.1 )
                    volume = 0.1 / _pairaved(highbid,lowask);
                if ( highbid * (1. - bid->profitmargin) > lowask * (1. + ask->profitmargin) )
                {
                    arbval = highbid * (1. - bid->profitmargin) - lowask * (1. + ask->profitmargin);
                    printf(">>>>>>>> FOUND ARB %s/%s highbid.%s %.8f lowask.%s %.8f volume %f (%.8f %.8f) %.4f%%\n",pair->base,pair->rel,bid->exchange,bid->price,ask->exchange,ask->price,volume,highbid,lowask,100.*(highbid-lowask)/_pairaved(highbid,lowask));
                    InstantDEX_buy(myinfo,0,0,0,ask->exchange,pair->base,"BTC",ask->price,volume,1);
                    InstantDEX_sell(myinfo,0,0,0,bid->exchange,pair->base,"BTC",bid->price,volume,1);
                    printf("finished trades %s/%s volume %f\n",pair->base,pair->rel,volume);
                }
            }
            if ( pair->counter > TRADEBOTS_NUMDECAYS )
            {
                if ( pair->lasttime != time(NULL) )
                {
                    if ( (pair->numrawfeatures= tradebots_calcrawfeatures(pair)) > 0 )
                    {
                        if ( pair->numsvmfeatures != 0 )
                        {
                            if ( myinfo->svmfeatures == 0 )
                                myinfo->svmfeatures = calloc(sizeof(*myinfo->svmfeatures),pair->numsvmfeatures);
                            if ( tradebots_calcsvmfeatures(myinfo->svmfeatures,pair,pair->rawfeatures,pair->prevrawfeatures) > 0 )
                                tradebots_calcpreds(pair->RTpreds,pair,myinfo->svmfeatures);
                        }
                    }
                    pair->lasttime = (uint32_t)time(NULL);
                }
                if ( 0 && time(NULL) > pair->lastanswertime+3600 )
                {
                    tradebots_calcanswers(pair);
                    pair->lastanswertime = (uint32_t)time(NULL);
                }
            }
        }
    }
}

cJSON *linfo_json(struct liquidity_info *li)
{
    cJSON *item = cJSON_CreateObject();
    jaddstr(item,"base",li->base);
    jaddstr(item,"rel",li->rel);
    if ( li->exchange[0] != 0 )
        jaddstr(item,"exchange",li->exchange);
    if ( li->assetid != 0 )
        jadd64bits(item,"assetid",li->assetid);
    if ( li->profit != 0. )
        jaddnum(item,"profitmargin",li->profit);
    if ( li->refprice != 0. )
        jaddnum(item,"refprice",li->refprice);
    if ( li->bid != 0. )
        jaddnum(item,"bid",li->bid);
    if ( li->ask != 0. )
        jaddnum(item,"ask",li->ask);
    if ( li->minvol != 0. )
        jaddnum(item,"minvol",li->minvol);
    if ( li->maxvol != 0. )
        jaddnum(item,"maxvol",li->maxvol);
    if ( li->totalvol != 0. )
        jaddnum(item,"totalvol",li->totalvol);
    return(item);
}

void _default_liquidity_command(struct supernet_info *myinfo,char *base,bits256 hash,cJSON *vals)
{
    struct liquidity_info li,refli; int32_t i; char *exchange,*relstr,numstr[32];
    if ( (exchange= jstr(vals,"exchange")) == 0 )
        exchange = "DEX";
    else if ( strcmp(exchange,"*") == 0 )
        exchange = "";
    else if ( exchanges777_find(exchange) == 0 )
    {
        printf("cant find exchange.(%s)\n",exchange);
        return;
    }
    if ( (relstr= jstr(vals,"rel")) == 0 )
        relstr = "BTC";
    if ( base == 0 || base[0] == 0 )
        base = jstr(vals,"base");
    if ( base == 0 || base[0] == 0 )
        return;
    memset(&li,0,sizeof(li));
    safecopy(li.base,base,sizeof(li.base));
    safecopy(li.rel,relstr,sizeof(li.rel));
    strncpy(li.exchange,exchange,sizeof(li.exchange));
    li.profit = jdouble(vals,"profit");
    li.refprice = jdouble(vals,"refprice");
    li.bid = jdouble(vals,"bid");
    li.ask = jdouble(vals,"ask");
    if ( (li.minvol= jdouble(vals,"minvol")) <= 0. )
        li.minvol = (strcmp("BTC",base) == 0) ? 0.0001 : 0.001;
    if ( strcmp(li.base,"KMD") == 0 && strcmp(li.rel,"BTC") == 0 && li.minvol >= 100. )
        li.minvol = 100.;
    if ( (li.maxvol= jdouble(vals,"maxvol")) < li.minvol )
        li.maxvol = li.minvol;
    if ( (li.totalvol= jdouble(vals,"total")) < li.maxvol )
        li.totalvol = li.maxvol;
    if ( strcmp("NXT",li.rel) == 0 )
        li.assetid = NXT_assetidfind(base);
    else if ( strcmp("UNITY",base) == 0 )
        li.assetid = NXT_assetidfind(base);
    if ( strcmp(li.base,"BTC") == 0 && strcmp("USD",li.rel) != 0 && strcmp("CNY",li.rel) != 0 )
    {
        printf("unsupported base BTC (%s/%s)\n",li.base,li.rel);
        return;
    }
    if ( strcmp(li.base,"BTC") != 0 && strcmp("BTC",li.rel) != 0 &&
        strcmp(li.base,"NXT") != 0 && strcmp("NXT",li.rel) != 0 &&
        strcmp(li.base,"USD") != 0 && strcmp("USD",li.rel) != 0 &&
        strcmp(li.base,"CNY") != 0 && strcmp("CNY",li.rel) != 0 &&
        strcmp(li.exchange,"DEX") != 0 ) // filter out most invalids
    {
        printf("unsupported base/rel %s/%s\n",li.base,li.rel);
        return;
    }
    for (i=0; i<sizeof(myinfo->linfos)/sizeof(*myinfo->linfos); i++)
    {
        refli = myinfo->linfos[i];
        if ( strcmp(li.rel,refli.base) == 0 && strcmp(li.base,refli.rel) == 0 )
        {
            /*li = refli;
            strcpy(li.base,refli.base);
            strcpy(li.rel,refli.rel);
            if ( fabs(li.refprice) > SMALLVAL )
                li.refprice = (1. / li.refprice);
            else li.refprice = 0.;
            li.dir = -li.dir;
            myinfo->linfos[i] = li;*/
            printf("cant Set rev linfo[%d] (%s/%s) %.6f %.8f already have (%s/%s)\n",i,li.rel,li.base,li.profit,li.refprice,refli.base,refli.rel);
            return;
        }
        else if ( refli.base[0] == 0 || (strcmp(li.base,refli.base) == 0 && strcmp(li.rel,refli.rel) == 0 && strcmp(li.exchange,refli.exchange) == 0) )
        {
            if ( refli.base[0] == 0 && li.exchange[0] != 0 && strcmp(li.exchange,"DEX") != 0 )
            {
                if ( strcmp("NXT",li.rel) == 0 && li.assetid != 0 )
                {
                    sprintf(numstr,"%llu",(long long)li.assetid);
                    printf("monitor %s %s\n",li.rel,numstr);
                    tradebot_monitor(myinfo,0,0,0,li.exchange,numstr,li.rel,0.);
                } else tradebot_monitor(myinfo,0,0,0,li.exchange,li.base,li.rel,0.);
            }
            myinfo->linfos[i] = li;
            //printf("Set linfo[%d] %s (%s/%s) profitmargin %.6f bid %.8f ask %.8f minvol %.6f maxvol %.6f ref %.8f <- (%s)\n",i,li.exchange,li.base,li.rel,li.profit,li.bid,li.ask,li.minvol,li.maxvol,li.refprice,jprint(vals,0));
            return;
        }
    }
    printf("ERROR: too many linfos %d\n",i);
}

int32_t _default_volume_ok(struct supernet_info *myinfo,struct liquidity_info *li,int32_t dir,double volume,double price)
{
    double minvol,maxvol;
    if ( dir < 0 )
    {
        minvol = li->minvol;
        maxvol = li->maxvol;
    }
    else
    {
        minvol = price * li->minvol;
        maxvol = price * li->maxvol;
    }
    printf("dir.%d minvol %f maxvol %f vs (%f %f) volume %f price %.8f\n",dir,li->minvol,li->maxvol,minvol,maxvol,volume,price);
    if ( (minvol == 0. || volume >= minvol) && (maxvol == 0. || volume <= maxvol) )
        return(0);
    else return(-1);
}

double _default_liquidity_active(struct supernet_info *myinfo,double *refpricep,char *exchange,char *base,char *rel,double destvolume)
{
    int32_t i,dir; struct liquidity_info refli;
    *refpricep = 0.;
    for (i=0; i<sizeof(myinfo->linfos)/sizeof(*myinfo->linfos); i++)
    {
        refli = myinfo->linfos[i];
        if ( refli.base[0] == 0 )
            continue;
        if ( strcmp(base,refli.base) == 0 && strcmp(rel,refli.rel) == 0 )
            dir = 1;
        else if ( strcmp(rel,refli.base) == 0 && strcmp(base,refli.rel) == 0 )
            dir = -1;
        else continue;
        if ( exchange[0] != 0 && refli.exchange[0] != 0 && strcmp(exchange,refli.exchange) != 0 )
        {
            printf("continue %s %s/%s [%d] dir.%d vs %s %s/%s\n",exchange,base,rel,i,dir,refli.exchange,refli.base,refli.rel);
            continue;
        }
        if ( _default_volume_ok(myinfo,&refli,dir,destvolume,dir > 0 ? refli.bid : refli.ask) == 0 )
        {
            if ( refli.profit != 0. )
                *refpricep = refli.refprice;
            else if ( dir > 0 )
                *refpricep = refli.bid;
            else if ( dir < 0 )
                *refpricep = refli.ask;
            printf(">>>>>>>> %s %s/%s [%d] dir.%d vs %s/%s -> %.8f margin %f\n",exchange,base,rel,i,dir,refli.base,refli.rel,*refpricep,refli.profit);
            return(refli.profit);
        }
        break;
    }
    return(0.);
}

struct liquidity_info *_default_lifind(struct supernet_info *myinfo,int32_t *dirp,char *base,char *rel)
{
    struct liquidity_info *li; int32_t i;
    *dirp = 0;
    for (i=0; i<sizeof(myinfo->linfos)/sizeof(*myinfo->linfos); i++)
    {
        li = &myinfo->linfos[i];
        if ( strcmp(li->base,base) == 0 && strcmp(li->rel,rel) == 0 )
        {
            *dirp = 1;
            return(li);
        }
        else if ( strcmp(li->base,rel) == 0 && strcmp(li->rel,base) == 0 )
        {
            *dirp = -1;
            return(li);
        }
    }
    return(0);
}

void _default_swap_balancingtrade(struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t iambob)
{
    // update balance, compare to target balance, issue balancing trade via central exchanges, if needed
    struct liquidity_info *li; double vol,price,volume,srcamount,destamount,profitmargin,dir=0.,dotrade=1.; char base[64],rel[64]; int32_t idir; char *tradestr=0; cJSON *tradejson;
    srcamount = swap->I.req.srcamount;
    destamount = swap->I.req.destamount;
    profitmargin = (double)swap->I.req.profitmargin / 1000000.;
    if ( srcamount <= SMALLVAL || destamount <= SMALLVAL )
    {
        printf("illegal amount for balancing %f %f\n",srcamount,destamount);
        return;
    }
    if ( (li= _default_lifind(myinfo,&idir,swap->I.req.src,swap->I.req.dest)) != 0 )
    {
        if ( idir < 0 )
            vol = 1. / ((double)destamount / SATOSHIDEN);
        else vol = ((double)srcamount / SATOSHIDEN);
        li->totalvol -= vol;
        if ( li->totalvol <= 0. || (li->minvol != 0. && li->totalvol < li->minvol) )
            li->minvol = li->maxvol = li->totalvol = 0.;
        printf("li.(%s/%s) totalvol %f after -= %f minmax.(%f %f)\n",li->base,li->rel,li->totalvol,vol,li->minvol,li->maxvol);
    }
    strcpy(rel,"BTC");
    if ( strcmp(swap->I.req.src,"BTC") == 0 )
    {
        strcpy(base,swap->I.req.dest);
        price = (srcamount / destamount);
        volume = destamount / SATOSHIDEN;
        dir = -1.;
    }
    else if ( strcmp(swap->I.req.dest,"BTC") == 0 )
    {
        strcpy(base,swap->I.req.src);
        price = (destamount / srcamount);
        volume = srcamount / SATOSHIDEN;
        dir = 1.;
    }
    else
    {
        printf("only BTC trades can be balanced, not (%s/%s)\n",swap->I.req.src,swap->I.req.dest);
        return;
    }
    if ( iambob != 0 )
    {
        if ( myinfo->IAMLP != 0 )
        {
            printf("BOB: price %f * vol %f -> %s newprice %f margin %.2f%%\n",price,volume,dir < 0. ? "buy" : "sell",price + dir * price * profitmargin,100*profitmargin);
            if ( dir < 0. )
                tradestr = InstantDEX_buy(myinfo,0,0,0,"bittrex",base,rel,price,volume,dotrade);
            else tradestr = InstantDEX_sell(myinfo,0,0,0,"bittrex",base,rel,price,volume,dotrade);
        }
    }
    else
    {
        if ( myinfo->IAMLP != 0 )
        {
            printf("ALICE: price %f * vol %f -> %s newprice %f margin %.2f%%\n",price,volume,dir > 0. ? "buy" : "sell",price - dir * price * profitmargin,100*profitmargin);
            if ( dir > 0. )
                tradestr = InstantDEX_buy(myinfo,0,0,0,"bittrex",base,rel,price,volume,dotrade);
            else tradestr = InstantDEX_sell(myinfo,0,0,0,"bittrex",base,rel,price,volume,dotrade);
        }
    }
    if ( tradestr != 0 )
    {
        if ( (tradejson= cJSON_Parse(tradestr)) != 0 )
        {
            if ( jobj(tradejson,"error") == 0 ) // balancing is opposite trade
                tradebot_pendingadd(myinfo,tradejson,swap->I.req.dest,destamount,swap->I.req.src,srcamount);
            else free_json(tradejson);
        }
        free(tradestr);
    }
}

void tradebot_swap_balancingtrade(struct supernet_info *myinfo,struct basilisk_swap *swap,int32_t iambob)
{
    if ( swap->bobcoin != 0 && swap->alicecoin != 0 )
    {
        if ( iambob != 0 )
        {
            if ( strcmp(swap->I.req.src,swap->bobcoin->symbol) == 0 )
                swap->bobcoin->DEXinfo.DEXpending -= swap->I.req.srcamount;
            else if ( strcmp(swap->I.req.dest,swap->bobcoin->symbol) == 0 )
                swap->bobcoin->DEXinfo.DEXpending -= swap->I.req.destamount;
        }
        else
        {
            if ( strcmp(swap->I.req.src,swap->alicecoin->symbol) == 0 )
                swap->alicecoin->DEXinfo.DEXpending -= swap->I.req.srcamount;
            else if ( strcmp(swap->I.req.dest,swap->alicecoin->symbol) == 0 )
                swap->alicecoin->DEXinfo.DEXpending -= swap->I.req.destamount;
        }
    }
    printf(">>>>>>>>>>>>>>>>>> balancing trade done by marketmaker\n");
    return;
    if ( swap->balancingtrade == 0 )
        _default_swap_balancingtrade(myinfo,swap,iambob);
    else (*swap->balancingtrade)(myinfo,swap,iambob);
}

void tradebot_liquidity_command(struct supernet_info *myinfo,char *base,bits256 hash,cJSON *vals)
{
    // processed in LIFO manner which allows to override existing command
    if ( myinfo->liquidity_command == 0 )
        _default_liquidity_command(myinfo,base,hash,vals);
    else (*myinfo->liquidity_command)(myinfo,base,hash,vals);
}

double tradebot_liquidity_active(struct supernet_info *myinfo,double *refpricep,char *exchange,char *base,char *rel,double destvolume)
{
    if ( myinfo->liquidity_active == 0 )
        return(_default_liquidity_active(myinfo,refpricep,exchange,base,rel,destvolume));
    else return((*myinfo->liquidity_active)(myinfo,refpricep,exchange,base,rel,destvolume));
}

// struct exchange_quote { uint64_t satoshis,orderid,offerNXT,exchangebits; double price,volume; uint32_t timestamp,val; };

void tradebots_processprices(struct supernet_info *myinfo,struct exchange_info *exchange,char *base,char *rel,struct exchange_quote *bidasks,int32_t numbids,int32_t numasks)
{
    double price,profitmargin=0.,volume; struct tradebot_arbpair *pair;
    if ( strcmp(rel,"NXT") == 0 && strcmp(base,"BTC") != 0 && (base= NXT_assetnamefind(base)) == 0 )
    {
        //printf("reject %s %s/%s\n",exchange,base,rel);
        return;
    }
    else if ( strcmp(base,"NXT") == 0 && strcmp(rel,"BTC") != 0 && (rel= NXT_assetnamefind(rel)) == 0 )
    {
        //printf("reject %s %s/%s\n",exchange,base,rel);
        return;
    }
    printf("%s %s/%s bids.%d asks.%d\n",exchange->name,base,rel,numbids,numasks);
    if ( numbids > 0 && (volume= bidasks[0].volume) > 0. && (profitmargin=
                         tradebot_liquidity_active(myinfo,&price,exchange->name,base,rel,volume)) > 0. )
    {
        if ( price == 0. )
            price = bidasks[0].price;
        tradebot_arbcandidate(myinfo,exchange->name,1,base,rel,price,volume,(uint32_t)time(NULL),profitmargin);
    }
    if ( numasks > 0 && (volume= bidasks[1].volume) > 0. && (profitmargin=
                         tradebot_liquidity_active(myinfo,&price,exchange->name,rel,base,volume)) > 0. )
    {
        if ( price == 0. )
            price = bidasks[1].price;
        tradebot_arbcandidate(myinfo,exchange->name,-1,base,rel,price,volume,(uint32_t)time(NULL),profitmargin);
    }
    if ( (pair= tradebots_arbpair_find(base,rel)) == 0 )
        pair = tradebots_arbpair_create(base,rel);
    if ( pair != 0 )
    {
        if ( strcmp(rel,"NXT") == 0 )
        {
            if ( pair->btcbid != 0. && pair->btcask != 0. )
            {
                tradebot_arbcandidate(myinfo,"arb",1,base,"BTC",pair->btcbid,pair->btcvol,(uint32_t)time(NULL),profitmargin);
                tradebot_arbcandidate(myinfo,"arb",-1,base,"BTC",pair->btcask,pair->btcvol,(uint32_t)time(NULL),profitmargin);
            }
        }
        if ( strcmp(rel,"USD") != 0 && pair->usdbid != 0. && pair->usdask != 0. )
        {
            tradebot_arbcandidate(myinfo,"arb",1,base,"USD",pair->usdbid,pair->usdvol,(uint32_t)time(NULL),profitmargin);
            tradebot_arbcandidate(myinfo,"arb",-1,base,"USD",pair->usdask,pair->usdvol,(uint32_t)time(NULL),profitmargin);
        }
        if ( strcmp(rel,"CNY") != 0 && pair->cnybid != 0. && pair->cnyask != 0. )
        {
            tradebot_arbcandidate(myinfo,"arb",1,base,"CNY",pair->cnybid,pair->cnyvol,(uint32_t)time(NULL),profitmargin);
            tradebot_arbcandidate(myinfo,"arb",-1,base,"CNY",pair->cnyask,pair->cnyvol,(uint32_t)time(NULL),profitmargin);
        }
    }
}
