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
#include "exchanges/bitcoin.h"

int32_t bitcoin_pubkeyspend(uint8_t *script,int32_t n,uint8_t pubkey[66])
{
    int32_t plen = bitcoin_pubkeylen(pubkey);
    script[n++] = plen;
    memcpy(&script[n],pubkey,plen);
    n += plen;
    script[n++] = SCRIPT_OP_CHECKSIG;
    return(n);
}

int32_t bitcoin_p2shspend(uint8_t *script,int32_t n,uint8_t rmd160[20])
{
    script[n++] = SCRIPT_OP_HASH160;
    script[n++] = 0x14; memcpy(&script[n],rmd160,0x14); n += 0x14;
    script[n++] = SCRIPT_OP_EQUAL;
    return(n);
}

int32_t bitcoin_secret160verify(uint8_t *script,int32_t n,uint8_t secret160[20])
{
    script[n++] = SCRIPT_OP_HASH160;
    script[n++] = 0x14;
    memcpy(&script[n],secret160,0x14);
    n += 0x14;
    script[n++] = SCRIPT_OP_EQUALVERIFY;
    return(n);
}

int32_t bitcoin_secret256spend(uint8_t *script,int32_t n,bits256 secret)
{
    script[n++] = SCRIPT_OP_SHA256;
    script[n++] = 0x20;
    memcpy(&script[n],secret.bytes,0x20);
    n += 0x20;
    script[n++] = SCRIPT_OP_EQUAL;
    return(n);
}

// OP_DUP OP_HASH160 <hash of pubkey> OP_EQUALVERIFY OP_CHECKSIG
int32_t bitcoin_standardspend(uint8_t *script,int32_t n,uint8_t rmd160[20])
{
    script[n++] = SCRIPT_OP_DUP;
    script[n++] = SCRIPT_OP_HASH160;
    script[n++] = 0x14; memcpy(&script[n],rmd160,0x14); n += 0x14;
    script[n++] = SCRIPT_OP_EQUALVERIFY;
    script[n++] = SCRIPT_OP_CHECKSIG;
    return(n);
}

int32_t bitcoin_checklocktimeverify(uint8_t *script,int32_t n,uint32_t locktime)
{
    script[n++] = 4;
    script[n++] = locktime & 0xff, locktime >>= 8;
    script[n++] = locktime & 0xff, locktime >>= 8;
    script[n++] = locktime & 0xff, locktime >>= 8;
    script[n++] = locktime & 0xff;
    script[n++] = SCRIPT_OP_CHECKLOCKTIMEVERIFY;
    script[n++] = SCRIPT_OP_DROP;
    return(n);
}

int32_t bitcoin_timelockspend(uint8_t *script,int32_t n,uint8_t rmd160[20],uint32_t timestamp)
{
    n = bitcoin_checklocktimeverify(script,n,timestamp);
    n = bitcoin_standardspend(script,n,rmd160);
    return(n);
}

int32_t bitcoin_MofNspendscript(uint8_t p2sh_rmd160[20],uint8_t *script,int32_t n,const struct vin_info *vp)
{
    int32_t i,plen;
    script[n++] = 0x50 + vp->M;
    for (i=0; i<vp->N; i++)
    {
        if ( (plen= bitcoin_pubkeylen(vp->signers[i].pubkey)) < 0 )
            return(-1);
        script[n++] = plen;
        memcpy(&script[n],vp->signers[i].pubkey,plen);
        n += plen;
    }
    script[n++] = 0x50 + vp->N;
    script[n++] = SCRIPT_OP_CHECKMULTISIG;
    calc_rmd160_sha256(p2sh_rmd160,script,n);
    return(n);
}

int32_t bitcoin_p2shscript(uint8_t *script,int32_t n,const uint8_t *p2shscript,const int32_t p2shlen)
{
    if ( p2shlen >= 0xfd )
    {
        script[n++] = 0x4d;
        script[n++] = (p2shlen & 0xff);
        script[n++] = ((p2shlen >> 8) & 0xff);
    }
    else if ( p2shlen > 76 )
    {
        script[n++] = 0x4c;
        script[n++] = p2shlen;
    } else script[n++] = p2shlen;
    memcpy(&script[n],p2shscript,p2shlen), n += p2shlen;
    return(n);
}

int32_t bitcoin_changescript(struct iguana_info *coin,uint8_t *changescript,int32_t n,uint64_t *changep,char *changeaddr,uint64_t inputsatoshis,uint64_t satoshis,uint64_t txfee)
{
    uint8_t addrtype,rmd160[20]; int32_t len;
    *changep = 0;
    if ( inputsatoshis >= (satoshis + txfee) )
    {
        *changep = inputsatoshis - (satoshis + txfee);
        if ( changeaddr != 0 && changeaddr[0] != 0 )
        {
            bitcoin_addr2rmd160(&addrtype,rmd160,changeaddr);
            if ( addrtype == coin->chain->pubtype )
                len = bitcoin_standardspend(changescript,0,rmd160);
            else if ( addrtype == coin->chain->p2shtype )
                len = bitcoin_standardspend(changescript,0,rmd160);
            else
            {
                printf("error with mismatched addrtype.%02x vs (%02x %02x)\n",addrtype,coin->chain->pubtype,coin->chain->p2shtype);
                return(-1);
            }
            return(len);
        }
        else printf("error no change address when there is change\n");
    }
    return(-1);
}

int32_t bitcoin_scriptsig(struct iguana_info *coin,uint8_t *script,int32_t n,const struct vin_info *vp,struct iguana_msgtx *msgtx)
{
    int32_t i,siglen,plen;
    if ( vp->N > 1 )
        script[n++] = SCRIPT_OP_NOP;
    for (i=0; i<vp->N; i++)
    {
        if ( (siglen= vp->signers[i].siglen) != 0 )
        {
            script[n++] = siglen;
            memcpy(&script[n],vp->signers[i].sig,siglen), n += siglen;
        }
    }
    if ( (plen= bitcoin_pubkeylen(vp->signers[0].pubkey)) > 0 && vp->type == IGUANA_SCRIPT_76A988AC )
    {
        script[n++] = plen;
        memcpy(&script[n],vp->signers[0].pubkey,plen), n += plen;
    }
    if ( vp->type == IGUANA_SCRIPT_P2SH )
    {
        printf("add p2sh script to sig\n");
        n = bitcoin_p2shscript(script,n,vp->p2shscript,vp->p2shlen);
    }
    return(n);
}

int32_t bitcoin_cltvscript(uint8_t p2shtype,char *ps2h_coinaddr,uint8_t p2sh_rmd160[20],uint8_t *script,int32_t n,char *senderaddr,char *otheraddr,uint8_t secret160[20],uint32_t locktime)
{
    // OP_IF
    //      <timestamp> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
    // OP_ELSE
    //      OP_HASH160 secret160 OP_EQUALVERIFY OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG // standard spend
    // OP_ENDIF
    uint8_t rmd160A[20],rmd160B[20],addrtypeA,addrtypeB;
    bitcoin_addr2rmd160(&addrtypeA,rmd160A,senderaddr);
    bitcoin_addr2rmd160(&addrtypeB,rmd160B,otheraddr);
    script[n++] = SCRIPT_OP_IF;
    n = bitcoin_checklocktimeverify(script,n,locktime);
    n = bitcoin_standardspend(script,n,rmd160A);
    script[n++] = SCRIPT_OP_ELSE;
    n = bitcoin_secret160verify(script,n,secret160);
    n = bitcoin_standardspend(script,n,rmd160B);
    script[n++] = SCRIPT_OP_ENDIF;
    calc_rmd160_sha256(p2sh_rmd160,script,n);
    bitcoin_address(ps2h_coinaddr,p2shtype,p2sh_rmd160,20);
    return(n);
}

uint8_t iguana_addrtype(struct iguana_info *coin,uint8_t script_type)
{
    if ( script_type == IGUANA_SCRIPT_76A988AC || script_type == IGUANA_SCRIPT_AC || script_type == IGUANA_SCRIPT_76AC )
        return(coin->chain->pubtype);
    else
    {
        //printf("P2SH type.%d\n",script_type);
        return(coin->chain->p2shtype);
    }
}

int32_t iguana_scriptgen(struct iguana_info *coin,int32_t *Mp,int32_t *nump,char *coinaddr,uint8_t *script,char *asmstr,uint8_t rmd160[20],uint8_t type,const struct vin_info *vp,int32_t txi)
{
    uint8_t addrtype; char rmd160str[41],pubkeystr[256]; int32_t plen,i,m,n,flag = 0,scriptlen = 0;
    m = n = 0;
    if ( asmstr != 0 )
        asmstr[0] = 0;
    addrtype = iguana_addrtype(coin,type);
    if ( type == IGUANA_SCRIPT_76A988AC || type == IGUANA_SCRIPT_AC || type == IGUANA_SCRIPT_76AC || type == IGUANA_SCRIPT_P2SH )
    {
        init_hexbytes_noT(rmd160str,rmd160,20);
        bitcoin_address(coinaddr,addrtype,rmd160,20);
    }
    switch ( type )
    {
        case IGUANA_SCRIPT_NULL:
            if ( asmstr != 0 )
                strcpy(asmstr,txi == 0 ? "coinbase " : "PoSbase ");
            flag++;
            coinaddr[0] = 0;
            break;
        case IGUANA_SCRIPT_76AC:
        case IGUANA_SCRIPT_AC:
            if ( (plen= bitcoin_pubkeylen(vp->signers[0].pubkey)) < 0 )
                return(0);
            init_hexbytes_noT(pubkeystr,(uint8_t *)vp->signers[0].pubkey,plen);
            if ( asmstr != 0 )
            {
                if ( type == IGUANA_SCRIPT_76AC )
                    strcpy(asmstr,"OP_DUP ");
                sprintf(asmstr + strlen(asmstr),"%s OP_CHECKSIG // %s",pubkeystr,coinaddr);
            }
            if ( type == IGUANA_SCRIPT_76AC )
                script[scriptlen++] = 0x76;
            scriptlen = bitcoin_pubkeyspend(script,scriptlen,(uint8_t *)vp->signers[0].pubkey);
            //printf("[%02x] type.%d scriptlen.%d\n",vp->signers[0].pubkey[0],type,scriptlen);
            break;
        case IGUANA_SCRIPT_76A988AC:
            if ( asmstr != 0 )
                sprintf(asmstr,"OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG // %s",rmd160str,coinaddr);
            scriptlen = bitcoin_standardspend(script,0,rmd160);
            break;
        case IGUANA_SCRIPT_P2SH:
            if ( asmstr != 0 )
                sprintf(asmstr,"OP_HASH160 %s OP_EQUAL // %s",rmd160str,coinaddr);
            scriptlen = bitcoin_p2shspend(script,0,rmd160);
            break;
        case IGUANA_SCRIPT_OPRETURN:
            if ( asmstr != 0 )
                strcpy(asmstr,"OP_RETURN ");
            bitcoin_address(coinaddr,addrtype,(uint8_t *)&vp->spendscript[0],vp->spendlen);
            flag++;
            break;
        case IGUANA_SCRIPT_3of3: m = 3, n = 3; break;
        case IGUANA_SCRIPT_2of3: m = 2, n = 3; break;
        case IGUANA_SCRIPT_1of3: m = 1, n = 3; break;
        case IGUANA_SCRIPT_2of2: m = 2, n = 2; break;
        case IGUANA_SCRIPT_1of2: m = 1, n = 2; break;
        case IGUANA_SCRIPT_1of1: m = 1, n = 1; break;
        case IGUANA_SCRIPT_MSIG: m = vp->M, n = vp->N; break;
        case IGUANA_SCRIPT_DATA:
            if ( asmstr != 0 )
                strcpy(asmstr,"DATA ONLY");
            bitcoin_address(coinaddr,addrtype,(uint8_t *)&vp->spendscript[0],vp->spendlen);
            flag++;
            break;
        case IGUANA_SCRIPT_STRANGE:
            if ( asmstr != 0 )
                strcpy(asmstr,"STRANGE SCRIPT ");
            bitcoin_address(coinaddr,addrtype,(uint8_t *)&vp->spendscript[0],vp->spendlen);
            flag++;
            break;
        default: break;//printf("unexpected script type.%d\n",type); break;
    }
    if ( n > 0 )
    {
        scriptlen = bitcoin_MofNspendscript(rmd160,script,0,vp);
        bitcoin_address(coinaddr,coin->chain->p2shtype,script,scriptlen);
        if ( asmstr != 0 )
        {
            sprintf(asmstr,"%d ",m);
            for (i=0; i<n; i++)
            {
                if ( (plen= bitcoin_pubkeylen(vp->signers[i].pubkey)) > 0 )
                {
                    init_hexbytes_noT(asmstr + strlen(asmstr),(uint8_t *)vp->signers[i].pubkey,plen);
                    if ( asmstr != 0 )
                        strcat(asmstr," ");
                }
                else if ( asmstr != 0 )
                    strcat(asmstr,"NOPUBKEY ");
                sprintf(asmstr + strlen(asmstr),"%d // M.%d of N.%d [",n,m,n);
                for (i=0; i<n; i++)
                    sprintf(asmstr + strlen(asmstr),"%s%s",vp->signers[i].coinaddr,i<n-1?" ":"");
            }
            strcat(asmstr,"]\n");
        }
    }
    if ( flag != 0 && asmstr != 0 && vp->spendlen > 0 )
        init_hexbytes_noT(asmstr + strlen(asmstr),(uint8_t *)vp->spendscript,vp->spendlen);
    *Mp = m, *nump = n;
    return(scriptlen);
}

int32_t _iguana_calcrmd160(struct iguana_info *coin,struct vin_info *vp)
{
    static uint8_t zero_rmd160[20];
    char hexstr[8192]; uint8_t *script,type; int32_t i,n,m,plen;
    if ( vp->N == 0 )
        vp->N = 1;
    if ( vp->M == 0 )
        vp->M = 1;
    type = IGUANA_SCRIPT_STRANGE;
    init_hexbytes_noT(hexstr,vp->spendscript,vp->spendlen);
    //char str[65]; printf("script.(%s).%d in %s len.%d plen.%d spendlen.%d cmp.%d\n",hexstr,vp->spendlen,bits256_str(str,vp->vin.prev_hash),vp->spendlen,bitcoin_pubkeylen(&vp->spendscript[1]),vp->spendlen,vp->spendscript[vp->spendlen-1] == SCRIPT_OP_CHECKSIG);
    if ( vp->spendlen == 0 )
    {
        if ( zero_rmd160[0] == 0 )
        {
            calc_rmd160_sha256(zero_rmd160,vp->spendscript,vp->spendlen);
            //vcalc_sha256(0,sha256,vp->spendscript,vp->spendlen); // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            //calc_rmd160(0,zero_rmd160,sha256,sizeof(sha256)); // b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
            init_hexbytes_noT(hexstr,zero_rmd160,20);
        }
        memcpy(vp->rmd160,zero_rmd160,sizeof(zero_rmd160));
        return(IGUANA_SCRIPT_NULL);
    }
    else if ( vp->spendscript[0] == SCRIPT_OP_RETURN )
        type = IGUANA_SCRIPT_OPRETURN;
    else if ( vp->spendscript[0] == SCRIPT_OP_DUP && vp->spendscript[1] == SCRIPT_OP_HASH160 && vp->spendscript[2] == 20 && vp->spendscript[vp->spendscript[2]+3] == SCRIPT_OP_EQUALVERIFY && vp->spendscript[vp->spendscript[2]+4] == SCRIPT_OP_CHECKSIG )
    {
        //printf("IGUANA_SCRIPT_76A988AC plen.%d vs %d vp->spendlen\n",vp->spendscript[2]+4,vp->spendlen);
        // 76a9145f69cb73016264270dae9f65c51f60d0e4d6fd4488ac
        memcpy(vp->rmd160,&vp->spendscript[3],20);
        if ( (plen= vp->spendscript[2]+5) != vp->spendlen )
        {
            return(IGUANA_SCRIPT_STRANGE);
            /*while ( plen < vp->spendlen )
                if ( vp->spendscript[plen++] != 0x61 ) // nop
                    return(IGUANA_SCRIPT_STRANGE);*/
        }
        return(IGUANA_SCRIPT_76A988AC);
    }
    // 21035f1321ed17d387e4433b2fa229c53616057964af065f98bfcae2233c5108055eac
    else if ( vp->spendscript[0] == SCRIPT_OP_DUP && (plen= bitcoin_pubkeylen(&vp->spendscript[2])) > 0 && vp->spendscript[vp->spendlen-1] == SCRIPT_OP_CHECKSIG && vp->spendscript[0] == plen && vp->spendlen == plen+3 )
    {
        memcpy(vp->signers[0].pubkey,&vp->spendscript[2],plen);
        calc_rmd160_sha256(vp->rmd160,vp->signers[0].pubkey,plen);
        //printf("found IGUANA_SCRIPT_76AC\n");
        return(IGUANA_SCRIPT_76AC);
    }
    else if ( (plen= bitcoin_pubkeylen(&vp->spendscript[1])) > 0 && vp->spendscript[vp->spendlen-1] == SCRIPT_OP_CHECKSIG && vp->spendscript[0] == plen && vp->spendlen == plen+2 )
    {
        memcpy(vp->signers[0].pubkey,&vp->spendscript[1],plen);
        calc_rmd160_sha256(vp->rmd160,vp->signers[0].pubkey,plen);
        //printf("found IGUANA_SCRIPT_AC\n");
        return(IGUANA_SCRIPT_AC);
    }
    else if ( vp->spendscript[0] == SCRIPT_OP_HASH160 && vp->spendscript[1] == 0x14 && vp->spendlen == 23 && vp->spendscript[22] == SCRIPT_OP_EQUAL )
    {
        memcpy(vp->rmd160,vp->spendscript+2,20);
        return(IGUANA_SCRIPT_P2SH);
    }
    else if ( vp->spendlen > 34 && vp->spendscript[vp->spendlen-1] == SCRIPT_OP_CHECKMULTISIG && (n= vp->spendscript[vp->spendlen-2]) >= 0x51 && n <= 0x60 && (m= vp->spendscript[0]) >= 0x51 && m <= n ) // m of n multisig
    {
        m -= 0x50, n -= 0x50;
        script = vp->spendscript+1;
        for (i=0; i<n; i++,script += plen)
        {
            plen = *script++;
            if ( bitcoin_pubkeylen(script) != plen )
            {
                static int32_t counter;
                if ( counter++ < 3 )
                    printf("multisig.%d of %d: invalid pubkey[%02x] len %d\n",i,n,script[0],bitcoin_pubkeylen(script));
                return(-1);
            }
            memcpy(vp->signers[i].pubkey,script,plen);
            calc_rmd160_sha256(vp->signers[i].rmd160,vp->signers[i].pubkey,plen);
            bitcoin_address(vp->signers[i].coinaddr,coin->chain->pubtype,vp->signers[i].pubkey,plen);
        }
        if ( (int32_t)((long)script - (long)vp->spendscript) == vp->spendlen-2 )
        {
            vp->N = n;
            vp->M = m;
            //printf("M.%d N.%d\n",m,n);
        }
        calc_rmd160_sha256(vp->rmd160,vp->spendscript,vp->spendlen);
        if ( n == 3 )
        {
            if ( m == 3 )
                return(IGUANA_SCRIPT_3of3);
            else if ( m == 2 )
                return(IGUANA_SCRIPT_2of3);
            else if ( m == 1 )
                return(IGUANA_SCRIPT_1of3);
        }
        else if ( n == 2 )
        {
            if ( m == 2 )
                return(IGUANA_SCRIPT_2of2);
            else if ( m == 1 )
                return(IGUANA_SCRIPT_1of2);
        }
        else if ( m == 1 && n == 1 )
            return(IGUANA_SCRIPT_1of1);
        //printf("strange msig M.%d of N.%d\n",m,n);
        return(IGUANA_SCRIPT_MSIG);
    }
    else if ( vp->spendlen == vp->spendscript[0]+1 )
    {
        //printf("just data.%d\n",vp->spendlen);
        memcpy(vp->rmd160,zero_rmd160,sizeof(zero_rmd160));
        return(IGUANA_SCRIPT_DATA);
    }
    if ( type != IGUANA_SCRIPT_OPRETURN && type != IGUANA_SCRIPT_DATA )
    {
        if ( vp->spendlen > 0 && vp->spendlen < sizeof(hexstr)/2-1 )
        {
            static FILE *fp;
            init_hexbytes_noT(hexstr,vp->spendscript,vp->spendlen);
            //char str[65]; printf("unparsed script.(%s).%d in %s len.%d\n",hexstr,vp->spendlen,bits256_str(str,vp->vin.prev_hash),vp->spendlen);
            if ( 1 && fp == 0 )
                fp = fopen("unparsed.txt","w");
            if ( fp != 0 )
                fprintf(fp,"%s\n",hexstr), fflush(fp);
        } else sprintf(hexstr,"pkscript overflowed %ld\n",(long)sizeof(hexstr));
    }
    calc_rmd160_sha256(vp->rmd160,vp->spendscript,vp->spendlen);
    return(type);
}

int32_t iguana_calcrmd160(struct iguana_info *coin,char *asmstr,struct vin_info *vp,uint8_t *pk_script,int32_t pk_scriptlen,bits256 debugtxid,int32_t vout,uint32_t sequence)
{
    int32_t scriptlen; uint8_t script[IGUANA_MAXSCRIPTSIZE];
    memset(vp,0,sizeof(*vp));
    vp->vin.prev_hash = debugtxid, vp->vin.prev_vout = vout;
    vp->spendlen = pk_scriptlen;
    vp->vin.sequence = sequence;
    memcpy(vp->spendscript,pk_script,pk_scriptlen);
    if ( (vp->type= _iguana_calcrmd160(coin,vp)) >= 0 )
    {
        scriptlen = iguana_scriptgen(coin,&vp->M,&vp->N,vp->coinaddr,script,asmstr,vp->rmd160,vp->type,(const struct vin_info *)vp,vout);
        if ( vp->M == 0 && vp->N == 0 )
        {
            vp->M = vp->N = 1;
            strcpy(vp->signers[0].coinaddr,vp->coinaddr);
            memcpy(vp->signers[0].rmd160,vp->rmd160,20);
        }
        if ( scriptlen != pk_scriptlen || (scriptlen != 0 && memcmp(script,pk_script,scriptlen) != 0) )
        {
            if ( vp->type != IGUANA_SCRIPT_OPRETURN && vp->type != IGUANA_SCRIPT_DATA && vp->type != IGUANA_SCRIPT_STRANGE )
            {
                int32_t i;
                printf("\n--------------------\n");
                for (i=0; i<scriptlen; i++)
                    printf("%02x ",script[i]);
                printf("script.%d\n",scriptlen);
                for (i=0; i<pk_scriptlen; i++)
                    printf("%02x ",pk_script[i]);
                printf("original script.%d\n",pk_scriptlen);
                printf("iguana_calcrmd160 type.%d error regenerating scriptlen.%d vs %d\n\n",vp->type,scriptlen,pk_scriptlen);
            }
        }
    }
    return(vp->type);
}

char *iguana_scriptaddress(struct iguana_info *coin,char *coinaddr,uint8_t *script,int32_t scriptlen)
{
    struct vin_info V;
    iguana_calcrmd160(coin,0,&V,script,scriptlen,GENESIS_PUBKEY,0,0xffffffff);
    if ( V.coinaddr[0] != 0 )
    {
        strcpy(coinaddr,V.coinaddr);
        return(coinaddr);
    }
    return(0);
}

//error memalloc mem.0x7f6fc6e4a2a8 94.242.229.158 alloc 1 used 2162688 totalsize.2162688 -> 94.242.229.158 (nil)

int32_t bitcoin_scriptget(struct iguana_info *coin,int32_t *hashtypep,uint32_t *sigsizep,uint32_t *pubkeysizep,uint8_t **userdatap,uint32_t *userdatalenp,struct vin_info *vp,uint8_t *scriptsig,int32_t len,int32_t spendtype)
{
    int32_t j,n,siglen,plen; uint8_t *p2shscript;
    j = n = 0;
    *userdatap = 0;
    *userdatalenp = *pubkeysizep = *sigsizep = 0;
    *hashtypep = SIGHASH_ALL;
    while ( (siglen= scriptsig[n]) >= 70 && siglen <= 73 && n+siglen < len && j < 16 )
    {
        vp->signers[j].siglen = siglen;
        memcpy(vp->signers[j].sig,&scriptsig[n+1],siglen);
        if ( j == 0 )
            *hashtypep = vp->signers[j].sig[siglen-1];
        else if ( vp->signers[j].sig[siglen-1] != *hashtypep )
        {
            //printf("SIGHASH.%d  mismatch %d vs %d\n",j,vp->signers[j].sig[siglen-1],*hashtypep);
            break;
        }
        (*sigsizep) += siglen;
        //printf("sigsize %d [%02x]\n",*sigsizep,vp->signers[j].sig[siglen-1]);
        n += (siglen + 1);
        j++;
        if ( spendtype == 0 && j > 1 )
            spendtype = IGUANA_SCRIPT_MSIG;
    }
    vp->numsigs = j;
    vp->type = spendtype;
    if ( j == 0 )
    {
        //*userdatalenp = len;
        vp->spendlen = len;
        return(vp->spendlen);
    }
    j = 0;
    while ( ((plen= scriptsig[n]) == 33 || plen == 65) && j < 16 && plen+n <= len )
    {
        memcpy(vp->signers[j].pubkey,&scriptsig[n+1],plen);
        calc_rmd160_sha256(vp->signers[j].rmd160,vp->signers[j].pubkey,plen);
        if ( j == 0 )
            memcpy(vp->rmd160,vp->signers[j].rmd160,20);
        n += (plen + 1);
        (*pubkeysizep) += plen;
        j++;
    }
    vp->numpubkeys = j;
    *userdatap = &scriptsig[n];
    if ( len > n )
        *userdatalenp = (len - n);
    p2shscript = 0;
    while ( n < len )
    {
        if ( n+2 < len && (scriptsig[n] == 0x4c || scriptsig[n] == 0x4d) )
        {
            if ( scriptsig[n] == 0x4c )
                vp->p2shlen = scriptsig[n+1], n += 2;
            else vp->p2shlen = ((uint32_t)scriptsig[n+1] + ((uint32_t)scriptsig[n+2] << 8)), n += 3;
            //printf("p2sh opcode.%02x %02x %02x scriptlen.%d\n",scriptsig[n],scriptsig[n+1],scriptsig[n+2],vp->p2shlen);
            if ( vp->p2shlen < IGUANA_MAXSCRIPTSIZE && n+vp->p2shlen <= len )
            {
                p2shscript = &scriptsig[n];
                memcpy(vp->p2shscript,&scriptsig[n],vp->p2shlen);
                n += vp->p2shlen;
                vp->type = IGUANA_SCRIPT_P2SH;
            } else vp->p2shlen = 0;
        }
    }
    if ( *userdatap == p2shscript )
        *userdatap = 0;
    /*if ( len == 0 )
     {
     //  txid.(eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2).v1
     decode_hex(vp->rmd160,20,"010966776006953d5567439e5e39f86a0d273bee");//3564a74f9ddb4372301c49154605573d7d1a88fe");
     vp->type = IGUANA_SCRIPT_76A988AC;
     }*/
    vp->spendlen = iguana_scriptgen(coin,&vp->M,&vp->N,vp->coinaddr,vp->spendscript,0,vp->rmd160,vp->type,(const struct vin_info *)vp,vp->vin.prev_vout);
    //printf("type.%d asmstr.(%s) spendlen.%d\n",vp->type,asmstr,vp->spendlen);
    return(vp->spendlen);
}

int32_t iguana_vinscriptparse(struct iguana_info *coin,struct vin_info *vp,uint32_t *sigsizep,uint32_t *pubkeysizep,uint32_t *p2shsizep,uint32_t *userdatalenp,uint8_t *vinscript,int32_t scriptlen)
{
    int32_t hashtype; uint8_t *userdata = 0;
    *sigsizep = *pubkeysizep = *p2shsizep = *userdatalenp = 0;
    if ( bitcoin_scriptget(coin,&hashtype,sigsizep,pubkeysizep,&userdata,userdatalenp,vp,vinscript,scriptlen,0) < 0 )
    {
        printf("iguana_vinscriptparse: error parsing vinscript?\n");
        return(-1);
    }
    if ( userdata != 0 && *userdatalenp > 0 )
        memcpy(vp->userdata,userdata,*userdatalenp);
    if ( vp->type == IGUANA_SCRIPT_P2SH )
    {
        *p2shsizep = vp->p2shlen + 1 + (vp->p2shlen >= 0xfd)*2;
        //printf("P2SHSIZE.%d\n",*p2shsizep);
    }
    return(hashtype);
}

char *iguana_scriptget(struct iguana_info *coin,char *scriptstr,char *asmstr,int32_t max,int32_t hdrsi,uint32_t unspentind,bits256 txid,int32_t vout,uint8_t *rmd160,int32_t type,uint8_t *pubkey33)
{
    int32_t scriptlen; uint8_t script[IGUANA_MAXSCRIPTSIZE]; struct vin_info V,*vp = &V;
    memset(vp,0,sizeof(*vp));
    scriptstr[0] = 0;
    if ( asmstr != 0 )
        asmstr[0] = 0;
    if ( pubkey33 != 0 && bitcoin_pubkeylen(pubkey33) > 0 )
        memcpy(vp->signers[0].pubkey,pubkey33,33);
    scriptlen = iguana_scriptgen(coin,&vp->M,&vp->N,vp->coinaddr,script,asmstr,rmd160,type,(const struct vin_info *)vp,vout);
    init_hexbytes_noT(scriptstr,script,scriptlen);
    return(scriptstr);
}


#ifdef later

uint32_t iguana_ramchain_pubkeyoffset(struct iguana_info *coin,RAMCHAIN_FUNC,int32_t createflag,uint32_t *pkindp,uint32_t *scriptoffsetp,uint8_t *pubkey,uint8_t rmd160[20])
{
    uint32_t pkind; int32_t plen; struct iguana_kvitem *ptr;
    if ( (ptr= iguana_hashfind(ramchain,'P',rmd160)) == 0 )
    {
        if ( createflag != 0 )
        {
            //printf("from pubkeyoffset\n");
            pkind = iguana_ramchain_addpkhash(coin,RAMCHAIN_ARG,rmd160,0,0,0);
            //int32_t i; for (i=0; i<33; i++)
            //    printf("%02x",pubkey[i]);
            //printf(" pkind.%d created from pubkeyoffset\n",pkind);
            *pkindp = pkind + 1;
        } else return(0);
    } else pkind = ptr->hh.itemind;
    if ( P[pkind].pubkeyoffset == 0 )
    {
        plen = bitcoin_pubkeylen(pubkey);
        if ( plen > 0 )
        {
            if ( *scriptoffsetp == 0 )
                *scriptoffsetp++ = 0;
            P[pkind].pubkeyoffset = *scriptoffsetp, *scriptoffsetp += plen;
            // printf(" plen.%d -> new offset.%d\n",plen,*scriptoffsetp);
            memcpy(&Kspace[P[pkind].pubkeyoffset],pubkey,plen);
        }
        else
        {
            //int32_t i; for (i=0; i<plen; i++)
            //    printf("%02x",pubkey[i]);
            //printf("iguana_ramchain_pubkeyoffset: illegal pubkey?\n");
            return(0);
        }
    }
    return(P[pkind].pubkeyoffset);
}

int32_t iguana_vinscriptdecode(struct iguana_info *coin,struct iguana_ramchain *ramchain,int32_t *metalenp,uint8_t _script[IGUANA_MAXSCRIPTSIZE],uint8_t *Kstackend,uint8_t *Kspace,struct iguana_spend *s)
{
    int32_t i,suffixlen,len = 0; long diff; uint8_t *pubkey,*metascript = &Kspace[s->scriptoffset]; uint32_t poffset; int32_t totalsize,sigslen,plen,stacksize=0,p2shlen=0,scriptlen = 0;
    if ( s->scriptoffset == 0 )
    {
        //printf("iguana_vinscriptdecode: null scriptoffset\n");
        return(0);
    }
    len += iguana_rwvarint32(0,&metascript[len],(void *)&totalsize);
    *metalenp = 0;
    if ( s->rawmode != 0 )
    {
        *metalenp = 0;
        if ( totalsize < IGUANA_MAXSCRIPTSIZE )
        {
            //printf("rawmode.%d\n",totalsize);
            memcpy(_script,&metascript[len],totalsize);
            return(totalsize);
        }
        printf("illegal rawmode vinscript totalsize.%d\n",totalsize);
        return(-1);
    }
    if ( totalsize > IGUANA_MAXSCRIPTSIZE )
    {
        fprintf(stderr,"totalsize too big %d\n",totalsize);
        return(0);
    }
    // expand metascript!!
    totalsize += len;
    len += iguana_rwvarint32(0,&metascript[len],(void *)&sigslen);
    //printf("totalsize %d, len %d sigslen %d numpubs.%d p2sh.%d\n",totalsize,len,sigslen,s->numpubkeys,s->p2sh);
    if ( sigslen > 0 && sigslen < 74*16 )
    {
        len += iguana_rwvarint32(0,&metascript[len],(void *)&stacksize);
        if ( ramchain->sigsfileptr != 0 && stacksize < ramchain->sigsfilesize )
            memcpy(&_script[scriptlen],(void *)((long)ramchain->sigsfileptr + ramchain->sigsfilesize - stacksize),sigslen);
        else
        {
            diff = (long)Kstackend - (long)Kspace;
            if ( stacksize < diff )
                memcpy(&_script[scriptlen],&Kspace[diff - stacksize],sigslen);
        }
        scriptlen += sigslen;
    }
    if ( s->numpubkeys > 0 )
    {
        for (i=0; i<s->numpubkeys; i++)
        {
            len += iguana_rwvarint32(0,&metascript[len],(void *)&poffset);
            if ( poffset > rdata->scriptspace-33 )
            {
                printf("illegal poffset.%d/%d\n",poffset,rdata->scriptspace);
                return(-1);
            }
            //printf("poffset[%d] of %d poffset %x\n",i,s->numpubkeys,poffset);
            pubkey = &Kspace[poffset];
            if ( (plen= bitcoin_pubkeylen(pubkey)) <= 0 )
            {
                /*int32_t j;
                 for (j=0; j<totalsize; j++)
                 printf("%02x",metascript[j]);
                 printf(" metascript\n");
                 for (j=0; j<scriptlen; j++)
                 printf("%02x",_script[j]);
                 printf(" _script\n");
                 printf(" iguana_vinscriptdecode illegal pubkey.%d numpubs.%d numsigs.%d\n",i,s->numpubkeys,s->numsigs);*/
                *metalenp = len;
                return(scriptlen);
            }
            else
            {
                _script[scriptlen++] = plen;
                //printf("plen.%d\n",i);
                memcpy(&_script[scriptlen],pubkey,plen), scriptlen += plen;
            }
        }
    }
    if ( s->p2sh != 0 )
    {
        len += iguana_rwvarint32(0,&metascript[len],(void *)&p2shlen);
        if ( p2shlen > 0 && p2shlen < IGUANA_MAXSCRIPTSIZE )
        {
            if ( p2shlen <= 75 )
                _script[scriptlen++] = p2shlen;
            else if ( p2shlen <= 0xff )
                _script[scriptlen++] = 0x4c, _script[scriptlen++] = p2shlen;
            else _script[scriptlen++] = 0x4d, _script[scriptlen++] = p2shlen & 0xff, _script[scriptlen++] = (p2shlen>>8) & 0xff;
            //printf("p2shlen.%d\n",p2shlen);
            memcpy(&_script[scriptlen],&metascript[len],p2shlen), scriptlen += p2shlen, len += p2shlen;
        }
    }
    if ( (suffixlen= (totalsize - len)) != 0 )
    {
        if ( suffixlen < 0 || suffixlen >= IGUANA_MAXSCRIPTSIZE )
            printf("suffixlen.%d totalsize.%d vs len.%d\n",suffixlen,totalsize,len);
        else memcpy(&_script[scriptlen],&metascript[len],suffixlen), scriptlen += suffixlen, len += suffixlen;
    }
    *metalenp = len - 1 - (len>=0xfd ? 2 : 0);
    return(scriptlen);
}

int32_t iguana_vinscriptencode(struct iguana_info *coin,int32_t *metalenp,uint8_t *Kstackend,uint32_t stacksize,uint8_t *Kspace,uint32_t scriptoffset,struct iguana_spend *s,uint8_t *sigsbuf,int32_t sigslen,uint32_t *poffsets,uint8_t *p2shscript,int32_t p2shlen,uint8_t *suffix,int32_t suffixlen)
{
    int32_t i,len = 0; long diff; uint8_t metascript[IGUANA_MAXSCRIPTSIZE]; uint32_t origoffset = scriptoffset;
    *metalenp = 0;
    //printf("vinencode[%d] <- stacksize.%d sigslen.%d numsigs.%d numpubs.%d p2shlen.%d suffixlen.%d\n",scriptoffset,stacksize,sigslen,s->numsigs,s->numpubkeys,p2shlen,suffixlen);
    if ( sigslen == 0 && s->numpubkeys == 0 && p2shlen == 0 && suffixlen == 0 )
    {
        printf("spendencode: null script??\n");
        return(0);
    }
    len += iguana_rwvarint32(1,&metascript[len],(void *)&sigslen);
    if ( sigslen > 0 )
    {
        diff = (long)Kstackend - (long)Kspace;
        if ( diff < stacksize )
        {
            printf("vinscriptencode error diff.%ld < stacksize.%u\n",diff,stacksize);
            return(0);
        }
        memcpy(&Kspace[diff - stacksize],sigsbuf,sigslen);
        //printf("Kspace.%p Kstackend.%p diff.%ld stacksize.%d sigsbuf.%p sigslen.%d [%02x]\n",Kspace,Kstackend,diff,stacksize,sigsbuf,sigslen,Kspace[diff - stacksize + sigslen - 1]);
        for (i=0; i<sigslen; i++)
        {break;
            printf("%02x",sigsbuf[i]);
            //printf("i.%d [%p] (%d)\n",i,&Kspace[diff - stacksize + i],i-stacksize);
            //Kspace[diff - stacksize + i] = sigsbuf[i];
        }
        len += iguana_rwvarint32(1,&metascript[len],&stacksize);
        //printf(" sigsbuf len.%d -> %p stacksize.%d\n",len,&Kspace[diff - stacksize],stacksize);
    }
    if ( s->numpubkeys > 0 )
    {
        //printf("metalen.%d\n",len);
        for (i=0; i<s->numpubkeys; i++)
        {
            len += iguana_rwvarint32(1,&metascript[len],&poffsets[i]);
            //printf("EMIT pubkey poffsets.[%x] len.%d\n",poffsets[0],len);
        }
    }
    if ( p2shlen != 0 )
    {
        len += iguana_rwvarint32(1,&metascript[len],(void *)&p2shlen);
        memcpy(&metascript[len],p2shscript,p2shlen), len += p2shlen;
    }
    if ( suffixlen > 0 && suffixlen < IGUANA_MAXSCRIPTSIZE )
    {
        //printf("[%d] <- SUFFIX.(%02x) len.%d\n",len,suffix[0],suffixlen);
        memcpy(&metascript[len],suffix,suffixlen), len += suffixlen;
    }
    scriptoffset += iguana_rwvarint32(1,&Kspace[scriptoffset],(void *)&len);
    memcpy(&Kspace[scriptoffset],metascript,len);
    //for (i=0; i<scriptoffset + len - origoffset; i++)
    //    printf("%02x",Kspace[origoffset+i]);
    //printf(" ret METAscript scriptoffset.%d + len.%d - orig.%d = %d\n",scriptoffset,len,origoffset,scriptoffset + len - origoffset);
    *metalenp = len;
    return(scriptoffset + len - origoffset);
}

int32_t iguana_metascript(struct iguana_info *coin,RAMCHAIN_FUNC,struct iguana_spend *s,uint8_t *vinscript,int32_t vinscriptlen,int32_t rawflag)
{
    int32_t i,len,metalen,checkmetalen,decodelen; struct vin_info V;
    uint32_t poffsets[16],sigsize,pubkeysize,p2shsize,sigslen,suffixlen;
    uint8_t sigsbuf[16*128],_script[IGUANA_MAXSCRIPTSIZE],*suffix;
    sigslen = 0;
    if ( vinscript != 0 && vinscriptlen > 0 && vinscriptlen < IGUANA_MAXSCRIPTSIZE )
    {
        memset(&V,0,sizeof(V));
        if ( rawflag == 0 )
        {
            memset(&V,0,sizeof(V));
            s->sighash = iguana_vinscriptparse(coin,&V,&sigsize,&pubkeysize,&p2shsize,&suffixlen,vinscript,vinscriptlen);
            //for (i=0; i<33; i++)
            //    printf("%02x",V.signers[0].pubkey[i]);
            //printf(" parsed pubkey0\n");
            //for (i=0; i<20; i++)
            //    printf("%02x",V.signers[0].rmd160[i]);
            //printf(" parsed rmd160_0\n");
            memset(sigsbuf,0,sizeof(sigsbuf));
            memset(poffsets,0,sizeof(poffsets));
            for (i=sigslen=0; i<V.numsigs; i++)
            {
                if ( V.signers[i].siglen > 0 )
                {
                    sigsbuf[sigslen++] = V.signers[i].siglen;
                    memcpy(&sigsbuf[sigslen],V.signers[i].sig,V.signers[i].siglen);
                    sigslen += V.signers[i].siglen;
                }
            }
            for (i=0; i<V.numpubkeys; i++)
            {
                if ( V.signers[i].pubkey[0] != 0 )
                {
                    if ( (poffsets[i]= iguana_ramchain_pubkeyoffset(coin,RAMCHAIN_ARG,1,&ramchain->pkind,&ramchain->H.scriptoffset,V.signers[i].pubkey,V.signers[i].rmd160)) == 0 )
                    {
                        //printf("addspend: error couldnt get pubkeyoffset\n");
                        return(-1);
                    } //else printf("poffset[%d] <- 0x%x (%02x %02x)\n",i,poffsets[i],Kspace[poffsets[i]],Kspace[poffsets[i]+32]);
                }
            }
            s->numsigs = V.numsigs;
            s->numpubkeys = V.numpubkeys;
            if ( p2shsize != 0 )
                s->p2sh = 1;
            suffix = &vinscript[vinscriptlen-suffixlen];
            if ( sigslen+V.numsigs+V.numpubkeys+suffixlen != 0 )
            {
                ramchain->H.stacksize += sigslen;
                s->scriptoffset = ramchain->H.scriptoffset;
                len = iguana_vinscriptencode(coin,&metalen,&Kspace[rdata->scriptspace],ramchain->H.stacksize,Kspace,ramchain->H.scriptoffset,s,sigsbuf,sigslen,poffsets,V.p2shscript,V.p2shlen,suffix,suffixlen);
            } else printf("sigslen.%d numsigs.%d numpubs.%d suffixlen.%d\n",sigslen,V.numsigs,V.numpubkeys,suffixlen);
        }
        else
        {
            metalen = sigslen = 0;
            s->sighash = s->numsigs = s->numpubkeys = s->p2sh = 0;
            suffix = vinscript;
            suffixlen = vinscriptlen;
            //for (i=0; i<vinscriptlen; i++)
            //    printf("%02x",vinscript[i]);
            //printf(" rawmode mode.%d\n",vinscriptlen);
            s->scriptoffset = ramchain->H.scriptoffset;
            s->rawmode = 1;
            ramchain->H.scriptoffset += iguana_rwvarint32(1,&Kspace[s->scriptoffset],(void *)&vinscriptlen);
            memcpy(&Kspace[ramchain->H.scriptoffset],vinscript,vinscriptlen);
            ramchain->H.scriptoffset += vinscriptlen;
        }
    }
    //printf("checklen.%d scriptoffset.%d\n",checklen,ramchain->H.scriptoffset);
    if ( (decodelen= iguana_vinscriptdecode(coin,ramchain,&checkmetalen,_script,&Kspace[rdata->scriptspace],Kspace,s)) != vinscriptlen || (vinscript != 0 && memcmp(_script,vinscript,vinscriptlen) != 0) || checkmetalen != metalen )
    {
        //static uint64_t counter;
        //if ( counter++ < 100 )
        {
            for (i=0; i<decodelen; i++)
                printf("%02x",_script[i]);
            printf(" decoded checklen.%d metalen.%d\n",checkmetalen,metalen);
            if ( vinscript != 0 )
            {
                for (i=0; i<vinscriptlen; i++)
                    printf("%02x",vinscript[i]);
                printf(" vinscript\n");
            }
            printf("B addspend: vinscript expand error (%d vs %d) %d\n",decodelen,vinscriptlen,vinscript!=0?memcmp(_script,vinscript,vinscriptlen):0);
        }
        ramchain->H.stacksize -= sigslen;
        return(-1);
    } //else s->coinbase = 1;//, printf("vin reconstructed metalen.%d vinlen.%d\n",metalen,checklen);
    ramchain->H.scriptoffset += len;
    return(metalen);
}

int32_t iguana_scriptspaceraw(struct iguana_info *coin,int32_t *scriptspacep,int32_t *sigspacep,int32_t *pubkeyspacep,struct iguana_msgtx *txarray,int32_t txn_count)
{
    uint32_t i,j,sigspace,suffixlen,scriptspace,pubkeyspace,p2shspace,p2shsize,sigsize,pubkeysize,type,scriptlen; //struct iguana_spend256 *s; struct iguana_unspent20 *u;
    struct iguana_msgtx *tx; struct vin_info V; uint8_t rmd160[20],scriptdata[IGUANA_MAXSCRIPTSIZE]; char asmstr[IGUANA_MAXSCRIPTSIZE*2+1];
    return(1);
    for (i=sigspace=scriptspace=pubkeyspace=p2shspace=0; i<txn_count; i++)
    {
        tx = &txarray[i];
        for (j=0; j<tx->tx_out; j++)
        {
            memset(&V,0,sizeof(V));
            type = iguana_calcrmd160(coin,asmstr,&V,tx->vouts[j].pk_script,tx->vouts[j].pk_scriptlen,tx->txid,j,0xffffffff);
            if ( type != 0 ) // IGUANA_SCRIPT_NULL
            {
                memcpy(rmd160,V.rmd160,sizeof(rmd160));
                memset(&V,0,sizeof(V));
                scriptlen = iguana_scriptgen(coin,&V.M,&V.N,V.coinaddr,scriptdata,asmstr,rmd160,type,(const struct vin_info *)&V,j);
                if ( (scriptlen != tx->vouts[j].pk_scriptlen || (scriptdata != 0 && memcmp(scriptdata,tx->vouts[j].pk_script,scriptlen) != 0)) ) //tx->vouts[j].pk_scriptlen > sizeof(u->script) &&
                {
                    scriptspace += tx->vouts[j].pk_scriptlen;
                    //printf("type.%d scriptspace.%d <= %d + 2\n",type,scriptspace,tx->vouts[j].pk_scriptlen);
                }
            }
        }
        for (j=0; j<tx->tx_in; j++)
        {
            memset(&V,0,sizeof(V));
            iguana_vinscriptparse(coin,&V,&sigsize,&pubkeysize,&p2shsize,&suffixlen,tx->vins[j].vinscript,tx->vins[j].scriptlen);
            pubkeyspace += pubkeysize;
            p2shspace += p2shsize;
            //if ( tx->vins[j].scriptlen > sizeof(s->vinscript) )
            sigspace += tx->vins[j].scriptlen;
        }
    }
    *scriptspacep = scriptspace + p2shspace, *sigspacep = sigspace, *pubkeyspacep = pubkeyspace;
    return(scriptspace + sigspace);
}

int32_t iguana_ramchain_scriptspace(struct iguana_info *coin,int32_t *sigspacep,int32_t *pubkeyspacep,struct iguana_ramchain *ramchain)
{
    RAMCHAIN_DECLARE;
    int32_t j,scriptlen; struct vin_info V;
    uint32_t sequence,p2shspace,altspace,sigspace,pubkeyspace,spendind,unspentind,p2shsize,pubkeysize,sigsize,scriptspace,suffixlen;
    struct iguana_txid *tx; struct iguana_ramchaindata *rdata; uint8_t *scriptdata;
    _iguana_ramchain_setptrs(RAMCHAIN_PTRS,rdata);
    *sigspacep = *pubkeyspacep = altspace = 0;
    return(1);
    if ( (rdata= ramchain->H.data) == 0 || ramchain->expanded != 0 )
    {
        printf("iguana_ramchain_scriptspace cant iterate without data and requires simple ramchain\n");
        return(-1);
    }
    sigspace = pubkeyspace = p2shspace = 0;
    scriptspace = 1;
    for (ramchain->H.txidind=rdata->firsti; ramchain->H.txidind<rdata->numtxids; ramchain->H.txidind++)
    {
        tx = &T[ramchain->H.txidind];
        for (j=0; j<tx->numvouts; j++)
        {
            if ( (unspentind= ramchain->H.unspentind++) < rdata->numunspents )
                if ( U[unspentind].scriptlen != 0 )
                    scriptspace += U[unspentind].scriptlen + 3;
        }
        for (j=0; j<tx->numvins; j++)
        {break;
            if ( (spendind= ramchain->H.spendind++) < rdata->numspends )
            {
                sequence = S[spendind].sequenceid;
                scriptlen = S[spendind].vinscriptlen;
                if ( S[spendind].scriptoffset != 0 && S[spendind].scriptoffset+scriptlen < rdata->scriptspace )
                {
                    scriptdata = &Kspace[S[spendind].scriptoffset];
                    altspace += scriptlen;
                    if ( scriptdata != 0 )
                    {
                        memset(&V,0,sizeof(V));
                        iguana_vinscriptparse(coin,&V,&sigsize,&pubkeysize,&p2shsize,&suffixlen,scriptdata,scriptlen);
                        p2shspace += p2shsize;
                        sigspace += sigsize;
                        pubkeyspace += pubkeysize;
                        sigspace += suffixlen;
                        // fprintf(stderr,"(%d %d %d %d).%d ",sigsize,pubkeysize,p2shsize,suffixlen,scriptlen);
                    } //else fprintf(stderr,"(none)" );
                }
            }
        }
        //altspace += tx->numvins * 16 + 128; // for metascripts
        //scriptspace += tx->numvins * 16 + 128; // for metascripts
        //fprintf(stderr,"scriptspace.%u altspace.%u, ",scriptspace,altspace);
    }
    *sigspacep = sigspace, *pubkeyspacep = pubkeyspace;
    //printf("altspace.%d numvouts.%d numvins.%d scriptspace.%d p2shspace.%d sigspace.%d pubkeyspace.%d\n",altspace,tx->numvouts,tx->numvins,scriptspace,p2shspace,sigspace,pubkeyspace);
    return(scriptspace + p2shspace);
}

uint32_t iguana_ramchain_scriptencode(struct iguana_info *coin,uint8_t *Kspace,uint32_t *offsetp,int32_t type,uint8_t *script,int32_t scriptlen,uint32_t *pubkeyoffsetp)
{
    uint32_t uoffset,starti,offset = *offsetp,pubkeyoffset = *pubkeyoffsetp; int32_t plen;
    if ( type == IGUANA_SCRIPT_76AC || type == IGUANA_SCRIPT_AC )
    {
        starti = (type == IGUANA_SCRIPT_76AC);
        plen = bitcoin_pubkeylen(script + starti);
        /*if ( plen <= 0 )
         {
         char buf[1025];
         buf[0] = 0;
         for (i=0; i<33; i++)
         sprintf(buf+strlen(buf),"%02x",script[1+i]);
         printf("%s pubkey -> pubkeyoffset.%d offset.%d plen.%d\n",buf,pubkeyoffset,offset,plen);
         }*/
        if ( plen > 0 )
        {
            if ( pubkeyoffset == 0 )
            {
                if ( offset == 0 )
                    offset = 1;
                *pubkeyoffsetp = pubkeyoffset = offset;
                memcpy(&Kspace[pubkeyoffset],script + starti,plen);
                offset += plen;
                *offsetp = offset;
                return(0);
            }
            if ( memcmp(script + starti,&Kspace[pubkeyoffset],plen) != 0 )
            {
                /*for (i=-1; i<=plen; i++)
                 printf("%02x",script[1+i]);
                 printf("  script arg\n");
                 for (i=0; i<plen; i++)
                 printf("%02x",Kspace[pubkeyoffset+i]);
                 printf(" Kspace[%d] len.%d pubkeyoffset.%d\n",offset,plen,pubkeyoffset);
                 printf("iguana_ramchain_scriptencode: mismatched pubkey?\n");*/
                //getchar();
            }
        }
    }
    uoffset = offset;
    offset += iguana_rwvarint32(1,&Kspace[offset],(void *)&scriptlen);
    memcpy(&Kspace[offset],script,scriptlen);
    (*offsetp) = (offset + scriptlen);
    return(uoffset);
}

uint8_t *iguana_ramchain_scriptdecode(int32_t *metalenp,int32_t *scriptlenp,uint8_t *Kspace,int32_t type,uint8_t _script[IGUANA_MAXSCRIPTSIZE],uint32_t uoffset,uint32_t pubkeyoffset)
{
    uint32_t plen,len = 0;
    *metalenp = *scriptlenp = 0;
    if ( (type == IGUANA_SCRIPT_76AC || type == IGUANA_SCRIPT_AC) && pubkeyoffset != 0 )
    {
        plen = bitcoin_pubkeylen(&Kspace[pubkeyoffset]);
        if ( type == IGUANA_SCRIPT_76AC )
            _script[len++] = 0x76;
        memcpy(&_script[len],&Kspace[pubkeyoffset],plen);
        _script[plen + len] = 0xac;
        *scriptlenp = plen + len;
        //printf("76AC special case\n");
        return(_script);
    }
    if ( uoffset != 0 )
    {
        uoffset += iguana_rwvarint32(0,&Kspace[uoffset],(void *)scriptlenp);
        *metalenp = len + *scriptlenp;
        return(&Kspace[uoffset]);
    } else return(0);
}
/*origoffset = ramchain->H.scriptoffset;
 if ( type != IGUANA_SCRIPT_STRANGE && type != IGUANA_SCRIPT_DATA && type != IGUANA_SCRIPT_OPRETURN && scriptlen > 0 && script != 0 )
 {
 if ( Kspace != 0 && ramchain->H.scriptoffset+scriptlen+3 <= rdata->scriptspace-ramchain->H.stacksize )
 {
 if ( (u->scriptoffset= iguana_ramchain_scriptencode(coin,Kspace,&ramchain->H.scriptoffset,type,script,scriptlen,&pubkeyoffset)) > 0 || type == IGUANA_SCRIPT_76AC )
 {
 fprintf(stderr,"new offset.%d from scriptlen.%d pubkeyoffset.%d\n",ramchain->H.scriptoffset,scriptlen,pubkeyoffset);
 }
 //printf("[%d] u%d offset.%u len.%d\n",hdrsi,unspentind,u->scriptoffset,scriptlen);
 } else printf("[%d] u%d Kspace.%p scriptspace overflow! %d + %d vs space.%d - stack.%d\n",hdrsi,unspentind,Kspace,ramchain->H.scriptoffset,scriptlen,rdata->scriptspace,ramchain->H.stacksize);
 checkscript = iguana_ramchain_scriptdecode(&metalen,&checklen,Kspace,u->type,_script,u->scriptoffset,P[pkind].pubkeyoffset < ramchain->H.scriptoffset ? P[pkind].pubkeyoffset : 0);
 if ( checklen != scriptlen || (script != 0 && checkscript != 0 && memcmp(checkscript,script,scriptlen) != 0) )
 {
 //printf("create script mismatch len.%d vs %d or cmp error.%d\n",scriptlen,checklen,(script!=0&&checkscript!=0)?memcmp(checkscript,script,scriptlen):0);
 type = IGUANA_SCRIPT_STRANGE;
 } //else printf("RO spendscript match.%d\n",scriptlen);
 }
 if ( type == IGUANA_SCRIPT_DATA || type == IGUANA_SCRIPT_OPRETURN || type == IGUANA_SCRIPT_STRANGE )
 {
 if ( script != 0 && scriptlen > 0 )
 {
 u->scriptoffset = origoffset;
 origoffset += iguana_rwvarint32(1,&Kspace[origoffset],(void *)&scriptlen);
 memcpy(&Kspace[origoffset],script,scriptlen);
 ramchain->H.scriptoffset = origoffset + scriptlen;
 }
 }
 else if ( type == IGUANA_SCRIPT_76AC && pubkeyoffset != 0 && P[pkind].pubkeyoffset == 0 )
 P[pkind].pubkeyoffset = pubkeyoffset;*/

#endif
