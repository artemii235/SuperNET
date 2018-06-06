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
#include "../includes/tweetnacl.h"
#include "../crypto777/OS_portable.h"
#include "../includes/libgfshare.h"
#include "../includes/utlist.h"
#include "../includes/uthash.h"
#include "../includes/curve25519.h"
#include "../includes/cJSON.h"

/*
if ( 0 )
{
    int32_t i,max=10000000; FILE *fp; bits256 check,val,hash = rand256(0);
    if ( (fp= fopen("/tmp/seeds2","rb")) != 0 )
    {
        if ( fread(&check,1,sizeof(check),fp) != sizeof(check) )
            printf("check read error\n");
        for (i=1; i<max; i++)
        {
            if ( (i % 1000000) == 0 )
                fprintf(stderr,".");
            if ( fread(&val,1,sizeof(val),fp) != sizeof(val) )
                printf("val read error\n");
            hash = bits256_sha256(val);
            hash = bits256_sha256(hash);
            if ( bits256_cmp(hash,check) != 0 )
                printf("hash error at i.%d\n",i);
            check = val;
        }
        printf("validated %d seeds\n",max);
        getchar();
    }
    else if ( (fp= fopen("/tmp/seeds2","wb")) != 0 )
    {
        for (i=0; i<max; i++)
        {
            if ( (i % 1000000) == 0 )
                fprintf(stderr,".");
            hash = bits256_sha256(hash);
            hash = bits256_sha256(hash);
            fseek(fp,(max-i-1) * sizeof(bits256),SEEK_SET);
            if ( fwrite(hash.bytes,1,sizeof(hash),fp) != sizeof(hash) )
                printf("error writing hash[%d] i.%d\n",(max-i-1),i);
        }
        fclose(fp);
    }
}
*/

bits256 SuperNET_wallet2shared(bits256 wallethash,bits256 wallet2priv)
{
    bits256 wallet2shared,seed,wallet2pub;
    wallet2pub = curve25519(wallet2priv,curve25519_basepoint9());
    seed = curve25519_shared(wallethash,wallet2pub);
    vcalc_sha256(0,wallet2shared.bytes,seed.bytes,sizeof(bits256));
    return(wallet2shared);
}

bits256 SuperNET_wallet2priv(char *wallet2fname,bits256 wallethash)
{
    char *wallet2str; uint32_t r,i,crc; long allocsize; bits256 wallet2priv;
    wallet2priv = GENESIS_PRIVKEY;
    if ( wallet2fname[0] != 0 && (wallet2str= OS_filestr(&allocsize,wallet2fname)) != 0 )
    {
        r = crc = calc_crc32(0,wallet2str,(int32_t)allocsize);
        r %= 32;
        for (i=0; i<allocsize; i++)
            wallet2str[i] ^= wallethash.bytes[(i + r) % 32];
        vcalc_sha256(0,wallet2priv.bytes,(void *)wallet2str,(int32_t)allocsize);
        free(wallet2str);
    } else if ( wallet2fname[0] != 0 )
        printf("SuperNET_wallet2priv cant open (%s)\n",wallet2fname);
    return(wallet2priv);
}

char *SuperNET_parsemainargs(struct supernet_info *myinfo,bits256 *wallethashp,bits256 *wallet2privp,char *argjsonstr)
{
    cJSON *exchanges=0,*json = 0; char *wallet2fname,*coinargs=0,*secret,*filestr;
    long allocsize; bits256 wallethash,wallet2priv; int32_t n,len; uint8_t secretbuf[8192];
    wallethash = wallet2priv = GENESIS_PRIVKEY;
    if ( argjsonstr != 0 )
    {
        if ( (filestr= OS_filestr(&allocsize,argjsonstr)) != 0 )
        {
            json = cJSON_Parse(filestr);
            free(filestr);
        }
        if ( json != 0 || (json= cJSON_Parse(argjsonstr)) != 0 )
        {
            printf("ARGSTR.(%s)\n",argjsonstr);
            if ( jobj(json,"numhelpers") != 0 )
                IGUANA_NUMHELPERS = juint(json,"numhelpers");
            if ( (secret= jstr(json,"passphrase")) != 0 )
            {
                len = (int32_t)strlen(secret);
                if ( is_hexstr(secret,0) != 0 && len == 128 )
                {
                    len >>= 1;
                    decode_hex(secretbuf,len,secret);
                } else vcalc_sha256(0,secretbuf,(void *)secret,len), len = sizeof(bits256);
                memcpy(wallethash.bytes,secretbuf,sizeof(wallethash));
                //printf("wallethash.(%s)\n",bits256_str(str,wallethash));
                if ( (wallet2fname= jstr(json,"permanentfile")) != 0 )
                {
                    wallet2priv = SuperNET_wallet2priv(wallet2fname,wallethash);
                    myinfo->expiration = (uint32_t)(time(NULL) + 600);
                }
            }
            exchanges = jarray(&n,json,"exchanges");
            if ( jobj(json,"coins") != 0 )
                coinargs = argjsonstr;
        }
    }
    //if ( exchanges == 0 )
    if ( exchanges != 0 )
        exchanges777_init(myinfo,exchanges,0);
    if ( json != 0 )
        free_json(json);
    *wallethashp = wallethash, *wallet2privp = wallet2priv;
    return(coinargs);
}

bits256 SuperNET_linehash(char *_line)
{
    int32_t i,j; bits256 hash;
    /*if ( _line[strlen(_line)-1] == '\'' && strncmp(_line,match,len) == 0 )
    {
        _line[strlen(_line)-1] = 0;
        _line += len;
    }
    printf("%02x %02x %02x %02x %02x\n",0xff & _line[0],0xff & _line[1],0xff & _line[2],0xff & _line[3],0xff & _line[4]);*/
    for (i=j=0; _line[i]!=0; i++)
    {
        if ( (uint8_t)_line[i] == 0xe2 && (uint8_t)_line[i+1] == 0x80 )
        {
            if ( (uint8_t)_line[i+2] == 0x99 )
                _line[j++] = '\'', i += 2;
            else if ( (uint8_t)_line[i+2] == 0x9c || (uint8_t)_line[i+2] == 0x9d )
                _line[j++] = '"', i += 2;
            else _line[j++] = _line[i];
        }
        else _line[j++] = _line[i];
        //else if ( (uint8_t)_line[i] == 0x9c )
        //  _line[i] = '"';
    }
    _line[j++] = 0;
    if ( j == sizeof(bits256)*2 && is_hexstr(_line,j) == j )
        decode_hex(hash.bytes,sizeof(hash),_line);
    else vcalc_sha256(0,hash.bytes,(void *)_line,j);
    //char str[65]; printf("line -> (%s)\n",bits256_str(str,hash));
    return(hash);
}

int32_t SuperNET_savejsonfile(struct supernet_info *myinfo,char *finalfname,bits256 privkey,bits256 destpubkey,cJSON *json)
{
    char *confstr,*ciphered; char destfname[1024]; FILE *fp; int32_t retval = -1;
    strcpy(destfname,finalfname);
    if ( (fp= fopen(finalfname,"rb")) != 0 )
        strcat(destfname,".tmp");
    confstr = jprint(json,0);
    if ( bits256_nonz(privkey) != 0 && bits256_cmp(privkey,GENESIS_PUBKEY) != 0 )
    {
        if ( (ciphered= SuperNET_cipher(0,0,json,0,privkey,destpubkey,confstr)) != 0 )
        {
            //printf("ciphered.save (%s) <- (%s)\n",destfname,confstr);
            if ( (fp= fopen(destfname,"wb")) != 0 )
            {
                if ( fwrite(ciphered,1,strlen(ciphered)+1,fp) == strlen(ciphered)+1 )
                    retval = 0;
                fclose(fp);
            }
            free(ciphered);
        } else printf("error ciphering.(%s) (%s)\n",destfname,confstr);
    }
    else
    {
        printf("save (%s) <- (%s)\n",destfname,confstr);
        if ( (fp= fopen(destfname,"wb")) != 0 )
        {
            if ( fwrite(confstr,1,strlen(confstr)+1,fp) == strlen(confstr)+1 )
                retval = 0;
            fclose(fp);
        }
    }
    free(confstr);
    if ( retval == 0 && strcmp(destfname,finalfname) != 0 )
    {
        char oldfname[1024]; int64_t fsize,dsize;
        if ( (fsize= OS_filesize(finalfname)) > (dsize= OS_filesize(destfname)) )
        {
            //printf("skip replacing (%s) since new one is smaller %lld vs %lld\n",finalfname,(long long)fsize,(long long)dsize);
        }
        else
        {
            strcpy(oldfname,finalfname), strcat(oldfname,".old");
            OS_renamefile(finalfname,oldfname);
            OS_renamefile(destfname,finalfname);
        }
    }
    myinfo->dirty = 0;
    return(retval);
}

int32_t SuperNET_userkeys(char *passphrase,int32_t passsize,char *fname2fa,int32_t fnamesize)
{
    return(0);
/*#ifndef __PNACL
    //if ( (bits256_nonz(*wallethashp) == 0 || bits256_cmp(*wallethashp,GENESIS_PRIVKEY) == 0) && (bits256_nonz(*wallet2privp) == 0 || bits256_cmp(*wallet2privp,GENESIS_PRIVKEY) == 0) )
    {
        sleep(1);
        printf("\n\n********************************\n");
        if ( OS_getline(1,passphrase,passsize-1,"passphrase: ") > 0 )
            ;
        if ( OS_getline(1,fname2fa,fnamesize-1,"enter filename of a file that you will NEVER lose: ") > 0 )
            ;
        return(0);
    }
#endif
    return(-1);*/
}

cJSON *SuperNET_decryptedjson(char *destfname,char *passphrase,int32_t passsize,bits256 wallethash,char *fname2fa,int32_t fnamesize,bits256 wallet2priv)
{
    long allocsize; cJSON *filejson,*msgjson=0,*json=0; char *confstr=0,*deciphered,str[65];
    bits256 wallet2shared,wallet2pub; int32_t first,second;
    msgjson = 0;
    first = (bits256_nonz(wallethash) != 0 && bits256_cmp(wallethash,GENESIS_PRIVKEY) != 0);
    second = (bits256_nonz(wallet2priv) != 0 && bits256_cmp(wallet2priv,GENESIS_PRIVKEY) != 0);
    if ( first == 0 && second == 0 && passphrase != 0 && fname2fa != 0 )
    {
        if ( passphrase[0] == 0 && fname2fa[0] == 0 )
            SuperNET_userkeys(passphrase,passsize,fname2fa,fnamesize);
        wallethash = SuperNET_linehash(passphrase);
        SuperNET_linehash(fname2fa); // maps special chars
        wallet2priv = SuperNET_wallet2priv(fname2fa,wallethash);
    }
    first = (bits256_nonz(wallethash) != 0 && bits256_cmp(wallethash,GENESIS_PRIVKEY) != 0);
    second = (bits256_nonz(wallet2priv) != 0 && bits256_cmp(wallet2priv,GENESIS_PRIVKEY) != 0);
    if ( first != 0 || second != 0 )
    {
        if ( bits256_nonz(wallethash) == 0 )
            wallethash = GENESIS_PRIVKEY;
        wallet2shared = SuperNET_wallet2shared(wallethash,wallet2priv);
        wallet2pub = curve25519(wallet2shared,curve25519_basepoint9());
        sprintf(destfname,"%s/%s",GLOBAL_CONFSDIR,bits256_str(str,wallet2pub));
        if ( (confstr= OS_filestr(&allocsize,destfname)) != 0 )
        {
            if ( (filejson= cJSON_Parse(confstr)) != 0 )
            {
                //printf("confstr.(%s)\n",confstr);
                if ( (deciphered= SuperNET_decipher(0,0,0,0,wallet2shared,curve25519(wallethash,curve25519_basepoint9()),jstr(filejson,"result"))) != 0 )
                {
                    if ( (json= cJSON_Parse(deciphered)) == 0 )
                        printf("cant decipher (%s) [%s]\n",destfname,confstr);
                    else
                    {
                        if ( (msgjson= cJSON_Parse(jstr(json,"message"))) == 0 )
                            printf("no message in (%s)\n",jprint(json,0));
                    }
                    free(deciphered);
                }
                free_json(filejson);
            }
        } else printf("couldnt load (%s)\n",destfname);
    }
    else
    {
        sprintf(destfname,"confs/iguana.conf");
        if ( (confstr= OS_filestr(&allocsize,destfname)) != 0 )
        {
            if ( (json= cJSON_Parse(confstr)) != 0 )
                msgjson = json;
        } else printf("couldnt open (%s)\n",destfname);
    }
    if ( msgjson != 0 )
        msgjson = jduplicate(msgjson);
    if ( json != 0 )
        free_json(json);
    return(msgjson);
}

int32_t _SuperNET_encryptjson(struct supernet_info *myinfo,char *destfname,char *passphrase,int32_t passsize,char *fname2fa,int32_t fnamesize,cJSON *argjson)
{
    bits256 wallethash,wallet2priv,wallet2shared,wallet2pub; char str[65];
    wallethash = wallet2priv = GENESIS_PRIVKEY;
    if ( passphrase == 0 || passphrase[0] == 0 || fname2fa == 0 || fname2fa[0] == 0 )
        SuperNET_userkeys(passphrase,passsize,fname2fa,fnamesize);
    wallethash = SuperNET_linehash(passphrase);
    SuperNET_linehash(fname2fa); // maps special chars
    wallet2priv = SuperNET_wallet2priv(fname2fa,wallethash);
    wallet2shared = SuperNET_wallet2shared(wallethash,wallet2priv);
    wallet2pub = curve25519(wallet2shared,curve25519_basepoint9());
    sprintf(destfname,"%s/%s",GLOBAL_CONFSDIR,bits256_str(str,wallet2pub));
    SuperNET_savejsonfile(myinfo,destfname,wallethash,wallet2pub,argjson);
    return(0);
}

int32_t curve25519_donna(uint8_t *mypublic,const uint8_t *secret,const uint8_t *basepoint);

static const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int32_t iguana_wifstr_valid(char *wifstr)
{
    bits256 privkey,cmpkey; uint8_t wiftype; char cmpstr[128],cmpstr2[128]; int32_t i,len,n,a,A;
    if ( (len= (int32_t)strlen(wifstr)) < 50 || len > 54 )
    {
        //printf("len.%d is wrong for wif %s\n",len,wifstr);
        return(0);
    }
    memset(privkey.bytes,0,sizeof(privkey));
    memset(cmpkey.bytes,0,sizeof(cmpkey));
    for (i=n=a=A=0; wifstr[i]!=0; i++)
    {
        if ( strchr(base58_chars,wifstr[i]) == 0 )
            return(0);
        if ( wifstr[i] >= '1' && wifstr[i] <= '9' )
            n++;
        else if ( wifstr[i] >= 'A' && wifstr[i] <= 'Z' )
            A++;
        else if ( wifstr[i] >= 'a' && wifstr[i] <= 'z' )
            a++;
    }
    if ( n == 0 || A == 0 || a == 0 )
        return(0);
    if ( A > 5*a || a > 5*A || a > n*20 || A > n*20 ) // unlikely it is a real wif
    {
        //printf("reject wif %s due to n.%d a.%d A.%d (%d %d %d %d)\n",wifstr,n,a,A,A > 5*a,a < 5*A,a > n*20,A > n*20);
        return(0);
    }
    bitcoin_wif2priv(&wiftype,&privkey,wifstr);
    bitcoin_priv2wif(cmpstr,privkey,wiftype);
    if ( strcmp(cmpstr,wifstr) == 0 )
    {
        //printf("%s is valid wif\n",wifstr);
        return(1);
    }
    else if ( bits256_nonz(privkey) != 0 )
    {
        bitcoin_wif2priv(&wiftype,&cmpkey,cmpstr);
        bitcoin_priv2wiflong(cmpstr2,privkey,wiftype);
        if ( bits256_cmp(privkey,cmpkey) == 0 )
            return(1);
       // char str[65],str2[65]; printf("mismatched wifstr %s -> %s -> %s %s %s\n",wifstr,bits256_str(str,privkey),cmpstr,bits256_str(str2,cmpkey),cmpstr2);
    }
    //char str[65]; printf("%s is not a wif, privkey.%s\n",wifstr,bits256_str(str,privkey));
    return(0);
}

void SuperNET_setkeys(struct supernet_info *myinfo,void *pass,int32_t passlen,int32_t dosha256)
{
    static uint8_t basepoint[32] = {9}; bits256 hash; uint8_t addrtype,usedwif = 0;
    if ( dosha256 != 0 )
    {
        memcpy(myinfo->secret,pass,passlen+1);
        if ( iguana_wifstr_valid((char *)pass) > 0 )
        {
            usedwif = 1;
            bitcoin_wif2priv(&addrtype,&myinfo->persistent_priv,(char *)pass);
            curve25519_donna(myinfo->myaddr.persistent.bytes,myinfo->persistent_priv.bytes,basepoint);
        }
        else myinfo->myaddr.nxt64bits = conv_NXTpassword(myinfo->persistent_priv.bytes,myinfo->myaddr.persistent.bytes,pass,passlen);
    }
    else
    {
        myinfo->myaddr.persistent = curve25519(myinfo->persistent_priv,curve25519_basepoint9());
        init_hexbytes_noT(myinfo->secret,myinfo->persistent_priv.bytes,sizeof(myinfo->persistent_priv));
        vcalc_sha256(0,hash.bytes,myinfo->myaddr.persistent.bytes,32);
        myinfo->myaddr.nxt64bits = hash.txid;
    }
    RS_encode(myinfo->myaddr.NXTADDR,myinfo->myaddr.nxt64bits);
    bitcoin_pubkey33(myinfo->ctx,myinfo->persistent_pubkey33,myinfo->persistent_priv);
    bitcoin_address(myinfo->myaddr.BTC,0,myinfo->persistent_pubkey33,33);
    bitcoin_address(myinfo->myaddr.BTCD,60,myinfo->persistent_pubkey33,33);
    if ( (0) && usedwif != 0 )
        printf("usedwif for %s %s\n",myinfo->myaddr.BTCD,myinfo->myaddr.BTC);
}

void SuperNET_parsemyinfo(struct supernet_info *myinfo,cJSON *msgjson)
{
    char *ipaddr,*secret,str[65]; bits256 checkhash;
    if ( msgjson != 0 )
    {
        if ( (ipaddr= jstr(msgjson,"ipaddr")) != 0 && is_ipaddr(ipaddr) != 0 )
            strcpy(myinfo->ipaddr,ipaddr);
        if ( (secret= jstr(msgjson,"passphrase")) != 0 )
            SuperNET_setkeys(myinfo,secret,(int32_t)strlen(secret),1);
        else
        {
            myinfo->persistent_priv = jbits256(msgjson,"persistent_priv");
            SuperNET_setkeys(myinfo,myinfo->persistent_priv.bytes,sizeof(myinfo->persistent_priv),0);
            if ( bits256_nonz(myinfo->persistent_priv) == 0 )
            {
                printf("null persistent_priv? generate new one\n");
                OS_randombytes(myinfo->persistent_priv.bytes,sizeof(myinfo->persistent_priv));
            }
            myinfo->myaddr.persistent = jbits256(msgjson,"persistent_pub");
            checkhash = curve25519(myinfo->persistent_priv,curve25519_basepoint9());
        }
        if ( memcmp(checkhash.bytes,myinfo->myaddr.persistent.bytes,sizeof(checkhash)) != 0 )
        {
            printf("persistent pubkey mismatches one in iguana.conf\n");
            myinfo->myaddr.persistent = checkhash;
        } else printf("persistent VALIDATED persistentpub.(%s)\n",bits256_str(str,checkhash));
    }
    if ( bits256_nonz(myinfo->persistent_priv) == 0 )
        OS_randombytes(myinfo->persistent_priv.bytes,sizeof(myinfo->persistent_priv));
    SuperNET_setkeys(myinfo,myinfo->persistent_priv.bytes,sizeof(myinfo->persistent_priv),0);
}

char *SuperNET_keysinit(struct supernet_info *myinfo,char *argjsonstr)
{
    long allocsize; cJSON *msgjson,*json=0; uint32_t r; bits256 wallethash,wallet2priv; int32_t len,c;
    char str[65],str2[65],destfname[1024],fname2fa[2048],passphrase[8192],*ipaddr,*coinargs=0;
    passphrase[0] = fname2fa[0] = 0;
    wallethash = wallet2priv = GENESIS_PRIVKEY;
    coinargs = SuperNET_parsemainargs(myinfo,&wallethash,&wallet2priv,argjsonstr);
    if ( (msgjson= SuperNET_decryptedjson(destfname,passphrase,sizeof(passphrase),wallethash,fname2fa,sizeof(fname2fa),wallet2priv)) != 0 )
    {
        SuperNET_parsemyinfo(myinfo,msgjson);
        free_json(msgjson);
    }
    else
    {
        if ( bits256_nonz(myinfo->persistent_priv) == 0 )
        {
            OS_randombytes(myinfo->persistent_priv.bytes,sizeof(myinfo->persistent_priv));
            myinfo->myaddr.persistent = curve25519(myinfo->persistent_priv,curve25519_basepoint9());
            bitcoin_pubkey33(myinfo->ctx,myinfo->persistent_pubkey33,myinfo->persistent_priv);
        }
        json = cJSON_CreateObject();
        jaddstr(json,"ipaddr",myinfo->ipaddr);
        jaddbits256(json,"persistent_priv",myinfo->persistent_priv);
        jaddbits256(json,"persistent_pub",myinfo->myaddr.persistent);
        OS_randombytes((void *)&r,sizeof(r));
        jadd64bits(json,"rand",r);
        _SuperNET_encryptjson(myinfo,destfname,passphrase,sizeof(passphrase),fname2fa,sizeof(fname2fa),json);
        free_json(json);
    }
    if ( myinfo->ipaddr[0] == 0 )
    {
        if ( (ipaddr= OS_filestr(&allocsize,"ipaddr")) != 0 )
        {
            printf("got ipaddr.(%s)\n",ipaddr);
            len = (int32_t)strlen(ipaddr) - 1;
            while ( len > 8 && ((c= ipaddr[len]) == '\r' || c == '\n' || c == ' ' || c == '\t') )
                ipaddr[len] = 0, len--;
            printf("got ipaddr.(%s) %x\n",ipaddr,is_ipaddr(ipaddr));
            if ( is_ipaddr(ipaddr) != 0 )
            {
                strcpy(myinfo->ipaddr,ipaddr);
                myinfo->myaddr.selfipbits = (uint32_t)calc_ipbits(ipaddr);
            }
            free(ipaddr);
        }
    }
    if ( myinfo->myaddr.selfipbits == 0 )
    {
        strcpy(myinfo->ipaddr,"127.0.0.1");
        myinfo->myaddr.selfipbits = (uint32_t)calc_ipbits(myinfo->ipaddr);
    }
    //OS_randombytes(myinfo->privkey.bytes,sizeof(myinfo->privkey));
    //myinfo->myaddr.pubkey = curve25519(myinfo->privkey,curve25519_basepoint9());
    printf("(%s) %s %llu session(%s %s) persistent.%llx %llx\n",myinfo->ipaddr,myinfo->myaddr.NXTADDR,(long long)myinfo->myaddr.nxt64bits,bits256_str(str,myinfo->privkey),bits256_str(str2,myinfo->myaddr.pubkey),(long long)myinfo->persistent_priv.txid,(long long)myinfo->myaddr.persistent.txid);
    return(coinargs);
}


