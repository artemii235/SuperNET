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

#ifndef FROM_JS
#include "OS_portable.h"
#include "../includes/curve25519.h"

// threadsafe 
int32_t iguana_rwnum(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp)
{
    int32_t i; uint64_t x;
    if ( rwflag == 0 )
    {
        x = 0;
        for (i=len-1; i>=0; i--)
        {
            x <<= 8;
            x |= serialized[i];
        }
        switch ( len )
        {
            case 1: *(uint8_t *)endianedp = (uint8_t)x; break;
            case 2: *(uint16_t *)endianedp = (uint16_t)x; break;
            case 4: *(uint32_t *)endianedp = (uint32_t)x; break;
            case 8: *(uint64_t *)endianedp = (uint64_t)x; break;
        }
    }
    else
    {
        x = 0;
        switch ( len )
        {
            case 1: x = *(uint8_t *)endianedp; break;
            case 2: x = *(uint16_t *)endianedp; break;
            case 4: x = *(uint32_t *)endianedp; break;
            case 8: x = *(uint64_t *)endianedp; break;
        }
        for (i=0; i<len; i++,x >>= 8)
            serialized[i] = (uint8_t)(x & 0xff);
    }
    return(len);
}

int32_t iguana_rwbignum(int32_t rwflag,uint8_t *serialized,int32_t len,uint8_t *endianedp)
{
    int32_t i;
    if ( rwflag == 0 )
    {
        for (i=0; i<len; i++)
            endianedp[i] = serialized[len - 1 - i];
    }
    else
    {
        for (i=0; i<len; i++)
            serialized[i] = endianedp[len - 1 - i];
    }
    return(len);
}

int32_t iguana_sethdr(struct iguana_msghdr *H,const uint8_t netmagic[4],char *command,uint8_t *data,int32_t datalen)
{
    bits256 hash2,tmp; int32_t i;
    memset(H,0,sizeof(*H));
    memcpy(H->netmagic,netmagic,4);
    strncpy(H->command,command,12);
    if ( datalen < 0 || datalen > IGUANA_MAXPACKETSIZE )
        return(-1);
    iguana_rwnum(1,H->serdatalen,sizeof(int32_t),&datalen);
    if ( data != 0 )
    {
        hash2 = bits256_doublesha256(0,data,datalen); // GRS?
        iguana_rwbignum(1,tmp.bytes,sizeof(tmp),hash2.bytes);
        for (i=0; i<4; i++)
            H->hash[i] = tmp.bytes[i];
    } else H->hash[0] = 0x5d, H->hash[1] = 0xf6, H->hash[2] = 0xe0, H->hash[3] = 0xe2;
    return(datalen + sizeof(*H));
}

uint8_t *iguana_varint16(int32_t rwflag,uint8_t *serialized,uint16_t *varint16p)
{
    uint16_t n = 0;
    if ( rwflag == 0 )
    {
        n = *serialized++;
        n |= ((int32_t)*serialized++ << 8);
        *varint16p = n;
    }
    else
    {
        n = *varint16p;
        *serialized++ = (uint8_t)n & 0xff;
        *serialized++ = (uint8_t)(n >> 8) & 0xff;
    }
    return(serialized);
}

uint8_t *iguana_varint32(int32_t rwflag,uint8_t *serialized,uint16_t *varint16p)
{
    serialized = iguana_varint16(rwflag,serialized,varint16p);
    serialized = iguana_varint16(rwflag,serialized,&varint16p[1]);
    return(serialized);
}

uint8_t *iguana_varint64(int32_t rwflag,uint8_t *serialized,uint32_t *varint32p)
{
    serialized = iguana_varint32(rwflag,serialized,(uint16_t *)varint32p);
    serialized = iguana_varint32(rwflag,serialized,(uint16_t *)&varint32p[1]);
    return(serialized);
}

int32_t iguana_rwvarint(int32_t rwflag,uint8_t *serialized,uint64_t *varint64p)
{
    uint64_t n; int32_t vlen = 1;
    if ( rwflag == 0 )
    {
        *varint64p = 0;
        if ( (n= *serialized++) >= 0xfd )
        {
            if ( n == 0xfd )
            {
                n = 0;
                iguana_varint16(rwflag,serialized,(uint16_t *)&n);
                vlen += 2;
            }
            else if ( n == 0xfe )
            {
                n = 0;
                iguana_varint32(rwflag,serialized,(uint16_t *)&n);
                vlen += 4;
            }
            else if ( n == 0xff )
            {
                n = 0;
                iguana_varint64(rwflag,serialized,(uint32_t *)&n);
                vlen += 8;
            }
        }
        *varint64p = n;
    }
    else
    {
        n = *varint64p;
        if ( n < 0xfd )
            *serialized++ = (uint8_t)n;
        else if ( n <= 0xffff )
        {
            *serialized++ = 0xfd;
            iguana_varint16(rwflag,serialized,(uint16_t *)varint64p);
            vlen += 2;
        }
        else if ( n <= 0xffffffff )
        {
            *serialized++ = 0xfe;
            iguana_varint32(rwflag,serialized,(uint16_t *)varint64p);
            vlen += 4;
        }
        else
        {
            *serialized++ = 0xff;
            iguana_varint64(rwflag,serialized,(uint32_t *)varint64p);
            vlen += 8;
        }
    }
    return(vlen);
}

int32_t iguana_rwvarint32(int32_t rwflag,uint8_t *serialized,uint32_t *int32p)
{
    int32_t len; uint64_t x = 0;
    if ( rwflag != 0 )
        x = *int32p;
    len = iguana_rwvarint(rwflag,serialized,&x);
    if ( rwflag == 0 )
        *int32p = (int32_t)x;
    return(len);
}

int32_t iguana_rwvarstr(int32_t rwflag,uint8_t *serialized,int32_t maxlen,char *endianedp)
{
    int32_t vlen; uint64_t n;
    if ( rwflag == 0 )
    {
        vlen = iguana_rwvarint(rwflag,serialized,&n);
        memcpy(endianedp,&serialized[vlen],n);
        ((uint8_t *)endianedp)[n] = 0;
    }
    else
    {
        n = strlen(endianedp);
        if ( n > maxlen )
            n = maxlen;
        vlen = iguana_rwvarint(rwflag,serialized,&n);
        memcpy(&serialized[vlen],endianedp,n);
    }
    return((int32_t)(n + vlen));
}

int32_t iguana_rwmem(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp)
{
    if ( rwflag == 0 )
        memcpy(endianedp,serialized,len);
    else memcpy(serialized,endianedp,len);
    return(len);
}
#endif
