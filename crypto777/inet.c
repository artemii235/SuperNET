/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#ifndef crypto777_inet_h
#define crypto777_inet_h
#include "OS_portable.h"


#ifdef _WIN32
#define in6_addr sockaddr
#define in_addr_t struct sockaddr_storage
#ifndef NATIVE_WINDOWS
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#endif

struct sockaddr_in6 {
    short   sin6_family;
    u_short sin6_port;
    u_long  sin6_flowinfo;
    struct  in6_addr sin6_addr;
    u_long  sin6_scope_id;
};
#else
#ifndef __MINGW
#include <arpa/inet.h>
#endif
#endif

#ifdef _WIN32
#ifdef AF_INET6
#undef AF_INET6
#endif
#define AF_INET6	23
#endif
static int inet_ntop4(unsigned char *src, char *dst, size_t size);
static int inet_ntop6(unsigned char *src, char *dst, size_t size);
static int inet_pton4(char *src, unsigned char *dst);
static int inet_pton6(char *src, unsigned char *dst);

int32_t portable_ntop(int af, void* src, char* dst, size_t size)
{
    switch (af) {
        case AF_INET:
            return (inet_ntop4(src, dst, size));
        case AF_INET6:
            return (inet_ntop6(src, dst, size));
        default:
            return -1;
    }
    /* NOTREACHED */
}


static int inet_ntop4(unsigned char *src, char *dst, size_t size) {
    static const char fmt[] = "%u.%u.%u.%u";
    char tmp[sizeof "255.255.255.255"];
    int l;
    
#ifndef _WIN32
    l = snprintf(tmp, sizeof(tmp), fmt, src[0], src[1], src[2], src[3]);
#else
    l = _snprintf(tmp, sizeof(tmp), fmt, src[0], src[1], src[2], src[3]);
#endif
    if (l <= 0 || (size_t) l >= size) {
        return -1;
    }
    strncpy(dst, tmp, size);
    dst[size - 1] = '\0';
    return 0;
}


static int inet_ntop6(unsigned char *src, char *dst, size_t size) {
    /*
     * Note that int32_t and int16_t need only be "at least" large enough
     * to contain a value of the specified size.  On some systems, like
     * Crays, there is no such thing as an integer variable with 16 bits.
     * Keep this in mind if you think this function should have been coded
     * to use pointer overlays.  All the world's not a VAX.
     */
    char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
    struct { int base, len; } best, cur;
    unsigned int words[sizeof(struct in6_addr) / sizeof(uint16_t)];
    int i;
    
    /*
     * Preprocess:
     *  Copy the input (bytewise) array into a wordwise array.
     *  Find the longest run of 0x00's in src[] for :: shorthanding.
     */
    memset(words, '\0', sizeof words);
    for (i = 0; i < (int) sizeof(struct in6_addr); i++)
        words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
    best.base = -1;
    best.len = 0;
    cur.base = -1;
    cur.len = 0;
    for (i = 0; i < (int)(sizeof(struct in6_addr) / sizeof(uint16_t)); i++) {
        if (words[i] == 0) {
            if (cur.base == -1)
                cur.base = i, cur.len = 1;
            else
                cur.len++;
        } else {
            if (cur.base != -1) {
                if (best.base == -1 || cur.len > best.len)
                    best = cur;
                cur.base = -1;
            }
        }
    }
    if (cur.base != -1) {
        if (best.base == -1 || cur.len > best.len)
            best = cur;
    }
    if (best.base != -1 && best.len < 2)
        best.base = -1;
    
    /*
     * Format the result.
     */
    tp = tmp;
    for (i = 0; i < (int)(sizeof(struct in6_addr) / sizeof(uint16_t)); i++) {
        /* Are we inside the best run of 0x00's? */
        if (best.base != -1 && i >= best.base &&
            i < (best.base + best.len)) {
            if (i == best.base)
                *tp++ = ':';
            continue;
        }
        /* Are we following an initial run of 0x00s or any real hex? */
        if (i != 0)
            *tp++ = ':';
        /* Is this address an encapsulated IPv4? */
        if (i == 6 && best.base == 0 && (best.len == 6 ||
                                         (best.len == 7 && words[7] != 0x0001) ||
                                         (best.len == 5 && words[5] == 0xffff))) {
            int err = inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp));
            if (err)
                return err;
            tp += strlen(tp);
            break;
        }
        tp += sprintf(tp, "%x", words[i]);
    }
    /* Was it a trailing run of 0x00's? */
    if (best.base != -1 && (best.base + best.len) == (sizeof(struct in6_addr) / sizeof(uint16_t)))
        *tp++ = ':';
    *tp++ = '\0';
    
    /*
     * Check for overflow, copy, and we're done.
     */
    if ((size_t)(tp - tmp) > size) {
        return ENOSPC;
    }
    strcpy(dst, tmp);
    return 0;
}


int portable_pton(int af, char* src, void* dst)
{
    switch (af) {
        case AF_INET:
            return (inet_pton4(src, dst));
        case AF_INET6:
            return (inet_pton6(src, dst));
        default:
            return EAFNOSUPPORT;
    }
    /* NOTREACHED */
}


static int inet_pton4(char *src, unsigned char *dst) {
    static const char digits[] = "0123456789";
    int saw_digit, octets, ch;
    unsigned char tmp[sizeof(struct in_addr)], *tp;
    char savestr[64];
    strcpy(savestr,src);
    
    //printf("inet_pton4(%s)\n",src);
    saw_digit = 0;
    octets = 0;
    *(tp = tmp) = 0;
    while ((ch = (uint8_t)*src++) != '\0')
    {
        char *pch;
        if ( (pch = strchr(digits, ch)) != NULL )
        {
            unsigned int nw = (unsigned int)(*tp * 10 + (pch - digits));
            if (saw_digit && *tp == 0)
            {
                printf("inet_pton4 0\n");
                return EINVAL;
            }
            if ( nw > 255 )
            {
                printf("inet_pton4 1\n");
                return EINVAL;
            }
            *tp = nw;
            if (!saw_digit) {
                if (++octets > 4)
                {
                    printf("inet_pton4 2\n");
                    return EINVAL;
                }
                saw_digit = 1;
            }
        } else if (ch == '.' && saw_digit) {
            if (octets == 4)
            {
                printf("inet_pton4 3\n");
                return EINVAL;
            }
            *++tp = 0;
            saw_digit = 0;
        } else
        {
            printf("inet_pton4 4 error.(%s)\n",savestr); //getchar();
            return EINVAL;
        }
    }
    if (octets < 4)
    {
        printf("inet_pton4 5 error.(%s)\n",savestr); //getchar();
        return EINVAL;
    }
    memcpy(dst, tmp, sizeof(struct in_addr));
    //printf("not errors %08x\n",*(int32_t *)dst);
    return 0;
}


static int inet_pton6(char *src, unsigned char *dst) {
    static char xdigits_l[] = "0123456789abcdef",
    xdigits_u[] = "0123456789ABCDEF";
    unsigned char tmp[sizeof(struct in6_addr)], *tp, *endp, *colonp;
    char *xdigits, *curtok;
    int ch, seen_xdigits;
    unsigned int val;
    
    memset((tp = tmp), '\0', sizeof tmp);
    endp = tp + sizeof tmp;
    colonp = NULL;
    /* Leading :: requires some special handling. */
    if (*src == ':')
        if (*++src != ':')
            return EINVAL;
    curtok = src;
    seen_xdigits = 0;
    val = 0;
    while ((ch = *src++) != '\0' && ch != '%') {
        char *pch;
        
        if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
            pch = strchr((xdigits = xdigits_u), ch);
        if (pch != NULL) {
            val <<= 4;
            val |= (pch - xdigits);
            if (++seen_xdigits > 4)
                return EINVAL;
            continue;
        }
        if (ch == ':') {
            curtok = src;
            if (!seen_xdigits) {
                if (colonp)
                    return EINVAL;
                colonp = tp;
                continue;
            } else if (*src == '\0') {
                return EINVAL;
            }
            if (tp + sizeof(uint16_t) > endp)
                return EINVAL;
            *tp++ = (unsigned char) (val >> 8) & 0xff;
            *tp++ = (unsigned char) val & 0xff;
            seen_xdigits = 0;
            val = 0;
            continue;
        }
        if (ch == '.' && ((tp + sizeof(struct in_addr)) <= endp)) {
            int err;
            
            /* Scope id present, parse ipv4 addr without it */
            pch = strchr(curtok, '%');
            if (pch != NULL) {
                char tmp2[sizeof "255.255.255.255"];
                
                memcpy(tmp2, curtok, pch - curtok);
                curtok = tmp2;
                src = pch;
            }
            
            err = inet_pton4(curtok, tp);
            if (err == 0) {
                tp += sizeof(struct in_addr);
                seen_xdigits = 0;
                break;  /*%< '\\0' was seen by inet_pton4(). */
            }
        }
        return EINVAL;
    }
    if (seen_xdigits) {
        if (tp + sizeof(uint16_t) > endp)
            return EINVAL;
        *tp++ = (unsigned char) (val >> 8) & 0xff;
        *tp++ = (unsigned char) val & 0xff;
    }
    if (colonp != NULL) {
        /*
         * Since some memmove()'s erroneously fail to handle
         * overlapping regions, we'll do the shift by hand.
         */
        int n = (int)(tp - colonp);
        int i;
        
        if (tp == endp)
            return EINVAL;
        for (i = 1; i <= n; i++) {
            endp[- i] = colonp[n - i];
            colonp[n - i] = 0;
        }
        tp = endp;
    }
    if (tp != endp)
        return EINVAL;
    memcpy(dst, tmp, sizeof tmp);
    return 0;
}

uint16_t parse_ipaddr(char *ipaddr,char *ip_port)
{
    int32_t j; uint16_t port = 0;
    if ( ip_port != 0 && ip_port[0] != 0 )
    {
		strcpy(ipaddr,ip_port);
        for (j=0; ipaddr[j]!=0&&j<60; j++)
            if ( ipaddr[j] == ':' )
            {
                port = atoi(ipaddr+j+1);
                break;
            }
        ipaddr[j] = 0;
        //printf("%p.(%s) -> (%s:%d)\n",ip_port,ip_port,ipaddr,port);
    } else strcpy(ipaddr,"127.0.0.1");
    return(port);
}

uint64_t _calc_ipbits(char *ip_port)
{
    int32_t port;
    char ipaddr[64];
    struct sockaddr_in addr;
    port = parse_ipaddr(ipaddr,ip_port);
    memset(&addr,0,sizeof(addr));
    portable_pton(ip_port[0] == '[' ? AF_INET6 : AF_INET,ipaddr,&addr);
    if ( (0) )
    {
        int i;
        for (i=0; i<16; i++)
            printf("%02x ",((uint8_t *)&addr)[i]);
        printf("<- %s %x\n",ip_port,*(uint32_t *)&addr);
    }
    return(*(uint32_t *)&addr | ((uint64_t)port << 32));
}

void expand_ipbits(char *ipaddr,uint64_t ipbits)
{
    uint16_t port;
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    *(uint32_t *)&addr = (uint32_t)ipbits;
    portable_ntop(AF_INET,&addr,ipaddr,64);
    if ( (port= (uint16_t)(ipbits>>32)) != 0 )
        sprintf(ipaddr + strlen(ipaddr),":%d",port);
    //sprintf(ipaddr,"%d.%d.%d.%d",(ipbits>>24)&0xff,(ipbits>>16)&0xff,(ipbits>>8)&0xff,(ipbits&0xff));
}

uint64_t calc_ipbits(char *ip_port)
{
    uint64_t ipbits = 0; char ipaddr[64],ipaddr2[64]; int32_t i;
    if ( ip_port != 0 )
    {
        ipbits = _calc_ipbits(ip_port);
        expand_ipbits(ipaddr,ipbits);
        if ( ipbits != 0 && strcmp(ipaddr,ip_port) != 0 )
        {
            for (i=0; i<63; i++)
                if ( (ipaddr[i]= ip_port[i]) == ':' || ipaddr[i] == 0 )
                break;
            ipaddr[i] = 0;
            ipbits = _calc_ipbits(ipaddr);
            expand_ipbits(ipaddr2,ipbits);
            if ( ipbits != 0 && strcmp(ipaddr,ipaddr2) != 0 )
            {
                if ( ipaddr[0] != 0 )
                    printf("calc_ipbits error: (%s) -> %llx -> (%s)\n",ip_port,(long long)ipbits,ipaddr);//, getchar();
                ipbits = 0;
            }
        }
    }
    return(ipbits);
}

char *ipbits_str(char ipaddr[64],uint64_t ipbits)
{
    expand_ipbits(ipaddr,ipbits);
    return(ipaddr);
}

uint32_t is_ipaddr(char *str)
{
    uint64_t ipbits; char ipaddr[64];
    if ( str != 0 && str[0] != 0 && (ipbits= calc_ipbits(str)) != 0 )
    {
        expand_ipbits(ipaddr,(uint32_t)ipbits);
        if ( strncmp(ipaddr,str,strlen(ipaddr)) == 0 )
            return((uint32_t)ipbits);
    }
    // printf("(%s) is not ipaddr\n",str);
    return(0);
}

/*int32_t conv_domain(struct sockaddr_storage *ss,const char *addr,int32_t ipv4only)
{
    //struct nn_dns dns; struct nn_dns_result dns_result;
    size_t addrlen,sslen;
    const char *semicolon,*hostname,*colon,*end;
    addrlen = strlen(addr);
    semicolon = strchr(addr,';');
    hostname = semicolon ? semicolon + 1 : addr;
    colon = strrchr(addr,':');
    end = addr + addrlen;
    if ( nn_slow(!colon) ) // Parse the port
        return -EINVAL;
    if ( nn_slow(nn_port_resolve (colon + 1, end - colon - 1) < 0) )
        return -EINVAL;
    //  Check whether the host portion of the address is either a literal or a valid hostname.
    if ( nn_dns_check_hostname(hostname,colon - hostname) < 0 && nn_literal_resolve(hostname,colon - hostname,ipv4only,ss,&sslen) < 0 )
        return -EINVAL;
    if ( semicolon != 0 && nn_iface_resolve(addr,semicolon - addr,ipv4only,ss,&sslen) < 0 ) // If local address is specified, check whether it is valid
        return -ENODEV;
    //memset(&dns_result,0,sizeof(dns_result));
    // nn_dns_start(&dns,addr,addrlen,ipv4only,&dns_result);
    // while ( *(uint32_t *)&dns_result.addr == 0 )
    //    usleep(10000);
    return(0);
}*/

uint32_t conv_domainname(char *ipaddr,char *domain)
{
    int32_t conv_domain(struct sockaddr_storage *ss,const char *addr,int32_t ipv4only);
    int32_t ipv4only = 1;
    uint32_t ipbits;
    struct sockaddr_in ss;
    if ( (0) && conv_domain((struct sockaddr_storage *)&ss,(const char *)domain,ipv4only) == 0 )
    {
        ipbits = *(uint32_t *)&ss.sin_addr;
        expand_ipbits(ipaddr,ipbits);
        if ( (uint32_t)calc_ipbits(ipaddr) == ipbits )
            return(ipbits);
        //printf("conv_domainname (%s) -> (%s)\n",domain,ipaddr);
    } //else printf("error conv_domain.(%s)\n",domain);
    return(0);
}

int32_t notlocalip(char *ipaddr)
{
    if ( ipaddr == 0 || ipaddr[0] == 0 || strcmp("127.0.0.1",ipaddr) == 0 || strncmp("192.168",ipaddr,7) == 0 )
        return(0);
    else return(1);
}

int32_t is_remote_access(char *previpaddr)
{
    if ( notlocalip(previpaddr) != 0 )
        return(1);
    else return(0);
}
/*struct sockaddr_in conv_ipbits(uint64_t ipbits)
 {
 char ipaddr[64];
 uint16_t port;
 struct hostent *host;
 struct sockaddr_in server_addr;
 port = (uint16_t)(ipbits>>32);
 ipbits = (uint32_t)ipbits;
 expand_ipbits(ipaddr,ipbits);
 host = (struct hostent *)gethostbyname(ipaddr);
 server_addr.sin_family = AF_INET;
 server_addr.sin_port = htons(port);
 server_addr.sin_addr = *((struct in_addr *)host->h_addr);
 memset(&(server_addr.sin_zero),0,8);
 return(server_addr);
 }*/

/*char *conv_ipv6(char *ipv6addr)
{
    unsigned char IPV4CHECK[10]; // 80 ZERO BITS for testing
    char ipv4str[4096];
    struct sockaddr_in6 ipv6sa;
    in_addr_t *ipv4bin;
    unsigned char *bytes = 0;
    int32_t isok;
    memset(IPV4CHECK,0,sizeof(IPV4CHECK));
    strcpy(ipv4str,ipv6addr);
    //isok = !uv_inet_pton(AF_INET,(const char*)ipv6addr,&ipv6sa.sin6_addr);
    //printf("isok.%d\n",isok);
    isok = portable_pton(AF_INET6,ipv6addr,&ipv6sa.sin6_addr);
    if ( isok == 0 )
    {
#ifdef _WIN32
        printf("need to figure this out for win32\n");
        //bytes = ((struct sockaddr_in6 *)&ipv6sa)->sin6_addr.s6_addr;
#else
        bytes = ((struct sockaddr_in6 *)&ipv6sa)->sin6_addr.s6_addr;
#endif
        if ( memcmp(bytes,IPV4CHECK,sizeof(IPV4CHECK)) != 0 ) // check its IPV4 really
        {
            bytes += 12;
            ipv4bin = (in_addr_t *)bytes;
#ifndef _WIN32
            if ( portable_ntop(AF_INET,ipv4bin,ipv4str,sizeof(ipv4str)) == 0 )
#endif
                isok = 0;
        } else isok = 0;
    }
    if ( isok != 0 )
        strcpy(ipv6addr,ipv4str);
    return(ipv6addr); // it is ipv4 now
}*/

uint16_t parse_endpoint(int32_t *ip6flagp,char *transport,char *ipbuf,char *retbuf,char *endpoint,uint16_t default_port)
{
    //int32_t myatoi(char *str,int32_t range);
    char *valids[] = { "tcp", "ws", "ipc", "inproc", "tcpmux" };
    char tmp[128],*inet = 0,*ipaddr = 0; uint64_t ipbits; int32_t i,j,n,port = 0;
    ipbuf[0] = retbuf[0] = 0;
    *ip6flagp = 0;
    if ( endpoint != 0 && strlen(endpoint) > 6 )
    {
        for (i=0; i<sizeof(valids)/sizeof(*valids); i++)
            if ( strncmp(endpoint,valids[i],strlen(valids[i])) == 0 )
            {
                n = (int32_t)strlen(valids[i]);
                ipaddr = &endpoint[n];
                if ( ipaddr[0] == '[' )
                {
                    *ip6flagp = 1;
                    inet = "ip6";
                    for (j=n-1; j>0; j--)
                    {
                        if ( ipaddr[j] == ':' )
                        {
                            if ( (port= atoi(ipaddr + j + 1)) < 0 || port >= (1 << 16) )
                            {
                                if ( ipaddr[j-1] == ']' )
                                    ipaddr[j] = 0;
                                else ipaddr = 0;
                                break;
                            }
                        }
                        else if ( ipaddr[j] == ']' )
                        {
                            if ( j == n-1 )
                                port = default_port;
                            break;
                        }
                    }
                }
                else
                {
                    inet = "ip4";
                    for (j=n-1; j>0; j--)
                    {
                        if ( ipaddr[j] == ':' )
                        {
                            if ( (port= atoi(ipaddr + j + 1)) < 0 || port >= (1 << 16) )
                                ipaddr = 0;
                            break;
                        }
                    }
                }
                if ( ipaddr != 0 )
                {
                    ipbits = calc_ipbits(ipaddr);
                    expand_ipbits(tmp,ipbits);
                    if ( strcmp(tmp,ipaddr) != 0 )
                    {
                        sprintf(retbuf,"{\"result\":\"illegal ipaddr\",\"endpoint\":\"%s\",\"ipaddr\":\"%s\",\"checkaddr\":\"%s\"}",endpoint,ipaddr,tmp);
                        ipaddr = 0;
                    }
                }
                if ( inet != 0 && ipaddr != 0 && port != 0 )
                {
                    sprintf(retbuf,"{\"result\":\"ip6 endpoint\",\"endpoint\":\"%s\",\"transport\":\"%s\",\"ipaddr\":\"%s\",\"port\":%d}",endpoint,valids[i],ipaddr,port);
                    if ( transport[0] == 0 )
                        strcpy(transport,valids[i]);
                    strcpy(ipbuf,ipaddr);
                    return(port);
                }
            }
        sprintf(retbuf,"{\"result\":\"illegal endpoint\",\"endpoint\":\"%s\"}",endpoint);
    } else sprintf(retbuf,"{\"error\":\"no mode specified\"}");
    *ip6flagp = 0;
    return(0);
}

#endif

