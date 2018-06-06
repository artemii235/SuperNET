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

 /**
 * - we need to include WinSock2.h header to correctly use windows structure
 * as the application is still using 32bit structure from mingw so, we need to
 * add the include based on checking
 * @author - fadedreamz@gmail.com
 * @remarks - #if (defined(_M_X64) || defined(__amd64__)) && defined(WIN32)
 *     is equivalent to #if defined(_M_X64) as _M_X64 is defined for MSVC only
 */
#if defined(_M_X64)
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#endif

#include "iguana777.h"

#define _iguana_hashfind(coin,ipbits) _iguana_hashset(coin,ipbits,-1)
struct iguana_iAddr *iguana_iAddrhashfind(struct iguana_info *coin,uint64_t ipbits,int32_t createflag);

int32_t iguana_validatehdr(char *symbol,struct iguana_msghdr *H)
{
    int32_t i = 0,valid=0,len = -1; char cmdstr[16];
    memcpy(cmdstr,H->command,sizeof(H->command));
    cmdstr[0] = toupper((int32_t)cmdstr[0]);
    cmdstr[5] = toupper((int32_t)cmdstr[5]);
    cmdstr[6] = toupper((int32_t)cmdstr[6]);
    cmdstr[7] = toupper((int32_t)cmdstr[7]);
    if ( strcmp(symbol,"VPN") == 0 || strncmp("SuperNET",cmdstr,strlen("SuperNET")) == 0 )
        valid = 1;
    else
    {
        for (i=0; Iguana_validcommands[i]!=0&&Iguana_validcommands[i][0]!=0; i++)
            if ( strcmp(H->command,Iguana_validcommands[i]) == 0 )
            {
                valid = 1;
                break;
            }
    }
    if ( valid != 0 )
    {
        iguana_rwnum(0,H->serdatalen,sizeof(H->serdatalen),(uint32_t *)&len);
        if ( len > IGUANA_MAXPACKETSIZE )
            return(-1);
    } else return(-1);
    return(len);
}

struct iguana_peer *iguana_peeralive(struct iguana_peer *addr,int32_t needalive)
{
    if ( needalive == 0 || (addr->usock >= 0 && addr->dead == 0) )
        return(addr);
    else return(0);
}

struct iguana_peer *iguana_peerfindipaddr(struct iguana_info *coin,char *ipaddr,int32_t needalive)
{
    int32_t i;
    for (i=0; i<IGUANA_MAXPEERS; i++)
        if ( strcmp(ipaddr,coin->peers->active[i].ipaddr) == 0 )
            return(iguana_peeralive(&coin->peers->active[i],needalive));
    return(0);
}

struct iguana_peer *iguana_peerfindipbits(struct iguana_info *coin,uint32_t ipbits,int32_t needalive)
{
    int32_t i;
    for (i=0; i<IGUANA_MAXPEERS; i++)
        if ( ipbits == coin->peers->active[i].ipbits )
            return(iguana_peeralive(&coin->peers->active[i],needalive));
    return(0);
}

struct iguana_iAddr *_iguana_hashset(struct iguana_info *coin,uint32_t ipbits,int32_t itemind)
{
    struct iguana_iAddr *ptr = 0; int32_t allocsize; char str[65]; struct OS_memspace *mem = 0;
    if ( coin->virtualchain != 0 )
        return(0);
    expand_ipbits(str,ipbits);
    HASH_FIND(hh,coin->iAddrs,&ipbits,sizeof(ipbits),ptr);
    //printf("%p hashset.(%s) -> ptr.%p itemind.%d keylen.%ld %x\n",coin->iAddrs,str,ptr,itemind,sizeof(ipbits),ipbits);
    if ( itemind >= 0 )
    {
        if ( ptr == 0 )
        {
            allocsize = (int32_t)(sizeof(*ptr));
            if ( mem != 0 )
                ptr = iguana_memalloc(mem,allocsize,1);
            else ptr = mycalloc('t',1,allocsize);
            if ( ptr == 0 )
            {
                printf("fatal alloc errorA in hashset\n");
                iguana_exit(0,0);
            }
            //printf("ptr.%p allocsize.%d key.%p keylen.%d itemind.%d\n",ptr,allocsize,key,keylen,itemind);
            ptr->hh.itemind = itemind;
            ptr->ipbits = ipbits;
            HASH_ADD(hh,coin->iAddrs,ipbits,sizeof(ipbits),ptr);
            {
                struct iguana_iAddr *tmp;
                HASH_FIND(hh,coin->iAddrs,&ipbits,sizeof(ipbits),tmp);
                if ( tmp != ptr )
                    printf("%s itemind.%d search error %p != %p\n",str,itemind,ptr,tmp);
                //else printf("%p added.(%s) ind.%d:%d %p tmp.%p %x\n",coin->iAddrs,str,itemind,ptr->hh.itemind,ptr,tmp,ipbits);
            }
        }
        else ptr->hh.itemind = itemind;
    }
    return(ptr);
}

struct iguana_iAddr *iguana_iAddrhashset(struct iguana_info *coin,struct iguana_iAddr *iA,int32_t ind)
{
    struct iguana_iAddr *tmp,*item;
    if ( coin->virtualchain != 0 )
        return(0);
    if ( iA == 0 || iA->ipbits == 0 )
    {
        printf("null iA.%p or ipbits.%llx ind.%d status.%d\n",iA,iA!=0?(long long)iA->ipbits:0,iA!=0?iA->hh.itemind:0,iA!=0?iA->status:0);
        iguana_exit(0,0);
        return(0);
    }
    portable_mutex_lock(&coin->peers_mutex);
    if ( (item= _iguana_hashfind(coin,(uint32_t)iA->ipbits)) == 0 )
    {
        tmp = mycalloc('p',1,sizeof(*iA));
        *tmp = *iA;
        iA = tmp;
        if ( ind <= 0 )
            ind = coin->numiAddrs + 1;
        printf("coin->iAddrs.%p call set.(%x) ind.%d\n",coin->iAddrs,(uint32_t)iA->ipbits,ind);
        if ( (item= _iguana_hashset(coin,(uint32_t)iA->ipbits,ind)) != 0 && item->hh.itemind == coin->numiAddrs+1 )
        {
            *item = *iA;
            iA = item;
            coin->numiAddrs++;
        } else printf("iguana_hashset error numiAddrs.%d ind.%d\n",coin->numiAddrs,iA->hh.itemind);
    }
    else
    {
        *item = *iA;
        iA = item;
        iA->hh.itemind = ind;
    }
    portable_mutex_unlock(&coin->peers_mutex);
    //printf("return iA.%p ind.%d %x\n",iA,iA->hh.itemind,iA->ipbits);
    return(iA);
}

struct iguana_iAddr *iguana_iAddrhashfind(struct iguana_info *coin,uint64_t ipbits,int32_t createflag)
{
    int32_t ind; struct iguana_iAddr *item = 0;
    if ( coin->virtualchain != 0 )
        return(0);
    portable_mutex_lock(&coin->peers_mutex);
    if ( ipbits != 0 )
    {
        if ( (item= _iguana_hashfind(coin,(uint32_t)ipbits)) == 0 && createflag != 0 )
        {
            ind = coin->numiAddrs + 1;
            _iguana_hashset(coin,(uint32_t)ipbits,ind);
            if ( (item= _iguana_hashfind(coin,(uint32_t)ipbits)) != 0 )
                coin->numiAddrs++;
        }
    }
    portable_mutex_unlock(&coin->peers_mutex);
    return(item);
}

uint32_t iguana_rwiAddrind(struct iguana_info *coin,int32_t rwflag,struct iguana_iAddr *iA,uint32_t ind)
{
    FILE *fp; char fname[512],hexstr[65],ipaddr[64]; uint32_t ipbits; int32_t i,n,m,retval = 0; struct iguana_iAddr tmp,*ptr;
    if ( coin->virtualchain != 0 )
        return(0);
    sprintf(fname,"%s/%s_peers.dat",GLOBAL_DBDIR,coin->symbol), OS_compatible_path(fname);
    if ( rwflag < 0 || iA == 0 )
    {
        coin->numiAddrs = 0;
        if ( (fp= fopen(fname,"rb+")) != 0 )
        {
            fseek(fp,0,SEEK_END);
            n = (int32_t)(ftell(fp) / sizeof(*iA));
            for (i=m=1; i<n; i++)
            {
                fseek(fp,i * sizeof(tmp),SEEK_SET);
                if ( ftell(fp) == i*sizeof(tmp) && fread(&tmp,1,sizeof(tmp),fp) == sizeof(tmp) && tmp.ipbits != 0 )
                {
                    portable_mutex_lock(&coin->peers_mutex);
                    ipbits = (uint32_t)tmp.ipbits;
                    HASH_FIND(hh,coin->iAddrs,&ipbits,sizeof(ipbits),ptr);
                    if ( ptr == 0 )
                    {
                        ptr = mycalloc('t',1,sizeof(*ptr));
                        if ( ptr == 0 )
                        {
                            printf("fatal alloc errorB in hashset\n");
                            iguana_exit(0,0);
                        }
                        ptr->hh.itemind = m;
                        ptr->ipbits = tmp.ipbits;
                        HASH_ADD(hh,coin->iAddrs,ipbits,sizeof(ipbits),ptr);
                        tmp.hh.itemind = m;
                        tmp.status = 0;
                        fseek(fp,m*sizeof(tmp),SEEK_SET);
                        fwrite(&tmp,1,sizeof(tmp),fp);
                        expand_ipbits(hexstr,ipbits);
                        //printf("create rwiAddrind m.%-4d %08x %s status.%d\n",m,(uint32_t)tmp.ipbits,hexstr,tmp.status);
                        m++;
                        coin->numiAddrs = m;
                        iguana_possible_peer(coin,hexstr);
                    }
                    else
                    {
                        expand_ipbits(hexstr,ipbits);
                        //printf("peer.%d status.%d ipbits.%x\n",i,tmp.status,(uint32_t)ipbits);
                        tmp.status = 0;
                        fseek(fp,i * sizeof(tmp),SEEK_SET);
                        if ( fwrite(&tmp,1,sizeof(tmp),fp) != sizeof(tmp) )
                            printf("error writing peer.%d\n",i);
                    }
                    portable_mutex_unlock(&coin->peers_mutex);
                }
            }
            fclose(fp);
            printf("i.%d m.%d numiAddrs.%d\n",i,m,coin->numiAddrs);
        }
        return(coin->numiAddrs);
    }
    if ( rwflag == 0 )
    {
        memset(iA,0,sizeof(*iA));
        if ( (fp= fopen(fname,"rb")) != 0 )
        {
            fseek(fp,ind * sizeof(*iA),SEEK_SET);
            if ( ftell(fp) == ind * sizeof(*iA) )
            {
                if ( fread(iA,1,sizeof(*iA),fp) != sizeof(*iA) )
                    printf("iAddr: error loading.[%d]\n",ind);
                else
                {
                    iA->status = 0;
                    if ( (iA= iguana_iAddrhashset(coin,iA,ind)) != 0 )
                    {
                        retval = iA->hh.itemind+1;
                        //printf("r %p status.%d ipbits.%x ind.%d saved iA->ind.%d retval.%d\n",iA,iA->status,(uint32_t)iA->ipbits,ind,iA->hh.itemind,retval);
                    }
                }
            } else printf("iAddr: error seeking.[%d] %ld vs %d\n",ind,ftell(fp),(int32_t)(ind * sizeof(*iA)));
            fclose(fp);
        }
    }
    else
    {
        if ( (fp= fopen(fname,"rb+")) == 0 )
        {
            if ( (fp= fopen(fname,"wb")) == 0 )
            {
                printf("iguana_rwAddrind: couldnt create.(%s)\n",fname);
                return(-1);
            }
        }
        if ( fp != 0 )
        {
            ipbits = (uint32_t)iA->ipbits;
            HASH_FIND(hh,coin->iAddrs,&ipbits,sizeof(ipbits),ptr);
            if ( ptr != 0 && ptr->hh.itemind != ind )
            {
                printf("mismatch iAddr ind.%d != %d\n",ptr->hh.itemind,ind);
                ind = ptr->hh.itemind;
            }
            if ( ind <= 0 )
                ind = coin->numiAddrs++;
            fseek(fp,ind * sizeof(*iA),SEEK_SET);
            if ( ftell(fp) == ind * sizeof(*iA) )
            {
                iA->hh.itemind = ind;
                if ( fwrite(iA,1,sizeof(*iA),fp) != sizeof(*iA) )
                    printf("iAddr: error saving.[%d]\n",ind);
                else
                {
                    if ( (iA= iguana_iAddrhashset(coin,iA,ind)) != 0 )
                    {
                        retval = iA->hh.itemind+1;
                        expand_ipbits(ipaddr,iA->ipbits);
                        //printf("%s status.%d lastkilled.%u ipbits.%x ind.%d saved iA->ind.%d retval.%d numiAddrs.%d\n",ipaddr,iA->status,iA->lastkilled,(uint32_t)ipbits,ind,iA->hh.itemind,retval,coin->numiAddrs);
                    }
                }
            } else printf("iAddr: error seeking.[%d] %ld vs %d\n",ind,ftell(fp),(int32_t)(ind * sizeof(*iA)));
            fclose(fp);
        }
        else
        {
            printf("iguana_rwAddrind: couldnt create.(%s)\n",fname);
            return(-1);
        }
    }
    return(retval);
}

void iguana_iAconnected(struct iguana_info *coin,struct iguana_peer *addr)
{
    struct iguana_iAddr *iA;
    if ( coin->virtualchain != 0 )
        return;
    if ( (iA= iguana_iAddrhashfind(coin,addr->ipbits,1)) != 0 )
    {
        iA->status = IGUANA_PEER_READY;
        if ( addr->height > iA->height )
            iA->height = addr->height;
        iA->numconnects++;
        iA->lastconnect = (uint32_t)time(NULL);
        if ( iguana_rwiAddrind(coin,1,iA,iA->hh.itemind) == 0 )
            printf("iguana_iAconnected (%s) save error iA->ind.%d\n",addr->ipaddr,iA->hh.itemind);
        //else printf("iguana_iAconnected.(%s)\n",addr->ipaddr);
    } else printf("iguana_iAconnected error getting iA\n");
}

void iguana_iAkill(struct iguana_info *coin,struct iguana_peer *addr,int32_t markflag)
{
    struct iguana_iAddr *iA; int32_t rank; char ipaddr[64];
    if ( coin->virtualchain != 0 )
        return;
    if ( addr->ipbits == 0 )
    {
        //printf("cant iAkill null ipbits\n");
        return;
    }
    rank = addr->rank;
    strcpy(ipaddr,addr->ipaddr);
    if ( addr->usock >= 0 )
        closesocket(addr->usock), addr->usock = -1;
    if ( coin->peers != 0 && addr == coin->peers->localaddr )
        coin->peers->localaddr = 0;
    //printf("iAkill.(%s)\n",addr->ipaddr);
    if ( (iA= iguana_iAddrhashfind(coin,addr->ipbits,1)) != 0 )
    {
        iA->status = IGUANA_PEER_KILLED;
        if ( addr->height > iA->height )
            iA->height = addr->height;
        if ( markflag != 0 )
        {
            iA->numkilled++;
            iA->lastkilled = (uint32_t)time(NULL);
            if ( iguana_rwiAddrind(coin,1,iA,iA->hh.itemind) == 0 )
                printf("killconnection (%s) save error\n",addr->ipaddr);
        }
    } else printf("killconnection cant get ind for ipaddr.%s\n",addr->ipaddr);
    memset(addr,0,sizeof(*addr));
    addr->usock = -1;
    //if ( rank > 0 )
    //    iguana_possible_peer(coin,ipaddr);
}

int32_t iguana_socket(int32_t bindflag,char *hostname,uint16_t port)
{
    int32_t opt,sock,result; char ipaddr[64],checkipaddr[64]; struct timeval timeout;
    struct sockaddr_in saddr; socklen_t addrlen,slen;
    addrlen = sizeof(saddr);
    struct hostent *hostent;
	
	/** 
	* gethostbyname() is deprecated and cause crash on x64 windows
	* the solution is to implement similar functionality by using getaddrinfo()
	* it is standard posix function and is correctly supported in win32/win64/linux
	* @author - fadedreamz@gmail.com
	*/
#if defined(_M_X64)
	struct addrinfo *addrresult = NULL;
	struct addrinfo *returnptr = NULL;
	struct addrinfo hints;
	struct sockaddr_in * sockaddr_ipv4;
	int retVal;
	int found = 0;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
#endif

    if ( parse_ipaddr(ipaddr,hostname) != 0 )
        port = parse_ipaddr(ipaddr,hostname);

#if defined(_M_X64)
	retVal = getaddrinfo(ipaddr, NULL, &hints, &addrresult);
	for (returnptr = addrresult; returnptr != NULL && found == 0; returnptr = returnptr->ai_next) {
		switch (returnptr->ai_family) {
		case AF_INET:
			sockaddr_ipv4 = (struct sockaddr_in *) returnptr->ai_addr;
			// we want to break from the loop after founding the first ipv4 address
			found = 1;
			break;
		}
	}

	// if we iterate through the loop and didn't find anything,
	// that means we failed in the dns lookup
	if (found == 0) {
		printf("getaddrinfo(%s) returned error\n", hostname);
		freeaddrinfo(addrresult);
		return(-1);
	}
#else
    hostent = gethostbyname(ipaddr);
    if ( hostent == NULL )
    {
        printf("gethostbyname(%s) returned error: %d port.%d ipaddr.(%s)\n",hostname,errno,port,ipaddr);
        return(-1);
    }
#endif
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    //#ifdef WIN32
    //   saddr.sin_addr.s_addr = (uint32_t)calc_ipbits("127.0.0.1");
    //#else

#if defined(_M_X64)
	saddr.sin_addr.s_addr = sockaddr_ipv4->sin_addr.s_addr;
	// graceful cleanup
	sockaddr_ipv4 = NULL;
	freeaddrinfo(addrresult);
#else
    memcpy(&saddr.sin_addr.s_addr,hostent->h_addr_list[0],hostent->h_length);
#endif
    expand_ipbits(checkipaddr,saddr.sin_addr.s_addr);
    if ( strcmp(ipaddr,checkipaddr) != 0 )
        printf("bindflag.%d iguana_socket mismatch (%s) -> (%s)?\n",bindflag,checkipaddr,ipaddr);
    //#endif
    if ( (sock= socket(AF_INET,SOCK_STREAM,0)) < 0 )
    {
        if ( errno != ETIMEDOUT )
            printf("socket() failed: %s errno.%d", strerror(errno),errno);
        return(-1);
    }
    opt = 1;
    slen = sizeof(opt);
    //printf("set keepalive.%d\n",setsockopt(sock,SOL_SOCKET,SO_KEEPALIVE,(void *)&opt,slen));
#ifndef WIN32
    if ( 1 )//&& bindflag != 0 )
    {
        opt = 0;
        getsockopt(sock,SOL_SOCKET,SO_KEEPALIVE,(void *)&opt,&slen);
        opt = 1;
        //printf("keepalive.%d\n",opt);
    }
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(void *)&opt,sizeof(opt));
#ifdef __APPLE__
    setsockopt(sock,SOL_SOCKET,SO_NOSIGPIPE,&opt,sizeof(opt));
#endif
#endif
    if ( bindflag == 0 )
    {
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(void *)&timeout,sizeof(timeout));
        result = connect(sock,(struct sockaddr *)&saddr,addrlen);
        if ( result != 0 )
        {
            if ( errno != ECONNRESET && errno != ENOTCONN && errno != ECONNREFUSED && errno != ETIMEDOUT && errno != EHOSTUNREACH )
            {
                //printf("%s(%s) port.%d failed: %s sock.%d. errno.%d\n",bindflag!=0?"bind":"connect",hostname,port,strerror(errno),sock,errno);
            }
            if ( sock >= 0 )
                closesocket(sock);
            return(-1);
        }
        timeout.tv_sec = 10000000;
        timeout.tv_usec = 0;
        setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(void *)&timeout,sizeof(timeout));
    }
    else
    {
        while ( (result= bind(sock,(struct sockaddr*)&saddr,addrlen)) != 0 )
        {
            if ( errno == EADDRINUSE )
            {
                sleep(1);
                printf("ERROR BINDING PORT.%d. this is normal tcp timeout, unless another process is using port\n",port);
                fflush(stdout);
                sleep(3);
                printf("%s(%s) port.%d try again: %s sock.%d. errno.%d\n",bindflag!=0?"bind":"connect",hostname,port,strerror(errno),sock,errno);
                if ( bindflag == 1 )
                {
                    closesocket(sock);
                    return(-1);
                }
                sleep(13);
                //continue;
            }
            if ( errno != ECONNRESET && errno != ENOTCONN && errno != ECONNREFUSED && errno != ETIMEDOUT && errno != EHOSTUNREACH )
            {
                printf("%s(%s) port.%d failed: %s sock.%d. errno.%d\n",bindflag!=0?"bind":"connect",hostname,port,strerror(errno),sock,errno);
                closesocket(sock);
                return(-1);
            }
        }
        if ( listen(sock,64) != 0 )
        {
            printf("listen(%s) port.%d failed: %s sock.%d. errno.%d\n",hostname,port,strerror(errno),sock,errno);
            if ( sock >= 0 )
                closesocket(sock);
            return(-1);
        }
    }
#ifdef __APPLE__
    //timeout.tv_sec = 0;
    //timeout.tv_usec = 30000;
    //setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(void *)&timeout,sizeof(timeout));
    timeout.tv_sec = 0;
    timeout.tv_usec = 10000;
    setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,(void *)&timeout,sizeof(timeout));
#endif
    return(sock);
}

int32_t iguana_send(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *serialized,int32_t len)
{
    int32_t numsent,remains,usock,r,i; char *cmdstr = (char *)&serialized[4];
    if ( addr == 0 && coin->peers != 0 )
    {
        r = rand();
        for (i=0; i<IGUANA_MAXPEERS; i++)
        {
            addr = &coin->peers->active[(i + r) % IGUANA_MAXPEERS];
            if ( addr->usock >= 0 && addr->msgcounts.verack > 0 )
                break;
        }
    }
    if ( addr == 0 )
        return(-1);
    usock = addr->usock;
    if ( usock < 0 || addr->dead != 0 )
    {
        return(-1);
    }
    remains = len;
    if ( strncmp(cmdstr+1,"uperNET",strlen("uperNET")) == 0 || strncmp(cmdstr+1,"uperNet",strlen("uperNet")) == 0  )
    {
        //for (i=0; i<len-sizeof(struct iguana_msghdr); i++)
        //    printf("%02x",serialized[i+sizeof(struct iguana_msghdr)]);
        //printf(" >>>>>>> send.(%s) crc.%x %d bytes to %s:%u supernet.%d\n",cmdstr,calc_crc32(0,serialized,len),len,addr->ipaddr,addr->A.port,addr->supernet);
    }
    else if ( addr->msgcounts.verack == 0 && (strcmp(cmdstr,"version") != 0 && strcmp(cmdstr,"ConnectTo") != 0 && strcmp(cmdstr,"verack") != 0) != 0 )
    {
        //printf("skip.(%s) since no verack yet\n",cmdstr);
        return(-1);
    }
    //printf("%s -> %s\n",cmdstr,addr->ipaddr);
    if ( strcmp(cmdstr,"ping") == 0 )
        addr->sendmillis = OS_milliseconds();
    if ( len > IGUANA_MAXPACKETSIZE )
        printf("sending too big! %d\n",len);
    while ( remains > 0 )
    {
        if ( coin->peers != 0 && coin->peers->shuttingdown != 0 )
            return(-1);
#ifdef _WIN32
        if ( (numsent= (int32_t)send(usock,serialized,remains,0)) < 0 )
#else
            if ( (numsent= (int32_t)send(usock,serialized,remains,MSG_NOSIGNAL)) < 0 )
#endif
            {
                if ( errno == EAGAIN || errno == EWOULDBLOCK )
                {
                    //addr->persistent_peer = 1;
                    sleep(1);
                    continue;
                }
                //if ( errno != EAGAIN && errno != EWOULDBLOCK )
                {
                    printf("%s: %s numsent.%d vs remains.%d len.%d errno.%d (%s) usock.%d\n",serialized+4,addr->ipaddr,numsent,remains,len,errno,strerror(errno),addr->usock);
                    printf("bad errno.%d %s zombify.%p\n",errno,strerror(errno),&addr->dead);
                    addr->dead = (uint32_t)time(NULL);
                    return(-errno);
                }
            }
            else if ( remains > 0 )
            {
                remains -= numsent;
                serialized += numsent;
                if ( remains > 0 )
                    printf("%s iguana sent.%d remains.%d of len.%d\n",addr->ipaddr,numsent,remains,len);
            }
    }
    addr->totalsent += len;
    if ( (0) && addr->basilisk != 0 )
        printf("verack.%d (%s) sent.%d bytes to %s\n",addr->msgcounts.verack,cmdstr,len,addr->ipaddr);
    return(len);
}

int32_t iguana_queue_send(struct iguana_peer *addr,int32_t delay,uint8_t *serialized,char *cmd,int32_t len)
{
    struct iguana_packet *packet; int32_t datalen;
    if ( addr == 0 )
    {
        printf("iguana_queue_send null addr\n");
        iguana_exit(0,0);
        return(-1);
    }
    if ( (datalen= iguana_sethdr((void *)serialized,addr->netmagic,cmd,&serialized[sizeof(struct iguana_msghdr)],len)) < 0 )
        return(-1);
    if ( strcmp("getaddr",cmd) == 0 && time(NULL) < addr->lastgotaddr+300 )
        return(0);
    packet = mycalloc('S',1,sizeof(struct iguana_packet) + datalen);
    packet->datalen = datalen;
    packet->addr = addr;
    if ( delay != 0 )
    {
        if ( delay > IGUANA_MAXDELAY_MILLIS )
            delay = IGUANA_MAXDELAY_MILLIS;
        packet->embargo = tai_now();
        packet->embargo.millis += delay;
    }
    memcpy(packet->serialized,serialized,datalen);
    if ( (0) && addr->supernet != 0 )
        printf("%p queue send.(%s) %d to (%s)\n",packet,serialized+4,datalen,addr->ipaddr);
    queue_enqueue("sendQ",&addr->sendQ,&packet->DL);
    return(datalen);
}

int32_t iguana_recv(char *ipaddr,int32_t usock,uint8_t *recvbuf,int32_t len)
{
    int32_t recvlen,remains = len;
    while ( remains > 0 )
    {
        if ( (recvlen= (int32_t)recv(usock,recvbuf,remains,0)) < 0 )
        {
            if ( errno == EAGAIN )
            {
                //printf("%s recv errno.%d %s len.%d remains.%d\n",ipaddr,errno,strerror(errno),len,remains);
                //printf("EAGAIN for len %d, remains.%d\n",len,remains);
                sleep(1);
            } else return(-errno);
        }
        else
        {
            if ( recvlen > 0 )
            {
                remains -= recvlen;
                //int32_t i; for (i=0; i<recvlen; i++)
                //    printf("%02x",recvbuf[i]);
                //printf("got %d remains.%d of total.%d from (%s)\n",recvlen,remains,len,ipaddr);
                recvbuf = &recvbuf[recvlen];
            } else usleep(10000);
        }
    }
    return(len);
}

void iguana_peer_meminit(struct iguana_info *coin,struct iguana_peer *addr)
{
    if ( addr->RAWMEM.ptr == 0 )
        iguana_meminit(&addr->RAWMEM,addr->ipaddr,0,IGUANA_MAXPACKETSIZE * 3,0);
    if ( addr->TXDATA.ptr == 0 )
        iguana_meminit(&addr->TXDATA,"txdata",0,IGUANA_MAXPACKETSIZE * 3,0);
    if ( addr->HASHMEM.ptr == 0 )
        iguana_meminit(&addr->HASHMEM,"HASHPTRS",0,256,0);//IGUANA_MAXPACKETSIZE*16,0);
    //printf("Init %s memory %p %p %p\n",addr->ipaddr,addr->RAWMEM.ptr,addr->TXDATA.ptr,addr->HASHMEM.ptr);
    iguana_memreset(&addr->RAWMEM);
    iguana_memreset(&addr->TXDATA);
    iguana_memreset(&addr->HASHMEM);
}

void iguana_parsebuf(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msghdr *H,uint8_t *buf,int32_t len,int32_t fromcache)
{
    struct iguana_msghdr checkH;
    memset(&checkH,0,sizeof(checkH));
    if ( iguana_sethdr(&checkH,coin->chain->netmagic,H->command,buf,len) > 0 && memcmp(&checkH,H,sizeof(checkH)) == 0 )
    {
        if ( strcmp(H->command,"block") == 0 || strcmp(H->command,"getblocks") == 0 || strcmp(H->command,"tx") == 0 )
            iguana_peer_meminit(coin,addr);
        if ( iguana_msgparser(myinfo,coin,addr,&addr->RAWMEM,&addr->TXDATA,&addr->HASHMEM,H,buf,len,fromcache) < 0 || addr->dead != 0 )
        {
            printf("%p addr->dead.%d or parser break at %u\n",&addr->dead,addr->dead,(uint32_t)time(NULL));
            addr->dead = (uint32_t)time(NULL);
        }
        else
        {
            addr->numpackets++;
            addr->totalrecv += len;
            coin->totalrecv += len, coin->totalpackets++;
            //printf("next iter.(%s) numreferrals.%d numpings.%d\n",addr->ipaddr,addr->numreferrals,addr->numpings);
        }
    }
    else
    {
        int z;
        for (z=0; z<sizeof(*H); z++)
            printf("%02x",((uint8_t *)H)[z]);
        printf(" header error from %s len %d crc.%08x\n",addr->ipaddr,len,calc_crc32(0,buf,len));
    }
}

void _iguana_processmsg(struct supernet_info *myinfo,struct iguana_info *coin,int32_t usock,struct iguana_peer *addr,uint8_t *_buf,int32_t maxlen)
{
    int32_t len,recvlen; void *buf = _buf; struct iguana_msghdr H;
    if ( (coin->peers != 0 && coin->peers->shuttingdown != 0) || addr->dead != 0 )
        return;
    memset(&H,0,sizeof(H));
    if ( (recvlen= (int32_t)iguana_recv(addr->ipaddr,usock,(uint8_t *)&H,sizeof(H))) == sizeof(H) )
    {
        if ( (coin->peers != 0 && coin->peers->shuttingdown != 0) || addr->dead != 0 )
            return;
        {
            iguana_rwnum(0,H.serdatalen,sizeof(H.serdatalen),(uint32_t *)&len);
            //printf("%08x got.(%s) recvlen.%d from %s | usock.%d ready.%u dead.%u len.%d\n",(uint32_t)addr->ipbits,H.command,recvlen,addr->ipaddr,addr->usock,addr->ready,addr->dead,len);
        }
        if ( (len= iguana_validatehdr(coin->symbol,&H)) >= 0 )
        {
            if ( len > 0 )
            {
                if ( len > IGUANA_MAXPACKETSIZE )
                {
                    printf("buffer %d too small for %d\n",IGUANA_MAXPACKETSIZE,len);
                    return;
                }
                if ( len > maxlen )
                    buf = mycalloc('p',1,len);
                if ( (recvlen= iguana_recv(addr->ipaddr,usock,buf,len)) < 0 )
                {
                    printf("%s recv error on (%s) len.%d errno.%d (%s)\n",addr->ipaddr,H.command,len,-recvlen,strerror(-recvlen));
                    if ( buf != _buf )
                        myfree(buf,len);
                    if ( addr->numrecverrs++ > 10 )
                    {
                        addr->dead = (uint32_t)time(NULL);
                        addr->numrecverrs = 0;
                    }
                    return;
                }
            }
            iguana_parsebuf(myinfo,coin,addr,&H,buf,len,0);
            if ( buf != _buf )
                myfree(buf,len);
            return;
        }
        static uint32_t counter;
        if ( counter++ < 10 )
        {
            int32_t i; for (i=0; i<sizeof(H); i++)
                printf("%02x",((uint8_t *)&H)[i]);
            printf(" %s invalid header.%s received from (%s) len.%d\n",coin->symbol,H.command,addr->ipaddr,len);
        }
        //addr->dead = 1;
    }
    // printf("%s recv error on hdr errno.%d (%s) -> zombify\n",addr->ipaddr,-recvlen,strerror(-recvlen));
#ifndef IGUANA_DEDICATED_THREADS
    addr->dead = 1;
#endif
}

void iguana_gotdata(struct iguana_info *coin,struct iguana_peer *addr,int32_t height)
{
    struct iguana_iAddr *iA;
    if ( addr != 0 && height > addr->height && height < coin->longestchain )
    {
        if ( (iA= iguana_iAddrhashfind(coin,addr->ipbits,0)) != 0 && iA->height < height )
            iA->height = height;
        //iguana_set_iAddrheight(coin,addr->ipbits,height);
        addr->height = height;
    }
    if ( height > 0 && height > coin->longestchain )
        coin->longestchain = (height + coin->longestchain + 1) >> 1;
}

int32_t iguana_iAddrheight(struct iguana_info *coin,uint64_t ipbits)
{
    struct iguana_iAddr *iA;
    if ( coin->virtualchain != 0 )
        return(0);
    if ( (iA= iguana_iAddrhashfind(coin,ipbits,0)) != 0 )
        return(iA->height);
    return(0);
}

void iguana_startconnection(void *arg)
{
    int32_t i,n; uint16_t port; char ipaddr[64]; struct iguana_peer *addr = arg; struct iguana_info *coin = 0;
    if ( addr == 0 || (coin= iguana_coinfind(addr->symbol)) == 0 )
    {
        printf("iguana_startconnection nullptrs addr.%p (%s) coin.%p\n",addr,addr!=0?addr->symbol:"",coin);
        return;
    }
    if ( coin->virtualchain != 0 || coin->peers == 0 )
        return;
    addr->addrind = (int32_t)(((long)addr - (long)&coin->peers->active[0]) / sizeof(*addr));
    if ( addr->usock >= 0 )
    {
        //printf("%s usock.%d skip connection\n",addr->ipaddr,addr->usock);
        return;
    }
    if ( strcmp(coin->name,addr->coinname) != 0 )
    {
        printf("iguana_startconnection.%s:%04x mismatched coin.%p (%s) vs (%s)\n",addr->ipaddr,coin->chain->portp2p,coin,coin->symbol,addr->coinname);
        return;
    }
    //printf("%s iguana_startconnection.%s:%04x\n",coin->symbol,addr->ipaddr,coin->chain->portp2p);
    if ( strcmp("127.0.0.1",addr->ipaddr) == 0 )//&& (coin->myservices & NODE_NETWORK) != 0 )
    {
        iguana_iAkill(coin,addr,0);
        printf("avoid self-loopback\n");
        return;
    }
    //printf(">>>>>>>> %s startconnection.(%s) pending.%u usock.%d addrind.%d\n",coin->symbol,addr->ipaddr,addr->pending,addr->usock,addr->addrind);
    addr->pending = (uint32_t)time(NULL);
    if ( (port= (uint16_t)(addr->ipbits >> 32)) == 0 )
        port = coin->chain->portp2p;
    if ( addr->usock < 0 )
        addr->usock = iguana_socket(0,addr->ipaddr,port);
    if ( addr->usock < 0 || (coin->peers != 0 && coin->peers->shuttingdown != 0) )
    {
        strcpy(ipaddr,addr->ipaddr);
        //printf("%s refused PEER KILLED. slot.%d for %s:%d usock.%d\n",coin->symbol,addr->addrind,ipaddr,coin->chain->portp2p,addr->usock);
        iguana_iAkill(coin,addr,1);
    }
    else
    {
        addr->ready = (uint32_t)time(NULL);
        addr->ipbits = calc_ipbits(addr->ipaddr);
        addr->dead = 0;
        addr->pending = 0;
        addr->height = iguana_iAddrheight(coin,addr->ipbits);
        strcpy(addr->symbol,coin->symbol);
        strcpy(addr->coinname,coin->name);
        if ( coin->peers != 0 )
        {
            coin->peers->lastpeer = (uint32_t)time(NULL);
            for (i=n=0; i<IGUANA_MAXPEERS; i++)
                if ( coin->peers->active[i].usock > 0 )
                    n++;
            coin->peers->numconnected++;
            if ( strcmp("127.0.0.1",addr->ipaddr) == 0 )
                coin->peers->localaddr = addr;
            else if ( coin->peers->numranked == 0 )
                coin->peers->ranked[0] = addr;
        } else n = 0;
        iguana_iAconnected(coin,addr);
        printf("%s.PEER CONNECTED.%d:%d of max.%d! %s:%d usock.%d\n",coin->symbol,coin->peers->numconnected,n,coin->MAXPEERS,addr->ipaddr,coin->chain->portp2p,addr->usock);
#ifdef IGUANA_DEDICATED_THREADS
        //iguana_launch("recv",iguana_dedicatedrecv,addr,IGUANA_RECVTHREAD);
        iguana_dedicatedloop(SuperNET_MYINFO(0),coin,addr);
#endif
    }
}

void iguana_peerkill(struct iguana_info *coin)
{
    struct iguana_peer *addr;
    if ( coin->virtualchain != 0 || coin->peers == 0 )
        return;
    if ( coin->peers->numranked > 0 && (addr= coin->peers->ranked[coin->peers->numranked-1]) != 0 )
    {
        printf("mark rank.%d as dead.(%s)\n",coin->peers->numranked,addr->ipaddr);
        addr->dead = (uint32_t)time(NULL);
    }
}

struct iguana_peer *iguana_peerslot(struct iguana_info *coin,uint64_t ipbits,int32_t forceflag)
{
    int32_t i; struct iguana_peer *addr; char ipaddr[64];
    if ( coin->virtualchain != 0 || coin->peers == 0 )
        return(0);
    for (i=0; i<IGUANA_MAXPEERS; i++)
        if ( (uint32_t)ipbits == (uint32_t)coin->peers->active[i].ipbits )
            return(forceflag!=0 ? &coin->peers->active[i] : 0);
    expand_ipbits(ipaddr,ipbits);
#ifdef IGUANA_DISABLEPEERS
    if ( strcmp("127.0.0.1",ipaddr) != 0 )
        return(0);
#endif
    //portable_mutex_lock(&coin->peers_mutex);
    for (i=0; i<IGUANA_MAXPEERS; i++)
    {
        if ( i < coin->MAXPEERS || forceflag != 0 )
        {
            addr = &coin->peers->active[i];
            addr->addrind = i;
            if ( addr->usock >= 0 || addr->pending != 0 || addr->ipbits == ipbits || strcmp(ipaddr,addr->ipaddr) == 0 )
            {
                //printf("%s i.%d skip.(%s) usock.%d pending.%d ipbits.%llx lag.%ld\n",coin->symbol,i,addr->ipaddr,addr->usock,addr->pending,(long long)addr->ipbits,time(NULL)-addr->pending);
                continue;
            }
            portable_mutex_lock(&coin->peers_mutex);
            if ( addr->ipbits == 0 )
            {
                iguana_initpeer(coin,addr,ipbits);
                //addr->pending = (uint32_t)time(NULL);
                portable_mutex_unlock(&coin->peers_mutex);
                return(addr);
            }
            portable_mutex_unlock(&coin->peers_mutex);
        }
    }
    return(0);
}

void iguana_launchpeer(struct iguana_info *coin,char *ipaddr,int32_t forceflag)
{
    struct iguana_peer *addr; uint32_t ipbits = (uint32_t)calc_ipbits(ipaddr);
    if ( coin == 0 )
    {
        printf("iguana_launchpeer: null coin?\n");
        return;
    }
    if ( coin->virtualchain != 0 )
        return;
    if ( (addr= iguana_peerslot(coin,ipbits,forceflag)) != 0 )
        iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
    else printf("iguana_launchpeer skip %s\n",ipaddr);
}

void *iguana_iAddriterator(struct iguana_info *coin,struct iguana_iAddr *iA,struct iguana_peer *addr)
{
    if ( coin->virtualchain != 0 )
        return(0);
    if ( iA != 0 && iA->ipbits != 0 && iguana_numthreads(coin,1 << IGUANA_CONNTHREAD) < IGUANA_MAXCONNTHREADS && iA->status == IGUANA_PEER_ELIGIBLE )
    {
        //printf("%x\n",iA->ipbits);
        //portable_mutex_unlock(&coin->peers_mutex);
        if ( addr != 0 || (addr= iguana_peerslot(coin,iA->ipbits,0)) != 0 )
        {
            addr->ipbits = iA->ipbits;
            //printf("pend.%d status.%d possible peer.(%s).%x threads %d %d %d %d\n",addr->pending,iA->status,addr->ipaddr,(uint32_t)addr->ipbits,iguana_numthreads(coin,0),iguana_numthreads(coin,1),iguana_numthreads(coin,2),iguana_numthreads(coin,3));
            if ( addr->pending == 0 && iA->status != IGUANA_PEER_CONNECTING && (iA->status != IGUANA_PEER_KILLED || time(NULL) > iA->lastkilled+600) )
            {
                //printf("call rwIaddrInd\n");
                if ( iguana_rwiAddrind(coin,1,iA,iA->hh.itemind) > 0 )
                {
                    //printf("iA.%p iguana_startconnection.(%s) status.%d pending.%d\n",iA,addr->ipaddr,iA->status,addr->pending);
                    iA->status = IGUANA_PEER_CONNECTING;
                    addr->pending = (uint32_t)time(NULL);
                    iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
                }
                else
                {
                    addr->ipbits = 0;
                    printf("error rwiAddrind.%d\n",iA->hh.itemind);
                }
            }
        } else printf("%s no open peer slots left\n",coin->symbol);
    }
    //else if ( iA != 0 )
    //    printf("iA->ipbits %d, %d iguana_numthreads(coin,1 << IGUANA_CONNTHREAD) status.%d\n",iA->ipbits,iguana_numthreads(coin,1 << IGUANA_CONNTHREAD),iA->status);
    //else printf("connector null iA\n");
    return(0);
}

uint32_t iguana_possible_peer(struct iguana_info *coin,char *ipaddr)
{
    char checkaddr[64],_ipaddr[64]; uint64_t ipbits; uint32_t now = (uint32_t)time(NULL); int32_t i,n; struct iguana_iAddr *iA; struct iguana_peer *addr; struct stritem *sitem;
    if ( coin->virtualchain != 0 || coin->peers == 0 )
        return(0);
    if ( ipaddr != 0 && ipaddr[0] != 0 && coin->peers != 0 )
    {
        if ( strcmp(ipaddr,"0.0.0.0") == 0 || strcmp(ipaddr,"127.0.0.1") == 0 )
            return(0);
        for (i=n=0; i<IGUANA_MAXPEERS; i++)
            if ( strcmp(ipaddr,coin->peers->active[i].ipaddr) == 0 )
            {
                //printf("%s possible peer.(%s) %x already there\n",coin->symbol,ipaddr,(uint32_t)coin->peers->active[i].ipbits);
                return(0);
            }
        //printf("%s Q possible.(%s)\n",coin->symbol,ipaddr);
        queue_enqueue("possibleQ",&coin->possibleQ,queueitem(ipaddr));
        return((uint32_t)time(NULL));
    }
    else if ( iguana_pendingaccept(coin) != 0 )
        return((uint32_t)time(NULL));
    else if ( (sitem= queue_dequeue(&coin->possibleQ)) == 0 )
        return((uint32_t)time(NULL));
    safecopy(_ipaddr,sitem->str,sizeof(_ipaddr));
    free(sitem);
    ipaddr = _ipaddr;
#ifdef IGUANA_DISABLEPEERS
    if ( strcmp(ipaddr,"127.0.0.1") != 0 )
        return((uint32_t)time(NULL));
#endif
    ipbits = (uint32_t)calc_ipbits(ipaddr);
    if ( (addr= iguana_peerslot(coin,(uint32_t)ipbits,0)) == 0 )
        return((uint32_t)time(NULL));
    /*for (i=n=0; i<IGUANA_MAXPEERS; i++)
     {
     if ( strcmp(ipaddr,coin->peers->active[i].ipaddr) == 0 )
     return((uint32_t)time(NULL));
     else if ( coin->peers->active[i].ipaddr[0] != 0 )
     n++;
     }*/
    n = coin->peers->numranked;
    if ( n >= coin->MAXPEERS-(coin->MAXPEERS>>3)-1 || coin->peers->numranked >= coin->MAXPEERS )
        return((uint32_t)time(NULL));
    if ( strncmp("0.0.0",ipaddr,5) != 0 && strcmp("0.0.255.255",ipaddr) != 0 && strcmp("1.0.0.0",ipaddr) != 0 )
    {
        for (i=0; ipaddr[i]!=0; i++)
            if ( ipaddr[i] == ':' )
            {
                ipaddr[i] = 0;
                break;
            }
        //printf("%s check possible peer.(%s)\n",coin->symbol,ipaddr);
        if ( (ipbits= calc_ipbits(ipaddr)) != 0 )
        {
            expand_ipbits(checkaddr,ipbits);
            if ( strcmp(checkaddr,ipaddr) == 0 )
            {
                //printf("%s valid ipaddr.(%s) MAXPEERS.%d\n",coin->symbol,ipaddr,coin->MAXPEERS);
                if ( (iA= iguana_iAddrhashfind(coin,ipbits,1)) != 0 )
                {
                    if ( iA->status != IGUANA_PEER_CONNECTING && iA->status != IGUANA_PEER_READY && iA->status != IGUANA_PEER_ELIGIBLE )
                    {
                        if ( (iA->lastconnect == 0 || iA->lastkilled == 0) || (iA->numconnects > 0 && iA->lastconnect > (now - IGUANA_RECENTPEER)) || iA->lastkilled < now-600 )
                        {
                            iA->status = IGUANA_PEER_ELIGIBLE;
                            if ( iguana_rwiAddrind(coin,1,iA,iA->hh.itemind) == 0 )
                                printf("error updating status for (%s) ind.%d\n",ipaddr,iA->hh.itemind);
                            iguana_iAddriterator(coin,iA,addr);
                        } else printf("ignore.(%s) lastconnect.%u lastkilled.%u numconnects.%d\n",ipaddr,iA->lastconnect,iA->lastkilled,iA->numconnects);
                    } else printf("skip.(%s) ind.%d status.%d\n",ipaddr,iA->hh.itemind,iA->status);
                } else printf("cant find (%s) which should have been created\n",ipaddr);
            } else printf("%s reject ipaddr.(%s) vs checkaddr.(%s)\n",coin->symbol,ipaddr,checkaddr);
        }
    }
    return((uint32_t)time(NULL));
}

void iguana_processmsg(void *ptr)
{
    struct iguana_info *coin; uint8_t buf[32768]; struct iguana_peer *addr = ptr;
    if ( addr == 0 || (coin= iguana_coinfind(addr->symbol)) == 0 || addr->dead != 0 )
    {
        printf("iguana_processmsg cant find addr.%p symbol.%s\n",addr,addr!=0?addr->symbol:0);
        return;
    }
    _iguana_processmsg(SuperNET_MYINFO(0),coin,addr->usock,addr,buf,sizeof(buf));
    addr->startrecv = 0;
}

int32_t iguana_pollsendQ(struct iguana_info *coin,struct iguana_peer *addr)
{
    struct iguana_packet *packet;
    if ( (packet= queue_dequeue(&addr->sendQ)) != 0 )
    {
        if ( (0) && (addr->supernet != 0 || strcmp((char *)&packet->serialized[4],"SuperNET") == 0) )
            printf("%s: send.(%s).%d usock.%d dead.%u ready.%u supernet.%d\n",addr->ipaddr,packet->serialized+4,packet->datalen,addr->usock,addr->dead,addr->ready,addr->supernet);
        if ( strcmp((char *)&packet->serialized[4],"getdata") == 0 )
        {
            printf("unexpected getdata for %s\n",addr->ipaddr);
            myfree(packet,sizeof(*packet) + packet->datalen);
        }
        else if ( packet->embargo.x == 0 || tai_diff(packet->embargo,tai_now()) >= -SMALLVAL )
        {
            iguana_send(coin,addr,packet->serialized,packet->datalen);
            myfree(packet,sizeof(*packet) + packet->datalen);
            return(1);
        }
        else
        {
            //printf("embargo.x %llu %f\n",(long long)packet->embargo.x,tai_diff(packet->embargo,tai_now()));
            queue_enqueue("embargo",&addr->sendQ,&packet->DL);
        }
    }
    return(0);
}

int32_t iguana_pollrecv(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,uint8_t *buf,int32_t bufsize)
{
#ifndef IGUANA_DEDICATED_THREADS
    strcpy(addr->symbol,coin->symbol);
    if ( coin->peers != 0 && addr != coin->peers->localaddr )
    {
        addr->startrecv = (uint32_t)time(NULL);
        iguana_launch("processmsg",iguana_processmsg,addr,IGUANA_RECVTHREAD);
    }
    else
#endif
        _iguana_processmsg(myinfo,coin,addr->usock,addr,buf,bufsize);
    return(1);
}

#ifdef IGUANA_PEERALLOC
void *iguana_peeralloc(struct iguana_info *coin,struct iguana_peer *addr,int32_t datalen)
{
    struct OS_memspace *mem; long i,iter; int32_t j,diff,size,bestfit; void *ptr;
    //printf("iguana_peeralloc.%s\n",addr->ipaddr);
    while ( 1 )
    {
        bestfit = -1;
        for (iter=0; iter<3; iter++)
        {
            for (i=0; i<sizeof(addr->SEROUT)/sizeof(*addr->SEROUT); i++)
            {
                mem = addr->SEROUT[i];
                if ( mem->threadsafe != 0 )
                    portable_mutex_lock(&mem->mutex);
                if ( iter < 2 && mem->availptrs > 0 )
                {
                    for (j=0; j<mem->numptrs; j++)
                    {
                        if ( mem->allocsizes[j] == 0 )
                        {
                            size = mem->maxsizes[j];
                            if ( size >= datalen )
                            {
                                diff = (size - datalen);
                                if ( diff == 0 || (iter == 1 && diff == bestfit) )
                                {
                                    mem->allocsizes[j] = datalen;
                                    mem->availptrs--;
                                    //printf("%s availptrs.%d size.%d j.%d diff.%d bestfit.%d %p.%d max.%d\n",mem->name,mem->availptrs,size,j,diff,bestfit,mem->ptrs[j],size,mem->maxsizes[j]);
                                    if ( mem->threadsafe != 0 )
                                        portable_mutex_unlock(&mem->mutex);
                                    return(mem->ptrs[j]);
                                }
                                else if ( iter == 0 && diff < (datalen >> 3) && diff < 4096 )
                                    bestfit = diff;
                            }
                        }
                    }
                }
                else if ( iter == 2 && (ptr= iguana_memalloc(mem,datalen,0)) != 0 )
                {
                    if ( mem->threadsafe != 0 )
                        portable_mutex_unlock(&mem->mutex);
                    ///printf("alloc iter.2\n");
                    return(ptr);
                }
                if ( mem->threadsafe != 0 )
                    portable_mutex_unlock(&mem->mutex);
                //printf("iter.%ld bestfit.%d\n",iter,bestfit);
            }
        }
        printf("iguana_peeralloc: cant find memory. wait and hope...\n");
        sleep(5);
    }
    return(0);
}

int64_t iguana_peerallocated(struct iguana_info *coin,struct iguana_peer *addr)
{
    int32_t i; int64_t total = 0;
    for (i=0; i<sizeof(addr->SEROUT)/sizeof(*addr->SEROUT); i++)
        if ( addr->SEROUT[i] != 0 )
            total += iguana_memallocated(addr->SEROUT[i]);
    return(total);
}

int64_t iguana_peerfree(struct iguana_info *coin,struct iguana_peer *addr,void *ptr,int32_t datalen)
{
    struct OS_memspace *mem; long offset,i; int64_t avail = -1;
    //printf("iguana_peerfree.%p %d\n",ptr,datalen);
    for (i=0; i<sizeof(addr->SEROUT)/sizeof(*addr->SEROUT); i++)
    {
        mem = addr->SEROUT[i];
        offset = ((long)ptr - (long)mem->ptr);
        if ( offset >= 0 && offset+datalen < mem->totalsize )
        {
            if ( iguana_memfree(mem,ptr,datalen) < 0 || (avail= iguana_peerallocated(coin,addr)) < 0 )
            {
                printf("iguana_peerfree: corrupted mem avail.%lld ptr.%p %d\n",(long long)avail,ptr,datalen);
                iguana_exit(myinfo);
            }
            return(avail);
        }
    }
    printf("iguana_peerfree: cant find ptr.%p %d\n",ptr,datalen);
    return(-1);
}
#else

void *iguana_peeralloc(struct iguana_info *coin,struct iguana_peer *addr,int32_t datalen)
{
    addr->allocated += datalen;
    return(calloc(1,datalen));
}

int64_t iguana_peerfree(struct iguana_info *coin,struct iguana_peer *addr,void *ptr,int32_t datalen)
{
    addr->freed += datalen;
    free(ptr);
    return(1);
}

int64_t iguana_peerallocated(struct iguana_info *coin,struct iguana_peer *addr)
{
    return(addr->allocated - addr->freed);
}
#endif

int32_t iguana_voutsfname(struct iguana_info *coin,int32_t roflag,char *fname,int32_t slotid)
{
    sprintf(fname,"%s/%s%s/vouts/%04d.vouts",GLOBAL_DBDIR,roflag!=0?"ro/":"",coin->symbol,slotid);
    return((int32_t)strlen(fname));
}

int32_t iguana_vinsfname(struct iguana_info *coin,int32_t roflag,char *fname,int32_t slotid)
{
    if ( roflag != 0 )
        sprintf(fname,"%s/ro/%s/purgeable/%04d.vins",coin->VALIDATEDIR,coin->symbol,slotid);
    else sprintf(fname,"%s/%s/%04d.vins",coin->VALIDATEDIR,coin->symbol,slotid);
    OS_compatible_path(fname);
    return((int32_t)strlen(fname));
}

int32_t iguana_peerslotinit(struct iguana_info *coin,struct iguana_peer *addr,int32_t slotid,uint64_t ipbits)
{
    char fname[1024];
    memcpy(addr->netmagic,coin->chain->netmagic,4);
    addr->ipbits = ipbits;
    addr->addrind = slotid;
    iguana_voutsfname(coin,0,fname,addr->addrind);
    if ( (addr->voutsfp= fopen(fname,"rb+")) != 0 )
        fseek(addr->voutsfp,0,SEEK_END);
    else if ( (addr->voutsfp= fopen(fname,"wb+")) == 0 )
    {
        printf("iguana_peerslotinit cant create.(%s)\n",fname);
        return(-1);
    }
    if ( coin->MAXPEERS == 1 || coin->VALIDATENODE > 0 || coin->FULLNODE > 0 )
    {
        iguana_vinsfname(coin,0,fname,addr->addrind);
        if ( (addr->vinsfp= fopen(fname,"rb+")) != 0 )
            fseek(addr->vinsfp,0,SEEK_END);
        else if ( (addr->vinsfp= fopen(fname,"wb+")) == 0 )
        {
            printf("iguana_peerslotinit cant create.(%s)\n",fname);
            return(-1);
        }
    }
    return(0);
}

void iguana_dedicatedloop(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr)
{
    //static uint32_t lastping;
    struct pollfd fds; struct iguana_bundlereq *req; uint8_t *buf; uint32_t ipbits;
    int32_t bufsize,flag,run,timeout = coin->polltimeout == 0 ? 10 : coin->polltimeout;
    if ( coin->virtualchain != 0 || coin->peers == 0 )
        return;
    if ( iguana_peerslotinit(coin,addr,(int32_t)(((long)addr - (long)&coin->peers->active[0]) / sizeof(*addr)),calc_ipbits(addr->ipaddr)) < 0 )
    {
        printf("error creating peer's files\n");
        return;
    }
    //instantdex_peerhas_clear(coin,addr);
#ifdef IGUANA_PEERALLOC
    int32_t i;  int64_t remaining; struct OS_memspace *mem[sizeof(addr->SEROUT)/sizeof(*addr->SEROUT)];
    for (i=0; i<sizeof(addr->SEROUT)/sizeof(*addr->SEROUT); i++)
    {
        mem[i] = mycalloc('s',1,sizeof(*mem[i]));
        addr->SEROUT[i] = mem[i];
        mem[i]->totalsize = IGUANA_MAXPACKETSIZE;
        mem[i]->ptr = mycalloc('P',1,mem[i]->totalsize);
        mem[i]->used = 0;
        strcpy(mem[i]->name,addr->ipaddr);
        //mem[i]->threadsafe = 1;
        iguana_memreset(mem[i]);
    }
#endif
    //addr->pubkey = GENESIS_PUBKEY;
    ipbits = (uint32_t)addr->ipbits;
    vcalc_sha256(0,addr->iphash.bytes,(uint8_t *)&ipbits,sizeof(ipbits));
    //char str[65]; printf("start dedicatedloop.%s addrind.%d %s\n",addr->ipaddr,addr->addrind,bits256_str(str,addr->iphash));
    //addr->maxfilehash2 = IGUANA_MAXFILEITEMS;
    bufsize = IGUANA_MAXPACKETSIZE * 2;
    if ( addr->blockspace == 0 )
        addr->blockspace = mycalloc('r',1,bufsize + 8192);
    buf = mycalloc('r',1,bufsize);
    if ( strcmp(coin->symbol,"VPN") == 0 )
    {
        addr->msgcounts.verack++;
        iguana_send_VPNversion(coin,addr,coin->myservices);
    }
    else
    {
        sleep(1 + (rand() % 3));
        //printf("greeting send version myservices.%llu to (%s)\n",(long long)coin->myservices,addr->ipaddr);
        iguana_send_version(coin,addr,coin->myservices);
    }
    //sleep(1+(rand()%5));
    run = 0;
    while ( addr->usock >= 0 && addr->dead == 0 && coin->peers->shuttingdown == 0 )
    {
        if ( (req= queue_dequeue(&coin->cacheQ)) != 0 )
        {
            if ( req->datalen != 0 )
            {
                //char str[65]; printf("CACHE.%p parse[%d] %s %s\n",req,req->recvlen,req->H.command,bits256_str(str,req->zblock.RO.hash2));
                iguana_parsebuf(myinfo,coin,addr,&req->H,req->serializeddata,req->recvlen,1);
            } else printf("CACHE error no datalen\n");
            coin->cachefreed++;
            myfree(req,req->allocsize);
            continue;
        }
        flag = 0;
        memset(&fds,0,sizeof(fds));
        fds.fd = addr->usock;
        fds.events |= (POLLOUT | POLLIN);

		if (  poll(&fds,1,timeout) > 0 && (fds.revents & POLLOUT) != 0 )
        {
            flag += iguana_pollsendQ(coin,addr);
            if ( addr->dead != 0 )
            {
                printf("%s is dead\n",addr->ipaddr);
                break;
            }
        }
        if ( flag == 0 )
        {
            if ( (fds.revents & POLLIN) != 0 )
            {
                flag += iguana_pollrecv(myinfo,coin,addr,buf,bufsize);
                if ( addr->dead != 0 )
                {
                    printf("%s is dead\n",addr->ipaddr);
                    break;
                }
            }
            if ( flag == 0 )
            {
                if ( coin->active != 0 && (fds.revents & POLLOUT) != 0 )
                {
                    if ( iguana_pollQsPT(coin,addr) > 0 )
                    {
                        //printf("pollQ!\n");
                        flag++;
                    }
                    if ( addr->dead != 0 )
                    {
                        printf("%s is dead\n",addr->ipaddr);
                        break;
                    }
                }
            }
            if ( flag == 0 )
            {
                if ( run++ > 1000 )
                {
                    //printf("sleep\n");
                    usleep(100000);
                }
                else if ( addr->rank != 1 )
                    usleep(coin->polltimeout*5000 + 1*(rand() % (coin->polltimeout*3000)));
                else usleep(10000 + coin->backlog);
            } else run >>= 2;
        }
        if ( flag != 0 )
            run = 0;
        /*else if ( 0 && addr->supernet != 0 && time(NULL) > lastping+SUPERNET_PINGGAP )
         {
         iguana_send_supernet(addr,SUPERNET_GETPEERSTR,0);
         lastping = (uint32_t)time(NULL);
         }*/
        if ( addr->persistent_peer != 0 )
        {
            if ( addr->usock < 0 || addr->dead != 0 )
            {
                if ( addr->usock >= 0 )
                    closesocket(addr->usock);
                addr->usock = -1;
                while ( addr->usock < 0 )
                {
                    printf("persistent peer.(%s) disconnected... reconnect\n",addr->ipaddr);
                    sleep(addr->persistent_peer);
                    if ( (addr->A.port= (uint16_t)(addr->ipbits >> 32)) == 0 )
                        addr->A.port = coin->chain->portp2p;
                    addr->usock = iguana_socket(0,addr->ipaddr,addr->A.port);
                }
            }
        }
        else if ( coin->isRT != 0 && addr->rank > coin->MAXPEERS && (rand() % 10) == 0 )
        {
            //printf("isRT and low rank.%d ",addr->rank);
            addr->dead = 1;
        }
    }
    //printf(">>>>>>>>>>>>>> finish %s dedicatedloop.%s\n",coin->symbol,addr->ipaddr);
    if ( (0) )
    {
        if ( addr->vinsfp != 0 )
            fclose(addr->vinsfp), addr->vinsfp = 0;
        if ( addr->voutsfp != 0 )
         fclose(addr->voutsfp), addr->voutsfp = 0;
    }
    iguana_iAkill(coin,addr,addr->dead != 0);
    myfree(buf,bufsize);
    //if ( addr->filehash2 != 0 )
    //    myfree(addr->filehash2,addr->maxfilehash2*sizeof(*addr->filehash2)), addr->filehash2 = 0;
    if ( (0) )
    {
        iguana_mempurge(&addr->RAWMEM);
        iguana_mempurge(&addr->TXDATA);
        iguana_mempurge(&addr->HASHMEM);
    }
#ifdef IGUANA_PEERALLOC
    while ( (remaining= iguana_peerallocated(coin,addr)) > 0 )
    {
        char str[65];
        printf("waiting for helperQ to flush peer mem %s\n",mbstr(str,remaining));
        sleep(5);
    }
    for (i=0; i<sizeof(addr->SEROUT)/sizeof(*addr->SEROUT); i++)
    {
        if ( addr->SEROUT[i] != 0 )
        {
            if ( addr->SEROUT[i]->ptr != 0 )
                myfree(addr->SEROUT[i]->ptr,IGUANA_MAXPACKETSIZE);
            myfree(addr->SEROUT[i],sizeof(*addr->SEROUT[i]));
        }
    }
#endif
    coin->peers->numconnected--;
}

void iguana_dedicatedglue(void *arg)
{
    struct iguana_info *coin = 0; struct iguana_peer *addr = arg;
    if ( addr == 0 || (coin= iguana_coinfind(addr->symbol)) == 0 )
    {
        printf("iguana_dedicatedglue nullptrs addr.%p coin.%p\n",addr,coin);
        return;
    }
    iguana_dedicatedloop(SuperNET_MYINFO(0),coin,addr);
}

void iguana_peersloop(void *ptr)
{
#ifndef IGUANA_DEDICATED_THREADS
    struct pollfd fds[IGUANA_MAXPEERS]; struct iguana_info *coin = ptr;
    struct iguana_peer *addr; uint8_t *bufs[IGUANA_MAXPEERS];
    int32_t i,j,n,r,nonz,flag,bufsizes[IGUANA_MAXPEERS],timeout=1;
    memset(fds,0,sizeof(fds));
    memset(bufs,0,sizeof(bufs));
    memset(bufsizes,0,sizeof(bufsizes));
    while ( coin->peers != 0 )
    {
        while ( coin->peers->shuttingdown != 0 )
        {
            printf("peers shuttingdown\n");
            sleep(3);
        }
        flag = 0;
        r = (rand() % coin->MAXPEERS);
        for (j=n=nonz=0; j<coin->MAXPEERS; j++)
        {
            i = (j + r) % coin->MAXPEERS;
            addr = &coin->peers->active[i];
            fds[i].fd = -1;
            if ( addr->usock >= 0 && addr->dead == 0 && addr->ready != 0 && (addr->startrecv+addr->startsend) != 0 )
            {
                fds[i].fd = addr->usock;
                fds[i].events = (addr->startrecv != 0) * POLLIN |  (addr->startsend != 0) * POLLOUT;
                nonz++;
            }
        }
        if ( nonz != 0 && poll(fds,coin->MAXPEERS,timeout) > 0 )
        {
            for (j=0; j<coin->MAXPEERS; j++)
            {
                i = (j + r) % coin->MAXPEERS;
                addr = &coin->peers->active[i];
                if ( addr->usock < 0 || addr->dead != 0 || addr->ready == 0 )
                    continue;
                if ( addr->startrecv == 0 && (fds[i].revents & POLLIN) != 0 && iguana_numthreads(1 << IGUANA_RECVTHREAD) < IGUANA_MAXRECVTHREADS )
                {
                    if ( bufs[i] == 0 )
                        bufsizes[i] = IGUANA_MAXPACKETSIZE, bufs[i] = mycalloc('r',1,bufsizes[i]);
                    flag += iguana_pollrecv(coin,addr,bufs[i],bufsizes[i]);
                }
                if ( addr->startsend == 0 && (fds[i].revents & POLLOUT) != 0 && iguana_numthreads(1 << IGUANA_SENDTHREAD) < IGUANA_MAXSENDTHREADS )
                {
                    if ( iguana_pollsendQ(coin,addr) == 0 )
                        flag += iguana_poll(coin,addr);
                    else flag++;
                }
            }
        }
        if ( flag == 0 )
        {
            if ( 0 && time(NULL) > lastping+1 && addr->supernet != 0 )
                iguana_send_supernet(coin,addr,SUPERNET_GETPEERSTR,0);
            usleep(1000);
        }
    }
#endif
}
