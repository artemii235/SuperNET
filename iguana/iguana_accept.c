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
#include "exchanges777.h"

struct iguana_accept { struct queueitem DL; char ipaddr[64]; uint32_t ipbits; int32_t sock; uint16_t port; };

int32_t iguana_acceptspoll(uint8_t *buf,int32_t bufsize,struct iguana_accept *accepts,int32_t num,int32_t timeout)
{
	/** 
	* This solution is for win64
	* 2^11*sizeof(struct fd) for win64 bit gives a very big number
	* for that reason it cannot allocate memory from stack
	* so the solution is to allocate memory from heap, instead of stack
	* @author - fadedreamz@gmail.com
	*/
#if defined(_M_X64)
	struct pollfd * fds;
	int32_t i, j, n, r, nonz, flag; struct iguana_accept *ptr;
	if (num == 0)
		return(0);;
	fds = (struct pollfd *) malloc(sizeof(struct pollfd) * IGUANA_MAXPEERS);
	if (NULL == fds)
		return -1;
	memset(fds, 0, sizeof(struct pollfd) * IGUANA_MAXPEERS);
#else
    struct pollfd fds[IGUANA_MAXPEERS]; int32_t i,j,n,r,nonz,flag; struct iguana_accept *ptr;
    if ( num == 0 )
        return(0);;
    memset(fds,0,sizeof(fds));
#endif
    flag = 0;
    r = (rand() % num);
    for (j=n=nonz=0; j<num&&j<sizeof(fds)/sizeof(*fds)-1; j++)
    {
        i = (j + r) % num;
        ptr = &accepts[i];
        fds[i].fd = -1;
        if ( ptr->sock >= 0 )
        {
            fds[i].fd = ptr->sock;
            fds[i].events = (POLLIN | POLLOUT);
            nonz++;
        }
    }
    if ( nonz != 0 && poll(fds,num,timeout) > 0 )
    {
        for (j=0; j<num; j++)
        {
            i = (j + r) % num;
            ptr = &accepts[i];
            if ( ptr->sock < 0 )
                continue;
            if ( (fds[i].revents & POLLIN) != 0 )
            {
                //return(iguana_recvmsg(ptr->ipaddr,ptr->sock,buf,bufsize));
            }
            if ( (fds[i].revents & POLLOUT) != 0 )
            {
                //if ( iguana_pollsendQ(coin,addr) == 0 )
                //    flag += iguana_poll(coin,addr);
                //else flag++;
            }
        }
    }

/**
* graceful memory release, because we allocated memory on heap,
* so we are releasing it here
* @author - fadedreamz@gmail.com
*/
#if defined(_M_X64)
	free(fds);
#endif
    return(0);
}

void iguana_acceptloop(void *args)
{
    struct iguana_peer *addr; struct iguana_info *coin = args;
    struct pollfd pfd; int32_t sock; struct iguana_accept *ptr; uint16_t port = coin->chain->portp2p;
    socklen_t clilen; struct sockaddr_in cli_addr; char ipaddr[64]; uint32_t i,ipbits,flag;
    if ( coin->peers == 0 )
        return;
    while ( (coin->bindsock= iguana_socket(1,"0.0.0.0",port)) < 0 )
    {
        if ( coin->peers->localaddr != 0 )
        {
            printf("another daemon running, no need to have iguana accept connections\n");
            return;
        }
        //if ( port != myinfo->rpcport )
        //    return;
        sleep(5);
    }
    printf(">>>>>>>>>>>>>>>> iguana_bindloop 127.0.0.1:%d bind sock.%d\n",port,coin->bindsock);
    printf("START ACCEPTING\n");
    while ( coin->bindsock >= 0 )
    {
        memset(&pfd,0,sizeof(pfd));
        pfd.fd = coin->bindsock;
        pfd.events = POLLIN;
        if ( poll(&pfd,1,100) <= 0 )
            continue;
        clilen = sizeof(cli_addr);
        //printf("ACCEPT (%s:%d) on sock.%d\n","127.0.0.1",coin->chain->portp2p,coin->bindsock);
        sock = accept(coin->bindsock,(struct sockaddr *)&cli_addr,&clilen);
        if ( sock < 0 )
        {
            printf("ERROR on accept bindsock.%d errno.%d (%s)\n",coin->bindsock,errno,strerror(errno));
            continue;
        }
        memcpy(&ipbits,&cli_addr.sin_addr.s_addr,sizeof(ipbits));
        expand_ipbits(ipaddr,ipbits);
        //printf("incoming %s (%s:%u)\n",coin->symbol,ipaddr,cli_addr.sin_port);
        for (i=flag=0; i<IGUANA_MAXPEERS; i++)
        {
            addr = &coin->peers->active[i];
            if ( addr->ipbits == (uint32_t)ipbits && addr->usock >= 0 )
            {
                //printf("found existing %s peer.(%s) in slot[%d]\n",coin->symbol,ipaddr,i);
                close(addr->usock);
                addr->dead = 0;
                addr->usock = sock;
                addr->A.port = cli_addr.sin_port;
                addr->ready = (uint32_t)time(NULL);
                flag = 1;
                iguana_send_version(coin,addr,coin->myservices);

                //instantdex_peerhas_clear(coin,&coin->peers->active[i]);
                //iguana_iAkill(coin,&coin->peers->active[i],0);
                //sleep(1);
                break;
            }
        }
        if ( flag != 0 )
            continue;
        printf("%s NEWSOCK.%d for %x (%s)\n",coin->symbol,sock,ipbits,ipaddr);
        /*if ( (uint32_t)ipbits == myinfo->myaddr.myipbits )
        {
            
        }*/
        if ( (addr= iguana_peerslot(coin,ipbits,1)) == 0 )
        {
            ptr = mycalloc('a',1,sizeof(*ptr));
            strcpy(ptr->ipaddr,ipaddr);
            ptr->ipbits = ipbits;
            ptr->sock = sock;
            ptr->port = cli_addr.sin_port;
            printf("queue PENDING ACCEPTS\n");
            queue_enqueue("acceptQ",&coin->acceptQ,&ptr->DL);
        }
        else
        {
            printf("LAUNCH %s DEDICATED THREAD for %s:%u\n",coin->symbol,ipaddr,cli_addr.sin_port);
            addr->usock = sock;
            addr->dead = 0;
            addr->A.port = cli_addr.sin_port;
            strcpy(addr->symbol,coin->symbol);
            iguana_launch(coin,"accept",iguana_dedicatedglue,addr,IGUANA_CONNTHREAD);
            //iguana_dedicatedloop(coin,addr);
        }
    }
}

int32_t iguana_pendingaccept(struct iguana_info *coin)
{
    struct iguana_accept *ptr; char ipaddr[64]; struct iguana_peer *addr;
    if ( (ptr= queue_dequeue(&coin->acceptQ)) != 0 )
    {
        if ( (addr= iguana_peerslot(coin,ptr->ipbits,0)) != 0 )
        {
            expand_ipbits(ipaddr,ptr->ipbits);
            printf("iguana_pendingaccept %s LAUNCH DEDICATED THREAD for %s\n",coin->symbol,ipaddr);
            addr->usock = ptr->sock;
            strcpy(addr->symbol,coin->symbol);
            iguana_launch(coin,"accept",iguana_dedicatedglue,addr,IGUANA_CONNTHREAD);
            myfree(ptr,sizeof(*ptr));
            return(1);
        } else queue_enqueue("requeue_acceptQ",&coin->acceptQ,&ptr->DL);
    }
    return(0);
}

/*int32_t iguana_acceptport(struct iguana_info *coin,uint16_t port)
{
    if ( OS_thread_create(malloc(sizeof(pthread_t)),NULL,(void *)iguana_acceptloop,(void *)coin) != 0 )
    {
        printf("error launching accept thread for port.%u\n",port);
        return(-1);
    }
    return(0);
}*/

void iguana_msgrequestQ(struct iguana_info *coin,struct iguana_peer *addr,int32_t type,bits256 hash2)
{
    struct iguana_peermsgrequest *msg;
    msg = calloc(1,sizeof(*msg));
    msg->addr = addr;
    msg->hash2 = hash2;
    msg->type = type;
    queue_enqueue("msgrequest",&coin->msgrequestQ,&msg->DL);
}

int32_t iguana_process_msgrequestQ(struct supernet_info *myinfo,struct iguana_info *coin)
{
    struct iguana_peermsgrequest *msg; int32_t height,len,flag = 0; bits256 checktxid; struct iguana_txid *tx,T; struct iguana_peer *addr;
    if ( (msg= queue_dequeue(&coin->msgrequestQ)) != 0 )
    {
        flag = 1;
        if ( msg->addr != 0 )
        {
            //char str[65]; printf("send type.%d %s -> (%s)\n",msg->type,bits256_str(str,msg->hash2),msg->addr->ipaddr);
            if ( msg->type == MSG_BLOCK )
            {
                if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
                {
                    if ( (addr= msg->addr) != 0 && (len= iguana_peerblockrequest(myinfo,coin,coin->blockspace,(int32_t)(coin->blockspacesize - sizeof(struct iguana_msghdr)),0,msg->hash2,0)) > 0 )
                    {
                        //char str[65]; printf("msg Sendlen.%d block %s to %s\n",len,bits256_str(str,msg->hash2),addr->ipaddr);
                        iguana_queue_send(addr,0,coin->blockspace,"block",len);
                    }
                }
            }
            else if ( msg->type == MSG_TX )
            {
                if ( coin->FULLNODE > 0 || coin->VALIDATENODE > 0 )
                {
                    if ( (tx= iguana_txidfind(coin,&height,&T,msg->hash2,coin->bundlescount-1)) != 0 )
                    {
                        if ( (len= iguana_ramtxbytes(coin,&coin->blockspace[sizeof(struct iguana_msghdr)],coin->blockspacesize,&checktxid,tx,height,0,0,0)) > 0 )
                        {
                            char str[65],str2[65];
                            if ( bits256_cmp(msg->hash2,checktxid) == 0 )
                                iguana_queue_send(msg->addr,0,coin->blockspace,"block",len);
                            else printf("checktxid mismatch (%s) != (%s)\n",bits256_str(str,msg->hash2),bits256_str(str2,checktxid));
                        }
                    }
                }
            }
            else if ( msg->type == MSG_FILTERED_BLOCK )
            {
                
            }
            else if ( msg->type == MSG_BUNDLE_HEADERS )
            {
                
            }
            else if ( msg->type == MSG_BUNDLE )
            {
                
            }
            /*else if ( msg->type == MSG_QUOTE )
            {
                if ( (len= instantdex_quoterequest(myinfo,coin,&coin->blockspace[sizeof(struct iguana_msghdr)],coin->blockspacesize,msg->addr,msg->hash2)) > 0 )
                {
                    //iguana_sethdr((void *)coin->blockspace,coin->chain->netmagic,"quote",&coin->blockspace[sizeof(struct iguana_msghdr)],len);
                    //iguana_msgparser(coin,msg->addr,0,0,0,(void *)coin->blockspace,&coin->blockspace[sizeof(struct iguana_msghdr)],len);
                    iguana_queue_send(msg->addr,0,coin->blockspace,"quote",len);
                }
            }*/
        }
        free(msg);
    }
    return(flag);
}

int32_t iguana_peerdatarequest(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *data,int32_t recvlen)
{
    int32_t i,type,len = 0; uint64_t x; bits256 hash2;
    len += iguana_rwvarint(0,data,&x);
    //for (i=0; i<10; i++)
    //    printf("%02x ",data[i]);
    //printf("x.%d recvlen.%d\n",(int32_t)x,recvlen);
    if ( x < IGUANA_MAXINV )
    {
        for (i=0; i<x; i++)
        {
            len += iguana_rwnum(0,&data[len],sizeof(uint32_t),&type);
            len += iguana_rwbignum(0,&data[len],sizeof(bits256),hash2.bytes);
            iguana_msgrequestQ(coin,addr,type,hash2);
        }
    }
    return(len);
}

int32_t iguana_inv2packet(uint8_t *serialized,int32_t maxsize,int32_t type,bits256 *hashes,int32_t n)
{
    int32_t i,len = sizeof(struct iguana_msghdr); uint64_t x = n;
    memset(serialized,0,len);
    len += iguana_rwvarint(1,&serialized[len],&x);
    //for (i=0; i<10; i++)
    //    printf("%02x ",data[i]);
    //printf("x.%d recvlen.%d\n",(int32_t)x,recvlen);
    if ( x < IGUANA_MAXINV )
    {
        for (i=0; i<x; i++)
        {
            len += iguana_rwnum(1,&serialized[len],sizeof(uint32_t),&type);
            len += iguana_rwbignum(1,&serialized[len],sizeof(bits256),hashes[i].bytes);
        }
    }
    if ( len > maxsize )
        return(-1);
    return(len - sizeof(struct iguana_msghdr));
}

int32_t iguana_headerget(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_block *block)
{
    bits256 checkhash2; struct iguana_msgzblock zmsgB; int32_t len = 0;
    iguana_blockunconv(coin->chain->zcash,coin->chain->auxpow,&zmsgB,(void *)block,1);
    if ( (len= iguana_rwblock(myinfo,coin->symbol,coin->chain->zcash,coin->chain->auxpow,coin->chain->hashalgo,1,&checkhash2,&serialized[sizeof(struct iguana_msghdr)],&zmsgB,(int32_t)(maxsize-sizeof(struct iguana_msghdr)))) < 0 )
        return(-1);
    if ( bits256_cmp(checkhash2,block->RO.hash2) != 0 )
    {
        char str[65],str2[65];
        printf("iguana_peerhdrrequest blockhash.%d error (%s) vs (%s)\n",block->height,bits256_str(str,checkhash2),bits256_str(str2,block->RO.hash2));
        return(-1);
    }
    return(len);
}

int32_t iguana_peerhdrrequest(struct supernet_info *myinfo,struct iguana_info *coin,uint8_t *serialized,int32_t maxsize,struct iguana_peer *addr,bits256 hash2)
{
    int32_t len=0,i,flag=0,height,n,hdrsi,bundlei,bundlesize,retval=-1; struct iguana_block *block; struct iguana_bundle *bp; struct iguana_outpoint outpt;
    if ( coin->RTheight > 0 && iguana_RTunspentindfind(myinfo,coin,&outpt,0,0,0,0,&height,hash2,0,coin->bundlescount-1,0) == 0 )
    {
        bundlesize = coin->chain->bundlesize;
        hdrsi = (height / bundlesize);
        bundlei = height - (hdrsi * bundlesize);
        if ( hdrsi >= 0 && hdrsi < bundlesize && bundlei >= 0 && bundlei < bundlesize && (bp= coin->bundles[hdrsi]) != 0 )
        {
            for (i=0; i<coin->chain->bundlesize; i++)
            {
                if ( (block= bp->blocks[i]) != 0 )
                {
                    if ( (n= iguana_headerget(myinfo,coin,&serialized[len],maxsize-len,block)) < 0 )
                    {
                        printf("%s error getting header ht.%d\n",coin->symbol,block->height);
                        continue;
                    }
                    len += n;
                } else printf("cant find block at ht.%d\n",height+i);
            }
        }
        if ( (0) && flag != 0 && strcmp("BTCD",coin->symbol) != 0 )
            retval = iguana_queue_send(addr,0,serialized,"headers",len);
        //printf("hdrs request retval.%d len.%d\n",retval,len);
    } //else printf("couldnt find header\n");
    return(retval);
}

int32_t iguana_peergetrequest(struct supernet_info *myinfo,struct iguana_info *coin,struct iguana_peer *addr,uint8_t *data,int32_t recvlen,int32_t getblock)
{
    int32_t i,reqvers,len,n,flag = 0; bits256 hash2;
    if ( coin->RTheight <= 0 )
        return(0);
    if ( getblock != 0 )
        addr->msgcounts.getblocks++;
    else addr->msgcounts.getheaders++;
    len = iguana_rwnum(0,&data[0],sizeof(uint32_t),&reqvers);
    len += iguana_rwvarint32(0,&data[len],(uint32_t *)&n);
    for (i=0; i<n&&len<=recvlen-sizeof(bits256)*2; i++)
    {
        len += iguana_rwbignum(0,&data[len],sizeof(bits256),hash2.bytes);
        if ( bits256_nonz(hash2) == 0 )
            break;
        if ( flag == 0 )
        {
            if ( getblock != 0 && iguana_peerblockrequest(myinfo,coin,addr->blockspace,IGUANA_MAXPACKETSIZE,addr,hash2,0) > 0 )
                flag = 1;
            else if ( getblock == 0 && iguana_peerhdrrequest(myinfo,coin,addr->blockspace,IGUANA_MAXPACKETSIZE,addr,hash2) > 0 )
                flag = 1;
        }
    }
    len += iguana_rwbignum(0,&data[len],sizeof(bits256),hash2.bytes);
    //for (i=0; i<69; i++)
    //    printf("%02x ",data[i]);
    //printf("version.%d num blocks.%d recvlen.%d len.%d\n",reqvers,n,recvlen,len);
    return(len);
}

int32_t iguana_peeraddrrequest(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *space,int32_t spacesize)
{
    int32_t i,iter,n,max,sendlen; uint64_t x; struct iguana_peer *tmpaddr,tmp; char ipaddr[65];
    if ( coin->peers == 0 )
        return(0);
    sendlen = 0;
    max = (IGUANA_MINPEERS + IGUANA_MAXPEERS) / 2;
    if ( max > coin->peers->numranked )
        max = coin->peers->numranked;
    x = 0;
    sendlen = iguana_rwvarint(1,&space[sendlen],&x);
    for (iter=0; iter<2; iter++)
    {
        for (i=n=0; i<max; i++)
        {
            if ( (tmpaddr= coin->peers->ranked[i]) != 0 && ((iter == 0 && tmpaddr->supernet != 0) || (iter == 1 && tmpaddr->supernet == 0)) && tmpaddr->ipbits != 0 )
            {
                tmp = *tmpaddr;
                iguana_rwnum(1,&tmp.A.ip[12],sizeof(uint32_t),&tmp.ipbits);
                expand_ipbits(ipaddr,tmp.ipbits);
                if ( tmp.A.port == 0 )
                {
                    ((uint8_t *)&tmp.A.port)[0] = ((uint8_t *)&coin->chain->portp2p)[1];
                    ((uint8_t *)&tmp.A.port)[1] = ((uint8_t *)&coin->chain->portp2p)[0];
                }
                //printf("(%s:%02x%02x).%04x ",ipaddr,((uint8_t *)&tmp.A.port)[0],((uint8_t *)&tmp.A.port)[1],(int32_t)tmp.protover);
                sendlen += iguana_rwaddr(1,&space[sendlen],&tmp.A,CADDR_TIME_VERSION);
                x++;
                if ( x == 0xf8 )
                    break;
            }
        }
    }
    iguana_rwvarint(1,space,&x);
    //for (i=0; i<sendlen; i++)
    //    printf("%02x",space[i]);
    //printf(" %p addrrequest: sendlen.%d x.%d\n",space,sendlen,(int32_t)x);
    if ( x == 0 )
        return(-1);
    return(sendlen);
}
