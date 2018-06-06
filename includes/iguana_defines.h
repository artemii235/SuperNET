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

#ifndef H_IGUANADEFINES_H
#define H_IGUANADEFINES_H

#define SPARSECOUNT(x) ((x) << 1)

#define IGUANA_MAXSCRIPTSIZE 10001
#define IGUANA_SERIALIZE_SPENDVECTORGEN
//#define IGUANA_DISABLEPEERS
#define _IGUANA_MAXSTUCKTIME 10
#ifdef __PNACL__
#define IGUANA_MAXITERATIONS 77
#else
#define IGUANA_MAXITERATIONS 777
#endif
#define IGUANA_DEFAULTLAG 7

#define IGUANA_MAXHEIGHT (1 << 30)
#define IGUANA_MAXCOINS 64
#define IGUANA_MAXDELAY_MILLIS (3600 * 1000 * 24)
#define IGUANA_DEFAULT_POLLTIMEOUT 10
#define IGUANA_SEQUENCEID_FINAL 0xfffffffe

#define IGUANA_EXCHANGEIDLE 10
#define IGUANS_JSMILLIS 100

#define IGUANA_WIDTH 1024
#define IGUANA_HEIGHT 200

#define IGUANA_HEADPERCENTAGE 0.
#define IGUANA_TAILPERCENTAGE 1.0
#define IGUANA_MAXPENDHDRS 1
#define IGUANA_BTCPENDINGREQUESTS 3
#define IGUANA_PENDINGREQUESTS 64
#define IGUANA_MINPENDBUNDLES 4
#define IGUANA_MAXPENDBUNDLES 64
#define IGUANA_RPCPORT 7778
#define IGUANA_NOTARYPORT 7776
#define IGUANA_MAXRAMCHAINSIZE ((uint64_t)1024L * 1024L * 1024L * 16)

#define IGUANA_MAPHASHTABLES 1
#define IGUANA_DEFAULTRAM 4
#define IGUANA_MAXRECVCACHE ((int64_t)1024L * 1024 * 1024L)
#define IGUANA_MAXBUNDLES (50000000 / 500)

#define IGUANA_MINPEERS 64

#define IGUANA_LOG2MAXPEERS 11 // cant exceed 13 bits as ramchain unspents has bitfield

#define IGUANA_MAXPEERS (1 << IGUANA_LOG2MAXPEERS)
#ifndef IGUANA_MAXPACKETSIZE
#define IGUANA_MAXPACKETSIZE (1 << IGUANA_LOG2PACKETSIZE)
#endif
//#define IGUANA_MAXFILEITEMS 8192
#define IGUANA_RECENTPEER (3600 * 24 * 7)

#define IGUANA_PERMTHREAD 0
#define IGUANA_CONNTHREAD 1
#define IGUANA_SENDTHREAD 2
#define IGUANA_RECVTHREAD 3
#define IGUANA_HELPERTHREAD 4
#define IGUANA_EXCHANGETHREAD 5

#define IGUANA_DEDICATED_THREADS
#ifdef IGUANA_DEDICATED_THREADS
#define IGUANA_MAXCONNTHREADS 16
#define IGUANA_MAXSENDTHREADS (IGUANA_MAXPEERS>>2)
#define IGUANA_MAXRECVTHREADS (IGUANA_MAXPEERS>>2)
#else
#define IGUANA_MAXCONNTHREADS 16
#define IGUANA_MAXSENDTHREADS 16
#define IGUANA_MAXRECVTHREADS 16
#endif
#define BASILISK_MAXRELAYS 64

#define IGUANA_SUBDIRDIVISOR 28000
#define NTARGETSPACING 60

#define IGUANA_PROTOCOL_BITCOIN 'b'
#define IGUANA_PROTOCOL_NXT 'n'
#define IGUANA_PROTOCOL_ETHER 'e'
#define IGUANA_PROTOCOL_LISK 'l'
#define IGUANA_PROTOCOL_WAVES 'w'
#define IGUANA_PROTOCOL_IOTA 'i'

#ifdef __PNACL
void PNACL_message(const char* format, ...);
#endif

extern int32_t IGUANA_NUMHELPERS;

#ifdef __PNACL
#define printf PNACL_message
#define MS_ASYNC	1		/* Sync memory asynchronously.  */
#define MS_SYNC		4		/* Synchronous memory sync.  */
#else
#define PNACL_message printf
#endif

#ifndef WIN32
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0x4000	// Do not generate SIGPIPE
#endif
#else
#define MSG_NOSIGNAL	0
#endif

#define BIP0031_VERSION	 60000
#define CADDR_TIME_VERSION 31402
#define MIN_PROTO_VERSION 209
#define MAX_BLOCK_SIZE 1000000
//#define COINBASE_MATURITY 100

#define _IGUANA_HDRSCOUNT 2000
#define _IGUANA_BLOCKHASHES 500
#define IGUANA_MAXBUNDLESIZE _IGUANA_HDRSCOUNT

#define NODE_NETWORK (1 << 0)
#define NODE_GETUTXO (1 << 1)
#define NODE_BLOOM (1 << 2)

#define INIT_PROTO_VERSION 209 // initial proto version, to be increased after version/verack negotiation
#define GETHEADERS_VERSION 31800 // In this version, 'getheaders' was introduced.
#define MIN_PEER_PROTO_VERSION GETHEADERS_VERSION // disconnect from peers older than this proto version
// nTime field added to CAddress, starting with this version, if possible, avoid requesting addresses nodes older than this
#define CADDR_TIME_VERSION 31402
// only request blocks from nodes outside this range of versions
#define NOBLKS_VERSION_START 32000
#define NOBLKS_VERSION_END 32400

#define BIP0031_VERSION 60000 // BIP 0031, pong message, is enabled for all versions AFTER this one
#define MEMPOOL_GD_VERSION 60002 // "mempool" command, enhanced "getdata" behavior starts with this version
#define NO_BLOOM_VERSION 70011 // "filter*" disabled without NODE_BLOOM after and including this version
#define PROTOCOL_HEADERS_VERSION 70012
#define PROTOCOL_VERSION 70003
//#define PROTOCOL_VERSION PROTOCOL_HEADERS_VERSION

#define MSG_TX 1
#define MSG_BLOCK 2
#define MSG_FILTERED_BLOCK 3
//#define MSG_QUOTE 253
#define MSG_BUNDLE 254
#define MSG_BUNDLE_HEADERS 255

#define IGUANA_MAXLOCATORS 64
#define IGUANA_MAXINV 50000

#define IGUANA_VOLATILE 1
#define IGUANA_ITEMIND_DATA 2
#define IGUANA_MAPPED_ITEM 4
#define IGUANA_SHA256 0x80
#define IGUANA_ALLOC_MULT 1.1
#define IGUANA_ALLOC_INCR 1000

#define IGUANA_JSONTIMEOUT 10000

#define IGUANA_MAPRECVDATA 1
#define IGUANA_MAPTXIDITEMS 2
#define IGUANA_MAPPKITEMS 4
#define IGUANA_MAPBLOCKITEMS 8
#define IGUANA_MAPPEERITEMS 16

#define IGUANA_PEER_ELIGIBLE 1
#define IGUANA_PEER_CONNECTING 2
#define IGUANA_PEER_READY 3
#define IGUANA_PEER_KILLED 4

#define IGUANA_NORMAL_TXVERSION 1
#define IGUANA_LOCKTIME_TXVERSION 1

#define IGUANA_SEARCHBUNDLE 1
#define IGUANA_SEARCHNOLAST (IGUANA_SEARCHBUNDLE | 2)
#define IGUANA_SEARCHPREV 4
#define IGUANA_SEARCHNEXT 8
#define IGUANA_SEARCHALL (IGUANA_SEARCHBUNDLE | IGUANA_SEARCHPREV | IGUANA_SEARCHNEXT)

#define SUPERNET_MAXEXCHANGES 64
#define SUPERNET_APIVERSION 0


#define IGUANA_SCRIPT_NULL 0
#define IGUANA_SCRIPT_76AC 1
#define IGUANA_SCRIPT_76A988AC 2
#define IGUANA_SCRIPT_P2SH 3
#define IGUANA_SCRIPT_OPRETURN 4
#define IGUANA_SCRIPT_3of3 5
#define IGUANA_SCRIPT_2of3 6
#define IGUANA_SCRIPT_1of3 7
#define IGUANA_SCRIPT_2of2 8
#define IGUANA_SCRIPT_1of2 9
#define IGUANA_SCRIPT_MSIG 10
#define IGUANA_SCRIPT_DATA 11
#define IGUANA_SCRIPT_AC 12
#define IGUANA_SCRIPT_1of1 13
#define IGUANA_SCRIPT_STRANGE 15

#define IGUANA_MAXSCRIPTSIZE 10001

#endif

