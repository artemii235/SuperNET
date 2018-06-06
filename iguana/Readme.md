#SuperNET Client "iguana"

[![Join the chat at https://gitter.im/jl777/SuperNET](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/jl777/SuperNET?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

> #TL;DR#
> 
> ```sudo apt-get update; sudo apt-get install libcurl4-gnutls-dev libssl-dev; git clone https://github.com/jl777/SuperNET; cd SuperNET; ./m_onetime m_unix; ./m_unix; agents/iguana```
> 
> The above one line gets SuperNET installed, built and launched for unix. 
> 
> After that ```./m_unix``` updates to latest.
> *Continue below at "Running".*

**iguana is easy to build. Start by cloning (or downloading) this repository.**

#DEPENDENCIES#
##for native (unix, osx)##
Just make sure you have the dev versions of openssl and curl installed:

```sudo apt-get install libcurl4-gnutls-dev libssl-dev```

##For native (win32, win64)##
TOOL_DIR := /usr/local/gcc-4.8.0-qt-4.8.4-for-mingw32/win32-gcc/bin
MINGW := i586-mingw32
The above two definitions need to be changed to match the mingw install on your system. m_win32 and m_win64 just invokes the makefile in mingw32 and mingw64

##For chrome app##
You need to make sure the nacl sdk is properly installed and you are able to build the examples.
Now you will need to get the external libs, which can be built from scratch using naclports or there use the reference builds of libssl.a, libcrypto.a, libcurl.a and libz.a in the SuperNET/crypto777/pnacl_libs. You can just copy those over into $(NACL_SDK_ROOT)/<pepper_dir>/lib/pnacl.


#ONETIME#
Now you are ready to build.
I try to make the build process as simple as possible, so there are no `autoconf`, `autoreconf`, `configure`, `cmake`, `make`, to get properly installed and running and run, etc. You do need a C compiler, like gcc.

The **first time** you need to build libcrypto777.a and to do that you need to run:

For unix: ```./m_onetime m_unix```

For osx: ```./m_onetime m_osx```

For win32: ```./m_onetime m_win32```

For win64: ```./m_onetime m_win64```

#(RE)BUILD

Once libcrypto777.a is built, you can build the agents.

For pnacl: ```cd crypto777; make clean; make; cd ../iguana; make clean; make```

For unix: ```./m_unix```

For osx: ```./m_osx```

For win32: ```./m_win32```

For win64: ```./m_win64```


The m_(OS) is a standard I follow and should be self explanatory. within each is usually just a few lines, ie compile all the .c files and link with the standard libs.

To build just iguana, you can ```cd``` into SuperNET/iguana and do ```./m_unix``` (or ```./m_osx```, ...).

```./m_clean``` will remove the files created from the building

#RUNNING#

The native versions are command line applications: agents/iguana {JSON}
The chrome app pexe requires that the chrome is launched with a command line parameter (tools/chrome.localhost) and then browse to *http://127.0.0.1:7777* to see the pexe

#SUPERUGLYGUI#

Once iguana is running, you can see the superuglyGUI at *http://127.0.0.1:7778/?method*
by submitting API calls using the forms, you will see it go to some specific URL. You can also do a programmatic GET request to ```http://127.0.0.1:7778/api/<path to apicall>```

*http://127.0.0.1:7778/ramchain/block/height/0* -> full webpage

*http://127.0.0.1:7778/json/ramchain/block/height/0* -> JSON only

```curl --url "http://127.0.0.1:7778/ramchain/BTCD/block/height/0"``` --> full webpage returned (probably not what you want)
```curl --url "http://127.0.0.1:7778/api/ramchain/BTCD/block/height/0"``` --> returns just the json object from the api call

Internally, all paths convert the request into a standard SuperNET JSON request. you can use a POST command to directly submit such JSON requests:
```curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"ramchain\",\"method\":\"block\",\"coin\":\"BTCD\",\"height\":0}"```

Another approach is to use the bitcoin RPC syntax via:
 curl --url "http://127.0.0.1:7778" --data "{\"coin\":\"BTCD\",\"method\":\"getinfo\",\"params\":[]}"
the params:[] array is where the standard bitcoin parameters go, the only change that is needed is to specify the coin
alternatively {"agent":"SuperNET","method":"bitcoinrpc","coin":"BTCD"} will set the coin 
to use for bitcoin RPC calls. this will suffice in single coin environments

curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"iguana",\"method\":\"test\"}"
curl --url "http://127.0.0.1:7778/iguana/test" -> html page with results
curl --url "http://127.0.0.1:7778/api/iguana/test" -> just json text
http://127.0.0.1:7778 -> superugly GUI
http://127.0.0.1:7778/iguana/test 
http://127.0.0.1:7778/api/iguana/test
postCall('{"agent":"iguana","method":"test"}'}
iguana_JSON("{\"agent\":\"iguana",\"method\":\"test\"}"); -> direct C function call


iguana can be invoked with a command line argument. if it is a name of a file, it will load it and check to see if it is valid JSON and if it is, it will use it. Otherwise the command line argument needs to be valid JSON to be used and it will process the JSON to initialize account passphrases, exchange apikeys, etc. A few special keys:

"wallet" -> passphrase used for the persistent privkey
"2fafile" -> secondary part (optional) for the persistent privkey
"numhelpers" -> number of helper threads (need at least 1)
"exchanges" -> { "name":"<name of exchange>", ... }
    "apikey", "apisecret", "userid", "tradepassword" these are as expected
    "pollgap" -> gap between each access to exchange for getting prices

######
The goal for iguana is to create a scalable bitcoin core implementation that is backward compatible and a drop in replacement, so all the RPC needs to be implemented in addition to peer messaging, blockchain, scripts, wallet, etc.

The first thing you notice when looking at the raw blockchain is that there is a LOT of redundancy, so by mapping the high entropy hashes to a 32bit integer, you get a 28 byte savings for each use. For a txid with N outputs, that is up to N*28 bytes that would be saved as each vin refers to the txid.

Since the blockchain has an implicit ordering, it is possible to create a canonical numbering for the txid, vouts, vins, and this will allow syncing the iguana files to save gobs of bandwidth. However both endian formats need to be put into the bittorrent network as the iguana files are designed to be directly memory mapped. This allows skipping of serialization/deserialization of each and every multibyte field. Since the files are less than half the size, even with the doubling due to both endian forms, it is still less overall data than the raw blockchain.

bitfields are used, so that means a standard way of allocating the bits needs to be used by each compiler. gcc and clang use the same method, so as long as it is compiled with those or one with compatible bitfield allocation, the memory mapped files should work.

The most space is used by the vout, vin, pkhash structures, as there are a lot more vouts than txids. The txid structure has not been fully optimized, but since it is less than 1% of overall space, I felt it was not worth making it more complicated to save few bytes. The pkhash is the pubkey hash rmd160(sha256(pubkey)) and this is the most efficient way to index the blockchain as all vout scripts generate a rmd160[20] either implicitly for the scripts with pubkey, pay to pubkey hash standard script and all the new p2sh scripts. Another reason to use rmd160 is that it makes it easy to convert to the equivalent addresses for other coins, ie. all coins have the same rmd160 even if the coin addresses are different due to the address type byte added to the base58 conversion.

The following are the second pass data structures that are created from a batch of raw structures in groups of 2000 (the size of the getheaders). The design needs to meet many constraints, primarily to be as small as possible without sacrificing speed and to be able to work in a parallel sync. That means that each block or bundle needs to be as self-contained as possible, but have external references that can be resolved. This is similar to object files and linkers. The main thing that has these external references are the vins.

I tried quite a few variations before settling on this. Earlier versions combined everything into a single dataset, which is good for making searches via hashtable really fast, but with the ever growing size of the blockchain not very scalable. The maximum size of 2000 blocks is 2GB right now and at that size there is no danger of overflowing any 32bit offset, but for the most part, the 32bit indexes are of the item, so it can represent much larger than 4GB.

iguana doesnt use any DB as that is what causes most of the bottlenecks and since the data doesnt change (after 20 blocks), a DB is just overkill. Using the memory mapped file approach, it takes no time to initialize the data structures, but certain operations take linear time relative to the number of bundles. Achieving this performance requires constant time performance for all operations within a bundle. Since most bundles will not have the hash that is being searched for, I used a bloom filter to quickly determine which bundles need to be searched deeper. For the deeper searches, there is a open hashtable that always has good performance as it is sized so it is one third empty. Since the total number of items is known and never changes, both the bloom filters and hashtable never change after initial creation.

What this means is that on initialization, you memory map the 200 bundles and in the time it takes to do that (less than 1sec), you are ready to query the dataset. Operations like adding a privkey takes a few milliseconds, since all the addresses are already indexed, but caching all the transactions for an address is probably not even necessary for a single user wallet use case. However for dealing with thousands of addresses, it would make sense to cache the lists of transactions to save the few milliseconds per address.

You might be wondering how is it even possible to have an append only dataset that allows traversing the entire blockchain and searching for all transactions from a specific address. Note that by indexing at the rmd160 level, there is no difference between a multisig address and a normal address and so all the operations work equally for any address, be it pubkey, pubkeyhash, multisig or p2sh.

With 200 bundles and millions of unspents per bundle recently, it would be easy to have things take a long time to iterate through and find all references to a specific address. What I realized was that during a single pass I can update an arbitrary number of linked lists, one for each rmd160. However it needs to work backwards so you never need to change any previous entry. As soon as an unspent is created, it is final and never changes. It does require a single dynamic data structure for the account which keeps track of the balance (just the sum of outputs) and the last unspentind. As new unspents are made to the same address, it links back to the prior one and updates the total balance.

To get the list of all transactions, all bundles need to be queried. For each bundle, constant time hash lookups find the last access and then iterating backwards to the first occurance finds all unspents in the bundle. So it is linear time relative to the total number of unspents that an address has with a small 200 constant time operations overhead. As the number of bundles grows, this will continue to increase, but it is always possible to make a single lookup table that spans the entire set of bundles, so I am not worried about scaling things up. Note that the parallel nature of all the bundles makes using multiple cores for all the searches relatively easy, so speedups of N using N cores is not much work.

I could probably get rid of the firstunspentind in the pkhash struct, but it is there to provide an error check when iterating backwards on the linked list. the pubkeyoffset is also optional, but I find it handy to be able to know what pubkey maps to the rmd160 for a variety of use cases and I am on the fence as to whether to make it purgeable or not.

I had to make the signatures from the vinscripts purgeable as I dont seem much use for them after a node has validated an input other than relaying the raw block to other nodes. Without the sigs, a node can still be totally self-sufficient when creating new transactions and the sigs are high entropy and unique and is approx equal to the uncompressed size of everything else! The pubkeys are much smaller, especially due to address reuse within a bundle, which only takes up 4 bytes. It is probably worth adding a way to purge the pubkeys at some point, but the method I used to enable signature pruning was to create a stack that grows down to put the signatures into during processing the each block. There is also a forward growing data store where all the things that cant be encoded in the baseline structures are put into. 

It is necessary to used an upfront memory allocation as doing hundreds of millions of malloc/free is a good way to slow things down, especially when there are many threads. Using the onetime allocation, cleanup is guaranteed to not leave any stragglers as a single free releases all memory. After all the blocks in the bundle are processed, there will be a gap between the end of the forward growing data called Kspace and the reverse growing stack for the sigs, so before saving to disk, the sigs are moved to remove the gap. At this point it becomes clear why it had to be a reverse growing stack. I dont want to have to make another pass through the data after moving the signatures and by using negative offsets relative to the top of the stack, there is no need to change any of the offsets used for the signatures.

Most of the unspents use standard scripts so usually the script offset is zero. However this doesnt take up much room at all as all this data is destined to be put into a compressed filesystem, like squashfs, which cuts the size in about half. Not sure what the compressed size will be with the final iteration, but last time with most of the data it was around 12GB, so I think it will end up around 15GB compressed and 25GB uncompressed.

Each bundle file will have the following order:
[<txid> <vouts> <vins>][nonstandard scripts and other data] ... gap ... [signatures]
after saving it the gap goes away. Since the signatures are at the end, it is possible to truncate each bundle file to dramatically reduce its size. It would save a lot of time compressing the files without the signatures as they are high entropy and dont compress, but having them in a different file would really complicate the code. Not that it isnt already quite complicated.

I realize totally replace all the DB is rather radical, but it was the only way possible to achieve a parallel sync that streams data in at bandwidth saturation speeds. In order to validate the dataset, which is clearly required before any production use of a DB replacement, I decided to put in the extra effort to make iguana able to act as a lossless codec. This would allow verification at the rawtx bytes level with a simple loop that iterates across all blocks and all tx within a block to verify that all txbytes match against what bitcoind returns.

Of course, since bitcoind wont be able to even calculate balances for all addresses without enabling watching all addresses, I dont know a practical way to verify that all the balance calculations are correct. 

Here are the fundamental data structures and the total size for each is not a typo, it really is 64 bytes for txid, 28 bytes per unspent, 12 bytes per spend and 32 bytes per pkhash and 12 bytes for account balance and end of linked list. But things are even smaller! Each unspent has a unique unspentind within each bundle, so you can have a list of all the unspents that takes up 4 bytes per unspent + 4bytes per bundle it appears in.

I havent optimized the utxo handling yet, but the plan is to calculate an overlay vector of all unspents that are spent for each bundle. This too is a static dataset, but it cant be calculated until all prior bundles are present due to all external references needing to be resolved. This final step would happen as the mainchain is validated linearly as the parallel sync is proceeding. For simplicity I will also verify all the signatures during this last pass.

At that point, to create the current utxo at any bundle boundary, it is a matter to OR all the spend vectors. That brings all the data current to the most recent bundle, which might be 1 or 1999 blocks in the past. So the final block will need to be special cased to allow it to be searched before it is in final form.

I think that covers most of the basics. 

struct iguana_txid // 64 bytes
{ 
    bits256 txid; 
    uint32_t txidind,firstvout,firstvin,locktime,version,timestamp,extraoffset;
    uint16_t numvouts,numvins; 
} __attribute__((packed));

struct iguana_unspent // 28 bytes
{ 
    uint64_t value; 
    uint32_t txidind,pkind,prevunspentind,scriptoffset; 
    uint16_t hdrsi:12,type:4,vout;
 } __attribute__((packed));

struct iguana_spend  // 12 bytes
{ 
    uint32_t spendtxidind,scriptoffset;
    int16_t prevout; 
    uint16_t numsigs:4,numpubkeys:4,p2sh:1,sighash:4,external:1,sequenceid:2;
 } __attribute__((packed));

struct iguana_pkhash // 32 bytes
{ 
    uint8_t rmd160[20]; 
    uint32_t pkind,firstunspentind,pubkeyoffset;
} __attribute__((packed));

// dynamic during bundle creation
struct iguana_account // 12 bytes
{ 
    uint64_t balance; uint32_t lastunspentind; 
} __attribute__((packed)); // pkind

# Cmake build of marketmaker with linked etomic lib for ETH/ERC20 atomic swaps:
1. Clone this repository.
1. `git checkout etomic`
1. `git submodule update --init --recursive`
1. `mkdir build`
1. `cd build`
1. `cmake ..`
1. `cmake --build . --target marketmaker`
1. `cd exchanges/iguana`
1. `export BOB_PK=YOUR_PRIVATE_KEY`
1. `./marketmaker`