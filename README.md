# SuperNET Client "iguana"

OS | Build Status 
-------------|------
Unix (Ubuntu 14.04) | [![Build Status](https://jenkinsmaster.sprnt.pw/buildStatus/icon?job=iguana-unix-jl777-release-v0.1)](https://jenkinsmaster.sprnt.pw/job/iguana-unix-jl777-release-v0.1)
Chrome | [![Build Status](https://jenkinsmaster.sprnt.pw/buildStatus/icon?job=iguana-pnacl-jl777-release-v0.1)](https://jenkinsmaster.sprnt.pw/job/iguana-pnacl-jl777-release-v0.1/)
Android | [![Build Status](https://jenkinsmaster.sprnt.pw/buildStatus/icon?job=iguana-android-jl777-release-v0.1)](https://jenkinsmaster.sprnt.pw/job/iguana-android-jl777-release-v0.1/)
iOS | [![Build Status](https://jenkinsmaster.sprnt.pw/buildStatus/icon?job=iguana-ios-jl777-release-v0.1)](https://jenkinsmaster.sprnt.pw/job/iguana-ios-jl777-release-v0.1/)
Windows 32 Bit | [![Build Status](https://jenkinsmaster.sprnt.pw/job/iguana-win32-jl777-release-v0.1/badge/icon)](https://jenkinsmaster.sprnt.pw/job/iguana-win32-jl777-release-v0.1/)
Windows 64 Bit | [![Build Status](https://jenkinsmaster.sprnt.pw/job/iguana-win64-jl777-release-v0.1/badge/icon)](https://jenkinsmaster.sprnt.pw/job/iguana-win64-jl777-release-v0.1/)
docs.supernet.org | [![Build Status](https://jenkinsmaster.sprnt.pw/buildStatus/icon?job=docs.supernet.org-updating)](https://jenkinsmaster.sprnt.pw/job/docs.supernet.org-updating/)

---

Codebase is going under radical changes now and versions from mid-May should be used unless you are doing advanced testing. There will be four layers:

gecko: abstracted bitcoin compatible blockchains that run via basilisk lite mode or as iguana core full network peers. I will try to get a geckochain to simultaneously have both virtual basilisk nodes and private iguana nodes, but at first will probably need to choose which mode a new chain will be and transition between the two via special suspend and resume functions that allow migration from virtual to physical. Each specific geckochain will be able to be enhanced into a datachain.

basilisk: abstracted crypto transactions layer, which has a reference implementation for bitcoin protocol via the iguana nodes, but can be expanded to support any coin protocol that can support the required functions. Since it works with bitcoin protocol, any 2.0 coin with at least bitcoin level functionality should be able to create a basilisk interface.

iguana: most efficient bitcoin core implementation that can simultaneously be full peers for multiple bitcoin blockchains. Special support being added to virtualize blockchains so all can share the same peers. The iguana peers identify as a supernet node, regardless of which coin, so by having nodes that support multiple coins, supernet peers are propagated across all coins. non-iguana peers wont get any non-standard packets so it is interoperable with all the existing bitcoin and bitcoin clone networks

komodo: this is the top secret project I cant talk about publicly yet

> # TL;DR
>
> ```sudo apt-get update; sudo apt-get install git libcurl4-openssl-dev build-essential libnanomsg-dev; git clone https://github.com/jl777/SuperNET; cd SuperNET; ./m_onetime m_unix;```
>
> The above one line gets SuperNET installed, built and launched for unix.
>
> After that ```./m_unix``` updates to latest.
> *Continue below at "Running".*

**iguana is easy to build. Start by cloning (or downloading) this repository.**
*** all external dependencies have been removed, except for -lpthread and -lm


##For native (win32, win64)##
TOOL_DIR := /usr/local/gcc-4.8.0-qt-4.8.4-for-mingw32/win32-gcc/bin
MINGW := i586-mingw32
The above two definitions need to be changed to match the mingw install on your system. m_win32 and m_win64 just invokes the makefile in mingw32 and mingw64

## For chrome app
You need to make sure the nacl sdk is properly installed and you are able to build the examples.
Now you will need to get the external libs, which can be built from scratch using naclports or there use the reference builds of libcurl.a and libz.a in the SuperNET/crypto777/pnacl_libs. You can just copy those over into $(NACL_SDK_ROOT)/<pepper_dir>/lib/pnacl.

## For android
You have to build a native libnanomsg for android. This section is work in progress. Contact ca333@protonmail.ch for assistance on building latest iguana for android.

# ONETIME
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

# RUNNING

The native versions are command line applications: agents/iguana {JSON}
The chrome app pexe requires that the chrome is launched with a command line parameter (tools/chrome.localhost) and then browse to *http://127.0.0.1:7777* to see the pexe

# SUPERUGLYGUI

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

on OSX mksquashfs is not native, you will need to install fuse: https://osxfuse.github.io/ and a squashfs for mac: https://github.com/vasi/squashfuse

    **********
    user feedback:
    A Note on Installation from pebwindkraft at bitco.in
=======================
Though I had xcode installed, aclocal didn’t work. I installed homebrew, and then:
`brew install autoconf`
`brew install automake`
`brew install gmp`

2.) libsecp256
it complained, that libsecp256 was not there in includes, so I linked it.
Loretta:/Users/volker/SuperNET/includes # ln -s ../osx/libsecp256k1 .

3.) I had to change ulimit
During the syncing, I have many, many messages like this:
>>
>> cant create.(tmp/BTC/252000/.tmpmarker) errno.24 Too many open files
>> cant create.(tmp/BTC/18000/.tmpmarker) errno.24 Too many open files
>>
Loretta:/Users/volker/SuperNET # ulimit -n 100000


##### tests
in the SuperNET/iguana/tests directory, there is a jsoncmp.c file, which can be built into the jsoncmp executable via ./make_jsoncmp
once jsoncmp is built, then ./test shows how to use it
./jsoncmp <filename> {\"fields\":[{\"fieldA\":\"requiredvalueA\"},{\"fieldB\":\"requiredvalueB\"},...]}

the idea is to issue a curl command into a /tmp/file and then use jsoncmp to verify the exact value of one or more fields. it will print to stdout JSON with "error" or "result" and to stderr if there is an error

##### ../agents/iguana notary
0.Have iguana installed at http://wiki.supernet.org/wiki/How_To_Install_Iguana_on_Linux
also install nanomsg: sudo apt-get install libnanomsg-dev
ports 7775 will be used

cd Supernet/iguana -->

../agents/iguana

#In another SSH window:

cd Supernet/iguana/coins -->

./basilisk

1. Create an iguana wallet with encryptwallet and importprivkey into both komodod and bitcoind using the KMDwif and BTCwif in the encryptwallet result

curl --url "http://127.0.0.1:7778" --data "{\"agent\":\"bitcoinrpc\",\"method\":\"encryptwallet\",\"passphrase\":\"insert very secure password here\"}"

2. Go to SuperNET/iguana/

pico wp

curl --url "http://127.0.0.1:7778" --data "{\"method\":\"walletpassphrase\",\"params\":[\"same passphrase as above\", 9999999]}"

#Save the file then run the following command:

chmod +x wp

#Run the file

./wp

#Get the btcpubkey key from the output and give it to James.

3. create a text file SuperNET/iguana/myip.txt with just your ip address in it:

pico myip.txt

#Put your WAN IP of your node

4. create a text file with the user home dir in it:

pico userhome.txt
root

5. make a copy of SuperNET/iguana/wp -> SuperNET/iguana/wp_7776 and change port 7778 to port 7776

cp wp wp_7776
pico wp_7776

#Then change the port to 7776 from within the new file.

6. make a copy of SuperNET/iguana/tests/dpow_7776 to SuperNET/iguana/dpow_7776 and edit the pubkey to match your btcpubkey from above

cp dpow_7776 ../
pico dpow_7776

7. make sure system clock is synchronized
sudo service ntp stop
sudo ntpdate -s time.nist.gov
sudo service ntp start

Now things should be ready. To update and run notary node:
pkill iguana; ./m_LP; tests/notaryinit



##Build for OSX distribution##
Get OSX SDK 10.6 from https://github.com/ca333/MacOSX-SDKs/releases/tag/10.6

Unpack & move the .sdk folder to Xcodes SDK folder:

```cd DownloadDirectory```

```mv MacOSX10.6.sdk /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/.```

If you are using Xcode > 7.3 add the new SDK to XCode by changing MinimumSDKVersion in your Info.plist:

```vi /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Info.plist```

Change the value to:

```
<key>MinimumSDKVersion</key>
<string>10.6</string>
```
Build crypto777 library and agents with OSX release makefile:

```./m_onetime m_osx_release```

Execute the OSX deploy script:

```
./osx_deploy.sh
```
The iguana binary and its linked libraries are in ```$HOME/tmp/iguana```.

# Cmake build of marketmaker with linked etomic lib for ETH/ERC20 atomic swaps:
1. `make sure g++-7 ln to /usr/bin/g++`
1. `cd ~/SuperNET`
1. `git checkout dev`
1. `git submodule update --init --recursive`
1. `mkdir build`
1. `cd build`
1. `cmake ..`
1. `cmake --build . --target marketmaker-testnet` for Ropsten Ethereum testnet.
1. `cmake --build . --target marketmaker-mainnet` for Ethereum mainnet.
1. `cd build/iguana/exchanges`
1. `./marketmaker-testnet` or `./marketmaker-mainnet`
