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

#ifdef _IGUANA_APIDEC_H_
emit compiler error if recursively being included
#endif
#ifndef _IGUANA_APIDEC_H_
#define _IGUANA_APIDEC_H_

STRING_ARG(dpow,pending,fiat);
STRING_AND_TWOINTS(dpow,notarizations,symbol,height,numblocks);
ZERO_ARGS(dpow,notarychains);
STRING_ARG(dpow,active,maskhex);
TWOINTS_AND_ARRAY(dpow,ratify,minsigs,timestamp,ratified);
ZERO_ARGS(dpow,cancelratify);
STRING_ARG(dpow,bindaddr,ipaddr);
STRING_AND_INT(dpow,fundnotaries,symbol,numblocks);

ZERO_ARGS(pax,start);
INT_ARG(passthru,paxfiats,mask);
TWO_STRINGS(zcash,passthru,function,hex);
TWO_STRINGS(komodo,passthru,function,hex);
TWO_STRINGS(dex,kvsearch,symbol,key);
THREE_STRINGS_AND_THREE_INTS(dex,kvupdate,symbol,key,value,flags,unused,unusedb);

TWO_STRINGS(dex,send,hex,handler);
HASH_AND_STRING(dex,gettransaction,txid,symbol);
STRING_ARG(dex,getinfo,symbol);
STRING_ARG(dex,getnotaries,symbol);
STRING_ARG(dex,alladdresses,symbol);
STRING_ARG(dex,getbestblockhash,symbol);
STRING_AND_INT(dex,getblockhash,symbol,height);
HASH_AND_STRING(dex,getblock,hash,symbol);
TWO_STRINGS(dex,sendrawtransaction,symbol,signedtx);
HASH_AND_STRING_AND_INT(dex,gettxout,txid,symbol,vout);
TWO_STRINGS(dex,importaddress,symbol,address);
TWO_STRINGS(dex,validateaddress,symbol,address);
TWO_STRINGS(dex,checkaddress,symbol,address);
TWO_STRINGS(dex,listunspent,symbol,address);
TWO_STRINGS_AND_TWO_DOUBLES(dex,listtransactions,symbol,address,count,skip);
TWO_STRINGS(dex,listunspent2,symbol,address);
TWO_STRINGS_AND_TWO_DOUBLES(dex,listtransactions2,symbol,address,count,skip);
HASH_AND_STRING_AND_INT(dex,gettxin,txid,symbol,vout);
TWO_STRINGS(dex,listspent,symbol,address);
TWO_STRINGS(dex,getbalance,symbol,address);
STRING_ARG(dex,explorer,symbol);
STRING_ARG(dex,getmessage,argstr);
STRING_ARG(dex,psock,argstr);

HASH_ARRAY_STRING(basilisk,genesis_opreturn,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,history,hash,vals,hexstr);
INT_ARG(basilisk,paxfiats,mask);
HASH_ARRAY_STRING(basilisk,balances,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,value,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,rawtx,hash,vals,hexstr);
TWO_STRINGS(basilisk,refresh,symbol,address);
ZERO_ARGS(basilisk,cancelrefresh);
STRING_ARRAY_OBJ_STRING(basilisk,utxorawtx,symbol,utxos,vals,ignore);
HASH_ARRAY_STRING(basilisk,utxocombine,ignore,vals,symbol);

HASH_ARRAY_STRING(basilisk,getmessage,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,sendmessage,hash,vals,hexstr);

HASH_ARRAY_STRING(basilisk,geckoheaders,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,geckoblock,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,geckotx,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,geckoget,hash,vals,hexstr);

HASH_ARRAY_STRING(basilisk,addrelay,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,dispatch,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,publish,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,subscribe,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,forward,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,mailbox,hash,vals,hexstr);

/*HASH_ARRAY_STRING(basilisk,VPNcreate,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,VPNjoin,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,VPNmessage,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,VPNbroadcast,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,VPNreceive,hash,vals,hexstr);
HASH_ARRAY_STRING(basilisk,VPNlogout,hash,vals,hexstr);

HASH_ARRAY_STRING(basilisk,vote,hash,vals,hexstr);*/

ZERO_ARGS(bitcoinrpc,getinfo);
ZERO_ARGS(bitcoinrpc,getblockcount);
ZERO_ARGS(bitcoinrpc,getdifficulty);
ZERO_ARGS(bitcoinrpc,getbestblockhash);
INT_ARG(bitcoinrpc,getblockhash,height);
HASH_AND_TWOINTS(bitcoinrpc,getblock,blockhash,verbose,remoteonly);

HASH_AND_INT(bitcoinrpc,getrawtransaction,txid,verbose);
HASH_ARG(bitcoinrpc,gettransaction,txid);
HASH_AND_TWOINTS(bitcoinrpc,gettxout,txid,vout,mempool);
TWOINTS_AND_ARRAY(bitcoinrpc,listunspent,minconf,maxconf,array);

STRING_ARG(bitcoinrpc,decodescript,scriptstr);
//STRING_ARG(bitcoinrpc,decoderawtransaction,rawtx);
STRING_AND_INT(bitcoinrpc,decoderawtransaction,rawtx,suppress);
STRING_AND_INT(bitcoinrpc,validaterawtransaction,rawtx,suppress);
ARRAY_OBJ_INT(bitcoinrpc,createrawtransaction,vins,vouts,locktime);

STRING_ARG(bitcoinrpc,validatepubkey,pubkey);
STRING_ARG(bitcoinrpc,validateaddress,address);

ZERO_ARGS(bitcoinrpc,walletlock);
TWOSTRINGS_AND_INT(bitcoinrpc,walletpassphrase,password,permanentfile,timeout);
THREE_STRINGS(bitcoinrpc,encryptwallet,passphrase,password,permanentfile);
FOUR_STRINGS(bitcoinrpc,walletpassphrasechange,oldpassword,newpassword,oldpermanentfile,permanentfile);
STRING_ARG(bitcoinrpc,dumpwallet,filename);
STRING_ARG(bitcoinrpc,backupwallet,filename);
STRING_ARG(bitcoinrpc,importwallet,filename);
STRING_ARG(bitcoinrpc,getnewaddress,account);
TWOSTRINGS_AND_INT(bitcoinrpc,importprivkey,wif,account,rescan);
TWOSTRINGS_AND_INT(bitcoinrpc,importaddress,address,account,rescan);
STRING_ARG(bitcoinrpc,dumpprivkey,address);

STRING_AND_THREEINTS(bitcoinrpc,listtransactions,account,count,skip,includewatchonly);
THREE_INTS(bitcoinrpc,listreceivedbyaddress,minconf,includeempty,flag);
THREE_INTS(bitcoinrpc,listreceivedbyaccount,confirmations,includeempty,watchonly);
TWO_INTS(bitcoinrpc,listaccounts,minconf,includewatchonly);
ZERO_ARGS(bitcoinrpc,listaddressgroupings);
STRING_AND_INT(bitcoinrpc,getreceivedbyaddress,address,minconf);
STRING_AND_INT(bitcoinrpc,getreceivedbyaccount,account,includeempty);
STRING_AND_THREEINTS(bitcoinrpc,getbalance,account,confirmations,includeempty,lastheight);
STRING_ARG(bitcoinrpc,getaddressesbyaccount,account);
STRING_ARG(bitcoinrpc,getaccount,address);
STRING_ARG(bitcoinrpc,getaccountaddress,account);
TWO_STRINGS(bitcoinrpc,setaccount,address,account);

INT_ARRAY_STRING(bitcoinrpc,createmultisig,M,pubkeys,ignore);
INT_ARRAY_STRING(bitcoinrpc,addmultisigaddress,M,pubkeys,account);
DOUBLE_ARG(bitcoinrpc,settxfee,amount);

ZERO_ARGS(bitcoinrpc,checkwallet);
ZERO_ARGS(bitcoinrpc,repairwallet);

STRING_ARRAY_OBJ_STRING(bitcoinrpc,signrawtransaction,rawtx,vins,privkeys,sighash);
TWO_STRINGS(bitcoinrpc,signmessage,address,message);
THREE_STRINGS(bitcoinrpc,verifymessage,address,sig,message);
STRING_AND_INT(bitcoinrpc,sendrawtransaction,rawtx,allowhighfees);

SS_D_I_SS(bitcoinrpc,sendfrom,fromaccount,toaddress,amount,minconf,comment,comment2);
S_A_I_S(bitcoinrpc,sendmany,fromaccount,payments,minconf,comment);
S_D_SS(bitcoinrpc,sendtoaddress,address,amount,comment,comment2);
INT_AND_ARRAY(bitcoinrpc,lockunspent,flag,array); //
ZERO_ARGS(bitcoinrpc,listlockunspent); //
STRING_ARG(bitcoinrpc,submitblock,rawbytes); //

// maybe later
HASH_AND_TWOINTS(bitcoinrpc,listsinceblock,blockhash,target,flag);
ZERO_ARGS(bitcoinrpc,gettxoutsetinfo);
ZERO_ARGS(bitcoinrpc,getrawchangeaddress);
SS_D_I_S(bitcoinrpc,move,fromaccount,toaccount,amount,minconf,comment);

THREE_INTS(iguana,splitfunds,satoshis,duplicates,sendflag);
ZERO_ARGS(iguana,makekeypair);
INT_AND_ARRAY(iguana,rates,unused,quotes);
TWO_STRINGS(iguana,rate,base,rel);
THREE_STRINGS_AND_THREE_INTS(iguana,prices,exchange,base,rel,period,start,end);
STRING_AND_INT(iguana,snapshot,symbol,height);
INT_ARRAY_STRING(iguana,dividends,height,vals,symbol);
THREE_STRINGS(iguana,passthru,asset,function,hex);
STRING_ARG(iguana,initfastfind,activecoin);
THREE_STRINGS_AND_DOUBLE(iguana,dpow,symbol,dest,pubkey,freq);
STRING_ARG(iguana,peers,activecoin);
STRING_AND_INT(iguana,maxpeers,activecoin,max);
STRING_ARG(iguana,getconnectioncount,activecoin);
STRING_ARG(iguana,addcoin,newcoin);
STRING_ARG(iguana,validate,activecoin);
STRING_ARG(iguana,removecoin,activecoin);
STRING_ARG(iguana,startcoin,activecoin);
STRING_ARG(iguana,pausecoin,activecoin);
STRING_ARG(iguana,stopcoin,activecoin);
TWO_STRINGS(iguana,addnode,activecoin,ipaddr);
STRING_ARG(iguana,addnotary,ipaddr);
TWO_STRINGS(iguana,persistent,activecoin,ipaddr);
TWO_STRINGS(iguana,removenode,activecoin,ipaddr);
TWO_STRINGS(iguana,oneshot,activecoin,ipaddr);
TWO_STRINGS(iguana,nodestatus,activecoin,ipaddr);
TWO_STRINGS_AND_TWO_DOUBLES(iguana,balance,activecoin,address,heightd,minconfd);
P2SH_SPENDAPI(iguana,spendmsig,activecoin,vintxid,vinvout,destaddress,destamount,destaddress2,destamount2,M,N,pubA,wifA,pubB,wifB,pubC,wifC);
STRING_AND_INT(iguana,bundleaddresses,activecoin,height);
STRING_AND_INT(iguana,bundlehashes,activecoin,height);
STRING_AND_INT(iguana,PoSweights,activecoin,height);
STRING_ARG(iguana,stakers,activecoin);

STRING_ARG(jumblr,setpassphrase,passphrase);
ZERO_ARGS(jumblr,status);
ZERO_ARGS(jumblr,runsilent);
ZERO_ARGS(jumblr,totransparent);

ZERO_ARGS(InstantDEX,allcoins);
STRING_ARG(InstantDEX,available,source);
HASH_ARRAY_STRING(InstantDEX,request,hash,vals,hexstr);
INT_ARG(InstantDEX,incoming,requestid);
INT_ARG(InstantDEX,automatched,requestid);
TWO_INTS(InstantDEX,accept,requestid,quoteid);
//TWO_INTS(InstantDEX,swapstatus,requestid,quoteid);
//TWO_STRINGS_AND_TWO_DOUBLES(InstantDEX,minaccept,base,rel,minprice,basevolume);
//TWO_STRINGS_AND_TWO_DOUBLES(InstantDEX,maxaccept,base,rel,maxprice,basevolume);
THREE_STRINGS_AND_THREE_DOUBLES(InstantDEX,buy,exchange,base,rel,price,volume,dotrade);
THREE_STRINGS_AND_THREE_DOUBLES(InstantDEX,sell,exchange,base,rel,price,volume,dotrade);
THREE_STRINGS_AND_DOUBLE(InstantDEX,withdraw,exchange,base,destaddr,amount);
THREE_STRINGS(InstantDEX,apikeypair,exchange,apikey,apisecret);
THREE_STRINGS(InstantDEX,setuserid,exchange,userid,tradepassword);
TWO_STRINGS(InstantDEX,balance,exchange,base);
TWO_STRINGS(InstantDEX,orderstatus,exchange,orderid);
TWO_STRINGS(InstantDEX,cancelorder,exchange,orderid);
STRING_ARG(InstantDEX,openorders,exchange);
STRING_ARG(InstantDEX,tradehistory,exchange);
THREE_STRINGS_AND_THREE_INTS(InstantDEX,orderbook,exchange,base,rel,depth,allfields,ignore);
STRING_AND_INT(InstantDEX,pollgap,exchange,pollgap);
//TWO_STRINGS(InstantDEX,events,base,rel);
ZERO_ARGS(InstantDEX,allexchanges);
STRING_ARG(InstantDEX,allpairs,exchange);
THREE_STRINGS(InstantDEX,supports,exchange,base,rel);
ZERO_ARGS(InstantDEX,init);
ZERO_ARGS(InstantDEX,getswaplist);
ZERO_ARGS(InstantDEX,smartaddresses);
TWO_STRINGS_AND_TWO_DOUBLES(InstantDEX,smartaddress,type,symbol,maxbid,minask);
DOUBLE_ARG(InstantDEX,DEXratio,ratio);

//THREE_STRINGS(atomic,approve,myorderid,otherid,txname);
//THREE_STRINGS(atomic,claim,myorderid,otherid,txname);

//TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(InstantDEX,proposal,reference,message,basetxid,reltxid,duration,flags);
//TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(InstantDEX,accept,reference,message,basetxid,reltxid,duration,flags);
//TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(InstantDEX,confirm,reference,message,basetxid,reltxid,baseheight,relheight);

HASH_ARRAY_STRING(tradebot,liquidity,hash,vals,targetcoin);
STRING_ARG(tradebot,amlp,blocktrail);
ZERO_ARGS(tradebot,notlp);
TWO_STRINGS(tradebot,gensvm,base,rel);
ZERO_ARGS(tradebot,openliquidity);
THREE_STRINGS_AND_DOUBLE(tradebot,aveprice,comment,base,rel,basevolume);
THREE_STRINGS_AND_DOUBLE(tradebot,monitor,exchange,base,rel,commission);
STRING_AND_DOUBLE(tradebot,monitorall,exchange,commission);
THREE_STRINGS(tradebot,unmonitor,exchange,base,rel);
THREE_STRINGS_AND_THREE_DOUBLES(tradebot,accumulate,exchange,base,rel,price,volume,duration);
THREE_STRINGS_AND_THREE_DOUBLES(tradebot,divest,exchange,base,rel,price,volume,duration);
STRING_ARG(tradebot,activebots,exchange);
TWO_STRINGS(tradebot,status,exchange,botid);
TWO_STRINGS(tradebot,pause,exchange,botid);
TWO_STRINGS(tradebot,stop,exchange,botid);
TWO_STRINGS(tradebot,resume,exchange,botid);
ZERO_ARGS(tradebot,allbalances);
ZERO_ARGS(tradebot,anchor);
ZERO_ARGS(tradebot,portfolio);
ARRAY_OBJ_INT(tradebot,goals,currencies,vals,targettime);

#ifndef WIN32
/*HASH_ARG(pangea,call,tablehash);
HASH_AND_INT(pangea,raise,tablehash,numchips);
HASH_AND_INT(pangea,bet,tablehash,numchips);
HASH_ARG(pangea,check,tablehash);
HASH_ARG(pangea,fold,tablehash);
HASH_ARG(pangea,allin,tablehash);
HASH_ARG(pangea,status,tablehash);
HASH_AND_STRING(pangea,mode,tablehash,params);
HASH_ARG(pangea,history,tablehash);
HASH_AND_INT(pangea,handhistory,tablehash,hand);
INT_AND_ARRAY(pangea,host,minplayers,params);
ZERO_ARGS(pangea,lobby);
HASH_AND_STRING(pangea,join,tablehash,handle);
HASH_AND_INT(pangea,buyin,tablehash,numchips);
HASH_ARG(pangea,start,tablehash);*/
#endif

ZERO_ARGS(SuperNET,help);
STRING_ARG(SuperNET,utime2utc,utime);
INT_ARG(SuperNET,utc2utime,utc);
STRING_ARG(SuperNET,getpeers,activecoin);
TWO_ARRAYS(SuperNET,mypeers,supernet,rawpeers);
ZERO_ARGS(SuperNET,stop);
HASH_AND_STRING(SuperNET,saveconf,wallethash,confjsonstr);
HASH_ARRAY_STRING(SuperNET,layer,mypriv,otherpubs,str);

STRING_ARG(SuperNET,bitcoinrpc,setcoin);
STRING_ARG(SuperNET,myipaddr,ipaddr);
STRING_ARG(SuperNET,setmyipaddr,ipaddr);

FOUR_STRINGS(SuperNET,login,handle,password,permanentfile,passphrase);
ZERO_ARGS(SuperNET,logout);
ZERO_ARGS(SuperNET,activehandle);
THREE_STRINGS(SuperNET,encryptjson,password,permanentfile,payload);
TWO_STRINGS(SuperNET,decryptjson,password,permanentfile);

TWO_STRINGS(SuperNET,html,agentform,htmlfile);
//TWOSTRINGS_AND_TWOHASHES_AND_TWOINTS(SuperNET,DHT,hexmsg,destip,categoryhash,subhash,maxdelay,broadcast);

THREE_STRINGS(SuperNET,rosetta,passphrase,pin,showprivkey);
ZERO_ARGS(SuperNET,keypair);
HASH_AND_INT(SuperNET,priv2pub,privkey,addrtype);
STRING_ARG(SuperNET,wif2priv,wif);
STRING_AND_INT(SuperNET,priv2wif,priv,wiftype);
STRING_ARG(SuperNET,addr2rmd160,address);
STRING_ARG(SuperNET,rmd160conv,rmd160);

TWOHASHES_AND_STRING(SuperNET,cipher,privkey,destpubkey,message);
TWOHASHES_AND_STRING(SuperNET,decipher,privkey,srcpubkey,cipherstr);

STRING_ARG(SuperNET,broadcastcipher,message);
STRING_ARG(SuperNET,broadcastdecipher,message);

HASH_AND_STRING(SuperNET,multicastcipher,pubkey,message);
HASH_AND_STRING(SuperNET,multicastdecipher,privkey,cipherstr);

/*TWO_STRINGS(SuperNET,subscribe,category,subcategory);
TWO_STRINGS(SuperNET,gethexmsg,category,subcategory);
THREE_STRINGS(SuperNET,posthexmsg,category,subcategory,hexmsg);
THREE_STRINGS(SuperNET,announce,category,subcategory,message);
THREE_STRINGS(SuperNET,survey,category,subcategory,message);
TWO_STRINGS(SuperNET,categoryhashes,category,subcategory);*/

STRING_AND_TWOINTS(mouse,image,name,x,y);
STRING_AND_TWOINTS(mouse,change,name,x,y);
STRING_AND_TWOINTS(mouse,click,name,x,y);
STRING_ARG(mouse,close,name);
STRING_ARG(mouse,leave,name);
STRING_AND_INT(keyboard,key,name,c);

STRING_ARG(hash,hex,message);
STRING_ARG(hash,unhex,hexmsg);
TWO_HASHES(hash,curve25519_pair,element,scalar);
STRING_ARG(hash,NXT,passphrase);
STRING_ARG(hash,curve25519,pubkey);
STRING_ARG(hash,crc32,message);
STRING_ARG(hash,base64_encode,message);
STRING_ARG(hash,base64_decode,message);
STRING_ARG(hash,rmd160_sha256,message);
STRING_ARG(hash,sha256_sha256,message);

#ifndef WIN32

STRING_ARG(hash,sha224,message);
STRING_ARG(hash,sha256,message);
STRING_ARG(hash,sha384,message);
STRING_ARG(hash,sha512,message);
STRING_ARG(hash,rmd128,message);
STRING_ARG(hash,rmd160,message);
STRING_ARG(hash,rmd256,message);
STRING_ARG(hash,rmd320,message);
STRING_ARG(hash,sha1,message);
STRING_ARG(hash,md2,message);
STRING_ARG(hash,md4,message);
STRING_ARG(hash,md5,message);
STRING_ARG(hash,tiger192_3,message);
STRING_ARG(hash,whirlpool,message);

TWO_STRINGS(hmac,sha224,message,passphrase);
TWO_STRINGS(hmac,sha256,message,passphrase);
TWO_STRINGS(hmac,sha384,message,passphrase);
TWO_STRINGS(hmac,sha512,message,passphrase);
TWO_STRINGS(hmac,rmd128,message,passphrase);
TWO_STRINGS(hmac,rmd160,message,passphrase);
TWO_STRINGS(hmac,rmd256,message,passphrase);
TWO_STRINGS(hmac,rmd320,message,passphrase);
TWO_STRINGS(hmac,sha1,message,passphrase);
TWO_STRINGS(hmac,md2,message,passphrase);
TWO_STRINGS(hmac,md4,message,passphrase);
TWO_STRINGS(hmac,md5,message,passphrase);
TWO_STRINGS(hmac,tiger192_3,message,passphrase);
TWO_STRINGS(hmac,whirlpool,message,passphrase);

#endif

#endif
