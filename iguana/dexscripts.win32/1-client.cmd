@echo off
set USERHOME=%APPDATA:\=\\%
rem [!] Coins config now taked from coins.json file, no need to put in environment variable
rem ---------------------------------------------------------------------------------------
rem set COINS=[{\"coin\":\"REVS\",\"active\":1,\"asset\":\"REVS\",\"rpcport\":10196}]
rem marketmaker "{\"gui\":\"nogui\",\"client\":1, \"userhome\":\"%USERHOME%\", \"passphrase\":\"mypassphrase\", \"coins\":%COINS%}"

set COINS=\"\"
rem set /p PASSPHRASE=<passphrase
rem , \"canbind\":1
rem marketmaker "{\"gui\":\"nogui\",\"client\":1, \"userhome\":\"%USERHOME%\", \"passphrase\":\"%PASSPHRASE%\"}" 1> marketmaker.log 2>&1
rem marketmaker "{\"gui\":\"nogui\",\"client\":1, \"userhome\":\"%USERHOME%\", \"passphrase\":\"%PASSPHRASE%\"}" 1> marketmaker.log 2>&1

rem echo "{\"gui\":\"nogui\",\"client\":1, \"userhome\":\"%USERHOME%\", \"passphrase\":\"%PASSPHRASE%\"}" 
rem marketmaker "{\"gui\":\"nogui\",\"client\":1, \"userhome\":\"%USERHOME%\", \"passphrase\":\"%PASSPHRASE%\"}" 

marketmaker "{\"gui\":\"nogui\",\"client\":1, \"userhome\":\"%USERHOME%\",\"passphrase\":\"default\"}" 





