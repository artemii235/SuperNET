@echo off
rem first time call to any method after started markemaker will return default userpass 1d8b27b21efabcd96571cd56f91a40fb9aa4cc623d273c63bf9223dc6f8cd81f
rem by-default userpass is 1d8b27b21efabcd96571cd56f91a40fb9aa4cc623d273c63bf9223dc6f8cd81f from "default" passphrase

rem first time call to marketmaker don't return anything now, so we disable it 
rem curl --url "http://127.0.0.1:7783" --data "{\"userpass\":null,\"method\":\"enable\",\"coin\":\"\"}" -s > default_userpass.json
rem curl --url "http://127.0.0.1:7783" --data "{\"userpass\":\"1d8b27b21efabcd96571cd56f91a40fb9aa4cc623d273c63bf9223dc6f8cd81f\",\"method\":\"hello\"}" -s > default_userpass.json

rem echo - First time call to MM API finished, default userpass received
set /p PASSPHRASE=<passphrase
echo - Pushing passphrase to login
curl --url "http://127.0.0.1:7783" --data "{\"userpass\":\"1d8b27b21efabcd96571cd56f91a40fb9aa4cc623d273c63bf9223dc6f8cd81f\",\"method\":\"passphrase\",\"passphrase\":\"%PASSPHRASE%\",\"gui\":\"nogui\"}" -s > userpass.json
echo Getting userpass related to your passphrase finished
for /f "tokens=4 delims=:," %%a in (' find "userpass" "userpass.json" ') do (
echo UserPass: %%~a 
echo %%~a > userpass
)
