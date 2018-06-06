@echo off
rem [ Decker] Automatically download and build depends script for marketmaker.
rem
rem 1. Requires installed CMake for Windows (!)
rem 2. Currently build only 64-bit release versions of .lib and .dll
rem 3. Libraries available: pthreads, nanomsg, curl

@REM Check for Visual Studio
call set "VSPATH="
if defined VS140COMNTOOLS ( if not defined VSPATH (
 call set "VSPATH=%%VS140COMNTOOLS%%"
) )

@REM check if we already have the tools in the environment
if exist "%VCINSTALLDIR%" (
 goto compile
)

if not defined VSPATH (
 echo You need Microsoft Visual Studio 15 installed
 pause
 exit
)

@REM set up the environment
if exist "%VSPATH%..\..\vc\vcvarsall.bat" (
 call "%%VSPATH%%..\..\vc\vcvarsall.bat" amd64
 goto compile
)

echo Unable to set up the environment
pause
exit

:compile
rem MSBuild /help
echo.
echo Decker will automatically download and build all needed *.dll and *.lib for you ;)
timeout /t 5 /nobreak

mkdir marketmaker_depends
mkdir x64\Release

rem --- pthreads ---
:compile_pthreads
cd marketmaker_depends
git clone https://github.com/DeckerSU/pthread-win32
cd pthread-win32
MSBuild pthread.2015.sln /t:Rebuild /p:Configuration=Release /p:Platform=Win32
MSBuild pthread.2015.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64
cd ../..
copy marketmaker_depends\pthread-win32\bin\x64_MSVC2015.Release\pthread_lib.lib OSlibs\win\x64\pthread_lib.lib 

rem --- nanomsg ---
:compile_nanomsg

cd marketmaker_depends 
git clone https://github.com/nanomsg/nanomsg
cd nanomsg
mkdir build_msvc_2015_win32
mkdir build_msvc_2015_win64
cd build_msvc_2015_win64
cmake -G "Visual Studio 14 2015 Win64" ..
cmake --build . --config Release --target nanomsg
cd ../../..
copy marketmaker_depends\nanomsg\build_msvc_2015_win64\Release\nanomsg.lib OSlibs\win\x64\release\nanomsg.lib 
copy marketmaker_depends\nanomsg\build_msvc_2015_win64\Release\nanomsg.exp OSlibs\win\x64\release\nanomsg.exp
copy marketmaker_depends\nanomsg\build_msvc_2015_win64\Release\nanomsg.dll x64\Release\nanomsg.dll 

rem --- curl ---
:compile_curl
cd marketmaker_depends 
git clone https://github.com/curl/curl
cd curl
mkdir build_msvc_2015_win32
mkdir build_msvc_2015_win64
cd build_msvc_2015_win64
cmake -G "Visual Studio 14 2015 Win64" -DCMAKE_USE_WINSSL:BOOL=ON ..
cmake --build . --config Release --target libcurl

rem cmake .. -G"Visual Studio 14 2015 Win64" -DCURL_STATICLIB=ON -DCURL_DISABLE_LDAP=ON -DCURL_STATIC_CRT=ON
rem cmake .. -G"Visual Studio 14 2015 Win64" -DCURL_STATICLIB:BOOL=ON -DCURL_STATIC_CRT:BOOL=ON -DHTTP_ONLY:BOOL=ON -DCMAKE_BUILD_TYPE:STRING=RELEASE ..
rem cmake --build . --config Release
rem cmake --build . --config Release --target libcurl

cd ../../..
copy marketmaker_depends\curl\build_msvc_2015_win64\lib\Release\libcurl_imp.lib OSlibs\win\x64\release\libcurl.lib
copy marketmaker_depends\curl\build_msvc_2015_win64\lib\Release\libcurl_imp.exp OSlibs\win\x64\release\libcurl.exp
copy marketmaker_depends\curl\build_msvc_2015_win64\lib\Release\libcurl.dll x64\Release\libcurl.dll