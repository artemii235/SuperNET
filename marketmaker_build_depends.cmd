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

@REM set up the environment, https://www.appveyor.com/docs/lang/cpp/#visual-studio-2017
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64.bat" (
 call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64.bat"
 goto compile
)

echo Unable to set up the environment
pause
exit

:compile
rem MSBuild /help
echo.
echo Decker will automatically download and build all needed *.dll and *.lib for you ;)

mkdir marketmaker_depends
mkdir x64

rem TODO: Download automatically from build.rs.
rem NB: "marketmaker_depends" is cached between the AppVeyor builds!
rem --- pthreads ---
:compile_pthreads
if not exist marketmaker_depends\pthreadVC2.dll (
    rem NB: This library depends on `msvcr100.dll`.
    rem     In the future we should probably get rid of it entirely, by starting all threads from Rust.
    curl ftp://sourceware.org/pub/pthreads-win32/prebuilt-dll-2-9-1-release/dll/x64/pthreadVC2.dll -o marketmaker_depends/pthreadVC2.dll
    curl ftp://sourceware.org/pub/pthreads-win32/prebuilt-dll-2-9-1-release/lib/x64/pthreadVC2.lib -o marketmaker_depends/pthreadVC2.lib
)
copy marketmaker_depends\pthreadVC2.dll x64\pthreadVC2.dll
copy marketmaker_depends\pthreadVC2.lib x64\pthreadVC2.lib

rem TODO: Move to build.rs and build automatically.
rem --- nanomsg ---
:compile_nanomsg
if not exist marketmaker_depends\nanomsg\build\Release\nanomsg.lib (
    cd marketmaker_depends
    rmdir nanomsg /S /Q
    git clone --depth=1 --quiet https://github.com/nanomsg/nanomsg
    cd nanomsg
    mkdir build
    cd build
    cmake -G "Visual Studio 15 2017 Win64" -DNN_STATIC_LIB=ON ..
    cmake --build . --config Release --target nanomsg
    cd ../../..
)
copy marketmaker_depends\nanomsg\build\Release\nanomsg.lib x64\nanomsg.lib

rem TODO: Move to build.rs and build automatically.
rem --- curl ---
:compile_curl
if not exist marketmaker_depends\curl\build\lib\Release\libcurl.dll (
    cd marketmaker_depends 
    rmdir curl /S /Q
    git clone --depth=1 --quiet https://github.com/curl/curl
    cd curl
    mkdir build
    cd build
    cmake -G "Visual Studio 15 2017 Win64" -DCMAKE_USE_WINSSL:BOOL=ON ..
    cmake --build . --config Release --target libcurl
    cd ../../..
)
copy marketmaker_depends\curl\build\lib\Release\libcurl_imp.lib x64\libcurl.lib
copy marketmaker_depends\curl\build\lib\Release\libcurl_imp.exp x64\libcurl.exp
copy marketmaker_depends\curl\build\lib\Release\libcurl.dll x64\libcurl.dll

rem Show what we've got here, in case we'd want to clear the cached folder, etc.
echo marketmaker_build_depends] dir marketmaker_depends
dir marketmaker_depends
