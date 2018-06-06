@echo off
rem (c) Decker

echo [#1] Build nanomsg, curl and pthreads ...
call marketmaker_build_depends.cmd
copy marketmaker_depends\curl\build_msvc_2015_win64\lib\Release\libcurl_imp.lib marketmaker_depends\curl\build_msvc_2015_win64\lib\Release\curl.lib
copy marketmaker_depends\pthread-win32\bin\x64_MSVC2015.Release\pthread_lib.lib marketmaker_depends\pthread-win32\bin\x64_MSVC2015.Release\pthread.lib

echo [#2] Prepare build etomic needed things ...
git submodule init
git submodule update --init --recursive
cd cpp-ethereum
rem git submodule init
rem git submodule update --init
call scripts\install_deps.bat 
cd ..
mkdir build_win64_release
cd build_win64_release
cmake .. -G "Visual Studio 14 2015 Win64"

rem Steps before build:
rem 
rem crypto777\CMakeLists.txt 
rem Add:
rem if(WIN32)
rem add_definitions(-DNATIVE_WINDOWS)
rem add_definitions(-DIGUANA_LOG2PACKETSIZE=20)
rem add_definitions(-DIGUANA_MAXPACKETSIZE=1572864)
rem include_directories("${CMAKE_SOURCE_DIR}/includes")
rem endif()
rem
rem iguana\exchanges\CMakeLists.txt 
rem
rem if(WIN32)
rem add_definitions(-DNATIVE_WINDOWS)
rem add_definitions(-DIGUANA_LOG2PACKETSIZE=20)
rem add_definitions(-DIGUANA_MAXPACKETSIZE=1572864)
rem add_definitions(-D_CRT_SECURE_NO_WARNINGS)
rem include_directories("${CMAKE_SOURCE_DIR}/includes")
rem endif()
rem
rem iguana\exchanges\etomicswap\CMakeLists.txt 
rem
rem if(WIN32)
rem add_definitions(-DNATIVE_WINDOWS)
rem add_definitions(-DIGUANA_LOG2PACKETSIZE=20)
rem add_definitions(-DIGUANA_MAXPACKETSIZE=1572864)
rem add_definitions(-D_CRT_SECURE_NO_WARNINGS)
rem add_definitions(-DNOMINMAX)
rem include_directories("${CMAKE_SOURCE_DIR}/includes")
rem endif()

echo [#3] Build marketmaker-mainnet ...

cmake --build . --config Release --target marketmaker-mainnet
cd ..