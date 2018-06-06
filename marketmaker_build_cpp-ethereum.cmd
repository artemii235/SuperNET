@echo off
rem Sample script to build cpp-ethereum libs by Decker (don't fully tested yet)
rem Make sure cpp-ethereum is empty, before run.

git submodule init
git submodule update --init --recursive
cd cpp-ethereum
rem git submodule init
rem git submodule update --init
call scripts\install_deps.bat 
mkdir build_win64_release
cd build_win64_release
cmake .. -G "Visual Studio 14 2015 Win64"
cmake --build . --config Release
rem cmake --build . 