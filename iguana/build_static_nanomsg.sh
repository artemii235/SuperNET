#!/bin/bash

#Check if libnanomsg-static.a file is already exists or not
if [[ "$OSTYPE" == "linux-gnu" ]]; then
	echo "Linux"
	file="../OSlibs/linux/$(uname -m)/libnanomsg-static.a"
	makedir="../OSlibs/linux/$(uname -m)/"
	copytarget="../OSlibs/linux/$(uname -m)/libnanomsg-static.a"
elif [[ "$OSTYPE" == "darwin"* ]]; then
	# Mac OSX
	echo "Mac OSX"
	file="../OSlibs/osx/$(uname -m)/libnanomsg-static.a"
	makedir="../OSlibs/osx/$(uname -m)/"
	copytarget="../OSlibs/osx/$(uname -m)/libnanomsg-static.a"
fi

if [ ! -f "$file" ]
then
    echo "$0: File '${file}' not found."
    #Download nanomsg library 1.0 stable
    rm -rf nanomsgsrc
	git clone https://github.com/nanomsg/nanomsg.git nanomsgsrc

	#Create destination folder
	mkdir nanomsglib

	#Switch into nanomsgsrc folder
	cd nanomsgsrc

	#Create build directory and switch into it
	mkdir build && cd build

	#Compile
	cmake .. -DCMAKE_INSTALL_PREFIX=../../nanomsglib/ -DCMAKE_BUILD_TYPE=Debug -DNN_STATIC_LIB=1
	cmake --build .
	ctest -C Debug .
	cmake --build . --target install

	cd ../..
	pwd
	mkdir -p $makedir
	cp -av nanomsglib/lib/libnanomsg.a $copytarget
fi


