#!/bin/sh

binaries=("iguana")

for binary in "${binaries[@]}";
do
    # find the dylibs to copy for komodod
    DYLIBS=`otool -L agents/$binary | grep "/usr/local" | awk -F' ' '{ print $1 }'`
    echo "copying $DYLIBS to agents"
    # copy the dylibs to the agents-dir
    for dylib in $DYLIBS; do cp -rf $dylib agents/; done

    # modify komodod to point to dylibs
    echo "modifying $binary to use local libraries"
    for dylib in $DYLIBS; do install_name_tool -change $dylib @executable_path/`basename $dylib` agents/$binary; done;
    chmod +x agents/$binary
done
