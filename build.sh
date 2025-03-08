#!/usr/bin/env bash

# Simple script to create the Makefile and build

git submodule update --init

if [[ $OSTYPE == 'darwin'* ]]; then
export LDFLAGS="-L/usr/local/opt/openssl/lib"
export CPPFLAGS="-I/usr/local/opt/openssl/include"
export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"
fi

make distclean || echo clean

rm -f Makefile.in
rm -f config.status
./autogen.sh || echo done

./configure.sh

make 
