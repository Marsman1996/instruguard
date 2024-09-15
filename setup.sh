#!/bin/bash

KRWDIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)
WORKDIR=`pwd`

if [[ ! "$WORKDIR" -ef "$KRWDIR" ]]; then
	echo "Run the script from the retrowrite root directory: cd $KRWDIR && bash ./setup.sh"
	exit 1
fi

git submodule update --init --checkout fix/retrowrite
cd $WORKDIR/fix/retrowrite
./setup.sh user || rm -r retro

wget https://releases.llvm.org/6.0.0/clang+llvm-6.0.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz
tar -xf clang+llvm-6.0.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz
mv clang+llvm-6.0.0-x86_64-linux-gnu-ubuntu-16.04 llvm-6
export PATH=$WORKDIR/llvm-6/bin:$PATH
export LD_LIBRARY_PATH=$WORKDIR/llvm-6/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

cd $WORKDIR/fix/aflig
make
cd instruguard
make
cd ../llvm_mode
make
