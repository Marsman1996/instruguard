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

cd $WORKDIR/fix/aflig
make
cd instruguard
make
cd ../llvm_mode
make
