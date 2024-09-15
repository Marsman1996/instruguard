#!/bin/bash

WORKDIR=`pwd`
export PATH=$WORKDIR/llvm-6/bin:$PATH
export LD_LIBRARY_PATH=$WORKDIR/llvm-6/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}