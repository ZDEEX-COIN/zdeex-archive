#!/usr/bin/env bash
# Copyright (c) 2016-2023 The Hush developers
# Released under the GPLv3

set -e
set -x

#hardcode and uncomment if hushd is not running on this machine
#VERSION=3.6.3
VERSION=$(./src/hushd --version|grep version|cut -d' ' -f4|cut -d- -f1|sed 's/v//g')
DIR="hush-$VERSION-linux-amd64"
FILE="$DIR.tar"
TIME=$(perl -e 'print time')

if [ -d "build" ]
then
    mv build build.$TIME
    echo "Moved existing build/ dir to build.$TIME"
fi
mkdir build
BUILD="build/$DIR"
mkdir $BUILD
echo "Created new build dir $BUILD"
cp contrib/asmap/asmap.dat $BUILD
cp sapling*.params $BUILD
cd src
cp hushd hush-cli hush-tx hush-smart-chain dragonx-cli dragonxd ../$BUILD
cd ../$BUILD
strip hushd hush-cli hush-tx
cd ..
tar -f $FILE -c  hush-$VERSION-linux-amd64/*
gzip -9 $FILE
sha256sum *.gz
du -sh *.gz
