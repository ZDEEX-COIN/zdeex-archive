#!/usr/bin/env bash
# Copyright (c) 2016-2023 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
## Usages:
##  ./util/build-debian-package.sh               # build amd64 package
##  ./util/build-debian-package.sh aarch64       # build package for specific archiecture

ARCH=${1:-amd64}
echo "Let There Be Hush Debian Packages"

# Check if lintian is installed and give details about installing
# It is an optional dependency
if ! [ -x "$(command -v lintian)" ]; then
  echo 'Warning: lintian is not installed yet. Consult your Linux version package manager...' >&2
  echo 'On Debian/Ubuntu, try "sudo apt install lintian"'
fi

# Check if fakeroot is installed and exit if it is not
if ! [ -x "$(command -v fakeroot)" ]; then
  echo 'Error: fakeroot is not installed yet. Consult your Linux version package manager...' >&2
  echo 'On Debian/Ubuntu, try "sudo apt install fakeroot"'
  echo ""
  exit 1
fi

set -e
set -x

BUILD_PATH="/tmp/hush-debian-$$"
PACKAGE_NAME="hush"
SRC_PATH=`pwd`
SRC_DEB=$SRC_PATH/contrib/debian
SRC_DOC=$SRC_PATH/doc

umask 022

if [ ! -d $BUILD_PATH ]; then
    mkdir $BUILD_PATH
fi

# If hushd is not currently running, package version can be hardcoded
#PACKAGE_VERSION=3.6.0
PACKAGE_VERSION=$($SRC_PATH/src/hushd --version|grep version|cut -d' ' -f4|cut -d- -f1|sed 's/v//g')
DEBVERSION=$(echo $PACKAGE_VERSION | sed 's/-beta/~beta/' | sed 's/-rc/~rc/' | sed 's/-/+/')
BUILD_DIR="$BUILD_PATH/$PACKAGE_NAME-$PACKAGE_VERSION-$ARCH"

if [ -d $BUILD_DIR ]; then
    rm -R $BUILD_DIR
fi

DEB_BIN=$BUILD_DIR/usr/bin
DEB_CMP=$BUILD_DIR/usr/share/bash-completion/completions
DEB_DOC=$BUILD_DIR/usr/share/doc/$PACKAGE_NAME
DEB_MAN=$BUILD_DIR/usr/share/man/man1
DEB_SHR=$BUILD_DIR/usr/share/hush
mkdir -p $BUILD_DIR/DEBIAN $DEB_CMP $DEB_BIN $DEB_DOC $DEB_MAN $DEB_SHR
chmod 0755 -R $BUILD_DIR/*

# Package maintainer scripts (currently empty)
#cp $SRC_DEB/postinst $BUILD_DIR/DEBIAN
#cp $SRC_DEB/postrm $BUILD_DIR/DEBIAN
#cp $SRC_DEB/preinst $BUILD_DIR/DEBIAN
#cp $SRC_DEB/prerm $BUILD_DIR/DEBIAN

cp $SRC_PATH/contrib/asmap/asmap.dat $DEB_SHR
cp $SRC_PATH/sapling-spend.params $DEB_SHR
cp $SRC_PATH/sapling-output.params $DEB_SHR
cp $SRC_PATH/src/hushd $DEB_BIN
strip $DEB_BIN/hushd
cp $SRC_PATH/src/hush-cli $DEB_BIN
strip $DEB_BIN/hush-cli
cp $SRC_PATH/src/hush-tx $DEB_BIN
strip $DEB_BIN/hush-tx

# these are scripts and don't require a strip
cp $SRC_PATH/src/dragonx-cli $DEB_BIN
cp $SRC_PATH/src/dragonxd $DEB_BIN

cp $SRC_PATH/src/hush-smart-chain $DEB_BIN
#cp $SRC_DEB/changelog $DEB_DOC/changelog.Debian
cp $SRC_DEB/copyright $DEB_DOC
cp -r $SRC_DEB/examples $DEB_DOC
# Copy manpages
cp $SRC_DOC/man/hushd.1 $DEB_MAN/hushd.1
cp $SRC_DOC/man/hush-cli.1 $DEB_MAN/hush-cli.1
cp $SRC_DOC/man/hush-tx.1 $DEB_MAN/hush-tx.1

# Copy bash completion files
cp $SRC_PATH/contrib/hushd.bash-completion $DEB_CMP/hushd
cp $SRC_PATH/contrib/hush-cli.bash-completion $DEB_CMP/hush-cli
cp $SRC_PATH/contrib/hush-tx.bash-completion $DEB_CMP/hush-tx
# Gzip files
#gzip --best -n $DEB_DOC/changelog
#gzip --best -n $DEB_DOC/changelog.Debian
gzip --best -n $DEB_MAN/hushd.1
gzip --best -n $DEB_MAN/hush-cli.1
gzip --best -n $DEB_MAN/hush-tx.1

cd $SRC_PATH/contrib

# Create the control file
dpkg-shlibdeps $DEB_BIN/hushd $DEB_BIN/hush-cli $DEB_BIN/hush-tx
dpkg-gencontrol -P$BUILD_DIR -v$DEBVERSION
#dpkg-gencontrol -P$BUILD_DIR

# Create the Debian package
fakeroot dpkg-deb --build $BUILD_DIR
cp $BUILD_PATH/$PACKAGE_NAME-$PACKAGE_VERSION-$ARCH.deb $SRC_PATH
shasum -a 256 $SRC_PATH/$PACKAGE_NAME-$PACKAGE_VERSION-$ARCH.deb
# Analyze with Lintian, reporting bugs and policy violations
lintian -i $SRC_PATH/$PACKAGE_NAME-$PACKAGE_VERSION-$ARCH.deb
exit 0
