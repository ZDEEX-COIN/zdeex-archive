#!/usr/bin/env bash
# Copyright (c) 2016-2023 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

# For use with https://git.hush.is/jahway603/hush-docs/src/branch/master/advanced/cross-compile-hush-full-node-to-aarch64-with-docker.md,
# Please follow that
set -eu -o pipefail

# Check if cmake, a new dependency for randomx support, is installed on system and exits if it is not
if ! [ -x "$(command -v cmake)" ]; then
  echo 'Error: cmake is not installed. Install cmake and try again.' >&2
  exit 1
fi

function cmd_pref() {
    if type -p "$2" > /dev/null; then
        eval "$1=$2"
    else
        eval "$1=$3"
    fi
}
cat <<'EOF'
 .~~~~~~~~~~~~~~~~.
{{ Building Hush!! }}
 `~~~~~~~~~~~~~~~~`
        \   ^__^
         \  (@@)\_______            
            (__)\ HUSH  )\/\      $
    z        zz ||----w |      z  |
zz  zz  z       || z   ||xxx   z z|z zz
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
EOF

# If a g-prefixed version of the command exists, use it preferentially.
function gprefix() {
    cmd_pref "$1" "g$2" "$2"
}

gprefix READLINK readlink
cd "$(dirname "$("$READLINK" -f "$0")")/.."

# Allow user overrides to $MAKE. Typical usage for users who need it:
#   MAKE=gmake ./util/build.sh -j$(nproc)
if [[ -z "${MAKE-}" ]]; then
    MAKE=make
fi

# Allow overrides to $BUILD and $HOST for porters. Most users will not need it.
#   BUILD=i686-pc-linux-gnu ./util/build.sh
if [[ -z "${BUILD-}" ]]; then
    BUILD="$(./depends/config.guess)"
fi
if [[ -z "${HOST-}" ]]; then
    HOST="$BUILD"
fi

# Allow users to set arbitrary compile flags. Most users will not need this.
if [[ -z "${CONFIGURE_FLAGS-}" ]]; then
    CONFIGURE_FLAGS=""
fi

if [ "x$*" = 'x--help' ]
then
    cat ./util/dragon.txt
    cat <<EOF
Welcome To The Hush Build System, Here Be Dragons!
Usage:
$0 --help
  Show this help message and exit.
$0 [ --enable-lcov || --disable-tests ] [ --disable-mining ] [ --disable-libs ] [ MAKEARGS... ]
  Build Hush and most of its transitive dependencies from source. MAKEARGS are applied to both dependencies and Hush itself.
  If --enable-lcov is passed, Hush is configured to add coverage instrumentation, thus enabling "make cov" to work.
  If --disable-tests is passed instead, the Hush tests are not built.
  If --disable-mining is passed, Hush is configured to not build any mining code. It must be passed after the test arguments, if present.
  It must be passed after the test/mining arguments, if present.
EOF
    exit 0
fi

set -x

# If --enable-lcov is the first argument, enable lcov coverage support:
LCOV_ARG=''
HARDENING_ARG='--enable-hardening'
TEST_ARG=''
if [ "x${1:-}" = 'x--enable-lcov' ]
then
    LCOV_ARG='--enable-lcov'
    HARDENING_ARG='--disable-hardening'
    shift
elif [ "x${1:-}" = 'x--disable-tests' ]
then
    TEST_ARG='--enable-tests=no'
    shift
fi

# If --disable-mining is the next argument, disable mining code:
MINING_ARG=''
if [ "x${1:-}" = 'x--disable-mining' ]
then
    MINING_ARG='--enable-mining=no'
    shift
fi

# Just show the useful info
eval "$MAKE" --version | head -n2
as --version | head -n1
as --version | tail -n1
ld -v

HOST="$HOST" BUILD="$BUILD" "$MAKE" "$@" -C ./depends/ V=1

./autogen.sh

CONFIG_SITE="$PWD/depends/$HOST/share/config.site" ./configure "$HARDENING_ARG" "$LCOV_ARG" "$TEST_ARG" "$MINING_ARG" $CONFIGURE_FLAGS CXXFLAGS='-g'

# Build CryptoConditions stuff
WD=$PWD
cd src/cc
echo $PWD
./makecustom
cd $WD

# Build RandomX
cd src/RandomX
if [ -d "build" ]
then
    ls -la build/librandomx*
else
    mkdir build && cd build
    cmake -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ -DCMAKE_STRIP=/usr/bin/aarch64-linux-gnu-strip -DARCH_ID=aarch64 ..
    make
fi

cd $WD

"$MAKE" "$@" V=1
