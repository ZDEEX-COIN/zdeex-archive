#!/usr/bin/env bash
# Copyright (c) 2019-2020 radix42
# Copyright (c) 2016-2023 The Hush developers
# Original aarch64 port by radix42. Thank you!
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

set -eu -o pipefail

# Check if cmake, a new dependency for randomx support, is installed on system and exits if it is not
if ! [ -x "$(command -v cmake)" ]; then
  echo 'Error: cmake is not installed. Install cmake and try again.' >&2
  exit 1
fi

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

if [ "x$*" = 'x--help' ]
then
    cat ./util/dragon.txt
    cat <<EOF
Welcome To The Hush Build System, Here Be Dragons!
Usage:
$0 --help
  Show this help message and exit.
$0 [ --enable-lcov ] [ MAKEARGS... ]
  Build Hush and most of its transitive dependencies from
  source. MAKEARGS are applied to both dependencies and Hush itself. If
  --enable-lcov is passed, Hush is configured to add coverage
  instrumentation, thus enabling "make cov" to work.
EOF
    exit 0
fi

set -x
cd "$(dirname "$(readlink -f "$0")")/.."

# If --enable-lcov is the first argument, enable lcov coverage support:
LCOV_ARG=''
HARDENING_ARG='--disable-hardening'
if [ "x${1:-}" = 'x--enable-lcov' ]
then
    LCOV_ARG='--enable-lcov'
    HARDENING_ARG='--disable-hardening'
    shift
fi

# BUG: parameterize the platform/host directory:
PREFIX="$(pwd)/depends/aarch64-unknown-linux-gnu/"

HOST=aarch64-unknown-linux-gnu BUILD=aarch64-unknown-linux-gnu make "$@" -C ./depends/ V=1 NO_QT=1
./autogen.sh
CONFIG_SITE="$(pwd)/depends/aarch64-unknown-linux-gnu/share/config.site" ./configure --prefix="${PREFIX}" --host=aarch64-unknown-linux-gnu --build=aarch64-unknown-linux-gnu --with-gui=no --enable-rust=no "$HARDENING_ARG" "$LCOV_ARG" CXXFLAGS='-fwrapv -fno-strict-aliasing -g'

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
    # TODO: Do things work without -DARCH=native ?
    # TODO: Make an env var for using native arch
    # CC="${CC} -g " CXX="${CXX} -g " cmake -DARCH=native ..
    CC="${CC} -g " CXX="${CXX} -g " cmake ..
    make
fi

CC="${CC} -g " CXX="${CXX} -g " make "$@" V=1
