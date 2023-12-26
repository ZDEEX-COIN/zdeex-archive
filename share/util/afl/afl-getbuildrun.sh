#!/usr/bin/env bash
# Copyright (c) 2016-2023 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
# Builds AFL and an instrumented hushd, then begins fuzzing.
# This script must be run from within the top level directory of a hush clone.
# Pass it the name of a directory in ./src/fuzzing.
# Additional arguments are passed-through to AFL.

set -eu -o pipefail

FUZZ_CASE="$1"
shift 1

export AFL_INSTALL_DIR=$(realpath "./afl-temp")

if [ ! -d "$AFL_INSTALL_DIR" ]; then
    mkdir "$AFL_INSTALL_DIR"
    ./util/afl/afl-get.sh "$AFL_INSTALL_DIR"
fi

./util/afl/afl-build.sh "$AFL_INSTALL_DIR" "$FUZZ_CASE" -j$(nproc)
./util/afl/afl-run.sh "$AFL_INSTALL_DIR" "$FUZZ_CASE" "$@"
