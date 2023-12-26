#!/usr/bin/env bash
# Copyright (c) 2016-2023 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

set -eu -o pipefail

AFL_INSTALL_DIR="$1"
FUZZ_CASE="$2"
shift 2

"$AFL_INSTALL_DIR/afl-fuzz" -i "./src/fuzzing/$FUZZ_CASE/input" -o "./src/fuzzing/$FUZZ_CASE/output" "$@" ./src/hushd @@
