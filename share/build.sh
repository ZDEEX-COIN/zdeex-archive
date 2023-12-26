#!/usr/bin/env bash
# Copyright (c) 2016-2023 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

set -eu -o pipefail

# run correct build script for detected OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    ./util/build.sh --disable-tests $@
elif [[ "$OSTYPE" == "darwin"* ]]; then
    ./util/build-mac.sh --disable-tests $@
elif [[ "$OSTYPE" == "msys"* ]]; then
    ./util/build-win.sh --disable-tests $@
#elif [[ "$OSTYPE" == "freebsd"* ]]; then
    # placeholder
else
    echo "Unable to detect your OS. What are you using?"
fi
