#!/usr/bin/env bash
# Copyright (c) 2016-2023 The Hush developers
# Released under the GPLv3

# Usage: update-copyrights.sh 2021 2022
# TODO: verify $1 and $2 exist
# TODO: verify ack and xargs exist on this system

# This update comments in source code
ack -l -i "20..-20..*Hush dev" | xargs ./util/replace.pl -$1 -$2

# This updates the define which is used by C++ help output
./util/replace.pl "COPYRIGHT_YEAR $1" "COPYRIGHT_YEAR $2" src/clientversion.h
./util/replace.pl "COPYRIGHT_YEAR, $1" "COPYRIGHT_YEAR, $2" configure.ac
