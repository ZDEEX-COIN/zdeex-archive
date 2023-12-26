#!/usr/bin/env bash
# Copyright (c) 2016-2023 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

# Usage: $0 BRANCH JOBS
# TODO: default to master branch with 2 jobs

# we don't want this for our build.sh and make commands
#set -eu -o pipefail

BRANCH=$1

git clone https://git.hush.is/hush/hush3
cd hush3
git checkout $BRANCH
# You need 2GB of RAM per core, don't use too many
# (GB of RAM)/2 - 1 is the optimal core count for compiling Hush
# `nproc` tells you how many cores you have
JOBS=$2
JOBZ=$(nproc) # if build.sh fails, we can use many more jobs with make
# Want to fix this parrallel-only build system bug we inherited ? you are a new hush dev
# Sometimes the parrallel build fails because of a race condition, so
# we do it a few times to Make Really Sure
./build.sh -j$JOBS;make -j$JOBZ;make -j$JOBZ;make -j$JOBZ
./src/hushd &> hush.log &
# You can give the entire or parts of this file to Hush developers for debugging,
# but there is a lot of metadata!!! We don't want any more than we need to fix bugz
tail -f hush.log
