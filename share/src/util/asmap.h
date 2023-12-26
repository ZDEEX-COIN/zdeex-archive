// Copyright (c) 2016-2023 The Hush developers
// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef HUSH_UTIL_ASMAP_H
#define HUSH_UTIL_ASMAP_H

#include <stdint.h>
#include <vector>

uint32_t Interpret(const std::vector<bool> &asmap, const std::vector<bool> &ip);

bool SanityCheckASMap(const std::vector<bool>& asmap, int bits);

#endif // HUSH_UTIL_ASMAP_H
