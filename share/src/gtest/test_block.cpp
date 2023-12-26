// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
#include <gtest/gtest.h>

#include "primitives/block.h"


TEST(block_tests, header_size_is_expected) {
    // Dummy header with an empty Equihash solution.
    CBlockHeader header;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << header;

    ASSERT_EQ(ss.size(), CBlockHeader::HEADER_SIZE);
}
