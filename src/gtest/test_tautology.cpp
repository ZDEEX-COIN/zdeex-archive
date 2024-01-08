// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
#include <gtest/gtest.h>

TEST(tautologies, seven_eq_seven) {
    ASSERT_EQ(7, 7);
}

TEST(tautologies, DISABLED_ObviousFailure)
{
    FAIL() << "This is expected";
}
