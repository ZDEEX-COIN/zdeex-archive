// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
#include "key.h"
#include "base58.h"
#include "chainparams.h"
#include "gtest/gtest.h"
#include "crypto/common.h"
//#include "testutils.h"

std::string notaryPubkey = "0205a8ad0c1dbc515f149af377981aab58b836af008d4d7ab21bd76faf80550b47";
std::string notarySecret = "UxFWWxsf1d7w7K5TvAWSkeX4H95XQKwdwGv49DXwWUTzPTTjHBbU";

int main(int argc, char **argv) {
    /*
    assert(init_and_check_sodium() != -1);
    ECC_Start();
    ECCVerifyHandle handle;  // Inits secp256k1 verify context
    SelectParams(CBaseChainParams::REGTEST);

    CBitcoinSecret vchSecret;
    // this returns false due to network prefix mismatch but works anyway
    vchSecret.SetString(notarySecret);
    CKey notaryKey = vchSecret.GetKey();
    */

    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
