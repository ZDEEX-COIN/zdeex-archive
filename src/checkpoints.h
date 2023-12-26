// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/
#ifndef HUSH_CHECKPOINTS_H
#define HUSH_CHECKPOINTS_H

#include "uint256.h"
#include "chainparams.h"
#include <map>

class CBlockIndex;
struct CCheckpointData;

// Blockchain checkpoints are compiled-in cyber warfare defenses
// They also change how blocks are validated and have the side effect
// of making block validation faster for blocks that are "protected"
// by a checkpoint block -- Duke Leto
namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

struct CCheckpointData {
    MapCheckpoints mapCheckpoints;
    int64_t nTimeLastCheckpoint;
    int64_t nTransactionsLastCheckpoint;
    double fTransactionsPerDay;
};
    bool CheckBlock(const CChainParams::CCheckpointData& data, int nHeight, const uint256& hash);
    
//! Return conservative estimate of total number of blocks, 0 if unknown
    int GetTotalBlocksEstimate(const CChainParams::CCheckpointData& data);

//! Returns last CBlockIndex* in mapBlockIndex that is a checkpoint
    CBlockIndex* GetLastCheckpoint(const CChainParams::CCheckpointData& data);

double GuessVerificationProgress(const CChainParams::CCheckpointData& data, CBlockIndex* pindex, bool fSigchecks = true);

} //namespace Checkpoints

#endif // HUSH_CHECKPOINTS_H
