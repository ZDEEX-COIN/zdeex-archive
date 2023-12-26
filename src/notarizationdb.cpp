// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
#include "dbwrapper.h"
#include "notarizationdb.h"
#include "uint256.h"
#include "cc/eval.h"
#include "crosschain.h"
#include "main.h"
#include <boost/foreach.hpp>

NotarizationDB *pnotarizations;
NotarizationDB::NotarizationDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "notarizations", nCacheSize, fMemory, fWipe, false, 64) { }

NotarizationsInBlock ScanBlockNotarizations(const CBlock &block, int nHeight) {
    EvalRef eval;
    NotarizationsInBlock vNotarizations;
    int timestamp = block.nTime;
    bool ishush3  = strncmp(SMART_CHAIN_SYMBOL, "HUSH3",5) == 0 ? true : false;

    // No valid ntz's before this height
    int minheight = ishush3 ? 365420 : 1;
    if(ishush3 && (nHeight <= GetArg("-dpow-start-height",minheight))) {
        return vNotarizations;
    }

    for (unsigned int i = 0; i < block.vtx.size(); i++) {
        CTransaction tx = block.vtx[i];

        NotarizationData data;
        bool parsed = ParseNotarizationOpReturn(tx, data);
        if (!parsed) data = NotarizationData();
        if (strlen(data.symbol) == 0)
          continue;

        //printf("Checked notarization data for %s \n",data.symbol);
        int authority = GetSymbolAuthority(data.symbol);

        if (authority == CROSSCHAIN_HUSH) {
            if (!eval->CheckNotaryInputs(tx, nHeight, block.nTime))
                continue;
        }

        if (parsed) {
            vNotarizations.push_back(std::make_pair(tx.GetHash(), data));
            if(fDebug) {
                printf("Parsed a notarization for: %s, txid:%s, ccid:%i, momdepth:%i\n", data.symbol, tx.GetHash().GetHex().data(), data.ccId, data.MoMDepth);
                if (!data.MoMoM.IsNull()) printf("MoMoM:%s\n", data.MoMoM.GetHex().data());
            }
        } else {
            LogPrintf("WARNING: Couldn't parse notarization for tx: %s at height %i\n", tx.GetHash().GetHex().data(), nHeight);
        }
    }
    return vNotarizations;
}

bool GetBlockNotarizations(uint256 blockHash, NotarizationsInBlock &nibs) {
    return pnotarizations->Read(blockHash, nibs);
}


bool GetBackNotarization(uint256 notarizationHash, Notarization &n) {
    return pnotarizations->Read(notarizationHash, n);
}

// Write an index of HUSH notarization id -> backnotarization
void WriteBackNotarizations(const NotarizationsInBlock notarizations, CDBBatch &batch) {
    int wrote = 0;
    BOOST_FOREACH(const Notarization &n, notarizations)
    {
        if (!n.second.txHash.IsNull()) {
            batch.Write(n.second.txHash, n);
            wrote++;
        }
    }
}

void EraseBackNotarizations(const NotarizationsInBlock notarizations, CDBBatch &batch) {
    BOOST_FOREACH(const Notarization &n, notarizations)
    {
        if (!n.second.txHash.IsNull())
            batch.Erase(n.second.txHash);
    }
}

// Scan notarizationsdb backwards for blocks containing a notarization
// for given symbol. Return height of matched notarization or 0.
int ScanNotarizationsDB(int height, std::string symbol, int scanLimitBlocks, Notarization& out) {
    if (height < 0 || height > chainActive.Height())
        return false;

    for (int i=0; i<scanLimitBlocks; i++) {
        if (i > height) break;
        NotarizationsInBlock notarizations;
        uint256 blockHash = *chainActive[height-i]->phashBlock;
        if (!GetBlockNotarizations(blockHash, notarizations))
            continue;

        BOOST_FOREACH(Notarization& nota, notarizations) {
            if (strcmp(nota.second.symbol, symbol.data()) == 0) {
                out = nota;
                return height-i;
            }
        }
    }
    return 0;
}
