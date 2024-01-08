// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
#ifndef HUSH_NOTARISATIONDB_H
#define HUSH_NOTARISATIONDB_H

#include "uint256.h"
#include "dbwrapper.h"
#include "cc/eval.h"

class NotarizationDB : public CDBWrapper
{
public:
    NotarizationDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
};

extern NotarizationDB *pnotarizations;
typedef std::pair<uint256,NotarizationData> Notarization;
typedef std::vector<Notarization> NotarizationsInBlock;

NotarizationsInBlock ScanBlockNotarizations(const CBlock &block, int nHeight);
bool GetBlockNotarizations(uint256 blockHash, NotarizationsInBlock &nibs);
bool GetBackNotarization(uint256 notarizationHash, Notarization &n);
void WriteBackNotarizations(const NotarizationsInBlock notarizations, CDBBatch &batch);
void EraseBackNotarizations(const NotarizationsInBlock notarizations, CDBBatch &batch);
int ScanNotarizationsDB(int height, std::string symbol, int scanLimitBlocks, Notarization& out);

#endif  /* HUSH_NOTARISATIONDB_H */
