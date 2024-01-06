// Copyright (c) 2009-2010 Satoshi Nakamoto
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
#include "pubkey.h"
#include "miner.h"
#ifdef ENABLE_MINING
#include "pow/tromp/equi_miner.h"
#endif

#include "amount.h"
#include "chainparams.h"
#include "importcoin.h"
#include "consensus/consensus.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#ifdef ENABLE_MINING
#include "crypto/equihash.h"
#include "RandomX/src/randomx.h"
#endif
#include "hash.h"
#include "key_io.h"
#include "main.h"
#include "metrics.h"
#include "net.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "random.h"
#include "timedata.h"
#include "ui_interface.h"
#include "util.h"
#include "utilmoneystr.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif
#include "zcash/Address.hpp"
#include "transaction_builder.h"
#include "sodium.h"
#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>
#ifdef ENABLE_MINING
#include <functional>
#endif
#include <mutex>

#define rxdebug(format, ...) if(fRandomXDebug) { fprintf(stderr, format, __func__, ## __VA_ARGS__ ); }

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.
// The COrphan class keeps track of these 'temporary orphans' while
// CreateBlock is figuring out which transactions to include.
//
class COrphan
{
public:
    const CTransaction* ptx;
    set<uint256> setDependsOn;
    CFeeRate feeRate;
    double dPriority;

    COrphan(const CTransaction* ptxIn) : ptx(ptxIn), feeRate(0), dPriority(0)
    {
    }
};

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;

// We want to sort transactions by priority and fee rate, so:
typedef boost::tuple<double, CFeeRate, const CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;

public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }

    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

extern int8_t ASSETCHAINS_ADAPTIVEPOW;
extern uint32_t ASSETCHAINS_RANDOMX;
extern bool fRandomXDebug;
extern std::string devtax_scriptpub_for_height(uint32_t nHeight);

void UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    if ( ASSETCHAINS_ADAPTIVEPOW <= 0 )
        pblock->nTime = std::max(pindexPrev->GetMedianTimePast()+1, GetTime());
    else pblock->nTime = std::max((int64_t)(pindexPrev->nTime+1), GetTime());

    // Updating time can change work required on testnet:
    if (ASSETCHAINS_ADAPTIVEPOW > 0 || consensusParams.nPowAllowMinDifficultyBlocksAfterHeight != boost::none)
    {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }
}
#include "hush_defs.h"
#include "cc/CCinclude.h"

extern CCriticalSection cs_metrics;
void vcalc_sha256(char deprecated[(256 >> 3) * 2 + 1],uint8_t hash[256 >> 3],uint8_t *src,int32_t len);

uint32_t Mining_start,Mining_height;
int32_t My_notaryid = -1;
int32_t hush_chosennotary(int32_t *notaryidp,int32_t height,uint8_t *pubkey33,uint32_t timestamp);
int32_t hush_baseid(char *origbase);
int32_t hush_longestchain();
int64_t hush_block_unlocktime(uint32_t nHeight);
uint64_t the_commission(const CBlock *block,int32_t height);
int32_t hush_notaryvin(CMutableTransaction &txNew,uint8_t *notarypub33, void *ptr);
int32_t decode_hex(uint8_t *bytes,int32_t n,char *hex);
int32_t hush_is_notarytx(const CTransaction& tx);
uint64_t hush_notarypay(CMutableTransaction &txNew, std::vector<int8_t> &NotarizationNotaries, uint32_t timestamp, int32_t height, uint8_t *script, int32_t len);
int32_t hush_notaries(uint8_t pubkeys[64][33],int32_t height,uint32_t timestamp);
int32_t hush_getnotarizedheight(uint32_t timestamp,int32_t height, uint8_t *script, int32_t len);
CScript hush_mineropret(int32_t nHeight);
bool hush_appendACscriptpub();

CBlockTemplate* CreateNewBlock(CPubKey _pk,const CScript& _scriptPubKeyIn, int32_t gpucount, bool isStake)
{
    //fprintf(stderr,"%s\n", __func__);
    CScript scriptPubKeyIn(_scriptPubKeyIn);

    CPubKey pk;
    if ( _pk.size() != 33 )
    {
        pk = CPubKey();
        std::vector<std::vector<unsigned char>> vAddrs;
        txnouttype txT;
        if ( scriptPubKeyIn.size() > 0 && Solver(scriptPubKeyIn, txT, vAddrs))
        {
            if (txT == TX_PUBKEY)
                pk = CPubKey(vAddrs[0]);
        }
    } else pk = _pk;

    uint64_t deposits,voutsum=0; int32_t isrealtime,hushheight; uint32_t blocktime; const CChainParams& chainparams = Params();
    bool fNotarizationBlock = false; std::vector<int8_t> NotarizationNotaries;
    
    //fprintf(stderr,"%s: create new block with pubkey=%s\n", __func__, HexStr(pk).c_str());
    // Create new block
    if ( gpucount < 0 )
        gpucount = HUSH_MAXGPUCOUNT;
    std::unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    //fprintf(stderr,"%s: created new block template\n", __func__);
    if(!pblocktemplate.get())
    {
        fprintf(stderr,"%s: pblocktemplate.get() failure\n", __func__);
        return NULL;
    }
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience
     // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (Params().MineBlocksOnDemand())
        pblock->nVersion = GetArg("-blockversion", pblock->nVersion);

    // Add dummy coinbase tx as first transaction
    pblock->vtx.push_back(CTransaction());
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end
    //fprintf(stderr,"%s: added dummy coinbase\n", __func__);

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", MAX_BLOCK_SIZE(chainActive.LastTip()->GetHeight()+1));
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE(chainActive.LastTip()->GetHeight()+1)-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", DEFAULT_BLOCK_MIN_SIZE);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);
    //fprintf(stderr,"%s: nBlockMaxSize=%u, nBlockPrioritySize=%u, nBlockMinSize=%u\n", __func__, nBlockMaxSize, nBlockPrioritySize, nBlockMinSize);


    // Collect memory pool transactions into the block
    CAmount nFees = 0;

    uint256 cbHash;
    
    boost::this_thread::interruption_point(); // exit thread before entering locks. 
    
    CBlockIndex* pindexPrev = 0;
    {
        // this should stop create block ever exiting until it has returned something. 
        boost::this_thread::disable_interruption();
        ENTER_CRITICAL_SECTION(cs_main);
        ENTER_CRITICAL_SECTION(mempool.cs);
        pindexPrev = chainActive.LastTip();
        const int nHeight = pindexPrev->GetHeight() + 1;
        const Consensus::Params &consensusParams = chainparams.GetConsensus();
        uint32_t consensusBranchId = CurrentEpochBranchId(nHeight, consensusParams);
        bool sapling = NetworkUpgradeActive(nHeight, consensusParams, Consensus::UPGRADE_SAPLING);

        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();
        uint32_t proposedTime = GetTime();

        //fprintf(stderr,"%s: nHeight=%d, consensusBranchId=%u, proposedTime=%u\n", __func__, nHeight, consensusBranchId,  proposedTime);

        voutsum = GetBlockSubsidy(nHeight,consensusParams) + 10000*COIN; // approx fees
        //fprintf(stderr,"%s: voutsum=%lu\n", __func__, voutsum);

        if (proposedTime == nMedianTimePast)
        {
            // too fast or stuck, this addresses the too fast issue, while moving
            // forward as quickly as possible
            for (int i; i < 100; i++)
            {
                proposedTime = GetTime();
                if (proposedTime == nMedianTimePast)
                    MilliSleep(10);
            }
        }
        pblock->nTime = GetTime();
        // Now we have the block time + height, we can get the active notaries.
        int8_t numSN = 0; uint8_t notarypubkeys[64][33] = {0};
        if ( ASSETCHAINS_NOTARY_PAY[0] != 0 )
        {
            // Only use speical miner for notary pay chains.
            numSN = hush_notaries(notarypubkeys, nHeight, pblock->nTime);
        }

        CCoinsViewCache view(pcoinsTip);
        uint32_t expired; uint64_t commission;
        
        SaplingMerkleTree sapling_tree;
        assert(view.GetSaplingAnchorAt(view.GetBestAnchor(SAPLING), sapling_tree));

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;
        bool fPrintPriority = GetBoolArg("-printpriority", false);

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size() + 1);

        //fprintf(stderr,"%s: going to add txs from mempool\n", __func__);
        // now add transactions from the mempool
        int32_t Notarizations = 0; uint64_t txvalue;
        uint32_t large_zins  = 0;                  // number of ztxs with large number of inputs in block
        uint32_t large_zouts = 0;                  // number of ztxs with large number of outputs in block
        const uint32_t LARGE_ZINS_MAX        = 1;  // max ztxs with large zins per block
        const uint32_t LARGE_ZOUTS_MAX       = 1;  // max ztxs with large zouts per block
        const uint32_t LARGE_ZINS_THRESHOLD  = 50; // min number of zins to be considered large
        const uint32_t LARGE_ZOUTS_THRESHOLD = 10; // min number of zouts to be considered large
        for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
             mi != mempool.mapTx.end(); ++mi) {
            const CTransaction& tx = mi->GetTx();

            int64_t nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
            ? nMedianTimePast
            : pblock->GetBlockTime();

            if (tx.IsCoinBase() || !IsFinalTx(tx, nHeight, nLockTimeCutoff) || IsExpiredTx(tx, nHeight))
            {
                fprintf(stderr,"%s: coinbase.%d finaltx.%d expired.%d\n",__func__, tx.IsCoinBase(),IsFinalTx(tx, nHeight, nLockTimeCutoff),IsExpiredTx(tx, nHeight));
                continue;
            }
            txvalue = tx.GetValueOut();
            if ( HUSH_VALUETOOBIG(txvalue) != 0 )
                continue;

            COrphan* porphan = NULL;
            double dPriority = 0;
            CAmount nTotalIn = 0;
            bool fMissingInputs = false;
            bool fNotarization = false;
            std::vector<int8_t> TMP_NotarizationNotaries;
            if (tx.IsCoinImport())
            {
                CAmount nValueIn = GetCoinImportValue(tx); // burn amount
                nTotalIn += nValueIn;
                dPriority += (double)nValueIn * 1000;  // flat multiplier... max = 1e16.
            } else {
                TMP_NotarizationNotaries.clear();
                bool fToCryptoAddress = false;
                if ( numSN != 0 && notarypubkeys[0][0] != 0 && hush_is_notarytx(tx) == 1 )
                    fToCryptoAddress = true;

                BOOST_FOREACH(const CTxIn& txin, tx.vin)
                {
                    if (tx.IsPegsImport() && txin.prevout.n==10e8)
                    {
                        CAmount nValueIn = GetCoinImportValue(tx); // burn amount
                        nTotalIn += nValueIn;
                        dPriority += (double)nValueIn * 1000;  // flat multiplier... max = 1e16.
                        continue;
                    }
                    // Read prev transaction
                    if (!view.HaveCoins(txin.prevout.hash))
                    {
                        // This should never happen; all transactions in the memory
                        // pool should connect to either transactions in the chain
                        // or other transactions in the memory pool.
                        if (!mempool.mapTx.count(txin.prevout.hash))
                        {
                            LogPrintf("ERROR: mempool transaction missing input\n");
                            // if (fDebug) assert("mempool transaction missing input" == 0);
                            fMissingInputs = true;
                            if (porphan)
                                vOrphan.pop_back();
                            break;
                        }

                        // Has to wait for dependencies
                        if (!porphan)
                        {
                            // Use list for automatic deletion
                            vOrphan.push_back(COrphan(&tx));
                            porphan = &vOrphan.back();
                        }
                        mapDependers[txin.prevout.hash].push_back(porphan);
                        porphan->setDependsOn.insert(txin.prevout.hash);
                        nTotalIn += mempool.mapTx.find(txin.prevout.hash)->GetTx().vout[txin.prevout.n].nValue;
                        continue;
                    }
                    const CCoins* coins = view.AccessCoins(txin.prevout.hash);
                    assert(coins);

                    CAmount nValueIn = coins->vout[txin.prevout.n].nValue;
                    nTotalIn += nValueIn;

                    int nConf = nHeight - coins->nHeight;
                    
                    uint8_t *script; int32_t scriptlen; uint256 hash; CTransaction tx1;
                    // loop over notaries array and extract index of signers.
                    if ( fToCryptoAddress && GetTransaction(txin.prevout.hash,tx1,hash,false) )
                    {
                        for (int8_t i = 0; i < numSN; i++) 
                        {
                            script = (uint8_t *)&tx1.vout[txin.prevout.n].scriptPubKey[0];
                            scriptlen = (int32_t)tx1.vout[txin.prevout.n].scriptPubKey.size();
                            if ( scriptlen == 35 && script[0] == 33 && script[34] == OP_CHECKSIG && memcmp(script+1,notarypubkeys[i],33) == 0 )
                            {
                                // We can add the index of each notary to vector, and clear it if this notarization is not valid later on.
                                TMP_NotarizationNotaries.push_back(i);                          
                            }
                        }
                    }
                    dPriority += (double)nValueIn * nConf;
                }
                if ( numSN != 0 && notarypubkeys[0][0] != 0 && TMP_NotarizationNotaries.size() >= numSN / 5 )
                {
                    // check a notary didnt sign twice (this would be an invalid notarization later on and cause problems)
                    std::set<int> checkdupes( TMP_NotarizationNotaries.begin(), TMP_NotarizationNotaries.end() );
                    if ( checkdupes.size() != TMP_NotarizationNotaries.size() ) 
                    {
                        fprintf(stderr, "%s: WTFBBQ! possible notarization is signed multiple times by same notary, passed as normal transaction.\n", __func__);
                    } else fNotarization = true;
                }
                nTotalIn += tx.GetShieldedValueIn();
            }

            if (fMissingInputs) continue;

            // Priority is sum(valuein * age) / modified_txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            // fprintf(stderr,"%s: computing priority with nTxSize=%u\n", __func__, nTxSize);
            dPriority = tx.ComputePriority(dPriority, nTxSize);

            uint256 hash = tx.GetHash();
            mempool.ApplyDeltas(hash, dPriority, nTotalIn);

            CFeeRate feeRate(nTotalIn-tx.GetValueOut(), nTxSize);

            if ( fNotarization ) {
                // Special miner for notary pay chains. Can only enter this if numSN/notarypubkeys is set higher up.
                if ( tx.vout.size() == 2 && tx.vout[1].nValue == 0 )
                {
                    // Get the OP_RETURN for the notarization
                    uint8_t *script = (uint8_t *)&tx.vout[1].scriptPubKey[0];
                    int32_t scriptlen = (int32_t)tx.vout[1].scriptPubKey.size();
                    if ( script[0] == OP_RETURN )
                    {
                        Notarizations++;
                        if ( Notarizations > 1 ) 
                        {
                            fprintf(stderr, "%s: skipping notarization.%d\n",__func__, Notarizations);
                            // Any attempted notarization needs to be in its own block!
                            continue;
                        }
                        int32_t notarizedheight = hush_getnotarizedheight(pblock->nTime, nHeight, script, scriptlen);
                        if ( notarizedheight != 0 )
                        {
                            // this is the first one we see, add it to the block as TX1 
                            NotarizationNotaries = TMP_NotarizationNotaries;
                            dPriority = 1e16;
                            fNotarizationBlock = true;
                            //fprintf(stderr, "Notarization %s set to maximum priority\n",hash.ToString().c_str());
                        }
                    }
                }
            } else if ( dPriority == 1e16 ) {
                dPriority -= 10;
                // make sure notarization is tx[1] in block. 
            }
            if (porphan) {
                porphan->dPriority = dPriority;
                porphan->feeRate = feeRate;
            } else {
                vecPriority.push_back(TxPriority(dPriority, feeRate, &(mi->GetTx())));
            }
        }
        // fprintf(stderr,"%s: done adding txs from mempool\n", __func__);

        // Collect transactions into block
        int64_t interest;
        uint64_t nBlockSize = 1000;
        uint64_t nBlockTx   = 0;
        int nBlockSigOps    = 100;
        bool fSortedByFee   = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        // fprintf(stderr,"%s: compared txs with fSortedByFee=%d\n", __func__, fSortedByFee);

        while (!vecPriority.empty()) {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            CFeeRate feeRate = vecPriority.front().get<1>();
            const CTransaction& tx = *(vecPriority.front().get<2>());

            // fprintf(stderr,"%s: grabbed first tx from priority queue\n", __func__);

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            // fprintf(stderr,"%s: compared first tx from priority queue\n", __func__);
            vecPriority.pop_back();

            if(tx.vShieldedSpend.size() >= LARGE_ZINS_THRESHOLD && large_zins >= LARGE_ZINS_MAX) {
                LogPrintf("%s: skipping ztx %s with %d zins because there are already %d ztxs with large zins\n",
                    __func__, tx.GetHash().ToString().c_str(), tx.vShieldedSpend.size(), LARGE_ZINS_MAX);
                continue;
            }

            if(tx.vShieldedOutput.size() >= LARGE_ZOUTS_THRESHOLD && large_zouts >= LARGE_ZOUTS_MAX) {
                LogPrintf("%s: skipping ztx %s with %d zouts because there are already %d ztxs with large zouts\n",
                    __func__, tx.GetHash().ToString().c_str(), tx.vShieldedOutput.size(), LARGE_ZOUTS_MAX);
                continue;
            }

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            // fprintf(stderr,"%s: nTxSize = %u\n", __func__, nTxSize);

            // Opret spam limits
            if (mapArgs.count("-opretmintxfee"))
            {
                CAmount n = 0;
                CFeeRate opretMinFeeRate;
                if (ParseMoney(mapArgs["-opretmintxfee"], n) && n > 0)
                    opretMinFeeRate = CFeeRate(n);
                else
                    opretMinFeeRate = CFeeRate(400000); // default opretMinFeeRate (1 HUSH per 250 Kb = 0.004 per 1 Kb = 400000 puposhis per 1 Kb)

                bool fSpamTx = false;
                unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
                unsigned int nTxOpretSize = 0;

                // calc total oprets size
                BOOST_FOREACH(const CTxOut& txout, tx.vout) {
                    if (txout.scriptPubKey.IsOpReturn()) {
                        CScript::const_iterator it = txout.scriptPubKey.begin() + 1;
                        opcodetype op;
                        std::vector<uint8_t> opretData;
                        if (txout.scriptPubKey.GetOp(it, op, opretData)) {
                            //std::cerr << HexStr(opretData.begin(), opretData.end()) << std::endl;
                            nTxOpretSize += opretData.size();
                        }
                    }
                }

                if ((nTxOpretSize > 256) && (feeRate < opretMinFeeRate)) fSpamTx = true;
                // std::cerr << tx.GetHash().ToString() << " nTxSize." << nTxSize << " nTxOpretSize." << nTxOpretSize << " feeRate." << feeRate.ToString() << " opretMinFeeRate." << opretMinFeeRate.ToString() << " fSpamTx." << fSpamTx << std::endl;
                if (fSpamTx) continue;
                // std::cerr << tx.GetHash().ToString() << " vecPriority.size() = " << vecPriority.size() << std::endl;
            }

            if (nBlockSize + nTxSize >= nBlockMaxSize-512) // room for extra autotx
            {
                fprintf(stderr,"%s: nBlockSize %d + %d nTxSize >= %d nBlockMaxSize\n",__func__, (int32_t)nBlockSize,(int32_t)nTxSize,(int32_t)nBlockMaxSize);
                continue;
            }

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = GetLegacySigOpCount(tx);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS-1)
            {
                //fprintf(stderr,"A nBlockSigOps %d + %d nTxSigOps >= %d MAX_BLOCK_SIGOPS-1\n",(int32_t)nBlockSigOps,(int32_t)nTxSigOps,(int32_t)MAX_BLOCK_SIGOPS);
                continue;
            }

            // fprintf(stderr,"%s: looking to see if we need to skip any fee=0 txs\n", __func__);

            // Skip free transactions if we're past the minimum block size:
            const uint256& hash = tx.GetHash();
            double dPriorityDelta = 0;
            CAmount nFeeDelta = 0;
            mempool.ApplyDeltas(hash, dPriorityDelta, nFeeDelta);
            if (fSortedByFee && (dPriorityDelta <= 0) && (nFeeDelta <= 0) && (feeRate < ::minRelayTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
            {
                fprintf(stderr,"%s: fee rate skip\n", __func__);
                continue;
            }
            // Prioritize by fee once past the priority size or we run out of high-priority transactions
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || !AllowFree(dPriority)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            if (!view.HaveInputs(tx))
            {
                //fprintf(stderr,"dont have inputs\n");
                continue;
            }
            CAmount nTxFees = view.GetValueIn(chainActive.LastTip()->GetHeight(),&interest,tx,chainActive.LastTip()->nTime)-tx.GetValueOut();

            nTxSigOps += GetP2SHSigOpCount(tx, view);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS-1)
            {
                //fprintf(stderr,"B nBlockSigOps %d + %d nTxSigOps >= %d MAX_BLOCK_SIGOPS-1\n",(int32_t)nBlockSigOps,(int32_t)nTxSigOps,(int32_t)MAX_BLOCK_SIGOPS);
                continue;
            }
            // Note that flags: we don't want to set mempool/IsStandard()
            // policy here, but we still have to ensure that the block we
            // create only contains transactions that are valid in new blocks.
            CValidationState state;
            PrecomputedTransactionData txdata(tx);
            if (!ContextualCheckInputs(tx, state, view, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true, txdata, Params().GetConsensus(), consensusBranchId))
            {
                fprintf(stderr,"%s: ContextualCheckInputs failure\n",__func__);
                continue;
            }
            UpdateCoins(tx, view, nHeight);

            BOOST_FOREACH(const OutputDescription &outDescription, tx.vShieldedOutput) {
                sapling_tree.append(outDescription.cm);
            }

            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if(tx.vShieldedOutput.size() >= LARGE_ZOUTS_THRESHOLD) {
                large_zouts++;
                LogPrintf("%s: txid=%s has large zouts=%d (%d large zouts in block)\n", __func__, tx.GetHash().ToString().c_str(),
                    tx.vShieldedOutput.size(), large_zouts );
            }

            if(tx.vShieldedSpend.size() >= LARGE_ZINS_THRESHOLD) {
                large_zins++;
                LogPrintf("%s: txid=%s has large zins=%d (%d large zins in block)\n", __func__, tx.GetHash().ToString().c_str(),
                    tx.vShieldedSpend.size(), large_zins );
            }

            if (fPrintPriority)
            {
                LogPrintf("priority %.1f fee %s txid %s\n",dPriority, feeRate.ToString(), tx.GetHash().ToString());
            }

            // Add transactions that depend on this one to the priority queue
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->feeRate, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        // fprintf(stderr,"%s: nLastBlockTx=%lu , nLastBlockSize=%lu\n", __func__, nLastBlockTx, nLastBlockSize);

        if ( ASSETCHAINS_ADAPTIVEPOW <= 0 )
            blocktime = 1 + std::max(pindexPrev->GetMedianTimePast()+1, GetTime());
        else blocktime = 1 + std::max((int64_t)(pindexPrev->nTime+1), GetTime());
        //pblock->nTime = blocktime + 1;
        // fprintf(stderr,"%s: calling GetNextWorkRequired\n", __func__);
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, Params().GetConsensus());

        LogPrintf("CreateNewBlock(): total size %u blocktime.%u nBits.%08x\n", nBlockSize,blocktime,pblock->nBits);
        
        // Create coinbase tx
        CMutableTransaction txNew = CreateNewContextualCMutableTransaction(consensusParams, nHeight);
        txNew.vin.resize(1);
        txNew.vin[0].prevout.SetNull();
        txNew.vin[0].scriptSig = CScript() << nHeight << OP_0;

        txNew.vout.resize(1);
        txNew.vout[0].scriptPubKey = scriptPubKeyIn;
        txNew.vout[0].nValue = GetBlockSubsidy(nHeight,consensusParams) + nFees;
        // fprintf(stderr,"%s: mine ht.%d with %.8f\n",__func__,nHeight,(double)txNew.vout[0].nValue/COIN);
        txNew.nExpiryHeight = 0;
        if ( ASSETCHAINS_ADAPTIVEPOW <= 0 )
            txNew.nLockTime = std::max(pindexPrev->GetMedianTimePast()+1, GetTime());
        else txNew.nLockTime = std::max((int64_t)(pindexPrev->nTime+1), GetTime());


        pblock->vtx[0] = txNew;

        // Create a local variable instead of modifying the global ASSETCHAINS_SCRIPTPUB
        auto assetchains_scriptpub = devtax_scriptpub_for_height(nHeight);

        if ( nHeight > 1 && SMART_CHAIN_SYMBOL[0] != 0 && (ASSETCHAINS_OVERRIDE_PUBKEY33[0] != 0 || assetchains_scriptpub.size() > 1) && (ASSETCHAINS_COMMISSION != 0 || ASSETCHAINS_FOUNDERS_REWARD != 0)  && (commission= the_commission((CBlock*)&pblocktemplate->block,(int32_t)nHeight)) != 0 )
        {
            int32_t i; uint8_t *ptr;
            txNew.vout.resize(2);
            txNew.vout[1].nValue = commission;
            if ( assetchains_scriptpub.size() > 1 )
            {
                static bool didinit = false;
                if ( !didinit && nHeight > HUSH_EARLYTXID_HEIGHT && HUSH_EARLYTXID != zeroid && hush_appendACscriptpub() )
                {
                    fprintf(stderr, "appended ccopreturn to assetchains_scriptpub.%s\n", assetchains_scriptpub.c_str());
                    didinit = true;
                }
                //fprintf(stderr,"mine to -ac_script\n");
                //txNew.vout[1].scriptPubKey = CScript() << ParseHex();
                int32_t len = strlen(assetchains_scriptpub.c_str());
                len >>= 1;
                txNew.vout[1].scriptPubKey.resize(len);
                ptr = (uint8_t *)&txNew.vout[1].scriptPubKey[0];
                decode_hex(ptr,len,(char *)assetchains_scriptpub.c_str());
            } else {
                txNew.vout[1].scriptPubKey.resize(35);
                ptr = (uint8_t *)&txNew.vout[1].scriptPubKey[0];
                ptr[0] = 33;
                for (i=0; i<33; i++)
                {
                    ptr[i+1] = ASSETCHAINS_OVERRIDE_PUBKEY33[i];
                    //fprintf(stderr,"%02x",ptr[i+1]);
                }
                ptr[34] = OP_CHECKSIG;
                //fprintf(stderr," set ASSETCHAINS_OVERRIDE_PUBKEY33 into vout[1]\n");
            }
            //printf("autocreate commision vout\n");
        } else if ( (uint64_t)(txNew.vout[0].nValue) >= ASSETCHAINS_TIMELOCKGTE) {
			fprintf(stderr,"timelocked chains not supported in this code!\n");
			LEAVE_CRITICAL_SECTION(cs_main);
			LEAVE_CRITICAL_SECTION(mempool.cs);
			return(0);
        } else if ( fNotarizationBlock && ASSETCHAINS_NOTARY_PAY[0] != 0 && pblock->vtx[1].vout.size() == 2 && pblock->vtx[1].vout[1].nValue == 0 ) {
            // Get the OP_RETURN for the notarization
            uint8_t *script = (uint8_t *)&pblock->vtx[1].vout[1].scriptPubKey[0];
            int32_t scriptlen = (int32_t)pblock->vtx[1].vout[1].scriptPubKey.size();
            if ( script[0] == OP_RETURN )
            {
                uint64_t totalsats = hush_notarypay(txNew, NotarizationNotaries, pblock->nTime, nHeight, script, scriptlen);
                if ( totalsats == 0 )
                {
                    fprintf(stderr, "Could not create notary payment, trying again.\n");
                    if ( SMART_CHAIN_SYMBOL[0] == 0 ||  (SMART_CHAIN_SYMBOL[0] != 0 && !isStake) )
                    {
                        LEAVE_CRITICAL_SECTION(cs_main);
                        LEAVE_CRITICAL_SECTION(mempool.cs);
                    }
                    return(0);
                }
                //fprintf(stderr, "Created notary payment coinbase totalsat.%lu\n",totalsats);    
            } else fprintf(stderr, "vout 2 of notarization is not OP_RETURN scriptlen.%i\n", scriptlen);
        }
        if ( ASSETCHAINS_CBOPRET != 0 )
        {
            int32_t numv = (int32_t)txNew.vout.size();
            txNew.vout.resize(numv+1);
            txNew.vout[numv].nValue = 0;
            txNew.vout[numv].scriptPubKey = hush_mineropret(nHeight);
            //printf("autocreate commision/cbopret.%lld vout[%d]\n",(long long)ASSETCHAINS_CBOPRET,(int32_t)txNew.vout.size());
        }
        pblock->vtx[0] = txNew;
        pblocktemplate->vTxFees[0] = -nFees;

        // if not staking, setup nonce, otherwise, leave it alone
        if (!isStake || ASSETCHAINS_LWMAPOS == 0)
        {
            // Randomize nonce
            arith_uint256 nonce = UintToArith256(GetRandHash());

            // Clear the top 16 and bottom 16 or 24 bits (for local use as thread flags and counters)
            nonce <<= ASSETCHAINS_NONCESHIFT[ASSETCHAINS_ALGO];
            nonce >>= 16;
            pblock->nNonce = ArithToUint256(nonce);
        }

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        pblock->hashFinalSaplingRoot   = sapling_tree.root();

        // all PoS chains need this data in the block at all times
        if ( ASSETCHAINS_LWMAPOS || SMART_CHAIN_SYMBOL[0] == 0 || ASSETCHAINS_STAKED == 0 || HUSH_MININGTHREADS > 0 )
        {
            UpdateTime(pblock, Params().GetConsensus(), pindexPrev);
            pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, Params().GetConsensus());
        }
        pblock->nSolution.clear();
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);
        if ( SMART_CHAIN_SYMBOL[0] == 0 && IS_HUSH_NOTARY != 0 && My_notaryid >= 0 )
        {
            uint32_t r; CScript opret; void **ptr=0;

            CMutableTransaction txNotary = CreateNewContextualCMutableTransaction(Params().GetConsensus(), chainActive.Height() + 1);
            if ( pblock->nTime < pindexPrev->nTime+60 )
                pblock->nTime = pindexPrev->nTime + 60;
            if ( gpucount < 33 )
            {
                uint8_t tmpbuffer[40]; uint32_t r; int32_t n=0; uint256 randvals;
                memcpy(&tmpbuffer[n],&My_notaryid,sizeof(My_notaryid)), n += sizeof(My_notaryid);
                memcpy(&tmpbuffer[n],&Mining_height,sizeof(Mining_height)), n += sizeof(Mining_height);
                memcpy(&tmpbuffer[n],&pblock->hashPrevBlock,sizeof(pblock->hashPrevBlock)), n += sizeof(pblock->hashPrevBlock);
                vcalc_sha256(0,(uint8_t *)&randvals,tmpbuffer,n);
                memcpy(&r,&randvals,sizeof(r));
                pblock->nTime += (r % (33 - gpucount)*(33 - gpucount));
            }
            if ( hush_notaryvin(txNotary,NOTARY_PUBKEY33,ptr) > 0 )
            {
                CAmount txfees = 5000;
                pblock->vtx.push_back(txNotary);
                pblocktemplate->vTxFees.push_back(txfees);
                pblocktemplate->vTxSigOps.push_back(GetLegacySigOpCount(txNotary));
                nFees += txfees;
                pblocktemplate->vTxFees[0] = -nFees;
                //*(uint64_t *)(&pblock->vtx[0].vout[0].nValue) += txfees;
                //fprintf(stderr,"added notaryvin\n");
            } else {
                fprintf(stderr,"error adding notaryvin, need to create 0.0001 utxos\n");
                if ( SMART_CHAIN_SYMBOL[0] == 0 ||  (SMART_CHAIN_SYMBOL[0] != 0 && !isStake) )
                {
                    LEAVE_CRITICAL_SECTION(cs_main);
                    LEAVE_CRITICAL_SECTION(mempool.cs);
                }
                return(0);
            }
        }
        else if ( ASSETCHAINS_CC == 0 && pindexPrev != 0 && ASSETCHAINS_STAKED == 0 && (SMART_CHAIN_SYMBOL[0] != 0 || IS_HUSH_NOTARY == 0 || My_notaryid < 0) )
        {
            CValidationState state;
            //fprintf(stderr,"%s: check validity\n", __func__);
            if ( !TestBlockValidity(state, *pblock, pindexPrev, false, false)) // invokes CC checks
            {
                if ( SMART_CHAIN_SYMBOL[0] == 0 || (SMART_CHAIN_SYMBOL[0] != 0 && !isStake) )
                {
                    LEAVE_CRITICAL_SECTION(cs_main);
                    LEAVE_CRITICAL_SECTION(mempool.cs);
                }
                fprintf(stderr,"%s: TestBlockValidity failed!\n", __func__);
                //throw std::runtime_error("CreateNewBlock(): TestBlockValidity failed"); // crashes the node, moved to GetBlockTemplate and issue return.
                return(0);
            }
            //fprintf(stderr,"valid\n");
        }
    }
    if ( SMART_CHAIN_SYMBOL[0] == 0 || (SMART_CHAIN_SYMBOL[0] != 0 && !isStake) )
    {
        LEAVE_CRITICAL_SECTION(cs_main);
        LEAVE_CRITICAL_SECTION(mempool.cs);
    }
    // fprintf(stderr,"%s: done\n", __func__);
    return pblocktemplate.release();
}


// Internal miner

#ifdef ENABLE_MINING

void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    //fprintf(stderr,"RandomXMiner: %s with nExtraNonce=%u\n", __func__, nExtraNonce);
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->GetHeight()+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = txCoinbase;
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}

#ifdef ENABLE_WALLET

// Internal miner
CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey, int32_t nHeight, int32_t gpucount, bool isStake)
{
    CPubKey pubkey; CScript scriptPubKey; uint8_t *script,*ptr; int32_t i,len;
    // fprintf(stderr,"%s: with nHeight=%d\n", __func__, nHeight);

    // Create a local variable instead of modifying the global assetchains_scriptpub
    auto assetchains_scriptpub = devtax_scriptpub_for_height(nHeight);
    if ( nHeight == 1 && ASSETCHAINS_COMMISSION != 0 && assetchains_scriptpub[assetchains_scriptpub.back()] != 49 && assetchains_scriptpub[assetchains_scriptpub.back()-1] != 51 )
    {
        if ( ASSETCHAINS_OVERRIDE_PUBKEY33[0] != 0 )
        {
            pubkey = ParseHex(ASSETCHAINS_OVERRIDE_PUBKEY);
            scriptPubKey = CScript() << ParseHex(HexStr(pubkey)) << OP_CHECKSIG;
            // fprintf(stderr,"%s: with pubkey=%s\n", __func__, HexStr(pubkey).c_str() );
        } else {
            len = strlen(assetchains_scriptpub.c_str());
            len >>= 1;
            scriptPubKey.resize(len);
            ptr = (uint8_t *)&scriptPubKey[0];
            decode_hex(ptr,len,(char *)assetchains_scriptpub.c_str());
        }
    } else if ( USE_EXTERNAL_PUBKEY != 0 ) {
        //fprintf(stderr,"use notary pubkey\n");
        pubkey = ParseHex(NOTARY_PUBKEY);
        scriptPubKey = CScript() << ParseHex(HexStr(pubkey)) << OP_CHECKSIG;
    } else {
        {
            // Support mining with -disablewallet and minetolocalwallet=0
            if (!GetBoolArg("-disablewallet", false)) {
                // wallet enabled
                if (!reservekey.GetReservedKey(pubkey))
                    return NULL;
                scriptPubKey.clear();
                scriptPubKey = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
            } else {
                // wallet disabled
                CTxDestination dest = DecodeDestination(GetArg("-mineraddress", ""));
                char destaddr[65];
                if (IsValidDestination(dest)) {
                    // CKeyID keyID = boost::get<CKeyID>(dest);
                    // scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
                    scriptPubKey = GetScriptForDestination(dest);
                    Getscriptaddress(destaddr,scriptPubKey);
                    fprintf(stderr,"%s: wallet disabled with mineraddress=%s\n", __func__, destaddr);
                } else {
                    return NULL;
                }
             }
         }
     }
    // fprintf(stderr,"%s: calling CreateNewBlock\n", __func__);
    return CreateNewBlock(pubkey, scriptPubKey, gpucount, isStake);
}

void hush_sendmessage(int32_t minpeers,int32_t maxpeers,const char *message,std::vector<uint8_t> payload)
{
    int32_t numsent = 0;
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if ( pnode->hSocket == INVALID_SOCKET )
            continue;
        if ( numsent < minpeers || (rand() % 10) == 0 )
        {
            //fprintf(stderr,"pushmessage\n");
            pnode->PushMessage(message,payload);
            if ( numsent++ > maxpeers )
                break;
        }
    }
}

static bool ProcessBlockFound(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
#else
static bool ProcessBlockFound(CBlock* pblock)
#endif // ENABLE_WALLET
{
    LogPrintf("%s\n", pblock->ToString());
    LogPrintf("generated %s height.%d\n", FormatMoney(pblock->vtx[0].vout[0].nValue),chainActive.LastTip()->GetHeight()+1);

    // Found a solution
    {
        if (pblock->hashPrevBlock != chainActive.LastTip()->GetBlockHash())
        {
            uint256 hash; int32_t i;
            hash = pblock->hashPrevBlock;
            for (i=31; i>=0; i--)
                fprintf(stderr,"%02x",((uint8_t *)&hash)[i]);
            fprintf(stderr," <- prev (stale)\n");
            hash = chainActive.LastTip()->GetBlockHash();
            for (i=31; i>=0; i--)
                fprintf(stderr,"%02x",((uint8_t *)&hash)[i]);
            fprintf(stderr," <- chainTip (stale)\n");

            return error("HushMiner: generated block is stale");
        }
    }

    // Inform about the new block
    GetMainSignals().BlockFound(pblock->GetHash());

#ifdef ENABLE_WALLET
    // Remove key from key pool
    if ( IS_HUSH_NOTARY == 0 )
    {
        if (GetArg("-mineraddress", "").empty()) {
            // Remove key from key pool
            reservekey.KeepKey();
        }
    }
#endif
    //fprintf(stderr,"process new block\n");

    // Process this block the same as if we had received it from another node
    CValidationState state;
    if (!ProcessNewBlock(1,chainActive.LastTip()->GetHeight()+1,state, NULL, pblock, true, NULL))
        return error("HushMiner: ProcessNewBlock, block not accepted");

    TrackMinedBlock(pblock->GetHash());
    return true;
}

int32_t hush_baseid(char *origbase);
int32_t hush_eligiblenotary(uint8_t pubkeys[66][33],int32_t *mids,uint32_t *blocktimes,int32_t *nonzpkeysp,int32_t height);
arith_uint256 hush_PoWtarget(int32_t *percPoSp,arith_uint256 target,int32_t height,int32_t goalperc);
int32_t FOUND_BLOCK,HUSH_MAYBEMINED;
extern int32_t HUSH_LASTMINED,HUSH_INSYNC;
int32_t roundrobin_delay;
arith_uint256 HASHTarget,HASHTarget_POW;

// wait for peers to connect
void waitForPeers(const CChainParams &chainparams)
{
    if (chainparams.MiningRequiresPeers())
    {
        bool fvNodesEmpty;
        {
            boost::this_thread::interruption_point();
            LOCK(cs_vNodes);
            fvNodesEmpty = vNodes.empty();
        }
        if (fvNodesEmpty || IsNotInSync())
        {
            int loops = 0, blockDiff = 0, newDiff = 0;

            do {
                if (fvNodesEmpty)
                {
                    MilliSleep(1000 + rand() % 4000);
                    boost::this_thread::interruption_point();
                    LOCK(cs_vNodes);
                    fvNodesEmpty = vNodes.empty();
                    loops = 0;
                    blockDiff = 0;
                }
                if ((newDiff = IsNotInSync()) > 1)
                {
                    if (blockDiff != newDiff)
                    {
                        blockDiff = newDiff;
                    }
                    else
                    {
                        if (++loops <= 10)
                        {
                            MilliSleep(1000);
                        }
                        else break;
                    }
                }
            } while (fvNodesEmpty || IsNotInSync());
            MilliSleep(100 + rand() % 400);
        }
    }
}

#ifdef ENABLE_WALLET
CBlockIndex *get_chainactive(int32_t height)
{
    if ( chainActive.LastTip() != 0 )
    {
        if ( height <= chainActive.LastTip()->GetHeight() )
        {
            LOCK(cs_main);
            return(chainActive[height]);
        }
        // else fprintf(stderr,"get_chainactive height %d > active.%d\n",height,chainActive.Tip()->GetHeight());
    }
    //fprintf(stderr,"get_chainactive null chainActive.Tip() height %d\n",height);
    return(0);
}


#endif

int32_t gotinvalid;

class RandomXSolverCanceledException : public std::exception
{
    virtual const char* what() const throw() {
        return "RandomX solver was canceled";
    }
};

enum RandomXSolverCancelCheck
{
    Reason1,
    Reason2
};

#ifdef ENABLE_WALLET
void static RandomXMiner(CWallet *pwallet)
#else
void static RandomXMiner()
#endif
{
    LogPrintf("HushRandomXMiner started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("hush-randomx");
    const CChainParams& chainparams = Params();

#ifdef ENABLE_WALLET
    // Each thread has its own key
    CReserveKey reservekey(pwallet);
#endif
    // Each thread has its own counter
    unsigned int nExtraNonce = 0;

    uint8_t *script; uint64_t total; int32_t i,j,gpucount=HUSH_MAXGPUCOUNT,notaryid = -1;
    while ( (ASSETCHAIN_INIT == 0 || HUSH_INITDONE == 0) )
    {
        sleep(1);
        if ( hush_baseid(SMART_CHAIN_SYMBOL) < 0 )
            break;
    }

    std::mutex m_cs;
    bool cancelSolver = false;
    boost::signals2::connection c = uiInterface.NotifyBlockTip.connect(
                                                                       [&m_cs, &cancelSolver](const uint256& hashNewTip) mutable {
                                                                           std::lock_guard<std::mutex> lock{m_cs};
                                                                           cancelSolver = true;
                                                                       }
                                                                       );
    miningTimer.start();

    randomx_flags flags         = randomx_get_flags();
    // TODO: attempt to use large pages and fall back to no large pages
    // flags |= RANDOMX_FLAG_LARGE_PAGES;
    flags |= RANDOMX_FLAG_FULL_MEM;
    //flags |= RANDOMX_FLAG_JIT;
    randomx_cache *randomxCache = randomx_alloc_cache(flags);
    if (randomxCache == NULL) {
        LogPrintf("RandomX cache is null, something is wrong, cannot mine!\n");
        return;
    }
    rxdebug("%s: created randomx flags + cache\n");
    randomx_dataset *randomxDataset = randomx_alloc_dataset(flags);
    rxdebug("%s: created dataset\n");

    if( randomxDataset == nullptr) {
        LogPrintf("%s: allocating randomx dataset failed!\n", __func__);
        return;
    }

    auto datasetItemCount = randomx_dataset_item_count();
    rxdebug("%s: dataset items=%lu\n", datasetItemCount);

    char randomxHash[RANDOMX_HASH_SIZE];
    rxdebug("%s: created randomxHash of size %d\n", RANDOMX_HASH_SIZE);
    char randomxKey[82]; // randomx spec says keysize of >60 bytes is implementation-specific
    // initial randomx key is unique to every Hush Smart Chain, and has at least 9 bytes (2^9=128 bits) of entropy
    // since magic is 4 bytes, rpc port is 4 bytes and smart chain symbol must be at least 1 character long
    snprintf(randomxKey, 81, "%08x%s%08x", ASSETCHAINS_MAGIC, SMART_CHAIN_SYMBOL, ASSETCHAINS_RPCPORT);

    // With the defaults of 1024 and 64
    // the key block will change every ~21.3 hours with a 75s block time
    // and every ~17 hours with the default 60s block time for HSCs
    int randomxInterval = GetArg("-ac_randomx_interval",1024);
    // This lag is 80 mins for 75s blocktime and 64 mins for 60s (default) blocktime for HSCs
    int randomxBlockLag = GetArg("-ac_randomx_lag", 64);
    randomx_vm *myVM = nullptr;

    try {
        // fprintf(stderr,"RandomXMiner: mining %s with randomx\n",SMART_CHAIN_SYMBOL);
        
        rxdebug("%s: mining %s with randomx\n", SMART_CHAIN_SYMBOL);
       
        while (true)
        {
            // fprintf(stderr,"RandomXMiner: beginning mining loop on %s with nExtraNonce=%u\n",SMART_CHAIN_SYMBOL, nExtraNonce);
            rxdebug("%s: start mining loop on %s with nExtraNonce=%u\n", SMART_CHAIN_SYMBOL, nExtraNonce);

            if (chainparams.MiningRequiresPeers()) {
                //if ( ASSETCHAINS_SEED != 0 && chainActive.LastTip()->GetHeight() < 100 )
                //    break;
                // Busy-wait for the network to come online so we don't waste time mining
                // on an obsolete chain. In regtest mode we expect to fly solo.
                miningTimer.stop();
                do {
                    bool fvNodesEmpty;
                    {
                        //LOCK(cs_vNodes);
                        fvNodesEmpty = vNodes.empty();
                    }
                    if (!fvNodesEmpty )//&& !IsInitialBlockDownload())
                        break;
                    MilliSleep(15000);
                    //fprintf(stderr,"fvNodesEmpty %d IsInitialBlockDownload(%s) %d\n",(int32_t)fvNodesEmpty,SMART_CHAIN_SYMBOL,(int32_t)IsInitialBlockDownload());

                } while (true);
                //fprintf(stderr,"%s Found peers\n",SMART_CHAIN_SYMBOL);
                miningTimer.start();
            }

            // Create new block
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            CBlockIndex* pindexPrev = chainActive.LastTip();

            // If we don't have a valid chain tip to work from, wait and try again.
            if (pindexPrev == nullptr) {
                fprintf(stderr,"%s: null pindexPrev, trying again...\n",__func__);
                MilliSleep(1000);
                continue;
            }

            if ( Mining_height != pindexPrev->GetHeight()+1 )
            {
                Mining_height = pindexPrev->GetHeight()+1;
                Mining_start = (uint32_t)time(NULL);
            }

            // fprintf(stderr,"RandomXMiner: using initial key with interval=%d and lag=%d\n", randomxInterval, randomxBlockLag);
            rxdebug("%s: using initial key, interval=%d, lag=%d, Mining_height=%u\n", randomxInterval, randomxBlockLag, Mining_height);
            // Use the initial key at the start of the chain, until the first key block
            if( (Mining_height) < randomxInterval + randomxBlockLag) {
                randomx_init_cache(randomxCache, &randomxKey, sizeof randomxKey);
                rxdebug("%s: initialized cache with initial key\n");
            } else {
                rxdebug("%s: calculating keyHeight with randomxInterval=%d\n", randomxInterval);
                // At heights between intervals, we use the same block key and wait randomxBlockLag blocks until changing
                int keyHeight = ((Mining_height - randomxBlockLag) / randomxInterval) * randomxInterval;
                uint256 randomxBlockKey = chainActive[keyHeight]->GetBlockHash();

                randomx_init_cache(randomxCache, &randomxBlockKey, sizeof randomxBlockKey);
                rxdebug("%s: initialized cache with keyHeight=%d, randomxBlockKey=%s\n", keyHeight, randomxBlockKey.ToString().c_str());
            }

            //TODO: this is hardcoded to use 2 threads instead of the number of mining threads
            rxdebug("%s: initializing dataset with 2 threads\n");
            std::thread t1(&randomx_init_dataset, randomxDataset, randomxCache, 0, datasetItemCount / 2);
            std::thread t2(&randomx_init_dataset, randomxDataset, randomxCache, datasetItemCount / 2, datasetItemCount - datasetItemCount / 2);
            t1.join();
            t2.join();

            // randomx_init_dataset(randomxDataset, randomxCache, 0, datasetItemCount);
            rxdebug("%s: dataset initialized\n");

            myVM = randomx_create_vm(flags, nullptr, randomxDataset);
            if(myVM == NULL) {
                LogPrintf("RandomXMiner: Cannot create RandomX VM, aborting!\n");
                return;
            }
            //fprintf(stderr,"RandomXMiner: Mining_start=%u\n", Mining_start);
#ifdef ENABLE_WALLET
            CBlockTemplate *ptr = CreateNewBlockWithKey(reservekey, pindexPrev->GetHeight()+1, gpucount, 0);
#else
            CBlockTemplate *ptr = CreateNewBlockWithKey();
#endif

            // fprintf(stderr,"RandomXMiner: created new block with Mining_start=%u\n",Mining_start);
            rxdebug("%s: created new block with Mining_start=%u\n",Mining_start);
            if ( ptr == 0 )
            {
                if ( !GetBoolArg("-gen",false))
                {
                    miningTimer.stop();
                    c.disconnect();
                    LogPrintf("HushRandomXMiner terminated\n");
                    return;
                }
                static uint32_t counter;
                if ( counter++ < 10 && ASSETCHAINS_STAKED == 0 )
                    fprintf(stderr,"RandomXMiner: created illegal blockB, retry with counter=%u\n", counter);
                sleep(1);
                continue;
            }
            // fprintf(stderr,"RandomXMiner: getting block template\n");
            rxdebug("%s: getting block template\n");

            unique_ptr<CBlockTemplate> pblocktemplate(ptr);
            if (!pblocktemplate.get())
            {
                if (GetArg("-mineraddress", "").empty()) {
                    LogPrintf("Error in HushRandomXMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
                } else {
                    // Should never reach here, because -mineraddress validity is checked in init.cpp
                    LogPrintf("Error in HushRandomXMiner: Invalid -mineraddress\n");
                }
                return;
            }
            CBlock *pblock = &pblocktemplate->block;
            if ( SMART_CHAIN_SYMBOL[0] != 0 )
            {
                if ( ASSETCHAINS_REWARD[0] == 0 && !ASSETCHAINS_LASTERA )
                {
                    if ( pblock->vtx.size() == 1 && pblock->vtx[0].vout.size() == 1 && Mining_height > ASSETCHAINS_MINHEIGHT )
                    {
                        static uint32_t counter;
                        if ( counter++ < 10 )
                            fprintf(stderr,"skip generating %s on-demand block, no tx avail\n",SMART_CHAIN_SYMBOL);
                        sleep(10);
                        continue;
                    } else fprintf(stderr,"%s vouts.%d mining.%d vs %d\n",SMART_CHAIN_SYMBOL,(int32_t)pblock->vtx[0].vout.size(),Mining_height,ASSETCHAINS_MINHEIGHT);
                }
            }
            rxdebug("%s: incrementing extra nonce\n");
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);
            // fprintf(stderr,"RandomXMiner: %u transactions in block\n",(int32_t)pblock->vtx.size());
            LogPrintf("Running HushRandomXMiner with %u transactions in block (%u bytes)\n",pblock->vtx.size(),::GetSerializeSize(*pblock,SER_NETWORK,PROTOCOL_VERSION));

            // Search
            uint32_t savebits;
            int64_t nStart = GetTime();
            pblock->nBits  = GetNextWorkRequired(pindexPrev, pblock, Params().GetConsensus());
            savebits = pblock->nBits;
            HASHTarget = arith_uint256().SetCompact(savebits);
            roundrobin_delay = ROUNDROBIN_DELAY;
            Mining_start = 0;
            gotinvalid = 0;

            while (true)
            {
                if ( gotinvalid != 0 ) {
                    fprintf(stderr,"RandomXMiner: gotinvalid=%d\n",gotinvalid);
                    break;
                }
                hush_longestchain();

                // fprintf(stderr,"RandomXMiner: solving with nNonce = %s\n",pblock->nNonce.ToString().c_str());
                rxdebug("%s: solving with nNonce = %s\n",pblock->nNonce.ToString().c_str());
                arith_uint256 hashTarget;
                hashTarget = HASHTarget;

                CDataStream randomxInput(SER_NETWORK, PROTOCOL_VERSION);
                // Use the current block as randomx input
                randomxInput << pblocktemplate->block;

                // std::cerr << "RandomXMiner: randomxInput=" << HexStr(randomxInput) << "\n";
                // fprintf(stderr,"RandomXMiner: created randomxKey=%s , randomxInput.size=%lu\n", randomxKey, randomxInput.size() ); //randomxInput);
                rxdebug("%s: randomxKey=%s randomxInput=%s\n", randomxKey, HexStr(randomxInput).c_str());

                rxdebug("%s: calculating randomx hash\n");
                randomx_calculate_hash(myVM, &randomxInput, sizeof randomxInput, randomxHash);
                rxdebug("%s: calculated randomx hash\n");

                rxdebug("%s: randomxHash=");
                if (fRandomXDebug) {
                    for (unsigned i = 0; i < RANDOMX_HASH_SIZE; ++i) {
                            printf("%02x", randomxHash[i] & 0xff);
                    }

                    printf("\n");
                }

                // Use randomx hash to build a valid block
                std::function<bool(std::vector<unsigned char>)> validBlock =
#ifdef ENABLE_WALLET
                [&pblock, &hashTarget, &pwallet, &reservekey, &m_cs, &cancelSolver, &chainparams]
#else
                [&pblock, &hashTarget, &m_cs, &cancelSolver, &chainparams]
#endif
                (std::vector<unsigned char> soln) {
                    int32_t z; arith_uint256 h; CBlock B;
                    // Write the solution to the hash and compute the result.
                    rxdebug("%s: Checking solution against target\n");
                    pblock->nSolution = soln;
                    solutionTargetChecks.increment();
                    // fprintf(stderr,"%s: solutionTargetChecks=%lu\n", __func__, solutionTargetChecks.get());
                    B = *pblock;
                    h = UintToArith256(B.GetHash());

                    rxdebug("%s: h=");
                    if (fRandomXDebug) {
                        for (z=31; z>=0; z--)
                            fprintf(stderr,"%02x",((uint8_t *)&h)[z]);
                        fprintf(stderr," , hashTarget=");
                        for (z=31; z>=0; z--)
                            fprintf(stderr,"%02x",((uint8_t *)&hashTarget)[z]);
                        fprintf(stderr,"\n");
                    }

                    if ( h > hashTarget )
                    {
                        rxdebug("%s: h > hashTarget");
                        return false;
                    }

                    CValidationState state;
                    if ( !TestBlockValidity(state,B, chainActive.LastTip(), true, false))
                    {
                        h = UintToArith256(B.GetHash());
                        fprintf(stderr,"RandomXMiner: Invalid randomx block mined, try again ");
                        for (z=31; z>=0; z--)
                            fprintf(stderr,"%02x",((uint8_t *)&h)[z]);
                        gotinvalid = 1;
                        fprintf(stderr,"\n");
                        return(false);
                    }
                    SetThreadPriority(THREAD_PRIORITY_NORMAL);
                    LogPrintf("HushRandomXMiner:\n");
                    LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", B.GetHash().GetHex(), HASHTarget.GetHex());
#ifdef ENABLE_WALLET
                    if (ProcessBlockFound(&B, *pwallet, reservekey)) {
#else
                        if (ProcessBlockFound(&B)) {
#endif
                            // Ignore chain updates caused by us
                            std::lock_guard<std::mutex> lock{m_cs};
                            cancelSolver = false;
                        }
                        SetThreadPriority(THREAD_PRIORITY_LOWEST);
                        // In regression test mode, stop mining after a block is found.
                        if (chainparams.MineBlocksOnDemand()) {
                            // Increment here because throwing skips the call below
                            // TODO: equivalent of ehSolverRuns.increment();
                            throw boost::thread_interrupted();
                        }
                        return true;
                    };
                    std::function<bool(RandomXSolverCancelCheck)> cancelled = [&m_cs, &cancelSolver](RandomXSolverCancelCheck pos) {
                        std::lock_guard<std::mutex> lock{m_cs};
                        return cancelSolver;
                    };

                    try { 
                        // Use the randomX hash as the block solution
                        std::vector<unsigned char> sol_char(randomxHash, randomxHash+32);
                        bool found = validBlock(sol_char);
                        if (found) {
                            rxdebug("%s: found solution!\n");
                            // If we find a POW solution, do not try other solutions
                            // because they become invalid as we created a new block in blockchain.
                            break;
                        } else {
                            rxdebug("%s: solution not found, validBlock=false\n");
                        }
                    } catch (RandomXSolverCanceledException&) {
                        LogPrintf("HushRandomXMiner solver canceled\n");
                        std::lock_guard<std::mutex> lock{m_cs};
                        cancelSolver = false;
                    }

                    boost::this_thread::interruption_point();

                    if (vNodes.empty() && chainparams.MiningRequiresPeers())
                    {
                        if ( Mining_height > ASSETCHAINS_MINHEIGHT )
                        {
                            fprintf(stderr,"%s: no nodes, break\n", __func__);
                            break;
                        }
                    }
                    if ((UintToArith256(pblock->nNonce) & 0xffff) == 0xffff)
                    {
                        fprintf(stderr,"%s: nonce & 0xffff == 0xffff, break\n", __func__);
                        break;
                    }
                    // Update nNonce and nTime
                    pblock->nNonce = ArithToUint256(UintToArith256(pblock->nNonce) + 1);
                    pblock->nBits = savebits;
                }

                rxdebug("%s: going to destroy rx VM\n");
                randomx_destroy_vm(myVM);
                rxdebug("%s: destroyed VM\n");

            }


   } catch (const boost::thread_interrupted&) {
       miningTimer.stop();
       c.disconnect();

       randomx_destroy_vm(myVM);
       LogPrintf("%s: destroyed vm via thread interrupt\n", __func__);
       randomx_release_dataset(randomxDataset);
       rxdebug("%s: released dataset via thread interrupt\n");
       randomx_release_cache(randomxCache);
       rxdebug("%s: released cache via thread interrupt\n");

       LogPrintf("HushRandomXMiner terminated\n");
       throw;
   } catch (const std::runtime_error &e) {
       miningTimer.stop();
       c.disconnect();
       fprintf(stderr,"RandomXMiner: runtime error: %s\n", e.what());

       randomx_destroy_vm(myVM);
       LogPrintf("%s: destroyed vm because of error\n", __func__);
       randomx_release_dataset(randomxDataset);
       rxdebug("%s: released dataset because of error\n");
       randomx_release_cache(randomxCache);
       rxdebug("%s: released cache because of error\n");

       return;
   }

   randomx_release_dataset(randomxDataset);
   rxdebug("%s: released dataset in normal exit\n");
   randomx_release_cache(randomxCache);
   rxdebug("%s: released cache in normal exit\n");
   miningTimer.stop();
   c.disconnect();
}

#ifdef ENABLE_WALLET
void static BitcoinMiner(CWallet *pwallet)
#else
void static BitcoinMiner()
#endif
{
    LogPrintf("HushMiner started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("hush-miner");
    const CChainParams& chainparams = Params();

#ifdef ENABLE_WALLET
    // Each thread has its own key
    CReserveKey reservekey(pwallet);
#endif

    // Each thread has its own counter
    unsigned int nExtraNonce = 0;

    unsigned int n = chainparams.EquihashN();
    unsigned int k = chainparams.EquihashK();
    uint8_t *script; uint64_t total; int32_t i,j,gpucount=HUSH_MAXGPUCOUNT,notaryid = -1;
    while ( (ASSETCHAIN_INIT == 0 || HUSH_INITDONE == 0) )
    {
        sleep(1);
        if ( hush_baseid(SMART_CHAIN_SYMBOL) < 0 )
            break;
    }
    if ( notaryid != My_notaryid )
        My_notaryid = notaryid;
    std::string solver;
    if ( ASSETCHAINS_NK[0] == 0 && ASSETCHAINS_NK[1] == 0 )
        solver = "tromp";
    else 
        solver = "default";
    assert(solver == "tromp" || solver == "default");
    LogPrint("pow", "Using Equihash solver \"%s\" with n = %u, k = %u\n", solver, n, k);
    if ( SMART_CHAIN_SYMBOL[0] != 0 )
        fprintf(stderr,"notaryid.%d Mining.%s with %s\n",notaryid,SMART_CHAIN_SYMBOL,solver.c_str());
    std::mutex m_cs;
    bool cancelSolver = false;
    boost::signals2::connection c = uiInterface.NotifyBlockTip.connect(
                                                                       [&m_cs, &cancelSolver](const uint256& hashNewTip) mutable {
                                                                           std::lock_guard<std::mutex> lock{m_cs};
                                                                           cancelSolver = true;
                                                                       }
                                                                       );
    miningTimer.start();

    try {
        if ( SMART_CHAIN_SYMBOL[0] != 0 )
            fprintf(stderr,"try %s Mining with %s\n",SMART_CHAIN_SYMBOL,solver.c_str());
        while (true)
        {
            if (chainparams.MiningRequiresPeers()) {
                //if ( ASSETCHAINS_SEED != 0 && chainActive.LastTip()->GetHeight() < 100 )
                //    break;
                // Busy-wait for the network to come online so we don't waste time mining
                // on an obsolete chain. In regtest mode we expect to fly solo.
                miningTimer.stop();
                do {
                    bool fvNodesEmpty;
                    {
                        //LOCK(cs_vNodes);
                        fvNodesEmpty = vNodes.empty();
                    }
                    if (!fvNodesEmpty )//&& !IsInitialBlockDownload())
                        break;
                    MilliSleep(15000);
                    //fprintf(stderr,"fvNodesEmpty %d IsInitialBlockDownload(%s) %d\n",(int32_t)fvNodesEmpty,SMART_CHAIN_SYMBOL,(int32_t)IsInitialBlockDownload());

                } while (true);
                //fprintf(stderr,"%s Found peers\n",SMART_CHAIN_SYMBOL);
                miningTimer.start();
            }
            //
            // Create new block
            //
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            CBlockIndex* pindexPrev = chainActive.LastTip();

            // If we don't have a valid chain tip to work from, wait and try again.
            if (pindexPrev == nullptr) {
                fprintf(stderr,"%s: null pindexPrev, trying again...\n",__func__);
                MilliSleep(1000);
                continue;
            }

            if ( Mining_height != pindexPrev->GetHeight()+1 )
            {
                Mining_height = pindexPrev->GetHeight()+1;
                Mining_start = (uint32_t)time(NULL);
            }
            if ( SMART_CHAIN_SYMBOL[0] != 0 && ASSETCHAINS_STAKED == 0 )
            {
                //fprintf(stderr,"%s create new block ht.%d\n",SMART_CHAIN_SYMBOL,Mining_height);
                //sleep(3);
            }

#ifdef ENABLE_WALLET
            // notaries always default to staking
            CBlockTemplate *ptr = CreateNewBlockWithKey(reservekey, pindexPrev->GetHeight()+1, gpucount, ASSETCHAINS_STAKED != 0 && HUSH_MININGTHREADS == 0);
#else
            CBlockTemplate *ptr = CreateNewBlockWithKey();
#endif
            if ( ptr == 0 )
            {
                if ( !GetBoolArg("-gen",false))
                {
                    miningTimer.stop();
                    c.disconnect();
                    LogPrintf("HushMiner terminated\n");
                    return;
                }
                static uint32_t counter;
                if ( counter++ < 10 && ASSETCHAINS_STAKED == 0 )
                    fprintf(stderr,"created illegal blockB, retry\n");
                sleep(1);
                continue;
            }
            //fprintf(stderr,"get template\n");
            unique_ptr<CBlockTemplate> pblocktemplate(ptr);
            if (!pblocktemplate.get())
            {
                if (GetArg("-mineraddress", "").empty()) {
                    LogPrintf("Error in HushMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
                } else {
                    // Should never reach here, because -mineraddress validity is checked in init.cpp
                    LogPrintf("Error in HushMiner: Invalid -mineraddress\n");
                }
                return;
            }
            CBlock *pblock = &pblocktemplate->block;
            if ( SMART_CHAIN_SYMBOL[0] != 0 )
            {
                if ( ASSETCHAINS_REWARD[0] == 0 && !ASSETCHAINS_LASTERA )
                {
                    if ( pblock->vtx.size() == 1 && pblock->vtx[0].vout.size() == 1 && Mining_height > ASSETCHAINS_MINHEIGHT )
                    {
                        static uint32_t counter;
                        if ( counter++ < 10 )
                            fprintf(stderr,"skip generating %s on-demand block, no tx avail\n",SMART_CHAIN_SYMBOL);
                        sleep(10);
                        continue;
                    } else fprintf(stderr,"%s vouts.%d mining.%d vs %d\n",SMART_CHAIN_SYMBOL,(int32_t)pblock->vtx[0].vout.size(),Mining_height,ASSETCHAINS_MINHEIGHT);
                }
            }
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);
            //fprintf(stderr,"Running HushMiner.%s with %u transactions in block\n",solver.c_str(),(int32_t)pblock->vtx.size());
            LogPrintf("Running HushMiner.%s with %u transactions in block (%u bytes)\n",solver.c_str(),pblock->vtx.size(),::GetSerializeSize(*pblock,SER_NETWORK,PROTOCOL_VERSION));

            // Search
            uint32_t savebits; int64_t nStart = GetTime();
            pblock->nBits         = GetNextWorkRequired(pindexPrev, pblock, Params().GetConsensus());
            savebits = pblock->nBits;
            HASHTarget = arith_uint256().SetCompact(savebits);
            roundrobin_delay = ROUNDROBIN_DELAY;
            Mining_start = 0;

            //else if ( ASSETCHAINS_ADAPTIVEPOW > 0 )
            //    HASHTarget_POW = hush_adaptivepow_target(Mining_height,HASHTarget,pblock->nTime);
            gotinvalid = 0;
            while (true)
            {
                //fprintf(stderr,"gotinvalid.%d\n",gotinvalid);
                if ( gotinvalid != 0 )
                    break;
                hush_longestchain();
                // Hash state
                HUSH_CHOSEN_ONE = 0;

                crypto_generichash_blake2b_state state;
                EhInitialiseState(n, k, state);
                // I = the block header minus nonce and solution.
                CEquihashInput I{*pblock};
                CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                ss << I;
                // H(I||...
                crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());
                // H(I||V||...
                crypto_generichash_blake2b_state curr_state;
                curr_state = state;
                crypto_generichash_blake2b_update(&curr_state,pblock->nNonce.begin(),pblock->nNonce.size());
                // (x_1, x_2, ...) = A(I, V, n, k)
                LogPrint("pow", "Running Equihash solver \"%s\" with nNonce = %s\n",solver, pblock->nNonce.ToString());
                arith_uint256 hashTarget;
                if ( HUSH_MININGTHREADS > 0 && ASSETCHAINS_STAKED > 0 && ASSETCHAINS_STAKED < 100 && Mining_height > 10 )
                    hashTarget = HASHTarget_POW;
                //else if ( ASSETCHAINS_ADAPTIVEPOW > 0 )
                //    hashTarget = HASHTarget_POW;
                else hashTarget = HASHTarget;
                std::function<bool(std::vector<unsigned char>)> validBlock =
#ifdef ENABLE_WALLET
                [&pblock, &hashTarget, &pwallet, &reservekey, &m_cs, &cancelSolver, &chainparams]
#else
                [&pblock, &hashTarget, &m_cs, &cancelSolver, &chainparams]
#endif
                (std::vector<unsigned char> soln) {
                    int32_t z; arith_uint256 h; CBlock B;
                    // Write the solution to the hash and compute the result.
                    LogPrint("pow", "- Checking solution against target\n");
                    pblock->nSolution = soln;
                    solutionTargetChecks.increment();
                    // fprintf(stderr, "%s: solutionTargetChecks=%lu\n", __func__, solutionTargetChecks.get());
                    B = *pblock;
                    h = UintToArith256(B.GetHash());
                    /*for (z=31; z>=16; z--)
                        fprintf(stderr,"%02x",((uint8_t *)&h)[z]);
                    fprintf(stderr," mined ");
                    for (z=31; z>=16; z--)
                        fprintf(stderr,"%02x",((uint8_t *)&HASHTarget)[z]);
                    fprintf(stderr," hashTarget ");
                    for (z=31; z>=16; z--)
                        fprintf(stderr,"%02x",((uint8_t *)&HASHTarget_POW)[z]);
                    fprintf(stderr," POW\n");*/
                    if ( h > hashTarget )
                    {
                        //if ( ASSETCHAINS_STAKED != 0 && HUSH_MININGTHREADS == 0 )
                          //  MilliSleep(30);
                        return false;
                    }
                    if ( IS_HUSH_NOTARY != 0 && B.nTime > GetTime() )
                    {
                        //fprintf(stderr,"need to wait %d seconds to submit block\n",(int32_t)(B.nTime - GetTime()));
                        while ( GetTime() < B.nTime-2 )
                        {
                            sleep(1);
                            if ( chainActive.LastTip()->GetHeight() >= Mining_height )
                            {
                                fprintf(stderr,"new block arrived\n");
                                return(false);
                            }
                        }
                    }
                    if ( ASSETCHAINS_STAKED == 0 )
                    {
                        if ( IS_HUSH_NOTARY != 0 )
                        {
                            int32_t r;
                            if ( (r= ((Mining_height + NOTARY_PUBKEY33[16]) % 64) / 8) > 0 )
                                MilliSleep((rand() % (r * 1000)) + 1000);
                        }
                    }
                    else
                    {
                        uint256 tmp = B.GetHash();
                        int32_t z; for (z=31; z>=0; z--)
                            fprintf(stderr,"%02x",((uint8_t *)&tmp)[z]);
                        fprintf(stderr," mined %s block %d!\n",SMART_CHAIN_SYMBOL,Mining_height);
                    }
                    CValidationState state;
                    if ( !TestBlockValidity(state,B, chainActive.LastTip(), true, false))
                    {
                        h = UintToArith256(B.GetHash());
                        //for (z=31; z>=0; z--)
                        //    fprintf(stderr,"%02x",((uint8_t *)&h)[z]);
                        //fprintf(stderr," Invalid block mined, try again\n");
                        gotinvalid = 1;
                        return(false);
                    }
                    HUSH_CHOSEN_ONE = 1;
                    // Found a solution
                    SetThreadPriority(THREAD_PRIORITY_NORMAL);
                    LogPrintf("HushMiner:\n");
                    LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", B.GetHash().GetHex(), HASHTarget.GetHex());
#ifdef ENABLE_WALLET
                    if (ProcessBlockFound(&B, *pwallet, reservekey)) {
#else
                        if (ProcessBlockFound(&B)) {
#endif
                            // Ignore chain updates caused by us
                            std::lock_guard<std::mutex> lock{m_cs};
                            cancelSolver = false;
                        }
                        HUSH_CHOSEN_ONE = 0;
                        SetThreadPriority(THREAD_PRIORITY_LOWEST);
                        // In regression test mode, stop mining after a block is found.
                        if (chainparams.MineBlocksOnDemand()) {
                            // Increment here because throwing skips the call below
                            ehSolverRuns.increment();
                            throw boost::thread_interrupted();
                        }
                        return true;
                    };
                    std::function<bool(EhSolverCancelCheck)> cancelled = [&m_cs, &cancelSolver](EhSolverCancelCheck pos) {
                        std::lock_guard<std::mutex> lock{m_cs};
                        return cancelSolver;
                    };
                    // TODO: factor this out into a function with the same API for each solver.
                    if (solver == "tromp" ) { //&& notaryid >= 0 ) {
                        // Create solver and initialize it.
                        equi eq(1);
                        eq.setstate(&curr_state);

                        // Initialization done, start algo driver.
                        eq.digit0(0);
                        eq.xfull = eq.bfull = eq.hfull = 0;
                        eq.showbsizes(0);
                        for (u32 r = 1; r < WK; r++) {
                            (r&1) ? eq.digitodd(r, 0) : eq.digiteven(r, 0);
                            eq.xfull = eq.bfull = eq.hfull = 0;
                            eq.showbsizes(r);
                        }
                        eq.digitK(0);
                        ehSolverRuns.increment();

                        // Convert solution indices to byte array (decompress) and pass it to validBlock method.
                        for (size_t s = 0; s < std::min(MAXSOLS, eq.nsols); s++) {
                            LogPrint("pow", "Checking solution %d\n", s+1);
                            std::vector<eh_index> index_vector(PROOFSIZE);
                            for (size_t i = 0; i < PROOFSIZE; i++) {
                                index_vector[i] = eq.sols[s][i];
                            }
                            std::vector<unsigned char> sol_char = GetMinimalFromIndices(index_vector, DIGITBITS);

                            if (validBlock(sol_char)) {
                                // If we find a POW solution, do not try other solutions
                                // because they become invalid as we created a new block in blockchain.
                                break;
                            }
                        }
                    } else {
                        try {
                            // If we find a valid block, we rebuild
                            bool found = EhOptimisedSolve(n, k, curr_state, validBlock, cancelled);
                            ehSolverRuns.increment();
                            if (found) {
                                int32_t i; uint256 hash = pblock->GetHash();
                                //for (i=0; i<32; i++)
                                //    fprintf(stderr,"%02x",((uint8_t *)&hash)[i]);
                                //fprintf(stderr," <- %s Block found %d\n",SMART_CHAIN_SYMBOL,Mining_height);
                                //FOUND_BLOCK = 1;
                                //HUSH_MAYBEMINED = Mining_height;
                                break;
                            }
                        } catch (EhSolverCancelledException&) {
                            LogPrint("pow", "Equihash solver cancelled\n");
                            std::lock_guard<std::mutex> lock{m_cs};
                            cancelSolver = false;
                        }
                    }

                    // Check for stop or if block needs to be rebuilt
                    boost::this_thread::interruption_point();
                    // Regtest mode doesn't require peers
                    /*if ( FOUND_BLOCK != 0 )
                    {
                        FOUND_BLOCK = 0;
                        fprintf(stderr,"FOUND_BLOCK!\n");
                        //sleep(2000);
                    } */
                    if (vNodes.empty() && chainparams.MiningRequiresPeers())
                    {
                        if ( SMART_CHAIN_SYMBOL[0] == 0 || Mining_height > ASSETCHAINS_MINHEIGHT )
                        {
                            fprintf(stderr,"no nodes, break\n");
                            break;
                        }
                    }
                    if ((UintToArith256(pblock->nNonce) & 0xffff) == 0xffff)
                    {
                        //if ( 0 && SMART_CHAIN_SYMBOL[0] != 0 )
                        fprintf(stderr,"0xffff, break\n");
                        break;
                    }
                    if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                    {
                        if ( 0 && SMART_CHAIN_SYMBOL[0] != 0 )
                            fprintf(stderr,"timeout, break\n");
                        break;
                    }
                    if ( pindexPrev != chainActive.LastTip() )
                    {
                        if ( 0 && SMART_CHAIN_SYMBOL[0] != 0 )
                            fprintf(stderr,"Tip advanced, break\n");
                        break;
                    }
                    // Update nNonce and nTime
                    pblock->nNonce = ArithToUint256(UintToArith256(pblock->nNonce) + 1);
                    pblock->nBits = savebits;
                    if ( ASSETCHAINS_ADAPTIVEPOW > 0 )
                    {
                        UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
                        HASHTarget.SetCompact(pblock->nBits);
                        hashTarget = HASHTarget;
                        savebits = pblock->nBits;
                        //hashTarget = HASHTarget_POW = hush_adaptivepow_target(Mining_height,HASHTarget,pblock->nTime);
                    }
                    /*if ( NOTARY_PUBKEY33[0] == 0 )
                    {
                        int32_t percPoS;
                        UpdateTime(pblock, consensusParams, pindexPrev);
                        if (consensusParams.fPowAllowMinDifficultyBlocks)
                        {
                            // Changing pblock->nTime can change work required on testnet:
                            HASHTarget.SetCompact(pblock->nBits);
                            HASHTarget_POW = hush_PoWtarget(&percPoS,HASHTarget,Mining_height,ASSETCHAINS_STAKED);
                        }
                    }*/
                }
            }
        }
        catch (const boost::thread_interrupted&)
        {
            miningTimer.stop();
            c.disconnect();
            LogPrintf("HushMiner terminated\n");
            throw;
        }
        catch (const std::runtime_error &e)
        {
            miningTimer.stop();
            c.disconnect();
            LogPrintf("HushMiner runtime error: %s\n", e.what());
            return;
        }

        miningTimer.stop();
        c.disconnect();
    }

#ifdef ENABLE_WALLET
    void GenerateBitcoins(bool fGenerate, CWallet* pwallet, int nThreads)
#else
    void GenerateBitcoins(bool fGenerate, int nThreads)
#endif
    {
        static boost::thread_group* minerThreads = NULL;

        if (nThreads < 0)
            nThreads = GetNumCores();

        if (minerThreads != NULL)
        {
            minerThreads->interrupt_all();
            delete minerThreads;
            minerThreads = NULL;
        }

        if(fDebug)
            fprintf(stderr,"%s: nThreads.%d fGenerate.%d\n",__FUNCTION__, (int32_t)nThreads,fGenerate);

        if (nThreads == 0)
            return;
        if (!fGenerate)
            return;
        if (pwallet == NULL)
            return;

        minerThreads = new boost::thread_group();

        for (int i = 0; i < nThreads; i++) {
#ifdef ENABLE_WALLET
            if ( ASSETCHAINS_ALGO == ASSETCHAINS_EQUIHASH ) {
                minerThreads->create_thread(boost::bind(&BitcoinMiner, pwallet));
            } else if (ASSETCHAINS_ALGO == ASSETCHAINS_RANDOMX ) {
                minerThreads->create_thread(boost::bind(&RandomXMiner, pwallet));
            }
#else
            if (ASSETCHAINS_ALGO == ASSETCHAINS_EQUIHASH ) {
                minerThreads->create_thread(&BitcoinMiner);
            } else if (ASSETCHAINS_ALGO == ASSETCHAINS_RANDOMX) {
                minerThreads->create_thread(&RandomXMiner);
            }
#endif
        }
    }

#endif // ENABLE_MINING
