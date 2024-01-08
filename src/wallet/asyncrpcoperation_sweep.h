// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
#include "amount.h"
#include "asyncrpcoperation.h"
#include "univalue.h"
#include "zcash/Address.hpp"
#include "zcash/zip32.h"

//Default fee used for sweep transactions
static const CAmount DEFAULT_SWEEP_FEE = 10000;
extern CAmount fSweepTxFee;
extern bool fSweepMapUsed;
extern boost::optional<libzcash::SaplingPaymentAddress> rpcSweepAddress;

class AsyncRPCOperation_sweep : public AsyncRPCOperation
{
public:
    AsyncRPCOperation_sweep(int targetHeight, bool fromRpc = false);
    virtual ~AsyncRPCOperation_sweep();

    // We don't want to be copied or moved around
    AsyncRPCOperation_sweep(AsyncRPCOperation_sweep const&) = delete;            // Copy construct
    AsyncRPCOperation_sweep(AsyncRPCOperation_sweep&&) = delete;                 // Move construct
    AsyncRPCOperation_sweep& operator=(AsyncRPCOperation_sweep const&) = delete; // Copy assign
    AsyncRPCOperation_sweep& operator=(AsyncRPCOperation_sweep&&) = delete;      // Move assign

    virtual void main();

    virtual void cancel();

    virtual UniValue getStatus() const;

private:
    int targetHeight_;
    bool fromRPC_;

    bool main_impl();

    void setSweepResult(int numTxCreated, const CAmount& amountSwept, const std::vector<std::string>& sweepTxIds);

};
