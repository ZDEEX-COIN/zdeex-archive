// Copyright (c) 2016-2023 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
#include "assert.h"
#include "boost/variant/static_visitor.hpp"
#include "asyncrpcoperation_sweep.h"
#include "init.h"
#include "key_io.h"
#include "rpc/protocol.h"
#include "random.h"
#include "sync.h"
#include "tinyformat.h"
#include "transaction_builder.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet.h"

extern string randomSietchZaddr();

CAmount fSweepTxFee = DEFAULT_SWEEP_FEE;
bool fSweepMapUsed = false;
const int SWEEP_EXPIRY_DELTA = 15;
boost::optional<libzcash::SaplingPaymentAddress> rpcSweepAddress;

AsyncRPCOperation_sweep::AsyncRPCOperation_sweep(int targetHeight, bool fromRpc) : targetHeight_(targetHeight), fromRPC_(fromRpc){}

AsyncRPCOperation_sweep::~AsyncRPCOperation_sweep() {}

void AsyncRPCOperation_sweep::main() {
    if (isCancelled())
        return;

    set_state(OperationStatus::EXECUTING);
    start_execution_clock();

    bool success = false;

    try {
        success = main_impl();
    } catch (const UniValue& objError) {
        int code = find_value(objError, "code").get_int();
        std::string message = find_value(objError, "message").get_str();
        set_error_code(code);
        set_error_message(message);
    } catch (const runtime_error& e) {
        set_error_code(-1);
        set_error_message("runtime error: " + string(e.what()));
    } catch (const logic_error& e) {
        set_error_code(-1);
        set_error_message("logic error: " + string(e.what()));
    } catch (const exception& e) {
        set_error_code(-1);
        set_error_message("general exception: " + string(e.what()));
    } catch (...) {
        set_error_code(-2);
        set_error_message("unknown error");
    }

    stop_execution_clock();

    if (success) {
        set_state(OperationStatus::SUCCESS);
    } else {
        set_state(OperationStatus::FAILED);
    }

    std::string s = strprintf("%s: Sweep operation finished. (status=%s", getId(), getStateAsString());
    if (success) {
        s += strprintf(", success)\n");
    } else {
        s += strprintf(", error=%s)\n", getErrorMessage());
    }

    LogPrintf("%s", s);
}

// Is this zaddr excluded from zsweep ?
bool IsExcludedAddress(libzcash::SaplingPaymentAddress zaddr) {
    for( auto & sweepExcludeAddress : pwalletMain->sweepExcludeAddresses ) {
        auto zAddressExclude = DecodePaymentAddress(sweepExcludeAddress);

        if (boost::get<libzcash::SaplingPaymentAddress>(&zAddressExclude) != nullptr) {
            auto excludeAddress = boost::get<libzcash::SaplingPaymentAddress>(zAddressExclude);
            if (excludeAddress == zaddr) {
                return true;
            }
        } else {
            // This is an invalid sapling zaddr
            LogPrintf("%s: Invalid zsweepexclude zaddr %s, ignoring\n", sweepExcludeAddress);
            continue;
        }

    }

    return false;
}

bool AsyncRPCOperation_sweep::main_impl() {
    bool status=true;
    auto opid=getId();
    LogPrintf("%s: Beginning asyncrpcoperation_sweep.\n", getId());
    auto consensusParams = Params().GetConsensus();
    auto nextActivationHeight = NextActivationHeight(targetHeight_, consensusParams);
    if (nextActivationHeight && targetHeight_ + SWEEP_EXPIRY_DELTA >= nextActivationHeight.get()) {
        LogPrintf("%s: Sweep txs would be created before a NU activation but may expire after. Skipping this round.\n", getId());
        setSweepResult(0, 0, std::vector<std::string>());
        return true;
    }

    std::vector<SaplingNoteEntry> saplingEntries;
    libzcash::SaplingPaymentAddress sweepAddress;
    std::map<libzcash::SaplingPaymentAddress, std::vector<SaplingNoteEntry>> mapAddresses;

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        pwalletMain->GetFilteredNotes(saplingEntries, "", 11);

        if (!fromRPC_) {
            if (fSweepMapUsed) {
                const vector<string>& v = mapMultiArgs["-zsweepaddress"];
                for(int i = 0; i < v.size(); i++) {
                    auto zAddress = DecodePaymentAddress(v[i]);
                    if (boost::get<libzcash::SaplingPaymentAddress>(&zAddress) != nullptr) {
                        sweepAddress = boost::get<libzcash::SaplingPaymentAddress>(zAddress);
                    } else {
                        LogPrintf("%s: Invalid zsweepaddress configured, exiting\n", opid);
                        return false;
                    }
                }
            } else {
                LogPrintf("%s: No zsweepaddress configured, exiting\n", opid);
                return false;
            }
        } else {
            if (boost::get<libzcash::SaplingPaymentAddress>(&rpcSweepAddress) != nullptr) {
                sweepAddress = boost::get<libzcash::SaplingPaymentAddress>(rpcSweepAddress);
            } else {
                LogPrintf("%s: Invalid zsweepaddress, exiting\n", opid);
                return false;
            }
        }

        // Map all notes (zutxos) by address
        for (auto & entry : saplingEntries) {
            // do not need to sweep Excluded Addresses
            if(IsExcludedAddress(entry.address)) {
                continue;
            }

            // do not need to sweep the sweepAddress as that is the destination
            if (sweepAddress == entry.address) {
                continue;
            } else {
                std::map<libzcash::SaplingPaymentAddress, std::vector<SaplingNoteEntry>>::iterator it;
                it = mapAddresses.find(entry.address);
                if (it != mapAddresses.end()) {
                    it->second.push_back(entry);
                } else {
                    std::vector<SaplingNoteEntry> entries;
                    entries.push_back(entry);
                    mapAddresses[entry.address] = entries;
                }
            }
        }
    }

    int numTxCreated = 0;
    std::vector<std::string> sweepTxIds;
    CAmount amountSwept = 0;
    CCoinsViewCache coinsView(pcoinsTip);
    bool sweepComplete = true;

    for (std::map<libzcash::SaplingPaymentAddress, std::vector<SaplingNoteEntry>>::iterator it = mapAddresses.begin(); it != mapAddresses.end(); it++) {
        auto addr = (*it).first;
        auto saplingEntries = (*it).second;

        libzcash::SaplingExtendedSpendingKey extsk;
        if (pwalletMain->GetSaplingExtendedSpendingKey(addr, extsk)) {

            std::vector<SaplingNoteEntry> fromNotes;
            CAmount amountToSend = 0;
            int maxInputs = GetArg("-zsweepmaxinputs", 8);
            if( maxInputs > 100 || maxInputs < 5) {
                fprintf(stderr,"%s: Invalid zsweep maxinputs=%d is >100 and <5, setting to default of 8\n", __func__, maxInputs);
                maxInputs = 8;
            }

            //Count Notes availiable for this address
            int targetCount = 0;
            int noteCount   = 0;
            for (const SaplingNoteEntry& saplingEntry : saplingEntries) {

              libzcash::SaplingIncomingViewingKey ivk;
              pwalletMain->GetSaplingIncomingViewingKey(boost::get<libzcash::SaplingPaymentAddress>(saplingEntry.address), ivk);

              if (ivk == extsk.expsk.full_viewing_key().in_viewing_key() && saplingEntry.address == addr) {
                noteCount++;
              }
            }

            //Don't sweep if under the threshold
            if (noteCount <= targetCount){
                continue;
            }

            //if we make it here then we need to sweep and the routine is considered incomplete
            sweepComplete = false;

            for (const SaplingNoteEntry& saplingEntry : saplingEntries) {

                libzcash::SaplingIncomingViewingKey ivk;
                pwalletMain->GetSaplingIncomingViewingKey(boost::get<libzcash::SaplingPaymentAddress>(saplingEntry.address), ivk);

                //Select Notes from that same address we will be sending to.
                if (ivk == extsk.expsk.full_viewing_key().in_viewing_key() && saplingEntry.address == addr) {
                  amountToSend += CAmount(saplingEntry.note.value());
                  fromNotes.push_back(saplingEntry);
                }

                if (fromNotes.size() >= maxInputs)
                  break;

            }

            int minQuantity = 1;
            if (fromNotes.size() < minQuantity)
              continue;

            CAmount fee = fSweepTxFee;
            if (amountToSend <= fSweepTxFee) {
                LogPrintf("%s: Amount to send %s is <= fee, using fee=0", getId(), FormatMoney(amountToSend));
                fee = 0;
            }

            auto builder = TransactionBuilder(consensusParams, targetHeight_, pwalletMain);
            {
                LOCK2(cs_main, pwalletMain->cs_wallet);
                builder.SetExpiryHeight(chainActive.Tip()->GetHeight()+ SWEEP_EXPIRY_DELTA);
            }
            LogPrintf("%s: Beginning creating transaction with Sapling output amount=%s\n", getId(), FormatMoney(amountToSend - fee));

            // Select Sapling notes
            std::vector<SaplingOutPoint> ops;
            std::vector<libzcash::SaplingNote> notes;
            for (auto fromNote : fromNotes) {
                ops.push_back(fromNote.op);
                notes.push_back(fromNote.note);
            }

            // Fetch Sapling anchor and witnesses
            uint256 anchor;
            std::vector<boost::optional<SaplingWitness>> witnesses;
            {
                LOCK2(cs_main, pwalletMain->cs_wallet);
                pwalletMain->GetSaplingNoteWitnesses(ops, witnesses, anchor);
            }

            // Add Sapling spends
            for (size_t i = 0; i < notes.size(); i++) {
                if (!witnesses[i]) {
                    LogPrintf("%s: Missing Witnesses! Stopping.\n", getId());
                    break;
                }
                builder.AddSaplingSpend(extsk.expsk, notes[i], anchor, witnesses[i].get());
            }

            builder.SetFee(fee);
            builder.AddSaplingOutput(extsk.expsk.ovk, sweepAddress, amountToSend - fee);

            // Add sietch zouts
            int ZOUTS = 7;
            for(size_t i = 0; i < ZOUTS; i++) {
                // In Privacy Zdust We Trust -- Duke
                string zdust = randomSietchZaddr();
                auto zaddr   = DecodePaymentAddress(zdust);
                if (IsValidPaymentAddress(zaddr)) {
                    CAmount amount=0;
                    auto sietchZoutput = boost::get<libzcash::SaplingPaymentAddress>(zaddr);
                    LogPrint("zrpcunsafe", "%s: Adding Sietch zdust output %d\n", __func__, i); //  %d %s amount=%li\n", __func__, i, zaddr, amount);

                    builder.AddSaplingOutput(extsk.expsk.ovk, sietchZoutput, amount);
                } else {
                    LogPrintf("%s: Invalid payment address %s! Stopping.\n", __func__, zdust);
                    status = false;
                    break;
                }
            }
            LogPrint("zrpcunsafe", "%s: Done adding %d sietch zouts\n", __func__, ZOUTS);

            auto maybe_tx = builder.Build();
            if (!maybe_tx) {
                LogPrintf("%s: Failed to build transaction %s.\n",__func__, getId());
                status=false;
                break;
            }
            CTransaction tx = maybe_tx.get();

            if (isCancelled()) {
                LogPrintf("%s: Canceled. Stopping.\n", getId());
                break;
            }

            if (pwalletMain->CommitAutomatedTx(tx)) {
                LogPrintf("%s: Committed sweep transaction with txid=%s\n", getId(), tx.GetHash().ToString());
                amountSwept += amountToSend - fee;
                sweepTxIds.push_back(tx.GetHash().ToString());
                numTxCreated++;
            } else {
                LogPrintf("%s: Sweep transaction FAILED in CommitTransaction, txid=%s\n",opid , tx.GetHash().ToString());
                setSweepResult(numTxCreated, amountSwept, sweepTxIds);
                status = false;
                break;
            }
        }
    }

    if (sweepComplete) {
        pwalletMain->nextSweep     = pwalletMain->sweepInterval + chainActive.Tip()->GetHeight();
        pwalletMain->fSweepRunning = false;
    }

    LogPrintf("%s: Created %d transactions with total output amount=%s, status=%d\n", getId(), numTxCreated, FormatMoney(amountSwept), (int)status);
    setSweepResult(numTxCreated, amountSwept, sweepTxIds);
    return status;
}

void AsyncRPCOperation_sweep::setSweepResult(int numTxCreated, const CAmount& amountSwept, const std::vector<std::string>& sweepTxIds) {
    UniValue res(UniValue::VOBJ);
    res.push_back(Pair("num_tx_created", numTxCreated));
    res.push_back(Pair("amount_swept", FormatMoney(amountSwept)));
    UniValue txIds(UniValue::VARR);
    for (const std::string& txId : sweepTxIds) {
        txIds.push_back(txId);
    }
    res.push_back(Pair("sweep_txids", txIds));
    set_result(res);
}

void AsyncRPCOperation_sweep::cancel() {
    set_state(OperationStatus::CANCELLED);
}

UniValue AsyncRPCOperation_sweep::getStatus() const {
    UniValue v = AsyncRPCOperation::getStatus();
    UniValue obj = v.get_obj();
    obj.push_back(Pair("method", "sweep"));
    obj.push_back(Pair("target_height", targetHeight_));
    return obj;
}
