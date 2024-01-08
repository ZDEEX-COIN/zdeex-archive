// Copyright (c) 2020 The Hush developers
// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

#ifndef HUSH_WALLET_RPCHUSHWALLET_H
#define HUSH_WALLET_RPCHUSHWALLET_H

struct balancestruct {
  CAmount confirmed;
  CAmount unconfirmed;
  CAmount locked;
  CAmount immature;
};

void zsTxSpendsToJSON(const CWalletTx& wtx, UniValue& spends, CAmount& totalSpends, CAmount& filteredSpends, const std::string& strAddress, bool filterByAddress);
void zsTxReceivedToJSON(const CWalletTx& wtx, UniValue& received, CAmount& totalReceived, const std::string& strAddress, bool filterByAddress);
void zsTxSendsToJSON(const CWalletTx& wtx, UniValue& sends, CAmount& totalSends, const std::string& strAddress, bool filterByAddress);
void zsWalletTxJSON(const CWalletTx& wtx, UniValue& ret, const std::string strAddress, bool fBool, const int returnType);


#endif //HUSH_WALLET_RPCWALLET_H
