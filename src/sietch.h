/******************************************************************************
 * Copyright © 2016-2023 The Hush developers                                  *
 *                                                                            *
 * See the AUTHORS and LICENSE files at                                       *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * this software, including this file may be copied, modified, propagated     *
 * or distributed except according to the terms contained in the GPLv3        *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 * https://hush.is
 *                                                                            *
 ******************************************************************************/

#ifndef SIETCH_H
#define SIETCH_H

string newSietchZaddr() {
    bool addToWallet = false;
    auto zaddr       = EncodePaymentAddress(pwalletMain->GenerateNewSaplingZKey(addToWallet));
    return zaddr;
}

SendManyRecipient newSietchRecipient(string zaddr) {
    int nAmount = 0;
    // TODO: Should we randomize length of data, perhaps into buckets?
    // Sietch zouts have random data in their memos so they are indistinguishable from
    // encrypted data being stored in the memo field
    char hex[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    // memo field is 512 bytes or 1024 hex chars
    char str[1024];
    for(int i=0;i<1024;i++) {
      str[i] = hex[GetRandInt(16)];
    }
    str[1024] = 0;
    return SendManyRecipient( zaddr, nAmount, string(str) );
}

string randomSietchZaddr() {
    auto zdust = libzcash::SaplingSpendingKey::random().default_address();
    return EncodePaymentAddress(zdust);
}

#endif
