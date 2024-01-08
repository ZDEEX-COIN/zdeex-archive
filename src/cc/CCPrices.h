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


#ifndef CC_PRICES_H
#define CC_PRICES_H

#include "hush_defs.h"
#include "CCinclude.h"

int32_t hush_priceget(int64_t *buf64,int32_t ind,int32_t height,int32_t numblocks);
extern void GetHushEarlytxidScriptPub();
extern CScript HUSH_EARLYTXID_SCRIPTPUB;

// #define PRICES_DAYWINDOW ((3600*24/ASSETCHAINS_BLOCKTIME) + 1) // defined in hush_defs.h
#define PRICES_TXFEE 10000
#define PRICES_MAXLEVERAGE 777
#define PRICES_SMOOTHWIDTH 1
#define HUSH_MAXPRICES 2048 // must be power of 2 and less than 8192
#define HUSH_PRICEMASK (~(HUSH_MAXPRICES -  1))     // actually 1111 1000 0000 0000
#define PRICES_WEIGHT (HUSH_MAXPRICES * 1)            //          0000 1000 0000 0000
#define PRICES_MULT (HUSH_MAXPRICES * 2)              //          0001 0000 0000 0000
#define PRICES_DIV (HUSH_MAXPRICES * 3)               //          0001 1000 0000 0000
#define PRICES_INV (HUSH_MAXPRICES * 4)               //          0010 0000 0000 0000
#define PRICES_MDD (HUSH_MAXPRICES * 5)               //          0010 1000 0000 0000
#define PRICES_MMD (HUSH_MAXPRICES * 6)               //          0011 0000 0000 0000
#define PRICES_MMM (HUSH_MAXPRICES * 7)               //          0011 1000 0000 0000
#define PRICES_DDD (HUSH_MAXPRICES * 8)               //          0100 0000 0000 0000

//#define PRICES_NORMFACTOR   (int64_t)(SATOSHIDEN)
//#define PRICES_POINTFACTOR   (int64_t)10000

#define PRICES_REVSHAREDUST 10000
#define PRICES_SUBREVSHAREFEE(amount) ((amount) * 199 / 200)    // revshare fee percentage == 0.005
#define PRICES_MINAVAILFUNDFRACTION  0.1                             // leveraged bet limit < fund fraction

bool PricesValidate(struct CCcontract_info *cp,Eval* eval,const CTransaction &tx, uint32_t nIn);

// CCcustom
UniValue PricesBet(int64_t txfee,int64_t amount,int16_t leverage,std::vector<std::string> synthetic);
UniValue PricesAddFunding(int64_t txfee,uint256 bettxid,int64_t amount);
UniValue PricesSetcostbasis(int64_t txfee,uint256 bettxid);
UniValue PricesRekt(int64_t txfee,uint256 bettxid,int32_t rektheight);
UniValue PricesCashout(int64_t txfee,uint256 bettxid);
UniValue PricesInfo(uint256 bettxid,int32_t refheight);
UniValue PricesList(uint32_t filter, CPubKey mypk);
UniValue PricesGetOrderbook();
UniValue PricesRefillFund(int64_t amount);


#endif
