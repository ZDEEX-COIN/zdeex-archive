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

#include "hush_defs.h"

int32_t PAX_pubkey(int32_t rwflag,uint8_t *pubkey33,uint8_t *addrtypep,uint8_t rmd160[20],char fiat[4],uint8_t *shortflagp,int64_t *fiatoshisp)
{
    return(33);
}

double PAX_val(uint32_t pval,int32_t baseid)
{
    return(0.);
}

void hush_pvals(int32_t height,uint32_t *pvals,uint8_t numpvals)
{
}

uint64_t hush_paxpriceB(uint64_t seed,int32_t height,char *base,char *rel,uint64_t basevolume)
{
    return 0;
}

uint64_t hush_paxprice(uint64_t *seedp,int32_t height,char *base,char *rel,uint64_t basevolume)
{
    return 0;
}

int32_t hush_paxprices(int32_t *heights,uint64_t *prices,int32_t max,char *base,char *rel)
{
    return 0;
}

void hush_paxpricefeed(int32_t height,uint8_t *pricefeed,int32_t opretlen)
{
}

uint64_t PAX_fiatdest(uint64_t *seedp,int32_t tokomodo,char *destaddr,uint8_t pubkey33[33],char *coinaddr,int32_t height,char *origbase,int64_t fiatoshis)
{
    return 0;
}
