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
 *****************************************************************************/
//TODO: Finish deleting all this jl777 garbage. This CC will never function

#include "CCassets.h"
#include "CCPrices.h"
#include <cstdlib>
#include <gmp.h>

#define IS_CHARINSTR(c, str) (std::string(str).find((char)(c)) != std::string::npos)
#define NVOUT_CCMARKER 1
#define NVOUT_NORMALMARKER 3

typedef struct OneBetData {
    int64_t positionsize;
    int32_t firstheight;
    int64_t costbasis;
    int64_t profits;

    OneBetData() { positionsize = 0; firstheight = 0; costbasis = 0; profits = 0; }
} onebetdata;

typedef struct BetInfo {
    uint256 txid;
    int64_t averageCostbasis, firstprice, lastprice, liquidationprice, equity;
    int64_t exitfee;
    int32_t lastheight;
    int16_t leverage;
    bool isOpen, isRekt;
    uint256 tokenid;

    std::vector<uint16_t> vecparsed;
    std::vector<onebetdata> bets;
    CPubKey pk;

    bool isUp;

    BetInfo() { 
        averageCostbasis = firstprice = lastprice = liquidationprice = equity = 0;
        lastheight = 0;
        leverage = 0;
        exitfee = 0;
        isOpen = isRekt = isUp = false;
    }
} BetInfo;

typedef struct MatchedBookTotal {

    int64_t diffLeveragedPosition;

} MatchedBookTotal;

typedef struct TotalFund {
    int64_t totalFund;
    int64_t totalActiveBets;
    int64_t totalCashout;
    int64_t totalRekt;
    int64_t totalEquity;

    TotalFund() {
        totalFund = totalActiveBets = totalCashout = totalRekt = totalEquity = 0;
    }

} TotalFund;

int32_t prices_syntheticprofits(int64_t &costbasis, int32_t firstheight, int32_t height, int16_t leverage, std::vector<uint16_t> vec, int64_t positionsize, int64_t &profits, int64_t &outprice);
static bool prices_isacceptableamount(const std::vector<uint16_t> &vecparsed, int64_t amount, int16_t leverage);

// helpers:

// returns true if there are only digits and no alphas or slashes in 's'
inline bool is_weight_str(std::string s) {
    return false;
}


// start of consensus code

CScript prices_betopret(CPubKey mypk,int32_t height,int64_t amount,int16_t leverage,int64_t firstprice,std::vector<uint16_t> vec,uint256 tokenid)
{
    CScript opret;
    opret << OP_RETURN << E_MARSHAL(ss << EVAL_PRICES << 'B' << mypk << height << amount << leverage << firstprice << vec << tokenid);
    return(opret);
}

uint8_t prices_betopretdecode(CScript scriptPubKey,CPubKey &pk,int32_t &height,int64_t &amount,int16_t &leverage,int64_t &firstprice,std::vector<uint16_t> &vec,uint256 &tokenid)
{
    return(0);
}

CScript prices_addopret(uint256 bettxid,CPubKey mypk,int64_t amount)
{
    CScript opret;
    return(opret);
}

uint8_t prices_addopretdecode(CScript scriptPubKey,uint256 &bettxid,CPubKey &pk,int64_t &amount)
{
    return(0);
}

CScript prices_costbasisopret(uint256 bettxid,CPubKey mypk,int32_t height,int64_t costbasis)
{
    CScript opret;
    return(opret);
}

uint8_t prices_costbasisopretdecode(CScript scriptPubKey,uint256 &bettxid,CPubKey &pk,int32_t &height,int64_t &costbasis)
{
    return(0);
}

CScript prices_finalopret(bool isRekt, uint256 bettxid, CPubKey pk, int32_t lastheight, int64_t costbasis, int64_t lastprice, int64_t liquidationprice, int64_t equity, int64_t exitfee, uint32_t nonce)
{
    CScript opret;
    return(opret);
}

uint8_t prices_finalopretdecode(CScript scriptPubKey, uint256 &bettxid,  CPubKey &pk, int32_t &lastheight, int64_t &costbasis, int64_t &lastprice, int64_t &liquidationprice, int64_t &equity, int64_t &exitfee)
{
    return(0);
}

// price opret basic validation and retrieval
static uint8_t PricesCheckOpret(const CTransaction & tx, vscript_t &opret)
{
    return (uint8_t)0;
}

// validate bet tx helper
static bool ValidateBetTx(struct CCcontract_info *cp, Eval *eval, const CTransaction & bettx)
{
    return true;
}

// validate add funding tx helper
static bool ValidateAddFundingTx(struct CCcontract_info *cp, Eval *eval, const CTransaction & addfundingtx, const CTransaction & vintx)
{
    return true;
}


// validate final tx helper
static bool ValidateFinalTx(struct CCcontract_info *cp, Eval *eval, const CTransaction & finaltx, const CTransaction & bettx)
{
    return true;
}

bool PricesValidate(struct CCcontract_info *cp,Eval* eval,const CTransaction &tx, uint32_t nIn)
{
    return true;
}
// helper functions for rpc calls in rpcwallet.cpp

int64_t AddPricesInputs(struct CCcontract_info *cp, CMutableTransaction &mtx, char *destaddr, int64_t total, int32_t maxinputs)
{
    int64_t totalinputs = 0;
    return(totalinputs);
}

double prices_minmarginpercent(int16_t leverage)
{
    return 0.0;
}


UniValue prices_rawtxresult(UniValue &result, std::string rawtx, int32_t broadcastflag)
{
    return(result);
}

static std::string prices_getsourceexpression(const std::vector<uint16_t> &vec) {
    std::string expr;
    return expr;
}

// helper functions to get synthetic expression reduced:

// return s true and needed operand count if string is opcode
static bool prices_isopcode(const std::string &s, int &need)
{
    return false;
}

// split pair onto two quotes divided by "_" 
static void prices_splitpair(const std::string &pair, std::string &upperquote, std::string &bottomquote)
{
}

// invert pair like BTS_USD -> USD_BTC
static std::string prices_invertpair(const std::string &pair)
{
    std::string s;
    return s;
}

// invert pairs in operation accordingly to "/" operator, convert operator to * or ***
static void prices_invertoperation(const std::vector<std::string> &vexpr, int p, std::vector<std::string> &voperation)
{
}

// reduce pairs in the operation, change or remove opcode if reduced
static int prices_reduceoperands(std::vector<std::string> &voperation)
{
    return 0;
}

// substitute reduced operation in vectored expr
static void prices_substitutereduced(std::vector<std::string> &vexpr, int p, std::vector<std::string> voperation)
{
}

// try to reduce synthetic expression by substituting "BTC_USD, BTC_EUR, 30, /" with "EUR_USD, 30" etc
static std::string prices_getreducedexpr(const std::string &expr)
{
    std::string reduced;
    return reduced;
}

// parse synthetic expression into vector of codes
int32_t prices_syntheticvec(std::vector<uint16_t> &vec, std::vector<std::string> synthetic)
{
    return(0);
}

// calculates price for synthetic expression
int64_t prices_syntheticprice(std::vector<uint16_t> vec, int32_t height, int32_t minmax, int16_t leverage)
{
    return 0;
}

// calculates costbasis and profit/loss for the bet
int32_t prices_syntheticprofits(int64_t &costbasis, int32_t firstheight, int32_t height, int16_t leverage, std::vector<uint16_t> vec, int64_t positionsize,  int64_t &profits, int64_t &outprice)
{
    return 0;
}

// makes result json object
void prices_betjson(UniValue &result, std::vector<OneBetData> bets, int16_t leverage, int32_t endheight, int64_t lastprice)
{
}

// retrieves costbasis from a tx spending bettx vout1 (deprecated)
int64_t prices_costbasis(CTransaction bettx, uint256 &txidCostbasis)
{
    return 0;
}

// enumerates and retrieves added bets, returns the last baton txid
int64_t prices_enumaddedbets(uint256 &batontxid, std::vector<OneBetData> &bets, uint256 bettxid)
{
    return 0;
}

// pricesbet rpc impl: make betting tx
UniValue PricesBet(int64_t txfee, int64_t amount, int16_t leverage, std::vector<std::string> synthetic)
{
    UniValue result(UniValue::VOBJ);
    return(result); 
}

// pricesaddfunding rpc impl: add yet another bet
UniValue PricesAddFunding(int64_t txfee, uint256 bettxid, int64_t amount)
{
    UniValue result(UniValue::VOBJ);
    return(result);
}

// scan chain from the initial bet's first position upto the chain tip and calculate bet's costbasises and profits, breaks if rekt detected 
int32_t prices_scanchain(std::vector<OneBetData> &bets, int16_t leverage, std::vector<uint16_t> vec, int64_t &lastprice, int32_t &endheight) {
    return 0;
}

// pricescostbasis rpc impl: set cost basis (open price) for the bet (deprecated)
UniValue PricesSetcostbasis(int64_t txfee, uint256 bettxid)
{
    UniValue result(UniValue::VOBJ);
    return(result);
}


// pricesaddfunding rpc impl: add yet another bet
UniValue PricesRefillFund(int64_t amount)
{
    UniValue result(UniValue::VOBJ);
    return(result);
}


int32_t prices_getbetinfo(uint256 bettxid, BetInfo &betinfo)
{
    return (-420);
}

// pricesrekt rpc: anyone can rekt a bet at some block where losses reached limit, collecting fee
UniValue PricesRekt(int64_t txfee, uint256 bettxid, int32_t rektheight)
{
    UniValue result(UniValue::VOBJ);
    return(result);
}

// pricescashout rpc impl: bettor can cashout hit bet if it is not rekt
UniValue PricesCashout(int64_t txfee, uint256 bettxid)
{
    UniValue result(UniValue::VOBJ);
    return result;
}


// pricesinfo rpc impl
UniValue PricesInfo(uint256 bettxid, int32_t refheight)
{
    UniValue result(UniValue::VOBJ);
    return(result);
}

// priceslist rpc impl
UniValue PricesList(uint32_t filter, CPubKey mypk)
{
    UniValue result(UniValue::VARR); 
    return(result);
}


static bool prices_addbookentry(uint256 txid, std::vector<BetInfo> &book)
{
    return false;
}


static bool prices_ispositionup(const std::vector<uint16_t> &vecparsed, int16_t leverage) {
    return false;
}

static bool prices_isopposite(BetInfo p1, BetInfo p2) {
    return false;
}



static std::string findMatchedBook(const std::vector<uint16_t> &vecparsed, const std::map<std::string, std::vector<BetInfo> > & bookmatched) {
    return std::string("");
}


void prices_getorderbook(std::map<std::string, std::vector<BetInfo> > & bookmatched, std::map<std::string, MatchedBookTotal> &matchedTotals, TotalFund &fundTotals) {
}

static bool prices_isacceptableamount(const std::vector<uint16_t> &vecparsed, int64_t amount, int16_t leverage) {
    return false;
}


// walk through uxtos on the global address
// calculate the balance:
// + rekt positions
// = opposite positions
// - unbalanced positions
UniValue PricesGetOrderbook()
{
    UniValue result(UniValue::VOBJ);
    return result;
}
