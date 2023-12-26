// Copyright 2016-2023 The Hush Developers
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
void hush_prefetch(FILE *fp);
uint32_t hush_heightstamp(int32_t height);
void hush_stateupdate(int32_t height,uint8_t notarypubs[][33],uint8_t numnotaries,uint8_t notaryid,uint256 txhash,uint64_t voutmask,uint8_t numvouts,uint32_t *pvals,uint8_t numpvals,int32_t kheight,uint32_t ktime,uint64_t opretvalue,uint8_t *opretbuf,uint16_t opretlen,uint16_t vout,uint256 MoM,int32_t MoMdepth);
void hush_init(int32_t height);
int32_t hush_MoMdata(int32_t *notarized_htp,uint256 *MoMp,uint256 *hushtxidp,int32_t nHeight,uint256 *MoMoMp,int32_t *MoMoMoffsetp,int32_t *MoMoMdepthp,int32_t *hushstartip,int32_t *hushendip);
int32_t hush_notarizeddata(int32_t nHeight,uint256 *notarized_hashp,uint256 *notarized_desttxidp);
char *hush_issuemethod(char *userpass,char *method,char *params,uint16_t port);
void hush_init(int32_t height);
int32_t hush_chosennotary(int32_t *notaryidp,int32_t height,uint8_t *pubkey33,uint32_t timestamp);
int32_t hush_isrealtime(int32_t *hushheightp);
uint64_t hush_paxtotal();
int32_t hush_longestchain();
int32_t hush_checkvout(int32_t vout,int32_t k,int32_t indallvouts);
pthread_mutex_t hush_mutex;

#define HUSH_DPOW_GAP 2000    //((SMART_CHAIN_SYMBOL[0] == 0) ? 2000 : 100)
#define HUSH_SMART_CHAIN_MAXLEN 65

struct pax_transaction *PAX;
int32_t NUM_PRICES; uint32_t *PVALS;
struct knotaries_entry *Pubkeys;
struct hush_state HUSH_STATES[34];

#define _COINBASE_MATURITY 100
int COINBASE_MATURITY = _COINBASE_MATURITY;//100;
unsigned int WITNESS_CACHE_SIZE = _COINBASE_MATURITY+10;
uint256 HUSH_EARLYTXID;

int32_t HUSH_MININGTHREADS = -1,IS_HUSH_NOTARY,USE_EXTERNAL_PUBKEY,HUSH_CHOSEN_ONE,ASSETCHAINS_SEED,HUSH_ON_DEMAND,HUSH_EXTERNAL_NOTARIES,HUSH_PASSPORT_INITDONE,HUSH_PAX,HUSH_EXCHANGEWALLET,HUSH_REWIND,HUSH_CONNECTING = -1,HUSH_DEALERNODE,HUSH_EXTRASATOSHI,ASSETCHAINS_FOUNDERS,ASSETCHAINS_CBMATURITY,HUSH_NSPV;
int32_t HUSH_INSYNC,HUSH_LASTMINED,prevHUSH_LASTMINED,HUSH_CCACTIVATE;
std::string NOTARY_PUBKEY,ASSETCHAINS_NOTARIES,ASSETCHAINS_OVERRIDE_PUBKEY,DONATION_PUBKEY,ASSETCHAINS_SCRIPTPUB,NOTARY_ADDRESS,ASSETCHAINS_SELFIMPORT,ASSETCHAINS_CCLIB;
uint8_t NOTARY_PUBKEY33[33],ASSETCHAINS_OVERRIDE_PUBKEY33[33],ASSETCHAINS_OVERRIDE_PUBKEYHASH[20],ASSETCHAINS_PUBLIC,ASSETCHAINS_PRIVATE,ASSETCHAINS_TXPOW,ASSETCHAINS_MARMARA;
int8_t ASSETCHAINS_ADAPTIVEPOW;
std::vector<uint8_t> Mineropret;
std::vector<std::string> vAllowListAddress;
char NOTARYADDRS[64][64];
char NOTARY_ADDRESSES[NUM_HUSH_SEASONS][64][64];

char SMART_CHAIN_SYMBOL[HUSH_SMART_CHAIN_MAXLEN],ASSETCHAINS_USERPASS[4096];
uint16_t ASSETCHAINS_P2PPORT,ASSETCHAINS_RPCPORT,ASSETCHAINS_BEAMPORT,ASSETCHAINS_CODAPORT;
uint32_t ASSETCHAIN_INIT,ASSETCHAINS_CC,HUSH_STOPAT,HUSH_DPOWCONFS = 1,STAKING_MIN_DIFF;
uint32_t ASSETCHAINS_MAGIC = 2387029918;
int64_t ASSETCHAINS_GENESISTXVAL = 5000000000;

int64_t MAX_MONEY = 200000000 * 100000000LL;

// consensus variables for coinbase timelock control and timelock transaction support
// time locks are specified enough to enable their use initially to lock specific coinbase transactions for emission control
// to be verifiable, timelocks require additional data that enables them to be validated and their ownership and
// release time determined from the blockchain. to do this, every time locked output according to this
// spec will use an op_return with CLTV at front and anything after |OP_RETURN|PUSH of rest|OPRETTYPE_TIMELOCK|script|
#define _ASSETCHAINS_TIMELOCKOFF 0xffffffffffffffff
uint64_t ASSETCHAINS_TIMELOCKGTE = _ASSETCHAINS_TIMELOCKOFF;
uint64_t ASSETCHAINS_TIMEUNLOCKFROM = 0, ASSETCHAINS_TIMEUNLOCKTO = 0,ASSETCHAINS_CBOPRET=0;

uint64_t ASSETCHAINS_LASTERA = 1;
uint64_t ASSETCHAINS_ENDSUBSIDY[ASSETCHAINS_MAX_ERAS+1],ASSETCHAINS_REWARD[ASSETCHAINS_MAX_ERAS+1],ASSETCHAINS_HALVING[ASSETCHAINS_MAX_ERAS+1],ASSETCHAINS_DECAY[ASSETCHAINS_MAX_ERAS+1],ASSETCHAINS_NOTARY_PAY[ASSETCHAINS_MAX_ERAS+1],ASSETCHAINS_PEGSCCPARAMS[3];
uint8_t ASSETCHAINS_CCDISABLES[256];
std::vector<std::string> ASSETCHAINS_PRICES,ASSETCHAINS_STOCKS;


// this is the offset in the ASSETCHAINS_ALGORITHMS array
#define _ASSETCHAINS_EQUIHASH 0
#define _ASSETCHAINS_RANDOMX 1

uint32_t ASSETCHAINS_NUMALGOS = 4; // there are different variants of equihash with different (N,K)
uint32_t ASSETCHAINS_EQUIHASH = _ASSETCHAINS_EQUIHASH;
uint32_t ASSETCHAINS_RANDOMX  = _ASSETCHAINS_RANDOMX;
const char *ASSETCHAINS_ALGORITHMS[] = {"equihash", "randomx"};
uint64_t ASSETCHAINS_NONCEMASK[] = {0xffff};
uint32_t ASSETCHAINS_NONCESHIFT[] = {32};
uint32_t ASSETCHAINS_HASHESPERROUND[] = {1};
uint32_t ASSETCHAINS_ALGO = _ASSETCHAINS_EQUIHASH;
// min diff returned from GetNextWorkRequired needs to be added here for each algo, so they can work with ac_staked.
uint32_t ASSETCHAINS_MINDIFF[] = {537857807};
int32_t ASSETCHAINS_LWMAPOS = 0;        // percentage of blocks should be PoS
int32_t ASSETCHAINS_SAPLING = -1;
int32_t ASSETCHAINS_OVERWINTER = -1;
int32_t ASSETCHAINS_STAKED;
uint64_t ASSETCHAINS_COMMISSION,ASSETCHAINS_SUPPLY = 10,ASSETCHAINS_FOUNDERS_REWARD;
uint32_t HUSH_INITDONE;
char HUSHUSERPASS[8192+512+1],BTCUSERPASS[8192]; uint16_t HUSH3_PORT = 18031,BITCOIND_RPCPORT = 18031;
uint64_t PENDING_HUSH_TX;
extern int32_t HUSH_LOADINGBLOCKS;
unsigned int MAX_BLOCK_SIGOPS = 20000;
int32_t HUSH_TESTNODE, HUSH_SNAPSHOT_INTERVAL;
CScript HUSH_EARLYTXID_SCRIPTPUB;
int32_t ASSETCHAINS_EARLYTXIDCONTRACT;
std::map <std::int8_t, int32_t> mapHeightEvalActivate;
struct hush_kv *HUSH_KV;
pthread_mutex_t HUSH_KV_mutex,HUSH_CC_mutex;

#define MAX_CURRENCIES 32
char CURRENCIES[][8] = { "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD", // major currencies
    "CNY", "RUB", "MXN", "BRL", "INR", "HKD", "TRY", "ZAR", "PLN", "NOK", "SEK", "DKK", "CZK", "HUF", "ILS", "KRW", "MYR", "PHP", "RON", "SGD", "THB", "BGN", "IDR", "HRK",
    "HUSH" };

int32_t hush_baseid(char *origbase)
{
    int32_t i; char base[64];
    for (i=0; origbase[i]!=0&&i<sizeof(base); i++)
        base[i] = toupper((int32_t)(origbase[i] & 0xff));
    base[i] = 0;
    for (i=0; i<=MAX_CURRENCIES; i++)
        if ( strcmp(CURRENCIES[i],base) == 0 )
            return(i);
    //printf("illegal base.(%s) %s\n",origbase,base);
    return(-1);
}

#ifndef SATOSHIDEN
#define SATOSHIDEN ((uint64_t)100000000L)
#endif
uint64_t hush_current_supply(uint32_t nHeight)
{
    uint64_t cur_money;
    int32_t baseid;

    //if ( (baseid = hush_baseid(SMART_CHAIN_SYMBOL)) >= 0 && baseid < 32 )
    //    cur_money = ASSETCHAINS_GENESISTXVAL + ASSETCHAINS_SUPPLY + nHeight * ASSETCHAINS_REWARD[0] / SATOSHIDEN;
    //else
    {
        // figure out max_money by adding up supply to a maximum of 10,000,000 blocks
        cur_money = (ASSETCHAINS_SUPPLY+1) * SATOSHIDEN + (ASSETCHAINS_MAGIC & 0xffffff) + ASSETCHAINS_GENESISTXVAL;
        if ( ASSETCHAINS_LASTERA == 0 && ASSETCHAINS_REWARD[0] == 0 )
        {
            cur_money += (nHeight * 10000);// / SATOSHIDEN;
        }
        else
        {
            for ( int j = 0; j <= ASSETCHAINS_LASTERA; j++ )
            {
                // if any condition means we have no more rewards, break
                if (j != 0 && (nHeight <= ASSETCHAINS_ENDSUBSIDY[j - 1] || (ASSETCHAINS_ENDSUBSIDY[j - 1] == 0 &&
                    (ASSETCHAINS_REWARD[j] == 0 && (j == ASSETCHAINS_LASTERA || ASSETCHAINS_DECAY[j] != SATOSHIDEN)))))
                    break;

                // add rewards from this era, up to nHeight
                int64_t reward = ASSETCHAINS_REWARD[j];
                
                //fprintf(stderr,"last.%d reward %llu period %llu\n",(int32_t)ASSETCHAINS_LASTERA,(long long)reward,(long long)ASSETCHAINS_HALVING[j]);
                if ( reward > 0 )
                {
                    uint64_t lastEnd = j == 0 ? 0 : ASSETCHAINS_ENDSUBSIDY[j - 1];
                    uint64_t curEnd = ASSETCHAINS_ENDSUBSIDY[j] == 0 ? nHeight : nHeight > ASSETCHAINS_ENDSUBSIDY[j] ? ASSETCHAINS_ENDSUBSIDY[j] : nHeight;
                    uint64_t period = ASSETCHAINS_HALVING[j];
                    if ( period == 0 )
                        period = 210000;
                    uint32_t nSteps = (curEnd - lastEnd) / period;
                    uint32_t modulo = (curEnd - lastEnd) % period;
                    uint64_t decay = ASSETCHAINS_DECAY[j];

                    //fprintf(stderr,"period.%llu cur_money %.8f += %.8f * %d\n",(long long)period,(double)cur_money/COIN,(double)reward/COIN,nHeight);
                    if ( ASSETCHAINS_HALVING[j] == 0 )
                    {
                        // no halving, straight multiply
                        cur_money += reward * (nHeight - 1);
                        //fprintf(stderr,"cur_money %.8f\n",(double)cur_money/COIN);
                    }
                    // if exactly SATOSHIDEN, linear decay to zero or to next era, same as:
                    // (next_era_reward + (starting reward - next_era_reward) / 2) * num_blocks
                    else if ( decay == SATOSHIDEN )
                    {
                        int64_t lowestSubsidy, subsidyDifference, stepDifference, stepTriangle;
                        int64_t denominator, modulo=1;
                        int32_t sign = 1;

                        if ( j == ASSETCHAINS_LASTERA )
                        {
                            subsidyDifference = reward;
                            lowestSubsidy = 0;
                        }
                        else
                        {
                            // Ex: -ac_eras=3 -ac_reward=0,384,24 -ac_end=1440,260640,0 -ac_halving=1,1440,2103840 -ac_decay 100000000,97750000,0
                            subsidyDifference = reward - ASSETCHAINS_REWARD[j + 1];
                            if (subsidyDifference < 0)
                            {
                                sign = -1;
                                subsidyDifference *= sign;
                                lowestSubsidy = reward;
                            }
                            else
                            {
                                lowestSubsidy = ASSETCHAINS_REWARD[j + 1];
                            }
                        }

                        // if we have not finished the current era, we need to caluclate a total as if we are at the end, with the current
                        // subsidy. we will calculate the total of a linear era as follows. Each item represents an area calculation:
                        // a) the rectangle from 0 to the lowest reward in the era * the number of blocks
                        // b) the rectangle of the remainder of blocks from the lowest point of the era to the highest point of the era if any remainder
                        // c) the minor triangle from the start of transition from the lowest point to the start of transition to the highest point
                        // d) one halving triangle (half area of one full step)
                        //
                        // we also need:
                        // e) number of steps = (n - erastart) / halving interval
                        //
                        // the total supply from era start up to height is:
                        // a + b + c + (d * e)

                        // calculate amount in one step's triangular protrusion over minor triangle's hypotenuse
                        denominator = nSteps * period;
                        if ( denominator == 0 )
                            denominator = 1;
                        // difference of one step vs. total
                        stepDifference = (period * subsidyDifference) / denominator;

                        // area == coin holding of one step triangle, protruding from minor triangle's hypotenuse
                        stepTriangle = (period * stepDifference) >> 1;

                        // sign is negative if slope is positive (start is less than end)
                        if (sign < 0)
                        {
                            // use steps minus one for our calculations, and add the potentially partial rectangle
                            // at the end
                            cur_money += stepTriangle * (nSteps - 1);
                            cur_money += stepTriangle * (nSteps - 1) * (nSteps - 1);

                            // difference times number of steps is height of rectangle above lowest subsidy
                            cur_money += modulo * stepDifference * nSteps;
                        }
                        else
                        {
                            // if negative slope, the minor triangle is the full number of steps, as the highest
                            // level step is full. lowest subsidy is just the lowest so far
                            lowestSubsidy = reward - (stepDifference * nSteps);

                            // add the step triangles, one per step
                            cur_money += stepTriangle * nSteps;

                            // add the minor triangle
                            cur_money += stepTriangle * nSteps * nSteps;
                        }

                        // add more for the base rectangle if lowest subsidy is not 0
                        cur_money += lowestSubsidy * (curEnd - lastEnd);
                    } else {
                        for ( int k = lastEnd; k < curEnd; k += period )
                        {
                            cur_money += period * reward;
                            // if zero, we do straight halving
                            reward = decay ? (reward * decay) / SATOSHIDEN : reward >> 1;
                        }
                        cur_money += modulo * reward;
                    }
                }
            }
        }
    }    
    if ( HUSH_BIT63SET(cur_money) != 0 )
        return(HUSH_MAXNVALUE);
    if ( ASSETCHAINS_COMMISSION != 0 ) {
        uint64_t newval = (cur_money + (cur_money/COIN * ASSETCHAINS_COMMISSION));
        if ( HUSH_BIT63SET(newval) != 0 )
            return(HUSH_MAXNVALUE);
        else if ( newval < cur_money ) // check for underflow
            return(HUSH_MAXNVALUE);
        return(newval);
    }
    //fprintf(stderr,"cur_money %.8f\n",(double)cur_money/COIN);
    return(cur_money);
}

// the number of different devtax addresses/scriptpubs
const uint32_t DEVTAX_NUM = 20;

std::string DEVTAX_DATA[DEVTAX_NUM][2] = {
{"RAMagYNy678TEFvjqE9kmkDX5j3xsK9whE", "76a9140bcca88d9224ec1571d4dd68009305d055ca3a4588ac"},
{"RAstH3RJSHq2jr9cigVmAdC5kLdeqCU9gu", "76a9141187d31f4b95c3210d2c69acb6853034fb748f8d88ac"},
{"RCjpaSm3SBnoR7EfM3BGFApx1FgMYZqUqd", "76a91425f1a8f5c0bcb7fb4c351f98fd664bbbc029c65488ac"},
{"RCoJZfPhyigihrzBx3nBnT2V2fdt8PUEmN", "76a914269a4514eaa07aa928d3d809d6f9b5a8b0a0d84588ac"},
{"REadVrDc5PdtkuuXhGMcdBfTLKFkYZtp61", "76a9143a24eb5ff34c8395c4159aa74113680960fbae0888ac"},
{"REJjRATXJ4YqtTTbcSS24HTzVpKc235kzb", "76a914372334851e666ff7932d423b1d614db0ad88f3e988ac"},
{"REktw85C53o6FN9yuQL4HfL8cEgq9oQzgg", "76a9143c15f6d372a486e0d3da907e0063d990d50a1f9588ac"},
{"REXWQqh6ibSc3SDZDN1n3tN6H2fjDB3LRs", "76a914398dc193009312742129f00bc12214c2e0ec2cba88ac"},
{"RFJYpa7sHMes2da1Kd9JZpNEwoz3ut2zxq", "76a91442127c49a163f79898c69906147ca3c7c34924b788ac"},
{"RFLXxCk7AAtUnxauu8k5BzuhXm6XqfJjLA", "76a914427297ae0417d18b7f9c31b4a51502d4f2a8cd7988ac"},
{"RHrBQoDnZ5QrtkL7B1zsdFxrNfLuEikf5T", "76a9145dfe2cfe9f6db1c0e6847a35f433d1948d4086a488ac"},
{"RJDnDj2XHFSbjrBWxW7AA5vv8pQbeiRw5i", "76a9146213f7d7567a97d4b6888d3863ed8d4808acf9c688ac"},
{"RKf78FsvzJebo41n1ZQGyLxbuh3bmbkmAg", "76a91471d646502b388d9cca69f05bdedc8920918eca4a88ac"},
{"RL6J7DU69YvJBFSL93RnezR7dJYW93yKN3", "76a9147699d74f361b559ef4cdab6ad2582f68fdd444bd88ac"},
{"RLDDJMB3fSexorUC7ZkTRjcRLJEkNJZktz", "76a91477e8bd3dc10277540fa7f183936c977c130c397c88ac"},
{"RR9ufAA8m5Myu5EZd2KdXy9hpD6sY5vE1f", "76a914ae2164e50fd814faa8629907679af2668f8fd08388ac"},
{"RUBz8fptKNXB5NL3H1ohNGTeKMBv9WRcpd", "76a914cf6e56a04785c9a913d355a2d9c7c7ec1243a4ff88ac"},
{"RUT8NytuYHqmYXwBkue7ujLWaCKw5ZVc38", "76a914d24b763bdac5fb28513d134743e42302736c0dfd88ac"},
{"RVF6tWNCrUsubeKLzadH4aeseVwnJPKd8N", "76a914dafd59fd09a4e7cb813fc4dde4515a605e3aceae88ac"},
{"RVMygLshHa8qvFX1orEi5FGji99BVXUQFy", "76a914dc4a3eb079349b4bb25864af4ddc5cd52faf382d88ac"},
};

// this is a deterministic consensus-changing function. All miners must be able
// to predict the scriptpub for the next block
std::string devtax_scriptpub_for_height(uint32_t nHeight) {
    bool ishush3  = strncmp(SMART_CHAIN_SYMBOL, "HUSH3",5) == 0 ? true : false;
    bool istush3  = strncmp(SMART_CHAIN_SYMBOL, "TUSH3",5) == 0 ? true : false;
    // Fork height for HUSH3 mainnet needs to be decided just before code is merged
    // Since it requires all full nodes on the network to have enough time to update.
    // For testing, we choose an early blockheight so we can observe the value changing
    // from the old fixed value to the new values which cycle
    const int DEVTAX_FORK_HEIGHT = ishush3 ? nHushHardforkHeight4 : 5;

    // Decentralized devtax is height-activated
    if (nHeight >= DEVTAX_FORK_HEIGHT) {
        if (ishush3 || istush3) {
            return DEVTAX_DATA[ nHeight % DEVTAX_NUM ][1];
        } else {
            // if this is not HUSH3 or a testchain for HUSH3, return it unchanged
            return ASSETCHAINS_SCRIPTPUB;
        }
    }
    // return default unchanged if we are less than fork height
    return ASSETCHAINS_SCRIPTPUB;
}

// this is only used by getblocktemplate, so it cannot change consensus of
// blocks < DEVTAX_FORK_HEIGHT but it could affect consensus of later blocks
std::string devtax_address_for_height(uint32_t nHeight) {
    const std::string legacy_devtax_address = "RHushEyeDm7XwtaTWtyCbjGQumYyV8vMjn";
    bool ishush3  = strncmp(SMART_CHAIN_SYMBOL, "HUSH3",5) == 0 ? true : false;
    bool istush3  = strncmp(SMART_CHAIN_SYMBOL, "TUSH3",5) == 0 ? true : false;
    // Fork height for HUSH3 mainnet needs to be decided just before code is merged
    // Since it requires all full nodes on the network to have enough time to update.
    // For testing, we choose an early blockheight so we can observe the value changing
    // from the old fixed value to the new values which cycle
    const int DEVTAX_FORK_HEIGHT = ishush3 ? nHushHardforkHeight4 : 5;

    // Decentralized devtax is height-activated
    if (nHeight >= DEVTAX_FORK_HEIGHT) {
        if (ishush3 || istush3) {
            return DEVTAX_DATA[ nHeight % DEVTAX_NUM ][0];
        } else {
            // if this is not HUSH3 or TUSH3, return legacy
            return legacy_devtax_address;
        }
    }
    // return default unchanged if we are less than fork height
    return legacy_devtax_address;
}
