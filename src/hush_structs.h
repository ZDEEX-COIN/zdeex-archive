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
#include "uthash.h"
#include "utlist.h"

/*#ifdef _WIN32
#define PACKED
#else
#define PACKED __attribute__((packed))
#endif*/

#ifndef HUSH_STRUCTS_H
#define HUSH_STRUCTS_H
#define GENESIS_NBITS 0x1f00ffff
#define HUSH_MINRATIFY ((height < 90000) ? 7 : 11)
#define HUSH_NOTARIES_HARDCODED 180000 // DONT CHANGE
#define HUSH_MAXBLOCKS 250000 // DONT CHANGE
#define HUSH_EVENT_RATIFY 'P'
#define HUSH_EVENT_NOTARIZED 'N'
#define HUSH_EVENT_HUSHHEIGHT 'K'
#define HUSH_EVENT_REWIND 'B'
#define HUSH_EVENT_PRICEFEED 'V'
#define HUSH_EVENT_OPRETURN 'R'
#define HUSH_OPRETURN_DEPOSIT 'D'
#define HUSH_OPRETURN_ISSUED 'I' // assetchain
#define HUSH_OPRETURN_WITHDRAW 'W' // assetchain
#define HUSH_OPRETURN_REDEEMED 'X'

#define HUSH_KVPROTECTED 1
#define HUSH_KVBINARY 2
#define HUSH_KVDURATION 1440
#define HUSH_SMART_CHAIN_MAXLEN 65

#ifndef _BITS256
#define _BITS256
    union _bits256 { uint8_t bytes[32]; uint16_t ushorts[16]; uint32_t uints[8]; uint64_t ulongs[4]; uint64_t txid; };
    typedef union _bits256 bits256;
#endif    

union _bits320 { uint8_t bytes[40]; uint16_t ushorts[20]; uint32_t uints[10]; uint64_t ulongs[5]; uint64_t txid; };
typedef union _bits320 bits320;

struct hush_kv { UT_hash_handle hh; bits256 pubkey; uint8_t *key,*value; int32_t height; uint32_t flags; uint16_t keylen,valuesize; };

struct hush_event_notarized { uint256 blockhash,desttxid,MoM; int32_t notarizedheight,MoMdepth; char dest[16]; };
struct hush_event_pubkeys { uint8_t num; uint8_t pubkeys[64][33]; };
struct hush_event_opreturn { uint256 txid; uint64_t value; uint16_t vout,oplen; uint8_t opret[]; };
struct hush_event_pricefeed { uint8_t num; uint32_t prices[35]; };

struct hush_event
{
    struct hush_event *related;
    uint16_t len;
    int32_t height;
    uint8_t type,reorged;
    char symbol[HUSH_SMART_CHAIN_MAXLEN];
    uint8_t space[];
};

struct pax_transaction
{
    UT_hash_handle hh;
    uint256 txid;
    uint64_t puposhis,fiatoshis,validated;
    int32_t marked,height,otherheight,approved,didstats,ready;
    uint16_t vout;
    char symbol[HUSH_SMART_CHAIN_MAXLEN],source[HUSH_SMART_CHAIN_MAXLEN],coinaddr[64]; uint8_t rmd160[20],type,buf[35];
};

struct knotary_entry { UT_hash_handle hh; uint8_t pubkey[33],notaryid; };
struct knotaries_entry { int32_t height,numnotaries; struct knotary_entry *Notaries; };
struct notarized_checkpoint
{
    uint256 notarized_hash,notarized_desttxid,MoM,MoMoM;
    int32_t nHeight,notarized_height,MoMdepth,MoMoMdepth,MoMoMoffset,hushstarti,hushendi;
};

struct hush_ccdataMoM
{
    uint256 MoM;
    int32_t MoMdepth,notarized_height,height,txi;
};

struct hush_ccdata_entry { uint256 MoM; int32_t notarized_height,hushheight,txi; char symbol[65]; };
struct hush_ccdatapair { int32_t notarized_height,MoMoMoffset; };

struct hush_ccdataMoMoM
{
    uint256 MoMoM;
    int32_t hushstarti,hushendi,MoMoMoffset,MoMoMdepth,numpairs,len;
    struct hush_ccdatapair *pairs;
};

struct hush_ccdata
{
    struct hush_ccdata *next,*prev;
    struct hush_ccdataMoM MoMdata;
    uint32_t CCid,len;
    char symbol[65];
};

struct hush_state
{
    uint256 NOTARIZED_HASH,NOTARIZED_DESTTXID,MoM;
    int32_t SAVEDHEIGHT,CURRENT_HEIGHT,NOTARIZED_HEIGHT,MoMdepth;
    uint32_t SAVEDTIMESTAMP;
    uint64_t deposited,issued,withdrawn,approved,redeemed,shorted;
    struct notarized_checkpoint *NPOINTS; int32_t NUM_NPOINTS,last_NPOINTSi;
    struct hush_event **Hush_events; int32_t Hush_numeventss;
    uint32_t RTbufs[64][3]; uint64_t RTmask;
};

#endif /* HUSH_STRUCT_H */
