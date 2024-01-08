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

#ifndef H_HUSHEVENTS_H
#define H_HUSHEVENTS_H
#include "hush_defs.h"

struct hush_event *hush_eventadd(struct hush_state *sp,int32_t height,char *symbol,uint8_t type,uint8_t *data,uint16_t datalen)
{
    struct hush_event *ep=0; uint16_t len = (uint16_t)(sizeof(*ep) + datalen);
    if ( sp != 0 && SMART_CHAIN_SYMBOL[0] != 0 )
    {
        portable_mutex_lock(&hush_mutex);
        ep = (struct hush_event *)calloc(1,len);
        ep->len = len;
        ep->height = height;
        ep->type = type;
        strcpy(ep->symbol,symbol);
        if ( datalen != 0 )
            memcpy(ep->space,data,datalen);
        sp->Hush_events = (struct hush_event **)realloc(sp->Hush_events,(1 + sp->Hush_numeventss) * sizeof(*sp->Hush_events));
        sp->Hush_events[sp->Hush_numeventss++] = ep;
        portable_mutex_unlock(&hush_mutex);
    }
    return(ep);
}

void hush_eventadd_notarized(struct hush_state *sp,char *symbol,int32_t height,char *dest,uint256 notarized_hash,uint256 notarized_desttxid,int32_t notarizedheight,uint256 MoM,int32_t MoMdepth)
{
    static uint32_t counter; int32_t verified=0; char *coin; struct hush_event_notarized N;
    coin = (SMART_CHAIN_SYMBOL[0] == 0) ? (char *)"HUSH3" : SMART_CHAIN_SYMBOL;
    if ( IS_HUSH_NOTARY != 0 && (verified= hush_verifynotarization(symbol,dest,height,notarizedheight,notarized_hash,notarized_desttxid)) < 0 )
    {
        if ( counter++ < 100 )
            printf("[%s] error validating notarization ht.%d notarized_height.%d, if on a pruned %s node this can be ignored\n",SMART_CHAIN_SYMBOL,height,notarizedheight,dest);
    }
    else if ( strcmp(symbol,coin) == 0 )
    {
        if ( 0 && IS_HUSH_NOTARY != 0 && verified != 0 )
            fprintf(stderr,"validated [%s] ht.%d notarized %d\n",coin,height,notarizedheight);
        memset(&N,0,sizeof(N));
        N.blockhash = notarized_hash;
        N.desttxid = notarized_desttxid;
        N.notarizedheight = notarizedheight;
        N.MoM = MoM;
        N.MoMdepth = MoMdepth;
        strncpy(N.dest,dest,sizeof(N.dest)-1);
        hush_eventadd(sp,height,symbol,HUSH_EVENT_NOTARIZED,(uint8_t *)&N,sizeof(N));
        if ( sp != 0 )
            hush_notarized_update(sp,height,notarizedheight,notarized_hash,notarized_desttxid,MoM,MoMdepth);
    }
}

void hush_eventadd_pubkeys(struct hush_state *sp,char *symbol,int32_t height,uint8_t num,uint8_t pubkeys[64][33])
{
    struct hush_event_pubkeys P;
    fprintf(stderr, "%s: eventadd pubkeys height=%d\n",__func__,height);
    memset(&P,0,sizeof(P));
    P.num = num;
    memcpy(P.pubkeys,pubkeys,33 * num);
    hush_eventadd(sp,height,symbol,HUSH_EVENT_RATIFY,(uint8_t *)&P,(int32_t)(sizeof(P.num) + 33 * num));
    if ( sp != 0 )
        hush_notarysinit(height,pubkeys,num);
}

void hush_eventadd_pricefeed(struct hush_state *sp,char *symbol,int32_t height,uint32_t *prices,uint8_t num)
{
    struct hush_event_pricefeed F;
    if ( num == sizeof(F.prices)/sizeof(*F.prices) )
    {
        memset(&F,0,sizeof(F));
        F.num = num;
        memcpy(F.prices,prices,sizeof(*F.prices) * num);
        hush_eventadd(sp,height,symbol,HUSH_EVENT_PRICEFEED,(uint8_t *)&F,(int32_t)(sizeof(F.num) + sizeof(*F.prices) * num));
        if ( sp != 0 )
            hush_pvals(height,prices,num);
    } //else fprintf(stderr,"skip pricefeed[%d]\n",num);
}

void hush_eventadd_opreturn(struct hush_state *sp,char *symbol,int32_t height,uint256 txid,uint64_t value,uint16_t vout,uint8_t *buf,uint16_t opretlen)
{
    struct hush_event_opreturn O; uint8_t *opret;
    if ( SMART_CHAIN_SYMBOL[0] != 0 )
    {
        opret = (uint8_t *)calloc(1,sizeof(O) + opretlen + 16);
        O.txid = txid;
        O.value = value;
        O.vout = vout;
        memcpy(opret,&O,sizeof(O));
        memcpy(&opret[sizeof(O)],buf,opretlen);
        O.oplen = (int32_t)(opretlen + sizeof(O));
        hush_eventadd(sp,height,symbol,HUSH_EVENT_OPRETURN,opret,O.oplen);
        free(opret);
        if ( sp != 0 )
            hush_opreturn(height,value,buf,opretlen,txid,vout,symbol);
    }
}

void hush_event_undo(struct hush_state *sp,struct hush_event *ep)
{
    switch ( ep->type )
    {
        case HUSH_EVENT_RATIFY: printf("rewind of ratify, needs to be coded.%d\n",ep->height); break;
        case HUSH_EVENT_NOTARIZED: break;
        case HUSH_EVENT_HUSHHEIGHT:
            if ( ep->height <= sp->SAVEDHEIGHT )
                sp->SAVEDHEIGHT = ep->height;
            break;
        case HUSH_EVENT_PRICEFEED:
            // backtrack prices;
            break;
        case HUSH_EVENT_OPRETURN:
            // backtrack opreturns
            break;
    }
}

void hush_event_rewind(struct hush_state *sp,char *symbol,int32_t height)
{
    struct hush_event *ep;
    if ( sp != 0 )
    {
        if ( SMART_CHAIN_SYMBOL[0] == 0 && height <= HUSH_LASTMINED && prevHUSH_LASTMINED != 0 )
        {
            printf("undo HUSH_LASTMINED %d <- %d\n",HUSH_LASTMINED,prevHUSH_LASTMINED);
            HUSH_LASTMINED = prevHUSH_LASTMINED;
            prevHUSH_LASTMINED = 0;
        }
        while ( sp->Hush_events != 0 && sp->Hush_numeventss > 0 )
        {
            if ( (ep= sp->Hush_events[sp->Hush_numeventss-1]) != 0 )
            {
                if ( ep->height < height )
                    break;
                //printf("[%s] undo %s event.%c ht.%d for rewind.%d\n",SMART_CHAIN_SYMBOL,symbol,ep->type,ep->height,height);
                hush_event_undo(sp,ep);
                sp->Hush_numeventss--;
            }
        }
    }
}

void hush_sethushheight(struct hush_state *sp,int32_t hushheight,uint32_t timestamp)
{
    if ( sp != 0 )
    {
        if ( hushheight > sp->SAVEDHEIGHT )
        {
            sp->SAVEDHEIGHT = hushheight;
            sp->SAVEDTIMESTAMP = timestamp;
        }
        if ( hushheight > sp->CURRENT_HEIGHT )
            sp->CURRENT_HEIGHT = hushheight;
    }
}

void hush_eventadd_hushheight(struct hush_state *sp,char *symbol,int32_t height,int32_t hushheight,uint32_t timestamp)
{
    uint32_t buf[2];
    if ( hushheight > 0 ) {
        buf[0] = (uint32_t)hushheight;
        buf[1] = timestamp;
        hush_eventadd(sp,height,symbol,HUSH_EVENT_HUSHHEIGHT,(uint8_t *)buf,sizeof(buf));
        if ( sp != 0 )
            hush_sethushheight(sp,hushheight,timestamp);
    } else {
        //fprintf(stderr,"REWIND hushheight.%d\n",hushheight);
        hushheight = -hushheight;
        hush_eventadd(sp,height,symbol,HUSH_EVENT_REWIND,(uint8_t *)&height,sizeof(height));
        if ( sp != 0 )
            hush_event_rewind(sp,symbol,height);
    }
}


#endif
