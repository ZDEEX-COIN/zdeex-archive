// Copyright (c) 2016-2023      The Hush developers
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
#include "hush_cJSON.h"

#define HUSH_NOTARIES_HEIGHT1 814000

const char *Notaries_genesis[][2] =
{
        {"RFetqf8WUfWnwNeXdknkm8ojk7EXnYFzrv", "038a1bd41a08f38edda51042988022933c5775dfce81f7bae0b32a9179650352ac"},
        {"RV7YSVW89WC9jBDtFG4ubtopDRove4Tfvc", "03c9d35488be73fe4f2dbb1dc011468482d71bac32249f8cce6480bcc574415d19"},
        {"RBPFE9oXceZBWTn3Vhne4FUKE9vxGEXUKX", "028a8bb6ded2692b39a69ec2d3c9836ff221815909d5cd65257374aeb66394a002"},
        {"RM3cvUcafPhjyypZLEginQjdhjLnSgJHte", "03a36180014115b47b97c1c8776a269bba66047b1ce2c7eb1a3d4e995a6dfff0df"},
        {"RFFX1VaTmZYPBLCzFj7w3iJQArV9ZdaWcW", "02190865f3ca3678d322c96e49a3ddf8ad394a4c8cd97d4bb3376cf547d0d83c66"},
        {"RDwZsLpH1QiAbJwUEY8ajXwTzu3PaWhx7n", "023ea0babb34e1ff9f4db8131ee84ad8991b954038a1e6ef9afc2a1b3fa13bbcb9"},
        {"RCUvfnmt16ZMvLTmLGGAztcAE8fBjfbP6u", "0379a5ba9fb6b463ffcdc0b1f3ecf45a5b737275354f9c2598492f20660f6f7dfd"},
        {"RBLu9adNVMVf6jzLLbAenWovcwq8nU6gYd", "022cd69381231d69d6d3b9638762df849bc7bbab71cbb8383eec29ca677f1afa30"},
        {"RWfv6wd2fwgecnJxC1Ykpf1SJefGh2Wc6i", "03da8a8f57d88afb61f712a8cd35462b65ce2b2575db8f9ee33a725dcd12c44755"},
        {"RWiK4xooG3dPdvaovu6JvR3DWoYD4tfRjx", "02ffe66af4d71345fe6984b5002ad69206e1817566a70d9ac406a679be6a3335a0"},
        {"RYLNiJiRnEGeMxx1Q2xLoFujshRNkBa2x4", "028ef6501004569c1170ce2d7ec7ecfe5739001130ad1b39129f8b88cd3d610257"},
        {"RTw36Ksy5Wk1Xv3B53T79zoRd6XDsE9MS6", "02d7cf4ece00895ca857fcdd0a4c2fc9c949a518d2750396f77d9f031c08a94364"},
        {"RTPkUBriQzZy67WmFhEs6aQzJn5HBB3ntb", "03319ca1eae5888c45115d160ac07c4f2abd1720926aa579d535c4b46c807bb7f7"},
        {"RBmZzttvDnMaEv47cWXs8SgdC993djB68r", "034302c4e1ff72a5f5391f259f7a46e646c7845aa2c9de9fb0c0a4c4802aad79d6"},
        {"RGocb2jLCa2E9kVHDUsijrVGTDP82ngGYZ", "024440a18a16e38b836b3ad9bb54ab0b5ba83b04edebb58c62c09b2de29e9fc703"},
        {"RVqwCjPQ6AJ6r9WeGzQvAT4eGXDScprLkW", "028a94e53ad8ed9e78f0f8a87cf3bc4754784222ad7ddf2d3dc5fafec2f6891cde"},
        {"RB2Xc8eLrATRWVsxrZKHHx3hyJz1vugMt9", "02eca07a9b5810fe929a87f90e5f02e29a06479d39cd3a888abfa1793e1565155a"},
        {"RKm7WUuFfqCTiUBkbxBsdh54nT6ivXpDPX", "03e3f634671005c8ffb7fe883fcf9e08f6f5486df057f215d761741d91c88de898"},
        {"RLbHTvFQoz946W3o3gXTrjxxADeUsWWW16", "02e6bb6dcecf5e3abfe239dec55842a92f096eeac7f0ff7621c3e8948e5e789b27"},
        {"RD75njr2RLGC5PqjHbWwuL7ndTqZiUfYxs", "0250d9996c25a34cb1b4e86303a297fc5c49c65615eb31a57fb17d1e1b376e71be"},
        {"RT1VTzZYZLWUsPWFJ2oypEqB1MXMfq8b5Y", "02d1797941b7df42a98f59ede0f22294e7c02754232a8b1de9512ededaf3f82880"},
        {"RKeXriTVXioHeKpFTjC8Cjohd6DHGUcKqt", "0341e62f0cdffc4ba3e0efb793c0fcaaad1b611db7021b844f643d5c25847733d2"},
        {"RQYrDEgZPKMFAgTHNkWFeMHEmpkXe8j28T", "02b8719cd8484755990158cbdf7b9d990d4a5c3741cabe204e51ed04be5bd50133"},
        {"RE85TACcn8CEn26itAxQV9afxV9mVg17vm", "0367f569d3dc304e699196fe9b798671fe3f12df7851a0a474879b0dbf8bc508d1"},
        {"RPYWQJXto1aeCGe8T6g9Wo4tAL4xE82LJ8", "02cf1e245dfb44e418fd550abb825a600e1753d46a51995970e70c98be539da33e"},
        {"RSVHRS5wqEw7bxfuE9k6xJGbARcy5guisp", "03ab8ac83d689ce76b5d29a54c3b34d0a6cb37d64313ff4467c744787475969a23"},
        {"REAQwBaJFo6DyBkwfW7rTTDbUtkdmATcQ8", "025e80f0075514cc5940de85c0c559efa99a3688faf6cccb8c1d1f38b96ca91e71"},
        {"RF1gz8QBw5uFScGasqVxoUjQwJCD9zHJwC", "031cdae4b545e5049ccee8e0cb792e25795b56e08b5e64b1d972c9b94e9bfd4ed0"},
        {"RTnLGoWzpsyoGSViGH8GyYcYhSveSEmnPV", "03cf3403a9d1cefa83e07b73e618a7f991d140a8283a02df3ce7c00223f27f43d0"},
        {"RArURqxp6qfF7fqv38tCYr6p4zBtLtqf4x", "026bc4c91c2c35fabe88fea6470d6cda98977a97c251656adf25b81653c00c3800"},
        {"RN8GCryShNFvBWtcNEWrQJ5A9AWb3JJoXt", "02afa94f6574cd0fe4f5dc83b09a2112457862421ce96bdc75c1cf25ef5b1f8c4b"},
        {"RQSC2eBckcFPWzq9UtofePC31wgDySfJtw", "035d570768d844c8150a3bd966a2e13aa99316f4ab3e80370c4d16fb02f95d0974"},
        {"RC4uQsfH6jXpgnTFuFiDwAFo58gHLNkWo7", "02402b0ab7001fd4bcb4fa0d8d7006a6c521b1c76e85aad7b374ecd6c5d564c237"},
        {"RREcuaUWSkNzTNPBbFLbXKTKiC4fd5t47J", "03d5bf8b43c44ba064e897da47dd36dba537bebf013d28247ce7a088496dd9b66d"},
        {"REFyC5e7kmse3PUapDuXHL2xmtYEGttYYL", "035f56fd01dd21725928bbd878b795dccafecc03b978dc83748e9194dcbfebfb79"},
};

int32_t gethushseason(int32_t height)
{
    bool istush = strncmp(SMART_CHAIN_SYMBOL, "TUSH",4) == 0 ? true : false;
    if ( istush ) {
        // TUSH is always Season 7 DPoW notaries from genblock
        return 7;
    }

    // It is season 7 until a new consensus code change, instead
    // of the old way, which requires a new code release before
    // the last season block height or nodes stop working correctly
    if ( height > nHushHardforkHeight3 ) {
        return 7;
    }

    if ( height <= HUSH_SEASON_HEIGHTS[0] )
        return(1);
    for (int32_t i = 1; i < NUM_HUSH_SEASONS; i++)
    {
        if ( height <= HUSH_SEASON_HEIGHTS[i] && height > HUSH_SEASON_HEIGHTS[i-1] )
            return(i+1);
    }
    return(0);
}

int32_t getacseason(uint32_t timestamp)
{
    if ( timestamp <= HUSH_SEASON_TIMESTAMPS[0] )
        return(1);
    for (int32_t i = 1; i < NUM_HUSH_SEASONS; i++)
    {
        if ( timestamp <= HUSH_SEASON_TIMESTAMPS[i] && timestamp > HUSH_SEASON_TIMESTAMPS[i-1] )
            return(i+1);
    }
    return(0);
}

int32_t hush_notaries(uint8_t pubkeys[64][33],int32_t height,uint32_t timestamp)
{
    int32_t i,htind,n; uint64_t mask = 0; struct knotary_entry *kp,*tmp;
    static uint8_t hush_pubkeys[NUM_HUSH_SEASONS][64][33],didinit[NUM_HUSH_SEASONS];
    
    //HUSH3+TUSH use block heights, HSCs use timestamps
    if ( timestamp == 0 && SMART_CHAIN_SYMBOL[0] != 0 ) {
        timestamp = hush_heightstamp(height);
    } else if ( SMART_CHAIN_SYMBOL[0] == 0 ) {
        timestamp = 0;
    }

    // Find the correct DPoW Notary pubkeys for this season
    int32_t hush_season = 0;
    bool ishush3        = strncmp(SMART_CHAIN_SYMBOL, "HUSH3",5) == 0 ? true : false;
    bool istush         = strncmp(SMART_CHAIN_SYMBOL, "TUSH",4) == 0 ? true : false;
    // TUSH uses height activation like HUSH3, other HSCs use timestamps
    hush_season         = (ishush3 || istush) ? gethushseason(height) : getacseason(timestamp);

    if(IS_HUSH_NOTARY) {
        fprintf(stderr,"%s: [%s] season=%d height=%d time=%d\n", __func__, ishush3 ? "HUSH3" : SMART_CHAIN_SYMBOL, hush_season, height, timestamp);
    }

    if ( hush_season != 0 )
    {
        if ( didinit[hush_season-1] == 0 )
        {
            for (i=0; i<NUM_HUSH_NOTARIES; i++)
                decode_hex(hush_pubkeys[hush_season-1][i],33,(char *)notaries_list[hush_season-1][i][1]);
            if ( ASSETCHAINS_PRIVATE != 0 )
            {
                // we need to populate the address array for the notary exemptions.
                for (i = 0; i<NUM_HUSH_NOTARIES; i++)
                    pubkey2addr((char *)NOTARY_ADDRESSES[hush_season-1][i],(uint8_t *)hush_pubkeys[hush_season-1][i]);
            }
            didinit[hush_season-1] = 1;
        }
        memcpy(pubkeys,hush_pubkeys[hush_season-1],NUM_HUSH_NOTARIES * 33);
        return(NUM_HUSH_NOTARIES);
    }

    return(-1);
}

int32_t hush_findnotary(int32_t *numnotariesp,uint8_t *pubkey33,int32_t height,uint32_t timestamp)
{
    int32_t i,n; uint8_t pubkeys[64][33];
    n = hush_notaries(pubkeys,height,timestamp);
    *numnotariesp = n;
    for (i=0; i<n; i++)
    {
        if ( memcmp(pubkey33,pubkeys[i],33) == 0 )
            return(i);
    }
    return(-1);
}

void hush_notarysinit(int32_t origheight,uint8_t pubkeys[64][33],int32_t num)
{
    static int32_t hwmheight;
    int32_t k,i,htind,height; struct knotary_entry *kp; struct knotaries_entry N;
    if ( Pubkeys == 0 )
        Pubkeys = (struct knotaries_entry *)calloc(1 + (HUSH_MAXBLOCKS / HUSH_DPOW_GAP),sizeof(*Pubkeys));
    memset(&N,0,sizeof(N));
    if ( origheight > 0 )
    {
        height = (origheight + HUSH_DPOW_GAP/2);
        height /= HUSH_DPOW_GAP;
        height = ((height + 1) * HUSH_DPOW_GAP);
        htind = (height / HUSH_DPOW_GAP);
        if ( htind >= HUSH_MAXBLOCKS / HUSH_DPOW_GAP )
            htind = (HUSH_MAXBLOCKS / HUSH_DPOW_GAP) - 1;
        //printf("htind.%d activation %d from %d vs %d | hwmheight.%d %s\n",htind,height,origheight,(((origheight+HUSH_DPOW_GAP/2)/HUSH_DPOW_GAP)+1)*HUSH_DPOW_GAP,hwmheight,SMART_CHAIN_SYMBOL);
    } else htind = 0;
    pthread_mutex_lock(&hush_mutex);
    for (k=0; k<num; k++)
    {
        kp = (struct knotary_entry *)calloc(1,sizeof(*kp));
        memcpy(kp->pubkey,pubkeys[k],33);
        kp->notaryid = k;
        HASH_ADD_KEYPTR(hh,N.Notaries,kp->pubkey,33,kp);
        if ( 0 && height > 10000 )
        {
            for (i=0; i<33; i++)
                printf("%02x",pubkeys[k][i]);
            printf(" notarypubs.[%d] ht.%d active at %d\n",k,origheight,htind*HUSH_DPOW_GAP);
        }
    }
    N.numnotaries = num;
    for (i=htind; i<HUSH_MAXBLOCKS / HUSH_DPOW_GAP; i++)
    {
        if ( Pubkeys[i].height != 0 && origheight < hwmheight )
        {
            printf("Pubkeys[%d].height %d < %d hwmheight, origheight.%d\n",i,Pubkeys[i].height,hwmheight,origheight);
            break;
        }
        Pubkeys[i] = N;
        Pubkeys[i].height = i * HUSH_DPOW_GAP;
    }
    pthread_mutex_unlock(&hush_mutex);
    if ( origheight > hwmheight )
        hwmheight = origheight;
}

int32_t hush_chosennotary(int32_t *notaryidp,int32_t height,uint8_t *pubkey33,uint32_t timestamp)
{
    // -1 if not notary, 0 if notary, 1 if special notary
    struct knotary_entry *kp; int32_t numnotaries=0,htind,modval = -1;
    *notaryidp = -1;
    if ( height < 0 )//|| height >= HUSH_MAXBLOCKS )
    {
        printf("hush_chosennotary ht.%d illegal\n",height);
        return(-1);
    }
    if ( height >= HUSH_NOTARIES_HARDCODED || SMART_CHAIN_SYMBOL[0] != 0 )
    {
        if ( (*notaryidp= hush_findnotary(&numnotaries,pubkey33,height,timestamp)) >= 0 && numnotaries != 0 )
        {
            modval = ((height % numnotaries) == *notaryidp);
            return(modval);
        }
    }
    if ( height >= 250000 )
        return(-1);
    if ( Pubkeys == 0 )
        hush_init(0);
    htind = height / HUSH_DPOW_GAP;
    if ( htind >= HUSH_MAXBLOCKS / HUSH_DPOW_GAP )
        htind = (HUSH_MAXBLOCKS / HUSH_DPOW_GAP) - 1;
    pthread_mutex_lock(&hush_mutex);
    HASH_FIND(hh,Pubkeys[htind].Notaries,pubkey33,33,kp);
    pthread_mutex_unlock(&hush_mutex);
    if ( kp != 0 )
    {
        if ( (numnotaries= Pubkeys[htind].numnotaries) > 0 )
        {
            *notaryidp = kp->notaryid;
            modval = ((height % numnotaries) == kp->notaryid);
            //printf("found notary.%d ht.%d modval.%d\n",kp->notaryid,height,modval);
        } else printf("unexpected zero notaries at height.%d\n",height);
    } //else printf("cant find kp at htind.%d ht.%d\n",htind,height);
    //int32_t i; for (i=0; i<33; i++)
    //    printf("%02x",pubkey33[i]);
    //printf(" ht.%d notary.%d special.%d htind.%d num.%d\n",height,*notaryidp,modval,htind,numnotaries);
    return(modval);
}

//struct hush_state *hush_stateptr(char *symbol,char *dest);

struct notarized_checkpoint *hush_npptr_for_height(int32_t height, int *idx)
{
    char symbol[HUSH_SMART_CHAIN_MAXLEN],dest[HUSH_SMART_CHAIN_MAXLEN]; int32_t i; struct hush_state *sp; struct notarized_checkpoint *np = 0;
    if ( (sp= hush_stateptr(symbol,dest)) != 0 )
    {
        for (i=sp->NUM_NPOINTS-1; i>=0; i--)
        {
            *idx = i;
            np = &sp->NPOINTS[i];
            if ( np->MoMdepth != 0 && height > np->notarized_height-(np->MoMdepth&0xffff) && height <= np->notarized_height )
                return(np);
        }
    }
    *idx = -1;
    return(0);
}

struct notarized_checkpoint *hush_npptr(int32_t height)
{
    int idx;
    return hush_npptr_for_height(height, &idx);
}

struct notarized_checkpoint *hush_npptr_at(int idx)
{
    char symbol[HUSH_SMART_CHAIN_MAXLEN],dest[HUSH_SMART_CHAIN_MAXLEN]; struct hush_state *sp;
    if ( (sp= hush_stateptr(symbol,dest)) != 0 )
        if (idx < sp->NUM_NPOINTS)
            return &sp->NPOINTS[idx];
    return(0);
}

int32_t hush_prevMoMheight()
{
    static uint256 zero;
    char symbol[HUSH_SMART_CHAIN_MAXLEN],dest[HUSH_SMART_CHAIN_MAXLEN]; int32_t i; struct hush_state *sp; struct notarized_checkpoint *np = 0;
    if ( (sp= hush_stateptr(symbol,dest)) != 0 )
    {
        for (i=sp->NUM_NPOINTS-1; i>=0; i--)
        {
            np = &sp->NPOINTS[i];
            if ( np->MoM != zero )
                return(np->notarized_height);
        }
    }
    return(0);
}

int32_t hush_notarized_height(int32_t *prevMoMheightp,uint256 *hashp,uint256 *txidp)
{
    char symbol[HUSH_SMART_CHAIN_MAXLEN],dest[HUSH_SMART_CHAIN_MAXLEN]; struct hush_state *sp;
    *prevMoMheightp = 0;
    memset(hashp,0,sizeof(*hashp));
    memset(txidp,0,sizeof(*txidp));
    if ( (sp= hush_stateptr(symbol,dest)) != 0 )
    {
        CBlockIndex *pindex;
        if ( (pindex= hush_blockindex(sp->NOTARIZED_HASH)) == 0 || pindex->GetHeight() < 0 )
        {
            //fprintf(stderr,"found orphaned notarization at ht.%d pindex.%p\n",sp->NOTARIZED_HEIGHT,(void *)pindex);
            memset(&sp->NOTARIZED_HASH,0,sizeof(sp->NOTARIZED_HASH));
            memset(&sp->NOTARIZED_DESTTXID,0,sizeof(sp->NOTARIZED_DESTTXID));
            sp->NOTARIZED_HEIGHT = 0;
        }
        else
        {
            *hashp = sp->NOTARIZED_HASH;
            *txidp = sp->NOTARIZED_DESTTXID;
            *prevMoMheightp = hush_prevMoMheight();
        }
        return(sp->NOTARIZED_HEIGHT);
    } else return(0);
}

int32_t hush_dpowconfs(int32_t txheight,int32_t numconfs)
{
    static int32_t hadnotarization;
    char symbol[HUSH_SMART_CHAIN_MAXLEN],dest[HUSH_SMART_CHAIN_MAXLEN]; struct hush_state *sp;
    if ( HUSH_DPOWCONFS != 0 && txheight > 0 && numconfs > 0 && (sp= hush_stateptr(symbol,dest)) != 0 )
    {
        if ( sp->NOTARIZED_HEIGHT > 0 )
        {
            hadnotarization = 1;
            if ( txheight < sp->NOTARIZED_HEIGHT )
                return(numconfs);
            else return(1);
        }
        else if ( hadnotarization != 0 )
            return(1);
    }
    return(numconfs);
}

int32_t hush_MoMdata(int32_t *notarized_htp,uint256 *MoMp,uint256 *hushtxidp,int32_t height,uint256 *MoMoMp,int32_t *MoMoMoffsetp,int32_t *MoMoMdepthp,int32_t *hushstartip,int32_t *hushendip)
{
    struct notarized_checkpoint *np = 0;
    if ( (np= hush_npptr(height)) != 0 )
    {
        *notarized_htp = np->notarized_height;
        *MoMp = np->MoM;
        *hushtxidp = np->notarized_desttxid;
        *MoMoMp = np->MoMoM;
        *MoMoMoffsetp = np->MoMoMoffset;
        *MoMoMdepthp = np->MoMoMdepth;
        *hushstartip = np->hushstarti;
        *hushendip = np->hushendi;
        return(np->MoMdepth & 0xffff);
    }
    *notarized_htp = *MoMoMoffsetp = *MoMoMdepthp = *hushstartip = *hushendip = 0;
    memset(MoMp,0,sizeof(*MoMp));
    memset(MoMoMp,0,sizeof(*MoMoMp));
    memset(hushtxidp,0,sizeof(*hushtxidp));
    return(0);
}

int32_t hush_notarizeddata(int32_t nHeight,uint256 *notarized_hashp,uint256 *notarized_desttxidp)
{
    struct notarized_checkpoint *np = 0; int32_t i=0,flag = 0; char symbol[HUSH_SMART_CHAIN_MAXLEN],dest[HUSH_SMART_CHAIN_MAXLEN]; struct hush_state *sp;
    if ( (sp= hush_stateptr(symbol,dest)) != 0 )
    {
        if ( sp->NUM_NPOINTS > 0 )
        {
            flag = 0;
            if ( sp->last_NPOINTSi < sp->NUM_NPOINTS && sp->last_NPOINTSi > 0 )
            {
                np = &sp->NPOINTS[sp->last_NPOINTSi-1];
                if ( np->nHeight < nHeight )
                {
                    for (i=sp->last_NPOINTSi; i<sp->NUM_NPOINTS; i++)
                    {
                        if ( sp->NPOINTS[i].nHeight >= nHeight )
                        {
                            //printf("flag.1 i.%d np->ht %d [%d].ht %d >= nHeight.%d, last.%d num.%d\n",i,np->nHeight,i,sp->NPOINTS[i].nHeight,nHeight,sp->last_NPOINTSi,sp->NUM_NPOINTS);
                            flag = 1;
                            break;
                        }
                        np = &sp->NPOINTS[i];
                        sp->last_NPOINTSi = i;
                    }
                }
            }
            if ( flag == 0 )
            {
                np = 0;
                for (i=0; i<sp->NUM_NPOINTS; i++)
                {
                    if ( sp->NPOINTS[i].nHeight >= nHeight )
                    {
                        //printf("i.%d np->ht %d [%d].ht %d >= nHeight.%d\n",i,np->nHeight,i,sp->NPOINTS[i].nHeight,nHeight);
                        break;
                    }
                    np = &sp->NPOINTS[i];
                    sp->last_NPOINTSi = i;
                }
            }
        }
        if ( np != 0 )
        {
            //char str[65],str2[65]; printf("[%s] notarized_ht.%d\n",SMART_CHAIN_SYMBOL,np->notarized_height);
            if ( np->nHeight >= nHeight || (i < sp->NUM_NPOINTS && np[1].nHeight < nHeight) )
                printf("warning: flag.%d i.%d np->ht %d [1].ht %d >= nHeight.%d\n",flag,i,np->nHeight,np[1].nHeight,nHeight);
            *notarized_hashp = np->notarized_hash;
            *notarized_desttxidp = np->notarized_desttxid;
            return(np->notarized_height);
        }
    }
    memset(notarized_hashp,0,sizeof(*notarized_hashp));
    memset(notarized_desttxidp,0,sizeof(*notarized_desttxidp));
    return(0);
}

void hush_notarized_update(struct hush_state *sp,int32_t nHeight,int32_t notarized_height,uint256 notarized_hash,uint256 notarized_desttxid,uint256 MoM,int32_t MoMdepth)
{
    struct notarized_checkpoint *np;
    if ( notarized_height >= nHeight )
    {
        fprintf(stderr,"hush_notarized_update REJECT notarized_height %d > %d nHeight\n",notarized_height,nHeight);
        return;
    }
    if ( 0 && SMART_CHAIN_SYMBOL[0] != 0 )
        fprintf(stderr,"[%s] hush_notarized_update nHeight.%d notarized_height.%d\n",SMART_CHAIN_SYMBOL,nHeight,notarized_height);
    portable_mutex_lock(&hush_mutex);
    sp->NPOINTS = (struct notarized_checkpoint *)realloc(sp->NPOINTS,(sp->NUM_NPOINTS+1) * sizeof(*sp->NPOINTS));
    np = &sp->NPOINTS[sp->NUM_NPOINTS++];
    memset(np,0,sizeof(*np));
    np->nHeight = nHeight;
    sp->NOTARIZED_HEIGHT = np->notarized_height = notarized_height;
    sp->NOTARIZED_HASH = np->notarized_hash = notarized_hash;
    sp->NOTARIZED_DESTTXID = np->notarized_desttxid = notarized_desttxid;
    sp->MoM = np->MoM = MoM;
    sp->MoMdepth = np->MoMdepth = MoMdepth;
    portable_mutex_unlock(&hush_mutex);
}

void hush_init(int32_t height)
{
    static int didinit; uint256 zero; int32_t k,n; uint8_t pubkeys[64][33];
    if ( 0 && height != 0 )
        printf("hush_init ht.%d didinit.%d\n",height,didinit);
    memset(&zero,0,sizeof(zero));
    if ( didinit == 0 )
    {
        pthread_mutex_init(&hush_mutex,NULL);
        decode_hex(NOTARY_PUBKEY33,33,(char *)NOTARY_PUBKEY.c_str());
        if ( height >= 0 )
        {
            n = (int32_t)(sizeof(Notaries_genesis)/sizeof(*Notaries_genesis));
            for (k=0; k<n; k++)
            {
                if ( Notaries_genesis[k][0] == 0 || Notaries_genesis[k][1] == 0 || Notaries_genesis[k][0][0] == 0 || Notaries_genesis[k][1][0] == 0 )
                    break;
                decode_hex(pubkeys[k],33,(char *)Notaries_genesis[k][1]);
            }
            hush_notarysinit(0,pubkeys,k);
        }
        //for (i=0; i<sizeof(Minerids); i++)
        //    Minerids[i] = -2;
        didinit = 1;
        hush_stateupdate(0,0,0,0,zero,0,0,0,0,0,0,0,0,0,0,zero,0);
    }
}
