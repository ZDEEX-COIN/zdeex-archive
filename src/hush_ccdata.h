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

#ifndef H_HUSHCCDATA_H
#define H_HUSHCCDATA_H

struct hush_ccdata *CC_data;
int32_t CC_firstheight;

uint256 BuildMerkleTree(bool* fMutated, const std::vector<uint256> leaves, std::vector<uint256> &vMerkleTree);

uint256 hush_calcMoM(int32_t height,int32_t MoMdepth)
{
    static uint256 zero; CBlockIndex *pindex; int32_t i; std::vector<uint256> tree, leaves;
    bool fMutated;
    MoMdepth &= 0xffff;  // In case it includes the ccid
    if ( MoMdepth >= height )
        return(zero);
    for (i=0; i<MoMdepth; i++)
    {
        if ( (pindex= hush_chainactive(height - i)) != 0 )
            leaves.push_back(pindex->hashMerkleRoot);
        else
            return(zero);
    }
    return BuildMerkleTree(&fMutated, leaves, tree);
}

struct hush_ccdata_entry *hush_allMoMs(int32_t *nump,uint256 *MoMoMp,int32_t hushstarti,int32_t hushendi)
{
    struct hush_ccdata_entry *allMoMs=0; struct hush_ccdata *ccdata,*tmpptr; int32_t i,num,max;
    bool fMutated; std::vector<uint256> tree, leaves;
    num = max = 0;
    portable_mutex_lock(&HUSH_CC_mutex);
    DL_FOREACH_SAFE(CC_data,ccdata,tmpptr)
    {
        if ( ccdata->MoMdata.height <= hushendi && ccdata->MoMdata.height >= hushstarti )
        {
            if ( num >= max )
            {
                max += 100;
                allMoMs = (struct hush_ccdata_entry *)realloc(allMoMs,max * sizeof(*allMoMs));
            }
            allMoMs[num].MoM = ccdata->MoMdata.MoM;
            allMoMs[num].notarized_height = ccdata->MoMdata.notarized_height;
            allMoMs[num].hushheight = ccdata->MoMdata.height;
            allMoMs[num].txi = ccdata->MoMdata.txi;
            strcpy(allMoMs[num].symbol,ccdata->symbol);
            num++;
        }
        if ( ccdata->MoMdata.height < hushstarti )
            break;
    }
    portable_mutex_unlock(&HUSH_CC_mutex);
    if ( (*nump= num) > 0 )
    {
        for (i=0; i<num; i++)
            leaves.push_back(allMoMs[i].MoM);
        *MoMoMp = BuildMerkleTree(&fMutated, leaves, tree);
    }
    else
    {
        free(allMoMs);
        allMoMs = 0;
    }
    return(allMoMs);
}

int32_t hush_addpair(struct hush_ccdataMoMoM *mdata,int32_t notarized_height,int32_t offset,int32_t maxpairs)
{
    if ( maxpairs >= 0) {
        if ( mdata->numpairs >= maxpairs )
        {
            maxpairs += 100;
            mdata->pairs = (struct hush_ccdatapair *)realloc(mdata->pairs,sizeof(*mdata->pairs)*maxpairs);
            //fprintf(stderr,"pairs reallocated to %p num.%d\n",mdata->pairs,mdata->numpairs);
        }
    } else {
        fprintf(stderr,"hush_addpair.maxpairs %d must be >= 0\n",(int32_t)maxpairs);
        return(-1);
    }
    mdata->pairs[mdata->numpairs].notarized_height = notarized_height;
    mdata->pairs[mdata->numpairs].MoMoMoffset = offset;
    mdata->numpairs++;
    return(maxpairs);
}

int32_t hush_MoMoMdata(char *hexstr,int32_t hexsize,struct hush_ccdataMoMoM *mdata,char *symbol,int32_t hushheight,int32_t notarized_height)
{
    uint8_t hexdata[8192]; struct hush_ccdata *ccdata,*tmpptr; int32_t len,maxpairs,i,retval=-1,depth,starti,endi,CCid=0; struct hush_ccdata_entry *allMoMs;
    starti = endi = depth = len = maxpairs = 0;
    hexstr[0] = 0;
    if ( sizeof(hexdata)*2+1 > hexsize )
    {
        fprintf(stderr,"hexsize.%d too small for %d\n",hexsize,(int32_t)sizeof(hexdata));
        return(-1);
    }
    memset(mdata,0,sizeof(*mdata));
    portable_mutex_lock(&HUSH_CC_mutex);
    DL_FOREACH_SAFE(CC_data,ccdata,tmpptr)
    {
        if ( ccdata->MoMdata.height < hushheight )
        {
            //fprintf(stderr,"%s notarized.%d HUSH3.%d\n",ccdata->symbol,ccdata->MoMdata.notarized_height,ccdata->MoMdata.height);
            if ( strcmp(ccdata->symbol,symbol) == 0 )
            {
                if ( endi == 0 )
                {
                    endi = ccdata->MoMdata.height;
                    CCid = ccdata->CCid;
                }
                if ( (mdata->numpairs == 1 && notarized_height == 0) || ccdata->MoMdata.notarized_height <= notarized_height )
                {
                    starti = ccdata->MoMdata.height + 1;
                    if ( notarized_height == 0 )
                        notarized_height = ccdata->MoMdata.notarized_height;
                    break;
                }
            }
            starti = ccdata->MoMdata.height;
        }
    }
    portable_mutex_unlock(&HUSH_CC_mutex);
    mdata->hushstarti = starti;
    mdata->hushendi = endi;
    if ( starti != 0 && endi != 0 && endi >= starti )
    {
        if ( (allMoMs= hush_allMoMs(&depth,&mdata->MoMoM,starti,endi)) != 0 )
        {
            mdata->MoMoMdepth = depth;
            for (i=0; i<depth; i++)
            {
                if ( strcmp(symbol,allMoMs[i].symbol) == 0 )
                    maxpairs = hush_addpair(mdata,allMoMs[i].notarized_height,i,maxpairs);
            }
            if ( mdata->numpairs > 0 )
            {
                len += dragon_rwnum(1,&hexdata[len],sizeof(CCid),(uint8_t *)&CCid);
                len += dragon_rwnum(1,&hexdata[len],sizeof(uint32_t),(uint8_t *)&mdata->hushstarti);
                len += dragon_rwnum(1,&hexdata[len],sizeof(uint32_t),(uint8_t *)&mdata->hushendi);
                len += dragon_rwbignum(1,&hexdata[len],sizeof(mdata->MoMoM),(uint8_t *)&mdata->MoMoM);
                len += dragon_rwnum(1,&hexdata[len],sizeof(uint32_t),(uint8_t *)&mdata->MoMoMdepth);
                len += dragon_rwnum(1,&hexdata[len],sizeof(uint32_t),(uint8_t *)&mdata->numpairs);
                for (i=0; i<mdata->numpairs; i++)
                {
                    if ( len + sizeof(uint32_t)*2 > sizeof(hexdata) )
                    {
                        fprintf(stderr,"%s %d %d i.%d of %d exceeds hexdata.%d\n",symbol,hushheight,notarized_height,i,mdata->numpairs,(int32_t)sizeof(hexdata));
                        break;
                    }
                    len += dragon_rwnum(1,&hexdata[len],sizeof(uint32_t),(uint8_t *)&mdata->pairs[i].notarized_height);
                    len += dragon_rwnum(1,&hexdata[len],sizeof(uint32_t),(uint8_t *)&mdata->pairs[i].MoMoMoffset);
                }
                if ( i == mdata->numpairs && len*2+1 < hexsize )
                {
                    init_hexbytes_noT(hexstr,hexdata,len);
                    //fprintf(stderr,"hexstr.(%s)\n",hexstr);
                    retval = 0;
                } else fprintf(stderr,"%s %d %d too much hexdata[%d] for hexstr[%d]\n",symbol,hushheight,notarized_height,len,hexsize);
            }
            free(allMoMs);
        }
    }
    return(retval);
}

void hush_purge_ccdata(int32_t height)
{
    struct hush_ccdata *ccdata,*tmpptr;
    if ( SMART_CHAIN_SYMBOL[0] == 0 )
    {
        portable_mutex_lock(&HUSH_CC_mutex);
        DL_FOREACH_SAFE(CC_data,ccdata,tmpptr)
        {
            if ( ccdata->MoMdata.height >= height )
            {
                printf("PURGE %s notarized.%d\n",ccdata->symbol,ccdata->MoMdata.notarized_height);
                DL_DELETE(CC_data,ccdata);
                free(ccdata);
            } else break;
        }
        portable_mutex_unlock(&HUSH_CC_mutex);
    }
    else
    {
        // purge notarized data
    }
}

// this is just a demo of ccdata processing to create example data for the MoMoM and allMoMs calls
int32_t hush_rwccdata(char *thischain,int32_t rwflag,struct hush_ccdata *ccdata,struct hush_ccdataMoMoM *MoMoMdata)
{
    uint256 hash,zero; bits256 tmp; int32_t i,nonz; struct hush_ccdata *ptr; struct notarized_checkpoint *np;
    return(0); // disable this path as libscott method is much better
    if ( rwflag == 0 )
    {
        // load from disk
    }
    else
    {
        // write to disk
    }
    if ( ccdata->MoMdata.height > 0 && (CC_firstheight == 0 || ccdata->MoMdata.height < CC_firstheight) )
        CC_firstheight = ccdata->MoMdata.height;
    for (nonz=i=0; i<32; i++)
    {
        if ( (tmp.bytes[i]= ((uint8_t *)&ccdata->MoMdata.MoM)[31-i]) != 0 )
            nonz++;
    }
    if ( nonz == 0 )
        return(0);
    memcpy(&hash,&tmp,sizeof(hash));
    //fprintf(stderr,"[%s] ccdata.%s id.%d notarized_ht.%d MoM.%s height.%d/t%d\n",SMART_CHAIN_SYMBOL,ccdata->symbol,ccdata->CCid,ccdata->MoMdata.notarized_height,hash.ToString().c_str(),ccdata->MoMdata.height,ccdata->MoMdata.txi);
    if ( SMART_CHAIN_SYMBOL[0] == 0 )
    {
        if ( CC_data != 0 && (CC_data->MoMdata.height > ccdata->MoMdata.height || (CC_data->MoMdata.height == ccdata->MoMdata.height && CC_data->MoMdata.txi >= ccdata->MoMdata.txi)) )
        {
            printf("out of order detected? SKIP CC_data ht.%d/txi.%d vs ht.%d/txi.%d\n",CC_data->MoMdata.height,CC_data->MoMdata.txi,ccdata->MoMdata.height,ccdata->MoMdata.txi);
        }
        else
        {
            ptr = (struct hush_ccdata *)calloc(1,sizeof(*ptr));
            *ptr = *ccdata;
            portable_mutex_lock(&HUSH_CC_mutex);
            DL_PREPEND(CC_data,ptr);
            portable_mutex_unlock(&HUSH_CC_mutex);
        }
    }
    else
    {
        if ( MoMoMdata != 0 && MoMoMdata->pairs != 0 )
        {
            for (i=0; i<MoMoMdata->numpairs; i++)
            {
                if ( (np= hush_npptr(MoMoMdata->pairs[i].notarized_height)) != 0 )
                {
                    memset(&zero,0,sizeof(zero));
                    if ( memcmp(&np->MoMoM,&zero,sizeof(np->MoMoM)) == 0 )
                    {
                        np->MoMoM = MoMoMdata->MoMoM;
                        np->MoMoMdepth = MoMoMdata->MoMoMdepth;
                        np->MoMoMoffset = MoMoMdata->MoMoMoffset;
                        np->hushstarti = MoMoMdata->hushstarti;
                        np->hushendi = MoMoMdata->hushendi;
                    }
                    else if ( memcmp(&np->MoMoM,&MoMoMdata->MoMoM,sizeof(np->MoMoM)) != 0 || np->MoMoMdepth != MoMoMdata->MoMoMdepth || np->MoMoMoffset != MoMoMdata->MoMoMoffset || np->hushstarti != MoMoMdata->hushstarti || np->hushendi != MoMoMdata->hushendi )
                    {
                        fprintf(stderr,"preexisting MoMoM mismatch: %s (%d %d %d %d) vs %s (%d %d %d %d)\n",np->MoMoM.ToString().c_str(),np->MoMoMdepth,np->MoMoMoffset,np->hushstarti,np->hushendi,MoMoMdata->MoMoM.ToString().c_str(),MoMoMdata->MoMoMdepth,MoMoMdata->MoMoMoffset,MoMoMdata->hushstarti,MoMoMdata->hushendi);
                    }
                }
            }
        }
    }
    return(1);
}

#endif
