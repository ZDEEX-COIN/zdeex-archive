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

#ifndef H_HUSHKV_H
#define H_HUSHKV_H

#include "hush_defs.h"

int32_t hush_kvcmp(uint8_t *refvalue,uint16_t refvaluesize,uint8_t *value,uint16_t valuesize)
{
    if ( refvalue == 0 && value == 0 )
        return(0);
    else if ( refvalue == 0 || value == 0 )
        return(-1);
    else if ( refvaluesize != valuesize )
        return(-1);
    else return(memcmp(refvalue,value,valuesize));
}

int32_t hush_kvnumdays(uint32_t flags)
{
    int32_t numdays;
    if ( (numdays= ((flags>>2)&0x3ff)+1) > 365 )
        numdays = 365;
    return(numdays);
}

int32_t hush_kvduration(uint32_t flags)
{
    return(hush_kvnumdays(flags) * HUSH_KVDURATION);
}

uint64_t hush_kvfee(uint32_t flags,int32_t opretlen,int32_t keylen)
{
    int32_t numdays,k; uint64_t fee;
    if ( (k= keylen) > 32 )
        k = 32;
    numdays = hush_kvnumdays(flags);
    if ( (fee= (numdays*(opretlen * opretlen / k))) < 100000 )
        fee = 100000;
    return(fee);
}

int32_t hush_kvsearch(uint256 *pubkeyp,int32_t current_height,uint32_t *flagsp,int32_t *heightp,uint8_t value[DRAGON_MAXSCRIPTSIZE],uint8_t *key,int32_t keylen)
{
    struct hush_kv *ptr; int32_t duration,retval = -1;
    *heightp = -1;
    *flagsp = 0;
    memset(pubkeyp,0,sizeof(*pubkeyp));
    portable_mutex_lock(&HUSH_KV_mutex);
    HASH_FIND(hh,HUSH_KV,key,keylen,ptr);
    if ( ptr != 0 )
    {
        duration = hush_kvduration(ptr->flags);
        //fprintf(stderr,"duration.%d flags.%d current.%d ht.%d keylen.%d valuesize.%d\n",duration,ptr->flags,current_height,ptr->height,ptr->keylen,ptr->valuesize);
        if ( current_height > (ptr->height + duration) )
        {
            HASH_DELETE(hh,HUSH_KV,ptr);
            if ( ptr->value != 0 )
                free(ptr->value);
            if ( ptr->key != 0 )
                free(ptr->key);
            free(ptr);
        }
        else
        {
            *heightp = ptr->height;
            *flagsp = ptr->flags;
            int32_t i; for (i=0; i<32; i++)
            {
                //printf("%02x",((uint8_t *)&ptr->pubkey)[31-i]);
                ((uint8_t *)pubkeyp)[i] = ((uint8_t *)&ptr->pubkey)[31-i];
            }
            //printf(" ptr->pubkey\n");
            memcpy(pubkeyp,&ptr->pubkey,sizeof(*pubkeyp));
            if ( (retval= ptr->valuesize) > 0 )
                memcpy(value,ptr->value,retval);
        }
    } //else fprintf(stderr,"couldnt find (%s)\n",(char *)key);
    portable_mutex_unlock(&HUSH_KV_mutex);
    if ( retval < 0 )
    {
        // search rawmempool
    }
    return(retval);
}

void hush_kvupdate(uint8_t *opretbuf,int32_t opretlen,uint64_t value)
{
    static uint256 zeroes;
    uint32_t flags; uint256 pubkey,refpubkey,sig; int32_t i,refvaluesize,hassig,coresize,haspubkey,height,kvheight; uint16_t keylen,valuesize,newflag = 0; uint8_t *key,*valueptr,keyvalue[DRAGON_MAXSCRIPTSIZE*8]; struct hush_kv *ptr; char *transferpubstr,*tstr; uint64_t fee;
    if ( SMART_CHAIN_SYMBOL[0] == 0 ) // disable KV
        return;
    dragon_rwnum(0,&opretbuf[1],sizeof(keylen),&keylen);
    dragon_rwnum(0,&opretbuf[3],sizeof(valuesize),&valuesize);
    dragon_rwnum(0,&opretbuf[5],sizeof(height),&height);
    dragon_rwnum(0,&opretbuf[9],sizeof(flags),&flags);
    key = &opretbuf[13];
    if ( keylen+13 > opretlen )
    {
        static uint32_t counter;
        if ( ++counter < 1 )
            fprintf(stderr,"hush_kvupdate: keylen.%d + 13 > opretlen.%d, this can be ignored\n",keylen,opretlen);
        return;
    }
    valueptr = &key[keylen];
    fee = hush_kvfee(flags,opretlen,keylen);
    //fprintf(stderr,"fee %.8f vs %.8f flags.%d keylen.%d valuesize.%d height.%d (%02x %02x %02x) (%02x %02x %02x)\n",(double)fee/COIN,(double)value/COIN,flags,keylen,valuesize,height,key[0],key[1],key[2],valueptr[0],valueptr[1],valueptr[2]);
    if ( value >= fee )
    {
        coresize = (int32_t)(sizeof(flags)+sizeof(height)+sizeof(keylen)+sizeof(valuesize)+keylen+valuesize+1);
        if ( opretlen == coresize || opretlen == coresize+sizeof(uint256) || opretlen == coresize+2*sizeof(uint256) )
        {
            memset(&pubkey,0,sizeof(pubkey));
            memset(&sig,0,sizeof(sig));
            if ( (haspubkey= (opretlen >= coresize+sizeof(uint256))) != 0 )
            {
                for (i=0; i<32; i++)
                    ((uint8_t *)&pubkey)[i] = opretbuf[coresize+i];
            }
            if ( (hassig= (opretlen == coresize+sizeof(uint256)*2)) != 0 )
            {
                for (i=0; i<32; i++)
                    ((uint8_t *)&sig)[i] = opretbuf[coresize+sizeof(uint256)+i];
            }
            memcpy(keyvalue,key,keylen);
            if ( (refvaluesize= hush_kvsearch((uint256 *)&refpubkey,height,&flags,&kvheight,&keyvalue[keylen],key,keylen)) >= 0 )
            {
                if ( memcmp(&zeroes,&refpubkey,sizeof(refpubkey)) != 0 )
                {
                    if ( hush_kvsigverify(keyvalue,keylen+refvaluesize,refpubkey,sig) < 0 )
                    {
                        //fprintf(stderr,"hush_kvsigverify error [%d]\n",coresize-13);
                        return;
                    }
                }
            }
            portable_mutex_lock(&HUSH_KV_mutex);
            HASH_FIND(hh,HUSH_KV,key,keylen,ptr);
            if ( ptr != 0 )
            {
                //fprintf(stderr,"(%s) already there\n",(char *)key);
                //if ( (ptr->flags & HUSH_KVPROTECTED) != 0 )
                {
                    tstr = (char *)"transfer:";
                    transferpubstr = (char *)&valueptr[strlen(tstr)];
                    if ( strncmp(tstr,(char *)valueptr,strlen(tstr)) == 0 && is_hexstr(transferpubstr,0) == 64 )
                    {
                        printf("transfer.(%s) to [%s]? ishex.%d\n",key,transferpubstr,is_hexstr(transferpubstr,0));
                        for (i=0; i<32; i++)
                            ((uint8_t *)&pubkey)[31-i] = _decode_hex(&transferpubstr[i*2]);
                    }
                }
            }
            else if ( ptr == 0 )
            {
                ptr = (struct hush_kv *)calloc(1,sizeof(*ptr));
                ptr->key = (uint8_t *)calloc(1,keylen);
                ptr->keylen = keylen;
                memcpy(ptr->key,key,keylen);
                newflag = 1;
                HASH_ADD_KEYPTR(hh,HUSH_KV,ptr->key,ptr->keylen,ptr);
                //fprintf(stderr,"KV add.(%s) (%s)\n",ptr->key,valueptr);
            }
            if ( newflag != 0 || (ptr->flags & HUSH_KVPROTECTED) == 0 )
            {
                if ( ptr->value != 0 )
                    free(ptr->value), ptr->value = 0;
                if ( (ptr->valuesize= valuesize) != 0 )
                {
                    ptr->value = (uint8_t *)calloc(1,valuesize);
                    memcpy(ptr->value,valueptr,valuesize);
                }
            } else fprintf(stderr,"newflag.%d zero or protected %d\n",newflag,(ptr->flags & HUSH_KVPROTECTED));
            /*for (i=0; i<32; i++)
                printf("%02x",((uint8_t *)&ptr->pubkey)[i]);
            printf(" <- ");
            for (i=0; i<32; i++)
                printf("%02x",((uint8_t *)&pubkey)[i]);
            printf(" new pubkey\n");*/
            memcpy(&ptr->pubkey,&pubkey,sizeof(ptr->pubkey));
            ptr->height = height;
            ptr->flags = flags; // jl777 used to or in KVPROTECTED
            portable_mutex_unlock(&HUSH_KV_mutex);
        } else fprintf(stderr,"KV update size mismatch %d vs %d\n",opretlen,coresize);
    } else fprintf(stderr,"not enough fee\n");
}

#endif
