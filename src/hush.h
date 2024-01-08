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
#ifndef H_HUSH_H
#define H_HUSH_H
#include "hush_defs.h"

#ifdef _WIN32
#define printf(...)
#endif

// Todo: verify: reorgs, lollerskates
#define HUSH_SMART_CHAINS_WAITNOTARIZE
#define HUSH_PAXMAX (10000 * COIN)
extern int32_t NOTARIZED_HEIGHT;
uint256 NOTARIZED_HASH,NOTARIZED_DESTTXID;

#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <ctype.h>
#include "uthash.h"
#include "utlist.h"

int32_t gettxout_scriptPubKey(uint8_t *scriptPubkey,int32_t maxsize,uint256 txid,int32_t n);
void hush_event_rewind(struct hush_state *sp,char *symbol,int32_t height);
int32_t hush_connectblock(bool fJustCheck, CBlockIndex *pindex,CBlock& block);
bool check_pprevnotarizedht();

#include "hush_structs.h"
#include "hush_globals.h"
#include "hush_utils.h"
#include "hush_curve25519.h"
#include "hush_cJSON.c"
#include "hush_bitcoind.h"
#include "hush_pax.h"
#include "hush_notary.h"

int32_t hush_parsestatefile(struct hush_state *sp,FILE *fp,char *symbol,char *dest);
#include "hush_kv.h"
#include "hush_gateway.h"
#include "hush_events.h"
#include "hush_ccdata.h"

void hush_currentheight_set(int32_t height)
{
    char symbol[HUSH_SMART_CHAIN_MAXLEN],dest[HUSH_SMART_CHAIN_MAXLEN]; struct hush_state *sp;
    if ( (sp= hush_stateptr(symbol,dest)) != 0 )
        sp->CURRENT_HEIGHT = height;
}

extern struct NSPV_inforesp NSPV_inforesult;
int32_t hush_currentheight()
{
    char symbol[HUSH_SMART_CHAIN_MAXLEN],dest[HUSH_SMART_CHAIN_MAXLEN]; struct hush_state *sp;
    if ( HUSH_NSPV_SUPERLITE )
    {
        return (NSPV_inforesult.height);
    }
    if ( (sp= hush_stateptr(symbol,dest)) != 0 )
        return(sp->CURRENT_HEIGHT);
    else return(0);
}

int32_t hush_parsestatefile(struct hush_state *sp,FILE *fp,char *symbol,char *dest)
{
    static int32_t errs;
    int32_t func,ht,notarized_height,num,matched=0,MoMdepth; uint256 MoM,notarized_hash,notarized_desttxid; uint8_t pubkeys[64][33];
    if ( (func= fgetc(fp)) != EOF )
    {
        matched = (strcmp(symbol,SMART_CHAIN_SYMBOL) == 0);
        if ( fread(&ht,1,sizeof(ht),fp) != sizeof(ht) )
            errs++;
        if ( 0 && SMART_CHAIN_SYMBOL[0] != 0 && func != 'T' )
            printf("[%s] matched.%d fpos.%ld func.(%d %c) ht.%d\n",SMART_CHAIN_SYMBOL,matched,ftell(fp),func,func,ht);
        if ( func == 'P' )
        {
            if ( (num= fgetc(fp)) <= 64 )
            {
                if ( fread(pubkeys,33,num,fp) != num )
                    errs++;
                else
                {
                    //printf("updated %d pubkeys at %s ht.%d\n",num,symbol,ht);
                    if ( (HUSH_EXTERNAL_NOTARIES != 0 && matched != 0) )
                        hush_eventadd_pubkeys(sp,symbol,ht,num,pubkeys);
                }
            } else printf("illegal num.%d\n",num);
        }
        else if ( func == 'N' || func == 'M' )
        {
            if ( fread(&notarized_height,1,sizeof(notarized_height),fp) != sizeof(notarized_height) )
                errs++;
            if ( fread(&notarized_hash,1,sizeof(notarized_hash),fp) != sizeof(notarized_hash) )
                errs++;
            if ( fread(&notarized_desttxid,1,sizeof(notarized_desttxid),fp) != sizeof(notarized_desttxid) )
                errs++;
            if ( func == 'M' )
            {
                if ( fread(&MoM,1,sizeof(MoM),fp) != sizeof(MoM) )
                    errs++;
                if ( fread(&MoMdepth,1,sizeof(MoMdepth),fp) != sizeof(MoMdepth) )
                    errs++;
                if ( 0 && SMART_CHAIN_SYMBOL[0] != 0 && sp != 0 )
                    printf("%s load[%s.%d -> %s] NOTARIZED %d %s MoM.%s %d CCid.%u\n",SMART_CHAIN_SYMBOL,symbol,sp->NUM_NPOINTS,dest,notarized_height,notarized_hash.ToString().c_str(),MoM.ToString().c_str(),MoMdepth&0xffff,(MoMdepth>>16)&0xffff);
            }
            else
            {
                memset(&MoM,0,sizeof(MoM));
                MoMdepth = 0;
            }
            //if ( matched != 0 ) global independent states -> inside *sp
            hush_eventadd_notarized(sp,symbol,ht,dest,notarized_hash,notarized_desttxid,notarized_height,MoM,MoMdepth);
        }
        else if ( func == 'U' ) // deprecated
        {
            uint8_t n,nid; uint256 hash; uint64_t mask;
            n = fgetc(fp);
            nid = fgetc(fp);
            //printf("U %d %d\n",n,nid);
            if ( fread(&mask,1,sizeof(mask),fp) != sizeof(mask) )
                errs++;
            if ( fread(&hash,1,sizeof(hash),fp) != sizeof(hash) )
                errs++;
            //if ( matched != 0 )
            //    hush_eventadd_utxo(sp,symbol,ht,nid,hash,mask,n);
        }
        else if ( func == 'K' )
        {
            int32_t kheight;
            if ( fread(&kheight,1,sizeof(kheight),fp) != sizeof(kheight) )
                errs++;
            //if ( matched != 0 ) global independent states -> inside *sp
            //printf("%s.%d load[%s] ht.%d\n",SMART_CHAIN_SYMBOL,ht,symbol,kheight);
            hush_eventadd_hushheight(sp,symbol,ht,kheight,0);
        }
        else if ( func == 'T' )
        {
            int32_t kheight,ktimestamp;
            if ( fread(&kheight,1,sizeof(kheight),fp) != sizeof(kheight) )
                errs++;
            if ( fread(&ktimestamp,1,sizeof(ktimestamp),fp) != sizeof(ktimestamp) )
                errs++;
            //if ( matched != 0 ) global independent states -> inside *sp
            //printf("%s.%d load[%s] ht.%d t.%u\n",SMART_CHAIN_SYMBOL,ht,symbol,kheight,ktimestamp);
            hush_eventadd_hushheight(sp,symbol,ht,kheight,ktimestamp);
        }
        else if ( func == 'R' )
        {
            uint16_t olen,v; uint64_t ovalue; uint256 txid; uint8_t opret[16384*4];
            if ( fread(&txid,1,sizeof(txid),fp) != sizeof(txid) )
                errs++;
            if ( fread(&v,1,sizeof(v),fp) != sizeof(v) )
                errs++;
            if ( fread(&ovalue,1,sizeof(ovalue),fp) != sizeof(ovalue) )
                errs++;
            if ( fread(&olen,1,sizeof(olen),fp) != sizeof(olen) )
                errs++;
            if ( olen < sizeof(opret) )
            {
                if ( fread(opret,1,olen,fp) != olen )
                    errs++;
                if ( 0 && SMART_CHAIN_SYMBOL[0] != 0 && matched != 0 )
                {
                    int32_t i;  for (i=0; i<olen; i++)
                        printf("%02x",opret[i]);
                    printf(" %s.%d load[%s] opret[%c] len.%d %.8f\n",SMART_CHAIN_SYMBOL,ht,symbol,opret[0],olen,(double)ovalue/COIN);
                }
                hush_eventadd_opreturn(sp,symbol,ht,txid,ovalue,v,opret,olen); // global shared state -> global PAX
            } else
            {
                int32_t i;
                for (i=0; i<olen; i++)
                    fgetc(fp);
                //printf("illegal olen.%u\n",olen);
            }
        }
        else if ( func == 'D' )
        {
            printf("unexpected function D[%d]\n",ht);
        }
        else if ( func == 'V' )
        {
            int32_t numpvals; uint32_t pvals[128];
            numpvals = fgetc(fp);
            if ( numpvals*sizeof(uint32_t) <= sizeof(pvals) && fread(pvals,sizeof(uint32_t),numpvals,fp) == numpvals )
            {
                //if ( matched != 0 ) global shared state -> global PVALS
                //printf("%s load[%s] prices %d\n",SMART_CHAIN_SYMBOL,symbol,ht);
                hush_eventadd_pricefeed(sp,symbol,ht,pvals,numpvals);
                //printf("load pvals ht.%d numpvals.%d\n",ht,numpvals);
            } else printf("error loading pvals[%d]\n",numpvals);
        } // else printf("[%s] %s illegal func.(%d %c)\n",SMART_CHAIN_SYMBOL,symbol,func,func);
        return(func);
    } else return(-1);
}

int32_t memread(void *dest,int32_t size,uint8_t *filedata,long *fposp,long datalen)
{
    if ( *fposp+size <= datalen )
    {
        memcpy(dest,&filedata[*fposp],size);
        (*fposp) += size;
        return(size);
    }
    return(-1);
}

int32_t hush_parsestatefiledata(struct hush_state *sp,uint8_t *filedata,long *fposp,long datalen,char *symbol,char *dest)
{
    static int32_t errs;
    int32_t func= -1,ht,notarized_height,MoMdepth,num,matched=0; uint256 MoM,notarized_hash,notarized_desttxid; uint8_t pubkeys[64][33]; long fpos = *fposp;
    if ( fpos < datalen )
    {
        func    = filedata[fpos++];
        matched = (strcmp(symbol,SMART_CHAIN_SYMBOL) == 0);

        if ( memread(&ht,sizeof(ht),filedata,&fpos,datalen) != sizeof(ht) )
            errs++;
        if ( func == 'P' )
        {
            if ( (num= filedata[fpos++]) <= 64 )
            {
                if ( memread(pubkeys,33*num,filedata,&fpos,datalen) != 33*num )
                    errs++;
                else
                {
                    //printf("updated %d pubkeys at %s ht.%d\n",num,symbol,ht);
                    if ( (HUSH_EXTERNAL_NOTARIES != 0 && matched != 0) )
                        hush_eventadd_pubkeys(sp,symbol,ht,num,pubkeys);
                }
            } else printf("illegal num.%d\n",num);
        }
        else if ( func == 'N' || func == 'M' )
        {
            if ( memread(&notarized_height,sizeof(notarized_height),filedata,&fpos,datalen) != sizeof(notarized_height) )
                errs++;
            if ( memread(&notarized_hash,sizeof(notarized_hash),filedata,&fpos,datalen) != sizeof(notarized_hash) )
                errs++;
            if ( memread(&notarized_desttxid,sizeof(notarized_desttxid),filedata,&fpos,datalen) != sizeof(notarized_desttxid) )
                errs++;
            if ( func == 'M' )
            {
                if ( memread(&MoM,sizeof(MoM),filedata,&fpos,datalen) != sizeof(MoM) )
                    errs++;
                if ( memread(&MoMdepth,sizeof(MoMdepth),filedata,&fpos,datalen) != sizeof(MoMdepth) )
                    errs++;
                if ( 0 && SMART_CHAIN_SYMBOL[0] != 0 && sp != 0 )
                    printf("%s load[%s.%d -> %s] NOTARIZED %d %s MoM.%s %d CCid.%u\n",SMART_CHAIN_SYMBOL,symbol,sp->NUM_NPOINTS,dest,notarized_height,notarized_hash.ToString().c_str(),MoM.ToString().c_str(),MoMdepth&0xffff,(MoMdepth>>16)&0xffff);
            }
            else
            {
                memset(&MoM,0,sizeof(MoM));
                MoMdepth = 0;
            }
            hush_eventadd_notarized(sp,symbol,ht,dest,notarized_hash,notarized_desttxid,notarized_height,MoM,MoMdepth);
        }
        else if ( func == 'U' ) // deprecated
        {
            uint8_t n,nid; uint256 hash; uint64_t mask;
            n = filedata[fpos++];
            nid = filedata[fpos++];
            //printf("U %d %d\n",n,nid);
            if ( memread(&mask,sizeof(mask),filedata,&fpos,datalen) != sizeof(mask) )
                errs++;
            if ( memread(&hash,sizeof(hash),filedata,&fpos,datalen) != sizeof(hash) )
                errs++;
        }
        else if ( func == 'K' )
        {
            int32_t kheight;
            if ( memread(&kheight,sizeof(kheight),filedata,&fpos,datalen) != sizeof(kheight) )
                errs++;
             hush_eventadd_hushheight(sp,symbol,ht,kheight,0);
        }
        else if ( func == 'T' )
        {
            int32_t kheight,ktimestamp;
            if ( memread(&kheight,sizeof(kheight),filedata,&fpos,datalen) != sizeof(kheight) )
                errs++;
            if ( memread(&ktimestamp,sizeof(ktimestamp),filedata,&fpos,datalen) != sizeof(ktimestamp) )
                errs++;
            //if ( matched != 0 ) global independent states -> inside *sp
            //printf("%s.%d load[%s] ht.%d t.%u\n",SMART_CHAIN_SYMBOL,ht,symbol,kheight,ktimestamp);
            hush_eventadd_hushheight(sp,symbol,ht,kheight,ktimestamp);
        }
        else if ( func == 'R' )
        {
            uint16_t olen,v; uint64_t ovalue; uint256 txid; uint8_t opret[16384*4];
            if ( memread(&txid,sizeof(txid),filedata,&fpos,datalen) != sizeof(txid) )
                errs++;
            if ( memread(&v,sizeof(v),filedata,&fpos,datalen) != sizeof(v) )
                errs++;
            if ( memread(&ovalue,sizeof(ovalue),filedata,&fpos,datalen) != sizeof(ovalue) )
                errs++;
            if ( memread(&olen,sizeof(olen),filedata,&fpos,datalen) != sizeof(olen) )
                errs++;
            if ( olen < sizeof(opret) )
            {
                if ( memread(opret,olen,filedata,&fpos,datalen) != olen )
                    errs++;
                if ( 0 && SMART_CHAIN_SYMBOL[0] != 0 && matched != 0 )
                {
                    int32_t i;  for (i=0; i<olen; i++)
                        printf("%02x",opret[i]);
                    printf(" %s.%d load[%s] opret[%c] len.%d %.8f\n",SMART_CHAIN_SYMBOL,ht,symbol,opret[0],olen,(double)ovalue/COIN);
                }
                hush_eventadd_opreturn(sp,symbol,ht,txid,ovalue,v,opret,olen); // global shared state -> global PAX
            } else
            {
                int32_t i;
                for (i=0; i<olen; i++)
                    filedata[fpos++];
                //printf("illegal olen.%u\n",olen);
            }
        }
        else if ( func == 'D' )
        {
            printf("unexpected function D[%d]\n",ht);
        }
        else if ( func == 'V' )
        {
            int32_t numpvals; uint32_t pvals[128];
            numpvals = filedata[fpos++];
            if ( numpvals*sizeof(uint32_t) <= sizeof(pvals) && memread(pvals,(int32_t)(sizeof(uint32_t)*numpvals),filedata,&fpos,datalen) == numpvals*sizeof(uint32_t) )
            {
                //if ( matched != 0 ) global shared state -> global PVALS
                //printf("%s load[%s] prices %d\n",SMART_CHAIN_SYMBOL,symbol,ht);
                hush_eventadd_pricefeed(sp,symbol,ht,pvals,numpvals);
                //printf("load pvals ht.%d numpvals.%d\n",ht,numpvals);
            } else printf("error loading pvals[%d]\n",numpvals);
        } // else printf("[%s] %s illegal func.(%d %c)\n",SMART_CHAIN_SYMBOL,symbol,func,func);
        *fposp = fpos;
        return(func);
    }
    return(-1);
}

void hush_stateupdate(int32_t height,uint8_t notarypubs[][33],uint8_t numnotaries,uint8_t notaryid,uint256 txhash,uint64_t voutmask,uint8_t numvouts,uint32_t *pvals,uint8_t numpvals,int32_t HUSHheight,uint32_t HUSHtimestamp,uint64_t opretvalue,uint8_t *opretbuf,uint16_t opretlen,uint16_t vout,uint256 MoM,int32_t MoMdepth)
{
    static FILE *fp; static int32_t errs,didinit; static uint256 zero;
    struct hush_state *sp; char fname[512],symbol[HUSH_SMART_CHAIN_MAXLEN],dest[HUSH_SMART_CHAIN_MAXLEN]; int32_t retval,ht,func; uint8_t num,pubkeys[64][33];
    if ( didinit == 0 )
    {
        portable_mutex_init(&HUSH_KV_mutex);
        portable_mutex_init(&HUSH_CC_mutex);
        didinit = 1;
    }
    if ( (sp= hush_stateptr(symbol,dest)) == 0 )
    {
        HUSH_INITDONE = (uint32_t)time(NULL);
        printf("[%s] no hush_stateptr\n",SMART_CHAIN_SYMBOL);
        return;
    }
    //printf("[%s] (%s) -> (%s)\n",SMART_CHAIN_SYMBOL,symbol,dest);
    if ( fp == 0 )
    {
        hush_statefname(fname,SMART_CHAIN_SYMBOL,(char *)"hushstate");
        if ( (fp= fopen(fname,"rb+")) != 0 )
        {
            if ( (retval= hush_faststateinit(sp,fname,symbol,dest)) > 0 )
                fseek(fp,0,SEEK_END);
            else
            {
                fprintf(stderr,"hush_faststateinit retval.%d\n",retval);
                while ( hush_parsestatefile(sp,fp,symbol,dest) >= 0 )
                    ;
            }
        } else fp = fopen(fname,"wb+");
        HUSH_INITDONE = (uint32_t)time(NULL);
    }
    if ( height <= 0 )
    {
        //printf("early return: stateupdate height.%d\n",height);
        return;
    }
    if ( fp != 0 ) // write out funcid, height, other fields, call side effect function
    {
        //printf("fpos.%ld ",ftell(fp));
        if ( HUSHheight != 0 )
        {
            if ( HUSHtimestamp != 0 )
            {
                fputc('T',fp);
                if ( fwrite(&height,1,sizeof(height),fp) != sizeof(height) )
                    errs++;
                if ( fwrite(&HUSHheight,1,sizeof(HUSHheight),fp) != sizeof(HUSHheight) )
                    errs++;
                if ( fwrite(&HUSHtimestamp,1,sizeof(HUSHtimestamp),fp) != sizeof(HUSHtimestamp) )
                    errs++;
            } else {
                fputc('K',fp);
                if ( fwrite(&height,1,sizeof(height),fp) != sizeof(height) )
                    errs++;
                if ( fwrite(&HUSHheight,1,sizeof(HUSHheight),fp) != sizeof(HUSHheight) )
                    errs++;
            }
            hush_eventadd_hushheight(sp,symbol,height,HUSHheight,HUSHtimestamp);
        } else if ( opretbuf != 0 && opretlen > 0 ) {
            uint16_t olen = opretlen;
            fputc('R',fp);
            if ( fwrite(&height,1,sizeof(height),fp) != sizeof(height) )
                errs++;
            if ( fwrite(&txhash,1,sizeof(txhash),fp) != sizeof(txhash) )
                errs++;
            if ( fwrite(&vout,1,sizeof(vout),fp) != sizeof(vout) )
                errs++;
            if ( fwrite(&opretvalue,1,sizeof(opretvalue),fp) != sizeof(opretvalue) )
                errs++;
            if ( fwrite(&olen,1,sizeof(olen),fp) != olen )
                errs++;
            if ( fwrite(opretbuf,1,olen,fp) != olen )
                errs++;
            //printf("create ht.%d R opret[%d] sp.%p\n",height,olen,sp);
            hush_eventadd_opreturn(sp,symbol,height,txhash,opretvalue,vout,opretbuf,olen);
        }
        else if ( notarypubs != 0 && numnotaries > 0 )
        {
            printf("ht.%d func P[%d] errs.%d\n",height,numnotaries,errs);
            fputc('P',fp);
            if ( fwrite(&height,1,sizeof(height),fp) != sizeof(height) )
                errs++;
            fputc(numnotaries,fp);
            if ( fwrite(notarypubs,33,numnotaries,fp) != numnotaries )
                errs++;
            hush_eventadd_pubkeys(sp,symbol,height,numnotaries,notarypubs);
        }
        else if ( voutmask != 0 && numvouts > 0 )
        {
            //printf("ht.%d func U %d %d errs.%d hashsize.%ld\n",height,numvouts,notaryid,errs,sizeof(txhash));
            fputc('U',fp);
            if ( fwrite(&height,1,sizeof(height),fp) != sizeof(height) )
                errs++;
            fputc(numvouts,fp);
            fputc(notaryid,fp);
            if ( fwrite(&voutmask,1,sizeof(voutmask),fp) != sizeof(voutmask) )
                errs++;
            if ( fwrite(&txhash,1,sizeof(txhash),fp) != sizeof(txhash) )
                errs++;
            //hush_eventadd_utxo(sp,symbol,height,notaryid,txhash,voutmask,numvouts);
        }
        else if ( pvals != 0 && numpvals > 0 )
        {
            int32_t i,nonz = 0;
            for (i=0; i<32; i++)
                if ( pvals[i] != 0 )
                    nonz++;
            if ( nonz >= 32 )
            {
                fputc('V',fp);
                if ( fwrite(&height,1,sizeof(height),fp) != sizeof(height) )
                    errs++;
                fputc(numpvals,fp);
                if ( fwrite(pvals,sizeof(uint32_t),numpvals,fp) != numpvals )
                    errs++;
                hush_eventadd_pricefeed(sp,symbol,height,pvals,numpvals);
                //printf("ht.%d V numpvals[%d]\n",height,numpvals);
            }
            //printf("save pvals height.%d numpvals.%d\n",height,numpvals);
        }
        else if ( height != 0 )
        {
            //printf("ht.%d func N ht.%d errs.%d\n",height,NOTARIZED_HEIGHT,errs);
            if ( sp != 0 )
            {
                if ( sp->MoMdepth != 0 && sp->MoM != zero )
                    fputc('M',fp);
                else fputc('N',fp);
                if ( fwrite(&height,1,sizeof(height),fp) != sizeof(height) )
                    errs++;
                if ( fwrite(&sp->NOTARIZED_HEIGHT,1,sizeof(sp->NOTARIZED_HEIGHT),fp) != sizeof(sp->NOTARIZED_HEIGHT) )
                    errs++;
                if ( fwrite(&sp->NOTARIZED_HASH,1,sizeof(sp->NOTARIZED_HASH),fp) != sizeof(sp->NOTARIZED_HASH) )
                    errs++;
                if ( fwrite(&sp->NOTARIZED_DESTTXID,1,sizeof(sp->NOTARIZED_DESTTXID),fp) != sizeof(sp->NOTARIZED_DESTTXID) )
                    errs++;
                if ( sp->MoMdepth != 0 && sp->MoM != zero )
                {
                    if ( fwrite(&sp->MoM,1,sizeof(sp->MoM),fp) != sizeof(sp->MoM) )
                        errs++;
                    if ( fwrite(&sp->MoMdepth,1,sizeof(sp->MoMdepth),fp) != sizeof(sp->MoMdepth) )
                        errs++;
                }
                hush_eventadd_notarized(sp,symbol,height,dest,sp->NOTARIZED_HASH,sp->NOTARIZED_DESTTXID,sp->NOTARIZED_HEIGHT,sp->MoM,sp->MoMdepth);
            }
        }
        fflush(fp);
    }
}

int32_t hush_validate_chain(uint256 srchash,int32_t notarized_height)
{
    //fprintf(stderr,"%s\n", __func__);
    static int32_t last_rewind; int32_t rewindtarget; CBlockIndex *pindex; struct hush_state *sp; char symbol[HUSH_SMART_CHAIN_MAXLEN],dest[HUSH_SMART_CHAIN_MAXLEN];
    if ( (sp= hush_stateptr(symbol,dest)) == 0 )
        return(0);
    if ( IsInitialBlockDownload() == 0 && ((pindex= hush_getblockindex(srchash)) == 0 || pindex->GetHeight() != notarized_height) )
    {
        fprintf(stderr,"%s: Not in IBD, height=%d\n", __func__, pindex->GetHeight() );
        if ( sp->NOTARIZED_HEIGHT > 0 && sp->NOTARIZED_HEIGHT < notarized_height )
            rewindtarget = sp->NOTARIZED_HEIGHT - 1;
        else if ( notarized_height > 101 )
            rewindtarget = notarized_height - 101;
        else rewindtarget = 0;
        if ( rewindtarget != 0 && rewindtarget > HUSH_REWIND && rewindtarget > last_rewind )
        {
            if ( last_rewind != 0 )
            {
                //HUSH_REWIND = rewindtarget;
                fprintf(stderr,"%s FORK detected. notarized.%d %s not in this chain! last notarization %d -> rewindtarget.%d\n",SMART_CHAIN_SYMBOL,notarized_height,srchash.ToString().c_str(),sp->NOTARIZED_HEIGHT,rewindtarget);
            }
            last_rewind = rewindtarget;
        }
        return(0);
    } else return(1);
}

int32_t hush_voutupdate(bool fJustCheck,int32_t *isratificationp,int32_t notaryid,uint8_t *scriptbuf,int32_t scriptlen,int32_t height,uint256 txhash,int32_t i,int32_t j,uint64_t *voutmaskp,int32_t *specialtxp,int32_t *notarizedheightp,uint64_t value,int32_t notarized,uint64_t signedmask,uint32_t timestamp)
{
    static uint256 zero; static FILE *signedfp;
    int32_t opretlen,nid,offset,k,MoMdepth,matched,len = 0; uint256 MoM,srchash,desttxid; uint8_t crypto555[33]; struct hush_state *sp; char symbol[HUSH_SMART_CHAIN_MAXLEN],dest[HUSH_SMART_CHAIN_MAXLEN];
    if ( (sp= hush_stateptr(symbol,dest)) == 0 )
        return(-1);
    if ( scriptlen == 35 && scriptbuf[0] == 33 && scriptbuf[34] == 0xac )
    {
        if ( i == 0 && j == 0 && memcmp(NOTARY_PUBKEY33,scriptbuf+1,33) == 0 && IS_HUSH_NOTARY != 0 )
        {
            printf("%s HUSH_LASTMINED.%d -> %d\n",SMART_CHAIN_SYMBOL,HUSH_LASTMINED,height);
            prevHUSH_LASTMINED = HUSH_LASTMINED;
            HUSH_LASTMINED = height;
        }
        decode_hex(crypto555,33,(char *)CRYPTO555_PUBSECPSTR);
        /*for (k=0; k<33; k++)
            printf("%02x",crypto555[k]);
        printf(" crypto555 ");
        for (k=0; k<scriptlen; k++)
            printf("%02x",scriptbuf[k]);
        printf(" <- script ht.%d i.%d j.%d cmp.%d\n",height,i,j,memcmp(crypto555,scriptbuf+1,33));*/
        if ( memcmp(crypto555,scriptbuf+1,33) == 0 )
        {
            *specialtxp = 1;
            //printf(">>>>>>>> ");
        }
        else if ( hush_chosennotary(&nid,height,scriptbuf + 1,timestamp) >= 0 )
        {
            //printf("found notary.k%d\n",k);
            if ( notaryid < 64 )
            {
                if ( notaryid < 0 )
                {
                    notaryid = nid;
                    *voutmaskp |= (1LL << j);
                }
                else if ( notaryid != nid )
                {
                    //for (i=0; i<33; i++)
                    //    printf("%02x",scriptbuf[i+1]);
                    //printf(" %s mismatch notaryid.%d k.%d\n",SMART_CHAIN_SYMBOL,notaryid,nid);
                    notaryid = 64;
                    *voutmaskp = 0;
                }
                else *voutmaskp |= (1LL << j);
            }
        }
    }
    if ( scriptbuf[len++] == 0x6a )
    {
        struct hush_ccdata ccdata; struct hush_ccdataMoMoM MoMoMdata;
        int32_t validated = 0,nameoffset,opoffset = 0;
        if ( (opretlen= scriptbuf[len++]) == 0x4c )
            opretlen = scriptbuf[len++];
        else if ( opretlen == 0x4d )
        {
            opretlen = scriptbuf[len++];
            opretlen += (scriptbuf[len++] << 8);
        }
        opoffset = len;
        matched = 0;
        if ( SMART_CHAIN_SYMBOL[0] == 0 )
        {
        } else {
            if ( scriptbuf[len] == 'K' )
            {
                //fprintf(stderr,"i.%d j.%d KV OPRET len.%d %.8f\n",i,j,opretlen,dstr(value));
                hush_stateupdate(height,0,0,0,txhash,0,0,0,0,0,0,value,&scriptbuf[len],opretlen,j,zero,0);
                return(-1);
            }
            if ( strcmp(SMART_CHAIN_SYMBOL,(char *)&scriptbuf[len+32*2+4]) == 0 )
                matched = 1;
        }
        offset = 32 * (1 + matched) + 4;
        nameoffset = (int32_t)strlen((char *)&scriptbuf[len+offset]);
        nameoffset++;
        memset(&ccdata,0,sizeof(ccdata));
        strncpy(ccdata.symbol,(char *)&scriptbuf[len+offset],sizeof(ccdata.symbol));
        if ( j == 1 && opretlen >= len+offset-opoffset )
        {
            memset(&MoMoMdata,0,sizeof(MoMoMdata));
            if ( matched == 0 && signedmask != 0 && bitweight(signedmask) >= HUSH_MINRATIFY )
                notarized = 1;
            if ( strcmp("DPOW",ccdata.symbol) == 0 || strncmp("ZPOW",ccdata.symbol,5) == 0 || strcmp("TUSH",ccdata.symbol) == 0)
                notarized = 1;
            if ( opretlen != 149 )
                printf("[%s].%d (%s) matched.%d i.%d j.%d notarized.%d %llx opretlen.%d len.%d offset.%d opoffset.%d\n",SMART_CHAIN_SYMBOL,height,ccdata.symbol,matched,i,j,notarized,(long long)signedmask,opretlen,len,offset,opoffset);
            len += dragon_rwbignum(0,&scriptbuf[len],32,(uint8_t *)&srchash);
            len += dragon_rwnum(0,&scriptbuf[len],sizeof(*notarizedheightp),(uint8_t *)notarizedheightp);
            if ( matched != 0 )
                len += dragon_rwbignum(0,&scriptbuf[len],32,(uint8_t *)&desttxid);
            if ( matched != 0 )
                validated = hush_validate_chain(srchash,*notarizedheightp);
            else validated = 1;
            // Any notarization that is matched and has a decodable op_return is enough to pay notaries. Otherwise bugs! 
            if ( fJustCheck && matched != 0 )
                return(-2);
            if ( notarized != 0 && validated != 0 )
            {
                //sp->NOTARIZED_HEIGHT = *notarizedheightp;
                //sp->NOTARIZED_HASH = srchash;
                //sp->NOTARIZED_DESTTXID = desttxid;
                memset(&MoM,0,sizeof(MoM));
                MoMdepth = 0;
                len += nameoffset;
                ccdata.MoMdata.notarized_height = *notarizedheightp;
                ccdata.MoMdata.height = height;
                ccdata.MoMdata.txi = i;
                printf("nameoffset.%d len.%d + 36 %d opoffset.%d vs opretlen.%d\n",nameoffset,len,len+36,opoffset,opretlen);
                if ( len+36-opoffset <= opretlen )
                {
                    len += dragon_rwbignum(0,&scriptbuf[len],32,(uint8_t *)&MoM);
                    len += dragon_rwnum(0,&scriptbuf[len],sizeof(MoMdepth),(uint8_t *)&MoMdepth);
                    ccdata.MoMdata.MoM = MoM;
                    ccdata.MoMdata.MoMdepth = MoMdepth & 0xffff;
                    if ( len+sizeof(ccdata.CCid)-opoffset <= opretlen )
                    {
                        len += dragon_rwnum(0,&scriptbuf[len],sizeof(ccdata.CCid),(uint8_t *)&ccdata.CCid);
                        if ( ((MoMdepth>>16) & 0xffff) != (ccdata.CCid & 0xffff) )
                            fprintf(stderr,"%s CCid mismatch %u != %u\n",SMART_CHAIN_SYMBOL,((MoMdepth>>16) & 0xffff),(ccdata.CCid & 0xffff));
                        ccdata.len = sizeof(ccdata.CCid);
                        if ( SMART_CHAIN_SYMBOL[0] != 0 )
                        {
                            // MoMoM, depth, numpairs, (notarization ht, MoMoM offset)
                            if ( len+48-opoffset <= opretlen && strcmp(ccdata.symbol,SMART_CHAIN_SYMBOL) == 0 )
                            {
                                len += dragon_rwnum(0,&scriptbuf[len],sizeof(uint32_t),(uint8_t *)&MoMoMdata.hushstarti);
                                len += dragon_rwnum(0,&scriptbuf[len],sizeof(uint32_t),(uint8_t *)&MoMoMdata.hushendi);
                                len += dragon_rwbignum(0,&scriptbuf[len],sizeof(MoMoMdata.MoMoM),(uint8_t *)&MoMoMdata.MoMoM);
                                len += dragon_rwnum(0,&scriptbuf[len],sizeof(uint32_t),(uint8_t *)&MoMoMdata.MoMoMdepth);
                                len += dragon_rwnum(0,&scriptbuf[len],sizeof(uint32_t),(uint8_t *)&MoMoMdata.numpairs);
                                MoMoMdata.len += sizeof(MoMoMdata.MoMoM) + sizeof(uint32_t)*4;
                                if ( len+MoMoMdata.numpairs*8-opoffset == opretlen )
                                {
                                    MoMoMdata.pairs = (struct hush_ccdatapair *)calloc(MoMoMdata.numpairs,sizeof(*MoMoMdata.pairs));
                                    for (k=0; k<MoMoMdata.numpairs; k++)
                                    {
                                        len += dragon_rwnum(0,&scriptbuf[len],sizeof(int32_t),(uint8_t *)&MoMoMdata.pairs[k].notarized_height);
                                        len += dragon_rwnum(0,&scriptbuf[len],sizeof(uint32_t),(uint8_t *)&MoMoMdata.pairs[k].MoMoMoffset);
                                        MoMoMdata.len += sizeof(uint32_t) * 2;
                                    }
                                } else ccdata.len = MoMoMdata.len = 0;
                            } else ccdata.len = MoMoMdata.len = 0;
                        }
                    }
                    if ( MoM == zero || (MoMdepth&0xffff) > *notarizedheightp || (MoMdepth&0xffff) < 0 )
                    {
                        memset(&MoM,0,sizeof(MoM));
                        MoMdepth = 0;
                    }
                    else
                    {
                        hush_rwccdata(SMART_CHAIN_SYMBOL,1,&ccdata,&MoMoMdata);
                        if ( matched != 0 )
                            printf("[%s] matched.%d VALID (%s) MoM.%s [%d] CCid.%u\n",SMART_CHAIN_SYMBOL,matched,ccdata.symbol,MoM.ToString().c_str(),MoMdepth&0xffff,(MoMdepth>>16)&0xffff);
                    }
                    if ( MoMoMdata.pairs != 0 )
                        free(MoMoMdata.pairs);
                    memset(&ccdata,0,sizeof(ccdata));
                    memset(&MoMoMdata,0,sizeof(MoMoMdata));
                }
                
                if ( matched != 0 && *notarizedheightp > sp->NOTARIZED_HEIGHT && *notarizedheightp < height )
                {
                    sp->NOTARIZED_HEIGHT = *notarizedheightp;
                    sp->NOTARIZED_HASH = srchash;
                    sp->NOTARIZED_DESTTXID = desttxid;
                    if ( MoM != zero && (MoMdepth&0xffff) > 0 )
                    {
                        sp->MoM = MoM;
                        sp->MoMdepth = MoMdepth;
                    }
                    hush_stateupdate(height,0,0,0,zero,0,0,0,0,0,0,0,0,0,0,sp->MoM,sp->MoMdepth);
                    //if ( SMART_CHAIN_SYMBOL[0] != 0 )
                        printf("[%s] ht.%d NOTARIZED.%d %s.%s %sTXID.%s lens.(%d %d) MoM.%s %d\n",SMART_CHAIN_SYMBOL,height,sp->NOTARIZED_HEIGHT,SMART_CHAIN_SYMBOL,srchash.ToString().c_str(),"HUSH",desttxid.ToString().c_str(),opretlen,len,sp->MoM.ToString().c_str(),sp->MoMdepth);
                    
                } //else if ( fJustCheck )
                //    return (-3); // if the notarization is only invalid because its out of order it cannot be mined in a block with a valid one!
            } else if ( opretlen != 149 && height > 600000 && matched != 0 )
                printf("%s validated.%d notarized.%d %llx reject ht.%d NOTARIZED.%d prev.%d %s.%s DESTTXID.%s len.%d opretlen.%d\n",ccdata.symbol,validated,notarized,(long long)signedmask,height,*notarizedheightp,sp->NOTARIZED_HEIGHT,SMART_CHAIN_SYMBOL,srchash.ToString().c_str(),desttxid.ToString().c_str(),len,opretlen);
        }
        else if ( matched != 0 && i == 0 && j == 1 && opretlen == 149 )
        {
            if ( notaryid >= 0 && notaryid < 64 )
                hush_paxpricefeed(height,&scriptbuf[len],opretlen);
        }
        else if ( matched != 0 )
        {
            //int32_t k; for (k=0; k<scriptlen; k++)
            //    printf("%02x",scriptbuf[k]);
            //printf(" <- script ht.%d i.%d j.%d value %.8f %s\n",height,i,j,dstr(value),SMART_CHAIN_SYMBOL);
            if ( opretlen >= 32*2+4 && strcmp(SMART_CHAIN_SYMBOL,(char *)&scriptbuf[len+32*2+4]) == 0 )
            {
                for (k=0; k<32; k++)
                    if ( scriptbuf[len+k] != 0 )
                        break;
                if ( k == 32 )
                {
                    *isratificationp = 1;
                    printf("%s: ISRATIFICATION (%s)\n",__func__,(char *)&scriptbuf[len+32*2+4]);
                }
            }

            if ( *isratificationp == 0 && (signedmask != 0 || (scriptbuf[len] != 'X' && scriptbuf[len] != 'A')) ) // && scriptbuf[len] != 'I')
                hush_stateupdate(height,0,0,0,txhash,0,0,0,0,0,0,value,&scriptbuf[len],opretlen,j,zero,0);
        }
    }
    return(notaryid);
}


// Special tx have vout[0] -> CRYPTO555 address
// with more than HUSH_MINRATIFY pay2pubkey outputs -> ratify
// if all outputs to notary -> notary utxo
// if txi == 0 && 2 outputs and 2nd OP_RETURN, len == 32*2+4 -> notarized, 1st byte 'P' -> pricefeed
// OP_RETURN: 'D' -> deposit, 'W' -> withdraw

int32_t gettxout_scriptPubKey(uint8_t *scriptPubKey,int32_t maxsize,uint256 txid,int32_t n);

int32_t hush_notarycmp(uint8_t *scriptPubKey,int32_t scriptlen,uint8_t pubkeys[64][33],int32_t numnotaries,uint8_t rmd160[20])
{
    int32_t i;
    if ( scriptlen == 25 && memcmp(&scriptPubKey[3],rmd160,20) == 0 )
        return(0);
    else if ( scriptlen == 35 )
    {
        for (i=0; i<numnotaries; i++)
            if ( memcmp(&scriptPubKey[1],pubkeys[i],33) == 0 )
                return(i);
    }
    return(-1);
}

// Connect a Hush Block, foshizzle
int32_t hush_connectblock(bool fJustCheck, CBlockIndex *pindex,CBlock& block)
{
    static int32_t hwmheight;
    std::vector<int32_t> notarizations;
    uint64_t signedmask,voutmask; char symbol[HUSH_SMART_CHAIN_MAXLEN],dest[HUSH_SMART_CHAIN_MAXLEN]; struct hush_state *sp;
    uint8_t scriptbuf[10001],pubkeys[64][33],rmd160[20],scriptPubKey[35]; uint256 zero,btctxid,txhash;
    int32_t i,j,k,numnotaries,notarized,scriptlen,isratification,nid,numvalid,specialtx,notarizedheight,notaryid,len,numvouts,numvins,height,txn_count;
    if ( pindex == 0 )
    {
        fprintf(stderr,"hush_connectblock null pindex\n");
        return(0);
    }
    memset(&zero,0,sizeof(zero));
    hush_init(pindex->GetHeight());
    HUSH_INITDONE = (uint32_t)time(NULL);
    if ( (sp= hush_stateptr(symbol,dest)) == 0 )
    {
        fprintf(stderr,"unexpected null stateptr.[%s]\n",SMART_CHAIN_SYMBOL);
        return(0);
    }
    //fprintf(stderr,"%s connect.%d\n",SMART_CHAIN_SYMBOL,pindex->nHeight);
    // Wallet Filter. Disabled here. Cant be activated by notaries or pools with some changes.
    numnotaries = hush_notaries(pubkeys,pindex->GetHeight(),pindex->GetBlockTime());
    calc_rmd160_sha256(rmd160,pubkeys[0],33);
    if ( pindex->GetHeight() > hwmheight )
        hwmheight = pindex->GetHeight();
    else
    {
        if ( pindex->GetHeight() != hwmheight )
        {
            printf("%s hwmheight.%d vs pindex->GetHeight().%d t.%u reorg.%d\n",SMART_CHAIN_SYMBOL,hwmheight,pindex->GetHeight(),(uint32_t)pindex->nTime,hwmheight-pindex->GetHeight());
            hush_purge_ccdata((int32_t)pindex->GetHeight());
            hwmheight = pindex->GetHeight();
        }
        if (!fJustCheck)
        {
            hush_event_rewind(sp,symbol,pindex->GetHeight());
            hush_stateupdate(pindex->GetHeight(),0,0,0,zero,0,0,0,0,-pindex->GetHeight(),pindex->nTime,0,0,0,0,zero,0);
        }
    }
    hush_currentheight_set(chainActive.LastTip()->GetHeight());
    int transaction = 0;
    if ( pindex != 0 )
    {
        height = pindex->GetHeight();
        txn_count = block.vtx.size();
        for (i=0; i<txn_count; i++)
        {
            // Notary pay chains need notarization in position 1, ignore the rest on validation. Check notarization is 1 on check.
            if ( !fJustCheck && i > 1 && ASSETCHAINS_NOTARY_PAY[0] != 0 )
                break;
            txhash = block.vtx[i].GetHash();
            numvouts = block.vtx[i].vout.size();
            notaryid = -1;
            voutmask = specialtx = notarizedheight = isratification = notarized = 0;
            signedmask = (height < 91400) ? 1 : 0;
            numvins = block.vtx[i].vin.size();
            for (j=0; j<numvins; j++)
            {
                if ( i == 0 && j == 0 )
                    continue;
                if ( (scriptlen= gettxout_scriptPubKey(scriptPubKey,sizeof(scriptPubKey),block.vtx[i].vin[j].prevout.hash,block.vtx[i].vin[j].prevout.n)) > 0 )
                {
                    if ( (k= hush_notarycmp(scriptPubKey,scriptlen,pubkeys,numnotaries,rmd160)) >= 0 )
                        signedmask |= (1LL << k);
                    else if ( 0 && numvins >= 17 )
                    {
                        int32_t k;
                        for (k=0; k<scriptlen; k++)
                            printf("%02x",scriptPubKey[k]);
                        printf(" scriptPubKey doesnt match any notary vini.%d of %d\n",j,numvins);
                    }
                } //else printf("cant get scriptPubKey for ht.%d txi.%d vin.%d\n",height,i,j);
            }
            numvalid = bitweight(signedmask);
            if ( ((height < 90000 || (signedmask & 1) != 0) && numvalid >= HUSH_MINRATIFY) ||
                (numvalid >= HUSH_MINRATIFY && SMART_CHAIN_SYMBOL[0] != 0) ||
                numvalid > (numnotaries/5) )
            {
                if ( !fJustCheck && SMART_CHAIN_SYMBOL[0] != 0)
                {
                    static FILE *signedfp;
                    if ( signedfp == 0 )
                    {
                        char fname[512];
                        hush_statefname(fname,SMART_CHAIN_SYMBOL,(char *)"hushsignedmasks");
                        if ( (signedfp= fopen(fname,"rb+")) == 0 )
                            signedfp = fopen(fname,"wb");
                        else fseek(signedfp,0,SEEK_END);
                    }
                    if ( signedfp != 0 )
                    {
                        fwrite(&height,1,sizeof(height),signedfp);
                        fwrite(&signedmask,1,sizeof(signedmask),signedfp);
                        fflush(signedfp);
                    }
                    transaction = i;
                    printf("[%s] ht.%d txi.%d signedmask.%llx numvins.%d numvouts.%d <<<<<<<<<<<  notarized\n",SMART_CHAIN_SYMBOL,height,i,(long long)signedmask,numvins,numvouts);
                }
                notarized = 1;
            }
            // simulate DPoW in regtest mode for dpowconfs tests/etc
            if ( Params().NetworkIDString() == "regtest" && ( height%7 == 0) ) {
                notarized              = 1;
                sp->NOTARIZED_HEIGHT   = height;
                sp->NOTARIZED_HASH     = block.GetHash();
                sp->NOTARIZED_DESTTXID = txhash;
            }
            if ( IS_HUSH_NOTARY != 0 && SMART_CHAIN_SYMBOL[0] == 0 )
                printf("(tx.%d: ",i);
            for (j=0; j<numvouts; j++)
            {
                /*if ( i == 0 && j == 0 )
                {
                    uint8_t *script = (uint8_t *)&block.vtx[0].vout[numvouts-1].scriptPubKey[0];
                    if ( numvouts <= 2 || script[0] != 0x6a )
                    {
                        if ( numvouts == 2 && block.vtx[0].vout[1].nValue != 0 )
                        {
                            fprintf(stderr,"ht.%d numvouts.%d value %.8f\n",height,numvouts,dstr(block.vtx[0].vout[1].nValue));
                            if ( height >= 235300 && block.vtx[0].vout[1].nValue >= 100000*COIN )
                                block.vtx[0].vout[1].nValue = 0;
                            break;
                        }
                    }
                }*/
                if ( IS_HUSH_NOTARY != 0 && SMART_CHAIN_SYMBOL[0] == 0 )
                    printf("%.8f ",dstr(block.vtx[i].vout[j].nValue));
                len = block.vtx[i].vout[j].scriptPubKey.size();
                
                if ( len >= sizeof(uint32_t) && len <= sizeof(scriptbuf) )
                {
                    memcpy(scriptbuf,(uint8_t *)&block.vtx[i].vout[j].scriptPubKey[0],len);
                    notaryid = hush_voutupdate(fJustCheck,&isratification,notaryid,scriptbuf,len,height,txhash,i,j,&voutmask,&specialtx,&notarizedheight,(uint64_t)block.vtx[i].vout[j].nValue,notarized,signedmask,(uint32_t)chainActive.LastTip()->GetBlockTime());
                    if ( fJustCheck && notaryid == -2 )
                    {
                        // We see a valid notarization here, save its location.
                        notarizations.push_back(i);
                    }
                    if ( 0 && i > 0 )
                    {
                        for (k=0; k<len; k++)
                            printf("%02x",scriptbuf[k]);
                        printf(" <- notaryid.%d ht.%d i.%d j.%d numvouts.%d numvins.%d voutmask.%llx txid.(%s)\n",notaryid,height,i,j,numvouts,numvins,(long long)voutmask,txhash.ToString().c_str());
                    }
                }
            }
            if ( IS_HUSH_NOTARY != 0 && SMART_CHAIN_SYMBOL[0] == 0 )
                printf(") ");
            if ( 0 && SMART_CHAIN_SYMBOL[0] == 0 )
                printf("[%s] ht.%d txi.%d signedmask.%llx numvins.%d numvouts.%d notarized.%d special.%d isratification.%d\n",SMART_CHAIN_SYMBOL,height,i,(long long)signedmask,numvins,numvouts,notarized,specialtx,isratification);
            if ( !fJustCheck && (notarized != 0 && (notarizedheight != 0 || specialtx != 0)) )
            {
                if ( isratification != 0 )
                {
                    printf("%s NOTARY SIGNED.%llx numvins.%d ht.%d txi.%d notaryht.%d specialtx.%d\n",SMART_CHAIN_SYMBOL,(long long)signedmask,numvins,height,i,notarizedheight,specialtx);
                    printf("ht.%d specialtx.%d isratification.%d numvouts.%d signed.%llx numnotaries.%d\n",height,specialtx,isratification,numvouts,(long long)signedmask,numnotaries);
                }
                if ( specialtx != 0 && isratification != 0 && numvouts > 2 )
                {
                    numvalid = 0;
                    memset(pubkeys,0,sizeof(pubkeys));
                    for (j=1; j<numvouts-1; j++)
                    {
                        len = block.vtx[i].vout[j].scriptPubKey.size();
                        if ( len >= sizeof(uint32_t) && len <= sizeof(scriptbuf) )
                        {
                            memcpy(scriptbuf,(uint8_t *)&block.vtx[i].vout[j].scriptPubKey[0],len);
                            if ( len == 35 && scriptbuf[0] == 33 && scriptbuf[34] == 0xac )
                            {
                                memcpy(pubkeys[numvalid++],scriptbuf+1,33);
                                for (k=0; k<33; k++)
                                    printf("%02x",scriptbuf[k+1]);
                                printf(" <- new notary.[%d]\n",j-1);
                            }
                        }
                    }
                    if ( SMART_CHAIN_SYMBOL[0] != 0 || height < 100000 )
                    {
                        if ( ((signedmask & 1) != 0 && numvalid >= HUSH_MINRATIFY) || bitweight(signedmask) > (numnotaries/3) )
                        {
                            memset(&txhash,0,sizeof(txhash));
                            hush_stateupdate(height,pubkeys,numvalid,0,txhash,0,0,0,0,0,0,0,0,0,0,zero,0);
                            printf("RATIFIED! >>>>>>>>>> new notaries.%d newheight.%d from height.%d\n",numvalid,(((height+HUSH_DPOW_GAP/2)/HUSH_DPOW_GAP)+1)*HUSH_DPOW_GAP,height);
                        } else printf("signedmask.%llx numvalid.%d wt.%d numnotaries.%d\n",(long long)signedmask,numvalid,bitweight(signedmask),numnotaries);
                    }
                }
            }
        }
        if ( !fJustCheck && IS_HUSH_NOTARY != 0 && SMART_CHAIN_SYMBOL[0] == 0 )
            printf("%s ht.%d\n",SMART_CHAIN_SYMBOL,height);
        if ( !fJustCheck && pindex->GetHeight() == hwmheight )
            hush_stateupdate(height,0,0,0,zero,0,0,0,0,height,(uint32_t)pindex->nTime,0,0,0,0,zero,0);
    } 
    else 
        { fprintf(stderr,"hush_connectblock: unexpected null pindex\n"); return(0); }
    //HUSH_INITDONE = (uint32_t)time(NULL);
    //fprintf(stderr,"%s end connect.%d\n",SMART_CHAIN_SYMBOL,pindex->GetHeight());
    if (fJustCheck)
    {
        if ( notarizations.size() == 0 )
            return(0);
        if ( notarizations.size() == 1 && notarizations[0] == 1 )
            return(1);
        if ( notarizations.size() > 1 || (notarizations.size() == 1 && notarizations[0] != 1) )
            return(-1);
        
        fprintf(stderr,"hush_connectblock: unxexpected behaviour when fJustCheck == true, report bug plz ! \n");
        /* this needed by gcc-8, it counts here that control reaches end of non-void function without this.
           by default, we count that if control reached here -> the valid notarization isnt in position 1 or there are too many notarizations in this block.
        */
        return(-1); 
    } else {
        return(0);
    }
}

#endif
