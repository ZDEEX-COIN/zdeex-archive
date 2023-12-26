// Copyright (c) 2016-2023 The Hush Developers
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
// Hush functions that interact with hushd C++
#include <curl/curl.h>
#include <curl/easy.h>
#include "consensus/params.h"
#include "hush_defs.h"
#include "script/standard.h"
#include "cc/CCinclude.h"
#include "sietch.h"

int32_t hush_notaries(uint8_t pubkeys[64][33],int32_t height,uint32_t timestamp);
int32_t hush_findnotary(int32_t *numnotariesp,uint8_t *pubkey33,int32_t height,uint32_t timestamp);
int32_t hush_voutupdate(bool fJustCheck,int32_t *isratificationp,int32_t notaryid,uint8_t *scriptbuf,int32_t scriptlen,int32_t height,uint256 txhash,int32_t i,int32_t j,uint64_t *voutmaskp,int32_t *specialtxp,int32_t *notarizedheightp,uint64_t value,int32_t notarized,uint64_t signedmask,uint32_t timestamp);
bool EnsureWalletIsAvailable(bool avoidException);
extern bool fRequestShutdown;
extern CScript HUSH_EARLYTXID_SCRIPTPUB;
extern std::string devtax_scriptpub_for_height(uint32_t nHeight);

uint32_t hush_heightstamp(int32_t height);

//#define issue_curl(cmdstr) bitcoind_RPC(0,(char *)"curl",(char *)"http://127.0.0.1:7776",0,0,(char *)(cmdstr))

struct MemoryStruct { char *memory; size_t size; };
struct return_string { char *ptr; size_t len; };

// return data from the server
#define CURL_GLOBAL_ALL (CURL_GLOBAL_SSL|CURL_GLOBAL_WIN32)
#define CURL_GLOBAL_SSL (1<<0)
#define CURL_GLOBAL_WIN32 (1<<1)


/************************************************************************
 *
 * Initialize the string handler so that it is thread safe
 *
 ************************************************************************/

void init_string(struct return_string *s)
{
    s->len = 0;
    s->ptr = (char *)calloc(1,s->len+1);
    if ( s->ptr == NULL )
    {
        fprintf(stderr,"init_string malloc() failed\n");
        StartShutdown();
    }
    s->ptr[0] = '\0';
}

int tx_height( const uint256 &hash ){
    int nHeight = 0;
    CTransaction tx;
    uint256 hashBlock;
    if (!GetTransaction(hash, tx, hashBlock, true)) {
        fprintf(stderr,"tx hash %s does not exist!\n", hash.ToString().c_str() );
        return nHeight;
    }

    BlockMap::const_iterator it = mapBlockIndex.find(hashBlock);
    if (it != mapBlockIndex.end()) {
        nHeight = it->second->GetHeight();
        //fprintf(stderr,"blockHash %s height %d\n",hashBlock.ToString().c_str(), nHeight);
    } else {
        // Unconfirmed xtns
        fprintf(stderr,"tx %s is unconfirmed\n", hash.ToString().c_str() );
        //fprintf(stderr,"block hash %s does not exist!\n", hashBlock.ToString().c_str() );
    }
    return nHeight;
}


/************************************************************************
 *
 * Use the "writer" to accumulate text until done
 *
 ************************************************************************/

size_t accumulatebytes(void *ptr,size_t size,size_t nmemb,struct return_string *s)
{
    size_t new_len = s->len + size*nmemb;
    s->ptr = (char *)realloc(s->ptr,new_len+1);
    if ( s->ptr == NULL )
    {
        fprintf(stderr, "accumulate realloc() failed\n");
        StartShutdown();
    }
    memcpy(s->ptr+s->len,ptr,size*nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;
    return(size * nmemb);
}

/************************************************************************
 *
 * return the current system time in milliseconds
 *
 ************************************************************************/

#define EXTRACT_BITCOIND_RESULT  // if defined, ensures error is null and returns the "result" field
#ifdef EXTRACT_BITCOIND_RESULT

/************************************************************************
 *
 * perform post processing of the results
 *
 ************************************************************************/

char *post_process_bitcoind_RPC(char *debugstr,char *command,char *rpcstr,char *params)
{
    long i,j,len; char *retstr = 0; cJSON *json,*result,*error;
    //printf("<<<<<<<<<<< bitcoind_RPC: %s post_process_bitcoind_RPC.%s.[%s]\n",debugstr,command,rpcstr);
    if ( command == 0 || rpcstr == 0 || rpcstr[0] == 0 )
    {
        if ( strcmp(command,"signrawtransaction") != 0 )
            printf("<<<<<<<<<<< bitcoind_RPC: %s post_process_bitcoind_RPC.%s.[%s]\n",debugstr,command,rpcstr);
        return(rpcstr);
    }
    json = cJSON_Parse(rpcstr);
    if ( json == 0 )
    {
        printf("<<<<<<<<<<< bitcoind_RPC: %s post_process_bitcoind_RPC.%s can't parse.(%s) params.(%s)\n",debugstr,command,rpcstr,params);
        free(rpcstr);
        return(0);
    }
    result = cJSON_GetObjectItem(json,"result");
    error = cJSON_GetObjectItem(json,"error");
    if ( error != 0 && result != 0 )
    {
        if ( (error->type&0xff) == cJSON_NULL && (result->type&0xff) != cJSON_NULL )
        {
            retstr = cJSON_Print(result);
            len = strlen(retstr);
            if ( retstr[0] == '"' && retstr[len-1] == '"' )
            {
                for (i=1,j=0; i<len-1; i++,j++)
                    retstr[j] = retstr[i];
                retstr[j] = 0;
            }
        }
        else if ( (error->type&0xff) != cJSON_NULL || (result->type&0xff) != cJSON_NULL )
        {
            if ( strcmp(command,"signrawtransaction") != 0 )
                printf("<<<<<<<<<<< bitcoind_RPC: %s post_process_bitcoind_RPC (%s) error.%s\n",debugstr,command,rpcstr);
        }
        free(rpcstr);
    } else retstr = rpcstr;
    free_json(json);
    //fprintf(stderr,"<<<<<<<<<<< bitcoind_RPC: postprocess returns.(%s)\n",retstr);
    return(retstr);
}
#endif

/************************************************************************
 *
 * perform the query
 *
 ************************************************************************/

char *bitcoind_RPC(char **retstrp,char *debugstr,char *url,char *userpass,char *command,char *params)
{
    static int didinit,count,count2; static double elapsedsum,elapsedsum2;
    struct curl_slist *headers = NULL; struct return_string s; CURLcode res; CURL *curl_handle;
    char *bracket0,*bracket1,*databuf = 0; long len; int32_t specialcase,numretries; double starttime;
    if ( didinit == 0 )
    {
        didinit = 1;
        curl_global_init(CURL_GLOBAL_ALL); //init the curl session
    }
    numretries = 0;
    if ( debugstr != 0 && strcmp(debugstr,"BTCD") == 0 && command != 0 && strcmp(command,"SuperNET") ==  0 )
        specialcase = 1;
    else specialcase = 0;
    if ( url[0] == 0 )
        strcpy(url,"http://127.0.0.1:7876/nxt");
    if ( specialcase != 0 && 0 )
        printf("<<<<<<<<<<< bitcoind_RPC: debug.(%s) url.(%s) command.(%s) params.(%s)\n",debugstr,url,command,params);
try_again:
    if ( retstrp != 0 )
        *retstrp = 0;
    starttime = OS_milliseconds();
    curl_handle = curl_easy_init();
    init_string(&s);
    headers = curl_slist_append(0,"Expect:");

    curl_easy_setopt(curl_handle,CURLOPT_USERAGENT,"mozilla/4.0");//"Mozilla/4.0 (compatible; )");
    curl_easy_setopt(curl_handle,CURLOPT_HTTPHEADER,	headers);
    curl_easy_setopt(curl_handle,CURLOPT_URL,		url);
    curl_easy_setopt(curl_handle,CURLOPT_WRITEFUNCTION,	(void *)accumulatebytes); 		// send all data to this function
    curl_easy_setopt(curl_handle,CURLOPT_WRITEDATA,		&s); 			// we pass our 's' struct to the callback
    curl_easy_setopt(curl_handle,CURLOPT_NOSIGNAL,		1L);   			// supposed to fix "Alarm clock" and long jump crash
    curl_easy_setopt(curl_handle,CURLOPT_NOPROGRESS,	1L);			// no progress callback
    //curl_easy_setopt(curl_handle, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    //curl_easy_setopt(curl_handle, CURLOPT_SSLVERSION, 2);

    if ( strncmp(url,"https",5) == 0 )
    {
        
        /* printf("[ Decker ] SSL: %s\n", curl_version()); */
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
        //curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L); // this is useful for debug, but seems crash on libcurl/7.64.1 OpenSSL/1.1.1b zlib/1.2.8 librtmp/2.3
    }
    if ( userpass != 0 )
        curl_easy_setopt(curl_handle,CURLOPT_USERPWD,	userpass);
    databuf = 0;
    if ( params != 0 )
    {
        if ( command != 0 && specialcase == 0 )
        {
            len = strlen(params);
            if ( len > 0 && params[0] == '[' && params[len-1] == ']' ) {
                bracket0 = bracket1 = (char *)"";
            }
            else
            {
                bracket0 = (char *)"[";
                bracket1 = (char *)"]";
            }

            databuf = (char *)malloc(256 + strlen(command) + strlen(params));
            sprintf(databuf,"{\"id\":\"jl777\",\"method\":\"%s\",\"params\":%s%s%s}",command,bracket0,params,bracket1);
            //printf("url.(%s) userpass.(%s) databuf.(%s)\n",url,userpass,databuf);
            //
        } //else if ( specialcase != 0 ) fprintf(stderr,"databuf.(%s)\n",params);
        curl_easy_setopt(curl_handle,CURLOPT_POST,1L);
        if ( databuf != 0 )
            curl_easy_setopt(curl_handle,CURLOPT_POSTFIELDS,databuf);
        else curl_easy_setopt(curl_handle,CURLOPT_POSTFIELDS,params);
    }
    //laststart = milliseconds();
    res = curl_easy_perform(curl_handle);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl_handle);
    if ( databuf != 0 ) // clean up temporary buffer
    {
        free(databuf);
        databuf = 0;
    }
    if ( res != CURLE_OK )
    {
        numretries++;
        if ( specialcase != 0 )
        {
            fprintf(stderr,"<<<<<<<<<<< bitcoind_RPC.(%s): BTCD.%s timeout params.(%s) s.ptr.(%s) err.%d\n",url,command,params,s.ptr,res);
            free(s.ptr);
            return(0);
        }
        else if ( numretries >= 1 )
        {
            fprintf(stderr,"%s: Maximum number of retries exceeded!\n", __FUNCTION__);
            free(s.ptr);
            return(0);
        }
        if ( (rand() % 1000) == 0 )
            printf( "curl_easy_perform() failed: %s %s.(%s %s), retries: %d\n",curl_easy_strerror(res),debugstr,url,command,numretries);
        free(s.ptr);
        sleep((1<<numretries));
        goto try_again;

    }
    else
    {
        if ( command != 0 && specialcase == 0 )
        {
            count++;
            elapsedsum += (OS_milliseconds() - starttime);
            if ( (count % 1000000) == 0)
                printf("%d: ave %9.6f | elapsed %.3f millis | bitcoind_RPC.(%s) url.(%s)\n",count,elapsedsum/count,(OS_milliseconds() - starttime),command,url);
            if ( retstrp != 0 )
            {
                *retstrp = s.ptr;
                return(s.ptr);
            }
            return(post_process_bitcoind_RPC(debugstr,command,s.ptr,params));
        }
        else
        {
            if ( 0 && specialcase != 0 )
                fprintf(stderr,"<<<<<<<<<<< bitcoind_RPC: BTCD.(%s) -> (%s)\n",params,s.ptr);
            count2++;
            elapsedsum2 += (OS_milliseconds() - starttime);
            if ( (count2 % 10000) == 0)
                printf("%d: ave %9.6f | elapsed %.3f millis | NXT calls.(%s) cmd.(%s)\n",count2,elapsedsum2/count2,(double)(OS_milliseconds() - starttime),url,command);
            return(s.ptr);
        }
    }
    printf("bitcoind_RPC: impossible case\n");
    free(s.ptr);
    return(0);
}

static size_t WriteMemoryCallback(void *ptr,size_t size,size_t nmemb,void *data)
{
    size_t realsize = (size * nmemb);
    struct MemoryStruct *mem = (struct MemoryStruct *)data;
    mem->memory = (char *)((ptr != 0) ? realloc(mem->memory,mem->size + realsize + 1) : malloc(mem->size + realsize + 1));
    if ( mem->memory != 0 )
    {
        if ( ptr != 0 )
            memcpy(&(mem->memory[mem->size]),ptr,realsize);
        mem->size += realsize;
        mem->memory[mem->size] = 0;
    }
    //printf("got %d bytes\n",(int32_t)(size*nmemb));
    return(realsize);
}

char *curl_post(CURL **cHandlep,char *url,char *userpass,char *postfields,char *hdr0,char *hdr1,char *hdr2,char *hdr3)
{
    struct MemoryStruct chunk; CURL *cHandle; long code; struct curl_slist *headers = 0;
    if ( (cHandle= *cHandlep) == NULL )
        *cHandlep = cHandle = curl_easy_init();
    else curl_easy_reset(cHandle);
    //#ifdef DEBUG
    //curl_easy_setopt(cHandle,CURLOPT_VERBOSE, 1);
    //#endif
    curl_easy_setopt(cHandle,CURLOPT_USERAGENT,"mozilla/4.0");//"Mozilla/4.0 (compatible; )");
    curl_easy_setopt(cHandle,CURLOPT_SSL_VERIFYPEER,0);
    //curl_easy_setopt(cHandle,CURLOPT_SSLVERSION,1);
    curl_easy_setopt(cHandle,CURLOPT_URL,url);
    curl_easy_setopt(cHandle,CURLOPT_CONNECTTIMEOUT,10);
    if ( userpass != 0 && userpass[0] != 0 )
        curl_easy_setopt(cHandle,CURLOPT_USERPWD,userpass);
    if ( postfields != 0 && postfields[0] != 0 )
    {
        curl_easy_setopt(cHandle,CURLOPT_POST,1);
        curl_easy_setopt(cHandle,CURLOPT_POSTFIELDS,postfields);
    }
    if ( hdr0 != NULL && hdr0[0] != 0 )
    {
        //printf("HDR0.(%s) HDR1.(%s) HDR2.(%s) HDR3.(%s)\n",hdr0!=0?hdr0:"",hdr1!=0?hdr1:"",hdr2!=0?hdr2:"",hdr3!=0?hdr3:"");
        headers = curl_slist_append(headers,hdr0);
        if ( hdr1 != 0 && hdr1[0] != 0 )
            headers = curl_slist_append(headers,hdr1);
        if ( hdr2 != 0 && hdr2[0] != 0 )
            headers = curl_slist_append(headers,hdr2);
        if ( hdr3 != 0 && hdr3[0] != 0 )
            headers = curl_slist_append(headers,hdr3);
    } //headers = curl_slist_append(0,"Expect:");
    if ( headers != 0 )
        curl_easy_setopt(cHandle,CURLOPT_HTTPHEADER,headers);
    //res = curl_easy_perform(cHandle);
    memset(&chunk,0,sizeof(chunk));
    curl_easy_setopt(cHandle,CURLOPT_WRITEFUNCTION,WriteMemoryCallback);
    curl_easy_setopt(cHandle,CURLOPT_WRITEDATA,(void *)&chunk);
    curl_easy_perform(cHandle);
    curl_easy_getinfo(cHandle,CURLINFO_RESPONSE_CODE,&code);
    if ( headers != 0 )
        curl_slist_free_all(headers);
    if ( code != 200 )
        printf("(%s) server responded with code %ld (%s)\n",url,code,chunk.memory);
    return(chunk.memory);
}

char *hush_issuemethod(char *userpass,char *method,char *params,uint16_t port)
{
    char url[512],*retstr=0,*retstr2=0,postdata[8192];
    if ( params == 0 || params[0] == 0 )
        params = (char *)"[]";
    if ( strlen(params) < sizeof(postdata)-128 )
    {
        sprintf(url,(char *)"http://127.0.0.1:%u",port);
        sprintf(postdata,"{\"method\":\"%s\",\"params\":%s}",method,params);
 //printf("[%s] (%s) postdata.(%s) params.(%s) USERPASS.(%s)\n",SMART_CHAIN_SYMBOL,url,postdata,params,HUSHUSERPASS);
        retstr2 = bitcoind_RPC(&retstr,(char *)"debug",url,userpass,method,params);
        //retstr = curl_post(&cHandle,url,USERPASS,postdata,0,0,0,0);
    }
    return(retstr2);
}

int32_t notarizedtxid_height(char *dest,char *txidstr,int32_t *hushnotarized_heightp)
{
    char *jsonstr,params[256],*userpass; uint16_t port; cJSON *json,*item; int32_t height = 0,txid_height = 0,txid_confirmations = 0;
    params[0] = 0;
    *hushnotarized_heightp = 0;
    if ( strcmp(dest,"HUSH3") == 0 ) {
        port     = HUSH3_PORT;
        userpass = HUSHUSERPASS;
    } else if ( strcmp(dest,"BTC") == 0 )
    {
        port     = 8332;
        userpass = BTCUSERPASS;
    } else {
        return(0);
    }
    if ( userpass[0] != 0 )
    {
        if ( (jsonstr= hush_issuemethod(userpass,(char *)"getinfo",params,port)) != 0 )
        {
            //printf("(%s)\n",jsonstr);
            if ( (json= cJSON_Parse(jsonstr)) != 0 )
            {
                if ( (item= jobj(json,(char *)"result")) != 0 )
                {
                    height = jint(item,(char *)"blocks");
                    *hushnotarized_heightp = strcmp(dest,"HUSH3") == 0 ? jint(item,(char *)"notarized") : height;
                }
                free_json(json);
            }
            free(jsonstr);
        }
        sprintf(params,"[\"%s\", 1]",txidstr);
        if ( (jsonstr= hush_issuemethod(userpass,(char *)"getrawtransaction",params,port)) != 0 )
        {
            //printf("(%s)\n",jsonstr);
            if ( (json= cJSON_Parse(jsonstr)) != 0 )
            {
                if ( (item= jobj(json,(char *)"result")) != 0 )
                {
                    txid_confirmations = jint(item,(char *)"rawconfirmations");
                    if ( txid_confirmations > 0 && height > txid_confirmations )
                        txid_height = height - txid_confirmations;
                    else txid_height = height;
                    //printf("height.%d tconfs.%d txid_height.%d\n",height,txid_confirmations,txid_height);
                }
                free_json(json);
            }
            free(jsonstr);
        }
    }
    return(txid_height);
}

int32_t hush_verifynotarizedscript(int32_t height,uint8_t *script,int32_t len,uint256 NOTARIZED_HASH)
{
    int32_t i; uint256 hash; char params[256];
    for (i=0; i<32; i++)
        ((uint8_t *)&hash)[i] = script[2+i];
    if ( hash == NOTARIZED_HASH )
        return(1);
    for (i=0; i<32; i++)
        printf("%02x",((uint8_t *)&NOTARIZED_HASH)[i]);
    printf(" notarized, ");
    for (i=0; i<32; i++)
        printf("%02x",((uint8_t *)&hash)[i]);
    printf(" opreturn from [%s] ht.%d MISMATCHED\n",SMART_CHAIN_SYMBOL,height);
    return(-1);
}

void hush_reconsiderblock(uint256 blockhash)
{
    char params[256],*jsonstr,*hexstr;
    sprintf(params,"[\"%s\"]",blockhash.ToString().c_str());
    if ( (jsonstr= hush_issuemethod(ASSETCHAINS_USERPASS,(char *)"reconsiderblock",params,ASSETCHAINS_RPCPORT)) != 0 )
    {
        //fprintf(stderr,"hush_reconsiderblock.(%s) (%s %u) -> (%s)\n",params,ASSETCHAINS_USERPASS,ASSETCHAINS_RPCPORT,jsonstr);
        free(jsonstr);
    }
    //fprintf(stderr,"hush_reconsiderblock.(%s) (%s %u) -> NULL\n",params,ASSETCHAINS_USERPASS,ASSETCHAINS_RPCPORT);
}

int32_t hush_verifynotarization(char *symbol,char *dest,int32_t height,int32_t NOTARIZED_HEIGHT,uint256 NOTARIZED_HASH,uint256 NOTARIZED_DESTTXID)
{
    char params[256],*jsonstr,*hexstr; uint8_t *script,_script[8192]; int32_t n,len,retval = -1; cJSON *json,*txjson,*vouts,*vout,*skey;
    script = _script;
    /*params[0] = '[';
     params[1] = '"';
     for (i=0; i<32; i++)
     sprintf(&params[i*2 + 2],"%02x",((uint8_t *)&NOTARIZED_DESTTXID)[31-i]);
     strcat(params,"\", 1]");*/
    sprintf(params,"[\"%s\", 1]",NOTARIZED_DESTTXID.ToString().c_str());
    if ( strcmp(symbol,SMART_CHAIN_SYMBOL[0]==0?(char *)"HUSH3":SMART_CHAIN_SYMBOL) != 0 )
        return(0);
    if ( 0 && SMART_CHAIN_SYMBOL[0] != 0 )
        printf("[%s] src.%s dest.%s params.[%s] ht.%d notarized.%d\n",SMART_CHAIN_SYMBOL,symbol,dest,params,height,NOTARIZED_HEIGHT);
    if ( strcmp(dest,"HUSH3") == 0 )
    {
        if ( HUSHUSERPASS[0] != 0 )
        {
            if ( SMART_CHAIN_SYMBOL[0] != 0 )
            {
                jsonstr = hush_issuemethod(HUSHUSERPASS,(char *)"getrawtransaction",params,HUSH3_PORT);
                //printf("userpass.(%s) got (%s)\n",HUSHUSERPASS,jsonstr);
            }
        }//else jsonstr = _dex_getrawtransaction();
        else return(0); // need universal way to issue DEX* API, since notaries mine most blocks, this ok
    } else if ( strcmp(dest,"BTC") == 0 ) {
        if ( BTCUSERPASS[0] != 0 )
        {
            //printf("BTCUSERPASS.(%s)\n",BTCUSERPASS);
            jsonstr = hush_issuemethod(BTCUSERPASS,(char *)"getrawtransaction",params,8332);
        }
        //else jsonstr = _dex_getrawtransaction();
        else return(0);
    } else {
        printf("[%s] verifynotarization error unexpected dest.(%s)\n",SMART_CHAIN_SYMBOL,dest);
        return(-1);
    }
    if ( jsonstr != 0 )
    {
        if ( (json= cJSON_Parse(jsonstr)) != 0 )
        {
            if ( (txjson= jobj(json,(char *)"result")) != 0 && (vouts= jarray(&n,txjson,(char *)"vout")) != 0 )
            {
                vout = jitem(vouts,n-1);
                if ( 0 && SMART_CHAIN_SYMBOL[0] != 0 )
                    printf("vout.(%s)\n",jprint(vout,0));
                if ( (skey= jobj(vout,(char *)"scriptPubKey")) != 0 )
                {
                    if ( (hexstr= jstr(skey,(char *)"hex")) != 0 )
                    {
                        //printf("HEX.(%s) vs hash.%s\n",hexstr,NOTARIZED_HASH.ToString().c_str());
                        len = strlen(hexstr) >> 1;
                        decode_hex(script,len,hexstr);
                        if ( script[1] == 0x4c )
                        {
                            script++;
                            len--;
                        }
                        else if ( script[1] == 0x4d )
                        {
                            script += 2;
                            len -= 2;
                        }
                        retval = hush_verifynotarizedscript(height,script,len,NOTARIZED_HASH);
                    }
                }
            }
            free_json(txjson);
        }
        free(jsonstr);
    }
    return(retval);
}

CScript hush_makeopret(CBlock *pblock, bool fNew)
{
    std::vector<uint256> vLeaves;
    vLeaves.push_back(pblock->hashPrevBlock); 
    for (int32_t i = 0; i < pblock->vtx.size()-(fNew ? 0 : 1); i++)
        vLeaves.push_back(pblock->vtx[i].GetHash());
    uint256 merkleroot = GetMerkleRoot(vLeaves);
    CScript opret;
    opret << OP_RETURN << E_MARSHAL(ss << merkleroot);
    return(opret);
}

/*uint256 hush_getblockhash(int32_t height)
 {
 uint256 hash; char params[128],*hexstr,*jsonstr; cJSON *result; int32_t i; uint8_t revbuf[32];
 memset(&hash,0,sizeof(hash));
 sprintf(params,"[%d]",height);
 if ( (jsonstr= hush_issuemethod(HUSHUSERPASS,(char *)"getblockhash",params,BITCOIND_RPCPORT)) != 0 )
 {
 if ( (result= cJSON_Parse(jsonstr)) != 0 )
 {
 if ( (hexstr= jstr(result,(char *)"result")) != 0 )
 {
 if ( is_hexstr(hexstr,0) == 64 )
 {
 decode_hex(revbuf,32,hexstr);
 for (i=0; i<32; i++)
 ((uint8_t *)&hash)[i] = revbuf[31-i];
 }
 }
 free_json(result);
 }
 printf("HUSH3 hash.%d (%s) %x\n",height,jsonstr,*(uint32_t *)&hash);
 free(jsonstr);
 }
 return(hash);
 }

 uint256 _hush_getblockhash(int32_t height);*/

uint64_t hush_seed(int32_t height)
{
    uint64_t seed = 0;
    /*if ( 0 ) // problem during init time, seeds are needed for loading blockindex, so null seeds...
     {
     uint256 hash,zero; CBlockIndex *pindex;
     memset(&hash,0,sizeof(hash));
     memset(&zero,0,sizeof(zero));
     if ( height > 10 )
     height -= 10;
     if ( SMART_CHAIN_SYMBOL[0] == 0 )
     hash = _hush_getblockhash(height);
     if ( memcmp(&hash,&zero,sizeof(hash)) == 0 )
     hash = hush_getblockhash(height);
     int32_t i;
     for (i=0; i<32; i++)
     printf("%02x",((uint8_t *)&hash)[i]);
     printf(" seed.%d\n",height);
     seed = arith_uint256(hash.GetHex()).GetLow64();
     }
     else*/
    {
        seed = (height << 13) ^ (height << 2);
        seed <<= 21;
        seed |= (height & 0xffffffff);
        seed ^= (seed << 17) ^ (seed << 1);
    }
    return(seed);
}

uint32_t hush_txtime(CScript &opret,uint64_t *valuep,uint256 hash, int32_t n, char *destaddr)
{
    CTxDestination address; CTransaction tx; uint256 hashBlock; int32_t numvouts;
    *valuep = 0;
    if (!GetTransaction(hash, tx,
#ifndef HUSH_ZCASH
                        Params().GetConsensus(),
#endif
                        hashBlock, true))
    {
        //fprintf(stderr,"ERROR: %s/v%d locktime.%u\n",hash.ToString().c_str(),n,(uint32_t)tx.nLockTime);
        return(0);
    }
    numvouts = tx.vout.size();
    //fprintf(stderr,"%s/v%d locktime.%u\n",hash.ToString().c_str(),n,(uint32_t)tx.nLockTime);
    if ( n < numvouts )
    {
        *valuep = tx.vout[n].nValue;
        opret = tx.vout[numvouts-1].scriptPubKey;
        if (ExtractDestination(tx.vout[n].scriptPubKey, address))
            strcpy(destaddr,CBitcoinAddress(address).ToString().c_str());
    }
    return(tx.nLockTime);
}

CBlockIndex *hush_getblockindex(uint256 hash)
{
    BlockMap::const_iterator it = mapBlockIndex.find(hash);
    return((it != mapBlockIndex.end()) ? it->second : NULL);
}

bool hush_checkopret(CBlock *pblock, CScript &merkleroot)
{
    merkleroot = pblock->vtx.back().vout.back().scriptPubKey;
    return(merkleroot.IsOpReturn() && merkleroot == hush_makeopret(pblock, false));
}


extern const uint32_t nHushHardforkHeight;

bool hush_hardfork_active(uint32_t time)
{
    //This allows simulating a different height via CLI option, with hardcoded height as default
    uint32_t nHardForkHeight = GetArg("-hardfork-height", nHushHardforkHeight);
    bool isactive = chainActive.Height() > nHardForkHeight;
    if(fDebug) {
        //fprintf(stderr, "%s: active=%d at height=%d and forkheight=%d\n", __FUNCTION__, (int)isactive, chainActive.Height(), nHardForkHeight);
    }
    return isactive;
}

int32_t hush_isPoS(CBlock *pblock,int32_t height,bool fJustCheck)
{
    return(0);
}

int32_t hush_is_notarytx(const CTransaction& tx)
{
    uint8_t *ptr; static uint8_t crypto555[33];
    if ( tx.vout.size() > 0 )
    {
        ptr = (uint8_t *)&tx.vout[0].scriptPubKey[0];
        if ( ptr != 0 )
        {
            if ( crypto555[0] == 0 )
                decode_hex(crypto555,33,(char *)CRYPTO555_PUBSECPSTR);
            if ( memcmp(ptr+1,crypto555,33) == 0 )
            {
                fprintf(stderr,"%s: found notarytx\n", __func__);
                return(1);
            }
        }
    }
    return(0);
}

int32_t hush_block2height(CBlock *block)
{
    static uint32_t match,mismatch;
    int32_t i,n,height2=-1,height = 0; uint8_t *ptr; CBlockIndex *pindex = NULL;
    BlockMap::const_iterator it = mapBlockIndex.find(block->GetHash());
    if ( it != mapBlockIndex.end() && (pindex = it->second) != 0 )
    {
        height2 = (int32_t)pindex->GetHeight();
        if ( height2 >= 0 )
            return(height2);
    }
    if ( pindex && block != 0 && block->vtx[0].vin.size() > 0 )
    {
        ptr = (uint8_t *)&block->vtx[0].vin[0].scriptSig[0];
        if ( ptr != 0 && block->vtx[0].vin[0].scriptSig.size() > 5 )
        {
            //for (i=0; i<6; i++)
            //    printf("%02x",ptr[i]);
            n = ptr[0];
            for (i=0; i<n; i++) // looks strange but this works
            {
                //03bb81000101(bb 187) (81 48001) (00 12288256)  <- coinbase.6 ht.12288256
                height += ((uint32_t)ptr[i+1] << (i*8));
                //printf("(%02x %x %d) ",ptr[i+1],((uint32_t)ptr[i+1] << (i*8)),height);
            }
            //printf(" <- coinbase.%d ht.%d\n",(int32_t)block->vtx[0].vin[0].scriptSig.size(),height);
        }
        //hush_init(height);
    }
    if ( height != height2 )
    {
        //fprintf(stderr,"block2height height.%d vs height2.%d, match.%d mismatch.%d\n",height,height2,match,mismatch);
        mismatch++;
        if ( height2 >= 0 )
            height = height2;
    } else match++;
    return(height);
}

int32_t hush_block2pubkey33(uint8_t *pubkey33,CBlock *block)
{
    int32_t n;
    if ( HUSH_LOADINGBLOCKS == 0 )
        memset(pubkey33,0xff,33);
    else memset(pubkey33,0,33);
    if ( block->vtx[0].vout.size() > 0 )
    {
        txnouttype whichType;
        vector<vector<unsigned char>> vch = vector<vector<unsigned char>>();
        if (Solver(block->vtx[0].vout[0].scriptPubKey, whichType, vch) && whichType == TX_PUBKEY)
        {
            CPubKey pubKey(vch[0]);
            if (pubKey.IsValid())
            {
                memcpy(pubkey33,vch[0].data(),33);
                return true;
            }
            else memset(pubkey33,0,33);
        }
        else memset(pubkey33,0,33);
    }
    return(0);
}

int32_t hush_blockload(CBlock& block,CBlockIndex *pindex)
{
    block.SetNull();
    // Open history file to read
    CAutoFile filein(OpenBlockFile(pindex->GetBlockPos(),true),SER_DISK,CLIENT_VERSION);
    if (filein.IsNull())
        return(-1);
    // Read block
    try { filein >> block; }
    catch (const std::exception& e)
    {
        fprintf(stderr,"readblockfromdisk err B\n");
        return(-1);
    }
    return(0);
}

uint32_t hush_chainactive_timestamp()
{
    if ( chainActive.LastTip() != 0 )
        return((uint32_t)chainActive.LastTip()->GetBlockTime());
    else return(0);
}

CBlockIndex *hush_chainactive(int32_t height)
{
    if ( chainActive.LastTip() != 0 )
    {
        if ( height <= chainActive.LastTip()->GetHeight() )
            return(chainActive[height]);
        // else fprintf(stderr,"hush_chainactive height %d > active.%d\n",height,chainActive.LastTip()->GetHeight());
    }
    //fprintf(stderr,"hush_chainactive null chainActive.LastTip() height %d\n",height);
    return(0);
}

uint32_t hush_heightstamp(int32_t height)
{
    CBlockIndex *ptr;
    if ( height > 0 && (ptr= hush_chainactive(height)) != 0 )
        return(ptr->nTime);
    //else fprintf(stderr,"hush_heightstamp null ptr for block.%d\n",height);
    return(0);
}

void hush_index2pubkey33(uint8_t *pubkey33,CBlockIndex *pindex,int32_t height)
{
    int32_t num,i; CBlock block;
    memset(pubkey33,0,33);
    if ( pindex != 0 )
    {
        if ( hush_blockload(block,pindex) == 0 )
            hush_block2pubkey33(pubkey33,&block);
    }
}

int32_t hush_eligiblenotary(uint8_t pubkeys[66][33],int32_t *mids,uint32_t blocktimes[66],int32_t *nonzpkeysp,int32_t height)
{
    // after the season HF block ALL new notaries instantly become elegible. 
    int32_t i,j,n,duplicate; CBlock block; CBlockIndex *pindex; uint8_t notarypubs33[64][33];
    memset(mids,-1,sizeof(*mids)*66);
    n = hush_notaries(notarypubs33,height,0);
    for (i=duplicate=0; i<66; i++)
    {
        if ( (pindex= hush_chainactive(height-i)) != 0 )
        {
            blocktimes[i] = pindex->nTime;
            if ( hush_blockload(block,pindex) == 0 )
            {
                hush_block2pubkey33(pubkeys[i],&block);
                for (j=0; j<n; j++)
                {
                    if ( memcmp(notarypubs33[j],pubkeys[i],33) == 0 )
                    {
                        mids[i] = j;
                        (*nonzpkeysp)++;
                        break;
                    }
                }
            } else {
                fprintf(stderr,"%s: couldnt load block height %d\n",__func__,height);
            }
            if ( mids[0] >= 0 && i > 0 && mids[i] == mids[0] )
                duplicate++;
        }
    }
    if ( i == 66 && duplicate == 0 && (height > 186233 || *nonzpkeysp > 0) )
        return(1);
    else return(0);
}

int32_t hush_minerids(uint8_t *minerids,int32_t height,int32_t width)
{
    int32_t i,j,nonz,numnotaries; CBlock block; CBlockIndex *pindex; uint8_t notarypubs33[64][33],pubkey33[33];
    numnotaries = hush_notaries(notarypubs33,height,0);
    for (i=nonz=0; i<width; i++)
    {
        if ( height-i <= 0 )
            continue;
        if ( (pindex= hush_chainactive(height-width+i+1)) != 0 )
        {
            if ( hush_blockload(block,pindex) == 0 )
            {
                hush_block2pubkey33(pubkey33,&block);
                for (j=0; j<numnotaries; j++)
                {
                    if ( memcmp(notarypubs33[j],pubkey33,33) == 0 )
                    {
                        minerids[nonz++] = j;
                        break;
                    }
                }
                if ( j == numnotaries )
                    minerids[nonz++] = j;
            } else fprintf(stderr,"couldnt load block.%d\n",height);
        }
    }
    return(nonz);
}

int32_t hush_MoM(int32_t *notarized_heightp,uint256 *MoMp,uint256 *hushtxidp,int32_t nHeight,uint256 *MoMoMp,int32_t *MoMoMoffsetp,int32_t *MoMoMdepthp,int32_t *hushstartip,int32_t *hushendip)
{
    int32_t depth,notarized_ht; uint256 MoM,hushtxid;
    depth = hush_MoMdata(&notarized_ht,&MoM,&hushtxid,nHeight,MoMoMp,MoMoMoffsetp,MoMoMdepthp,hushstartip,hushendip);
    memset(MoMp,0,sizeof(*MoMp));
    memset(hushtxidp,0,sizeof(*hushtxidp));
    *notarized_heightp = 0;
    if ( depth != 0 && notarized_ht > 0 && nHeight > notarized_ht-depth && nHeight <= notarized_ht )
    {
        *MoMp = MoM;
        *notarized_heightp = notarized_ht;
        *hushtxidp = hushtxid;
    }
    return(depth);
}

CBlockIndex *hush_blockindex(uint256 hash)
{
    BlockMap::const_iterator it; CBlockIndex *pindex = 0;
    if ( (it = mapBlockIndex.find(hash)) != mapBlockIndex.end() )
        pindex = it->second;
    return(pindex);
}

int32_t hush_blockheight(uint256 hash)
{
    BlockMap::const_iterator it; CBlockIndex *pindex = 0;
    if ( (it = mapBlockIndex.find(hash)) != mapBlockIndex.end() )
    {
        if ( (pindex= it->second) != 0 )
            return(pindex->GetHeight());
    }
    return(0);
}

uint32_t hush_blocktime(uint256 hash)
{
    BlockMap::const_iterator it; CBlockIndex *pindex = 0;
    if ( (it = mapBlockIndex.find(hash)) != mapBlockIndex.end() )
    {
        if ( (pindex= it->second) != 0 )
            return(pindex->nTime);
    }
    return(0);
}

int32_t hush_checkpoint(int32_t *notarized_heightp,int32_t nHeight,uint256 hash)
{
    int32_t notarized_height,MoMdepth; uint256 MoM,notarized_hash,notarized_desttxid; CBlockIndex *notary,*pindex;
    if ( (pindex= chainActive.LastTip()) == 0 )
        return(-1);
    notarized_height   = hush_notarizeddata(pindex->GetHeight(),&notarized_hash,&notarized_desttxid);
    *notarized_heightp = notarized_height;
    BlockMap::const_iterator it;
    if ( notarized_height >= 0 && notarized_height <= pindex->GetHeight() && (it = mapBlockIndex.find(notarized_hash)) != mapBlockIndex.end() && (notary = it->second) != NULL )
    {
        //printf("nHeight.%d -> (%d %s)\n",pindex->Tip()->GetHeight(),notarized_height,notarized_hash.ToString().c_str());
        if ( notary->GetHeight() == notarized_height ) // if notarized_hash not in chain, reorg
        {
            if ( nHeight < notarized_height )
            {
                //fprintf(stderr,"[%s] nHeight.%d < NOTARIZED_HEIGHT.%d\n",SMART_CHAIN_SYMBOL,nHeight,notarized_height);
                return(-1);
            } else if ( nHeight == notarized_height && memcmp(&hash,&notarized_hash,sizeof(hash)) != 0 ) {
                fprintf(stderr,"[%s] nHeight.%d == NOTARIZED_HEIGHT.%d, diff hash\n",SMART_CHAIN_SYMBOL,nHeight,notarized_height);
                return(-1);
            }
        } //else fprintf(stderr,"[%s] unexpected error notary_hash %s ht.%d at ht.%d\n",SMART_CHAIN_SYMBOL,notarized_hash.ToString().c_str(),notarized_height,notary->GetHeight());
    }
    //else if ( notarized_height > 0 && notarized_height != 73880 && notarized_height >= 170000 )
    //    fprintf(stderr,"[%s] couldnt find notarized.(%s %d) ht.%d\n",SMART_CHAIN_SYMBOL,notarized_hash.ToString().c_str(),notarized_height,pindex->GetHeight());
    return(0);
}

int32_t hush_nextheight()
{
    CBlockIndex *pindex; int32_t ht;
    if ( (pindex= chainActive.LastTip()) != 0 && (ht= pindex->GetHeight()) > 0 )
        return(ht+1);
    else return(hush_longestchain() + 1);
}

int32_t hush_isrealtime(int32_t *hushheightp)
{
    struct hush_state *sp; CBlockIndex *pindex;
    if ( (sp= hush_stateptrget((char *)"HUSH3")) != 0 )
        *hushheightp = sp->CURRENT_HEIGHT;
    else *hushheightp = 0;
    if ( (pindex= chainActive.LastTip()) != 0 && pindex->GetHeight() >= (int32_t)hush_longestchain() )
        return(1);
    else return(0);
}

/*
 hush_checkPOW (fast) is called early in the process and should only refer to data immediately available. it is a filter to prevent bad blocks from going into the local DB. The more blocks we can filter out at this stage, the less junk in the local DB that will just get purged later on.

 hush_checkPOW (slow) is called right before connecting blocks so all prior blocks can be assumed to be there and all checks must pass

 commission must be in coinbase.vout[1] and must be >= 10000 sats
 */

CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams);

// This function defines the Hush Founders Reward (AKA Dev Tax)
// 10% of all block rewards go towards Hush core team
// If you do not like this, you are encouraged to fork the chain
// or start your own Hush Smart Chain: https://git.hush.is/hush/hush-smart-chains
// HUSH supply curve cannot be exactly represented via KMD AC CLI args, so we do it ourselves.
// You specify the BR, and the FR % gets added so 10% of 12.5 is 1.25
// but to tell the AC params, I need to say "11% of 11.25" is 1.25
// 11% ie. 1/9th cannot be exactly represented and so the FR has tiny amounts of error unless done manually
// This must be kept in sync with hush_block_subsidy() in hush_utils.h!
// Changing these functions are consensus changes!
// Here Be Dragons! -- Duke Leto
uint64_t hush_commission(int height)
{
    int32_t starting_commission = 125000000, HALVING1 = GetArg("-z2zheight",340000),
        INTERVAL = GetArg("-ac_halving1",840000), TRANSITION = 129;
    uint64_t commission = 0;

    //TODO: Likely a bug hiding here or at the next halving :)
    //if( height >= HALVING1) {
    if( height > HALVING1) {
        // Block time going from 150s to 75s (half) means the interval between halvings
        // must be twice as often, i.e. 840000*2=1680000
        // 840000 is ~4 years worth of 150s blocks
        // With 150s blocks, we have 210,000 blocks per year
        // With 75s blocks,  we have 420,000 blocks per year
        INTERVAL = GetArg("-ac_halving2",1680000);  // ~4 years worth of 75s blocks
        //fprintf(stderr,"%s: height=%d increasing interval to %d\n", __func__, height, INTERVAL);
    }

    // Block 128 had a miner subsidy but no FR!!! Discovered by Denio
    if (height < TRANSITION) {
        commission = 0;
    } else {
        // Just like BTC, BRs in the far future will be slightly less than
        // they should be because exact values are not integers, causing
        // slightly less coins to be actually mined and small deviations
        // to the ideal FR/devtax
        if (height < HALVING1) { // before 1st Halving @ Block 340000 (Nov 2020)
            commission = starting_commission;
        } else if (height < 2020000 ) {
            commission = 31250000;
        } else if (height < 3700000 ) {
            commission = 15625000;
        } else if (height < 5380000 ) {
            commission = 7812500;
        } else if (height < 7060000 ) {
            commission = 3906250;
        } else if (height < 8740000 ) {
            commission = 1953125;
        } else if (height < 10420000) {
            commission = 976562; // 0.5 puposhi deviation, all further BRs have deviation from ideal
        } else if (height < 12100000) {
            commission = 488281;
        } else if (height < 15460000) {
            commission = 244140;
        } else if (height < 17140000) {
            commission = 122070;
        } else if (height < 18820000) {
            commission = 61035;
        } else if (height < 23860000) {
            commission = 30517;
        } else if (height < 23860000) {
            commission = 15258;
        } else if (height < 25540000) {
            commission = 7629;
        } else if (height < 27220000) {
            commission = 3814;
        } else if (height < 27220000) {
            commission = 1907;
        } else if (height < 28900000) {
            commission = 953;
        } else if (height < 30580000) {
            commission = 476;
        } else if (height < 32260000) {
            commission = 238;
        } else if (height < 33940000) {
            commission = 119;
        } else if (height < 35620000) {
            commission = 59;
        } else if (height < 37300000) {
            commission = 29;
        } else if (height < 38980000) {
            commission = 14;
        } else if (height < 40660000) {
            commission = 7;
        } else if (height < 42340000) {
            commission = 3;
        } else if (height < 44020000) {
            commission = 1;
        } else if (height < 45700000) {
            // FR goes to zero at Halving 26
            commission = 0;
        } else if (height < 47380000) {
            // FR still zero at Halving 27
            commission = 0;
        } else if (height < 49060000) {
            // FR still zero at Halving 28
            commission = 0;
        } else if (height < 50740000) {
            // FR still zero at Halving 29
            commission = 0;
        } else {
            // enforce FR=0 for all other heights
            // This over-rides the -ac_end param via HUSH3 cli args
            commission = 0;
        }
    }

    if(fDebug)
        fprintf(stderr,"%s: commission=%lu,interval=%d at height %d\n", __func__, commission, INTERVAL, height);
    return commission;
}

uint64_t the_commission(const CBlock *pblock,int32_t height)
{
    //fprintf(stderr,"%s at height=%d\n",__func__,height);
    static bool didinit = false, ishush3 = false;

    if (!didinit) {
        ishush3 = strncmp(SMART_CHAIN_SYMBOL, "HUSH3",5) == 0 ? true : false;
        didinit = true;
        fprintf(stderr,"%s: didinit ishush3=%d\n", __func__, ishush3);
    }

    int32_t i,j,n=0,txn_count; int64_t nSubsidy; uint64_t commission,total = 0;
    if ( ASSETCHAINS_FOUNDERS != 0 )
    {
        nSubsidy = GetBlockSubsidy(height,Params().GetConsensus());
        if(fDebug)
            fprintf(stderr,"ht.%d nSubsidy %.8f prod %llu\n",height,(double)nSubsidy/COIN,(long long)(nSubsidy * ASSETCHAINS_COMMISSION));
        commission = ((nSubsidy * ASSETCHAINS_COMMISSION) / COIN);

        if (ishush3) {
            commission = hush_commission(height);
        }

        if ( ASSETCHAINS_FOUNDERS > 1 )
        {
            if ( (height % ASSETCHAINS_FOUNDERS) == 0 )
            {
                if ( ASSETCHAINS_FOUNDERS_REWARD == 0 ) {
                    commission = commission * ASSETCHAINS_FOUNDERS;
                } else {
                    commission = ASSETCHAINS_FOUNDERS_REWARD;
                }
                if(fDebug)
                    fprintf(stderr,"%s: set commission=%lu at height %d with\n",__func__,commission, height);
            } else {
                commission = 0;
            }
        }
    } else if ( pblock != 0 ) {
        txn_count = pblock->vtx.size();
        for (i=0; i<txn_count; i++)
        {
            n = pblock->vtx[i].vout.size();
            for (j=0; j<n; j++)
            {
                if ( height > 225000 && ASSETCHAINS_STAKED != 0 && txn_count > 1 && i == txn_count-1 && j == n-1 )
                    break;
                //fprintf(stderr,"(%d %.8f).%d ",i,dstr(pblock->vtx[i].vout[j].nValue),j);
                if ( i != 0 || j != 1 )
                    total += pblock->vtx[i].vout[j].nValue;
                if ( total > 1000000 * COIN )
                {
                    total = 1000000 * COIN;
                    break;
                }
            }
        }
        commission = ((total / 10000) * ASSETCHAINS_COMMISSION) / 10000;
        //commission = ((total * ASSETCHAINS_COMMISSION) / COIN);
    }
    if ( commission < 10000 )
        commission = 0;
    if(fDebug)
        fprintf(stderr,"%s: commission=%.8f at height=%d\n",__func__, (double)commission/COIN, height);
    return(commission);
}

uint32_t hush_segid32(char *coinaddr)
{
    bits256 addrhash;
    vcalc_sha256(0,(uint8_t *)&addrhash,(uint8_t *)coinaddr,(int32_t)strlen(coinaddr));
    return(addrhash.uints[0]);
}

int8_t hush_segid(int32_t nocache,int32_t height)
{
    CTxDestination voutaddress; CBlock block; CBlockIndex *pindex; uint64_t value; uint32_t txtime; char voutaddr[64],destaddr[64]; int32_t txn_count,vout; uint256 txid; CScript opret; int8_t segid = -1;
    if ( height > 0 && (pindex= hush_chainactive(height)) != 0 )
    {
        if ( nocache == 0 && pindex->segid >= -1 )
            return(pindex->segid);
        if ( hush_blockload(block,pindex) == 0 )
        {
            txn_count = block.vtx.size();
            if ( txn_count > 1 && block.vtx[txn_count-1].vin.size() == 1 && block.vtx[txn_count-1].vout.size() == 1 )
            {
                txid = block.vtx[txn_count-1].vin[0].prevout.hash;
                vout = block.vtx[txn_count-1].vin[0].prevout.n;
                txtime = hush_txtime(opret,&value,txid,vout,destaddr);
                if ( ExtractDestination(block.vtx[txn_count-1].vout[0].scriptPubKey,voutaddress) )
                {
                    strcpy(voutaddr,CBitcoinAddress(voutaddress).ToString().c_str());
                    if ( strcmp(destaddr,voutaddr) == 0 && block.vtx[txn_count-1].vout[0].nValue == value )
                    {
                        segid = hush_segid32(voutaddr) & 0x3f;
                        pindex->segid = segid;
                        //fprintf(stderr,"hush_segid.(%d) -> %d\n",height,pindex->segid);
                    }
                } else fprintf(stderr,"hush_segid ht.%d couldnt extract voutaddress\n",height);
            }
        }
    }
    return(segid);
}

void hush_segids(uint8_t *hashbuf,int32_t height,int32_t n)
{
    static uint8_t prevhashbuf[100]; static int32_t prevheight;
    int32_t i;
    if ( height == prevheight && n == 100 )
        memcpy(hashbuf,prevhashbuf,100);
    else
    {
        memset(hashbuf,0xff,n);
        for (i=0; i<n; i++)
        {
            hashbuf[i] = (uint8_t)hush_segid(1,height+i);
            //fprintf(stderr,"%02x ",hashbuf[i]);
        }
        if ( n == 100 )
        {
            memcpy(prevhashbuf,hashbuf,100);
            prevheight = height;
            //fprintf(stderr,"prevsegids.%d\n",height+n);
        }
    }
}

arith_uint256 hush_adaptivepow_target(int32_t height,arith_uint256 bnTarget,uint32_t nTime)
{
    arith_uint256 origtarget,easy; int32_t diff,tipdiff; int64_t mult; bool fNegative,fOverflow; CBlockIndex *tipindex;
    if ( height > 10 && (tipindex= hush_chainactive(height - 1)) != 0 ) // disable offchain diffchange
    {
        diff = (nTime - tipindex->GetMedianTimePast());
        tipdiff = (nTime - tipindex->nTime);
        if ( tipdiff > 13*ASSETCHAINS_BLOCKTIME )
            diff = tipdiff;
        if ( diff >= 13 * ASSETCHAINS_BLOCKTIME && (height < 30 || tipdiff > 2*ASSETCHAINS_BLOCKTIME) )
        {
            mult = diff - 12 * ASSETCHAINS_BLOCKTIME;
            mult = (mult / ASSETCHAINS_BLOCKTIME) * ASSETCHAINS_BLOCKTIME + ASSETCHAINS_BLOCKTIME / 2;
            origtarget = bnTarget;
            bnTarget = bnTarget * arith_uint256(mult * mult);
            easy.SetCompact(HUSH_MINDIFF_NBITS,&fNegative,&fOverflow);
            if ( bnTarget < origtarget || bnTarget > easy ) // deal with overflow
            {
                bnTarget = easy;
                fprintf(stderr,"tipdiff.%d diff.%d height.%d miner overflowed mult.%lld, set to mindiff\n",tipdiff,diff,height,(long long)mult);
            } else fprintf(stderr,"tipdiff.%d diff.%d height.%d miner elapsed %d, adjust by factor of %lld\n",tipdiff,diff,height,diff,(long long)mult);
        } //else fprintf(stderr,"height.%d tipdiff.%d diff %d, vs %d\n",height,tipdiff,diff,13*ASSETCHAINS_BLOCKTIME);
    } else fprintf(stderr,"adaptive cant find height.%d\n",height);
    return(bnTarget);
}

arith_uint256 hush_PoWtarget(int32_t *percPoSp,arith_uint256 target,int32_t height,int32_t goalperc)
{
    int32_t oldflag = 0,dispflag = 0;
    CBlockIndex *pindex; arith_uint256 easydiff,bnTarget,hashval,sum,ave; bool fNegative,fOverflow; int32_t i,n,m,ht,percPoS,diff,val;
    *percPoSp = percPoS = 0;
    
    if ( height <= 10 || (ASSETCHAINS_STAKED == 100 && height <= 100) ) 
        return(target);
        
    sum = arith_uint256(0);
    ave = sum;
    easydiff.SetCompact(STAKING_MIN_DIFF,&fNegative,&fOverflow);
    for (i=n=m=0; i<100; i++)
    {
        ht = height - 100 + i;
        if ( ht <= 1 )
            continue;
        if ( (pindex= hush_chainactive(ht)) != 0 )
        {
            if ( hush_segid(0,ht) >= 0 )
            {
                n++;
                percPoS++;
                if ( dispflag != 0 && ASSETCHAINS_STAKED < 100 )
                    fprintf(stderr,"0");
            }
            else
            {
                if ( dispflag != 0 && ASSETCHAINS_STAKED < 100 )
                    fprintf(stderr,"1");
                sum += UintToArith256(pindex->GetBlockHash());
                m++;
            }
        } //else fprintf(stderr, "pindex returned null ht.%i\n",ht);
        if ( dispflag != 0 && ASSETCHAINS_STAKED < 100 && (i % 10) == 9 )
            fprintf(stderr," %d, ",percPoS);
    }
    if ( m+n < 100 )
    {
		percPoS = ((percPoS * n) + (goalperc * (100-n))) / 100;            
    } 
    if ( dispflag != 0 && ASSETCHAINS_STAKED < 100 )
        fprintf(stderr," -> %d%% percPoS vs goalperc.%d ht.%d\n",percPoS,goalperc,height);
    *percPoSp = percPoS;
    if ( m > 0 )
    {
        ave = (sum / arith_uint256(m));
        if ( ave > target )
            ave = target;
    } else ave = target; //easydiff; //else return(target);
    if ( percPoS == 0 )
        percPoS = 1;
    if ( percPoS < goalperc ) // increase PoW diff -> lower bnTarget
    {
        if ( oldflag != 0 )
            bnTarget = (ave / arith_uint256(goalperc * goalperc * goalperc)) * arith_uint256(percPoS * percPoS);
        else bnTarget = (ave / arith_uint256(goalperc * goalperc * goalperc * goalperc)) * arith_uint256(percPoS * percPoS);
        if ( dispflag != 0 && ASSETCHAINS_STAKED < 100 )
        {
            for (i=31; i>=24; i--)
                fprintf(stderr,"%02x",((uint8_t *)&ave)[i]);
            fprintf(stderr," increase diff -> ");
            for (i=31; i>=24; i--)
                fprintf(stderr,"%02x",((uint8_t *)&bnTarget)[i]);
            fprintf(stderr," floor diff ");
            for (i=31; i>=24; i--)
                fprintf(stderr,"%02x",((uint8_t *)&target)[i]);
            fprintf(stderr," ht.%d percPoS.%d vs goal.%d -> diff %d\n",height,percPoS,goalperc,goalperc - percPoS);
        }
    }
    else if ( percPoS > goalperc ) // decrease PoW diff -> raise bnTarget
    {
        if ( oldflag != 0 )
        {
            bnTarget = ((ave * arith_uint256(goalperc)) + (easydiff * arith_uint256(percPoS))) / arith_uint256(percPoS + goalperc);
            bnTarget = (bnTarget / arith_uint256(goalperc * goalperc)) * arith_uint256(percPoS * percPoS * percPoS);
        }
        else bnTarget = (ave / arith_uint256(goalperc * goalperc)) * arith_uint256(percPoS * percPoS * percPoS);
        if ( bnTarget > easydiff )
            bnTarget = easydiff;
        else if ( bnTarget < ave ) // overflow
        {
            bnTarget = ((ave * arith_uint256(goalperc)) + (easydiff * arith_uint256(percPoS))) / arith_uint256(percPoS + goalperc);
            if ( bnTarget < ave )
                bnTarget = ave;
        }
        if ( dispflag != 0 )
        {
            for (i=31; i>=24; i--)
                fprintf(stderr,"%02x",((uint8_t *)&ave)[i]);
            fprintf(stderr," decrease diff -> ");
            for (i=31; i>=24; i--)
                fprintf(stderr,"%02x",((uint8_t *)&bnTarget)[i]);
            fprintf(stderr," floor diff ");
            for (i=31; i>=24; i--)
                fprintf(stderr,"%02x",((uint8_t *)&target)[i]);
            fprintf(stderr," ht.%d percPoS.%d vs goal.%d -> diff %d\n",height,percPoS,goalperc,goalperc - percPoS);
        }
    }
    else
        bnTarget = ave; // recent ave is perfect
    return(bnTarget);
}

// lulz
int32_t komodo_is_PeiceOfShit() { return(1); }

uint64_t hush_notarypayamount(int32_t nHeight, int64_t notarycount)
{
    int8_t curEra = 0; int64_t ret = 0;
    // if we have an end block in the first era, find our current era
    if ( ASSETCHAINS_ENDSUBSIDY[0] > 1 )
    {
        for ( curEra = 0; curEra <= ASSETCHAINS_LASTERA; curEra++ )
        {
            if ( ASSETCHAINS_ENDSUBSIDY[curEra] > nHeight || ASSETCHAINS_ENDSUBSIDY[curEra] == 0 )
                break;
        }
    }
    if ( curEra > ASSETCHAINS_LASTERA )
        return(0);
    
    if ( notarycount == 0 )
    {
        fprintf(stderr, "hush_notarypayamount failed num notaries is 0!\n");
        return(0);
    }
    // Because of reorgs we cannot use the notarized height value. 
    // We need to basically guess here and just pay some static amount.
    // Has the unwanted effect of varying coin emission, but cannot be helped.
    //fprintf(stderr, "era.%i paying total of %lu\n",curEra, ASSETCHAINS_NOTARY_PAY[curEra]);
    ret = ASSETCHAINS_NOTARY_PAY[curEra] / notarycount;
    return(ret);
}

int32_t hush_getnotarizedheight(uint32_t timestamp,int32_t height, uint8_t *script, int32_t len)
{
    // Check the notarization is valid, and extract notarized height. 
    uint64_t voutmask;
    uint8_t scriptbuf[10001]; 
    int32_t isratification,specialtx,notarizedheight;

    if ( len >= sizeof(uint32_t) && len <= sizeof(scriptbuf) )
    {
        memcpy(scriptbuf,script,len);
        if ( hush_voutupdate(true,&isratification,0,scriptbuf,len,height,uint256(),1,1,&voutmask,&specialtx,&notarizedheight,0,1,0,timestamp) != -2 )
        {
            fprintf(stderr, "<<<<<<INVALID NOTARIZATION ht.%i\n",notarizedheight);
            return(0);
        }
    } else return(0);
    return(notarizedheight);
}

uint64_t hush_notarypay(CMutableTransaction &txNew, std::vector<int8_t> &NotarizationNotaries, uint32_t timestamp, int32_t height, uint8_t *script, int32_t len)
{
    // fetch notary pubkey array.
    uint64_t total = 0, AmountToPay = 0;
    int8_t numSN = 0; uint8_t notarypubkeys[64][33] = {0};
    numSN = hush_notaries(notarypubkeys, height, timestamp);

    // No point going further, no notaries can be paid.
    if ( notarypubkeys[0][0] == 0 )
        return(0);
    
    // Check the notarization is valid.
    int32_t notarizedheight = hush_getnotarizedheight(timestamp, height, script, len);
    if ( notarizedheight == 0 )
        return(0);

    // resize coinbase vouts to number of notary nodes +1 for coinbase itself.
    txNew.vout.resize(NotarizationNotaries.size()+1);
    
    // Calcualte the amount to pay according to the current era.
    AmountToPay = hush_notarypayamount(height,NotarizationNotaries.size());
    if ( AmountToPay == 0 )
        return(0);
    
    // loop over notarization vins and add transaction to coinbase.
    // Commented prints here can be used to verify manually the pubkeys match.
    for (int8_t n = 0; n < NotarizationNotaries.size(); n++) 
    {
        uint8_t *ptr;
        txNew.vout[n+1].scriptPubKey.resize(35);
        ptr = (uint8_t *)&txNew.vout[n+1].scriptPubKey[0];
        ptr[0] = 33;
        for (int8_t i=0; i<33; i++)
        {
            ptr[i+1] = notarypubkeys[NotarizationNotaries[n]][i];
            //fprintf(stderr,"%02x",ptr[i+1]);
        }
        ptr[34] = OP_CHECKSIG;
        //fprintf(stderr," set notary %i PUBKEY33 into vout[%i] amount.%lu\n",NotarizationNotaries[n],n+1,AmountToPay);
        txNew.vout[n+1].nValue = AmountToPay;
        total += txNew.vout[n+1].nValue;
    }
    return(total);
}

bool GetNotarizationNotaries(uint8_t notarypubkeys[64][33], int8_t &numNN, const std::vector<CTxIn> &vin, std::vector<int8_t> &NotarizationNotaries)
{
    uint8_t *script; int32_t scriptlen;
    if ( notarypubkeys[0][0] == 0 )
        return false;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        uint256 hash; CTransaction tx1;
        if ( GetTransaction(txin.prevout.hash,tx1,hash,false) )
        {
            for (int8_t i = 0; i < numNN; i++) 
            {
                script = (uint8_t *)&tx1.vout[txin.prevout.n].scriptPubKey[0];
                scriptlen = (int32_t)tx1.vout[txin.prevout.n].scriptPubKey.size();
                if ( scriptlen == 35 && script[0] == 33 && script[34] == OP_CHECKSIG && memcmp(script+1,notarypubkeys[i],33) == 0 )
                    NotarizationNotaries.push_back(i);
            }
        } else return false;
    }
    return true;
}

uint64_t hush_checknotarypay(CBlock *pblock,int32_t height)
{
    std::vector<int8_t> NotarizationNotaries; uint8_t *script; int32_t scriptlen;
    uint64_t timestamp = pblock->nTime;
    int8_t numSN = 0; uint8_t notarypubkeys[64][33] = {0};
    numSN = hush_notaries(notarypubkeys, height, timestamp);
    if ( !GetNotarizationNotaries(notarypubkeys, numSN, pblock->vtx[1].vin, NotarizationNotaries) )
        return(0);
    
    // check a notary didnt sign twice (this would be an invalid notarization later on and cause problems)
    std::set<int> checkdupes( NotarizationNotaries.begin(), NotarizationNotaries.end() );
    if ( checkdupes.size() != NotarizationNotaries.size() ) {
        fprintf(stderr, "Possible notarization is signed multiple times by same notary. It is invalid.\n");
        return(0);
    }
    const CChainParams& chainparams = Params();
    const Consensus::Params &consensusParams = chainparams.GetConsensus();
    uint64_t totalsats = 0;
    CMutableTransaction txNew = CreateNewContextualCMutableTransaction(consensusParams, height);
    if ( pblock->vtx[1].vout.size() == 2 && pblock->vtx[1].vout[1].nValue == 0 )
    {
        // Get the OP_RETURN for the notarization
        uint8_t *script = (uint8_t *)&pblock->vtx[1].vout[1].scriptPubKey[0];
        int32_t scriptlen = (int32_t)pblock->vtx[1].vout[1].scriptPubKey.size();
        if ( script[0] == OP_RETURN )
        {
            // Create the coinbase tx again, using the extracted data, this is the same function the miner uses, with the same data. 
            // This allows us to know exactly that the coinbase is correct.
            totalsats = hush_notarypay(txNew, NotarizationNotaries, pblock->nTime, height, script, scriptlen);
        } 
        else 
        {
            fprintf(stderr, "vout 2 of notarization is not OP_RETURN scriptlen.%i\n", scriptlen);
            return(0);
        }
    } else return(0);
    
    // if notarypay fails, because the notarization is not valid, exit now as txNew was not created.
    // This should never happen, as the notarization is checked before this function is called.
    if ( totalsats == 0 )
    {
        fprintf(stderr, "notary pay returned 0!\n");
        return(0);
    }
    
    int8_t n = 0, i = 0, matches = 0;
    uint64_t total = 0, AmountToPay = 0;
    
    // get the pay amount from the created tx.
    AmountToPay = txNew.vout[1].nValue;
    
    // Check the created coinbase pays the correct notaries.
    BOOST_FOREACH(const CTxOut& txout, pblock->vtx[0].vout)
    {
        // skip the coinbase paid to the miner.
        if ( n == 0 ) 
        {
            n++;
            continue;
        }
        // Check the pubkeys match the pubkeys in the notarization.
        script = (uint8_t *)&txout.scriptPubKey[0];
        scriptlen = (int32_t)txout.scriptPubKey.size();
        if ( scriptlen == 35 && script[0] == 33 && script[34] == OP_CHECKSIG && memcmp(script+1,notarypubkeys[NotarizationNotaries[n-1]],33) == 0 )
        {
            // check the value is correct
            if ( pblock->vtx[0].vout[n].nValue == AmountToPay )
            {
                matches++;
                total += txout.nValue;
                //fprintf(stderr, "MATCHED AmountPaid.%lu notaryid.%i\n",AmountToPay,NotarizationNotaries[n-1]);
            }
            else fprintf(stderr, "NOT MATCHED AmountPaid.%llu AmountToPay.%llu notaryid.%i\n", (long long)pblock->vtx[0].vout[n].nValue, (long long)AmountToPay, NotarizationNotaries[n-1]);
        }
        n++;
    }
    if ( matches != 0 && matches == NotarizationNotaries.size() && totalsats == total )
    {
        //fprintf(stderr, "Validated coinbase matches notarization in tx position 1.\n" );
        return(totalsats);
    }
    return(0);
}

bool hush_appendACscriptpub()
{
    static bool didinit = false;
    if ( didinit ) 
        return didinit;
    // HUSH doesn't use earlytxid so we do not need this in this function
    //ASSETCHAINS_SCRIPTPUB = devtax_scriptpub_for_height(height);
    if ( ASSETCHAINS_SCRIPTPUB[ASSETCHAINS_SCRIPTPUB.back()] == 49 && ASSETCHAINS_SCRIPTPUB[ASSETCHAINS_SCRIPTPUB.back()-1] == 51 )
    {
        CTransaction tx; uint256 blockhash; 
        // get transaction and check that it occured before height 100. 
        if ( myGetTransaction(HUSH_EARLYTXID,tx,blockhash) && mapBlockIndex[blockhash]->GetHeight() < HUSH_EARLYTXID_HEIGHT )
        {
             for (int i = 0; i < tx.vout.size(); i++) 
             {
                 if ( tx.vout[i].scriptPubKey[0] == OP_RETURN )
                 {
                     ASSETCHAINS_SCRIPTPUB.pop_back(); ASSETCHAINS_SCRIPTPUB.pop_back(); // remove last 2 chars. 
                      // get OP_RETURN from txid and append the HexStr of it to scriptpub 
                     ASSETCHAINS_SCRIPTPUB.append(HexStr(tx.vout[i].scriptPubKey.begin()+3, tx.vout[i].scriptPubKey.end()));
                     //fprintf(stderr, "ac_script.%s\n",ASSETCHAINS_SCRIPTPUB.c_str());
                     didinit = true;
                     return true;
                 }
             }
        }
        fprintf(stderr, "could not get HUSH_EARLYTXID.%s OP_RETURN data. Restart with correct txid!\n", HUSH_EARLYTXID.GetHex().c_str());
        StartShutdown();
    }
    return false;
}

void GetHushEarlytxidScriptPub()
{
    if ( HUSH_EARLYTXID == zeroid )
    {
        fprintf(stderr, "Restart deamon with -earlytxid.\n");
        StartShutdown();
        return;
    }
    if ( ASSETCHAINS_EARLYTXIDCONTRACT == EVAL_PRICES && HUSH_SNAPSHOT_INTERVAL == 0 )
    {
        fprintf(stderr, "Prices->paymentsCC contract must have -ac_snapshot enabled to pay out.\n");
        StartShutdown();
        return;
    }
    if ( chainActive.Height() < HUSH_EARLYTXID_HEIGHT )
    {
        fprintf(stderr, "Cannot fetch -earlytxid before block %d.\n",HUSH_EARLYTXID_HEIGHT);
        StartShutdown();
        return;
    }
    CTransaction tx; uint256 blockhash; int32_t i;
    // get transaction and check that it occured before height 100. 
    if ( myGetTransaction(HUSH_EARLYTXID,tx,blockhash) && mapBlockIndex[blockhash]->GetHeight() < HUSH_EARLYTXID_HEIGHT )
    {
        for (i = 0; i < tx.vout.size(); i++) 
            if ( tx.vout[i].scriptPubKey[0] == OP_RETURN )
                break;
        if ( i < tx.vout.size() )
        {
            HUSH_EARLYTXID_SCRIPTPUB = CScript(tx.vout[i].scriptPubKey.begin()+3, tx.vout[i].scriptPubKey.end());
            fprintf(stderr, "HUSH_EARLYTXID_SCRIPTPUB.%s\n", HexStr(HUSH_EARLYTXID_SCRIPTPUB.begin(),HUSH_EARLYTXID_SCRIPTPUB.end()).c_str());
            return;
        }
    }
    fprintf(stderr, "INVALID -earlytxid, restart daemon with correct txid.\n");
    StartShutdown();
}

int64_t hush_checkcommission(CBlock *pblock,int32_t height)
{
    if(fDebug)
        fprintf(stderr,"%s at height=%d\n",__func__,height);
    int64_t checktoshis=0; uint8_t *script,scripthex[8192]; int32_t scriptlen,matched = 0; static bool didinit = false;
    ASSETCHAINS_SCRIPTPUB = devtax_scriptpub_for_height(height);
    if ( ASSETCHAINS_COMMISSION != 0 || ASSETCHAINS_FOUNDERS_REWARD != 0 )
    {
        checktoshis = the_commission(pblock,height);
        if ( checktoshis >= 10000 && pblock->vtx[0].vout.size() < 2 )
        {
            fprintf(stderr,"ERROR: hush_checkcommission vsize.%d height.%d commission %.8f has checktoshis=%lu <10000 or less than 2 vouts (vouts=%lu)\n",(int32_t)pblock->vtx[0].vout.size(),height,(double)checktoshis/COIN, checktoshis, pblock->vtx[0].vout.size() );
            return(-1);
        }
        else if ( checktoshis != 0 )
        {
            script = (uint8_t *)&pblock->vtx[0].vout[1].scriptPubKey[0];
            scriptlen = (int32_t)pblock->vtx[0].vout[1].scriptPubKey.size();
            if ( fDebug )
            {
                int32_t i;
                for (i=0; i<scriptlen; i++)
                    fprintf(stderr,"%02x",script[i]);
                fprintf(stderr," vout[1] %.8f vs %.8f\n",(double)checktoshis/COIN,(double)pblock->vtx[0].vout[1].nValue/COIN);
            }
            if ( ASSETCHAINS_SCRIPTPUB.size() > 1 )
            {
                static bool didinit = false;
                if ( !didinit && height > HUSH_EARLYTXID_HEIGHT && HUSH_EARLYTXID != zeroid && hush_appendACscriptpub() )
                {
                    fprintf(stderr, "appended CC_op_return to ASSETCHAINS_SCRIPTPUB.%s\n", ASSETCHAINS_SCRIPTPUB.c_str());
                    didinit = true;
                }
                if ( ASSETCHAINS_SCRIPTPUB.size()/2 == scriptlen && scriptlen < sizeof(scripthex) )
                {
                    decode_hex(scripthex,scriptlen,(char *)ASSETCHAINS_SCRIPTPUB.c_str());
                    if ( memcmp(scripthex,script,scriptlen) == 0 )
                        matched = scriptlen;
                }
            }
            else if ( scriptlen == 35 && script[0] == 33 && script[34] == OP_CHECKSIG && memcmp(script+1,ASSETCHAINS_OVERRIDE_PUBKEY33,33) == 0 )
                matched = 35;
            else if ( scriptlen == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 && script[2] == 20 && script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG && memcmp(script+3,ASSETCHAINS_OVERRIDE_PUBKEYHASH,20) == 0 )
                matched = 25;
            if ( matched == 0 )
            {
                if ( 0 && ASSETCHAINS_SCRIPTPUB.size() > 1 )
                {
                    int32_t i;
                    for (i=0; i<ASSETCHAINS_SCRIPTPUB.size(); i++)
                        fprintf(stderr,"%02x",ASSETCHAINS_SCRIPTPUB[i]);
                }
                fprintf(stderr," -ac[%d] payment to wrong pubkey scriptlen.%d, scriptpub[%d] checktoshis.%llu\n",(int32_t)ASSETCHAINS_SCRIPTPUB.size(),scriptlen,(int32_t)ASSETCHAINS_SCRIPTPUB.size()/2,(long long)checktoshis);
                return(-1);

            }
            if ( pblock->vtx[0].vout[1].nValue != checktoshis )
            {
                fprintf(stderr,"ERROR: ht.%d checktoshis %.8f vs actual vout[1] %.8f !!!\n",height,dstr(checktoshis),dstr(pblock->vtx[0].vout[1].nValue));
                return(-1);
            }
        }
    }
    if(fDebug)
        fprintf(stderr,"%s checktoshis=%li at height=%d\n",__func__,checktoshis, height);
    return(checktoshis);
}

bool HUSH_TEST_ASSETCHAIN_SKIP_POW = 0;

int32_t hush_checkPOW(int32_t slowflag,CBlock *pblock,int32_t height)
{
    uint256 hash,merkleroot; arith_uint256 bnTarget,bhash; bool fNegative,fOverflow; uint8_t *script,pubkey33[33],pubkeys[64][33]; int32_t i,scriptlen,possible,PoSperc,is_PoSblock=0,n,failed = 0,notaryid = -1; int64_t checktoshis,value; CBlockIndex *pprev;
    if ( HUSH_TEST_ASSETCHAIN_SKIP_POW == 0 && Params().NetworkIDString() == "regtest" )
        HUSH_TEST_ASSETCHAIN_SKIP_POW = 1;
    if ( !CheckEquihashSolution(pblock, Params()) )
    {
        fprintf(stderr,"hush_checkPOW slowflag.%d ht.%d CheckEquihashSolution failed\n",slowflag,height);
        return(-1);
    }
    hash = pblock->GetHash();
    bnTarget.SetCompact(pblock->nBits,&fNegative,&fOverflow);
    bhash = UintToArith256(hash);
    possible = hush_block2pubkey33(pubkey33,pblock);
    if ( height == 0 ) {
        if ( slowflag != 0 ) {
            fprintf(stderr,"height.%d slowflag.%d possible.%d cmp.%d\n",height,slowflag,possible,bhash > bnTarget);
            return(0);
        }
        BlockMap::const_iterator it = mapBlockIndex.find(pblock->hashPrevBlock);
        if ( it != mapBlockIndex.end() && (pprev= it->second) != 0 )
            height = pprev->GetHeight() + 1;
        if ( height == 0 )
            return(0);
    }

    if ( (SMART_CHAIN_SYMBOL[0] != 0) && bhash > bnTarget ) {
        failed = 1;
        if ( height > 0 && SMART_CHAIN_SYMBOL[0] == 0 ) // for the fast case
        {
            if ( (n= hush_notaries(pubkeys,height,pblock->nTime)) > 0 )
            {
                for (i=0; i<n; i++)
                    if ( memcmp(pubkey33,pubkeys[i],33) == 0 )
                    {
                        notaryid = i;
                        break;
                    }
            }
        } else if ( possible == 0 || SMART_CHAIN_SYMBOL[0] != 0 ) {
            if ( HUSH_TEST_ASSETCHAIN_SKIP_POW )
                return(0);
            if ( ASSETCHAINS_STAKED == 0 )
                return(-1);
        }
    }
    if ( failed == 0 && ASSETCHAINS_COMMISSION != 0 ) {
        if ( height == 1 ) {
            ASSETCHAINS_SCRIPTPUB = devtax_scriptpub_for_height(height);
            if ( ASSETCHAINS_SCRIPTPUB.size() > 1 && ASSETCHAINS_SCRIPTPUB[ASSETCHAINS_SCRIPTPUB.back()] != 49 && ASSETCHAINS_SCRIPTPUB[ASSETCHAINS_SCRIPTPUB.back()-1] != 51 ) {
                int32_t scriptlen; uint8_t scripthex[10000];
                script = (uint8_t *)&pblock->vtx[0].vout[0].scriptPubKey[0];
                scriptlen = (int32_t)pblock->vtx[0].vout[0].scriptPubKey.size();
                if ( ASSETCHAINS_SCRIPTPUB.size()/2 == scriptlen && scriptlen < sizeof(scripthex) ) {
                    decode_hex(scripthex,scriptlen,(char *)ASSETCHAINS_SCRIPTPUB.c_str());
                    if ( memcmp(scripthex,script,scriptlen) != 0 )
                        return(-1);
                } else return(-1);
            } else if ( ASSETCHAINS_OVERRIDE_PUBKEY33[0] != 0 ) {
                script = (uint8_t *)&pblock->vtx[0].vout[0].scriptPubKey[0];
                scriptlen = (int32_t)pblock->vtx[0].vout[0].scriptPubKey.size();
                if ( scriptlen != 35 || script[0] != 33 || script[34] != OP_CHECKSIG || memcmp(script+1,ASSETCHAINS_OVERRIDE_PUBKEY33,33) != 0 )
                    return(-1);
            }
        } else {
            if ( hush_checkcommission(pblock,height) < 0 )
                return(-1);
        }
    }
    // Consensus rule to force miners to mine the notary coinbase payment happens in ConnectBlock 
    // the default daemon miner, checks the actual vins so the only way this will fail, is if someone changes the miner, 
    // and then creates txs to the crypto address meeting min sigs and puts it in tx position 1.
    // If they go through this effort, the block will still fail at connect block, and will be auto purged by the temp file fix, teh lulz
    if ( failed == 0 && ASSETCHAINS_NOTARY_PAY[0] != 0 && pblock->vtx.size() > 1 )
    {
        // We check the full validation in ConnectBlock directly to get the amount for coinbase. So just approx here.
        if ( slowflag == 0 && pblock->vtx[0].vout.size() > 1 )
        {
            // Check the notarization tx is to the crypto address.
            if ( !hush_is_notarytx(pblock->vtx[1]) == 1 )
            {
                fprintf(stderr, "notarization is not to crypto address ht.%i\n",height);
                return(-1); 
            }
            // Check min sigs.
            int8_t numSN = 0; uint8_t notarypubkeys[64][33] = {0};
            numSN = hush_notaries(notarypubkeys, height, pblock->nTime);
            if ( pblock->vtx[1].vin.size() < numSN/5 )
            {
                fprintf(stderr, "ht.%i does not meet minsigs.%i sigs.%lld\n",height,numSN/5,(long long)pblock->vtx[1].vin.size());
                return(-1);
            }
        }
    }

    if(fDebug) {
        fprintf(stderr,"hush_checkPOW possible.%d slowflag.%d ht.%d notaryid.%d failed.%d\n",possible,slowflag,height,notaryid,failed);
    }
    if ( failed != 0 && possible == 0 && notaryid < 0 ) {
        return(-1);
    } else {
         return(0);
    }
}

int32_t hush_scpublic(uint32_t tiptime)
{
    // HUSH does not support surveillance coins, go use something else if you want no privacy
    return 0;
}

int64_t hush_newcoins(int64_t *zfundsp,int32_t nHeight,CBlock *pblock)
{
    CTxDestination address; int32_t i,j,m,n,vout; uint8_t *script; uint256 txid,hashBlock; int64_t zfunds=0,vinsum=0,voutsum=0;
    n = pblock->vtx.size();
    for (i=0; i<n; i++)
    {
        CTransaction vintx,&tx = pblock->vtx[i];
        if ( (m= tx.vin.size()) > 0 )
        {
            for (j=0; j<m; j++)
            {
                if ( i == 0 )
                    continue;
                txid = tx.vin[j].prevout.hash;
                vout = tx.vin[j].prevout.n;
                if ( !GetTransaction(txid,vintx,hashBlock, false) || vout >= vintx.vout.size() )
                {
                    fprintf(stderr,"ERROR: %s/v%d cant find\n",txid.ToString().c_str(),vout);
                    return(0);
                }
                vinsum += vintx.vout[vout].nValue;
            }
        }
        if ( (m= tx.vout.size()) > 0 )
        {
            for (j=0; j<m-1; j++)
            {
                // This is an example address used in docs
                if ( ExtractDestination(tx.vout[j].scriptPubKey,address) != 0 && strcmp("RD6GgnrMpPaTSMn8vai6yiGA7mN4QGPVMY",CBitcoinAddress(address).ToString().c_str()) != 0 )
                    voutsum += tx.vout[j].nValue;
                else printf("skip %.8f -> %s\n",dstr(tx.vout[j].nValue),CBitcoinAddress(address).ToString().c_str());
            }
            script = (uint8_t *)&tx.vout[j].scriptPubKey[0];
            if ( script == 0 || script[0] != 0x6a )
            {
                if ( ExtractDestination(tx.vout[j].scriptPubKey,address) != 0 && strcmp("RD6GgnrMpPaTSMn8vai6yiGA7mN4QGPVMY",CBitcoinAddress(address).ToString().c_str()) != 0 )
                    voutsum += tx.vout[j].nValue;
            }
        }
        zfunds -= tx.valueBalance;
    }
    *zfundsp = zfunds;
    //if ( voutsum-vinsum+zfunds > 100000*SATOSHIDEN || voutsum-vinsum+zfunds < 0 )
    //.    fprintf(stderr,"ht.%d vins %.8f, vouts %.8f -> %.8f zfunds %.8f\n",nHeight,dstr(vinsum),dstr(voutsum),dstr(voutsum)-dstr(vinsum),dstr(zfunds));
    return(voutsum - vinsum);
}

int64_t hush_coinsupply(int64_t *zfundsp,int32_t height)
{
    CBlockIndex *pindex; CBlock block; int64_t zfunds=0,supply = 0;
    //fprintf(stderr,"coinsupply %d\n",height);
    *zfundsp = 0;
    if ( (pindex= hush_chainactive(height)) != 0 )
    {
        while ( pindex != 0 && pindex->GetHeight() > 0 )
        {
            if ( pindex->newcoins == 0 && pindex->zfunds == 0 )
            {
                if ( hush_blockload(block,pindex) == 0 ) {
                    pindex->newcoins = hush_newcoins(&pindex->zfunds,pindex->GetHeight(),&block);
                } else {
                    fprintf(stderr,"error loading block.%d\n",pindex->GetHeight());
                    return(0);
                }
            }
            supply += pindex->newcoins;
            zfunds += pindex->zfunds;
            //printf("start ht.%d new %.8f -> supply %.8f zfunds %.8f -> %.8f\n",pindex->GetHeight(),dstr(pindex->newcoins),dstr(supply),dstr(pindex->zfunds),dstr(zfunds));
            pindex = pindex->pprev;
        }
    }
    *zfundsp = zfunds;
    return(supply);
}

