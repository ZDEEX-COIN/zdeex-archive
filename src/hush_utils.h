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
#include "key_io.h"
#include "cc/CCinclude.h"
#include <string.h>

#ifdef _WIN32
#include <sodium.h>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread.hpp>
#endif

#define SATOSHIDEN ((uint64_t)100000000L)
#define dstr(x) ((double)(x) / SATOSHIDEN)
#define portable_mutex_t pthread_mutex_t
#define portable_mutex_init(ptr) pthread_mutex_init(ptr,NULL)
#define portable_mutex_lock pthread_mutex_lock
#define portable_mutex_unlock pthread_mutex_unlock

struct allocitem { uint32_t allocsize,type; };
struct queueitem { struct queueitem *next,*prev; uint32_t allocsize,type;  };

typedef struct queue
{
	struct queueitem *list;
	pthread_mutex_t mutex;
    char name[64],initflag;
} queue_t;

#include "mini-gmp.c"

#define CRYPTO555_PUBSECPSTR "038a1bd41a08f38edda51042988022933c5775dfce81f7bae0b32a9179650352ac"
#define CRYPTO555_HUSHADDR   "RFetqf8WUfWnwNeXdknkm8ojk7EXnYFzrv"
#define CRYPTO555_RMD160STR  "deadbeefbadcaca748c4986b240ff7d7bc3fffb0"

#define HUSH_PUBTYPE 60

struct sha256_vstate { uint64_t length; uint32_t state[8],curlen; uint8_t buf[64]; };
struct rmd160_vstate { uint64_t length; uint8_t buf[64]; uint32_t curlen, state[5]; };

// following is ported from libtom

#define STORE32L(x, y)                                                                     \
{ (y)[3] = (uint8_t)(((x)>>24)&255); (y)[2] = (uint8_t)(((x)>>16)&255);   \
(y)[1] = (uint8_t)(((x)>>8)&255); (y)[0] = (uint8_t)((x)&255); }

#define LOAD32L(x, y)                            \
{ x = (uint32_t)(((uint64_t)((y)[3] & 255)<<24) | \
((uint32_t)((y)[2] & 255)<<16) | \
((uint32_t)((y)[1] & 255)<<8)  | \
((uint32_t)((y)[0] & 255))); }

#define STORE64L(x, y)                                                                     \
{ (y)[7] = (uint8_t)(((x)>>56)&255); (y)[6] = (uint8_t)(((x)>>48)&255);   \
(y)[5] = (uint8_t)(((x)>>40)&255); (y)[4] = (uint8_t)(((x)>>32)&255);   \
(y)[3] = (uint8_t)(((x)>>24)&255); (y)[2] = (uint8_t)(((x)>>16)&255);   \
(y)[1] = (uint8_t)(((x)>>8)&255); (y)[0] = (uint8_t)((x)&255); }

#define LOAD64L(x, y)                                                       \
{ x = (((uint64_t)((y)[7] & 255))<<56)|(((uint64_t)((y)[6] & 255))<<48)| \
(((uint64_t)((y)[5] & 255))<<40)|(((uint64_t)((y)[4] & 255))<<32)| \
(((uint64_t)((y)[3] & 255))<<24)|(((uint64_t)((y)[2] & 255))<<16)| \
(((uint64_t)((y)[1] & 255))<<8)|(((uint64_t)((y)[0] & 255))); }

#define STORE32H(x, y)                                                                     \
{ (y)[0] = (uint8_t)(((x)>>24)&255); (y)[1] = (uint8_t)(((x)>>16)&255);   \
(y)[2] = (uint8_t)(((x)>>8)&255); (y)[3] = (uint8_t)((x)&255); }

#define LOAD32H(x, y)                            \
{ x = (uint32_t)(((uint64_t)((y)[0] & 255)<<24) | \
((uint32_t)((y)[1] & 255)<<16) | \
((uint32_t)((y)[2] & 255)<<8)  | \
((uint32_t)((y)[3] & 255))); }

#define STORE64H(x, y)                                                                     \
{ (y)[0] = (uint8_t)(((x)>>56)&255); (y)[1] = (uint8_t)(((x)>>48)&255);     \
(y)[2] = (uint8_t)(((x)>>40)&255); (y)[3] = (uint8_t)(((x)>>32)&255);     \
(y)[4] = (uint8_t)(((x)>>24)&255); (y)[5] = (uint8_t)(((x)>>16)&255);     \
(y)[6] = (uint8_t)(((x)>>8)&255); (y)[7] = (uint8_t)((x)&255); }

#define LOAD64H(x, y)                                                      \
{ x = (((uint64_t)((y)[0] & 255))<<56)|(((uint64_t)((y)[1] & 255))<<48) | \
(((uint64_t)((y)[2] & 255))<<40)|(((uint64_t)((y)[3] & 255))<<32) | \
(((uint64_t)((y)[4] & 255))<<24)|(((uint64_t)((y)[5] & 255))<<16) | \
(((uint64_t)((y)[6] & 255))<<8)|(((uint64_t)((y)[7] & 255))); }

// Various logical functions
#define RORc(x, y) ( ((((uint32_t)(x)&0xFFFFFFFFUL)>>(uint32_t)((y)&31)) | ((uint32_t)(x)<<(uint32_t)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y))
#define S(x, n)         RORc((x),(n))
#define R(x, n)         (((x)&0xFFFFFFFFUL)>>(n))
#define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)       (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))
#ifndef MIN
#define MIN(x, y) ( ((x)<(y))?(x):(y) )
#endif

static inline int32_t sha256_vcompress(struct sha256_vstate * md,uint8_t *buf)
{
    uint32_t S[8],W[64],t0,t1,i;
    for (i=0; i<8; i++) // copy state into S
        S[i] = md->state[i];
    for (i=0; i<16; i++) // copy the state into 512-bits into W[0..15]
        LOAD32H(W[i],buf + (4*i));
    for (i=16; i<64; i++) // fill W[16..63]
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];

#define RND(a,b,c,d,e,f,g,h,i,ki)                    \
t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i];   \
t1 = Sigma0(a) + Maj(a, b, c);                  \
d += t0;                                        \
h  = t0 + t1;

    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],0,0x428a2f98);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],1,0x71374491);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],2,0xb5c0fbcf);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],3,0xe9b5dba5);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],4,0x3956c25b);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],5,0x59f111f1);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],6,0x923f82a4);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],7,0xab1c5ed5);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],8,0xd807aa98);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],9,0x12835b01);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],10,0x243185be);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],11,0x550c7dc3);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],12,0x72be5d74);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],13,0x80deb1fe);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],14,0x9bdc06a7);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],15,0xc19bf174);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],16,0xe49b69c1);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],17,0xefbe4786);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],18,0x0fc19dc6);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],19,0x240ca1cc);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],20,0x2de92c6f);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],21,0x4a7484aa);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],22,0x5cb0a9dc);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],23,0x76f988da);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],24,0x983e5152);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],25,0xa831c66d);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],26,0xb00327c8);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],27,0xbf597fc7);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],28,0xc6e00bf3);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],29,0xd5a79147);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],30,0x06ca6351);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],31,0x14292967);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],32,0x27b70a85);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],33,0x2e1b2138);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],34,0x4d2c6dfc);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],35,0x53380d13);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],36,0x650a7354);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],37,0x766a0abb);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],38,0x81c2c92e);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],39,0x92722c85);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],40,0xa2bfe8a1);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],41,0xa81a664b);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],42,0xc24b8b70);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],43,0xc76c51a3);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],44,0xd192e819);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],45,0xd6990624);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],46,0xf40e3585);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],47,0x106aa070);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],48,0x19a4c116);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],49,0x1e376c08);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],50,0x2748774c);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],51,0x34b0bcb5);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],52,0x391c0cb3);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],53,0x4ed8aa4a);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],54,0x5b9cca4f);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],55,0x682e6ff3);
    RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],56,0x748f82ee);
    RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],57,0x78a5636f);
    RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],58,0x84c87814);
    RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],59,0x8cc70208);
    RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],60,0x90befffa);
    RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],61,0xa4506ceb);
    RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],62,0xbef9a3f7);
    RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],63,0xc67178f2);
#undef RND
    for (i=0; i<8; i++) // feedback
        md->state[i] = md->state[i] + S[i];
    return(0);
}

#undef RORc
#undef Ch
#undef Maj
#undef S
#undef R
#undef Sigma0
#undef Sigma1
#undef Gamma0
#undef Gamma1

static inline void sha256_vinit(struct sha256_vstate * md)
{
    md->curlen = 0;
    md->length = 0;
    md->state[0] = 0x6A09E667UL;
    md->state[1] = 0xBB67AE85UL;
    md->state[2] = 0x3C6EF372UL;
    md->state[3] = 0xA54FF53AUL;
    md->state[4] = 0x510E527FUL;
    md->state[5] = 0x9B05688CUL;
    md->state[6] = 0x1F83D9ABUL;
    md->state[7] = 0x5BE0CD19UL;
}

static inline int32_t sha256_vprocess(struct sha256_vstate *md,const uint8_t *in,uint64_t inlen)
{
    uint64_t n; int32_t err;
    if ( md->curlen > sizeof(md->buf) )
        return(-1);
    while ( inlen > 0 )
    {
        if ( md->curlen == 0 && inlen >= 64 )
        {
            if ( (err= sha256_vcompress(md,(uint8_t *)in)) != 0 )
                return(err);
            md->length += 64 * 8, in += 64, inlen -= 64;
        }
        else
        {
            n = MIN(inlen,64 - md->curlen);
            memcpy(md->buf + md->curlen,in,(size_t)n);
            md->curlen += n, in += n, inlen -= n;
            if ( md->curlen == 64 )
            {
                if ( (err= sha256_vcompress(md,md->buf)) != 0 )
                    return(err);
                md->length += 8*64;
                md->curlen = 0;
            }
        }
    }
    return(0);
}

static inline int32_t sha256_vdone(struct sha256_vstate *md,uint8_t *out)
{
    int32_t i;
    if ( md->curlen >= sizeof(md->buf) )
        return(-1);
    md->length += md->curlen * 8; // increase the length of the message
    md->buf[md->curlen++] = (uint8_t)0x80; // append the '1' bit
    // if len > 56 bytes we append zeros then compress.  Then we can fall back to padding zeros and length encoding like normal.
    if ( md->curlen > 56 )
    {
        while ( md->curlen < 64 )
            md->buf[md->curlen++] = (uint8_t)0;
        sha256_vcompress(md,md->buf);
        md->curlen = 0;
    }
    while ( md->curlen < 56 ) // pad upto 56 bytes of zeroes
        md->buf[md->curlen++] = (uint8_t)0;
    STORE64H(md->length,md->buf+56); // store length
    sha256_vcompress(md,md->buf);
    for (i=0; i<8; i++) // copy output
        STORE32H(md->state[i],out+(4*i));
    return(0);
}

void vcalc_sha256(char deprecated[(256 >> 3) * 2 + 1],uint8_t hash[256 >> 3],uint8_t *src,int32_t len)
{
    struct sha256_vstate md;
    sha256_vinit(&md);
    sha256_vprocess(&md,src,len);
    sha256_vdone(&md,hash);
}

bits256 bits256_doublesha256(char *deprecated,uint8_t *data,int32_t datalen)
{
    bits256 hash,hash2; int32_t i;
    vcalc_sha256(0,hash.bytes,data,datalen);
    vcalc_sha256(0,hash2.bytes,hash.bytes,sizeof(hash));
    for (i=0; i<sizeof(hash); i++)
        hash.bytes[i] = hash2.bytes[sizeof(hash) - 1 - i];
    return(hash);
}


// rmd160: the five basic functions F(), G() and H()
#define F(x, y, z)        ((x) ^ (y) ^ (z))
#define G(x, y, z)        (((x) & (y)) | (~(x) & (z)))
#define H(x, y, z)        (((x) | ~(y)) ^ (z))
#define I(x, y, z)        (((x) & (z)) | ((y) & ~(z)))
#define J(x, y, z)        ((x) ^ ((y) | ~(z)))
#define ROLc(x, y) ( (((unsigned long)(x)<<(unsigned long)((y)&31)) | (((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)

/* the ten basic operations FF() through III() */
#define FF(a, b, c, d, e, x, s)        \
(a) += F((b), (c), (d)) + (x);\
(a) = ROLc((a), (s)) + (e);\
(c) = ROLc((c), 10);

#define GG(a, b, c, d, e, x, s)        \
(a) += G((b), (c), (d)) + (x) + 0x5a827999UL;\
(a) = ROLc((a), (s)) + (e);\
(c) = ROLc((c), 10);

#define HH(a, b, c, d, e, x, s)        \
(a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL;\
(a) = ROLc((a), (s)) + (e);\
(c) = ROLc((c), 10);

#define II(a, b, c, d, e, x, s)        \
(a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcUL;\
(a) = ROLc((a), (s)) + (e);\
(c) = ROLc((c), 10);

#define JJ(a, b, c, d, e, x, s)        \
(a) += J((b), (c), (d)) + (x) + 0xa953fd4eUL;\
(a) = ROLc((a), (s)) + (e);\
(c) = ROLc((c), 10);

#define FFF(a, b, c, d, e, x, s)        \
(a) += F((b), (c), (d)) + (x);\
(a) = ROLc((a), (s)) + (e);\
(c) = ROLc((c), 10);

#define GGG(a, b, c, d, e, x, s)        \
(a) += G((b), (c), (d)) + (x) + 0x7a6d76e9UL;\
(a) = ROLc((a), (s)) + (e);\
(c) = ROLc((c), 10);

#define HHH(a, b, c, d, e, x, s)        \
(a) += H((b), (c), (d)) + (x) + 0x6d703ef3UL;\
(a) = ROLc((a), (s)) + (e);\
(c) = ROLc((c), 10);

#define III(a, b, c, d, e, x, s)        \
(a) += I((b), (c), (d)) + (x) + 0x5c4dd124UL;\
(a) = ROLc((a), (s)) + (e);\
(c) = ROLc((c), 10);

#define JJJ(a, b, c, d, e, x, s)        \
(a) += J((b), (c), (d)) + (x) + 0x50a28be6UL;\
(a) = ROLc((a), (s)) + (e);\
(c) = ROLc((c), 10);

static int32_t rmd160_vcompress(struct rmd160_vstate *md,uint8_t *buf)
{
    uint32_t aa,bb,cc,dd,ee,aaa,bbb,ccc,ddd,eee,X[16];
    int i;

    /* load words X */
    for (i = 0; i < 16; i++){
        LOAD32L(X[i], buf + (4 * i));
    }

    /* load state */
    aa = aaa = md->state[0];
    bb = bbb = md->state[1];
    cc = ccc = md->state[2];
    dd = ddd = md->state[3];
    ee = eee = md->state[4];

    /* round 1 */
    FF(aa, bb, cc, dd, ee, X[ 0], 11);
    FF(ee, aa, bb, cc, dd, X[ 1], 14);
    FF(dd, ee, aa, bb, cc, X[ 2], 15);
    FF(cc, dd, ee, aa, bb, X[ 3], 12);
    FF(bb, cc, dd, ee, aa, X[ 4],  5);
    FF(aa, bb, cc, dd, ee, X[ 5],  8);
    FF(ee, aa, bb, cc, dd, X[ 6],  7);
    FF(dd, ee, aa, bb, cc, X[ 7],  9);
    FF(cc, dd, ee, aa, bb, X[ 8], 11);
    FF(bb, cc, dd, ee, aa, X[ 9], 13);
    FF(aa, bb, cc, dd, ee, X[10], 14);
    FF(ee, aa, bb, cc, dd, X[11], 15);
    FF(dd, ee, aa, bb, cc, X[12],  6);
    FF(cc, dd, ee, aa, bb, X[13],  7);
    FF(bb, cc, dd, ee, aa, X[14],  9);
    FF(aa, bb, cc, dd, ee, X[15],  8);

    /* round 2 */
    GG(ee, aa, bb, cc, dd, X[ 7],  7);
    GG(dd, ee, aa, bb, cc, X[ 4],  6);
    GG(cc, dd, ee, aa, bb, X[13],  8);
    GG(bb, cc, dd, ee, aa, X[ 1], 13);
    GG(aa, bb, cc, dd, ee, X[10], 11);
    GG(ee, aa, bb, cc, dd, X[ 6],  9);
    GG(dd, ee, aa, bb, cc, X[15],  7);
    GG(cc, dd, ee, aa, bb, X[ 3], 15);
    GG(bb, cc, dd, ee, aa, X[12],  7);
    GG(aa, bb, cc, dd, ee, X[ 0], 12);
    GG(ee, aa, bb, cc, dd, X[ 9], 15);
    GG(dd, ee, aa, bb, cc, X[ 5],  9);
    GG(cc, dd, ee, aa, bb, X[ 2], 11);
    GG(bb, cc, dd, ee, aa, X[14],  7);
    GG(aa, bb, cc, dd, ee, X[11], 13);
    GG(ee, aa, bb, cc, dd, X[ 8], 12);

    /* round 3 */
    HH(dd, ee, aa, bb, cc, X[ 3], 11);
    HH(cc, dd, ee, aa, bb, X[10], 13);
    HH(bb, cc, dd, ee, aa, X[14],  6);
    HH(aa, bb, cc, dd, ee, X[ 4],  7);
    HH(ee, aa, bb, cc, dd, X[ 9], 14);
    HH(dd, ee, aa, bb, cc, X[15],  9);
    HH(cc, dd, ee, aa, bb, X[ 8], 13);
    HH(bb, cc, dd, ee, aa, X[ 1], 15);
    HH(aa, bb, cc, dd, ee, X[ 2], 14);
    HH(ee, aa, bb, cc, dd, X[ 7],  8);
    HH(dd, ee, aa, bb, cc, X[ 0], 13);
    HH(cc, dd, ee, aa, bb, X[ 6],  6);
    HH(bb, cc, dd, ee, aa, X[13],  5);
    HH(aa, bb, cc, dd, ee, X[11], 12);
    HH(ee, aa, bb, cc, dd, X[ 5],  7);
    HH(dd, ee, aa, bb, cc, X[12],  5);

    /* round 4 */
    II(cc, dd, ee, aa, bb, X[ 1], 11);
    II(bb, cc, dd, ee, aa, X[ 9], 12);
    II(aa, bb, cc, dd, ee, X[11], 14);
    II(ee, aa, bb, cc, dd, X[10], 15);
    II(dd, ee, aa, bb, cc, X[ 0], 14);
    II(cc, dd, ee, aa, bb, X[ 8], 15);
    II(bb, cc, dd, ee, aa, X[12],  9);
    II(aa, bb, cc, dd, ee, X[ 4],  8);
    II(ee, aa, bb, cc, dd, X[13],  9);
    II(dd, ee, aa, bb, cc, X[ 3], 14);
    II(cc, dd, ee, aa, bb, X[ 7],  5);
    II(bb, cc, dd, ee, aa, X[15],  6);
    II(aa, bb, cc, dd, ee, X[14],  8);
    II(ee, aa, bb, cc, dd, X[ 5],  6);
    II(dd, ee, aa, bb, cc, X[ 6],  5);
    II(cc, dd, ee, aa, bb, X[ 2], 12);

    /* round 5 */
    JJ(bb, cc, dd, ee, aa, X[ 4],  9);
    JJ(aa, bb, cc, dd, ee, X[ 0], 15);
    JJ(ee, aa, bb, cc, dd, X[ 5],  5);
    JJ(dd, ee, aa, bb, cc, X[ 9], 11);
    JJ(cc, dd, ee, aa, bb, X[ 7],  6);
    JJ(bb, cc, dd, ee, aa, X[12],  8);
    JJ(aa, bb, cc, dd, ee, X[ 2], 13);
    JJ(ee, aa, bb, cc, dd, X[10], 12);
    JJ(dd, ee, aa, bb, cc, X[14],  5);
    JJ(cc, dd, ee, aa, bb, X[ 1], 12);
    JJ(bb, cc, dd, ee, aa, X[ 3], 13);
    JJ(aa, bb, cc, dd, ee, X[ 8], 14);
    JJ(ee, aa, bb, cc, dd, X[11], 11);
    JJ(dd, ee, aa, bb, cc, X[ 6],  8);
    JJ(cc, dd, ee, aa, bb, X[15],  5);
    JJ(bb, cc, dd, ee, aa, X[13],  6);

    /* parallel round 1 */
    JJJ(aaa, bbb, ccc, ddd, eee, X[ 5],  8);
    JJJ(eee, aaa, bbb, ccc, ddd, X[14],  9);
    JJJ(ddd, eee, aaa, bbb, ccc, X[ 7],  9);
    JJJ(ccc, ddd, eee, aaa, bbb, X[ 0], 11);
    JJJ(bbb, ccc, ddd, eee, aaa, X[ 9], 13);
    JJJ(aaa, bbb, ccc, ddd, eee, X[ 2], 15);
    JJJ(eee, aaa, bbb, ccc, ddd, X[11], 15);
    JJJ(ddd, eee, aaa, bbb, ccc, X[ 4],  5);
    JJJ(ccc, ddd, eee, aaa, bbb, X[13],  7);
    JJJ(bbb, ccc, ddd, eee, aaa, X[ 6],  7);
    JJJ(aaa, bbb, ccc, ddd, eee, X[15],  8);
    JJJ(eee, aaa, bbb, ccc, ddd, X[ 8], 11);
    JJJ(ddd, eee, aaa, bbb, ccc, X[ 1], 14);
    JJJ(ccc, ddd, eee, aaa, bbb, X[10], 14);
    JJJ(bbb, ccc, ddd, eee, aaa, X[ 3], 12);
    JJJ(aaa, bbb, ccc, ddd, eee, X[12],  6);

    /* parallel round 2 */
    III(eee, aaa, bbb, ccc, ddd, X[ 6],  9);
    III(ddd, eee, aaa, bbb, ccc, X[11], 13);
    III(ccc, ddd, eee, aaa, bbb, X[ 3], 15);
    III(bbb, ccc, ddd, eee, aaa, X[ 7],  7);
    III(aaa, bbb, ccc, ddd, eee, X[ 0], 12);
    III(eee, aaa, bbb, ccc, ddd, X[13],  8);
    III(ddd, eee, aaa, bbb, ccc, X[ 5],  9);
    III(ccc, ddd, eee, aaa, bbb, X[10], 11);
    III(bbb, ccc, ddd, eee, aaa, X[14],  7);
    III(aaa, bbb, ccc, ddd, eee, X[15],  7);
    III(eee, aaa, bbb, ccc, ddd, X[ 8], 12);
    III(ddd, eee, aaa, bbb, ccc, X[12],  7);
    III(ccc, ddd, eee, aaa, bbb, X[ 4],  6);
    III(bbb, ccc, ddd, eee, aaa, X[ 9], 15);
    III(aaa, bbb, ccc, ddd, eee, X[ 1], 13);
    III(eee, aaa, bbb, ccc, ddd, X[ 2], 11);

    /* parallel round 3 */
    HHH(ddd, eee, aaa, bbb, ccc, X[15],  9);
    HHH(ccc, ddd, eee, aaa, bbb, X[ 5],  7);
    HHH(bbb, ccc, ddd, eee, aaa, X[ 1], 15);
    HHH(aaa, bbb, ccc, ddd, eee, X[ 3], 11);
    HHH(eee, aaa, bbb, ccc, ddd, X[ 7],  8);
    HHH(ddd, eee, aaa, bbb, ccc, X[14],  6);
    HHH(ccc, ddd, eee, aaa, bbb, X[ 6],  6);
    HHH(bbb, ccc, ddd, eee, aaa, X[ 9], 14);
    HHH(aaa, bbb, ccc, ddd, eee, X[11], 12);
    HHH(eee, aaa, bbb, ccc, ddd, X[ 8], 13);
    HHH(ddd, eee, aaa, bbb, ccc, X[12],  5);
    HHH(ccc, ddd, eee, aaa, bbb, X[ 2], 14);
    HHH(bbb, ccc, ddd, eee, aaa, X[10], 13);
    HHH(aaa, bbb, ccc, ddd, eee, X[ 0], 13);
    HHH(eee, aaa, bbb, ccc, ddd, X[ 4],  7);
    HHH(ddd, eee, aaa, bbb, ccc, X[13],  5);

    /* parallel round 4 */
    GGG(ccc, ddd, eee, aaa, bbb, X[ 8], 15);
    GGG(bbb, ccc, ddd, eee, aaa, X[ 6],  5);
    GGG(aaa, bbb, ccc, ddd, eee, X[ 4],  8);
    GGG(eee, aaa, bbb, ccc, ddd, X[ 1], 11);
    GGG(ddd, eee, aaa, bbb, ccc, X[ 3], 14);
    GGG(ccc, ddd, eee, aaa, bbb, X[11], 14);
    GGG(bbb, ccc, ddd, eee, aaa, X[15],  6);
    GGG(aaa, bbb, ccc, ddd, eee, X[ 0], 14);
    GGG(eee, aaa, bbb, ccc, ddd, X[ 5],  6);
    GGG(ddd, eee, aaa, bbb, ccc, X[12],  9);
    GGG(ccc, ddd, eee, aaa, bbb, X[ 2], 12);
    GGG(bbb, ccc, ddd, eee, aaa, X[13],  9);
    GGG(aaa, bbb, ccc, ddd, eee, X[ 9], 12);
    GGG(eee, aaa, bbb, ccc, ddd, X[ 7],  5);
    GGG(ddd, eee, aaa, bbb, ccc, X[10], 15);
    GGG(ccc, ddd, eee, aaa, bbb, X[14],  8);

    /* parallel round 5 */
    FFF(bbb, ccc, ddd, eee, aaa, X[12] ,  8);
    FFF(aaa, bbb, ccc, ddd, eee, X[15] ,  5);
    FFF(eee, aaa, bbb, ccc, ddd, X[10] , 12);
    FFF(ddd, eee, aaa, bbb, ccc, X[ 4] ,  9);
    FFF(ccc, ddd, eee, aaa, bbb, X[ 1] , 12);
    FFF(bbb, ccc, ddd, eee, aaa, X[ 5] ,  5);
    FFF(aaa, bbb, ccc, ddd, eee, X[ 8] , 14);
    FFF(eee, aaa, bbb, ccc, ddd, X[ 7] ,  6);
    FFF(ddd, eee, aaa, bbb, ccc, X[ 6] ,  8);
    FFF(ccc, ddd, eee, aaa, bbb, X[ 2] , 13);
    FFF(bbb, ccc, ddd, eee, aaa, X[13] ,  6);
    FFF(aaa, bbb, ccc, ddd, eee, X[14] ,  5);
    FFF(eee, aaa, bbb, ccc, ddd, X[ 0] , 15);
    FFF(ddd, eee, aaa, bbb, ccc, X[ 3] , 13);
    FFF(ccc, ddd, eee, aaa, bbb, X[ 9] , 11);
    FFF(bbb, ccc, ddd, eee, aaa, X[11] , 11);

    /* combine results */
    ddd += cc + md->state[1];               /* final result for md->state[0] */
    md->state[1] = md->state[2] + dd + eee;
    md->state[2] = md->state[3] + ee + aaa;
    md->state[3] = md->state[4] + aa + bbb;
    md->state[4] = md->state[0] + bb + ccc;
    md->state[0] = ddd;

    return 0;
}

/**
 Initialize the hash state
 @param md   The hash state you wish to initialize
 @return 0 if successful
 */
int rmd160_vinit(struct rmd160_vstate * md)
{
    md->state[0] = 0x67452301UL;
    md->state[1] = 0xefcdab89UL;
    md->state[2] = 0x98badcfeUL;
    md->state[3] = 0x10325476UL;
    md->state[4] = 0xc3d2e1f0UL;
    md->curlen   = 0;
    md->length   = 0;
    return 0;
}
#define HASH_PROCESS(func_name, compress_name, state_var, block_size)                       \
int func_name (struct rmd160_vstate * md, const unsigned char *in, unsigned long inlen)               \
{                                                                                           \
unsigned long n;                                                                        \
int           err;                                                                      \
if (md->curlen > sizeof(md->buf)) {                             \
return -1;                                                            \
}                                                                                       \
while (inlen > 0) {                                                                     \
if (md->curlen == 0 && inlen >= block_size) {                           \
if ((err = compress_name (md, (unsigned char *)in)) != 0) {               \
return err;                                                                   \
}                                                                                \
md->length += block_size * 8;                                        \
in             += block_size;                                                    \
inlen          -= block_size;                                                    \
} else {                                                                            \
n = MIN(inlen, (block_size - md->curlen));                           \
memcpy(md->buf + md->curlen, in, (size_t)n);              \
md->curlen += n;                                                     \
in             += n;                                                             \
inlen          -= n;                                                             \
if (md->curlen == block_size) {                                      \
if ((err = compress_name (md, md->buf)) != 0) {            \
return err;                                                                \
}                                                                             \
md->length += 8*block_size;                                       \
md->curlen = 0;                                                   \
}                                                                                \
}                                                                                    \
}                                                                                       \
return 0;                                                                        \
}

/**
 Process a block of memory though the hash
 @param md     The hash state
 @param in     The data to hash
 @param inlen  The length of the data (octets)
 @return 0 if successful
 */
HASH_PROCESS(rmd160_vprocess, rmd160_vcompress, rmd160, 64)

/**
 Terminate the hash to get the digest
 @param md  The hash state
 @param out [out] The destination of the hash (20 bytes)
 @return 0 if successful
 */
int rmd160_vdone(struct rmd160_vstate * md, unsigned char *out)
{
    int i;
    if (md->curlen >= sizeof(md->buf)) {
        return -1;
    }
    /* increase the length of the message */
    md->length += md->curlen * 8;

    /* append the '1' bit */
    md->buf[md->curlen++] = (unsigned char)0x80;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->curlen > 56) {
        while (md->curlen < 64) {
            md->buf[md->curlen++] = (unsigned char)0;
        }
        rmd160_vcompress(md, md->buf);
        md->curlen = 0;
    }
    /* pad upto 56 bytes of zeroes */
    while (md->curlen < 56) {
        md->buf[md->curlen++] = (unsigned char)0;
    }
    /* store length */
    STORE64L(md->length, md->buf+56);
    rmd160_vcompress(md, md->buf);
    /* copy output */
    for (i = 0; i < 5; i++) {
        STORE32L(md->state[i], out+(4*i));
    }
    return 0;
}

void calc_rmd160(char deprecated[41],uint8_t buf[20],uint8_t *msg,int32_t len)
{
    struct rmd160_vstate md;
    rmd160_vinit(&md);
    rmd160_vprocess(&md,msg,len);
    rmd160_vdone(&md, buf);
}
#undef F
#undef G
#undef H
#undef I
#undef J
#undef ROLc
#undef FF
#undef GG
#undef HH
#undef II
#undef JJ
#undef FFF
#undef GGG
#undef HHH
#undef III
#undef JJJ

static const uint32_t crc32_tab[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3,	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de,	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,	0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5,	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,	0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940,	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,	0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t calc_crc32(uint32_t crc,const void *buf,size_t size)
{
	const uint8_t *p;

	p = (const uint8_t *)buf;
	crc = crc ^ ~0U;

	while (size--)
		crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

	return crc ^ ~0U;
}

void calc_rmd160_sha256(uint8_t rmd160[20],uint8_t *data,int32_t datalen)
{
    bits256 hash;
    vcalc_sha256(0,hash.bytes,data,datalen);
    calc_rmd160(0,rmd160,hash.bytes,sizeof(hash));
}

int32_t bitcoin_addr2rmd160(uint8_t *addrtypep,uint8_t rmd160[20],char *coinaddr)
{
    bits256 hash; uint8_t *buf,_buf[25]; int32_t len;
    memset(rmd160,0,20);
    *addrtypep = 0;
    buf = _buf;
    if ( (len= bitcoin_base58decode(buf,coinaddr)) >= 4 )
    {
        // validate with trailing hash, then remove hash
        hash = bits256_doublesha256(0,buf,21);
        *addrtypep = *buf;
        memcpy(rmd160,buf+1,20);
        if ( (buf[21]&0xff) == hash.bytes[31] && (buf[22]&0xff) == hash.bytes[30] &&(buf[23]&0xff) == hash.bytes[29] && (buf[24]&0xff) == hash.bytes[28] )
        {
            //printf("coinaddr.(%s) valid checksum addrtype.%02x\n",coinaddr,*addrtypep);
            return(20);
        }
        else
        {
            int32_t i;
            if ( len > 20 )
            {
                hash = bits256_doublesha256(0,buf,len);
            }
            for (i=0; i<len; i++)
                printf("%02x ",buf[i]);
            printf("\nhex checkhash.(%s) len.%d mismatch %02x %02x %02x %02x vs %02x %02x %02x %02x\n",coinaddr,len,buf[len-1]&0xff,buf[len-2]&0xff,buf[len-3]&0xff,buf[len-4]&0xff,hash.bytes[31],hash.bytes[30],hash.bytes[29],hash.bytes[28]);
        }
    }
	return(0);
}

char *bitcoin_address(char *coinaddr,uint8_t addrtype,uint8_t *pubkey_or_rmd160,int32_t len)
{
    int32_t i; uint8_t data[25]; bits256 hash;// char checkaddr[65];
    if ( len != 20 )
        calc_rmd160_sha256(data+1,pubkey_or_rmd160,len);
    else memcpy(data+1,pubkey_or_rmd160,20);
    //btc_convrmd160(checkaddr,addrtype,data+1);
    data[0] = addrtype;
    hash = bits256_doublesha256(0,data,21);
    for (i=0; i<4; i++)
        data[21+i] = hash.bytes[31-i];
    if ( (coinaddr= bitcoin_base58encode(coinaddr,data,25)) != 0 )
    {
        //uint8_t checktype,rmd160[20];
        //bitcoin_addr2rmd160(&checktype,rmd160,coinaddr);
        //if ( strcmp(checkaddr,coinaddr) != 0 )
        //    printf("checkaddr.(%s) vs coinaddr.(%s) %02x vs [%02x] memcmp.%d\n",checkaddr,coinaddr,addrtype,checktype,memcmp(rmd160,data+1,20));
    }
    return(coinaddr);
}

int32_t hush_is_issuer()
{
    if ( SMART_CHAIN_SYMBOL[0] != 0 && hush_baseid(SMART_CHAIN_SYMBOL) >= 0 )
        return(1);
    else return(0);
}

int32_t bitweight(uint64_t x)
{
    int i,wt = 0;
    for (i=0; i<64; i++)
        if ( (1LL << i) & x )
            wt++;
    return(wt);
}

int32_t _unhex(char c)
{
    if ( c >= '0' && c <= '9' )
        return(c - '0');
    else if ( c >= 'a' && c <= 'f' )
        return(c - 'a' + 10);
    else if ( c >= 'A' && c <= 'F' )
        return(c - 'A' + 10);
    return(-1);
}

int32_t is_hexstr(char *str,int32_t n)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return(0);
    for (i=0; str[i]!=0; i++)
    {
        if ( n > 0 && i >= n )
            break;
        if ( _unhex(str[i]) < 0 )
            break;
    }
    if ( n == 0 )
        return(i);
    return(i == n);
}

int32_t unhex(char c)
{
    int32_t hex;
    if ( (hex= _unhex(c)) < 0 )
    {
        fprintf(stderr,"unhex: illegal hexchar.(%c)\n",c);
    }
    return(hex);
}

unsigned char _decode_hex(char *hex) { return((unhex(hex[0])<<4) | unhex(hex[1])); }

int32_t decode_hex(uint8_t *bytes,int32_t n,char *hex)
{
    int32_t adjust,i = 0;
    //printf("decode.(%s)\n",hex);
    if ( is_hexstr(hex,n) <= 0 )
    {
        memset(bytes,0,n);
        return(n);
    }
    if ( hex[n-1] == '\n' || hex[n-1] == '\r' )
        hex[--n] = 0;
    if ( n == 0 || (hex[n*2+1] == 0 && hex[n*2] != 0) )
    {
        if ( n > 0 )
        {
            bytes[0] = unhex(hex[0]);
            printf("decode_hex n.%d hex[0] (%c) -> %d hex.(%s) [n*2+1: %d] [n*2: %d %c] len.%ld\n",n,hex[0],bytes[0],hex,hex[n*2+1],hex[n*2],hex[n*2],(long)strlen(hex));
        }
        bytes++;
        hex++;
        adjust = 1;
    } else adjust = 0;
    if ( n > 0 )
    {
        for (i=0; i<n; i++)
            bytes[i] = _decode_hex(&hex[i*2]);
    }
    //bytes[i] = 0;
    return(n + adjust);
}

char hexbyte(int32_t c)
{
    c &= 0xf;
    if ( c < 10 )
        return('0'+c);
    else if ( c < 16 )
        return('a'+c-10);
    else return(0);
}

int32_t init_hexbytes_noT(char *hexbytes,unsigned char *message,long len)
{
    int32_t i;
    if ( len <= 0 )
    {
        hexbytes[0] = 0;
        return(1);
    }
    for (i=0; i<len; i++)
    {
        hexbytes[i*2] = hexbyte((message[i]>>4) & 0xf);
        hexbytes[i*2 + 1] = hexbyte(message[i] & 0xf);
        //printf("i.%d (%02x) [%c%c]\n",i,message[i],hexbytes[i*2],hexbytes[i*2+1]);
    }
    hexbytes[len*2] = 0;
    //printf("len.%ld\n",len*2+1);
    return((int32_t)len*2+1);
}

char *bits256_str(char hexstr[65],bits256 x)
{
    init_hexbytes_noT(hexstr,x.bytes,sizeof(x));
    return(hexstr);
}

int32_t dragon_rwnum(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp)
{
    int32_t i; uint64_t x;
    if ( rwflag == 0 )
    {
        x = 0;
        for (i=len-1; i>=0; i--)
        {
            x <<= 8;
            x |= serialized[i];
        }
        switch ( len )
        {
            case 1: *(uint8_t *)endianedp = (uint8_t)x; break;
            case 2: *(uint16_t *)endianedp = (uint16_t)x; break;
            case 4: *(uint32_t *)endianedp = (uint32_t)x; break;
            case 8: *(uint64_t *)endianedp = (uint64_t)x; break;
        }
    } else {
        x = 0;
        switch ( len )
        {
            case 1: x = *(uint8_t *)endianedp; break;
            case 2: x = *(uint16_t *)endianedp; break;
            case 4: x = *(uint32_t *)endianedp; break;
            case 8: x = *(uint64_t *)endianedp; break;
        }
        for (i=0; i<len; i++,x >>= 8)
            serialized[i] = (uint8_t)(x & 0xff);
    }
    return(len);
}

int32_t dragon_rwbignum(int32_t rwflag,uint8_t *serialized,int32_t len,uint8_t *endianedp)
{
    int32_t i;
    if ( rwflag == 0 )
    {
        for (i=0; i<len; i++)
            endianedp[i] = serialized[i];
    }
    else
    {
        for (i=0; i<len; i++)
            serialized[i] = endianedp[i];
    }
    return(len);
}

int32_t hush_scriptitemlen(int32_t *opretlenp,uint8_t *script)
{
    int32_t opretlen,len = 0;
    if ( (opretlen= script[len++]) >= 0x4c )
    {
        if ( opretlen == 0x4c )
            opretlen = script[len++];
        else if ( opretlen == 0x4d )
        {
            opretlen = script[len] + (script[len+1] << 8);
            len += 2;
            //opretlen = script[len++];
            //opretlen = (opretlen << 8) | script[len++];
        }
    }
    *opretlenp = opretlen;
    return(len);
}

int32_t hush_opreturnscript(uint8_t *script,uint8_t type,uint8_t *opret,int32_t opretlen)
{
    int32_t offset = 0;
    script[offset++] = 0x6a;
    opretlen++;
    if ( opretlen >= 0x4c )
    {
        if ( opretlen > 0xff )
        {
            script[offset++] = 0x4d;
            script[offset++] = opretlen & 0xff;
            script[offset++] = (opretlen >> 8) & 0xff;
        }
        else
        {
            script[offset++] = 0x4c;
            script[offset++] = opretlen;
        }
    } else script[offset++] = opretlen;
    script[offset++] = type; // covered by opretlen
    memcpy(&script[offset],opret,opretlen-1);
    return(offset + opretlen - 1);
}

// get a pseudo random number that is the same for each block individually at all times and different
// from all other blocks. the sequence is extremely likely, but not guaranteed to be unique for each block chain
uint64_t hush_block_prg(uint32_t nHeight)
{
    int i;
    uint8_t hashSrc[8];
    uint64_t result=0, hashSrc64 = (uint64_t)ASSETCHAINS_MAGIC << 32 + nHeight;
    bits256 hashResult;

    for ( i = 0; i < sizeof(hashSrc); i++ )
    {
        hashSrc[i] = hashSrc64 & 0xff;
        hashSrc64 >>= 8;
        int8_t b = hashSrc[i];
    }

    vcalc_sha256(0, hashResult.bytes, hashSrc, sizeof(hashSrc));
    for ( i = 0; i < 8; i++ )
    {
        result = (result << 8) + hashResult.bytes[i];
    }
    return result;
}

// given a block height, this returns the unlock time for that block height, derived from
// the ASSETCHAINS_MAGIC number as well as the block height, providing different random numbers
// for corresponding blocks across chains, but the same sequence in each chain
int64_t hush_block_unlocktime(uint32_t nHeight)
{
    uint64_t fromTime, toTime, unlocktime;

    if ( ASSETCHAINS_TIMEUNLOCKFROM == ASSETCHAINS_TIMEUNLOCKTO )
        unlocktime = ASSETCHAINS_TIMEUNLOCKTO;
    else
    {
        unlocktime = hush_block_prg(nHeight) / (0xffffffffffffffff / ((ASSETCHAINS_TIMEUNLOCKTO - ASSETCHAINS_TIMEUNLOCKFROM) + 1));
        // boundary and power of 2 can make it exceed to time by 1
        unlocktime = unlocktime + ASSETCHAINS_TIMEUNLOCKFROM;
        if (unlocktime > ASSETCHAINS_TIMEUNLOCKTO)
            unlocktime--;
    }
    return ((int64_t)unlocktime);
}

long _stripwhite(char *buf,int accept)
{
    int32_t i,j,c;
    if ( buf == 0 || buf[0] == 0 )
        return(0);
    for (i=j=0; buf[i]!=0; i++)
    {
        buf[j] = c = buf[i];
        if ( c == accept || (c != ' ' && c != '\n' && c != '\r' && c != '\t' && c != '\b') )
            j++;
    }
    buf[j] = 0;
    return(j);
}

char *clonestr(char *str)
{
    char *clone;
    if ( str == 0 || str[0] == 0 )
    {
        printf("warning cloning nullstr.%p\n",str);
#ifdef __APPLE__
        while ( 1 ) sleep(1);
#endif
        str = (char *)"<nullstr>";
    }
    clone = (char *)malloc(strlen(str)+16);
    strcpy(clone,str);
    return(clone);
}

int32_t safecopy(char *dest,char *src,long len)
{
    int32_t i = -1;
    if ( src != 0 && dest != 0 && src != dest )
    {
        if ( dest != 0 )
            memset(dest,0,len);
        for (i=0; i<len&&src[i]!=0; i++)
            dest[i] = src[i];
        if ( i == len )
        {
            printf("safecopy: %s too long %ld\n",src,len);
#ifdef __APPLE__
            //getchar();
#endif
            return(-1);
        }
        dest[i] = 0;
    }
    return(i);
}

char *parse_conf_line(char *line,char *field)
{
    line += strlen(field);
    for (; *line!='='&&*line!=0; line++)
        break;
    if ( *line == 0 )
        return(0);
    if ( *line == '=' )
        line++;
    while ( line[strlen(line)-1] == '\r' || line[strlen(line)-1] == '\n' || line[strlen(line)-1] == ' ' )
        line[strlen(line)-1] = 0;
    //printf("LINE.(%s)\n",line);
    _stripwhite(line,0);
    return(clonestr(line));
}

double OS_milliseconds()
{
    struct timeval tv; double millis;
    gettimeofday(&tv,NULL);
    millis = ((double)tv.tv_sec * 1000. + (double)tv.tv_usec / 1000.);
    //printf("tv_sec.%ld usec.%d %f\n",tv.tv_sec,tv.tv_usec,millis);
    return(millis);
}

#ifndef _WIN32
void OS_randombytes(unsigned char *x,long xlen)
{
    static int fd = -1;
    int32_t i;
    if (fd == -1) {
        for (;;) {
            fd = open("/dev/urandom",O_RDONLY);
            if (fd != -1) break;
            sleep(1);
        }
    }
    while (xlen > 0) {
        if (xlen < 1048576) i = (int32_t)xlen; else i = 1048576;
        i = (int32_t)read(fd,x,i);
        if (i < 1) {
            sleep(1);
            continue;
        }
        if ( 0 )
        {
            int32_t j;
            for (j=0; j<i; j++)
                printf("%02x ",x[j]);
            printf("-> %p\n",x);
        }
        x += i;
        xlen -= i;
    }
}
#endif

void lock_queue(queue_t *queue)
{
    if ( queue->initflag == 0 )
    {
        portable_mutex_init(&queue->mutex);
        queue->initflag = 1;
    }
	portable_mutex_lock(&queue->mutex);
}

void queue_enqueue(char *name,queue_t *queue,struct queueitem *item)
{
    if ( queue->name[0] == 0 && name != 0 && name[0] != 0 )
        strcpy(queue->name,name);
    if ( item == 0 )
    {
        printf("FATAL type error: queueing empty value\n");
        return;
    }
    lock_queue(queue);
    DL_APPEND(queue->list,item);
    portable_mutex_unlock(&queue->mutex);
}

struct queueitem *queue_dequeue(queue_t *queue)
{
    struct queueitem *item = 0;
    lock_queue(queue);
    if ( queue->list != 0 )
    {
        item = queue->list;
        DL_DELETE(queue->list,item);
    }
	portable_mutex_unlock(&queue->mutex);
    return(item);
}

void *queue_delete(queue_t *queue,struct queueitem *copy,int32_t copysize)
{
    struct queueitem *item = 0;
    lock_queue(queue);
    if ( queue->list != 0 )
    {
        DL_FOREACH(queue->list,item)
        {
						#ifdef _WIN32
						if ( item == copy || (item->allocsize == copysize && memcmp((void *)((intptr_t)item + sizeof(struct queueitem)),(void *)((intptr_t)copy + sizeof(struct queueitem)),copysize) == 0) )
						#else
            if ( item == copy || (item->allocsize == copysize && memcmp((void *)((long)item + sizeof(struct queueitem)),(void *)((long)copy + sizeof(struct queueitem)),copysize) == 0) )
						#endif
            {
                DL_DELETE(queue->list,item);
                portable_mutex_unlock(&queue->mutex);
                printf("name.(%s) deleted item.%p list.%p\n",queue->name,item,queue->list);
                return(item);
            }
        }
    }
	portable_mutex_unlock(&queue->mutex);
    return(0);
}

void *queue_free(queue_t *queue)
{
    struct queueitem *item = 0;
    lock_queue(queue);
    if ( queue->list != 0 )
    {
        DL_FOREACH(queue->list,item)
        {
            DL_DELETE(queue->list,item);
            free(item);
        }
        //printf("name.(%s) dequeue.%p list.%p\n",queue->name,item,queue->list);
    }
	portable_mutex_unlock(&queue->mutex);
    return(0);
}

void *queue_clone(queue_t *clone,queue_t *queue,int32_t size)
{
    struct queueitem *ptr,*item = 0;
    lock_queue(queue);
    if ( queue->list != 0 )
    {
        DL_FOREACH(queue->list,item)
        {
            ptr = (struct queueitem *)calloc(1,sizeof(*ptr));
            memcpy(ptr,item,size);
            queue_enqueue(queue->name,clone,ptr);
        }
        //printf("name.(%s) dequeue.%p list.%p\n",queue->name,item,queue->list);
    }
	portable_mutex_unlock(&queue->mutex);
    return(0);
}

int32_t queue_size(queue_t *queue)
{
    int32_t count = 0;
    struct queueitem *tmp;
    lock_queue(queue);
    DL_COUNT(queue->list,tmp,count);
    portable_mutex_unlock(&queue->mutex);
	return count;
}

void dragon_initQ(queue_t *Q,char *name)
{
    struct queueitem *item,*I;
    memset(Q,0,sizeof(*Q));
    I = (struct queueitem *)calloc(1,sizeof(*I));
    strcpy(Q->name,name);
    queue_enqueue(name,Q,I);
    if ( (item= queue_dequeue(Q)) != 0 )
        free(item);
}

uint16_t _hush_userpass(char *username,char *password,FILE *fp)
{
    char *rpcuser,*rpcpassword,*str,line[8192]; uint16_t port = 0;
    rpcuser = rpcpassword = 0;
    username[0] = password[0] = 0;
    while ( fgets(line,sizeof(line),fp) != 0 )
    {
        if ( line[0] == '#' )
            continue;
        //printf("line.(%s) %p %p\n",line,strstr(line,(char *)"rpcuser"),strstr(line,(char *)"rpcpassword"));
        if ( (str= strstr(line,(char *)"rpcuser")) != 0 )
            rpcuser = parse_conf_line(str,(char *)"rpcuser");
        else if ( (str= strstr(line,(char *)"rpcpassword")) != 0 )
            rpcpassword = parse_conf_line(str,(char *)"rpcpassword");
        else if ( (str= strstr(line,(char *)"rpcport")) != 0 )
        {
            port = atoi(parse_conf_line(str,(char *)"rpcport"));
            //fprintf(stderr,"rpcport.%u in file\n",port);
        }
    }
    if ( rpcuser != 0 && rpcpassword != 0 )
    {
        strcpy(username,rpcuser);
        strcpy(password,rpcpassword);
    }
    //printf("rpcuser.(%s) rpcpassword.(%s) HUSHUSERPASS.(%s) %u\n",rpcuser,rpcpassword,HUSHUSERPASS,port);
    if ( rpcuser != 0 )
        free(rpcuser);
    if ( rpcpassword != 0 )
        free(rpcpassword);
    return(port);
}

void hush_statefname(char *fname,char *symbol,char *str)
{
    int32_t n,len;
    sprintf(fname,"%s",GetDataDir(false).string().c_str());
    if ( (n= (int32_t)strlen(SMART_CHAIN_SYMBOL)) != 0 )
    {
        len = (int32_t)strlen(fname);
        if ( strcmp(SMART_CHAIN_SYMBOL,&fname[len - n]) == 0 )
            fname[len - n] = 0;
        else
        {
            if ( strcmp(symbol,"REGTEST") != 0 )
                printf("unexpected fname.(%s) vs %s [%s] n.%d len.%d (%s)\n",fname,symbol,SMART_CHAIN_SYMBOL,n,len,&fname[len - n]);
            return;
        }
    } else {
#ifdef _WIN32
        strcat(fname,"\\");
#else
        strcat(fname,"/");
#endif
    }
    if ( symbol != 0 && symbol[0] != 0)
    {
        strcat(fname,symbol);
        //printf("statefname.(%s) -> (%s)\n",symbol,fname);
#ifdef _WIN32
        strcat(fname,"\\");
#else
        strcat(fname,"/");
#endif
    }
    strcat(fname,str);
    //printf("test.(%s) -> [%s] statename.(%s) %s\n",test,SMART_CHAIN_SYMBOL,symbol,fname);
}

void hush_configfile(char *symbol,uint16_t rpcport)
{
    static char myusername[512],mypassword[8192];
    FILE *fp; uint16_t hushport; uint8_t buf2[33]; char fname[512],buf[128],username[512],password[8192]; uint32_t crc,r,r2,i;
    if ( symbol != 0 && rpcport != 0 )
    {
        r = (uint32_t)time(NULL);
        r2 = OS_milliseconds();
        memcpy(buf,&r,sizeof(r));
        memcpy(&buf[sizeof(r)],&r2,sizeof(r2));
        memcpy(&buf[sizeof(r)+sizeof(r2)],symbol,strlen(symbol));
        crc = calc_crc32(0,(uint8_t *)buf,(int32_t)(sizeof(r)+sizeof(r2)+strlen(symbol)));
				#ifdef _WIN32
				randombytes_buf(buf2,sizeof(buf2));
				#else
        OS_randombytes(buf2,sizeof(buf2));
				#endif
        for (i=0; i<sizeof(buf2); i++)
            sprintf(&password[i*2],"%02x",buf2[i]);
        password[i*2] = 0;
        sprintf(buf,"%s.conf",symbol);
        BITCOIND_RPCPORT = rpcport;
#ifdef _WIN32
        sprintf(fname,"%s\\%s",GetDataDir(false).string().c_str(),buf);
#else
        sprintf(fname,"%s/%s",GetDataDir(false).string().c_str(),buf);
#endif
        if ( (fp= fopen(fname,"rb")) == 0 )
        {
#ifndef FROM_CLI
            if ( (fp= fopen(fname,"wb")) != 0 )
            {
                fprintf(fp,"rpcuser=user%u\nrpcpassword=pass%s\nrpcport=%u\nserver=1\ntxindex=1\nrpcworkqueue=4096\nrpcallowip=127.0.0.1\nrpcbind=127.0.0.1\n",crc,password,rpcport);
                fclose(fp);
                printf("Created (%s)\n",fname);
            } else printf("Couldnt create (%s)\n",fname);
#endif
        } else {
            _hush_userpass(myusername,mypassword,fp);
            mapArgs["-rpcpassword"] = mypassword;
            mapArgs["-rpcusername"] = myusername;
            //fprintf(stderr,"myusername.(%s)\n",myusername);
            fclose(fp);
        }
    }
    strcpy(fname,GetDataDir().string().c_str());
#ifdef _WIN32
    while ( fname[strlen(fname)-1] != '\\' )
        fname[strlen(fname)-1] = 0;
    strcat(fname,"HUSH3.conf");
#else
    while ( fname[strlen(fname)-1] != '/' )
        fname[strlen(fname)-1] = 0;
#ifdef __APPLE__
    strcat(fname,"HUSH3.conf");
#else
    strcat(fname,"HUSH3.conf");
#endif
#endif
    if ( (fp= fopen(fname,"rb")) != 0 )
    {
        if ( (hushport= _hush_userpass(username,password,fp)) != 0 )
            HUSH3_PORT = hushport;
        sprintf(HUSHUSERPASS,"%s:%s",username,password);
        fclose(fp);
        //printf("HUSH.(%s) -> userpass.(%s)\n",fname,HUSHUSERPASS);
    } else {
        printf("could not open.(%s)\n",fname);
    }
}

uint16_t hush_userpass(char *userpass,char *symbol)
{
    FILE *fp; uint16_t port = 0; char fname[512],username[512],password[512],confname[HUSH_SMART_CHAIN_MAXLEN];
    userpass[0] = 0;

    sprintf(confname,"%s.conf",symbol);

    hush_statefname(fname,symbol,confname);
    if ( (fp= fopen(fname,"rb")) != 0 )
    {
        port = _hush_userpass(username,password,fp);
        sprintf(userpass,"%s:%s",username,password);
        if ( strcmp(symbol,SMART_CHAIN_SYMBOL) == 0 )
            strcpy(ASSETCHAINS_USERPASS,userpass);
        fclose(fp);
    }
    return(port);
}

#define HUSH_MAGIC 0xd394d36e

uint32_t hush_smartmagic(char *symbol,uint64_t supply,uint8_t *extraptr,int32_t extralen)
{
    uint8_t buf[512]; uint32_t crc0=0; int32_t len = 0; bits256 hash;
    len = dragon_rwnum(1,&buf[len],sizeof(supply),(void *)&supply);
    strcpy((char *)&buf[len],symbol);
    len += strlen(symbol);
    if ( extraptr != 0 && extralen != 0 )
    {
        vcalc_sha256(0,hash.bytes,extraptr,extralen);
        crc0 = hash.uints[0];
        fprintf(stderr,"HUSH raw magic=");
        int32_t i; for (i=0; i<extralen; i++)
            fprintf(stderr,"%02x",extraptr[i]);
        fprintf(stderr," extralen=%d crc0=%x\n",extralen,crc0);
    }

    //TODO: why is this needed?
    bool ishush3 = strncmp(symbol, "HUSH3",5) == 0 ? true : false;
    if(ishush3) {
        return HUSH_MAGIC;
    } else {
        return(calc_crc32(crc0,buf,len));
    }
}

uint16_t hush_smartport(uint32_t magic,int32_t extralen)
{
    if(fDebug)
        fprintf(stderr,"%s: extralen=%d\n",__func__,extralen);

    if ( extralen == 0 )
        return(8000 + (magic % 7777));
    else return(16000 + (magic % 49500));
}

uint16_t hush_port(char *symbol,uint64_t supply,uint32_t *magicp,uint8_t *extraptr,int32_t extralen)
{
    if(fDebug)
        fprintf(stderr,"%s: extralen=%d\n",__func__,extralen);

    *magicp = hush_smartmagic(symbol,supply,extraptr,extralen);
    //if(fDebug)
        fprintf(stderr,"%s: extralen=%d, supply=%lu\n",__func__,extralen, supply);

    return(hush_smartport(*magicp,extralen));
}

int32_t hush_whoami(char *pubkeystr,int32_t height,uint32_t timestamp)
{
    int32_t i,notaryid;
    for (i=0; i<33; i++)
        sprintf(&pubkeystr[i<<1],"%02x",NOTARY_PUBKEY33[i]);
    pubkeystr[66] = 0;
    hush_chosennotary(&notaryid,height,NOTARY_PUBKEY33,timestamp);
    return(notaryid);
}

// Large total supplies lead to numerical errors, beware!
uint64_t hush_max_money()
{
    return hush_current_supply(10000000);
}

// This implements the Hush Emission Curve, the miner subsidy part,
// and must be kept in sync with hush_commision() in hush_bitcoind.h!
// Changing these functions are consensus changes!
// Here Be Dragons! -- Duke Leto
uint64_t hush_block_subsidy(int height)
{
    uint64_t subsidy = 0;
    int32_t HALVING1 = GetArg("-z2zheight",340000);
    //TODO: support INTERVAL :(
    //int32_t INTERVAL = GetArg("-ac_halving1",840000);
    int32_t TRANSITION = 128;

    if (height < TRANSITION) {
        if(fDebug)
            fprintf(stderr,"%s: setting subsidy=0 during transition at height=%d\n",__func__, height);
        subsidy = 0;
    } else {
        // Just like BTC, BRs in the far future will be slightly less than
        // they should be because exact values are not integers, causing
        // slightly less coins to be actually mined and small deviations
        // to the ideal FR/devtax
        if (height < HALVING1) { // before 1st Halving @ Block 340000 (Nov 2020)
            subsidy = 1125000000;
        } else if (height < 2020000 ) {
            subsidy = 281250000;
        } else if (height < 3700000 ) {
            subsidy = 140625000;
        } else if (height < 5380000 ) {
            subsidy = 70312500;
        } else if (height < 7060000 ) {
            subsidy = 35156250;
        } else if (height < 8740000 ) {
            subsidy = 17578125;
        } else if (height < 10420000) {
            subsidy = 8789062;
        } else if (height < 12100000) {
            subsidy = 4394531;
        } else if (height < 15460000) {
            subsidy = 2197265;
        } else if (height < 17140000) {
            subsidy = 1098632;
        } else if (height < 18820000) {
            subsidy = 549316;
        } else if (height < 23860000) {
            subsidy = 274658;
        } else if (height < 23860000) {
            subsidy = 137329;
        } else if (height < 25540000) {
            subsidy = 68664;
        } else if (height < 27220000) {
            subsidy = 34332;
        } else if (height < 27220000) {
            subsidy = 17166;
        } else if (height < 28900000) {
            subsidy = 8583;
        } else if (height < 30580000) {
            subsidy = 4291;
        } else if (height < 32260000) {
            subsidy = 2145;
        } else if (height < 33940000) {
            subsidy = 1072;
        } else if (height < 35620000) {
            subsidy = 536;
        } else if (height < 37300000) {
            subsidy = 268;
        } else if (height < 38980000) {
            subsidy = 134;
        } else if (height < 40660000) {
            subsidy = 67;
        } else if (height < 42340000) {
            subsidy = 33;
        } else if (height < 44020000) {
            subsidy = 16;
        } else if (height < 45700000) {
            subsidy = 8;
        } else if (height < 47380000) {
            subsidy = 4;
        } else if (height < 49060000) {
            subsidy = 2;
        } else if (height < 50740000) {
            subsidy = 1;
        } else {
            // HUSH Block Reward rounds down to 0 at Block 50740000 which is the 31st halving
            // because Bitcoin/Zcash/Hush internals don't support 0.5 sat block reward yet ;)
            subsidy = 0;
        }
    }
    if(fDebug)
        fprintf(stderr,"%s: subsidy=%lu at height=%d\n",__func__,subsidy,height);
    return subsidy;
}

// wrapper for more general supply curves of Hush Smart Chains
uint64_t hush_sc_block_subsidy(int nHeight)
{
    // Find current era, start from beginning reward, and determine current subsidy
    int64_t numerator, denominator, subsidy = 0;
    int64_t subsidyDifference;
    int32_t numhalvings = 0, curEra = 0, sign = 1;
    static uint64_t cached_subsidy; static int32_t cached_numhalvings; static int cached_era;
    bool ishush3 = strncmp(SMART_CHAIN_SYMBOL, "HUSH3",5) == 0 ? true : false;
    // fprintf(stderr,"%s: ht=%d ishush3=%d\n", __func__, nHeight, ishush3);

    // check for backwards compat, older chains with no explicit rewards had 0.0001 block reward
    if ( ASSETCHAINS_ENDSUBSIDY[0] == 0 && ASSETCHAINS_REWARD[0] == 0 ) {
        fprintf(stderr,"%s: defaulting to 0.0001 subsidy\n",__func__);
        subsidy = 10000;
    } else if ( (ASSETCHAINS_ENDSUBSIDY[0] == 0 && ASSETCHAINS_REWARD[0] != 0) || ASSETCHAINS_ENDSUBSIDY[0] != 0 ) {
        // if we have an end block in the first era, find our current era
        if ( ASSETCHAINS_ENDSUBSIDY[0] != 0 )
        {
            for ( curEra = 0; curEra <= ASSETCHAINS_LASTERA; curEra++ )
            {
                if ( ASSETCHAINS_ENDSUBSIDY[curEra] > nHeight || ASSETCHAINS_ENDSUBSIDY[curEra] == 0 )
                    break;
            }
        }

        if ( curEra <= ASSETCHAINS_LASTERA )
        {
            int64_t nStart = curEra ? ASSETCHAINS_ENDSUBSIDY[curEra - 1] : 0;
            subsidy = (int64_t)ASSETCHAINS_REWARD[curEra];
            if(fDebug)
                fprintf(stderr,"%s: nStart.%ld subsidy.%ld curEra.%d\n",__func__,nStart,subsidy,curEra);

            if ( subsidy || (curEra != ASSETCHAINS_LASTERA && ASSETCHAINS_REWARD[curEra + 1] != 0) )
            {
                if(fDebug) {
                    fprintf(stderr,"%s: subsidy=%ld at height=%d with ASSETCHAINS_HALVING[curEra]=%lu\n",__func__,subsidy,nHeight, ASSETCHAINS_HALVING[curEra]);
                }
                if ( ASSETCHAINS_HALVING[curEra] != 0 )
                {
                    if (ishush3) {
                        subsidy = hush_block_subsidy(nHeight);
                        if(fDebug)
                            fprintf(stderr,"%s: HUSH3 subsidy=%ld at height=%d\n",__func__,subsidy,nHeight);
                    } else if ( (numhalvings = ((nHeight - nStart) / ASSETCHAINS_HALVING[curEra])) > 0 ) {
                        // The code below is not compatible with HUSH3 mainnet
                        if ( ASSETCHAINS_DECAY[curEra] == 0 ) {
                            subsidy >>= numhalvings;
                            // fprintf(stderr,"%s: no decay, numhalvings.%d curEra.%d subsidy.%ld nStart.%ld\n",__func__, numhalvings, curEra, subsidy, nStart);
                        } else if ( ASSETCHAINS_DECAY[curEra] == 100000000 && ASSETCHAINS_ENDSUBSIDY[curEra] != 0 ) {
                            if ( curEra == ASSETCHAINS_LASTERA )
                            {
                                subsidyDifference = subsidy;
                            } else {
                                // Ex: -ac_eras=3 -ac_reward=0,384,24 -ac_end=1440,260640,0 -ac_halving=1,1440,2103840 -ac_decay 100000000,97750000,0
                                subsidyDifference = subsidy - ASSETCHAINS_REWARD[curEra + 1];
                                if (subsidyDifference < 0)
                                {
                                    sign = -1;
                                    subsidyDifference *= sign;
                                }
                            }
                            denominator = ASSETCHAINS_ENDSUBSIDY[curEra] - nStart;
                            numerator = denominator - ((ASSETCHAINS_ENDSUBSIDY[curEra] - nHeight) + ((nHeight - nStart) % ASSETCHAINS_HALVING[curEra]));
                            // fprintf(stderr,"%s: numerator=%ld , denominator=%ld at height=%d\n",__func__,numerator, denominator,nHeight);
                            if( denominator ) {
                                subsidy = subsidy - sign * ((subsidyDifference * numerator) / denominator);
                            } else {
                                fprintf(stderr,"%s: invalid denominator=%ld !\n",  __func__, denominator);
                                fprintf(stderr,"%s: defaulting to 0.0001 subsidy\n",__func__);
                                subsidy = 10000;
                            }
                        } else {
                            if ( cached_subsidy > 0 && cached_era == curEra && cached_numhalvings == numhalvings ) {
                                subsidy = cached_subsidy;
                            } else {
                                for (int i=0; i < numhalvings && subsidy != 0; i++)
                                    subsidy = (subsidy * ASSETCHAINS_DECAY[curEra]) / 100000000;
                                cached_subsidy = subsidy;
                                cached_numhalvings = numhalvings;
                                cached_era = curEra;
                            }
                        }
                    }
                }
            }
        } else {
            fprintf(stderr,"%s: curEra.%d > lastEra.%lu\n", __func__, curEra, ASSETCHAINS_LASTERA);
        }
    }
    uint32_t magicExtra = ASSETCHAINS_STAKED ? ASSETCHAINS_MAGIC : (ASSETCHAINS_MAGIC & 0xffffff);
    if ( ASSETCHAINS_SUPPLY > 10000000000 ) // over 10 billion?
    {
        fprintf(stderr,"%s: Detected supply over 10 billion, danger zone!\n",__func__);
        if ( nHeight <= ASSETCHAINS_SUPPLY/1000000000 )
        {
            subsidy += (uint64_t)1000000000 * COIN;
            if ( nHeight == 1 )
                subsidy += (ASSETCHAINS_SUPPLY % 1000000000)*COIN + magicExtra;
        }
    } else if ( nHeight == 1 ) {
        if ( ASSETCHAINS_LASTERA == 0 )
            subsidy = ASSETCHAINS_SUPPLY * SATOSHIDEN + magicExtra;
        else
            subsidy += ASSETCHAINS_SUPPLY * SATOSHIDEN + magicExtra;
    }
    if(fDebug)
        fprintf(stderr,"%s: ht.%d curEra.%d lastEra.%lu subsidy.%ld magicExtra.%u\n",__func__,nHeight,curEra,ASSETCHAINS_LASTERA,subsidy,magicExtra);
    return(subsidy);
}

extern int64_t MAX_MONEY;
void hush_cbopretupdate(int32_t forceflag);
void SplitStr(const std::string& strVal, std::vector<std::string> &outVals);

int8_t equihash_params_possible(uint64_t n, uint64_t k)
{
    /* To add more of these you also need to edit:
    * equihash.cpp very end of file with the tempate to point to the new param numbers 
    * equihash.h
    *  line 210/217 (declaration of equihash class)
    * Add this object to the following functions: 
    *  EhInitialiseState 
    *  EhBasicSolve
    *  EhOptimisedSolve
    *  EhIsValidSolution
    * Alternatively change ASSETCHAINS_N and ASSETCHAINS_K in hush_nk.h for fast testing.
    */
    if ( k == 9 && (n == 200 || n == 210) )
        return(0);
    if ( k == 5 && (n == 150 || n == 144 || n == 96 || n == 48) )
        return(0);
    if ( k == ASSETCHAINS_K && n == ASSETCHAINS_N)
        return(0);
    return(-1);
}

void hush_args(char *argv0)
{
    std::string name,addn,hexstr,symbol; char *dirname,fname[512],arg0str[64],magicstr[9]; uint8_t magic[4],extrabuf[32756],disablebits[32],*extraptr=0;
    FILE *fp; uint64_t val; uint16_t port; int32_t i,nonz=0,baseid,len,n,extralen = 0; uint64_t ccenables[256], ccEnablesHeight[512] = {0}; CTransaction earlytx; uint256 hashBlock;

    IS_HUSH_NOTARY = GetBoolArg("-notary", false);
    HUSH_NSPV = GetArg("-nSPV",0);
    memset(ccenables,0,sizeof(ccenables));
    memset(disablebits,0,sizeof(disablebits));
    memset(ccEnablesHeight,0,sizeof(ccEnablesHeight));

    if ( GetBoolArg("-gen", false) != 0 )
    {
        HUSH_MININGTHREADS = GetArg("-genproclimit",-1);
    }
    DONATION_PUBKEY   = GetArg("-donation", "");
    NOTARY_PUBKEY     = GetArg("-pubkey", "");
    HUSH_DEALERNODE   = GetArg("-dealer",0);
    HUSH_TESTNODE     = GetArg("-testnode",0);

    if ( strlen(NOTARY_PUBKEY.c_str()) == 66 )
    {
        decode_hex(NOTARY_PUBKEY33,33,(char *)NOTARY_PUBKEY.c_str());
        USE_EXTERNAL_PUBKEY = 1;
        if ( IS_HUSH_NOTARY == 0 )
        {
            // We dont have any chain data yet, so use system clock to guess.
            // I think on season change should recommend notaries to use -notary to avoid needing this.
            int32_t hush_season = getacseason(time(NULL));
            for (i=0; i<64; i++)
            {
                if ( strcmp(NOTARY_PUBKEY.c_str(),notaries_list[hush_season-1][i][1]) == 0 )
                {
                    IS_HUSH_NOTARY     = 1;
                    HUSH_MININGTHREADS = 1;
                    mapArgs ["-genproclimit"] = itostr(HUSH_MININGTHREADS);
                    fprintf(stderr,"running as notary.%d %s\n",i,notaries_list[hush_season-1][i][0]);
                    break;
                }
            }
        }
    }


	name = GetArg("-ac_name","HUSH3");
    fprintf(stderr,".oO Starting %s Full Node (Extreme Privacy!) with genproc=%d notary=%d\n",name.c_str(),HUSH_MININGTHREADS, IS_HUSH_NOTARY);

vector<string> HUSH_nodes= {"3456789.234567.is"};
    vector<string> more_nodes = mapMultiArgs["-addnode"];
    if (more_nodes.size() > 0) {
        fprintf(stderr,"%s: Adding %lu more nodes via custom -addnode arguments\n", __func__, more_nodes.size() );
    }
    // Add default HUSH nodes after custom addnodes
    more_nodes.insert( more_nodes.end(), HUSH_nodes.begin(), HUSH_nodes.end() );

    mapMultiArgs["-addnode"] = more_nodes;
    HUSH_STOPAT              = GetArg("-stopat",0);
    MAX_REORG_LENGTH         = GetArg("-maxreorg",MAX_REORG_LENGTH);
    WITNESS_CACHE_SIZE       = MAX_REORG_LENGTH+10;
    ASSETCHAINS_CC           = GetArg("-ac_cc",0);
    HUSH_CCACTIVATE          = GetArg("-ac_ccactivate",0);
    ASSETCHAINS_BLOCKTIME    = GetArg("-ac_blocktime",60);
    // We do not support ac_public=1 chains, Hush is a platform for privacy
    ASSETCHAINS_PUBLIC       = 0;
    ASSETCHAINS_PRIVATE      = GetArg("-ac_private",0);
    HUSH_SNAPSHOT_INTERVAL   = GetArg("-ac_snapshot",0);
    Split(GetArg("-ac_nk",""), sizeof(ASSETCHAINS_NK)/sizeof(*ASSETCHAINS_NK), ASSETCHAINS_NK, 0);

    
    // -ac_ccactivateht=evalcode,height,evalcode,height,evalcode,height....
    Split(GetArg("-ac_ccactivateht",""), sizeof(ccEnablesHeight)/sizeof(*ccEnablesHeight), ccEnablesHeight, 0);
    // fill map with all eval codes and activation height of 0.
    for ( int i = 0; i < 256; i++ )
        mapHeightEvalActivate[i] = 0;
    for ( int i = 0; i < 512; i++ )
    {
        int32_t ecode = ccEnablesHeight[i];
        int32_t ht = ccEnablesHeight[i+1];
        if ( i > 1 && ccEnablesHeight[i-2] == ecode )
            break;
        if ( ecode > 255 || ecode < 0 )
            fprintf(stderr, "ac_ccactivateht: invalid evalcode.%i must be between 0 and 256.\n", ecode);
        else if ( ht > 0 )
        {
            // update global map. 
            mapHeightEvalActivate[ecode] = ht;
            fprintf(stderr, "ac_ccactivateht: ecode.%i activates at height.%i\n", ecode, mapHeightEvalActivate[ecode]);
        }
        i++;
    }
    
    if ( (HUSH_REWIND= GetArg("-rewind",0)) != 0 )
    {
        printf("HUSH_REWIND %d\n",HUSH_REWIND);
    }
    HUSH_EARLYTXID = Parseuint256(GetArg("-earlytxid","0").c_str());    
    ASSETCHAINS_EARLYTXIDCONTRACT = GetArg("-ac_earlytxidcontract",0);
    if ( name.c_str()[0] != 0 )
    {
        std::string selectedAlgo = GetArg("-ac_algo", std::string(ASSETCHAINS_ALGORITHMS[0]));

        for ( int i = 0; i < ASSETCHAINS_NUMALGOS; i++ )
        {
            if (std::string(ASSETCHAINS_ALGORITHMS[i]) == selectedAlgo)
            {
                ASSETCHAINS_ALGO = i;
                STAKING_MIN_DIFF = ASSETCHAINS_MINDIFF[i];
                // only worth mentioning if it's not equihash
                if (ASSETCHAINS_ALGO != ASSETCHAINS_EQUIHASH)
                    printf("ASSETCHAINS_ALGO, algorithm set to %s\n", selectedAlgo.c_str());
                break;
            }
        }
        if ( ASSETCHAINS_ALGO == ASSETCHAINS_EQUIHASH && ASSETCHAINS_NK[0] != 0 && ASSETCHAINS_NK[1] != 0 )
        {
            if ( equihash_params_possible(ASSETCHAINS_NK[0], ASSETCHAINS_NK[1]) == -1 ) 
            {
                printf("equihash values N.%li and K.%li are not currently available\n", ASSETCHAINS_NK[0], ASSETCHAINS_NK[1]);
                exit(0);
            } else printf("ASSETCHAINS_ALGO, algorithm set to equihash with N.%li and K.%li\n", ASSETCHAINS_NK[0], ASSETCHAINS_NK[1]);
        }
        if (i == ASSETCHAINS_NUMALGOS)
        {
            printf("ASSETCHAINS_ALGO, %s not supported. using equihash\n", selectedAlgo.c_str());
        }

        // Set our symbol from -ac_name value
        strncpy(SMART_CHAIN_SYMBOL,name.c_str(),sizeof(SMART_CHAIN_SYMBOL)-1);
        bool ishush3 = strncmp(SMART_CHAIN_SYMBOL, "HUSH3",5) == 0 ? true : false;

        ASSETCHAINS_LASTERA = GetArg("-ac_eras", 1);
        if(ishush3) {
            ASSETCHAINS_LASTERA = 3;
        }
        if ( ASSETCHAINS_LASTERA < 1 || ASSETCHAINS_LASTERA > ASSETCHAINS_MAX_ERAS )
        {
            ASSETCHAINS_LASTERA = 1;
            printf("ASSETCHAINS_LASTERA, if specified, must be between 1 and %u. ASSETCHAINS_LASTERA set to %lu\n", ASSETCHAINS_MAX_ERAS, ASSETCHAINS_LASTERA);
        }
        ASSETCHAINS_LASTERA -= 1;
        if(fDebug)
            fprintf(stderr,"%s: lastEra=%lu maxEras=%d\n", __func__, ASSETCHAINS_LASTERA, ASSETCHAINS_MAX_ERAS);

        ASSETCHAINS_TIMELOCKGTE = (uint64_t)GetArg("-ac_timelockgte", _ASSETCHAINS_TIMELOCKOFF);
        ASSETCHAINS_TIMEUNLOCKFROM = GetArg("-ac_timeunlockfrom", 0);
        ASSETCHAINS_TIMEUNLOCKTO = GetArg("-ac_timeunlockto", 0);
        if ( ASSETCHAINS_TIMEUNLOCKFROM > ASSETCHAINS_TIMEUNLOCKTO )
        {
            printf("ASSETCHAINS_TIMELOCKGTE - must specify valid ac_timeunlockfrom and ac_timeunlockto\n");
            ASSETCHAINS_TIMELOCKGTE    = _ASSETCHAINS_TIMELOCKOFF;
            ASSETCHAINS_TIMEUNLOCKFROM = ASSETCHAINS_TIMEUNLOCKTO = 0;
        }

        Split(GetArg("-ac_end",""), sizeof(ASSETCHAINS_ENDSUBSIDY)/sizeof(*ASSETCHAINS_ENDSUBSIDY),  ASSETCHAINS_ENDSUBSIDY, 0);
        Split(GetArg("-ac_halving",""), sizeof(ASSETCHAINS_HALVING)/sizeof(*ASSETCHAINS_HALVING),  ASSETCHAINS_HALVING, 0);
        Split(GetArg("-ac_reward",""), sizeof(ASSETCHAINS_REWARD)/sizeof(*ASSETCHAINS_REWARD),  ASSETCHAINS_REWARD, 0);

        MAX_BLOCK_SIGOPS            = 60000;
        ASSETCHAINS_TXPOW           = GetArg("-ac_txpow",0) & 3;
        ASSETCHAINS_FOUNDERS        = GetArg("-ac_founders",0);// & 1;
		ASSETCHAINS_FOUNDERS_REWARD = GetArg("-ac_founders_reward",0);
        ASSETCHAINS_SUPPLY          = GetArg("-ac_supply",10);
        ASSETCHAINS_COMMISSION      = GetArg("-ac_perc",0);
        ASSETCHAINS_OVERRIDE_PUBKEY = GetArg("-ac_pubkey","");
        ASSETCHAINS_SCRIPTPUB       = GetArg("-ac_script","");
        

        fprintf(stderr,"%s: Setting custom %s reward HUSH3=%d reward,halving,subsidy chain values...\n",__func__, SMART_CHAIN_SYMBOL, ishush3);
        if(ishush3) {
            // Migrated from hushd script
            ASSETCHAINS_CC           = 2;
            ASSETCHAINS_BLOCKTIME    = 150; // this will change to 75 at the correct block
            ASSETCHAINS_COMMISSION   = 11111111;
            // 6250000 - (Sprout pool at block 500,000)
            ASSETCHAINS_SUPPLY       = 6178674;
            ASSETCHAINS_FOUNDERS     = 1;
            ASSETCHAINS_SAPLING      = 1;
            // this corresponds to FR address RHushEyeDm7XwtaTWtyCbjGQumYyV8vMjn
            ASSETCHAINS_SCRIPTPUB       = "76a9145eb10cf64f2bab1b457f1f25e658526155928fac88ac";
            // we do not want to change the magic of HUSH3 mainnet so we do not call devtax_scriptpub_for_height() here,
            // instead we call it whenever ASSETCHAINS_SCRIPTPUB is used later on

            // Over-ride HUSH3 values from CLI params. Changing our blocktime to 75s changes things
            ASSETCHAINS_REWARD[0]     = 0;
            ASSETCHAINS_REWARD[1]     = 1125000000;
            ASSETCHAINS_REWARD[2]     = 281250000; // 2.8125  HUSH goes to miners per block after 1st halving at Block 340K
            ASSETCHAINS_REWARD[3]     = 140625000; // 1.40625 HUSH after 2nd halving at Block 2020000
            ASSETCHAINS_HALVING[0]    = 129;
            ASSETCHAINS_HALVING[1]    = GetArg("-z2zheight",340000);
            ASSETCHAINS_HALVING[2]    = 2020000; // 2020000 = 340000 + 1680000 (1st halving block plus new halving interval)
            ASSETCHAINS_HALVING[3]    = 3700000; // ASSETCHAINS_HALVING[2] + 1680000;
            ASSETCHAINS_ENDSUBSIDY[0] = 129;
            ASSETCHAINS_ENDSUBSIDY[1] = GetArg("-z2zheight",340000);
            ASSETCHAINS_ENDSUBSIDY[2] = 2*5422111; // TODO: Fix this, twice the previous end of rewards is an estimate
        }
        Split(GetArg("-ac_decay",""), sizeof(ASSETCHAINS_DECAY)/sizeof(*ASSETCHAINS_DECAY),  ASSETCHAINS_DECAY, 0);
        Split(GetArg("-ac_notarypay",""), sizeof(ASSETCHAINS_NOTARY_PAY)/sizeof(*ASSETCHAINS_NOTARY_PAY),  ASSETCHAINS_NOTARY_PAY, 0);

        for ( int i = 0; i < ASSETCHAINS_MAX_ERAS; i++ )
        {
            if ( ASSETCHAINS_DECAY[i] == 100000000 && ASSETCHAINS_ENDSUBSIDY == 0 )
            {
                ASSETCHAINS_DECAY[i] = 0;
                printf("ERA%u: ASSETCHAINS_DECAY of 100000000 means linear and that needs ASSETCHAINS_ENDSUBSIDY\n", i);
            }
            else if ( ASSETCHAINS_DECAY[i] > 100000000 )
            {
                ASSETCHAINS_DECAY[i] = 0;
                printf("ERA%u: ASSETCHAINS_DECAY cant be more than 100000000\n", i);
            }
        }

        if ( ASSETCHAINS_SUPPLY > (uint64_t)90*1000*1000000 )
        {
            fprintf(stderr,"-ac_supply must be less than 90 billion, derpz\n");
            StartShutdown();
        }
        if(fDebug)
            fprintf(stderr,"ASSETCHAINS_SUPPLY %llu\n",(long long)ASSETCHAINS_SUPPLY);
        
        ASSETCHAINS_BEAMPORT        = GetArg("-ac_beam",0);
        ASSETCHAINS_CODAPORT        = GetArg("-ac_coda",0);
        ASSETCHAINS_CBOPRET         = GetArg("-ac_cbopret",0);
        ASSETCHAINS_CBMATURITY      = GetArg("-ac_cbmaturity",0);
        ASSETCHAINS_ADAPTIVEPOW     = GetArg("-ac_adaptivepow",0);
        if(fDebug)
            fprintf(stderr,"ASSETCHAINS_CBOPRET.%llx\n",(long long)ASSETCHAINS_CBOPRET);
        if ( ASSETCHAINS_CBOPRET != 0 ) {
            SplitStr(GetArg("-ac_prices",""),  ASSETCHAINS_PRICES);
            if ( ASSETCHAINS_PRICES.size() > 0 )
                ASSETCHAINS_CBOPRET |= 4;
            SplitStr(GetArg("-ac_stocks",""),  ASSETCHAINS_STOCKS);
            if ( ASSETCHAINS_STOCKS.size() > 0 )
                ASSETCHAINS_CBOPRET |= 8;
            for (i=0; i<ASSETCHAINS_PRICES.size(); i++)
                fprintf(stderr,"%s ",ASSETCHAINS_PRICES[i].c_str());
            fprintf(stderr,"%d -ac_prices\n",(int32_t)ASSETCHAINS_PRICES.size());
            for (i=0; i<ASSETCHAINS_STOCKS.size(); i++)
                fprintf(stderr,"%s ",ASSETCHAINS_STOCKS[i].c_str());
            fprintf(stderr,"%d -ac_stocks\n",(int32_t)ASSETCHAINS_STOCKS.size());
        }
        hexstr = GetArg("-ac_mineropret","");
        if ( hexstr.size() != 0 )
        {
            Mineropret.resize(hexstr.size()/2);
            decode_hex(Mineropret.data(),hexstr.size()/2,(char *)hexstr.c_str());
            for (i=0; i<Mineropret.size(); i++)
                fprintf(stderr,"%02x",Mineropret[i]);
            fprintf(stderr," Mineropret\n");
        }
        if ( ASSETCHAINS_COMMISSION != 0 && ASSETCHAINS_FOUNDERS_REWARD != 0 )
        {
            fprintf(stderr,"cannot use founders reward and commission on the same chain.\n");
            StartShutdown();
        }
        if ( ASSETCHAINS_CC != 0 )
        {
            uint8_t prevCCi = 0;
            ASSETCHAINS_CCLIB = GetArg("-ac_cclib","hush3");

            // these are the enabled CCs on HUSH3 mainnet
            Split(GetArg("-ac_ccenable","228,234,235,236,241"), sizeof(ccenables)/sizeof(*ccenables),  ccenables, 0);
            for (i=nonz=0; i<0x100; i++)
            {
                if ( ccenables[i] != prevCCi && ccenables[i] != 0 )
                {
                    nonz++;
                    prevCCi = ccenables[i];
                    fprintf(stderr,"%d ",(uint8_t)(ccenables[i] & 0xff));
                }
            }
            fprintf(stderr,"nonz.%d ccenables[]\n",nonz);
            if ( nonz > 0 )
            {
                for (i=0; i<256; i++)
                {
                    ASSETCHAINS_CCDISABLES[i] = 1;
                    SETBIT(disablebits,i);
                }
                for (i=0; i<nonz; i++)
                {
                    CLEARBIT(disablebits,(ccenables[i] & 0xff));
                    ASSETCHAINS_CCDISABLES[ccenables[i] & 0xff] = 0;
                }
                CLEARBIT(disablebits,0);
            }
            /*if ( ASSETCHAINS_CCLIB.size() > 0 )
            {
                for (i=first; i<=last; i++)
                {
                    CLEARBIT(disablebits,i);
                    ASSETCHAINS_CCDISABLES[i] = 0;
                }
            }*/
        }
        if ( ASSETCHAINS_BEAMPORT != 0 )
        {
            fprintf(stderr,"can only have one of -ac_beam or -ac_coda\n");
            StartShutdown();
        }
        ASSETCHAINS_SELFIMPORT = GetArg("-ac_import",""); // BEAM, CODA, PUBKEY, GATEWAY
        if ( ASSETCHAINS_SELFIMPORT == "PUBKEY" )
        {
            if ( strlen(ASSETCHAINS_OVERRIDE_PUBKEY.c_str()) != 66 )
            {
                fprintf(stderr,"invalid -ac_pubkey for -ac_import=PUBKEY\n");
                StartShutdown();
            }
        }
        else if ( ASSETCHAINS_SELFIMPORT == "BEAM" )
        {
            if (ASSETCHAINS_BEAMPORT == 0)
            {
                fprintf(stderr,"missing -ac_beam for BEAM rpcport\n");
                StartShutdown();
            }
        }
        else if ( ASSETCHAINS_SELFIMPORT == "CODA" )
        {
            if (ASSETCHAINS_CODAPORT == 0)
            {
                fprintf(stderr,"missing -ac_coda for CODA rpcport\n");
                StartShutdown();
            }
        }
        else if ( ASSETCHAINS_SELFIMPORT == "PEGSCC")
        {
            Split(GetArg("-ac_pegsccparams",""), sizeof(ASSETCHAINS_PEGSCCPARAMS)/sizeof(*ASSETCHAINS_PEGSCCPARAMS), ASSETCHAINS_PEGSCCPARAMS, 0);
            if (ASSETCHAINS_ENDSUBSIDY[0]!=1 || ASSETCHAINS_COMMISSION!=0)
            {
                fprintf(stderr,"when using import for pegsCC these must be set: -ac_end=1 -ac_perc=0\n");
                StartShutdown();
            }
        }
        // else it can be gateway coin
        else if (!ASSETCHAINS_SELFIMPORT.empty() && (ASSETCHAINS_ENDSUBSIDY[0]!=1 || ASSETCHAINS_SUPPLY>0 || ASSETCHAINS_COMMISSION!=0))
        {
            fprintf(stderr,"when using gateway import these must be set: -ac_end=1 -ac_supply=0 -ac_perc=0\n");
            StartShutdown();
        }
        
        // HUSH will always be The First Pure Sapling Coin, no Sprout JoinSplits in our history! ;)
        ASSETCHAINS_SAPLING = GetArg("-ac_sapling", 1);
        if (ASSETCHAINS_SAPLING == -1)
        {
            ASSETCHAINS_OVERWINTER = GetArg("-ac_overwinter", -1);
        } else {
            ASSETCHAINS_OVERWINTER = GetArg("-ac_overwinter", ASSETCHAINS_SAPLING);
        }
        if ( strlen(ASSETCHAINS_OVERRIDE_PUBKEY.c_str()) == 66 || ASSETCHAINS_SCRIPTPUB.size() > 1 )
        {
            if ( ASSETCHAINS_SUPPLY > 10000000000 )
            {
                printf("ac_pubkey or ac_script wont work with ac_supply over 10 billion\n");
                StartShutdown();
            }
            if ( ASSETCHAINS_NOTARY_PAY[0] != 0 )
            {
                printf("Assetchains NOTARY PAY cannot be used with ac_pubkey or ac_script.\n");
                StartShutdown();
            }
            if ( strlen(ASSETCHAINS_OVERRIDE_PUBKEY.c_str()) == 66 )
            {
                decode_hex(ASSETCHAINS_OVERRIDE_PUBKEY33,33,(char *)ASSETCHAINS_OVERRIDE_PUBKEY.c_str());
                calc_rmd160_sha256(ASSETCHAINS_OVERRIDE_PUBKEYHASH,ASSETCHAINS_OVERRIDE_PUBKEY33,33);
            }
            if ( ASSETCHAINS_COMMISSION == 0 && ASSETCHAINS_FOUNDERS != 0 )
            {
                if ( ASSETCHAINS_FOUNDERS_REWARD == 0 )
                {
                    ASSETCHAINS_COMMISSION = 53846154; // maps to 35%
                    printf("ASSETCHAINS_COMMISSION defaulted to 35%% when founders reward active\n");
                } else {
                    printf("ASSETCHAINS_FOUNDERS_REWARD set to %ld\n", ASSETCHAINS_FOUNDERS_REWARD);
                }
                /*else if ( ASSETCHAINS_SELFIMPORT.size() == 0 )
                {
                    //ASSETCHAINS_OVERRIDE_PUBKEY.clear();
                    printf("-ac_perc must be set with -ac_pubkey\n");
                }*/
            }
        } else {
            if ( ASSETCHAINS_COMMISSION != 0 )
            {
                ASSETCHAINS_COMMISSION = 0;
                printf("ASSETCHAINS_COMMISSION needs an ASSETCHAINS_OVERRIDE_PUBKEY and cant be more than 100000000 (100%%)\n");
            }
            if ( ASSETCHAINS_FOUNDERS != 0 )
            {
                ASSETCHAINS_FOUNDERS = 0;
                printf("ASSETCHAINS_FOUNDERS needs an ASSETCHAINS_OVERRIDE_PUBKEY or ASSETCHAINS_SCRIPTPUB\n");
            }
        }

        if ( ASSETCHAINS_ENDSUBSIDY[0] != 0 || ASSETCHAINS_REWARD[0] != 0 || ASSETCHAINS_HALVING[0] != 0 || ASSETCHAINS_DECAY[0] != 0 || ASSETCHAINS_COMMISSION != 0 || ASSETCHAINS_PUBLIC != 0 || ASSETCHAINS_PRIVATE != 0 || ASSETCHAINS_TXPOW != 0 || ASSETCHAINS_FOUNDERS != 0 || ASSETCHAINS_SCRIPTPUB.size() > 1 || ASSETCHAINS_SELFIMPORT.size() > 0 || ASSETCHAINS_OVERRIDE_PUBKEY33[0] != 0 || ASSETCHAINS_TIMELOCKGTE != _ASSETCHAINS_TIMELOCKOFF|| ASSETCHAINS_ALGO != ASSETCHAINS_EQUIHASH || ASSETCHAINS_LWMAPOS != 0 || ASSETCHAINS_LASTERA > 0 || ASSETCHAINS_BEAMPORT != 0 || ASSETCHAINS_CODAPORT != 0 || ASSETCHAINS_MARMARA != 0 || nonz > 0 || ASSETCHAINS_CCLIB.size() > 0 || ASSETCHAINS_FOUNDERS_REWARD != 0 || ASSETCHAINS_NOTARY_PAY[0] != 0 || ASSETCHAINS_BLOCKTIME != 60 || ASSETCHAINS_CBOPRET != 0 || Mineropret.size() != 0 || (ASSETCHAINS_NK[0] != 0 && ASSETCHAINS_NK[1] != 0) || HUSH_SNAPSHOT_INTERVAL != 0 || ASSETCHAINS_EARLYTXIDCONTRACT != 0 || ASSETCHAINS_CBMATURITY != 0 || ASSETCHAINS_ADAPTIVEPOW != 0 )
        {
            if(fDebug)
                fprintf(stderr,"perc %.4f%% ac_pub=[%02x%02x%02x...] acsize.%d\n",dstr(ASSETCHAINS_COMMISSION)*100,ASSETCHAINS_OVERRIDE_PUBKEY33[0],ASSETCHAINS_OVERRIDE_PUBKEY33[1],ASSETCHAINS_OVERRIDE_PUBKEY33[2],(int32_t)ASSETCHAINS_SCRIPTPUB.size());
            extraptr = extrabuf;
            memcpy(extraptr,ASSETCHAINS_OVERRIDE_PUBKEY33,33), extralen = 33;

            // if we have one era, this should create the same data structure as it used to, same if we increase _MAX_ERAS
            for ( int i = 0; i <= ASSETCHAINS_LASTERA; i++ )
            {
                if (fDebug) {
                    printf("ERA%u: end.%llu reward.%llu halving.%llu decay.%llu notarypay.%llu\n", i,
                       (long long)ASSETCHAINS_ENDSUBSIDY[i],
                       (long long)ASSETCHAINS_REWARD[i],
                       (long long)ASSETCHAINS_HALVING[i],
                       (long long)ASSETCHAINS_DECAY[i],
                       (long long)ASSETCHAINS_NOTARY_PAY[i]);
                }

                // TODO: Verify that we don't overrun extrabuf here, which is a 32KB byte buffer
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_ENDSUBSIDY[i]),(void *)&ASSETCHAINS_ENDSUBSIDY[i]);
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_REWARD[i]),(void *)&ASSETCHAINS_REWARD[i]);
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_HALVING[i]),(void *)&ASSETCHAINS_HALVING[i]);
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_DECAY[i]),(void *)&ASSETCHAINS_DECAY[i]);
                if ( ASSETCHAINS_NOTARY_PAY[0] != 0 )
                    extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_NOTARY_PAY[i]),(void *)&ASSETCHAINS_NOTARY_PAY[i]);
            }

            if (ASSETCHAINS_LASTERA > 0)
            {
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_LASTERA),(void *)&ASSETCHAINS_LASTERA);
            }

            // hash in lock above for time locked coinbase transactions above a certain reward value only if the lock above
            // param was specified, otherwise, for compatibility, do nothing
            if ( ASSETCHAINS_TIMELOCKGTE != _ASSETCHAINS_TIMELOCKOFF )
            {
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_TIMELOCKGTE),(void *)&ASSETCHAINS_TIMELOCKGTE);
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_TIMEUNLOCKFROM),(void *)&ASSETCHAINS_TIMEUNLOCKFROM);
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_TIMEUNLOCKTO),(void *)&ASSETCHAINS_TIMEUNLOCKTO);
            }

            if ( ASSETCHAINS_ALGO != ASSETCHAINS_EQUIHASH )
            {
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_ALGO),(void *)&ASSETCHAINS_ALGO);
            }

            if ( ASSETCHAINS_LWMAPOS != 0 )
            {
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_LWMAPOS),(void *)&ASSETCHAINS_LWMAPOS);
            }

            val = ASSETCHAINS_COMMISSION | (((int64_t)ASSETCHAINS_STAKED & 0xff) << 32) | (((uint64_t)ASSETCHAINS_CC & 0xffff) << 40) | ((ASSETCHAINS_PUBLIC != 0) << 7) | ((ASSETCHAINS_PRIVATE != 0) << 6) | ASSETCHAINS_TXPOW;
            extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(val),(void *)&val);
            
            if ( ASSETCHAINS_FOUNDERS != 0 )
            {
                uint8_t tmp = 1;
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(tmp),(void *)&tmp);
                if ( ASSETCHAINS_FOUNDERS > 1 )
                    extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_FOUNDERS),(void *)&ASSETCHAINS_FOUNDERS);
                // NOTE: Hush does not use this, we use -ac_script to implement our FR -- Duke
                if ( ASSETCHAINS_FOUNDERS_REWARD != 0 )
                {
                    fprintf(stderr, "set founders reward.%lld\n",(long long)ASSETCHAINS_FOUNDERS_REWARD);
                    extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_FOUNDERS_REWARD),(void *)&ASSETCHAINS_FOUNDERS_REWARD);
                }
            }
            if ( ASSETCHAINS_SCRIPTPUB.size() > 1 )
            {
                decode_hex(&extraptr[extralen],ASSETCHAINS_SCRIPTPUB.size()/2,(char *)ASSETCHAINS_SCRIPTPUB.c_str());
                extralen += ASSETCHAINS_SCRIPTPUB.size()/2;
                //extralen += dragon_rwnum(1,&extraptr[extralen],(int32_t)ASSETCHAINS_SCRIPTPUB.size(),(void *)ASSETCHAINS_SCRIPTPUB.c_str());
                fprintf(stderr,"append ac_script %s\n",ASSETCHAINS_SCRIPTPUB.c_str());
            }
            if ( ASSETCHAINS_SELFIMPORT.size() > 0 )
            {
                memcpy(&extraptr[extralen],(char *)ASSETCHAINS_SELFIMPORT.c_str(),ASSETCHAINS_SELFIMPORT.size());
                for (i=0; i<ASSETCHAINS_SELFIMPORT.size(); i++)
                    fprintf(stderr,"%c",extraptr[extralen+i]);
                fprintf(stderr," selfimport\n");
                extralen += ASSETCHAINS_SELFIMPORT.size();
            }
            if ( ASSETCHAINS_BEAMPORT != 0 )
                extraptr[extralen++] = 'b';
            if ( ASSETCHAINS_CODAPORT != 0 )
                extraptr[extralen++] = 'c';
            if ( ASSETCHAINS_MARMARA != 0 )
                extraptr[extralen++] = ASSETCHAINS_MARMARA;

            fprintf(stderr,"extralen.%d before disable bits\n",extralen);

            if ( nonz > 0 ) {
                memcpy(&extraptr[extralen],disablebits,sizeof(disablebits));
                extralen += sizeof(disablebits);
            }
            if ( ASSETCHAINS_CCLIB.size() > 1 )
            {
                for (i=0; i<ASSETCHAINS_CCLIB.size(); i++)
                {
                    extraptr[extralen++] = ASSETCHAINS_CCLIB[i];
                    fprintf(stderr,"%c",ASSETCHAINS_CCLIB[i]);
                }
                fprintf(stderr," <- CCLIB name\n");
            }

            if ( ASSETCHAINS_BLOCKTIME != 60 ) {
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_BLOCKTIME),(void *)&ASSETCHAINS_BLOCKTIME);
                fprintf(stderr,"%s: ASSETCHAINS_BLOCKTIME=%d, extralen=%d\n", __func__, ASSETCHAINS_BLOCKTIME, extralen);
            }

            if ( Mineropret.size() != 0 )
            {
                for (i=0; i<Mineropret.size(); i++)
                    extraptr[extralen++] = Mineropret[i];
            }
            if ( ASSETCHAINS_CBOPRET != 0 )
            {
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_CBOPRET),(void *)&ASSETCHAINS_CBOPRET);
                if ( ASSETCHAINS_PRICES.size() != 0 )
                {
                    for (i=0; i<ASSETCHAINS_PRICES.size(); i++)
                    {
                        symbol = ASSETCHAINS_PRICES[i];
                        memcpy(&extraptr[extralen],(char *)symbol.c_str(),symbol.size());
                        extralen += symbol.size();
                    }
                }
                if ( ASSETCHAINS_STOCKS.size() != 0 )
                {
                    for (i=0; i<ASSETCHAINS_STOCKS.size(); i++)
                    {
                        symbol = ASSETCHAINS_STOCKS[i];
                        memcpy(&extraptr[extralen],(char *)symbol.c_str(),symbol.size());
                        extralen += symbol.size();
                    }
                }
                //hush_pricesinit();
                hush_cbopretupdate(1); // will set Mineropret
                fprintf(stderr,"This blockchain uses data produced from CoinDesk Bitcoin Price Index\n");
            }
            if ( ASSETCHAINS_NK[0] != 0 && ASSETCHAINS_NK[1] != 0 )
            {
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_NK[0]),(void *)&ASSETCHAINS_NK[0]);
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_NK[1]),(void *)&ASSETCHAINS_NK[1]);
            }
            if ( HUSH_SNAPSHOT_INTERVAL != 0 )
            {
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(HUSH_SNAPSHOT_INTERVAL),(void *)&HUSH_SNAPSHOT_INTERVAL);
            }
            if ( ASSETCHAINS_EARLYTXIDCONTRACT != 0 )
            {
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_EARLYTXIDCONTRACT),(void *)&ASSETCHAINS_EARLYTXIDCONTRACT);
            }
            if ( ASSETCHAINS_CBMATURITY != 0 )
            {
                extralen += dragon_rwnum(1,&extraptr[extralen],sizeof(ASSETCHAINS_CBMATURITY),(void *)&ASSETCHAINS_CBMATURITY);
            }
            if ( ASSETCHAINS_ADAPTIVEPOW != 0 )
                extraptr[extralen++] = ASSETCHAINS_ADAPTIVEPOW;
        }
        
        addn = GetArg("-seednode","");
        if ( strlen(addn.c_str()) > 0 )
            ASSETCHAINS_SEED = 1;

        MAX_MONEY = hush_max_money();

        if ( (baseid = hush_baseid(SMART_CHAIN_SYMBOL)) >= 0 && baseid < 32 )
        {
            if(fDebug) 
                printf("baseid.%d MAX_MONEY.%s %.8f\n",baseid,SMART_CHAIN_SYMBOL,(double)MAX_MONEY/SATOSHIDEN);
        }

        if ( ASSETCHAINS_CC >= HUSH_FIRSTFUNGIBLEID && MAX_MONEY < 1000000LL*SATOSHIDEN )
            MAX_MONEY = 1000000LL*SATOSHIDEN;
        if ( HUSH_BIT63SET(MAX_MONEY) != 0 )
            MAX_MONEY = HUSH_MAXNVALUE;
        if(fDebug)
            fprintf(stderr,"MAX_MONEY %llu %.8f\n",(long long)MAX_MONEY,(double)MAX_MONEY/SATOSHIDEN);
        //printf("baseid.%d MAX_MONEY.%s %.8f\n",baseid,SMART_CHAIN_SYMBOL,(double)MAX_MONEY/SATOSHIDEN);
        uint16_t tmpport = hush_port(SMART_CHAIN_SYMBOL,ASSETCHAINS_SUPPLY,&ASSETCHAINS_MAGIC,extraptr,extralen);
        if ( GetArg("-port",0) != 0 )
        {
            ASSETCHAINS_P2PPORT = GetArg("-port",0);
            if(ishush3) {
                fprintf(stderr,"set HUSH3 p2pport.%u\n",ASSETCHAINS_P2PPORT);
                ASSETCHAINS_P2PPORT = 18030;
            }
        if(fDebug)
            fprintf(stderr,"set p2pport.%u\n",ASSETCHAINS_P2PPORT);
        } else ASSETCHAINS_P2PPORT = tmpport;

        while ( (dirname= (char *)GetDataDir(false).string().c_str()) == 0 || dirname[0] == 0 )
        {
            fprintf(stderr,"waiting for datadir (%s)\n",dirname);
#ifndef _WIN32
            sleep(3);
#else
            boost::this_thread::sleep(boost::posix_time::milliseconds(3000));
#endif
        }
        //fprintf(stderr,"Got datadir.(%s)\n",dirname);
        if ( SMART_CHAIN_SYMBOL[0] != 0 )
        {
            int32_t hush_baseid(char *origbase);
            extern int COINBASE_MATURITY;
            if ( (port= hush_userpass(ASSETCHAINS_USERPASS,SMART_CHAIN_SYMBOL)) != 0 )
                ASSETCHAINS_RPCPORT = port;
            else hush_configfile(SMART_CHAIN_SYMBOL,ASSETCHAINS_P2PPORT + 1);

            if (ASSETCHAINS_CBMATURITY != 0)
                COINBASE_MATURITY = ASSETCHAINS_CBMATURITY;
            else if (ASSETCHAINS_LASTERA == 0)
                COINBASE_MATURITY = 1;
            if (COINBASE_MATURITY < 1)
            {
                fprintf(stderr,"ac_cbmaturity must be >0, shutting down\n");
                StartShutdown();
            }
            //fprintf(stderr,"ASSETCHAINS_RPCPORT (%s) %u\n",SMART_CHAIN_SYMBOL,ASSETCHAINS_RPCPORT);
        }
        if ( ASSETCHAINS_RPCPORT == 0 )
            ASSETCHAINS_RPCPORT = ASSETCHAINS_P2PPORT + 1;
        //ASSETCHAINS_NOTARIES = GetArg("-ac_notaries","");
        //hush_assetchain_pubkeys((char *)ASSETCHAINS_NOTARIES.c_str());
        dragon_rwnum(1,magic,sizeof(ASSETCHAINS_MAGIC),(void *)&ASSETCHAINS_MAGIC);
        for (i=0; i<4; i++)
            sprintf(&magicstr[i<<1],"%02x",magic[i]);
        magicstr[8] = 0;

        if ( ASSETCHAINS_CC < 2 )
        {
            if ( HUSH_CCACTIVATE != 0 )
            {
                ASSETCHAINS_CC = 2;
                fprintf(stderr,"smart utxo CC contracts will activate at height.%d\n",HUSH_CCACTIVATE);
            } else if ( ccEnablesHeight[0] != 0 ) {
                ASSETCHAINS_CC = 2;
                fprintf(stderr,"smart utxo CC contract %d will activate at height.%d\n",(int32_t)ccEnablesHeight[0],(int32_t)ccEnablesHeight[1]);
            }
        }
    } else {
        char fname[512],username[512],password[4096]; int32_t iter; FILE *fp;
        ASSETCHAINS_P2PPORT = 7770;
        ASSETCHAINS_RPCPORT = 7771;
        for (iter=0; iter<2; iter++)
        {
            strcpy(fname,GetDataDir().string().c_str());
#ifdef _WIN32
            while ( fname[strlen(fname)-1] != '\\' )
                fname[strlen(fname)-1] = 0;
            if ( iter == 0 )
                strcat(fname,"Hush\\HUSH3\\HUSH3.conf");
            else strcat(fname,"Bitcoin\\bitcoin.conf");
#else
            while ( fname[strlen(fname)-1] != '/' )
                fname[strlen(fname)-1] = 0;
#ifdef __APPLE__
            if ( iter == 0 )
                strcat(fname,"Hush/HUSH3/HUSH3.conf");
            else strcat(fname,"Bitcoin/Bitcoin.conf");
#else
            if ( iter == 0 )
                strcat(fname,".hush/HUSH3/HUSH3.conf");
            else strcat(fname,".bitcoin/bitcoin.conf");
#endif
#endif
            if ( (fp= fopen(fname,"rb")) != 0 )
            {
                _hush_userpass(username,password,fp);
                sprintf(iter == 0 ? HUSHUSERPASS : BTCUSERPASS,"%s:%s",username,password);
                fclose(fp);
                //printf("HUSH.(%s) -> userpass.(%s)\n",fname,HUSHUSERPASS);
            } //else printf("couldnt open.(%s)\n",fname);
            if ( IS_HUSH_NOTARY == 0 )
                break;
        }
    }
    int32_t dpowconfs = HUSH_DPOWCONFS;
    if ( SMART_CHAIN_SYMBOL[0] != 0 )
    {
        BITCOIND_RPCPORT = GetArg("-rpcport", ASSETCHAINS_RPCPORT);
        //fprintf(stderr,"(%s) port.%u chain params initialized\n",SMART_CHAIN_SYMBOL,BITCOIND_RPCPORT);

        // Set custom cc rulse for chains here
        if ( strcmp("HUSH3",SMART_CHAIN_SYMBOL) == 0 ) {
            // Disable all CC's
            if(GetArg("-ac_disable_cc",false)) {
                CCDISABLEALL;
            }
        }
    } else BITCOIND_RPCPORT = GetArg("-rpcport", BaseParams().RPCPort());
    HUSH_DPOWCONFS = GetArg("-dpowconfs",dpowconfs);
}

void hush_nameset(char *symbol,char *dest,char *source)
{
    if ( source[0] == 0 ) {
        strcpy(symbol,(char *)"HUSH3");
        strcpy(dest,(char *)"BTC");
    } else {
        strcpy(symbol,source);
        strcpy(dest,(char *)"HUSH3");
    }
}

struct hush_state *hush_stateptrget(char *base)
{
    int32_t baseid;
    if ( base == 0 || base[0] == 0 ) {
        return(&HUSH_STATES[33]);
    } else if ( (baseid= hush_baseid(base)) >= 0 ) {
        return(&HUSH_STATES[baseid+1]);
    } else {
        return(&HUSH_STATES[0]);
    }
}

struct hush_state *hush_stateptr(char *symbol,char *dest)
{
    int32_t baseid;
    hush_nameset(symbol,dest,SMART_CHAIN_SYMBOL);
    return(hush_stateptrget(symbol));
}

void hush_prefetch(FILE *fp)
{
    long fsize,fpos; int32_t incr = 16*1024*1024;
    fpos = ftell(fp);
    fseek(fp,0,SEEK_END);
    fsize = ftell(fp);
    if ( fsize > incr )
    {
        char *ignore = (char *)malloc(incr);
        if ( ignore != 0 )
        {
            rewind(fp);
            while ( fread(ignore,1,incr,fp) == incr ) // prefetch
                fprintf(stderr,".");
            free(ignore);
        }
    }
    fseek(fp,fpos,SEEK_SET);
}
