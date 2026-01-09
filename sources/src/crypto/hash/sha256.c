/*
 * ============================================================================
 *  File: SHA256.c
 *
 *  Description:
 *      Basic SHA256 implementatin
 *
 *  Copyright (c) 2026 Deepak Gauba
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * ============================================================================
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"

// SHA-256 constants - first 32 bits of the fractional parts of cube-roots of primes
static const uint32_t k[64] = 
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Rotate and shift macros
#define ROTR(x,n) ((x >> n) | (x << (32-n)))
#define SHR(x,n)  (x >> n)

// SHA-256 functions
#define CH(x,y,z)  ((x & y) ^ (~x & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define BSIG0(x)   (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define BSIG1(x)   (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SSIG0(x)   (ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3))
#define SSIG1(x)   (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))

// Process a 512 bit block
static void sha256_transform(sha256_ctx *ctx, const uint8_t data[64]) 
{

    uint32_t w[64], a,b,c,d,e,f,g,h,t1,t2;

    for (uint32_t i = 0; i < 16; i++) 
    {
        w[i] = (data[i*4]<<24) | (data[i*4+1]<<16) | (data[i*4+2]<<8) | data[i*4+3];
    }

    for (uint32_t i = 16; i < 64; i++) 
    {
        w[i] = SSIG1(w[i-2]) + w[i-7] + SSIG0(w[i-15]) + w[i-16];
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (uint32_t i = 0; i < 64; i++) 
    {
        t1 = h + BSIG1(e) + CH(e,f,g) + k[i] + w[i];
        t2 = BSIG0(a) + MAJ(a,b,c);
        h = g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;

    return;
}

// Initial SHA-256 hash values - first 32 bits of square roots of primes
int32_t sha256_init(sha256_ctx *ctx) 
{
    if (ctx == NULL)
    {
        return -1;
    }

    ctx->bitlen = 0;
    ctx->buffer_len = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;

    return 0;
}


// Update SHA-256 with arbitrary data (can be called multiple times)
int32_t sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) 
{
    size_t offset = 0;

    if ( (ctx == NULL) || (len == 0) )
    {
        // No change in the conext
        return 0;
    }

    ctx->bitlen += len * 8;   
    while (len > 0) 
    {
        size_t to_copy = 64 - ctx->buffer_len;
        if (to_copy > len) 
        {
            to_copy = len;
        }
        
        memcpy(ctx->buffer + ctx->buffer_len, data + offset, to_copy);
        ctx->buffer_len += to_copy;
        offset += to_copy;
        len -= to_copy;

        if (ctx->buffer_len == 64) 
        {
            sha256_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }

    return 0;
}

// Finalize SHA-256, produce 32-byte hash
void sha256_finish(sha256_ctx *ctx, uint8_t hash[32]) 
{
    if ( (ctx == NULL) || (hash == NULL) )
    {        
        return;
    }

    size_t i = ctx->buffer_len;
    ctx->buffer[i++] = 0x80;

    if (i > 56) 
    {
        while (i < 64) 
        {
            ctx->buffer[i++] = 0;
        }
        sha256_transform(ctx, ctx->buffer);
        i = 0;
    }

    while (i<56) 
    {
        ctx->buffer[i++] = 0;
    }

    // append length in bits
    uint64_t bitlen_be = ctx->bitlen;
    for (int32_t j = 7 ; j >= 0; j--) 
    {
        ctx->buffer[i++] = (bitlen_be >> (j*8)) & 0xff;
    }

    sha256_transform(ctx, ctx->buffer);

    // convert state to big endian
    for (i = 0; i < 8; i++) 
    {
        hash[i*4]   = (ctx->state[i] >> 24) & 0xff;
        hash[i*4+1] = (ctx->state[i] >> 16) & 0xff;
        hash[i*4+2] = (ctx->state[i] >> 8) & 0xff;
        hash[i*4+3] = (ctx->state[i]) & 0xff;
    }

    return;
}


// Complete Hash - All data in one go
int32_t sha256_hash(const uint8_t* msg, const uint32_t msg_size, uint8_t* hash)
{
    if (hash == NULL)
    {
        return -1;
    }
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, msg, msg_size);
    sha256_finish(&ctx, hash);
    
    return 0;
}



