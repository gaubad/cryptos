/*
 * ============================================================================
 *  File: hmac.c
 *
 *  Description:
 *      This implements the HMAC-SHA256 for a single memory block and multiple
 *      different memory blocks. 
 * 
 *      This implementation is provided as a reference and has not undergone
 *      formal cryptographic validation.
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

#include "crypto.h"
#include "common.h"

#define  HMAC_INNER_BLOCK_SIZE      64
#define  HMAC_OUTPUT_BLOCK_SIZE     32

//////////////////////////////////////////////////////////////////////////
/// @brief - This implements the HMAC-SHA256 for a single memory block
/// @param msg -  Message on which mac needs to be calculated
/// @param msg_size - Size of the message
/// @param key - Key for Mac computation
/// @param key_size - Key size - Should be 32 or 64 bytes
/// @param hmac - HMAc output
/// @return - Success, Fail
////////////////////////////////////////////////////////////////////////// 
int32_t hmac_sha256(const uint8_t* msg, const uint32_t msg_size, 
                    const uint8_t* key, const uint8_t key_size, uint8_t* hmac)
{
    // Inner and outer pad constants
    uint8_t ipad = 0x36;
    uint8_t opad = 0x5C;

    uint8_t k0[HMAC_INNER_BLOCK_SIZE] = {0};
    uint8_t si[HMAC_INNER_BLOCK_SIZE] = {0};
    uint8_t so[HMAC_INNER_BLOCK_SIZE] = {0};

    uint8_t inner_digest[HMAC_OUTPUT_BLOCK_SIZE] = {0};
 
    sha256_ctx ctx;

    // Key size must be exactly 32 or 64 bytes (design constraint)                   
    if ( (hmac == NULL) || (key == NULL) || (msg == NULL) ||
            ( (key_size != 32U) && (key_size != 64U) ) )
    {
        return -1;
    }
    // Key size 32 or 64 - (if 32, rest should be 00s)
    cmn_memcpy(k0, key, key_size);

    // Mask key using ipad and opad to generate inner and outer keys
    for (uint8_t i = 0; i < 64; i++)
    {
        si[i] = k0[i] ^ ipad;
        so[i] = k0[i] ^ opad;
    }

    // Inner hash
    sha256_init(&ctx);
    sha256_update(&ctx, si, HMAC_INNER_BLOCK_SIZE);
    sha256_update(&ctx, msg, msg_size);
    sha256_finish(&ctx, inner_digest);

    // Outer hash
    sha256_init(&ctx);
    sha256_update(&ctx, so, HMAC_INNER_BLOCK_SIZE);
    sha256_update(&ctx, inner_digest, HMAC_OUTPUT_BLOCK_SIZE);
    sha256_finish(&ctx, hmac);

    // Clear internal arrays to avoid any leakage
    cmn_memset(k0, 0, sizeof(k0));
    cmn_memset(si, 0, sizeof(si));
    cmn_memset(so, 0, sizeof(so));
    cmn_memset(inner_digest, 0, sizeof(inner_digest));

    return 0;
}

//////////////////////////////////////////////////////
/// @brief 
/// @param key - Key for Mac computation
/// @param key_size - Key size - Should be 32 or 64 bytes
/// @param buffers - Buffers on which Mac need to be computed
/// @param num_buffers - Number of Buffers 
/// @param hmac - HMAC Output
/// @return - Success, Fail
//////////////////////////////////////////////////////// 
int32_t hmac_sha256_multi(const uint8_t *key, uint8_t key_size,
                          const hmac_multi_buf_t *buffers, uint32_t num_buffers, uint8_t *hmac)
{

    // Inner and outer pad constants
    uint8_t ipad = 0x36;
    uint8_t opad = 0x5C;

    uint8_t k0[HMAC_INNER_BLOCK_SIZE] = {0};
    uint8_t si[HMAC_INNER_BLOCK_SIZE] = {0};
    uint8_t so[HMAC_INNER_BLOCK_SIZE] = {0};

    uint8_t inner_digest[HMAC_OUTPUT_BLOCK_SIZE] = {0};
 
    sha256_ctx ctx;
    uint32_t i, j;

    // Validate inputs
    if ( (key == NULL) || (buffers == NULL) || (hmac == NULL) ||
            ( (key_size != 32U) && (key_size != 64U) ) )
    {
        return -1;
    }
    
    // k0 - paddedwith 00s already, in case key size is 32
    cmn_memcpy(k0, key, key_size); 

    // prepare inner and outer padded keys 
    for (i = 0; i < HMAC_INNER_BLOCK_SIZE; i++) 
    {
        si[i] = k0[i] ^ ipad;
        so[i] = k0[i] ^ opad;
    }

    // Inner hash over all buffers 
    sha256_init(&ctx);
    sha256_update(&ctx, si, HMAC_INNER_BLOCK_SIZE);

    for (i = 0; i < num_buffers; i++) 
    {
        if ((buffers[i].data != NULL) && (buffers[i].length > 0)) 
        {
            sha256_update(&ctx, buffers[i].data, buffers[i].length);
        }
    }
    sha256_finish(&ctx, inner_digest);

    // Outer hash 
    sha256_init(&ctx);
    sha256_update(&ctx, so, HMAC_INNER_BLOCK_SIZE);
    sha256_update(&ctx, inner_digest, HMAC_OUTPUT_BLOCK_SIZE);
    sha256_finish(&ctx, hmac);

    // Clear internal arrays to avoid any leakage
    cmn_memset(k0, 0, sizeof(k0));
    cmn_memset(si, 0, sizeof(si));
    cmn_memset(so, 0, sizeof(so));
    cmn_memset(inner_digest, 0, sizeof(inner_digest));

    return 0;
}

