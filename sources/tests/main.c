/*
 * ============================================================================
 *  File: main.c
 *
 *  Description:
 *      This is the entry and test code for reference implementation of a 
 *      hash-based AEAD construction using HMAC-SHA256 for encryption and 
 *      authentication.
 *
 *  Copyright (c) 2026 Deepak Gauba
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * ============================================================================
 */

#include <stdio.h>
#include "crypto.h"
#include "stdint.h"
#include <stddef.h>
#include "hmac_aead.h"


#define ASSERT(cond, msg) \
    do { if (!(cond)) { printf("FAIL: %s\n", msg); return -1; } } while (0)

#define BLOCK_SIZE 64
#define TAG_SIZE   32

#define MAX_MSG_LENGTH  1024
#define MAX_AAD_LENGTH  256


// Test Master key - 32 bytes
static const uint8_t master_key[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
};

//////////////////////////////////////
// Verify the HMAc-AEAD outputs
//////////////////////////////////////
static size_t expected_ciphertext_len(size_t msg_len)
{
    size_t rem = msg_len % BLOCK_SIZE;

    if (rem <= 48) {
        return msg_len + (BLOCK_SIZE - rem);
    } else {
        /* Pad to block + add one full length block */
        return msg_len + (BLOCK_SIZE - rem) + BLOCK_SIZE;
    }
}

//////////////////////////////////////////
// Run HMAC-AEAD Tests
/////////////////////////////////////////
static int run_test_case(size_t msg_len, size_t aad_len)
{
    uint8_t msg[MAX_MSG_LENGTH];
    uint8_t aad[MAX_AAD_LENGTH];
    uint8_t ciphertext[MAX_MSG_LENGTH + 80];
    uint8_t decrypted[MAX_MSG_LENGTH];
    uint8_t iv[SIZE_IV];
    uint8_t tag[SIZE_TAG];

    size_t ct_len = 0;
    size_t dec_len = 0;

    for (size_t i = 0; i < msg_len; i++) 
    {
        msg[i] = (uint8_t)(i & 0xFF);
    }

    for (size_t i = 0; i < aad_len; i++)
    {  
        aad[i] = (uint8_t)(0xA0 + i);
    }

    printf("Test: msg_len=%zu, aad_len=%zu\n", msg_len, aad_len);

  
    ASSERT(hmac_aead_enc(
        msg, msg_len,
        aad, aad_len,        
        master_key,
        ciphertext, sizeof(ciphertext),
        &ct_len,
        iv, tag) == HMAC_ENC_OK, "Encryption failed \n");

    ASSERT( (ct_len + aad_len) == expected_ciphertext_len(msg_len + aad_len),
           "Unexpected ciphertext length");

    ASSERT(hmac_aead_dec(
        ciphertext, ct_len,
        aad, aad_len,        
        tag,
        master_key,
        iv,
        decrypted,
        &dec_len) == HMAC_ENC_OK, "Decryption failed \n");

    ASSERT(dec_len == msg_len, "Decrypted length mismatch");
    ASSERT(memcmp(msg, decrypted, msg_len) == 0, "Plaintext mismatch");    

    // --- Tamper ciphertext --- 
    ciphertext[0] ^= 0x01;
    ASSERT(hmac_aead_dec(
        ciphertext, ct_len,
        aad, aad_len,        
        tag,
        master_key,
        iv,
        decrypted,
        &dec_len) == HMAC_ENC_AUTH_VERIFY_FAILED,
        "Ciphertext tampering not detected \n");
    ciphertext[0] ^= 0x01;

    // --- Tamper tag --- 
    tag[0] ^= 0x01;
    ASSERT(hmac_aead_dec(
        ciphertext, ct_len,
        aad, aad_len,        
        tag,
        master_key,
        iv,
        decrypted,
        &dec_len) == HMAC_ENC_AUTH_VERIFY_FAILED,
        "Tag tampering not detected \n");
    tag[0] ^= 0x01;

    // --- Tamper AAD --- 
    aad[0] ^= 0x01;
    ASSERT(hmac_aead_dec(
        ciphertext, ct_len,
        aad, aad_len,        
        tag,
        master_key,
        iv,
        decrypted,
        &dec_len) == HMAC_ENC_AUTH_VERIFY_FAILED,
        "AAD tampering not detected \n");  

    printf("Passed\n\n");  
    return 0;
}

/////////////////////////////////////////////////
// Enrty point for HMAC AEAD and Crypto tests
////////////////////////////////////////////////
int main() 
{
    printf("***** Starting HMAC AEAD Tests ******** \n\n");

    run_test_case(48, 16);
    run_test_case(55, 30);
    run_test_case(64, 64);
    run_test_case(260, 128);
    run_test_case(1024, 35);

    printf("******Done******\n\n");

    /*

    // Tests for SHA256 and HMAC 
    uint8_t data_to_be_hashed[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                                      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
                                      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                                      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                                    };

    uint8_t hmac_key[32]          = { 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,                                
                                      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                                      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                                    };
                                    
    // Hash result    
    uint8_t hash_value[32] = {0};
    // Get Hash of the test data
    sha256_hash( data_to_be_hashed, 32, hash_value);

    // hashed output 
    printf("SHA256 hash = ");
    for (uint8_t i = 0; i < 32; i++) 
    {
        printf("%02x", hash_value[i]);
    }
    printf("\n\n\n");


    // Get HMAC of the test data
    hmac_sha256(data_to_be_hashed, 32, hmac_key, 32, hash_value);
  

    // hashed output 
    printf("HMAC = ");
    for (uint8_t i = 0; i < 32; i++) 
    {
        printf("%02x", hash_value[i]);
    }
    printf("\n\n\n");
    */

    return 0;
}

