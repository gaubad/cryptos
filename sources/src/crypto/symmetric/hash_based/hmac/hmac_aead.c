/*
 * ============================================================================
 *  File: hmac_aead.c
 *
 *  Description:
 *      Reference implementation of a hash-based AEAD construction using
 *      HMAC-SHA256 for encryption and authentication.
 *
 *      This module is intended for embedded systems with constrained resources
 *      and limited cryptographic hardware support. The design prioritizes
 *      simplicity, clear key separation, and deterministic behavior suitable
 *      for security evaluation and analysis.
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
#include "hmac_aead.h"
#include "crypto.h"
#include "common.h"

#define SIZE_LENGTH_BLOCK           8

#define SIZE_B_ENC                  64
#define SIZE_B_AUTH                 64
#define SIZE_IV                     64

#define SIZE_HALF_IV                (SIZE_IV / 2)

#define SIZE_HMAC_INPUT_BLOCK       64
#define SIZE_HMAC_OUTPUT_BLOCK      32

// Key sizes
#define SIZE_PRK                    32
#define SIZE_ENC_KEY                32
#define SIZE_AUTH_KEY               32

#define SIZE_ENC_DEC_KEY            32

#define SIZE_SHA256_OUTPUT_BLOCK    32
#define SIZE_SHA256_INPUT_BLOCK     64

#define SIZE_KEY_STREAM_BLOCK       SIZE_SHA256_OUTPUT_BLOCK 
#define SIZE_TAG                    SIZE_SHA256_OUTPUT_BLOCK

#define MAX_MULTI_HMAC_BUFS         7

//////////////////////////////////////////////////////////////////////////////////////
/// @brief - Derive key Derivation data for Encryption and Authentication. The 
///          key derivation data is derived from 512 bit IV. This makes sure the 
///          domain separation between encryption and authetication.
/// @param iv - 512 bit IV
/// @param b_enc - 512 bit key derivation data for encryption key derivation
/// @param b_auth - 512 bit Auth derivation data for authentication key derivation
/// @return Success, Fail
///////////////////////////////////////////////////////////////////////////////////////
static int32_t hmac_aead_derive_b_enc_b_auth(const uint8_t *iv, uint8_t *b_enc, uint8_t *b_auth)
{
    if ((NULL == iv) || (NULL == b_enc) || (NULL == b_auth))
    {
        return HMAC_ENC_ERR_NULL;
    }

    // IV0 = iv[0 .. SIZE_HALF_IV-1]
    // IV1 = iv[SIZE_HALF_IV .. IV_LEN-1] 

    for (uint32_t i = 0; i < SIZE_HALF_IV; i++)
    {
        // B_enc = (~IV0) || IV1 
        b_enc[i]                = (uint8_t)(~iv[i]);
        b_enc[i + SIZE_HALF_IV] = iv[i + SIZE_HALF_IV];

        // B_auth = IV0 || (~IV1) 
        b_auth[i]                = iv[i];
        b_auth[i + SIZE_HALF_IV] = (uint8_t)(~iv[i + SIZE_HALF_IV]);
    }

    return HMAC_ENC_OK;
}

////////////////////////////////////////////////////////////////////////////////
/// @brief - From Big Endian array to 64 bit little endian unsigned integer value
/// @param buf - Buffer of length 8 bytes
/// @param value - 
/// @return Success, Fail
////////////////////////////////////////////////////////////////////////////////
static int32_t hmac_aead_get_value_from_big_endian(const uint8_t* buf, uint64_t* value)
{
    if (NULL == buf)
    {
        return HMAC_ENC_ERR_NULL;
    }

    *value =  ((uint64_t)buf[0] << 56) |
                ((uint64_t)buf[1] << 48) |
                ((uint64_t)buf[2] << 40) |
                ((uint64_t)buf[3] << 32) |
                ((uint64_t)buf[4] << 24) |
                ((uint64_t)buf[5] << 16) |
                ((uint64_t)buf[6] << 8)  |
                ((uint64_t)buf[7]);

    return HMAC_ENC_OK;
}

/////////////////////////////////////////////////////////////
/// @brief - Add the data value in big endian
/// @param buf - Buffer of length 8 bytes
/// @param value - Value to be stored in Big Endian ( in the buf)
/// @return Success, Fail
//////////////////////////////////////////////////////////////
static int32_t hmac_aead_update_data_big_endian(uint8_t* buf, uint64_t value)
{
    if (NULL == buf)
    {
        return HMAC_ENC_ERR_NULL;
    }

    // We buf is 64 bit (8 bytes) long for Length block 
    for (uint32_t i = 0; i < SIZE_LENGTH_BLOCK; i++) 
    {
        buf[SIZE_LENGTH_BLOCK - 1 - i] = (uint8_t)(value & 0xFFu);
        value >>= 8;
    }

    return HMAC_ENC_OK;
}

/////////////////////////////////////////////////////////
/// @brief - Initialize the counter in 512 bit IV - last 32 bits
/// @param iv -  Pointer to IV
/// @return - Success, Fail
/////////////////////////////////////////////////////////
static int32_t hmac_aead_init_iv_counter(uint8_t *iv)
{
    if (iv == NULL)
    {
        return HMAC_ENC_ERR_NULL;
    }

    // Initialize counter - last 32 bits to 0
    iv[SIZE_IV -1] = 0x00;
    iv[SIZE_IV -2] = 0x00;
    iv[SIZE_IV -3] = 0x00;
    iv[SIZE_IV -4] = 0x00;

    return HMAC_ENC_OK;
}

//////////////////////////////////////////////////////////////////////////
/// @brief - Increment the counter in IV - Last 32 bits and Big Endian
/// @param iv - Pointer to IV 
/// @return Success, Fail
//////////////////////////////////////////////////////////////////////////
static int32_t hmac_aead_inc_iv_counter(uint8_t *iv)
{
    if (iv == NULL)
    {
        return HMAC_ENC_ERR_NULL;
    }

    for (int32_t i = (int32_t)SIZE_IV - 1; i >= (int32_t)(SIZE_IV - 4); i--)
    {   
        iv[i]++;

        if (iv[i] != 0)
        {
            break;
        }
    }

    return HMAC_ENC_OK;
}
////////////////////////////////////////////////////////////////////////////////////////////////////
/// @brief - This function encrypts and decrypts the input data using the given key. It uses 512 bit
///          IV (480 + 32 bit counter) to generate the key stream and XOR it with the plain text to 
///          generate the cipher text.              
/// @param msg - Message to be encrypted
/// @param len_msg - Message length
/// @param key - Encryption key
/// @param iv - 64 Byte IV
/// @param out - Encrypted or Decrypted message 
/// @return - Success, Fail
//////////////////////////////////////////////////////////////////////////////////////////////////// 
static int32_t hmac_aead_encrypt_decrypt(const uint8_t *msg, size_t len_msg, const uint8_t *key, const uint8_t *iv, uint8_t *out )
{
    uint32_t num_msg_blocks = 0;
    uint32_t left_over_size = 0;
    uint32_t i = 0;
    
    uint8_t key_stream[SIZE_SHA256_OUTPUT_BLOCK] = {0};
    uint8_t iv_cpy[SIZE_IV];

    // Verify inputs
    if ( (msg == NULL) || (key == NULL) || 
         (out == NULL) || (iv == NULL) )
    {
        return HMAC_ENC_ERR_NULL;
    }

    if (0 != len_msg)
    {
        // Copy IV to a local buffer, will change through counter 
        cmn_memcpy(iv_cpy, iv, SIZE_IV);
        // Get 32 byte msg blocks and remaining data
        num_msg_blocks =  len_msg / SIZE_SHA256_OUTPUT_BLOCK;
        left_over_size = len_msg % SIZE_SHA256_OUTPUT_BLOCK;
        // Initialize counter in the last 4 bytes on IV
        hmac_aead_init_iv_counter(iv_cpy);

        for (i = 0; i < num_msg_blocks; i++)
        {
            // Generate key stream for encryption
            hmac_sha256(iv_cpy, SIZE_IV, key, SIZE_ENC_DEC_KEY, key_stream);
            // XOR plain text and key stream
            cmn_memxor(&msg[i * SIZE_KEY_STREAM_BLOCK], key_stream, &out[i * SIZE_KEY_STREAM_BLOCK], SIZE_KEY_STREAM_BLOCK);
            // Increment counter
            hmac_aead_inc_iv_counter(iv_cpy);
        }

        if ( 0 != left_over_size)
        {
            // Generate key stream
            hmac_sha256(iv_cpy, SIZE_IV, key, SIZE_ENC_DEC_KEY, key_stream);
            // Encrypt plain text with key stream
            cmn_memxor(&msg[i * SIZE_KEY_STREAM_BLOCK], key_stream, &out[i * SIZE_KEY_STREAM_BLOCK], left_over_size);
        }
        
        // Clear the key stream buffer
        cmn_memset(key_stream, 0, SIZE_KEY_STREAM_BLOCK);
        // Clear Local IV copy and counter
        cmn_memset(iv_cpy, 0, SIZE_IV);        
    }

    return HMAC_ENC_OK;
}

/////////////////////////////////////////////////////////////////////////////////
/// @brief - Generate Authentication Tag for aad and cipther text. The tag is 
///          computed over 
///          AAD || Cipher text || Zero Pad || AAD Length || cipher text length
///          It returns length of the padded cipher text and 32 byte long tag. 
/// @param key_auth - Key to generate Authentication tag
/// @param aad - aad for Tag generation 
/// @param aad_len - aad Length
/// @param ciphertext - Cipther Text 
/// @param ciphertext_len - Cipther text length
/// @param tag  - ag (output)
/// @param padded_ciphertext_len Cipher text length with padding and block length
///        (aad not included) 
/// @return Success, Fail
//////////////////////////////////////////////////////////////////////////////////
static int32_t hmac_aead_gen_auth(const uint8_t *key_auth, const uint8_t *aad, size_t aad_len, 
                                uint8_t *ciphertext, size_t ciphertext_len, uint8_t *tag,
                                size_t* padded_ciphertext_len)
{
    size_t aad_full_len;
    size_t aad_rem_len;
    size_t ct_full_len;
    size_t ct_rem_len;

    uint8_t aad_ct_block[SIZE_HMAC_INPUT_BLOCK] = {0};

    uint8_t *len_aad_ptr;
    uint8_t *len_ct_ptr;

    hmac_multi_buf_t hmac_bufs[MAX_MULTI_HMAC_BUFS];

    uint8_t *ct_ptr;
    size_t ct_remaining;

    uint8_t hmac_buf_count = 0;
    uint32_t padded_space = 0;

    // Verify inputs    
    if ((key_auth == NULL) || (ciphertext == NULL) ||
        (tag == NULL) || (padded_ciphertext_len == NULL))
    {
        return HMAC_ENC_ERR_NULL;
    }

    // If aad length is not 00, then aad should be valid
    if ((aad_len != 0U) && (aad == NULL))
    {
        return HMAC_ENC_ERR_NULL;
    }

    // Init padded cipher text length with default
    *padded_ciphertext_len = ciphertext_len;
    
    ct_ptr = ciphertext;
    ct_remaining  = ciphertext_len;

    // Get lengths of aad - multile of 64 bytes and remaining data
    aad_full_len = (size_t)((aad_len / SIZE_HMAC_INPUT_BLOCK) * SIZE_HMAC_INPUT_BLOCK);    
    aad_rem_len = (uint8_t)(aad_len % SIZE_HMAC_INPUT_BLOCK);                             

    // aad data multiple of 64 bytes
    if (aad_full_len != 0)
    {
        hmac_bufs[hmac_buf_count].data = aad;
        hmac_bufs[hmac_buf_count].length = aad_full_len;
        hmac_buf_count++;
    }

    if (aad_rem_len != 0)
    {
        uint32_t copy_len = 0;

        // Copy remaining aad data to local buffer
        cmn_memcpy(aad_ct_block, aad + aad_full_len, aad_rem_len);        

        // Fill rest of the buffer with cipher text data --> aad || cipther text
        if (ct_remaining <= (SIZE_HMAC_INPUT_BLOCK - aad_rem_len))
        { 
            // All of the cipher text can fill the buffer
            copy_len = ct_remaining;

        } else
        {
            // Partial ciphertext data
            copy_len = SIZE_HMAC_INPUT_BLOCK - aad_rem_len;
        }

        cmn_memcpy(aad_ct_block + aad_rem_len, ct_ptr, copy_len);
        ct_ptr       += copy_len;
        ct_remaining -= copy_len;

        // Add the remaining aad and partial ct data to the HMAC buffers
        hmac_bufs[hmac_buf_count].data = aad_ct_block;
        hmac_bufs[hmac_buf_count].length = SIZE_HMAC_INPUT_BLOCK;
        hmac_buf_count++;   // second Chunk  
    }

    // Process Cipher text data
    ct_full_len = (ct_remaining / SIZE_HMAC_INPUT_BLOCK) * SIZE_HMAC_INPUT_BLOCK;
    ct_rem_len  = ct_remaining % SIZE_HMAC_INPUT_BLOCK;

    // Ciphertext data length multiple of 64 bytes
    if (ct_full_len != 0U)
    {
        hmac_bufs[hmac_buf_count].data = ct_ptr;
        hmac_bufs[hmac_buf_count].length = ct_full_len;
        hmac_buf_count++;   // 3rd Chunk

        ct_ptr += ct_full_len;
    }

    if (ct_rem_len != 0U)
    {
        padded_space = SIZE_HMAC_INPUT_BLOCK - ct_rem_len;

        // If space available, add the block length in the same block
        if (padded_space < (2 * SIZE_LENGTH_BLOCK))
        {
            padded_space += SIZE_HMAC_INPUT_BLOCK;

        }
    } else if (((aad_len + ciphertext_len) % SIZE_HMAC_INPUT_BLOCK) == 0U)
    {
        padded_space += SIZE_HMAC_INPUT_BLOCK;

    } else
    {
        // Some thing is Wrong, return with Error
        return HMAC_ENC_AUTH_GEN_FAILED;
    }

    // Zero pad 
    cmn_memset(ct_ptr + ct_rem_len, 0, padded_space);

    // Get pointers for adding aad length and cipher/plain text lengths
    len_aad_ptr = (ct_ptr + ct_rem_len + padded_space) - (2 * SIZE_LENGTH_BLOCK);
    len_ct_ptr  = (ct_ptr + ct_rem_len + padded_space) - SIZE_LENGTH_BLOCK;

    // Add block lengths - aad and cipher text length
    hmac_aead_update_data_big_endian(len_aad_ptr, (uint64_t)aad_len);
    hmac_aead_update_data_big_endian(len_ct_ptr,  (uint64_t)ciphertext_len);

    // Update the bufs to compute tag
    hmac_bufs[hmac_buf_count].data = ct_ptr;
    hmac_bufs[hmac_buf_count].length = padded_space + ct_rem_len;
    hmac_buf_count++;

    // Compute Tag
    hmac_sha256_multi(key_auth, SIZE_AUTH_KEY, hmac_bufs, hmac_buf_count, tag);

    // Update the output for padded cipher text length
    *padded_ciphertext_len += padded_space;

    // Cleanup 
    cmn_memset(aad_ct_block, 0, sizeof(aad_ct_block));

    return HMAC_ENC_OK;
}

//////////////////////////////////////////////////////////////////////////////////////////////
/// @brief - This is the Public function for AEAD encryption. It takes the messaage 
///          to be encrypted, master key and aad (if any). It generates IV and Derive 
///          Encryption and Authentication keys (unique per message) to encrypt the 
///          the message and generate the authentication tag on aad and encrypted 
///          message. It also appends 00 padding and length block (aad length and 
///          message length) to the encrypted message before generating the length.
///          
/// @param msg - Plain text message to be encrypted
/// @param msg_len - Length of the plain text message
/// @param aad - aad, if any
/// @param aad_len - add length. If aad is NULL, then it Must Be 0
/// @param key_master - 256 Bit master key ( Must be 256 bit long)
/// @param enc_msg_buf - Buffer to store Encrypted message
/// @param enc_msg_buf_len - Length of the given encrypted message buf. It should be
///                          at-least 79 bytes more than the plain text message size
/// @param enc_msg_len - (output) The actual length of the encrypted message ( inlcuding 
///                         padding and block length)
/// @param iv - (output) IV
/// @param tag - (output) Authentication Tag
/// @return - Success, Fail
///////////////////////////////////////////////////////////////////////////////////////////////
int32_t hmac_aead_enc(const uint8_t *msg, size_t msg_len, const uint8_t *aad, 
                        size_t aad_len, const uint8_t *key_master, uint8_t *enc_msg_buf, 
                        size_t enc_msg_buf_len, size_t* enc_msg_len, uint8_t *iv, uint8_t *tag )
{
    int32_t status = HMAC_ENC_OK;

    uint8_t prk[SIZE_PRK] = {0};
    uint8_t key_enc[SIZE_ENC_KEY] = {0};
    uint8_t key_auth[SIZE_AUTH_KEY] = {0};

    uint8_t b_enc[SIZE_IV];
    uint8_t b_auth[SIZE_IV];   

    *enc_msg_len = 0;

    // Verify inputs
    if ((msg == NULL) || (msg_len == 0U) ||
        (key_master == NULL) || 
        (enc_msg_buf == NULL) || (enc_msg_len == NULL) ||
        (iv == NULL) ||
        (tag == NULL))
    {
        return HMAC_ENC_ERR_NULL;
    }

    // aad should  be validif length is not 0
    if ((aad_len != 0U) && (aad == NULL))
    {
        return HMAC_ENC_ERR_NULL;
    }

    // Encrypted data bffer should be larger than plaintext buffer 
    // as encrypted data will have padding and block length appended
    if (enc_msg_buf_len < msg_len)
    {
        return HMAC_ENC_ERR_BUF_TOO_SMALL;
    }

    // Generate random IV   
    if (cmn_secure_random(iv, SIZE_IV) != COMMON_OK)
    {
        status = HMAC_ENC_GENERAL_FAILURE;
        goto cleanup;
    }

    /********* Derive Encryption and Authentication Keys ***********/

    // Generate prk
    hmac_sha256(iv, SIZE_IV, key_master, SIZE_KEY_MASTER, prk);

    // Get Encryption and Authetication key derivation data
    hmac_aead_derive_b_enc_b_auth(iv, b_enc, b_auth);

    // Derive Encryption Key
    hmac_sha256(b_enc, SIZE_B_ENC, prk, SIZE_PRK, key_enc);

    // Derive Auth key
    hmac_sha256(b_auth, SIZE_B_AUTH, prk, SIZE_PRK, key_auth);

    // Clear prk 
    cmn_memset(prk, 0, SIZE_PRK);

    /********* Encrypt the Message *********/
    
    if (hmac_aead_encrypt_decrypt(msg, msg_len, key_enc, iv, enc_msg_buf) != HMAC_ENC_OK)
    {
        status = HMAC_ENC_ENCRYPTION_FAILED;
        goto cleanup;
    }

    /********* Generate Tag **********/

    if (hmac_aead_gen_auth(key_auth, aad, aad_len, enc_msg_buf, msg_len, tag, enc_msg_len) != HMAC_ENC_OK)
    {
        status = HMAC_ENC_AUTH_GEN_FAILED;
        goto cleanup;
    }

    // Clear all sensitive data
    cleanup:
    cmn_memset(key_enc, 0, SIZE_ENC_KEY);
    cmn_memset(key_auth, 0, SIZE_AUTH_KEY);
    cmn_memset(b_enc, 0, SIZE_B_ENC);
    cmn_memset(b_auth, 0, SIZE_B_AUTH);

    // Clear IV also if the status is not good
    if (status != HMAC_ENC_OK)
    {
        cmn_memset(iv, 0, SIZE_IV);
    }       

    return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
/// @brief This function computes the tag of the given aad and cipher rext data
///         and compare it with the reference tag provided as input parameter. The function also
///         provides the actual cipher text length (Without padding and block lengths). It authenticates
///         AAD || cipher text || Padding || AAD length || Cipher text length
///
/// @param ciphertext - Pointer to the Cipher text
/// @param cipthertext_len - Length of the Cipher text. It includes the padding and block length
/// @param key_auth - Pointer to 32 byte authentication key
/// @param aad - Pointer to aad, if any
/// @param aad_len - aad length, if it is there, otherwise it is 0
/// @param tag_ref - Reference Tag to compare with
/// @param len_nopad_ciphertext - Length of the actual cipher text, without padding nd block length
/// @return Success, Fail
/////////////////////////////////////////////////////////////////////////////////////////////////////
static int32_t hmac_aead_verify_auth(const uint8_t* ciphertext, size_t ciphertext_len, const uint8_t* aad, 
                                    size_t aad_len,uint8_t *key_auth, const uint8_t* tag_ref, 
                                    size_t *len_nopad_ciphertext )
{
    uint64_t    block_length_aad = 0;
    uint64_t    block_length_msg = 0;

    size_t      aad_full_len = 0;
    uint8_t     aad_rem_len  = 0;
    size_t      ct_full_len = 0;             
    uint8_t     ct_rem_len  = 0;
    uint8_t     hmac_buf_count = 0; 

    uint8_t     *len_aad_ptr;
    uint8_t     *len_ct_ptr;

    uint8_t     *ct_ptr;
    size_t      ct_remaining;

    uint8_t     tag[SIZE_TAG] = {0};
    uint8_t     aad_ct_block[SIZE_HMAC_INPUT_BLOCK] = {0};

    hmac_multi_buf_t    bufs_hmac[MAX_MULTI_HMAC_BUFS];
 
    // Verify inputs
    if ( (ciphertext == NULL) || (ciphertext_len == 0U) || 
         (key_auth == NULL) ||
         (tag_ref == NULL) || (len_nopad_ciphertext == NULL)
        )        
    {
        return HMAC_ENC_ERR_NULL;
    }

    // If aad length is not 00, then aad should be valid
    if ((aad_len != 0U) && (aad == NULL))
    {
        return HMAC_ENC_ERR_NULL;
    }

    // aad len + cipher text length should be multiple of 64
    if ( ( (aad_len + ciphertext_len) % SIZE_HMAC_INPUT_BLOCK) != 0U)
    {
        return HMAC_ENC_INVALID_CIPHER_TEXT_LEN;
    }

    ct_ptr = ciphertext;
    ct_remaining = ciphertext_len;

    // Extract aad and cipther text lengths from the padding length block
    hmac_aead_get_value_from_big_endian(&ciphertext[ciphertext_len - 2 * SIZE_LENGTH_BLOCK], &block_length_aad);
    hmac_aead_get_value_from_big_endian(&ciphertext[ciphertext_len - SIZE_LENGTH_BLOCK], &block_length_msg);

    // aad length and add block length should match
    if (block_length_aad != aad_len)
    {
        return HMAC_ENC_INVALID_ADD_LEN;
    }

    // Actual cipher text should be smaller than padded cipher text length
    if (block_length_msg > ciphertext_len)
    {
        return HMAC_ENC_INVALID_CIPHER_TEXT_LEN;
    }

    aad_full_len = (size_t)((aad_len / SIZE_HMAC_INPUT_BLOCK) * SIZE_HMAC_INPUT_BLOCK);    
    aad_rem_len = (uint8_t)(aad_len % SIZE_HMAC_INPUT_BLOCK);                              

    // aad data multiple of 64 bytes
    if (aad_full_len != 0)
    {
        bufs_hmac[hmac_buf_count].data = aad;
        bufs_hmac[hmac_buf_count].length = aad_full_len;
        hmac_buf_count++;   
    }

    if (aad_rem_len != 0)
    {
        // Copy remaining aad data
        cmn_memcpy(aad_ct_block, (aad + aad_full_len), aad_rem_len);

        // Fill rest of the buffer with encrypted data
        if ( ciphertext_len <= (SIZE_HMAC_INPUT_BLOCK - aad_rem_len) )
        { 
            // All encrypted msg data can fit in the remaining space                   
            cmn_memcpy( (aad_ct_block + aad_rem_len), ct_ptr, ct_remaining);
            ct_remaining = 0;

        }else
        {
            // We have more data than remaining space
            uint32_t data_size = SIZE_HMAC_INPUT_BLOCK - aad_rem_len;

            cmn_memcpy( (aad_ct_block + aad_rem_len), ct_ptr, data_size);
            ct_remaining -= data_size;
            ct_ptr += data_size;
        }

        // Add the partial aad and cipher text data to the HMAC buffers        
        bufs_hmac[hmac_buf_count].data = aad_ct_block;
        bufs_hmac[hmac_buf_count].length = SIZE_HMAC_INPUT_BLOCK;
        hmac_buf_count++;  
    }

    // Length of the message chunk multiple of 64
    ct_full_len = (size_t)((ct_remaining / SIZE_HMAC_INPUT_BLOCK) * SIZE_HMAC_INPUT_BLOCK);  
    ct_rem_len = (uint8_t)(ct_remaining % SIZE_HMAC_INPUT_BLOCK);                              

    // If still remaining data, then it is a padding issue. Something is wrong
    if (ct_rem_len != 0 )
    {
        return HMAC_ENC_INVALID_CIPHER_TEXT_LEN;
    }

    // AAD + Cipher text data with padding should be multiple of 64 bytes
    if (ct_full_len != 0)
    {
        bufs_hmac[hmac_buf_count].data = ct_ptr;
        bufs_hmac[hmac_buf_count].length = ct_full_len;
        hmac_buf_count++;  
    }

    // Compute the Tag
    hmac_sha256_multi(key_auth, SIZE_AUTH_KEY, bufs_hmac, hmac_buf_count, tag);

    // Compare the tag
    if (cmn_memcmp(tag, tag_ref, SIZE_TAG) != COMMON_OK)
    {
        return HMAC_ENC_AUTH_VERIFY_FAILED;
    }

    *len_nopad_ciphertext = (size_t)block_length_msg;

    return HMAC_ENC_OK;
}

///////////////////////////////////////////////////////////////////////////////////
/// @brief - This is the Public function for AEAD decryption. It takes the messaage 
///          to be decrypted as input parameter and output is stored in the msg
///          buffer provided. It authenticates the cipher text first, and then 
///          decrypts only if the authentication passes.   
/// 
/// @param enc_msg - Message to be decrypted and authenticated 
/// @param enc_msg_len - Total data Length - cipher text || padding || length block
/// @param aad_len - aad data length 
/// @param key - Master key for Encryption and Authentication
/// @param key_len - Key Size
/// @param dec_msg - Decrypted Message (output ) in the format ...
///                    aad || plain Text
/// @param decc_msg_len - Encrypted message buffer length - It should be 
///                        at least 96 bytes more than msg_len to store IV and TAG
/// @return Success, Fail
////////////////////////////////////////////////////////////////////////////////////
int32_t hmac_aead_dec(uint8_t *enc_msg, size_t enc_msg_len, uint8_t *aad, 
                        size_t aad_len, const uint8_t *tag, const uint8_t *key, 
                        const uint8_t *iv, uint8_t *dec_msg, size_t *dec_msg_len)
{
    uint8_t* cipther_text = NULL;
    size_t len_cipher_text = 0;

    uint8_t prk[SIZE_PRK] = {0};
    uint8_t key_dec[SIZE_ENC_KEY] = {0};
    uint8_t key_auth[SIZE_AUTH_KEY] = {0};

    uint8_t b_enc[SIZE_IV];
    uint8_t b_auth[SIZE_IV];

    uint8_t key_stream[SIZE_SHA256_OUTPUT_BLOCK] = {0};

    size_t msg_len = 0;

    // Verify inputs
    if ( (NULL == enc_msg) || (0 == enc_msg_len) || (NULL == key) ||
          (NULL == dec_msg) 
        )        
    {
        return HMAC_ENC_ERR_NULL;
    }

    /********** Derive Decryption and Authentication Keys **********/

    // Derive PRK
    hmac_sha256(iv, SIZE_IV, key, SIZE_KEY_MASTER, prk);

    // Get Encryption and Authetication key derivation data
    hmac_aead_derive_b_enc_b_auth(iv, b_enc, b_auth);

    // Derive Encryption Key
    hmac_sha256(b_enc, SIZE_B_ENC, prk, SIZE_PRK, key_dec);

    // Derive Auth key
    hmac_sha256(b_auth, SIZE_B_AUTH, prk, SIZE_PRK, key_auth);

    // Clear prk 
    cmn_memset(prk, 0, SIZE_PRK);

    /********* Verify tag *********/

    if ( (hmac_aead_verify_auth(enc_msg, enc_msg_len, aad, aad_len, key_auth, tag, &msg_len)) != HMAC_ENC_OK)
    {
        return HMAC_ENC_AUTH_VERIFY_FAILED;
    }

    /********* Decrypt cipther text *********/

    if (hmac_aead_encrypt_decrypt(enc_msg, msg_len, key_dec, iv, dec_msg) != HMAC_ENC_OK)
    {
        // Clear encryption and authentication keys
        cmn_memset(key_dec, 0, SIZE_ENC_KEY);

        return HMAC_ENC_ENCRYPTION_FAILED;
    }    

    // Clear Decryption key
    cmn_memset(key_dec, 0, SIZE_ENC_KEY);

    // Return plain text message length
    *dec_msg_len = msg_len;

    return HMAC_ENC_OK;
}