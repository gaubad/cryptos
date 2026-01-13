#ifndef HMAC_AEAD_H
#define HMAC_AEAD_H

#include <stdint.h>
#include <stddef.h>

// clang-format off
#define HMAC_AEAD_OK                            0
#define HMAC_AEAD_ERR_NULL                      -1
#define HMAC_AEAD_ERR_LEN                       -2
#define HMAC_AEAD_GENERAL_FAILURE               -3
#define HMAC_AEAD_AUTH_GEN_FAILED               -4
#define HMAC_AEAD_ENCRYPTION_FAILED             -5
#define HMAC_AEAD_AUTH_VERIFY_FAILED            -6
#define HMAC_AEAD_ERR_BUF_TOO_SMALL             -7
#define HMAC_AEAD_INVALID_CIPHER_TEXT_LEN       -8
#define HMAC_AEAD_INVALID_ADD_LEN               -9
#define HMAC_AEAD_INVALID_IV                    -10

#define SIZE_KEY_MASTER                         32
#define SIZE_IV                                 64

#define SIZE_SHA256_OUTPUT_BLOCK                32
#define SIZE_SHA256_INPUT_BLOCK                 64

#define SIZE_TAG                                SIZE_SHA256_OUTPUT_BLOCK

// clang-format on

int32_t hmac_aead_enc(const uint8_t *msg, size_t msg_len, const uint8_t *aad,
                      size_t aad_len, const uint8_t *key, uint8_t *enc_msg_buf,
                      size_t enc_msg_buf_len, size_t *enc_msg_len, uint8_t *iv,
                      uint8_t *tag);

int32_t hmac_aead_dec(uint8_t *enc_msg, size_t enc_msg_len, uint8_t *aad,
                      size_t aad_len, const uint8_t *tag, const uint8_t *key,
                      const uint8_t *iv, uint8_t *dec_msg, size_t *dec_msg_len);

#endif