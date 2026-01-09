#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

////////// Public functions for SHA256 ////////// 

// SHA-256 context
typedef struct sha256_ctx_s
{
    uint64_t bitlen;
    uint32_t state[8];
    uint8_t buffer[64];
    size_t buffer_len;
} sha256_ctx;

// One function for complete hash - Init, update and finish 
int32_t sha256_hash(const uint8_t* msg, const uint32_t msg_size, uint8_t* hash);

// Individual hash funtions
int32_t sha256_init(sha256_ctx *ctx);
int32_t sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_finish(sha256_ctx *ctx, uint8_t hash[32]);

// HAMC 
 
// Buffers for multi HMAc
typedef struct hmac_multi_buf_s
{
    const uint8_t *data;
    uint32_t length;
} hmac_multi_buf_t;

int32_t hmac_sha256(const uint8_t* msg, const uint32_t msg_size, const uint8_t* key, const uint8_t key_size, uint8_t* hmac);
int32_t hmac_sha256_multi(const uint8_t *key, uint8_t key_size, const hmac_multi_buf_t *buffers, uint32_t num_buffers, uint8_t *hmac);

#endif