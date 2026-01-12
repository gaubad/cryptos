#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdint.h>

#define COMMON_OK                       0
#define COMMON_ERR_NULL                 -1
#define COMMON_ERR_LEN                  -2
#define COMMON_ERR_MISMATCH             -3
#define COMMON_GENERAL_FAILURE          -4

// Memory manipulation functions
int32_t cmn_memcpy(uint8_t *dst, const uint8_t *src, size_t len);
int32_t cmn_memcmp(const uint8_t *a, const uint8_t *b, size_t len);
int32_t cmn_memset(uint8_t *buf, uint8_t val, size_t len);
int32_t cmn_memxor(const uint8_t *a, const uint8_t *b, uint8_t *res, size_t len);
int32_t cmn_memprnt(const uint8_t *mem, size_t size);

// Random number generator
int32_t cmn_secure_random(uint8_t *buf, size_t len);

#endif