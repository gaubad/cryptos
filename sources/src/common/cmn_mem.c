/******************************************************************************
 *  @file    cmn_mem.c
 * 
 *  @brief   Common memory utility functions 
 *
 *  @details
 *  This file provides controlled implementations of basic memory operations
 *  intended for embedded and security-critical environments where:
 *    - Standard C library usage is restricted or unavailable
 *    - Memory overlap must be explicitly forbidden
 *    - Constant-time comparison is required
 *
 *  The APIs are deliberately strict to fail fast on programmer errors
 *  and avoid silent data corruption.
 *
 *  @note
 *  - These functions do NOT fully replicate standard libc semantics.
 *  - common_memcpy() explicitly rejects overlapping memory regions.
 *  - common_memcmp() is implemented in constant time.
 *
 *  Author:   Deepak Gauba
 *  Version:  1.0
 *  Date:     2025/12/25
 ******************************************************************************/

#include "common.h"

///////////////////////////////////////////////////////
/// @brief Mem Copy
/// @param dst - Pointer to destination buffer 
/// @param src - Pointer to source buffer
/// @param len - length of the data to be copied
/// @return 0 - Sucess, -1 - Fail
////////////////////////////////////////////////////////
int32_t cmn_memcpy(uint8_t *dst, const uint8_t *src, size_t len)
{
    if ((NULL == dst) || (NULL == src))
    {
        return COMMON_ERR_NULL;
    }

    if (src == dst)
    {
        return COMMON_ERR_MISMATCH;
    }

    // Check for src and dst buffer overlps for safe mem copy
    // This is not the standard memcpy behaviour. 
    // Making it for securty specific code 
    if ( ((dst < src) && ((dst + len) > src)) ||
     ((src < dst) && ((src + len) > dst)) )     
    {
        return COMMON_ERR_LEN;
    }

    // Matching with the lib memcpy behaviour
    if (0 == len)
    {
        return COMMON_OK;
    }

    // Copy data 
    for (size_t i = 0; i < len; i++)
    {
        dst[i] = src[i];
    }

    return COMMON_OK;
}

///////////////////////////////////////////////////////
/// @brief Mem compare
/// @param a - Pointer to buffer a 
/// @param b - Pointer to buffer b
/// @param len - length to be compared
/// @return 0 - Sucess, -1 - Fail
////////////////////////////////////////////////////////
int32_t cmn_memcmp(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t result = 0; 

    if ((NULL == a) || (NULL == b) || (0 == len ))
    {
        return COMMON_ERR_NULL;
    }

    // Time constant comparison
    for (size_t i = 0; i < len; i++)
    {
        result |= a[i] ^ b[i];
    }

    if (result == 0)
    {
        return COMMON_OK;
    }else
    {
        return COMMON_ERR_MISMATCH;
    }
}

/////////////////////////////////////////////////////
/// @brief - Memset 
/// @param buf - pointer to the buffer 
/// @param val - value to be set in the buffer
/// @param len - Length of the buffer to be set
/// @return 0 - Sucess, -1 - Fail
//////////////////////////////////////////////////////
int32_t cmn_memset(uint8_t *buf, uint8_t val, size_t len)
{
    if ((NULL == buf) || (0 == len ))
    {
        return COMMON_ERR_NULL;
    }

    for (size_t i = 0; i < len; i++)
    {
        buf[i] = val;
    }

    return COMMON_OK;
}
////////////////////////////////////////////////////////////////////
/// @brief - XOR two memory buffers data 
/// @param a - Pointer to data a
/// @param b - Pointer to data b
/// @param res - Pointer to XORed result
/// @param len - Length of the data to be xored
/// @return 0 - Sucess, -1 - Fail
///////////////////////////////////////////////////////////////////// 
int32_t cmn_memxor(const uint8_t *a, const uint8_t *b, uint8_t *res, size_t len)
{
    if ((NULL == a) || (NULL == b) || (NULL == res) )
    {
        return COMMON_ERR_NULL;
    }

    if (0 == len) 
    {
        return COMMON_OK;
    }

    for (size_t i = 0; i < len; i++)
    {
        res[i] = a[i] ^ b[i];
    }

    return COMMON_OK;
}

////////////////////////////////////////////////////////////////////
/// @brief - Memory debug print
/// @param mem - Pointer to memory to be printed
/// @param size-Size of the memory to be printed
/// @return 0 - Sucess, -1 - Fail
///////////////////////////////////////////////////////////////////// 
int32_t cmn_memprnt(const uint8_t *mem, size_t size)
{
    if ((NULL == mem) || (0 == size))
    {
        printf("Invalid Params \n\n");
        return COMMON_ERR_NULL;
    }

    for (uint8_t i = 0; i < size; i++) 
    {
        printf("%02x", mem[i]);
    }
    printf("\n\n");

    return 0;
}