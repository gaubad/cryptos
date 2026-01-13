/******************************************************************************
 *  @file    cmn_random.c
 *
 *  @brief   Random Number Generator
 *
 *  @details
 *  This file provides a SW based Random number generator. On an Embedded system
 *  this should be replaced with a TRNG driver interface.
 *
 *
 *  Author:   Deepak Gauba
 *  Version:  1.0
 *  Date:     2025/12/25
 ******************************************************************************/
#include <unistd.h>
#include "common.h"

#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <stdlib.h>
#else
#error "Unsupported platform"
#endif

//////////////////////////////////////////////////////////////////////////////////
/// @brief - Ramdom number generator (Replace with TRNG on Embedded environment)
/// @param buf - output buffer
/// @param len - Length of the buffer/ random data required
/// @return Success, Fail/Error
//////////////////////////////////////////////////////////////////////////////////
int32_t cmn_secure_random(uint8_t *buf, size_t len)
{
#if defined(__linux__)
    ssize_t ret;
    size_t offset = 0;

    while (offset < len)
    {
        ret = getrandom(buf + offset, len - offset, 0);
        if (ret <= 0)
            return -1;
        offset += ret;
    }
    return 0;

#elif defined(__APPLE__)
    arc4random_buf(buf, len);
    return 0;
#endif
}
