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

#include <sys/random.h>
#include <unistd.h>
#include "common.h"

//////////////////////////////////////////////////////////////////////////////////
/// @brief - Ramdom number generator (Replace with TRNG on Embedded environment)
/// @param buf - output buffer
/// @param len - Length of the buffer/ random data required
/// @return Success, Fail/Error
////////////////////////////////////////////////////////////////////////////////// 
int32_t cmn_secure_random(uint8_t *buf, size_t len)
{
    size_t offset = 0;
    ssize_t ret;

    while (offset < len) 
    {
        ret = getrandom(buf + offset, len - offset, 0);
        if (ret < 0) 
        {
            return COMMON_GENERAL_FAILURE;
        }
        offset += (size_t)ret;
    }

    // TODO : Check randomness of the data, Humming weight??

    return COMMON_OK;
}

