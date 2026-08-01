/* port/ti/ti-rng.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#if defined(WOLFSSL_TI_CRYPT) && !defined(WC_NO_RNG)

#ifdef __cplusplus
    extern "C" {
#endif

#include <stdint.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/port/ti/ti-ccm.h>
#include "ti-am26xx.h"
#include <wolfssl/wolfcrypt/logging.h>

#include <crypto/rng/rng.h>

/* ------------------------------------------------------------------------ */
/* Static RNG handle — opened once, persists across WC_RNG lifecycles.      */
/* The TRNG/DRBG hardware is a system resource.                             */
/* ------------------------------------------------------------------------ */
static RNG_Handle gRngHandle = NULL;

/* ------------------------------------------------------------------------ */
/* Internal: open & setup the TI RNG on first use                           */
/* ------------------------------------------------------------------------ */
static int tiRngEnsureInit(void)
{
    if (gRngHandle != NULL)
        return 0;

    if (!wolfSSL_TI_CCMInit())
        return WC_HW_E;

    gRngHandle = RNG_open(0);
    if (gRngHandle == NULL)
        return WC_HW_E;

    if (RNG_setup(gRngHandle) != RNG_RETURN_SUCCESS) {
        RNG_close(gRngHandle);
        gRngHandle = NULL;
        return WC_HW_E;
    }

    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_InitRng                                                               */
/* ------------------------------------------------------------------------ */
WOLFSSL_ABI
int wc_InitRng(WC_RNG* rng)
{
    return wc_InitRng_ex(rng, NULL, INVALID_DEVID);
}

/* ------------------------------------------------------------------------ */
/* wc_InitRng_ex                                                            */
/* ------------------------------------------------------------------------ */
int wc_InitRng_ex(WC_RNG* rng, void* heap, int devId)
{
    if (rng == NULL) return BAD_FUNC_ARG;

    (void)devId;

    XMEMSET(rng, 0, sizeof(*rng));
    rng->heap   = heap;
    rng->status = WC_DRBG_NOT_INIT;

    if (tiRngEnsureInit() != 0)
        return WC_HW_E;

    rng->status = WC_DRBG_OK;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_InitRngNonce                                                          */
/* ------------------------------------------------------------------------ */
int wc_InitRngNonce(WC_RNG* rng, byte* nonce, word32 nonceSz)
{
    (void)nonce;
    (void)nonceSz;
    return wc_InitRng_ex(rng, NULL, INVALID_DEVID);
}

/* ------------------------------------------------------------------------ */
/* wc_InitRngNonce_ex                                                       */
/* ------------------------------------------------------------------------ */
int wc_InitRngNonce_ex(WC_RNG* rng, byte* nonce, word32 nonceSz,
                       void* heap, int devId)
{
    (void)nonce;
    (void)nonceSz;
    return wc_InitRng_ex(rng, heap, devId);
}

/* ------------------------------------------------------------------------ */
/* wc_RNG_GenerateBlock                                                     */
/* ------------------------------------------------------------------------ */
WOLFSSL_ABI
int wc_RNG_GenerateBlock(WC_RNG* rng, byte* output, word32 sz)
{
    uint32_t buf[4];

    if (rng == NULL || output == NULL)
        return BAD_FUNC_ARG;
    if (sz == 0)
        return 0;
    if (gRngHandle == NULL)
        return WC_HW_E;

    while (sz > 0) {
        word32 copySz;

        wolfSSL_TI_lockCCM();
        if (RNG_read(gRngHandle, buf) != RNG_RETURN_SUCCESS) {
            wolfSSL_TI_unlockCCM();
            return WC_HW_E;
        }
        wolfSSL_TI_unlockCCM();

        copySz = (sz > 16) ? 16 : sz;
        XMEMCPY(output, (byte*)buf, copySz);
        output += copySz;
        sz    -= copySz;
    }

    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_RNG_GenerateByte                                                      */
/* ------------------------------------------------------------------------ */
int wc_RNG_GenerateByte(WC_RNG* rng, byte* b)
{
    return wc_RNG_GenerateBlock(rng, b, 1);
}

/* ------------------------------------------------------------------------ */
/* wc_FreeRng                                                               */
/* ------------------------------------------------------------------------ */
int wc_FreeRng(WC_RNG* rng)
{
    if (rng)
        rng->status = WC_DRBG_NOT_INIT;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_rng_new                                                               */
/* ------------------------------------------------------------------------ */
WOLFSSL_ABI
WC_RNG* wc_rng_new(byte* nonce, word32 nonceSz, void* heap)
{
    WC_RNG* rng;

    (void)nonce;
    (void)nonceSz;

    rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), heap, DYNAMIC_TYPE_RNG);
    if (rng == NULL) return NULL;

    if (wc_InitRng_ex(rng, heap, INVALID_DEVID) != 0) {
        XFREE(rng, heap, DYNAMIC_TYPE_RNG);
        return NULL;
    }

    return rng;
}

/* ------------------------------------------------------------------------ */
/* wc_rng_new_ex                                                            */
/* ------------------------------------------------------------------------ */
int wc_rng_new_ex(WC_RNG** rng, byte* nonce, word32 nonceSz,
                  void* heap, int devId)
{
    (void)nonce;
    (void)nonceSz;

    if (rng == NULL) return BAD_FUNC_ARG;

    *rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), heap, DYNAMIC_TYPE_RNG);
    if (*rng == NULL) return MEMORY_E;

    if (wc_InitRng_ex(*rng, heap, devId) != 0) {
        XFREE(*rng, heap, DYNAMIC_TYPE_RNG);
        *rng = NULL;
        return WC_HW_E;
    }

    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_rng_free                                                              */
/* ------------------------------------------------------------------------ */
WOLFSSL_ABI
void wc_rng_free(WC_RNG* rng)
{
    if (rng) {
        wc_FreeRng(rng);
        XFREE(rng, rng->heap, DYNAMIC_TYPE_RNG);
        (void)rng;
    }
}

/* ------------------------------------------------------------------------ */
/* wc_GenerateSeed                                                          */
/* ------------------------------------------------------------------------ */
int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    RNG_Handle h;

    if (os == NULL || output == NULL)
        return BAD_FUNC_ARG;
    if (sz == 0)
        return 0;

    (void)os;

    if (tiRngEnsureInit() != 0)
        return WC_HW_E;

    h = gRngHandle;

    while (sz > 0) {
        uint32_t buf[4];
        word32 copySz;

        wolfSSL_TI_lockCCM();
        if (RNG_read(h, buf) != RNG_RETURN_SUCCESS) {
            wolfSSL_TI_unlockCCM();
            return WC_HW_E;
        }
        wolfSSL_TI_unlockCCM();

        copySz = (sz > 16) ? 16 : sz;
        XMEMCPY(output, (byte*)buf, copySz);
        output += copySz;
        sz    -= copySz;
    }

    return 0;
}

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_TI_CRYPT && !WC_NO_RNG */