/* port/ti/ti-cmac.c
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

#if defined(WOLFSSL_TI_CRYPT) && defined(WOLFSSL_CMAC) && !defined(NO_AES)

#ifdef __cplusplus
    extern "C" {
#endif

#include <limits.h>
#include <stdint.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/port/ti/ti-ccm.h>
#include "ti-am26xx.h"
#include <wolfssl/wolfcrypt/logging.h>

#include <security_common/drivers/crypto/dthe/dthe.h>
#include <security_common/drivers/crypto/dthe/dthe_aes.h>
#include <drivers/soc.h>

/* ------------------------------------------------------------------------ */
/* Key-length helper (duplicated from ti-aes.c)                             */
/* ------------------------------------------------------------------------ */
static uint8_t AesKeyLenToDthe(word32 keylen)
{
    switch (keylen) {
        case 16: return DTHE_AES_KEY_128_SIZE;
        case 24: return DTHE_AES_KEY_192_SIZE;
        case 32: return DTHE_AES_KEY_256_SIZE;
        default: return 0;
    }
}

/* ------------------------------------------------------------------------ */
/* ShiftAndXorRb — CMAC sub-key derivation (RFC 4493)                       */
/* ------------------------------------------------------------------------ */
void ShiftAndXorRb(byte* out, byte* in)
{
    int i, j, xorRb;
    int mask = 0, last = 0;
    byte Rb = 0x87;

    xorRb = (in[0] & 0x80) != 0;

    for (i = 1, j = WC_AES_BLOCK_SIZE - 1; i <= WC_AES_BLOCK_SIZE; i++, j--) {
        last = (in[j] & 0x80) ? 1 : 0;
        out[j] = (byte)((in[j] << 1) | mask);
        mask = last;
        if (xorRb) {
            out[j] ^= Rb;
            Rb = 0;
        }
    }
}

/* ------------------------------------------------------------------------ */
/* wc_InitCmac                                                              */
/* ------------------------------------------------------------------------ */
int wc_InitCmac(Cmac* cmac, const byte* key, word32 keySz,
                int type, void* unused)
{
    return wc_InitCmac_ex(cmac, key, keySz, type, unused, NULL, INVALID_DEVID);
}

/* ------------------------------------------------------------------------ */
/* wc_InitCmac_ex                                                           */
/* ------------------------------------------------------------------------ */
int wc_InitCmac_ex(Cmac* cmac, const byte* key, word32 keySz,
                   int type, void* unused, void* heap, int devId)
{
    (void)unused;
    if (cmac == NULL || key == NULL) return BAD_FUNC_ARG;
    if (type != WC_CMAC_AES) return BAD_FUNC_ARG;
    if (keySz != 16) return BAD_FUNC_ARG;

    cmac->bufferSz = 0;
    cmac->totalSz  = 0;
    XMEMSET(cmac->buffer, 0, sizeof(cmac->buffer));
    XMEMSET(cmac->digest, 0, sizeof(cmac->digest));

    return wc_AesSetKey(&cmac->aes, key, keySz, NULL, AES_ENCRYPTION);
}

/* ------------------------------------------------------------------------ */
/* wc_CmacUpdate                                                            */
/* ------------------------------------------------------------------------ */
int wc_CmacUpdate(Cmac* cmac, const byte* in, word32 inSz)
{
    word32 newSz;
    if (cmac == NULL || (in == NULL && inSz != 0)) return BAD_FUNC_ARG;
    if (!WC_SAFE_SUM_WORD32(cmac->bufferSz, inSz, newSz)) return BAD_FUNC_ARG;

    if (newSz > WC_AES_BLOCK_SIZE) {
        word32 consume = WC_AES_BLOCK_SIZE - cmac->bufferSz;
        XMEMCPY(cmac->buffer + cmac->bufferSz, in, consume);

        wolfSSL_TI_lockCCM();
        {
            DTHE_Handle h = (DTHE_Handle)wolfSSL_TI_getDtheHandle();
            DTHE_AES_Params params;
            XMEMSET(&params, 0, sizeof(params));
            params.algoType    = DTHE_AES_CBC_MAC_MODE;
            params.opType      = DTHE_AES_ENCRYPT;
            params.ptrKey      = (uint32_t*)cmac->aes.key;
            params.keyLen      = AesKeyLenToDthe(cmac->aes.keylen);
            params.ptrIV       = (uint32_t*)cmac->digest;
            params.ptrPlainTextData = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)cmac->buffer);
            params.ptrTag      = (uint32_t*)cmac->digest;
            params.dataLenBytes = WC_AES_BLOCK_SIZE;
            params.streamState = DTHE_AES_ONE_SHOT_SUPPORT;
            if (h != NULL)
                DTHE_AES_execute(h, &params);
        }
        wolfSSL_TI_unlockCCM();

        cmac->bufferSz = 0;
        in += consume;
        inSz -= consume;

        while (inSz >= WC_AES_BLOCK_SIZE) {
            wolfSSL_TI_lockCCM();
            {
                DTHE_Handle h = (DTHE_Handle)wolfSSL_TI_getDtheHandle();
                DTHE_AES_Params params;
                XMEMSET(&params, 0, sizeof(params));
                params.algoType    = DTHE_AES_CBC_MAC_MODE;
                params.opType      = DTHE_AES_ENCRYPT;
                params.ptrKey      = (uint32_t*)cmac->aes.key;
                params.keyLen      = AesKeyLenToDthe(cmac->aes.keylen);
                params.ptrIV       = (uint32_t*)cmac->digest;
                params.ptrPlainTextData = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)in);
                params.ptrTag      = (uint32_t*)cmac->digest;
                params.dataLenBytes = WC_AES_BLOCK_SIZE;
                params.streamState = DTHE_AES_ONE_SHOT_SUPPORT;
                if (h != NULL)
                    DTHE_AES_execute(h, &params);
            }
            wolfSSL_TI_unlockCCM();
            in += WC_AES_BLOCK_SIZE;
            inSz -= WC_AES_BLOCK_SIZE;
        }
    }

    if (inSz > 0) {
        XMEMCPY(cmac->buffer + cmac->bufferSz, in, inSz);
        cmac->bufferSz += inSz;
    }
    cmac->totalSz += inSz;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_CmacFinalNoFree                                                       */
/* ------------------------------------------------------------------------ */
int wc_CmacFinalNoFree(Cmac* cmac, byte* out, word32* outSz)
{
    DTHE_Handle h = (DTHE_Handle)wolfSSL_TI_getDtheHandle();
    DTHE_AES_Params params;
    Aes* aes = &cmac->aes;
    byte lastBlock[WC_AES_BLOCK_SIZE];
    byte k1[WC_AES_BLOCK_SIZE], k2[WC_AES_BLOCK_SIZE];
    byte zero[WC_AES_BLOCK_SIZE];
    word32 i;
    uint32_t algoType;

    if (cmac == NULL || out == NULL || outSz == NULL) return BAD_FUNC_ARG;
    if (h == NULL) return WC_HW_E;

    XMEMSET(zero, 0, sizeof(zero));

    /* Compute K1, K2 via ECB encryption of zero block */
    {
        DTHE_AES_Params ecb;
        XMEMSET(&ecb, 0, sizeof(ecb));
        ecb.algoType    = DTHE_AES_ECB_MODE;
        ecb.opType      = DTHE_AES_ENCRYPT;
        ecb.ptrKey      = (uint32_t*)aes->key;
        ecb.keyLen      = AesKeyLenToDthe(aes->keylen);
        ecb.ptrPlainTextData = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)zero);
        ecb.ptrEncryptedData = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)zero);
        ecb.dataLenBytes = WC_AES_BLOCK_SIZE;
        ecb.streamState = DTHE_AES_ONE_SHOT_SUPPORT;
        wolfSSL_TI_lockCCM();
        DTHE_AES_execute(h, &ecb);
        wolfSSL_TI_unlockCCM();
    }

    ShiftAndXorRb(k1, zero);
    ShiftAndXorRb(k2, k1);

    XMEMCPY(lastBlock, cmac->buffer, cmac->bufferSz);
    if (cmac->bufferSz < WC_AES_BLOCK_SIZE) {
        lastBlock[cmac->bufferSz] = 0x80;
        for (i = cmac->bufferSz + 1; i < WC_AES_BLOCK_SIZE; i++)
            lastBlock[i] = 0;
        for (i = 0; i < WC_AES_BLOCK_SIZE; i++)
            lastBlock[i] ^= k2[i];
        algoType = DTHE_AES_CBC_MAC_MODE;
    } else {
        for (i = 0; i < WC_AES_BLOCK_SIZE; i++)
            lastBlock[i] ^= k1[i];
        algoType = DTHE_AES_CMAC_MODE;
    }

    XMEMSET(&params, 0, sizeof(params));
    params.algoType    = algoType;
    params.opType      = DTHE_AES_ENCRYPT;
    params.ptrKey      = (uint32_t*)aes->key;
    params.keyLen      = AesKeyLenToDthe(aes->keylen);
    params.ptrIV       = (uint32_t*)cmac->digest;
    params.ptrPlainTextData = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)lastBlock);
    params.ptrTag      = (uint32_t*)cmac->digest;
    params.dataLenBytes = WC_AES_BLOCK_SIZE;
    params.streamState = DTHE_AES_ONE_SHOT_SUPPORT;

    wolfSSL_TI_lockCCM();
    DTHE_AES_execute(h, &params);
    wolfSSL_TI_unlockCCM();

    if (*outSz > WC_AES_BLOCK_SIZE)
        *outSz = WC_AES_BLOCK_SIZE;
    XMEMCPY(out, cmac->digest, *outSz);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_CmacFinal                                                             */
/* ------------------------------------------------------------------------ */
int wc_CmacFinal(Cmac* cmac, byte* out, word32* outSz)
{
    int ret = wc_CmacFinalNoFree(cmac, out, outSz);
    wc_CmacFree(cmac);
    return ret;
}

/* ------------------------------------------------------------------------ */
/* wc_CmacFree                                                              */
/* ------------------------------------------------------------------------ */
int wc_CmacFree(Cmac* cmac)
{
    if (cmac) ForceZero(cmac, sizeof(*cmac));
    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_AesCmacGenerate                                                       */
/* ------------------------------------------------------------------------ */
int wc_AesCmacGenerate(byte* out, word32* outSz,
                       const byte* in, word32 inSz,
                       const byte* key, word32 keySz)
{
    Cmac cmac;
    int ret;
    XMEMSET(&cmac, 0, sizeof(cmac));
    ret = wc_InitCmac(&cmac, key, keySz, WC_CMAC_AES, NULL);
    if (ret == 0) ret = wc_CmacUpdate(&cmac, in, inSz);
    if (ret == 0) ret = wc_CmacFinal(&cmac, out, outSz);
    return ret;
}

/* ------------------------------------------------------------------------ */
/* wc_AesCmacVerify                                                        */
/* ------------------------------------------------------------------------ */
int wc_AesCmacVerify(const byte* check, word32 checkSz,
                     const byte* in, word32 inSz,
                     const byte* key, word32 keySz)
{
    Cmac cmac;
    byte tmp[WC_AES_BLOCK_SIZE];
    word32 tmpSz = sizeof(tmp);
    int ret;
    XMEMSET(&cmac, 0, sizeof(cmac));
    ret = wc_InitCmac(&cmac, key, keySz, WC_CMAC_AES, NULL);
    if (ret == 0) ret = wc_CmacUpdate(&cmac, in, inSz);
    if (ret == 0) ret = wc_CmacFinal(&cmac, tmp, &tmpSz);
    if (ret == 0 && (tmpSz != checkSz || ConstantCompare(tmp, check, checkSz) != 0))
        ret = MAC_CMP_E;
    return ret;
}

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_TI_CRYPT && WOLFSSL_CMAC && !NO_AES */