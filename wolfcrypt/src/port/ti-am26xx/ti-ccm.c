/* port/ti/ti-ccm.c
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

#if !defined(NO_AES) && defined(WOLFSSL_TI_CRYPT) && defined(HAVE_AESCCM)

#include <stdint.h>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/ti/ti-ccm.h>
#include "ti-am26xx.h"

#include <security_common/drivers/crypto/dthe/dthe.h>
#include <security_common/drivers/crypto/dthe/dthe_aes.h>
#include <drivers/soc.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* ------------------------------------------------------------------------ */
/* Helpers (duplicated from ti-aes.c)                                       */
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

static uint8_t AesCcmMToDthe(word32 authTagSz)
{
    return (uint8_t)((authTagSz - 2) / 2);
}

static uint8_t AesCcmLToDthe(word32 nonceSz)
{
    return (uint8_t)(14 - nonceSz);
}

#ifndef WC_NO_RNG
static WC_INLINE void IncCtr(byte* ctr, word32 ctrSz)
{
    int i;
    for (i = (int)ctrSz - 1; i >= 0; i--)
        if (++ctr[i]) break;
}
#endif

static int AesAuthArgCheck(Aes* aes, byte* out, const byte* in, word32 inSz,
                            const byte* nonce, word32 nonceSz,
                            const byte* authTag, word32 authTagSz, int mode)
{
    if (aes == NULL || nonce == NULL || authTag == NULL)
        return BAD_FUNC_ARG;
    if (inSz != 0 && (out == NULL || in == NULL))
        return BAD_FUNC_ARG;
    switch (authTagSz) {
        case 16:
            break;
        default:
            return BAD_FUNC_ARG;
    }
    switch (nonceSz) {
        case 7: case 8: case 9: case 10: case 11: case 12: case 13: case 14:
            break;
        default:
            return BAD_FUNC_ARG;
    }
    if (mode == DTHE_AES_CCM_MODE) {
        word32 lenSz = (word32)WC_AES_BLOCK_SIZE - 1U - nonceSz;
        if ((lenSz < sizeof(inSz)) && (inSz >= ((word32)1 << (lenSz * 8))))
            return AES_CCM_OVERFLOW_E;
    }
    return 0;
}

static int AesAuthSetKey(Aes* aes, const byte* key, word32 keySz)
{
    byte nonce[WC_AES_BLOCK_SIZE];
    if ((aes == NULL) || (key == NULL))
        return BAD_FUNC_ARG;
    if (!((keySz == 16) || (keySz == 24) || (keySz == 32)))
        return BAD_FUNC_ARG;
    XMEMSET(nonce, 0, sizeof(nonce));
    return wc_AesSetKey(aes, key, keySz, nonce, AES_ENCRYPTION);
}

static int AesAuthEncrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                           const byte* nonce, word32 nonceSz,
                           byte* authTag, word32 authTagSz,
                           const byte* authIn, word32 authInSz, int mode)
{
    int ret;
    DTHE_AES_Params params;
    DTHE_Handle h = (DTHE_Handle)wolfSSL_TI_getDtheHandle();
    word32 tmpTag[WC_AES_BLOCK_SIZE / sizeof(word32)];
    word32 ivBlock[WC_AES_BLOCK_SIZE / sizeof(word32)];
    uint32_t algoType = (mode == DTHE_AES_CCM_MODE) ? DTHE_AES_CCM_MODE
                                                     : DTHE_AES_GCM_MODE;

    if (h == NULL) return WC_HW_E;
    ret = AesAuthArgCheck(aes, out, in, inSz, nonce, nonceSz, authTag,
                          authTagSz, algoType);
    if (ret != 0) return ret;
    if ((authIn == NULL) && (authInSz > 0)) return BAD_FUNC_ARG;

    if (inSz == 0 && authInSz == 0) {
        DTHE_AES_Params ecb;
        XMEMSET(&ecb, 0, sizeof(ecb));
        ecb.algoType = DTHE_AES_ECB_MODE;
        ecb.opType   = DTHE_AES_ENCRYPT;
        ecb.ptrKey   = (uint32_t*)aes->key;
        ecb.keyLen   = AesKeyLenToDthe(aes->keylen);
        ecb.ptrPlainTextData = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)aes->reg);
        ecb.ptrEncryptedData = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)tmpTag);
        ecb.dataLenBytes = WC_AES_BLOCK_SIZE;
        ecb.streamState  = DTHE_AES_ONE_SHOT_SUPPORT;
        wolfSSL_TI_lockCCM();
        ret = DTHE_AES_execute(h, &ecb);
        wolfSSL_TI_unlockCCM();
        if (ret != DTHE_AES_RETURN_SUCCESS) return WC_HW_E;
        XMEMCPY(authTag, tmpTag, authTagSz);
        return 0;
    }

    /* DTHE_AES_setIV() always writes all 4 IV registers (16 bytes), but
     * nonce is only nonceSz (7-14) bytes, so it must be expanded into a
     * full 16-byte J0 block rather than passed as-is (which reads past
     * the end of the caller's nonce buffer). For the standard 96-bit GCM
     * nonce, J0 = nonce || 0x00000001, matching NIST SP 800-38D and TI's
     * own DTHE GCM examples (mode 3 expects a pre-built J0, it does not
     * derive it from a raw IV in hardware). */
    XMEMSET(ivBlock, 0, sizeof(ivBlock));
    XMEMCPY(ivBlock, nonce, nonceSz);
    if ((algoType == DTHE_AES_GCM_MODE) && (nonceSz == GCM_NONCE_MID_SZ))
        ((byte*)ivBlock)[WC_AES_BLOCK_SIZE - 1] = 0x01;

    XMEMSET(&params, 0, sizeof(params));
    params.algoType     = algoType;
    params.opType       = DTHE_AES_ENCRYPT;
    params.ptrKey       = (uint32_t*)aes->key;
    params.keyLen       = AesKeyLenToDthe(aes->keylen);
    params.ptrIV        = ivBlock;
    params.ptrPlainTextData  = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)in);
    params.ptrEncryptedData  = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)out);
    params.dataLenBytes = inSz;
    params.ptrTag       = (uint32_t*)tmpTag;
    params.ptrAAD       = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)authIn);
    params.aadLength    = authInSz;
    params.counterWidth = DTHE_AES_CTR_WIDTH_32;
    params.streamState  = DTHE_AES_ONE_SHOT_SUPPORT;
    params.modeSelect   = DTHE_AES_NO_MODE;
    if (algoType == DTHE_AES_CCM_MODE) {
        params.ccmL = AesCcmLToDthe(nonceSz);
        params.ccmM = AesCcmMToDthe(authTagSz);
    }

    wolfSSL_TI_lockCCM();
    ret = DTHE_AES_execute(h, &params);
    wolfSSL_TI_unlockCCM();

    if (ret != DTHE_AES_RETURN_SUCCESS) {
        XMEMSET(out, 0, inSz);
        XMEMSET(authTag, 0, authTagSz);
        return AES_GCM_AUTH_E;
    }
    XMEMCPY(authTag, tmpTag, authTagSz);
    return 0;
}

static int AesAuthDecrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                           const byte* nonce, word32 nonceSz,
                           const byte* authTag, word32 authTagSz,
                           const byte* authIn, word32 authInSz, int mode)
{
    int ret;
    DTHE_AES_Params params;
    DTHE_Handle h = (DTHE_Handle)wolfSSL_TI_getDtheHandle();
    word32 tmpTag[WC_AES_BLOCK_SIZE / sizeof(word32)];
    word32 ivBlock[WC_AES_BLOCK_SIZE / sizeof(word32)];
    uint32_t algoType = (mode == DTHE_AES_CCM_MODE) ? DTHE_AES_CCM_MODE
                                                     : DTHE_AES_GCM_MODE;

    if (h == NULL) return WC_HW_E;
    ret = AesAuthArgCheck(aes, out, in, inSz, nonce, nonceSz, authTag,
                          authTagSz, algoType);
    if (ret != 0) return ret;
    if ((authIn == NULL) && (authInSz > 0)) return BAD_FUNC_ARG;

    if (inSz == 0 && authInSz == 0) {
        DTHE_AES_Params ecb;
        XMEMSET(&ecb, 0, sizeof(ecb));
        ecb.algoType = DTHE_AES_ECB_MODE;
        ecb.opType   = DTHE_AES_ENCRYPT;
        ecb.ptrKey   = (uint32_t*)aes->key;
        ecb.keyLen   = AesKeyLenToDthe(aes->keylen);
        ecb.ptrPlainTextData = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)aes->reg);
        ecb.ptrEncryptedData = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)tmpTag);
        ecb.dataLenBytes = WC_AES_BLOCK_SIZE;
        ecb.streamState  = DTHE_AES_ONE_SHOT_SUPPORT;
        wolfSSL_TI_lockCCM();
        ret = DTHE_AES_execute(h, &ecb);
        wolfSSL_TI_unlockCCM();
        if (ret != DTHE_AES_RETURN_SUCCESS) return WC_HW_E;
        return (ConstantCompare(authTag, (byte*)tmpTag, authTagSz) == 0) ? 0
                                                                  : AES_GCM_AUTH_E;
    }

    /* See AesAuthEncrypt() above: nonce must be expanded into a full
     * 16-byte J0 block before being handed to the DTHE IV registers. */
    XMEMSET(ivBlock, 0, sizeof(ivBlock));
    XMEMCPY(ivBlock, nonce, nonceSz);
    if ((algoType == DTHE_AES_GCM_MODE) && (nonceSz == GCM_NONCE_MID_SZ))
        ((byte*)ivBlock)[WC_AES_BLOCK_SIZE - 1] = 0x01;

    XMEMSET(&params, 0, sizeof(params));
    params.algoType     = algoType;
    params.opType       = DTHE_AES_DECRYPT;
    params.ptrKey       = (uint32_t*)aes->key;
    params.keyLen       = AesKeyLenToDthe(aes->keylen);
    params.ptrIV        = ivBlock;
    params.ptrPlainTextData  = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)out);
    params.ptrEncryptedData  = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)in);
    params.dataLenBytes = inSz;
    params.ptrTag       = (uint32_t*)tmpTag;
    params.ptrAAD       = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)authIn);
    params.aadLength    = authInSz;
    params.counterWidth = DTHE_AES_CTR_WIDTH_32;
    params.streamState  = DTHE_AES_ONE_SHOT_SUPPORT;
    params.modeSelect   = DTHE_AES_NO_MODE;
    if (algoType == DTHE_AES_CCM_MODE) {
        params.ccmL = AesCcmLToDthe(nonceSz);
        params.ccmM = AesCcmMToDthe(authTagSz);
    }

    wolfSSL_TI_lockCCM();
    ret = DTHE_AES_execute(h, &params);
    wolfSSL_TI_unlockCCM();

    if ((ret != DTHE_AES_RETURN_SUCCESS) ||
        (ConstantCompare(authTag, (byte*)tmpTag, authTagSz) != 0)) {
        XMEMSET(out, 0, inSz);
        return AES_GCM_AUTH_E;
    }
    return 0;
}

/* ======================================================================== */
/* CCM                                                                      */
/* ======================================================================== */

int wc_AesCcmSetKey(Aes* aes, const byte* key, word32 keySz)
{
    return AesAuthSetKey(aes, key, keySz);
}

int wc_AesCcmEncrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                     const byte* nonce, word32 nonceSz,
                     byte* authTag, word32 authTagSz,
                     const byte* authIn, word32 authInSz)
{
    return AesAuthEncrypt(aes, out, in, inSz, nonce, nonceSz,
                          authTag, authTagSz, authIn, authInSz,
                          DTHE_AES_CCM_MODE);
}

int wc_AesCcmDecrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                     const byte* nonce, word32 nonceSz,
                     const byte* authTag, word32 authTagSz,
                     const byte* authIn, word32 authInSz)
{
    return AesAuthDecrypt(aes, out, in, inSz, nonce, nonceSz,
                          authTag, authTagSz, authIn, authInSz,
                          DTHE_AES_CCM_MODE);
}

#ifndef WC_NO_RNG
int wc_AesCcmSetNonce(Aes* aes, const byte* nonce, word32 nonceSz)
{
    int ret = 0;
    if (aes == NULL || nonce == NULL ||
        nonceSz < CCM_NONCE_MIN_SZ || nonceSz > CCM_NONCE_MAX_SZ)
        ret = BAD_FUNC_ARG;
    if (ret == 0) {
        XMEMCPY(aes->reg, nonce, nonceSz);
        aes->nonceSz = nonceSz;
        aes->invokeCtr[0] = 0;
        aes->invokeCtr[1] = 0xE0000000;
    }
    return ret;
}

int wc_AesCcmEncrypt_ex(Aes* aes, byte* out, const byte* in, word32 sz,
                        byte* ivOut, word32 ivOutSz,
                        byte* authTag, word32 authTagSz,
                        const byte* authIn, word32 authInSz)
{
    int ret = 0;
    if (aes == NULL || out == NULL || (in == NULL && sz != 0) ||
        ivOut == NULL || (authIn == NULL && authInSz != 0) ||
        (ivOutSz != aes->nonceSz))
        ret = BAD_FUNC_ARG;
    if (ret == 0) {
        aes->invokeCtr[0]++;
        if (aes->invokeCtr[0] == 0) {
            aes->invokeCtr[1]++;
            if (aes->invokeCtr[1] == 0) ret = AES_CCM_OVERFLOW_E;
        }
    }
    if (ret == 0) {
        ret = wc_AesCcmEncrypt(aes, out, in, sz, (byte*)aes->reg, aes->nonceSz,
                               authTag, authTagSz, authIn, authInSz);
        if (ret == 0) {
            XMEMCPY(ivOut, aes->reg, aes->nonceSz);
            IncCtr((byte*)aes->reg, aes->nonceSz);
        }
    }
    return ret;
}
#endif /* !WC_NO_RNG */

#endif /* !NO_AES && WOLFSSL_TI_CRYPT && HAVE_AESCCM */
