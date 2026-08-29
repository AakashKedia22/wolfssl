/* port/ti/ti-gcm.c
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

#if !defined(NO_AES) && defined(WOLFSSL_TI_CRYPT) && defined(HAVE_AESGCM)

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

#ifndef NO_RNG
static WC_INLINE void IncCtr(byte* ctr, word32 ctrSz)
{
    int i;
    for (i = (int)ctrSz - 1; i >= 0; i--)
        if (++ctr[i]) break;
}
#endif

/* wolfCrypt's own self-tests exercise GCM IV lengths well outside the
 * 7-14 byte range the IV||0x1 fast path supports (test.c's
 * ENABLE_NON_12BYTE_IV_TEST loop runs ivlen 1..31). Bound accepted IV
 * lengths, and AesGcmDeriveJ0()'s scratch buffer, to comfortably cover
 * that range. */
#define TI_GCM_IV_MAX_SZ 64

static int AesAuthArgCheck(Aes* aes, byte* out, const byte* in, word32 inSz,
                            const byte* nonce, word32 nonceSz,
                            const byte* authTag, word32 authTagSz, int mode)
{
    if (aes == NULL || nonce == NULL || authTag == NULL)
        return BAD_FUNC_ARG;
    if (inSz != 0 && (out == NULL || in == NULL))
        return BAD_FUNC_ARG;
    switch (authTagSz) {
        case 4: case 8: case 12: case 13: case 14: case 15: case 16:
            break;
        default:
            return BAD_FUNC_ARG;
    }
    /* GCM allows any non-zero IV length (NIST SP 800-38D Sec. 8.2); the
     * 12-byte case uses the IV||0x1 fast path, anything else is handled
     * via AesGcmDeriveJ0()'s hardware GHASH-based J0 derivation. CCM's
     * narrower 7-13 byte nonce requirement is enforced by ti-ccm.c's own
     * copy of this check - the CCM branch below is unreachable from this
     * file, since every caller here always passes DTHE_AES_GCM_MODE. */
    if ((nonceSz == 0) || (nonceSz > TI_GCM_IV_MAX_SZ))
        return BAD_FUNC_ARG;
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

/* Derive J0 (the GCM initial counter block) from an arbitrary-length IV
 * per NIST SP 800-38D Sec. 7.1, using the same three-step hardware
 * recipe TI demonstrates in test_aes_gcm_nist_unaligned_iv()
 * (tifs test_dthe_aes_gcm_aad.c):
 *   1. H = AES_ECB_Encrypt(key, 0^128)
 *   2. J0 = GHASH(H, IV zero-padded to a 16-byte multiple || len(IV)),
 *      computed directly by DTHE's GHASH-only mode - DTHE_AES_execute()
 *      already zero-pads any partial trailing block for non-ECB/CBC
 *      algoTypes, so the raw (unpadded) IV can be passed as-is.
 * hOut receives H (needed again by the caller for the main GCM op via
 * DTHE_AES_GCM_MODE_2); j0Out receives J0. DTHE never derives J0 from a
 * raw IV internally (confirmed in dthe_aes.c: DTHE_AES_setIV() always
 * just writes whatever ptrIV it's given), so this must be done by the
 * caller for any IV length other than the standard 12-byte case. */
static int AesGcmDeriveJ0(Aes* aes, const byte* nonce, word32 nonceSz,
                           byte* hOut, byte* j0Out)
{
    DTHE_AES_Params ecbParams;
    DTHE_AES_Params ghashParams;
    DTHE_Handle h = (DTHE_Handle)wolfSSL_TI_getDtheHandle();
    byte zero[WC_AES_BLOCK_SIZE];
    byte scratch[TI_GCM_IV_MAX_SZ];
    int ret;

    if (h == NULL) return WC_HW_E;
    if (nonceSz > TI_GCM_IV_MAX_SZ) return BAD_FUNC_ARG;

    XMEMSET(zero, 0, sizeof(zero));

    wolfSSL_TI_lockCCM();
    if (DTHE_AES_open(h) != DTHE_AES_RETURN_SUCCESS) {
        wolfSSL_TI_unlockCCM();
        return WC_HW_E;
    }
    wolfSSL_TI_unlockCCM();

    XMEMSET(&ecbParams, 0, sizeof(ecbParams));
    ecbParams.algoType         = DTHE_AES_ECB_MODE;
    ecbParams.opType           = DTHE_AES_ENCRYPT;
    ecbParams.ptrKey           = (uint32_t*)aes->key;
    ecbParams.keyLen           = AesKeyLenToDthe(aes->keylen);
    ecbParams.ptrPlainTextData = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)zero);
    ecbParams.ptrEncryptedData = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)hOut);
    ecbParams.dataLenBytes     = WC_AES_BLOCK_SIZE;
    ecbParams.streamState      = DTHE_AES_ONE_SHOT_SUPPORT;

    wolfSSL_TI_lockCCM();
    ret = DTHE_AES_execute(h, &ecbParams);
    if (ret != DTHE_AES_RETURN_SUCCESS) {
        wolfSSL_TI_unlockCCM();
        return WC_HW_E;
    }

    wolfSSL_TI_lockCCM();
    DTHE_AES_close(h);
    wolfSSL_TI_unlockCCM();

    wolfSSL_TI_lockCCM();
    if (DTHE_AES_open(h) != DTHE_AES_RETURN_SUCCESS) {
        wolfSSL_TI_unlockCCM();
        return WC_HW_E;
    }
    wolfSSL_TI_unlockCCM();

    XMEMSET(&ghashParams, 0, sizeof(ghashParams));
    ghashParams.algoType         = DTHE_AES_GHASH_ONLY_MODE;
    ghashParams.modeSelect       = DTHE_AES_GCM_MODE_1;
    ghashParams.opType           = DTHE_AES_DECRYPT;
    ghashParams.ptrKey           = (uint32_t*)aes->key;
    ghashParams.ptrKey1          = (uint32_t*)hOut;
    ghashParams.keyLen           = AesKeyLenToDthe(aes->keylen);
    ghashParams.ptrIV            = NULL;
    ghashParams.ptrEncryptedData = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)nonce);
    ghashParams.ptrPlainTextData = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)scratch);
    ghashParams.dataLenBytes     = nonceSz;
    ghashParams.ptrTag           = (uint32_t*)j0Out;
    ghashParams.ptrAAD           = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)zero);
    ghashParams.aadLength        = 0;
    ghashParams.streamState      = DTHE_AES_ONE_SHOT_SUPPORT;

    ret = DTHE_AES_execute(h, &ghashParams);
    wolfSSL_TI_unlockCCM();

    wolfSSL_TI_lockCCM();
    DTHE_AES_close(h);
    wolfSSL_TI_unlockCCM();

    wolfSSL_TI_lockCCM();
    if (DTHE_AES_open(h) != DTHE_AES_RETURN_SUCCESS) {
        wolfSSL_TI_unlockCCM();
        return WC_HW_E;
    }
    wolfSSL_TI_unlockCCM();

    return (ret == DTHE_AES_RETURN_SUCCESS) ? 0 : WC_HW_E;
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
    byte hSubkey[WC_AES_BLOCK_SIZE];
    uint32_t modeSelect = DTHE_AES_NO_MODE;
    uint32_t algoType = (mode == DTHE_AES_CCM_MODE) ? DTHE_AES_CCM_MODE
                                                     : DTHE_AES_GCM_MODE;

    if (h == NULL) return WC_HW_E;
    ret = AesAuthArgCheck(aes, out, in, inSz, nonce, nonceSz, authTag,
                          authTagSz, algoType);
    if (ret != 0) return ret;
    if ((authIn == NULL) && (authInSz > 0)) return BAD_FUNC_ARG;

    /* DTHE_AES_setIV() always writes all 4 IV registers (16 bytes), but
     * nonce is only nonceSz bytes, so it must be expanded into a full
     * 16-byte J0 block rather than passed as-is (which reads past the end
     * of the caller's nonce buffer). For the standard 96-bit GCM nonce,
     * J0 = nonce || 0x00000001, matching NIST SP 800-38D and TI's own
     * DTHE GCM examples (mode 3 expects a pre-built J0, it does not
     * derive it from a raw IV in hardware). Any other IV length needs
     * the hardware-GHASH-based J0 derivation in AesGcmDeriveJ0(). Computed
     * up front since the empty-input fast path below also needs J0. */
    if ((algoType == DTHE_AES_GCM_MODE) && (nonceSz != GCM_NONCE_MID_SZ)) {
        ret = AesGcmDeriveJ0(aes, nonce, nonceSz, hSubkey, (byte*)ivBlock);
        if (ret != 0) return ret;
        modeSelect = DTHE_AES_GCM_MODE_2;
    }
    else {
        XMEMSET(ivBlock, 0, sizeof(ivBlock));
        XMEMCPY(ivBlock, nonce, nonceSz);
        if (algoType == DTHE_AES_GCM_MODE)
            ((byte*)ivBlock)[WC_AES_BLOCK_SIZE - 1] = 0x01;
    }

    /* GCM defines Tag = MSB(GHASH_H(A || C || len(A) || len(C)) XOR
     * CIPH_K(J0)); when both A and C are empty, GHASH's input collapses to
     * a single all-zero block, so GHASH_H(0^128) = 0 and the tag reduces
     * to CIPH_K(J0) directly (NIST SP 800-38D Sec. 7.1). The DTHE hardware
     * GCM/GHASH modes refuse dataLenBytes == 0 together with aadLength ==
     * 0 (DTHE_AES_validateExecuteParams() in the TI SDK), so this case is
     * computed with a plain ECB encrypt of the already-derived J0 instead
     * of going through the hardware GCM path. */
    if ((algoType == DTHE_AES_GCM_MODE) && inSz == 0 && authInSz == 0) {
        DTHE_AES_Params ecb;
        XMEMSET(&ecb, 0, sizeof(ecb));
        ecb.algoType = DTHE_AES_ECB_MODE;
        ecb.opType   = DTHE_AES_ENCRYPT;
        ecb.ptrKey   = (uint32_t*)aes->key;
        ecb.keyLen   = AesKeyLenToDthe(aes->keylen);
        ecb.ptrPlainTextData = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)ivBlock);
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

    {
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
        params.modeSelect   = modeSelect;
        if (modeSelect == DTHE_AES_GCM_MODE_2)
            params.ptrKey1 = (uint32_t*)hSubkey;
        if (algoType == DTHE_AES_CCM_MODE) {
            params.ccmL = AesCcmLToDthe(nonceSz);
            params.ccmM = AesCcmMToDthe(authTagSz);
        }

        wolfSSL_TI_lockCCM();
        ret = DTHE_AES_execute(h, &params);
        wolfSSL_TI_unlockCCM();
    }

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
    byte hSubkey[WC_AES_BLOCK_SIZE];
    uint32_t modeSelect = DTHE_AES_NO_MODE;
    uint32_t algoType = (mode == DTHE_AES_CCM_MODE) ? DTHE_AES_CCM_MODE
                                                     : DTHE_AES_GCM_MODE;

    if (h == NULL) return WC_HW_E;
    ret = AesAuthArgCheck(aes, out, in, inSz, nonce, nonceSz, authTag,
                          authTagSz, algoType);
    if (ret != 0) return ret;
    if ((authIn == NULL) && (authInSz > 0)) return BAD_FUNC_ARG;

    /* See AesAuthEncrypt() above: nonce must be expanded into a full
     * 16-byte J0 block before being handed to the DTHE IV registers,
     * deriving it via hardware GHASH for any length other than the
     * standard 12-byte case. Computed up front since the empty-input
     * fast path below also needs J0. */
    if ((algoType == DTHE_AES_GCM_MODE) && (nonceSz != GCM_NONCE_MID_SZ)) {
        ret = AesGcmDeriveJ0(aes, nonce, nonceSz, hSubkey, (byte*)ivBlock);
        if (ret != 0) return ret;
        modeSelect = DTHE_AES_GCM_MODE_2;
    }
    else {
        XMEMSET(ivBlock, 0, sizeof(ivBlock));
        XMEMCPY(ivBlock, nonce, nonceSz);
        if (algoType == DTHE_AES_GCM_MODE)
            ((byte*)ivBlock)[WC_AES_BLOCK_SIZE - 1] = 0x01;
    }

    /* See AesAuthEncrypt() above: with both A and C empty, Tag reduces to
     * CIPH_K(J0) directly, and the DTHE hardware GCM/GHASH modes refuse
     * dataLenBytes == 0 with aadLength == 0, so verify by recomputing
     * CIPH_K(J0) via plain ECB instead of the hardware GCM path. */
    if ((algoType == DTHE_AES_GCM_MODE) && inSz == 0 && authInSz == 0) {
        DTHE_AES_Params ecb;
        XMEMSET(&ecb, 0, sizeof(ecb));
        ecb.algoType = DTHE_AES_ECB_MODE;
        ecb.opType   = DTHE_AES_ENCRYPT;
        ecb.ptrKey   = (uint32_t*)aes->key;
        ecb.keyLen   = AesKeyLenToDthe(aes->keylen);
        ecb.ptrPlainTextData = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)ivBlock);
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

    {
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
        params.modeSelect   = modeSelect;
        if (modeSelect == DTHE_AES_GCM_MODE_2)
            params.ptrKey1 = (uint32_t*)hSubkey;
        if (algoType == DTHE_AES_CCM_MODE) {
            params.ccmL = AesCcmLToDthe(nonceSz);
            params.ccmM = AesCcmMToDthe(authTagSz);
        }

        wolfSSL_TI_lockCCM();
        ret = DTHE_AES_execute(h, &params);
        wolfSSL_TI_unlockCCM();
    }

    if ((ret != DTHE_AES_RETURN_SUCCESS) ||
        (ConstantCompare(authTag, (byte*)tmpTag, authTagSz) != 0)) {
        XMEMSET(out, 0, inSz);
        return AES_GCM_AUTH_E;
    }
    return 0;
}

/* ======================================================================== */
/* GCM                                                                      */
/* ======================================================================== */

int wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len)
{
    return AesAuthSetKey(aes, key, len);
}

int wc_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                     const byte* iv, word32 ivSz,
                     byte* authTag, word32 authTagSz,
                     const byte* authIn, word32 authInSz)
{
    int ret = wc_local_AesGcmCheckTagSz(authTagSz);
    if (ret != 0) return ret;
    return AesAuthEncrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz,
                          authIn, authInSz, DTHE_AES_GCM_MODE);
}

#if defined(HAVE_AES_DECRYPT) || defined(HAVE_AESGCM_DECRYPT)
int wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                     const byte* iv, word32 ivSz,
                     const byte* authTag, word32 authTagSz,
                     const byte* authIn, word32 authInSz)
{
    return AesAuthDecrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz,
                          authIn, authInSz, DTHE_AES_GCM_MODE);
}
#endif

int wc_GmacSetKey(Gmac* gmac, const byte* key, word32 len)
{
    if (gmac == NULL) return BAD_FUNC_ARG;
    return AesAuthSetKey(&gmac->aes, key, len);
}

int wc_GmacUpdate(Gmac* gmac, const byte* iv, word32 ivSz,
                  const byte* authIn, word32 authInSz,
                  byte* authTag, word32 authTagSz)
{
    if (gmac == NULL) return BAD_FUNC_ARG;
    return AesAuthEncrypt(&gmac->aes, NULL, NULL, 0, iv, ivSz,
                          authTag, authTagSz, authIn, authInSz,
                          DTHE_AES_GCM_MODE);
}

#ifndef NO_RNG
static WC_INLINE int CheckAesGcmIvSize(int ivSz)
{
    return (ivSz == GCM_NONCE_MIN_SZ ||
            ivSz == GCM_NONCE_MID_SZ ||
            ivSz == GCM_NONCE_MAX_SZ);
}

int wc_AesGcmSetIV(Aes* aes, word32 ivSz,
                   const byte* ivFixed, word32 ivFixedSz,
                   WC_RNG* rng)
{
    int ret = 0;
    if (aes == NULL || rng == NULL || !CheckAesGcmIvSize((int)ivSz) ||
        (ivFixed == NULL && ivFixedSz != 0) ||
        (ivFixed != NULL && ivFixedSz != AES_IV_FIXED_SZ))
        ret = BAD_FUNC_ARG;
    if (ret == 0) {
        byte* iv = (byte*)aes->reg;
        if (ivFixedSz) XMEMCPY(iv, ivFixed, ivFixedSz);
        ret = wc_RNG_GenerateBlock(rng, iv + ivFixedSz, ivSz - ivFixedSz);
    }
    if (ret == 0) {
        aes->invokeCtr[0] = 0;
        aes->invokeCtr[1] = (ivSz == GCM_NONCE_MID_SZ) ? 0 : 0xFFFFFFFF;
    #ifdef WOLFSSL_AESGCM_STREAM
        aes->ctrSet = 1;
    #endif
        aes->nonceSz = ivSz;
    }
    return ret;
}

int wc_AesGcmEncrypt_ex(Aes* aes, byte* out, const byte* in, word32 sz,
                        byte* ivOut, word32 ivOutSz,
                        byte* authTag, word32 authTagSz,
                        const byte* authIn, word32 authInSz)
{
    int ret = 0;
    if (aes == NULL || (sz != 0 && (in == NULL || out == NULL)) ||
        ivOut == NULL || ivOutSz != aes->nonceSz ||
        (authIn == NULL && authInSz != 0))
        ret = BAD_FUNC_ARG;
    if (ret == 0) {
        aes->invokeCtr[0]++;
        if (aes->invokeCtr[0] == 0) {
            aes->invokeCtr[1]++;
            if (aes->invokeCtr[1] == 0) ret = AES_GCM_OVERFLOW_E;
        }
    }
    if (ret == 0) {
        XMEMCPY(ivOut, aes->reg, ivOutSz);
        ret = wc_AesGcmEncrypt(aes, out, in, sz, (byte*)aes->reg, ivOutSz,
                               authTag, authTagSz, authIn, authInSz);
        if (ret == 0) IncCtr((byte*)aes->reg, ivOutSz);
    }
    return ret;
}

int wc_Gmac(const byte* key, word32 keySz, byte* iv, word32 ivSz,
            const byte* authIn, word32 authInSz,
            byte* authTag, word32 authTagSz, WC_RNG* rng)
{
    WC_DECLARE_VAR(aes, Aes, 1, 0);
    int ret;
    if (key == NULL || iv == NULL || (authIn == NULL && authInSz != 0) ||
        authTag == NULL || authTagSz == 0 || rng == NULL)
        return BAD_FUNC_ARG;
#ifdef WOLFSSL_SMALL_STACK
    if ((aes = (Aes*)XMALLOC(sizeof *aes, NULL, DYNAMIC_TYPE_AES)) == NULL)
        return MEMORY_E;
#endif
    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_AesGcmSetKey(aes, key, keySz);
    if (ret == 0)
        ret = wc_AesGcmSetIV(aes, ivSz, NULL, 0, rng);
    if (ret == 0)
        ret = wc_AesGcmEncrypt_ex(aes, NULL, NULL, 0, iv, ivSz,
                                  authTag, authTagSz, authIn, authInSz);
    wc_AesFree(aes);
    ForceZero(aes, sizeof *aes);
    WC_FREE_VAR_EX(aes, NULL, DYNAMIC_TYPE_AES);
    return ret;
}

int wc_GmacVerify(const byte* key, word32 keySz,
                  const byte* iv, word32 ivSz,
                  const byte* authIn, word32 authInSz,
                  const byte* authTag, word32 authTagSz)
{
    int ret;
#ifdef HAVE_AES_DECRYPT
    WC_DECLARE_VAR(aes, Aes, 1, 0);
    if (key == NULL || iv == NULL || (authIn == NULL && authInSz != 0) ||
        authTag == NULL || authTagSz == 0 || authTagSz > WC_AES_BLOCK_SIZE)
        return BAD_FUNC_ARG;
#ifdef WOLFSSL_SMALL_STACK
    if ((aes = (Aes*)XMALLOC(sizeof *aes, NULL, DYNAMIC_TYPE_AES)) == NULL)
        return MEMORY_E;
#endif
    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(aes, key, keySz);
        if (ret == 0)
            ret = wc_AesGcmDecrypt(aes, NULL, NULL, 0, iv, ivSz,
                                   authTag, authTagSz, authIn, authInSz);
        wc_AesFree(aes);
    }
    ForceZero(aes, sizeof *aes);
    WC_FREE_VAR_EX(aes, NULL, DYNAMIC_TYPE_AES);
#else
    (void)key; (void)keySz; (void)iv; (void)ivSz;
    (void)authIn; (void)authInSz; (void)authTag; (void)authTagSz;
    ret = NOT_COMPILED_IN;
#endif
    return ret;
}
#endif /* !NO_RNG */

#endif /* !NO_AES && WOLFSSL_TI_CRYPT && HAVE_AESGCM */
