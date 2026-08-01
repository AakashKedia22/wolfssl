/* port/ti/ti-aes.c
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

#if (defined(WOLFSSL_TI_CRYPT) && !defined(NO_AES)) || \
    (defined(WOLFSSL_TI_HASH) && !defined(NO_HMAC))

#include <stdbool.h>
#include <stdint.h>

#include <wolfssl/wolfcrypt/port/ti/ti-ccm.h>
#include "ti-am26xx.h"

#ifndef SINGLE_THREADED
#include <wolfssl/wolfcrypt/wc_port.h>
#endif

#include <security_common/drivers/crypto/dthe/dthe.h>
#include <security_common/drivers/crypto/dthe/dthe_aes.h>
#include <security_common/drivers/crypto/dthe/dthe_sha.h>
#include <drivers/soc.h>

#if defined(WOLFSSL_TI_CRYPT) && !defined(TI_DUMMY_BUILD)
#include <security_common/drivers/crypto/asym_crypt.h>
#endif

#endif

#if !defined(NO_AES) && defined(WOLFSSL_TI_CRYPT)

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>


#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* ------------------------------------------------------------------------ */
/* DTHE init, handle, and mutex (shared with ti-hash.c via ti-ccm.h)        */
/* ------------------------------------------------------------------------ */

static DTHE_Handle gDtheHandle = NULL;
static bool        gDtheInit   = false;

#ifndef SINGLE_THREADED
    static wolfSSL_Mutex gDtheMutex;
#endif
#ifndef TI_DUMMY_BUILD

int wolfSSL_TI_CCMInit(void)
{
    if (gDtheInit)
        return true;
    gDtheInit = true;

    DTHE_init();
    gDtheHandle = DTHE_open(0);
    if (gDtheHandle == NULL) {
        gDtheInit = false;
        return false;
    }

    if (DTHE_AES_open(gDtheHandle) != DTHE_AES_RETURN_SUCCESS) {
        DTHE_close(gDtheHandle);
        gDtheHandle = NULL;
        gDtheInit = false;
        return false;
    }

    if (DTHE_SHA_open(gDtheHandle) != DTHE_SHA_RETURN_SUCCESS) {
        DTHE_AES_close(gDtheHandle);
        DTHE_close(gDtheHandle);
        gDtheHandle = NULL;
        gDtheInit = false;
        return false;
    }

#ifndef SINGLE_THREADED
    if (wc_InitMutex(&gDtheMutex)) {
        DTHE_SHA_close(gDtheHandle);
        DTHE_AES_close(gDtheHandle);
        DTHE_close(gDtheHandle);
        gDtheHandle = NULL;
        gDtheInit = false;
        return false;
    }
#endif

    return true;
}

void* wolfSSL_TI_getDtheHandle(void)
{
    return (void*)gDtheHandle;
}

#ifdef WOLFSSL_TI_CRYPT
void* wolfSSL_TI_getAsymCryptHandle(void)
{
    static AsymCrypt_Handle gAsymHandle = NULL;

    if (!wolfSSL_TI_CCMInit())
        return NULL;

    if (gAsymHandle == NULL) {
        wolfSSL_TI_lockCCM();
        if (gAsymHandle == NULL)
            gAsymHandle = AsymCrypt_open(0);
        wolfSSL_TI_unlockCCM();
    }

    return (void*)gAsymHandle;
}
#endif /* WOLFSSL_TI_CRYPT */

#ifndef SINGLE_THREADED
void wolfSSL_TI_lockCCM(void)
{
    wc_LockMutex(&gDtheMutex);
}

void wolfSSL_TI_unlockCCM(void)
{
    wc_UnLockMutex(&gDtheMutex);
}
#endif

#endif /* TI_DUMMY_BUILD */

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
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

static int AesSetIV(Aes* aes, const byte* iv)
{
    if (aes == NULL)
        return BAD_FUNC_ARG;
    if (iv)
        XMEMCPY(aes->reg, iv, WC_AES_BLOCK_SIZE);
    else
        XMEMSET(aes->reg, 0, WC_AES_BLOCK_SIZE);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Key management                                                           */
/* ------------------------------------------------------------------------ */

int wc_AesSetKey(Aes* aes, const byte* key, word32 len, const byte* iv, int dir)
{
    if (!wolfSSL_TI_CCMInit())
        return WC_HW_E;
    if ((aes == NULL) || (key == NULL))
        return BAD_FUNC_ARG;
    if (!((dir == AES_ENCRYPTION) || (dir == AES_DECRYPTION)))
        return BAD_FUNC_ARG;

    switch (len) {
    #ifdef WOLFSSL_AES_128
        case 16: break;
    #endif
    #ifdef WOLFSSL_AES_192
        case 24: break;
    #endif
    #ifdef WOLFSSL_AES_256
        case 32: break;
    #endif
        default: return BAD_FUNC_ARG;
    }
    aes->keylen = len;
    aes->rounds = len / 4 + 6;
    XMEMCPY(aes->key, key, len);

#if defined(WOLFSSL_AES_COUNTER) || defined(WOLFSSL_AES_CFB) || \
    defined(WOLFSSL_AES_OFB) || defined(WOLFSSL_AES_XTS)
    aes->left = 0;
#endif
    return AesSetIV(aes, iv);
}

int wc_AesGetKeySize(Aes* aes, word32* keySize)
{
    int ret = 0;
    if (aes == NULL || keySize == NULL)
        return BAD_FUNC_ARG;
    switch (aes->rounds) {
#ifdef WOLFSSL_AES_128
    case 10: *keySize = 16; break;
#endif
#ifdef WOLFSSL_AES_192
    case 12: *keySize = 24; break;
#endif
#ifdef WOLFSSL_AES_256
    case 14: *keySize = 32; break;
#endif
    default: *keySize = 0; ret = BAD_FUNC_ARG;
    }
    return ret;
}

/* ------------------------------------------------------------------------ */
/* Core AES one-shot helper                                                 */
/* ------------------------------------------------------------------------ */

static int AesOneShot(Aes* aes, byte* out, const byte* in, word32 sz,
                      uint32_t opType, uint32_t algoType)
{
    DTHE_AES_Params params;
    DTHE_Handle h = (DTHE_Handle)wolfSSL_TI_getDtheHandle();

    if (h == NULL) return WC_HW_E;
    if ((aes == NULL) || (in == NULL) || (out == NULL)) return BAD_FUNC_ARG;

    XMEMSET(&params, 0, sizeof(params));
    params.algoType     = algoType;
    params.opType       = opType;
    params.ptrKey       = (uint32_t*)aes->key;
    params.keyLen       = AesKeyLenToDthe(aes->keylen);
    params.ptrIV        = (uint32_t*)aes->reg;
    params.ptrPlainTextData  = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)((opType == DTHE_AES_ENCRYPT) ? (byte*)in : out));
    params.ptrEncryptedData  = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)((opType == DTHE_AES_ENCRYPT) ? out : (byte*)in));
    params.dataLenBytes = sz;
    params.streamState  = DTHE_AES_ONE_SHOT_SUPPORT;
    params.modeSelect   = DTHE_AES_NO_MODE;

    if (algoType == DTHE_AES_CTR_MODE)
        params.counterWidth = DTHE_AES_CTR_WIDTH_128;

    wolfSSL_TI_lockCCM();

    if (opType == DTHE_AES_DECRYPT && algoType == DTHE_AES_CBC_MODE)
        XMEMCPY(aes->tmp, in + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);

    if (DTHE_AES_execute(h, &params) != DTHE_AES_RETURN_SUCCESS) {
        wolfSSL_TI_unlockCCM();
        return WC_HW_E;
    }
    wolfSSL_TI_unlockCCM();

    if (algoType == DTHE_AES_CBC_MODE) {
        if (opType == DTHE_AES_ENCRYPT)
            XMEMCPY(aes->reg, out + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
        else
            XMEMCPY(aes->reg, aes->tmp, WC_AES_BLOCK_SIZE);
    }

    if (algoType == DTHE_AES_CTR_MODE) {
        do {
            int i;
            for (i = WC_AES_BLOCK_SIZE - 1; i >= 0; i--)
                if (++((byte*)aes->reg)[i]) break;
            sz -= WC_AES_BLOCK_SIZE;
        } while ((int)sz > 0);
    }

    return 0;
}

/* ======================================================================== */
/* CBC                                                                      */
/* ======================================================================== */

int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    if (sz % WC_AES_BLOCK_SIZE)
        return BAD_FUNC_ARG;
    return AesOneShot(aes, out, in, sz, DTHE_AES_ENCRYPT, DTHE_AES_CBC_MODE);
}

int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    if (sz % WC_AES_BLOCK_SIZE)
        return BAD_FUNC_ARG;
    return AesOneShot(aes, out, in, sz, DTHE_AES_DECRYPT, DTHE_AES_CBC_MODE);
}

/* ======================================================================== */
/* ECB                                                                      */
/* ======================================================================== */

#ifdef HAVE_AES_ECB
int wc_AesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return AesOneShot(aes, out, in, sz, DTHE_AES_ENCRYPT, DTHE_AES_ECB_MODE);
}

int wc_AesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return AesOneShot(aes, out, in, sz, DTHE_AES_DECRYPT, DTHE_AES_ECB_MODE);
}
#endif

/* ======================================================================== */
/* CTR                                                                      */
/* ======================================================================== */

#ifdef WOLFSSL_AES_COUNTER
int wc_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    char out_block[WC_AES_BLOCK_SIZE];
    int odd, even;
    char *tmp;
    int ret;

    if ((aes == NULL) || (out == NULL) || (in == NULL))
        return BAD_FUNC_ARG;

    tmp = (char *)aes->tmp;
    if (aes->left) {
        if ((aes->left + sz) >= WC_AES_BLOCK_SIZE)
            odd = WC_AES_BLOCK_SIZE - aes->left;
        else
            odd = sz;
        XMEMCPY(tmp + aes->left, in, odd);
        if ((odd + aes->left) == WC_AES_BLOCK_SIZE) {
            ret = AesOneShot(aes, (byte*)out_block, (byte const*)tmp,
                             WC_AES_BLOCK_SIZE, DTHE_AES_ENCRYPT, DTHE_AES_CTR_MODE);
            if (ret != 0) return ret;
            XMEMCPY(out, out_block + aes->left, odd);
            aes->left = 0;
            XMEMSET(tmp, 0, WC_AES_BLOCK_SIZE);
        }
        in  += odd;
        out += odd;
        sz  -= odd;
    }
    odd = sz % WC_AES_BLOCK_SIZE;
    if (sz / WC_AES_BLOCK_SIZE) {
        even = (sz / WC_AES_BLOCK_SIZE) * WC_AES_BLOCK_SIZE;
        ret = AesOneShot(aes, out, in, even, DTHE_AES_ENCRYPT, DTHE_AES_CTR_MODE);
        if (ret != 0) return ret;
        out += even;
        in  += even;
    }
    if (odd) {
        XMEMSET(tmp + aes->left, 0, WC_AES_BLOCK_SIZE - aes->left);
        XMEMCPY(tmp + aes->left, in, odd);
        ret = AesOneShot(aes, (byte*)out_block, (byte const*)tmp,
                         WC_AES_BLOCK_SIZE, DTHE_AES_ENCRYPT, DTHE_AES_CTR_MODE);
        if (ret != 0) return ret;
        XMEMCPY(out, out_block + aes->left, odd);
        aes->left += odd;
    }
    return 0;
}

int wc_AesCtrSetKey(Aes* aes, const byte* key, word32 len, const byte* iv, int dir)
{
    return wc_AesSetKey(aes, key, len, iv, dir);
}
#endif

/* ======================================================================== */
/* CFB                                                                      */
/* ======================================================================== */

#ifdef WOLFSSL_AES_CFB
int wc_AesCfbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return AesOneShot(aes, out, in, sz, DTHE_AES_ENCRYPT, DTHE_AES_CFB_MODE);
}

int wc_AesCfbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return AesOneShot(aes, out, in, sz, DTHE_AES_DECRYPT, DTHE_AES_CFB_MODE);
}
#endif

/* ======================================================================== */
/* AES-DIRECT                                                               */
/* ======================================================================== */

#if defined(WOLFSSL_AES_DIRECT)
int wc_AesEncryptDirect(Aes* aes, byte* out, const byte* in)
{
    return AesOneShot(aes, out, in, WC_AES_BLOCK_SIZE,
                      DTHE_AES_ENCRYPT, DTHE_AES_ECB_MODE);
}

int wc_AesDecryptDirect(Aes* aes, byte* out, const byte* in)
{
    return AesOneShot(aes, out, in, WC_AES_BLOCK_SIZE,
                      DTHE_AES_DECRYPT, DTHE_AES_ECB_MODE);
}

int wc_AesSetKeyDirect(Aes* aes, const byte* key, word32 len, const byte* iv, int dir)
{
    return wc_AesSetKey(aes, key, len, iv, dir);
}
#endif

/* ======================================================================== */
/* XTS                                                                      */
/* ======================================================================== */

#ifdef WOLFSSL_AES_XTS

int wc_AesXtsInit(XtsAes* aes, void* heap, int devId)
{
    if (aes == NULL) return BAD_FUNC_ARG;
    aes->heap = heap;
    (void)devId;
    return 0;
}

int wc_AesXtsSetKeyNoInit(XtsAes* aes, const byte* key, word32 len, int dir)
{
    word32 keyHalf = len / 2;
    if (aes == NULL || key == NULL) return BAD_FUNC_ARG;
    return wc_AesSetKey(&aes->tweak, key, keyHalf, NULL, dir) |
           wc_AesSetKey(&aes->aes,   key + keyHalf, keyHalf, NULL, dir);
}

int wc_AesXtsSetKey(XtsAes* aes, const byte* key, word32 len, int dir,
                    void* heap, int devId)
{
    if (aes == NULL) return BAD_FUNC_ARG;
    aes->heap = heap;
    (void)devId;
    return wc_AesXtsSetKeyNoInit(aes, key, len, dir);
}

int wc_AesXtsEncryptSector(XtsAes* aes, byte* out, const byte* in, word32 sz,
                           word64 sector)
{
    byte i[WC_AES_BLOCK_SIZE];
    XMEMSET(i, 0, sizeof(i));
    int j;
    for (j = 0; j < 8; j++) {
        i[j] = (byte)(sector >> (j * 8));
    }
    return wc_AesXtsEncrypt(aes, out, in, sz, i, sizeof(i));
}

int wc_AesXtsDecryptSector(XtsAes* aes, byte* out, const byte* in, word32 sz,
                           word64 sector)
{
    byte i[WC_AES_BLOCK_SIZE];
    XMEMSET(i, 0, sizeof(i));
    int j;
    for (j = 0; j < 8; j++) {
        i[j] = (byte)(sector >> (j * 8));
    }
    return wc_AesXtsDecrypt(aes, out, in, sz, i, sizeof(i));
}

static int XtsProcess(Aes* aesTweak, Aes* aesData, byte* out, const byte* in,
                      word32 sz, const byte* i, word32 iSz, uint32_t opType)
{
    DTHE_AES_Params params;
    DTHE_Handle h = (DTHE_Handle)wolfSSL_TI_getDtheHandle();
    DTHE_AES_Params tweakParams;
    byte tweak[WC_AES_BLOCK_SIZE];
    int ret;

    if (h == NULL) return WC_HW_E;

    XMEMSET(&tweakParams, 0, sizeof(tweakParams));
    tweakParams.algoType     = DTHE_AES_ECB_MODE;
    tweakParams.opType       = DTHE_AES_ENCRYPT;
    tweakParams.ptrKey       = (uint32_t*)aesTweak->key;
    tweakParams.keyLen       = AesKeyLenToDthe(aesTweak->keylen);
    tweakParams.ptrPlainTextData  = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)i);
    tweakParams.ptrEncryptedData  = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)tweak);
    tweakParams.dataLenBytes = WC_AES_BLOCK_SIZE;
    tweakParams.streamState  = DTHE_AES_ONE_SHOT_SUPPORT;

    wolfSSL_TI_lockCCM();
    ret = DTHE_AES_execute(h, &tweakParams);
    wolfSSL_TI_unlockCCM();
    if (ret != DTHE_AES_RETURN_SUCCESS) return WC_HW_E;

    XMEMSET(&params, 0, sizeof(params));
    params.algoType     = DTHE_AES_XTS_MODE;
    params.opType       = opType;
    params.ptrKey       = (uint32_t*)aesData->key;
    params.keyLen       = AesKeyLenToDthe(aesData->keylen);
    params.ptrIV        = (uint32_t*)tweak;
    params.ptrPlainTextData  = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)((opType == DTHE_AES_ENCRYPT) ? (byte*)in : out));
    params.ptrEncryptedData  = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)((opType == DTHE_AES_ENCRYPT) ? out : (byte*)in));
    params.dataLenBytes = sz;
    params.streamState  = DTHE_AES_ONE_SHOT_SUPPORT;
    params.modeSelect   = DTHE_AES_XTS_MODE_1;
    params.counterWidth = DTHE_AES_CTR_WIDTH_128;

    wolfSSL_TI_lockCCM();
    ret = DTHE_AES_execute(h, &params);
    wolfSSL_TI_unlockCCM();
    return (ret == DTHE_AES_RETURN_SUCCESS) ? 0 : WC_HW_E;
}

int wc_AesXtsEncrypt(XtsAes* aes, byte* out, const byte* in, word32 sz,
                     const byte* i, word32 iSz)
{
    if (sz < WC_AES_BLOCK_SIZE) return BAD_FUNC_ARG;
    return XtsProcess(&aes->tweak, &aes->aes, out, in, sz, i, iSz,
                      DTHE_AES_ENCRYPT);
}

int wc_AesXtsDecrypt(XtsAes* aes, byte* out, const byte* in, word32 sz,
                     const byte* i, word32 iSz)
{
    if (sz < WC_AES_BLOCK_SIZE) return BAD_FUNC_ARG;
    return XtsProcess(&aes->tweak, &aes->aes, out, in, sz, i, iSz,
                      DTHE_AES_DECRYPT);
}

int wc_AesXtsFree(XtsAes* aes)
{
    (void)aes;
    return 0;
}

#endif /* WOLFSSL_AES_XTS */

/* ======================================================================== */
/* GCM / CCM shared helpers                                                 */
/* ======================================================================== */

#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)

#ifndef NO_RNG
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
        case 4: case 6: case 8: case 10: case 12: case 14: case 16:
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

    XMEMSET(&params, 0, sizeof(params));
    params.algoType     = algoType;
    params.opType       = DTHE_AES_ENCRYPT;
    params.ptrKey       = (uint32_t*)aes->key;
    params.keyLen       = AesKeyLenToDthe(aes->keylen);
    params.ptrIV        = (uint32_t*)nonce;
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
        return (ConstantCompare(authTag, tmpTag, authTagSz) == 0) ? 0
                                                                  : AES_GCM_AUTH_E;
    }

    XMEMSET(&params, 0, sizeof(params));
    params.algoType     = algoType;
    params.opType       = DTHE_AES_DECRYPT;
    params.ptrKey       = (uint32_t*)aes->key;
    params.keyLen       = AesKeyLenToDthe(aes->keylen);
    params.ptrIV        = (uint32_t*)nonce;
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
        (ConstantCompare(authTag, tmpTag, authTagSz) != 0)) {
        XMEMSET(out, 0, inSz);
        return AES_GCM_AUTH_E;
    }
    return 0;
}

#endif /* HAVE_AESGCM || HAVE_AESCCM */

/* ======================================================================== */
/* GCM                                                                      */
/* ======================================================================== */

#ifdef HAVE_AESGCM

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

#endif /* HAVE_AESGCM */

/* ======================================================================== */
/* CCM                                                                      */
/* ======================================================================== */

#ifdef HAVE_AESCCM

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

#endif /* HAVE_AESCCM */

/* ======================================================================== */
/* CMAC                                                                     */
/* ======================================================================== */

/* ======================================================================== */
/* Init / Free                                                              */
/* ======================================================================== */

int wc_AesInit(Aes* aes, void* heap, int devId)
{
    if (aes == NULL) return BAD_FUNC_ARG;
    aes->heap = heap;
    (void)devId;
    return 0;
}

void wc_AesFree(Aes* aes)
{
    (void)aes;
}

#endif /* !NO_AES && WOLFSSL_TI_CRYPT */