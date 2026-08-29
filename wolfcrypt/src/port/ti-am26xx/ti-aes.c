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

#endif /* !NO_AES && WOLFSSL_TI_CRYPT */

/* ------------------------------------------------------------------------ */
/* DTHE init, handle, and mutex (shared with ti-hash.c/ti-hmac.c via         */
/* ti-ccm.h) -- available whenever hardware AES or hardware hash is enabled */
/* ------------------------------------------------------------------------ */
#if defined(WOLFSSL_TI_CRYPT) || defined(WOLFSSL_TI_HASH)

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

#endif /* WOLFSSL_TI_CRYPT || WOLFSSL_TI_HASH */

#if !defined(NO_AES) && defined(WOLFSSL_TI_CRYPT)

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
    byte* keystream;
    word32 processed;
    word32 even;
    int ret;

    if ((aes == NULL) || (out == NULL) || (in == NULL))
        return BAD_FUNC_ARG;

    /* aes->tmp caches the raw keystream block for the current counter
     * value; aes->left counts how many of its trailing bytes are still
     * unused. Consume those first, byte-for-byte, without touching the
     * hardware or the counter - this block's keystream was already
     * generated (and the counter already advanced past it) by whichever
     * earlier call produced it. Re-deriving it via another AesOneShot()
     * call here would use the now-advanced counter and produce the wrong
     * keystream for this block. */
    keystream = (byte*)aes->tmp + WC_AES_BLOCK_SIZE - aes->left;
    processed = (aes->left < sz) ? aes->left : sz;
    while (processed > 0) {
        *(out++) = *(in++) ^ *(keystream++);
        aes->left--;
        sz--;
        processed--;
    }

    even = sz - (sz % WC_AES_BLOCK_SIZE);
    if (even > 0) {
        ret = AesOneShot(aes, out, in, even, DTHE_AES_ENCRYPT, DTHE_AES_CTR_MODE);
        if (ret != 0) return ret;
        out += even;
        in  += even;
        sz  -= even;
    }

    if (sz > 0) {
        byte zero[WC_AES_BLOCK_SIZE];
        XMEMSET(zero, 0, sizeof(zero));
        /* CTR-encrypt a zero block to pull out the raw keystream for the
         * current counter value; this also advances the counter by the
         * one block consumed here. */
        ret = AesOneShot(aes, (byte*)aes->tmp, zero, WC_AES_BLOCK_SIZE,
                         DTHE_AES_ENCRYPT, DTHE_AES_CTR_MODE);
        if (ret != 0) return ret;
        aes->left = WC_AES_BLOCK_SIZE;
        keystream = (byte*)aes->tmp;
        while (sz > 0) {
            *(out++) = *(in++) ^ *(keystream++);
            aes->left--;
            sz--;
        }
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
/* Init / Free                                                              */
/* ======================================================================== */

int wc_AesInit(Aes* aes, void* heap, int devId)
{
    DTHE_Handle h;

    if (aes == NULL) return BAD_FUNC_ARG;
    if (!wolfSSL_TI_CCMInit())
        return WC_HW_E;

    aes->heap = heap;
    (void)devId;

    h = (DTHE_Handle)wolfSSL_TI_getDtheHandle();
    if (h == NULL) return WC_HW_E;

    wolfSSL_TI_lockCCM();
    if (DTHE_AES_open(h) != DTHE_AES_RETURN_SUCCESS) {
        wolfSSL_TI_unlockCCM();
        return WC_HW_E;
    }
    wolfSSL_TI_unlockCCM();

    return 0;
}

void wc_AesFree(Aes* aes)
{
    DTHE_Handle h = (DTHE_Handle)wolfSSL_TI_getDtheHandle();

    (void)aes;
    if (h != NULL) {
        wolfSSL_TI_lockCCM();
        DTHE_AES_close(h);
        wolfSSL_TI_unlockCCM();
    }
}

#endif /* !NO_AES && WOLFSSL_TI_CRYPT */
