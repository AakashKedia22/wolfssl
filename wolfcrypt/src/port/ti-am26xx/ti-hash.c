/* port/ti/ti-hash.c
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

#if defined(WOLFSSL_TI_HASH)

#ifdef __cplusplus
    extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>

#include <wolfssl/wolfcrypt/port/ti/ti-hash.h>
#include <wolfssl/wolfcrypt/port/ti/ti-ccm.h>
#include "ti-am26xx.h"
#include <wolfssl/wolfcrypt/logging.h>

#include <security_common/drivers/crypto/dthe/dthe.h>
#include <security_common/drivers/crypto/dthe/dthe_sha.h>
#include <drivers/soc.h>

/* ======================================================================== */
/* Internal buffer-management struct
 * Cast from wolfSSL hash structs (wolfssl_TI_Hash, wc_Sha512) and Hmac.     */
/* ======================================================================== */

/* For MD5, SHA-1, SHA-224, SHA-256: cast wolfssl_TI_Hash */
/* For SHA-384, SHA-512: cast wc_Sha512 (the wolfSSL header typedefs it) */
/* For HMAC: stored in a separate allocation pointed to by Hmac::heap */

typedef struct {
    byte   *msg;
    word32 used;
    word32 len;
} TiHashBuf;

static int hashInitBuf(TiHashBuf *b)
{
    b->msg  = NULL;
    b->used = 0;
    b->len  = 0;
    return 0;
}

static int hashUpdateBuf(TiHashBuf *b, const byte* data, word32 dataSz)
{
    void *p;
    word32 newSz;

    if (b == NULL) return BAD_FUNC_ARG;
    if (dataSz == 0) return 0;
    if (data == NULL || !WC_SAFE_SUM_WORD32(b->used, dataSz, newSz))
        return BAD_FUNC_ARG;

    if (b->len < newSz) {
        if (b->msg == NULL)
            p = XMALLOC(newSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        else
            p = XREALLOC(b->msg, newSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (p == NULL) return MEMORY_E;
        b->msg = (byte*)p;
        b->len = newSz;
    }
    XMEMCPY(b->msg + b->used, data, dataSz);
    b->used += dataSz;
    return 0;
}

static void hashFreeBuf(TiHashBuf *b)
{
    if (b && b->msg) {
        XFREE(b->msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        b->msg  = NULL;
        b->used = 0;
        b->len  = 0;
    }
}

/* ======================================================================== */
/* One-shot SHA compute (used by all hash algorithm Final/GetHash paths)    */
/* ======================================================================== */

static int shaOneShot(const byte* data, word32 dataSz,
                      byte* digest, word32 digestSz,
                      uint32_t algoType)
{
    DTHE_SHA_Params p;
    DTHE_Handle h = (DTHE_Handle)wolfSSL_TI_getDtheHandle();

    if (h == NULL) return WC_HW_E;

    XMEMSET(&p, 0, sizeof(p));
    p.algoType      = algoType;
    p.ptrDataBuffer = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)data);
    p.dataLenBytes  = dataSz;

    wolfSSL_TI_lockCCM();
    if (DTHE_SHA_compute(h, &p, TRUE) != DTHE_SHA_RETURN_SUCCESS) {
        wolfSSL_TI_unlockCCM();
        return WC_HW_E;
    }
    wolfSSL_TI_unlockCCM();

    XMEMCPY(digest, p.digest, digestSz);
    return 0;
}

/* ======================================================================== */
/* MD5                                                                      */
/* ======================================================================== */

#if !defined(NO_MD5)

int wc_InitMd5_ex(Md5* md5, void* heap, int devId)
{
    if (md5 == NULL) return BAD_FUNC_ARG;
    if (!wolfSSL_TI_CCMInit()) return WC_HW_E;
    (void)heap; (void)devId;
    return hashInitBuf((TiHashBuf*)md5);
}

int wc_InitMd5(Md5* md5) { return wc_InitMd5_ex(md5, NULL, INVALID_DEVID); }

int wc_Md5Update(Md5* md5, const byte* data, word32 len)
{
    return hashUpdateBuf((TiHashBuf*)md5, data, len);
}

int wc_Md5Final(Md5* md5, byte* hash)
{
    TiHashBuf *b = (TiHashBuf*)md5;
    int ret = shaOneShot(b->msg, b->used, hash, MD5_DIGEST_SIZE,
                         DTHE_SHA_ALGO_MD5);
    hashFreeBuf(b);
    return ret;
}

int wc_Md5GetHash(Md5* md5, byte* hash)
{
    TiHashBuf *b = (TiHashBuf*)md5;
    return shaOneShot(b->msg, b->used, hash, MD5_DIGEST_SIZE,
                      DTHE_SHA_ALGO_MD5);
}

int wc_Md5Copy(Md5* src, Md5* dst)
{
    TiHashBuf *s = (TiHashBuf*)src;
    TiHashBuf *d = (TiHashBuf*)dst;
    if (src == NULL || dst == NULL) return BAD_FUNC_ARG;
    hashInitBuf(d);
    if (s->used > 0) return hashUpdateBuf(d, s->msg, s->used);
    return 0;
}

int wc_Md5Hash(const byte* data, word32 len, byte* hash)
{
    return shaOneShot(data, len, hash, MD5_DIGEST_SIZE, DTHE_SHA_ALGO_MD5);
}

void wc_Md5Free(Md5* md5) { hashFreeBuf((TiHashBuf*)md5); }

#endif /* !NO_MD5 */

/* ======================================================================== */
/* SHA-1                                                                    */
/* ======================================================================== */

#if !defined(NO_SHA)

int wc_InitSha_ex(Sha* sha, void* heap, int devId)
{
    if (sha == NULL) return BAD_FUNC_ARG;
    if (!wolfSSL_TI_CCMInit()) return WC_HW_E;
    (void)heap; (void)devId;
    return hashInitBuf((TiHashBuf*)sha);
}

int wc_InitSha(Sha* sha) { return wc_InitSha_ex(sha, NULL, INVALID_DEVID); }

int wc_ShaUpdate(Sha* sha, const byte* data, word32 len)
{
    return hashUpdateBuf((TiHashBuf*)sha, data, len);
}

int wc_ShaFinal(Sha* sha, byte* hash)
{
    TiHashBuf *b = (TiHashBuf*)sha;
    int ret = shaOneShot(b->msg, b->used, hash, SHA_DIGEST_SIZE,
                         DTHE_SHA_ALGO_SHA1);
    hashFreeBuf(b);
    return ret;
}

int wc_ShaGetHash(Sha* sha, byte* hash)
{
    TiHashBuf *b = (TiHashBuf*)sha;
    return shaOneShot(b->msg, b->used, hash, SHA_DIGEST_SIZE,
                      DTHE_SHA_ALGO_SHA1);
}

int wc_ShaCopy(Sha* src, Sha* dst)
{
    TiHashBuf *s = (TiHashBuf*)src;
    TiHashBuf *d = (TiHashBuf*)dst;
    if (src == NULL || dst == NULL) return BAD_FUNC_ARG;
    hashInitBuf(d);
    if (s->used > 0) return hashUpdateBuf(d, s->msg, s->used);
    return 0;
}

int wc_ShaHash(const byte* data, word32 len, byte* hash)
{
    return shaOneShot(data, len, hash, SHA_DIGEST_SIZE, DTHE_SHA_ALGO_SHA1);
}

void wc_ShaFree(Sha* sha) { hashFreeBuf((TiHashBuf*)sha); }

#endif /* !NO_SHA */

/* ======================================================================== */
/* SHA-224                                                                  */
/* ======================================================================== */

#if defined(WOLFSSL_SHA224)

int wc_InitSha224_ex(Sha224* sha224, void* heap, int devId)
{
    if (sha224 == NULL) return BAD_FUNC_ARG;
    if (!wolfSSL_TI_CCMInit()) return WC_HW_E;
    (void)heap; (void)devId;
    return hashInitBuf((TiHashBuf*)sha224);
}

int wc_InitSha224(Sha224* sha224) { return wc_InitSha224_ex(sha224, NULL, INVALID_DEVID); }

int wc_Sha224Update(Sha224* sha224, const byte* data, word32 len)
{
    return hashUpdateBuf((TiHashBuf*)sha224, data, len);
}

int wc_Sha224Final(Sha224* sha224, byte* hash)
{
    TiHashBuf *b = (TiHashBuf*)sha224;
    int ret = shaOneShot(b->msg, b->used, hash, SHA224_DIGEST_SIZE,
                         DTHE_SHA_ALGO_SHA224);
    hashFreeBuf(b);
    return ret;
}

int wc_Sha224GetHash(Sha224* sha224, byte* hash)
{
    TiHashBuf *b = (TiHashBuf*)sha224;
    return shaOneShot(b->msg, b->used, hash, SHA224_DIGEST_SIZE,
                      DTHE_SHA_ALGO_SHA224);
}

int wc_Sha224Copy(Sha224* src, Sha224* dst)
{
    TiHashBuf *s = (TiHashBuf*)src;
    TiHashBuf *d = (TiHashBuf*)dst;
    if (src == NULL || dst == NULL) return BAD_FUNC_ARG;
    hashInitBuf(d);
    if (s->used > 0) return hashUpdateBuf(d, s->msg, s->used);
    return 0;
}

int wc_Sha224Hash(const byte* data, word32 len, byte* hash)
{
    return shaOneShot(data, len, hash, SHA224_DIGEST_SIZE, DTHE_SHA_ALGO_SHA224);
}

void wc_Sha224Free(Sha224* sha224) { hashFreeBuf((TiHashBuf*)sha224); }

#endif /* WOLFSSL_SHA224 */

/* ======================================================================== */
/* SHA-256                                                                  */
/* ======================================================================== */

#if !defined(NO_SHA256)

int wc_InitSha256_ex(Sha256* sha256, void* heap, int devId)
{
    if (sha256 == NULL) return BAD_FUNC_ARG;
    if (!wolfSSL_TI_CCMInit()) return WC_HW_E;
    (void)heap; (void)devId;
    return hashInitBuf((TiHashBuf*)sha256);
}

int wc_InitSha256(Sha256* sha256) { return wc_InitSha256_ex(sha256, NULL, INVALID_DEVID); }

int wc_Sha256Update(Sha256* sha256, const byte* data, word32 len)
{
    return hashUpdateBuf((TiHashBuf*)sha256, data, len);
}

int wc_Sha256Final(Sha256* sha256, byte* hash)
{
    TiHashBuf *b = (TiHashBuf*)sha256;
    int ret = shaOneShot(b->msg, b->used, hash, SHA256_DIGEST_SIZE,
                         DTHE_SHA_ALGO_SHA256);
    hashFreeBuf(b);
    return ret;
}

int wc_Sha256GetHash(Sha256* sha256, byte* hash)
{
    TiHashBuf *b = (TiHashBuf*)sha256;
    return shaOneShot(b->msg, b->used, hash, SHA256_DIGEST_SIZE,
                      DTHE_SHA_ALGO_SHA256);
}

int wc_Sha256Copy(Sha256* src, Sha256* dst)
{
    TiHashBuf *s = (TiHashBuf*)src;
    TiHashBuf *d = (TiHashBuf*)dst;
    if (src == NULL || dst == NULL) return BAD_FUNC_ARG;
    hashInitBuf(d);
    if (s->used > 0) return hashUpdateBuf(d, s->msg, s->used);
    return 0;
}

int wc_Sha256Hash(const byte* data, word32 len, byte* hash)
{
    return shaOneShot(data, len, hash, SHA256_DIGEST_SIZE,
                      DTHE_SHA_ALGO_SHA256);
}

void wc_Sha256Free(Sha256* sha256) { hashFreeBuf((TiHashBuf*)sha256); }

#endif /* !NO_SHA256 */

/* ======================================================================== */
/* SHA-384                                                                  */
/* ======================================================================== */

#if defined(WOLFSSL_SHA384)

int wc_InitSha384_ex(wc_Sha384* sha, void* heap, int devId)
{
    if (sha == NULL) return BAD_FUNC_ARG;
    if (!wolfSSL_TI_CCMInit()) return WC_HW_E;
    (void)heap; (void)devId;
    sha->heap = NULL;
    sha->heap = XMALLOC(sizeof(TiHashBuf), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha->heap == NULL) return MEMORY_E;
    return hashInitBuf((TiHashBuf*)sha->heap);
}

int wc_InitSha384(wc_Sha384* sha) { return wc_InitSha384_ex(sha, NULL, INVALID_DEVID); }

int wc_Sha384Update(wc_Sha384* sha, const byte* data, word32 len)
{
    if (sha == NULL || sha->heap == NULL) return BAD_FUNC_ARG;
    return hashUpdateBuf((TiHashBuf*)sha->heap, data, len);
}

int wc_Sha384Final(wc_Sha384* sha, byte* hash)
{
    TiHashBuf *b;
    int ret;
    if (sha == NULL || sha->heap == NULL) return BAD_FUNC_ARG;
    b = (TiHashBuf*)sha->heap;
    ret = shaOneShot(b->msg, b->used, hash, WC_SHA384_DIGEST_SIZE,
                     DTHE_SHA_ALGO_SHA384);
    hashFreeBuf(b);
    sha->heap = NULL;
    return ret;
}

int wc_Sha384GetHash(wc_Sha384* sha, byte* hash)
{
    if (sha == NULL || sha->heap == NULL) return BAD_FUNC_ARG;
    return shaOneShot(((TiHashBuf*)sha->heap)->msg,
                      ((TiHashBuf*)sha->heap)->used,
                      hash, WC_SHA384_DIGEST_SIZE, DTHE_SHA_ALGO_SHA384);
}

int wc_Sha384Copy(wc_Sha384* src, wc_Sha384* dst)
{
    TiHashBuf *s, *d;
    if (src == NULL || dst == NULL) return BAD_FUNC_ARG;
    dst->heap = XMALLOC(sizeof(TiHashBuf), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (dst->heap == NULL) return MEMORY_E;
    d = (TiHashBuf*)dst->heap;
    hashInitBuf(d);
    if (src->heap != NULL) {
        s = (TiHashBuf*)src->heap;
        if (s->used > 0) return hashUpdateBuf(d, s->msg, s->used);
    }
    return 0;
}

void wc_Sha384Free(wc_Sha384* sha)
{
    if (sha && sha->heap) {
        hashFreeBuf((TiHashBuf*)sha->heap);
        XFREE(sha->heap, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        sha->heap = NULL;
    }
}

#endif /* WOLFSSL_SHA384 */

/* ======================================================================== */
/* SHA-512                                                                  */
/* ======================================================================== */

#if defined(WOLFSSL_SHA512)

int wc_InitSha512_ex(wc_Sha512* sha, void* heap, int devId)
{
    if (sha == NULL) return BAD_FUNC_ARG;
    if (!wolfSSL_TI_CCMInit()) return WC_HW_E;
    (void)heap; (void)devId;
    sha->heap = XMALLOC(sizeof(TiHashBuf), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha->heap == NULL) return MEMORY_E;
    return hashInitBuf((TiHashBuf*)sha->heap);
}

int wc_InitSha512(wc_Sha512* sha) { return wc_InitSha512_ex(sha, NULL, INVALID_DEVID); }

int wc_Sha512Update(wc_Sha512* sha, const byte* data, word32 len)
{
    if (sha == NULL || sha->heap == NULL) return BAD_FUNC_ARG;
    return hashUpdateBuf((TiHashBuf*)sha->heap, data, len);
}

int wc_Sha512Final(wc_Sha512* sha, byte* hash)
{
    TiHashBuf *b;
    int ret;
    if (sha == NULL || sha->heap == NULL) return BAD_FUNC_ARG;
    b = (TiHashBuf*)sha->heap;
    ret = shaOneShot(b->msg, b->used, hash, WC_SHA512_DIGEST_SIZE,
                     DTHE_SHA_ALGO_SHA512);
    hashFreeBuf(b);
    sha->heap = NULL;
    return ret;
}

int wc_Sha512GetHash(wc_Sha512* sha, byte* hash)
{
    if (sha == NULL || sha->heap == NULL) return BAD_FUNC_ARG;
    return shaOneShot(((TiHashBuf*)sha->heap)->msg,
                      ((TiHashBuf*)sha->heap)->used,
                      hash, WC_SHA512_DIGEST_SIZE, DTHE_SHA_ALGO_SHA512);
}

int wc_Sha512Copy(wc_Sha512* src, wc_Sha512* dst)
{
    TiHashBuf *s, *d;
    if (src == NULL || dst == NULL) return BAD_FUNC_ARG;
    dst->heap = XMALLOC(sizeof(TiHashBuf), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (dst->heap == NULL) return MEMORY_E;
    d = (TiHashBuf*)dst->heap;
    hashInitBuf(d);
    if (src->heap != NULL) {
        s = (TiHashBuf*)src->heap;
        if (s->used > 0) return hashUpdateBuf(d, s->msg, s->used);
    }
    return 0;
}

void wc_Sha512Free(wc_Sha512* sha)
{
    if (sha && sha->heap) {
        hashFreeBuf((TiHashBuf*)sha->heap);
        XFREE(sha->heap, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        sha->heap = NULL;
    }
}

#endif /* WOLFSSL_SHA512 */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_TI_HASH */