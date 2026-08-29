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

#include <limits.h>
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
/* Incremental hardware streaming (SHA-256/SHA-512 only)                    */
/*                                                                          */
/* Feeds complete blocks to the DTHE SHA hardware as they accumulate,      */
/* buffering only the unaligned remainder in software. Mirrors TI's own    */
/* SEC_BOOT_validateStreamingImage() leftover-buffer pattern (sec_boot.c),  */
/* but keeps the leftover buffer/flag per-object instead of in globals.    */
/* ======================================================================== */

static int shaStreamUpdate(byte* leftover, word32* leftoverLen,
                           word32 blockSize, uint32_t algoType,
                           void** started, const byte* data, word32 len)
{
    DTHE_SHA_Params p;
    DTHE_Handle h;
    word32 fill, n, chunk;

    if (len == 0) return 0;
    if (data == NULL) return BAD_FUNC_ARG;

    h = (DTHE_Handle)wolfSSL_TI_getDtheHandle();
    if (h == NULL) return WC_HW_E;

    XMEMSET(&p, 0, sizeof(p));
    p.algoType = algoType;

    if (*leftoverLen > 0 && len > (blockSize - *leftoverLen)) {
        fill = blockSize - *leftoverLen;
        XMEMCPY(leftover + *leftoverLen, data, fill);
        p.ptrDataBuffer = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)leftover);
        p.dataLenBytes  = blockSize;
        wolfSSL_TI_lockCCM();
        if (DTHE_SHA_compute(h, &p, FALSE) != DTHE_SHA_RETURN_SUCCESS) {
            wolfSSL_TI_unlockCCM();
            return WC_HW_E;
        }
        wolfSSL_TI_unlockCCM();
        *started = leftover;
        data += fill;
        len  -= fill;
        *leftoverLen = 0;
    }

    n = (len + blockSize - 1) / blockSize;
    if (n > 1) {
        chunk = (n - 1) * blockSize;
        p.ptrDataBuffer = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)data);
        p.dataLenBytes  = chunk;
        wolfSSL_TI_lockCCM();
        if (DTHE_SHA_compute(h, &p, FALSE) != DTHE_SHA_RETURN_SUCCESS) {
            wolfSSL_TI_unlockCCM();
            return WC_HW_E;
        }
        wolfSSL_TI_unlockCCM();
        *started = leftover;
        data += chunk;
        len  -= chunk;
    }

    if (len > 0) {
        XMEMCPY(leftover + *leftoverLen, data, len);
        *leftoverLen += len;
    }

    return 0;
}

static int shaStreamFinal(byte* leftover, word32 leftoverLen,
                          uint32_t algoType, byte* hash, word32 digestSz)
{
    DTHE_SHA_Params p;
    DTHE_Handle h = (DTHE_Handle)wolfSSL_TI_getDtheHandle();
    int ret;

    if (h == NULL) return WC_HW_E;

    XMEMSET(&p, 0, sizeof(p));
    p.algoType      = algoType;
    p.ptrDataBuffer = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)leftover);
    p.dataLenBytes  = leftoverLen;

    wolfSSL_TI_lockCCM();
    ret = DTHE_SHA_compute(h, &p, TRUE);
    wolfSSL_TI_unlockCCM();

    if (ret != DTHE_SHA_RETURN_SUCCESS) return WC_HW_E;

    XMEMCPY(hash, p.digest, digestSz);
    return 0;
}

static void shaStreamAbort(byte* leftover, word32 leftoverLen,
                          uint32_t algoType)
{
    byte scratch[DTHE_SHA_MAX_DIGEST_SIZE_BYTES];
    (void)shaStreamFinal(leftover, leftoverLen, algoType, scratch,
                        sizeof(scratch));
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

/* NOTE: unlike the other algorithms in this file, SHA-256 streams full
 * blocks to the DTHE hardware as they arrive (see shaStreamUpdate()),
 * instead of buffering the whole message. wolfssl_TI_Hash::hash[64] (dead
 * space here, WOLFSSL_NO_HASH_RAW) holds the leftover partial block;
 * ::used is the leftover byte count; ::msg is repurposed as a "have we
 * streamed a block to hardware yet" sentinel (NULL = no, non-NULL = yes).
 * ::len is unused. Once non-NULL, Copy()/GetHash() can no longer produce
 * a correct result (the hardware holds no rewindable intermediate state)
 * and return BAD_STATE_E instead. */

int wc_Sha256Update(Sha256* sha256, const byte* data, word32 len)
{
    wolfssl_TI_Hash *b = (wolfssl_TI_Hash*)sha256;
    if (b == NULL) return BAD_FUNC_ARG;
    return shaStreamUpdate(b->hash, &b->used, WC_SHA256_BLOCK_SIZE,
                           DTHE_SHA_ALGO_SHA256, (void**)&b->msg, data, len);
}

int wc_Sha256Final(Sha256* sha256, byte* hash)
{
    wolfssl_TI_Hash *b = (wolfssl_TI_Hash*)sha256;
    int ret;
    if (b == NULL) return BAD_FUNC_ARG;
    ret = shaStreamFinal(b->hash, b->used, DTHE_SHA_ALGO_SHA256, hash,
                         SHA256_DIGEST_SIZE);
    b->used = 0;
    b->msg  = NULL;
    return ret;
}

int wc_Sha256GetHash(Sha256* sha256, byte* hash)
{
    wolfssl_TI_Hash *b = (wolfssl_TI_Hash*)sha256;
    if (b == NULL) return BAD_FUNC_ARG;
    if (b->msg != NULL) return BAD_STATE_E;
    return shaOneShot(b->hash, b->used, hash, SHA256_DIGEST_SIZE,
                      DTHE_SHA_ALGO_SHA256);
}

int wc_Sha256Copy(Sha256* src, Sha256* dst)
{
    wolfssl_TI_Hash *s = (wolfssl_TI_Hash*)src;
    wolfssl_TI_Hash *d = (wolfssl_TI_Hash*)dst;
    if (src == NULL || dst == NULL) return BAD_FUNC_ARG;
    if (s->msg != NULL) return BAD_STATE_E;
    d->msg  = NULL;
    d->len  = 0;
    d->used = s->used;
    XMEMCPY(d->hash, s->hash, sizeof(d->hash));
    return 0;
}

int wc_Sha256Hash(const byte* data, word32 len, byte* hash)
{
    return shaOneShot(data, len, hash, SHA256_DIGEST_SIZE,
                      DTHE_SHA_ALGO_SHA256);
}

void wc_Sha256Free(Sha256* sha256)
{
    wolfssl_TI_Hash *b = (wolfssl_TI_Hash*)sha256;
    if (b == NULL) return;
    if (b->msg != NULL)
        shaStreamAbort(b->hash, b->used, DTHE_SHA_ALGO_SHA256);
    b->used = 0;
    b->msg  = NULL;
}

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

/* SHA-512 streams full 128-byte blocks to the DTHE hardware as they arrive
 * (see shaStreamUpdate()), instead of buffering the whole message. ::started
 * is a "have we streamed a block to hardware yet" sentinel (NULL = no); once
 * non-NULL, Copy()/GetHash() return BAD_STATE_E instead of a wrong result,
 * since the hardware holds no rewindable intermediate state. */
typedef struct {
    byte   leftover[WC_SHA512_BLOCK_SIZE];
    word32 leftoverLen;
    void*  started;
} TiSha512Stream;

int wc_InitSha512_ex(wc_Sha512* sha, void* heap, int devId)
{
    if (sha == NULL) return BAD_FUNC_ARG;
    if (!wolfSSL_TI_CCMInit()) return WC_HW_E;
    (void)heap; (void)devId;
    sha->heap = XMALLOC(sizeof(TiSha512Stream), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha->heap == NULL) return MEMORY_E;
    XMEMSET(sha->heap, 0, sizeof(TiSha512Stream));
    return 0;
}

int wc_InitSha512(wc_Sha512* sha) { return wc_InitSha512_ex(sha, NULL, INVALID_DEVID); }

int wc_Sha512Update(wc_Sha512* sha, const byte* data, word32 len)
{
    TiSha512Stream *st;
    if (sha == NULL || sha->heap == NULL) return BAD_FUNC_ARG;
    st = (TiSha512Stream*)sha->heap;
    return shaStreamUpdate(st->leftover, &st->leftoverLen,
                           WC_SHA512_BLOCK_SIZE, DTHE_SHA_ALGO_SHA512,
                           &st->started, data, len);
}

int wc_Sha512Final(wc_Sha512* sha, byte* hash)
{
    TiSha512Stream *st;
    int ret;
    if (sha == NULL || sha->heap == NULL) return BAD_FUNC_ARG;
    st = (TiSha512Stream*)sha->heap;
    ret = shaStreamFinal(st->leftover, st->leftoverLen, DTHE_SHA_ALGO_SHA512,
                         hash, WC_SHA512_DIGEST_SIZE);
    XFREE(sha->heap, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    sha->heap = NULL;
    return ret;
}

int wc_Sha512GetHash(wc_Sha512* sha, byte* hash)
{
    TiSha512Stream *st;
    if (sha == NULL || sha->heap == NULL) return BAD_FUNC_ARG;
    st = (TiSha512Stream*)sha->heap;
    if (st->started != NULL) return BAD_STATE_E;
    return shaOneShot(st->leftover, st->leftoverLen, hash,
                      WC_SHA512_DIGEST_SIZE, DTHE_SHA_ALGO_SHA512);
}

int wc_Sha512Copy(wc_Sha512* src, wc_Sha512* dst)
{
    TiSha512Stream *s, *d;
    if (src == NULL || dst == NULL || src->heap == NULL) return BAD_FUNC_ARG;
    s = (TiSha512Stream*)src->heap;
    if (s->started != NULL) return BAD_STATE_E;
    dst->heap = XMALLOC(sizeof(TiSha512Stream), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (dst->heap == NULL) return MEMORY_E;
    d = (TiSha512Stream*)dst->heap;
    XMEMSET(d, 0, sizeof(*d));
    d->leftoverLen = s->leftoverLen;
    XMEMCPY(d->leftover, s->leftover, sizeof(d->leftover));
    return 0;
}

void wc_Sha512Free(wc_Sha512* sha)
{
    TiSha512Stream *st;
    if (sha && sha->heap) {
        st = (TiSha512Stream*)sha->heap;
        if (st->started != NULL)
            shaStreamAbort(st->leftover, st->leftoverLen, DTHE_SHA_ALGO_SHA512);
        XFREE(sha->heap, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        sha->heap = NULL;
    }
}

#endif /* WOLFSSL_SHA512 */

/* ------------------------------------------------------------------------ */
/* One-shot hash convenience wrappers                                       */
/* wolfcrypt/src/hash.c omits its own copies of wc_Md5Hash_ex/wc_ShaHash_ex/ */
/* wc_Sha256Hash_ex when WOLFSSL_TI_HASH is defined, expecting the TI port  */
/* to provide them.                                                         */
/* ------------------------------------------------------------------------ */
#if !defined(NO_MD5)
int wc_Md5Hash_ex(const byte* data, word32 len, byte* hash,
    void* heap, int devId)
{
    int ret;
    Md5 md5;

    if ((ret = wc_InitMd5_ex(&md5, heap, devId)) != 0)
        return ret;
    if ((ret = wc_Md5Update(&md5, data, len)) == 0)
        ret = wc_Md5Final(&md5, hash);
    wc_Md5Free(&md5);
    return ret;
}
#endif /* !NO_MD5 */

#if !defined(NO_SHA)
int wc_ShaHash_ex(const byte* data, word32 len, byte* hash,
    void* heap, int devId)
{
    int ret;
    Sha sha;

    if ((ret = wc_InitSha_ex(&sha, heap, devId)) != 0)
        return ret;
    if ((ret = wc_ShaUpdate(&sha, data, len)) == 0)
        ret = wc_ShaFinal(&sha, hash);
    wc_ShaFree(&sha);
    return ret;
}
#endif /* !NO_SHA */

#if !defined(NO_SHA256)
int wc_Sha256Hash_ex(const byte* data, word32 len, byte* hash,
    void* heap, int devId)
{
    int ret;
    Sha256 sha256;

    if ((ret = wc_InitSha256_ex(&sha256, heap, devId)) != 0)
        return ret;
    if ((ret = wc_Sha256Update(&sha256, data, len)) == 0)
        ret = wc_Sha256Final(&sha256, hash);
    wc_Sha256Free(&sha256);
    return ret;
}
#endif /* !NO_SHA256 */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_TI_HASH */