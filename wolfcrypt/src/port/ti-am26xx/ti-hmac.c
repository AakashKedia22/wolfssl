/* port/ti/ti-hmac.c
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

#if defined(WOLFSSL_TI_HASH) && !defined(NO_HMAC)

#ifdef __cplusplus
    extern "C" {
#endif

#include <stdint.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/port/ti/ti-ccm.h>
#include "ti-am26xx.h"
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <security_common/drivers/crypto/dthe/dthe.h>
#include <security_common/drivers/crypto/dthe/dthe_sha.h>
#include <drivers/soc.h>

/* ------------------------------------------------------------------------ */
/* Internal context: message buffer + key                                   */
/* ------------------------------------------------------------------------ */
typedef struct {
    byte   *msg;
    word32 used;
    word32 len;
} TiHmacBuf;

static int hmacBufInit(TiHmacBuf *b)
{
    b->msg  = NULL;
    b->used = 0;
    b->len  = 0;
    return 0;
}

static int hmacBufUpdate(TiHmacBuf *b, const byte* data, word32 dataSz)
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

static void hmacBufFree(TiHmacBuf *b)
{
    if (b && b->msg) {
        XFREE(b->msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        b->msg  = NULL;
        b->used = 0;
        b->len  = 0;
    }
}

/* ------------------------------------------------------------------------ */
/* HMAC context stored in Hmac::heap                                        */
/* ------------------------------------------------------------------------ */
typedef struct {
    TiHmacBuf msg;
    byte      rawKey[WC_HMAC_BLOCK_SIZE];
    word32    rawKeySz;
    uint32_t  algoType;
    byte      blockSize;
} TiHmacCtx;

/* ------------------------------------------------------------------------ */
/* Helper: map wolfSSL HMAC type to DTHE SHA algorithm                      */
/* ------------------------------------------------------------------------ */
static int HmacTypeToAlgo(int macType, uint32_t *algo, byte *blockSz)
{
    switch (macType) {
    #if !defined(NO_MD5)
        case WC_MD5:     *algo = DTHE_SHA_ALGO_MD5;    *blockSz = 64;  return 0;
    #endif
    #if !defined(NO_SHA)
        case WC_SHA:     *algo = DTHE_SHA_ALGO_SHA1;    *blockSz = 64;  return 0;
    #endif
    #if defined(WOLFSSL_SHA224)
        case WC_SHA224:  *algo = DTHE_SHA_ALGO_SHA224;  *blockSz = 64;  return 0;
    #endif
    #if !defined(NO_SHA256)
        case WC_SHA256:  *algo = DTHE_SHA_ALGO_SHA256;  *blockSz = 64;  return 0;
    #endif
    #if defined(WOLFSSL_SHA384)
        case WC_SHA384:  *algo = DTHE_SHA_ALGO_SHA384;  *blockSz = 128; return 0;
    #endif
    #if defined(WOLFSSL_SHA512)
        case WC_SHA512:  *algo = DTHE_SHA_ALGO_SHA512;  *blockSz = 128; return 0;
    #endif
        default:         return BAD_FUNC_ARG;
    }
}

/* ------------------------------------------------------------------------ */
/* Helper: digest size for a DTHE SHA algorithm                             */
/* ------------------------------------------------------------------------ */
static word32 algoDigestSz(uint32_t algoType)
{
    switch (algoType) {
        case DTHE_SHA_ALGO_MD5:    return 16;
        case DTHE_SHA_ALGO_SHA1:   return 20;
        case DTHE_SHA_ALGO_SHA224: return 28;
        case DTHE_SHA_ALGO_SHA256: return 32;
        case DTHE_SHA_ALGO_SHA384: return 48;
        case DTHE_SHA_ALGO_SHA512: return 64;
        default:                   return 0;
    }
}

/* ------------------------------------------------------------------------ */
/* wc_HmacSetKey                                                            */
/* ------------------------------------------------------------------------ */
int wc_HmacSetKey(Hmac* hmac, int type, const byte* key, word32 length)
{
    TiHmacCtx *ctx;
    uint32_t algo;
    byte blk;

    if (hmac == NULL) return BAD_FUNC_ARG;
    if (key == NULL && length != 0) return BAD_FUNC_ARG;
    if (HmacTypeToAlgo(type, &algo, &blk) != 0) return BAD_FUNC_ARG;
    if (!wolfSSL_TI_CCMInit()) return WC_HW_E;

    if (hmac->heap != NULL) {
        XFREE(hmac->heap, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        hmac->heap = NULL;
    }

    ctx = (TiHmacCtx*)XMALLOC(sizeof(TiHmacCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) return MEMORY_E;
    XMEMSET(ctx, 0, sizeof(*ctx));

    ctx->algoType  = algo;
    ctx->blockSize = blk;
    ctx->rawKeySz  = length > blk ? blk : length;
    XMEMCPY(ctx->rawKey, key, ctx->rawKeySz);
    if (length > blk) {
        DTHE_SHA_Params p;
        DTHE_Handle h = (DTHE_Handle)wolfSSL_TI_getDtheHandle();
        if (h == NULL) { XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER); return WC_HW_E; }
        XMEMSET(&p, 0, sizeof(p));
        p.algoType      = algo;
        p.ptrDataBuffer = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)key);
        p.dataLenBytes  = length;
        wolfSSL_TI_lockCCM();
        if (DTHE_SHA_compute(h, &p, TRUE) != DTHE_SHA_RETURN_SUCCESS) {
            wolfSSL_TI_unlockCCM();
            XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return WC_HW_E;
        }
        wolfSSL_TI_unlockCCM();
        ctx->rawKeySz = algoDigestSz(algo);
        XMEMCPY(ctx->rawKey, p.digest, ctx->rawKeySz);
    }

    hmac->heap      = ctx;
    hmac->macType   = (byte)type;
    hmac->innerHashKeyed = WC_HMAC_INNER_HASH_KEYED_DEV;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_HmacUpdate                                                            */
/* ------------------------------------------------------------------------ */
int wc_HmacUpdate(Hmac* hmac, const byte* msg, word32 length)
{
    TiHmacCtx *ctx;
    if (hmac == NULL || hmac->heap == NULL) return BAD_FUNC_ARG;
    ctx = (TiHmacCtx*)hmac->heap;
    return hmacBufUpdate(&ctx->msg, msg, length);
}

/* ------------------------------------------------------------------------ */
/* wc_HmacFinal                                                             */
/* ------------------------------------------------------------------------ */
int wc_HmacFinal(Hmac* hmac, byte* hash)
{
    DTHE_SHA_Params p;
    DTHE_Handle h;
    TiHmacCtx *ctx;
    int ret;

    if (hmac == NULL || hmac->heap == NULL) return BAD_FUNC_ARG;
    ctx = (TiHmacCtx*)hmac->heap;
    h   = (DTHE_Handle)wolfSSL_TI_getDtheHandle();
    if (h == NULL) { ret = WC_HW_E; goto out; }

    XMEMSET(&p, 0, sizeof(p));
    p.algoType      = ctx->algoType;
    p.ptrDataBuffer = (uint32_t*)(uintptr_t)SOC_virtToPhy((void*)ctx->msg.msg);
    p.dataLenBytes  = ctx->msg.used;
    p.ptrKey        = (uint32_t*)ctx->rawKey;
    p.keySize       = ctx->rawKeySz;

    wolfSSL_TI_lockCCM();
    ret = DTHE_HMACSHA_compute(h, &p);
    wolfSSL_TI_unlockCCM();

    if (ret != DTHE_SHA_RETURN_SUCCESS) {
        ret = WC_HW_E;
        goto out;
    }

    XMEMCPY(hash, p.digest, wc_HmacSizeByType(hmac->macType));
    ret = 0;

out:
    hmacBufFree(&ctx->msg);
    return ret;
}

/* ------------------------------------------------------------------------ */
/* wc_HmacInit                                                              */
/* ------------------------------------------------------------------------ */
int wc_HmacInit(Hmac* hmac, void* heap, int devId)
{
    if (hmac == NULL) return BAD_FUNC_ARG;
    XMEMSET(hmac, 0, sizeof(*hmac));
    hmac->heap = NULL;
    (void)heap; (void)devId;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_HmacCopy                                                              */
/* ------------------------------------------------------------------------ */
int wc_HmacCopy(Hmac* src, Hmac* dst)
{
    TiHmacCtx *sc, *dc;
    int ret;

    if (src == NULL || dst == NULL) return BAD_FUNC_ARG;
    if (src->heap == NULL) { XMEMSET(dst, 0, sizeof(*dst)); return 0; }

    sc = (TiHmacCtx*)src->heap;
    dc = (TiHmacCtx*)XMALLOC(sizeof(TiHmacCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (dc == NULL) return MEMORY_E;
    XMEMCPY(dc, sc, sizeof(TiHmacCtx));

    dc->msg.msg  = NULL;
    dc->msg.used = 0;
    dc->msg.len  = 0;
    if (sc->msg.msg != NULL && sc->msg.used > 0) {
        ret = hmacBufUpdate(&dc->msg, sc->msg.msg, sc->msg.used);
        if (ret != 0) { XFREE(dc, NULL, DYNAMIC_TYPE_TMP_BUFFER); return ret; }
    }

    XMEMCPY(dst, src, sizeof(*dst));
    dst->heap = dc;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_HmacFree                                                              */
/* ------------------------------------------------------------------------ */
void wc_HmacFree(Hmac* hmac)
{
    if (hmac) {
        TiHmacCtx *ctx = (TiHmacCtx*)hmac->heap;
        if (ctx) {
            hmacBufFree(&ctx->msg);
            XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        hmac->heap = NULL;
    }
}

/* ------------------------------------------------------------------------ */
/* wc_HmacSizeByType                                                        */
/* ------------------------------------------------------------------------ */
int wc_HmacSizeByType(int type)
{
    switch (type) {
    #if !defined(NO_MD5)
        case WC_MD5:     return WC_MD5_DIGEST_SIZE;
    #endif
    #if !defined(NO_SHA)
        case WC_SHA:     return WC_SHA_DIGEST_SIZE;
    #endif
    #if defined(WOLFSSL_SHA224)
        case WC_SHA224:  return WC_SHA224_DIGEST_SIZE;
    #endif
    #if !defined(NO_SHA256)
        case WC_SHA256:  return WC_SHA256_DIGEST_SIZE;
    #endif
    #if defined(WOLFSSL_SHA384)
        case WC_SHA384:  return WC_SHA384_DIGEST_SIZE;
    #endif
    #if defined(WOLFSSL_SHA512)
        case WC_SHA512:  return WC_SHA512_DIGEST_SIZE;
    #endif
        default:         return 0;
    }
}

/* ------------------------------------------------------------------------ */
/* _InitHmac                                                                */
/* ------------------------------------------------------------------------ */
int _InitHmac(Hmac* hmac, int type, void* heap)
{
    (void)hmac; (void)type; (void)heap;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* _HmacInitIOHashes                                                        */
/* ------------------------------------------------------------------------ */
int _HmacInitIOHashes(Hmac* hmac)
{
    (void)hmac;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_HmacSetKey_ex                                                         */
/* ------------------------------------------------------------------------ */
int wc_HmacSetKey_ex(Hmac* hmac, int type, const byte* key,
                     word32 length, int allowFlag)
{
    (void)allowFlag;
    return wc_HmacSetKey(hmac, type, key, length);
}

/* ------------------------------------------------------------------------ */
/* wolfSSL_GetHmacMaxSize                                                   */
/* ------------------------------------------------------------------------ */
int wolfSSL_GetHmacMaxSize(void)
{
    return WC_MAX_DIGEST_SIZE;
}

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_TI_HASH && !NO_HMAC */