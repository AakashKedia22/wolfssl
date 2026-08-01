/* port/ti/ti-rsa.c
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

#if defined(WOLFSSL_TI_CRYPT) && !defined(NO_RSA)

#ifdef __cplusplus
    extern "C" {
#endif

#include <stdint.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/port/ti/ti-ccm.h>
#include "ti-am26xx.h"

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/crypto.h>
#endif

#include <security_common/drivers/crypto/asym_crypt.h>

/* ------------------------------------------------------------------------ */
/* Big integer helpers.                                                      */
/*                                                                           */
/* The TI AsymCrypt driver uses the "bigint" format:                         */
/*   [0] = number of data words, then the words least-significant first.     */
/* The words themselves are host-endian (little-endian on AM26Px).           */
/* These helpers convert between that format and big-endian byte strings,    */
/* matching what Crypto_Uint8ToUint32()/Crypto_Uint32ToBigInt() in           */
/* crypto_util.c do -- but without mutating the source buffer.               */
/* ------------------------------------------------------------------------ */

static void tiBytesToBigInt(const byte* bytes, word32 byteLen, uint32_t* out)
{
    word32 words = (byteLen + 3u) / 4u;
    word32 i;

    out[0] = words;
    for (i = 0; i < words; i++) {
        uint32_t val = 0;
        word32 s;
        for (s = 0; s < 4u; s++) {
            int byteIdx = (int)byteLen - (int)(4u * i) - 1 - (int)s;
            if (byteIdx >= 0)
                val |= ((uint32_t)bytes[byteIdx]) << (8u * s);
        }
        out[1u + i] = val;
    }
}

/* bigint -> big-endian bytes, zero-padded to exactly byteLen bytes */
static void tiBigIntToBytes(const uint32_t* in, word32 byteLen, byte* out)
{
    word32 i;

    XMEMSET(out, 0, byteLen);
    for (i = 0; i < in[0]; i++) {
        uint32_t val = in[1u + i];
        word32 s;
        for (s = 0; s < 4u; s++) {
            int byteIdx = (int)(4u * i) + (int)s;
            if (byteIdx < (int)byteLen)
                out[byteLen - 1u - (word32)byteIdx] = (byte)(val >> (8u * s));
        }
    }
}

static int tiBigIntToMp(const uint32_t* big, word32 byteLen, mp_int* mp)
{
    byte* buf;
    int ret;

    if (big == NULL || mp == NULL)
        return BAD_FUNC_ARG;

    buf = (byte*)XMALLOC(byteLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL)
        return MEMORY_E;

    tiBigIntToBytes(big, byteLen, buf);
    ret = mp_read_unsigned_bin(mp, buf, (int)byteLen);

    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

static int tiMpToBigInt(const mp_int* mp, word32 byteLen, uint32_t* out)
{
    byte* buf;
    int ret;

    if (mp == NULL || out == NULL)
        return BAD_FUNC_ARG;

    buf = (byte*)XMALLOC(byteLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL)
        return MEMORY_E;

    ret = mp_to_unsigned_bin_len((mp_int*)mp, buf, (int)byteLen);
    if (ret == MP_OKAY)
        tiBytesToBigInt(buf, byteLen, out);

    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Fill an AsymCrypt_RSAPubkey from a wolfSSL RsaKey (public parts). */
static int tiRsaPubFromKey(RsaKey* key, struct AsymCrypt_RSAPubkey* pub)
{
    int keyLen = wc_RsaEncryptSize(key);
    int eSz;
    int ret;

    if (keyLen <= 0)
        return BAD_FUNC_ARG;

    ret = tiMpToBigInt(&key->n, (word32)keyLen, pub->n);
    if (ret != 0)
        return ret;

    eSz = mp_unsigned_bin_size(&key->e);
    if (eSz <= 0)
        eSz = 1;
    return tiMpToBigInt(&key->e, (word32)eSz, pub->e);
}

#if !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* Fill an AsymCrypt_RSAPrivkey (full CRT set) from a wolfSSL RsaKey. */
static int tiRsaPrivFromKey(RsaKey* key, struct AsymCrypt_RSAPrivkey* priv)
{
    int keyLen = wc_RsaEncryptSize(key);
    int halfLen;
    int ret;
    mp_int dP, dQ, u;
    int hasCrt;
    int needCrt = 1;

    if (keyLen <= 0)
        return BAD_FUNC_ARG;
    halfLen = keyLen / 2;

    ret = tiMpToBigInt(&key->n, (word32)keyLen, priv->n);
    if (ret != 0)
        return ret;
    ret = tiMpToBigInt(&key->d, (word32)keyLen, priv->d);
    if (ret != 0)
        return ret;
    ret = tiMpToBigInt(&key->p, (word32)halfLen, priv->p);
    if (ret != 0)
        return ret;
    ret = tiMpToBigInt(&key->q, (word32)halfLen, priv->q);
    if (ret != 0)
        return ret;

#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || !defined(RSA_LOW_MEM)
    hasCrt = 1;
    ret = tiMpToBigInt(&key->dP, (word32)halfLen, priv->dp);
    if (ret != 0)
        return ret;
    ret = tiMpToBigInt(&key->dQ, (word32)halfLen, priv->dq);
    if (ret != 0)
        return ret;
    ret = tiMpToBigInt(&key->u, (word32)halfLen, priv->coefficient);
    if (ret != 0)
        return ret;
#else
    hasCrt = 0;
#endif

    if (!hasCrt && needCrt) {
        /* RSA_LOW_MEM keys carry n, e, d, p, q only. Reconstruct the CRT
         * parameters in software so the driver gets a complete key. */
        mp_int pm1, qm1;

        if (mp_init_multi(&pm1, &qm1, &dP, &dQ, &u, NULL) != MP_OKAY)
            return MEMORY_E;

        ret = mp_sub_d(&key->p, 1, &pm1);
        if (ret == MP_OKAY)
            ret = mp_mod(&key->d, &pm1, &dP);
        ret = mp_sub_d(&key->q, 1, &qm1);
        if (ret == MP_OKAY)
            ret = mp_mod(&key->d, &qm1, &dQ);
        if (ret == MP_OKAY)
            ret = mp_invmod(&key->q, &key->p, &u);

        if (ret == MP_OKAY) {
            byte tmp[256];
            XMEMSET(tmp, 0, sizeof(tmp));
            ret = mp_to_unsigned_bin_len(&dP, tmp, halfLen);
            if (ret == MP_OKAY) {
                tiBytesToBigInt(tmp, (word32)halfLen, priv->dp);
                ret = mp_to_unsigned_bin_len(&dQ, tmp, halfLen);
            }
            if (ret == MP_OKAY) {
                tiBytesToBigInt(tmp, (word32)halfLen, priv->dq);
                ret = mp_to_unsigned_bin_len(&u, tmp, halfLen);
            }
            if (ret == MP_OKAY)
                tiBytesToBigInt(tmp, (word32)halfLen, priv->coefficient);
        }

        mp_clear(&pm1);
        mp_clear(&qm1);
        mp_clear(&dP);
        mp_clear(&dQ);
        mp_clear(&u);
    }

    return ret;
}
#endif /* !WOLFSSL_RSA_PUBLIC_ONLY */

/* ------------------------------------------------------------------------ */
/* wc_InitRsaKey                                                            */
/* ------------------------------------------------------------------------ */
int wc_InitRsaKey(RsaKey* key, void* heap)
{
    return wc_InitRsaKey_ex(key, heap, INVALID_DEVID);
}

/* ------------------------------------------------------------------------ */
/* wc_InitRsaKey_ex                                                         */
/* ------------------------------------------------------------------------ */
int wc_InitRsaKey_ex(RsaKey* key, void* heap, int devId)
{
    int ret = 0;

    (void)devId;

    if (key == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(key, 0, sizeof(RsaKey));
    key->type  = RSA_TYPE_UNKNOWN;
    key->state = 0; /* RSA_STATE_NONE */
    key->heap  = heap;

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    ret = mp_init_multi(&key->n, &key->e, NULL, NULL, NULL, NULL);
    if (ret != MP_OKAY)
        return ret;

#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || !defined(RSA_LOW_MEM)
    ret = mp_init_multi(&key->d, &key->p, &key->q, &key->dP, &key->dQ, &key->u);
#else
    ret = mp_init_multi(&key->d, &key->p, &key->q, NULL, NULL, NULL);
#endif
    if (ret != MP_OKAY) {
        mp_clear(&key->n);
        mp_clear(&key->e);
        return ret;
    }
#else
    ret = mp_init(&key->n);
    if (ret != MP_OKAY)
        return ret;
    ret = mp_init(&key->e);
    if (ret != MP_OKAY) {
        mp_clear(&key->n);
        return ret;
    }
#endif

    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_FreeRsaKey                                                            */
/* ------------------------------------------------------------------------ */
int wc_FreeRsaKey(RsaKey* key)
{
    if (key == NULL)
        return 0;

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    /* Forcezero all private key fields to scrub residual sensitive data. */
#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || !defined(RSA_LOW_MEM)
    mp_forcezero(&key->u);
    mp_forcezero(&key->dQ);
    mp_forcezero(&key->dP);
#endif
    mp_forcezero(&key->q);
    mp_forcezero(&key->p);
    mp_forcezero(&key->d);
#endif

    mp_clear(&key->n);
    mp_clear(&key->e);

#if !defined(WOLFSSL_NO_MALLOC) && (defined(WOLFSSL_ASYNC_CRYPT) || \
    (!defined(WOLFSSL_RSA_VERIFY_ONLY) && !defined(WOLFSSL_RSA_VERIFY_INLINE)))
    if (key->dataIsAlloc == 1) {
        XFREE(key->data, key->heap, DYNAMIC_TYPE_RSA);
        key->data = NULL;
        key->dataIsAlloc = 0;
    }
#endif

    key->type = RSA_TYPE_UNKNOWN;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_RsaEncryptSize                                                        */
/* ------------------------------------------------------------------------ */
int wc_RsaEncryptSize(const RsaKey* key)
{
    if (key == NULL)
        return BAD_FUNC_ARG;

    return mp_unsigned_bin_size(&key->n);
}

/* ------------------------------------------------------------------------ */
/* wc_RsaFunction                                                           */
/*                                                                           */
/* Raw RSA exponentiation. The input is already a key-length block:          */
/*   RSA_PUBLIC_ENCRYPT  : out = in^e mod n  (AsymCrypt_RSAPublic)           */
/*   RSA_PUBLIC_DECRYPT  : out = in^e mod n  (AsymCrypt_RSAPublic)           */
/*   RSA_PRIVATE_ENCRYPT : out = in^d mod n  (AsymCrypt_RSAPrivate)          */
/*   RSA_PRIVATE_DECRYPT : out = in^d mod n  (AsymCrypt_RSAPrivate)          */
/*                                                                           */
/* The PKA performs the blinding internally, so the rng argument is only     */
/* accepted for API compatibility (it may be NULL, as callers like           */
/* wc_RsaPrivateDecrypt pass it).                                            */
/* ------------------------------------------------------------------------ */
int wc_RsaFunction(const byte* in, word32 inLen, byte* out, word32* outLen,
                   int type, RsaKey* key, WC_RNG* rng)
{
    int ret = 0;
    int keyLen;
    int isPriv;
    AsymCrypt_Handle h;
    uint32_t* mBig   = NULL;
    uint32_t* result = NULL;
    AsymCrypt_Return_t st;

    (void)rng;

    if (key == NULL || in == NULL || out == NULL || outLen == NULL)
        return BAD_FUNC_ARG;
    if (inLen == 0 || *outLen == 0 || type == RSA_TYPE_UNKNOWN)
        return BAD_FUNC_ARG;
    if (type != RSA_PUBLIC_ENCRYPT && type != RSA_PUBLIC_DECRYPT &&
        type != RSA_PRIVATE_ENCRYPT && type != RSA_PRIVATE_DECRYPT)
        return BAD_FUNC_ARG;

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (key->devId != INVALID_DEVID)
    #endif
    {
        ret = wc_CryptoCb_Rsa(in, inLen, out, outLen, type, key, rng);
        #ifndef WOLF_CRYPTO_CB_ONLY_RSA
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable and use the PKA */
        #else
        if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return NO_VALID_DEVID;
        return ret;
        #endif
    }
#endif
#ifdef WOLF_CRYPTO_CB_ONLY_RSA
    return NO_VALID_DEVID;
#endif

    keyLen = wc_RsaEncryptSize(key);
    if (keyLen <= 0)
        return BAD_FUNC_ARG;
    if (inLen != (word32)keyLen)
        return BAD_FUNC_ARG;
    if (*outLen < (word32)keyLen)
        return BAD_FUNC_ARG;

    isPriv = (type == RSA_PRIVATE_DECRYPT || type == RSA_PRIVATE_ENCRYPT);
#ifdef WOLFSSL_RSA_PUBLIC_ONLY
    if (isPriv)
        return BAD_FUNC_ARG;
#endif

    h = wolfSSL_TI_getAsymCryptHandle();
    if (h == NULL)
        return WC_HW_E;

    mBig = (uint32_t*)XMALLOC(sizeof(uint32_t) * RSA_MAX_LENGTH, key->heap,
                              DYNAMIC_TYPE_RSA);
    result = (uint32_t*)XMALLOC(sizeof(uint32_t) * RSA_MAX_LENGTH, key->heap,
                                DYNAMIC_TYPE_RSA);
    if (mBig == NULL || result == NULL) {
        ret = MEMORY_E;
        goto done;
    }

    tiBytesToBigInt(in, inLen, mBig);

    if (isPriv) {
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
        struct AsymCrypt_RSAPrivkey* priv;

        priv = (struct AsymCrypt_RSAPrivkey*)XMALLOC(sizeof(*priv), key->heap,
                                              DYNAMIC_TYPE_RSA);
        if (priv == NULL) {
            ret = MEMORY_E;
            goto done;
        }

        XMEMSET(priv, 0, sizeof(*priv));
        ret = tiRsaPrivFromKey(key, priv);
        if (ret == 0) {
            wolfSSL_TI_lockCCM();
            st = AsymCrypt_RSAPrivate(h, mBig, priv, result);
            wolfSSL_TI_unlockCCM();
            if (st != ASYM_CRYPT_RETURN_SUCCESS)
                ret = WC_HW_E;
        }

        XFREE(priv, key->heap, DYNAMIC_TYPE_RSA);
#else
        ret = BAD_FUNC_ARG;
        goto done;
#endif
    }
    else {
        struct AsymCrypt_RSAPubkey pub;

        XMEMSET(&pub, 0, sizeof(pub));
        ret = tiRsaPubFromKey(key, &pub);
        if (ret == 0) {
            wolfSSL_TI_lockCCM();
            st = AsymCrypt_RSAPublic(h, mBig, &pub, result);
            wolfSSL_TI_unlockCCM();
            if (st != ASYM_CRYPT_RETURN_SUCCESS)
                ret = WC_HW_E;
        }
    }

    if (ret == 0) {
        tiBigIntToBytes(result, (word32)keyLen, out);
        *outLen = (word32)keyLen;
    }

done:
    if (mBig != NULL)
        XFREE(mBig, key->heap, DYNAMIC_TYPE_RSA);
    if (result != NULL)
        XFREE(result, key->heap, DYNAMIC_TYPE_RSA);
    return ret;
}

#ifdef WOLFSSL_KEY_GEN
/* ------------------------------------------------------------------------ */
/* wc_MakeRsaKey                                                            */
/* ------------------------------------------------------------------------ */
int wc_MakeRsaKey(RsaKey* key, int size, long e, WC_RNG* rng)
{
    AsymCrypt_Handle h;
    struct AsymCrypt_RSAPrivkey* priv;
    uint32_t eBig[ASYM_CRYPT_LEN(RSA_KEY_E_MAXLEN)];
    byte ebuf[4];
    word32 eLen;
    int keyLen;
    int halfLen;
    int ret = 0;
    word32 i;

    (void)rng;

    if (key == NULL || rng == NULL)
        return BAD_FUNC_ARG;
    if (size < RSA_MIN_SIZE || size > 4096 || (size & 63) != 0)
        return BAD_FUNC_ARG;
    if (e < 3 || (e & 1) == 0)
        return BAD_FUNC_ARG;

    h = wolfSSL_TI_getAsymCryptHandle();
    if (h == NULL)
        return WC_HW_E;

    /* Encode the public exponent (fits in 32 bits) as a bigint. */
    XMEMSET(ebuf, 0, sizeof(ebuf));
    XMEMSET(eBig, 0, sizeof(eBig));
    ebuf[0] = (byte)((e >> 24) & 0xFF);
    ebuf[1] = (byte)((e >> 16) & 0xFF);
    ebuf[2] = (byte)((e >> 8) & 0xFF);
    ebuf[3] = (byte)(e & 0xFF);
    eLen = 4;
    for (i = 0; i < 4; i++) {
        if (ebuf[i] != 0) {
            eLen = 4 - i;
            break;
        }
    }
    if (eLen == 0)
        eLen = 1;
    tiBytesToBigInt(ebuf + (4 - eLen), eLen, eBig);

    priv = (struct AsymCrypt_RSAPrivkey*)XMALLOC(sizeof(*priv), key->heap,
                                          DYNAMIC_TYPE_RSA);
    if (priv == NULL)
        return MEMORY_E;
    XMEMSET(priv, 0, sizeof(*priv));

    /* The driver needs the public exponent populated so it can derive d. */
    XMEMCPY(priv->e, eBig, sizeof(eBig));

    wolfSSL_TI_lockCCM();
    if (AsymCrypt_RSAKeyGenPrivate(h, priv, (uint32_t)size)
            != ASYM_CRYPT_RETURN_SUCCESS) {
        wolfSSL_TI_unlockCCM();
        XFREE(priv, key->heap, DYNAMIC_TYPE_RSA);
        return WC_HW_E;
    }
    wolfSSL_TI_unlockCCM();

    keyLen  = size / 8;
    halfLen = size / 16;

    ret = tiBigIntToMp(priv->n, (word32)keyLen, &key->n);
    if (ret == 0)
        ret = tiBigIntToMp(priv->d, (word32)keyLen, &key->d);
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
    if (ret == 0)
        ret = tiBigIntToMp(priv->p, (word32)halfLen, &key->p);
    if (ret == 0)
        ret = tiBigIntToMp(priv->q, (word32)halfLen, &key->q);
#endif
    if (ret == 0)
        ret = tiBigIntToMp(priv->e, (word32)(priv->e[0] * 4u), &key->e);
#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || !defined(RSA_LOW_MEM)
    if (ret == 0)
        ret = tiBigIntToMp(priv->dp, (word32)halfLen, &key->dP);
    if (ret == 0)
        ret = tiBigIntToMp(priv->dq, (word32)halfLen, &key->dQ);
    if (ret == 0)
        ret = tiBigIntToMp(priv->coefficient, (word32)halfLen, &key->u);
#endif

    XFREE(priv, key->heap, DYNAMIC_TYPE_RSA);

    if (ret == 0)
        key->type = RSA_PRIVATE;

    return ret;
}
#endif /* WOLFSSL_KEY_GEN */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_TI_CRYPT && !NO_RSA */
