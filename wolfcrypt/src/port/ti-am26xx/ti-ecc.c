/* port/ti/ti-ecc.c
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

#if defined(WOLFSSL_TI_CRYPT) && defined(HAVE_ECC)

#ifdef __cplusplus
    extern "C" {
#endif

#include <stdint.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/port/ti/ti-ccm.h>
#include "ti-am26xx.h"

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#ifndef NO_ASN
    #include <wolfssl/wolfcrypt/asn.h>
#endif

#include <security_common/drivers/crypto/asym_crypt.h>
#include <modules/ecdsa/ecdsa.h>

/* ------------------------------------------------------------------------ */
/* TI curve IDs (Ecdsa_getPrimeCurve) for the wolfSSL curves we support.     */
/*                                                                           */
/* These are the curveId values the TIFS-MCU ECDSA module (modules/ecdsa)    */
/* accepts. They differ from wolfSSL's ECC_*_R1 curve ids.                   */
/* ------------------------------------------------------------------------ */
#define TI_ECDSA_CURVE_P256  (8U)   /* prime256v1  */
#define TI_ECDSA_CURVE_P384  (10U)  /* secp384r1   */
#define TI_ECDSA_CURVE_P521  (11U)  /* secp521r1   */
#define TI_ECDSA_CURVE_BRAINPOOLP512R1 (6U)

/* ------------------------------------------------------------------------ */
/* Big integer helpers -- same "bigint" format as the RSA port.              */
/* ------------------------------------------------------------------------ */

static void tiEccBytesToBigInt(const byte* bytes, word32 byteLen, uint32_t* out)
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
static void tiEccBigIntToBytes(const uint32_t* in, word32 byteLen, byte* out)
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

static int tiEccBigIntToMp(const uint32_t* big, word32 byteLen, mp_int* mp)
{
    byte* buf;
    int ret;

    if (big == NULL || mp == NULL)
        return BAD_FUNC_ARG;

    buf = (byte*)XMALLOC(byteLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL)
        return MEMORY_E;

    tiEccBigIntToBytes(big, byteLen, buf);
    ret = mp_read_unsigned_bin(mp, buf, (int)byteLen);

    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

static int tiEccMpToBigInt(const mp_int* mp, word32 byteLen, uint32_t* out)
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
        tiEccBytesToBigInt(buf, byteLen, out);

    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* ------------------------------------------------------------------------ */
/* Curve helpers                                                            */
/* ------------------------------------------------------------------------ */

static int tiEccMapCurve(int wolfCurveId, uint32_t* tiCurveId)
{
    switch (wolfCurveId) {
        case ECC_SECP256R1:
            *tiCurveId = TI_ECDSA_CURVE_P256;
            return 0;
        case ECC_SECP384R1:
            *tiCurveId = TI_ECDSA_CURVE_P384;
            return 0;
        case ECC_SECP521R1:
            *tiCurveId = TI_ECDSA_CURVE_P521;
            return 0;
        case ECC_BRAINPOOLP512R1:
            *tiCurveId = TI_ECDSA_CURVE_BRAINPOOLP512R1;
            return 0;
        default:
            return ECC_CURVE_OID_E;
    }
}

/* Populate an AsymCrypt_ECPrimeCurveP (and the order bit length) for a
 * wolfSSL curve id. */
static int tiEccGetCurve(int wolfCurveId, struct AsymCrypt_ECPrimeCurveP* cp,
                         ECDSA_primeCurve* raw)
{
    uint32_t tiCurveId;
    word32 words;
    int ret;

    ret = tiEccMapCurve(wolfCurveId, &tiCurveId);
    if (ret != 0)
        return ret;

    if (Ecdsa_getPrimeCurve(tiCurveId, raw) != ECDSA_RETURN_SUCCESS)
        return ECC_CURVE_OID_E;

    /* Each parameter array is a bigint: [wordCount, words...]. Copy the
     * full (wordCount + 1) words; this handles P-521 correctly where a
     * byte-length heuristic would truncate the final partial word. */
    words = raw->prime[0] + 1u;
    XMEMSET(cp, 0, sizeof(*cp));
    XMEMCPY(cp->prime, raw->prime, words * sizeof(uint32_t));
    XMEMCPY(cp->order, raw->order, words * sizeof(uint32_t));
    XMEMCPY(cp->a,     raw->A,     words * sizeof(uint32_t));
    XMEMCPY(cp->b,     raw->B,     words * sizeof(uint32_t));
    XMEMCPY(cp->g.x,   raw->gX,    words * sizeof(uint32_t));
    XMEMCPY(cp->g.y,   raw->gY,    words * sizeof(uint32_t));

    return 0;
}

/* Select an ecc_set for this key from a key size or a curve id. Mirrors
 * wc_ecc_set_curve(). */
static int tiEccSetCurve(ecc_key* key, int keysize, int curve_id)
{
    int x;

    if (key == NULL || (keysize <= 0 && curve_id < 0))
        return BAD_FUNC_ARG;
    if (keysize > ECC_MAXSIZE)
        return ECC_BAD_ARG_E;

    key->idx = 0;
    key->dp  = NULL;

    for (x = 0; ecc_sets[x].size != 0; x++) {
        if (curve_id > ECC_CURVE_DEF) {
            if (curve_id == ecc_sets[x].id)
                break;
        }
        else if (keysize <= ecc_sets[x].size) {
            break;
        }
    }
    if (ecc_sets[x].size == 0)
        return ECC_CURVE_OID_E;

    key->idx = x;
    key->dp  = &ecc_sets[x];

    return 0;
}

/* Truncate/reduce a digest to the curve's order bit length, exactly as the
 * software ECDSA does: keep the left-most orderBitlen bits. */
static word32 tiEccReduceHash(const byte* in, word32 inlen,
                              uint32_t orderBitlen, byte* out)
{
    word32 orderBytes = (orderBitlen + 7u) / 8u;
    word32 hlen = (inlen < orderBytes) ? inlen : orderBytes;

    XMEMSET(out, 0, orderBytes);
    XMEMCPY(out, in, hlen);
    if ((8u * hlen) > orderBitlen)
        out[hlen - 1u] &= (byte)(0xFFu >> (8u * hlen - orderBitlen));

    return hlen;
}

/* ------------------------------------------------------------------------ */
/* wc_ecc_init / wc_ecc_init_ex                                             */
/* ------------------------------------------------------------------------ */
int wc_ecc_init(ecc_key* key)
{
    return wc_ecc_init_ex(key, NULL, INVALID_DEVID);
}

int wc_ecc_init_ex(ecc_key* key, void* heap, int devId)
{
    int ret = 0;

    (void)devId;

    if (key == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(key, 0, sizeof(ecc_key));
    key->state = 0; /* ECC_STATE_NONE */

#ifdef ALT_ECC_SIZE
    key->pubkey.x = (mp_int*)&key->pubkey.xyz[0];
    key->pubkey.y = (mp_int*)&key->pubkey.xyz[1];
    key->pubkey.z = (mp_int*)&key->pubkey.xyz[2];
    alt_fp_init(key->pubkey.x);
    alt_fp_init(key->pubkey.y);
    alt_fp_init(key->pubkey.z);
    key->k = (mp_int*)key->ka;
    alt_fp_init(key->k);
#else
    ret = mp_init_multi(key->k, key->pubkey.x, key->pubkey.y, key->pubkey.z,
                        NULL, NULL);
    if (ret != MP_OKAY)
        return MEMORY_E;
#endif

    key->type = ECC_PUBLICKEY;
    key->heap = heap;

    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_ecc_free                                                              */
/* ------------------------------------------------------------------------ */
int wc_ecc_free(ecc_key* key)
{
    if (key == NULL)
        return 0;

    mp_clear(key->pubkey.x);
    mp_clear(key->pubkey.y);
    mp_clear(key->pubkey.z);

#ifdef ALT_ECC_SIZE
    if (key->k != NULL)
#endif
        mp_forcezero(key->k);

    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_ecc_make_key / wc_ecc_make_key_ex / wc_ecc_make_key_ex2               */
/* ------------------------------------------------------------------------ */
int wc_ecc_make_key(WC_RNG* rng, int keysize, ecc_key* key)
{
    return wc_ecc_make_key_ex(rng, keysize, key, ECC_CURVE_DEF);
}

int wc_ecc_make_key_ex(WC_RNG* rng, int keysize, ecc_key* key, int curve_id)
{
    return wc_ecc_make_key_ex2(rng, keysize, key, curve_id, 0);
}

int wc_ecc_make_key_ex2(WC_RNG* rng, int keysize, ecc_key* key, int curve_id,
                        int flags)
{
    int err;
    AsymCrypt_Handle h;
    struct AsymCrypt_ECPrimeCurveP cp;
    ECDSA_primeCurve raw;
    uint32_t priv[ECDSA_MAX_LENGTH];
    struct AsymCrypt_ECPoint pub;
    struct AsymCrypt_ECPoint pubCheck;
    AsymCrypt_Return_t st = ASYM_CRYPT_RETURN_FAILURE;
    word32 orderBytes;

    (void)rng;

    if (key == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    err = tiEccSetCurve(key, keysize, curve_id);
    if (err != 0)
        return err;

    key->flags = (word32)flags;

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (key->devId != INVALID_DEVID)
    #endif
    {
        err = wc_CryptoCb_MakeEccKey(rng, keysize, key, curve_id);
        if (err != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return err;
        /* fall-through when unavailable and use the PKA */
    }
#endif
#ifdef WOLF_CRYPTO_CB_ONLY_ECC
    return NO_VALID_DEVID;
#endif

    h = wolfSSL_TI_getAsymCryptHandle();
    if (h == NULL)
        return WC_HW_E;

    err = tiEccGetCurve(key->dp->id, &cp, &raw);
    if (err != 0)
        return err;

    orderBytes = (word32)key->dp->size;

    wolfSSL_TI_lockCCM();
    st = AsymCrypt_ECDSAKeyGenPrivate(h, &cp, priv, (uint32_t)raw.curveType);
    if (st == ASYM_CRYPT_RETURN_SUCCESS) {
        st = AsymCrypt_ECDSAKeyGenPublic(h, &cp, &pub, priv,
                                         (uint32_t)raw.curveType);
    }
    wolfSSL_TI_unlockCCM();
    if (st != ASYM_CRYPT_RETURN_SUCCESS)
        return WC_HW_E;

    err = tiEccBigIntToMp(priv, orderBytes, key->k);
    if (err == 0)
        err = tiEccBigIntToMp(pub.x, orderBytes, key->pubkey.x);
    if (err == 0)
        err = tiEccBigIntToMp(pub.y, orderBytes, key->pubkey.y);

    /* Self-test: derive the public key from the private key and compare. */
    XMEMSET(&pubCheck, 0, sizeof(pubCheck));
    if (err == 0) {
        uint32_t privCheck[ECDSA_MAX_LENGTH];
        XMEMCPY(privCheck, priv, sizeof(privCheck));
        wolfSSL_TI_lockCCM();
        st = AsymCrypt_ECDSAKeyGenPublic(h, &cp, &pubCheck, privCheck,
                                         (uint32_t)raw.curveType);
        wolfSSL_TI_unlockCCM();
        if (st != ASYM_CRYPT_RETURN_SUCCESS ||
            XMEMCMP(pubCheck.x, pub.x, sizeof(pub.x)) != 0 ||
            XMEMCMP(pubCheck.y, pub.y, sizeof(pub.y)) != 0) {
            err = WC_HW_E;
        }
    }

    if (err == 0)
        key->type = ECC_PRIVATEKEY;
    else
        key->type = ECC_PUBLICKEY;

    return err;
}

/* ------------------------------------------------------------------------ */
/* wc_ecc_sign_hash_ex                                                      */
/* ------------------------------------------------------------------------ */
int wc_ecc_sign_hash_ex(const byte* in, word32 inlen, WC_RNG* rng,
                        ecc_key* key, mp_int* r, mp_int* s)
{
#ifndef WC_ALLOW_ECC_ZERO_HASH
    byte hashIsZero = 0;
    word32 zIdx;
#endif
    int err = 0;
    AsymCrypt_Handle h;
    struct AsymCrypt_ECPrimeCurveP cp;
    ECDSA_primeCurve raw;
    uint32_t privBig[ECDSA_MAX_LENGTH];
    uint32_t hBig[ECDSA_MAX_LENGTH];
    uint32_t kBig[ECDSA_MAX_LENGTH];
    struct AsymCrypt_ECDSASig sig;
    AsymCrypt_Return_t st = ASYM_CRYPT_RETURN_FAILURE;
    byte reduced[ECC_MAXSIZE];
    byte kBytes[ECC_MAXSIZE];
    word32 hlen;
    word32 orderBytes;
    word32 orderBitlen;
    int retries;

    if (in == NULL || r == NULL || s == NULL || key == NULL || rng == NULL)
        return ECC_BAD_ARG_E;
    if ((inlen > WC_MAX_DIGEST_SIZE) || (inlen < WC_MIN_DIGEST_SIZE))
        return BAD_LENGTH_E;

#ifndef WC_ALLOW_ECC_ZERO_HASH
    for (zIdx = 0; zIdx < inlen; zIdx++)
        hashIsZero |= in[zIdx];
    if (hashIsZero == 0)
        return ECC_BAD_ARG_E;
#endif

    if (key->type != ECC_PRIVATEKEY || key->dp == NULL)
        return ECC_BAD_ARG_E;
    if (mp_iszero(key->k))
        return ECC_BAD_ARG_E;

    h = wolfSSL_TI_getAsymCryptHandle();
    if (h == NULL)
        return WC_HW_E;

    err = tiEccGetCurve(key->dp->id, &cp, &raw);
    if (err != 0)
        return err;

    orderBitlen = raw.orderBitlen;
    orderBytes  = (word32)key->dp->size;

    /* digest reduced to the order bit length */
    hlen = tiEccReduceHash(in, inlen, orderBitlen, reduced);
    tiEccBytesToBigInt(reduced, hlen, hBig);

    /* private key as bigint */
    err = tiEccMpToBigInt(key->k, orderBytes, privBig);
    if (err != 0)
        return err;

    /* random k (retry on the astronomically unlikely k mod n == 0) */
    for (retries = 0; retries < 8; retries++) {
        if (wc_RNG_GenerateBlock(rng, kBytes, orderBytes) != 0)
            return RNG_FAILURE_E;
        if ((8u * orderBytes) > orderBitlen)
            kBytes[orderBytes - 1u] &= (byte)(0xFFu >> (8u * orderBytes - orderBitlen));
        tiEccBytesToBigInt(kBytes, orderBytes, kBig);

        wolfSSL_TI_lockCCM();
        st = AsymCrypt_ECDSASign(h, &cp, privBig, kBig, hBig, &sig,
                                 (uint32_t)raw.curveType);
        wolfSSL_TI_unlockCCM();
        if (st == ASYM_CRYPT_RETURN_SUCCESS)
            break;
    }
    if (st != ASYM_CRYPT_RETURN_SUCCESS)
        return WC_HW_E;

    err = tiEccBigIntToMp(sig.r, orderBytes, r);
    if (err != 0)
        return err;
    err = tiEccBigIntToMp(sig.s, orderBytes, s);
    if (err != 0)
        return err;

    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_ecc_sign_hash                                                         */
/* ------------------------------------------------------------------------ */
int wc_ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32* outlen,
                     WC_RNG* rng, ecc_key* key)
{
    int err;
    mp_int r;
    mp_int s;

    if (in == NULL || out == NULL || outlen == NULL || key == NULL)
        return ECC_BAD_ARG_E;
    if ((inlen > WC_MAX_DIGEST_SIZE) ||
        (inlen < WC_MIN_DIGEST_SIZE_FOR_SIGN))
        return BAD_LENGTH_E;
    if (rng == NULL)
        return ECC_BAD_ARG_E;

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (key->devId != INVALID_DEVID)
    #endif
    {
        err = wc_CryptoCb_EccSign(in, inlen, out, outlen, rng, key);
        if (err != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return err;
        /* fall-through when unavailable and use the PKA */
    }
#endif
#ifdef WOLF_CRYPTO_CB_ONLY_ECC
    return NO_VALID_DEVID;
#endif

    if (key->dp == NULL)
        return ECC_BAD_ARG_E;

    mp_init(&r);
    mp_init(&s);

    err = wc_ecc_sign_hash_ex(in, inlen, rng, key, &r, &s);
    if (err < 0) {
        mp_clear(&r);
        mp_clear(&s);
        return err;
    }

#ifndef NO_ASN
    err = StoreECC_DSA_Sig(out, outlen, &r, &s);
#else
    {
        word32 keySz = (word32)key->dp->size;
        if (*outlen < keySz * 2u)
            err = BUFFER_E;
        else {
            *outlen = keySz * 2u;
            err = mp_to_unsigned_bin_len(&r, out, (int)keySz);
            if (err == 0)
                err = mp_to_unsigned_bin_len(&s, out + keySz, (int)keySz);
        }
    }
#endif

    mp_clear(&r);
    mp_clear(&s);
    return err;
}

/* ------------------------------------------------------------------------ */
/* wc_ecc_verify_hash_ex                                                    */
/* ------------------------------------------------------------------------ */
int wc_ecc_verify_hash_ex(mp_int* r, mp_int* s, const byte* hash,
                          word32 hashlen, int* res, ecc_key* key)
{
    int err = 0;
    AsymCrypt_Handle h;
    struct AsymCrypt_ECPrimeCurveP cp;
    ECDSA_primeCurve raw;
    uint32_t rBig[ECDSA_MAX_LENGTH];
    uint32_t sBig[ECDSA_MAX_LENGTH];
    uint32_t hBig[ECDSA_MAX_LENGTH];
    struct AsymCrypt_ECPoint pub;
    struct AsymCrypt_ECDSASig sig;
    AsymCrypt_Return_t st;
    byte reduced[ECC_MAXSIZE];
    word32 hlen;
    word32 orderBytes;
    word32 orderBitlen;

    if (r == NULL || s == NULL || hash == NULL || res == NULL || key == NULL)
        return ECC_BAD_ARG_E;
    if ((hashlen > WC_MAX_DIGEST_SIZE) ||
        (hashlen < WC_MIN_DIGEST_SIZE_FOR_VERIFY))
        return BAD_LENGTH_E;

    if (key->dp == NULL)
        return ECC_BAD_ARG_E;

    *res = 0;

    h = wolfSSL_TI_getAsymCryptHandle();
    if (h == NULL)
        return WC_HW_E;

    err = tiEccGetCurve(key->dp->id, &cp, &raw);
    if (err != 0)
        return err;

    orderBitlen = raw.orderBitlen;
    orderBytes  = (word32)key->dp->size;

    hlen = tiEccReduceHash(hash, hashlen, orderBitlen, reduced);
    tiEccBytesToBigInt(reduced, hlen, hBig);

    err = tiEccMpToBigInt(r, orderBytes, rBig);
    if (err != 0)
        return err;
    err = tiEccMpToBigInt(s, orderBytes, sBig);
    if (err != 0)
        return err;

    XMEMCPY(sig.r, rBig, sizeof(sig.r));
    XMEMCPY(sig.s, sBig, sizeof(sig.s));

    err = tiEccMpToBigInt(key->pubkey.x, orderBytes, pub.x);
    if (err != 0)
        return err;
    err = tiEccMpToBigInt(key->pubkey.y, orderBytes, pub.y);
    if (err != 0)
        return err;

    wolfSSL_TI_lockCCM();
    st = AsymCrypt_ECDSAVerify(h, &cp, &pub, &sig, hBig,
                               (uint32_t)raw.curveType);
    wolfSSL_TI_unlockCCM();

    if (st == ASYM_CRYPT_RETURN_SUCCESS)
        *res = 1;
    else if (st != ASYM_CRYPT_RETURN_FAILURE)
        return WC_HW_E;

    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_ecc_verify_hash                                                       */
/* ------------------------------------------------------------------------ */
int wc_ecc_verify_hash(const byte* sig, word32 siglen, const byte* hash,
                       word32 hashlen, int* res, ecc_key* key)
{
    int err = 0;
    mp_int r;
    mp_int s;

    if (sig == NULL || hash == NULL || res == NULL || key == NULL)
        return ECC_BAD_ARG_E;
    if ((hashlen > WC_MAX_DIGEST_SIZE) ||
        (hashlen < WC_MIN_DIGEST_SIZE_FOR_VERIFY))
        return BAD_LENGTH_E;

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (key->devId != INVALID_DEVID)
    #endif
    {
        err = wc_CryptoCb_EccVerify(sig, siglen, hash, hashlen, res, key);
        if (err != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return err;
        /* fall-through when unavailable and use the PKA */
    }
#endif
#ifdef WOLF_CRYPTO_CB_ONLY_ECC
    return NO_VALID_DEVID;
#endif

    if (key->dp == NULL)
        return ECC_BAD_ARG_E;

    *res = 0;

#ifndef NO_ASN
    /* DecodeECC_DSA_Sig() calls mp_init() on r and s. */
    err = DecodeECC_DSA_Sig(sig, siglen, &r, &s);
    if (err < 0) {
        mp_clear(&r);
        mp_clear(&s);
        return err;
    }
#else
    {
        word32 keySz = (word32)key->dp->size;
        if (siglen != keySz * 2u) {
            return ECC_BAD_ARG_E;
        }
        mp_init(&r);
        mp_init(&s);
        mp_read_unsigned_bin(&r, sig, (int)keySz);
        mp_read_unsigned_bin(&s, sig + keySz, (int)keySz);
    }
#endif

    err = wc_ecc_verify_hash_ex(&r, &s, hash, hashlen, res, key);

    mp_clear(&r);
    mp_clear(&s);
    return err;
}

#ifdef HAVE_ECC_DHE
/* ------------------------------------------------------------------------ */
/* wc_ecc_shared_secret_ex                                                  */
/* ------------------------------------------------------------------------ */
int wc_ecc_shared_secret_ex(ecc_key* private_key, ecc_point* point,
                            byte* out, word32* outlen)
{
    int err = 0;
    AsymCrypt_Handle h;
    struct AsymCrypt_ECPrimeCurveP cp;
    ECDSA_primeCurve raw;
    uint32_t privBig[ECDSA_MAX_LENGTH];
    struct AsymCrypt_ECPoint pub;
    struct AsymCrypt_ECPoint secret;
    AsymCrypt_Return_t st;
    word32 orderBytes;

    if (private_key == NULL || point == NULL || out == NULL ||
        outlen == NULL)
        return BAD_FUNC_ARG;

    if (private_key->type != ECC_PRIVATEKEY &&
        private_key->type != ECC_PRIVATEKEY_ONLY)
        return ECC_BAD_ARG_E;

    if (private_key->dp == NULL)
        return ECC_BAD_ARG_E;

    orderBytes = (word32)private_key->dp->size;
    if (*outlen < orderBytes)
        return BUFFER_E;

    h = wolfSSL_TI_getAsymCryptHandle();
    if (h == NULL)
        return WC_HW_E;

    err = tiEccGetCurve(private_key->dp->id, &cp, &raw);
    if (err != 0)
        return err;

    err = tiEccMpToBigInt(private_key->k, orderBytes, privBig);
    if (err != 0)
        return err;
    err = tiEccMpToBigInt(point->x, orderBytes, pub.x);
    if (err != 0)
        return err;
    err = tiEccMpToBigInt(point->y, orderBytes, pub.y);
    if (err != 0)
        return err;

    wolfSSL_TI_lockCCM();
    st = AsymCrypt_EcdhGenSharedSecret(h, &cp, privBig, &pub, &secret,
                                       (uint32_t)raw.curveType);
    wolfSSL_TI_unlockCCM();
    if (st != ASYM_CRYPT_RETURN_SUCCESS)
        return WC_HW_E;

    tiEccBigIntToBytes(secret.x, orderBytes, out);
    *outlen = orderBytes;

    return 0;
}

/* ------------------------------------------------------------------------ */
/* wc_ecc_shared_secret                                                     */
/* ------------------------------------------------------------------------ */
int wc_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key, byte* out,
                         word32* outlen)
{
    int err = 0;

    (void)err;

    if (private_key == NULL || public_key == NULL || out == NULL ||
        outlen == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (private_key->devId != INVALID_DEVID)
    #endif
    {
        err = wc_CryptoCb_Ecdh(private_key, public_key, out, outlen);
        if (err != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return err;
        /* fall-through when unavailable and use the PKA */
    }
#endif
#ifdef WOLF_CRYPTO_CB_ONLY_ECC
    return NO_VALID_DEVID;
#endif

    if (private_key->type != ECC_PRIVATEKEY &&
        private_key->type != ECC_PRIVATEKEY_ONLY)
        return ECC_BAD_ARG_E;

    if (private_key->dp == NULL || public_key->dp == NULL)
        return ECC_BAD_ARG_E;

    if (private_key->dp->id != public_key->dp->id)
        return ECC_BAD_ARG_E;

    err = wc_ecc_shared_secret_ex(private_key, &public_key->pubkey, out,
                                  outlen);
    return err;
}
#endif /* HAVE_ECC_DHE */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_TI_CRYPT && HAVE_ECC */
