/* port/ti/ti-ed25519.c
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

#if defined(WOLFSSL_TI_CRYPT) && defined(HAVE_ED25519)

#ifdef __cplusplus
    extern "C" {
#endif

#include <stdint.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/port/ti/ti-ccm.h>
#include "ti-am26xx.h"

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#include <security_common/drivers/crypto/asym_crypt.h>
#include <security_common/drivers/crypto/dthe/dthe.h>
#include <security_common/drivers/crypto/dthe/dthe_sha.h>

/* ------------------------------------------------------------------------ */
/* Internal helpers                                                          */
/* ------------------------------------------------------------------------ */

/* The AsymCrypt EdDSA engine computes SHA-512 internally through this
 * callback. The digest must be returned in the exact byte order used by the
 * validated SDK example (ed25519_signing_verification): each DTHE digest word
 * is unpacked little-endian.
 *
 * The callback runs while the PKA owns the crypto fabric, so the SHA engine is
 * driven without DMA (identity-mapped RAM, no SOC_virtToPhy() needed) and
 * without taking wolfSSL_TI_lockCCM() again (it is already held around the
 * AsymCrypt call). */
static AsymCrypt_Return_t tiEd25519Sha512(uint8_t* in, uint32_t len,
                                          uint8_t* digest)
{
    DTHE_SHA_Params p;
    DTHE_Handle h = (DTHE_Handle)wolfSSL_TI_getDtheHandle();
    DTHE_Config* cfg;
    uint32_t savedDma;
    word32 i;

    if (h == NULL)
        return ASYM_CRYPT_RETURN_FAILURE;

    /* The SDK example disables DMA for the Ed25519 SHA pass; save/restore so
     * subsequent wolfSSL hashing keeps its configured behavior. */
    cfg       = (DTHE_Config*)h;
    savedDma  = cfg->dmaEnable;
    cfg->dmaEnable = 0;

    XMEMSET(&p, 0, sizeof(p));
    p.algoType      = DTHE_SHA_ALGO_SHA512;
    p.ptrDataBuffer = (uint32_t*)in;
    p.dataLenBytes  = len;

    if (DTHE_SHA_compute(h, &p, TRUE) != DTHE_SHA_RETURN_SUCCESS) {
        cfg->dmaEnable = savedDma;
        return ASYM_CRYPT_RETURN_FAILURE;
    }
    cfg->dmaEnable = savedDma;

    for (i = 0; i < 64; i += 4) {
        uint32_t w = p.digest[i >> 2];
        digest[i]     = (uint8_t)(w & 0xFF);
        digest[i + 1] = (uint8_t)((w >> 8) & 0xFF);
        digest[i + 2] = (uint8_t)((w >> 16) & 0xFF);
        digest[i + 3] = (uint8_t)((w >> 24) & 0xFF);
    }
    return ASYM_CRYPT_RETURN_SUCCESS;
}

/* Copy a driver signature (R || s, 32 + 32 bytes) into the caller buffer. */
static void tiEd25519SigToBytes(const struct AsymCrypt_EddsaSig* sig, byte* out)
{
    XMEMCPY(out, sig->R, ED25519_KEY_SIZE);
    XMEMCPY(out + ED25519_KEY_SIZE, sig->s, ED25519_KEY_SIZE);
}

/* Copy a caller signature into the driver's R || s struct. */
static void tiEd25519BytesToSig(const byte* in, struct AsymCrypt_EddsaSig* sig)
{
    XMEMSET(sig, 0, sizeof(*sig));
    XMEMCPY(sig->R, in, ED25519_KEY_SIZE);
    XMEMCPY(sig->s, in + ED25519_KEY_SIZE, ED25519_KEY_SIZE);
}

/* Pack a wolfSSL key into the driver's seed + pub pair. */
static void tiEd25519KeyToDriver(const ed25519_key* key,
                                 struct AsymCrypt_EddsaKey* dkey)
{
    XMEMSET(dkey, 0, sizeof(*dkey));
    XMEMCPY(dkey->privKey, key->k, ED25519_KEY_SIZE);
    XMEMCPY(dkey->pubKey, key->p, ED25519_PUB_KEY_SIZE);
}

/* The EdDSA driver uses the 64 bytes immediately before the message pointer as
 * scratch space, so the message is copied into a buffer with 64 reserved,
 * zeroed bytes in front. */
static int tiEd25519CopyMsg(const byte* msg, word32 msgLen, void* heap,
                            byte** out)
{
    byte* buf = (byte*)XMALLOC(msgLen + 64, heap, DYNAMIC_TYPE_TMP_BUFFER);

    if (buf == NULL)
        return MEMORY_E;
    XMEMSET(buf, 0, msgLen + 64);
    XMEMCPY(buf + 64, msg, msgLen);
    *out = buf;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* AsymCrypt Ed25519 operations (plain RFC 8032 only)                       */
/* ------------------------------------------------------------------------ */

static int tiEd25519DoMakePub(ed25519_key* key, byte* pubKey, word32 pubKeySz)
{
    int ret = 0;
    AsymCrypt_Handle h;
    struct AsymCrypt_EddsaKey dkey;
    uint8_t pub[EDDSA_MAX_KEY_LEN];

    if (key == NULL || pubKey == NULL || pubKeySz != ED25519_PUB_KEY_SIZE)
        return BAD_FUNC_ARG;
    if (!key->privKeySet)
        return ECC_PRIV_KEY_E;

    h = wolfSSL_TI_getAsymCryptHandle();
    if (h == NULL)
        return WC_HW_E;

    tiEd25519KeyToDriver(key, &dkey);
    XMEMSET(pub, 0, sizeof(pub));
    wolfSSL_TI_lockCCM();
    if (AsymCrypt_EddsaGetPubKey(h, tiEd25519Sha512, dkey.privKey, pub,
                ASYM_CRYPT_CURVE_TYPE_EDDSA_25519)
            != ASYM_CRYPT_RETURN_SUCCESS) {
        ret = WC_HW_E;
    }
    wolfSSL_TI_unlockCCM();

    if (ret == 0) {
        XMEMCPY(pubKey, pub, ED25519_PUB_KEY_SIZE);
        key->pubKeySet = 1;
    }
    return ret;
}

static int tiEd25519DoMakeKey(WC_RNG* rng, int keySz, ed25519_key* key)
{
    int ret;

    if (rng == NULL || key == NULL || keySz != ED25519_KEY_SIZE)
        return BAD_FUNC_ARG;

    ret = wc_RNG_GenerateBlock(rng, key->k, ED25519_KEY_SIZE);
    if (ret != 0)
        return ret;

    key->privKeySet = 1;
    ret = tiEd25519DoMakePub(key, key->p, ED25519_PUB_KEY_SIZE);
    if (ret != 0) {
        key->privKeySet = 0;
        ForceZero(key->k, ED25519_KEY_SIZE);
        return ret;
    }

    /* put public key after private key, on the same buffer */
    XMEMMOVE(key->k + ED25519_KEY_SIZE, key->p, ED25519_PUB_KEY_SIZE);

    return 0;
}

static int tiEd25519DoSign(const byte* in, word32 inLen, byte* out,
                           word32* outLen, ed25519_key* key, byte type)
{
    int ret = 0;
    AsymCrypt_Handle h;
    struct AsymCrypt_EddsaKey dkey;
    struct AsymCrypt_EddsaSig sig;
    byte* msgBuf = NULL;

    /* sanity check on arguments */
    if (in == NULL || out == NULL || outLen == NULL || key == NULL)
        return BAD_FUNC_ARG;

    /* The PKA implements plain Ed25519 (RFC 8032) only; decline the others so
     * the software path handles Ed25519ctx / Ed25519ph. */
    if (type != (byte)Ed25519)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    if (!key->pubKeySet || !key->privKeySet)
        return BAD_FUNC_ARG;

    /* check and set up out length */
    if (*outLen < ED25519_SIG_SIZE) {
        *outLen = ED25519_SIG_SIZE;
        return BUFFER_E;
    }
    *outLen = ED25519_SIG_SIZE;

    h = wolfSSL_TI_getAsymCryptHandle();
    if (h == NULL)
        return WC_HW_E;

    ret = tiEd25519CopyMsg(in, inLen, key->heap, &msgBuf);
    if (ret != 0)
        return ret;

    tiEd25519KeyToDriver(key, &dkey);

    wolfSSL_TI_lockCCM();
    if (AsymCrypt_EddsaSign(h, tiEd25519Sha512, &dkey, msgBuf + 64, inLen,
            &sig, ASYM_CRYPT_CURVE_TYPE_EDDSA_25519)
            != ASYM_CRYPT_RETURN_SUCCESS) {
        ret = WC_HW_E;
    }
    wolfSSL_TI_unlockCCM();

    if (ret == 0)
        tiEd25519SigToBytes(&sig, out);

    XFREE(msgBuf, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

static int tiEd25519DoVerify(const byte* sig, word32 sigLen, const byte* msg,
                             word32 msgLen, int* res, ed25519_key* key,
                             byte type)
{
    AsymCrypt_Return_t st;
    AsymCrypt_Handle h;
    struct AsymCrypt_EddsaSig dsig;
    uint8_t pub[EDDSA_MAX_KEY_LEN];
    byte* msgBuf = NULL;

    /* sanity check on arguments */
    if (sig == NULL || msg == NULL || res == NULL || key == NULL)
        return BAD_FUNC_ARG;

    /* The PKA implements plain Ed25519 (RFC 8032) only; decline the others so
     * the software path handles Ed25519ctx / Ed25519ph. */
    if (type != (byte)Ed25519)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    if (sigLen != ED25519_SIG_SIZE)
        return BUFFER_E;
    if (!key->pubKeySet)
        return ECC_BAD_ARG_E;

    /* default to invalid signature */
    *res = 0;

    h = wolfSSL_TI_getAsymCryptHandle();
    if (h == NULL)
        return WC_HW_E;

    {
        int ret = tiEd25519CopyMsg(msg, msgLen, key->heap, &msgBuf);
        if (ret != 0)
            return ret;
    }

    tiEd25519BytesToSig(sig, &dsig);
    XMEMSET(pub, 0, sizeof(pub));
    XMEMCPY(pub, key->p, ED25519_PUB_KEY_SIZE);

    wolfSSL_TI_lockCCM();
    st = AsymCrypt_EddsaVerify(h, tiEd25519Sha512, pub, msgBuf + 64, msgLen,
                               &dsig, ASYM_CRYPT_CURVE_TYPE_EDDSA_25519);
    wolfSSL_TI_unlockCCM();

    XFREE(msgBuf, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    if (st == ASYM_CRYPT_RETURN_SUCCESS)
        *res = 1;
    else if (st != ASYM_CRYPT_RETURN_FAILURE)
        return WC_HW_E;

    return 0;
}

static int tiEd25519DoCheckKey(ed25519_key* key)
{
    int ret = 0;
    AsymCrypt_Handle h;
    struct AsymCrypt_EddsaKey dkey;
    uint8_t pub[EDDSA_MAX_KEY_LEN];

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (!key->pubKeySet)
        return PUBLIC_KEY_E;

    /* Public-key-only: decline so the software path validates the point (the
     * AsymCrypt engine cannot decompress/validate a standalone point). */
    if (!key->privKeySet)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    h = wolfSSL_TI_getAsymCryptHandle();
    if (h == NULL)
        return WC_HW_E;

    /* Re-derive the public key from the private seed and compare. */
    tiEd25519KeyToDriver(key, &dkey);
    XMEMSET(pub, 0, sizeof(pub));
    wolfSSL_TI_lockCCM();
    if (AsymCrypt_EddsaGetPubKey(h, tiEd25519Sha512, dkey.privKey, pub,
                ASYM_CRYPT_CURVE_TYPE_EDDSA_25519)
            != ASYM_CRYPT_RETURN_SUCCESS) {
        ret = WC_HW_E;
    }
    wolfSSL_TI_unlockCCM();

    if (ret == 0 && XMEMCMP(pub, key->p, ED25519_PUB_KEY_SIZE) != 0)
        ret = PUBLIC_KEY_E;

    return ret;
}

/* ------------------------------------------------------------------------ */
/* WOLF_CRYPTO_CB device                                                     */
/* ------------------------------------------------------------------------ */
#ifdef WOLF_CRYPTO_CB

static int wolfSSL_TI_Ed25519CryptoCb(int devId, struct wc_CryptoInfo* info,
                                      void* ctx)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    (void)devId;
    (void)ctx;

    if (info == NULL)
        return ret;

    switch (info->pk.type) {
        case WC_PK_TYPE_ED25519_MAKE_PUB:
            ret = tiEd25519DoMakePub(info->pk.ed25519makepub.key,
                info->pk.ed25519makepub.pubOut,
                info->pk.ed25519makepub.pubOutSz);
            break;
        case WC_PK_TYPE_ED25519_KEYGEN:
            ret = tiEd25519DoMakeKey(info->pk.ed25519kg.rng,
                info->pk.ed25519kg.size, info->pk.ed25519kg.key);
            break;
        case WC_PK_TYPE_ED25519_SIGN:
            ret = tiEd25519DoSign(info->pk.ed25519sign.in,
                info->pk.ed25519sign.inLen, info->pk.ed25519sign.out,
                info->pk.ed25519sign.outLen, info->pk.ed25519sign.key,
                info->pk.ed25519sign.type);
            break;
        case WC_PK_TYPE_ED25519_VERIFY:
            ret = tiEd25519DoVerify(info->pk.ed25519verify.sig,
                info->pk.ed25519verify.sigLen, info->pk.ed25519verify.msg,
                info->pk.ed25519verify.msgLen, info->pk.ed25519verify.res,
                info->pk.ed25519verify.key, info->pk.ed25519verify.type);
            break;
        case WC_PK_TYPE_ED25519_CHECK_KEY:
            ret = tiEd25519DoCheckKey(info->pk.ed25519checkkey.key);
            break;
        default:
            /* not an Ed25519 operation; signal unhandled */
            break;
    }
    return ret;
}

#endif /* WOLF_CRYPTO_CB */

int wolfSSL_TI_Ed25519Register(int devId)
{
#ifdef WOLF_CRYPTO_CB
    if (devId == INVALID_DEVID)
        return BAD_FUNC_ARG;
    return wc_CryptoCb_RegisterDevice(devId, wolfSSL_TI_Ed25519CryptoCb, NULL);
#else
    (void)devId;
    return NOT_COMPILED_IN;
#endif
}

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_TI_CRYPT && HAVE_ED25519 */
