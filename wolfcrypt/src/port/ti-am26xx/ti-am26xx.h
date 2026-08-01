/* port/ti-am26xx/ti-am26xx.h
 *
 * Customer port header for the TI AM26XX crypto offload. All customer-specific
 * API for this port lives here; nothing is added to the wolfSSL-distributed
 * headers (wolfssl/wolfcrypt/port/ti/ti-ccm.h stays pristine).
 */

#ifndef WOLF_CRYPT_TI_AM26XX_H
#define WOLF_CRYPT_TI_AM26XX_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(WOLFSSL_TI_CRYPT) || defined(WOLFSSL_TI_HASH)

#ifdef __cplusplus
    extern "C" {
#endif

/* Returns the DTHE (hash/AES/CMAC) engine handle, lazily opened by
 * wolfSSL_TI_CCMInit(). NULL when the engine could not be opened. */
void* wolfSSL_TI_getDtheHandle(void);

#ifdef WOLFSSL_TI_CRYPT
/* AsymCrypt (PKA) handle — shared by ti-rsa.c, ti-ecc.c and ti-ed25519.c.
 * Opens the AsymCrypt engine once on first use and returns the handle.
 * Returns NULL if the engine could not be opened. */
void* wolfSSL_TI_getAsymCryptHandle(void);

#ifdef HAVE_ED25519
/* Default device id used by wolfSSL_TI_Ed25519Register(). Applications may
 * pass any non-INVALID_DEVID value they prefer. */
#ifndef WOLFSSL_TI_ED25519_DEV_ID
    #define WOLFSSL_TI_ED25519_DEV_ID 0x2D
#endif

/* Registers the TI Ed25519 AsymCrypt engine as a WOLF_CRYPTO_CB device so
 * wc_ed25519_make_public, wc_ed25519_make_key, wc_ed25519_sign_msg and
 * wc_ed25519_verify_msg (and check_key) offload to hardware when the key was
 * created with wc_ed25519_init_ex(key, heap, devId). Returns 0 on success.
 * Requires WOLF_CRYPTO_CB; otherwise NOT_COMPILED_IN. */
int wolfSSL_TI_Ed25519Register(int devId);
#endif /* HAVE_ED25519 */
#endif /* WOLFSSL_TI_CRYPT */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_TI_CRYPT || WOLFSSL_TI_HASH */

#endif /* WOLF_CRYPT_TI_AM26XX_H */
