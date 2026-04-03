/*  Minimal libsodium stub for test builds that never exercise encryption.
 *  Only the constants and function signatures referenced by databasemanager.cpp
 *  are provided here.  Calling any function is a fatal error.                  */
#ifndef SODIUM_H_STUB
#define SODIUM_H_STUB

#ifdef __cplusplus
extern "C" {
#endif

#define crypto_aead_xchacha20poly1305_ietf_KEYBYTES  32U
#define crypto_aead_xchacha20poly1305_ietf_NPUBBYTES 24U
#define crypto_aead_xchacha20poly1305_ietf_ABYTES    16U

void randombytes_buf(void *buf, unsigned long long size);

int crypto_aead_xchacha20poly1305_ietf_encrypt(
    unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k);

int crypto_aead_xchacha20poly1305_ietf_decrypt(
    unsigned char *m, unsigned long long *mlen_p,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k);

#ifdef __cplusplus
}
#endif

#endif /* SODIUM_H_STUB */
