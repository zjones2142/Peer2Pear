/*  Stub implementations — these must never be reached in tests because
 *  the DatabaseManager encryption key is left empty.  If a test does
 *  call them it means we exercised an encryption path by accident.      */
#include "sodium.h"
#include <stdio.h>
#include <stdlib.h>

static void abort_stub(const char *fn)
{
    fprintf(stderr, "FATAL: sodium stub '%s' called — "
                    "tests must not exercise encryption paths\n", fn);
    abort();
}

void randombytes_buf(void *buf, unsigned long long size)
{
    (void)buf; (void)size;
    abort_stub("randombytes_buf");
}

int crypto_aead_xchacha20poly1305_ietf_encrypt(
    unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k)
{
    (void)c; (void)clen_p; (void)m; (void)mlen;
    (void)ad; (void)adlen; (void)nsec; (void)npub; (void)k;
    abort_stub("crypto_aead_xchacha20poly1305_ietf_encrypt");
    return -1;
}

int crypto_aead_xchacha20poly1305_ietf_decrypt(
    unsigned char *m, unsigned long long *mlen_p,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k)
{
    (void)m; (void)mlen_p; (void)nsec; (void)c; (void)clen;
    (void)ad; (void)adlen; (void)npub; (void)k;
    abort_stub("crypto_aead_xchacha20poly1305_ietf_decrypt");
    return -1;
}
