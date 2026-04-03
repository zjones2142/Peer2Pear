/*  Minimal libsodium stubs so the tests compile without vcpkg/libsodium.
 *  Only the constants and functions referenced by DatabaseManager and
 *  CryptoEngine are stubbed here.
 *
 *  Field encryption in DatabaseManager uses XChaCha20-Poly1305 (AEAD).
 *  These stubs make "encryption" a no-op so tests can exercise the SQL
 *  and business-logic paths without needing real crypto.
 */

#pragma once
#include <cstddef>
#include <cstring>
#include <cstdint>

/* ── constants ─────────────────────────────────────────────────────────── */

#define crypto_aead_xchacha20poly1305_ietf_KEYBYTES  32U
#define crypto_aead_xchacha20poly1305_ietf_NPUBBYTES 24U
#define crypto_aead_xchacha20poly1305_ietf_ABYTES    16U

#define crypto_sign_PUBLICKEYBYTES  32U
#define crypto_sign_SECRETKEYBYTES  64U
#define crypto_sign_BYTES           64U

#define crypto_box_PUBLICKEYBYTES   32U
#define crypto_box_SECRETKEYBYTES   32U

#define crypto_secretbox_KEYBYTES   32U
#define crypto_secretbox_NONCEBYTES 24U
#define crypto_secretbox_MACBYTES   16U

#define crypto_scalarmult_BYTES     32U

#define crypto_pwhash_SALTBYTES     16U
#define crypto_pwhash_STRBYTES      128U
#define crypto_pwhash_OPSLIMIT_INTERACTIVE 2U
#define crypto_pwhash_MEMLIMIT_INTERACTIVE 67108864U
#define crypto_pwhash_ALG_ARGON2I13       1
#define crypto_pwhash_ALG_DEFAULT         crypto_pwhash_ALG_ARGON2I13

#define crypto_generichash_BYTES    32U
#define crypto_generichash_BYTES_MAX 64U

/* ── init ──────────────────────────────────────────────────────────────── */

inline int sodium_init() { return 0; }

/* ── random ────────────────────────────────────────────────────────────── */

inline void randombytes_buf(void *buf, size_t size)
{
    // Fill with deterministic pattern for testing
    std::memset(buf, 0xAB, size);
}

/* ── memory zeroing ────────────────────────────────────────────────────── */

inline void sodium_memzero(void *pnt, size_t len)
{
    volatile unsigned char *p = static_cast<volatile unsigned char *>(pnt);
    while (len--) *p++ = 0;
}

/* ── AEAD XChaCha20-Poly1305 (stub: plaintext passthrough with tag) ──── */

inline int crypto_aead_xchacha20poly1305_ietf_encrypt(
    unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char * /*ad*/, unsigned long long /*adlen*/,
    const unsigned char * /*nsec*/,
    const unsigned char * /*npub*/,
    const unsigned char * /*k*/)
{
    // Stub: copy plaintext + append 16-byte zero tag
    std::memcpy(c, m, static_cast<size_t>(mlen));
    std::memset(c + mlen, 0, crypto_aead_xchacha20poly1305_ietf_ABYTES);
    if (clen_p)
        *clen_p = mlen + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    return 0;
}

inline int crypto_aead_xchacha20poly1305_ietf_decrypt(
    unsigned char *m, unsigned long long *mlen_p,
    unsigned char * /*nsec*/,
    const unsigned char *c, unsigned long long clen,
    const unsigned char * /*ad*/, unsigned long long /*adlen*/,
    const unsigned char * /*npub*/,
    const unsigned char * /*k*/)
{
    if (clen < crypto_aead_xchacha20poly1305_ietf_ABYTES) return -1;
    const unsigned long long mlen = clen - crypto_aead_xchacha20poly1305_ietf_ABYTES;
    std::memcpy(m, c, static_cast<size_t>(mlen));
    if (mlen_p) *mlen_p = mlen;
    return 0;
}

/* ── Ed25519 key generation (stub: deterministic keys) ─────────────────── */

inline int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    std::memset(pk, 0x11, crypto_sign_PUBLICKEYBYTES);
    std::memset(sk, 0x22, crypto_sign_SECRETKEYBYTES);
    return 0;
}

inline int crypto_sign_detached(unsigned char *sig, unsigned long long *siglen_p,
                                const unsigned char * /*m*/, unsigned long long /*mlen*/,
                                const unsigned char * /*sk*/)
{
    std::memset(sig, 0x33, crypto_sign_BYTES);
    if (siglen_p) *siglen_p = crypto_sign_BYTES;
    return 0;
}

inline int crypto_sign_verify_detached(const unsigned char * /*sig*/,
                                        const unsigned char * /*m*/,
                                        unsigned long long /*mlen*/,
                                        const unsigned char * /*pk*/)
{
    return 0;  // always valid in stubs
}

/* ── X25519 / Curve25519 ──────────────────────────────────────────────── */

inline int crypto_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
                                                 const unsigned char * /*ed25519_pk*/)
{
    std::memset(curve25519_pk, 0x44, crypto_box_PUBLICKEYBYTES);
    return 0;
}

inline int crypto_sign_ed25519_sk_to_curve25519(unsigned char *curve25519_sk,
                                                 const unsigned char * /*ed25519_sk*/)
{
    std::memset(curve25519_sk, 0x55, crypto_box_SECRETKEYBYTES);
    return 0;
}

inline int crypto_box_keypair(unsigned char *pk, unsigned char *sk)
{
    std::memset(pk, 0x66, crypto_box_PUBLICKEYBYTES);
    std::memset(sk, 0x77, crypto_box_SECRETKEYBYTES);
    return 0;
}

inline int crypto_scalarmult(unsigned char *q,
                              const unsigned char * /*n*/,
                              const unsigned char * /*p*/)
{
    std::memset(q, 0x88, crypto_scalarmult_BYTES);
    return 0;
}

/* ── BLAKE2b generic hash ──────────────────────────────────────────────── */

inline int crypto_generichash(unsigned char *out, size_t outlen,
                               const unsigned char *in, unsigned long long inlen,
                               const unsigned char * /*key*/, size_t /*keylen*/)
{
    // Simple stub: XOR-fold input into output
    std::memset(out, 0, outlen);
    for (unsigned long long i = 0; i < inlen; ++i)
        out[i % outlen] ^= in[i];
    return 0;
}

/* ── secretbox (XSalsa20-Poly1305) ─────────────────────────────────────── */

inline int crypto_secretbox_easy(unsigned char *c,
                                  const unsigned char *m, unsigned long long mlen,
                                  const unsigned char * /*n*/,
                                  const unsigned char * /*k*/)
{
    std::memset(c, 0, crypto_secretbox_MACBYTES);
    std::memcpy(c + crypto_secretbox_MACBYTES, m, static_cast<size_t>(mlen));
    return 0;
}

inline int crypto_secretbox_open_easy(unsigned char *m,
                                       const unsigned char *c, unsigned long long clen,
                                       const unsigned char * /*n*/,
                                       const unsigned char * /*k*/)
{
    if (clen < crypto_secretbox_MACBYTES) return -1;
    std::memcpy(m, c + crypto_secretbox_MACBYTES,
                static_cast<size_t>(clen - crypto_secretbox_MACBYTES));
    return 0;
}

/* ── password hashing (Argon2) ─────────────────────────────────────────── */

inline int crypto_pwhash(unsigned char *out, unsigned long long outlen,
                          const char * /*passwd*/, unsigned long long /*passwdlen*/,
                          const unsigned char * /*salt*/,
                          unsigned long long /*opslimit*/,
                          size_t /*memlimit*/,
                          int /*alg*/)
{
    std::memset(out, 0x99, static_cast<size_t>(outlen));
    return 0;
}

/* ── base64 encoding / decoding (URL-safe, no padding) ─────────────────── */

#define sodium_base64_VARIANT_URLSAFE_NO_PADDING 7

// Compute the maximum encoded length for base64 (includes NUL terminator)
#define sodium_base64_ENCODED_LEN(BIN_LEN, VARIANT) \
    (((BIN_LEN) / 3U) * 4U + (((BIN_LEN) % 3U != 0U) ? 4U : 0U) + 1U)

// Minimal base64url-encode stub (no-padding, URL-safe).
// Maps '+' → '-', '/' → '_' and strips trailing '='.
inline char *sodium_bin2base64(char *b64, size_t b64_maxlen,
                               const unsigned char *bin, size_t bin_len,
                               int /*variant*/)
{
    // Standard base64 alphabet
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    size_t o = 0;
    size_t i = 0;
    while (i + 2 < bin_len) {
        if (o + 4 > b64_maxlen) break;
        unsigned int v = (unsigned(bin[i]) << 16) | (unsigned(bin[i+1]) << 8) | unsigned(bin[i+2]);
        b64[o++] = tbl[(v >> 18) & 0x3F];
        b64[o++] = tbl[(v >> 12) & 0x3F];
        b64[o++] = tbl[(v >>  6) & 0x3F];
        b64[o++] = tbl[ v        & 0x3F];
        i += 3;
    }
    if (i < bin_len) {
        unsigned int v = unsigned(bin[i]) << 16;
        if (i + 1 < bin_len) v |= unsigned(bin[i+1]) << 8;
        if (o < b64_maxlen) b64[o++] = tbl[(v >> 18) & 0x3F];
        if (o < b64_maxlen) b64[o++] = tbl[(v >> 12) & 0x3F];
        if (i + 1 < bin_len && o < b64_maxlen) b64[o++] = tbl[(v >> 6) & 0x3F];
    }
    // Convert to URL-safe: + → -, / → _
    for (size_t j = 0; j < o; ++j) {
        if (b64[j] == '+') b64[j] = '-';
        else if (b64[j] == '/') b64[j] = '_';
    }
    if (o < b64_maxlen) b64[o] = '\0';
    return b64;
}

// Minimal base64url-decode stub (URL-safe, no padding).
inline int sodium_base642bin(unsigned char *bin, size_t bin_maxlen,
                             const char *b64, size_t b64_len,
                             const char * /*ignore*/, size_t *bin_len,
                             const char ** /*b64_end*/,
                             int /*variant*/)
{
    // Build decode table
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-' || c == '+') return 62;
        if (c == '_' || c == '/') return 63;
        return -1;
    };

    size_t o = 0;
    size_t i = 0;
    while (i < b64_len) {
        int a = -1, b = -1, c = -1, d = -1;
        if (i < b64_len) a = val(b64[i++]);
        if (i < b64_len) b = val(b64[i++]);
        if (i < b64_len) c = val(b64[i++]);
        if (i < b64_len) d = val(b64[i++]);

        if (a < 0 || b < 0) break;

        if (o < bin_maxlen) bin[o++] = static_cast<unsigned char>((a << 2) | (b >> 4));
        if (c >= 0 && o < bin_maxlen) bin[o++] = static_cast<unsigned char>((b << 4) | (c >> 2));
        if (d >= 0 && o < bin_maxlen) bin[o++] = static_cast<unsigned char>((c << 6) | d);
    }
    if (bin_len) *bin_len = o;
    return 0;
}
