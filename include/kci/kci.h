/*
 * KCI-20: an experimental stream cipher whose key chooses the Krark-Clan Ironworks loops it plays.
 * Spec: vault/Refactor/KCI-Primitive-Design.md (v0.2).
 *
 * WARNING: original, unreviewed cryptography. For research and fun; do not protect real data with it.
 *
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0 (see LICENSE).
 */
#ifndef KCI_KCI_H
#define KCI_KCI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KCI_KEY_BYTES   32
#define KCI_NONCE_BYTES 12
#define KCI_BLOCK_BYTES 64
#define KCI_ROUNDS      20
#define KCI_LOOPS       8
#define KCI_TAG_BYTES   16
/* Longest message per (key, nonce): counters 1 .. 2^32 - 1, 64 bytes each (counter 0 is the MAC key block). */
#define KCI_MAX_MSG_BYTES ((((uint64_t)1 << 32) - 1) * 64u)

/* Return codes */
#define KCI_OK          0
#define KCI_ERR_LIMIT  (-1)   /* request would run the 32-bit block counter past 2^32 - 1 */
#define KCI_ERR_AUTH   (-2)   /* AEAD tag mismatch: ciphertext, AAD, nonce or key is wrong */
#define KCI_ERR_PARAM  (-3)   /* parameter below a safety minimum (e.g. KDF iterations or salt length) */

/* Password front end (spec 6, D-020): PBKDF2-HMAC-SHA256 */
#define KCI_KDF_DEFAULT_ITERATIONS 600000u
#define KCI_KDF_MIN_ITERATIONS     100000u
#define KCI_KDF_SALT_BYTES         16     /* what the CLI generates */
#define KCI_KDF_MIN_SALT_BYTES     16

/* Expanded key: key words + the expanded deck (spec section 4.2). Treat as opaque; wipe with kci_key_wipe(). */
typedef struct {
    uint32_t c[4];                    /* stack constants */
    uint32_t k[8];                    /* key words */
    uint8_t  rot[KCI_ROUNDS][4];      /* rotation set of each round's loop */
    uint32_t rc[KCI_ROUNDS];          /* round constant of each round */
} kci_key;

/* Keystream state for one (key, nonce). Treat as opaque; wipe with kci_stream_wipe(). */
typedef struct {
    kci_key  key;
    uint32_t nonce[3];
    uint64_t next_ctr;                /* next block counter to generate; <= 2^32 */
    uint8_t  buf[KCI_BLOCK_BYTES];    /* current keystream block */
    uint32_t used;                    /* bytes of buf already consumed (64 = empty) */
} kci_stream;

/* Key setup: shuffle the deck and expand it (spec 4.2). Constant-time in the key. */
void kci_key_setup(kci_key *k, const uint8_t key[KCI_KEY_BYTES]);

/* One 64-byte keystream block for (key, counter, nonce) (spec 4.3-4.5). */
void kci_block(uint8_t out[KCI_BLOCK_BYTES], const kci_key *k, uint32_t ctr,
               const uint8_t nonce[KCI_NONCE_BYTES]);

/* Raw stream mode (spec 5). Start at counter 1 for files (counter 0 is the AEAD MAC key block). */
void kci_stream_init(kci_stream *s, const kci_key *k, const uint8_t nonce[KCI_NONCE_BYTES], uint32_t ctr0);

/* out = in XOR keystream. Encrypt == decrypt. in and out may be the same buffer.
 * Returns KCI_ERR_LIMIT, writing nothing, if len exceeds the keystream left before the counter limit. */
int kci_stream_xor(kci_stream *s, uint8_t *out, const uint8_t *in, size_t len);

/* AEAD mode (spec 7, the default): RFC 8439 composition with KCI-20 and Poly1305.
 * Never reuse a (key, nonce) pair. ct may equal pt (in place). aad may be NULL when aad_len is 0.
 * Returns KCI_ERR_LIMIT (writing nothing) if len > KCI_MAX_MSG_BYTES. */
int kci_aead_encrypt(uint8_t *ct, uint8_t tag[KCI_TAG_BYTES],
                     const uint8_t *pt, size_t len,
                     const uint8_t *aad, size_t aad_len,
                     const kci_key *k, const uint8_t nonce[KCI_NONCE_BYTES]);

/* Verifies the tag first (constant-time compare), and only then decrypts.
 * Returns KCI_ERR_AUTH, writing nothing to pt, if the tag does not match. pt may equal ct (in place). */
int kci_aead_decrypt(uint8_t *pt, const uint8_t *ct, size_t len,
                     const uint8_t tag[KCI_TAG_BYTES],
                     const uint8_t *aad, size_t aad_len,
                     const kci_key *k, const uint8_t nonce[KCI_NONCE_BYTES]);

/* Password -> 32-byte key (then call kci_key_setup, which shuffles the deck).
 * Returns KCI_ERR_PARAM if iterations < KCI_KDF_MIN_ITERATIONS or salt_len < KCI_KDF_MIN_SALT_BYTES. */
int kci_kdf_password(uint8_t key[KCI_KEY_BYTES], const uint8_t *pw, size_t pw_len,
                     const uint8_t *salt, size_t salt_len, uint32_t iterations);

/* Constant-time comparison: 0 if equal, -1 otherwise. */
int kci_ct_memcmp(const void *a, const void *b, size_t n);

/* Secure wipe (not removed by the optimiser). */
void kci_wipe(void *p, size_t n);
void kci_key_wipe(kci_key *k);
void kci_stream_wipe(kci_stream *s);

#ifdef __cplusplus
}
#endif
#endif /* KCI_KCI_H */
