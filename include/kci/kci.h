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

/* Return codes */
#define KCI_OK          0
#define KCI_ERR_LIMIT  (-1)   /* request would run the 32-bit block counter past 2^32 - 1 */

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

/* Secure wipe (not removed by the optimiser). */
void kci_wipe(void *p, size_t n);
void kci_key_wipe(kci_key *k);
void kci_stream_wipe(kci_stream *s);

#ifdef __cplusplus
}
#endif
#endif /* KCI_KCI_H */
