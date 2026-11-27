/* Internal definitions shared by the core and the tests. Not part of the public API.
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#ifndef KCI_INTERNAL_H
#define KCI_INTERNAL_H

#include "kci/kci.h"

#define KCI_PHI 0x9E3779B9u

/* Normative tables (spec 4.3); tools/kci_ref.py FROZEN / PACKED must match. */
extern const uint8_t  kci_loop_rot[KCI_LOOPS][4];
extern const uint32_t kci_loop_packed[KCI_LOOPS];
extern const uint32_t kci_stack_const[4];   /* "KCI 256-bit loop" */
extern const uint32_t kci_deck_const[4];    /* "KCI shuffle deck" */

static inline uint32_t kci_load32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static inline void kci_store32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* The block function core: out = P(in) + in with an explicit round table (spec 4.4-4.5).
 * Also used by the RFC 8439 kernel cross-check test with ChaCha's rotations and zero round constants. */
void kci_core(uint32_t out[16], const uint32_t in[16],
              const uint8_t rot[][4], const uint32_t rc[], int rounds);

/* kci_block with the nonce as words and caller-owned scratch (32 words) that the caller wipes once. */
void kci_block_words(uint8_t out[KCI_BLOCK_BYTES], const kci_key *k, uint32_t ctr,
                     const uint32_t nonce[3], uint32_t scratch[32]);

/* Poly1305 (RFC 8439 2.5), streaming. final() wipes the state. */
typedef struct {
    uint32_t r[5], h[5], pad[4];
    uint8_t  buf[16];
    size_t   left;
} kci_poly1305_state;
void kci_poly1305_init(kci_poly1305_state *st, const uint8_t key[32]);
void kci_poly1305_update(kci_poly1305_state *st, const uint8_t *m, size_t bytes);
void kci_poly1305_final(kci_poly1305_state *st, uint8_t tag[16]);
void kci_poly1305(uint8_t tag[16], const uint8_t *m, size_t bytes, const uint8_t key[32]);

/* Deck derivation without expansion: writes the 20 secret loop picks (spec 4.2 steps 1-2). Test hook. */
void kci_shuffle_deck(uint8_t deck[KCI_ROUNDS], const uint8_t key[KCI_KEY_BYTES]);

#endif
