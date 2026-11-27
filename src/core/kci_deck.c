/* Key setup: shuffle the deck (spec 4.2). Constant-time in the key.
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#include "kci_internal.h"

/* 0xFFFFFFFF if a == b else 0, without branches (a, b < 2^31). */
static inline uint32_t ct_eq_mask(uint32_t a, uint32_t b) {
    return 0u - (((a ^ b) - 1u) >> 31);
}

static void setup_block(uint32_t w[16], const uint8_t key[KCI_KEY_BYTES])
{
    uint8_t  rot[KCI_ROUNDS][4];
    uint32_t rc[KCI_ROUNDS], in[16];

    /* fixed public setup schedule s_r = r mod 8 */
    for (int r = 0; r < KCI_ROUNDS; r++) {
        for (int i = 0; i < 4; i++) rot[r][i] = kci_loop_rot[r % KCI_LOOPS][i];
        rc[r] = kci_loop_packed[r % KCI_LOOPS] + (uint32_t)(r + 1) * KCI_PHI;
    }
    for (int i = 0; i < 4; i++) in[i] = kci_deck_const[i];
    for (int i = 0; i < 8; i++) in[4 + i] = kci_load32(key + 4 * i);
    for (int i = 12; i < 16; i++) in[i] = 0;            /* counter 0, nonce 0 */
    kci_core(w, in, (const uint8_t (*)[4])rot, rc, KCI_ROUNDS);
    kci_wipe(in, sizeof in);
}

static inline uint32_t deck_pick(const uint32_t w[16], int r) {
    return (w[r / 10] >> (3 * (r % 10))) & 7u;    /* public positions, secret value */
}

void kci_shuffle_deck(uint8_t deck[KCI_ROUNDS], const uint8_t key[KCI_KEY_BYTES])
{
    uint32_t w[16];
    setup_block(w, key);
    for (int r = 0; r < KCI_ROUNDS; r++) deck[r] = (uint8_t)deck_pick(w, r);
    kci_wipe(w, sizeof w);
}

void kci_key_setup(kci_key *k, const uint8_t key[KCI_KEY_BYTES])
{
    uint32_t w[16];
    setup_block(w, key);

    for (int i = 0; i < 4; i++) k->c[i] = kci_stack_const[i];
    for (int i = 0; i < 8; i++) k->k[i] = kci_load32(key + 4 * i);

    /* Expand the deck with a masked scan over all 8 loops: no memory index depends on the secret pick. */
    for (int r = 0; r < KCI_ROUNDS; r++) {
        const uint32_t s = deck_pick(w, r);
        uint32_t rot0 = 0, rot1 = 0, rot2 = 0, rot3 = 0, packed = 0;
        for (uint32_t j = 0; j < KCI_LOOPS; j++) {
            const uint32_t m = ct_eq_mask(j, s);
            rot0 |= kci_loop_rot[j][0] & m;
            rot1 |= kci_loop_rot[j][1] & m;
            rot2 |= kci_loop_rot[j][2] & m;
            rot3 |= kci_loop_rot[j][3] & m;
            packed |= kci_loop_packed[j] & m;
        }
        k->rot[r][0] = (uint8_t)rot0; k->rot[r][1] = (uint8_t)rot1;
        k->rot[r][2] = (uint8_t)rot2; k->rot[r][3] = (uint8_t)rot3;
        k->rc[r] = packed + (uint32_t)(r + 1) * KCI_PHI;
    }
    kci_wipe(w, sizeof w);
}
