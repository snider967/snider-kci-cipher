/* KCI-20 unit tests and known-answer tests (spec v0.2).
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#include <stdio.h>
#include <string.h>

#include "kci/kci.h"
#include "../src/core/kci_internal.h"
#include "kat_vectors.h"

static int failures = 0, checks = 0;
#define CHECK(cond, ...)                                                    \
    do {                                                                    \
        checks++;                                                           \
        if (!(cond)) { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); \
                       printf(__VA_ARGS__); printf("\n"); }                 \
    } while (0)

static const uint32_t chacha_const[4] = { 0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u };

/* A kci_key configured as plain ChaCha20: the kernel cross-check (spec 11). */
static void chacha_mode_key(kci_key *k, const uint8_t key[32]) {
    for (int i = 0; i < 4; i++) k->c[i] = chacha_const[i];
    for (int i = 0; i < 8; i++) k->k[i] = kci_load32(key + 4 * i);
    for (int r = 0; r < KCI_ROUNDS; r++) {
        k->rot[r][0] = 16; k->rot[r][1] = 12; k->rot[r][2] = 8; k->rot[r][3] = 7;
        k->rc[r] = 0;
    }
}

static void test_tables(void) {
    CHECK(memcmp(kci_loop_rot, kat_loop_rot, sizeof kat_loop_rot) == 0, "loop rotation table != Python FROZEN");
    CHECK(memcmp(kci_loop_packed, kat_loop_packed, sizeof kat_loop_packed) == 0, "packed loop table != Python");
    uint8_t b[16];
    for (int i = 0; i < 4; i++) kci_store32(b + 4 * i, kci_stack_const[i]);
    CHECK(memcmp(b, "KCI 256-bit loop", 16) == 0, "stack constants != \"KCI 256-bit loop\"");
    for (int i = 0; i < 4; i++) kci_store32(b + 4 * i, kci_deck_const[i]);
    CHECK(memcmp(b, "KCI shuffle deck", 16) == 0, "deck constants != \"KCI shuffle deck\"");
}

static void test_rfc8439_crosscheck(void) {
    static const uint8_t key[32] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31 };
    static const uint8_t nonce[12] = { 0,0,0,0x09, 0,0,0,0x4a, 0,0,0,0 };
    kci_key k; uint8_t out[64];
    chacha_mode_key(&k, key);
    kci_block(out, &k, 1, nonce);
    CHECK(memcmp(out, kat_rfc8439_block, 64) == 0, "ChaCha-mode block != RFC 8439 2.3.2");

    uint8_t buf[KAT_STREAM_LEN] = {0};
    kci_stream s;
    chacha_mode_key(&k, kat_stream_key);
    kci_stream_init(&s, &k, kat_stream_nonce, 1);
    CHECK(kci_stream_xor(&s, buf, buf, sizeof buf) == KCI_OK, "stream xor failed");
    CHECK(memcmp(buf, kat_chacha_stream, sizeof buf) == 0, "ChaCha-mode keystream != OpenSSL chacha20");
}

static void test_block_kats(void) {
    for (size_t i = 0; i < sizeof kat_blocks / sizeof kat_blocks[0]; i++) {
        const struct kat_block *v = &kat_blocks[i];
        uint8_t deck[KCI_ROUNDS], out[64];
        kci_key k;
        kci_shuffle_deck(deck, v->key);
        CHECK(memcmp(deck, v->deck, KCI_ROUNDS) == 0, "deck mismatch, vector %zu", i);
        kci_key_setup(&k, v->key);
        for (int r = 0; r < KCI_ROUNDS; r++) {
            CHECK(memcmp(k.rot[r], kci_loop_rot[v->deck[r]], 4) == 0, "expanded rotations, vector %zu round %d", i, r);
            CHECK(k.rc[r] == kci_loop_packed[v->deck[r]] + (uint32_t)(r + 1) * KCI_PHI,
                  "expanded round constant, vector %zu round %d", i, r);
        }
        kci_block(out, &k, v->ctr, v->nonce);
        CHECK(memcmp(out, v->out, 64) == 0, "block KAT %zu (ctr 0x%08x)", i, (unsigned)v->ctr);
    }
}

static void test_single_loop(void) {
    uint32_t in[16], out[16];
    uint8_t rot[KCI_ROUNDS][4], b[64];
    uint32_t rc[KCI_ROUNDS];
    static const uint8_t nonce[12] = { 0,0,0,0x09, 0,0,0,0x4a, 0,0,0,0 };
    for (int s = 0; s < KCI_LOOPS; s++) {
        for (int i = 0; i < 4; i++) in[i] = kci_stack_const[i];
        for (int i = 0; i < 8; i++) in[4 + i] = 0x03020100u + 0x04040404u * (uint32_t)i;   /* key 00..1f */
        in[12] = 1;
        for (int i = 0; i < 3; i++) in[13 + i] = kci_load32(nonce + 4 * i);
        for (int r = 0; r < KCI_ROUNDS; r++) {
            memcpy(rot[r], kci_loop_rot[s], 4);
            rc[r] = kci_loop_packed[s] + (uint32_t)(r + 1) * KCI_PHI;
        }
        kci_core(out, in, (const uint8_t (*)[4])rot, rc, KCI_ROUNDS);
        for (int i = 0; i < 16; i++) kci_store32(b + 4 * i, out[i]);
        CHECK(memcmp(b, kat_single_loop[s], 64) == 0, "single-loop schedule, loop %d", s);
    }
}

static void test_reduced_rounds(void) {
    static const uint8_t key[32] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31 };
    static const uint8_t nonce[12] = { 0,0,0,0x09, 0,0,0,0x4a, 0,0,0,0 };
    kci_key k; uint32_t in[16], out[16]; uint8_t b[64];
    kci_key_setup(&k, key);
    for (int i = 0; i < 4; i++) in[i] = k.c[i];
    for (int i = 0; i < 8; i++) in[4 + i] = k.k[i];
    in[12] = 1;
    for (int i = 0; i < 3; i++) in[13 + i] = kci_load32(nonce + 4 * i);
    for (int R = 1; R <= 8; R++) {
        kci_core(out, in, (const uint8_t (*)[4])k.rot, k.rc, R);
        for (int i = 0; i < 16; i++) kci_store32(b + 4 * i, out[i]);
        CHECK(memcmp(b, kat_reduced[R - 1], 64) == 0, "reduced rounds R = %d", R);
    }
}

static void test_stream(void) {
    uint8_t pt[KAT_STREAM_LEN], buf[KAT_STREAM_LEN];
    kci_key k; kci_stream s;
    for (int i = 0; i < KAT_STREAM_LEN; i++) pt[i] = (uint8_t)(i * 7 + 3);
    kci_key_setup(&k, kat_stream_key);

    /* one shot, encrypt */
    kci_stream_init(&s, &k, kat_stream_nonce, 1);
    CHECK(kci_stream_xor(&s, buf, pt, sizeof pt) == KCI_OK, "encrypt");
    CHECK(memcmp(buf, kat_stream_ct, sizeof buf) == 0, "stream KAT ciphertext");

    /* decrypt in place, in odd chunk sizes */
    static const size_t chunks[] = { 1, 63, 64, 65, 3, 0, 104 };   /* partial, full and mixed blocks */
    size_t pos = 0;
    kci_stream_init(&s, &k, kat_stream_nonce, 1);
    for (size_t c = 0; c < sizeof chunks / sizeof chunks[0] && pos < sizeof buf; c++) {
        size_t n = chunks[c];
        if (pos + n > sizeof buf) n = sizeof buf - pos;
        CHECK(kci_stream_xor(&s, buf + pos, buf + pos, n) == KCI_OK, "chunked decrypt");
        pos += n;
    }
    CHECK(pos == sizeof buf, "chunk list covers the vector");
    CHECK(memcmp(buf, pt, sizeof pt) == 0, "chunked in-place decrypt round trip");
    kci_stream_wipe(&s);
    kci_key_wipe(&k);
}

static void test_counter_limit(void) {
    kci_key k; kci_stream s;
    uint8_t buf[130] = {0};
    kci_key_setup(&k, kat_stream_key);

    kci_stream_init(&s, &k, kat_stream_nonce, 0xffffffffu);   /* exactly one block left */
    CHECK(kci_stream_xor(&s, buf, buf, 65) == KCI_ERR_LIMIT, "65 bytes with one block left must fail");
    CHECK(buf[0] == 0, "failed call must write nothing");
    CHECK(kci_stream_xor(&s, buf, buf, 40) == KCI_OK, "40 bytes of the last block");
    CHECK(kci_stream_xor(&s, buf, buf, 24) == KCI_OK, "remaining 24 bytes of the last block");
    CHECK(kci_stream_xor(&s, buf, buf, 1) == KCI_ERR_LIMIT, "past the last block must fail");
    CHECK(kci_stream_xor(&s, buf, buf, 0) == KCI_OK, "zero length is always fine");

    /* the last block really is counter 0xffffffff */
    uint8_t blk[64], ks[64] = {0};
    kci_block(blk, &k, 0xffffffffu, kat_stream_nonce);
    kci_stream_init(&s, &k, kat_stream_nonce, 0xffffffffu);
    CHECK(kci_stream_xor(&s, ks, ks, 64) == KCI_OK && memcmp(ks, blk, 64) == 0, "last block = counter 0xffffffff");
}

static void test_wipe(void) {
    kci_key k;
    kci_key_setup(&k, kat_stream_key);
    kci_key_wipe(&k);
    const uint8_t *p = (const uint8_t *)&k; int nonzero = 0;
    for (size_t i = 0; i < sizeof k; i++) nonzero |= p[i];
    CHECK(nonzero == 0, "kci_key_wipe leaves bytes");
}

int main(void) {
    test_tables();
    test_rfc8439_crosscheck();
    test_block_kats();
    test_single_loop();
    test_reduced_rounds();
    test_stream();
    test_counter_limit();
    test_wipe();
    printf("%s: %d checks, %d failures\n", failures ? "FAILED" : "OK", checks, failures);
    return failures ? 1 : 0;
}
