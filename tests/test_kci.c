/* KCI-20 unit tests and known-answer tests (spec v0.3).
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

static void test_raw_mode(void) {
    uint8_t pt[KAT_STREAM_LEN], buf[KAT_STREAM_LEN];
    kci_key k; kci_stream s;
    for (int i = 0; i < KAT_STREAM_LEN; i++) pt[i] = (uint8_t)(i * 7 + 3);
    kci_key_setup(&k, kat_stream_key);
    kci_raw_init(&s, &k, kat_stream_nonce);
    CHECK(kci_stream_xor(&s, buf, pt, sizeof pt) == KCI_OK && memcmp(buf, kat_raw_ct, sizeof buf) == 0, "raw-mode KAT");
    CHECK(memcmp(buf, kat_stream_ct, 64) != 0, "raw keystream must differ from the AEAD-domain keystream (D-024)");

    /* AEAD ciphertext of the same message is the AEAD-domain stream, not the raw one */
    uint8_t ct[KAT_STREAM_LEN], tag[16];
    kci_aead_encrypt(ct, tag, pt, sizeof pt, NULL, 0, &k, kat_stream_nonce);
    CHECK(memcmp(ct, kat_stream_ct, sizeof ct) == 0, "AEAD body = AEAD-domain keystream");
    CHECK(memcmp(ct, kat_raw_ct, 64) != 0, "AEAD ciphertext != raw ciphertext");

    kci_raw_init(&s, &k, kat_stream_nonce);
    CHECK(kci_stream_xor(&s, buf, buf, sizeof buf) == KCI_OK && memcmp(buf, pt, sizeof pt) == 0, "raw-mode decrypt");
    CHECK(memcmp(k.c, kci_stack_const, 16) == 0, "kci_raw_init must not change the caller's key");
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

static void test_poly1305(void) {
    uint8_t tag[16];
    kci_poly1305(tag, kat_poly_rfc_msg, sizeof kat_poly_rfc_msg, kat_poly_keys[0]);
    CHECK(memcmp(tag, kat_poly_rfc_tag, 16) == 0, "Poly1305 RFC 8439 2.5.2");

    static const size_t splits[] = { 1, 7, 16, 9, 33 };
    for (size_t i = 0; i < sizeof kat_polys / sizeof kat_polys[0]; i++) {
        const struct kat_poly *v = &kat_polys[i];
        const uint8_t *msg = v->pool ? kat_pool_rn : kat_pool_ff;
        kci_poly1305(tag, msg, v->len, kat_poly_keys[v->key]);
        CHECK(memcmp(tag, v->tag, 16) == 0, "Poly1305 one-shot: key %u len %u pool %u", v->key, v->len, v->pool);

        /* same message fed in uneven pieces */
        kci_poly1305_state st; size_t pos = 0, c = 0;
        kci_poly1305_init(&st, kat_poly_keys[v->key]);
        while (pos < v->len) {
            size_t n = splits[c++ % (sizeof splits / sizeof splits[0])];
            if (n > v->len - pos) n = v->len - pos;
            kci_poly1305_update(&st, msg + pos, n);
            pos += n;
        }
        kci_poly1305_final(&st, tag);
        CHECK(memcmp(tag, v->tag, 16) == 0, "Poly1305 streamed: key %u len %u pool %u", v->key, v->len, v->pool);
    }
}

static void test_poly1305_edges(void) {
    uint8_t tag[16];
    for (int j = 0; j < 6; j++) {
        kci_poly1305(tag, kat_poly_edge[j][0], 48, kat_poly_edge_key);
        CHECK(memcmp(tag, kat_poly_edge[j][1], 16) == 0, "Poly1305 final reduction, h = p + %d", j - 1);
    }
}

static void test_aead_rfc8439(void) {
    kci_key k; uint8_t ct[KAT_RFC_AEAD_LEN], pt[KAT_RFC_AEAD_LEN], tag[16];
    chacha_mode_key(&k, kat_rfc_aead_key);
    CHECK(kci_aead_encrypt(ct, tag, kat_rfc_aead_pt, sizeof ct, kat_rfc_aead_aad, 12, &k, kat_rfc_aead_nonce) == KCI_OK,
          "RFC AEAD encrypt");
    CHECK(memcmp(ct, kat_rfc_aead_ct, sizeof ct) == 0, "ChaCha-mode AEAD ciphertext != RFC 8439 2.8.2");
    CHECK(memcmp(tag, kat_rfc_aead_tag, 16) == 0, "ChaCha-mode AEAD tag != RFC 8439 2.8.2");
    CHECK(kci_aead_decrypt(pt, ct, sizeof ct, tag, kat_rfc_aead_aad, 12, &k, kat_rfc_aead_nonce) == KCI_OK &&
          memcmp(pt, kat_rfc_aead_pt, sizeof pt) == 0, "RFC AEAD decrypt");
}

static void test_aead_kats(void) {
    uint8_t buf[256], tag[16];
    for (size_t i = 0; i < sizeof kat_aeads / sizeof kat_aeads[0]; i++) {
        const struct kat_aead *v = &kat_aeads[i];
        const uint8_t *aad = v->aad_len ? kat_pool_rn + 256 - v->aad_len : NULL;
        kci_key k;
        kci_key_setup(&k, v->key);

        memcpy(buf, kat_pool_rn, v->len);   /* encrypt in place */
        CHECK(kci_aead_encrypt(buf, tag, buf, v->len, aad, v->aad_len, &k, v->nonce) == KCI_OK, "AEAD encrypt %zu", i);
        CHECK(memcmp(buf, kat_aead_cts + v->ct_off, v->len) == 0, "AEAD ciphertext %zu (aad %u, len %u)", i, v->aad_len, v->len);
        CHECK(memcmp(tag, v->tag, 16) == 0, "AEAD tag %zu (aad %u, len %u)", i, v->aad_len, v->len);

        CHECK(kci_aead_decrypt(buf, buf, v->len, v->tag, aad, v->aad_len, &k, v->nonce) == KCI_OK &&
              memcmp(buf, kat_pool_rn, v->len) == 0, "AEAD decrypt in place %zu", i);
        kci_key_wipe(&k);
    }
}

/* streaming AEAD in uneven pieces must give the one-shot KATs */
static void test_aead_streaming(void) {
    static const size_t pieces[] = { 1, 15, 16, 17, 63, 64, 65, 7 };
    uint8_t buf[256], tag[16];
    for (size_t i = 0; i < sizeof kat_aeads / sizeof kat_aeads[0]; i++) {
        const struct kat_aead *v = &kat_aeads[i];
        const uint8_t *aad = v->aad_len ? kat_pool_rn + 256 - v->aad_len : NULL;
        kci_key k; kci_aead_ctx c; size_t pos = 0, p = i;
        kci_key_setup(&k, v->key);

        memcpy(buf, kat_pool_rn, v->len);
        kci_aead_init(&c, &k, v->nonce, aad, v->aad_len);
        while (pos < v->len) {
            size_t n = pieces[p++ % 8]; if (n > v->len - pos) n = v->len - pos;
            CHECK(kci_aead_encrypt_update(&c, buf + pos, buf + pos, n) == KCI_OK, "stream encrypt update");
            pos += n;
        }
        kci_aead_encrypt_final(&c, tag);
        CHECK(memcmp(buf, kat_aead_cts + v->ct_off, v->len) == 0 && memcmp(tag, v->tag, 16) == 0,
              "streaming AEAD encrypt %zu", i);

        kci_aead_init(&c, &k, v->nonce, aad, v->aad_len);
        for (pos = 0, p = i + 3; pos < v->len; ) {
            size_t n = pieces[p++ % 8]; if (n > v->len - pos) n = v->len - pos;
            CHECK(kci_aead_decrypt_update(&c, buf + pos, buf + pos, n) == KCI_OK, "stream decrypt update");
            pos += n;
        }
        CHECK(kci_aead_decrypt_final(&c, v->tag) == KCI_OK && memcmp(buf, kat_pool_rn, v->len) == 0,
              "streaming AEAD decrypt %zu", i);

        uint8_t bad[16]; memcpy(bad, v->tag, 16); bad[0] ^= 1;
        kci_aead_init(&c, &k, v->nonce, aad, v->aad_len);
        kci_aead_decrypt_update(&c, buf, kat_aead_cts + v->ct_off, v->len);
        CHECK(kci_aead_decrypt_final(&c, bad) == KCI_ERR_AUTH, "streaming AEAD bad tag %zu", i);
    }
}

static void test_aead_tamper(void) {
    const struct kat_aead *v = &kat_aeads[sizeof kat_aeads / sizeof kat_aeads[0] - 1];   /* aad 17, len 200 */
    const uint8_t *ct = kat_aead_cts + v->ct_off;
    uint8_t c2[256], tag[16], aad[32], nonce[12], out[256];
    kci_key k;
    kci_key_setup(&k, v->key);

#define EXPECT_AUTH_FAIL(what, CT, TAG, AAD, NONCE)                                                  \
    do {                                                                                          \
        memset(out, 0xa5, sizeof out);                                                            \
        int rc_ = kci_aead_decrypt(out, CT, v->len, TAG, AAD, v->aad_len, &k, NONCE);             \
        int untouched_ = 1;                                                                       \
        for (size_t j = 0; j < sizeof out; j++) untouched_ &= (out[j] == 0xa5);                   \
        CHECK(rc_ == KCI_ERR_AUTH && untouched_, "tampered %s must fail and write nothing", what); \
    } while (0)

    memcpy(aad, kat_pool_rn + 256 - v->aad_len, v->aad_len);
    memcpy(nonce, v->nonce, 12);
    memcpy(tag, v->tag, 16);
    for (size_t pos = 0; pos < v->len; pos += 37) {
        memcpy(c2, ct, v->len); c2[pos] ^= 0x01;
        EXPECT_AUTH_FAIL("ciphertext", c2, tag, aad, nonce);
    }
    for (int b = 0; b < 16; b++) {
        memcpy(tag, v->tag, 16); tag[b] ^= 0x80;
        EXPECT_AUTH_FAIL("tag", ct, tag, aad, nonce);
    }
    memcpy(tag, v->tag, 16);
    aad[v->aad_len - 1] ^= 0x01;
    EXPECT_AUTH_FAIL("aad", ct, tag, aad, nonce);
    aad[v->aad_len - 1] ^= 0x01;
    nonce[11] ^= 0x01;
    EXPECT_AUTH_FAIL("nonce", ct, tag, aad, nonce);
    nonce[11] ^= 0x01;
    /* truncated message (length is authenticated) */
    memset(out, 0xa5, sizeof out);
    CHECK(kci_aead_decrypt(out, ct, v->len - 1, tag, aad, v->aad_len, &k, nonce) == KCI_ERR_AUTH, "truncated must fail");
    /* wrong key */
    kci_key k2; uint8_t key2[32]; memcpy(key2, v->key, 32); key2[31] ^= 1;
    kci_key_setup(&k2, key2);
    CHECK(kci_aead_decrypt(out, ct, v->len, tag, aad, v->aad_len, &k2, nonce) == KCI_ERR_AUTH, "wrong key must fail");
    /* and the untampered inputs still verify */
    CHECK(kci_aead_decrypt(out, ct, v->len, tag, aad, v->aad_len, &k, nonce) == KCI_OK &&
          memcmp(out, kat_pool_rn, v->len) == 0, "untampered still verifies");
#undef EXPECT_AUTH_FAIL
}

static void test_aead_limit_and_ctcmp(void) {
    kci_key k; uint8_t tag[16] = {0}, b[1] = {0};
    kci_key_setup(&k, kat_stream_key);
    if ((uint64_t)SIZE_MAX > KCI_MAX_MSG_BYTES) {   /* 64-bit hosts: the limit is reachable as a size_t */
        CHECK(kci_aead_encrypt(b, tag, b, (size_t)KCI_MAX_MSG_BYTES + 1, NULL, 0, &k, kat_stream_nonce) == KCI_ERR_LIMIT,
              "encrypt over the length limit");
        CHECK(kci_aead_decrypt(b, b, (size_t)KCI_MAX_MSG_BYTES + 1, tag, NULL, 0, &k, kat_stream_nonce) == KCI_ERR_LIMIT,
              "decrypt over the length limit");
    }
    static const uint8_t x[5] = {1,2,3,4,5}, y[5] = {1,2,3,4,6};
    CHECK(kci_ct_memcmp(x, x, 5) == 0 && kci_ct_memcmp(x, y, 5) == -1 && kci_ct_memcmp(x, y, 0) == 0, "kci_ct_memcmp");
}

static void test_sha256(void) {
    uint8_t md[32];
    kci_sha256(md, (const uint8_t *)"abc", 3);
    CHECK(memcmp(md, kat_sha_abc, 32) == 0, "SHA-256 FIPS 180-4 \"abc\"");
    kci_sha256(md, (const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
    CHECK(memcmp(md, kat_sha_448, 32) == 0, "SHA-256 FIPS 180-4 448-bit message");

    kci_sha256_state st;                      /* one million 'a', fed in 1000-byte pieces */
    uint8_t a[1000]; memset(a, 'a', sizeof a);
    kci_sha256_init(&st);
    for (int i = 0; i < 1000; i++) kci_sha256_update(&st, a, sizeof a);
    kci_sha256_final(&st, md);
    CHECK(memcmp(md, kat_sha_million_a, 32) == 0, "SHA-256 FIPS 180-4 one million 'a'");

    static const size_t splits[] = { 1, 63, 2, 64, 17 };
    for (size_t i = 0; i < sizeof kat_shas / sizeof kat_shas[0]; i++) {
        const struct kat_sha *v = &kat_shas[i];
        kci_sha256(md, kat_sha_pool, v->len);
        CHECK(memcmp(md, v->md, 32) == 0, "SHA-256 one-shot len %u", v->len);
        size_t pos = 0, c = 0;
        kci_sha256_init(&st);
        while (pos < v->len) {
            size_t n = splits[c++ % 5];
            if (n > (size_t)v->len - pos) n = (size_t)v->len - pos;
            kci_sha256_update(&st, kat_sha_pool + pos, n);
            pos += n;
        }
        kci_sha256_final(&st, md);
        CHECK(memcmp(md, v->md, 32) == 0, "SHA-256 streamed len %u", v->len);
    }
}

static void test_hmac_sha256(void) {
    uint8_t mac[32];
    for (size_t i = 0; i < sizeof kat_hmacs / sizeof kat_hmacs[0]; i++) {
        const struct kat_hmac *v = &kat_hmacs[i];
        kci_hmac_sha256(mac, v->key, v->key_len, v->msg, v->msg_len);
        CHECK(memcmp(mac, v->mac, 32) == 0, "HMAC-SHA256 vector %zu (key %u bytes)", i, v->key_len);
    }
}

static void test_pbkdf2(void) {
    uint8_t dk[97];
    for (size_t i = 0; i < sizeof kat_pbkdf2s / sizeof kat_pbkdf2s[0]; i++) {
        const struct kat_pbkdf2 *v = &kat_pbkdf2s[i];
        kci_pbkdf2_hmac_sha256(dk, v->dk_len, v->pw, v->pw_len, v->salt, v->salt_len, v->iter);
        CHECK(memcmp(dk, v->dk, v->dk_len) == 0, "PBKDF2 vector %zu (c = %u, dkLen = %u)", i, (unsigned)v->iter, v->dk_len);
    }
}

static void test_kdf_password(void) {
    uint8_t key[32] = {0};
    CHECK(kci_kdf_password(key, kat_kdf_pw, sizeof kat_kdf_pw, kat_kdf_salt, 16, KCI_KDF_DEFAULT_ITERATIONS) == KCI_OK &&
          memcmp(key, kat_kdf_key_default, 32) == 0, "kci_kdf_password at the default 600 000 iterations");
    CHECK(kci_kdf_password(key, kat_kdf_pw, sizeof kat_kdf_pw, kat_kdf_salt, 16, KCI_KDF_MIN_ITERATIONS - 1) == KCI_ERR_PARAM,
          "too few iterations must be refused");
    CHECK(kci_kdf_password(key, kat_kdf_pw, sizeof kat_kdf_pw, kat_kdf_salt, 15, KCI_KDF_DEFAULT_ITERATIONS) == KCI_ERR_PARAM,
          "short salt must be refused");
}

/* Reference keystream: one portable kci_block per counter. */
static void ref_xor(uint8_t *out, const uint8_t *in, size_t len, const kci_key *k, const uint8_t nonce[12], uint32_t ctr) {
    uint8_t blk[64];
    for (size_t off = 0; off < len; off += 64, ctr++) {
        kci_block(blk, k, ctr, nonce);
        for (size_t i = 0; i < 64 && off + i < len; i++) out[off + i] = in[off + i] ^ blk[i];
    }
}

/* The AVX2 path (when this CPU has it) must equal the portable block function exactly. */
static void test_simd_matches_portable(void) {
    static uint8_t in[8192 + 64], a[8192 + 64], b[8192 + 64];
    uint32_t seed = 0x6b636921u;
    for (size_t i = 0; i < sizeof in; i++) { seed = seed * 1664525u + 1013904223u; in[i] = (uint8_t)(seed >> 24); }
    printf("keystream implementation: %s\n", kci_impl());

    for (int t = 0; t < 24; t++) {                       /* 24 keys -> 24 different decks */
        uint8_t key[32], nonce[12];
        for (int i = 0; i < 32; i++) { seed = seed * 1664525u + 1013904223u; key[i] = (uint8_t)(seed >> 24); }
        for (int i = 0; i < 12; i++) { seed = seed * 1664525u + 1013904223u; nonce[i] = (uint8_t)(seed >> 24); }
        kci_key k; kci_key_setup(&k, key);

        /* direct call of the 8-block kernel */
        if (kci_avx2_available()) {
            uint32_t nw[3]; for (int i = 0; i < 3; i++) nw[i] = kci_load32(nonce + 4 * i);
            uint32_t ctr = (t % 3 == 0) ? 0xfffffff8u - 8u * (uint32_t)(t % 2) : (uint32_t)t * 1000u;
            kci_avx2_xor(a, in, 2, &k, nw, ctr);
            ref_xor(b, in, 1024, &k, nonce, ctr);
            CHECK(memcmp(a, b, 1024) == 0, "AVX2 kernel != portable, key %d ctr 0x%08x", t, (unsigned)ctr);
        }

        /* through the stream API: odd lead-in, then a long run (dispatch), then a tail */
        static const size_t lens[] = { 511, 512, 513, 1000, 4096, 4097, 8192 };
        for (size_t li = 0; li < sizeof lens / sizeof lens[0]; li++) {
            size_t len = lens[li], lead = (size_t)(t * 7) % 70;
            kci_stream s;
            kci_raw_init(&s, &k, nonce);
            kci_stream_xor(&s, a, in, lead);
            kci_stream_xor(&s, a + lead, in + lead, len);
            kci_raw_init(&s, &k, nonce);
            kci_key rk = s.key;                           /* raw-domain key copy for the reference */
            ref_xor(b, in, lead + len, &rk, nonce, 1);
            CHECK(memcmp(a, b, lead + len) == 0, "stream (lead %zu, len %zu) != portable, key %d", lead, len, t);
        }
        kci_key_wipe(&k);
    }

    /* last 8 counters before the limit go through AVX2 without wrapping */
    kci_key k; kci_stream s;
    kci_key_setup(&k, kat_stream_key);
    kci_stream_init(&s, &k, kat_stream_nonce, 0xfffffff8u);
    CHECK(kci_stream_xor(&s, a, in, 512) == KCI_OK, "last 8 blocks");
    ref_xor(b, in, 512, &k, kat_stream_nonce, 0xfffffff8u);
    CHECK(memcmp(a, b, 512) == 0, "last 8 blocks via AVX2 == portable");
    CHECK(kci_stream_xor(&s, a, in, 1) == KCI_ERR_LIMIT, "nothing left after the last block");
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
    test_raw_mode();
    test_counter_limit();
    test_poly1305();
    test_poly1305_edges();
    test_aead_rfc8439();
    test_aead_kats();
    test_aead_streaming();
    test_aead_tamper();
    test_aead_limit_and_ctcmp();
    test_sha256();
    test_hmac_sha256();
    test_pbkdf2();
    test_kdf_password();
    test_simd_matches_portable();
    test_wipe();
    printf("%s: %d checks, %d failures\n", failures ? "FAILED" : "OK", checks, failures);
    return failures ? 1 : 0;
}
