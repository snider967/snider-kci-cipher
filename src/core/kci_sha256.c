/* SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104) and PBKDF2-HMAC-SHA256 (RFC 8018), portable C11.
 * In-house so the library has no dependencies (Q6 default; needed for microcontrollers).
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#include "kci_internal.h"

static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static inline uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32u - n)); }
static inline uint32_t load_be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
}
static inline void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static void compress(uint32_t h[8], const uint8_t block[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = load_be32(block + 4 * i);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    kci_wipe(w, sizeof w);
}

void kci_sha256_init(kci_sha256_state *st)
{
    static const uint32_t iv[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
    for (int i = 0; i < 8; i++) st->h[i] = iv[i];
    st->total = 0;
    st->left = 0;
}

void kci_sha256_update(kci_sha256_state *st, const uint8_t *m, size_t n)
{
    st->total += n;
    if (st->left) {
        size_t want = 64 - st->left;
        if (want > n) want = n;
        for (size_t i = 0; i < want; i++) st->buf[st->left + i] = m[i];
        st->left += want; m += want; n -= want;
        if (st->left < 64) return;
        compress(st->h, st->buf);
        st->left = 0;
    }
    while (n >= 64) { compress(st->h, m); m += 64; n -= 64; }
    for (size_t i = 0; i < n; i++) st->buf[i] = m[i];
    st->left = n;
}

void kci_sha256_final(kci_sha256_state *st, uint8_t out[KCI_SHA256_BYTES])
{
    const uint64_t bits = st->total * 8u;
    size_t i = st->left;
    st->buf[i++] = 0x80;
    if (i > 56) {
        while (i < 64) st->buf[i++] = 0;
        compress(st->h, st->buf);
        i = 0;
    }
    while (i < 56) st->buf[i++] = 0;
    for (int j = 0; j < 8; j++) st->buf[56 + j] = (uint8_t)(bits >> (56 - 8 * j));
    compress(st->h, st->buf);
    for (int j = 0; j < 8; j++) store_be32(out + 4 * j, st->h[j]);
    kci_wipe(st, sizeof *st);
}

void kci_sha256(uint8_t out[KCI_SHA256_BYTES], const uint8_t *m, size_t n)
{
    kci_sha256_state st;
    kci_sha256_init(&st);
    kci_sha256_update(&st, m, n);
    kci_sha256_final(&st, out);
}

/* ---------------- HMAC-SHA256 ---------------- */

void kci_hmac_sha256_init(kci_hmac_sha256_state *st, const uint8_t *key, size_t key_len)
{
    uint8_t k[64] = {0}, pad[64];
    if (key_len > 64) kci_sha256(k, key, key_len);          /* long keys are hashed first */
    else for (size_t i = 0; i < key_len; i++) k[i] = key[i];

    for (int i = 0; i < 64; i++) pad[i] = (uint8_t)(k[i] ^ 0x36);
    kci_sha256_init(&st->inner);
    kci_sha256_update(&st->inner, pad, 64);
    for (int i = 0; i < 64; i++) pad[i] = (uint8_t)(k[i] ^ 0x5c);
    kci_sha256_init(&st->outer);
    kci_sha256_update(&st->outer, pad, 64);
    kci_wipe(k, sizeof k);
    kci_wipe(pad, sizeof pad);
}

void kci_hmac_sha256_update(kci_hmac_sha256_state *st, const uint8_t *m, size_t n)
{
    kci_sha256_update(&st->inner, m, n);
}

void kci_hmac_sha256_final(kci_hmac_sha256_state *st, uint8_t out[KCI_SHA256_BYTES])
{
    uint8_t ih[KCI_SHA256_BYTES];
    kci_sha256_final(&st->inner, ih);
    kci_sha256_update(&st->outer, ih, sizeof ih);
    kci_sha256_final(&st->outer, out);
    kci_wipe(ih, sizeof ih);
    kci_wipe(st, sizeof *st);
}

void kci_hmac_sha256(uint8_t out[KCI_SHA256_BYTES], const uint8_t *key, size_t key_len,
                     const uint8_t *m, size_t n)
{
    kci_hmac_sha256_state st;
    kci_hmac_sha256_init(&st, key, key_len);
    kci_hmac_sha256_update(&st, m, n);
    kci_hmac_sha256_final(&st, out);
}

/* ---------------- PBKDF2-HMAC-SHA256 (RFC 8018 section 5.2) ---------------- */

void kci_pbkdf2_hmac_sha256(uint8_t *out, size_t out_len,
                            const uint8_t *pw, size_t pw_len,
                            const uint8_t *salt, size_t salt_len, uint32_t iterations)
{
    kci_hmac_sha256_state base, st;
    uint8_t u[KCI_SHA256_BYTES], t[KCI_SHA256_BYTES], ctr[4];

    /* Key the HMAC once; each iteration then copies the keyed state (2 compressions instead of 4). */
    kci_hmac_sha256_init(&base, pw, pw_len);
    for (uint32_t block = 1; out_len > 0; block++) {
        store_be32(ctr, block);
        st = base;
        kci_hmac_sha256_update(&st, salt, salt_len);
        kci_hmac_sha256_update(&st, ctr, 4);
        kci_hmac_sha256_final(&st, u);
        for (int i = 0; i < KCI_SHA256_BYTES; i++) t[i] = u[i];
        for (uint32_t it = 1; it < iterations; it++) {
            st = base;
            kci_hmac_sha256_update(&st, u, sizeof u);
            kci_hmac_sha256_final(&st, u);
            for (int i = 0; i < KCI_SHA256_BYTES; i++) t[i] ^= u[i];
        }
        size_t take = out_len < KCI_SHA256_BYTES ? out_len : KCI_SHA256_BYTES;
        for (size_t i = 0; i < take; i++) out[i] = t[i];
        out += take; out_len -= take;
    }
    kci_wipe(&base, sizeof base);
    kci_wipe(u, sizeof u);
    kci_wipe(t, sizeof t);
}

int kci_kdf_password(uint8_t key[KCI_KEY_BYTES], const uint8_t *pw, size_t pw_len,
                     const uint8_t *salt, size_t salt_len, uint32_t iterations)
{
    if (iterations < KCI_KDF_MIN_ITERATIONS) return KCI_ERR_PARAM;
    if (salt_len < KCI_KDF_MIN_SALT_BYTES) return KCI_ERR_PARAM;
    kci_pbkdf2_hmac_sha256(key, KCI_KEY_BYTES, pw, pw_len, salt, salt_len, iterations);
    return KCI_OK;
}
