/* Poly1305 one-time authenticator (RFC 8439 section 2.5), 26-bit limbs on 32-bit words.
 * Portable and constant-time on targets whose 32x32 -> 64-bit multiply is constant-time
 * (see vault/Refactor/KCI-Primitive-Design.md section 8 for the Cortex-M3 caveat).
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#include "kci_internal.h"

#define M26 0x3ffffffu

void kci_poly1305_init(kci_poly1305_state *st, const uint8_t key[32])
{
    /* r = key[0..15] clamped (RFC 8439 2.5.1), split into 26-bit limbs */
    st->r[0] = (kci_load32(key +  0)     ) & 0x3ffffffu;
    st->r[1] = (kci_load32(key +  3) >> 2) & 0x3ffff03u;
    st->r[2] = (kci_load32(key +  6) >> 4) & 0x3ffc0ffu;
    st->r[3] = (kci_load32(key +  9) >> 6) & 0x3f03fffu;
    st->r[4] = (kci_load32(key + 12) >> 8) & 0x00fffffu;
    for (int i = 0; i < 5; i++) st->h[i] = 0;
    for (int i = 0; i < 4; i++) st->pad[i] = kci_load32(key + 16 + 4 * i);
    st->left = 0;
}

/* h = (h + m) * r mod 2^130 - 5 for each 16-byte block; hibit = 2^128 marker (0 for the padded final block) */
static void blocks(kci_poly1305_state *st, const uint8_t *m, size_t bytes, uint32_t hibit)
{
    const uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];

    while (bytes >= 16) {
        h0 += (kci_load32(m +  0)     ) & M26;
        h1 += (kci_load32(m +  3) >> 2) & M26;
        h2 += (kci_load32(m +  6) >> 4) & M26;
        h3 += (kci_load32(m +  9) >> 6) & M26;
        h4 += (kci_load32(m + 12) >> 8) | hibit;

        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & M26;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & M26;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & M26;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & M26;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & M26;
        h0 += c * 5; c = h0 >> 26; h0 &= M26;
        h1 += c;

        m += 16; bytes -= 16;
    }
    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

void kci_poly1305_update(kci_poly1305_state *st, const uint8_t *m, size_t bytes)
{
    if (st->left) {                         /* top up a partial block */
        size_t want = 16 - st->left;
        if (want > bytes) want = bytes;
        for (size_t i = 0; i < want; i++) st->buf[st->left + i] = m[i];
        st->left += want; m += want; bytes -= want;
        if (st->left < 16) return;
        blocks(st, st->buf, 16, 1u << 24);
        st->left = 0;
    }
    if (bytes >= 16) {
        size_t full = bytes & ~(size_t)15;
        blocks(st, m, full, 1u << 24);
        m += full; bytes -= full;
    }
    for (size_t i = 0; i < bytes; i++) st->buf[i] = m[i];
    st->left = bytes;
}

void kci_poly1305_final(kci_poly1305_state *st, uint8_t tag[16])
{
    if (st->left) {                         /* final partial block: append 1, pad with zeros, no 2^128 bit */
        st->buf[st->left] = 1;
        for (size_t i = st->left + 1; i < 16; i++) st->buf[i] = 0;
        blocks(st, st->buf, 16, 0);
    }

    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4], c;

    /* fully carry h */
    c = h1 >> 26; h1 &= M26; h2 += c;
    c = h2 >> 26; h2 &= M26; h3 += c;
    c = h3 >> 26; h3 &= M26; h4 += c;
    c = h4 >> 26; h4 &= M26; h0 += c * 5;
    c = h0 >> 26; h0 &= M26; h1 += c;

    /* g = h + 5 - 2^130; use g if h >= p, chosen with a mask (constant-time) */
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= M26;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= M26;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= M26;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= M26;
    uint32_t g4 = h4 + c - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1u;       /* all ones if g4 did not go negative, i.e. h >= p */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

    /* h mod 2^128, as four 32-bit words */
    h0 = (h0      ) | (h1 << 26);
    h1 = (h1 >>  6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 <<  8);

    /* tag = (h + s) mod 2^128 */
    uint64_t f;
    f = (uint64_t)h0 + st->pad[0];             h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;

    kci_store32(tag + 0, h0); kci_store32(tag + 4, h1);
    kci_store32(tag + 8, h2); kci_store32(tag + 12, h3);
    kci_wipe(st, sizeof *st);
}

void kci_poly1305(uint8_t tag[16], const uint8_t *m, size_t bytes, const uint8_t key[32])
{
    kci_poly1305_state st;
    kci_poly1305_init(&st, key);
    kci_poly1305_update(&st, m, bytes);
    kci_poly1305_final(&st, tag);
}
