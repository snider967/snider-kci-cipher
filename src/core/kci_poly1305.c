/* Poly1305 one-time authenticator (RFC 8439 section 2.5), two implementations with identical output:
 *   - 44/44/42-bit limbs with 64x64 -> 128-bit products, where the compiler has unsigned __int128 (x86-64, ARM64)
 *   - 26-bit limbs with 32x32 -> 64-bit products everywhere else (32-bit CPUs, MCUs), or with -DKCI_NO_INT128
 * Constant-time where the multiply is (see vault/Refactor/KCI-Primitive-Design.md section 8 for the Cortex-M3 caveat).
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#include "kci_internal.h"

#if defined(__SIZEOF_INT128__) && !defined(KCI_NO_INT128)
#define KCI_POLY64 1
#else
#define KCI_POLY64 0
#endif

#if KCI_POLY64
/* ======================= 64-bit limbs ======================= */
__extension__ typedef unsigned __int128 u128;   /* GCC/Clang; __extension__ keeps -Wpedantic quiet */
#define M44 0xfffffffffffull
#define M42 0x3ffffffffffull

static inline uint64_t load64(const uint8_t *p) { return (uint64_t)kci_load32(p) | (uint64_t)kci_load32(p + 4) << 32; }
static inline void store64(uint8_t *p, uint64_t v) { kci_store32(p, (uint32_t)v); kci_store32(p + 4, (uint32_t)(v >> 32)); }

void kci_poly1305_init(kci_poly1305_state *st, const uint8_t key[32])
{
    const uint64_t t0 = load64(key), t1 = load64(key + 8);
    st->u.p64.r[0] = t0 & 0xffc0fffffffull;                          /* clamped r, 44/44/42 bits */
    st->u.p64.r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffffull;
    st->u.p64.r[2] = (t1 >> 24) & 0x00ffffffc0full;
    st->u.p64.h[0] = st->u.p64.h[1] = st->u.p64.h[2] = 0;
    st->u.p64.pad[0] = load64(key + 16);
    st->u.p64.pad[1] = load64(key + 24);
    st->left = 0;
}

static void blocks(kci_poly1305_state *st, const uint8_t *m, size_t bytes, uint64_t hibit)
{
    const uint64_t r0 = st->u.p64.r[0], r1 = st->u.p64.r[1], r2 = st->u.p64.r[2];
    const uint64_t s1 = r1 * (5 << 2), s2 = r2 * (5 << 2);
    uint64_t h0 = st->u.p64.h[0], h1 = st->u.p64.h[1], h2 = st->u.p64.h[2], c;

    while (bytes >= 16) {
        const uint64_t t0 = load64(m), t1 = load64(m + 8);
        h0 += t0 & M44;
        h1 += ((t0 >> 44) | (t1 << 20)) & M44;
        h2 += ((t1 >> 24) & M42) | hibit;

        u128 d0 = (u128)h0 * r0 + (u128)h1 * s2 + (u128)h2 * s1;
        u128 d1 = (u128)h0 * r1 + (u128)h1 * r0 + (u128)h2 * s2;
        u128 d2 = (u128)h0 * r2 + (u128)h1 * r1 + (u128)h2 * r0;

        c = (uint64_t)(d0 >> 44); h0 = (uint64_t)d0 & M44;
        d1 += c; c = (uint64_t)(d1 >> 44); h1 = (uint64_t)d1 & M44;
        d2 += c; c = (uint64_t)(d2 >> 42); h2 = (uint64_t)d2 & M42;
        h0 += c * 5; c = h0 >> 44; h0 &= M44;
        h1 += c;

        m += 16; bytes -= 16;
    }
    st->u.p64.h[0] = h0; st->u.p64.h[1] = h1; st->u.p64.h[2] = h2;
}

#define HIBIT_FULL ((uint64_t)1 << 40)

static void finish(kci_poly1305_state *st, uint8_t tag[16])
{
    uint64_t h0 = st->u.p64.h[0], h1 = st->u.p64.h[1], h2 = st->u.p64.h[2], c;

    /* fully carry h (two passes, as in poly1305-donna-64) */
    c = h1 >> 44; h1 &= M44; h2 += c;
    c = h2 >> 42; h2 &= M42; h0 += c * 5;
    c = h0 >> 44; h0 &= M44; h1 += c;
    c = h1 >> 44; h1 &= M44; h2 += c;
    c = h2 >> 42; h2 &= M42; h0 += c * 5;
    c = h0 >> 44; h0 &= M44; h1 += c;

    /* g = h + 5 - 2^130; select g if h >= p, with a mask */
    uint64_t g0 = h0 + 5; c = g0 >> 44; g0 &= M44;
    uint64_t g1 = h1 + c; c = g1 >> 44; g1 &= M44;
    uint64_t g2 = h2 + c - ((uint64_t)1 << 42);
    c = (g2 >> 63) - 1;                      /* all ones if g2 did not go negative */
    g0 &= c; g1 &= c; g2 &= c;
    c = ~c;
    h0 = (h0 & c) | g0; h1 = (h1 & c) | g1; h2 = (h2 & c) | g2;

    /* tag = (h + s) mod 2^128 */
    const uint64_t t0 = st->u.p64.pad[0], t1 = st->u.p64.pad[1];
    h0 += t0 & M44;                                  c = h0 >> 44; h0 &= M44;
    h1 += (((t0 >> 44) | (t1 << 20)) & M44) + c;     c = h1 >> 44; h1 &= M44;
    h2 += ((t1 >> 24) & M42) + c;                    h2 &= M42;
    h0 = h0 | (h1 << 44);
    h1 = (h1 >> 20) | (h2 << 24);
    store64(tag, h0);
    store64(tag + 8, h1);
}

#else
/* ======================= 32-bit limbs ======================= */
#define M26 0x3ffffffu

void kci_poly1305_init(kci_poly1305_state *st, const uint8_t key[32])
{
    /* r = key[0..15] clamped (RFC 8439 2.5.1), split into 26-bit limbs */
    st->u.p32.r[0] = (kci_load32(key +  0)     ) & 0x3ffffffu;
    st->u.p32.r[1] = (kci_load32(key +  3) >> 2) & 0x3ffff03u;
    st->u.p32.r[2] = (kci_load32(key +  6) >> 4) & 0x3ffc0ffu;
    st->u.p32.r[3] = (kci_load32(key +  9) >> 6) & 0x3f03fffu;
    st->u.p32.r[4] = (kci_load32(key + 12) >> 8) & 0x00fffffu;
    for (int i = 0; i < 5; i++) st->u.p32.h[i] = 0;
    for (int i = 0; i < 4; i++) st->u.p32.pad[i] = kci_load32(key + 16 + 4 * i);
    st->left = 0;
}

/* h = (h + m) * r mod 2^130 - 5 for each 16-byte block; hibit = 2^128 marker (0 for the padded final block) */
static void blocks(kci_poly1305_state *st, const uint8_t *m, size_t bytes, uint32_t hibit)
{
    const uint32_t r0 = st->u.p32.r[0], r1 = st->u.p32.r[1], r2 = st->u.p32.r[2], r3 = st->u.p32.r[3], r4 = st->u.p32.r[4];
    const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->u.p32.h[0], h1 = st->u.p32.h[1], h2 = st->u.p32.h[2], h3 = st->u.p32.h[3], h4 = st->u.p32.h[4];

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
    st->u.p32.h[0] = h0; st->u.p32.h[1] = h1; st->u.p32.h[2] = h2; st->u.p32.h[3] = h3; st->u.p32.h[4] = h4;
}

#define HIBIT_FULL (1u << 24)

static void finish(kci_poly1305_state *st, uint8_t tag[16])
{
    uint32_t h0 = st->u.p32.h[0], h1 = st->u.p32.h[1], h2 = st->u.p32.h[2], h3 = st->u.p32.h[3], h4 = st->u.p32.h[4], c;

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
    f = (uint64_t)h0 + st->u.p32.pad[0];             h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->u.p32.pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->u.p32.pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->u.p32.pad[3] + (f >> 32); h3 = (uint32_t)f;

    kci_store32(tag + 0, h0); kci_store32(tag + 4, h1);
    kci_store32(tag + 8, h2); kci_store32(tag + 12, h3);
}
#endif

void kci_poly1305_update(kci_poly1305_state *st, const uint8_t *m, size_t bytes)
{
    if (st->left) {                         /* top up a partial block */
        size_t want = 16 - st->left;
        if (want > bytes) want = bytes;
        for (size_t i = 0; i < want; i++) st->buf[st->left + i] = m[i];
        st->left += want; m += want; bytes -= want;
        if (st->left < 16) return;
        blocks(st, st->buf, 16, HIBIT_FULL);
        st->left = 0;
    }
    if (bytes >= 16) {
        size_t full = bytes & ~(size_t)15;
        blocks(st, m, full, HIBIT_FULL);
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
    finish(st, tag);
    kci_wipe(st, sizeof *st);
}

void kci_poly1305(uint8_t tag[16], const uint8_t *m, size_t bytes, const uint8_t key[32])
{
    kci_poly1305_state st;
    kci_poly1305_init(&st, key);
    kci_poly1305_update(&st, m, bytes);
    kci_poly1305_final(&st, tag);
}
