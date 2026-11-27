/* AVX2 path: 8 KCI-20 blocks at once (spec v0.4 sections 4 and 11, layout from bench/prototype/avx2_rot.c).
 * One register per state word; lane j holds block (ctr + j).
 *   d rotations (rho1, rho3 in {8,16,24}): one byte shuffle, mask picked per round in constant time.
 *   b rotations (rho2, rho4): vpsllvd / vpsrlvd with broadcast counts.
 * Compiled with a target attribute and selected at run time, so the rest of the build needs no -mavx2.
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#include "../core/kci_internal.h"

#if KCI_HAVE_AVX2
#include <immintrin.h>

#define AVX2_FN __attribute__((target("avx2")))

/* pshufb masks: rotl by 8, 16, 24 bits within each little-endian 32-bit word */
static const uint8_t rotmask[3][32] = {
    { 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14, 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14 },
    { 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13, 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13 },
    { 1,2,3,0, 5,6,7,4, 9,10,11,8, 13,14,15,12, 1,2,3,0, 5,6,7,4, 9,10,11,8, 13,14,15,12 },
};

typedef struct {
    __m256i dmask[KCI_ROUNDS][2];        /* byte-shuffle masks for rho1, rho3 */
    __m256i bl[KCI_ROUNDS][2], br[KCI_ROUNDS][2];   /* left / right shift counts for rho2, rho4 */
    __m256i rc[KCI_ROUNDS];
} avx2_sched;

/* Select the mask for a secret byte rotation r in {8,16,24} without branches or secret indexes. */
AVX2_FN static __m256i pick_mask(uint32_t r)
{
    const __m256i v = _mm256_set1_epi32((int)r);
    const __m256i m8  = _mm256_cmpeq_epi32(v, _mm256_set1_epi32(8));
    const __m256i m16 = _mm256_cmpeq_epi32(v, _mm256_set1_epi32(16));
    const __m256i m24 = _mm256_cmpeq_epi32(v, _mm256_set1_epi32(24));
    __m256i out = _mm256_and_si256(m8, _mm256_loadu_si256((const __m256i *)rotmask[0]));
    out = _mm256_or_si256(out, _mm256_and_si256(m16, _mm256_loadu_si256((const __m256i *)rotmask[1])));
    out = _mm256_or_si256(out, _mm256_and_si256(m24, _mm256_loadu_si256((const __m256i *)rotmask[2])));
    return out;
}

AVX2_FN static void make_sched(avx2_sched *S, const kci_key *k)
{
    for (int r = 0; r < KCI_ROUNDS; r++) {
        S->dmask[r][0] = pick_mask(k->rot[r][0]);
        S->dmask[r][1] = pick_mask(k->rot[r][2]);
        S->bl[r][0] = _mm256_set1_epi32((int)k->rot[r][1]);
        S->br[r][0] = _mm256_set1_epi32(32 - (int)k->rot[r][1]);
        S->bl[r][1] = _mm256_set1_epi32((int)k->rot[r][3]);
        S->br[r][1] = _mm256_set1_epi32(32 - (int)k->rot[r][3]);
        S->rc[r] = _mm256_set1_epi32((int)k->rc[r]);
    }
}

#define ADD(a, b) _mm256_add_epi32(a, b)
#define XOR(a, b) _mm256_xor_si256(a, b)
#define ROTB(x, r)    _mm256_shuffle_epi8(x, S->dmask[r][0])
#define ROTB2(x, r)   _mm256_shuffle_epi8(x, S->dmask[r][1])
#define ROTV(x, r, i) _mm256_or_si256(_mm256_sllv_epi32(x, S->bl[r][i]), _mm256_srlv_epi32(x, S->br[r][i]))

#define ACT(a, b, c, d, r)                               \
    a = ADD(a, b); d = ROTB(XOR(d, a), r);               \
    c = ADD(c, d); b = ROTV(XOR(b, c), r, 0);            \
    a = ADD(a, b); d = ROTB2(XOR(d, a), r);              \
    c = ADD(c, d); b = ROTV(XOR(b, c), r, 1);

#define COLUMN(r)   ACT(x0,x4,x8,x12,r) ACT(x1,x5,x9,x13,r) ACT(x2,x6,x10,x14,r) ACT(x3,x7,x11,x15,r)
#define DIAGONAL(r) ACT(x0,x5,x10,x15,r) ACT(x1,x6,x11,x12,r) ACT(x2,x7,x8,x13,r) ACT(x3,x4,x9,x14,r)

/* 8x8 transpose of 32-bit words: in a[w] lane j = word w of block j; out o[j] = words 0..7 of block j */
#define TRANSPOSE8(a0,a1,a2,a3,a4,a5,a6,a7, o)                                              \
    do {                                                                                   \
        __m256i t0 = _mm256_unpacklo_epi32(a0, a1), t1 = _mm256_unpackhi_epi32(a0, a1);     \
        __m256i t2 = _mm256_unpacklo_epi32(a2, a3), t3 = _mm256_unpackhi_epi32(a2, a3);     \
        __m256i t4 = _mm256_unpacklo_epi32(a4, a5), t5 = _mm256_unpackhi_epi32(a4, a5);     \
        __m256i t6 = _mm256_unpacklo_epi32(a6, a7), t7 = _mm256_unpackhi_epi32(a6, a7);     \
        __m256i u0 = _mm256_unpacklo_epi64(t0, t2), u1 = _mm256_unpackhi_epi64(t0, t2);     \
        __m256i u2 = _mm256_unpacklo_epi64(t1, t3), u3 = _mm256_unpackhi_epi64(t1, t3);     \
        __m256i u4 = _mm256_unpacklo_epi64(t4, t6), u5 = _mm256_unpackhi_epi64(t4, t6);     \
        __m256i u6 = _mm256_unpacklo_epi64(t5, t7), u7 = _mm256_unpackhi_epi64(t5, t7);     \
        o[0] = _mm256_permute2x128_si256(u0, u4, 0x20); o[4] = _mm256_permute2x128_si256(u0, u4, 0x31); \
        o[1] = _mm256_permute2x128_si256(u1, u5, 0x20); o[5] = _mm256_permute2x128_si256(u1, u5, 0x31); \
        o[2] = _mm256_permute2x128_si256(u2, u6, 0x20); o[6] = _mm256_permute2x128_si256(u2, u6, 0x31); \
        o[3] = _mm256_permute2x128_si256(u3, u7, 0x20); o[7] = _mm256_permute2x128_si256(u3, u7, 0x31); \
    } while (0)

/* out = in XOR keystream for blocks ctr .. ctr + 8*groups - 1. The caller guarantees no counter wrap. */
AVX2_FN void kci_avx2_xor(uint8_t *out, const uint8_t *in, size_t groups,
                          const kci_key *k, const uint32_t nonce[3], uint32_t ctr)
{
    avx2_sched sched, *S = &sched;
    make_sched(S, k);

    const __m256i lane = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);
    const __m256i c0 = _mm256_set1_epi32((int)k->c[0]), c1 = _mm256_set1_epi32((int)k->c[1]);
    const __m256i c2 = _mm256_set1_epi32((int)k->c[2]), c3 = _mm256_set1_epi32((int)k->c[3]);
    const __m256i k0 = _mm256_set1_epi32((int)k->k[0]), k1 = _mm256_set1_epi32((int)k->k[1]);
    const __m256i k2 = _mm256_set1_epi32((int)k->k[2]), k3 = _mm256_set1_epi32((int)k->k[3]);
    const __m256i k4 = _mm256_set1_epi32((int)k->k[4]), k5 = _mm256_set1_epi32((int)k->k[5]);
    const __m256i k6 = _mm256_set1_epi32((int)k->k[6]), k7 = _mm256_set1_epi32((int)k->k[7]);
    const __m256i n0 = _mm256_set1_epi32((int)nonce[0]), n1 = _mm256_set1_epi32((int)nonce[1]);
    const __m256i n2 = _mm256_set1_epi32((int)nonce[2]);

    for (size_t g = 0; g < groups; g++, ctr += 8, in += 512, out += 512) {
        const __m256i ctrv = ADD(_mm256_set1_epi32((int)ctr), lane);
        __m256i x0 = c0, x1 = c1, x2 = c2, x3 = c3, x4 = k0, x5 = k1, x6 = k2, x7 = k3;
        __m256i x8 = k4, x9 = k5, x10 = k6, x11 = k7, x12 = ctrv, x13 = n0, x14 = n1, x15 = n2;

        for (int r = 0; r < KCI_ROUNDS; r += 4) {
            x0 = XOR(x0, S->rc[r]);     COLUMN(r)
            x1 = XOR(x1, S->rc[r + 1]); DIAGONAL(r + 1)
            x2 = XOR(x2, S->rc[r + 2]); COLUMN(r + 2)
            x3 = XOR(x3, S->rc[r + 3]); DIAGONAL(r + 3)
        }

        x0 = ADD(x0, c0); x1 = ADD(x1, c1); x2 = ADD(x2, c2); x3 = ADD(x3, c3);
        x4 = ADD(x4, k0); x5 = ADD(x5, k1); x6 = ADD(x6, k2); x7 = ADD(x7, k3);
        x8 = ADD(x8, k4); x9 = ADD(x9, k5); x10 = ADD(x10, k6); x11 = ADD(x11, k7);
        x12 = ADD(x12, ctrv); x13 = ADD(x13, n0); x14 = ADD(x14, n1); x15 = ADD(x15, n2);

        __m256i lo[8], hi[8];
        TRANSPOSE8(x0, x1, x2, x3, x4, x5, x6, x7, lo);
        TRANSPOSE8(x8, x9, x10, x11, x12, x13, x14, x15, hi);
        for (int j = 0; j < 8; j++) {
            __m256i a = _mm256_loadu_si256((const __m256i *)(in + 64 * j));
            __m256i b = _mm256_loadu_si256((const __m256i *)(in + 64 * j + 32));
            _mm256_storeu_si256((__m256i *)(out + 64 * j), XOR(a, lo[j]));
            _mm256_storeu_si256((__m256i *)(out + 64 * j + 32), XOR(b, hi[j]));
        }
    }
    kci_wipe(&sched, sizeof sched);
}

int kci_avx2_available(void)
{
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx2");
}

#else  /* not an x86-64 GCC/Clang build */

int kci_avx2_available(void) { return 0; }
void kci_avx2_xor(uint8_t *out, const uint8_t *in, size_t groups,
                  const kci_key *k, const uint32_t nonce[3], uint32_t ctr)
{ (void)out; (void)in; (void)groups; (void)k; (void)nonce; (void)ctr; }

#endif
