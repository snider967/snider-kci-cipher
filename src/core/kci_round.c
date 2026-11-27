/* KCI-20 round function and block function (spec 4.3-4.5). Portable C11, 32-bit words.
 * Every round runs the same instructions; the key's deck only changes the loaded values (spec 8).
 * Branches below depend only on the public round number.
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#include "kci_internal.h"

/* Loop rotation sets (rho1, rho2, rho3, rho4); rho1, rho3 in {8,16,24}. Spec 4.3, D-018. */
const uint8_t kci_loop_rot[KCI_LOOPS][4] = {
    {24,  4,  8, 13},   /* 0: KCI, Trawler, Myr x2, Mox Opal */
    { 8, 11, 16, 25},   /* 1: KCI, Trawler, Spine, Mind Stone, Chromatic Star, Mox */
    { 8,  5, 16, 10},   /* 2: KCI, Trawler, Myr, Chromatic Star x2, Mox */
    {16,  3, 24, 31},   /* 3: KCI, Trawler, Myr, Chromatic Star, Mox */
    { 8, 29, 24, 10},   /* 4: KCI, Trawler x2, Myr, Mox */
    {24, 25, 16, 18},   /* 5: KCI, Trawler x2, Spine, Ichor Wellspring, Mox x2 */
    {16, 21, 24, 30},   /* 6: KCI, Trawler, Myr, Chromatic Sphere x2, Mox */
    { 8, 22, 16, 27},   /* 7: KCI, Trawler, Myr, Pyrite Spellbomb, Mox */
};

/* packed[s] = cd | mpil<<4 | msil<<8 | nmp<<12 | gat<<16 | tos<<20 | sos<<24 (vault: KCI-Loop-Model) */
const uint32_t kci_loop_packed[KCI_LOOPS] = {
    0x02253250u, 0x046a0aa1u, 0x04593691u, 0x03580771u,
    0x044a55a0u, 0x058d49d2u, 0x04493690u, 0x04490770u,
};

const uint32_t kci_stack_const[4] = { 0x2049434bu, 0x2d363532u, 0x20746962u, 0x706f6f6cu };
const uint32_t kci_deck_const[4]  = { 0x2049434bu, 0x66756873u, 0x20656c66u, 0x6b636564u };

/* Rotate by a (possibly secret) amount. Branch-free; compiles to rol/ror on x86 and ARM. */
static inline uint32_t rotl(uint32_t x, uint32_t n) {
    return (x << (n & 31u)) | (x >> ((32u - n) & 31u));
}

/* One round = four independent quarter-round "activations" A_rho(a, b, c, d) (spec 4.3):
 *   a += b; d ^= a; d <<<= r1;   c += d; b ^= c; b <<<= r2;
 *   a += b; d ^= a; d <<<= r3;   c += d; b ^= c; b <<<= r4;
 * The four activations are written step by step side by side. That is the same result (they touch
 * disjoint words), but each secret rotation count is used four times in a row, which keeps x86 from
 * reloading the count register for every rotation. */
#define STEP(A0,B0,D0, A1,B1,D1, A2,B2,D2, A3,B3,D3, R)          \
    A0 += B0; D0 ^= A0; D0 = rotl(D0, R);                         \
    A1 += B1; D1 ^= A1; D1 = rotl(D1, R);                         \
    A2 += B2; D2 ^= A2; D2 = rotl(D2, R);                         \
    A3 += B3; D3 ^= A3; D3 = rotl(D3, R);

#define ROUND(a0,b0,c0,d0, a1,b1,c1,d1, a2,b2,c2,d2, a3,b3,c3,d3)        \
    do {                                                                 \
        STEP(a0,b0,d0, a1,b1,d1, a2,b2,d2, a3,b3,d3, r1)                 \
        STEP(c0,d0,b0, c1,d1,b1, c2,d2,b2, c3,d3,b3, r2)                 \
        STEP(a0,b0,d0, a1,b1,d1, a2,b2,d2, a3,b3,d3, r3)                 \
        STEP(c0,d0,b0, c1,d1,b1, c2,d2,b2, c3,d3,b3, r4)                 \
    } while (0)

void kci_core(uint32_t out[16], const uint32_t in[16],
              const uint8_t rot[][4], const uint32_t rc[], int rounds)
{
    uint32_t x0 = in[0], x1 = in[1], x2 = in[2], x3 = in[3];
    uint32_t x4 = in[4], x5 = in[5], x6 = in[6], x7 = in[7];
    uint32_t x8 = in[8], x9 = in[9], x10 = in[10], x11 = in[11];
    uint32_t x12 = in[12], x13 = in[13], x14 = in[14], x15 = in[15];

#define LOAD_ROT(r) const uint32_t r1 = rot[r][0], r2 = rot[r][1], r3 = rot[r][2], r4 = rot[r][3]
#define COLUMN   ROUND(x0,x4,x8,x12, x1,x5,x9,x13, x2,x6,x10,x14, x3,x7,x11,x15)
#define DIAGONAL ROUND(x0,x5,x10,x15, x1,x6,x11,x12, x2,x7,x8,x13, x3,x4,x9,x14)

    int r = 0;
    /* main path: 4 rounds per iteration, so the round-constant target S[r & 3] and the
     * column/diagonal pattern are fixed in the code (KCI-20 = 5 iterations) */
    for (; r + 4 <= rounds; r += 4) {
        { LOAD_ROT(r);     x0 ^= rc[r];     COLUMN;   }
        { LOAD_ROT(r + 1); x1 ^= rc[r + 1]; DIAGONAL; }
        { LOAD_ROT(r + 2); x2 ^= rc[r + 2]; COLUMN;   }
        { LOAD_ROT(r + 3); x3 ^= rc[r + 3]; DIAGONAL; }
    }
    /* tail for reduced-round analysis builds (rounds not a multiple of 4); r is public */
    for (; r < rounds; r++) {
        LOAD_ROT(r);
        switch (r & 3) {
        case 0: x0 ^= rc[r]; break;
        case 1: x1 ^= rc[r]; break;
        case 2: x2 ^= rc[r]; break;
        default: x3 ^= rc[r]; break;
        }
        if ((r & 1) == 0) COLUMN; else DIAGONAL;
    }

    out[0] = x0 + in[0];   out[1] = x1 + in[1];   out[2] = x2 + in[2];   out[3] = x3 + in[3];
    out[4] = x4 + in[4];   out[5] = x5 + in[5];   out[6] = x6 + in[6];   out[7] = x7 + in[7];
    out[8] = x8 + in[8];   out[9] = x9 + in[9];   out[10] = x10 + in[10]; out[11] = x11 + in[11];
    out[12] = x12 + in[12]; out[13] = x13 + in[13]; out[14] = x14 + in[14]; out[15] = x15 + in[15];
}

void kci_block_words(uint8_t out[KCI_BLOCK_BYTES], const kci_key *k, uint32_t ctr,
                     const uint32_t nonce[3], uint32_t scratch[32])
{
    uint32_t *in = scratch, *w = scratch + 16;
    for (int i = 0; i < 4; i++) in[i] = k->c[i];
    for (int i = 0; i < 8; i++) in[4 + i] = k->k[i];
    in[12] = ctr;
    for (int i = 0; i < 3; i++) in[13 + i] = nonce[i];
    kci_core(w, in, k->rot, k->rc, KCI_ROUNDS);
    for (int i = 0; i < 16; i++) kci_store32(out + 4 * i, w[i]);
}

void kci_block(uint8_t out[KCI_BLOCK_BYTES], const kci_key *k, uint32_t ctr,
               const uint8_t nonce[KCI_NONCE_BYTES])
{
    uint32_t scratch[32], n[3];
    for (int i = 0; i < 3; i++) n[i] = kci_load32(nonce + 4 * i);
    kci_block_words(out, k, ctr, n, scratch);
    kci_wipe(scratch, sizeof scratch);
}
