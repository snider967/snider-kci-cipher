/* Shared by the analysis tools: schedules, the reduced-round permutation and the single-bit differential bias measurement.
 * See kci_diffbias.c for the method. Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#ifndef KCI_ANALYSIS_COMMON_H
#define KCI_ANALYSIS_COMMON_H
#include "../../src/core/kci_internal.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NIN  128               /* input bits under attacker control: words 12..15 */
#define NOUT 512

typedef struct { uint8_t rot[KCI_ROUNDS][4]; uint32_t rc[KCI_ROUNDS]; uint32_t c[4]; } sched;

static inline uint64_t splitmix(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

/* schedule for a deck under any rotation table (the library's table, or a candidate one) */
static inline void sched_from_table(sched *S, const uint8_t table[KCI_LOOPS][4], const uint8_t deck[KCI_ROUNDS]) {
    for (int r = 0; r < KCI_ROUNDS; r++) {
        memcpy(S->rot[r], table[deck[r]], 4);
        S->rc[r] = kci_loop_packed[deck[r]] + (uint32_t)(r + 1) * KCI_PHI;
    }
    memcpy(S->c, kci_stack_const, sizeof S->c);
}

static inline void sched_from_deck(sched *S, const uint8_t deck[KCI_ROUNDS]) {
    for (int r = 0; r < KCI_ROUNDS; r++) {
        memcpy(S->rot[r], kci_loop_rot[deck[r]], 4);
        S->rc[r] = kci_loop_packed[deck[r]] + (uint32_t)(r + 1) * KCI_PHI;
    }
    memcpy(S->c, kci_stack_const, sizeof S->c);
}

static inline void sched_chacha(sched *S) {
    static const uint8_t cr[4] = {16, 12, 8, 7};
    static const uint32_t cc[4] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};
    for (int r = 0; r < KCI_ROUNDS; r++) { memcpy(S->rot[r], cr, 4); S->rc[r] = 0; }
    memcpy(S->c, cc, sizeof S->c);
}

/* P after `rounds` rounds = core output minus the feed-forward */
static inline void perm(uint32_t y[16], const uint32_t x[16], const sched *S, int rounds) {
    kci_core(y, x, (const uint8_t (*)[4])S->rot, S->rc, rounds);
    for (int i = 0; i < 16; i++) y[i] -= x[i];
}

typedef struct { double max_eps; int in_bit, out_bit, n_sig; } result;

/* max |eps| over the input bits in[0..nin-1] and all 512 output bits, N = 2^logn samples each */
static inline result measure(const sched *S, int rounds, int logn, const int *in, int nin, uint64_t seed) {
    const long n = 1L << logn;
    const double thresh = 6.0 / sqrt((double)n);
    result res = {0.0, -1, -1, 0};
    #pragma omp parallel for schedule(dynamic, 1)
    for (int t = 0; t < nin; t++) {
        uint32_t cnt[NOUT];
        memset(cnt, 0, sizeof cnt);
        uint64_t rs = seed ^ (0x1000003ull * (uint64_t)(in[t] + 1));
        const int w = 12 + in[t] / 32, b = in[t] % 32;
        for (long i = 0; i < n; i++) {
            uint32_t x[16], x2[16], y[16], y2[16];
            memcpy(x, S->c, sizeof S->c);
            for (int j = 4; j < 16; j += 2) { uint64_t v = splitmix(&rs); x[j] = (uint32_t)v; x[j + 1] = (uint32_t)(v >> 32); }
            memcpy(x2, x, sizeof x);
            x2[w] ^= 1u << b;
            perm(y, x, S, rounds);
            perm(y2, x2, S, rounds);
            for (int j = 0; j < 16; j++) {
                uint32_t d = y[j] ^ y2[j];
                while (d) { cnt[32 * j + __builtin_ctz(d)]++; d &= d - 1; }
            }
        }
        double best = 0.0; int bo = -1, sig = 0;
        for (int o = 0; o < NOUT; o++) {
            double e = fabs(2.0 * (double)cnt[o] / (double)n - 1.0);
            if (e > thresh) sig++;
            if (e > best) { best = e; bo = o; }
        }
        #pragma omp critical
        {
            res.n_sig += sig;
            if (best > res.max_eps) { res.max_eps = best; res.in_bit = in[t]; res.out_bit = bo; }
        }
    }
    return res;
}

static inline void print_res(const char *name, int rounds, int logn, result r) {
    const double thresh = 6.0 / sqrt((double)(1L << logn));
    printf("%-22s r=%d  max|eps|=%.4f %s  (in w%d.b%02d -> out w%02d.b%02d)  significant pairs=%d\n",
           name, rounds, r.max_eps, r.max_eps > thresh ? "BIASED" : "random",
           12 + r.in_bit / 32, r.in_bit % 32, r.out_bit / 32, r.out_bit % 32, r.n_sig);
}

#endif
