/* Reduced-round differential bias of the KCI-20 permutation (spec v0.3 section 12, items 1 and 2).
 *
 * The test is the single-bit truncated differential used against Salsa/ChaCha by Aumasson et al. (FSE 2008).
 * Flip one bit of the attacker-controlled input (counter or nonce, state words 12..15), run r rounds of the
 * permutation P (the core without the feed-forward), and measure for every output bit j
 *     eps = 2 * Pr[bit j of P(x) ^ P(x')] - 1.
 * The key words are random for every sample. A large |eps| after r rounds is a distinguisher on r rounds and the
 * starting point of PNB-style key-recovery attacks on about r + 2 or r + 3 rounds.
 *
 * Estimation noise: the standard error of eps is 1/sqrt(N). Over the 128 x 512 = 65 536 (in, out) pairs the largest
 * noise value is about 4.6/sqrt(N), so a result counts as a real bias only above THRESH = 6/sqrt(N).
 *
 * This is evidence, not a proof: it finds single-bit biases only (no multi-bit differences, no linear masks).
 *
 *   build:  make analysis      (or see the Makefile)
 *   usage:  build/kci_diffbias [log2_samples [decks|deep]]   default 16; "decks" runs only section 4,
 *           "deep" runs the high-precision 4-round check; every run is deterministic (fixed seeds)
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#include "../../src/core/kci_internal.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NIN  128               /* input bits under attacker control: words 12..15 */
#define NOUT 512

typedef struct { uint8_t rot[KCI_ROUNDS][4]; uint32_t rc[KCI_ROUNDS]; uint32_t c[4]; } sched;

static uint64_t splitmix(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

static void sched_from_deck(sched *S, const uint8_t deck[KCI_ROUNDS]) {
    for (int r = 0; r < KCI_ROUNDS; r++) {
        memcpy(S->rot[r], kci_loop_rot[deck[r]], 4);
        S->rc[r] = kci_loop_packed[deck[r]] + (uint32_t)(r + 1) * KCI_PHI;
    }
    memcpy(S->c, kci_stack_const, sizeof S->c);
}

static void sched_chacha(sched *S) {
    static const uint8_t cr[4] = {16, 12, 8, 7};
    static const uint32_t cc[4] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};
    for (int r = 0; r < KCI_ROUNDS; r++) { memcpy(S->rot[r], cr, 4); S->rc[r] = 0; }
    memcpy(S->c, cc, sizeof S->c);
}

/* P after `rounds` rounds = core output minus the feed-forward */
static void perm(uint32_t y[16], const uint32_t x[16], const sched *S, int rounds) {
    kci_core(y, x, (const uint8_t (*)[4])S->rot, S->rc, rounds);
    for (int i = 0; i < 16; i++) y[i] -= x[i];
}

typedef struct { double max_eps; int in_bit, out_bit, n_sig; } result;

/* max |eps| over the input bits in[0..nin-1] and all 512 output bits, N = 2^logn samples each */
static result measure(const sched *S, int rounds, int logn, const int *in, int nin, uint64_t seed) {
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

static void print_res(const char *name, int rounds, int logn, result r) {
    const double thresh = 6.0 / sqrt((double)(1L << logn));
    printf("%-22s r=%d  max|eps|=%.4f %s  (in w%d.b%02d -> out w%02d.b%02d)  significant pairs=%d\n",
           name, rounds, r.max_eps, r.max_eps > thresh ? "BIASED" : "random",
           12 + r.in_bit / 32, r.in_bit % 32, r.out_bit / 32, r.out_bit % 32, r.n_sig);
}

/* first round count at which no significant bias is left (searching rounds lo..hi) */
static int clean_round(const sched *S, int lo, int hi, int logn, const int *in, int nin, double *eps_prev) {
    const double thresh = 6.0 / sqrt((double)(1L << logn));
    *eps_prev = 1.0;
    for (int r = lo; r <= hi; r++) {
        result x = measure(S, r, logn, in, nin, 0xC0FFEEull + (uint64_t)r);
        if (x.max_eps <= thresh) return r;
        *eps_prev = x.max_eps;
    }
    return hi + 1;
}

int main(int argc, char **argv) {
    const int logn = argc > 1 ? atoi(argv[1]) : 16;
    const int only_decks = argc > 2 && strcmp(argv[2], "decks") == 0;   /* run section 4 only */
    int all[NIN];
    for (int i = 0; i < NIN; i++) all[i] = i;
    int sub[16];                                /* screening subset: 4 bits from each attacker word */
    for (int i = 0; i < 16; i++) sub[i] = 32 * (i / 4) + (int[]){0, 7, 13, 31}[i % 4];
    sched S;
    uint8_t deck[KCI_ROUNDS];

    printf("# KCI-20 single-bit differential bias, N = 2^%d samples per input bit, threshold %.4f\n",
           logn, 6.0 / sqrt((double)(1L << logn)));

    if (argc > 2 && strcmp(argv[2], "deep") == 0) {
        /* 4-round check at high precision: all 32 bits of the input word that carries the strongest 3-round bias */
        static const uint8_t worst_deck[KCI_ROUNDS] = {4,4,7,2,3,7,7,4,2,6,4,5,6,7,2,6,7,6,7,4};  /* section 4, 2^18 run */
        const char *names[3] = {"chacha", "loop 0 x20", "deck 4,4,7,2,..."};
        for (int c = 0; c < 3; c++) {
            if (c == 0) sched_chacha(&S);
            else if (c == 1) { memset(deck, 0, sizeof deck); sched_from_deck(&S, deck); }
            else sched_from_deck(&S, worst_deck);
            result r3 = measure(&S, 3, 16, all, NIN, 0xC0FFEEull + 3);
            int word[32];
            for (int i = 0; i < 32; i++) word[i] = 32 * (r3.in_bit / 32) + i;
            print_res(names[c], 3, 16, r3);
            print_res(names[c], 4, logn, measure(&S, 4, logn, word, 32, 0xD33Bull));
        }
        return 0;
    }
    if (only_decks) goto random_decks;
    printf("\n## 1. Baseline: ChaCha rotations and constants, no round constants\n");
    sched_chacha(&S);
    for (int r = 2; r <= 5; r++) print_res("chacha", r, logn, measure(&S, r, logn, all, NIN, 0xC0FFEEull + (uint64_t)r));

    printf("\n## 2. Constant decks (one loop for all 20 rounds)\n");
    for (int s = 0; s < KCI_LOOPS; s++) {
        char name[32];
        snprintf(name, sizeof name, "loop %d x20 {%d,%d,%d,%d}", s, kci_loop_rot[s][0], kci_loop_rot[s][1],
                 kci_loop_rot[s][2], kci_loop_rot[s][3]);
        memset(deck, s, sizeof deck);
        sched_from_deck(&S, deck);
        for (int r = 2; r <= 5; r++) print_res(name, r, logn, measure(&S, r, logn, all, NIN, 0xC0FFEEull + (uint64_t)r));
    }

    printf("\n## 3. Alternating pairs (s, t, s, t, ...): rounds until clean, screening subset of 16 input bits\n");
    int worst_pair_r = 0;
    for (int s = 0; s < KCI_LOOPS; s++) {
        printf("  s=%d:", s);
        for (int t = 0; t < KCI_LOOPS; t++) {
            for (int r = 0; r < KCI_ROUNDS; r++) deck[r] = (uint8_t)((r & 1) ? t : s);
            sched_from_deck(&S, deck);
            double e;
            int cr = clean_round(&S, 3, 7, logn - 2, sub, 16, &e);
            if (cr > worst_pair_r) worst_pair_r = cr;
            printf(" t%d:%d", t, cr);
        }
        printf("\n");
    }
    printf("  worst alternating pair is clean from round %d\n", worst_pair_r);

random_decks:
    printf("\n## 4. Random decks from random keys (real key setup): rounds until clean, screening subset\n");
    int hist[10] = {0};
    uint64_t ks = 0xDEC0DEull;
    int worst_r = 0; double worst_e = 0.0; uint8_t worst[KCI_ROUNDS] = {0};
    const int ndecks = 400;
    for (int k = 0; k < ndecks; k++) {
        uint8_t key[32];
        for (int i = 0; i < 32; i += 8) { uint64_t v = splitmix(&ks); memcpy(key + i, &v, 8); }
        kci_shuffle_deck(deck, key);
        sched_from_deck(&S, deck);
        double e;
        int cr = clean_round(&S, 3, 7, logn - 2, sub, 16, &e);
        hist[cr]++;
        /* worst = needs the most rounds; ties broken by the larger bias in its last biased round */
        if (cr > worst_r || (cr == worst_r && e > worst_e)) { worst_r = cr; worst_e = e; memcpy(worst, deck, sizeof worst); }
    }
    printf("  %d decks; first clean round histogram:", ndecks);
    for (int r = 3; r <= 8; r++) if (hist[r]) printf("  r%d: %d", r, hist[r]);
    printf("\n  worst deck (bias %.4f in round %d on the screening subset):", worst_e, worst_r - 1);
    for (int r = 0; r < KCI_ROUNDS; r++) printf(" %d", worst[r]);
    printf("\n");
    sched_from_deck(&S, worst);
    for (int r = 3; r <= 5; r++) print_res("worst random deck", r, logn, measure(&S, r, logn, all, NIN, 0xC0FFEEull + (uint64_t)r));
    return 0;
}
