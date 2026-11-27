/* Statistics of the KCI-20 deck (spec v0.3 section 4.2) and related-key behaviour (section 12, items 2 and 3).
 *
 *   1. Uniformity: each deck position, and each pair of adjacent positions, over many random keys (chi-square).
 *   2. Related keys: flip one key bit, compare the two decks. If the setup block works, the decks are independent:
 *      the number of equal positions is Binomial(20, 1/8) (mean 2.5, sd 1.479) for every key bit.
 *   3. Structured keys (all-zero, one bit set, repeated bytes, counting bytes): their decks must look random too.
 *   4. Full-cipher related-key avalanche: flip one key bit, compare kci_block outputs (deck changes as well).
 *   5. How often "weak-looking" decks occur (long runs of one loop, few distinct loops), observed vs ideal.
 *
 *   usage: build/kci_deckstats [log2_keys]      default 18; deterministic (fixed seeds)
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#include "../../src/core/kci_internal.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t splitmix(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}
static void rand_key(uint8_t key[32], uint64_t *s) {
    for (int i = 0; i < 32; i += 8) { uint64_t v = splitmix(s); memcpy(key + i, &v, 8); }
}
static int equal_positions(const uint8_t a[KCI_ROUNDS], const uint8_t b[KCI_ROUNDS]) {
    int e = 0;
    for (int r = 0; r < KCI_ROUNDS; r++) e += a[r] == b[r];
    return e;
}
static int longest_run(const uint8_t d[KCI_ROUNDS]) {
    int best = 1, cur = 1;
    for (int r = 1; r < KCI_ROUNDS; r++) { cur = d[r] == d[r - 1] ? cur + 1 : 1; if (cur > best) best = cur; }
    return best;
}
static int distinct(const uint8_t d[KCI_ROUNDS]) {
    int seen = 0;
    for (int r = 0; r < KCI_ROUNDS; r++) seen |= 1 << d[r];
    return __builtin_popcount((unsigned)seen);
}
/* p-value approximation for chi-square (Wilson-Hilferty), enough to flag gross non-uniformity */
static double chi2_z(double x, int df) {
    double k = df;
    return (pow(x / k, 1.0 / 3.0) - (1.0 - 2.0 / (9.0 * k))) / sqrt(2.0 / (9.0 * k));
}

int main(int argc, char **argv) {
    const int logk = argc > 1 ? atoi(argv[1]) : 18;
    const long nkeys = 1L << logk;
    uint64_t seed = 0x5EEDDECCull;
    uint8_t key[32], key2[32], d[KCI_ROUNDS], d2[KCI_ROUNDS];

    printf("# KCI-20 deck statistics, 2^%d random keys\n", logk);

    /* 1. uniformity, and the run / distinct-loop distributions */
    static long pos[KCI_ROUNDS][8], pair[KCI_ROUNDS - 1][64];
    long runs[KCI_ROUNDS + 1] = {0}, dist[9] = {0};
    for (long i = 0; i < nkeys; i++) {
        rand_key(key, &seed);
        kci_shuffle_deck(d, key);
        for (int r = 0; r < KCI_ROUNDS; r++) pos[r][d[r]]++;
        for (int r = 0; r + 1 < KCI_ROUNDS; r++) pair[r][d[r] * 8 + d[r + 1]]++;
        runs[longest_run(d)]++;
        dist[distinct(d)]++;
    }
    double worst_z1 = -99, worst_z2 = -99;
    for (int r = 0; r < KCI_ROUNDS; r++) {
        double e = nkeys / 8.0, x = 0;
        for (int s = 0; s < 8; s++) x += (pos[r][s] - e) * (pos[r][s] - e) / e;
        double z = chi2_z(x, 7);
        if (z > worst_z1) worst_z1 = z;
    }
    for (int r = 0; r + 1 < KCI_ROUNDS; r++) {
        double e = nkeys / 64.0, x = 0;
        for (int s = 0; s < 64; s++) x += (pair[r][s] - e) * (pair[r][s] - e) / e;
        double z = chi2_z(x, 63);
        if (z > worst_z2) worst_z2 = z;
    }
    printf("\n## 1. Uniformity\n");
    printf("  single positions (20 tests, df 7): largest chi-square z = %.2f\n", worst_z1);
    printf("  adjacent pairs   (19 tests, df 63): largest chi-square z = %.2f   (|z| < ~3 is consistent with uniform)\n", worst_z2);

    /* ideal distributions by simulation with an independent uniform source */
    long iruns[KCI_ROUNDS + 1] = {0}, idist[9] = {0};
    uint64_t is = 0x1DEA1ull;
    for (long i = 0; i < nkeys; i++) {
        uint64_t v = splitmix(&is);
        for (int r = 0; r < KCI_ROUNDS; r++) d[r] = (uint8_t)((v >> (3 * r)) & 7);
        iruns[longest_run(d)]++;
        idist[distinct(d)]++;
    }
    printf("\n## 5. Weak-looking decks: observed vs ideal uniform (per 2^%d keys)\n", logk);
    printf("  longest run of one loop:");
    for (int k = 1; k <= KCI_ROUNDS; k++) if (runs[k] || iruns[k]) printf("  %d: %ld/%ld", k, runs[k], iruns[k]);
    printf("\n  distinct loops in the deck:");
    for (int k = 1; k <= 8; k++) if (dist[k] || idist[k]) printf("  %d: %ld/%ld", k, dist[k], idist[k]);
    printf("\n");

    /* 2. single key-bit flips */
    printf("\n## 2. Related keys: one key bit flipped (2^%d keys x 256 bits)\n", logk - 6);
    const long nrk = nkeys >> 6;
    double worst_bit_z = 0; int worst_bit = -1;
    long hist[KCI_ROUNDS + 1] = {0};
    long total = 0, totsum = 0;
    for (int b = 0; b < 256; b++) {
        long sum = 0;
        uint64_t s2 = 0xB17F11Bull + (uint64_t)b;
        for (long i = 0; i < nrk; i++) {
            rand_key(key, &s2);
            memcpy(key2, key, 32);
            key2[b / 8] ^= (uint8_t)(1u << (b % 8));
            kci_shuffle_deck(d, key);
            kci_shuffle_deck(d2, key2);
            int e = equal_positions(d, d2);
            sum += e; hist[e]++;
        }
        total += nrk; totsum += sum;
        double mean = (double)sum / nrk, z = (mean - 2.5) / (sqrt(20 * (1.0 / 8) * (7.0 / 8)) / sqrt((double)nrk));
        if (fabs(z) > fabs(worst_bit_z)) { worst_bit_z = z; worst_bit = b; }
    }
    printf("  equal deck positions: mean %.4f (ideal 2.5000); worst key bit %d with z = %.2f over 256 bits (|z| < ~3.5 expected)\n",
           (double)totsum / total, worst_bit, worst_bit_z);
    printf("  histogram of equal positions (count / ideal Binomial(20,1/8)):\n   ");
    for (int e = 0; e <= 10; e++) {
        double p = 1; for (int i = 0; i < e; i++) p *= (20.0 - i) / (i + 1); p *= pow(1.0 / 8, e) * pow(7.0 / 8, 20 - e);
        printf(" %d:%ld/%.0f", e, hist[e], p * total);
    }
    printf("\n  identical decks after a 1-bit key change: %ld of %ld (ideal %.2g)\n", hist[20], total, total * pow(8, -20));

    /* 3. structured keys */
    printf("\n## 3. Structured keys\n");
    uint8_t decks[600][KCI_ROUNDS]; int nd = 0;
    memset(key, 0, 32); kci_shuffle_deck(decks[nd++], key);
    memset(key, 0xff, 32); kci_shuffle_deck(decks[nd++], key);
    for (int b = 0; b < 256; b++) { memset(key, 0, 32); key[b / 8] = (uint8_t)(1u << (b % 8)); kci_shuffle_deck(decks[nd++], key); }
    for (int v = 1; v < 255; v++) { memset(key, v, 32); kci_shuffle_deck(decks[nd++], key); }
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    kci_shuffle_deck(decks[nd++], key);
    printf("  zero key deck:   "); for (int r = 0; r < KCI_ROUNDS; r++) printf(" %d", decks[0][r]); printf("\n");
    printf("  0xff.. key deck: "); for (int r = 0; r < KCI_ROUNDS; r++) printf(" %d", decks[1][r]); printf("\n");
    printf("  00 01 .. 1f deck:"); for (int r = 0; r < KCI_ROUNDS; r++) printf(" %d", decks[nd - 1][r]); printf("\n");
    long cnt[8] = {0}, eqsum = 0, eqn = 0; int maxrun = 0, mindist = 9, maxeq = 0;
    for (int i = 0; i < nd; i++) {
        for (int r = 0; r < KCI_ROUNDS; r++) cnt[decks[i][r]]++;
        if (longest_run(decks[i]) > maxrun) maxrun = longest_run(decks[i]);
        if (distinct(decks[i]) < mindist) mindist = distinct(decks[i]);
        for (int j = 0; j < i; j++) { int e = equal_positions(decks[i], decks[j]); eqsum += e; eqn++; if (e > maxeq) maxeq = e; }
    }
    double x = 0, e = nd * 20.0 / 8;
    for (int s = 0; s < 8; s++) x += (cnt[s] - e) * (cnt[s] - e) / e;
    printf("  %d structured keys (zero, all-ones, 256 single-bit, 254 repeated-byte, counting):\n", nd);
    printf("    loop counts chi-square z = %.2f; longest run %d; fewest distinct loops %d\n", chi2_z(x, 7), maxrun, mindist);
    printf("    pairwise equal positions: mean %.4f (ideal 2.5), max %d over %ld pairs\n", (double)eqsum / eqn, maxeq, eqn);

    /* 4. full-cipher related-key avalanche: kci_block under K and K ^ e_b */
    printf("\n## 4. Full KCI-20 block, related keys (deck changes too): flip probability of each output bit\n");
    const long nav = nkeys >> 8;
    double worst = 0; int wb = -1, wo = -1;
    long minflip = 1 << 30, maxflip = 0;
    uint8_t nonce[12] = {0};
    for (int b = 0; b < 256; b++) {
        static long c[512];
        memset(c, 0, sizeof c);
        uint64_t s3 = 0xAB1Eull + (uint64_t)b;
        for (long i = 0; i < nav; i++) {
            kci_key k1, k2; uint8_t o1[64], o2[64];
            rand_key(key, &s3);
            memcpy(key2, key, 32);
            key2[b / 8] ^= (uint8_t)(1u << (b % 8));
            uint64_t v = splitmix(&s3); memcpy(nonce, &v, 8);
            kci_key_setup(&k1, key); kci_key_setup(&k2, key2);
            kci_block(o1, &k1, 1, nonce); kci_block(o2, &k2, 1, nonce);
            long fl = 0;
            for (int j = 0; j < 64; j++) {
                unsigned dd = (unsigned)(o1[j] ^ o2[j]);
                fl += __builtin_popcount(dd);
                while (dd) { c[8 * j + __builtin_ctz(dd)]++; dd &= dd - 1; }
            }
            if (fl < minflip) minflip = fl;
            if (fl > maxflip) maxflip = fl;
        }
        for (int o = 0; o < 512; o++) {
            double eps = fabs(2.0 * c[o] / nav - 1.0);
            if (eps > worst) { worst = eps; wb = b; wo = o; }
        }
    }
    printf("  2^%d keys per key bit; max |eps| = %.4f (key bit %d -> output bit %d); noise level for 131072 pairs ~ %.4f\n",
           logk - 8, worst, wb, wo, 4.9 / sqrt((double)nav));
    printf("  flipped output bits per pair: min %ld, max %ld (of 512)\n", minflip, maxflip);
    return 0;
}
