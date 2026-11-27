/* Rotation-set search for KCI-20 spec v0.4 (draft, Q20), and checks of a rotation table.
 *
 * Why: the first analysis (vault/Security/Cryptanalysis-Notes.md) found that the 3-round single-bit differential bias
 * depends only on the first three loops of the deck, and that some v0.3 loops (0 and 4) and some mixtures of loops are
 * much weaker than ChaCha there. The 3-round bias is the starting point of the PNB attacks on reduced-round ChaCha.
 *
 * Criterion (the v0.4 filter): for EVERY deck start (s0, s1, s2) in 8^3 = 512, the 3-round max |eps| must not exceed
 * ChaCha's, measured with the same samples and seeds. The 3-round bias of a deck is fully determined by its start, so
 * checking all 512 starts covers every one of the 8^20 decks for this metric.
 *
 * Search (deterministic):
 *   Loops are filled in order 0..7. For loop s, first try the v0.3 set (keep what is already good), then candidates
 *   drawn from splitmix64 seeded with the loop's packed vector packed[s] (the 2023 KCI loop heritage, spec 4.3), under the
 *   spec 4.3 rules. A candidate is accepted when every start made of it and the loops accepted so far passes the criterion.
 *
 *   usage: build/kci_rotsearch starts|search|verify [log2_samples [tolerance]]
 *          starts: 3-round bias of all 512 starts of the v0.3 table; search: run the search and print the new table;
 *          verify: checks of the table compiled into V04 below. tolerance (default 1.0): the bar is tolerance x ChaCha's bias,
 *          which allows for the estimation noise when deciding whether to keep a v0.3 set.
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#include "analysis_common.h"

#define SEED3 0xC0FFEEull + 3          /* same seed as kci_diffbias for 3 rounds */

static int all[NIN];

static double bias_start(const uint8_t table[KCI_LOOPS][4], int a, int b, int c, int rounds, int logn) {
    uint8_t deck[KCI_ROUNDS];
    for (int r = 0; r < KCI_ROUNDS; r++) deck[r] = (uint8_t)((int[]){a, b, c}[r < 3 ? r : 2]);
    sched S;
    sched_from_table(&S, table, deck);
    return measure(&S, rounds, logn, all, NIN, SEED3 + (uint64_t)(rounds - 3)).max_eps;
}

static double chacha_bias(int rounds, int logn) {
    sched S;
    sched_chacha(&S);
    return measure(&S, rounds, logn, all, NIN, SEED3 + (uint64_t)(rounds - 3)).max_eps;
}

/* spec 4.3 rules */
static int valid(const uint8_t p[4]) {
    if (p[0] % 8 || p[2] % 8 || p[0] == p[2] || p[0] < 8 || p[0] > 24 || p[2] < 8 || p[2] > 24) return 0;
    if (p[1] % 8 == 0 || p[3] % 8 == 0 || p[1] == p[3] || p[1] > 31 || p[3] > 31) return 0;
    return (p[1] | p[3]) & 1;
}

/* all 512 starts: distribution, worst, worst per loop */
static void table_starts(const uint8_t table[KCI_LOOPS][4], int logn, double t, int worst_start[3]) {
    double worst = 0, per_loop[KCI_LOOPS] = {0};
    int wa = 0, wb = 0, wc = 0, over = 0, hist[8] = {0};
    for (int a = 0; a < 8; a++) for (int b = 0; b < 8; b++) for (int c = 0; c < 8; c++) {
        double e = bias_start(table, a, b, c, 3, logn);
        if (e > t) over++;
        int h = (int)(e / 0.1); hist[h > 7 ? 7 : h]++;
        if (e > worst) { worst = e; wa = a; wb = b; wc = c; }
        if (e > per_loop[a]) per_loop[a] = e;
        if (e > per_loop[b]) per_loop[b] = e;
        if (e > per_loop[c]) per_loop[c] = e;
    }
    if (worst_start) { worst_start[0] = wa; worst_start[1] = wb; worst_start[2] = wc; }
    printf("  starts above the bar (%.4f): %d of 512; worst start (%d,%d,%d) = %.4f\n", t, over, wa, wb, wc, worst);
    printf("  histogram of 3-round max|eps|:");
    for (int h = 0; h < 8; h++) printf("  %.1f-%.1f: %d", h / 10.0, h == 7 ? 1.0 : (h + 1) / 10.0, hist[h]);
    printf("\n  worst start containing each loop:");
    for (int s = 0; s < KCI_LOOPS; s++) printf("  %d: %.3f", s, per_loop[s]);
    printf("\n");
}

static const uint8_t V03[KCI_LOOPS][4] = {
    {24, 4, 8, 13}, {8, 11, 16, 25}, {8, 5, 16, 10}, {16, 3, 24, 31},
    {8, 29, 24, 10}, {24, 25, 16, 18}, {16, 21, 24, 30}, {8, 22, 16, 27},
};
/* the search result (filled in after running `search`; see the spec v0.4 draft) */
static const uint8_t V04[KCI_LOOPS][4] = {   /* `search 14` (strict, tolerance 1.0), 2026-11-27 */
    {16, 3, 24, 27}, {8, 11, 16, 25}, {8, 5, 16, 10}, {8, 13, 16, 2},
    {8, 14, 24, 17}, {8, 3, 16, 14}, {8, 4, 16, 25}, {8, 12, 16, 1},
};

/* does every start built from loops 0..s (with loop s = cand) pass? Constant start first: it fails most often. */
static int accept(uint8_t table[KCI_LOOPS][4], int s, const uint8_t cand[4], int logn, double t, double *worst) {
    memcpy(table[s], cand, 4);
    *worst = bias_start((const uint8_t (*)[4])table, s, s, s, 3, logn);
    if (*worst > t) return 0;
    for (int a = 0; a <= s; a++) for (int b = 0; b <= s; b++) for (int c = 0; c <= s; c++) {
        if ((a != s && b != s && c != s) || (a == s && b == s && c == s)) continue;
        double e = bias_start((const uint8_t (*)[4])table, a, b, c, 3, logn);
        if (e > *worst) *worst = e;
        if (e > t) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "starts";
    const int logn = argc > 2 ? atoi(argv[2]) : 14;
    const double tol = argc > 3 ? atof(argv[3]) : 1.0;      /* bar = tol x ChaCha's bias */
    for (int i = 0; i < NIN; i++) all[i] = i;
    const double t = tol * chacha_bias(3, logn);
    printf("# KCI-20 rotation search, mode %s, N = 2^%d; bar = %.2f x ChaCha's 3-round max|eps| = %.4f\n", mode, logn, tol, t);

    if (strcmp(mode, "starts") == 0) {
        printf("\n## v0.3 table, all 512 starts\n");
        table_starts(V03, logn, t, NULL);
        return 0;
    }
    if (strcmp(mode, "search") == 0) {
        uint8_t table[KCI_LOOPS][4];
        memset(table, 0, sizeof table);
        for (int s = 0; s < KCI_LOOPS; s++) {
            double w;
            if (accept(table, s, V03[s], logn, t, &w)) {
                printf("  loop %d: kept v0.3 set {%d,%d,%d,%d}, worst start %.4f\n", s, V03[s][0], V03[s][1], V03[s][2], V03[s][3], w);
                continue;
            }
            printf("  loop %d: v0.3 set {%d,%d,%d,%d} fails (%.4f); searching\n", s, V03[s][0], V03[s][1], V03[s][2], V03[s][3], w);
            uint64_t seed = kci_loop_packed[s];
            int tried = 0, found = 0;
            while (!found && tried < 5000) {
                uint64_t v = splitmix(&seed);
                uint8_t c[4] = {(uint8_t)(8 * (1 + v % 3)), (uint8_t)(1 + (v >> 8) % 31),
                                (uint8_t)(8 * (1 + (v >> 16) % 3)), (uint8_t)(1 + (v >> 24) % 31)};
                if (!valid(c)) continue;
                int dup = 0;
                for (int j = 0; j < s; j++) dup |= memcmp(table[j], c, 4) == 0;
                if (dup) continue;
                tried++;
                if (accept(table, s, c, logn, t, &w)) {
                    printf("  loop %d: candidate %d {%d,%d,%d,%d} accepted, worst start %.4f\n", s, tried, c[0], c[1], c[2], c[3], w);
                    found = 1;
                }
            }
            if (!found) { printf("  loop %d: no candidate in %d passed; stop\n", s, tried); return 1; }
        }
        printf("\n## new table\n");
        for (int s = 0; s < KCI_LOOPS; s++) printf("  {%d, %d, %d, %d},\n", table[s][0], table[s][1], table[s][2], table[s][3]);
        printf("\n## new table, all 512 starts\n");
        table_starts((const uint8_t (*)[4])table, logn, t, NULL);
        return 0;
    }
    if (strcmp(mode, "verify") == 0) {
        if (V04[1][0] == 0) { printf("V04 is not filled in yet\n"); return 1; }
        printf("\n## v0.4 table, all 512 starts\n");
        int ws[3];
        table_starts(V04, logn, t, ws);
        printf("\n## worst start (%d,%d,%d) at 4 rounds, N = 2^%d\n", ws[0], ws[1], ws[2], logn + 6);
        printf("  r=4 max|eps| = %.4f (threshold %.4f); ChaCha r=4 = %.4f\n", bias_start(V04, ws[0], ws[1], ws[2], 4, logn + 6),
               6.0 / sqrt((double)(1L << (logn + 6))), chacha_bias(4, logn + 6));
        printf("\n## v0.4 constant decks, 4 rounds (N = 2^%d)\n", logn);
        for (int s = 0; s < KCI_LOOPS; s++)
            printf("  loop %d x20: r=4 max|eps| = %.4f (threshold %.4f)\n", s, bias_start(V04, s, s, s, 4, logn), 6.0 / sqrt((double)(1L << logn)));
        printf("  chacha:      r=4 max|eps| = %.4f\n", chacha_bias(4, logn));
        return 0;
    }
    fprintf(stderr, "usage: kci_rotsearch starts|search|verify [log2_samples]\n");
    return 2;
}
