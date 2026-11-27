/* Raw stream mode: counter-mode keystream XOR (spec 5).
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#include "kci_internal.h"

#define KCI_CTR_END ((uint64_t)1 << 32)   /* counters run up to 2^32 - 1 inclusive */

void kci_stream_init(kci_stream *s, const kci_key *k, const uint8_t nonce[KCI_NONCE_BYTES], uint32_t ctr0)
{
    s->key = *k;
    for (int i = 0; i < 3; i++) s->nonce[i] = kci_load32(nonce + 4 * i);
    s->next_ctr = ctr0;
    s->used = KCI_BLOCK_BYTES;
}

/* Raw mode (spec v0.3 section 5): same key and deck, raw-mode stack constants, counters from 1. */
void kci_raw_init(kci_stream *s, const kci_key *k, const uint8_t nonce[KCI_NONCE_BYTES])
{
    kci_stream_init(s, k, nonce, 1);
    for (int i = 0; i < 4; i++) s->key.c[i] = kci_raw_const[i];
}


int kci_stream_xor(kci_stream *s, uint8_t *out, const uint8_t *in, size_t len)
{
    /* keystream still available: rest of the current block + all remaining counters */
    const uint64_t avail = (uint64_t)(KCI_BLOCK_BYTES - s->used)
                         + (KCI_CTR_END - s->next_ctr) * KCI_BLOCK_BYTES;
    if ((uint64_t)len > avail) return KCI_ERR_LIMIT;

    uint32_t scratch[32];                    /* block temporaries, wiped once per call */
    uint8_t  ks[KCI_BLOCK_BYTES];            /* local keystream for the full-block fast path */

    /* use up a partly consumed block first */
    if (s->used < KCI_BLOCK_BYTES && len > 0) {
        size_t take = KCI_BLOCK_BYTES - s->used;
        if (take > len) take = len;
        for (size_t i = 0; i < take; i++) out[i] = in[i] ^ s->buf[s->used + i];
        s->used += (uint32_t)take;
        out += take; in += take; len -= take;
    }
    /* full blocks straight through a local buffer (lets the compiler vectorise the XOR) */
    while (len >= KCI_BLOCK_BYTES) {
        kci_block_words(ks, &s->key, (uint32_t)s->next_ctr, s->nonce, scratch);
        s->next_ctr++;
        for (size_t i = 0; i < KCI_BLOCK_BYTES; i++) out[i] = in[i] ^ ks[i];
        out += KCI_BLOCK_BYTES; in += KCI_BLOCK_BYTES; len -= KCI_BLOCK_BYTES;
    }
    /* final partial block: keep the rest of its keystream for the next call */
    while (len > 0) {
        if (s->used == KCI_BLOCK_BYTES) {
            kci_block_words(s->buf, &s->key, (uint32_t)s->next_ctr, s->nonce, scratch);
            s->next_ctr++;
            s->used = 0;
        }
        size_t take = KCI_BLOCK_BYTES - s->used;
        if (take > len) take = len;
        for (size_t i = 0; i < take; i++) out[i] = in[i] ^ s->buf[s->used + i];
        s->used += (uint32_t)take;
        out += take; in += take; len -= take;
    }
    kci_wipe(scratch, sizeof scratch);
    kci_wipe(ks, sizeof ks);
    return KCI_OK;
}
