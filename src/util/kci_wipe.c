/* Secure zeroing that the optimiser cannot remove.
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#include "kci/kci.h"

void kci_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

void kci_key_wipe(kci_key *k) { kci_wipe(k, sizeof *k); }
void kci_stream_wipe(kci_stream *s) { kci_wipe(s, sizeof *s); }
