/* AEAD mode (spec 7): RFC 8439 section 2.8 composition with KCI-20 in place of ChaCha20.
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#include "kci_internal.h"

static const uint8_t zeros[16];

/* tag = Poly1305(otk, aad || pad16 || ct || pad16 || le64(aad_len) || le64(ct_len)), otk = block 0 */
static void compute_tag(uint8_t tag[KCI_TAG_BYTES], const uint8_t *ct, size_t len,
                        const uint8_t *aad, size_t aad_len,
                        const kci_key *k, const uint8_t nonce[KCI_NONCE_BYTES])
{
    uint8_t block0[KCI_BLOCK_BYTES], lens[16];
    kci_poly1305_state st;

    kci_block(block0, k, 0, nonce);
    kci_poly1305_init(&st, block0);                 /* first 32 bytes = one-time key */
    kci_wipe(block0, sizeof block0);

    if (aad_len) kci_poly1305_update(&st, aad, aad_len);
    kci_poly1305_update(&st, zeros, (16 - (aad_len & 15)) & 15);
    if (len) kci_poly1305_update(&st, ct, len);
    kci_poly1305_update(&st, zeros, (16 - (len & 15)) & 15);
    for (int i = 0; i < 8; i++) {
        lens[i]     = (uint8_t)((uint64_t)aad_len >> (8 * i));
        lens[8 + i] = (uint8_t)((uint64_t)len >> (8 * i));
    }
    kci_poly1305_update(&st, lens, sizeof lens);
    kci_poly1305_final(&st, tag);
}

static int crypt_body(uint8_t *out, const uint8_t *in, size_t len,
                      const kci_key *k, const uint8_t nonce[KCI_NONCE_BYTES])
{
    kci_stream s;
    kci_stream_init(&s, k, nonce, 1);
    int rc = len ? kci_stream_xor(&s, out, in, len) : KCI_OK;
    kci_stream_wipe(&s);
    return rc;
}

int kci_aead_encrypt(uint8_t *ct, uint8_t tag[KCI_TAG_BYTES],
                     const uint8_t *pt, size_t len,
                     const uint8_t *aad, size_t aad_len,
                     const kci_key *k, const uint8_t nonce[KCI_NONCE_BYTES])
{
    if ((uint64_t)len > KCI_MAX_MSG_BYTES) return KCI_ERR_LIMIT;
    int rc = crypt_body(ct, pt, len, k, nonce);
    if (rc != KCI_OK) return rc;
    compute_tag(tag, ct, len, aad, aad_len, k, nonce);
    return KCI_OK;
}

int kci_aead_decrypt(uint8_t *pt, const uint8_t *ct, size_t len,
                     const uint8_t tag[KCI_TAG_BYTES],
                     const uint8_t *aad, size_t aad_len,
                     const kci_key *k, const uint8_t nonce[KCI_NONCE_BYTES])
{
    uint8_t expect[KCI_TAG_BYTES];
    if ((uint64_t)len > KCI_MAX_MSG_BYTES) return KCI_ERR_LIMIT;
    compute_tag(expect, ct, len, aad, aad_len, k, nonce);
    int bad = kci_ct_memcmp(expect, tag, KCI_TAG_BYTES);
    kci_wipe(expect, sizeof expect);
    if (bad) return KCI_ERR_AUTH;                  /* nothing released */
    return crypt_body(pt, ct, len, k, nonce);
}

int kci_ct_memcmp(const void *a, const void *b, size_t n)
{
    const volatile uint8_t *x = (const volatile uint8_t *)a, *y = (const volatile uint8_t *)b;
    uint32_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint32_t)(x[i] ^ y[i]);
    /* 0 -> 0, nonzero -> -1, without a data-dependent branch */
    return (int)((uint32_t)0 - ((d | (0u - d)) >> 31)) ;
}
