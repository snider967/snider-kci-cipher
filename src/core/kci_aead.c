/* AEAD mode (spec 7): RFC 8439 section 2.8 composition with KCI-20 in place of ChaCha20.
 * Streaming API plus one-shot wrappers. The one-shot decrypt verifies before it writes anything.
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#include "kci_internal.h"

static const uint8_t zeros[16];

void kci_aead_init(kci_aead_ctx *c, const kci_key *k, const uint8_t nonce[KCI_NONCE_BYTES],
                   const uint8_t *aad, size_t aad_len)
{
    uint8_t block0[KCI_BLOCK_BYTES];
    kci_block(block0, k, 0, nonce);                 /* counter 0 -> Poly1305 one-time key */
    kci_poly1305_init(&c->mac, block0);
    kci_wipe(block0, sizeof block0);

    if (aad_len) kci_poly1305_update(&c->mac, aad, aad_len);
    kci_poly1305_update(&c->mac, zeros, (16 - (aad_len & 15)) & 15);
    kci_stream_init(&c->stream, k, nonce, 1);       /* message keystream starts at counter 1 */
    c->aad_len = aad_len;
    c->len = 0;
}

static int room_for(const kci_aead_ctx *c, size_t len)
{
    return (uint64_t)len <= KCI_MAX_MSG_BYTES - c->len;
}

int kci_aead_encrypt_update(kci_aead_ctx *c, uint8_t *ct, const uint8_t *pt, size_t len)
{
    if (!room_for(c, len)) return KCI_ERR_LIMIT;
    if (len == 0) return KCI_OK;
    int rc = kci_stream_xor(&c->stream, ct, pt, len);
    if (rc != KCI_OK) return rc;
    kci_poly1305_update(&c->mac, ct, len);
    c->len += len;
    return KCI_OK;
}

int kci_aead_decrypt_update(kci_aead_ctx *c, uint8_t *pt, const uint8_t *ct, size_t len)
{
    if (!room_for(c, len)) return KCI_ERR_LIMIT;
    if (len == 0) return KCI_OK;
    kci_poly1305_update(&c->mac, ct, len);          /* MAC the ciphertext before ct may be overwritten in place */
    c->len += len;
    return kci_stream_xor(&c->stream, pt, ct, len);
}

static void finish_tag(kci_aead_ctx *c, uint8_t tag[KCI_TAG_BYTES])
{
    uint8_t lens[16];
    kci_poly1305_update(&c->mac, zeros, (size_t)((16 - (c->len & 15)) & 15));
    for (int i = 0; i < 8; i++) {
        lens[i]     = (uint8_t)(c->aad_len >> (8 * i));
        lens[8 + i] = (uint8_t)(c->len >> (8 * i));
    }
    kci_poly1305_update(&c->mac, lens, sizeof lens);
    kci_poly1305_final(&c->mac, tag);
    kci_wipe(c, sizeof *c);
}

void kci_aead_encrypt_final(kci_aead_ctx *c, uint8_t tag[KCI_TAG_BYTES])
{
    finish_tag(c, tag);
}

int kci_aead_decrypt_final(kci_aead_ctx *c, const uint8_t tag[KCI_TAG_BYTES])
{
    uint8_t expect[KCI_TAG_BYTES];
    finish_tag(c, expect);
    int bad = kci_ct_memcmp(expect, tag, KCI_TAG_BYTES);
    kci_wipe(expect, sizeof expect);
    return bad ? KCI_ERR_AUTH : KCI_OK;
}

/* ---------------- one-shot ---------------- */

int kci_aead_encrypt(uint8_t *ct, uint8_t tag[KCI_TAG_BYTES],
                     const uint8_t *pt, size_t len,
                     const uint8_t *aad, size_t aad_len,
                     const kci_key *k, const uint8_t nonce[KCI_NONCE_BYTES])
{
    kci_aead_ctx c;
    if ((uint64_t)len > KCI_MAX_MSG_BYTES) return KCI_ERR_LIMIT;
    kci_aead_init(&c, k, nonce, aad, aad_len);
    int rc = kci_aead_encrypt_update(&c, ct, pt, len);
    if (rc != KCI_OK) { kci_wipe(&c, sizeof c); return rc; }
    kci_aead_encrypt_final(&c, tag);
    return KCI_OK;
}

int kci_aead_decrypt(uint8_t *pt, const uint8_t *ct, size_t len,
                     const uint8_t tag[KCI_TAG_BYTES],
                     const uint8_t *aad, size_t aad_len,
                     const kci_key *k, const uint8_t nonce[KCI_NONCE_BYTES])
{
    kci_aead_ctx c;
    if ((uint64_t)len > KCI_MAX_MSG_BYTES) return KCI_ERR_LIMIT;

    /* pass 1: authenticate only, so nothing is released on failure */
    kci_aead_init(&c, k, nonce, aad, aad_len);
    if (len) kci_poly1305_update(&c.mac, ct, len);
    c.len = len;
    if (kci_aead_decrypt_final(&c, tag) != KCI_OK) return KCI_ERR_AUTH;

    /* pass 2: decrypt */
    kci_stream s;
    kci_stream_init(&s, k, nonce, 1);
    int rc = len ? kci_stream_xor(&s, pt, ct, len) : KCI_OK;
    kci_stream_wipe(&s);
    return rc;
}

int kci_ct_memcmp(const void *a, const void *b, size_t n)
{
    const volatile uint8_t *x = (const volatile uint8_t *)a, *y = (const volatile uint8_t *)b;
    uint32_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint32_t)(x[i] ^ y[i]);
    /* 0 -> 0, nonzero -> -1, without a data-dependent branch */
    return (int)((uint32_t)0 - ((d | (0u - d)) >> 31));
}
