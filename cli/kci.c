/* kci: command-line tool for KCI-20 files (file format v1, spec section 10 / D-022).
 *
 * WARNING: KCI-20 is original, unreviewed cryptography. For research and fun; do not protect real data with it.
 *
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kci/kci.h"
#include "platform.h"

#define KCI_VERSION       "0.4.0"
#define HDR_BYTES         40
#define FORMAT_VERSION    2      /* "KCI\x02" = KCI-20 v0.4 (D-028); format 1 was v0.3 */
#define MODE_AEAD         0
#define MODE_RAW          1
#define KDF_NONE          0
#define KDF_PBKDF2        1
#define KDF_MAX_ITER      100000000u      /* refuse absurd costs from a hostile header */
#define CHUNK             (64 * 1024)
#define PW_CAP            1024

enum { EXIT_OK = 0, EXIT_ERR = 1, EXIT_AUTH = 2 };

static const char *prog = "kci";

static void usage(FILE *o)
{
    fprintf(o,
        "kci " KCI_VERSION " - KCI-20 file encryption (EXPERIMENTAL, unreviewed: do not protect real data)\n\n"
        "usage:\n"
        "  kci enc [key options] [-i ITER] [--raw] [-f] IN OUT   encrypt IN to OUT\n"
        "  kci dec [key options] [--raw] [-f] IN OUT             decrypt IN to OUT\n"
        "  kci keygen [-f] KEYFILE                               write a random 32-byte key file\n"
        "  kci selftest                                          run built-in known-answer tests\n"
        "  kci bench                                             measure speed\n\n"
        "key options (default: prompt for a password):\n"
        "  -k, --key-file FILE        use a 32-byte key file instead of a password\n"
        "  --password-file FILE       read the password from the first line of FILE\n"
        "other options:\n"
        "  -i, --iterations N         PBKDF2 iterations for enc (default %u, minimum %u)\n"
        "  --raw                      enc: no integrity check (malleable; experiments only)\n"
        "                             dec: required to accept a raw-mode file\n"
        "  -f, --force                overwrite OUT / KEYFILE if it exists\n",
        KCI_KDF_DEFAULT_ITERATIONS, KCI_KDF_MIN_ITERATIONS);
}

static int fail(const char *msg, const char *arg)
{
    if (arg) fprintf(stderr, "%s: %s: %s\n", prog, msg, arg);
    else     fprintf(stderr, "%s: %s\n", prog, msg);
    return EXIT_ERR;
}

static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

/* ---------------- options ---------------- */

typedef struct {
    const char *key_file, *pw_file, *in, *out;
    uint32_t iterations;
    int raw, force;
} opts_t;

static int parse(int argc, char **argv, int first, opts_t *o, int npos, const char **pos)
{
    int got = 0;
    memset(o, 0, sizeof *o);
    o->iterations = KCI_KDF_DEFAULT_ITERATIONS;
    for (int i = first; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-k") || !strcmp(a, "--key-file")) {
            if (++i >= argc) return fail("missing value for", a);
            o->key_file = argv[i];
        } else if (!strcmp(a, "--password-file")) {
            if (++i >= argc) return fail("missing value for", a);
            o->pw_file = argv[i];
        } else if (!strcmp(a, "-i") || !strcmp(a, "--iterations")) {
            if (++i >= argc) return fail("missing value for", a);
            char *end; unsigned long v = strtoul(argv[i], &end, 10);
            if (*end || v > KDF_MAX_ITER) return fail("bad iteration count", argv[i]);
            o->iterations = (uint32_t)v;
        } else if (!strcmp(a, "--raw")) {
            o->raw = 1;
        } else if (!strcmp(a, "-f") || !strcmp(a, "--force")) {
            o->force = 1;
        } else if (a[0] == '-' && a[1]) {
            return fail("unknown option", a);
        } else {
            if (got >= npos) return fail("too many arguments", a);
            pos[got++] = a;
        }
    }
    if (got != npos) { usage(stderr); return EXIT_ERR; }
    if (o->key_file && o->pw_file) return fail("use either a key file or a password file, not both", NULL);
    return EXIT_OK;
}

/* ---------------- key material ---------------- */

static int read_key_file(const char *path, uint8_t key[KCI_KEY_BYTES])
{
    uint8_t extra;
    FILE *f = fopen(path, "rb");
    if (!f) return fail("cannot open key file", path);
    size_t n = fread(key, 1, KCI_KEY_BYTES, f);
    size_t m = fread(&extra, 1, 1, f);
    fclose(f);
    if (n != KCI_KEY_BYTES || m != 0) { memset(key, 0, KCI_KEY_BYTES); return fail("key file must be exactly 32 bytes", path); }
    return EXIT_OK;
}

static int read_password_file(const char *path, char *pw, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return fail("cannot open password file", path);
    size_t n = fread(pw, 1, cap - 1, f);
    fclose(f);
    pw[n] = '\0';
    char *nl = memchr(pw, '\n', n);
    if (nl) n = (size_t)(nl - pw);
    else if (n == cap - 1) return fail("password file line too long", path);
    if (n && pw[n - 1] == '\r') n--;
    pw[n] = '\0';
    *len = n;
    return EXIT_OK;
}

/* Get the password: from --password-file, or prompted (twice when confirm is set). */
static int get_password(const opts_t *o, int confirm, char *pw, size_t *len)
{
    if (o->pw_file) {
        if (read_password_file(o->pw_file, pw, PW_CAP, len)) return EXIT_ERR;
    } else {
        int n = plat_read_password("Password: ", pw, PW_CAP);
        if (n < 0) return fail("cannot read a password from the terminal (use --password-file or -k)", NULL);
        *len = (size_t)n;
        if (confirm) {
            char again[PW_CAP];
            int m = plat_read_password("Repeat password: ", again, sizeof again);
            int same = m == n && memcmp(pw, again, (size_t)n) == 0;
            kci_wipe(again, sizeof again);
            if (!same) return fail("passwords do not match", NULL);
        }
    }
    if (*len == 0) return fail("empty password refused", NULL);
    return EXIT_OK;
}

/* ---------------- temp output ---------------- */

typedef struct { char path[4096 + 32]; FILE *f; } tmpout_t;

static int tmp_open(tmpout_t *t, const char *final_path)
{
    uint8_t r[8];
    if (strlen(final_path) > 4096) return fail("output path too long", final_path);
    if (plat_random(r, sizeof r)) return fail("OS random number generator failed", NULL);
    snprintf(t->path, sizeof t->path, "%s.kci-tmp-%02x%02x%02x%02x%02x%02x%02x%02x",
             final_path, r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
    t->f = plat_create_private(t->path);
    if (!t->f) return fail("cannot create temporary output file", t->path);
    return EXIT_OK;
}

static void tmp_discard(tmpout_t *t)
{
    if (t->f) { fclose(t->f); t->f = NULL; }
    remove(t->path);
}

static int tmp_commit(tmpout_t *t, const char *final_path)
{
    int bad = ferror(t->f) != 0;
    bad |= fclose(t->f) != 0;
    t->f = NULL;
    if (bad) { remove(t->path); return fail("write error", final_path); }
    if (plat_rename(t->path, final_path)) { remove(t->path); return fail("cannot move output into place", final_path); }
    return EXIT_OK;
}

/* ---------------- enc / dec ---------------- */

static uint8_t inbuf[CHUNK + KCI_TAG_BYTES], outbuf[CHUNK + KCI_TAG_BYTES];

static int cmd_enc(int argc, char **argv)
{
    opts_t o; const char *pos[2];
    if (parse(argc, argv, 2, &o, 2, pos)) return EXIT_ERR;
    o.in = pos[0]; o.out = pos[1];
    if (!o.force && plat_exists(o.out)) return fail("output exists (use -f to overwrite)", o.out);
    if (!o.key_file && o.iterations < KCI_KDF_MIN_ITERATIONS) return fail("iteration count below the minimum", NULL);
    if (o.raw) fprintf(stderr, "%s: warning: --raw gives no integrity check; changes to the file will go undetected\n", prog);

    uint8_t hdr[HDR_BYTES] = { 'K', 'C', 'I', FORMAT_VERSION }, key[KCI_KEY_BYTES], tag[KCI_TAG_BYTES];
    hdr[4] = o.raw ? MODE_RAW : MODE_AEAD;
    if (plat_random(hdr + 28, KCI_NONCE_BYTES)) return fail("OS random number generator failed", NULL);

    int rc = EXIT_ERR;
    if (o.key_file) {
        hdr[5] = KDF_NONE;
        if (read_key_file(o.key_file, key)) return EXIT_ERR;
    } else {
        char pw[PW_CAP]; size_t pwlen = 0;
        hdr[5] = KDF_PBKDF2;
        put32(hdr + 8, o.iterations);
        if (plat_random(hdr + 12, KCI_KDF_SALT_BYTES)) return fail("OS random number generator failed", NULL);
        if (get_password(&o, 1, pw, &pwlen)) { kci_wipe(pw, sizeof pw); return EXIT_ERR; }
        int k = kci_kdf_password(key, (const uint8_t *)pw, pwlen, hdr + 12, KCI_KDF_SALT_BYTES, o.iterations);
        kci_wipe(pw, sizeof pw);
        if (k != KCI_OK) return fail("key derivation refused its parameters", NULL);
    }

    kci_key k; kci_aead_ctx a; kci_stream s; tmpout_t t = { "", NULL };
    kci_key_setup(&k, key);
    kci_wipe(key, sizeof key);

    FILE *in = fopen(o.in, "rb");
    if (!in) { fail("cannot open input", o.in); goto out; }
    if (tmp_open(&t, o.out)) goto out;
    if (fwrite(hdr, 1, HDR_BYTES, t.f) != HDR_BYTES) { fail("write error", o.out); goto out; }

    if (o.raw) kci_raw_init(&s, &k, hdr + 28);
    else       kci_aead_init(&a, &k, hdr + 28, hdr, HDR_BYTES);   /* the header is the AAD */
    for (;;) {
        size_t n = fread(inbuf, 1, CHUNK, in);
        if (n == 0) break;
        int r = o.raw ? kci_stream_xor(&s, outbuf, inbuf, n) : kci_aead_encrypt_update(&a, outbuf, inbuf, n);
        if (r != KCI_OK) { fail("input too large for one KCI-20 message (256 GiB limit)", o.in); goto out; }
        if (fwrite(outbuf, 1, n, t.f) != n) { fail("write error", o.out); goto out; }
    }
    if (ferror(in)) { fail("read error", o.in); goto out; }
    if (!o.raw) {
        kci_aead_encrypt_final(&a, tag);
        if (fwrite(tag, 1, KCI_TAG_BYTES, t.f) != KCI_TAG_BYTES) { fail("write error", o.out); goto out; }
    }
    rc = tmp_commit(&t, o.out);
out:
    if (rc != EXIT_OK && t.f) tmp_discard(&t);
    if (in) fclose(in);
    kci_key_wipe(&k); kci_wipe(&a, sizeof a); kci_stream_wipe(&s);
    kci_wipe(inbuf, sizeof inbuf); kci_wipe(outbuf, sizeof outbuf);
    return rc;
}

static int cmd_dec(int argc, char **argv)
{
    opts_t o; const char *pos[2];
    if (parse(argc, argv, 2, &o, 2, pos)) return EXIT_ERR;
    o.in = pos[0]; o.out = pos[1];
    if (!o.force && plat_exists(o.out)) return fail("output exists (use -f to overwrite)", o.out);

    uint8_t hdr[HDR_BYTES], key[KCI_KEY_BYTES];
    FILE *in = fopen(o.in, "rb");
    if (!in) return fail("cannot open input", o.in);
    if (fread(hdr, 1, HDR_BYTES, in) != HDR_BYTES || memcmp(hdr, "KCI", 3) != 0) {
        fclose(in); return fail("not a KCI-20 file", o.in);
    }
    if (hdr[3] != FORMAT_VERSION) {
        fclose(in);
        return fail(hdr[3] == 1 ? "file was made by KCI-20 v0.3 (format 1), which this version cannot decrypt"
                                : "unsupported KCI-20 file format version", o.in);
    }
    const int mode = hdr[4], kdf = hdr[5];
    const uint32_t iter = get32(hdr + 8);
    int zero_salt = 1;
    for (int i = 12; i < 28; i++) zero_salt &= hdr[i] == 0;
    if ((mode != MODE_AEAD && mode != MODE_RAW) || (kdf != KDF_NONE && kdf != KDF_PBKDF2) || hdr[6] || hdr[7] ||
        (kdf == KDF_NONE && (iter != 0 || !zero_salt))) {
        fclose(in); return fail("unsupported or corrupt header", o.in);
    }
    if (kdf == KDF_PBKDF2 && (iter < KCI_KDF_MIN_ITERATIONS || iter > KDF_MAX_ITER)) {
        fclose(in); return fail("header asks for an iteration count outside the accepted range", o.in);
    }
    if (kdf == KDF_NONE && !o.key_file) { fclose(in); return fail("this file was encrypted with a key file (use -k)", o.in); }
    if (kdf == KDF_PBKDF2 && o.key_file) { fclose(in); return fail("this file was encrypted with a password, not a key file", o.in); }
    /* A raw file is only accepted when the user asks for it. Otherwise flipping the mode byte of an AEAD file
     * would silently turn off authentication (a downgrade: raw and AEAD share the same ciphertext). */
    if (mode == MODE_RAW && !o.raw) {
        fclose(in);
        return fail("raw-mode file: it has no integrity check, so it may have been modified (or downgraded from an "
                    "authenticated file). Pass --raw to decrypt it anyway", o.in);
    }
    if (mode == MODE_RAW) fprintf(stderr, "%s: warning: raw-mode file: no integrity check, tampering cannot be detected\n", prog);

    if (kdf == KDF_NONE) {
        if (read_key_file(o.key_file, key)) { fclose(in); return EXIT_ERR; }
    } else {
        char pw[PW_CAP]; size_t pwlen = 0;
        if (get_password(&o, 0, pw, &pwlen)) { kci_wipe(pw, sizeof pw); fclose(in); return EXIT_ERR; }
        int r = kci_kdf_password(key, (const uint8_t *)pw, pwlen, hdr + 12, KCI_KDF_SALT_BYTES, iter);
        kci_wipe(pw, sizeof pw);
        if (r != KCI_OK) { fclose(in); return fail("key derivation refused its parameters", NULL); }
    }

    int rc = EXIT_ERR;
    kci_key k; kci_aead_ctx a; kci_stream s; tmpout_t t = { "", NULL };
    kci_key_setup(&k, key);
    kci_wipe(key, sizeof key);
    if (tmp_open(&t, o.out)) goto out;

    if (mode == MODE_RAW) {
        kci_raw_init(&s, &k, hdr + 28);
        for (;;) {
            size_t n = fread(inbuf, 1, CHUNK, in);
            if (n == 0) break;
            if (kci_stream_xor(&s, outbuf, inbuf, n) != KCI_OK) { fail("input too large", o.in); goto out; }
            if (fwrite(outbuf, 1, n, t.f) != n) { fail("write error", o.out); goto out; }
        }
    } else {
        /* stream through, always holding back the last 16 bytes: they are the tag */
        size_t have = 0;
        kci_aead_init(&a, &k, hdr + 28, hdr, HDR_BYTES);
        for (;;) {
            size_t n = fread(inbuf + have, 1, sizeof inbuf - have, in);
            if (n == 0) break;
            have += n;
            if (have > KCI_TAG_BYTES) {
                size_t body = have - KCI_TAG_BYTES;
                if (kci_aead_decrypt_update(&a, outbuf, inbuf, body) != KCI_OK) { fail("input too large", o.in); goto out; }
                if (fwrite(outbuf, 1, body, t.f) != body) { fail("write error", o.out); goto out; }
                memmove(inbuf, inbuf + body, KCI_TAG_BYTES);
                have = KCI_TAG_BYTES;
            }
        }
        if (have < KCI_TAG_BYTES) { fail("file is truncated", o.in); goto out; }
        if (kci_aead_decrypt_final(&a, inbuf) != KCI_OK) {
            fprintf(stderr, "%s: authentication failed: wrong key or password, or the file was modified; no output written\n", prog);
            rc = EXIT_AUTH;
            goto out;
        }
    }
    if (ferror(in)) { fail("read error", o.in); goto out; }
    rc = tmp_commit(&t, o.out);
out:
    if (rc != EXIT_OK && t.f) tmp_discard(&t);
    fclose(in);
    kci_key_wipe(&k); kci_wipe(&a, sizeof a); kci_stream_wipe(&s);
    kci_wipe(inbuf, sizeof inbuf); kci_wipe(outbuf, sizeof outbuf);
    return rc;
}

/* ---------------- keygen ---------------- */

static int cmd_keygen(int argc, char **argv)
{
    opts_t o; const char *pos[1];
    if (parse(argc, argv, 2, &o, 1, pos)) return EXIT_ERR;
    if (plat_exists(pos[0])) {
        if (!o.force) return fail("key file exists (use -f to overwrite)", pos[0]);
        if (remove(pos[0])) return fail("cannot remove existing key file", pos[0]);
    }
    uint8_t key[KCI_KEY_BYTES];
    if (plat_random(key, sizeof key)) return fail("OS random number generator failed", NULL);
    FILE *f = plat_create_private(pos[0]);
    if (!f) { kci_wipe(key, sizeof key); return fail("cannot create key file", pos[0]); }
    size_t n = fwrite(key, 1, sizeof key, f);
    kci_wipe(key, sizeof key);
    if (fclose(f) != 0 || n != sizeof key) { remove(pos[0]); return fail("write error", pos[0]); }
    return EXIT_OK;
}

/* ---------------- selftest ---------------- */

static int cmd_selftest(void)
{
    /* KCI-20 v0.4 block, key 00..1f, nonce 000000090000004a00000000, counter 1. Same value from the C library and the
     * independent Python reference (tools/kci_ref.py); see tests/kat_vectors.h. */
    static const char *expect =
        "40b9da6580f402a175df9b60394cab46d57e073c98252ad92b2df9962a6ca139"
        "a5ab360260272181fa5c66e6dad33d7457f2a7d3d9b5acce32bb89c80bf35d0d";
    uint8_t key[32], nonce[12] = { 0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0 }, blk[64], tag[16];
    char hex[129];
    int ok = 1;
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    kci_key k;
    kci_key_setup(&k, key);
    kci_block(blk, &k, 1, nonce);
    for (int i = 0; i < 64; i++) snprintf(hex + 2 * i, 3, "%02x", blk[i]);
    if (strcmp(hex, expect) != 0) { fprintf(stderr, "selftest: block KAT FAILED\n"); ok = 0; }

    uint8_t msg[300], buf[300];
    for (int i = 0; i < 300; i++) msg[i] = (uint8_t)(i * 7 + 3);
    kci_aead_encrypt(buf, tag, msg, sizeof msg, nonce, 12, &k, nonce);
    if (kci_aead_decrypt(buf, buf, sizeof buf, tag, nonce, 12, &k, nonce) != KCI_OK || memcmp(buf, msg, sizeof msg)) {
        fprintf(stderr, "selftest: AEAD round trip FAILED\n"); ok = 0;
    }
    kci_aead_encrypt(buf, tag, msg, sizeof msg, NULL, 0, &k, nonce);
    buf[123] ^= 1;
    if (kci_aead_decrypt(buf, buf, sizeof buf, tag, NULL, 0, &k, nonce) != KCI_ERR_AUTH) {
        fprintf(stderr, "selftest: AEAD tamper detection FAILED\n"); ok = 0;
    }
    if (kci_kdf_password(key, (const uint8_t *)"pw", 2, key, 16, KCI_KDF_MIN_ITERATIONS - 1) != KCI_ERR_PARAM) {
        fprintf(stderr, "selftest: KDF minimum not enforced\n"); ok = 0;
    }
    kci_key_wipe(&k);
    printf("selftest %s\n", ok ? "OK" : "FAILED");
    return ok ? EXIT_OK : EXIT_ERR;
}

/* ---------------- bench ---------------- */

static double now(void)
{
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int cmd_bench(void)
{
    static uint8_t buf[1 << 20];
    uint8_t key[32] = { 1 }, nonce[12] = { 2 }, tag[16], salt[16] = { 3 };
    kci_key k;
    kci_key_setup(&k, key);
    double best = 1e9;
    for (int rep = 0; rep < 3; rep++) {
        double t = now();
        for (int i = 0; i < 64; i++) kci_aead_encrypt(buf, tag, buf, sizeof buf, NULL, 0, &k, nonce);
        t = now() - t;
        if (t < best) best = t;
    }
    printf("AEAD encrypt (%s): %.0f MB/s\n", kci_impl(), 64.0 * (double)sizeof buf / best / 1e6);
    double t = now();
    kci_kdf_password(key, (const uint8_t *)"password", 8, salt, sizeof salt, KCI_KDF_DEFAULT_ITERATIONS);
    printf("password KDF, %u iterations: %.2f s\n", KCI_KDF_DEFAULT_ITERATIONS, now() - t);
    kci_key_wipe(&k);
    return EXIT_OK;
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(stderr); return EXIT_ERR; }
    const char *c = argv[1];
    if (!strcmp(c, "enc"))      return cmd_enc(argc, argv);
    if (!strcmp(c, "dec"))      return cmd_dec(argc, argv);
    if (!strcmp(c, "keygen"))   return cmd_keygen(argc, argv);
    if (!strcmp(c, "selftest")) return cmd_selftest();
    if (!strcmp(c, "bench"))    return cmd_bench();
    if (!strcmp(c, "-h") || !strcmp(c, "--help") || !strcmp(c, "help")) { usage(stdout); return EXIT_OK; }
    if (!strcmp(c, "--version")) { printf("kci %s\n", KCI_VERSION); return EXIT_OK; }
    fprintf(stderr, "%s: unknown command: %s\n\n", prog, c);
    usage(stderr);
    return EXIT_ERR;
}
