/*
 * key_parser.c
 *
 * Parse SSH public keys (authorized_keys format) into OpenSSL EVP_PKEY.
 *
 * SSH wire format (RFC 4253 §6.6):
 *   Each field is:  uint32 length  |  <length bytes>
 *
 *   ssh-rsa:      string "ssh-rsa" | mpint e | mpint n
 *   ssh-ed25519:  string "ssh-ed25519" | string <32-byte public key>
 *
 * SPDX-License-Identifier: MIT
 */

#include "key_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#  include <openssl/param_build.h>
#  include <openssl/core_names.h>
#endif

/* ── base64 decode (OpenSSL BIO) ──────────────────────────────────────── */
int
b64_decode(const char *b64, unsigned char *out, size_t out_size, size_t *out_len)
{
    BIO *bio = BIO_new_mem_buf(b64, (int)strlen(b64));
    BIO *b64_bio = BIO_new(BIO_f_base64());
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64_bio, bio);

    int n = BIO_read(bio, out, (int)out_size);
    BIO_free_all(bio);

    if (n <= 0)
        return -1;

    *out_len = (size_t)n;
    return 0;
}

/* ── SSH wire-format reader ──────────────────────────────────────────── */

/* Read a big-endian uint32 from a buffer, advance ptr. */
static int
read_u32(const unsigned char **p, const unsigned char *end, uint32_t *val)
{
    if ((*p) + 4 > end)
        return -1;
    *val = ((uint32_t)(*p)[0] << 24) |
           ((uint32_t)(*p)[1] << 16) |
           ((uint32_t)(*p)[2] <<  8) |
           ((uint32_t)(*p)[3]);
    *p += 4;
    return 0;
}

/* Read a length-prefixed string from SSH wire format, advance ptr.
   Returns a pointer into the buffer (NOT NUL-terminated) and its length. */
static int
read_string(const unsigned char **p, const unsigned char *end,
            const unsigned char **str, size_t *slen)
{
    uint32_t len;
    if (read_u32(p, end, &len) != 0)
        return -1;
    if ((*p) + len > end)
        return -1;
    *str  = *p;
    *slen = len;
    *p   += len;
    return 0;
}

/* ── RSA key decoder ─────────────────────────────────────────────────── */
/*
 * SSH RSA wire bytes: string "ssh-rsa" | mpint e | mpint n
 *   (mpint is the same length-prefixed format; leading 0x00 byte if high
 *   bit would be set to keep it positive.)
 *
 * Uses EVP_PKEY_fromdata (OpenSSL 3.x) when available, falling back to
 * the legacy RSA_new / RSA_set0_key path for OpenSSL 1.x.
 */
static EVP_PKEY *
decode_rsa_key(const unsigned char *data, size_t len)
{
    const unsigned char *p   = data;
    const unsigned char *end = data + len;

    /* Skip the key type string */
    const unsigned char *ktype; size_t ktype_len;
    if (read_string(&p, end, &ktype, &ktype_len) != 0) return NULL;

    /* Read exponent e */
    const unsigned char *e_bytes; size_t e_len;
    if (read_string(&p, end, &e_bytes, &e_len) != 0) return NULL;

    /* Read modulus n */
    const unsigned char *n_bytes; size_t n_len;
    if (read_string(&p, end, &n_bytes, &n_len) != 0) return NULL;

    BIGNUM *e = BN_bin2bn(e_bytes, (int)e_len, NULL);
    BIGNUM *n = BN_bin2bn(n_bytes, (int)n_len, NULL);
    if (!e || !n) { BN_free(e); BN_free(n); return NULL; }

    EVP_PKEY *pkey = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* OpenSSL 3.x — use EVP_PKEY_fromdata, no deprecated RSA_* needed */
    unsigned char n_buf[1024], e_buf[64];
    int n_sz = BN_bn2bin(n, n_buf);
    int e_sz = BN_bn2bin(e, e_buf);
    BN_free(n); BN_free(e);
    if (n_sz <= 0 || e_sz <= 0) return NULL;

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_BN("n", n_buf, (size_t)n_sz);
    params[1] = OSSL_PARAM_construct_BN("e", e_buf, (size_t)e_sz);
    params[2] = OSSL_PARAM_construct_end();

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) return NULL;
    if (EVP_PKEY_fromdata_init(ctx) == 1)
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
    EVP_PKEY_CTX_free(ctx);
#else
    /* OpenSSL 1.x legacy path */
    RSA *rsa = RSA_new();
    if (!rsa) { BN_free(e); BN_free(n); return NULL; }
    if (RSA_set0_key(rsa, n, e, NULL) != 1) {
        RSA_free(rsa); BN_free(e); BN_free(n); return NULL;
    }
    pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey); RSA_free(rsa); return NULL;
    }
#endif

    return pkey;
}

/* ── Ed25519 key decoder ─────────────────────────────────────────────── */
/*
 * SSH Ed25519 wire bytes: string "ssh-ed25519" | string <32-byte key>
 */
static EVP_PKEY *
decode_ed25519_key(const unsigned char *data, size_t len)
{
    const unsigned char *p   = data;
    const unsigned char *end = data + len;

    const unsigned char *ktype;
    size_t ktype_len;
    if (read_string(&p, end, &ktype, &ktype_len) != 0)
        return NULL;

    const unsigned char *key_bytes;
    size_t key_len;
    if (read_string(&p, end, &key_bytes, &key_len) != 0)
        return NULL;

    if (key_len != 32)
        return NULL;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                                   key_bytes, key_len);
    return pkey; /* may be NULL if OpenSSL < 1.1.1 */
}

/* ── parse_authorized_keys ───────────────────────────────────────────── */
int
parse_authorized_keys(const char *path, key_list_t **out)
{
    *out = NULL;

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[4096];
    int  count = 0;
    key_list_t *tail = NULL;

    while (fgets(line, sizeof(line), f)) {
        /* Strip trailing newline */
        size_t linelen = strlen(line);
        while (linelen > 0 && (line[linelen-1] == '\n' || line[linelen-1] == '\r'))
            line[--linelen] = '\0';

        /* Skip empty lines and comments */
        if (linelen == 0 || line[0] == '#')
            continue;

        /* Skip option lines starting with known option keywords or quotes
           (basic; a full parser is complex — for security-critical use
           consider rejecting any lines with leading non-alpha chars) */
        if (line[0] == '"' || line[0] == '!')
            continue;

        /* Tokenise: key_type  base64_data  [comment] */
        char *key_type_str = strtok(line, " \t");
        char *key_b64      = strtok(NULL, " \t");
        char *comment_str  = strtok(NULL, "");  /* rest of line */

        if (!key_type_str || !key_b64)
            continue;

        /* Only accept supported key types */
        int is_rsa      = (strcmp(key_type_str, "ssh-rsa")      == 0 ||
                           strcmp(key_type_str, "rsa-sha2-256")  == 0 ||
                           strcmp(key_type_str, "rsa-sha2-512")  == 0);
        int is_ed25519  = (strcmp(key_type_str, "ssh-ed25519")   == 0);

        if (!is_rsa && !is_ed25519)
            continue;

        /* Decode base64 blob */
        unsigned char raw[4096];
        size_t raw_len = 0;
        if (b64_decode(key_b64, raw, sizeof(raw), &raw_len) != 0)
            continue;

        /* Decode into EVP_PKEY */
        EVP_PKEY *pkey = NULL;
        if (is_rsa)
            pkey = decode_rsa_key(raw, raw_len);
        else if (is_ed25519)
            pkey = decode_ed25519_key(raw, raw_len);

        if (!pkey)
            continue;

        /* Build list entry */
        key_list_t *entry = calloc(1, sizeof(*entry));
        if (!entry) {
            EVP_PKEY_free(pkey);
            break;
        }
        entry->key_type = strdup(key_type_str);
        entry->comment  = comment_str ? strdup(comment_str) : NULL;
        entry->pkey     = pkey;
        entry->next     = NULL;

        if (!tail) {
            *out = entry;
        } else {
            tail->next = entry;
        }
        tail = entry;
        count++;
    }

    fclose(f);
    return count;
}

/* ── free_key_list ───────────────────────────────────────────────────── */
void
free_key_list(key_list_t *list)
{
    while (list) {
        key_list_t *next = list->next;
        free(list->key_type);
        free(list->comment);
        EVP_PKEY_free(list->pkey);
        free(list);
        list = next;
    }
}
