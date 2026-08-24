/*
 * ssh_cert.c
 *
 * OpenSSH certificate parser and CA signature check.  See ssh_cert.h.
 *
 * Wire layout (PROTOCOL.certkeys):
 *
 *   string    cert type name
 *   string    nonce
 *   (ed25519) string pk            | (rsa) mpint e, mpint n
 *   uint64    serial
 *   uint32    type
 *   string    key id
 *   string    valid principals     (packed strings)
 *   uint64    valid after
 *   uint64    valid before
 *   string    critical options     (packed name/data pairs)
 *   string    extensions
 *   string    reserved
 *   string    signature key
 *   string    signature            (string algo || string bytes)
 *
 * The CA signed every byte before the final signature string.
 *
 * SPDX-License-Identifier: MIT
 */

#include "ssh_cert.h"

#include <stdlib.h>
#include <string.h>

/* ── bounds-checked readers ──────────────────────────────────────────── */

typedef struct {
    const unsigned char *p;
    const unsigned char *end;
} reader_t;

static int
rd_u32(reader_t *r, uint32_t *v)
{
    if ((size_t)(r->end - r->p) < 4) return -1;
    *v = ((uint32_t)r->p[0] << 24) | ((uint32_t)r->p[1] << 16) |
         ((uint32_t)r->p[2] <<  8) |  (uint32_t)r->p[3];
    r->p += 4;
    return 0;
}

static int
rd_u64(reader_t *r, uint64_t *v)
{
    uint32_t hi, lo;
    if (rd_u32(r, &hi) != 0 || rd_u32(r, &lo) != 0) return -1;
    *v = ((uint64_t)hi << 32) | lo;
    return 0;
}

/* A length-prefixed string; the length is checked against what is left. */
static int
rd_string(reader_t *r, const unsigned char **s, size_t *len)
{
    uint32_t n;
    if (rd_u32(r, &n) != 0) return -1;
    if ((size_t)(r->end - r->p) < n) return -1;
    *s = r->p;
    *len = n;
    r->p += n;
    return 0;
}

/*
 * Same, copied into a NUL-terminated heap string.  Only printable ASCII
 * (0x20..0x7e) is accepted: these strings (key id, principals, option and
 * algorithm names) end up in syslog, and a newline in one would let an
 * unauthenticated client forge a log line.  OpenSSH itself never writes
 * anything else into them.
 */
static char *
rd_cstring(reader_t *r)
{
    const unsigned char *s; size_t n;
    if (rd_string(r, &s, &n) != 0) return NULL;
    for (size_t i = 0; i < n; i++)
        if (s[i] < 0x20 || s[i] > 0x7e) return NULL;
    char *out = malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

/* ── key blob decoders (public part of a certificate or a CA key) ───── */

static EVP_PKEY *
pkey_from_ed25519(reader_t *r)
{
    const unsigned char *pk; size_t n;
    if (rd_string(r, &pk, &n) != 0 || n != 32) return NULL;
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, n);
}

static EVP_PKEY *
pkey_from_rsa(reader_t *r)
{
    /*
     * Re-encode e and n as an ssh-rsa key blob and let key_parser's decoder
     * do the OpenSSL work, so RSA keys have one construction path.
     */
    const unsigned char *e, *n; size_t elen, nlen;
    if (rd_string(r, &e, &elen) != 0) return NULL;
    if (rd_string(r, &n, &nlen) != 0) return NULL;
    if (elen == 0 || nlen == 0 || elen > 64 || nlen > 1024) return NULL;

    size_t blen = 4 + 7 + 4 + elen + 4 + nlen;
    unsigned char *blob = malloc(blen);
    if (!blob) return NULL;
    unsigned char *w = blob;
#define PUT_STR(src, len) do { \
        uint32_t _l = (uint32_t)(len); \
        w[0] = (unsigned char)(_l >> 24); w[1] = (unsigned char)(_l >> 16); \
        w[2] = (unsigned char)(_l >> 8);  w[3] = (unsigned char)_l; \
        memcpy(w + 4, (src), (len)); w += 4 + (len); } while (0)
    PUT_STR("ssh-rsa", 7);
    PUT_STR(e, elen);
    PUT_STR(n, nlen);
#undef PUT_STR
    EVP_PKEY *pk = ssh_pubkey_from_blob(blob, blen);
    free(blob);
    return pk;
}

/* A complete ssh public key blob: string type || type-specific fields. */
static EVP_PKEY *
pkey_from_blob(const unsigned char *blob, size_t len, char **type_out)
{
    reader_t r = { blob, blob + len };
    char *type = rd_cstring(&r);
    if (!type) return NULL;
    EVP_PKEY *pk = NULL;
    if (strcmp(type, "ssh-ed25519") == 0)
        pk = pkey_from_ed25519(&r);
    else if (strcmp(type, "ssh-rsa") == 0)
        pk = pkey_from_rsa(&r);
    if (!pk || r.p != r.end) {
        EVP_PKEY_free(pk);
        free(type);
        return NULL;
    }
    *type_out = type;
    return pk;
}

/* ── parse ───────────────────────────────────────────────────────────── */

void
ssh_cert_free(ssh_cert_t *c)
{
    if (!c) return;
    free(c->cert_type);
    free(c->key_type);
    EVP_PKEY_free(c->pkey);
    free(c->key_id);
    for (size_t i = 0; i < c->nprincipals; i++) free(c->principals[i]);
    free(c->principals);
    free(c->critical_option);
    free(c->ca_key_type);
    EVP_PKEY_free(c->ca_pkey);
    free(c->sig_algo);
    free(c->sig);
    free(c->tbs);
    free(c);
}

int
ssh_cert_parse(const unsigned char *blob, size_t len, ssh_cert_t **out)
{
    *out = NULL;
    if (!blob || len == 0) return -1;

    ssh_cert_t *c = calloc(1, sizeof(*c));
    if (!c) return -1;

    reader_t r = { blob, blob + len };
    const unsigned char *s; size_t n;

    c->cert_type = rd_cstring(&r);
    if (!c->cert_type) goto bad;
    if (strcmp(c->cert_type, "ssh-ed25519-cert-v01@openssh.com") == 0)
        c->key_type = strdup("ssh-ed25519");
    else if (strcmp(c->cert_type, "ssh-rsa-cert-v01@openssh.com") == 0)
        c->key_type = strdup("ssh-rsa");
    else
        goto bad;
    if (!c->key_type) goto bad;

    if (rd_string(&r, &s, &n) != 0) goto bad;            /* nonce */

    c->pkey = (strcmp(c->key_type, "ssh-ed25519") == 0)
              ? pkey_from_ed25519(&r) : pkey_from_rsa(&r);
    if (!c->pkey) goto bad;

    if (rd_u64(&r, &c->serial) != 0) goto bad;
    if (rd_u32(&r, &c->type) != 0) goto bad;
    c->key_id = rd_cstring(&r);
    if (!c->key_id) goto bad;

    /* principals: a string holding zero or more packed strings */
    if (rd_string(&r, &s, &n) != 0) goto bad;
    {
        reader_t pr = { s, s + n };
        while (pr.p < pr.end) {
            char *name = rd_cstring(&pr);
            if (!name) goto bad;
            char **grown = realloc(c->principals,
                                   (c->nprincipals + 1) * sizeof(char *));
            if (!grown) { free(name); goto bad; }
            c->principals = grown;
            c->principals[c->nprincipals++] = name;
        }
    }

    if (rd_u64(&r, &c->valid_after)  != 0) goto bad;
    if (rd_u64(&r, &c->valid_before) != 0) goto bad;

    /* critical options: packed (string name, string data) pairs */
    if (rd_string(&r, &s, &n) != 0) goto bad;
    {
        reader_t cr = { s, s + n };
        while (cr.p < cr.end) {
            char *name = rd_cstring(&cr);
            if (!name) goto bad;
            const unsigned char *d; size_t dn;
            if (rd_string(&cr, &d, &dn) != 0) { free(name); goto bad; }
            if (!c->critical_option) c->critical_option = name;
            else free(name);
        }
    }

    if (rd_string(&r, &s, &n) != 0) goto bad;            /* extensions */
    if (rd_string(&r, &s, &n) != 0) goto bad;            /* reserved */

    if (rd_string(&r, &s, &n) != 0) goto bad;            /* signature key */
    c->ca_pkey = pkey_from_blob(s, n, &c->ca_key_type);
    if (!c->ca_pkey) goto bad;

    /* everything so far is what the CA signed */
    c->tbs_len = (size_t)(r.p - blob);
    c->tbs = malloc(c->tbs_len);
    if (!c->tbs) goto bad;
    memcpy(c->tbs, blob, c->tbs_len);

    if (rd_string(&r, &s, &n) != 0) goto bad;            /* signature */
    {
        reader_t sr = { s, s + n };
        c->sig_algo = rd_cstring(&sr);
        if (!c->sig_algo) goto bad;
        const unsigned char *sb; size_t sn;
        if (rd_string(&sr, &sb, &sn) != 0 || sn == 0) goto bad;
        if (sr.p != sr.end) goto bad;
        c->sig = malloc(sn);
        if (!c->sig) goto bad;
        memcpy(c->sig, sb, sn);
        c->sig_len = sn;
    }

    if (r.p != r.end) goto bad;                          /* trailing bytes */

    *out = c;
    return 0;

bad:
    ssh_cert_free(c);
    return -1;
}

/* ── CA checks ───────────────────────────────────────────────────────── */

int
ssh_cert_ca_is_trusted(const ssh_cert_t *cert, const key_list_t *cas)
{
    if (!cert || !cert->ca_pkey) return 0;
    for (const key_list_t *k = cas; k; k = k->next) {
        if (!k->pkey) continue;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (EVP_PKEY_eq(k->pkey, cert->ca_pkey) == 1) return 1;
#else
        if (EVP_PKEY_cmp(k->pkey, cert->ca_pkey) == 1) return 1;
#endif
    }
    return 0;
}

int
ssh_cert_verify_ca_signature(const ssh_cert_t *cert)
{
    if (!cert || !cert->ca_pkey || !cert->sig || !cert->tbs) return -1;

    const EVP_MD *md = NULL;
    int ed = 0;
    if (strcmp(cert->sig_algo, "ssh-ed25519") == 0)       ed = 1;
    else if (strcmp(cert->sig_algo, "rsa-sha2-256") == 0) md = EVP_sha256();
    else if (strcmp(cert->sig_algo, "rsa-sha2-512") == 0) md = EVP_sha512();
    else return -2;

    /* the algorithm must belong to the CA key's family */
    if (ed  && strcmp(cert->ca_key_type, "ssh-ed25519") != 0) return -1;
    if (!ed && strcmp(cert->ca_key_type, "ssh-rsa") != 0)     return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int rc = -1;
    if (ed) {
        if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, cert->ca_pkey) == 1 &&
            EVP_DigestVerify(ctx, cert->sig, cert->sig_len,
                             cert->tbs, cert->tbs_len) == 1)
            rc = 0;
    } else {
        if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, cert->ca_pkey) == 1 &&
            EVP_DigestVerifyUpdate(ctx, cert->tbs, cert->tbs_len) == 1 &&
            EVP_DigestVerifyFinal(ctx, cert->sig, cert->sig_len) == 1)
            rc = 0;
    }
    EVP_MD_CTX_free(ctx);
    return rc;
}
