/*
 * pg_sshkey_sign.c
 *
 * Client-side helper: signs a server-issued challenge with the user's
 * SSH private key and outputs the PAM token string.
 *
 * Usage:
 *   pg_sshkey_sign [--at TS] [--nonce HEX] <private_key_path>          (v2)
 *   pg_sshkey_sign --cert <cert.pub> [--at TS] [--nonce HEX] <key>     (v3)
 *   pg_sshkey_sign <challenge_hex> <private_key_path>                  (v1)
 *
 * Prints to stdout:
 *   v2: <unix_ts>:<nonce_hex64>:<base64_signature>
 *   v3: <unix_ts>:<nonce_hex64>:<base64_signature>:<base64_cert>
 *   v1: <challenge_hex>:<base64_signature>
 *
 * Key formats accepted:
 *   - OpenSSH private key  (-----BEGIN OPENSSH PRIVATE KEY-----)
 *     Ed25519 only; unencrypted only.  For passphrase-protected or RSA
 *     OpenSSH keys, see the conversion notes in the error messages below.
 *   - PKCS#8 PEM            (-----BEGIN PRIVATE KEY-----)
 *   - Traditional PEM       (-----BEGIN EC/RSA/... PRIVATE KEY-----)
 *
 * Key types signed:
 *   - Ed25519  → Ed25519 signature (64 bytes)
 *   - RSA      → RSASSA-PKCS1-v1_5 with SHA-256
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

#include "ssh_agent.h"

/* Domain prefix, must match sig_verify.c */
static const unsigned char SIGN_PREFIX[]   = "pg-sshkey-v1";
static const size_t        SIGN_PREFIX_LEN = 13; /* 12 chars + NUL */

/*
 * v2 (default): the client issues its own challenge.
 *   token   = "<unix_ts>:<nonce_hex64>:<base64_sig>"
 *   message = "pg-sshkey-v2\0" || "<unix_ts>:<nonce_hex64>"   (ASCII)
 * The server checks |now - ts| <= 60 s, verifies the signature, then
 * records the nonce so it can never be accepted again.  No server-side
 * step happens before the connection, so remote clients need nothing.
 */
static const unsigned char SIGN_PREFIX_V2[]   = "pg-sshkey-v2";
static const size_t        SIGN_PREFIX_V2_LEN = 13;

/*
 * v3: like v2, but the token carries an OpenSSH user certificate so the
 * server can trust the key through a CA instead of an authorized_keys line.
 *   token   = "<unix_ts>:<nonce_hex64>:<base64_sig>:<base64_cert>"
 *   message = "pg-sshkey-v3\0" || "<unix_ts>:<nonce_hex64>"   (ASCII)
 * <base64_cert> is the second field of the *-cert.pub file, unchanged.
 */
static const unsigned char SIGN_PREFIX_V3[]   = "pg-sshkey-v3";
static const size_t        SIGN_PREFIX_V3_LEN = 13;

#define OPENSSH_MAGIC "openssh-key-v1"
#define MAX_CERT_FILE 65536

/* ── hex_to_bytes ─────────────────────────────────────────────────────── */
static int
hex_to_bytes(const char *hex, unsigned char *out, size_t out_size,
             size_t *out_len)
{
    size_t hexlen = strlen(hex);
    if (hexlen % 2 != 0 || hexlen / 2 > out_size)
        return -1;

    for (size_t i = 0; i < hexlen / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%02x", &byte) != 1)
            return -1;
        out[i] = (unsigned char)byte;
    }
    *out_len = hexlen / 2;
    return 0;
}

/* ── b64_encode ───────────────────────────────────────────────────────── */
static char *
b64_encode(const unsigned char *data, size_t len)
{
    BIO *b64  = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, data, (int)len);
    BIO_flush(b64);
    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(b64, &bptr);
    char *result = malloc(bptr->length + 1);
    if (result) {
        memcpy(result, bptr->data, bptr->length);
        result[bptr->length] = '\0';
    }
    BIO_free_all(b64);
    return result;
}

/* ── b64_decode_buf ───────────────────────────────────────────────────── */
/* Decode base64 (with or without newlines) into a malloc'd buffer. */
static unsigned char *
b64_decode_buf(const char *b64_in, size_t in_len, size_t *out_len)
{
    /* Strip newlines into a clean buffer */
    char *clean = malloc(in_len + 1);
    if (!clean) return NULL;
    size_t clen = 0;
    for (size_t i = 0; i < in_len; i++)
        if (b64_in[i] != '\n' && b64_in[i] != '\r')
            clean[clen++] = b64_in[i];
    clean[clen] = '\0';

    BIO *b64  = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf(clean, (int)clen);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    b64 = BIO_push(b64, bmem);

    unsigned char *buf = malloc(clen);   /* decoded is always <= encoded */
    if (!buf) { free(clean); BIO_free_all(b64); return NULL; }

    int n = BIO_read(b64, buf, (int)clen);
    BIO_free_all(b64);
    free(clean);

    if (n <= 0) { free(buf); return NULL; }
    *out_len = (size_t)n;
    return buf;
}

/* ── OpenSSH binary format helpers ───────────────────────────────────── */

/* Read a big-endian uint32 from buf at *pos; advance *pos. */
static int
read_u32(const unsigned char *buf, size_t buflen, size_t *pos, uint32_t *val)
{
    if (*pos + 4 > buflen) return -1;
    *val = ((uint32_t)buf[*pos]   << 24) |
           ((uint32_t)buf[*pos+1] << 16) |
           ((uint32_t)buf[*pos+2] <<  8) |
           ((uint32_t)buf[*pos+3]);
    *pos += 4;
    return 0;
}

/* Read a length-prefixed string; set *str to pointer into buf, *slen to length. */
static int
read_string(const unsigned char *buf, size_t buflen, size_t *pos,
            const unsigned char **str, size_t *slen)
{
    uint32_t len;
    if (read_u32(buf, buflen, pos, &len) != 0) return -1;
    if (*pos + len > buflen) return -1;
    *str  = buf + *pos;
    *slen = len;
    *pos += len;
    return 0;
}

/* ── load_openssh_ed25519 ─────────────────────────────────────────────── */
/*
 * Parse an unencrypted OpenSSH private key file containing an Ed25519 key.
 *
 * OpenSSH key format (PROTOCOL.key):
 *
 *   "openssh-key-v1\0"
 *   string  ciphername     ("none" when unencrypted)
 *   string  kdfname        ("none" when unencrypted)
 *   string  kdfoptions
 *   uint32  number_of_keys (we only handle 1)
 *   string  publickey
 *   string  private_section
 *
 * private_section (unencrypted):
 *   uint32  check1
 *   uint32  check2         (must equal check1)
 *   string  keytype        ("ssh-ed25519")
 *   string  pubkey         (32 bytes)
 *   string  privkey        (64 bytes: 32-byte seed || 32-byte pubkey)
 *   string  comment
 *   bytes   padding
 */
static EVP_PKEY *
load_openssh_ed25519(const unsigned char *der, size_t derlen)
{
    size_t pos = 0;

    /* Magic + NUL */
    size_t magic_len = strlen(OPENSSH_MAGIC) + 1;
    if (derlen < magic_len || memcmp(der, OPENSSH_MAGIC, magic_len) != 0) {
        fprintf(stderr, "Not an OpenSSH private key\n");
        return NULL;
    }
    pos = magic_len;

    /* ciphername */
    const unsigned char *cipher; size_t cipher_len;
    if (read_string(der, derlen, &pos, &cipher, &cipher_len) != 0) {
        fprintf(stderr, "OpenSSH key: truncated at ciphername\n");
        return NULL;
    }
    if (cipher_len != 4 || memcmp(cipher, "none", 4) != 0) {
        /* Key is encrypted with a passphrase */
        char name[64] = {0};
        size_t n = cipher_len < 63 ? cipher_len : 63;
        memcpy(name, cipher, n);
        fprintf(stderr,
            "Error: OpenSSH key is encrypted (cipher: %s).\n"
            "\n"
            "pg_sshkey_sign cannot unlock passphrase-protected OpenSSH keys.\n"
            "Options:\n"
            "  1. Remove the passphrase (creates an unencrypted copy):\n"
            "       ssh-keygen -p -N '' -f <keyfile>\n"
            "  2. Export to unencrypted PKCS#8 PEM (recommended, keeps\n"
            "     original key intact):\n"
            "       openssl pkey -in <keyfile> -out key.pem\n"
            "     (OpenSSL will prompt for the passphrase once.)\n"
            "  3. Use an ssh-agent integration instead of a key file.\n",
            name);
        return NULL;
    }

    /* kdfname */
    const unsigned char *kdf; size_t kdf_len;
    if (read_string(der, derlen, &pos, &kdf, &kdf_len) != 0) return NULL;

    /* kdfoptions */
    const unsigned char *kdfopts; size_t kdfopts_len;
    if (read_string(der, derlen, &pos, &kdfopts, &kdfopts_len) != 0) return NULL;

    /* number of keys */
    uint32_t nkeys;
    if (read_u32(der, derlen, &pos, &nkeys) != 0 || nkeys < 1) return NULL;

    /* public key blob (skip) */
    const unsigned char *pubblob; size_t pubblob_len;
    if (read_string(der, derlen, &pos, &pubblob, &pubblob_len) != 0) return NULL;

    /* private section */
    const unsigned char *priv_section; size_t priv_len;
    if (read_string(der, derlen, &pos, &priv_section, &priv_len) != 0) return NULL;

    /* Parse private section */
    size_t pp = 0;

    uint32_t check1, check2;
    if (read_u32(priv_section, priv_len, &pp, &check1) != 0) return NULL;
    if (read_u32(priv_section, priv_len, &pp, &check2) != 0) return NULL;
    if (check1 != check2) {
        fprintf(stderr, "OpenSSH key: check values mismatch (corrupt or wrong passphrase)\n");
        return NULL;
    }

    /* keytype */
    const unsigned char *keytype; size_t keytype_len;
    if (read_string(priv_section, priv_len, &pp, &keytype, &keytype_len) != 0) return NULL;

    if (keytype_len != 11 || memcmp(keytype, "ssh-ed25519", 11) != 0) {
        /* Not Ed25519, tell user how to convert */
        char kt[64] = {0};
        size_t n = keytype_len < 63 ? keytype_len : 63;
        memcpy(kt, keytype, n);
        fprintf(stderr,
            "Error: OpenSSH key type '%s' is not supported in OpenSSH format.\n"
            "\n"
            "Convert to PKCS#8 PEM first, then pass the .pem file:\n"
            "  openssl pkey -in <keyfile> -out key.pem\n"
            "\n"
            "Supported key types in OpenSSH format: ssh-ed25519\n"
            "Supported key types in PKCS#8 PEM format: Ed25519, RSA\n",
            kt);
        return NULL;
    }

    /* pubkey (32 bytes), skip */
    const unsigned char *pubkey; size_t pubkey_len;
    if (read_string(priv_section, priv_len, &pp, &pubkey, &pubkey_len) != 0) return NULL;
    if (pubkey_len != 32) {
        fprintf(stderr, "OpenSSH Ed25519: unexpected pubkey length %zu\n", pubkey_len);
        return NULL;
    }

    /* privkey: 64 bytes = 32-byte seed || 32-byte pubkey */
    const unsigned char *privkey; size_t privkey_len;
    if (read_string(priv_section, priv_len, &pp, &privkey, &privkey_len) != 0) return NULL;
    if (privkey_len != 64) {
        fprintf(stderr, "OpenSSH Ed25519: unexpected privkey length %zu\n", privkey_len);
        return NULL;
    }

    /* The first 32 bytes of privkey are the seed (the actual secret) */
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                    privkey, 32);
    if (!pkey)
        fprintf(stderr, "OpenSSH Ed25519: EVP_PKEY_new_raw_private_key failed\n");
    return pkey;
}

/* ── load_private_key ─────────────────────────────────────────────────── */
/*
 * Load a private key from path.  Handles:
 *   - OpenSSH format  (BEGIN OPENSSH PRIVATE KEY)
 *   - PKCS#8 PEM      (BEGIN PRIVATE KEY)
 *   - Traditional PEM (BEGIN RSA/EC/... PRIVATE KEY)
 */
static EVP_PKEY *
load_private_key(const char *path)
{
    /* Read the whole file */
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);
    if (fsize <= 0 || fsize > 1024 * 1024) {
        fprintf(stderr, "Key file too large or empty: %s\n", path);
        fclose(f);
        return NULL;
    }

    char *filebuf = malloc((size_t)fsize + 1);
    if (!filebuf) { fclose(f); return NULL; }
    size_t nread = fread(filebuf, 1, (size_t)fsize, f);
    fclose(f);
    filebuf[nread] = '\0';

    /* Detect OpenSSH format */
    if (strstr(filebuf, "-----BEGIN OPENSSH PRIVATE KEY-----")) {
        /* Extract the base64 body between the header/footer */
        const char *start = strchr(filebuf, '\n');
        if (!start) {
            fprintf(stderr, "Malformed OpenSSH key file\n");
            free(filebuf);
            return NULL;
        }
        start++; /* skip newline after header */

        const char *end = strstr(start, "-----END OPENSSH PRIVATE KEY-----");
        if (!end) {
            fprintf(stderr, "Missing OpenSSH key footer\n");
            free(filebuf);
            return NULL;
        }

        size_t b64_len = (size_t)(end - start);
        size_t der_len = 0;
        unsigned char *der = b64_decode_buf(start, b64_len, &der_len);
        free(filebuf);

        if (!der) {
            fprintf(stderr, "Failed to base64-decode OpenSSH key\n");
            return NULL;
        }

        EVP_PKEY *pkey = load_openssh_ed25519(der, der_len);
        free(der);
        return pkey;
    }

    /* Standard PEM, let OpenSSL handle it */
    BIO *bio = BIO_new_mem_buf(filebuf, (int)nread);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(filebuf);

    if (!pkey) {
        fprintf(stderr,
            "Failed to load private key from %s\n"
            "Supported formats:\n"
            "  -----BEGIN OPENSSH PRIVATE KEY-----  (Ed25519, unencrypted)\n"
            "  -----BEGIN PRIVATE KEY-----           (PKCS#8, any type)\n"
            "  -----BEGIN RSA PRIVATE KEY-----       (traditional RSA)\n"
            "\n"
            "To convert an OpenSSH key to PKCS#8 PEM:\n"
            "  openssl pkey -in %s -out key.pem\n",
            path, path);
        ERR_print_errors_fp(stderr);
    }
    return pkey;
}

/* ── sign_message ─────────────────────────────────────────────────────── */
static unsigned char *
sign_message(EVP_PKEY *pkey,
             const unsigned char *msg, size_t msg_len,
             size_t *sig_len_out)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return NULL;

    int key_type = EVP_PKEY_id(pkey);
    const EVP_MD *md = NULL;
    if (key_type == EVP_PKEY_RSA || key_type == EVP_PKEY_RSA2)
        md = EVP_sha256();
    /* Ed25519: md stays NULL */

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    size_t sig_len = 0;
    if (EVP_DigestSign(ctx, NULL, &sig_len, msg, msg_len) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    unsigned char *sig = malloc(sig_len);
    if (!sig) { EVP_MD_CTX_free(ctx); return NULL; }

    if (EVP_DigestSign(ctx, sig, &sig_len, msg, msg_len) != 1) {
        ERR_print_errors_fp(stderr);
        free(sig);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    EVP_MD_CTX_free(ctx);
    *sig_len_out = sig_len;
    return sig;
}

/* ── read_cert_b64 ────────────────────────────────────────────────────── */
/*
 * Read an OpenSSH certificate file (*-cert.pub) and return its base64
 * field as a malloc'd string.  The first field must end in
 * "-cert-v01@openssh.com"; a plain public key is refused.
 */
static char *
read_cert_b64(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Cannot read certificate %s: %s\n", path, strerror(errno));
        return NULL;
    }
    char *line = malloc(MAX_CERT_FILE);
    if (!line) { fclose(f); return NULL; }
    if (!fgets(line, MAX_CERT_FILE, f)) {
        fprintf(stderr, "Certificate %s is empty\n", path);
        fclose(f); free(line);
        return NULL;
    }
    if (!strchr(line, '\n') && !feof(f)) {
        fprintf(stderr, "Certificate %s: line too long\n", path);
        fclose(f); free(line);
        return NULL;
    }
    fclose(f);

    /* first field: cert type */
    char *type = line;
    while (*type == ' ' || *type == '\t') type++;
    char *p = type;
    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
    size_t type_len = (size_t)(p - type);
    static const char suffix[] = "-cert-v01@openssh.com";
    size_t suffix_len = sizeof(suffix) - 1;
    if (type_len < suffix_len ||
        memcmp(type + type_len - suffix_len, suffix, suffix_len) != 0) {
        fprintf(stderr,
            "%s is not an OpenSSH certificate (first field must end in %s)\n",
            path, suffix);
        free(line);
        return NULL;
    }

    /* second field: base64 blob */
    while (*p == ' ' || *p == '\t') p++;
    char *b64 = p;
    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
    size_t b64_len = (size_t)(p - b64);
    if (b64_len == 0) {
        fprintf(stderr, "%s has no certificate data\n", path);
        free(line);
        return NULL;
    }
    for (size_t i = 0; i < b64_len; i++) {
        char c = b64[i];
        if (!(isalnum((unsigned char)c) || c == '+' || c == '/' || c == '=')) {
            fprintf(stderr, "%s: certificate field is not base64\n", path);
            free(line);
            return NULL;
        }
    }
    if (b64_len % 4 != 0) {
        fprintf(stderr, "%s: certificate field is not padded base64\n", path);
        free(line);
        return NULL;
    }
    char *out = malloc(b64_len + 1);
    if (out) { memcpy(out, b64, b64_len); out[b64_len] = '\0'; }
    free(line);
    return out;
}

/* ── helpers for main ─────────────────────────────────────────────────── */
static void
usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s [--at <unix_ts>] [--nonce <hex64>] <private_key_path>\n"
        "       %s --agent <public_key.pub> [--cert <cert.pub>]\n"
        "       %s --cert <cert.pub> [--at <unix_ts>] [--nonce <hex64>] <private_key_path>\n"
        "       %s <challenge_hex> <private_key_path>        (v1, legacy)\n"
        "\n"
        "Default (v2): prints <unix_ts>:<nonce_hex>:<base64_signature>.\n"
        "  The challenge is issued by this client; nothing is needed on the\n"
        "  server beforehand.  --at and --nonce override the timestamp and\n"
        "  nonce (for tests / clock experiments only).\n"
        "--cert (v3): prints <unix_ts>:<nonce_hex>:<base64_signature>:<base64_cert>.\n"
        "  <cert.pub> is an OpenSSH user certificate (ssh-keygen -s) for the\n"
        "  private key; the server checks it against trusted_ca_keys.\n"
        "--agent: signs through the ssh-agent at $SSH_AUTH_SOCK using the\n"
        "  identity whose public key is in <public_key.pub>.  The private key\n"
        "  is never read, so passphrase-protected keys, OpenSSH-format RSA\n"
        "  keys, and forwarded agents work.  Not available with v1.\n"
        "v1: prints <challenge_hex>:<base64_signature> for a nonce created\n"
        "  on the server by pg_sshkey_challenge.\n"
        "\n"
        "Accepted key formats:\n"
        "  ~/.ssh/id_ed25519          OpenSSH Ed25519 (unencrypted)\n"
        "  ~/.ssh/id_rsa              OpenSSH RSA, convert first:\n"
        "                               openssl pkey -in ~/.ssh/id_rsa -out key.pem\n"
        "  key.pem                    PKCS#8 or traditional PEM (any type)\n",
        argv0, argv0, argv0, argv0);
}

static int
is_hex64_lower(const char *s)
{
    size_t n = 0;
    for (; s[n]; n++)
        if (!((s[n] >= '0' && s[n] <= '9') || (s[n] >= 'a' && s[n] <= 'f')))
            return 0;
    return n == 64;
}

/*
 * Sign msg and print "<head>:<b64sig>[:<tail>]\n"; 0 on success.
 * With agent_pubkey set the private key is never read: the signature comes
 * from the ssh-agent identity whose public blob that file holds.
 */
static int
sign_and_print(const char *privkey_path, const char *agent_pubkey,
               const unsigned char *msg, size_t msg_len,
               const char *head, const char *tail)
{
    size_t sig_len = 0;
    unsigned char *sig = NULL;

    if (agent_pubkey) {
        size_t blob_len = 0;
        unsigned char *blob = ssh_pubkey_blob_from_file(agent_pubkey, &blob_len);
        if (!blob)
            return 1;
        sig = ssh_agent_sign(blob, blob_len, msg, msg_len, &sig_len);
        free(blob);
    } else {
        EVP_PKEY *pkey = load_private_key(privkey_path);
        if (!pkey)
            return 1;
        sig = sign_message(pkey, msg, msg_len, &sig_len);
        EVP_PKEY_free(pkey);
    }
    if (!sig) {
        fprintf(stderr, "Signing failed\n");
        return 1;
    }

    char *sig_b64 = b64_encode(sig, sig_len);
    free(sig);
    if (!sig_b64) {
        fprintf(stderr, "Base64 encoding failed\n");
        return 1;
    }
    if (tail)
        printf("%s:%s:%s\n", head, sig_b64, tail);
    else
        printf("%s:%s\n", head, sig_b64);
    free(sig_b64);
    return 0;
}

/* ── main ─────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    long        at         = -1;
    const char *nonce_opt  = NULL;
    const char *cert_path  = NULL;
    const char *agent_pubkey = NULL;
    const char *positional[2] = { NULL, NULL };
    int         npos       = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--at") == 0 && i + 1 < argc) {
            char *end; at = strtol(argv[++i], &end, 10);
            if (*end || at < 0) { fprintf(stderr, "Invalid --at timestamp\n"); return 1; }
        } else if (strcmp(argv[i], "--nonce") == 0 && i + 1 < argc) {
            nonce_opt = argv[++i];
            if (!is_hex64_lower(nonce_opt)) { fprintf(stderr, "--nonce must be 64 lowercase hex chars\n"); return 1; }
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert_path = argv[++i];
        } else if (strcmp(argv[i], "--agent") == 0 && i + 1 < argc) {
            agent_pubkey = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]); return 1;
        } else if (argv[i][0] == '-' && argv[i][1] == '-') {
            fprintf(stderr, "Unknown option: %s\n", argv[i]); usage(argv[0]); return 1;
        } else if (npos < 2) {
            positional[npos++] = argv[i];
        } else {
            usage(argv[0]); return 1;
        }
    }

    if (npos == 2) {
        /* ── v1: sign a server-issued challenge ── */
        if (at >= 0 || nonce_opt || cert_path) { fprintf(stderr, "--at/--nonce/--cert apply to v2 and v3 only\n"); return 1; }
        if (agent_pubkey) { fprintf(stderr, "--agent cannot be combined with a v1 challenge\n"); return 1; }
        const char *challenge_hex = positional[0];
        const char *privkey_path  = positional[1];

        unsigned char challenge_bytes[64];
        size_t        challenge_len = 0;
        if (hex_to_bytes(challenge_hex, challenge_bytes, sizeof(challenge_bytes),
                         &challenge_len) != 0) {
            fprintf(stderr, "Invalid challenge hex\n");
            return 1;
        }
        unsigned char msg[512];
        if (SIGN_PREFIX_LEN + challenge_len > sizeof(msg)) {
            fprintf(stderr, "Challenge too long\n");
            return 1;
        }
        memcpy(msg, SIGN_PREFIX, SIGN_PREFIX_LEN);
        memcpy(msg + SIGN_PREFIX_LEN, challenge_bytes, challenge_len);
        return sign_and_print(privkey_path, NULL, msg,
                              SIGN_PREFIX_LEN + challenge_len,
                              challenge_hex, NULL);
    }

    if (agent_pubkey) {
        if (npos != 0) {
            fprintf(stderr,
                "--agent takes the PUBLIC key file; do not also pass a private key\n");
            return 1;
        }
    } else if (npos != 1) {
        usage(argv[0]); return 1;
    }

    /* ── v2 / v3: issue our own challenge ── */
    const char *privkey_path = positional[0];
    char *cert_b64 = NULL;
    if (cert_path) {
        cert_b64 = read_cert_b64(cert_path);
        if (!cert_b64)
            return 1;
    }
    char nonce_hex[65];
    if (nonce_opt) {
        memcpy(nonce_hex, nonce_opt, 65);
    } else {
        unsigned char raw[32];
        if (RAND_bytes(raw, sizeof(raw)) != 1) { fprintf(stderr, "RAND_bytes failed\n"); return 1; }
        for (int i = 0; i < 32; i++) sprintf(nonce_hex + 2 * i, "%02x", raw[i]);
        nonce_hex[64] = '\0';
    }
    long ts = (at >= 0) ? at : (long)time(NULL);

    char head[96];
    snprintf(head, sizeof(head), "%ld:%s", ts, nonce_hex);

    unsigned char msg[128];
    size_t head_len = strlen(head);
    const unsigned char *prefix     = cert_b64 ? SIGN_PREFIX_V3     : SIGN_PREFIX_V2;
    size_t               prefix_len = cert_b64 ? SIGN_PREFIX_V3_LEN : SIGN_PREFIX_V2_LEN;
    memcpy(msg, prefix, prefix_len);
    memcpy(msg + prefix_len, head, head_len);
    int rc = sign_and_print(privkey_path, agent_pubkey, msg,
                            prefix_len + head_len, head, cert_b64);
    free(cert_b64);
    return rc;
}
