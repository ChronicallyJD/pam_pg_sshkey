/*
 * pg_sshkey_sign.c
 *
 * Client-side helper: signs a server-issued challenge with the user's
 * SSH private key and outputs the PAM token string.
 *
 * Usage:
 *   pg_sshkey_sign <challenge_hex> <private_key_path>
 *
 * Prints to stdout:
 *   <challenge_hex>:<base64_signature>
 *
 * This string is used as the PostgreSQL "password".
 *
 * Key types supported:
 *   - Ed25519  (ssh-ed25519)
 *   - RSA      (ssh-rsa / rsa-sha2-256)
 *
 * NOTE: This tool reads unencrypted private keys.  For production use,
 * integrate with ssh-agent via the SSH_AUTH_SOCK socket instead so the
 * private key never leaves the agent.  See pg_sshkey_sign_agent.c for
 * an ssh-agent-based implementation.
 *
 * Build (standalone, not part of the PAM .so):
 *   gcc -o pg_sshkey_sign pg_sshkey_sign.c \
 *       $(pkg-config --cflags --libs libcrypto)
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

/* Domain prefix — must match sig_verify.c */
static const unsigned char SIGN_PREFIX[]   = "pg-sshkey-v1";
static const size_t        SIGN_PREFIX_LEN = 13; /* 12 chars + NUL */

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

/* ── base64_encode ────────────────────────────────────────────────────── */
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

/* ── load_private_key ─────────────────────────────────────────────────── */
static EVP_PKEY *
load_private_key(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    if (!pkey) {
        fprintf(stderr, "Failed to load private key from %s\n", path);
        ERR_print_errors_fp(stderr);
    }
    return pkey;
}

/* ── sign ──────────────────────────────────────────────────────────────── */
static unsigned char *
sign_message(EVP_PKEY *pkey,
             const unsigned char *msg, size_t msg_len,
             size_t *sig_len_out)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return NULL;

    /* Choose digest: Ed25519 uses NULL digest (self-hashing).
       RSA uses SHA-256.  OpenSSL auto-detects key type. */
    int key_type = EVP_PKEY_id(pkey);
    const EVP_MD *md = NULL;
    if (key_type == EVP_PKEY_RSA || key_type == EVP_PKEY_RSA2)
        md = EVP_sha256();
    /* Ed25519: md remains NULL */

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    /* Determine required signature buffer size */
    size_t sig_len = 0;
    if (EVP_DigestSign(ctx, NULL, &sig_len, msg, msg_len) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    unsigned char *sig = malloc(sig_len);
    if (!sig) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

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

/* ── main ──────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr,
                "Usage: %s <challenge_hex> <private_key_path>\n", argv[0]);
        fprintf(stderr,
                "Output: <challenge_hex>:<base64_signature>  (to stdout)\n");
        return 1;
    }

    const char *challenge_hex  = argv[1];
    const char *privkey_path   = argv[2];

    /* Decode challenge hex → bytes */
    unsigned char challenge_bytes[64];
    size_t        challenge_len = 0;
    if (hex_to_bytes(challenge_hex, challenge_bytes, sizeof(challenge_bytes),
                     &challenge_len) != 0) {
        fprintf(stderr, "Invalid challenge hex\n");
        return 1;
    }

    /* Build signed message: prefix || challenge */
    unsigned char msg[512];
    if (SIGN_PREFIX_LEN + challenge_len > sizeof(msg)) {
        fprintf(stderr, "Challenge too long\n");
        return 1;
    }
    memcpy(msg, SIGN_PREFIX, SIGN_PREFIX_LEN);
    memcpy(msg + SIGN_PREFIX_LEN, challenge_bytes, challenge_len);
    size_t msg_len = SIGN_PREFIX_LEN + challenge_len;

    /* Load private key */
    EVP_PKEY *pkey = load_private_key(privkey_path);
    if (!pkey)
        return 1;

    /* Sign */
    size_t sig_len = 0;
    unsigned char *sig = sign_message(pkey, msg, msg_len, &sig_len);
    EVP_PKEY_free(pkey);

    if (!sig) {
        fprintf(stderr, "Signing failed\n");
        return 1;
    }

    /* Base64-encode signature */
    char *sig_b64 = b64_encode(sig, sig_len);
    free(sig);

    if (!sig_b64) {
        fprintf(stderr, "Base64 encoding failed\n");
        return 1;
    }

    /* Output PAM token */
    printf("%s:%s\n", challenge_hex, sig_b64);
    free(sig_b64);

    return 0;
}
