/*
 * sig_verify.c
 *
 * Verify SSH-style signatures via OpenSSL EVP API.
 *
 * Signed message = "pg-sshkey-v1\0" || challenge_bytes
 * (the NUL is part of the prefix so the domain is unambiguous)
 *
 * Key types and digest used:
 *   ssh-rsa        → RSA-PKCS1-v1_5 with SHA-256
 *   rsa-sha2-256   → RSA-PKCS1-v1_5 with SHA-256
 *   rsa-sha2-512   → RSA-PKCS1-v1_5 with SHA-256  (label accepted as an
 *                    alias; see below)
 *   ssh-ed25519    → Ed25519 (digest handled internally)
 *
 * The key-type word in an authorized_keys line identifies the KEY, not the
 * signature algorithm: OpenSSH only ever writes "ssh-rsa" for RSA keys, and
 * "rsa-sha2-256"/"rsa-sha2-512" are signature-algorithm names.  Because a
 * client signs before it can know which server-side entry will match, every
 * shipped signer (pg_sshkey_sign, pam_pg_sshkey.py) uses SHA-256, and the
 * verifier must therefore treat all three RSA labels identically.
 *
 * SPDX-License-Identifier: MIT
 */

#include "sig_verify.h"
#include "key_parser.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* Domain-separation prefix (including the NUL byte) */
static const unsigned char SIGN_PREFIX[]   = "pg-sshkey-v1";
static const size_t        SIGN_PREFIX_LEN = 13; /* 12 chars + NUL */

/*
 * Build the message that was signed.
 * msg must be at least SIGN_PREFIX_LEN + challenge_len bytes.
 */
static void
build_signed_message(const unsigned char *challenge, size_t challenge_len,
                     unsigned char *msg, size_t *msg_len)
{
    memcpy(msg, SIGN_PREFIX, SIGN_PREFIX_LEN);
    memcpy(msg + SIGN_PREFIX_LEN, challenge, challenge_len);
    *msg_len = SIGN_PREFIX_LEN + challenge_len;
}

int
verify_signature(const key_list_t  *key,
                 const unsigned char *challenge, size_t challenge_len,
                 const unsigned char *sig,       size_t sig_len)
{
    if (!key || !key->pkey || !challenge || !sig)
        return -1;

    /* Build the signed message buffer (max 32 bytes challenge + prefix) */
    unsigned char msg[512];
    size_t        msg_len = 0;

    if (SIGN_PREFIX_LEN + challenge_len > sizeof(msg))
        return -1;

    build_signed_message(challenge, challenge_len, msg, &msg_len);
    return verify_signature_raw(key, msg, msg_len, sig, sig_len);
}

int
verify_signature_raw(const key_list_t    *key,
                     const unsigned char *msg, size_t msg_len,
                     const unsigned char *sig, size_t sig_len)
{
    if (!key || !key->pkey || !msg || !sig)
        return -1;

    /* Choose digest algorithm based on key type */
    const EVP_MD *md = NULL;

    if (strcmp(key->key_type, "ssh-rsa")      == 0 ||
        strcmp(key->key_type, "rsa-sha2-256") == 0 ||
        strcmp(key->key_type, "rsa-sha2-512") == 0) {
        md = EVP_sha256();   /* all RSA labels: PKCS#1 v1.5 / SHA-256 */
    } else if (strcmp(key->key_type, "ssh-ed25519") == 0) {
        md = NULL; /* Ed25519 uses its own internal hash */
    } else {
        return -1; /* unsupported key type */
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return -1;

    int rc = -1;

    if (md != NULL) {
        /* RSA: DigestVerify */
        if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, key->pkey) != 1)
            goto done;
        if (EVP_DigestVerifyUpdate(ctx, msg, msg_len) != 1)
            goto done;
        rc = (EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1) ? 0 : -1;
    } else {
        /* Ed25519: one-shot EVP_DigestVerify */
        if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key->pkey) != 1)
            goto done;
        rc = (EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) == 1) ? 0 : -1;
    }

done:
    EVP_MD_CTX_free(ctx);
    return rc;
}
