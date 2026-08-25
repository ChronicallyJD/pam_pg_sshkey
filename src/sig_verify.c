/*
 * sig_verify.c
 *
 * Verify SSH-style signatures via OpenSSL EVP API.
 *
 * Signed message = "pg-sshkey-v2\0" || "<unix_ts>:<nonce_hex>"
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



/* ── security keys ───────────────────────────────────────────────────── */
/*
 * A FIDO key does not sign the message.  It signs
 *
 *     SHA256(application) || flags || counter || SHA256(message)
 *
 * and its SSH signature carries the flags byte and the 4-byte counter after
 * the 64 raw signature bytes, so sig is 69 bytes here.
 *
 * The user-presence bit must be set: without it the signature says nothing
 * about whether a person touched the key, which is the whole point of the
 * hardware.  (OpenSSH calls this SSH_SK_USER_PRESENCE_REQD.)
 */
#define SK_FLAG_USER_PRESENT  0x01
#define SK_SIG_LEN            (64 + 1 + 4)

static int
verify_sk_signature(const key_list_t    *key,
                    const unsigned char *msg, size_t msg_len,
                    const unsigned char *sig, size_t sig_len)
{
    if (!key->sk_application || sig_len != SK_SIG_LEN)
        return -1;

    const unsigned char *raw_sig = sig;
    unsigned char        flags   = sig[64];
    const unsigned char *counter = sig + 65;      /* 4 bytes, big endian */

    if ((flags & SK_FLAG_USER_PRESENT) == 0)
        return -1;                                 /* nobody touched the key */

    unsigned char signed_data[32 + 1 + 4 + 32];
    unsigned int  app_hash_len = 0, msg_hash_len = 0;

    if (EVP_Digest(key->sk_application, strlen(key->sk_application),
                   signed_data, &app_hash_len, EVP_sha256(), NULL) != 1 ||
        app_hash_len != 32)
        return -1;
    signed_data[32] = flags;
    memcpy(signed_data + 33, counter, 4);
    if (EVP_Digest(msg, msg_len, signed_data + 37, &msg_hash_len,
                   EVP_sha256(), NULL) != 1 || msg_hash_len != 32)
        return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int rc = -1;
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key->pkey) == 1 &&
        EVP_DigestVerify(ctx, raw_sig, 64, signed_data, sizeof(signed_data)) == 1)
        rc = 0;
    EVP_MD_CTX_free(ctx);
    return rc;
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
    } else if (strcmp(key->key_type, "sk-ssh-ed25519@openssh.com") == 0) {
        return verify_sk_signature(key, msg, msg_len, sig, sig_len);
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
