/*
 * sig_verify.h
 *
 * Verify SSH signatures produced by ssh-keysign or a custom client.
 *
 * The client signs "pg-sshkey-v2\0" || "<unix_ts>:<nonce_hex>", or the v3
 * prefix when the token carries a certificate, using its SSH private key.
 * The resulting signature bytes are what the PAM token carries.
 *
 * For Ed25519 the signature is 64 raw bytes (no hash pre-processing -
 * Ed25519 internally hashes with SHA-512).
 * For RSA the signature is an RSASSA-PKCS1-v1_5 (SHA-256) signature.
 * For sk-ssh-ed25519@openssh.com the signature is 69 bytes, the 64 raw bytes
 * followed by the flags byte and the 4-byte counter, and it covers
 * SHA256(application) || flags || counter || SHA256(message).  The
 * user-presence flag must be set.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef SIG_VERIFY_H
#define SIG_VERIFY_H

#include <stddef.h>
#include "key_parser.h"


/*
 * Verify sig over an already-built message (no prefix is added).
 * v2 tokens use msg = "pg-sshkey-v2\0" || "<ts>:<nonce_hex>".
 * Returns 0 on success, non-zero on failure.
 */
int verify_signature_raw(const key_list_t    *key,
                         const unsigned char *msg, size_t msg_len,
                         const unsigned char *sig, size_t sig_len);

#endif /* SIG_VERIFY_H */
