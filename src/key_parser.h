/*
 * key_parser.h
 *
 * Parse SSH authorized_keys files and expose public key material
 * as OpenSSL EVP_PKEY objects ready for signature verification.
 *
 * Supported key types:
 *   ssh-rsa          RSA (verified as PKCS#1 v1.5 / SHA-256)
 *   rsa-sha2-256     RSA, alias label, same key, same verification
 *   rsa-sha2-512     RSA, alias label, same key, same verification
 *                    (the label names the key, not a digest; see sig_verify.c)
 *   ssh-ed25519      Ed25519
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KEY_PARSER_H
#define KEY_PARSER_H

#include <stddef.h>
#include <openssl/evp.h>

/* One entry from an authorized_keys file */
typedef struct key_list {
    char         *key_type;   /* e.g. "ssh-ed25519", "ssh-rsa" */
    char         *comment;    /* optional comment field, may be NULL */
    EVP_PKEY     *pkey;       /* OpenSSL public key, ready to verify */
    struct key_list *next;
} key_list_t;

/*
 * Parse an authorized_keys file.
 *
 * @param path    Path to the authorized_keys file.
 * @param out     Set to a linked list of parsed keys (caller frees with
 *                free_key_list).
 *
 * Returns the number of successfully parsed keys (0 or positive).
 * On file-open error returns -1.
 */
int parse_authorized_keys(const char *path, key_list_t **out);

/*
 * Free a key_list returned by parse_authorized_keys.
 */
void free_key_list(key_list_t *list);

/*
 * Decode an SSH public key blob (string type || fields) into an EVP_PKEY.
 * Accepts "ssh-rsa" and "ssh-ed25519" blobs.  Returns NULL on error.
 */
EVP_PKEY *ssh_pubkey_from_blob(const unsigned char *blob, size_t len);

/*
 * Decode a base64 string into bytes.
 * Returns 0 on success, -1 on error.
 */
int b64_decode(const char *b64, unsigned char *out, size_t out_size,
               size_t *out_len);

#endif /* KEY_PARSER_H */
