/*
 * ssh_cert.h
 *
 * Parse OpenSSH user certificates (PROTOCOL.certkeys) and verify the CA
 * signature over them.  No PAM dependency: the policy decisions (validity
 * window, principals, options, trust) belong to the caller, which logs
 * each one; this file only exposes the fields and checks the cryptography.
 *
 * Accepted certificate types:
 *   ssh-ed25519-cert-v01@openssh.com
 *   ssh-rsa-cert-v01@openssh.com
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef SSH_CERT_H
#define SSH_CERT_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

#include "key_parser.h"

#define SSH_CERT_TYPE_USER 1
#define SSH_CERT_TYPE_HOST 2

typedef struct {
    char      *cert_type;        /* "ssh-ed25519-cert-v01@openssh.com" */
    char      *key_type;         /* "ssh-ed25519" or "ssh-rsa": the embedded key */
    EVP_PKEY  *pkey;             /* the certified public key */
    uint64_t   serial;
    uint32_t   type;             /* SSH_CERT_TYPE_USER or _HOST */
    char      *key_id;
    char     **principals;
    size_t     nprincipals;
    uint64_t   valid_after;
    uint64_t   valid_before;
    char      *critical_option;  /* name of the first critical option other
                                    than source-address, or NULL */
    char      *source_address;   /* the source-address list, or NULL */
    char      *ca_key_type;      /* "ssh-ed25519" or "ssh-rsa" */
    EVP_PKEY  *ca_pkey;          /* signature key */
    char      *sig_algo;         /* "ssh-ed25519", "rsa-sha2-256", ... */
    unsigned char *sig;          /* raw signature bytes */
    size_t     sig_len;
    unsigned char *tbs;          /* copy of the signed bytes */
    size_t     tbs_len;
} ssh_cert_t;

/*
 * Parse a decoded certificate blob.  Every read is bounds-checked and
 * trailing bytes after the signature are refused.
 * Returns 0 and sets *out on success, -1 on any malformation.
 */
int ssh_cert_parse(const unsigned char *blob, size_t len, ssh_cert_t **out);

void ssh_cert_free(ssh_cert_t *cert);

/* 1 if the certificate's signature key equals one of the keys in cas. */
int ssh_cert_ca_is_trusted(const ssh_cert_t *cert, const key_list_t *cas);

/*
 * Verify the CA signature over the to-be-signed bytes.
 * Returns 0 when it verifies, -1 when it does not, and -2 when sig_algo
 * is not one of ssh-ed25519, rsa-sha2-256, rsa-sha2-512.
 */
int ssh_cert_verify_ca_signature(const ssh_cert_t *cert);

/*
 * Does `list`, a source-address critical option (comma-separated CIDR
 * masks, as ssh-keygen -O source-address writes), permit `addr`?
 *
 * Returns 1 permitted, 0 not permitted, -1 when the question cannot be
 * answered: a malformed list, or an address that is not a numeric IPv4 or
 * IPv6 address.  The caller refuses on -1; an address the module cannot
 * parse must never satisfy a restriction.
 */
int ssh_cert_address_permitted(const char *list, const char *addr);

#endif /* SSH_CERT_H */
