/*
 * ssh_agent.h
 *
 * Sign through a running ssh-agent over the socket in $SSH_AUTH_SOCK.
 *
 * The agent holds the private key, so pg_sshkey_sign never reads it: this
 * is the only way to use a passphrase-protected key, an OpenSSH-format RSA
 * key, or a key on another machine reached by agent forwarding.
 *
 * The agent returns an SSH wire signature ("string algo | string bytes").
 * These functions hand back the inner bytes, which is what the PAM module
 * verifies: 64 raw bytes for Ed25519, PKCS#1 v1.5 with SHA-256 for RSA.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef SSH_AGENT_H
#define SSH_AGENT_H

#include <stddef.h>

/*
 * Read the base64 field of an OpenSSH public key or certificate file and
 * return the decoded blob.  On error prints the reason and returns NULL.
 */
unsigned char *ssh_pubkey_blob_from_file(const char *path, size_t *len_out);

/*
 * Ask the agent to sign msg with the identity whose public blob is keyblob.
 * Returns malloc'd raw signature bytes, or NULL with the reason on stderr.
 *
 * Refused, because the PAM module could not verify the result:
 *   - sk-* keys (the signature carries extra authenticator fields)
 *   - an agent that answers an RSA request with a SHA-1 "ssh-rsa" signature
 */
unsigned char *ssh_agent_sign(const unsigned char *keyblob, size_t blob_len,
                              const unsigned char *msg, size_t msg_len,
                              size_t *sig_len_out);

#endif /* SSH_AGENT_H */
