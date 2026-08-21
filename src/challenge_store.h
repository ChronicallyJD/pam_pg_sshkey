/*
 * challenge_store.h
 *
 * Simple filesystem-backed challenge store.
 *
 * Each challenge is stored as a file:
 *   <challenge_dir>/<challenge_hex>
 *
 * File contents: <unix_timestamp_issued>\n<hex_challenge_bytes>\n
 *
 * Challenges expire after CHALLENGE_TTL_SECS seconds.
 * The challenge server (pg_sshkey_challenge) creates these files;
 * the PAM module reads and deletes them.
 */

#ifndef CHALLENGE_STORE_H
#define CHALLENGE_STORE_H

#include <stddef.h>

/* Challenges expire after 60 seconds */
#define CHALLENGE_TTL_SECS 60

/* Upper bound on stale nonces removed per challenge_sweep() call */
#define CHALLENGE_SWEEP_MAX 256

/*
 * Files older than this are swept.  Twice the TTL: a v2 marker is written
 * when the token is *accepted*, which may be up to TTL after its timestamp,
 * and it must outlive every moment at which that token could still pass
 * the timestamp check.
 */
#define CHALLENGE_SWEEP_AGE_SECS (2 * CHALLENGE_TTL_SECS)

/*
 * Load a challenge by its hex ID.
 *
 * @param dir          Directory containing challenge files.
 * @param challenge_hex Hex string naming the challenge file.
 * @param out_bytes    Output buffer for raw challenge bytes.
 * @param out_size     Size of output buffer.
 * @param out_len      Set to the number of bytes decoded.
 *
 * Returns 0 on success, -1 if not found / expired / corrupt.
 * Expired challenges are deleted automatically.
 */
int challenge_load(const char    *dir,
                   const char    *challenge_hex,
                   unsigned char *out_bytes,
                   size_t         out_size,
                   size_t        *out_len);

/*
 * Delete a challenge file (call immediately after successful load).
 * Returns 0 if the file was removed, -1 (errno set) otherwise.  A consumer
 * must treat failure as fatal, an unremovable nonce can be replayed.
 */
int challenge_delete(const char *dir, const char *challenge_hex);

/*
 * v2: record a client-issued nonce as used.
 *
 * Atomically creates <dir>/<nonce_hex> (O_CREAT|O_EXCL, mode 0600).  Call
 * it only AFTER the signature verified, so garbage tokens create nothing.
 *
 * Returns  0  recorded, first use, accept
 *          1  already present, replay, reject
 *         -1  could not record (errno set), fail closed, reject
 */
int challenge_mark(const char *dir, const char *nonce_hex);

/*
 * Remove stale nonce files from dir.
 *
 * Clients create a nonce for every connection attempt but only a successful
 * authentication consumes it; without a sweeper a reconnect loop against a
 * down server fills the directory until reboot.  The PAM module (running as
 * the directory owner) calls this on every authentication.
 *
 * Only regular files whose name is exactly 64 hex characters and whose mtime
 * is older than CHALLENGE_SWEEP_AGE_SECS are touched, anything else in the
 * directory is left alone.  At most max_unlink files are removed per call so
 * the cost of one authentication stays bounded.
 *
 * Returns the number of files removed, or -1 if dir cannot be opened.
 */
int challenge_sweep(const char *dir, int max_unlink);

/*
 * Generate and store a new challenge.
 *
 * @param dir           Directory to store challenge files (must exist).
 * @param out_hex       Output buffer for the hex challenge ID (≥65 bytes).
 *
 * Returns 0 on success, -1 on error.
 */
int challenge_create(const char *dir, char *out_hex, size_t out_hex_size);

#endif /* CHALLENGE_STORE_H */
