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
 */
void challenge_delete(const char *dir, const char *challenge_hex);

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
