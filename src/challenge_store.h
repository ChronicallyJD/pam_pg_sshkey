/*
 * challenge_store.h
 *
 * A record of the nonces that have been used.
 *
 * A client issues its own nonce and timestamp; the module records the nonce
 * as a file <challenge_dir>/<nonce_hex> once the token is accepted, so the
 * same token cannot be used twice.  Records older than
 * CHALLENGE_SWEEP_AGE_SECS are swept, because a token whose timestamp is
 * that old can no longer pass the window check.
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
 * Record a client-issued nonce as used.
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


#endif /* CHALLENGE_STORE_H */
