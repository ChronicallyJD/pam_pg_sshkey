/*
 * challenge_store.c, filesystem-backed nonce store.
 * See challenge_store.h for full documentation.
 *
 * SPDX-License-Identifier: MIT
 */

#include "challenge_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>

#include <openssl/rand.h>

/* ── helpers ─────────────────────────────────────────────────────────── */

/* Convert hex string to bytes.  Returns number of bytes, -1 on error. */
static int
hex_to_bytes(const char *hex, unsigned char *out, size_t out_size)
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
    return (int)(hexlen / 2);
}

/* Convert bytes to lowercase hex string (buf must be >= 2*len+1). */
static void
bytes_to_hex(const unsigned char *bytes, size_t len, char *hex)
{
    for (size_t i = 0; i < len; i++)
        sprintf(hex + 2 * i, "%02x", bytes[i]);
    hex[2 * len] = '\0';
}

/* ── challenge_load ──────────────────────────────────────────────────── */
int
challenge_load(const char    *dir,
               const char    *challenge_hex,
               unsigned char *out_bytes,
               size_t         out_size,
               size_t        *out_len)
{
    /* Validate challenge_hex is hex-only (path-traversal guard) */
    for (const char *p = challenge_hex; *p; p++) {
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
              (*p >= 'A' && *p <= 'F'))) {
            return -1;
        }
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, challenge_hex);

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    long ts_issued = 0;
    char hex_data[256] = {0};
    if (fscanf(f, "%ld\n%255s\n", &ts_issued, hex_data) != 2) {
        fclose(f);
        challenge_delete(dir, challenge_hex);
        return -1;
    }
    fclose(f);

    /* Check expiry */
    time_t now = time(NULL);
    if (now - (time_t)ts_issued > CHALLENGE_TTL_SECS) {
        challenge_delete(dir, challenge_hex);
        return -1;
    }

    int nbytes = hex_to_bytes(hex_data, out_bytes, out_size);
    if (nbytes < 0)
        return -1;

    *out_len = (size_t)nbytes;
    return 0;
}

/* ── challenge_delete ────────────────────────────────────────────────── */
/*
 * Returns 0 when the nonce file was removed, -1 (errno set) otherwise.
 * Callers that consume a nonce MUST treat failure as fatal: a nonce that
 * cannot be removed can be replayed until it expires.
 */
int
challenge_delete(const char *dir, const char *challenge_hex)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, challenge_hex);
    return unlink(path) == 0 ? 0 : -1;
}

/* ── challenge_sweep ─────────────────────────────────────────────────── */
static int
is_hex64(const char *name)
{
    size_t n = 0;
    for (; name[n]; n++) {
        char c = name[n];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return 0;
    }
    return n == 64;
}

int
challenge_sweep(const char *dir, int max_unlink)
{
    DIR *d = opendir(dir);
    if (!d)
        return -1;

    time_t now = time(NULL);
    int removed = 0;
    struct dirent *de;

    while (removed < max_unlink && (de = readdir(d)) != NULL) {
        if (!is_hex64(de->d_name))
            continue;

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);

        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        if (now - st.st_mtime <= CHALLENGE_SWEEP_AGE_SECS)
            continue;                       /* still live */

        if (unlink(path) == 0)
            removed++;
    }

    closedir(d);
    return removed;
}

/* ── challenge_mark (v2) ─────────────────────────────────────────────── */
int
challenge_mark(const char *dir, const char *nonce_hex)
{
    if (!is_hex64(nonce_hex))
        return -1;

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, nonce_hex);

    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        return errno == EEXIST ? 1 : -1;

    /* content is informational; the file's existence is the record */
    FILE *f = fdopen(fd, "w");
    if (f) {
        fprintf(f, "%ld\n%s\n", (long)time(NULL), nonce_hex);
        fclose(f);
    } else {
        close(fd);
    }
    return 0;
}

/* ── challenge_create ────────────────────────────────────────────────── */
int
challenge_create(const char *dir, char *out_hex, size_t out_hex_size)
{
    if (out_hex_size < 65) /* 32 bytes × 2 + NUL */
        return -1;

    /* Generate 32 random bytes using OpenSSL */
    unsigned char raw[32];
    if (RAND_bytes(raw, sizeof(raw)) != 1)
        return -1;

    char hex[65];
    bytes_to_hex(raw, sizeof(raw), hex);

    /* Use the hex as the file name AND the challenge ID */
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, hex);

    /*
     * Write atomically (O_EXCL prevents overwrite).
     *
     * Use 0644 so the PostgreSQL backend (running as 'postgres') can read
     * nonce files created by any client user.  The challenge directory uses
     * the sticky bit (mode 1733) so only the creator of a file can delete
     * it, preventing one user removing another's pending challenge.
     */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0)
        return -1;

    /* open() applies the caller's umask; a client under umask 077 would
       leave a 0600 nonce that the postgres-run module cannot read. */
    if (fchmod(fd, 0644) != 0) {
        close(fd);
        unlink(path);
        return -1;
    }

    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        unlink(path);
        return -1;
    }

    fprintf(f, "%ld\n%s\n", (long)time(NULL), hex);
    fclose(f);

    strncpy(out_hex, hex, out_hex_size - 1);
    out_hex[out_hex_size - 1] = '\0';
    return 0;
}
