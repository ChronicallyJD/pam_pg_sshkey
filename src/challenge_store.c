/*
 * challenge_store.c — filesystem-backed nonce store.
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
void
challenge_delete(const char *dir, const char *challenge_hex)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, challenge_hex);
    unlink(path);
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

    /* Write atomically (O_EXCL prevents overwrite) */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        return -1;

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
