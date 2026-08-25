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

