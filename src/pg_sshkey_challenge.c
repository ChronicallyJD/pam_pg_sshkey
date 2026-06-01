/*
 * pg_sshkey_challenge.c
 *
 * Tiny challenge-issuance helper.
 *
 * PostgreSQL's BEFORE-connect hook (or a sidecar service) calls this
 * program to get a fresh nonce that the connecting client must sign.
 *
 * Usage:
 *   pg_sshkey_challenge <challenge_dir>
 *
 * Prints the challenge hex to stdout (no newline).
 * Exit code 0 on success, 1 on error.
 *
 * Typical integration:
 *   1. Client connects to a wrapper service.
 *   2. Wrapper runs `pg_sshkey_challenge /var/run/pg_sshkey` → gets HEX.
 *   3. Wrapper sends HEX to client over a secure channel.
 *   4. Client signs HEX with its SSH key, sends back HEX:BASE64SIG.
 *   5. Wrapper passes that string as the PostgreSQL password.
 *   6. PAM module verifies it.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#include "challenge_store.h"

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <challenge_dir>\n", argv[0]);
        return 1;
    }

    const char *dir = argv[1];

    /*
     * Ensure directory exists with sticky-bit world-write permissions
     * (mode 1733 = rwx-wx-wxt) so that:
     *   - Any user can create nonce files (w+x for group and other)
     *   - Only the file's owner can delete it (sticky bit)
     *   - The postgres user (PAM module) can read and delete any file (owner rwx)
     *
     * If the directory already exists we chmod it to the correct mode in
     * case it was created with wrong permissions (e.g. after a reboot when
     * /var/run is a tmpfs and the directory was recreated by a naive script).
     */
    if (mkdir(dir, 01733) != 0 && errno != EEXIST) {
        perror("mkdir");
        return 1;
    }

    char hex[65];
    if (challenge_create(dir, hex, sizeof(hex)) != 0) {
        fprintf(stderr, "Failed to create challenge\n");
        return 1;
    }

    printf("%s", hex);
    return 0;
}
