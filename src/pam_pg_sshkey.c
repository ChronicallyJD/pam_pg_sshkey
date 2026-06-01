/*
 * pam_pg_sshkey.c
 *
 * A PAM module that authenticates PostgreSQL users via SSH public keys.
 *
 * Authentication flow:
 *   1. PostgreSQL is configured to use PAM (auth method = pam in pg_hba.conf).
 *   2. The client presents a "token" as the PAM password. The token is a
 *      base64-encoded ED25519 or RSA signature over a server-issued challenge,
 *      produced by the client's SSH private key.
 *   3. This module reads the user's authorized_keys file, finds a matching
 *      public key, and verifies the signature with OpenSSL/libcrypto.
 *
 * Because PostgreSQL's PAM integration only passes username + password, the
 * "password" field carries:
 *
 *     <challenge_hex>:<base64_signature>
 *
 * The challenge_hex is a hex-encoded 32-byte random nonce that the server
 * previously issued and stored (see challenge_store.[ch]).  This module
 * looks up the stored challenge, verifies the signature, then invalidates
 * the challenge so it cannot be replayed.
 *
 * Build:
 *   gcc -shared -fPIC -o pam_pg_sshkey.so pam_pg_sshkey.c challenge_store.c \
 *       key_parser.c sig_verify.c \
 *       $(pkg-config --cflags --libs libcrypto) -lpam
 *
 * Install:
 *   sudo cp pam_pg_sshkey.so /lib/security/          (Debian/Ubuntu)
 *   sudo cp pam_pg_sshkey.so /lib64/security/        (RHEL/Fedora)
 *
 * /etc/pam.d/postgresql:
 *   auth  required  pam_pg_sshkey.so  authorized_keys_dir=/etc/pg_sshkeys \
 *                                     challenge_dir=/var/run/pg_sshkey       \
 *                                     debug
 *   account required pam_permit.so
 *
 * SPDX-License-Identifier: MIT
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>

#include "challenge_store.h"
#include "key_parser.h"
#include "sig_verify.h"

/* ── Module defaults ─────────────────────────────────────────────────── */
#define DEFAULT_AUTHKEYS_DIR   "/etc/pg_sshkeys"
#define DEFAULT_CHALLENGE_DIR  "/var/run/pg_sshkey"
#define MAX_TOKEN_LEN          4096
#define MAX_PATH_LEN           512

/* ── Option parsing ──────────────────────────────────────────────────── */
typedef struct {
    const char *authkeys_dir;
    const char *challenge_dir;
    int         debug;
} mod_opts_t;

static void
parse_opts(mod_opts_t *opts, int argc, const char **argv)
{
    opts->authkeys_dir  = DEFAULT_AUTHKEYS_DIR;
    opts->challenge_dir = DEFAULT_CHALLENGE_DIR;
    opts->debug         = 0;

    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "authorized_keys_dir=", 20) == 0)
            opts->authkeys_dir  = argv[i] + 20;
        else if (strncmp(argv[i], "challenge_dir=", 14) == 0)
            opts->challenge_dir = argv[i] + 14;
        else if (strcmp(argv[i], "debug") == 0)
            opts->debug = 1;
    }
}

/* ── Token parsing ───────────────────────────────────────────────────── */
/*
 * Token format: "<challenge_hex>:<base64_signature>"
 * Returns 0 on success, -1 on format error.
 */
static int
parse_token(const char *token,
            char       *challenge_hex,  size_t chex_size,
            char       *sig_b64,        size_t sig_size)
{
    const char *colon = strchr(token, ':');
    if (!colon)
        return -1;

    size_t chex_len = (size_t)(colon - token);
    if (chex_len == 0 || chex_len >= chex_size)
        return -1;

    memcpy(challenge_hex, token, chex_len);
    challenge_hex[chex_len] = '\0';

    const char *sig_start = colon + 1;
    size_t sig_len = strlen(sig_start);
    if (sig_len == 0 || sig_len >= sig_size)
        return -1;

    memcpy(sig_b64, sig_start, sig_len);
    sig_b64[sig_len] = '\0';

    return 0;
}

/* ── pam_sm_authenticate ─────────────────────────────────────────────── */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
                    int argc, const char **argv)
{
    mod_opts_t opts;
    parse_opts(&opts, argc, argv);

    /* ── 1. Get username ── */
    const char *username = NULL;
    int rc = pam_get_user(pamh, &username, "Username: ");
    if (rc != PAM_SUCCESS || !username || username[0] == '\0') {
        pam_syslog(pamh, LOG_ERR, "pam_pg_sshkey: failed to get username");
        return PAM_AUTH_ERR;
    }

    if (opts.debug)
        pam_syslog(pamh, LOG_DEBUG,
                   "pam_pg_sshkey: authenticating user '%s'", username);

    /* ── 2. Get token (passed as PAM "password") ── */
    const char *token = NULL;
    rc = pam_get_authtok(pamh, PAM_AUTHTOK, &token, "SSH-Key Token: ");
    if (rc != PAM_SUCCESS || !token || token[0] == '\0') {
        pam_syslog(pamh, LOG_ERR,
                   "pam_pg_sshkey: failed to get auth token for '%s'",
                   username);
        return PAM_AUTH_ERR;
    }

    /* ── 3. Parse token into challenge + signature ── */
    char challenge_hex[256];
    char sig_b64[MAX_TOKEN_LEN];

    if (parse_token(token, challenge_hex, sizeof(challenge_hex),
                    sig_b64, sizeof(sig_b64)) != 0) {
        pam_syslog(pamh, LOG_ERR,
                   "pam_pg_sshkey: malformed token for '%s'", username);
        return PAM_AUTH_ERR;
    }

    if (opts.debug)
        pam_syslog(pamh, LOG_DEBUG,
                   "pam_pg_sshkey: challenge=%s", challenge_hex);

    /* ── 4. Retrieve & validate challenge from store ── */
    unsigned char challenge_bytes[32];
    size_t        challenge_len = 0;

    rc = challenge_load(opts.challenge_dir, challenge_hex,
                        challenge_bytes, sizeof(challenge_bytes),
                        &challenge_len);
    if (rc != 0) {
        pam_syslog(pamh, LOG_WARNING,
                   "pam_pg_sshkey: challenge not found or expired for '%s'",
                   username);
        return PAM_AUTH_ERR;
    }

    /* Invalidate challenge immediately (prevent replay) */
    challenge_delete(opts.challenge_dir, challenge_hex);

    /* ── 5. Decode base64 signature ── */
    unsigned char sig_bytes[1024];
    size_t        sig_len = 0;

    if (b64_decode(sig_b64, sig_bytes, sizeof(sig_bytes), &sig_len) != 0) {
        pam_syslog(pamh, LOG_ERR,
                   "pam_pg_sshkey: base64 decode failed for '%s'", username);
        return PAM_AUTH_ERR;
    }

    /* ── 6. Build authorized_keys path ── */
    char authkeys_path[MAX_PATH_LEN];
    snprintf(authkeys_path, sizeof(authkeys_path),
             "%s/%s/authorized_keys", opts.authkeys_dir, username);

    if (opts.debug)
        pam_syslog(pamh, LOG_DEBUG,
                   "pam_pg_sshkey: authorized_keys path: %s", authkeys_path);

    /* Verify file exists and has safe permissions */
    struct stat st;
    if (stat(authkeys_path, &st) != 0) {
        pam_syslog(pamh, LOG_WARNING,
                   "pam_pg_sshkey: no authorized_keys for '%s': %s",
                   username, strerror(errno));
        return PAM_AUTH_ERR;
    }
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        pam_syslog(pamh, LOG_ERR,
                   "pam_pg_sshkey: authorized_keys for '%s' is world/group"
                   " writable — refusing", username);
        return PAM_AUTH_ERR;
    }

    /* ── 7. Iterate keys and verify signature ── */
    key_list_t *keys = NULL;
    int nkeys = parse_authorized_keys(authkeys_path, &keys);
    if (nkeys <= 0) {
        pam_syslog(pamh, LOG_WARNING,
                   "pam_pg_sshkey: no valid keys in '%s'", authkeys_path);
        return PAM_AUTH_ERR;
    }

    int authenticated = 0;
    for (key_list_t *k = keys; k != NULL; k = k->next) {
        if (opts.debug)
            pam_syslog(pamh, LOG_DEBUG,
                       "pam_pg_sshkey: trying key type=%s comment=%s",
                       k->key_type, k->comment ? k->comment : "(none)");

        int vrc = verify_signature(k,
                                   challenge_bytes, challenge_len,
                                   sig_bytes,       sig_len);
        if (vrc == 0) {
            pam_syslog(pamh, LOG_INFO,
                       "pam_pg_sshkey: user '%s' authenticated with key %s",
                       username, k->comment ? k->comment : k->key_type);
            authenticated = 1;
            break;
        }
    }

    free_key_list(keys);

    if (!authenticated) {
        pam_syslog(pamh, LOG_WARNING,
                   "pam_pg_sshkey: authentication failed for '%s'", username);
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
}

/* ── pam_sm_setcred  (required stub) ────────────────────────────────── */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
               int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

/* ── pam_sm_acct_mgmt (required stub) ───────────────────────────────── */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                 int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;

    /*
     * Verify the Unix account still exists.  The PostgreSQL user must
     * exist in the database independently, but this check ensures the
     * OS account is still active.
     */
    const char *username = NULL;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username)
        return PAM_ACCT_EXPIRED;

    struct passwd *pw = getpwnam(username);
    if (!pw) {
        pam_syslog(pamh, LOG_WARNING,
                   "pam_pg_sshkey: account '%s' not found in passwd",
                   username);
        return PAM_ACCT_EXPIRED;
    }
    return PAM_SUCCESS;
}
