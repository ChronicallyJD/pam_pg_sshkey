/*
 * test_system.c
 *
 * System-level tests for pg_sshkey_challenge and pg_sshkey_sign.
 * Exercises the compiled binaries end-to-end as a user would.
 *
 * Requires pg_sshkey_challenge and pg_sshkey_sign in PATH.
 * The Makefile test target runs it as PATH="$(CURDIR):$PATH" tests/test_system.
 *
 * Tests:
 *   pg_sshkey_challenge:
 *     - produces a 64-char lowercase hex nonce
 *     - creates a nonce file in the challenge directory
 *     - nonce file mode is 0644 (also under umask 077)
 *     - successive nonces are unique
 *     - auto-creates the challenge directory if absent
 *     - fails on an unwritable directory
 *
 *   pg_sshkey_sign:
 *     - signs with an OpenSSH Ed25519 key (unencrypted)
 *     - signs with a PKCS#8 PEM Ed25519 key
 *     - signs with a PKCS#8 PEM RSA-2048 key
 *     - token hex prefix matches the input challenge
 *     - fails on a missing key file
 *     - fails on an invalid (too-short) challenge
 *
 *   Pipeline:
 *     - two challenges produce two different valid tokens
 *     - nonce file is present on disk before the PAM module consumes it
 *
 * SPDX-License-Identifier: MIT
 */

#include "test_framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* ── helpers ─────────────────────────────────────────────────────────────── */

static char g_dir[256];

static void mk_dir(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/pam_sys_%d", (int)getpid());
    mkdir(g_dir, 01733);
}

static void rm_dir(void) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir);
    system(cmd);
}

/* Run cmd via popen, capture stdout into out (NUL-terminated, newline stripped).
   Returns the exit code of the command. */
static int
run_capture(const char *cmd, char *out, size_t out_size)
{
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    size_t n = fread(out, 1, out_size - 1, p);
    out[n] = '\0';
    int status = pclose(p);
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    if (n > 0 && out[n-1] == '\n') out[n-1] = '\0';
    return rc;
}

/* 1 iff str is exactly 64 lowercase hex chars */
static int is_hex64(const char *s) {
    if (strlen(s) != 64) return 0;
    for (int i = 0; i < 64; i++)
        if (!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f'))) return 0;
    return 1;
}

/* 1 iff str matches <64hex>:<base64> */
static int is_valid_token(const char *s) {
    const char *c = strchr(s, ':');
    if (!c || c - s != 64) return 0;
    for (const char *p = s; p < c; p++)
        if (!(((*p)>='0'&&(*p)<='9')||((*p)>='a'&&(*p)<='f'))) return 0;
    const char *b = c + 1;
    if (strlen(b) < 4) return 0;
    for (const char *p = b; *p; p++) {
        char ch = *p;
        if (!((ch>='A'&&ch<='Z')||(ch>='a'&&ch<='z')||
              (ch>='0'&&ch<='9')||ch=='+'||ch=='/'||ch=='=')) return 0;
    }
    return 1;
}

/*
 * Write a Python script to a temp file, run it, unlink it.
 * This avoids all shell quoting issues with inline -c strings.
 */
static int
run_python_script(const char *script_body, const char *args)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/pam_test_script_%d.py", (int)getpid());
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(script_body, f);
    fclose(f);
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "python3 %s %s 2>/dev/null", path, args ? args : "");
    int rc = system(cmd);
    unlink(path);
    return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

/* Generate an OpenSSH Ed25519 key pair via a Python script file */
static int
gen_openssh_ed25519(const char *priv_path, const char *pub_path)
{
    const char *script =
        "import sys, struct, base64, os, subprocess\n"
        "priv = sys.argv[1]\n"
        "pub  = sys.argv[2]\n"
        "r = subprocess.run(['openssl','genpkey','-algorithm','ed25519'],\n"
        "                   capture_output=True)\n"
        "pem = r.stdout\n"
        "pd = subprocess.run(\n"
        "    ['openssl','pkey','-in','/dev/stdin','-outform','DER'],\n"
        "    input=pem, capture_output=True).stdout\n"
        "seed = pd[-32:]\n"
        "kd = subprocess.run(\n"
        "    ['openssl','pkey','-in','/dev/stdin','-pubout','-outform','DER'],\n"
        "    input=pem, capture_output=True).stdout\n"
        "pubkey = kd[-32:]\n"
        "def ss(d):\n"
        "    if isinstance(d, str): d = d.encode()\n"
        "    return struct.pack('>I', len(d)) + d\n"
        "pb = ss('ssh-ed25519') + ss(pubkey)\n"
        "chk = os.urandom(4)\n"
        "ps = chk + chk + ss('ssh-ed25519') + ss(pubkey) + ss(seed + pubkey) + ss('')\n"
        "ps += bytes(range(1, 1 + (8 - len(ps) % 8) % 8))\n"
        "body = (b'openssh-key-v1\\x00' + ss('none') + ss('none') + ss('')\n"
        "        + struct.pack('>I', 1) + ss(pb) + ss(ps))\n"
        "b64 = base64.b64encode(body).decode()\n"
        "wrapped = '\\n'.join(b64[i:i+70] for i in range(0, len(b64), 70))\n"
        "open(priv, 'w').write(\n"
        "    '-----BEGIN OPENSSH PRIVATE KEY-----\\n'\n"
        "    + wrapped + '\\n'\n"
        "    + '-----END OPENSSH PRIVATE KEY-----\\n')\n"
        "pb64 = base64.b64encode(ss('ssh-ed25519') + ss(pubkey)).decode()\n"
        "open(pub, 'w').write('ssh-ed25519 ' + pb64 + ' test\\n')\n";

    char args[1024];
    snprintf(args, sizeof(args), "%s %s", priv_path, pub_path);
    return run_python_script(script, args);
}

static int gen_pkcs8_ed25519(const char *path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "openssl genpkey -algorithm ed25519 -out %s 2>/dev/null", path);
    return system(cmd) == 0 ? 0 : -1;
}

static int gen_pkcs8_rsa(const char *path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048"
        " -out %s 2>/dev/null", path);
    return system(cmd) == 0 ? 0 : -1;
}

/* ── pg_sshkey_challenge tests ────────────────────────────────────────────── */

static void test_challenge_produces_hex64(void) {
    mk_dir();
    char cmd[512], out[256];
    snprintf(cmd, sizeof(cmd), "pg_sshkey_challenge %s 2>/dev/null", g_dir);
    int rc = run_capture(cmd, out, sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_TRUE(is_hex64(out));
    rm_dir();
}

static void test_challenge_creates_file(void) {
    mk_dir();
    char cmd[512], out[256];
    snprintf(cmd, sizeof(cmd), "pg_sshkey_challenge %s 2>/dev/null", g_dir);
    run_capture(cmd, out, sizeof(out));
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_dir, out);
    struct stat st;
    ASSERT_EQ(stat(path, &st), 0);
    rm_dir();
}

static void test_challenge_file_mode_0644(void) {
    mk_dir();
    char cmd[512], out[256];
    snprintf(cmd, sizeof(cmd), "pg_sshkey_challenge %s 2>/dev/null", g_dir);
    run_capture(cmd, out, sizeof(out));
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_dir, out);
    struct stat st;
    stat(path, &st);
    ASSERT_EQ((int)(st.st_mode & 0777), 0644);
    rm_dir();
}

static void test_challenge_unique(void) {
    mk_dir();
    char cmd[512], out1[256], out2[256];
    snprintf(cmd, sizeof(cmd), "pg_sshkey_challenge %s 2>/dev/null", g_dir);
    run_capture(cmd, out1, sizeof(out1));
    run_capture(cmd, out2, sizeof(out2));
    ASSERT_TRUE(strcmp(out1, out2) != 0);
    rm_dir();
}

static void test_challenge_autocreates_dir(void) {
    char newdir[512];
    snprintf(newdir, sizeof(newdir), "/tmp/pam_sys_new_%d", (int)getpid());
    char cmd[512], out[256];
    snprintf(cmd, sizeof(cmd), "pg_sshkey_challenge %s 2>/dev/null", newdir);
    int rc = run_capture(cmd, out, sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_TRUE(is_hex64(out));
    struct stat st;
    ASSERT_EQ(stat(newdir, &st), 0);
    char rmcmd[512];
    snprintf(rmcmd, sizeof(rmcmd), "rm -rf %s", newdir);
    system(rmcmd);
}

static void test_challenge_fails_unwritable_dir(void) {
    char cmd[256], out[256];
    /* /proc/1 exists but is not writable by non-root */
    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_challenge /proc/1/pam_test_nonexistent 2>/dev/null");
    int rc = run_capture(cmd, out, sizeof(out));
    ASSERT_NE(rc, 0);
}

static void test_challenge_file_mode_0644_under_umask_077(void) {
    /* A client running under a restrictive umask (systemd services, cron)
       must still produce a nonce the postgres-run PAM module can read. */
    mk_dir();
    char cmd[512], out[256];
    snprintf(cmd, sizeof(cmd), "umask 077; pg_sshkey_challenge %s 2>/dev/null", g_dir);
    int rc = run_capture(cmd, out, sizeof(out));
    ASSERT_EQ(rc, 0);
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_dir, out);
    struct stat st;
    ASSERT_EQ(stat(path, &st), 0);
    ASSERT_EQ((int)(st.st_mode & 0777), 0644);
    rm_dir();
}

/* ── pg_sshkey_sign tests ─────────────────────────────────────────────────── */

static void test_sign_openssh_ed25519(void) {
    mk_dir();
    char priv[512], pub[512], chal[256], cmd[1024], out[512];
    snprintf(priv, sizeof(priv), "%s/id_ed25519",     g_dir);
    snprintf(pub,  sizeof(pub),  "%s/id_ed25519.pub", g_dir);
    ASSERT_EQ(gen_openssh_ed25519(priv, pub), 0);

    char chaldir[512];
    snprintf(chaldir, sizeof(chaldir), "%s/chal", g_dir);
    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_challenge %s 2>/dev/null", chaldir);
    run_capture(cmd, chal, sizeof(chal));
    ASSERT_TRUE(is_hex64(chal));

    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_sign %s %s 2>/dev/null", chal, priv);
    int rc = run_capture(cmd, out, sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_TRUE(is_valid_token(out));
    rm_dir();
}

static void test_sign_pkcs8_ed25519(void) {
    mk_dir();
    char priv[512], chal[256], cmd[1024], out[512];
    snprintf(priv, sizeof(priv), "%s/ed25519.pem", g_dir);
    ASSERT_EQ(gen_pkcs8_ed25519(priv), 0);

    char chaldir[512];
    snprintf(chaldir, sizeof(chaldir), "%s/chal", g_dir);
    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_challenge %s 2>/dev/null", chaldir);
    run_capture(cmd, chal, sizeof(chal));

    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_sign %s %s 2>/dev/null", chal, priv);
    int rc = run_capture(cmd, out, sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_TRUE(is_valid_token(out));
    rm_dir();
}

static void test_sign_pkcs8_rsa(void) {
    mk_dir();
    char priv[512], chal[256], cmd[1024], out[1024];
    snprintf(priv, sizeof(priv), "%s/rsa.pem", g_dir);
    ASSERT_EQ(gen_pkcs8_rsa(priv), 0);

    char chaldir[512];
    snprintf(chaldir, sizeof(chaldir), "%s/chal", g_dir);
    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_challenge %s 2>/dev/null", chaldir);
    run_capture(cmd, chal, sizeof(chal));

    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_sign %s %s 2>/dev/null", chal, priv);
    int rc = run_capture(cmd, out, sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_TRUE(is_valid_token(out));
    rm_dir();
}

static void test_sign_token_hex_matches_challenge(void) {
    mk_dir();
    char priv[512], chal[256], cmd[1024], out[512];
    snprintf(priv, sizeof(priv), "%s/ed25519.pem", g_dir);
    gen_pkcs8_ed25519(priv);

    char chaldir[512];
    snprintf(chaldir, sizeof(chaldir), "%s/chal", g_dir);
    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_challenge %s 2>/dev/null", chaldir);
    run_capture(cmd, chal, sizeof(chal));

    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_sign %s %s 2>/dev/null", chal, priv);
    run_capture(cmd, out, sizeof(out));

    char token_hex[65] = {0};
    strncpy(token_hex, out, 64);
    ASSERT_STR_EQ(token_hex, chal);
    rm_dir();
}

static void test_sign_fails_missing_key(void) {
    mk_dir();
    char chal[256], cmd[512], out[256];
    char chaldir[512];
    snprintf(chaldir, sizeof(chaldir), "%s/chal", g_dir);
    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_challenge %s 2>/dev/null", chaldir);
    run_capture(cmd, chal, sizeof(chal));

    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_sign %s /tmp/no_such_key_pam_test.pem 2>/dev/null", chal);
    int rc = run_capture(cmd, out, sizeof(out));
    ASSERT_NE(rc, 0);
    rm_dir();
}

static void test_sign_fails_invalid_hex_challenge(void) {
    mk_dir();
    char priv[512], cmd[512], out[256];
    snprintf(priv, sizeof(priv), "%s/ed25519.pem", g_dir);
    gen_pkcs8_ed25519(priv);

    /* A string with non-hex characters must fail format validation */
    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_sign not-valid-hex-at-all %s 2>/dev/null", priv);
    int rc = run_capture(cmd, out, sizeof(out));
    ASSERT_NE(rc, 0);
    rm_dir();
}

/* ── pg_sshkey_sign v2 (self-issued challenge) ───────────────────────────── */

/* 1 iff str matches <digits>:<64hex>:<base64>; stores ts */
static int parse_v2(const char *s, long *ts) {
    char *end; *ts = strtol(s, &end, 10);
    if (end == s || *end != ':') return 0;
    return is_valid_token(end + 1);
}

static void test_sign_v2_needs_no_challenge(void) {
    mk_dir();
    char priv[512], cmd[1024], out[1024];
    snprintf(priv, sizeof(priv), "%s/ed25519.pem", g_dir);
    gen_pkcs8_ed25519(priv);

    long before = (long)time(NULL);
    snprintf(cmd, sizeof(cmd), "pg_sshkey_sign %s 2>/dev/null", priv);
    int rc = run_capture(cmd, out, sizeof(out));
    long after = (long)time(NULL);
    ASSERT_EQ(rc, 0);
    long ts = 0;
    ASSERT_TRUE(parse_v2(out, &ts));
    ASSERT_TRUE(ts >= before && ts <= after);
    rm_dir();
}

static void test_sign_v2_tokens_are_unique(void) {
    mk_dir();
    char priv[512], cmd[1024], t1[1024], t2[1024];
    snprintf(priv, sizeof(priv), "%s/ed25519.pem", g_dir);
    gen_pkcs8_ed25519(priv);
    snprintf(cmd, sizeof(cmd), "pg_sshkey_sign %s 2>/dev/null", priv);
    run_capture(cmd, t1, sizeof(t1));
    run_capture(cmd, t2, sizeof(t2));
    long ts;
    ASSERT_TRUE(parse_v2(t1, &ts));
    ASSERT_TRUE(parse_v2(t2, &ts));
    ASSERT_TRUE(strcmp(t1, t2) != 0);
    rm_dir();
}

static void test_sign_v2_at_and_nonce_overrides(void) {
    /* --at / --nonce exist so tests can build expired or colliding tokens */
    mk_dir();
    char priv[512], cmd[1024], out[1024];
    snprintf(priv, sizeof(priv), "%s/ed25519.pem", g_dir);
    gen_pkcs8_ed25519(priv);
    const char *nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_sign --at 1700000000 --nonce %s %s 2>/dev/null", nonce, priv);
    ASSERT_EQ(run_capture(cmd, out, sizeof(out)), 0);
    char expect[96]; snprintf(expect, sizeof(expect), "1700000000:%s:", nonce);
    ASSERT_TRUE(strncmp(out, expect, strlen(expect)) == 0);
    rm_dir();
}

/* ── Pipeline tests ───────────────────────────────────────────────────────── */

static void test_pipeline_two_challenges_two_tokens(void) {
    mk_dir();
    char priv[512], chal1[256], chal2[256];
    char cmd[1024], tok1[512], tok2[512];

    snprintf(priv, sizeof(priv), "%s/ed25519.pem", g_dir);
    gen_pkcs8_ed25519(priv);

    char chaldir[512];
    snprintf(chaldir, sizeof(chaldir), "%s/chal", g_dir);
    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_challenge %s 2>/dev/null", chaldir);

    run_capture(cmd, chal1, sizeof(chal1));
    run_capture(cmd, chal2, sizeof(chal2));
    ASSERT_TRUE(strcmp(chal1, chal2) != 0);

    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_sign %s %s 2>/dev/null", chal1, priv);
    run_capture(cmd, tok1, sizeof(tok1));

    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_sign %s %s 2>/dev/null", chal2, priv);
    run_capture(cmd, tok2, sizeof(tok2));

    ASSERT_TRUE(is_valid_token(tok1));
    ASSERT_TRUE(is_valid_token(tok2));
    ASSERT_TRUE(strcmp(tok1, tok2) != 0);
    rm_dir();
}

static void test_pipeline_nonce_file_present_before_auth(void) {
    mk_dir();
    char chaldir[512], cmd[512], chal[256];
    snprintf(chaldir, sizeof(chaldir), "%s/chal", g_dir);
    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_challenge %s 2>/dev/null", chaldir);
    run_capture(cmd, chal, sizeof(chal));
    ASSERT_TRUE(is_hex64(chal));

    /* Nonce file must exist until PAM module consumes it */
    char nonce_path[512];
    snprintf(nonce_path, sizeof(nonce_path), "%s/%s", chaldir, chal);
    struct stat st;
    ASSERT_EQ(stat(nonce_path, &st), 0);
    rm_dir();
}

/* ── main ─────────────────────────────────────────────────────────────────── */
int main(void) {
    if (system("which pg_sshkey_challenge >/dev/null 2>&1") != 0 ||
        system("which pg_sshkey_sign >/dev/null 2>&1") != 0) {
        fprintf(stderr,
            "SKIP: pg_sshkey_challenge and/or pg_sshkey_sign not in PATH.\n"
            "The Makefile test target adds the build directory automatically.\n"
            "To run manually: PATH=$(pwd):$PATH tests/test_system\n");
        return 0;
    }

    printf("=== system (tool pipeline) ===\n");
    RUN(test_challenge_produces_hex64);
    RUN(test_challenge_creates_file);
    RUN(test_challenge_file_mode_0644);
    RUN(test_challenge_file_mode_0644_under_umask_077);
    RUN(test_challenge_unique);
    RUN(test_challenge_autocreates_dir);
    RUN(test_challenge_fails_unwritable_dir);
    RUN(test_sign_openssh_ed25519);
    RUN(test_sign_pkcs8_ed25519);
    RUN(test_sign_pkcs8_rsa);
    RUN(test_sign_token_hex_matches_challenge);
    RUN(test_sign_fails_missing_key);
    RUN(test_sign_fails_invalid_hex_challenge);
    RUN(test_sign_v2_needs_no_challenge);
    RUN(test_sign_v2_tokens_are_unique);
    RUN(test_sign_v2_at_and_nonce_overrides);
    RUN(test_pipeline_two_challenges_two_tokens);
    RUN(test_pipeline_nonce_file_present_before_auth);
    return SUMMARY();
}
