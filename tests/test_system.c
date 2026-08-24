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
 *     - --cert prints a v3 token whose 4th field is the cert base64
 *     - --cert works with an RSA PEM key and RSA cert
 *     - --cert fails on a missing file or a non-certificate file
 *     - --cert signature verifies over the pg-sshkey-v3 message with the cert's key
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


/* 1 iff s starts with <digits>:<64hex>: ; stores ts */
static int parse_v2_head(const char *s, long *ts) {
    char *end; *ts = strtol(s, &end, 10);
    if (end == s || *end != ':') return 0;
    const char *n = end + 1;
    const char *c = strchr(n, ':');
    if (!c || c - n != 64) return 0;
    for (const char *p = n; p < c; p++)
        if (!((*p>='0'&&*p<='9')||(*p>='a'&&*p<='f'))) return 0;
    return 1;
}

/* ── pg_sshkey_sign v3 (certificate) ─────────────────────────────────────── */

/* Read the second whitespace field of a *-cert.pub file into out. */
static int
cert_b64_field(const char *path, char *out, size_t out_size)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[16384];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    fclose(f);
    char *sp = strchr(line, ' ');
    if (!sp) return -1;
    char *start = sp + 1;
    char *end = start;
    while (*end && *end != ' ' && *end != '\n') end++;
    size_t n = (size_t)(end - start);
    if (n + 1 > out_size) return -1;
    memcpy(out, start, n);
    out[n] = '\0';
    return 0;
}

/* Generate a CA and a user key with ssh-keygen and sign the user key.
   type is "ed25519" or "rsa"; the user private key ends up at priv,
   the certificate at <priv>-cert.pub. */
static int
gen_cert(const char *type, const char *priv, char *cert_out, size_t cert_size)
{
    char ca[512], cmd[2048];
    snprintf(ca, sizeof(ca), "%s/ca_%s", g_dir, type);
    snprintf(cert_out, cert_size, "%s-cert.pub", priv);
    snprintf(cmd, sizeof(cmd),
        "ssh-keygen -q -t ed25519 -N '' -f %s >/dev/null 2>&1 && "
        "ssh-keygen -q -t %s %s -N '' -f %s >/dev/null 2>&1 && "
        "ssh-keygen -q -s %s -I testid -n testuser -V -1m:+5m %s.pub >/dev/null 2>&1",
        ca, type, strcmp(type, "rsa") == 0 ? "-b 2048 -m PEM" : "", priv, ca, priv);
    return system(cmd) == 0 ? 0 : -1;
}

/* 1 iff s has exactly three ':' and the 4th field equals cert_b64 */
static int
v3_fourth_field_equals(const char *s, const char *cert_b64)
{
    int colons = 0; const char *last = NULL;
    for (const char *p = s; *p; p++) if (*p == ':') { colons++; last = p; }
    if (colons != 3) return 0;
    return strcmp(last + 1, cert_b64) == 0;
}

static void test_sign_cert_ed25519_prints_v3_token(void) {
    mk_dir();
    char priv[512], cert[512], cert_b64[8192], cmd[2048], out[16384];
    snprintf(priv, sizeof(priv), "%s/user_ed25519", g_dir);
    ASSERT_EQ(gen_cert("ed25519", priv, cert, sizeof(cert)), 0);
    ASSERT_EQ(cert_b64_field(cert, cert_b64, sizeof(cert_b64)), 0);

    const char *nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_sign --cert %s --at 1700000000 --nonce %s %s 2>/dev/null",
        cert, nonce, priv);
    int rc = run_capture(cmd, out, sizeof(out));
    ASSERT_EQ(rc, 0);
    char expect[96]; snprintf(expect, sizeof(expect), "1700000000:%s:", nonce);
    ASSERT_TRUE(strncmp(out, expect, strlen(expect)) == 0);
    ASSERT_TRUE(v3_fourth_field_equals(out, cert_b64));
    rm_dir();
}

static void test_sign_cert_rsa_pem_prints_v3_token(void) {
    mk_dir();
    char priv[512], cert[512], cert_b64[8192], cmd[2048], out[16384];
    snprintf(priv, sizeof(priv), "%s/user_rsa", g_dir);
    ASSERT_EQ(gen_cert("rsa", priv, cert, sizeof(cert)), 0);
    ASSERT_EQ(cert_b64_field(cert, cert_b64, sizeof(cert_b64)), 0);

    snprintf(cmd, sizeof(cmd), "pg_sshkey_sign --cert %s %s 2>/dev/null", cert, priv);
    int rc = run_capture(cmd, out, sizeof(out));
    ASSERT_EQ(rc, 0);
    long ts = 0;
    ASSERT_TRUE(parse_v2_head(out, &ts));
    ASSERT_TRUE(v3_fourth_field_equals(out, cert_b64));
    rm_dir();
}


/* 1 iff <g_dir>/err names the cert file and is not the unknown-option usage text */
static int
stderr_mentions_cert(const char *cert_name)
{
    char errpath[512]; snprintf(errpath, sizeof(errpath), "%s/err", g_dir);
    FILE *f = fopen(errpath, "r");
    if (!f) return 0;
    char buf[4096]; size_t n = fread(buf, 1, sizeof(buf) - 1, f); buf[n] = '\0';
    fclose(f);
    if (strstr(buf, "Unknown option")) return 0;
    return strstr(buf, cert_name) != NULL;
}

static void test_sign_cert_missing_file_fails(void) {
    mk_dir();
    char priv[512], cmd[2048], out[1024];
    snprintf(priv, sizeof(priv), "%s/ed25519.pem", g_dir);
    gen_pkcs8_ed25519(priv);
    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_sign --cert %s/no_such-cert.pub %s 2>%s/err", g_dir, priv, g_dir);
    int rc = run_capture(cmd, out, sizeof(out));
    ASSERT_EQ(rc, 1);
    ASSERT_STR_EQ(out, "");
    ASSERT_TRUE(stderr_mentions_cert("no_such-cert.pub"));
    rm_dir();
}

static void test_sign_cert_not_a_cert_fails(void) {
    /* A plain public key is not a certificate: first field lacks -cert-v01@openssh.com */
    mk_dir();
    char priv[512], cert[512], pub[1024], cmd[2048], out[1024];
    snprintf(priv, sizeof(priv), "%s/user_ed25519", g_dir);
    ASSERT_EQ(gen_cert("ed25519", priv, cert, sizeof(cert)), 0);
    snprintf(pub, sizeof(pub), "%s.pub", priv);
    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_sign --cert %s %s 2>%s/err", pub, priv, g_dir);
    int rc = run_capture(cmd, out, sizeof(out));
    ASSERT_EQ(rc, 1);
    ASSERT_STR_EQ(out, "");
    ASSERT_TRUE(stderr_mentions_cert(pub));
    rm_dir();
}

static void test_sign_cert_unpadded_field_fails(void) {
    /* The server's decoder drops a final partial base64 group: refuse early */
    mk_dir();
    char priv[512], cert[512], bad[1024], cmd[2048], out[1024];
    snprintf(priv, sizeof(priv), "%s/user_ed25519", g_dir);
    ASSERT_EQ(gen_cert("ed25519", priv, cert, sizeof(cert)), 0);
    snprintf(bad, sizeof(bad), "%s/unpadded-cert.pub", g_dir);
    /* copy the cert line minus its last character (drops a padding byte) */
    snprintf(cmd, sizeof(cmd),
        "awk '{ sub(/.$/, \"\", $2); print $1, $2 }' %s > %s", cert, bad);
    ASSERT_EQ(system(cmd), 0);
    snprintf(cmd, sizeof(cmd),
        "pg_sshkey_sign --cert %s %s 2>%s/err", bad, priv, g_dir);
    int rc = run_capture(cmd, out, sizeof(out));
    ASSERT_EQ(rc, 1);
    ASSERT_STR_EQ(out, "");
    ASSERT_TRUE(stderr_mentions_cert("not padded base64"));
    rm_dir();
}

/* ── ssh-agent signing ────────────────────────────────────────────────── */

/* Write a .pub file whose blob names <type>, without needing that hardware. */
static int
fake_pubkey(const char *type, const char *path)
{
    static const char script[] =
        "import base64, struct, sys\n"
        "t = sys.argv[1].encode()\n"
        "blob = struct.pack('>I', len(t)) + t\n"
        "blob += struct.pack('>I', 32) + b'\\0' * 32\n"
        "blob += struct.pack('>I', 4) + b'ssh:'\n"
        "open(sys.argv[2], 'w').write('%s %s test\\n' %"
        " (sys.argv[1], base64.b64encode(blob).decode()))\n";
    char args[1024];
    snprintf(args, sizeof(args), "'%s' '%s'", type, path);
    return run_python_script(script, args);
}

static void test_agent_without_auth_sock_fails(void) {
    mk_dir();
    char priv[512], cmd[2048], out[1024];
    snprintf(priv, sizeof(priv), "%s/user_ed25519", g_dir);
    ASSERT_EQ(gen_cert("ed25519", priv, cmd, sizeof(cmd)), 0);   /* also writes .pub */
    snprintf(cmd, sizeof(cmd),
        "unset SSH_AUTH_SOCK; pg_sshkey_sign --agent %s.pub 2>%s/err", priv, g_dir);
    int rc = run_capture(cmd, out, sizeof(out));
    ASSERT_EQ(rc, 1);
    ASSERT_STR_EQ(out, "");
    ASSERT_TRUE(stderr_mentions_cert("SSH_AUTH_SOCK is not set"));
    rm_dir();
}

static void test_agent_security_key_types(void) {
    /*
     * sk-ecdsa needs an ECDSA verifier the server does not have, so it is
     * refused on the key type alone.  sk-ssh-ed25519 is supported and gets
     * past that check, failing later for want of an agent.
     */
    mk_dir();
    char pub[512], cmd[2048], out[1024];

    snprintf(pub, sizeof(pub), "%s/sk_ecdsa.pub", g_dir);
    ASSERT_EQ(fake_pubkey("sk-ecdsa-sha2-nistp256@openssh.com", pub), 0);
    snprintf(cmd, sizeof(cmd),
        "SSH_AUTH_SOCK=/nonexistent pg_sshkey_sign --agent %s 2>%s/err", pub, g_dir);
    ASSERT_EQ(run_capture(cmd, out, sizeof(out)), 1);
    ASSERT_STR_EQ(out, "");
    ASSERT_TRUE(stderr_mentions_cert("no ECDSA verifier"));

    snprintf(pub, sizeof(pub), "%s/sk_ed.pub", g_dir);
    ASSERT_EQ(fake_pubkey("sk-ssh-ed25519@openssh.com", pub), 0);
    snprintf(cmd, sizeof(cmd),
        "SSH_AUTH_SOCK=/nonexistent pg_sshkey_sign --agent %s 2>%s/err", pub, g_dir);
    ASSERT_EQ(run_capture(cmd, out, sizeof(out)), 1);
    ASSERT_FALSE(stderr_mentions_cert("no ECDSA verifier"));
    ASSERT_TRUE(stderr_mentions_cert("Cannot connect to the ssh-agent"));
    rm_dir();
}

static void test_agent_rejects_private_key_and_stray_positional(void) {
    mk_dir();
    char priv[512], cmd[2048], out[1024];
    snprintf(priv, sizeof(priv), "%s/user_ed25519", g_dir);
    ASSERT_EQ(gen_cert("ed25519", priv, cmd, sizeof(cmd)), 0);

    /* the PRIVATE key is not a public key line */
    snprintf(cmd, sizeof(cmd),
        "SSH_AUTH_SOCK=/nonexistent pg_sshkey_sign --agent %s 2>%s/err", priv, g_dir);
    ASSERT_EQ(run_capture(cmd, out, sizeof(out)), 1);
    ASSERT_TRUE(stderr_mentions_cert("not an OpenSSH public key line"));

    /* --agent replaces the private key argument, it does not accompany it */
    snprintf(cmd, sizeof(cmd),
        "SSH_AUTH_SOCK=/nonexistent pg_sshkey_sign --agent %s.pub %s 2>%s/err",
        priv, priv, g_dir);
    ASSERT_EQ(run_capture(cmd, out, sizeof(out)), 1);
    ASSERT_TRUE(stderr_mentions_cert("do not also pass a private key"));

    /* v1 has no agent flow */
    snprintf(cmd, sizeof(cmd),
        "SSH_AUTH_SOCK=/nonexistent pg_sshkey_sign --agent %s.pub %064d %s 2>%s/err",
        priv, 0, priv, g_dir);
    ASSERT_EQ(run_capture(cmd, out, sizeof(out)), 1);
    /* the usage text also contains "--agent": pin the refusal itself */
    ASSERT_TRUE(stderr_mentions_cert("--agent cannot be combined with a v1 challenge"));
    rm_dir();
}

static void test_sign_cert_signature_covers_v3_prefix(void) {
    /* The signature must be over "pg-sshkey-v3\0<ts>:<nonce>" with the key
       embedded in the certificate, else the server's v3 check cannot pass. */
    mk_dir();
    char priv[512], cert[512], cmd[2048], out[16384], tokpath[512];
    snprintf(priv, sizeof(priv), "%s/user_ed25519", g_dir);
    ASSERT_EQ(gen_cert("ed25519", priv, cert, sizeof(cert)), 0);
    snprintf(cmd, sizeof(cmd), "pg_sshkey_sign --cert %s %s 2>/dev/null", cert, priv);
    ASSERT_EQ(run_capture(cmd, out, sizeof(out)), 0);
    snprintf(tokpath, sizeof(tokpath), "%s/token", g_dir);
    FILE *tf = fopen(tokpath, "w"); ASSERT_TRUE(tf != NULL);
    fputs(out, tf); fclose(tf);

    const char *script =
        "import sys, struct, base64\n"
        "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey\n"
        "tok = open(sys.argv[1]).read().strip()\n"
        "ts, nonce, sig, cert = tok.split(':')\n"
        "blob = base64.b64decode(cert)\n"
        "pos = 0\n"
        "def rs():\n"
        "    global pos\n"
        "    n = struct.unpack('>I', blob[pos:pos+4])[0]; pos += 4\n"
        "    v = blob[pos:pos+n]; pos += n\n"
        "    return v\n"
        "assert rs() == b'ssh-ed25519-cert-v01@openssh.com'\n"
        "rs()  # cert nonce\n"
        "pk = Ed25519PublicKey.from_public_bytes(rs())\n"
        "pk.verify(base64.b64decode(sig), b'pg-sshkey-v3\\x00' + (ts + ':' + nonce).encode())\n";
    ASSERT_EQ(run_python_script(script, tokpath), 0);
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
    RUN(test_sign_cert_ed25519_prints_v3_token);
    RUN(test_sign_cert_rsa_pem_prints_v3_token);
    RUN(test_sign_cert_missing_file_fails);
    RUN(test_sign_cert_not_a_cert_fails);
    RUN(test_sign_cert_unpadded_field_fails);
    RUN(test_agent_without_auth_sock_fails);
    RUN(test_agent_security_key_types);
    RUN(test_agent_rejects_private_key_and_stray_positional);
    RUN(test_sign_cert_signature_covers_v3_prefix);
    RUN(test_pipeline_two_challenges_two_tokens);
    RUN(test_pipeline_nonce_file_present_before_auth);
    return SUMMARY();
}
