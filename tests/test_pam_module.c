/*
 * test_pam_module.c, tests at the libpam seam.
 *
 * Loads the freshly built pam_pg_sshkey.so through libpam exactly the way
 * PostgreSQL does (src/backend/libpq/auth.c, CheckPAMAuth):
 *
 *   pam_start_confdir(service, "pgsql@", &conv, confdir, &pamh)
 *   pam_set_item(PAM_USER, user)
 *   pam_set_item(PAM_CONV, &conv)
 *   pam_set_item(PAM_RHOST, client address)
 *   pam_authenticate(pamh, 0)
 *   pam_acct_mgmt(pamh, 0)
 *   pam_end(pamh, rc)
 *
 * The conversation function mirrors pam_passwd_conv_proc(): it answers
 * PAM_PROMPT_ECHO_OFF from appdata_ptr (the client "password") and never
 * talks to a terminal.  An empty password models "client sent nothing".
 *
 * Keys and tokens come from ssh-keygen and the built pg_sshkey_sign binary,
 * so the module only ever sees real client output.
 *
 * Environment:
 *   PAM_PG_SSHKEY_BUILDDIR   directory holding pam_pg_sshkey.so and the tools
 *                            (default: ".")
 *   PAM_TEST_KEEP=1          keep per-test temp dirs for inspection
 *   PAM_TEST_DEBUG=1         add `debug` to the module line (logs to syslog)
 *
 * The harness defines pam_syslog() itself (linked with -rdynamic) so every
 * line the module logs is captured and can be asserted with ASSERT_LOGGED.
 *
 * Runs unprivileged.  Never skips: a missing .so is a failure.
 *
 * SPDX-License-Identifier: MIT
 */

#include "test_framework.h"

#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <security/pam_appl.h>

/* ── log capture ──────────────────────────────────────────────────────── */
/*
 * The module logs through pam_syslog().  The harness is linked with
 * -rdynamic and defines pam_syslog itself, so the dynamic linker binds the
 * module's calls here (the executable's symbols win over libpam's for a
 * dlopen'ed library).  Each line is kept in a ring so tests can assert the
 * exact message the module emitted; it is also forwarded to syslog.
 */
#include <stdarg.h>
#include <syslog.h>

#define LOG_RING 64
static char g_log[LOG_RING][1024];
static int  g_log_n;

void
pam_syslog(const pam_handle_t *pamh, int priority, const char *fmt, ...)
{
    (void)pamh;
    va_list ap;
    va_start(ap, fmt);
    if (g_log_n < LOG_RING)
        vsnprintf(g_log[g_log_n++], sizeof(g_log[0]), fmt, ap);
    va_end(ap);
    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
    va_end(ap);
}

static void log_reset(void) { g_log_n = 0; }

/* 1 iff some line logged since the last authenticate() contains needle */
static int
log_contains(const char *needle)
{
    for (int i = 0; i < g_log_n; i++)
        if (strstr(g_log[i], needle)) return 1;
    return 0;
}

static void
log_dump(void)
{
    for (int i = 0; i < g_log_n; i++) fprintf(stderr, "      log: %s\n", g_log[i]);
}

/* ASSERT_LOGGED: the module emitted a line containing needle */
#define ASSERT_LOGGED(needle) \
    do { if (!log_contains(needle)) { _TF_FAIL("no log line contains \"%s\"", needle); log_dump(); } } while (0)

/* ── global paths ─────────────────────────────────────────────────────── */

static char g_so[PATH_MAX];
static char g_sign_bin[PATH_MAX];
static char g_test_dir[PATH_MAX];   /* this file's directory, for sk_helper.py */

#define SERVICE_AUTH "pam-pg-sshkey-test"
#define SERVICE_ACCT "pam-pg-sshkey-acct"

/* ── per-test environment ─────────────────────────────────────────────── */

typedef struct {
    char root[PATH_MAX];
    char confdir[PATH_MAX];   /* root/pam.d  */
    char keys[PATH_MAX];      /* root/keys   */
    char chal[PATH_MAX];      /* root/chal   */
    char ca_file[PATH_MAX];   /* root/trusted_ca_keys, "" when the option is off */
    char revoked_file[PATH_MAX]; /* root/revoked_keys, "" when the option is off */
    char agent_sock[PATH_MAX];/* root/agent.sock, "" when no agent was started */
    long agent_pid;           /* ssh-agent to kill in env_teardown */
} env_t;

static env_t *g_live_env = NULL;   /* for atexit cleanup on abort */

static int
run_capture(const char *cmd, char *out, size_t out_size)
{
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    size_t n = fread(out, 1, out_size - 1, p);
    out[n] = '\0';
    int status = pclose(p);
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    while (n > 0 && (out[n-1] == '\n' || out[n-1] == '\r')) out[--n] = '\0';
    return rc;
}

static void
write_file(const char *path, const char *content, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); exit(2); }
    fputs(content, f);
    fclose(f);
    chmod(path, mode);
}

static void
write_services(const env_t *e)
{
    char path[PATH_MAX], body[PATH_MAX * 2];
    const char *dbg = getenv("PAM_TEST_DEBUG") ? " debug" : "";

    char ca_opt[PATH_MAX + 32] = "";
    if (e->ca_file[0])
        snprintf(ca_opt, sizeof(ca_opt), " trusted_ca_keys=%s", e->ca_file);
    char rev_opt[PATH_MAX + 32] = "";
    if (e->revoked_file[0])
        snprintf(rev_opt, sizeof(rev_opt), " revoked_keys=%s", e->revoked_file);

    /* The cert tests add trusted_ca_keys=; every other test keeps the
       shipped shape of the line. */
    snprintf(body, sizeof(body),
             "#%%PAM-1.0\n"
             "auth    required  %s authorized_keys_dir=%s challenge_dir=%s%s%s%s\n"
             "account required  pam_permit.so\n",
             g_so, e->keys, e->chal, ca_opt, rev_opt, dbg);
    snprintf(path, sizeof(path), "%s/%s", e->confdir, SERVICE_AUTH);
    write_file(path, body, 0644);

    snprintf(body, sizeof(body),
             "#%%PAM-1.0\n"
             "account required  %s%s\n", g_so, dbg);
    snprintf(path, sizeof(path), "%s/%s", e->confdir, SERVICE_ACCT);
    write_file(path, body, 0644);
}

static void env_teardown(env_t *e);

static void
atexit_cleanup(void)
{
    if (g_live_env) env_teardown(g_live_env);
}

static void
env_setup(env_t *e)
{
    const char *tmp = getenv("TMPDIR");
    snprintf(e->root, sizeof(e->root), "%s/pam_mod_XXXXXX", tmp ? tmp : "/tmp");
    if (!mkdtemp(e->root)) { perror("mkdtemp"); exit(2); }

    snprintf(e->confdir, sizeof(e->confdir), "%s/pam.d", e->root);
    snprintf(e->keys,    sizeof(e->keys),    "%s/keys",  e->root);
    snprintf(e->chal,    sizeof(e->chal),    "%s/chal",  e->root);
    mkdir(e->confdir, 0755);
    mkdir(e->keys,    0755);
    mkdir(e->chal,    0700);
    chmod(e->chal,    0700);   /* mkdir honours umask; force the real mode */
    e->ca_file[0] = '\0';
    e->revoked_file[0] = '\0';
    e->agent_sock[0] = '\0';
    e->agent_pid = 0;

    write_services(e);
    g_live_env = e;
}

static void
env_teardown(env_t *e)
{
    g_live_env = NULL;
    if (e->agent_pid > 0) { kill((pid_t)e->agent_pid, SIGTERM); e->agent_pid = 0; }
    if (getenv("PAM_TEST_KEEP")) {
        fprintf(stderr, "    (kept %s)\n", e->root);
        return;
    }
    char cmd[PATH_MAX * 2 + 64];
    snprintf(cmd, sizeof(cmd), "chmod -R u+rwx '%s' && rm -rf '%s'", e->root, e->root);
    if (system(cmd) != 0) fprintf(stderr, "    warning: cleanup failed for %s\n", e->root);
}

/* ── key helpers ──────────────────────────────────────────────────────── */

/* Returns 0 on success; writes <root>/<name> and <root>/<name>.pub */
static int
gen_key(const env_t *e, const char *name, const char *keygen_args)
{
    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd),
             "ssh-keygen -q %s -N '' -C '%s' -f '%s/%s' </dev/null >/dev/null 2>&1",
             keygen_args, name, e->root, name);
    return system(cmd) == 0 ? 0 : -1;
}
static int gen_ed25519(const env_t *e, const char *name) { return gen_key(e, name, "-t ed25519"); }

/* Same, with a passphrase: only an agent can use the result. */
static int
gen_key_pass(const env_t *e, const char *name, const char *keygen_args,
             const char *passphrase)
{
    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd),
             "ssh-keygen -q %s -N '%s' -C '%s' -f '%s/%s' </dev/null >/dev/null 2>&1",
             keygen_args, passphrase, name, e->root, name);
    return system(cmd) == 0 ? 0 : -1;
}
static int gen_rsa_pem(const env_t *e, const char *name) { return gen_key(e, name, "-t rsa -b 2048 -m PEM"); }

static void
key_path(const env_t *e, const char *name, char *out, size_t sz)
{
    snprintf(out, sz, "%s/%s", e->root, name);
}

/*
 * Copy <root>/<pubname>.pub into <keys>/<user>/authorized_keys (0640).
 * label_override != NULL replaces the first word of the line.
 * append != 0 appends instead of replacing.
 */
static int
install_pubkey(const env_t *e, const char *user, const char *pubname,
               const char *label_override, int append)
{
    char pub[PATH_MAX], dir[PATH_MAX], ak[PATH_MAX], line[8192];
    snprintf(pub, sizeof(pub), "%s/%s.pub", e->root, pubname);
    snprintf(dir, sizeof(dir), "%s/%s", e->keys, user);
    snprintf(ak,  sizeof(ak),  "%s/authorized_keys", dir);
    mkdir(dir, 0750);

    FILE *in = fopen(pub, "r");
    if (!in) return -1;
    if (!fgets(line, sizeof(line), in)) { fclose(in); return -1; }
    fclose(in);

    FILE *out = fopen(ak, append ? "a" : "w");
    if (!out) return -1;
    if (label_override) {
        const char *rest = strchr(line, ' ');
        if (!rest) { fclose(out); return -1; }
        fprintf(out, "%s%s", label_override, rest);
    } else {
        fputs(line, out);
    }
    fclose(out);
    chmod(ak, 0640);
    return 0;
}

static void
authkeys_path(const env_t *e, const char *user, char *out, size_t sz)
{
    snprintf(out, sz, "%s/%s/authorized_keys", e->keys, user);
}

static int
count_colons_str(const char *s)
{
    int n = 0;
    for (; *s; s++) if (*s == ':') n++;
    return n;
}

/* ── ssh-agent helpers ────────────────────────────────────────────────── */

/*
 * Start a real ssh-agent listening on <root>/agent.sock.  The agent is the
 * only place the private key lives in the agent tests: they delete the key
 * file, so a token can only come from the agent.
 */
static int
agent_start(env_t *e)
{
    snprintf(e->agent_sock, sizeof(e->agent_sock), "%s/agent.sock", e->root);
    char cmd[PATH_MAX * 2], out[256];
    snprintf(cmd, sizeof(cmd),
             "ssh-agent -a '%s' 2>/dev/null | sed -n 's/^SSH_AGENT_PID=\\([0-9]*\\).*/\\1/p'",
             e->agent_sock);
    if (run_capture(cmd, out, sizeof(out)) != 0) return -1;
    e->agent_pid = strtol(out, NULL, 10);
    return e->agent_pid > 0 ? 0 : -1;
}

/* Add <name> to the agent.  passphrase != NULL uses an askpass helper. */
static int
agent_add(const env_t *e, const char *name, const char *passphrase)
{
    char key[PATH_MAX], cmd[PATH_MAX * 3], out[512];
    key_path(e, name, key, sizeof(key));
    if (passphrase) {
        char ask[PATH_MAX], body[512];
        snprintf(ask, sizeof(ask), "%s/askpass.sh", e->root);
        snprintf(body, sizeof(body), "#!/bin/sh\nprintf '%%s\\n' '%s'\n", passphrase);
        write_file(ask, body, 0755);
        snprintf(cmd, sizeof(cmd),
                 "SSH_AUTH_SOCK='%s' SSH_ASKPASS='%s' SSH_ASKPASS_REQUIRE=force "
                 "DISPLAY=:0 ssh-add '%s' 2>&1", e->agent_sock, ask, key);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "SSH_AUTH_SOCK='%s' ssh-add '%s' 2>&1", e->agent_sock, key);
    }
    return run_capture(cmd, out, sizeof(out));
}

/*
 * Sign through the agent: pg_sshkey_sign --agent <name>.pub [extra].
 * sock_override lets a test point at a missing or wrong socket.
 */
static int
make_token_agent(const env_t *e, const char *name, const char *extra,
                 const char *sock_override, char *tok, size_t tok_sz)
{
    char key[PATH_MAX], cmd[PATH_MAX * 3];
    key_path(e, name, key, sizeof(key));
    /* stderr is kept: a missing token must say why, not just fail */
    snprintf(cmd, sizeof(cmd),
             "SSH_AUTH_SOCK='%s' '%s' --agent '%s.pub' %s 2>&1",
             sock_override ? sock_override : e->agent_sock,
             g_sign_bin, key, extra ? extra : "");
    return run_capture(cmd, tok, tok_sz);
}

/* ── token helpers ────────────────────────────────────────────────────── */


/*
 * v2: the client issues its own challenge.  `extra` holds optional
 * pg_sshkey_sign flags (--at <ts>, --nonce <hex>) so tests can build
 * expired, future, or colliding tokens.  Nothing is written on the server.
 */
static int
make_token_v2(const env_t *e, const char *keyname, const char *extra,
              char *tok, size_t tok_sz)
{
    char cmd[PATH_MAX * 2], key[PATH_MAX];
    key_path(e, keyname, key, sizeof(key));
    snprintf(cmd, sizeof(cmd), "'%s' %s '%s' 2>/dev/null", g_sign_bin, extra ? extra : "", key);
    if (run_capture(cmd, tok, tok_sz) != 0) return -1;
    /* <digits>:<64hex>:<b64> */
    const char *c1 = strchr(tok, ':');
    if (!c1 || c1 == tok) return -1;
    const char *c2 = strchr(c1 + 1, ':');
    if (!c2 || c2 - (c1 + 1) != 64) return -1;
    return 0;
}

/* the nonce part of a v2 token */
static void
v2_nonce(const char *tok, char out[65])
{
    const char *c1 = strchr(tok, ':');
    if (!c1 || strlen(c1 + 1) < 64) { out[0] = '\0'; return; }
    memcpy(out, c1 + 1, 64); out[64] = '\0';
}

static int
dir_entry_count(const char *dir)
{
    char cmd[PATH_MAX + 64], out[32];
    snprintf(cmd, sizeof(cmd), "ls -1A '%s' | wc -l", dir);
    run_capture(cmd, out, sizeof(out));
    return atoi(out);
}

static int
nonce_exists(const env_t *e, const char *hex)
{
    char p[PATH_MAX]; struct stat st;
    snprintf(p, sizeof(p), "%s/%s", e->chal, hex);
    return stat(p, &st) == 0;
}

/* ── PostgreSQL-style conversation ────────────────────────────────────── */

static int g_echo_off_calls;

static int
pg_style_conv(int num_msg, const struct pam_message **msg,
              struct pam_response **resp, void *appdata_ptr)
{
    const char *passwd = appdata_ptr;
    *resp = NULL;
    if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG) return PAM_CONV_ERR;

    struct pam_response *reply = calloc((size_t)num_msg, sizeof *reply);
    if (!reply) return PAM_CONV_ERR;

    for (int i = 0; i < num_msg; i++) {
        switch (msg[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
            g_echo_off_calls++;
            /* PostgreSQL would round-trip to the client here; an empty
               password models "client sent nothing" → conversation fails. */
            if (!passwd || passwd[0] == '\0') goto fail;
            reply[i].resp = strdup(passwd);
            break;
        case PAM_ERROR_MSG:
        case PAM_TEXT_INFO:
            reply[i].resp = strdup("");
            break;
        default:
            goto fail;
        }
        reply[i].resp_retcode = PAM_SUCCESS;
    }
    *resp = reply;
    return PAM_SUCCESS;

fail:
    for (int i = 0; i < num_msg; i++) free(reply[i].resp);
    free(reply);
    return PAM_CONV_ERR;
}

/*
 * Authenticate `user` with `token` the way PostgreSQL does.
 * Returns the pam_authenticate() result.  If acct_rc is non-NULL and
 * authentication succeeded, *acct_rc receives pam_acct_mgmt()'s result.
 */
static const char *g_rhost = NULL;   /* what PostgreSQL would report */

static int
authenticate(const env_t *e, const char *user, const char *token, int *acct_rc)
{
    struct pam_conv conv = { pg_style_conv, (void *)token };
    pam_handle_t *pamh = NULL;
    g_echo_off_calls = 0;
    log_reset();
    if (acct_rc) *acct_rc = -1;

    int rc = pam_start_confdir(SERVICE_AUTH, "pgsql@", &conv, e->confdir, &pamh);
    if (rc != PAM_SUCCESS) {
        fprintf(stderr, "    pam_start_confdir: %s\n", pam_strerror(NULL, rc));
        return rc;
    }
    pam_set_item(pamh, PAM_USER, user);
    pam_set_item(pamh, PAM_CONV, &conv);
    /*
     * PostgreSQL sets PAM_RHOST to port->remote_host: the client address,
     * for a TCP connection, nothing at all on the unix socket, and the
     * reverse-DNS name when pg_hba.conf carries pam_use_hostname=1.
     * g_rhost is NULL unless a test sets it, which is the case of a
     * PostgreSQL build that does not set the item at all.
     */
    if (g_rhost) pam_set_item(pamh, PAM_RHOST, g_rhost);

    rc = pam_authenticate(pamh, 0);
    if (rc == PAM_SUCCESS && acct_rc)
        *acct_rc = pam_acct_mgmt(pamh, 0);

    pam_end(pamh, rc);
    return rc;
}

/* ── tests ────────────────────────────────────────────────────────────── */

static void
test_valid_ed25519_token_succeeds(void)
{
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(install_pubkey(&e, "alice", "id_ed25519", NULL, 0), 0);

    char tok[4096];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);

    int acct = -1;
    int rc = authenticate(&e, "alice", tok, &acct);
    ASSERT_EQ(rc, PAM_SUCCESS);
    /* exactly one conversation round, PostgreSQL's client can't answer a second */
    ASSERT_EQ(g_echo_off_calls, 1);
    /* shipped config: account stack is pam_permit, alice need not be an OS user */
    ASSERT_EQ(acct, PAM_SUCCESS);
    env_teardown(&e);
}

static void
test_replayed_token_rejected_and_nonce_recorded(void)
{
    env_t e; env_setup(&e);
    gen_ed25519(&e, "id_ed25519");
    install_pubkey(&e, "alice", "id_ed25519", NULL, 0);

    char tok[4096];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(dir_entry_count(e.chal), 0);      /* nothing recorded yet */

    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);
    /* the nonce is recorded on first use ... */
    ASSERT_EQ(dir_entry_count(e.chal), 1);
    /* ... so the identical token is refused */
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);
    ASSERT_LOGGED("replayed token for 'alice'");
    env_teardown(&e);
}

static void
test_wrong_key_rejected(void)
{
    env_t e; env_setup(&e);
    gen_ed25519(&e, "id_ed25519");
    gen_ed25519(&e, "id_wrong");
    install_pubkey(&e, "alice", "id_ed25519", NULL, 0);   /* id_wrong never registered */

    char tok[4096];
    ASSERT_EQ(make_token_v2(&e, "id_wrong", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);
    /* a refused attempt records nothing: verification comes first */
    ASSERT_EQ(dir_entry_count(e.chal), 0);
    env_teardown(&e);
}

static void
test_malformed_and_empty_tokens_rejected(void)
{
    env_t e; env_setup(&e);
    gen_ed25519(&e, "id_ed25519");
    install_pubkey(&e, "alice", "id_ed25519", NULL, 0);

    char tok[4096];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);

    /* the nonce of the good token, and the shapes built around it */
    char nonce[65], one_colon[160], bad_sig[4096], traversal[160];
    memcpy(nonce, strchr(tok, ':') + 1, 64);
    nonce[64] = '\0';
    snprintf(one_colon, sizeof(one_colon), "%s:AAAA", nonce);   /* the v1 shape */
    snprintf(bad_sig,  sizeof(bad_sig),  "%.*s:!!not-base64!!",
             (int)(strrchr(tok, ':') - tok), tok);
    snprintf(traversal, sizeof(traversal), "1:../../etc/passwd:AAAA");

    /* Refused on shape alone, so nothing is recorded. */
    const char *pre[] = { "", "nocolon", ":AAAA", one_colon, traversal };
    for (size_t i = 0; i < sizeof(pre)/sizeof(pre[0]); i++) {
        int rc = authenticate(&e, "alice", pre[i], NULL);
        if (rc != PAM_AUTH_ERR)
            fprintf(stderr, "    token #%zu \"%.20s\" -> %s\n", i, pre[i], pam_strerror(NULL, rc));
        ASSERT_EQ(rc, PAM_AUTH_ERR);
        ASSERT_EQ(g_echo_off_calls, 1);   /* never a second prompt to the client */
    }
    ASSERT_EQ(dir_entry_count(e.chal), 0);

    /* A well-shaped token whose signature is not base64 is refused too */
    ASSERT_EQ(authenticate(&e, "alice", bad_sig, NULL), PAM_AUTH_ERR);
    ASSERT_EQ(g_echo_off_calls, 1);
    ASSERT_EQ(dir_entry_count(e.chal), 0);
    env_teardown(&e);
}

static void
test_missing_authorized_keys_rejected(void)
{
    env_t e; env_setup(&e);
    gen_ed25519(&e, "id_ed25519");
    /* no keys/alice/ at all */
    char tok[4096];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);
    env_teardown(&e);
}

static void
test_empty_authorized_keys_rejected(void)
{
    env_t e; env_setup(&e);
    gen_ed25519(&e, "id_ed25519");
    char dir[PATH_MAX], ak[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/alice", e.keys); mkdir(dir, 0750);
    authkeys_path(&e, "alice", ak, sizeof(ak));
    write_file(ak, "# no keys here\n\n", 0640);

    char tok[4096];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);
    env_teardown(&e);
}

static void
test_group_writable_authorized_keys_refused(void)
{
    env_t e; env_setup(&e);
    gen_ed25519(&e, "id_ed25519");
    install_pubkey(&e, "alice", "id_ed25519", NULL, 0);
    char ak[PATH_MAX]; authkeys_path(&e, "alice", ak, sizeof(ak));

    char tok[4096];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    chmod(ak, 0660);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);

    /* same key, correct mode, fresh token: proves the refusal was the mode */
    chmod(ak, 0640);
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);
    env_teardown(&e);
}



static void
test_rsa_ssh_rsa_entry_succeeds(void)
{
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_rsa_pem(&e, "id_rsa"), 0);
    install_pubkey(&e, "alice", "id_rsa", NULL, 0);   /* genuine "ssh-rsa ..." line */

    char tok[4096];
    ASSERT_EQ(make_token_v2(&e, "id_rsa", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);
    env_teardown(&e);
}

static void
test_rsa_sha2_512_label_succeeds(void)
{
    /* The module accepts an rsa-sha2-512 key-type word in authorized_keys
       (key_parser.c, pg_sshkey_addkey).  A key registered that way must
       authenticate with the token the shipped signer produces. */
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_rsa_pem(&e, "id_rsa"), 0);
    install_pubkey(&e, "alice", "id_rsa", "rsa-sha2-512", 0);

    char tok[4096];
    ASSERT_EQ(make_token_v2(&e, "id_rsa", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);
    env_teardown(&e);
}

/* pam_sm_acct_mgmt is exported even though the shipped config routes the
   account stack to pam_permit; lock its contract down directly. */
static int
acct_mgmt_direct(const env_t *e, const char *user)
{
    struct pam_conv conv = { pg_style_conv, (void *)"" };
    pam_handle_t *pamh = NULL;
    int rc = pam_start_confdir(SERVICE_ACCT, user, &conv, e->confdir, &pamh);
    if (rc != PAM_SUCCESS) return rc;
    rc = pam_acct_mgmt(pamh, 0);
    pam_end(pamh, rc);
    return rc;
}

static void
test_acct_mgmt_direct(void)
{
    env_t e; env_setup(&e);
    struct passwd *pw = getpwuid(geteuid());
    ASSERT_NOT_NULL(pw);
    if (pw) ASSERT_EQ(acct_mgmt_direct(&e, pw->pw_name), PAM_SUCCESS);
    ASSERT_EQ(acct_mgmt_direct(&e, "no_such_user_e2e"), PAM_ACCT_EXPIRED);
    env_teardown(&e);
}

static void
write_stale_nonce(const env_t *e, const char *name, long age)
{
    char p[PATH_MAX], body[128];
    snprintf(p, sizeof(p), "%s/%s", e->chal, name);
    snprintf(body, sizeof(body), "%ld\n%s\n", (long)time(NULL) - age, name);
    write_file(p, body, 0644);
    struct utimbuf t = { time(NULL) - age, time(NULL) - age };
    utime(p, &t);
}

static void
test_stale_nonces_swept_on_auth(void)
{
    env_t e; env_setup(&e);
    gen_ed25519(&e, "id_ed25519");
    install_pubkey(&e, "alice", "id_ed25519", NULL, 0);

    /* leftovers from earlier failed connection attempts (any user) */
    const char *stale1 = "1111111111111111111111111111111111111111111111111111111111111111";
    const char *stale2 = "2222222222222222222222222222222222222222222222222222222222222222";
    const char *live   = "3333333333333333333333333333333333333333333333333333333333333333";
    write_stale_nonce(&e, stale1, 3600);
    write_stale_nonce(&e, stale2, 300);
    write_stale_nonce(&e, live, 5);                 /* another user's pending nonce */
    write_stale_nonce(&e, "README", 3600);          /* not a nonce */

    char tok[4096];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);

    ASSERT_FALSE(nonce_exists(&e, stale1));
    ASSERT_FALSE(nonce_exists(&e, stale2));
    ASSERT_TRUE(nonce_exists(&e, live));
    ASSERT_TRUE(nonce_exists(&e, "README"));
    env_teardown(&e);
}

/* ── v2: client-issued challenge ─────────────────────────────────────── */

static void
test_v2_token_succeeds_with_no_server_side_nonce(void)
{
    env_t e; env_setup(&e);
    gen_ed25519(&e, "id_ed25519");
    install_pubkey(&e, "alice", "id_ed25519", NULL, 0);

    char tok[4096];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(dir_entry_count(e.chal), 0);          /* nothing pre-created */

    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);
    ASSERT_EQ(g_echo_off_calls, 1);

    /* the module recorded the nonce so it can never be accepted again */
    char nonce[65]; v2_nonce(tok, nonce);
    ASSERT_TRUE(nonce_exists(&e, nonce));
    env_teardown(&e);
}

static void
test_v2_replay_rejected(void)
{
    env_t e; env_setup(&e);
    gen_ed25519(&e, "id_ed25519");
    install_pubkey(&e, "alice", "id_ed25519", NULL, 0);
    char tok[4096];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);
    env_teardown(&e);
}

static void
test_v2_expired_and_future_rejected(void)
{
    env_t e; env_setup(&e);
    gen_ed25519(&e, "id_ed25519");
    install_pubkey(&e, "alice", "id_ed25519", NULL, 0);
    char tok[4096], extra[64];

    snprintf(extra, sizeof(extra), "--at %ld", (long)time(NULL) - 120);
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", extra, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);

    snprintf(extra, sizeof(extra), "--at %ld", (long)time(NULL) + 300);
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", extra, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);

    /* small clock skew is tolerated: 30 s in the future is fine */
    snprintf(extra, sizeof(extra), "--at %ld", (long)time(NULL) + 30);
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", extra, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);

    /* rejected tokens leave no marker behind */
    ASSERT_EQ(dir_entry_count(e.chal), 1);
    env_teardown(&e);
}

static void
test_v2_wrong_key_and_tampering_rejected(void)
{
    env_t e; env_setup(&e);
    gen_ed25519(&e, "id_ed25519");
    gen_ed25519(&e, "id_wrong");
    install_pubkey(&e, "alice", "id_ed25519", NULL, 0);
    char tok[4096];

    ASSERT_EQ(make_token_v2(&e, "id_wrong", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);

    /* a valid token with its timestamp edited is a different message */
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    tok[0] = (tok[0] == '1') ? '2' : '1';
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);

    /* garbage that merely looks like v2 */
    ASSERT_EQ(authenticate(&e, "alice", "1:2:3", NULL), PAM_AUTH_ERR);
    ASSERT_EQ(authenticate(&e, "alice", "abc:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:AAAA", NULL), PAM_AUTH_ERR);
    ASSERT_EQ(dir_entry_count(e.chal), 0);          /* garbage creates no files */
    env_teardown(&e);
}

static void
test_v2_nonce_cannot_be_reused_with_a_new_timestamp(void)
{
    env_t e; env_setup(&e);
    gen_ed25519(&e, "id_ed25519");
    install_pubkey(&e, "alice", "id_ed25519", NULL, 0);
    const char *nonce = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    char tok[4096], extra[160];

    snprintf(extra, sizeof(extra), "--nonce %s", nonce);
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", extra, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);

    /* freshly signed, valid timestamp, same nonce → still a replay */
    snprintf(extra, sizeof(extra), "--nonce %s --at %ld", nonce, (long)time(NULL) + 1);
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", extra, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);
    env_teardown(&e);
}

static void
test_v2_works_with_private_0700_marker_dir(void)
{
    /* v2 needs no world-writable directory: only the module writes to it */
    env_t e; env_setup(&e);
    gen_ed25519(&e, "id_ed25519");
    install_pubkey(&e, "alice", "id_ed25519", NULL, 0);
    chmod(e.chal, 0700);
    char tok[4096];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);
    env_teardown(&e);
}

static void
test_v2_unrecordable_nonce_fails_closed(void)
{
    if (geteuid() == 0) { fprintf(stderr, "(skipped as root) "); return; }
    env_t e; env_setup(&e);
    gen_ed25519(&e, "id_ed25519");
    install_pubkey(&e, "alice", "id_ed25519", NULL, 0);
    chmod(e.chal, 0500);                 /* cannot create the marker */
    char tok[4096];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);
    chmod(e.chal, 0700);
    env_teardown(&e);
}

/* ── v3: OpenSSH user certificates ───────────────────────────────────── */

/*
 * Write <root>/trusted_ca_keys from the named CA public keys (0640) and
 * turn the option on in the service file.  Called only by cert tests.
 */
static void
enable_certs(env_t *e, const char *ca1, const char *ca2)
{
    char cmd[PATH_MAX * 3];
    snprintf(e->ca_file, sizeof(e->ca_file), "%s/trusted_ca_keys", e->root);
    if (ca2)
        snprintf(cmd, sizeof(cmd), "cat '%s/%s.pub' '%s/%s.pub' > '%s'",
                 e->root, ca1, e->root, ca2, e->ca_file);
    else
        snprintf(cmd, sizeof(cmd), "cat '%s/%s.pub' > '%s'",
                 e->root, ca1, e->ca_file);
    if (system(cmd) != 0) { fprintf(stderr, "enable_certs failed\n"); exit(2); }
    chmod(e->ca_file, 0640);
    write_services(e);
}

/*
 * tests/cert_helper.py signs a certificate ssh-keygen would refuse to
 * write, so the module can be held to lists a careless or compromised CA
 * could produce.  Writes <root>/<name>-cert.pub.
 */
static int
forge_cert(const env_t *e, const char *ca, const char *key, const char *name,
           const char *args)
{
    char cmd[PATH_MAX * 4], out[4096];
    snprintf(cmd, sizeof(cmd),
             "python3 '%s/cert_helper.py' '%s/%s' '%s/%s.pub' '%s/%s-cert.pub' "
             "--key-id alice-key --principal alice %s 2>&1",
             g_test_dir, e->root, ca, e->root, key, e->root, name, args);
    return run_capture(cmd, out, sizeof(out));
}

/* ── security keys ────────────────────────────────────────────────────── */
/*
 * tests/sk_helper.py stands in for a FIDO authenticator: it writes an
 * sk-ssh-ed25519 public key and signs the way a security key does.  The
 * module cannot tell the difference, because the format is the format.
 */
static int
sk_helper(const char *args, char *out, size_t out_sz)
{
    char cmd[PATH_MAX * 3];
    snprintf(cmd, sizeof(cmd), "python3 '%s/sk_helper.py' %s 2>&1",
             g_test_dir, args);
    return run_capture(cmd, out, out_sz);
}

static int
sk_keygen(const env_t *e, const char *extra)
{
    char args[PATH_MAX * 2], out[8192];
    snprintf(args, sizeof(args), "keygen '%s' %s", e->root, extra ? extra : "");
    return sk_helper(args, out, sizeof(out));
}

/* Install <root>/sk.pub as the user's authorized_keys. */
static int
sk_install(const env_t *e, const char *user)
{
    char dir[PATH_MAX], ak[PATH_MAX], cmd[PATH_MAX * 3];
    snprintf(dir, sizeof(dir), "%s/%s", e->keys, user);
    mkdir(dir, 0750);
    snprintf(ak, sizeof(ak), "%s/authorized_keys", dir);
    snprintf(cmd, sizeof(cmd), "cp '%s/sk.pub' '%s'", e->root, ak);
    if (system(cmd) != 0) return -1;
    chmod(ak, 0640);
    return 0;
}

static int
sk_token(const env_t *e, const char *extra, char *tok, size_t tok_sz)
{
    char args[PATH_MAX * 2];
    snprintf(args, sizeof(args), "token '%s' %s", e->root, extra ? extra : "");
    return sk_helper(args, tok, tok_sz);
}

/*
 * Point revoked_keys= at a file holding the named public keys.  Pass NULL
 * for an empty file (the option on, nothing revoked yet).
 */
static void
enable_revocations(env_t *e, const char *k1, const char *k2)
{
    char cmd[PATH_MAX * 3];
    snprintf(e->revoked_file, sizeof(e->revoked_file), "%s/revoked_keys", e->root);
    if (k1 && k2)
        snprintf(cmd, sizeof(cmd), "cat '%s/%s.pub' '%s/%s.pub' > '%s'",
                 e->root, k1, e->root, k2, e->revoked_file);
    else if (k1)
        snprintf(cmd, sizeof(cmd), "cat '%s/%s.pub' > '%s'", e->root, k1, e->revoked_file);
    else
        snprintf(cmd, sizeof(cmd), ": > '%s'", e->revoked_file);
    if (system(cmd) != 0) { fprintf(stderr, "enable_revocations failed\n"); exit(2); }
    chmod(e->revoked_file, 0640);
    write_services(e);
}

/* ssh-keygen -s <root>/<ca> <args> <root>/<key>.pub  ->  <root>/<key>-cert.pub */
static int
gen_cert(const env_t *e, const char *ca, const char *key, const char *args)
{
    char cmd[PATH_MAX * 3];
    snprintf(cmd, sizeof(cmd),
             "ssh-keygen -q -s '%s/%s' %s '%s/%s.pub' </dev/null >/dev/null 2>&1",
             e->root, ca, args, e->root, key);
    return system(cmd) == 0 ? 0 : -1;
}

/* Sign with <key> and attach <certkey>-cert.pub.  `extra` as in make_token_v2. */
static int
make_token_v3(const env_t *e, const char *key, const char *certkey,
              const char *extra, char *tok, size_t tok_sz)
{
    char cmd[PATH_MAX * 3];
    snprintf(cmd, sizeof(cmd), "'%s' --cert '%s/%s-cert.pub' %s '%s/%s' 2>/dev/null",
             g_sign_bin, e->root, certkey, extra ? extra : "", e->root, key);
    if (run_capture(cmd, tok, tok_sz) != 0) return -1;
    int n = 0;
    for (const char *p = tok; *p; p++) if (*p == ':') n++;
    return n == 3 ? 0 : -1;
}

static void
test_cert_ed25519_authenticates_without_authorized_keys(void)
{
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "ca"), 0);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(gen_cert(&e, "ca", "id_ed25519", "-I alice-key -n alice -V -1m:+5m"), 0);
    enable_certs(&e, "ca", NULL);
    /* no keys/alice/authorized_keys at all */

    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int acct = -1;
    int rc = authenticate(&e, "alice", tok, &acct);
    if (rc != PAM_SUCCESS) log_dump();
    ASSERT_EQ(rc, PAM_SUCCESS);
    ASSERT_EQ(g_echo_off_calls, 1);
    ASSERT_EQ(acct, PAM_SUCCESS);
    ASSERT_LOGGED("user 'alice' authenticated with certificate 'alice-key' serial 0");
    env_teardown(&e);
}

/* CA + user key + cert for principal alice, valid for five minutes.
   The option is left off; the test decides which CA file to trust. */
static void
cert_fixture(env_t *e)
{
    ASSERT_EQ(gen_ed25519(e, "ca"), 0);
    ASSERT_EQ(gen_ed25519(e, "id_ed25519"), 0);
    ASSERT_EQ(gen_cert(e, "ca", "id_ed25519", "-I alice-key -n alice -V -1m:+5m"), 0);
}

static void
test_cert_refused_when_trusted_ca_keys_unset(void)
{
    env_t e; env_setup(&e);
    cert_fixture(&e);
    /* service line unchanged: no trusted_ca_keys= */
    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("certificate token for 'alice' but trusted_ca_keys is not set");
    ASSERT_EQ(dir_entry_count(e.chal), 0);        /* nonce not recorded */
    env_teardown(&e);
}

static void
test_oversized_token_refused_before_parsing(void)
{
    /* every field under MAX_TOKEN_LEN, the whole token over it */
    env_t e; env_setup(&e);
    cert_fixture(&e);
    enable_certs(&e, "ca", NULL);
    static char tok[16384];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    size_t len = strlen(tok);
    ASSERT_TRUE(len < 2000);
    /* grow the signature field to ~8000 chars: still under MAX_TOKEN_LEN by
       itself, but the whole token is over it */
    char *sig = strchr(strchr(tok, ':') + 1, ':') + 1;
    memmove(sig + 8000, sig, strlen(sig) + 1);
    memset(sig, 'A', 8000);                  /* base64 alphabet, group aligned */
    ASSERT_TRUE(strlen(tok) >= 8192);
    ASSERT_TRUE(strlen(strrchr(tok, ':') + 1) < 8192);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("malformed token for 'alice'");
    ASSERT_EQ(dir_entry_count(e.chal), 0);
    env_teardown(&e);
}

static void
test_cert_with_control_characters_refused(void)
{
    /*
     * ssh-keygen accepts newlines in the key id and in option names.  A
     * client could use one to forge an "authenticated with certificate"
     * journal line.  The parser refuses any byte outside printable ASCII,
     * so nothing attacker-written reaches syslog.
     */
    env_t e; env_setup(&e);
    cert_fixture(&e);
    enable_certs(&e, "ca", NULL);
    char tok[8192];

    /* trusted CA, newline in the key id: would be logged on success */
    ASSERT_EQ(gen_cert(&e, "ca", "id_ed25519",
        "-I \"$(printf 'alice-key\\nFORGED')\" -n alice -V -1m:+5m"), 0);
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("certificate for 'alice' rejected: malformed certificate");
    ASSERT_FALSE(log_contains("FORGED"));
    ASSERT_EQ(dir_entry_count(e.chal), 0);

    /* untrusted CA, newline in a critical option name: logged before any
       signature check unless the parser refuses it */
    ASSERT_EQ(gen_ed25519(&e, "other_ca"), 0);
    ASSERT_EQ(gen_cert(&e, "other_ca", "id_ed25519",
        "-I alice-key -n alice -V -1m:+5m -O \"$(printf 'critical:evil\\nFORGED')\""), 0);
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("certificate for 'alice' rejected: malformed certificate");
    ASSERT_FALSE(log_contains("FORGED"));
    ASSERT_EQ(dir_entry_count(e.chal), 0);
    env_teardown(&e);
}

static void
test_agent_ed25519_authenticates_without_the_private_key_file(void)
{
    /*
     * The key is added to a real ssh-agent and then deleted from disk, so
     * pg_sshkey_sign cannot read it: a token can only come from the agent.
     */
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(install_pubkey(&e, "alice", "id_ed25519", NULL, 0), 0);
    ASSERT_EQ(agent_start(&e), 0);
    ASSERT_EQ(agent_add(&e, "id_ed25519", NULL), 0);

    char key[PATH_MAX];
    key_path(&e, "id_ed25519", key, sizeof(key));
    ASSERT_EQ(unlink(key), 0);

    char tok[8192];
    ASSERT_EQ(make_token_agent(&e, "id_ed25519", NULL, NULL, tok, sizeof(tok)), 0);
    int acct = -1;
    int rc = authenticate(&e, "alice", tok, &acct);
    if (rc != PAM_SUCCESS) log_dump();
    ASSERT_EQ(rc, PAM_SUCCESS);
    ASSERT_EQ(acct, PAM_SUCCESS);
    ASSERT_LOGGED("user 'alice' authenticated with key");
    env_teardown(&e);
}

static void
test_agent_rsa_key_authenticates(void)
{
    /* The agent signs RSA with SHA-1 unless the client asks for
       rsa-sha2-256; the module only verifies SHA-256. */
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_rsa_pem(&e, "id_rsa"), 0);
    ASSERT_EQ(install_pubkey(&e, "alice", "id_rsa", NULL, 0), 0);
    ASSERT_EQ(agent_start(&e), 0);
    ASSERT_EQ(agent_add(&e, "id_rsa", NULL), 0);
    char key[PATH_MAX];
    key_path(&e, "id_rsa", key, sizeof(key));
    ASSERT_EQ(unlink(key), 0);

    char tok[8192];
    ASSERT_EQ(make_token_agent(&e, "id_rsa", NULL, NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    if (rc != PAM_SUCCESS) log_dump();
    ASSERT_EQ(rc, PAM_SUCCESS);
    ASSERT_LOGGED("user 'alice' authenticated with key");
    env_teardown(&e);
}

static void
test_agent_passphrase_protected_key_authenticates(void)
{
    /*
     * A passphrase-protected key cannot be used any other way: the signer
     * has no passphrase prompt and refuses an encrypted key file.
     */
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_key_pass(&e, "id_locked", "-t ed25519", "hunter2"), 0);
    ASSERT_EQ(install_pubkey(&e, "alice", "id_locked", NULL, 0), 0);

    /* the key file alone is useless to pg_sshkey_sign */
    char tok[8192];
    ASSERT_NE(make_token_v2(&e, "id_locked", NULL, tok, sizeof(tok)), 0);

    ASSERT_EQ(agent_start(&e), 0);
    ASSERT_EQ(agent_add(&e, "id_locked", "hunter2"), 0);
    ASSERT_EQ(make_token_agent(&e, "id_locked", NULL, NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    if (rc != PAM_SUCCESS) log_dump();
    ASSERT_EQ(rc, PAM_SUCCESS);
    ASSERT_LOGGED("user 'alice' authenticated with key");
    env_teardown(&e);
}

static void
test_agent_certificate_authenticates(void)
{
    /* --agent and --cert together: a v3 token with no key file and no
       authorized_keys for the user. */
    env_t e; env_setup(&e);
    cert_fixture(&e);
    enable_certs(&e, "ca", NULL);
    ASSERT_EQ(agent_start(&e), 0);
    ASSERT_EQ(agent_add(&e, "id_ed25519", NULL), 0);
    char key[PATH_MAX], extra[PATH_MAX + 16];
    key_path(&e, "id_ed25519", key, sizeof(key));
    ASSERT_EQ(unlink(key), 0);

    char tok[8192];
    snprintf(extra, sizeof(extra), "--cert '%s/id_ed25519-cert.pub'", e.root);
    ASSERT_EQ(make_token_agent(&e, "id_ed25519", extra, NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(count_colons_str(tok), 3);
    int rc = authenticate(&e, "alice", tok, NULL);
    if (rc != PAM_SUCCESS) log_dump();
    ASSERT_EQ(rc, PAM_SUCCESS);
    ASSERT_LOGGED("authenticated with certificate 'alice-key'");
    env_teardown(&e);
}

static void
test_agent_key_not_registered_refused(void)
{
    /* The agent signs, but the key is not in the user's authorized_keys. */
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(gen_ed25519(&e, "id_wrong"), 0);
    ASSERT_EQ(install_pubkey(&e, "alice", "id_ed25519", NULL, 0), 0);
    ASSERT_EQ(agent_start(&e), 0);
    ASSERT_EQ(agent_add(&e, "id_wrong", NULL), 0);

    char tok[8192];
    ASSERT_EQ(make_token_agent(&e, "id_wrong", NULL, NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("authentication failed for 'alice'");
    ASSERT_EQ(dir_entry_count(e.chal), 0);
    env_teardown(&e);
}

static void
test_agent_absent_or_keyless_produces_no_token(void)
{
    /* No SSH_AUTH_SOCK, a dead socket, and an agent without the key each
       fail loudly instead of printing something the server would refuse. */
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(install_pubkey(&e, "alice", "id_ed25519", NULL, 0), 0);

    char tok[8192], sock[PATH_MAX];
    /* each case must fail for its own reason, not merely fail */
    ASSERT_NE(make_token_agent(&e, "id_ed25519", NULL, "", tok, sizeof(tok)), 0);
    ASSERT_TRUE(strstr(tok, "SSH_AUTH_SOCK is not set") != NULL);

    snprintf(sock, sizeof(sock), "%s/no-such.sock", e.root);
    ASSERT_NE(make_token_agent(&e, "id_ed25519", NULL, sock, tok, sizeof(tok)), 0);
    ASSERT_TRUE(strstr(tok, "Cannot connect to the ssh-agent") != NULL);

    ASSERT_EQ(agent_start(&e), 0);            /* running, but empty */
    ASSERT_NE(make_token_agent(&e, "id_ed25519", NULL, NULL, tok, sizeof(tok)), 0);
    ASSERT_TRUE(strstr(tok, "refused to sign") != NULL);
    env_teardown(&e);
}

static void
test_revoked_key_refused(void)
{
    /* the key is registered and the signature is good: only the
       revocation list stands between it and a login */
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(install_pubkey(&e, "alice", "id_ed25519", NULL, 0), 0);

    char tok[8192];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);   /* before */

    enable_revocations(&e, "id_ed25519", NULL);
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("key for 'alice' is revoked");
    ASSERT_EQ(dir_entry_count(e.chal), 1);   /* only the first login's nonce */
    env_teardown(&e);
}

static void
test_revoked_certified_key_refused(void)
{
    /* a certificate from a trusted CA does not outrank the revocation list */
    env_t e; env_setup(&e);
    cert_fixture(&e);
    enable_certs(&e, "ca", NULL);
    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);   /* before */

    enable_revocations(&e, "id_ed25519", NULL);
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("certificate for 'alice' rejected: key is revoked");
    env_teardown(&e);
}

static void
test_unreadable_revocation_list_fails_closed(void)
{
    /*
     * A list that cannot be read must refuse every login: readmitting the
     * keys it named because the file went missing is the one failure mode
     * a revocation list cannot have.
     */
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(install_pubkey(&e, "alice", "id_ed25519", NULL, 0), 0);
    enable_revocations(&e, NULL, NULL);           /* empty list: a login works */

    char tok[8192];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);

    ASSERT_EQ(unlink(e.revoked_file), 0);         /* the file disappears */
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("cannot read revoked_keys");

    env_teardown(&e);
}

static void
test_group_writable_revocation_list_refused(void)
{
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(install_pubkey(&e, "alice", "id_ed25519", NULL, 0), 0);
    enable_revocations(&e, NULL, NULL);
    ASSERT_EQ(chmod(e.revoked_file, 0660), 0);

    char tok[8192];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("revoked_keys");
    ASSERT_LOGGED("is world/group writable, refusing");

    ASSERT_EQ(chmod(e.revoked_file, 0640), 0);    /* the mode was the problem */
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);
    env_teardown(&e);
}

static void
test_revocation_names_one_key_not_all(void)
{
    /* revoking one key must not lock out the others in the same file */
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(gen_ed25519(&e, "id_second"), 0);
    ASSERT_EQ(install_pubkey(&e, "alice", "id_ed25519", NULL, 0), 0);
    ASSERT_EQ(install_pubkey(&e, "alice", "id_second", NULL, 1), 0);
    enable_revocations(&e, "id_ed25519", NULL);

    char tok[8192];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);

    ASSERT_EQ(make_token_v2(&e, "id_second", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    if (rc != PAM_SUCCESS) log_dump();
    ASSERT_EQ(rc, PAM_SUCCESS);
    ASSERT_LOGGED("authenticated with key id_second");
    env_teardown(&e);
}

static void
test_unparseable_revocation_list_fails_closed(void)
{
    /*
     * A file the module cannot read as a list of keys is not an empty list.
     * An OpenSSH KRL, a cert-authority line, a certificate, a key type this
     * module does not know: each would silently revoke nothing, which is
     * the one thing a revocation list must never do.
     */
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(install_pubkey(&e, "alice", "id_ed25519", NULL, 0), 0);
    enable_revocations(&e, NULL, NULL);          /* empty: a login works */

    char tok[8192], cmd[PATH_MAX * 3];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);

    /* the same key, but written the way ssh-keygen -k writes a KRL */
    snprintf(cmd, sizeof(cmd), "ssh-keygen -q -k -f '%s' '%s/id_ed25519.pub' >/dev/null 2>&1",
             e.revoked_file, e.root);
    ASSERT_EQ(system(cmd), 0);
    chmod(e.revoked_file, 0640);
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("revoked_keys");
    ASSERT_EQ(dir_entry_count(e.chal), 1);       /* only the first login's nonce */

    /* a cert-authority prefix: also not a plain key line */
    snprintf(cmd, sizeof(cmd), "sed 's/^/cert-authority /' '%s/id_ed25519.pub' > '%s'",
             e.root, e.revoked_file);
    ASSERT_EQ(system(cmd), 0);
    chmod(e.revoked_file, 0640);
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);

    /* a directory is not a list either */
    ASSERT_EQ(unlink(e.revoked_file), 0);
    ASSERT_EQ(mkdir(e.revoked_file, 0750), 0);
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);
    ASSERT_EQ(rmdir(e.revoked_file), 0);

    /* comments and blank lines around a real key are fine */
    snprintf(cmd, sizeof(cmd),
             "{ echo '# revoked 2026-08-24'; echo; cat '%s/id_ed25519.pub'; } > '%s'",
             e.root, e.revoked_file);
    ASSERT_EQ(system(cmd), 0);
    chmod(e.revoked_file, 0640);
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);
    ASSERT_LOGGED("key for 'alice' is revoked");
    env_teardown(&e);
}

static void
test_revoked_ca_key_refuses_its_certificates(void)
{
    /* revoking a CA withdraws every certificate it signed */
    env_t e; env_setup(&e);
    cert_fixture(&e);
    enable_certs(&e, "ca", NULL);
    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);

    enable_revocations(&e, "ca", NULL);          /* the CA, not the user key */
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("certificate for 'alice' rejected: signing CA is revoked");
    env_teardown(&e);
}

static void
test_same_file_for_ca_and_revocation_refused(void)
{
    /*
     * Pointing both options at one file would make every revoked key a CA
     * able to certify any role name, which is the opposite of revoking it.
     */
    env_t e; env_setup(&e);
    cert_fixture(&e);
    enable_certs(&e, "ca", NULL);
    snprintf(e.revoked_file, sizeof(e.revoked_file), "%s", e.ca_file);
    write_services(&e);

    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("are the same file");
    env_teardown(&e);
}

static void
test_certificate_source_address_is_enforced(void)
{
    /*
     * A certificate can be pinned to the addresses it may be used from.
     * PostgreSQL reports the client address in PAM_RHOST, so the module can
     * hold the certificate to it instead of refusing the option outright.
     */
    env_t e; env_setup(&e);
    cert_fixture(&e);
    enable_certs(&e, "ca", NULL);
    ASSERT_EQ(gen_cert(&e, "ca", "id_ed25519",
        "-I alice-key -n alice -V -1m:+5m -O source-address=127.0.0.1/32"), 0);

    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);

    g_rhost = "127.0.0.1";
    int rc = authenticate(&e, "alice", tok, NULL);
    if (rc != PAM_SUCCESS) log_dump();
    ASSERT_EQ(rc, PAM_SUCCESS);
    ASSERT_LOGGED("authenticated with certificate 'alice-key'");

    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    g_rhost = "10.0.0.7";
    rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("certificate for 'alice' rejected: client address 10.0.0.7 "
                  "is not permitted by source-address");
    ASSERT_EQ(dir_entry_count(e.chal), 1);   /* only the first login's nonce */
    g_rhost = NULL;
    env_teardown(&e);
}

static void
test_source_address_refuses_what_it_cannot_check(void)
{
    /*
     * A restriction the module cannot evaluate must refuse, not pass: a
     * host name (PostgreSQL with pam_use_hostname=1), a value that is not
     * an address at all, and a PostgreSQL that sets no PAM_RHOST, which is
     * what it does on the unix socket.
     */
    env_t e; env_setup(&e);
    cert_fixture(&e);
    enable_certs(&e, "ca", NULL);
    ASSERT_EQ(gen_cert(&e, "ca", "id_ed25519",
        "-I alice-key -n alice -V -1m:+5m -O source-address=127.0.0.1/32"), 0);

    char tok[8192];
    /* a name, which is what pam_use_hostname=1 reports */
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    g_rhost = "client.example.com";
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("cannot check source-address");

    /* an empty item, which is a different branch from a name */
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    g_rhost = "";
    rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("the client address is not known");

    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    g_rhost = NULL;                      /* no PAM_RHOST item at all */
    rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("the client address is not known");
    ASSERT_EQ(dir_entry_count(e.chal), 0);

    /* a certificate without the option is unaffected by any of this */
    ASSERT_EQ(gen_cert(&e, "ca", "id_ed25519", "-I alice-key -n alice -V -1m:+5m"), 0);
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);
    env_teardown(&e);
}

static void
test_source_address_list_and_ipv6(void)
{
    env_t e; env_setup(&e);
    cert_fixture(&e);
    enable_certs(&e, "ca", NULL);
    ASSERT_EQ(gen_cert(&e, "ca", "id_ed25519",
        "-I alice-key -n alice -V -1m:+5m "
        "-O source-address=10.0.0.0/8,192.168.5.7,::1/128"), 0);

    char tok[8192];
    const char *allowed[]  = { "10.9.9.9", "192.168.5.7", "::1", NULL };
    const char *refused[]  = { "11.0.0.1", "192.168.5.8", "::2", NULL };
    for (size_t i = 0; allowed[i]; i++) {
        ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
        g_rhost = allowed[i];
        int rc = authenticate(&e, "alice", tok, NULL);
        if (rc != PAM_SUCCESS) log_dump();
        ASSERT_EQ(rc, PAM_SUCCESS);
    }
    int nonces = dir_entry_count(e.chal);
    for (size_t i = 0; refused[i]; i++) {
        ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
        g_rhost = refused[i];
        int rc = authenticate(&e, "alice", tok, NULL);
        ASSERT_EQ(rc, PAM_AUTH_ERR);
        ASSERT_LOGGED("is not permitted by source-address");
        ASSERT_EQ(dir_entry_count(e.chal), nonces);   /* refused, so no nonce */
    }
    g_rhost = NULL;
    env_teardown(&e);
}

static void
test_source_address_malformed_list_refuses(void)
{
    /*
     * ssh-keygen will not sign "192.168.1.50/24" (host bits set), but
     * another CA might.  The module must refuse the certificate rather than
     * enforce the entries it does understand, or a typo would hand out a
     * subnet.  cert_helper.py mints what ssh-keygen will not.
     */
    env_t e; env_setup(&e);
    cert_fixture(&e);
    enable_certs(&e, "ca", NULL);
    ASSERT_EQ(forge_cert(&e, "ca", "id_ed25519", "id_ed25519",
                         "--critical 'source-address=192.168.1.50/24'"), 0);

    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    g_rhost = "192.168.1.50";            /* inside the network it names */
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("cannot check source-address");
    ASSERT_EQ(dir_entry_count(e.chal), 0);

    /* the same CA and key, with a list ssh-keygen would sign, works */
    ASSERT_EQ(forge_cert(&e, "ca", "id_ed25519", "id_ed25519",
                         "--critical 'source-address=192.168.1.0/24'"), 0);
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    rc = authenticate(&e, "alice", tok, NULL);
    if (rc != PAM_SUCCESS) log_dump();
    ASSERT_EQ(rc, PAM_SUCCESS);
    g_rhost = NULL;
    env_teardown(&e);
}

static void
test_v1_token_is_refused(void)
{
    /*
     * v1 is gone.  A token of the old shape, "<nonce_hex>:<signature>", is
     * refused as malformed however good its signature, and the nonce file
     * it would have consumed is left alone.
     */
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(install_pubkey(&e, "alice", "id_ed25519", NULL, 0), 0);

    /* a well-formed v2 token still works, so the key and the file are good */
    char tok[8192];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);

    /* the v1 shape: 64 hex characters, a colon, a signature */
    char v1[8192], cmd[PATH_MAX * 3];
    snprintf(cmd, sizeof(cmd),
        "python3 -c \"import sys;t=sys.argv[1].split(':');"
        "print(t[1]+':'+t[2])\" '%s'", tok);
    ASSERT_EQ(run_capture(cmd, v1, sizeof(v1)), 0);
    ASSERT_EQ(count_colons_str(v1), 1);

    int rc = authenticate(&e, "alice", v1, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("malformed token for 'alice'");
    env_teardown(&e);
}

static void
test_security_key_authenticates(void)
{
    /*
     * A FIDO key signs SHA256(application) || flags || counter ||
     * SHA256(message) and its SSH signature carries the flags and counter
     * after the raw 64 bytes.  Nothing else the module knows how to verify
     * has that shape.
     */
    env_t e; env_setup(&e);
    ASSERT_EQ(sk_keygen(&e, NULL), 0);
    ASSERT_EQ(sk_install(&e, "alice"), 0);

    char tok[8192];
    ASSERT_EQ(sk_token(&e, NULL, tok, sizeof(tok)), 0);
    int acct = -1;
    int rc = authenticate(&e, "alice", tok, &acct);
    if (rc != PAM_SUCCESS) log_dump();
    ASSERT_EQ(rc, PAM_SUCCESS);
    ASSERT_EQ(acct, PAM_SUCCESS);
    ASSERT_LOGGED("user 'alice' authenticated with key sk");
    env_teardown(&e);
}

static void
test_security_key_without_user_presence_refused(void)
{
    /*
     * The presence bit is what says a person touched the key.  A signature
     * without it is cryptographically valid and worth nothing.
     */
    env_t e; env_setup(&e);
    ASSERT_EQ(sk_keygen(&e, NULL), 0);
    ASSERT_EQ(sk_install(&e, "alice"), 0);

    char tok[8192];
    ASSERT_EQ(sk_token(&e, "--flags 0", tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("authentication failed for 'alice'");
    ASSERT_EQ(dir_entry_count(e.chal), 0);

    /* the same key with the bit set authenticates */
    ASSERT_EQ(sk_token(&e, "--flags 1", tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);
    env_teardown(&e);
}

static void
test_security_key_signature_is_bound_to_its_application(void)
{
    /*
     * The application string is part of what the key signs, and it comes
     * from the registered key rather than from the token.  The key here is
     * scoped to "ssh:corp", so a signature made for the default "ssh:" must
     * not open this door: a module that ignored the field and assumed the
     * default would let it through.
     */
    env_t e; env_setup(&e);
    ASSERT_EQ(sk_keygen(&e, "--application ssh:corp"), 0);
    ASSERT_EQ(sk_install(&e, "alice"), 0);

    char tok[8192];
    /* the key's own application authenticates */
    ASSERT_EQ(sk_token(&e, NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    if (rc != PAM_SUCCESS) log_dump();
    ASSERT_EQ(rc, PAM_SUCCESS);

    /* the default application, which this key is not scoped to, does not */
    ASSERT_EQ(sk_token(&e, "--application-override 'ssh:'", tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);
    ASSERT_LOGGED("authentication failed for 'alice'");

    /* and neither does a third one */
    ASSERT_EQ(sk_token(&e, "--application-override 'ssh:other'", tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_AUTH_ERR);
    env_teardown(&e);
}

static void
test_security_key_signature_length_is_exact(void)
{
    /*
     * 69 bytes: 64 raw, one flags byte, four counter bytes.  A signature
     * field of any other length must be refused before it is unpacked.
     */
    env_t e; env_setup(&e);
    ASSERT_EQ(sk_keygen(&e, NULL), 0);
    ASSERT_EQ(sk_install(&e, "alice"), 0);

    char tok[8192], mangled[8192], cmd[PATH_MAX * 3];
    ASSERT_EQ(sk_token(&e, NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);

    /* one byte too many, then the tail cut off entirely */
    const char *ops[] = { "b += b'\\0'", "b = b[:64]" };
    for (size_t i = 0; i < 2; i++) {
        ASSERT_EQ(sk_token(&e, NULL, tok, sizeof(tok)), 0);
        snprintf(cmd, sizeof(cmd),
            "python3 -c \"import base64,sys;t=sys.argv[1].split(':');"
            "b=bytearray(base64.b64decode(t[2]));%s;"
            "print(t[0]+':'+t[1]+':'+base64.b64encode(bytes(b)).decode())\" '%s'",
            ops[i], tok);
        ASSERT_EQ(run_capture(cmd, mangled, sizeof(mangled)), 0);
        int rc = authenticate(&e, "alice", mangled, NULL);
        ASSERT_EQ(rc, PAM_AUTH_ERR);
        ASSERT_LOGGED("authentication failed for 'alice'");
    }
    env_teardown(&e);
}

static void
test_security_key_counter_and_flags_are_signed(void)
{
    /*
     * Both trailing fields are covered by the signature: changing either
     * one in the token invalidates it, so neither can be forged.
     */
    env_t e; env_setup(&e);
    ASSERT_EQ(sk_keygen(&e, NULL), 0);
    ASSERT_EQ(sk_install(&e, "alice"), 0);

    char tok[8192], sig_b64[8192];
    ASSERT_EQ(sk_token(&e, "--counter 9", tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);

    /* flip the last byte of the counter inside the signature field */
    ASSERT_EQ(sk_token(&e, "--counter 9", tok, sizeof(tok)), 0);
    char cmd[PATH_MAX * 3];
    snprintf(cmd, sizeof(cmd),
        "python3 -c \"import base64,sys;t=sys.argv[1].split(':');"
        "b=bytearray(base64.b64decode(t[2]));b[-1]^=1;"
        "print(t[0]+':'+t[1]+':'+base64.b64encode(bytes(b)).decode())\" '%s'", tok);
    ASSERT_EQ(run_capture(cmd, sig_b64, sizeof(sig_b64)), 0);
    int rc = authenticate(&e, "alice", sig_b64, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("authentication failed for 'alice'");
    env_teardown(&e);
}

static void
test_security_key_ecdsa_type_is_not_accepted(void)
{
    /*
     * sk-ecdsa needs ECDSA verification, which the module does not have.
     * The entry must be skipped, not half-parsed into something that
     * verifies by accident.
     */
    env_t e; env_setup(&e);
    ASSERT_EQ(sk_keygen(&e, "--type sk-ecdsa-sha2-nistp256@openssh.com"), 0);
    ASSERT_EQ(sk_install(&e, "alice"), 0);

    char tok[8192];
    ASSERT_EQ(sk_token(&e, NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("no valid keys in");
    env_teardown(&e);
}

static void
test_revoked_security_key_refused(void)
{
    env_t e; env_setup(&e);
    ASSERT_EQ(sk_keygen(&e, NULL), 0);
    ASSERT_EQ(sk_install(&e, "alice"), 0);
    char tok[8192];
    ASSERT_EQ(sk_token(&e, NULL, tok, sizeof(tok)), 0);
    ASSERT_EQ(authenticate(&e, "alice", tok, NULL), PAM_SUCCESS);

    enable_revocations(&e, "sk", NULL);
    ASSERT_EQ(sk_token(&e, NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("key for 'alice' is revoked");
    env_teardown(&e);
}

static void
test_cert_from_untrusted_ca_refused(void)
{
    env_t e; env_setup(&e);
    cert_fixture(&e);
    ASSERT_EQ(gen_ed25519(&e, "other_ca"), 0);
    enable_certs(&e, "other_ca", NULL);           /* the signing CA is not listed */
    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("certificate for 'alice' rejected: not signed by a trusted CA");
    ASSERT_EQ(dir_entry_count(e.chal), 0);
    env_teardown(&e);
}

static void
test_cert_expired_refused(void)
{
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "ca"), 0);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    /* valid window ended one minute ago */
    ASSERT_EQ(gen_cert(&e, "ca", "id_ed25519", "-I alice-key -n alice -V -10m:-1m"), 0);
    enable_certs(&e, "ca", NULL);
    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("certificate for 'alice' rejected: expired");
    ASSERT_EQ(dir_entry_count(e.chal), 0);
    env_teardown(&e);
}

static void
test_cert_not_yet_valid_refused(void)
{
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "ca"), 0);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(gen_cert(&e, "ca", "id_ed25519", "-I alice-key -n alice -V +10m:+20m"), 0);
    enable_certs(&e, "ca", NULL);
    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("certificate for 'alice' rejected: not yet valid");
    ASSERT_EQ(dir_entry_count(e.chal), 0);
    env_teardown(&e);
}

static void
test_cert_wrong_principal_refused(void)
{
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "ca"), 0);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(gen_cert(&e, "ca", "id_ed25519", "-I bob-key -n bob,alicia -V -1m:+5m"), 0);
    enable_certs(&e, "ca", NULL);
    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("certificate for 'alice' rejected: principal 'alice' not listed");
    ASSERT_EQ(dir_entry_count(e.chal), 0);
    /* the same token is good for a listed principal */
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    rc = authenticate(&e, "bob", tok, NULL);
    ASSERT_EQ(rc, PAM_SUCCESS);
    env_teardown(&e);
}

static void
test_cert_without_principals_refused(void)
{
    /* ssh-keygen with no -n writes an empty principal list; sshd with
       TrustedUserCAKeys refuses such a certificate and so does the module. */
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "ca"), 0);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(gen_cert(&e, "ca", "id_ed25519", "-I any-key -V -1m:+5m"), 0);
    enable_certs(&e, "ca", NULL);
    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("certificate for 'alice' rejected: principal 'alice' not listed");
    ASSERT_EQ(dir_entry_count(e.chal), 0);
    env_teardown(&e);
}

static void
test_host_cert_refused(void)
{
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "ca"), 0);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(gen_cert(&e, "ca", "id_ed25519", "-h -I alice-key -n alice -V -1m:+5m"), 0);
    enable_certs(&e, "ca", NULL);
    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("certificate for 'alice' rejected: not a user certificate");
    ASSERT_EQ(dir_entry_count(e.chal), 0);
    env_teardown(&e);
}

static void
test_cert_with_critical_option_refused(void)
{
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "ca"), 0);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    /* source-address is honoured; every other critical option is refused */
    ASSERT_EQ(gen_cert(&e, "ca", "id_ed25519",
                       "-I alice-key -n alice -V -1m:+5m -O force-command=/bin/true"), 0);
    enable_certs(&e, "ca", NULL);
    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("certificate for 'alice' rejected: unsupported critical option force-command");
    ASSERT_EQ(dir_entry_count(e.chal), 0);

    /* and an unknown option alongside source-address is still refused */
    ASSERT_EQ(gen_cert(&e, "ca", "id_ed25519",
                       "-I alice-key -n alice -V -1m:+5m "
                       "-O source-address=127.0.0.1/32 -O force-command=/bin/true"), 0);
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    g_rhost = "127.0.0.1";
    rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("unsupported critical option force-command");
    g_rhost = NULL;
    ASSERT_EQ(dir_entry_count(e.chal), 0);
    env_teardown(&e);
}

static void
test_cert_tampered_byte_refused(void)
{
    env_t e; env_setup(&e);
    cert_fixture(&e);
    enable_certs(&e, "ca", NULL);
    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);

    /* base64 char 60 of the cert lies inside the CA-signed nonce field */
    char *cert = strrchr(tok, ':') + 1;
    ASSERT_TRUE(strlen(cert) > 60);
    cert[60] = (cert[60] == 'A') ? 'B' : 'A';

    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("certificate for 'alice' rejected: invalid CA signature");
    ASSERT_EQ(dir_entry_count(e.chal), 0);
    env_teardown(&e);
}

static void
test_cert_token_signed_by_other_key_refused(void)
{
    /* a genuine, trusted certificate presented with a signature from a
       private key other than the one it certifies */
    env_t e; env_setup(&e);
    cert_fixture(&e);
    ASSERT_EQ(gen_ed25519(&e, "id_other"), 0);
    enable_certs(&e, "ca", NULL);
    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_other", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("authentication failed for 'alice'");
    ASSERT_EQ(dir_entry_count(e.chal), 0);
    env_teardown(&e);
}

static void
test_cert_replay_and_timestamp_window(void)
{
    env_t e; env_setup(&e);
    cert_fixture(&e);
    enable_certs(&e, "ca", NULL);
    char tok[8192], extra[64];

    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_SUCCESS);
    rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("replayed token for 'alice' (nonce already used)");

    snprintf(extra, sizeof(extra), "--at %ld", (long)time(NULL) - 120);
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", extra, tok, sizeof(tok)), 0);
    rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    /* a second may tick between signing and the module's time(NULL) */
    ASSERT_TRUE(log_contains("token timestamp for 'alice' is -120 s from server time") ||
                log_contains("token timestamp for 'alice' is -121 s from server time"));

    snprintf(extra, sizeof(extra), "--at %ld", (long)time(NULL) + 300);
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", extra, tok, sizeof(tok)), 0);
    rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_TRUE(log_contains("token timestamp for 'alice' is 300 s from server time") ||
                log_contains("token timestamp for 'alice' is 299 s from server time"));

    snprintf(extra, sizeof(extra), "--at %ld", (long)time(NULL) + 30);
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", extra, tok, sizeof(tok)), 0);
    rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_SUCCESS);

    ASSERT_EQ(dir_entry_count(e.chal), 2);        /* only the two accepted nonces */
    env_teardown(&e);
}

static void
test_cert_rsa_key_under_ed25519_ca(void)
{
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_ed25519(&e, "ca"), 0);
    ASSERT_EQ(gen_rsa_pem(&e, "id_rsa"), 0);
    ASSERT_EQ(gen_cert(&e, "ca", "id_rsa", "-I alice-rsa -n alice -V -1m:+5m -z 42"), 0);
    enable_certs(&e, "ca", NULL);
    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_rsa", "id_rsa", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    if (rc != PAM_SUCCESS) log_dump();
    ASSERT_EQ(rc, PAM_SUCCESS);
    ASSERT_LOGGED("user 'alice' authenticated with certificate 'alice-rsa' serial 42");
    env_teardown(&e);
}

static void
test_cert_ed25519_key_under_rsa_ca(void)
{
    /* ssh-keygen signs with rsa-sha2-512 by default for an RSA CA */
    env_t e; env_setup(&e);
    ASSERT_EQ(gen_rsa_pem(&e, "ca_rsa"), 0);
    ASSERT_EQ(gen_ed25519(&e, "id_ed25519"), 0);
    ASSERT_EQ(gen_cert(&e, "ca_rsa", "id_ed25519", "-I alice-key -n alice -V -1m:+5m"), 0);
    enable_certs(&e, "ca_rsa", NULL);
    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    if (rc != PAM_SUCCESS) log_dump();
    ASSERT_EQ(rc, PAM_SUCCESS);
    ASSERT_LOGGED("user 'alice' authenticated with certificate 'alice-key' serial 0");

    /* ssh-rsa (SHA-1) CA signatures are refused */
    ASSERT_EQ(gen_cert(&e, "ca_rsa", "id_ed25519", "-t ssh-rsa -I alice-key -n alice -V -1m:+5m"), 0);
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("certificate for 'alice' rejected: unsupported signature algorithm ssh-rsa");
    ASSERT_EQ(dir_entry_count(e.chal), 1);           /* only the earlier success recorded a nonce */
    env_teardown(&e);
}

static void
test_cert_group_writable_ca_file_refused(void)
{
    env_t e; env_setup(&e);
    cert_fixture(&e);
    enable_certs(&e, "ca", NULL);
    char tok[8192];
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    chmod(e.ca_file, 0660);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_AUTH_ERR);
    ASSERT_LOGGED("trusted_ca_keys");
    ASSERT_LOGGED("is world/group writable, refusing");
    ASSERT_EQ(dir_entry_count(e.chal), 0);

    /* same token, correct mode: proves the refusal was the mode */
    chmod(e.ca_file, 0640);
    rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_SUCCESS);
    env_teardown(&e);
}

static void
test_v1_and_v2_still_pass_with_trusted_ca_keys_set(void)
{
    env_t e; env_setup(&e);
    cert_fixture(&e);
    enable_certs(&e, "ca", NULL);
    install_pubkey(&e, "alice", "id_ed25519", NULL, 0);

    char tok[8192];
    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    int rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_SUCCESS);
    ASSERT_LOGGED("user 'alice' authenticated with key id_ed25519");

    ASSERT_EQ(make_token_v2(&e, "id_ed25519", NULL, tok, sizeof(tok)), 0);
    rc = authenticate(&e, "alice", tok, NULL);
    ASSERT_EQ(rc, PAM_SUCCESS);
    ASSERT_LOGGED("user 'alice' authenticated with key id_ed25519");

    /* and a v3 token for a user with no authorized_keys still works alongside */
    ASSERT_EQ(gen_cert(&e, "ca", "id_ed25519", "-I carol-key -n carol -V -1m:+5m"), 0);
    ASSERT_EQ(make_token_v3(&e, "id_ed25519", "id_ed25519", NULL, tok, sizeof(tok)), 0);
    rc = authenticate(&e, "carol", tok, NULL);
    ASSERT_EQ(rc, PAM_SUCCESS);
    env_teardown(&e);
}

/* ── main ─────────────────────────────────────────────────────────────── */

int
main(void)
{
    const char *bd = getenv("PAM_PG_SSHKEY_BUILDDIR");
    if (!bd || !*bd) bd = ".";

    /* sk_helper.py sits beside this source file */
    char here[PATH_MAX];
    snprintf(here, sizeof(here), "%s/tests", bd);
    if (!realpath(here, g_test_dir)) {
        fprintf(stderr, "FAIL: %s not found\n", here);
        return 1;
    }

    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s/pam_pg_sshkey.so", bd);
    if (!realpath(tmp, g_so)) {
        fprintf(stderr, "FAIL: %s not found, build it first (make)\n", tmp);
        return 1;
    }
    snprintf(tmp, sizeof(tmp), "%s/pg_sshkey_sign", bd);
    if (!realpath(tmp, g_sign_bin)) { fprintf(stderr, "FAIL: %s not found\n", tmp); return 1; }
    if (system("command -v ssh-keygen >/dev/null 2>&1") != 0) {
        fprintf(stderr, "FAIL: ssh-keygen not found (install openssh-client)\n");
        return 1;
    }
    atexit(atexit_cleanup);

    printf("=== pam module (libpam seam) ===\n");
    printf("  module: %s\n", g_so);
    RUN(test_v1_token_is_refused);
    RUN(test_valid_ed25519_token_succeeds);
    RUN(test_replayed_token_rejected_and_nonce_recorded);
    RUN(test_wrong_key_rejected);
    RUN(test_malformed_and_empty_tokens_rejected);
    RUN(test_missing_authorized_keys_rejected);
    RUN(test_empty_authorized_keys_rejected);
    RUN(test_group_writable_authorized_keys_refused);
    RUN(test_rsa_ssh_rsa_entry_succeeds);
    RUN(test_rsa_sha2_512_label_succeeds);
    RUN(test_acct_mgmt_direct);
    RUN(test_stale_nonces_swept_on_auth);
    RUN(test_v2_token_succeeds_with_no_server_side_nonce);
    RUN(test_v2_replay_rejected);
    RUN(test_v2_expired_and_future_rejected);
    RUN(test_v2_wrong_key_and_tampering_rejected);
    RUN(test_v2_nonce_cannot_be_reused_with_a_new_timestamp);
    RUN(test_v2_works_with_private_0700_marker_dir);
    RUN(test_v2_unrecordable_nonce_fails_closed);
    RUN(test_cert_ed25519_authenticates_without_authorized_keys);
    RUN(test_cert_refused_when_trusted_ca_keys_unset);
    RUN(test_oversized_token_refused_before_parsing);
    RUN(test_cert_with_control_characters_refused);
    RUN(test_certificate_source_address_is_enforced);
    RUN(test_source_address_refuses_what_it_cannot_check);
    RUN(test_source_address_list_and_ipv6);
    RUN(test_source_address_malformed_list_refuses);
    RUN(test_security_key_authenticates);
    RUN(test_security_key_without_user_presence_refused);
    RUN(test_security_key_signature_is_bound_to_its_application);
    RUN(test_security_key_signature_length_is_exact);
    RUN(test_security_key_counter_and_flags_are_signed);
    RUN(test_security_key_ecdsa_type_is_not_accepted);
    RUN(test_revoked_security_key_refused);
    RUN(test_revoked_key_refused);
    RUN(test_revoked_certified_key_refused);
    RUN(test_unreadable_revocation_list_fails_closed);
    RUN(test_group_writable_revocation_list_refused);
    RUN(test_revocation_names_one_key_not_all);
    RUN(test_unparseable_revocation_list_fails_closed);
    RUN(test_revoked_ca_key_refuses_its_certificates);
    RUN(test_same_file_for_ca_and_revocation_refused);
    RUN(test_agent_ed25519_authenticates_without_the_private_key_file);
    RUN(test_agent_rsa_key_authenticates);
    RUN(test_agent_passphrase_protected_key_authenticates);
    RUN(test_agent_certificate_authenticates);
    RUN(test_agent_key_not_registered_refused);
    RUN(test_agent_absent_or_keyless_produces_no_token);
    RUN(test_cert_from_untrusted_ca_refused);
    RUN(test_cert_expired_refused);
    RUN(test_cert_not_yet_valid_refused);
    RUN(test_cert_wrong_principal_refused);
    RUN(test_cert_without_principals_refused);
    RUN(test_host_cert_refused);
    RUN(test_cert_with_critical_option_refused);
    RUN(test_cert_tampered_byte_refused);
    RUN(test_cert_token_signed_by_other_key_refused);
    RUN(test_cert_replay_and_timestamp_window);
    RUN(test_cert_rsa_key_under_ed25519_ca);
    RUN(test_cert_ed25519_key_under_rsa_ca);
    RUN(test_cert_group_writable_ca_file_refused);
    RUN(test_v1_and_v2_still_pass_with_trusted_ca_keys_set);
    return SUMMARY();
}
