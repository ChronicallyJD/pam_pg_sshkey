/*
 * test_ssh_agent.c, ssh_agent.c against a hostile agent.
 *
 * The other agent tests drive a real ssh-agent, which is honest by
 * construction. This one serves the socket itself and answers with what a
 * wedged or malicious agent would send: silence, oversize lengths, truncated
 * bodies, empty signatures, wrong algorithms, terminal escapes, and a
 * signature made by the wrong key. With a forwarded agent the socket is
 * served by another host, so none of this is hypothetical.
 *
 * Built with AddressSanitizer, so a read past a reply buffer fails here.
 *
 * SPDX-License-Identifier: MIT
 */

#include "test_framework.h"
#include "ssh_agent.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/evp.h>

#define SSH_AGENT_FAILURE           5
#define SSH_AGENT_IDENTITIES_ANSWER 12
#define SSH_AGENT_SIGN_RESPONSE     14

static char g_dir[256];
static char g_sock[512];
static pid_t g_agent = 0;

/* ── scripted replies ─────────────────────────────────────────────────── */

typedef enum {
    R_SILENT,            /* accept, then never answer */
    R_SHORT_BODY,        /* header promises more than the body holds */
    R_HUGE_LEN,          /* length header beyond the cap */
    R_ZERO_LEN,          /* length header of zero */
    R_FAILURE_CLOSE,     /* refuse, then close (the SIGPIPE case) */
    R_EMPTY_SIG,         /* SIGN_RESPONSE with a zero-length signature */
    R_ESCAPE_ALGO,       /* algorithm name full of terminal escapes */
    R_WRONG_KEY_SIG,     /* well-formed signature by a different key */
    R_INNER_OVERRUN,     /* inner string claims more than the blob holds */
    R_GOOD_SIG,          /* a genuine signature, correctly labelled */
    R_GOOD_SIG_BAD_ALGO, /* a genuine signature under a wrong algorithm name */
} reply_kind;

static void
put_u32(unsigned char *p, size_t v)
{
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}

static size_t
put_string(unsigned char *p, const void *s, size_t n)
{
    put_u32(p, n);
    if (n) memcpy(p + 4, s, n);
    return 4 + n;
}

/* Serve exactly one connection, then exit. */
static void
serve(int listen_fd, reply_kind kind, const unsigned char *sig, size_t sig_len)
{
    int fd = accept(listen_fd, NULL, NULL);
    if (fd < 0) _exit(1);

    unsigned char req[8192];
    ssize_t n = read(fd, req, sizeof(req));   /* the request, unread */
    (void)n;

    unsigned char body[8192], msg[8192 + 4];
    size_t body_len = 0;

    switch (kind) {
    case R_SILENT:
        pause();
        _exit(0);
    case R_SHORT_BODY:
        put_u32(msg, 100);
        (void)!write(fd, msg, 4);
        (void)!write(fd, "xx", 2);
        close(fd);
        _exit(0);
    case R_HUGE_LEN:
        put_u32(msg, 0xffffffffu);
        (void)!write(fd, msg, 4);
        close(fd);
        _exit(0);
    case R_ZERO_LEN:
        put_u32(msg, 0);
        (void)!write(fd, msg, 4);
        close(fd);
        _exit(0);
    case R_FAILURE_CLOSE:
        body[0] = SSH_AGENT_FAILURE;
        put_u32(msg, 1);
        memcpy(msg + 4, body, 1);
        (void)!write(fd, msg, 5);
        close(fd);
        _exit(0);                 /* the client's next request hits a closed socket */
    case R_EMPTY_SIG: {
        unsigned char blob[128]; size_t bl = 0;
        bl += put_string(blob + bl, "ssh-ed25519", 11);
        bl += put_string(blob + bl, "", 0);
        body[body_len++] = SSH_AGENT_SIGN_RESPONSE;
        body_len += put_string(body + body_len, blob, bl);
        break;
    }
    case R_ESCAPE_ALGO: {
        const char evil[] = "\033[2J\033[1;1HTYPE YOUR PASSWORD:\r";
        unsigned char blob[256]; size_t bl = 0;
        bl += put_string(blob + bl, evil, sizeof(evil) - 1);
        bl += put_string(blob + bl, sig, sig_len);
        body[body_len++] = SSH_AGENT_SIGN_RESPONSE;
        body_len += put_string(body + body_len, blob, bl);
        break;
    }
    case R_GOOD_SIG:
    case R_GOOD_SIG_BAD_ALGO: {
        const char *algo = (kind == R_GOOD_SIG) ? "ssh-ed25519"
                                                : "ecdsa-sha2-nistp256";
        unsigned char blob[256]; size_t bl = 0;
        bl += put_string(blob + bl, algo, strlen(algo));
        bl += put_string(blob + bl, sig, sig_len);
        body[body_len++] = SSH_AGENT_SIGN_RESPONSE;
        body_len += put_string(body + body_len, blob, bl);
        break;
    }
    case R_WRONG_KEY_SIG: {
        unsigned char blob[256]; size_t bl = 0;
        bl += put_string(blob + bl, "ssh-ed25519", 11);
        bl += put_string(blob + bl, sig, sig_len);
        body[body_len++] = SSH_AGENT_SIGN_RESPONSE;
        body_len += put_string(body + body_len, blob, bl);
        break;
    }
    case R_INNER_OVERRUN: {
        unsigned char blob[64]; size_t bl = 0;
        put_u32(blob, 0xfffffff0u);          /* algorithm string, absurd length */
        bl = 4 + 8;
        memset(blob + 4, 'A', 8);
        body[body_len++] = SSH_AGENT_SIGN_RESPONSE;
        body_len += put_string(body + body_len, blob, bl);
        break;
    }
    }

    put_u32(msg, body_len);
    memcpy(msg + 4, body, body_len);
    (void)!write(fd, msg, 4 + body_len);
    close(fd);
    _exit(0);
}

/* Start the fake agent and point SSH_AUTH_SOCK at it. */
static void
agent_up(reply_kind kind, const unsigned char *sig, size_t sig_len)
{
    snprintf(g_sock, sizeof(g_sock), "%s/agent.sock", g_dir);
    unlink(g_sock);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(g_sock) >= sizeof(addr.sun_path)) { fprintf(stderr, "socket path too long\n"); exit(2); }
    memcpy(addr.sun_path, g_sock, strlen(g_sock) + 1);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { perror("bind"); exit(2); }
    if (listen(fd, 4) != 0) { perror("listen"); exit(2); }

    g_agent = fork();
    if (g_agent == 0) { serve(fd, kind, sig, sig_len); _exit(0); }
    close(fd);
    setenv("SSH_AUTH_SOCK", g_sock, 1);
    setenv("PG_SSHKEY_AGENT_TIMEOUT_MS", "400", 1);
}

static void
agent_down(void)
{
    if (g_agent > 0) {
        kill(g_agent, SIGKILL);
        waitpid(g_agent, NULL, 0);
        g_agent = 0;
    }
    unlink(g_sock);
}

/* ── fixtures ─────────────────────────────────────────────────────────── */

static void
mk_dir(void)
{
    const char *tmp = getenv("TMPDIR");
    if (!tmp || strlen(tmp) > 120) tmp = "/tmp";
    snprintf(g_dir, sizeof(g_dir), "%s/pam_agent_XXXXXX", tmp);
    if (!mkdtemp(g_dir)) { perror("mkdtemp"); exit(2); }
}

static void
rm_dir(void)
{
    char cmd[sizeof(g_dir) + 32];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) fprintf(stderr, "    warning: cleanup failed\n");
}

/* An Ed25519 key pair, and the .pub file the client names. */
static int
gen_key(char *pub_out, size_t pub_sz)
{
    char cmd[sizeof(g_dir) * 2 + 128];
    snprintf(cmd, sizeof(cmd),
             "ssh-keygen -q -t ed25519 -N '' -C k -f '%s/k' </dev/null >/dev/null 2>&1",
             g_dir);
    if (system(cmd) != 0) return -1;
    snprintf(pub_out, pub_sz, "%s/k.pub", g_dir);
    return 0;
}

static const unsigned char MSG[] = "pg-sshkey-v2\0" "1700000000:abc";

static void
put_u32_buf(unsigned char *p, size_t v)
{
    put_u32(p, v);
}

/*
 * Generate an Ed25519 key, write its SSH public key line, and return the
 * private key.  The harness signs with it, so a reply can carry a genuine
 * signature and isolate the checks that are not about the signature itself.
 */
static EVP_PKEY *
gen_key_openssl(char *pub_out, size_t pub_sz)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_keygen(ctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);

    unsigned char raw[32]; size_t raw_len = sizeof(raw);
    if (EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len) != 1 || raw_len != 32) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    unsigned char blob[128]; size_t bl = 0;
    put_u32_buf(blob, 11); memcpy(blob + 4, "ssh-ed25519", 11); bl = 15;
    put_u32_buf(blob + bl, 32); memcpy(blob + bl + 4, raw, 32); bl += 36;

    static const char *b64c =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char b64[256]; size_t o = 0;
    for (size_t i = 0; i < bl; i += 3) {
        unsigned v = (unsigned)blob[i] << 16;
        if (i + 1 < bl) v |= (unsigned)blob[i + 1] << 8;
        if (i + 2 < bl) v |= blob[i + 2];
        b64[o++] = b64c[(v >> 18) & 63];
        b64[o++] = b64c[(v >> 12) & 63];
        b64[o++] = (i + 1 < bl) ? b64c[(v >> 6) & 63] : '=';
        b64[o++] = (i + 2 < bl) ? b64c[v & 63] : '=';
    }
    b64[o] = '\0';

    snprintf(pub_out, pub_sz, "%s/gen.pub", g_dir);
    FILE *f = fopen(pub_out, "w");
    if (!f) { EVP_PKEY_free(pkey); return NULL; }
    fprintf(f, "ssh-ed25519 %s gen\n", b64);
    fclose(f);
    return pkey;
}

/* Sign MSG with pkey; caller frees. */
static unsigned char *
sign_msg(EVP_PKEY *pkey, size_t *len_out)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return NULL;
    unsigned char *sig = malloc(128);
    size_t sl = 128;
    int ok = sig &&
             EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
             EVP_DigestSign(ctx, sig, &sl, MSG, sizeof(MSG) - 1) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) { free(sig); return NULL; }
    *len_out = sl;
    return sig;
}

/* ── tests ────────────────────────────────────────────────────────────── */

static void
test_silent_agent_times_out(void)
{
    /* A wedged agent must not hang the login for ever. */
    mk_dir();
    char pub[512];
    ASSERT_EQ(gen_key(pub, sizeof(pub)), 0);
    size_t blob_len = 0;
    unsigned char *blob = ssh_pubkey_blob_from_file(pub, &blob_len);
    ASSERT_NOT_NULL(blob);

    agent_up(R_SILENT, NULL, 0);
    size_t sig_len = 0;
    time_t t0 = time(NULL);
    unsigned char *sig = ssh_agent_sign(blob, blob_len, MSG, sizeof(MSG) - 1, &sig_len);
    ASSERT_NULL(sig);
    ASSERT_TRUE(time(NULL) - t0 < 5);
    agent_down();
    free(blob);
    rm_dir();
}

static void
test_hostile_replies_are_refused(void)
{
    mk_dir();
    char pub[512];
    ASSERT_EQ(gen_key(pub, sizeof(pub)), 0);
    size_t blob_len = 0;
    unsigned char *blob = ssh_pubkey_blob_from_file(pub, &blob_len);
    ASSERT_NOT_NULL(blob);

    reply_kind kinds[] = { R_SHORT_BODY, R_HUGE_LEN, R_ZERO_LEN,
                           R_EMPTY_SIG, R_INNER_OVERRUN, R_ESCAPE_ALGO };
    unsigned char fake[64];
    memset(fake, 0x5a, sizeof(fake));
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        agent_up(kinds[i], fake, sizeof(fake));
        size_t sig_len = 0;
        unsigned char *sig = ssh_agent_sign(blob, blob_len, MSG, sizeof(MSG) - 1,
                                            &sig_len);
        if (sig) fprintf(stderr, "    reply kind %d was accepted\n", (int)kinds[i]);
        ASSERT_NULL(sig);
        agent_down();
    }
    free(blob);
    rm_dir();
}

static void
test_signature_by_another_key_is_refused(void)
{
    /*
     * The agent answers with a well-formed Ed25519 signature that simply is
     * not this key's.  Without a local check the client would print a token
     * and the only symptom would be "authentication failed" on the server.
     */
    mk_dir();
    char pub[512];
    ASSERT_EQ(gen_key(pub, sizeof(pub)), 0);
    size_t blob_len = 0;
    unsigned char *blob = ssh_pubkey_blob_from_file(pub, &blob_len);
    ASSERT_NOT_NULL(blob);

    unsigned char wrong[64];
    memset(wrong, 0x5a, sizeof(wrong));      /* right length, wrong signature */
    agent_up(R_WRONG_KEY_SIG, wrong, sizeof(wrong));
    size_t sig_len = 0;
    unsigned char *sig = ssh_agent_sign(blob, blob_len, MSG, sizeof(MSG) - 1, &sig_len);
    ASSERT_NULL(sig);
    agent_down();
    free(blob);
    rm_dir();
}

static void
test_refusal_then_close_does_not_kill_the_client(void)
{
    /*
     * On a refusal the client asks for the identity list to build its error
     * message.  If the agent has gone, that write must not raise SIGPIPE.
     * A signal here would take the whole process down mid-login.
     */
    mk_dir();
    char pub[512];
    ASSERT_EQ(gen_key(pub, sizeof(pub)), 0);
    size_t blob_len = 0;
    unsigned char *blob = ssh_pubkey_blob_from_file(pub, &blob_len);
    ASSERT_NOT_NULL(blob);

    pid_t child = fork();
    if (child == 0) {
        agent_up(R_FAILURE_CLOSE, NULL, 0);
        size_t sig_len = 0;
        unsigned char *sig = ssh_agent_sign(blob, blob_len, MSG, sizeof(MSG) - 1,
                                            &sig_len);
        _exit(sig ? 2 : 0);       /* 0: refused cleanly */
    }
    int status = 0;
    waitpid(child, &status, 0);
    if (WIFSIGNALED(status))
        fprintf(stderr, "    client died on signal %d\n", WTERMSIG(status));
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(WEXITSTATUS(status), 0);
    agent_down();
    free(blob);
    rm_dir();
}

static void
test_genuine_signature_under_a_wrong_algorithm_is_refused(void)
{
    /*
     * The signature verifies, only its algorithm name is wrong.  Nothing
     * else in the client can catch this: it is what the algorithm check is
     * for, and what the documentation promises.
     */
    mk_dir();
    char pub[512];
    EVP_PKEY *pkey = gen_key_openssl(pub, sizeof(pub));
    ASSERT_NOT_NULL(pkey);
    size_t sig_len = 0;
    unsigned char *sig = sign_msg(pkey, &sig_len);
    ASSERT_NOT_NULL(sig);
    size_t blob_len = 0;
    unsigned char *blob = ssh_pubkey_blob_from_file(pub, &blob_len);
    ASSERT_NOT_NULL(blob);

    /* the control: correctly labelled, the same bytes are accepted */
    agent_up(R_GOOD_SIG, sig, sig_len);
    size_t out_len = 0;
    unsigned char *out = ssh_agent_sign(blob, blob_len, MSG, sizeof(MSG) - 1, &out_len);
    ASSERT_NOT_NULL(out);
    ASSERT_EQ(out_len, sig_len);
    free(out);
    agent_down();

    agent_up(R_GOOD_SIG_BAD_ALGO, sig, sig_len);
    out = ssh_agent_sign(blob, blob_len, MSG, sizeof(MSG) - 1, &out_len);
    ASSERT_NULL(out);
    agent_down();

    free(sig); free(blob); EVP_PKEY_free(pkey);
    rm_dir();
}

static void
test_empty_signature_with_a_certificate_blob_is_refused(void)
{
    /*
     * A certificate blob skips the local signature check, because the key
     * inside the certificate is not the blob.  The empty-signature guard is
     * what stops a token with no signature in it there.
     */
    mk_dir();
    char cmd[2048], cert[512];
    snprintf(cmd, sizeof(cmd),
             "ssh-keygen -q -t ed25519 -N '' -C k -f '%s/ca' </dev/null >/dev/null 2>&1 && "
             "ssh-keygen -q -t ed25519 -N '' -C k -f '%s/u' </dev/null >/dev/null 2>&1 && "
             "ssh-keygen -q -s '%s/ca' -I id -n alice -V -1m:+5m '%s/u.pub' >/dev/null 2>&1",
             g_dir, g_dir, g_dir, g_dir);
    ASSERT_EQ(system(cmd), 0);
    snprintf(cert, sizeof(cert), "%s/u-cert.pub", g_dir);
    size_t blob_len = 0;
    unsigned char *blob = ssh_pubkey_blob_from_file(cert, &blob_len);
    ASSERT_NOT_NULL(blob);

    agent_up(R_EMPTY_SIG, NULL, 0);
    size_t sig_len = 0;
    unsigned char *sig = ssh_agent_sign(blob, blob_len, MSG, sizeof(MSG) - 1, &sig_len);
    ASSERT_NULL(sig);
    agent_down();
    free(blob);
    rm_dir();
}

int
main(void)
{
    RUN(test_silent_agent_times_out);
    RUN(test_hostile_replies_are_refused);
    RUN(test_signature_by_another_key_is_refused);
    RUN(test_refusal_then_close_does_not_kill_the_client);
    RUN(test_genuine_signature_under_a_wrong_algorithm_is_refused);
    RUN(test_empty_signature_with_a_certificate_blob_is_refused);
    return SUMMARY();
}
