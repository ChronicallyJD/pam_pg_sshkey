/*
 * test_ssh_cert.c, unit tests for src/ssh_cert.c
 *
 * Supporting evidence for the libpam-seam tests in test_pam_module.c: the
 * parser reads real ssh-keygen output, every field comes back as written,
 * the CA signature verifies over the signed bytes, and cut or padded blobs
 * are refused without a crash (the binary runs under ASan/UBSan).
 *
 * SPDX-License-Identifier: MIT
 */

#include "test_framework.h"
#include "ssh_cert.h"
#include "key_parser.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static char g_dir[512];

static int
sh(const char *fmt, ...)
{
    char cmd[4096];
    va_list ap; va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);
    return system(cmd) == 0 ? 0 : -1;
}

static int gen_ed25519(const char *n) { return sh("ssh-keygen -q -t ed25519 -N '' -f %s/%s </dev/null >/dev/null 2>&1", g_dir, n); }
static int gen_rsa(const char *n)     { return sh("ssh-keygen -q -t rsa -b 2048 -N '' -f %s/%s </dev/null >/dev/null 2>&1", g_dir, n); }
static int sign(const char *ca, const char *key, const char *args)
{
    return sh("ssh-keygen -q -s %s/%s %s %s/%s.pub </dev/null >/dev/null 2>&1", g_dir, ca, args, g_dir, key);
}

/* decode the second field of <g_dir>/<key>-cert.pub into blob */
static int
load_cert(const char *key, unsigned char *blob, size_t size, size_t *len)
{
    char path[1024], line[16384];
    snprintf(path, sizeof(path), "%s/%s-cert.pub", g_dir, key);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    fclose(f);
    char *b64 = strchr(line, ' ');
    if (!b64) return -1;
    b64++;
    char *end = strpbrk(b64, " \n");
    if (end) *end = '\0';
    return b64_decode(b64, blob, size, len);
}

static void
test_parse_ed25519_cert_fields(void)
{
    ASSERT_EQ(gen_ed25519("ca"), 0);
    ASSERT_EQ(gen_ed25519("k1"), 0);
    ASSERT_EQ(sign("ca", "k1", "-I id-one -n alice,bob -V -1m:+4m -z 7"), 0);

    unsigned char blob[8192]; size_t len = 0;
    ASSERT_EQ(load_cert("k1", blob, sizeof(blob), &len), 0);

    ssh_cert_t *c = NULL;
    ASSERT_EQ(ssh_cert_parse(blob, len, &c), 0);
    ASSERT_NOT_NULL(c);
    if (!c) return;
    ASSERT_STR_EQ(c->cert_type, "ssh-ed25519-cert-v01@openssh.com");
    ASSERT_STR_EQ(c->key_type, "ssh-ed25519");
    ASSERT_NOT_NULL(c->pkey);
    ASSERT_EQ(c->serial, 7);
    ASSERT_EQ(c->type, SSH_CERT_TYPE_USER);
    ASSERT_STR_EQ(c->key_id, "id-one");
    ASSERT_EQ(c->nprincipals, 2);
    if (c->nprincipals == 2) {
        ASSERT_STR_EQ(c->principals[0], "alice");
        ASSERT_STR_EQ(c->principals[1], "bob");
    }
    ASSERT_EQ(c->valid_before - c->valid_after, 300);
    ASSERT_NULL(c->critical_option);
    ASSERT_STR_EQ(c->ca_key_type, "ssh-ed25519");
    ASSERT_STR_EQ(c->sig_algo, "ssh-ed25519");
    ASSERT_EQ(c->sig_len, 64);
    ASSERT_TRUE(c->tbs_len > 0 && c->tbs_len < len);
    ASSERT_EQ(ssh_cert_verify_ca_signature(c), 0);

    /* the CA's own public key line is a trusted list of one */
    key_list_t *cas = NULL; char ca_pub[1024];
    snprintf(ca_pub, sizeof(ca_pub), "%s/ca.pub", g_dir);
    ASSERT_EQ(parse_authorized_keys(ca_pub, &cas), 1);
    ASSERT_EQ(ssh_cert_ca_is_trusted(c, cas), 1);
    free_key_list(cas);

    ASSERT_EQ(gen_ed25519("ca2"), 0);
    snprintf(ca_pub, sizeof(ca_pub), "%s/ca2.pub", g_dir);
    ASSERT_EQ(parse_authorized_keys(ca_pub, &cas), 1);
    ASSERT_EQ(ssh_cert_ca_is_trusted(c, cas), 0);
    free_key_list(cas);
    ssh_cert_free(c);
}

static void
test_parse_host_cert_and_critical_option(void)
{
    ASSERT_EQ(sign("ca", "k1", "-h -I host-id -n db.example -V -1m:+4m"), 0);
    unsigned char blob[8192]; size_t len = 0;
    ASSERT_EQ(load_cert("k1", blob, sizeof(blob), &len), 0);
    ssh_cert_t *c = NULL;
    ASSERT_EQ(ssh_cert_parse(blob, len, &c), 0);
    if (c) { ASSERT_EQ(c->type, SSH_CERT_TYPE_HOST); ssh_cert_free(c); }

    ASSERT_EQ(sign("ca", "k1", "-I id -n alice -V -1m:+4m -O force-command=/bin/true"), 0);
    ASSERT_EQ(load_cert("k1", blob, sizeof(blob), &len), 0);
    c = NULL;
    ASSERT_EQ(ssh_cert_parse(blob, len, &c), 0);
    if (c) { ASSERT_STR_EQ(c->critical_option, "force-command"); ssh_cert_free(c); }

    /* no -n: an empty principal list, parsed as such */
    ASSERT_EQ(sign("ca", "k1", "-I id -V -1m:+4m"), 0);
    ASSERT_EQ(load_cert("k1", blob, sizeof(blob), &len), 0);
    c = NULL;
    ASSERT_EQ(ssh_cert_parse(blob, len, &c), 0);
    if (c) { ASSERT_EQ(c->nprincipals, 0); ssh_cert_free(c); }
}

static void
test_rsa_cert_and_rsa_ca(void)
{
    ASSERT_EQ(gen_rsa("ca_rsa"), 0);
    ASSERT_EQ(gen_rsa("k_rsa"), 0);

    /* RSA user key under an ed25519 CA */
    ASSERT_EQ(sign("ca", "k_rsa", "-I rsa-id -n alice -V -1m:+4m"), 0);
    unsigned char blob[8192]; size_t len = 0;
    ASSERT_EQ(load_cert("k_rsa", blob, sizeof(blob), &len), 0);
    ssh_cert_t *c = NULL;
    ASSERT_EQ(ssh_cert_parse(blob, len, &c), 0);
    if (c) {
        ASSERT_STR_EQ(c->cert_type, "ssh-rsa-cert-v01@openssh.com");
        ASSERT_STR_EQ(c->key_type, "ssh-rsa");
        ASSERT_EQ(EVP_PKEY_id(c->pkey), EVP_PKEY_RSA);
        ASSERT_EQ(ssh_cert_verify_ca_signature(c), 0);
        ssh_cert_free(c);
    }

    /* ed25519 user key under an RSA CA: rsa-sha2-512 by default */
    ASSERT_EQ(sign("ca_rsa", "k1", "-I id -n alice -V -1m:+4m"), 0);
    ASSERT_EQ(load_cert("k1", blob, sizeof(blob), &len), 0);
    c = NULL;
    ASSERT_EQ(ssh_cert_parse(blob, len, &c), 0);
    if (c) {
        ASSERT_STR_EQ(c->ca_key_type, "ssh-rsa");
        ASSERT_STR_EQ(c->sig_algo, "rsa-sha2-512");
        ASSERT_EQ(ssh_cert_verify_ca_signature(c), 0);
        ssh_cert_free(c);
    }

    /* rsa-sha2-256 on request */
    ASSERT_EQ(sign("ca_rsa", "k1", "-t rsa-sha2-256 -I id -n alice -V -1m:+4m"), 0);
    ASSERT_EQ(load_cert("k1", blob, sizeof(blob), &len), 0);
    c = NULL;
    ASSERT_EQ(ssh_cert_parse(blob, len, &c), 0);
    if (c) {
        ASSERT_STR_EQ(c->sig_algo, "rsa-sha2-256");
        ASSERT_EQ(ssh_cert_verify_ca_signature(c), 0);
        ssh_cert_free(c);
    }

    /* ssh-rsa (SHA-1) parses but is not verified */
    ASSERT_EQ(sign("ca_rsa", "k1", "-t ssh-rsa -I id -n alice -V -1m:+4m"), 0);
    ASSERT_EQ(load_cert("k1", blob, sizeof(blob), &len), 0);
    c = NULL;
    ASSERT_EQ(ssh_cert_parse(blob, len, &c), 0);
    if (c) {
        ASSERT_STR_EQ(c->sig_algo, "ssh-rsa");
        ASSERT_EQ(ssh_cert_verify_ca_signature(c), -2);
        ssh_cert_free(c);
    }
}

static void
test_tampered_tbs_fails_signature(void)
{
    ASSERT_EQ(sign("ca", "k1", "-I id -n alice -V -1m:+4m"), 0);
    unsigned char blob[8192]; size_t len = 0;
    ASSERT_EQ(load_cert("k1", blob, sizeof(blob), &len), 0);
    blob[50] ^= 0x01;                       /* inside the nonce */
    ssh_cert_t *c = NULL;
    ASSERT_EQ(ssh_cert_parse(blob, len, &c), 0);
    if (c) { ASSERT_EQ(ssh_cert_verify_ca_signature(c), -1); ssh_cert_free(c); }
}

static void
test_truncated_and_padded_blobs_rejected(void)
{
    ASSERT_EQ(sign("ca", "k1", "-I id -n alice -V -1m:+4m"), 0);
    unsigned char blob[8192]; size_t len = 0;
    ASSERT_EQ(load_cert("k1", blob, sizeof(blob), &len), 0);

    int accepted = 0;
    for (size_t cut = 0; cut < len; cut++) {
        ssh_cert_t *c = NULL;
        if (ssh_cert_parse(blob, cut, &c) == 0) { accepted++; ssh_cert_free(c); }
    }
    ASSERT_EQ(accepted, 0);

    /* one trailing byte */
    blob[len] = 0;
    ssh_cert_t *c = NULL;
    ASSERT_EQ(ssh_cert_parse(blob, len + 1, &c), -1);
    ASSERT_NULL(c);

    /* a length field claiming more than the blob holds */
    unsigned char big[8]; memset(big, 0xff, sizeof(big));
    ASSERT_EQ(ssh_cert_parse(big, sizeof(big), &c), -1);
    ASSERT_NULL(c);

    /* a plain public key is not a certificate */
    ASSERT_EQ(ssh_cert_parse((const unsigned char *)"\0\0\0\x0bssh-ed25519", 15, &c), -1);
    ASSERT_NULL(c);
    ASSERT_EQ(ssh_cert_parse(NULL, 0, &c), -1);
}

int
main(void)
{
    snprintf(g_dir, sizeof(g_dir), "/tmp/pam_cert_%d", (int)getpid());
    mkdir(g_dir, 0700);
    if (system("command -v ssh-keygen >/dev/null 2>&1") != 0) {
        fprintf(stderr, "FAIL: ssh-keygen not found\n");
        return 1;
    }
    printf("=== ssh_cert ===\n");
    RUN(test_parse_ed25519_cert_fields);
    RUN(test_parse_host_cert_and_critical_option);
    RUN(test_rsa_cert_and_rsa_ca);
    RUN(test_tampered_tbs_fails_signature);
    RUN(test_truncated_and_padded_blobs_rejected);
    sh("rm -rf %s", g_dir);
    return SUMMARY();
}
