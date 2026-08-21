/*
 * test_challenge_store.c
 *
 * Unit tests for challenge_store.c:
 *   challenge_create, uniqueness, format, file creation, error paths
 *   challenge_load  , round-trip, TTL expiry, hex validation, path traversal
 *   challenge_delete, idempotence, prevents replay
 *
 * SPDX-License-Identifier: MIT
 */
#include "test_framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <utime.h>

#include "../src/challenge_store.h"

/* ── helpers ──────────────────────────────────────────────────────────── */
static char g_tmpdir[256];

static void mk_tmpdir(void) {
    snprintf(g_tmpdir, sizeof(g_tmpdir), "/tmp/pam_cs_%d", (int)getpid());
    mkdir(g_tmpdir, 0700);
}
static void rm_tmpdir(void) {
    char cmd[512]; snprintf(cmd,sizeof(cmd),"rm -rf %s",g_tmpdir); system(cmd);
}

/* Write a challenge file whose timestamp is 120 seconds in the past */
static void write_expired(const char *hex) {
    char path[512]; snprintf(path,sizeof(path),"%s/%s",g_tmpdir,hex);
    FILE *f = fopen(path,"w");
    fprintf(f,"%ld\n%s\n",(long)(time(NULL)-120),hex); fclose(f);
}

/* Create a nonce file and back-date its mtime by `age` seconds */
static void write_aged(const char *name, long age) {
    char path[512]; snprintf(path,sizeof(path),"%s/%s",g_tmpdir,name);
    FILE *f = fopen(path,"w");
    fprintf(f,"%ld\n%s\n",(long)(time(NULL)-age),name); fclose(f);
    struct utimbuf t = { time(NULL)-age, time(NULL)-age };
    utime(path,&t);
}
static int file_exists(const char *name) {
    char path[512]; struct stat st;
    snprintf(path,sizeof(path),"%s/%s",g_tmpdir,name);
    return stat(path,&st)==0;
}
#define HEX_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define HEX_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define HEX_C "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
#define HEX_D "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
#define HEX_E "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

/* ── challenge_sweep ──────────────────────────────────────────────────── */
static void test_sweep_removes_expired_keeps_fresh_and_foreign(void) {
    mk_tmpdir();
    write_aged(HEX_A, 200);            /* past the sweep age (2×TTL) */
    write_aged(HEX_B, 3600);           /* long expired */
    write_aged(HEX_C, 90);             /* expired for auth, but a v2 marker
                                          must outlive its token: kept */
    write_aged("not-a-nonce.txt", 3600); /* not ours: never touched */
    ASSERT_EQ(challenge_sweep(g_tmpdir, 100), 2);
    ASSERT_FALSE(file_exists(HEX_A));
    ASSERT_FALSE(file_exists(HEX_B));
    ASSERT_TRUE(file_exists(HEX_C));
    ASSERT_TRUE(file_exists("not-a-nonce.txt"));
    rm_tmpdir();
}

static void test_sweep_respects_limit(void) {
    mk_tmpdir();
    write_aged(HEX_A,300); write_aged(HEX_B,300); write_aged(HEX_C,300);
    write_aged(HEX_D,300); write_aged(HEX_E,300);
    ASSERT_EQ(challenge_sweep(g_tmpdir, 3), 3);
    ASSERT_EQ(challenge_sweep(g_tmpdir, 3), 2);
    ASSERT_EQ(challenge_sweep(g_tmpdir, 3), 0);
    rm_tmpdir();
}

static void test_sweep_missing_dir_returns_minus_one(void) {
    ASSERT_EQ(challenge_sweep("/nonexistent/pam_cs_dir", 10), -1);
}

/* ── challenge_create ─────────────────────────────────────────────────── */
static void test_create_returns_zero(void) {
    mk_tmpdir();
    char hex[65];
    ASSERT_EQ(challenge_create(g_tmpdir, hex, sizeof(hex)), 0);
    rm_tmpdir();
}

static void test_create_hex_is_64_chars(void) {
    mk_tmpdir();
    char hex[65];
    challenge_create(g_tmpdir, hex, sizeof(hex));
    ASSERT_EQ((int)strlen(hex), 64);
    rm_tmpdir();
}

static void test_create_hex_chars_lowercase(void) {
    mk_tmpdir();
    char hex[65];
    challenge_create(g_tmpdir, hex, sizeof(hex));
    for (int i=0; hex[i]; i++) {
        char c = hex[i];
        ASSERT_TRUE((c>='0'&&c<='9')||(c>='a'&&c<='f'));
    }
    rm_tmpdir();
}

static void test_create_file_exists(void) {
    mk_tmpdir();
    char hex[65];
    challenge_create(g_tmpdir, hex, sizeof(hex));
    char path[512]; snprintf(path,sizeof(path),"%s/%s",g_tmpdir,hex);
    struct stat st;
    ASSERT_EQ(stat(path,&st), 0);
    rm_tmpdir();
}

static void test_create_unique_ids(void) {
    mk_tmpdir();
    char h1[65], h2[65];
    challenge_create(g_tmpdir, h1, sizeof(h1));
    challenge_create(g_tmpdir, h2, sizeof(h2));
    ASSERT_TRUE(strcmp(h1, h2) != 0);
    rm_tmpdir();
}

static void test_create_bad_dir_fails(void) {
    char hex[65];
    ASSERT_EQ(challenge_create("/tmp/__no_such_dir_pam__", hex, sizeof(hex)), -1);
}

static void test_create_small_buf_fails(void) {
    mk_tmpdir();
    char hex[8]; /* too small */
    ASSERT_EQ(challenge_create(g_tmpdir, hex, sizeof(hex)), -1);
    rm_tmpdir();
}

/* ── challenge_load ───────────────────────────────────────────────────── */
static void test_load_roundtrip(void) {
    mk_tmpdir();
    char hex[65]; challenge_create(g_tmpdir, hex, sizeof(hex));
    unsigned char out[64]; size_t len=0;
    ASSERT_EQ(challenge_load(g_tmpdir, hex, out, sizeof(out), &len), 0);
    ASSERT_EQ((int)len, 32);
    rm_tmpdir();
}

static void test_load_missing_fails(void) {
    mk_tmpdir();
    unsigned char out[64]; size_t len=0;
    int rc = challenge_load(g_tmpdir,
        "0000000000000000000000000000000000000000000000000000000000000000",
        out, sizeof(out), &len);
    ASSERT_EQ(rc, -1);
    rm_tmpdir();
}

static void test_load_expired_fails(void) {
    mk_tmpdir();
    const char *hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_expired(hex);
    unsigned char out[64]; size_t len=0;
    ASSERT_EQ(challenge_load(g_tmpdir, hex, out, sizeof(out), &len), -1);
    rm_tmpdir();
}

static void test_load_expired_deletes_file(void) {
    mk_tmpdir();
    const char *hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    write_expired(hex);
    unsigned char out[64]; size_t len=0;
    challenge_load(g_tmpdir, hex, out, sizeof(out), &len);
    char path[512]; snprintf(path,sizeof(path),"%s/%s",g_tmpdir,hex);
    struct stat st;
    ASSERT_EQ(stat(path,&st), -1); /* must be gone */
    rm_tmpdir();
}

static void test_load_rejects_path_traversal(void) {
    mk_tmpdir();
    unsigned char out[64]; size_t len=0;
    ASSERT_EQ(challenge_load(g_tmpdir, "../etc/passwd", out, sizeof(out), &len), -1);
    rm_tmpdir();
}

static void test_load_rejects_non_hex(void) {
    mk_tmpdir();
    unsigned char out[64]; size_t len=0;
    ASSERT_EQ(challenge_load(g_tmpdir, "not-hex!", out, sizeof(out), &len), -1);
    rm_tmpdir();
}

static void test_load_small_output_buf_fails(void) {
    mk_tmpdir();
    char hex[65]; challenge_create(g_tmpdir, hex, sizeof(hex));
    unsigned char out[1]; size_t len=0;
    ASSERT_EQ(challenge_load(g_tmpdir, hex, out, sizeof(out), &len), -1);
    rm_tmpdir();
}

/* ── challenge_delete ─────────────────────────────────────────────────── */
static void test_delete_prevents_reload(void) {
    mk_tmpdir();
    char hex[65]; challenge_create(g_tmpdir, hex, sizeof(hex));
    challenge_delete(g_tmpdir, hex);
    unsigned char out[64]; size_t len=0;
    ASSERT_EQ(challenge_load(g_tmpdir, hex, out, sizeof(out), &len), -1);
    rm_tmpdir();
}

static void test_delete_idempotent(void) {
    mk_tmpdir();
    char hex[65]; challenge_create(g_tmpdir, hex, sizeof(hex));
    challenge_delete(g_tmpdir, hex);
    challenge_delete(g_tmpdir, hex); /* second call must not crash */
    rm_tmpdir();
}

static void test_delete_missing_no_crash(void) {
    mk_tmpdir();
    challenge_delete(g_tmpdir,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    rm_tmpdir();
}

/* ── main ─────────────────────────────────────────────────────────────── */
int main(void) {
    printf("=== challenge_store ===\n");
    RUN(test_create_returns_zero);
    RUN(test_create_hex_is_64_chars);
    RUN(test_create_hex_chars_lowercase);
    RUN(test_create_file_exists);
    RUN(test_create_unique_ids);
    RUN(test_create_bad_dir_fails);
    RUN(test_create_small_buf_fails);
    RUN(test_load_roundtrip);
    RUN(test_load_missing_fails);
    RUN(test_load_expired_fails);
    RUN(test_load_expired_deletes_file);
    RUN(test_load_rejects_path_traversal);
    RUN(test_load_rejects_non_hex);
    RUN(test_load_small_output_buf_fails);
    RUN(test_delete_prevents_reload);
    RUN(test_delete_idempotent);
    RUN(test_delete_missing_no_crash);
    RUN(test_sweep_removes_expired_keeps_fresh_and_foreign);
    RUN(test_sweep_respects_limit);
    RUN(test_sweep_missing_dir_returns_minus_one);
    return SUMMARY();
}
