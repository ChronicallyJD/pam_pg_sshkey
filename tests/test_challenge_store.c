/*
 * test_challenge_store.c
 *
 * Unit tests for challenge_store.c:
 *   challenge_mark , records a nonce once and refuses it thereafter
 *   challenge_sweep, removes records too old to matter and nothing else
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







/* ── challenge_load ───────────────────────────────────────────────────── */







/* ── challenge_delete ─────────────────────────────────────────────────── */



/* ── challenge_mark ──────────────────────────────────────────────────── */
static void test_mark_records_once(void) {
    mk_tmpdir();
    ASSERT_EQ(challenge_mark(g_tmpdir, HEX_A), 0);   /* first use */
    ASSERT_TRUE(file_exists(HEX_A));
    ASSERT_EQ(challenge_mark(g_tmpdir, HEX_A), 1);   /* the same nonce again */
    rm_tmpdir();
}

static void test_mark_file_is_private(void) {
    mk_tmpdir();
    ASSERT_EQ(challenge_mark(g_tmpdir, HEX_A), 0);
    char path[512]; snprintf(path,sizeof(path),"%s/%s",g_tmpdir,HEX_A);
    struct stat st;
    ASSERT_EQ(stat(path,&st), 0);
    ASSERT_EQ((int)(st.st_mode & 07777), 0600);
    rm_tmpdir();
}

static void test_mark_rejects_bad_names(void) {
    mk_tmpdir();
    /* a name that is not 64 lowercase hex characters cannot become a path */
    ASSERT_NE(challenge_mark(g_tmpdir, "../../etc/passwd"), 0);
    ASSERT_NE(challenge_mark(g_tmpdir, "SHORT"), 0);
    ASSERT_NE(challenge_mark(g_tmpdir, "ZZ"), 0);
    rm_tmpdir();
}

static void test_mark_missing_dir_fails(void) {
    ASSERT_NE(challenge_mark("/nonexistent-pam-pg-sshkey", HEX_A), 0);
}

/* ── main ─────────────────────────────────────────────────────────────── */
int main(void) {
    printf("=== challenge_store ===\n");
    RUN(test_mark_records_once);
    RUN(test_mark_file_is_private);
    RUN(test_mark_rejects_bad_names);
    RUN(test_mark_missing_dir_fails);
    RUN(test_sweep_removes_expired_keeps_fresh_and_foreign);
    RUN(test_sweep_respects_limit);
    RUN(test_sweep_missing_dir_returns_minus_one);
    return SUMMARY();
}
