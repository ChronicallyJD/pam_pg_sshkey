/*
 * test_key_parser.c — unit tests for key_parser.c
 *
 * Covers: b64_decode, parse_authorized_keys, free_key_list.
 * Keys are generated ephemerally via OpenSSL (no static private key material).
 *
 * SPDX-License-Identifier: MIT
 */
#include "test_framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "../src/key_parser.h"

/* ── helpers ──────────────────────────────────────────────────────────── */
static char g_dir[256];

static void mk_dir(void) {
    snprintf(g_dir,sizeof(g_dir),"/tmp/pam_kp_%d",(int)getpid());
    mkdir(g_dir,0700);
}
static void rm_dir(void) {
    char cmd[512]; snprintf(cmd,sizeof(cmd),"rm -rf %s",g_dir); system(cmd);
}

static char *b64_enc(const unsigned char *data, size_t len) {
    BIO *b64=BIO_new(BIO_f_base64()), *mem=BIO_new(BIO_s_mem());
    BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);
    b64=BIO_push(b64,mem);
    BIO_write(b64,data,(int)len); BIO_flush(b64);
    BUF_MEM *bp=NULL; BIO_get_mem_ptr(b64,&bp);
    char *out=malloc(bp->length+1);
    memcpy(out,bp->data,bp->length); out[bp->length]='\0';
    BIO_free_all(b64); return out;
}

/* Build SSH wire-format blob for Ed25519 */
static size_t ed25519_blob(const unsigned char *pub32,
                            unsigned char *out, size_t out_size) {
    const char *kt="ssh-ed25519"; size_t kl=strlen(kt);
    size_t total=4+kl+4+32; if(total>out_size)return 0;
    unsigned char *p=out;
    p[0]=0;p[1]=0;p[2]=0;p[3]=(unsigned char)kl; p+=4;
    memcpy(p,kt,kl); p+=kl;
    p[0]=0;p[1]=0;p[2]=0;p[3]=32; p+=4;
    memcpy(p,pub32,32); return total;
}

static EVP_PKEY *gen_ed25519(void) {
    EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);
    EVP_PKEY_keygen_init(ctx); EVP_PKEY *pk=NULL;
    EVP_PKEY_keygen(ctx,&pk); EVP_PKEY_CTX_free(ctx); return pk;
}

/* Generate a valid authorized_keys line for an Ed25519 key */
static void make_ed25519_line(EVP_PKEY *pk, char *out, size_t out_size) {
    unsigned char raw[32]; size_t raw_len=sizeof(raw);
    EVP_PKEY_get_raw_public_key(pk,raw,&raw_len);
    unsigned char blob[256];
    size_t blen=ed25519_blob(raw,blob,sizeof(blob));
    char *b64=b64_enc(blob,blen);
    snprintf(out,out_size,"ssh-ed25519 %s test-comment",b64);
    free(b64);
}

static char *write_file(const char *name, const char *content) {
    static char path[512];
    snprintf(path,sizeof(path),"%s/%s",g_dir,name);
    FILE *f=fopen(path,"w"); fputs(content,f); fclose(f); return path;
}

/* ── b64_decode ───────────────────────────────────────────────────────── */
static void test_b64_known_value(void) {
    unsigned char out[16]; size_t len=0;
    ASSERT_EQ(b64_decode("aGVsbG8=",out,sizeof(out),&len),0);
    ASSERT_EQ((int)len,5);
    ASSERT_MEM_EQ(out,"hello",5);
}

static void test_b64_empty_fails(void) {
    unsigned char out[16]; size_t len=0;
    ASSERT_NE(b64_decode("",out,sizeof(out),&len),0);
}

static void test_b64_zero_buf_fails(void) {
    /* A zero-size output buffer cannot hold any decoded bytes */
    unsigned char out[1]; size_t len=0;
    int rc = b64_decode("aGVsbG8=", out, 0, &len);
    ASSERT_NE(rc, 0);
}

static void test_b64_roundtrip(void) {
    unsigned char orig[32]; for(int i=0;i<32;i++) orig[i]=(unsigned char)i;
    char *enc=b64_enc(orig,sizeof(orig));
    unsigned char dec[64]; size_t len=0;
    ASSERT_EQ(b64_decode(enc,dec,sizeof(dec),&len),0);
    ASSERT_EQ((int)len,32);
    ASSERT_MEM_EQ(orig,dec,32);
    free(enc);
}

/* ── parse_authorized_keys ────────────────────────────────────────────── */
static void test_parse_missing_file(void) {
    key_list_t *k=NULL;
    ASSERT_EQ(parse_authorized_keys("/tmp/__nope_pam__",&k),-1);
    ASSERT_NULL(k);
}

static void test_parse_single_ed25519(void) {
    mk_dir();
    EVP_PKEY *pk=gen_ed25519();
    char line[512]; make_ed25519_line(pk,line,sizeof(line));
    char *path=write_file("single",line);
    key_list_t *k=NULL;
    ASSERT_EQ(parse_authorized_keys(path,&k),1);
    ASSERT_NOT_NULL(k);
    ASSERT_STR_EQ(k->key_type,"ssh-ed25519");
    ASSERT_NOT_NULL(k->pkey);
    free_key_list(k); EVP_PKEY_free(pk); rm_dir();
}

static void test_parse_comment_field(void) {
    mk_dir();
    EVP_PKEY *pk=gen_ed25519();
    char line[512]; make_ed25519_line(pk,line,sizeof(line));
    char *path=write_file("comment",line);
    key_list_t *k=NULL; parse_authorized_keys(path,&k);
    ASSERT_NOT_NULL(k);
    ASSERT_STR_EQ(k->comment,"test-comment");
    free_key_list(k); EVP_PKEY_free(pk); rm_dir();
}

static void test_parse_skips_hash_comments(void) {
    mk_dir();
    char *path=write_file("hashes","# comment\n# another\n");
    key_list_t *k=NULL;
    ASSERT_EQ(parse_authorized_keys(path,&k),0);
    ASSERT_NULL(k);
    rm_dir();
}

static void test_parse_skips_empty_lines(void) {
    mk_dir();
    char *path=write_file("empty","\n\n\n");
    key_list_t *k=NULL;
    ASSERT_EQ(parse_authorized_keys(path,&k),0);
    rm_dir();
}

static void test_parse_skips_unsupported_type(void) {
    mk_dir();
    char *path=write_file("ecdsa","ecdsa-sha2-nistp256 AAAAE2Vj key\n");
    key_list_t *k=NULL;
    ASSERT_EQ(parse_authorized_keys(path,&k),0);
    rm_dir();
}

static void test_parse_multiple_keys(void) {
    mk_dir();
    EVP_PKEY *pk1=gen_ed25519(), *pk2=gen_ed25519();
    char l1[512],l2[512];
    make_ed25519_line(pk1,l1,sizeof(l1));
    make_ed25519_line(pk2,l2,sizeof(l2));
    char content[1200];
    snprintf(content,sizeof(content),"%s\n# sep\n%s\n",l1,l2);
    char *path=write_file("multi",content);
    key_list_t *k=NULL;
    ASSERT_EQ(parse_authorized_keys(path,&k),2);
    int cnt=0; for(key_list_t *e=k;e;e=e->next) cnt++;
    ASSERT_EQ(cnt,2);
    free_key_list(k); EVP_PKEY_free(pk1); EVP_PKEY_free(pk2); rm_dir();
}

static void test_parse_bad_base64_skipped(void) {
    mk_dir();
    char *path=write_file("badb64","ssh-ed25519 NOT!VALID!!! bad\n");
    key_list_t *k=NULL;
    ASSERT_EQ(parse_authorized_keys(path,&k),0);
    rm_dir();
}

/* ── free_key_list ────────────────────────────────────────────────────── */
static void test_free_null(void) { free_key_list(NULL); /* no crash */ }

static void test_free_single(void) {
    mk_dir();
    EVP_PKEY *pk=gen_ed25519();
    char line[512]; make_ed25519_line(pk,line,sizeof(line));
    char *path=write_file("sfree",line);
    key_list_t *k=NULL; parse_authorized_keys(path,&k);
    free_key_list(k); EVP_PKEY_free(pk); rm_dir();
}

/* ── main ─────────────────────────────────────────────────────────────── */
int main(void) {
    printf("=== key_parser ===\n");
    RUN(test_b64_known_value);
    RUN(test_b64_empty_fails);
    RUN(test_b64_zero_buf_fails);
    RUN(test_b64_roundtrip);
    RUN(test_parse_missing_file);
    RUN(test_parse_single_ed25519);
    RUN(test_parse_comment_field);
    RUN(test_parse_skips_hash_comments);
    RUN(test_parse_skips_empty_lines);
    RUN(test_parse_skips_unsupported_type);
    RUN(test_parse_multiple_keys);
    RUN(test_parse_bad_base64_skipped);
    RUN(test_free_null);
    RUN(test_free_single);
    return SUMMARY();
}
