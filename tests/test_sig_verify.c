/*
 * test_sig_verify.c, unit tests for sig_verify.c
 *
 * Ed25519 and RSA: valid, wrong key, tampered, wrong challenge,
 * digest mismatch, NULL inputs, unknown key type.
 *
 * SPDX-License-Identifier: MIT
 */
#include "test_framework.h"

#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "../src/key_parser.h"
#include "../src/sig_verify.h"

/* Domain prefix matching sig_verify.c */
static const unsigned char PFX[] = "pg-sshkey-v2";
static const size_t        PFX_LEN = 13; /* 12 + NUL */

static const unsigned char CHAL[32] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
};

/* ── helpers ──────────────────────────────────────────────────────────── */
static EVP_PKEY *gen_ed25519(void) {
    EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);
    EVP_PKEY_keygen_init(ctx); EVP_PKEY *pk=NULL;
    EVP_PKEY_keygen(ctx,&pk); EVP_PKEY_CTX_free(ctx); return pk;
}

static EVP_PKEY *gen_rsa2048(void) {
    EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_from_name(NULL,"RSA",NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,2048);
    EVP_PKEY *pk=NULL; EVP_PKEY_keygen(ctx,&pk);
    EVP_PKEY_CTX_free(ctx); return pk;
}

static int do_sign(EVP_PKEY *sk, const EVP_MD *md,
                   const unsigned char *challenge, size_t clen,
                   unsigned char **sig, size_t *slen) {
    unsigned char msg[512];
    size_t mlen = PFX_LEN + clen;
    if (mlen > sizeof(msg)) return -1;
    memcpy(msg, PFX, PFX_LEN);
    memcpy(msg + PFX_LEN, challenge, clen);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx,NULL,md,NULL,sk);
    size_t n=0; EVP_DigestSign(ctx,NULL,&n,msg,mlen);
    *sig=malloc(n);
    int ok=(EVP_DigestSign(ctx,*sig,&n,msg,mlen)==1)?0:-1;
    EVP_MD_CTX_free(ctx); *slen=n; return ok;
}

static key_list_t make_entry(EVP_PKEY *pk, const char *type) {
    key_list_t e={0}; e.key_type=(char*)type; e.pkey=pk; return e;
}

/* The module verifies a prepared message; build it the way the client does. */
static int verify_prefixed(const key_list_t *e,
                           const unsigned char *chal, size_t clen,
                           const unsigned char *sig, size_t slen) {
    unsigned char msg[512];
    if (PFX_LEN + clen > sizeof(msg)) return -1;
    memcpy(msg, PFX, PFX_LEN);
    memcpy(msg + PFX_LEN, chal, clen);
    return verify_signature_raw(e, msg, PFX_LEN + clen, sig, slen);
}

/* ── Ed25519 ──────────────────────────────────────────────────────────── */
static void test_ed25519_valid(void) {
    EVP_PKEY *sk=gen_ed25519();
    unsigned char *sig=NULL; size_t slen=0;
    ASSERT_EQ(do_sign(sk,NULL,CHAL,sizeof(CHAL),&sig,&slen),0);
    key_list_t e=make_entry(sk,"ssh-ed25519");
    ASSERT_EQ(verify_prefixed(&e,CHAL,sizeof(CHAL),sig,slen),0);
    free(sig); EVP_PKEY_free(sk);
}

static void test_ed25519_wrong_key(void) {
    EVP_PKEY *signer=gen_ed25519(), *other=gen_ed25519();
    unsigned char *sig=NULL; size_t slen=0;
    do_sign(signer,NULL,CHAL,sizeof(CHAL),&sig,&slen);
    key_list_t e=make_entry(other,"ssh-ed25519");
    ASSERT_NE(verify_prefixed(&e,CHAL,sizeof(CHAL),sig,slen),0);
    free(sig); EVP_PKEY_free(signer); EVP_PKEY_free(other);
}

static void test_ed25519_tampered_sig(void) {
    EVP_PKEY *sk=gen_ed25519();
    unsigned char *sig=NULL; size_t slen=0;
    do_sign(sk,NULL,CHAL,sizeof(CHAL),&sig,&slen);
    sig[0]^=0x01;
    key_list_t e=make_entry(sk,"ssh-ed25519");
    ASSERT_NE(verify_prefixed(&e,CHAL,sizeof(CHAL),sig,slen),0);
    free(sig); EVP_PKEY_free(sk);
}

static void test_ed25519_wrong_challenge(void) {
    EVP_PKEY *sk=gen_ed25519();
    unsigned char *sig=NULL; size_t slen=0;
    do_sign(sk,NULL,CHAL,sizeof(CHAL),&sig,&slen);
    unsigned char other[32]; memset(other,0xff,sizeof(other));
    key_list_t e=make_entry(sk,"ssh-ed25519");
    ASSERT_NE(verify_prefixed(&e,other,sizeof(other),sig,slen),0);
    free(sig); EVP_PKEY_free(sk);
}

static void test_ed25519_truncated_sig(void) {
    EVP_PKEY *sk=gen_ed25519();
    unsigned char *sig=NULL; size_t slen=0;
    do_sign(sk,NULL,CHAL,sizeof(CHAL),&sig,&slen);
    key_list_t e=make_entry(sk,"ssh-ed25519");
    ASSERT_NE(verify_prefixed(&e,CHAL,sizeof(CHAL),sig,slen/2),0);
    free(sig); EVP_PKEY_free(sk);
}

/* ── RSA ──────────────────────────────────────────────────────────────── */
static void test_rsa_sha256_valid(void) {
    EVP_PKEY *sk=gen_rsa2048();
    unsigned char *sig=NULL; size_t slen=0;
    ASSERT_EQ(do_sign(sk,EVP_sha256(),CHAL,sizeof(CHAL),&sig,&slen),0);
    key_list_t e=make_entry(sk,"rsa-sha2-256");
    ASSERT_EQ(verify_prefixed(&e,CHAL,sizeof(CHAL),sig,slen),0);
    free(sig); EVP_PKEY_free(sk);
}

/* The rsa-sha2-512 key-type word is accepted as an alias: it names the same
   RSA key, and every shipped signer produces PKCS#1 v1.5 / SHA-256. */
static void test_rsa_sha512_label_verifies_sha256_sig(void) {
    EVP_PKEY *sk=gen_rsa2048();
    unsigned char *sig=NULL; size_t slen=0;
    ASSERT_EQ(do_sign(sk,EVP_sha256(),CHAL,sizeof(CHAL),&sig,&slen),0);
    key_list_t e=make_entry(sk,"rsa-sha2-512");
    ASSERT_EQ(verify_prefixed(&e,CHAL,sizeof(CHAL),sig,slen),0);
    free(sig); EVP_PKEY_free(sk);
}

static void test_ssh_rsa_alias_sha256(void) {
    EVP_PKEY *sk=gen_rsa2048();
    unsigned char *sig=NULL; size_t slen=0;
    do_sign(sk,EVP_sha256(),CHAL,sizeof(CHAL),&sig,&slen);
    key_list_t e=make_entry(sk,"ssh-rsa");
    ASSERT_EQ(verify_prefixed(&e,CHAL,sizeof(CHAL),sig,slen),0);
    free(sig); EVP_PKEY_free(sk);
}

static void test_rsa_wrong_key(void) {
    EVP_PKEY *sk=gen_rsa2048(), *other=gen_rsa2048();
    unsigned char *sig=NULL; size_t slen=0;
    do_sign(sk,EVP_sha256(),CHAL,sizeof(CHAL),&sig,&slen);
    key_list_t e=make_entry(other,"rsa-sha2-256");
    ASSERT_NE(verify_prefixed(&e,CHAL,sizeof(CHAL),sig,slen),0);
    free(sig); EVP_PKEY_free(sk); EVP_PKEY_free(other);
}

/* A SHA-512 signature is not accepted under any label, no signer emits one. */
static void test_rsa_sha512_sig_rejected_under_any_label(void) {
    EVP_PKEY *sk=gen_rsa2048();
    unsigned char *sig=NULL; size_t slen=0;
    do_sign(sk,EVP_sha512(),CHAL,sizeof(CHAL),&sig,&slen);
    const char *labels[]={"rsa-sha2-512","rsa-sha2-256","ssh-rsa"};
    for (size_t i=0;i<3;i++) {
        key_list_t e=make_entry(sk,labels[i]);
        ASSERT_NE(verify_prefixed(&e,CHAL,sizeof(CHAL),sig,slen),0);
    }
    free(sig); EVP_PKEY_free(sk);
}

/* ── NULL / error paths ───────────────────────────────────────────────── */
static void test_null_entry(void) {
    unsigned char sig[64]={0};
    ASSERT_NE(verify_signature_raw(NULL,CHAL,sizeof(CHAL),sig,sizeof(sig)),0);
}

static void test_null_pkey(void) {
    key_list_t e={0}; e.key_type=(char*)"ssh-ed25519"; e.pkey=NULL;
    unsigned char sig[64]={0};
    ASSERT_NE(verify_prefixed(&e,CHAL,sizeof(CHAL),sig,sizeof(sig)),0);
}

static void test_null_challenge(void) {
    EVP_PKEY *sk=gen_ed25519();
    key_list_t e=make_entry(sk,"ssh-ed25519");
    unsigned char sig[64]={0};
    /* a NULL message is refused by the function the module calls */
    ASSERT_NE(verify_signature_raw(&e,NULL,32,sig,sizeof(sig)),0);
    EVP_PKEY_free(sk);
}

static void test_null_sig(void) {
    EVP_PKEY *sk=gen_ed25519();
    key_list_t e=make_entry(sk,"ssh-ed25519");
    ASSERT_NE(verify_prefixed(&e,CHAL,sizeof(CHAL),NULL,64),0);
    EVP_PKEY_free(sk);
}

static void test_unknown_key_type(void) {
    EVP_PKEY *sk=gen_ed25519();
    key_list_t e=make_entry(sk,"ssh-mystery-algo");
    unsigned char sig[64]={0};
    ASSERT_NE(verify_prefixed(&e,CHAL,sizeof(CHAL),sig,sizeof(sig)),0);
    EVP_PKEY_free(sk);
}

static void test_empty_sig(void) {
    EVP_PKEY *sk=gen_ed25519();
    key_list_t e=make_entry(sk,"ssh-ed25519");
    unsigned char sig[1]={0};
    ASSERT_NE(verify_prefixed(&e,CHAL,sizeof(CHAL),sig,0),0);
    EVP_PKEY_free(sk);
}

/* ── main ─────────────────────────────────────────────────────────────── */
int main(void) {
    printf("=== sig_verify ===\n");
    RUN(test_ed25519_valid);
    RUN(test_ed25519_wrong_key);
    RUN(test_ed25519_tampered_sig);
    RUN(test_ed25519_wrong_challenge);
    RUN(test_ed25519_truncated_sig);
    RUN(test_rsa_sha256_valid);
    RUN(test_rsa_sha512_label_verifies_sha256_sig);
    RUN(test_ssh_rsa_alias_sha256);
    RUN(test_rsa_wrong_key);
    RUN(test_rsa_sha512_sig_rejected_under_any_label);
    RUN(test_null_entry);
    RUN(test_null_pkey);
    RUN(test_null_challenge);
    RUN(test_null_sig);
    RUN(test_unknown_key_type);
    RUN(test_empty_sig);
    return SUMMARY();
}
