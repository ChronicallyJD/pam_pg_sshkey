/*
 * test_integration.c — end-to-end flow tests
 *
 * Exercises: challenge_create → sign → parse_authorized_keys → verify_signature
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

#include "../src/challenge_store.h"
#include "../src/key_parser.h"
#include "../src/sig_verify.h"

static const unsigned char PFX[] = "pg-sshkey-v1";
static const size_t        PFX_LEN = 13;

static char g_dir[256];

static void mk_dir(void) {
    snprintf(g_dir,sizeof(g_dir),"/tmp/pam_integ_%d",(int)getpid());
    mkdir(g_dir,0700);
}
static void rm_dir(void) {
    char cmd[512]; snprintf(cmd,sizeof(cmd),"rm -rf %s",g_dir); system(cmd);
}

static char *b64_enc(const unsigned char *d, size_t n) {
    BIO *b=BIO_new(BIO_f_base64()), *m=BIO_new(BIO_s_mem());
    BIO_set_flags(b,BIO_FLAGS_BASE64_NO_NL); b=BIO_push(b,m);
    BIO_write(b,d,(int)n); BIO_flush(b);
    BUF_MEM *bp=NULL; BIO_get_mem_ptr(b,&bp);
    char *out=malloc(bp->length+1);
    memcpy(out,bp->data,bp->length); out[bp->length]='\0';
    BIO_free_all(b); return out;
}

static size_t ed25519_blob(const unsigned char *pub32,
                            unsigned char *out, size_t sz) {
    const char *kt="ssh-ed25519"; size_t kl=strlen(kt);
    size_t tot=4+kl+4+32; if(tot>sz)return 0;
    unsigned char *p=out;
    p[0]=0;p[1]=0;p[2]=0;p[3]=(unsigned char)kl; p+=4;
    memcpy(p,kt,kl); p+=kl;
    p[0]=0;p[1]=0;p[2]=0;p[3]=32; p+=4;
    memcpy(p,pub32,32); return tot;
}

static EVP_PKEY *gen_ed25519(void) {
    EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);
    EVP_PKEY_keygen_init(ctx); EVP_PKEY *pk=NULL;
    EVP_PKEY_keygen(ctx,&pk); EVP_PKEY_CTX_free(ctx); return pk;
}

static void write_authkeys(const char *path, EVP_PKEY *pk) {
    unsigned char raw[32]; size_t rlen=sizeof(raw);
    EVP_PKEY_get_raw_public_key(pk,raw,&rlen);
    unsigned char blob[256]; size_t blen=ed25519_blob(raw,blob,sizeof(blob));
    char *b64=b64_enc(blob,blen);
    FILE *f=fopen(path,"w"); fprintf(f,"ssh-ed25519 %s integ\n",b64);
    fclose(f); free(b64);
}

static int sign_chal(EVP_PKEY *sk,
                      const unsigned char *chal, size_t clen,
                      unsigned char **sig, size_t *slen) {
    unsigned char msg[512]; size_t mlen=PFX_LEN+clen;
    if(mlen>sizeof(msg))return -1;
    memcpy(msg,PFX,PFX_LEN); memcpy(msg+PFX_LEN,chal,clen);
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx,NULL,NULL,NULL,sk);
    size_t n=0; EVP_DigestSign(ctx,NULL,&n,msg,mlen);
    *sig=malloc(n);
    int ok=(EVP_DigestSign(ctx,*sig,&n,msg,mlen)==1)?0:-1;
    EVP_MD_CTX_free(ctx); *slen=n; return ok;
}

/* ── tests ────────────────────────────────────────────────────────────── */
static void test_happy_path(void) {
    mk_dir();
    EVP_PKEY *sk=gen_ed25519();

    char akpath[512]; snprintf(akpath,sizeof(akpath),"%s/ak",g_dir);
    write_authkeys(akpath,sk);

    char cdir[512]; snprintf(cdir,sizeof(cdir),"%s/c",g_dir);
    mkdir(cdir,0700);

    char hex[65]; ASSERT_EQ(challenge_create(cdir,hex,sizeof(hex)),0);

    unsigned char cbytes[64]; size_t clen=0;
    ASSERT_EQ(challenge_load(cdir,hex,cbytes,sizeof(cbytes),&clen),0);
    ASSERT_EQ((int)clen,32);
    challenge_delete(cdir,hex);

    unsigned char *sig=NULL; size_t slen=0;
    ASSERT_EQ(sign_chal(sk,cbytes,clen,&sig,&slen),0);

    key_list_t *keys=NULL; ASSERT_EQ(parse_authorized_keys(akpath,&keys),1);
    ASSERT_EQ(verify_signature(keys,cbytes,clen,sig,slen),0);

    free(sig); free_key_list(keys); EVP_PKEY_free(sk); rm_dir();
}

static void test_replay_prevented(void) {
    mk_dir();
    char cdir[512]; snprintf(cdir,sizeof(cdir),"%s/c",g_dir);
    mkdir(cdir,0700);

    char hex[65]; challenge_create(cdir,hex,sizeof(hex));
    unsigned char cbytes[64]; size_t clen=0;
    challenge_load(cdir,hex,cbytes,sizeof(cbytes),&clen);
    challenge_delete(cdir,hex); /* first auth consumes nonce */

    /* Second load of same nonce must fail */
    unsigned char cb2[64]; size_t cl2=0;
    ASSERT_EQ(challenge_load(cdir,hex,cb2,sizeof(cb2),&cl2),-1);
    rm_dir();
}

static void test_wrong_key_rejected(void) {
    mk_dir();
    EVP_PKEY *legit=gen_ed25519(), *attacker=gen_ed25519();

    char akpath[512]; snprintf(akpath,sizeof(akpath),"%s/ak",g_dir);
    write_authkeys(akpath,legit); /* only legit is authorised */

    char cdir[512]; snprintf(cdir,sizeof(cdir),"%s/c",g_dir);
    mkdir(cdir,0700);

    char hex[65]; challenge_create(cdir,hex,sizeof(hex));
    unsigned char cbytes[64]; size_t clen=0;
    challenge_load(cdir,hex,cbytes,sizeof(cbytes),&clen);
    challenge_delete(cdir,hex);

    unsigned char *sig=NULL; size_t slen=0;
    sign_chal(attacker,cbytes,clen,&sig,&slen); /* attacker signs */

    key_list_t *keys=NULL; parse_authorized_keys(akpath,&keys);
    ASSERT_NE(verify_signature(keys,cbytes,clen,sig,slen),0);

    free(sig); free_key_list(keys); EVP_PKEY_free(legit); EVP_PKEY_free(attacker); rm_dir();
}

static void test_multiple_authorised_keys(void) {
    mk_dir();
    EVP_PKEY *kp[2];
    for(int i=0;i<2;i++) kp[i]=gen_ed25519();

    char akpath[512]; snprintf(akpath,sizeof(akpath),"%s/ak",g_dir);
    FILE *f=fopen(akpath,"w");
    for(int i=0;i<2;i++){
        unsigned char raw[32]; size_t rlen=sizeof(raw);
        EVP_PKEY_get_raw_public_key(kp[i],raw,&rlen);
        unsigned char blob[256]; size_t blen=ed25519_blob(raw,blob,sizeof(blob));
        char *b64=b64_enc(blob,blen);
        fprintf(f,"ssh-ed25519 %s key%d\n",b64,i); free(b64);
    }
    fclose(f);

    char cdir[512]; snprintf(cdir,sizeof(cdir),"%s/c",g_dir);
    mkdir(cdir,0700);

    for(int k=0;k<2;k++){
        char hex[65]; challenge_create(cdir,hex,sizeof(hex));
        unsigned char cbytes[64]; size_t clen=0;
        challenge_load(cdir,hex,cbytes,sizeof(cbytes),&clen);
        challenge_delete(cdir,hex);

        unsigned char *sig=NULL; size_t slen=0;
        sign_chal(kp[k],cbytes,clen,&sig,&slen);

        key_list_t *keys=NULL; parse_authorized_keys(akpath,&keys);
        int found=0;
        for(key_list_t *e=keys;e;e=e->next)
            if(verify_signature(e,cbytes,clen,sig,slen)==0){found=1;break;}
        ASSERT_TRUE(found);
        free(sig); free_key_list(keys);
    }

    for(int i=0;i<2;i++) EVP_PKEY_free(kp[i]);
    rm_dir();
}

/* ── main ─────────────────────────────────────────────────────────────── */
int main(void) {
    printf("=== integration ===\n");
    RUN(test_happy_path);
    RUN(test_replay_prevented);
    RUN(test_wrong_key_rejected);
    RUN(test_multiple_authorised_keys);
    return SUMMARY();
}
