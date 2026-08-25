/*
 * ssh_agent.c
 *
 * A minimal ssh-agent client: request identities, request a signature.
 *
 * Wire format (OpenSSH PROTOCOL.agent).  Every message is
 *
 *     uint32  length
 *     byte    type
 *     ...payload
 *
 * Requests used here:
 *   SSH_AGENTC_REQUEST_IDENTITIES (11)
 *     -> SSH_AGENT_IDENTITIES_ANSWER (12): uint32 n, then n x (string blob,
 *        string comment)
 *   SSH_AGENTC_SIGN_REQUEST (13): string key_blob, string data, uint32 flags
 *     -> SSH_AGENT_SIGN_RESPONSE (14): string signature
 *        signature = string algorithm, string signature_bytes
 *
 * flags carries SSH_AGENT_RSA_SHA2_256 for RSA keys: without it an agent
 * signs with SHA-1, which the PAM module refuses.
 *
 * SPDX-License-Identifier: MIT
 */

#include "ssh_agent.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "key_parser.h"

#define SSH_AGENTC_REQUEST_IDENTITIES  11
#define SSH_AGENT_IDENTITIES_ANSWER    12
#define SSH_AGENTC_SIGN_REQUEST        13
#define SSH_AGENT_SIGN_RESPONSE        14
#define SSH_AGENT_RSA_SHA2_256          2

#define AGENT_MAX_MSG   (256 * 1024)
/* Generous: an agent may be waiting for a person to confirm (ssh-add -c) or
   to enter a smartcard PIN.  Only a wedged agent should ever hit this. */
#define AGENT_TIMEOUT_MS_DEFAULT 60000
#define PUBKEY_MAX_LINE (64 * 1024)

/*
 * Copy an agent-supplied string for printing.  Everything the agent sends is
 * attacker-controlled when the socket is forwarded from another host, and
 * these strings reach a terminal: an escape or a carriage return could
 * repaint the line and fake a prompt.  Only printable ASCII survives.
 */
static const char *
printable(const unsigned char *s, size_t n, char *out, size_t out_size)
{
    size_t i = 0;
    for (; i < n && i < out_size - 1; i++)
        out[i] = (s[i] >= 0x20 && s[i] <= 0x7e) ? (char)s[i] : '?';
    out[i] = '\0';
    return out;
}

/* ── wire helpers ─────────────────────────────────────────────────────── */

static void
put_u32(unsigned char *p, size_t v)
{
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}

static size_t
get_u32(const unsigned char *p)
{
    return ((size_t)p[0] << 24) | ((size_t)p[1] << 16) |
           ((size_t)p[2] << 8)  |  (size_t)p[3];
}

/* Read one length-prefixed string, advancing *pos.  0 on success. */
static int
rd_string(const unsigned char *buf, size_t len, size_t *pos,
          const unsigned char **out, size_t *out_len)
{
    if (len < 4 || *pos > len - 4) return -1;
    size_t n = get_u32(buf + *pos);
    if (n > len - *pos - 4) return -1;
    *out = buf + *pos + 4;
    *out_len = n;
    *pos += 4 + n;
    return 0;
}

/* ── public key file ──────────────────────────────────────────────────── */

unsigned char *
ssh_pubkey_blob_from_file(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Cannot read public key %s: %s\n", path, strerror(errno));
        return NULL;
    }
    char *line = malloc(PUBKEY_MAX_LINE);
    if (!line) { fclose(f); return NULL; }
    if (!fgets(line, PUBKEY_MAX_LINE, f)) {
        fprintf(stderr, "Public key %s is empty\n", path);
        fclose(f); free(line);
        return NULL;
    }
    if (!strchr(line, '\n') && !feof(f)) {
        fprintf(stderr, "Public key %s: line too long\n", path);
        fclose(f); free(line);
        return NULL;
    }
    fclose(f);

    /* second whitespace field: the base64 blob */
    char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
    while (*p == ' ' || *p == '\t') p++;
    char *b64 = p;
    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
    size_t b64_len = (size_t)(p - b64);
    if (b64_len == 0 || b64_len % 4 != 0) {
        fprintf(stderr,
                "%s is not an OpenSSH public key line "
                "(expected '<type> <base64> [comment]', as ssh-keygen -y writes)\n",
                path);
        free(line);
        return NULL;
    }
    for (size_t i = 0; i < b64_len; i++) {
        char c = b64[i];
        if (!(isalnum((unsigned char)c) || c == '+' || c == '/' || c == '=')) {
            fprintf(stderr, "%s: key field is not base64\n", path);
            free(line);
            return NULL;
        }
    }

    unsigned char *blob = malloc(b64_len);
    if (!blob) { free(line); return NULL; }
    BIO *b = BIO_new_mem_buf(b64, (int)b64_len);
    BIO *d = BIO_new(BIO_f_base64());
    BIO_set_flags(d, BIO_FLAGS_BASE64_NO_NL);
    d = BIO_push(d, b);
    int n = BIO_read(d, blob, (int)b64_len);
    BIO_free_all(d);
    free(line);
    if (n <= 0) {
        fprintf(stderr, "%s: cannot decode the key field\n", path);
        free(blob);
        return NULL;
    }
    *len_out = (size_t)n;
    return blob;
}

/* ── socket ───────────────────────────────────────────────────────────── */

static int
agent_connect(void)
{
    const char *sock = getenv("SSH_AUTH_SOCK");
    if (!sock || !*sock) {
        fprintf(stderr,
            "No ssh-agent: SSH_AUTH_SOCK is not set.\n"
            "Start one and add the key:\n"
            "  eval $(ssh-agent)\n"
            "  ssh-add ~/.ssh/id_ed25519\n");
        return -1;
    }
    struct sockaddr_un addr;
    if (strlen(sock) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "SSH_AUTH_SOCK path is too long: %s\n", sock);
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    /*
     * A wedged or hostile agent must not hang the login.  With a forwarded
     * agent the socket is served by another host, so this is not theoretical.
     * PG_SSHKEY_AGENT_TIMEOUT_MS exists so the tests need not wait 10 s.
     */
    long ms = AGENT_TIMEOUT_MS_DEFAULT;
    const char *tmo = getenv("PG_SSHKEY_AGENT_TIMEOUT_MS");
    if (tmo && *tmo) {
        char *end;
        long v = strtol(tmo, &end, 10);
        if (!*end && v > 0) ms = v;
    }
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "Cannot connect to the ssh-agent at %s: %s\n",
                sock, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int
write_all(int fd, const unsigned char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;   /* includes EPIPE and the send timeout */
        }
        off += (size_t)n;
    }
    return 0;
}

static int
read_all(int fd, unsigned char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/* Send one request and read the reply.  Returns the malloc'd payload
   (type byte first) and its length, or NULL. */
static unsigned char *
agent_round_trip(int fd, const unsigned char *payload, size_t payload_len,
                 size_t *reply_len)
{
    unsigned char hdr[4];
    put_u32(hdr, payload_len);
    if (write_all(fd, hdr, 4) != 0 || write_all(fd, payload, payload_len) != 0) {
        fprintf(stderr, "ssh-agent: write failed: %s\n", strerror(errno));
        return NULL;
    }
    if (read_all(fd, hdr, 4) != 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            fprintf(stderr, "ssh-agent: timed out waiting for a reply\n");
        else
            fprintf(stderr, "ssh-agent: no reply: %s\n", strerror(errno));
        return NULL;
    }
    size_t len = get_u32(hdr);
    if (len == 0 || len > AGENT_MAX_MSG) {
        fprintf(stderr, "ssh-agent: reply of %zu bytes is out of range\n", len);
        return NULL;
    }
    unsigned char *reply = malloc(len);
    if (!reply) return NULL;
    if (read_all(fd, reply, len) != 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            fprintf(stderr, "ssh-agent: timed out reading the reply\n");
        else
            fprintf(stderr, "ssh-agent: truncated reply: %s\n", strerror(errno));
        free(reply);
        return NULL;
    }
    *reply_len = len;
    return reply;
}

/* ── identities, for the "key is not in the agent" message ───────────── */

static void
report_missing_identity(int fd)
{
    unsigned char req = SSH_AGENTC_REQUEST_IDENTITIES;
    size_t reply_len = 0;
    unsigned char *reply = agent_round_trip(fd, &req, 1, &reply_len);
    if (!reply) return;

    if (reply_len < 5 || reply[0] != SSH_AGENT_IDENTITIES_ANSWER) {
        free(reply);
        return;
    }
    size_t n = get_u32(reply + 1), pos = 5;
    fprintf(stderr, "The agent holds %zu key%s:\n", n, n == 1 ? "" : "s");
    for (size_t i = 0; i < n; i++) {
        const unsigned char *blob, *comment;
        size_t blob_len, comment_len, bpos = 0;
        if (rd_string(reply, reply_len, &pos, &blob, &blob_len) != 0) break;
        if (rd_string(reply, reply_len, &pos, &comment, &comment_len) != 0) break;
        const unsigned char *type; size_t type_len;
        if (rd_string(blob, blob_len, &bpos, &type, &type_len) != 0) break;
        char tbuf[64], cbuf[256];
        fprintf(stderr, "  %s %s\n",
                printable(type, type_len, tbuf, sizeof(tbuf)),
                printable(comment, comment_len, cbuf, sizeof(cbuf)));
    }
    free(reply);
}

/* ── sign ─────────────────────────────────────────────────────────────── */

unsigned char *
ssh_agent_sign(const unsigned char *keyblob, size_t blob_len,
               const unsigned char *msg, size_t msg_len,
               size_t *sig_len_out)
{
    /* key type: the first string of the blob */
    const unsigned char *type; size_t type_len, pos = 0;
    if (rd_string(keyblob, blob_len, &pos, &type, &type_len) != 0) {
        fprintf(stderr, "The public key file does not hold an SSH key blob\n");
        return NULL;
    }
    int is_sk_ed25519 = (type_len == 26 &&
                         memcmp(type, "sk-ssh-ed25519@openssh.com", 26) == 0);
    if (type_len > 3 && memcmp(type, "sk-", 3) == 0 && !is_sk_ed25519) {
        char tbuf[64];
        fprintf(stderr,
            "Key type %s is not supported.  Of the security key types only\n"
            "sk-ssh-ed25519@openssh.com is: the server has no ECDSA verifier.\n",
            printable(type, type_len, tbuf, sizeof(tbuf)));
        return NULL;
    }
    int is_rsa = (type_len >= 7 && memcmp(type, "ssh-rsa", 7) == 0);

    int fd = agent_connect();
    if (fd < 0) return NULL;

    size_t req_len = 1 + 4 + blob_len + 4 + msg_len + 4;
    unsigned char *req = malloc(req_len);
    if (!req) { close(fd); return NULL; }
    size_t o = 0;
    req[o++] = SSH_AGENTC_SIGN_REQUEST;
    put_u32(req + o, blob_len); o += 4;
    memcpy(req + o, keyblob, blob_len); o += blob_len;
    put_u32(req + o, msg_len); o += 4;
    memcpy(req + o, msg, msg_len); o += msg_len;
    put_u32(req + o, is_rsa ? SSH_AGENT_RSA_SHA2_256 : 0); o += 4;

    size_t reply_len = 0;
    unsigned char *reply = agent_round_trip(fd, req, o, &reply_len);
    free(req);
    if (!reply) { close(fd); return NULL; }

    if (reply[0] != SSH_AGENT_SIGN_RESPONSE) {
        fprintf(stderr, "The ssh-agent refused to sign with this key.\n");
        report_missing_identity(fd);
        fprintf(stderr, "Add the key with: ssh-add <private key>\n");
        free(reply);
        close(fd);
        return NULL;
    }
    close(fd);

    /* SSH_AGENT_SIGN_RESPONSE: string signature */
    const unsigned char *sigblob; size_t sigblob_len; pos = 1;
    if (rd_string(reply, reply_len, &pos, &sigblob, &sigblob_len) != 0) {
        fprintf(stderr, "ssh-agent: malformed signature response\n");
        free(reply);
        return NULL;
    }
    /* signature = string algorithm, string bytes */
    const unsigned char *algo, *sig; size_t algo_len, sig_len, spos = 0;
    if (rd_string(sigblob, sigblob_len, &spos, &algo, &algo_len) != 0 ||
        rd_string(sigblob, sigblob_len, &spos, &sig, &sig_len) != 0) {
        fprintf(stderr, "ssh-agent: malformed signature blob\n");
        free(reply);
        return NULL;
    }
    char abuf[64];
    /*
     * A security key's signature carries a flags byte and a 4-byte counter
     * after the raw 64 bytes, and both are part of what it signed.  The
     * server needs all 69 bytes, so they travel in the token.
     */
    unsigned char sk_tail[5];
    if (is_sk_ed25519) {
        if (!(algo_len == 26 &&
              memcmp(algo, "sk-ssh-ed25519@openssh.com", 26) == 0)) {
            fprintf(stderr,
                "The ssh-agent signed with '%s'; this key needs "
                "sk-ssh-ed25519@openssh.com.\n",
                printable(algo, algo_len, abuf, sizeof(abuf)));
            free(reply);
            return NULL;
        }
        if (sigblob_len - spos != 5 || sig_len != 64) {
            fprintf(stderr,
                "The ssh-agent returned a security key signature without its\n"
                "flags and counter; the server cannot verify it.\n");
            free(reply);
            return NULL;
        }
        memcpy(sk_tail, sigblob + spos, 5);
        if ((sk_tail[0] & 0x01) == 0) {
            fprintf(stderr,
                "The security key reported no user presence: touch the key when\n"
                "it flashes.  The server refuses a signature without it.\n");
            free(reply);
            return NULL;
        }
    }
    if (!is_sk_ed25519 && is_rsa &&
        !(algo_len == 12 && memcmp(algo, "rsa-sha2-256", 12) == 0)) {
        fprintf(stderr,
            "The ssh-agent signed with '%s'; the server needs rsa-sha2-256.\n"
            "Use an OpenSSH 7.2 or newer agent, or sign from the key file.\n",
            printable(algo, algo_len, abuf, sizeof(abuf)));
        free(reply);
        return NULL;
    }
    if (!is_sk_ed25519 && !is_rsa &&
        !(algo_len == 11 && memcmp(algo, "ssh-ed25519", 11) == 0)) {
        fprintf(stderr,
            "The ssh-agent signed with '%s', which the server does not verify.\n",
            printable(algo, algo_len, abuf, sizeof(abuf)));
        free(reply);
        return NULL;
    }
    if (sig_len == 0) {
        fprintf(stderr, "The ssh-agent returned an empty signature.\n");
        free(reply);
        return NULL;
    }

    /*
     * Verify with the public key the caller named.  The agent could return
     * anything; without this a wrong or corrupt signature only surfaces as
     * "authentication failed" on the server, with nothing to go on.  A
     * certificate blob is skipped: the key inside it is not this blob.
     */
    int is_cert = (type_len > 21 &&
                   memcmp(type + type_len - 21, "-cert-v01@openssh.com", 21) == 0);
    if (is_sk_ed25519) {
        char *application = NULL;
        EVP_PKEY *pub = ssh_sk_pubkey_from_blob(keyblob, blob_len, &application);
        int ok = 0;
        if (pub && application) {
            unsigned char signed_data[32 + 1 + 4 + 32];
            unsigned int n1 = 0, n2 = 0;
            if (EVP_Digest(application, strlen(application), signed_data, &n1,
                           EVP_sha256(), NULL) == 1 && n1 == 32) {
                signed_data[32] = sk_tail[0];
                memcpy(signed_data + 33, sk_tail + 1, 4);
                if (EVP_Digest(msg, msg_len, signed_data + 37, &n2,
                               EVP_sha256(), NULL) == 1 && n2 == 32) {
                    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
                    if (ctx) {
                        if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pub) == 1)
                            ok = (EVP_DigestVerify(ctx, sig, sig_len,
                                                   signed_data,
                                                   sizeof(signed_data)) == 1);
                        EVP_MD_CTX_free(ctx);
                    }
                }
            }
        }
        free(application);
        EVP_PKEY_free(pub);
        if (!ok) {
            fprintf(stderr,
                "The security key's signature does not verify with the public\n"
                "key in the file you named.\n");
            free(reply);
            return NULL;
        }
        unsigned char *out = malloc(64 + 5);
        if (!out) { free(reply); return NULL; }
        memcpy(out, sig, 64);
        memcpy(out + 64, sk_tail, 5);
        free(reply);
        *sig_len_out = 64 + 5;
        return out;
    }
    if (!is_cert) {
        EVP_PKEY *pub = ssh_pubkey_from_blob(keyblob, blob_len);
        if (!pub) {
            fprintf(stderr, "Cannot read the public key to check the signature\n");
            free(reply);
            return NULL;
        }
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        int ok = 0;
        if (ctx) {
            const EVP_MD *md = is_rsa ? EVP_sha256() : NULL;
            if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pub) == 1)
                ok = (EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) == 1);
            EVP_MD_CTX_free(ctx);
        }
        EVP_PKEY_free(pub);
        if (!ok) {
            fprintf(stderr,
                "The ssh-agent returned a signature that does not verify with\n"
                "the public key in the file you named.  The agent may hold a\n"
                "different key under that name.\n");
            free(reply);
            return NULL;
        }
    }

    unsigned char *out = malloc(sig_len);
    if (!out) { free(reply); return NULL; }
    memcpy(out, sig, sig_len);
    free(reply);
    *sig_len_out = sig_len;
    return out;
}
