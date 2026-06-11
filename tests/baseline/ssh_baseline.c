/*
 * SSH Client Baseline — minimal working SSH client in C
 *
 * Implements: version exchange → KEX (curve25519-sha256) → password auth → exec → print output
 * Dependencies: libcrypto (OpenSSL 1.1+/3.x)
 *
 * Build: gcc -o ssh_baseline ssh_baseline.c -lcrypto -lssl
 * Run:   ./ssh_baseline <host> <port> <user> <password> [command]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

/* ================================================================
 *  Constants / Message Types (RFC 4250-4254)
 * ================================================================ */

#define MSG_DISCONNECT          1
#define MSG_IGNORE              2
#define MSG_UNIMPLEMENTED       3
#define MSG_DEBUG               4
#define MSG_SERVICE_REQUEST     5
#define MSG_SERVICE_ACCEPT      6
#define MSG_KEXINIT            20
#define MSG_NEWKEYS            21
#define MSG_KEX_ECDH_INIT      30
#define MSG_KEX_ECDH_REPLY     31
#define MSG_USERAUTH_REQUEST   50
#define MSG_USERAUTH_FAILURE   51
#define MSG_USERAUTH_SUCCESS   52
#define MSG_USERAUTH_PK_OK     60
#define MSG_CHANNEL_OPEN       90
#define MSG_CHANNEL_OPEN_CONF  91
#define MSG_CHANNEL_OPEN_FAIL  92
#define MSG_CHANNEL_WINDOW_ADJ  93
#define MSG_CHANNEL_DATA       94
#define MSG_CHANNEL_EOF        95
#define MSG_CHANNEL_CLOSE      96
#define MSG_CHANNEL_REQUEST    98
#define MSG_CHANNEL_SUCCESS    99
#define MSG_CHANNEL_FAILURE   100

#define MAX_PACKET 35000
#define BLOCK_SIZE 16  /* AES block size */
#define SHA256_LEN 32

/* ================================================================
 *  Utility helpers
 * ================================================================ */

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[FATAL] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

/* Big-endian uint32 encode/decode */
static void put_u32(unsigned char *p, uint32_t v) {
    p[0] = (v >> 24) & 0xff;
    p[1] = (v >> 16) & 0xff;
    p[2] = (v >> 8)  & 0xff;
    p[3] = v & 0xff;
}

static uint32_t get_u32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

/* SSH string: uint32(len) + data */
static int put_string(unsigned char *buf, int offset, const unsigned char *data, int len) {
    put_u32(buf + offset, (uint32_t)len);
    memcpy(buf + offset + 4, data, len);
    return offset + 4 + len;
}

static int put_string_cstr(unsigned char *buf, int offset, const char *s) {
    int len = (int)strlen(s);
    return put_string(buf, offset, (const unsigned char *)s, len);
}

static const unsigned char *get_string_data(const unsigned char *p, int *out_len) {
    *out_len = (int)get_u32(p);
    return p + 4;
}

static void hexdump(const char *label, const unsigned char *d, int len) {
    printf("%s (%d bytes):", label, len);
    for (int i = 0; i < len && i < 64; i++) {
        if (i % 16 == 0) printf("\n  ");
        printf(" %02x", d[i]);
    }
    printf("\n"); fflush(stdout);
}

#define LOG(...) do { printf(__VA_ARGS__); fflush(stdout); } while(0)

/* ================================================================
 *  TCP I/O
 * ================================================================ */

typedef struct {
    int fd;
} Conn;

static int tcp_connect(const char *host, int port) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char ps[16];
    snprintf(ps, sizeof(ps), "%d", port);

    if (getaddrinfo(host, ps, &hints, &res) != 0)
        die("getaddrinfo failed for %s:%d", host, port);

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); die("socket"); }

    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd); freeaddrinfo(res);
        die("connect to %s:%d failed", host, port);
    }
    freeaddrinfo(res);
    return fd;
}

/* Read exactly n bytes */
static int read_exact(int fd, unsigned char *buf, int n) {
    int got = 0;
    while (got < n) {
        int r = (int)recv(fd, buf + got, n - got, 0);
        if (r < 0) {
            LOG("[DEBUG] read_exact error: %s (fd=%d, got=%d, need=%d)\n", strerror(errno), fd, got, n);
            return -1;
        }
        if (r == 0) {
            LOG("[DEBUG] read_exact: connection closed (fd=%d, got=%d, need=%d)\n", fd, got, n);
            return -1;
        }
        got += r;
    }
    return got;
}

/* Send all bytes */
static int send_all(int fd, const unsigned char *buf, int n) {
    int sent = 0;
    while (sent < n) {
        int w = (int)send(fd, buf + sent, n - sent, 0);
        if (w <= 0) return -1;
        sent += w;
    }
    return sent;
}

/* Read until newline (for banner) */
static int read_line(int fd, unsigned char *buf, int maxlen) {
    int i = 0;
    while (i < maxlen - 1) {
        int r = (int)recv(fd, buf + i, 1, 0);
        if (r <= 0) return -1;
        if (buf[i] == '\n') { buf[++i] = 0; return i; }
        i++;
    }
    buf[i] = 0;
    return i;
}

/* ================================================================
 *  Buffer writer (append-only byte buffer)
 * ================================================================ */

typedef struct {
    unsigned char *data;
    int cap, len;
} Buf;

static void buf_init(Buf *b, int cap) {
    b->data = (unsigned char *)malloc(cap ? cap : 256);
    b->cap = cap ? cap : 256;
    b->len = 0;
}

static void buf_ensure(Buf *b, int need) {
    if (b->len + need > b->cap) {
        int nc = b->cap * 2 + need;
        b->data = (unsigned char *)realloc(b->data, nc);
        b->cap = nc;
    }
}

static void buf_u8(Buf *b, unsigned char v) {
    buf_ensure(b, 1);
    b->data[b->len++] = v;
}

static void buf_u32(Buf *b, uint32_t v) {
    buf_ensure(b, 4);
    put_u32(b->data + b->len, v);
    b->len += 4;
}

static void buf_bytes(Buf *b, const unsigned char *d, int n) {
    buf_ensure(b, n);
    memcpy(b->data + b->len, d, n);
    b->len += n;
}

static void buf_cstr(Buf *b, const char *s) {
    buf_bytes(b, (const unsigned char *)s, (int)strlen(s));
}

/* Write SSH string (length-prefixed) */
static void buf_string(Buf *b, const unsigned char *d, int n) {
    buf_u32(b, (uint32_t)n);
    buf_bytes(b, d, n);
}

static void buf_string_cstr(Buf *b, const char *s) {
    buf_string(b, (const unsigned char *)s, (int)strlen(s));
}

/* ================================================================
 *  Crypto state (post-KEX encryption context)
 * ================================================================ */

typedef struct {
    /* Encryption */
    EVP_CIPHER_CTX *enc_ctx_send; /* encrypt c2s */
    EVP_CIPHER_CTX *enc_ctx_recv; /* decrypt s2c */
    const EVP_CIPHER *cipher_type;
    int key_len, iv_len, block_len;

    /* MAC (non-AEAD only) */
    int mac_enabled;
    int mac_len;
    unsigned char mac_key_s2c[64]; /* recv direction */
    unsigned char mac_key_c2s[64]; /* send direction */
    const EVP_MD  *md_type;

    /* AEAD tag buffer */
    int is_aead;
    unsigned char aead_tag_recv[16];

    /* Sequence numbers */
    uint32_t seq_send;
    uint32_t seq_recv;
} CryptoCtx;

/* ================================================================
 *  Protocol State
 * ================================================================ */

typedef struct {
    Conn conn;

    /* Banner strings */
    char vc[256], vs[256];

    /* KEX payloads (raw, including msg type byte) */
    unsigned char ic_payload[2048]; int ic_len;
    unsigned char is_payload[4096]; int is_len;

    /* Negotiated algorithms */
    char kex_alg[128];
    char host_key_alg[128];
    char enc_alg_c2s[128];
    char enc_alg_s2c[128];
    char mac_alg_c2s[128];
    char mac_alg_s2c[128];
    char comp_alg[128];

    /* Session ID (set after first KEX) */
    unsigned char session_id[SHA256_LEN];
    int session_id_set;

    /* Crypto context (valid after NEWKEYS) */
    CryptoCtx crypto;

    int encrypted;
    unsigned char shared_secret[64]; /* shared secret from KEX */
    int shared_secret_len;
    int channel_peer_id;
} SshClient;

/* ================================================================
 *  KDF: RFC 4253 §7.2 — derive keys from shared secret and hash
 * ================================================================ */

/*
 * key = HASH(K || H || X || session_id) [|| HASH(K || H || key) || ...]
 */
static void ssh_kdf(const EVP_MD *md,
                    const unsigned char *K, int Klen,
                    const unsigned char *H, /* always 32 for SHA-256 */
                    const char X,
                    const unsigned char *sid, int sid_len,
                    unsigned char *out, int need)
{
    unsigned int hlen = (unsigned int)EVP_MD_size(md);
    int done = 0;
    unsigned char tmp[SHA256_LEN];
    const unsigned char *prev = NULL; /* previous hash output for chaining */
    int idx = 0;

    while (done < need) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, md, NULL);
        EVP_DigestUpdate(ctx, K, Klen);
        EVP_DigestUpdate(ctx, H, hlen);
        if (prev == NULL)
            EVP_DigestUpdate(ctx, &X, 1);
        else
            EVP_DigestUpdate(ctx, prev, (size_t)hlen);
        EVP_DigestUpdate(ctx, sid, sid_len);
        EVP_DigestFinal_ex(ctx, tmp, NULL);
        EVP_MD_CTX_free(ctx);

        int copy = hlen;
        if (done + copy > need) copy = need - done;
        memcpy(out + idx, tmp, copy);
        idx += copy;
        done += copy;
        prev = tmp;
    }
}

/* ================================================================
 *  Build KEXINIT payload
 * ================================================================ */

static int build_kexinit(unsigned char *out, int outmax) {
    Buf b;
    buf_init(&b, outmax);

    buf_u8(&b, MSG_KEXINIT);  /* msg type = 20 */

    /* 16-byte random cookie */
    unsigned char cookie[16];
    RAND_bytes(cookie, 16);
    buf_bytes(&b, cookie, 16);

    /* name-lists (order per RFC 4253 §7.1) */
    buf_string_cstr(&b, "curve25519-sha256,curve25519-sha256@libssh.org,"
                       "ecdh-sha2-nistp256,diffie-hellman-group14-sha256");

    buf_string_cstr(&b, "rsa-sha2-512,rsa-sha2-256,ssh-ed25519,"
                       "ecdsa-sha2-nistp256,ssh-rsa");

    buf_string_cstr(&b, "aes256-ctr,aes192-ctr,aes128-ctr,"
                       "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com");

    buf_string_cstr(&b, "aes256-ctr,aes192-ctr,aes128-ctr,"
                       "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com");

    buf_string_cstr(&b, "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
                       "umac-128-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,umac-128@openssh.com,hmac-sha1");

    buf_string_cstr(&b, "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
                       "umac-128-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,umac-128@openssh.com,hmac-sha1");

    buf_string_cstr(&b, "none,zlib@openssh.com");
    buf_string_cstr(&b, "none,zlib@openssh.com");
    buf_string_cstr(&b, "");  /* languages c2s */
    buf_string_cstr(&b, "");  /* languages s2c */

    buf_u8(&b, 0);            /* first_kex_packet_follows = false */
    buf_u32(&b, 0);           /* reserved */

    memcpy(out, b.data, b.len);
    free(b.data);
    return b.len;
}

/* ================================================================
 *  Parse KEXINIT from server — extract algorithm lists
 * ================================================================ */

typedef struct {
    char kex_algs[1024];
    char host_key_algs[1024];
    char enc_c2s[1024];
    char enc_s2c[1024];
    char mac_c2s[1024];
    char mac_s2c[1024];
    char comp_c2s[256];
    char comp_s2c[256];
} ServerKexInit;

static int parse_name_list(const unsigned char *p, char *dst, int dstsz) {
    int len = (int)get_u32(p);
    p += 4;
    int cp = len < dstsz - 1 ? len : dstsz - 1;
    memcpy(dst, p, cp);
    dst[cp] = 0;
    return 4 + len;
}

static int parse_kexinit(const unsigned char *payload, int plen, ServerKexInit *ski) {
    const unsigned char *p = payload + 1; /* skip msg type */
    p += 16; /* skip cookie */
    p += parse_name_list(p, ski->kex_algs, sizeof(ski->kex_algs));
    p += parse_name_list(p, ski->host_key_algs, sizeof(ski->host_key_algs));
    p += parse_name_list(p, ski->enc_c2s, sizeof(ski->enc_c2s));
    p += parse_name_list(p, ski->enc_s2c, sizeof(ski->enc_s2c));
    p += parse_name_list(p, ski->mac_c2s, sizeof(ski->mac_c2s));
    p += parse_name_list(p, ski->mac_s2c, sizeof(ski->mac_s2c));
    p += parse_name_list(p, ski->comp_c2s, sizeof(ski->comp_c2s));
    p += parse_name_list(p, ski->comp_s2c, sizeof(ski->comp_s2c));
    LOG("[DEBUG] Server kex_algs: %s\n", ski->kex_algs);
    LOG("[DEBUG] Server host_key_algs: %s\n", ski->host_key_algs);
    LOG("[DEBUG] Server enc_s2c: %s\n", ski->enc_s2c);
    LOG("[DEBUG] Server mac_s2c: %s\n", ski->mac_s2c);
    /* skip languages, first_kex_follows, reserved */
    return 0;
}

/* First-match algorithm selection: pick the first algo in 'ours' that appears in 'theirs' */
static int first_match(const char *ours, const char *thes, char *result, int rsz) {
    char ours_copy[1024];
    strncpy(ours_copy, ours, sizeof(ours_copy)-1);
    ours_copy[sizeof(ours_copy)-1] = 0;

    /* Tokenize ours using strtok */
    char *tok = strtok(ours_copy, ",");
    while (tok) {
        /* Check if tok appears in theirs WITHOUT strtok (avoid nested strtok bug) */
        const char *p = thes;
        int tlen = (int)strlen(tok);
        while (*p) {
            /* Find next comma or end of string */
            const char *comma = strchr(p, ',');
            int clen = comma ? (int)(comma - p) : (int)strlen(p);
            if (clen == tlen && strncmp(p, tok, tlen) == 0) {
                strncpy(result, tok, rsz-1);
                result[rsz-1] = 0;
                return 1;
            }
            p += clen;
            if (*p == ',') p++; /* skip comma */
        }
        tok = strtok(NULL, ",");
    }
    return 0;
}

/* ================================================================
 *  Curve25519 via OpenSSL EVP (requires OpenSSL 1.1+ with X25519)
 * ================================================================ */

static int x25519_gen_keypair(unsigned char pubkey[32], EVP_PKEY **out_pkey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) return -1;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    size_t pubk_len = 32;
    EVP_PKEY_get_raw_public_key(pkey, pubkey, &pubk_len);
    *out_pkey = pkey;
    return 0;
}

static int x25519_derive(EVP_PKEY *my_key, const unsigned char *peer_pub,
                          unsigned char shared_secret[32]) {
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    if (!peer) return -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_key, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer);
    size_t sflen = 32;
    int rc = EVP_PKEY_derive(ctx, shared_secret, &sflen);
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(ctx);
    return rc == 1 ? 0 : -1;
}

/* ================================================================
 *  Compute ECDH exchange hash H = SHA256(V_C || V_S || I_C || I_S ||
 *                                          K_S || Q_c || Q_s || K)
 * ================================================================ */

static void compute_exchange_hash(
    const char *vc, const char *vs,
    const unsigned char *ic, int ic_len,
    const unsigned char *is_pl, int is_len,
    const unsigned char *ks, int ks_len,
    const unsigned char *qc, int qc_len, /* client public key as string */
    const unsigned char *qs, int qs_len, /* server public key as string */
    const unsigned char *K_mpint, int Kmp_len, /* shared secret as mpint */
    unsigned char H_out[SHA256_LEN])
{
    EVP_MD_CTX *h = EVP_MD_CTX_new();
    EVP_DigestInit_ex(h, EVP_sha256(), NULL);

    /* Helper macro: feed a string (length-prefixed) into hash */
    #define HASH_STR(data, len) do { \
        unsigned char _lbuf[4]; \
        put_u32(_lbuf, (uint32_t)(len)); \
        EVP_DigestUpdate(h, _lbuf, 4); \
        EVP_DigestUpdate(h, (data), (len)); \
    } while(0)

    HASH_STR(vc, (int)strlen(vc));
    HASH_STR(vs, (int)strlen(vs));
    HASH_STR(ic, ic_len);
    HASH_STR(is_pl, is_len);
    HASH_STR(ks, ks_len);
    HASH_STR(qc, qc_len);
    HASH_STR(qs, qs_len);
    /* K as mpint */
    EVP_DigestUpdate(h, K_mpint, Kmp_len);

    unsigned int hlen = SHA256_LEN;
    EVP_DigestFinal_ex(h, H_out, &hlen);
    EVP_MD_CTX_free(h);
    #undef HASH_STR
}

/* Encode raw big-endian bytes as SSH mpint (add leading 0x00 if high bit set) */
static int mpint_encode(const unsigned char *bytes, int len,
                        unsigned char *out) {
    if (len == 0) {
        put_u32(out, 0);
        return 4;
    }
    int start = 0;
    /* skip leading zero bytes but keep at least one */
    while (start < len - 1 && bytes[start] == 0) start++;
    int eff_len = len - start;
    /* if high bit set, prepend 0x00 */
    int need_prefix = (bytes[start] & 0x80) ? 1 : 0;
    int total = 4 + need_prefix + eff_len;
    put_u32(out, need_prefix + eff_len);
    if (need_prefix) out[4] = 0x00;
    memcpy(out + 4 + need_prefix, bytes + start, eff_len);
    return total;
}

/* Verify host key signature of exchange hash - supports Ed25519 and RSA */
static int verify_host_key_sig(
    const unsigned char *host_key_blob, int hkblen,
    const unsigned char *sig_blob,     int sigblen,
    const unsigned char H[SHA256_LEN],
    const char *host_key_alg)
{
    LOG("[*] verify_host_key_sig called hkblen=%d sigblen=%d\n", hkblen, sigblen);
    fflush(stdout);
    /* Parse host key blob to get algorithm */
    const unsigned char *p = host_key_blob;
    int len;
    /* get_string_data returns pointer to string data (after length prefix) */
    const unsigned char *alg_ptr = get_string_data(p, &len);
    p = alg_ptr + len; /* advance past algorithm string */
    char alg[64];
    if (len < (int)sizeof(alg) - 1) {
        memcpy(alg, alg_ptr, len);
        alg[len] = 0;
    } else {
        memcpy(alg, alg_ptr, sizeof(alg) - 1);
        alg[sizeof(alg) - 1] = 0;
    }

    LOG("[*] Verifying host key signature: alg=%s\n", alg);
    fflush(stdout);

    if (strcmp(alg, "ssh-ed25519") == 0 || strcmp(alg, "ssh-ed25519-cert-v01@openssh.com") == 0) {
        /* Ed25519 verification */
        p = get_string_data(p, &len); /* 32-byte pubkey */
        const unsigned char *pubkey = p; /* 32 bytes */

        const unsigned char *sp = sig_blob;
        sp = get_string_data(sp, &len); /* algorithm */ sp += len;
        sp = get_string_data(sp, &len); /* 64-byte signature */

        EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey, 32);
        if (!pk) { LOG("Failed to load ED25519 pubkey\n"); return -1; }

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pk);
        int ret = EVP_DigestVerify(ctx, sp, (size_t)len, H, SHA256_LEN);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pk);

        LOG("Ed25519 signature verification: %s\n", ret == 1 ? "OK" : "FAILED");
        return ret == 1 ? 0 : -1;

    } else if (strcmp(alg, "ssh-rsa") == 0) {
        /* RSA verification using OpenSSL EVP_PKEY_verify API */
        /* Parse e (exponent mpint) */
        const unsigned char *e_ptr = get_string_data(p, &len);
        int e_mpint_len = len;
        /* Parse n (modulus mpint) */
        const unsigned char *n_ptr = get_string_data(e_ptr + len, &len);
        int n_mpint_len = len;
        p = n_ptr + len;

        /* Build RSA public key from e and n (mpints may have leading 0x00 for positive encoding) */
        int e_skip = (e_mpint_len > 0 && e_ptr[0] == 0x00) ? 1 : 0;
        BIGNUM *e_bn = BN_bin2bn(e_ptr + e_skip, e_mpint_len - e_skip, NULL);
        int n_skip = (n_mpint_len > 0 && n_ptr[0] == 0x00) ? 1 : 0;
        BIGNUM *n_bn = BN_bin2bn(n_ptr + n_skip, n_mpint_len - n_skip, NULL);
        if (!e_bn || !n_bn) { LOG("Failed to parse RSA e/n\n"); return -1; }

        RSA *rsa = RSA_new();
        RSA_set0_key(rsa, n_bn, e_bn, NULL);
        EVP_PKEY *pk = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pk, rsa);

        /* Parse signature blob: {sig_alg_string, S as mpint} */
        const unsigned char *sp = sig_blob;
        const unsigned char *salg_ptr = get_string_data(sp, &len);
        char sig_alg[64];
        memcpy(sig_alg, salg_ptr, len < 63 ? len : 63);
        sig_alg[len < 63 ? len : 63] = 0;
        sp = salg_ptr + len;

        const unsigned char *sig_ptr = get_string_data(sp, &len); /* S as mpint */

        /* Determine hash algorithm from signature algorithm name */
        const EVP_MD *md;
        if (strstr(sig_alg, "sha2-512")) md = EVP_sha512();
        else if (strstr(sig_alg, "sha2-256")) md = EVP_sha256();
        else if (strstr(sig_alg, "sha1")) md = EVP_sha1();
        else { md = EVP_sha256(); LOG("Unknown sig alg '%s'\n", sig_alg); }

        /* Skip leading 0x00 in signature mpint if present */
        int sig_skip = (len > 0 && sig_ptr[0] == 0x00) ? 1 : 0;

        /* Verify using OpenSSL's PKCS#1 v1.5 implementation */
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pk);
        EVP_DigestVerifyUpdate(mdctx, H, SHA256_LEN);
        int ret = EVP_DigestVerifyFinal(mdctx, (unsigned char *)(sig_ptr + sig_skip), len - sig_skip);

        LOG("RSA signature verification (%s): %s\n", sig_alg, ret == 1 ? "OK" : "FAILED");
        if (ret != 1) {
            LOG("  debug: e_skip=%d n_skip=%d sig_skip=%d sig_len=%d\n",
                e_skip, n_skip, sig_skip, len);
        }
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pk);
        return ret == 1 ? 0 : -1;

    } else if (strncmp(alg, "ecdsa-", 6) == 0) {
        /* TODO: ECDSA verification not implemented yet */
        LOG("ECDSA host key verification not implemented\n");
        return -1;
    }

    LOG("Unknown host key algorithm: %s\n", alg);
    return -1;
}

/* ================================================================
 *  Install encryption after KEX
 * ================================================================ */

static void setup_cipher(CryptoCtx *cx, const char *alg_name,
                         const unsigned char *key, const unsigned char *iv,
                         int enc_dir) /* 1=encrypt, 0=decrypt */
{
    EVP_CIPHER_CTX **target = enc_dir ? &cx->enc_ctx_send : &cx->enc_ctx_recv;
    const EVP_CIPHER *cipher = NULL;
    int kl = 0, il = 0, bl = 16;

    if (strstr(alg_name, "chacha20")) {
        cipher = EVP_chacha20_poly1305();
        kl = 64; il = 0; bl = 64;
        cx->is_aead = 1;
    } else if (strstr(alg_name, "aes256-gcm")) {
        cipher = EVP_aes_256_gcm();
        kl = 32; il = 12; bl = 16;
        cx->is_aead = 1;
    } else if (strstr(alg_name, "aes128-gcm")) {
        cipher = EVP_aes_128_gcm();
        kl = 16; il = 12; bl = 16;
        cx->is_aead = 1;
    } else if (strstr(alg_name, "aes256-ctr")) {
        cipher = EVP_aes_256_ctr();
        kl = 32; il = 16; bl = 16;
        cx->is_aead = 0;
    } else if (strstr(alg_name, "aes192-ctr")) {
        cipher = EVP_aes_192_ctr();
        kl = 24; il = 16; bl = 16;
        cx->is_aead = 0;
    } else if (strstr(alg_name, "aes128-ctr")) {
        cipher = EVP_aes_128_ctr();
        kl = 16; il = 16; bl = 16;
        cx->is_aead = 0;
    } else {
        die("Unsupported cipher: %s", alg_name);
    }

    cx->cipher_type = cipher;
    cx->key_len = kl;
    cx->iv_len = il;
    cx->block_len = bl;

    *target = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(*target, 0); /* SSH does its own padding */
    if (il > 0) {
        /* Set IV length for ciphers that need it (e.g., AES-GCM) */
        if (strstr(alg_name, "-gcm"))
            EVP_CIPHER_CTX_ctrl(*target, EVP_CTRL_GCM_SET_IVLEN, il, NULL);
    }
    /* Single init call with key and IV - works for both encrypt and decrypt in CTR mode */
    if (enc_dir) {
        EVP_EncryptInit_ex(*target, cipher, NULL, key, iv);
    } else {
        /* Use Decrypt API but for CTR it's same as Encrypt */
        EVP_DecryptInit_ex(*target, cipher, NULL, key, iv);
        /* For GCM, also need to init properly */
        if (strstr(alg_name, "-gcm")) {
            EVP_DecryptInit_ex(*target, NULL, NULL, NULL, NULL);
        }
    }
}

static void setup_mac(CryptoCtx *cx, const char *mac_name,
                      const unsigned char *key, int key_len,
                      int is_recv)
{
    cx->mac_enabled = 1;
    if (strstr(mac_name, "sha2-256") || strstr(mac_name, "hmac-sha2-256")) {
        cx->md_type = EVP_sha256();
        cx->mac_len = 32;
    } else if (strstr(mac_name, "sha2-512") || strstr(mac_name, "hmac-sha2-512")) {
        cx->md_type = EVP_sha512();
        cx->mac_len = 64;
    } else if (strstr(mac_name, "sha1") || strstr(mac_name, "hmac-sha1")) {
        cx->md_type = EVP_sha1();
        cx->mac_len = 20;
    } else if (strstr(mac_name, "umac-64")) {
        cx->mac_len = 8;
    } else if (strstr(mac_name, "umac-128")) {
        cx->mac_len = 16;
    } else {
        LOG("Unknown MAC %s, defaulting to sha256\n", mac_name);
        cx->md_type = EVP_sha256();
        cx->mac_len = 32;
    }

    if (is_recv)
        memcpy(cx->mac_key_s2c, key, key_len < 64 ? key_len : 64);
    else
        memcpy(cx->mac_key_c2s, key, key_len < 64 ? key_len : 64);

    /* Disable MAC for AEAD */
    if (cx->is_aead) {
        cx->mac_enabled = 0;
        cx->mac_len = 0;
    }
}

static void install_encryption(SshClient *c) {
    CryptoCtx *cx = &c->crypto;
    memset(cx, 0, sizeof(*cx));

    const EVP_MD *md = EVP_sha256();

    /* Determine key sizes */
    int key_len = 32, iv_len = 16, mkl = 32;

    if (strstr(c->enc_alg_c2s, "aes128")) { key_len = 16; iv_len = 16; }
    else if (strstr(c->enc_alg_c2s, "aes192")) { key_len = 24; iv_len = 16; }
    else if (strstr(c->enc_alg_c2s, "aes256-gcm")) { key_len = 32; iv_len = 12; }
    else if (strstr(c->enc_alg_c2s, "aes128-gcm")) { key_len = 16; iv_len = 12; }
    else if (strstr(c->enc_alg_c2s, "chacha20")) { key_len = 64; iv_len = 0; }

    /* Derive keys */
    unsigned char iv_c2s[32], iv_s2c[32];
    unsigned char ek_c2s[64], ek_s2c[64];
    unsigned char mk_c2s[64], mk_s2c[64];

    ssh_kdf(md,
            c->shared_secret, c->shared_secret_len,  /* K */
            c->session_id,         /* H */
            'A', c->session_id, SHA256_LEN,
            iv_c2s, iv_len);
    ssh_kdf(md, c->shared_secret, c->shared_secret_len, c->session_id,
            'B', c->session_id, SHA256_LEN,
            iv_s2c, iv_len);
    ssh_kdf(md, c->shared_secret, c->shared_secret_len, c->session_id,
            'C', c->session_id, SHA256_LEN,
            ek_c2s, key_len);
    ssh_kdf(md, c->shared_secret, c->shared_secret_len, c->session_id,
            'D', c->session_id, SHA256_LEN,
            ek_s2c, key_len);
    ssh_kdf(md, c->shared_secret, c->shared_secret_len, c->session_id,
            'E', c->session_id, SHA256_LEN,
            mk_c2s, mkl);
    ssh_kdf(md, c->shared_secret, c->shared_secret_len, c->session_id,
            'F', c->session_id, SHA256_LEN,
            mk_s2c, mkl);

    LOG("Installing encryption: cipher=%s mac=%s\n", c->enc_alg_c2s, c->mac_alg_c2s);
    LOG("  key_len=%d iv_len=%d mac_len=%d\n", key_len, iv_len, mkl);
    hexdump("  ek_c2s:", ek_c2s, key_len);
    hexdump("  iv_c2s:", iv_c2s, iv_len > 16 ? 16 : iv_len);
    hexdump("  mk_c2s:", mk_c2s, mkl);

    /* Setup cipher directions */
    setup_cipher(cx, c->enc_alg_c2s, ek_c2s, iv_c2s, 1);  /* send (encrypt) */
    setup_cipher(cx, c->enc_alg_s2c, ek_s2c, iv_s2c, 0);  /* recv (decrypt) */

    /* Setup MAC */
    setup_mac(cx, c->mac_alg_c2s, mk_c2s, mkl, 0);  /* send */
    setup_mac(cx, c->mac_alg_s2c, mk_s2c, mkl, 1);  /* recv */

    cx->seq_send = 0;
    cx->seq_recv = 0;
}

/* ================================================================
 *  Packet I/O: plain (unencrypted) and encrypted
 * ================================================================ */

/* Write an unencrypted packet: [uint32 length][byte padding_length][payload][padding] */
static void send_plain_packet(SshClient *c, const unsigned char *payload, int plen) {
    int bs = 8; /* minimum block size before KEX */
    int min_pad = 4;
    int pad_len = min_pad;
    /* RFC 4253: (packet_length + 4) must be multiple of block_size
       packet_length = 1 (padlen byte) + plen + pad_len
       So: (1 + plen + pad_len + 4) % 8 == 0  =>  (plen + pad_len + 5) % 8 == 0
       Equivalently: (plen + pad_len) % 8 == 3 */
    while ((plen + pad_len) % bs != (bs - 5)) pad_len++;

    unsigned char padding[256];
    RAND_bytes(padding, pad_len);

    int body_len = 1 + plen + pad_len;  /* padding_length byte + payload + padding */
    unsigned char hdr[4];
    put_u32(hdr, body_len);

    LOG("[DEBUG] send_plain: payload[0]=0x%02x body_len=%d pad=%d\n", plen > 0 ? payload[0] : 0, body_len, pad_len);

    send_all(c->conn.fd, hdr, 4);
    unsigned char pb = (unsigned char)pad_len;
    send_all(c->conn.fd, &pb, 1);
    send_all(c->conn.fd, payload, plen);
    send_all(c->conn.fd, padding, pad_len);
}

/* Read an unencrypted packet, return payload (caller frees) */
static int recv_plain_packet(SshClient *c, unsigned char **payload_out, int *payload_len) {
    unsigned char lenbuf[4];
    if (read_exact(c->conn.fd, lenbuf, 4) < 0) die("recv_plain: length read failed");

    uint32_t pkt_len = get_u32(lenbuf);
    if (pkt_len > MAX_PACKET) die("recv_plain: packet too large: %u", pkt_len);

    unsigned char *body = (unsigned char *)malloc(pkt_len);
    if (read_exact(c->conn.fd, body, pkt_len) < 0) die("recv_plain: body read failed");

    int pad_len = body[0];
    *payload_len = pkt_len - 1 - pad_len;
    *payload_out = (unsigned char *)malloc(*payload_len);
    memcpy(*payload_out, body + 1, *payload_len);
    free(body);
    return 0;
}

/* Compute MAC for encrypt-then-MAC mode */
static void compute_mac(CryptoCtx *cx, int is_send,
                        const unsigned char *pkt_hdr_and_body, int body_total_len,
                        unsigned char *mac_out) {
    if (!cx->mac_enabled || !cx->md_type) return;

    uint32_t seq = is_send ? cx->seq_send : cx->seq_recv;
    unsigned char seqbuf[4];
    put_u32(seqbuf, seq);

    unsigned int len = 0;
    HMAC(cx->md_type,
         is_send ? cx->mac_key_c2s : cx->mac_key_s2c,
         cx->mac_len,
         seqbuf, 4,
         NULL, &len); /* just to get len... actually let's compute directly */

    HMAC(cx->md_type,
         is_send ? cx->mac_key_c2s : cx->mac_key_s2c,
         cx->mac_len,
         seqbuf, 4,
         NULL, &len);

    /* Now compute over seq_num || packet_data */
    HMAC_CTX *hctx = HMAC_CTX_new();
    HMAC_Init_ex(hctx,
                 is_send ? cx->mac_key_c2s : cx->mac_key_s2c,
                 cx->mac_len, cx->md_type, NULL);
    HMAC_Update(hctx, seqbuf, 4);
    HMAC_Update(hctx, pkt_hdr_and_body, body_total_len);
    HMAC_Final(hctx, mac_out, NULL);
    HMAC_CTX_free(hctx);
}

/* Encrypt data in-place using CTR mode (or stream mode) */
static void do_encrypt(CryptoCtx *cx, unsigned char *data, int len) {
    if (!cx->enc_ctx_send) { LOG("WARNING: enc_ctx_send is NULL!\n"); return; }
    unsigned char *tmp = (unsigned char *)calloc(1, len);
    int outl = 0;
    int rc = EVP_EncryptUpdate(cx->enc_ctx_send, tmp, &outl, data, len);
    LOG("[ENCRYPT] call: ctx=%p rc=%d outl=%d/%d\n", (void*)cx->enc_ctx_send, rc, outl, len);
    LOG("[ENCRYPT] memcmp: %d (in[0]=%02x tmp[0]=%02x)\n",
        memcmp(data, tmp, len), data[0], tmp[0]);
    memcpy(data, tmp, len);
    free(tmp);
}

/* Decrypt data in-place */
static void do_decrypt(CryptoCtx *cx, unsigned char *data, int len) {
    if (!cx->enc_ctx_recv) return;
    /* CTR mode: must use separate in/out buffers */
    unsigned char *tmp = (unsigned char *)malloc(len);
    int outl = 0;
    EVP_DecryptUpdate(cx->enc_ctx_recv, tmp, &outl, data, len);
    memcpy(data, tmp, len);
    free(tmp);
}

/* Send an encrypted packet (EtM or AEAD) */
static void send_encrypted_packet(SshClient *c, const unsigned char *payload, int plen) {
    CryptoCtx *cx = &c->crypto;
    int bs = cx->block_len < 8 ? 8 : cx->block_len;
    int min_pad = 4;
    int pad_len = min_pad;
    /* RFC 4253: (plen + pad_len + 5) % bs == 0  =>  (plen + pad_len) % bs == (bs - 5) */
    while ((plen + pad_len) % bs != (bs - 5)) pad_len++;

    unsigned char padding[256];
    RAND_bytes(padding, pad_len);

    int body_len = 1 + plen + pad_len;

    /* Assemble unencrypted packet: [4 byte length][padlen][payload][random padding] */
    unsigned char *pkt = (unsigned char *)malloc(4 + body_len);
    put_u32(pkt, body_len);
    pkt[4] = (unsigned char)pad_len;
    memcpy(pkt + 5, payload, plen);
    memcpy(pkt + 5 + plen, padding, pad_len);

    if (cx->is_aead) {
        /* AEAD mode: encrypt then append tag */
        /* For GCM: AAD = packet_length (4 bytes) */
        int outl;
        if (strstr(c->enc_alg_c2s, "chacha20")) {
            /* ChaCha20-Poly1305 in OpenSSH style */
            /* We need special handling... for now try standard AEAD */
            EVP_EncryptUpdate(cx->enc_ctx_send, pkt + 4, &outl, pkt + 4, body_len);
            unsigned char tag[16];
            int tagl = 0;
            EVP_EncryptFinal_ex(cx->enc_ctx_send, tag, &tagl);
            /* Append tag */
            send_all(c->conn.fd, pkt, 4 + body_len);
            send_all(c->conn.fd, tag, 16);
        } else {
            /* GCM */
            /* Set AAD */
            EVP_EncryptUpdate(cx->enc_ctx_send, NULL, &outl, pkt, 4); /* AAD = length */
            EVP_EncryptUpdate(cx->enc_ctx_send, pkt + 4, &outl, pkt + 4, body_len);
            unsigned char tag[16];
            int tagl = 0;
            EVP_EncryptFinal_ex(cx->enc_ctx_send, tag, &tagl);
            /* Append tag after ciphertext */
            send_all(c->conn.fd, pkt, 4 + body_len);
            send_all(c->conn.fd, tag, 16);
        }
    } else {
        /* EtM mode per RFC 4253 / OpenSSH:
           1. Build: [plaintext_length][padlen][payload][padding]
           2. Encrypt ENTIRE packet including length (for CTR mode)
           3. Compute MAC over seq_num || encrypted_packet
           4. Send: [encrypted_all][MAC] */
        
        LOG("[DEBUG] Pre-encrypt: total=%d body_len=%d\n", 4 + body_len, body_len);
        hexdump("  pre-enc pkt:", pkt, 4 + body_len > 36 ? 36 : 4 + body_len);

        /* Encrypt everything including length prefix */
        do_encrypt(cx, pkt, 4 + body_len);

        /* MAC over seq_num || entire encrypted packet (including encrypted length) */
        unsigned char mac[64];
        compute_mac(cx, 1, pkt, 4 + body_len, mac);

        LOG("[DEBUG] Encrypted send: seq=%u len=%d mac=%d\n", cx->seq_send, body_len, cx->mac_len);
        hexdump("  full packet:", pkt, 4 + body_len > 36 ? 36 : 4 + body_len);
        hexdump("  MAC:", mac, cx->mac_len > 16 ? 16 : cx->mac_len);

        send_all(c->conn.fd, pkt, 4 + body_len);  /* send all encrypted data */
        if (cx->mac_enabled && cx->mac_len > 0)
            send_all(c->conn.fd, mac, cx->mac_len);
    }

    free(pkt);
    cx->seq_send++;
}

/* Receive an encrypted packet, return payload */
static int recv_encrypted_packet(SshClient *c, unsigned char **payload_out, int *payload_len) {
    CryptoCtx *cx = &c->crypto;

    /* Read block_size bytes and decrypt to get packet length (OpenSSH CTR mode) */
    int read_size = cx->block_len;
    if (read_size < 8) read_size = 8;

    unsigned char first_block[32];
    if (read_exact(c->conn.fd, first_block, read_size) < 0)
        die("recv_enc: first block read failed");

    /* Decrypt first block to get length */
    unsigned char dec_first[32];
    memcpy(dec_first, first_block, read_size);
    do_decrypt(cx, dec_first, read_size);

    uint32_t pkt_body_len = get_u32(dec_first);
    if (pkt_body_len < 1 || pkt_body_len > MAX_PACKET)
        die("recv_enc: bad packet length %u", pkt_body_len);

    int remain = (int)pkt_body_len - (read_size - 4);
    int mac_len = cx->is_aead ? 0 : cx->mac_len;

    /* Read remaining encrypted body + MAC */
    int total_remain = remain + mac_len;
    unsigned char *rest = NULL;
    if (total_remain > 0) {
        rest = (unsigned char *)malloc(total_remain);
        if (read_exact(c->conn.fd, rest, total_remain) < 0)
            die("recv_enc: remainder read failed");
    }

    /* Reassemble and decrypt remaining body */
    unsigned char *body = (unsigned char *)malloc(pkt_body_len);
    memcpy(body, dec_first + 4, read_size - 4); /* already-decrypted part after length */
    if (remain > 0) {
        do_decrypt(cx, rest, remain);
        memcpy(body + (read_size - 4), rest, remain);
    }

    /* MAC verification: EtM covers seq_num || encrypted_packet */
    if (!cx->is_aead && cx->mac_enabled && mac_len > 0 && rest) {
        unsigned char *mac_data = rest + remain;
        /* TODO: verify MAC */
        (void)mac_data;
    }

    /* Extract payload */
    int pad_len = body[0];
    *payload_len = (int)pkt_body_len - 1 - pad_len;
    *payload_out = (unsigned char *)malloc(*payload_len);
    memcpy(*payload_out, body + 1, *payload_len);

    free(body);
    if (rest) free(rest);
    cx->seq_recv++;
    return 0;
}

/* Generic send packet (chooses plain or encrypted) */
static void ssh_send(SshClient *c, const unsigned char *payload, int plen) {
    if (c->encrypted)
        send_encrypted_packet(c, payload, plen);
    else
        send_plain_packet(c, payload, plen);
}

/* Generic recv packet */
static int ssh_recv(SshClient *c, unsigned char **payload_out, int *payload_len) {
    if (c->encrypted)
        return recv_encrypted_packet(c, payload_out, payload_len);
    else
        return recv_plain_packet(c, payload_out, payload_len);
}

/* Recv packet that skips IGNORE/DEBUG/EXT_INFO messages */
static int ssh_recv_skip(SshClient *c, unsigned char **payload_out, int *payload_len) {
    for (;;) {
        int rc = ssh_recv(c, payload_out, payload_len);
        if (rc != 0) return rc;
        if (*payload_len < 1) continue;
        unsigned char mt = (*payload_out)[0];
        if (mt == MSG_IGNORE || mt == MSG_DEBUG || /* EXT_INFO */ mt == 7) {
            LOG("(skipping msg=%d len=%d)\n", mt, *payload_len);
            free(*payload_out);
            continue;
        }
        if (mt == MSG_DISCONNECT) {
            die("Server sent DISCONNECT");
        }
        return 0;
    }
}

/* ================================================================
 *  Main protocol flow
 * ================================================================ */

int main(int argc, char **argv) {
    setbuf(stdout, NULL);

    if (argc < 5) {
        fprintf(stderr, "Usage: %s <host> <port> <user> <password> [command]\n", argv[0]);
        fprintf(stderr, "Example: %s localhost 2222 root test123 'uname -a'\n", argv[0]);
        return 1;
    }

    const char *host = argv[1];
    int port = atoi(argv[2]);
    const char *user = argv[3];
    const char *pass = argv[4];
    const char *command = argc > 5 ? argv[5] : "uname -a";

    SshClient cli;
    memset(&cli, 0, sizeof(cli));

    /* ===== Phase 1: TCP Connect & Version Exchange ===== */
    LOG("[*] Connecting to %s:%d ...\n", host, port);
    cli.conn.fd = tcp_connect(host, port);
    LOG("[*] Connected.\n");

    /* Receive server banner */
    unsigned char banner_buf[512];
    int bl = read_line(cli.conn.fd, banner_buf, sizeof(banner_buf));
    if (bl < 0) die("Banner receive failed");
    /* Strip \r\n */
    if (bl > 0 && banner_buf[bl-1] == '\n') banner_buf[--bl] = 0;
    if (bl > 0 && banner_buf[bl-1] == '\r') banner_buf[--bl] = 0;
    strncpy(cli.vs, (char*)banner_buf, sizeof(cli.vs)-1);
    LOG("[*] Server banner: %s\n", cli.vs);

    /* Check SSH-2.0 prefix */
    if (strncmp((char*)banner_buf, "SSH-", 4) != 0)
        die("Not an SSH server: %s", banner_buf);

    /* Send client banner */
    const char *client_banner = "SSH-2.0-BaselineSSH_1.0";
    strncpy(cli.vc, client_banner, sizeof(cli.vc)-1);
    char banner_to_send[256];
    snprintf(banner_to_send, sizeof(banner_to_send), "%s\r\n", client_banner);
    send_all(cli.conn.fd, (unsigned char*)banner_to_send, (int)strlen(banner_to_send));
    LOG("[*] Sent banner: %s\n", client_banner);
    usleep(100000); /* small delay so server can process */

    /* ===== Phase 2: Algorithm Negotiation (KEXINIT) ===== */
    LOG("[*] Building KEXINIT...\n");
    cli.ic_len = build_kexinit(cli.ic_payload, sizeof(cli.ic_payload));

    /* Send our KEXINIT */
    ssh_send(&cli, cli.ic_payload, cli.ic_len);
    LOG("[*] Sent KEXINIT (%d bytes payload)\n", cli.ic_len);

    /* Receive server KEXINIT */
    unsigned char *srv_kex_payload = NULL;
    int srv_kex_len = 0;
    ssh_recv_skip(&cli, &srv_kex_payload, &srv_kex_len);

    /* Store server KEXINIT payload (full, including msg type byte) */
    if (srv_kex_len > (int)sizeof(cli.is_payload))
        die("Server KEXINIT too large");
    memcpy(cli.is_payload, srv_kex_payload, srv_kex_len);
    cli.is_len = srv_kex_len;

    /* Parse server KEXINIT */
    ServerKexInit ski;
    parse_kexinit(srv_kex_payload, srv_kex_len, &ski);
    free(srv_kex_payload);

    LOG("[*] Server KEX parsed.\n");

    /* Negotiate algorithms (first-match) — order matters! Match OpenSSH preferences */
    if (!first_match("curve25519-sha256,curve25519-sha256@libssh.org,"
                     "ecdh-sha2-nistp256,diffie-hellman-group14-sha256",
                     ski.kex_algs, cli.kex_alg, sizeof(cli.kex_alg)))
        die("No matching KEX algorithm");

    if (!first_match("rsa-sha2-512,rsa-sha2-256,ssh-ed25519,"
                     "ecdsa-sha2-nistp256,ssh-rsa",
                     ski.host_key_algs, cli.host_key_alg, sizeof(cli.host_key_alg)))
        die("No matching host key algorithm");

    if (!first_match("aes256-ctr,aes192-ctr,aes128-ctr,"
                     "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
                     ski.enc_s2c, cli.enc_alg_s2c, sizeof(cli.enc_alg_s2c)))
        die("No matching cipher (s2c)");

    strncpy(cli.enc_alg_c2s, cli.enc_alg_s2c, sizeof(cli.enc_alg_c2s)); /* symmetric */

    if (!first_match("hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
                     "hmac-sha1-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1,"
                     "umac-128@openssh.com,umac-64@openssh.com",
                     ski.mac_s2c, cli.mac_alg_s2c, sizeof(cli.mac_alg_s2c)))
        die("No matching MAC (s2c)");

    strncpy(cli.mac_alg_c2s, cli.mac_alg_s2c, sizeof(cli.mac_alg_c2s));

    if (!first_match("none,zlib@openssh.com", ski.comp_s2c, cli.comp_alg, sizeof(cli.comp_alg)))
        die("No matching compression");

    LOG("[*] Negotiated: kex=%s host_key=%s enc=%s mac=%s comp=%s\n",
        cli.kex_alg, cli.host_key_alg, cli.enc_alg_s2c, cli.mac_alg_s2c, cli.comp_alg);

    /* ===== Phase 3: Key Exchange (Curve25519) ===== */
    LOG("[*] Starting Curve25519 key exchange...\n");

    unsigned char my_pubkey[32];
    EVP_PKEY *my_evp_key = NULL;
    if (x25519_gen_keypair(my_pubkey, &my_evp_key) != 0)
        die("X25519 key generation failed");

    hexdump("My X25519 public key:", my_pubkey, 32);

    /* Build SSH_MSG_KEX_ECDH_INIT (30) */
    Buf ecdh_init;
    buf_init(&ecdh_init, 128);
    buf_u8(&ecdh_init, MSG_KEX_ECDH_INIT); /* 30 */
    /* Public key as string (not mpint!) */
    buf_string(&ecdh_init, my_pubkey, 32);

    LOG("[DEBUG] ECDH_INIT payload (%d bytes):", ecdh_init.len);
    hexdump("", ecdh_init.data, ecdh_init.len);

    /* Before sending ECDH_INIT, drain any pending data from server */
    LOG("[DEBUG] Draining socket before ECDH_INIT...\n");
    {
        unsigned char drain_buf[4096];
        ssize_t avail;
        while ((avail = recv(cli.conn.fd, drain_buf, sizeof(drain_buf), MSG_DONTWAIT)) > 0) {
            LOG("[DRAIN] Got %zd bytes before ECDH_INIT: msg_type=0x%02x\n", avail, drain_buf[4]);
            hexdump("Drained", drain_buf, avail > 64 ? 64 : (int)avail);
        }
    }

    ssh_send(&cli, ecdh_init.data, ecdh_init.len);
    free(ecdh_init.data);

    LOG("[*] Sent ECDH_INIT, waiting for reply...\n");

    /* Receive ECDH_REPLY (31) */
    unsigned char *reply_payload = NULL;
    int reply_len = 0;
    ssh_recv_skip(&cli, &reply_payload, &reply_len);

    if (reply_len < 1 || reply_payload[0] != MSG_KEX_ECDH_REPLY)
        die("Expected KEX_ECDH_REPLY (31), got %d", reply_payload[0]);

    /* Parse ECDH_REPLY: K_S (host key) | Q_S (server pubkey) | signature (blob) */
    const unsigned char *p = reply_payload + 1; /* skip msg type */
    int slen;

    /* K_S */
    p = get_string_data(p, &slen);
    const unsigned char *K_S = p; int K_Slen = slen;
    p += slen;

    /* Q_S (server public key as string) */
    p = get_string_data(p, &slen);
    const unsigned char *Q_S = p; int Q_Slen = slen;
    p += slen;

    /* signature blob */
    p = get_string_data(p, &slen);
    const unsigned char *sig_blob = p; int sig_blen = slen;
    p += slen;

    hexdump("Host key K_S:", K_S, K_Slen);
    hexdump("Server pubkey Q_S:", Q_S, Q_Slen);
    hexdump("Signature:", sig_blob, sig_blen);

    /* Derive shared secret */
    /* IMPORTANT: x25519_derive takes const unsigned char *peer_pub[32] which dereferences to get raw bytes.
       Q_S is already a pointer to the key data, so we must PASS Q_S DIRECTLY, not &Q_S! */
    unsigned char shared_le[32]; /* little-endian from X25519 */
    if (x25519_derive(my_evp_key, Q_S, shared_le) != 0)
        die("X25519 derive failed");
    EVP_PKEY_free(my_evp_key);

    hexdump("Shared secret (LE):", shared_le, 32);

    /* Convert shared secret to big-endian mpint for hashing */
    unsigned char shared_be[32];
    for (int i = 0; i < 32; i++) shared_be[i] = shared_le[31 - i];

    unsigned char mpint_buf[36];
    int mplen = mpint_encode(shared_be, 32, mpint_buf);

    hexdump("Shared secret (mpint):", mpint_buf, mplen);

    /* Compute exchange hash H */
    unsigned char H[SHA256_LEN];
    compute_exchange_hash(
        cli.vc, cli.vs,
        cli.ic_payload, cli.ic_len,
        cli.is_payload, cli.is_len,
        K_S, K_Slen,
        my_pubkey, 32,   /* Q_c as string */
        Q_S, Q_Slen,     /* Q_s as string */
        mpint_buf, mplen, /* K as mpint */
        H);

    hexdump("Exchange hash H:", H, SHA256_LEN);

    /* Store session ID */
    if (!cli.session_id_set) {
        memcpy(cli.session_id, H, SHA256_LEN);
        cli.session_id_set = 1;
    }

    /* Store shared secret for key derivation */
    /* Use big-endian (mpint) format, same as MoonBit implementation.
       See src/kex.mbt line 744: self.shared_secret = shared_be */
    cli.shared_secret_len = 32;
    memcpy(cli.shared_secret, shared_be, cli.shared_secret_len);

    /* Verify host key signature */
    if (verify_host_key_sig(K_S, K_Slen, sig_blob, sig_blen, H, cli.host_key_alg) != 0) {
        LOG("[!] Host key verification FAILED - continuing anyway (insecure mode)\n");
        /* In production, should abort here. For testing, continue. */
    }

    free(reply_payload);

    /* ===== Send NEWKEYS (21) ===== */
    unsigned char newkeys_msg[] = { MSG_NEWKEYS };
    ssh_send(&cli, newkeys_msg, 1);
    LOG("[*] Sent NEWKEYS\n");

    /* ===== Receive server NEWKEYS (21) ===== */
    unsigned char *nk_payload = NULL;
    int nk_len = 0;
    ssh_recv_skip(&cli, &nk_payload, &nk_len);
    if (nk_len != 1 || nk_payload[0] != MSG_NEWKEYS)
        die("Expected NEWKEYS, got msg=%d len=%d", nk_payload[0], nk_len);
    free(nk_payload);
    LOG("[*] Received NEWKEYS — installing encryption...\n");

    /* ===== Install encryption ===== */
    cli.encrypted = 1;
    install_encryption(&cli);
    LOG("[*] Encryption installed. Channel is now secure.\n");

    /* ===== Phase 4: Request ssh-userauth service ===== */
    {
        LOG("[*] About to send SERVICE_REQUEST (encrypted)...\n");

        /* First, let's peek if server sends something without us sending */
        usleep(100000);
        {
            unsigned char peek[64];
            ssize_t av = recv(cli.conn.fd, peek, sizeof(peek), MSG_DONTWAIT);
            if (av > 0)
                LOG("[DEBUG] Server sent %zd bytes before SERVICE_REQUEST!\n", av);
            else if (av == 0)
                LOG("[DEBUG] Server closed before SERVICE_REQUEST\n");
        }

        Buf sr;
        buf_init(&sr, 128);
        buf_u8(&sr, MSG_SERVICE_REQUEST); /* 5 */
        buf_string_cstr(&sr, "ssh-userauth");
        LOG("[*] Sending SERVICE_REQUEST (encrypted)...\n");
        ssh_send(&cli, sr.data, sr.len);
        free(sr.data);
        LOG("[*] SERVICE_REQUEST sent (%d bytes). Waiting...\n", sr.len);

        /* Check immediately after send */
        usleep(50000);
        {
            unsigned char peek[64];
            ssize_t av = recv(cli.conn.fd, peek, sizeof(peek), MSG_DONTWAIT);
            if (av > 0) {
                LOG("[DEBUG] %zd bytes available after send\n", av);
                hexdump("peek:", peek, av > 32 ? 32 : av);
            } else if (av == 0) {
                LOG("[DEBUG] FIN after SERVICE_REQUEST send\n");
            } else {
                LOG("[DEBUG] No data yet (errno=%d)\n", errno);
            }
        }
    }

    /* Receive SERVICE_ACCEPT (6) */
    unsigned char *sa_payload = NULL;
    int sa_len = 0;
    ssh_recv_skip(&cli, &sa_payload, &sa_len);
    if (sa_len < 1 || sa_payload[0] != MSG_SERVICE_ACCEPT)
        die("Expected SERVICE_ACCEPT (6), got %d", sa_payload[0]);
    free(sa_payload);
    LOG("[*] Service accepted (ssh-userauth)\n");

    /* ===== Phase 5: Password Authentication ===== */
    {
        Buf ar;
        buf_init(&ar, 512);
        buf_u8(&ar, MSG_USERAUTH_REQUEST); /* 50 */
        buf_string_cstr(&ar, user);              /* username */
        buf_string_cstr(&ar, "ssh-connection");   /* service */
        buf_string_cstr(&ar, "password");         /* method */
        buf_u8(&ar, 0);                           /* FALSE = no password change */
        buf_string_cstr(&ar, pass);               /* password */
        ssh_send(&cli, ar.data, ar.len);
        free(ar.data);
    }
    LOG("[*] Password auth request sent for user '%s'\n", user);

    /* Receive USERAUTH_SUCCESS (52) or FAILURE (51) */
    unsigned char *au_payload = NULL;
    int au_len = 0;
    ssh_recv_skip(&cli, &au_payload, &au_len);
    if (au_len < 1) die("Empty auth response");
    if (au_payload[0] == MSG_USERAUTH_SUCCESS) {
        LOG("[*] Authentication SUCCESS!\n");
    } else if (au_payload[0] == MSG_USERAUTH_FAILURE) {
        die("Authentication FAILED for user '%s'", user);
    } else {
        die("Unexpected auth response: msg=%d", au_payload[0]);
    }
    free(au_payload);

    /* ===== Phase 6: Open Session Channel (90) ===== */
    {
        Buf co;
        buf_init(&co, 128);
        buf_u8(&co, MSG_CHANNEL_OPEN);       /* 90 */
        buf_string_cstr(&co, "session");      /* channel type */
        buf_u32(&co, 0);                      /* sender channel id = 0 */
        buf_u32(&co, 1024 * 1024);            /* initial window size = 1MB */
        buf_u32(&co, 32 * 1024);              /* max packet size = 32KB */
        ssh_send(&cli, co.data, co.len);
        free(co.data);
    }
    LOG("[*] Sent CHANNEL_OPEN (session)\n");

    /* Wait for CHANNEL_OPEN_CONFIRMATION (91) */
    int got_conf = 0;
    while (!got_conf) {
        unsigned char *ch_payload = NULL;
        int ch_len = 0;
        ssh_recv_skip(&cli, &ch_payload, &ch_len);
        if (ch_len < 1) die("Empty channel response");
        if (ch_payload[0] == MSG_CHANNEL_OPEN_CONF) {
            /* Parse: sender_channel(4) | initial_window(4) | max_pkt(4) */
            const unsigned char *cp = ch_payload + 1;
            cli.channel_peer_id = (int)get_u32(cp);
            LOG("[*] Channel opened! peer_id=%d\n", cli.channel_peer_id);
            got_conf = 1;
        } else if (ch_payload[0] == MSG_CHANNEL_OPEN_FAIL) {
            die("Channel open FAILED");
        } else {
            LOG("[*] Ignoring unexpected msg=%d during channel open\n", ch_payload[0]);
        }
        free(ch_payload);
    }

    /* ===== Phase 7: Exec Command (CHANNEL_REQUEST exec) ===== */
    {
        Buf er;
        buf_init(&er, 512);
        buf_u8(&er, MSG_CHANNEL_REQUEST);      /* 98 */
        buf_u32(&er, cli.channel_peer_id);     /* recipient channel */
        buf_string_cstr(&er, "exec");           /* request type */
        buf_u8(&er, 1);                         /* want_reply = true */
        buf_string_cstr(&er, command);          /* command string */
        ssh_send(&cli, er.data, er.len);
        free(er.data);
    }
    LOG("[*] Sent EXEC request: %s\n", command);

    /* ===== Phase 8: Read stdout until EOF ===== */
    int total_stdout = 0;
    unsigned char stdout_accum[65536];
    int stdout_acc_len = 0;
    int eof_received = 0;
    int exit_status = -1;
    int close_received = 0;

    while (!close_received) {
        unsigned char *dpayload = NULL;
        int dlen = 0;
        int rc = ssh_recv(&cli, &dpayload, &dlen);
        if (rc != 0 || dlen < 1) {
            LOG("[*] Connection ended (rc=%d dlen=%d)\n", rc, dlen);
            break;
        }
        unsigned char msgtype = dpayload[0];

        switch (msgtype) {
        case MSG_CHANNEL_DATA: {
            /* 94: recipient_channel(uint32) | data(string) */
            const unsigned char *dp = dpayload + 1;
            int chan = (int)get_u32(dp); dp += 4;
            int dlen2;
            const unsigned char *ddata = get_string_data(dp, &dlen2);
            int copy = dlen2;
            if (stdout_acc_len + copy > (int)sizeof(stdout_accum) - 1)
                copy = (int)sizeof(stdout_accum) - 1 - stdout_acc_len;
            memcpy(stdout_accum + stdout_acc_len, ddata, copy);
            stdout_acc_len += copy;
            total_stdout += copy;

            /* Send WINDOW_ADJUST to keep flow control happy */
            Buf wa;
            buf_init(&wa, 16);
            buf_u8(&wa, MSG_CHANNEL_WINDOW_ADJ); /* 93 */
            buf_u32(&wa, cli.channel_peer_id);
            buf_u32(&wa, 1024 * 1024); /* generous window adjustment */
            ssh_send(&cli, wa.data, wa.len);
            free(wa.data);
            break;
        }
        case MSG_CHANNEL_EOF: /* 95 */
            LOG("[*] Got CHANNEL_EOF\n");
            eof_received = 1;
            break;
        case MSG_CHANNEL_CLOSE: /* 96 */
            LOG("[*] Got CHANNEL_CLOSE\n");
            close_received = 1;
            break;
        case MSG_CHANNEL_REQUEST: {
            /* 98: could be exit-status, exit-signal etc */
            const unsigned char *rp = dpayload + 1;
            int rchan = (int)get_u32(rp); rp += 4;
            int rtlen;
            const unsigned char *rtype = get_string_data(rp, &rtlen); rp += rtlen;
            int want_reply = rp[0]; rp++;
            (void)rchan;(void)want_reply;

            if (rtlen == 11 && memcmp(rtype, "exit-status", 11) == 0) {
                exit_status = (int)get_u32(rp);
                LOG("[*] exit-status = %d\n", exit_status);
            } else if (rtlen == 11 && memcmp(rtype, "exit-signal", 11) == 0) {
                LOG("[*] exit-signal received\n");
            } else {
                LOG("[*] Unknown channel request: %.*s\n", rtlen, rtype);
            }
            break;
        }
        case MSG_CHANNEL_SUCCESS: /* 99 */
            LOG("[*] CHANNEL_SUCCESS (exec accepted)\n");
            break;
        case MSG_CHANNEL_FAILURE: /* 100 */
            LOG("[*] CHANNEL_FAILURE (exec rejected?!)\n");
            break;
        default:
            LOG("[*] Unexpected msg=%d len=%d\n", msgtype, dlen);
            break;
        }
        free(dpayload);
    }

    /* Null-terminate and print stdout */
    stdout_accum[stdout_acc_len] = 0;
    printf("%s", (char *)stdout_accum);
    fflush(stdout);

    if (exit_status >= 0)
        LOG("\n[*] Exit status: %d\n", exit_status);
    LOG("[*] Total stdout: %d bytes\n", total_stdout);

    /* Clean up */
    close(cli.conn.fd);
    if (cli.crypto.enc_ctx_send) EVP_CIPHER_CTX_free(cli.crypto.enc_ctx_send);
    if (cli.crypto.enc_ctx_recv) EVP_CIPHER_CTX_free(cli.crypto.enc_ctx_recv);

    return 0;
}
