/*
 * OpenSSL FFI for MoonSSH SSH client.
 * Dynamically loads libcrypto and provides individual
 * SSH-primitive wrappers: AES-128-CTR, HMAC-SHA1/SHA256,
 * SHA1/SHA256, DH Group14, ECDH P-256, RSA sign/verify,
 * PEM key loading, BIGNUM utils, random bytes.
 */

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <moonbit.h>

/* Opaque forward declarations */
typedef struct evp_md_ctx_st  EVP_MD_CTX;
typedef struct evp_md_st      EVP_MD;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st  EVP_CIPHER;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct evp_pkey_st    EVP_PKEY;
typedef struct evp_mac_st     EVP_MAC;
typedef struct evp_mac_ctx_st EVP_MAC_CTX;
typedef struct bignum_st      BIGNUM;
typedef struct bn_ctx_st      BN_CTX;
typedef struct engine_st      ENGINE;
typedef struct ossl_param_st {
  const char *key;
  unsigned int data_type;
  void *data;
  size_t data_size;
  size_t return_size;
} OSSL_PARAM;
typedef struct bio_st BIO;
typedef struct rsa_st RSA;

/* ------------------------------------------------------------------ */
/* Symbol list                                                        */
/* ------------------------------------------------------------------ */
#define IMPORTED_OPEN_SSL_FUNCTIONS \
  /* version / errors / random */ \
  IMPORT_FUNC(unsigned long, OpenSSL_version_num, (void)) \
  IMPORT_FUNC(int, RAND_bytes, (unsigned char *buf, int num)) \
  IMPORT_FUNC(unsigned long, ERR_get_error, (void)) \
  IMPORT_FUNC(unsigned long, ERR_peek_error, (void)) \
  IMPORT_FUNC(char *, ERR_error_string, (unsigned long e, char *buf)) \
  IMPORT_FUNC(void, ERR_clear_error, (void)) \
  IMPORT_FUNC(int, OPENSSL_init_crypto, (uint64_t opts, const void *settings)) \
  /* digest */ \
  IMPORT_FUNC(const EVP_MD *, EVP_sha1, (void)) \
  IMPORT_FUNC(const EVP_MD *, EVP_sha256, (void)) \
  IMPORT_FUNC(EVP_MD_CTX *, EVP_MD_CTX_new, (void)) \
  IMPORT_FUNC(void, EVP_MD_CTX_free, (EVP_MD_CTX *ctx)) \
  IMPORT_FUNC(int, EVP_DigestInit_ex, (EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)) \
  IMPORT_FUNC(int, EVP_DigestUpdate, (EVP_MD_CTX *ctx, const void *d, size_t cnt)) \
  IMPORT_FUNC(int, EVP_DigestFinal_ex, (EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)) \
  IMPORT_FUNC(int, EVP_Digest, (const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl)) \
  /* cipher */ \
  IMPORT_FUNC(const EVP_CIPHER *, EVP_aes_128_ctr, (void)) \
  IMPORT_FUNC(EVP_CIPHER_CTX *, EVP_CIPHER_CTX_new, (void)) \
  IMPORT_FUNC(void, EVP_CIPHER_CTX_free, (EVP_CIPHER_CTX *a)) \
  IMPORT_FUNC(int, EVP_EncryptInit_ex, (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv)) \
  IMPORT_FUNC(int, EVP_EncryptUpdate, (EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)) \
  IMPORT_FUNC(int, EVP_EncryptFinal_ex, (EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)) \
  IMPORT_FUNC(int, EVP_DecryptInit_ex, (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv)) \
  IMPORT_FUNC(int, EVP_DecryptUpdate, (EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)) \
  IMPORT_FUNC(int, EVP_DecryptFinal_ex, (EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)) \
  /* HMAC (EVP_MAC) */ \
  IMPORT_FUNC(EVP_MAC *, EVP_MAC_fetch, (void *ctx, const char *algorithm, const char *properties)) \
  IMPORT_FUNC(void, EVP_MAC_free, (EVP_MAC *mac)) \
  IMPORT_FUNC(EVP_MAC_CTX *, EVP_MAC_CTX_new, (EVP_MAC *mac)) \
  IMPORT_FUNC(void, EVP_MAC_CTX_free, (EVP_MAC_CTX *ctx)) \
  IMPORT_FUNC(int, EVP_MAC_init, (EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen, const void *params)) \
  IMPORT_FUNC(int, EVP_MAC_update, (EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen)) \
  IMPORT_FUNC(int, EVP_MAC_final, (EVP_MAC_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize)) \
  IMPORT_FUNC(int, EVP_MAC_CTX_set_params, (EVP_MAC_CTX *ctx, const void *params)) \
  /* pkey */ \
  IMPORT_FUNC(EVP_PKEY_CTX *, EVP_PKEY_CTX_new, (EVP_PKEY *pkey, ENGINE *e)) \
  IMPORT_FUNC(EVP_PKEY_CTX *, EVP_PKEY_CTX_new_from_name, (void *libctx, const char *name, const char *propq)) \
  IMPORT_FUNC(EVP_PKEY_CTX *, EVP_PKEY_CTX_new_id, (int id, ENGINE *e)) \
  IMPORT_FUNC(void, EVP_PKEY_CTX_free, (EVP_PKEY_CTX *ctx)) \
  IMPORT_FUNC(int, EVP_PKEY_keygen_init, (EVP_PKEY_CTX *ctx)) \
  IMPORT_FUNC(int, EVP_PKEY_keygen, (EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)) \
  IMPORT_FUNC(int, EVP_PKEY_sign_init, (EVP_PKEY_CTX *ctx)) \
  IMPORT_FUNC(int, EVP_PKEY_sign, (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)) \
  IMPORT_FUNC(int, EVP_PKEY_verify_init, (EVP_PKEY_CTX *ctx)) \
  IMPORT_FUNC(int, EVP_PKEY_verify, (EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)) \
  IMPORT_FUNC(int, EVP_PKEY_derive_init, (EVP_PKEY_CTX *ctx)) \
  IMPORT_FUNC(int, EVP_PKEY_derive_set_peer, (EVP_PKEY_CTX *ctx, EVP_PKEY *peer)) \
  IMPORT_FUNC(int, EVP_PKEY_derive, (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)) \
  IMPORT_FUNC(int, EVP_PKEY_CTX_set_signature_md, (EVP_PKEY_CTX *ctx, const EVP_MD *md)) \
  IMPORT_FUNC(int, EVP_PKEY_CTX_set_ec_paramgen_curve_nid, (EVP_PKEY_CTX *ctx, int nid)) \
  IMPORT_FUNC(EVP_PKEY *, EVP_PKEY_new, (void)) \
  IMPORT_FUNC(void, EVP_PKEY_free, (EVP_PKEY *pkey)) \
  IMPORT_FUNC(int, EVP_PKEY_get_size, (const EVP_PKEY *pkey)) \
  IMPORT_FUNC(int, EVP_PKEY_get_octet_string_param, (const EVP_PKEY *pkey, const char *key_name, unsigned char *buf, size_t bufsize, size_t *written_len)) \
  IMPORT_FUNC(int, i2d_PUBKEY, (const EVP_PKEY *a, unsigned char **pp)) \
  IMPORT_FUNC(EVP_PKEY *, d2i_PUBKEY, (EVP_PKEY **a, const unsigned char **pp, long length)) \
  IMPORT_FUNC(int, i2d_PrivateKey, (EVP_PKEY *a, unsigned char **pp)) \
  /* fromdata for raw key construction */ \
  IMPORT_FUNC(int, EVP_PKEY_fromdata_init, (EVP_PKEY_CTX *ctx)) \
  IMPORT_FUNC(int, EVP_PKEY_fromdata, (EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey, int selection, const void *params)) \
  IMPORT_FUNC(void *, OSSL_PARAM_BLD_new, (void)) \
  IMPORT_FUNC(void, OSSL_PARAM_BLD_free, (void *bld)) \
  IMPORT_FUNC(int, OSSL_PARAM_BLD_push_BN, (void *bld, const char *key, const BIGNUM *bn)) \
  IMPORT_FUNC(int, OSSL_PARAM_BLD_push_octet_string, (void *bld, const char *key, const void *buf, size_t bsize)) \
  IMPORT_FUNC(int, OSSL_PARAM_BLD_push_utf8_string, (void *bld, const char *key, const char *buf, size_t bsize)) \
  IMPORT_FUNC(const void *, OSSL_PARAM_BLD_to_param, (void *bld)) \
  /* bignum */ \
  IMPORT_FUNC(BIGNUM *, BN_new, (void)) \
  IMPORT_FUNC(void, BN_free, (BIGNUM *a)) \
  IMPORT_FUNC(int, BN_num_bits, (const BIGNUM *a)) \
  IMPORT_FUNC(BIGNUM *, BN_bin2bn, (const unsigned char *s, int len, BIGNUM *ret)) \
  IMPORT_FUNC(int, BN_bn2bin, (const BIGNUM *a, unsigned char *to)) \
  IMPORT_FUNC(int, BN_bn2binpad, (const BIGNUM *a, unsigned char *to, int tolen)) \
  IMPORT_FUNC(int, BN_mod_exp, (BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx)) \
  IMPORT_FUNC(int, BN_rand_range, (BIGNUM *rnd, const BIGNUM *range)) \
  /* PEM / BIO */ \
  IMPORT_FUNC(BIO *, BIO_new_file, (const char *filename, const char *mode)) \
  IMPORT_FUNC(BIO *, BIO_new_mem_buf, (const void *buf, int len)) \
  IMPORT_FUNC(void, BIO_free, (BIO *a)) \
  IMPORT_FUNC(EVP_PKEY *, PEM_read_bio_PrivateKey, (BIO *bp, EVP_PKEY **x, void *cb, void *u)) \
  IMPORT_FUNC(EVP_PKEY *, PEM_read_bio_PUBKEY, (BIO *bp, EVP_PKEY **x, void *cb, void *u))

#ifndef EVP_PKEY_KEYPAIR
#define EVP_PKEY_KEYPAIR  0x0007
#endif
#ifndef EVP_PKEY_PUBLIC_KEY
#define EVP_PKEY_PUBLIC_KEY 0x0002
#endif

#define IMPORT_FUNC(ret, name, params) static ret (*name) params;
IMPORTED_OPEN_SSL_FUNCTIONS
#undef IMPORT_FUNC

/* ------------------------------------------------------------------ */
/* Loader                                                             */
/* ------------------------------------------------------------------ */
int moonbitlang_ssh_load_openssl(int *major, int *minor, int *fix) {
#ifdef _WIN32
  HMODULE handle = LoadLibraryA("libcrypto-3-x64.dll");
  if (!handle) handle = LoadLibraryA("libcrypto-3.dll");
  if (!handle) handle = LoadLibraryA("libcrypto.dll");
  if (!handle) return 1;
  unsigned long (*OPENSSL_version_num_func)(void) =
    (unsigned long (*)(void))GetProcAddress(handle, "OpenSSL_version_num");
  if (!OPENSSL_version_num_func) return 2;
  unsigned long version = (*OPENSSL_version_num_func)();
  *major = version >> 28;
  *minor = (version >> 20) & 0xff;
  *fix = (version >> 12) & 0xff;
  if (*major < 1 || (*major == 1 && (*minor < 1 || (*minor == 1 && *fix < 1)))) return 3;
#define IMPORT_FUNC(ret, func, params) \
  func = (ret (*) params)GetProcAddress(handle, "" #func ""); \
  if (!func) return 4;
  IMPORTED_OPEN_SSL_FUNCTIONS
#undef IMPORT_FUNC
#else
  void *handle = 0;
#ifdef __MACH__
  handle = dlopen("/usr/lib/libcrypto.44.dylib", RTLD_LAZY);
  if (!handle) handle = dlopen("/usr/lib/libcrypto.46.dylib", RTLD_LAZY);
  if (!handle) handle = dlopen("/usr/lib/libcrypto.dylib", RTLD_LAZY);
#else
  handle = dlopen("libcrypto.so.3", RTLD_NOW);
  if (!handle) handle = dlopen("libcrypto.so.1.1", RTLD_NOW);
  if (!handle) handle = dlopen("libcrypto.so", RTLD_NOW);
#endif
  if (!handle) return 1;
  unsigned long (*OPENSSL_version_num_fn)() = dlsym(handle, "OpenSSL_version_num");
  if (!OPENSSL_version_num_fn) return 2;
  unsigned long version = (*OPENSSL_version_num_fn)();
  *major = version >> 28;
  *minor = (version >> 20) & 0xff;
  *fix = (version >> 12) & 0xff;
  if (*major < 1 || (*major == 1 && (*minor < 1 || (*minor == 1 && *fix < 1)))) return 3;
#define IMPORT_FUNC(ret, func, params) \
  func = dlsym(handle, "" #func ""); \
  if (!func) return 4;
  IMPORTED_OPEN_SSL_FUNCTIONS
#undef IMPORT_FUNC
#endif
  OPENSSL_init_crypto(0, NULL);
  return 0;
}

int moonbitlang_ssh_peek_error_code(void) { return (int)ERR_peek_error(); }
int moonbitlang_ssh_get_error_string(void *buf) {
  unsigned long code = ERR_get_error();
  if (code == 0) return 0;
  ERR_error_string(code, (char *)buf);
  return (int)strlen((char *)buf);
}
void moonbitlang_ssh_clear_error(void) { ERR_clear_error(); }

/* ------------------------------------------------------------------ */
/* Random                                                             */
/* ------------------------------------------------------------------ */
int moonbitlang_ssh_rand_bytes(unsigned char *buf, int num) {
  return RAND_bytes(buf, num);
}

/* ------------------------------------------------------------------ */
/* Digest                                                             */
/* ------------------------------------------------------------------ */
void *moonbitlang_ssh_md_ctx_new(void) { return EVP_MD_CTX_new(); }
void moonbitlang_ssh_md_ctx_free(void *ctx) { if (ctx) EVP_MD_CTX_free((EVP_MD_CTX *)ctx); }

static const EVP_MD *md_by_id(int alg_id) {
  switch (alg_id) {
    case 1: return EVP_sha1();
    case 2: return EVP_sha256();
    default: return 0;
  }
}

int moonbitlang_ssh_md_size(int alg_id) {
  switch (alg_id) { case 1: return 20; case 2: return 32; default: return 0; }
}

int moonbitlang_ssh_md_init(void *ctx, int alg_id) {
  return EVP_DigestInit_ex((EVP_MD_CTX *)ctx, md_by_id(alg_id), 0);
}
int moonbitlang_ssh_md_update(void *ctx, const void *data, int len) {
  return EVP_DigestUpdate((EVP_MD_CTX *)ctx, data, (size_t)len);
}
int moonbitlang_ssh_md_final(void *ctx, unsigned char *out, int *out_len) {
  unsigned int len = 0;
  int r = EVP_DigestFinal_ex((EVP_MD_CTX *)ctx, out, &len);
  if (out_len) *out_len = (int)len;
  return r;
}
int moonbitlang_ssh_digest(int alg_id, const void *data, int len,
                           unsigned char *out, int *out_len) {
  unsigned int size = 0;
  int r = EVP_Digest(data, (size_t)len, out, &size, md_by_id(alg_id), 0);
  if (out_len) *out_len = (int)size;
  return r;
}

/* ------------------------------------------------------------------ */
/* HMAC                                                               */
/* ------------------------------------------------------------------ */
static const char *hmac_digest_name(int alg_id) {
  switch (alg_id) { case 1: return "SHA1"; case 2: return "SHA256"; default: return 0; }
}

static void *build_hmac_digest_param(const char *digest_name) {
  void *bld = OSSL_PARAM_BLD_new();
  if (!bld) return 0;
  OSSL_PARAM_BLD_push_utf8_string(bld, "digest", (char *)digest_name, 0);
  const void *params = OSSL_PARAM_BLD_to_param(bld);
  OSSL_PARAM_BLD_free(bld);
  return (void *)params;
}

int moonbitlang_ssh_hmac(
  int alg_id, const unsigned char *key, int key_len,
  const unsigned char *data, int data_len,
  unsigned char *out, int *out_len
) {
  const char *digest = hmac_digest_name(alg_id);
  if (!digest) return 0;
  EVP_MAC *mac = EVP_MAC_fetch(0, "HMAC", 0);
  if (!mac) return 0;
  EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
  if (!ctx) { EVP_MAC_free(mac); return 0; }
  int ok = 1;
  void *params = build_hmac_digest_param(digest);
  if (!params || EVP_MAC_CTX_set_params(ctx, (const OSSL_PARAM *)params) != 1) ok = 0;
  if (ok && EVP_MAC_init(ctx, key, (size_t)key_len, 0) != 1) ok = 0;
  if (ok && EVP_MAC_update(ctx, data, (size_t)data_len) != 1) ok = 0;
  size_t outl = 0;
  if (ok) {
    int max_out = moonbitlang_ssh_md_size(alg_id);
    if (EVP_MAC_final(ctx, out, &outl, (size_t)max_out) != 1) ok = 0;
  }
  if (out_len) *out_len = (int)outl;
  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);
  return ok;
}

/* ------------------------------------------------------------------ */
/* Cipher (AES-128-CTR)                                               */
/* ------------------------------------------------------------------ */
void *moonbitlang_ssh_cipher_ctx_new(void) { return EVP_CIPHER_CTX_new(); }
void moonbitlang_ssh_cipher_ctx_free(void *ctx) { if (ctx) EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)ctx); }

static const EVP_CIPHER *cipher_by_id(int alg_id) {
  switch (alg_id) {
    case 1: return EVP_aes_128_ctr();
    default: return 0;
  }
}

int moonbitlang_ssh_cipher_init(void *ctx, int alg_id, int encrypt,
                                const unsigned char *key, const unsigned char *iv) {
  const EVP_CIPHER *c = cipher_by_id(alg_id);
  if (!c) return 0;
  if (encrypt) return EVP_EncryptInit_ex((EVP_CIPHER_CTX *)ctx, c, 0, key, iv);
  else return EVP_DecryptInit_ex((EVP_CIPHER_CTX *)ctx, c, 0, key, iv);
}

int moonbitlang_ssh_cipher_update(void *ctx, int encrypt,
                                  const unsigned char *in, int in_len,
                                  unsigned char *out, int *out_len) {
  int outl = 0;
  int r = encrypt
    ? EVP_EncryptUpdate((EVP_CIPHER_CTX *)ctx, out, &outl, in, in_len)
    : EVP_DecryptUpdate((EVP_CIPHER_CTX *)ctx, out, &outl, in, in_len);
  if (out_len) *out_len = outl;
  return r;
}

int moonbitlang_ssh_cipher_final(void *ctx, int encrypt,
                                 unsigned char *out, int *out_len) {
  int outl = 0;
  int r = encrypt
    ? EVP_EncryptFinal_ex((EVP_CIPHER_CTX *)ctx, out, &outl)
    : EVP_DecryptFinal_ex((EVP_CIPHER_CTX *)ctx, out, &outl);
  if (out_len) *out_len = outl;
  return r;
}

/* ------------------------------------------------------------------ */
/* ECDH P-256                                                         */
/* ------------------------------------------------------------------ */

/*
 * Extract the raw uncompressed EC point (04 || x || y) from a
 * SubjectPublicKeyInfo DER blob for EC P-256.
 *
 * SPKI DER structure (P-256):
 *   30 59                    SEQUENCE (89 bytes)
 *     30 13                  SEQUENCE (19 bytes) AlgorithmIdentifier
 *       06 07 ...             OID ecPublicKey
 *       06 08 ...             OID secp256r1
 *     03 3b                  BIT STRING (59 bytes)
 *       00                   unused bits
 *       04 xx...             raw point (65 bytes)
 *
 * Returns the length of the raw point, or 0 on failure.
 */
static int extract_raw_ec_point(const unsigned char *spki, int spki_len,
                                unsigned char *out, int out_cap) {
  int pos = 0;
  /* Outer SEQUENCE */
  if (pos >= spki_len || spki[pos] != 0x30) return 0; pos++;
  if (pos >= spki_len) return 0;
  int outer_len = spki[pos]; pos++;
  if (pos + outer_len > spki_len) return 0;
  /* Inner SEQUENCE (AlgorithmIdentifier) */
  if (pos >= spki_len || spki[pos] != 0x30) return 0; pos++;
  if (pos >= spki_len) return 0;
  int alg_len = spki[pos]; pos++;
  pos += alg_len; /* skip AlgorithmIdentifier */
  /* BIT STRING */
  if (pos >= spki_len || spki[pos] != 0x03) return 0; pos++;
  if (pos >= spki_len) return 0;
  int bs_len = spki[pos]; pos++;
  if (pos + bs_len > spki_len) return 0;
  /* Unused bits count */
  /* Handle long-form length */
  int bs_content_len = bs_len;
  /* Skip unused bits byte */
  pos++;
  int raw_len = bs_content_len - 1; /* subtract unused bits byte */
  if (raw_len <= 0 || raw_len > out_cap) return 0;
  memcpy(out, spki + pos, (size_t)raw_len);
  return raw_len;
}

/*
 * Build a minimal SubjectPublicKeyInfo DER for EC P-256
 * wrapping the given raw uncompressed EC point.
 *
 * Output format (89 bytes):
 *   30 59 30 13 06 07 2a 86 48 ce 3d 02 01
 *   06 08 2a 86 48 ce 3d 03 01 07 03 3b 00
 *   <raw_point (65 bytes)>
 */
static int wrap_raw_point_in_spki(const unsigned char *raw, int raw_len,
                                  unsigned char *out, int out_cap) {
  /* Only P-256 raw points are supported (65 bytes: 04 || x || y) */
  if (raw_len != 65) return 0;
  if (out_cap < 89) return 0;
  const unsigned char spki_prefix[] = {
    0x30, 0x59,                                           /* SEQUENCE (89) */
      0x30, 0x13,                                         /* SEQUENCE (19) */
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, /* ecPublicKey */
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, /* secp256r1 */
      0x03, 0x3b,                                         /* BIT STRING (59) */
        0x00                                              /* unused bits */
  };
  memcpy(out, spki_prefix, sizeof(spki_prefix));
  memcpy(out + sizeof(spki_prefix), raw, (size_t)raw_len);
  return (int)(sizeof(spki_prefix) + raw_len);
}

/*
 * Extract the raw uncompressed EC point (04 || x || y, 65 bytes for P-256)
 * from an EVP_PKEY using OpenSSL's EVP_PKEY_get_octet_string_param.
 * Falls back to parsing SPKI DER if the direct API is unavailable.
 */
static int get_ec_raw_point(void *pkey, unsigned char *out, int out_cap) {
  size_t written = 0;
  int rc = EVP_PKEY_get_octet_string_param((EVP_PKEY *)pkey, "pub", out, (size_t)out_cap, &written);
  if (rc == 1 && written == 65) {
    return (int)written;
  }
  /* Fallback: parse from SPKI DER */
  unsigned char *der = 0;
  int der_len = i2d_PUBKEY((const EVP_PKEY *)pkey, &der);
  if (der_len <= 0) return 0;
  int pos = 0;
  if (pos >= der_len || der[pos] != 0x30) { free(der); return 0; } pos++;
  if (pos >= der_len) { free(der); return 0; }
  int outer_len = der[pos]; pos++;
  if (pos + outer_len > der_len) { free(der); return 0; }
  if (pos >= der_len || der[pos] != 0x30) { free(der); return 0; } pos++;
  if (pos >= der_len) { free(der); return 0; }
  int alg_len = der[pos]; pos++;
  pos += alg_len;
  if (pos >= der_len || der[pos] != 0x03) { free(der); return 0; } pos++;
  if (pos >= der_len) { free(der); return 0; }
  int bs_len = der[pos]; pos++;
  if (pos + bs_len > der_len) { free(der); return 0; }
  pos++; /* skip unused bits */
  int raw_len = bs_len - 1;
  if (raw_len <= 0 || raw_len > out_cap) { free(der); return 0; }
  memcpy(out, der + pos, (size_t)raw_len);
  free(der);
  return raw_len;
}

int moonbitlang_ssh_ecdh_gen_key(void **priv_out, unsigned char *pub_buf, int *pub_len) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(0, "EC", 0);
  if (!ctx) return 0;
  if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return 0; }
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, 415) <= 0) { EVP_PKEY_CTX_free(ctx); return 0; }
  EVP_PKEY *pkey = 0;
  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return 0; }
  EVP_PKEY_CTX_free(ctx);
  /* Get raw uncompressed EC point directly from the key */
  int raw_len = get_ec_raw_point(pkey, pub_buf, *pub_len);
  if (raw_len <= 0) { EVP_PKEY_free(pkey); return 0; }
  *pub_len = raw_len;
  *priv_out = pkey;
  return 1;
}

int moonbitlang_ssh_ecdh_derive(void *our, const unsigned char *peer_pub, int peer_len,
                                unsigned char *out, int *out_len) {
  /* Wrap raw EC point in SPKI DER so d2i_PUBKEY can parse it */
  unsigned char spki_buf[128];
  int spki_len = wrap_raw_point_in_spki(peer_pub, peer_len, spki_buf, sizeof(spki_buf));
  if (spki_len <= 0) return 0;
  EVP_PKEY *peer = 0;
  const unsigned char *p = spki_buf;
  peer = d2i_PUBKEY(0, &p, (long)spki_len);
  if (!peer) return 0;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY *)our, 0);
  if (!ctx) { EVP_PKEY_free(peer); return 0; }
  int ok = 1;
  if (EVP_PKEY_derive_init(ctx) <= 0) ok = 0;
  if (ok && EVP_PKEY_derive_set_peer(ctx, peer) <= 0) ok = 0;
  size_t olen = (size_t)*out_len;
  if (ok && EVP_PKEY_derive(ctx, out, &olen) <= 0) ok = 0;
  if (ok) *out_len = (int)olen;
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(peer);
  return ok;
}

/* ------------------------------------------------------------------ */
/* RSA sign/verify                                                     */
/* ------------------------------------------------------------------ */
int moonbitlang_ssh_rsa_sign(void *pkey, int md_alg_id,
                             const unsigned char *tbs, int tbs_len,
                             unsigned char *sig, int *sig_len) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY *)pkey, 0);
  if (!ctx) return 0;
  int ok = 1;
  if (EVP_PKEY_sign_init(ctx) <= 0) ok = 0;
  if (ok && md_alg_id != 0) {
    if (EVP_PKEY_CTX_set_signature_md(ctx, md_by_id(md_alg_id)) <= 0) ok = 0;
  }
  size_t slen = (size_t)*sig_len;
  if (ok && EVP_PKEY_sign(ctx, sig, &slen, tbs, (size_t)tbs_len) <= 0) ok = 0;
  if (ok) *sig_len = (int)slen;
  EVP_PKEY_CTX_free(ctx);
  return ok;
}

int moonbitlang_ssh_rsa_verify(void *pkey, int md_alg_id,
                               const unsigned char *tbs, int tbs_len,
                               const unsigned char *sig, int sig_len) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY *)pkey, 0);
  if (!ctx) return 0;
  int ok = 1;
  if (EVP_PKEY_verify_init(ctx) <= 0) ok = 0;
  if (ok && md_alg_id != 0) {
    if (EVP_PKEY_CTX_set_signature_md(ctx, md_by_id(md_alg_id)) <= 0) ok = 0;
  }
  if (ok && EVP_PKEY_verify(ctx, sig, (size_t)sig_len, tbs, (size_t)tbs_len) <= 0) ok = 0;
  EVP_PKEY_CTX_free(ctx);
  return ok;
}

/* ------------------------------------------------------------------ */
/* PEM key loading                                                     */
/* ------------------------------------------------------------------ */
int moonbitlang_ssh_pem_read_private_key(const char *path, void **out) {
  BIO *bio = BIO_new_file(path, "r");
  if (!bio) return 0;
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, 0, 0, 0);
  BIO_free(bio);
  if (!pkey) return 0;
  *out = pkey;
  return 1;
}

int moonbitlang_ssh_pem_read_public_key(const char *path, void **out) {
  BIO *bio = BIO_new_file(path, "r");
  if (!bio) return 0;
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, 0, 0, 0);
  BIO_free(bio);
  if (!pkey) return 0;
  *out = pkey;
  return 1;
}

/* ------------------------------------------------------------------ */
/* BIGNUM helpers                                                     */
/* ------------------------------------------------------------------ */
void *moonbitlang_ssh_bn_new(void) { return BN_new(); }
void moonbitlang_ssh_bn_free(void *bn) { if (bn) BN_free((BIGNUM *)bn); }
int moonbitlang_ssh_bn_bin2bn(const unsigned char *buf, int len, void *bn) {
  return BN_bin2bn(buf, len, (BIGNUM *)bn) != 0;
}
int moonbitlang_ssh_bn_bn2bin(void *bn, unsigned char *buf) {
  return BN_bn2bin((BIGNUM *)bn, buf);
}
int moonbitlang_ssh_bn_bn2binpad(void *bn, unsigned char *buf, int len) {
  return BN_bn2binpad((BIGNUM *)bn, buf, len);
}
int moonbitlang_ssh_bn_num_bytes(void *bn) { return (BN_num_bits((BIGNUM *)bn) + 7) / 8; }
int moonbitlang_ssh_bn_num_bits(void *bn) { return BN_num_bits((BIGNUM *)bn); }
int moonbitlang_ssh_bn_mod_exp(void *r, void *a, void *p, void *m) {
  return BN_mod_exp((BIGNUM *)r, (BIGNUM *)a, (BIGNUM *)p, (BIGNUM *)m, 0);
}
int moonbitlang_ssh_bn_rand_range(void *rnd, void *range) {
  return BN_rand_range((BIGNUM *)rnd, (BIGNUM *)range);
}

/* Convert BIGNUM to SSH mpint format (string with optional leading 0x00) */
int moonbitlang_ssh_bn_to_mpint(void *bn, unsigned char *buf, int *buf_len) {
  BIGNUM *b = (BIGNUM *)bn;
  int raw_len = (BN_num_bits(b) + 7) / 8;
  if (raw_len == 0) {
    if (*buf_len >= 4) {
      buf[0] = 0; buf[1] = 0; buf[2] = 0; buf[3] = 1;
      buf[4] = 0;
      *buf_len = 5;
      return 1;
    }
    return 0;
  }
  /* Check if high bit is set -> need leading 0x00 */
  unsigned char *tmp = (unsigned char *)malloc((size_t)raw_len);
  BN_bn2bin(b, tmp);
  int need_zero = (tmp[0] & 0x80) != 0;
  int total_len = 4 + raw_len + (need_zero ? 1 : 0);
  if (*buf_len < total_len) { free(tmp); return 0; }
  /* Write uint32 length */
  uint32_t nlen = (uint32_t)(raw_len + (need_zero ? 1 : 0));
  buf[0] = (unsigned char)(nlen >> 24);
  buf[1] = (unsigned char)(nlen >> 16);
  buf[2] = (unsigned char)(nlen >> 8);
  buf[3] = (unsigned char)nlen;
  int off = 4;
  if (need_zero) { buf[off] = 0; off++; }
  memcpy(buf + off, tmp, (size_t)raw_len);
  free(tmp);
  *buf_len = total_len;
  return 1;
}

int moonbitlang_ssh_pkey_new_rsa(
  const unsigned char *n, int n_len,
  const unsigned char *e, int e_len,
  const unsigned char *d, int d_len,
  void **out
) {
  BIGNUM *bn_n = BN_bin2bn(n, n_len, 0);
  BIGNUM *bn_e = BN_bin2bn(e, e_len, 0);
  BIGNUM *bn_d = (d && d_len > 0) ? BN_bin2bn(d, d_len, 0) : 0;
  if (!bn_n || !bn_e) { if (bn_n) BN_free(bn_n); if (bn_e) BN_free(bn_e); return 0; }
  
  void *bld = OSSL_PARAM_BLD_new();
  if (!bld) { BN_free(bn_n); BN_free(bn_e); if (bn_d) BN_free(bn_d); return 0; }
  OSSL_PARAM_BLD_push_BN(bld, "n", bn_n);
  OSSL_PARAM_BLD_push_BN(bld, "e", bn_e);
  if (bn_d) OSSL_PARAM_BLD_push_BN(bld, "d", bn_d);
  const void *params = OSSL_PARAM_BLD_to_param(bld);
  OSSL_PARAM_BLD_free(bld);
  if (!params) { BN_free(bn_n); BN_free(bn_e); if (bn_d) BN_free(bn_d); return 0; }
  
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(0, "RSA", 0);
  if (!ctx) { BN_free(bn_n); BN_free(bn_e); if (bn_d) BN_free(bn_d); return 0; }
  EVP_PKEY *pkey = 0;
  int ok = 1;
  if (EVP_PKEY_fromdata_init(ctx) <= 0) ok = 0;
  if (ok && EVP_PKEY_fromdata(ctx, &pkey, bn_d ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) <= 0) ok = 0;
  EVP_PKEY_CTX_free(ctx);
  BN_free(bn_n); BN_free(bn_e); if (bn_d) BN_free(bn_d);
  if (ok) { *out = pkey; return 1; }
  if (pkey) EVP_PKEY_free(pkey);
  return 0;
}

void *moonbitlang_ssh_pkey_new(void) { return EVP_PKEY_new(); }
void moonbitlang_ssh_pkey_free(void *pkey) { if (pkey) EVP_PKEY_free((EVP_PKEY *)pkey); }
int moonbitlang_ssh_pkey_size(void *pkey) { return EVP_PKEY_get_size((EVP_PKEY *)pkey); }
int moonbitlang_ssh_i2d_pubkey(void *pkey, unsigned char **buf) {
  return i2d_PUBKEY((const EVP_PKEY *)pkey, buf);
}
