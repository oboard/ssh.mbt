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

/* Global debug flag controlled by MoonBit layer (defined in socket.c) */
extern int moonssh_debug;

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
  IMPORT_FUNC(const EVP_MD *, EVP_sha384, (void)) \
  IMPORT_FUNC(const EVP_MD *, EVP_sha521, (void)) \
  IMPORT_FUNC(EVP_MD_CTX *, EVP_MD_CTX_new, (void)) \
  IMPORT_FUNC(void, EVP_MD_CTX_free, (EVP_MD_CTX *ctx)) \
  IMPORT_FUNC(int, EVP_DigestInit_ex, (EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)) \
  IMPORT_FUNC(int, EVP_DigestUpdate, (EVP_MD_CTX *ctx, const void *d, size_t cnt)) \
  IMPORT_FUNC(int, EVP_DigestFinal_ex, (EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)) \
  IMPORT_FUNC(int, EVP_Digest, (const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl)) \
  IMPORT_FUNC(int, EVP_DigestSignInit, (EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)) \
  IMPORT_FUNC(int, EVP_DigestSign, (EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen)) \
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
  /* old-style HMAC (deprecated but stable) */ \
  IMPORT_FUNC(unsigned char *, HMAC, (const EVP_MD *evp_md, const void *key, int key_len, const unsigned char *d, size_t n, unsigned char *md, unsigned int *md_len)) \
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
  IMPORT_FUNC(int, EVP_PKEY_verify_recover_init, (EVP_PKEY_CTX *ctx)) \
  IMPORT_FUNC(int, EVP_PKEY_verify_recover, (EVP_PKEY_CTX *ctx, unsigned char *rout, size_t *routlen, const unsigned char *sig, size_t siglen)) \
  IMPORT_FUNC(int, EVP_PKEY_derive_init, (EVP_PKEY_CTX *ctx)) \
  IMPORT_FUNC(int, EVP_PKEY_derive_set_peer, (EVP_PKEY_CTX *ctx, EVP_PKEY *peer)) \
  IMPORT_FUNC(int, EVP_PKEY_derive, (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)) \
  IMPORT_FUNC(int, EVP_PKEY_CTX_set_signature_md, (EVP_PKEY_CTX *ctx, const EVP_MD *md)) \
  IMPORT_FUNC(int, EVP_PKEY_CTX_set_ec_paramgen_curve_nid, (EVP_PKEY_CTX *ctx, int nid)) \
  IMPORT_FUNC(EVP_PKEY *, EVP_PKEY_new, (void)) \
  IMPORT_FUNC(void, EVP_PKEY_free, (EVP_PKEY *pkey)) \
  IMPORT_FUNC(int, EVP_PKEY_get_size, (const EVP_PKEY *pkey)) \
  IMPORT_FUNC(int, EVP_PKEY_get_id, (const EVP_PKEY *pkey)) \
  IMPORT_FUNC(int, EVP_PKEY_get_octet_string_param, (const EVP_PKEY *pkey, const char *key_name, unsigned char *buf, size_t bufsize, size_t *written_len)) \
  IMPORT_FUNC(int, EVP_PKEY_get_utf8_string_param, (const EVP_PKEY *pkey, const char *key_name, char *buf, size_t bufsize, size_t *written_len)) \
  IMPORT_FUNC(int, EVP_PKEY_get_bn_param, (const EVP_PKEY *pkey, const char *key_name, BIGNUM **bn)) \
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
    case 3: return EVP_sha384();
    case 4: return EVP_sha521();
    default: return 0;
  }
}

int moonbitlang_ssh_md_size(int alg_id) {
  switch (alg_id) { case 1: return 20; case 2: return 32; case 3: return 48; case 4: return 64; default: return 0; }
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
  const EVP_MD *md = md_by_id(alg_id);
  if (!md) return 0;

  /* Debug: dump HMAC key and full data */
  if (moonssh_debug) {
    fprintf(stderr, "openssl_hmac: alg=%d key_len=%d data_len=%d\n", alg_id, key_len, data_len);
    fprintf(stderr, "HMAC_KEY_HEX=");
    for (int i = 0; i < key_len; i++) fprintf(stderr, "%02x", key[i]);
    fprintf(stderr, "\nHMAC_DATA_HEX=");
    for (int i = 0; i < data_len; i++) fprintf(stderr, "%02x", data[i]);
    fprintf(stderr, "\n");
  }

  unsigned int md_len = 0;
  unsigned char *result = HMAC(md, key, key_len, data, (size_t)data_len, out, &md_len);
  if (!result) return 0;

  /* Debug: dump full HMAC output */
  if (moonssh_debug) {
    fprintf(stderr, "openssl_hmac: out=");
    for (int i = 0; i < (int)md_len; i++) {
      fprintf(stderr, "%02x", out[i]);
    }
    fprintf(stderr, " (len=%d)\n", (int)md_len);
  }

  if (out_len) *out_len = (int)md_len;
  return 1;
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
  /* P-256: 65 bytes -> SPKI 91 bytes
   * P-384: 97 bytes -> SPKI 123 bytes
   * P-521: 133 bytes -> SPKI 159 bytes */
  /* AlgorithmIdentifier is always 19 bytes: SEQUENCE(13) + ecPublicKey OID(8) + curve OID(10) */
  /* But the outer lengths and BIT STRING length change per curve */
  int alg_id_len = 19; /* inner SEQUENCE content length */
  int bit_string_content_len = 1 + raw_len; /* unused_bits_byte + raw point */
  int bit_string_len = bit_string_content_len;
  int outer_content_len = 2 + alg_id_len + 2 + bit_string_len;
  int total_len = 2 + outer_content_len;

  if (out_cap < total_len) return 0;

  const unsigned char *curve_oid;
  int curve_oid_len;
  if (raw_len == 65) {
    /* secp256r1: 06 08 2a 86 48 ce 3d 03 01 07 */
    static const unsigned char oid_p256[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    curve_oid = oid_p256; curve_oid_len = 10;
  } else if (raw_len == 97) {
    /* secp384r1: 06 05 2b 81 04 00 22 */
    static const unsigned char oid_p384[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
    curve_oid = oid_p384; curve_oid_len = 7;
  } else if (raw_len == 133) {
    /* secp521r1: 06 05 2b 81 04 00 23 */
    static const unsigned char oid_p521[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};
    curve_oid = oid_p521; curve_oid_len = 7;
  } else {
    return 0;
  }

  int pos = 0;
  /* Outer SEQUENCE */
  out[pos++] = 0x30;
  out[pos++] = (unsigned char)outer_content_len;
  /* Inner SEQUENCE (AlgorithmIdentifier) */
  out[pos++] = 0x30;
  out[pos++] = (unsigned char)alg_id_len;
  /* ecPublicKey OID */
  out[pos++] = 0x06; out[pos++] = 0x07;
  out[pos++] = 0x2a; out[pos++] = 0x86; out[pos++] = 0x48;
  out[pos++] = 0xce; out[pos++] = 0x3d; out[pos++] = 0x02; out[pos++] = 0x01;
  /* Curve OID */
  memcpy(out + pos, curve_oid, (size_t)curve_oid_len);
  pos += curve_oid_len;
  /* BIT STRING */
  out[pos++] = 0x03;
  out[pos++] = (unsigned char)bit_string_len;
  out[pos++] = 0x00; /* unused bits */
  memcpy(out + pos, raw, (size_t)raw_len);
  pos += raw_len;
  return pos;
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
  /* SSH RSASSA-PKCS1-v1_5 signature verification.
   * The server signs DigestInfo(SHA-256(H)) directly.
   * We use EVP_PKEY_verify_recover to extract the original DigestInfo,
   * then compare the recovered hash with SHA-256(tbs). */
  unsigned char hash_buf[64];
  unsigned int hash_len = 0;
  
  /* Step 1: compute SHA-256(tbs) = SHA-256(exchange_hash) */
  const EVP_MD *md = md_by_id(md_alg_id);
  if (!md) return 0;
  if (!EVP_Digest(tbs, (size_t)tbs_len, hash_buf, &hash_len, md, NULL)) return 0;
  
  /* Step 2: recover DigestInfo from signature */
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY *)pkey, 0);
  if (!ctx) return 0;
  unsigned char recovered[512];
  size_t recovered_len = sizeof(recovered);
  int ok = 1;
  if (EVP_PKEY_verify_recover_init(ctx) <= 0) ok = -1;
  if (ok == 1 && EVP_PKEY_verify_recover(ctx, recovered, &recovered_len,
                                         sig, (size_t)sig_len) <= 0) ok = -1;
  EVP_PKEY_CTX_free(ctx);
  if (ok < 0) return 0;
  
  /* Step 3: extract hash from DigestInfo end and compare */
  if (recovered_len < (size_t)(hash_len + 8)) return 0;
  const unsigned char *extracted = recovered + (recovered_len - hash_len);
  return memcmp(extracted, hash_buf, (size_t)hash_len) == 0 ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* PEM key loading                                                     */
/* ------------------------------------------------------------------ */
/* Copy a MoonBit Bytes (path_bytes, path_len) into a stack-allocated
 * NUL-terminated C string. MoonBit Bytes is not NUL-terminated so we
 * must build a proper C string before passing to fopen/BIO_new_file.
 * Caller-supplied buffer must have room for path_len+1 bytes.
 * Returns 1 on success, 0 if path_len exceeds buf_cap-1. */
static int copy_path_to_cstr(const char *path_bytes, int path_len,
                             char *buf, int buf_cap) {
  if (path_len < 0 || path_len + 1 > buf_cap) return 0;
  memcpy(buf, path_bytes, (size_t)path_len);
  buf[path_len] = '\0';
  return 1;
}

int moonbitlang_ssh_pem_read_private_key(const char *path_bytes, int path_len,
                                         void **out) {
  char path[4096];
  if (!copy_path_to_cstr(path_bytes, path_len, path, sizeof(path))) return 0;
  BIO *bio = BIO_new_file(path, "r");
  if (!bio) return 0;
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, 0, 0, 0);
  BIO_free(bio);
  if (!pkey) return 0;
  *out = pkey;
  return 1;
}

int moonbitlang_ssh_pem_read_public_key(const char *path_bytes, int path_len,
                                        void **out) {
  char path[4096];
  if (!copy_path_to_cstr(path_bytes, path_len, path, sizeof(path))) return 0;
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
int moonbitlang_ssh_pkey_id(void *pkey) {
  return EVP_PKEY_get_id((const EVP_PKEY *)pkey);
}
int moonbitlang_ssh_i2d_pubkey(void *pkey, unsigned char **buf) {
  return i2d_PUBKEY((const EVP_PKEY *)pkey, buf);
}
int moonbitlang_ssh_pkey_get_octet_param(void *pkey, const char *name,
                                         unsigned char *buf, int buf_len,
                                         int *out_len) {
  size_t written = 0;
  int rc = EVP_PKEY_get_octet_string_param(
    (const EVP_PKEY *)pkey, name, buf, (size_t)buf_len, &written);
  if (rc != 1) return 0;
  if (out_len) *out_len = (int)written;
  return 1;
}
int moonbitlang_ssh_pkey_get_bn_bytes(void *pkey, const char *name,
                                      unsigned char *buf, int buf_len,
                                      int *out_len) {
  BIGNUM *bn = 0;
  if (EVP_PKEY_get_bn_param((const EVP_PKEY *)pkey, name, &bn) != 1) return 0;
  if (!bn) return 0;
  /* BN_num_bytes is a macro in OpenSSL 3.x; compute it inline. */
  int n = (BN_num_bits(bn) + 7) / 8;
  if (buf && buf_len >= n) {
    BN_bn2bin(bn, buf);
  } else {
    BN_free(bn);
    return 0;
  }
  BN_free(bn);
  if (out_len) *out_len = n;
  return 1;
}

/* ------------------------------------------------------------------ */
/* ECDSA signature format conversion                                  */
/*   SSH wire format: r || s (each zero-padded to key_size bytes)     */
/*   OpenSSL format:  DER SEQUENCE { INTEGER r, INTEGER s }           */
/* ------------------------------------------------------------------ */

/* Convert DER ECDSA signature to SSH raw r||s format.
 * Returns total bytes written (key_size * 2), or 0 on failure. */
static int ecdsa_der_to_raw(const unsigned char *der, int der_len,
                            unsigned char *out, int out_cap, int key_size) {
  if (out_cap < key_size * 2) return 0;
  int pos = 0;
  /* SEQUENCE tag */
  if (pos >= der_len || der[pos] != 0x30) return 0; pos++;
  if (pos >= der_len) return 0;
  int seq_len = der[pos]; pos++;
  if (pos + seq_len > der_len) return 0;
  /* INTEGER r */
  if (pos >= der_len || der[pos] != 0x02) return 0; pos++;
  if (pos >= der_len) return 0;
  int r_len = der[pos]; pos++;
  if (pos + r_len > der_len) return 0;
  /* skip leading zero */
  const unsigned char *r_bytes = der + pos;
  int r_real = r_len;
  while (r_real > key_size && *r_bytes == 0x00) { r_bytes++; r_real--; }
  if (r_real > key_size) return 0;
  memset(out, 0, (size_t)key_size);
  memcpy(out + key_size - r_real, r_bytes, (size_t)r_real);
  pos += r_len;
  /* INTEGER s */
  if (pos >= der_len || der[pos] != 0x02) return 0; pos++;
  if (pos >= der_len) return 0;
  int s_len = der[pos]; pos++;
  if (pos + s_len > der_len) return 0;
  const unsigned char *s_bytes = der + pos;
  int s_real = s_len;
  while (s_real > key_size && *s_bytes == 0x00) { s_bytes++; s_real--; }
  if (s_real > key_size) return 0;
  memset(out + key_size, 0, (size_t)key_size);
  memcpy(out + key_size + key_size - s_real, s_bytes, (size_t)s_real);
  return key_size * 2;
}

/* Convert SSH raw r||s signature to DER format.
 * Returns bytes written, or 0 on failure. */
static int ecdsa_raw_to_der(const unsigned char *raw, int raw_len,
                            unsigned char *out, int out_cap) {
  int key_size = raw_len / 2;
  if (raw_len != key_size * 2 || out_cap < raw_len + 8) return 0;
  const unsigned char *r = raw;
  const unsigned char *s = raw + key_size;
  /* strip leading zeros */
  int r_off = 0;
  while (r_off < key_size - 1 && r[r_off] == 0x00) r_off++;
  int s_off = 0;
  while (s_off < key_size - 1 && s[s_off] == 0x00) s_off++;
  int r_len = key_size - r_off;
  int s_len = key_size - s_off;
  int r_need_zero = (r[r_off] & 0x80) ? 1 : 0;
  int s_need_zero = (s[s_off] & 0x80) ? 1 : 0;
  int r_int_len = r_len + r_need_zero;
  int s_int_len = s_len + s_need_zero;
  int seq_len = 2 + r_int_len + 2 + s_int_len;
  int pos = 0;
  out[pos++] = 0x30;
  out[pos++] = (unsigned char)seq_len;
  /* INTEGER r */
  out[pos++] = 0x02;
  out[pos++] = (unsigned char)r_int_len;
  if (r_need_zero) out[pos++] = 0x00;
  memcpy(out + pos, r + r_off, (size_t)r_len);
  pos += r_len;
  /* INTEGER s */
  out[pos++] = 0x02;
  out[pos++] = (unsigned char)s_int_len;
  if (s_need_zero) out[pos++] = 0x00;
  memcpy(out + pos, s + s_off, (size_t)s_len);
  pos += s_len;
  return pos;
}

/* ------------------------------------------------------------------ */
/* Generic private-key sign (works for both RSA and Ed25519)          */
/*   md_alg_id = 0  -> Ed25519: uses EVP_DigestSign one-shot API.      */
/*                     OpenSSL rejects EVP_PKEY_sign for EdDSA with    */
/*                     "invalid eddsa instance for attempted operation"*/
/*   md_alg_id = 1/2 -> EVP_PKEY_sign with SHA1/SHA256 (RSA PKCS#1)    */
/* ------------------------------------------------------------------ */
int moonbitlang_ssh_pkey_sign(void *pkey, int md_alg_id,
                              const unsigned char *tbs, int tbs_len,
                              unsigned char *sig, int *sig_len) {
  int key_type = EVP_PKEY_get_id((EVP_PKEY *)pkey);

  if (key_type == 1087) {
    /* Ed25519: one-shot EVP_DigestSign, no digest */
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return 0;
    int ok = 1;
    if (EVP_DigestSignInit(mctx, 0, 0, 0, (EVP_PKEY *)pkey) <= 0) ok = 0;
    size_t slen = (size_t)*sig_len;
    if (ok && EVP_DigestSign(mctx, sig, &slen, tbs, (size_t)tbs_len) <= 0)
      ok = 0;
    if (ok) *sig_len = (int)slen;
    EVP_MD_CTX_free(mctx);
    return ok;
  }

  if (key_type == 408) {
    /* ECDSA: EVP_DigestSign with appropriate digest, then DER→raw */
    const EVP_MD *md = md_by_id(md_alg_id);
    if (!md) return 0;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return 0;
    int ok = 1;
    if (EVP_DigestSignInit(mctx, 0, md, 0, (EVP_PKEY *)pkey) <= 0) ok = 0;
    /* First call to get DER signature size */
    size_t der_len = 0;
    if (ok && EVP_DigestSign(mctx, 0, &der_len, tbs, (size_t)tbs_len) <= 0) ok = 0;
    unsigned char der_sig[512];
    if (ok && der_len > sizeof(der_sig)) ok = 0;
    if (ok && EVP_DigestSign(mctx, der_sig, &der_len, tbs, (size_t)tbs_len) <= 0) ok = 0;
    EVP_MD_CTX_free(mctx);
    if (!ok) return 0;
    /* Determine key size from the curve */
    int key_size = (int)(der_len / 3); /* rough estimate; use max */
    /* Try known sizes: P-256=32, P-384=48, P-521=66 */
    if (*sig_len >= 64 && der_len <= 72) key_size = 32;       /* P-256 */
    else if (*sig_len >= 96 && der_len <= 104) key_size = 48;  /* P-384 */
    else if (*sig_len >= 132 && der_len <= 140) key_size = 66; /* P-521 */
    else key_size = *sig_len / 2;
    int raw_len = ecdsa_der_to_raw(der_sig, (int)der_len, sig, *sig_len, key_size);
    if (raw_len <= 0) return 0;
    *sig_len = raw_len;
    return 1;
  }

  if (key_type == 116) {
    /* DSA: EVP_DigestSign with SHA-1 */
    const EVP_MD *md = md_by_id(md_alg_id);
    if (!md) md = EVP_sha1();
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return 0;
    int ok = 1;
    if (EVP_DigestSignInit(mctx, 0, md, 0, (EVP_PKEY *)pkey) <= 0) ok = 0;
    size_t slen = (size_t)*sig_len;
    if (ok && EVP_DigestSign(mctx, sig, &slen, tbs, (size_t)tbs_len) <= 0) ok = 0;
    if (ok) *sig_len = (int)slen;
    EVP_MD_CTX_free(mctx);
    return ok;
  }

  /* RSA: EVP_PKEY_sign with digest */
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY *)pkey, 0);
  if (!ctx) return 0;
  int ok = 1;
  if (EVP_PKEY_sign_init(ctx) <= 0) ok = 0;
  if (ok && EVP_PKEY_CTX_set_signature_md(ctx, md_by_id(md_alg_id)) <= 0)
    ok = 0;
  size_t slen = (size_t)*sig_len;
  if (ok && EVP_PKEY_sign(ctx, sig, &slen, tbs, (size_t)tbs_len) <= 0) ok = 0;
  if (ok) *sig_len = (int)slen;
  EVP_PKEY_CTX_free(ctx);
  return ok;
}

/* ------------------------------------------------------------------ */
/* Base64 decoder (RFC 4648, standard alphabet)                       */
/*   Strips whitespace, ignores trailing padding.                     */
/*   Returns 1 on success, 0 on invalid input.                        */
/* ------------------------------------------------------------------ */
static const int b64_index[256] = {
  ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
  ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
  ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
  ['Y']=24,['Z']=25,
  ['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,
  ['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,
  ['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,
  ['y']=50,['z']=51,
  ['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,
  ['8']=60,['9']=61,
  ['+']=62,['/']=63
};

int moonbitlang_ssh_base64_decode(const char *src, int src_len,
                                  unsigned char *out, int *out_len) {
  if (!src || src_len < 0 || !out || !out_len) return 0;
  /* Collect 4 base64 chars -> 3 output bytes. '=' is the padding char. */
  int olen = 0;
  int quad[4];
  int qi = 0;
  for (int i = 0; i < src_len; i++) {
    unsigned char c = (unsigned char)src[i];
    if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
    if (c == '=') {
      quad[qi++] = -1;
    } else {
      int v = b64_index[c];
      if (v == 0 && c != 'A') return 0; /* invalid char */
      quad[qi++] = v;
    }
    if (qi == 4) {
      int a = quad[0], b = quad[1], c2 = quad[2], d = quad[3];
      if (a < 0 || b < 0) return 0;
      out[olen++] = (unsigned char)((a << 2) | (b >> 4));
      if (c2 >= 0) out[olen++] = (unsigned char)(((b & 0x0f) << 4) | (c2 >> 2));
      if (d >= 0)  out[olen++] = (unsigned char)(((c2 & 0x03) << 6) | d);
      qi = 0;
    }
  }
  if (qi != 0) return 0; /* incomplete quad */
  *out_len = olen;
  return 1;
}

/* ------------------------------------------------------------------ */
/* OpenSSH private key format decoder (PROTOCOL.key 2016/01/26)       */
/*                                                                      */
/* File format (after base64 decode):                                  */
/*   "openssh-key-v1\0"  (15 bytes)                                    */
/*   string  ciphername  (e.g. "none", "aes256-ctr")                   */
/*   string  kdfname     (e.g. "none", "bcrypt")                       */
/*   string  kdfoptions  (kdf params)                                  */
/*   uint32  number_of_keys (N)                                        */
/*   string  public_key_blob (the SSH wire-format pubkey, repeated N?) */
/*   string  encrypted_private_data                                    */
/*                                                                      */
/* Inner encrypted_private_data layout (when cipher=none, plaintext):   */
/*   uint32  checkint1                                                    */
/*   uint32  checkint2  (must equal checkint1)                          */
/*   <key-type-specific fields, repeated N times>                       */
/*                                                                      */
/* Supported inner key types:                                           */
/*   "ssh-ed25519" -> pub (32), priv (64)                              */
/*   "ssh-rsa"     -> n, e, d, iqmp, p, q, comment                     */
/* ------------------------------------------------------------------ */

/* Read a 4-byte big-endian uint32 at *pos, advancing *pos. */
static int read_u32(const unsigned char *buf, int len, int *pos, uint32_t *out) {
  if (*pos + 4 > len) return 0;
  *out = ((uint32_t)buf[*pos] << 24) |
         ((uint32_t)buf[*pos + 1] << 16) |
         ((uint32_t)buf[*pos + 2] << 8) |
         ((uint32_t)buf[*pos + 3]);
  *pos += 4;
  return 1;
}

/* Read an SSH "string" at *pos (uint32 length + payload). Writes the
 * payload length to *out_len and (optionally) copies payload to out.
 * Returns 1 on success. */
static int read_ssh_string(const unsigned char *buf, int len, int *pos,
                           unsigned char *out, int out_cap, int *out_len) {
  uint32_t slen = 0;
  if (!read_u32(buf, len, pos, &slen)) return 0;
  if (*pos + (int)slen > len) return 0;
  if (out && out_cap >= (int)slen) {
    memcpy(out, buf + *pos, slen);
  } else if (out) {
    return 0;
  }
  *pos += (int)slen;
  if (out_len) *out_len = (int)slen;
  return 1;
}

/* Same as read_ssh_string, but uses a pointer instead of copying.
 * If out or out_len is NULL, the corresponding value is not returned. */
static int read_ssh_string_peek(const unsigned char *buf, int len, int *pos,
                                const unsigned char **out, int *out_len) {
  uint32_t slen = 0;
  if (!read_u32(buf, len, pos, &slen)) return 0;
  if (*pos + (int)slen > len) return 0;
  if (out) *out = buf + *pos;
  if (out_len) *out_len = (int)slen;
  *pos += (int)slen;
  return 1;
}

/* Build an ed25519 EVP_PKEY from a 32-byte public key and a 32-byte
 * private seed (OpenSSH stores the 64-byte form pub||seed; we split it
 * before calling). */
static EVP_PKEY *build_ed25519_pkey(const unsigned char *pub32,
                                    const unsigned char *seed32) {
  EVP_PKEY *pkey = 0;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(0, "ED25519", 0);
  if (!ctx) return 0;
  void *bld = OSSL_PARAM_BLD_new();
  if (!bld) { EVP_PKEY_CTX_free(ctx); return 0; }
  OSSL_PARAM_BLD_push_octet_string(bld, "pub", pub32, 32);
  OSSL_PARAM_BLD_push_octet_string(bld, "priv", seed32, 32);
  const void *params = OSSL_PARAM_BLD_to_param(bld);
  OSSL_PARAM_BLD_free(bld);
  if (!params) { EVP_PKEY_CTX_free(ctx); return 0; }
  if (EVP_PKEY_fromdata_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return 0;
  }
  if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return 0;
  }
  EVP_PKEY_CTX_free(ctx);
  return pkey;
}

/* Build an RSA EVP_PKEY from raw n/e/d byte strings. */
static EVP_PKEY *build_rsa_pkey(const unsigned char *n, int n_len,
                                const unsigned char *e, int e_len,
                                const unsigned char *d, int d_len) {
  BIGNUM *bn_n = BN_bin2bn(n, n_len, 0);
  BIGNUM *bn_e = BN_bin2bn(e, e_len, 0);
  BIGNUM *bn_d = BN_bin2bn(d, d_len, 0);
  if (!bn_n || !bn_e || !bn_d) {
    if (bn_n) BN_free(bn_n);
    if (bn_e) BN_free(bn_e);
    if (bn_d) BN_free(bn_d);
    return 0;
  }
  void *bld = OSSL_PARAM_BLD_new();
  if (!bld) { BN_free(bn_n); BN_free(bn_e); BN_free(bn_d); return 0; }
  OSSL_PARAM_BLD_push_BN(bld, "n", bn_n);
  OSSL_PARAM_BLD_push_BN(bld, "e", bn_e);
  OSSL_PARAM_BLD_push_BN(bld, "d", bn_d);
  const void *params = OSSL_PARAM_BLD_to_param(bld);
  OSSL_PARAM_BLD_free(bld);
  if (!params) { BN_free(bn_n); BN_free(bn_e); BN_free(bn_d); return 0; }
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(0, "RSA", 0);
  if (!ctx) { BN_free(bn_n); BN_free(bn_e); BN_free(bn_d); return 0; }
  EVP_PKEY *pkey = 0;
  if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
      EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    BN_free(bn_n); BN_free(bn_e); BN_free(bn_d);
    if (pkey) EVP_PKEY_free(pkey);
    return 0;
  }
  EVP_PKEY_CTX_free(ctx);
  BN_free(bn_n); BN_free(bn_e); BN_free(bn_d);
  return pkey;
}

/* Map SSH curve identifier to OpenSSL group name */
static const char *ssh_curve_to_openssl_group(const char *curve) {
  if (strcmp(curve, "nistp256") == 0) return "prime256v1";
  if (strcmp(curve, "nistp384") == 0) return "secp384r1";
  if (strcmp(curve, "nistp521") == 0) return "secp521r1";
  return 0;
}

/* Get expected raw EC point size from SSH curve identifier */
static int ssh_curve_point_size(const char *curve) {
  if (strcmp(curve, "nistp256") == 0) return 65;
  if (strcmp(curve, "nistp384") == 0) return 97;
  if (strcmp(curve, "nistp521") == 0) return 133;
  return 0;
}

/* Get key size (r/s component size) from SSH curve identifier */
static int ssh_curve_key_size(const char *curve) {
  if (strcmp(curve, "nistp256") == 0) return 32;
  if (strcmp(curve, "nistp384") == 0) return 48;
  if (strcmp(curve, "nistp521") == 0) return 66;
  return 0;
}

/* Build an ECDSA EVP_PKEY from group name, raw uncompressed point, and private scalar */
static EVP_PKEY *build_ecdsa_pkey(const char *group,
                                  const unsigned char *pub, int pub_len,
                                  const unsigned char *priv, int priv_len) {
  EVP_PKEY *pkey = 0;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(0, "EC", 0);
  if (!ctx) return 0;
  void *bld = OSSL_PARAM_BLD_new();
  if (!bld) { EVP_PKEY_CTX_free(ctx); return 0; }
  OSSL_PARAM_BLD_push_utf8_string(bld, "group", group, 0);
  OSSL_PARAM_BLD_push_octet_string(bld, "pub", pub, (size_t)pub_len);
  if (priv && priv_len > 0)
    OSSL_PARAM_BLD_push_octet_string(bld, "priv", priv, (size_t)priv_len);
  const void *params = OSSL_PARAM_BLD_to_param(bld);
  OSSL_PARAM_BLD_free(bld);
  if (!params) { EVP_PKEY_CTX_free(ctx); return 0; }
  if (EVP_PKEY_fromdata_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return 0; }
  int sel = (priv && priv_len > 0) ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;
  if (EVP_PKEY_fromdata(ctx, &pkey, sel, params) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return 0;
  }
  EVP_PKEY_CTX_free(ctx);
  return pkey;
}

/* Build a DSA EVP_PKEY from raw components */
static EVP_PKEY *build_dsa_pkey(const unsigned char *p, int p_len,
                                const unsigned char *q, int q_len,
                                const unsigned char *g, int g_len,
                                const unsigned char *y, int y_len,
                                const unsigned char *x, int x_len) {
  BIGNUM *bn_p = BN_bin2bn(p, p_len, 0);
  BIGNUM *bn_q = BN_bin2bn(q, q_len, 0);
  BIGNUM *bn_g = BN_bin2bn(g, g_len, 0);
  BIGNUM *bn_y = BN_bin2bn(y, y_len, 0);
  BIGNUM *bn_x = (x && x_len > 0) ? BN_bin2bn(x, x_len, 0) : 0;
  if (!bn_p || !bn_q || !bn_g || !bn_y) {
    if (bn_p) BN_free(bn_p); if (bn_q) BN_free(bn_q);
    if (bn_g) BN_free(bn_g); if (bn_y) BN_free(bn_y);
    if (bn_x) BN_free(bn_x);
    return 0;
  }
  void *bld = OSSL_PARAM_BLD_new();
  if (!bld) { BN_free(bn_p); BN_free(bn_q); BN_free(bn_g); BN_free(bn_y); if (bn_x) BN_free(bn_x); return 0; }
  OSSL_PARAM_BLD_push_BN(bld, "p", bn_p);
  OSSL_PARAM_BLD_push_BN(bld, "q", bn_q);
  OSSL_PARAM_BLD_push_BN(bld, "g", bn_g);
  OSSL_PARAM_BLD_push_BN(bld, "pub", bn_y);
  if (bn_x) OSSL_PARAM_BLD_push_BN(bld, "priv", bn_x);
  const void *params = OSSL_PARAM_BLD_to_param(bld);
  OSSL_PARAM_BLD_free(bld);
  if (!params) { BN_free(bn_p); BN_free(bn_q); BN_free(bn_g); BN_free(bn_y); if (bn_x) BN_free(bn_x); return 0; }
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(0, "DSA", 0);
  if (!ctx) { BN_free(bn_p); BN_free(bn_q); BN_free(bn_g); BN_free(bn_y); if (bn_x) BN_free(bn_x); return 0; }
  EVP_PKEY *pkey = 0;
  int ok = 1;
  if (EVP_PKEY_fromdata_init(ctx) <= 0) ok = 0;
  if (ok && EVP_PKEY_fromdata(ctx, &pkey, bn_x ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) <= 0) ok = 0;
  EVP_PKEY_CTX_free(ctx);
  BN_free(bn_p); BN_free(bn_q); BN_free(bn_g); BN_free(bn_y);
  if (bn_x) BN_free(bn_x);
  if (ok) return pkey;
  if (pkey) EVP_PKEY_free(pkey);
  return 0;
}

/* Decode a single OpenSSH-format private key blob (the plaintext form
 * stored inside openssh-key-v1). Produces an EVP_PKEY. */
static EVP_PKEY *openssh_decode_plain(const unsigned char *enc, int enc_len) {
  int pos = 0;
  uint32_t check1 = 0, check2 = 0;
  if (!read_u32(enc, enc_len, &pos, &check1)) return 0;
  if (!read_u32(enc, enc_len, &pos, &check2)) return 0;
  if (check1 != check2) return 0;
  /* keytype string */
  char keytype[64];
  int ktype_len = 0;
  if (!read_ssh_string(enc, enc_len, &pos, (unsigned char *)keytype,
                       sizeof(keytype) - 1, &ktype_len)) return 0;
  keytype[ktype_len] = '\0';
  if (strcmp(keytype, "ssh-ed25519") == 0) {
    /* pub (32), priv (64 = 32 pub + 32 seed), comment */
    unsigned char pub32[32];
    unsigned char priv64[64];
    int pub_len = 0, priv_len = 0;
    if (!read_ssh_string(enc, enc_len, &pos, pub32, sizeof(pub32), &pub_len))
      return 0;
    if (pub_len != 32) return 0;
    if (!read_ssh_string(enc, enc_len, &pos, priv64, sizeof(priv64), &priv_len))
      return 0;
    if (priv_len != 64) return 0;
    /* OpenSSH ed25519 stores private as seed (32) || public_key (32).
     * The last 32 bytes of the 64-byte blob must equal the public key. */
    if (memcmp(priv64 + 32, pub32, 32) != 0) return 0;
    return build_ed25519_pkey(pub32, priv64);
  } else if (strcmp(keytype, "ssh-rsa") == 0) {
    /* n, e, d, iqmp, p, q, comment */
    unsigned char *n = 0, *e = 0, *d = 0, *iqmp = 0, *p = 0, *q = 0;
    int n_len = 0, e_len = 0, d_len = 0, iqmp_len = 0, p_len = 0, q_len = 0;
    const unsigned char *p_view = 0;
    int vlen = 0;
    if (!read_ssh_string_peek(enc, enc_len, &pos, &p_view, &vlen)) return 0;
    n = (unsigned char *)malloc((size_t)vlen);
    memcpy(n, p_view, (size_t)vlen);
    n_len = vlen;
    if (!read_ssh_string_peek(enc, enc_len, &pos, &p_view, &vlen)) {
      free(n); return 0;
    }
    e = (unsigned char *)malloc((size_t)vlen);
    memcpy(e, p_view, (size_t)vlen);
    e_len = vlen;
    if (!read_ssh_string_peek(enc, enc_len, &pos, &p_view, &vlen)) {
      free(n); free(e); return 0;
    }
    d = (unsigned char *)malloc((size_t)vlen);
    memcpy(d, p_view, (size_t)vlen);
    d_len = vlen;
    if (!read_ssh_string_peek(enc, enc_len, &pos, &p_view, &vlen)) {
      free(n); free(e); free(d); return 0;
    }
    iqmp = (unsigned char *)malloc((size_t)vlen);
    memcpy(iqmp, p_view, (size_t)vlen);
    iqmp_len = vlen;
    if (!read_ssh_string_peek(enc, enc_len, &pos, &p_view, &vlen)) {
      free(n); free(e); free(d); free(iqmp); return 0;
    }
    p = (unsigned char *)malloc((size_t)vlen);
    memcpy(p, p_view, (size_t)vlen);
    p_len = vlen;
    if (!read_ssh_string_peek(enc, enc_len, &pos, &p_view, &vlen)) {
      free(n); free(e); free(d); free(iqmp); free(p); return 0;
    }
    q = (unsigned char *)malloc((size_t)vlen);
    memcpy(q, p_view, (size_t)vlen);
    q_len = vlen;
    /* comment (string) — we don't need it */
    if (!read_ssh_string_peek(enc, enc_len, &pos, &p_view, &vlen)) {
      free(n); free(e); free(d); free(iqmp); free(p); free(q); return 0;
    }
    EVP_PKEY *pkey = build_rsa_pkey(n, n_len, e, e_len, d, d_len);
    free(n); free(e); free(d); free(iqmp); free(p); free(q);
    return pkey;
  } else if (strncmp(keytype, "ecdsa-sha2-nistp", 16) == 0) {
    /* ECDSA: curve_id(string) + pubkey(string) + privkey(string) + comment(string) */
    char curve_id[32];
    int curve_len = 0;
    if (!read_ssh_string(enc, enc_len, &pos, (unsigned char *)curve_id,
                         sizeof(curve_id) - 1, &curve_len)) return 0;
    curve_id[curve_len] = '\0';
    const char *group = ssh_curve_to_openssl_group(curve_id);
    if (!group) return 0;
    int expected_pub_len = ssh_curve_point_size(curve_id);
    if (expected_pub_len == 0) return 0;
    unsigned char pub[133]; /* max P-521 */
    int pub_len = 0;
    if (!read_ssh_string(enc, enc_len, &pos, pub, sizeof(pub), &pub_len)) return 0;
    if (pub_len != expected_pub_len) return 0;
    unsigned char priv[66]; /* max P-521 */
    int priv_len = 0;
    if (!read_ssh_string(enc, enc_len, &pos, priv, sizeof(priv), &priv_len)) return 0;
    /* comment */
    if (!read_ssh_string_peek(enc, enc_len, &pos, 0, 0)) return 0;
    return build_ecdsa_pkey(group, pub, pub_len, priv, priv_len);
  } else if (strcmp(keytype, "ssh-dss") == 0) {
    /* DSA: p + q + g + y + x + comment */
    const unsigned char *v;
    int vlen;
    unsigned char *dp = 0, *dq = 0, *dg = 0, *dy = 0, *dx = 0;
    int dp_len = 0, dq_len = 0, dg_len = 0, dy_len = 0, dx_len = 0;
    #define READ_DSA_PARAM(buf, len) do { \
      if (!read_ssh_string_peek(enc, enc_len, &pos, &v, &vlen)) { \
        free(dp); free(dq); free(dg); free(dy); return 0; \
      } \
      buf = (unsigned char *)malloc((size_t)vlen); \
      memcpy(buf, v, (size_t)vlen); \
      len = vlen; \
    } while(0)
    READ_DSA_PARAM(dp, dp_len);
    READ_DSA_PARAM(dq, dq_len);
    READ_DSA_PARAM(dg, dg_len);
    READ_DSA_PARAM(dy, dy_len);
    READ_DSA_PARAM(dx, dx_len);
    #undef READ_DSA_PARAM
    /* comment */
    if (!read_ssh_string_peek(enc, enc_len, &pos, 0, 0)) {
      free(dp); free(dq); free(dg); free(dy); free(dx); return 0;
    }
    EVP_PKEY *pkey = build_dsa_pkey(dp, dp_len, dq, dq_len, dg, dg_len, dy, dy_len, dx, dx_len);
    free(dp); free(dq); free(dg); free(dy); free(dx);
    return pkey;
  }
  return 0;
}

int moonbitlang_ssh_load_openssh_private_key(const unsigned char *enc,
                                              int enc_len, void **out) {
  if (!enc || enc_len < 15) { *out = 0; return 0; }
  if (memcmp(enc, "openssh-key-v1", 14) != 0) { *out = 0; return 0; }
  int pos = 15; /* skip magic + NUL */
  /* ciphername, kdfname, kdfoptions (3 strings) */
  if (!read_ssh_string_peek(enc, enc_len, &pos, 0, 0)) { *out = 0; return 0; }
  if (!read_ssh_string_peek(enc, enc_len, &pos, 0, 0)) { *out = 0; return 0; }
  if (!read_ssh_string_peek(enc, enc_len, &pos, 0, 0)) { *out = 0; return 0; }
  /* number of keys (uint32) */
  uint32_t nkeys = 0;
  if (!read_u32(enc, enc_len, &pos, &nkeys)) { *out = 0; return 0; }
  if (nkeys < 1) { *out = 0; return 0; }
  /* public key blob (one per key) — skip them */
  for (uint32_t i = 0; i < nkeys; i++) {
    if (!read_ssh_string_peek(enc, enc_len, &pos, 0, 0)) { *out = 0; return 0; }
  }
  /* encrypted private data */
  const unsigned char *priv = 0;
  int priv_len = 0;
  if (!read_ssh_string_peek(enc, enc_len, &pos, &priv, &priv_len)) {
    *out = 0; return 0;
  }
  /* We only support unencrypted (cipher=none, kdf=none) keys. The caller
   * is responsible for not invoking us on a passphrase-protected key. */
  EVP_PKEY *pkey = openssh_decode_plain(priv, priv_len);
  if (!pkey) { *out = 0; return 0; }
  *out = pkey;
  return 1;
}

/* Read the entire file into a heap-allocated buffer. Caller frees. */
static int read_whole_file(const char *path, unsigned char **out_buf,
                           int *out_len) {
  FILE *f = fopen(path, "rb");
  if (!f) return 0;
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
  long sz = ftell(f);
  if (sz < 0) { fclose(f); return 0; }
  if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 0; }
  unsigned char *buf = (unsigned char *)malloc((size_t)sz);
  if (!buf) { fclose(f); return 0; }
  size_t got = fread(buf, 1, (size_t)sz, f);
  fclose(f);
  if ((long)got != sz) { free(buf); return 0; }
  *out_buf = buf;
  *out_len = (int)sz;
  return 1;
}

int moonbitlang_ssh_load_private_key(const char *path_bytes, int path_len,
                                     void **out) {
  char path[4096];
  if (!copy_path_to_cstr(path_bytes, path_len, path, sizeof(path))) return 0;
  unsigned char *raw = 0;
  int raw_len = 0;
  if (!read_whole_file(path, &raw, &raw_len)) return 0;
  /* Detect format by the PEM/OpenSSH armor header. */
  int is_openssh = 0;
  int is_pem = 0;
  /* We scan up to 200 bytes of header for the BEGIN line. */
  int scan_len = raw_len < 200 ? raw_len : 200;
  for (int i = 0; i + 32 < scan_len; i++) {
    if (memcmp(raw + i, "-----BEGIN OPENSSH PRIVATE KEY-----", 35) == 0) {
      is_openssh = 1;
      break;
    }
    if (memcmp(raw + i, "-----BEGIN ", 11) == 0) {
      is_pem = 1;
      break;
    }
  }
  int rc = 0;
  if (is_openssh) {
    /* Collect base64 payload between BEGIN/END markers. */
    unsigned char *b64 = (unsigned char *)malloc((size_t)raw_len);
    if (!b64) { free(raw); return 0; }
    int b64_len = 0;
    int state = 0; /* 0=before BEGIN, 1=inside, 2=after END */
    for (int i = 0; i < raw_len; i++) {
      if (state == 0) {
        if (memcmp(raw + i, "-----BEGIN OPENSSH PRIVATE KEY-----", 35) == 0) {
          state = 1;
          /* advance past the BEGIN line */
          while (i < raw_len && raw[i] != '\n') i++;
        }
      } else if (state == 1) {
        if (memcmp(raw + i, "-----END OPENSSH PRIVATE KEY-----", 32) == 0) {
          state = 2;
        } else {
          b64[b64_len++] = raw[i];
        }
      }
    }
    unsigned char *decoded = (unsigned char *)malloc((size_t)b64_len);
    if (!decoded) { free(b64); free(raw); return 0; }
    int decoded_len = 0;
    if (!moonbitlang_ssh_base64_decode((const char *)b64, b64_len,
                                       decoded, &decoded_len)) {
      free(b64); free(decoded); free(raw); return 0;
    }
    free(b64);
    rc = moonbitlang_ssh_load_openssh_private_key(decoded, decoded_len, out);
    free(decoded);
  } else if (is_pem) {
    /* Hand the raw PEM text to OpenSSL via a memory BIO. */
    BIO *bio = BIO_new_mem_buf(raw, raw_len);
    if (bio) {
      EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, 0, 0, 0);
      BIO_free(bio);
      if (pkey) { *out = pkey; rc = 1; }
    }
  }
  free(raw);
  return rc;
}

/* ------------------------------------------------------------------ */
/* OpenSSH .pub file reader                                            */
/*                                                                      */
/* Parses the single-line OpenSSH public key file:                     */
/*   <algorithm> <base64-blob> <comment>                                */
/* where the base64-blob is the SSH wire-format pubkey (i.e. exactly   */
/* the same bytes that go into SSH_MSG_USERAUTH_REQUEST for "publickey").*/
/*                                                                      */
/* On success returns 1 and writes:                                     */
/*   - alg_buf: the algorithm name (e.g. "ssh-ed25519", "ssh-rsa")      */
/*   - alg_len: length of alg_buf                                       */
/*   - blob: the SSH wire-format pubkey blob                           */
/*   - blob_len: length of blob                                         */
/* ------------------------------------------------------------------ */
int moonbitlang_ssh_read_openssh_pubkey(const char *path_bytes, int path_len,
                                        char *alg_buf, int alg_cap, int *alg_len,
                                        unsigned char *blob, int blob_cap,
                                        int *blob_len) {
  char path[4096];
  if (!copy_path_to_cstr(path_bytes, path_len, path, sizeof(path))) return 0;
  unsigned char *raw = 0;
  int raw_len = 0;
  if (!read_whole_file(path, &raw, &raw_len)) return 0;
  /* Find the first whitespace-separated token. */
  int tok_start = 0;
  while (tok_start < raw_len && (raw[tok_start] == ' ' || raw[tok_start] == '\t'))
    tok_start++;
  int tok_end = tok_start;
  while (tok_end < raw_len && raw[tok_end] != ' ' && raw[tok_end] != '\t' &&
         raw[tok_end] != '\n' && raw[tok_end] != '\r')
    tok_end++;
  if (tok_end == tok_start) { free(raw); return 0; }
  int alg_name_len = tok_end - tok_start;
  if (alg_name_len + 1 > alg_cap) { free(raw); return 0; }
  memcpy(alg_buf, raw + tok_start, (size_t)alg_name_len);
  alg_buf[alg_name_len] = '\0';
  if (alg_len) *alg_len = alg_name_len;
  /* Find the second token: the base64 blob. */
  int b64_start = tok_end;
  while (b64_start < raw_len && (raw[b64_start] == ' ' || raw[b64_start] == '\t'))
    b64_start++;
  int b64_end = b64_start;
  while (b64_end < raw_len && raw[b64_end] != ' ' && raw[b64_end] != '\t' &&
         raw[b64_end] != '\n' && raw[b64_end] != '\r')
    b64_end++;
  if (b64_end == b64_start) { free(raw); return 0; }
  int b64_len = b64_end - b64_start;
  if (blob_cap < b64_len) { free(raw); return 0; }
  int out_len = blob_cap;
  if (!moonbitlang_ssh_base64_decode((const char *)(raw + b64_start),
                                     b64_len, blob, &out_len)) {
    free(raw);
    return 0;
  }
  if (blob_len) *blob_len = out_len;
  free(raw);
  return 1;
}

/* ------------------------------------------------------------------ */
/* EC curve NID detection                                             */
/* ------------------------------------------------------------------ */

/* Returns the EC curve NID from an EVP_PKEY:
 *   415 -> prime256v1 (P-256)
 *   715 -> secp384r1  (P-384)
 *   716 -> secp521r1  (P-521)
 * Returns 0 for non-EC keys or on failure. */
int moonbitlang_ssh_pkey_ec_curve_nid(void *pkey) {
  if (!pkey) return 0;
  if (EVP_PKEY_get_id((const EVP_PKEY *)pkey) != 408) return 0;
  char group_name[64];
  size_t group_len = 0;
  if (!EVP_PKEY_get_utf8_string_param((const EVP_PKEY *)pkey, "group",
                                       group_name, sizeof(group_name), &group_len))
    return 0;
  group_name[group_len] = '\0';
  if (strcmp(group_name, "prime256v1") == 0) return 415;
  if (strcmp(group_name, "secp384r1") == 0) return 715;
  if (strcmp(group_name, "secp521r1") == 0) return 716;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Build EC public key from curve name + raw point                    */
/* ------------------------------------------------------------------ */
int moonbitlang_ssh_pkey_from_ec_point(
    const char *curve, int curve_len,
    const unsigned char *point, int point_len,
    void **out) {
  /* curve is SSH curve name like "nistp256" */
  char curve_buf[32];
  if (curve_len < 0 || curve_len >= (int)sizeof(curve_buf)) return 0;
  memcpy(curve_buf, curve, (size_t)curve_len);
  curve_buf[curve_len] = '\0';
  const char *group = ssh_curve_to_openssl_group(curve_buf);
  if (!group) return 0;
  EVP_PKEY *pkey = build_ecdsa_pkey(group, point, point_len, 0, 0);
  if (!pkey) return 0;
  *out = pkey;
  return 1;
}

/* ------------------------------------------------------------------ */
/* Build DSA public key from raw components                           */
/* ------------------------------------------------------------------ */
int moonbitlang_ssh_pkey_from_dsa_components(
    const unsigned char *p, int p_len,
    const unsigned char *q, int q_len,
    const unsigned char *g, int g_len,
    const unsigned char *y, int y_len,
    void **out) {
  EVP_PKEY *pkey = build_dsa_pkey(p, p_len, q, q_len, g, g_len, y, y_len, 0, 0);
  if (!pkey) return 0;
  *out = pkey;
  return 1;
}

/* ------------------------------------------------------------------ */
/* Generic verify (dispatches by key type)                            */
/*   Returns 1 if valid, 0 if invalid, -1 on error.                  */
/* ------------------------------------------------------------------ */
int moonbitlang_ssh_pkey_verify(void *pkey, int md_alg_id,
                                const unsigned char *tbs, int tbs_len,
                                const unsigned char *sig, int sig_len) {
  if (!pkey) return -1;
  int key_type = EVP_PKEY_get_id((EVP_PKEY *)pkey);

  if (key_type == 6) {
    /* RSA: use verify_recover approach (existing) */
    unsigned char hash_buf[64];
    unsigned int hash_len = 0;
    const EVP_MD *md = md_by_id(md_alg_id);
    if (!md) return -1;
    if (!EVP_Digest(tbs, (size_t)tbs_len, hash_buf, &hash_len, md, NULL)) return -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY *)pkey, 0);
    if (!ctx) return -1;
    unsigned char recovered[512];
    size_t recovered_len = sizeof(recovered);
    int ok = 1;
    if (EVP_PKEY_verify_recover_init(ctx) <= 0) ok = -1;
    if (ok == 1 && EVP_PKEY_verify_recover(ctx, recovered, &recovered_len,
                                           sig, (size_t)sig_len) <= 0) ok = -1;
    EVP_PKEY_CTX_free(ctx);
    if (ok < 0) return 0;
    if (recovered_len < (size_t)(hash_len + 8)) return 0;
    const unsigned char *extracted = recovered + (recovered_len - hash_len);
    return memcmp(extracted, hash_buf, (size_t)hash_len) == 0 ? 1 : 0;
  }

  if (key_type == 408) {
    /* ECDSA: convert raw r||s to DER, then EVP_DigestVerify */
    const EVP_MD *md = md_by_id(md_alg_id);
    if (!md) return -1;
    /* Determine key size from curve NID */
    int nid = moonbitlang_ssh_pkey_ec_curve_nid(pkey);
    int key_size = 0;
    switch (nid) {
      case 415: key_size = 32; break;
      case 715: key_size = 48; break;
      case 716: key_size = 66; break;
      default: return -1;
    }
    if (sig_len != key_size * 2) return -1;
    /* Convert raw→DER */
    unsigned char der_sig[256];
    int der_len = ecdsa_raw_to_der(sig, sig_len, der_sig, sizeof(der_sig));
    if (der_len <= 0) return -1;
    /* Verify */
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return -1;
    int rc = EVP_DigestVerifyInit(mctx, 0, md, 0, (EVP_PKEY *)pkey);
    if (rc == 1) rc = EVP_DigestVerify(mctx, der_sig, (size_t)der_len, tbs, (size_t)tbs_len);
    EVP_MD_CTX_free(mctx);
    return rc == 1 ? 1 : 0;
  }

  if (key_type == 116) {
    /* DSA: EVP_DigestVerify with SHA-1 */
    const EVP_MD *md = md_by_id(md_alg_id);
    if (!md) md = EVP_sha1();
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) return -1;
    int rc = EVP_DigestVerifyInit(mctx, 0, md, 0, (EVP_PKEY *)pkey);
    if (rc == 1) rc = EVP_DigestVerify(mctx, sig, (size_t)sig_len, tbs, (size_t)tbs_len);
    EVP_MD_CTX_free(mctx);
    return rc == 1 ? 1 : 0;
  }

  return -1;
}
