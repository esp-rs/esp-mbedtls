typedef struct mbedtls_sha256_context {
  void* sha224_hasher;
  void* sha256_hasher;
  int   is224;
} mbedtls_sha256_context;
