typedef struct mbedtls_sha512_context {
  void* sha384_hasher;
  void* sha512_hasher;
  int   is384;
} mbedtls_sha512_context;
