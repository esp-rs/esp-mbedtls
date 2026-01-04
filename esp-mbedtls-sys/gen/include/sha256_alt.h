typedef struct mbedtls_sha256_context {
    unsigned char work_area[256];
    unsigned char is224;
} mbedtls_sha256_context;
