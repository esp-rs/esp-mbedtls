typedef struct mbedtls_sha256_context {
    unsigned char work_area[MBEDTLS_SHA256_ALT_WORK_AREA_SIZE];
    unsigned char is224;
} mbedtls_sha256_context;
