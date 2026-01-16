typedef struct mbedtls_sha512_context {
    unsigned char work_area[MBEDTLS_SHA512_ALT_WORK_AREA_SIZE];
    unsigned char is384;
} mbedtls_sha512_context;
