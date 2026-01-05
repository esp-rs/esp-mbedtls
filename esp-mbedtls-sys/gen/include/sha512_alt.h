typedef struct mbedtls_sha512_context {
    unsigned char work_area[300];
    unsigned char is384;
} mbedtls_sha512_context;
