#include <stdint.h>

typedef struct mbedtls_aes_context {
   __attribute__((aligned(16))) unsigned char work_area[MBEDTLS_AES_ALT_WORK_AREA_SIZE];
} mbedtls_aes_context;

#if defined(MBEDTLS_CIPHER_MODE_XTS)
typedef struct mbedtls_aes_xts_context {
    mbedtls_aes_context crypt;
    mbedtls_aes_context tweak;
} mbedtls_aes_xts_context;
#endif
