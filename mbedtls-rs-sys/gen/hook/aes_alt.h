#include <stdint.h>

// `aligned(16)` is REQUIRED so that compiler-managed relocation (Rust moves,
// C struct assignment) lands contexts at uniformly aligned addresses, keeping
// the runtime-emplaced hook state at a stable offset — while the Rust hooks
// must still tolerate under-aligned opaque storage (e.g. OpenThread's
// 8-aligned `AesEcb` context storage) and therefore never form references to
// the whole struct. See `sha256_alt.h` for the full rationale.
typedef struct mbedtls_aes_context {
    __attribute__((aligned(16))) unsigned char work_area[MBEDTLS_AES_ALT_WORK_AREA_SIZE];
} mbedtls_aes_context;

#if defined(MBEDTLS_CIPHER_MODE_XTS)
typedef struct mbedtls_aes_xts_context {
    mbedtls_aes_context crypt;
    mbedtls_aes_context tweak;
} mbedtls_aes_xts_context;
#endif
