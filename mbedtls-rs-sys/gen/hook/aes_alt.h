#include <stdint.h>

// NOTE: deliberately NO alignment attribute on `work_area` — callers place
// contexts in opaque, minimally-aligned storage (e.g. OpenThread's AesEcb
// context storage is only 8-aligned), where a stronger declared alignment is
// UB once the Rust hook forms a reference to the context. The Rust `WorkArea`
// helpers align the emplaced state at runtime within the work-area slack
// instead (the size assert in `src/hook/aes.rs` budgets +16 for exactly
// this). See `sha256_alt.h` for the full rationale.
typedef struct mbedtls_aes_context {
    unsigned char work_area[MBEDTLS_AES_ALT_WORK_AREA_SIZE];
} mbedtls_aes_context;

#if defined(MBEDTLS_CIPHER_MODE_XTS)
typedef struct mbedtls_aes_xts_context {
    mbedtls_aes_context crypt;
    mbedtls_aes_context tweak;
} mbedtls_aes_xts_context;
#endif
