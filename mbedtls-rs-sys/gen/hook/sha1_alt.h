#include <stdint.h>

// `aligned(16)` is REQUIRED so that compiler-managed relocation (Rust moves,
// C struct assignment) lands contexts at uniformly aligned addresses, keeping
// the runtime-emplaced hook state at a stable offset — while the Rust hooks
// must still tolerate under-aligned opaque storage and therefore never form
// references to the whole struct. See `sha256_alt.h` for the full rationale.
typedef struct mbedtls_sha1_context {
    __attribute__((aligned(16))) unsigned char work_area[MBEDTLS_SHA1_ALT_WORK_AREA_SIZE];
} mbedtls_sha1_context;
