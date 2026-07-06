#include <stdint.h>

// NOTE: deliberately NO alignment attribute on `work_area` — callers place
// contexts in opaque, minimally-aligned storage (8-aligned or less), where a
// stronger declared alignment is UB once the Rust hook forms a reference to
// the context. The Rust `WorkArea` helpers align the emplaced state at
// runtime within the work-area slack instead. See `sha256_alt.h` for the
// full rationale.
typedef struct mbedtls_sha1_context {
    unsigned char work_area[MBEDTLS_SHA1_ALT_WORK_AREA_SIZE];
} mbedtls_sha1_context;
