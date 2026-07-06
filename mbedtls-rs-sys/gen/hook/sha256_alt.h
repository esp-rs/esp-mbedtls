#include <stdint.h>

// NOTE: deliberately NO alignment attribute on `work_area`. Callers routinely
// place contexts in opaque, minimally-aligned storage the C compiler never
// sees as this struct type — e.g. OpenThread's
// `OT_DEFINE_ALIGNED_VAR(..., uint64_t)` crypto-context storage is only
// 8-aligned, and some heaps return 4-aligned memory. Declaring an alignment
// stronger than what every such caller guarantees is undefined behavior the
// moment the Rust hook forms a reference to the context (Rust validates the
// *declared* alignment). Instead, the Rust `WorkArea` helpers align the
// emplaced state at *runtime* within the work area; the `*_WORK_AREA_SIZE`
// values include slack for that (see `Hook::work_area_size` in
// `gen/builder.rs`).
typedef struct mbedtls_sha256_context {
    unsigned char work_area[MBEDTLS_SHA256_ALT_WORK_AREA_SIZE];
    unsigned char is224;
} mbedtls_sha256_context;
