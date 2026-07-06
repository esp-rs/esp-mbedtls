#include <stdint.h>

// The `aligned(16)` on `work_area` is REQUIRED — but the Rust hooks must not
// rely on it. Both halves matter:
//
// - REQUIRED: the hook state is emplaced *inside* `work_area` at a
//   runtime-computed aligned offset. Contexts owned by compiler-managed
//   storage can be relocated by plain bitwise copies that no hook observes —
//   most importantly **Rust move semantics** (a context, or a struct
//   embedding one, moved between stack slots / into a `Box`), and C struct
//   assignment. After such a copy the state's stored offset is only correct
//   if the new address has the same alignment (mod 16) as the old one; the
//   declared alignment makes every compiler-chosen location uniformly
//   16-aligned (offset always 0), so bitwise relocation is safe.
//
// - NOT RELIED UPON: opaque external storage casts these contexts out of
//   plain byte buffers the C compiler never sees as this type — e.g.
//   OpenThread's `OT_DEFINE_ALIGNED_VAR(..., uint64_t)` crypto-context
//   storage is only 8-aligned. Such storage never relocates its contexts, so
//   the runtime-computed offset stays valid — but the Rust hooks must never
//   create a `&`/`&mut` to the whole context struct (that would assert the
//   declared 16-byte alignment); they use raw field projection instead (see
//   `RawWorkArea` in `src/hook.rs`), and the `*_WORK_AREA_SIZE` values keep
//   slack for the worst-case emplacement offset (see `Hook::work_area_size`
//   in `gen/builder.rs`).
typedef struct mbedtls_sha256_context {
    __attribute__((aligned(16))) unsigned char work_area[MBEDTLS_SHA256_ALT_WORK_AREA_SIZE];
    unsigned char is224;
} mbedtls_sha256_context;
