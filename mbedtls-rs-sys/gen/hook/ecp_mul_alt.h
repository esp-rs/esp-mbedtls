// Declaration of the alternative ECP scalar multiplication expected by the
// Espressif MbedTLS fork when MBEDTLS_ECP_MUL_ALT_SOFT_FALLBACK is defined:
// `library/ecp.c` renames its built-in implementation to
// `ecp_mul_restartable_internal_soft` but keeps calling
// `ecp_mul_restartable_internal`, whose declaration (and implementation - in
// Rust, see `src/hook/ecp.rs`) must be provided externally.
//
// This header is injected through the generated MbedTLS user config, which is
// processed before any MbedTLS type is declared - hence the struct tags
// (`mbedtls_ecp_group` et al. are typedefs of identically-named struct tags)
// and `void *` for the restart context (`mbedtls_ecp_restart_ctx` is a `void`
// typedef in non-restartable builds, which is the only configuration this
// crate builds).

#include <stddef.h>

struct mbedtls_ecp_group;
struct mbedtls_ecp_point;
struct mbedtls_mpi;

int ecp_mul_restartable_internal(struct mbedtls_ecp_group *grp,
                                 struct mbedtls_ecp_point *R,
                                 const struct mbedtls_mpi *m,
                                 const struct mbedtls_ecp_point *P,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 void *rs_ctx);
