#define MBEDTLS_CONFIG_FILE "config.h"

#include MBEDTLS_CONFIG_FILE

#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/entropy.h"
#include "mbedtls/debug.h"
#include "mbedtls/ctr_drbg.h"
#include "psa/crypto_values.h"

// Provides a function prototype to generate bindings for mbedtls_mpi_exp_mod_soft()
#if defined(MBEDTLS_MPI_EXP_MOD_ALT_FALLBACK)
  int mbedtls_mpi_exp_mod_soft(mbedtls_mpi *X, const mbedtls_mpi *A,
      const mbedtls_mpi *E, const mbedtls_mpi *N,
      mbedtls_mpi *prec_RR);
#endif
