#ifndef __INTTYPES_H__
#define __INTTYPES_H__

#include <stdint.h>

/* Printf format macros for fixed-width integer types */
/* Using clang's built-in format string macros for portability */

/* 64-bit integers */
#define PRId64   __INT64_FMTd__
#define PRIi64   __INT64_FMTi__
#define PRIu64   __UINT64_FMTu__
#define PRIo64   __UINT64_FMTo__
#define PRIx64   __UINT64_FMTx__
#define PRIX64   __UINT64_FMTX__

/* Pointer-sized integers */
#define PRIdPTR  __INTPTR_FMTd__
#define PRIiPTR  __INTPTR_FMTi__
#define PRIuPTR  __UINTPTR_FMTu__
#define PRIoPTR  __UINTPTR_FMTo__
#define PRIxPTR  __UINTPTR_FMTx__
#define PRIXPTR  __UINTPTR_FMTX__

/* Scan format macros */
#define SCNd64   PRId64
#define SCNi64   PRIi64
#define SCNu64   PRIu64
#define SCNo64   PRIo64
#define SCNx64   PRIx64

#define SCNdPTR  PRIdPTR
#define SCNiPTR  PRIiPTR
#define SCNuPTR  PRIuPTR
#define SCNoPTR  PRIoPTR
#define SCNxPTR  PRIxPTR

#endif
