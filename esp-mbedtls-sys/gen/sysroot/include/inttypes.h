#ifndef __INTTYPES_H__
#define __INTTYPES_H__

#include <stdint.h>

/* Printf format macros for fixed-width integer types */
/* Using clang's built-in format string macros for portability */

/* 8-bit integers */
#define PRId8    __INT8_FMTd__
#define PRIi8    __INT8_FMTi__
#define PRIu8    __UINT8_FMTu__
#define PRIo8    __UINT8_FMTo__
#define PRIx8    __UINT8_FMTx__
#define PRIX8    __UINT8_FMTX__

/* 16-bit integers */
#define PRId16   __INT16_FMTd__
#define PRIi16   __INT16_FMTi__
#define PRIu16   __UINT16_FMTu__
#define PRIo16   __UINT16_FMTo__
#define PRIx16   __UINT16_FMTx__
#define PRIX16   __UINT16_FMTX__

/* 32-bit integers */
#define PRId32   __INT32_FMTd__
#define PRIi32   __INT32_FMTi__
#define PRIu32   __UINT32_FMTu__
#define PRIo32   __UINT32_FMTo__
#define PRIx32   __UINT32_FMTx__
#define PRIX32   __UINT32_FMTX__

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
#define SCNd8    PRId8
#define SCNi8    PRIi8
#define SCNu8    PRIu8
#define SCNo8    PRIo8
#define SCNx8    PRIx8

#define SCNd16   PRId16
#define SCNi16   PRIi16
#define SCNu16   PRIu16
#define SCNo16   PRIo16
#define SCNx16   PRIx16

#define SCNd32   PRId32
#define SCNi32   PRIi32
#define SCNu32   PRIu32
#define SCNo32   PRIo32
#define SCNx32   PRIx32

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