set(CMAKE_SYSTEM_NAME Generic)

# Install with `espup install --extended-llvm`
set(CMAKE_C_COMPILER "$ENV{CLANG_PATH}")

set(CMAKE_AR llvm-ar)
set(CMAKE_RANLIB llvm-ranlib)
set(CMAKE_OBJDUMP xtensa-esp32-elf-objdump)

set(CMAKE_C_FLAGS "--target=xtensa-esp-elf -mcpu=esp32"
  CACHE STRING "C Compiler Base Flags"
  FORCE)

set(CMAKE_CXX_FLAGS "--target=xtensa-esp-elf -mcpu=esp32 "
  CACHE STRING "C++ Compiler Base Flags"
  FORCE)

set(CMAKE_ASM_FLAGS "--target=xtensa-esp-elf -mcpu=esp32 -Xassembler --longcalls"
  CACHE STRING "Assembler Base Flags"
  FORCE)
