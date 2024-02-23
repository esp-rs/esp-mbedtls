set(CMAKE_SYSTEM_NAME Generic)

# Install with `espup install --extended-llvm`
set(CMAKE_C_COMPILER "$ENV{CLANG_PATH}")

set(CMAKE_AR llvm-ar)
set(CMAKE_RANLIB llvm-ranlib)
set(CMAKE_OBJDUMP riscv32-esp-elf-objdump)

set(CMAKE_C_FLAGS "--target=riscv32-esp-elf -march=rv32imc -mabi=ilp32"
  CACHE STRING "C Compiler Base Flags"
  FORCE)

set(CMAKE_CXX_FLAGS "--target=riscv32-esp-elf -march=rv32imc -mabi=ilp32"
  CACHE STRING "C++ Compiler Base Flags"
  FORCE)

set(CMAKE_ASM_FLAGS "--target=riscv32-esp-elf -march=rv32imc -mabi=ilp32 "
  CACHE STRING "Assembler Base Flags"
  FORCE)
