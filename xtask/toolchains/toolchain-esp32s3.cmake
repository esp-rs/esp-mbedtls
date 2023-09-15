set(CMAKE_SYSTEM_NAME Generic)

set(CMAKE_C_COMPILER xtensa-esp32s3-elf-gcc)
set(CMAKE_CXX_COMPILER xtensa-esp32s3-elf-g++)
set(CMAKE_ASM_COMPILER xtensa-esp32s3-elf-gcc)

set(CMAKE_C_FLAGS "-mlongcalls" CACHE STRING "C Compiler Base Flags" FORCE)
set(CMAKE_CXX_FLAGS "-mlongcalls" CACHE STRING "C++ Compiler Base Flags" FORCE)
