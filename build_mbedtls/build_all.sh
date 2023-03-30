#!/bin/bash

rm -rf target
rm -rf tmpsrc
mkdir target
mkdir tmpsrc
cp -r ../mbedtls tmpsrc
cp config.h tmpsrc/mbedtls/include/mbedtls/mbedtls_config.h
cd target

cmake -DCMAKE_BUILD_TYPE=Release -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_TOOLCHAIN_FILE=$IDF_PATH/tools/cmake/toolchain-esp32c3.cmake ../tmpsrc/mbedtls
make

cp library/libmbedcrypto.a ../../libs/riscv32imc-unknown-none-elf/libmbedcrypto.a
cp library/libmbedtls.a ../../libs/riscv32imc-unknown-none-elf/libmbedtls.a
cp library/libmbedx509.a ../../libs/riscv32imc-unknown-none-elf/libmbedx509.a

cd ..

# on Xtensa varargs don't work right yet - use a no debug output build
cp config_no_debug.h tmpsrc/mbedtls/include/mbedtls/mbedtls_config.h

rm -rf target
mkdir target
cd target

cmake -DCMAKE_BUILD_TYPE=Release -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_TOOLCHAIN_FILE=$IDF_PATH/tools/cmake/toolchain-esp32.cmake ../tmpsrc/mbedtls
make

cp library/libmbedcrypto.a ../../libs/xtensa-esp32-none-elf/libmbedcrypto.a
cp library/libmbedtls.a ../../libs/xtensa-esp32-none-elf/libmbedtls.a
cp library/libmbedx509.a ../../libs/xtensa-esp32-none-elf/libmbedx509.a

cd ..
rm -rf target
mkdir target
cd target

cmake -DCMAKE_BUILD_TYPE=Release -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_TOOLCHAIN_FILE=$IDF_PATH/tools/cmake/toolchain-esp32s2.cmake ../tmpsrc/mbedtls
make

cp library/libmbedcrypto.a ../../libs/xtensa-esp32s2-none-elf/libmbedcrypto.a
cp library/libmbedtls.a ../../libs/xtensa-esp32s2-none-elf/libmbedtls.a
cp library/libmbedx509.a ../../libs/xtensa-esp32s2-none-elf/libmbedx509.a

cd ..
rm -rf target
mkdir target
cd target

cmake -DCMAKE_BUILD_TYPE=Release -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_TOOLCHAIN_FILE=$IDF_PATH/tools/cmake/toolchain-esp32s3.cmake ../tmpsrc/mbedtls
make

cp library/libmbedcrypto.a ../../libs/xtensa-esp32s3-none-elf/libmbedcrypto.a
cp library/libmbedtls.a ../../libs/xtensa-esp32s3-none-elf/libmbedtls.a
cp library/libmbedx509.a ../../libs/xtensa-esp32s3-none-elf/libmbedx509.a

cd ..
rm -rf target
rm -rf tmpsrc
