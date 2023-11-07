export SSID := "Dummy"
export PASSWORD := "Dummy"

all: (check "xtensa-esp32-none-elf" "esp32" "esp") (check "xtensa-esp32s3-none-elf" "esp32s3" "esp") (check "riscv32imc-unknown-none-elf" "esp32c3" "nightly")
    cd esp-mbedtls && cargo +nightly fmt --all -- --check
    
[private]
check target arch toolchain:
    cargo +{{ toolchain }} build --target {{ target }} --example sync_client --features {{ arch }}
    cargo +{{ toolchain }} build --target {{ target }} --example sync_client_mTLS --features {{ arch }}
    cargo +{{ toolchain }} build --target {{ target }} --example async_client --features="async {{ arch }}"
    cargo +{{ toolchain }} build --target {{ target }} --example async_client_mTLS --features="async {{ arch }}"
    cargo +{{ toolchain }} build --target {{ target }} --example sync_server --features {{ arch }}
    cargo +{{ toolchain }} build --target {{ target }} --example sync_server_mTLS --features {{ arch }}
    cargo +{{ toolchain }} build --target {{ target }} --example async_server --features="async {{ arch }}"
    cargo +{{ toolchain }} build --target {{ target }} --example async_server_mTLS --features="async {{ arch }}"
    cargo +{{ toolchain }} fmt --all -- --check
