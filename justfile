export SSID := "Dummy"
export PASSWORD := "Dummy"

all: (check "esp32" "esp") (check "esp32s3" "esp") (check "esp32c3" "nightly")
    cd esp-mbedtls && cargo fmt --all -- --check
    
[private]
check target toolchain:
    cd examples-{{ target }} && cargo +{{ toolchain }} check --example sync
    cd examples-{{ target }} && cargo +{{ toolchain }} check --example sync_client
    cd examples-{{ target }} && cargo +{{ toolchain }} check --example async --features=async
    cd examples-{{ target }} && cargo +{{ toolchain }} check --example async_client --features=async
    cd examples-{{ target }} && cargo fmt --all -- --check
