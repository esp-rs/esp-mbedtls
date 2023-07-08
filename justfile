export SSID := "Dummy"
export PASSWORD := "Dummy"

all: (check "esp32" "esp") (check "esp32s3" "esp") (check "esp32c3" "nightly-2023-03-09")
    cd esp-mbedtls && cargo +nightly-2023-03-09 fmt --all -- --check
    
[private]
check target toolchain:
    cd examples-{{ target }} && cargo +{{ toolchain }} check --example sync_client
    cd examples-{{ target }} && cargo +{{ toolchain }} check --example sync_client_mTLS
    cd examples-{{ target }} && cargo +{{ toolchain }} check --example async_client --features=async
    cd examples-{{ target }} && cargo +{{ toolchain }} check --example async_client_mTLS --features=async
    cd examples-{{ target }} && cargo +{{ toolchain }} check --example sync_server
    cd examples-{{ target }} && cargo +{{ toolchain }} check --example sync_server_mTLS
    cd examples-{{ target }} && cargo +{{ toolchain }} check --example async_server --features=async
    cd examples-{{ target }} && cargo +{{ toolchain }} check --example async_server_mTLS --features=async
    cd examples-{{ target }} && cargo +{{ toolchain }} fmt --all -- --check
