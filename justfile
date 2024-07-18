export SSID := "Dummy"
export PASSWORD := "Dummy"

all: (check "esp32" "esp") (check "esp32s3" "esp") (check "esp32c3" "nightly-2024-06-12")
    cd esp-mbedtls && cargo +nightly-2024-06-12 fmt --all -- --check
    
[private]
check arch toolchain:
    cargo +{{ toolchain }} b{{ arch }} --release --example sync_client
    cargo +{{ toolchain }} b{{ arch }} --release --example sync_client_mTLS
    cargo +{{ toolchain }} b{{ arch }} --release --example async_client --features="async,esp-hal-embassy"
    cargo +{{ toolchain }} b{{ arch }} --release --example async_client_mTLS --features="async,esp-hal-embassy"
    cargo +{{ toolchain }} b{{ arch }} --release --example sync_server
    cargo +{{ toolchain }} b{{ arch }} --release --example sync_server_mTLS
    cargo +{{ toolchain }} b{{ arch }} --release --example async_server --features="async,esp-hal-embassy"
    cargo +{{ toolchain }} b{{ arch }} --release --example async_server_mTLS --features="async,esp-hal-embassy"
    cargo +{{ toolchain }} fmt --all -- --check
