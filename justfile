export SSID := "Dummy"
export PASSWORD := "Dummy"

all: (check "esp32" "esp") (check "esp32s3" "esp") (check "esp32c3" "nightly-2024-07-22")
    cd esp-mbedtls && cargo +nightly-2024-07-22 fmt --all -- --check
    
[private]
check arch toolchain:
    cargo +{{ toolchain }} b{{ arch }} --example sync_client
    cargo +{{ toolchain }} b{{ arch }} --example sync_client_mTLS
    cargo +{{ toolchain }} b{{ arch }} --example async_client --features="async,esp-hal-embassy"
    cargo +{{ toolchain }} b{{ arch }} --example async_client_mTLS --features="async,esp-hal-embassy"
    cargo +{{ toolchain }} b{{ arch }} --example sync_server
    cargo +{{ toolchain }} b{{ arch }} --example sync_server_mTLS
    cargo +{{ toolchain }} b{{ arch }} --example async_server --features="async,esp-hal-embassy"
    cargo +{{ toolchain }} b{{ arch }} --example async_server_mTLS --features="async,esp-hal-embassy"
    cargo +{{ toolchain }} b{{ arch }} --example edge_server --features="async,esp-hal-embassy,edge-nal-embassy,edge-http,esp-mbedtls/edge-nal"
    cargo +{{ toolchain }} fmt --all -- --check
