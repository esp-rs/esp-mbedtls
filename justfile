export SSID := "Dummy"
export PASSWORD := "Dummy"

all: (check "esp32" "esp") (check "esp32s3" "esp") (check "esp32c3" "nightly-2024-07-22")
    cd esp-mbedtls && cargo +nightly-2024-07-22 fmt --all -- --check
    
[private]
check arch toolchain:
    cargo +{{ toolchain }} b{{ arch }} --example sync_client --features="examples"
    cargo +{{ toolchain }} b{{ arch }} --example sync_client_mTLS --features="examples"
    cargo +{{ toolchain }} b{{ arch }} --example async_client --features="examples-async"
    cargo +{{ toolchain }} b{{ arch }} --example async_client_mTLS --features="examples-async"
    cargo +{{ toolchain }} b{{ arch }} --example sync_server --features="examples"
    cargo +{{ toolchain }} b{{ arch }} --example sync_server_mTLS --features="examples"
    cargo +{{ toolchain }} b{{ arch }} --example async_server --features="examples-async"
    cargo +{{ toolchain }} b{{ arch }} --example async_server_mTLS --features="examples-async"
    cargo +{{ toolchain }} b{{ arch }} --example edge_server --features="examples-async"
    cargo +{{ toolchain }} b{{ arch }} --example crypto_self_test --features="examples"
    cargo +{{ toolchain }} b --example crypto_self_test_std --features="examples-std" --target x86_64-unknown-linux-gnu -Z build-std=std,panic_abort
    cargo +{{ toolchain }} b --example crypto_self_test_std --features="examples-std" --target xtensa-esp32-espidf -Z build-std=std,panic_abort
    cargo +{{ toolchain }} fmt --all -- --check
