export SSID := "Dummy"
export PASSWORD := "Dummy"

all: (check "esp32" "esp") (check "esp32s3" "esp") (check "esp32c3" "nightly")
    cargo +nightly b --example crypto_self_test_std --features="examples-std" --target x86_64-unknown-linux-gnu -Z build-std=std,panic_abort
    cd esp-mbedtls && cargo +nightly fmt --all -- --check
    
[private]
check arch toolchain:
    cargo +{{ toolchain }} b{{ arch }} --example sync_client --features="examples"
    cargo +{{ toolchain }} b{{ arch }} --example sync_client --features="examples, mtls"
    cargo +{{ toolchain }} b{{ arch }} --example async_client --features="examples-async"
    cargo +{{ toolchain }} b{{ arch }} --example async_client --features="examples-async, mtls"
    cargo +{{ toolchain }} b{{ arch }} --example sync_server --features="examples"
    cargo +{{ toolchain }} b{{ arch }} --example sync_server --features="examples, mtls"
    cargo +{{ toolchain }} b{{ arch }} --example async_server --features="examples-async"
    cargo +{{ toolchain }} b{{ arch }} --example async_server --features="examples-async, mtls"
    cargo +{{ toolchain }} b{{ arch }} --example edge_server --features="examples-async"
    cargo +{{ toolchain }} b{{ arch }} --example crypto_self_test --features="examples"
    cargo +{{ toolchain }} fmt --all -- --check
