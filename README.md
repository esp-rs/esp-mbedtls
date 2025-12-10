# esp-mbedtls

This is mbedtls for ESP32 / bare-metal Rust.

It comes with mbedtls precompiled to avoid the need for a complete C toolchain. See `build_mbedtls` for how it was built.

## Status

This should work together with `esp-radio`. It currently won't work without. However it's not well tested yet besides the included examples.

In general this is heavy in terms of heap memory used and code size. If you can, you should prefer using something like `embedded-tls`.

For now it's missing advanced configuration options which will be added step-by-step.

The examples use one hard-coded address of `www.google.com` which might not always work.

### Certificates

These examples use certificates that expire after a given time.

The script `genssl.sh` is there to renew expired certificates, without having to manually update them within the code.

## Running Examples

Examples are available for:

- esp32
- esp32c3
- esp32c6
- esp32s2
- esp32s3

To run examples, you need to specify the architecture as a feature, the example name, the target and the toolchain.

You also need to set `SSID` and `PASSWORD` as your environment variables

### Examples

Xtensa:

```shell
SSID=<your_ssid> PASSWORD=<your_password> cargo +esp run --release --example sync_client -F esp32s3 --target xtensa-esp32s3-none-elf
```

RISC-V: 

```shell
SSID=<your_ssid> PASSWORD=<your_password> cargo +nightly run --release --example async_client -F esp32c3,async --target riscv32imc-unknown-none-elf
```

Here's a table of the architectures with their corresponding target for quick reference:

| Architecture | Target                      | Toolchain          |
| ------------ | --------------------------- | ------------------ |
| esp32        | xtensa-esp32-none-elf       | esp                |
| esp32c3      | riscv32imc-unknown-none-elf | nightly            |
| esp32c6      | riscv32imac-unknown-none-elf| nightly            |
| esp32s2      | xtensa-esp32s2-none-elf     | esp                |
| esp32s3      | xtensa-esp32s3-none-elf     | esp                |

Heres's a list of all the examples with their description, and the required features to enable them:

| Example                  | Features | Description                                                  |
| :----------------------- | -------- | ------------------------------------------------------------ |
| async_client             | -        | Example of a HTTPS connection using the async client.        |
| async_client (with mTLS) | mtls     | Example of a HTTPS connection using the async client, with certificate authentication. This sends client certificates to a server, and the response indicates informations about the certificates. |
| sync_client              | -        | Example of a HTTPS connection using the sync client.         |
| sync_client (with mTLS)  | mtls     | Example of a HTTPS connection using the sync client, with certificate authentication. This sends client certificates to a server, and the response indicates informations about the certificates. |
| async_server             | -        | Example of a simple async server with HTTPS support. This uses self-signed certificates, so you will need to enable an exception in your browser. |
| async_server (with mTLS) | mtls     | Example of a simple async server with HTTPS support, with client authentication. You will need to pass client certificates in your request in order to have a successful connection. Refer to the documentation inside the example. |
| sync_server              | -        | Example of a simple sync server with HTTPS support. This uses self-signed certificates, so you will need to enable an exception in your browser. |
| sync_server (with mTLS)  | mtls     | Example of a simple sync server with HTTPS support, with client authentication. You will need to pass client certificates in your request in order to have a successful connection. Refer to the documentation inside the example. |

This needs `espflash` version 2.x. If you are using version 1.x you need to remove the `flash` command from the runner in `.cargo/config.toml`

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
