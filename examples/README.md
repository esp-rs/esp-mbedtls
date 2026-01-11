# `esp-mbedtls` Examples

The examples currently run on the following platforms:

## STD

Check folder [std](std).

Building:
```
cd examples/std
cargo build
```

## Baremetal ESP32-XX with `esp-hal` and `embassy-net`

Check folder [esp](esp).

Building:
```
cd examples/esp
cargo build --features <esp32XX> --target <esp32XX-target>
```

To build and run one example, i.e. `client`:
```
cd examples/esp
cargo run --bin client --features <esp32XX> --target <esp32XX-target>
```

...where:
- `<esp32XX>` - the ESP32 MCU you would like to build for
- `<esp32XX-target>` - the target corresponding to the ESP32MCU

Supported `esp32xx` MCUs,and their corresponding `<esp32XX-target>` targets:
| MCU          | Target                       | Hardware Acceleration                            |
| ------------ | ---------------------------- | ------------------------------------------------ |
| esp32        | xtensa-esp32-none-elf        | RSA-ExpMod                                       |
| esp32c2      | riscv32imac-unknown-none-elf | SHA1, SHA224, SHA256                             |
| esp32c3      | riscv32imc-unknown-none-elf  | RSA-ExpMod, SHA1, SHA224, SHA256                 |
| esp32c6      | riscv32imac-unknown-none-elf | RSA-ExpMod, SHA1, SHA224, SHA256                 |
| esp32h2      | riscv32imac-unknown-none-elf | RSA-ExpMod, SHA1, SHA224, SHA256                 |
| esp32s2      | xtensa-esp32s2-none-elf      | RSA-ExpMod, SHA1, SHA224, SHA256, SHA384, SHA512 |
| esp32s3      | xtensa-esp32s3-none-elf      | RSA-ExpMod, SHA1, SHA224, SHA256, SHA384, SHA512 |

## Upcoming soon

- Baremetal Raspberry Pi Pico
- Baremetal NRF52
  
## Available example binaries

### client

A basic TLS (HTTPS) client demonstrating a TLS and an mTLS client

### server

A basic TLS (HTTPS) server with a self-signed certificate

### edge_client

Similar to `client` but utilizing the true HTTP client from `edge-http`

### edge_server

Similar to `server` but utilizing the true HTTP server from `edge-http`

### crypto_self_tests

Runs the MbedTLS crypto self tests for all hookable MbedTLS algorithms in `esp-mbedtls-sys`
