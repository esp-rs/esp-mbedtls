# esp-mbedtls

This is mbedtls for ESP32 / bare-metal Rust.

It comes with mbedtls precompiled to avoid the need for a complete C toolchain. See `build_mbedtls` for how it was built.

## Status

This should work together with `esp-wifi`. It currently won't work without. However it's not well tested yet besides the included examples.

See the examples for how to use it. A key thing is to enable the feature `big-heap` in esp-wifi since more heap memory is needed to get this working.

For now it's missing advanced configuration options which will be added step-by-step.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
