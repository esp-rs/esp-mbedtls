# esp-mbedtls-sys*

"No-thrills" raw Rust bindings to the 3.X branch of the MbedTLS library.
`no_std` compatible and thus suitable for use on baremetal MCUs.

## Goals

- Power `esp-mbedtls` - a **type-safe**, async and blocking API specifically and only for TLS IO (the original purpose of MbedTLS);
- Use the generated `.a` libs with other C libraries depending on `MbedTLS` crypto algorithms (e.g. OpenThread) thus taking advantage of the hardware-acceleration capabilities this crate exposes (See "Hooking" below);
- Use - from Rust - as a generic library for crypto algorithms (e.g. digests, AES, RSA etc.). Alternative to `RustCrypto`.

## Non-goals

- Provide type-safe bindings for the crypto algorithms in MbedTLS
  - The above use cases are too few and a bit corner-case to justify the effort

(*) NOTE: Name to be changed soon as this crate is no longer ESP-specific.

## Precompilation

For user-convenience, the MbedTLS C library also comes pre-compiled for the following Rust targets:
- `rsicv32imc-unknown-none-elf`
- `rsicv32imac-unknown-none-elf`
- `xtensa-esp32-none-elf`
- `xtensa-esp32s2-none-elf`
- `xtensa-esp32s3-none-elf`
- (PRs for other Rust baremetal targets appreciated!)

For other MCU baremetal targets as well as for STD platforms, the MbedTLS C library will be compiled on the fly, but that requires GCC (the cross-compiler flavor for your MCU) and Clang pre-installed.

ESP-IDF is also supported and in that case `esp-mbedtls-sys` becomes just an alias for `esp-idf-sys` and uses the MbedTLS library which is built-in inside ESP-IDF.

**NOTE:**: on-the-fly compilation can be forced by using the `force-generate-bindings` feature.

## Hooking (for HW accel)

Putting aside the new PSA Crypto driver layer, MbedTLS 3.X has a relatively simplistic approach ("_ALT" macros) towards hardware acceleration.
Say, you want the SHA-1 algorithm beging accelerated. You then need to:
- Instruct MbedTLS - **at C compile-time** to **compile-out** its built-in SHA-1 implementation by defining the `MBEDTLS_SHA1_ALT` macro;
- Provide your own mbedtls_sha1_* functions at link time which need to match the signatures of the MbedTLS SHA-1 implementation;
- Provide your own `mbedtls_sha1_context` structure to MbedTLS - **at C compile-time** - in a custom C header file (the structure is treated as opaque by MbedTLS).

Needless to say, this is a lot of lift-and-shift for Rust developers, especially if they plan to plug-in **Rust-based** hardware accelerated routines.
For that reason, `esp-mbedtls-sys` provides the so called Hooking mechanism. Currently, only for some MbedTLS crypto-functions, but the list is expected to grow a bit possibly including EC curves and AES.

In essence Hooking relies on the "_ALT" functionality in MbedTLS and specifically does the following:
- It replaces e.g. the `mbedtls_sha1_context` of MbedTLS with a custom one which is just a sequence of bytes (called a "work area" throughout esp-mbedtls-sys)
  - The exact number of bytes of the work area depends on the concrete algorithm being hooked, but the size **IS** hard-coded yet chosen large enough to be "good enough" for any Rust based HW-accel implementation
  - In case the unthinkable happens and the size is not large enough, it must be extended with a PR, or the Rust accel needs to manage its own storage and use the sequence of bytes in `mbedtls_sha1_context` as a pointer of sorts
  - How the Rust HW accel implementation uses the sequence of bytes is up to the implementation, but the expectation is that it would emplace its own Rust type(s) in there, following the rules of Rust for proper memory allgnment; the `WorkArea` type provided by esp-mbedtls-sys provides helpers for that
- There is a dyn-compatible trait for each hook (algorithm to be HW accelerated) provided by esp-mbedtls-sys that the Rust developer needs to implement. For e.g. SHA-1, the trait is called `MbedtlsSha1`. User is expected to call e.g. `hook_sha1(&'static dyn MbedtlsSha1)` with their own implementation early in their program initialization code
  - If `hook_XXX` is not called for a particular hook algorithm, MbedTLS would function just fine but would fallback to either its own software implementation of the algorithm, or to a `RustCrypto` based one provided out of the box. Sadly, for most hooks it is just not possible to fallback to the MbedTLS original C software impl, as it is **completely erased** from the source code when the "_ALT" macro functionality is used

Finally, when hooking stateless algorithms that do their job with a single function call (like `mbedtls_mpi_mod_exp`), there is no notion of a "work area" as the crypto algorithm does not really have an externally-observable state, in that it finishes all its operation in one go.

## Error Handling

Laboriously checking the integer result when calling each `mbedtls_*` function is deemed unergonomic enough so that esp-mbedtls-sys provides:
- A Rust `core::error::Error` wrapper over the integer codes of MbedTLS: `MbedtlsError`
- A small macro - `merr!` that turns MbedTLS error codes into a `Result<i32, MbedtlsError>` where `Ok(i32)` is returned for non-negative error codes, and `Err(MbedtlsError)` is returned for negative error codes

## Future

The [backwards-incompatible MbedTLS 4.0 released in Oct 2025](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-4.0.0) finally splits the "I'm a generic library for crypto algorithms" use case from the "I'm a library for doing TLS IO" use case into two separate libraries:
- [TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto) - for "I'm a generic library for crypto algorithms" - implementing the PSA API and having a special new driver layer for HW accel
- [MBedTLS](https://github.com/Mbed-TLS/mbedtls) - for "I'm a library for doing TLS IO" - and for now - relying **specifically** on the TF-PSA-Crypto for doing that rather than capable of using any library implementing the PSA API

Whether, and how exactly a migration to MbedTLS 4.0 would happen is still unclear but that's on the table once it sarts to see wider use overall.

One way would be to have a new crate - `tf-psa-crypto-sys` which provides raw bindings to `TF-PSA-Crypto` (and somehow still does hooking). `esp-mbedtls-sys` would then only provide bindings for the "I'm a library for doing TLS IO" which is what MBedTLS 4.0 is.
