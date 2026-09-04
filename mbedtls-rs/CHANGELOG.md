# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
* (Breaking) Add `ClientSessionConfig::skip_hostname_verification`: skip the certificate hostname (CN/SAN) check while still sending SNI and verifying the certificate chain, mirroring esp-idf's `skip_cert_common_name_check` (#174)

## [0.2.0] - 2026-08-20
* (Breaking) Enforce the short-enums policy across all of clang, GCC and bindgen (#168)
* Fix the crate build when defmt is enabled (#166)
* (Breaking) AES and ECC accel for esp32XX (#164)

## [0.1.0] - 2026-06-25
* Initial release
