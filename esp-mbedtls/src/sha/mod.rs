//! Re-export SHA Hardware implementation based on availability.
//!
//! # Hardware support
//! This does not reflect the current implementation but rather the support
//! for the SHA modes on the specific SoCs.
//!
//! | Modes   | esp32   | esp32c3 | esp32s2 | esp32s3 |
//! | ------- | ------- | ------- | ------- | ------- |
//! | SHA1    |    ✓    |    ✓    |    ✓    |    ✓    |
//! | SHA224  |    x    |    ✓    |    ✓    |    ✓    |
//! | SHA256  |    ✓    |    ✓    |    ✓    |    ✓    |
//! | SHA384  |    ✓    |    x    |    ✓    |    ✓    |
//! | SHA512  |    ✓    |    x    |    ✓    |    ✓    |

mod sha256;
