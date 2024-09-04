use crate::hal::{
    prelude::nb,
    sha::{Context, ShaDigest},
};

mod sha1;
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
mod sha256;
#[cfg(any(feature = "esp32s2", feature = "esp32s3"))]
mod sha512;
