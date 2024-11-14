use std::{env, path::PathBuf};

use anyhow::Result;

#[path = "gen/builder.rs"]
mod builder;

fn main() -> Result<()> {
    let crate_root_path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());

    // If any one of these features is selected, we don't build anything
    // and just use the pre-generated baremetal ESP bindings and libraries
    let esp32 = env::var("CARGO_FEATURE_ESP32").is_ok();
    let esp32c3 = env::var("CARGO_FEATURE_ESP32C3").is_ok();
    let esp32s2 = env::var("CARGO_FEATURE_ESP32S2").is_ok();
    let esp32s3 = env::var("CARGO_FEATURE_ESP32S3").is_ok();

    let target = env::var("TARGET").unwrap();
    let bindings_dir = crate_root_path.join("src").join("include");
    let libs_dir = crate_root_path.join("libs");

    let dirs = if esp32 {
        Some((bindings_dir.join("esp32.rs"), libs_dir.join("xtensa-esp32-none-elf")))
    } else if esp32c3 {
        Some((bindings_dir.join("esp32.rs"), libs_dir.join("xtensa-esp32c3-none-elf")))
    } else if esp32s2 {
        Some((bindings_dir.join("esp32.rs"), libs_dir.join("xtensa-esp32s2-none-elf")))
    } else if esp32s3 {
        Some((bindings_dir.join("esp32.rs"), libs_dir.join("xtensa-esp32s3-none-elf")))
    } else if target.ends_with("-espidf") {
        // Nothing to do for ESP-IDF, `esp-idf-sys` will do everything for us
        None
    } else {
        // Need to do on-the-fly build and bindings' generation
        let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());

        let builder = builder::MbedtlsBuilder::new(crate_root_path.clone(), "generic".to_string(), None, None);

        let bindings = builder.compile(&out)?;
        let libs_dir = builder.generate_bindings(&out)?;

        Some((bindings, libs_dir))
    };

    if let Some((bindings, libs_dir)) = dirs {
        println!("cargo::rustc-env=ESP_MBEDTLS_SYS_BINDINGS={}", bindings.display());

        println!("cargo:rustc-link-lib={}", "mbedtls");
        println!("cargo:rustc-link-lib={}", "mbedx509");
        println!("cargo:rustc-link-lib={}", "mbedcrypto");
        println!("cargo:rustc-link-search={}", libs_dir.display());
        println!("cargo:rerun-if-changed={}", libs_dir.display());
    }

    Ok(())
}
