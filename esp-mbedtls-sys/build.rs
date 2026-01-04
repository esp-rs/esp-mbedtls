use std::{env, path::PathBuf};

use anyhow::Result;
use enumset::EnumSet;

use crate::builder::Accel;

#[path = "gen/builder.rs"]
mod builder;

fn main() -> Result<()> {
    let crate_root_path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());

    builder::MbedtlsBuilder::track(&crate_root_path.join("gen"));
    builder::MbedtlsBuilder::track(&crate_root_path.join("mbedtls"));

    let host = env::var("HOST").unwrap();
    let target = env::var("TARGET").unwrap();

    let force_esp_riscv_toolchain = env::var("CARGO_FEATURE_FORCE_ESP_RISCV_TOOLCHAIN").is_ok();
    let pregen_bindings = env::var("CARGO_FEATURE_FORCE_GENERATE_BINDINGS").is_err();
    let pregen_bindings_rs_file = crate_root_path
        .join("src")
        .join("include")
        .join(format!("{target}.rs"));
    let pregen_libs_dir = crate_root_path.join("libs").join(&target);            

    let dirs = if pregen_bindings && pregen_bindings_rs_file.exists() {
        // Use the pre-generated bindings
        Some((pregen_bindings_rs_file, pregen_libs_dir))
    } else if target.ends_with("-espidf") {
        // Nothing to do for ESP-IDF, `esp-idf-sys` will do everything for us
        None
    } else {
        // Need to do on-the-fly build and bindings' generation
        let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());

        // Figure out what MbedTLS HW acceleration options (ALT modules) to enable
        let mut accel = EnumSet::empty();

        if env::var("CARGO_FEATURE_ACCEL_SHA1").is_ok() {
            accel |= Accel::Sha1;
        }

        if env::var("CARGO_FEATURE_ACCEL_SHA256").is_ok() {
            accel |= Accel::Sha256;
        }

        if env::var("CARGO_FEATURE_ACCEL_SHA512").is_ok() {
            accel |= Accel::Sha512;
        }

        if env::var("CARGO_FEATURE_ACCEL_EXP_MOD").is_ok() {
            accel |= Accel::ExpMod;
        }

        let builder = builder::MbedtlsBuilder::new(
            accel,
            false,
            crate_root_path.clone(),
            Some(target),
            Some(host),
            None,
            None,
            None,
            force_esp_riscv_toolchain,
        );

        let libs_dir = builder.compile(&out, None)?;
        let bindings = builder.generate_bindings(&out, None)?;

        Some((bindings, libs_dir))
    };

    if let Some((bindings, libs_dir)) = dirs {
        println!(
            "cargo::rustc-env=ESP_MBEDTLS_SYS_BINDINGS_FILE={}",
            bindings.display()
        );

        println!("cargo:rustc-link-search={}", libs_dir.display());

        for entry in std::fs::read_dir(libs_dir)? {
            let entry = entry?;

            let file_name = entry.file_name();
            let file_name = file_name.to_str().unwrap();
            if file_name.ends_with(".a") || file_name.to_ascii_lowercase().ends_with(".lib") {
                let lib_name = if file_name.ends_with(".a") {
                    file_name.trim_start_matches("lib").trim_end_matches(".a")
                } else {
                    file_name.trim_end_matches(".lib")
                };

                println!("cargo:rustc-link-lib=static={lib_name}");
            }
        }        
    }

    Ok(())
}
