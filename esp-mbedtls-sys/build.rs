use std::{
    env,
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

use anyhow::Result;

fn main() -> Result<()> {
    // Put the linker script somewhere the linker can find it
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let target = env::var_os("TARGET").unwrap();

    if target == "riscv32imc-unknown-none-elf" || target == "riscv32imac-unknown-none-elf" {
        copy_file(
            &out,
            "../libs/riscv32imc-unknown-none-elf/libmbedcrypto.a",
            "libmbedcrypto.a",
        )?;
        copy_file(
            &out,
            "../libs/riscv32imc-unknown-none-elf/libmbedtls.a",
            "libmbedtls.a",
        )?;
        copy_file(
            &out,
            "../libs/riscv32imc-unknown-none-elf/libmbedx509.a",
            "libmbedx509.a",
        )?;
    }

    if target == "xtensa-esp32-none-elf" {
        copy_file(
            &out,
            "../libs/xtensa-esp32-none-elf/libmbedcrypto.a",
            "libmbedcrypto.a",
        )?;
        copy_file(
            &out,
            "../libs/xtensa-esp32-none-elf/libmbedtls.a",
            "libmbedtls.a",
        )?;
        copy_file(
            &out,
            "../libs/xtensa-esp32-none-elf/libmbedx509.a",
            "libmbedx509.a",
        )?;
    }

    if target == "xtensa-esp32s2-none-elf" {
        copy_file(
            &out,
            "../libs/xtensa-esp32s2-none-elf/libmbedcrypto.a",
            "libmbedcrypto.a",
        )?;
        copy_file(
            &out,
            "../libs/xtensa-esp32s2-none-elf/libmbedtls.a",
            "libmbedtls.a",
        )?;
        copy_file(
            &out,
            "../libs/xtensa-esp32s2-none-elf/libmbedx509.a",
            "libmbedx509.a",
        )?;
    }

    if target == "xtensa-esp32s3-none-elf" {
        copy_file(
            &out,
            "../libs/xtensa-esp32s3-none-elf/libmbedcrypto.a",
            "libmbedcrypto.a",
        )?;
        copy_file(
            &out,
            "../libs/xtensa-esp32s3-none-elf/libmbedtls.a",
            "libmbedtls.a",
        )?;
        copy_file(
            &out,
            "../libs/xtensa-esp32s3-none-elf/libmbedx509.a",
            "libmbedx509.a",
        )?;
    }

    println!("cargo:rustc-link-lib={}", "mbedtls");
    println!("cargo:rustc-link-lib={}", "mbedx509");
    println!("cargo:rustc-link-lib={}", "mbedcrypto");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=../libs");
    Ok(())
}

fn copy_file(out: &PathBuf, from: &str, to: &str) -> Result<()> {
    let mut file = File::create(out.join(to))?;
    file.write_all(&fs::read(from)?)?;

    Ok(())
}
