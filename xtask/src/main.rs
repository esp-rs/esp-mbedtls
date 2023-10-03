use std::{
    env,
    fs::{self, rename},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, Result};
use bindgen::Builder;
use clap::{Parser, Subcommand, ValueEnum};
use cmake::Config;
use directories::UserDirs;
use fs_extra::dir::{copy, CopyOptions};
use log::LevelFilter;
use tempdir::TempDir;

// Arguments
#[derive(Parser, Debug)]
#[command(author, version, about = "Compile and generate bindings for mbedtls to be used in Rust.", long_about = None, subcommand_required = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate Rust bindings for mbedtls
    Bindings {
        #[arg(long, value_name = "TARGET", value_enum)]
        chip: Option<Soc>,
    },
    /// Build mbedtls and generate .a libraries
    Compile {
        #[arg(long, value_name = "TARGET", value_enum)]
        chip: Option<Soc>,
    },
}

/// All SOCs available for compiling and binding
#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
enum Soc {
    ESP32,
    ESP32C3,
    ESP32S2,
    ESP32S3,
}

impl core::fmt::Display for Soc {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Soc::ESP32 => write!(f, "esp32"),
            Soc::ESP32C3 => write!(f, "esp32c3"),
            Soc::ESP32S2 => write!(f, "esp32s2"),
            Soc::ESP32S3 => write!(f, "esp32s3"),
        }
    }
}

#[derive(Debug, PartialEq)]
enum Arch {
    RiscV,
    Xtensa,
}

/// Data for binding compiling on a target
struct CompilationTarget<'a> {
    /// Chip of the target
    soc: Soc,

    /// The chip architecture
    arch: Arch,

    /// Target triple
    target: &'a str,

    /// cmake toolchain file
    toolchain_file: PathBuf,

    /// Path for headers files for compiling (where mbedtls_config.h is stored)
    compile_include_path: PathBuf,

    /// Sysroot path for bindings
    sysroot_path: PathBuf,
}

fn main() -> Result<()> {
    env_logger::Builder::new()
        .filter_module("xtask", LevelFilter::Info)
        .init();

    // The directory containing the cargo manifest for the 'xtask' package is a
    // subdirectory
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = workspace.parent().unwrap().canonicalize()?;

    // Determine the $HOME directory, and subsequently the Espressif tools
    // directory:
    let home = UserDirs::new().unwrap().home_dir().to_path_buf();
    // We use the tools that come installed with the toolchain
    let toolchain_dir = home.join(".rustup").join("toolchains").join("esp");

    let compilation_targets: Vec<CompilationTarget> = vec![
        CompilationTarget {
            soc: Soc::ESP32,
            arch: Arch::Xtensa,
            target: "xtensa-esp32-none-elf",
            toolchain_file: workspace
                .join("xtask/toolchains/toolchain-esp32.cmake")
                .canonicalize()
                .unwrap(),
            compile_include_path: workspace.join("esp-mbedtls-sys").join("headers/esp32/"),
            sysroot_path: toolchain_dir.join(
                "xtensa-esp32-elf/esp-2021r2-patch5-8_4_0/xtensa-esp32-elf/xtensa-esp32-elf/",
            ),
        },
        CompilationTarget {
            soc: Soc::ESP32C3,
            arch: Arch::RiscV,
            target: "riscv32imc-unknown-none-elf",
            toolchain_file: workspace
                .join("xtask/toolchains/toolchain-esp32c3.cmake")
                .canonicalize()
                .unwrap(),
            compile_include_path: workspace.join("esp-mbedtls-sys").join("headers/esp32c3/"),
            sysroot_path: toolchain_dir
                .join("riscv32-esp-elf/esp-2021r2-patch5-8_4_0/riscv32-esp-elf/riscv32-esp-elf/"),
        },
        CompilationTarget {
            soc: Soc::ESP32S2,
            arch: Arch::Xtensa,
            target: "xtensa-esp32s2-none-elf",
            toolchain_file: workspace
                .join("xtask/toolchains/toolchain-esp32s2.cmake")
                .canonicalize()
                .unwrap(),
            compile_include_path: workspace.join("esp-mbedtls-sys").join("headers/esp32s2/"),
            sysroot_path: toolchain_dir.join(
                "xtensa-esp32s2-elf/esp-2021r2-patch5-8_4_0/xtensa-esp32s2-elf/xtensa-esp32s2-elf/",
            ),
        },
        CompilationTarget {
            soc: Soc::ESP32S3,
            arch: Arch::Xtensa,
            target: "xtensa-esp32s3-none-elf",
            toolchain_file: workspace
                .join("xtask/toolchains/toolchain-esp32s3.cmake")
                .canonicalize()
                .unwrap(),
            compile_include_path: workspace.join("esp-mbedtls-sys").join("headers/esp32s3/"),
            sysroot_path: toolchain_dir.join(
                "xtensa-esp32s3-elf/esp-2021r2-patch5-8_4_0/xtensa-esp32s3-elf/xtensa-esp32s3-elf/",
            ),
        },
    ];
    let args = Args::parse();

    match args.command {
        Some(Commands::Compile { chip }) => match chip {
            Some(chip) => {
                compile(
                    &workspace,
                    compilation_targets
                        .iter()
                        .find(|&target| target.soc == chip)
                        .expect("Compilation target not found"),
                )?;
            }
            None => {
                for target in compilation_targets {
                    compile(&workspace, &target)?;
                }
            }
        },
        Some(Commands::Bindings { chip }) => match chip {
            Some(chip) => {
                generate_bindings(
                    &workspace,
                    compilation_targets
                        .iter()
                        .find(|&target| target.soc == chip)
                        .expect("Compilation target not found"),
                )?;
            }
            None => {
                for target in compilation_targets {
                    generate_bindings(&workspace, &target)?;
                }
            }
        },
        _ => {
            unreachable!();
        }
    }

    Ok(())
}

/// Generate bindings for esp-mbedtls-sys
fn generate_bindings(workspace: &Path, compilation_target: &CompilationTarget) -> Result<()> {
    let sys_path = workspace.join("esp-mbedtls-sys");

    // Generate the bindings using `bindgen`:
    log::info!("Generating bindings");
    let bindings = Builder::default()
        .clang_args([
            &format!(
                "-I{}",
                &compilation_target
                    .compile_include_path
                    .display()
                    .to_string()
                    .replace('\\', "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "-I{}",
                sys_path
                    .join("../mbedtls/include/")
                    .display()
                    .to_string()
                    .replace('\\', "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "-I{}",
                sys_path
                    .join("include")
                    .display()
                    .to_string()
                    .replace('\\', "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "-I{}",
                compilation_target
                    .sysroot_path
                    .join("include")
                    .display()
                    .to_string()
                    .replace('\\', "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "--sysroot={}",
                compilation_target
                    .sysroot_path
                    .display()
                    .to_string()
                    .replace('\\', "/")
                    .replace("//?/C:", "")
            ),
            &format!(
                "--target={}",
                if compilation_target.arch == Arch::Xtensa {
                    "xtensa"
                } else {
                    "riscv32"
                }
            ),
        ])
        .ctypes_prefix("crate::c_types")
        .derive_debug(false)
        .header(sys_path.join("include/include.h").to_string_lossy())
        .layout_tests(false)
        .raw_line("#![allow(non_camel_case_types,non_snake_case,non_upper_case_globals,dead_code)]")
        .use_core()
        .generate()
        .map_err(|_| anyhow!("Failed to generate bindings"))?;

    // Write out the bindings to the appropriate path:
    let path = sys_path
        .join("src")
        .join("include")
        .join(format!("{}.rs", compilation_target.soc.to_string()));
    log::info!("Writing out bindings to: {}", path.display());
    bindings.write_to_file(&path)?;

    // Format the bindings:
    Command::new("rustfmt")
        .arg(path.to_string_lossy().to_string())
        .arg("--config")
        .arg("normalize_doc_attributes=true")
        .output()?;

    Ok(())
}

/// Compile mbedtls for the given target and copy the libraries into /libs/
fn compile(workspace: &Path, compilation_target: &CompilationTarget) -> Result<()> {
    log::info!(
        "Initializing directory for compiling {:?}",
        compilation_target.soc
    );
    let mbedtls_path = workspace.join("mbedtls");
    let tmp = TempDir::new("tmp").expect("Failed to create tmp directory for building");

    let tmpsrc = TempDir::new_in(tmp.path(), "tmpsrc")
        .expect("Failed to create tmpsrc directory for building");
    let target_dir = TempDir::new_in(tmp.path(), "target")
        .expect("Failed to create target directory for building");
    let copy_options = CopyOptions::new().overwrite(true); //Initialize default values for CopyOptions

    // Copy mbedtls into the building directory
    copy(mbedtls_path, tmpsrc.path(), &copy_options)?;
    // Copy header files for building
    copy(
        &compilation_target.compile_include_path,
        tmpsrc
            .path()
            .join("mbedtls")
            .join("include")
            .join("mbedtls"),
        &copy_options.content_only(true),
    )?;
    // Move config.h back to mbedtls_config.h
    rename(
        tmpsrc
            .path()
            .join("mbedtls")
            .join("include")
            .join("mbedtls")
            .join("config.h"),
        tmpsrc
            .path()
            .join("mbedtls")
            .join("include")
            .join("mbedtls")
            .join("mbedtls_config.h"),
    )?;

    // Remove "-Wdocumentation" since Clang will complain
    let mut file = fs::File::open(
        tmpsrc
            .path()
            .join("mbedtls")
            .join("library")
            .join("CMakeLists.txt"),
    )?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    let mut file = fs::File::create(
        tmpsrc
            .path()
            .join("mbedtls")
            .join("library")
            .join("CMakeLists.txt"),
    )?;
    file.write_all(content.replace("-Wdocumentation", "").as_bytes())?;

    // Compile mbedtls and generate libraries to link against
    log::info!("Compiling mbedtls");
    let dst = Config::new(tmpsrc.path().join("mbedtls"))
        .define("USE_SHARED_MBEDTLS_LIBRARY", "OFF")
        .define("USE_STATIC_MBEDTLS_LIBRARY", "ON")
        .define("ENABLE_PROGRAMS", "OFF")
        .define("ENABLE_TESTING", "OFF")
        .define("CMAKE_EXPORT_COMPILE_COMMANDS", "ON")
        .define("CMAKE_TOOLCHAIN_FILE", &compilation_target.toolchain_file)
        .target(compilation_target.target)
        .host("riscv32")
        .profile("Release")
        .out_dir(target_dir)
        .build();

    log::info!("Copying libraries into workspace");
    fs::copy(
        dst.join("lib").join("libmbedcrypto.a"),
        workspace
            .join("libs")
            .join(compilation_target.target)
            .join("libmbedcrypto.a"),
    )?;
    fs::copy(
        dst.join("lib").join("libmbedx509.a"),
        workspace
            .join("libs")
            .join(compilation_target.target)
            .join("libmbedx509.a"),
    )?;
    fs::copy(
        dst.join("lib").join("libmbedtls.a"),
        workspace
            .join("libs")
            .join(compilation_target.target)
            .join("libmbedtls.a"),
    )?;
    Ok(())
}
