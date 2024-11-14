use std::{
    env,
    path::{Path, PathBuf},
};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use directories::UserDirs;
use log::LevelFilter;
use tempdir::TempDir;

#[path = "../../esp-mbedtls-sys/gen/builder.rs"]
mod builder;

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

    /// Sysroot path for bindings
    sysroot_path: &'a str,
}

impl CompilationTarget<'_> {
    pub fn build(&self, sys_crate_root_path: PathBuf, _toolchain_dir: &Path) -> Result<()> {
        let builder = builder::MbedtlsBuilder::new(
            sys_crate_root_path.clone(),
            format!("{}", self.soc),
            None,
            None,
        );

        let out = TempDir::new("mbedtls-sys")?;

        builder.compile(
            out.path(),
            Some(&sys_crate_root_path.join("libs").join(self.target)),
        )?;

        Ok(())
    }

    pub fn generate_bindings(
        &self,
        sys_crate_root_path: PathBuf,
        _toolchain_dir: &Path,
    ) -> Result<()> {
        let builder = builder::MbedtlsBuilder::new(
            sys_crate_root_path.clone(),
            format!("{}", self.soc),
            None,
            None,
        );

        let out = TempDir::new("mbedtls-sys")?;

        builder.generate_bindings(
            out.path(),
            Some(
                &sys_crate_root_path
                    .join("src")
                    .join("include")
                    .join(format!("{}.rs", self.soc)),
            ),
        )?;

        Ok(())
    }
}

static COMPILATION_TARGETS: &[CompilationTarget] = &[
    CompilationTarget {
        soc: Soc::ESP32,
        arch: Arch::Xtensa,
        target: "xtensa-esp32-none-elf",
        sysroot_path: "xtensa-esp32-elf/esp-2021r2-patch5-8_4_0/xtensa-esp32-elf/xtensa-esp32-elf/",
    },
    CompilationTarget {
        soc: Soc::ESP32C3,
        arch: Arch::RiscV,
        target: "riscv32imc-unknown-none-elf",
        sysroot_path: "riscv32-esp-elf/esp-2021r2-patch5-8_4_0/riscv32-esp-elf/riscv32-esp-elf/",
    },
    CompilationTarget {
        soc: Soc::ESP32S2,
        arch: Arch::Xtensa,
        target: "xtensa-esp32s2-none-elf",
        sysroot_path:
            "xtensa-esp32s2-elf/esp-2021r2-patch5-8_4_0/xtensa-esp32s2-elf/xtensa-esp32s2-elf/",
    },
    CompilationTarget {
        soc: Soc::ESP32S3,
        arch: Arch::Xtensa,
        target: "xtensa-esp32s3-none-elf",
        sysroot_path:
            "xtensa-esp32s3-elf/esp-2021r2-patch5-8_4_0/xtensa-esp32s3-elf/xtensa-esp32s3-elf/",
    },
];

fn main() -> Result<()> {
    env_logger::Builder::new()
        .filter_module("xtask", LevelFilter::Info)
        .init();

    // The directory containing the cargo manifest for the 'xtask' package is a
    // subdirectory
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = workspace.parent().unwrap().canonicalize()?;

    let sys_crate_root_path = workspace.join("esp-mbedtls-sys");

    // Determine the $HOME directory, and subsequently the Espressif tools
    // directory:
    let home = UserDirs::new().unwrap().home_dir().to_path_buf();
    // We use the tools that come installed with the toolchain
    let toolchain_dir = home.join(".rustup").join("toolchains").join("esp");

    let args = Args::parse();

    match args.command {
        Some(Commands::Compile { chip }) => match chip {
            Some(chip) => {
                let target = COMPILATION_TARGETS
                    .iter()
                    .find(|&target| target.soc == chip)
                    .expect("Compilation target {chip} not found");

                target.build(sys_crate_root_path.clone(), &toolchain_dir)?;
            }
            None => {
                for target in COMPILATION_TARGETS {
                    target.build(sys_crate_root_path.clone(), &toolchain_dir)?;
                }
            }
        },
        Some(Commands::Bindings { chip }) => match chip {
            Some(chip) => {
                let target = COMPILATION_TARGETS
                    .iter()
                    .find(|&target| target.soc == chip)
                    .expect("Compilation target {chip} not found");

                target.generate_bindings(sys_crate_root_path.clone(), &toolchain_dir)?;
            }
            None => {
                for target in COMPILATION_TARGETS {
                    target.generate_bindings(sys_crate_root_path.clone(), &toolchain_dir)?;
                }
            }
        },
        _ => {
            unreachable!();
        }
    }

    Ok(())
}
