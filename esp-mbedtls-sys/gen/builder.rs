use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, Result};
use bindgen::Builder;
use cmake::Config;

pub struct MbedtlsBuilder {
    crate_root_path: PathBuf,
    soc_config: String,
    clang_path: Option<PathBuf>,
    sysroot_path: Option<PathBuf>,
    cmake_target: Option<String>,
    clang_target: Option<String>,
    host: Option<String>,
}

impl MbedtlsBuilder {
    /// Create a new MbedtlsBuilder
    ///
    /// Arguments:
    /// - `crate_root_path`: Path to the root of the crate
    /// - `soc_config`: The name of the SoC configuration in the `headers/` directory. Use `generic` for a generic, software-only build
    /// - `clang_path`: Optional path to the Clang compiler. If not specified, the system Clang will be used for generating bindings,
    ///   and the system compiler (likely GCC) would be used for building the MbedTLS C code itself
    /// - `sysroot_path`: Optional path to the compiler sysroot directory. If not specified, the host sysroot will be used
    /// - `cmake_target`: Optional target for CMake when building MbedTLS, with Rust target-triple syntax. If not specified, the "TARGET" env variable will be used
    /// - `clang_target`: Optional target for Clang when generating bindings. If not specified, the host target will be used
    /// - `host`: Optional host target for the build
    pub const fn new(
        crate_root_path: PathBuf,
        soc_config: String,
        clang_path: Option<PathBuf>,
        sysroot_path: Option<PathBuf>,
        cmake_target: Option<String>,
        clang_target: Option<String>,
        host: Option<String>,
    ) -> Self {
        Self {
            crate_root_path,
            soc_config,
            clang_path,
            sysroot_path,
            cmake_target,
            clang_target,
            host,
        }
    }

    /// Generate bindings for esp-mbedtls-sys
    ///
    /// Arguments:
    /// - `out_path`: Path to write the bindings to
    pub fn generate_bindings(
        &self,
        out_path: &Path,
        copy_file_path: Option<&Path>,
    ) -> Result<PathBuf> {
        if let Some(clang_path) = &self.clang_path {
            std::env::set_var("CLANG_PATH", clang_path);
        }

        let canon = |path: &Path| {
            // TODO: Is this really necessary?
            path.display()
                .to_string()
                .replace('\\', "/")
                .replace("//?/C:", "")
        };

        // Generate the bindings using `bindgen`:
        log::info!("Generating bindings");
        let mut builder = Builder::default().clang_args([
            &format!(
                "-I{}",
                canon(&self.crate_root_path.join("mbedtls").join("include"))
            ),
            &format!(
                "-I{}",
                canon(
                    &self
                        .crate_root_path
                        .join("gen")
                        .join("include")
                        .join("soc")
                        .join(&self.soc_config)
                )
            ),
        ]);

        if let Some(sysroot_path) = &self.sysroot_path {
            builder = builder.clang_args([
                &format!("-I{}", canon(&sysroot_path.join("include"))),
                &format!("--sysroot={}", canon(sysroot_path)),
            ]);
        }

        if let Some(target) = &self.clang_target {
            builder = builder.clang_arg(&format!("--target={target}"));
        }

        let bindings = builder
            .ctypes_prefix("crate::c_types")
            .derive_debug(false)
            .header(
                self.crate_root_path
                    .join("gen")
                    .join("include")
                    .join("include.h")
                    .to_string_lossy(),
            )
            .layout_tests(false)
            .use_core()
            .generate()
            .map_err(|_| anyhow!("Failed to generate bindings"))?;

        let bindings_file = out_path.join("bindings.rs");

        // Write out the bindings to the appropriate path:
        log::info!("Writing out bindings to: {}", bindings_file.display());
        bindings.write_to_file(&bindings_file)?;

        // Format the bindings:
        Command::new("rustfmt")
            .arg(bindings_file.to_string_lossy().to_string())
            .arg("--config")
            .arg("normalize_doc_attributes=true")
            .output()?;

        if let Some(copy_file_path) = copy_file_path {
            log::info!("Copying bindings to {}", copy_file_path.display());
            std::fs::copy(&bindings_file, copy_file_path)?;
        }

        Ok(bindings_file)
    }

    /// Compile mbedtls
    ///
    /// Arguments:
    /// - `out_path`: Path to write the compiled libraries to
    pub fn compile(&self, out_path: &Path, copy_path: Option<&Path>) -> Result<PathBuf> {
        if let Some(clang_path) = &self.clang_path {
            std::env::set_var("CLANG_PATH", clang_path);
        }

        log::info!("Compiling for {} SOC", self.soc_config);
        let mbedtls_path = self.crate_root_path.join("mbedtls");

        let target_dir = out_path.join("mbedtls").join("build");

        std::fs::create_dir_all(&target_dir)?;

        // Compile mbedtls and generate libraries to link against
        log::info!("Compiling mbedtls");
        let mut config = Config::new(&mbedtls_path);

        config
            .define("USE_SHARED_MBEDTLS_LIBRARY", "OFF")
            .define("USE_STATIC_MBEDTLS_LIBRARY", "ON")
            .define("ENABLE_PROGRAMS", "OFF")
            .define("ENABLE_TESTING", "OFF")
            .define("CMAKE_EXPORT_COMPILE_COMMANDS", "ON")
            // Clang will complain about some documentation formatting in mbedtls
            .define("MBEDTLS_FATAL_WARNINGS", "OFF")
            .define(
                "MBEDTLS_CONFIG_FILE",
                &self
                    .crate_root_path
                    .join("gen")
                    .join("include")
                    .join("soc")
                    .join(&self.soc_config)
                    .join("config.h"),
            )
            .define(
                "CMAKE_TOOLCHAIN_FILE",
                &self
                    .crate_root_path
                    .join("gen")
                    .join("toolchains")
                    .join(format!("toolchain-clang-{}.cmake", self.soc_config)),
            )
            .cflag(&format!(
                "-I{}",
                self.crate_root_path
                    .join("gen")
                    .join("include")
                    .join("soc")
                    .join(&self.soc_config)
                    .display()
            ))
            .cflag(&format!("-DMBEDTLS_CONFIG_FILE='<config.h>'"))
            .cxxflag(&format!("-DMBEDTLS_CONFIG_FILE='<config.h>'"))
            .profile("Release")
            .out_dir(&target_dir);

        if let Some(target) = &self.cmake_target {
            config.target(target);
        }

        if let Some(host) = &self.host {
            config.host(host);
        }

        config.build();

        let lib_dir = target_dir.join("lib");

        if let Some(copy_path) = copy_path {
            log::info!("Copying mbedtls libraries to {}", copy_path.display());
            std::fs::create_dir_all(copy_path)?;

            for file in ["libmbedcrypto.a", "libmbedx509.a", "libmbedtls.a"] {
                std::fs::copy(lib_dir.join(file), copy_path.join(file))?;
            }
        }

        Ok(lib_dir)
    }

    /// Re-run the build script if the file or directory has changed.
    #[allow(unused)]
    pub fn track(file_or_dir: &Path) {
        println!("cargo:rerun-if-changed={}", file_or_dir.display())
    }
}
