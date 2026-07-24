//! Build script for `stwo-backend-metal-sys`.
//!
//! Compiles the Objective-C Metal runtime (`metal/runtime.m`) and embeds the GPU kernel
//! library, using one of two strategies:
//!
//! - **AOT** (preferred): when the Metal compiler is available (`xcrun -f metal`, requires a full
//!   Xcode installation), the shaders are compiled to a `.metallib` at build time and its bytes are
//!   embedded.
//! - **Source** (fallback): the shader *source* is preprocessed (local includes inlined) and
//!   embedded; the runtime compiles it once at startup via `newLibraryWithSource`. This works with
//!   Command Line Tools only and on machines without Xcode.
//!
//! On non-macOS targets the crate compiles to a stub (no native code, empty library).

use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};

/// Shader translation units, in concatenation order (headers are inlined first).
const METAL_SOURCES: &[&str] = &[
    "fields",
    "twiddles",
    "eval_at_point",
    "poly_utils",
    "rfft",
    "ifft",
    "quotients",
    "quotient",
    "fold_circle_into_line",
    "fold_line",
    "fri",
    "mle",
    "gkr",
    "prefix_sum",
    "bit_reverse",
    "poly_order",
    "blake2s",
    "grind",
];

const METAL_HEADERS: &[&str] = &[
    "fields_support.h",
    "secure_field_support.h",
    "poly_support.h",
];

const KERNEL_NAME_CONSTS: &str = "\
pub const STWO_METAL_BIT_REVERSE_U32_KERNEL: &str = \"bit_reverse_u32\";
pub const STWO_METAL_BIT_REVERSE_U32X4_KERNEL: &str = \"bit_reverse_u32x4\";
pub const STWO_METAL_INVERT_M31_VALUES_U32_KERNEL: &str = \"invert_m31_values_u32\";
pub const STWO_METAL_PRECOMPUTE_TWIDDLE_LEVEL_U32_KERNEL: &str = \"precompute_twiddle_level_u32\";
pub const STWO_METAL_RESCALE_M31_VALUES_U32_KERNEL: &str = \"rescale_m31_values_u32\";
pub const STWO_METAL_RFFT_CIRCLE_PART_U32_KERNEL: &str = \"rfft_circle_part_u32\";
pub const STWO_METAL_RFFT_LINE_PART_U32_KERNEL: &str = \"rfft_line_part_u32\";
pub const STWO_METAL_IFFT_CIRCLE_PART_U32_KERNEL: &str = \"ifft_circle_part_u32\";
pub const STWO_METAL_IFFT_LINE_PART_U32_KERNEL: &str = \"ifft_line_part_u32\";
pub const STWO_METAL_PERMUTE_COSET_TO_CIRCLE_DOMAIN_BIT_REVERSED_U32_KERNEL: &str = \"permute_coset_to_circle_domain_bit_reversed_u32\";
pub const STWO_METAL_FRI_FOLD_CIRCLE_INTO_LINE_FIRST_LAYER_U32X4_KERNEL: &str = \"fri_fold_circle_into_line_first_layer_u32x4\";
pub const STWO_METAL_FRI_FOLD_LINE_STEP_U32X4_KERNEL: &str = \"fri_fold_line_step_u32x4\";
";

fn main() {
    println!("cargo:rustc-check-cfg=cfg(stwo_metal_link)");
    println!("cargo:rerun-if-changed=metal/runtime.m");
    for header in METAL_HEADERS {
        println!("cargo:rerun-if-changed=metal/{header}");
    }
    for source in METAL_SOURCES {
        println!("cargo:rerun-if-changed=metal/{source}.metal");
    }

    if !cfg!(target_os = "macos") {
        println!("cargo:rustc-env=STWO_METAL_BUILD_MODE=no-metal");
        write_autogen(None, None);
        return;
    }
    println!("cargo:rustc-env=STWO_METAL_BUILD_MODE=metal");

    // Compile the Objective-C runtime.
    cc::Build::new()
        .file("metal/runtime.m")
        .flag("-fobjc-arc")
        .flag("-fblocks")
        .compile("stwo_metal_runtime");
    println!("cargo:rustc-cfg=stwo_metal_link");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Metal");
    println!("cargo:rustc-link-lib=objc");

    if metal_compiler_available() {
        let metallib = compile_metallib();
        write_autogen(Some(&metallib), None);
    } else {
        let sources = preprocess_shader_sources();
        write_autogen(None, Some(&sources));
    }
}

fn metal_compiler_available() -> bool {
    Command::new("xcrun")
        .args(["-f", "metal"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// AOT path: compile each shader to `.air` and link a `.metallib`.
fn compile_metallib() -> PathBuf {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    let metallib_path = out_dir.join("stwo-backend-metal.metallib");
    let air_paths: Vec<PathBuf> = METAL_SOURCES
        .iter()
        .map(|source| {
            let air_path = out_dir.join(format!("{source}.air"));
            run(Command::new("xcrun")
                .arg("metal")
                .arg("-c")
                .arg(format!("metal/{source}.metal"))
                .arg("-o")
                .arg(&air_path))
            .unwrap_or_else(|error| panic!("Failed to compile metal/{source}.metal: {error}"));
            air_path
        })
        .collect();

    let mut link = Command::new("xcrun");
    link.arg("metallib");
    for air_path in &air_paths {
        link.arg(air_path);
    }
    link.arg("-o").arg(&metallib_path);
    run(&mut link).unwrap_or_else(|error| panic!("Failed to link Metal library: {error}"));
    metallib_path
}

/// Source path: produce one preprocessed source string per translation unit (headers
/// inlined), each suitable for `newLibraryWithSource`. Units are compiled into separate
/// `MTLLibrary` objects so that file-scope `static` helpers do not collide.
fn preprocess_shader_sources() -> Vec<String> {
    let mut headers = String::new();
    for header in METAL_HEADERS {
        let contents = fs::read_to_string(format!("metal/{header}"))
            .unwrap_or_else(|error| panic!("Failed to read metal/{header}: {error}"));
        headers.push_str(&strip_local_includes(&contents));
        headers.push('\n');
    }
    METAL_SOURCES
        .iter()
        .map(|source| {
            let contents = fs::read_to_string(format!("metal/{source}.metal"))
                .unwrap_or_else(|error| panic!("Failed to read metal/{source}.metal: {error}"));
            format!("{headers}\n{}", strip_local_includes(&contents))
        })
        .collect()
}

/// Removes `#include "..."` lines (local headers are inlined up front) and `#pragma once`
/// directives (meaningless once inlined).
fn strip_local_includes(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#include \"") || trimmed.starts_with("#pragma once") {
            continue;
        }
        result.push_str(line);
        result.push('\n');
    }
    result
}

fn write_autogen(metallib_path: Option<&PathBuf>, sources: Option<&[String]>) {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));

    let library_const = match metallib_path {
        Some(path) => format!(
            "pub const STWO_METAL_KERNEL_LIBRARY: &[u8] = include_bytes!(r#\"{}\"#);\n",
            path.display()
        ),
        None => "pub const STWO_METAL_KERNEL_LIBRARY: &[u8] = &[];\n".to_string(),
    };
    let source_const = match sources {
        Some(sources) => {
            let mut entries = String::new();
            for (index, source) in sources.iter().enumerate() {
                let source_path = out_dir.join(format!("stwo-backend-metal-unit-{index}.metal"));
                fs::write(&source_path, source).expect("write Metal library source");
                entries.push_str(&format!(
                    "    include_str!(r#\"{}\"#),\n",
                    source_path.display()
                ));
            }
            format!("pub const STWO_METAL_KERNEL_LIBRARY_SOURCES: &[&str] = &[\n{entries}];\n")
        }
        None => "pub const STWO_METAL_KERNEL_LIBRARY_SOURCES: &[&str] = &[];\n".to_string(),
    };

    let generated = out_dir.join("metal_autogen.rs");
    fs::write(
        generated,
        format!("{library_const}{source_const}{KERNEL_NAME_CONSTS}"),
    )
    .expect("write metal autogen file");
}

fn run(command: &mut Command) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|error| format!("could not launch command: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}
