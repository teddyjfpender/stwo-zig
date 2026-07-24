//! Content-addressed CUDA build artifacts and compiler-identity checks.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const FNV1A128_OFFSET: u128 = 0x6c62272e07bb014262b821756295c58d;
const FNV1A128_PRIME: u128 = 0x0000000001000000000000000000013b;

fn fnv1a(bytes: &[u8], mut hash: u128) -> u128 {
    for &byte in bytes {
        hash ^= byte as u128;
        hash = hash.wrapping_mul(FNV1A128_PRIME);
    }
    hash
}

const COMPILER_FINGERPRINT_SCHEMA: &str = "stwo-cuda-compiler-fingerprint-v1";
pub(crate) const OBJECT_COMPILER_POLICY: &str = "archive-object-v1";
pub(crate) const AOT_COMPILER_POLICY: &str = "embedded-aot-cubin-v1";

pub(crate) fn parse_archive_lto(raw: Option<&str>) -> Result<bool, &'static str> {
    match raw {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(_) => Err("STWO_CUDA_ARCHIVE_LTO must be unset, 0, or 1"),
    }
}

/// Produce either executable SM targets or LTO IR targets for ordinary archive objects.
///
/// nvcc rejects a literal `-dlto` alongside explicit `-gencode`; `code=lto_N` is the documented
/// compile-side equivalent. The matching device link always requests executable `sm_N` targets.
pub(crate) fn archive_gencode_flags(target_sms: &[u32], lto_ir: bool) -> Vec<String> {
    let code = if lto_ir { "lto" } else { "sm" };
    target_sms
        .iter()
        .flat_map(|sm| {
            [
                "-gencode".to_string(),
                format!("arch=compute_{sm},code={code}_{sm}"),
            ]
        })
        .collect()
}

#[derive(Clone, Copy)]
pub(crate) struct CompilerIdentity<'a> {
    pub(crate) executable: &'a str,
    pub(crate) command: &'a str,
    pub(crate) version: &'a [u8],
    pub(crate) host_executable: &'a str,
    pub(crate) host_command: &'a str,
    pub(crate) host_version: &'a [u8],
    pub(crate) host_flag: &'a str,
}

/// Identity of the compiler, argv and policy inputs controlled by this build.
/// The pod image seals subordinate CUDA tools and system headers, which remain
/// outside this per-build cache identity.
pub(crate) fn compiler_fingerprint(
    compiler: CompilerIdentity<'_>,
    command_flags: &[String],
    policy: &str,
) -> u128 {
    fn feed(hash: &mut u128, bytes: &[u8]) {
        *hash = fnv1a(&(bytes.len() as u64).to_le_bytes(), *hash);
        *hash = fnv1a(bytes, *hash);
    }

    let mut hash = FNV1A128_OFFSET;
    feed(&mut hash, COMPILER_FINGERPRINT_SCHEMA.as_bytes());
    feed(&mut hash, compiler.command.as_bytes());
    feed(&mut hash, compiler.version);
    feed(&mut hash, compiler.host_command.as_bytes());
    feed(&mut hash, compiler.host_version);
    feed(&mut hash, &(command_flags.len() as u64).to_le_bytes());
    for flag in command_flags {
        feed(&mut hash, flag.as_bytes());
    }
    feed(&mut hash, policy.as_bytes());
    hash
}

pub(crate) fn artifact_fingerprint(
    compiler: u128,
    source_path: &Path,
    source: &[u8],
    dependency_digest: Option<u128>,
) -> u128 {
    let mut hash = FNV1A128_OFFSET;
    hash = fnv1a(b"stwo-cuda-artifact-v2", hash);
    hash = fnv1a(&compiler.to_le_bytes(), hash);
    match dependency_digest {
        Some(dependencies) => {
            hash = fnv1a(b"dependencies", hash);
            hash = fnv1a(&dependencies.to_le_bytes(), hash);
        }
        None => hash = fnv1a(b"self-contained", hash),
    }
    let source_path = source_path.to_string_lossy();
    hash = fnv1a(&(source_path.len() as u64).to_le_bytes(), hash);
    hash = fnv1a(source_path.as_bytes(), hash);
    fnv1a(source, hash)
}

pub(crate) fn current_artifact_fingerprint(
    compiler: u128,
    source: &Path,
    source_arg: &Path,
    dependency_digest: Option<u128>,
) -> std::io::Result<u128> {
    std::fs::read(source)
        .map(|bytes| artifact_fingerprint(compiler, source_arg, &bytes, dependency_digest))
}

pub(crate) fn validate_source_identities(
    compiler: u128,
    dependency_digest: Option<u128>,
    identities: &[(PathBuf, PathBuf, u128)],
) -> Result<(), String> {
    for (source, source_arg, expected) in identities {
        let current = current_artifact_fingerprint(compiler, source, source_arg, dependency_digest)
            .map_err(|error| format!("re-read {}: {error}", source.display()))?;
        if current != *expected {
            return Err(format!(
                "{} changed while nvcc was running; retry the build",
                source.display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn staging_path(final_path: &Path) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock predates Unix epoch")
        .as_nanos();
    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let extension = final_path
        .extension()
        .map(|value| value.to_string_lossy())
        .unwrap_or_default();
    final_path.with_extension(format!(
        "{extension}.tmp-{}-{nonce}-{sequence}",
        std::process::id()
    ))
}

pub(crate) fn publish_validated_artifacts(
    artifacts: &[(PathBuf, PathBuf)],
    validate: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    validate()?;
    for (staging, _) in artifacts {
        if !staging.is_file() {
            return Err(format!(
                "staged CUDA artifact is missing: {}",
                staging.display()
            ));
        }
    }
    for (staging, final_path) in artifacts {
        std::fs::rename(staging, final_path).map_err(|error| {
            format!(
                "publish {} to {}: {error}",
                staging.display(),
                final_path.display()
            )
        })?;
    }
    Ok(())
}

pub(crate) fn stage_cached_artifact(cached: &Path, final_path: &Path) -> Option<PathBuf> {
    if !cached.is_file() {
        return None;
    }
    let staging = staging_path(final_path);
    match std::fs::copy(cached, &staging) {
        Ok(_) => Some(staging),
        Err(_) => {
            let _ = std::fs::remove_file(staging);
            None
        }
    }
}

pub(crate) fn normalized_source_path(source: &Path) -> PathBuf {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    source
        .strip_prefix(&manifest)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| std::fs::canonicalize(source).unwrap_or_else(|_| source.to_path_buf()))
}

pub(crate) fn validate_extra_flags(flags: &[String]) -> Result<(), &'static str> {
    fn selects(value: &str, selectors: &[&str]) -> bool {
        selectors.iter().any(|selector| {
            value == *selector
                || value
                    .strip_prefix(*selector)
                    .is_some_and(|suffix| suffix.starts_with('='))
        })
    }

    fn forwarded_selects(flags: &[String], forwarders: &[&str], selectors: &[&str]) -> bool {
        flags.iter().enumerate().any(|(index, flag)| {
            forwarders.iter().any(|forwarder| {
                let payload = if flag == *forwarder {
                    flags.get(index + 1).map(String::as_str)
                } else {
                    flag.strip_prefix(*forwarder)
                        .and_then(|suffix| suffix.strip_prefix('='))
                };
                payload.is_some_and(|payload| {
                    payload
                        .split(',')
                        .any(|option| selects(option.trim(), selectors))
                })
            })
        })
    }

    let overrides_host_compiler = flags.iter().any(|flag| {
        flag == "-ccbin"
            || flag.starts_with("-ccbin=")
            || flag == "--compiler-bindir"
            || flag.starts_with("--compiler-bindir=")
    });
    if overrides_host_compiler {
        return Err("use STWO_CUDA_HOST_COMPILER instead of overriding nvcc -ccbin");
    }
    let overrides_target_sms = flags.iter().any(|flag| {
        selects(
            flag,
            &[
                "-arch",
                "--arch",
                "--gpu-architecture",
                "--gpu-name",
                "-code",
                "--gpu-code",
                "-gencode",
                "--generate-code",
            ],
        )
    });
    if overrides_target_sms {
        return Err("use STWO_CUDA_ARCH instead of overriding nvcc architecture/code flags");
    }
    let configures_global_lto = flags.iter().any(|flag| {
        selects(
            flag,
            &[
                "-dlto",
                "--dlink-time-opt",
                "-lto",
                "--lto",
                "-gen-opt-lto",
                "--gen-opt-lto",
                "-ltoir",
                "--ltoir",
            ],
        )
    });
    if configures_global_lto {
        return Err(
            "use STWO_CUDA_ARCHIVE_LTO=1; global LTO flags also reach generated AOT cubins",
        );
    }
    let imports_unsealed_flags = flags
        .iter()
        .any(|flag| selects(flag, &["-optf", "--options-file"]));
    if imports_unsealed_flags {
        return Err("STWO_CUDA_NVCC_FLAGS may not import an nvcc options file");
    }
    if forwarded_selects(
        flags,
        &["-Xptxas", "--ptxas-options"],
        &["-arch", "--gpu-name", "-optf", "--options-file"],
    ) {
        return Err(
            "forwarded CUDA tool flags may not override target SMs or import options files",
        );
    }
    if flags.iter().any(|flag| {
        selects(
            flag,
            &[
                "-Xnvlink",
                "--nvlink-options",
                "-prune",
                "--prune",
                "-Xnvprune",
                "--nvprune-options",
            ],
        )
    }) {
        return Err("STWO_CUDA_NVCC_FLAGS may not configure nvlink or nvprune");
    }
    Ok(())
}

pub(crate) fn headers_digest(include_dirs: &[String]) -> u128 {
    let mut paths = Vec::new();
    for dir in include_dirs {
        let entries =
            std::fs::read_dir(dir).expect("read CUDA include directory for cache identity");
        for entry in entries {
            let path = entry
                .expect("read CUDA include entry for cache identity")
                .path();
            let is_header = path
                .extension()
                .map(|extension| extension == "cuh" || extension == "h" || extension == "hpp")
                .unwrap_or(false);
            if is_header {
                paths.push(path);
            }
        }
    }
    paths.sort();
    let mut hash = FNV1A128_OFFSET;
    for path in paths {
        let path_bytes = path.to_string_lossy();
        hash = fnv1a(&(path_bytes.len() as u64).to_le_bytes(), hash);
        hash = fnv1a(path_bytes.as_bytes(), hash);
        let bytes = std::fs::read(&path).expect("read CUDA header for cache identity");
        hash = fnv1a(&(bytes.len() as u64).to_le_bytes(), hash);
        hash = fnv1a(&bytes, hash);
    }
    hash
}

pub(crate) fn command_path(command: &str) -> Option<PathBuf> {
    let path = Path::new(command);
    let candidate = if path.components().count() > 1 {
        Some(path.to_path_buf())
    } else {
        env::var_os("PATH").and_then(|paths| {
            env::split_paths(&paths)
                .map(|dir| dir.join(command))
                .find(|candidate| candidate.is_file())
        })
    };
    candidate.filter(|path| path.is_file()).map(|path| {
        if path.is_absolute() {
            path
        } else {
            env::current_dir()
                .expect("resolve command from current directory")
                .join(path)
        }
    })
}

pub(crate) fn command_identity(command: &str, path: Option<&Path>) -> String {
    let resolved = path.and_then(|path| std::fs::canonicalize(path).ok());
    let executable_digest = resolved
        .as_deref()
        .and_then(|path| std::fs::read(path).ok())
        .map(|bytes| fnv1a(&bytes, FNV1A128_OFFSET));
    format!(
        "{command}\0{}\0{}\0{}",
        path.map(|path| path.to_string_lossy()).unwrap_or_default(),
        resolved
            .as_deref()
            .map(Path::to_string_lossy)
            .unwrap_or_default(),
        executable_digest
            .map(|digest| format!("{digest:032x}"))
            .unwrap_or_default()
    )
}

pub(crate) fn emit_command_reruns(path: Option<&Path>) {
    if let Some(path) = path {
        println!("cargo:rerun-if-changed={}", path.display());
        if let Ok(resolved) = std::fs::canonicalize(path) {
            if resolved != path {
                println!("cargo:rerun-if-changed={}", resolved.display());
            }
        }
    }
}

pub(crate) fn nvcc_command(nvcc: &str) -> Command {
    let mut command = Command::new(nvcc);
    command
        .env_remove("NVCC_PREPEND_FLAGS")
        .env_remove("NVCC_APPEND_FLAGS")
        .env_remove("NVCC_CCBIN");
    command
}

pub(crate) fn command_version(command: &str, is_nvcc: bool) -> Option<Vec<u8>> {
    let mut command = if is_nvcc {
        nvcc_command(command)
    } else {
        Command::new(command)
    };
    let output = command.arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let mut identity = output.stdout;
    identity.push(0);
    identity.extend_from_slice(&output.stderr);
    Some(identity)
}

pub(crate) fn compiler_identity_is_current(compiler: CompilerIdentity<'_>) -> bool {
    let nvcc_path = Path::new(compiler.executable);
    let host_path = Path::new(compiler.host_executable);
    command_identity(compiler.executable, Some(nvcc_path)) == compiler.command
        && command_version(compiler.executable, true).as_deref() == Some(compiler.version)
        && command_identity(compiler.host_executable, Some(host_path)) == compiler.host_command
        && command_version(compiler.host_executable, false).as_deref()
            == Some(compiler.host_version)
}
