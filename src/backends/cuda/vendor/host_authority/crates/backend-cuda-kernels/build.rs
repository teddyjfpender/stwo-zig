//! Build script for `stwo-backend-cuda-kernels`.
//!
//! Compile-gated: when `nvcc` is available (on `PATH`, or via the `STWO_CUDA_NVCC` env
//! var), every kernel under `cuda/` is compiled into a static archive and linked into the
//! crate, so `cargo build -p stwo-backend-cuda-kernels` on a CUDA machine validates that
//! the staged kernels compile. Without `nvcc` the crate builds as a stub and the rest of
//! the workspace is unaffected — no CUDA toolkit is required to build or test stwo.
//!
//! Tunables:
//! - `STWO_CUDA_NVCC`: path to the nvcc binary (default: `nvcc` from `PATH`)
//! - `STWO_CUDA_ARCH`: comma-separated numeric SMs; detected from the first local GPU, and required
//!   explicitly on a headless compiler host
//! - `STWO_CUDA_NVCC_FLAGS`: extra whitespace-separated flags appended to every call
//! - `STWO_CUDA_ARCHIVE_LTO`: `1` enables device LTO for the ordinary archive only (default: `0`)
//! - `STWO_CUDA_BUILD_JOBS`: maximum concurrent nvcc processes (default: host parallelism)
//! - `STWO_CUDA_HOST_COMPILER`: explicit nvcc host compiler (default: `c++` from `PATH`)
//!
//! The kernels use separable compilation because translation units cross-reference
//! `fields.cu`; see "Known issues" in the README for the remaining inlining cost.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn cuda_build_workers(job_count: usize) -> usize {
    env::var("STWO_CUDA_BUILD_JOBS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&value| value > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        })
        .min(16)
        .min(job_count)
}

#[path = "build_cache.rs"]
mod build_cache;
use build_cache::*;

#[path = "static_module_identity.rs"]
mod static_module_identity;
use static_module_identity::{
    is_ordinary_cuda_authority_file, normalized_target_sms, receipt_carrier_source,
    static_module_build_identity, ExactFile, ExecutableIdentity, StaticModuleIdentityInput,
    TuObject,
};

#[path = "src/aot_identity.rs"]
mod aot_identity;
use aot_identity::{
    cubin_identity, kernel_authority_identity, module_globals_for_source, pack_identity,
    source_identity, AotKernelAbiSchema, AotKernelModuleGlobals, AotKernelSchemaScope,
    CubinIdentityInput, KernelAuthorityIdentityInput,
};

#[path = "src/aot_source_manifest.rs"]
mod aot_source_manifest;
use aot_source_manifest::{
    parse_source_manifest, validate_exported_kernel_symbol, validate_structured_kernel_signature,
};

struct AotBuildEntry {
    cache_key: u64,
    sm: u32,
    cubin: PathBuf,
    kernel_symbol: String,
    semantic_hash: u64,
    source_identity: [u8; 32],
    abi_schema: Option<AotKernelAbiSchema>,
    program_identity: [u8; 32],
    module_globals: AotKernelModuleGlobals,
}

struct AotBuildSnapshot {
    sources: Vec<(PathBuf, PathBuf, u128)>,
    exact_sources: Vec<(PathBuf, [u8; 32])>,
    manifest: (PathBuf, PathBuf, u128),
    manifest_bytes: Vec<u8>,
}

fn object_fixed_flags(include_dirs: &[String]) -> Vec<String> {
    // The fp256/poseidon252 stack calls constexpr host accessors from device
    // code (sppark lineage), which requires relaxed constexpr compilation.
    let mut flags = ["-dc", "-O3", "--std=c++17", "--expt-relaxed-constexpr"]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    flags.extend(
        include_dirs
            .iter()
            .flat_map(|dir| ["-I".to_string(), dir.clone()]),
    );
    flags.extend(["-Xcompiler".to_string(), "-fPIC".to_string()]);
    flags
}

fn aot_fixed_flags() -> Vec<String> {
    ["-cubin", "-O3", "--std=c++17", "--expt-relaxed-constexpr"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(stwo_cuda_link)");
    println!("cargo:rerun-if-env-changed=STWO_CUDA_NVCC");
    println!("cargo:rerun-if-env-changed=STWO_CUDA_ARCH");
    println!("cargo:rerun-if-env-changed=STWO_CUDA_NVCC_FLAGS");
    println!("cargo:rerun-if-env-changed=STWO_CUDA_ARCHIVE_LTO");
    println!("cargo:rerun-if-env-changed=STWO_CUDA_BUILD_JOBS");
    println!("cargo:rerun-if-env-changed=STWO_CUDA_HOST_COMPILER");
    println!("cargo:rerun-if-env-changed=PATH");
    println!("cargo:rerun-if-changed=build_cache.rs");
    println!("cargo:rerun-if-changed=build_fingerprint_tests.rs");
    println!("cargo:rerun-if-changed=static_module_identity.rs");
    println!("cargo:rerun-if-changed=static_module_identity_tests.rs");
    println!("cargo:rerun-if-changed=src/aot_identity.rs");
    println!("cargo:rerun-if-changed=src/aot_source_manifest.rs");

    let sources = kernel_sources();
    for source in &sources {
        println!("cargo:rerun-if-changed={}", source.display());
    }
    // Track the whole cuda/ tree (cargo traverses directories recursively): headers
    // (.cuh) are compiled into every translation unit, so an edit there must dirty
    // the build just like a .cu edit — otherwise stale objects with old symbol
    // signatures survive in the archive.
    println!("cargo:rerun-if-changed=cuda");

    let nvcc_requested = env::var("STWO_CUDA_NVCC").unwrap_or_else(|_| "nvcc".to_string());
    let nvcc_path = command_path(&nvcc_requested);
    emit_command_reruns(nvcc_path.as_deref());
    let nvcc_available = command_version(&nvcc_requested, true).is_some();
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    write_static_cuda_source_identity(&out_dir);
    let aot_constraint_max_instrs = generated_aot_constraint_max_instrs();
    let aot_constraint_max_live_u32_lanes = generated_aot_constraint_max_live_u32_lanes();
    if !nvcc_available {
        write_static_cuda_module_build_identity(&out_dir, [0; 32], &[]);
        write_aot_pack(
            &out_dir,
            &[],
            aot_constraint_max_instrs,
            aot_constraint_max_live_u32_lanes,
        );
        println!("cargo:rustc-env=STWO_CUDA_BUILD_MODE=no-cuda");
        return;
    }
    let nvcc_path = nvcc_path
        .and_then(|path| std::fs::canonicalize(path).ok())
        .unwrap_or_else(|| PathBuf::from(&nvcc_requested));
    let nvcc = nvcc_path.to_string_lossy().into_owned();
    let nvcc_executable_bytes =
        std::fs::read(&nvcc_path).expect("read exact nvcc executable identity");
    let nvcc_identity =
        command_version(&nvcc, true).expect("re-probe resolved nvcc version successfully");
    let nvcc_command_identity = command_identity(&nvcc, Some(&nvcc_path));
    let host_compiler = env::var("STWO_CUDA_HOST_COMPILER").unwrap_or_else(|_| "c++".to_string());
    let host_path = command_path(&host_compiler)
        .unwrap_or_else(|| panic!("nvcc host compiler not found: {host_compiler}"));
    emit_command_reruns(Some(&host_path));
    let host_executable = std::fs::canonicalize(&host_path).unwrap_or_else(|_| host_path.clone());
    let host_executable = host_executable.to_string_lossy().into_owned();
    let host_executable_bytes =
        std::fs::read(&host_executable).expect("read exact nvcc host compiler executable identity");
    let host_version_identity = command_version(&host_executable, false)
        .expect("query resolved nvcc host compiler version");
    let host_command_identity = command_identity(
        &host_executable,
        Some(std::path::Path::new(&host_executable)),
    );
    let host_compiler_flag = format!("-ccbin={host_executable}");
    let compiler_identity = CompilerIdentity {
        executable: &nvcc,
        command: &nvcc_command_identity,
        version: &nvcc_identity,
        host_executable: &host_executable,
        host_command: &host_command_identity,
        host_version: &host_version_identity,
        host_flag: &host_compiler_flag,
    };
    // STWO_CUDA_ARCH accepts a comma list (e.g. "sm_86,sm_90") to build a fat binary
    // that runs on multiple GPU generations — one release artifact for 3090 and H100.
    let target_sms =
        normalized_target_sms(&env::var("STWO_CUDA_ARCH").unwrap_or_else(|_| detect_arch()))
            .unwrap_or_else(|error| panic!("{error}"));
    let archs = target_sms
        .iter()
        .map(|sm| format!("sm_{sm}"))
        .collect::<Vec<_>>();
    let archive_lto = parse_archive_lto(env::var("STWO_CUDA_ARCHIVE_LTO").ok().as_deref())
        .unwrap_or_else(|error| panic!("{error}"));
    let object_gencode_flags = archive_gencode_flags(&target_sms, archive_lto);
    let dlink_gencode_flags = archive_gencode_flags(&target_sms, false);
    let extra_flags: Vec<String> = env::var("STWO_CUDA_NVCC_FLAGS")
        .map(|flags| flags.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    validate_extra_flags(&extra_flags).unwrap_or_else(|error| panic!("{error}"));
    let source_closure = snapshot_ordinary_cuda_sources();

    // Separable compilation (-rdc=true) requires an explicit device-link step: the
    // final Rust link knows nothing about CUDA, so the device-link object must be in
    // the archive. Pipeline: each .cu -> .o (-dc), then nvcc -dlink over all objects,
    // then everything into one archive.
    let run_nvcc = |args: &mut Command| {
        let output = args
            .output()
            .expect("nvcc was detected but could not be launched");
        assert!(
            output.status.success(),
            "nvcc failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };

    // Every kernel directory is an include root: the generated headers include each
    // other by bare name regardless of subdirectory.
    let mut include_dirs: Vec<String> = vec!["cuda".to_string()];
    collect_dirs(std::path::Path::new("cuda"), &mut include_dirs);
    include_dirs.sort();
    let mut object_compile_flags = object_fixed_flags(&include_dirs);
    object_compile_flags.push(compiler_identity.host_flag.to_string());
    object_compile_flags.extend(object_gencode_flags.iter().cloned());
    object_compile_flags.extend(extra_flags.iter().cloned());
    let object_compiler_fingerprint = compiler_fingerprint(
        compiler_identity,
        &object_compile_flags,
        OBJECT_COMPILER_POLICY,
    );
    let header_fingerprint = headers_digest(&include_dirs);

    // Archive objects compile on the same bounded pool (independent TUs). Their
    // local and persistent paths are content-addressed by source, headers and
    // compiler policy; mtimes are never trusted for generated-code freshness.
    let obj_cache: Option<PathBuf> = env::var("STWO_CUDA_OBJ_CACHE").ok().map(PathBuf::from);
    if let Some(dir) = &obj_cache {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut objects: Vec<PathBuf> = Vec::with_capacity(sources.len() + 1);
    let mut object_argvs: Vec<Vec<String>> = Vec::with_capacity(sources.len());
    let mut obj_jobs: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut staged_objects: Vec<(PathBuf, PathBuf, Option<PathBuf>)> = Vec::new();
    let mut source_identities: Vec<(PathBuf, PathBuf, u128)> = Vec::with_capacity(sources.len());
    for source in &sources {
        let source_arg = normalized_source_path(source);
        let source_bytes = std::fs::read(source).expect("read CUDA source for cache identity");
        let key = artifact_fingerprint(
            object_compiler_fingerprint,
            &source_arg,
            &source_bytes,
            Some(header_fingerprint),
        );
        let object = out_dir.join(format!(
            "{}-{key:032x}.o",
            source
                .file_stem()
                .expect("kernel file stem")
                .to_string_lossy()
        ));
        let cache_path = obj_cache.as_ref().map(|dir| {
            dir.join(format!(
                "{}-{key:032x}.o",
                source
                    .file_stem()
                    .expect("kernel file stem")
                    .to_string_lossy()
            ))
        });
        if !object.is_file() {
            let restored_staging = cache_path
                .as_ref()
                .and_then(|cached| stage_cached_artifact(cached, &object));
            let restored = restored_staging.is_some();
            let staging = restored_staging.unwrap_or_else(|| staging_path(&object));
            if !restored {
                obj_jobs.push((source_arg.clone(), staging.clone()));
            }
            let publish_cache = if restored { None } else { cache_path };
            staged_objects.push((staging, object.clone(), publish_cache));
        }
        objects.push(object);
        // Seal the exact compiler-policy argv against the final content-addressed
        // object name. A temporary publication suffix is intentionally normalized
        // away: cache hits execute no nvcc command, while the exact object bytes
        // below remain authoritative in either path.
        let mut argv = object_compile_flags.clone();
        argv.push(source_arg.to_string_lossy().into_owned());
        argv.push("-o".to_string());
        argv.push(objects.last().unwrap().to_string_lossy().into_owned());
        object_argvs.push(argv);
        source_identities.push((source.clone(), source_arg, key));
    }
    if !obj_jobs.is_empty() {
        let workers = cuda_build_workers(obj_jobs.len());
        let next = std::sync::atomic::AtomicUsize::new(0);
        let jobs_ref = &obj_jobs;
        let next_ref = &next;
        let compile_flags_ref = &object_compile_flags;
        let nvcc_ref = &nvcc;
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(move || loop {
                    let i = next_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some((source, staging)) = jobs_ref.get(i) else {
                        break;
                    };
                    let output = nvcc_command(nvcc_ref)
                        .args(compile_flags_ref.iter())
                        .arg(source)
                        .arg("-o")
                        .arg(staging)
                        .output()
                        .expect("nvcc was detected but could not be launched");
                    assert!(
                        output.status.success(),
                        "nvcc failed:\nstdout:\n{}\nstderr:\n{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                });
            }
        });
    }
    let object_publications: Vec<(PathBuf, PathBuf)> = staged_objects
        .iter()
        .map(|(staging, object, _)| (staging.clone(), object.clone()))
        .collect();
    publish_validated_artifacts(&object_publications, || {
        if headers_digest(&include_dirs) != header_fingerprint {
            return Err("CUDA headers changed while nvcc was running; retry the build".to_string());
        }
        validate_source_identities(
            object_compiler_fingerprint,
            Some(header_fingerprint),
            &source_identities,
        )?;
        if !compiler_identity_is_current(compiler_identity) {
            return Err(
                "nvcc or its host compiler changed while compiling CUDA objects; retry the build"
                    .to_string(),
            );
        }
        Ok(())
    })
    .unwrap_or_else(|error| panic!("{error}"));
    for (_staging, object, cache_path) in staged_objects {
        if let Some(cached) = cache_path {
            let cache_staging = staging_path(&cached);
            if std::fs::copy(&object, &cache_staging).is_ok() {
                let _ = std::fs::rename(&cache_staging, cached);
            }
        }
    }
    let dlink = out_dir.join("stwo_cuda_kernels_dlink.o");
    let dlink_staging = out_dir.join("stwo_cuda_kernels_dlink.staged.o");
    let _ = std::fs::remove_file(&dlink_staging);
    let mut dlink_argv = vec![
        "-dlink".to_string(),
        "-Xcompiler".to_string(),
        "-fPIC".to_string(),
        compiler_identity.host_flag.to_string(),
    ];
    if archive_lto {
        dlink_argv.push("-dlto".to_string());
    }
    dlink_argv.extend(dlink_gencode_flags.iter().cloned());
    dlink_argv.extend(extra_flags.iter().cloned());
    dlink_argv.extend(
        objects
            .iter()
            .map(|object| object.to_string_lossy().into_owned()),
    );
    dlink_argv.push("-o".to_string());
    dlink_argv.push(dlink_staging.to_string_lossy().into_owned());
    run_nvcc(nvcc_command(&nvcc).args(&dlink_argv));

    let object_payloads = objects
        .iter()
        .map(|object| std::fs::read(object).expect("read exact CUDA TU object payload"))
        .collect::<Vec<_>>();
    let dlink_payload =
        std::fs::read(&dlink_staging).expect("read exact CUDA device-link object payload");
    let source_entries = source_closure
        .iter()
        .map(|(_, path, bytes)| ExactFile { path, bytes })
        .collect::<Vec<_>>();
    assert_eq!(sources.len(), object_argvs.len());
    assert_eq!(sources.len(), object_payloads.len());
    let object_source_paths = sources
        .iter()
        .map(|source| {
            normalized_source_path(source)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect::<Vec<_>>();
    let object_entries = object_source_paths
        .iter()
        .zip(object_argvs.iter())
        .zip(object_payloads.iter())
        .map(|((source_path, argv), bytes)| TuObject {
            source_path,
            argv,
            bytes,
        })
        .collect::<Vec<_>>();
    let identity = static_module_build_identity(&StaticModuleIdentityInput {
        target_sms: &target_sms,
        nvcc: ExecutableIdentity {
            path: &nvcc,
            bytes: &nvcc_executable_bytes,
            version_output: &nvcc_identity,
        },
        host_compiler: ExecutableIdentity {
            path: &host_executable,
            bytes: &host_executable_bytes,
            version_output: &host_version_identity,
        },
        sources: &source_entries,
        objects: &object_entries,
        dlink_argv: &dlink_argv,
        dlink_bytes: &dlink_payload,
    })
    .unwrap_or_else(|error| panic!("invalid static CUDA build identity: {error}"));
    write_static_cuda_module_build_identity(&out_dir, identity, &target_sms);

    let carrier_source = receipt_carrier_source(identity);
    let carrier_source_path = out_dir.join("static_cuda_module_build_identity.cc");
    std::fs::write(&carrier_source_path, &carrier_source)
        .expect("write static CUDA build-identity receipt source");
    let carrier = out_dir.join("static_cuda_module_build_identity.o");
    let carrier_staging = out_dir.join("static_cuda_module_build_identity.staged.o");
    let _ = std::fs::remove_file(&carrier_staging);
    let output = Command::new(&host_executable)
        .args(["-std=c++17", "-O2", "-fPIC", "-c"])
        .arg(&carrier_source_path)
        .arg("-o")
        .arg(&carrier_staging)
        .output()
        .expect("compile static CUDA build-identity receipt carrier");
    assert!(
        output.status.success(),
        "receipt carrier compilation failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let archive = out_dir.join("libstwo_cuda_kernels.a");
    let archive_staging = staging_path(&archive);
    let _ = std::fs::remove_file(&archive_staging);
    let ar = env::var("AR").unwrap_or_else(|_| "ar".to_string());
    let output = Command::new(&ar)
        .arg("crs")
        .arg(&archive_staging)
        .args(&objects)
        .arg(&dlink_staging)
        // The receipt is deliberately last and excluded from `identity`.
        .arg(&carrier_staging)
        .output()
        .expect("ar should be available to archive the kernel objects");
    assert!(
        output.status.success(),
        "ar failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    publish_validated_artifacts(
        &[
            (dlink_staging.clone(), dlink.clone()),
            (carrier_staging, carrier),
            (archive_staging, archive),
        ],
        || {
            validate_static_module_inputs(
                &source_closure,
                &objects,
                &object_payloads,
                &dlink_staging,
                &dlink_payload,
                &nvcc_path,
                &nvcc_executable_bytes,
                std::path::Path::new(&host_executable),
                &host_executable_bytes,
            )?;
            validate_exact_bytes(&carrier_source_path, &carrier_source)?;
            if !compiler_identity_is_current(compiler_identity) {
                return Err(
                    "nvcc or its host compiler changed while linking CUDA archive; retry the build"
                        .to_string(),
                );
            }
            Ok(())
        },
    )
    .unwrap_or_else(|error| panic!("{error}"));

    let aot_snapshot = build_aot_pack(
        &nvcc,
        compiler_identity,
        &archs,
        &extra_flags,
        &out_dir,
        aot_constraint_max_instrs,
        aot_constraint_max_live_u32_lanes,
    );

    assert_eq!(
        kernel_sources(),
        sources,
        "CUDA source set changed while nvcc was running; retry the build"
    );
    let expected_aot_sources: Vec<PathBuf> = aot_snapshot
        .sources
        .iter()
        .map(|(source, ..)| source.clone())
        .collect();
    assert_eq!(
        aot_sources_for_build(),
        expected_aot_sources,
        "generated AOT source set changed while nvcc was running; retry the build"
    );
    let mut final_include_dirs = vec!["cuda".to_string()];
    collect_dirs(std::path::Path::new("cuda"), &mut final_include_dirs);
    final_include_dirs.sort();
    assert_eq!(
        final_include_dirs, include_dirs,
        "CUDA include-directory set changed while nvcc was running; retry the build"
    );
    assert_eq!(
        headers_digest(&final_include_dirs),
        header_fingerprint,
        "CUDA headers changed before build completion; retry the build"
    );
    validate_source_identities(
        object_compiler_fingerprint,
        Some(header_fingerprint),
        &source_identities,
    )
    .unwrap_or_else(|error| panic!("{error}"));
    validate_source_identities(0, None, &aot_snapshot.sources)
        .unwrap_or_else(|error| panic!("{error}"));
    validate_exact_aot_sources(&aot_snapshot.exact_sources)
        .unwrap_or_else(|error| panic!("{error}"));
    validate_source_identities(0, None, std::slice::from_ref(&aot_snapshot.manifest))
        .unwrap_or_else(|error| panic!("{error}"));
    validate_exact_bytes(&aot_snapshot.manifest.0, &aot_snapshot.manifest_bytes)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        generated_aot_constraint_max_instrs(),
        aot_constraint_max_instrs,
        "generated AOT instruction cap changed during build"
    );
    assert_eq!(
        generated_aot_constraint_max_live_u32_lanes(),
        aot_constraint_max_live_u32_lanes,
        "generated AOT live-lane cap changed during build"
    );
    validate_static_module_inputs(
        &source_closure,
        &objects,
        &object_payloads,
        &dlink,
        &dlink_payload,
        &nvcc_path,
        &nvcc_executable_bytes,
        std::path::Path::new(&host_executable),
        &host_executable_bytes,
    )
    .unwrap_or_else(|error| panic!("{error}"));
    validate_exact_bytes(&carrier_source_path, &carrier_source)
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        compiler_identity_is_current(compiler_identity),
        "nvcc or its host compiler changed before build completion; retry the build"
    );

    println!("cargo:rustc-env=STWO_CUDA_BUILD_MODE=cuda");
    println!("cargo:rustc-cfg=stwo_cuda_link");
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    if let Some(lib_dir) = cuda_lib_dir(&nvcc) {
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
    }
    println!("cargo:rustc-link-lib=static=stwo_cuda_kernels");
    println!("cargo:rustc-link-lib=cudart");
    // The JIT runtime (runtime_jit.cu) compiles generated kernels at runtime.
    println!("cargo:rustc-link-lib=nvrtc");
    println!("cargo:rustc-link-lib=cuda");
    // The .cu host code uses C++ exceptions and the C++ runtime.
    println!("cargo:rustc-link-lib=stdc++");
}

fn write_static_cuda_module_build_identity(
    out_dir: &std::path::Path,
    identity: [u8; 32],
    target_sms: &[u32],
) {
    let sms = target_sms
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let contents = format!(
        "pub(crate) const STATIC_CUDA_MODULE_BUILD_IDENTITY: [u8; 32] = {};\n\
         pub(crate) static STATIC_CUDA_MODULE_TARGET_SMS: &[u32] = &[{sms}];\n",
        rust_digest(&identity)
    );
    let destination = out_dir.join("static_cuda_module_build_identity.rs");
    let staging = staging_path(&destination);
    std::fs::write(&staging, contents).expect("write static CUDA build identity constants");
    std::fs::rename(staging, destination).expect("publish static CUDA build identity constants");
}

fn ordinary_cuda_authority_files() -> Vec<PathBuf> {
    let cuda = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("cuda");
    let mut files = Vec::new();
    collect_ordinary_cuda_authority_files(&cuda, &mut files);
    files.sort();
    files.dedup();
    files
}

fn collect_ordinary_cuda_authority_files(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read ordinary CUDA authority directory") {
        let path = entry.expect("read ordinary CUDA authority entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "generated") {
                continue;
            }
            collect_ordinary_cuda_authority_files(&path, out);
        } else if is_ordinary_cuda_authority_file(&path) {
            out.push(path);
        }
    }
}

fn snapshot_ordinary_cuda_sources() -> Vec<(PathBuf, String, Vec<u8>)> {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    ordinary_cuda_authority_files()
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(&manifest)
                .expect("ordinary CUDA source belongs to this crate")
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = std::fs::read(&path).expect("read exact ordinary CUDA source closure");
            (path, relative, bytes)
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn validate_static_module_inputs(
    sources: &[(PathBuf, String, Vec<u8>)],
    objects: &[PathBuf],
    object_payloads: &[Vec<u8>],
    dlink: &std::path::Path,
    dlink_payload: &[u8],
    nvcc: &std::path::Path,
    nvcc_bytes: &[u8],
    host_compiler: &std::path::Path,
    host_compiler_bytes: &[u8],
) -> Result<(), String> {
    let current_sources = ordinary_cuda_authority_files();
    let expected_sources = sources
        .iter()
        .map(|(path, ..)| path.clone())
        .collect::<Vec<_>>();
    if current_sources != expected_sources {
        return Err("ordinary CUDA source closure changed during build; retry".to_string());
    }
    for (path, _, bytes) in sources {
        validate_exact_bytes(path, bytes)?;
    }
    if objects.len() != object_payloads.len() {
        return Err("CUDA object snapshot cardinality changed".to_string());
    }
    for (path, bytes) in objects.iter().zip(object_payloads) {
        validate_exact_bytes(path, bytes)?;
    }
    validate_exact_bytes(dlink, dlink_payload)?;
    validate_exact_bytes(nvcc, nvcc_bytes)?;
    validate_exact_bytes(host_compiler, host_compiler_bytes)
}

/// The compute capability of the local GPU as an `-arch` value (e.g. `sm_86`), queried
/// via `nvidia-smi`. A headless compiler host must set `STWO_CUDA_ARCH` explicitly.
fn detect_arch() -> String {
    Command::new("nvidia-smi")
        .args(["--query-gpu=compute_cap", "--format=csv,noheader"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            let cap = String::from_utf8(output.stdout).ok()?;
            let cap = cap.lines().next()?.trim().replace('.', "");
            (!cap.is_empty()).then(|| format!("sm_{cap}"))
        })
        .unwrap_or_else(|| {
            panic!("could not detect a numeric GPU SM; set STWO_CUDA_ARCH explicitly")
        })
}

/// The toolkit's library directory (for `-lcudart`), from `CUDA_HOME`/`CUDA_PATH` or
/// derived from the nvcc binary's location (`<root>/bin/nvcc` -> `<root>/lib64`).
fn cuda_lib_dir(nvcc: &str) -> Option<PathBuf> {
    let root = env::var_os("CUDA_HOME")
        .or_else(|| env::var_os("CUDA_PATH"))
        .map(PathBuf::from)
        .or_else(|| {
            let which = Command::new("which").arg(nvcc).output().ok()?;
            let path = String::from_utf8(which.stdout).ok()?;
            Some(PathBuf::from(path.trim()).parent()?.parent()?.to_path_buf())
        })?;
    [root.join("lib64"), root.join("lib")]
        .into_iter()
        .find(|dir| dir.is_dir())
}

fn kernel_sources() -> Vec<PathBuf> {
    let cuda_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("cuda");
    let mut sources = Vec::new();
    collect_cu(&cuda_dir, &mut sources);
    sources.sort();
    assert!(!sources.is_empty(), "no .cu kernels found under cuda/");
    sources
}

fn write_static_cuda_source_identity(out_dir: &std::path::Path) {
    const DOMAIN: &[u8] = b"stwo-cuda-static-source-set-v1\0";
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let files = ordinary_cuda_authority_files();

    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(&encoded_len(files.len()));
    for file in files {
        let relative = file
            .strip_prefix(&manifest)
            .expect("static CUDA source belongs to this crate")
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = std::fs::read(&file).expect("read static CUDA authority source");
        hasher.update(&encoded_len(relative.len()));
        hasher.update(relative.as_bytes());
        hasher.update(&encoded_len(bytes.len()));
        hasher.update(&bytes);
    }
    let identity = *hasher.finalize().as_bytes();
    std::fs::write(
        out_dir.join("static_cuda_source_identity.rs"),
        format!(
            "pub(crate) const STATIC_CUDA_SOURCE_IDENTITY: [u8; 32] = {};\n",
            rust_digest(&identity)
        ),
    )
    .expect("write static CUDA source identity");
}

fn encoded_len(value: usize) -> [u8; 8] {
    u64::try_from(value)
        .expect("static CUDA source identity length fits u64")
        .to_le_bytes()
}

fn collect_cu(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("cuda/ kernel directory must exist") {
        let path = entry.expect("readable cuda/ directory entry").path();
        if path.is_dir() {
            // generated/ holds SELF-CONTAINED AOT module sources (kernel_emit):
            // they redefine the field helpers, so they never join the archive —
            // they compile to standalone cubins embedded in the AOT pack.
            if path.file_name().is_some_and(|n| n == "generated") {
                continue;
            }
            collect_cu(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "cu") {
            out.push(path);
        }
    }
}

fn collect_dirs(dir: &std::path::Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("cuda/ directory must exist") {
        let path = entry.expect("readable directory entry").path();
        if path.is_dir() {
            out.push(path.to_string_lossy().into_owned());
            collect_dirs(&path, out);
        }
    }
}

fn generated_aot_sources() -> Vec<PathBuf> {
    let gen_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("cuda")
        .join("generated");
    let mut sources: Vec<PathBuf> = std::fs::read_dir(gen_dir)
        .expect("generated AOT source directory must exist")
        .map(|entry| entry.expect("read generated AOT source entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "cu"))
        .collect();
    sources.sort();
    sources
}

fn aot_sources_for_build() -> Vec<PathBuf> {
    if cfg!(feature = "test-only-empty-aot-pack") {
        Vec::new()
    } else {
        generated_aot_sources()
    }
}

/// Compile every `cuda/generated/*.cu` (kernel_emit output: self-contained AOT
/// module sources named `<kind>_<label>_<cache_key:016x>.cu`) to a standalone
/// cubin per arch at -O3, and embed them as one pack + index. The runtime's
/// `stwo_aot_lookup` (src/aot_pack.rs) serves `get_or_compile`'s tier-0 — a
/// cache-key miss falls back to NVRTC, which IS the drift check (design §4).
///
/// Cubins are cached in OUT_DIR by source content and the exact nvcc invocation:
/// an unchanged kernel never recompiles, while compiler or policy drift selects
/// a new path. SASS generation for the biggest fused kernels is the expensive
/// step — paid per AIR revision at build time, never at prove time.
fn build_aot_pack(
    nvcc: &str,
    compiler_identity: CompilerIdentity<'_>,
    archs: &[String],
    extra_flags: &[String],
    out_dir: &std::path::Path,
    constraint_max_instrs: usize,
    constraint_max_live_u32_lanes: usize,
) -> AotBuildSnapshot {
    let sources = aot_sources_for_build();
    let manifest_path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("cuda")
        .join("generated")
        .join("aot_manifest.json");
    let manifest_arg = normalized_source_path(&manifest_path);
    let manifest_bytes = std::fs::read(&manifest_path).expect("read generated AOT manifest");
    let manifest = parse_source_manifest(&manifest_bytes)
        .unwrap_or_else(|error| panic!("invalid generated AOT manifest: {error}"));
    let manifest_identity = artifact_fingerprint(0, &manifest_arg, &manifest_bytes, None);
    let manifest_sources = manifest
        .iter()
        .map(|entry| manifest_path.parent().unwrap().join(&entry.file))
        .collect::<Vec<_>>();
    if !cfg!(feature = "test-only-empty-aot-pack") {
        assert_eq!(
            sources, manifest_sources,
            "generated AOT source set does not match aot_manifest.json"
        );
    }

    let cubin_dir = out_dir.join("aot_cubins");
    std::fs::create_dir_all(&cubin_dir).expect("create aot cubin cache dir");
    let source_snapshot_dir = out_dir.join("aot_sources");
    std::fs::create_dir_all(&source_snapshot_dir).expect("create AOT source snapshot dir");
    // Collect jobs, then compile stale ones on a bounded worker pool — cubins
    // are independent TUs and SASS -O3 on the big fp256 kernels takes minutes
    // each; serial nvcc dominated the first pod build.
    let mut entries = Vec::new();
    let mut jobs: Vec<(PathBuf, PathBuf, PathBuf, Vec<String>)> = Vec::new();
    let mut source_identities: Vec<(PathBuf, PathBuf, u128)> = Vec::with_capacity(sources.len());
    let mut exact_source_identities = Vec::with_capacity(sources.len());
    for (source, metadata) in sources.iter().zip(&manifest) {
        let source_arg = normalized_source_path(source);
        let stem = source.file_stem().unwrap().to_string_lossy().to_string();
        let source_bytes = std::fs::read(source).expect("read generated AOT source identity");
        if let Some(schema) = metadata.abi_schema {
            validate_structured_kernel_signature(&source_bytes, &metadata.kernel_symbol, schema)
        } else {
            validate_exported_kernel_symbol(&source_bytes, &metadata.kernel_symbol)
        }
        .unwrap_or_else(|error| panic!("invalid generated source {}: {error}", source.display()));
        let exact_source_identity = source_identity(&source_bytes);
        let module_globals = module_globals_for_source(metadata.abi_schema, &source_bytes)
            .unwrap_or_else(|error| {
                panic!(
                    "invalid generated module-global contract {}: {error}",
                    source.display()
                )
            });
        assert_ne!(
            exact_source_identity,
            aot_identity::ZERO_IDENTITY,
            "generated AOT source must be nonempty"
        );
        exact_source_identities.push((source.clone(), exact_source_identity));
        // Compile the exact authorized bytes, not a checkout path that could
        // drift between hashing and a worker invoking nvcc.
        let source_snapshot =
            source_snapshot_dir.join(format!("{stem}_{}.cu", hex_digest(&exact_source_identity)));
        if source_snapshot.is_file() {
            validate_exact_bytes(&source_snapshot, &source_bytes)
                .unwrap_or_else(|error| panic!("{error}"));
        } else {
            std::fs::write(&source_snapshot, &source_bytes)
                .expect("write exact generated AOT source snapshot");
        }
        let build_source_identity = artifact_fingerprint(0, &source_arg, &source_bytes, None);
        source_identities.push((source.clone(), source_arg.clone(), build_source_identity));
        for arch in archs {
            let num: u32 = arch
                .trim_start_matches("sm_")
                .parse()
                .expect("STWO_CUDA_ARCH entries look like sm_90");
            // The fully fused Poseidon partial-round witness reaches the CUDA
            // 11.8 sm_90 register ceiling, where ptxas miscompiles this TU. Keep
            // its generated CUDA and fp256 math unchanged while selecting a
            // conservative ptxas schedule. The flag is part of the exact
            // compiler identity below.
            let ptxas_o0 =
                arch == "sm_90" && stem.starts_with("witness_poseidon_3_partial_rounds_chain_");
            let mut compile_flags = aot_fixed_flags();
            compile_flags.push(compiler_identity.host_flag.to_string());
            compile_flags.push(format!("-arch={arch}"));
            compile_flags.extend(extra_flags.iter().cloned());
            if ptxas_o0 {
                compile_flags.push("-Xptxas=-O0".to_string());
            }
            let compiler =
                compiler_fingerprint(compiler_identity, &compile_flags, AOT_COMPILER_POLICY);
            let artifact = artifact_fingerprint(compiler, &source_arg, &source_bytes, None);
            let cubin = cubin_dir.join(format!("{stem}_{arch}_{artifact:032x}.cubin"));
            if !cubin.is_file() {
                let staging = staging_path(&cubin);
                let _ = std::fs::remove_file(&staging);
                jobs.push((
                    source_snapshot.clone(),
                    staging,
                    cubin.clone(),
                    compile_flags,
                ));
            }
            entries.push(AotBuildEntry {
                cache_key: metadata.cache_key,
                sm: num,
                cubin,
                kernel_symbol: metadata.kernel_symbol.clone(),
                semantic_hash: metadata.semantic_hash,
                source_identity: exact_source_identity,
                abi_schema: metadata.abi_schema,
                program_identity: metadata.program_identity,
                module_globals,
            });
        }
    }
    if !jobs.is_empty() {
        let workers = cuda_build_workers(jobs.len());
        let next = std::sync::atomic::AtomicUsize::new(0);
        let jobs_ref = &jobs;
        let next_ref = &next;
        let nvcc_ref = &nvcc;
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(move || loop {
                    let i = next_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some((source, staging, _cubin, compile_flags)) = jobs_ref.get(i) else {
                        break;
                    };
                    let output = nvcc_command(nvcc_ref)
                        .args(compile_flags.iter())
                        .arg(source)
                        .arg("-o")
                        .arg(staging)
                        .output()
                        .expect("nvcc launch for AOT cubin");
                    assert!(
                        output.status.success(),
                        "nvcc -cubin failed for {}:\n{}",
                        source.display(),
                        String::from_utf8_lossy(&output.stderr)
                    );
                });
            }
        });
    }
    let aot_publications: Vec<(PathBuf, PathBuf)> = jobs
        .iter()
        .map(|(_source, staging, cubin, _flags)| (staging.clone(), cubin.clone()))
        .collect();
    publish_validated_artifacts(&aot_publications, || {
        validate_source_identities(0, None, &source_identities)?;
        validate_exact_aot_sources(&exact_source_identities)?;
        validate_source_identities(
            0,
            None,
            std::slice::from_ref(&(
                manifest_path.clone(),
                manifest_arg.clone(),
                manifest_identity,
            )),
        )?;
        validate_exact_bytes(&manifest_path, &manifest_bytes)?;
        if !compiler_identity_is_current(compiler_identity) {
            return Err(
                "nvcc or its host compiler changed while compiling AOT cubins; retry the build"
                    .to_string(),
            );
        }
        Ok(())
    })
    .unwrap_or_else(|error| panic!("{error}"));
    write_aot_pack(
        out_dir,
        &entries,
        constraint_max_instrs,
        constraint_max_live_u32_lanes,
    );
    AotBuildSnapshot {
        sources: source_identities,
        exact_sources: exact_source_identities,
        manifest: (manifest_path, manifest_arg, manifest_identity),
        manifest_bytes,
    }
}

/// Concatenate cubins into `aot_pack.bin` + emit `aot_index.rs` (sorted by
/// (cache_key, sm)). Always written — an empty pack keeps the stub build and
/// include_bytes! happy.
fn write_aot_pack(
    out_dir: &std::path::Path,
    entries: &[AotBuildEntry],
    constraint_max_instrs: usize,
    constraint_max_live_u32_lanes: usize,
) {
    let mut blobs = entries
        .iter()
        .map(|entry| {
            (
                entry,
                std::fs::read(&entry.cubin).expect("read generated AOT cubin"),
            )
        })
        .collect::<Vec<_>>();
    blobs.sort_by_key(|(entry, _)| (entry.cache_key, entry.sm));
    let identity_inputs = blobs
        .iter()
        .map(|(entry, bytes)| CubinIdentityInput {
            cache_key: entry.cache_key,
            sm: entry.sm,
            bytes,
        })
        .collect::<Vec<_>>();
    let pack_digest = pack_identity(
        constraint_max_instrs,
        constraint_max_live_u32_lanes,
        &identity_inputs,
    );
    let mut pack: Vec<u8> = Vec::new();
    let mut index = Vec::new();
    for ((entry, _), input) in blobs.iter().zip(identity_inputs) {
        let exact_cubin_identity = cubin_identity(input);
        let exact_abi_identity = entry
            .abi_schema
            .map(AotKernelAbiSchema::identity)
            .unwrap_or(aot_identity::ZERO_IDENTITY);
        let exact_schema_scope = if entry.abi_schema.is_some() {
            AotKernelSchemaScope::StructuredAbi
        } else {
            AotKernelSchemaScope::ExportedSymbolOnly
        };
        let authority_identity = kernel_authority_identity(KernelAuthorityIdentityInput {
            source_identity: entry.source_identity,
            kernel_symbol: &entry.kernel_symbol,
            semantic_hash: entry.semantic_hash,
            cache_key: entry.cache_key,
            sm: entry.sm,
            cubin_identity: exact_cubin_identity,
            abi_schema_identity: exact_abi_identity,
            program_identity: entry.program_identity,
            schema_scope: exact_schema_scope,
            module_globals: entry.module_globals,
        });
        assert_ne!(
            authority_identity,
            aot_identity::ZERO_IDENTITY,
            "generated AOT kernel authority must be nonzero"
        );
        index.push((
            entry,
            pack.len(),
            input.bytes.len(),
            exact_cubin_identity,
            exact_abi_identity,
            exact_schema_scope,
            authority_identity,
        ));
        pack.extend_from_slice(input.bytes);
    }
    std::fs::write(out_dir.join("aot_pack.bin"), &pack).expect("write aot pack");
    let mut rs = String::from(
        "// Generated by build.rs — exact identities for aot_pack.bin.\n         static AOT_INDEX: &[AotIndexEntry] = &[\n",
    );
    for (entry, off, len, cubin_digest, abi_digest, scope, authority_digest) in &index {
        let abi_schema = match entry.abi_schema {
            Some(AotKernelAbiSchema::RecordedWitnessV1) => {
                "Some(AotKernelAbiSchema::RecordedWitnessV1)"
            }
            Some(AotKernelAbiSchema::OrdinaryConstraintV1) => {
                "Some(AotKernelAbiSchema::OrdinaryConstraintV1)"
            }
            Some(AotKernelAbiSchema::CompositionWaveV2) => {
                "Some(AotKernelAbiSchema::CompositionWaveV2)"
            }
            None => "None",
        };
        let scope = match scope {
            aot_identity::AotKernelSchemaScope::ExportedSymbolOnly => {
                "AotKernelSchemaScope::ExportedSymbolOnly"
            }
            aot_identity::AotKernelSchemaScope::StructuredAbi => {
                "AotKernelSchemaScope::StructuredAbi"
            }
        };
        let module_globals = match entry.module_globals {
            AotKernelModuleGlobals::Unspecified => "AotKernelModuleGlobals::Unspecified",
            AotKernelModuleGlobals::None => "AotKernelModuleGlobals::None",
            AotKernelModuleGlobals::WitnessPedersenV1 => {
                "AotKernelModuleGlobals::WitnessPedersenV1"
            }
        };
        rs.push_str(&format!(
            "    AotIndexEntry {{ offset: {off}, len: {len}, authority: AotKernelAuthority {{ \
             source_identity: {}, kernel_symbol: {:?}, semantic_hash: 0x{:016x}, \
             cache_key: 0x{:016x}, target_sm: {}, cubin_identity: {}, abi_schema: {abi_schema}, \
             abi_schema_identity: {}, program_identity: {}, identity: {}, \
             schema_scope: {scope}, module_globals: {module_globals} }} }},\n",
            rust_digest(&entry.source_identity),
            entry.kernel_symbol,
            entry.semantic_hash,
            entry.cache_key,
            entry.sm,
            rust_digest(cubin_digest),
            rust_digest(abi_digest),
            rust_digest(&entry.program_identity),
            rust_digest(authority_digest),
        ));
    }
    rs.push_str("];\n");
    rs.push_str(&format!(
        "pub(crate) const AOT_PACK_IDENTITY: [u8; 32] = {};\n",
        rust_digest(&pack_digest)
    ));
    rs.push_str(&format!(
        "pub(crate) const AOT_CONSTRAINT_MAX_INSTRS: usize = {constraint_max_instrs};\n"
    ));
    rs.push_str(&format!(
        "pub(crate) const AOT_CONSTRAINT_MAX_LIVE_U32_LANES: usize = \
         {constraint_max_live_u32_lanes};\n"
    ));
    std::fs::write(out_dir.join("aot_index.rs"), rs).expect("write aot index");
}

fn rust_digest(digest: &[u8; 32]) -> String {
    let bytes = digest
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{bytes}]")
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_exact_aot_sources(sources: &[(PathBuf, [u8; 32])]) -> Result<(), String> {
    for (path, identity) in sources {
        let bytes =
            std::fs::read(path).map_err(|error| format!("re-read {}: {error}", path.display()))?;
        if source_identity(&bytes) != *identity {
            return Err(format!(
                "{} changed while nvcc was running; retry the build",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_exact_bytes(path: &std::path::Path, expected: &[u8]) -> Result<(), String> {
    let current =
        std::fs::read(path).map_err(|error| format!("re-read {}: {error}", path.display()))?;
    if current != expected {
        return Err(format!(
            "{} changed while nvcc was running; retry the build",
            path.display()
        ));
    }
    Ok(())
}

fn generated_aot_constraint_max_instrs() -> usize {
    let path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("cuda")
        .join("generated")
        .join("aot_constraint_max_instrs.txt");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "generated AOT constraint cap is missing at {}: {error}",
            path.display()
        )
    });
    let cap = raw.trim().parse::<usize>().unwrap_or_else(|error| {
        panic!(
            "invalid generated AOT constraint cap at {}: {error}",
            path.display()
        )
    });
    assert!(cap > 0, "generated AOT constraint cap must be non-zero");
    cap
}

fn generated_aot_constraint_max_live_u32_lanes() -> usize {
    let path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("cuda")
        .join("generated")
        .join("aot_constraint_max_live_u32_lanes.txt");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "generated AOT constraint live-lane cap is missing at {}: {error}",
            path.display()
        )
    });
    let cap = raw.trim().parse::<usize>().unwrap_or_else(|error| {
        panic!(
            "invalid generated AOT constraint live-lane cap at {}: {error}",
            path.display()
        )
    });
    assert!(
        cap > 0,
        "generated AOT constraint live-lane cap must be non-zero"
    );
    cap
}

#[cfg(test)]
#[path = "build_fingerprint_tests.rs"]
mod tests;
