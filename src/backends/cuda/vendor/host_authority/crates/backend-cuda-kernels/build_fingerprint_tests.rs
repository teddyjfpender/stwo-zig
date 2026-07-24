use super::*;

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn compiler<'a>(command: &'a str, version: &'a [u8]) -> CompilerIdentity<'a> {
    CompilerIdentity {
        executable: command,
        command,
        version,
        host_executable: "/usr/bin/c++",
        host_command: "/usr/bin/c++",
        host_version: b"c++ 12.2",
        host_flag: "-ccbin=/usr/bin/c++",
    }
}

#[test]
fn archive_lto_policy_is_strict_and_preserves_default_gencode() {
    assert_eq!(parse_archive_lto(None), Ok(false));
    assert_eq!(parse_archive_lto(Some("0")), Ok(false));
    assert_eq!(parse_archive_lto(Some("1")), Ok(true));
    for invalid in ["", "2", "true", " 1"] {
        assert!(parse_archive_lto(Some(invalid)).is_err(), "{invalid:?}");
    }

    assert_eq!(
        archive_gencode_flags(&[86, 90], false),
        strings(&[
            "-gencode",
            "arch=compute_86,code=sm_86",
            "-gencode",
            "arch=compute_90,code=sm_90",
        ])
    );
    assert_eq!(
        archive_gencode_flags(&[86, 90], true),
        strings(&[
            "-gencode",
            "arch=compute_86,code=lto_86",
            "-gencode",
            "arch=compute_90,code=lto_90",
        ])
    );

    for global_lto in [
        "-dlto",
        "--dlink-time-opt",
        "-lto",
        "--lto",
        "-gen-opt-lto",
        "--gen-opt-lto",
        "-ltoir",
        "--ltoir",
    ] {
        assert!(validate_extra_flags(&strings(&[global_lto])).is_err());
    }
}

#[test]
fn command_path_tracks_existing_explicit_executables_but_not_missing_paths() {
    let existing = std::env::current_exe().unwrap();
    assert_eq!(
        command_path(existing.to_str().unwrap()).as_deref(),
        Some(existing.as_path())
    );

    let missing = staging_path(&existing);
    assert!(!missing.exists());
    assert_eq!(command_path(missing.to_str().unwrap()), None);
}

#[test]
fn compiler_fingerprint_covers_exact_invocation_and_policy() {
    let version = b"Cuda compilation tools, release 12.6";
    let flags = strings(&[
        "-dc",
        "-O3",
        "-gencode",
        "arch=compute_90,code=sm_90",
        "-DUSER_FLAG=1",
    ]);
    let baseline = compiler_fingerprint(
        compiler("/cuda/bin/nvcc", version),
        &flags,
        OBJECT_COMPILER_POLICY,
    );
    let changed = |command, version: &[u8], flags: &[String], policy| {
        assert_ne!(
            baseline,
            compiler_fingerprint(compiler(command, version), flags, policy)
        );
    };

    changed("/wrapper/bin/nvcc", version, &flags, OBJECT_COMPILER_POLICY);
    changed(
        "/cuda/bin/nvcc",
        b"nvcc 12.7",
        &flags,
        OBJECT_COMPILER_POLICY,
    );
    changed("/cuda/bin/nvcc", version, &flags, AOT_COMPILER_POLICY);
    let mut changed_host = compiler("/cuda/bin/nvcc", version);
    changed_host.host_version = b"c++ 13.1";
    assert_ne!(
        baseline,
        compiler_fingerprint(changed_host, &flags, OBJECT_COMPILER_POLICY)
    );
    for (index, replacement) in [
        (0, "-cubin"),
        (1, "-O2"),
        (3, "arch=compute_89,code=sm_89"),
        (4, "-DUSER_FLAG=2"),
    ] {
        let mut flags = flags.clone();
        flags[index] = replacement.to_string();
        changed("/cuda/bin/nvcc", version, &flags, OBJECT_COMPILER_POLICY);
    }
    assert_ne!(
        compiler_fingerprint(compiler("nvcc", version), &strings(&["ab", "c"]), "policy"),
        compiler_fingerprint(compiler("nvcc", version), &strings(&["a", "bc"]), "policy")
    );
    let command = nvcc_command("nvcc");
    for variable in ["NVCC_PREPEND_FLAGS", "NVCC_APPEND_FLAGS", "NVCC_CCBIN"] {
        assert!(command
            .get_envs()
            .any(|(name, value)| name == variable && value.is_none()));
    }
    assert!(validate_extra_flags(&strings(&["-lineinfo", "-ccbin=/other/c++"])).is_err());
    for selector in [
        "-arch",
        "-arch=sm_89",
        "--arch=sm_89",
        "--gpu-architecture",
        "--gpu-architecture=sm_89",
        "--gpu-name=sm_89",
        "-code",
        "-code=sm_89",
        "--gpu-code",
        "--gpu-code=sm_89",
        "-gencode",
        "-gencode=arch=compute_89,code=sm_89",
        "--generate-code",
        "--generate-code=arch=compute_89,code=sm_89",
        "-optf",
        "-optf=/tmp/nvcc.flags",
        "--options-file",
        "--options-file=/tmp/nvcc.flags",
        "-prune",
        "--prune",
        "-Xnvprune=-arch=sm_89",
        "--nvprune-options=-optf=/tmp/nvprune.flags",
    ] {
        assert!(
            validate_extra_flags(&strings(&["-lineinfo", selector])).is_err(),
            "unsafe nvcc selector escaped admission: {selector}"
        );
    }
    for forwarded in [
        &["-Xptxas=-arch=sm_89"][..],
        &["--ptxas-options=--gpu-name=sm_89"][..],
        &["-Xptxas=-v,-optf=/tmp/ptxas.flags"][..],
        &["--ptxas-options=--options-file=/tmp/ptxas.flags"][..],
        &["-Xptxas", "-v,-arch=sm_89"][..],
        &["-Xnvlink=-arch=sm_89"][..],
        &["--nvlink-options=--arch=sm_89"][..],
        &["-Xnvlink=--Xptxas=-arch=sm_89"][..],
        &["--nvlink-options=-Xptxas=--gpu-name=sm_89"][..],
        &["-Xnvlink=-v,-optf=/tmp/nvlink.flags"][..],
        &["--nvlink-options", "--options-file=/tmp/nvlink.flags"][..],
    ] {
        assert!(
            validate_extra_flags(&strings(forwarded)).is_err(),
            "forwarded selector escaped admission: {forwarded:?}"
        );
    }
    assert!(validate_extra_flags(&strings(&["-lineinfo", "-Xptxas=-v"])).is_ok());
    assert!(validate_extra_flags(&strings(&["-Xptxas=-v,-O3"])).is_ok());
}

#[test]
fn artifact_fingerprint_covers_source_headers_and_compiler() {
    let compiler = compiler_fingerprint(
        compiler("nvcc", b"nvcc 12.6"),
        &strings(&["-cubin", "-O3", "-arch=sm_90"]),
        AOT_COMPILER_POLICY,
    );
    let source = std::path::Path::new("cuda/generated/kernel.cu");
    let baseline = artifact_fingerprint(compiler, source, b"kernel source", Some(7));
    for changed in [
        artifact_fingerprint(compiler.wrapping_add(1), source, b"kernel source", Some(7)),
        artifact_fingerprint(compiler, source, b"changed source", Some(7)),
        artifact_fingerprint(compiler, source, b"kernel source", Some(8)),
        artifact_fingerprint(compiler, source, b"kernel source", None),
        artifact_fingerprint(
            compiler,
            std::path::Path::new("cuda/other/kernel.cu"),
            b"kernel source",
            Some(7),
        ),
    ] {
        assert_ne!(baseline, changed);
    }
    assert_eq!(format!("{baseline:032x}").len(), 32);
}

#[test]
fn aot_cubin_freshness_changes_path_for_source_or_compiler_drift() {
    let source_arg = std::path::Path::new("cuda/generated/witness_deadbeef.cu");
    let flags = strings(&["-cubin", "-O3", "-arch=sm_90"]);
    let compiler_v1 =
        compiler_fingerprint(compiler("nvcc", b"nvcc 12.6"), &flags, AOT_COMPILER_POLICY);
    let compiler_v2 =
        compiler_fingerprint(compiler("nvcc", b"nvcc 12.7"), &flags, AOT_COMPILER_POLICY);
    let original = artifact_fingerprint(compiler_v1, source_arg, b"generated source", None);
    assert_ne!(
        original,
        artifact_fingerprint(compiler_v2, source_arg, b"generated source", None)
    );
    assert_ne!(
        original,
        artifact_fingerprint(compiler_v1, source_arg, b"changed source", None)
    );
}

#[test]
fn changed_input_cannot_publish_old_key_and_cache_restore_is_staged() {
    let root = staging_path(&std::env::temp_dir().join("stwo-cuda-cache-test"));
    std::fs::create_dir_all(&root).unwrap();
    let source = root.join("kernel.cu");
    let source_arg = std::path::Path::new("cuda/kernel.cu");
    let final_object = root.join("kernel.o");
    std::fs::write(&source, b"original").unwrap();
    let expected = current_artifact_fingerprint(7, &source, source_arg, Some(11)).unwrap();

    let compiled_staging = staging_path(&final_object);
    std::fs::write(&compiled_staging, b"compiled original").unwrap();
    std::fs::write(&source, b"mutated during compile").unwrap();
    let identities = vec![(source.clone(), source_arg.to_path_buf(), expected)];
    let publications = vec![(compiled_staging.clone(), final_object.clone())];
    assert!(publish_validated_artifacts(&publications, || {
        validate_source_identities(7, Some(11), &identities)
    })
    .is_err());
    assert!(!final_object.exists());

    std::fs::write(&source, b"original").unwrap();
    publish_validated_artifacts(&publications, || {
        validate_source_identities(7, Some(11), &identities)
    })
    .unwrap();
    assert_eq!(std::fs::read(&final_object).unwrap(), b"compiled original");

    let persistent = root.join("persistent.o");
    let restored = root.join("restored.o");
    std::fs::write(&persistent, b"cached object").unwrap();
    let restore_staging = stage_cached_artifact(&persistent, &restored).unwrap();
    assert_ne!(restore_staging, restored);
    assert!(!restored.exists());
    publish_validated_artifacts(&[(restore_staging, restored.clone())], || Ok(())).unwrap();
    assert_eq!(std::fs::read(&restored).unwrap(), b"cached object");
    assert!(stage_cached_artifact(&root.join("miss.o"), &restored).is_none());

    std::fs::remove_dir_all(root).unwrap();
}
