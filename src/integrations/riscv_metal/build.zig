const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const error_tracing = b.option(
        bool,
        "error-tracing",
        "Keep error return traces in the retained Stage101 commands (diagnostic builds only)",
    ) orelse false;
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const prover = b.dependency(
        "stwo_prover_engine",
        dependency_options,
    ).module("stwo_prover_engine");
    const prover_api = b.dependency(
        "stwo_prover_api",
        dependency_options,
    ).module("stwo_prover_api");
    const metal_backend = b.dependency(
        "stwo_metal_backend",
        dependency_options,
    ).module("stwo_metal_backend");
    const frontend_dependency = b.dependency(
        "stwo_riscv_frontend",
        dependency_options,
    );
    const frontend = frontend_dependency.module("stwo_riscv_frontend");
    const cpu_stage101_degree5_metal = b.dependency(
        "stwo_riscv_cpu_integration",
        dependency_options,
    ).module("stwo_riscv_cpu_stage101_degree5_metal");
    const tree0_probe_root = b.dependency("stwo_riscv_cpu_integration", dependency_options)
        .module("stwo_riscv_cpu_ethereum_tree0_probe");
    const tree0_backend_policy = b.createModule(.{
        .root_source_file = b.path("ethereum_tree0_probe_backend.zig"),
        .target = target,
        .optimize = optimize,
    });
    tree0_backend_policy.addImport("stwo_metal_backend", metal_backend);
    tree0_probe_root.addImport("ethereum_tree0_probe_backend", tree0_backend_policy);
    const tree0_probe = b.addTest(.{
        .root_module = tree0_probe_root,
        .filters = &.{"role0 saved Stage101 pair compares CPU and authenticated Metal Tree0 admission"},
    });
    const tree0_run = b.addRunArtifact(tree0_probe);
    tree0_run.has_side_effects = true;
    b.step("test-ethereum-wrapper-tree0", "Compare the same admitted wrapper Tree0 on CPU and authenticated Metal PCS; no wrapper proof")
        .dependOn(&tree0_run.step);
    b.step("check-ethereum-wrapper-tree0", "Compile the explicit CPU/Metal Tree0 admission comparison")
        .dependOn(&tree0_probe.step);

    const secp256k1_proof_harness =
        frontend_dependency.module("secp256k1_proof_harness");
    const keccakf_proof_harness =
        frontend_dependency.module("keccakf_proof_harness");
    const integration = b.addModule("stwo_riscv_metal_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_core", core);
    integration.addImport("stwo_prover_api", prover_api);
    integration.addImport("stwo_prover_engine", prover);
    integration.addImport("stwo_metal_backend", metal_backend);
    integration.addImport("stwo_riscv_frontend", frontend);

    const test_step = b.step(
        "test",
        "Run device-free stwo_riscv_metal_integration contract tests",
    );
    const authenticated_aot_step = b.step(
        "test-authenticated-aot",
        "Run the guest Poseidon2 proof on a real device with authenticated AOT",
    );
    const secp256k1_proof_step = b.step(
        "test-secp256k1-precompile-proof",
        "Prove compact typed secp256k1 ECDSA on Metal and verify independently",
    );
    const keccakf_proof_step = b.step(
        "test-keccakf-precompile-proof",
        "Prove compact typed Keccak-f on Metal and verify independently",
    );
    const stage101_test_step = b.step(
        "test-stage101-leaf-autoresearch-v1",
        "Test the isolated exact Poseidon/q193 Stage101 Metal contract",
    );
    const stage101_compile_step = b.step(
        "build-stage101-leaf-autoresearch-v1",
        "Compile the isolated Stage101 Metal autoresearch command",
    );
    const stage101_install_step = b.step(
        "install-stage101-leaf-autoresearch-v1",
        "Materialize the isolated Stage101 Metal autoresearch command",
    );
    const stage101_benchmark_step = b.step(
        "benchmark-stage101-leaf-autoresearch-v1",
        "Run one retained Stage101 leaf on authenticated-AOT Metal",
    );
    const prepared_metal_test_step = b.step("test-ethereum-prepared-leaf-metal-v1", "Test production prepared Metal leaf option and AOT admission");
    const prepared_metal_install_step = b.step("install-ethereum-prepared-leaf-metal-v1", "Build the authenticated Metal full-leaf producer with independent CPU verification");
    const d5_sweep_test_step = b.step(
        "test-stage101-degree5-provider-sweep-v1",
        "Test the retained q193 D5 provider Metal sweep contract",
    );
    const d5_sweep_compile_step = b.step(
        "build-stage101-degree5-provider-sweep-v1",
        "Compile the retained q193 D5 provider Metal sweep command",
    );
    const d5_sweep_install_step = b.step(
        "install-stage101-degree5-provider-sweep-v1",
        "Materialize the retained q193 D5 provider Metal sweep command",
    );
    if (target.result.os.tag != .macos) {
        const unsupported = b.addFail(
            "stwo_riscv_metal_integration tests require macOS and the Apple Metal SDK",
        );
        test_step.dependOn(&unsupported.step);
        authenticated_aot_step.dependOn(&unsupported.step);
        secp256k1_proof_step.dependOn(&unsupported.step);
        keccakf_proof_step.dependOn(&unsupported.step);
        stage101_test_step.dependOn(&unsupported.step);
        stage101_compile_step.dependOn(&unsupported.step);
        stage101_install_step.dependOn(&unsupported.step);
        stage101_benchmark_step.dependOn(&unsupported.step);
        prepared_metal_test_step.dependOn(&unsupported.step);
        prepared_metal_install_step.dependOn(&unsupported.step);
        d5_sweep_test_step.dependOn(&unsupported.step);
        d5_sweep_compile_step.dependOn(&unsupported.step);
        d5_sweep_install_step.dependOn(&unsupported.step);
        return;
    }
    const small_recursive_runner = b.createModule(.{
        .root_source_file = b.path("recursive_segment_v2_detached_leaf_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    small_recursive_runner.addImport("stwo_metal_backend", metal_backend);
    small_recursive_runner.addImport("stwo_riscv_detached_leaf_runner", b.dependency(
        "stwo_riscv_cpu_integration",
        dependency_options,
    ).module("stwo_riscv_detached_leaf_runner"));
    const small_recursive_executable = b.addExecutable(.{
        .name = "recursive-segment-v2-detached-leaf-prove-metal",
        .root_module = small_recursive_runner,
    });
    linkMetalFrameworks(small_recursive_executable);
    const small_recursive_run = b.addRunArtifact(small_recursive_executable);
    if (b.args) |args| small_recursive_run.addArgs(args);
    small_recursive_run.has_side_effects = true;
    b.step("run-recursive-segment-v2-detached-leaf-producer", "Run the shared small recursive proof with explicit native CPU or authenticated Metal")
        .dependOn(&small_recursive_run.step);
    b.step("check-recursive-segment-v2-detached-leaf-producer", "Compile the shared small recursive CPU/Metal proof driver")
        .dependOn(&small_recursive_executable.step);
    b.step("build-recursive-segment-v2-detached-leaf-producer", "Install the shared small recursive CPU/Metal proof driver")
        .dependOn(&b.addInstallArtifact(small_recursive_executable, .{}).step);

    const detached_parent_runner = b.createModule(.{
        .root_source_file = b.path("recursive_segment_v2_detached_parent_producer_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    detached_parent_runner.addImport("stwo_metal_backend", metal_backend);
    detached_parent_runner.addImport("stwo_riscv_frontend", frontend);
    detached_parent_runner.addImport("stwo_riscv_detached_parent_producer", b.dependency(
        "stwo_riscv_cpu_integration",
        dependency_options,
    ).module("stwo_riscv_detached_parent_producer"));
    const detached_parent_exe = b.addExecutable(.{
        .name = "recursive-segment-v2-detached-parent-prove-metal",
        .root_module = detached_parent_runner,
    });
    linkMetalFrameworks(detached_parent_exe);
    b.step("build-recursive-segment-v2-detached-parent-producer", "Build the shared detached parent transaction on authenticated Metal")
        .dependOn(&b.addInstallArtifact(detached_parent_exe, .{}).step);

    const tests = b.addTest(.{ .root_module = integration });
    const ethereum_node_root = b.createModule(.{
        .root_source_file = b.path("ethereum_node_proof_v1_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    ethereum_node_root.addImport("stwo_metal_backend", metal_backend);
    ethereum_node_root.addImport("stwo_riscv_frontend", frontend);
    const ethereum_node_exe = b.addExecutable(.{ .name = "ethereum-node-proof-v1-metal", .root_module = ethereum_node_root });
    linkMetalFrameworks(ethereum_node_exe);
    const ethereum_node_run = b.addRunArtifact(ethereum_node_exe);
    if (b.args) |args| ethereum_node_run.addArgs(args);
    ethereum_node_run.has_side_effects = true;
    b.step("run-ethereum-node-proof-v1", "Prove Ethereum node callers and providers using authenticated Metal AOT").dependOn(&ethereum_node_run.step);
    linkMetalFrameworks(tests);
    test_step.dependOn(&b.addRunArtifact(tests).step);

    const stage101_module = b.createModule(.{
        .root_source_file = b.path("stage101_leaf_autoresearch_v1.zig"),
        .target = target,
        .optimize = optimize,
    });
    stage101_module.addImport("stwo_metal_backend", metal_backend);
    // The leaf and its opt-in `--provider-route degree5-omit-v1` command
    // (stage101_leaf_degree5_provider_v1.zig) share one CPU facade: the
    // degree-five facade is a superset of `stwo_riscv_cpu_stage101_metal`, and
    // Zig refuses a source file that belongs to two modules of one
    // compilation, so the narrower facade is not imported here as well.
    stage101_module.addImport(
        "stwo_riscv_cpu_stage101_degree5_metal",
        cpu_stage101_degree5_metal,
    );
    stage101_module.addImport("stwo_riscv_frontend", frontend);
    stage101_module.addImport("stwo_core", core);
    stage101_module.addImport("stwo_prover_engine", prover);
    const stage101_tests = b.addTest(.{
        .root_module = stage101_module,
        .filters = &.{
            "Stage101 Metal engine preserves the exact q193 Poseidon protocol",
            "Stage101 explicit benchmark tuple binds reference bytes and claim schema",
            "Stage101 explicit benchmark tuple rejects unknown versions and malformed digests",
            "Stage101 benchmark tuple explicitly pins small circle placement and preserves legacy default",
            "Stage101 benchmark tuple explicitly admits fixed program schema five without changing legacy",
            "Stage101 legacy benchmark admission retains exact reference and AOT pins",
            "Stage101 fixed program selects separate AOT authority and legacy keeps core",
            "Stage101 fixed program inventory borrow has explicit preparation receipt counts",
            "Stage101 real leaf placement receipt admits zero small transforms and rejects other host work",
            "Stage101 five-second budget is exact and fail closed by stage",
            "Stage101 worker matrix is current-host evidence not a protocol cap",
            "Stage101 Metal coverage rejects missing and host fallback work",
            "Stage101 Poseidon Merkle device family is typed and seedless",
            "Stage101 Poseidon polynomial residency accepts exact u64 tree maps",
            "Stage101 degree-five provider AOT roster is four direct plus one lookup",
            "Stage101 D5 route strips only its own flag and rejects unknown route values",
            "Stage101 D5 route Metal coverage admits only small-circle host placements",
            "Stage101 D5 route bundle pins reject a drifted manifest",
        },
    });
    linkMetalFrameworks(stage101_tests);
    stage101_test_step.dependOn(&b.addRunArtifact(stage101_tests).step);

    const stage101_main = b.createModule(.{
        .root_source_file = b.path("stage101_leaf_autoresearch_main_v1.zig"),
        .target = target,
        .optimize = optimize,
    });
    stage101_main.addImport("stage101_leaf_autoresearch_v1", stage101_module);
    const stage101_executable = b.addExecutable(.{
        .name = "stage101-metal-autoresearch-v1",
        .root_module = stage101_main,
    });
    linkMetalFrameworks(stage101_executable);
    stage101_compile_step.dependOn(&stage101_executable.step);
    const stage101_install = b.addInstallArtifact(stage101_executable, .{});
    stage101_install_step.dependOn(&stage101_install.step);

    const prepared_metal_module = b.createModule(.{
        .root_source_file = b.path("ethereum_prepared_leaf_metal_v1.zig"),
        .target = target,
        .optimize = optimize,
    });
    prepared_metal_module.addImport("stwo_metal_backend", metal_backend);
    prepared_metal_module.addImport("stwo_riscv_frontend", frontend);
    prepared_metal_module.addImport("stwo_riscv_cpu_stage101_degree5_metal", cpu_stage101_degree5_metal);
    const prepared_metal_tests = b.addTest(.{ .root_module = prepared_metal_module, .filters = &.{"prepared Metal "} });
    linkMetalFrameworks(prepared_metal_tests);
    prepared_metal_test_step.dependOn(&b.addRunArtifact(prepared_metal_tests).step);
    const prepared_metal_executable = b.addExecutable(.{ .name = "ethereum-prepared-leaf-metal-v1", .root_module = prepared_metal_module });
    linkMetalFrameworks(prepared_metal_executable);
    prepared_metal_install_step.dependOn(&b.addInstallArtifact(prepared_metal_executable, .{}).step);

    const d5_sweep_module = b.createModule(.{
        .error_tracing = error_tracing,
        .root_source_file = b.path("stage101_degree5_provider_sweep_v1.zig"),
        .target = target,
        .optimize = optimize,
    });
    d5_sweep_module.addImport("stwo_metal_backend", metal_backend);
    d5_sweep_module.addImport(
        "stwo_riscv_cpu_stage101_degree5_metal",
        cpu_stage101_degree5_metal,
    );
    d5_sweep_module.addImport("stwo_riscv_frontend", frontend);
    d5_sweep_module.addImport("stwo_core", core);
    const d5_sweep_tests = b.addTest(.{
        .root_module = d5_sweep_module,
        .filters = &.{
            "Stage101 D5 retained first arm pins exact q193 log18 topology",
            "Stage101 D5 backend identity pins authenticated ABI21 custody",
        },
    });
    linkMetalFrameworks(d5_sweep_tests);
    d5_sweep_test_step.dependOn(&b.addRunArtifact(d5_sweep_tests).step);

    const d5_sweep_main = b.createModule(.{
        .error_tracing = error_tracing,
        .root_source_file = b.path("stage101_degree5_provider_sweep_main_v1.zig"),
        .target = target,
        .optimize = optimize,
    });
    d5_sweep_main.addImport(
        "stage101_degree5_provider_sweep_v1",
        d5_sweep_module,
    );
    const d5_sweep_executable = b.addExecutable(.{
        .name = "stage101-degree5-provider-sweep-v1",
        .root_module = d5_sweep_main,
    });

    // Semantic-only gates.  A Compile whose emitted binary nothing requests is
    // passed `-fno-emit-bin`, so `zig build check-*` runs analysis without
    // LLVM codegen or linking.  A full ReleaseFast product build of either
    // command is about ten minutes; these are tens of seconds, which is the
    // difference between iterating on this campaign and waiting on it.
    const check_step = b.step(
        "check",
        "Analyse both Stage101 Metal commands without emitting binaries",
    );
    const check_targets = [_]struct {
        name: []const u8,
        description: []const u8,
        module: *std.Build.Module,
    }{
        .{
            .name = "check-stage101-leaf-autoresearch-v1",
            .description = "Analyse the Stage101 leaf command without emitting a binary",
            .module = stage101_main,
        },
        .{
            .name = "check-stage101-degree5-provider-sweep-v1",
            .description = "Analyse the retained D5 provider sweep without emitting a binary",
            .module = d5_sweep_main,
        },
    };
    for (check_targets) |entry| {
        const analysis = b.addExecutable(.{
            .name = entry.name,
            .root_module = entry.module,
        });
        linkMetalFrameworks(analysis);
        b.step(entry.name, entry.description).dependOn(&analysis.step);
        check_step.dependOn(&analysis.step);
    }
    linkMetalFrameworks(d5_sweep_executable);
    d5_sweep_compile_step.dependOn(&d5_sweep_executable.step);
    const d5_sweep_install = b.addInstallArtifact(d5_sweep_executable, .{});
    d5_sweep_install_step.dependOn(&d5_sweep_install.step);

    const configured_bundle = b.option(
        []const u8,
        "metal-core-aot-bundle",
        "Absolute authenticated core AOT bundle for real-device acceptance",
    ) orelse {
        const missing_bundle = b.addFail(
            "test-authenticated-aot requires -Dmetal-core-aot-bundle=<absolute-path>",
        );
        authenticated_aot_step.dependOn(&missing_bundle.step);
        secp256k1_proof_step.dependOn(&missing_bundle.step);
        keccakf_proof_step.dependOn(&missing_bundle.step);
        stage101_benchmark_step.dependOn(&missing_bundle.step);
        return;
    };
    if (!std.fs.path.isAbsolute(configured_bundle)) {
        const invalid_bundle = b.addFail(
            "test-authenticated-aot requires an absolute AOT bundle path",
        );
        authenticated_aot_step.dependOn(&invalid_bundle.step);
        secp256k1_proof_step.dependOn(&invalid_bundle.step);
        keccakf_proof_step.dependOn(&invalid_bundle.step);
        stage101_benchmark_step.dependOn(&invalid_bundle.step);
        return;
    }
    const real_tests = b.addTest(.{
        .root_module = integration,
        .filters = &.{
            "guest Metal profile proves and independently verifies when an AOT bundle is supplied",
        },
    });
    linkMetalFrameworks(real_tests);
    const run_real = b.addRunArtifact(real_tests);
    run_real.setEnvironmentVariable(
        "STWO_RISCV_METAL_AOT_BUNDLE",
        configured_bundle,
    );
    run_real.setEnvironmentVariable("STWO_ZIG_WORKERS", "1");
    run_real.setEnvironmentVariable("STWO_ZIG_MERKLE_WORKERS", "1");
    authenticated_aot_step.dependOn(&run_real.step);

    const run_stage101 = b.addRunArtifact(stage101_executable);
    run_stage101.step.dependOn(&stage101_install.step);
    run_stage101.has_side_effects = true;
    run_stage101.setEnvironmentVariable(
        "STWO_RISCV_METAL_AOT_BUNDLE",
        configured_bundle,
    );
    if (b.args) |arguments| run_stage101.addArgs(arguments);
    stage101_benchmark_step.dependOn(&run_stage101.step);

    const secp256k1_root = b.createModule(.{
        .root_source_file = b.path("secp256k1_precompile_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    secp256k1_root.addImport("stwo_core", core);
    secp256k1_root.addImport("stwo_metal_backend", metal_backend);
    secp256k1_root.addImport("stwo_prover_engine", prover);
    secp256k1_root.addImport("stwo_riscv_frontend", frontend);
    secp256k1_root.addImport("secp256k1_proof_harness", secp256k1_proof_harness);
    const secp256k1_tests = b.addTest(.{
        .root_module = secp256k1_root,
        .filters = &.{"secp256k1 typed ECDSA bundle proves on Metal"},
    });
    linkMetalFrameworks(secp256k1_tests);
    const run_secp256k1 = b.addRunArtifact(secp256k1_tests);
    run_secp256k1.has_side_effects = true;
    run_secp256k1.setEnvironmentVariable(
        "STWO_RISCV_METAL_AOT_BUNDLE",
        configured_bundle,
    );
    secp256k1_proof_step.dependOn(&run_secp256k1.step);

    const keccakf_root = b.createModule(.{
        .root_source_file = b.path("keccakf_precompile_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    keccakf_root.addImport("stwo_core", core);
    keccakf_root.addImport("stwo_metal_backend", metal_backend);
    keccakf_root.addImport("stwo_prover_engine", prover);
    keccakf_root.addImport("stwo_riscv_frontend", frontend);
    keccakf_root.addImport("keccakf_proof_harness", keccakf_proof_harness);
    const keccakf_tests = b.addTest(.{
        .root_module = keccakf_root,
        .filters = &.{"Keccak-f typed shard proves on Metal"},
    });
    linkMetalFrameworks(keccakf_tests);
    const run_keccakf = b.addRunArtifact(keccakf_tests);
    run_keccakf.has_side_effects = true;
    run_keccakf.setEnvironmentVariable(
        "STWO_RISCV_METAL_AOT_BUNDLE",
        configured_bundle,
    );
    keccakf_proof_step.dependOn(&run_keccakf.step);
}

fn linkMetalFrameworks(artifact: *std.Build.Step.Compile) void {
    artifact.linkLibC();
    artifact.linkFramework("Foundation");
    artifact.linkFramework("Metal");
    artifact.linkSystemLibrary("objc");
}
