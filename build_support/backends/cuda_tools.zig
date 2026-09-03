//! Host-independent source/build-plan gates and explicit CUDA archive build.

const std = @import("std");
const cuda = @import("cuda.zig");
const cuda_aot = @import("cuda_aot.zig");
const cuda_cumetal = @import("cuda_cumetal.zig");
const cuda_external = @import("cuda_external.zig");
const cuda_portability = @import("cuda_portability.zig");
pub const Options = @import("cuda_tools_options.zig").Options;
const construction_observer = @import("../graph/construction_observer.zig");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");

pub fn addProducts(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const options = Options.read(b);
    cuda_portability.addStep(b, target, .{
        .compiler = options.cumetalc,
        .root = options.cumetal_root,
        .inspect = options.air_inspect,
        .validate = options.air_validate,
    });
    cuda_aot.addNativeToolStep(b);
    const source = cuda.addSourceClosureGate(b);
    b.step(
        "cuda-source-closure",
        "Verify the exact pinned CUDA/C++ source authority",
    ).dependOn(&source.step);
    const external_authority = cuda_external.addAuthority(b);
    b.step(
        "cuda-authority-materialize",
        "Fetch and authenticate the audit-only upstream CUDA workspace",
    ).dependOn(&external_authority.run.step);

    const plan = cuda.addPlan(b, options.planningToolchain());
    b.step(
        "cuda-build-plan",
        "Validate and print the isolated native CUDA archive build plan",
    ).dependOn(&plan.step);

    const tests = b.addSystemCommand(&.{
        "python3",
        "-m",
        "unittest",
        "scripts.tests.test_cuda_build",
        "scripts.tests.test_cuda_aot_identity",
        "scripts.tests.test_cuda_build_cache",
        "scripts.tests.test_cuda_cairo_eval_aot",
        "scripts.tests.test_cuda_source_closure",
        "scripts.tests.test_cuda_product_closure",
        "scripts.tests.test_cuda_recorded_witness_product",
        "scripts.tests.test_cuda_aot_authentication",
        "scripts.tests.test_cuda_blake_aot",
        "scripts.tests.test_cuda_blake_exact_interaction_oracle",
        "scripts.tests.test_cuda_blake_exact_trace_aot",
        "scripts.tests.test_cuda_compact_b2n",
        "scripts.tests.test_cuda_blake_exact_interaction_aot",
        "scripts.tests.test_cuda_plonk_logup_aot",
        "scripts.tests.test_cuda_poseidon_aot",
        "scripts.tests.test_cuda_xor_logup_aot",
        "scripts.tests.test_cuda_xor_logup_trace_aot",
        "scripts.tests.test_cuda_proof_parity_gate",
        "scripts.tests.test_cuda_activation",
    });
    tests.step.dependOn(&source.step);
    b.step(
        "test-cuda-build-plan",
        "Test CUDA source, AOT, toolchain, and build-plan contracts without a GPU",
    ).dependOn(&tests.step);

    const runtime_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = graph.source(
                b,
                "src/backends/cuda/mod.zig",
                target,
                optimize,
            ),
            .target = target,
            .optimize = optimize,
        }),
    });
    runtime_tests.root_module.addImport(
        "stwo_backend_contracts",
        b.createModule(.{
            .root_source_file = graph.source(
                b,
                "src/backend/mod.zig",
                target,
                optimize,
            ),
            .target = target,
            .optimize = optimize,
        }),
    );
    runtime_tests.addCSourceFile(.{
        .file = b.path("src/backends/cuda/runtime/stages/test_stubs.c"),
        .flags = &.{ "-std=c11", "-Wno-strict-prototypes" },
    });
    runtime_tests.linkLibC();
    b.step(
        "test-cuda-runtime-contract",
        "Test proof-owned CUDA context, residency, and strict-AOT contracts",
    ).dependOn(&b.addRunArtifact(runtime_tests).step);

    const protocol = graph.createPrivateProtocolModules(
        b,
        target,
        optimize,
    );
    const tool_product = graph.Product{
        .name = "stwo-native-cuda-tools",
        .frontend = .native,
        .backend = .cuda,
        .role = .library,
    };
    const stwo = b.createModule(.{
        .root_source_file = b.path("src/stwo.zig"),
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(stwo);
    const proof_wire = graph.addProofWireImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    _ = graph.addArtifactStoreImport(b, tool_product, target, optimize, stwo);
    const metal_session = graph.addMetalSessionImport(
        b,
        tool_product,
        target,
        optimize,
        stwo,
    );
    const cpu_backend = graph.addCpuBackendImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    const native_examples = graph.addNativeExamplesImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        cpu_backend,
        proof_wire,
        stwo,
    );
    const metal_backend = graph.addMetalBackendImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    const cuda_backend = graph.addCudaBackendImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    const native_cuda = integration_graph.addNativeCudaImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        cuda_backend,
        native_examples,
        proof_wire,
        stwo,
    );
    const riscv_frontend = graph.addRiscVFrontendImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    _ = integration_graph.addRiscVCpuImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        cpu_backend,
        riscv_frontend,
        stwo,
    );
    const cairo_frontend = graph.addCairoFrontendImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    const cairo_cuda = integration_graph.addCairoCudaImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        cuda_backend,
        cairo_frontend,
        native_cuda,
        stwo,
    );
    cuda_aot.addCairoEvalToolStep(b, target, stwo);
    _ = integration_graph.addCairoCpuImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        cpu_backend,
        cairo_frontend,
        stwo,
    );
    _ = integration_graph.addCairoMetalImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        metal_backend,
        cairo_frontend,
        metal_session,
        stwo,
    );
    const ec_oracle_root = b.createModule(.{
        .root_source_file = b.path(
            "src/tools/cuda_native_ec_composite_oracle/main.zig",
        ),
        .target = target,
        .optimize = .ReleaseFast,
    });
    ec_oracle_root.addImport("stwo_cairo_frontend", cairo_frontend);
    ec_oracle_root.addImport("stwo_cairo_cuda_integration", cairo_cuda);
    const ec_oracle = b.addExecutable(.{
        .name = "cuda-native-ec-composite-oracle",
        .root_module = ec_oracle_root,
    });
    b.step(
        "cuda-native-ec-composite-oracle",
        "Emit the canonical Zig SIMD receipt for the native EC consumer",
    ).dependOn(&b.addRunArtifact(ec_oracle).step);
    const plonk_logup_root = b.createModule(.{
        .root_source_file = b.path("tests/native_cuda_plonk_logup.zig"),
        .target = target,
        .optimize = optimize,
    });
    plonk_logup_root.addImport("stwo_under_test", stwo);
    const plonk_logup_tests = b.addTest(.{
        .root_module = plonk_logup_root,
    });
    b.step(
        "test-cuda-plonk-logup-contract",
        "Test activation-disabled exact Plonk/LogUp CUDA contracts",
    ).dependOn(&b.addRunArtifact(plonk_logup_tests).step);

    const xor_logup_root = b.createModule(.{
        .root_source_file = b.path("tests/native_cuda_xor_logup.zig"),
        .target = target,
        .optimize = optimize,
    });
    xor_logup_root.addImport("stwo_under_test", stwo);
    const xor_logup_tests = b.addTest(.{
        .root_module = xor_logup_root,
    });
    b.step(
        "test-cuda-xor-logup-contract",
        "Test exact XOR/LogUp CUDA contracts without a GPU",
    ).dependOn(&b.addRunArtifact(xor_logup_tests).step);

    const state_machine_root = b.createModule(.{
        .root_source_file = b.path("tests/native_cuda_state_machine.zig"),
        .target = target,
        .optimize = optimize,
    });
    state_machine_root.addImport("stwo_under_test", stwo);
    const state_machine_tests = b.addTest(.{
        .root_module = state_machine_root,
    });
    b.step(
        "test-cuda-state-machine-contract",
        "Test activation-disabled exact State Machine v2 CUDA contracts",
    ).dependOn(&b.addRunArtifact(state_machine_tests).step);

    const poseidon_arena_root = b.createModule(.{
        .root_source_file = b.path(
            "tests/native_cuda_poseidon_arena.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    poseidon_arena_root.addImport("stwo_under_test", stwo);
    const poseidon_arena_tests = b.addTest(.{
        .root_module = poseidon_arena_root,
    });
    b.step(
        "test-cuda-poseidon-arena-contract",
        "Test exact Poseidon CUDA arena contracts without a GPU",
    ).dependOn(&b.addRunArtifact(poseidon_arena_tests).step);

    const blake_exact_root = b.createModule(.{
        .root_source_file = b.path(
            "tests/native_cuda_blake_exact_structure.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    blake_exact_root.addImport("stwo_under_test", stwo);
    const blake_exact_tests = b.addTest(.{
        .root_module = blake_exact_root,
    });
    const blake_exact_step = b.step(
        "test-cuda-blake-exact-structure",
        "Test exact mixed-height Blake CUDA contracts without a GPU",
    );
    blake_exact_step.dependOn(&b.addRunArtifact(blake_exact_tests).step);

    const blake_route_root = b.createModule(.{
        .root_source_file = b.path(
            "src/products/native_cuda/blake_route.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    blake_route_root.addImport("stwo_native_cuda", stwo);
    const blake_route_tests = b.addTest(.{
        .root_module = blake_route_root,
    });
    blake_exact_step.dependOn(&b.addRunArtifact(blake_route_tests).step);

    addCuMetalNative(b, target, optimize, stwo, options);

    const adapter_tests = cuda_external.addAdapter(
        b,
        "test",
        external_authority.directory,
    );
    b.step(
        "test-cuda-adapter",
        "Compile and test the external-authority Native proof adapter",
    ).dependOn(&adapter_tests.step);

    if (options.complete()) {
        const archive = cuda.addArchive(
            b,
            options.toolchain(),
            .native,
            null,
        );
        b.step(
            "cuda-native-archive",
            "Build the exact static CUDA runtime and generated AOT pack",
        ).dependOn(&archive.build.step);

        const adapter = cuda_external.addAdapter(
            b,
            "build",
            external_authority.directory,
        );
        adapter.setEnvironmentVariable("STWO_CUDA_NVCC", options.nvcc.?);
        adapter.setEnvironmentVariable("STWO_CUDA_HOST_COMPILER", options.host_cxx.?);
        adapter.setEnvironmentVariable("STWO_CUDA_ARCH", options.architectures.?);
        adapter.setEnvironmentVariable(
            "STWO_CUDA_BUILD_JOBS",
            b.fmt("{d}", .{options.jobs}),
        );
        adapter.step.dependOn(&source.step);
        b.step(
            "cuda-native-adapter",
            "Build the external-authority Native CUDA proof adapter",
        ).dependOn(&adapter.step);
    } else {
        const unavailable = b.addFail(
            "cuda-native-archive requires explicit compiler, toolkit, library, " ++
                "archiver, and SM options; run `zig build cuda-build-plan` for " ++
                "the host-independent contract",
        );
        b.step(
            "cuda-native-archive",
            "Build the exact static CUDA runtime and generated AOT pack",
        ).dependOn(&unavailable.step);

        const adapter_unavailable = b.addFail(
            "cuda-native-adapter requires -Dcuda-nvcc, -Dcuda-host-cxx, " ++
                "-Dcuda-ar, -Dcuda-home, -Dcuda-library-dir, and -Dcuda-arch",
        );
        b.step(
            "cuda-native-adapter",
            "Build the external-authority Native CUDA proof adapter",
        ).dependOn(&adapter_unavailable.step);
    }
    construction_observer.recordConstructor(b, "backends/cuda_tools.addProducts");
}

fn addCuMetalNative(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    stwo: *std.Build.Module,
    options: Options,
) void {
    const archive_step = b.step(
        "cuda-cumetal-native-archive",
        "Build the authenticated Native CuMetal provider archive",
    );
    const smoke_step = b.step(
        "run-native-cumetal-smoke",
        "Prove and verify Native wide Fibonacci on the Apple GPU",
    );
    if (target.result.os.tag != .macos) {
        const unavailable = b.addFail("the CuMetal provider requires macOS");
        archive_step.dependOn(&unavailable.step);
        smoke_step.dependOn(&unavailable.step);
        return;
    }
    const clang = options.cumetal_clang;
    const compiler = options.cumetalc;
    const root = options.cumetal_root;
    const library = options.cumetal_library;
    const inspect = options.air_inspect;
    const validate = options.air_validate;
    if (clang == null or compiler == null or root == null or
        library == null or inspect == null or validate == null)
    {
        const unavailable = b.addFail(
            "Native CuMetal requires -Dcuda-cumetal-clang, " ++
                "-Dcuda-cumetalc, -Dcuda-cumetal-root, " ++
                "-Dcuda-cumetal-library, -Dcuda-air-inspect, and " ++
                "-Dcuda-air-validate",
        );
        archive_step.dependOn(&unavailable.step);
        smoke_step.dependOn(&unavailable.step);
        return;
    }
    const toolchain = cuda_cumetal.Toolchain{
        .clang = clang.?,
        .compiler = compiler.?,
        .root = root.?,
        .library = library.?,
        .air_inspect = inspect.?,
        .air_validate = validate.?,
        .archiver = options.cumetal_archiver orelse "/usr/bin/ar",
        .jobs = options.jobs,
    };
    const archive = cuda_cumetal.addNativeArchive(b, toolchain);
    archive_step.dependOn(&archive.build.step);
    const root_module = b.createModule(.{
        .root_source_file = b.path(
            "tests/cuda/cumetal/native_frontend_execution.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    root_module.addImport("stwo_under_test", stwo);
    const tests = b.addTest(.{ .root_module = root_module });
    cuda_cumetal.linkRuntime(tests, toolchain, archive);
    const run = b.addRunArtifact(tests);
    run.setEnvironmentVariable("CUMETAL_TRACE_GPU", "1");
    run.setEnvironmentVariable("CUMETAL_MSL_MATH_MODE", "safe");
    smoke_step.dependOn(&run.step);
}
