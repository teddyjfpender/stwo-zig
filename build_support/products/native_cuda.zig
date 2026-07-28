//! Explicit Linux Native + CUDA product ownership.

const std = @import("std");
const build_identity = @import("../build_identity.zig");
const cuda = @import("../backends/cuda.zig");
const cuda_tools = @import("../backends/cuda_tools.zig");
const graph_identity = @import("../graph/identity.zig");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");
const graph_install = @import("../graph/install.zig");
const policy = @import("../graph/product.zig");

const protocol_features =
    "native-examples-v1+cuda-resident-proof-v1+explicit-toolchain-v1";
const toolchain_requirement =
    "the Native CUDA product requires -Dcuda-nvcc, -Dcuda-host-cxx, " ++
    "-Dcuda-host-runtime, -Dcuda-host-unwind-runtime, -Dcuda-ar, " ++
    "-Dcuda-home, -Dcuda-library-dir, and -Dcuda-arch";
const source_closure = policy.SourceClosure{
    .entry_roots = &.{
        "src/products/native_cuda/main.zig",
        "src/stwo.zig",
    },
    .named_imports = &.{
        .{ .name = "stwo", .source = "src/stwo.zig" },
        .{ .name = "stwo_native_cuda", .source = "src/stwo.zig" },
        .{ .name = "stwo_backend_contracts", .source = "src/backend/mod.zig" },
        .{ .name = "stwo_core", .source = "src/core/mod.zig" },
        .{ .name = "stwo_cairo_frontend", .source = "src/frontends/cairo/mod.zig" },
        .{ .name = "stwo_cairo_cpu_integration", .source = "src/integrations/cairo_cpu/mod.zig" },
        .{ .name = "stwo_cairo_metal_integration", .source = "src/integrations/cairo_metal/mod.zig" },
        .{ .name = "stwo_cpu_backend", .source = "src/backends/cpu_scalar/mod.zig" },
        .{ .name = "stwo_cuda_backend", .source = "src/backends/cuda/mod.zig" },
        .{ .name = "stwo_metal_backend", .source = "src/backends/metal/mod.zig" },
        .{ .name = "stwo_prover_impl", .source = "src/prover/mod.zig" },
        .{ .name = "stwo_riscv_frontend", .source = "src/frontends/riscv/mod.zig" },
        .{ .name = "stwo_riscv_cpu_integration", .source = "src/integrations/riscv_cpu/mod.zig" },
        .{ .name = "stwo_metal_session", .source = "src/tools/metal_session/mod.zig" },
    },
    .allowed_files = &.{"src/stwo.zig"},
    .allowed_prefixes = &.{
        "src/backend",
        "src/backends/cuda",
        "src/backends/cpu_scalar",
        "src/backends/metal",
        "src/core",
        "src/examples",
        "src/frontends/cairo",
        "src/frontends/riscv",
        "src/integrations/native_cuda",
        "src/integrations/cairo_metal",
        "src/interop",
        "src/products/native_cuda",
        "src/prover",
        "src/tools/metal_session",
    },
    .required_dynamic_dependencies = &.{ "cuda", "cudart", "libstdc++.so.6" },
    .forbidden_dynamic_dependencies = &.{
        "Metal.framework",
        "Foundation.framework",
        "libobjc",
    },
};

pub const descriptor = policy.Descriptor{
    .product = product(.cli),
    .state = .staged,
    .target_support = .linux,
    .unsupported_target_reason = "the CUDA runtime product requires a Linux target",
    .build_step = "stwo-native-cuda",
    .test_step = "run-native-cuda-smoke",
    .executable = "stwo-zig-native-cuda",
    .installed_artifacts = &.{
        "stwo-zig-native-cuda",
        "lib/libstwo_cuda_kernels.a",
    },
    .release_gates = &.{
        "cuda-source-closure",
        "test-cuda-build-plan",
        "test-cuda-runtime-contract",
        "test-cuda-plonk-logup-contract",
        "test-cuda-xor-logup-contract",
        "test-cuda-state-machine-contract",
        "test-cuda-poseidon-arena-contract",
        "test-cuda-blake-exact-structure",
        "upstream-pins",
        "test-cuda-adapter",
        "run-native-cuda-smoke",
    },
    .benchmark_step = "benchmark-native-cuda",
    .dependencies = .{
        .module_roots = source_closure.entry_roots,
        .external_dependencies = &.{ "cuda", "cudart", "libstdc++.so.6" },
    },
    .source_closure = source_closure,
};

pub const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    identity: build_identity.Identity,
    protocol: graph.ProtocolModules,
};

pub fn addProduct(context: Context) void {
    descriptor.validate() catch |err| std.debug.panic(
        "invalid Native CUDA descriptor: {s}",
        .{@errorName(err)},
    );
    if (!descriptor.isAvailableOn(context.target.result.os.tag)) {
        policy.registerUnavailable(context.b, descriptor, context.target.result.os.tag);
        return;
    }

    const options = cuda_tools.Options.read(context.b);
    if (!options.runtimeComplete()) {
        registerMissingToolchain(context.b);
        return;
    }

    const stwo = createStwoModule(context, .library);
    const root = createProductModule(context, descriptor.product, stwo);

    const installed = graph_install.executable(
        context.b,
        descriptor.executable.?,
        root,
        descriptor.build_step,
        "Build the focused Native CUDA proof executable",
    );
    const archive = cuda.addArchive(context.b, options.toolchain());
    cuda.linkRuntime(installed.executable, options.toolchain(), archive);
    const install_archive = context.b.addInstallFile(
        archive.directory.path(context.b, "libstwo_cuda_kernels.a"),
        "lib/libstwo_cuda_kernels.a",
    );
    installed.build_step.dependOn(&install_archive.step);

    const run = context.b.addRunArtifact(installed.executable);
    run.addArgs(&.{
        "prove",
        "--air",
        "wide_fibonacci",
        "--backend",
        "cuda",
        "--protocol",
        "raw-stwo-wide-v1",
        "--log-n-rows",
        "5",
        "--sequence-len",
        "8",
        "--output",
    });
    _ = run.addOutputFileArg("native-cuda-smoke-proof.json");
    run.addArg("--report-out");
    _ = run.addOutputFileArg("native-cuda-smoke-report.json");
    run.addArgs(&.{ "--repeat", "3" });
    const test_step = context.b.step(
        descriptor.test_step.?,
        "Run repeated Native CUDA resident proof smokes",
    );
    test_step.dependOn(&run.step);
    const test_stwo = createStwoModule(context, .@"test");
    const tests = context.b.addTest(.{
        .root_module = createProductModule(
            context,
            product(.@"test"),
            test_stwo,
        ),
    });
    cuda.linkRuntime(tests, options.toolchain(), archive);
    test_step.dependOn(&context.b.addRunArtifact(tests).step);

    const benchmark = context.b.addSystemCommand(&.{
        "python3",
        "scripts/native_cuda_benchmark.py",
        "--candidate-bin",
    });
    benchmark.addFileArg(installed.executable.getEmittedBin());
    benchmark.addArgs(&.{ "--profile", "screen", "--output" });
    _ = benchmark.addOutputFileArg("native-cuda-structural-screen.json");
    context.b.step(
        descriptor.benchmark_step.?,
        "Run the fail-closed Native CUDA structural screen",
    ).dependOn(&benchmark.step);
}

fn createStwoModule(
    context: Context,
    role: graph.Role,
) *std.Build.Module {
    const module = graph.create(context.b, .{
        .product = product(role),
        .root_source_file = "src/stwo.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(module);
    const metal_session = graph.addMetalSessionImport(
        context.b,
        product(role),
        context.target,
        context.optimize,
        module,
    );
    const cpu_backend = graph.addCpuBackendImport(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        module,
    );
    const metal_backend = graph.addMetalBackendImport(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        cpu_backend,
        module,
    );
    _ = graph.addCudaBackendImport(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        module,
    );
    const riscv_frontend = graph.addRiscVFrontendImport(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        module,
    );
    _ = integration_graph.addRiscVCpuImport(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        cpu_backend,
        riscv_frontend,
        module,
    );
    const cairo_frontend = graph.addCairoFrontendImport(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        module,
    );
    _ = integration_graph.addCairoCpuImport(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        cpu_backend,
        cairo_frontend,
        module,
    );
    _ = integration_graph.addCairoMetalImport(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        metal_backend,
        cairo_frontend,
        metal_session,
        module,
    );
    return module;
}

fn createProductModule(
    context: Context,
    product_descriptor: graph.Product,
    stwo: *std.Build.Module,
) *std.Build.Module {
    const root = graph.create(context.b, .{
        .product = product_descriptor,
        .root_source_file = "src/products/native_cuda/main.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    root.addImport("stwo", stwo);
    root.addImport("stwo_native_cuda", stwo);
    root.addOptions(
        "product_identity",
        graph_identity.productOptionsWithRuntime(
            context.b,
            context.identity,
            product_descriptor,
            context.target,
            context.optimize,
            .{
                .runtime_manifest = "cuda-process-runtime-v1",
                .sdk_manifest = "cuda-explicit-toolchain-v1",
                .aot_manifest = "cuda-authenticated-native-pack-v1",
            },
        ),
    );
    return root;
}

fn registerMissingToolchain(b: *std.Build) void {
    const unavailable = b.addFail(toolchain_requirement);
    b.step(descriptor.build_step, toolchain_requirement).dependOn(&unavailable.step);
    b.step(descriptor.test_step.?, toolchain_requirement).dependOn(&unavailable.step);
    b.step(descriptor.benchmark_step.?, toolchain_requirement).dependOn(&unavailable.step);
}

fn product(role: graph.Role) graph.Product {
    return .{
        .name = "stwo-native-cuda",
        .frontend = .native,
        .backend = .cuda,
        .role = role,
        .protocol_features = protocol_features,
    };
}

test "Native CUDA is staged only for explicit Linux construction" {
    try descriptor.validate();
    try std.testing.expect(descriptor.isConstructible());
    try std.testing.expect(descriptor.isAvailableOn(.linux));
    try std.testing.expect(!descriptor.isAvailableOn(.macos));
    try std.testing.expectEqual(policy.State.staged, descriptor.state);
    try std.testing.expectEqualStrings(
        descriptor.test_step.?,
        descriptor.release_gates[descriptor.release_gates.len - 1],
    );
    try std.testing.expectEqualStrings(
        "benchmark-native-cuda",
        descriptor.benchmark_step.?,
    );
}
