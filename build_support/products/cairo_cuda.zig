//! Explicit Linux Cairo + CUDA product ownership.

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
    "cairo-stwo-v1+cuda-resident-proof-v1+strict-aot-v1";
const toolchain_requirement =
    "the Cairo CUDA product requires -Dcuda-nvcc, -Dcuda-host-cxx, " ++
    "-Dcuda-host-runtime, -Dcuda-host-unwind-runtime, -Dcuda-ar, " ++
    "-Dcuda-home, -Dcuda-library-dir, and -Dcuda-arch";
const source_closure = policy.SourceClosure{
    .entry_roots = &.{
        "src/products/cairo_cuda/main.zig",
        "src/cairo_cuda.zig",
    },
    .named_imports = &.{
        .{ .name = "stwo_cairo_cuda", .source = "src/cairo_cuda.zig" },
        .{ .name = "stwo_backend_contracts", .source = "src/backend/mod.zig" },
        .{ .name = "stwo_core", .source = "src/core/mod.zig" },
        .{ .name = "stwo_cairo_frontend", .source = "src/frontends/cairo/mod.zig" },
        .{ .name = "stwo_cairo_cuda_integration", .source = "src/integrations/cairo_cuda/mod.zig" },
        .{ .name = "stwo_cpu_backend", .source = "src/backends/cpu_scalar/mod.zig" },
        .{ .name = "stwo_cuda_backend", .source = "src/backends/cuda/mod.zig" },
        .{ .name = "stwo_native_cuda_integration", .source = "src/integrations/native_cuda/mod.zig" },
        .{ .name = "stwo_native_examples", .source = "src/examples/mod.zig" },
        .{ .name = "stwo_proof_wire", .source = "src/interop/proof_wire/mod.zig" },
        .{ .name = "stwo_prover_impl", .source = "src/prover/mod.zig" },
    },
    .allowed_files = &.{"src/cairo_cuda.zig"},
    .allowed_prefixes = &.{
        "src/backend",
        "src/backends/cpu_scalar",
        "src/backends/cuda",
        "src/core",
        "src/examples",
        "src/frontends/cairo",
        "src/integrations/cairo_cuda",
        "src/integrations/native_cuda",
        "src/interop",
        "src/products/cairo_cuda",
        "src/prover",
        "src/tools/cuda_native_ec_composite_oracle",
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
    .unsupported_target_reason = "the Cairo CUDA runtime product requires a Linux target",
    .build_step = "stwo-cairo-cuda",
    .test_step = "test-cairo-cuda-product",
    .executable = "stwo-cairo-cuda",
    .installed_artifacts = &.{
        "stwo-cairo-cuda",
        "lib/libstwo_cuda_kernels.a",
    },
    .release_gates = &.{
        "cuda-source-closure",
        "test-cuda-build-plan",
        "test-cuda-runtime-contract",
        "test-cairo-cuda-product",
    },
    .benchmark_step = "benchmark-cairo-cuda-sn2",
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
        "invalid Cairo CUDA descriptor: {s}",
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
        "Build the resident Cairo CUDA proof executable",
    );
    const archive = cuda.addArchive(context.b, options.toolchain());
    cuda.linkRuntime(installed.executable, options.toolchain(), archive);
    const install_archive = context.b.addInstallFile(
        archive.directory.path(context.b, "libstwo_cuda_kernels.a"),
        "lib/libstwo_cuda_kernels.a",
    );
    installed.build_step.dependOn(&install_archive.step);

    const test_root = createProductModule(
        context,
        product(.@"test"),
        createStwoModule(context, .@"test"),
    );
    const tests = context.b.addTest(.{ .root_module = test_root });
    cuda.linkRuntime(tests, options.toolchain(), archive);
    context.b.step(
        descriptor.test_step.?,
        "Compile and run the resident Cairo CUDA product tests",
    ).dependOn(&context.b.addRunArtifact(tests).step);

    const benchmark = context.b.addRunArtifact(installed.executable);
    benchmark.addArgs(&.{ "prove", "--backend", "cuda", "--input" });
    benchmark.addFileArg(context.b.path(
        context.b.option(
            []const u8,
            "cairo-cuda-sn2-input",
            "Adapted SN2 input used by benchmark-cairo-cuda-sn2",
        ) orelse "bench/fixtures/cairo/sn2-adapted-input.bin",
    ));
    benchmark.addArg("--output");
    _ = benchmark.addOutputFileArg("cairo-cuda-sn2-proof.json");
    benchmark.addArg("--report-out");
    _ = benchmark.addOutputFileArg("cairo-cuda-sn2-report.json");
    benchmark.addArgs(&.{ "--repeat", "3" });
    context.b.step(
        descriptor.benchmark_step.?,
        "Run the strict resident SN2 Cairo CUDA benchmark",
    ).dependOn(&benchmark.step);
}

fn createStwoModule(
    context: Context,
    role: graph.Role,
) *std.Build.Module {
    const module = graph.create(context.b, .{
        .product = product(role),
        .root_source_file = "src/cairo_cuda.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(module);
    const cuda_backend = graph.addCudaBackendImport(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        module,
    );
    const proof_wire = graph.createProofWire(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
    );
    const cpu_backend = graph.createCpuBackend(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
    );
    const native_examples = graph.createNativeExamples(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        cpu_backend,
        proof_wire,
    );
    const native_cuda = integration_graph.addNativeCudaImport(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        cuda_backend,
        native_examples,
        proof_wire,
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
    _ = integration_graph.addCairoCudaImport(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        cuda_backend,
        cairo_frontend,
        native_cuda,
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
        .root_source_file = "src/products/cairo_cuda/main.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    root.addImport("stwo_cairo_cuda", stwo);
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
                .aot_manifest = "cuda-authenticated-cairo-pack-v1",
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
        .name = "stwo-cairo-cuda",
        .frontend = .cairo,
        .backend = .cuda,
        .role = role,
        .protocol_features = protocol_features,
    };
}

test "Cairo CUDA is staged only for explicit Linux construction" {
    try descriptor.validate();
    try std.testing.expect(descriptor.isConstructible());
    try std.testing.expect(descriptor.isAvailableOn(.linux));
    try std.testing.expect(!descriptor.isAvailableOn(.macos));
    try std.testing.expectEqual(policy.State.staged, descriptor.state);
}
