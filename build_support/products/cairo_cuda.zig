//! Explicit Linux Cairo + CUDA product ownership.

const std = @import("std");
const build_identity = @import("../build_identity.zig");
const cuda = @import("../backends/cuda.zig");
const cuda_aot = @import("../backends/cuda_aot.zig");
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
        .{ .name = "interop_felt_json", .source = "src/interop/felt_json.zig" },
        .{ .name = "interop_cairo_prover_parameters", .source = "src/interop/cairo_prover_parameters.zig" },
        .{ .name = "stwo_cairo_cuda_integration", .source = "src/integrations/cairo_cuda/mod.zig" },
        .{ .name = "stwo_cpu_backend", .source = "src/backends/cpu_scalar/mod.zig" },
        .{ .name = "stwo_cuda_backend", .source = "src/backends/cuda/mod.zig" },
        .{ .name = "stwo_native_cuda_integration", .source = "src/integrations/native_cuda/mod.zig" },
        .{ .name = "stwo_native_examples", .source = "src/examples/mod.zig" },
        .{ .name = "stwo_proof_wire", .source = "src/interop/proof_wire/mod.zig" },
        .{ .name = "stwo_prover_api", .source = "src/prover_api/mod.zig" },
        .{ .name = "stwo_prover_engine", .source = "src/prover/mod.zig" },
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
        "src/prover_api",
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
    // Compile the complete CLI/controller/verification path without linking a
    // CUDA runtime. This gate is useful on development hosts without NVIDIA.
    const local_stwo = createStwoModule(context, .library);
    const local_root = createProductModule(context, product(.library), local_stwo, "80,90");
    local_root.root_source_file = context.b.path("src/products/cairo_cuda/compile_check.zig");
    local_root.link_libc = true;
    const local_object = context.b.addObject(.{
        .name = "cairo-cuda-local-compile",
        .root_module = local_root,
    });
    const local_step = context.b.step("check-cairo-cuda-local", "Compile the complete Cairo CUDA product and validate its archive plan without a GPU");
    local_step.dependOn(&local_object.step);
    var generator_context = context;
    generator_context.target = context.b.graph.host;
    generator_context.protocol = graph.createPrivateProtocolModules(context.b, context.b.graph.host, context.optimize);
    const generator_stwo = createStwoModule(generator_context, .library);
    const local_aot = cuda_aot.addCairoEval(context.b, context.b.graph.host, generator_stwo);
    local_step.dependOn(&cuda.addCairoPlan(context.b, local_aot).step);
    const host_test_root = context.b.createModule(.{
        .root_source_file = context.b.path("src/integrations/cairo_cuda/local_test_root.zig"),
        .target = context.target,
        .optimize = context.optimize,
        .link_libc = true,
    });
    const integration_module = local_stwo.import_table.get("stwo_cairo_cuda_integration").?;
    var imports = integration_module.import_table.iterator();
    while (imports.next()) |item| host_test_root.addImport(item.key_ptr.*, item.value_ptr.*);
    const host_test_filter = context.b.option([]const u8, "cairo-test-filter", "Run focused Cairo tests containing this text");
    const host_tests = context.b.addTest(.{
        .root_module = host_test_root,
        .filters = if (host_test_filter) |filter| &.{filter} else &.{"canonical CUDA"},
    });
    context.b.step("test-cairo-cuda-local", "Test canonical CUDA source admission and table geometry without a GPU").dependOn(&context.b.addRunArtifact(host_tests).step);
    const relation_root = context.b.createModule(.{
        .root_source_file = context.b.path("src/backends/cuda/relation_local_test_root.zig"),
        .target = context.target,
        .optimize = context.optimize,
        .link_libc = true,
    });
    var relation_imports = integration_module.import_table.get("stwo_cuda_backend").?.import_table.iterator();
    while (relation_imports.next()) |item| relation_root.addImport(item.key_ptr.*, item.value_ptr.*);
    const relation_tests = context.b.addTest(.{ .root_module = relation_root, .filters = &.{"relation"} });
    context.b.step("test-cairo-cuda-relation-local", "Test relation graph scratch admission and stream execution without a GPU").dependOn(&context.b.addRunArtifact(relation_tests).step);
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
    const root = createProductModule(context, descriptor.product, stwo, options.architectures.?);
    const installed = graph_install.executable(
        context.b,
        descriptor.executable.?,
        root,
        descriptor.build_step,
        "Build the resident Cairo CUDA proof executable",
    );
    const cairo_eval_aot = cuda_aot.addCairoEval(
        context.b,
        context.target,
        stwo,
    );
    const archive = cuda.addArchive(
        context.b,
        options.toolchain(),
        .cairo,
        cairo_eval_aot,
    );
    cuda.linkRuntime(installed.executable, options.toolchain(), archive);
    addCircuitResidentBenchmark(context, options.toolchain(), cairo_eval_aot);
    const install_archive = context.b.addInstallFile(
        archive.directory.path(context.b, "libstwo_cuda_kernels.a"),
        "lib/libstwo_cuda_kernels.a",
    );
    installed.build_step.dependOn(&install_archive.step);

    const test_root = createProductModule(
        context,
        product(.@"test"),
        createStwoModule(context, .@"test"),
        options.architectures.?,
    );
    const test_filters: []const []const u8 = if (host_test_filter) |filter| &.{filter} else &.{};
    const tests = context.b.addTest(.{ .root_module = test_root, .filters = test_filters });
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

/// The circuit benchmark is a separate executable and full circuit AOT
/// archive. It does not change the Cairo product's source closure or binary.
fn addCircuitResidentBenchmark(context: Context, toolchain: cuda.Toolchain, cairo_eval_aot: cuda_aot.GeneratedSet) void {
    const b = context.b;
    const core = context.protocol.core;
    const prover = context.protocol.prover;
    const prover_api = context.protocol.prover_api;
    // Package test targets attach C ABI stubs to their root modules. The
    // benchmark links the real CUDA archive, so take the product graph's
    // clean runtime modules instead of those test-owned module instances.
    const stwo = createStwoModule(context, .library);
    const cairo_cuda = stwo.import_table.get("stwo_cairo_cuda_integration") orelse @panic("missing product Cairo CUDA module");
    const cairo_frontend = cairo_cuda.import_table.get("stwo_cairo_frontend") orelse @panic("missing product Cairo frontend");
    const backend_contracts = cairo_cuda.import_table.get("stwo_backend_contracts") orelse @panic("missing CUDA backend contracts");
    const cuda_backend = cairo_cuda.import_table.get("stwo_cuda_backend") orelse @panic("missing CUDA runtime");
    const native_cuda = cairo_cuda.import_table.get("stwo_native_cuda_integration") orelse @panic("missing native CUDA integration");
    const native_examples = native_cuda.import_table.get("stwo_native_examples") orelse @panic("missing native examples");
    const circuit = b.createModule(.{
        .root_source_file = b.path("src/frontends/circuit/mod.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    circuit.addImport("stwo_core", core);
    circuit.addImport("stwo_prover_engine", prover);
    const testing = b.createModule(.{
        .root_source_file = b.path("src/frontends/circuit/testing/mod.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    testing.addImport("stwo_core", core);
    testing.addImport("stwo_circuit_frontend", circuit);
    const cpu_backend = native_examples.import_table.get("stwo_cpu_backend") orelse @panic("missing product CPU backend");
    const wire = graph.createCircuitRecursionWire(b, context.protocol, product(.library), context.target, context.optimize, cairo_frontend);
    const circuit_cpu = b.createModule(.{
        .root_source_file = b.path("src/integrations/circuit_cpu/mod.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(circuit_cpu);
    circuit_cpu.addImport("stwo_cpu_backend", cpu_backend);
    circuit_cpu.addImport("stwo_circuit_frontend", circuit);
    circuit_cpu.addImport("stwo_cairo_frontend", cairo_frontend);
    circuit_cpu.addImport("stwo_circuit_recursion_wire", wire);
    const forbidden_cpu_aot = b.createModule(.{
        .root_source_file = b.path("src/integrations/circuit_cuda/cpu_composition_forbidden.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    forbidden_cpu_aot.addImport("stwo_cairo_frontend", cairo_frontend);
    circuit_cpu.addImport("circuit_composition_cpu_aot", forbidden_cpu_aot);
    const integration = b.createModule(.{
        .root_source_file = b.path("src/integrations/circuit_cuda/mod.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    integration.addImport("stwo_core", core);
    integration.addImport("stwo_backend_contracts", backend_contracts);
    integration.addImport("stwo_prover_api", prover_api);
    integration.addImport("stwo_prover_engine", prover);
    integration.addImport("stwo_cpu_backend", cpu_backend);
    integration.addImport("stwo_circuit_frontend", circuit);
    integration.addImport("stwo_cairo_frontend", cairo_frontend);
    integration.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    integration.addImport("stwo_cairo_cuda_integration", cairo_cuda);
    integration.addImport("stwo_cuda_backend", cuda_backend);
    integration.addImport("stwo_native_cuda_integration", native_cuda);
    const root = b.createModule(.{
        .root_source_file = b.path("src/integrations/circuit_cuda/tests/resident_bench.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    root.addImport("stwo_core", core);
    root.addImport("stwo_circuit_frontend", circuit);
    root.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    root.addImport("stwo_circuit_cuda_integration", integration);
    root.addImport("stwo_cuda_backend", cuda_backend);
    root.addImport("circuit_testing", testing);
    const exe = b.addExecutable(.{ .name = "stwo-circuit-cuda-resident-bench", .root_module = root });
    const circuit_archive = cuda.addCircuitArchive(
        b,
        toolchain,
        cairo_eval_aot,
        b.path("src/backends/cuda/aot/native/circuit_eval"),
    );
    cuda.linkRuntime(exe, toolchain, circuit_archive);
    b.step("benchmark-circuit-cuda-resident", "Build the verified resident circuit-recursion CUDA benchmark").dependOn(&b.addInstallArtifact(exe, .{}).step);

    const cairo_app = b.createModule(.{
        .root_source_file = b.path("src/products/cairo_cuda/app.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    cairo_app.addImport("stwo_cairo_cuda", stwo);
    cairo_app.addImport("stwo_circuit_recursion_wire", wire);
    const architectures = b.addOptions();
    architectures.addOption([]const u8, "architectures", toolchain.architectures);
    const architecture_module = architectures.createModule();
    cairo_app.addImport("cuda_architectures", architecture_module);
    const cairo_cpu = integration_graph.addCairoCpuImport(
        b,
        context.protocol,
        product(.library),
        context.target,
        context.optimize,
        cpu_backend,
        cairo_frontend,
        circuit_cpu,
    );
    const circuit_app = b.createModule(.{
        .root_source_file = b.path("src/products/circuit_recursion_cpu/app.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    circuit_app.addImport("stwo_cairo_frontend", cairo_frontend);
    circuit_app.addImport("stwo_cairo_cpu_integration", cairo_cpu);
    circuit_app.addImport("stwo_circuit_frontend", circuit);
    circuit_app.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    circuit_app.addImport("stwo_circuit_recursion_wire", wire);
    circuit_app.addImport("stwo_prover_engine", prover);
    circuit_app.addAnonymousImport("circuit_air_projection", .{ .root_source_file = b.path("vectors/circuit/official/compiled_air_constraints_v1.bin") });
    circuit_app.addAnonymousImport("circuit_air_programs", .{ .root_source_file = b.path("vectors/circuit/official/circuit_air.air_programs_v1.bin") });
    const pipeline_root = b.createModule(.{
        .root_source_file = b.path("src/products/circuit_recursion_cuda/main.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    pipeline_root.addImport("cairo_cuda_app", cairo_app);
    pipeline_root.addImport("circuit_recursion_app", circuit_app);
    pipeline_root.addImport("stwo_circuit_cpu_integration", circuit_cpu);
    pipeline_root.addImport("stwo_circuit_cuda_integration", integration);
    pipeline_root.addImport("stwo_cuda_backend", cuda_backend);
    pipeline_root.addImport("cuda_architectures", architecture_module);
    pipeline_root.addImport("stwo_circuit_recursion_wire", wire);
    pipeline_root.addImport("stwo_cairo_cuda_integration", cairo_cuda);
    pipeline_root.addImport("stwo_cairo_frontend", cairo_frontend);
    const pipeline_exe = b.addExecutable(.{ .name = "stwo-circuit-recursion-cuda", .root_module = pipeline_root });
    cuda.linkRuntime(pipeline_exe, toolchain, circuit_archive);
    b.step("circuit-recursion-cuda-resident", "Build the fully resident PIE-to-root CUDA prover").dependOn(&b.addInstallArtifact(pipeline_exe, .{}).step);
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
    architectures: []const u8,
) *std.Build.Module {
    const root = graph.create(context.b, .{
        .product = product_descriptor,
        .root_source_file = "src/products/cairo_cuda/main.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    root.addImport("stwo_cairo_cuda", stwo);
    const cairo_frontend = stwo.import_table.get("stwo_cairo_cuda_integration").?.import_table.get("stwo_cairo_frontend").?;
    root.addImport("stwo_circuit_recursion_wire", graph.createCircuitRecursionWire(
        context.b,
        context.protocol,
        product_descriptor,
        context.target,
        context.optimize,
        cairo_frontend,
    ));
    const architecture_options = context.b.addOptions();
    architecture_options.addOption([]const u8, "architectures", architectures);
    root.addOptions("cuda_architectures", architecture_options);
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
