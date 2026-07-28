//! Build ownership for Native example AIRs on CPU scalar/SIMD.

const std = @import("std");
const build_identity = @import("../build_identity.zig");
const closure_gate = @import("../gates/product_closure.zig");
const graph_identity = @import("../graph/identity.zig");
const graph_install = @import("../graph/install.zig");
const graph = @import("../graph/modules.zig");
const product_policy = @import("../graph/product.zig");

const protocol_features = "native-examples-v1+lifted-pcs-v1";
const source_closure = product_policy.SourceClosure{
    .entry_roots = &.{
        "src/products/native_cpu/main.zig",
        "src/stwo_native_cpu.zig",
        "src/prover/native/runner.zig",
        "src/products/native_cpu/benchmark.zig",
    },
    .named_imports = &.{
        .{ .name = "stwo", .source = "src/stwo_native_cpu.zig" },
        .{ .name = "stwo_backend_contracts", .source = "src/backend/mod.zig" },
        .{ .name = "stwo_core", .source = "src/core/mod.zig" },
        .{ .name = "stwo_cpu_backend", .source = "src/backends/cpu_scalar/mod.zig" },
        .{ .name = "stwo_native_examples", .source = "src/examples/mod.zig" },
        .{ .name = "stwo_native_cpu", .source = "src/stwo_native_cpu.zig" },
        .{ .name = "stwo_proof_wire", .source = "src/interop/proof_wire/mod.zig" },
        .{ .name = "stwo_prover_impl", .source = "src/prover/mod.zig" },
        .{ .name = "native_proof_runner", .source = "src/prover/native/runner.zig" },
        .{ .name = "native_resource_admission", .source = "src/prover/native/resource_admission.zig" },
        .{ .name = "native_transaction", .source = "src/integrations/native/transaction.zig" },
        .{ .name = "output_transaction", .source = "src/interop/output_transaction.zig" },
        .{ .name = "native_product_identity", .source = "src/integrations/native/product_identity.zig" },
    },
    .allowed_files = &.{
        "src/products/native_cpu/main.zig",
        "src/stwo_native_cpu.zig",
        "src/interop/atomic_file.zig",
        "src/interop/output_transaction.zig",
        "src/interop/examples_artifact.zig",
        "src/interop/examples_artifact_verifier.zig",
        "src/interop/postcard.zig",
        "src/interop/proof_wire/mod.zig",
        "src/integrations/native/transaction.zig",
        "src/integrations/native/product_identity.zig",
    },
    .allowed_prefixes = &.{
        "src/core",
        "src/backend",
        "src/backends/cpu_scalar",
        "src/prover",
        "src/examples",
        "src/products/native_cpu",
        "src/interop/postcard",
    },
    .forbidden_dynamic_dependencies = &.{
        "Metal.framework",
        "Foundation.framework",
        "libobjc",
        "cuda",
    },
};

pub const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    identity: build_identity.Identity,
    protocol: graph.ProtocolModules,
};

pub fn descriptor(role: graph.Role) product_policy.Descriptor {
    return .{
        .product = product(role),
        .state = .released,
        .target_support = .any,
        .build_step = "stwo-native-cpu",
        .test_step = "test-native-cpu-product",
        .executable = "stwo-zig-native-cpu",
        .installed_artifacts = &.{"stwo-zig-native-cpu"},
        .release_gates = &.{ "test-native-cpu-product", "vectors", "interop" },
        .benchmark_step = "benchmark-native-cpu",
        .profiler_step = "profile-opt",
        .dependencies = .{ .module_roots = source_closure.entry_roots },
        .source_closure = source_closure,
    };
}

pub fn addProduct(context: Context) void {
    const policy = descriptor(.cli);
    policy.validate() catch |err| std.debug.panic(
        "invalid Native CPU descriptor: {s}",
        .{@errorName(err)},
    );
    const cli_product = policy.product;
    const stwo = createStwoModule(context, .library);
    const runner = createRunnerModule(context, stwo, .library);
    const root = createProductModule(context, cli_product, stwo, runner, "src/products/native_cpu/main.zig");
    const installed = graph_install.executable(
        context.b,
        "stwo-zig-native-cpu",
        root,
        "stwo-native-cpu",
        "Build the focused Native CPU/SIMD proof CLI",
    );

    const benchmark_product = product(.benchmark);
    const benchmark_root = createProductModule(
        context,
        benchmark_product,
        stwo,
        runner,
        "src/products/native_cpu/benchmark.zig",
    );
    _ = graph_install.executable(
        context.b,
        "stwo-zig-native-cpu-bench",
        benchmark_root,
        "benchmark-native-cpu",
        "Build the focused Native CPU/SIMD benchmark",
    );

    const tests = addProductTests(context);
    const facade_tests = context.b.addTest(.{
        .root_module = createStwoModule(context, .@"test"),
    });
    const runner_test_stwo = createStwoModule(context, .@"test");
    const runner_tests = context.b.addTest(.{
        .root_module = createRunnerModule(context, runner_test_stwo, .@"test"),
    });
    const test_step = context.b.step(
        "test-native-cpu-product",
        "Test Native CPU product behavior, imports, and visible capabilities",
    );
    test_step.dependOn(&context.b.addRunArtifact(tests).step);
    test_step.dependOn(&context.b.addRunArtifact(facade_tests).step);
    test_step.dependOn(&context.b.addRunArtifact(runner_tests).step);

    const help = context.b.addRunArtifact(installed.executable);
    help.addArg("--help");
    test_step.dependOn(&help.step);
    const applications = context.b.addRunArtifact(installed.executable);
    applications.addArg("applications");
    test_step.dependOn(&applications.step);

    const closure_check = closure_gate.addCheck(.{
        .b = context.b,
        .descriptor = policy,
        .binary = installed.executable,
    });
    test_step.dependOn(&closure_check.step);
    const marker_check = context.b.addSystemCommand(&.{
        "python3",
        "scripts/check_native_cpu_product.py",
    });
    test_step.dependOn(&marker_check.step);
}

fn addProductTests(context: Context) *std.Build.Step.Compile {
    const stwo = createStwoModule(context, .@"test");
    const runner = createRunnerModule(context, stwo, .@"test");
    const root = createProductModule(
        context,
        product(.@"test"),
        stwo,
        runner,
        "src/products/native_cpu/main.zig",
    );
    return context.b.addTest(.{ .root_module = root });
}

fn createStwoModule(context: Context, role: graph.Role) *std.Build.Module {
    const module = graph.create(context.b, .{
        .product = product(role),
        .root_source_file = "src/stwo_native_cpu.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(module);
    const cpu_backend = graph.addCpuBackendImport(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        module,
    );
    const proof_wire = graph.addProofWireImport(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        module,
    );
    _ = graph.addNativeExamplesImport(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        cpu_backend,
        proof_wire,
        module,
    );
    return module;
}

fn createRunnerModule(
    context: Context,
    stwo: *std.Build.Module,
    role: graph.Role,
) *std.Build.Module {
    const runner = graph.create(context.b, .{
        .product = product(role),
        .root_source_file = "src/prover/native/runner.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(runner);
    runner.addImport("stwo", stwo);
    runner.addImport("native_resource_admission", graph.create(context.b, .{
        .product = product(role),
        .root_source_file = "src/prover/native/resource_admission.zig",
        .target = context.target,
        .optimize = context.optimize,
    }));
    return runner;
}

fn createProductModule(
    context: Context,
    product_descriptor: graph.Product,
    stwo: *std.Build.Module,
    runner: *std.Build.Module,
    root_source_file: []const u8,
) *std.Build.Module {
    const root = graph.create(context.b, .{
        .product = product_descriptor,
        .root_source_file = root_source_file,
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    root.addImport("stwo", stwo);
    root.addImport("stwo_native_cpu", stwo);
    root.addImport("native_proof_runner", runner);
    const lifecycle = graph.create(context.b, .{
        .product = product_descriptor,
        .root_source_file = "src/integrations/native/transaction.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    lifecycle.addImport("output_transaction", graph.create(context.b, .{
        .product = product_descriptor,
        .root_source_file = "src/interop/output_transaction.zig",
        .target = context.target,
        .optimize = context.optimize,
    }));
    root.addImport("native_transaction", lifecycle);
    root.addOptions("build_identity", graph_identity.buildOptions(context.b, context.identity));
    root.addOptions(
        "product_identity",
        graph_identity.productOptions(
            context.b,
            context.identity,
            product_descriptor,
            context.target,
            context.optimize,
        ),
    );
    const native_identity = graph.create(context.b, .{
        .product = product_descriptor,
        .root_source_file = "src/integrations/native/product_identity.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    native_identity.addImport("native_proof_runner", runner);
    native_identity.addOptions(
        "product_identity",
        graph_identity.productOptions(
            context.b,
            context.identity,
            product_descriptor,
            context.target,
            context.optimize,
        ),
    );
    root.addImport("native_product_identity", native_identity);
    return root;
}

fn product(role: graph.Role) graph.Product {
    return .{
        .name = "stwo-native-cpu",
        .frontend = .native,
        .backend = .cpu,
        .role = role,
        .protocol_features = protocol_features,
    };
}
