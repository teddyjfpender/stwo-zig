//! Build ownership for Native example AIRs on the Metal backend.

const std = @import("std");
const metal = @import("../backends/metal.zig");
const build_identity = @import("../build_identity.zig");
const closure_gate = @import("../gates/product_closure.zig");
const graph_identity = @import("../graph/identity.zig");
const graph_install = @import("../graph/install.zig");
const graph = @import("../graph/modules.zig");
const product_policy = @import("../graph/product.zig");

const protocol_features = "native-examples-v1+lifted-pcs-v1+metal-runtime-v1";
const source_closure = product_policy.SourceClosure{
    .entry_roots = &.{
        "src/products/native_metal/main.zig",
        "src/stwo_native_metal.zig",
        "src/prover/native/runner.zig",
    },
    .named_imports = &.{
        .{ .name = "stwo", .source = "src/stwo_native_metal.zig" },
        .{ .name = "stwo_backend_contracts", .source = "src/backend/mod.zig" },
        .{ .name = "stwo_core", .source = "src/core/mod.zig" },
        .{ .name = "stwo_cpu_backend", .source = "src/backends/cpu_scalar/mod.zig" },
        .{ .name = "stwo_metal_backend", .source = "src/backends/metal/mod.zig" },
        .{ .name = "stwo_native_metal", .source = "src/stwo_native_metal.zig" },
        .{ .name = "stwo_prover_impl", .source = "src/prover/mod.zig" },
        .{ .name = "native_proof_runner", .source = "src/prover/native/runner.zig" },
        .{ .name = "native_resource_admission", .source = "src/prover/native/resource_admission.zig" },
        .{ .name = "native_transaction", .source = "src/integrations/native/transaction.zig" },
        .{ .name = "output_transaction", .source = "src/interop/output_transaction.zig" },
        .{ .name = "native_product_identity", .source = "src/integrations/native/product_identity.zig" },
        .{ .name = "native_cpu_capabilities", .source = "src/products/native_cpu/capabilities.zig" },
    },
    .allowed_files = &.{
        "src/stwo_native_metal.zig",
        "src/interop/atomic_file.zig",
        "src/interop/output_transaction.zig",
        "src/interop/examples_artifact.zig",
        "src/interop/examples_artifact_verifier.zig",
        "src/interop/postcard.zig",
        "src/interop/proof_wire.zig",
        "src/integrations/native/transaction.zig",
        "src/integrations/native/product_identity.zig",
        "src/products/native_cpu/capabilities.zig",
    },
    .allowed_prefixes = &.{
        "src/core",
        "src/backend",
        "src/backends/cpu_scalar",
        "src/backends/metal",
        "src/prover",
        "src/examples",
        "src/products/native_metal",
        "src/interop/postcard",
    },
    .required_dynamic_dependencies = &.{
        "Metal.framework",
        "Foundation.framework",
        "libobjc",
    },
    .forbidden_dynamic_dependencies = &.{"cuda"},
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
        .state = .parity_gated,
        .target_support = .macos,
        .unsupported_target_reason = "the Metal backend requires a macOS target and Apple Metal SDK",
        .build_step = "stwo-native-metal",
        .test_step = "test-native-metal",
        .executable = "stwo-zig-native-metal",
        .installed_artifacts = &.{"stwo-zig-native-metal"},
        .compatibility_aliases = &.{"native-proof-bench-metal"},
        .release_gates = &.{ "metal-test", "metal-core-aot-acceptance" },
        .benchmark_step = "native-proof-bench-metal",
        .profiler_step = "native-proof-profile",
        .dependencies = .{
            .module_roots = source_closure.entry_roots,
            .external_dependencies = &.{ "Foundation.framework", "Metal.framework", "libobjc" },
        },
        .source_closure = source_closure,
    };
}

pub fn addProduct(context: Context) void {
    const policy = descriptor(.cli);
    policy.validate() catch |err| std.debug.panic(
        "invalid Native Metal descriptor: {s}",
        .{@errorName(err)},
    );
    if (!policy.isAvailableOn(context.target.result.os.tag)) {
        product_policy.registerUnavailable(context.b, policy, context.target.result.os.tag);
        return;
    }

    const stwo = createStwoModule(context, .library);
    const runner = createRunnerModule(context, stwo, .library);
    const root = createProductModule(context, policy.product, stwo, runner);
    const installed = graph_install.executable(
        context.b,
        policy.executable.?,
        root,
        policy.build_step,
        "Build the focused Native Metal proof CLI",
    );
    metal.linkRuntime(context.b, installed.executable);

    const compatibility_root = createProductModule(context, product(.benchmark), stwo, runner);
    const compatibility = graph_install.executable(
        context.b,
        "native-proof-bench-metal",
        compatibility_root,
        policy.benchmark_step.?,
        "Build the compatible machine-readable Native Metal proof benchmark",
    );
    metal.linkRuntime(context.b, compatibility.executable);

    const tests = context.b.addTest(.{
        .root_module = createProductModule(context, product(.@"test"), stwo, runner),
    });
    metal.linkRuntime(context.b, tests);
    const facade_tests = context.b.addTest(.{
        .root_module = createStwoModule(context, .@"test"),
    });
    metal.linkRuntime(context.b, facade_tests);
    const runner_test_stwo = createStwoModule(context, .@"test");
    const runner_tests = context.b.addTest(.{
        .root_module = createRunnerModule(context, runner_test_stwo, .@"test"),
    });
    metal.linkRuntime(context.b, runner_tests);
    const test_step = context.b.step(
        policy.test_step.?,
        "Test Native Metal ownership, linkage, and visible capabilities",
    );
    test_step.dependOn(&context.b.addRunArtifact(tests).step);
    test_step.dependOn(&context.b.addRunArtifact(facade_tests).step);
    test_step.dependOn(&context.b.addRunArtifact(runner_tests).step);
    const policy_tests = context.b.addTest(.{
        .root_module = context.b.createModule(.{
            .root_source_file = context.b.path("build_support/product_policy_test.zig"),
            .target = context.target,
            .optimize = context.optimize,
        }),
    });
    test_step.dependOn(&context.b.addRunArtifact(policy_tests).step);

    const help = context.b.addRunArtifact(installed.executable);
    help.addArg("--help");
    test_step.dependOn(&help.step);
    const applications = context.b.addRunArtifact(installed.executable);
    applications.addArg("applications");
    test_step.dependOn(&applications.step);
    const lifecycle = context.b.addSystemCommand(&.{
        "python3",
        "scripts/check_native_metal_lifecycle.py",
    });
    lifecycle.addArtifactArg(installed.executable);
    test_step.dependOn(&lifecycle.step);

    const closure_check = closure_gate.addCheck(.{
        .b = context.b,
        .descriptor = policy,
        .binary = installed.executable,
    });
    test_step.dependOn(&closure_check.step);
    const marker_check = context.b.addSystemCommand(&.{
        "python3",
        "scripts/check_native_metal_product.py",
    });
    test_step.dependOn(&marker_check.step);
    const identity_cache_check = context.b.addSystemCommand(&.{
        "python3",
        "scripts/tests/test_delegated_identity_cache.py",
    });
    test_step.dependOn(&identity_cache_check.step);
}

fn createStwoModule(context: Context, role: graph.Role) *std.Build.Module {
    const module = graph.create(context.b, .{
        .product = product(role),
        .root_source_file = "src/stwo_native_metal.zig",
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
    _ = graph.addMetalBackendImport(
        context.b,
        context.protocol,
        product(role),
        context.target,
        context.optimize,
        cpu_backend,
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
    logical_product: graph.Product,
    stwo: *std.Build.Module,
    runner: *std.Build.Module,
) *std.Build.Module {
    const root = graph.create(context.b, .{
        .product = logical_product,
        .root_source_file = "src/products/native_metal/main.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    root.addImport("stwo", stwo);
    root.addImport("stwo_native_metal", stwo);
    root.addImport("native_proof_runner", runner);
    const transaction = graph.create(context.b, .{
        .product = logical_product,
        .root_source_file = "src/integrations/native/transaction.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    transaction.addImport("output_transaction", graph.create(context.b, .{
        .product = logical_product,
        .root_source_file = "src/interop/output_transaction.zig",
        .target = context.target,
        .optimize = context.optimize,
    }));
    root.addImport("native_transaction", transaction);
    const capabilities = graph.create(context.b, .{
        .product = logical_product,
        .root_source_file = "src/products/native_cpu/capabilities.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    root.addImport("native_cpu_capabilities", capabilities);
    root.addOptions("build_identity", graph_identity.buildOptions(context.b, context.identity));
    const runtime_identity = metal.sourceJitIdentity(context.b);
    root.addOptions(
        "product_identity",
        graph_identity.productOptionsWithRuntime(
            context.b,
            context.identity,
            logical_product,
            context.target,
            context.optimize,
            runtime_identity,
        ),
    );
    const native_identity = graph.create(context.b, .{
        .product = logical_product,
        .root_source_file = "src/integrations/native/product_identity.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    native_identity.addImport("native_proof_runner", runner);
    native_identity.addOptions(
        "product_identity",
        graph_identity.productOptionsWithRuntime(
            context.b,
            context.identity,
            logical_product,
            context.target,
            context.optimize,
            runtime_identity,
        ),
    );
    root.addImport("native_product_identity", native_identity);
    return root;
}

fn product(role: graph.Role) graph.Product {
    return .{
        .name = "stwo-native-metal",
        .frontend = .native,
        .backend = .metal,
        .role = role,
        .protocol_features = protocol_features,
    };
}

test "descriptor binds runtime identity and explicit target policy" {
    const policy = descriptor(.cli);
    try policy.validate();
    try std.testing.expectEqual(product_policy.State.parity_gated, policy.state);
    try std.testing.expectEqualStrings("stwo-zig-native-metal", policy.executable.?);
    try std.testing.expect(std.mem.indexOf(u8, policy.product.protocol_features, "metal-runtime-v1") != null);
    try std.testing.expectEqualStrings("source-jit", metal.runtime_modes);
}
