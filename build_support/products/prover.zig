//! Build ownership for the backend-generic Stwo prover library.

const std = @import("std");
const build_identity = @import("../build_identity.zig");
const closure_gate = @import("../gates/product_closure.zig");
const identity_receipt = @import("../graph/identity/receipt.zig");
const graph = @import("../graph/modules.zig");
const product_policy = @import("../graph/product.zig");

const source_closure = product_policy.SourceClosure{
    .entry_roots = &.{
        "src/products/prover/root.zig",
        "src/products/prover/surface.zig",
    },
    .named_imports = &.{
        .{ .name = "stwo_core", .source = "src/core/mod.zig" },
        .{ .name = "stwo_backend_contracts", .source = "src/backend/mod.zig" },
        .{ .name = "stwo_prover_api", .source = "src/prover_api/mod.zig" },
        .{ .name = "stwo_prover_engine", .source = "src/prover/mod.zig" },
        .{ .name = "stwo_prover", .source = "src/products/prover/root.zig" },
    },
    .allowed_prefixes = &.{
        "src/core",
        "src/backend",
        "src/prover",
        "src/prover_api",
        "src/products/prover",
    },
};

pub const descriptor = product_policy.Descriptor{
    .product = graph.proverProduct(.library),
    .state = .released,
    .target_support = .any,
    .build_step = "stwo-prover",
    .test_step = "test-stwo-prover",
    .executable = null,
    .installed_artifacts = &.{"lib/stwo-prover.o"},
    .release_gates = &.{"test-stwo-prover"},
    .dependencies = .{ .module_roots = source_closure.entry_roots },
    .source_closure = source_closure,
};

pub const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    core: *std.Build.Module,
    identity: build_identity.Identity,
};

pub const Result = struct {
    module: *std.Build.Module,
    protocol: graph.ProtocolModules,
    test_step: *std.Build.Step,
};

pub fn addProduct(context: Context) Result {
    descriptor.validate() catch |err| std.debug.panic(
        "invalid Prover descriptor: {s}",
        .{@errorName(err)},
    );
    const protocol = graph.createProtocolModules(
        context.b,
        context.core,
        context.target,
        context.optimize,
    );
    const module = graph.addPublic(context.b, "stwo_prover", .{
        .product = graph.proverProduct(.library),
        .root_source_file = "src/products/prover/root.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    protocol.addImports(module);

    const surface = surfaceModule(context, module);
    const object = context.b.addObject(.{ .name = "stwo-prover", .root_module = surface });
    const install_object = context.b.addInstallFile(object.getEmittedBin(), "lib/stwo-prover.o");
    const closure = closure_gate.addCheck(.{ .b = context.b, .descriptor = descriptor });
    const purity = purityCheck(context);
    const build_step = context.b.step("stwo-prover", "Build the focused backend-generic Stwo prover library");
    build_step.dependOn(&object.step);
    build_step.dependOn(&install_object.step);
    build_step.dependOn(&closure.step);
    build_step.dependOn(&purity.step);
    const identity_step = identity_receipt.add(.{
        .b = context.b,
        .source = context.identity,
        .product = descriptor.product,
        .target = context.target,
        .optimize = context.optimize,
        .artifact = object.getEmittedBin(),
        .artifact_path = "lib/stwo-prover.o",
        .executable = false,
        .step_name = "identity-stwo-prover",
        .output_name = "stwo-prover.json",
    });
    identity_step.dependOn(&install_object.step);

    const tests = context.b.addTest(.{ .root_module = surfaceModule(context, module) });
    const engine_tests = context.b.addTest(.{ .root_module = protocol.prover });
    const test_step = context.b.step(
        "test-stwo-prover",
        "Test the focused generic prover, backend contracts, and purity boundary",
    );
    test_step.dependOn(&context.b.addRunArtifact(tests).step);
    test_step.dependOn(&context.b.addRunArtifact(engine_tests).step);
    test_step.dependOn(&closure.step);
    test_step.dependOn(&purity.step);

    return .{ .module = module, .protocol = protocol, .test_step = test_step };
}

fn surfaceModule(context: Context, prover: *std.Build.Module) *std.Build.Module {
    const root = graph.create(context.b, .{
        .product = graph.proverProduct(.@"test"),
        .root_source_file = "src/products/prover/surface.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    root.addImport("stwo_prover", prover);
    return root;
}

fn purityCheck(context: Context) *std.Build.Step.Run {
    return context.b.addSystemCommand(&.{
        "python3",
        "scripts/check_library_products.py",
        "--product",
        "prover",
    });
}
