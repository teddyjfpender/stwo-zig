//! Build ownership for the independently consumable Stwo core library.

const std = @import("std");
const build_identity = @import("../build_identity.zig");
const closure_gate = @import("../gates/product_closure.zig");
const identity_receipt = @import("../graph/identity/receipt.zig");
const graph = @import("../graph/modules.zig");
const product_policy = @import("../graph/product.zig");

const source_closure = product_policy.SourceClosure{
    .entry_roots = &.{ "src/core/mod.zig", "src/products/core/surface.zig" },
    .named_imports = &.{
        .{ .name = "stwo_core", .source = "src/core/mod.zig" },
    },
    .allowed_prefixes = &.{ "src/core", "src/products/core" },
};

pub const descriptor = product_policy.Descriptor{
    .product = graph.coreProduct(.library),
    .state = .released,
    .target_support = .any,
    .build_step = "stwo-core",
    .test_step = "test-stwo-core",
    .executable = null,
    .installed_artifacts = &.{"lib/stwo-core.o"},
    .release_gates = &.{"test-stwo-core"},
    .dependencies = .{ .module_roots = source_closure.entry_roots },
    .source_closure = source_closure,
};

pub const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    identity: build_identity.Identity,
};

pub const Result = struct {
    module: *std.Build.Module,
};

pub fn addProduct(context: Context) Result {
    descriptor.validate() catch |err| std.debug.panic(
        "invalid Core descriptor: {s}",
        .{@errorName(err)},
    );
    const module = graph.addPublic(context.b, "stwo_core", .{
        .product = graph.coreProduct(.library),
        .root_source_file = "src/core/mod.zig",
        .target = context.target,
        .optimize = context.optimize,
    });

    const surface = surfaceModule(context, module);
    const object = context.b.addObject(.{ .name = "stwo-core", .root_module = surface });
    const install_object = context.b.addInstallFile(object.getEmittedBin(), "lib/stwo-core.o");
    const closure = closure_gate.addCheck(.{ .b = context.b, .descriptor = descriptor });
    const purity = purityCheck(context, "core");
    const build_step = context.b.step("stwo-core", "Build the focused Stwo core library");
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
        .artifact_path = "lib/stwo-core.o",
        .executable = false,
        .step_name = "identity-stwo-core",
        .output_name = "stwo-core.json",
    });
    identity_step.dependOn(&install_object.step);

    const tests = context.b.addTest(.{ .root_module = surfaceModule(context, module) });
    const test_step = context.b.step("test-stwo-core", "Test the focused Stwo core library and purity boundary");
    test_step.dependOn(&context.b.addRunArtifact(tests).step);
    test_step.dependOn(&closure.step);
    test_step.dependOn(&purity.step);
    const focused = graph.create(context.b, .{ .product = graph.coreProduct(.@"test"), .root_source_file = "src/core/focused_test_root.zig", .target = context.target, .optimize = context.optimize });
    const field_tests = context.b.addTest(.{ .root_module = focused, .filters = &.{"m31:"} });
    context.b.step("test-stwo-core-m31", "Test scalar and packed M31 arithmetic and butterfly parity").dependOn(&context.b.addRunArtifact(field_tests).step);

    const hash_tests = context.b.addTest(.{ .root_module = focused, .filters = &.{ "BLAKE2s", "blake2", "Blake2" } });
    context.b.step("test-stwo-core-blake2s", "Test BLAKE2s streams and mixed-height SIMD leaf hashing").dependOn(&context.b.addRunArtifact(hash_tests).step);
    return .{ .module = module };
}

fn surfaceModule(context: Context, core: *std.Build.Module) *std.Build.Module {
    const root = graph.create(context.b, .{
        .product = graph.coreProduct(.@"test"),
        .root_source_file = "src/products/core/surface.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    root.addImport("stwo_core", core);
    return root;
}

fn purityCheck(context: Context, product: []const u8) *std.Build.Step.Run {
    const check = context.b.addSystemCommand(&.{
        "python3",
        "scripts/check_library_products.py",
        "--product",
        product,
    });
    return check;
}
