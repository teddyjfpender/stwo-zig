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
        "src/prover/focused_test_root.zig",
        "src/prover/merkle_test_root.zig",
        "src/prover/work_pool_test.zig",
    },
    .named_imports = &.{
        .{ .name = "stwo_core", .source = "src/core/mod.zig" },
        .{ .name = "stwo_backend_contracts", .source = "src/backend/mod.zig" },
        .{ .name = "stwo_prover_api", .source = "src/prover_api/mod.zig" },
        .{ .name = "stwo_prover_engine", .source = "src/prover/mod.zig" },
        .{ .name = "stwo_prover", .source = "src/products/prover/root.zig" },
        .{ .name = "lifted_height_vectors", .source = "src/core/vcs_lifted/testdata/lifted_height_vectors.zig" },
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
    const focused = graph.create(context.b, .{ .product = graph.proverProduct(.@"test"), .root_source_file = "src/prover/focused_test_root.zig", .target = context.target, .optimize = context.optimize });
    protocol.addImports(focused);
    const fft_tests = context.b.addTest(.{ .root_module = focused, .filters = &.{ "circle poly", "fft" } });
    context.b.step("test-stwo-prover-fft", "Test circle transforms, radix scheduling and coefficient parity").dependOn(&context.b.addRunArtifact(fft_tests).step);
    const sampling_tests = context.b.addTest(.{ .root_module = focused, .filters = &.{ "sampled", "point evaluation", "circle poly" } });
    context.b.step("test-stwo-prover-sampling", "Test sampled values and independent circle polynomial evaluation").dependOn(&context.b.addRunArtifact(sampling_tests).step);
    const merkle_root = graph.create(context.b, .{ .product = graph.proverProduct(.@"test"), .root_source_file = "src/prover/merkle_test_root.zig", .target = context.target, .optimize = context.optimize });
    protocol.addImports(merkle_root);
    // Test-only Rust-oracle data owned by core, outside the stwo_core API.
    merkle_root.addImport("lifted_height_vectors", graph.create(context.b, .{ .product = graph.proverProduct(.@"test"), .root_source_file = "src/core/vcs_lifted/testdata/lifted_height_vectors.zig", .target = context.target, .optimize = context.optimize }));
    const merkle_tests = context.b.addTest(.{ .root_module = merkle_root, .filters = &.{ "vcs_lifted", "MerkleProverLifted" } });
    context.b.step("test-stwo-prover-merkle", "Test lifted Merkle commitment paths and allocation custody").dependOn(&context.b.addRunArtifact(merkle_tests).step);
    const preparation_root = graph.create(context.b, .{ .product = graph.proverProduct(.@"test"), .root_source_file = "src/prover/focused_test_root.zig", .target = context.target, .optimize = context.optimize });
    protocol.addImports(preparation_root);
    const preparation_tests = context.b.addTest(.{ .root_module = preparation_root, .filters = &.{"column preparation"} });
    context.b.step("test-stwo-prover-preparation", "Test prepared column cache and asynchronous publication").dependOn(&context.b.addRunArtifact(preparation_tests).step);
    const coefficient_root = graph.create(context.b, .{ .product = graph.proverProduct(.@"test"), .root_source_file = "src/prover/coefficient_storage_test_root.zig", .target = context.target, .optimize = context.optimize });
    protocol.addImports(coefficient_root);
    const coefficient_tests = context.b.addTest(.{ .root_module = coefficient_root, .filters = &.{"coefficient storage"} });
    context.b.step("test-stwo-prover-coefficient-storage", "Qualify compact polynomial commitments, quotients, openings and failure custody").dependOn(&context.b.addRunArtifact(coefficient_tests).step);
    const pool_root = graph.create(context.b, .{ .product = graph.proverProduct(.@"test"), .root_source_file = "src/prover/work_pool_test.zig", .target = context.target, .optimize = context.optimize });
    protocol.addImports(pool_root);
    const pool_tests = context.b.addTest(.{ .root_module = pool_root });
    context.b.step("test-stwo-prover-pool", "Test proof-scoped pool lifetimes and concurrent borrowed coordinators").dependOn(&context.b.addRunArtifact(pool_tests).step);

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
