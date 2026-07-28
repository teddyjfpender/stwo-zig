const std = @import("std");
const metal_backend = @import("backends/metal.zig");
const build_identity = @import("build_identity.zig");
const graph_identity = @import("graph/identity.zig");
const graph = @import("graph/modules.zig");
const native_cpu_product = @import("products/native_cpu.zig");
const native_metal_product = @import("products/native_metal.zig");

pub const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    stwo_module: *std.Build.Module,
    native_proof_runner_module: *std.Build.Module,
    native_resource_admission_module: *std.Build.Module,
    test_step: *std.Build.Step,
    identity: build_identity.Identity,
    product: graph.Product,
    runtime: graph_identity.RuntimeHooks,
    metal_enabled: bool,
};

pub fn addProduct(context: Context) *std.Build.Step.Compile {
    const b = context.b;
    const resource_admission = context.native_resource_admission_module;
    const identity = context.identity;
    const identity_options = graph_identity.buildOptions(b, identity);
    const product_options = graph_identity.productOptionsWithRuntime(
        b,
        identity,
        context.product,
        context.target,
        context.optimize,
        context.runtime,
    );
    const capabilities = b.addOptions();
    capabilities.addOption(bool, "metal_enabled", context.metal_enabled);
    capabilities.addOption(bool, "native_cpu_enabled", native_cpu_product.descriptor(.cli).isConstructible());
    capabilities.addOption([]const u8, "native_cpu_product", native_cpu_product.descriptor(.cli).product.name);
    capabilities.addOption([]const u8, "native_cpu_state", @tagName(native_cpu_product.descriptor(.cli).state));
    capabilities.addOption([]const u8, "native_metal_product", native_metal_product.descriptor(.cli).product.name);
    capabilities.addOption([]const u8, "native_metal_state", @tagName(native_metal_product.descriptor(.cli).state));
    const native_capabilities = b.createModule(.{
        .root_source_file = b.path("src/products/native_cpu/capabilities.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    const riscv_capabilities = b.createModule(.{
        .root_source_file = b.path("src/products/riscv_cpu/capabilities.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    const riscv_adapter = b.createModule(.{
        .root_source_file = graph.source(
            b,
            "src/integrations/riscv_cpu/proof_adapter.zig",
            context.target,
            context.optimize,
        ),
        .target = context.target,
        .optimize = context.optimize,
    });
    riscv_adapter.addImport("stwo", context.stwo_module);
    riscv_adapter.addImport("riscv_cpu_capabilities", riscv_capabilities);
    riscv_adapter.addOptions("build_identity", identity_options);
    const module = b.createModule(.{
        .root_source_file = b.path("src/tools/prove/main.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    module.addImport("stwo", context.stwo_module);
    module.addImport("native_proof_runner", context.native_proof_runner_module);
    module.addImport("native_resource_admission", resource_admission);
    const native_transaction = b.createModule(.{
        .root_source_file = b.path("src/integrations/native/transaction.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    const output_transaction = b.createModule(.{
        .root_source_file = b.path("src/interop/output_transaction.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    native_transaction.addImport("output_transaction", output_transaction);
    module.addImport("native_transaction", native_transaction);
    module.addImport("output_transaction", output_transaction);
    const native_identity = b.createModule(.{
        .root_source_file = b.path("src/integrations/native/product_identity.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    native_identity.addImport("native_proof_runner", context.native_proof_runner_module);
    native_identity.addOptions("product_identity", product_options);
    module.addImport("native_product_identity", native_identity);
    module.addOptions("build_identity", identity_options);
    module.addOptions("aggregate_capabilities", capabilities);
    module.addOptions("product_identity", product_options);
    module.addImport("native_cpu_capabilities", native_capabilities);
    module.addImport("riscv_cpu_capabilities", riscv_capabilities);
    module.addImport("riscv_adapter", riscv_adapter);
    const executable = b.addExecutable(.{ .name = "stwo-zig", .root_module = module });
    executable.linkLibC();
    if (context.metal_enabled) metal_backend.linkRuntime(b, executable);
    const install = b.addInstallArtifact(executable, .{});
    b.getInstallStep().dependOn(&install.step);
    const build_step = b.step("stwo-zig", "Build the production proof CLI");
    build_step.dependOn(&install.step);

    const parser_module = b.createModule(.{
        .root_source_file = b.path("src/tools/prove/cli.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    parser_module.addImport("native_resource_admission", resource_admission);
    const parser_tests = b.addTest(.{ .root_module = parser_module });
    context.test_step.dependOn(&b.addRunArtifact(parser_tests).step);
    const resource_parser_module = b.createModule(.{
        .root_source_file = b.path("src/tools/prove/cli_resource_test.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    resource_parser_module.addImport("prove_cli", parser_module);
    resource_parser_module.addImport("native_proof_runner", context.native_proof_runner_module);
    resource_parser_module.addImport("native_resource_admission", resource_admission);
    context.test_step.dependOn(&b.addRunArtifact(
        b.addTest(.{ .root_module = resource_parser_module }),
    ).step);

    const registry_test_module = b.createModule(.{
        .root_source_file = b.path("src/tools/prove/registry.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    registry_test_module.addOptions("aggregate_capabilities", capabilities);
    registry_test_module.addImport("native_cpu_capabilities", native_capabilities);
    registry_test_module.addImport("riscv_cpu_capabilities", riscv_capabilities);
    const registry_tests = b.addTest(.{ .root_module = registry_test_module });
    context.test_step.dependOn(&b.addRunArtifact(registry_tests).step);

    const riscv_artifact_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/interop/riscv_artifact.zig"),
        .target = context.target,
        .optimize = context.optimize,
    }) });
    context.test_step.dependOn(&b.addRunArtifact(riscv_artifact_tests).step);

    const dispatch_module = b.createModule(.{
        .root_source_file = b.path("src/tools/prove/native_dispatch.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    dispatch_module.addImport("stwo", context.stwo_module);
    dispatch_module.addImport("native_proof_runner", context.native_proof_runner_module);
    dispatch_module.addImport("native_resource_admission", resource_admission);
    dispatch_module.addOptions("aggregate_capabilities", capabilities);
    dispatch_module.addImport("native_product_identity", native_identity);
    const dispatch_tests = b.addTest(.{ .root_module = dispatch_module });
    if (context.metal_enabled) metal_backend.linkRuntime(b, dispatch_tests);
    context.test_step.dependOn(&b.addRunArtifact(dispatch_tests).step);

    const app_module = b.createModule(.{
        .root_source_file = b.path("src/tools/prove/app.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    app_module.addImport("stwo", context.stwo_module);
    app_module.addImport("native_proof_runner", context.native_proof_runner_module);
    app_module.addImport("native_resource_admission", resource_admission);
    app_module.addImport("native_transaction", native_transaction);
    app_module.addImport("output_transaction", output_transaction);
    app_module.addOptions("build_identity", identity_options);
    app_module.addOptions("aggregate_capabilities", capabilities);
    app_module.addOptions("product_identity", product_options);
    app_module.addImport("native_product_identity", native_identity);
    app_module.addImport("native_cpu_capabilities", native_capabilities);
    app_module.addImport("riscv_cpu_capabilities", riscv_capabilities);
    app_module.addImport("riscv_adapter", riscv_adapter);
    const app_tests = b.addTest(.{ .root_module = app_module });
    app_tests.linkLibC();
    if (context.metal_enabled) metal_backend.linkRuntime(b, app_tests);
    context.test_step.dependOn(&b.addRunArtifact(app_tests).step);
    return executable;
}

pub fn resolveBuildIdentity(b: *std.Build) build_identity.Identity {
    const explicit_commit = b.option(
        []const u8,
        "implementation-commit",
        "Exact lowercase 40-hex source commit embedded in the production CLI",
    );
    const explicit_dirty = b.option(
        bool,
        "implementation-dirty",
        "Whether the source embedded in the production CLI has local modifications",
    );
    const explicit_tree = b.option(
        []const u8,
        "implementation-tree",
        "Exact lowercase 40-hex source tree for an identity override",
    );
    const explicit_dirty_digest = b.option(
        []const u8,
        "implementation-dirty-content-sha256",
        "Canonical dirty-content digest required for a diagnostic dirty override",
    );
    if ((explicit_commit == null) != (explicit_dirty == null))
        std.debug.panic("cannot resolve production CLI build identity: incomplete override", .{});
    if (explicit_commit == null and (explicit_tree != null or explicit_dirty_digest != null))
        std.debug.panic("cannot resolve production CLI build identity: orphan tree or dirty digest", .{});
    return build_identity.resolveWithOverride(
        b.allocator,
        b.pathFromRoot("."),
        if (explicit_commit) |commit| .{
            .commit = commit,
            .tree = explicit_tree,
            .dirty = explicit_dirty.?,
            .dirty_content_sha256 = explicit_dirty_digest,
        } else null,
    ) catch |err| std.debug.panic("cannot resolve production CLI build identity: {s}", .{@errorName(err)});
}
