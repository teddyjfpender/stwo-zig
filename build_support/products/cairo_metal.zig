//! Build ownership for the official Cairo + Metal product.

const std = @import("std");
const metal = @import("../backends/metal.zig");
const metal_aot = @import("../backends/metal_aot.zig");
const build_identity = @import("../build_identity.zig");
const cairo_cpu = @import("cairo_cpu.zig");
const cairo_support = @import("cairo_support.zig");
const cairo_vm_adapter = @import("cairo_cpu/vm_adapter.zig");
const oracle_gate = @import("cairo_metal/oracle_gate.zig");
const closure_gate = @import("../gates/product_closure.zig");
const graph_identity = @import("../graph/identity.zig");
const graph_install = @import("../graph/install.zig");
const graph = @import("../graph/modules.zig");
const policy = @import("../graph/product.zig");

const protocol_features =
    cairo_support.protocol_features ++
    "+metal-runtime-v2+plain-blake2s+authenticated-core-aot-v2";

const source_closure = policy.SourceClosure{
    .entry_roots = &.{
        "src/products/cairo_metal/main.zig",
        "src/stwo_cairo_metal.zig",
    },
    .named_imports = &.{
        .{ .name = "cairo_product", .source = "src/products/cairo/shared/mod.zig" },
        .{ .name = "stwo_cairo", .source = "src/stwo_cairo_metal.zig" },
        .{ .name = "stwo_cairo_metal", .source = "src/stwo_cairo_metal.zig" },
        .{ .name = "stwo_backend_contracts", .source = "src/backend/mod.zig" },
        .{ .name = "stwo_core", .source = "src/core/mod.zig" },
        .{ .name = "stwo_prover_impl", .source = "src/prover/mod.zig" },
    },
    .generated_imports = &.{ "metal_aot_config", "product_identity" },
    .allowed_files = &.{
        "src/stwo_cairo_metal.zig",
        "src/interop/atomic_file.zig",
        "src/interop/bzip2.zig",
        "src/interop/output_transaction.zig",
    },
    .allowed_prefixes = &.{
        "src/backend",
        "src/backends/cpu_scalar",
        "src/backends/metal",
        "src/core",
        "src/frontends/cairo",
        "src/integrations/cairo_metal/prover",
        "src/products/cairo",
        "src/products/cairo_metal",
        "src/prover",
    },
    .required_dynamic_dependencies = &.{
        "Metal.framework",
        "Foundation.framework",
        "libobjc",
    },
    .forbidden_dynamic_dependencies = &.{"cuda"},
};

pub const descriptor = policy.Descriptor{
    .product = product(.cli),
    .state = .staged,
    .target_support = .macos,
    .unsupported_target_reason = "the Metal backend requires a macOS target and Apple Metal SDK",
    .build_step = "stwo-cairo-metal",
    .test_step = "test-cairo-metal-product",
    .executable = "stwo-cairo-metal",
    .installed_artifacts = &.{
        "stwo-cairo-metal",
        "stwo-cairo-vm-adapter",
        "share/stwo-zig/cairo/official/all_opcodes.params.json",
        "share/stwo-zig/cairo/official/all_builtins.params.json",
        "share/stwo-zig/metal/core/stwo_zig_core.air",
        "share/stwo-zig/metal/core/stwo_zig_core.manifest.json",
        "share/stwo-zig/metal/core/stwo_zig_core.manifest.sha256",
        "share/stwo-zig/metal/core/stwo_zig_core.metal",
        "share/stwo-zig/metal/core/stwo_zig_core.metallib",
    },
    .release_gates = &.{
        "test-cairo-metal-product",
        "test-cairo-metal-oracle",
    },
    .dependencies = .{
        .module_roots = source_closure.entry_roots,
        .external_dependencies = &.{
            "Foundation.framework",
            "Metal.framework",
            "libobjc",
        },
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
        "invalid Cairo Metal descriptor: {s}",
        .{@errorName(err)},
    );
    if (!descriptor.isAvailableOn(context.target.result.os.tag)) {
        policy.registerUnavailable(
            context.b,
            descriptor,
            context.target.result.os.tag,
        );
        return;
    }
    const configured_bundle = context.b.option(
        []const u8,
        "metal-core-aot-bundle",
        "Authenticated core Metal AOT bundle consumed by stwo-cairo-metal",
    ) orelse {
        registerMissingAotBundle(context.b);
        return;
    };
    const aot_bundle = metal_aot.loadExternalBundle(
        context.b,
        configured_bundle,
    );

    const stwo = createStwoModule(context, .library);
    const shared = cairo_support.createProductSupportModule(
        context.b,
        context.target,
        context.optimize,
        product(.library),
        stwo,
    );
    const root = createProductModule(
        context,
        descriptor.product,
        stwo,
        shared,
        aot_bundle,
    );
    const installed = graph_install.executable(
        context.b,
        descriptor.executable.?,
        root,
        descriptor.build_step,
        "Build the focused official Cairo Metal proof CLI",
    );
    cairo_support.linkBzip2(context.b, installed.executable);
    metal.linkRuntime(context.b, installed.executable);
    installed.build_step.dependOn(cairo_vm_adapter.addInstall(context.b));
    cairo_support.installProfile(context.b, installed.build_step);
    aot_bundle.install(context.b, installed.build_step);

    const test_stwo = createStwoModule(context, .@"test");
    const test_shared = cairo_support.createProductSupportModule(
        context.b,
        context.target,
        context.optimize,
        product(.@"test"),
        test_stwo,
    );
    const tests = context.b.addTest(.{
        .root_module = createProductModule(
            context,
            product(.@"test"),
            test_stwo,
            test_shared,
            aot_bundle,
        ),
    });
    cairo_support.linkBzip2(context.b, tests);
    metal.linkRuntime(context.b, tests);
    const run_tests = context.b.addRunArtifact(tests);
    run_tests.setEnvironmentVariable(
        "STWO_CAIRO_METAL_AOT_BUNDLE",
        aot_bundle.absolute_path,
    );
    const test_step = context.b.step(
        descriptor.test_step.?,
        "Test the Cairo Metal product, lifecycle, and command contract",
    );
    test_step.dependOn(&run_tests.step);

    const help = context.b.addRunArtifact(installed.executable);
    help.addArg("--help");
    test_step.dependOn(&help.step);
    const capabilities = context.b.addRunArtifact(installed.executable);
    capabilities.addArg("capabilities");
    test_step.dependOn(&capabilities.step);
    const identity = context.b.addRunArtifact(installed.executable);
    identity.addArg("identity");
    test_step.dependOn(&identity.step);
    const fail_closed = context.b.addSystemCommand(&.{
        "python3",
        "scripts/check_cairo_metal_aot_fail_closed.py",
        "--executable",
    });
    fail_closed.addArtifactArg(installed.executable);
    fail_closed.addArgs(&.{
        "--bundle",
        aot_bundle.absolute_path,
        "--prover-input",
        context.b.pathFromRoot(
            "vectors/cairo/official/all_opcodes.prover_input.json",
        ),
        "--params",
        context.b.pathFromRoot(
            "vectors/cairo/official/all_opcodes.params.json",
        ),
    });
    test_step.dependOn(&fail_closed.step);

    const closure = closure_gate.addCheck(.{
        .b = context.b,
        .descriptor = descriptor,
        .binary = installed.executable,
    });
    test_step.dependOn(&closure.step);
    oracle_gate.add(
        context.b,
        installed.executable,
        cairo_cpu.addReferenceExecutable(.{
            .b = context.b,
            .target = context.target,
            .optimize = context.optimize,
            .identity = context.identity,
            .protocol = context.protocol,
        }),
        aot_bundle.absolute_path,
    );
}

fn registerMissingAotBundle(b: *std.Build) void {
    const reason =
        "requires -Dmetal-core-aot-bundle=<path>; build the bundle with " ++
        "`zig build metal-core-aot-acceptance` on a full-Xcode host or " ++
        "consume its retained artifact";
    const failure = b.addFail(b.fmt(
        "{s} is unavailable: {s}",
        .{ descriptor.product.name, reason },
    ));
    b.step(descriptor.build_step, reason).dependOn(&failure.step);
    b.step(descriptor.test_step.?, reason).dependOn(&failure.step);
    for (descriptor.release_gates) |gate| {
        if (std.mem.eql(u8, gate, descriptor.test_step.?)) continue;
        b.step(gate, reason).dependOn(&failure.step);
    }
}

fn createStwoModule(
    context: Context,
    role: graph.Role,
) *std.Build.Module {
    const module = graph.create(context.b, .{
        .product = product(role),
        .root_source_file = "src/stwo_cairo_metal.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(module);
    return module;
}

fn createProductModule(
    context: Context,
    logical_product: graph.Product,
    stwo: *std.Build.Module,
    shared: *std.Build.Module,
    aot_bundle: metal_aot.ExternalBundle,
) *std.Build.Module {
    const root = graph.create(context.b, .{
        .product = logical_product,
        .root_source_file = "src/products/cairo_metal/main.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    root.addImport("stwo_cairo_metal", stwo);
    root.addImport("cairo_product", shared);
    root.addOptions("metal_aot_config", aot_bundle.addOptions(context.b));
    root.addOptions(
        "product_identity",
        graph_identity.productOptionsWithRuntime(
            context.b,
            context.identity,
            logical_product,
            context.target,
            context.optimize,
            metal.authenticatedAotIdentity(
                context.b,
                &aot_bundle.manifest_sha256_hex,
            ),
        ),
    );
    return root;
}

fn product(role: graph.Role) graph.Product {
    return .{
        .name = "stwo-cairo-metal",
        .frontend = .cairo,
        .backend = .metal,
        .role = role,
        .protocol_features = protocol_features,
    };
}

test "Cairo Metal is a focused staged product" {
    try descriptor.validate();
    try std.testing.expect(descriptor.isConstructible());
    try std.testing.expectEqual(policy.State.staged, descriptor.state);
}
