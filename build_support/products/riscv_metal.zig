//! Build ownership for the RV32IM frontend on the fail-closed Metal backend.
//!
//! Two executables come out of this product and they are *not* the same
//! program:
//!
//!   * `stwo-zig-riscv-metal` — the production proof CLI, built from
//!     `src/products/riscv_metal/main.zig`. It binds the engine-generic proof
//!     adapter (`src/integrations/riscv_cpu/proof_adapter.zig`) to
//!     `MetalProverEngine` through the shared product shell, so it speaks the
//!     same `prove`/`bench`/`verify`/`applications` contract as
//!     `stwo-zig-riscv-cpu` with `--backend metal` instead of `--backend cpu`.
//!   * `riscv-metal-bench` — the benchmark CLI, still built from
//!     `src/riscv_metal_bench_cli.zig`. Until this change that program was also
//!     installed under the `stwo-zig-riscv-metal` name; consumers of the *bench*
//!     argv shape (`--elf X --production --profile`) must use
//!     `riscv-metal-bench`.
//!
//! Injected module-name contract for `src/products/riscv_metal/*` (mirrors
//! `riscv_cpu.zig` so the shared shell files compile unchanged in both
//! products):
//!
//!   | module name              | source                                        |
//!   |--------------------------|-----------------------------------------------|
//!   | `stwo`, `stwo_riscv_metal` | `src/products/riscv_metal/root.zig`         |
//!   | `riscv_adapter`          | `src/integrations/riscv_cpu/proof_adapter.zig`|
//!   | `riscv_capabilities`     | `src/products/riscv_metal/capabilities.zig`   |
//!   | `riscv_cpu_capabilities` | the same file, under the name the shared       |
//!   |                          | adapter hard-codes                            |
//!   | `riscv_shared_{app,cli,registry}` | `src/products/riscv_shared/*.zig`    |
//!   | `output_transaction`     | `src/interop/output_transaction.zig`          |
//!   | `interop_atomic_file`    | `src/interop/atomic_file.zig`                 |
//!   | `interop_postcard`       | `src/interop/postcard.zig`                    |
//!   | `interop_riscv_artifact` | `src/interop/riscv_artifact.zig`              |
//!
//! The three `interop_*` names exist because the CPU facade
//! (`src/stwo_riscv_cpu.zig`) reaches those files with relative imports from
//! `src/`, while this product's facade root is
//! `src/products/riscv_metal/root.zig`: Zig 0.15 rejects a relative `@import`
//! that leaves the importing module's root directory ("import of file outside
//! module path"), so the facade must receive them as named modules instead.

const std = @import("std");
const metal = @import("../backends/metal.zig");
const build_identity = @import("../build_identity.zig");
const closure_gate = @import("../gates/product_closure.zig");
const graph_identity = @import("../graph/identity.zig");
const graph_install = @import("../graph/install.zig");
const graph = @import("../graph/modules.zig");
const product_policy = @import("../graph/product.zig");

const product = graph.Product{
    .name = "stwo-riscv-metal",
    .frontend = .riscv,
    .backend = .metal,
    .role = .cli,
    .protocol_features = "rv32im-zkvm-v1+lifted-pcs-v1+metal-runtime-v1",
};

const source_closure = product_policy.SourceClosure{
    .entry_roots = &.{
        "src/products/riscv_metal/main.zig",
        "src/riscv_metal_bench_cli.zig",
        "src/products/riscv_metal/root.zig",
        "src/integrations/riscv_metal/mod.zig",
        "src/tests/riscv/metal_backend_test.zig",
    },
    .named_imports = &.{
        .{ .name = "stwo", .source = "src/products/riscv_metal/root.zig" },
        .{ .name = "stwo_backend_contracts", .source = "src/backend/mod.zig" },
        .{ .name = "stwo_core", .source = "src/core/mod.zig" },
        .{ .name = "stwo_metal_backend", .source = "src/backends/metal/mod.zig" },
        .{ .name = "stwo_proof_wire", .source = "src/interop/proof_wire/mod.zig" },
        .{ .name = "stwo_prover_api", .source = "src/prover_api/mod.zig" },
        .{ .name = "stwo_prover_engine", .source = "src/prover/mod.zig" },
        .{ .name = "stwo_riscv_frontend", .source = "src/frontends/riscv/mod.zig" },
        .{ .name = "stwo_riscv_metal", .source = "src/products/riscv_metal/root.zig" },
        .{ .name = "stwo_riscv_metal_integration", .source = "src/integrations/riscv_metal/mod.zig" },
        .{ .name = "riscv_adapter", .source = "src/integrations/riscv_cpu/proof_adapter.zig" },
        .{ .name = "riscv_capabilities", .source = "src/products/riscv_metal/capabilities.zig" },
        .{ .name = "riscv_cpu_capabilities", .source = "src/products/riscv_metal/capabilities.zig" },
        .{ .name = "riscv_shared_app", .source = "src/products/riscv_shared/app.zig" },
        .{ .name = "riscv_shared_cli", .source = "src/products/riscv_shared/cli.zig" },
        .{ .name = "riscv_shared_registry", .source = "src/products/riscv_shared/registry.zig" },
        .{ .name = "output_transaction", .source = "src/interop/output_transaction.zig" },
        .{ .name = "interop_atomic_file", .source = "src/interop/atomic_file.zig" },
        .{ .name = "interop_postcard", .source = "src/interop/postcard.zig" },
        .{ .name = "interop_riscv_artifact", .source = "src/interop/riscv_artifact.zig" },
    },
    .allowed_files = &.{
        "src/riscv_metal_bench_cli.zig",
        "src/products/riscv_metal/root.zig",
        "src/tests/riscv/metal_backend_test.zig",
        "src/interop/atomic_file.zig",
        "src/interop/output_transaction.zig",
        "src/interop/postcard.zig",
        "src/interop/proof_wire/mod.zig",
        "src/interop/riscv_artifact.zig",
    },
    .allowed_prefixes = &.{
        "src/core",
        "src/backend",
        "src/backends/metal",
        "src/prover",
        "src/prover_api",
        "src/frontends/riscv",
        "src/integrations/riscv_cpu",
        "src/integrations/riscv_metal",
        "src/interop/postcard",
        "src/interop/riscv_artifact",
        "src/products/riscv_metal",
        "src/products/riscv_shared",
        "src/tools/riscv",
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

pub const descriptor = product_policy.Descriptor{
    .product = product,
    .state = .parity_gated,
    .target_support = .macos,
    .unsupported_target_reason = "the Metal backend requires a macOS target and Apple Metal SDK",
    .build_step = "stwo-riscv-metal",
    .test_step = "test-riscv-metal",
    .executable = "stwo-zig-riscv-metal",
    .installed_artifacts = &.{"stwo-zig-riscv-metal"},
    .compatibility_aliases = &.{"riscv-metal-bench"},
    .release_gates = &.{ "test-riscv-metal", "metal-test", "riscv-release-gate" },
    .benchmark_step = "riscv-metal-bench",
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

pub fn addProduct(context: Context) void {
    descriptor.validate() catch |err| std.debug.panic(
        "invalid RISC-V Metal descriptor: {s}",
        .{@errorName(err)},
    );
    if (!descriptor.isAvailableOn(context.target.result.os.tag)) {
        product_policy.registerUnavailable(context.b, descriptor, context.target.result.os.tag);
        return;
    }

    const installed = graph_install.executable(
        context.b,
        descriptor.executable.?,
        productionRootModule(context),
        descriptor.build_step,
        "Build the focused RV32IM Metal proof CLI",
    );
    metal.linkRuntime(context.b, installed.executable);

    const benchmark_product = graph.Product{
        .name = product.name,
        .frontend = product.frontend,
        .backend = product.backend,
        .role = .benchmark,
        .protocol_features = product.protocol_features,
    };
    const benchmark = graph_install.executable(
        context.b,
        "riscv-metal-bench",
        createModule(context, benchmark_product, "src/riscv_metal_bench_cli.zig"),
        descriptor.benchmark_step.?,
        "Build the compatible RV32IM Metal benchmark",
    );
    metal.linkRuntime(context.b, benchmark.executable);

    const stwo_tests = createFacadeModule(
        context,
        testProduct(),
    );
    const integration_tests = context.b.addTest(.{ .root_module = stwo_tests });
    metal.linkRuntime(context.b, integration_tests);
    const proof_test_module = createModule(
        context,
        testProduct(),
        "src/tests/riscv/metal_backend_test.zig",
    );
    const stwo = createFacadeModule(context, moduleProduct(.library));
    proof_test_module.addImport("stwo_riscv_metal", stwo);
    const proof_tests = context.b.addTest(.{
        .root_module = proof_test_module,
    });
    metal.linkRuntime(context.b, proof_tests);

    const test_step = context.b.step(
        descriptor.test_step.?,
        "Test RV32IM Metal engine ownership and end-to-end proof parity",
    );
    test_step.dependOn(&context.b.addRunArtifact(integration_tests).step);
    test_step.dependOn(&context.b.addRunArtifact(proof_tests).step);

    const closure_check = closure_gate.addCheck(.{
        .b = context.b,
        .descriptor = descriptor,
        .binary = installed.executable,
    });
    test_step.dependOn(&closure_check.step);
}

/// The production CLI's root module. Mirrors `riscv_cpu.zig`'s `addExecutable`
/// binding one-for-one so the shared shell (`src/products/riscv_shared/*.zig`)
/// and the engine-generic adapter see exactly the same injected module names in
/// both products.
fn productionRootModule(context: Context) *std.Build.Module {
    const b = context.b;
    const stwo = createFacadeModule(context, moduleProduct(.library));
    const capabilities = createLeafModule(context, "src/products/riscv_metal/capabilities.zig");
    const adapter = createAdapterModule(context, stwo, capabilities);
    const root = graph.create(b, .{
        .product = product,
        .root_source_file = "src/products/riscv_metal/main.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    root.addImport("stwo", stwo);
    root.addImport("stwo_riscv_metal", stwo);
    root.addImport("riscv_adapter", adapter);
    root.addImport("riscv_capabilities", capabilities);
    root.addImport("riscv_cpu_capabilities", capabilities);
    root.addImport("riscv_shared_app", createLeafModule(
        context,
        "src/products/riscv_shared/app.zig",
    ));
    root.addImport("riscv_shared_registry", createLeafModule(
        context,
        "src/products/riscv_shared/registry.zig",
    ));
    root.addImport("riscv_shared_cli", createLeafModule(
        context,
        "src/products/riscv_shared/cli.zig",
    ));
    root.addImport("output_transaction", createLeafModule(
        context,
        "src/interop/output_transaction.zig",
    ));
    root.addOptions("build_identity", graph_identity.buildOptions(b, context.identity));
    root.addOptions(
        "product_identity",
        graph_identity.productOptions(b, context.identity, product, context.target, context.optimize),
    );
    return root;
}

/// The engine-generic proof adapter. It is shared verbatim with the CPU
/// product, so it keeps the historical `riscv_cpu_capabilities` import name —
/// here bound to *this* product's capability file, which reports
/// `backend = "metal"`.
fn createAdapterModule(
    context: Context,
    stwo: *std.Build.Module,
    capabilities: *std.Build.Module,
) *std.Build.Module {
    const module = graph.create(context.b, .{
        .product = product,
        .root_source_file = "src/integrations/riscv_cpu/proof_adapter.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(module);
    module.addImport("stwo", stwo);
    module.addImport("riscv_cpu_capabilities", capabilities);
    module.addOptions("build_identity", graph_identity.buildOptions(context.b, context.identity));
    return module;
}

/// A product-local module whose source imports nothing but `std` and its own
/// directory. The shared shell files, the capability file and the interop
/// wire files are all in this class.
fn createLeafModule(context: Context, root_source_file: []const u8) *std.Build.Module {
    return graph.create(context.b, .{
        .product = product,
        .root_source_file = root_source_file,
        .target = context.target,
        .optimize = context.optimize,
    });
}

fn createModule(
    context: Context,
    logical_product: graph.Product,
    root_source_file: []const u8,
) *std.Build.Module {
    const module = graph.create(context.b, .{
        .product = logical_product,
        .root_source_file = root_source_file,
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(module);
    const dependencies = createDependencies(context, logical_product);
    module.addImport("stwo_metal_backend", dependencies.metal_backend);
    module.addImport("stwo_riscv_frontend", dependencies.frontend);
    module.addImport("stwo_riscv_metal_integration", dependencies.integration);
    return module;
}

fn createFacadeModule(
    context: Context,
    logical_product: graph.Product,
) *std.Build.Module {
    const dependencies = createDependencies(context, logical_product);
    const facade = graph.create(context.b, .{
        .product = logical_product,
        .root_source_file = "src/products/riscv_metal/root.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(facade);
    facade.addImport("stwo_riscv_frontend", dependencies.frontend);
    facade.addImport("stwo_riscv_metal_integration", dependencies.integration);
    addInteropImports(context, logical_product, facade);
    return facade;
}

/// The facade's `interop` namespace. `src/stwo_riscv_cpu.zig` reaches these
/// three files relatively because its module root is `src/`; this product's
/// facade root is two directories deeper, and Zig 0.15 rejects a relative
/// `@import` that escapes the module root, so each file becomes its own named
/// module. `postcard` is the only one with dependencies of its own.
fn addInteropImports(
    context: Context,
    logical_product: graph.Product,
    facade: *std.Build.Module,
) void {
    const postcard = createLeafModule(context, "src/interop/postcard.zig");
    postcard.addImport("stwo_core", context.protocol.core);
    postcard.addImport("stwo_proof_wire", graph.createProofWire(
        context.b,
        context.protocol,
        logical_product,
        context.target,
        context.optimize,
    ));
    facade.addImport("interop_atomic_file", createLeafModule(
        context,
        "src/interop/atomic_file.zig",
    ));
    facade.addImport("interop_postcard", postcard);
    facade.addImport("interop_riscv_artifact", createLeafModule(
        context,
        "src/interop/riscv_artifact.zig",
    ));
}

const Dependencies = struct {
    frontend: *std.Build.Module,
    metal_backend: *std.Build.Module,
    integration: *std.Build.Module,
};

fn createDependencies(
    context: Context,
    logical_product: graph.Product,
) Dependencies {
    const frontend = graph.createRiscVFrontend(
        context.b,
        context.protocol,
        logical_product,
        context.target,
        context.optimize,
    );

    const metal_backend = graph.createMetalBackend(
        context.b,
        context.protocol,
        logical_product,
        context.target,
        context.optimize,
    );

    const integration = graph.create(context.b, .{
        .product = logical_product,
        .root_source_file = "src/integrations/riscv_metal/mod.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(integration);
    integration.addImport("stwo_metal_backend", metal_backend);
    integration.addImport("stwo_riscv_frontend", frontend);
    return .{
        .frontend = frontend,
        .metal_backend = metal_backend,
        .integration = integration,
    };
}

fn moduleProduct(role: graph.Role) graph.Product {
    return .{
        .name = product.name,
        .frontend = product.frontend,
        .backend = product.backend,
        .role = role,
        .protocol_features = product.protocol_features,
    };
}

fn testProduct() graph.Product {
    return moduleProduct(.@"test");
}

test "descriptor requires Metal and explicitly excludes CUDA" {
    try descriptor.validate();
    try std.testing.expectEqual(product_policy.State.parity_gated, descriptor.state);
    try std.testing.expectEqual(product_policy.TargetSupport.macos, descriptor.target_support);
    try std.testing.expectEqualStrings("stwo-zig-riscv-metal", descriptor.executable.?);
    try std.testing.expectEqualStrings("cuda", source_closure.forbidden_dynamic_dependencies[0]);
}

test "the installed CLI is the production shell and the bench keeps its own name" {
    try std.testing.expectEqualStrings(
        "src/products/riscv_metal/main.zig",
        source_closure.entry_roots[0],
    );
    try std.testing.expectEqualStrings("riscv-metal-bench", descriptor.benchmark_step.?);
    var bench_cli_declared = false;
    for (source_closure.entry_roots) |root| {
        if (std.mem.eql(u8, root, "src/riscv_metal_bench_cli.zig")) bench_cli_declared = true;
    }
    try std.testing.expect(bench_cli_declared);
}

test "the shared adapter and shell arrive under the CPU product's module names" {
    const expected = [_]product_policy.NamedImport{
        .{ .name = "riscv_adapter", .source = "src/integrations/riscv_cpu/proof_adapter.zig" },
        .{ .name = "riscv_cpu_capabilities", .source = "src/products/riscv_metal/capabilities.zig" },
        .{ .name = "riscv_shared_app", .source = "src/products/riscv_shared/app.zig" },
        .{ .name = "riscv_shared_cli", .source = "src/products/riscv_shared/cli.zig" },
        .{ .name = "riscv_shared_registry", .source = "src/products/riscv_shared/registry.zig" },
    };
    for (expected) |want| {
        var found = false;
        for (source_closure.named_imports) |named| {
            if (!std.mem.eql(u8, named.name, want.name)) continue;
            try std.testing.expectEqualStrings(want.source, named.source);
            found = true;
        }
        try std.testing.expect(found);
    }
}
