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
//!   | `interop_postcard`       | `src/interop/postcard.zig`                    |
//!   | `interop_riscv_artifact` | `src/interop/riscv_artifact.zig`              |
//!
//! The two `interop_*` names, and the absence of a third for
//! `src/interop/atomic_file.zig`, both follow from Zig 0.15's module rules;
//! `addInteropImports` below carries that explanation in full.

const std = @import("std");
const metal = @import("../backends/metal.zig");
const build_identity = @import("../build_identity.zig");
const closure_gate = @import("../gates/product_closure.zig");
const graph_identity = @import("../graph/identity.zig");
const graph_install = @import("../graph/install.zig");
const graph = @import("../graph/modules.zig");
const product_policy = @import("../graph/product.zig");
const shared_shell = @import("riscv_shared_shell.zig");

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
    .named_imports = &([_]product_policy.NamedImport{
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
        .{ .name = "output_transaction", .source = "src/interop/output_transaction.zig" },
        .{ .name = "interop_postcard", .source = "src/interop/postcard.zig" },
        .{ .name = "interop_riscv_artifact", .source = "src/interop/riscv_artifact.zig" },
    } ++ shared_shell.shell_named_imports),
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

    const benchmark_product = moduleProduct(.benchmark);
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
    addShellTests(context, test_step);

    const closure_check = closure_gate.addCheck(.{
        .b = context.b,
        .descriptor = descriptor,
        .binary = installed.executable,
    });
    test_step.dependOn(&closure_check.step);
}

/// The product shell's own tests. These are the isolation assertions that keep
/// this CLI from ever advertising the CPU lane — `cli.zig` requires that the
/// usage text names no other backend, `registry.zig` requires a single-key
/// `backend_availability` and no quoted `cpu` token, `app.zig` pins the engine
/// and backend tag, `capabilities.zig` pins the admission path — so they must
/// actually execute.
///
/// Each file gets its own test root because Zig collects `test` declarations
/// only from a test binary's root source file: a test rooted at `main.zig`
/// resolves the `app.zig` import inside `main`'s body, which is never analysed
/// in test mode, and reports "All 0 tests passed". Rooting per file also keeps
/// each binary's module graph to what that file actually imports, so only the
/// `app.zig` root pays for the facade and the Metal runtime.
fn addShellTests(context: Context, test_step: *std.Build.Step) void {
    const b = context.b;
    const identity_product = moduleProduct(.@"test");

    const app = rootModule(context, identity_product, "src/products/riscv_metal/app.zig");
    const app_tests = b.addTest(.{ .root_module = app });
    metal.linkRuntime(b, app_tests);
    test_step.dependOn(&b.addRunArtifact(app_tests).step);

    const cli = binding(context).leafModule("src/products/riscv_metal/cli.zig");
    cli.addImport("riscv_shared_cli", binding(context).leafModule(
        "src/products/riscv_shared/cli.zig",
    ));
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = cli })).step);

    const registry = binding(context).leafModule("src/products/riscv_metal/registry.zig");
    registry.addImport("riscv_capabilities", capabilitiesModule(context));
    registry.addImport("riscv_shared_registry", binding(context).leafModule(
        "src/products/riscv_shared/registry.zig",
    ));
    registry.addOptions("product_identity", graph_identity.productOptions(
        b,
        context.identity,
        identity_product,
        context.target,
        context.optimize,
    ));
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = registry })).step);

    test_step.dependOn(&b.addRunArtifact(b.addTest(.{
        .root_module = capabilitiesModule(context),
    })).step);
}

/// The production CLI's root module. Mirrors `riscv_cpu.zig`'s `addExecutable`
/// binding one-for-one so the shared shell (`src/products/riscv_shared/*.zig`)
/// and the engine-generic adapter see exactly the same injected module names in
/// both products.
fn productionRootModule(context: Context) *std.Build.Module {
    return rootModule(context, product, "src/products/riscv_metal/main.zig");
}

fn rootModule(
    context: Context,
    identity_product: graph.Product,
    root_source_file: []const u8,
) *std.Build.Module {
    const b = context.b;
    const stwo = createFacadeModule(context, moduleProduct(.library));
    const capabilities = capabilitiesModule(context);
    // The engine-generic adapter keeps the historical `riscv_cpu_capabilities`
    // import name, bound here to *this* product's capability file — the one
    // that reports `backend = "metal"`.
    const adapter = binding(context).adapterModule(.{
        .protocol = context.protocol,
        .identity = context.identity,
        .stwo = stwo,
        .capabilities = capabilities,
    });
    const root = graph.create(b, .{
        .product = identity_product,
        .root_source_file = root_source_file,
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    root.addImport("stwo", stwo);
    root.addImport("stwo_riscv_metal", stwo);
    root.addImport("riscv_adapter", adapter);
    root.addImport("riscv_capabilities", capabilities);
    root.addImport("riscv_cpu_capabilities", capabilities);
    binding(context).addShellImports(root);
    root.addImport("output_transaction", binding(context).leafModule(
        "src/interop/output_transaction.zig",
    ));
    root.addOptions("build_identity", graph_identity.buildOptions(b, context.identity));
    root.addOptions(
        "product_identity",
        graph_identity.productOptions(
            b,
            context.identity,
            identity_product,
            context.target,
            context.optimize,
        ),
    );
    return root;
}

/// This product's capability surface. It is one module reached under two names:
/// `riscv_capabilities` by this product's own shell files, and
/// `riscv_cpu_capabilities` by the shared adapter, which hard-codes that
/// historical name. Both must resolve to *this* file — the one that reports
/// `backend = "metal"`.
fn capabilitiesModule(context: Context) *std.Build.Module {
    return binding(context).leafModule("src/products/riscv_metal/capabilities.zig");
}

/// How this product creates its own leaf modules, its shared shell modules and
/// the engine-generic adapter: always against the CLI product identity and the
/// host target/optimize pair.
fn binding(context: Context) shared_shell.Binding {
    return .{
        .b = context.b,
        .product = product,
        .target = context.target,
        .optimize = context.optimize,
    };
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
/// files relatively because its module root is `src/`; this product's facade
/// root is two directories deeper, and Zig 0.15 rejects a relative `@import`
/// that escapes the module root, so they arrive as named modules.
///
/// Two modules, not three: `src/interop/riscv_artifact.zig` imports
/// `atomic_file.zig` relatively, so that file already belongs to the artifact
/// module, and a Zig file belongs to exactly one module ("file exists in
/// modules ... files must belong to only one module"). The facade takes
/// `atomic_file` as the artifact module's own re-export instead.
fn addInteropImports(
    context: Context,
    logical_product: graph.Product,
    facade: *std.Build.Module,
) void {
    const postcard = binding(context).leafModule("src/interop/postcard.zig");
    postcard.addImport("stwo_core", context.protocol.core);
    postcard.addImport("stwo_proof_wire", graph.createProofWire(
        context.b,
        context.protocol,
        logical_product,
        context.target,
        context.optimize,
    ));

    facade.addImport("interop_postcard", postcard);
    facade.addImport("interop_riscv_artifact", binding(context).leafModule(
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
    return shared_shell.roleProduct(product, role);
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
