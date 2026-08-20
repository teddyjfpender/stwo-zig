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
const metal_aot = @import("../backends/metal_aot.zig");
const closure_gate = @import("../gates/product_closure.zig");
const graph_install = @import("../graph/install.zig");
const graph = @import("../graph/modules.zig");
const product_policy = @import("../graph/product.zig");
const riscv_metal_modules = @import("riscv_metal_modules.zig");
const riscv_metal_tests = @import("riscv_metal_tests.zig");
const shared_shell = @import("riscv_shared_shell.zig");

const product = graph.Product{
    .name = "stwo-riscv-metal",
    .frontend = .riscv,
    .backend = .metal,
    .role = .cli,
    .protocol_features = "rv32im-zkvm-v1+lifted-pcs-v1" ++
        "+metal-runtime-v2+authenticated-core-aot-v2" ++
        "+rv32im-zkvm-poseidon2-v1",
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
    .generated_imports = &.{
        "build_identity",
        "metal_aot_config",
        "product_identity",
        // Injected by the frontend package build for compatibility tests. The
        // production Metal module graph never constructs or consumes it.
        "typed_air_artifacts",
        "typed_air_h009_artifacts",
        "typed_air_h010_artifacts",
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

pub const Context = riscv_metal_modules.Context;

pub const descriptor = product_policy.Descriptor{
    .product = product,
    .state = .parity_gated,
    .target_support = .macos,
    .unsupported_target_reason = "the Metal backend requires a macOS target and Apple Metal SDK",
    .build_step = "stwo-riscv-metal",
    .test_step = "test-riscv-metal",
    .executable = "stwo-zig-riscv-metal",
    .installed_artifacts = &.{
        "stwo-zig-riscv-metal",
        "share/stwo-zig/metal/core/stwo_zig_core.air",
        "share/stwo-zig/metal/core/stwo_zig_core.manifest.json",
        "share/stwo-zig/metal/core/stwo_zig_core.manifest.sha256",
        "share/stwo-zig/metal/core/stwo_zig_core.metal",
        "share/stwo-zig/metal/core/stwo_zig_core.metallib",
    },
    .compatibility_aliases = &.{"riscv-metal-bench"},
    .release_gates = &.{
        "test-riscv-metal",
        "test-riscv-metal-guest-poseidon2-aot",
        "metal-test",
        "riscv-release-gate",
    },
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
        registerUnavailableCspBenchmark(
            context.b,
            descriptor.unsupported_target_reason.?,
        );
        registerUnavailableGuestPoseidon2(
            context.b,
            descriptor.unsupported_target_reason.?,
        );
        return;
    }
    const configured_bundle = context.b.option(
        []const u8,
        "metal-core-aot-bundle",
        "Authenticated core Metal AOT bundle consumed by stwo-riscv-metal",
    ) orelse {
        registerMissingAotBundle(context.b);
        return;
    };
    const aot_bundle = metal_aot.loadExternalBundle(
        context.b,
        configured_bundle,
    );

    const installed = graph_install.executable(
        context.b,
        descriptor.executable.?,
        riscv_metal_modules.productionRootModule(context, product, aot_bundle),
        descriptor.build_step,
        "Build the focused RV32IM Metal proof CLI",
    );
    metal.linkRuntime(context.b, installed.executable);
    aot_bundle.install(context.b, installed.build_step);
    riscv_metal_tests.addGuestPoseidon2AotLane(
        context,
        product,
        aot_bundle,
        installed.executable,
    );

    const csp_benchmark = context.b.addSystemCommand(&.{
        "python3",
        "scripts/riscv_csp_benchmark.py",
        "--backend",
        "metal",
    });
    csp_benchmark.step.dependOn(installed.build_step);
    context.b.step(
        "riscv-csp-bench-metal",
        "Run the pinned EthProofs CSP benchmark matrix on Metal",
    ).dependOn(&csp_benchmark.step);

    const benchmark_product = riscv_metal_modules.roleProduct(product, .benchmark);
    const benchmark = graph_install.executable(
        context.b,
        "riscv-metal-bench",
        riscv_metal_modules.createModule(
            context,
            product,
            benchmark_product,
            "src/riscv_metal_bench_cli.zig",
        ),
        descriptor.benchmark_step.?,
        "Build the compatible RV32IM Metal benchmark",
    );
    metal.linkRuntime(context.b, benchmark.executable);

    const stwo_tests = riscv_metal_modules.createFacadeModule(
        context,
        product,
        riscv_metal_modules.roleProduct(product, .@"test"),
    );
    const integration_tests = context.b.addTest(.{ .root_module = stwo_tests });
    metal.linkRuntime(context.b, integration_tests);
    const proof_test_module = riscv_metal_modules.createModule(
        context,
        product,
        riscv_metal_modules.roleProduct(product, .@"test"),
        "src/tests/riscv/metal_backend_test.zig",
    );
    proof_test_module.addOptions(
        "metal_aot_config",
        aot_bundle.addOptions(context.b),
    );
    const stwo = riscv_metal_modules.createFacadeModule(
        context,
        product,
        riscv_metal_modules.roleProduct(product, .library),
    );
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
    const run_proof_tests = context.b.addRunArtifact(proof_tests);
    run_proof_tests.setEnvironmentVariable(
        "STWO_RISCV_METAL_AOT_BUNDLE",
        aot_bundle.absolute_path,
    );
    test_step.dependOn(&run_proof_tests.step);
    riscv_metal_tests.addShellTests(context, product, aot_bundle, test_step);

    const closure_check = closure_gate.addCheck(.{
        .b = context.b,
        .descriptor = descriptor,
        .binary = installed.executable,
    });
    test_step.dependOn(&closure_check.step);
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
    b.step(descriptor.benchmark_step.?, reason).dependOn(&failure.step);
    b.step("riscv-csp-bench-metal", reason).dependOn(&failure.step);
    b.step("test-riscv-metal-guest-poseidon2-aot", reason).dependOn(&failure.step);
}

fn registerUnavailableCspBenchmark(b: *std.Build, reason: []const u8) void {
    const failure = b.addFail(b.fmt(
        "RISC-V Metal CSP benchmark is unavailable: {s}",
        .{reason},
    ));
    b.step("riscv-csp-bench-metal", reason).dependOn(&failure.step);
}

fn registerUnavailableGuestPoseidon2(b: *std.Build, reason: []const u8) void {
    const failure = b.addFail(b.fmt(
        "RISC-V Metal guest Poseidon2 acceptance is unavailable: {s}",
        .{reason},
    ));
    b.step(
        "test-riscv-metal-guest-poseidon2-aot",
        reason,
    ).dependOn(&failure.step);
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
