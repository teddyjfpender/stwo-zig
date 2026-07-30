//! Internal entry point for one delegated product graph.

const std = @import("std");
const build_identity = @import("build_identity.zig");
const architecture_receipts = @import("gates/architecture_receipts.zig");
const baseline = @import("gates/baseline.zig");
const configure_plan = @import("gates/configure_plan.zig");
const construction_observer = @import("graph/construction_observer.zig");
const cuda_tools = @import("backends/cuda_tools.zig");
const native_gates = @import("gates/native.zig");
const release_evidence = @import("gates/release_evidence.zig");
const riscv_gates = @import("gates/riscv.zig");
const graph = @import("graph/modules.zig");
const integration_graph = @import("graph/integrations.zig");
const metal_core_aot = @import("backends/metal_aot.zig");
const metal_products = @import("benchmarks/metal.zig");
const native_benchmarks = @import("benchmarks/native.zig");
const products = @import("products/matrix.zig");

const Scope = configure_plan.Scope;

pub fn build(b: *std.Build) void {
    const repository_root = b.option(
        []const u8,
        "repository-root",
        "Absolute stwo-zig repository root",
    ) orelse @panic("missing internal -Drepository-root");
    setRepositoryRoot(b, repository_root);

    const scope_name = b.option(
        []const u8,
        "product-scope",
        "Internal focused product scope",
    ) orelse @panic("missing internal -Dproduct-scope");
    const scope = std.meta.stringToEnum(Scope, scope_name) orelse
        std.debug.panic("unknown internal product scope: {s}", .{scope_name});

    if (scope == .aggregate) {
        const aggregate_metal = b.option(
            bool,
            "aggregate-metal",
            "Explicitly link Metal into the aggregate compatibility product",
        ) orelse false;
        products.constructAggregate(b, aggregate_metal);
        configure_plan.add(b, scope, aggregate_metal);
        return;
    }

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const shared = SharedOptions.read(b);
    switch (scope) {
        .aggregate => unreachable,
        .architecture => {
            architecture_receipts.addGates(b);
            construction_observer.recordConstructor(b, "gates/architecture_receipts.addGates");
            baseline.addGate(b);
            construction_observer.recordConstructor(b, "gates/baseline.addGate");
        },
        .core, .prover, .native_cpu, .native_cuda, .native_metal, .riscv_cpu, .riscv_metal, .cairo_cpu, .cairo_metal, .cairo_cuda => constructProduct(
            b,
            target,
            optimize,
            repository_root,
            shared,
            scope,
        ),
        .package => {
            _ = @import("products/libraries.zig").addProducts(.{
                .b = b,
                .target = target,
                .optimize = optimize,
                .identity = resolveIdentity(b, repository_root, shared),
            });
            construction_observer.recordConstructor(b, "products/libraries.addProducts");
        },
        .riscv_cpu_compat => {
            constructProduct(b, target, optimize, repository_root, shared, .riscv_cpu);
            const focused = &b.top_level_steps.get("test-riscv-cpu-product").?.step;
            const exhaustive = &b.top_level_steps.get("test-riscv-release-exhaustive").?.step;
            b.step("test-riscv", "Run RISC-V runner tests (trace_dump)").dependOn(focused);
            b.step("test-riscv-prover", "Run RISC-V prover tests (prove+verify)").dependOn(exhaustive);
            construction_observer.recordConstructor(b, "compatibility aliases");
        },
        .compatibility_tools => {
            @import("products/compatibility_tools.zig").addProducts(.{
                .b = b,
                .target = target,
                .optimize = optimize,
            });
            construction_observer.recordConstructor(b, "products/compatibility_tools.addProducts");
        },
        .cuda_tools => cuda_tools.addProducts(b, target, optimize),
        .metal_tools => addMetalTools(b, target, optimize),
        .deferred => {
            products.addDeferredProducts(b, target);
            construction_observer.recordConstructor(b, "products/matrix.addDeferredProducts");
            const cuda_test = b.step(
                "cuda-test",
                "Unavailable compatibility alias; CUDA now requires an explicit product toolchain",
            );
            cuda_test.dependOn(&b.addFail(
                "cuda-test is unavailable: select an explicit CUDA product with complete library and runtime paths",
            ).step);
        },
        .verification => {
            const release_options = ReleaseOptions.read(b);
            riscv_gates.addGates(.{
                .b = b,
                .release_phase = release_options.phase,
                .evidence_dir = release_options.evidence_dir,
            });
            construction_observer.recordConstructor(b, "gates/riscv.addGates");
            const native = native_gates.addGates(b, b.fmt("-O{s}", .{@tagName(optimize)}));
            construction_observer.recordConstructor(b, "gates/native.addGates");
            native_benchmarks.addProducts(.{ .b = b });
            construction_observer.recordConstructor(b, "benchmarks/native.addProducts");
            release_evidence.addGates(b, native.prove_checkpoints);
            construction_observer.recordConstructor(b, "gates/release_evidence.addGates");
        },
        .policy => {
            addPolicyGates(b);
            construction_observer.recordConstructor(b, "internal_build.addPolicyGates");
        },
        .release => {
            @import("gates/release.zig").addGates(b, optimize);
            construction_observer.recordConstructor(b, "gates/release.addGates");
        },
    }
    configure_plan.add(b, scope, false);
}

fn setRepositoryRoot(b: *std.Build, repository_root: []const u8) void {
    b.build_root = .{
        .path = repository_root,
        .handle = std.fs.openDirAbsolute(repository_root, .{}) catch
            @panic("invalid internal repository root"),
    };
}

const SharedOptions = struct {
    implementation_commit: ?[]const u8,
    implementation_dirty: ?bool,
    implementation_tree: ?[]const u8,
    dirty_content_sha256: ?[]const u8,

    fn read(b: *std.Build) SharedOptions {
        return .{
            .implementation_commit = b.option([]const u8, "implementation-commit", "Exact lowercase 40-hex source commit embedded in the product"),
            .implementation_dirty = b.option(bool, "implementation-dirty", "Whether the source embedded in the product has local modifications"),
            .implementation_tree = b.option([]const u8, "implementation-tree", "Exact lowercase 40-hex source tree for an identity override"),
            .dirty_content_sha256 = b.option([]const u8, "implementation-dirty-content-sha256", "Canonical dirty-content digest required for a diagnostic dirty override"),
        };
    }
};

const ReleaseOptions = struct {
    phase: []const u8,
    evidence_dir: []const u8,

    fn read(b: *std.Build) ReleaseOptions {
        return .{
            .phase = b.option([]const u8, "riscv-release-phase", "CP-13 phase: candidate or promoted") orelse "candidate",
            .evidence_dir = b.option([]const u8, "riscv-evidence-dir", "Fresh CP-13 evidence directory") orelse "zig-out/release-evidence/riscv",
        };
    }
};

fn resolveIdentity(
    b: *std.Build,
    repository_root: []const u8,
    shared: SharedOptions,
) build_identity.Identity {
    if ((shared.implementation_commit == null) != (shared.implementation_dirty == null))
        @panic("incomplete internal implementation identity override");
    if (shared.implementation_commit == null and
        (shared.implementation_tree != null or shared.dirty_content_sha256 != null))
        @panic("orphan internal implementation identity override");
    return build_identity.resolveWithOverride(
        b.allocator,
        repository_root,
        if (shared.implementation_commit) |commit| .{
            .commit = commit,
            .tree = shared.implementation_tree,
            .dirty = shared.implementation_dirty.?,
            .dirty_content_sha256 = shared.dirty_content_sha256,
        } else null,
    ) catch |err| std.debug.panic("cannot resolve product build identity: {s}", .{@errorName(err)});
}

fn constructProduct(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    repository_root: []const u8,
    shared: SharedOptions,
    scope: Scope,
) void {
    const constructed = products.construct(.{
        .b = b,
        .target = target,
        .optimize = optimize,
        .identity = resolveIdentity(b, repository_root, shared),
    }, scope);
    if (!constructed) std.debug.panic(
        "product scope absent from central catalog: {s}",
        .{@tagName(scope)},
    );
}

fn addMetalTools(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const protocol = graph.createPrivateProtocolModules(b, target, optimize);
    const tool_product = graph.Product{
        .name = "stwo-native-metal-tools",
        .frontend = .native,
        .backend = .metal,
        .role = .library,
    };
    const stwo = graph.create(b, .{
        .product = tool_product,
        .root_source_file = "src/stwo.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(stwo);
    const proof_wire = graph.addProofWireImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    const metal_session = graph.addMetalSessionImport(
        b,
        tool_product,
        target,
        optimize,
        stwo,
    );
    const cpu_backend = graph.addCpuBackendImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    const native_examples = graph.addNativeExamplesImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        cpu_backend,
        proof_wire,
        stwo,
    );
    const metal_backend = graph.addMetalBackendImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    const cuda_backend = graph.addCudaBackendImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    const native_cuda = integration_graph.addNativeCudaImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        cuda_backend,
        native_examples,
        proof_wire,
        stwo,
    );
    const riscv_frontend = graph.addRiscVFrontendImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    _ = integration_graph.addRiscVCpuImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        cpu_backend,
        riscv_frontend,
        stwo,
    );
    const cairo_frontend = graph.addCairoFrontendImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        stwo,
    );
    _ = integration_graph.addCairoCudaImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        cuda_backend,
        cairo_frontend,
        native_cuda,
        stwo,
    );
    _ = integration_graph.addCairoCpuImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        cpu_backend,
        cairo_frontend,
        stwo,
    );
    const cairo_metal_integration = integration_graph.addCairoMetalImport(
        b,
        protocol,
        tool_product,
        target,
        optimize,
        metal_backend,
        cairo_frontend,
        metal_session,
        stwo,
    );
    const shader_manifest = graph.create(b, .{
        .product = tool_product,
        .root_source_file = "src/backends/metal/shader_manifest.zig",
        .target = target,
        .optimize = optimize,
    });
    protocol.addImports(shader_manifest);
    metal_core_aot.addProducts(.{
        .b = b,
        .target = target,
        .optimize = optimize,
        .shader_manifest_module = shader_manifest,
    });
    construction_observer.recordConstructor(b, "backends/metal_aot.addProducts");
    metal_products.addProducts(.{
        .b = b,
        .target = target,
        .optimize = optimize,
        .stwo_module = stwo,
        .cpu_backend = cpu_backend,
        .metal_backend = metal_backend,
        .cairo_frontend = cairo_frontend,
        .metal_session = metal_session,
        .cairo_metal_integration = cairo_metal_integration,
        .protocol = protocol,
        .test_step = null,
    });
    construction_observer.recordConstructor(b, "benchmarks/metal.addProducts");
}

fn addPolicyGates(b: *std.Build) void {
    inline for (.{
        .{ "fmt", "Check formatting (zig fmt --check)", &.{ "zig", "fmt", "--check", "build.zig", "build_support", "src", "tools" } },
        .{ "api-parity", "Validate API parity ledger coverage", &.{ "python3", "scripts/check_api_parity.py" } },
        .{ "upstream-pins", "Validate Native and Cairo pin carriers against the upstream ledger", &.{ "python3", "scripts/check_upstream_pins.py" } },
        .{ "source-conformance", "Reject new source layout, dependency direction, and file-size violations", &.{ "python3", "scripts/check_source_conformance.py" } },
        .{ "package-workspace", "Audit package ownership, API, and dependency boundaries", &.{ "python3", "scripts/check_package_workspace.py" } },
        .{ "registry-parity", "Compare focused and aggregate compiled capability registries", &.{ "python3", "scripts/check_registry_parity.py" } },
        .{ "upstream-surface", "Validate API parity rust_path entries against pinned upstream commit", &.{ "python3", "scripts/check_upstream_surface.py" } },
    }) |gate| {
        const command = b.addSystemCommand(gate[2]);
        b.step(gate[0], gate[1]).dependOn(&command.step);
    }
    const closure = b.addSystemCommand(&.{
        "python3",
        "scripts/check_build_configure_closure.py",
    });
    b.step(
        "build-configure-closure",
        "Verify focused configure closure and the default install manifest",
    ).dependOn(&closure.step);
}
