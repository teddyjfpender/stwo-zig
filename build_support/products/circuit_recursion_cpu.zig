//! Build ownership for the circuit recursion CPU product: the leaf wrap, the
//! recursive tree and registry generation of the circuit recursion stage
//! (design §7.4).

const std = @import("std");
const build_identity = @import("../build_identity.zig");
const closure_gate = @import("../gates/product_closure.zig");
const graph_install = @import("../graph/install.zig");
const graph = @import("../graph/modules.zig");
const integration_graph = @import("../graph/integrations.zig");
const product_policy = @import("../graph/product.zig");

const protocol_features = "circuit-recursion-proving-5a7c5ed-v1";

/// The circuit AIR data embedded in the binary, authenticated at run time.
const embedded_assets = [_]struct { name: []const u8, path: []const u8 }{
    .{ .name = "circuit_air_projection", .path = "vectors/circuit/official/compiled_air_constraints_v1.bin" },
    .{ .name = "circuit_air_programs", .path = "vectors/circuit/official/circuit_air.air_programs_v1.bin" },
};

const source_closure = product_policy.SourceClosure{
    .entry_roots = &.{"src/products/circuit_recursion_cpu/main.zig"},
    .named_imports = &.{
        .{ .name = "stwo_backend_contracts", .source = "src/backend/mod.zig" },
        .{ .name = "stwo_core", .source = "src/core/mod.zig" },
        .{ .name = "stwo_cairo_frontend", .source = "src/frontends/cairo/mod.zig" },
        .{ .name = "stwo_cairo_cpu_integration", .source = "src/integrations/cairo_cpu/mod.zig" },
        .{ .name = "stwo_circuit_frontend", .source = "src/frontends/circuit/mod.zig" },
        .{ .name = "stwo_circuit_cpu_integration", .source = "src/integrations/circuit_cpu/mod.zig" },
        .{ .name = "stwo_circuit_recursion_wire", .source = "src/interop/circuit_recursion/mod.zig" },
        .{ .name = "interop_felt_json", .source = "src/interop/felt_json.zig" },
        .{ .name = "interop_cairo_prover_parameters", .source = "src/interop/cairo_prover_parameters.zig" },
        .{ .name = "stwo_cpu_backend", .source = "src/backends/cpu_scalar/mod.zig" },
        .{ .name = "stwo_prover_api", .source = "src/prover_api/mod.zig" },
        .{ .name = "stwo_prover_engine", .source = "src/prover/mod.zig" },
    },
    .generated_imports = &.{ "circuit_air_projection", "circuit_air_programs" },
    .allowed_files = &.{
        "src/interop/felt_json.zig",
        "src/interop/cairo_prover_parameters.zig",
    },
    .allowed_prefixes = &.{
        "src/backend",
        "src/backends/cpu_scalar",
        "src/core",
        "src/frontends/cairo",
        "src/frontends/circuit",
        "src/integrations/cairo_cpu",
        "src/integrations/circuit_cpu",
        "src/interop/circuit_recursion",
        "src/products/circuit_recursion_cpu",
        "src/prover",
        "src/prover_api",
    },
    .forbidden_dynamic_dependencies = &.{
        "Metal.framework",
        "Foundation.framework",
        "libobjc",
        "cuda",
    },
};

pub const descriptor = product_policy.Descriptor{
    .product = product(.cli),
    // Byte parity with the pinned upstream binaries is its release gate: the
    // local parity lane (every rung that fits the 8 GB development budget).
    // The large lane (R8, R8b, R9) is `circuit-parity-large`.
    .state = .parity_gated,
    .target_support = .any,
    .build_step = "stwo-circuit-recursion-cpu",
    .test_step = "test-circuit-recursion-cpu-product",
    .executable = "stwo-circuit-recursion-cpu",
    .installed_artifacts = &.{"stwo-circuit-recursion-cpu"},
    .release_gates = &.{ "test-circuit-recursion-cpu-product", "circuit-parity-local" },
    .dependencies = .{ .module_roots = source_closure.entry_roots },
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
        "invalid circuit recursion CPU descriptor: {s}",
        .{@errorName(err)},
    );
    const root = createProductModule(context, descriptor.product);
    const installed = graph_install.executable(
        context.b,
        descriptor.executable.?,
        root,
        descriptor.build_step,
        "Build the circuit recursion CPU CLI (leaf wrap, recursive tree, registry generation)",
    );

    const tests = context.b.addTest(.{ .root_module = createProductModule(context, product(.@"test")) });
    const test_step = context.b.step(
        descriptor.test_step.?,
        "Test the circuit recursion CPU product's commands and embedded assets",
    );
    test_step.dependOn(&context.b.addRunArtifact(tests).step);
    const help = context.b.addRunArtifact(installed.executable);
    help.addArg("--help");
    test_step.dependOn(&help.step);
    const closure_check = closure_gate.addCheck(.{
        .b = context.b,
        .descriptor = descriptor,
        .binary = installed.executable,
    });
    test_step.dependOn(&closure_check.step);

    // R8 and R8b: large (a 2^23-row circuit proof, about 11 GB, and for R8b
    // a four-leaf tree after it); not part of the product test step. The
    // tests read `vectors/` from the repository root.
    const app = createProductModuleAt(context, product(.@"test"), "src/products/circuit_recursion_cpu/app.zig");
    context.b.step(
        "circuit-parity-r8",
        "Rung R8: leaf-wrap of the leaf prover's test program equals leaf-prover's expected_output.json",
    ).dependOn(addAppTest(context, app, "src/products/circuit_recursion_cpu/tests/r8_leaf_wrap_test.zig"));
    context.b.step(
        "circuit-parity-r8b",
        "Rung R8b: the Zig leaf of the leaf simple bootloader equals four_leaves/leaf.json, and four of them fold to the root goldens",
    ).dependOn(addAppTest(context, app, "src/products/circuit_recursion_cpu/tests/r8b_leaf_chain_test.zig"));
    addParityLanes(context.b);
}

/// One rung of the parity ladder (design §8.2): a step of the root build or
/// of a package build, and the mode it runs in.
const Rung = struct {
    build_file: ?[]const u8 = null,
    step: []const u8,
    optimize: []const u8 = "-Doptimize=ReleaseSafe",
};

const frontend_build = "src/frontends/circuit/build.zig";
const integration_build = "src/integrations/circuit_cpu/build.zig";

/// Rungs that run within the 8 GB development budget.
const local_rungs = [_]Rung{
    // R0: the wire formats' vectors (felt252, base64, leaf JSON, serializers).
    .{ .build_file = "src/interop/circuit_recursion/build.zig", .step = "test" },
    // R0 (FRI), R1, R2, R3 and R5: the frontend's unit and fixture tests.
    .{ .build_file = frontend_build, .step = "circuit-parity-r1" },
    .{ .build_file = frontend_build, .step = "circuit-parity-r4" },
    .{ .build_file = frontend_build, .step = "circuit-parity-r6-fold" },
    .{ .build_file = integration_build, .step = "circuit-parity-r4-values" },
    .{ .build_file = integration_build, .step = "circuit-parity-r6-leaf" },
    .{ .build_file = integration_build, .step = "circuit-parity-r7" },
    .{ .build_file = integration_build, .step = "circuit-parity-registry", .optimize = "-Doptimize=ReleaseFast" },
    // R10b/R10c: the Zig Cairo leaf lane.
    .{ .step = "test-cairo-leaf-proof", .optimize = "-Doptimize=ReleaseFast" },
    .{ .build_file = integration_build, .step = "circuit-parity-r11" },
};

/// Rungs above the development budget (11-18 GB peaks): design §8.3's
/// large lane. `circuit-parity-r7-multiverifier` is skipped without its
/// external inputs file.
const large_rungs = [_]Rung{
    .{ .step = "circuit-parity-r8", .optimize = "-Doptimize=ReleaseFast" },
    .{ .step = "circuit-parity-r8b", .optimize = "-Doptimize=ReleaseFast" },
    .{ .build_file = integration_build, .step = "circuit-parity-r9", .optimize = "-Doptimize=ReleaseFast" },
    .{ .build_file = integration_build, .step = "circuit-parity-r7-multiverifier", .optimize = "-Doptimize=ReleaseFast" },
};

/// `circuit-parity-local`, `circuit-parity-large` and `circuit-parity`
/// (both). Every rung is its own `zig build` run from the repository root,
/// one after another, so that no two large circuits are resident at once.
fn addParityLanes(b: *std.Build) void {
    const local = addLane(b, &local_rungs, null);
    const large = addLane(b, &large_rungs, local);
    b.step(
        "circuit-parity-local",
        "Parity ladder, local lane: R0-R7, registry generation, R10b/R10c and R11, one rung at a time",
    ).dependOn(local);
    const large_step = b.step(
        "circuit-parity-large",
        "Parity ladder, large lane (11-18 GB): R8, R8b, R9 and, with its inputs, the R7 multiverifier",
    );
    large_step.dependOn(addLane(b, &large_rungs, null));
    b.step("circuit-parity", "The whole parity ladder: the local lane, then the large lane").dependOn(large);
}

/// Chains `rungs` after `first`; returns the last rung's step.
fn addLane(b: *std.Build, rungs: []const Rung, first: ?*std.Build.Step) *std.Build.Step {
    var previous = first;
    for (rungs) |rung| {
        const command = b.addSystemCommand(&.{ "zig", "build", rung.step });
        if (rung.build_file) |file| command.addArgs(&.{ "--build-file", file });
        command.addArgs(&.{ rung.optimize, "-j2" });
        command.setCwd(b.path("."));
        command.setName(rung.step);
        if (previous) |step| command.step.dependOn(step);
        previous = &command.step;
    }
    return previous.?;
}

/// A test root that sees the product's `app` module, run from the
/// repository root.
fn addAppTest(context: Context, app: *std.Build.Module, root_source_file: []const u8) *std.Build.Step {
    const root = graph.create(context.b, .{
        .product = product(.@"test"),
        .root_source_file = root_source_file,
        .target = context.target,
        .optimize = context.optimize,
    });
    root.addImport("app", app);
    // The R8/R8b rungs prove with the CPU scalar oracle here; `circuit_metal`
    // builds the same tests with its device provers.
    const cpu_provers = context.b.createModule(.{
        .root_source_file = context.b.path("src/integrations/circuit_cpu/tests/cpu_provers.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    cpu_provers.addImport("stwo_circuit_cpu_integration", app.import_table.get("stwo_circuit_cpu_integration") orelse
        @panic("circuit recursion app is missing stwo_circuit_cpu_integration"));
    root.addImport("circuit_provers_under_test", cpu_provers);
    const run = context.b.addRunArtifact(context.b.addTest(.{ .root_module = root }));
    run.setCwd(context.b.path("."));
    return &run.step;
}

fn createProductModule(context: Context, product_descriptor: graph.Product) *std.Build.Module {
    return createProductModuleAt(context, product_descriptor, "src/products/circuit_recursion_cpu/main.zig");
}

fn createProductModuleAt(context: Context, product_descriptor: graph.Product, root_source_file: []const u8) *std.Build.Module {
    const b = context.b;
    const root = graph.create(b, .{
        .product = product_descriptor,
        .root_source_file = root_source_file,
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    const cpu_backend = graph.addCpuBackendImport(b, context.protocol, product_descriptor, context.target, context.optimize, root);
    const cairo_frontend = graph.addCairoFrontendImport(b, context.protocol, product_descriptor, context.target, context.optimize, root);
    _ = integration_graph.addCairoCpuImport(b, context.protocol, product_descriptor, context.target, context.optimize, cpu_backend, cairo_frontend, root);
    const wire = graph.createCircuitRecursionWire(b, context.protocol, product_descriptor, context.target, context.optimize, cairo_frontend);
    root.addImport("stwo_circuit_recursion_wire", wire);

    const circuit_frontend = graph.create(b, .{
        .product = product_descriptor,
        .root_source_file = "src/frontends/circuit/mod.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    circuit_frontend.addImport("stwo_core", context.protocol.core);
    circuit_frontend.addImport("stwo_prover_engine", context.protocol.prover);
    root.addImport("stwo_circuit_frontend", circuit_frontend);

    const integration = graph.create(b, .{
        .product = product_descriptor,
        .root_source_file = "src/integrations/circuit_cpu/mod.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    integration.addImport("stwo_core", context.protocol.core);
    integration.addImport("stwo_prover_api", context.protocol.prover_api);
    integration.addImport("stwo_prover_engine", context.protocol.prover);
    integration.addImport("stwo_cpu_backend", cpu_backend);
    integration.addImport("stwo_circuit_frontend", circuit_frontend);
    integration.addImport("stwo_cairo_frontend", cairo_frontend);
    integration.addImport("stwo_circuit_recursion_wire", wire);
    root.addImport("stwo_circuit_cpu_integration", integration);

    for (embedded_assets) |asset| root.addAnonymousImport(asset.name, .{ .root_source_file = b.path(asset.path) });
    return root;
}

fn product(role: graph.Role) graph.Product {
    return .{
        .name = "stwo-circuit-recursion-cpu",
        .frontend = .circuit,
        .backend = .cpu,
        .role = role,
        .protocol_features = protocol_features,
    };
}
