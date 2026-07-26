//! Build ownership for the official Cairo + CPU/SIMD product.

const std = @import("std");
const build_identity = @import("../build_identity.zig");
const closure_gate = @import("../gates/product_closure.zig");
const graph_identity = @import("../graph/identity.zig");
const graph_install = @import("../graph/install.zig");
const graph = @import("../graph/modules.zig");
const policy = @import("../graph/product.zig");

const protocol_features =
    "stwo-cairo-v1.2.2+official-json-v1+lifted-pcs-v2+blake2s";

const source_closure = policy.SourceClosure{
    .entry_roots = &.{
        "src/products/cairo_cpu/main.zig",
        "src/stwo_cairo_cpu.zig",
    },
    .named_imports = &.{
        .{ .name = "stwo_cairo_cpu", .source = "src/stwo_cairo_cpu.zig" },
        .{ .name = "stwo_backend_contracts", .source = "src/backend/mod.zig" },
        .{ .name = "stwo_core", .source = "src/core/mod.zig" },
        .{ .name = "stwo_prover_impl", .source = "src/prover/mod.zig" },
    },
    .generated_imports = &.{"product_identity"},
    .allowed_files = &.{
        "src/stwo_cairo_cpu.zig",
        "src/interop/atomic_file.zig",
        "src/interop/output_transaction.zig",
        "src/interop/stwo_json.zig",
    },
    .allowed_prefixes = &.{
        "src/backend",
        "src/backends/cpu_scalar",
        "src/core",
        "src/frontends/cairo",
        "src/integrations/cairo_cpu",
        "src/products/cairo_cpu",
        "src/prover",
    },
    .forbidden_dynamic_dependencies = &.{
        "Metal.framework",
        "Foundation.framework",
        "libobjc",
        "cuda",
    },
};

pub const descriptor = policy.Descriptor{
    .product = product(.cli),
    .state = .staged,
    .target_support = .any,
    .build_step = "stwo-cairo-cpu",
    .test_step = "test-cairo-cpu-product",
    .executable = "stwo-cairo-cpu",
    .installed_artifacts = &.{
        "stwo-cairo-cpu",
        "share/stwo-zig/cairo/official/all_opcodes.params.json",
    },
    .release_gates = &.{
        "test-cairo-cpu-product",
        "test-cairo-cpu-oracle",
    },
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
        "invalid Cairo CPU descriptor: {s}",
        .{@errorName(err)},
    );
    const stwo = createStwoModule(context, .library);
    const root = createProductModule(context, descriptor.product, stwo);
    const installed = graph_install.executable(
        context.b,
        descriptor.executable.?,
        root,
        descriptor.build_step,
        "Build the focused official Cairo CPU/SIMD proof CLI",
    );
    installProfile(context, installed.build_step);

    const test_root = createProductModule(
        context,
        product(.@"test"),
        createStwoModule(context, .@"test"),
    );
    const tests = context.b.addTest(.{ .root_module = test_root });
    const test_step = context.b.step(
        descriptor.test_step.?,
        "Test the Cairo CPU product, profile, and command contract",
    );
    test_step.dependOn(&context.b.addRunArtifact(tests).step);

    const help = context.b.addRunArtifact(installed.executable);
    help.addArg("--help");
    test_step.dependOn(&help.step);
    const capabilities = context.b.addRunArtifact(installed.executable);
    capabilities.addArg("capabilities");
    test_step.dependOn(&capabilities.step);
    const identity = context.b.addRunArtifact(installed.executable);
    identity.addArg("identity");
    test_step.dependOn(&identity.step);

    const closure = closure_gate.addCheck(.{
        .b = context.b,
        .descriptor = descriptor,
        .binary = installed.executable,
    });
    test_step.dependOn(&closure.step);
    addOracleGate(context, installed.executable);
}

fn createStwoModule(
    context: Context,
    role: graph.Role,
) *std.Build.Module {
    const module = graph.create(context.b, .{
        .product = product(role),
        .root_source_file = "src/stwo_cairo_cpu.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(module);
    return module;
}

fn createProductModule(
    context: Context,
    product_descriptor: graph.Product,
    stwo: *std.Build.Module,
) *std.Build.Module {
    const root = graph.create(context.b, .{
        .product = product_descriptor,
        .root_source_file = "src/products/cairo_cpu/main.zig",
        .target = context.target,
        .optimize = context.optimize,
    });
    context.protocol.addImports(root);
    root.addImport("stwo_cairo_cpu", stwo);
    root.addOptions(
        "product_identity",
        graph_identity.productOptions(
            context.b,
            context.identity,
            product_descriptor,
            context.target,
            context.optimize,
        ),
    );
    return root;
}

fn installProfile(context: Context, step: *std.Build.Step) void {
    const Asset = struct {
        source: []const u8,
        destination: []const u8,
    };
    for ([_]Asset{
        .{
            .source = "vectors/cairo/official/all_opcodes.params.json",
            .destination = "share/stwo-zig/cairo/official/all_opcodes.params.json",
        },
        .{
            .source = "vectors/cairo/official/witness_programs_v1.bin",
            .destination = "share/stwo-zig/cairo/official/witness_programs_v1.bin",
        },
        .{
            .source = "vectors/cairo/official/witness_feed_topology_v1.json",
            .destination = "share/stwo-zig/cairo/official/witness_feed_topology_v1.json",
        },
        .{
            .source = "vectors/cairo/official/all_opcodes.air_programs_v1.bin",
            .destination = "share/stwo-zig/cairo/official/all_opcodes.air_programs_v1.bin",
        },
        .{
            .source = "vectors/cairo/official/all_opcodes.base_trace_checkpoint.json",
            .destination = "share/stwo-zig/cairo/official/all_opcodes.base_trace_checkpoint.json",
        },
        .{
            .source = "vectors/cairo/cairo_fixed_tables.bin",
            .destination = "share/stwo-zig/cairo/cairo_fixed_tables.bin",
        },
        .{
            .source = "vectors/cairo/cairo_relation_templates.bin",
            .destination = "share/stwo-zig/cairo/cairo_relation_templates.bin",
        },
    }) |asset| {
        const install = context.b.addInstallFile(
            context.b.path(asset.source),
            asset.destination,
        );
        step.dependOn(&install.step);
    }
}

fn addOracleGate(
    context: Context,
    executable: *std.Build.Step.Compile,
) void {
    const prove = context.b.addRunArtifact(executable);
    prove.addArgs(&.{ "prove", "--prover-input" });
    prove.addFileArg(context.b.path(
        "vectors/cairo/official/all_opcodes.prover_input.json",
    ));
    prove.addArg("--params");
    prove.addFileArg(context.b.path(
        "vectors/cairo/official/all_opcodes.params.json",
    ));
    prove.addArg("--proof");
    const proof = prove.addOutputFileArg("official-cairo-proof.json");
    prove.addArg("--report-out");
    _ = prove.addOutputFileArg("official-cairo-report.json");
    prove.addArg("--verify");

    const cargo = context.b.addSystemCommand(&.{
        "cargo",
        "build",
        "--locked",
        "--manifest-path",
        context.b.pathFromRoot(
            "tools/stwo-cairo-official-verifier-rs/Cargo.toml",
        ),
    });
    const verify = context.b.addSystemCommand(&.{
        context.b.pathFromRoot(
            "tools/stwo-cairo-official-verifier-rs/target/debug/" ++
                "stwo-cairo-official-verifier",
        ),
        "verify",
        "--proof",
    });
    verify.step.dependOn(&cargo.step);
    verify.addFileArg(proof);
    verify.addArgs(&.{
        "--channel",
        "blake2s",
        "--proof-format",
        "json",
        "--result",
    });
    _ = verify.addOutputFileArg("official-rust-verdict.json");
    context.b.step(
        "test-cairo-cpu-oracle",
        "Prove through the CPU CLI and require official Rust acceptance",
    ).dependOn(&verify.step);
}

fn product(role: graph.Role) graph.Product {
    return .{
        .name = "stwo-cairo-cpu",
        .frontend = .cairo,
        .backend = .cpu,
        .role = role,
        .protocol_features = protocol_features,
    };
}

test "Cairo CPU is a focused staged product" {
    try descriptor.validate();
    try std.testing.expect(descriptor.isConstructible());
    try std.testing.expectEqual(policy.State.staged, descriptor.state);
}
