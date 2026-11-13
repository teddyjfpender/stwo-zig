//! Canonical circuit providers shared by product graph owners.
const std = @import("std");
const graph = @import("modules.zig");

/// Provider-only composition reused by native RISC-V recursion. The caller
/// supplies its actual backend/Cairo owners and proof wire; no product identity
/// or embedded recursion assets are manufactured for this operation.
pub const ProviderContext = struct {
    b: *std.Build,
    protocol: graph.ProtocolModules,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
};
pub fn addCircuitProviders(context: ProviderContext, product_descriptor: graph.Product, root: *std.Build.Module, cpu_backend: *std.Build.Module, cairo_frontend: *std.Build.Module) void {
    const b = context.b;
    const wire = root.import_table.get("stwo_circuit_recursion_wire") orelse graph.createCircuitRecursionWire(b, context.protocol, product_descriptor, context.target, context.optimize, cairo_frontend);
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
    integration.addImport("stwo_proof_wire", root.import_table.get("stwo_proof_wire") orelse graph.addProofWireImport(b, context.protocol, product_descriptor, context.target, context.optimize, root));
    integration.addImport("stwo_prover_api", context.protocol.prover_api);
    integration.addImport("stwo_prover_engine", context.protocol.prover);
    integration.addImport("stwo_cpu_backend", cpu_backend);
    integration.addImport("stwo_circuit_frontend", circuit_frontend);
    integration.addImport("stwo_cairo_frontend", cairo_frontend);
    integration.addImport("stwo_circuit_recursion_wire", wire);
    integration.addImport("circuit_composition_cpu_aot", createCompositionModule(b, context.target, context.optimize, context.protocol.core, cairo_frontend));
    root.addImport("stwo_circuit_cpu_integration", integration);
}

/// The root build owns its generated module. Zig's build-module ownership
/// prevents importing the package build's helper file into this build graph.
fn createCompositionModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    core: *std.Build.Module,
    cairo_frontend: *std.Build.Module,
) *std.Build.Module {
    const generator = b.addExecutable(.{
        .name = "circuit-composition-cpu-codegen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/products/cairo/tools/composition_cpu_codegen/bundle_main.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseFast,
        }),
    });
    const surface = b.createModule(.{
        .root_source_file = b.path("src/frontends/cairo/codegen_surface.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseFast,
    });
    surface.addImport("stwo_core", core);
    generator.root_module.addImport("stwo_cairo", surface);
    const generate = b.addRunArtifact(generator);
    generate.addFileArg(b.path("vectors/circuit/official/circuit_air.air_programs_v1.bin"));
    generate.addArgs(&.{
        "7b8022b09d84db371cc433aa0fcf132f7687f2720e05e4dc9a7650c575dc02c2",
        "circuit_cpu_air",
        "11",
    });
    const directory = generate.addOutputDirectoryArg("circuit-composition-cpu-aot");
    const module = b.createModule(.{
        .root_source_file = directory.path(b, "registry.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("stwo_cairo_frontend", cairo_frontend);
    const kernels = b.addLibrary(.{
        .name = "circuit-composition-cpu-kernels",
        .linkage = .static,
        .root_module = b.createModule(.{ .target = target, .optimize = optimize, .pic = true, .link_libc = true }),
    });
    for (0..11) |index| kernels.root_module.addCSourceFile(.{
        .file = directory.path(b, b.fmt("circuit_cpu_air_{d}.c", .{index})),
        .flags = &.{ "-std=c11", "-O3", "-fstrict-aliasing", "-fno-vectorize", "-fno-slp-vectorize", "-gline-tables-only" },
    });
    module.linkLibrary(kernels);
    return module;
}
