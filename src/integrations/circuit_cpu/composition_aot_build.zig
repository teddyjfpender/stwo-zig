//! Build wiring for the circuit AIR's native CPU composition kernels, shared
//! by this package's `build.zig` and the circuit recursion product.
//!
//! The Cairo lane's composition code generator
//! (`src/tools/cairo_composition_cpu_codegen`) turns every distinct program
//! of the SHA-authenticated circuit AIR bundle
//! (`vectors/circuit/official/circuit_air.air_programs_v1.bin`) into a C
//! kernel. The generated `registry.zig` resolves a program identity to its
//! kernel for the captured-AIR component's native executor; an unresolved
//! program stays on the SIMD interpreter. Both evaluate the same exact field
//! arithmetic, so the composition bytes are identical.

const std = @import("std");

pub const bundle_path = "vectors/circuit/official/circuit_air.air_programs_v1.bin";
/// Must equal `air.bundle_sha256`; the generator refuses any other bundle.
pub const bundle_sha256 = "7b8022b09d84db371cc433aa0fcf132f7687f2720e05e4dc9a7650c575dc02c2";
/// Distinct program identities in the bundle; the generator fails on drift.
pub const program_count: usize = 11;
pub const kernel_prefix = "circuit_cpu_air";

/// `repository_root`: the repository root relative to `b`'s build root,
/// with a trailing slash ("" for the root build).
pub fn createModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    core: *std.Build.Module,
    cairo_frontend: *std.Build.Module,
    repository_root: []const u8,
) *std.Build.Module {
    const generator = b.addExecutable(.{
        .name = "circuit-composition-cpu-codegen",
        .root_module = b.createModule(.{
            .root_source_file = b.path(b.fmt("{s}src/tools/cairo_composition_cpu_codegen/bundle_main.zig", .{repository_root})),
            .target = b.graph.host,
            .optimize = .ReleaseFast,
        }),
    });
    const surface = b.createModule(.{
        .root_source_file = b.path(b.fmt("{s}src/frontends/cairo/codegen_surface.zig", .{repository_root})),
        .target = b.graph.host,
        .optimize = .ReleaseFast,
    });
    surface.addImport("stwo_core", core);
    generator.root_module.addImport("stwo_cairo", surface);
    const generate = b.addRunArtifact(generator);
    generate.addFileArg(b.path(b.fmt("{s}{s}", .{ repository_root, bundle_path })));
    generate.addArgs(&.{ bundle_sha256, kernel_prefix, b.fmt("{d}", .{program_count}) });
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
    // The Cairo lane's kernel flags (`cairo_composition_cpu_aot.zig`).
    for (0..program_count) |index| kernels.root_module.addCSourceFile(.{
        .file = directory.path(b, b.fmt("{s}_{d}.c", .{ kernel_prefix, index })),
        .flags = &.{ "-std=c11", "-O3", "-fstrict-aliasing", "-fno-vectorize", "-fno-slp-vectorize", "-gline-tables-only" },
    });
    module.linkLibrary(kernels);
    return module;
}
