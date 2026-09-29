//! Native CPU evaluators generated only from the authenticated Cairo AIR library.
const std = @import("std");
pub fn createModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, stwo: *std.Build.Module) *std.Build.Module {
    const generator = b.addExecutable(.{
        .name = "cairo-composition-cpu-codegen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/cairo_composition_cpu_codegen/main.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseFast,
        }),
    });
    const surface = b.createModule(.{ .root_source_file = b.path("src/frontends/cairo/codegen_surface.zig"), .target = b.graph.host, .optimize = .ReleaseFast });
    surface.addImport("stwo_core", stwo.import_table.get("stwo_core").?);
    generator.root_module.addImport("stwo_cairo", surface);
    const generate = b.addRunArtifact(generator);
    generate.addFileArg(b.path("vectors/cairo/official/air_template_library_v1.json"));
    // Declare all authenticated bundle inputs so cached generation cannot go stale.
    generate.addFileInput(b.path("vectors/cairo/official/all_opcodes.air_programs_v1.bin"));
    generate.addFileInput(b.path("vectors/cairo/official/all_builtins_canonical.air_programs_v1.bin"));
    generate.addFileInput(b.path("vectors/cairo/official/all_builtins_canonical_small.air_programs_v1.bin"));
    const directory = generate.addOutputDirectoryArg("cairo-composition-cpu-aot");
    const module = b.createModule(.{ .root_source_file = directory.path(b, "registry.zig"), .target = target, .optimize = optimize });
    module.addImport("stwo_cairo", stwo);
    // Share one PIC C library between the CLI and parity tests. Attaching C
    // sources to the Zig registry compiled the same 69 kernels per consumer.
    const kernels = b.addLibrary(.{
        .name = "cairo-composition-cpu-kernels",
        .linkage = .static,
        .root_module = b.createModule(.{ .target = target, .optimize = optimize, .pic = true, .link_libc = true }),
    });
    for (0..69) |index| kernels.root_module.addCSourceFile(.{ .file = directory.path(b, b.fmt("air_{d}.c", .{index})), .flags = &.{ "-std=c11", "-O3", "-fstrict-aliasing", "-fno-vectorize", "-fno-slp-vectorize", "-gline-tables-only" } });
    module.linkLibrary(kernels);
    return module;
}
