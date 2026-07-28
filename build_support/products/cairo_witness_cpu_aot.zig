//! Build-time generation of authenticated Cairo CPU witness writers.

const std = @import("std");

const bundle_path = "vectors/cairo/official/witness_programs_v1.bin";
const provenance_path =
    "vectors/cairo/official/witness_programs_v1.provenance.json";

pub fn createModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    stwo: *std.Build.Module,
) *std.Build.Module {
    const generator = b.addExecutable(.{
        .name = "cairo-witness-cpu-codegen",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "src/tools/cairo_witness_cpu_codegen/main.zig",
            ),
            .target = b.graph.host,
            .optimize = .ReleaseFast,
        }),
    });
    const generate = b.addRunArtifact(generator);
    generate.addFileArg(b.path(bundle_path));
    const source_directory = generate.addOutputDirectoryArg(
        "cairo-witness-cpu-aot",
    );
    const module = b.createModule(.{
        .root_source_file = source_directory.path(b, "registry.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("stwo_cairo", stwo);
    for (componentLabels(b)) |label| {
        module.addCSourceFile(.{
            .file = source_directory.path(
                b,
                b.fmt("{s}.c", .{label}),
            ),
            .flags = &.{
                "-std=c11",
                "-O3",
                "-fstrict-aliasing",
            },
        });
    }
    return module;
}

fn componentLabels(b: *std.Build) []const []const u8 {
    const encoded = b.build_root.handle.readFileAlloc(
        b.allocator,
        provenance_path,
        1024 * 1024,
    ) catch @panic("cannot read Cairo witness provenance");
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        b.allocator,
        encoded,
        .{},
    ) catch @panic("cannot parse Cairo witness provenance");
    const artifact = parsed.value.object.get("artifact") orelse
        @panic("Cairo witness provenance has no artifact");
    const components = artifact.object.get("components") orelse
        @panic("Cairo witness provenance has no component list");
    const labels = b.allocator.alloc(
        []const u8,
        components.array.items.len,
    ) catch @panic("out of memory");
    for (components.array.items, labels) |value, *label| {
        label.* = value.string;
    }
    return labels;
}
