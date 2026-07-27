//! Shared build ownership for focused Cairo products.

const std = @import("std");
const graph = @import("../graph/modules.zig");

pub const protocol_features =
    "stwo-cairo-v1.2.2+cairo-executable-v1+cairo-lang-2.20.0+cairo-vm-3.2.0+official-vm-adapter-v2+official-json-v1+cairo-serde-v1+bincode-v1+bzip2-1.0.8+live-geometry-v1+air-template-library-v1+lifted-pcs-v2+blake2s";

pub fn linkBzip2(
    b: *std.Build,
    artifact: *std.Build.Step.Compile,
) void {
    artifact.addIncludePath(b.path("third_party/bzip2"));
    inline for (.{
        "blocksort.c",
        "huffman.c",
        "crctable.c",
        "randtable.c",
        "compress.c",
        "decompress.c",
        "bzlib.c",
    }) |name| {
        artifact.addCSourceFile(.{
            .file = b.path("third_party/bzip2/" ++ name),
            .flags = &.{
                "-std=c99",
                "-DBZ_NO_STDIO=1",
                "-D_FILE_OFFSET_BITS=64",
                "-Wno-unused-parameter",
            },
        });
    }
    artifact.linkLibC();
}

pub fn createProductSupportModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    product: graph.Product,
    stwo: *std.Build.Module,
) *std.Build.Module {
    const shared = graph.create(b, .{
        .product = product,
        .root_source_file = "src/products/cairo/shared/mod.zig",
        .target = target,
        .optimize = optimize,
    });
    shared.addImport("stwo_cairo", stwo);
    return shared;
}

pub fn installProfile(
    b: *std.Build,
    step: *std.Build.Step,
) void {
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
            .source = "vectors/cairo/official/all_builtins.params.json",
            .destination = "share/stwo-zig/cairo/official/all_builtins.params.json",
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
            .source = "vectors/cairo/official/all_builtins_canonical.air_programs_v1.bin",
            .destination = "share/stwo-zig/cairo/official/all_builtins_canonical.air_programs_v1.bin",
        },
        .{
            .source = "vectors/cairo/official/all_builtins_canonical_small.air_programs_v1.bin",
            .destination = "share/stwo-zig/cairo/official/all_builtins_canonical_small.air_programs_v1.bin",
        },
        .{
            .source = "vectors/cairo/official/air_template_library_v1.json",
            .destination = "share/stwo-zig/cairo/official/air_template_library_v1.json",
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
        const install = b.addInstallFile(
            b.path(asset.source),
            asset.destination,
        );
        step.dependOn(&install.step);
    }
}
