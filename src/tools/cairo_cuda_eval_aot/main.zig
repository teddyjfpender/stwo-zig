//! Reproducible build-cache AOT source generator for the exact SN2 AIR bundle.

const std = @import("std");
const stwo = @import("stwo");
const composition = if (@hasDecl(stwo, "frontends"))
    stwo.frontends.cairo.witness.composition_bundle
else
    stwo.frontend.witness.composition_bundle;
const eval_aot = if (@hasDecl(stwo, "integrations"))
    stwo.integrations.cairo_cuda.eval_aot
else
    stwo.integration.eval_aot;

const usage =
    "usage: cairo-cuda-eval-aot <composition.bin> <output-directory>\n";

pub fn main() void {
    run() catch |err| {
        std.debug.print(
            "cairo-cuda-eval-aot failed: {s}\n",
            .{@errorName(err)},
        );
        std.process.exit(2);
    };
}

fn run() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 3) {
        std.debug.print("{s}", .{usage});
        return error.InvalidArguments;
    }

    var bundle = try composition.Bundle.readFile(allocator, args[1]);
    defer bundle.deinit();
    var product = try eval_aot.build(allocator, bundle);
    defer product.deinit();
    if (product.bodies.len != 271 or product.occurrence_count != 279) {
        std.debug.print(
            "observed {} bodies and {} placements\n",
            .{ product.bodies.len, product.occurrence_count },
        );
        return error.UnexpectedSn2Inventory;
    }

    try std.fs.cwd().makePath(args[2]);
    var directory = try std.fs.cwd().openDir(
        args[2],
        .{ .iterate = true },
    );
    defer directory.close();
    var iterator = directory.iterate();
    while (try iterator.next()) |entry| {
        if (entry.kind == .file and
            (std.mem.endsWith(u8, entry.name, ".cu") or
                std.mem.eql(
                    u8,
                    entry.name,
                    "aot_manifest.json",
                )))
        {
            try directory.deleteFile(entry.name);
        }
    }

    for (product.bodies) |body| {
        const filename = try body.filename(allocator);
        defer allocator.free(filename);
        try directory.writeFile(.{
            .sub_path = filename,
            .data = body.source,
        });
    }
    const manifest = try eval_aot.renderManifest(allocator, product);
    defer allocator.free(manifest);
    try directory.writeFile(.{
        .sub_path = "aot_manifest.json",
        .data = manifest,
    });
    std.debug.print(
        "generated {} authenticated bodies for {} exact SN2 placements\n",
        .{ product.bodies.len, product.occurrence_count },
    );
}
