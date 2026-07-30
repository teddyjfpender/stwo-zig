//! Reproducible bounded SIMD/CUDA constraint-parity fixture generator.

const std = @import("std");
const stwo = @import("stwo");
const composition = stwo.frontends.cairo.witness.composition_bundle;
const eval_aot = stwo.integrations.cairo_cuda.eval_aot;
const parity = stwo.integrations.cairo_cuda.eval_parity_fixture;

const usage =
    "usage: cairo-cuda-eval-parity <composition.bin> <fixture.h>\n";

pub fn main() void {
    run() catch |err| {
        std.debug.print(
            "cairo-cuda-eval-parity failed: {s}\n",
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
    var fixture = try parity.build(allocator, bundle, product);
    defer fixture.deinit();
    if (fixture.placements.len != 279 or fixture.zero_inversions != 0)
        return error.InvalidParityFixture;
    const header = try parity.renderHeader(allocator, fixture);
    defer allocator.free(header);
    if (std.fs.path.dirname(args[2])) |directory| {
        try std.fs.cwd().makePath(directory);
    }
    try std.fs.cwd().writeFile(.{
        .sub_path = args[2],
        .data = header,
    });
    std.debug.print(
        "generated {}-lane SIMD oracle for {} canonical placements; " ++ "arena={} words\n",
        .{
            parity.fixture_rows,
            fixture.placements.len,
            fixture.arena_words,
        },
    );
}
