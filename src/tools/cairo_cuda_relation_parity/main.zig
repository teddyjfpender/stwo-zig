//! Reproducible exact-height SN2 relation-parity fixture generator.

const std = @import("std");
const stwo = @import("stwo");
const composition_bundle =
    stwo.frontends.cairo.witness.composition_bundle;
const relation_bundle = stwo.frontends.cairo.witness.relation_bundle;
const parity = stwo.integrations.cairo_cuda.relation_sn2_parity_fixture;

const usage =
    "usage: cairo-cuda-relation-parity <composition.bin> " ++
    "<relations.bin> <fixture.h>\n";

pub fn main() void {
    run() catch |err| {
        std.debug.print(
            "cairo-cuda-relation-parity failed: {s}\n",
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
    if (args.len != 4) {
        std.debug.print("{s}", .{usage});
        return error.InvalidArguments;
    }

    var composition = try composition_bundle.Bundle.readFile(
        allocator,
        args[1],
    );
    defer composition.deinit();
    var relations = try relation_bundle.Bundle.readFile(
        allocator,
        args[2],
    );
    defer relations.deinit();
    var fixture = try parity.build(allocator, composition, relations);
    defer fixture.deinit();
    if (fixture.instances.len != 58 or
        fixture.max_alpha_powers != 126 or
        fixture.descriptors.len != 9_072)
    {
        return error.InvalidParityFixture;
    }
    const header = try parity.renderHeader(allocator, fixture);
    defer allocator.free(header);
    if (std.fs.path.dirname(args[3])) |directory|
        try std.fs.cwd().makePath(directory);
    try std.fs.cwd().writeFile(.{
        .sub_path = args[3],
        .data = header,
    });
    std.debug.print(
        "generated exact SN2 relation oracle: instances={} " ++
            "descriptors={} bytes={}\n",
        .{ fixture.instances.len, fixture.descriptors.len, header.len },
    );
}
