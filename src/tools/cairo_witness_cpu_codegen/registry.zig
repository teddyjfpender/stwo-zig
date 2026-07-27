//! Generated Zig registry for native Cairo witness writer objects.

const std = @import("std");
const model = @import("model.zig");

pub fn emit(
    writer: *std.Io.Writer,
    programs: []const model.Program,
) !void {
    try writer.writeAll(
        \\//! Generated from the authenticated Cairo witness bundle. Do not edit.
        \\
        \\const std = @import("std");
        \\const package = @import("stwo_cairo");
        \\const generated = package.frontends.cairo.witness.generated_executor;
        \\
        \\pub const generated_program_count: usize =
    );
    try writer.print("{};\n\n", .{programs.len});
    try writer.writeAll(
        \\pub fn executor() generated.Executor {
        \\    return .{ .resolve_fn = resolve };
        \\}
        \\
        \\fn resolve(_: ?*anyopaque, identity: [32]u8) ?generated.Writer {
        \\
    );
    for (programs) |witness_program| {
        const digest = witness_program.semanticIdentity();
        try writer.writeAll("    if (std.mem.eql(u8, &identity, &.{ ");
        for (digest, 0..) |byte, index| {
            if (index != 0) try writer.writeAll(", ");
            try writer.print("0x{x:0>2}", .{byte});
        }
        try writer.print(" }})) return writer_{x};\n", .{
            std.mem.readInt(u64, digest[0..8], .little),
        });
    }
    try writer.writeAll(
        \\    return null;
        \\}
        \\
    );
    for (programs) |witness_program| {
        const digest = witness_program.semanticIdentity();
        const symbol = std.mem.readInt(u64, digest[0..8], .little);
        try writer.print(
            \\
            \\extern fn cairo_witness_{x}(
            \\    run: *const generated.NativeRangeExecution,
            \\) callconv(.c) c_int;
            \\
            \\fn writer_{x}(run: generated.RangeExecution) !void {{
            \\    return generated.executeNative(cairo_witness_{x}, run);
            \\}}
            \\
        , .{ symbol, symbol, symbol });
    }
}
