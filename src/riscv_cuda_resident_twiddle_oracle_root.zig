const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
test "export original CPU canonical twiddle oracle for device differential" {
    const a = std.testing.allocator;
    const path = std.posix.getenv("STWO_TWIDDLE_ORACLE") orelse return error.MissingOracleOutput;
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    for (1..21) |log| {
        var tree = try engine.poly.twiddles.precomputeM31(a, core.poly.circle.CanonicCoset.new(@intCast(log)).circleDomain().half_coset);
        defer engine.poly.twiddles.deinitM31(a, &tree);
        const header = [_]u32{ @intCast(log), @intCast(tree.twiddles.len) };
        try file.writeAll(std.mem.sliceAsBytes(&header));
        try file.writeAll(std.mem.sliceAsBytes(tree.twiddles));
        try file.writeAll(std.mem.sliceAsBytes(tree.itwiddles));
    }
}
