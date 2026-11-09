const std = @import("std");
const E = @import("../evaluation.zig");
const U = @import("u16_source.zig");
const core = @import("stwo_core");
test "U16 source validates mass geometry and transactional inverse allocation without retained main" {
    const a = std.testing.allocator;
    const counts = try a.alloc(u64, U.SIZE);
    defer a.free(counts);
    @memset(counts, 0);
    const Runner = struct {
        fn run(allocator: std.mem.Allocator, values: []const u64) !void {
            var setup = try U.Setup.init(allocator);
            defer setup.deinit();
            var source = try U.Source.init(allocator, &setup, values);
            defer source.deinit();
            source.releaseMain();
            const claim = try source.generate(.{ .offset = E.Q.one(), .coefficient = E.Q.zero() });
            try std.testing.expect(claim.isZero());
        }
    };
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{counts});
    var setup = try U.Setup.init(a);
    defer setup.deinit();
    var source = try U.Source.init(a, &setup, counts);
    defer source.deinit();
    source.releaseMain();
    try std.testing.expectError(error.DivisionByZero, source.generate(.{ .offset = E.Q.zero(), .coefficient = E.Q.one() }));
    try std.testing.expectEqual(@as(usize, 0), source.interaction.len);
    try std.testing.expectEqual(@as(usize, 0), source.dictionary.len);
    _ = try source.generate(.{ .offset = E.Q.one(), .coefficient = E.Q.zero() });
    try std.testing.expectError(error.InvalidU16Phase, source.generate(.{ .offset = E.Q.one(), .coefficient = E.Q.zero() }));
    counts[0] = core.fields.m31.Modulus;
    try std.testing.expectError(error.Word16MassExceeded, U.Source.init(a, &setup, counts));
}
