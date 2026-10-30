//! Exact protocol preservation for independent physical memory claims.
const std = @import("std");
const T = @import("../block_v7_memory_trace_v1.zig");
const R = @import("../block_v7_memory_relations_v1.zig");
const Q = R.Q;
const M = R.M;
const Context = struct {
    singular: bool = false,
    pub fn termsAt(self: @This(), matrix: T.Matrix, logical: usize) ![3]R.Term(Q) {
        const value = Q.fromBase(matrix.get(0, logical));
        return .{
            .{ .left = if (self.singular and logical == matrix.size() - 1) Q.zero() else value.add(Q.one()), .right = value.add(Q.fromBase(M.fromCanonical(7))), .wl = value, .wr = Q.one(), .constant = value },
            .{ .left = value.add(Q.fromBase(M.fromCanonical(11))), .wl = Q.one(), .constant = value.neg() },
            .{ .right = value.add(Q.fromBase(M.fromCanonical(19))), .wr = value },
        };
    }
};
test "batched independent memory planes match scalar sums and committed bytes across chunks" {
    const a = std.testing.allocator;
    for ([_]u32{ 4, 13 }) |log| {
        var source = try T.Matrix.init(a, log, 1, 1 << 20);
        defer source.deinit();
        for (0..source.size()) |i| source.set(0, i, M.fromU64(i + 1));
        var reference = try T.interactionsReference(3, a, source, Context{}, 1 << 24);
        defer reference.deinit();
        var batched = try T.interactions(3, a, source, Context{}, 1 << 24);
        defer batched.deinit();
        try std.testing.expectEqualDeep(reference.sums, batched.sums);
        try std.testing.expectEqualSlices(M, reference.matrix.storage, batched.matrix.storage);
        try std.testing.expectError(error.DivisionByZero, T.interactions(3, a, source, Context{ .singular = true }, 1 << 24));
    }
}
test "prepared interaction context is admitted once before row generation" {
    const PreparedContext = struct {
        admissions: *usize,
        pub fn prepare(self: @This(), _: usize) !Context {
            self.admissions.* += 1;
            return .{};
        }
    };
    const a = std.testing.allocator;
    var source = try T.Matrix.init(a, 4, 1, 1 << 20);
    defer source.deinit();
    var admissions: usize = 0;
    var result = try T.interactions(3, a, source, PreparedContext{ .admissions = &admissions }, 1 << 20);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), admissions);
}
