//! A same-domain request must accumulate into one shared bucket.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const DomainEvaluationAccumulator = @import("accumulation.zig").DomainEvaluationAccumulator;

test "prover air accumulation: duplicate log sizes preserve both writers" {
    const alloc = std.testing.allocator;
    var acc = try DomainEvaluationAccumulator.init(alloc, QM31.one(), 1, 2);
    defer acc.deinit();
    const cols = try acc.columns(alloc, &.{
        .{ .log_size = 1, .n_cols = 1 },
        .{ .log_size = 1, .n_cols = 1 },
    });
    defer alloc.free(cols);
    var left = cols[0];
    var right = cols[1];
    left.accumulate(0, QM31.fromU32Unchecked(7, 0, 0, 0));
    right.accumulate(0, QM31.fromU32Unchecked(5, 0, 0, 0));
    left.accumulate(1, QM31.fromU32Unchecked(3, 0, 0, 0));
    try std.testing.expect(left.col.at(0).eql(QM31.fromU32Unchecked(12, 0, 0, 0)));
    try std.testing.expect(left.col.at(1).eql(QM31.fromU32Unchecked(3, 0, 0, 0)));
}
