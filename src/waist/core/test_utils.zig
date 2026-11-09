const std = @import("std");
const channel_blake2s = @import("channel/blake2s.zig");
const m31 = @import("fields/m31.zig");
const qm31 = @import("fields/qm31.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

/// Projects secure-field evaluations onto their first base-field coordinate.
///
/// Inputs/outputs:
/// - `eval` is a secure-field evaluation vector.
/// - output is `eval.len` base-field values, where output[i] = eval[i].toM31Array()[0].
///
/// Failure modes:
/// - allocator failures.
pub fn secureEvalToBaseEval(
    allocator: std.mem.Allocator,
    eval: []const QM31,
) ![]M31 {
    const out = try allocator.alloc(M31, eval.len);
    for (eval, 0..) |value, i| {
        out[i] = value.toM31Array()[0];
    }
    return out;
}

pub fn testChannel() channel_blake2s.Blake2sChannel {
    return .{};
}

test "test utils: secure eval projected to first coordinate" {
    const alloc = std.testing.allocator;
    const eval = [_]QM31{
        QM31.fromU32Unchecked(3, 5, 7, 11),
        QM31.fromU32Unchecked(13, 17, 19, 23),
    };

    const projected = try secureEvalToBaseEval(alloc, eval[0..]);
    defer alloc.free(projected);

    try std.testing.expect(projected[0].eql(M31.fromCanonical(3)));
    try std.testing.expect(projected[1].eql(M31.fromCanonical(13)));
}

test "test utils: test channel deterministic start" {
    var c0 = testChannel();
    var c1 = testChannel();

    const draw0 = c0.drawSecureFelt();
    const draw1 = c1.drawSecureFelt();
    try std.testing.expect(draw0.eql(draw1));
}
