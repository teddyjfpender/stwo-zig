//! Paired-LogUp constraint evaluation shared by all Blake components.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const Entry = struct {
    multiplicity: QM31,
    denominator: QM31,
};

pub fn evaluate(
    entries: []const Entry,
    current_columns: []const QM31,
    previous_last: QM31,
    claimed_sum: QM31,
    log_size: u32,
    output: []QM31,
) !void {
    const batch_count = (entries.len + 1) / 2;
    if (batch_count == 0 or
        current_columns.len != batch_count or
        output.len != batch_count or
        log_size >= 31)
    {
        return error.InvalidProofShape;
    }

    var previous_column = QM31.zero();
    for (0..batch_count) |batch| {
        const first = entries[2 * batch];
        var numerator = first.multiplicity;
        var denominator = first.denominator;
        if (2 * batch + 1 < entries.len) {
            const second = entries[2 * batch + 1];
            numerator = first.multiplicity.mul(second.denominator)
                .add(second.multiplicity.mul(first.denominator));
            denominator = first.denominator.mul(second.denominator);
        }

        const current = current_columns[batch];
        if (batch + 1 == batch_count) {
            const row_count = M31.fromCanonical(
                @as(u32, 1) << @intCast(log_size),
            );
            const shifted_diff = current
                .sub(previous_last)
                .sub(previous_column)
                .add(try claimed_sum.divM31(row_count));
            output[batch] = shifted_diff.mul(denominator).sub(numerator);
        } else {
            output[batch] = current.sub(previous_column)
                .mul(denominator)
                .sub(numerator);
        }
        previous_column = current;
    }
}

test "paired LogUp constraints bind intermediate and shifted final columns" {
    const entries = [_]Entry{
        .{ .multiplicity = QM31.one(), .denominator = QM31.fromBase(M31.fromCanonical(2)) },
        .{ .multiplicity = QM31.one(), .denominator = QM31.fromBase(M31.fromCanonical(3)) },
        .{ .multiplicity = QM31.one().neg(), .denominator = QM31.fromBase(M31.fromCanonical(5)) },
    };
    const first = try QM31.fromBase(M31.fromCanonical(5)).div(
        QM31.fromBase(M31.fromCanonical(6)),
    );
    const second = first.sub(try QM31.one().div(
        QM31.fromBase(M31.fromCanonical(5)),
    ));
    var output: [2]QM31 = undefined;
    try evaluate(
        &entries,
        &.{ first, second },
        QM31.zero(),
        QM31.zero(),
        4,
        &output,
    );
    try std.testing.expect(output[0].isZero());
    try std.testing.expect(output[1].isZero());
}
