const std = @import("std");
const qm31 = @import("../core/fields/qm31.zig");

const QM31 = qm31.QM31;

pub const FriDecommitError = error{
    QueryOutOfRange,
    FoldStepTooLarge,
};

pub const ValueEntry = struct {
    position: usize,
    value: QM31,
};

pub const DecommitmentPositionsResult = struct {
    decommitment_positions: []usize,
    witness_evals: []QM31,
    value_map: []ValueEntry,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.decommitment_positions);
        allocator.free(self.witness_evals);
        allocator.free(self.value_map);
        self.* = undefined;
    }
};

/// Returns Merkle decommitment positions and witness evals needed for one FRI layer decommitment.
///
/// `query_positions` are expected in sorted ascending order.
pub fn computeDecommitmentPositionsAndWitnessEvals(
    allocator: std.mem.Allocator,
    column: []const QM31,
    query_positions: []const usize,
    fold_step: u32,
) (std.mem.Allocator.Error || FriDecommitError)!DecommitmentPositionsResult {
    if (fold_step >= @bitSizeOf(usize)) return FriDecommitError.FoldStepTooLarge;

    var decommitment_positions = std.ArrayList(usize).init(allocator);
    defer decommitment_positions.deinit();
    var witness_evals = std.ArrayList(QM31).init(allocator);
    defer witness_evals.deinit();
    var value_map = std.ArrayList(ValueEntry).init(allocator);
    defer value_map.deinit();

    const subset_len = @as(usize, 1) << @intCast(fold_step);

    var subset_start_idx: usize = 0;
    while (subset_start_idx < query_positions.len) {
        const subset_key = query_positions[subset_start_idx] >> @intCast(fold_step);
        var subset_end_idx = subset_start_idx + 1;
        while (subset_end_idx < query_positions.len and
            (query_positions[subset_end_idx] >> @intCast(fold_step)) == subset_key)
        {
            subset_end_idx += 1;
        }

        const subset_queries = query_positions[subset_start_idx..subset_end_idx];
        const subset_start = subset_key << @intCast(fold_step);
        var subset_query_at: usize = 0;

        var position = subset_start;
        while (position < subset_start + subset_len) : (position += 1) {
            if (position >= column.len) return FriDecommitError.QueryOutOfRange;

            try decommitment_positions.append(position);
            const eval = column[position];
            try value_map.append(.{
                .position = position,
                .value = eval,
            });

            if (subset_query_at < subset_queries.len and subset_queries[subset_query_at] == position) {
                subset_query_at += 1;
            } else {
                try witness_evals.append(eval);
            }
        }

        subset_start_idx = subset_end_idx;
    }

    return .{
        .decommitment_positions = try decommitment_positions.toOwnedSlice(),
        .witness_evals = try witness_evals.toOwnedSlice(),
        .value_map = try value_map.toOwnedSlice(),
    };
}

test "prover fri: decommitment positions and witness evals" {
    const alloc = std.testing.allocator;

    const column = [_]QM31{
        QM31.fromBase(.fromCanonical(1)),
        QM31.fromBase(.fromCanonical(2)),
        QM31.fromBase(.fromCanonical(3)),
        QM31.fromBase(.fromCanonical(4)),
        QM31.fromBase(.fromCanonical(5)),
        QM31.fromBase(.fromCanonical(6)),
        QM31.fromBase(.fromCanonical(7)),
        QM31.fromBase(.fromCanonical(8)),
    };
    const queries = [_]usize{ 1, 3, 6 };

    var result = try computeDecommitmentPositionsAndWitnessEvals(
        alloc,
        column[0..],
        queries[0..],
        1,
    );
    defer result.deinit(alloc);

    try std.testing.expectEqualSlices(usize, &[_]usize{ 0, 1, 2, 3, 6, 7 }, result.decommitment_positions);
    try std.testing.expectEqual(@as(usize, 3), result.witness_evals.len);
    try std.testing.expect(result.witness_evals[0].eql(column[0]));
    try std.testing.expect(result.witness_evals[1].eql(column[2]));
    try std.testing.expect(result.witness_evals[2].eql(column[7]));

    try std.testing.expectEqual(@as(usize, 6), result.value_map.len);
    for (result.value_map, 0..) |entry, i| {
        try std.testing.expectEqual(result.decommitment_positions[i], entry.position);
        try std.testing.expect(entry.value.eql(column[entry.position]));
    }
}

test "prover fri: query out of range fails" {
    const column = [_]QM31{
        QM31.fromBase(.fromCanonical(1)),
        QM31.fromBase(.fromCanonical(2)),
        QM31.fromBase(.fromCanonical(3)),
        QM31.fromBase(.fromCanonical(4)),
    };
    const queries = [_]usize{7};
    try std.testing.expectError(
        FriDecommitError.QueryOutOfRange,
        computeDecommitmentPositionsAndWitnessEvals(
            std.testing.allocator,
            column[0..],
            queries[0..],
            0,
        ),
    );
}

test "prover fri: fold step too large fails" {
    const column = [_]QM31{QM31.fromBase(.fromCanonical(1))};
    const queries = [_]usize{0};
    try std.testing.expectError(
        FriDecommitError.FoldStepTooLarge,
        computeDecommitmentPositionsAndWitnessEvals(
            std.testing.allocator,
            column[0..],
            queries[0..],
            @bitSizeOf(usize),
        ),
    );
}
