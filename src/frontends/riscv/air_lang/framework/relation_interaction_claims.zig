//! Per-batch claim derivation for an authenticated logical interaction row.

pub fn rowClaims(
    comptime Runtime: type,
    plan: *const Runtime.Plan,
    arena: anytype,
    expected_digest: anytype,
    event_ids: anytype,
    row: Runtime.Row,
    relations: anytype,
) Runtime.ClaimErrorSet!Runtime.Claims {
    const pairs = try plan.rowPairs(
        arena,
        expected_digest,
        event_ids,
        row,
        relations,
    );
    var sums: [Runtime.BATCH_COUNT]Runtime.QM31Type = undefined;
    for (&sums, pairs) |*sum, pair| sum.* = try Runtime.pairSumPrepared(pair);
    return .{ .sums = sums };
}
