//! Cold per-domain claim audit for an authenticated relation interaction plan.

const std = @import("std");
const stwo_core = @import("stwo_core");
const fields = stwo_core.fields;
const QM31 = fields.qm31.QM31;
const logup = @import("../../air/logup.zig");
const universal = @import("universal_challenges.zig");

pub fn auditPreparedDomainSums(
    comptime Runtime: type,
    plan: *const Runtime.Plan,
    allocator: std.mem.Allocator,
    rows: []const Runtime.Row,
    relations: *const universal.UniversalRelations,
    expected_claimed_sum: QM31,
) Runtime.DomainAuditErrorSet!Runtime.DomainAuditResult {
    try relations.validate();
    const pair_count = std.math.mul(
        usize,
        Runtime.BATCH_COUNT,
        rows.len,
    ) catch return error.InvalidTraceShape;
    const inverse_scratch_count = std.math.mul(
        usize,
        pair_count,
        2,
    ) catch return error.InvalidTraceShape;

    const pairs = try allocator.alloc(logup.RowPair, pair_count);
    defer allocator.free(pairs);
    const inverse_scratch = try allocator.alloc(QM31, inverse_scratch_count);
    defer allocator.free(inverse_scratch);
    const denominators = inverse_scratch[0..pair_count];
    const inverses = inverse_scratch[pair_count..];

    for (rows, 0..) |row, logical_row| {
        const row_pairs = try plan.preparedRowPairs(row, relations);
        for (row_pairs, 0..) |pair, batch| {
            const index = batch * rows.len + logical_row;
            pairs[index] = pair;
            denominators[index] = pair.d1.mul(pair.d2);
        }
    }
    if (pair_count != 0) {
        fields.batchInverseInPlace(QM31, denominators, inverses) catch
            return error.ZeroDenominator;
    }

    var values = [_]QM31{QM31.zero()} ** universal.RELATION_COUNT;
    for (plan.batches, 0..) |batch_plan, batch| {
        const first_domain = @intFromEnum(
            plan.events[batch_plan.first].domain,
        );
        for (0..rows.len) |logical_row| {
            const index = batch * rows.len + logical_row;
            const pair = pairs[index];
            const inverse = inverses[index];
            values[first_domain] = values[first_domain].add(
                pair.n1.mul(pair.d2).mul(inverse),
            );
            if (batch_plan.second) |second| {
                const second_domain = @intFromEnum(plan.events[second].domain);
                values[second_domain] = values[second_domain].add(
                    pair.n2.mul(pair.d1).mul(inverse),
                );
            }
        }
    }

    var total = QM31.zero();
    for (values) |value| total = total.add(value);
    if (!total.eql(expected_claimed_sum)) return error.ClaimMismatch;
    const event_terms = std.math.mul(
        usize,
        Runtime.EVENT_COUNT,
        rows.len,
    ) catch return error.InvalidTraceShape;
    return .{
        .values = values,
        .total = total,
        .logical_rows = rows.len,
        .event_terms = event_terms,
    };
}
