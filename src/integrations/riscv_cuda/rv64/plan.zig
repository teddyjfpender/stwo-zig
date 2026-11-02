//! Exact numerical-engine arena geometry. No VRAM aggregation or host spill.
const std = @import("std");
pub const Region = struct { offset_words: u64, words: u64 };
pub const Plan = struct {
    count: u32,
    arity: u32,
    tuples: Region,
    weights: Region,
    active: Region,
    challenges: Region,
    leaf_n: Region,
    leaf_d: Region,
    tree: Region,
    fold_n: Region,
    fold_d: Region,
    fold_next_n: Region,
    fold_next_d: Region,
    eq: Region,
    scratch_a: Region,
    scratch_b: Region,
    parameters: Region,
    round_state: Region,
    round_records: Region,
    terminal_mask: Region,
    verdict: Region,
    total_bytes: u64,

    pub fn init(log_count: u6, arity: u32) !Plan {
        if (log_count < 2 or log_count > 28 or arity == 0 or arity > 32) return error.InvalidGeometry;
        const n: u64 = @as(u64, 1) << log_count;
        var cursor: u64 = 0;
        const tuples = try append(&cursor, n * arity);
        const weights = try append(&cursor, n);
        const active = try append(&cursor, n);
        const challenges = try append(&cursor, 8 * (@as(u64, arity) + 1));
        const leaf_n = try append(&cursor, n);
        const leaf_d = try append(&cursor, 8 * n);
        // Every upper fraction-tree level retained; sum_{j>=1} n/2^j=n-1.
        const tree = try append(&cursor, 16 * (n - 1));
        const fold_n = try append(&cursor, 8 * (n / 2));
        const fold_d = try append(&cursor, 8 * (n / 2));
        // A second bank is required after the first half-split fold. It may
        // reuse dead tree storage only when the owner proves that liveness.
        const fold_next_n = try append(&cursor, 8 * (n / 4));
        const fold_next_d = try append(&cursor, 8 * (n / 4));
        const eq = try append(&cursor, 8 * (n / 4));
        const groups = (n / 4 + 127) / 128;
        const scratch_a = try append(&cursor, 16 * groups);
        const scratch_b = try append(&cursor, 16 * groups);
        // y point, lambda, initial claim, 9-word native seed and raw at0/2.
        // The seed counter is a ninth word, not a field coordinate.
        const parameters = try append(&cursor, 8 * (@as(u64, log_count) - 1) + 8 + 8 + 9 + 16);
        const round_state = try append(&cursor, 40);
        const round_records = try append(&cursor, 44 * (@as(u64, log_count) - 1));
        const terminal_mask = try append(&cursor, 32);
        const verdict = try append(&cursor, 1);
        return .{ .count = @intCast(n), .arity = arity, .tuples = tuples, .weights = weights, .active = active, .challenges = challenges, .leaf_n = leaf_n, .leaf_d = leaf_d, .tree = tree, .fold_n = fold_n, .fold_d = fold_d, .fold_next_n = fold_next_n, .fold_next_d = fold_next_d, .eq = eq, .scratch_a = scratch_a, .scratch_b = scratch_b, .parameters = parameters, .round_state = round_state, .round_records = round_records, .terminal_mask = terminal_mask, .verdict = verdict, .total_bytes = try std.math.mul(u64, cursor, 4) };
    }
};
fn append(cursor: *u64, words: u64) !Region {
    const aligned = try std.math.add(u64, cursor.*, 63);
    const offset = aligned & ~@as(u64, 63);
    cursor.* = try std.math.add(u64, offset, words);
    return .{ .offset_words = offset, .words = words };
}
