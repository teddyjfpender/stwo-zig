//! Explicit bounded chip planning. Counts choose instance geometry; proofs still
//! authenticate every bus claim and every cross-instance service span.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const Coverage = @import("../../word16_execution/coverage.zig");
const W = @import("../services/wire.zig");
const Capture = @import("capture.zig").Owner;
pub const Ladder = struct { head: u32, tail: ?u32 = null };
pub fn ladder(count: usize, reserve: u32) !Ladder {
    const full: u32 = @intCast(std.math.log2_int_ceil(usize, @max(32, try std.math.add(usize, count, reserve))));
    if (full > 22) return error.EthereumInstanceCapacityExceeded;
    if (full <= 5) return .{ .head = full };
    const head = full - 1;
    const capacity = (@as(usize, 1) << @intCast(head)) - reserve;
    if (count <= capacity) return error.InvalidEthereumLadder;
    const tail: u32 = @intCast(std.math.log2_int_ceil(usize, @max(32, try std.math.add(usize, count - capacity, reserve))));
    if ((@as(u64, 1) << @intCast(head)) + (@as(u64, 1) << @intCast(tail)) >= (@as(u64, 1) << @intCast(full))) return .{ .head = full };
    return .{ .head = head, .tail = tail };
}
pub fn cpus(a: std.mem.Allocator, captured: *const Capture) ![]W.CpuDeclaration {
    const out = try a.alloc(W.CpuDeclaration, captured.native.items.len);
    errdefer a.free(out);
    const boundary = try Coverage.minimalPrefixLog(@intCast(captured.advice.initial.len));
    for (captured.native.items, out, 0..) |n, *d, i| {
        var g = try n.geometryOmittingEmptyDivision();
        const ls = try ladder(captured.advice.events[i].len, 1);
        g.ls_log = ls.head;
        g.ls_tail_log = ls.tail;
        const alu = try ladder(n.alu.facts.len, 0);
        g.alu_log = alu.head;
        g.alu_tail_log = alu.tail;
        const binary = try ladder(n.binary.facts.len, 0);
        g.binary_log = binary.head;
        g.binary_tail_log = binary.tail;
        const shift = try ladder(n.shift.len, 0);
        g.shift_log = shift.head;
        g.shift_tail_log = shift.tail;
        g.boundary_log = 5;
        g.initial_log = if (i == 0) boundary else 5;
        g.terminal_log = if (i + 1 == out.len) boundary else 5;
        d.* = .{ .geometry = g, .bridges = .{} };
        const k = captured.advice.keccak[i].len;
        const add = captured.advice.secp[i][0].len;
        const double = captured.advice.secp[i][1].len;
        if (k != 0) d.bridges.keccak = try Coverage.minimalPrefixLog(@intCast(try std.math.mul(usize, 25, k)));
        if (add != 0) d.bridges.add = try Coverage.minimalPrefixLog(@intCast(try std.math.mul(usize, A.crypto.secp256k1.word16_bridge.types.coordinates(.add), add)));
        if (double != 0) d.bridges.double = try Coverage.minimalPrefixLog(@intCast(try std.math.mul(usize, A.crypto.secp256k1.word16_bridge.types.coordinates(.double), double)));
        try g.validate();
    }
    return out;
}
pub fn truths(a: std.mem.Allocator, captured: *const Capture) ![]W.TruthDeclaration {
    return truthsWithKeccakMaxLog(a, captured, 18);
}
/// Producer geometry experiment only; the receiver admits original call spans.
/// The default entry point remains log18. Smaller shards multiply proof leaves.
pub fn truthsWithKeccakMaxLog(a: std.mem.Allocator, captured: *const Capture, max_log: u32) ![]W.TruthDeclaration {
    var total: [3]u32 = @splat(0);
    for (captured.advice.keccak, captured.advice.secp) |k, s| {
        total[0] = try std.math.add(u32, total[0], @intCast(k.len));
        total[1] = try std.math.add(u32, total[1], @intCast(s[0].len));
        total[2] = try std.math.add(u32, total[2], @intCast(s[1].len));
    }
    return truthsForCounts(a, total, max_log);
}
fn truthsForCounts(a: std.mem.Allocator, total: [3]u32, max_log: u32) ![]W.TruthDeclaration {
    if (max_log < 16 or max_log > 18) return error.UnsupportedEthereumKeccakShardLog;
    var out: std.ArrayList(W.TruthDeclaration) = .{};
    errdefer out.deinit(a);
    // Keep full shard lengths even so partitioning preserves paired slots.
    const max_keccak: u32 = ((@as(u32, 1) << @intCast(max_log)) / A.crypto.keccak.layout.ROWS_PER_PAIR) * 2;
    var next: u32 = 1;
    while (next <= total[0]) {
        const calls = @min(max_keccak, total[0] - next + 1);
        const log: u32 = if (calls > max_keccak / 2) max_log else @intCast(std.math.log2_int_ceil(u32, @max(32, ((calls + 1) / 2) * 29)));
        try out.append(a, .{ .family = .keccak, .first_id = next, .calls = calls, .logs = .{ log, 0 } });
        next = try std.math.add(u32, next, calls);
    }
    for (1..3) |family| {
        const kind: A.crypto.secp256k1.program.Kind = if (family == 1) .add else .double;
        const program = A.crypto.secp256k1.program.get(kind);
        next = 1;
        while (next <= total[family]) {
            // Bound product and linear workers separately; real call counts
            // select shape without constraining CPU geometry to provider size.
            const capacity = @min(((1 << 18) - 1) / program.rows(true), ((1 << 18) - 1) / program.rows(false));
            const calls: u32 = @intCast(@min(capacity, total[family] - next + 1));
            if (calls == 0) return error.EthereumTruthCapacityExceeded;
            const logs = [2]u32{ try A.crypto.secp256k1.layout.logSize(.product, program, calls), try A.crypto.secp256k1.layout.logSize(.linear, program, calls) };
            try out.append(a, .{ .family = @enumFromInt(family), .first_id = next, .calls = calls, .logs = logs });
            next = try std.math.add(u32, next, calls);
        }
    }
    return out.toOwnedSlice(a);
}
test "two-instance planner reduces physical rows only and respects reserved LS rows" {
    try std.testing.expectEqualDeep(Ladder{ .head = 20, .tail = 18 }, try ladder(1200000, 1));
    try std.testing.expectEqualDeep(Ladder{ .head = 19, .tail = 16 }, try ladder(574440, 0));
    try std.testing.expectEqualDeep(Ladder{ .head = 5 }, try ladder(0, 1));
    try std.testing.expectEqualDeep(Ladder{ .head = 6 }, try ladder(32, 1));
    try std.testing.expectError(error.EthereumInstanceCapacityExceeded, ladder(1 << 22, 1));
}

test "bounded Keccak shard experiment preserves full-block call spans and reports physical costs" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.UnsupportedEthereumKeccakShardLog, truthsForCounts(a, .{ 0, 0, 0 }, 15));
    try std.testing.expectError(error.UnsupportedEthereumKeccakShardLog, truthsForCounts(a, .{ 0, 0, 0 }, 19));
    const Shape = @import("../services/gkr_local/truth_components.zig");
    for ([_]u32{ 18, 16 }) |max_log| {
        const declarations = try truthsForCounts(a, .{ 32835, 0, 0 }, max_log);
        defer a.free(declarations);
        var next: u32 = 1;
        var cells: [3]u64 = @splat(0);
        var permutation_rows: u64 = 0;
        var active_rows: u64 = 0;
        var opening_samples: u64 = 0;
        var max_main_bytes: u64 = 0;
        var max_interaction_bytes: u64 = 0;
        var narrow_metadata_bytes: u64 = 0;
        for (declarations) |d| {
            try std.testing.expectEqual(next, d.first_id);
            try std.testing.expect(d.calls > 0 and d.logs[0] <= max_log);
            next += d.calls;
            permutation_rows += @as(u64, 1) << @intCast(d.logs[0]);
            active_rows += ((@as(u64, d.calls) + 1) / 2) * A.crypto.keccak.layout.ROWS_PER_PAIR;
            var worker_cells: [3]u64 = @splat(0);
            narrow_metadata_bytes += (((@as(u64, d.calls) + 1) / 2) * A.crypto.keccak.layout.ROWS_PER_PAIR) * @sizeOf(A.crypto.keccak.trace.PackedRow);
            narrow_metadata_bytes += (@as(u64, A.crypto.keccak.layout.FIXED) * 4) << @intCast(d.logs[0]);
            narrow_metadata_bytes += (8192 + 1024) * (7 * 4 + 4);
            for (try Shape.shapesForDeclaration(d)) |role| {
                for (role.widths(), 0..) |width, tree| {
                    const count = @as(u64, width) << @intCast(role.log_size);
                    cells[tree] += count;
                    worker_cells[tree] += count;
                    for (0..width) |column| opening_samples += role.shifts(tree, column).len;
                }
            }
            max_main_bytes = @max(max_main_bytes, worker_cells[1] * 4);
            max_interaction_bytes = @max(max_interaction_bytes, worker_cells[2] * 4);
        }
        try std.testing.expectEqual(@as(u32, 32836), next);
        try std.testing.expectEqual(@as(u64, 476122), active_rows);
        try std.testing.expectEqual(if (max_log == 18) @as(usize, 2) else 8, declarations.len);
        try std.testing.expectEqual(if (max_log == 18) @as(u64, 524288) else 491520, permutation_rows);
        std.debug.print("KECCAK_SHARD_COST max_log={d} proofs={d} permutation_rows={d} active_rows={d} fixed_cells={d} main_cells={d} interaction_cells={d} opening_samples={d} max_main_bytes={d} max_interaction_bytes={d} narrow_metadata_bytes={d} packed_row_bytes={d}\n", .{ max_log, declarations.len, permutation_rows, active_rows, cells[0], cells[1], cells[2], opening_samples, max_main_bytes, max_interaction_bytes, narrow_metadata_bytes, @sizeOf(A.crypto.keccak.trace.PackedRow) });
    }
}
