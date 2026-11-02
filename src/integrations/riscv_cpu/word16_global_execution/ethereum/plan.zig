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
/// CPU AIR layout options chosen by the producer route. Every option is part of
/// the declaration (`Geometry` or the LS-D64 bridge logs), so it is mixed into
/// each CPU transcript and published; the receiver rebuilds keys from it.
pub const CpuLayout = struct {
    /// Fused-tail CPU interaction (40 -> 36 columns, same LogUp statement).
    fused_tail: bool = false,
    /// Byte-pair CPU lookups on top of the fused tail (36 -> 32 columns).
    u8_pairs: bool = false,
    /// Route every aligned LD/SD of a shard to the LS-D64 component; LS32
    /// instances are sized on the remainder.
    ls_dword: bool = false,
    /// Compact decode CPU MAIN on top of the byte pairs (47 -> 37 columns).
    /// Changes the AUIPC/JAL FUNCTION facts, so the capture program must be
    /// made compact (Program.makeCompact) before capture.
    compact_decode: bool = false,
    /// Default layout for a profile route. Only the admitted
    /// `ethereum_services_v3` route defaults to the fused tail, byte pairs,
    /// compact decode and LS-D64; every older route keeps its historical
    /// layout and bundle bytes.
    pub fn forProfile(profile: @import("stwo_riscv_frontend").rv64.execution_profile.Profile) CpuLayout {
        const v3 = profile == .ethereum_services_v3;
        return .{ .fused_tail = v3, .u8_pairs = v3, .ls_dword = v3, .compact_decode = v3 };
    }
};
pub fn cpus(a: std.mem.Allocator, captured: *const Capture, layout: CpuLayout) ![]W.CpuDeclaration {
    const out = try a.alloc(W.CpuDeclaration, captured.native.items.len);
    errdefer a.free(out);
    const boundary = try Coverage.minimalPrefixLog(@intCast(captured.advice.initial.len));
    for (captured.native.items, out, 0..) |n, *d, i| {
        var g = try n.geometryOmittingEmptyDivision();
        const events = captured.advice.events[i];
        const dword: usize = if (layout.ls_dword) @import("../services/pipeline.zig").dwordCount(events) else 0;
        const ls = try ladder(events.len - dword, 1);
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
        g.cpu_fused_tail = layout.fused_tail;
        g.cpu_u8_pairs = layout.u8_pairs;
        g.cpu_compact_decode = layout.compact_decode;
        // A log-23 CPU segment (batch_steps >= 2^22) has only the wide-clock
        // encoding, which is defined on the fused tail without byte pairs.
        if (g.wideClock()) {
            g.cpu_fused_tail = true;
            g.cpu_u8_pairs = false;
            g.cpu_compact_decode = false;
        }
        d.* = .{ .geometry = g, .bridges = .{} };
        // The same two-instance ladder as LS32 (one inactive row per instance).
        if (dword != 0) {
            const dl = try ladder(dword, 1);
            d.bridges.ls_dword = dl.head;
            d.bridges.ls_dword_tail = dl.tail;
        }
        const k = captured.advice.keccak[i].len;
        const add = captured.advice.secp[i][0].len;
        const double = captured.advice.secp[i][1].len;
        if (k != 0) d.bridges.keccak = try Coverage.minimalPrefixLog(@intCast(try std.math.mul(usize, 25, k)));
        if (add != 0) d.bridges.add = try Coverage.minimalPrefixLog(@intCast(try std.math.mul(usize, A.crypto.secp256k1.word16_bridge.types.coordinates(.add), add)));
        if (double != 0) d.bridges.double = try Coverage.minimalPrefixLog(@intCast(try std.math.mul(usize, A.crypto.secp256k1.word16_bridge.types.coordinates(.double), double)));
        const sha256 = captured.advice.sha256[i].len;
        if (sha256 != 0) d.bridges.sha256 = try Coverage.minimalPrefixLog(@intCast(try std.math.mul(usize, A.crypto.secp256k1.word16_bridge.types.coordinates(.sha256), sha256)));
        const arith = captured.advice.arith256_mod[i].len;
        if (arith != 0) d.bridges.arith256_mod = try Coverage.minimalPrefixLog(@intCast(try std.math.mul(usize, A.crypto.secp256k1.word16_bridge.types.coordinates(.arith256_mod), arith)));
        // v3 curve/field families: coordinates rows per call each.
        const ST = @import("../services/types.zig");
        for (captured.advice.curves[i], ST.FIRST_CURVE..) |calls, f| if (calls.len != 0) {
            const family: ST.Family = @enumFromInt(f);
            d.bridges.set(family, try Coverage.minimalPrefixLog(@intCast(try std.math.mul(usize, A.crypto.secp256k1.word16_bridge.types.coordinates(ST.bridgeKind(family)), calls.len))));
        };
        // v3 bulk memory: one descriptor row per call, one body row per word.
        const bulk = captured.advice.bulk[i].counts();
        if (bulk.calls != 0) d.bridges.bulk.desc = try Coverage.minimalPrefixLog(bulk.calls);
        if (bulk.copy_words != 0) d.bridges.bulk.copy = try Coverage.minimalPrefixLog(bulk.copy_words);
        if (bulk.set_words != 0) d.bridges.bulk.set = try Coverage.minimalPrefixLog(bulk.set_words);
        if (bulk.jump_calls != 0) {
            d.bridges.bulk.jdesc = try Coverage.minimalPrefixLog(bulk.jump_calls);
            d.bridges.bulk.jscan = try Coverage.minimalPrefixLog(bulk.jump_rows);
            d.bridges.bulk.jtab = @import("stwo_riscv_frontend").rv64_air.crypto.bulk_memory.types.TABLE_LOG;
        }
        // Extension: unaligned copy rows, memcmp descriptors and compared words.
        if (bulk.ucopy_rows != 0) d.bridges.bulk.ucopy = try Coverage.minimalPrefixLog(bulk.ucopy_rows);
        if (bulk.cmp_calls != 0) d.bridges.bulk.cdesc = try Coverage.minimalPrefixLog(bulk.cmp_calls);
        if (bulk.cmp_words != 0) d.bridges.bulk.cmp = try Coverage.minimalPrefixLog(bulk.cmp_words);
        // v3 Keccak sponge: one call row per ECALL, one row per permutation.
        const sponge = captured.advice.sponge[i].counts();
        if (sponge.calls != 0) d.bridges.sponge.call = @max(5, try Coverage.minimalPrefixLog(sponge.calls));
        if (sponge.perms != 0) d.bridges.sponge.perm = @max(5, try Coverage.minimalPrefixLog(sponge.perms));
        try g.validate();
    }
    return out;
}
pub const KeccakPolicy = A.crypto.keccak.equations.BatchPolicy;
/// Exact committed MAIN+INTERACTION cells of one Keccak truth proof
/// (permutation at `log` plus both tables), the quantity the cost proxy counts.
pub fn keccakTruthCells(policy: KeccakPolicy, log: u32) u64 {
    const L = A.crypto.keccak.layout;
    const permutation = (@as(u64, L.MAIN) + policy.interactionCount()) << @intCast(log);
    return permutation + (@as(u64, 5) << @intCast(policy.tableLog(.chi))) + (@as(u64, 5) << @intCast(policy.tableLog(.xor5)));
}
/// v3 profile: each truth takes the throughput tables exactly when that is
/// fewer committed cells (log >= 13: 1,988 cells/row saved vs the 2^21+2^16
/// tables). v2 never selects it (receiver policy rejects it there).
pub fn keccakTruthPolicy(v3: bool, log: u32) KeccakPolicy {
    if (!v3) return .triple_v2;
    return if (keccakTruthCells(.throughput_v1, log) < keccakTruthCells(.triple_v2, log)) .throughput_v1 else .triple_v2;
}
pub fn truths(a: std.mem.Allocator, captured: *const Capture) ![]W.TruthDeclaration {
    return truthsForProfile(a, captured, false);
}
pub fn truthsForProfile(a: std.mem.Allocator, captured: *const Capture, v3: bool) ![]W.TruthDeclaration {
    return truthsWithOptions(a, captured, v3, 18);
}
/// Producer geometry experiment only; the receiver admits original call spans.
/// The default entry point remains log18. Smaller shards multiply proof leaves.
/// v2 profile (compact Keccak truth): the OM GKR route is v2-only.
pub fn truthsWithKeccakMaxLog(a: std.mem.Allocator, captured: *const Capture, max_log: u32) ![]W.TruthDeclaration {
    return truthsWithOptions(a, captured, false, max_log);
}
fn truthsForCounts(a: std.mem.Allocator, total: [3]u32, max_log: u32) ![]W.TruthDeclaration {
    var out: std.ArrayList(W.TruthDeclaration) = .{};
    errdefer out.deinit(a);
    try appendKeccakSecp(a, &out, total, max_log, false);
    return out.toOwnedSlice(a);
}
fn appendKeccakSecp(a: std.mem.Allocator, out: *std.ArrayList(W.TruthDeclaration), total: [3]u32, max_log: u32, v3: bool) !void {
    if (max_log < 16 or max_log > 18) return error.UnsupportedEthereumKeccakShardLog;
    // Keep full shard lengths even so partitioning preserves paired slots.
    const max_keccak: u32 = ((@as(u32, 1) << @intCast(max_log)) / A.crypto.keccak.layout.ROWS_PER_PAIR) * 2;
    var next: u32 = 1;
    while (next <= total[0]) {
        // Explicit u32: @min with a comptime bound narrows to u15, and the row
        // product below then wraps (latent: logs below 18 were under-sized).
        const calls: u32 = @min(max_keccak, total[0] - next + 1);
        const log: u32 = if (calls > max_keccak / 2) max_log else @intCast(std.math.log2_int_ceil(u32, @max(32, ((calls + 1) / 2) * 29)));
        try out.append(a, .{ .family = .keccak, .first_id = next, .calls = calls, .logs = .{ log, W.keccakProfileWord(keccakTruthPolicy(v3, log)) } });
        next = try std.math.add(u32, next, calls);
    }
    for (1..3) |family| {
        const kind: A.crypto.secp256k1.program.Kind = if (family == 1) .add else .double;
        const program = A.crypto.secp256k1.program.get(kind);
        next = 1;
        // v3: the row profile wherever it commits fewer cells than the RCB
        // providers for the same span (always, beyond tiny call counts).
        if (v3 and total[family] != 0) {
            const row_capacity: u32 = (@as(u32, 1) << @intCast(SecpRow.MAX_LOG)) - 1;
            var rows: std.ArrayList(W.TruthDeclaration) = .{};
            defer rows.deinit(a);
            var row_cells: u64 = 0;
            var rcb_cells: u64 = 0;
            var at: u32 = 1;
            while (at <= total[family]) {
                const calls = try secpRowSpan(kind, @min(row_capacity, total[family] - at + 1));
                const log = try SecpRow.logSize(kind, calls);
                try rows.append(a, .{ .family = @enumFromInt(family), .first_id = at, .calls = calls, .logs = .{ log, SecpRow.PROFILE_WORD } });
                row_cells += SecpRow.cells(kind, log);
                at = try std.math.add(u32, at, calls);
            }
            rcb_cells = try secpRcbCells(kind, total[family]);
            if (row_cells < rcb_cells) {
                try out.appendSlice(a, rows.items);
                continue;
            }
        }
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
}
const SecpRow = @import("../secp/row_roster.zig");
/// Calls of the next row span out of `remaining` (<= capacity): one padded
/// power of two, unless splitting at the next smaller one (head of
/// 2^(log-1) - 1 calls, its own padding row included) and covering the rest
/// separately commits at least 1/8 fewer cells. Padding only: every call is
/// still covered exactly once, in order.
pub fn secpRowSpan(kind: A.crypto.secp256k1.program.Kind, remaining: u32) !u32 {
    const log = try SecpRow.logSize(kind, remaining);
    if (log <= A.crypto.curves.layout.MIN_LOG) return remaining;
    const head: u32 = (@as(u32, 1) << @intCast(log - 1)) - 1;
    if (head >= remaining) return remaining;
    const split = SecpRow.cells(kind, log - 1) + SecpRow.cells(kind, try SecpRow.logSize(kind, remaining - head));
    return if (8 * split <= 7 * SecpRow.cells(kind, log)) head else remaining;
}
/// Committed MAIN+INTERACTION cells of the RCB product/linear/BYTE truths
/// covering `calls` (the spans the v2 planner emits).
pub fn secpRcbCells(kind: A.crypto.secp256k1.program.Kind, calls_total: u32) !u64 {
    const S = A.crypto.secp256k1;
    const program = S.program.get(kind);
    const policy = @import("../secp/roster.zig").TruthSetup.byte_policy;
    const capacity = @min(((1 << 18) - 1) / program.rows(true), ((1 << 18) - 1) / program.rows(false));
    var cells: u64 = 0;
    var at: u64 = 0;
    while (at < calls_total) {
        const calls: usize = @intCast(@min(capacity, calls_total - at));
        const lp = try S.layout.logSize(.product, program, calls);
        const ll = try S.layout.logSize(.linear, program, calls);
        cells += (@as(u64, S.layout.main(.product) + S.layout.interactionFor(.product, policy)) << @intCast(lp)) + (@as(u64, S.layout.main(.linear) + S.layout.interactionFor(.linear, policy)) << @intCast(ll)) + 9 * 256;
        at += calls;
    }
    return cells;
}
fn truthsWithOptions(a: std.mem.Allocator, captured: *const Capture, v3: bool, max_log: u32) ![]W.TruthDeclaration {
    var total: [3]u32 = @splat(0);
    for (captured.advice.keccak, captured.advice.secp) |k, s| {
        total[0] = try std.math.add(u32, total[0], @intCast(k.len));
        total[1] = try std.math.add(u32, total[1], @intCast(s[0].len));
        total[2] = try std.math.add(u32, total[2], @intCast(s[1].len));
    }
    // Keccak-sponge permutations follow the Keccak-f calls in the IO11 ID space.
    for (captured.advice.sponge) |z| total[0] = try std.math.add(u32, total[0], @intCast(z.inputs.len));
    var out: std.ArrayList(W.TruthDeclaration) = .{};
    errdefer out.deinit(a);
    try appendKeccakSecp(a, &out, total, max_log, v3);
    var next: u32 = 1;
    // SHA-256: one compression per row plus a padding row; bounded log13 spans.
    var sha256: u32 = 0;
    for (captured.advice.sha256) |calls| sha256 = try std.math.add(u32, sha256, @intCast(calls.len));
    const capacity: u32 = (@as(u32, 1) << @intCast(@import("../sha256/roster.zig").MAX_LOG)) - 1;
    next = 1;
    while (next <= sha256) {
        const calls: u32 = @min(capacity, sha256 - next + 1);
        try out.append(a, .{ .family = .sha256, .first_id = next, .calls = calls, .logs = .{ try A.crypto.sha256.layout.logSize(calls), 0 } });
        next = try std.math.add(u32, next, calls);
    }
    // arith256_mod: one call per row plus a padding row (>= 256 rows for the
    // local BYTE table); bounded log16 spans.
    var arith: u32 = 0;
    for (captured.advice.arith256_mod) |calls| arith = try std.math.add(u32, arith, @intCast(calls.len));
    const arith_capacity: u32 = (@as(u32, 1) << @intCast(@import("../arith256/roster.zig").MAX_LOG)) - 1;
    next = 1;
    while (next <= arith) {
        const calls: u32 = @min(arith_capacity, arith - next + 1);
        try out.append(a, .{ .family = .arith256_mod, .first_id = next, .calls = calls, .logs = .{ try A.crypto.arith256.layout.logSize(calls), 0 } });
        next = try std.math.add(u32, next, calls);
    }
    // Curve/field families 5..11: one call per row plus a padding row
    // (>= 256 rows for the local BYTE table); bounded log16 spans.
    const ST = @import("../services/types.zig");
    const CR = @import("../curves/roster.zig");
    const curve_capacity: u32 = (@as(u32, 1) << @intCast(CR.MAX_LOG)) - 1;
    for (0..ST.CURVES) |c| {
        var curve_total: u32 = 0;
        for (captured.advice.curves) |shard| curve_total = try std.math.add(u32, curve_total, @intCast(shard[c].len));
        const family: ST.Family = @enumFromInt(ST.FIRST_CURVE + c);
        next = 1;
        while (next <= curve_total) {
            const calls: u32 = @min(curve_capacity, curve_total - next + 1);
            try out.append(a, .{ .family = family, .first_id = next, .calls = calls, .logs = .{ try CR.logSize(ST.curveOp(family).?, calls), 0 } });
            next = try std.math.add(u32, next, calls);
        }
    }
    return out.toOwnedSlice(a);
}
test "keccak truth plan sizes prefixes below the log18 bound without u15 wrap" {
    const calls: u32 = 3934;
    const narrowed = @min(@as(u32, ((1 << 18) / 29) * 2), calls);
    _ = narrowed;
    try std.testing.expectEqual(@as(u32, 16), try A.crypto.keccak.layout.logSize(calls));
}
test "v3 keccak truth takes the throughput tables exactly where they commit fewer cells" {
    try std.testing.expectEqual(KeccakPolicy.triple_v2, keccakTruthPolicy(false, 18));
    try std.testing.expectEqual(KeccakPolicy.triple_v2, keccakTruthPolicy(true, 12));
    try std.testing.expectEqual(KeccakPolicy.throughput_v1, keccakTruthPolicy(true, 13));
    try std.testing.expectEqual(KeccakPolicy.throughput_v1, keccakTruthPolicy(true, 18));
    // log18: 2^18 x (1923 + 2596) + 5 x (2^13 + 2^10) vs 2^18 x 2531 + 5 x (2^21 + 2^16).
    try std.testing.expectEqual(@as(u64, 1_184_674_816), keccakTruthCells(.triple_v2, 18));
    try std.testing.expectEqual(@as(u64, 674_299_904), keccakTruthCells(.throughput_v1, 18));
}
test "v3 secp row spans split only where padding wastes at least 1/8 of the cells" {
    // 4-packet prefix of block 24,628,607: 1,080 ADD -> 1,023 (log 10) + 57 (log 8).
    try std.testing.expectEqual(@as(u32, 1023), try secpRowSpan(.add, 1080));
    try std.testing.expectEqual(@as(u32, 57), try secpRowSpan(.add, 57));
    // 1,001 DOUBLE fits log 10 unsplit.
    try std.testing.expectEqual(@as(u32, 1001), try secpRowSpan(.double, 1001));
    // Complete block scale: 11,496 -> 8,191 (log 13) + 3,305 (log 12, unsplit).
    try std.testing.expectEqual(@as(u32, 8191), try secpRowSpan(.add, 11496));
    try std.testing.expectEqual(@as(u32, 3305), try secpRowSpan(.add, 3305));
}
test "v3 secp truths take the row profile wherever it commits fewer cells" {
    // Real-prefix scale: fewer cells even with worst-case padding (1,200
    // calls in 2^11 rows), under half at a full power of two (1,023 calls).
    for ([_]A.crypto.secp256k1.program.Kind{ .add, .double }) |kind| {
        try std.testing.expect(SecpRow.cells(kind, try SecpRow.logSize(kind, 1200)) < try secpRcbCells(kind, 1200));
        try std.testing.expect(2 * SecpRow.cells(kind, try SecpRow.logSize(kind, 1023)) < try secpRcbCells(kind, 1023));
    }
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
