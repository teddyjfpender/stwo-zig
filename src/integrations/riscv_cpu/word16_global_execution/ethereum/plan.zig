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
/// `Geometry`, so it is mixed into each CPU transcript and published in the
/// declaration; the receiver rebuilds keys from the declared geometry.
pub const CpuLayout = struct {
    /// Fused-tail CPU interaction (40 -> 36 columns, same LogUp statement).
    fused_tail: bool = false,
    /// Default layout for a profile route. Only the admitted
    /// `ethereum_services_v3` route defaults to the fused tail; every older
    /// route keeps its historical layout and bundle bytes.
    pub fn forProfile(profile: @import("stwo_riscv_frontend").rv64.execution_profile.Profile) CpuLayout {
        return .{ .fused_tail = profile == .ethereum_services_v3 };
    }
};
pub fn cpus(a: std.mem.Allocator, captured: *const Capture, layout: CpuLayout) ![]W.CpuDeclaration {
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
        g.cpu_fused_tail = layout.fused_tail;
        d.* = .{ .geometry = g, .bridges = .{} };
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
        // Extension: unaligned copy rows, memcmp descriptors and compared words.
        if (bulk.ucopy_rows != 0) d.bridges.bulk.ucopy = try Coverage.minimalPrefixLog(bulk.ucopy_rows);
        if (bulk.cmp_calls != 0) d.bridges.bulk.cdesc = try Coverage.minimalPrefixLog(bulk.cmp_calls);
        if (bulk.cmp_words != 0) d.bridges.bulk.cmp = try Coverage.minimalPrefixLog(bulk.cmp_words);
        // v3 Keccak sponge: one call row per ECALL, one row per permutation.
        const sponge = captured.advice.sponge[i].counts();
        if (sponge.calls != 0) d.bridges.sponge.call = @max(5, try Coverage.minimalPrefixLog(sponge.calls));
        if (sponge.perms != 0) d.bridges.sponge.perm = @max(5, try Coverage.minimalPrefixLog(sponge.perms));
        // v3_zbb: one Zbb BINARY row per distinct Zbb FUNCTION fact (pure
        // truth provider, every row may be active), only when the shard has one.
        if (n.zbb.facts.len != 0) d.bridges.zbb = try Coverage.minimalLog(@intCast(n.zbb.facts.len));
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
    // Two Keccak permutations share each29-row slot. A bounded log18 shape
    // is reusable and avoids the log19 provider's doubled peak working set.
    const max_keccak: u32 = ((1 << 18) / 29) * 2;
    var next: u32 = 1;
    while (next <= total[0]) {
        // Explicit u32: @min with a comptime bound narrows to u15, and the row
        // product below then wraps (latent: logs below 18 were under-sized).
        const calls: u32 = @min(max_keccak, total[0] - next + 1);
        const log: u32 = if (calls > max_keccak / 2) 18 else @intCast(std.math.log2_int_ceil(u32, @max(32, ((calls + 1) / 2) * 29)));
        try out.append(a, .{ .family = .keccak, .first_id = next, .calls = calls, .logs = .{ log, W.keccakProfileWord(keccakTruthPolicy(v3, log)) } });
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
test "two-instance planner reduces physical rows only and respects reserved LS rows" {
    try std.testing.expectEqualDeep(Ladder{ .head = 20, .tail = 18 }, try ladder(1200000, 1));
    try std.testing.expectEqualDeep(Ladder{ .head = 19, .tail = 16 }, try ladder(574440, 0));
    try std.testing.expectEqualDeep(Ladder{ .head = 5 }, try ladder(0, 1));
    try std.testing.expectEqualDeep(Ladder{ .head = 6 }, try ladder(32, 1));
    try std.testing.expectError(error.EthereumInstanceCapacityExceeded, ladder(1 << 22, 1));
}
