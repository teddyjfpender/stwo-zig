//! CPU geometry from ordered capture counts. Shared by complete inventories
//! and early segment/shard admission; no security parameters are selected here.
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
    /// Candidate source admission requires arithmetic request counts strictly
    /// below capacity. Reserve a padding row when a fact table is exactly full.
    /// Operational geometry only; receiver bounds and security stay unchanged.
    reserve_arithmetic_row: bool = false,
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
    /// MUL byte pairs served by the AND pair column (requires u8_pairs).
    mul_u8_pairs: bool = false,
    /// LS32 fused tail + byte pairs, INIT/TEARDOWN fused single (requires u8_pairs).
    ls_fused_pairs: bool = false,
    /// ALU fused tail (head and tail instances).
    alu_fused_tail: bool = false,
    /// LS-D64 fused tail + byte pair (requires u8_pairs and ls_dword).
    ls_dword_fused_pairs: bool = false,
    /// Default layout for a profile route. Only the admitted v3 routes
    /// (`ethereum_services_v3` and its Zbb variant `ethereum_services_v3_zbb`)
    /// default to the fused tail, byte pairs,
    /// LS-D64 and the fused2 component layouts (MUL pairs, LS32/INIT/TEARDOWN
    /// fused pairs, ALU fused tail, LS-D64 fused pairs) and compact decode (all proved and freshly
    /// verified on a real 4-packet prefix of block 24,628,607); every older
    /// route keeps its historical layout and bundle bytes.
    /// GKR replaces classic interaction encodings. Keep its qualified query
    /// representation explicit instead of inheriting new classic defaults.
    pub fn forGkrProfile(profile: @import("stwo_riscv_frontend").rv64.execution_profile.Profile) CpuLayout {
        const v3 = profile == .ethereum_services_v3;
        // Compact decode has GKR-local CPU/ROM projections (gkr_local/fractions.zig
        // cpuCompactFor, main_only `.cpu_compact`): 37 instead of 47 CPU MAIN columns.
        return .{ .fused_tail = v3, .u8_pairs = v3, .ls_dword = v3, .compact_decode = v3 };
    }
    pub fn forProfile(profile: @import("stwo_riscv_frontend").rv64.execution_profile.Profile) CpuLayout {
        const v3 = @import("stwo_riscv_frontend").rv64.execution_profile.isV3(profile);
        // Compact decode is proven with the RV64IM opcode set only; the Zbb
        // profile keeps the classic decode MAIN until compact decode admits Zbb.
        return .{ .fused_tail = v3, .u8_pairs = v3, .ls_dword = v3, .mul_u8_pairs = v3, .ls_fused_pairs = v3, .alu_fused_tail = v3, .ls_dword_fused_pairs = v3, .compact_decode = profile == .ethereum_services_v3 };
    }
};
/// One source-derived class declaration. Whole-inventory planning and early
/// local class admission share this exact geometry/census authority. The RAM
/// INITIAL count must be the complete first-pass/collector set, never a guess.
pub fn cpuForSegment(n: *const @import("../../word16_execution/prepared.zig").Prepared, advice: *const @import("../services/collector.zig").Advice, ordinal: usize, total_segments: usize, initial_count: usize, layout: CpuLayout) !W.CpuDeclaration {
    return cpuForSegmentAt(n, advice, ordinal, ordinal, total_segments, initial_count, layout);
}
/// The same source class from one already ordered ledger shard, before the
/// complete Advice inventory exists. Only the global boundary ordinal differs.
pub fn cpuForShard(n: *const @import("../../word16_execution/prepared.zig").Prepared, shard: @import("../services/collector.zig").Shard, ordinal: usize, total_segments: usize, initial_count: usize, layout: CpuLayout) !W.CpuDeclaration {
    const Collector = @import("../services/collector.zig");
    var view = Collector.OneShardView.init(shard);
    var advice = view.advice(n.allocator, &.{}, &.{});
    return cpuForSegmentAt(n, &advice, 0, ordinal, total_segments, initial_count, layout);
}
fn cpuForSegmentAt(n: *const @import("../../word16_execution/prepared.zig").Prepared, advice: *const @import("../services/collector.zig").Advice, advice_index: usize, ordinal: usize, total_segments: usize, initial_count: usize, layout: CpuLayout) !W.CpuDeclaration {
    if (total_segments == 0 or ordinal >= total_segments or advice_index >= advice.events.len) return error.CanonRosterMismatch;
    const boundary = try Coverage.minimalBoundaryLog(@intCast(initial_count));
    var result: W.CpuDeclaration = undefined;
    const d = &result;
    var g = n.geometryOmittingEmptyDivision() catch |err| {
        std.debug.print("RV64_PLAN_CAPACITY cpu_ordinal={d} memory={d} unique_words={d} alu={d} binary={d} shift={d} mul={d} div={d}\n", .{ ordinal, n.raw_counts.memory, n.unique_memory_words, n.alu.facts.len, n.binary.facts.len, n.shift.len, n.multiplication.len, n.division.len });
        return err;
    };
    if (layout.reserve_arithmetic_row) {
        if (n.division.len != 0) g.division_log = try Coverage.minimalPrefixLog(@intCast(n.division.len));
        if (n.multiplication.len != 0) g.multiplication_log = try Coverage.minimalMultiplicationLog(@intCast(try std.math.add(usize, n.multiplication.len, 1)));
    }
    const events = advice.events[advice_index];
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
    g.initial_log = if (ordinal == 0) boundary else 5;
    g.terminal_log = if (ordinal + 1 == total_segments) boundary else 5;
    g.cpu_fused_tail = layout.fused_tail;
    g.cpu_u8_pairs = layout.u8_pairs;
    g.cpu_compact_decode = layout.compact_decode;
    g.mul_u8_pairs = layout.mul_u8_pairs;
    g.ls_fused_pairs = layout.ls_fused_pairs;
    g.alu_fused_tail = layout.alu_fused_tail;
    g.ls_dword_fused_pairs = layout.ls_dword_fused_pairs;
    // A log-23 CPU segment (batch_steps >= 2^22) has only the wide-clock
    // encoding, which is defined on the fused tail without byte pairs; the
    // component pair layouts need the CPU pair column, so they go too.
    if (g.wideClock()) {
        g.cpu_fused_tail = true;
        g.cpu_u8_pairs = false;
        g.cpu_compact_decode = false;
        g.mul_u8_pairs = false;
        g.ls_fused_pairs = false;
        g.ls_dword_fused_pairs = false;
    }
    d.* = .{ .geometry = g, .bridges = .{} };
    // The same two-instance ladder as LS32 (one inactive row per instance).
    if (dword != 0) {
        const dl = try ladder(dword, 1);
        d.bridges.ls_dword = dl.head;
        d.bridges.ls_dword_tail = dl.tail;
    }
    const k = advice.keccak[advice_index].len;
    const add = advice.secp[advice_index][0].len;
    const double = advice.secp[advice_index][1].len;
    if (k != 0) d.bridges.keccak = try Coverage.minimalPrefixLog(@intCast(try std.math.mul(usize, 25, k)));
    if (add != 0) d.bridges.add = try Coverage.minimalPrefixLog(@intCast(try std.math.mul(usize, A.crypto.secp256k1.word16_bridge.types.coordinates(.add), add)));
    if (double != 0) d.bridges.double = try Coverage.minimalPrefixLog(@intCast(try std.math.mul(usize, A.crypto.secp256k1.word16_bridge.types.coordinates(.double), double)));
    const sha256 = advice.sha256[advice_index].len;
    if (sha256 != 0) d.bridges.sha256 = try Coverage.minimalPrefixLog(@intCast(try std.math.mul(usize, A.crypto.secp256k1.word16_bridge.types.coordinates(.sha256), sha256)));
    const arith = advice.arith256_mod[advice_index].len;
    if (arith != 0) d.bridges.arith256_mod = try Coverage.minimalPrefixLog(@intCast(try std.math.mul(usize, A.crypto.secp256k1.word16_bridge.types.coordinates(.arith256_mod), arith)));
    // v3 curve/field families: coordinates rows per call each.
    const ST = @import("../services/types.zig");
    for (advice.curves[advice_index], ST.FIRST_CURVE..) |calls, f| if (calls.len != 0) {
        const family: ST.Family = @enumFromInt(f);
        d.bridges.set(family, try Coverage.minimalPrefixLog(@intCast(try std.math.mul(usize, A.crypto.secp256k1.word16_bridge.types.coordinates(ST.bridgeKind(family)), calls.len))));
    };
    // v3 bulk memory: one descriptor row per call, one body row per word.
    const bulk = advice.bulk[advice_index].counts();
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
    const sponge = advice.sponge[advice_index].counts();
    if (sponge.calls != 0) d.bridges.sponge.call = @max(5, try Coverage.minimalPrefixLog(sponge.calls));
    if (sponge.perms != 0) d.bridges.sponge.perm = @max(5, try Coverage.minimalPrefixLog(sponge.perms));
    // v3_zbb: one Zbb BINARY row per distinct Zbb FUNCTION fact (pure
    // truth provider, every row may be active), only when the shard has one.
    if (n.zbb.facts.len != 0) d.bridges.zbb = try Coverage.minimalLog(@intCast(n.zbb.facts.len));
    try g.validate();
    return result;
}
pub fn cpus(a: std.mem.Allocator, captured: *const Capture, layout: CpuLayout) ![]W.CpuDeclaration {
    const out = try a.alloc(W.CpuDeclaration, captured.native.items.len);
    errdefer a.free(out);
    for (captured.native.items, out, 0..) |n, *d, i| d.* = try cpuForSegment(n, &captured.advice, i, out.len, captured.advice.initial.len, layout);
    return out;
}
