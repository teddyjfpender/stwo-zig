//! Truth-family geometry, bounded spans and service-provider selection.
//! CPU declaration planning stays in plan.zig; canonical truth records stay native.
const std = @import("std");
const A = @import("ethereum_frontend_component").rv64_air;
const W = @import("stwo_riscv_cpu_integration").rv64_execution.services.wire;
const Capture = @import("capture.zig").Owner;
const Canon = @import("stwo_riscv_cpu_integration").rv64_native_schema;

pub const KeccakPolicy = A.crypto.keccak.equations.BatchPolicy;
/// Exact committed MAIN+INTERACTION cells of one Keccak truth proof
/// (permutation at `log` plus both tables), the quantity the cost proxy counts.
pub fn keccakTruthCells(policy: KeccakPolicy, log: u32) u64 {
    const L = A.crypto.keccak.layout;
    const permutation = (@as(u64, L.MAIN) + policy.interactionCount()) << @intCast(log);
    return permutation + (@as(u64, 5) << @intCast(policy.tableLog(.chi))) + (@as(u64, 5) << @intCast(policy.tableLog(.xor5)));
}
/// v3 profile: each truth takes the throughput tables exactly when that is
/// fewer committed cells (log >= 13), batched four per degree-five batch by
/// default (`KeccakTruthOptions.quartet`). v2 never selects them (receiver
/// policy rejects them there).
pub fn keccakTruthPolicy(v3: bool, log: u32) KeccakPolicy {
    return keccakTruthPolicyFor(.{ .v3 = v3 }, log);
}
/// Producer-only Keccak truth selection. The chosen profile is published in
/// the declaration (`W.keccakProfileWord`) and mixed into the truth
/// transcript; the receiver admits any v3 profile it can rebuild.
pub const KeccakTruthOptions = struct {
    v3: bool = false,
    /// Producer geometry preference, not a new AIR or security construction.
    /// Reuse the qualified throughput family for every span on resident GPUs.
    /// The default preserves the cost-minimized mixed-policy native roster.
    uniform_throughput: bool = false,
    /// One physical truth per active family, bounded by existing source caps.
    /// May require a new canonical truth rung and more backend memory.
    one_per_family: bool = false,
    /// Coalesce non-Keccak families while keeping the bounded Keccak partition.
    coalesce_families: bool = false,
    /// M8 p-truth-split (`STWO_RV64_M8_TRUTH_SPLIT=1`, default off; coalesced
    /// plans only): a family whose single coalesced truth the profile refuses
    /// (source MAX_LOG, V3 shape, or no admissible canonical rung) is split
    /// into consecutive bounded spans instead. Families that fit keep their
    /// single truth, so every plan the profile admits today is unchanged.
    split_families: bool = false,
    /// Bound split spans by the top canonical rung of their family (set when
    /// the producer pads to rungs: strict roster or STWO_RV64_CANON_RUNGS=1).
    rung_bound: bool = false,
    /// Throughput tables cleared four per degree-five batch
    /// (`throughput_quartet_v1`, 456 instead of 608 interaction columns).
    /// v3 default since it proved and fresh-verified a real 4-packet prefix
    /// of block 24,628,607; `false` keeps `throughput_v1`.
    quartet: bool = true,
    /// Quartet batching on the 27-row slot (`throughput_r27_v1`, 480
    /// interaction columns, 27 rows per pair). Requires `quartet`. v3
    /// default since it proved and fresh-verified the real 4-packet prefix
    /// of block 24,628,607 (Keccak-f truth cells 801,177,600 -> 760,799,232).
    r27: bool = true,
    /// Shared producer resource mapping: keep every partition preference on
    /// the actual capture-to-truth path, rather than only in reporting.
    pub fn fromResources(v3: bool, uniform: bool, resources: anytype) KeccakTruthOptions {
        return .{ .v3 = v3, .uniform_throughput = uniform, .one_per_family = if (resources) |r| r.one_truth_per_family else false, .coalesce_families = if (resources) |r| r.coalesce_truth_families else false, .split_families = truthSplitEnabled(), .rung_bound = canonRungsEnabled() };
    }
    pub fn throughput(self: KeccakTruthOptions) KeccakPolicy {
        if (self.quartet and self.r27) return .throughput_r27_v1;
        return if (self.quartet) .throughput_quartet_v1 else .throughput_v1;
    }
};
pub fn envFlag(name: []const u8) bool {
    const flag = std.posix.getenv(name) orelse return false;
    return std.mem.eql(u8, flag, "1");
}
/// `STWO_RV64_M8_TRUTH_SPLIT=1` (default off): see `KeccakTruthOptions.split_families`.
pub fn truthSplitEnabled() bool {
    return envFlag("STWO_RV64_M8_TRUTH_SPLIT");
}
/// Same predicate gkr_main uses to pad declarations to canonical rungs.
pub fn canonRungsEnabled() bool {
    return @import("stwo_riscv_cpu_integration").rv64_native_policy.strictRoster();
}
pub fn keccakTruthPolicyFor(options: KeccakTruthOptions, log: u32) KeccakPolicy {
    if (!options.v3) return .triple_v2;
    const throughput = options.throughput();
    return if (options.uniform_throughput or keccakTruthCells(throughput, log) < keccakTruthCells(.triple_v2, log)) throughput else .triple_v2;
}
/// Smallest log holding `calls` permutations in `geometry` (>= 5).
pub fn keccakLogFor(geometry: A.crypto.keccak.layout.Geometry, calls: u32) u32 {
    return @intCast(std.math.log2_int_ceil(u32, @max(32, ((calls + 1) / 2) * @as(u32, @intCast(geometry.rowsPerPair())))));
}
pub fn truths(a: std.mem.Allocator, captured: *const Capture) ![]W.TruthDeclaration {
    return truthsForProfile(a, captured, false);
}
pub fn truthsForProfile(a: std.mem.Allocator, captured: *const Capture, v3: bool) ![]W.TruthDeclaration {
    return truthsWithOptions(a, captured, .{ .v3 = v3 }, 18);
}
pub fn truthsForKeccakOptions(a: std.mem.Allocator, captured: *const Capture, options: KeccakTruthOptions) ![]W.TruthDeclaration {
    return truthsWithOptions(a, captured, options, 18);
}
/// Producer geometry experiment only; the receiver admits original call spans.
/// The default entry point remains log18. Smaller shards multiply proof leaves.
/// v2 profile (compact Keccak truth): the OM GKR route is v2-only.
pub fn truthsWithKeccakMaxLog(a: std.mem.Allocator, captured: *const Capture, max_log: u32) ![]W.TruthDeclaration {
    return truthsWithOptions(a, captured, .{}, max_log);
}
pub fn truthsForCounts(a: std.mem.Allocator, total: [3]u32, max_log: u32) ![]W.TruthDeclaration {
    var out: std.ArrayList(W.TruthDeclaration) = .{};
    errdefer out.deinit(a);
    try appendKeccakSecp(a, &out, total, max_log, .{});
    return out.toOwnedSlice(a);
}
/// One planned Keccak truth span: `calls` IDs in one proof of `log` rows.
pub const KeccakPiece = struct { calls: u32, log: u32, policy: KeccakPolicy };
pub const KeccakSplit = struct { pieces: [3]KeccakPiece = undefined, len: usize = 0, cells: u64 = std.math.maxInt(u64) };
/// Calls of a full `log` truth in `geometry` (whole pairs).
pub fn keccakCapacity(geometry: A.crypto.keccak.layout.Geometry, log: u32) u32 {
    return @intCast(((@as(usize, 1) << @intCast(log)) / geometry.rowsPerPair()) * 2);
}
/// v3: the cheapest single truth for `calls` (throughput profile in its slot
/// geometry, or the compact truth in 29-row slots), bounded by `max_log`.
pub fn keccakSingle(options: KeccakTruthOptions, calls: u32, max_log: u32) ?KeccakPiece {
    const throughput = options.throughput();
    const tlog = keccakLogFor(throughput.geometry(), calls);
    const clog = keccakLogFor(.pair29, calls);
    var best: ?KeccakPiece = null;
    if (tlog <= max_log) best = .{ .calls = calls, .log = tlog, .policy = throughput };
    if (!options.uniform_throughput and clog <= max_log and (best == null or keccakTruthCells(.triple_v2, clog) <= keccakTruthCells(throughput, tlog))) best = .{ .calls = calls, .log = clog, .policy = .triple_v2 };
    return best;
}
/// v3 truth sizing of a remainder of at most one full shard: the cheapest
/// split into at most `depth` spans (each but the last a full throughput
/// truth of some log >= 13), counting every proof's tables. Committed cells
/// only; receivers admit any contiguous span roster.
pub fn keccakBestSplit(options: KeccakTruthOptions, calls: u32, max_log: u32, depth: usize) KeccakSplit {
    var best = KeccakSplit{};
    if (keccakSingle(options, calls, max_log)) |piece| {
        best.pieces[0] = piece;
        best.len = 1;
        best.cells = keccakTruthCells(piece.policy, piece.log);
    }
    if (depth <= 1) return best;
    const throughput = options.throughput();
    var log: u32 = 13;
    while (log <= max_log) : (log += 1) {
        const capacity = keccakCapacity(throughput.geometry(), log);
        if (capacity == 0 or capacity >= calls) break;
        const rest = keccakBestSplit(options, calls - capacity, max_log, depth - 1);
        if (rest.len == 0) continue;
        const cells = keccakTruthCells(throughput, log) + rest.cells;
        if (cells < best.cells) {
            best.cells = cells;
            best.pieces[0] = .{ .calls = capacity, .log = log, .policy = throughput };
            @memcpy(best.pieces[1..][0..rest.len], rest.pieces[0..rest.len]);
            best.len = 1 + rest.len;
        }
    }
    return best;
}
pub fn appendKeccakSecp(a: std.mem.Allocator, out: *std.ArrayList(W.TruthDeclaration), total: [3]u32, max_log: u32, options: KeccakTruthOptions) !void {
    if (max_log < 16 or max_log > 18) return error.UnsupportedEthereumKeccakShardLog;
    if (options.v3) return appendKeccakV3(a, out, total, max_log, options);
    // Keep full shard lengths even so partitioning preserves paired slots.
    const max_keccak: u32 = ((@as(u32, 1) << @intCast(max_log)) / A.crypto.keccak.layout.ROWS_PER_PAIR) * 2;
    var next: u32 = 1;
    while (next <= total[0]) {
        // Explicit u32: @min with a comptime bound narrows to u15, and the row
        // product below then wraps (latent: logs below 18 were under-sized).
        const calls: u32 = @min(max_keccak, total[0] - next + 1);
        const log: u32 = if (calls > max_keccak / 2) max_log else @intCast(std.math.log2_int_ceil(u32, @max(32, ((calls + 1) / 2) * 29)));
        try out.append(a, .{ .family = .keccak, .first_id = next, .calls = calls, .logs = .{ log, W.keccakProfileWord(keccakTruthPolicyFor(options, log)) } });
        next = try std.math.add(u32, next, calls);
    }
    try appendSecp(a, out, total, options.v3);
}
/// v3 Keccak truths: full shards of the throughput profile's slot geometry,
/// then the cheapest split of the remainder (`keccakBestSplit`).
pub fn appendKeccakV3(a: std.mem.Allocator, out: *std.ArrayList(W.TruthDeclaration), total: [3]u32, max_log: u32, options: KeccakTruthOptions) !void {
    // Keep full shard lengths even so partitioning preserves paired slots.
    const throughput = options.throughput();
    const max_keccak = keccakCapacity(throughput.geometry(), max_log);
    var next: u32 = 1;
    while (next <= total[0]) {
        const remaining = total[0] - next + 1;
        if (remaining > max_keccak) {
            try out.append(a, .{ .family = .keccak, .first_id = next, .calls = max_keccak, .logs = .{ max_log, W.keccakProfileWord(keccakTruthPolicyFor(options, max_log)) } });
            next = try std.math.add(u32, next, max_keccak);
            continue;
        }
        const split = keccakBestSplit(options, remaining, max_log, 3);
        if (split.len == 0) return error.EthereumTruthCapacityExceeded;
        for (split.pieces[0..split.len]) |piece| {
            try A.crypto.keccak.layout.validateGeometryFor(piece.policy.geometry(), piece.calls, next, piece.log);
            try out.append(a, .{ .family = .keccak, .first_id = next, .calls = piece.calls, .logs = .{ piece.log, W.keccakProfileWord(piece.policy) } });
            next = try std.math.add(u32, next, piece.calls);
        }
    }
    try appendSecp(a, out, total, options.v3);
}
pub fn appendSecp(a: std.mem.Allocator, out: *std.ArrayList(W.TruthDeclaration), total: [3]u32, v3: bool) !void {
    for (1..3) |family| {
        const kind: A.crypto.secp256k1.program.Kind = if (family == 1) .add else .double;
        const program = A.crypto.secp256k1.program.get(kind);
        var next: u32 = 1;
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
pub const SecpRow = @import("stwo_riscv_cpu_integration").rv64_execution.services.secp.row_roster;
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
    const policy = @import("stwo_riscv_cpu_integration").rv64_execution.services.secp.roster.TruthSetup.byte_policy;
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
pub fn truthsWithOptions(a: std.mem.Allocator, captured: *const Capture, options: KeccakTruthOptions, max_log: u32) ![]W.TruthDeclaration {
    if (options.one_per_family and options.coalesce_families) return error.ConflictingTruthFamilyPlans;
    if (options.one_per_family or options.coalesce_families) {
        const ST = @import("stwo_riscv_cpu_integration").rv64_services_types;
        var total: [ST.FAMILIES]u32 = @splat(0);
        for (captured.advice.keccak, captured.advice.secp, captured.advice.sha256, captured.advice.arith256_mod, captured.advice.curves, captured.advice.sponge) |keccak, secp, sha256, arith, curves, sponge| {
            total[0] = try std.math.add(u32, total[0], try std.math.add(u32, @intCast(keccak.len), @intCast(sponge.inputs.len)));
            total[1] = try std.math.add(u32, total[1], @intCast(secp[0].len));
            total[2] = try std.math.add(u32, total[2], @intCast(secp[1].len));
            total[3] = try std.math.add(u32, total[3], @intCast(sha256.len));
            total[4] = try std.math.add(u32, total[4], @intCast(arith.len));
            for (curves, 0..) |calls, index| total[ST.FIRST_CURVE + index] = try std.math.add(u32, total[ST.FIRST_CURVE + index], @intCast(calls.len));
        }
        return if (options.one_per_family) oneTruthPerFamily(a, total, options) else coalesceTruthFamilies(a, total, options, max_log);
    }

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
    try appendKeccakSecp(a, &out, total, max_log, options);
    var next: u32 = 1;
    // SHA-256: one compression per row plus a padding row; bounded log13 spans.
    var sha256: u32 = 0;
    for (captured.advice.sha256) |calls| sha256 = try std.math.add(u32, sha256, @intCast(calls.len));
    const capacity: u32 = (@as(u32, 1) << @intCast(@import("stwo_riscv_cpu_integration").rv64_execution.services.sha256.roster.MAX_LOG)) - 1;
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
    const arith_capacity: u32 = (@as(u32, 1) << @intCast(@import("stwo_riscv_cpu_integration").rv64_execution.services.arith256.roster.MAX_LOG)) - 1;
    next = 1;
    while (next <= arith) {
        const calls: u32 = @min(arith_capacity, arith - next + 1);
        try out.append(a, .{ .family = .arith256_mod, .first_id = next, .calls = calls, .logs = .{ try A.crypto.arith256.layout.logSize(calls), 0 } });
        next = try std.math.add(u32, next, calls);
    }
    // Curve/field families 5..11: one call per row plus a padding row
    // (>= 256 rows for the local BYTE table); bounded log16 spans.
    const ST = @import("stwo_riscv_cpu_integration").rv64_services_types;
    const CR = @import("stwo_riscv_cpu_integration").rv64_execution.services.curves.roster;
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
/// Producer geometry only: complete family spans start at1. Existing source
/// receiver admission is applied before returning; capacity failure never
/// silently restores a split roster. CPU geometry/authority is unchanged.
pub fn oneTruthPerFamily(a: std.mem.Allocator, total: [@import("stwo_riscv_cpu_integration").rv64_services_types.FAMILIES]u32, options: KeccakTruthOptions) ![]W.TruthDeclaration {
    if (!options.v3) return error.OneTruthPerFamilyRequiresV3;
    const ST = @import("stwo_riscv_cpu_integration").rv64_services_types;
    var out: std.ArrayList(W.TruthDeclaration) = .empty;
    errdefer out.deinit(a);
    for (std.enums.values(ST.Family), total) |family, calls| {
        if (calls == 0) continue;
        const logs: [2]u32 = switch (family) {
            .keccak => block: {
                if (calls > keccakCapacity(options.throughput().geometry(), 22)) return error.OneTruthPerFamilySourceCapacity;
                const piece = keccakSingle(options, calls, 22) orelse return error.OneTruthPerFamilySourceCapacity;
                break :block .{ piece.log, W.keccakProfileWord(piece.policy) };
            },
            else => try nonKeccakLogs(family, calls),
        };
        const declaration = W.TruthDeclaration{ .family = family, .first_id = 1, .calls = calls, .logs = logs };
        try @import("stwo_riscv_cpu_integration").rv64_execution.services.scope.truthDeclaration(declaration);
        try out.append(a, declaration);
    }
    return out.toOwnedSlice(a);
}
/// Wire logs of one non-Keccak V3 truth over `calls` (the single-truth sizing
/// of `oneTruthPerFamily`; source caps return OneTruthPerFamilySourceCapacity).
pub fn nonKeccakLogs(family: @import("stwo_riscv_cpu_integration").rv64_services_types.Family, calls: u32) ![2]u32 {
    const ST = @import("stwo_riscv_cpu_integration").rv64_services_types;
    return switch (family) {
        .keccak => error.NotV3Truth,
        .add, .double => .{ try SecpRow.logSize(if (family == .add) .add else .double, calls), SecpRow.PROFILE_WORD },
        .sha256 => block: {
            const log = try A.crypto.sha256.layout.logSize(calls);
            if (log > @import("stwo_riscv_cpu_integration").rv64_execution.services.sha256.roster.MAX_LOG) return error.OneTruthPerFamilySourceCapacity;
            break :block .{ log, 0 };
        },
        .arith256_mod => block: {
            const log = try A.crypto.arith256.layout.logSize(calls);
            if (log > @import("stwo_riscv_cpu_integration").rv64_execution.services.arith256.roster.MAX_LOG) return error.OneTruthPerFamilySourceCapacity;
            break :block .{ log, 0 };
        },
        else => .{ try @import("stwo_riscv_cpu_integration").rv64_execution.services.curves.roster.logSize(ST.curveOp(family).?, calls), 0 },
    };
}
/// Source cap (roster MAX_LOG) of one V3 truth of `family`.
pub fn sourceMaxLog(family: @import("stwo_riscv_cpu_integration").rv64_services_types.Family) u32 {
    return switch (family) {
        .keccak => 22,
        .sha256 => @import("stwo_riscv_cpu_integration").rv64_execution.services.sha256.roster.MAX_LOG,
        .arith256_mod => @import("stwo_riscv_cpu_integration").rv64_execution.services.arith256.roster.MAX_LOG,
        .add, .double => SecpRow.MAX_LOG,
        else => @import("stwo_riscv_cpu_integration").rv64_execution.services.curves.roster.MAX_LOG,
    };
}
/// Top canonical rung log of `family` with wire aux `aux` (null: no entry).
pub fn topRungLog(table: anytype, family: @import("stwo_riscv_cpu_integration").rv64_services_types.Family, aux: u32) ?u32 {
    const canon = Canon.Family.truth(family);
    for (table.TRUTH) |e| {
        if (e.family == canon and e.aux == aux) return e.logs[e.logs.len - 1];
    }
    return null;
}
/// The single coalesced truth of `family`, or null where the D2 profile
/// refuses it: source capacity, V3 shape/geometry, or (rung_bound) no
/// admissible canonical rung. The returned declaration is exactly the one
/// `oneTruthPerFamily` emits.
pub fn admittedSingle(family: @import("stwo_riscv_cpu_integration").rv64_services_types.Family, calls: u32, rung_bound: bool) ?W.TruthDeclaration {
    const logs = nonKeccakLogs(family, calls) catch return null;
    const declaration = W.TruthDeclaration{ .family = family, .first_id = 1, .calls = calls, .logs = logs };
    @import("stwo_riscv_cpu_integration").rv64_execution.services.scope.truthDeclaration(declaration) catch return null;
    if (rung_bound) {
        const top = topRungLog(@import("stwo_riscv_cpu_integration").rv64_native_rungs, family, logs[1]) orelse return null;
        if (logs[0] > top) return null;
    }
    return declaration;
}
/// Consecutive spans of `family` covering IDs 1..calls in order: full spans of
/// 2^cap - 1 calls (one padding row each; cap = source MAX_LOG, also bounded
/// by the family's top canonical rung when `rung_bound`), then the remainder
/// at its own smallest log. Each span is an ordinary admitted V3 geometry
/// (validated by the same `truthDeclaration` the single truth passes).
pub fn appendSplitFamily(a: std.mem.Allocator, out: *std.ArrayList(W.TruthDeclaration), family: @import("stwo_riscv_cpu_integration").rv64_services_types.Family, calls: u32, rung_bound: bool) !void {
    var cap = sourceMaxLog(family);
    if (rung_bound) {
        // Every non-Keccak V3 truth has wire aux 0.
        const top = topRungLog(@import("stwo_riscv_cpu_integration").rv64_native_rungs, family, 0) orelse return error.CanonFamilyMissing;
        cap = @min(cap, top);
    }
    const capacity: u32 = (@as(u32, 1) << @intCast(cap)) - 1;
    var next: u32 = 1;
    var left = calls;
    while (left > 0) {
        const span = @min(capacity, left);
        const logs = try nonKeccakLogs(family, span);
        const declaration = W.TruthDeclaration{ .family = family, .first_id = next, .calls = span, .logs = logs };
        try @import("stwo_riscv_cpu_integration").rv64_execution.services.scope.truthDeclaration(declaration);
        try out.append(a, declaration);
        next = try std.math.add(u32, next, span);
        left -= span;
    }
}
/// Preserve Keccak's admitted bounded shards; combine each other family into
/// one physical proof. This explicit partial plan does not claim one Keccak proof.
pub fn coalesceTruthFamilies(a: std.mem.Allocator, total: [@import("stwo_riscv_cpu_integration").rv64_services_types.FAMILIES]u32, options: KeccakTruthOptions, max_log: u32) ![]W.TruthDeclaration {
    if (!options.v3) return error.OneTruthPerFamilyRequiresV3;
    var out: std.ArrayList(W.TruthDeclaration) = .empty;
    errdefer out.deinit(a);
    try appendKeccakSecp(a, &out, .{ total[0], 0, 0 }, max_log, options);
    if (options.split_families) {
        // Per family, in family order (the receiver's span order): the single
        // admitted truth where the profile plans it today, bounded spans only
        // where it refuses.
        const ST = @import("stwo_riscv_cpu_integration").rv64_services_types;
        for (std.enums.values(ST.Family)[1..], total[1..]) |family, calls| {
            if (calls == 0) continue;
            if (admittedSingle(family, calls, options.rung_bound)) |declaration| {
                try out.append(a, declaration);
            } else try appendSplitFamily(a, &out, family, calls, options.rung_bound);
        }
        return out.toOwnedSlice(a);
    }
    var remainder = total;
    remainder[0] = 0;
    const rest = try oneTruthPerFamily(a, remainder, options);
    defer a.free(rest);
    try out.appendSlice(a, rest);
    return out.toOwnedSlice(a);
}
