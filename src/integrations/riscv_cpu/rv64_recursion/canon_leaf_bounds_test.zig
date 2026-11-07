//! M9 canon-leaf review: the receiver's source-bounds preflight on PADDED (catalog) declarations.
//!
//! `gkr_local/execution.zig` runs `source_bounds.derive` on the declarations it is handed, so under
//! STWO_RV64_M9_CANON_LEAF=on the padded rung geometry must pass the same receiver gates as today's exact geometry:
//! - per CPU proof, every relation's unit masses < p (`Bound.validate`, CandidateCharacteristicBoundExceeded);
//!   unit masses are charged on FULL physical rows, so padding raises them;
//! - every non-boundary component log <= MAX_TRACE_LOG (22), initial/terminal <= 23 (`includeRole`);
//! - local-GKR instances per proof <= MAX_LOCAL_INSTANCES (strict presence adds instances);
//! - the block's lookup-only conditional degree budget at 128 bits (`requireLookupOnlyBits`): the tuple-collision term
//!   is quadratic in padded denominator slots.
//! This mirrors the CPU half of `derive` (the request-count checks are omitted: padding only relaxes them, and
//! presence is one-sided). Truth scopes are left out of the block budget; the test reports the CPU-only margin.
const std = @import("std");
const testing = std.testing;
const L = @import("canon_leaf.zig");
const Canon = @import("../word16_global_execution/ethereum/canon_native.zig");
const W = @import("../word16_global_execution/services/wire.zig");
const T = @import("../word16_global_execution/services/types.zig");
const B = @import("../word16_global_execution/services/gkr_local/source_bounds.zig");
const Frame = @import("../word16_global_execution/services/gkr_local/frame.zig");
const Meta = @import("../word16_global_execution/services/gkr_local/shape_metadata.zig");
const Geometry = @import("../word16_execution/geometry.zig");
const Policy = @import("../word16_execution/om31_security_candidate.zig");
const Manifest = @import("../word16_global_execution/services/gkr_local/manifest.zig");
/// Global namespace tuple arities, as source_bounds.derive (ram, kio, wire).
const GLOBAL_ARITIES = [_]usize{
    @typeInfo(@FieldType(@FieldType(Manifest.Shared, "ram"), "coefficients")).array.len,
    @typeInfo(@FieldType(@FieldType(Manifest.Shared, "kio"), "coefficients")).array.len,
    @typeInfo(@FieldType(@FieldType(Manifest.Shared, "wire"), "coefficients")).array.len,
};

const Truth = struct { family: T.Family, logs: [2]u32 };
const Block = struct { block: u64, cpus: []W.CpuDeclaration, truths: []Truth };
const Basket = struct { schema: []const u8, blocks: []Block };
/// [E] ROM log used for the review (the image's program.log_size); it is identical for exact and padded declarations.
const PROGRAM_LOG: u32 = 16;

const Proof = struct { max_unit_mass: u64 = 0, max_log: u32 = 0, instances: usize = 0 };

fn role(scope: *B.CpuScope, slots: *[3]u64, p: *Proof, origin: Frame.Origin, log: u32, pairs: bool) !void {
    const boundary = origin == .core and (origin.core == .initial or origin.core == .terminal);
    if (!boundary) p.max_log = @max(p.max_log, log);
    if ((try Meta.forOrigin(origin)).local_terms != 0 or (origin == .core and pairs and (origin.core == .cpu or origin.core == .and_table))) p.instances += 1;
    try B.addCpuRoleMode(scope, origin, log, pairs);
    try B.globalSlots(slots, origin, log);
}

/// CPU half of source_bounds.derive for one declaration; adds its relations to `degrees`.
fn cpuProof(d: W.CpuDeclaration, degrees: *B.ConditionalDegrees, slots: *[3]u64) !Proof {
    var p = Proof{};
    var scope = B.emptyCpu();
    for (Geometry.shapesForProgramLog(PROGRAM_LOG, d.geometry)) |part| {
        if (!part.present()) continue;
        try role(&scope, slots, &p, .{ .core = part.role }, part.log, d.geometry.cpu_u8_pairs);
    }
    for (std.enums.values(T.Family)) |family| if (d.bridges.at(family)) |log| try role(&scope, slots, &p, .{ .bridge = family }, log, false);
    inline for (T.bulk_kinds) |kind| if (d.bridges.bulk.at(kind)) |log| try role(&scope, slots, &p, .{ .bulk = kind }, log, false);
    for (T.sponge_kinds) |kind| if (d.bridges.sponge.at(kind)) |log| try role(&scope, slots, &p, .{ .sponge = kind }, log, false);
    for (0..T.DWORD_INSTANCES) |i| if (d.bridges.dwordLog(i)) |log| try role(&scope, slots, &p, .{ .dword = @intCast(i) }, log, false);
    for (scope.relations) |bound| {
        p.max_unit_mass = @max(p.max_unit_mass, bound.unit_consumer_mass, bound.unit_positive_mass, bound.unit_negative_mass);
        try degrees.add(bound);
    }
    p.max_unit_mass = @max(p.max_unit_mass, scope.owner_table.unit_consumer_mass);
    return p;
}

fn padded(d: W.CpuDeclaration, ordinal: usize, n: usize, dword: bool) !W.CpuDeclaration {
    const class = try L.cpuClass(L.Catalog, d, ordinal, n, dword);
    for (L.Catalog.CPU) |e| if (e.family == class.family) {
        var out = Canon.applyCpuVector(d, e.rungs[class.rung]);
        out.geometry.omit_empty_division = false;
        return out;
    };
    unreachable;
}

/// log2 of the remaining lookup-only budget (bits of slack at the 128-bit target), CPU + global slots only.
fn slackBits(degrees: B.ConditionalDegrees, slots: [3]u64) !f64 {
    var d = degrees;
    for (GLOBAL_ARITIES, slots) |arity, s| try d.addGlobal(.{ .arity = arity, .denominator_slots = s });
    var ledger = Policy.Ledger{ .degree_weight = @splat(0) };
    ledger.degree_weight[@intFromEnum(Policy.AlgebraicTerm.tuple_compression)] = d.tuple_collision;
    ledger.degree_weight[@intFromEnum(Policy.AlgebraicTerm.local_rational_identity)] = d.local_rational_identity;
    ledger.degree_weight[@intFromEnum(Policy.AlgebraicTerm.global_rational_identity)] = d.global_rational_identity;
    ledger.degree_weight[@intFromEnum(Policy.AlgebraicTerm.pole_events)] = d.poles;
    try ledger.requireRawModuloBits(Policy.TARGET_BITS);
    const total = try ledger.total();
    // log2 without a u512 -> f64 conversion (no compiler-rt call for 512-bit ints): keep the top 52 bits.
    const bits: u32 = @intCast(512 - @clz(total));
    const shift: u32 = if (bits > 52) bits - 52 else 0;
    const top: f64 = @floatFromInt(@as(u64, @intCast(total >> @intCast(shift))));
    return 128.0 - @log2(6561.0) - (@log2(top) + @as(f64, @floatFromInt(shift)));
}

test "canon-leaf padded declarations pass the receiver source-bounds gates (characteristic, logs, instances, 128-bit lookup budget)" {
    const a = testing.allocator;
    const parsed = try std.json.parseFromSlice(Basket, a, @embedFile("canon_leaf_basket.json"), .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    var worst_mass = [2]u64{ 0, 0 };
    var worst_inst = [2]usize{ 0, 0 };
    var worst_log = [2]u32{ 0, 0 };
    var min_slack = [2]f64{ 1e9, 1e9 };
    var max_loss: f64 = 0;
    for (parsed.value.blocks) |blk| {
        var dword = false;
        for (blk.cpus) |c| dword = dword or c.bridges.ls_dword != null;
        var deg = [2]B.ConditionalDegrees{ .{}, .{} };
        var slots = [2][3]u64{ @splat(0), @splat(0) };
        for (blk.cpus, 0..) |d, i| {
            const ds = [2]W.CpuDeclaration{ d, try padded(d, i, blk.cpus.len, dword) };
            for (ds, 0..) |x, k| {
                const p = try cpuProof(x, &deg[k], &slots[k]);
                worst_mass[k] = @max(worst_mass[k], p.max_unit_mass);
                worst_inst[k] = @max(worst_inst[k], p.instances);
                worst_log[k] = @max(worst_log[k], p.max_log);
            }
        }
        const s = [2]f64{ try slackBits(deg[0], slots[0]), try slackBits(deg[1], slots[1]) };
        for (s, 0..) |x, k| min_slack[k] = @min(min_slack[k], x);
        max_loss = @max(max_loss, s[0] - s[1]);
    }
    std.debug.print("RV64_M9_CANON_LEAF_BOUNDS exact/padded: max_unit_mass={d}/{d} (p=2147483647) max_instances={d}/{d} (cap {d}) max_log={d}/{d} (cap {d}) min_cpu_lookup_slack_bits={d:.1}/{d:.1} max_slack_loss_bits={d:.2}\n", .{ worst_mass[0], worst_mass[1], worst_inst[0], worst_inst[1], Policy.MAX_LOCAL_INSTANCES, worst_log[0], worst_log[1], Policy.MAX_TRACE_LOG, min_slack[0], min_slack[1], max_loss });
    try testing.expect(worst_mass[1] < std.math.maxInt(u31));
    try testing.expect(worst_inst[1] <= Policy.MAX_LOCAL_INSTANCES);
    try testing.expect(worst_log[1] <= Policy.MAX_TRACE_LOG);
    try testing.expect(min_slack[1] > 0);
}

test "canon-leaf catalog rungs respect the receiver log caps (non-boundary <= MAX_TRACE_LOG, initial/terminal <= MAX_PUBLIC_BOUNDARY_LOG)" {
    for (L.Catalog.CPU) |e| for (e.rungs) |v| for (v, 0..) |log, c| {
        const cap = if (c == 13 or c == 14) Policy.MAX_PUBLIC_BOUNDARY_LOG else Policy.MAX_TRACE_LOG;
        try testing.expect(log <= cap);
    };
}

test "canon-leaf class derivation is idempotent: the padded declaration re-derives its own class (receiver-side rule)" {
    // Soundness point 3 needs the receiver's derivation to agree with the producer's. A receiver that sees only the padded
    // declaration (= the rung vector, omit_empty_division false) must land on the same class index; this holds because no
    // earlier rung of the same cpu_log dominates a later one (checked here) and first-fit is monotone in the vector.
    const a = testing.allocator;
    const parsed = try std.json.parseFromSlice(Basket, a, @embedFile("canon_leaf_basket.json"), .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    var checked: usize = 0;
    for (parsed.value.blocks) |blk| {
        var dword = false;
        for (blk.cpus) |c| dword = dword or c.bridges.ls_dword != null;
        for (blk.cpus, 0..) |d, i| {
            const class = try L.cpuClass(L.Catalog, d, i, blk.cpus.len, dword);
            const again = try L.cpuClass(L.Catalog, try padded(d, i, blk.cpus.len, dword), i, blk.cpus.len, dword);
            try testing.expectEqual(class.index, again.index);
            checked += 1;
        }
    }
    try testing.expectEqual(@as(usize, 347), checked);
    for (L.Catalog.CPU) |e| for (e.rungs, 0..) |x, i| for (e.rungs[i + 1 ..]) |y| {
        if (x[0] != y[0]) continue;
        var dominates = true;
        for (x, y) |p, q| dominates = dominates and p >= q;
        try testing.expect(!dominates);
    };
}

test "canon-leaf catalog has no cpu_single family: a one-segment block is refused (CanonLeafFamilyMissing)" {
    // Completeness gap, not a soundness one: the basket has no single-segment block (min 4 CPU segments, 26235156 at
    // 5.44M gas), so the builder emits no cpu_single rungs. Mainnet blocks below ~1.5M gas would be refused under `on`.
    const a = testing.allocator;
    const parsed = try std.json.parseFromSlice(Basket, a, @embedFile("canon_leaf_basket.json"), .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const d = parsed.value.blocks[0].cpus[0];
    try testing.expectError(error.CanonLeafFamilyMissing, L.cpuClass(L.Catalog, d, 0, 1, true));
}
