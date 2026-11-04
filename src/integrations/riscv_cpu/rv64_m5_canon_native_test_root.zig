test {
    _ = @import("word16_global_execution/ethereum/canon_native.zig");
    _ = @import("word16_global_execution/ethereum/canon_native_widths.zig");
    _ = @import("word16_execution/native_policy.zig");
}
test "canon-native generated rung table has R rungs per family and ascending truth logs" {
    const std = @import("std");
    const Rungs = @import("word16_global_execution/ethereum/canon_native_rungs.zig");
    try std.testing.expectEqual(@as(u32, 4), Rungs.R);
    for (Rungs.CPU) |e| {
        try std.testing.expect(e.rungs.len >= 1 and e.rungs.len <= Rungs.R);
        for (e.rungs) |v| try std.testing.expect(v[0] >= 5 and v[0] <= 23);
    }
    for (Rungs.TRUTH) |e| for (e.logs[1..], 0..) |l, i| try std.testing.expect(l > e.logs[i]);
}
test "m5 chi-chain manifest digest: spec agreement, differs from flat, refuses mixed versions" {
    const std = @import("std");
    const M = @import("word16_global_execution/services/gkr_local/manifest.zig");
    const Canon = @import("word16_global_execution/ethereum/canon_native.zig");
    const c0 = M.Chain{ .family = 0, .rung = 1, .vkhash = @splat(1), .stmt = @splat(2), .s_in = @splat(3), .s_out = @splat(4) };
    const c1 = M.Chain{ .family = 16, .rung = 0, .vkhash = @splat(11), .stmt = @splat(12), .s_in = @splat(4), .s_out = @splat(4) };
    var views = [_]M.CommitmentView{
        .{ .kind = .cpu, .global_relations = .{ .ram = true, .kio = true, .wire = false }, .mass = .{ .ram = 10, .kio = 2, .wire = 0 }, .scope = .{ .ordinal = 0, .statement = @splat(5), .fixed = @splat(6), .main = @splat(7) }, .local = null, .chain = c0 },
        .{ .kind = .keccak, .global_relations = .{ .ram = false, .kio = true, .wire = false }, .mass = .{ .ram = 0, .kio = 2, .wire = 0 }, .scope = .{ .ordinal = 1, .statement = @splat(15), .fixed = @splat(16), .main = @splat(17) }, .local = null, .chain = c1 },
    };
    const execution: [32]u8 = @splat(9);
    const chained = try M.commitViewsFor(.m5_chain_v1, execution, &views);
    // Agreement with the spec encodings (canon_native.zig = the Python reference).
    var segs: [2]Canon.Segment = undefined;
    for (views, &segs, 0..) |v, *s, k| {
        const c = v.chain.?;
        s.* = .{ .k = @intCast(k), .family = c.family, .rung = c.rung, .vkhash = c.vkhash, .stmt = c.stmt, .s_in = c.s_in, .s_out = c.s_out, .rho = try Canon.rho(v.scope.main, null, &.{}) };
    }
    const want = Canon.chi(execution, try Canon.chainFinal(Canon.versionIdentity(Canon.RUNGS), &segs));
    try std.testing.expectEqual(want, chained.digest);
    // The flat v1 digest is unchanged when no entry carries chain fields, and differs.
    // A4 (M6 native-format): chained policy + entry without chain = refused;
    // the flat digest exists only under the flat policy.
    views[0].chain = null;
    try std.testing.expectError(error.NativeChainMissing, M.commitViewsFor(.m5_chain_v1, execution, &views));
    views[1].chain = null;
    try std.testing.expectError(error.NativeChainMissing, M.commitViewsFor(.m6_v2_strict, execution, &views));
    const flat = try M.commitViewsFor(.flat, execution, &views);
    try std.testing.expect(!std.mem.eql(u8, &flat.digest, &chained.digest));
    // A coherent permutation (S08 shape) changes chi.
    views[0].chain = c1;
    views[1].chain = c0;
    const swapped = try M.commitViewsFor(.m5_chain_v1, execution, &views);
    try std.testing.expect(!std.mem.eql(u8, &swapped.digest, &chained.digest));
}
test "m5 chi-chain adversarial: every chain field and every rho input is bound; order and version policy fail closed" {
    const std = @import("std");
    const M = @import("word16_global_execution/services/gkr_local/manifest.zig");
    const ChainMod = @import("word16_global_execution/services/gkr_local/chain.zig");
    const O = @import("stwo_core").fields.om31.OM31;
    const one = [_]O{O.one()};
    const zero = [_]O{O.zero()};
    const marg_one = [_][]const O{&one};
    const marg_zero = [_][]const O{&zero};
    const base_chain = M.Chain{ .family = 0, .rung = 1, .vkhash = @splat(1), .stmt = @splat(2), .s_in = @splat(3), .s_out = @splat(4) };
    const base = [_]M.CommitmentView{
        .{ .kind = .cpu, .global_relations = .{ .ram = true, .kio = false, .wire = false }, .mass = .{ .ram = 1, .kio = 0, .wire = 0 }, .scope = .{ .ordinal = 0, .statement = @splat(5), .fixed = @splat(6), .main = @splat(7) }, .local = .{ .digest = @splat(8), .claims_to_verify_by_instance = &marg_one }, .chain = base_chain },
        .{ .kind = .keccak, .global_relations = .{ .ram = false, .kio = true, .wire = false }, .mass = .{ .ram = 0, .kio = 1, .wire = 0 }, .scope = .{ .ordinal = 1, .statement = @splat(15), .fixed = @splat(16), .main = @splat(17) }, .local = null, .chain = .{ .family = 16, .rung = 0, .vkhash = @splat(11), .stmt = @splat(12), .s_in = @splat(4), .s_out = @splat(4) } },
    };
    const execution: [32]u8 = @splat(9);
    const want = (try M.commitViewsFor(.m5_chain_v1, execution, &base)).digest;
    var seen = std.ArrayList([32]u8){};
    defer seen.deinit(std.testing.allocator);
    try seen.append(std.testing.allocator, want);
    // One tamper per bound input; each must move chi to a fresh value.
    var t: usize = 0;
    while (t < 13) : (t += 1) {
        var v = base;
        var c = v[0].chain.?;
        var exec = execution;
        switch (t) {
            0 => c.family = 3,
            1 => c.rung = 2,
            2 => c.vkhash[31] ^= 1,
            3 => c.stmt[0] ^= 1,
            4 => c.s_in[5] ^= 1,
            5 => c.s_out[9] ^= 1,
            6 => v[0].scope.main[0] ^= 1,
            7 => v[0].local = null,
            8 => v[0].local.?.digest[3] ^= 1,
            9 => v[0].local.?.claims_to_verify_by_instance = &marg_zero,
            10 => v[0].local.?.claims_to_verify_by_instance = &.{},
            11 => exec[0] ^= 1,
            12 => v[1].scope.main[1] ^= 1,
            else => unreachable,
        }
        v[0].chain = c;
        const got = (try M.commitViewsFor(.m5_chain_v1, exec, &v)).digest;
        for (seen.items) |s| try std.testing.expect(!std.mem.eql(u8, &s, &got));
        try seen.append(std.testing.allocator, got);
    }
    // Entry ordinal must equal its chain index (no relabelled segment).
    var bad = base;
    bad[1].scope.ordinal = 0;
    try std.testing.expectError(error.NativeChainOrder, M.commitViewsFor(.m5_chain_v1, execution, &bad));
    // Version policy: unknown names are a clean error, never a panic (corpus P03).
    try std.testing.expectEqual(false, try ChainMod.select(null));
    try std.testing.expectEqual(false, try ChainMod.select(""));
    try std.testing.expectEqual(false, try ChainMod.select("v1-flat"));
    try std.testing.expectEqual(true, try ChainMod.select("m5-chi-chain-v1"));
    try std.testing.expectEqual(true, try ChainMod.select("rv64-m5-native-chi-chain/v1"));
    try std.testing.expectError(error.UnknownNativeVersion, ChainMod.select("m5-chi-chain-v2"));
    try std.testing.expectEqual(true, try ChainMod.select("m6-native-v2-strict"));
    try std.testing.expectError(error.NativeVersionNotImplemented, ChainMod.select("m6-native-v2-gkr"));
    try std.testing.expectError(error.UnknownNativeVersion, ChainMod.select("M5-CHI-CHAIN-V1"));
}

// ---------------------------------------------------------------- M6 native-format: rv64-m6-native/v2 (strict roster)
test "corpus NV01 rv64-m6-native/v2: chain structure/vkhash of a strict segment equals the T_nat class structure (canon-native A1)" {
    const std = @import("std");
    const Canon = @import("word16_global_execution/ethereum/canon_native.zig");
    const Rungs = @import("word16_global_execution/ethereum/canon_native_rungs.zig");
    const Chain = @import("word16_global_execution/services/gkr_local/chain.zig");
    const flags: u32 = 0b1111_1110; // production v3 layout: every pair flag on, division never omitted
    for (Rungs.CPU) |e| for (e.rungs, 0..) |rung, r| {
        // A strict segment's declaration IS the rung vector: the receiver labels it exactly (f, r) and the
        // chain hashes the same structure as the T_nat class entry.
        try std.testing.expectEqual(@as(u32, @intCast(r)), Chain.cpuRungFor(.m6_v2_strict, e.family, rung));
        const chain_structure = Canon.cpuStructureV2(e.family, @intCast(r), rung, flags);
        try std.testing.expectEqual(try Chain.cpuClassStructure(e.family, @intCast(r), flags), chain_structure);
        // v1 hashed the declaration's own vector under the v1 tag: never equal to the v2 class structure.
        try std.testing.expect(!std.mem.eql(u8, &Canon.cpuStructure(e.family, @intCast(r), rung), &chain_structure));
    };
    // The layout flags are bound: an omitted division (bit 0) is a different structure.
    const e = Rungs.CPU[0];
    try std.testing.expect(!std.mem.eql(u8, &Canon.cpuStructureV2(e.family, 0, e.rungs[0], flags), &Canon.cpuStructureV2(e.family, 0, e.rungs[0], flags | 1)));
}
test "corpus NV02 rv64-m6-native/v2: a declaration vector that differs from every rung vector is refused (no UNCLASSED, no dominance)" {
    const std = @import("std");
    const Rungs = @import("word16_global_execution/ethereum/canon_native_rungs.zig");
    const Chain = @import("word16_global_execution/services/gkr_local/chain.zig");
    const e = Rungs.CPU[1]; // cpu_middle
    var presence_preserving = e.rungs[2];
    // Drop one present rung component (a bridge the segment did not use, v1 presence-preserving padding).
    for (presence_preserving[15..], 15..) |log, c| if (log != 0) {
        presence_preserving[c] = 0;
        break;
    };
    // v1 labels it with a dominating rung (the A1 flaw); v2 refuses it.
    try std.testing.expect(Chain.cpuRungFor(.m5_chain_v1, e.family, presence_preserving) != Chain.UNCLASSED);
    try std.testing.expectEqual(Chain.UNCLASSED, Chain.cpuRungFor(.m6_v2_strict, e.family, presence_preserving));
    // A raised log is refused too, as is a rung index outside the table.
    var raised = e.rungs[0];
    raised[1] += 1;
    try std.testing.expectEqual(Chain.UNCLASSED, Chain.cpuRungFor(.m6_v2_strict, e.family, raised));
    try std.testing.expectError(error.NativeChainNotStrict, Chain.cpuClassStructure(e.family, 9, 0));
    // Truth: exact (log, aux) only.
    const t = Rungs.TRUTH[0];
    try std.testing.expectEqual(@as(u32, 1), Chain.truthRung(t.family, .{ t.logs[1], t.aux }));
    try std.testing.expectEqual(Chain.UNCLASSED, Chain.truthRung(t.family, .{ t.logs[0] + 1, t.aux }));
}
test "corpus NV05 rv64-m6-native/v2: the version identity hashes LOCAL_RELATIONS = 10, the strict flag and the gkr mode" {
    const std = @import("std");
    const Canon = @import("word16_global_execution/ethereum/canon_native.zig");
    const Chain = @import("word16_global_execution/services/gkr_local/chain.zig");
    const v2 = Canon.versionIdentityV2(Canon.RUNGS, .strict_local);
    var h9 = Canon.Hasher.init(.version_v2);
    h9.words(&.{ 2, 9, Canon.GLOBAL_RELATIONS, Canon.RUNGS, 32, 1, 0 });
    try std.testing.expect(!std.mem.eql(u8, &h9.final(), &v2));
    var h10 = Canon.Hasher.init(.version_v2);
    h10.words(&.{ 2, 10, Canon.GLOBAL_RELATIONS, Canon.RUNGS, 32, 1, 0 });
    try std.testing.expectEqual(h10.final(), v2);
    try std.testing.expect(!std.mem.eql(u8, &v2, &Canon.versionIdentityV2(Canon.RUNGS, .native_gkr)));
    try std.testing.expect(!std.mem.eql(u8, &v2, &Canon.versionIdentity(Canon.RUNGS)));
    try std.testing.expectEqual(v2, try Chain.versionIdentity(.m6_v2_strict));
    try std.testing.expectError(error.NativeChainMissing, Chain.versionIdentity(.flat));
}
test "corpus NV04 rv64-m6-native/v2: lambda_k (local GKR digest / marginals) is bound by rho under v2 exactly as under v1" {
    const std = @import("std");
    const M = @import("word16_global_execution/services/gkr_local/manifest.zig");
    const O = @import("stwo_core").fields.om31.OM31;
    const one = [_]O{O.one()};
    const two = [_]O{O.one().add(O.one())};
    const m1 = [_][]const O{&one};
    const m2 = [_][]const O{&two};
    const c = M.Chain{ .family = 0, .rung = 1, .vkhash = @splat(1), .stmt = @splat(2), .s_in = @splat(3), .s_out = @splat(4) };
    var v = [_]M.CommitmentView{.{ .kind = .cpu, .global_relations = .{ .ram = true, .kio = false, .wire = false }, .mass = .{ .ram = 1, .kio = 0, .wire = 0 }, .scope = .{ .ordinal = 0, .statement = @splat(5), .fixed = @splat(6), .main = @splat(7) }, .local = .{ .digest = @splat(8), .claims_to_verify_by_instance = &m1 }, .chain = c }};
    const base = (try M.commitViewsFor(.m6_v2_strict, @splat(9), &v)).digest;
    v[0].local.?.claims_to_verify_by_instance = &m2;
    try std.testing.expect(!std.mem.eql(u8, &base, &(try M.commitViewsFor(.m6_v2_strict, @splat(9), &v)).digest));
    v[0].local.?.claims_to_verify_by_instance = &m1;
    v[0].local.?.digest[0] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &base, &(try M.commitViewsFor(.m6_v2_strict, @splat(9), &v)).digest));
    // and v2 chi differs from v1 chi over the same entries (version identity in the IV)
    v[0].local.?.digest[0] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &base, &(try M.commitViewsFor(.m5_chain_v1, @splat(9), &v)).digest));
}
