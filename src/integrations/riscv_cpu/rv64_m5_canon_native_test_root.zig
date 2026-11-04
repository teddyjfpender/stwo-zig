test {
    _ = @import("word16_global_execution/ethereum/canon_native.zig");
    _ = @import("word16_global_execution/ethereum/canon_native_widths.zig");
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
    const chained = try M.commitViews(execution, &views);
    // Agreement with the spec encodings (canon_native.zig = the Python reference).
    var segs: [2]Canon.Segment = undefined;
    for (views, &segs, 0..) |v, *s, k| {
        const c = v.chain.?;
        s.* = .{ .k = @intCast(k), .family = c.family, .rung = c.rung, .vkhash = c.vkhash, .stmt = c.stmt, .s_in = c.s_in, .s_out = c.s_out, .rho = try Canon.rho(v.scope.main, null, &.{}) };
    }
    const want = Canon.chi(execution, try Canon.chainFinal(Canon.versionIdentity(Canon.RUNGS), &segs));
    try std.testing.expectEqual(want, chained.digest);
    // The flat v1 digest is unchanged when no entry carries chain fields, and differs.
    views[0].chain = null;
    try std.testing.expectError(error.MixedNativeChainVersion, M.commitViews(execution, &views));
    views[1].chain = null;
    const flat = try M.commitViews(execution, &views);
    try std.testing.expect(!std.mem.eql(u8, &flat.digest, &chained.digest));
    // A coherent permutation (S08 shape) changes chi.
    views[0].chain = c1;
    views[1].chain = c0;
    const swapped = try M.commitViews(execution, &views);
    try std.testing.expect(!std.mem.eql(u8, &swapped.digest, &chained.digest));
}
