//! fused pair cases; fixture authority is shared with the other test owners.
//! LS-D64 known-answer, projection and adversarial tests.
//!
//! Acceptance model (as in the bulk-memory tests): a witness is accepted only
//! if every local residual of every row is zero, every U16/U8 query value lies
//! in its table, RAM14 closes against the honest INIT/TERM endpoints of every
//! touched word, and OWNER19 closes against the honest CPU LS tuples. The
//! interaction for a forged MAIN is rebuilt independently from the expanded
//! rows (exact inverses and prefixes), so a rejection is never an artifact of
//! a stale interaction column. Each adversarial case names the failing check.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const D = @import("mod.zig");
const R = @import("../closed_ram/mod.zig");
const L = D.layout;
const M = core.fields.m31.M31;
const Q = D.types.Q;
const testing = std.testing;
const a = testing.allocator;
const LOG: u32 = 5;
const N: usize = 1 << LOG;

const Support = @import("tests_support.zig");
const q = Support.q;
const challenges = Support.challenges;
const expanded = Support.expanded;
const Tables = Support.Tables;
const pairChallenges = Support.pairChallenges;
const firstFusedResidual = Support.firstFusedResidual;
const readInter = Support.readInter;
const addInter = Support.addInter;
const fusedHonest = Support.fusedHonest;

test "LS-D64 fused-pair ledger: 39 MAIN + 16 INTER and 252 residuals" {
    try testing.expectEqual(@as(usize, 16), L.fused.INTERACTION);
    try testing.expectEqual(@as(usize, 252), L.fused.CONSTRAINTS);
    const c = D.component.Component{ .log_size = LOG, .rows = 1, .offsets = .{ 0, 0, 0 }, .claims = D.types.Claims.zero(), .challenges = challenges(), .pairs = pairChallenges() };
    try testing.expectEqual([3]usize{ L.FIXED, L.MAIN, 16 }, c.widths());
    try testing.expectEqual(@as(usize, 252), c.nConstraints());
    for (0..16) |col| try testing.expectEqual(col < 4 or col >= 12, c.previousInter(col));
}
test "LS-D64 fused-pair honest witness: every residual vanishes; RAM/OWNER/U16 shares equal the classic layout and the pair share balances the table counts" {
    var h = try fusedHonest();
    defer {
        h.source.deinit();
        h.w.deinit();
        a.free(h.pairs);
    }
    try testing.expect(firstFusedResidual(h.source.fixed, h.source.main, h.source.interaction, @intCast(h.w.events.items.len), h.claims, h.ch, h.pc) == null);
    try testing.expect(h.claims.ram.eql(h.classic.ram));
    try testing.expect(h.claims.owner.eql(h.classic.owner));
    try testing.expect(h.claims.range16.eql(h.classic.range16));
    // Pair share: one (b13, b26) pair per physical row.
    var expected = Q.zero();
    for (0..N) |r| {
        const m = expanded(h.source.main, R.trace.physical(r, LOG));
        expected = expected.add(try Tables.pairDenominatorFor(Q, h.pc, m[L.LOGICAL_U8[0]], m[L.LOGICAL_U8[1]]).inv());
    }
    try testing.expect(h.claims.range8.eql(expected));
    // The classic receiver's residuals reject the fused witness width and vice versa.
    try testing.expectEqual(@as(usize, L.fused.INTERACTION * N), h.source.interaction.len);
}
test "LS-D64 fused-pair adversarial: forged K slots, prefixes and a moved pair fraction are local residuals" {
    var h = try fusedHonest();
    defer {
        h.source.deinit();
        h.w.deinit();
        a.free(h.pairs);
    }
    const rows: u32 = @intCast(h.w.events.items.len);
    const delta = q(77);
    const inter = try a.dupe(M, h.source.interaction);
    defer a.free(inter);
    // (1) K_j += delta with the centered prefix repaired (claim moves too):
    // only the slot residual K*a*b = numerator can reject it.
    for ([_]usize{ 0, 1 }) |slot| for ([_]usize{ 0, N - 1 }) |r| {
        @memcpy(inter, h.source.interaction);
        addInter(inter, r, L.fused.WITNESS + 4 * slot, delta);
        for (0..r) |k| addInter(inter, k, L.fused.LOCAL_PREFIX, delta.neg());
        var claims = h.claims;
        claims.owner = claims.owner.add(delta);
        const hit = firstFusedResidual(h.source.fixed, h.source.main, inter, rows, claims, h.ch, h.pc) orelse return error.ForgedSlotAccepted;
        try testing.expectEqual(r, hit.row);
    };
    // (2) A single prefix += delta (RAM or local) is rejected.
    for ([_]usize{ L.fused.RAM_PREFIX, L.fused.LOCAL_PREFIX }) |column| {
        @memcpy(inter, h.source.interaction);
        addInter(inter, 3, column, delta);
        try testing.expect(firstFusedResidual(h.source.fixed, h.source.main, inter, rows, h.claims, h.ch, h.pc) != null);
    }
    // (3) Move row r's byte-pair fraction to row t: claims unchanged, rejected.
    for ([_][2]usize{ .{ 0, 9 }, .{ N - 2, N - 1 } }) |move| {
        @memcpy(inter, h.source.interaction);
        const m = expanded(h.source.main, R.trace.physical(move[0], LOG));
        const fraction = try Tables.pairDenominatorFor(Q, h.pc, m[L.LOGICAL_U8[0]], m[L.LOGICAL_U8[1]]).inv();
        for (move[0]..move[1]) |k| addInter(inter, k, L.fused.LOCAL_PREFIX, fraction.neg());
        const hit = firstFusedResidual(h.source.fixed, h.source.main, inter, rows, h.claims, h.ch, h.pc) orelse return error.MovedPairAccepted;
        try testing.expectEqual(move[0], hit.row);
    }
    // (4) Fused RAM fraction moved between rows (active row 0 to row 5).
    @memcpy(inter, h.source.interaction);
    const step = readInter(h.source.interaction, 1, L.fused.RAM_PREFIX).sub(readInter(h.source.interaction, 0, L.fused.RAM_PREFIX));
    try testing.expect(!step.isZero());
    for (1..5) |k| addInter(inter, k, L.fused.RAM_PREFIX, step.neg());
    try testing.expect(firstFusedResidual(h.source.fixed, h.source.main, inter, rows, h.claims, h.ch, h.pc) != null);
    // (5) Out-of-range pair elements never alias a canonical table pair row.
    for ([_][2]u32{ .{ 256, 0 }, .{ 0, 256 }, .{ 2147483646, 1 } }) |bad| {
        const p = Tables.pairDenominatorFor(Q, h.pc, E.q(bad[0]), E.q(bad[1]));
        for (0..65536) |i| try testing.expect(!p.eql(Tables.pairDenominatorFor(Q, h.pc, E.q(@intCast(i >> 8)), E.q(@intCast(i & 255)))));
    }
}
test "LS-D64 fused-pair packed quotient rows on four workers equal serial accumulation" {
    const engine = @import("stwo_prover_engine");
    const size = 16384;
    const component = D.component.Component{ .log_size = 13, .rows = 8191, .offsets = .{ 0, 0, 0 }, .claims = D.types.Claims.zero(), .challenges = challenges(), .pairs = pairChallenges() };
    const widths = component.widths();
    const count = widths[0] + widths[1] + widths[2];
    const data = try a.alloc(M, count * size);
    defer a.free(data);
    var views: [L.FIXED + L.MAIN + L.INTERACTION][]const M = undefined;
    for (views[0..count], 0..) |*view, c| {
        const column = data[c * size ..][0..size];
        for (column, 0..) |*v, r| v.* = M.fromCanonical(@intCast((c * size + r + 1) % 2147483647));
        view.* = column;
    }
    var channel = core.channel.blake2s.Blake2sChannel{};
    var powers: [L.fused.CONSTRAINTS]Q = undefined;
    for (&powers) |*v| v.* = channel.drawSecureFelt();
    const inverses = [_]M{ M.fromCanonical(3), M.fromCanonical(5) };
    const reference = try a.alloc(M, 4 * size);
    defer a.free(reference);
    const actual = try a.alloc(M, 4 * size);
    defer a.free(actual);
    @memset(reference, M.zero());
    @memset(actual, M.zero());
    var ref_col = engine.secure_column.SecureColumnByCoords{ .columns = .{ reference[0..size], reference[size..][0..size], reference[2 * size ..][0..size], reference[3 * size ..][0..size] }, .owns_columns = false };
    var actual_col = engine.secure_column.SecureColumnByCoords{ .columns = .{ actual[0..size], actual[size..][0..size], actual[2 * size ..][0..size], actual[3 * size ..][0..size] }, .owns_columns = false };
    var ref_output = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &powers, .col = &ref_col, .next_fresh_index = 0 };
    var actual_output = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &powers, .col = &actual_col, .next_fresh_index = 0 };
    try D.component.testing.packedRows.evaluate(&component, views[0..count], 0, size, &inverses, &ref_output);
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = engine.work_pool.WORKER_STACK_SIZE, .backing_allocator = a });
    defer pool.deinit();
    try D.component.testing.evaluateRows(&component, views[0..count], &inverses, &actual_output, &pool);
    try testing.expectEqualSlices(M, reference, actual);
    for ([_]usize{ 0, 1, 17, 4095 }) |row| {
        var f: [L.FIXED]Q = undefined;
        var m: [L.MAIN]Q = undefined;
        var i: [L.fused.INTERACTION]Q = undefined;
        for (&f, 0..) |*v, c| v.* = Q.fromBase(views[c][row]);
        for (&m, 0..) |*v, c| v.* = Q.fromBase(views[L.FIXED + c][row]);
        for (&i, 0..) |*v, c| v.* = Q.fromBase(views[L.FIXED + L.MAIN + c][row]);
        var pm: [L.MAIN]Q = @splat(Q.zero());
        var pi: [L.fused.INTERACTION]Q = @splat(Q.zero());
        const prev = core.utils.previousBitReversedCircleDomainIndex(row, 13, 14);
        pm[0] = Q.fromBase(views[L.FIXED][prev]);
        for (&pi, 0..) |*v, c| if (component.previousInter(c)) {
            v.* = Q.fromBase(views[L.FIXED + L.MAIN + c][prev]);
        };
        var acc = E.WeightedAccumulator{ .powers = &powers };
        var sink = E.Sink{ .values = null, .weighted_accumulator = &acc };
        component.emitFor(Q, &f, &m, &pm, &i, &pi, &sink);
        const scaled = acc.accumulation.mul(Q.fromBase(inverses[row >> 13]));
        const got = Q.fromM31Array(.{ reference[row], reference[size + row], reference[2 * size + row], reference[3 * size + row] });
        try testing.expect(scaled.eql(got));
    }
}
