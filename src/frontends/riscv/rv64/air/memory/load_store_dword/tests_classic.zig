//! classic cases; fixture authority is shared with the other test owners.
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
const Decode = @import("../../../decode.zig");
const D = @import("mod.zig");
const V1 = @import("../load_store_v1/mod.zig");
const V2 = @import("../load_store/mod.zig");
const R = @import("../closed_ram/mod.zig");
const L = D.layout;
const Eq = D.equations;
const M = core.fields.m31.M31;
const Q = D.types.Q;
const testing = std.testing;
const a = testing.allocator;
const LOG: u32 = 5;
const N: usize = 1 << LOG;

const Support = @import("tests_support.zig");
const q = Support.q;
const challenges = Support.challenges;
const dictionary = Support.dictionary;
const cpuTuple = Support.cpuTuple;
const honestWorld = Support.honestWorld;
const relations = Support.relations;
const firstResidual = Support.firstResidual;
const Verdict = Support.Verdict;
const judge = Support.judge;
const honestMain = Support.honestMain;
const at = Support.at;
const rowOf = Support.rowOf;

test "LS-D64 ledger: 39 MAIN + 28 INTER = 67 cells and the counted constraint total" {
    try testing.expectEqual(@as(usize, 67), L.MAIN + L.INTERACTION);
    try testing.expectEqual(@as(usize, 102), V2.layout.MAIN + V2.layout.INTERACTION);
    var values: [D.component.CONSTRAINTS + 8]Q = undefined;
    var sink = E.Sink{ .values = &values };
    const zero_main: [L.MAIN]Q = @splat(Q.zero());
    const zero_inter: [L.INTERACTION]Q = @splat(Q.zero());
    const f: [L.FIXED]Q = @splat(Q.zero());
    Eq.emitFor(Q, &f, &zero_main, &zero_main, &zero_inter, &zero_inter, 0, D.types.Claims.zero(), challenges(), &sink);
    try testing.expectEqual(@as(usize, D.component.CONSTRAINTS), sink.count);
}

test "LS-D64 expansion equals the LS32 native oracle on every LD/SD coordinate it reads and passes the V1 residuals" {
    var w = try honestWorld();
    defer w.deinit();
    const unread = [_]usize{ V1.layout.selected_byte, V1.layout.selected_sign, V1.layout.limb_sign, V1.layout.b_low, V1.layout.b_high };
    for (w.events.items) |e| {
        try D.source.validate(e);
        const oracle = V2.native.logicalRow(e);
        const physical = D.source.row(e);
        const x = L.expandFor(M, &physical);
        for (0..L.LOGICAL_MAIN) |c| {
            var skip = false;
            for (unread) |u| skip = skip or u == c;
            if (!skip) try testing.expectEqual(oracle[c].v, x[c].v);
        }
        // The audited V1 local equations accept the expansion (row in the
        // middle of an active prefix: first = last = 0, previous active).
        var logical: [L.LOGICAL_MAIN]Q = undefined;
        for (&logical, x) |*v, m| v.* = Q.fromBase(m);
        var previous: [L.LOGICAL_MAIN]Q = @splat(Q.zero());
        previous[0] = Q.one();
        var values: [400]Q = undefined;
        var sink = E.Sink{ .values = &values };
        const f = [_]Q{ E.q(1), Q.zero(), Q.zero() };
        V1.equations.emitLocalWithPublicFor(Q, &f, &logical, &previous, E.q(4), Q.one(), &sink);
        for (values[0..sink.count]) |v| try testing.expect(v.isZero());
        // The OWNER19 tuple is the LS32 tuple and the CPU's tuple.
        const v2_row = V2.native.row(e);
        const lhs = Eq.ownerTuple(M, &physical);
        const rhs = V2.equations.ownerTuple(M, &v2_row);
        const cpu = cpuTuple(e);
        for (lhs, rhs, cpu) |x0, y0, z0| {
            try testing.expectEqual(x0.v, y0.v);
            try testing.expect(Q.fromBase(x0).eql(z0));
        }
    }
    for (L.expandFor(M, &D.source.row(null))) |v| try testing.expectEqual(@as(u32, 0), v.v);
}

test "LS-D64 virtual expansion is affine on arbitrary secure coordinates" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    var origin: [L.MAIN]Q = undefined;
    var direction: [L.MAIN]Q = undefined;
    for (&origin, &direction) |*x, *y| {
        x.* = channel.drawSecureFelt();
        y.* = channel.drawSecureFelt();
    }
    var rows: [3][L.LOGICAL_MAIN]Q = undefined;
    for (&rows, 0..) |*row, k| {
        var physical: [L.MAIN]Q = undefined;
        for (&physical, origin, direction) |*v, x, y| v.* = x.add(y.mul(E.q(@intCast(k))));
        row.* = L.expandFor(Q, &physical);
        try testing.expectEqualSlices(Q, &physical, &L.projectFor(Q, row));
    }
    for (0..L.LOGICAL_MAIN) |c| try testing.expect(rows[2][c].sub(rows[1][c]).eql(rows[1][c].sub(rows[0][c])));
}

test "LS-D64 honest witness: native interaction equals the independent rebuild, all residuals vanish, RAM and OWNER close" {
    var w = try honestWorld();
    defer w.deinit();
    const ch = challenges();
    const d16 = try dictionary(ch.range16, 65536);
    defer a.free(d16);
    const d8 = try dictionary(ch.range8, 256);
    defer a.free(d8);
    var source = try D.source.Source.init(a, w.events.items, LOG);
    defer source.deinit();
    const main = try honestMain(&w);
    try testing.expectEqualSlices(M, &main, source.main);
    const claims = try source.generate(ch, d16, d8);
    const rel = try relations(&main, ch);
    try testing.expectEqualSlices(M, &rel.inter, source.interaction);
    try testing.expect(claims.ram.eql(rel.ram));
    try testing.expect(claims.owner.eql(rel.owner));
    try testing.expect(claims.range16.eql(rel.range16));
    try testing.expect(claims.range8.eql(rel.range8));
    try testing.expect(firstResidual(source.fixed, source.main, source.interaction, @intCast(w.events.items.len), claims, ch) == null);
    try testing.expectEqual(Verdict.accepted, try judge(&w, &main, @intCast(w.events.items.len), ch));
    // A wrong public row count is a local residual (active-prefix shape).
    try testing.expectEqual(Verdict.local_residual, try judge(&w, &main, @intCast(w.events.items.len - 1), ch));
}

test "LS-D64 rejects every non-LD/SD event at construction and capacity without a padding row" {
    var w = try honestWorld();
    defer w.deinit();
    try w.access(.LW, 0x1000, 0, 0, 0);
    try w.access(.LB, 0x1000, 3, 0, 0);
    try w.access(.SB, 0x1000, 5, 0x77, 0);
    try w.access(.LWU, 0x1008, 4, 0, 0);
    for (w.events.items[w.events.items.len - 4 ..]) |e| try testing.expectError(error.NotDwordLoadStoreEvent, D.source.validate(e));
    try testing.expectError(error.NotDwordLoadStoreEvent, D.source.Source.init(a, w.events.items, LOG));
    var many: [N]D.source.Event = undefined;
    @memset(&many, w.events.items[0]);
    try testing.expectError(error.LsCapacityExceeded, D.source.Source.init(a, &many, LOG));
}

test "LS-D64 routing admits only naturally aligned LD/SD (opcode alone is not enough)" {
    var w = try honestWorld();
    defer w.deinit();
    for ([_]Decode.Opcode{ .LD, .SD }) |op| {
        const e = w.events.items[rowOf(&w, op)];
        try testing.expect(D.source.admits(e));
        try D.source.validate(e);
        // Every misaligned effective address (A or the immediate off by 1..7)
        // is refused by the router, so it can never become a dword row.
        for (1..8) |k| {
            var by_a = e;
            by_a.a +%= k;
            try testing.expect(!D.source.admits(by_a));
            try testing.expectError(error.NotDwordLoadStoreEvent, D.source.validate(by_a));
            var by_imm = e;
            by_imm.immediate +%= k;
            try testing.expect(!D.source.admits(by_imm));
            try testing.expectError(error.NotDwordLoadStoreEvent, D.source.validate(by_imm));
            const one = [_]D.source.Event{by_a};
            try testing.expectError(error.NotDwordLoadStoreEvent, D.source.Source.init(a, &one, LOG));
        }
        // Wrap-around: A + I aligned modulo 2^64 is still natural alignment.
        var wrapped = e;
        wrapped.a = e.a +% e.immediate +% 8;
        wrapped.immediate = std.math.maxInt(u64) - 7;
        try testing.expect(D.source.admits(wrapped));
    }
}

test "LS-D64 adversarial: value limb forgeries are local residuals" {
    var w = try honestWorld();
    defer w.deinit();
    const ch = challenges();
    const rows: u32 = @intCast(w.events.items.len);
    const ld = rowOf(&w, .LD);
    const sd = rowOf(&w, .SD);
    // LD returning a value other than the RAM word (after != before).
    {
        var main = try honestMain(&w);
        at(&main, ld, 18 + 2).* = at(&main, ld, 18 + 2).add(M.one());
        try testing.expectEqual(Verdict.local_residual, try judge(&w, &main, rows, ch));
    }
    // LD with a nonzero B (C = after - B would otherwise carry a forged result).
    {
        var main = try honestMain(&w);
        at(&main, ld, V1.layout.b + 1).* = M.fromCanonical(5);
        try testing.expectEqual(Verdict.local_residual, try judge(&w, &main, rows, ch));
    }
    // SD writing a word other than B.
    {
        var main = try honestMain(&w);
        at(&main, sd, 18 + 3).* = at(&main, sd, 18 + 3).add(M.one());
        try testing.expectEqual(Verdict.local_residual, try judge(&w, &main, rows, ch));
    }
    // SD whose B differs from the register (after = B kept consistent):
    // locally fine, but the OWNER tuple's B no longer matches the CPU.
    {
        var main = try honestMain(&w);
        at(&main, sd, V1.layout.b).* = at(&main, sd, V1.layout.b).add(M.one());
        at(&main, sd, 18).* = at(&main, sd, 18).add(M.one());
        const v = try judge(&w, &main, rows, ch);
        try testing.expect(v == .ram_unclosed or v == .owner_unclosed);
    }
}

test "LS-D64 adversarial: activity and store flag forgeries" {
    var w = try honestWorld();
    defer w.deinit();
    const ch = challenges();
    const rows: u32 = @intCast(w.events.items.len);
    const ld = rowOf(&w, .LD);
    for ([_]u32{ 2, M.fromCanonical(0).sub(M.one()).v }) |value| {
        var main = try honestMain(&w);
        at(&main, ld, 1).* = M.fromCanonical(value);
        try testing.expectEqual(Verdict.local_residual, try judge(&w, &main, rows, ch));
    }
    // store = 1 on an inactive (padding) row.
    {
        var main = try honestMain(&w);
        at(&main, N - 1, 1).* = M.one();
        try testing.expectEqual(Verdict.local_residual, try judge(&w, &main, rows, ch));
    }
    // Any nonzero committed coordinate on a padding row.
    for (L.STORED[1..]) |logical| {
        var main = try honestMain(&w);
        at(&main, rows + 2, logical).* = M.fromCanonical(3);
        try testing.expectEqual(Verdict.local_residual, try judge(&w, &main, rows, ch));
    }
    // Every Boolean (active, store) yields an opcode in {0, LD, SD} or a residual.
    for ([_][2]u32{ .{ 0, 0 }, .{ 1, 0 }, .{ 1, 1 } }) |bits| {
        var physical: [L.MAIN]M = @splat(M.zero());
        physical[0] = M.fromCanonical(bits[0]);
        physical[1] = M.fromCanonical(bits[1]);
        const opcode = L.expandFor(M, &physical)[V1.layout.opcode].v;
        try testing.expect(opcode == 0 or opcode == L.LD_OPCODE or opcode == L.SD_OPCODE);
    }
}

test "LS-D64 adversarial: misaligned address claimed aligned" {
    var w = try honestWorld();
    defer w.deinit();
    const ch = challenges();
    const rows: u32 = @intCast(w.events.items.len);
    const ld = rowOf(&w, .LD);
    // The CPU executed LD at EA + 4 (A grew by 4); the row keeps the aligned word.
    var cpu = w.events.items[ld];
    cpu.a +%= 4;
    // (1) Keep the true A and quotient: the virtual immediate drops by 4 and
    // no longer equals the ROM immediate in OWNER.
    {
        var main = try honestMain(&w);
        for (0..4) |c| at(&main, ld, V1.layout.a + c).* = M.fromCanonical(@as(u16, @truncate(cpu.a >> @as(u6, @intCast(16 * c)))));
        var forged = w;
        forged.events = try w.events.clone(a);
        defer forged.events.deinit(a);
        forged.events.items[ld] = cpu;
        try testing.expectEqual(Verdict.owner_unclosed, try judge(&forged, &main, rows, ch));
    }
    // (2) Exhaustive: no U16 quotient and Boolean carry make limb 0 of the
    // virtual immediate equal the canonical immediate when A0+I0 = 4 mod 8.
    const a0: u32 = @as(u16, @truncate(cpu.a));
    const imm0: u32 = @as(u16, @truncate(cpu.immediate));
    try testing.expect((a0 + imm0) % 8 == 4);
    var quotient: u32 = 0;
    while (quotient < 65536) : (quotient += 1) for (0..2) |carry| {
        const imm = M.fromCanonical(8 * quotient).add(M.fromCanonical(65536 * @as(u32, @intCast(carry)))).sub(M.fromCanonical(a0));
        try testing.expect(imm.v != imm0);
    };
    // (3) Inverse-of-eight compensation: q = EA0 / 8 in the field is not U16.
    {
        var main = try honestMain(&w);
        const ea0 = M.fromCanonical(@as(u16, @truncate(cpu.a +% cpu.immediate)));
        at(&main, ld, V1.layout.quotient).* = ea0.mul(try M.fromCanonical(8).inv());
        for (0..4) |c| at(&main, ld, V1.layout.a + c).* = M.fromCanonical(@as(u16, @truncate(cpu.a >> @as(u6, @intCast(16 * c)))));
        var forged = w;
        forged.events = try w.events.clone(a);
        defer forged.events.deinit(a);
        forged.events.items[ld] = cpu;
        try testing.expectEqual(Verdict.range_membership, try judge(&forged, &main, rows, ch));
    }
}

test "LS-D64 adversarial: wrong width and LB/LW routed through the dword row" {
    const ch = challenges();
    // The CPU issued LB (byte 3) / LW (word at offset 0) / SB; the prover puts
    // the access in the dword chip with LD/SD semantics on the aligned word.
    for ([_]struct { op: Decode.Opcode, imm: u64, b: u64 }{ .{ .op = .LB, .imm = 3, .b = 0 }, .{ .op = .LW, .imm = 0, .b = 0 }, .{ .op = .LBU, .imm = 0, .b = 0 }, .{ .op = .SB, .imm = 0, .b = 0x5a } }) |case| {
        var narrow = try honestWorld();
        defer narrow.deinit();
        try narrow.access(case.op, 0x1000, case.imm, case.b, 0);
        const e = narrow.events.items[narrow.events.items.len - 1];
        try testing.expectError(error.NotDwordLoadStoreEvent, D.source.validate(e));
        // Best dword imitation: same word, same clock, the CPU's A and B,
        // LD/SD semantics; its tuple opcode is LD/SD, never the narrow one.
        var imitation = e;
        imitation.opcode = if (e.opcode == .SB) .SD else .LD;
        imitation.immediate = e.immediate & ~@as(u64, 7);
        if (imitation.opcode == .LD) imitation.c = e.before.value else imitation.after.value = e.b;
        const physical = D.source.row(imitation);
        const tuple = Eq.ownerTuple(M, &physical);
        try testing.expect(tuple[0].v != @intFromEnum(e.opcode));
        var main = try honestMain(&narrow);
        for (physical, 0..) |v, c| main[c * N + R.trace.physical(narrow.events.items.len - 1, LOG)] = v;
        const forged_after = narrow.states.get(0x1000).?;
        narrow.states.put(0x1000, imitation.after) catch unreachable;
        const v = try judge(&narrow, &main, @intCast(narrow.events.items.len), ch);
        narrow.states.put(0x1000, forged_after) catch unreachable;
        try testing.expectEqual(Verdict.owner_unclosed, v);
    }
}

test "LS-D64 adversarial: RAM predecessor and clock forgeries" {
    var w = try honestWorld();
    defer w.deinit();
    const ch = challenges();
    const rows: u32 = @intCast(w.events.items.len);
    // LD of 0x1000 (row 1) claims a different predecessor value; it returns
    // that value consistently (before = after = C), so all local checks pass.
    {
        var main = try honestMain(&w);
        const r: usize = 1;
        try testing.expectEqual(Decode.Opcode.LD, w.events.items[r].opcode);
        for ([_]usize{ 14, 18 }) |base| at(&main, r, base).* = at(&main, r, base).add(M.one());
        var forged = w;
        forged.events = try w.events.clone(a);
        defer forged.events.deinit(a);
        forged.events.items[r].c +%= 1;
        try testing.expectEqual(Verdict.ram_unclosed, try judge(&forged, &main, rows, ch));
    }
    // A predecessor clock in the future of the access (time travel): the
    // strict gap would have to be negative, which no U16/U8 split encodes.
    {
        var main = try honestMain(&w);
        const r: usize = 2; // LD 0x1008, first access (cross-epoch).
        at(&main, r, 2).* = M.one(); // claim same epoch
        at(&main, r, 8).* = M.one();
        const after_lo = at(&main, r, 12).v;
        at(&main, r, 10).* = M.fromCanonical(after_lo + 4);
        at(&main, r, 24).* = M.zero();
        // gap = after - before - 1 = -5: the field residue is not U16.
        at(&main, r, 25).* = M.fromCanonical(0).sub(M.fromCanonical(5));
        at(&main, r, 26).* = M.zero();
        at(&main, r, 27).* = M.zero();
        try testing.expect(try judge(&w, &main, rows, ch) != .accepted);
    }
    // OWNER tuple mismatch: a different tick (gap kept consistent), epoch, or A.
    {
        var main = try honestMain(&w);
        const r: usize = 1;
        at(&main, r, 12).* = at(&main, r, 12).add(M.fromCanonical(4));
        at(&main, r, 25).* = at(&main, r, 25).add(M.fromCanonical(4));
        const v = try judge(&w, &main, rows, ch);
        try testing.expect(v == .owner_unclosed or v == .ram_unclosed);
    }
    {
        var main = try honestMain(&w);
        at(&main, 1, V1.layout.a + 3).* = M.fromCanonical(7);
        try testing.expectEqual(Verdict.owner_unclosed, try judge(&w, &main, rows, ch));
    }
}

test "LS-D64 OWNER is one-to-one across chips: split consumption closes, double consumption does not" {
    var w = try honestWorld();
    defer w.deinit();
    const ch = challenges();
    const d16 = try dictionary(ch.range16, 65536);
    defer a.free(d16);
    const d8 = try dictionary(ch.range8, 256);
    defer a.free(d8);
    const events = w.events.items;
    var evens: std.ArrayList(D.source.Event) = .{};
    defer evens.deinit(a);
    var odds: std.ArrayList(D.source.Event) = .{};
    defer odds.deinit(a);
    for (events, 0..) |e, i| try (if (i % 2 == 0) &evens else &odds).append(a, e);
    const cpu = try w.cpuOwner(ch, events);
    const env = try w.ramEnvironment(ch);
    // LS32 on the odd events, LS-D64 on the even ones: OWNER and RAM close.
    var dword = try D.source.Source.init(a, evens.items, LOG);
    defer dword.deinit();
    const dc = try dword.generate(ch, d16, d8);
    var ls32 = try V2.source.Source.init(a, odds.items, LOG);
    defer ls32.deinit();
    const lc = try ls32.generate(ch, d16, d8);
    try testing.expect(dc.owner.add(lc.owner).add(cpu).isZero());
    try testing.expect(dc.ram.add(lc.ram).sub(env).isZero());
    // The same tuple consumed by both chips leaves CPU-local OWNER debt.
    var both = try V2.source.Source.init(a, events, LOG);
    defer both.deinit();
    const bc = try both.generate(ch, d16, d8);
    var all = try D.source.Source.init(a, events, LOG);
    defer all.deinit();
    const ac = try all.generate(ch, d16, d8);
    try testing.expect(bc.owner.add(cpu).isZero());
    try testing.expect(ac.owner.add(cpu).isZero());
    try testing.expect(!bc.owner.add(ac.owner).add(cpu).isZero());
}

test "LS-D64 packed quotient rows on four workers equal serial accumulation" {
    const engine = @import("stwo_prover_engine");
    const size = 16384;
    const widths = L.widths();
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
    const component = D.component.Component{ .log_size = 13, .rows = 8191, .offsets = .{ 0, 0, 0 }, .claims = D.types.Claims.zero(), .challenges = challenges() };
    var powers: [D.component.CONSTRAINTS]Q = undefined;
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
    // Packed lanes agree with the scalar Q authority on a sample of rows.
    for ([_]usize{ 0, 1, 17, 4095 }) |row| {
        var f: [L.FIXED]Q = undefined;
        var m: [L.MAIN]Q = undefined;
        var i: [L.INTERACTION]Q = undefined;
        for (&f, 0..) |*v, c| v.* = Q.fromBase(views[c][row]);
        for (&m, 0..) |*v, c| v.* = Q.fromBase(views[L.FIXED + c][row]);
        for (&i, 0..) |*v, c| v.* = Q.fromBase(views[L.FIXED + L.MAIN + c][row]);
        var pm: [L.MAIN]Q = @splat(Q.zero());
        var pi: [L.INTERACTION]Q = @splat(Q.zero());
        const prev = core.utils.previousBitReversedCircleDomainIndex(row, 13, 14);
        pm[0] = Q.fromBase(views[L.FIXED][prev]);
        for (&pi, 0..) |*v, c| if (L.previousInter(c)) {
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

// ---- Opt-in fused-pair layout (Geometry.ls_dword_fused_pairs, L.fused) ----
