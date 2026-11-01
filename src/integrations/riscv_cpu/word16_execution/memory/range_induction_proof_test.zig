//! Actual valid PCS proofs of false, open LS witnesses. The production closed
//! receiver must reject their unclosed physical OWNER/RAM/range debts.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const X = A.memory.load_store_v2;
const V = A.memory.load_store_v1;
const R = A.memory.closed_ram;
const P = @import("../protocol.zig");
const Mat = @import("../setup.zig");
const Sources = @import("../sources.zig");
const Components = @import("../components.zig").Components;
const Execution = @import("../execution.zig");
const Driver = @import("../driver.zig");
const Q = X.types.Q;
const M = X.types.M;
const a = std.testing.allocator;
const n: usize = 32;
fn repair(main: []const M, inter: []M, ch: X.types.Challenges) !X.types.Claims {
    var claims = X.types.Claims.zero();
    for (0..n) |logical| {
        const pos = R.trace.physical(logical, 5);
        var m: [X.layout.MAIN]Q = undefined;
        for (&m, 0..) |*v, column| v.* = Q.fromBase(main[column * n + pos]);
        const expanded = X.layout.projection.expandFor(Q, &m);
        const before = ch.ram.denominatorFor(Q, R.equations.ramTuple(Q, .transition, expanded[0..28], false));
        const after = ch.ram.denominatorFor(Q, R.equations.ramTuple(Q, .transition, expanded[0..28], true));
        const inverse = try before.mul(after).inv();
        R.trace.store(inter, n, pos, 0, inverse);
        claims.ram = claims.ram.add(after.sub(before).mul(inverse).mul(m[0]));
        R.trace.store(inter, n, pos, 4, claims.ram);
        var inv: [X.layout.LOCAL_FRACTIONS]Q = undefined;
        inv[0] = try ch.owner.denominatorFor(Q, X.equations.ownerTuple(Q, &m)).neg().inv();
        claims.owner = claims.owner.add(inv[0].mul(m[0]));
        for (X.layout.U16, 0..) |column, j| {
            inv[1 + j] = try ch.range16.denominatorFor(Q, m[column]).inv();
            claims.range16 = claims.range16.add(inv[1 + j]);
        }
        for (X.layout.LOGICAL_U8, 0..) |column, j| {
            inv[1 + X.layout.U16.len + j] = try ch.range8.denominatorFor(Q, expanded[column]).inv();
            claims.range8 = claims.range8.add(inv[1 + X.layout.U16.len + j]);
        }
        inv[inv.len - 1] = try ch.selection.denominatorFor(Q, V.equations.selectionTuple(Q, &expanded)).inv();
        claims.selection = claims.selection.add(inv[inv.len - 1]);
        for (0..X.layout.LOCAL_PAIRS) |pair| R.trace.store(inter, n, pos, X.layout.LOCAL_INVERSES + 4 * pair, inv[2 * pair].mul(inv[2 * pair + 1]));
        R.trace.store(inter, n, pos, X.layout.LOCAL_PREFIX, claims.owner.add(claims.range16).add(claims.range8).add(claims.selection));
    }
    R.trace.center(inter, n, 4, claims.ram);
    R.trace.center(inter, n, X.layout.LOCAL_PREFIX, claims.owner.add(claims.range16).add(claims.range8).add(claims.selection));
    return claims;
}
const Attack = enum { upper_store_b, read_clock, read_write_value, future_epoch, reversed_tick, ghost_cycle, store_byte_split, load_c_alias, store_after_alias, lb_false_byte };
/// Which LS ledger shares an LS32 joint-write attack must leave untouched
/// (the removed U16 checks are blind to it) or move (the debt that rejects).
const Shares = struct { ram: bool, owner: bool, selection: bool };
fn jointWriteShares(kind: Attack) ?Shares {
    return switch (kind) {
        // LW row: before/after/C limb0 += 65536. RAM before token and OWNER C move.
        .load_c_alias => .{ .ram = true, .owner = true, .selection = false },
        // SD row: B limb1 and after limb1 += 65536. RAM after token and OWNER B move.
        .store_after_alias => .{ .ram = true, .owner = true, .selection = false },
        // LB row: false selected byte and C limb0 += 65536. Selection and OWNER C move.
        .lb_false_byte => .{ .ram = false, .owner = true, .selection = true },
        else => null,
    };
}

fn attack(kind: Attack) !void {
    var fixture = try @import("../../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    var setup = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, .{ .cpu_log = 5, .alu_log = 5, .binary_log = 5, .shift_log = 5, .jalr_log = 5, .division_log = 5, .multiplication_log = 5, .ls_log = 5, .boundary_log = 5 });
    defer setup.deinit();
    const admission = Driver.admission(&fixture.image);
    var source = try Sources.Source.init(a, &setup.materials, admission.image, fixture.boundary, 1, &fixture.tape);
    defer source.deinit();
    const request = source.request();
    const row: usize = switch (kind) {
        .upper_store_b, .store_byte_split => 3,
        .future_epoch, .ghost_cycle, .store_after_alias => 0,
        .lb_false_byte => 2,
        else => 1,
    };
    const pos = R.trace.physical(row, 5);
    const honest_main = try a.dupe(M, source.memory.ls.main);
    defer a.free(honest_main);
    const m = try @import("projection_test_support.zig").expandMatrix(a, source.memory.ls.main, n);
    defer a.free(m);
    switch (kind) {
        .upper_store_b => {
            m[37 * n + pos] = m[37 * n + pos].add(M.fromCanonical(65536));
            m[38 * n + pos] = m[38 * n + pos].sub(M.one());
        },
        .read_clock => {
            m[10 * n + pos] = M.fromCanonical(core.fields.m31.Modulus - 1);
            m[25 * n + pos] = m[12 * n + pos];
            m[26 * n + pos] = M.zero();
            m[27 * n + pos] = M.zero();
        },
        .ghost_cycle => {
            // Replace INIT->SD->LW by the cycle LW.after->SD->LW.
            // The first two events use the same word and both end at value4096.
            const next = R.trace.physical(1, 5);
            try std.testing.expectEqual(@as(u32, 4096), m[18 * n + pos].v);
            m[2 * n + pos] = M.one();
            m[8 * n + pos] = m[9 * n + next];
            m[10 * n + pos] = m[12 * n + next];
            m[11 * n + pos] = m[13 * n + next];
            for (0..4) |j| m[(14 + j) * n + pos] = m[(18 + j) * n + next];
            m[24 * n + pos] = M.zero();
            m[25 * n + pos] = M.fromCanonical(core.fields.m31.Modulus - 5);
            m[26 * n + pos] = M.zero();
            m[27 * n + pos] = M.zero();
        },
        .future_epoch => {
            m[8 * n + pos] = M.fromCanonical(2);
            m[24 * n + pos] = M.fromCanonical(core.fields.m31.Modulus - 2);
        },
        .reversed_tick => {
            m[10 * n + pos] = m[12 * n + pos].add(M.fromCanonical(4));
            m[25 * n + pos] = M.fromCanonical(core.fields.m31.Modulus - 5);
            m[26 * n + pos] = M.zero();
            m[27 * n + pos] = M.zero();
        },
        .store_byte_split => {
            // Row 3 is SH x4=17: B0=17=b_low+256*b_high with b_high=0. b_low is
            // no longer committed (encoding v5): it is the affine B0-256*b_high.
            // Forge b_high=1. Every local LS/RAM residual still vanishes (SH does
            // not read b_low), but the derived b_low is 17-256 mod p, so only
            // the retained U8 membership of the affine expression rejects.
            try std.testing.expectEqual(@as(u32, 17), m[V.layout.b * n + pos].v);
            try std.testing.expectEqual(@as(u32, 0), m[V.layout.b_high * n + pos].v);
            m[V.layout.b_high * n + pos] = M.one();
        },
        .load_c_alias => {
            try std.testing.expectEqual(@intFromEnum(@import("stwo_riscv_frontend").rv64.decode.Opcode.LW), m[V.layout.opcode * n + pos].v);
            for ([_]usize{ 14, 18, V.layout.c }) |column| m[column * n + pos] = m[column * n + pos].add(M.fromCanonical(65536));
        },
        .store_after_alias => {
            try std.testing.expectEqual(@intFromEnum(@import("stwo_riscv_frontend").rv64.decode.Opcode.SD), m[V.layout.opcode * n + pos].v);
            for ([_]usize{ V.layout.b + 1, 19 }) |column| m[column * n + pos] = m[column * n + pos].add(M.fromCanonical(65536));
        },
        .lb_false_byte => {
            try std.testing.expectEqual(@intFromEnum(@import("stwo_riscv_frontend").rv64.decode.Opcode.LB), m[V.layout.opcode * n + pos].v);
            for ([_]usize{ V.layout.selected_byte, V.layout.c }) |column| m[column * n + pos] = m[column * n + pos].add(M.fromCanonical(65536));
        },
        .read_write_value => {
            for ([_]usize{ 14, 18, 40 }) |column| {
                m[column * n + pos] = m[column * n + pos].add(M.fromCanonical(65536));
                m[(column + 1) * n + pos] = m[(column + 1) * n + pos].sub(M.one());
            }
            m[V.layout.selected_limb * n + pos] = m[15 * n + pos];
        },
    }
    @import("projection_test_support.zig").projectMatrix(m, source.memory.ls.main, n);
    if (kind == .store_byte_split) {
        // The forged physical row satisfies every local LS polynomial.
        var row: [X.layout.MAIN]Q = undefined;
        for (&row, 0..) |*v, column| v.* = Q.fromBase(source.memory.ls.main[column * n + pos]);
        const logical = X.layout.projection.expandFor(Q, &row);
        try std.testing.expect(logical[V.layout.b_low].eql(Q.fromBase(M.fromCanonical(17)).sub(Q.fromBase(M.fromCanonical(256)))));
        var previous: [X.layout.projection.LOGICAL_MAIN]Q = @splat(Q.zero());
        const prior = R.trace.physical(2, 5);
        previous[0] = Q.fromBase(source.memory.ls.main[prior]);
        var residuals: [256]Q = undefined;
        var sink = A.evaluation.Sink{ .values = &residuals };
        const fixed = [_]Q{ Q.zero(), Q.zero(), Q.zero() };
        V.equations.emitLocalWithPublicFor(Q, &fixed, &logical, &previous, Q.fromBase(M.fromCanonical(4)), Q.one(), &sink);
        for (residuals[0..sink.count]) |v| try std.testing.expect(v.isZero());
        // Rebalance the shared U8 table for every representable forged query:
        // b_high 0->1, and withdraw the honest b_low=17. The derived b_low
        // 17-256 has no table row, so no multiplicity assignment can close it.
        const counts = @constCast(source.range8.counts);
        counts[0] -= 1;
        counts[1] += 1;
        counts[17] -= 1;
        for ([_]usize{ 0, 1, 17 }) |value| source.range8.main[R.trace.physical(value, 8)] = M.fromCanonical(@intCast(counts[value]));
    }
    const actual = try a.dupe(M, source.memory.ls.main);
    defer a.free(actual);
    var scheme = try P.T.Scheme.init(a, P.T.P.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = P.T.P.Channel{};
    try P.mix(&channel, &setup, request, admission.image_identity);
    try setup.appendFixed(a, &scheme, &channel);
    const main = try source.columns(a, 1);
    defer a.free(main);
    try scheme.commitBorrowedStreaming(a, main, 8, &channel);
    try source.releaseMain();
    const draw = P.draw(&channel);
    var claims = (try source.generateForDelegationJoin(draw)).physical;
    if (jointWriteShares(kind)) |moved| {
        // Every forged coordinate now lies outside every retained LS32 range
        // query: the range ledger shares equal the honest ones exactly.
        const scratch = try a.alloc(M, X.layout.INTERACTION * n);
        defer a.free(scratch);
        const honest = try repair(honest_main, scratch, draw.memory);
        const forged = try repair(actual, scratch, draw.memory);
        try std.testing.expect(honest.range16.eql(forged.range16));
        try std.testing.expect(honest.range8.eql(forged.range8));
        try std.testing.expectEqual(moved.ram, !honest.ram.eql(forged.ram));
        try std.testing.expectEqual(moved.owner, !honest.owner.eql(forged.owner));
        try std.testing.expectEqual(moved.selection, !honest.selection.eql(forged.selection));
    }
    claims.ls = try repair(actual, source.memory.ls.interaction, draw.memory);
    try std.testing.expectError(error.UnclosedExecutionRelations, claims.validate());
    channel.mixFelts(&claims.values());
    const inter = try source.columns(a, 2);
    defer a.free(inter);
    try scheme.commitBorrowedStreaming(a, inter, 8, &channel);
    source.releaseCommittedInteraction();
    var components = try Components.init(&setup.materials, request, draw, claims);
    const handles = try components.provers(a);
    defer a.free(handles);
    owns = false;
    var result = try engine.prove.proveExWithRecorder(Backend, P.T.P.Hasher, P.T.P.MerkleChannel, a, handles, &channel, scheme, false, null);
    defer result.aux.deinit(a);
    defer result.proof.deinit(a);
    const bytes = try @import("stwo_proof_wire").encodeProofBytesBinary(a, result.proof);
    defer a.free(bytes);
    const encoded = Execution.Encoded{ .bytes = bytes, .claims = claims, .request = request };
    var fresh = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, setup.materials.geometry);
    defer fresh.deinit();
    try @import("boundary_anchor_test.zig").verifyPhysical(&fresh, admission, encoded);
    try std.testing.expectError(error.UnclosedExecutionRelations, Execution.verify(a, &fresh, admission, encoded));
}
test "actual valid physical proof with compensated unused store B fails closed OWNER authority" {
    try attack(.upper_store_b);
}
test "actual valid physical proof with noncanonical before clock fails closed RAM and gap ledger" {
    try attack(.read_clock);
}
test "actual valid physical proof with compensated read and write values fails retained canonical write ranges" {
    try attack(.read_write_value);
}

test "actual valid physical proof with future epoch predecessor fails retained gap and RAM closure" {
    try attack(.future_epoch);
}
test "actual valid physical proof with reversed tick predecessor fails retained gap and RAM closure" {
    try attack(.reversed_tick);
}

test "actual valid physical proof with orphan RAM history cycle fails retained chronology and complete boundary closure" {
    try attack(.ghost_cycle);
}

test "actual valid physical proof with noncanonical derived store byte split fails retained U8 closure" {
    try attack(.store_byte_split);
}

test "LS32 actual valid physical proof with noncanonical LW before after and C limb fails only closed RAM and OWNER debts" {
    try attack(.load_c_alias);
}
test "LS32 actual valid physical proof with noncanonical SD B and after limb fails only closed RAM and OWNER debts" {
    try attack(.store_after_alias);
}
test "LS32 actual valid physical proof with false LB selected byte and noncanonical C fails only selection and OWNER debts" {
    try attack(.lb_false_byte);
}
