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
        for (X.layout.U8, 0..) |column, j| {
            inv[1 + X.layout.U16.len + j] = try ch.range8.denominatorFor(Q, m[column]).inv();
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
const Attack = enum { upper_store_b, read_clock, read_write_value, future_epoch, reversed_tick, ghost_cycle };
fn attack(kind: Attack) !void {
    var fixture = try @import("../../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    var setup = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, .{ .cpu_log = 5, .alu_log = 5, .binary_log = 5, .shift_log = 5, .jalr_log = 5, .division_log = 5, .multiplication_log = 5, .ls_log = 5, .boundary_log = 5 });
    defer setup.deinit();
    const admission = Driver.admission(&fixture.image);
    var source = try Sources.Source.init(a, &setup.materials, admission.image, fixture.boundary, 1, &fixture.tape);
    defer source.deinit();
    const request = source.request();
    const pos = R.trace.physical(if (kind == .upper_store_b) 3 else if (kind == .future_epoch or kind == .ghost_cycle) 0 else 1, 5);
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
        .read_write_value => {
            for ([_]usize{ 14, 18, 40 }) |column| {
                m[column * n + pos] = m[column * n + pos].add(M.fromCanonical(65536));
                m[(column + 1) * n + pos] = m[(column + 1) * n + pos].sub(M.one());
            }
            m[V.layout.selected_limb * n + pos] = m[15 * n + pos];
        },
    }
    @import("projection_test_support.zig").projectMatrix(m, source.memory.ls.main, n);
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
