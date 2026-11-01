//! Deliberately bypasses native canonical projections. The full physical proof
//! is valid and its global ledger closes; only independently anchored boundary
//! tuple authority rejects it. Never expose this permissive verifier in code.
//!
//! Since the public-sortedness trim (rv64-boundary-public-sortedness-v1) the
//! INIT/TEARDOWN chips carry no in-chip gap/carry/inverse or U16 lookups. Each
//! attack below constructs a witness that the REMOVED checks used to reject
//! (noncanonical limb, duplicated address, out-of-range value) and shows the
//! remaining argument (exact expectedClaim comparison + AIR prefix binding)
//! rejects it. An unsorted permutation of the exact public set is accepted:
//! it is the same RAM14 multiset, hence the same statement.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const R = A.memory.closed_ram;
const X = A.memory.load_store_v2;
const Mat = @import("../setup.zig");
const P = @import("../protocol.zig");
const Sources = @import("../sources.zig");
const Components = @import("../components.zig").Components;
const Execution = @import("../execution.zig");
const Driver = @import("../driver.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;
const n: usize = 32;
const W = X.layout.BOUND_MAIN;
pub const Attack = enum {
    /// Same integer address, non-canonical limbs (limb0 + 2^16, limb1 - 1).
    noncanonical_address_limb,
    /// Row 2 duplicates row 1 (address repeated, the third public cell omitted).
    duplicate_address,
    /// Value limb outside u16 (no compensating limb).
    out_of_range_value,
    /// Rows 1 and 2 swapped: unsorted, but the exact public multiset.
    unsorted_permutation,
};
fn cell(main: []M, row: usize, column: usize) *M {
    return &main[column * n + R.trace.physical(row, 5)];
}
fn ghostMain(main: []M, attack: Attack) void {
    switch (attack) {
        .noncanonical_address_limb => {
            cell(main, 2, 1).* = cell(main, 2, 1).add(M.fromCanonical(65536));
            cell(main, 2, 2).* = cell(main, 2, 2).sub(M.one());
        },
        .duplicate_address => for (0..W) |c| {
            cell(main, 2, c).* = cell(main, 1, c).*;
        },
        .out_of_range_value => cell(main, 2, 5).* = M.fromCanonical(70000),
        .unsorted_permutation => for (0..W) |c| {
            const t = cell(main, 1, c).*;
            cell(main, 1, c).* = cell(main, 2, c).*;
            cell(main, 2, c).* = t;
        },
    }
}
fn repairRam(main: []const M, source: *X.boundary_source.Source, ch: R.types.RamChallenges) !Q {
    var sum = Q.zero();
    for (0..n) |logical| {
        const pos = R.trace.physical(logical, 5);
        var row: [W]Q = undefined;
        for (&row, 0..) |*v, c| v.* = Q.fromBase(main[c * n + pos]);
        const inv = try ch.denominatorFor(Q, R.equations.ramTuple(Q, if (source.kind == .initial) .initial else .terminal, &row, false)).inv();
        R.trace.store(source.interaction, n, pos, 0, inv);
        const value = inv.mul(row[0]);
        sum = if (source.kind == .initial) sum.sub(value) else sum.add(value);
        R.trace.store(source.interaction, n, pos, 4, sum);
    }
    R.trace.center(source.interaction, n, 4, sum);
    return sum;
}
pub fn verifyPhysical(setup: *const Mat.Setup, admission: Execution.Admission, encoded: Execution.Encoded) !void {
    const wire = @import("stwo_proof_wire");
    var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(P.T.P.Hasher, P.T.P.MerkleChannel).init(a, P.T.P.config());
    defer verifier.deinit(a);
    var channel = P.T.P.Channel{};
    try P.mix(&channel, setup, encoded.request, admission.image_identity);
    for ([_]usize{ 0, 1 }) |tree| {
        const logs = try setup.materials.logs(a, tree);
        defer a.free(logs);
        try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[tree], logs, &channel);
    }
    const draw = P.draw(&channel);
    channel.mixFelts(&encoded.claims.values());
    const logs = try setup.materials.logs(a, 2);
    defer a.free(logs);
    try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[2], logs, &channel);
    var components = try Components.init(&setup.materials, encoded.request, draw, encoded.claims);
    const handles = try components.verifiers(a);
    defer a.free(handles);
    owns = false;
    try core.verifier.verify(P.T.P.Hasher, P.T.P.MerkleChannel, a, handles, &channel, &verifier, proof);
}
fn runAttack(attack: Attack) !void {
    var fixture = try @import("../../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    var setup = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, .{ .cpu_log = 5, .alu_log = 5, .binary_log = 5, .shift_log = 5, .jalr_log = 5, .division_log = 5, .multiplication_log = 5, .ls_log = 5, .boundary_log = 5 });
    defer setup.deinit();
    const admission = Driver.admission(&fixture.image);
    var prepared = try Sources.Prepared.init(a, &setup.materials.program, fixture.boundary, 1, 5, &fixture.tape, .{ .deduplicate_binary = false, .jalr_log = 5 });
    defer prepared.deinit();
    var collected = try @import("collector.zig").collect(a, admission.image, prepared.cpu.?.memory.items, 1);
    defer collected.deinit();
    try std.testing.expectEqual(@as(usize, 1), collected.initial.len);
    const initial = try a.alloc(R.types.Cell, 3);
    const terminal = try a.alloc(R.types.Cell, 3);
    initial[0] = collected.initial[0];
    terminal[0] = collected.terminal[0];
    for ([_]u64{ 0x2108000, 0x2112000 }, 1..) |address, j| {
        initial[j] = .{ .address = address, .state = .{ .value = 0, .rights = 3 } };
        terminal[j] = initial[j]; // Untouched words carry the same canonical state.
    }
    const memory = try @import("prepared.zig").Prepared.initOwnedForGlobalRamIndependent(a, collected.events, initial, terminal, 1, 5, 5, 5);
    var source = try Sources.Source.fromPreparedWithOwnedMemory(a, &setup.materials, &prepared, memory);
    defer source.deinit();
    const request = source.request();
    try admission.validate(&setup, request);
    ghostMain(source.memory.initial.main, attack);
    ghostMain(source.memory.terminal.main, attack);
    const im = try a.dupe(M, source.memory.initial.main);
    defer a.free(im);
    const tm = try a.dupe(M, source.memory.terminal.main);
    defer a.free(tm);
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
    var claims = try source.generate(draw);
    claims.initial.ram = try repairRam(im, &source.memory.initial, draw.memory.ram);
    claims.terminal.ram = try repairRam(tm, &source.memory.terminal, draw.memory.ram);
    try claims.validate(); // Ghost debts cancel; aggregate-only validation passes.
    const expected_initial = try X.boundary_source.expectedClaim(request.memory.initial, true, draw.memory.ram);
    const expected_terminal = try X.boundary_source.expectedClaim(request.memory.terminal, false, draw.memory.ram);
    const same_multiset = attack == .unsorted_permutation;
    try std.testing.expectEqual(same_multiset, claims.initial.ram.eql(expected_initial));
    try std.testing.expectEqual(same_multiset, claims.terminal.ram.eql(expected_terminal));
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
    var encoded = Execution.Encoded{ .bytes = bytes, .claims = claims, .request = request };
    // Fresh key and actual polynomial verification demonstrate this is not
    // rejection by native advice construction or a broken underlying proof:
    // the remaining AIR alone accepts every ghost (the trimmed in-chip checks
    // are really gone), so rejection below is owned by expectedClaim.
    var fresh = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, setup.materials.geometry);
    defer fresh.deinit();
    try verifyPhysical(&fresh, admission, encoded);
    if (same_multiset) {
        // Order is not part of the statement: same RAM14 multiset, same debt.
        try Execution.verify(a, &fresh, admission, encoded);
        return;
    }
    try std.testing.expectError(error.UntrustedWord16MemoryBoundaryClaim, Execution.verify(a, &fresh, admission, encoded));
    // Replacing both ghosts with public debts preserves closure but the AIR
    // prefix binding (claim vs committed interaction sum) and FS then fail.
    encoded.claims.initial.ram = expected_initial;
    encoded.claims.terminal.ram = expected_terminal;
    try encoded.claims.validate();
    if (Execution.verify(a, &fresh, admission, encoded)) |_| return error.ReboundBoundaryProofAccepted else |_| {}
    if (verifyPhysical(&fresh, admission, encoded)) |_| return error.ReboundBoundaryProofAccepted else |_| {}
}
test "valid full proof with balanced noncanonical boundary ghosts is rejected by independent RAM tuple authority" {
    try runAttack(.noncanonical_address_limb);
}
test "trimmed boundary chip: duplicated INIT/TEARDOWN address proves physically but is rejected by expectedClaim" {
    try runAttack(.duplicate_address);
}
test "trimmed boundary chip: out-of-range value limb proves physically but is rejected by expectedClaim" {
    try runAttack(.out_of_range_value);
}
test "trimmed boundary chip: unsorted permutation of the exact public set is the same statement and verifies" {
    try runAttack(.unsorted_permutation);
}
test "trimmed boundary chip: nonzero boundary range claims are rejected before and inside the AIR" {
    var claims = std.mem.zeroes(P.Claims);
    claims.initial.range16 = Q.one();
    claims.r16 = Q.one().neg();
    try std.testing.expectError(error.NonzeroOmittedBoundaryRangeClaim, claims.validate());
    try std.testing.expectError(error.NonzeroOmittedBoundaryRangeClaim, Sources.validateCanonicalClaims(claims));
    // The AIR pins both range claims as constant residuals on every row.
    var ch: X.types.Challenges = undefined;
    ch.ram.offset = Q.fromU32Unchecked(7, 1, 2, 3);
    for (&ch.ram.coefficients, 0..) |*c, i| c.* = Q.fromU32Unchecked(@intCast(i + 11), 5, 6, 7);
    const f: [3]Q = .{ Q.zero(), Q.zero(), Q.zero() };
    const m: [W]Q = @splat(Q.zero());
    const inter: [X.layout.BOUND_INTERACTION]Q = @splat(Q.zero());
    const inverse = try ch.ram.denominatorFor(Q, R.equations.ramTuple(Q, .initial, &m, false)).inv();
    var i = inter;
    for (inverse.toM31Array(), 0..) |v, c| i[c] = Q.fromBase(v);
    var values: [X.layout.constraints(.initial)]Q = undefined;
    for ([_]bool{ false, true }) |range8| {
        var bad = X.types.Claims.zero();
        if (range8) bad.range8 = Q.one() else bad.range16 = Q.one();
        var sink = A.evaluation.Sink{ .values = &values };
        X.equations.emitFor(Q, .initial, &f, &m, &m, &i, &inter, 0, bad, ch, &sink);
        try std.testing.expectEqual(X.layout.constraints(.initial), sink.count);
        var nonzero: usize = 0;
        for (values) |v| nonzero += @intFromBool(!v.isZero());
        try std.testing.expectEqual(@as(usize, 1), nonzero);
    }
}
