//! Opt-in byte-pair CPU interaction (Geometry.cpu_u8_pairs) end to end: the
//! honest physical proof verifies with a fresh receiver, fused and pair
//! receivers reject each other's proofs, and every forged pair-mode witness
//! (CPU or AND pair table) is rejected by the physical STARK.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const X = A.word16_execution;
const R = A.memory.closed_ram;
const Tables = A.providers.tables;
const P = @import("protocol.zig");
const Mat = @import("setup.zig");
const Sources = @import("sources.zig");
const Components = @import("components.zig").Components;
const Execution = @import("execution.zig");
const Driver = @import("driver.zig");
const Q = A.evaluation.Q;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const n: usize = 32;
const PAIRS = Mat.Geometry{ .cpu_log = 5, .cpu_fused_tail = true, .cpu_u8_pairs = true };
const FUSED = Mat.Geometry{ .cpu_log = 5, .cpu_fused_tail = true };
const LEGACY = Mat.Geometry{ .cpu_log = 5 };
const verifyPhysical = @import("memory/boundary_anchor_test.zig").verifyPhysical;

pub const Tamper = union(enum) {
    none,
    /// CPU witness slot += delta at a row; prefix repaired (claim follows).
    slot: struct { row: usize, slot: usize },
    /// FUNCTION/ROM slot := bare inverse 1/d (legacy strict form); prefix repaired.
    bare_inverse: struct { row: usize, slot: usize },
    /// Drop one row's two byte-pair fractions and add them back at `to`.
    drop_pairs: struct { row: usize, to: usize },
    /// S += delta at one row only.
    sum: struct { row: usize },
    /// AND pair table: pair inverse += delta at one row, its prefix repaired.
    table_inverse: struct { row: usize },
};
const DELTA = Q.fromU32Unchecked(3, 1, 4, 1);
fn rowAt(main: []const M, logical: usize) [X.layout.main.COUNT]M {
    var row: [X.layout.main.COUNT]M = undefined;
    const pos = R.trace.physical(logical, 5);
    for (&row, 0..) |*v, column| v.* = main[column * n + pos];
    return row;
}
fn fixedAt(logical: usize) [3]M {
    return .{ M.fromCanonical(@intCast(logical)), M.fromCanonical(@intFromBool(logical == 0)), M.fromCanonical(@intFromBool(logical == n - 1)) };
}
/// Rewrites the pair-mode CPU interaction from MAIN with an optional forgery
/// and returns the resulting CPU claim (the full prefix total).
pub fn repairPairs(main: []const M, inter: []M, public: X.types.Inputs, ch: X.types.Challenges, pc: Tables.Challenges, tamper: Tamper) !Q {
    const L = X.layout.pairs;
    var increments: [n]Q = undefined;
    for (0..n) |logical| {
        const pos = R.trace.physical(logical, 5);
        const row = rowAt(main, logical);
        const fixed = fixedAt(logical);
        const ds = X.equations.nativeDenominators(&fixed, &row, public, ch);
        var witness = try X.equations.nativePairWitnesses(ds, &row);
        switch (tamper) {
            .slot => |t| if (t.row == logical) {
                witness[t.slot] = witness[t.slot].add(DELTA);
            },
            .bare_inverse => |t| if (t.row == logical) {
                witness[t.slot] = try (if (t.slot == 3) ds.function else ds.rom).inv();
            },
            else => {},
        }
        for (witness, 0..) |value, i| R.trace.store(inter, n, pos, 4 * i, value);
        increments[logical] = try X.equations.nativePairContribution(&row, pc, witness);
    }
    if (tamper == .drop_pairs) {
        const t = tamper.drop_pairs;
        const p = X.equations.nativePairDenominators(&rowAt(main, t.row), pc);
        const tail = (try p[0].inv()).add(try p[1].inv());
        increments[t.row] = increments[t.row].sub(tail);
        increments[t.to] = increments[t.to].add(tail);
    }
    var claim = Q.zero();
    for (0..n) |logical| {
        claim = claim.add(increments[logical]);
        R.trace.store(inter, n, R.trace.physical(logical, 5), L.sum, claim);
    }
    R.trace.center(inter, n, L.sum, claim);
    if (tamper == .sum) {
        const pos = R.trace.physical(tamper.sum.row, 5);
        var value: [4]M = undefined;
        for (&value, 0..) |*v, c| v.* = inter[(L.sum + c) * n + pos];
        R.trace.store(inter, n, pos, L.sum, Q.fromM31Array(value).add(DELTA));
    }
    return claim;
}
fn readQ(data: []const M, size: usize, row: usize, column: usize) Q {
    return Q.fromM31(data[column * size + row], data[(column + 1) * size + row], data[(column + 2) * size + row], data[(column + 3) * size + row]);
}
/// AND pair table forgery: one inverse += delta, then the prefix is rebuilt
/// from the forged inverse so that only the inverse residual can reject.
fn forgeTable(request: *Tables.Request, setup: *const Tables.Setup, ch: Tables.Challenges, logical: usize) !Q {
    const size = Tables.Kind.byte_and.size();
    const physical = A.witness.physical;
    var sum = Q.zero();
    for (0..size) |i| {
        const row = physical(i, 16);
        var inverse = readQ(request.interaction, size, row, 0);
        if (i == logical) {
            inverse = inverse.add(DELTA);
            for (inverse.toM31Array(), 0..) |coordinate, c| request.interaction[c * size + row] = coordinate;
        }
        var tuple: [3]Q = undefined;
        for (&tuple, 0..) |*value, c| value.* = Q.fromBase(setup.fixed[c * size + row]);
        const d = ch.denominator(&tuple);
        const p = Tables.pairDenominatorFor(Q, ch, tuple[0], tuple[1]);
        sum = sum.sub(p.mulM31(request.main[row]).add(d.mulM31(request.main[size + row])).mul(inverse));
        for (sum.toM31Array(), 0..) |coordinate, c| request.interaction[(4 + c) * size + row] = coordinate;
    }
    return sum;
}
const Outcome = struct { physical: bool, full: bool, claim_changed: bool, physical_error: ?anyerror = null };
fn run(tamper: Tamper) !Outcome {
    var fixture = try @import("../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    var setup = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, PAIRS);
    defer setup.deinit();
    const admission = Driver.admission(&fixture.image);
    var source = try Sources.Source.init(a, &setup.materials, admission.image, fixture.boundary, 1, &fixture.tape);
    defer source.deinit();
    const request = source.request();
    const actual = try a.dupe(M, source.cpu.main);
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
    try std.testing.expectEqual(X.layout.pairs.COUNT * n, source.cpu.interaction.len);
    try std.testing.expectEqual(2 * Tables.Kind.byte_and.size(), source.and_table.main.len);
    const honest = try a.dupe(M, source.cpu.interaction);
    defer a.free(honest);
    const honest_claims = claims;
    try claims.validate();
    claims.cpu = try repairPairs(actual, source.cpu.interaction, try X.types.inputs(request.cpu, request.epoch, 5), draw.cpu, draw.and_, tamper);
    if (tamper == .table_inverse) claims.and_table = try forgeTable(&source.and_table, &setup.materials.and_table, draw.and_, tamper.table_inverse.row);
    if (tamper == .none) {
        try std.testing.expect(claims.cpu.eql(honest_claims.cpu));
        try std.testing.expectEqualSlices(M, honest, source.cpu.interaction);
    }
    channel.mixFelts(&claims.values());
    const inter = try source.columns(a, 2);
    defer a.free(inter);
    try scheme.commitBorrowedStreaming(a, inter, 8, &channel);
    source.releaseCommittedInteraction();
    var components = try Components.init(&setup.materials, request, draw, claims);
    const handles = try components.provers(a);
    defer a.free(handles);
    owns = false;
    var diagnostic: ?@import("stwo_prover_api").ProveDiagnostic = null;
    var failed: ?core.proof.ExtendedStarkProof(P.T.P.Hasher) = null;
    var prover_refused = false;
    var result = engine.prove.proveExWithExecutionDiagnosedRetainingFailure(Backend, P.T.P.Hasher, P.T.P.MerkleChannel, a, handles, &channel, scheme, false, null, null, null, &diagnostic, &failed) catch |err| blk: {
        if (err != error.ConstraintsNotSatisfied) return err;
        prover_refused = true;
        break :blk failed orelse return error.MissingUnverifiedAdversarialProof;
    };
    defer result.aux.deinit(a);
    defer result.proof.deinit(a);
    const bytes = try @import("stwo_proof_wire").encodeProofBytesBinary(a, result.proof);
    defer a.free(bytes);
    const encoded = Execution.Encoded{ .bytes = bytes, .claims = claims, .request = request };
    var fresh = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, PAIRS);
    defer fresh.deinit();
    var physical_error: ?anyerror = null;
    const physical = if (verifyPhysical(&fresh, admission, encoded)) |_| true else |err| blk: {
        physical_error = err;
        break :blk false;
    };
    const full = if (Execution.verify(a, &fresh, admission, encoded)) |_| true else |_| false;
    if (tamper == .none) try std.testing.expect(!prover_refused);
    return .{ .physical = physical, .full = full, .claim_changed = !claims.cpu.eql(honest_claims.cpu) or !claims.and_table.eql(honest_claims.and_table), .physical_error = physical_error };
}

test "byte-pair CPU: honest physical proof verifies with a fresh pair receiver" {
    const outcome = try run(.none);
    try std.testing.expect(outcome.physical and outcome.full and !outcome.claim_changed);
}
test "byte-pair CPU: forged fractions, bare inverses, prefixes and AND pair-table inverses are rejected by the physical STARK" {
    // Row 0 retires LUI (rd slot 2 enabled); row 31 is the mandatory padding row (all weights zero).
    for ([_]Tamper{
        .{ .slot = .{ .row = 0, .slot = 2 } },
        .{ .slot = .{ .row = 0, .slot = 0 } },
        .{ .slot = .{ .row = 0, .slot = 3 } },
        .{ .slot = .{ .row = 0, .slot = 4 } },
        .{ .slot = .{ .row = 7, .slot = 5 } },
        .{ .slot = .{ .row = 3, .slot = 6 } },
        .{ .slot = .{ .row = 31, .slot = 3 } },
        .{ .bare_inverse = .{ .row = 31, .slot = 3 } },
        .{ .bare_inverse = .{ .row = 31, .slot = 4 } },
        .{ .sum = .{ .row = 3 } },
        .{ .table_inverse = .{ .row = 0 } },
        .{ .table_inverse = .{ .row = 3 * 256 + 5 } },
    }) |tamper| {
        const outcome = try run(tamper);
        try std.testing.expectEqual(@as(?anyerror, error.OodsNotMatching), outcome.physical_error);
        try std.testing.expect(!outcome.physical);
        try std.testing.expect(!outcome.full);
    }
}
test "byte-pair CPU: dropping a row's byte pairs and compensating in S keeps every claim honest yet is rejected" {
    const outcome = try run(.{ .drop_pairs = .{ .row = 2, .to = 11 } });
    try std.testing.expect(!outcome.claim_changed);
    try std.testing.expectEqual(@as(?anyerror, error.OodsNotMatching), outcome.physical_error);
    try std.testing.expect(!outcome.physical);
    try std.testing.expect(!outcome.full);
}
test "byte-pair CPU: pair, fused and legacy receivers reject each other's proofs; exact cell delta" {
    var fixture = try @import("../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    const admission = Driver.admission(&fixture.image);
    var setups: [3]Mat.Setup = undefined;
    var made: usize = 0;
    defer for (setups[0..made]) |*s| s.deinit();
    for ([_]Mat.Geometry{ LEGACY, FUSED, PAIRS }, &setups) |g, *s| {
        s.* = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, g);
        made += 1;
    }
    var proofs: [3]Execution.Encoded = undefined;
    var proved: usize = 0;
    defer for (proofs[0..proved]) |*p| p.deinit(a);
    for (&setups, &proofs) |*s, *p| {
        p.* = try Execution.prove(a, s, admission, fixture.boundary, &fixture.tape, null);
        proved += 1;
    }
    for (&setups, 0..) |*s, i| for (proofs, 0..) |p, j| {
        if (i == j) try Execution.verify(a, s, admission, p) else try std.testing.expect(std.meta.isError(Execution.verify(a, s, admission, p)));
    };
    // Exact committed cells: CPU interaction -4 columns x 2^cpu_log rows and
    // AND table +1 MAIN column x 2^16 rows versus the fused layout.
    const f = try Mat.G.cells(&setups[1].materials.shapes());
    const p = try Mat.G.cells(&setups[2].materials.shapes());
    try std.testing.expectEqual(f.fixed, p.fixed);
    try std.testing.expectEqual(f.main + 65536, p.main);
    try std.testing.expectEqual(f.interaction - 4 * n, p.interaction);
    // Pair geometry requires the fused tail; JSON omits the flag when false.
    try std.testing.expectError(error.InvalidCpuPairGeometry, (Mat.Geometry{ .cpu_log = 5, .cpu_u8_pairs = true }).validate());
    const fused_json = try std.json.Stringify.valueAlloc(a, FUSED, .{});
    defer a.free(fused_json);
    try std.testing.expect(std.mem.indexOf(u8, fused_json, "cpu_u8_pairs") == null);
    const pair_json = try std.json.Stringify.valueAlloc(a, PAIRS, .{});
    defer a.free(pair_json);
    try std.testing.expect(std.mem.indexOf(u8, pair_json, "\"cpu_u8_pairs\":true") != null);
    var parsed = try std.json.parseFromSlice(Mat.Geometry, a, pair_json, .{});
    defer parsed.deinit();
    try std.testing.expect(std.meta.eql(parsed.value, PAIRS));
}
