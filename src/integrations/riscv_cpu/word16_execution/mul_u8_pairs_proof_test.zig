//! Opt-in MUL byte-pair interaction (Geometry.mul_u8_pairs) end to end: the
//! honest physical proof verifies with a fresh receiver, the CPU-pair and
//! MUL-pair receivers reject each other's proofs, every forged MUL pair-mode
//! witness is rejected by the physical STARK, and an out-of-range byte that
//! keeps every arithmetic residual satisfied is rejected by AND closure.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const Mul = A.arithmetic.multiplication;
const PL = Mul.pairs_layout;
const R = A.memory.closed_ram;
const Tables = A.providers.tables;
const P = @import("protocol.zig");
const Mat = @import("setup.zig");
const Sources = @import("sources.zig");
const Components = @import("components.zig").Components;
const Execution = @import("execution.zig");
const Driver = @import("driver.zig");
const AB = @import("arithmetic_bus.zig");
const Q = A.evaluation.Q;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const MUL_PAIRS = Mat.Geometry{ .cpu_log = 5, .cpu_fused_tail = true, .cpu_u8_pairs = true, .mul_u8_pairs = true };
const CPU_PAIRS = Mat.Geometry{ .cpu_log = 5, .cpu_fused_tail = true, .cpu_u8_pairs = true };
const verifyPhysical = @import("memory/boundary_anchor_test.zig").verifyPhysical;

pub const Tamper = union(enum) {
    none,
    /// Pair inverse column += delta at a row; prefix repaired (claim follows).
    slot: struct { row: usize, column: usize },
    /// Drop one row's first byte-pair fraction and add it back at `to`.
    drop_pair: struct { row: usize, to: usize },
    /// Fused FUNCTION fraction dropped at an active row, compensated at `to`.
    drop_function: struct { row: usize, to: usize },
    /// S += delta at one row only.
    sum: struct { row: usize },
    /// MAIN forgery: CARRY_LOW[k] += 256, CARRY_HIGH[k] -= 1 at `row` (the
    /// integer carry is unchanged, so every arithmetic residual holds) and
    /// the interaction is rebuilt honestly from the forged MAIN. The byte pair
    /// containing 256 has no table row, so the AND relation cannot close.
    out_of_range,
};
const DELTA = Q.fromU32Unchecked(3, 1, 4, 1);

fn rowAt(main: []const M, n: usize, log: u32, logical: usize) [PL.MAIN]Q {
    var row: [PL.MAIN]Q = undefined;
    const pos = R.trace.physical(logical, log);
    for (&row, 0..) |*v, column| v.* = Q.fromBase(main[column * n + pos]);
    return row;
}
/// Independent pair-mode oracle: rebuilds the MUL interaction from committed
/// MAIN with direct field inversions (no dictionary), applies a forgery and
/// returns the MUL claim.
fn repair(main: []const M, inter: []M, log: u32, count: u32, ch: Mul.provider.Challenges, pc: Tables.Challenges, tamper: Tamper) !Q {
    const n = @as(usize, 1) << @intCast(log);
    const increments = try a.alloc(Q, n);
    defer a.free(increments);
    for (0..n) |logical| {
        const pos = R.trace.physical(logical, log);
        const row = rowAt(main, n, log, logical);
        const p = Mul.pairs_provider.nativePairDenominators(&row, pc);
        var increment = Q.zero();
        for (0..PL.PAIR_COLUMNS) |j| {
            var inverse = try p[2 * j].mul(p[2 * j + 1]).inv();
            if (tamper == .slot and tamper.slot.row == logical and tamper.slot.column == j) inverse = inverse.add(DELTA);
            R.trace.store(inter, n, pos, 4 * j, inverse);
            increment = increment.add(p[2 * j].add(p[2 * j + 1]).mul(inverse));
        }
        const active = Mul.provider.active(&row);
        if (!active.isZero()) increment = increment.sub(active.mul(try ch.denominator(&Mul.provider.tuple(&row)).inv()));
        increments[logical] = increment;
        _ = count;
    }
    switch (tamper) {
        .drop_pair => |t| {
            const p = Mul.pairs_provider.nativePairDenominators(&rowAt(main, n, log, t.row), pc);
            const tail = try p[0].inv();
            increments[t.row] = increments[t.row].sub(tail);
            increments[t.to] = increments[t.to].add(tail);
        },
        .drop_function => |t| {
            const row = rowAt(main, n, log, t.row);
            const tail = try ch.denominator(&Mul.provider.tuple(&row)).inv();
            increments[t.row] = increments[t.row].add(tail);
            increments[t.to] = increments[t.to].sub(tail);
        },
        else => {},
    }
    var claim = Q.zero();
    for (0..n) |logical| {
        claim = claim.add(increments[logical]);
        R.trace.store(inter, n, R.trace.physical(logical, log), PL.PREFIX, claim);
    }
    R.trace.center(inter, n, PL.PREFIX, claim);
    if (tamper == .sum) {
        const pos = R.trace.physical(tamper.sum.row, log);
        var value: [4]M = undefined;
        for (&value, 0..) |*v, c| v.* = inter[(PL.PREFIX + c) * n + pos];
        R.trace.store(inter, n, pos, PL.PREFIX, Q.fromM31Array(value).add(DELTA));
    }
    return claim;
}
/// Moves 256 between carry limbs of active row 0: CARRY_LOW[0] += 256 and
/// CARRY_HIGH[0] -= 1 (a field wrap to p-1 when it was zero). The field
/// carry low + 256*high is unchanged, so every arithmetic residual holds, but
/// the BYTE values low+256 and 32*high are no longer canonical bytes.
fn forgeCarry(main: []M, n: usize, log: u32) void {
    const pos = R.trace.physical(0, log);
    const high = &main[Mul.layout.CARRY_HIGH * n + pos];
    const low = &main[Mul.layout.CARRY_LOW * n + pos];
    high.* = high.sub(M.one());
    low.* = low.add(M.fromCanonical(256));
}
const Outcome = struct { physical: bool, full: bool, claim_changed: bool, physical_error: ?anyerror = null };
fn run(tamper: Tamper) !Outcome {
    var fixture = try @import("../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    var setup = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, MUL_PAIRS);
    defer setup.deinit();
    const admission = Driver.admission(&fixture.image);
    var source = try Sources.Source.init(a, &setup.materials, admission.image, fixture.boundary, 1, &fixture.tape);
    defer source.deinit();
    const request = source.request();
    const log = source.multiplication.log_size;
    const n = source.multiplication.domainSize();
    try std.testing.expect(source.multiplication.count >= 2);
    if (tamper == .out_of_range) forgeCarry(source.multiplication.main, n, log);
    const actual = try a.dupe(M, source.multiplication.main);
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
    try std.testing.expectEqual(PL.INTERACTION * n, source.multiplication.interaction.len);
    const honest = try a.dupe(M, source.multiplication.interaction);
    defer a.free(honest);
    const honest_claims = claims;
    try claims.validate();
    claims.multiplication = try repair(actual, source.multiplication.interaction, log, source.multiplication.count, AB.multiplication(draw.cpu.function), draw.and_, tamper);
    if (tamper == .none) {
        // The dictionary-based prover equals the independent direct oracle.
        try std.testing.expect(claims.multiplication.eql(honest_claims.multiplication));
        try std.testing.expectEqualSlices(M, honest, source.multiplication.interaction);
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
    var fresh = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, MUL_PAIRS);
    defer fresh.deinit();
    var physical_error: ?anyerror = null;
    const physical = if (verifyPhysical(&fresh, admission, encoded)) |_| true else |err| blk: {
        physical_error = err;
        break :blk false;
    };
    const full = if (Execution.verify(a, &fresh, admission, encoded)) |_| true else |_| false;
    if (tamper == .none or tamper == .out_of_range) try std.testing.expect(!prover_refused);
    return .{ .physical = physical, .full = full, .claim_changed = !claims.multiplication.eql(honest_claims.multiplication), .physical_error = physical_error };
}

test "byte-pair MUL: honest physical proof verifies with a fresh receiver" {
    const outcome = try run(.none);
    try std.testing.expect(outcome.physical and outcome.full and !outcome.claim_changed);
}
test "byte-pair MUL: forged pair inverses, padding inverses and prefixes are rejected by the physical STARK" {
    // Row 0 is an active MUL request; the last row is padding (pair (0,0) only).
    for ([_]Tamper{
        .{ .slot = .{ .row = 0, .column = 0 } },
        .{ .slot = .{ .row = 1, .column = PL.PAIR_COLUMNS - 1 } },
        .{ .slot = .{ .row = 31, .column = 7 } },
        .{ .sum = .{ .row = 4 } },
    }) |tamper| {
        const outcome = try run(tamper);
        try std.testing.expectEqual(@as(?anyerror, error.OodsNotMatching), outcome.physical_error);
        try std.testing.expect(!outcome.physical);
        try std.testing.expect(!outcome.full);
    }
}
test "byte-pair MUL: dropping a pair or the fused FUNCTION fraction and compensating in S keeps the claim honest yet is rejected" {
    for ([_]Tamper{ .{ .drop_pair = .{ .row = 0, .to = 9 } }, .{ .drop_pair = .{ .row = 30, .to = 2 } }, .{ .drop_function = .{ .row = 1, .to = 20 } } }) |tamper| {
        const outcome = try run(tamper);
        try std.testing.expect(!outcome.claim_changed);
        try std.testing.expectEqual(@as(?anyerror, error.OodsNotMatching), outcome.physical_error);
        try std.testing.expect(!outcome.physical);
        try std.testing.expect(!outcome.full);
    }
}
test "byte-pair MUL: an out-of-range pair element satisfies every MUL residual but cannot close the AND relation" {
    const outcome = try run(.out_of_range);
    // The AIR itself accepts the forged row; only LogUp closure rejects it.
    try std.testing.expect(outcome.physical);
    try std.testing.expect(!outcome.full);
}
test "byte-pair MUL: MUL-pair and CPU-pair receivers reject each other's proofs; exact cell delta and geometry admission" {
    var fixture = try @import("../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    const admission = Driver.admission(&fixture.image);
    var setups: [2]Mat.Setup = undefined;
    var made: usize = 0;
    defer for (setups[0..made]) |*s| s.deinit();
    for ([_]Mat.Geometry{ CPU_PAIRS, MUL_PAIRS }, &setups) |g, *s| {
        s.* = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, g);
        made += 1;
    }
    var proofs: [2]Execution.Encoded = undefined;
    var proved: usize = 0;
    defer for (proofs[0..proved]) |*p| p.deinit(a);
    for (&setups, &proofs) |*s, *p| {
        p.* = try Execution.prove(a, s, admission, fixture.boundary, &fixture.tape, null);
        proved += 1;
    }
    for (&setups, 0..) |*s, i| for (proofs, 0..) |p, j| {
        if (i == j) try Execution.verify(a, s, admission, p) else try std.testing.expect(std.meta.isError(Execution.verify(a, s, admission, p)));
    };
    // Exact committed cells: MUL interaction 200 -> 100 columns x 2^mul_log rows.
    const before = try Mat.G.cells(&setups[0].materials.shapes());
    const after = try Mat.G.cells(&setups[1].materials.shapes());
    const rows = Mat.G.rows(MUL_PAIRS.multiplication_log);
    try std.testing.expectEqual(before.fixed, after.fixed);
    try std.testing.expectEqual(before.main, after.main);
    try std.testing.expectEqual(before.interaction - 100 * rows, after.interaction);
    try std.testing.expectEqual(@as(usize, 100), PL.INTERACTION);
    // Mass: MUL bytes leave range8 and join the AND relation.
    try std.testing.expectEqual((try CPU_PAIRS.range8Mass()) - Mul.layout.BYTE_QUERIES * rows, try MUL_PAIRS.range8Mass());
    try std.testing.expectEqual((try CPU_PAIRS.andMass()) + PL.PAIR_QUERIES * rows, try MUL_PAIRS.andMass());
    // MUL pairs require the CPU pair layout (its AND table pair column).
    try std.testing.expectError(error.InvalidMulPairGeometry, (Mat.Geometry{ .cpu_log = 5, .cpu_fused_tail = true, .mul_u8_pairs = true }).validate());
    const old_json = try std.json.Stringify.valueAlloc(a, CPU_PAIRS, .{});
    defer a.free(old_json);
    try std.testing.expect(std.mem.indexOf(u8, old_json, "mul_u8_pairs") == null);
    const new_json = try std.json.Stringify.valueAlloc(a, MUL_PAIRS, .{});
    defer a.free(new_json);
    try std.testing.expect(std.mem.indexOf(u8, new_json, "\"mul_u8_pairs\":true") != null);
    var parsed = try std.json.parseFromSlice(Mat.Geometry, a, new_json, .{});
    defer parsed.deinit();
    try std.testing.expect(std.meta.eql(parsed.value, MUL_PAIRS));
}
