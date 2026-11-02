//! Opt-in fused-tail CPU interaction (Geometry.cpu_fused_tail) end to end:
//! the honest physical proof verifies with a fresh receiver, legacy and fused
//! receivers reject each other's proofs, and every forged fused witness is
//! rejected by the physical STARK even when the prefix is repaired.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const A = @import("stwo_riscv_frontend").rv64_air;
const X = A.word16_execution;
const R = A.memory.closed_ram;
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
const FUSED = Mat.Geometry{ .cpu_log = 5, .cpu_fused_tail = true };
const LEGACY = Mat.Geometry{ .cpu_log = 5 };
const verifyPhysical = @import("memory/boundary_anchor_test.zig").verifyPhysical;

pub const Tamper = union(enum) {
    none,
    /// R_s += delta at a row; prefix repaired (claim follows).
    register: struct { row: usize, slot: usize },
    /// R_s := 1/(before*after), the legacy inverse value; prefix repaired.
    bare_inverse: struct { row: usize, slot: usize },
    /// OWNER+U16 pair fraction += delta; prefix repaired.
    owner: struct { row: usize },
    /// Drop the fused U8 tail at `row` and add it back at `to`: every
    /// witness and the global claim stay honest; only the prefix path moves.
    drop_tail: struct { row: usize, to: usize },
    /// S += delta at one row only.
    sum: struct { row: usize },
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
/// Rewrites the fused CPU interaction from MAIN with an optional forgery and
/// returns the resulting CPU claim (the full prefix total).
pub fn repairFused(main: []const M, inter: []M, public: X.types.Inputs, ch: X.types.Challenges, tamper: Tamper) !Q {
    const L = X.layout.fused;
    var increments: [n]Q = undefined;
    for (0..n) |logical| {
        const pos = R.trace.physical(logical, 5);
        const row = rowAt(main, logical);
        const fixed = fixedAt(logical);
        const ds = X.equations.nativeDenominators(&fixed, &row, public, ch);
        var witness = try X.equations.nativeFusedWitnesses(ds, &row);
        switch (tamper) {
            .register => |t| if (t.row == logical) {
                witness[t.slot] = witness[t.slot].add(DELTA);
            },
            .bare_inverse => |t| if (t.row == logical) {
                witness[t.slot] = try ds.before[t.slot].mul(ds.after[t.slot]).inv();
            },
            .owner => |t| if (t.row == logical) {
                witness[5] = witness[5].add(DELTA);
            },
            else => {},
        }
        for (witness, 0..) |value, i| R.trace.store(inter, n, pos, 4 * i, value);
        increments[logical] = try X.equations.nativeFusedContribution(ds, &row, witness);
    }
    if (tamper == .drop_tail) {
        const t = tamper.drop_tail;
        const row = rowAt(main, t.row);
        const tail = try X.equations.nativeDenominators(&fixedAt(t.row), &row, public, ch).affine[6].inv();
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
const Outcome = struct { physical: bool, full: bool, claim_changed: bool, physical_error: ?anyerror = null };
/// Proves the fixture under FUSED geometry with the CPU interaction rewritten
/// by `repairFused`. Returns whether a fresh fused receiver accepts.
fn run(tamper: Tamper) !Outcome {
    var fixture = try @import("../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    var setup = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, FUSED);
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
    try std.testing.expectEqual(X.layout.fused.COUNT * n, source.cpu.interaction.len);
    const honest = try a.dupe(M, source.cpu.interaction);
    defer a.free(honest);
    const honest_claim = claims.cpu;
    try claims.validate();
    claims.cpu = try repairFused(actual, source.cpu.interaction, try X.types.inputs(request.cpu, request.epoch, 5), draw.cpu, tamper);
    // The repair helper is faithful: untampered it reproduces the native fill.
    if (tamper == .none) {
        try std.testing.expect(claims.cpu.eql(honest_claim));
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
    // A forged trace makes the honest prover's own OODS self-check refuse;
    // the retained proof is then handed to fresh receivers, as a malicious
    // prover would.
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
    var fresh = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, FUSED);
    defer fresh.deinit();
    var physical_error: ?anyerror = null;
    const physical = if (verifyPhysical(&fresh, admission, encoded)) |_| true else |err| blk: {
        physical_error = err;
        break :blk false;
    };
    const full = if (Execution.verify(a, &fresh, admission, encoded)) |_| true else |_| false;
    if (tamper == .none) try std.testing.expect(!prover_refused);
    return .{ .physical = physical, .full = full, .claim_changed = !claims.cpu.eql(honest_claim), .physical_error = physical_error };
}

test "fused-tail CPU: honest physical proof verifies with a fresh fused receiver" {
    const outcome = try run(.none);
    try std.testing.expect(outcome.physical and outcome.full and !outcome.claim_changed);
}
test "fused-tail CPU: forged fraction, inverse, owner and prefix witnesses are rejected by the physical STARK" {
    // Row 0 retires LUI: its rd slot (2) is enabled; slot 0 (x0 source) is disabled.
    for ([_]Tamper{
        .{ .register = .{ .row = 0, .slot = 2 } },
        .{ .register = .{ .row = 0, .slot = 0 } },
        .{ .register = .{ .row = 9, .slot = 1 } },
        .{ .bare_inverse = .{ .row = 0, .slot = 2 } },
        .{ .owner = .{ .row = 0 } },
        .{ .owner = .{ .row = 7 } },
        .{ .sum = .{ .row = 3 } },
    }) |tamper| {
        const outcome = try run(tamper);
        // Rejected by the constraint (OODS) check itself, not by an unrelated shape error.
        try std.testing.expectEqual(@as(?anyerror, error.OodsNotMatching), outcome.physical_error);
        try std.testing.expect(!outcome.physical);
        try std.testing.expect(!outcome.full);
    }
}
test "fused-tail CPU: dropping the fused U8 tail and compensating in S keeps every claim honest yet is rejected" {
    const outcome = try run(.{ .drop_tail = .{ .row = 2, .to = 11 } });
    // The ledger is untouched, so only the fused prefix residual can reject.
    try std.testing.expect(!outcome.claim_changed);
    try std.testing.expectEqual(@as(?anyerror, error.OodsNotMatching), outcome.physical_error);
    try std.testing.expect(!outcome.physical);
    try std.testing.expect(!outcome.full);
}
test "fused-tail CPU: legacy and fused receivers reject each other's proofs; legacy shapes and JSON unchanged" {
    var fixture = try @import("../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    const admission = Driver.admission(&fixture.image);
    var legacy = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, LEGACY);
    defer legacy.deinit();
    var fused = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, FUSED);
    defer fused.deinit();
    var fused_proof = try Execution.prove(a, &fused, admission, fixture.boundary, &fixture.tape, null);
    defer fused_proof.deinit(a);
    var legacy_proof = try Execution.prove(a, &legacy, admission, fixture.boundary, &fixture.tape, null);
    defer legacy_proof.deinit(a);
    try Execution.verify(a, &fused, admission, fused_proof);
    try Execution.verify(a, &legacy, admission, legacy_proof);
    try std.testing.expect(std.meta.isError(Execution.verify(a, &legacy, admission, fused_proof)));
    try std.testing.expect(std.meta.isError(Execution.verify(a, &fused, admission, legacy_proof)));
    // Exact committed-cell delta: -4 interaction columns x 2^cpu_log rows.
    const l = try Mat.G.cells(&legacy.materials.shapes());
    const f = try Mat.G.cells(&fused.materials.shapes());
    try std.testing.expectEqual(l.fixed, f.fixed);
    try std.testing.expectEqual(l.main, f.main);
    try std.testing.expectEqual(l.interaction - 4 * n, f.interaction);
    // Legacy geometry JSON carries no new field; fused round-trips.
    const legacy_json = try std.json.Stringify.valueAlloc(a, LEGACY, .{});
    defer a.free(legacy_json);
    try std.testing.expect(std.mem.indexOf(u8, legacy_json, "cpu_fused_tail") == null);
    try std.testing.expect(std.mem.indexOf(u8, legacy_json, "\"initial_log\":null") != null);
    const fused_json = try std.json.Stringify.valueAlloc(a, FUSED, .{});
    defer a.free(fused_json);
    try std.testing.expect(std.mem.indexOf(u8, fused_json, "\"cpu_fused_tail\":true") != null);
    // Byte identity against the historical Geometry shape (no new field), in
    // the exact bundle.json formatting.
    const Historical = comptime blk: {
        const fields = std.meta.fields(Mat.Geometry);
        var out: [fields.len - 2]std.builtin.Type.StructField = undefined;
        var i: usize = 0;
        for (fields) |field| if (!std.mem.eql(u8, field.name, "cpu_fused_tail") and !std.mem.eql(u8, field.name, "cpu_u8_pairs")) {
            out[i] = field;
            i += 1;
        };
        break :blk @Type(.{ .@"struct" = .{ .layout = .auto, .fields = &out, .decls = &.{}, .is_tuple = false } });
    };
    var historical: Historical = undefined;
    inline for (std.meta.fields(Historical)) |field| @field(historical, field.name) = @field(LEGACY, field.name);
    const old = try std.json.Stringify.valueAlloc(a, historical, .{ .whitespace = .indent_2 });
    defer a.free(old);
    const new = try std.json.Stringify.valueAlloc(a, LEGACY, .{ .whitespace = .indent_2 });
    defer a.free(new);
    try std.testing.expectEqualStrings(old, new);
    for ([_][]const u8{ legacy_json, fused_json }, [_]Mat.Geometry{ LEGACY, FUSED }) |json, expected| {
        var parsed = try std.json.parseFromSlice(Mat.Geometry, a, json, .{});
        defer parsed.deinit();
        try std.testing.expect(std.meta.eql(parsed.value, expected));
    }
}
