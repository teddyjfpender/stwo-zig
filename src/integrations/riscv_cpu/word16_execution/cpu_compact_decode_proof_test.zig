//! Opt-in compact decode CPU MAIN (Geometry.cpu_compact_decode) end to end:
//! the honest physical proof verifies with a fresh compact receiver, the
//! legacy/fused/pair/compact receivers reject each other's proofs, forged
//! interaction witnesses are rejected by the physical STARK, and every forged
//! decode MAIN (immediate, operand slot, LS offset, PC jump, AUIPC static
//! immediate, JALR target alias) is rejected by the physical STARK or, with
//! every CPU interaction repaired from the forged MAIN, by LogUp closure.
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
const Program = @import("program.zig").Program;
const Q = A.evaluation.Q;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const n: usize = 32;
const K = X.layout.compact;
const COMPACT = Mat.Geometry{ .cpu_log = 5, .cpu_fused_tail = true, .cpu_u8_pairs = true, .cpu_compact_decode = true };
const PAIRS = Mat.Geometry{ .cpu_log = 5, .cpu_fused_tail = true, .cpu_u8_pairs = true };
const FUSED = Mat.Geometry{ .cpu_log = 5, .cpu_fused_tail = true };
const LEGACY = Mat.Geometry{ .cpu_log = 5 };
const verifyPhysical = @import("memory/boundary_anchor_test.zig").verifyPhysical;
const P31: u64 = (1 << 31) - 1;

/// Forged decode MAIN. Each targets the first row retiring `opcode`.
pub const Forge = enum {
    /// ADDI: B (the immediate slot) += 1.
    immediate,
    /// BGE x13, x0: the x0 rs2 slot B := 5 (no local guard; ROM binds it).
    x0_operand,
    /// ADDI: immediate moved from B to the LS-offset slot.
    wrong_slot,
    /// SH: LS offset low limb += 4.
    store_offset,
    /// ADD (static): felt(next) += 4, so the next row's pc follows the jump.
    pc_jump,
    /// AUIPC: B += 4 and C += 4 (a true ADD, but not the decoded constant).
    auipc_immediate,
    /// AUIPC: A := 1 although rs1 is unused (A_eff is A).
    auipc_operand,
    /// JAL: B += 4 and C += 4 (static link constant forged).
    jal_immediate,
    /// JALR: next limbs := limbs(T + p), felt(next) unchanged.
    jalr_alias,
    /// ADD (static): next limbs (n0 + 65536, n1 - 1), felt unchanged. Harmless.
    noncanonical_static,
};
pub const Tamper = union(enum) {
    none,
    /// Interaction witness slot += delta at a row; prefix repaired.
    slot: struct { row: usize, slot: usize },
    /// S += delta at one row only.
    sum: struct { row: usize },
    /// Forged MAIN; the whole CPU interaction is then rebuilt from it.
    main: Forge,
};
const DELTA = Q.fromU32Unchecked(3, 1, 4, 1);
fn rowAt(main: []const M, logical: usize) [K.COUNT]M {
    var row: [K.COUNT]M = undefined;
    const pos = R.trace.physical(logical, 5);
    for (&row, 0..) |*v, column| v.* = main[column * n + pos];
    return row;
}
fn setAt(main: []M, logical: usize, column: usize, value: M) void {
    main[column * n + R.trace.physical(logical, 5)] = value;
}
fn fixedAt(logical: usize) [3]M {
    return .{ M.fromCanonical(@intCast(logical)), M.fromCanonical(@intFromBool(logical == 0)), M.fromCanonical(@intFromBool(logical == n - 1)) };
}
fn felt(row: [K.COUNT]M) u64 {
    return row[K.next].add(M.fromCanonical(65536).mul(row[K.next + 1])).v;
}
/// Logical row retiring the first `opcode`, walking the felt PC chain.
fn rowOf(program: *const Program, main: []const M, steps: usize, initial: u64, opcode: @import("stwo_riscv_frontend").rv64.decode.Opcode) !usize {
    var pc = initial;
    for (0..steps) |logical| {
        const entry = program.entries[try program.lookup(pc)];
        if (entry.instruction.opcode == opcode) return logical;
        pc = felt(rowAt(main, logical));
    }
    return error.FixtureOpcodeMissing;
}
fn limbs(value: u64) [2]M {
    return .{ M.fromCanonical(@as(u16, @truncate(value))), M.fromCanonical(@as(u16, @truncate(value >> 16))) };
}
fn add(main: []M, logical: usize, column: usize, delta: u32) void {
    const old = rowAt(main, logical)[column];
    setAt(main, logical, column, old.add(M.fromCanonical(delta)));
}
fn forgeMain(program: *const Program, main: []M, steps: usize, initial: u64, forge: Forge) !void {
    switch (forge) {
        .immediate => add(main, try rowOf(program, main, steps, initial, .ADDI), K.b, 1),
        .x0_operand => setAt(main, try rowOf(program, main, steps, initial, .BGE), K.b, M.fromCanonical(5)),
        .wrong_slot => {
            const row = try rowOf(program, main, steps, initial, .ADDI);
            const r = rowAt(main, row);
            for (0..4) |i| setAt(main, row, K.b + i, M.zero());
            setAt(main, row, K.ls_imm, r[K.b]);
            setAt(main, row, K.ls_imm + 1, r[K.b + 1]);
        },
        .store_offset => add(main, try rowOf(program, main, steps, initial, .SH), K.ls_imm, 4),
        .pc_jump => {
            const row = try rowOf(program, main, steps, initial, .ADD);
            const forged = limbs(felt(rowAt(main, row)) + 4);
            setAt(main, row, K.next, forged[0]);
            setAt(main, row, K.next + 1, forged[1]);
        },
        .auipc_immediate, .jal_immediate => {
            const row = try rowOf(program, main, steps, initial, if (forge == .auipc_immediate) .AUIPC else .JAL);
            add(main, row, K.b, 4);
            add(main, row, K.c, 4);
        },
        .auipc_operand => setAt(main, try rowOf(program, main, steps, initial, .AUIPC), K.a, M.one()),
        .jalr_alias => {
            const row = try rowOf(program, main, steps, initial, .JALR);
            const v = felt(rowAt(main, row));
            // T = v + p < 2^32 is odd (v even, p odd): no AND16(x, ~1) output.
            try std.testing.expect((v + P31) & 1 == 1 and v + P31 < (1 << 32));
            const forged = limbs(v + P31);
            setAt(main, row, K.next, forged[0]);
            setAt(main, row, K.next + 1, forged[1]);
            try std.testing.expectEqual(v, felt(rowAt(main, row)));
        },
        .noncanonical_static => {
            const row = try rowOf(program, main, steps, initial, .ADD);
            const r = rowAt(main, row);
            // n1 - 1 wraps to p - 1 when n1 = 0; felt(next) is still unchanged.
            setAt(main, row, K.next, r[K.next].add(M.fromCanonical(65536)));
            setAt(main, row, K.next + 1, r[K.next + 1].sub(M.one()));
        },
    }
}
/// Rewrites the compact CPU interaction from MAIN with an optional forgery
/// and returns the resulting CPU claim (the full prefix total).
pub fn repairCompact(main: []const M, inter: []M, public: X.types.Inputs, ch: X.types.Challenges, pc: Tables.Challenges, tamper: Tamper) !Q {
    const L = X.layout.pairs;
    var increments: [n]Q = undefined;
    for (0..n) |logical| {
        const pos = R.trace.physical(logical, 5);
        const row = rowAt(main, logical);
        const prior = rowAt(main, (logical + n - 1) % n);
        const fixed = fixedAt(logical);
        const ds = X.equations.nativeCompactDenominators(&fixed, &row, &prior, public, ch);
        var witness = try X.equations.nativeCompactWitnesses(ds, &row);
        switch (tamper) {
            .slot => |t| if (t.row == logical) {
                witness[t.slot] = witness[t.slot].add(DELTA);
            },
            else => {},
        }
        for (witness, 0..) |value, i| R.trace.store(inter, n, pos, 4 * i, value);
        const p = X.equations.nativeCompactPairDenominators(&row, pc);
        increments[logical] = X.equations.pairContributionFor(Q, witness).add(try p[0].inv()).add(try p[1].inv());
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
fn run(tamper: Tamper) !Outcome {
    var fixture = try @import("../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    var setup = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, COMPACT);
    defer setup.deinit();
    try std.testing.expect(setup.materials.program.compact);
    const admission = Driver.admission(&fixture.image);
    var source = try Sources.Source.init(a, &setup.materials, admission.image, fixture.boundary, 1, &fixture.tape);
    defer source.deinit();
    try std.testing.expect(source.cpu.compact);
    try std.testing.expectEqual(K.COUNT * n, source.cpu.main.len);
    const request = source.request();
    if (tamper == .main) try forgeMain(&setup.materials.program, source.cpu.main, request.cpu.steps, request.cpu.initial_pc, tamper.main);
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
    const honest = try a.dupe(M, source.cpu.interaction);
    defer a.free(honest);
    const honest_claims = claims;
    claims.cpu = try repairCompact(actual, source.cpu.interaction, try X.types.inputs(request.cpu, request.epoch, 5), draw.cpu, draw.and_, tamper);
    if (tamper == .none) {
        try claims.validate();
        // The production fill and the test repair agree bit for bit.
        try std.testing.expect(claims.cpu.eql(honest_claims.cpu));
        try std.testing.expectEqualSlices(M, honest, source.cpu.interaction);
    }
    channel.mixFelts(&claims.values());
    const inter = try source.columns(a, 2);
    defer a.free(inter);
    try scheme.commitBorrowedStreaming(a, inter, 8, &channel);
    source.releaseCommittedInteraction();
    var components = try Components.init(&setup.materials, request, draw, claims);
    try std.testing.expect(components.cpu.compact);
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
    var fresh = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, COMPACT);
    defer fresh.deinit();
    var physical_error: ?anyerror = null;
    const physical = if (verifyPhysical(&fresh, admission, encoded)) |_| true else |err| blk: {
        physical_error = err;
        break :blk false;
    };
    const full = if (Execution.verify(a, &fresh, admission, encoded)) |_| true else |_| false;
    if (tamper == .none) try std.testing.expect(!prover_refused);
    return .{ .physical = physical, .full = full, .claim_changed = !claims.cpu.eql(honest_claims.cpu), .physical_error = physical_error };
}

test "compact decode CPU: honest physical proof verifies with a fresh compact receiver" {
    const outcome = try run(.none);
    std.testing.expect(outcome.physical and outcome.full and !outcome.claim_changed) catch |err| {
        std.debug.print("noncanonical: {any}\n", .{outcome});
        return err;
    };
}
test "compact decode CPU: forged interaction fractions and prefixes are rejected by the physical STARK" {
    for ([_]Tamper{
        .{ .slot = .{ .row = 0, .slot = 2 } },
        .{ .slot = .{ .row = 0, .slot = 3 } },
        .{ .slot = .{ .row = 0, .slot = 4 } },
        .{ .slot = .{ .row = 7, .slot = 5 } },
        .{ .slot = .{ .row = 3, .slot = 6 } },
        .{ .slot = .{ .row = 31, .slot = 4 } },
        .{ .sum = .{ .row = 3 } },
    }) |tamper| {
        const outcome = try run(tamper);
        try std.testing.expectEqual(@as(?anyerror, error.OodsNotMatching), outcome.physical_error);
        try std.testing.expect(!outcome.full);
    }
}
test "compact decode CPU: a forged A on an AUIPC row (rs1 unused) is rejected by the physical STARK" {
    const outcome = try run(.{ .main = .auipc_operand });
    try std.testing.expectEqual(@as(?anyerror, error.OodsNotMatching), outcome.physical_error);
    try std.testing.expect(!outcome.full);
}
test "compact decode CPU: forged immediates, operand slots, LS offsets, PC jumps, static AUIPC/JAL constants and JALR aliases are rejected by closure" {
    // Every CPU interaction is rebuilt from the forged MAIN, so the STARK
    // itself holds; the forged ROM/FUNCTION/OWNER query has no supplier.
    for ([_]Forge{ .immediate, .x0_operand, .wrong_slot, .store_offset, .pc_jump, .auipc_immediate, .jal_immediate, .jalr_alias }) |forge| {
        const outcome = try run(.{ .main = forge });
        std.testing.expect(outcome.physical and outcome.claim_changed and !outcome.full) catch |err| {
            std.debug.print("forge {s}: {any}\n", .{ @tagName(forge), outcome });
            return err;
        };
    }
}
test "compact decode CPU: non-canonical next limbs on a static row encode the same PC and are accepted" {
    // Only felt(next) is read on static rows (ROM next, successor pc, padding),
    // so a different limb split of the same canonical PC changes nothing.
    // Every tuple is a function of felt(next) there, so even the claim is unchanged.
    const outcome = try run(.{ .main = .noncanonical_static });
    std.testing.expect(outcome.physical and outcome.full and !outcome.claim_changed) catch |err| {
        std.debug.print("noncanonical: {any}\n", .{outcome});
        return err;
    };
}
test "compact decode CPU: all four layouts reject each other's proofs; exact cell delta" {
    var fixture = try @import("../tests/rv64_word16_execution_fixture.zig").Fixture.init(a);
    defer fixture.deinit();
    const admission = Driver.admission(&fixture.image);
    var setups: [4]Mat.Setup = undefined;
    var made: usize = 0;
    defer for (setups[0..made]) |*s| s.deinit();
    for ([_]Mat.Geometry{ LEGACY, FUSED, PAIRS, COMPACT }, &setups) |g, *s| {
        s.* = try Mat.Setup.initWithAuthority(a, &fixture.image.authority, g);
        made += 1;
    }
    var proofs: [4]Execution.Encoded = undefined;
    var proved: usize = 0;
    defer for (proofs[0..proved]) |*p| p.deinit(a);
    for (&setups, &proofs) |*s, *p| {
        p.* = try Execution.prove(a, s, admission, fixture.boundary, &fixture.tape, null);
        proved += 1;
    }
    for (&setups, 0..) |*s, i| for (proofs, 0..) |p, j| {
        if (i == j) try Execution.verify(a, s, admission, p) else try std.testing.expect(std.meta.isError(Execution.verify(a, s, admission, p)));
    };
    // Exact committed cells: CPU MAIN -10 columns x 2^cpu_log rows versus the
    // pair layout; fixed and interaction unchanged (ROM keeps 30 coordinates).
    const p = try Mat.G.cells(&setups[2].materials.shapes());
    const c = try Mat.G.cells(&setups[3].materials.shapes());
    try std.testing.expectEqual(p.fixed, c.fixed);
    try std.testing.expectEqual(p.main - 10 * n, c.main);
    try std.testing.expectEqual(p.interaction, c.interaction);
    try std.testing.expectError(error.InvalidCpuCompactGeometry, (Mat.Geometry{ .cpu_log = 5, .cpu_fused_tail = true, .cpu_compact_decode = true }).validate());
    const pair_json = try std.json.Stringify.valueAlloc(a, PAIRS, .{});
    defer a.free(pair_json);
    try std.testing.expect(std.mem.indexOf(u8, pair_json, "cpu_compact_decode") == null);
    const compact_json = try std.json.Stringify.valueAlloc(a, COMPACT, .{});
    defer a.free(compact_json);
    try std.testing.expect(std.mem.indexOf(u8, compact_json, "\"cpu_compact_decode\":true") != null);
    var parsed = try std.json.parseFromSlice(Mat.Geometry, a, compact_json, .{});
    defer parsed.deinit();
    try std.testing.expect(std.meta.eql(parsed.value, COMPACT));
}
