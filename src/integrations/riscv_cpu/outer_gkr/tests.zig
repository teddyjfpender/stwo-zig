//! Outer LogUp-GKR (profile outer_gkr_om31_strict_v1): profile pins, strict draws, CPU reference
//! round trip, exhaustive single-word tamper corpus, in-circuit gadget validity and rejection.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const P = @import("profile.zig");
const S = @import("section.zig");
const CG = @import("circuit.zig");
const lane = @import("../rv64_recursion/om31_circuit_lane.zig");
const candidate = @import("../word16_execution/om31_security_candidate.zig");
const O = core.fields.om31.OM31;
const M31 = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;

test "outer GKR profile: classes, hybrid roster, lane groups, header and security facts" {
    for (P.CLASSES) |c| try c.validate();
    // Hybrid rule: GKR only where classic OM31 interaction is wider than 16 binding columns.
    var bound: [P.N_COMPONENTS]bool = undefined;
    for (&bound, 0..) |*b, c| b.* = P.gkrBound(@enumFromInt(c));
    try std.testing.expectEqualSlices(bool, &.{ false, false, true, true, true, false, true, false, false, false, false }, &bound);
    // Classic OM31 interaction width per node = 304 committed columns (M4.0 item 8).
    var cols: u32 = 0;
    for (0..P.N_COMPONENTS) |c| cols += P.classicInteractionBaseColumns(@enumFromInt(c));
    try std.testing.expectEqual(@as(u32, 304), cols);
    const leaf = &P.LEAF_CPU_24628607;
    try std.testing.expectEqual(@as(usize, 8), leaf.instances.len);
    const vars = [_]u32{ 23, 22, 23, 21, 27, 26, 24, 24 };
    for (leaf.instances, vars) |inst, v| try std.testing.expectEqual(v, inst.variables());
    try std.testing.expectEqual(@as(u32, 27), leaf.layers());
    try std.testing.expectEqual(@as(u64, 351), leaf.rounds());
    try std.testing.expectEqual(@as(u32, 27), P.FOLD_24628607.layers());
    // Header carries identity, magic, version, class id, roster.
    var buf: [12 + P.MAX_INSTANCES]u32 = undefined;
    const h = try leaf.header(&buf);
    try std.testing.expectEqual(@as(usize, 20), h.len);
    try std.testing.expectEqual(P.MAGIC, h[8]);
    try std.testing.expectEqual(leaf.id, h[10]);
    // Security facts of the real classes (40 outer proofs per request is above 24628607's 33).
    try P.requireSecurity(leaf.*, 40);
    try P.requireSecurity(P.FOLD_24628607, 40);
    try std.testing.expect(leaf.conservativeMass() < core.fields.m31.Modulus);
    // QM31 challenges would not reach the target (profiles note 4.2 finding 1).
    try std.testing.expectError(error.Om31CandidateAlgebraicBudgetInsufficient, candidate.requireOuterGkrBitsQm31(leaf.facts(40), 124));
    // Reordered or incomplete rosters are not classes.
    var bad = leaf.*;
    var swapped: [8]P.Instance = undefined;
    @memcpy(&swapped, leaf.instances);
    std.mem.swap(P.Instance, &swapped[0], &swapped[1]);
    bad.instances = &swapped;
    try std.testing.expectError(error.InvalidOuterGkrClass, bad.validate());
    bad.instances = leaf.instances[0..7];
    try std.testing.expectError(error.InvalidOuterGkrClass, bad.validate());
}

test "outer GKR strict draw: rejection predicate and equality with the raw-mod channel on admitted draws" {
    try std.testing.expect(S.admissibleDraw(.{ 0, 1, 0x7fffffff, 0xfffffffd, 2, 3, 4, 5 }));
    try std.testing.expect(!S.admissibleDraw(.{ 0, 1, 2, 3, 4, 5, 6, 0xfffffffe }));
    try std.testing.expect(!S.admissibleDraw(.{ 0xffffffff, 1, 2, 3, 4, 5, 6, 7 }));
    var raw = S.benchChannel();
    var strict = S.StrictChannel{ .inner = S.benchChannel() };
    for (0..2000) |i| {
        raw.mixFelts(&.{O.fromBase(M31.fromCanonical(@intCast(i)))});
        strict.mixFelts(&.{O.fromBase(M31.fromCanonical(@intCast(i)))});
        const x = raw.drawSecureFelt();
        const y = strict.drawSecureFelt();
        if (!strict.rejected) try std.testing.expect(x.eql(y));
    }
    try std.testing.expectEqualSlices(u8, &raw.inner.digest, &strict.inner.inner.digest);
}

const Fixture = struct {
    inputs: S.Inputs,
    section: S.Section,
    words: []u32,
    fn init(class: *const P.Class, seed: u64) !Fixture {
        var inputs = try S.synthetic(a, class, seed, true);
        errdefer inputs.deinit(a);
        const start = S.benchChannel();
        var section = try S.proveCpu(a, &start, class, &inputs);
        errdefer section.deinit(a);
        return .{ .inputs = inputs, .section = section, .words = try S.encode(a, &section) };
    }
    fn deinit(self: *Fixture) void {
        a.free(self.words);
        self.section.deinit(a);
        self.inputs.deinit(a);
    }
};

/// The full receiver decision on encoded words: decode, verify, closure (no external term),
/// terminal against inputs evaluated at the transcript's own point.
fn receive(words: []const u32, inputs: *const S.Inputs) !void {
    var section = try S.decode(a, words);
    defer section.deinit(a);
    var channel = S.benchChannel();
    var verified = try S.verify(a, &channel, &section);
    defer verified.deinit(a);
    try S.requireClosure(&verified, O.zero());
    const expected = try S.terminalExpected(a, inputs, &verified);
    defer a.free(expected);
    try S.requireTerminal(&verified, expected);
}

test "outer GKR CPU reference: prove, encode, decode, verify, closure, terminal and transcript continuation" {
    var f = try Fixture.init(&P.TEST_SMALL, 7);
    defer f.deinit();
    try receive(f.words, &f.inputs);
    try std.testing.expectEqual(S.wordCount(&P.TEST_SMALL), f.words.len);
    // Verifier channel continues exactly where the prover's did.
    var prover = S.benchChannel();
    try S.mixHeader(&prover, &P.TEST_SMALL, f.section.salt);
    var layers: [P.MAX_INSTANCES]S.GP.Layer = undefined;
    for (layers[0..f.inputs.numerators.len], f.inputs.numerators, f.inputs.denominators) |*l, n, d|
        l.* = .{ .LogUpMultiplicities = .{ .numerators = try @import("stwo_prover_engine").lookups.mle.MleFor(O, M31).initBorrowed(n), .denominators = try @import("stwo_prover_engine").lookups.mle.MleFor(O, O).initBorrowed(d) } };
    var again = try S.GP.proveBatch(a, &prover, layers[0..f.inputs.numerators.len]);
    defer again.deinit(a);
    var channel = S.benchChannel();
    var verified = try S.verify(a, &channel, &f.section);
    defer verified.deinit(a);
    try std.testing.expectEqualSlices(u8, &prover.inner.digest, &channel.inner.digest);
    try std.testing.expectEqual(prover.inner.n_draws, channel.inner.n_draws);
    // Unbalanced inputs prove fine but fail closure without the matching external term.
    var raw_inputs = try S.synthetic(a, &P.TEST_SMALL, 8, false);
    defer raw_inputs.deinit(a);
    const start = S.benchChannel();
    var section = try S.proveCpu(a, &start, &P.TEST_SMALL, &raw_inputs);
    defer section.deinit(a);
    var c2 = S.benchChannel();
    var v2 = try S.verify(a, &c2, &section);
    defer v2.deinit(a);
    try std.testing.expectError(error.OuterGkrClosureMismatch, S.requireClosure(&v2, O.zero()));
    try S.requireClosure(&v2, v2.root_sum.neg());
}

test "outer GKR tamper corpus: every single-word change of the encoded section is rejected (M01, M02, order, salt, header)" {
    var f = try Fixture.init(&P.TEST_SMALL, 11);
    defer f.deinit();
    const words = try a.dupe(u32, f.words);
    defer a.free(words);
    var rejected: usize = 0;
    for (0..words.len) |i| {
        const old = words[i];
        words[i] = if (i < 5) old +% 1 else (old + 1) % core.fields.m31.Modulus;
        if (receive(words, &f.inputs)) |_| {
            std.debug.print("\nOUTER_GKR_TAMPER accepted word={}\n", .{i});
            return error.TamperAccepted;
        } else |_| rejected += 1;
        words[i] = old;
    }
    try receive(words, &f.inputs);
    std.debug.print("\nOUTER_GKR_TAMPER {f}\n", .{std.json.fmt(.{ .class = P.TEST_SMALL.name, .words = words.len, .rejected = rejected }, .{})});
    try std.testing.expectEqual(words.len, rejected);
    // Instance order: swapping two instances' roots and masks (same height) is rejected.
    var section = try S.decode(a, f.words);
    defer section.deinit(a);
    std.mem.swap([]O, &section.proof.output_claims_by_instance[0], &section.proof.output_claims_by_instance[2]);
    std.mem.swap([]S.G.GkrMask, &section.proof.layer_masks_by_instance[0], &section.proof.layer_masks_by_instance[2]);
    var channel = S.benchChannel();
    if (S.verify(a, &channel, &section)) |v| {
        var owned = v;
        defer owned.deinit(a);
        const expected = try S.terminalExpected(a, &f.inputs, &owned);
        defer a.free(expected);
        try std.testing.expectError(error.OuterGkrTerminalMismatch, S.requireTerminal(&owned, expected));
    } else |_| {}
    // M02: an authenticated input evaluation that differs from the final claim is rejected.
    var c2 = S.benchChannel();
    var v2 = try S.verify(a, &c2, &f.section);
    defer v2.deinit(a);
    const expected = try S.terminalExpected(a, &f.inputs, &v2);
    defer a.free(expected);
    expected[3][1] = expected[3][1].add(O.one());
    try std.testing.expectError(error.OuterGkrTerminalMismatch, S.requireTerminal(&v2, expected));
    // A section of one class is not a section of another (class constants, not proof values).
    words[2] = P.LEAF_CPU_24628607.id;
    try std.testing.expectError(error.MalformedOuterGkrSection, S.decode(a, words));
    // Wrong starting transcript (section moved to another outer proof) is rejected.
    var other = S.RawChannel.init();
    if (S.verify(a, &other, &f.section)) |v| {
        var owned = v;
        owned.deinit(a);
        return error.MovedSectionAccepted;
    } else |_| {}
}

fn circuitRun(f: *const Fixture, comptime mutation: enum { none, coefficient, mask, salt, terminal, closure }) !bool {
    var context = try CG.Context.init(a, 0);
    defer context.deinit();
    lane.begin(&context);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    var wired = try CG.wireSection(&context, &f.section);
    const bump = struct {
        fn apply(ctx: *CG.Context, w: CG.F) void {
            ctx.value_table.items[w.c0.v.idx] = ctx.get(w.c0.v).add(Q.one());
        }
    }.apply;
    switch (mutation) {
        .coefficient => bump(&context, wired.proof.sumcheck_proofs[5].round_polys[2].coefficients[1]),
        .mask => bump(&context, wired.proof.layer_masks_by_instance[1][3].columns[0][1]),
        .salt => bump(&context, wired.salt),
        else => {},
    }
    var channel = try CG.Channel.initBench(&context);
    var result = try CG.verify(&context, &channel, f.section.class, &wired);
    defer result.deinit(a);
    var native_channel = S.benchChannel();
    var native = try S.verify(a, &native_channel, &f.section);
    defer native.deinit(a);
    if (mutation == .none) {
        for (result.artifact.ood_point, native.artifact.ood_point) |w, v| try std.testing.expect(w.value().eql(v));
        try std.testing.expectEqual(native.draws, channel.draws);
    }
    try CG.requireClosure(&context, &result, if (mutation == .closure) CG.F.one() else CG.F.zero());
    const expected_native = try S.terminalExpected(a, &f.inputs, &native);
    defer a.free(expected_native);
    var expected: [P.MAX_INSTANCES][2]CG.F = undefined;
    for (expected[0..expected_native.len], expected_native) |*e, v| e.* = .{ try CG.F.guess(&context, v[0]), try CG.F.guess(&context, v[1]) };
    if (mutation == .terminal) expected[2][0] = expected[2][0].add(CG.F.one());
    try CG.requireTerminal(&context, &result, expected[0..expected_native.len]);
    try channel.finish();
    bound = false;
    try lane.finish();
    try context.finalize(false);
    if (mutation == .none) {
        const g = context.gate_counts;
        std.debug.print("\nOUTER_GKR_M5_CIRCUIT {f}\n", .{std.json.fmt(.{ .class = f.section.class.name, .layers = f.section.class.layers(), .instances = f.section.class.instances.len, .draws = channel.draws, .blake_g_gate = g.blake_g_gate, .qm31_ops = g.qm31_ops, .m31_to_u32 = g.m31_to_u32, .triple_xor = g.triple_xor, .eq = g.eq, .variables = context.circuit.n_vars }, .{})});
    }
    return context.isCircuitValid();
}

test "outer GKR circuit gadget: honest section valid with native transcript parity; tampers unsatisfiable" {
    var f = try Fixture.init(&P.TEST_SMALL, 13);
    defer f.deinit();
    try std.testing.expect(try circuitRun(&f, .none));
    try std.testing.expect(!try circuitRun(&f, .coefficient));
    try std.testing.expect(!try circuitRun(&f, .mask));
    try std.testing.expect(!try circuitRun(&f, .salt));
    try std.testing.expect(!try circuitRun(&f, .terminal));
    try std.testing.expect(!try circuitRun(&f, .closure));
    const cost = try CG.measure(a, &f.section, O.zero(), null);
    try std.testing.expect(cost.valid);
}

test "outer GKR circuit strict draw: raw words >= 2p make the graph unsatisfiable" {
    for ([_]struct { w: u32, ok: bool }{ .{ .w = 0, .ok = true }, .{ .w = 0xfffffffd, .ok = true }, .{ .w = 0x7fffffff, .ok = true }, .{ .w = 0xffff_0000, .ok = true }, .{ .w = 0xfffeffff, .ok = true }, .{ .w = 0xfffffffe, .ok = false }, .{ .w = 0xffffffff, .ok = false } }) |case| {
        var context = try CG.Context.init(a, 0);
        defer context.deinit();
        var words: [8]circuit.builder.wrappers.U32Wrapper(circuit.builder.Var) = undefined;
        for (&words, 0..) |*w, i| w.* = try circuit.builder.wrappers.constU32(Q, &context, if (i == 5) case.w else @intCast(i * 1000 + 1));
        try CG.requireAdmissible(&context, &words);
        try context.finalize(false);
        try std.testing.expectEqual(case.ok, try context.isCircuitValid());
    }
}
