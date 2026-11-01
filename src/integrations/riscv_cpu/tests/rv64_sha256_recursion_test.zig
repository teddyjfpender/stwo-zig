//! SHA-256 (`ethereum_services_v3`) recursion authorities:
//! - native/circuit parity of the SHA-256 truth and the `.sha256` Word16
//!   bridge point evaluators, with mutated challenge/claim/span/mask wires;
//! - the receiver-derived truth shape against the actual component vtable;
//! - a services-fixture truth proof verified by the in-circuit native
//!   verifier, its statement and the cross-leaf Wire35 closure, plus
//!   tampered OODS values, a wrong shape, wrong statement words, a locally
//!   valid false output and a missing bridge contribution.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const A = @import("stwo_riscv_frontend").rv64_air;
const H = A.crypto.sha256;
const B = A.crypto.secp256k1.word16_bridge;
const V = A.evaluation;
const Circuit = @import("../rv64_recursion/circuit_lane.zig");
const Leaf = @import("../rv64_recursion/services_truth_leaf.zig");
const Fixture = @import("../word16_global_execution/services/sha256_fixture.zig");
const Exec = @import("../word16_global_execution/services/execution.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const G = @import("../word16_global_execution/protocol.zig");
const wire_codec = @import("stwo_proof_wire");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const F = Circuit.Lane;
const a = std.testing.allocator;

fn randomQ(r: std.Random) Q {
    return Q.fromM31(M.fromU64(r.int(u32)), M.fromU64(r.int(u32)), M.fromU64(r.int(u32)), M.fromU64(r.int(u32)));
}

/// Dense masks (tree, column, sample) for one component at offset 0.
const NativeMasks = struct {
    values: [3][][]Q,
    pub fn count(self: NativeMasks, tree: usize, c: usize) !usize {
        if (tree > 2 or c >= self.values[tree].len) return error.InvalidMask;
        return self.values[tree][c].len;
    }
    pub fn at(self: NativeMasks, tree: usize, c: usize, s: usize) !Q {
        if (s >= try self.count(tree, c)) return error.InvalidMask;
        return self.values[tree][c][s];
    }
};
/// The same masks as wires guessed ONCE (columns are read many times).
const WireMasks = struct {
    values: [3][][]F,
    pub fn count(self: WireMasks, tree: usize, c: usize) !usize {
        if (tree > 2 or c >= self.values[tree].len) return error.InvalidMask;
        return self.values[tree][c].len;
    }
    pub fn at(self: WireMasks, tree: usize, c: usize, s: usize) !F {
        if (s >= try self.count(tree, c)) return error.InvalidMask;
        return self.values[tree][c][s];
    }
};
fn makeMasks(arena: std.mem.Allocator, r: std.Random, widths: [3]usize, previous: *const fn (usize, usize) bool) !NativeMasks {
    var out: NativeMasks = undefined;
    for (widths, 0..) |w, tree| {
        out.values[tree] = try arena.alloc([]Q, w);
        for (out.values[tree], 0..) |*col, c| {
            col.* = try arena.alloc(Q, if (previous(tree, c)) 2 else 1);
            for (col.*) |*v| v.* = randomQ(r);
        }
    }
    return out;
}
fn guessMasks(arena: std.mem.Allocator, ctx: *Circuit.Context, native: NativeMasks, mutate: ?[3]usize) !WireMasks {
    var out: WireMasks = undefined;
    for (native.values, 0..) |tree, t| {
        out.values[t] = try arena.alloc([]F, tree.len);
        for (out.values[t], tree, 0..) |*col, src, c| {
            col.* = try arena.alloc(F, src.len);
            for (col.*, src, 0..) |*v, q, s| {
                const bump = if (mutate) |m| m[0] == t and m[1] == c and m[2] == s else false;
                v.* = F.wire(try ctx.guess(if (bump) q.add(Q.one()) else q));
            }
        }
    }
    return out;
}
fn wireQ(ctx: *Circuit.Context, q: Q, bump: bool) !F {
    return F.wire(try ctx.guess(if (bump) q.add(Q.one()) else q));
}
fn shaPrevious(tree: usize, c: usize) bool {
    return (tree == 1 and c == H.layout.ACTIVE) or (tree == 2 and c >= 4);
}
fn bridgePrevious(tree: usize, c: usize) bool {
    return if (tree == 1) B.layout.previousMainFor(.bridge, c) else tree == 2 and B.layout.previousInterFor(.bridge, c);
}

test "SHA-256 truth: circuit point authority equals native residuals and composition; every bound wire is load-bearing" {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(0x53484132);
    const r = prng.random();
    const masks = try makeMasks(arena, r, H.layout.widths(), &shaPrevious);
    var channel = core.channel.blake2s.Blake2sChannel{};
    const wire = A.crypto.secp256k1.equations.Wire.draw(&channel);
    const claim = randomQ(r);
    const log: u32 = 6;
    const global_log: u32 = 6;
    const point = core.circle.secureFieldPointFromRandomSeed(randomQ(r));
    const randomness = randomQ(r);
    const component = H.component.Component{ .log_size = log, .public = .{ .calls = 5, .first_id = 19 }, .claim = claim, .wire = wire };
    const expected = try arena.alloc(Q, H.layout.CONSTRAINTS);
    var acc = core.air.accumulation.PointEvaluationAccumulator.init(randomness);
    var ns = V.Sink{ .values = expected, .accumulator = &acc };
    try component.evaluatePointFor(Q, point, global_log, masks, component.public, claim, wire, &ns);
    try std.testing.expectEqual(@as(usize, H.layout.CONSTRAINTS), ns.count);
    const native_composition = acc.finalize();
    // Mutations: none, wire offset, wire coefficient, claim, calls, first ID,
    // one MAIN sample, the previous ACTIVE sample, one interaction sample.
    for (0..9) |mutation| {
        var context = try Circuit.Context.init(a, 0);
        defer context.deinit();
        var cw: A.crypto.secp256k1.equations.WireFor(F) = undefined;
        cw.offset = try wireQ(&context, wire.offset, mutation == 1);
        for (&cw.coefficients, wire.coefficients, 0..) |*v, q, i| v.* = try wireQ(&context, q, mutation == 2 and i == 7);
        const cclaim = try wireQ(&context, claim, mutation == 3);
        const span = V.CallSpanFor(F){ .calls = try wireQ(&context, V.q(5), mutation == 4), .first_id = try wireQ(&context, V.q(19), mutation == 5), .nonempty = F.wire(context.one()) };
        const mutate: ?[3]usize = switch (mutation) {
            6 => .{ 1, H.layout.A + 100, 0 },
            7 => .{ 1, H.layout.ACTIVE, 1 },
            8 => .{ 2, 5, 1 },
            else => null,
        };
        const wm = try guessMasks(arena, &context, masks, mutate);
        const cpoint = A.geometry.PointFor(F){ .x = try wireQ(&context, point.x, false), .y = try wireQ(&context, point.y, false) };
        const actual = try arena.alloc(F, H.layout.CONSTRAINTS);
        Circuit.begin(&context);
        var cacc = A.lane.PointAccumulator(F).init(try wireQ(&context, randomness, false));
        var sink = V.SinkFor(F){ .values = actual, .accumulator = &cacc };
        try component.evaluatePointFor(F, cpoint, global_log, wm, span, cclaim, cw, &sink);
        try Circuit.finish();
        try std.testing.expectEqual(@as(usize, H.layout.CONSTRAINTS), sink.count);
        if (mutation == 0) {
            for (actual, expected) |v, q| try std.testing.expect(context.get(v.v).eql(q));
            try std.testing.expect(context.get(cacc.finalize().v).eql(native_composition));
        }
        try context.eq(cacc.finalize().v, try context.constant(native_composition));
        try context.finalize(false);
        try std.testing.expectEqual(mutation == 0, try context.isCircuitValid());
    }
}

test "SHA-256 bridge kind: circuit point authority equals native residuals; claims, challenges and span are wires" {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(0x42524453);
    const r = prng.random();
    const masks = try makeMasks(arena, r, B.layout.widths(.bridge), &bridgePrevious);
    var ch: B.types.Challenges = undefined;
    ch.ram.offset = randomQ(r);
    for (&ch.ram.coefficients) |*v| v.* = randomQ(r);
    ch.owner.offset = randomQ(r);
    for (&ch.owner.coefficients) |*v| v.* = randomQ(r);
    ch.wire.offset = randomQ(r);
    for (&ch.wire.coefficients) |*v| v.* = randomQ(r);
    ch.range16 = .{ .offset = randomQ(r), .coefficient = randomQ(r) };
    ch.range8 = .{ .offset = randomQ(r), .coefficient = randomQ(r) };
    const claims = B.types.Claims{ .ram = randomQ(r), .owner = randomQ(r), .wire = randomQ(r), .range16 = randomQ(r), .range8 = randomQ(r) };
    const log: u32 = 5;
    const global_log: u32 = 9;
    const point = core.circle.secureFieldPointFromRandomSeed(randomQ(r));
    const randomness = randomQ(r);
    const component = B.component.Component{ .kind = .sha256, .log_size = log, .rows = 3, .first_id = 7, .offsets = .{ 0, 0, 0 }, .claims = claims, .challenges = ch };
    const expected = try arena.alloc(Q, B.layout.CONSTRAINTS);
    var acc = core.air.accumulation.PointEvaluationAccumulator.init(randomness);
    var ns = V.Sink{ .values = expected, .accumulator = &acc };
    try component.evaluatePointFor(Q, point, global_log, masks, .{ .calls = 3, .first_id = 7 }, claims, ch, &ns);
    const native_composition = acc.finalize();
    // The QM31 vtable path is the same authority.
    {
        var vacc = core.air.accumulation.PointEvaluationAccumulator.init(randomness);
        var items: [3][][]Q = masks.values;
        const tree_vec = core.air.components.MaskValues{ .items = &items };
        try component.evaluateConstraintQuotientsAtPoint(point, &tree_vec, &vacc, global_log);
        try std.testing.expect(vacc.finalize().eql(native_composition));
    }
    // Mutations: none, ram claim, owner claim, wire claim, range8 claim, RAM
    // coefficient, owner offset, wire coefficient, range16 offset, calls,
    // first ID, nonempty, one AFTER byte sample, one previous interaction sample.
    for (0..14) |mutation| {
        var context = try Circuit.Context.init(a, 0);
        defer context.deinit();
        var cc: B.types.ChallengesFor(F) = undefined;
        cc.ram.offset = try wireQ(&context, ch.ram.offset, false);
        for (&cc.ram.coefficients, ch.ram.coefficients, 0..) |*v, q, i| v.* = try wireQ(&context, q, mutation == 5 and i == 4);
        cc.owner.offset = try wireQ(&context, ch.owner.offset, mutation == 6);
        for (&cc.owner.coefficients, ch.owner.coefficients) |*v, q| v.* = try wireQ(&context, q, false);
        cc.wire.offset = try wireQ(&context, ch.wire.offset, false);
        for (&cc.wire.coefficients, ch.wire.coefficients, 0..) |*v, q, i| v.* = try wireQ(&context, q, mutation == 7 and i == 20);
        cc.range16 = .{ .offset = try wireQ(&context, ch.range16.offset, mutation == 8), .coefficient = try wireQ(&context, ch.range16.coefficient, false) };
        cc.range8 = .{ .offset = try wireQ(&context, ch.range8.offset, false), .coefficient = try wireQ(&context, ch.range8.coefficient, false) };
        const cl = B.types.ClaimsFor(F){ .ram = try wireQ(&context, claims.ram, mutation == 1), .owner = try wireQ(&context, claims.owner, mutation == 2), .wire = try wireQ(&context, claims.wire, mutation == 3), .range16 = try wireQ(&context, claims.range16, false), .range8 = try wireQ(&context, claims.range8, mutation == 4) };
        const span = V.CallSpanFor(F){ .calls = try wireQ(&context, V.q(3), mutation == 9), .first_id = try wireQ(&context, V.q(7), mutation == 10), .nonempty = try wireQ(&context, V.q(1), mutation == 11) };
        const mutate: ?[3]usize = switch (mutation) {
            12 => .{ 1, B.layout.AFTER + 3, 0 },
            13 => .{ 2, B.layout.WIRE + 5, 1 },
            else => null,
        };
        const wm = try guessMasks(arena, &context, masks, mutate);
        const cpoint = A.geometry.PointFor(F){ .x = try wireQ(&context, point.x, false), .y = try wireQ(&context, point.y, false) };
        const actual = try arena.alloc(F, B.layout.CONSTRAINTS);
        Circuit.begin(&context);
        var cacc = A.lane.PointAccumulator(F).init(try wireQ(&context, randomness, false));
        var sink = V.SinkFor(F){ .values = actual, .accumulator = &cacc };
        try component.evaluatePointFor(F, cpoint, global_log, wm, span, cl, cc, &sink);
        try Circuit.finish();
        try std.testing.expectEqual(@as(usize, B.layout.CONSTRAINTS), sink.count);
        if (mutation == 0) {
            for (actual, expected) |v, q| try std.testing.expect(context.get(v.v).eql(q));
        }
        try context.eq(cacc.finalize().v, try context.constant(native_composition));
        try context.finalize(false);
        try std.testing.expectEqual(mutation == 0, try context.isCircuitValid());
    }
}

test "SHA-256 truth shape: receiver derivation equals the actual component geometry for every admitted log" {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const config = A.protocol.config();
    for ([_]u32{ 4, 5, 9, 12, 13 }) |log| {
        const shape = try Leaf.sha256Shape(arena, log, config);
        const component = H.component.Component{ .log_size = log, .public = .{ .calls = 1, .first_id = 1 }, .claim = Q.zero(), .wire = undefined };
        const handles = [_]core.air.components.Component{component.asVerifierComponent()};
        const cc = core.air.components.Components{ .components = &handles, .n_preprocessed_columns = H.layout.FIXED };
        const split = try cc.compositionLogSplit();
        try std.testing.expectEqual(shape.composition_log_split, split);
        try std.testing.expectEqual(shape.global_log, core.verifier_types.compositionMaskLogSize(cc.compositionLogDegreeBound(), split).?);
        var logs = try cc.columnLogSizes(a);
        defer logs.deinitDeep(a);
        const probe = core.circle.secureFieldPointFromRandomSeed(Q.fromU32Unchecked(7, 11, 13, 17));
        var points = try cc.maskPoints(a, probe, shape.global_log, false);
        defer points.deinitDeep(a);
        const step = core.poly.circle.canonic.CanonicCoset.new(shape.global_log).coset().step;
        const lifted = core.circle.CirclePointQM31{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) };
        for (0..3) |tree| {
            try std.testing.expectEqualSlices(u32, logs.items[tree], shape.tree_column_log_sizes[tree]);
            for (points.items[tree], shape.mask_offsets[tree]) |mask, offsets| {
                try std.testing.expectEqual(mask.len, offsets.len);
                for (mask, offsets) |p, o| try std.testing.expect(p.eql(probe.add(lifted.mulSigned(o))));
            }
        }
    }
    try std.testing.expectError(error.InvalidSha256Geometry, Leaf.sha256Shape(arena, 14, config));
}

const Prepared = struct {
    case: Fixture.Case,
    proof: G.T.P.Proof,
    truth: R.Truth,
    verified: Leaf.NativeVerified,
    fn init(mutation: Fixture.Case.Mutation) !*Prepared {
        const self = try a.create(Prepared);
        errdefer a.destroy(self);
        self.case = try Fixture.Case.init(a, mutation, false);
        errdefer self.case.deinit();
        var buffer: [2]R.Truth = undefined;
        self.truth = self.case.truths(&buffer)[0];
        self.proof = try wire_codec.decodeProofBytesBinary(a, self.case.bundle.truths[0].bytes);
        errdefer self.proof.deinit(a);
        self.verified = try Leaf.verifyNative(a, self.truth, 0, 2, self.case.expected(), &self.case.bundle.manifest, self.case.bundle.truths[0].claims, &self.proof);
        return self;
    }
    fn public(self: *const Prepared) !Leaf.Public {
        return Leaf.Public.fromTruth(self.truth, 0, self.case.expected(), &self.case.bundle.manifest, self.case.bundle.truths[0].claims);
    }
    fn deinit(self: *Prepared) void {
        self.verified.deinit(a);
        self.proof.deinit(a);
        self.case.deinit();
        a.destroy(self);
    }
};

/// The native receiver's Wire35 sum with the truth term taken from a leaf.
fn wireSum(case: *const Fixture.Case, leaf_claim: Q, include_bridges: bool) Q {
    var sum = leaf_claim;
    if (include_bridges) for (case.bundle.cpus) |cpu| {
        sum = sum.add(cpu.claims.wire());
    };
    return sum;
}

test "SHA-256 truth leaf: a services-fixture truth proof verifies in-circuit; statement, digest and Wire35 closure match the receiver" {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const prepared = try Prepared.init(.none);
    defer prepared.deinit();
    const public = try prepared.public();
    var ctx = try Circuit.Context.init(a, circuit.common.component_list.N_RESERVED);
    defer ctx.deinit();
    const built = try Leaf.build(arena, &ctx, public, prepared.truth.key().root, A.protocol.config(), &prepared.proof, &prepared.verified.capture);
    try std.testing.expect(built.valid);
    try std.testing.expectEqualSlices(u8, &prepared.verified.channel.digestBytes(), &built.channel_digest);
    const main_root = prepared.proof.commitment_scheme_proof.commitments.items[1];
    const native_words = Leaf.statementWords(public, main_root);
    try std.testing.expectEqualSlices(u32, &native_words, built.words);
    try std.testing.expectEqual(Leaf.statementDigest(&native_words), built.output);
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
    std.debug.print("SHA256_TRUTH_LEAF log={d} vars={d} gates={any}\n", .{ public.log, built.n_vars, built.gate_counts });
    // Root side: words are the receiver's own, the Wire35 bus closes only
    // with every bridge contribution present.
    const claim = try Leaf.checkStatement(built.words, prepared.truth, 0, 2, prepared.case.expected(), &prepared.case.bundle.manifest);
    try std.testing.expect(wireSum(&prepared.case, claim, true).isZero());
    try std.testing.expect(!wireSum(&prepared.case, claim, false).isZero());
    // Each statement word is load-bearing at the root.
    for ([_]usize{ Leaf.Words.ORDINAL, Leaf.Words.CALLS, Leaf.Words.FIRST_ID, Leaf.Words.PROGRAM_IDENTITY, Leaf.Words.FINAL_REGISTERS + 3, Leaf.Words.MANIFEST_DIGEST + 2, Leaf.Words.MAIN_ROOT + 7 }) |at| {
        const words = try arena.dupe(u32, built.words);
        words[at] ^= 1;
        try std.testing.expectError(error.ServicesTruthStatementMismatch, Leaf.checkStatement(words, prepared.truth, 0, 2, prepared.case.expected(), &prepared.case.bundle.manifest));
    }
    const noncanonical = try arena.dupe(u32, built.words);
    noncanonical[Leaf.Words.CLAIM] = core.fields.m31.Modulus;
    try std.testing.expectError(error.NoncanonicalSecpClaim, Leaf.checkStatement(noncanonical, prepared.truth, 0, 2, prepared.case.expected(), &prepared.case.bundle.manifest));
}

test "SHA-256 truth leaf adversarial: tampered OODS values, wrong shape, wrong public statement and claim are rejected in-circuit" {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const prepared = try Prepared.init(.none);
    defer prepared.deinit();
    const config = A.protocol.config();
    const honest = try prepared.public();
    const nv = circuit.native_verifier;
    const Mutation = enum { oods_main, oods_interaction, oods_composition, wrong_manifest, wrong_calls, wrong_claim, nonzero_absent_claim, wrong_ordinal, wrong_final_register, wrong_key_root };
    for (std.enums.values(Mutation)) |mutation| {
        var ctx = try Circuit.Context.init(a, circuit.common.component_list.N_RESERVED);
        defer ctx.deinit();
        var public = honest;
        var key_root = prepared.truth.key().root;
        switch (mutation) {
            .wrong_manifest => public.manifest_digest[5] ^= 1,
            .wrong_calls => public.calls += 1,
            .wrong_claim => public.claims[0] = public.claims[0].add(Q.one()),
            .nonzero_absent_claim => public.claims[1] = Q.one(),
            .wrong_ordinal => public.ordinal += 1,
            .wrong_final_register => public.expected.final_registers[10] ^= 1,
            .wrong_key_root => key_root[0] ^= 1,
            else => {},
        }
        const shape = try Leaf.sha256Shape(arena, public.log, config);
        var values = try nv.proof.fromNative(arena, G.T.P.Hasher, &prepared.proof, &prepared.verified.capture, &shape);
        const sampled = try arena.alloc([]const []const Q, values.sampled_values.len);
        for (sampled, values.sampled_values) |*t, src| {
            const cols = try arena.alloc([]const Q, src.len);
            for (cols, src) |*c, s| c.* = try arena.dupe(Q, s);
            t.* = cols;
        }
        const bump = struct {
            fn at(s: [][]const []const Q, arena_: std.mem.Allocator, tree: usize, column: usize, sample: usize) !void {
                const col = try arena_.dupe(Q, s[tree][column]);
                col[sample] = col[sample].add(Q.one());
                @constCast(s[tree])[column] = col;
            }
        }.at;
        switch (mutation) {
            .oods_main => try bump(sampled, arena, 1, H.layout.E + 77, 0),
            .oods_interaction => try bump(sampled, arena, 2, 6, 1),
            .oods_composition => try bump(sampled, arena, 3, 2, 0),
            else => {},
        }
        values.sampled_values = sampled;
        const wires = try nv.proof.guess(Circuit.Q, &ctx, &values);
        try @import("../rv64_recursion/native_fixed_root.zig").enforce(&ctx, wires.commitments[0], key_root);
        var statement = try Leaf.Statement.init(arena, public, config);
        _ = try nv.verify.verify(Circuit.Q, &ctx, &shape, &wires, &statement);
        _ = try statement.finish(&ctx, wires.commitments[1]);
        try ctx.finalize(false);
        try std.testing.expect(!try ctx.isCircuitValid());
    }
    // A shape for a different log is a different circuit: the native proof
    // does not even convert into its fixed-width witness.
    const wrong = try Leaf.sha256Shape(arena, honest.log + 1, config);
    try std.testing.expectError(error.ShapeMismatch, nv.proof.fromNative(arena, G.T.P.Hasher, &prepared.proof, &prepared.verified.capture, &wrong));
    // Only the SHA-256 family has a recursive truth statement today.
    var keccak = honest;
    keccak.family = .keccak;
    try std.testing.expectError(error.UnsupportedRecursiveServiceFamily, Leaf.Statement.init(arena, keccak, config));
}

test "SHA-256 truth leaf: a locally valid false output verifies as a leaf and fails only the cross-leaf Wire35 closure" {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const prepared = try Prepared.init(.wrong_output);
    defer prepared.deinit();
    const public = try prepared.public();
    var ctx = try Circuit.Context.init(a, circuit.common.component_list.N_RESERVED);
    defer ctx.deinit();
    const built = try Leaf.build(arena, &ctx, public, prepared.truth.key().root, A.protocol.config(), &prepared.proof, &prepared.verified.capture);
    try std.testing.expect(built.valid);
    const claim = try Leaf.checkStatement(built.words, prepared.truth, 0, 2, prepared.case.expected(), &prepared.case.bundle.manifest);
    try std.testing.expect(!wireSum(&prepared.case, claim, true).isZero());
    // The native receiver agrees: the same bundle is rejected globally.
    const keys = prepared.case.keys();
    var buffer: [2]R.Truth = undefined;
    try std.testing.expectError(error.UnclosedCombinedSecpWire, Exec.verify(a, &keys, prepared.case.truths(&buffer), prepared.case.expected(), &prepared.case.bundle));
}
