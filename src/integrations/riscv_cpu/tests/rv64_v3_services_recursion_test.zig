//! `ethereum_services_v3` recursion authorities (SHA-256, arith256_mod, bulk memory):
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
const Ar = A.crypto.arith256;
const BM = A.crypto.bulk_memory;
const B = A.crypto.secp256k1.word16_bridge;
const V = A.evaluation;
const Circuit = @import("../rv64_recursion/circuit_lane.zig");
const Leaf = @import("../rv64_recursion/services_truth_leaf.zig");
const Fixture = @import("../word16_global_execution/services/v3_fixture.zig");
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
    for ([_]u32{ 5, 9, 12, 13 }) |log| {
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
    try std.testing.expectError(error.InvalidRecursiveTruthGeometry, Leaf.sha256Shape(arena, 14, config));
    try std.testing.expectError(error.InvalidRecursiveTruthGeometry, Leaf.sha256Shape(arena, 4, config));
    try std.testing.expectError(error.InvalidRecursiveTruthGeometry, Leaf.truthShape(arena, .arith256_mod, Ar.layout.MIN_LOG - 1, config));
}


/// One v3 fixture (2 CPU proofs with SHA/arith/bulk bridges, then the
/// SHA-256 truth at ordinal 0 and the arith256_mod truth at ordinal 1).
const Prepared = struct {
    case: Fixture.Case,
    proofs: [2]G.T.P.Proof,
    verified: [2]Leaf.NativeVerified,
    fn init(mutation: Fixture.Case.Mutation) !*Prepared {
        const self = try a.create(Prepared);
        errdefer a.destroy(self);
        self.case = try Fixture.Case.init(a, mutation);
        errdefer self.case.deinit();
        const truths = self.case.truths();
        for (0..2) |k| {
            self.proofs[k] = try wire_codec.decodeProofBytesBinary(a, self.case.bundle.truths[k].bytes);
            self.verified[k] = try Leaf.verifyNative(a, truths[k], k, 2, self.case.expected(), &self.case.bundle.manifest, self.case.bundle.truths[k].claims, &self.proofs[k]);
        }
        return self;
    }
    fn truth(self: *const Prepared, k: usize) R.Truth {
        return self.case.truths()[k];
    }
    fn public(self: *const Prepared, k: usize) !Leaf.Public {
        return Leaf.Public.fromTruth(self.truth(k), k, self.case.expected(), &self.case.bundle.manifest, self.case.bundle.truths[k].claims);
    }
    fn leaf(self: *const Prepared, arena: std.mem.Allocator, k: usize) !Leaf.Built {
        var ctx = try Circuit.Context.init(a, circuit.common.component_list.N_RESERVED);
        defer ctx.deinit();
        const built = try Leaf.build(arena, &ctx, try self.public(k), self.truth(k).key().root, A.protocol.config(), &self.proofs[k], &self.verified[k].capture);
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid() == built.valid);
        return built;
    }
    fn deinit(self: *Prepared) void {
        for (&self.verified, &self.proofs) |*v, *p| {
            v.deinit(a);
            p.deinit(a);
        }
        self.case.deinit();
        a.destroy(self);
    }
};

/// The receiver's Wire35 sum with every truth term taken from a leaf.
fn wireSum(case: *const Fixture.Case, leaf_claims: []const Q, include_bridges: bool) Q {
    var sum = Q.zero();
    for (leaf_claims) |c| sum = sum.add(c);
    if (include_bridges) for (case.bundle.cpus) |cpu| {
        sum = sum.add(cpu.claims.wire());
    };
    return sum;
}

test "v3 truth leaves: SHA-256 and arith256_mod truth proofs verify in-circuit; statements and the cross-leaf Wire35 closure match the receiver" {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const prepared = try Prepared.init(.none);
    defer prepared.deinit();
    var claims: [2]Q = undefined;
    for (0..2) |k| {
        const built = try prepared.leaf(arena, k);
        try std.testing.expect(built.valid);
        try std.testing.expectEqualSlices(u8, &prepared.verified[k].channel.digestBytes(), &built.channel_digest);
        const public = try prepared.public(k);
        const native_words = Leaf.statementWords(public, prepared.proofs[k].commitment_scheme_proof.commitments.items[1]);
        try std.testing.expectEqualSlices(u32, &native_words, built.words);
        try std.testing.expectEqual(Leaf.statementDigest(&native_words), built.output);
        std.debug.print("V3_TRUTH_LEAF family={s} log={d} vars={d} gates={any}\n", .{ @tagName(public.family), public.log, built.n_vars, built.gate_counts });
        claims[k] = try Leaf.checkStatement(built.words, prepared.truth(k), k, 2, prepared.case.expected(), &prepared.case.bundle.manifest);
        // Each statement word is load-bearing at the root.
        for ([_]usize{ Leaf.Words.ORDINAL, Leaf.Words.CALLS, Leaf.Words.FIRST_ID, Leaf.Words.PROGRAM_IDENTITY, Leaf.Words.FINAL_REGISTERS + 3, Leaf.Words.MANIFEST_DIGEST + 2, Leaf.Words.MAIN_ROOT + 7 }) |at| {
            const words = try arena.dupe(u32, built.words);
            words[at] ^= 1;
            try std.testing.expect(std.meta.isError(Leaf.checkStatement(words, prepared.truth(k), k, 2, prepared.case.expected(), &prepared.case.bundle.manifest)));
        }
        const noncanonical = try arena.dupe(u32, built.words);
        noncanonical[Leaf.Words.CLAIM] = core.fields.m31.Modulus;
        try std.testing.expectError(error.NoncanonicalSecpClaim, Leaf.checkStatement(noncanonical, prepared.truth(k), k, 2, prepared.case.expected(), &prepared.case.bundle.manifest));
        // A leaf statement cannot be replayed at the other ordinal.
        try std.testing.expect(std.meta.isError(Leaf.checkStatement(built.words, prepared.truth(1 - k), 1 - k, 2, prepared.case.expected(), &prepared.case.bundle.manifest)));
    }
    // The claim is free at the root (only canonical); a different claim is a
    // different Wire35 sum, so closure is what binds it.
    var shifted = claims;
    shifted[0] = shifted[0].add(Q.one());
    try std.testing.expect(!wireSum(&prepared.case, &shifted, true).isZero());
    // Wire35 closes only with both truth leaves AND every CPU bridge term.
    try std.testing.expect(wireSum(&prepared.case, &claims, true).isZero());
    try std.testing.expect(!wireSum(&prepared.case, &claims, false).isZero());
    try std.testing.expect(!wireSum(&prepared.case, claims[0..1], true).isZero());
    try std.testing.expect(!wireSum(&prepared.case, claims[1..2], true).isZero());
}

test "v3 truth leaves adversarial: tampered OODS values, wrong shape, wrong public statement and claim are rejected in-circuit" {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const prepared = try Prepared.init(.none);
    defer prepared.deinit();
    const config = A.protocol.config();
    const nv = circuit.native_verifier;
    const Mutation = enum { oods_main, oods_interaction, oods_composition, oods_fixed, wrong_manifest, wrong_calls, wrong_first, wrong_claim, wrong_ordinal, wrong_final_register, wrong_key_root };
    for (0..2) |k| {
        const honest = try prepared.public(k);
        for (std.enums.values(Mutation)) |mutation| {
            var ctx = try Circuit.Context.init(a, circuit.common.component_list.N_RESERVED);
            defer ctx.deinit();
            var public = honest;
            var key_root = prepared.truth(k).key().root;
            switch (mutation) {
                .wrong_manifest => public.manifest_digest[5] ^= 1,
                .wrong_calls => public.calls += 1,
                .wrong_first => public.first_id += 1,
                .wrong_claim => public.claims[0] = public.claims[0].add(Q.one()),
                .wrong_ordinal => public.ordinal ^= 1,
                .wrong_final_register => public.expected.final_registers[10] ^= 1,
                .wrong_key_root => key_root[0] ^= 1,
                else => {},
            }
            const shape = try Leaf.truthShape(arena, public.family, public.log, config);
            var values = try nv.proof.fromNative(arena, G.T.P.Hasher, &prepared.proofs[k], &prepared.verified[k].capture, &shape);
            const sampled = try arena.alloc([]const []const Q, values.sampled_values.len);
            for (sampled, values.sampled_values) |*t, src| t.* = try arena.dupe([]const Q, src);
            const at: ?[3]usize = switch (mutation) {
                .oods_main => .{ 1, 40, 0 },
                .oods_interaction => .{ 2, 6, 0 },
                .oods_composition => .{ 3, 2, 0 },
                .oods_fixed => .{ 0, 1, 0 },
                else => null,
            };
            if (at) |m| {
                const col = try arena.dupe(Q, sampled[m[0]][m[1]]);
                col[m[2]] = col[m[2]].add(Q.one());
                const tree = try arena.dupe([]const Q, sampled[m[0]]);
                tree[m[1]] = col;
                sampled[m[0]] = tree;
            }
            values.sampled_values = sampled;
            const wires = try nv.proof.guess(Q, &ctx, &values);
            try @import("../rv64_recursion/native_fixed_root.zig").enforce(&ctx, wires.commitments[0], key_root);
            var statement = try Leaf.Statement.init(arena, public, config);
            _ = try nv.verify.verify(Q, &ctx, &shape, &wires, &statement);
            _ = try statement.finish(&ctx, wires.commitments[1]);
            try ctx.finalize(false);
            if (try ctx.isCircuitValid()) {
                std.debug.print("accepted mutation {s} for truth {d}\n", .{ @tagName(mutation), k });
                return error.TestUnexpectedResult;
            }
        }
        // A shape for a different log is a different circuit: the native
        // proof does not even convert into its fixed-width witness.
        const wrong = try Leaf.truthShape(arena, honest.family, honest.log + 1, config);
        try std.testing.expectError(error.ShapeMismatch, nv.proof.fromNative(arena, G.T.P.Hasher, &prepared.proofs[k], &prepared.verified[k].capture, &wrong));
    }
    // Absent claim slots are circuit constants (zero), so a nonzero slot can
    // only come from a proof whose transcript differs; the native capture
    // already refuses it, exactly like the receiver.
    for (0..2) |k| {
        var claims = prepared.case.bundle.truths[k].claims;
        claims[2] = Q.one();
        try std.testing.expectError(error.NonzeroAbsentServiceClaim, Leaf.verifyNative(a, prepared.truth(k), k, 2, prepared.case.expected(), &prepared.case.bundle.manifest, claims, &prepared.proofs[k]));
    }
    // The other family's shape is rejected the same way.
    const swapped = try Leaf.truthShape(arena, .arith256_mod, (try prepared.public(0)).log, config);
    try std.testing.expectError(error.ShapeMismatch, nv.proof.fromNative(arena, G.T.P.Hasher, &prepared.proofs[0], &prepared.verified[0].capture, &swapped));
    // v2 truth families have no recursive truth statement yet.
    var keccak = try prepared.public(0);
    keccak.family = .keccak;
    try std.testing.expectError(error.UnsupportedRecursiveServiceFamily, Leaf.Statement.init(arena, keccak, config));
}

test "v3 truth leaves: locally valid false SHA-256 and arith256_mod outputs verify as leaves and fail only the cross-leaf Wire35 closure" {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for ([_]Fixture.Case.Mutation{ .wrong_sha_output, .wrong_arith_output }) |mutation| {
        const prepared = try Prepared.init(mutation);
        defer prepared.deinit();
        var claims: [2]Q = undefined;
        for (0..2) |k| {
            const built = try prepared.leaf(arena, k);
            try std.testing.expect(built.valid);
            claims[k] = try Leaf.checkStatement(built.words, prepared.truth(k), k, 2, prepared.case.expected(), &prepared.case.bundle.manifest);
        }
        try std.testing.expect(!wireSum(&prepared.case, &claims, true).isZero());
        const keys = prepared.case.keys();
        const truths = prepared.case.truths();
        try std.testing.expectError(error.UnclosedCombinedSecpWire, Exec.verify(a, &keys, &truths, prepared.case.expected(), &prepared.case.bundle));
    }
}

fn arithPrevious(tree: usize, c: usize) bool {
    return Ar.component.Component.previousMask(tree, c);
}

test "arith256_mod truth: circuit point authority equals native residuals and composition; every bound wire is load-bearing" {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(0x41524d34);
    const r = prng.random();
    const masks = try makeMasks(arena, r, Ar.layout.widths(), &arithPrevious);
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = Ar.equations.Challenges{ .bytes = channel.drawSecureFelt(), .wire = A.crypto.secp256k1.equations.Wire.draw(&channel) };
    const claim = randomQ(r);
    const log: u32 = Ar.layout.MIN_LOG;
    const point = core.circle.secureFieldPointFromRandomSeed(randomQ(r));
    const randomness = randomQ(r);
    const component = Ar.component.Component{ .log_size = log, .public = .{ .calls = 3, .first_id = 11 }, .claim = claim, .challenges = ch };
    const expected = try arena.alloc(Q, Ar.layout.CONSTRAINTS);
    var acc = core.air.accumulation.PointEvaluationAccumulator.init(randomness);
    var ns = V.Sink{ .values = expected, .accumulator = &acc };
    try component.evaluatePointFor(Q, point, log, masks, component.public, claim, ch, &ns);
    const native_composition = acc.finalize();
    // Mutations: none, bytes point, wire offset, wire coefficient, claim,
    // calls, first ID, one MAIN sample, previous ACTIVE, one interaction sample.
    for (0..10) |mutation| {
        var context = try Circuit.Context.init(a, 0);
        defer context.deinit();
        var cw: A.crypto.secp256k1.equations.WireFor(F) = undefined;
        cw.offset = try wireQ(&context, ch.wire.offset, mutation == 2);
        for (&cw.coefficients, ch.wire.coefficients, 0..) |*v, q, i| v.* = try wireQ(&context, q, mutation == 3 and i == 9);
        const cch = Ar.equations.ChallengesFor(F){ .bytes = try wireQ(&context, ch.bytes, mutation == 1), .wire = cw };
        const cclaim = try wireQ(&context, claim, mutation == 4);
        const span = V.CallSpanFor(F){ .calls = try wireQ(&context, V.q(3), mutation == 5), .first_id = try wireQ(&context, V.q(11), mutation == 6), .nonempty = F.wire(context.one()) };
        const mutate: ?[3]usize = switch (mutation) {
            7 => .{ 1, Ar.layout.A + 3, 0 },
            8 => .{ 1, Ar.layout.ACTIVE, 1 },
            9 => .{ 2, 1, 0 },
            else => null,
        };
        const wm = try guessMasks(arena, &context, masks, mutate);
        const cpoint = A.geometry.PointFor(F){ .x = try wireQ(&context, point.x, false), .y = try wireQ(&context, point.y, false) };
        const actual = try arena.alloc(F, Ar.layout.CONSTRAINTS);
        Circuit.begin(&context);
        var cacc = A.lane.PointAccumulator(F).init(try wireQ(&context, randomness, false));
        var sink = V.SinkFor(F){ .values = actual, .accumulator = &cacc };
        try component.evaluatePointFor(F, cpoint, log, wm, span, cclaim, cch, &sink);
        try Circuit.finish();
        if (mutation == 0) for (actual, expected) |v, q| try std.testing.expect(context.get(v.v).eql(q));
        try context.eq(cacc.finalize().v, try context.constant(native_composition));
        try context.finalize(false);
        try std.testing.expectEqual(mutation == 0, try context.isCircuitValid());
    }
}

test "bulk memory desc/copy/set: circuit point authority equals native residuals; rows, claims and challenges are wires" {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = std.Random.DefaultPrng.init(0x424d454d);
    const r = prng.random();
    inline for (.{ BM.layout.Kind.desc, BM.layout.Kind.copy, BM.layout.Kind.set }) |kind| {
        const previous = struct {
            fn f(tree: usize, c: usize) bool {
                return if (tree == 1) BM.layout.previousMainFor(kind, c) else tree == 2 and BM.layout.previousInterFor(kind, c);
            }
        }.f;
        const masks = try makeMasks(arena, r, BM.layout.widths(kind), &previous);
        var ch: BM.types.Challenges = undefined;
        ch.ram.offset = randomQ(r);
        for (&ch.ram.coefficients) |*v| v.* = randomQ(r);
        ch.owner.offset = randomQ(r);
        for (&ch.owner.coefficients) |*v| v.* = randomQ(r);
        ch.range16 = .{ .offset = randomQ(r), .coefficient = randomQ(r) };
        const claims = BM.types.Claims{ .ram = randomQ(r), .owner = randomQ(r), .range16 = randomQ(r) };
        const log: u32 = 6;
        const global_log: u32 = 10;
        const point = core.circle.secureFieldPointFromRandomSeed(randomQ(r));
        const randomness = randomQ(r);
        const component = BM.component.Component{ .kind = kind, .log_size = log, .rows = 9, .offsets = .{ 0, 0, 0 }, .claims = claims, .challenges = ch };
        const n = BM.layout.constraints(kind);
        const expected = try arena.alloc(Q, n);
        var acc = core.air.accumulation.PointEvaluationAccumulator.init(randomness);
        var ns = V.Sink{ .values = expected, .accumulator = &acc };
        try component.evaluatePointFor(Q, point, global_log, masks, 9, claims, ch, &ns);
        const native_composition = acc.finalize();
        // Mutations: none, ram claim, owner claim, range claim, RAM coefficient,
        // owner offset, range coefficient, rows, nonempty, one MAIN sample.
        for (0..10) |mutation| {
            var context = try Circuit.Context.init(a, 0);
            defer context.deinit();
            var cc: BM.types.ChallengesFor(F) = undefined;
            cc.ram.offset = try wireQ(&context, ch.ram.offset, false);
            for (&cc.ram.coefficients, ch.ram.coefficients, 0..) |*v, q, i| v.* = try wireQ(&context, q, mutation == 4 and i == 1);
            cc.owner.offset = try wireQ(&context, ch.owner.offset, mutation == 5);
            for (&cc.owner.coefficients, ch.owner.coefficients) |*v, q| v.* = try wireQ(&context, q, false);
            cc.range16 = .{ .offset = try wireQ(&context, ch.range16.offset, false), .coefficient = try wireQ(&context, ch.range16.coefficient, mutation == 6) };
            const cl = BM.types.ClaimsFor(F){ .ram = try wireQ(&context, claims.ram, mutation == 1), .owner = try wireQ(&context, claims.owner, mutation == 2), .range16 = try wireQ(&context, claims.range16, mutation == 3) };
            const rows = BM.types.RowsFor(F){ .rows = try wireQ(&context, V.q(9), mutation == 7), .nonempty = try wireQ(&context, V.q(1), mutation == 8) };
            const wm = try guessMasks(arena, &context, masks, if (mutation == 9) .{ 1, 1, 0 } else null);
            const cpoint = A.geometry.PointFor(F){ .x = try wireQ(&context, point.x, false), .y = try wireQ(&context, point.y, false) };
            const actual = try arena.alloc(F, n);
            Circuit.begin(&context);
            var cacc = A.lane.PointAccumulator(F).init(try wireQ(&context, randomness, false));
            var sink = V.SinkFor(F){ .values = actual, .accumulator = &cacc };
            try component.evaluatePointFor(F, cpoint, global_log, wm, rows, cl, cc, &sink);
            try Circuit.finish();
            if (mutation == 0) for (actual, expected) |v, q| try std.testing.expect(context.get(v.v).eql(q));
            try context.eq(cacc.finalize().v, try context.constant(native_composition));
            try context.finalize(false);
            try std.testing.expectEqual(mutation == 0, try context.isCircuitValid());
        }
    }
}
