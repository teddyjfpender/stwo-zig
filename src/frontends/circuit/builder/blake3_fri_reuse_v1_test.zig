const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const postcard = @import("interop_postcard");
const b = @import("mod.zig");
const f = @import("blake3_fri_reuse_v1.zig");
const channel = @import("blake3_channel_reuse_v1.zig");
const merkle = @import("blake3_merkle_reuse_v1.zig");
const suite = core.proof_suites.Blake3;
const H = suite.Hasher;
const Q = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const a = std.testing.allocator;
const Prover = engine.fri.FriProver(Cpu, H, suite.MerkleChannel);
const Verifier = core.fri.FriVerifier(H, suite.MerkleChannel);
const Capture = core.fri.FriQueryCapture(H);
const Fixture = struct {
    geometry: f.Geometry,
    capture: Capture,
    raw: []usize,
    answers: []Q,
    last: Q,
    bytes: []u8,
    final_digest: [32]u8,
    final_draws: u64,
    fn init(queries: usize) !Fixture {
        return initMode(queries, false);
    }
    fn initMode(queries: usize, forged_terminal: bool) !Fixture {
        const g = try f.Geometry.init(4, .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = queries, .fold_step = 1 });
        const domain = core.poly.circle.canonic.CanonicCoset.new(g.startLog()).circleDomain();
        var coefficients: [16]M31 = undefined;
        for (&coefficients, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(17 * i + 11));
        const poly = try engine.poly.circle.CircleCoefficients.initBorrowed(&coefficients);
        const values = try a.alloc(Q, domain.size());
        defer a.free(values);
        for (values, 0..) |*value, i| {
            const point = domain.at(core.utils.bitReverseIndex(i, g.startLog()));
            value.* = poly.evalAtPoint(.{ .x = Q.fromBase(point.x), .y = Q.fromBase(point.y) });
        }
        try std.testing.expect(!values[0].eql(values[1]));
        const column = try engine.secure_column.SecureColumnByCoords.fromSecureSlice(a, values);
        var native = suite.Channel{};
        var prover = try Prover.commit(a, &native, g.config, domain, column);
        if (forged_terminal) {
            // Keep every genuine layer/root unchanged. Rebind the transcript
            // to a false terminal and open all authentic layers at its queries.
            prover.last_layer_poly.coefficientsMut()[0] = prover.last_layer_poly.coefficients()[0].add(Q.one());
            native = suite.Channel{};
            native.mixRoot(prover.first_layer.merkle_tree.root());
            _ = native.drawSecureFelt();
            for (prover.inner_layers) |layer| {
                native.mixRoot(layer.merkle_tree.root());
                _ = native.drawSecureFelt();
            }
            native.mixFelts(prover.last_layer_poly.coefficients());
        }
        var result = try prover.decommit(a, &native);
        defer result.deinit(a);
        // Existing native postcard codec carries the genuine FRI body. The
        // empty surrounding PCS is a transport carrier, NOT a STARK claim.
        const carrier: core.proof.StarkProof(H) = .{ .commitment_scheme_proof = .{
            .config = .{ .pow_bits = 0, .fri_config = g.config },
            .commitments = .{ .items = &.{} },
            .sampled_values = .{ .items = &.{} },
            .decommitments = .{ .items = &.{} },
            .queried_values = .{ .items = &.{} },
            .proof_of_work = 0,
            .fri_proof = result.fri_proof.proof,
        } };
        var buffer: std.Io.Writer.Allocating = .init(a);
        defer buffer.deinit();
        try postcard.serializeProof(H, &buffer.writer, carrier);
        const bytes = try a.dupe(u8, buffer.written());
        errdefer a.free(bytes);
        var stream = std.io.fixedBufferStream(bytes);
        var decoded = try postcard.deserializeProof(H, a, stream.reader());
        defer decoded.deinit(a);
        try std.testing.expectEqual(bytes.len, stream.pos);
        var verifier_channel = suite.Channel{};
        var verifier = try Verifier.commit(a, &verifier_channel, g.config, decoded.commitment_scheme_proof.fri_proof, .{ .log_degree_bound = g.degree_log });
        defer verifier.deinit(a);
        var positions = try verifier.sampleQueryPositionsWithRaw(a, &verifier_channel);
        defer positions.deinit(a);
        try std.testing.expectEqualSlices(usize, result.unsorted_query_locations, positions.raw);
        const unique_answers = try a.alloc(Q, positions.unique.len);
        defer a.free(unique_answers);
        for (unique_answers, positions.unique) |*value, index| value.* = values[index];
        var capture: Capture = undefined;
        if (forged_terminal) {
            // This exact native error occurs AFTER all authentication and fold
            // checks. There is deliberately no successful verifier capture.
            try std.testing.expectError(error.LastLayerEvaluationsInvalid, verifier.decommit(a, unique_answers));
            capture = try expandUntrusted(g, &result.fri_proof, positions.raw, &verifier);
        } else try verifier.decommitWithQueryCapture(a, unique_answers, positions.raw, &capture);
        errdefer capture.deinit(a);
        const raw = try a.dupe(usize, positions.raw);
        errdefer a.free(raw);
        const answers = try a.alloc(Q, raw.len);
        for (answers, raw) |*value, index| value.* = values[index];
        return .{ .geometry = g, .capture = capture, .raw = raw, .answers = answers, .last = decoded.commitment_scheme_proof.fri_proof.last_layer_poly.coefficients()[0], .bytes = bytes, .final_digest = verifier_channel.digestBytes(), .final_draws = verifier_channel.n_draws };
    }
    fn deinit(self: *Fixture) void {
        self.capture.deinit(a);
        a.free(self.raw);
        a.free(self.answers);
        a.free(self.bytes);
    }
};
// Witness extraction from prover aux, used ONLY for an invalid terminal
// proof that the native verifier rejects. No verification receipt is created.
fn expandUntrusted(g: f.Geometry, extended: *const core.fri.ExtendedFriProof(H), raw: []const usize, verifier: *const Verifier) !Capture {
    const layers = try a.alloc(core.fri.FriLayerQueryCapture(H), g.degree_log);
    errdefer a.free(layers);
    var ready: usize = 0;
    errdefer for (layers[0..ready]) |*layer| layer.deinit(a);
    for (layers, 0..) |*layer, i| {
        const aux = if (i == 0) extended.aux.first_layer else extended.aux.inner_layers[i - 1];
        const source = if (i == 0) extended.proof.first_layer else extended.proof.inner_layers[i - 1];
        const depth = g.startLog() - @as(u32, @intCast(i)) - 1;
        const positions = try a.alloc(usize, raw.len);
        errdefer a.free(positions);
        const values = try a.alloc(Q, raw.len * 2);
        errdefer a.free(values);
        const siblings = try a.alloc(H.Hash, raw.len * depth);
        errdefer a.free(siblings);
        for (raw, 0..) |index, q| {
            const position = index >> @intCast(i);
            positions[q] = position;
            const start = (position >> 1) << 1;
            for (0..2) |j| {
                var found = false;
                for (aux.all_values[0]) |entry| if (entry.index == start + j) {
                    values[2 * q + j] = entry.value;
                    found = true;
                    break;
                };
                if (!found) return error.MissingUntrustedFriWitness;
            }
            for (0..depth) |level| {
                const sibling_index = (position >> @intCast(level + 1)) ^ 1;
                var found = false;
                for (aux.decommitment.all_node_values[level + 1]) |entry| if (entry.index == sibling_index) {
                    siblings[q * depth + level] = entry.hash;
                    found = true;
                    break;
                };
                if (!found) return error.MissingUntrustedFriWitness;
            }
        }
        layer.* = .{ .commitment = source.commitment, .folding_alpha = if (i == 0) verifier.first_layer.folding_alpha else verifier.inner_layers[i - 1].folding_alpha, .fold_step = 1, .fold_width = 2, .path_depth = depth, .query_count = raw.len, .positions = positions, .values = values, .siblings = siblings };
        ready += 1;
    }
    return .{ .layers = layers };
}

fn rootWire(comptime V: type, ctx: *b.Context(V), digest: [32]u8) !merkle.Digest {
    var out: merkle.Digest = undefined;
    for (&out, 0..) |*word, i| word.* = try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, std.mem.readInt(u32, digest[4 * i ..][0..4], .little)));
    return out;
}
const Fault = enum { none, fold, last, input, sibling, root };
fn proofWires(comptime V: type, ctx: *b.Context(V), fixture: *const Fixture, fault: Fault) !f.Proof {
    const layers = try ctx.scratch().alloc(f.Layer, fixture.capture.layers.len);
    for (layers, fixture.capture.layers, 0..) |*layer, captured, index| {
        const cosets = try ctx.scratch().alloc(b.Var, captured.values.len);
        for (cosets, captured.values, 0..) |*wire, value, i| wire.* = try ctx.guess(b.ivalue.fromQm31(V, if (fault == .fold and index == 1 and i == 0) value.add(Q.one()) else value));
        const paths = try ctx.scratch().alloc([]const merkle.Digest, captured.query_count);
        for (paths, 0..) |*path, q| {
            const siblings = try ctx.scratch().alloc(merkle.Digest, captured.path_depth);
            for (siblings, captured.queryPath(q), 0..) |*wire, digest, i| {
                var bytes = digest;
                if (fault == .sibling and index == 0 and q == 0 and i == 0) bytes[0] ^= 1;
                wire.* = try rootWire(V, ctx, bytes);
            }
            path.* = siblings;
        }
        var root = captured.commitment;
        if (fault == .root and index == 0) root[7] ^= 1;
        layer.* = .{ .root = try rootWire(V, ctx, root), .cosets = cosets, .paths = paths };
    }
    const last = try ctx.scratch().alloc(b.Var, 1);
    last[0] = try ctx.guess(b.ivalue.fromQm31(V, if (fault == .last) fixture.last.add(Q.one()) else fixture.last));
    return .{ .layers = layers, .last_coefs = last };
}
fn run(comptime V: type, ctx: *b.Context(V), fixture: *const Fixture, fault: Fault) !f.Result {
    const proof = try proofWires(V, ctx, fixture, fault);
    const input = try ctx.scratch().alloc(b.Var, fixture.answers.len);
    for (input, fixture.answers, 0..) |*wire, value, i| wire.* = try ctx.guess(b.ivalue.fromQm31(V, if (fault == .input and i == 0) value.add(Q.one()) else value));
    var transcript = try channel.Channel(V).init(ctx);
    const result = try f.verifyStandalone(V, ctx, fixture.geometry, &transcript, proof, input);
    if (V == Q and fault == .none) {
        for (result.committed.alphas, fixture.capture.layers) |alpha, captured| try std.testing.expectEqualDeep(captured.folding_alpha, ctx.get(alpha));
        for (result.queries, fixture.raw) |index, expected| try std.testing.expectEqualDeep(Q.fromU32Unchecked(@intCast(expected), 0, 0, 0), ctx.get(index.get()));
        for (transcript.digest, 0..) |word, i| try std.testing.expectEqual(std.mem.readInt(u32, fixture.final_digest[4 * i ..][0..4], .little), b.ivalue.unpackU32(Q, ctx.get(word.get())));
        try std.testing.expectEqual(fixture.final_draws, transcript.n_draws);
    }
    return result;
}
test "circuit native FRI genuine nonconstant proof fresh postcard native verify q8 and q70" {
    for ([_]usize{ 8, 70 }) |queries| {
        var fixture = try Fixture.init(queries);
        defer fixture.deinit();
        // All original prover/decoder/native-verifier objects have already
        // been destroyed. Captured values are only fully checked witnesses.
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        _ = try run(Q, &ctx, &fixture, .none);
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(fixture.bytes, &digest, .{});
        const expected = if (queries == 8) "810de08d0946ee7fa071bbc9d4ff9aa7c4c4058d2519ee21d9bff19e8e135ad7" else "d5d4362ca93cc2d4f3865aa788381871380d8008c487526a1c2a3daf15be01a9";
        try std.testing.expectEqualStrings(expected, &std.fmt.bytesToHex(digest, .lower));
        std.debug.print("CIRCUIT_NATIVE_FRI q={d} degree_log={d} bytes={d} sha256={s} geometry={s}\n", .{ queries, fixture.geometry.degree_log, fixture.bytes.len, std.fmt.bytesToHex(digest, .lower), std.fmt.bytesToHex(try fixture.geometry.identity(), .lower) });
        const out = "vectors/reports/riscv-cpu-architecture-20261029/circuit-native-fri-kernel-v1";
        try std.fs.cwd().makePath(out);
        const name = try std.fmt.allocPrint(a, "{s}/q{d}-native-fri-postcard-carrier.bin", .{ out, queries });
        defer a.free(name);
        try std.fs.cwd().writeFile(.{ .sub_path = name, .data = fixture.bytes });
    }
}
test "circuit native FRI rejects wrong fold terminal polynomial input and path" {
    var fixture = try Fixture.init(8);
    defer fixture.deinit();
    for ([_]Fault{ .fold, .last, .input, .sibling, .root }) |fault| {
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        _ = try run(Q, &ctx, &fixture, fault);
        try ctx.finalize(false);
        try std.testing.expect(!try ctx.isCircuitValid());
    }
}
test "circuit native FRI derived challenge cannot be replaced by host nomination" {
    var fixture = try Fixture.init(8);
    defer fixture.deinit();
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    const result = try run(Q, &ctx, &fixture, .none);
    const wrong = try ctx.guess(fixture.capture.layers[0].folding_alpha.add(Q.one()));
    try ctx.eq(result.committed.alphas[0], wrong);
    try ctx.finalize(false);
    try std.testing.expect(!try ctx.isCircuitValid());
}
test "circuit native FRI topology and gate-free value replay match original equations" {
    var fixture = try Fixture.init(8);
    defer fixture.deinit();
    var values = try b.Context(Q).init(a, 0);
    defer values.deinit();
    var topology = try b.Context(b.NoValue).init(a, 0);
    defer topology.deinit();
    var replay = try b.Context(Q).initWithGateRecording(a, 0, false);
    defer replay.deinit();
    _ = try run(Q, &values, &fixture, .none);
    _ = try run(b.NoValue, &topology, &fixture, .none);
    _ = try run(Q, &replay, &fixture, .none);
    try values.finalize(false);
    try topology.finalize(false);
    try replay.finalize(false);
    try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
    inline for (.{ "add", "sub", "mul", "pointwise_mul", "eq", "blake_g_gate", "triple_xor", "m31_to_u32", "output" }) |field| try std.testing.expectEqualDeep(@field(values.circuit, field).items, @field(topology.circuit, field).items);
    try std.testing.expectEqualDeep(values.gate_counts, replay.gate_counts);
    try std.testing.expectEqualDeep(values.value_table.items, replay.value_table.items);
    try std.testing.expect(try values.isCircuitValid());
}
test "circuit native FRI geometry rejects Cairo fold4 and untrusted proof shapes" {
    const config = core.fri.FriConfig{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 4 };
    try std.testing.expectError(error.UnsupportedNativeCircuitFriGeometry, f.Geometry.init(4, config));
    var fixture = try Fixture.init(8);
    defer fixture.deinit();
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    var transcript = try channel.Channel(Q).init(&ctx);
    var proof = try proofWires(Q, &ctx, &fixture, .none);
    proof.layers = proof.layers[0..3];
    try std.testing.expectError(error.InvalidNativeCircuitFriShape, f.commit(Q, &ctx, fixture.geometry, &transcript, proof));
}

test "circuit native FRI rejects authentic root paths with forged transcript-bound terminal polynomial" {
    var fixture = try Fixture.initMode(70, true);
    defer fixture.deinit();
    // Native verifier rejected ONLY at the terminal polynomial equation;
    // all roots, alpha draws, query positions and authentication paths match.
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    _ = try run(Q, &ctx, &fixture, .none);
    try ctx.finalize(false);
    try std.testing.expect(!try ctx.isCircuitValid());
}
