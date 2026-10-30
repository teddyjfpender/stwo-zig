const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const postcard = @import("interop_postcard");
const b = @import("mod.zig");
const pcs = @import("blake3_pcs_reuse_v1.zig");
const channel = @import("blake3_channel_reuse_v1.zig");
const merkle = @import("blake3_merkle_reuse_v1.zig");
const fri = @import("blake3_fri_reuse_v1.zig");
const suite = core.proof_suites.Blake3;
const H = suite.Hasher;
const Q = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const Point = core.circle.CirclePointQM31;
const D = H.Hash;
const M = b.wrappers.M31Wrapper(b.Var);
const a = std.testing.allocator;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, H, suite.MerkleChannel);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(H, suite.MerkleChannel);
const masks_one = [_]pcs.Mask{.{ .row_log = 4, .offset = 0 }};
const masks_two = [_]pcs.Mask{ .{ .row_log = 4, .offset = 0 }, .{ .row_log = 4, .offset = -1 } };
const masks_three = [_]pcs.Mask{ .{ .row_log = 4, .offset = 0 }, .{ .row_log = 4, .offset = 0 }, .{ .row_log = 4, .offset = 0 } };
const trees = [_]pcs.Tree{
    .{ .columns = &.{.{ .log_size = 6, .masks = &.{} }} }, // Higher UNSAMPLED tree.
    .{ .columns = &.{ .{ .log_size = 2, .masks = &masks_one }, .{ .log_size = 3, .masks = &masks_two } } },
    .{ .columns = &.{} }, // Exact declared empty tree, still absorbed.
    .{ .columns = &.{.{ .log_size = 1, .masks = &masks_three }} },
    .{ .columns = &.{ .{ .log_size = 4, .masks = &masks_one }, .{ .log_size = 2, .masks = &.{} } } },
};
fn geometry(queries: usize, pow_bits: u32) pcs.Geometry {
    return .{ .config = .{ .pow_bits = pow_bits, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = queries, .fold_step = 1 } }, .trees = &trees };
}
fn maskPointNative(point: Point, mask: pcs.Mask) Point {
    if (mask.offset == 0) return point;
    const shift = core.poly.circle.canonic.CanonicCoset.new(mask.row_log).step().mulSigned(mask.offset);
    return point.add(.{ .x = Q.fromBase(shift.x), .y = Q.fromBase(shift.y) });
}
fn sampleShape(allocator: std.mem.Allocator, g: pcs.Geometry, point: Point) !core.pcs.TreeVec([][]Point) {
    const result = try allocator.alloc([][]Point, g.trees.len);
    var ready: usize = 0;
    errdefer {
        for (result[0..ready]) |tree| {
            for (tree) |column| allocator.free(column);
            allocator.free(tree);
        }
        allocator.free(result);
    }
    for (result, g.trees) |*tree, layout| {
        tree.* = try allocator.alloc([]Point, layout.columns.len);
        var columns: usize = 0;
        errdefer {
            for (tree.*[0..columns]) |points| allocator.free(points);
            allocator.free(tree.*);
        }
        for (tree.*, layout.columns) |*points, column| {
            points.* = try allocator.alloc(Point, column.masks.len);
            for (points.*, column.masks) |*p, mask| p.* = maskPointNative(point, mask);
            columns += 1;
        }
        ready += 1;
    }
    return .{ .items = result };
}
fn extendedLogs(allocator: std.mem.Allocator, g: pcs.Geometry) !core.pcs.TreeVec([]u32) {
    const all = try allocator.alloc([]u32, g.trees.len);
    for (all, g.trees) |*logs, tree| {
        logs.* = try allocator.alloc(u32, tree.columns.len);
        for (logs.*, tree.columns) |*log, column| log.* = column.log_size + g.config.fri_config.log_blowup_factor;
    }
    return .{ .items = all };
}
fn findHash(entries: []const core.vcs_lifted.verifier.MerkleDecommitmentLiftedAux(H).NodeValue, index: usize) !D {
    for (entries) |entry| if (entry.index == index) return entry.hash;
    return error.MissingUntrustedPcsHash;
}
fn rankOf(unique: []const usize, value: usize) !usize {
    for (unique, 0..) |index, rank| if (index == value) return rank;
    return error.MissingUntrustedPcsQuery;
}
const NativeTrace = struct { values: []M31, paths: [][]D };
const NativeFriLayer = struct { root: D, cosets: []Q, paths: [][]D, alpha: Q };
const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    g: pcs.Geometry,
    bytes: []u8,
    roots: []D,
    samples: []Q,
    trace: []NativeTrace,
    fri_layers: []NativeFriLayer,
    last: Q,
    nonce: u64,
    invalid_nonce: u64,
    seed: Q,
    oods: Point,
    beta: Q,
    raw: []usize,
    deep: []Q,
    final_digest: D,
    final_draws: u64,
    fn init(queries: usize, pow_bits: u32) !Fixture {
        const g = geometry(queries, pow_bits);
        try g.validate();
        const fg = try g.friGeometry();
        try std.testing.expectEqual(@as(u32, 5), fg.startLog());
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const own = arena.allocator();
        var native = suite.Channel{};
        g.config.mixInto(&native);
        var scheme = try Scheme.init(a, g.config);
        var scheme_owned = true;
        defer if (scheme_owned) scheme.deinit(a);
        for (g.trees, 0..) |tree, tree_index| {
            const columns = try own.alloc(engine.pcs.ColumnEvaluation, tree.columns.len);
            for (columns, tree.columns, 0..) |*column, shape, col_index| {
                const n = @as(usize, 1) << @intCast(shape.log_size);
                const coefficients = try own.alloc(M31, n);
                for (coefficients, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(37 * tree_index + 19 * col_index + 7 * i + 11));
                const polynomial = try engine.poly.circle.CircleCoefficients.initBorrowed(coefficients);
                const domain = core.poly.circle.canonic.CanonicCoset.new(shape.log_size).circleDomain();
                const values = try own.alloc(M31, n);
                for (values, 0..) |*value, i| {
                    const point = domain.at(core.utils.bitReverseIndex(i, shape.log_size));
                    value.* = try polynomial.evalAtPoint(.{ .x = Q.fromBase(point.x), .y = Q.fromBase(point.y) }).tryIntoM31();
                }
                if (values.len > 1) try std.testing.expect(!values[0].eql(values[1]));
                column.* = .{ .log_size = shape.log_size, .values = values };
            }
            try scheme.commit(a, columns, &native);
        }
        const seed = native.drawSecureFelt();
        const point = core.circle.secureFieldPointFromRandomSeed(seed);
        const opening_prefix = native;
        const points = try sampleShape(a, g, point);
        scheme_owned = false; // proveValues consumes scheme and sampled points.
        var extended = try scheme.proveValues(a, points, &native);
        defer extended.deinit(a);
        var writer: std.Io.Writer.Allocating = .init(a);
        defer writer.deinit();
        try postcard.serializeProof(H, &writer.writer, .{ .commitment_scheme_proof = extended.proof });
        const bytes = try own.dupe(u8, writer.written());
        const raw = try own.dupe(usize, extended.aux.unsorted_query_locations);
        const unique = try core.queries.sortedUniquePositions(own, raw);
        const roots = try own.dupe(D, extended.proof.commitments.items);
        const samples = try own.alloc(Q, g.sampleCount());
        var sample_at: usize = 0;
        for (extended.proof.sampled_values.items) |tree| for (tree) |column| {
            @memcpy(samples[sample_at..][0..column.len], column);
            sample_at += column.len;
        };
        var replay = opening_prefix;
        replay.mixFelts(samples);
        const beta = replay.drawSecureFelt();
        const fri_layers = try own.alloc(NativeFriLayer, fg.degree_log);
        for (fri_layers, 0..) |*layer, i| {
            const proof = if (i == 0) extended.proof.fri_proof.first_layer else extended.proof.fri_proof.inner_layers[i - 1];
            const aux = if (i == 0) extended.aux.fri.first_layer else extended.aux.fri.inner_layers[i - 1];
            replay.mixRoot(proof.commitment);
            const alpha = replay.drawSecureFelt();
            const depth = fg.startLog() - @as(u32, @intCast(i)) - 1;
            const cosets = try own.alloc(Q, 2 * queries);
            const paths = try own.alloc([]D, queries);
            for (raw, 0..) |index, q| {
                const position = index >> @intCast(i);
                const start = (position >> 1) << 1;
                for (0..2) |j| {
                    var found = false;
                    for (aux.all_values[0]) |entry| if (entry.index == start + j) {
                        cosets[2 * q + j] = entry.value;
                        found = true;
                        break;
                    };
                    if (!found) return error.MissingUntrustedPcsFriValue;
                }
                paths[q] = try own.alloc(D, depth);
                for (paths[q], 0..) |*sibling, level| sibling.* = try findHash(aux.decommitment.all_node_values[level + 1], (position >> @intCast(level + 1)) ^ 1);
            }
            layer.* = .{ .root = proof.commitment, .cosets = cosets, .paths = paths, .alpha = alpha };
        }
        const last = extended.proof.fri_proof.last_layer_poly.coefficients()[0];
        replay.mixFelts(&.{last});
        const nonce = extended.proof.proof_of_work;
        try std.testing.expect(replay.verifyPowNonce(pow_bits, nonce));
        var invalid_nonce = nonce;
        if (pow_bits > 0) {
            invalid_nonce += 1;
            while (replay.verifyPowNonce(pow_bits, invalid_nonce)) invalid_nonce += 1;
        }
        replay.mixU64(nonce);
        const replay_queries = try core.queries.drawQueries(&replay, own, fg.startLog(), queries);
        try std.testing.expectEqualSlices(usize, raw, replay_queries);
        try std.testing.expectEqualSlices(u8, &native.digestBytes(), &replay.digestBytes());
        const trace = try own.alloc(NativeTrace, g.trees.len);
        for (trace, g.trees, 0..) |*tree, layout, t| {
            const values = try own.alloc(M31, layout.columns.len * queries);
            for (layout.columns, 0..) |_, c| for (raw, 0..) |index, q| {
                values[c * queries + q] = extended.proof.queried_values.items[t][c][try rankOf(unique, index)];
            };
            const projected = try core.pcs.utils.prepareTreeQueryPositions(own, raw, fg.startLog(), if (layout.columns.len == 0) null else g.treeHeight(layout));
            const paths = try own.alloc([]D, projected.len);
            for (projected, paths) |index, *path| {
                path.* = try own.alloc(D, g.treeHeight(layout));
                for (path.*, 0..) |*sibling, level| sibling.* = try findHash(extended.aux.trace_decommitment.items[t].all_node_values[level], (index >> @intCast(level)) ^ 1);
            }
            tree.* = .{ .values = values, .paths = paths };
        }
        const expected_unique = try core.pcs.quotients.friAnswers(own, try extendedLogs(own, g), try sampleShape(own, g, point), extended.proof.sampled_values, beta, unique, extended.proof.queried_values, fg.startLog());
        const deep = try own.alloc(Q, raw.len);
        for (deep, raw) |*answer, index| answer.* = expected_unique[try rankOf(unique, index)];
        // Fresh bytes, independent shape/config and a fresh native verifier.
        var stream = std.io.fixedBufferStream(bytes);
        var decoded = try postcard.deserializeProof(H, a, stream.reader());
        var decoded_owned = true;
        defer if (decoded_owned) decoded.deinit(a);
        try std.testing.expectEqual(bytes.len, stream.pos);
        try std.testing.expectEqualDeep(g.config, decoded.commitment_scheme_proof.config);
        var receiver = try Verifier.init(a, g.config);
        defer receiver.deinit(a);
        var receiver_channel = suite.Channel{};
        g.config.mixInto(&receiver_channel);
        for (decoded.commitment_scheme_proof.commitments.items, g.trees) |root, layout| {
            const logs = try own.alloc(u32, layout.columns.len);
            for (logs, layout.columns) |*log, column| log.* = column.log_size;
            try receiver.commit(a, root, logs, &receiver_channel);
        }
        try std.testing.expectEqualDeep(seed, receiver_channel.drawSecureFelt());
        var capture: core.pcs.verifier.QueryCapture = undefined;
        const receiver_points = try sampleShape(a, g, point);
        decoded_owned = false; // Native verifyValues consumes proof and points.
        try receiver.verifyValuesWithQueryCapture(a, receiver_points, decoded.commitment_scheme_proof, &receiver_channel, &capture);
        defer capture.deinit(a);
        try std.testing.expectEqualSlices(usize, raw, capture.raw);
        try std.testing.expectEqualSlices(u8, &native.digestBytes(), &receiver_channel.digestBytes());
        return .{ .arena = arena, .g = g, .bytes = bytes, .roots = roots, .samples = samples, .trace = trace, .fri_layers = fri_layers, .last = last, .nonce = nonce, .invalid_nonce = invalid_nonce, .seed = seed, .oods = point, .beta = beta, .raw = raw, .deep = deep, .final_digest = native.digestBytes(), .final_draws = native.n_draws };
    }
    fn deinit(self: *Fixture) void {
        self.arena.deinit();
    }
};
fn rootWire(comptime V: type, ctx: *b.Context(V), bytes: D) !merkle.Digest {
    var root: merkle.Digest = undefined;
    for (&root, 0..) |*word, i| word.* = try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, std.mem.readInt(u32, bytes[4 * i ..][0..4], .little)));
    return root;
}
const Fault = enum { none, oods, leaf, nonce, root, fri };
fn proofWires(comptime V: type, ctx: *b.Context(V), fixture: *const Fixture, fault: Fault) !pcs.Proof {
    const roots = try ctx.scratch().alloc(merkle.Digest, fixture.roots.len);
    for (roots, fixture.roots, 0..) |*wire, value, i| {
        var bytes = value;
        if (fault == .root and i == 0) bytes[0] ^= 1;
        wire.* = try rootWire(V, ctx, bytes);
    }
    const samples = try ctx.scratch().alloc(b.Var, fixture.samples.len);
    for (samples, fixture.samples, 0..) |*wire, value, i| wire.* = try ctx.guess(b.ivalue.fromQm31(V, if (fault == .oods and i == 0) value.add(Q.one()) else value));
    const trace = try ctx.scratch().alloc(pcs.Trace, fixture.trace.len);
    for (trace, fixture.trace, 0..) |*target, source, t| {
        const values = try ctx.scratch().alloc(M, source.values.len);
        for (values, source.values, 0..) |*wire, value, i| wire.* = try b.wrappers.guessM31(V, ctx, b.wrappers.m31Value(V, if (fault == .leaf and t == 0 and i == 0) value.add(M31.one()) else value));
        const paths = try ctx.scratch().alloc([]const merkle.Digest, source.paths.len);
        for (paths, source.paths) |*path, hashes| {
            const siblings = try ctx.scratch().alloc(merkle.Digest, hashes.len);
            for (siblings, hashes) |*wire, hash| wire.* = try rootWire(V, ctx, hash);
            path.* = siblings;
        }
        target.* = .{ .values = values, .paths = paths };
    }
    const layers = try ctx.scratch().alloc(fri.Layer, fixture.fri_layers.len);
    for (layers, fixture.fri_layers, 0..) |*target, source, layer| {
        const cosets = try ctx.scratch().alloc(b.Var, source.cosets.len);
        for (cosets, source.cosets, 0..) |*wire, value, i| wire.* = try ctx.guess(b.ivalue.fromQm31(V, if (fault == .fri and layer == 0 and i == 0) value.add(Q.one()) else value));
        const paths = try ctx.scratch().alloc([]const merkle.Digest, source.paths.len);
        for (paths, source.paths) |*path, hashes| {
            const siblings = try ctx.scratch().alloc(merkle.Digest, hashes.len);
            for (siblings, hashes) |*wire, hash| wire.* = try rootWire(V, ctx, hash);
            path.* = siblings;
        }
        target.* = .{ .root = try rootWire(V, ctx, source.root), .cosets = cosets, .paths = paths };
    }
    const last = try ctx.scratch().alloc(b.Var, 1);
    last[0] = try ctx.guess(b.ivalue.fromQm31(V, fixture.last));
    const nonce = if (fault == .nonce) fixture.invalid_nonce else fixture.nonce;
    return .{ .roots = roots, .sampled_values = samples, .trace = trace, .nonce = .{ try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, @truncate(nonce))), try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, @truncate(nonce >> 32))) }, .fri_proof = .{ .layers = layers, .last_coefs = last } };
}
fn run(comptime V: type, ctx: *b.Context(V), fixture: *const Fixture, fault: Fault) !pcs.Result {
    var transcript = try channel.Channel(V).init(ctx);
    const result = try pcs.verifyStandalone(V, ctx, fixture.g, &transcript, try proofWires(V, ctx, fixture, fault));
    if (V == Q and fault == .none) {
        try std.testing.expectEqualDeep(fixture.seed, ctx.get(result.oods.seed));
        try std.testing.expectEqualDeep(fixture.oods.x, ctx.get(result.oods.point.x));
        try std.testing.expectEqualDeep(fixture.oods.y, ctx.get(result.oods.point.y));
        try std.testing.expectEqualDeep(fixture.beta, ctx.get(result.deep_randomness));
        for (result.deep_answers, fixture.deep) |wire, value| try std.testing.expectEqualDeep(value, ctx.get(wire));
        for (result.queries, fixture.raw) |wire, index| try std.testing.expectEqualDeep(Q.fromU32Unchecked(@intCast(index), 0, 0, 0), ctx.get(wire.get()));
        for (result.fri_commit.alphas, fixture.fri_layers) |wire, layer| try std.testing.expectEqualDeep(layer.alpha, ctx.get(wire));
        for (transcript.digest, 0..) |wire, i| try std.testing.expectEqual(std.mem.readInt(u32, fixture.final_digest[4 * i ..][0..4], .little), b.ivalue.unpackU32(Q, ctx.get(wire.get())));
        try std.testing.expectEqual(fixture.final_draws, transcript.n_draws);
    }
    return result;
}
test "circuit native PCS full heterogeneous opening and DEEP binding q8 and q70 pow26" {
    for ([_][2]u32{ .{ 8, 0 }, .{ 70, 26 } }) |profile| {
        var fixture = try Fixture.init(profile[0], profile[1]);
        defer fixture.deinit();
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        _ = try run(Q, &ctx, &fixture, .none);
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        if (profile[1] > 0) {
            var invalid = try b.Context(Q).init(a, 0);
            defer invalid.deinit();
            _ = try run(Q, &invalid, &fixture, .nonce);
            try invalid.finalize(false);
            try std.testing.expect(!try invalid.isCircuitValid());
        }
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(fixture.bytes, &hash, .{});
        std.debug.print("CIRCUIT_NATIVE_PCS q={d} pow={d} trees={d} bytes={d} sha256={s} geometry={s} nonce={d}\n", .{ profile[0], profile[1], fixture.roots.len, fixture.bytes.len, std.fmt.bytesToHex(hash, .lower), std.fmt.bytesToHex(try fixture.g.identity(), .lower), fixture.nonce });
        const out = "vectors/reports/riscv-cpu-architecture-20261029/circuit-native-pcs-kernel-v1";
        try std.fs.cwd().makePath(out);
        const path = try std.fmt.allocPrint(a, "{s}/q{d}-pow{d}-native-pcs.bin", .{ out, profile[0], profile[1] });
        defer a.free(path);
        try std.fs.cwd().writeFile(.{ .sub_path = path, .data = fixture.bytes });
    }
}
test "circuit native PCS rejects altered OODS cells leaf roots and FRI witnesses" {
    var fixture = try Fixture.init(8, 0);
    defer fixture.deinit();
    for ([_]Fault{ .oods, .leaf, .root, .fri }) |fault| {
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        _ = try run(Q, &ctx, &fixture, fault);
        try ctx.finalize(false);
        try std.testing.expect(!try ctx.isCircuitValid());
    }
}
test "circuit native PCS DEEP answer cannot be host-authorized independently of OODS and leaves" {
    var fixture = try Fixture.init(8, 0);
    defer fixture.deinit();
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    const result = try run(Q, &ctx, &fixture, .none);
    const wrong = try ctx.guess(fixture.deep[0].add(Q.one()));
    try ctx.eq(result.deep_answers[0], wrong);
    try ctx.finalize(false);
    try std.testing.expect(!try ctx.isCircuitValid());
}
test "circuit native PCS geometry and masks are independent of proof shape" {
    const g = geometry(8, 0);
    var wrong = g;
    wrong.config.lifting_log_size = 8;
    try std.testing.expectError(error.UnsupportedNativeCircuitPcsGeometry, wrong.validate());
    wrong = g;
    wrong.config.fri_config.fold_step = 4;
    try std.testing.expectError(error.UnsupportedNativeCircuitFriGeometry, wrong.validate());
    var fixture = try Fixture.init(8, 0);
    defer fixture.deinit();
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    var transcript = try channel.Channel(Q).init(&ctx);
    var proof = try proofWires(Q, &ctx, &fixture, .none);
    proof.sampled_values = proof.sampled_values[0 .. proof.sampled_values.len - 1];
    try std.testing.expectError(error.InvalidNativeCircuitPcsShape, pcs.verifyStandalone(Q, &ctx, g, &transcript, proof));
}
test "circuit native PCS NoValue topology and gate-free replay preserve full opening equations" {
    var fixture = try Fixture.init(8, 0);
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
    try std.testing.expectEqualDeep(values.value_table.items, replay.value_table.items);
    try std.testing.expectEqualDeep(values.gate_counts, replay.gate_counts);
    try std.testing.expect(try values.isCircuitValid());
}
