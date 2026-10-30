//! Raw-byte witness expansion. No typed-parent verifier or Verified token is
//! used. Core PCS expansion checks compressed transport while generating paths;
//! every emitted value is subsequently an UNTRUSTED circuit witness.
const std = @import("std");
const core = @import("stwo_core");
const b = @import("stwo_circuit_frontend").builder;
const pcs = @import("stwo_circuit_frontend").builder.blake3_pcs_reuse_v1;
const merkle = @import("stwo_circuit_frontend").builder.blake3_merkle_reuse_v1;
const fri = @import("stwo_circuit_frontend").builder.blake3_fri_reuse_v1;
const Authority = @import("authority_v1.zig");
const Parent = @import("../../../frontends/riscv/recursion/blake3_execution_parent_proof.zig");
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
pub const production_active = false;
pub const Wires = struct { proof: pcs.Proof, claims: [25]b.Var };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    claims: Parent.artifact.Claims,
    material: core.pcs.verifier.VerifiedProofCapture(suite.Hasher),
    /// Shape-only witness for independent NoValue registry compilation. It is
    /// not a proof, and must never be used to authorize value-mode acceptance.
    pub fn zeroForTopologyLeaky(a: std.mem.Allocator, g: pcs.Geometry) !Owned {
        try g.validate();
        // Caller owns a temporary arena and releases partial state on failure.
        const roots = try a.alloc([32]u8, 4);
        @memset(roots, @splat(0));
        const samples = try a.alloc(Q, g.sampleCount());
        @memset(samples, Q.zero());
        var count: usize = 0;
        for (g.trees) |tree| count = try std.math.add(usize, count, try std.math.mul(usize, tree.columns.len, g.config.fri_config.n_queries));
        const queries = try a.alloc(core.fields.m31.M31, count);
        @memset(queries, core.fields.m31.M31.zero());
        const paths = try a.alloc(core.vcs_lifted.verifier.MerklePathCapture(suite.Hasher), 4);
        const n = g.config.fri_config.n_queries;
        for (paths, g.trees) |*path, tree| {
            const positions = try a.alloc(usize, n);
            @memset(positions, 0);
            const siblings = try a.alloc([32]u8, n * g.treeHeight(tree));
            @memset(siblings, @splat(0));
            path.* = .{ .positions = positions, .path_depth = g.treeHeight(tree), .siblings = siblings };
        }
        const fg = try g.friGeometry();
        const layers = try a.alloc(core.fri.FriLayerQueryCapture(suite.Hasher), fg.degree_log);
        for (layers, 0..) |*layer, i| {
            const depth = fg.startLog() - @as(u32, @intCast(i)) - 1;
            const values = try a.alloc(Q, 2 * n);
            @memset(values, Q.zero());
            const positions = try a.alloc(usize, n);
            @memset(positions, 0);
            const siblings = try a.alloc([32]u8, n * depth);
            @memset(siblings, @splat(0));
            layer.* = .{ .commitment = @splat(0), .folding_alpha = Q.zero(), .fold_step = 1, .fold_width = 2, .path_depth = depth, .query_count = n, .positions = positions, .values = values, .siblings = siblings };
        }
        const last = try a.alloc(Q, 1);
        last[0] = Q.zero();
        // No certificate is returned: these fields are just parser-compatible
        // zero payloads. The registry calls build(NoValue), never build(QM31).
        return .{ .allocator = a, .claims = @splat(Q.zero()), .material = .{ .queries = .{ .raw = &.{}, .unique = &.{} }, .commitments = roots, .column_log_sizes = &.{}, .sampled_points = &.{}, .sampled_values = samples, .queried_values = queries, .deep_answers = &.{}, .trace_paths = paths, .fri = .{ .layers = layers }, .last_layer_coefficients = last, .proof_of_work = 0, .composition_randomness = Q.zero(), .oods_seed = Q.zero(), .deep_randomness = Q.zero() } };
    }
    /// Codec + PCS-only expansion. Success here conveys no RISC AIR authority.
    pub fn fromBytes(a: std.mem.Allocator, raw: []const u8, authority: *const Authority.Owned) !Owned {
        try authority.validate();
        var decoded = try Parent.codec.decode(a, raw, &authority.profile.admission);
        defer decoded.deinit();
        const proof = &decoded.proof.?.commitment_scheme_proof;
        const g = authority.geometry;
        var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel).init(a, g.config);
        defer scheme.deinit(a);
        var ch = suite.Channel{};
        try authority.profile.admission.mix(&ch);
        try commit(a, &scheme, &ch, g, proof.commitments.items, 0);
        try commit(a, &scheme, &ch, g, proof.commitments.items, 1);
        const before = ch.n_draws;
        const draws = try ch.drawSecureFelts(a, 94);
        a.free(draws);
        if (ch.n_draws - before != 47) return error.UnsupportedRiscCircuitRejectionSchedule;
        try authority.profile.admission.mixClaims(&ch, &decoded.claims);
        try commit(a, &scheme, &ch, g, proof.commitments.items, 2);
        const alpha = try drawOne(&ch);
        try commit(a, &scheme, &ch, g, proof.commitments.items, 3);
        const seed = try drawOne(&ch);
        const seed_square = seed.mul(seed);
        const denominator = try Q.one().add(seed_square).inv();
        const point = core.circle.CirclePointQM31{ .x = Q.one().sub(seed_square).mul(denominator), .y = seed.add(seed).mul(denominator) };
        const points = try samplePoints(a, g, point);
        const opening_prefix = ch;
        // This core routine consumes the allocated sample points, including on
        // error. It borrows decoded proof bytes; no receipt crosses the API.
        var expanded: core.pcs.verifier.VerifiedProofCapture(suite.Hasher) = undefined;
        try scheme.verifyValuesWithBorrowedProofCapture(a, points, proof, &ch, .{ .composition_randomness = alpha, .oods_seed = seed }, &expanded);
        errdefer expanded.deinit(a);
        // The first finite circuit grammar has one accepted block per draw.
        // Reject unsupported retry schedules explicitly, before gate rendering.
        // Circuit sampling still constrains acceptance itself on every block.
        var replay = opening_prefix;
        replay.mixFelts(expanded.sampled_values);
        _ = try drawOne(&replay);
        for (expanded.fri.layers) |layer| {
            replay.mixRoot(layer.commitment);
            _ = try drawOne(&replay);
        }
        return .{ .allocator = a, .claims = decoded.claims, .material = expanded };
    }
    pub fn deinit(v: *Owned) void {
        v.material.deinit(v.allocator);
        v.* = undefined;
    }
    /// Wire allocation ignores host-computed challenge/DEEP/query/point fields.
    /// Transcript and all quotient arithmetic are re-derived in the circuit.
    pub fn allocate(v: *const Owned, comptime V: type, ctx: *b.Context(V), g: pcs.Geometry) !Wires {
        try g.validate();
        const m = &v.material;
        if (m.commitments.len != 4 or m.trace_paths.len != 4 or m.sampled_values.len != g.sampleCount() or m.last_layer_coefficients.len != 1 or m.fri.layers.len != (try g.friGeometry()).degree_log) return error.InvalidRiscCircuitMaterial;
        const a = ctx.scratch();
        const roots = try a.alloc(merkle.Digest, 4);
        for (roots, m.commitments) |*root, value| root.* = try digestWire(V, ctx, value);
        const samples = try fieldWires(V, ctx, m.sampled_values);
        const traces = try a.alloc(pcs.Trace, 4);
        var at: usize = 0;
        const n = g.config.fri_config.n_queries;
        for (traces, g.trees, m.trace_paths) |*trace, tree, paths| {
            const count = try std.math.mul(usize, tree.columns.len, n);
            if (at > m.queried_values.len or count > m.queried_values.len - at or paths.positions.len != n or paths.path_depth != g.treeHeight(tree)) return error.InvalidRiscCircuitMaterial;
            const values = try a.alloc(b.wrappers.M31Wrapper(b.Var), count);
            for (values, m.queried_values[at..][0..count]) |*wire, value| wire.* = try b.wrappers.guessM31(V, ctx, b.wrappers.m31Value(V, value));
            at += count;
            const path_wires = try a.alloc([]const merkle.Digest, n);
            for (path_wires, 0..) |*path, q| path.* = try pathWires(V, ctx, paths.path(q));
            trace.* = .{ .values = values, .paths = path_wires };
        }
        if (at != m.queried_values.len) return error.InvalidRiscCircuitMaterial;
        const layers = try a.alloc(fri.Layer, m.fri.layers.len);
        for (layers, m.fri.layers, 0..) |*layer, original, i| {
            if (original.fold_step != 1 or original.fold_width != 2 or original.query_count != n or original.values.len != 2 * n or original.path_depth != (try g.friGeometry()).startLog() - @as(u32, @intCast(i)) - 1) return error.InvalidRiscCircuitMaterial;
            const paths = try a.alloc([]const merkle.Digest, n);
            for (paths, 0..) |*path, q| path.* = try pathWires(V, ctx, original.queryPath(q));
            layer.* = .{ .root = try digestWire(V, ctx, original.commitment), .cosets = try fieldWires(V, ctx, original.values), .paths = paths };
        }
        var claims: [25]b.Var = undefined;
        for (&claims, v.claims) |*wire, value| wire.* = try ctx.guess(b.ivalue.fromQm31(V, value));
        return .{ .claims = claims, .proof = .{ .roots = roots, .sampled_values = samples, .trace = traces, .nonce = .{ try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, @truncate(m.proof_of_work))), try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, @truncate(m.proof_of_work >> 32))) }, .fri_proof = .{ .layers = layers, .last_coefs = try fieldWires(V, ctx, m.last_layer_coefficients) } } };
    }
};
fn drawOne(ch: *suite.Channel) !Q {
    const before = ch.n_draws;
    const value = ch.drawSecureFelt();
    if (ch.n_draws - before != 1) return error.UnsupportedRiscCircuitRejectionSchedule;
    return value;
}
fn commit(a: std.mem.Allocator, scheme: anytype, ch: *suite.Channel, g: pcs.Geometry, roots: []const [32]u8, index: usize) !void {
    if (index >= roots.len or g.trees.len != 4) return error.InvalidRiscCircuitMaterial;
    const logs = try a.alloc(u32, g.trees[index].columns.len);
    defer a.free(logs);
    for (logs, g.trees[index].columns) |*log, column| log.* = column.log_size;
    try scheme.commit(a, roots[index], logs, ch);
}
pub fn samplePoints(a: std.mem.Allocator, g: pcs.Geometry, point: core.circle.CirclePointQM31) !core.pcs.TreeVec([][]core.circle.CirclePointQM31) {
    const Point = core.circle.CirclePointQM31;
    const all = try a.alloc([][]Point, g.trees.len);
    var ready: usize = 0;
    errdefer {
        for (all[0..ready]) |tree| {
            for (tree) |column| a.free(column);
            a.free(tree);
        }
        a.free(all);
    }
    for (all, g.trees) |*tree, shape| {
        tree.* = try a.alloc([]Point, shape.columns.len);
        var columns: usize = 0;
        errdefer {
            for (tree.*[0..columns]) |column| a.free(column);
            a.free(tree.*);
        }
        for (tree.*, shape.columns) |*column, definition| {
            column.* = try a.alloc(Point, definition.masks.len);
            for (column.*, definition.masks) |*out, mask| {
                const offset = core.poly.circle.canonic.CanonicCoset.new(mask.row_log).step().mulSigned(mask.offset);
                out.* = point.add(.{ .x = Q.fromBase(offset.x), .y = Q.fromBase(offset.y) });
            }
            columns += 1;
        }
        ready += 1;
    }
    return .{ .items = all };
}
pub fn digestWire(comptime V: type, ctx: *b.Context(V), value: [32]u8) !merkle.Digest {
    var result: merkle.Digest = undefined;
    for (&result, 0..) |*word, i| word.* = try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, std.mem.readInt(u32, value[4 * i ..][0..4], .little)));
    return result;
}
fn fieldWires(comptime V: type, ctx: *b.Context(V), values: []const Q) ![]const b.Var {
    const wires = try ctx.scratch().alloc(b.Var, values.len);
    for (wires, values) |*wire, value| wire.* = try ctx.guess(b.ivalue.fromQm31(V, value));
    return wires;
}
fn pathWires(comptime V: type, ctx: *b.Context(V), values: []const [32]u8) ![]const merkle.Digest {
    const wires = try ctx.scratch().alloc(merkle.Digest, values.len);
    for (wires, values) |*wire, value| wire.* = try digestWire(V, ctx, value);
    return wires;
}
