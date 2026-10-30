//! Canonical native unlifted FRI (fold1, constant terminal) in circuit gates.
//! Native q70 uses this schedule; Cairo circuit fold4 is a distinct protocol.
//! This verifies FRI against supplied input-evaluation wires. Binding those
//! wires to DEEP/OODS/typed AIR and admitting a leaf registry remain OPEN.
const std = @import("std");
const core = @import("stwo_core");
const b = @import("mod.zig");
const ch = @import("blake3_channel_reuse_v1.zig");
const merkle = @import("blake3_merkle_reuse_v1.zig");
const hash = @import("blake3_reuse_v1.zig");
const circle = @import("../stark_verifier/circle.zig");
const select_queries = @import("../stark_verifier/select_queries.zig");
const M = b.wrappers.M31Wrapper(b.Var);
pub const production_active = false;
pub const Geometry = struct {
    degree_log: u32,
    config: core.fri.FriConfig,
    pub fn init(degree_log: u32, config: core.fri.FriConfig) !Geometry {
        const self = Geometry{ .degree_log = degree_log, .config = config };
        try self.validate();
        return self;
    }
    pub fn validate(self: Geometry) !void {
        if (self.config.fold_step != 1 or self.config.log_last_layer_degree_bound != 0 or self.degree_log == 0 or self.degree_log > 29 or self.config.log_blowup_factor == 0 or self.config.log_blowup_factor > 16 or self.degree_log + self.config.log_blowup_factor > 30 or self.config.n_queries == 0 or self.config.n_queries > 256) return error.UnsupportedNativeCircuitFriGeometry;
    }
    pub fn startLog(self: Geometry) u32 {
        return self.degree_log + self.config.log_blowup_factor;
    }
    /// Structural key input, independently derived by a future wrapper.
    pub fn identity(self: Geometry) ![32]u8 {
        try self.validate();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("stwo-circuit/native-blake3-fri/fold1-constant/v1");
        for ([_]u32{ self.degree_log, self.config.log_blowup_factor, self.config.log_last_layer_degree_bound, @intCast(self.config.n_queries), self.config.fold_step }) |word| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            h.update(&bytes);
        }
        return h.finalResult();
    }
};
pub const Layer = struct {
    root: merkle.Digest,
    /// Two evaluations per raw query, even then odd, duplicates preserved.
    cosets: []const b.Var,
    /// Upper path above the pair's subtree, one path per raw query.
    paths: []const []const merkle.Digest,
};
pub const Proof = struct { layers: []const Layer, last_coefs: []const b.Var };
pub const Committed = struct { identity: [32]u8, alphas: []const b.Var };
pub const Result = struct { committed: Committed, queries: []const M, terminal: []const b.Var };
fn validate(g: Geometry, proof: Proof) !void {
    try g.validate();
    if (proof.layers.len != g.degree_log or proof.last_coefs.len != 1) return error.InvalidNativeCircuitFriShape;
    for (proof.layers, 0..) |layer, i| {
        if (layer.cosets.len != 2 * g.config.n_queries or layer.paths.len != g.config.n_queries) return error.InvalidNativeCircuitFriShape;
        const depth = g.startLog() - @as(u32, @intCast(i)) - 1;
        for (layer.paths) |path| if (path.len != depth) return error.InvalidNativeCircuitFriShape;
    }
}
/// Exact native commit sequence: root, secure alpha for every layer, then
/// last polynomial. This finite topology checks one accepted sampler block
/// per alpha; a rejected block fails closed rather than being host-authorized.
pub fn commit(comptime V: type, ctx: *b.Context(V), g: Geometry, transcript: *ch.Channel(V), proof: Proof) !Committed {
    try validate(g, proof);
    const alphas = try ctx.scratch().alloc(b.Var, g.degree_log);
    for (proof.layers, alphas) |layer, *alpha| {
        try transcript.mixRoot(ctx, layer.root);
        alpha.* = try transcript.drawSecureFelt(ctx, 1);
    }
    try transcript.mixFelts(ctx, proof.last_coefs);
    return .{ .identity = try g.identity(), .alphas = alphas };
}
fn leaf(comptime V: type, ctx: *b.Context(V), value: b.Var, layer_log: u32) !merkle.Digest {
    const packed_value = [1]b.Var{value};
    const lanes = b.simd.Simd.fromPacked(&packed_value, 4);
    var values: [4]M = undefined;
    for (&values, 0..) |*word, i| word.* = .newUnsafe(try b.simd.unpackIdx(V, ctx, lanes, i));
    return merkle.hashLeaf(V, ctx, .{ .column_logs = &@as([4]u32, @splat(layer_log)), .height = layer_log }, &values);
}
fn authenticatePair(comptime V: type, ctx: *b.Context(V), coset: []const b.Var, layer_log: u32, bits: []const b.Var, siblings: []const merkle.Digest, root: merkle.Digest) !void {
    if (coset.len != 2 or bits.len != siblings.len or bits.len + 1 != layer_log) return error.InvalidNativeCircuitFriShape;
    var current = try hash.protocolNode(V, ctx, try leaf(V, ctx, coset[0], layer_log), try leaf(V, ctx, coset[1], layer_log));
    // These direction bits come only from selectQueries on the authenticated
    // raw query wires; unlike PCS tree projection, FRI folding shifts bits.
    for (bits, siblings) |bit, sibling| {
        var left: merkle.Digest = undefined;
        var right: merkle.Digest = undefined;
        for (current, sibling, &left, &right) |word, other, *l, *r| {
            const selected = try b.ops.condFlipU32(V, ctx, bit, word, other);
            l.* = selected[0];
            r.* = selected[1];
        }
        current = try hash.protocolNode(V, ctx, left, right);
    }
    for (current, root) |actual, expected| try ctx.eq(actual.get(), expected.get());
}
fn choose(comptime V: type, ctx: *b.Context(V), bit: b.Var, zero: b.Var, one: b.Var) !b.Var {
    return ctx.add(zero, try ctx.mul(bit, try ctx.sub(one, zero)));
}
/// Must receive the exact commit result and query wires from the same keyed
/// transcript grammar. A host capture supplies witnesses, never this authority.
pub fn decommit(comptime V: type, ctx: *b.Context(V), g: Geometry, proof: Proof, committed: Committed, indices: []const M, fri_input: []const b.Var) ![]const b.Var {
    try validate(g, proof);
    if (!std.meta.eql(committed.identity, try g.identity()) or committed.alphas.len != g.degree_log or indices.len != g.config.n_queries or fri_input.len != g.config.n_queries) return error.InvalidNativeCircuitFriShape;
    const packed_indices = try b.simd.pack(V, ctx, indices);
    const selected = try select_queries.selectQueries(V, ctx, packed_indices, g.startLog());
    const terminal = try ctx.scratch().alloc(b.Var, g.config.n_queries);
    const bits = try ctx.scratch().alloc(b.Var, g.startLog());
    for (fri_input, terminal, 0..) |input, *output, q| {
        for (bits, selected.bits) |*bit, column| bit.* = try b.simd.unpackIdx(V, ctx, column, q);
        var x = try b.simd.unpackIdx(V, ctx, selected.points.x, q);
        const y = try b.simd.unpackIdx(V, ctx, selected.points.y, q);
        var current = input;
        for (proof.layers, committed.alphas, 0..) |layer, alpha, i| {
            const coset = layer.cosets[2 * q ..][0..2];
            try ctx.eq(current, try b.select.selectByIndex(V, ctx, coset, bits[i .. i + 1]));
            try authenticatePair(V, ctx, coset, g.startLog() - @as(u32, @intCast(i)), bits[i + 1 ..], layer.paths[q], layer.root);
            const coordinate = if (i == 0) y else x;
            const base = try choose(V, ctx, bits[i], coordinate, try ctx.sub(ctx.zero(), coordinate));
            const twiddle = try ctx.inv(base);
            const sum = try ctx.add(coset[0], coset[1]);
            const difference = try ctx.sub(coset[0], coset[1]);
            current = try ctx.add(sum, try ctx.mul(alpha, try ctx.mul(difference, twiddle)));
            // Circle-to-line keeps x; later line folds apply x -> 2x²-1.
            // The terminal polynomial is constant. A coordinate for a
            // nonexistent next fold has no consumer or verification obligation.
            if (i != 0 and i + 1 < proof.layers.len) x = try circle.doubleX(V, ctx, x);
        }
        try ctx.eq(current, proof.last_coefs[0]);
        output.* = current;
    }
    return terminal;
}
/// Genuine standalone native FRI order. PCS callers insert their exact PoW
/// verify+absorb between commit() and drawQueries()/decommit(), as native does.
pub fn verifyStandalone(comptime V: type, ctx: *b.Context(V), g: Geometry, transcript: *ch.Channel(V), proof: Proof, fri_input: []const b.Var) !Result {
    const committed = try commit(V, ctx, g, transcript, proof);
    const queries = try merkle.drawQueries(V, ctx, transcript, g.startLog(), g.config.n_queries);
    return .{ .committed = committed, .queries = queries, .terminal = try decommit(V, ctx, g, proof, committed, queries, fri_input) };
}

test {
    _ = @import("blake3_fri_reuse_v1_test.zig");
}
