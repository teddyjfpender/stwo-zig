//! Codec and PCS-only auxiliary expansion for original STARKs. No AIR receipt.
const std = @import("std");
const core = @import("stwo_core");
const b = @import("stwo_circuit_frontend").builder;
const pcs = b.blake3_pcs_reuse_v1;
const merkle = b.blake3_merkle_reuse_v1;
const fri = b.blake3_fri_reuse_v1;
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const Sources = @import("../../../frontends/riscv/recursion/block_v8_endpoint_join_source_v1.zig");
const Authority = @import("verifier.zig").Authority;
pub const production_active = false;
pub const Limits = struct { artifact_bytes: usize = 128 << 20, decode_bytes: usize = 512 << 20 };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    material: core.pcs.verifier.VerifiedProofCapture(suite.Hasher),
    pub fn deinit(v: *Owned) void {
        v.material.deinit(v.allocator);
        v.* = undefined;
    }
    /// Shape-only witness for independent NoValue registry compilation. It is
    /// not a proof, and must never be used to authorize value-mode acceptance.
    pub fn zeroForTopologyLeaky(a: std.mem.Allocator, g: pcs.Geometry) !Owned {
        try g.validate();
        // Caller owns a temporary arena and releases partial state on failure.
        const roots = try a.alloc([32]u8, g.trees.len);
        @memset(roots, @splat(0));
        const samples = try a.alloc(Q, g.sampleCount());
        @memset(samples, Q.zero());
        var count: usize = 0;
        for (g.trees) |tree| count = try std.math.add(usize, count, try std.math.mul(usize, tree.columns.len, g.config.fri_config.n_queries));
        const queries = try a.alloc(core.fields.m31.M31, count);
        @memset(queries, core.fields.m31.M31.zero());
        const paths = try a.alloc(core.vcs_lifted.verifier.MerklePathCapture(suite.Hasher), g.trees.len);
        const n = g.config.fri_config.n_queries;
        for (paths, g.trees) |*path, tree| {
            const positions = try a.alloc(usize, if (tree.columns.len == 0) @as(usize, 0) else n);
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
        return .{ .allocator = a, .material = .{ .queries = .{ .raw = &.{}, .unique = &.{} }, .commitments = roots, .column_log_sizes = &.{}, .sampled_points = &.{}, .sampled_values = samples, .queried_values = queries, .deep_answers = &.{}, .trace_paths = paths, .fri = .{ .layers = layers }, .last_layer_coefficients = last, .proof_of_work = 0, .composition_randomness = Q.zero(), .oods_seed = Q.zero(), .deep_randomness = Q.zero() } };
    }
    pub fn fromBytes(a: std.mem.Allocator, authority: *const Authority, raw: []const u8, limits: Limits) !Owned {
        try authority.validate();
        if (raw.len > limits.artifact_bytes or limits.decode_bytes == 0) return error.OriginalCircuitMaterialLimit;
        return switch (authority.source) {
            inline else => |profile, kind| blk: {
                var decoded = try decode(a, kind, profile, raw, limits);
                defer decoded.deinit();
                // Decoder claims nominate the same independently admitted ports.
                try requireClaims(a, decoded.claims, profile.claims);
                break :blk expand(a, authority, &decoded.stark.commitment_scheme_proof);
            },
        };
    }
    /// Wire allocation ignores host-computed challenge/DEEP/query/point fields.
    /// Transcript and all quotient arithmetic are re-derived in the circuit.
    pub fn allocate(v: *const Owned, comptime V: type, ctx: *b.Context(V), g: pcs.Geometry) !pcs.Proof {
        try g.validate();
        const m = &v.material;
        if (m.commitments.len != g.trees.len or m.trace_paths.len != g.trees.len or m.sampled_values.len != g.sampleCount() or m.last_layer_coefficients.len != 1 or m.fri.layers.len != (try g.friGeometry()).degree_log) return error.InvalidOriginalCircuitContainer;
        const a = ctx.scratch();
        const roots = try a.alloc(merkle.Digest, g.trees.len);
        for (roots, m.commitments) |*root, value| root.* = try digestWire(V, ctx, value);
        const samples = try fieldWires(V, ctx, m.sampled_values);
        const traces = try a.alloc(pcs.Trace, g.trees.len);
        var at: usize = 0;
        const n = g.config.fri_config.n_queries;
        for (traces, g.trees, m.trace_paths) |*trace, tree, paths| {
            const count = try std.math.mul(usize, tree.columns.len, n);
            if (at > m.queried_values.len or count > m.queried_values.len - at or paths.positions.len != (if (tree.columns.len == 0) @as(usize, 0) else n) or paths.path_depth != g.treeHeight(tree) or paths.siblings.len != n * paths.path_depth) return error.InvalidOriginalCircuitTrace;
            const values = try a.alloc(b.wrappers.M31Wrapper(b.Var), count);
            for (values, m.queried_values[at..][0..count]) |*wire, value| wire.* = try b.wrappers.guessM31(V, ctx, b.wrappers.m31Value(V, value));
            at += count;
            const path_wires = try a.alloc([]const merkle.Digest, if (tree.columns.len == 0) @as(usize, 0) else n);
            for (path_wires, 0..) |*path, q| path.* = try pathWires(V, ctx, paths.path(q));
            trace.* = .{ .values = values, .paths = path_wires };
        }
        if (at != m.queried_values.len) return error.InvalidOriginalCircuitQueryExtent;
        const layers = try a.alloc(fri.Layer, m.fri.layers.len);
        for (layers, m.fri.layers, 0..) |*layer, original, i| {
            if (original.fold_step != 1 or original.fold_width != 2 or original.query_count != n or original.values.len != 2 * n or original.positions.len != n or original.siblings.len != n * original.path_depth or original.path_depth != (try g.friGeometry()).startLog() - @as(u32, @intCast(i)) - 1) return error.InvalidOriginalCircuitFri;
            const paths = try a.alloc([]const merkle.Digest, n);
            for (paths, 0..) |*path, q| path.* = try pathWires(V, ctx, original.queryPath(q));
            layer.* = .{ .root = try digestWire(V, ctx, original.commitment), .cosets = try fieldWires(V, ctx, original.values), .paths = paths };
        }
        return .{ .roots = roots, .sampled_values = samples, .trace = traces, .nonce = .{ try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, @truncate(m.proof_of_work))), try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, @truncate(m.proof_of_work >> 32))) }, .fri_proof = .{ .layers = layers, .last_coefs = try fieldWires(V, ctx, m.last_layer_coefficients) } };
    }
};
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

fn Decoded(comptime k: Sources.Kind) type {
    return switch (k) {
        .local => @import("../../../frontends/riscv/prover/block_v8_endpoint_local_codec_v1.zig").Owned,
        .mixed => @import("../../../frontends/riscv/prover/block_v8_endpoint_mixed_codec_v1.zig").Owned,
        .bridge => @import("../../../frontends/riscv/prover/block_v8_endpoint_local_transport_v1.zig").Owned([]Q),
        .global => @import("../../../frontends/riscv/prover/block_v8_endpoint_local_transport_v1.zig").Owned(Sources.Adapter(.global).Ledger.Claims),
    };
}
fn decode(a: std.mem.Allocator, comptime k: Sources.Kind, p: anytype, raw: []const u8, limits: Limits) !Decoded(k) {
    const Transport = @import("../../../frontends/riscv/prover/block_v8_endpoint_local_transport_v1.zig");
    return switch (k) {
        .local => @import("../../../frontends/riscv/prover/block_v8_endpoint_local_codec_v1.zig").decode(a, raw, p.statement.trusted, p.statement.input, .{ .artifact_bytes = limits.artifact_bytes, .decode_bytes = limits.decode_bytes }),
        .mixed => @import("../../../frontends/riscv/prover/block_v8_endpoint_mixed_codec_v1.zig").decode(a, raw, p.statement.trusted, p.statement.input, .{ .artifact_bytes = limits.artifact_bytes, .decode_bytes = limits.decode_bytes }),
        .bridge => Transport.bridge(a, raw, @intCast(p.scope.sources.len), p.shape.mask_log, p.shape.config, .{ .artifact_bytes = limits.artifact_bytes, .decode_bytes = limits.decode_bytes }),
        .global => Transport.compact(a, raw, p.scope.event_count, p.scope.boundaryLog(), p.shape.config, .{ .artifact_bytes = limits.artifact_bytes, .decode_bytes = limits.decode_bytes }),
    };
}
fn requireClaims(a: std.mem.Allocator, actual: anytype, expected: @TypeOf(actual)) !void {
    const Wire = @import("../../../frontends/riscv/prover/block_v7_union_claim_wire_v1.zig");
    const Writer = @import("../../../frontends/riscv/prover/bounded_artifact_writer_v1.zig").Writer;
    var left = Writer.init(a, 32 << 20);
    defer left.deinit();
    var right = Writer.init(a, 32 << 20);
    defer right.deinit();
    var count: usize = 1 << 21;
    try Wire.encode(@TypeOf(actual), &left, actual, &count);
    count = 1 << 21;
    try Wire.encode(@TypeOf(actual), &right, expected, &count);
    if (!std.mem.eql(u8, left.bytes.items, right.bytes.items)) return error.OriginalCircuitClaimsMismatch;
}
fn expand(a: std.mem.Allocator, authority: *const Authority, proof: anytype) !Owned {
    const g = authority.geometry;
    if (!std.meta.eql(g.config, proof.config) or proof.commitments.items.len != g.trees.len) return error.InvalidOriginalCircuitProof;
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel).init(a, g.config);
    defer scheme.deinit(a);
    var ignored = suite.Channel{};
    for (g.trees, proof.commitments.items) |tree, root| {
        const logs = try a.alloc(u32, tree.columns.len);
        defer a.free(logs);
        for (logs, tree.columns) |*log, col| log.* = col.log_size;
        try scheme.commit(a, root, logs, &ignored);
    }
    var ch = suite.Channel{};
    var alpha: ?Q = null;
    var seed: ?Q = null;
    for (authority.schedule.operations) |op| {
        switch (op) {
            .restart => ch = .{},
            .words => |v| ch.mixU32s(v),
            .felts => |v| ch.mixFelts(v),
            .root => |v| ch.mixRoot(v),
            .integer => |v| ch.mixU64(v),
            .routed_words => |v| ch.mixU32s(try authority.nativeWords(v.source, v.values.len)),
            .routed_integer => |v| {
                const words = try authority.nativeWords(v.source, 2);
                ch.mixU64(@as(u64, words[0]) | (@as(u64, words[1]) << 32));
            },
            .routed_root => |v| {
                if (v.source.circuit == authority.schedule.public_circuit) ch.mixRoot(try authority.schedule.frame.digest(v.source.first_wire)) else {
                    if (v.source.circuit != 4_000_003 or v.source.first_wire % 8 != 0 or v.source.first_wire / 8 >= proof.commitments.items.len) return error.InvalidOriginalCircuitRoute;
                    ch.mixRoot(proof.commitments.items[v.source.first_wire / 8]);
                }
            },
            .routed_felts => |v| ch.mixFelts(try authority.nativeFelts(v.source, v.values.len)),
            .secure => |v| {
                const before = ch.n_draws;
                const n: usize = if (v.consumption == .two) 2 else 1;
                const draws = try ch.drawSecureFelts(a, n);
                defer a.free(draws);
                if (ch.n_draws - before != 1) return error.UnsupportedOriginalCircuitRejectionSchedule;
                if (v.output) |role| switch (role) {
                    .composition => alpha = draws[0],
                    .oods => {
                        seed = draws[0];
                    },
                    else => {},
                };
            },
            else => return error.InvalidOriginalCircuitPrefix,
        }
        if (seed != null) break;
    }
    const s = seed orelse return error.InvalidOriginalCircuitPrefix;
    const s2 = s.mul(s);
    const inv = try Q.one().add(s2).inv();
    const points = try samplePoints(a, g, .{ .x = Q.one().sub(s2).mul(inv), .y = s.add(s).mul(inv) });
    var capture: core.pcs.verifier.VerifiedProofCapture(suite.Hasher) = undefined;
    const prefix = ch;
    try scheme.verifyValuesWithBorrowedProofCapture(a, points, proof, &ch, .{ .composition_randomness = alpha orelse return error.InvalidOriginalCircuitPrefix, .oods_seed = s }, &capture);
    errdefer capture.deinit(a);
    var replay = prefix;
    replay.mixFelts(capture.sampled_values);
    try single(&replay);
    for (capture.fri.layers) |layer| {
        replay.mixRoot(layer.commitment);
        try single(&replay);
    }
    return .{ .allocator = a, .material = capture };
}
fn single(ch: *suite.Channel) !void {
    const before = ch.n_draws;
    _ = ch.drawSecureFelt();
    if (ch.n_draws - before != 1) return error.UnsupportedOriginalCircuitRejectionSchedule;
}
