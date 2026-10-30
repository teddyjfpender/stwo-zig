//! Complete finite native unlifted PCS opening kernel, not typed AIR/VM closure.
//! Geometry is independently authorized structural data; all request roots,
//! OODS samples, queried cells, nonce and FRI proof material are circuit wires.
//! No four-tree container, host verifier receipt or free DEEP-value input exists.
const std = @import("std");
const core = @import("stwo_core");
const b = @import("mod.zig");
const channel = @import("blake3_channel_reuse_v1.zig");
const merkle = @import("blake3_merkle_reuse_v1.zig");
const fri = @import("blake3_fri_reuse_v1.zig");
const circle = @import("../stark_verifier/circle.zig");
const select_queries = @import("../stark_verifier/select_queries.zig");
const Q = core.fields.qm31.QM31;
const M = b.wrappers.M31Wrapper(b.Var);
const W = b.wrappers.U32Wrapper(b.Var);
pub const Point = circle.Point(b.Var);
pub const production_active = false;
pub const Mask = struct { row_log: u32, offset: i32 };
pub const Column = struct { log_size: u32, masks: []const Mask };
pub const Tree = struct { columns: []const Column };
pub const Geometry = struct {
    config: core.pcs.PcsConfig,
    trees: []const Tree,
    pub fn validate(g: Geometry) !void {
        if (g.config.lifting_log_size != null or g.config.pow_bits > 32 or g.trees.len == 0 or g.trees.len > 256) return error.UnsupportedNativeCircuitPcsGeometry;
        var columns: usize = 0;
        var samples: usize = 0;
        var max_sample_log: ?u32 = null;
        for (g.trees) |tree| for (tree.columns) |column| {
            if (column.log_size > 29 or g.config.fri_config.log_blowup_factor > 30 - column.log_size or column.masks.len > 8) return error.UnsupportedNativeCircuitPcsGeometry;
            columns = try std.math.add(usize, columns, 1);
            samples = try std.math.add(usize, samples, column.masks.len);
            for (column.masks) |mask| if (mask.row_log > 30 or (mask.offset != 0 and mask.row_log == 0)) return error.UnsupportedNativeCircuitPcsGeometry;
            if (column.masks.len > 0) max_sample_log = if (max_sample_log) |log| @max(log, column.log_size) else column.log_size;
        };
        if (columns > 1 << 16 or samples == 0 or samples > (channel.MAX_FRAME_WORDS - 17) / 4) return error.UnsupportedNativeCircuitPcsGeometry;
        _ = try fri.Geometry.init(max_sample_log orelse return error.UnsupportedNativeCircuitPcsGeometry, g.config.fri_config);
    }
    pub fn friGeometry(g: Geometry) !fri.Geometry {
        try g.validate();
        var log: u32 = 0;
        for (g.trees) |tree| for (tree.columns) |column| {
            if (column.masks.len > 0) log = @max(log, column.log_size);
        };
        return fri.Geometry.init(log, g.config.fri_config);
    }
    pub fn sampleCount(g: Geometry) usize {
        var total: usize = 0;
        for (g.trees) |tree| for (tree.columns) |column| {
            total += column.masks.len;
        };
        return total;
    }
    pub fn treeHeight(g: Geometry, tree: Tree) u32 {
        if (tree.columns.len == 0) return 0;
        var height: u32 = 0;
        for (tree.columns) |column| height = @max(height, column.log_size + g.config.fri_config.log_blowup_factor);
        return height;
    }
    pub fn identity(g: Geometry) ![32]u8 {
        try g.validate();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("stwo-circuit/native-unlifted-blake3-pcs/v1");
        const mix = struct {
            fn word(hash: anytype, value: u32) void {
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, value, .little);
                hash.update(&bytes);
            }
        }.word;
        mix(&h, g.config.pow_bits);
        mix(&h, g.config.fri_config.log_blowup_factor);
        mix(&h, @intCast(g.config.fri_config.n_queries));
        mix(&h, g.config.fri_config.log_last_layer_degree_bound);
        mix(&h, g.config.fri_config.fold_step);
        mix(&h, @intCast(g.trees.len));
        for (g.trees) |tree| {
            mix(&h, @intCast(tree.columns.len));
            for (tree.columns) |column| {
                mix(&h, column.log_size);
                mix(&h, @intCast(column.masks.len));
                for (column.masks) |mask| {
                    mix(&h, mask.row_log);
                    mix(&h, @bitCast(mask.offset));
                }
            }
        }
        return h.finalResult();
    }
};
pub const Trace = struct {
    /// Column-major, then raw transcript query order, duplicates preserved.
    values: []const M,
    paths: []const []const merkle.Digest,
};
pub const Proof = struct {
    roots: []const merkle.Digest,
    /// Tree, column, then declared mask order; periodic copies are derived.
    sampled_values: []const b.Var,
    trace: []const Trace,
    nonce: [2]W,
    fri_proof: fri.Proof,
};
pub const Oods = struct { seed: b.Var, point: Point };
pub const Result = struct {
    oods: Oods,
    deep_randomness: b.Var,
    deep_answers: []const b.Var,
    queries: []const M,
    fri_commit: fri.Committed,
    terminal: []const b.Var,
};
fn validateProof(g: Geometry, proof: Proof) !void {
    try g.validate();
    if (proof.roots.len != g.trees.len or proof.trace.len != g.trees.len or proof.sampled_values.len != g.sampleCount()) return error.InvalidNativeCircuitPcsShape;
    const n = g.config.fri_config.n_queries;
    for (g.trees, proof.trace) |tree, trace| {
        if (trace.values.len != tree.columns.len * n or trace.paths.len != if (tree.columns.len == 0) @as(usize, 0) else n) return error.InvalidNativeCircuitPcsShape;
        for (trace.paths) |path| if (path.len != g.treeHeight(tree)) return error.InvalidNativeCircuitPcsShape;
    }
}
/// Exact default native PcsConfig mix. Wider/lifted profiles are rejected.
pub fn mixConfig(comptime V: type, ctx: *b.Context(V), g: Geometry, transcript: *channel.Channel(V)) !void {
    try g.validate();
    const packed_config = try ctx.constant(Q.fromU32Unchecked(g.config.pow_bits, g.config.fri_config.log_blowup_factor, @intCast(g.config.fri_config.n_queries), g.config.fri_config.log_last_layer_degree_bound));
    try transcript.mixFelts(ctx, &.{packed_config});
}
pub fn drawOods(comptime V: type, ctx: *b.Context(V), transcript: *channel.Channel(V)) !Oods {
    const seed = try transcript.drawSecureFelt(ctx, 1);
    const square = try ctx.mul(seed, seed);
    const inverse = try ctx.inv(try ctx.add(ctx.one(), square));
    return .{ .seed = seed, .point = .{ .x = try ctx.mul(try ctx.sub(ctx.one(), square), inverse), .y = try ctx.mul(try ctx.add(seed, seed), inverse) } };
}
fn addConstantPoint(comptime V: type, ctx: *b.Context(V), point: Point, shift: core.circle.CirclePointM31) !Point {
    if (shift.eql(core.circle.CirclePointM31.zero())) return point;
    return circle.addPoints(V, ctx, point, .{ .x = try ctx.constant(Q.fromBase(shift.x)), .y = try ctx.constant(Q.fromBase(shift.y)) });
}
/// Explicit mask metadata, not a nominated sample-point witness.
pub fn maskPoint(comptime V: type, ctx: *b.Context(V), point: Point, mask: Mask) !Point {
    if (mask.offset == 0) return point;
    return addConstantPoint(V, ctx, point, core.poly.circle.canonic.CanonicCoset.new(mask.row_log).step().mulSigned(mask.offset));
}
const Response = struct {
    tree: usize,
    column: usize,
    a: b.Var,
    b_term: b.Var,
    c: b.Var,
    prx: b.Var,
    pry: b.Var,
    pix: b.Var,
    piy: b.Var,
};
fn response(comptime V: type, ctx: *b.Context(V), tree: usize, column: usize, point: Point, value: b.Var, power: b.Var) !Response {
    // Direct native complex-conjugate line coefficients; this avoids any
    // dependence on Cairo's fixed response inventory/grouping containers.
    const raw_a = try ctx.sub(try b.ops.conj(V, ctx, value), value);
    const raw_c = try ctx.sub(try b.ops.conj(V, ctx, point.y), point.y);
    _ = try ctx.inv(raw_c); // Native rejects the same degenerate line.
    const raw_b = try ctx.sub(try ctx.mul(value, raw_c), try ctx.mul(raw_a, point.y));
    const im_x = try b.ops.im(V, ctx, point.x);
    const im_y = try b.ops.im(V, ctx, point.y);
    const inv_u = try ctx.constant(try Q.fromU32Unchecked(0, 0, 1, 0).inv());
    return .{ .tree = tree, .column = column, .a = try ctx.mul(power, raw_a), .b_term = try ctx.mul(power, raw_b), .c = try ctx.mul(power, raw_c), .prx = try ctx.sub(point.x, im_x), .pry = try ctx.sub(point.y, im_y), .pix = try ctx.mul(im_x, inv_u), .piy = try ctx.mul(im_y, inv_u) };
}
fn responses(comptime V: type, ctx: *b.Context(V), g: Geometry, proof: Proof, oods: Oods, beta: b.Var) ![]Response {
    var out: std.ArrayList(Response) = .empty;
    defer out.deinit(ctx.scratch());
    var sample: usize = 0;
    var power = ctx.one();
    const lifting_generator = core.poly.circle.canonic.CanonicCoset.new((try g.friGeometry()).startLog()).step();
    for (g.trees, 0..) |tree, tree_index| for (tree.columns, 0..) |column, column_index| {
        // Native's extra periodicity response precedes both declared samples
        // and reuses sample1. Every response advances the global beta power.
        if (column.masks.len == 2) {
            const base = try maskPoint(V, ctx, oods.point, column.masks[1]);
            const period = lifting_generator.repeatedDouble(column.log_size + g.config.fri_config.log_blowup_factor);
            const periodic = try addConstantPoint(V, ctx, base, period);
            if (out.items.len != 0) power = try ctx.mul(power, beta);
            try out.append(ctx.scratch(), try response(V, ctx, tree_index, column_index, periodic, proof.sampled_values[sample + 1], power));
        }
        for (column.masks, 0..) |mask, index| {
            const point = try maskPoint(V, ctx, oods.point, mask);
            if (out.items.len != 0) power = try ctx.mul(power, beta);
            try out.append(ctx.scratch(), try response(V, ctx, tree_index, column_index, point, proof.sampled_values[sample + index], power));
        }
        sample += column.masks.len;
    };
    return out.toOwnedSlice(ctx.scratch());
}
/// Derived DEEP answers reuse the exact cells authenticated by trace paths.
pub fn deepAnswers(comptime V: type, ctx: *b.Context(V), g: Geometry, proof: Proof, oods: Oods, beta: b.Var, queries: []const M) ![]b.Var {
    const samples = try responses(V, ctx, g, proof, oods, beta);
    const packed_indices = try b.simd.pack(V, ctx, queries);
    const points = try select_queries.selectQueries(V, ctx, packed_indices, (try g.friGeometry()).startLog());
    const result = try ctx.scratch().alloc(b.Var, queries.len);
    for (result, 0..) |*answer, q| {
        const x = try b.simd.unpackIdx(V, ctx, points.points.x, q);
        const y = try b.simd.unpackIdx(V, ctx, points.points.y, q);
        var sum = ctx.zero();
        for (samples) |s| {
            const value = proof.trace[s.tree].values[s.column * queries.len + q].get();
            const numerator = try ctx.sub(try ctx.mul(s.c, value), try ctx.add(try ctx.mul(s.a, y), s.b_term));
            const denominator = try ctx.sub(try ctx.mul(try ctx.sub(s.prx, x), s.piy), try ctx.mul(try ctx.sub(s.pry, y), s.pix));
            sum = try ctx.add(sum, try ctx.div(numerator, denominator));
        }
        answer.* = sum;
    }
    return result;
}
/// Starts AFTER independently keyed root/claim prelude and OODS draw, so a
/// complete statement adapter can replay its own native transcript grammar.
pub fn verifyAfterOods(comptime V: type, ctx: *b.Context(V), g: Geometry, transcript: *channel.Channel(V), proof: Proof, oods: Oods) !Result {
    return verifyAfterOodsImpl(false, V, ctx, g, transcript, proof, oods);
}
/// Explicit direct-original layout. The transcript, authentication and FRI
/// protocol remain identical; only native DEEP point batching changes gates.
/// Existing NativeParent/Cairo callers keep verifyAfterOods's old topology.
pub fn verifyAfterOodsGrouped(comptime V: type, ctx: *b.Context(V), g: Geometry, transcript: *channel.Channel(V), proof: Proof, oods: Oods) !Result {
    return verifyAfterOodsImpl(true, V, ctx, g, transcript, proof, oods);
}
fn verifyAfterOodsImpl(comptime use_grouped_deep: bool, comptime V: type, ctx: *b.Context(V), g: Geometry, transcript: *channel.Channel(V), proof: Proof, oods: Oods) !Result {
    try validateProof(g, proof);
    try transcript.mixFelts(ctx, proof.sampled_values);
    const beta = try transcript.drawSecureFelt(ctx, 1);
    const fg = try g.friGeometry();
    const committed = try fri.commit(V, ctx, fg, transcript, proof.fri_proof);
    try transcript.pow(ctx, g.config.pow_bits, proof.nonce);
    const queries = try merkle.drawQueries(V, ctx, transcript, fg.startLog(), g.config.fri_config.n_queries);
    for (g.trees, proof.trace, proof.roots) |tree, trace, root| {
        if (tree.columns.len == 0) continue; // Exact declared empty tree: no opening authority.
        const logs = try ctx.scratch().alloc(u32, tree.columns.len);
        for (logs, tree.columns) |*log, column| log.* = column.log_size + g.config.fri_config.log_blowup_factor;
        const row = try ctx.scratch().alloc(M, tree.columns.len);
        for (queries, 0..) |query, q| {
            for (row, 0..) |*cell, column| cell.* = trace.values[column * queries.len + q];
            try merkle.verifyOpening(V, ctx, .{ .column_logs = logs, .height = g.treeHeight(tree) }, query, fg.startLog(), row, trace.paths[q], root);
        }
    }
    const deep = if (use_grouped_deep) try @import("blake3_pcs_grouped_deep_v1.zig").deepAnswers(V, ctx, g, proof, oods, beta, queries) else try deepAnswers(V, ctx, g, proof, oods, beta, queries);
    const terminal = try fri.decommit(V, ctx, fg, proof.fri_proof, committed, queries, deep);
    return .{ .oods = oods, .deep_randomness = beta, .deep_answers = deep, .queries = queries, .fri_commit = committed, .terminal = terminal };
}
/// Genuine standalone native PCS protocol: config, ordered roots, OODS seed,
/// sampled evaluations, DEEP beta, FRI commits, PoW+nonce, raw openings/FRI.
/// Typed AIR identities and the complete RISC-V root/claim prelude stay OPEN.
pub fn verifyStandalone(comptime V: type, ctx: *b.Context(V), g: Geometry, transcript: *channel.Channel(V), proof: Proof) !Result {
    try validateProof(g, proof);
    try mixConfig(V, ctx, g, transcript);
    for (proof.roots) |root| try transcript.mixRoot(ctx, root);
    const oods = try drawOods(V, ctx, transcript);
    return verifyAfterOods(V, ctx, g, transcript, proof, oods);
}

test {
    _ = @import("blake3_pcs_reuse_v1_test.zig");
}
