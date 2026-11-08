//! FRI geometry and compact readback formatting. No prover field arithmetic,
//! challenge derivation or GPU feedback occurs in this assembler. A native
//! verifier must independently establish the complete transcript and claims.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
pub const O = core.fields.om31.OM31;
pub const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const F = core.fri.ForField(O);
pub const Layer = struct {
    count: u32,
    fold_step: u32,
    leaf_log: u32,
    shift: u32,
    pub fn validate(self: Layer) !void {
        if (self.count == 0 or self.count > 1 << 28 or !std.math.isPowerOfTwo(self.count) or self.fold_step == 0 or self.fold_step > 4 or self.shift > 28 or @as(u64, self.count) << @intCast(self.shift) > 1 << 28 or self.count < @as(u32, 1) << @intCast(self.fold_step) or self.leaf_log != (if (self.fold_step > 1) @as(u32, 2) else 0)) return error.InvalidFriGeometry;
    }
    pub fn treeWords(self: Layer) usize {
        return (@as(usize, self.count >> @intCast(self.leaf_log)) * 2 - 1) * 8;
    }
    pub fn height(self: Layer) u32 {
        return std.math.log2_int(u32, self.count) - self.leaf_log;
    }
    pub fn valueWords(self: Layer, queries: usize) usize {
        return (queries << @intCast(self.fold_step)) * 8;
    }
    pub fn pathWords(self: Layer, queries: usize) usize {
        return (queries << @intCast(self.fold_step - self.leaf_log)) * self.height() * 8;
    }
};
pub const Plan = struct {
    layers: [28]Layer = undefined,
    len: usize = 0,
    initial_log: u32,
    terminal_count: u32,
    queries: usize,
    pub fn validate(self: Plan) !void {
        if (self.len == 0 or self.len > 28 or self.initial_log == 0 or self.initial_log > 28 or self.queries == 0 or self.queries > 1024 or self.terminal_count < 2 or self.terminal_count > 65536 or !std.math.isPowerOfTwo(self.terminal_count)) return error.InvalidFriReadback;
        var count = @as(u32, 1) << @intCast(self.initial_log);
        var shift: u32 = 0;
        for (self.layers[0..self.len]) |layer| {
            try layer.validate();
            if (layer.count != count or layer.shift != shift or layer.fold_step == 0 or layer.fold_step > 4 or layer.leaf_log != (if (layer.fold_step > 1) @as(u32, 2) else 0) or count >> @intCast(layer.fold_step) < self.terminal_count) return error.InvalidFriReadback;
            count >>= @intCast(layer.fold_step);
            shift += layer.fold_step;
        }
        if (count != self.terminal_count) return error.InvalidFriReadback;
    }
    pub fn init(degree_log: u32, config: F.FriConfig) !Plan {
        if (config.log_last_layer_degree_bound != 0 or config.log_blowup_factor < 1 or config.log_blowup_factor > 16 or
            config.fold_step < 1 or config.fold_step > 4 or degree_log < config.fold_step or
            degree_log > 28 - config.log_blowup_factor or config.n_queries == 0 or config.n_queries > 1024) return error.UnsupportedFriGeometry;
        var p = Plan{ .initial_log = degree_log + config.log_blowup_factor, .terminal_count = @as(u32, 1) << @intCast(config.log_blowup_factor), .queries = config.n_queries };
        var remaining = degree_log;
        while (remaining > 0) {
            const step = @min(config.fold_step, remaining);
            p.layers[p.len] = .{ .count = @as(u32, 1) << @intCast(remaining + config.log_blowup_factor), .fold_step = step, .leaf_log = if (step > 1) 2 else 0, .shift = degree_log - remaining };
            p.len += 1;
            remaining -= step;
        }
        return p;
    }
};
pub const LayerReadback = struct { root: [8]u32, values: []const u32, paths: []const u32 };
fn decode(words: []const u32) !O {
    if (words.len != 8) return error.InvalidFriReadback;
    var limbs: [8]M = undefined;
    for (words, &limbs) |word, *v| {
        if (word >= core.fields.m31.Modulus) return error.NoncanonicalFriField;
        v.* = M.fromCanonical(word);
    }
    return O.fromM31Array(limbs);
}
fn digest(words: []const u32) H.Hash {
    var out: H.Hash = undefined;
    for (words, 0..) |word, i| std.mem.writeInt(u32, out[i * 4 ..][0..4], word, .little);
    return out;
}
fn layerProof(a: std.mem.Allocator, layout: Layer, raw: []const u32, queries: []const usize, data: LayerReadback) !F.FriLayerProof(H) {
    if (data.values.len != layout.valueWords(raw.len) or data.paths.len != layout.pathWords(raw.len)) return error.InvalidFriReadback;
    var values = std.AutoHashMap(usize, O).init(a);
    defer values.deinit();
    var hashes = std.AutoHashMap(u64, H.Hash).init(a);
    defer hashes.deinit();
    const subset = @as(usize, 1) << @intCast(layout.fold_step);
    const slots = @as(usize, 1) << @intCast(layout.fold_step - layout.leaf_log);
    for (raw, 0..) |q, qi| {
        const start = ((@as(usize, q) >> @intCast(layout.shift)) >> @intCast(layout.fold_step)) << @intCast(layout.fold_step);
        for (0..subset) |offset| {
            const v = try decode(data.values[(qi * subset + offset) * 8 ..][0..8]);
            if (values.get(start + offset)) |old| {
                if (!old.eql(v)) return error.InconsistentFriReadback;
            } else try values.put(start + offset, v);
        }
        for (0..slots) |slot| for (0..layout.height()) |level| {
            const leaf = (start >> @intCast(layout.leaf_log)) + slot;
            const sibling = (leaf >> @intCast(level)) ^ 1;
            const key = (@as(u64, level) << 32) | sibling;
            const h = digest(data.paths[((qi * slots + slot) * layout.height() + level) * 8 ..][0..8]);
            if (hashes.get(key)) |old| {
                if (!std.mem.eql(u8, &old, &h)) return error.InconsistentFriReadback;
            } else try hashes.put(key, h);
        };
    }
    var witness: std.ArrayList(O) = .empty;
    defer witness.deinit(a);
    var leaves: std.ArrayList(usize) = .empty;
    defer leaves.deinit(a);
    var cursor: usize = 0;
    while (cursor < queries.len) {
        const start = (queries[cursor] >> @intCast(layout.fold_step)) << @intCast(layout.fold_step);
        for (start..start + subset) |position| {
            const value = values.get(position) orelse return error.MissingFriReadback;
            if (cursor < queries.len and queries[cursor] == position) cursor += 1 else try witness.append(a, value);
            const leaf = position >> @intCast(layout.leaf_log);
            if (leaves.items.len == 0 or leaves.items[leaves.items.len - 1] != leaf) try leaves.append(a, leaf);
        }
    }
    var hash_witness: std.ArrayList(H.Hash) = .empty;
    defer hash_witness.deinit(a);
    var current = try leaves.toOwnedSlice(a);
    defer a.free(current);
    for (0..layout.height()) |level| {
        var next: std.ArrayList(usize) = .empty;
        defer next.deinit(a);
        var i: usize = 0;
        while (i < current.len) {
            const first = current[i];
            const sibling = i + 1 < current.len and current[i + 1] == (first ^ 1);
            if (!sibling) try hash_witness.append(a, hashes.get((@as(u64, level) << 32) | (first ^ 1)) orelse return error.MissingFriReadback);
            try next.append(a, first >> 1);
            i += if (sibling) @as(usize, 2) else 1;
        }
        const owned = try next.toOwnedSlice(a);
        a.free(current);
        current = owned;
    }
    const fri_witness = try witness.toOwnedSlice(a);
    errdefer a.free(fri_witness);
    return .{ .fri_witness = fri_witness, .decommitment = .{ .hash_witness = try hash_witness.toOwnedSlice(a) }, .commitment = digest(&data.root) };
}
pub fn assemble(a: std.mem.Allocator, plan: Plan, raw: []const u32, layers: []const LayerReadback, terminal: []const u32) !F.FriProof(H) {
    try plan.validate();
    if (layers.len != plan.len or plan.len == 0 or plan.len > 28 or raw.len != plan.queries or terminal.len != 8) return error.InvalidFriReadback;
    const positions = try a.alloc(usize, raw.len);
    defer a.free(positions);
    for (raw, positions) |q, *v| {
        if (q >= @as(u32, 1) << @intCast(plan.initial_log)) return error.InvalidFriQuery;
        v.* = q;
    }
    var queries = try core.queries.Queries.init(a, positions, plan.initial_log);
    defer queries.deinit(a);
    const proofs = try a.alloc(F.FriLayerProof(H), plan.len);
    defer a.free(proofs);
    var done: usize = 0;
    errdefer for (proofs[0..done]) |*proof| proof.deinit(a);
    for (plan.layers[0..plan.len], layers, proofs) |layout, data, *proof| {
        proof.* = try layerProof(a, layout, raw, queries.positions, data);
        done += 1;
        const next = try queries.fold(a, layout.fold_step);
        queries.deinit(a);
        queries = next;
    }
    const inner = try a.dupe(F.FriLayerProof(H), proofs[1..]);
    errdefer a.free(inner);
    const coefficients = try a.alloc(O, 1);
    errdefer a.free(coefficients);
    coefficients[0] = try decode(terminal);
    return .{ .first_layer = proofs[0], .inner_layers = inner, .last_layer_poly = core.poly.line.LinePolyFor(O).fromOrderedCoefficients(coefficients) };
}
test "FRI geometry retains four-value leaves with fold4 and clamps final line folds" {
    const p = try Plan.init(17, .{ .log_blowup_factor = 2, .log_last_layer_degree_bound = 0, .n_queries = 256, .fold_step = 4 });
    try std.testing.expectEqual(@as(usize, 5), p.len);
    try std.testing.expectEqual(@as(u32, 2), p.layers[0].leaf_log);
    try std.testing.expectEqual(@as(u32, 1), p.layers[4].fold_step);
    try std.testing.expectEqual(@as(u32, 0), p.layers[4].leaf_log);
    try std.testing.expectEqual(@as(u32, 4), p.terminal_count);
    try std.testing.expectError(error.UnsupportedFriGeometry, Plan.init(3, .{ .log_blowup_factor = 2, .log_last_layer_degree_bound = 0, .n_queries = 256, .fold_step = 4 }));
}
