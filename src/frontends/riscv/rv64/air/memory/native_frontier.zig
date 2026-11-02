//! Native batch preparation, not receiver/proof authority. Reuses the exact
//! private frontier builder and retains only its sparse graph, patch and full
//! permutation I/O. No ProviderWriter, S-box rows or all-cache snapshot exists.
const std = @import("std");
const core = @import("stwo_core");
const batch = @import("batch.zig");
const values = @import("values.zig");
const openings = @import("openings.zig");
const graph = @import("graph_model.zig");
const node = @import("../../../air/memory_commitment/ethereum_node_v1.zig");
const M = core.fields.m31.M31;
pub const Phase = enum { prepared, durable, published, consumed };
pub const MAX_IO = @as(usize, 1) << 24;
pub const Handoff = struct {
    context: ?*anyopaque = null,
    persist: *const fn (?*anyopaque, *const Prepared) anyerror!void,
};
pub const View = struct {
    geometry: values.Geometry,
    before: values.Digest,
    after: values.Digest,
    counts: batch.Counts,
    leaves: []const batch.Leaf,
    before_nodes: []const batch.Node,
    after_nodes: []const batch.Node,
    sides: []const graph.Side,
    patches: []const values.Patch,
    io: []const values.PermutationIO,
};
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    witness: batch.Witness,
    io: []values.PermutationIO,
    counts: batch.Counts,
    phase: Phase = .prepared,

    /// Borrows openings only for this call. Failure leaves cache and opening
    /// owners unchanged. The successful result contains no opening/cache borrow.
    pub fn init(a: std.mem.Allocator, cache: *const values.Cache, owned: *const openings.Owned) !Prepared {
        const changes = try a.alloc(bool, owned.chunks.len);
        defer a.free(changes);
        const counts = try batch.countPrepared(a, cache.geometry, owned.chunks, changes, false);
        if (try counts.permutations(cache.geometry) > MAX_IO) return error.NativeFrontierResourceLimit;
        var recorder = values.Recorder{ .allocator = a, .writer = null };
        defer recorder.deinit();
        var witness = try batch.Witness.initPrepared(a, cache, owned.chunks, &recorder, counts, changes);
        errdefer witness.deinit();
        const io = try recorder.calls.toOwnedSlice(a);
        errdefer a.free(io);
        var result = Prepared{ .allocator = a, .witness = witness, .io = io, .counts = counts };
        try result.validate();
        return result;
    }
    pub fn view(self: *const Prepared) View {
        const w = &self.witness;
        return .{ .geometry = w.geometry, .before = w.before, .after = w.after, .counts = self.counts, .leaves = w.leaves, .before_nodes = w.before_nodes, .after_nodes = w.after_nodes, .sides = w.sides, .patches = w.patches, .io = self.io };
    }
    /// Exact retained narrow payload for queue/resource admission; temporary
    /// validation maps have already been freed when init returns.
    pub fn ownedBytes(self: *const Prepared) usize {
        const w = &self.witness;
        return self.io.len * @sizeOf(values.PermutationIO) + w.leaves.len * @sizeOf(batch.Leaf) + (w.before_nodes.len + w.after_nodes.len) * @sizeOf(batch.Node) + w.sides.len * @sizeOf(graph.Side) + w.patches.len * @sizeOf(values.Patch);
    }
    /// Canonical coverage/index/framing checks only. The future worker's
    /// Poseidon provider must prove every I/O pair; these native checks are not
    /// a substitute for permutation AIR or CPU/RAM/policy global closure.
    pub fn validate(self: *const Prepared) !void {
        if (self.phase == .consumed) return error.InvalidNativeFrontierPhase;
        const w = &self.witness;
        const c = self.counts;
        if (c.leaves == 0 or c.leaves > batch.MAX_OPENINGS or c.leaves != w.leaves.len or c.changed_leaves > c.leaves or c.before_nodes != w.before_nodes.len or c.after_nodes != w.after_nodes.len or c.sides != w.sides.len or self.io.len > MAX_IO or self.io.len != try c.permutations(w.geometry) or w.patches.len != c.changed_leaves + c.after_nodes) return error.InvalidNativeFrontier;
        const before = try self.allocator.alloc(graph.Node, w.before_nodes.len);
        defer self.allocator.free(before);
        const after = try self.allocator.alloc(graph.Node, w.after_nodes.len);
        defer self.allocator.free(after);
        const leaves = try self.allocator.alloc(graph.Leaf, w.leaves.len);
        defer self.allocator.free(leaves);
        for (before, w.before_nodes) |*out, source| out.* = source.graph;
        for (after, w.after_nodes) |*out, source| out.* = source.graph;
        for (leaves, w.leaves) |*out, source| out.* = source.graph;
        try graph.verify(self.allocator, w.geometry.depth(), w.before, w.after, before, after, leaves, w.sides);
        for (self.io) |call| {
            for (call.input) |word| if (word.v >= core.fields.m31.Modulus) return error.NoncanonicalNativeFrontierIO;
            for (call.output) |word| if (word.v >= core.fields.m31.Modulus) return error.NoncanonicalNativeFrontierIO;
        }
        var cursor: usize = 0;
        var next_id: usize = w.leaves.len;
        var changed: usize = 0;
        var patch: usize = 0;
        for (w.leaves, 0..) |leaf, i| {
            if (leaf.before_id != i or leaf.before_io != cursor or (i != 0 and w.leaves[i - 1].graph.index >= leaf.graph.index)) return error.InvalidNativeFrontier;
            try self.digest(cursor, w.geometry.permutations(), leaf.graph.before);
            cursor += w.geometry.permutations();
        }
        for (w.leaves) |leaf| {
            if (leaf.graph.changed) {
                if (leaf.after_id != next_id or leaf.after_io != cursor) return error.InvalidNativeFrontier;
                try self.digest(cursor, w.geometry.permutations(), leaf.graph.after);
                try checkPatch(w.patches[patch], 0, leaf.graph.index, leaf.graph.before, leaf.graph.after);
                patch += 1;
                next_id += 1;
                changed += 1;
                cursor += w.geometry.permutations();
            } else if (leaf.after_id != 0 or leaf.after_io != 0) return error.InvalidNativeFrontier;
        }
        if (changed != c.changed_leaves) return error.InvalidNativeFrontier;
        var after_at: usize = 0;
        for (w.before_nodes, 0..) |entry, i| {
            if (i != 0 and !lessNode(w.before_nodes[i - 1].graph, entry.graph)) return error.InvalidNativeFrontier;
            if (entry.io != cursor) return error.InvalidNativeFrontier;
            try self.nodeFrame(entry);
            cursor += 4;
            if (after_at < w.after_nodes.len) {
                const updated = w.after_nodes[after_at];
                if (updated.graph.height == entry.graph.height and updated.graph.index == entry.graph.index) {
                    if (updated.io != cursor) return error.InvalidNativeFrontier;
                    try self.nodeFrame(updated);
                    try checkPatch(w.patches[patch], updated.graph.height, updated.graph.index, entry.graph.digest, updated.graph.digest);
                    patch += 1;
                    cursor += 4;
                    after_at += 1;
                }
            }
        }
        if (cursor != self.io.len or after_at != w.after_nodes.len or patch != w.patches.len) return error.InvalidNativeFrontier;
    }
    /// Validates the saved absorption frames against caller-owned words. All
    /// permutations remain opaque here and are expanded exactly once by worker.
    pub fn validateOpenings(self: *const Prepared, source: []const batch.Opening) !void {
        if (self.phase == .consumed) return error.InvalidNativeFrontierPhase;
        const g = self.witness.geometry;
        try batch.validate(g, source);
        if (source.len != self.witness.leaves.len) return error.InvalidNativeFrontier;
        for (source, self.witness.leaves) |opening, leaf| {
            if (opening.index != leaf.graph.index or leaf.graph.changed != !std.mem.eql(u64, opening.before, opening.after)) return error.InvalidNativeFrontier;
            try self.valueFrame(opening.before, leaf.before_io);
            if (leaf.graph.changed) try self.valueFrame(opening.after, leaf.after_io);
        }
    }
    fn valueFrame(self: *const Prepared, words: []const u64, start: usize) !void {
        const g = self.witness.geometry;
        if (start > self.io.len or g.permutations() > self.io.len - start) return error.InvalidNativeFrontier;
        var previous: @FieldType(values.PermutationIO, "output") = @splat(M.zero());
        for (self.io[start..][0..g.permutations()], 0..) |call, phase| {
            if (!std.meta.eql(try values.valueInput(g, words, phase, previous), call.input)) return error.InvalidNativeFrontierIO;
            previous = call.output;
        }
    }
    pub fn requireMovable(self: *const Prepared) !void {
        if (self.phase != .prepared and self.phase != .published) return error.InvalidNativeFrontierPhase;
    }
    pub const Taken = struct { witness: batch.Witness, io: []values.PermutationIO };
    /// Success-only move for the worker's single wide constructor. Durable-but-
    /// unpublished data stays with the collector so cache publication can retry.
    pub fn take(self: *Prepared) !Taken {
        try self.requireMovable();
        const result = Taken{ .witness = self.witness, .io = self.io };
        self.witness.leaves = &.{};
        self.witness.before_nodes = &.{};
        self.witness.after_nodes = &.{};
        self.witness.sides = &.{};
        self.witness.patches = &.{};
        self.io = &.{};
        self.phase = .consumed;
        return result;
    }
    fn digest(self: *const Prepared, start: usize, calls: usize, expected: values.Digest) !void {
        if (calls < 2 or start > self.io.len or calls > self.io.len - start) return error.InvalidNativeFrontier;
        for (expected[0..7], self.io[start + calls - 2].output[0..7]) |word, actual| if (word != actual.v) return error.InvalidNativeFrontierIO;
        for (expected[7..9], self.io[start + calls - 1].output[0..2]) |word, actual| if (word != actual.v) return error.InvalidNativeFrontierIO;
    }
    fn nodeFrame(self: *const Prepared, entry: batch.Node) !void {
        const start: usize = entry.io;
        try self.digest(start, 4, entry.graph.digest);
        var row: node.Row(M) = undefined;
        const height = entry.graph.height - 1;
        row.kind = M.fromCanonical(height >> 5);
        for (&row.height_bits, 0..) |*bit, i| bit.* = M.fromCanonical((@as(u32, height) >> @intCast(i)) & 1);
        for (&row.left, entry.graph.left, &row.right, entry.graph.right, &row.digest, entry.graph.digest) |*left, x, *right, y, *out, z| {
            left.* = M.fromCanonical(x);
            right.* = M.fromCanonical(y);
            out.* = M.fromCanonical(z);
        }
        for (&row.inputs, &row.outputs, self.io[start..][0..4]) |*input, *output, call| {
            input.* = call.input;
            output.* = call.output;
        }
        for (node.evaluateGeneric(M, row)) |residual| if (!residual.isZero()) return error.InvalidNativeFrontierIO;
    }
    fn checkBefore(self: *const Prepared, cache: *const values.Cache) !void {
        if (self.witness.geometry != cache.geometry or !values.equal(self.witness.before, cache.root())) return error.PrivateRamBeforeRootMismatch;
    }
    /// Persist must durably accept/copy the read-only view before returning.
    /// It must not retain borrows or mutate the exclusively owned cache. On a
    /// publication OOM the durable phase remembers acceptance for retry.
    pub fn handoffAndPublish(self: *Prepared, cache: *values.Cache, handoff: Handoff) !void {
        if (self.phase == .published or self.phase == .consumed) return error.InvalidNativeFrontierPhase;
        try self.checkBefore(cache);
        if (self.phase == .prepared) {
            try self.validate();
            try handoff.persist(handoff.context, self);
            self.phase = .durable;
        }
        try self.finishPublish(cache);
    }
    pub fn finishPublish(self: *Prepared, cache: *values.Cache) !void {
        if (self.phase != .durable) return error.InvalidNativeFrontierPhase;
        try self.checkBefore(cache);
        try self.witness.publish(cache);
        self.phase = .published;
    }
    pub fn deinit(self: *Prepared) void {
        self.witness.deinit();
        self.allocator.free(self.io);
        self.* = undefined;
    }
};
fn lessNode(left: graph.Node, right: graph.Node) bool {
    return left.height < right.height or (left.height == right.height and left.index < right.index);
}
fn checkPatch(patch: values.Patch, height: u6, index: u64, before: values.Digest, after: values.Digest) !void {
    if (patch.height != height or patch.index != index or !values.equal(patch.before, before) or !values.equal(patch.after, after)) return error.InvalidNativeFrontierPatch;
}
