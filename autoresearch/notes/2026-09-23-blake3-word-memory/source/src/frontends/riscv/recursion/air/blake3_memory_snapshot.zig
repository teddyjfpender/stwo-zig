//! Owned BLAKE3 projection of the runner's retained word states.
//! Continuation commits all RW bytes; ordinary boundary commitments apply the
//! existing public-input/output custody policy. These are distinct projections.
const std = @import("std");
const core = @import("stwo_core");
const state = @import("../../runner/memory_state.zig");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const word = @import("blake3_memory_word.zig");
pub const Side = enum { entry, exit };
pub const Projection = enum { continuation, ordinary_boundary };
pub const Source = struct {
    allocator: std.mem.Allocator,
    words: []state.WordState,
    leaves: []tree.Leaf,
    root: tree.Digest,
    side: Side,
    projection: Projection,
    pub fn deinit(self: *Source) void {
        self.allocator.free(self.leaves);
        self.allocator.free(self.words);
        self.* = undefined;
    }
    /// Only ordinary boundary projections produce memory-access boundary rows.
    /// Continuation roots authenticate the whole snapshot through separate claims.
    pub fn statement(self: *const Source, address: u32, source_circuit: u32, path_namespace: u32) !word.Statement {
        if (self.projection != .ordinary_boundary) return error.NotOrdinaryMemoryProjection;
        const entry = self.find(address) orelse return error.MissingSnapshotWord;
        if (!included(entry, self.side, self.projection)) return error.PublicMemoryCustody;
        const result = word.Statement{ .address = address, .clock = if (self.side == .entry) 0 else entry.final_clock, .direction = if (self.side == .entry) .initial else .final, .source_circuit = source_circuit, .path_namespace = path_namespace, .root = self.root };
        try result.validate();
        return result;
    }
    pub fn prepareWord(self: *const Source, a: std.mem.Allocator, address: u32, source_circuit: u32, path_namespace: u32) !word.Prepared {
        return word.prepare(a, try self.statement(address, source_circuit, path_namespace), self.leaves);
    }
    fn find(self: *const Source, address: u32) ?state.WordState {
        var low: usize = 0;
        var high = self.words.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (self.words[middle].addr < address) low = middle + 1 else high = middle;
        }
        return if (low < self.words.len and self.words[low].addr == address) self.words[low] else null;
    }
};
pub fn fromSnapshot(a: std.mem.Allocator, snapshot: *const state.Snapshot, side: Side, projection: Projection) !Source {
    for (snapshot.words, 0..) |entry, i| {
        if (entry.addr & 3 != 0 or entry.addr >= tree.ADDRESS_LIMIT) return error.InvalidSnapshotAddress;
        if (i != 0 and snapshot.words[i - 1].addr >= entry.addr) return error.UnsortedSnapshotWords;
        if (entry.final_clock >= core.fields.m31.Modulus) return error.InvalidSnapshotClock;
    }
    const words = try a.dupe(state.WordState, snapshot.words);
    errdefer a.free(words);
    var leaves: std.ArrayList(tree.Leaf) = .empty;
    defer leaves.deinit(a);
    for (words) |entry| {
        if (!included(entry, side, projection)) continue;
        const value = if (side == .entry) entry.initial_word else entry.final_word;
        if (value != 0) try leaves.append(a, .{ .index = try tree.memoryIndex(entry.addr), .value = value });
    }
    const hasher = tree.TreeHasher.init(.memory);
    const root = try hasher.root(leaves.items);
    return .{ .allocator = a, .words = words, .leaves = try leaves.toOwnedSlice(a), .root = root, .side = side, .projection = projection };
}
fn included(entry: state.WordState, side: Side, projection: Projection) bool {
    return projection == .continuation or switch (side) {
        .entry => entry.includeInitial(),
        .exit => entry.includeFinal(),
    };
}
