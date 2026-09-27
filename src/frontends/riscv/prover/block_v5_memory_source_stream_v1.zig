//! Deterministic bounded witness scheduling for the source equations.
//! Readers and openings are private witness providers, never authorities.
//! All bytes/values/paths must be authenticated by the emitted circuits and
//! exact-coverage closure before a block receiver can accept source claims.
const std = @import("std");
const core = @import("stwo_core");
const protocol = @import("block_v5_memory_source_auth_protocol_v1.zig");
const eq = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
const sha = @import("../air/guest_precompile/sha256_compression.zig");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
pub const Opening = struct { siblings: [tree.DEPTH][32]u8 };
pub const Source = struct {
    context: *anyopaque,
    /// Must fill exactly dst.len; caller offsets/lengths are independent.
    read: *const fn (*anyopaque, protocol.Stream, u64, []u8) anyerror!void,
    /// One shared sibling list for before AND after at the requested address.
    opening: *const fn (*anyopaque, u64, u32, u32, u32) anyerror!Opening,
};
pub const Chunk = struct { kind: eq.Kind, witness: eq.Witness };
pub const Census = struct {
    sha: u64,
    records: u64,
    edits: u64,
    leaf: u64,
    node: u64,
    root: u64,
    total: u64,
};
pub fn census(a: *const protocol.Admitted) !Census {
    try a.require();
    var sha_count: u64 = 0;
    var record_count: u64 = 0;
    inline for (std.meta.tags(protocol.Stream)) |s| {
        sha_count += a.byteLength(s) / 64 + 1;
        if (s != .public_input) record_count += a.records(s);
    }
    const edits = a.records(.input_words) + a.records(.rw_words) + a.records(.endpoints);
    const nodes = try std.math.mul(u64, edits, tree.DEPTH);
    const all_edits = try std.math.mul(u64, edits, tree.DEPTH + 2);
    return .{ .sha = sha_count, .records = record_count, .edits = edits, .leaf = edits, .node = nodes, .root = edits, .total = try std.math.add(u64, try std.math.add(u64, sha_count, record_count), all_edits) };
}
pub const Cursor = struct {
    admitted: protocol.Admitted,
    source: Source,
    expected: Census,
    emitted: u64 = 0,
    phase: enum { sha, records, edits, done } = .sha,
    stream: u32 = 1,
    ordinal: u64 = 0,
    sha_state: sha.State = sha.initial_state,
    previous_address: u32 = 0,
    edit: protocol.Edit = .insert_input,
    layer: u32 = 0,
    edit_witness: eq.Witness = .{},
    siblings: [tree.DEPTH][32]u8 = undefined,
    before_hash: [32]u8 = undefined,
    after_hash: [32]u8 = undefined,
    pub fn init(a: protocol.Admitted, source: Source) !Cursor {
        return .{ .admitted = a, .source = source, .expected = try census(&a) };
    }
    pub fn next(self: *Cursor) !?Chunk {
        while (true) switch (self.phase) {
            .sha => {
                if (self.stream > 5) {
                    self.phase = .records;
                    self.stream = 2;
                    self.ordinal = 0;
                    continue;
                }
                const stream: protocol.Stream = @enumFromInt(self.stream);
                const length = self.admitted.byteLength(stream);
                if (self.ordinal > length / 64) {
                    self.stream += 1;
                    self.ordinal = 0;
                    self.sha_state = sha.initial_state;
                    continue;
                }
                var witness = eq.Witness{ .state = self.sha_state };
                const terminal = self.ordinal == length / 64;
                const used: usize = if (terminal) @intCast(length % 64) else 64;
                if (used != 0) try self.source.read(self.source.context, stream, self.ordinal * 64, witness.raw[0..used]);
                if (!terminal) self.sha_state = sha.compress(self.sha_state, witness.raw);
                const chunk = Chunk{ .kind = .{ .sha = .{ .stream = stream, .block = self.ordinal } }, .witness = witness };
                self.ordinal += 1;
                self.emitted += 1;
                return chunk;
            },
            .records => {
                if (self.stream > 5) {
                    self.phase = .edits;
                    self.ordinal = 0;
                    continue;
                }
                const stream: protocol.Stream = @enumFromInt(self.stream);
                if (self.ordinal == self.admitted.records(stream)) {
                    self.stream += 1;
                    self.ordinal = 0;
                    self.previous_address = 0;
                    continue;
                }
                var witness = try self.record(stream, self.ordinal);
                witness.previous_address = self.previous_address;
                const chunk = Chunk{ .kind = .{ .record = .{ .stream = stream, .ordinal = self.ordinal } }, .witness = witness };
                self.previous_address = witness.address;
                self.ordinal += 1;
                self.emitted += 1;
                return chunk;
            },
            .edits => {
                const stream: protocol.Stream = switch (self.edit) {
                    .insert_input => .input_words,
                    .insert_rw => .rw_words,
                    .update => .endpoints,
                };
                if (self.ordinal == self.admitted.records(stream)) {
                    if (self.edit == .update) {
                        self.phase = .done;
                        continue;
                    }
                    self.edit = @enumFromInt(@intFromEnum(self.edit) + 1);
                    self.ordinal = 0;
                    self.layer = 0;
                    continue;
                }
                var kind: eq.Kind = undefined;
                var witness: eq.Witness = .{};
                if (self.layer == 0) {
                    const current = try self.record(stream, self.ordinal);
                    self.edit_witness = current;
                    if (self.edit == .update) {
                        const touch = try self.record(.first_touches, self.ordinal);
                        if (touch.address != current.address) return error.InvalidMemorySourceTouchPair;
                        self.edit_witness.before = touch.before;
                    }
                    const index = eq.editIndex(&self.admitted, self.edit, self.ordinal);
                    self.siblings = (try self.source.opening(self.source.context, index, current.address, self.edit_witness.before, self.edit_witness.after)).siblings;
                    const hasher = tree.TreeHasher.init(.memory);
                    self.before_hash = hasher.leaf(self.edit_witness.before).bytes;
                    self.after_hash = hasher.leaf(self.edit_witness.after).bytes;
                    kind = .{ .leaf = .{ .edit = self.edit, .ordinal = self.ordinal } };
                    witness = self.edit_witness;
                } else if (self.layer <= tree.DEPTH) {
                    const height: u5 = @intCast(self.layer - 1);
                    witness.address = self.edit_witness.address;
                    witness.before_hash = self.before_hash;
                    witness.after_hash = self.after_hash;
                    witness.sibling = self.siblings[height];
                    const side = ((witness.address / 4) >> height) & 1;
                    const sibling = tree.Digest{ .bytes = witness.sibling };
                    const before = tree.Digest{ .bytes = witness.before_hash };
                    const after = tree.Digest{ .bytes = witness.after_hash };
                    const hasher = tree.TreeHasher.init(.memory);
                    self.before_hash = (if (side == 0) hasher.pair(before, sibling) else hasher.pair(sibling, before)).bytes;
                    self.after_hash = (if (side == 0) hasher.pair(after, sibling) else hasher.pair(sibling, after)).bytes;
                    kind = .{ .node = .{ .edit = self.edit, .ordinal = self.ordinal, .height = height } };
                } else {
                    witness.address = self.edit_witness.address;
                    witness.before_hash = self.before_hash;
                    witness.after_hash = self.after_hash;
                    kind = .{ .root = .{ .edit = self.edit, .ordinal = self.ordinal } };
                }
                self.layer += 1;
                if (self.layer == tree.DEPTH + 2) {
                    self.layer = 0;
                    self.ordinal += 1;
                }
                self.emitted += 1;
                return .{ .kind = kind, .witness = witness };
            },
            .done => {
                if (self.emitted != self.expected.total) return error.InvalidMemorySourceChunkCensus;
                return null;
            },
        };
    }
    fn record(self: *Cursor, stream: protocol.Stream, ordinal: u64) !eq.Witness {
        var raw: [16]u8 = @splat(0);
        const size: usize = switch (stream) {
            .input_words, .rw_words => 8,
            .first_touches => 9,
            .endpoints => 16,
            .public_input => return error.InvalidMemorySourceChunk,
        };
        try self.source.read(self.source.context, stream, ordinal * size, raw[0..size]);
        var witness: eq.Witness = .{};
        switch (stream) {
            .input_words, .rw_words => {
                witness.address = std.mem.readInt(u32, raw[0..4], .little);
                witness.after = std.mem.readInt(u32, raw[4..8], .little);
            },
            .first_touches => {
                if (raw[0] != 1) return error.InvalidMemorySourceRamSpace;
                witness.address = std.mem.readInt(u32, raw[1..5], .little);
                witness.before = std.mem.readInt(u32, raw[5..9], .little);
            },
            .endpoints => {
                witness.address = std.mem.readInt(u32, raw[0..4], .little);
                witness.clock = std.mem.readInt(u64, raw[4..12], .little);
                witness.after = std.mem.readInt(u32, raw[12..16], .little);
            },
            .public_input => unreachable,
        }
        return witness;
    }
};

/// Independently reconstruct the exact heterogeneous chunk schedule from pins,
/// without reading witness bytes or trusting a payload-selected Kind.
/// A future typed receiver must call this for each physical proof ordinal.
pub fn kindAt(admitted: *const protocol.Admitted, physical_index: u64) !eq.Kind {
    const counts = try census(admitted);
    if (physical_index >= counts.total) return error.InvalidMemorySourceChunkCensus;
    var remaining = physical_index;
    inline for (std.meta.tags(protocol.Stream)) |s| {
        const n = admitted.byteLength(s) / 64 + 1;
        if (remaining < n) return .{ .sha = .{ .stream = s, .block = remaining } };
        remaining -= n;
    }
    inline for (.{ protocol.Stream.input_words, protocol.Stream.rw_words, protocol.Stream.first_touches, protocol.Stream.endpoints }) |s| {
        const n = admitted.records(s);
        if (remaining < n) return .{ .record = .{ .stream = s, .ordinal = remaining } };
        remaining -= n;
    }
    inline for (std.meta.tags(protocol.Edit)) |e| {
        const s: protocol.Stream = switch (e) {
            .insert_input => .input_words,
            .insert_rw => .rw_words,
            .update => .endpoints,
        };
        const n = admitted.records(s) * (tree.DEPTH + 2);
        if (remaining < n) {
            const ordinal = remaining / (tree.DEPTH + 2);
            const layer = remaining % (tree.DEPTH + 2);
            if (layer == 0) return .{ .leaf = .{ .edit = e, .ordinal = ordinal } };
            if (layer == tree.DEPTH + 1) return .{ .root = .{ .edit = e, .ordinal = ordinal } };
            return .{ .node = .{ .edit = e, .ordinal = ordinal, .height = @intCast(layer - 1) } };
        }
        remaining -= n;
    }
    return error.InvalidMemorySourceChunkCensus;
}
