//! Bounded Merkle-leaf storage for incremental commitment construction.
//! Streaming state retains Zig's BLAKE3 implementation with a shortened CV stack.
//! Four-leaf dispatch delegates to the canonical full-tree batch implementation.
//! Callers preflight the full leaf size before consuming columns.
const std = @import("std");
const core = @import("stwo_core");
const Standard = std.crypto.hash.Blake3;
const Original = core.vcs_lifted.blake3_merkle.MerkleHasher;
const framing = core.channel.blake3.framing;
const M31 = core.fields.m31.M31;

pub const Hasher = struct {
    const Self = @This();
    pub const Hash = Original.Hash;
    pub const Children = Original.Children;
    pub const NodeSeed = Original.NodeSeed;
    pub const nodeSeed = Original.nodeSeed;
    pub const hashChildren = Original.hashChildren;
    pub const hashChildrenWithSeed = Original.hashChildrenWithSeed;
    pub const hashChildrenWithSeed4 = Original.hashChildrenWithSeed4;
    pub const leafSeed = Original.leafSeed;
    pub const hashPackedLeavesWithSeed4 = Original.hashPackedLeavesWithSeed4;
    pub const hashDirectM31LeavesWithSeed4 = Original.hashDirectM31LeavesWithSeed4;
    pub const max_input_bytes = 16 * 1024;
    pub const max_columns = (max_input_bytes - framing.PROTOCOL_ID.len - 1) / @sizeOf(M31);
    chunk: @FieldType(Standard, "chunk_state"),
    stack: [4][8]u32 = undefined,
    stack_len: u8 = 0,
    total_bytes: u32,

    pub fn defaultWithInitialState() Self {
        const standard = Original.defaultWithInitialState().inner.state;
        std.debug.assert(standard.cv_stack_len == 0);
        return .{ .chunk = standard.chunk_state, .total_bytes = framing.PROTOCOL_ID.len + 1 };
    }
    fn expand(self: *const Self) Standard {
        var state = Standard.init(.{});
        state.chunk_state = self.chunk;
        state.cv_stack_len = self.stack_len;
        @memcpy(state.cv_stack[0..self.stack_len], self.stack[0..self.stack_len]);
        return state;
    }
    pub fn update(self: *Self, bytes: []const u8) void {
        // Builder admission enforces this before it consumes caller columns.
        if (bytes.len > max_input_bytes - self.total_bytes) @panic("compact BLAKE3 leaf capacity exceeded");
        var state = self.expand();
        state.update(bytes);
        std.debug.assert(state.cv_stack_len <= self.stack.len);
        self.chunk = state.chunk_state;
        self.stack_len = state.cv_stack_len;
        @memcpy(self.stack[0..self.stack_len], state.cv_stack[0..self.stack_len]);
        self.total_bytes += @intCast(bytes.len);
    }
    pub fn updateLeaf(self: *Self, values: []const M31) void {
        framing.writeLeaf(self, values);
    }
    pub fn updateLeafPackedBytes(self: *Self, bytes: []const u8) void {
        std.debug.assert(bytes.len % 4 == 0);
        self.update(bytes);
    }
    pub fn finalize(self: *const Self) Hash {
        var result: Hash = undefined;
        const state = self.expand();
        state.final(&result);
        return result;
    }
};

test "compact BLAKE3 leaf storage matches standard across every admitted column count" {
    try std.testing.expect(@sizeOf(Hasher) * 4 < @sizeOf(Original));
    var compact = Hasher.defaultWithInitialState();
    var standard = Original.defaultWithInitialState();
    for (0..Hasher.max_columns + 1) |i| {
        try std.testing.expectEqualSlices(u8, &standard.finalize(), &compact.finalize());
        if (i == Hasher.max_columns) break;
        const word = [_]M31{M31.fromU64(i * 37 + 11)};
        compact.updateLeaf(&word);
        standard.updateLeaf(&word);
        // State copies are independent, including partial blocks and CV carries.
        if (i % 251 == 0 and i + 1 < Hasher.max_columns) {
            var copied = compact;
            var reference = standard;
            copied.updateLeaf(&word);
            reference.updateLeaf(&word);
            try std.testing.expectEqualSlices(u8, &reference.finalize(), &copied.finalize());
        }
    }
}
