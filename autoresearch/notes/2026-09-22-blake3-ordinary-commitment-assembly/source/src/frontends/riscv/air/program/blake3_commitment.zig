//! Full-width program commitment over canonical decoded program-access fields.
//! Admission is shared with the legacy suite; this module performs no Poseidon
//! hashing and does not reinterpret instruction fields as single bytes.
const std = @import("std");
const legacy = @import("commitment.zig");
const tree = @import("../memory_commitment/blake3_byte_tree.zig");
const state = @import("../../runner/memory_state.zig");
const table = @import("table.zig");
pub const Row = struct {
    addr: u32,
    values: @import("decode.zig").ProgramValues,
    multiplicity: u32,
};
pub const Commitment = struct {
    allocator: std.mem.Allocator,
    rows: []Row,
    leaves: []tree.Leaf,
    root: tree.Digest,
    pub fn deinit(self: *Commitment) void {
        self.allocator.free(self.rows);
        self.allocator.free(self.leaves);
        self.* = undefined;
    }
    pub fn opening(self: *const Commitment, address: u32) !tree.Opening {
        const hasher = tree.TreeHasher.init(.program);
        const result = try hasher.opening(self.leaves, address);
        if (!std.meta.eql(result.root, self.root)) return error.ProgramRootMismatch;
        return result;
    }
};
pub fn buildDeclared(
    a: std.mem.Allocator,
    decoder: anytype,
    execution_sources: anytype,
    program_words: []const state.WordState,
    extra_fetch: ?table.Fetch,
) !Commitment {
    const admitted = try legacy.declaredRows(a, decoder, execution_sources, program_words, extra_fetch);
    defer a.free(admitted);
    const rows = try a.alloc(Row, admitted.len);
    errdefer a.free(rows);
    const leaves = try a.alloc(tree.Leaf, try std.math.mul(usize, admitted.len, 4));
    errdefer a.free(leaves);
    for (admitted, rows, 0..) |entry, *row, i| {
        row.* = .{ .addr = entry.addr, .values = entry.values, .multiplicity = entry.multiplicity };
        for (entry.values, 0..) |value, limb|
            leaves[i * 4 + limb] = .{ .index = entry.addr + @as(u32, @intCast(limb)), .value = value };
    }
    const hasher = tree.TreeHasher.init(.program);
    return .{ .allocator = a, .rows = rows, .leaves = leaves, .root = try hasher.root(leaves) };
}
