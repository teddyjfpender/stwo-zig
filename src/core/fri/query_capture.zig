//! Verifier-owned FRI query captures for recursive witness generation.

const std = @import("std");
const QM31 = @import("../fields/qm31.zig").QM31;

/// Both forms of the verifier-owned FRI query draw.
///
/// `raw` preserves protocol order and duplicates. `unique` is the sorted,
/// deduplicated set used by Merkle multiproof verification. Recursive witness
/// construction needs both: the former fixes logical query slots, while the
/// latter indexes the compressed proof openings.
pub const SampledQueryPositions = struct {
    raw: []usize,
    unique: []usize,

    pub fn deinit(self: *SampledQueryPositions, allocator: std.mem.Allocator) void {
        allocator.free(self.raw);
        allocator.free(self.unique);
        self.* = undefined;
    }
};

/// Fixed-slot material reconstructed for one authenticated FRI layer.
/// Values and paths are laid out in raw transcript-query order, including
/// duplicates, so recursive witness generation never depends on multiproof
/// compression choices.
pub fn FriLayerQueryCapture(comptime H: type) type {
    return struct {
        commitment: H.Hash,
        folding_alpha: QM31,
        fold_step: u32,
        fold_width: u32,
        path_depth: u32,
        query_count: usize,
        positions: []usize,
        values: []QM31,
        siblings: []H.Hash,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.positions);
            allocator.free(self.values);
            allocator.free(self.siblings);
            self.* = undefined;
        }

        pub fn queryValues(self: Self, query_index: usize) []const QM31 {
            std.debug.assert(query_index < self.query_count);
            const width: usize = @intCast(self.fold_width);
            const start = query_index * width;
            return self.values[start..][0..width];
        }

        pub fn queryPath(self: Self, query_index: usize) []const H.Hash {
            std.debug.assert(query_index < self.query_count);
            const depth: usize = @intCast(self.path_depth);
            const start = query_index * depth;
            return self.siblings[start..][0..depth];
        }
    };
}

/// All FRI-layer openings expanded by a successful verifier.
pub fn FriQueryCapture(comptime H: type) type {
    return struct {
        layers: []FriLayerQueryCapture(H),

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            for (self.layers) |*layer| layer.deinit(allocator);
            allocator.free(self.layers);
            self.* = undefined;
        }
    };
}
