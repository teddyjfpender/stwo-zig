//! Host-only retained Merkle values, moved without hashing/rebuilding a tree.
//! Outer descriptors remain tree-owned; an enclosing FD owner retains nodes.
const std = @import("std");
const Tree = @import("protocol.zig").T.Scheme.CommittedTree;
const Hash = [32]u8;
comptime {
    std.debug.assert(@import("protocol.zig").T.P.Hasher == @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher);
}
pub const HEADER_BYTES: usize = 128;
pub const HASH_SCHEMA: u32 = 1; // Native prefixed unreduced Blake2s-256.
pub fn nodeBytes(tree: *const Tree) !usize {
    if (tree.commitment.layer_values_borrowed or tree.commitment.layers_parked or tree.commitment.layers.len == 0 or tree.commitment.layers.len > 31) return error.UnsupportedRetainedMainMerkle;
    var count: usize = 0;
    var pruned = false;
    for (tree.commitment.layers, 0..) |layer, i| {
        if (layer.len == 0) {
            if (i == 0) return error.RetainedMainShapeMismatch;
            pruned = true;
            continue;
        }
        if (pruned or layer.len != @as(usize, 1) << @intCast(i)) return error.RetainedMainShapeMismatch;
        count = try std.math.add(usize, count, layer.len);
    }
    return std.math.mul(usize, count, @sizeOf(Hash));
}
pub const Capture = struct {
    lengths: []usize,
    descriptor_address: usize,
    root_cell: [1]Hash,
    bytes: usize,
    offset: usize,
    pub fn init(a: std.mem.Allocator, tree: *const Tree, offset: usize) !Capture {
        if (@import("builtin").target.cpu.arch.endian() != .little) return error.UnsupportedRetainedMainEndian;
        const bytes = try nodeBytes(tree);
        const lengths = try a.alloc(usize, tree.commitment.layers.len);
        for (tree.commitment.layers, lengths) |layer, *len| len.* = layer.len;
        return .{ .lengths = lengths, .descriptor_address = @intFromPtr(tree.commitment.layers.ptr), .root_cell = .{tree.root()}, .bytes = bytes, .offset = offset };
    }
    pub fn deinit(self: *Capture, a: std.mem.Allocator) void {
        a.free(self.lengths);
        self.* = undefined;
    }
    pub fn write(self: *const Capture, tree: *const Tree, file: std.fs.File, hash: *std.crypto.hash.blake2.Blake2s256) !void {
        _ = self;
        for (tree.commitment.layers) |layer| {
            const bytes = std.mem.sliceAsBytes(layer);
            try file.writeAll(bytes);
            hash.update(bytes);
        }
    }
    /// All I/O and allocations have completed. Caller owns tree exclusively.
    pub fn park(self: *Capture, tree: *Tree) void {
        for (tree.commitment.layers) |*layer| {
            tree.commitment.layer_allocator.free(layer.*);
            layer.* = &.{};
        }
        tree.commitment.layers[0] = &self.root_cell;
        tree.commitment.layer_values_borrowed = true;
        tree.commitment.layers_parked = true;
    }
    pub fn validate(self: *const Capture, tree: *const Tree, mapping: ?[]align(std.heap.page_size_min) u8) !void {
        const m = tree.commitment;
        if (!m.layer_values_borrowed or m.layers_parked != (mapping == null) or @intFromPtr(m.layers.ptr) != self.descriptor_address or m.layers.len != self.lengths.len) return error.RetainedMainShapeMismatch;
        var at = self.offset;
        for (m.layers, self.lengths, 0..) |layer, len, i| {
            if (mapping) |memory| {
                const bytes = try std.math.mul(usize, len, @sizeOf(Hash));
                if (at > memory.len or bytes > memory.len - at) return error.RetainedMainShapeMismatch;
                const values = std.mem.bytesAsSlice(Hash, memory[at..][0..bytes]);
                if (layer.len != len or (len != 0 and layer.ptr != values.ptr)) return error.RetainedMainShapeMismatch;
                at = try std.math.add(usize, at, bytes);
            } else if (i == 0) {
                if (layer.len != 1 or layer.ptr != self.root_cell[0..].ptr) return error.RetainedMainShapeMismatch;
            } else if (layer.len != 0) return error.RetainedMainShapeMismatch;
        }
        if (!std.mem.eql(u8, &tree.root(), &self.root_cell[0])) return error.RetainedMainShapeMismatch;
    }
    pub fn publish(self: *const Capture, tree: *Tree, memory: []align(std.heap.page_size_min) u8) void {
        var at = self.offset;
        for (tree.commitment.layers, self.lengths) |*layer, len| {
            const bytes = len * @sizeOf(Hash);
            layer.* = std.mem.bytesAsSlice(Hash, memory[at..][0..bytes]);
            at += bytes;
        }
        tree.commitment.layers_parked = false;
    }
};
pub fn metadataDigest(tree: *const Tree, words: usize, capture: *const Capture) Hash {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    h.update("STWO/native-main/coefficient+merkle-shape/v2\x00");
    var bytes: [8]u8 = undefined;
    for ([_]usize{ HASH_SCHEMA, words, tree.columns.len, capture.lengths.len, capture.offset, capture.bytes }) |n| {
        std.mem.writeInt(u64, &bytes, @intCast(n), .little);
        h.update(&bytes);
    }
    for (tree.coefficients.?, tree.columns) |c, col| for ([_]usize{ c.log_size, c.coeffs.len, col.log_size }) |n| {
        std.mem.writeInt(u64, &bytes, @intCast(n), .little);
        h.update(&bytes);
    };
    for (capture.lengths) |n| {
        std.mem.writeInt(u64, &bytes, @intCast(n), .little);
        h.update(&bytes);
    }
    var result: [32]u8 = undefined;
    h.final(&result);
    return result;
}
pub fn header(tree: *const Tree, words: usize, capture: *const Capture) [HEADER_BYTES]u8 {
    var out = [_]u8{0} ** HEADER_BYTES;
    @memcpy(out[0..16], "STWOMAINPARKv2\x00\x00");
    std.mem.writeInt(u32, out[16..20], 2, .little);
    std.mem.writeInt(u32, out[20..24], HASH_SCHEMA, .little);
    std.mem.writeInt(u32, out[24..28], @intCast(capture.lengths.len), .little);
    std.mem.writeInt(u32, out[28..32], @intCast(tree.columns.len), .little);
    std.mem.writeInt(u64, out[32..40], words, .little);
    std.mem.writeInt(u64, out[40..48], capture.bytes, .little);
    std.mem.writeInt(u64, out[48..56], capture.offset, .little);
    std.mem.writeInt(u32, out[56..60], @import("stwo_core").fields.m31.Modulus, .little);
    std.mem.writeInt(u32, out[60..64], 1, .little); // LE native M31 payload.
    @memcpy(out[64..96], &tree.root());
    @memcpy(out[96..128], &metadataDigest(tree, words, capture));
    return out;
}
