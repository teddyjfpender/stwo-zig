//! Bounded portable witness frame for detached workers. Graph coverage and
//! canonical fields are checked, but only the worker AIR proves the hash I/O.
//! Native durability/publication phases are not transferable proof authority.
const std = @import("std");
const core = @import("stwo_core");
const N = @import("native_frontier.zig");
const B = @import("batch.zig");
const V = @import("values.zig");
const G = @import("graph_model.zig");
const M = core.fields.m31.M31;
pub const MAGIC = "RV64NF01";
pub const HEADER_BYTES = 112;
pub const Limits = struct { bytes: usize = 512 * 1024 * 1024, records: usize = G.MAX_RECORDS, permutations: usize = N.MAX_IO };
const Counts = struct { counts: B.Counts, patches: usize, io: usize, bytes: usize };
fn geometry(code: u32) !V.Geometry {
    return switch (code) {
        9 => .chunk512,
        12 => .page4096,
        else => error.InvalidFrontierWireGeometry,
    };
}
fn sizes(g: V.Geometry, c: B.Counts, limits: Limits) !Counts {
    const records = try std.math.add(usize, try std.math.add(usize, c.leaves, c.before_nodes), try std.math.add(usize, c.after_nodes, c.sides));
    if (c.leaves == 0 or c.leaves > B.MAX_OPENINGS or c.changed_leaves > c.leaves or records > G.MAX_RECORDS or records > limits.records) return error.FrontierWireResourceLimit;
    const patches = try std.math.add(usize, c.changed_leaves, c.after_nodes);
    const io = try c.permutations(g);
    if (io > N.MAX_IO or io > limits.permutations) return error.FrontierWireResourceLimit;
    var bytes: usize = HEADER_BYTES;
    for ([_]usize{ c.leaves, c.before_nodes + c.after_nodes, c.sides, patches, io }, [_]usize{ 97, 122, 46, 81, 128 }) |count, width| bytes = try std.math.add(usize, bytes, try std.math.mul(usize, count, width));
    if (bytes > limits.bytes) return error.FrontierWireResourceLimit;
    return .{ .counts = c, .patches = patches, .io = io, .bytes = bytes };
}
pub fn encodedBytes(prepared: *const N.Prepared) !usize {
    return (try sizes(prepared.witness.geometry, prepared.counts, .{})).bytes;
}
/// Caller owns atomic publication/fsync. The complete graph is validated before
/// writing. Fixed64KiB buffering avoids a syscall per word or permutation.
pub fn write(file: std.fs.File, prepared: *const N.Prepared) !void {
    try prepared.validate();
    _ = try encodedBytes(prepared);
    var writer = Writer{ .file = file };
    try writer.bytes(MAGIC);
    try writer.int(u32, prepared.witness.geometry.logBytes());
    try writer.int(u32, V.VERSION);
    try writer.digest(prepared.witness.before);
    try writer.digest(prepared.witness.after);
    const c = prepared.counts;
    for ([_]usize{ c.leaves, c.changed_leaves, c.before_nodes, c.after_nodes, c.sides }) |count| try writer.int(u32, @intCast(count));
    try writer.int(u32, 0);
    for (prepared.witness.leaves) |leaf| {
        try writer.int(u64, leaf.graph.index);
        try writer.digest(leaf.graph.before);
        try writer.digest(leaf.graph.after);
        try writer.int(u8, @as(u8, @intFromBool(leaf.graph.changed)) | (@as(u8, @intFromBool(leaf.graph.reuse)) << 1));
        for ([_]u32{ leaf.before_id, leaf.after_id, leaf.before_io, leaf.after_io }) |index| try writer.int(u32, index);
    }
    for ([_][]const B.Node{ prepared.witness.before_nodes, prepared.witness.after_nodes }) |nodes| for (nodes) |node| {
        try writer.int(u8, node.graph.height);
        try writer.int(u64, node.graph.index);
        try writer.digest(node.graph.left);
        try writer.digest(node.graph.right);
        try writer.digest(node.graph.digest);
        try writer.int(u8, @intFromBool(node.graph.reuse));
        try writer.int(u32, node.io);
    };
    for (prepared.witness.sides) |side| {
        try writer.int(u8, side.height);
        try writer.int(u64, side.index);
        try writer.digest(side.digest);
        try writer.int(u8, @intFromBool(side.reuse));
    }
    for (prepared.witness.patches) |patch| {
        try writer.int(u8, patch.height);
        try writer.int(u64, patch.index);
        try writer.digest(patch.before);
        try writer.digest(patch.after);
    }
    for (prepared.io) |call| for ([_][16]M{ call.input, call.output }) |state| for (state) |word| try writer.int(u32, word.v);
    try writer.flush();
}
/// Reads exactly this frame, leaving subsequent work-packet sections untouched.
/// Header byte/count caps are checked before any allocation. A reloaded frame
/// is always prepared advice, irrespective of the sender's publication phase.
pub fn read(a: std.mem.Allocator, file: std.fs.File, limits: Limits) !N.Prepared {
    var raw: [HEADER_BYTES]u8 = undefined;
    if (try file.readAll(&raw) != raw.len) return error.TruncatedFrontierWire;
    if (!std.mem.eql(u8, raw[0..8], MAGIC) or get(u32, raw[12..16]) != V.VERSION or get(u32, raw[108..112]) != 0) return error.InvalidFrontierWireHeader;
    const g = try geometry(get(u32, raw[8..12]));
    const c = B.Counts{ .leaves = get(u32, raw[88..92]), .changed_leaves = get(u32, raw[92..96]), .before_nodes = get(u32, raw[96..100]), .after_nodes = get(u32, raw[100..104]), .sides = get(u32, raw[104..108]) };
    const shape = try sizes(g, c, limits);
    var before: V.Digest = undefined;
    var after: V.Digest = undefined;
    for (&before, &after, 0..) |*x, *y, i| {
        x.* = get(u32, raw[16 + 4 * i ..][0..4]);
        y.* = get(u32, raw[52 + 4 * i ..][0..4]);
    }
    const leaves = try a.alloc(B.Leaf, c.leaves);
    errdefer a.free(leaves);
    const before_nodes = try a.alloc(B.Node, c.before_nodes);
    errdefer a.free(before_nodes);
    const after_nodes = try a.alloc(B.Node, c.after_nodes);
    errdefer a.free(after_nodes);
    const sides = try a.alloc(G.Side, c.sides);
    errdefer a.free(sides);
    const patches = try a.alloc(V.Patch, shape.patches);
    errdefer a.free(patches);
    const io = try a.alloc(V.PermutationIO, shape.io);
    errdefer a.free(io);
    var reader = Reader{ .file = file, .remaining = shape.bytes - HEADER_BYTES };
    for (leaves) |*leaf| {
        const index = try reader.int(u64);
        const x = try reader.digest();
        const y = try reader.digest();
        const flags = try reader.int(u8);
        if (flags > 3) return error.InvalidFrontierWireFlags;
        leaf.* = .{ .graph = .{ .index = index, .before = x, .after = y, .changed = flags & 1 != 0, .reuse = flags & 2 != 0 }, .before_id = try reader.int(u32), .after_id = try reader.int(u32), .before_io = try reader.int(u32), .after_io = try reader.int(u32) };
    }
    for ([_][]B.Node{ before_nodes, after_nodes }) |nodes| for (nodes) |*node| {
        const height = try reader.height();
        const index = try reader.int(u64);
        const left = try reader.digest();
        const right = try reader.digest();
        const digest = try reader.digest();
        const reuse = try reader.boolean();
        node.* = .{ .graph = .{ .height = height, .index = index, .left = left, .right = right, .digest = digest, .reuse = reuse }, .io = try reader.int(u32) };
    };
    for (sides) |*side| {
        const height = try reader.height();
        const index = try reader.int(u64);
        const digest = try reader.digest();
        side.* = .{ .height = height, .index = index, .digest = digest, .reuse = try reader.boolean() };
    }
    for (patches) |*patch| {
        const height = try reader.height();
        const index = try reader.int(u64);
        const x = try reader.digest();
        patch.* = .{ .height = height, .index = index, .before = x, .after = try reader.digest() };
    }
    for (io) |*call| for ([_]*[16]M{ &call.input, &call.output }) |state| for (state) |*word| {
        const value = try reader.int(u32);
        if (value >= core.fields.m31.Modulus) return error.NoncanonicalNativeFrontierIO;
        word.* = M.fromCanonical(value);
    };
    std.debug.assert(reader.remaining == 0 and reader.cursor == reader.used);
    const result = N.Prepared{ .allocator = a, .witness = .{ .allocator = a, .geometry = g, .before = before, .after = after, .leaves = leaves, .before_nodes = before_nodes, .after_nodes = after_nodes, .sides = sides, .patches = patches }, .io = io, .counts = c };
    try result.validate();
    return result;
}
const Writer = struct {
    file: std.fs.File,
    buffer: [65536]u8 = undefined,
    used: usize = 0,
    fn flush(self: *Writer) !void {
        try self.file.writeAll(self.buffer[0..self.used]);
        self.used = 0;
    }
    fn bytes(self: *Writer, data: []const u8) !void {
        std.debug.assert(data.len <= self.buffer.len);
        if (self.buffer.len - self.used < data.len) try self.flush();
        @memcpy(self.buffer[self.used..][0..data.len], data);
        self.used += data.len;
    }
    fn int(self: *Writer, comptime I: type, value: I) !void {
        var raw: [@sizeOf(I)]u8 = undefined;
        std.mem.writeInt(I, &raw, value, .little);
        try self.bytes(&raw);
    }
    fn digest(self: *Writer, value: V.Digest) !void {
        for (value) |word| try self.int(u32, word);
    }
};
const Reader = struct {
    file: std.fs.File,
    buffer: [65536]u8 = undefined,
    cursor: usize = 0,
    used: usize = 0,
    remaining: usize,
    fn byte(self: *Reader) !u8 {
        if (self.cursor == self.used) {
            const count = @min(self.buffer.len, self.remaining);
            if (count == 0) return error.TruncatedFrontierWire;
            self.used = try self.file.readAll(self.buffer[0..count]);
            if (self.used != count) return error.TruncatedFrontierWire;
            self.remaining -= count;
            self.cursor = 0;
        }
        defer self.cursor += 1;
        return self.buffer[self.cursor];
    }
    fn int(self: *Reader, comptime I: type) !I {
        var raw: [@sizeOf(I)]u8 = undefined;
        for (&raw) |*value| value.* = try self.byte();
        return std.mem.readInt(I, &raw, .little);
    }
    fn digest(self: *Reader) !V.Digest {
        var result: V.Digest = undefined;
        for (&result) |*word| word.* = try self.int(u32);
        return result;
    }
    fn boolean(self: *Reader) !bool {
        const value = try self.byte();
        if (value > 1) return error.InvalidFrontierWireFlags;
        return value != 0;
    }
    fn height(self: *Reader) !u6 {
        const value = try self.byte();
        if (value > 63) return error.InvalidFrontierWireHeight;
        return @intCast(value);
    }
};
fn get(comptime I: type, bytes: *const [@sizeOf(I)]u8) I {
    return std.mem.readInt(I, bytes, .little);
}
