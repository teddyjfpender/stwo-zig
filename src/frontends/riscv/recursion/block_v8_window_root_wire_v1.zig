//! Thin public metadata. Snapshots/ELF stay in the independently pinned
//! checkpoint catalog; no proof body, capture or verifier key is serialized.
const std = @import("std");
const Wire = @import("../prover/block_v7_union_claim_wire_v1.zig");
const Cursor = @import("../prover/guest_precompile/proof_artifact_wire.zig").Cursor;
pub const NativeLeaf = @import("block_v8_window_root_receiver_v1.zig").Leaf;
pub const MixedLeaf = struct {
    main_root: [32]u8,
    global_g_repartition: bool = false,
    input: @import("block_v8_endpoint_mixed_join_receiver_v1.zig").Input,
};
pub const NodeRecord = struct {
    /// 0=native leaf; 1=mixed leaf; 2=fold. index is catalog node ordinal.
    kind: u8,
    index: u32,
    children: []const u32,
    main_root: [32]u8,
    pub fn validate(v: NodeRecord) !void {
        if (v.kind > 2 or v.index >= 4096) return error.InvalidB8RootNode;
        if (v.kind != 2) {
            if (v.children.len != 0) return error.InvalidB8RootNode;
        } else {
            if (v.children.len < 2 or v.children.len > 4) return error.InvalidB8RootNode;
            for (v.children, 0..) |child, i| {
                if (child >= v.index) return error.InvalidB8RootNode;
                for (v.children[0..i]) |previous| if (previous == child) return error.InvalidB8RootNode;
            }
        }
    }
};
pub const Limits = struct { max_bytes: usize = 128 << 20, max_items: usize = 16 << 20 };
fn Owned(comptime T: type) type {
    return struct {
        arena: std.heap.ArenaAllocator,
        value: T,
        pub fn deinit(v: *@This()) void {
            v.arena.deinit();
            v.* = undefined;
        }
    };
}
pub const NativeOwned = Owned(NativeLeaf);
pub const MixedOwned = Owned(MixedLeaf);
pub const NodeOwned = Owned(NodeRecord);
fn encode(comptime T: type, a: std.mem.Allocator, value: T, kind: u8, limits: Limits) ![]u8 {
    var out = @import("../prover/bounded_artifact_writer_v1.zig").Writer.init(a, limits.max_bytes);
    defer out.deinit();
    try out.writeAll("B8WROOT1");
    try out.writeByte(kind);
    try out.writeAll(&Wire.schemaId(T));
    var items = limits.max_items;
    try Wire.encode(T, &out, value, &items);
    return a.dupe(u8, out.bytes.items);
}
fn decode(comptime T: type, a: std.mem.Allocator, bytes: []const u8, kind: u8, limits: Limits) !Owned(T) {
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const value = try decodeValue(T, arena.allocator(), bytes, kind, limits);
    return .{ .arena = arena, .value = value };
}

pub fn encodeNativeLeafWithLimits(a: std.mem.Allocator, value: NativeLeaf, limits: Limits) ![]u8 {
    return encode(NativeLeaf, a, value, 0, limits);
}
pub fn decodeNativeLeafOwned(a: std.mem.Allocator, bytes: []const u8, limits: Limits) !NativeOwned {
    return decode(NativeLeaf, a, bytes, 0, limits);
}
pub fn encodeMixedLeafWithLimits(a: std.mem.Allocator, value: MixedLeaf, limits: Limits) ![]u8 {
    if (value.input.root.len != 0) return error.ChildProofInB8RootMetadata;
    return encode(MixedLeaf, a, value, 1, limits);
}
pub fn decodeMixedLeafOwned(a: std.mem.Allocator, bytes: []const u8, limits: Limits) !MixedOwned {
    var result = try decode(MixedLeaf, a, bytes, 1, limits);
    errdefer result.deinit();
    if (result.value.input.root.len != 0) return error.ChildProofInB8RootMetadata;
    return result;
}
pub fn encodeNodeWithLimits(a: std.mem.Allocator, value: NodeRecord, limits: Limits) ![]u8 {
    try value.validate();
    return encode(NodeRecord, a, value, 2, limits);
}
pub fn decodeNodeOwned(a: std.mem.Allocator, bytes: []const u8, limits: Limits) !NodeOwned {
    var result = try decode(NodeRecord, a, bytes, 2, limits);
    errdefer result.deinit();
    try result.value.validate();
    return result;
}

/// Convenience receiver forms require a caller-owned arena (also on failure).
/// The Owned forms above support independent allocator cleanup where needed.
fn decodeValue(comptime T: type, a: std.mem.Allocator, bytes: []const u8, kind: u8, limits: Limits) !T {
    if (bytes.len < 41 or bytes.len > limits.max_bytes or !std.mem.eql(u8, bytes[0..8], "B8WROOT1") or bytes[8] != kind or !std.meta.eql(bytes[9..41].*, Wire.schemaId(T))) return error.InvalidB8RootMetadata;
    var cursor = Cursor{ .bytes = bytes, .position = 41 };
    var items = limits.max_items;
    const value = try Wire.decode(T, a, &cursor, &items);
    if (cursor.position != bytes.len) return error.NonCanonicalB8RootMetadata;
    return value;
}
pub fn encodeNativeLeaf(a: std.mem.Allocator, value: NativeLeaf) ![]u8 {
    return encodeNativeLeafWithLimits(a, value, .{});
}
pub fn decodeNativeLeaf(a: std.mem.Allocator, bytes: []const u8) !NativeLeaf {
    return decodeNativeLeafLeaky(a, bytes, .{});
}
pub fn encodeMixedLeaf(a: std.mem.Allocator, value: MixedLeaf) ![]u8 {
    return encodeMixedLeafWithLimits(a, value, .{});
}
pub fn decodeMixedLeaf(a: std.mem.Allocator, bytes: []const u8) !MixedLeaf {
    const value = try decodeValue(MixedLeaf, a, bytes, 1, .{});
    if (value.input.root.len != 0) return error.ChildProofInB8RootMetadata;
    return value;
}
pub fn encodeNode(a: std.mem.Allocator, value: NodeRecord) ![]u8 {
    return encodeNodeWithLimits(a, value, .{});
}
pub fn decodeNode(a: std.mem.Allocator, bytes: []const u8) !NodeRecord {
    const value = try decodeValue(NodeRecord, a, bytes, 2, .{});
    try value.validate();
    return value;
}

pub fn decodeNativeLeafLeaky(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) !NativeLeaf {
    return decodeValue(NativeLeaf, arena, bytes, 0, limits);
}
pub fn decodeMixedLeafLeaky(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) !MixedLeaf {
    const value = try decodeValue(MixedLeaf, arena, bytes, 1, limits);
    if (value.input.root.len != 0) return error.ChildProofInB8RootMetadata;
    return value;
}
pub fn decodeNodeLeaky(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) !NodeRecord {
    const value = try decodeValue(NodeRecord, arena, bytes, 2, limits);
    try value.validate();
    return value;
}
