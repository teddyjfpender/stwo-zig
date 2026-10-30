//! Finite union claim encoding: fixed little-endian integers, canonical field
//! limbs, checked slice lengths, and a structural schema identifier. No proof
//! authority is granted by transport validation. Caller owns a bounded arena.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Wire = @import("guest_precompile/proof_artifact_wire.zig");

fn IntWire(comptime T: type) type {
    const info = @typeInfo(T).int;
    if (info.signedness != .unsigned or info.bits > 64) @compileError("unsupported union claim integer");
    return if (info.bits <= 8) u8 else if (info.bits <= 16) u16 else if (info.bits <= 32) u32 else u64;
}
pub fn minimum(comptime T: type) usize {
    if (T == M) return 4;
    if (T == Q) return 16;
    return switch (@typeInfo(T)) {
        .void => 0,
        .int => @sizeOf(IntWire(T)),
        .bool, .optional => 1,
        .array => |info| info.len * minimum(info.child),
        .pointer => |info| if (info.size == .slice) 4 else @compileError("only slices in union claims"),
        .@"struct" => |info| blk: {
            var n: usize = 0;
            inline for (info.fields) |field| n += minimum(field.type);
            break :blk n;
        },
        else => @compileError("unsupported union claim type " ++ @typeName(T)),
    };
}
pub fn encode(comptime T: type, out: anytype, value: T, remaining_items: *usize) anyerror!void {
    if (T == M) {
        if (value.v >= core.fields.m31.Modulus) return error.NonCanonicalM31;
        return Wire.writeInt(out, u32, value.v);
    }
    if (T == Q) return out.writeClaim(value);
    switch (@typeInfo(T)) {
        .void => {},
        .int => try Wire.writeInt(out, IntWire(T), @intCast(value)),
        .bool => try out.writeByte(@intFromBool(value)),
        .optional => |info| {
            try out.writeByte(@intFromBool(value != null));
            if (value) |v| try encode(info.child, out, v, remaining_items);
        },
        .array => |info| for (value) |v| try encode(info.child, out, v, remaining_items),
        .pointer => |info| {
            if (info.size != .slice) @compileError("only slices in union claims");
            if (value.len > remaining_items.*) return error.UnionClaimCountLimit;
            remaining_items.* -= value.len;
            try Wire.writeInt(out, u32, std.math.cast(u32, value.len) orelse return error.Overflow);
            for (value) |v| try encode(info.child, out, v, remaining_items);
        },
        .@"struct" => |info| inline for (info.fields) |field| try encode(field.type, out, @field(value, field.name), remaining_items),
        else => @compileError("unsupported union claim type " ++ @typeName(T)),
    }
}
pub fn decode(comptime T: type, a: std.mem.Allocator, cursor: *Wire.Cursor, remaining_items: *usize) anyerror!T {
    if (T == M) {
        const value = try cursor.readInt(u32);
        if (value >= core.fields.m31.Modulus) return error.NonCanonicalM31;
        return M.fromCanonical(value);
    }
    if (T == Q) return cursor.readQm31();
    return switch (@typeInfo(T)) {
        .void => {},
        .int => std.math.cast(T, try cursor.readInt(IntWire(T))) orelse error.NonCanonicalUnionInteger,
        .bool => switch (try cursor.readInt(u8)) {
            0 => false,
            1 => true,
            else => error.NonCanonicalUnionTag,
        },
        .optional => |info| switch (try cursor.readInt(u8)) {
            0 => null,
            1 => try decode(info.child, a, cursor, remaining_items),
            else => error.NonCanonicalUnionTag,
        },
        .array => |info| blk: {
            var result: T = undefined;
            for (&result) |*v| v.* = try decode(info.child, a, cursor, remaining_items);
            break :blk result;
        },
        .pointer => |info| blk: {
            if (info.size != .slice) @compileError("only slices in union claims");
            const count = try cursor.readInt(u32);
            if (count > remaining_items.*) return error.UnionClaimCountLimit;
            const needed = try std.math.mul(usize, count, minimum(info.child));
            // Reject amplified/truncated length prefixes before allocation.
            if (needed > cursor.bytes.len - cursor.position) return error.TruncatedUnionClaims;
            remaining_items.* -= count;
            const result = try a.alloc(info.child, count);
            for (result) |*v| v.* = try decode(info.child, a, cursor, remaining_items);
            break :blk result;
        },
        .@"struct" => |info| blk: {
            var result: T = undefined;
            inline for (info.fields) |field| @field(result, field.name) = try decode(field.type, a, cursor, remaining_items);
            break :blk result;
        },
        else => @compileError("unsupported union claim type " ++ @typeName(T)),
    };
}
fn number(h: *std.crypto.hash.sha2.Sha256, n: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, n, .little);
    h.update(&bytes);
}
fn schema(comptime T: type, h: *std.crypto.hash.sha2.Sha256) void {
    if (T == M) return h.update("canonical-m31;");
    if (T == Q) return h.update("canonical-qm31-le4;");
    switch (@typeInfo(T)) {
        .void => h.update("unit;"),
        .int => |info| {
            h.update("uint;");
            number(h, info.bits);
        },
        .bool => h.update("bool01;"),
        .optional => |info| {
            h.update("optional01;");
            schema(info.child, h);
        },
        .array => |info| {
            h.update("array;");
            number(h, info.len);
            schema(info.child, h);
        },
        .pointer => |info| {
            h.update("slice-u32;");
            schema(info.child, h);
        },
        .@"struct" => |info| {
            h.update("struct;");
            number(h, info.fields.len);
            inline for (info.fields) |field| {
                number(h, field.name.len);
                h.update(field.name);
                schema(field.type, h);
            }
        },
        else => @compileError("unsupported union claim schema"),
    }
}
pub fn schemaId(comptime T: type) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo-zig/finite-union-claims/v1\x00");
    schema(T, &h);
    return h.finalResult();
}

test "union claim framing rejects length amplification and noncanonical scalar tags" {
    const a = std.testing.allocator;
    var remaining: usize = 8;
    var empty = Wire.Cursor.init(&.{ 8, 0, 0, 0 });
    try std.testing.expectError(error.TruncatedUnionClaims, decode([]Q, std.testing.failing_allocator, &empty, &remaining));
    var narrow = Wire.Cursor.init(&.{2});
    try std.testing.expectError(error.NonCanonicalUnionInteger, decode(u1, a, &narrow, &remaining));
    var optional = Wire.Cursor.init(&.{2});
    try std.testing.expectError(error.NonCanonicalUnionTag, decode(?u64, a, &optional, &remaining));
    var noncanonical = Wire.Cursor.init(&.{ 255, 255, 255, 127 });
    try std.testing.expectError(error.NonCanonicalM31, decode(M, a, &noncanonical, &remaining));
    try std.testing.expect(!std.meta.eql(schemaId(struct { count: u32 }), schemaId(struct { count: u64 })));
}
