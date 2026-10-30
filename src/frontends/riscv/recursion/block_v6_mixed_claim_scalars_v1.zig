//! Explicit little-endian scalar grammar for fixed original claim structures.
//! ABI padding and native pointers never appear on the wire.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Wire = @import("../prover/guest_precompile/proof_artifact_wire.zig");
pub const Limits = @import("block_v6_mixed_claim_types_v1.zig").Limits;
pub fn write(writer: anytype, value: anytype, limits: Limits) anyerror!void {
    const T = @TypeOf(value);
    if (T == Q) return writer.writeClaim(value);
    switch (@typeInfo(T)) {
        .int => try Wire.writeInt(writer, T, value),
        .array => for (value) |item| try write(writer, item, limits),
        .@"struct" => |info| inline for (info.fields) |field| try write(writer, @field(value, field.name), limits),
        .pointer => |info| {
            if (info.size != .slice) @compileError("claim pointers must be slices");
            if (value.len > limits.max_slice_elements or value.len > std.math.maxInt(u32)) return error.MixedClaimResourceLimit;
            try Wire.writeInt(writer, u32, @intCast(value.len));
            for (value) |item| try write(writer, item, limits);
        },
        else => @compileError("unsupported original claim scalar " ++ @typeName(T)),
    }
}
pub fn free(a: std.mem.Allocator, value: anytype) void {
    const T = @TypeOf(value);
    if (T == Q) return;
    switch (@typeInfo(T)) {
        .int => {},
        .array => for (value) |item| free(a, item),
        .@"struct" => |info| inline for (info.fields) |field| free(a, @field(value, field.name)),
        .pointer => {
            for (value) |item| free(a, item);
            a.free(value);
        },
        else => @compileError("unsupported original claim scalar"),
    }
}
pub fn minimum(comptime T: type) usize {
    if (T == Q) return 16;
    return switch (@typeInfo(T)) {
        .int => @sizeOf(T),
        .pointer => 4,
        .array => |info| info.len * minimum(info.child),
        .@"struct" => |info| blk: {
            var sum: usize = 0;
            inline for (info.fields) |field| sum += minimum(field.type);
            break :blk sum;
        },
        else => @compileError("unsupported original claim scalar"),
    };
}
pub const Reader = struct {
    a: std.mem.Allocator,
    cursor: Wire.Cursor,
    limits: Limits,
    owned: usize = 0,
    pub fn read(self: *@This(), comptime T: type) anyerror!T {
        if (T == Q) return self.cursor.readQm31();
        switch (@typeInfo(T)) {
            .int => return self.cursor.readInt(T),
            .array => |info| {
                var result: T = undefined;
                var initialized: usize = 0;
                errdefer for (result[0..initialized]) |item| free(self.a, item);
                for (&result) |*item| {
                    item.* = try self.read(info.child);
                    initialized += 1;
                }
                return result;
            },
            .@"struct" => |info| {
                var result: T = undefined;
                var initialized: usize = 0;
                errdefer inline for (info.fields, 0..) |field, i| {
                    if (i < initialized) free(self.a, @field(result, field.name));
                };
                inline for (info.fields) |field| {
                    @field(result, field.name) = try self.read(field.type);
                    initialized += 1;
                }
                return result;
            },
            .pointer => |info| {
                if (info.size != .slice) @compileError("claim pointers must be slices");
                const count = try self.cursor.readInt(u32);
                if (count > self.limits.max_slice_elements or try std.math.mul(usize, count, minimum(info.child)) > self.cursor.bytes.len - self.cursor.position) return error.MixedClaimResourceLimit;
                self.owned = try std.math.add(usize, self.owned, try std.math.mul(usize, count, @sizeOf(info.child)));
                if (self.owned > self.limits.max_owned_bytes) return error.MixedClaimResourceLimit;
                const result = try self.a.alloc(info.child, count);
                var initialized: usize = 0;
                errdefer {
                    for (result[0..initialized]) |item| free(self.a, item);
                    self.a.free(result);
                }
                for (result) |*item| {
                    item.* = try self.read(info.child);
                    initialized += 1;
                }
                return result;
            },
            else => @compileError("unsupported original claim scalar " ++ @typeName(T)),
        }
    }
};
/// Claim field names, widths and array extents bind the grammar; changing an
/// original claim structure cannot silently reinterpret a prior artifact.
pub fn schema(comptime T: type, hash: *std.crypto.hash.sha2.Sha256) void {
    if (T == Q) {
        hash.update("qm31;");
        return;
    }
    switch (@typeInfo(T)) {
        .int => |info| hash.update(std.fmt.comptimePrint("int{d}:{s};", .{ info.bits, @tagName(info.signedness) })),
        .array => |info| {
            hash.update("array" ++ std.fmt.comptimePrint("{d}:", .{info.len}));
            schema(info.child, hash);
        },
        .pointer => |info| {
            hash.update("slice:");
            schema(info.child, hash);
        },
        .@"struct" => |info| {
            hash.update("struct{");
            inline for (info.fields) |field| {
                hash.update(field.name ++ ":");
                schema(field.type, hash);
            }
            hash.update("};");
        },
        else => @compileError("unsupported original claim scalar"),
    }
}
