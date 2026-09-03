//! Small canonical-JSON codec shared by the recursive pipeline worker wire.
//!
//! This deliberately matches Python's sorted-key, compact, ASCII JSON plus a
//! single LF. Floating point values are outside the worker protocol.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

pub const Json = std.json.Value;
pub const Digest = artifact_store.Digest;

pub fn canonicalAlloc(
    allocator: std.mem.Allocator,
    value: Json,
    omit_content_sha256: bool,
) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try appendCanonical(
        allocator,
        &output,
        value,
        if (omit_content_sha256) "content_sha256" else null,
    );
    try output.append(allocator, '\n');
    return output.toOwnedSlice(allocator);
}

pub fn canonicalDigest(
    allocator: std.mem.Allocator,
    value: Json,
) !Digest {
    const encoded = try canonicalAlloc(allocator, value, false);
    defer allocator.free(encoded);
    return artifact_store.digestBytes(encoded);
}

pub fn sealObject(allocator: std.mem.Allocator, value: *Json) !void {
    const object_map = try objectPointer(value);
    if (object_map.contains("content_sha256"))
        return error.WorkerSealAlreadyPresent;
    const encoded = try canonicalAlloc(allocator, value.*, true);
    defer allocator.free(encoded);
    try putDigest(
        allocator,
        value,
        "content_sha256",
        artifact_store.digestBytes(encoded),
    );
}

pub fn validateSeal(
    allocator: std.mem.Allocator,
    object_map: std.json.ObjectMap,
) !void {
    const observed = try digestField(object_map, "content_sha256", true);
    const encoded = try canonicalAlloc(
        allocator,
        .{ .object = object_map },
        true,
    );
    defer allocator.free(encoded);
    const expected = artifact_store.digestBytes(encoded);
    if (!std.mem.eql(u8, &observed, &expected))
        return error.InvalidWorkerContentSeal;
}

pub fn jsonObject(allocator: std.mem.Allocator) Json {
    return .{ .object = std.json.ObjectMap.init(allocator) };
}

pub fn array(allocator: std.mem.Allocator) Json {
    return .{ .array = std.json.Array.init(allocator) };
}

pub fn string(value: []const u8) Json {
    return .{ .string = value };
}

pub fn integer(value: anytype) Json {
    return .{ .integer = @intCast(value) };
}

pub fn integerU64(allocator: std.mem.Allocator, value: u64) !Json {
    if (value > std.math.maxInt(i64)) {
        return .{ .number_string = try std.fmt.allocPrint(
            allocator,
            "{d}",
            .{value},
        ) };
    }
    return .{ .integer = @intCast(value) };
}

pub fn put(target: *Json, key: []const u8, value: Json) !void {
    const map = try objectPointer(target);
    if (map.contains(key)) return error.DuplicateWorkerField;
    try map.put(key, value);
}

pub fn append(target: *Json, value: Json) !void {
    if (target.* != .array) return error.InvalidWorkerJson;
    try target.array.append(value);
}

pub fn stringField(
    object_map: std.json.ObjectMap,
    name: []const u8,
) ![]const u8 {
    const value = object_map.get(name) orelse return error.MissingWorkerField;
    if (value != .string) return error.InvalidWorkerField;
    return value.string;
}

pub fn unsignedField(
    comptime T: type,
    object_map: std.json.ObjectMap,
    name: []const u8,
) !T {
    const value = object_map.get(name) orelse return error.MissingWorkerField;
    return switch (value) {
        .integer => |item| if (item >= 0)
            (std.math.cast(T, item) orelse return error.InvalidWorkerInteger)
        else
            error.InvalidWorkerInteger,
        .number_string => |item| std.fmt.parseInt(T, item, 10) catch
            error.InvalidWorkerInteger,
        else => error.InvalidWorkerInteger,
    };
}

pub fn positiveField(
    comptime T: type,
    object_map: std.json.ObjectMap,
    name: []const u8,
) !T {
    const result = try unsignedField(T, object_map, name);
    if (result == 0) return error.InvalidWorkerInteger;
    return result;
}

pub fn objectValue(value: Json) !std.json.ObjectMap {
    if (value != .object) return error.InvalidWorkerObject;
    return value.object;
}

pub fn objectPointer(value: *Json) !*std.json.ObjectMap {
    if (value.* != .object) return error.InvalidWorkerObject;
    return &value.object;
}

pub fn exactKeys(
    object_map: std.json.ObjectMap,
    expected: []const []const u8,
) !void {
    if (object_map.count() != expected.len) return error.InvalidWorkerFields;
    for (expected) |name| {
        if (!object_map.contains(name)) return error.InvalidWorkerFields;
    }
}

pub fn digestField(
    object_map: std.json.ObjectMap,
    name: []const u8,
    nonzero: bool,
) !Digest {
    const encoded = try stringField(object_map, name);
    if (encoded.len != 64) return error.InvalidWorkerDigest;
    for (encoded) |byte| {
        if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f'))
            return error.InvalidWorkerDigest;
    }
    var result: Digest = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch
        return error.InvalidWorkerDigest;
    if (nonzero and artifact_store.encoding.isZeroDigest(result))
        return error.InvalidWorkerDigest;
    return result;
}

pub fn hexAlloc(
    allocator: std.mem.Allocator,
    value: Digest,
) ![]u8 {
    const encoded = std.fmt.bytesToHex(value, .lower);
    return allocator.dupe(u8, &encoded);
}

pub fn putDigest(
    allocator: std.mem.Allocator,
    target: *Json,
    key: []const u8,
    value: Digest,
) !void {
    try put(target, key, string(try hexAlloc(allocator, value)));
}

fn appendCanonical(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u8),
    value: Json,
    omitted_object_key: ?[]const u8,
) !void {
    switch (value) {
        .null => try output.appendSlice(allocator, "null"),
        .bool => |item| try output.appendSlice(
            allocator,
            if (item) "true" else "false",
        ),
        .integer => |item| try output.writer(allocator).print("{d}", .{item}),
        .float => return error.UnsupportedWorkerJsonNumber,
        .number_string => |item| try output.appendSlice(allocator, item),
        .string => |item| {
            const encoded = try std.json.Stringify.valueAlloc(
                allocator,
                item,
                .{ .escape_unicode = true },
            );
            defer allocator.free(encoded);
            try output.appendSlice(allocator, encoded);
        },
        .array => |items| {
            try output.append(allocator, '[');
            for (items.items, 0..) |item, index| {
                if (index != 0) try output.append(allocator, ',');
                try appendCanonical(allocator, output, item, null);
            }
            try output.append(allocator, ']');
        },
        .object => |object_map| {
            const omitted_count: usize = if (omitted_object_key) |name|
                @intFromBool(object_map.contains(name))
            else
                0;
            const keys = try allocator.alloc(
                []const u8,
                object_map.count() - omitted_count,
            );
            defer allocator.free(keys);
            var at: usize = 0;
            var iterator = object_map.iterator();
            while (iterator.next()) |entry| {
                if (omitted_object_key) |name| {
                    if (std.mem.eql(u8, entry.key_ptr.*, name)) continue;
                }
                keys[at] = entry.key_ptr.*;
                at += 1;
            }
            std.mem.sort([]const u8, keys, {}, lessThanString);
            try output.append(allocator, '{');
            for (keys, 0..) |key, index| {
                if (index != 0) try output.append(allocator, ',');
                try appendCanonical(allocator, output, string(key), null);
                try output.append(allocator, ':');
                try appendCanonical(
                    allocator,
                    output,
                    object_map.get(key).?,
                    null,
                );
            }
            try output.append(allocator, '}');
        },
    }
}

fn lessThanString(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.order(u8, lhs, rhs) == .lt;
}
