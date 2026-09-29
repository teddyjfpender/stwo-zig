//! The `serde_json` text surface the circuit-recursion JSON formats share.
//!
//! `Writer` reproduces `serde_json::to_string` (compact) and
//! `serde_json::to_string_pretty` (two-space `PrettyFormatter`) byte for byte:
//! `"key": value` in pretty mode and `"key":value` in compact mode, one element
//! per line in pretty mode, `[]` and `{}` for empty containers, and serde_json's
//! string escapes (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, other control
//! bytes as lowercase `\u00xx`, everything else verbatim).
//!
//! The read side parses with `std.json` into a `Value` tree with numbers kept
//! as text, then extracts typed fields strictly: an unsigned integer is
//! decimal digits only (serde rejects a sign, fraction or exponent for an
//! unsigned field), required fields must be present, and fields a schema does
//! not name are ignored, as serde's derive does. Duplicate keys are rejected
//! (serde's derive rejects them for struct fields; for a map, where serde keeps
//! the last, rejecting is the fail-closed choice).

const std = @import("std");

pub const ReadError = error{
    /// The text is not JSON.
    InvalidJson,
    /// A required field is absent.
    MissingField,
    /// A value has the wrong JSON type or is out of range.
    InvalidValue,
} || std.mem.Allocator.Error;

pub const Parsed = std.json.Parsed(std.json.Value);

/// Parses `text` into a `Value` tree owned by the returned arena.
pub fn parse(allocator: std.mem.Allocator, text: []const u8) ReadError!Parsed {
    return std.json.parseFromSlice(std.json.Value, allocator, text, .{
        .parse_numbers = false,
        .duplicate_field_behavior = .@"error",
    }) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidJson,
    };
}

pub fn object(value: std.json.Value) ReadError!std.json.ObjectMap {
    return switch (value) {
        .object => |map| map,
        else => error.InvalidValue,
    };
}

pub fn array(value: std.json.Value) ReadError![]std.json.Value {
    return switch (value) {
        .array => |list| list.items,
        else => error.InvalidValue,
    };
}

pub fn string(value: std.json.Value) ReadError![]const u8 {
    return switch (value) {
        .string => |text| text,
        else => error.InvalidValue,
    };
}

pub fn boolean(value: std.json.Value) ReadError!bool {
    return switch (value) {
        .bool => |flag| flag,
        else => error.InvalidValue,
    };
}

/// An unsigned JSON integer that fits `T`.
pub fn unsigned(comptime T: type, value: std.json.Value) ReadError!T {
    const text = switch (value) {
        .number_string => |text| text,
        else => return error.InvalidValue,
    };
    if (text.len == 0) return error.InvalidValue;
    for (text) |char| if (!std.ascii.isDigit(char)) return error.InvalidValue;
    return std.fmt.parseInt(T, text, 10) catch error.InvalidValue;
}

pub fn field(map: std.json.ObjectMap, name: []const u8) ReadError!std.json.Value {
    return map.get(name) orelse error.MissingField;
}

/// A `serde_json` serializer over a `std.Io.Writer`.
pub const Writer = struct {
    out: *std.Io.Writer,
    pretty: bool,
    depth: usize = 0,
    /// Whether the innermost open container already holds a value.
    has_value: bool = false,
    /// Set between an object key and its value.
    after_key: bool = false,

    pub const Error = std.Io.Writer.Error;

    pub fn init(out: *std.Io.Writer, pretty: bool) Writer {
        return .{ .out = out, .pretty = pretty };
    }

    pub fn beginObject(self: *Writer) Error!void {
        try self.beginValue();
        try self.out.writeByte('{');
        self.open();
    }

    pub fn endObject(self: *Writer) Error!void {
        try self.close('}');
    }

    pub fn beginArray(self: *Writer) Error!void {
        try self.beginValue();
        try self.out.writeByte('[');
        self.open();
    }

    pub fn endArray(self: *Writer) Error!void {
        try self.close(']');
    }

    /// Writes an object key; the next value written is its value.
    pub fn key(self: *Writer, name: []const u8) Error!void {
        try self.separate();
        try writeString(self.out, name);
        try self.out.writeAll(if (self.pretty) ": " else ":");
        self.after_key = true;
    }

    pub fn stringValue(self: *Writer, text: []const u8) Error!void {
        try self.beginValue();
        try writeString(self.out, text);
    }

    /// Opens a string value whose content the caller streams to `out` and
    /// closes with `endVerbatimString`. The content must need no escaping
    /// (base64 text, for instance).
    pub fn beginVerbatimString(self: *Writer) Error!void {
        try self.beginValue();
        try self.out.writeByte('"');
    }

    pub fn endVerbatimString(self: *Writer) Error!void {
        try self.out.writeByte('"');
    }

    pub fn unsignedValue(self: *Writer, value: u64) Error!void {
        try self.beginValue();
        try self.out.print("{d}", .{value});
    }

    pub fn boolValue(self: *Writer, value: bool) Error!void {
        try self.beginValue();
        try self.out.writeAll(if (value) "true" else "false");
    }

    pub fn nullValue(self: *Writer) Error!void {
        try self.beginValue();
        try self.out.writeAll("null");
    }

    fn beginValue(self: *Writer) Error!void {
        if (self.after_key) {
            self.after_key = false;
            return;
        }
        if (self.depth != 0) try self.separate();
    }

    fn separate(self: *Writer) Error!void {
        if (self.has_value) try self.out.writeByte(',');
        if (self.pretty) {
            try self.out.writeByte('\n');
            try self.indent(self.depth);
        }
        self.has_value = true;
    }

    fn open(self: *Writer) void {
        self.depth += 1;
        self.has_value = false;
    }

    fn close(self: *Writer, bracket: u8) Error!void {
        std.debug.assert(self.depth != 0 and !self.after_key);
        self.depth -= 1;
        if (self.pretty and self.has_value) {
            try self.out.writeByte('\n');
            try self.indent(self.depth);
        }
        try self.out.writeByte(bracket);
        // The closed container is itself a value of its parent.
        self.has_value = true;
    }

    fn indent(self: *Writer, depth: usize) Error!void {
        for (0..depth) |_| try self.out.writeAll("  ");
    }
};

/// A JSON string literal with serde_json's escapes.
pub fn writeString(out: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    try out.writeByte('"');
    var start: usize = 0;
    for (text, 0..) |char, index| {
        const escape: ?[]const u8 = switch (char) {
            '"' => "\\\"",
            '\\' => "\\\\",
            0x08 => "\\b",
            0x0c => "\\f",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            else => null,
        };
        if (escape == null and char >= 0x20) continue;
        try out.writeAll(text[start..index]);
        if (escape) |sequence| {
            try out.writeAll(sequence);
        } else {
            try out.print("\\u{x:0>4}", .{char});
        }
        start = index + 1;
    }
    try out.writeAll(text[start..]);
    try out.writeByte('"');
}

fn render(storage: []u8, pretty: bool, comptime body: fn (*Writer) Writer.Error!void) ![]const u8 {
    var out = std.Io.Writer.fixed(storage);
    var writer = Writer.init(&out, pretty);
    try body(&writer);
    return out.buffered();
}

fn nestedDocument(writer: *Writer) Writer.Error!void {
    try writer.beginObject();
    try writer.key("a");
    try writer.unsignedValue(1);
    try writer.key("b");
    try writer.beginArray();
    try writer.stringValue("x");
    try writer.beginObject();
    try writer.key("c");
    try writer.boolValue(true);
    try writer.endObject();
    try writer.endArray();
    try writer.key("e");
    try writer.beginArray();
    try writer.endArray();
    try writer.key("f");
    try writer.nullValue();
    try writer.endObject();
}

test "json text: pretty and compact layouts match serde_json" {
    var storage: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        "{\n  \"a\": 1,\n  \"b\": [\n    \"x\",\n    {\n      \"c\": true\n    }\n  ],\n  \"e\": [],\n  \"f\": null\n}",
        try render(&storage, true, nestedDocument),
    );
    try std.testing.expectEqualStrings(
        "{\"a\":1,\"b\":[\"x\",{\"c\":true}],\"e\":[],\"f\":null}",
        try render(&storage, false, nestedDocument),
    );
}

test "json text: strings use serde_json escapes" {
    var storage: [64]u8 = undefined;
    var out = std.Io.Writer.fixed(&storage);
    try writeString(&out, "a\"\\\x08\x0c\n\r\t\x01\x1f\x7f\xc3\xa9");
    try std.testing.expectEqualStrings("\"a\\\"\\\\\\b\\f\\n\\r\\t\\u0001\\u001f\x7f\xc3\xa9\"", out.buffered());
}

test "json text: strict extraction rejects duplicates, signs and fractions" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidJson, parse(allocator, "{\"a\":1,\"a\":2}"));
    try std.testing.expectError(error.InvalidJson, parse(allocator, "{\"a\":"));

    var parsed = try parse(allocator, "{\"a\":7,\"b\":-1,\"c\":1.0,\"d\":4294967296,\"e\":\"s\"}");
    defer parsed.deinit();
    const map = try object(parsed.value);
    try std.testing.expectEqual(@as(u32, 7), try unsigned(u32, try field(map, "a")));
    try std.testing.expectError(error.InvalidValue, unsigned(u32, try field(map, "b")));
    try std.testing.expectError(error.InvalidValue, unsigned(u32, try field(map, "c")));
    try std.testing.expectError(error.InvalidValue, unsigned(u32, try field(map, "d")));
    try std.testing.expectError(error.InvalidValue, unsigned(u32, try field(map, "e")));
    try std.testing.expectError(error.MissingField, field(map, "z"));
}
