//! Stable, source-attributed diagnostics for typed AIR authoring and lowering.
//!
//! Rendering is explicit rather than reflection-based so enum renames, native
//! layouts, allocator addresses, and formatter implementation details do not
//! leak into golden diagnostics.

const std = @import("std");
const degree = @import("degree.zig");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const Severity = enum(u8) {
    @"error",
    warning,
    note,
};

pub const Code = enum(u16) {
    validation_failed = 1,
    type_mismatch = 2,
    degree_exceeded = 3,
    unbound_hint_output = 4,
    invalid_relation_event = 5,
    lowering_failed = 6,
};

pub const TypeContext = struct {
    expected: types.Type,
    actual: types.Type,
};

pub const DegreeContext = struct {
    expression: degree.Degree,
    gate: ?degree.Degree,
    total: degree.Degree,
    limit: ?degree.Degree,
};

pub const Diagnostic = struct {
    severity: Severity = .@"error",
    code: Code,
    component: []const u8,
    message: []const u8,
    source_span: source.SourceSpan = source.SourceSpan.generated(),
    value_path: []const types.ValueId = &.{},
    type_context: ?TypeContext = null,
    degree_context: ?DegreeContext = null,
};

pub fn render(
    writer: anytype,
    arena: *const ir.Arena,
    analysis: ?*const degree.Analysis,
    item: Diagnostic,
) !void {
    try writer.writeAll(severityName(item.severity));
    try writer.print("[{s} {s}] component=", .{
        codeId(item.code),
        codeName(item.code),
    });
    try writeQuoted(writer, item.component);
    try writer.writeAll(" source=");
    try writeSpan(writer, arena, item.source_span);
    try writer.writeByte('\n');

    try writer.writeAll("  message=");
    try writeQuoted(writer, item.message);
    try writer.writeByte('\n');

    try writer.writeAll("  value_path=");
    if (item.value_path.len == 0) {
        try writer.writeAll("<none>");
    } else {
        for (item.value_path, 0..) |value_id, index| {
            if (index != 0) try writer.writeAll(" -> ");
            try writer.print("%{d}:", .{@intFromEnum(value_id)});
            if (arena.node(value_id)) |node| {
                try writeType(writer, node.key.ty);
            } else {
                try writer.writeAll("<invalid>");
            }
            try writer.writeAll("@degree=");
            if (analysis) |available| {
                if (available.value(value_id)) |value_degree| {
                    try writer.print("{d}", .{value_degree});
                } else {
                    try writer.writeByte('?');
                }
            } else {
                try writer.writeByte('?');
            }
        }
    }
    try writer.writeByte('\n');

    try writer.writeAll("  type=");
    if (item.type_context) |context| {
        try writer.writeAll("expected:");
        try writeType(writer, context.expected);
        try writer.writeAll(" actual:");
        try writeType(writer, context.actual);
    } else {
        try writer.writeAll("<none>");
    }
    try writer.writeByte('\n');

    try writer.writeAll("  degree=");
    if (item.degree_context) |context| {
        try writer.print("expression:{d} gate:", .{context.expression});
        if (context.gate) |gate| {
            try writer.print("{d}", .{gate});
        } else {
            try writer.writeAll("<none>");
        }
        try writer.print(" total:{d} limit:", .{context.total});
        if (context.limit) |limit| {
            try writer.print("{d}", .{limit});
        } else {
            try writer.writeAll("<none>");
        }
    } else {
        try writer.writeAll("<none>");
    }
    try writer.writeByte('\n');
}

pub fn renderAlloc(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    analysis: ?*const degree.Analysis,
    item: Diagnostic,
) std.mem.Allocator.Error![]u8 {
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    render(output.writer(allocator), arena, analysis, item) catch
        return error.OutOfMemory;
    return output.toOwnedSlice(allocator);
}

pub fn codeId(code: Code) []const u8 {
    return switch (code) {
        .validation_failed => "AIR0001",
        .type_mismatch => "AIR0002",
        .degree_exceeded => "AIR0003",
        .unbound_hint_output => "AIR0004",
        .invalid_relation_event => "AIR0005",
        .lowering_failed => "AIR0006",
    };
}

pub fn codeName(code: Code) []const u8 {
    return switch (code) {
        .validation_failed => "validation_failed",
        .type_mismatch => "type_mismatch",
        .degree_exceeded => "degree_exceeded",
        .unbound_hint_output => "unbound_hint_output",
        .invalid_relation_event => "invalid_relation_event",
        .lowering_failed => "lowering_failed",
    };
}

fn severityName(severity: Severity) []const u8 {
    return switch (severity) {
        .@"error" => "error",
        .warning => "warning",
        .note => "note",
    };
}

fn writeSpan(
    writer: anytype,
    arena: *const ir.Arena,
    span: source.SourceSpan,
) !void {
    const source_id = span.source orelse {
        try writer.writeAll("<generated>");
        return;
    };
    const path = arena.sourcePath(source_id) orelse {
        try writer.print("<invalid-source:%{d}>", .{@intFromEnum(source_id)});
        return;
    };
    try writeQuoted(writer, path);
    try writer.print(":{d}:{d}@{d}-{d}:{d}@{d}", .{
        span.start.line,
        span.start.column,
        span.start.byte_offset,
        span.end.line,
        span.end.column,
        span.end.byte_offset,
    });
}

fn writeType(writer: anytype, ty: types.Type) !void {
    switch (ty) {
        .felt => try writer.writeAll("felt"),
        .bit => try writer.writeAll("bit"),
        .byte => try writer.writeAll("byte"),
        .uint16 => try writer.writeAll("uint16"),
        .uint20 => try writer.writeAll("uint20"),
        .word32 => try writer.writeAll("word32"),
        .register_index => try writer.writeAll("register_index"),
        .address => try writer.writeAll("address"),
        .pc => try writer.writeAll("pc"),
        .clock => try writer.writeAll("clock"),
        .selector => try writer.writeAll("selector"),
        .bounded_uint => |bounded| {
            try writer.print("bounded_uint(bits={d},representation=", .{bounded.bits});
            switch (bounded.representation) {
                .canonical_field => try writer.writeAll("canonical_field)"),
                .little_endian_limbs => |layout| try writer.print(
                    "little_endian_limbs(limb_bits={d},limb_count={d}))",
                    .{ layout.limb_bits, layout.limb_count },
                ),
            }
        },
        .array => |array| try writer.print("array(element={s},len={d})", .{
            arrayElementName(array.element),
            array.len,
        }),
    }
}

fn arrayElementName(element: types.ArrayElement) []const u8 {
    return switch (element) {
        .felt => "felt",
        .bit => "bit",
        .byte => "byte",
        .uint16 => "uint16",
        .uint20 => "uint20",
        .word32 => "word32",
        .register_index => "register_index",
        .address => "address",
        .pc => "pc",
        .clock => "clock",
        .selector => "selector",
    };
}

fn writeQuoted(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| switch (byte) {
        '\\' => try writer.writeAll("\\\\"),
        '"' => try writer.writeAll("\\\""),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0...0x08, 0x0b...0x0c, 0x0e...0x1f, 0x7f => try writer.print("\\x{x:0>2}", .{byte}),
        else => try writer.writeByte(byte),
    };
    try writer.writeByte('"');
}
