//! Canonical compact AIR IR v2 serialization for the LUI vertical slice.
//!
//! This writer emits the unsigned semantic object.  Python packaging adds the
//! sorted `source_identity` closure and `content_digest`; neither is fabricated
//! by Zig.  All remaining keys are emitted in lexicographic order with compact
//! separators and no trailing newline, matching `codec.canonical_bytes`.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const constraint_program = @import("../constraint_program.zig");
const entry = @import("../lookups/entry.zig");
const table_schema = @import("../lookups/tables/schema.zig");
const program_mod = @import("program.zig");
const symbolic = @import("symbolic.zig");

pub const SCHEMA_VERSION: u32 = 2;
pub const KIND = "stwo-riscv-air-constraint-program";
pub const LUI_MANIFEST_ID: u32 = 35;
pub const LUI_MNEMONIC = "lui";
pub const LOOKUP_LIVENESS = "nonzero_numerator";

pub const Error = error{NonAsciiString};

/// Construct and serialize LUI into a caller-owned writer.
///
/// Output is the compact unsigned semantic body, with no trailing newline.
pub fn emitLui(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
) !void {
    var arena = symbolic.Arena.init(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    const program = try program_mod.buildLui(&arena);
    try writeLui(writer, &arena, program);
}

pub fn writeLui(
    writer: *std.Io.Writer,
    arena: *const symbolic.Arena,
    program: program_mod.LuiProgram,
) !void {
    // Top-level keys are lexicographically sorted. `content_digest` and
    // `source_identity` are deliberately absent from this unsigned body.
    try writer.print("{{\"active_row\":{d},\"columns\":[", .{program.production.active_row.id});
    for (program.columns, 0..) |column, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("{{\"index\":{d},\"name\":", .{column.index});
        try writeString(writer, column.name);
        try writer.writeAll(",\"role\":");
        try writeString(writer, @tagName(column.role));
        try writer.writeAll(",\"type\":\"m31\",\"width\":1}");
    }

    try writer.writeAll("],\"events\":[");
    var event_ordinal: usize = 0;
    for (
        program.production.direct_constraints.values[0..program.production.direct_constraints.len],
    ) |root| {
        if (event_ordinal != 0) try writer.writeByte(',');
        try writer.print(
            "{{\"kind\":\"constraint\",\"ordinal\":{d},\"root\":{d}}}",
            .{ event_ordinal, root.id },
        );
        event_ordinal += 1;
    }
    for (
        program.production.lookup_entries.entries[0..program.production.lookup_entries.len],
    ) |lookup| {
        if (event_ordinal != 0) try writer.writeByte(',');
        try writer.writeAll("{\"access_ordinal\":");
        if (lookup.access_ordinal) |ordinal|
            try writer.print("{d}", .{ordinal})
        else
            try writer.writeAll("null");
        try writer.writeAll(",\"domain\":");
        try writeString(writer, @tagName(lookup.domain));
        try writer.writeAll(",\"kind\":\"lookup\",\"liveness\":\"");
        try writer.writeAll(LOOKUP_LIVENESS);
        try writer.print(
            "\",\"numerator\":{d},\"ordinal\":{d},\"role\":",
            .{ lookup.numerator.id, event_ordinal },
        );
        try writeString(writer, @tagName(lookup.role));
        try writer.writeAll(",\"table_id\":");
        if (fixedTableId(lookup.domain)) |table_id|
            try writeString(writer, table_id)
        else
            try writer.writeAll("null");
        try writer.writeAll(",\"tuple\":[");
        for (lookup.values[0..lookup.arity], 0..) |value, tuple_index| {
            if (tuple_index != 0) try writer.writeByte(',');
            try writer.print("{d}", .{value.id});
        }
        try writer.writeAll("]}");
        event_ordinal += 1;
    }

    try writer.writeAll("],\"family\":\"lui\",\"field\":{\"modulus\":");
    try writer.print("{d}", .{M31_MODULUS});
    try writer.writeAll(",\"name\":\"M31\"},\"fixed_tables\":[");
    for (0..table_schema.KIND_COUNT) |index| {
        if (index != 0) try writer.writeByte(',');
        const kind: table_schema.Kind = @enumFromInt(index);
        const table_id = @tagName(kind);
        try writer.print("{{\"arity\":{d},\"domain\":", .{table_schema.arity(kind)});
        try writeString(writer, table_id);
        try writer.writeAll(",\"id\":");
        try writeString(writer, table_id);
        try writer.print(
            ",\"log_size\":{d},\"schema_sha256\":",
            .{table_schema.logSize(kind)},
        );
        try writeString(writer, tableSchemaDigest(kind));
        try writer.writeByte('}');
    }

    try writer.writeAll("],\"kind\":");
    try writeString(writer, KIND);
    try writer.writeAll(",\"nodes\":[");
    for (arena.nodes.items, 0..) |node, index| {
        if (index != 0) try writer.writeByte(',');
        switch (node.op) {
            .constant => try writer.print(
                "{{\"op\":\"const\",\"value\":{d}}}",
                .{node.value},
            ),
            .column => try writer.print(
                "{{\"column\":{d},\"op\":\"col\"}}",
                .{node.value},
            ),
            .neg => try writer.print(
                "{{\"args\":[{d}],\"op\":\"neg\"}}",
                .{node.lhs},
            ),
            .add, .sub, .mul => try writer.print(
                "{{\"args\":[{d},{d}],\"op\":\"{s}\"}}",
                .{ node.lhs, node.rhs, @tagName(node.op) },
            ),
        }
    }

    try writer.print(
        "],\"opcode_selector\":{{\"expression\":{d},\"manifest_id\":{d},\"mnemonic\":\"{s}\"}}",
        .{ program.opcode_selector, LUI_MANIFEST_ID, LUI_MNEMONIC },
    );
    try writer.print(
        ",\"projection\":{{\"destination_events\":[{d},{d}],\"next_pc\":{d},\"program_event\":{d},\"source_events\":[],\"state_events\":[{d},{d}]}}",
        .{
            program.projection.destination_events[0],
            program.projection.destination_events[1],
            program.projection.next_pc,
            program.projection.program_event,
            program.projection.state_events[0],
            program.projection.state_events[1],
        },
    );
    try writer.print(",\"schema_version\":{d}}}", .{SCHEMA_VERSION});
}

fn fixedTableId(domain: entry.Domain) ?[]const u8 {
    return switch (domain) {
        .bitwise,
        .range_check_20,
        .range_check_8_11,
        .range_check_8_8_4,
        .range_check_8_8,
        .range_check_m31,
        => @tagName(domain),
        else => null,
    };
}

fn tableSchemaDigest(kind: table_schema.Kind) []const u8 {
    return switch (kind) {
        .bitwise => "7de3a5c8de009b1f2d9da74ce88f02b3705c26da488d0005d0c67b07b9a6daab",
        .range_check_20 => "618f993093152e26cd08fc37b4ddc942a7a7e998444ee2e34d433d42667613e0",
        .range_check_8_11 => "1fa99606e17949d62271f75ad3ecfdb68bc016dadaa1995579d8831417ab8976",
        .range_check_8_8_4 => "c5894ccdf667ad77987691500806fbdb7f93b91fa40672785465e41fb393e1df",
        .range_check_8_8 => "74691adaef966cf81ce717e97fc298c8272958c614327b87aee9dafea79c5102",
        .range_check_m31 => "bf4f031af4d434f3d9ad028c3b8976822499b3f3cdfe81be0933e45baafd674d",
    };
}

fn writeString(writer: *std.Io.Writer, text: []const u8) !void {
    try writer.writeByte('"');
    for (text) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        0x08 => try writer.writeAll("\\b"),
        0x0c => try writer.writeAll("\\f"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0x00...0x07, 0x0b, 0x0e...0x1f => {
            const hex = "0123456789abcdef";
            try writer.writeAll("\\u00");
            try writer.writeByte(hex[byte >> 4]);
            try writer.writeByte(hex[byte & 0xf]);
        },
        0x20...0x21, 0x23...0x5b, 0x5d...0x7f => try writer.writeByte(byte),
        else => return error.NonAsciiString,
    };
    try writer.writeByte('"');
}

test "AIR IR v2 LUI JSON is canonical, exact, and production-differential" {
    const allocator = std.testing.allocator;
    var arena = symbolic.Arena.init(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    const program = try program_mod.buildLui(&arena);
    var text = std.Io.Writer.Allocating.init(allocator);
    defer text.deinit();
    try writeLui(&text.writer, &arena, program);
    const encoded = text.written();

    try std.testing.expect(encoded.len > 0);
    try std.testing.expectEqual(@as(u8, '{'), encoded[0]);
    try std.testing.expectEqual(@as(u8, '}'), encoded[encoded.len - 1]);
    try std.testing.expect(std.mem.startsWith(u8, encoded, "{\"active_row\":"));
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\n") == null);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqual(@as(usize, 11), object.count());
    try std.testing.expect(object.get("source_identity") == null);
    try std.testing.expect(object.get("content_digest") == null);
    try std.testing.expectEqualStrings("lui", object.get("family").?.string);

    const columns = object.get("columns").?.array.items;
    try std.testing.expectEqual(program_mod.LUI_COLUMN_COUNT, columns.len);
    for (columns, program.columns, 0..) |column_value, expected, index| {
        const column = column_value.object;
        try std.testing.expectEqual(@as(i64, @intCast(index)), column.get("index").?.integer);
        try std.testing.expectEqualStrings(expected.name, column.get("name").?.string);
        try std.testing.expectEqualStrings(@tagName(expected.role), column.get("role").?.string);
        try std.testing.expect(!std.mem.startsWith(u8, column.get("name").?.string, "bus_value_"));
    }

    const events = object.get("events").?.array.items;
    try std.testing.expectEqual(
        program_mod.LUI_DIRECT_CONSTRAINT_COUNT + program_mod.LUI_LOOKUP_COUNT,
        events.len,
    );
    for (
        events[0..program_mod.LUI_DIRECT_CONSTRAINT_COUNT],
        program.production.direct_constraints.values[0..program.production.direct_constraints.len],
        0..,
    ) |event_value, expected, ordinal| {
        const event = event_value.object;
        try std.testing.expectEqualStrings("constraint", event.get("kind").?.string);
        try std.testing.expectEqual(@as(i64, @intCast(ordinal)), event.get("ordinal").?.integer);
        try std.testing.expectEqual(@as(i64, expected.id), event.get("root").?.integer);
    }
    for (
        events[program_mod.LUI_DIRECT_CONSTRAINT_COUNT..],
        program.production.lookup_entries.entries[0..program.production.lookup_entries.len],
        0..,
    ) |event_value, expected, lookup_index| {
        const event = event_value.object;
        try std.testing.expectEqualStrings("lookup", event.get("kind").?.string);
        try std.testing.expectEqualStrings(@tagName(expected.domain), event.get("domain").?.string);
        try std.testing.expectEqualStrings(@tagName(expected.role), event.get("role").?.string);
        const access = event.get("access_ordinal").?;
        if (expected.access_ordinal) |ordinal|
            try std.testing.expectEqual(@as(i64, ordinal), access.integer)
        else
            try std.testing.expect(access == .null);
        try std.testing.expectEqual(
            @as(i64, @intCast(program_mod.LUI_DIRECT_CONSTRAINT_COUNT + lookup_index)),
            event.get("ordinal").?.integer,
        );
        try std.testing.expectEqual(@as(i64, expected.numerator.id), event.get("numerator").?.integer);
        const tuple = event.get("tuple").?.array.items;
        try std.testing.expectEqual(@as(usize, expected.arity), tuple.len);
        for (tuple, expected.values[0..expected.arity]) |node, value|
            try std.testing.expectEqual(@as(i64, value.id), node.integer);
    }

    // Replay the serialized node IDs on concrete values and compare every
    // root/event with a fresh QM31 construction of the shared production path.
    var base_columns: [program_mod.LUI_COLUMN_COUNT]M31 = undefined;
    var secure_columns: [program_mod.LUI_COLUMN_COUNT]QM31 = undefined;
    for (&base_columns, &secure_columns, 0..) |*base, *secure, index| {
        base.* = M31.fromU64(index * 10_007 + 97);
        secure.* = QM31.fromBase(base.*);
    }
    const replayed = try allocator.alloc(M31, arena.nodes.items.len);
    defer allocator.free(replayed);
    symbolic.replay(&arena, &base_columns, replayed);

    const Concrete = constraint_program.Builder(QM31);
    const concrete = try Concrete.build(.lui, &secure_columns, QM31.one());
    for (
        concrete.direct_constraints.values[0..concrete.direct_constraints.len],
        program.production.direct_constraints.values[0..program.production.direct_constraints.len],
    ) |expected, root|
        try std.testing.expect(expected.eql(QM31.fromBase(replayed[root.id])));
    for (
        concrete.lookup_entries.entries[0..concrete.lookup_entries.len],
        program.production.lookup_entries.entries[0..program.production.lookup_entries.len],
    ) |expected, symbolic_entry| {
        try std.testing.expectEqual(expected.domain, symbolic_entry.domain);
        try std.testing.expectEqual(expected.role, symbolic_entry.role);
        try std.testing.expectEqual(expected.access_ordinal, symbolic_entry.access_ordinal);
        try std.testing.expect(expected.numerator.eql(
            QM31.fromBase(replayed[symbolic_entry.numerator.id]),
        ));
        for (
            expected.values[0..expected.arity],
            symbolic_entry.values[0..symbolic_entry.arity],
        ) |expected_value, symbolic_value|
            try std.testing.expect(expected_value.eql(
                QM31.fromBase(replayed[symbolic_value.id]),
            ));
    }
}
