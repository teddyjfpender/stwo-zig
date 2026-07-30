//! Canonical compact AIR IR v2 serialization for every production opcode.
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
const opcode_manifest = @import("../../opcode_manifest.zig");

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
    return emitOpcode(allocator, writer, opcode_manifest.entries[LUI_MANIFEST_ID]);
}

/// Construct and serialize one manifest opcode into a caller-owned writer.
///
/// Multi-selector families share the exact same production program and
/// selector expression.  The manifest entry fixes which selector value this
/// artifact proves.
pub fn emitOpcode(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    opcode: opcode_manifest.Entry,
) !void {
    var arena = symbolic.Arena.init(allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    const program = try program_mod.build(&arena, opcode.family);
    try writeProgram(writer, &arena, &program, opcode);
}

pub fn writeLui(
    writer: *std.Io.Writer,
    arena: *const symbolic.Arena,
    program: program_mod.Program,
) !void {
    try writeProgram(
        writer,
        arena,
        &program,
        opcode_manifest.entries[LUI_MANIFEST_ID],
    );
}

pub fn writeProgram(
    writer: *std.Io.Writer,
    arena: *const symbolic.Arena,
    program: *const program_mod.Program,
    opcode: opcode_manifest.Entry,
) !void {
    if (program.family != opcode.family) return error.InvalidOpcodeFamily;
    var remap = try NodeRemap.init(arena, program);
    defer remap.deinit();
    // Top-level keys are lexicographically sorted. `content_digest` and
    // `source_identity` are deliberately absent from this unsigned body.
    try writer.print(
        "{{\"active_row\":{d},\"columns\":[",
        .{try remap.get(program.production.active_row.id)},
    );
    for (program.columnSlice(), 0..) |column, index| {
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
            .{ event_ordinal, try remap.get(root.id) },
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
            .{ try remap.get(lookup.numerator.id), event_ordinal },
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
            try writer.print("{d}", .{try remap.get(value.id)});
        }
        try writer.writeAll("]}");
        event_ordinal += 1;
    }

    try writer.writeAll("],\"family\":");
    try writeString(writer, @tagName(program.family));
    try writer.writeAll(",\"field\":{\"modulus\":");
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
    var compact_index: usize = 0;
    for (arena.nodes.items, 0..) |node, old_index| {
        if (remap.ids[old_index] == null) continue;
        if (compact_index != 0) try writer.writeByte(',');
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
                .{try remap.get(node.lhs)},
            ),
            .add, .sub, .mul => try writer.print(
                "{{\"args\":[{d},{d}],\"op\":\"{s}\"}}",
                .{
                    try remap.get(node.lhs),
                    try remap.get(node.rhs),
                    @tagName(node.op),
                },
            ),
        }
        compact_index += 1;
    }

    try writer.print(
        "],\"opcode_selector\":{{\"expression\":{d},\"manifest_id\":{d},\"mnemonic\":",
        .{
            try remap.get(program.opcode_selector),
            opcode.opcode.protocolId(),
        },
    );
    try writeString(writer, opcode.mnemonic);
    try writer.writeAll("},\"projection\":{\"destination_events\":[");
    for (program.projection.destinationSlice(), 0..) |ordinal, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("{d}", .{ordinal});
    }
    try writer.print(
        "],\"next_pc\":{d},\"program_event\":{d},\"source_events\":[",
        .{
            try remap.get(program.projection.next_pc),
            program.projection.program_event,
        },
    );
    for (program.projection.sourceSlice(), 0..) |ordinal, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("{d}", .{ordinal});
    }
    try writer.print(
        "],\"state_events\":[{d},{d}]}}",
        .{
            program.projection.state_events[0],
            program.projection.state_events[1],
        },
    );
    try writer.print(",\"schema_version\":{d}}}", .{SCHEMA_VERSION});
}

const NodeRemap = struct {
    allocator: std.mem.Allocator,
    ids: []?u32,

    fn init(
        arena: *const symbolic.Arena,
        program: *const program_mod.Program,
    ) !NodeRemap {
        const allocator = arena.allocator;
        const reached = try allocator.alloc(bool, arena.nodes.items.len);
        defer allocator.free(reached);
        @memset(reached, false);

        // Typed columns remain part of the wire contract even when a
        // selector-specific family path does not otherwise reference one.
        for (arena.nodes.items, 0..) |node, index| {
            if (node.op == .column) reached[index] = true;
        }
        try markReachable(arena, program.production.active_row.id, reached);
        try markReachable(arena, program.opcode_selector, reached);
        try markReachable(arena, program.projection.next_pc, reached);
        for (
            program.production.direct_constraints
                .values[0..program.production.direct_constraints.len],
        ) |root| try markReachable(arena, root.id, reached);
        for (
            program.production.lookup_entries
                .entries[0..program.production.lookup_entries.len],
        ) |lookup| {
            try markReachable(arena, lookup.numerator.id, reached);
            for (lookup.values[0..lookup.arity]) |value|
                try markReachable(arena, value.id, reached);
        }

        const ids = try allocator.alloc(?u32, arena.nodes.items.len);
        errdefer allocator.free(ids);
        @memset(ids, null);
        var next: u32 = 0;
        for (reached, 0..) |is_reached, old_index| {
            if (!is_reached) continue;
            ids[old_index] = next;
            next += 1;
        }
        return .{ .allocator = allocator, .ids = ids };
    }

    fn deinit(self: *NodeRemap) void {
        self.allocator.free(self.ids);
        self.* = undefined;
    }

    fn get(self: *const NodeRemap, old_id: u32) !u32 {
        if (old_id >= self.ids.len) return error.InvalidNodeReference;
        return self.ids[old_id] orelse error.InvalidNodeReference;
    }
};

fn markReachable(
    arena: *const symbolic.Arena,
    node_id: u32,
    reached: []bool,
) !void {
    if (node_id >= arena.nodes.items.len) return error.InvalidNodeReference;
    if (reached[node_id]) return;
    reached[node_id] = true;
    const node = arena.nodes.items[node_id];
    switch (node.op) {
        .constant, .column => {},
        .neg => try markReachable(arena, node.lhs, reached),
        .add, .sub, .mul => {
            try markReachable(arena, node.lhs, reached);
            try markReachable(arena, node.rhs, reached);
        },
    }
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
    for (columns, program.columnSlice(), 0..) |column_value, expected, index| {
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

test "AIR IR v2 serializes every manifest opcode from its production family" {
    const allocator = std.testing.allocator;
    for (opcode_manifest.entries) |opcode| {
        var arena = symbolic.Arena.init(allocator);
        defer arena.deinit();
        symbolic.begin(&arena);
        defer symbolic.end();

        const program = try program_mod.build(&arena, opcode.family);
        var remap = try NodeRemap.init(&arena, &program);
        defer remap.deinit();
        var text = std.Io.Writer.Allocating.init(allocator);
        defer text.deinit();
        try writeProgram(&text.writer, &arena, &program, opcode);

        const parsed = try std.json.parseFromSlice(
            std.json.Value,
            allocator,
            text.written(),
            .{},
        );
        defer parsed.deinit();
        const object = parsed.value.object;
        try std.testing.expectEqualStrings(
            @tagName(opcode.family),
            object.get("family").?.string,
        );
        const selector = object.get("opcode_selector").?.object;
        try std.testing.expectEqual(
            @as(i64, opcode.opcode.protocolId()),
            selector.get("manifest_id").?.integer,
        );
        try std.testing.expectEqualStrings(
            opcode.mnemonic,
            selector.get("mnemonic").?.string,
        );
        try std.testing.expectEqual(
            @as(i64, try remap.get(program.opcode_selector)),
            selector.get("expression").?.integer,
        );
    }
}
