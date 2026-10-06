//! Value-independent row-11 fixed columns from an admitted canonical V2 wire
//! shape. A verifier selects four section counts before child proof admission;
//! this writer derives every section offset rather than adopting a wire view.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const wire = @import("segment_statement_v2.zig");
const span = @import("span_statement.zig");
const register_bytes = @import("segment_register_byte_layout_v1.zig");
const source = @import("segment_statement_outer_source_v2.zig");
const source_rows = @import("segment_statement_outer_source_v2_prepared_v2.zig");
const boundary = @import("segment_leaf_authority_v2.zig");
const framework = @import("air/framework_interaction.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const ROW: u8 = 11;
pub const COLUMN_COUNT = source.Air.PREPROCESSED_COLUMN_COUNT;

pub const WireShapeV6 = struct {
    /// Entry/exit sparse state, then entry/exit predecessor clocks.
    counts: [4]u32,
    sections: [4]wire.RetainedSectionV2,
    word_count: usize,
    log_size: u32,

    pub fn init(counts: [4]u32) !WireShapeV6 {
        var at: usize = wire.FIXED_CANONICAL_WORDS;
        var sections: [4]wire.RetainedSectionV2 = undefined;
        for (counts, &sections) |count, *section| {
            if (count > wire.MAX_SPARSE_BOUNDARY_ENTRIES)
                return error.InvalidWireShapeV6;
            at = try std.math.add(usize, at, wire.SECTION_HEADER_WORDS);
            section.* = .{ .payload_start = at, .count = count };
            at = try std.math.add(usize, at, try std.math.mul(usize, count, wire.RETAINED_ENTRY_WORDS));
        }
        const logical = try std.math.add(usize, at, 8 + boundary.CONTEXT_WORD_COUNT);
        const log_size: u32 = @intCast(std.math.log2_int_ceil(usize, logical));
        if (log_size >= 31 or at >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidWireShapeV6;
        return .{ .counts = counts, .sections = sections, .word_count = at, .log_size = log_size };
    }

    pub fn validate(self: WireShapeV6) !void {
        const rebuilt = try init(self.counts);
        if (!std.meta.eql(self, rebuilt)) return error.InvalidWireShapeV6;
    }

    /// This is a comparison against a freshly authenticated native wire, not
    /// the constructor for the independently expected shape.
    pub fn validateAgainstView(self: WireShapeV6, view: *const wire.CanonicalWireViewV2) !void {
        try self.validate();
        if (view.words.len != self.word_count or
            !std.meta.eql(view.entry_snapshot, self.sections[0]) or
            !std.meta.eql(view.exit_snapshot, self.sections[1]) or
            !std.meta.eql(view.entry_memory_clocks, self.sections[2]) or
            !std.meta.eql(view.exit_memory_clocks, self.sections[3]))
            return error.WireShapeMismatchV6;
    }

    pub fn writePhysical(self: WireShapeV6, columns: [][]M31) !void {
        try self.validate();
        if (columns.len != COLUMN_COUNT) return error.Row11GeometryMismatchV6;
        const capacity = @as(usize, 1) << @intCast(self.log_size);
        for (columns) |column| {
            if (column.len != capacity) return error.Row11GeometryMismatchV6;
            for (column) |value| if (!value.isZero()) return error.Row11DestinationNotFreshV6;
        }
        const zero_context = [_]M31{M31.zero()} ** boundary.CONTEXT_WORD_COUNT;
        const zero_id = [_]u32{0} ** 8;
        for (0..8) |index| put(columns, self.log_size, index, (try source_rows.headerRow(self.word_count, index)).preprocessing);
        for (0..self.word_count) |index| put(columns, self.log_size, 8 + index, self.wireRow(index));
        for (0..boundary.CONTEXT_WORD_COUNT) |index| put(columns, self.log_size, 8 + self.word_count + index, source_rows.contextRow(&zero_context, zero_id, index).preprocessing);
    }

    fn wireRow(self: WireShapeV6, index: usize) source.PreprocessedRowV2 {
        const is_u16 = self.wireWordIsU16(index);
        const memory = register_bytes.MemoryLayout{ .entry = self.sections[0], .exit = self.sections[1] };
        const memory_byte = memory.firstByteIndexForWireWord(index);
        const register_byte = register_bytes.firstByteIndexForWireWord(index) orelse memory_byte;
        return .{
            .row_mask = 1,
            .source_mask = 1,
            .verifier_a_mask = 1,
            .verifier_b_mask = 0,
            .header_mask = 0,
            .recombine_mask = 0,
            .source_u16_mask = @intFromBool(is_u16),
            .verifier_a_u16_mask = 0,
            .verifier_b_u16_mask = 0,
            .source_scope = boundary.WIRE_SCOPE,
            .source_index = @intCast(index),
            .verifier_item = source.Air.WIRE_WORD_ITEM,
            .verifier_a_index = @intCast(index),
            .verifier_b_index = 0,
            .expected_header = 0,
            .boundary_bridge_mask = 1,
            .register_byte_bridge_mask = @intFromBool(register_byte != null),
            .register_low_byte_index = if (register_byte) |byte| @intCast(self.word_count + byte) else 0,
            .register_high_byte_index = if (register_byte) |byte| @intCast(self.word_count + byte + 1) else 0,
            .memory_byte_bridge_mask = @intFromBool(memory_byte != null),
            .memory_low_selector_index = if (memory_byte) |byte| @intCast(self.word_count + memory.selectorIndex(byte)) else 0,
            .memory_high_selector_index = if (memory_byte) |byte| @intCast(self.word_count + memory.selectorIndex(byte + 1)) else 0,
        };
    }

    fn wireWordIsU16(self: WireShapeV6, index: usize) bool {
        if (index == wire.fixed_layout.format_version or
            index == wire.fixed_layout.schema_version or
            index == wire.fixed_layout.flags) return true;
        const base = wire.fixed_layout.base_statement;
        if (inRange(index, base, span.SPAN_STATEMENT_CANONICAL_WORDS))
            return span.isIntegerWord(index - base);
        inline for (.{
            .{ wire.fixed_layout.entry_snapshot_count, 4 },
            .{ wire.fixed_layout.exit_snapshot_count, 4 },
            .{ wire.fixed_layout.entry_memory_clock_count, 2 },
            .{ wire.fixed_layout.exit_memory_clock_count, 2 },
            .{ wire.fixed_layout.entry_register_clocks, 64 },
            .{ wire.fixed_layout.exit_register_clocks, 64 },
            .{ wire.fixed_layout.completion + 2, 6 },
        }) |range| if (inRange(index, range[0], range[1])) return true;
        for (self.sections) |section| {
            const header = section.payload_start - wire.SECTION_HEADER_WORDS;
            if (inRange(index, header + 1, 2) or
                inRange(index, section.payload_start, @as(usize, section.count) * wire.RETAINED_ENTRY_WORDS)) return true;
        }
        return false;
    }
};

fn inRange(index: usize, start: usize, len: usize) bool {
    return index >= start and index - start < len;
}

fn put(columns: [][]M31, log_size: u32, logical: usize, row: source.PreprocessedRowV2) void {
    const physical = framework.committedRow(logical, log_size);
    const values = row.values();
    for (values, columns) |value, column| column[physical] = value;
}

test "V6 row11 fixed columns match two distinct canonical wires of one shape" {
    const allocator = std.testing.allocator;
    const support = @import("../air/public_data_v2_test_support.zig");
    const expected = try WireShapeV6.init(.{ 1, 1, 0, 1 });
    var first_id: ?wire.Digest = null;
    for ([_]u32{ 0, 0x1234 }) |register_value| {
        var fixture = try support.Fixture.initWithRegister7(register_value);
        const native = fixture.leftSource();
        const words = try support.encode(allocator, &native);
        defer allocator.free(words);
        const view = try wire.authenticateCanonicalWire(words);
        try expected.validateAgainstView(&view);
        if (first_id) |id| try std.testing.expect(!std.meta.eql(id, view.wire_id)) else first_id = view.wire_id;
        const capacity = @as(usize, 1) << @intCast(expected.log_size);
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const columns = try a.alloc([]M31, COLUMN_COUNT);
        for (columns) |*column| {
            column.* = try a.alloc(M31, capacity);
            @memset(column.*, M31.zero());
        }
        try expected.writePhysical(columns);
        const zero_context = [_]M31{M31.zero()} ** boundary.CONTEXT_WORD_COUNT;
        for (0..8 + view.words.len + boundary.CONTEXT_WORD_COUNT) |logical| {
            const original = try source_rows.rowAt(&view, &zero_context, logical, @intCast(8 + view.words.len + boundary.CONTEXT_WORD_COUNT));
            const values = original.preprocessing.values();
            const physical = framework.committedRow(logical, expected.log_size);
            for (values, columns) |value, column| try std.testing.expectEqual(value.toU32(), column[physical].toU32());
        }
        for (8 + view.words.len + boundary.CONTEXT_WORD_COUNT..capacity) |logical| {
            const physical = framework.committedRow(logical, expected.log_size);
            for (columns) |column| try std.testing.expect(column[physical].isZero());
        }
        var changed = expected;
        changed.sections[1].payload_start += 1;
        try std.testing.expectError(error.InvalidWireShapeV6, changed.validate());
        const other_shape = try WireShapeV6.init(.{ 1, 2, 0, 1 });
        try std.testing.expectError(error.WireShapeMismatchV6, other_shape.validateAgainstView(&view));
        columns[0][0] = M31.one();
        try std.testing.expectError(error.Row11DestinationNotFreshV6, expected.writePhysical(columns));
    }
}
