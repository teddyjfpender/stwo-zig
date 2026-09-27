//! Statement-bound input producers for native public-boundary arithmetic.
//! Public values deliberately remain in preprocessing until reusable-key binding.
const std = @import("std");
const core = @import("stwo_core");
const statement = @import("../../air/statement_v2.zig");
const bytes = @import("../segment_register_byte_layout_v1.zig");
const public = @import("blake3_native_public_boundary.zig");
const transcript_mod = @import("blake3_native_transcript.zig");
const recorder = @import("blake3_native_recorder.zig");
const boundary = @import("blake3_boundary.zig");
const scalar = @import("scalar_wire_source.zig");
const CIRCUIT = @import("blake3_native_public_links.zig").BOUNDARY_CIRCUIT;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const Columns = @import("blake3_upstream_source_columns_v1.zig").ForSlots(.{ 2, 12 });
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    rows: []boundary.Row,
    fixed_rows: []boundary.Row,
    sums: []scalar.Row,
    fixed_sums: []scalar.Row,
    columns: ?Columns = null,
    statement_operation: usize,
    pub fn deinit(self: *Prepared) void {
        if (self.columns) |*columns| columns.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn appendSums(self: *const Prepared, b: anytype) !void {
        if (self.columns) |*columns| {
            if (self.sums.len != 0 or self.fixed_sums.len != 0) return error.InvalidNativePublicSource;
            try columns.appendTo(12, b);
        } else try b.append(12, self.sums, self.fixed_sums);
    }
    pub fn appendCoordinates(self: *const Prepared, b: anytype) !void {
        if (self.columns) |*columns| {
            if (self.rows.len != 0 or self.fixed_rows.len != 0) return error.InvalidNativePublicSource;
            try columns.appendTo(2, b);
        } else try b.append(2, self.rows, self.fixed_rows);
    }
};
pub fn prepare(a: std.mem.Allocator, statement_value: *const statement.RiscVStatementV2, config: core.pcs.PcsConfig, transcript: *const transcript_mod.Prepared, inputs: *const public.Prepared) !Prepared {
    return prepareMode(true, a, statement_value, config, transcript, inputs);
}
/// Explicit dense-source parity oracle.
pub fn prepareRows(a: std.mem.Allocator, statement_value: *const statement.RiscVStatementV2, config: core.pcs.PcsConfig, transcript: *const transcript_mod.Prepared, inputs: *const public.Prepared) !Prepared {
    return prepareMode(false, a, statement_value, config, transcript, inputs);
}
fn prepareMode(comptime direct: bool, a: std.mem.Allocator, statement_value: *const statement.RiscVStatementV2, config: core.pcs.PcsConfig, transcript: *const transcript_mod.Prepared, inputs: *const public.Prepared) !Prepared {
    try inputs.validate(a);
    try transcript.plan.validate();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    const temp = scratch.allocator();
    const output = arena.allocator();
    // Invoke the authoritative encoder to determine both position and content.
    var replay = recorder.Recorder{ .a = temp };
    config.mixInto(&replay);
    const start = replay.operations.items.len;
    try statement.mixIntoNativeTranscript(&statement_value.public_data, &replay);
    try replay.check();
    if (replay.operations.items.len != start + 3 or transcript.operations.len < replay.operations.items.len) return error.InvalidNativePublicSource;
    for (replay.operations.items[start..], transcript.operations[start..replay.operations.items.len]) |expected, actual| {
        if (expected != .words or actual != .words or !std.mem.eql(u32, expected.words, actual.words)) return error.InvalidNativePublicSource;
    }
    const view = try statement_value.public_data.authenticatedView();
    const layout = try bytes.MemoryLayout.init(&view);
    if (inputs.wire_count != view.words.len or inputs.memory_byte_count != layout.memoryByteCount()) return error.InvalidNativePublicSource;
    const count = try std.math.add(usize, try std.math.add(usize, view.words.len, bytes.BYTE_COUNT), try std.math.mul(usize, 2, layout.memoryByteCount()));
    var columns: ?Columns = null;
    errdefer if (columns) |*owned| owned.deinit();
    if (direct) columns = try Columns.init(a, .{ count, 16 });
    const rows: []boundary.Row = if (direct) &.{} else try output.alloc(boundary.Row, count);
    const fixed_rows: []boundary.Row = if (direct) &.{} else try output.alloc(boundary.Row, count);
    const sums: []scalar.Row = if (direct) &.{} else try output.alloc(scalar.Row, 16);
    const fixed_sums: []scalar.Row = if (direct) &.{} else try output.alloc(scalar.Row, 16);
    var seen: [16]bool = @splat(false);
    var next: usize = 0;
    const uses = inputs.circuit.useCounts();
    for (inputs.bindings, inputs.circuit.inputNodes(), inputs.inputs) |binding, node, value| {
        const expected: M = switch (binding) {
            .wire_word => |index| view.words[index],
            .register_byte => |index| bytes.value(view.words, index),
            .memory_byte => |index| layout.value(view.words, bytes.BYTE_COUNT + index),
            .memory_selector => |index| M.fromCanonical(@intFromBool(layout.value(view.words, bytes.BYTE_COUNT + index).v != 0)),
            .published_sum_word => |c| {
                const slot = @as(usize, @intFromEnum(c.domain)) * 4 + c.limb;
                if (slot >= seen.len or seen[slot]) return error.InvalidNativePublicSource;
                const coordinates = value.toM31Array();
                if (!value.eql(Q.fromBase(coordinates[0]))) return error.InvalidNativePublicSource;
                const row = try scalar.logicalRow(CIRCUIT, node, uses[node], coordinates[0]);
                const fixed = try scalar.logicalRow(CIRCUIT, node, uses[node], M.zero());
                if (direct) try columns.?.putFixed(12, slot, row, fixed) else {
                    sums[slot] = row;
                    fixed_sums[slot] = fixed;
                }
                seen[slot] = true;
                continue;
            },
            .native_challenge_word, .published_total_word => continue, // Shared producers in public_links.
        };
        if (next >= count or !value.eql(Q.fromBase(expected))) return error.InvalidNativePublicSource;
        const row = try boundary.logicalCoordinates(CIRCUIT, node, M.fromCanonical(uses[node]), .{ expected, M.zero(), M.zero(), M.zero() });
        var fixed = row;
        fixed[0..4].* = @splat(M.zero());
        if (direct) try columns.?.appendFixed(2, row, fixed) else {
            rows[next] = row;
            fixed_rows[next] = fixed;
        }
        next += 1;
    }
    if (next != count) return error.InvalidNativePublicSource;
    for (seen) |present| if (!present) return error.InvalidNativePublicSource;
    if (columns) |*owned| try owned.finish();
    return .{ .columns = columns, .arena = arena, .rows = rows, .fixed_rows = fixed_rows, .sums = sums, .fixed_sums = fixed_sums, .statement_operation = start + 2 };
}
