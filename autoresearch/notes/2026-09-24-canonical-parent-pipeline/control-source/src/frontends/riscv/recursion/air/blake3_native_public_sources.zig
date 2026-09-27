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
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    rows: []boundary.Row,
    fixed_rows: []boundary.Row,
    sums: [16]scalar.Row,
    fixed_sums: [16]scalar.Row,
    statement_operation: usize,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, statement_value: *const statement.RiscVStatementV2, config: core.pcs.PcsConfig, transcript: *const transcript_mod.Prepared, inputs: *const public.Prepared) !Prepared {
    try inputs.validate(a);
    try transcript.plan.validate();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
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
    const count = view.words.len + bytes.BYTE_COUNT + 2 * layout.memoryByteCount();
    const rows = try temp.alloc(boundary.Row, count);
    const fixed_rows = try temp.alloc(boundary.Row, count);
    var sums: [16]scalar.Row = undefined;
    var fixed_sums: [16]scalar.Row = undefined;
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
                if (slot >= sums.len or seen[slot]) return error.InvalidNativePublicSource;
                const coordinates = value.toM31Array();
                if (!value.eql(Q.fromBase(coordinates[0]))) return error.InvalidNativePublicSource;
                sums[slot] = try scalar.logicalRow(CIRCUIT, node, uses[node], coordinates[0]);
                fixed_sums[slot] = try scalar.logicalRow(CIRCUIT, node, uses[node], M.zero());
                seen[slot] = true;
                continue;
            },
            .native_challenge_word, .published_total_word => continue, // Shared producers in public_links.
        };
        if (next >= rows.len or !value.eql(Q.fromBase(expected))) return error.InvalidNativePublicSource;
        rows[next] = try boundary.logicalCoordinates(CIRCUIT, node, M.fromCanonical(uses[node]), .{ expected, M.zero(), M.zero(), M.zero() });
        fixed_rows[next] = rows[next];
        fixed_rows[next][0..4].* = @splat(M.zero());
        next += 1;
    }
    if (next != rows.len) return error.InvalidNativePublicSource;
    for (seen) |present| if (!present) return error.InvalidNativePublicSource;
    return .{ .arena = arena, .rows = rows, .fixed_rows = fixed_rows, .sums = sums, .fixed_sums = fixed_sums, .statement_operation = start + 2 };
}
