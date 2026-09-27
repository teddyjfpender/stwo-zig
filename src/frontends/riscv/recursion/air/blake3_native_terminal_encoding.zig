//! FRI coefficient scalar inputs joined to canonical transcript bytes.
const std = @import("std");
const native = @import("blake3_native_transcript.zig");
const fri_mod = @import("blake3_native_fri.zig");
const rows_mod = @import("blake3_scalar_payload_rows.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const t = @import("blake3_transcript_witness.zig");
pub const PACK_CIRCUIT: u32 = 5_000_011;
pub const Columns = @import("blake3_upstream_source_columns_v1.zig").ForSlots(.{ 12, 11, 10 });
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    rows: []rows_mod.Rows,
    columns: ?Columns = null,
    pub fn deinit(self: *Prepared) void {
        if (self.columns) |*columns| columns.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn appendInputs(self: *const Prepared, b: anytype) !void {
        if (self.columns) |*columns| {
            if (self.rows.len != 0) return error.InvalidNativeTerminalEncoding;
            // Per-cohort order equals the old interleaved bundle walk.
            try columns.appendTo(12, b);
            try columns.appendTo(11, b);
            try columns.appendTo(10, b);
        } else {
            for (self.rows) |row| {
                try b.append(12, &row.scalars, &row.fixed_scalars);
                try b.append(11, &.{row.packing}, &.{row.fixed_packing});
                try b.append(10, &.{row.encoded}, &.{row.fixed_encoded});
            }
        }
    }
};
pub fn prepare(a: std.mem.Allocator, transcript: anytype, fri: *const fri_mod.Prepared, circuit: u32) !Prepared {
    return prepareMode(false, a, transcript, fri, circuit);
}
pub fn prepareColumns(a: std.mem.Allocator, transcript: anytype, fri: *const fri_mod.Prepared, circuit: u32) !Prepared {
    return prepareMode(true, a, transcript, fri, circuit);
}
fn prepareMode(comptime direct: bool, a: std.mem.Allocator, transcript: anytype, fri: *const fri_mod.Prepared, circuit: u32) !Prepared {
    try transcript.plan.validate();
    try fri.evaluation.validateAgainst(&fri.graph);
    const count = try fri.graph.profile().lastLayerCoefficientCount();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    const scalar_count = try std.math.mul(usize, count, 4);
    const nodes = try a.alloc([4]u32, count);
    defer a.free(nodes);
    const missing = std.math.maxInt(u32);
    @memset(nodes, @splat(missing));
    for (fri.graph.bindings) |binding| switch (binding.source) {
        .last_layer_coefficient_word => |c| {
            if (c.coefficient >= count or c.word >= 4 or nodes[c.coefficient][c.word] != missing) return error.InvalidNativeTerminalEncoding;
            nodes[c.coefficient][c.word] = binding.node_id;
        },
        else => {},
    };
    for (nodes) |tuple| for (tuple) |node| if (node == missing) return error.InvalidNativeTerminalEncoding;
    if (@hasField(@TypeOf(transcript.*), "live")) {
        if (transcript.plan.fixed.payload_reads.len != transcript.live.payload_reads.len) return error.InvalidNativeTerminalEncoding;
        for (transcript.plan.fixed.payload_reads, transcript.live.payload_reads) |fixed, live| {
            if (fixed.operation != live.operation or !std.meta.eql(fixed.source, live.source) or !std.mem.eql(u32, fixed.uses, live.uses)) return error.InvalidNativeTerminalEncoding;
        }
    }
    var selected: ?t.PayloadReads = null;
    for (transcript.plan.fixed.payload_reads) |fixed| {
        if (fixed.source.circuit != native.TERMINAL_SOURCE.circuit) continue;
        if (selected != null or !std.meta.eql(fixed.source, native.TERMINAL_SOURCE)) return error.InvalidNativeTerminalEncoding;
        selected = fixed;
    }
    const receipt = selected orelse return error.InvalidNativeTerminalEncoding;
    if (receipt.uses.len != scalar_count or receipt.operation >= transcript.operations.len or transcript.operations[receipt.operation] != .routed_felts) return error.InvalidNativeTerminalEncoding;
    const payload = transcript.operations[receipt.operation].routed_felts;
    if (!std.meta.eql(payload.source, native.TERMINAL_SOURCE) or payload.values.len != count) return error.InvalidNativeTerminalEncoding;
    const scratch = try a.alloc(u32, fri.graph.nodes.len);
    defer a.free(scratch);
    const uses = try lower.computeUseCountsInto(fri.graph.graph(), scratch);
    var columns: ?Columns = null;
    errdefer if (columns) |*owned| owned.deinit();
    if (direct) columns = try Columns.init(a, .{ scalar_count, count, count });
    const rows: []rows_mod.Rows = if (direct) &.{} else try temp.alloc(rows_mod.Rows, count);
    for (nodes, payload.values, 0..) |tuple, value, i| {
        const row = rows_mod.build(tuple, fri.evaluation.values, uses, circuit, .{ .circuit = PACK_CIRCUIT, .first_wire = @intCast(i) }, .{ .circuit = receipt.source.circuit, .first_wire = try std.math.add(u32, receipt.source.first_wire, @intCast(i * 4)) }, receipt.uses[i * 4 ..][0..4].*, value) catch |err| switch (err) {
            error.InvalidScalarPayload => return error.InvalidNativeTerminalEncoding,
            else => return err,
        };
        if (direct) {
            for (row.scalars) |source| try columns.?.append(12, source);
            try columns.?.append(11, row.packing);
            try columns.?.append(10, row.encoded);
        } else rows[i] = row;
    }
    if (columns) |*owned| try owned.finish();
    return .{ .arena = arena, .rows = rows, .columns = columns };
}
