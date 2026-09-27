//! FRI coefficient scalar inputs joined to canonical transcript bytes.
const std = @import("std");
const native = @import("blake3_native_transcript.zig");
const fri_mod = @import("blake3_native_fri.zig");
const rows_mod = @import("blake3_scalar_payload_rows.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const t = @import("blake3_transcript_witness.zig");
pub const PACK_CIRCUIT: u32 = 5_000_011;
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    rows: []rows_mod.Rows,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, transcript: *const native.Prepared, fri: *const fri_mod.Prepared, circuit: u32) !Prepared {
    try transcript.plan.validate();
    try fri.evaluation.validateAgainst(&fri.graph);
    const count = try fri.graph.profile().lastLayerCoefficientCount();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    const nodes = try temp.alloc([4]u32, count);
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
    if (transcript.plan.fixed.payload_reads.len != transcript.live.payload_reads.len) return error.InvalidNativeTerminalEncoding;
    var selected: ?t.PayloadReads = null;
    for (transcript.plan.fixed.payload_reads, transcript.live.payload_reads) |fixed, live| {
        if (fixed.operation != live.operation or !std.meta.eql(fixed.source, live.source) or !std.mem.eql(u32, fixed.uses, live.uses)) return error.InvalidNativeTerminalEncoding;
        if (fixed.source.circuit != native.TERMINAL_SOURCE.circuit) continue;
        if (selected != null or !std.meta.eql(fixed.source, native.TERMINAL_SOURCE)) return error.InvalidNativeTerminalEncoding;
        selected = fixed;
    }
    const receipt = selected orelse return error.InvalidNativeTerminalEncoding;
    if (receipt.uses.len != count * 4 or receipt.operation >= transcript.operations.len or transcript.operations[receipt.operation] != .routed_felts) return error.InvalidNativeTerminalEncoding;
    const payload = transcript.operations[receipt.operation].routed_felts;
    if (!std.meta.eql(payload.source, native.TERMINAL_SOURCE) or payload.values.len != count) return error.InvalidNativeTerminalEncoding;
    const uses = try lower.computeUseCountsInto(fri.graph.graph(), try temp.alloc(u32, fri.graph.nodes.len));
    const rows = try temp.alloc(rows_mod.Rows, count);
    for (rows, nodes, payload.values, 0..) |*row, tuple, value, i| {
        row.* = rows_mod.build(tuple, fri.evaluation.values, uses, circuit, .{ .circuit = PACK_CIRCUIT, .first_wire = @intCast(i) }, .{ .circuit = receipt.source.circuit, .first_wire = try std.math.add(u32, receipt.source.first_wire, @intCast(i * 4)) }, receipt.uses[i * 4 ..][0..4].*, value) catch |err| switch (err) {
            error.InvalidScalarPayload => return error.InvalidNativeTerminalEncoding,
            else => return err,
        };
    }
    return .{ .arena = arena, .rows = rows };
}
