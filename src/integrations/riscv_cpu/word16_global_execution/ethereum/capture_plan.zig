//! CPU-only candidate cost from the SAME source-bound accounting as production.
//! No fixed keys, prover inputs, proof or acceptance are constructed here.
const std = @import("std");
const C = @import("../services/gkr_local/coordinator.zig");
const P = @import("../services/protocol.zig");
const W = @import("../services/wire.zig");
const Bounds = @import("../services/gkr_local/source_bounds.zig");
const Capture = @import("capture.zig").Owner;

pub fn sourceBounds(a: std.mem.Allocator, program_log: u32, cpu: []const W.CpuDeclaration, truths: []const W.TruthDeclaration, captured: *const Capture) !Bounds.Report {
    _ = try Bounds.validateInventory(cpu.len, truths.len);
    const requests = try a.alloc(P.Request, captured.native.items.len);
    defer a.free(requests);
    for (requests, 0..) |*value, i| {
        value.* = try C.requestView(captured.native.items, &captured.advice, i);
        try C.routeDword(value, cpu[i].bridges, captured.advice.events[i]);
    }
    try C.assignSpongeIds(requests);
    return Bounds.derive(a, program_log, cpu, truths, requests);
}

pub fn committedBits(cells: [3]u64) !u64 {
    return std.math.mul(u64, try std.math.add(u64, cells[1], cells[2]), 31);
}

pub const Result = struct {
    schema: []const u8 = "rv64-native-plan-cost/v1",
    scope: []const u8 = "source-derived native FIXED/MAIN/INTERACTION cells including padding; excludes PCS blowup, composition, openings, recursion, proof bytes and timing; no proof or acceptance",
    security_qualified: bool = false,
    proof_generated: bool = false,
    profile: []const u8,
    program_log: u32,
    prefix_count: u32,
    total_steps: u64,
    final_pc: u64,
    memory_words: usize,
    capture_ns: u64,
    cpu: []const W.CpuDeclaration,
    truths: []const W.TruthDeclaration,
    source_shape: Bounds.Shape,
    native_trace_cells: [3]u64,
    main_interaction_bits: u64,
    base_field_bits: u8 = 31,
    storage_bits_per_cell: u8 = 32,
};
pub fn result(a: std.mem.Allocator, profile: []const u8, program_log: u32, cpu: []const W.CpuDeclaration, truths: []const W.TruthDeclaration, captured: *const Capture, prefix_count: u32, capture_ns: u64) !Result {
    var bounds = try sourceBounds(a, program_log, cpu, truths, captured);
    defer bounds.deinit();
    return .{ .profile = profile, .program_log = program_log, .prefix_count = prefix_count, .total_steps = captured.total_steps, .final_pc = captured.final_pc, .memory_words = captured.advice.initial.len, .capture_ns = capture_ns, .cpu = cpu, .truths = truths, .source_shape = bounds.shape, .native_trace_cells = bounds.shape.native_trace_cells, .main_interaction_bits = try committedBits(bounds.shape.native_trace_cells) };
}

test "candidate cost excludes fixed key cells and rejects sum or product overflow" {
    try std.testing.expectEqual(@as(u64, 217), try committedBits(.{ std.math.maxInt(u64), 3, 4 }));
    try std.testing.expectError(error.Overflow, committedBits(.{ 0, std.math.maxInt(u64), 1 }));
    try std.testing.expectError(error.Overflow, committedBits(.{ 0, std.math.maxInt(u64) / 31 + 1, 0 }));
}
