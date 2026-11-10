//! Success-only ownership handoff of completed CPU INTER matrices to PCS.
//! Component handles retain immutable binding points/challenges/claims, never
//! these generator matrices. All evaluation reads the committed PCS trace.
const std = @import("std");
const C = @import("stwo_core");
const E = @import("stwo_prover_engine");
const M = C.fields.m31.M31;
const Column = E.pcs.ColumnEvaluation;
const Commit = @import("../../word16_execution/main_ownership.zig").Commit;
const Parts = @import("../../word16_global_execution/services/gkr_local/cpu_components.zig");
const Global = @import("../../word16_global_execution/services/gkr_local/global_cpu.zig");
const Binding = @import("../../word16_global_execution/services/gkr_local/witness.zig").Witness;
const Classic = @import("../../word16_global_execution/services/gkr_local/classic_witness.zig").Witness;
const Frontier = @import("binding.zig").Witness;
const L = @import("equations.zig").Layout;
const sameAllocator = @import("stwo_riscv_frontend").rv64_air.memory.ownership.same;

fn rows(log: u32) !usize {
    if (log < 5 or log > 23) return error.SpongeCpuInteractionShape;
    return @as(usize, 1) << @intCast(log);
}
fn addBuffer(backings: [][]M, at: *usize, data: []M, log: u32, width: usize, columns: []Column) !void {
    const n = try rows(log);
    if (width == 0 or columns.len != width or data.len != try std.math.mul(usize, n, width) or at.* >= backings.len) return error.SpongeCpuInteractionShape;
    const start = @intFromPtr(data.ptr);
    const end = try std.math.add(usize, start, try std.math.mul(usize, data.len, @sizeOf(M)));
    for (backings[0..at.*]) |prior| {
        const prior_end = try std.math.add(usize, @intFromPtr(prior.ptr), try std.math.mul(usize, prior.len, @sizeOf(M)));
        if (start < prior_end and @intFromPtr(prior.ptr) < end) return error.SpongeCpuInteractionAlias;
    }
    backings[at.*] = data;
    at.* += 1;
    for (columns, 0..) |*column, i| column.* = .{ .log_size = log, .values = data[i * n ..][0..n] };
}
/// No source owner changes on failure. Returned bundle must be consumed once
/// by PCS (which consumes on success AND error), or explicitly deinitialized.
pub fn take(a: std.mem.Allocator, plan: *const Parts.Plan, binding: *Binding, globals: []?Classic, frontier: *Frontier, frontier_log: u32) !Commit {
    if (!plan.op_only or globals.len != plan.slots.len or binding.columns.len != plan.binding_count) return error.SpongeCpuInteractionShape;
    if (frontier.data.len == 0) return error.SpongeCpuInteractionShape;
    for (binding.columns) |data| if (data.len == 0) return error.SpongeCpuInteractionShape;
    if (!sameAllocator(a, binding.allocator) or !sameAllocator(a, frontier.allocator)) return error.SpongeCpuInteractionAllocator;
    var count = try std.math.add(usize, plan.binding_count, 1);
    for (globals) |w| if (w) |v| {
        if (!sameAllocator(a, v.allocator)) return error.SpongeCpuInteractionAllocator;
        count = try std.math.add(usize, count, 1);
    };
    const columns = try a.alloc(Column, try std.math.add(usize, plan.inter_columns, L.INTERACTION));
    errdefer a.free(columns);
    const backings = try a.alloc([]M, count);
    errdefer a.free(backings);
    var at: usize = 0;
    var offset: usize = 0;
    var next_binding: usize = 0;
    for (plan.slots, globals) |slot, w| {
        if (slot.inter_offset != offset) return error.SpongeCpuInteractionShape;
        if (slot.binding_index) |i| {
            if (i != next_binding or i >= binding.columns.len or offset > plan.inter_columns or 16 > plan.inter_columns - offset) return error.SpongeCpuInteractionShape;
            try addBuffer(backings, &at, binding.columns[i], slot.log, 16, columns[offset..][0..16]);
            offset += 16;
            next_binding += 1;
        }
        const n = Global.claimCount(slot.origin);
        if (w) |v| {
            const width = Global.layout(slot.origin).width();
            if (n == 0 or v.group_count != n or v.group_count > v.groups.len or v.log_size != slot.log or v.width() != width or offset > plan.inter_columns or width > plan.inter_columns - offset) return error.SpongeCpuInteractionShape;
            try addBuffer(backings, &at, v.data, slot.log, width, columns[offset..][0..width]);
            offset += width;
        } else if (n != 0) return error.SpongeCpuInteractionShape;
    }
    if (offset != plan.inter_columns or next_binding != binding.columns.len) return error.SpongeCpuInteractionShape;
    try addBuffer(backings, &at, frontier.data, frontier_log, L.INTERACTION, columns[offset..]);
    if (at != backings.len) return error.SpongeCpuInteractionShape;
    // All shape, allocator, disjointness and allocation checks completed.
    // Keep the small generator descriptor allocations for their usual deinit.
    for (binding.columns) |*data| data.* = &.{};
    for (globals) |*w| {
        if (w.*) |*v| v.data = &.{};
    }
    frontier.data = &.{};
    return .{ .columns = columns, .backings = backings };
}
