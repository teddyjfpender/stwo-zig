//! Generated native INTER accounting for the declaration-only cost diagnostic.
//! Own-height cells; not lifted openings, witness memory or verification authority.
const std = @import("std");
const RP = @import("retention_plan.zig");
const Truth = @import("truth_components.zig");
const Wire = @import("../wire.zig");
fn cells(bytes: usize) !u64 {
    if (bytes % @sizeOf(u32) != 0) return error.UnalignedInteractionPayload;
    return @intCast(bytes / @sizeOf(u32));
}
pub const Breakdown = struct {
    cpu_local_binding_cells: u64 = 0,
    cpu_global_cells: u64 = 0,
    truth_classic_local_cells: u64 = 0,
    truth_global_cells: u64 = 0,
    pub fn recordCpu(self: *@This(), plan: RP.RetentionPlan) !void {
        self.cpu_local_binding_cells = try std.math.add(u64, self.cpu_local_binding_cells, try cells(plan.binding_bytes));
        self.cpu_global_cells = try std.math.add(u64, self.cpu_global_cells, try cells(plan.global_output_bytes));
    }
    pub fn recordTruth(self: *@This(), declaration: Wire.TruthDeclaration, plan: RP.RetentionPlan) !void {
        const shapes = try Truth.shapesForDeclaration(declaration);
        var local: u64 = 0;
        var global: u64 = 0;
        for (shapes) |shape| {
            const n = @as(u64, 1) << @intCast(shape.log_size);
            const local_width: u64 = @intCast(shape.localWidth());
            const global_width = try std.math.sub(u64, @intCast(shape.widths()[2]), local_width);
            local = try std.math.add(u64, local, try std.math.mul(u64, local_width, n));
            global = try std.math.add(u64, global, try std.math.mul(u64, global_width, n));
        }
        // Truth retention currently places both classic-local and global output
        // in this field. Reconcile against its independent physical authority.
        if (try std.math.add(u64, local, global) != try cells(plan.global_output_bytes) or plan.binding_bytes != 0) return error.InteractionAccountingMismatch;
        self.truth_classic_local_cells = try std.math.add(u64, self.truth_classic_local_cells, local);
        self.truth_global_cells = try std.math.add(u64, self.truth_global_cells, global);
    }
    pub fn total(self: @This()) !u64 {
        return std.math.add(u64, try std.math.add(u64, self.cpu_local_binding_cells, self.cpu_global_cells), try std.math.add(u64, self.truth_classic_local_cells, self.truth_global_cells));
    }
    pub fn reconcile(self: @This(), physical_bytes: u64) !void {
        if (physical_bytes % @sizeOf(u32) != 0 or try self.total() != physical_bytes / @sizeOf(u32)) return error.InteractionAccountingMismatch;
    }
};

test "generated INTER accounting separates actual truth shapes and rejects physical drift" {
    const A = @import("stwo_riscv_frontend").rv64_air;
    for ([_]Wire.TruthDeclaration{
        .{ .family = .keccak, .first_id = 1, .calls = 2, .logs = .{ 5, 0 } },
        .{ .family = .add, .first_id = 1, .calls = 1, .logs = .{ try A.crypto.secp256k1.layout.logSize(.product, A.crypto.secp256k1.program.get(.add), 1), try A.crypto.secp256k1.layout.logSize(.linear, A.crypto.secp256k1.program.get(.add), 1) } },
    }) |declaration| {
        var bytes: u64 = 0;
        for (try Truth.shapesForDeclaration(declaration)) |shape| bytes += @as(u64, @intCast(shape.widths()[2])) * (@as(u64, 1) << @intCast(shape.log_size)) * 4;
        var out = Breakdown{};
        try out.recordCpu(.{ .binding_bytes = 64, .global_output_bytes = 32 });
        try out.recordTruth(declaration, .{ .global_output_bytes = @intCast(bytes) });
        try std.testing.expect(out.truth_classic_local_cells > 0 and out.truth_global_cells > 0);
        try std.testing.expectEqual(@as(u64, 16), out.cpu_local_binding_cells);
        try std.testing.expectEqual(@as(u64, 8), out.cpu_global_cells);
        try out.reconcile(bytes + 96);
        try std.testing.expectError(error.InteractionAccountingMismatch, out.reconcile(bytes + 100));
        try std.testing.expectError(error.InteractionAccountingMismatch, out.recordTruth(declaration, .{ .global_output_bytes = @intCast(bytes + 4) }));
    }
}
test "generated INTER accounting rejects unaligned and overflowing payloads" {
    var out = Breakdown{};
    try std.testing.expectError(error.UnalignedInteractionPayload, out.recordCpu(.{ .binding_bytes = 1 }));
    out.cpu_local_binding_cells = std.math.maxInt(u64);
    try std.testing.expectError(error.Overflow, out.recordCpu(.{ .binding_bytes = 4 }));
    out.truth_global_cells = 1;
    try std.testing.expectError(error.Overflow, out.total());
}
