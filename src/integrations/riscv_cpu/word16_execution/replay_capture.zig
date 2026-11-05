//! Compact capture retained across the global-challenge barrier. Only CPU/JALR
//! transport is copied; original Prepared owns all borrowed normalized facts
//! through stage two. Never call Prepared.deinit on this borrowed overlay.
const std = @import("std");
const Prepared = @import("prepared.zig").Prepared;
const J = @import("jalr_source.zig");
pub const Capture = struct {
    value: Prepared,
    pub fn init(a: std.mem.Allocator, original: *const Prepared) !Capture {
        const cpu = original.cpu orelse return error.PreparedExecutionConsumed;
        const jalr = original.jalr orelse return error.PreparedExecutionConsumed;
        if (jalr.main.len != 0 or jalr.fixed.len != 0 or jalr.interaction.len != 0) return error.CpuReplayRequiresUnmaterializedCapture;
        var own_cpu = try cpu.cloneCapture(a);
        errdefer own_cpu.deinit();
        const own_jalr = try J.Source.capture(a, jalr.facts, jalr.log_size);
        var overlay = original.*;
        overlay.cpu = own_cpu;
        overlay.jalr = own_jalr;
        return .{ .value = overlay };
    }
    pub fn deinit(self: *Capture) void {
        if (self.value.cpu) |*cpu| cpu.deinit();
        if (self.value.jalr) |*jalr| jalr.deinit();
        self.* = undefined;
    }
    pub fn bytes(original: *const Prepared) !usize {
        const cpu = original.cpu orelse return error.PreparedExecutionConsumed;
        const jalr = original.jalr orelse return error.PreparedExecutionConsumed;
        var n: usize = @sizeOf(Capture);
        inline for (.{ cpu.metadata, cpu.rom_counts, cpu.counts16, cpu.counts8, jalr.facts, original.alu.facts, original.alu.weights, original.binary.facts, original.binary.weights, original.shift, original.shift_weights, original.division, original.multiplication, original.zbb.facts, original.zbb.weights }) |slice| n = try std.math.add(usize, n, std.mem.sliceAsBytes(slice).len);
        return n;
    }
};
