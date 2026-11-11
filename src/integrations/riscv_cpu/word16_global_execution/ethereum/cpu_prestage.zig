//! Optional GPU CPU-source pre-stage callbacks; no CPU fallback or ownership change.
const std = @import("std");
pub const CpuPrestage = struct {
    stage: @import("../../word16_execution/cpu_source.zig").ProjectionStage,
    image_identity: [32]u8 = undefined,
    first_pass: bool = false,
    pub fn firstPass(raw: *anyopaque, source: *const @import("../../word16_execution/cpu_source.zig").FirstPass) void {
        const self: *CpuPrestage = @ptrCast(@alignCast(raw));
        self.stage.prestage_first_pass.?(self.stage.context, source, self.image_identity);
    }
    pub fn ready(raw: *anyopaque, index: usize, native: *const @import("../../word16_execution/prepared.zig").Prepared, _: []const @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2.native.Event, at_ns: u64) void {
        const self: *CpuPrestage = @ptrCast(@alignCast(raw));
        if (index != 0 or self.first_pass) return;
        std.debug.print("GPU_CPU_PRESTAGE event=capture_ready ordinal=0 utc_ns={} ordered_ready_ns={}\n", .{ std.time.nanoTimestamp(), at_ns });
        if (native.cpu) |*source| self.stage.prestage.?(self.stage.context, source, self.image_identity);
    }
    pub fn cancel(raw: *anyopaque) void {
        const self: *CpuPrestage = @ptrCast(@alignCast(raw));
        self.stage.cancel_prestage.?(self.stage.context);
    }
};
