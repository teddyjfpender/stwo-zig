//! Bounded per-proof retention of coefficients already computed by PCS commits.
//! Does not cache witness data between statements or change committed values.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
pub const Budget = struct {
    remaining: usize = 1024 * 1024 * 1024,
    pub fn configure(self: *Budget, scheme: anytype, columns: anytype) void {
        scheme.setCoefficientRetentionPolicy(.never);
        if (std.process.hasEnvVarConstant("STWO_RISCV_NO_EXECUTION_COEFFICIENT_CACHE")) return;
        var bytes: usize = 0;
        for (columns) |column| {
            const column_bytes = std.math.mul(usize, column.values.len, @sizeOf(M31)) catch return;
            bytes = std.math.add(usize, bytes, column_bytes) catch return;
        }
        self.reserve(scheme, bytes);
    }
    /// Secure composition has four base-field coordinates. Splitting preserves
    /// their total coefficient count; use the same AIR bound as core proving.
    pub fn configureComposition(self: *Budget, scheme: anytype, components: anytype) void {
        scheme.setCoefficientRetentionPolicy(.never);
        if (std.process.hasEnvVarConstant("STWO_RISCV_NO_EXECUTION_COEFFICIENT_CACHE")) return;
        var log: u32 = 0;
        for (components) |component| log = @max(log, component.maxConstraintLogDegreeBound());
        if (log >= @bitSizeOf(usize)) return;
        const size = @as(usize, 1) << @intCast(log);
        const bytes = std.math.mul(usize, size, @sizeOf(@import("stwo_core").fields.qm31.QM31)) catch return;
        self.reserve(scheme, bytes);
    }
    fn reserve(self: *Budget, scheme: anytype, bytes: usize) void {
        if (bytes > self.remaining) return;
        self.remaining -= bytes;
        scheme.setCoefficientRetentionPolicy(.always);
    }
};
