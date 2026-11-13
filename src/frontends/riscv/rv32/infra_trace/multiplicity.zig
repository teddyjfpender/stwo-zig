//! Historical preprocessed lookup multiplicity column facade.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const trace_mod = @import("../runner/trace.zig");
const permutation = @import("stwo_riscv_air_lang").trace_layout.permutation;

pub const N_MULTIPLICITY_TABLES: usize = 6;

/// Allocate the six zero-valued table columns used by the historical API.
/// Production lookup multiplicities are derived by `air/lookups/tables`.
pub fn genPreprocessedMultiplicityColumns(
    allocator: std.mem.Allocator,
    exec_trace: *const trace_mod.Trace,
) !struct { columns: [N_MULTIPLICITY_TABLES][]M31, log_size: u32 } {
    const log_size = multiplicityLogSize(exec_trace);
    const domain_size = @as(usize, 1) << @intCast(log_size);
    return .{
        .columns = try permutation.allocZeroColumns(
            allocator,
            N_MULTIPLICITY_TABLES,
            domain_size,
        ),
        .log_size = log_size,
    };
}

pub fn freeMultiplicityColumns(
    allocator: std.mem.Allocator,
    columns: *[N_MULTIPLICITY_TABLES][]M31,
) void {
    for (columns) |column| allocator.free(column);
}

pub fn multiplicityLogSize(exec_trace: *const trace_mod.Trace) u32 {
    const count = @max(exec_trace.step_count, 16);
    return @intCast(std.math.log2_int_ceil(usize, count));
}
