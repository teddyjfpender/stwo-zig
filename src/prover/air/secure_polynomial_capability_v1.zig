//! Trusted frontend export seam. The callback owns bounded DAG metadata only;
//! it never receives a proof wire, opens a device, or changes CPU OODS checks.
const std = @import("std");
pub const ir = @import("secure_polynomial_program_v1.zig");
pub const Capability = struct {
    context: *const anyopaque,
    kind: ir.Kind,
    trace_log: u32,
    export_program: *const fn (*const anyopaque, std.mem.Allocator) anyerror!ir.Program,
};
pub const Limits = struct {
    max_components: usize = 16,
    max_metadata_bytes: usize = 16 * 1024 * 1024,
    max_resident_bytes: usize = 24 * 1024 * 1024 * 1024,
};
pub fn metadataBytes(program: *const ir.Program) !usize {
    var result = try std.math.mul(usize, program.nodes.len, @sizeOf(ir.Node));
    result = try std.math.add(usize, result, try std.math.mul(usize, program.inputs.len, @sizeOf(ir.Input)));
    result = try std.math.add(usize, result, try std.math.mul(usize, program.roots.len, @sizeOf(u32)));
    return std.math.add(usize, result, try std.math.mul(usize, program.parameters.len, @sizeOf(@import("stwo_core").fields.qm31.QM31)));
}
/// Protocol powers are ascending, but component order consumes them from the
/// end. The kernel reverses each returned slice for ordered root equations.
pub fn powerStart(total: usize, cursor: *usize, count: usize) !usize {
    if (cursor.* > total or count == 0 or count > cursor.*) return error.InvalidSecurePowerPartition;
    cursor.* -= count;
    return cursor.*;
}
pub fn residentBytes(kind: ir.Kind, trace_log: u32) !usize {
    if (ir.isFraction(kind) or trace_log < 1 or trace_log > 24 or
        (kind == .range16_equations_v4 and trace_log != 16)) return error.InvalidSecureCompositionGeometry;
    const shape = ir.layout(kind);
    const rows = @as(usize, 1) << @intCast(trace_log + shape.expansion_bits);
    // All source columns are materialized on the exact quotient domain once.
    // Four output coordinates retain the same resident owner through PCS.
    const cells = try std.math.mul(usize, rows, @as(usize, shape.fixed) + shape.main + shape.interaction + 4);
    return std.math.mul(usize, cells, 4);
}
