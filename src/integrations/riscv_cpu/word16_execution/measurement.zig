//! Physical source and declared quotient-evaluation geometry. These are not
//! estimated FFT executions or prover speed: implementations may reuse work.
const std = @import("std");
const G = @import("geometry.zig");
const Components = @import("components.zig").Components;
pub const RoleEvaluation = struct {
    role: G.Role,
    present: bool = true,
    source_log: u32,
    native_evaluation_log: u32,
    composition_contribution_bound_log: u32,
    evaluation_points: u64,
    composition_log_split: u32,
};
pub const Geometry = struct {
    source_cells: G.Cells,
    declared_component_evaluation_points: u64,
    components: [G.ROLE_COUNT]RoleEvaluation,
    scope: []const u8 = "component declared quotient evaluation domains; includes separate chip domains, excludes FFT reuse and actual execution counters",
};
pub fn inspect(a: std.mem.Allocator, components: *const Components) !Geometry {
    const shapes = components.materials.shapes();
    const handles = try components.provers(a);
    defer a.free(handles);
    var result = Geometry{ .source_cells = try G.cells(&shapes), .declared_component_evaluation_points = 0, .components = undefined };
    var at: usize = 0;
    for (shapes, &result.components) |shape, *value| {
        if (!shape.present()) {
            value.* = .{ .role = shape.role, .present = false, .source_log = shape.log, .native_evaluation_log = 0, .composition_contribution_bound_log = 0, .evaluation_points = 0, .composition_log_split = 0 };
            continue;
        }
        const handle = handles[at];
        at += 1;
        const log = shape.log + 1;
        if (log > 30) return error.InvalidExecutionEvaluationGeometry;
        const n = @as(u64, 1) << @intCast(log);
        value.* = .{ .role = shape.role, .source_log = shape.log, .native_evaluation_log = log, .composition_contribution_bound_log = handle.maxConstraintLogDegreeBound(), .evaluation_points = n, .composition_log_split = handle.compositionLogSplit() };
        result.declared_component_evaluation_points = try std.math.add(u64, result.declared_component_evaluation_points, n);
    }
    return result;
}
