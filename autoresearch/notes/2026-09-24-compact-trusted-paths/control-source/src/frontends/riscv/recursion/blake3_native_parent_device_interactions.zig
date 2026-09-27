//! Authenticated parent interaction dispatch with one cohort's fixed staging.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const binding = @import("air/universal_relation_binding.zig");
const framework = @import("air/framework_interaction.zig");
const projection = @import("air/blake3_row_columns.zig");
const storage = @import("air/blake3_parent_row_storage.zig");
const exporter = @import("air/framework_polynomial_export_v1.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const Program = engine.air.component_prover.OwnedFrameworkPolynomialProgramV1;

pub fn prepare(comptime Backend: type, comptime Air: type, a: std.mem.Allocator, definition: anytype, plan: *const binding.Binding(Air).Plan) !?Program {
    if (comptime !@hasDecl(Backend, "supportsFrameworkInteractionProgram")) return null;
    const direct = try @import("air/direct_constraint_program.zig").authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    var program = try exporter.exportLocalPrepared(Air, a, &direct, plan);
    errdefer program.deinit();
    if (try Backend.supportsFrameworkInteractionProgram(a, &program, &.{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT })) return program;
    program.deinit();
    return null;
}

pub fn generate(comptime Backend: type, comptime Air: type, a: std.mem.Allocator, program: ?*const Program, plan: *const binding.Binding(Air).Plan, view: framework.Runtime(binding.Binding(Air).Runtime).ColumnRows, metadata: []const storage.FixedRow(Air), log: u32, relations: *const @import("air/universal_challenges.zig").UniversalRelations, padding: Air.Row, scratch: []Q) !framework.Runtime(binding.Binding(Air).Runtime).OwnedColumns {
    const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
    if (comptime @hasDecl(Backend, "supportsFrameworkInteractionProgram")) {
        if (program) |selected| {
            try view.validate(log);
            if (metadata.len != view.count) return error.InvalidTraceShape;
            var fixed: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
            defer {
                for (fixed.items) |column| a.free(column.values);
                fixed.deinit(a);
            }
            // Fixed rows were checked against the admitted immutable plan.
            // Stage only this cohort and release it after synchronous readback.
            try projection.projectFixed(Air, a, metadata, log, &fixed);
            var fixed_values: [Air.PREPROCESSED_COLUMN_COUNT][]const M = undefined;
            for (&fixed_values, fixed.items) |*dst, column| dst.* = column.values;
            var result = Runtime.OwnedColumns{ .columns = @splat(&.{}), .claimed_sum = undefined };
            errdefer result.deinit(a);
            for (&result.columns) |*column| column.* = try a.alloc(M, @as(usize, 1) << @intCast(log));
            result.claimed_sum = try @import("air/framework_device_interaction.zig").generateColumnsInto(Backend, Air, a, selected, plan, .{ &fixed_values, view.columns[0..Air.PHYSICAL_MAIN_COLUMN_COUNT] }, padding[Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT ..], log, relations, &result.columns);
            return result;
        }
    }
    const tile_log = @min(log, framework.OWNED_TILE_LOG_SIZE);
    var workspace = Runtime.Workspace{ .allocator = a, .capacity_log_size = tile_log, .scratch = scratch[0..try Runtime.requiredScratchElementCount(tile_log)] };
    return @import("air/framework_parallel_interaction.zig").generate(Runtime, a, &workspace, plan, view, log, relations, padding);
}
