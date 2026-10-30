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

pub fn generate(comptime Backend: type, comptime Air: type, a: std.mem.Allocator, program: ?*const Program, plan: *const binding.Binding(Air).Plan, view: framework.Runtime(binding.Binding(Air).Runtime).ColumnRows, metadata: []const storage.FixedRow(Air), log: u32, relations: *const @import("air/universal_challenges.zig").UniversalRelations, padding: Air.Row, scratch: []Q, executor: ?*const @import("blake3_parent_interaction_executor_v1.zig").Executor) !framework.Runtime(binding.Binding(Air).Runtime).OwnedColumns {
    const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
    if (executor != null or comptime @hasDecl(Backend, "supportsFrameworkInteractionProgram")) {
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
            result.claimed_sum = try @import("air/framework_device_interaction.zig").generateColumnsIntoWithExecutor(Backend, Air, a, selected, plan, .{ &fixed_values, view.columns[0..Air.PHYSICAL_MAIN_COLUMN_COUNT] }, padding[Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT ..], log, relations, &result.columns, executor);
            return result;
        }
    }
    const tile_log = @min(log, framework.OWNED_TILE_LOG_SIZE);
    var workspace = Runtime.Workspace{ .allocator = a, .capacity_log_size = tile_log, .scratch = scratch[0..try Runtime.requiredScratchElementCount(tile_log)] };
    return @import("air/framework_parallel_interaction.zig").generate(Runtime, a, &workspace, plan, view, log, relations, padding);
}

/// Exact table provider adapter for the explicit value executor. The original
/// fixed tuple generator and already committed multiplicity column are used.
pub fn generateTable(a: std.mem.Allocator, executor: *const @import("blake3_parent_interaction_executor_v1.zig").Executor, kind: @import("../air/lookups/tables/schema.zig").Kind, relations: *const @import("../air/relation_challenges.zig").Relations, main: []const M) !@import("../air/lookups/tables/interaction.zig").Result {
    const Table = @import("../air/lookups/tables/component.zig").LookupTableComponent;
    const TableExport = @import("../air/lookups/tables/framework_export.zig");
    const schema = @import("../air/lookups/tables/schema.zig");
    var fixed: std.ArrayList(engine.pcs.ColumnEvaluation) = .empty;
    defer {
        for (fixed.items) |column| a.free(column.values);
        fixed.deinit(a);
    }
    try projection.tablePreprocessed(a, kind, &fixed);
    const arity = schema.arity(kind);
    var tuples: [schema.MAX_ARITY]usize = undefined;
    for (tuples[0..arity], 0..) |*slot, i| slot.* = i + 1;
    const component = try Table.initProver(kind, 0, tuples[0..arity], 0, 0, relations, Q.zero());
    const counts = [_]usize{ arity + 1, 1, 4 };
    var program = try TableExport.exportProgram(a, &component, &counts);
    defer program.deinit();
    var parameters = try TableExport.exportParameters(a, &component);
    defer parameters.deinit();
    var fixed_values: [schema.MAX_ARITY + 1][]const M = undefined;
    for (fixed.items, 0..) |column, i| fixed_values[i] = column.values;
    const sources = [2][]const []const M{ fixed_values[0 .. arity + 1], &.{main} };
    var result = @import("../air/lookups/tables/interaction.zig").Result{ .columns = @splat(&.{}), .claim = undefined };
    errdefer result.deinit(a);
    for (&result.columns) |*column| column.* = try a.alloc(M, schema.size(kind));
    var claims: [1]Q = undefined;
    try @import("blake3_parent_interaction_executor_v1.zig").validate(&program, counts, sources, parameters.values, &result.columns, &claims);
    try executor.generate(executor.context, a, &program, counts, sources, parameters.values, &result.columns, &claims);
    result.claim = claims[0];
    return result;
}
