//! Native table equations projected into an admitted device interaction writer.
//! Output stays in the existing commitment-column ownership/layout contract.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const schema = @import("schema.zig");
const counter_mod = @import("counter.zig");
const interaction = @import("interaction.zig");
const component = @import("component.zig");
const framework = @import("framework_export.zig");
const Relations = @import("../../relation_challenges.zig").Relations;

pub fn generate(comptime Backend: type, allocator: std.mem.Allocator, counter: *const counter_mod.Counter, relations: *const Relations) !interaction.Result {
    const rows = schema.size(counter.kind);
    if (counter.values.len != rows) return error.InvalidTraceShape;
    const arity = schema.arity(counter.kind);
    const tuple_indices = [_]usize{ 1, 2, 3, 4 };
    const table = try component.LookupTableComponent.initProver(counter.kind, 0, tuple_indices[0..arity], 0, 0, relations, QM31.zero());
    const counts = [_]usize{ 1 + arity, 1, interaction.N_COLUMNS };
    var program = try framework.exportProgram(allocator, &table, &counts);
    defer program.deinit();
    var parameters = try framework.exportParameters(allocator, &table);
    defer parameters.deinit();
    var tuples = try schema.generatePreprocessed(allocator, counter.kind);
    defer tuples.deinit(allocator);
    const first = try allocator.alloc(M31, rows);
    defer allocator.free(first);
    @memset(first, M31.zero());
    first[0] = M31.one();
    const multiplicities = try counter.committedColumn(allocator);
    defer allocator.free(multiplicities);
    var preprocessed: [1 + schema.MAX_ARITY][]const M31 = undefined;
    preprocessed[0] = first;
    for (tuples.columns[0..arity], preprocessed[1 .. 1 + arity]) |column, *slot| slot.* = column;
    var result: interaction.Result = .{ .columns = .{&.{}} ** interaction.N_COLUMNS, .claim = QM31.zero() };
    errdefer result.deinit(allocator);
    for (&result.columns) |*column| column.* = try allocator.alloc(M31, rows);
    result.claim = Backend.generateFrameworkInteractionInto(allocator, &program, &counts, .{ preprocessed[0 .. 1 + arity], &.{multiplicities} }, .{
        .trace_log_size = schema.logSize(counter.kind),
        .profile_values = parameters.values.profile_values,
        .relation_values = parameters.values.relation_values,
    }, &result.columns) catch |err| switch (err) {
        error.FrameworkInteractionZeroDenominator => return error.DivisionByZero,
        else => return err,
    };
    std.debug.print("NATIVE_TABLE_DEVICE_INTERACTION kind={s} rows={d}\n", .{ @tagName(counter.kind), rows });
    return result;
}
