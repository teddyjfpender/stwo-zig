const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const parallel = @import("../parallel.zig");
const cosets = @import("../coset_evaluation.zig");
const Component = @import("../component.zig").Component;
const Plan = @import("../../encoding.zig").Plan;
const frame = @import("../frame.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;

test "RV64 row pool: exact serial residual authority, additive output, and drained coset reuse" {
    try compareRows(7);
    try compareRows(10);
}
fn compareRows(log: u32) !void {
    var all_opcodes: [63]@import("../../evaluation.zig").O = undefined;
    for (&all_opcodes, 0..) |*opcode, i| opcode.* = @enumFromInt(i);
    const plan = Plan.fromOpcodes(&all_opcodes);
    const zero = Q.zero();
    const typed = @import("../../providers/tables.zig").Challenges{ .offset = Q.one(), .coefficients = @splat(Q.one()) };
    const challenges = @import("../component.zig").Challenges{ .state = .{ .offset = Q.one(), .coefficients = @splat(Q.one()) }, .rom = .{ .offset = Q.one(), .coefficients = @splat(Q.one()) }, .bytes = Q.one(), .bitwise = typed, .shifts = typed };
    const claims = @import("../component.zig").Claims{ .state = zero, .rom = zero, .bytes = zero, .bitwise = zero, .shifts = zero };
    const size: usize = @as(usize, 1) << @intCast(log);
    const component = try Component.init(log, &plan, .{ .steps = @intCast(size - 1), .initial_pc = 0x1000, .final_pc = 0x2000 }, challenges, claims, .{});
    const total = frame.FIXED + component.mainCount() + component.interactionCount();
    const sources = try a.alloc(engine.air.component_prover.Poly, total);
    defer a.free(sources);
    const coefficients = try a.alloc(M, total * size);
    defer a.free(coefficients);
    const previous_columns = try a.alloc(bool, total);
    defer a.free(previous_columns);
    var prng = std.Random.DefaultPrng.init(0x5256504152414c4c);
    const rng = prng.random();
    for (sources, previous_columns, 0..) |*source, *previous, i| {
        const column = coefficients[i * size ..][0..size];
        for (column) |*value| value.* = M.fromCanonical(rng.int(u32) % core.fields.m31.Modulus);
        source.* = .{ .log_size = log + 1, .values = &.{}, .coefficients = try engine.poly.circle.CircleCoefficients.initBorrowed(column) };
        previous.* = if (i < frame.FIXED) false else if (i < frame.FIXED + component.mainCount()) component.needsPreviousMain(i - frame.FIXED) else component.needsPreviousInteraction(i - frame.FIXED - component.mainCount());
    }
    var evaluation = try cosets.Evaluation.init(a, sources, log, previous_columns);
    defer evaluation.deinit();
    const alpha = Q.fromU32Unchecked(2, 3, 5, 7);
    var serial = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, log + 2, component.constraint_count);
    defer serial.deinit();
    var pooled = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, log + 2, component.constraint_count);
    defer pooled.deinit();
    const serial_columns = try serial.columns(a, &.{.{ .log_size = log + 2, .n_cols = component.constraint_count }});
    defer a.free(serial_columns);
    const pooled_columns = try pooled.columns(a, &.{.{ .log_size = log + 2, .n_cols = component.constraint_count }});
    defer a.free(pooled_columns);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = parallel.MIN_STACK_BYTES, .backing_allocator = a });
    defer pool.deinit();
    // Repeat each complete wave: this must add to existing bucket values and
    // must not retain any pointer to a previous coset's scratch contents.
    for (0..2) |_| for (0..cosets.PARTS) |part| {
        try evaluation.evaluatePart(part);
        const inverse = try evaluation.denominatorInverse(part);
        try parallel.evaluatePart(&component, &evaluation, part, &serial_columns[0], inverse, null);
        try parallel.evaluatePart(&component, &evaluation, part, &pooled_columns[0], inverse, &pool);
        for (0..4 * size) |row| try std.testing.expect(serial_columns[0].col.at(row).eql(pooled_columns[0].col.at(row)));
    };
    // Reservation failure occurs before publication/submission. No background
    // helper may touch the bucket after the failure is returned.
    var competing = try pool.acquire(try engine.work_pool.WorkerBudget.init(3));
    const before = pooled_columns[0].col.at(0);
    try std.testing.expectError(error.WorkerBudgetUnavailable, parallel.evaluatePart(&component, &evaluation, 0, &pooled_columns[0], M.one(), &pool));
    competing.deinit();
    try std.testing.expect(before.eql(pooled_columns[0].col.at(0)));
    try std.testing.expectError(error.InvalidRv64ParallelShape, parallel.evaluatePart(&component, &evaluation, 4, &pooled_columns[0], M.one(), &pool));
    var small_stack_pool: engine.work_pool.WorkPool = undefined;
    try small_stack_pool.initInPlaceWithOptions(.{ .worker_count = 2, .stack_size = parallel.MIN_STACK_BYTES / 2, .backing_allocator = a });
    defer small_stack_pool.deinit();
    try std.testing.expectError(error.InvalidRv64ParallelStack, parallel.evaluatePart(&component, &evaluation, 0, &pooled_columns[0], M.one(), &small_stack_pool));
}
