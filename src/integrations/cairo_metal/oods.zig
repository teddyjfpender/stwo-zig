const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const metal_runtime = @import("stwo_metal_backend").runtime;
const composition_bundle = @import("stwo_cairo_frontend").witness.composition_bundle;
const eval_program = @import("stwo_cairo_frontend").witness.eval_program;
const circle = @import("stwo_core").circle;
const canonic = @import("stwo_core").poly.circle.canonic;
const circle_poly = @import("stwo_prover_engine").poly.circle.poly;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const Telemetry = struct {
    wall_ms: f64,
    gpu_ms: f64,
    sample_count: usize,
    column_count: usize,
};

const Task = struct {
    coefficients: circle_poly.CircleCoefficients,
    point_start: usize,
    point_count: usize,
    output_start: usize,
};

const Worker = struct {
    tasks: []const Task,
    points: []const circle.CirclePointQM31,
    output: []QM31,
    next: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    fn run(self: *Worker) void {
        while (true) {
            const task_index = self.next.fetchAdd(1, .monotonic);
            if (task_index >= self.tasks.len) return;
            const task = self.tasks[task_index];
            const points = self.points[task.point_start .. task.point_start + task.point_count];
            const output = self.output[task.output_start .. task.output_start + task.point_count];
            for (points, output) |point, *value| value.* = task.coefficients.evalAtPoint(point);
        }
    }
};

const MetalPlan = struct {
    coeff_log_size: u32,
    normalized_points: []circle.CirclePointQM31,
    flat_factors: []QM31,
    column_indices: std.ArrayList(usize) = .empty,

    fn deinit(self: *MetalPlan, allocator: std.mem.Allocator) void {
        allocator.free(self.normalized_points);
        allocator.free(self.flat_factors);
        self.column_indices.deinit(allocator);
        self.* = undefined;
    }
};

const PreparedMetalEvaluation = struct {
    coefficients: []circle_poly.CircleCoefficients,
    tree_values: [][]QM31,
    plans: std.ArrayList(MetalPlan),

    fn deinit(self: *PreparedMetalEvaluation, allocator: std.mem.Allocator) void {
        allocator.free(self.coefficients);
        allocator.free(self.tree_values);
        for (self.plans.items) |*plan| plan.deinit(allocator);
        self.plans.deinit(allocator);
        self.* = undefined;
    }
};

/// Reconstructs the canonical Cairo mask from the captured evaluation programs
/// and evaluates every OODS sample directly from resident circle coefficients.
/// The destination is the exact flattened QM31 payload mixed at transcript
/// ordinal 25.
pub fn populate(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    bundle: composition_bundle.Bundle,
    preprocessed: []const arena_plan.Binding,
    base: []const arena_plan.Binding,
    interaction: []const arena_plan.Binding,
    composition: []const arena_plan.Binding,
    challenge: arena_plan.Binding,
    destination: arena_plan.Binding,
) !Telemetry {
    if (composition.len != 8 or challenge.size_bytes < 16 or destination.size_bytes % 16 != 0)
        return error.InvalidOodsShape;
    const max_log_degree_bound = bundle.verifierMaxLogDegreeBound() catch
        return error.InvalidOodsShape;

    const challenge_words = try bindingWords(resident_arena, challenge);
    const parameter = QM31.fromU32Unchecked(
        challenge_words[0],
        challenge_words[1],
        challenge_words[2],
        challenge_words[3],
    );
    const oods_point = try pointFromParameter(parameter);
    const trace_step_m31 = canonic.CanonicCoset.new(max_log_degree_bound).step();
    const trace_step = circle.CirclePointQM31{
        .x = QM31.fromBase(trace_step_m31.x),
        .y = QM31.fromBase(trace_step_m31.y),
    };

    const preprocessed_used = try allocator.alloc(bool, preprocessed.len);
    defer allocator.free(preprocessed_used);
    @memset(preprocessed_used, false);
    const base_offsets = try allocateOffsetLists(allocator, base.len);
    defer freeOffsetLists(allocator, base_offsets);
    const interaction_offsets = try allocateOffsetLists(allocator, interaction.len);
    defer freeOffsetLists(allocator, interaction_offsets);

    for (bundle.components) |component| {
        const base_span = try componentSpan(component, 1, base.len);
        const interaction_span = try componentSpan(component, 2, interaction.len);
        for (component.parts) |part| {
            for (part.program.base_insts) |instruction| switch (instruction.op) {
                .preprocessed_col => {
                    if (instruction.a >= component.preprocessed_indices.len) return error.InvalidOodsMask;
                    const column = component.preprocessed_indices[instruction.a];
                    if (column >= preprocessed_used.len) return error.InvalidOodsMask;
                    preprocessed_used[column] = true;
                },
                .trace_col => switch (instruction.interaction) {
                    0 => {
                        if (instruction.a >= component.preprocessed_indices.len) return error.InvalidOodsMask;
                        const column = component.preprocessed_indices[instruction.a];
                        if (column >= preprocessed_used.len) return error.InvalidOodsMask;
                        preprocessed_used[column] = true;
                    },
                    1 => try appendUnique(
                        allocator,
                        &base_offsets[base_span.start + instruction.a],
                        instruction.imm,
                        base_span,
                        instruction.a,
                    ),
                    2 => try appendUnique(
                        allocator,
                        &interaction_offsets[interaction_span.start + instruction.a],
                        instruction.imm,
                        interaction_span,
                        instruction.a,
                    ),
                    else => return error.InvalidOodsMask,
                },
                else => {},
            };
        }
    }

    var points = std.ArrayList(circle.CirclePointQM31).empty;
    defer points.deinit(allocator);
    var tasks = std.ArrayList(Task).empty;
    defer tasks.deinit(allocator);
    var output_cursor: usize = 0;

    for (preprocessed, preprocessed_used) |binding, used| {
        if (!used) continue;
        try appendTask(
            resident_arena,
            &points,
            &tasks,
            allocator,
            binding,
            &.{oods_point},
            &output_cursor,
            max_log_degree_bound,
        );
    }
    try appendTreeTasks(
        resident_arena,
        &points,
        &tasks,
        allocator,
        base,
        base_offsets,
        oods_point,
        trace_step,
        &output_cursor,
        max_log_degree_bound,
    );
    try appendTreeTasks(
        resident_arena,
        &points,
        &tasks,
        allocator,
        interaction,
        interaction_offsets,
        oods_point,
        trace_step,
        &output_cursor,
        max_log_degree_bound,
    );
    for (composition) |binding| try appendTask(
        resident_arena,
        &points,
        &tasks,
        allocator,
        binding,
        &.{oods_point},
        &output_cursor,
        max_log_degree_bound,
    );

    const destination_bytes: []align(@alignOf(QM31)) u8 = @alignCast(try resident_arena.bytes(destination));
    const output = std.mem.bytesAsSlice(QM31, destination_bytes);
    if (output_cursor != output.len or points.items.len != output.len) {
        std.debug.print(
            "OODS shape mismatch: derived_samples={} scheduled_samples={} tasks={}\n",
            .{ output_cursor, output.len, tasks.items.len },
        );
        return error.InvalidOodsShape;
    }
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_OODS_TASKS")) {
        for (tasks.items, 0..) |task, task_index| std.debug.print(
            "oods_task index={} coefficient_log={} point_start={} point_count={} output_start={}\n",
            .{
                task_index,
                task.coefficients.logSize(),
                task.point_start,
                task.point_count,
                task.output_start,
            },
        );
    }

    var timer = try std.time.Timer.start();
    const gpu_ms = if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_OODS_CPU")) blk: {
        var worker = Worker{ .tasks = tasks.items, .points = points.items, .output = output };
        const cpu_count = std.Thread.getCpuCount() catch 1;
        const worker_count = @min(@min(cpu_count, tasks.items.len), 64);
        var threads: [63]std.Thread = undefined;
        var spawned: usize = 0;
        while (spawned + 1 < worker_count) : (spawned += 1) {
            threads[spawned] = std.Thread.spawn(.{}, Worker.run, .{&worker}) catch break;
        }
        worker.run();
        for (threads[0..spawned]) |thread| thread.join();
        break :blk 0;
    } else try evaluateMetal(
        allocator,
        metal,
        tasks.items,
        points.items,
        output,
    );

    return .{
        .wall_ms = @as(f64, @floatFromInt(timer.read())) / std.time.ns_per_ms,
        .gpu_ms = gpu_ms,
        .sample_count = output.len,
        .column_count = tasks.items.len,
    };
}

fn evaluateMetal(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    tasks: []const Task,
    points: []const circle.CirclePointQM31,
    output: []QM31,
) !f64 {
    var prepared = try prepareMetalEvaluation(allocator, tasks, points, output);
    defer prepared.deinit(allocator);

    return metal.evaluateCoefficientPlansUnprofiled(
        allocator,
        prepared.coefficients,
        prepared.tree_values,
        prepared.plans.items,
    );
}

fn prepareMetalEvaluation(
    allocator: std.mem.Allocator,
    tasks: []const Task,
    points: []const circle.CirclePointQM31,
    output: []QM31,
) !PreparedMetalEvaluation {
    const coefficients = try allocator.alloc(circle_poly.CircleCoefficients, tasks.len);
    errdefer allocator.free(coefficients);
    const tree_values = try allocator.alloc([]QM31, tasks.len);
    errdefer allocator.free(tree_values);
    var plans = std.ArrayList(MetalPlan).empty;
    errdefer {
        for (plans.items) |*plan| plan.deinit(allocator);
        plans.deinit(allocator);
    }

    for (tasks, 0..) |task, column_index| {
        coefficients[column_index] = task.coefficients;
        const task_points = points[task.point_start .. task.point_start + task.point_count];
        tree_values[column_index] = output[task.output_start .. task.output_start + task.point_count];
        const log_size = task.coefficients.logSize();
        var plan_index: ?usize = null;
        for (plans.items, 0..) |plan, index| {
            if (plan.coeff_log_size != log_size or plan.normalized_points.len != task_points.len)
                continue;
            var matches = true;
            for (plan.normalized_points, task_points) |lhs, rhs| matches = matches and lhs.eql(rhs);
            if (matches) {
                plan_index = index;
                break;
            }
        }
        if (plan_index == null) {
            const owned_points = try allocator.dupe(circle.CirclePointQM31, task_points);
            errdefer allocator.free(owned_points);
            const factors = try allocator.alloc(QM31, task_points.len * log_size);
            errdefer allocator.free(factors);
            var factor_buffer: [circle.M31_CIRCLE_LOG_ORDER]QM31 = undefined;
            for (task_points, 0..) |point, point_index| {
                const point_factors = circle_poly.fillEvalFactorsForPoint(point, log_size, &factor_buffer);
                @memcpy(factors[point_index * log_size ..][0..log_size], point_factors);
            }
            try plans.append(allocator, .{
                .coeff_log_size = log_size,
                .normalized_points = owned_points,
                .flat_factors = factors,
            });
            plan_index = plans.items.len - 1;
        }
        try plans.items[plan_index.?].column_indices.append(allocator, column_index);
    }

    return .{
        .coefficients = coefficients,
        .tree_values = tree_values,
        .plans = plans,
    };
}

const Span = struct { start: usize, end: usize };

fn componentSpan(component: composition_bundle.Component, tree: u32, tree_len: usize) !Span {
    var found: ?Span = null;
    for (component.trace_spans) |span| {
        if (span.tree != tree) continue;
        if (found != null or span.start > span.end or span.end > tree_len) return error.InvalidOodsMask;
        found = .{ .start = span.start, .end = span.end };
    }
    return found orelse error.InvalidOodsMask;
}

fn allocateOffsetLists(allocator: std.mem.Allocator, count: usize) ![]std.ArrayList(i32) {
    const lists = try allocator.alloc(std.ArrayList(i32), count);
    for (lists) |*list| list.* = .empty;
    return lists;
}

fn freeOffsetLists(allocator: std.mem.Allocator, lists: []std.ArrayList(i32)) void {
    for (lists) |*list| list.deinit(allocator);
    allocator.free(lists);
}

fn appendUnique(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(i32),
    offset: i32,
    span: Span,
    local_column: u32,
) !void {
    if (local_column >= span.end - span.start) return error.InvalidOodsMask;
    for (list.items) |existing| if (existing == offset) return;
    try list.append(allocator, offset);
}

fn appendTreeTasks(
    resident_arena: *arena_plan.ResidentArena,
    points: *std.ArrayList(circle.CirclePointQM31),
    tasks: *std.ArrayList(Task),
    allocator: std.mem.Allocator,
    bindings: []const arena_plan.Binding,
    offsets: []const std.ArrayList(i32),
    oods_point: circle.CirclePointQM31,
    trace_step: circle.CirclePointQM31,
    output_cursor: *usize,
    max_log_degree_bound: u32,
) !void {
    if (bindings.len != offsets.len) return error.InvalidOodsShape;
    var column_points = std.ArrayList(circle.CirclePointQM31).empty;
    defer column_points.deinit(allocator);
    for (bindings, offsets) |binding, column_offsets| {
        column_points.clearRetainingCapacity();
        for (column_offsets.items) |offset| try column_points.append(
            allocator,
            oods_point.add(trace_step.mulSigned(offset)),
        );
        if (column_points.items.len == 0) return error.InvalidOodsMask;
        try appendTask(
            resident_arena,
            points,
            tasks,
            allocator,
            binding,
            column_points.items,
            output_cursor,
            max_log_degree_bound,
        );
    }
}

fn appendTask(
    resident_arena: *arena_plan.ResidentArena,
    points: *std.ArrayList(circle.CirclePointQM31),
    tasks: *std.ArrayList(Task),
    allocator: std.mem.Allocator,
    binding: arena_plan.Binding,
    sample_points: []const circle.CirclePointQM31,
    output_cursor: *usize,
    max_log_degree_bound: u32,
) !void {
    const words = try bindingWords(resident_arena, binding);
    const coefficients = std.mem.bytesAsSlice(M31, std.mem.sliceAsBytes(words));
    const polynomial = try circle_poly.CircleCoefficients.initBorrowed(coefficients);
    const point_start = points.items.len;
    const fold_count = try oodsFoldCount(max_log_degree_bound, polynomial.logSize());
    for (sample_points) |point| try points.append(allocator, point.repeatedDouble(fold_count));
    try tasks.append(allocator, .{
        .coefficients = polynomial,
        .point_start = point_start,
        .point_count = sample_points.len,
        .output_start = output_cursor.*,
    });
    output_cursor.* += sample_points.len;
}

fn oodsFoldCount(max_log_degree_bound: u32, coefficient_log_size: u32) !u32 {
    if (coefficient_log_size > max_log_degree_bound) return error.InvalidOodsShape;
    return max_log_degree_bound - coefficient_log_size;
}

fn bindingWords(resident_arena: *arena_plan.ResidentArena, binding: arena_plan.Binding) ![]align(4) u32 {
    const bytes: []align(4) u8 = @alignCast(try resident_arena.bytes(binding));
    if (bytes.len % 4 != 0) return error.InvalidOodsShape;
    return std.mem.bytesAsSlice(u32, bytes);
}

fn pointFromParameter(parameter: QM31) !circle.CirclePointQM31 {
    const square = parameter.square();
    const inverse = square.add(QM31.one()).inv() catch return error.InvalidOodsPoint;
    return .{
        .x = QM31.one().sub(square).mul(inverse),
        .y = parameter.add(parameter).mul(inverse),
    };
}

test "metal: SN2 captured programs reconstruct the exact OODS sample cardinality" {
    var bundle = try composition_bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer bundle.deinit();

    var preprocessed_used = [_]bool{false} ** 161;
    const base_offsets = try allocateOffsetLists(std.testing.allocator, 3449);
    defer freeOffsetLists(std.testing.allocator, base_offsets);
    const interaction_offsets = try allocateOffsetLists(std.testing.allocator, 2268);
    defer freeOffsetLists(std.testing.allocator, interaction_offsets);
    for (bundle.components) |component| {
        const base_span = try componentSpan(component, 1, base_offsets.len);
        const interaction_span = try componentSpan(component, 2, interaction_offsets.len);
        for (component.parts) |part| for (part.program.base_insts) |instruction| switch (instruction.op) {
            .preprocessed_col => preprocessed_used[component.preprocessed_indices[instruction.a]] = true,
            .trace_col => switch (instruction.interaction) {
                0 => preprocessed_used[component.preprocessed_indices[instruction.a]] = true,
                1 => try appendUnique(std.testing.allocator, &base_offsets[base_span.start + instruction.a], instruction.imm, base_span, instruction.a),
                2 => try appendUnique(std.testing.allocator, &interaction_offsets[interaction_span.start + instruction.a], instruction.imm, interaction_span, instruction.a),
                else => return error.InvalidOodsMask,
            },
            else => {},
        };
    }
    var count: usize = 8;
    for (preprocessed_used) |used| count += @intFromBool(used);
    for (base_offsets) |offsets| count += offsets.items.len;
    for (interaction_offsets) |offsets| count += offsets.items.len;
    try std.testing.expectEqual(@as(usize, 6110), count);
}

test "metal: OODS folds coefficient domains to the maximum degree bound" {
    // Legacy v1 commits the split composition at log 23 under verifier max 24.
    try std.testing.expectEqual(@as(u32, 1), try oodsFoldCount(24, 23));
    // Projected v2 Fib commits log-20 coefficients under verifier max 20.
    try std.testing.expectEqual(@as(u32, 0), try oodsFoldCount(20, 20));
    try std.testing.expectEqual(@as(u32, 8), try oodsFoldCount(24, 16));
    try std.testing.expectError(error.InvalidOodsShape, oodsFoldCount(20, 21));
}

test "metal: OODS plans preserve grouped multi-point output order and scalar parity" {
    const allocator = std.testing.allocator;
    const p0_m31 = canonic.CanonicCoset.new(5).at(0);
    const p1_m31 = canonic.CanonicCoset.new(5).at(3);
    const p0 = circle.CirclePointQM31{
        .x = QM31.fromBase(p0_m31.x),
        .y = QM31.fromBase(p0_m31.y),
    };
    const p1 = circle.CirclePointQM31{
        .x = QM31.fromBase(p1_m31.x),
        .y = QM31.fromBase(p1_m31.y),
    };

    const coeffs0 = [_]M31{
        M31.fromCanonical(2),
        M31.fromCanonical(3),
        M31.fromCanonical(5),
        M31.fromCanonical(7),
    };
    const coeffs1 = [_]M31{ M31.fromCanonical(11), M31.fromCanonical(13) };
    const coeffs2 = [_]M31{
        M31.fromCanonical(17),
        M31.fromCanonical(19),
        M31.fromCanonical(23),
        M31.fromCanonical(29),
    };
    const coeffs3 = [_]M31{
        M31.fromCanonical(31),
        M31.fromCanonical(37),
        M31.fromCanonical(41),
        M31.fromCanonical(43),
    };
    const tasks = [_]Task{
        .{
            .coefficients = try circle_poly.CircleCoefficients.initBorrowed(&coeffs0),
            .point_start = 0,
            .point_count = 2,
            .output_start = 0,
        },
        .{
            .coefficients = try circle_poly.CircleCoefficients.initBorrowed(&coeffs1),
            .point_start = 2,
            .point_count = 1,
            .output_start = 2,
        },
        .{
            .coefficients = try circle_poly.CircleCoefficients.initBorrowed(&coeffs2),
            .point_start = 3,
            .point_count = 2,
            .output_start = 3,
        },
        .{
            .coefficients = try circle_poly.CircleCoefficients.initBorrowed(&coeffs3),
            .point_start = 5,
            .point_count = 2,
            .output_start = 5,
        },
    };
    const points = [_]circle.CirclePointQM31{
        p0, p1,
        p0, p0,
        p1, p1,
        p0,
    };
    var output = [_]QM31{QM31.zero()} ** points.len;

    var prepared = try prepareMetalEvaluation(allocator, &tasks, &points, &output);
    defer prepared.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 3), prepared.plans.items.len);
    try std.testing.expectEqualSlices(usize, &.{ 0, 2 }, prepared.plans.items[0].column_indices.items);
    try std.testing.expectEqualSlices(usize, &.{1}, prepared.plans.items[1].column_indices.items);
    try std.testing.expectEqualSlices(usize, &.{3}, prepared.plans.items[2].column_indices.items);
    try std.testing.expectEqual(@as(u32, 2), prepared.plans.items[0].coeff_log_size);
    try std.testing.expectEqual(@as(u32, 1), prepared.plans.items[1].coeff_log_size);
    try std.testing.expect(prepared.plans.items[0].normalized_points[0].eql(p0));
    try std.testing.expect(prepared.plans.items[0].normalized_points[1].eql(p1));
    try std.testing.expect(prepared.plans.items[2].normalized_points[0].eql(p1));
    try std.testing.expect(prepared.plans.items[2].normalized_points[1].eql(p0));

    var expected_factors: [circle.M31_CIRCLE_LOG_ORDER]QM31 = undefined;
    const p0_factors = circle_poly.fillEvalFactorsForPoint(p0, 2, &expected_factors);
    for (p0_factors, prepared.plans.items[0].flat_factors[0..2]) |expected, actual|
        try std.testing.expect(expected.eql(actual));
    const p1_factors = circle_poly.fillEvalFactorsForPoint(p1, 2, &expected_factors);
    for (p1_factors, prepared.plans.items[0].flat_factors[2..4]) |expected, actual|
        try std.testing.expect(expected.eql(actual));

    // Run the exact plan layout through the scalar evaluator. This isolates
    // grouping and destination placement from the Metal runtime itself.
    for (prepared.plans.items) |plan| {
        for (plan.column_indices.items) |column_index| {
            for (0..plan.normalized_points.len) |point_index| {
                const factor_start = point_index * plan.coeff_log_size;
                prepared.tree_values[column_index][point_index] =
                    prepared.coefficients[column_index].evalAtPointWithFactors(
                        plan.flat_factors[factor_start..][0..plan.coeff_log_size],
                    );
            }
        }
    }

    for (tasks) |task| {
        const task_points = points[task.point_start .. task.point_start + task.point_count];
        for (task_points, 0..) |point, point_index| {
            const expected = task.coefficients.evalAtPoint(point);
            try std.testing.expect(expected.eql(output[task.output_start + point_index]));
        }
    }
}
