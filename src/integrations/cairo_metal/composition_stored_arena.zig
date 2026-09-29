//! Native-height placement for the authenticated stored-domain AIR kernels.
const std = @import("std");
const frontend = @import("stwo_cairo_frontend");
const eval_arena = @import("composition_eval_arena.zig");
const pool_split = frontend.witness.pool_split;
const geometry = frontend.witness.resident_geometry;
const Component = frontend.witness.composition_bundle.Component;

pub const Plan = struct {
    layout: eval_arena.Plan,
    offsets: []u32,
    lengths: []u32,
    shifts: []u32,
    base_params: u32,

    pub fn deinit(self: *Plan, allocator: std.mem.Allocator) void {
        allocator.free(self.shifts);
        allocator.free(self.lengths);
        allocator.free(self.offsets);
        self.layout.deinit(allocator);
        self.* = undefined;
    }
};

/// Sizes come from the actual committed PCS columns, before device admission.
/// No workload labels, guessed claim sizes or proof-selected code enter this plan.
pub fn plan(allocator: std.mem.Allocator, component: Component, tree_logs: []const []u32) !Plan {
    var layout = try eval_arena.nativeGeometry(allocator, component);
    errdefer layout.deinit(allocator);
    const offsets = try allocator.alloc(u32, layout.columns);
    errdefer allocator.free(offsets);
    const lengths = try allocator.alloc(u32, layout.columns);
    errdefer allocator.free(lengths);
    const shifts = try allocator.alloc(u32, layout.columns);
    errdefer allocator.free(shifts);
    var next: u64 = 0;
    for (layout.bases, 0..) |base, interaction| {
        if (interaction >= tree_logs.len) return error.InvalidTraceShape;
        const end = if (interaction + 1 < layout.bases.len) layout.bases[interaction + 1] else layout.columns;
        for (base..end) |global| {
            const local = global - base;
            const column = if (interaction == 0) blk: {
                if (local >= component.preprocessed_indices.len) return error.InvalidTraceShape;
                break :blk component.preprocessed_indices[local];
            } else blk: {
                const span = try geometry.componentSpan(component, @intCast(interaction));
                if (local >= span.end - span.start) return error.InvalidTraceShape;
                break :blk span.start + local;
            };
            if (column >= tree_logs[interaction].len) return error.InvalidTraceShape;
            const log_size = tree_logs[interaction][column];
            if (log_size == 0 or log_size > component.evaluation_log_size or log_size >= 31)
                return error.InvalidTraceShape;
            lengths[global] = @as(u32, 1) << @intCast(log_size);
            offsets[global] = std.math.cast(u32, next) orelse return error.EvalArenaTooLarge;
            shifts[global] = component.evaluation_log_size - log_size + 1;
            next += lengths[global];
        }
    }
    layout.trace_offsets = try take(&next, layout.columns);
    layout.interaction_offsets = try take(&next, layout.interactions);
    const base_params = try take(&next, layout.columns);
    layout.ext_params = try take(&next, 4 * @as(u64, layout.ext_param_count));
    layout.random_coeffs = try take(&next, 4 * @as(u64, layout.coefficient_count));
    layout.denom_inv = try take(&next, layout.denominator_count);
    for (&layout.coordinates) |*offset| offset.* = try take(&next, layout.eval_rows);
    if (next > std.math.maxInt(u32)) return error.EvalArenaTooLarge;
    layout.words = next;
    return .{ .layout = layout, .offsets = offsets, .lengths = lengths, .shifts = shifts, .base_params = base_params };
}

fn take(next: *u64, count: u64) !u32 {
    const offset = std.math.cast(u32, next.*) orelse return error.EvalArenaTooLarge;
    next.* = try std.math.add(u64, next.*, count);
    return offset;
}

/// Native copies preserve the host's own lifting shifts, including mask reads
/// that wrap the circle domain. There is no evaluation-height expansion.
pub fn stage(words: []u32, planned: Plan, resolved: []const eval_arena.ResolvedScratch) !u64 {
    if (words.len < planned.layout.words or resolved.len != planned.layout.columns)
        return error.EvalArenaColumnShape;
    var copied: u64 = 0;
    for (resolved, planned.lengths, planned.shifts) |column, length, shift| {
        if (column.values.len != 0 and (column.values.len != length or column.shift_amt != shift))
            return error.EvalArenaColumnShape;
        copied += @as(u64, length) * @sizeOf(u32);
    }
    const worker_count = @min(resolved.len, pool_split.workerCount(.{
        .rows = @intCast(copied / @sizeOf(u32)),
        .min_rows_per_worker = 1 << 18,
    }));
    var workers: [pool_split.work_pool.MAX_WORKERS]CopyWork = undefined;
    for (workers[0..worker_count], 0..) |*worker, index| worker.* = .{
        .words = words,
        .planned = &planned,
        .resolved = resolved,
        .index = index,
        .count = worker_count,
    };
    try pool_split.dispatch(CopyWork, workers[0..worker_count]);
    @memcpy(words[planned.layout.trace_offsets..][0..planned.offsets.len], planned.offsets);
    @memcpy(words[planned.base_params..][0..planned.shifts.len], planned.shifts);
    return copied;
}

const CopyWork = struct {
    words: []u32,
    planned: *const Plan,
    resolved: []const eval_arena.ResolvedScratch,
    index: usize,
    count: usize,
    failure: ?anyerror = null,

    pub fn run(self: *CopyWork) void {
        var column_index = self.index;
        while (column_index < self.resolved.len) : (column_index += self.count) {
            const destination = self.words[self.planned.offsets[column_index]..][0..self.planned.lengths[column_index]];
            const source = self.resolved[column_index].values;
            if (source.len == 0) @memset(destination, 0) else @memcpy(destination, source);
        }
    }
};

const test_reads = [_]frontend.witness.eval_program.BaseInst{
    .{ .op = .preprocessed_col, .interaction = 0, .dst = 0, .a = 0, .b = 0, .imm = 0 },
    .{ .op = .trace_col, .interaction = 1, .dst = 1, .a = 0, .b = 0, .imm = -1 },
};
const test_denominators = [_]u32{ 1, 1, 1, 1 };
const test_spans = [_]frontend.witness.composition_bundle.TraceSpan{.{ .tree = 1, .start = 0, .end = 1 }};
const test_preprocessed = [_]u32{0};
const test_parts = [_]frontend.witness.composition_bundle.Part{.{
    .rc_base = 0,
    .semantic_hash = 0,
    .program = .{ .allocator = std.testing.allocator, .header = .{ .flags = 0, .semantic_hash = 0, .capability_bits = 0, .n_interactions = 2, .n_base_params = 0, .n_ext_params = 0, .n_constraints = 1, .max_base_regs = 2, .max_ext_regs = 0, .domain_log_size = 2 }, .base_consts = &.{}, .ext_consts = &.{}, .base_insts = @constCast(&test_reads), .ext_insts = &.{}, .constraint_roots = &.{} },
}};

fn testComponent() Component {
    return .{ .label = @constCast("stored-test"), .instance = 0, .trace_log_size = 2, .evaluation_log_size = 4, .n_constraints = 1, .random_coefficient_offset = 0, .trace_spans = @constCast(&test_spans), .preprocessed_indices = @constCast(&test_preprocessed), .denominator_inverses = @constCast(&test_denominators), .ext_sources = &.{}, .parts = @constCast(&test_parts) };
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    var logs0 = [_]u32{2};
    var logs1 = [_]u32{3};
    const logs = [_][]u32{ &logs0, &logs1 };
    var stored = try plan(allocator, testComponent(), &logs);
    defer stored.deinit(allocator);
    try std.testing.expectEqualSlices(u32, &.{ 4, 8 }, stored.lengths);
    try std.testing.expectEqualSlices(u32, &.{ 3, 2 }, stored.shifts);
}

test "stored composition planning cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}

test "stored composition staging preserves native lengths and rejects mismatched shifts" {
    var logs0 = [_]u32{2};
    var logs1 = [_]u32{3};
    const logs = [_][]u32{ &logs0, &logs1 };
    var stored = try plan(std.testing.allocator, testComponent(), &logs);
    defer stored.deinit(std.testing.allocator);
    const words = try std.testing.allocator.alloc(u32, @intCast(stored.layout.words));
    defer std.testing.allocator.free(words);
    @memset(words, 0);
    const short = [_]u32{ 3, 11, 19, 29 };
    const long = [_]u32{ 7, 13, 23, 31, 43, 53, 61, 71 };
    var resolved = [_]eval_arena.ResolvedScratch{
        .{ .values = &short, .shift_amt = 3 }, .{ .values = &long, .shift_amt = 2 },
    };
    try std.testing.expectEqual(@as(u64, 48), try stage(words, stored, &resolved));
    for (0..16) |row| {
        for (resolved, stored.offsets) |column, offset| {
            const index = eval_arena.liftedIndex(row, column.shift_amt);
            try std.testing.expectEqual(column.values[index], words[offset + index]);
        }
    }
    resolved[1].shift_amt = 1;
    try std.testing.expectError(error.EvalArenaColumnShape, stage(words, stored, &resolved));
    logs1[0] = 5;
    try std.testing.expectError(error.InvalidTraceShape, plan(std.testing.allocator, testComponent(), &logs));
}

test "stored composition does not inherit expanded column addressing limits" {
    var component = testComponent();
    component.trace_log_size = 17;
    component.evaluation_log_size = 20;
    var denominators = [_]u32{1} ** 8;
    component.denominator_inverses = &denominators;
    var indices: [4096]u32 = undefined;
    for (&indices, 0..) |*index, ordinal| index.* = @intCast(ordinal);
    component.preprocessed_indices = &indices;
    var reads = [_]frontend.witness.eval_program.BaseInst{test_reads[0]};
    reads[0].a = indices.len - 1;
    var parts = test_parts;
    parts[0].program.header.domain_log_size = 17;
    parts[0].program.header.n_interactions = 1;
    parts[0].program.base_insts = &reads;
    component.parts = &parts;
    var native_logs = [_]u32{2} ** 4096;
    const logs = [_][]u32{&native_logs};
    try std.testing.expectError(error.EvalArenaTooLarge, eval_arena.plan(std.testing.allocator, component));
    var stored = try plan(std.testing.allocator, component, &logs);
    defer stored.deinit(std.testing.allocator);
    try std.testing.expect(stored.layout.words < 5 * (1 << 20));
    try std.testing.expectEqual(@as(u32, 4), stored.lengths[4095]);
}
