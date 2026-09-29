//! Exact public preprocessed-trace variants from the pinned Stwo-Cairo source.

const std = @import("std");
const core = @import("stwo_core");
const columns = @import("columns.zig");
const pedersen_table = @import("pedersen_table.zig");
const prover = @import("stwo_prover_engine");
const work_pool = prover.work_pool;

const M31 = core.fields.m31.M31;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;

pub const Variant = @import("variant.zig").Variant;
const layout = @import("stwo_core").cairo_air_layout;

pub const Column = struct {
    identity: []u8,
    log_size: u32,
    source_ordinal: u32,
};

pub const Spec = struct {
    allocator: std.mem.Allocator,
    variant: Variant,
    columns: []Column,

    /// Owns the ordered ids of `stwo_core.cairo_air_layout.preprocessedColumns`,
    /// the one builder shared with circuit recursion.
    pub fn init(allocator: std.mem.Allocator, variant: Variant) !Spec {
        var ids: [layout.max_preprocessed_columns]layout.ColumnId = undefined;
        const sorted = try layout.preprocessedColumns(variant, &ids);
        const owned = try allocator.alloc(Column, sorted.len);
        var filled: usize = 0;
        errdefer {
            for (owned[0..filled]) |column| allocator.free(column.identity);
            allocator.free(owned);
        }
        for (sorted, owned) |*id, *column| {
            column.* = .{
                .identity = try allocator.dupe(u8, id.name()),
                .log_size = id.log_size,
                .source_ordinal = id.source_ordinal,
            };
            filled += 1;
        }
        const result = Spec{
            .allocator = allocator,
            .variant = variant,
            .columns = owned,
        };
        try result.validate();
        return result;
    }

    pub fn deinit(self: *Spec) void {
        for (self.columns) |column| self.allocator.free(column.identity);
        self.allocator.free(self.columns);
        self.* = undefined;
    }

    pub fn validate(self: Spec) !void {
        if (self.columns.len != self.variant.columnCount())
            return error.InvalidPreprocessedTrace;
        var cells: u64 = 0;
        var previous_log: u32 = 0;
        for (self.columns, 0..) |column, index| {
            if (column.identity.len == 0 or column.log_size < previous_log)
                return error.InvalidPreprocessedTrace;
            for (self.columns[0..index]) |previous| {
                if (std.mem.eql(u8, previous.identity, column.identity))
                    return error.InvalidPreprocessedTrace;
            }
            const rows = @as(u64, 1) << @intCast(column.log_size);
            cells = std.math.add(u64, cells, rows) catch
                return error.InvalidPreprocessedTrace;
            previous_log = column.log_size;
        }
        if (cells != self.variant.traceCellCount() or
            previous_log != self.variant.maxLogSize())
            return error.InvalidPreprocessedTrace;
    }

    pub fn logs(self: Spec, allocator: std.mem.Allocator) ![]u32 {
        const result = try allocator.alloc(u32, self.columns.len);
        for (self.columns, result) |column, *log_size| {
            log_size.* = column.log_size;
        }
        return result;
    }

    pub fn indexOf(self: Spec, identity: []const u8) ?u32 {
        for (self.columns, 0..) |column, index| {
            if (std.mem.eql(u8, column.identity, identity))
                return @intCast(index);
        }
        return null;
    }

    pub fn projectIndices(
        self: Spec,
        allocator: std.mem.Allocator,
        target: Spec,
        source_indices: []const u32,
    ) ![]u32 {
        const projected = try allocator.alloc(u32, source_indices.len);
        errdefer allocator.free(projected);
        for (source_indices, projected) |source_index, *target_index| {
            if (source_index >= self.columns.len)
                return error.InvalidPreprocessedColumnIndex;
            target_index.* = target.indexOf(self.columns[source_index].identity) orelse
                return error.PreprocessedColumnMissingFromVariant;
        }
        return projected;
    }

    pub fn materialize(self: Spec, allocator: std.mem.Allocator) ![]ColumnEvaluation {
        var pedersen: pedersen_table.Table = undefined;
        var has_pedersen = false;
        defer if (has_pedersen) pedersen.deinit();
        switch (self.variant) {
            .canonical_without_pedersen => {},
            .canonical => {
                pedersen = try pedersen_table.Table.init(allocator, .standard);
                has_pedersen = true;
            },
            .canonical_small => {
                pedersen = try pedersen_table.Table.init(allocator, .small);
                has_pedersen = true;
            },
        }
        return self.materializeWithPedersen(
            allocator,
            if (has_pedersen) &pedersen else null,
        );
    }

    pub fn materializeWithPedersen(
        self: Spec,
        allocator: std.mem.Allocator,
        pedersen: ?*const pedersen_table.Table,
    ) ![]ColumnEvaluation {
        return self.materializeColumnRangeWithPedersen(allocator, pedersen, 0, self.columns.len);
    }

    /// Materialize a sorted native-height batch without allocating the complete
    /// public source trace. Identity and field values are unchanged.
    pub fn materializeColumnRangeWithPedersen(self: Spec, allocator: std.mem.Allocator, pedersen: ?*const pedersen_table.Table, start: usize, end: usize) ![]ColumnEvaluation {
        if (start > end or end > self.columns.len) return error.InvalidPreprocessedTrace;
        var range = self;
        range.columns = self.columns[start..end];
        switch (self.variant) {
            .canonical_without_pedersen => if (pedersen != null)
                return error.InvalidPreprocessedTrace,
            .canonical => if (pedersen == null or pedersen.?.window != .standard)
                return error.InvalidPreprocessedTrace,
            .canonical_small => if (pedersen == null or pedersen.?.window != .small)
                return error.InvalidPreprocessedTrace,
        }
        const result = try allocator.alloc(ColumnEvaluation, range.columns.len);
        var initialized: usize = 0;
        errdefer {
            for (result[0..initialized]) |column| allocator.free(column.values);
            allocator.free(result);
        }
        for (range.columns, result) |column, *evaluation| {
            const rows = @as(usize, 1) << @intCast(column.log_size);
            const values = try allocator.alloc(M31, rows);
            errdefer allocator.free(values);
            evaluation.* = .{
                .log_size = column.log_size,
                .values = values,
            };
            initialized += 1;
        }
        try materializeValues(
            allocator,
            range,
            pedersen,
            result,
        );
        return result;
    }
};

const materialize_rows_per_task = 64 * 1024;

const MaterializeTask = struct {
    plan: ?columns.Plan,
    values: []M31,
    row_start: usize,
    row_end: usize,
    pedersen_column: ?usize,
};

const MaterializeWorker = struct {
    pedersen: ?*const pedersen_table.Table,
    tasks: []const MaterializeTask,
    next: *std.atomic.Value(usize),
    err: ?anyerror = null,

    fn run(self: *MaterializeWorker) void {
        while (true) {
            const task_index = self.next.fetchAdd(1, .monotonic);
            if (task_index >= self.tasks.len) return;
            const task = self.tasks[task_index];
            for (task.row_start..task.row_end) |row| {
                const raw = if (task.pedersen_column) |index|
                    self.pedersen.?.value(index, row) catch |err| {
                        self.err = err;
                        return;
                    }
                else
                    task.plan.?.value(@intCast(row)) catch |err| {
                        self.err = err;
                        return;
                    };
                task.values[row] = M31.fromCanonical(raw);
            }
        }
    }
};

fn materializeValues(
    allocator: std.mem.Allocator,
    spec: Spec,
    pedersen: ?*const pedersen_table.Table,
    evaluations: []ColumnEvaluation,
) !void {
    var tasks = std.ArrayList(MaterializeTask).empty;
    defer tasks.deinit(allocator);
    for (spec.columns, 0..) |column, column_index| {
        const pedersen_column = try pedersenColumn(column.identity);
        const plan = if (pedersen_column == null)
            try columns.Plan.init(column.identity)
        else
            null;
        const rows = evaluations[column_index].values.len;
        var row_start: usize = 0;
        while (row_start < rows) : (row_start += materialize_rows_per_task) {
            try tasks.append(allocator, .{
                .plan = plan,
                .values = @constCast(evaluations[column_index].values),
                .row_start = row_start,
                .row_end = @min(rows, row_start + materialize_rows_per_task),
                .pedersen_column = pedersen_column,
            });
        }
    }

    if (tasks.items.len == 0) return;

    const active_pool = work_pool.getGlobalPool();
    const worker_count = if (active_pool) |pool|
        @min(pool.workerCount(), tasks.items.len)
    else
        1;
    var next = std.atomic.Value(usize).init(0);
    const workers = try allocator.alloc(MaterializeWorker, worker_count);
    defer allocator.free(workers);
    for (workers) |*worker| worker.* = .{
        .pedersen = pedersen,
        .tasks = tasks.items,
        .next = &next,
    };

    if (worker_count > 1) {
        var wait_group = std.Thread.WaitGroup{};
        for (workers[1..]) |*worker| {
            active_pool.?.spawnWg(&wait_group, MaterializeWorker.run, .{worker});
        }
        MaterializeWorker.run(&workers[0]);
        wait_group.wait();
    } else {
        MaterializeWorker.run(&workers[0]);
    }
    for (workers) |worker| if (worker.err) |err| return err;
}

fn pedersenColumn(identity: []const u8) !?usize {
    const canonical_prefix = "pedersen_points_";
    const small_prefix = "pedersen_points_small_";
    const suffix = if (std.mem.startsWith(u8, identity, small_prefix))
        identity[small_prefix.len..]
    else if (std.mem.startsWith(u8, identity, canonical_prefix))
        identity[canonical_prefix.len..]
    else
        return null;
    const column = std.fmt.parseUnsigned(usize, suffix, 10) catch
        return error.InvalidPreprocessedTrace;
    if (column >= 56) return error.InvalidPreprocessedTrace;
    return column;
}

pub fn deinitMaterialized(
    allocator: std.mem.Allocator,
    evaluations: []ColumnEvaluation,
) void {
    for (evaluations) |evaluation| allocator.free(evaluation.values);
    allocator.free(evaluations);
}

test "official Cairo preprocessed variants preserve source geometry" {
    inline for (std.meta.tags(Variant)) |variant| {
        var spec = try Spec.init(std.testing.allocator, variant);
        defer spec.deinit();
        try std.testing.expectEqual(variant.columnCount(), spec.columns.len);
    }
}

test "official Cairo preprocessed indices project by identity" {
    var canonical = try Spec.init(std.testing.allocator, .canonical);
    defer canonical.deinit();
    var small = try Spec.init(std.testing.allocator, .canonical_small);
    defer small.deinit();

    const source = [_]u32{
        canonical.indexOf("seq_20").?,
        canonical.indexOf("blake_sigma_7").?,
        canonical.indexOf("range_check_9_9_column_1").?,
    };
    const projected = try canonical.projectIndices(
        std.testing.allocator,
        small,
        &source,
    );
    defer std.testing.allocator.free(projected);
    try std.testing.expectEqual(small.indexOf("seq_20").?, projected[0]);
    try std.testing.expectEqual(small.indexOf("blake_sigma_7").?, projected[1]);
    try std.testing.expectEqual(
        small.indexOf("range_check_9_9_column_1").?,
        projected[2],
    );
    const missing = [_]u32{canonical.indexOf("seq_25").?};
    try std.testing.expectError(
        error.PreprocessedColumnMissingFromVariant,
        canonical.projectIndices(std.testing.allocator, small, &missing),
    );
}

fn checkColumnRanges(a: std.mem.Allocator) !void {
    var metadata = [_]Column{
        .{ .identity = @constCast("seq_4"), .log_size = 4, .source_ordinal = 0 },
        .{ .identity = @constCast("seq_6"), .log_size = 6, .source_ordinal = 1 },
        .{ .identity = @constCast("bitwise_xor_4_0"), .log_size = 8, .source_ordinal = 2 },
        .{ .identity = @constCast("bitwise_xor_4_1"), .log_size = 8, .source_ordinal = 3 },
        .{ .identity = @constCast("bitwise_xor_4_2"), .log_size = 8, .source_ordinal = 4 },
    };
    const spec = Spec{ .allocator = a, .variant = .canonical_without_pedersen, .columns = &metadata };
    const complete = try spec.materializeWithPedersen(a, null);
    defer {
        for (complete) |column| a.free(column.values);
        a.free(complete);
    }
    const boundaries = [_]usize{ 0, 1, 3, 5 };
    for (boundaries[0 .. boundaries.len - 1], boundaries[1..]) |start, end| {
        const batch = try spec.materializeColumnRangeWithPedersen(a, null, start, end);
        defer {
            for (batch) |column| a.free(column.values);
            a.free(batch);
        }
        for (batch, complete[start..end], metadata[start..end]) |actual, expected, source| {
            try std.testing.expectEqual(expected.log_size, actual.log_size);
            try std.testing.expectEqualSlices(M31, expected.values, actual.values);
            const plan = try columns.Plan.init(source.identity);
            for (actual.values, 0..) |value, row|
                try std.testing.expectEqual(try plan.value(@intCast(row)), value.v);
        }
    }
    try std.testing.expectError(error.InvalidPreprocessedTrace, spec.materializeColumnRangeWithPedersen(a, null, 4, 3));
    try std.testing.expectError(error.InvalidPreprocessedTrace, spec.materializeColumnRangeWithPedersen(a, null, 0, 6));
}

test "Cairo preprocessed source batching preserves identities and values across mixed heights" {
    try checkColumnRanges(std.testing.allocator);
}
test "Cairo preprocessed source batching cleans up every materialization allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkColumnRanges, .{});
}
