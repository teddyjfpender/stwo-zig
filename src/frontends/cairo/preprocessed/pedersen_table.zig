//! Canonical Stwo-Cairo Pedersen preprocessed-table generation.
//!
//! Rows are produced in the official block order. Each block uses projective
//! additions followed by one batch inversion, so curve points are computed
//! once per row rather than once per encoded limb.

const std = @import("std");
const felt252 = @import("../witness/deductions/felt252.zig");
const stark_curve = @import("../witness/deductions/stark_curve.zig");
const parameters = @import("../witness/deductions/pedersen.zig");

pub const Window = enum(u5) {
    small = 9,
    standard = 18,

    pub fn bits(self: Window) u5 {
        return @intFromEnum(self);
    }

    pub fn rowCount(self: Window) u32 {
        const raw = (@as(u32, 2) * 252 / self.bits()) << self.bits();
        return std.math.ceilPowerOfTwo(u32, raw) catch unreachable;
    }
};

pub const Error = stark_curve.Error || felt252.Error || error{
    AllocationSizeOverflow,
    InvalidColumn,
    InvalidRow,
    OutOfMemory,
    ThreadSpawnFailed,
};

pub const Options = struct {
    /// Zero selects the host's logical CPU count, bounded by `max_workers`.
    worker_count: u8 = 0,
};

pub const Table = struct {
    allocator: std.mem.Allocator,
    window: Window,
    points: []stark_curve.AffinePoint,

    pub fn init(allocator: std.mem.Allocator, window: Window) Error!Table {
        return initWithOptions(allocator, window, .{});
    }

    pub fn initWithOptions(
        allocator: std.mem.Allocator,
        window: Window,
        options: Options,
    ) Error!Table {
        const points = try allocator.alloc(stark_curve.AffinePoint, window.rowCount());
        errdefer allocator.free(points);
        try fill(allocator, window, points, options.worker_count);
        return .{ .allocator = allocator, .window = window, .points = points };
    }

    pub fn deinit(self: *Table) void {
        self.allocator.free(self.points);
        self.* = undefined;
    }

    pub fn rowCount(self: Table) usize {
        return self.points.len;
    }

    pub fn value(self: Table, column: usize, row: usize) Error!u32 {
        if (column >= 2 * felt252.word_count) return error.InvalidColumn;
        if (row >= self.points.len) return error.InvalidRow;
        const point = self.points[row];
        return if (column < felt252.word_count)
            felt252.wordAt(point.x, column)
        else
            felt252.wordAt(point.y, column - felt252.word_count);
    }
};

const max_workers = 32;
const max_rows_per_plan = 64 * 1024;

const BlockPlan = struct {
    start: stark_curve.ProjectivePoint,
    step: stark_curve.AffinePoint,
    first_row: usize,
    row_count: usize,
};

const Workspace = struct {
    allocator: std.mem.Allocator,
    projective: []stark_curve.ProjectivePoint,
    prefixes: []u256,

    fn init(allocator: std.mem.Allocator, rows: usize) !Workspace {
        const projective = try allocator.alloc(stark_curve.ProjectivePoint, rows);
        errdefer allocator.free(projective);
        const prefixes = try allocator.alloc(u256, rows);
        errdefer allocator.free(prefixes);
        return .{
            .allocator = allocator,
            .projective = projective,
            .prefixes = prefixes,
        };
    }

    fn deinit(self: *Workspace) void {
        self.allocator.free(self.prefixes);
        self.allocator.free(self.projective);
        self.* = undefined;
    }

    fn block(
        self: *Workspace,
        start: stark_curve.ProjectivePoint,
        step: stark_curve.AffinePoint,
        destination: []stark_curve.AffinePoint,
    ) Error!void {
        std.debug.assert(destination.len <= self.projective.len);
        var point = start;
        for (self.projective[0..destination.len]) |*slot| {
            slot.* = point;
            try stark_curve.add(&point, step);
        }
        try stark_curve.batchToAffine(
            self.projective[0..destination.len],
            self.prefixes[0..destination.len],
            destination,
        );
    }
};

fn fill(
    allocator: std.mem.Allocator,
    window: Window,
    destination: []stark_curve.AffinePoint,
    worker_count: u8,
) Error!void {
    std.debug.assert(destination.len == window.rowCount());
    const plans = try allocator.alloc(BlockPlan, blockPlanCount(window));
    defer allocator.free(plans);
    const block_count = try planBlocks(window, plans);
    const detected_workers = std.Thread.getCpuCount() catch 1;
    const active_workers = resolveWorkerCount(
        worker_count,
        detected_workers,
        block_count,
    );
    const workspace_rows = @min(
        @as(usize, 1) << window.bits(),
        max_rows_per_plan,
    );

    var workspaces: [max_workers]Workspace = undefined;
    var initialized_workspaces: usize = 0;
    defer for (workspaces[0..initialized_workspaces]) |*workspace| workspace.deinit();
    while (initialized_workspaces < active_workers) : (initialized_workspaces += 1)
        workspaces[initialized_workspaces] = try Workspace.init(allocator, workspace_rows);

    var workers: [max_workers]Worker = undefined;
    var next_plan = std.atomic.Value(usize).init(0);
    for (workers[0..active_workers], 0..) |*worker, index| worker.* = .{
        .workspace = &workspaces[index],
        .plans = plans[0..block_count],
        .destination = destination,
        .next_plan = &next_plan,
    };

    var threads: [max_workers - 1]std.Thread = undefined;
    var spawned: usize = 0;
    while (spawned + 1 < active_workers) : (spawned += 1) {
        threads[spawned] = std.Thread.spawn(
            .{},
            Worker.run,
            .{&workers[spawned + 1]},
        ) catch {
            for (threads[0..spawned]) |thread| thread.join();
            return error.ThreadSpawnFailed;
        };
    }
    workers[0].run();
    for (threads[0..spawned]) |thread| thread.join();
    for (workers[0..active_workers]) |worker|
        if (worker.failure) |failure| return failure;

    const real_rows = (@as(usize, 2) * 252 / @as(usize, window.bits())) <<
        window.bits();
    for (destination[real_rows..]) |*point| point.* = parameters.negative_shift;
}

fn resolveWorkerCount(
    requested_workers: u8,
    detected_workers: usize,
    block_count: usize,
) usize {
    const available = if (requested_workers == 0)
        @max(@as(usize, 1), detected_workers)
    else
        @as(usize, requested_workers);
    return @min(@min(available, max_workers), block_count);
}

const Worker = struct {
    workspace: *Workspace,
    plans: []const BlockPlan,
    destination: []stark_curve.AffinePoint,
    next_plan: *std.atomic.Value(usize),
    failure: ?Error = null,

    fn run(self: *Worker) void {
        while (true) {
            const plan_index = self.next_plan.fetchAdd(1, .monotonic);
            if (plan_index >= self.plans.len) return;
            const plan = self.plans[plan_index];
            self.workspace.block(
                plan.start,
                plan.step,
                self.destination[plan.first_row..][0..plan.row_count],
            ) catch |failure| {
                self.failure = failure;
                return;
            };
        }
    }
};

fn blockPlanCount(window: Window) usize {
    const windows = 252 / @as(usize, window.bits());
    const rows_per_window: usize = @as(usize, 1) << window.bits();
    const high_rows: usize = @as(usize, 1) << (window.bits() - 4);
    return 2 *
        ((windows - 1) * ((rows_per_window + max_rows_per_plan - 1) / max_rows_per_plan) +
            16 * ((high_rows + max_rows_per_plan - 1) / max_rows_per_plan));
}

fn planBlocks(window: Window, plans: []BlockPlan) Error!usize {
    const bits: usize = window.bits();
    const windows = 252 / bits;
    const rows_per_window: usize = @as(usize, 1) << @intCast(bits);
    const high_rows: usize = @as(usize, 1) << @intCast(bits - 4);
    var cursor: usize = 0;
    var block_count: usize = 0;

    inline for (.{ .{ parameters.p0, parameters.p1 }, .{ parameters.p2, parameters.p3 } }) |pair| {
        var step = stark_curve.projectiveFromAffine(pair[0]);
        for (0..windows - 1) |_| {
            try appendBlockPlans(
                plans,
                &block_count,
                &cursor,
                parameters.negative_shift,
                try stark_curve.projectiveToAffine(step),
                rows_per_window,
            );
            for (0..bits) |_| try stark_curve.double(&step);
        }

        const raised_low = try stark_curve.scaleByPowerOfTwo(
            pair[0],
            (windows - 1) * bits,
        );
        for (0..16) |high_multiplier| {
            const start = try stark_curve.tableCombination(
                pair[1],
                high_multiplier,
                null,
                0,
                parameters.negative_shift,
            );
            try appendBlockPlans(
                plans,
                &block_count,
                &cursor,
                start,
                raised_low,
                high_rows,
            );
        }
    }
    std.debug.assert(block_count == plans.len);
    return block_count;
}

fn appendBlockPlans(
    plans: []BlockPlan,
    block_count: *usize,
    cursor: *usize,
    start: stark_curve.AffinePoint,
    step: stark_curve.AffinePoint,
    row_count: usize,
) Error!void {
    var chunk_start = stark_curve.projectiveFromAffine(start);
    const chunk_step = if (row_count > max_rows_per_plan)
        try stark_curve.scaleByPowerOfTwo(
            step,
            std.math.log2_int(usize, max_rows_per_plan),
        )
    else
        undefined;
    var remaining = row_count;
    while (remaining != 0) {
        const chunk_rows = @min(remaining, max_rows_per_plan);
        plans[block_count.*] = .{
            .start = chunk_start,
            .step = step,
            .first_row = cursor.*,
            .row_count = chunk_rows,
        };
        block_count.* += 1;
        cursor.* += chunk_rows;
        remaining -= chunk_rows;
        if (remaining != 0) try stark_curve.add(&chunk_start, chunk_step);
    }
}

test "Pedersen block generation agrees with exact window-18 deductions" {
    const allocator = std.testing.allocator;
    const rows = 128;
    var workspace = try Workspace.init(allocator, rows);
    defer workspace.deinit();
    const actual = try allocator.alloc(stark_curve.AffinePoint, rows);
    defer allocator.free(actual);
    try workspace.block(
        stark_curve.projectiveFromAffine(parameters.negative_shift),
        parameters.p0,
        actual,
    );
    for (actual, 0..) |point, row|
        try std.testing.expectEqual(try parameters.tablePoint(@intCast(row)), point);
}

test "Pedersen table geometry covers official window variants" {
    try std.testing.expectEqual(@as(u32, 1 << 15), Window.small.rowCount());
    try std.testing.expectEqual(@as(u32, 1 << 23), Window.standard.rowCount());
    try std.testing.expectEqual(@as(usize, 86), blockPlanCount(.small));
    try std.testing.expectEqual(@as(usize, 136), blockPlanCount(.standard));
}

test "standard Pedersen plans preserve exact points across chunk boundaries" {
    var plans: [blockPlanCount(.standard)]BlockPlan = undefined;
    const count = try planBlocks(.standard, &plans);
    try std.testing.expectEqual(plans.len, count);
    try std.testing.expectEqual(@as(usize, max_rows_per_plan), plans[0].row_count);
    try std.testing.expectEqual(@as(usize, max_rows_per_plan), plans[1].first_row);
    try std.testing.expectEqual(
        try parameters.tablePointForWindow(max_rows_per_plan, Window.standard.bits()),
        try stark_curve.projectiveToAffine(plans[1].start),
    );
}

test "Pedersen worker policy is explicit, bounded, and never empty" {
    try std.testing.expectEqual(@as(usize, 18), resolveWorkerCount(0, 18, 58));
    try std.testing.expectEqual(@as(usize, max_workers), resolveWorkerCount(0, 64, 58));
    try std.testing.expectEqual(@as(usize, 1), resolveWorkerCount(0, 0, 58));
    try std.testing.expectEqual(@as(usize, 4), resolveWorkerCount(4, 18, 58));
    try std.testing.expectEqual(@as(usize, 2), resolveWorkerCount(8, 18, 2));
}

test "complete window-9 Pedersen table agrees at section boundaries and padding" {
    var table = try Table.init(std.testing.allocator, .small);
    defer table.deinit();
    const bits = Window.small.bits();
    const rows_per_window = @as(u32, 1) << bits;
    const section_rows = (252 / @as(u32, bits)) * rows_per_window;
    const real_rows = 2 * section_rows;
    const indices = [_]u32{
        0,
        1,
        rows_per_window - 1,
        rows_per_window,
        section_rows - rows_per_window,
        section_rows - 1,
        section_rows,
        real_rows - 1,
        real_rows,
        Window.small.rowCount() - 1,
    };
    for (indices) |row|
        try std.testing.expectEqual(
            try parameters.tablePointForWindow(row, bits),
            table.points[row],
        );
}
