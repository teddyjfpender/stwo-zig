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
    worker_count: u8 = 4,
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

const max_blocks = 64;
const max_workers = 8;

const BlockPlan = struct {
    start: stark_curve.AffinePoint,
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
        start: stark_curve.AffinePoint,
        step: stark_curve.AffinePoint,
        destination: []stark_curve.AffinePoint,
    ) Error!void {
        std.debug.assert(destination.len <= self.projective.len);
        var point = stark_curve.projectiveFromAffine(start);
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
    var plans: [max_blocks]BlockPlan = undefined;
    const block_count = try planBlocks(window, &plans);
    const requested_workers = @max(@as(usize, 1), worker_count);
    const active_workers = @min(@min(requested_workers, max_workers), block_count);
    const workspace_rows = @as(usize, 1) << window.bits();

    var workspaces: [max_workers]Workspace = undefined;
    var initialized_workspaces: usize = 0;
    defer for (workspaces[0..initialized_workspaces]) |*workspace| workspace.deinit();
    while (initialized_workspaces < active_workers) : (initialized_workspaces += 1)
        workspaces[initialized_workspaces] = try Workspace.init(allocator, workspace_rows);

    var workers: [max_workers]Worker = undefined;
    for (workers[0..active_workers], 0..) |*worker, index| worker.* = .{
        .workspace = &workspaces[index],
        .plans = plans[0..block_count],
        .destination = destination,
        .first_plan = index,
        .plan_stride = active_workers,
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

const Worker = struct {
    workspace: *Workspace,
    plans: []const BlockPlan,
    destination: []stark_curve.AffinePoint,
    first_plan: usize,
    plan_stride: usize,
    failure: ?Error = null,

    fn run(self: *Worker) void {
        var plan_index = self.first_plan;
        while (plan_index < self.plans.len) : (plan_index += self.plan_stride) {
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

fn planBlocks(window: Window, plans: *[max_blocks]BlockPlan) Error!usize {
    const bits: usize = window.bits();
    const windows = 252 / bits;
    const rows_per_window: usize = @as(usize, 1) << @intCast(bits);
    const high_rows: usize = @as(usize, 1) << @intCast(bits - 4);
    var cursor: usize = 0;
    var block_count: usize = 0;

    inline for (.{ .{ parameters.p0, parameters.p1 }, .{ parameters.p2, parameters.p3 } }) |pair| {
        var step = stark_curve.projectiveFromAffine(pair[0]);
        for (0..windows - 1) |_| {
            plans[block_count] = .{
                .start = parameters.negative_shift,
                .step = try stark_curve.projectiveToAffine(step),
                .first_row = cursor,
                .row_count = rows_per_window,
            };
            block_count += 1;
            cursor += rows_per_window;
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
            plans[block_count] = .{
                .start = start,
                .step = raised_low,
                .first_row = cursor,
                .row_count = high_rows,
            };
            block_count += 1;
            cursor += high_rows;
        }
    }
    std.debug.assert(block_count <= plans.len);
    return block_count;
}

test "Pedersen block generation agrees with exact window-18 deductions" {
    const allocator = std.testing.allocator;
    const rows = 128;
    var workspace = try Workspace.init(allocator, rows);
    defer workspace.deinit();
    const actual = try allocator.alloc(stark_curve.AffinePoint, rows);
    defer allocator.free(actual);
    try workspace.block(parameters.negative_shift, parameters.p0, actual);
    for (actual, 0..) |point, row|
        try std.testing.expectEqual(try parameters.tablePoint(@intCast(row)), point);
}

test "Pedersen table geometry covers official window variants" {
    try std.testing.expectEqual(@as(u32, 1 << 15), Window.small.rowCount());
    try std.testing.expectEqual(@as(u32, 1 << 23), Window.standard.rowCount());
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
