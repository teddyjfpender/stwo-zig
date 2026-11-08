//! Immutable canonical M31 twiddles shared across circle-domain sizes.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const canonic = @import("stwo_core").poly.circle.canonic;
const domain = @import("stwo_core").poly.circle.domain;
const twiddles = @import("twiddles.zig");

const M31 = m31.M31;

pub const M31TwiddleTower = struct {
    tree: twiddles.TwiddleTree([]M31),
    max_circle_log: u32,
    retained_bytes: usize,

    const Self = @This();

    pub const InitError = std.mem.Allocator.Error || twiddles.TwiddleError || error{
        InvalidCircleLog,
        SizeOverflow,
        HostByteBudgetExceeded,
    };

    pub const ViewError = error{InvalidCircleLog};

    /// Builds the single largest canonical tree owned by this tower.
    ///
    /// Budget validation is completed before either twiddle allocation begins.
    pub fn init(
        allocator: std.mem.Allocator,
        max_circle_log: u32,
        host_byte_budget: usize,
    ) InitError!Self {
        try validateCircleLog(max_circle_log);
        const retained_bytes = try retainedBytesForLog(max_circle_log);
        if (retained_bytes > host_byte_budget) return error.HostByteBudgetExceeded;

        const root_coset = canonic.CanonicCoset
            .new(max_circle_log)
            .circleDomain()
            .half_coset;
        const tree = try twiddles.precomputeM31(allocator, root_coset);
        std.debug.assert(tree.twiddles.len == try elementCountForLog(max_circle_log));
        std.debug.assert(tree.itwiddles.len == tree.twiddles.len);

        return .{
            .tree = tree,
            .max_circle_log = max_circle_log,
            .retained_bytes = retained_bytes,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        twiddles.deinitM31(allocator, &self.tree);
        self.* = undefined;
    }

    /// Returns an immutable exact-log view borrowed for the tower's lifetime.
    pub fn view(
        self: *const Self,
        circle_log: u32,
    ) ViewError!twiddles.TwiddleTree([]const M31) {
        if (circle_log < domain.MIN_CIRCLE_DOMAIN_LOG_SIZE or
            circle_log > self.max_circle_log)
        {
            return error.InvalidCircleLog;
        }

        const view_len = elementCountForLog(circle_log) catch
            return error.InvalidCircleLog;
        std.debug.assert(view_len <= self.tree.twiddles.len);
        const suffix_start = self.tree.twiddles.len - view_len;

        return .{
            .root_coset = canonic.CanonicCoset
                .new(circle_log)
                .circleDomain()
                .half_coset,
            .twiddles = self.tree.twiddles[suffix_start..],
            .itwiddles = self.tree.itwiddles[suffix_start..],
        };
    }

    pub inline fn retainedBytes(self: *const Self) usize {
        return self.retained_bytes;
    }

    pub inline fn maxCircleLog(self: *const Self) u32 {
        return self.max_circle_log;
    }

    fn validateCircleLog(circle_log: u32) InitError!void {
        if (circle_log < domain.MIN_CIRCLE_DOMAIN_LOG_SIZE or
            circle_log > domain.MAX_CIRCLE_DOMAIN_LOG_SIZE)
        {
            return error.InvalidCircleLog;
        }
        _ = try elementCountForLog(circle_log);
    }

    fn elementCountForLog(circle_log: u32) error{SizeOverflow}!usize {
        if (circle_log == 0) return error.SizeOverflow;
        const root_log = circle_log - 1;
        if (root_log >= @bitSizeOf(usize)) return error.SizeOverflow;
        return @as(usize, 1) << @intCast(root_log);
    }

    fn retainedBytesForLog(circle_log: u32) error{SizeOverflow}!usize {
        const elements = try elementCountForLog(circle_log);
        const one_tree_bytes = std.math.mul(usize, elements, @sizeOf(M31)) catch
            return error.SizeOverflow;
        return std.math.mul(usize, one_tree_bytes, 2) catch
            return error.SizeOverflow;
    }
};

test "m31 twiddle tower: every canonical suffix matches an exact tree" {
    const allocator = std.testing.allocator;
    const max_circle_log: u32 = 10;
    var tower = try M31TwiddleTower.init(allocator, max_circle_log, std.math.maxInt(usize));
    defer tower.deinit(allocator);

    var circle_log: u32 = domain.MIN_CIRCLE_DOMAIN_LOG_SIZE;
    while (circle_log <= max_circle_log) : (circle_log += 1) {
        const suffix = try tower.view(circle_log);
        var exact = try twiddles.precomputeM31(
            allocator,
            canonic.CanonicCoset.new(circle_log).circleDomain().half_coset,
        );
        defer twiddles.deinitM31(allocator, &exact);

        try std.testing.expect(suffix.root_coset.eql(exact.root_coset));
        try std.testing.expectEqualSlices(M31, exact.twiddles, suffix.twiddles);
        try std.testing.expectEqualSlices(M31, exact.itwiddles, suffix.itwiddles);
    }
}

test "m31 twiddle tower: views retain the forward inverse law" {
    const allocator = std.testing.allocator;
    var tower = try M31TwiddleTower.init(allocator, 11, std.math.maxInt(usize));
    defer tower.deinit(allocator);

    var circle_log: u32 = domain.MIN_CIRCLE_DOMAIN_LOG_SIZE;
    while (circle_log <= tower.maxCircleLog()) : (circle_log += 1) {
        const tree = try tower.view(circle_log);
        for (tree.twiddles, tree.itwiddles) |forward, inverse| {
            try std.testing.expect(forward.mul(inverse).eql(M31.one()));
        }
    }
}

test "m31 twiddle tower: rejects invalid init and view logs" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidCircleLog,
        M31TwiddleTower.init(allocator, 0, std.math.maxInt(usize)),
    );
    try std.testing.expectError(
        error.InvalidCircleLog,
        M31TwiddleTower.init(
            allocator,
            domain.MAX_CIRCLE_DOMAIN_LOG_SIZE + 1,
            std.math.maxInt(usize),
        ),
    );

    var tower = try M31TwiddleTower.init(allocator, 7, std.math.maxInt(usize));
    defer tower.deinit(allocator);
    try std.testing.expectError(error.InvalidCircleLog, tower.view(0));
    try std.testing.expectError(error.InvalidCircleLog, tower.view(8));
}

test "m31 twiddle tower: enforces host budget before allocation" {
    const allocator = std.testing.allocator;
    const circle_log: u32 = 9;
    const required = try M31TwiddleTower.retainedBytesForLog(circle_log);

    var fail_first_allocation = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    try std.testing.expectError(
        error.HostByteBudgetExceeded,
        M31TwiddleTower.init(
            fail_first_allocation.allocator(),
            circle_log,
            required - 1,
        ),
    );
    try std.testing.expect(!fail_first_allocation.has_induced_failure);

    var exact_budget = try M31TwiddleTower.init(allocator, circle_log, required);
    defer exact_budget.deinit(allocator);
    try std.testing.expectEqual(required, exact_budget.retainedBytes());
    try std.testing.expectEqual(circle_log, exact_budget.maxCircleLog());
}

fn checkTowerAllocationFailures(allocator: std.mem.Allocator) !void {
    var tower = try M31TwiddleTower.init(allocator, 8, std.math.maxInt(usize));
    defer tower.deinit(allocator);
    _ = try tower.view(5);
}

test "m31 twiddle tower: init cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkTowerAllocationFailures,
        .{},
    );
}
