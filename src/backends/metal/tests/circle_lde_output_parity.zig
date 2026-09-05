const std = @import("std");

const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const M31 = core.fields.m31.M31;
const parity = @import("../circle_lde_output_parity.zig");

const Fixture = struct {
    source_storage: [2][16]M31,
    coefficient_storage: [2][16]M31,
    extended_storage: [2][32]M31,
    source: [2][]const M31,
    coefficients: [2][]M31,
    extended: [2][]M31,
    base_tree: prover.poly.twiddles.TwiddleTree([]M31),
    extended_tree: prover.poly.twiddles.TwiddleTree([]M31),

    fn init(self: *Fixture, allocator: std.mem.Allocator) !void {
        for (&self.source_storage, 0..) |*column, column_index| {
            for (column, 0..) |*value, row| {
                value.* = M31.fromCanonical(@intCast(
                    column_index * 997 + row * 313 + 17,
                ));
            }
            @memcpy(&self.coefficient_storage[column_index], column);
            self.source[column_index] = column;
            self.coefficients[column_index] = &self.coefficient_storage[column_index];
            self.extended[column_index] = &self.extended_storage[column_index];
        }
        const base_domain = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
        const extended_domain = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
        self.base_tree = try prover.poly.twiddles.precomputeM31(
            allocator,
            base_domain.half_coset,
        );
        errdefer prover.poly.twiddles.deinitM31(allocator, &self.base_tree);
        self.extended_tree = try prover.poly.twiddles.precomputeM31(
            allocator,
            extended_domain.half_coset,
        );
        errdefer prover.poly.twiddles.deinitM31(allocator, &self.extended_tree);
        try prover.poly.circle.poly.interpolateBuffersWithTwiddles(
            &self.coefficients,
            base_domain,
            constTwiddles(self.base_tree),
        );
        for (self.coefficients, self.extended) |coefficient, extended| {
            @memcpy(extended[0..coefficient.len], coefficient);
            @memset(extended[coefficient.len..], M31.zero());
        }
        try prover.poly.circle.poly.evaluateBuffersWithTwiddles(
            &self.extended,
            extended_domain,
            constTwiddles(self.extended_tree),
        );
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        prover.poly.twiddles.deinitM31(allocator, &self.base_tree);
        prover.poly.twiddles.deinitM31(allocator, &self.extended_tree);
        self.* = undefined;
    }

    fn capture(self: *Fixture, allocator: std.mem.Allocator) !parity.GroupCaptureV1 {
        const base_domain = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
        const extended_domain = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
        return parity.GroupCaptureV1.init(
            allocator,
            &self.source,
            &self.coefficients,
            &self.extended,
            64,
            0,
            32,
            base_domain,
            .{
                .root_coset = self.base_tree.root_coset,
                .twiddles = self.base_tree.twiddles,
                .itwiddles = self.base_tree.itwiddles,
            },
            extended_domain,
            .{
                .root_coset = self.extended_tree.root_coset,
                .twiddles = self.extended_tree.twiddles,
                .itwiddles = self.extended_tree.itwiddles,
            },
        );
    }
};

fn constTwiddles(
    tree: prover.poly.twiddles.TwiddleTree([]M31),
) prover.poly.twiddles.TwiddleTree([]const M31) {
    return .{
        .root_coset = tree.root_coset,
        .twiddles = tree.twiddles,
        .itwiddles = tree.itwiddles,
    };
}

test "Metal circle LDE parity reconstructs CPU coefficients and evaluations" {
    var fixture: Fixture = undefined;
    try fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    var capture = try fixture.capture(std.testing.allocator);
    defer capture.deinit(std.testing.allocator);
    var captures = [_]parity.GroupCaptureV1{capture};
    const result = try parity.compareBatch(std.testing.allocator, &captures);
    // `captures` owns the mutated source snapshot after the comparison.
    capture = captures[0];
    switch (result) {
        .exact => |receipt| {
            try receipt.validate();
            try std.testing.expectEqual(@as(usize, 1), receipt.group_count);
            try std.testing.expectEqual(@as(usize, 2), receipt.selected_column_count);
            try std.testing.expectEqual(@as(u64, 32), receipt.coefficient_values);
            try std.testing.expectEqual(@as(u64, 64), receipt.extended_values);
        },
        .mismatch => return error.UnexpectedCircleLdeMismatch,
    }
}

test "Metal circle LDE parity reports a structured extended mutation" {
    var fixture: Fixture = undefined;
    try fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    var capture = try fixture.capture(std.testing.allocator);
    defer capture.deinit(std.testing.allocator);
    fixture.extended_storage[1][19] = fixture.extended_storage[1][19].add(M31.one());
    var captures = [_]parity.GroupCaptureV1{capture};
    const result = try parity.compareBatch(std.testing.allocator, &captures);
    capture = captures[0];
    switch (result) {
        .exact => return error.ExpectedCircleLdeMismatch,
        .mismatch => |mismatch| {
            try std.testing.expectEqual(@as(usize, 0), mismatch.group_index);
            try std.testing.expectEqual(@as(usize, 1), mismatch.group_column_index);
            try std.testing.expectEqual(parity.PhaseV1.extended_evaluation, mismatch.phase);
            try std.testing.expectEqual(@as(usize, 19), mismatch.row);
            try std.testing.expect(!mismatch.expected.eql(mismatch.actual));
        },
    }
}

test "Metal circle LDE parity selects retained u32 split boundaries" {
    try std.testing.expectEqual(@as(usize, 7), parity.selectedColumnCount(455));
    for ([_]usize{ 0, 254, 255, 256, 339, 444, 454 }) |column| {
        try std.testing.expect(parity.shouldCompareColumn(455, column));
    }
    for ([_]usize{ 1, 253, 257, 338, 340, 443, 453 }) |column| {
        try std.testing.expect(!parity.shouldCompareColumn(455, column));
    }
    const plan = try parity.routeForShape(
        455 * (@as(usize, 1) << 24),
        0,
        @as(usize, 1) << 24,
        @as(usize, 1) << 24,
        455,
    );
    try std.testing.expectEqual(parity.RouteV1.u32_rebased, plan.route);
    try std.testing.expectEqual(@as(usize, 2), plan.dispatch_count);
}

test "Metal circle LDE parity releases every diagnostic allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit(allocator);
    var capture = try fixture.capture(allocator);
    defer capture.deinit(allocator);
    var captures = [_]parity.GroupCaptureV1{capture};
    const result = try parity.compareBatch(allocator, &captures);
    capture = captures[0];
    switch (result) {
        .exact => {},
        .mismatch => return error.UnexpectedCircleLdeMismatch,
    }
}
