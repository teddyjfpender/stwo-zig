const std = @import("std");

const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CirclePointQM31 = core.circle.CirclePointQM31;
const TreeVec = core.pcs.utils.TreeVec;
const prover = @import("stwo_prover_engine");
const quotient_ops = prover.pcs.quotient_ops;
const secure_column = prover.secure_column;
const parity = @import("../quotient_output_parity.zig");

const RawBackend = struct {
    pub const rawQuotientInputs = true;
};

const InputStorage = struct {
    full: [32]M31,
    short: [8]M31,
    columns: [2]quotient_ops.ColumnEvaluation,
    column_trees: [1][]const quotient_ops.ColumnEvaluation,
    full_points: [1]CirclePointQM31,
    short_points: [2]CirclePointQM31,
    point_columns: [2][]CirclePointQM31,
    point_trees: [1][][]CirclePointQM31,
    full_values: [1]QM31,
    short_values: [2]QM31,
    value_columns: [2][]QM31,
    value_trees: [1][][]QM31,

    fn init(self: *InputStorage) void {
        for (&self.full, 0..) |*value, index| {
            value.* = M31.fromCanonical(@intCast(index * 7 + 3));
        }
        for (&self.short, 0..) |*value, index| {
            value.* = M31.fromCanonical(@intCast(index * 11 + 101));
        }
        self.columns = .{
            .{ .log_size = 5, .values = &self.full },
            .{ .log_size = 3, .values = &self.short },
        };
        self.column_trees = .{&self.columns};
        const point0 = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(7);
        const point1 = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(19);
        self.full_points = .{point0};
        self.short_points = .{ point0, point1 };
        self.point_columns = .{ &self.full_points, &self.short_points };
        self.point_trees = .{&self.point_columns};
        self.full_values = .{QM31.fromU32Unchecked(1, 2, 3, 4)};
        self.short_values = .{
            QM31.fromU32Unchecked(5, 6, 7, 8),
            QM31.fromU32Unchecked(9, 10, 11, 12),
        };
        self.value_columns = .{ &self.full_values, &self.short_values };
        self.value_trees = .{&self.value_columns};
    }

    fn columnTree(self: *InputStorage) TreeVec([]const quotient_ops.ColumnEvaluation) {
        return TreeVec([]const quotient_ops.ColumnEvaluation).initOwned(
            &self.column_trees,
        );
    }

    fn pointTree(self: *InputStorage) TreeVec([][]CirclePointQM31) {
        return TreeVec([][]CirclePointQM31).initOwned(&self.point_trees);
    }

    fn valueTree(self: *InputStorage) TreeVec([][]QM31) {
        return TreeVec([][]QM31).initOwned(&self.value_trees);
    }
};

const Fixture = struct {
    storage: *InputStorage,
    provider: quotient_ops.LazyQuotientProvider,
    expected: secure_column.SecureColumnByCoords,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const storage = try allocator.create(InputStorage);
        errdefer allocator.destroy(storage);
        storage.init();
        const alpha = QM31.fromU32Unchecked(3, 0, 1, 0);
        var expected = try quotient_ops.computeFriQuotients(
            allocator,
            storage.columnTree(),
            storage.pointTree(),
            storage.valueTree(),
            alpha,
            5,
            1,
        );
        errdefer expected.deinit(allocator);
        const provider = try quotient_ops.LazyQuotientProvider.initForBackend(
            RawBackend,
            allocator,
            storage.columnTree(),
            storage.pointTree(),
            storage.valueTree(),
            alpha,
            5,
        );
        return .{
            .storage = storage,
            .provider = provider,
            .expected = expected,
        };
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        self.provider.deinit(allocator);
        self.expected.deinit(allocator);
        allocator.destroy(self.storage);
        self.* = undefined;
    }
};

test "Metal quotient parity reconstructs the ordinary CPU quotient exactly" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    const result = try parity.compareRawProviderAgainstCpu(
        std.testing.allocator,
        &fixture.provider,
        &fixture.expected,
    );
    switch (result) {
        .exact => |receipt| {
            try receipt.validate();
            try std.testing.expectEqual(@as(usize, 32), receipt.row_count);
            try std.testing.expectEqual(@as(u64, 128), receipt.compared_values);
        },
        .mismatch => return error.UnexpectedQuotientMismatch,
    }
}

test "Metal quotient parity returns the first structured mismatch" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    fixture.expected.columns[2][17] = fixture.expected.columns[2][17].add(M31.one());
    const result = try parity.compareRawProviderAgainstCpu(
        std.testing.allocator,
        &fixture.provider,
        &fixture.expected,
    );
    switch (result) {
        .exact => return error.ExpectedQuotientMismatch,
        .mismatch => |mismatch| {
            try std.testing.expectEqual(@as(usize, 17), mismatch.row);
            try std.testing.expectEqual(@as(u8, 2), mismatch.coordinate);
            try std.testing.expect(!mismatch.expected.eql(mismatch.actual));
        },
    }
}

test "Metal quotient CPU parity releases every diagnostic allocation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        compareForAllocationTest,
        .{ &fixture.provider, &fixture.expected },
    );
}

fn compareForAllocationTest(
    allocator: std.mem.Allocator,
    provider: *const quotient_ops.LazyQuotientProvider,
    expected: *const secure_column.SecureColumnByCoords,
) !void {
    const result = try parity.compareRawProviderAgainstCpu(
        allocator,
        provider,
        expected,
    );
    switch (result) {
        .exact => {},
        .mismatch => return error.UnexpectedQuotientMismatch,
    }
}
