//! Fail-closed exact-work authority for Metal's precommitted PCS transactions.

const std = @import("std");
const work_profile = @import("stwo_prover_api").work_profile;

pub const Recorder = work_profile.Recorder(true);

pub const DeviceReceipt = struct {
    normalization_batch_count: u32,
    forward_skipped_layers: u32,
    merkle_compressions: u64,
};

pub const Receipt = struct {
    transform: work_profile.Counters,
    merkle_compressions: u64,

    pub fn fromUniformOwned(
        base_log_size: u32,
        extended_log_size: u32,
        column_count: usize,
        device: DeviceReceipt,
    ) !Receipt {
        try validateUniformMerkle(extended_log_size, device.merkle_compressions);
        const execution = work_profile.M31CircleLdeExecution{
            .interpolation = .{
                .log_size = base_log_size,
                .column_count = @intCast(column_count),
                .batch_count = device.normalization_batch_count,
            },
            .forward = .{
                .log_size = extended_log_size,
                .column_count = @intCast(column_count),
                .skipped_layers = device.forward_skipped_layers,
            },
        };
        return init(try execution.exactWork(), device.merkle_compressions);
    }

    pub fn fromUniformPolynomials(
        extended_log_size: u32,
        column_count: usize,
        device: DeviceReceipt,
    ) !Receipt {
        if (device.normalization_batch_count != 0)
            return error.InvalidCounterGroup;
        try validateUniformMerkle(extended_log_size, device.merkle_compressions);
        const execution = work_profile.M31ForwardFftExecution{
            .log_size = extended_log_size,
            .column_count = @intCast(column_count),
            .skipped_layers = device.forward_skipped_layers,
        };
        return init(try execution.exactWork(), device.merkle_compressions);
    }

    pub fn init(
        transform: work_profile.Counters,
        merkle_compressions: u64,
    ) !Receipt {
        if (transform.fri_folds != 0 or transform.merkle_compressions != 0 or
            merkle_compressions == 0)
        {
            return error.InvalidCounterGroup;
        }
        return .{
            .transform = transform,
            .merkle_compressions = merkle_compressions,
        };
    }
};

/// Accumulates the independently prepared log groups in a heterogeneous
/// transaction. Each group owns one normalization batch and executes every
/// forward layer in `circle_plans.m`.
pub const HeterogeneousReceipt = struct {
    transform: work_profile.Counters = .{},
    group_count: u64 = 0,

    pub fn addGroup(
        self: *HeterogeneousReceipt,
        base_log_size: u32,
        column_count: usize,
    ) !void {
        const columns = std.math.cast(u64, column_count) orelse
            return error.CounterOverflow;
        const execution = work_profile.M31CircleLdeExecution{
            .interpolation = .{
                .log_size = base_log_size,
                .column_count = columns,
                .batch_count = 1,
            },
            .forward = .{
                .log_size = try std.math.add(u32, base_log_size, 1),
                .column_count = columns,
                .skipped_layers = 0,
            },
        };
        self.transform = try self.transform.add(try execution.exactWork());
        self.group_count = std.math.add(u64, self.group_count, 1) catch
            return error.CounterOverflow;
    }

    pub fn finish(
        self: HeterogeneousReceipt,
        leaf_count: u64,
    ) !Receipt {
        if (self.group_count == 0) return error.InvalidCounterGroup;
        return Receipt.init(
            self.transform,
            try work_profile.logicalMerkleCompressions(leaf_count, false),
        );
    }
};

/// Registers both independently planned sites before a device command can be
/// submitted. Unless `complete` publishes both deltas, `deinit` permanently
/// fail-closes the enclosing request.
pub const Audit = struct {
    recorder: *Recorder,
    transform_site: work_profile.Site,
    completed: bool = false,

    pub fn beginOwned(recorder: *Recorder) !Audit {
        return begin(recorder, .column_combined_fft);
    }

    pub fn beginPolynomials(recorder: *Recorder) !Audit {
        return begin(recorder, .polynomial_commit_forward_fft);
    }

    fn begin(recorder: *Recorder, transform_site: work_profile.Site) !Audit {
        recorder.expectProducer(transform_site) catch |err| {
            recorder.markIncomplete();
            return err;
        };
        recorder.expectProducer(.commitment_tree_merkle) catch |err| {
            recorder.markIncomplete();
            return err;
        };
        return .{
            .recorder = recorder,
            .transform_site = transform_site,
        };
    }

    pub fn deinit(self: *Audit) void {
        if (!self.completed) self.recorder.markIncomplete();
        self.* = undefined;
    }

    pub fn complete(self: *Audit, receipt: Receipt) !void {
        const transform = work_profile.Delta{
            .site = self.transform_site,
            .producer = work_profile.boundaryForSite(self.transform_site),
            .source_mask = transformSourceMask(),
            .counters = receipt.transform,
        };
        const merkle = work_profile.Delta{
            .site = .commitment_tree_merkle,
            .producer = .commitment_tree_merkle,
            .source_mask = work_profile.SourceMask.one(.merkle_compressions),
            .counters = .{ .merkle_compressions = receipt.merkle_compressions },
        };
        // Validate both deltas before either becomes observable. Recorder-side
        // checked additions can still fail, in which case `deinit` fail-closes
        // the request rather than publishing a partial exact receipt.
        try transform.validate();
        try merkle.validate();
        try self.recorder.recordCompletedDelta(transform);
        try self.recorder.recordCompletedDelta(merkle);
        self.completed = true;
    }
};

fn transformSourceMask() work_profile.SourceMask {
    return .{ .bits = work_profile.SourceMask.one(.field_additions).bits |
        work_profile.SourceMask.one(.field_multiplications).bits |
        work_profile.SourceMask.one(.field_inversions).bits |
        work_profile.SourceMask.one(.fft_butterflies).bits };
}

fn validateUniformMerkle(log_size: u32, completed: u64) !void {
    if (log_size >= @bitSizeOf(u64)) return error.InvalidCounterGroup;
    const expected = try work_profile.logicalMerkleCompressions(
        @as(u64, 1) << @intCast(log_size),
        false,
    );
    if (completed != expected) return error.InvalidCounterGroup;
}

test "precommitted work audit publishes exact owned sites transactionally" {
    var recorder: Recorder = .{};
    var audit = try Audit.beginOwned(&recorder);
    defer audit.deinit();
    const receipt = try Receipt.fromUniformOwned(16, 17, 8, .{
        .normalization_batch_count = 1,
        .forward_skipped_layers = 1,
        .merkle_compressions = (@as(u64, 1) << 17) - 1,
    });
    try audit.complete(receipt);

    try std.testing.expect(!recorder.incomplete);
    try std.testing.expectEqual(
        @as(u64, 1),
        recorder.completed_sites[@intFromEnum(work_profile.Site.column_combined_fft)],
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        recorder.completed_sites[@intFromEnum(work_profile.Site.commitment_tree_merkle)],
    );
    try std.testing.expectEqual(receipt.transform.fft_butterflies, recorder.counters.fft_butterflies);
    try std.testing.expectEqual(receipt.merkle_compressions, recorder.counters.merkle_compressions);
}

test "precommitted work audit fail-closes an uncompleted device transaction" {
    var recorder: Recorder = .{};
    {
        var audit = try Audit.beginPolynomials(&recorder);
        audit.deinit();
    }
    try std.testing.expect(recorder.incomplete);
    try std.testing.expectEqual(@as(u64, 0), recorder.record_count);
}

test "precommitted polynomial receipt requires coefficient-form device geometry" {
    const merkle_compressions = (@as(u64, 1) << 17) - 1;
    const receipt = try Receipt.fromUniformPolynomials(17, 8, .{
        .normalization_batch_count = 0,
        .forward_skipped_layers = 1,
        .merkle_compressions = merkle_compressions,
    });
    try std.testing.expect(receipt.transform.fft_butterflies > 0);
    try std.testing.expectEqual(merkle_compressions, receipt.merkle_compressions);
    try std.testing.expectError(
        error.InvalidCounterGroup,
        Receipt.fromUniformPolynomials(17, 8, .{
            .normalization_batch_count = 1,
            .forward_skipped_layers = 1,
            .merkle_compressions = merkle_compressions,
        }),
    );
    try std.testing.expectError(
        error.InvalidCounterGroup,
        Receipt.fromUniformPolynomials(17, 8, .{
            .normalization_batch_count = 0,
            .forward_skipped_layers = 1,
            .merkle_compressions = merkle_compressions - 1,
        }),
    );
}

test "heterogeneous receipt preserves per-group normalization geometry" {
    var builder: HeterogeneousReceipt = .{};
    try builder.addGroup(6, 2);
    try builder.addGroup(8, 3);
    const receipt = try builder.finish(@as(u64, 1) << 9);
    try std.testing.expectEqual(@as(u64, 511), receipt.merkle_compressions);
    try std.testing.expect(receipt.transform.field_inversions > 0);
    try std.testing.expect(receipt.transform.fft_butterflies > 0);
}
