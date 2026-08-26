//! Determinism, fail-atomicity, and exact execution-receipt tests.

const std = @import("std");
const owner = @import("work_profile.zig");
const Counters = owner.Counters;
const Delta = owner.Delta;
const FieldOperations = owner.FieldOperations;
const FriFoldExecution = owner.FriFoldExecution;
const FriFoldExecutionLedger = owner.FriFoldExecutionLedger;
const FriLineInterpolationExecution = owner.FriLineInterpolationExecution;
const M31CircleLdeExecution = owner.M31CircleLdeExecution;
const M31InterpolationExecution = owner.M31InterpolationExecution;
const ProducerBoundary = owner.ProducerBoundary;
const Profile = owner.Profile;
const QuotientPreparationExecution = owner.QuotientPreparationExecution;
const QuotientRowExecution = owner.QuotientRowExecution;
const ReceiptCounters = owner.ReceiptCounters;
const Recorder = owner.Recorder;
const SampledCoefficientExecution = owner.SampledCoefficientExecution;
const Site = owner.Site;
const SourceMask = owner.SourceMask;
const boundaryForSite = owner.boundaryForSite;
const zeroProducerCounts = owner.zeroProducerCounts;
const logicalFftButterflies = owner.logicalFftButterflies;
const logicalM31ColdTwiddleWork = owner.logicalM31ColdTwiddleWork;
const logicalM31ForwardFftFieldOperations = owner.logicalM31ForwardFftFieldOperations;
const logicalM31InterpolationWork = owner.logicalM31InterpolationWork;
const logicalMerkleCompressions = owner.logicalMerkleCompressions;
const logicalSampledCoefficientBasisMultiplications = owner.logicalSampledCoefficientBasisMultiplications;

test "logical work profile: exact aggregation is deterministic and complete" {
    var recorder = Recorder(true){};
    try recorder.expectProducer(.main_witness_field);
    try recorder.record(.{
        .site = .main_witness_field,
        .producer = .field_operations,
        .source_mask = .{ .bits = SourceMask.one(.field_additions).bits |
            SourceMask.one(.field_multiplications).bits |
            SourceMask.one(.field_inversions).bits },
        .counters = .{
            .field_additions = 11,
            .field_multiplications = 7,
            .field_inversions = 1,
        },
    });
    try recorder.expectProducer(.fri_protocol);
    try recorder.record(.{
        .site = .fri_protocol,
        .producer = .fri_protocol,
        .source_mask = .{ .bits = SourceMask.one(.fft_butterflies).bits |
            SourceMask.one(.fri_folds).bits |
            SourceMask.one(.merkle_compressions).bits },
        .counters = .{
            .fft_butterflies = 64,
            .fri_folds = 32,
            .merkle_compressions = 16,
        },
    });
    try recorder.finalizeFieldCoverage();
    try std.testing.expect(try recorder.finalizePlannedProducerCoverage());

    const profile = try recorder.snapshot();
    try profile.validate();
    try std.testing.expect(profile.completeExact());
    try std.testing.expectEqual(@as(u64, 2), profile.record_count);
    try std.testing.expectEqual(@as(u64, 11), profile.counters.field_additions);
    try std.testing.expectEqual(@as(u64, 64), profile.counters.fft_butterflies);
    try std.testing.expectEqualStrings(
        "2d73cdb6eee4b639a47d847b736676d5fe88ab73614faad2f8929e93d56eac34",
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );

    const receipt = try ReceiptCounters.fromProfile(&profile);
    try receipt.validate();
    try std.testing.expect(receipt.complete());
    try std.testing.expectEqual(@as(?u64, 16), receipt.merkle_compressions);
}

test "logical work profile: checked aggregation is failure atomic" {
    var recorder = Recorder(true){};
    try recorder.record(.{
        .producer = .field_operations,
        .source_mask = .{ .bits = SourceMask.one(.field_additions).bits |
            SourceMask.one(.field_multiplications).bits |
            SourceMask.one(.field_inversions).bits },
        .counters = .{ .field_additions = std.math.maxInt(u64) },
    });
    const before = try recorder.snapshot();
    try std.testing.expectError(error.CounterOverflow, recorder.record(.{
        .producer = .field_operations,
        .source_mask = .{ .bits = SourceMask.one(.field_additions).bits |
            SourceMask.one(.field_multiplications).bits |
            SourceMask.one(.field_inversions).bits },
        .counters = .{ .field_additions = 1 },
    }));
    const after = try recorder.snapshot();
    try std.testing.expectEqualDeep(before, after);
}

test "logical work profile: source coverage and digest mutations fail closed" {
    try std.testing.expectError(error.InvalidProducerCoverage, (Delta{
        .site = .main_witness_field,
        .producer = .fri_protocol,
        .source_mask = .{ .bits = SourceMask.one(.fft_butterflies).bits |
            SourceMask.one(.fri_folds).bits |
            SourceMask.one(.merkle_compressions).bits },
    }).validate());
    try std.testing.expectError(error.InvalidCounterGroup, (Delta{
        .producer = .fri_protocol,
        .source_mask = SourceMask.one(.fri_folds),
        .counters = .{ .fft_butterflies = 1 },
    }).validate());
    try std.testing.expectError(error.InvalidCounterGroup, (Delta{
        .producer = .fri_protocol,
        .source_mask = .{ .bits = 0x80 },
    }).validate());

    var partial = try Profile.seal(
        .instrumented_exact,
        SourceMask.one(.fri_folds),
        .{ .fri_folds = 8 },
        1,
        .{ .completed = blk: {
            var counts = zeroProducerCounts();
            counts[@intFromEnum(ProducerBoundary.fri_protocol)] = 1;
            break :blk counts;
        } },
    );
    try partial.validate();
    try std.testing.expect(!partial.completeExact());
    try std.testing.expectError(
        error.InvalidCounterGroup,
        ReceiptCounters.fromProfile(&partial),
    );
    partial.counters.fri_folds += 1;
    try std.testing.expectError(error.InvalidWorkProfile, partial.validate());

    var recorder = Recorder(true){};
    try recorder.expectProducer(.main_witness_field);
    try recorder.record(.{
        .site = .main_witness_field,
        .producer = .field_operations,
        .source_mask = .{ .bits = SourceMask.one(.field_additions).bits |
            SourceMask.one(.field_multiplications).bits |
            SourceMask.one(.field_inversions).bits },
    });
    try recorder.expectProducer(.fri_protocol);
    try recorder.record(.{
        .site = .fri_protocol,
        .producer = .fri_protocol,
        .source_mask = .{ .bits = SourceMask.one(.fft_butterflies).bits |
            SourceMask.one(.fri_folds).bits |
            SourceMask.one(.merkle_compressions).bits },
    });
    const premature = try recorder.snapshot();
    try std.testing.expect(!premature.completeExact());
    try recorder.finalizeFieldCoverage();
    const unsealed = try recorder.snapshot();
    try std.testing.expect(!unsealed.completeExact());
    var expected = zeroProducerCounts();
    expected[@intFromEnum(ProducerBoundary.field_operations)] = 1;
    expected[@intFromEnum(ProducerBoundary.fri_protocol)] = 1;
    var missing = expected;
    missing[@intFromEnum(ProducerBoundary.fri_protocol)] = 0;
    try std.testing.expectError(
        error.InvalidProducerCoverage,
        recorder.finalizeProducerCoverage(.{ .counts = missing }),
    );
    try recorder.finalizeProducerCoverage(.{ .counts = expected });
    const complete = try recorder.snapshot();
    try std.testing.expect(complete.completeExact());
    try std.testing.expectError(
        error.InvalidProducerCoverage,
        recorder.record((FieldOperations{ .additions = 1 }).delta()),
    );
    recorder.markIncomplete();
    const unavailable = try recorder.snapshot();
    try unavailable.validate();
    try std.testing.expect(!unavailable.completeExact());
}

test "logical work profile: aggregate boundary adapter cannot seal exact sites" {
    var recorder = Recorder(true){};
    const field_boundary: ProducerBoundary = .field_operations;
    try recorder.expectProducer(field_boundary);
    try recorder.record(.{
        .producer = field_boundary,
        .source_mask = .{ .bits = SourceMask.one(.field_additions).bits |
            SourceMask.one(.field_multiplications).bits |
            SourceMask.one(.field_inversions).bits },
    });
    const fri_boundary: ProducerBoundary = .fri_protocol;
    try recorder.expectProducer(fri_boundary);
    try recorder.record(.{
        .producer = fri_boundary,
        .source_mask = .{ .bits = SourceMask.one(.fft_butterflies).bits |
            SourceMask.one(.fri_folds).bits |
            SourceMask.one(.merkle_compressions).bits },
    });
    try recorder.finalizeFieldCoverage();
    try std.testing.expect(!try recorder.finalizePlannedProducerCoverage());
    const profile = try recorder.snapshot();
    try profile.validate();
    try std.testing.expect(!profile.completeExact());
    try std.testing.expect(!profile.producer_ledger.terminal_sealed);
}

test "logical work profile: exact completion surface requires a site" {
    var recorder = Recorder(true){};
    const before = try recorder.snapshot();
    try std.testing.expectError(
        error.InvalidProducerCoverage,
        recorder.recordCompletedDelta(.{
            .producer = .column_preparation_fft,
            .source_mask = SourceMask.one(.fft_butterflies),
        }),
    );
    try std.testing.expectEqualDeep(before, try recorder.snapshot());

    try recorder.expectProducer(.column_passthrough_fft);
    try recorder.recordCompletedDelta(.{
        .site = .column_passthrough_fft,
        .producer = boundaryForSite(.column_passthrough_fft),
        .source_mask = SourceMask.one(.fft_butterflies),
    });
    try std.testing.expectEqual(@as(u64, 1), recorder.record_count);
    try std.testing.expectEqual(
        @as(u64, 1),
        recorder.completed_sites[@intFromEnum(Site.column_passthrough_fft)],
    );
}

test "logical work profile: equal aggregate boundaries cannot hide site substitution" {
    var recorder = Recorder(true){};
    try recorder.expectProducer(.main_witness_field);
    try recorder.record(.{
        .site = .main_witness_field,
        .producer = .field_operations,
        .source_mask = .{ .bits = SourceMask.one(.field_additions).bits |
            SourceMask.one(.field_multiplications).bits |
            SourceMask.one(.field_inversions).bits },
    });
    try recorder.expectProducer(.fri_protocol);
    try recorder.record(.{
        .site = .fri_protocol,
        .producer = .fri_protocol,
        .source_mask = .{ .bits = SourceMask.one(.fft_butterflies).bits |
            SourceMask.one(.fri_folds).bits |
            SourceMask.one(.merkle_compressions).bits },
    });
    try recorder.expectProducer(.column_passthrough_fft);
    try recorder.record(.{
        .site = .column_extension_fft,
        .producer = .column_preparation_fft,
        .source_mask = SourceMask.one(.fft_butterflies),
    });
    try recorder.finalizeFieldCoverage();
    try std.testing.expectError(
        error.InvalidProducerCoverage,
        recorder.finalizePlannedProducerCoverage(),
    );
    var expected = zeroProducerCounts();
    expected[@intFromEnum(ProducerBoundary.field_operations)] = 1;
    expected[@intFromEnum(ProducerBoundary.column_preparation_fft)] = 1;
    expected[@intFromEnum(ProducerBoundary.fri_protocol)] = 1;
    try std.testing.expectError(
        error.InvalidProducerCoverage,
        recorder.finalizeProducerCoverage(.{ .counts = expected }),
    );
}

test "logical work profile: unavailable and disabled capability carry no work" {
    comptime std.debug.assert(@sizeOf(Recorder(false)) == 0);
    var disabled = Recorder(false){};
    try disabled.record(.{
        .producer = .field_operations,
        .source_mask = .{ .bits = 0xff },
        .counters = .{ .field_additions = std.math.maxInt(u64) },
    });
    const profile = try disabled.snapshot();
    try profile.validate();
    try std.testing.expect(!profile.completeExact());
    const receipt = try ReceiptCounters.fromProfile(&profile);
    try receipt.validate();
    try std.testing.expect(!receipt.complete());
}

test "logical work profile: FFT butterfly arithmetic is exact and checked" {
    try std.testing.expectEqual(@as(u64, 32), try logicalFftButterflies(4, 0));
    try std.testing.expectEqual(@as(u64, 24), try logicalFftButterflies(4, 1));
    try std.testing.expectEqual(@as(u64, 0), try logicalFftButterflies(0, 0));
    try std.testing.expectError(
        error.CounterOverflow,
        logicalFftButterflies(4, 5),
    );
    try std.testing.expectError(
        error.CounterOverflow,
        logicalFftButterflies(@bitSizeOf(u64), 0),
    );
}

test "logical work profile: forward M31 FFT field operations are exact" {
    try std.testing.expectEqualDeep(
        FieldOperations{ .additions = 64, .multiplications = 32 },
        try logicalM31ForwardFftFieldOperations(32),
    );
    try std.testing.expectError(
        error.CounterOverflow,
        logicalM31ForwardFftFieldOperations(std.math.maxInt(u64)),
    );
}

test "logical work profile: M31 interpolation follows actual batch geometry" {
    try std.testing.expectEqualDeep(
        Counters{
            .field_additions = 6,
            .field_multiplications = 12,
            .field_inversions = 1,
            .fft_butterflies = 3,
        },
        try logicalM31InterpolationWork(1, 3),
    );
    try std.testing.expectEqualDeep(
        Counters{
            .field_additions = 16,
            .field_multiplications = 24,
            .field_inversions = 1,
            .fft_butterflies = 8,
        },
        try logicalM31InterpolationWork(2, 2),
    );
    try std.testing.expectEqualDeep(
        Counters{
            .field_additions = 96,
            .field_multiplications = 80,
            .field_inversions = 1,
            .fft_butterflies = 48,
        },
        try logicalM31InterpolationWork(3, 4),
    );
    try std.testing.expectError(
        error.InvalidCounterGroup,
        logicalM31InterpolationWork(0, 1),
    );
    try std.testing.expectError(
        error.InvalidCounterGroup,
        logicalM31InterpolationWork(3, 0),
    );
    try std.testing.expectError(
        error.CounterOverflow,
        logicalM31InterpolationWork(63, 2),
    );
}

test "logical work profile: backend interpolation receipts preserve batching wins" {
    const cpu = M31InterpolationExecution{
        .log_size = 12,
        .column_count = 4,
        .batch_count = 4,
    };
    const metal = M31InterpolationExecution{
        .log_size = 12,
        .column_count = 4,
        .batch_count = 1,
    };
    const cpu_work = try cpu.exactWork();
    const metal_work = try metal.exactWork();
    try std.testing.expectEqual(cpu_work.field_additions, metal_work.field_additions);
    try std.testing.expectEqual(cpu_work.field_multiplications, metal_work.field_multiplications);
    try std.testing.expectEqual(cpu_work.fft_butterflies, metal_work.fft_butterflies);
    try std.testing.expectEqual(@as(u64, 4), cpu_work.field_inversions);
    try std.testing.expectEqual(@as(u64, 1), metal_work.field_inversions);
    try std.testing.expectEqualDeep(
        cpu_work,
        try metal.perColumnBatchProjection(),
    );

    const cpu_lde = M31CircleLdeExecution{
        .interpolation = cpu,
        .forward = .{
            .log_size = 13,
            .column_count = 4,
            .skipped_layers = 1,
        },
    };
    const metal_lde = M31CircleLdeExecution{
        .interpolation = metal,
        .forward = cpu_lde.forward,
    };
    const cpu_lde_work = try cpu_lde.exactWork();
    const metal_lde_work = try metal_lde.exactWork();
    try std.testing.expectEqual(cpu_lde_work.field_additions, metal_lde_work.field_additions);
    try std.testing.expectEqual(cpu_lde_work.field_multiplications, metal_lde_work.field_multiplications);
    try std.testing.expectEqual(cpu_lde_work.fft_butterflies, metal_lde_work.fft_butterflies);
    try std.testing.expectEqual(
        cpu_lde_work.field_inversions - 3,
        metal_lde_work.field_inversions,
    );
}

test "logical work profile: sampled coefficient receipt follows device reductions" {
    try std.testing.expectEqual(
        @as(u64, 384),
        try logicalSampledCoefficientBasisMultiplications(3, 256),
    );
    try std.testing.expectEqual(
        @as(u64, 4_868),
        try logicalSampledCoefficientBasisMultiplications(10, 256),
    );
    try std.testing.expectEqual(
        @as(u64, 5_120),
        try logicalSampledCoefficientBasisMultiplications(10, 128),
    );
    const execution = SampledCoefficientExecution{
        .plan_count = 1,
        .basis_task_count = 2,
        .evaluation_task_count = 4,
        .evaluation_coefficient_terms = 32,
        .basis_multiplications = 768,
        .basis_threadgroup_width = 256,
        .evaluation_threadgroup_width = 256,
    };
    try std.testing.expectEqualDeep(
        Counters{
            .field_additions = 1_052,
            .field_multiplications = 800,
        },
        try execution.exactWork(),
    );

    var malformed = execution;
    malformed.basis_task_count = 5;
    try std.testing.expectError(error.InvalidCounterGroup, malformed.validate());
    try std.testing.expectEqualDeep(
        Counters{},
        try (SampledCoefficientExecution{
            .plan_count = 0,
            .basis_task_count = 0,
            .evaluation_task_count = 0,
            .evaluation_coefficient_terms = 0,
            .basis_multiplications = 0,
            .basis_threadgroup_width = 0,
            .evaluation_threadgroup_width = 0,
        }).exactWork(),
    );
}

test "logical work profile: quotient preparation binds expanded sample geometry" {
    const execution = QuotientPreparationExecution{
        .lifting_log_size = 8,
        .tree_count = 2,
        .column_count = 6,
        .sampled_column_count = 4,
        .input_sample_count = 7,
        .periodic_sample_count = 2,
        .expanded_sample_count = 9,
        .distinct_batch_count = 5,
        .periodicity_doubles = 10,
    };
    try std.testing.expectEqualDeep(
        Counters{
            .field_additions = 74,
            .field_multiplications = 112,
        },
        try execution.exactWork(),
    );

    var malformed = execution;
    malformed.expanded_sample_count -= 1;
    try std.testing.expectError(error.InvalidCounterGroup, malformed.validate());
    malformed = execution;
    malformed.periodicity_doubles = 17;
    try std.testing.expectError(error.InvalidCounterGroup, malformed.validate());
}

test "logical work profile: quotient row receipt separates host and Metal schedules" {
    const host = QuotientRowExecution{
        .path = .host_streaming,
        .lifting_log_size = 4,
        .row_count = 16,
        .sample_batch_count = 3,
        .contribution_count = 7,
        .combined_view_count = 2,
        .grouped_partial_count = 0,
        .numerator_additions = 32,
        .numerator_multiplications = 0,
        .combined_plan_source_cells = 10,
        .domain_circle_additions = 20,
        .batch_inverse_multiplications = 150,
        .batch_inverse_calls = 2,
    };
    try std.testing.expectEqualDeep(
        Counters{
            .field_additions = 352,
            .field_multiplications = 462,
            .field_inversions = 2,
        },
        try host.exactWork(),
    );

    const metal = QuotientRowExecution{
        .path = .metal_raw_direct,
        .lifting_log_size = 4,
        .row_count = 16,
        .sample_batch_count = 3,
        .contribution_count = 7,
        .combined_view_count = 0,
        .grouped_partial_count = 0,
        .numerator_additions = 112,
        .numerator_multiplications = 448,
        .combined_plan_source_cells = 0,
        .domain_circle_additions = 12,
        .batch_inverse_multiplications = 0,
        .batch_inverse_calls = 48,
    };
    try std.testing.expectEqualDeep(
        Counters{
            .field_additions = 376,
            .field_multiplications = 688,
            .field_inversions = 48,
        },
        try metal.exactWork(),
    );

    var malformed = metal;
    malformed.batch_inverse_calls -= 1;
    try std.testing.expectError(error.InvalidCounterGroup, malformed.validate());
    malformed = metal;
    malformed.row_count = 15;
    try std.testing.expectError(error.InvalidCounterGroup, malformed.validate());
}

test "logical work profile: FRI fold receipts distinguish host and retained paths" {
    const host_line = FriFoldExecution{
        .kind = .line,
        .initial_count = 16,
        .fold_count = 2,
        .domain_log_size = 4,
        .domain_initial_index = 1 << 25,
        .domain_step_size = 1 << 27,
        .inverse_path = .host_batch,
        .alpha_squares = 2,
        .domain_doubles = 2,
    };
    try std.testing.expectEqualDeep(Counters{
        .field_additions = 68,
        .field_multiplications = 124,
        .field_inversions = 2,
        .fri_folds = 12,
    }, try host_line.exactWork());

    const host_circle = FriFoldExecution{
        .kind = .circle_to_line,
        .initial_count = 16,
        .fold_count = 1,
        .domain_log_size = 3,
        .domain_initial_index = 1 << 25,
        .domain_step_size = 1 << 28,
        .inverse_path = .host_batch,
        .alpha_squares = 1,
        .domain_doubles = 0,
    };
    try std.testing.expectEqualDeep(Counters{
        .field_additions = 48,
        .field_multiplications = 82,
        .field_inversions = 1,
        .fri_folds = 8,
    }, try host_circle.exactWork());

    const retained_circle = FriFoldExecution{
        .kind = .circle_to_line,
        .initial_count = 16,
        .fold_count = 1,
        .domain_log_size = 3,
        .domain_initial_index = 1 << 25,
        .domain_step_size = 1 << 28,
        .inverse_path = .retained,
        .alpha_squares = 0,
        .domain_doubles = 0,
        .optimized_zero_accumulator = true,
    };
    try std.testing.expectEqualDeep(Counters{
        .field_additions = 24,
        .field_multiplications = 16,
        .fri_folds = 8,
    }, try retained_circle.exactWork());
}

test "logical work profile: terminal FRI interpolation includes walks and normalization" {
    const execution = FriLineInterpolationExecution{ .log_size = 3 };
    try std.testing.expectEqualDeep(Counters{
        .field_additions = 60,
        .field_multiplications = 92,
        .field_inversions = 13,
        .fft_butterflies = 12,
    }, try execution.exactWork());
}

test "logical work profile: malformed FRI receipt fails atomically" {
    var ledger: FriFoldExecutionLedger = .{};
    ledger.observe(.{
        .kind = .circle_to_line,
        .initial_count = 16,
        .fold_count = 2,
        .domain_log_size = 3,
        .domain_initial_index = 1,
        .domain_step_size = 1 << 28,
        .inverse_path = .host_batch,
        .alpha_squares = 1,
        .domain_doubles = 0,
    });
    try std.testing.expect(!ledger.complete);
    try std.testing.expectEqual(@as(usize, 0), ledger.count);
    try std.testing.expectError(error.InvalidCounterGroup, ledger.exactWork());
}

test "logical work profile: cold M31 twiddles follow direct and chunked inversion" {
    try std.testing.expectEqualDeep(
        Counters{
            .field_additions = 14,
            .field_multiplications = 28,
            .field_inversions = 4,
        },
        try logicalM31ColdTwiddleWork(3),
    );
    try std.testing.expectEqualDeep(
        Counters{
            .field_additions = 8_238,
            .field_multiplications = 28_769,
            .field_inversions = 1,
        },
        try logicalM31ColdTwiddleWork(13),
    );
    try std.testing.expectEqualDeep(
        Counters{
            .field_additions = 16_434,
            .field_multiplications = 57_454,
            .field_inversions = 2,
        },
        try logicalM31ColdTwiddleWork(14),
    );
    try std.testing.expectError(
        error.InvalidCounterGroup,
        logicalM31ColdTwiddleWork(0),
    );
    try std.testing.expectError(
        error.InvalidCounterGroup,
        logicalM31ColdTwiddleWork(65),
    );
}

test "logical work profile: Merkle compression arithmetic follows execution" {
    try std.testing.expectEqual(
        @as(u64, 1_023),
        try logicalMerkleCompressions(1_024, false),
    );
    try std.testing.expectEqual(
        @as(u64, 10),
        try logicalMerkleCompressions(1_024, true),
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        try logicalMerkleCompressions(1, true),
    );
    try std.testing.expectError(
        error.InvalidCounterGroup,
        logicalMerkleCompressions(3, false),
    );
}
