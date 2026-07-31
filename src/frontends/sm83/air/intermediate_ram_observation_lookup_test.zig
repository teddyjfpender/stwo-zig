const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const memory_lookup = @import("cartridge_memory_lookup.zig");
const subject = @import("intermediate_ram_observation_lookup.zig");

test "observation schedule is positive unique canonical and phase bounded" {
    try std.testing.expectError(
        error.EmptyObservationSchedule,
        subject.validateSchedule(&.{}),
    );
    try std.testing.expectError(
        error.DuplicateObservation,
        subject.validateSchedule(&.{
            sample(5, 0xc000, 1),
            sample(5, 0xc000, 2),
        }),
    );
    try std.testing.expectError(
        error.NonCanonicalObservationOrder,
        subject.validateSchedule(&.{
            sample(6, 0xc000, 1),
            sample(5, 0xc001, 2),
        }),
    );
    try std.testing.expectError(
        error.NonCanonicalObservationOrder,
        subject.validateSchedule(&.{
            sample(5, 0xc001, 1),
            sample(5, 0xc000, 2),
        }),
    );
    try std.testing.expectError(
        error.ObservationKeyOutOfRange,
        subject.validateSchedule(&.{
            sample(5, memory_lookup.KEY_COUNT, 1),
        }),
    );
    try std.testing.expectError(
        error.NonCanonicalObservationMcycle,
        subject.validateSchedule(&.{
            sample(std.math.maxInt(u32), 0, 1),
        }),
    );
    try subject.validateSchedule(&.{
        sample(5, 0xc000, 1),
        sample(5, memory_lookup.SRAM_KEY_OFFSET, 2),
        sample(6, 0xc000, 3),
    });
    try std.testing.expectEqual(
        @as(u32, 9),
        subject.OBSERVATION_PHASE,
    );
    try std.testing.expect(
        subject.OBSERVATION_PHASE >
            memory_lookup.memory_clock.DMA_PHASE,
    );
}

test "observation schedule admits only canonical WRAM and physical SRAM" {
    try subject.validateSchedule(&.{
        sample(5, 0xc000, 1),
        sample(5, 0xdfff, 2),
        sample(5, memory_lookup.SRAM_KEY_OFFSET, 3),
        sample(5, memory_lookup.KEY_COUNT - 1, 4),
    });

    const rejected_system_keys = [_]u17{
        0x0000, // ROM
        0x8000, // VRAM
        0xa000, // logical cartridge SRAM
        0xe000, // WRAM echo
        0xfe00, // OAM
        0xfea0, // unusable
        0xff00, // MMIO
        0xff80, // HRAM
    };
    for (rejected_system_keys) |key| {
        try std.testing.expectError(
            error.ObservationKeyOutsideDomain,
            subject.validateSchedule(&.{sample(5, key, 1)}),
        );
    }
    try std.testing.expectError(
        error.ObservationKeyOutsideDomain,
        subject.accessForSample(
            sample(5, 0xa000, 1),
            .{ .clock = 1 },
        ),
    );
    try std.testing.expectError(
        error.ObservationKeyOutsideDomain,
        subject.pair(
            .{
                .enabled = true,
                .key = 0xa000,
                .previous_clock = 1,
                .clock = 2,
                .expected = 1,
            },
            memory_lookup.Relation.dummy(),
        ),
    );
    try std.testing.expectError(
        error.ObservationKeyOutOfRange,
        subject.validateSchedule(&.{
            sample(5, memory_lookup.KEY_COUNT, 1),
        }),
    );
}

test "canonical encoding digest count and public table bind every sample field" {
    const samples = scenarioSamples();
    const claim = try subject.scheduleClaim(&samples);
    try std.testing.expectEqual(@as(u32, samples.len), claim.count);
    try std.testing.expect(!std.mem.allEqual(
        u8,
        &claim.digest,
        0,
    ));
    var channel = RecordingChannel{};
    claim.mixInto(&channel);
    try std.testing.expectEqual(
        @as(usize, channel.words.len),
        channel.count,
    );
    try std.testing.expectEqual(
        subject.PUBLIC_CLAIM_TAG,
        channel.words[0],
    );
    try std.testing.expectEqual(claim.count, channel.words[1]);
    const record = subject.canonicalRecord(samples[0]);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 5, 0, 0, 0, 0, 0xc0, 0, 0, 0x42 },
        &record,
    );

    var mutation = samples;
    mutation[0].expected ^= 1;
    const changed_value = try subject.scheduleClaim(&mutation);
    try std.testing.expect(!std.mem.eql(
        u8,
        &claim.digest,
        &changed_value.digest,
    ));
    mutation = samples;
    mutation[1].key += 1;
    const changed_key = try subject.scheduleClaim(&mutation);
    try std.testing.expect(!std.mem.eql(
        u8,
        &claim.digest,
        &changed_key.digest,
    ));
    mutation = samples;
    mutation[2].mcycle += 1;
    const changed_mcycle = try subject.scheduleClaim(&mutation);
    try std.testing.expect(!std.mem.eql(
        u8,
        &claim.digest,
        &changed_mcycle.digest,
    ));

    var table = try subject.generatePublicTable(
        std.testing.allocator,
        4,
        &samples,
    );
    defer table.deinit();
    try subject.validatePublicTable(
        &table.columns,
        4,
        &samples,
    );
    const storage = try core_air_utils.circleBitReversedIndex(4, 0);
    table.columns[3][storage] =
        table.columns[3][storage].add(M31.one());
    try std.testing.expectError(
        error.NonCanonicalPublicTable,
        subject.validatePublicTable(
            &table.columns,
            4,
            &samples,
        ),
    );
}

test "observation witness is ordered bit-reversed and evaluates directly" {
    const samples = scenarioSamples();
    const predecessors = scenarioPredecessors();
    var witness = try subject.generateWitness(
        std.testing.allocator,
        4,
        &samples,
        &predecessors,
    );
    defer witness.deinit();
    try std.testing.expectEqual(@as(usize, 16), witness.accesses.len);
    for (witness.accesses[0..samples.len], samples) |
        access,
        expected,
    | {
        try std.testing.expect(access.enabled);
        try std.testing.expectEqual(
            expected.expected,
            access.expected,
        );
    }
    for (witness.accesses[samples.len..]) |access|
        try std.testing.expectEqual(subject.Access{}, access);

    const storage = try core_air_utils.circleBitReversedIndex(4, 0);
    try std.testing.expectEqual(
        M31.fromCanonical(predecessors[0].clock),
        witness.main[subject.PREVIOUS_CLOCK_OFFSET][storage],
    );
    const relation = memory_lookup.Relation.dummy();
    const access = witness.accesses[0];
    const increment = try subject.accumulate(
        QM31.zero(),
        try subject.pair(access, relation),
    );
    var main_values: [subject.N_MAIN_COLUMNS]QM31 = undefined;
    for (&main_values, witness.main) |*target, column|
        target.* = QM31.fromBase(column[storage]);
    const evaluation = subject.evaluateRows(
        QM31,
        publicValues(samples[0]),
        try subject.Row(QM31).fromColumns(&main_values),
        QM31.zero(),
        QM31.zero(),
        QM31.one(),
        increment,
        subject.relationValues(relation),
    );
    try std.testing.expect(evaluation.allZero());

    var wrong_main = main_values;
    wrong_main[subject.PREVIOUS_CLOCK_OFFSET] =
        wrong_main[subject.PREVIOUS_CLOCK_OFFSET].add(QM31.one());
    try std.testing.expect(!subject.evaluateRows(
        QM31,
        publicValues(samples[0]),
        try subject.Row(QM31).fromColumns(&wrong_main),
        QM31.zero(),
        QM31.zero(),
        QM31.one(),
        increment,
        subject.relationValues(relation),
    ).allZero());
    wrong_main = main_values;
    wrong_main[subject.DIFFERENCE_BITS_OFFSET] =
        wrong_main[subject.DIFFERENCE_BITS_OFFSET].sub(QM31.one());
    try std.testing.expect(!subject.evaluateRows(
        QM31,
        publicValues(samples[0]),
        try subject.Row(QM31).fromColumns(&wrong_main),
        QM31.zero(),
        QM31.zero(),
        QM31.one(),
        increment,
        subject.relationValues(relation),
    ).allZero());
}

test "read-only observation cancels only its exact predecessor and expected byte" {
    const relation = memory_lookup.Relation.dummy();
    const source = sample(5, 0xc000, 0x42);
    const access = try subject.accessForSample(
        source,
        .{ .clock = 2 },
    );
    const entry = try subject.pair(access, relation);
    try std.testing.expectEqual(entry.d1, relation.combine(
        q(source.key),
        q(2),
        q(source.expected),
    ));
    try std.testing.expectEqual(entry.d2, relation.combine(
        q(source.key),
        q(observationClock(source.mcycle)),
        q(source.expected),
    ));

    var total = try subject.accumulate(QM31.zero(), entry);
    total = try subject.accumulate(
        total,
        boundaryPair(
            relation,
            source.key,
            2,
            source.expected,
            observationClock(source.mcycle),
            source.expected,
        ),
    );
    try std.testing.expect(total.isZero());

    const substitutions = [_]subject.Access{
        .{
            .enabled = true,
            .key = 0xc001,
            .previous_clock = 2,
            .clock = observationClock(5),
            .expected = 0x42,
        },
        .{
            .enabled = true,
            .key = 0xc000,
            .previous_clock = 3,
            .clock = observationClock(5),
            .expected = 0x42,
        },
        .{
            .enabled = true,
            .key = 0xc000,
            .previous_clock = 2,
            .clock = observationClock(5),
            .expected = 0x43,
        },
        .{
            .enabled = true,
            .key = 0xc000,
            .previous_clock = 2,
            .clock = observationClock(5) + 1,
            .expected = 0x42,
        },
    };
    for (substitutions) |substitution| {
        var forged = try subject.accumulate(
            QM31.zero(),
            try subject.pair(substitution, relation),
        );
        forged = try subject.accumulate(
            forged,
            boundaryPair(
                relation,
                source.key,
                2,
                source.expected,
                observationClock(source.mcycle),
                source.expected,
            ),
        );
        try std.testing.expect(!forged.isZero());
    }
    const omitted = try subject.accumulate(
        QM31.zero(),
        boundaryPair(
            relation,
            source.key,
            2,
            source.expected,
            observationClock(source.mcycle),
            source.expected,
        ),
    );
    try std.testing.expect(!omitted.isZero());
}

test "interaction binds exact positive count and rejects inactive vacuity" {
    const samples = scenarioSamples();
    const predecessors = scenarioPredecessors();
    const claim = try subject.scheduleClaim(&samples);
    var witness = try subject.generateWitness(
        std.testing.allocator,
        4,
        &samples,
        &predecessors,
    );
    defer witness.deinit();
    var interaction = try subject.generateInteraction(
        std.testing.allocator,
        witness.accesses,
        4,
        claim,
        memory_lookup.Relation.dummy(),
    );
    defer interaction.deinit();
    try std.testing.expectEqual(claim.count, interaction.count);
    try std.testing.expect(!interaction.claim.isZero());

    var omitted = try std.testing.allocator.dupe(
        subject.Access,
        witness.accesses,
    );
    defer std.testing.allocator.free(omitted);
    omitted[1] = .{};
    try std.testing.expectError(
        error.ObservationCountMismatch,
        subject.generateInteraction(
            std.testing.allocator,
            omitted,
            4,
            claim,
            memory_lookup.Relation.dummy(),
        ),
    );
    var empty_claim = claim;
    empty_claim.count = 0;
    try std.testing.expectError(
        error.EmptyObservationSchedule,
        subject.generateInteraction(
            std.testing.allocator,
            witness.accesses,
            4,
            empty_claim,
            memory_lookup.Relation.dummy(),
        ),
    );

    const inactive = [_]QM31{QM31.zero()} ** subject.N_MAIN_COLUMNS;
    try std.testing.expect(subject.evaluateRows(
        QM31,
        .{ QM31.zero(), QM31.zero(), QM31.zero(), QM31.zero() },
        try subject.Row(QM31).fromColumns(&inactive),
        QM31.zero(),
        QM31.zero(),
        QM31.one(),
        QM31.zero(),
        subject.relationValues(memory_lookup.Relation.dummy()),
    ).allZero());
    var garbage = inactive;
    garbage[subject.DIFFERENCE_BITS_OFFSET] = QM31.one();
    try std.testing.expect(!subject.evaluateRows(
        QM31,
        .{ QM31.zero(), QM31.zero(), QM31.zero(), QM31.zero() },
        try subject.Row(QM31).fromColumns(&garbage),
        QM31.zero(),
        QM31.zero(),
        QM31.one(),
        QM31.zero(),
        subject.relationValues(memory_lookup.Relation.dummy()),
    ).allZero());
}

fn scenarioSamples() [3]subject.Sample {
    return .{
        sample(5, 0xc000, 0x42),
        sample(5, memory_lookup.SRAM_KEY_OFFSET + 3, 0x99),
        sample(8, 0xc000, 0x43),
    };
}

fn scenarioPredecessors() [3]subject.Predecessor {
    return .{
        .{ .clock = 2 },
        .{ .clock = 1 },
        .{ .clock = 60 },
    };
}

fn sample(mcycle: u32, key: anytype, expected: u8) subject.Sample {
    return .{
        .mcycle = mcycle,
        .key = @intCast(key),
        .expected = expected,
    };
}

fn publicValues(source: subject.Sample) [subject.N_PUBLIC_COLUMNS]QM31 {
    return .{
        QM31.one(),
        q(source.mcycle),
        q(source.key),
        q(source.expected),
    };
}

fn observationClock(mcycle: u32) u32 {
    return memory_lookup.memory_clock.phaseClock(
        mcycle,
        subject.OBSERVATION_PHASE,
    ) catch unreachable;
}

fn boundaryPair(
    relation: memory_lookup.Relation,
    key: u17,
    initial_clock: u32,
    initial_value: u8,
    final_clock: u32,
    final_value: u8,
) memory_lookup.RowPair {
    return .{
        .n1 = QM31.one(),
        .d1 = relation.combine(
            q(key),
            q(initial_clock),
            q(initial_value),
        ),
        .n2 = QM31.one().neg(),
        .d2 = relation.combine(
            q(key),
            q(final_clock),
            q(final_value),
        ),
    };
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
}

const RecordingChannel = struct {
    words: [2 + subject.DIGEST_SIZE / 4]u32 =
        [_]u32{0} ** (2 + subject.DIGEST_SIZE / 4),
    count: usize = 0,

    pub fn mixU32s(self: *RecordingChannel, values: []const u32) void {
        @memcpy(self.words[0..values.len], values);
        self.count = values.len;
    }
};
