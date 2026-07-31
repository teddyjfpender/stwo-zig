//! Authenticated scheduler IE/IF samples in ordered cartridge memory.
//!
//! Every active row contributes pre-state IE/IF reads in scheduler phase 1
//! and a post-state IF read in observation phase 9 of its final M-cycle. The
//! predecessors come from the shared replay, so device writes during the row
//! are authenticated before the scheduler's after-state IF is sampled.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const runner = @import("../runner/mod.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const scheduler = @import("scheduler.zig");
const scheduler_component = @import("scheduler_component.zig");

pub const N_SAMPLES: usize = 3;
pub const SCHEDULER_PHASE: u32 =
    memory_lookup.memory_clock.SCHEDULER_PHASE;
pub const OBSERVATION_PHASE: u32 =
    memory_lookup.memory_clock.OBSERVATION_PHASE;
pub const N_HIGH_BITS: usize = 3;
pub const N_DIFF_BITS: usize = memory_lookup.N_DIFF_BITS;
pub const PREVIOUS_CLOCK_OFFSET: usize = 0;
pub const HIGH_BITS_OFFSET: usize = PREVIOUS_CLOCK_OFFSET + 1;
pub const DIFFERENCE_BITS_OFFSET: usize =
    HIGH_BITS_OFFSET + N_HIGH_BITS;
pub const N_SAMPLE_COLUMNS: usize =
    DIFFERENCE_BITS_OFFSET + N_DIFF_BITS;
pub const N_MAIN_COLUMNS: usize = N_SAMPLES * N_SAMPLE_COLUMNS;
pub const N_CONSTRAINTS: usize =
    N_SAMPLES * (N_HIGH_BITS + N_DIFF_BITS + 2) + 4;
pub const N_INTERACTION_COLUMNS: usize = N_SAMPLES * 4;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

pub const SampleIndex = enum(usize) {
    interrupt_enable,
    interrupt_flags,
    post_interrupt_flags,
};

pub const Boundary = struct {
    initial_mcycle: u32,
    final_mcycle: u32,
};

pub const Predecessor = struct {
    clock: u32 = 0,
    value: u8 = 0,
};

pub const Predecessors = struct {
    interrupt_enable: Predecessor = .{},
    interrupt_flags: Predecessor = .{},
    post_interrupt_flags: Predecessor = .{},

    pub fn at(
        self: Predecessors,
        index: SampleIndex,
    ) Predecessor {
        return switch (index) {
            .interrupt_enable => self.interrupt_enable,
            .interrupt_flags => self.interrupt_flags,
            .post_interrupt_flags => self.post_interrupt_flags,
        };
    }
};

pub const Sample = struct {
    enabled: bool = false,
    previous_clock: u32 = 0,
    value: u8 = 0,
    clock: u32 = 0,
};

pub const RowSamples = [N_SAMPLES]Sample;

pub fn SampleRow(comptime S: type) type {
    return struct {
        previous_clock: S,
        high_bits: [N_HIGH_BITS]S,
        difference_bits: [N_DIFF_BITS]S,
    };
}

pub fn Row(comptime S: type) type {
    return struct {
        samples: [N_SAMPLES]SampleRow(S),

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != N_MAIN_COLUMNS)
                return error.InvalidSchedulerMemoryShape;
            var samples: [N_SAMPLES]SampleRow(S) = undefined;
            for (&samples, 0..) |*sample, index| {
                const offset = index * N_SAMPLE_COLUMNS;
                sample.* = .{
                    .previous_clock = values[offset + PREVIOUS_CLOCK_OFFSET],
                    .high_bits = values[offset + HIGH_BITS_OFFSET ..][0..N_HIGH_BITS].*,
                    .difference_bits = values[offset + DIFFERENCE_BITS_OFFSET ..][0..N_DIFF_BITS].*,
                };
            }
            return .{ .samples = samples };
        }
    };
}

pub fn Evaluation(comptime S: type) type {
    return struct {
        values: [N_CONSTRAINTS]S,

        pub fn allZero(self: @This()) bool {
            for (self.values) |value|
                if (!value.isZero()) return false;
            return true;
        }
    };
}

pub fn evaluate(
    comptime S: type,
    scheduler_values: []const S,
    memory_values: []const S,
    is_first: S,
    is_last: S,
    boundary: Boundary,
) !Evaluation(S) {
    try validateBoundary(boundary);
    const scheduled =
        try scheduler_component.Row(S).fromColumns(scheduler_values);
    const row = try Row(S).fromColumns(memory_values);
    const one = S.one();
    const enabled = scheduled.active;
    var out: [N_CONSTRAINTS]S = undefined;
    var at: usize = 0;

    for (row.samples, 0..) |sample, index_value| {
        const index: SampleIndex = @enumFromInt(index_value);
        for (sample.high_bits) |bit_value| {
            out[at] = bit_value.mul(
                bit_value.sub(scheduled.active),
            );
            at += 1;
        }
        var difference = S.zero();
        var power = S.one();
        for (sample.difference_bits) |bit_value| {
            out[at] = bit_value.mul(bit_value.sub(enabled));
            at += 1;
            difference = difference.add(power.mul(bit_value));
            power = power.add(power);
        }
        out[at] = one.sub(enabled).mul(sample.previous_clock);
        at += 1;
        out[at] = enabled.mul(
            fieldSampleClock(S, scheduled, index)
                .sub(sample.previous_clock)
                .sub(one).sub(difference),
        );
        at += 1;
    }
    out[at] = is_first.mul(scheduled.active.sub(one));
    at += 1;
    out[at] = is_last.mul(scheduled.active.sub(one));
    at += 1;
    out[at] = is_first.mul(scheduled.active).mul(
        scheduled.mcycle.sub(constant(S, boundary.initial_mcycle)),
    );
    at += 1;
    out[at] = is_last.mul(scheduled.active).mul(
        scheduled.mcycle
            .add(compose(scheduled.scheduler.mcycle_bits))
            .sub(constant(S, boundary.final_mcycle)),
    );
    at += 1;
    std.debug.assert(at == out.len);
    return .{ .values = out };
}

pub fn columns(
    step: scheduler.ValidatedStep,
    mcycle: u32,
    predecessors: Predecessors,
) ![N_MAIN_COLUMNS]M31 {
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    const result = step.result;
    const values = [N_SAMPLES]u8{
        result.before.interrupt_enable,
        result.before.interrupt_flags,
        result.after.interrupt_flags,
    };
    for (values, 0..) |value, index_value| {
        const index: SampleIndex = @enumFromInt(index_value);
        const predecessor = predecessors.at(index);
        const sample_clock = try sampleClock(
            mcycle,
            result.m_cycles,
            index,
        );
        const offset = index_value * N_SAMPLE_COLUMNS;
        writeBits(
            out[offset + HIGH_BITS_OFFSET ..][0..N_HIGH_BITS],
            value >> 5,
        );
        if (predecessor.value != value)
            return error.SchedulerMemoryReadMismatch;
        if (predecessor.clock >= sample_clock)
            return error.InvalidSchedulerMemoryClock;
        const difference =
            sample_clock - predecessor.clock - 1;
        if (difference >= (@as(u32, 1) << N_DIFF_BITS))
            return error.SchedulerMemoryClockDifferenceTooLarge;
        out[offset + PREVIOUS_CLOCK_OFFSET] =
            M31.fromCanonical(predecessor.clock);
        writeBits(
            out[offset + DIFFERENCE_BITS_OFFSET ..][0..N_DIFF_BITS],
            difference,
        );
    }
    return out;
}

pub const Witness = struct {
    log_size: u32,
    main: [N_MAIN_COLUMNS][]M31,
    samples: []RowSamples,
    allocator: std.mem.Allocator,
    main_owned: bool = true,

    pub fn disownColumns(self: *Witness) void {
        self.main_owned = false;
    }

    pub fn deinit(self: *Witness) void {
        if (self.main_owned)
            for (self.main) |column| self.allocator.free(column);
        self.allocator.free(self.samples);
        self.* = undefined;
    }
};

pub fn generateWitness(
    allocator: std.mem.Allocator,
    results: anytype,
    boundary: Boundary,
    predecessors: []const Predecessors,
) !Witness {
    try validateBoundary(boundary);
    if (results.len < 16 or
        !std.math.isPowerOfTwo(results.len))
        return error.InvalidSchedulerTraceLength;
    if (predecessors.len != results.len)
        return error.InvalidSchedulerPredecessorCount;
    const log_size: u32 =
        @intCast(std.math.log2_int(usize, results.len));
    var witness = Witness{
        .log_size = log_size,
        .main = undefined,
        .samples = try allocator.alloc(RowSamples, results.len),
        .allocator = allocator,
    };
    errdefer allocator.free(witness.samples);
    @memset(
        witness.samples,
        [_]Sample{.{}} ** N_SAMPLES,
    );
    var initialized: usize = 0;
    errdefer for (witness.main[0..initialized]) |column|
        allocator.free(column);
    for (&witness.main) |*column| {
        column.* = try allocator.alloc(M31, results.len);
        @memset(column.*, M31.zero());
        initialized += 1;
    }

    var mcycle = boundary.initial_mcycle;
    for (results, predecessors, 0..) |
        result,
        row_predecessors,
        row_index,
    | {
        const validated = scheduler.ValidatedStep.init(result) catch
            return error.InvalidSchedulerStep;
        const row = try columns(
            validated,
            mcycle,
            row_predecessors,
        );
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row_index,
        );
        for (witness.main, row) |column, value|
            column[storage] = value;

        const canonical = validated.result;
        const values = [N_SAMPLES]u8{
            canonical.before.interrupt_enable,
            canonical.before.interrupt_flags,
            canonical.after.interrupt_flags,
        };
        for (&witness.samples[row_index], values, 0..) |
            *sample,
            value,
            index_value,
        | {
            const index: SampleIndex = @enumFromInt(index_value);
            const sample_clock = try sampleClock(
                mcycle,
                canonical.m_cycles,
                index,
            );
            sample.* = .{
                .enabled = true,
                .previous_clock = row_predecessors.at(index).clock,
                .value = value,
                .clock = sample_clock,
            };
        }
        mcycle = std.math.add(
            u32,
            mcycle,
            canonical.m_cycles,
        ) catch return error.SchedulerMemoryClockOverflow;
    }
    if (mcycle != boundary.final_mcycle)
        return error.InvalidSchedulerFinalClock;
    return witness;
}

pub fn evaluateM31(
    scheduler_values: [scheduler_component.N_MAIN_COLUMNS]M31,
    memory_values: [N_MAIN_COLUMNS]M31,
    is_first: bool,
    is_last: bool,
    boundary: Boundary,
) !Evaluation(QM31) {
    var scheduled: [scheduler_component.N_MAIN_COLUMNS]QM31 = undefined;
    var memory: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&scheduled, scheduler_values) |*target, source|
        target.* = QM31.fromBase(source);
    for (&memory, memory_values) |*target, source|
        target.* = QM31.fromBase(source);
    return evaluate(
        QM31,
        &scheduled,
        &memory,
        booleanQ(is_first),
        booleanQ(is_last),
        boundary,
    );
}

pub const Claims = struct {
    samples: [N_SAMPLES]QM31,

    pub fn total(self: Claims) QM31 {
        var result = QM31.zero();
        for (self.samples) |claim| result = result.add(claim);
        return result;
    }
};

pub const Interaction = struct {
    columns: [N_INTERACTION_COLUMNS][]M31,
    claims: Claims,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Interaction) void {
        for (self.columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    samples: []const RowSamples,
    log_size: u32,
    relation: memory_lookup.Relation,
) !Interaction {
    const size = try traceSize(log_size);
    if (samples.len != size) return error.InvalidSchedulerTraceLength;
    var result = Interaction{
        .columns = undefined,
        .claims = .{
            .samples = [_]QM31{QM31.zero()} ** N_SAMPLES,
        },
        .allocator = allocator,
    };
    var initialized: usize = 0;
    errdefer for (result.columns[0..initialized]) |column|
        allocator.free(column);
    for (&result.columns) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    var previous_clocks = [_]u32{0} ** N_SAMPLES;
    for (samples, 0..) |row, row_index| {
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row_index,
        );
        for (row, 0..) |sample, index_value| {
            try validateSample(sample);
            if (sample.enabled) {
                if (previous_clocks[index_value] >= sample.clock)
                    return error.NonIncreasingSchedulerSampleClock;
                previous_clocks[index_value] = sample.clock;
            }
            const entry = try pairForSample(
                @enumFromInt(index_value),
                sample,
                relation,
            );
            result.claims.samples[index_value] = try accumulate(
                result.claims.samples[index_value],
                entry,
            );
            writeSecure(
                result.columns[4 * index_value ..][0..4],
                storage,
                result.claims.samples[index_value],
            );
        }
    }
    return result;
}

pub fn pairsForRows(
    scheduled: scheduler_component.Row(QM31),
    row: Row(QM31),
    is_first: QM31,
    relation: memory_lookup.Relation,
) [N_SAMPLES]memory_lookup.RowPair {
    _ = is_first;
    const enabled = scheduled.active;
    var pairs: [N_SAMPLES]memory_lookup.RowPair = undefined;
    for (&pairs, row.samples, 0..) |*entry, sample, index_value| {
        const index: SampleIndex = @enumFromInt(index_value);
        const value = sampleValue(
            QM31,
            scheduled,
            sample,
            index,
        );
        const sample_clock =
            fieldSampleClock(QM31, scheduled, index);
        entry.* = .{
            .n1 = enabled.neg(),
            .d1 = relation.combine(
                q(address(index)),
                sample.previous_clock,
                value,
            ),
            .n2 = enabled,
            .d2 = relation.combine(
                q(address(index)),
                sample_clock,
                value,
            ),
        };
    }
    return pairs;
}

pub fn verifyCancellation(
    memory_claims: memory_lookup.Claims,
    scheduler_claims: Claims,
) !void {
    // This two-party helper is only complete when no device also contributes
    // to the shared memory relation. Environment statements must sum every
    // device claim together with these scheduler samples.
    if (!memory_claims.total().add(
        scheduler_claims.total(),
    ).isZero()) return error.SchedulerMemoryLookupSumNonZero;
}

fn pairForSample(
    index: SampleIndex,
    sample: Sample,
    relation: memory_lookup.Relation,
) !memory_lookup.RowPair {
    try validateSample(sample);
    if (!sample.enabled) return .{
        .n1 = QM31.zero(),
        .d1 = QM31.one(),
        .n2 = QM31.zero(),
        .d2 = QM31.one(),
    };
    return .{
        .n1 = QM31.one().neg(),
        .d1 = relation.combine(
            q(address(index)),
            q(sample.previous_clock),
            q(sample.value),
        ),
        .n2 = QM31.one(),
        .d2 = relation.combine(
            q(address(index)),
            q(sample.clock),
            q(sample.value),
        ),
    };
}

fn sampleValue(
    comptime S: type,
    scheduled: scheduler_component.Row(S),
    sample: SampleRow(S),
    index: SampleIndex,
) S {
    const low = switch (index) {
        .interrupt_enable => scheduled.scheduler.ie_bits,
        .interrupt_flags => scheduled.scheduler.if_bits,
        .post_interrupt_flags => scheduled.scheduler.post_if_bits,
    };
    var value = compose(low);
    var power = constant(S, 32);
    for (sample.high_bits) |bit_value| {
        value = value.add(power.mul(bit_value));
        power = power.add(power);
    }
    return value;
}

fn address(index: SampleIndex) u16 {
    return switch (index) {
        .interrupt_enable => 0xffff,
        .interrupt_flags,
        .post_interrupt_flags,
        => runner.cartridge_memory.INTERRUPT_FLAGS,
    };
}

fn sampleClock(
    mcycle: u32,
    m_cycles: u3,
    index: SampleIndex,
) !u32 {
    const sample_mcycle = switch (index) {
        .interrupt_enable, .interrupt_flags => mcycle,
        .post_interrupt_flags => std.math.add(
            u32,
            mcycle,
            @intCast(std.math.sub(u3, m_cycles, 1) catch
                return error.InvalidSchedulerMemoryClock),
        ) catch return error.SchedulerMemoryClockOverflow,
    };
    if (sample_mcycle > memory_lookup.memory_clock.MAX_FINAL_MCYCLE)
        return error.NonCanonicalSchedulerMemoryClock;
    return memory_lookup.memory_clock.phaseClock(
        sample_mcycle,
        phase(index),
    ) catch |err| switch (err) {
        error.MemoryClockOverflow => error.SchedulerMemoryClockOverflow,
        error.MemoryClockOutsideField,
        error.InvalidMemoryClockPhase,
        => error.NonCanonicalSchedulerMemoryClock,
    };
}

fn fieldSampleClock(
    comptime S: type,
    scheduled: scheduler_component.Row(S),
    index: SampleIndex,
) S {
    const mcycle = switch (index) {
        .interrupt_enable, .interrupt_flags => scheduled.mcycle,
        .post_interrupt_flags => scheduled.mcycle
            .add(compose(scheduled.scheduler.mcycle_bits))
            .sub(S.one()),
    };
    return memory_lookup.memory_clock.fieldClock(
        S,
        mcycle,
        phase(index),
    );
}

fn phase(index: SampleIndex) u32 {
    return switch (index) {
        .interrupt_enable, .interrupt_flags => SCHEDULER_PHASE,
        .post_interrupt_flags => OBSERVATION_PHASE,
    };
}

fn validateBoundary(boundary: Boundary) !void {
    if (boundary.initial_mcycle >= boundary.final_mcycle)
        return error.InvalidSchedulerMemoryBoundary;
    if (boundary.final_mcycle >
        memory_lookup.memory_clock.MAX_FINAL_MCYCLE)
        return error.NonCanonicalSchedulerMemoryClock;
}

fn validateSample(sample: Sample) !void {
    if (!sample.enabled) {
        if (sample.previous_clock != 0 or sample.value != 0 or
            sample.clock != 0)
            return error.InvalidInactiveSchedulerSample;
        return;
    }
    if (sample.previous_clock >= sample.clock)
        return error.InvalidSchedulerMemoryClock;
    if (sample.clock - sample.previous_clock - 1 >=
        (@as(u32, 1) << N_DIFF_BITS))
        return error.SchedulerMemoryClockDifferenceTooLarge;
}

fn accumulate(
    current: QM31,
    entry: memory_lookup.RowPair,
) !QM31 {
    if (entry.n1.isZero() and entry.n2.isZero()) return current;
    const denominator = entry.d1.mul(entry.d2);
    const numerator =
        entry.n1.mul(entry.d2).add(entry.n2.mul(entry.d1));
    return current.add(numerator.mul(
        denominator.inv() catch
            return error.SchedulerMemoryLookupZeroDenominator,
    ));
}

fn traceSize(log_size: u32) !usize {
    if (log_size < 4 or log_size >= @bitSizeOf(usize))
        return error.InvalidSchedulerMemoryLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn writeBits(target: []M31, value: anytype) void {
    for (target, 0..) |*bit_value, index|
        bit_value.* = M31.fromCanonical(
            @intCast(value >> @intCast(index) & 1),
        );
}

fn writeSecure(
    target_columns: []const []M31,
    row: usize,
    value: QM31,
) void {
    for (target_columns, value.toM31Array()) |column, coordinate|
        column[row] = coordinate;
}

fn compose(bits: anytype) @TypeOf(bits[0]) {
    const S = @TypeOf(bits[0]);
    var result = S.zero();
    var power = S.one();
    for (bits) |bit_value| {
        result = result.add(power.mul(bit_value));
        power = power.add(power);
    }
    return result;
}

fn constant(comptime S: type, value: anytype) S {
    const base = M31.fromU64(@intCast(value));
    if (S == M31) return base;
    return S.fromBase(base);
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
}

fn booleanQ(value: bool) QM31 {
    return if (value) QM31.one() else QM31.zero();
}
