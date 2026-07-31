//! Public intermediate RAM observations in ordered mutable memory.
//!
//! Each canonical `(mcycle, key, expected)` sample over WRAM C000..DFFF or
//! physical SRAM is a read-only self-transition from its ordered predecessor
//! to `OBSERVATION_PHASE`.
//! The schedule count and SHA-256 digest are public protocol data; a verifier
//! must validate the fixed public table and mix the claim before drawing the
//! shared cartridge-memory relation.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const memory_lookup = @import("cartridge_memory_lookup.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const OBSERVATION_PHASE: u32 =
    memory_lookup.memory_clock.OBSERVATION_PHASE;
pub const N_PUBLIC_COLUMNS: usize = 4;
pub const PREVIOUS_CLOCK_OFFSET: usize = 0;
pub const DIFFERENCE_BITS_OFFSET: usize = 1;
pub const N_MAIN_COLUMNS: usize =
    DIFFERENCE_BITS_OFFSET + memory_lookup.N_DIFF_BITS;
pub const N_INTERACTION_COLUMNS: usize = 4;
pub const N_CONSTRAINTS: usize =
    memory_lookup.N_DIFF_BITS + 7;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;
pub const RECORD_SIZE: usize = 9;
pub const DIGEST_SIZE: usize = Sha256.digest_length;
pub const PUBLIC_CLAIM_TAG: u32 = 0x4f42_5301;

comptime {
    std.debug.assert(
        OBSERVATION_PHASE > memory_lookup.memory_clock.DMA_PHASE,
    );
    std.debug.assert(
        OBSERVATION_PHASE < memory_lookup.memory_clock.PHASES,
    );
}

pub const Sample = struct {
    mcycle: u32,
    key: u17,
    expected: u8,
};

pub const Predecessor = struct {
    clock: u32,
};

pub const ScheduleClaim = struct {
    count: u32,
    digest: [DIGEST_SIZE]u8,

    pub fn mixInto(self: ScheduleClaim, channel: anytype) void {
        var words: [2 + DIGEST_SIZE / 4]u32 = undefined;
        words[0] = PUBLIC_CLAIM_TAG;
        words[1] = self.count;
        for (0..DIGEST_SIZE / 4) |index| {
            words[2 + index] = std.mem.readInt(
                u32,
                self.digest[index * 4 ..][0..4],
                .little,
            );
        }
        channel.mixU32s(&words);
    }
};

pub const PublicTable = struct {
    log_size: u32,
    columns: [N_PUBLIC_COLUMNS][]M31,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *PublicTable) void {
        for (self.columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub const Access = struct {
    enabled: bool = false,
    key: u17 = 0,
    previous_clock: u32 = 0,
    clock: u32 = 0,
    expected: u8 = 0,
};

pub const Witness = struct {
    log_size: u32,
    main: [N_MAIN_COLUMNS][]M31,
    accesses: []Access,
    allocator: std.mem.Allocator,
    owned: bool = true,

    pub fn disownColumns(self: *Witness) void {
        self.owned = false;
    }

    pub fn takeAccesses(self: *Witness) []Access {
        const result = self.accesses;
        self.accesses = &.{};
        return result;
    }

    pub fn deinit(self: *Witness) void {
        if (self.owned)
            for (self.main) |column| self.allocator.free(column);
        if (self.accesses.len != 0) self.allocator.free(self.accesses);
        self.* = undefined;
    }
};

pub const Interaction = struct {
    columns: [N_INTERACTION_COLUMNS][]M31,
    claim: QM31,
    count: u32,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Interaction) void {
        for (self.columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn Row(comptime S: type) type {
    return struct {
        previous_clock: S,
        difference_bits: [memory_lookup.N_DIFF_BITS]S,

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != N_MAIN_COLUMNS)
                return error.InvalidObservationWitnessShape;
            return .{
                .previous_clock = values[PREVIOUS_CLOCK_OFFSET],
                .difference_bits = values[DIFFERENCE_BITS_OFFSET..N_MAIN_COLUMNS].*,
            };
        }
    };
}

pub fn RelationValues(comptime S: type) type {
    return struct {
        z: S,
        clock_coefficient: S,
        value_coefficient: S,
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

pub fn validateSchedule(samples: []const Sample) !void {
    if (samples.len == 0) return error.EmptyObservationSchedule;
    _ = std.math.cast(u32, samples.len) orelse
        return error.TooManyObservations;
    var previous: ?Sample = null;
    for (samples) |sample| {
        _ = observationClock(sample.mcycle) catch
            return error.NonCanonicalObservationMcycle;
        try validateObservationKey(sample.key);
        if (previous) |prior| {
            if (sample.mcycle < prior.mcycle or
                (sample.mcycle == prior.mcycle and
                    sample.key < prior.key))
                return error.NonCanonicalObservationOrder;
            if (sample.mcycle == prior.mcycle and
                sample.key == prior.key)
                return error.DuplicateObservation;
        }
        previous = sample;
    }
}

pub fn canonicalRecord(sample: Sample) [RECORD_SIZE]u8 {
    var result: [RECORD_SIZE]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], sample.mcycle, .little);
    std.mem.writeInt(u32, result[4..8], sample.key, .little);
    result[8] = sample.expected;
    return result;
}

pub fn scheduleClaim(samples: []const Sample) !ScheduleClaim {
    try validateSchedule(samples);
    const count = std.math.cast(u32, samples.len) orelse
        return error.TooManyObservations;
    var hasher = Sha256.init(.{});
    hasher.update("stwo-zig/sm83/intermediate-ram-observation/v1\x00");
    var count_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &count_bytes, count, .little);
    hasher.update(&count_bytes);
    for (samples) |sample| {
        const record = canonicalRecord(sample);
        hasher.update(&record);
    }
    var digest: [DIGEST_SIZE]u8 = undefined;
    hasher.final(&digest);
    return .{ .count = count, .digest = digest };
}

pub fn generatePublicTable(
    allocator: std.mem.Allocator,
    log_size: u32,
    samples: []const Sample,
) !PublicTable {
    try validateSchedule(samples);
    const size = try traceSize(log_size);
    if (samples.len > size)
        return error.TooManyObservationsForTrace;
    var result = PublicTable{
        .log_size = log_size,
        .columns = undefined,
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
    for (samples, 0..) |sample, row| {
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row,
        );
        result.columns[0][storage] = M31.one();
        result.columns[1][storage] =
            M31.fromCanonical(sample.mcycle);
        result.columns[2][storage] =
            M31.fromCanonical(sample.key);
        result.columns[3][storage] =
            M31.fromCanonical(sample.expected);
    }
    return result;
}

pub fn validatePublicTable(
    columns: []const []const M31,
    log_size: u32,
    samples: []const Sample,
) !void {
    if (columns.len != N_PUBLIC_COLUMNS)
        return error.InvalidPublicTableShape;
    var expected = try generatePublicTable(
        std.heap.page_allocator,
        log_size,
        samples,
    );
    defer expected.deinit();
    for (columns, expected.columns) |actual, canonical| {
        if (actual.len != canonical.len)
            return error.NonCanonicalPublicTable;
        for (actual, canonical) |value, expected_value|
            if (value.v != expected_value.v)
                return error.NonCanonicalPublicTable;
    }
}

pub fn generateWitness(
    allocator: std.mem.Allocator,
    log_size: u32,
    samples: []const Sample,
    predecessors: []const Predecessor,
) !Witness {
    try validateSchedule(samples);
    const size = try traceSize(log_size);
    if (samples.len > size)
        return error.TooManyObservationsForTrace;
    if (predecessors.len != samples.len)
        return error.InvalidPredecessorCount;
    var result = Witness{
        .log_size = log_size,
        .main = undefined,
        .accesses = try allocator.alloc(Access, size),
        .allocator = allocator,
    };
    errdefer allocator.free(result.accesses);
    @memset(result.accesses, Access{});
    var initialized: usize = 0;
    errdefer for (result.main[0..initialized]) |column|
        allocator.free(column);
    for (&result.main) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    for (samples, predecessors, 0..) |
        sample,
        predecessor,
        row,
    | {
        const access = try accessForSample(sample, predecessor);
        result.accesses[row] = access;
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row,
        );
        result.main[PREVIOUS_CLOCK_OFFSET][storage] =
            M31.fromCanonical(access.previous_clock);
        const difference =
            access.clock - access.previous_clock - 1;
        for (0..memory_lookup.N_DIFF_BITS) |bit_index| {
            result.main[
                DIFFERENCE_BITS_OFFSET + bit_index
            ][storage] = M31.fromCanonical(
                (difference >> @intCast(bit_index)) & 1,
            );
        }
    }
    return result;
}

pub fn accessForSample(
    sample: Sample,
    predecessor: Predecessor,
) !Access {
    try validateObservationKey(sample.key);
    const clock = observationClock(sample.mcycle) catch
        return error.NonCanonicalObservationMcycle;
    if (predecessor.clock >= clock)
        return error.InvalidObservationPredecessorClock;
    if (clock - predecessor.clock - 1 >=
        (@as(u32, 1) << memory_lookup.N_DIFF_BITS))
        return error.ObservationClockDifferenceTooLarge;
    return .{
        .enabled = true,
        .key = sample.key,
        .previous_clock = predecessor.clock,
        .clock = clock,
        .expected = sample.expected,
    };
}

pub fn pair(
    access: Access,
    relation: memory_lookup.Relation,
) !memory_lookup.RowPair {
    try validateAccess(access);
    if (!access.enabled) return neutralPair();
    return .{
        .n1 = QM31.one().neg(),
        .d1 = relation.combine(
            q(access.key),
            q(access.previous_clock),
            q(access.expected),
        ),
        .n2 = QM31.one(),
        .d2 = relation.combine(
            q(access.key),
            q(access.clock),
            q(access.expected),
        ),
    };
}

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    accesses: []const Access,
    log_size: u32,
    public_claim: ScheduleClaim,
    relation: memory_lookup.Relation,
) !Interaction {
    if (public_claim.count == 0)
        return error.EmptyObservationSchedule;
    const size = try traceSize(log_size);
    if (accesses.len != size) return error.InvalidTraceLength;
    var columns: [N_INTERACTION_COLUMNS][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column|
        allocator.free(column);
    for (&columns) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    var claim = QM31.zero();
    var count: u32 = 0;
    for (accesses, 0..) |access, row| {
        claim = try accumulate(claim, try pair(access, relation));
        count = std.math.add(
            u32,
            count,
            @intFromBool(access.enabled),
        ) catch return error.TooManyObservations;
        writeSecure(
            &columns,
            try core_air_utils.circleBitReversedIndex(log_size, row),
            claim,
        );
    }
    if (count != public_claim.count)
        return error.ObservationCountMismatch;
    return .{
        .columns = columns,
        .claim = claim,
        .count = count,
        .allocator = allocator,
    };
}

pub fn evaluateRows(
    comptime S: type,
    public: [N_PUBLIC_COLUMNS]S,
    row: Row(S),
    current: S,
    previous: S,
    is_first: S,
    claim: S,
    relation: RelationValues(S),
) Evaluation(S) {
    const one = S.one();
    const active = public[0];
    const clock = observationClockField(S, public[1]);
    var difference = S.zero();
    var power = one;
    var out: [N_CONSTRAINTS]S = undefined;
    var at: usize = 0;
    out[at] = active.mul(active.sub(one));
    at += 1;
    out[at] = one.sub(active).mul(public[1]);
    at += 1;
    out[at] = one.sub(active).mul(public[2]);
    at += 1;
    out[at] = one.sub(active).mul(public[3]);
    at += 1;
    out[at] = one.sub(active).mul(row.previous_clock);
    at += 1;
    for (row.difference_bits) |bit_value| {
        out[at] = bit_value.mul(bit_value.sub(active));
        at += 1;
        difference = difference.add(power.mul(bit_value));
        power = power.add(power);
    }
    out[at] = active.mul(
        clock.sub(row.previous_clock).sub(one).sub(difference),
    );
    at += 1;
    const d1 = combine(
        S,
        relation,
        public[2],
        row.previous_clock,
        public[3],
    );
    const d2 = combine(
        S,
        relation,
        public[2],
        clock,
        public[3],
    );
    out[at] = recurrence(
        S,
        current,
        previous,
        is_first,
        claim,
        active.neg(),
        d1,
        active,
        d2,
    );
    at += 1;
    std.debug.assert(at == out.len);
    return .{ .values = out };
}

pub fn relationValues(
    relation: memory_lookup.Relation,
) RelationValues(QM31) {
    return .{
        .z = relation.z,
        .clock_coefficient = relation.clock_coefficient,
        .value_coefficient = relation.value_coefficient,
    };
}

pub fn accumulate(
    current: QM31,
    entry: memory_lookup.RowPair,
) !QM31 {
    if (entry.n1.isZero() and entry.n2.isZero()) return current;
    const denominator = entry.d1.mul(entry.d2);
    const numerator =
        entry.n1.mul(entry.d2).add(entry.n2.mul(entry.d1));
    return current.add(numerator.mul(denominator.inv() catch
        return error.ObservationLookupZeroDenominator));
}

fn observationClock(mcycle: u32) !u32 {
    return memory_lookup.memory_clock.phaseClock(
        mcycle,
        OBSERVATION_PHASE,
    );
}

fn observationClockField(comptime S: type, mcycle: S) S {
    return mcycle
        .mul(constant(S, memory_lookup.memory_clock.PHASES))
        .add(constant(S, OBSERVATION_PHASE + 1));
}

fn validateAccess(access: Access) !void {
    if (!access.enabled) {
        if (access.key != 0 or access.previous_clock != 0 or
            access.clock != 0 or access.expected != 0)
            return error.InvalidInactiveObservation;
        return;
    }
    try validateObservationKey(access.key);
    if (access.previous_clock >= access.clock)
        return error.InvalidObservationPredecessorClock;
    if (access.clock - access.previous_clock - 1 >=
        (@as(u32, 1) << memory_lookup.N_DIFF_BITS))
        return error.ObservationClockDifferenceTooLarge;
}

fn validateObservationKey(key: u17) !void {
    if (key >= memory_lookup.KEY_COUNT)
        return error.ObservationKeyOutOfRange;
    if ((key >= 0xc000 and key < 0xe000) or
        key >= memory_lookup.SRAM_KEY_OFFSET)
        return;
    return error.ObservationKeyOutsideDomain;
}

fn combine(
    comptime S: type,
    relation: RelationValues(S),
    key: S,
    clock: S,
    value: S,
) S {
    return key
        .add(relation.clock_coefficient.mul(clock))
        .add(relation.value_coefficient.mul(value))
        .sub(relation.z);
}

fn recurrence(
    comptime S: type,
    current: S,
    previous: S,
    is_first: S,
    claim: S,
    n1: S,
    d1: S,
    n2: S,
    d2: S,
) S {
    const delta = current.sub(previous).add(is_first.mul(claim));
    return delta.mul(d1).mul(d2)
        .sub(n1.mul(d2))
        .sub(n2.mul(d1));
}

fn neutralPair() memory_lookup.RowPair {
    return .{
        .n1 = QM31.zero(),
        .d1 = QM31.one(),
        .n2 = QM31.zero(),
        .d2 = QM31.one(),
    };
}

fn traceSize(log_size: u32) !usize {
    if (log_size < 4 or log_size >= @bitSizeOf(usize))
        return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn writeSecure(
    columns: []const []M31,
    row: usize,
    value: QM31,
) void {
    for (columns, value.toM31Array()) |column, coordinate|
        column[row] = coordinate;
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
}

fn constant(comptime S: type, value: anytype) S {
    const base = M31.fromU64(@intCast(value));
    if (S == M31) return base;
    return S.fromBase(base);
}
