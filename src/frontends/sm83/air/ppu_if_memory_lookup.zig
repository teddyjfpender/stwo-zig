//! PPU interrupt-request contribution to authenticated system memory.
//!
//! Every proven PPU row that requests VBlank and/or STAT contributes one
//! ordered FF0F transition at the PPU memory phase. A simultaneous VBlank and
//! STAT edge is one canonical OR update, never two writes at the same clock.
//! Global authenticated-memory cancellation and the PPU semantic/binding
//! components remain separate owners.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const runner = @import("../runner/mod.zig");
const ppu_runner = @import("../runner/ppu_timing.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const ppu_air = @import("ppu_timing.zig");
const ppu_binding = @import("ppu_binding.zig");

pub const N_VALUE_BITS: usize = 8;
pub const N_DIFF_BITS: usize = memory_lookup.N_DIFF_BITS;
pub const N_MASKED_BITS: usize = 2;
pub const PREVIOUS_CLOCK_OFFSET: usize = 0;
pub const PREVIOUS_VALUE_OFFSET: usize = PREVIOUS_CLOCK_OFFSET + 1;
pub const DIFFERENCE_BITS_OFFSET: usize =
    PREVIOUS_VALUE_OFFSET + N_VALUE_BITS;
pub const MASKED_BITS_OFFSET: usize =
    DIFFERENCE_BITS_OFFSET + N_DIFF_BITS;
pub const N_MAIN_COLUMNS: usize = MASKED_BITS_OFFSET + N_MASKED_BITS;
pub const N_CONSTRAINTS: usize =
    N_VALUE_BITS + N_DIFF_BITS + 3 + N_MASKED_BITS;
pub const N_INTERACTION_COLUMNS: usize = 4;

pub const Predecessor = struct {
    clock: u32 = 0,
    value: u8 = 0,
};

pub const Access = struct {
    enabled: bool = false,
    vblank: bool = false,
    stat: bool = false,
    previous_clock: u32 = 0,
    previous_value: u8 = 0,
    clock: u32 = 0,
    next_value: u8 = 0,
};

pub fn Row(comptime S: type) type {
    return struct {
        previous_clock: S,
        previous_value: [N_VALUE_BITS]S,
        difference_bits: [N_DIFF_BITS]S,
        masked_previous: [N_MASKED_BITS]S,

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != N_MAIN_COLUMNS)
                return error.InvalidPpuIfMemoryShape;
            return .{
                .previous_clock = values[PREVIOUS_CLOCK_OFFSET],
                .previous_value = values[PREVIOUS_VALUE_OFFSET..DIFFERENCE_BITS_OFFSET].*,
                .difference_bits = values[DIFFERENCE_BITS_OFFSET..MASKED_BITS_OFFSET].*,
                .masked_previous = values[MASKED_BITS_OFFSET..N_MAIN_COLUMNS].*,
            };
        }
    };
}

pub fn PpuRow(comptime S: type) type {
    return struct {
        active: S,
        semantic: ppu_air.Semantics(S).Row,
        mcycle: S,

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != ppu_binding.N_MAIN_COLUMNS)
                return error.InvalidPpuBindingShape;
            return .{
                .active = values[0],
                .semantic = try ppu_air.Semantics(S).Row.fromColumns(
                    values[1..ppu_binding.MCYCLE_OFFSET],
                ),
                .mcycle = values[ppu_binding.MCYCLE_OFFSET],
            };
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
    ppu: PpuRow(S),
    row: Row(S),
) Evaluation(S) {
    const one = S.one();
    const vblank = ppu.semantic.interrupts[0];
    const stat = ppu.semantic.interrupts[1];
    const requested = boolOr(S, vblank, stat);
    var out: [N_CONSTRAINTS]S = undefined;
    var at: usize = 0;
    for (row.previous_value) |bit_value| {
        out[at] = bit_value.mul(bit_value.sub(requested));
        at += 1;
    }
    var difference = S.zero();
    var power = one;
    for (row.difference_bits) |bit_value| {
        out[at] = bit_value.mul(bit_value.sub(requested));
        at += 1;
        difference = difference.add(power.mul(bit_value));
        power = power.add(power);
    }
    out[at] = one.sub(requested).mul(row.previous_clock);
    at += 1;
    out[at] = requested.mul(one.sub(ppu.active));
    at += 1;
    out[at] = requested.mul(
        phasedClock(S, ppu)
            .sub(row.previous_clock)
            .sub(one)
            .sub(difference),
    );
    at += 1;
    out[at] = row.masked_previous[0].sub(
        vblank.mul(row.previous_value[0]),
    );
    at += 1;
    out[at] = row.masked_previous[1].sub(
        stat.mul(row.previous_value[1]),
    );
    at += 1;
    std.debug.assert(at == out.len);
    return .{ .values = out };
}

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

pub fn generateWitness(
    allocator: std.mem.Allocator,
    ppu_log_size: u32,
    events: []const ppu_binding.EventRow,
    predecessors: []const Predecessor,
) !Witness {
    const size = try traceSize(ppu_log_size);
    if (events.len == 0) return error.EmptyPpuTrace;
    if (events.len > size) return error.TooManyPpuEvents;
    if (predecessors.len != events.len)
        return error.InvalidPredecessorCount;
    var result = Witness{
        .log_size = ppu_log_size,
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

    var last_request_clock: ?u32 = null;
    for (events, predecessors, 0..) |event, predecessor, index| {
        const access = try accessForEvent(event, predecessor);
        if (access.enabled) {
            if (last_request_clock != null and
                last_request_clock.? >= access.clock)
                return error.PpuIfClockCollision;
            last_request_clock = access.clock;
        }
        result.accesses[index] = access;
        const values = try columnsForAccess(access);
        const storage = try core_air_utils.circleBitReversedIndex(
            ppu_log_size,
            index,
        );
        for (result.main, values) |column, value|
            column[storage] = value;
    }
    return result;
}

pub fn accessForEvent(
    event: ppu_binding.EventRow,
    predecessor: Predecessor,
) !Access {
    _ = ppu_binding.columns(event) catch
        return error.InvalidPpuBindingEvent;
    const vblank = event.transition.interrupts.vblank;
    const stat = event.transition.interrupts.stat;
    if (!vblank and !stat) {
        if (predecessor.clock != 0 or predecessor.value != 0)
            return error.InvalidInactivePredecessor;
        return .{};
    }
    const clock = memory_lookup.memory_clock.phaseClock(
        event.mcycle,
        memory_lookup.memory_clock.PPU_PHASE,
    ) catch return error.NonCanonicalPpuIfClock;
    if (predecessor.clock >= clock)
        return error.InvalidPpuIfPredecessorClock;
    const difference = clock - predecessor.clock - 1;
    if (difference >= (@as(u32, 1) << N_DIFF_BITS))
        return error.PpuIfClockDifferenceTooLarge;
    const mask = interruptMask(vblank, stat);
    return .{
        .enabled = true,
        .vblank = vblank,
        .stat = stat,
        .previous_clock = predecessor.clock,
        .previous_value = predecessor.value,
        .clock = clock,
        .next_value = predecessor.value | mask,
    };
}

pub fn columnsForAccess(access: Access) ![N_MAIN_COLUMNS]M31 {
    try validateAccess(access);
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    if (!access.enabled) return out;
    out[PREVIOUS_CLOCK_OFFSET] =
        M31.fromCanonical(access.previous_clock);
    setBits(
        out[PREVIOUS_VALUE_OFFSET..DIFFERENCE_BITS_OFFSET],
        access.previous_value,
    );
    setBits(
        out[DIFFERENCE_BITS_OFFSET..MASKED_BITS_OFFSET],
        access.clock - access.previous_clock - 1,
    );
    out[MASKED_BITS_OFFSET] = M31.fromCanonical(
        @intFromBool(access.vblank and access.previous_value & 1 != 0),
    );
    out[MASKED_BITS_OFFSET + 1] = M31.fromCanonical(
        @intFromBool(access.stat and access.previous_value & 2 != 0),
    );
    return out;
}

pub fn inactiveColumns() [N_MAIN_COLUMNS]M31 {
    return [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
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
            q(runner.cartridge_memory.INTERRUPT_FLAGS),
            q(access.previous_clock),
            q(access.previous_value),
        ),
        .n2 = QM31.one(),
        .d2 = relation.combine(
            q(runner.cartridge_memory.INTERRUPT_FLAGS),
            q(access.clock),
            q(access.next_value),
        ),
    };
}

pub fn pairForRows(
    ppu: PpuRow(QM31),
    row: Row(QM31),
    relation: memory_lookup.Relation,
) memory_lookup.RowPair {
    const vblank = ppu.semantic.interrupts[0];
    const stat = ppu.semantic.interrupts[1];
    const requested = boolOr(QM31, vblank, stat);
    const previous_value = compose(row.previous_value);
    const next_value = previous_value
        .add(vblank)
        .sub(row.masked_previous[0])
        .add(stat.sub(row.masked_previous[1]).mul(q(2)));
    return .{
        .n1 = requested.neg(),
        .d1 = relation.combine(
            q(runner.cartridge_memory.INTERRUPT_FLAGS),
            row.previous_clock,
            previous_value,
        ),
        .n2 = requested,
        .d2 = relation.combine(
            q(runner.cartridge_memory.INTERRUPT_FLAGS),
            phasedClock(QM31, ppu),
            next_value,
        ),
    };
}

pub const Interaction = struct {
    columns: [N_INTERACTION_COLUMNS][]M31,
    claim: QM31,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Interaction) void {
        for (self.columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    accesses: []const Access,
    log_size: u32,
    relation: memory_lookup.Relation,
) !Interaction {
    const size = try traceSize(log_size);
    if (accesses.len != size) return error.InvalidTraceLength;
    var result = Interaction{
        .columns = undefined,
        .claim = QM31.zero(),
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
    for (accesses, 0..) |access, index| {
        result.claim = try accumulate(
            result.claim,
            try pair(access, relation),
        );
        writeSecure(
            &result.columns,
            try core_air_utils.circleBitReversedIndex(log_size, index),
            result.claim,
        );
    }
    return result;
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
        return error.PpuIfMemoryLookupZeroDenominator));
}

fn validateAccess(access: Access) !void {
    if (!access.enabled) {
        if (access.vblank or access.stat or
            access.previous_clock != 0 or access.previous_value != 0 or
            access.clock != 0 or access.next_value != 0)
            return error.InvalidInactiveAccess;
        return;
    }
    if (!access.vblank and !access.stat)
        return error.InvalidPpuIfRequest;
    if (access.clock >= M31_MODULUS)
        return error.NonCanonicalPpuIfClock;
    if (access.previous_clock >= access.clock)
        return error.InvalidPpuIfPredecessorClock;
    if (access.clock - access.previous_clock - 1 >=
        (@as(u32, 1) << N_DIFF_BITS))
        return error.PpuIfClockDifferenceTooLarge;
    const mask = interruptMask(access.vblank, access.stat);
    if (access.next_value != access.previous_value | mask)
        return error.InvalidPpuIfValueTransition;
}

fn interruptMask(vblank: bool, stat: bool) u8 {
    return (@as(u8, @intFromBool(vblank)) *
        ppu_runner.VBLANK_INTERRUPT) |
        (@as(u8, @intFromBool(stat)) * ppu_runner.STAT_INTERRUPT);
}

fn neutralPair() memory_lookup.RowPair {
    return .{
        .n1 = QM31.zero(),
        .d1 = QM31.one(),
        .n2 = QM31.zero(),
        .d2 = QM31.one(),
    };
}

fn phasedClock(comptime S: type, ppu: PpuRow(S)) S {
    return ppu.mcycle
        .mul(constant(S, memory_lookup.memory_clock.PHASES))
        .add(constant(
        S,
        memory_lookup.memory_clock.PPU_PHASE + 1,
    ));
}

fn boolOr(comptime S: type, a: S, b: S) S {
    return a.add(b).sub(a.mul(b));
}

fn traceSize(log_size: u32) !usize {
    if (log_size < 4 or log_size >= @bitSizeOf(usize))
        return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn setBits(target: []M31, value: anytype) void {
    const unsigned: u64 = @intCast(value);
    for (target, 0..) |*bit_value, index|
        bit_value.* = M31.fromCanonical(
            @intCast((unsigned >> @intCast(index)) & 1),
        );
}

fn compose(bits: anytype) QM31 {
    var result = QM31.zero();
    var power = QM31.one();
    for (bits) |bit_value| {
        result = result.add(power.mul(bit_value));
        power = power.add(power);
    }
    return result;
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
