//! Joypad interrupt-request contribution to authenticated system memory.
//!
//! Each proven joypad edge contributes one ordered mutable-memory transition
//! at FF0F: `(previous_clock, previous_value)` becomes the event's phased
//! M-cycle clock with value `previous_value | 0x10`. The existing memory
//! boundary and CPU-access relations must share this relation and add this
//! claim; this leaf is not independently balanced.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const event_trace = @import("../joypad_trace.zig");
const runner = @import("../runner/mod.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const joypad_air = @import("joypad.zig");
const joypad_binding = @import("joypad_binding.zig");

pub const N_VALUE_BITS: usize = 8;
pub const N_DIFF_BITS: usize = memory_lookup.N_DIFF_BITS;
pub const PREVIOUS_CLOCK_OFFSET: usize = 0;
pub const PREVIOUS_VALUE_OFFSET: usize = PREVIOUS_CLOCK_OFFSET + 1;
pub const DIFFERENCE_BITS_OFFSET: usize =
    PREVIOUS_VALUE_OFFSET + N_VALUE_BITS;
pub const N_MAIN_COLUMNS: usize = DIFFERENCE_BITS_OFFSET + N_DIFF_BITS;
pub const N_CONSTRAINTS: usize = N_VALUE_BITS + N_DIFF_BITS + 3;
pub const N_INTERACTION_COLUMNS: usize = 4;

pub const Predecessor = struct {
    clock: u32 = 0,
    value: u8 = 0,
};

pub const Access = struct {
    enabled: bool = false,
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

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != N_MAIN_COLUMNS)
                return error.InvalidJoypadIfMemoryShape;
            return .{
                .previous_clock = values[PREVIOUS_CLOCK_OFFSET],
                .previous_value = values[PREVIOUS_VALUE_OFFSET..DIFFERENCE_BITS_OFFSET].*,
                .difference_bits = values[DIFFERENCE_BITS_OFFSET..N_MAIN_COLUMNS].*,
            };
        }
    };
}

pub fn JoypadRow(comptime S: type) type {
    return struct {
        active: S,
        semantic: joypad_air.Semantics(S).Row,
        mcycle: S,

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != joypad_binding.N_MAIN_COLUMNS)
                return error.InvalidJoypadBindingShape;
            return .{
                .active = values[0],
                .semantic = try joypad_air.Semantics(S).Row.fromColumns(
                    values[1..][0..joypad_air.N_MAIN_COLUMNS],
                ),
                .mcycle = values[joypad_binding.MCYCLE_OFFSET],
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
    joypad: JoypadRow(S),
    row: Row(S),
) Evaluation(S) {
    const one = S.one();
    const requested = joypad.semantic.interrupt_requested;
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
    out[at] = requested.mul(one.sub(joypad.active));
    at += 1;
    out[at] = requested.mul(
        phasedClock(S, joypad)
            .sub(row.previous_clock)
            .sub(one)
            .sub(difference),
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
    joypad_log_size: u32,
    events: []const event_trace.EventRow,
    predecessors: []const Predecessor,
) !Witness {
    const size = try traceSize(joypad_log_size);
    if (events.len == 0) return error.EmptyJoypadTrace;
    if (events.len > size) return error.TooManyJoypadEvents;
    if (predecessors.len != events.len)
        return error.InvalidPredecessorCount;
    var result = Witness{
        .log_size = joypad_log_size,
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
        event.transition.validate() catch
            return error.InvalidJoypadTransition;
        const access = try accessForEvent(event, predecessor);
        if (access.enabled) {
            if (last_request_clock != null and
                last_request_clock.? >= access.clock)
                return error.JoypadIfClockCollision;
            last_request_clock = access.clock;
        }
        result.accesses[index] = access;
        const values = try columnsForAccess(access);
        const storage = try core_air_utils.circleBitReversedIndex(
            joypad_log_size,
            index,
        );
        for (result.main, values) |column, value|
            column[storage] = value;
    }
    return result;
}

pub fn accessForEvent(
    event: event_trace.EventRow,
    predecessor: Predecessor,
) !Access {
    event.transition.validate() catch
        return error.InvalidJoypadTransition;
    if (!event.transition.interrupt_requested) {
        if (predecessor.clock != 0 or predecessor.value != 0)
            return error.InvalidInactivePredecessor;
        return .{};
    }
    const clock = memory_lookup.memory_clock.phaseClock(
        event.mcycle,
        phaseForEvent(event.transition.event),
    ) catch return error.NonCanonicalJoypadIfClock;
    if (predecessor.clock >= clock)
        return error.InvalidJoypadIfPredecessorClock;
    const difference = clock - predecessor.clock - 1;
    if (difference >= (@as(u32, 1) << N_DIFF_BITS))
        return error.JoypadIfClockDifferenceTooLarge;
    return .{
        .enabled = true,
        .previous_clock = predecessor.clock,
        .previous_value = predecessor.value,
        .clock = clock,
        .next_value = predecessor.value | runner.joypad.JOYPAD_INTERRUPT,
    };
}

pub fn columnsForAccess(
    access: Access,
) ![N_MAIN_COLUMNS]M31 {
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
        out[DIFFERENCE_BITS_OFFSET..N_MAIN_COLUMNS],
        access.clock - access.previous_clock - 1,
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
    if (!access.enabled) return .{
        .n1 = QM31.zero(),
        .d1 = QM31.one(),
        .n2 = QM31.zero(),
        .d2 = QM31.one(),
    };
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
    joypad: JoypadRow(QM31),
    row: Row(QM31),
    relation: memory_lookup.Relation,
) memory_lookup.RowPair {
    const requested = joypad.semantic.interrupt_requested;
    const previous_value = compose(row.previous_value);
    const next_value = previous_value.add(
        requested.mul(
            QM31.fromBase(M31.fromCanonical(
                runner.joypad.JOYPAD_INTERRUPT,
            )),
        ).mul(QM31.one().sub(row.previous_value[4])),
    );
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
            phasedClock(QM31, joypad),
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
        return error.JoypadIfMemoryLookupZeroDenominator));
}

fn validateAccess(access: Access) !void {
    if (!access.enabled) {
        if (access.previous_clock != 0 or access.previous_value != 0 or
            access.clock != 0 or access.next_value != 0)
            return error.InvalidInactiveAccess;
        return;
    }
    if (access.clock >= M31_MODULUS)
        return error.NonCanonicalJoypadIfClock;
    if (access.previous_clock >= access.clock)
        return error.InvalidJoypadIfPredecessorClock;
    if (access.clock - access.previous_clock - 1 >=
        (@as(u32, 1) << N_DIFF_BITS))
        return error.JoypadIfClockDifferenceTooLarge;
    if (access.next_value !=
        access.previous_value | runner.joypad.JOYPAD_INTERRUPT)
        return error.InvalidJoypadIfValueTransition;
}

fn phasedClock(
    comptime S: type,
    joypad: JoypadRow(S),
) S {
    const phase = joypad.semantic.events[1]
        .mul(constant(S, memory_lookup.memory_clock.CPU_PHASE))
        .add(joypad.semantic.events[2].mul(
        constant(S, memory_lookup.memory_clock.JOYPAD_TICK_PHASE),
    ));
    return joypad.mcycle
        .mul(constant(S, memory_lookup.memory_clock.PHASES))
        .add(phase)
        .add(S.one());
}

fn phaseForEvent(event: runner.joypad.Event) u32 {
    return switch (event) {
        .set_pressed => memory_lookup.memory_clock.ACTION_PHASE,
        .write_p1 => memory_lookup.memory_clock.CPU_PHASE,
        .tick_mcycle => memory_lookup.memory_clock.JOYPAD_TICK_PHASE,
    };
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
