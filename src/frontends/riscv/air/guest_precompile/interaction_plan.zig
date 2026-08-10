//! Authenticated event projection and batch placement for guest interactions.
//!
//! Public evaluator entries are secure-field valued. Prover generation uses
//! the same compile-time-specialized projection over M31 and `combineBase`.
//! This module owns no allocation and performs no row scan.

const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const base_relation = @import("../lang/relation.zig");
const types = @import("../lang/types.zig");
const logup = @import("../logup.zig");
const poseidon2_air = @import("../memory_commitment/poseidon2_air.zig");
const components = @import("component_registry.zig");
const main_trace = @import("main_trace.zig");
const challenges = @import("relation_challenges.zig");
const registry = @import("relation_registry.zig");

const Relations = challenges.Poseidon2V1Relations;

pub const caller_event_count: usize = components.caller_event_count;
pub const caller_batch_count: usize = components.caller_batch_count;
pub const provider_event_count: usize = components.provider_event_count;
pub const provider_batch_count: usize = components.provider_batch_count;
pub const caller_column_count: usize = components.caller_interaction_columns;
pub const provider_column_count: usize = components.provider_interaction_columns;
pub const total_batch_count: usize = caller_batch_count + provider_batch_count;
pub const total_column_count: usize = caller_column_count + provider_column_count;
pub const caller_relation_source_columns: usize =
    components.caller_layout.canonical_materializations;

const provider_column_start: usize = caller_column_count;
const provider_input_start: usize = 1;
const provider_output_start: usize = 1 + poseidon2_air.N_TEMPORARIES;

pub const output_column_starts = buildOutputColumnStarts();

pub const Error = error{
    InvalidEventIndex,
    InvalidEntryArity,
    InvalidMainTraceShape,
    UnknownRelationSchema,
    ZeroDenominator,
};

fn ProjectedEntry(comptime S: type) type {
    return struct {
        schema: types.RelationSchemaId,
        role: base_relation.Role,
        access_ordinal: ?u8,
        numerator: S,
        values: [registry.guest_relation_arity]S,
        arity: u8,

        const Self = @This();

        pub fn validate(self: *const Self) Error!void {
            const arity = expectedArity(types.idIndex(self.schema)) orelse
                return error.UnknownRelationSchema;
            if (self.arity != arity) return error.InvalidEntryArity;
        }

        pub fn denominator(self: *const Self, relations: *const Relations) Error!QM31 {
            const schema = types.idIndex(self.schema);
            try self.validate();
            return switch (schema) {
                0 => combine(relations.base.registers_state, self.values[0..2].*),
                1 => combine(relations.base.memory_access, self.values[0..7].*),
                2 => combine(relations.base.program_access, self.values[0..5].*),
                3 => combine(relations.base.merkle, self.values[0..4].*),
                4 => combine(relations.base.poseidon2, self.values[0..16].*),
                5 => combine(relations.base.poseidon2_io, self.values[0..32].*),
                6 => combine(relations.base.bitwise, self.values[0..4].*),
                7 => combine(relations.base.range_check_20, self.values[0..1].*),
                8 => combine(relations.base.range_check_8_11, self.values[0..2].*),
                9 => combine(relations.base.range_check_8_8_4, self.values[0..3].*),
                10 => combine(relations.base.range_check_8_8, self.values[0..2].*),
                11 => combine(relations.base.range_check_m31, self.values[0..2].*),
                registry.guest_schema_numeric_id => combine(
                    relations.guest_poseidon2_io,
                    self.values,
                ),
                else => error.UnknownRelationSchema,
            };
        }

        fn denominatorForPlan(
            self: *const Self,
            comptime event: components.EventPlan,
            relations: *const Relations,
        ) QM31 {
            comptime validateStaticPlan(event);
            return switch (comptime types.idIndex(event.schema)) {
                0 => combine(relations.base.registers_state, self.values[0..2].*),
                1 => combine(relations.base.memory_access, self.values[0..7].*),
                2 => combine(relations.base.program_access, self.values[0..5].*),
                3 => combine(relations.base.merkle, self.values[0..4].*),
                4 => combine(relations.base.poseidon2, self.values[0..16].*),
                5 => combine(relations.base.poseidon2_io, self.values[0..32].*),
                6 => combine(relations.base.bitwise, self.values[0..4].*),
                7 => combine(relations.base.range_check_20, self.values[0..1].*),
                8 => combine(relations.base.range_check_8_11, self.values[0..2].*),
                9 => combine(relations.base.range_check_8_8_4, self.values[0..3].*),
                10 => combine(relations.base.range_check_8_8, self.values[0..2].*),
                11 => combine(relations.base.range_check_m31, self.values[0..2].*),
                registry.guest_schema_numeric_id => combine(
                    relations.guest_poseidon2_io,
                    self.values,
                ),
                else => unreachable,
            };
        }

        pub fn term(self: *const Self, relations: *const Relations) Error!QM31 {
            try self.validate();
            const numerator = lift(self.numerator);
            if (numerator.isZero()) return QM31.zero();
            const inverse = (try self.denominator(relations)).inv() catch
                return error.ZeroDenominator;
            return numerator.mul(inverse);
        }

        fn combine(relation: anytype, values: anytype) QM31 {
            if (comptime S == M31) return relation.combineBase(values);
            if (comptime S == QM31) return relation.combineSecure(values);
            @compileError("guest projection supports only M31 and QM31");
        }
    };
}

pub const Entry = ProjectedEntry(QM31);

pub fn callerEntry(main: []const QM31, event_index: usize) Error!Entry {
    if (main.len != main_trace.caller_main_column_count)
        return error.InvalidMainTraceShape;
    return callerEntryDynamic(
        QM31,
        main[0..caller_relation_source_columns],
        event_index,
    );
}

pub fn providerEntry(main: []const QM31, event_index: usize) Error!Entry {
    if (main.len != main_trace.provider_main_column_count)
        return error.InvalidMainTraceShape;
    return providerEntryDynamic(QM31, providerView(QM31, main), event_index);
}

pub fn callerRowPairs(
    main: []const QM31,
    relations: *const Relations,
) Error![caller_batch_count]logup.RowPair {
    if (main.len != main_trace.caller_main_column_count)
        return error.InvalidMainTraceShape;
    return callerPairsFromSource(
        QM31,
        main[0..caller_relation_source_columns],
        relations,
    );
}

pub fn providerRowPairs(
    main: []const QM31,
    relations: *const Relations,
) Error![provider_batch_count]logup.RowPair {
    if (main.len != main_trace.provider_main_column_count)
        return error.InvalidMainTraceShape;
    return providerPairsFromView(QM31, providerView(QM31, main), relations);
}

pub fn writeCallerGenerationTerms(
    main: *const [caller_relation_source_columns]M31,
    relations: *const Relations,
    numerators: []QM31,
    denominators: []QM31,
    stride: usize,
    row: usize,
) void {
    inline for (components.caller_batches) |batch| {
        const first_event = components.caller_events[batch.first_event];
        const first = callerEntryStatic(M31, main, first_event);
        const d1 = first.denominatorForPlan(first_event, relations);
        const pair = if (comptime batch.second_event) |second_index| blk: {
            const second_event = components.caller_events[second_index];
            const second = callerEntryStatic(M31, main, second_event);
            break :blk logup.RowPair{
                .n1 = lift(first.numerator),
                .d1 = d1,
                .n2 = lift(second.numerator),
                .d2 = second.denominatorForPlan(second_event, relations),
            };
        } else logup.RowPair.single(lift(first.numerator), d1);
        writeNormalizedTerm(
            pair,
            &numerators[batch.ordinal * stride + row],
            &denominators[batch.ordinal * stride + row],
        );
    }
}

pub const ProviderGuestTerm = struct { numerator: QM31, denominator: QM31 };

pub fn providerGuestGenerationTerm(
    active: M31,
    input: [16]M31,
    output: [16]M31,
    relations: *const Relations,
) ProviderGuestTerm {
    comptime validateFixedZeroProviderPlans();
    const event = components.provider_events[3];
    const entry = providerEntryStatic(M31, .{
        .active = active,
        .input = input,
        .output = output,
    }, event);
    return .{
        .numerator = lift(entry.numerator),
        .denominator = entry.denominatorForPlan(event, relations),
    };
}

pub fn writeNormalizedTerm(
    pair: logup.RowPair,
    numerator: *QM31,
    denominator: *QM31,
) void {
    if (pair.n1.isZero()) {
        if (pair.n2.isZero()) {
            numerator.* = QM31.zero();
            denominator.* = QM31.one();
        } else {
            numerator.* = pair.n2;
            denominator.* = pair.d2;
        }
    } else if (pair.n2.isZero()) {
        numerator.* = pair.n1;
        denominator.* = pair.d1;
    } else {
        numerator.* = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
        denominator.* = pair.d1.mul(pair.d2);
    }
}

fn callerPairsFromSource(
    comptime S: type,
    main: []const S,
    relations: *const Relations,
) [caller_batch_count]logup.RowPair {
    var result: [caller_batch_count]logup.RowPair = undefined;
    inline for (components.caller_batches) |batch| {
        const first_event = components.caller_events[batch.first_event];
        const first = callerEntryStatic(S, main, first_event);
        const d1 = first.denominatorForPlan(first_event, relations);
        if (comptime batch.second_event) |second_index| {
            const second_event = components.caller_events[second_index];
            const second = callerEntryStatic(S, main, second_event);
            result[batch.ordinal] = .{
                .n1 = lift(first.numerator),
                .d1 = d1,
                .n2 = lift(second.numerator),
                .d2 = second.denominatorForPlan(second_event, relations),
            };
        } else {
            result[batch.ordinal] = logup.RowPair.single(lift(first.numerator), d1);
        }
    }
    return result;
}

fn providerPairsFromView(
    comptime S: type,
    main: ProviderView(S),
    relations: *const Relations,
) [provider_batch_count]logup.RowPair {
    var result: [provider_batch_count]logup.RowPair = undefined;
    inline for (components.provider_batches) |batch| {
        const first_event = components.provider_events[batch.first_event];
        const second_index = comptime batch.second_event orelse
            @compileError("provider batches must remain paired");
        const second_event = components.provider_events[second_index];
        const first = providerEntryStatic(S, main, first_event);
        const second = providerEntryStatic(S, main, second_event);
        result[batch.ordinal] = .{
            .n1 = lift(first.numerator),
            .d1 = first.denominatorForPlan(first_event, relations),
            .n2 = lift(second.numerator),
            .d2 = second.denominatorForPlan(second_event, relations),
        };
    }
    return result;
}

fn callerEntryDynamic(
    comptime S: type,
    main: []const S,
    event_index: usize,
) Error!ProjectedEntry(S) {
    inline for (components.caller_events, 0..) |event, index| {
        if (event_index == index) return callerEntryStatic(S, main, event);
    }
    return error.InvalidEventIndex;
}

fn providerEntryDynamic(
    comptime S: type,
    main: ProviderView(S),
    event_index: usize,
) Error!ProjectedEntry(S) {
    inline for (components.provider_events, 0..) |event, index| {
        if (event_index == index) return providerEntryStatic(S, main, event);
    }
    return error.InvalidEventIndex;
}

fn callerEntryStatic(
    comptime S: type,
    main: []const S,
    comptime event: components.EventPlan,
) ProjectedEntry(S) {
    comptime validateStaticPlan(event);
    const layout = components.caller_layout;
    const active = main[layout.enabler];
    const clock = main[layout.execution_clock];
    const pointer_bytes = main[layout.pointer_bytes..][0..4].*;
    var entry = entryForPlan(S, event, active);
    switch (event.projection) {
        .program => assign(&entry, .{
            main[layout.pc],
            scalar(S, components.guest_opcode_id),
            scalar(S, 0),
            main[layout.pointer_register],
            scalar(S, 0),
        }),
        .state_before => assign(&entry, .{ main[layout.pc], clock }),
        .state_after => assign(&entry, .{
            main[layout.pc].add(scalar(S, 4)), clock.add(scalar(S, 1)),
        }),
        .pointer_consume => assignMemory(S, &entry, scalar(S, 0), main[layout.pointer_register], main[layout.pointer_previous_clock], pointer_bytes),
        .pointer_emit => assignMemory(S, &entry, scalar(S, 0), main[layout.pointer_register], accessClock(S, clock, 1), pointer_bytes),
        .pointer_clock_gap => assign(&entry, .{
            accessClock(S, clock, 1)
                .sub(main[layout.pointer_previous_clock]).sub(scalar(S, 1)),
        }),
        .lane_consume => {
            const lane = event.index;
            assignMemory(S, &entry, scalar(S, 1), laneAddress(S, main[layout.pointer_word_index], lane), main[layout.previousClock(lane)], wordBytes(S, main, layout.inputByte(lane, 0)));
        },
        .lane_emit => {
            const lane = event.index;
            assignMemory(S, &entry, scalar(S, 1), laneAddress(S, main[layout.pointer_word_index], lane), accessClock(S, clock, 2), wordBytes(S, main, layout.outputByte(lane, 0)));
        },
        .lane_clock_gap => assign(&entry, .{
            accessClock(S, clock, 2)
                .sub(main[layout.previousClock(event.index)]).sub(scalar(S, 1)),
        }),
        .input_byte_pair => {
            const start = layout.inputByte(event.index, 2 * event.part);
            assign(&entry, .{ main[start], main[start + 1] });
        },
        .input_high_limb => assign(&entry, .{
            scalar(S, 0), main[layout.inputByte(event.index, 3)],
        }),
        .output_byte_pair => {
            const start = layout.outputByte(event.index, 2 * event.part);
            assign(&entry, .{ main[start], main[start + 1] });
        },
        .output_high_limb => assign(&entry, .{
            scalar(S, 0), main[layout.outputByte(event.index, 3)],
        }),
        .pointer_span_low => assign(&entry, .{
            main[layout.span_end_limbs], main[layout.span_end_limbs + 1],
        }),
        .pointer_span_high => assign(&entry, .{
            main[layout.span_end_limbs + 2],
            mulConstant(S, main[layout.pointer_bytes + 3], 4),
            main[layout.span_end_limbs + 3],
        }),
        .guest_input_output => for (0..16) |lane| {
            entry.values[lane] = composeWord(
                S,
                wordBytes(S, main, layout.inputByte(@intCast(lane), 0)),
            );
            entry.values[16 + lane] = composeWord(
                S,
                wordBytes(S, main, layout.outputByte(@intCast(lane), 0)),
            );
        },
        else => unreachable,
    }
    return entry;
}

fn ProviderView(comptime S: type) type {
    return struct { active: S, input: [16]S, output: [16]S };
}

fn providerView(comptime S: type, main: []const S) ProviderView(S) {
    return .{
        .active = main[0],
        .input = main[provider_input_start..][0..16].*,
        .output = main[provider_output_start..][0..16].*,
    };
}

fn providerEntryStatic(
    comptime S: type,
    main: ProviderView(S),
    comptime event: components.EventPlan,
) ProjectedEntry(S) {
    comptime validateStaticPlan(event);
    var entry = entryForPlan(S, event, main.active);
    switch (event.projection) {
        .provider_input => assign(&entry, main.input),
        .provider_narrow_output => {
            @memset(entry.values[0..16], scalar(S, 0));
            entry.values[0] = main.output[0];
        },
        .provider_wide_output => {
            @memset(entry.values[0..16], scalar(S, 0));
            for (0..8) |lane| entry.values[lane] = main.output[lane];
        },
        .provider_input_output => for (main.input, main.output, 0..) |input, output, lane| {
            entry.values[lane] = input;
            entry.values[16 + lane] = output;
        },
        else => unreachable,
    }
    return entry;
}

fn entryForPlan(
    comptime S: type,
    comptime event: components.EventPlan,
    active: S,
) ProjectedEntry(S) {
    return .{
        .schema = event.schema,
        .role = event.role,
        .access_ordinal = event.access_ordinal,
        .numerator = switch (event.numerator) {
            .negative_active => active.neg(),
            .positive_active => active,
            .zero_in_guest_mode => scalar(S, 0),
        },
        .values = undefined,
        .arity = event.arity,
    };
}

fn assign(entry: anytype, values: anytype) void {
    inline for (values, 0..) |value, index| entry.values[index] = value;
}

fn assignMemory(
    comptime S: type,
    entry: *ProjectedEntry(S),
    address_space: S,
    address: S,
    clock: S,
    limbs: [4]S,
) void {
    assign(entry, .{
        address_space, address,  clock,
        limbs[0],      limbs[1], limbs[2],
        limbs[3],
    });
}

fn wordBytes(comptime S: type, main: []const S, start: usize) [4]S {
    return main[start..][0..4].*;
}

fn composeWord(comptime S: type, bytes: [4]S) S {
    return bytes[0]
        .add(mulConstant(S, bytes[1], 1 << 8))
        .add(mulConstant(S, bytes[2], 1 << 16))
        .add(mulConstant(S, bytes[3], 1 << 24));
}

fn accessClock(comptime S: type, clock: S, ordinal: u8) S {
    return mulConstant(S, clock.sub(scalar(S, 1)), 4)
        .add(scalar(S, ordinal));
}

fn laneAddress(comptime S: type, word_index: S, lane: u8) S {
    return mulConstant(S, word_index, 4)
        .add(scalar(S, @as(u32, lane) * 4));
}

fn validateStaticPlan(comptime event: components.EventPlan) void {
    const arity = expectedArity(types.idIndex(event.schema)) orelse
        @compileError("interaction plan references an unknown relation schema");
    if (event.arity != arity)
        @compileError("interaction plan relation arity drifted");
}

fn validateFixedZeroProviderPlans() void {
    inline for (components.provider_events[0..3]) |event| {
        validateStaticPlan(event);
        if (event.numerator != .zero_in_guest_mode)
            @compileError("legacy provider interaction must remain coefficient-zero");
    }
}

fn buildOutputColumnStarts() [total_batch_count]usize {
    var result: [total_batch_count]usize = undefined;
    var occupied = [_]bool{false} ** total_column_count;
    for (components.caller_batches, 0..) |batch, index| {
        if (batch.ordinal != index)
            @compileError("caller batch ordinal drifted from authenticated order");
        const start: usize = batch.interaction_column_start;
        if (start + 4 > caller_column_count)
            @compileError("caller interaction column offset is out of bounds");
        result[batch.ordinal] = start;
        for (start..start + 4) |column| {
            if (occupied[column])
                @compileError("caller interaction column offsets overlap");
            occupied[column] = true;
        }
    }
    for (components.provider_batches, 0..) |batch, index| {
        if (batch.ordinal != index)
            @compileError("provider batch ordinal drifted from authenticated order");
        const relative: usize = batch.interaction_column_start;
        if (relative + 4 > provider_column_count)
            @compileError("provider interaction column offset is out of bounds");
        const start = provider_column_start + relative;
        result[caller_batch_count + batch.ordinal] = start;
        for (start..start + 4) |column| {
            if (occupied[column])
                @compileError("provider interaction column offsets overlap");
            occupied[column] = true;
        }
    }
    for (occupied) |is_owned| if (!is_owned)
        @compileError("authenticated interaction offsets leave a column unowned");
    return result;
}

fn expectedArity(schema: usize) ?u8 {
    return switch (schema) {
        0, 8, 10, 11 => 2,
        1 => 7,
        2 => 5,
        3, 6 => 4,
        4 => 16,
        5, registry.guest_schema_numeric_id => 32,
        7 => 1,
        9 => 3,
        else => null,
    };
}

fn scalar(comptime S: type, value: anytype) S {
    if (comptime S == M31) return M31.fromU64(@as(u64, value));
    if (comptime S == QM31) return QM31.fromBase(M31.fromU64(@as(u64, value)));
    @compileError("guest projection supports only M31 and QM31");
}

fn lift(value: anytype) QM31 {
    const S = @TypeOf(value);
    if (comptime S == M31) return QM31.fromBase(value);
    if (comptime S == QM31) return value;
    @compileError("guest projection supports only M31 and QM31");
}

fn mulConstant(comptime S: type, value: S, coefficient: u32) S {
    const base = M31.fromCanonical(coefficient);
    if (comptime S == M31) return value.mul(base);
    if (comptime S == QM31) return value.mulM31(base);
    @compileError("guest projection supports only M31 and QM31");
}

comptime {
    if (caller_relation_source_columns != 158 or provider_input_start != 1 or
        provider_output_start != 427)
    {
        @compileError("guest interaction projection placement drifted");
    }
}
