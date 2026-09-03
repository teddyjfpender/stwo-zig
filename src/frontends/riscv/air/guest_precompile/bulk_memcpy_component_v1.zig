//! Nonproduction component contract for the bulk-memcpy caller and word AIRs.
//!
//! The two compile-time configurations pin direct-constraint geometry and the
//! exact 29/7 relation-event schedules.  They are intentionally not registered
//! in the VM statement and do not expose a production `Component` vtable yet;
//! that final adapter must consume the boundary-aware evaluator below rather
//! than the finite-slice legacy word evaluator.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const boundary = @import("bulk_memcpy_boundary_candidate_v1.zig");
const caller = @import("bulk_memcpy_caller_candidate_v1.zig");
const relations_mod = @import("bulk_memcpy_relations_v1.zig");
const trace_mod = @import("bulk_memcpy_trace_v1.zig");
const words = @import("bulk_memcpy_word_candidate_v1.zig");
const logup = @import("../logup.zig");

pub const production_active = false;
pub const caller_event_count: usize = 29;
pub const caller_batch_count: usize = 15;
pub const word_event_count: usize = 7;
pub const word_batch_count: usize = 4;

pub const Caller = struct {
    pub const stable_name = "bulk_memcpy_caller_candidate_v1";
    pub const main_column_count = caller.main_column_count;
    pub const direct_constraint_count = boundary.caller_constraint_count;
    pub const event_count = caller_event_count;
    pub const batch_count = caller_batch_count;
    pub const interaction_column_count = 4 * batch_count;
    pub const maximum_constraint_degree = boundary.caller_maximum_constraint_degree;

    pub fn evaluate(
        comptime S: type,
        main: *const [main_column_count]S,
        previous: *const [main_column_count]S,
        next: *const [main_column_count]S,
        domain_first: S,
        domain_last: S,
        active_prefix: S,
        relations: anytype,
        sink: anytype,
    ) !void {
        _ = previous;
        _ = next;
        _ = domain_first;
        _ = domain_last;
        _ = relations;
        try boundary.evaluateCaller(S, main, active_prefix, sink);
    }

    pub fn rowPairs(
        comptime S: type,
        main: *const [main_column_count]S,
        relations: anytype,
    ) [batch_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) {
        return callerRowPairs(S, main, relations);
    }
};

pub const Word = struct {
    pub const stable_name = "bulk_memcpy_word_candidate_v1";
    pub const main_column_count = words.main_column_count;
    pub const direct_constraint_count = boundary.word_constraint_count;
    pub const event_count = word_event_count;
    pub const batch_count = word_batch_count;
    pub const interaction_column_count = 4 * batch_count;
    pub const maximum_constraint_degree = boundary.word_maximum_constraint_degree;

    pub fn evaluate(
        comptime S: type,
        main: *const [main_column_count]S,
        previous: *const [main_column_count]S,
        next: *const [main_column_count]S,
        domain_first: S,
        domain_last: S,
        active_prefix: S,
        relations: anytype,
        sink: anytype,
    ) !void {
        _ = previous;
        _ = domain_first;
        _ = relations;
        try boundary.evaluateWord(
            S,
            main,
            next,
            domain_last,
            active_prefix,
            sink,
        );
    }

    pub fn rowPairs(
        comptime S: type,
        main: *const [main_column_count]S,
        relations: anytype,
    ) [batch_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) {
        return wordRowPairs(S, main, relations);
    }
};

pub fn Claim(comptime Config: type) type {
    return struct {
        log_size: u32,
        n_rows: u32,
        batch_sums: [Config.batch_count]QM31,
        component_sum: QM31,

        pub fn canonical(
            log_size: u32,
            n_rows: u32,
            batch_sums: [Config.batch_count]QM31,
        ) !@This() {
            const result = @This(){
                .log_size = log_size,
                .n_rows = n_rows,
                .batch_sums = batch_sums,
                .component_sum = sumClaims(Config, batch_sums),
            };
            try result.validate();
            return result;
        }

        pub fn validate(self: @This()) !void {
            const expected_log: u32 = @max(
                trace_mod.minimum_log_size,
                std.math.log2_int_ceil(u32, @max(@as(u32, 1), self.n_rows)),
            );
            if (self.log_size != expected_log or
                self.log_size > trace_mod.maximum_log_size or
                self.n_rows > @as(u64, 1) << @intCast(self.log_size) or
                !sumClaims(Config, self.batch_sums).eql(self.component_sum))
            {
                return error.InvalidClaim;
            }
            if (self.n_rows == 0) {
                for (self.batch_sums) |sum| if (!sum.isZero())
                    return error.InvalidClaim;
            }
        }
    };
}

pub const CallerClaim = Claim(Caller);
pub const WordClaim = Claim(Word);

pub fn callerRowPairs(
    comptime S: type,
    main: *const [caller.main_column_count]S,
    relations: anytype,
) [caller_batch_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    return pairEvents(
        relations_mod.InteractionScalar(S),
        caller_event_count,
        caller_batch_count,
        callerEvents(S, main, relations),
    );
}

pub fn callerEvents(
    comptime S: type,
    main: *const [caller.main_column_count]S,
    relations: anytype,
) [caller_event_count]EventFor(relations_mod.InteractionScalar(S)) {
    const I = relations_mod.InteractionScalar(S);
    const active = main[caller.Layout.active];
    const negative = active.neg();
    var events: [caller_event_count]EventFor(I) = undefined;
    var event: usize = 0;

    appendEvent(I, &events, &event, S, negative, relations_mod.combine(
        S,
        relations.base.program_access,
        [5]S{
            main[caller.Layout.pc],
            relations_mod.scalar(S, 48),
            relations_mod.scalar(S, 10),
            relations_mod.scalar(S, 11),
            relations_mod.scalar(S, 12),
        },
    ));
    appendEvent(I, &events, &event, S, negative, relations_mod.combine(
        S,
        relations.base.registers_state,
        [2]S{ main[caller.Layout.pc], main[caller.Layout.execution_clock] },
    ));
    appendEvent(I, &events, &event, S, active, relations_mod.combine(
        S,
        relations.base.registers_state,
        [2]S{
            main[caller.Layout.pc].add(relations_mod.scalar(S, 4)),
            main[caller.Layout.execution_clock].add(S.one()),
        },
    ));

    const register_clock = accessClock(S, main[caller.Layout.execution_clock], 1);
    inline for (0..3) |register_index| {
        const value_group = register_index;
        const register_number: u32 = 10 + register_index;
        const previous_clock = main[caller.Layout.previousClock(register_index)];
        const value = callerValueBytes(S, main, value_group);
        appendEvent(I, &events, &event, S, negative, relations_mod.combine(
            S,
            relations.base.memory_access,
            memoryTuple(
                S,
                relations_mod.scalar(S, 0),
                relations_mod.scalar(S, register_number),
                previous_clock,
                value,
            ),
        ));
        appendEvent(I, &events, &event, S, active, relations_mod.combine(
            S,
            relations.base.memory_access,
            memoryTuple(
                S,
                relations_mod.scalar(S, 0),
                relations_mod.scalar(S, register_number),
                register_clock,
                value,
            ),
        ));
        appendEvent(I, &events, &event, S, negative, relations_mod.combine(
            S,
            relations.base.range_check_20,
            [1]S{register_clock.sub(previous_clock).sub(S.one())},
        ));
    }

    inline for (0..8) |group| inline for (0..2) |pair| {
        appendEvent(I, &events, &event, S, negative, relations_mod.combine(
            S,
            relations.base.range_check_8_8,
            [2]S{
                main[caller.Layout.valueByte(group, 2 * pair)],
                main[caller.Layout.valueByte(group, 2 * pair + 1)],
            },
        ));
    };
    appendEvent(I, &events, &event, S, active, relations_mod.combine(
        S,
        relations.call,
        relations_mod.callerCallTuple(S, main),
    ));
    std.debug.assert(event == caller_event_count);
    return events;
}

pub fn wordRowPairs(
    comptime S: type,
    main: *const [words.main_column_count]S,
    relations: anytype,
) [word_batch_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    return pairEvents(
        relations_mod.InteractionScalar(S),
        word_event_count,
        word_batch_count,
        wordEvents(S, main, relations),
    );
}

pub fn wordEvents(
    comptime S: type,
    main: *const [words.main_column_count]S,
    relations: anytype,
) [word_event_count]EventFor(relations_mod.InteractionScalar(S)) {
    const I = relations_mod.InteractionScalar(S);
    const active = main[words.Layout.active];
    const negative = active.neg();
    const first_negative = main[words.Layout.is_first].neg();
    const memory_clock = accessClock(S, main[words.Layout.execution_clock], 2);
    const source_bytes = wordBytes(S, main, words.Layout.source_bytes);
    const destination_before = wordBytes(S, main, words.Layout.destination_before);
    const destination_after = wordBytes(S, main, words.Layout.destination_after);
    const source_previous = main[words.Layout.source_previous_clock];
    const destination_previous = main[words.Layout.destination_previous_clock];
    const source_byte_address = main[words.Layout.source_word_index].mul(
        relations_mod.scalar(S, 4),
    );
    const destination_byte_address = main[words.Layout.destination_word_index].mul(
        relations_mod.scalar(S, 4),
    );
    var events: [word_event_count]EventFor(I) = undefined;
    var event: usize = 0;

    appendEvent(I, &events, &event, S, negative, relations_mod.combine(
        S,
        relations.base.memory_access,
        memoryTuple(
            S,
            relations_mod.scalar(S, 1),
            source_byte_address,
            source_previous,
            source_bytes,
        ),
    ));
    appendEvent(I, &events, &event, S, active, relations_mod.combine(
        S,
        relations.base.memory_access,
        memoryTuple(
            S,
            relations_mod.scalar(S, 1),
            source_byte_address,
            memory_clock,
            source_bytes,
        ),
    ));
    appendEvent(I, &events, &event, S, negative, relations_mod.combine(
        S,
        relations.base.memory_access,
        memoryTuple(
            S,
            relations_mod.scalar(S, 1),
            destination_byte_address,
            destination_previous,
            destination_before,
        ),
    ));
    appendEvent(I, &events, &event, S, active, relations_mod.combine(
        S,
        relations.base.memory_access,
        memoryTuple(
            S,
            relations_mod.scalar(S, 1),
            destination_byte_address,
            memory_clock,
            destination_after,
        ),
    ));
    appendEvent(I, &events, &event, S, negative, relations_mod.combine(
        S,
        relations.base.range_check_20,
        [1]S{memory_clock.sub(source_previous).sub(S.one())},
    ));
    appendEvent(I, &events, &event, S, negative, relations_mod.combine(
        S,
        relations.base.range_check_20,
        [1]S{memory_clock.sub(destination_previous).sub(S.one())},
    ));
    appendEvent(I, &events, &event, S, first_negative, relations_mod.combine(
        S,
        relations.call,
        relations_mod.wordCallTuple(S, main),
    ));
    std.debug.assert(event == word_event_count);
    return events;
}

pub fn EventFor(comptime I: type) type {
    return struct { numerator: I, denominator: I };
}

fn appendEvent(
    comptime I: type,
    events: anytype,
    index: *usize,
    comptime S: type,
    numerator: S,
    denominator: I,
) void {
    events[index.*] = .{
        .numerator = relations_mod.liftInteraction(S, numerator),
        .denominator = denominator,
    };
    index.* += 1;
}

fn pairEvents(
    comptime I: type,
    comptime event_count: usize,
    comptime batch_count: usize,
    events: [event_count]EventFor(I),
) [batch_count]logup.RowPairFor(I) {
    var result: [batch_count]logup.RowPairFor(I) = undefined;
    inline for (0..batch_count) |batch| {
        const first = events[2 * batch];
        if (comptime 2 * batch + 1 < event_count) {
            const second = events[2 * batch + 1];
            result[batch] = .{
                .n1 = first.numerator,
                .d1 = first.denominator,
                .n2 = second.numerator,
                .d2 = second.denominator,
            };
        } else {
            result[batch] = logup.RowPairFor(I).single(
                first.numerator,
                first.denominator,
            );
        }
    }
    return result;
}

fn memoryTuple(
    comptime S: type,
    address_space: S,
    address: S,
    clock: S,
    bytes: [4]S,
) [7]S {
    return .{
        address_space,
        address,
        clock,
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
    };
}

fn callerValueBytes(
    comptime S: type,
    main: *const [caller.main_column_count]S,
    group: usize,
) [4]S {
    var result: [4]S = undefined;
    for (&result, 0..) |*value, byte| value.* =
        main[caller.Layout.valueByte(group, byte)];
    return result;
}

fn wordBytes(
    comptime S: type,
    main: *const [words.main_column_count]S,
    start: usize,
) [4]S {
    return main[start..][0..4].*;
}

fn accessClock(comptime S: type, execution_clock: S, ordinal: u32) S {
    return execution_clock.sub(S.one())
        .mul(relations_mod.scalar(S, 4))
        .add(relations_mod.scalar(S, ordinal));
}

fn sumClaims(comptime Config: type, values: [Config.batch_count]QM31) QM31 {
    var result = QM31.zero();
    for (values) |value| result = result.add(value);
    return result;
}

comptime {
    if (production_active or boundary.production_active or
        relations_mod.production_active or
        caller_event_count != 29 or caller_batch_count != 15 or
        word_event_count != 7 or word_batch_count != 4 or
        Caller.interaction_column_count != 60 or
        Word.interaction_column_count != 16)
    {
        @compileError("bulk memcpy component contract drifted");
    }
}
