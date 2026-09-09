//! Genuine proof contract for the nonproduction atomic-U256-swap AIR.
//!
//! The semantic projection originally budgeted eight caller LogUp batches.
//! A proof needs nine: fifteen base-bus events plus the call event cannot leave
//! the call contribution independently auditable in eight pairs.  This module
//! adds one zero-numerator slot and dedicates the ninth batch to the call bus.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const access_clock = @import("../../access_clock.zig");
const abi = @import("../../isa/stack_swap_candidate_v1.zig");
const caller = @import("stack_swap_caller_candidate_v1.zig");
const relations_mod = @import("stack_swap_relations_v1.zig");
const trace_mod = @import("stack_swap_trace_v1.zig");
const words = @import("stack_swap_word_candidate_v1.zig");
const logup = @import("../logup.zig");

pub const production_active = false;
pub const caller_direct_constraint_count: usize = 62;
pub const word_direct_constraint_count: usize = 24;
pub const caller_base_event_count: usize = 15;
pub const caller_event_count: usize = 17;
pub const caller_batch_count: usize = 9;
pub const word_event_count: usize = 7;
pub const word_batch_count: usize = 4;

pub const Inputs = struct {
    relations: *const relations_mod.Relations,
    authority: *const abi.Authority,
};

pub const Caller = struct {
    pub const stable_name = "stack_swap_caller_proof_v1";
    pub const main_column_count = caller.main_column_count;
    pub const direct_constraint_count = caller_direct_constraint_count;
    pub const batch_count = caller_batch_count;
    pub const interaction_column_count = 4 * batch_count;
    pub const maximum_constraint_degree: u8 = 3;
    pub const minimum_log_size = trace_mod.minimum_caller_log_size;

    pub fn validateRows(_: u32) !void {}

    pub fn logSizeForRows(n_rows: u32) !u32 {
        return ordinaryLogSize(n_rows, minimum_log_size);
    }

    pub fn evaluate(
        comptime S: type,
        main: *const [main_column_count]S,
        next: *const [main_column_count]S,
        domain_first: S,
        active_prefix: S,
        lane_last: S,
        inputs: Inputs,
        sink: anytype,
    ) !void {
        _ = next;
        _ = domain_first;
        _ = lane_last;
        _ = inputs;
        try caller.evaluateDirect(S, main, sink);
        sink.add(main[caller.Layout.active].sub(active_prefix), 1);
    }

    pub fn rowPairs(
        comptime S: type,
        main: *const [main_column_count]S,
        lane_last: S,
        inputs: Inputs,
    ) [batch_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) {
        _ = lane_last;
        return callerRowPairs(S, main, inputs);
    }
};

pub const Word = struct {
    pub const stable_name = "stack_swap_word_proof_v1";
    pub const main_column_count = words.main_column_count;
    pub const direct_constraint_count = word_direct_constraint_count;
    pub const batch_count = word_batch_count;
    pub const interaction_column_count = 4 * batch_count;
    pub const maximum_constraint_degree: u8 = 3;
    pub const minimum_log_size = trace_mod.minimum_word_log_size;

    pub fn validateRows(n_rows: u32) !void {
        if (n_rows % words.lane_count != 0)
            return error.InvalidStackSwapWordRowCount;
    }

    pub fn logSizeForRows(n_rows: u32) !u32 {
        var log_size = try ordinaryLogSize(n_rows, minimum_log_size);
        if (n_rows != 0 and n_rows == @as(u64, 1) << @intCast(log_size))
            log_size = std.math.add(u32, log_size, 1) catch
                return error.InvalidStackSwapClaim;
        if (log_size > trace_mod.maximum_log_size)
            return error.InvalidStackSwapClaim;
        return log_size;
    }

    pub fn evaluate(
        comptime S: type,
        main: *const [main_column_count]S,
        next: *const [main_column_count]S,
        domain_first: S,
        active_prefix: S,
        lane_last: S,
        inputs: Inputs,
        sink: anytype,
    ) !void {
        _ = inputs;
        _ = domain_first;
        const one = S.one();
        const active = main[words.Layout.active];
        const next_active = next[words.Layout.active];
        boolean(sink, active);
        boolean(sink, next_active);
        const padding = one.sub(active);
        for (main[1..]) |value| sink.add(padding.mul(value), 2);
        sink.add(active.sub(active_prefix), 1);

        const non_last_active = active.mul(one.sub(lane_last));
        sink.add(non_last_active.mul(next_active.sub(one)), 3);
        inline for (.{ words.Layout.execution_clock, words.Layout.pc }) |column|
            sink.add(non_last_active.mul(next[column].sub(main[column])), 3);
        inline for (.{
            words.Layout.lhs_word_address,
            words.Layout.rhs_word_address,
        }) |column| sink.add(non_last_active.mul(
            next[column].sub(main[column]).sub(one),
        ), 3);
        // On every live noncyclic edge the call index advances exactly on a
        // lane-seven boundary.  This single degree-three identity also handles
        // a full eight-row domain without trusting a host lane branch.
        sink.add(active.mul(next_active).mul(
            next[words.Layout.call_index]
                .sub(main[words.Layout.call_index])
                .sub(lane_last),
        ), 3);
    }

    pub fn rowPairs(
        comptime S: type,
        main: *const [main_column_count]S,
        lane_last: S,
        inputs: Inputs,
    ) [batch_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) {
        return wordRowPairs(S, main, lane_last, inputs);
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
            const expected_log = try Config.logSizeForRows(self.n_rows);
            if (self.log_size != expected_log or
                self.log_size > trace_mod.maximum_log_size or
                self.n_rows > @as(u64, 1) << @intCast(self.log_size) or
                !sumClaims(Config, self.batch_sums).eql(self.component_sum))
            {
                return error.InvalidStackSwapClaim;
            }
            try Config.validateRows(self.n_rows);
            if (self.n_rows == 0) for (self.batch_sums) |sum|
                if (!sum.isZero()) return error.InvalidStackSwapClaim;
        }
    };
}

pub const CallerClaim = Claim(Caller);
pub const WordClaim = Claim(Word);

pub fn callerRowPairs(
    comptime S: type,
    main: *const [caller.main_column_count]S,
    inputs: Inputs,
) [caller_batch_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    return pairEvents(
        relations_mod.InteractionScalar(S),
        caller_event_count,
        caller_batch_count,
        callerEvents(S, main, inputs),
    );
}

fn callerEvents(
    comptime S: type,
    main: *const [caller.main_column_count]S,
    inputs: Inputs,
) [caller_event_count]EventFor(relations_mod.InteractionScalar(S)) {
    const I = relations_mod.InteractionScalar(S);
    const active = main[caller.Layout.active];
    const negative = active.neg();
    const relations = inputs.relations;
    var events: [caller_event_count]EventFor(I) = undefined;
    var event: usize = 0;
    appendEvent(I, &events, &event, S, negative, relations_mod.combine(
        S,
        relations.base.program_access,
        [5]S{
            main[caller.Layout.pc],
            scalar(S, inputs.authority.allocation.proof_opcode_id),
            scalar(S, abi.destination_register),
            scalar(S, abi.lhs_pointer_register),
            scalar(S, abi.rhs_pointer_register),
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
            main[caller.Layout.pc].add(scalar(S, 4)),
            main[caller.Layout.execution_clock].add(S.one()),
        },
    ));
    const register_clock = accessClock(S, main[caller.Layout.execution_clock], 1);
    inline for (0..2) |side| {
        const previous = main[caller.Layout.previousClock(side)];
        const bytes = callerPointerBytes(S, main, side);
        const register = if (side == 0)
            abi.lhs_pointer_register
        else
            abi.rhs_pointer_register;
        appendEvent(I, &events, &event, S, negative, relations_mod.combine(
            S,
            relations.base.memory_access,
            memoryTuple(S, scalar(S, 0), scalar(S, register), previous, bytes),
        ));
        appendEvent(I, &events, &event, S, active, relations_mod.combine(
            S,
            relations.base.memory_access,
            memoryTuple(S, scalar(S, 0), scalar(S, register), register_clock, bytes),
        ));
        appendEvent(I, &events, &event, S, negative, relations_mod.combine(
            S,
            relations.base.range_check_20,
            [1]S{register_clock.sub(previous).sub(S.one())},
        ));
    }
    inline for (0..2) |side| inline for (0..2) |pair|
        appendEvent(I, &events, &event, S, negative, relations_mod.combine(
            S,
            relations.base.range_check_8_8,
            [2]S{
                main[caller.Layout.pointerByte(side, 2 * pair)],
                main[caller.Layout.pointerByte(side, 2 * pair + 1)],
            },
        ));
    inline for (0..2) |pair| appendEvent(
        I,
        &events,
        &event,
        S,
        negative,
        relations_mod.combine(S, relations.base.range_check_8_8, [2]S{
            main[caller.Layout.gapByte(2 * pair)],
            main[caller.Layout.gapByte(2 * pair + 1)],
        }),
    );
    std.debug.assert(event == caller_base_event_count);
    // Zero numerator keeps the fifteenth base event out of the call-only batch.
    appendEvent(I, &events, &event, S, S.zero(), relations_mod.combine(
        S,
        relations.call,
        relations_mod.callerCallTuple(S, main),
    ));
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
    lane_last: S,
    inputs: Inputs,
) [word_batch_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    return pairEvents(
        relations_mod.InteractionScalar(S),
        word_event_count,
        word_batch_count,
        wordEvents(S, main, lane_last, inputs),
    );
}

fn wordEvents(
    comptime S: type,
    main: *const [words.main_column_count]S,
    lane_last: S,
    inputs: Inputs,
) [word_event_count]EventFor(relations_mod.InteractionScalar(S)) {
    const I = relations_mod.InteractionScalar(S);
    const relations = inputs.relations;
    const active = main[words.Layout.active];
    const negative = active.neg();
    const memory_clock = accessClock(S, main[words.Layout.execution_clock], 2);
    const lhs = wordBytes(S, main, words.Layout.lhs_bytes);
    const rhs = wordBytes(S, main, words.Layout.rhs_bytes);
    const lhs_previous = main[words.Layout.lhs_previous_clock];
    const rhs_previous = main[words.Layout.rhs_previous_clock];
    const lhs_address = main[words.Layout.lhs_word_address].mul(
        scalar(S, abi.word_bytes),
    );
    const rhs_address = main[words.Layout.rhs_word_address].mul(
        scalar(S, abi.word_bytes),
    );
    var events: [word_event_count]EventFor(I) = undefined;
    var event: usize = 0;
    appendEvent(I, &events, &event, S, negative, relations_mod.combine(
        S,
        relations.base.memory_access,
        memoryTuple(S, scalar(S, 1), lhs_address, lhs_previous, lhs),
    ));
    appendEvent(I, &events, &event, S, active, relations_mod.combine(
        S,
        relations.base.memory_access,
        memoryTuple(S, scalar(S, 1), lhs_address, memory_clock, rhs),
    ));
    appendEvent(I, &events, &event, S, negative, relations_mod.combine(
        S,
        relations.base.memory_access,
        memoryTuple(S, scalar(S, 1), rhs_address, rhs_previous, rhs),
    ));
    appendEvent(I, &events, &event, S, active, relations_mod.combine(
        S,
        relations.base.memory_access,
        memoryTuple(S, scalar(S, 1), rhs_address, memory_clock, lhs),
    ));
    appendEvent(I, &events, &event, S, negative, relations_mod.combine(
        S,
        relations.base.range_check_20,
        [1]S{memory_clock.sub(lhs_previous).sub(S.one())},
    ));
    appendEvent(I, &events, &event, S, negative, relations_mod.combine(
        S,
        relations.base.range_check_20,
        [1]S{memory_clock.sub(rhs_previous).sub(S.one())},
    ));
    appendEvent(I, &events, &event, S, active.mul(lane_last).neg(), relations_mod.combine(
        S,
        relations.call,
        wordProofCallTuple(S, main),
    ));
    std.debug.assert(event == word_event_count);
    return events;
}

/// Lane seven carries the same call authority as the caller row after checked
/// semantic materialization has advanced each word address exactly seven.
pub fn wordProofCallTuple(
    comptime S: type,
    main: *const [words.main_column_count]S,
) relations_mod.CallTupleFor(S) {
    return .{
        main[words.Layout.execution_clock],
        main[words.Layout.call_index],
        main[words.Layout.pc],
        main[words.Layout.lhs_word_address].sub(scalar(
            S,
            @intCast(words.lane_count - 1),
        )),
        main[words.Layout.rhs_word_address].sub(scalar(
            S,
            @intCast(words.lane_count - 1),
        )),
    };
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
        .numerator = liftInteraction(S, numerator),
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
        } else result[batch] = logup.RowPairFor(I).single(
            first.numerator,
            first.denominator,
        );
    }
    return result;
}

fn sumClaims(comptime Config: type, claims: [Config.batch_count]QM31) QM31 {
    var result = QM31.zero();
    for (claims) |claim| result = result.add(claim);
    return result;
}

fn ordinaryLogSize(n_rows: u32, minimum: u32) !u32 {
    const result: u32 = @max(
        minimum,
        std.math.log2_int_ceil(u32, @max(@as(u32, 1), n_rows)),
    );
    if (result > trace_mod.maximum_log_size)
        return error.InvalidStackSwapClaim;
    return result;
}

fn boolean(sink: anytype, value: anytype) void {
    sink.add(value.mul(value.sub(@TypeOf(value).one())), 2);
}

fn accessClock(comptime S: type, clock: S, subclock: u32) S {
    return clock.sub(S.one())
        .mul(scalar(S, access_clock.STRIDE))
        .add(scalar(S, subclock));
}

fn memoryTuple(
    comptime S: type,
    address_space: S,
    address: S,
    clock: S,
    bytes: [4]S,
) [7]S {
    return .{ address_space, address, clock, bytes[0], bytes[1], bytes[2], bytes[3] };
}

fn callerPointerBytes(
    comptime S: type,
    main: *const [caller.main_column_count]S,
    side: usize,
) [4]S {
    var result: [4]S = undefined;
    for (&result, 0..) |*value, byte|
        value.* = main[caller.Layout.pointerByte(side, byte)];
    return result;
}

fn wordBytes(
    comptime S: type,
    main: *const [words.main_column_count]S,
    start: usize,
) [4]S {
    return .{ main[start], main[start + 1], main[start + 2], main[start + 3] };
}

fn scalar(comptime S: type, value: u32) S {
    if (comptime S == M31) return M31.fromCanonical(value);
    if (comptime S == QM31) return QM31.fromBase(M31.fromCanonical(value));
    return S.fromBase(M31.fromCanonical(value));
}

fn liftInteraction(comptime S: type, value: S) relations_mod.InteractionScalar(S) {
    if (comptime S == M31) return QM31.fromBase(value);
    return value;
}

comptime {
    if (production_active or Caller.interaction_column_count != 36 or
        Word.interaction_column_count != 16 or caller_event_count != 17 or
        word_event_count != 7 or caller_base_event_count != 15)
    {
        @compileError("stack-swap proof component geometry drifted");
    }
}
