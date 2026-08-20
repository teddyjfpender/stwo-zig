//! Stack-bounded evaluation of the caller's authenticated interaction plan.
//!
//! The canonical specialized evaluator deliberately unrolls all 153 events.
//! This runtime projection retains the registry plan as the sole event/order
//! authority while keeping one entry alive at a time, so Debug builds remain
//! inside the prepared worker-stack budget.

const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const components = @import("component_registry.zig");
const direct_constraints = @import("direct_constraints.zig");
const interaction = @import("interaction.zig");
const logup = @import("../logup.zig");
const relation_challenges = @import("relation_challenges.zig");

const Relations = relation_challenges.Poseidon2V1Relations;
const main_column_count = direct_constraints.caller_main_column_count;
const batch_count = interaction.caller_batch_count;
const direct_constraint_count = direct_constraints.caller_constraint_count;

pub fn evaluate(
    main: *const [main_column_count]QM31,
    is_first: QM31,
    current: [batch_count]QM31,
    previous: [batch_count]QM31,
    claims: [batch_count]QM31,
    relations: *const Relations,
) ![batch_count]QM31 {
    var result: [batch_count]QM31 = undefined;
    for (components.caller_batches, 0..) |batch_plan, batch| {
        result[batch] = logup.pairConstraint(
            current[batch],
            previous[batch],
            is_first,
            claims[batch],
            try callerPair(main, batch_plan, relations),
        );
    }
    return result;
}

pub fn fold(
    main: *const [main_column_count]QM31,
    current: *const [batch_count]QM31,
    previous: *const [batch_count]QM31,
    is_first: QM31,
    claims: *const [batch_count]QM31,
    relations: *const Relations,
    powers: []const QM31,
) !QM31 {
    var folded = QM31.zero();
    for (components.caller_batches, 0..) |batch_plan, batch| {
        const pair = try callerPair(main, batch_plan, relations);
        const constraint = logup.pairConstraint(
            current[batch],
            previous[batch],
            is_first,
            claims[batch],
            pair,
        );
        const constraint_index = direct_constraint_count + batch;
        folded = folded.add(
            powers[powers.len - 1 - constraint_index].mul(constraint),
        );
    }
    return folded;
}

fn callerPair(
    main: *const [main_column_count]QM31,
    batch: components.BatchPlan,
    relations: *const Relations,
) !logup.RowPair {
    const first = try callerEntry(main, components.caller_events[batch.first_event]);
    const d1 = try first.denominator(relations);
    if (batch.second_event) |second_index| {
        const second = try callerEntry(
            main,
            components.caller_events[second_index],
        );
        return .{
            .n1 = first.numerator,
            .d1 = d1,
            .n2 = second.numerator,
            .d2 = try second.denominator(relations),
        };
    }
    return logup.RowPair.single(first.numerator, d1);
}

fn callerEntry(
    main: *const [main_column_count]QM31,
    plan: components.EventPlan,
) !interaction.Entry {
    const layout = components.caller_layout;
    const active = main[layout.enabler];
    const clock = main[layout.execution_clock];
    const pointer_bytes = wordBytes(main, layout.pointer_bytes);
    var entry = interaction.Entry{
        .schema = plan.schema,
        .role = plan.role,
        .access_ordinal = plan.access_ordinal,
        .numerator = switch (plan.numerator) {
            .negative_active => active.neg(),
            .positive_active => active,
            .zero_in_guest_mode => QM31.zero(),
        },
        .values = undefined,
        .arity = plan.arity,
    };
    switch (plan.projection) {
        .program => assignEntry(&entry, .{
            main[layout.pc],
            scalar(components.guest_opcode_id),
            QM31.zero(),
            main[layout.pointer_register],
            QM31.zero(),
        }),
        .state_before => assignEntry(&entry, .{
            main[layout.pc],
            clock,
        }),
        .state_after => assignEntry(&entry, .{
            main[layout.pc].add(scalar(4)),
            clock.add(scalar(1)),
        }),
        .pointer_consume => assignMemory(
            &entry,
            QM31.zero(),
            main[layout.pointer_register],
            main[layout.pointer_previous_clock],
            pointer_bytes,
        ),
        .pointer_emit => assignMemory(
            &entry,
            QM31.zero(),
            main[layout.pointer_register],
            accessClock(clock, 1),
            pointer_bytes,
        ),
        .pointer_clock_gap => assignEntry(&entry, .{
            accessClock(clock, 1)
                .sub(main[layout.pointer_previous_clock])
                .sub(QM31.one()),
        }),
        .lane_consume => assignMemory(
            &entry,
            QM31.one(),
            laneAddress(main[layout.pointer_word_index], plan.index),
            main[layout.previousClock(plan.index)],
            wordBytes(main, layout.inputByte(plan.index, 0)),
        ),
        .lane_emit => assignMemory(
            &entry,
            QM31.one(),
            laneAddress(main[layout.pointer_word_index], plan.index),
            accessClock(clock, 2),
            wordBytes(main, layout.outputByte(plan.index, 0)),
        ),
        .lane_clock_gap => assignEntry(&entry, .{
            accessClock(clock, 2)
                .sub(main[layout.previousClock(plan.index)])
                .sub(QM31.one()),
        }),
        .input_byte_pair => {
            const start = layout.inputByte(plan.index, 2 * plan.part);
            assignEntry(&entry, .{ main[start], main[start + 1] });
        },
        .input_high_limb => assignEntry(&entry, .{
            QM31.zero(),
            main[layout.inputByte(plan.index, 3)],
        }),
        .output_byte_pair => {
            const start = layout.outputByte(plan.index, 2 * plan.part);
            assignEntry(&entry, .{ main[start], main[start + 1] });
        },
        .output_high_limb => assignEntry(&entry, .{
            QM31.zero(),
            main[layout.outputByte(plan.index, 3)],
        }),
        .pointer_span_low => assignEntry(&entry, .{
            main[layout.span_end_limbs],
            main[layout.span_end_limbs + 1],
        }),
        .pointer_span_high => assignEntry(&entry, .{
            main[layout.span_end_limbs + 2],
            mulSmall(main[layout.pointer_bytes + 3], 4),
            main[layout.span_end_limbs + 3],
        }),
        .guest_input_output => for (0..16) |lane| {
            const lane_u8: u8 = @intCast(lane);
            entry.values[lane] = composeWord(
                wordBytes(main, layout.inputByte(lane_u8, 0)),
            );
            entry.values[16 + lane] = composeWord(
                wordBytes(main, layout.outputByte(lane_u8, 0)),
            );
        },
        .provider_input,
        .provider_narrow_output,
        .provider_wide_output,
        .provider_input_output,
        => return error.ConstructionAuthorityMismatch,
    }
    return entry;
}

fn assignEntry(entry: *interaction.Entry, values: anytype) void {
    inline for (values, 0..) |value, index| entry.values[index] = value;
}

fn assignMemory(
    entry: *interaction.Entry,
    address_space: QM31,
    address: QM31,
    clock: QM31,
    limbs: [4]QM31,
) void {
    assignEntry(entry, .{
        address_space,
        address,
        clock,
        limbs[0],
        limbs[1],
        limbs[2],
        limbs[3],
    });
}

fn wordBytes(
    main: *const [main_column_count]QM31,
    start: usize,
) [4]QM31 {
    return main[start..][0..4].*;
}

fn composeWord(bytes: [4]QM31) QM31 {
    return bytes[0]
        .add(mulSmall(bytes[1], 1 << 8))
        .add(mulSmall(bytes[2], 1 << 16))
        .add(mulSmall(bytes[3], 1 << 24));
}

fn accessClock(clock: QM31, ordinal: u8) QM31 {
    return mulSmall(clock.sub(QM31.one()), 4).add(scalar(ordinal));
}

fn laneAddress(word_index: QM31, lane: u8) QM31 {
    return mulSmall(word_index, 4).add(scalar(@as(u32, lane) * 4));
}

fn scalar(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@as(u64, value)));
}

fn mulSmall(value: QM31, coefficient: u32) QM31 {
    return value.mulM31(M31.fromCanonical(coefficient));
}
