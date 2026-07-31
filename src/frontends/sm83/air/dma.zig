//! Direct DMG-B OAM DMA transition constraints.
//!
//! This leaf binds phase, page, byte count, M-cycle clock, exact source and
//! FE00...FE9F destination progression, restart ordering, activity, and
//! completion. The source-read byte is intentionally a separate witness from
//! the copied value so mutations are caught locally; both still require a
//! later ordered memory lookup to authenticate cartridge/system-memory data.
//! PPU/OAM corruption and hardware-model variants are outside this relation.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const dma = @import("../runner/dma.zig");

const N_EVENTS: usize = 4;
const N_PHASES: usize = 4;
const N_CLOCK_BITS: usize = 30;
const EVENT_OFFSET: usize = 0;
const BEFORE_PAGE_OFFSET: usize = EVENT_OFFSET + N_EVENTS;
const BEFORE_PHASE_OFFSET: usize = BEFORE_PAGE_OFFSET + 8;
const BEFORE_COPIED_OFFSET: usize = BEFORE_PHASE_OFFSET + N_PHASES;
const BEFORE_RESTART_OFFSET: usize = BEFORE_COPIED_OFFSET + 8;
const BEFORE_CLOCK_OFFSET: usize = BEFORE_RESTART_OFFSET + 1;
const AFTER_PAGE_OFFSET: usize = BEFORE_CLOCK_OFFSET + N_CLOCK_BITS;
const AFTER_PHASE_OFFSET: usize = AFTER_PAGE_OFFSET + 8;
const AFTER_COPIED_OFFSET: usize = AFTER_PHASE_OFFSET + N_PHASES;
const AFTER_RESTART_OFFSET: usize = AFTER_COPIED_OFFSET + 8;
const AFTER_CLOCK_OFFSET: usize = AFTER_RESTART_OFFSET + 1;
const WRITE_PAGE_OFFSET: usize = AFTER_CLOCK_OFFSET + N_CLOCK_BITS;
const SOURCE_INPUT_OFFSET: usize = WRITE_PAGE_OFFSET + 8;
const TRANSFER_ACTIVE_OFFSET: usize = SOURCE_INPUT_OFFSET + 8;
const SOURCE_ADDRESS_OFFSET: usize = TRANSFER_ACTIVE_OFFSET + 1;
const DESTINATION_ADDRESS_OFFSET: usize = SOURCE_ADDRESS_OFFSET + 16;
const TRANSFER_VALUE_OFFSET: usize = DESTINATION_ADDRESS_OFFSET + 16;
const BEFORE_ACTIVE_OFFSET: usize = TRANSFER_VALUE_OFFSET + 8;
const AFTER_ACTIVE_OFFSET: usize = BEFORE_ACTIVE_OFFSET + 1;
const COMPLETED_OFFSET: usize = AFTER_ACTIVE_OFFSET + 1;
const COPIED_IS_159_OFFSET: usize = COMPLETED_OFFSET + 1;
const COPIED_159_INVERSE_OFFSET: usize = COPIED_IS_159_OFFSET + 1;

pub const N_MAIN_COLUMNS: usize = COPIED_159_INVERSE_OFFSET + 1;
pub const N_CONSTRAINTS: usize = 458;
pub const N_CHAIN_CONSTRAINTS: usize = 52;

pub const ValidatedStep = struct {
    transition: dma.Transition,

    pub fn init(
        transition: dma.Transition,
    ) error{InvalidDmaTransition}!ValidatedStep {
        transition.validate() catch return error.InvalidDmaTransition;
        return .{ .transition = transition };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        pub const StateRow = struct {
            page: [8]S,
            phases: [N_PHASES]S,
            copied: [8]S,
            restarting: S,
            clock: [N_CLOCK_BITS]S,
        };

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            events: [N_EVENTS]S,
            before: StateRow,
            after: StateRow,
            write_page: [8]S,
            source_input: [8]S,
            transfer_active: S,
            source_address: [16]S,
            destination_address: [16]S,
            transfer_value: [8]S,
            before_active: S,
            after_active: S,
            completed: S,
            copied_is_159: S,
            copied_159_inverse: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .events = values[EVENT_OFFSET..BEFORE_PAGE_OFFSET].*,
                    .before = stateFromColumns(
                        values,
                        BEFORE_PAGE_OFFSET,
                    ),
                    .after = stateFromColumns(
                        values,
                        AFTER_PAGE_OFFSET,
                    ),
                    .write_page = values[WRITE_PAGE_OFFSET..SOURCE_INPUT_OFFSET].*,
                    .source_input = values[SOURCE_INPUT_OFFSET..TRANSFER_ACTIVE_OFFSET].*,
                    .transfer_active = values[TRANSFER_ACTIVE_OFFSET],
                    .source_address = values[SOURCE_ADDRESS_OFFSET..DESTINATION_ADDRESS_OFFSET].*,
                    .destination_address = values[DESTINATION_ADDRESS_OFFSET..TRANSFER_VALUE_OFFSET].*,
                    .transfer_value = values[TRANSFER_VALUE_OFFSET..BEFORE_ACTIVE_OFFSET].*,
                    .before_active = values[BEFORE_ACTIVE_OFFSET],
                    .after_active = values[AFTER_ACTIVE_OFFSET],
                    .completed = values[COMPLETED_OFFSET],
                    .copied_is_159 = values[COPIED_IS_159_OFFSET],
                    .copied_159_inverse = values[COPIED_159_INVERSE_OFFSET],
                };
            }
        };

        pub const Evaluation = struct {
            values: [N_CONSTRAINTS]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value|
                    if (!value.isZero()) return false;
                return true;
            }
        };

        pub const ChainEvaluation = struct {
            values: [N_CHAIN_CONSTRAINTS]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value|
                    if (!value.isZero()) return false;
                return true;
            }
        };

        pub fn evaluate(row: Row, is_active: S) Evaluation {
            @setEvalBranchQuota(100_000);
            var out: [N_CONSTRAINTS]S = undefined;
            var at: usize = 0;
            const one = S.one();

            out[at] = bit(is_active);
            at += 1;
            for (row.values[0..COPIED_159_INVERSE_OFFSET]) |value| {
                out[at] = bit(value);
                at += 1;
            }
            for (row.values) |value| {
                out[at] = one.sub(is_active).mul(value);
                at += 1;
            }

            const tick = event(row, .tick);
            const write = event(row, .write_ff46);
            const transfer = event(row, .transfer);
            const transfer_write = event(row, .transfer_and_write);
            const transfer_event = transfer.add(transfer_write);
            const write_event = write.add(transfer_write);

            var selected_event = S.zero();
            for (row.events) |selector|
                selected_event = selected_event.add(selector);
            out[at] = selected_event.sub(is_active);
            at += 1;

            var before_phase = S.zero();
            var after_phase = S.zero();
            for (row.before.phases) |selector|
                before_phase = before_phase.add(selector);
            for (row.after.phases) |selector|
                after_phase = after_phase.add(selector);
            out[at] = before_phase.sub(is_active);
            at += 1;
            out[at] = after_phase.sub(is_active);
            at += 1;

            for (canonicalState(row.before)) |constraint| {
                out[at] = constraint;
                at += 1;
            }
            for (canonicalState(row.after)) |constraint| {
                out[at] = constraint;
                at += 1;
            }

            const before_transfer = phase(row.before, .transfer);
            out[at] = transfer_event.sub(before_transfer);
            at += 1;

            for (row.write_page) |value| {
                out[at] = one.sub(write_event).mul(value);
                at += 1;
            }
            for (row.source_input) |value| {
                out[at] = one.sub(transfer_event).mul(value);
                at += 1;
            }
            for (
                row.source_address ++
                    row.destination_address ++
                    row.transfer_value,
            ) |value| {
                out[at] = one.sub(transfer_event).mul(value);
                at += 1;
            }

            out[at] = row.transfer_active.sub(transfer_event);
            at += 1;
            out[at] = row.before_active.sub(
                is_active.sub(phase(row.before, .idle)),
            );
            at += 1;
            out[at] = row.after_active.sub(
                is_active.sub(phase(row.after, .idle)),
            );
            at += 1;
            out[at] = row.completed.sub(
                phase(row.before, .finishing),
            );
            at += 1;

            const copied = compose(row.before.copied);
            const copied_159_diff = copied.sub(q(159).mul(is_active));
            out[at] = copied_159_diff.mul(row.copied_is_159);
            at += 1;
            out[at] = copied_159_diff
                .mul(row.copied_159_inverse)
                .sub(is_active.sub(row.copied_is_159));
            at += 1;
            for (row.source_address[0..8], row.before.copied) |
                actual,
                expected,
            | {
                out[at] = actual.sub(transfer_event.mul(expected));
                at += 1;
            }
            for (row.source_address[8..], row.before.page, 0..) |
                actual,
                expected,
                index,
            | {
                if (index == 5) continue;
                out[at] = actual.sub(transfer_event.mul(expected));
                at += 1;
            }
            const source_bit_13 = row.source_address[13];
            const gated_page_bit_5 =
                transfer_event.mul(row.before.page[5]);
            out[at] = one.sub(row.before.page[7]).mul(
                gated_page_bit_5.sub(source_bit_13),
            );
            at += 1;
            out[at] = one.sub(row.before.page[6]).mul(
                gated_page_bit_5.sub(source_bit_13),
            );
            at += 1;
            out[at] = source_bit_13
                .mul(row.before.page[7])
                .mul(row.before.page[6]);
            at += 1;
            out[at] = compose(row.destination_address).sub(
                transfer_event.mul(q(dma.OAM_START).add(copied)),
            );
            at += 1;
            for (row.transfer_value, row.source_input) |value, input| {
                out[at] = value.sub(transfer_event.mul(input));
                at += 1;
            }

            const keep_page = tick.add(transfer);
            for (
                row.after.page,
                row.before.page,
                row.write_page,
            ) |after, before, written| {
                out[at] = after.sub(
                    keep_page.mul(before).add(write_event.mul(written)),
                );
                at += 1;
            }

            const last = before_transfer.mul(row.copied_is_159);
            const expected_phases = [_]S{
                tick.mul(
                    phase(row.before, .idle)
                        .add(phase(row.before, .finishing)),
                ),
                write_event,
                tick.mul(phase(row.before, .startup))
                    .add(transfer.mul(one.sub(last))),
                transfer.mul(last),
            };
            for (row.after.phases, expected_phases) |actual, expected| {
                out[at] = actual.sub(expected);
                at += 1;
            }

            out[at] = compose(row.after.copied).sub(
                transfer.mul(copied.add(one)),
            );
            at += 1;
            out[at] = row.after.restarting.sub(
                tick.mul(row.before.restarting)
                    .add(transfer_write.mul(one.sub(last))),
            );
            at += 1;
            out[at] = compose(row.after.clock)
                .sub(compose(row.before.clock))
                .sub(is_active);
            at += 1;

            std.debug.assert(at == out.len);
            return .{ .values = out };
        }

        pub fn evaluateChain(
            previous: Row,
            next: Row,
        ) ChainEvaluation {
            var out: [N_CHAIN_CONSTRAINTS]S = undefined;
            var at: usize = 0;
            for (previous.after.page, next.before.page) |after, before| {
                out[at] = after.sub(before);
                at += 1;
            }
            for (previous.after.phases, next.before.phases) |after, before| {
                out[at] = after.sub(before);
                at += 1;
            }
            for (previous.after.copied, next.before.copied) |after, before| {
                out[at] = after.sub(before);
                at += 1;
            }
            out[at] = previous.after.restarting.sub(
                next.before.restarting,
            );
            at += 1;
            for (previous.after.clock, next.before.clock) |after, before| {
                out[at] = after.sub(before);
                at += 1;
            }
            out[at] = previous.after_active.sub(next.before_active);
            at += 1;
            std.debug.assert(at == out.len);
            return .{ .values = out };
        }

        fn canonicalState(state: StateRow) [7]S {
            const copied = compose(state.copied);
            const idle = phase(state, .idle);
            const startup = phase(state, .startup);
            const transfer = phase(state, .transfer);
            const finishing = phase(state, .finishing);
            return .{
                idle.mul(copied),
                startup.mul(copied),
                finishing.mul(copied.sub(q(dma.OAM_LENGTH))),
                transfer.mul(state.copied[7]).mul(state.copied[5]),
                transfer.mul(state.copied[7]).mul(state.copied[6]),
                state.restarting.mul(idle.add(finishing)),
                state.restarting.mul(transfer).mul(copied),
            };
        }

        fn stateFromColumns(
            values: []const S,
            comptime offset: usize,
        ) StateRow {
            return .{
                .page = values[offset .. offset + 8].*,
                .phases = values[offset + 8 .. offset + 12].*,
                .copied = values[offset + 12 .. offset + 20].*,
                .restarting = values[offset + 20],
                .clock = values[offset + 21 .. offset + 51].*,
            };
        }

        fn event(row: Row, selected: std.meta.Tag(dma.Event)) S {
            return row.events[@intFromEnum(selected)];
        }

        fn phase(state: StateRow, selected: dma.Phase) S {
            return state.phases[@intFromEnum(selected)];
        }

        fn bit(value: S) S {
            return value.mul(value.sub(S.one()));
        }

        fn compose(bits: anytype) S {
            var value = S.zero();
            for (bits, 0..) |bit_value, index|
                value = value.add(
                    q(@as(u64, 1) << @intCast(index)).mul(bit_value),
                );
            return value;
        }

        fn q(value: u64) S {
            return S.fromBase(M31.fromU64(value));
        }
    };
}

pub const Shipped = Semantics(QM31);

pub fn columns(step: ValidatedStep) [N_MAIN_COLUMNS]M31 {
    const transition = step.transition;
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    out[EVENT_OFFSET + @intFromEnum(std.meta.activeTag(transition.event))] =
        M31.one();
    setState(&out, BEFORE_PAGE_OFFSET, transition.before);
    setState(&out, AFTER_PAGE_OFFSET, transition.after);

    switch (transition.event) {
        .write_ff46 => |page| {
            writeBits(out[WRITE_PAGE_OFFSET..SOURCE_INPUT_OFFSET], page);
        },
        .transfer => |source_byte| {
            writeBits(
                out[SOURCE_INPUT_OFFSET..TRANSFER_ACTIVE_OFFSET],
                source_byte,
            );
        },
        .transfer_and_write => |write| {
            writeBits(
                out[WRITE_PAGE_OFFSET..SOURCE_INPUT_OFFSET],
                write.page,
            );
            writeBits(
                out[SOURCE_INPUT_OFFSET..TRANSFER_ACTIVE_OFFSET],
                write.source_byte,
            );
        },
        .tick => {},
    }

    if (transition.transfer) |transfer| {
        out[TRANSFER_ACTIVE_OFFSET] = M31.one();
        writeBits(
            out[SOURCE_ADDRESS_OFFSET..DESTINATION_ADDRESS_OFFSET],
            transfer.source_address,
        );
        writeBits(
            out[DESTINATION_ADDRESS_OFFSET..TRANSFER_VALUE_OFFSET],
            transfer.destination_address,
        );
        writeBits(
            out[TRANSFER_VALUE_OFFSET..BEFORE_ACTIVE_OFFSET],
            transfer.value,
        );
    }
    out[BEFORE_ACTIVE_OFFSET] = boolean(transition.before.isActive());
    out[AFTER_ACTIVE_OFFSET] = boolean(transition.after.isActive());
    out[COMPLETED_OFFSET] = boolean(transition.completed);
    out[COPIED_IS_159_OFFSET] =
        boolean(transition.before.copied == dma.OAM_LENGTH - 1);
    const copied_159_diff = M31.fromCanonical(
        transition.before.copied,
    ).sub(M31.fromCanonical(dma.OAM_LENGTH - 1));
    out[COPIED_159_INVERSE_OFFSET] = if (copied_159_diff.isZero())
        M31.zero()
    else
        copied_159_diff.invUncheckedNonZero();
    return out;
}

pub fn inactiveColumns() [N_MAIN_COLUMNS]M31 {
    return [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
}

pub fn evaluate(
    values: [N_MAIN_COLUMNS]M31,
    is_active: bool,
) !Shipped.Evaluation {
    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, values) |*destination, value|
        destination.* = QM31.fromBase(value);
    return Shipped.evaluate(
        try Shipped.Row.fromColumns(&lifted),
        QM31.fromBase(boolean(is_active)),
    );
}

pub fn evaluateChain(
    previous: [N_MAIN_COLUMNS]M31,
    next: [N_MAIN_COLUMNS]M31,
) !Shipped.ChainEvaluation {
    var left: [N_MAIN_COLUMNS]QM31 = undefined;
    var right: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&left, previous) |*destination, value|
        destination.* = QM31.fromBase(value);
    for (&right, next) |*destination, value|
        destination.* = QM31.fromBase(value);
    return Shipped.evaluateChain(
        try Shipped.Row.fromColumns(&left),
        try Shipped.Row.fromColumns(&right),
    );
}

fn setState(
    out: *[N_MAIN_COLUMNS]M31,
    offset: usize,
    state: dma.State,
) void {
    writeBits(out[offset .. offset + 8], state.page);
    out[offset + 8 + @intFromEnum(state.phase)] = M31.one();
    writeBits(out[offset + 12 .. offset + 20], state.copied);
    out[offset + 20] = boolean(state.restarting);
    writeBits(out[offset + 21 .. offset + 51], state.clock);
}

fn writeBits(out: []M31, value: anytype) void {
    const integer: u64 = @intCast(value);
    for (out, 0..) |*column, index|
        column.* = M31.fromCanonical(
            @intCast((integer >> @intCast(index)) & 1),
        );
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

test "DMA AIR direct constraints are at most cubic" {
    try std.testing.expectEqual(@as(usize, 168), N_MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 458), N_CONSTRAINTS);
    const variables = [_]Degree{Degree.variable()} ** N_MAIN_COLUMNS;
    const semantics = Semantics(Degree);
    const evaluation = semantics.evaluate(
        try semantics.Row.fromColumns(&variables),
        Degree.variable(),
    );
    for (evaluation.values) |constraint|
        try std.testing.expect(constraint.degree <= 3);
}

test "DMA AIR accepts exact boundaries and all source pages" {
    for (0..256) |page| {
        var state = dma.State{ .clock = @intCast(page) };
        const start = try dma.Transition.apply(
            state,
            .{ .write_ff46 = @intCast(page) },
        );
        try expectHonest(start);
        state = start.after;

        const warmup = try dma.Transition.apply(state, .tick);
        try expectHonest(warmup);
        state = warmup.after;

        const first = try dma.Transition.apply(
            state,
            .{ .transfer = @intCast(page) },
        );
        try expectHonest(first);
        const expected = dma.effectiveSourceAddress(
            @intCast(page),
            0,
        );
        try std.testing.expectEqual(
            expected,
            first.transfer.?.source_address,
        );
    }

    var state = dma.State{
        .clock = 400,
        .page = 0xc0,
        .copied = dma.OAM_LENGTH - 1,
        .phase = .transfer,
    };
    const last = try dma.Transition.apply(
        state,
        .{ .transfer = 0x5a },
    );
    const honest_last = columns(try ValidatedStep.init(last));
    try std.testing.expect((try evaluate(honest_last, true)).allZero());
    var forged_last = honest_last;
    forged_last[COPIED_IS_159_OFFSET] = M31.zero();
    try std.testing.expect(
        !(try evaluate(forged_last, true)).allZero(),
    );
    state = last.after;
    const complete = try dma.Transition.apply(state, .tick);
    try expectHonest(complete);
    try std.testing.expect(complete.completed);
}

test "DMA AIR accepts restart ordering and state chains" {
    var state = dma.State{
        .clock = 10,
        .page = 0xc0,
        .copied = 7,
        .phase = .transfer,
    };
    const restart = try dma.Transition.apply(state, .{
        .transfer_and_write = .{
            .source_byte = 0x42,
            .page = 0x80,
        },
    });
    const first = columns(try ValidatedStep.init(restart));
    try std.testing.expect((try evaluate(first, true)).allZero());

    state = restart.after;
    const warmup = try dma.Transition.apply(state, .tick);
    const second = columns(try ValidatedStep.init(warmup));
    try std.testing.expect((try evaluate(second, true)).allZero());
    try std.testing.expect((try evaluateChain(first, second)).allZero());

    state = warmup.after;
    const transfer = try dma.Transition.apply(
        state,
        .{ .transfer = 0x99 },
    );
    const third = columns(try ValidatedStep.init(transfer));
    try std.testing.expect((try evaluate(third, true)).allZero());
    try std.testing.expect((try evaluateChain(second, third)).allZero());
}

test "DMA AIR rejects address value clock activity and vacuity mutations" {
    const state = dma.State{
        .clock = 33,
        .page = 0xfe,
        .copied = 4,
        .phase = .transfer,
    };
    const transition = try dma.Transition.apply(
        state,
        .{ .transfer = 0xa5 },
    );
    const honest = columns(try ValidatedStep.init(transition));
    try std.testing.expect((try evaluate(honest, true)).allZero());

    const mutations = [_]usize{
        SOURCE_INPUT_OFFSET,
        TRANSFER_ACTIVE_OFFSET,
        SOURCE_ADDRESS_OFFSET,
        SOURCE_ADDRESS_OFFSET + 13,
        DESTINATION_ADDRESS_OFFSET,
        TRANSFER_VALUE_OFFSET,
        BEFORE_ACTIVE_OFFSET,
        AFTER_ACTIVE_OFFSET,
        COMPLETED_OFFSET,
        AFTER_CLOCK_OFFSET,
        COPIED_IS_159_OFFSET,
        COPIED_159_INVERSE_OFFSET,
    };
    for (mutations) |column| {
        var forged = honest;
        forged[column] = M31.one().sub(forged[column]);
        try std.testing.expect(!(try evaluate(forged, true)).allZero());
    }

    var forged_event = honest;
    forged_event[
        EVENT_OFFSET + @intFromEnum(
            std.meta.Tag(dma.Event).transfer,
        )
    ] = M31.zero();
    forged_event[
        EVENT_OFFSET + @intFromEnum(
            std.meta.Tag(dma.Event).transfer_and_write,
        )
    ] = M31.one();
    try std.testing.expect(!(try evaluate(forged_event, true)).allZero());

    const next_transition = try dma.Transition.apply(
        transition.after,
        .{ .transfer = 0x33 },
    );
    var broken_chain = columns(
        try ValidatedStep.init(next_transition),
    );
    broken_chain[BEFORE_COPIED_OFFSET] =
        M31.one().sub(broken_chain[BEFORE_COPIED_OFFSET]);
    try std.testing.expect(
        !(try evaluateChain(honest, broken_chain)).allZero(),
    );

    const inactive = inactiveColumns();
    try std.testing.expect((try evaluate(inactive, false)).allZero());
    for (0..N_MAIN_COLUMNS) |column| {
        var non_vacuous = inactive;
        non_vacuous[column] = M31.one();
        try std.testing.expect(
            !(try evaluate(non_vacuous, false)).allZero(),
        );
    }
}

test "DMA AIR validation rejects forged transition metadata" {
    const state = dma.State{
        .page = 0xc0,
        .phase = .transfer,
    };
    var transition = try dma.Transition.apply(
        state,
        .{ .transfer = 0x42 },
    );
    transition.transfer.?.value ^= 1;
    try std.testing.expectError(
        error.InvalidDmaTransition,
        ValidatedStep.init(transition),
    );
}

fn expectHonest(transition: dma.Transition) !void {
    const witness = columns(try ValidatedStep.init(transition));
    try std.testing.expect((try evaluate(witness, true)).allZero());
}

const Degree = struct {
    degree: u32,

    fn variable() Degree {
        return .{ .degree = 1 };
    }

    pub fn zero() Degree {
        return .{ .degree = 0 };
    }

    pub fn one() Degree {
        return .{ .degree = 0 };
    }

    pub fn fromBase(_: M31) Degree {
        return .{ .degree = 0 };
    }

    pub fn add(left: Degree, right: Degree) Degree {
        return .{ .degree = @max(left.degree, right.degree) };
    }

    pub fn sub(left: Degree, right: Degree) Degree {
        return add(left, right);
    }

    pub fn mul(left: Degree, right: Degree) Degree {
        return .{ .degree = left.degree + right.degree };
    }

    pub fn isZero(_: Degree) bool {
        return false;
    }
};
