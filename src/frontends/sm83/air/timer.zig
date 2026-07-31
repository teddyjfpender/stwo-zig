//! Direct constraints for deterministic SM83 divider/timer transitions.
//!
//! This leaf binds one M-cycle tick or one write to DIV, TIMA, TMA, or TAC,
//! including divider edges, TIMA overflow, the delayed reload states, and the
//! timer interrupt request. The host oracle is `runner/timer.zig`, which in
//! turn pins SameBoy's divider and reload ordering.
//!
//! This is not yet an execution/MMIO proof. A separate integration must bind
//! writes and pre-tick reads to FF04..FF07 bus accesses, bind one tick to every
//! execution M-cycle, and bind `interrupt_requested` to IF bit 2.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const timer = @import("../runner/timer.zig");

const N_EVENTS: usize = 5;
pub const N_STATE_COLUMNS: usize = 38;
const EVENT_OFFSET: usize = 0;
const BEFORE_DIV_OFFSET: usize = EVENT_OFFSET + N_EVENTS;
const BEFORE_TIMA_OFFSET: usize = BEFORE_DIV_OFFSET + 16;
const BEFORE_TMA_OFFSET: usize = BEFORE_TIMA_OFFSET + 8;
const BEFORE_TAC_OFFSET: usize = BEFORE_TMA_OFFSET + 8;
const BEFORE_RELOAD_OFFSET: usize = BEFORE_TAC_OFFSET + 3;
const ACTION_OFFSET: usize = BEFORE_RELOAD_OFFSET + 3;
const AFTER_DIV_OFFSET: usize = ACTION_OFFSET + 8;
const AFTER_TIMA_OFFSET: usize = AFTER_DIV_OFFSET + 16;
const AFTER_TMA_OFFSET: usize = AFTER_TIMA_OFFSET + 8;
const AFTER_TAC_OFFSET: usize = AFTER_TMA_OFFSET + 8;
const AFTER_RELOAD_OFFSET: usize = AFTER_TAC_OFFSET + 3;
const INTERRUPT_OFFSET: usize = AFTER_RELOAD_OFFSET + 3;
pub const BASE_N_MAIN_COLUMNS: usize = INTERRUPT_OFFSET + 1;
const BEFORE_SELECTOR_HOT_OFFSET: usize = BASE_N_MAIN_COLUMNS;
const NEW_SELECTOR_HOT_OFFSET: usize = BEFORE_SELECTOR_HOT_OFFSET + 3;
const TICK_CARRY_OFFSET: usize = NEW_SELECTOR_HOT_OFFSET + 3;
const TIMA_CARRY_OFFSET: usize = TICK_CARRY_OFFSET + 13;
const OLD_SIGNAL_OFFSET: usize = TIMA_CARRY_OFFSET + 8;
const TICK_SELECTED_OFFSET: usize = OLD_SIGNAL_OFFSET + 1;
const TICK_SIGNAL_OFFSET: usize = TICK_SELECTED_OFFSET + 1;
const NEW_SIGNAL_OFFSET: usize = TICK_SIGNAL_OFFSET + 1;
const INCREMENT_OFFSET: usize = NEW_SIGNAL_OFFSET + 1;
const OVERFLOW_OFFSET: usize = INCREMENT_OFFSET + 1;

pub const N_MAIN_COLUMNS: usize = OVERFLOW_OFFSET + 1;
pub const N_CONSTRAINTS: usize = 330;
pub const N_CHAIN_CONSTRAINTS: usize = N_STATE_COLUMNS;
pub const BEFORE_STATE_OFFSET: usize = BEFORE_DIV_OFFSET;
pub const ACTION_COLUMN_OFFSET: usize = ACTION_OFFSET;
pub const AFTER_STATE_OFFSET: usize = AFTER_DIV_OFFSET;
pub const INTERRUPT_COLUMN: usize = INTERRUPT_OFFSET;

pub const Event = union(enum) {
    tick_mcycle,
    write_div: u8,
    write_tima: u8,
    write_tma: u8,
    write_tac: u8,
};

pub const Transition = struct {
    before: timer.Timer,
    after: timer.Timer,
    event: Event,
    interrupt_requested: bool,

    pub fn apply(before: timer.Timer, event_value: Event) Transition {
        var after = before;
        const interrupt_requested = switch (event_value) {
            .tick_mcycle => after.tickMcycle(),
            .write_div => |_| no_interrupt: {
                after.writeDiv();
                break :no_interrupt false;
            },
            .write_tima => |value| no_interrupt: {
                after.writeTima(value);
                break :no_interrupt false;
            },
            .write_tma => |value| no_interrupt: {
                after.writeTma(value);
                break :no_interrupt false;
            },
            .write_tac => |value| no_interrupt: {
                after.writeTac(value);
                break :no_interrupt false;
            },
        };
        return .{
            .before = before,
            .after = after,
            .event = event_value,
            .interrupt_requested = interrupt_requested,
        };
    }

    pub fn validate(
        self: Transition,
    ) error{InvalidTimerTransition}!void {
        if (!std.meta.eql(Transition.apply(self.before, self.event), self))
            return error.InvalidTimerTransition;
    }
};

pub const ValidatedStep = struct {
    transition: Transition,

    pub fn init(
        transition: Transition,
    ) error{InvalidTimerTransition}!ValidatedStep {
        try transition.validate();
        return .{ .transition = transition };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        pub const StateRow = struct {
            values: [N_STATE_COLUMNS]S,
            div: [16]S,
            tima: [8]S,
            tma: [8]S,
            tac: [3]S,
            reload: [3]S,

            fn fromColumns(values: []const S) !StateRow {
                if (values.len != N_STATE_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_STATE_COLUMNS].*,
                    .div = values[0..16].*,
                    .tima = values[16..24].*,
                    .tma = values[24..32].*,
                    .tac = values[32..35].*,
                    .reload = values[35..38].*,
                };
            }
        };

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            events: [N_EVENTS]S,
            before: StateRow,
            action: [8]S,
            after: StateRow,
            interrupt_requested: S,
            before_selector_hot: [3]S,
            new_selector_hot: [3]S,
            tick_carry: [13]S,
            tima_carry: [8]S,
            old_signal: S,
            tick_selected: S,
            tick_signal: S,
            new_signal: S,
            increment: S,
            overflow: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .events = values[EVENT_OFFSET..BEFORE_DIV_OFFSET].*,
                    .before = try StateRow.fromColumns(
                        values[BEFORE_DIV_OFFSET..ACTION_OFFSET],
                    ),
                    .action = values[ACTION_OFFSET..AFTER_DIV_OFFSET].*,
                    .after = try StateRow.fromColumns(
                        values[AFTER_DIV_OFFSET..INTERRUPT_OFFSET],
                    ),
                    .interrupt_requested = values[INTERRUPT_OFFSET],
                    .before_selector_hot = values[BEFORE_SELECTOR_HOT_OFFSET..NEW_SELECTOR_HOT_OFFSET].*,
                    .new_selector_hot = values[NEW_SELECTOR_HOT_OFFSET..TICK_CARRY_OFFSET].*,
                    .tick_carry = values[TICK_CARRY_OFFSET..TIMA_CARRY_OFFSET].*,
                    .tima_carry = values[TIMA_CARRY_OFFSET..OLD_SIGNAL_OFFSET].*,
                    .old_signal = values[OLD_SIGNAL_OFFSET],
                    .tick_selected = values[TICK_SELECTED_OFFSET],
                    .tick_signal = values[TICK_SIGNAL_OFFSET],
                    .new_signal = values[NEW_SIGNAL_OFFSET],
                    .increment = values[INCREMENT_OFFSET],
                    .overflow = values[OVERFLOW_OFFSET],
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
            var out: [N_CONSTRAINTS]S = undefined;
            var at: usize = 0;
            const one = S.one();
            out[at] = bit(is_active);
            at += 1;
            for (row.values) |value| {
                out[at] = bit(value);
                at += 1;
            }
            for (row.values) |value| {
                out[at] = one.sub(is_active).mul(value);
                at += 1;
            }

            const tick = row.events[@intFromEnum(Tag.tick_mcycle)];
            const write_div = row.events[@intFromEnum(Tag.write_div)];
            const write_tima = row.events[@intFromEnum(Tag.write_tima)];
            const write_tma = row.events[@intFromEnum(Tag.write_tma)];
            const write_tac = row.events[@intFromEnum(Tag.write_tac)];
            var event_sum = S.zero();
            for (row.events) |selected| event_sum = event_sum.add(selected);
            out[at] = event_sum.sub(is_active);
            at += 1;
            for (row.action) |action_bit| {
                out[at] = tick.mul(action_bit);
                at += 1;
            }
            out[at] = sum(row.before.reload).sub(is_active);
            at += 1;
            out[at] = sum(row.after.reload).sub(is_active);
            at += 1;

            const expected_before_hot = selectorHot(
                row.before.tac[0..2].*,
                is_active,
            );
            for (
                row.before_selector_hot,
                expected_before_hot[0..3],
            ) |actual, expected| {
                out[at] = actual.sub(expected);
                at += 1;
            }
            const expected_new_hot = selectorHot(
                row.action[0..2].*,
                is_active,
            );
            for (
                row.new_selector_hot,
                expected_new_hot[0..3],
            ) |actual, expected| {
                out[at] = actual.sub(expected);
                at += 1;
            }

            out[at] = row.tick_carry[0].sub(row.before.div[2]);
            at += 1;
            for (row.tick_carry[1..], 1..) |carry, index| {
                out[at] = carry.sub(
                    row.before.div[index + 2].mul(
                        row.tick_carry[index - 1],
                    ),
                );
                at += 1;
            }
            out[at] = row.tima_carry[0].sub(row.before.tima[0]);
            at += 1;
            for (row.tima_carry[1..], 1..) |carry, index| {
                out[at] = carry.sub(
                    row.before.tima[index].mul(
                        row.tima_carry[index - 1],
                    ),
                );
                at += 1;
            }

            const before_hot = committedHot(
                row.before_selector_hot,
                is_active,
            );
            const new_hot = committedHot(row.new_selector_hot, is_active);
            const selected_before = selectDividerBit(
                row.before.div,
                before_hot,
            );
            out[at] = row.old_signal.sub(
                row.before.tac[2].mul(selected_before),
            );
            at += 1;
            var tick_bits: [16]S = undefined;
            for (&tick_bits, 0..) |*value, index|
                value.* = tickDivBit(row, index);
            out[at] = row.tick_selected.sub(
                selectDividerBit(tick_bits, before_hot),
            );
            at += 1;
            out[at] = row.tick_signal.sub(
                row.before.tac[2].mul(row.tick_selected),
            );
            at += 1;
            out[at] = row.new_signal.sub(
                row.action[2].mul(
                    selectDividerBit(row.before.div, new_hot),
                ),
            );
            at += 1;
            out[at] = row.increment.sub(
                tick.mul(row.old_signal).mul(
                    one.sub(row.tick_signal),
                ).add(write_div.mul(row.old_signal)).add(
                    write_tac.mul(row.old_signal).mul(
                        one.sub(row.new_signal),
                    ),
                ),
            );
            at += 1;
            out[at] = row.overflow.sub(
                row.increment.mul(row.tima_carry[7]),
            );
            at += 1;

            const preserve_div = write_tima.add(write_tma).add(write_tac);
            for (row.after.div, row.before.div, 0..) |
                actual,
                before,
                index,
            | {
                out[at] = actual.sub(
                    tick.mul(tick_bits[index]).add(
                        preserve_div.mul(before),
                    ),
                );
                at += 1;
            }

            const clock_ops = tick.add(write_div).add(write_tac);
            const increment_nonoverflow =
                row.increment.sub(row.overflow);
            const unchanged_clock = clock_ops.sub(row.increment);
            const before_reloaded = row.before.reload[
                @intFromEnum(timer.ReloadState.reloaded)
            ];
            const before_running = row.before.reload[
                @intFromEnum(timer.ReloadState.running)
            ];
            for (
                row.after.tima,
                row.before.tima,
                row.before.tma,
                row.action,
                0..,
            ) |actual, before, modulo, action, index| {
                const incremented = timaIncrementBit(row, index);
                const tima_write_value = one.sub(before_reloaded)
                    .mul(action).add(before_reloaded.mul(before));
                const tma_write_value = one.sub(before_running)
                    .mul(action).add(before_running.mul(before));
                const expected = row.overflow.mul(modulo)
                    .add(increment_nonoverflow.mul(incremented))
                    .add(unchanged_clock.mul(before))
                    .add(write_tima.mul(tima_write_value))
                    .add(write_tma.mul(tma_write_value));
                out[at] = actual.sub(expected);
                at += 1;
            }
            for (row.after.tma, row.before.tma, row.action) |
                actual,
                before,
                action,
            | {
                out[at] = actual.sub(
                    write_tma.mul(action).add(
                        one.sub(write_tma).mul(before),
                    ),
                );
                at += 1;
            }
            for (row.after.tac, row.before.tac, row.action[0..3]) |
                actual,
                before,
                action,
            | {
                out[at] = actual.sub(
                    write_tac.mul(action).add(
                        one.sub(write_tac).mul(before),
                    ),
                );
                at += 1;
            }

            const not_tick =
                write_div.add(write_tima).add(write_tma).add(write_tac);
            const before_reloading = row.before.reload[
                @intFromEnum(timer.ReloadState.reloading)
            ];
            const base_running = tick.mul(
                before_running.add(before_reloaded),
            ).add(not_tick.mul(before_running));
            const base_reloading = not_tick.mul(before_reloading);
            const base_reloaded = tick.mul(before_reloading)
                .add(not_tick.mul(before_reloaded));
            const no_overflow = one.sub(row.overflow);
            const expected_reload = [3]S{
                base_running.mul(no_overflow),
                row.overflow.add(base_reloading.mul(no_overflow)),
                base_reloaded.mul(no_overflow),
            };
            for (row.after.reload, expected_reload) |actual, expected| {
                out[at] = actual.sub(expected);
                at += 1;
            }
            out[at] = row.interrupt_requested.sub(
                tick.mul(before_reloading),
            );
            at += 1;
            std.debug.assert(at == out.len);
            return .{ .values = out };
        }

        pub fn evaluateChain(
            previous: Row,
            next: Row,
        ) ChainEvaluation {
            var out: [N_CHAIN_CONSTRAINTS]S = undefined;
            for (
                &out,
                previous.after.values,
                next.before.values,
            ) |*constraint, after, before|
                constraint.* = after.sub(before);
            return .{ .values = out };
        }

        fn bit(value: S) S {
            return value.mul(value.sub(S.one()));
        }

        fn sum(values: anytype) S {
            var result = S.zero();
            for (values) |value| result = result.add(value);
            return result;
        }

        fn selectorHot(bits: [2]S, active: S) [4]S {
            const one = S.one();
            return .{
                active.sub(bits[0]).sub(bits[1])
                    .add(bits[0].mul(bits[1])),
                bits[0].mul(one.sub(bits[1])),
                one.sub(bits[0]).mul(bits[1]),
                bits[0].mul(bits[1]),
            };
        }

        fn committedHot(first_three: [3]S, active: S) [4]S {
            return .{
                first_three[0],
                first_three[1],
                first_three[2],
                active.sub(first_three[0])
                    .sub(first_three[1])
                    .sub(first_three[2]),
            };
        }

        fn selectDividerBit(bits: [16]S, hot: [4]S) S {
            return hot[0].mul(bits[9])
                .add(hot[1].mul(bits[3]))
                .add(hot[2].mul(bits[5]))
                .add(hot[3].mul(bits[7]));
        }

        fn tickDivBit(row: Row, index: usize) S {
            if (index < 2) return row.before.div[index];
            if (index == 2) return S.one().sub(row.before.div[2]);
            const carry = row.tick_carry[index - 3];
            const before = row.before.div[index];
            return before.add(carry).sub(
                q(2).mul(before.mul(carry)),
            );
        }

        fn timaIncrementBit(row: Row, index: usize) S {
            if (index == 0) return S.one().sub(row.before.tima[0]);
            const carry = row.tima_carry[index - 1];
            const before = row.before.tima[index];
            return before.add(carry).sub(
                q(2).mul(before.mul(carry)),
            );
        }

        fn q(value: u32) S {
            if (S == M31) return M31.fromCanonical(value);
            return S.fromBase(M31.fromCanonical(value));
        }
    };
}

const Tag = std.meta.Tag(Event);
pub const Shipped = Semantics(QM31);

pub fn columns(step: ValidatedStep) [N_MAIN_COLUMNS]M31 {
    const transition = step.transition;
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    const tag = std.meta.activeTag(transition.event);
    out[EVENT_OFFSET + @intFromEnum(tag)] = M31.one();
    setState(&out, BEFORE_DIV_OFFSET, transition.before);
    const action: u8 = switch (transition.event) {
        .tick_mcycle => 0,
        .write_div => |value| value,
        .write_tima => |value| value,
        .write_tma => |value| value,
        .write_tac => |value| value,
    };
    writeBits(out[ACTION_OFFSET..AFTER_DIV_OFFSET], action);
    setState(&out, AFTER_DIV_OFFSET, transition.after);
    out[INTERRUPT_OFFSET] = boolean(transition.interrupt_requested);
    setAuxiliaries(&out, transition.before, transition.event, action);
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

pub fn stateConstants(
    comptime S: type,
    value: timer.Timer,
) [N_STATE_COLUMNS]S {
    var base = [_]M31{M31.zero()} ** N_STATE_COLUMNS;
    setStateSlice(&base, value);
    var result: [N_STATE_COLUMNS]S = undefined;
    for (&result, base) |*destination, source|
        destination.* = S.fromBase(source);
    return result;
}

fn setState(
    out: *[N_MAIN_COLUMNS]M31,
    offset: usize,
    value: timer.Timer,
) void {
    setStateSlice(out[offset .. offset + N_STATE_COLUMNS], value);
}

fn setStateSlice(out: []M31, value: timer.Timer) void {
    std.debug.assert(out.len == N_STATE_COLUMNS);
    writeBits(out[0..16], value.div_counter);
    writeBits(out[16..24], value.tima);
    writeBits(out[24..32], value.tma);
    writeBits(out[32..35], value.tac);
    out[35 + @as(usize, @intFromEnum(value.reload_state))] = M31.one();
}

fn setAuxiliaries(
    out: *[N_MAIN_COLUMNS]M31,
    before: timer.Timer,
    event_value: Event,
    action: u8,
) void {
    const before_selector: u2 = @truncate(before.tac);
    const new_selector: u2 = @truncate(action);
    writeHot(
        out[BEFORE_SELECTOR_HOT_OFFSET..NEW_SELECTOR_HOT_OFFSET],
        before_selector,
    );
    writeHot(
        out[NEW_SELECTOR_HOT_OFFSET..TICK_CARRY_OFFSET],
        new_selector,
    );

    var carry = before.div_counter >> 2 & 1 != 0;
    for (out[TICK_CARRY_OFFSET..TIMA_CARRY_OFFSET], 3..) |
        *destination,
        bit_index,
    | {
        destination.* = boolean(carry);
        carry = carry and
            before.div_counter >> @intCast(bit_index) & 1 != 0;
    }
    carry = true;
    for (out[TIMA_CARRY_OFFSET..OLD_SIGNAL_OFFSET], 0..) |
        *destination,
        bit_index,
    | {
        carry = carry and
            before.tima >> @intCast(bit_index) & 1 != 0;
        destination.* = boolean(carry);
    }

    const tick_div = before.div_counter +% 4;
    const old_signal = signal(before.div_counter, before.tac);
    const tick_signal = signal(tick_div, before.tac);
    const new_tac: u3 = @truncate(action);
    const new_signal = signal(before.div_counter, new_tac);
    const increment = switch (event_value) {
        .tick_mcycle => old_signal and !tick_signal,
        .write_div => old_signal,
        .write_tac => old_signal and !new_signal,
        .write_tima, .write_tma => false,
    };
    out[OLD_SIGNAL_OFFSET] = boolean(old_signal);
    out[TICK_SELECTED_OFFSET] = boolean(
        selectedDividerBit(tick_div, before_selector),
    );
    out[TICK_SIGNAL_OFFSET] = boolean(tick_signal);
    out[NEW_SIGNAL_OFFSET] = boolean(new_signal);
    out[INCREMENT_OFFSET] = boolean(increment);
    out[OVERFLOW_OFFSET] = boolean(increment and before.tima == 0xff);
}

fn writeHot(out: []M31, selector: u2) void {
    std.debug.assert(out.len == 3);
    if (selector < 3) out[selector] = M31.one();
}

fn writeBits(out: []M31, value: anytype) void {
    const integer: u64 = @intCast(value);
    for (out, 0..) |*destination, index|
        destination.* = M31.fromCanonical(
            @intCast(integer >> @intCast(index) & 1),
        );
}

fn signal(div: u16, tac: u3) bool {
    return tac & 4 != 0 and selectedDividerBit(div, @truncate(tac));
}

fn selectedDividerBit(div: u16, selector: u2) bool {
    const bit_index: u4 = switch (selector) {
        0 => 9,
        1 => 3,
        2 => 5,
        3 => 7,
    };
    return div >> bit_index & 1 != 0;
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}
