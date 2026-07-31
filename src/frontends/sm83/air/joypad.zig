//! Direct deterministic DMG-B joypad transition constraints.
//!
//! This leaf binds canonical joypad state, host-key/P1/tick events, selector
//! propagation, P1 reads, and the joypad IF edge. It is not yet an
//! authenticated MMIO or scheduler relation: a later integration must bind
//! these rows to ordered 0xff00 bus accesses, elapsed M-cycles, and IF writes.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const joypad = @import("../runner/joypad.zig");

const N_EVENTS: usize = 3;
const N_DELAYS: usize = 49;
const EVENT_OFFSET: usize = 0;
const BEFORE_P1_OFFSET: usize = EVENT_OFFSET + N_EVENTS;
const BEFORE_PRESSED_OFFSET: usize = BEFORE_P1_OFFSET + 8;
const BEFORE_PENDING_OFFSET: usize = BEFORE_PRESSED_OFFSET + 8;
const BEFORE_DELAY_OFFSET: usize = BEFORE_PENDING_OFFSET + 2;
const ACTION_OFFSET: usize = BEFORE_DELAY_OFFSET + 6;
const AFTER_P1_OFFSET: usize = ACTION_OFFSET + 8;
const AFTER_PRESSED_OFFSET: usize = AFTER_P1_OFFSET + 8;
const AFTER_PENDING_OFFSET: usize = AFTER_PRESSED_OFFSET + 8;
const AFTER_DELAY_OFFSET: usize = AFTER_PENDING_OFFSET + 2;
const READ_OFFSET: usize = AFTER_DELAY_OFFSET + 6;
const EDGE_OFFSET: usize = READ_OFFSET + 8;
const DELAY_HOT_OFFSET: usize = EDGE_OFFSET + 1;
const BASE_N_MAIN_COLUMNS: usize = DELAY_HOT_OFFSET + N_DELAYS;
const BEFORE_HOT_OFFSET: usize = BASE_N_MAIN_COLUMNS;
const REQUESTED_HOT_OFFSET: usize = BEFORE_HOT_OFFSET + 3;
const SAME_SELECTOR_OFFSET: usize = REQUESTED_HOT_OFFSET + 3;
const BASE_SELECTOR_OFFSET: usize = SAME_SELECTOR_OFFSET + 1;
const BASE_HOT_OFFSET: usize = BASE_SELECTOR_OFFSET + 2;
const WRITE_SELECTOR_OFFSET: usize = BASE_HOT_OFFSET + 3;
const WRITE_DELAY_NONZERO_OFFSET: usize = WRITE_SELECTOR_OFFSET + 2;
const AFTER_HOT_OFFSET: usize = WRITE_DELAY_NONZERO_OFFSET + 1;
const AFTER_DELAY_NONZERO_OFFSET: usize = AFTER_HOT_OFFSET + 3;
const FALLING_OFFSET: usize = AFTER_DELAY_NONZERO_OFFSET + 1;
const EDGE_PREFIX_OFFSET: usize = FALLING_OFFSET + 4;
const WRITE_DELAY_OFFSET: usize = EDGE_PREFIX_OFFSET + 2;

pub const N_MAIN_COLUMNS: usize = WRITE_DELAY_OFFSET + 1;
pub const N_CONSTRAINTS: usize = 336;
pub const N_CHAIN_CONSTRAINTS: usize = 24;

pub const ValidatedStep = struct {
    transition: joypad.Transition,

    pub fn init(
        transition: joypad.Transition,
    ) error{InvalidJoypadTransition}!ValidatedStep {
        transition.validate() catch return error.InvalidJoypadTransition;
        return .{ .transition = transition };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            events: [N_EVENTS]S,
            before_p1: [8]S,
            before_pressed: [8]S,
            before_pending: [2]S,
            before_delay: [6]S,
            action: [8]S,
            after_p1: [8]S,
            after_pressed: [8]S,
            after_pending: [2]S,
            after_delay: [6]S,
            p1_read: [8]S,
            interrupt_requested: S,
            delay_hot: [N_DELAYS]S,
            before_hot: [3]S,
            requested_hot: [3]S,
            same_selector: S,
            base_selector: [2]S,
            base_hot: [3]S,
            write_selector: [2]S,
            write_delay_nonzero: S,
            after_hot: [3]S,
            after_delay_nonzero: S,
            falling: [4]S,
            edge_prefix: [2]S,
            write_delay: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .events = values[EVENT_OFFSET..BEFORE_P1_OFFSET].*,
                    .before_p1 = values[BEFORE_P1_OFFSET..BEFORE_PRESSED_OFFSET].*,
                    .before_pressed = values[BEFORE_PRESSED_OFFSET..BEFORE_PENDING_OFFSET].*,
                    .before_pending = values[BEFORE_PENDING_OFFSET..BEFORE_DELAY_OFFSET].*,
                    .before_delay = values[BEFORE_DELAY_OFFSET..ACTION_OFFSET].*,
                    .action = values[ACTION_OFFSET..AFTER_P1_OFFSET].*,
                    .after_p1 = values[AFTER_P1_OFFSET..AFTER_PRESSED_OFFSET].*,
                    .after_pressed = values[AFTER_PRESSED_OFFSET..AFTER_PENDING_OFFSET].*,
                    .after_pending = values[AFTER_PENDING_OFFSET..AFTER_DELAY_OFFSET].*,
                    .after_delay = values[AFTER_DELAY_OFFSET..READ_OFFSET].*,
                    .p1_read = values[READ_OFFSET..EDGE_OFFSET].*,
                    .interrupt_requested = values[EDGE_OFFSET],
                    .delay_hot = values[DELAY_HOT_OFFSET..BASE_N_MAIN_COLUMNS].*,
                    .before_hot = values[BEFORE_HOT_OFFSET..REQUESTED_HOT_OFFSET].*,
                    .requested_hot = values[REQUESTED_HOT_OFFSET..SAME_SELECTOR_OFFSET].*,
                    .same_selector = values[SAME_SELECTOR_OFFSET],
                    .base_selector = values[BASE_SELECTOR_OFFSET..BASE_HOT_OFFSET].*,
                    .base_hot = values[BASE_HOT_OFFSET..WRITE_SELECTOR_OFFSET].*,
                    .write_selector = values[WRITE_SELECTOR_OFFSET..WRITE_DELAY_NONZERO_OFFSET].*,
                    .write_delay_nonzero = values[WRITE_DELAY_NONZERO_OFFSET],
                    .after_hot = values[AFTER_HOT_OFFSET..AFTER_DELAY_NONZERO_OFFSET].*,
                    .after_delay_nonzero = values[AFTER_DELAY_NONZERO_OFFSET],
                    .falling = values[FALLING_OFFSET..EDGE_PREFIX_OFFSET].*,
                    .edge_prefix = values[EDGE_PREFIX_OFFSET..WRITE_DELAY_OFFSET].*,
                    .write_delay = values[WRITE_DELAY_OFFSET],
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
            @setEvalBranchQuota(1_000_000);
            var out: [N_CONSTRAINTS]S = undefined;
            var at: usize = 0;
            const one = S.one();

            out[at] = bit(is_active);
            at += 1;
            for (row.values[0..BASE_N_MAIN_COLUMNS]) |value| {
                out[at] = bit(value);
                at += 1;
            }
            for (row.values) |value| {
                out[at] = one.sub(is_active).mul(value);
                at += 1;
            }

            const set_pressed = row.events[
                @intFromEnum(
                    std.meta.Tag(joypad.Event).set_pressed,
                )
            ];
            const write_p1 = row.events[
                @intFromEnum(
                    std.meta.Tag(joypad.Event).write_p1,
                )
            ];
            const tick_mcycle = row.events[
                @intFromEnum(
                    std.meta.Tag(joypad.Event).tick_mcycle,
                )
            ];
            out[at] = set_pressed.add(write_p1).add(tick_mcycle)
                .sub(is_active);
            at += 1;

            var delay_selected = S.zero();
            var before_delay = S.zero();
            for (row.delay_hot, 0..) |selected, delay| {
                delay_selected = delay_selected.add(selected);
                before_delay = before_delay.add(q(delay).mul(selected));
            }
            out[at] = delay_selected.sub(is_active);
            at += 1;
            out[at] = compose(row.before_delay).sub(before_delay);
            at += 1;

            for (row.action) |value| {
                out[at] = tick_mcycle.mul(value);
                at += 1;
            }

            const before_selector = [2]S{
                row.before_p1[4],
                row.before_p1[5],
            };
            const expected_before_hot = selectorHot(
                before_selector,
                is_active,
            );
            for (row.before_hot, expected_before_hot[0..3]) |
                actual,
                expected,
            | {
                out[at] = actual.sub(expected);
                at += 1;
            }
            const before_selector_hot = committedHot(
                row.before_hot,
                is_active,
            );
            const before_lines = lineValues(
                before_selector_hot,
                row.before_pressed,
            );
            out[at] = row.before_p1[6].sub(is_active);
            at += 1;
            out[at] = row.before_p1[7].sub(is_active);
            at += 1;
            for (row.before_p1[0..4], before_lines) |actual, expected| {
                out[at] = actual.sub(expected);
                at += 1;
            }

            const delay_zero = row.delay_hot[0];
            const delay_nonzero = is_active.sub(delay_zero);
            for (before_selector, row.before_pending) |selected, pending| {
                out[at] = delay_zero.mul(selected.sub(pending));
                at += 1;
            }

            const requested_selector = [2]S{
                row.action[4],
                row.action[5],
            };
            const expected_requested_hot = selectorHot(
                requested_selector,
                is_active,
            );
            for (row.requested_hot, expected_requested_hot[0..3]) |
                actual,
                expected,
            | {
                out[at] = actual.sub(expected);
                at += 1;
            }
            const requested_hot = committedHot(
                row.requested_hot,
                is_active,
            );
            var expected_same_selector = S.zero();
            for (before_selector_hot, requested_hot) |before, requested|
                expected_same_selector =
                    expected_same_selector.add(before.mul(requested));
            out[at] = row.same_selector.sub(expected_same_selector);
            at += 1;

            const expected_base_selector = [2]S{
                delay_zero.mul(before_selector[0])
                    .add(delay_nonzero.mul(row.before_pending[0])),
                delay_zero.mul(before_selector[1])
                    .add(delay_nonzero.mul(row.before_pending[1])),
            };
            for (row.base_selector, expected_base_selector) |
                actual,
                expected,
            | {
                out[at] = actual.sub(expected);
                at += 1;
            }
            const expected_base_hot = selectorHot(
                row.base_selector,
                is_active,
            );
            for (row.base_hot, expected_base_hot[0..3]) |actual, expected| {
                out[at] = actual.sub(expected);
                at += 1;
            }
            const base_hot = committedHot(row.base_hot, is_active);

            var expected_write_delay = S.zero();
            var expected_write_delay_nonzero = S.zero();
            var expected_write_selector = [_]S{S.zero()} ** 2;
            for (row.delay_hot, 0..) |delay_selected_bit, old_delay| {
                for (base_hot, 0..) |base_selected, base| {
                    for (requested_hot, 0..) |requested_selected, requested| {
                        const selected = delay_selected_bit
                            .mul(base_selected)
                            .mul(requested_selected);
                        const transition_delay = selectorDelay(base, requested);
                        const next_delay = @max(old_delay, transition_delay);
                        expected_write_delay = expected_write_delay.add(
                            q(next_delay).mul(selected),
                        );
                        if (next_delay != 0)
                            expected_write_delay_nonzero =
                                expected_write_delay_nonzero.add(selected);
                        const internal = if (next_delay == 0)
                            requested
                        else
                            requested & base;
                        inline for (0..2) |bit_index| {
                            if (internal & (1 << bit_index) != 0)
                                expected_write_selector[bit_index] =
                                    expected_write_selector[bit_index].add(
                                        selected,
                                    );
                        }
                    }
                }
            }
            for (row.write_selector, expected_write_selector) |
                actual,
                expected,
            | {
                out[at] = actual.sub(expected);
                at += 1;
            }
            out[at] = row.write_delay_nonzero.sub(
                expected_write_delay_nonzero,
            );
            at += 1;
            out[at] = row.write_delay.sub(expected_write_delay);
            at += 1;

            var tick_delay = S.zero();
            var tick_delay_nonzero = S.zero();
            var tick_install = S.zero();
            for (row.delay_hot, 0..) |selected, delay| {
                const next_delay = if (delay > 8) delay - 8 else 0;
                tick_delay = tick_delay.add(q(next_delay).mul(selected));
                if (next_delay != 0)
                    tick_delay_nonzero = tick_delay_nonzero.add(selected);
                if (delay > 0 and delay <= 8)
                    tick_install = tick_install.add(selected);
            }

            const different_selector = one.sub(row.same_selector);
            const expected_selector = [2]S{
                set_pressed.mul(before_selector[0])
                    .add(tick_mcycle.mul(
                        tick_install.mul(row.before_pending[0]).add(
                            one.sub(tick_install).mul(before_selector[0]),
                        ),
                    ))
                    .add(write_p1.mul(
                    row.same_selector.mul(before_selector[0]).add(
                        different_selector.mul(row.write_selector[0]),
                    ),
                )),
                set_pressed.mul(before_selector[1])
                    .add(tick_mcycle.mul(
                        tick_install.mul(row.before_pending[1]).add(
                            one.sub(tick_install).mul(before_selector[1]),
                        ),
                    ))
                    .add(write_p1.mul(
                    row.same_selector.mul(before_selector[1]).add(
                        different_selector.mul(row.write_selector[1]),
                    ),
                )),
            };
            var expected_pressed: [8]S = undefined;
            for (&expected_pressed, row.before_pressed, row.action) |
                *expected,
                before,
                action,
            | {
                expected.* = set_pressed.mul(action)
                    .add(write_p1.add(tick_mcycle).mul(before));
            }
            const expected_pending = [2]S{
                set_pressed.add(tick_mcycle).mul(row.before_pending[0])
                    .add(write_p1.mul(
                    row.same_selector.mul(row.before_pending[0]).add(
                        different_selector.mul(requested_selector[0]),
                    ),
                )),
                set_pressed.add(tick_mcycle).mul(row.before_pending[1])
                    .add(write_p1.mul(
                    row.same_selector.mul(row.before_pending[1]).add(
                        different_selector.mul(requested_selector[1]),
                    ),
                )),
            };
            const expected_delay = set_pressed.mul(before_delay)
                .add(tick_mcycle.mul(tick_delay))
                .add(write_p1.mul(
                row.same_selector.mul(before_delay)
                    .add(different_selector.mul(row.write_delay)),
            ));
            const expected_delay_nonzero =
                set_pressed.mul(delay_nonzero)
                    .add(tick_mcycle.mul(tick_delay_nonzero))
                    .add(write_p1.mul(
                    row.same_selector.mul(delay_nonzero)
                        .add(
                        different_selector.mul(row.write_delay_nonzero),
                    ),
                ));

            for (row.after_pressed, expected_pressed) |actual, expected| {
                out[at] = actual.sub(expected);
                at += 1;
            }
            for (row.after_pending, expected_pending) |actual, expected| {
                out[at] = actual.sub(expected);
                at += 1;
            }
            out[at] = compose(row.after_delay).sub(expected_delay);
            at += 1;
            for (row.after_p1[4..6], expected_selector) |actual, expected| {
                out[at] = actual.sub(expected);
                at += 1;
            }

            const after_selector = [2]S{
                row.after_p1[4],
                row.after_p1[5],
            };
            const expected_after_hot = selectorHot(
                after_selector,
                is_active,
            );
            for (row.after_hot, expected_after_hot[0..3]) |
                actual,
                expected,
            | {
                out[at] = actual.sub(expected);
                at += 1;
            }
            const after_selector_hot = committedHot(
                row.after_hot,
                is_active,
            );
            const expected_lines = lineValues(
                after_selector_hot,
                row.after_pressed,
            );
            for (row.after_p1[0..4], expected_lines) |actual, expected| {
                out[at] = actual.sub(expected);
                at += 1;
            }
            out[at] = row.after_p1[6].sub(is_active);
            at += 1;
            out[at] = row.after_p1[7].sub(is_active);
            at += 1;

            out[at] = row.after_delay_nonzero.sub(
                expected_delay_nonzero,
            );
            at += 1;
            const expected_delay_zero = is_active.sub(
                row.after_delay_nonzero,
            );
            for (row.after_p1[4..6], row.after_pending) |selected, pending| {
                out[at] = expected_delay_zero.mul(selected.sub(pending));
                at += 1;
            }

            for (row.p1_read[0..4], row.after_p1[0..4]) |actual, expected| {
                out[at] = actual.sub(expected);
                at += 1;
            }
            for (row.p1_read[4..6], row.after_p1[4..6], row.after_pending) |
                actual,
                internal,
                pending,
            | {
                out[at] = actual.sub(
                    row.after_delay_nonzero.mul(pending).add(
                        expected_delay_zero.mul(internal),
                    ),
                );
                at += 1;
            }
            out[at] = row.p1_read[6].sub(is_active);
            at += 1;
            out[at] = row.p1_read[7].sub(is_active);
            at += 1;

            for (
                row.falling,
                row.before_p1[0..4],
                row.after_p1[0..4],
            ) |actual, before, after| {
                out[at] = actual.sub(before.mul(one.sub(after)));
                at += 1;
            }
            out[at] = row.edge_prefix[0].sub(
                booleanOr(row.falling[0], row.falling[1]),
            );
            at += 1;
            out[at] = row.edge_prefix[1].sub(
                booleanOr(row.edge_prefix[0], row.falling[2]),
            );
            at += 1;
            out[at] = row.interrupt_requested.sub(
                booleanOr(row.edge_prefix[1], row.falling[3]),
            );
            at += 1;

            std.debug.assert(at == out.len);
            return .{ .values = out };
        }

        pub fn evaluateChain(previous: Row, next: Row) ChainEvaluation {
            var out: [N_CHAIN_CONSTRAINTS]S = undefined;
            var at: usize = 0;
            for (previous.after_p1, next.before_p1) |after, before| {
                out[at] = after.sub(before);
                at += 1;
            }
            for (previous.after_pressed, next.before_pressed) |after, before| {
                out[at] = after.sub(before);
                at += 1;
            }
            for (previous.after_pending, next.before_pending) |after, before| {
                out[at] = after.sub(before);
                at += 1;
            }
            for (previous.after_delay, next.before_delay) |after, before| {
                out[at] = after.sub(before);
                at += 1;
            }
            std.debug.assert(at == out.len);
            return .{ .values = out };
        }

        fn bit(value: S) S {
            return value.mul(value.sub(S.one()));
        }

        fn q(value: usize) S {
            return S.fromBase(M31.fromU64(value));
        }

        fn compose(bits: anytype) S {
            var result = S.zero();
            for (bits, 0..) |value, index|
                result = result.add(
                    q(@as(usize, 1) << @intCast(index)).mul(value),
                );
            return result;
        }

        fn selectorHot(bits: [2]S, is_active: S) [4]S {
            const one = S.one();
            return .{
                is_active.sub(bits[0]).sub(bits[1])
                    .add(bits[0].mul(bits[1])),
                bits[0].mul(one.sub(bits[1])),
                one.sub(bits[0]).mul(bits[1]),
                bits[0].mul(bits[1]),
            };
        }

        fn committedHot(first_three: [3]S, is_active: S) [4]S {
            return .{
                first_three[0],
                first_three[1],
                first_three[2],
                is_active.sub(first_three[0])
                    .sub(first_three[1])
                    .sub(first_three[2]),
            };
        }

        fn booleanOr(left: S, right: S) S {
            return left.add(right).sub(left.mul(right));
        }

        fn lineValues(selected: [4]S, pressed: [8]S) [4]S {
            const one = S.one();
            var result: [4]S = undefined;
            inline for (0..4) |line| {
                const direction = if (line == 1)
                    one.sub(pressed[1].mul(one.sub(pressed[0])))
                else if (line == 3)
                    one.sub(pressed[3].mul(one.sub(pressed[2])))
                else
                    one.sub(pressed[line]);
                const button = one.sub(pressed[line + 4]);
                const both = one.sub(pressed[line])
                    .mul(one.sub(pressed[line + 4]));
                result[line] = selected[0].mul(both)
                    .add(selected[1].mul(button))
                    .add(selected[2].mul(direction))
                    .add(selected[3]);
            }
            return result;
        }
    };
}

pub const Shipped = Semantics(QM31);

pub fn columns(step: ValidatedStep) [N_MAIN_COLUMNS]M31 {
    const transition = step.transition;
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    const event_tag = std.meta.activeTag(transition.event);
    out[EVENT_OFFSET + @intFromEnum(event_tag)] = M31.one();
    setState(&out, BEFORE_P1_OFFSET, transition.before);
    const action_value: u8 = switch (transition.event) {
        .set_pressed => |pressed| pressed,
        .write_p1 => |value| value,
        .tick_mcycle => 0,
    };
    writeBits(out[ACTION_OFFSET..AFTER_P1_OFFSET], action_value);
    setState(&out, AFTER_P1_OFFSET, transition.after);
    writeBits(out[READ_OFFSET..EDGE_OFFSET], transition.p1_read);
    out[EDGE_OFFSET] = boolean(transition.interrupt_requested);
    out[DELAY_HOT_OFFSET + transition.before.switching_delay] = M31.one();
    setAuxiliaries(&out, transition, action_value);
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
    state: joypad.State,
) void {
    writeBits(out[offset .. offset + 8], state.p1);
    writeBits(out[offset + 8 .. offset + 16], state.pressed);
    writeBits(out[offset + 16 .. offset + 18], state.pending_selection);
    writeBits(out[offset + 18 .. offset + 24], state.switching_delay);
}

fn setAuxiliaries(
    out: *[N_MAIN_COLUMNS]M31,
    transition: joypad.Transition,
    action_value: u8,
) void {
    const before_selector: u2 = @truncate(transition.before.p1 >> 4);
    const requested_selector: u2 = @truncate(action_value >> 4);
    const base_selector = if (transition.before.switching_delay == 0)
        before_selector
    else
        transition.before.pending_selection;
    const next_delay = @max(
        transition.before.switching_delay,
        selectorDelay(base_selector, requested_selector),
    );
    const write_selector = if (next_delay == 0)
        requested_selector
    else
        requested_selector & base_selector;
    const after_selector: u2 = @truncate(transition.after.p1 >> 4);

    writeHot(out[BEFORE_HOT_OFFSET..REQUESTED_HOT_OFFSET], before_selector);
    writeHot(
        out[REQUESTED_HOT_OFFSET..SAME_SELECTOR_OFFSET],
        requested_selector,
    );
    out[SAME_SELECTOR_OFFSET] = boolean(
        before_selector == requested_selector,
    );
    writeBits(
        out[BASE_SELECTOR_OFFSET..BASE_HOT_OFFSET],
        base_selector,
    );
    writeHot(out[BASE_HOT_OFFSET..WRITE_SELECTOR_OFFSET], base_selector);
    writeBits(
        out[WRITE_SELECTOR_OFFSET..WRITE_DELAY_NONZERO_OFFSET],
        write_selector,
    );
    out[WRITE_DELAY_NONZERO_OFFSET] = boolean(next_delay != 0);
    writeHot(out[AFTER_HOT_OFFSET..AFTER_DELAY_NONZERO_OFFSET], after_selector);
    out[AFTER_DELAY_NONZERO_OFFSET] = boolean(
        transition.after.switching_delay != 0,
    );

    var edge = false;
    for (0..4) |line| {
        const falling =
            transition.before.p1 & (@as(u8, 1) << @intCast(line)) != 0 and
            transition.after.p1 & (@as(u8, 1) << @intCast(line)) == 0;
        out[FALLING_OFFSET + line] = boolean(falling);
        edge = edge or falling;
        if (line == 1)
            out[EDGE_PREFIX_OFFSET] = boolean(edge)
        else if (line == 2)
            out[EDGE_PREFIX_OFFSET + 1] = boolean(edge);
    }
    out[WRITE_DELAY_OFFSET] = M31.fromU64(next_delay);
}

fn writeHot(out: []M31, selection: u2) void {
    std.debug.assert(out.len == 3);
    if (selection < 3)
        out[selection] = M31.one();
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

fn selectorDelay(previous: usize, requested: usize) usize {
    const transition = previous | (requested << 2);
    return switch (transition) {
        0x4, 0x6, 0xc, 0xe => 48,
        0x8, 0x9, 0xd => 24,
        else => 0,
    };
}
