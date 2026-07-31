//! Direct scheduler-event constraints.
//!
//! This leaf classifies machine rows from IE/IF witness values. It does not
//! authenticate those values: a complete proof must add memory lookups for
//! 0xffff (IE) and 0xff0f (IF) before claiming scheduler soundness.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const machine = @import("../runner/machine.zig");

const N_EVENTS: usize = 4;
const N_INTERRUPTS: usize = 5;
const EVENT_OFFSET: usize = 0;
const INTERRUPT_OFFSET: usize = EVENT_OFFSET + N_EVENTS;
const IE_OFFSET: usize = INTERRUPT_OFFSET + N_INTERRUPTS;
const IF_OFFSET: usize = IE_OFFSET + N_INTERRUPTS;
const QUEUE_OFFSET: usize = IF_OFFSET + N_INTERRUPTS;
const QUEUE_NONZERO_OFFSET: usize = QUEUE_OFFSET + N_INTERRUPTS;
const QUEUE_INVERSE_OFFSET: usize = QUEUE_NONZERO_OFFSET + 1;
const POST_IF_OFFSET: usize = QUEUE_INVERSE_OFFSET + 1;
const POST_QUEUE_OFFSET: usize = POST_IF_OFFSET + N_INTERRUPTS;
const POST_QUEUE_NONZERO_OFFSET: usize = POST_QUEUE_OFFSET + N_INTERRUPTS;
const POST_QUEUE_INVERSE_OFFSET: usize = POST_QUEUE_NONZERO_OFFSET + 1;
const EFFECTIVE_IME_OFFSET: usize = POST_QUEUE_INVERSE_OFFSET + 1;
const BEFORE_IME_OFFSET: usize = EFFECTIVE_IME_OFFSET + 1;
const BEFORE_PENDING_OFFSET: usize = BEFORE_IME_OFFSET + 1;
const BEFORE_HALTED_OFFSET: usize = BEFORE_PENDING_OFFSET + 1;
const BEFORE_HALT_BUG_OFFSET: usize = BEFORE_HALTED_OFFSET + 1;
const AFTER_IME_OFFSET: usize = BEFORE_HALT_BUG_OFFSET + 1;
const AFTER_PENDING_OFFSET: usize = AFTER_IME_OFFSET + 1;
const AFTER_HALTED_OFFSET: usize = AFTER_PENDING_OFFSET + 1;
const AFTER_HALT_BUG_OFFSET: usize = AFTER_HALTED_OFFSET + 1;
const MCYCLE_OFFSET: usize = AFTER_HALT_BUG_OFFSET + 1;
const MCYCLE_LOW_ZERO_OFFSET: usize = MCYCLE_OFFSET + 3;
const MCYCLE_LOW_ONE_OFFSET: usize = MCYCLE_LOW_ZERO_OFFSET + 1;

pub const N_MAIN_COLUMNS: usize = MCYCLE_LOW_ONE_OFFSET + 1;
pub const N_CONSTRAINTS: usize = 149;

pub const ValidatedStep = struct {
    result: machine.StepResult,
    queue: u8,
    post_queue: u8,

    pub fn init(
        source: anytype,
    ) error{NotSchedulerStep}!ValidatedStep {
        const T = @TypeOf(source);
        const result: machine.StepResult = if (T == machine.StepResult)
            source
        else if (T == machine.CartridgeStepResult)
            source.schedulerResult()
        else
            @compileError("expected canonical scheduler result");
        const canonical = if (T == machine.StepResult)
            source.hasCanonicalShape()
        else
            source.hasCanonicalShape();
        if (!canonical or result.before.cpu.stopped or result.after.cpu.stopped)
            return error.NotSchedulerStep;

        const queue =
            result.before.interrupt_enable & result.before.interrupt_flags & 0x1f;
        const post_queue =
            result.before.interrupt_enable & result.after.interrupt_flags & 0x1f;
        if (result.event != expectedEvent(
            result.before.cpu.halted,
            result.before.cpu.ime,
            queue != 0,
            post_queue != 0,
        )) return error.NotSchedulerStep;

        return .{
            .result = result,
            .queue = queue,
            .post_queue = post_queue,
        };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            events: [N_EVENTS]S,
            interrupts: [N_INTERRUPTS]S,
            ie_bits: [N_INTERRUPTS]S,
            if_bits: [N_INTERRUPTS]S,
            queue_bits: [N_INTERRUPTS]S,
            queue_nonzero: S,
            queue_inverse: S,
            post_if_bits: [N_INTERRUPTS]S,
            post_queue_bits: [N_INTERRUPTS]S,
            post_queue_nonzero: S,
            post_queue_inverse: S,
            effective_ime: S,
            before_ime: S,
            before_pending: S,
            before_halted: S,
            before_halt_bug: S,
            after_ime: S,
            after_pending: S,
            after_halted: S,
            after_halt_bug: S,
            mcycle_bits: [3]S,
            mcycle_low_zero: S,
            mcycle_low_one: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .events = values[EVENT_OFFSET..INTERRUPT_OFFSET].*,
                    .interrupts = values[INTERRUPT_OFFSET..IE_OFFSET].*,
                    .ie_bits = values[IE_OFFSET..IF_OFFSET].*,
                    .if_bits = values[IF_OFFSET..QUEUE_OFFSET].*,
                    .queue_bits = values[QUEUE_OFFSET..QUEUE_NONZERO_OFFSET].*,
                    .queue_nonzero = values[QUEUE_NONZERO_OFFSET],
                    .queue_inverse = values[QUEUE_INVERSE_OFFSET],
                    .post_if_bits = values[POST_IF_OFFSET..POST_QUEUE_OFFSET].*,
                    .post_queue_bits = values[POST_QUEUE_OFFSET..POST_QUEUE_NONZERO_OFFSET].*,
                    .post_queue_nonzero = values[POST_QUEUE_NONZERO_OFFSET],
                    .post_queue_inverse = values[POST_QUEUE_INVERSE_OFFSET],
                    .effective_ime = values[EFFECTIVE_IME_OFFSET],
                    .before_ime = values[BEFORE_IME_OFFSET],
                    .before_pending = values[BEFORE_PENDING_OFFSET],
                    .before_halted = values[BEFORE_HALTED_OFFSET],
                    .before_halt_bug = values[BEFORE_HALT_BUG_OFFSET],
                    .after_ime = values[AFTER_IME_OFFSET],
                    .after_pending = values[AFTER_PENDING_OFFSET],
                    .after_halted = values[AFTER_HALTED_OFFSET],
                    .after_halt_bug = values[AFTER_HALT_BUG_OFFSET],
                    .mcycle_bits = values[MCYCLE_OFFSET..MCYCLE_LOW_ZERO_OFFSET].*,
                    .mcycle_low_zero = values[MCYCLE_LOW_ZERO_OFFSET],
                    .mcycle_low_one = values[MCYCLE_LOW_ONE_OFFSET],
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

        pub fn evaluate(row: Row, is_active: S) Evaluation {
            var out: [N_CONSTRAINTS]S = undefined;
            var at: usize = 0;
            const one = S.one();
            const instruction = event(row, .instruction);
            const idle = event(row, .halt_idle);
            const wake = event(row, .halt_wake);
            const service = event(row, .interrupt_service);

            out[at] = bit(is_active);
            at += 1;
            for (row.events ++ row.interrupts ++ row.ie_bits ++
                row.if_bits ++ row.queue_bits ++ row.post_if_bits ++
                row.post_queue_bits) |value|
            {
                out[at] = bit(value);
                at += 1;
            }
            for ([_]S{
                row.queue_nonzero,
                row.post_queue_nonzero,
                row.effective_ime,
                row.before_ime,
                row.before_pending,
                row.before_halted,
                row.before_halt_bug,
                row.after_ime,
                row.after_pending,
                row.after_halted,
                row.after_halt_bug,
            } ++ row.mcycle_bits) |value| {
                out[at] = bit(value);
                at += 1;
            }

            for (row.values) |value| {
                out[at] = one.sub(is_active).mul(value);
                at += 1;
            }

            for (row.queue_bits, row.ie_bits, row.if_bits) |queued, ie, flag| {
                out[at] = queued.sub(ie.mul(flag));
                at += 1;
            }
            const queue = compose(row.queue_bits);
            out[at] = queue.mul(row.queue_inverse).sub(row.queue_nonzero);
            at += 1;
            out[at] = queue.mul(one.sub(row.queue_nonzero));
            at += 1;
            out[at] = one.sub(row.queue_nonzero).mul(row.queue_inverse);
            at += 1;
            for (
                row.post_queue_bits,
                row.ie_bits,
                row.post_if_bits,
            ) |queued, ie, flag| {
                out[at] = queued.sub(ie.mul(flag));
                at += 1;
            }
            const post_queue = compose(row.post_queue_bits);
            out[at] = post_queue.mul(row.post_queue_inverse)
                .sub(row.post_queue_nonzero);
            at += 1;
            out[at] = post_queue.mul(one.sub(row.post_queue_nonzero));
            at += 1;
            out[at] = one.sub(row.post_queue_nonzero)
                .mul(row.post_queue_inverse);
            at += 1;
            out[at] = row.effective_ime.sub(row.before_ime);
            at += 1;

            out[at] = service.sub(
                is_active.mul(row.effective_ime).mul(row.queue_nonzero),
            );
            at += 1;
            out[at] = idle.sub(
                row.before_halted.mul(one.sub(service))
                    .mul(one.sub(row.post_queue_nonzero)),
            );
            at += 1;
            out[at] = wake.sub(is_active.mul(row.before_halted))
                .add(idle)
                .add(row.before_halted.mul(service));
            at += 1;
            out[at] = instruction.sub(
                is_active.sub(service).sub(idle).sub(wake),
            );
            at += 1;

            var selected_interrupt = S.zero();
            for (row.interrupts) |selector|
                selected_interrupt = selected_interrupt.add(selector);
            out[at] = selected_interrupt.sub(service);
            at += 1;
            for (row.interrupts, row.queue_bits, 0..) |selector, queued, index| {
                out[at] = selector.mul(one.sub(queued));
                at += 1;
                var lower = S.zero();
                for (0..index) |candidate|
                    lower = lower.add(row.queue_bits[candidate]);
                out[at] = selector.mul(lower);
                at += 1;
            }

            const halt_transition = idle.add(wake);
            const promoted_ime = row.before_ime.add(row.before_pending)
                .sub(row.before_ime.mul(row.before_pending));
            out[at] = halt_transition.mul(row.after_ime.sub(promoted_ime));
            at += 1;
            out[at] = halt_transition.mul(row.after_pending);
            at += 1;
            out[at] = halt_transition.mul(row.after_halted).sub(idle);
            at += 1;
            out[at] = service.mul(row.after_ime);
            at += 1;
            out[at] = service.mul(row.after_pending);
            at += 1;
            out[at] = service.mul(row.after_halted);
            at += 1;
            const not_instruction = idle.add(wake).add(service);
            out[at] = not_instruction.mul(row.before_halt_bug);
            at += 1;
            out[at] = not_instruction.mul(row.after_halt_bug);
            at += 1;
            out[at] = row.before_halt_bug.mul(row.before_halted);
            at += 1;
            out[at] = row.after_halt_bug.mul(row.after_halted);
            at += 1;

            const mcycles = compose(row.mcycle_bits);
            out[at] = halt_transition.mul(mcycles.sub(one));
            at += 1;
            out[at] = service.mul(
                mcycles.sub(q(5)).sub(row.before_halted),
            );
            at += 1;
            out[at] = row.mcycle_low_zero.sub(
                is_active.sub(row.mcycle_bits[0])
                    .mul(is_active.sub(row.mcycle_bits[1])),
            );
            at += 1;
            out[at] = row.mcycle_low_one.sub(
                row.mcycle_bits[0].mul(row.mcycle_bits[1]),
            );
            at += 1;
            out[at] = instruction.mul(row.mcycle_low_zero)
                .mul(one.sub(row.mcycle_bits[2]));
            at += 1;
            out[at] = instruction.mul(row.mcycle_low_one)
                .mul(row.mcycle_bits[2]);
            at += 1;

            std.debug.assert(at == out.len);
            return .{ .values = out };
        }

        fn event(row: Row, selected: machine.SchedulerEvent) S {
            return row.events[@intFromEnum(selected)];
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
    const result = step.result;
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    out[EVENT_OFFSET + @intFromEnum(result.event)] = M31.one();
    if (result.event == .interrupt_service)
        out[INTERRUPT_OFFSET + @ctz(step.queue)] = M31.one();
    writeBits(out[IE_OFFSET..IF_OFFSET], result.before.interrupt_enable);
    writeBits(out[IF_OFFSET..QUEUE_OFFSET], result.before.interrupt_flags);
    writeBits(out[QUEUE_OFFSET..QUEUE_NONZERO_OFFSET], step.queue);
    if (step.queue != 0) {
        out[QUEUE_NONZERO_OFFSET] = M31.one();
        out[QUEUE_INVERSE_OFFSET] =
            M31.fromCanonical(step.queue).inv() catch unreachable;
    }
    writeBits(
        out[POST_IF_OFFSET..POST_QUEUE_OFFSET],
        result.after.interrupt_flags,
    );
    writeBits(
        out[POST_QUEUE_OFFSET..POST_QUEUE_NONZERO_OFFSET],
        step.post_queue,
    );
    if (step.post_queue != 0) {
        out[POST_QUEUE_NONZERO_OFFSET] = M31.one();
        out[POST_QUEUE_INVERSE_OFFSET] =
            M31.fromCanonical(step.post_queue).inv() catch unreachable;
    }
    out[EFFECTIVE_IME_OFFSET] = boolean(result.before.cpu.ime);
    out[BEFORE_IME_OFFSET] = boolean(result.before.cpu.ime);
    out[BEFORE_PENDING_OFFSET] =
        boolean(result.before.cpu.ime_enable_pending);
    out[BEFORE_HALTED_OFFSET] = boolean(result.before.cpu.halted);
    out[BEFORE_HALT_BUG_OFFSET] = boolean(result.before.halt_bug);
    out[AFTER_IME_OFFSET] = boolean(result.after.cpu.ime);
    out[AFTER_PENDING_OFFSET] =
        boolean(result.after.cpu.ime_enable_pending);
    out[AFTER_HALTED_OFFSET] = boolean(result.after.cpu.halted);
    out[AFTER_HALT_BUG_OFFSET] = boolean(result.after.halt_bug);
    writeBits(out[MCYCLE_OFFSET..MCYCLE_LOW_ZERO_OFFSET], result.m_cycles);
    const low_bits = result.m_cycles & 0x3;
    out[MCYCLE_LOW_ZERO_OFFSET] = boolean(low_bits == 0);
    out[MCYCLE_LOW_ONE_OFFSET] = boolean(low_bits == 3);
    return out;
}

pub fn evaluate(
    values: [N_MAIN_COLUMNS]M31,
    is_active: bool,
) !Shipped.Evaluation {
    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, values) |*value, source|
        value.* = QM31.fromBase(source);
    return Shipped.evaluate(
        try Shipped.Row.fromColumns(&lifted),
        QM31.fromBase(boolean(is_active)),
    );
}

fn expectedEvent(
    halted: bool,
    effective_ime: bool,
    queued_before: bool,
    queued_after: bool,
) machine.SchedulerEvent {
    if (halted) {
        if (effective_ime and queued_before)
            return .interrupt_service;
        if (!queued_after) return .halt_idle;
        return .halt_wake;
    }
    return if (effective_ime and queued_before)
        .interrupt_service
    else
        .instruction;
}

fn writeBits(output: []M31, value: anytype) void {
    for (output, 0..) |*bit_value, index|
        bit_value.* = M31.fromCanonical((value >> @intCast(index)) & 1);
}

fn boolean(value: anytype) M31 {
    return M31.fromCanonical(@intFromBool(value));
}
