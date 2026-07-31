//! Pinned-SameBoy interrupt-service constraints.
//!
//! Bus cycles and logical IE/IF operations are separate; memory and mapper
//! authentication remain environment lookups.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const machine = @import("../runner/machine.zig");
const runner = @import("../runner/mod.zig");
const N_INTERRUPTS: usize = 5;
const SELECTED_OFFSET: usize = 0;
const ACK_SELECTED_OFFSET: usize = SELECTED_OFFSET + N_INTERRUPTS;
const IE_BEFORE_OFFSET: usize = ACK_SELECTED_OFFSET + N_INTERRUPTS;
const IE_SAMPLE_OFFSET: usize = IE_BEFORE_OFFSET + 8;
const IE_AFTER_OFFSET: usize = IE_SAMPLE_OFFSET + 8;
const IF_BEFORE_HIGH_OFFSET: usize = IE_AFTER_OFFSET + 8;
const IF_SAMPLE_OFFSET: usize = IF_BEFORE_HIGH_OFFSET + 3;
const IF_AFTER_LOW_OFFSET: usize = IF_SAMPLE_OFFSET + N_INTERRUPTS;
const ACK_BEFORE_OFFSET: usize = IF_AFTER_LOW_OFFSET + N_INTERRUPTS;
const ACK_AFTER_OFFSET: usize = ACK_BEFORE_OFFSET + 8;
const IF_AFTER_OFFSET: usize = ACK_AFTER_OFFSET + 8;
const PC_OFFSET: usize = IF_AFTER_OFFSET + 8;
const SP_OFFSET: usize = PC_OFFSET + 16;
const SP_BORROW_OFFSET: usize = SP_OFFSET + 16;
const IE_CYCLE_OFFSET: usize = SP_BORROW_OFFSET + 2;
const IF_CYCLE_OFFSET: usize = IE_CYCLE_OFFSET + 3;
const ACK_CYCLE_OFFSET: usize = IF_CYCLE_OFFSET + 3;
const BEFORE_HALT_BUG_OFFSET: usize = ACK_CYCLE_OFFSET + 3;
const AFTER_HALT_BUG_OFFSET: usize = BEFORE_HALT_BUG_OFFSET + 1;
const HIGH_IS_IE_OFFSET: usize = AFTER_HALT_BUG_OFFSET + 1;
const HIGH_IE_INVERSE_OFFSET: usize = HIGH_IS_IE_OFFSET + 1;
const LOW_IS_IE_OFFSET: usize = HIGH_IE_INVERSE_OFFSET + 1;
const LOW_IE_INVERSE_OFFSET: usize = LOW_IS_IE_OFFSET + 1;
const LOW_IS_IF_OFFSET: usize = LOW_IE_INVERSE_OFFSET + 1;
const LOW_IF_INVERSE_OFFSET: usize = LOW_IS_IF_OFFSET + 1;
pub const N_MAIN_COLUMNS: usize = LOW_IF_INVERSE_OFFSET + 1;
pub const N_CONSTRAINTS: usize = 390;
pub const N_BOUND_CONSTRAINTS: usize = N_CONSTRAINTS;
pub const ValidationError = error{
    NotInterruptService,
    FlatServiceTraceUnavailable,
};
pub const ValidatedStep = struct {
    result: machine.CartridgeStepResult,

    pub fn init(source: anytype) ValidationError!ValidatedStep {
        const T = @TypeOf(source);
        if (T == machine.StepResult) {
            if (source.event == .interrupt_service)
                return error.FlatServiceTraceUnavailable;
            return error.NotInterruptService;
        }
        if (T != machine.CartridgeStepResult)
            @compileError("expected cartridge scheduler result");
        const result: machine.CartridgeStepResult = source;
        if (!result.hasCanonicalShape() or
            result.event != .interrupt_service or
            result.instruction != null or
            result.service.count != result.m_cycles or
            result.before.cpu.stopped or result.after.cpu.stopped or
            !preservedRegisters(result.before.cpu, result.after.cpu))
            return error.NotInterruptService;
        return .{ .result = result };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            selected: [N_INTERRUPTS]S,
            ack_selected: [N_INTERRUPTS]S,
            ie_before: [8]S,
            ie_sample: [8]S,
            ie_after: [8]S,
            if_before_high: [3]S,
            if_sample: [N_INTERRUPTS]S,
            if_after_low: [N_INTERRUPTS]S,
            ack_before: [8]S,
            ack_after: [8]S,
            if_after: [8]S,
            pc_bits: [16]S,
            sp_bits: [16]S,
            sp_borrows: [2]S,
            ie_cycle_bits: [3]S,
            if_cycle_bits: [3]S,
            ack_cycle_bits: [3]S,
            before_halt_bug: S,
            after_halt_bug: S,
            high_is_ie: S,
            high_ie_inverse: S,
            low_is_ie: S,
            low_ie_inverse: S,
            low_is_if: S,
            low_if_inverse: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .selected = values[SELECTED_OFFSET..ACK_SELECTED_OFFSET].*,
                    .ack_selected = values[ACK_SELECTED_OFFSET..IE_BEFORE_OFFSET].*,
                    .ie_before = values[IE_BEFORE_OFFSET..IE_SAMPLE_OFFSET].*,
                    .ie_sample = values[IE_SAMPLE_OFFSET..IE_AFTER_OFFSET].*,
                    .ie_after = values[IE_AFTER_OFFSET..IF_BEFORE_HIGH_OFFSET].*,
                    .if_before_high = values[IF_BEFORE_HIGH_OFFSET..IF_SAMPLE_OFFSET].*,
                    .if_sample = values[IF_SAMPLE_OFFSET..IF_AFTER_LOW_OFFSET].*,
                    .if_after_low = values[IF_AFTER_LOW_OFFSET..ACK_BEFORE_OFFSET].*,
                    .ack_before = values[ACK_BEFORE_OFFSET..ACK_AFTER_OFFSET].*,
                    .ack_after = values[ACK_AFTER_OFFSET..IF_AFTER_OFFSET].*,
                    .if_after = values[IF_AFTER_OFFSET..PC_OFFSET].*,
                    .pc_bits = values[PC_OFFSET..SP_OFFSET].*,
                    .sp_bits = values[SP_OFFSET..SP_BORROW_OFFSET].*,
                    .sp_borrows = values[SP_BORROW_OFFSET..IE_CYCLE_OFFSET].*,
                    .ie_cycle_bits = values[IE_CYCLE_OFFSET..IF_CYCLE_OFFSET].*,
                    .if_cycle_bits = values[IF_CYCLE_OFFSET..ACK_CYCLE_OFFSET].*,
                    .ack_cycle_bits = values[ACK_CYCLE_OFFSET..BEFORE_HALT_BUG_OFFSET].*,
                    .before_halt_bug = values[BEFORE_HALT_BUG_OFFSET],
                    .after_halt_bug = values[AFTER_HALT_BUG_OFFSET],
                    .high_is_ie = values[HIGH_IS_IE_OFFSET],
                    .high_ie_inverse = values[HIGH_IE_INVERSE_OFFSET],
                    .low_is_ie = values[LOW_IS_IE_OFFSET],
                    .low_ie_inverse = values[LOW_IE_INVERSE_OFFSET],
                    .low_is_if = values[LOW_IS_IF_OFFSET],
                    .low_if_inverse = values[LOW_IF_INVERSE_OFFSET],
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
        pub const BoundEvaluation = Evaluation;
        pub fn evaluateBound(
            row: Row,
            execution_row: execution.Row(S),
            is_active: S,
        ) BoundEvaluation {
            var out: [N_CONSTRAINTS]S = undefined;
            var at: usize = 0;
            const one = S.one();
            const inactive = one.sub(is_active);
            for (row.values, 0..) |value, index| {
                if (index != HIGH_IE_INVERSE_OFFSET and
                    index != LOW_IE_INVERSE_OFFSET and
                    index != LOW_IF_INVERSE_OFFSET)
                {
                    out[at] = bit(value);
                    at += 1;
                }
            }
            for (row.values) |value| {
                out[at] = inactive.mul(value);
                at += 1;
            }
            var selected = S.zero();
            for (row.selected) |value| selected = selected.add(value);
            for (row.selected, row.ack_selected) |choice, ack_choice| {
                out[at] = ack_choice.sub(choice);
                at += 1;
            }
            for (row.selected, 0..) |choice, index| {
                const queued =
                    row.ie_sample[index].mul(row.if_sample[index]);
                out[at] = choice.mul(queued.sub(one));
                at += 1;
                var lower = S.zero();
                for (0..index) |candidate|
                    lower = lower.add(
                        row.ie_sample[candidate].mul(
                            row.if_sample[candidate],
                        ),
                    );
                out[at] = choice.mul(lower);
                at += 1;
            }
            for (row.ie_sample[0..N_INTERRUPTS], row.if_sample) |ie, flag| {
                out[at] = is_active.sub(selected).mul(ie).mul(flag);
                at += 1;
            }
            const pc = compose(row.pc_bits);
            const sp = compose(row.sp_bits);
            const sp1 = sp.sub(one).add(q(65536).mul(row.sp_borrows[0]));
            const sp2 = sp.sub(q(2)).add(q(65536).mul(row.sp_borrows[1]));
            const pc_low = compose(row.pc_bits[0..8].*);
            const pc_high = compose(row.pc_bits[8..16].*);
            const before = execution_row.before;
            const after = execution_row.after;
            const halted = before.at(.halted);
            out[at] = is_active.mul(before.at(.pc).sub(pc));
            at += 1;
            out[at] = is_active.mul(before.at(.sp).sub(sp));
            at += 1;
            out[at] = is_active.mul(before.at(.ime).sub(one));
            at += 1;
            out[at] = is_active.mul(before.at(.stopped));
            at += 1;
            out[at] = is_active.mul(bit(before.at(.halted)));
            at += 1;
            out[at] = is_active.mul(bit(before.at(.ime_enable_pending)));
            at += 1;
            out[at] = is_active.mul(after.at(.ime));
            at += 1;
            out[at] = is_active.mul(after.at(.ime_enable_pending));
            at += 1;
            out[at] = is_active.mul(after.at(.halted));
            at += 1;
            out[at] = is_active.mul(after.at(.stopped));
            at += 1;
            const target = selectedValue(row.selected);
            out[at] = is_active.mul(after.at(.pc).sub(target));
            at += 1;
            out[at] = is_active.mul(after.at(.sp).sub(sp2));
            at += 1;
            for ([_]execution.StateIndex{
                .a, .b, .c, .d, .e, .f, .h, .l,
            }) |field| {
                out[at] = is_active.mul(after.at(field).sub(before.at(field)));
                at += 1;
            }
            out[at] = is_active.mul(row.before_halt_bug);
            at += 1;
            out[at] = is_active.mul(row.after_halt_bug);
            at += 1;
            out[at] = is_active.mul(
                compose(row.ie_cycle_bits).sub(q(3)).sub(halted),
            );
            at += 1;
            out[at] = is_active.mul(
                compose(row.if_cycle_bits).sub(q(4)).sub(halted),
            );
            at += 1;
            out[at] = compose(row.ack_cycle_bits).sub(
                selected.mul(q(4).add(halted)),
            );
            at += 1;

            aliasConstraints(
                S,
                &out,
                &at,
                sp1.sub(q(0xffff)),
                row.high_is_ie,
                row.high_ie_inverse,
                is_active,
            );
            aliasConstraints(
                S,
                &out,
                &at,
                sp2.sub(q(0xffff)),
                row.low_is_ie,
                row.low_ie_inverse,
                is_active,
            );
            aliasConstraints(
                S,
                &out,
                &at,
                sp2.sub(q(0xff0f)),
                row.low_is_if,
                row.low_if_inverse,
                is_active,
            );

            for (
                row.ie_before,
                row.ie_sample,
                row.ie_after,
                row.pc_bits[8..16],
                row.pc_bits[0..8],
            ) |ie_before, ie_sample, ie_after, high_bit, low_bit| {
                const expected_sample = row.high_is_ie.mul(high_bit)
                    .add(one.sub(row.high_is_ie).mul(ie_before));
                out[at] = is_active.mul(ie_sample.sub(expected_sample));
                at += 1;
                const expected_after = row.low_is_ie.mul(low_bit)
                    .add(one.sub(row.low_is_ie).mul(ie_sample));
                out[at] = is_active.mul(ie_after.sub(expected_after));
                at += 1;
            }

            for (
                row.if_sample,
                row.if_after_low,
                row.pc_bits[0..N_INTERRUPTS],
            ) |sample, after_low, pc_bit| {
                const expected = row.low_is_if.mul(pc_bit)
                    .add(one.sub(row.low_is_if).mul(sample));
                out[at] = is_active.mul(after_low.sub(expected));
                at += 1;
            }
            for (row.ack_before, row.ack_after, 0..) |
                ack_before,
                ack_after,
                index,
            | {
                out[at] = is_active.sub(selected).mul(ack_before);
                at += 1;
                out[at] = is_active.sub(selected).mul(ack_after);
                at += 1;
                const clear = if (index < N_INTERRUPTS)
                    row.selected[index]
                else
                    S.zero();
                out[at] = selected.mul(
                    ack_after.sub(ack_before.mul(one.sub(clear))),
                );
                at += 1;
            }
            for (
                row.if_after_low,
                row.ack_before[0..N_INTERRUPTS],
            ) |after_low, ack_before| {
                out[at] = after_low.mul(selected.sub(ack_before));
                at += 1;
            }
            for (
                row.if_before_high,
                row.ack_before[N_INTERRUPTS..8],
                row.pc_bits[N_INTERRUPTS..8],
            ) |before_high, ack_before, pc_bit| {
                const expected = row.low_is_if.mul(pc_bit)
                    .add(one.sub(row.low_is_if).mul(before_high));
                out[at] = ack_before.sub(selected.mul(expected));
                at += 1;
            }
            for (row.if_after, 0..) |final_flag, index| {
                if (index < N_INTERRUPTS) {
                    const base = selected.mul(row.ack_after[index]).add(
                        is_active.sub(selected).mul(row.if_after_low[index]),
                    );
                    out[at] = base.mul(is_active.sub(final_flag));
                } else {
                    const before_high =
                        row.if_before_high[index - N_INTERRUPTS];
                    const expected = row.low_is_if.mul(row.pc_bits[index])
                        .add(one.sub(row.low_is_if).mul(before_high));
                    out[at] = is_active.mul(final_flag.sub(expected));
                }
                at += 1;
            }

            bindBus(
                S,
                &out,
                &at,
                execution_row,
                is_active,
                halted,
                pc,
                sp1,
                sp2,
                pc_high,
                pc_low,
            );
            out[at] = is_active.mul(execution_row.branch_taken);
            at += 1;
            std.debug.assert(at == out.len);
            return .{ .values = out };
        }

        fn bit(value: S) S {
            return value.mul(value.sub(S.one()));
        }

        fn q(value: u64) S {
            return S.fromBase(M31.fromU64(value));
        }

        fn compose(bits: anytype) S {
            var value = S.zero();
            for (bits, 0..) |bit_value, index|
                value = value.add(
                    q(@as(u64, 1) << @intCast(index)).mul(bit_value),
                );
            return value;
        }

        fn selectedValue(selected: [N_INTERRUPTS]S) S {
            var value = S.zero();
            for (selected, 0..) |choice, index|
                value = value.add(q(0x40 + 8 * index).mul(choice));
            return value;
        }
    };
}

fn aliasConstraints(
    comptime S: type,
    out: *[N_CONSTRAINTS]S,
    at: *usize,
    delta: S,
    is_alias: S,
    inverse: S,
    is_active: S,
) void {
    out[at.*] = delta.mul(is_alias);
    at.* += 1;
    out[at.*] = delta.mul(inverse).sub(is_active.sub(is_alias));
    at.* += 1;
}

fn bindBus(
    comptime S: type,
    out: *[N_CONSTRAINTS]S,
    at: *usize,
    row: execution.Row(S),
    active: S,
    halted: S,
    pc: S,
    sp1: S,
    sp2: S,
    pc_high: S,
    pc_low: S,
) void {
    const one = S.one();
    const running = active.sub(halted);
    const expected_active = [_]S{
        active, active, active, active, active, halted,
    };
    const expected_read = [_]S{
        running, halted, S.zero(), S.zero(), S.zero(), S.zero(),
    };
    const expected_write = [_]S{
        S.zero(), S.zero(), S.zero(), running, active, halted,
    };
    const expected_address = [_]S{
        running.mul(pc),
        halted.mul(pc),
        S.zero(),
        running.mul(sp1),
        running.mul(sp2).add(halted.mul(sp1)),
        halted.mul(sp2),
    };
    const expected_value = [_]S{
        S.zero(),
        S.zero(),
        S.zero(),
        running.mul(pc_high),
        running.mul(pc_low).add(halted.mul(pc_high)),
        halted.mul(pc_low),
    };
    for (row.bus, 0..) |bus, index| {
        out[at.*] = active.mul(bus.active.sub(expected_active[index]));
        at.* += 1;
        out[at.*] = active.mul(bus.read.sub(expected_read[index]));
        at.* += 1;
        out[at.*] = active.mul(bus.write.sub(expected_write[index]));
        at.* += 1;
        out[at.*] = active.mul(bus.program);
        at.* += 1;
        out[at.*] = active.mul(bus.address.sub(expected_address[index]));
        at.* += 1;
        const value_constraint = if (index == 0)
            halted.mul(bus.value)
        else if (index == 1)
            one.sub(halted).mul(bus.value)
        else
            bus.value.sub(expected_value[index]);
        out[at.*] = active.mul(value_constraint);
        at.* += 1;
    }
}

pub const Shipped = Semantics(QM31);

pub fn columns(step: ValidatedStep) [N_MAIN_COLUMNS]M31 {
    const result = step.result;
    const service = result.service;
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    if (result.interrupt_index) |index| {
        out[SELECTED_OFFSET + index] = M31.one();
        out[ACK_SELECTED_OFFSET + service.acknowledgement.?.index] = M31.one();
    }
    writeBits(
        out[IE_BEFORE_OFFSET..IE_SAMPLE_OFFSET],
        result.before.interrupt_enable,
    );
    writeBits(
        out[IE_SAMPLE_OFFSET..IE_AFTER_OFFSET],
        service.ie_resample.?.value,
    );
    writeBits(
        out[IE_AFTER_OFFSET..IF_BEFORE_HIGH_OFFSET],
        result.after.interrupt_enable,
    );
    writeBits(
        out[IF_BEFORE_HIGH_OFFSET..IF_SAMPLE_OFFSET],
        result.before.interrupt_flags >> 5,
    );
    writeBits(
        out[IF_SAMPLE_OFFSET..IF_AFTER_LOW_OFFSET],
        service.if_resample.?.value,
    );
    const low = result.before.cpu.sp -% 2;
    const after_low = if (low == 0xff0f)
        @as(u8, @truncate(result.before.cpu.pc))
    else
        service.if_resample.?.value;
    writeBits(
        out[IF_AFTER_LOW_OFFSET..ACK_BEFORE_OFFSET],
        after_low,
    );
    if (service.acknowledgement) |ack| {
        writeBits(out[ACK_BEFORE_OFFSET..ACK_AFTER_OFFSET], ack.before);
        writeBits(out[ACK_AFTER_OFFSET..IF_AFTER_OFFSET], ack.after);
        writeBits(
            out[ACK_CYCLE_OFFSET..BEFORE_HALT_BUG_OFFSET],
            ack.during_cycle,
        );
    }
    writeBits(
        out[IF_AFTER_OFFSET..PC_OFFSET],
        result.after.interrupt_flags,
    );
    writeBits(out[PC_OFFSET..SP_OFFSET], result.before.cpu.pc);
    writeBits(out[SP_OFFSET..SP_BORROW_OFFSET], result.before.cpu.sp);
    out[SP_BORROW_OFFSET] =
        boolean(result.before.cpu.sp == 0);
    out[SP_BORROW_OFFSET + 1] =
        boolean(result.before.cpu.sp < 2);
    writeBits(
        out[IE_CYCLE_OFFSET..IF_CYCLE_OFFSET],
        service.ie_resample.?.after_cycle,
    );
    writeBits(
        out[IF_CYCLE_OFFSET..ACK_CYCLE_OFFSET],
        service.if_resample.?.after_cycle,
    );
    out[BEFORE_HALT_BUG_OFFSET] = boolean(result.before.halt_bug);
    out[AFTER_HALT_BUG_OFFSET] = boolean(result.after.halt_bug);
    writeAlias(
        &out,
        HIGH_IS_IE_OFFSET,
        HIGH_IE_INVERSE_OFFSET,
        result.before.cpu.sp -% 1,
        0xffff,
    );
    writeAlias(
        &out,
        LOW_IS_IE_OFFSET,
        LOW_IE_INVERSE_OFFSET,
        low,
        0xffff,
    );
    writeAlias(
        &out,
        LOW_IS_IF_OFFSET,
        LOW_IF_INVERSE_OFFSET,
        low,
        0xff0f,
    );
    return out;
}

pub fn executionColumns(
    step: ValidatedStep,
    mcycle_before: u32,
) error{ExecutionClockOverflow}![execution.N_MAIN_COLUMNS]M31 {
    const result = step.result;
    const mcycle_after = std.math.add(
        u32,
        mcycle_before,
        result.m_cycles,
    ) catch return error.ExecutionClockOverflow;
    var out = [_]M31{M31.zero()} ** execution.N_MAIN_COLUMNS;
    const before = execution.stateFromCpu(M31, result.before.cpu);
    const after = execution.stateFromCpu(M31, result.after.cpu);
    @memcpy(out[0..execution.N_STATE_COLUMNS], &before.values);
    @memcpy(
        out[execution.N_STATE_COLUMNS .. 2 * execution.N_STATE_COLUMNS],
        &after.values,
    );
    var offset: usize = 2 * execution.N_STATE_COLUMNS;
    for (result.service.activeCycles()) |cycle| {
        out[offset + 2] = M31.one();
        if (cycle.access) |access| {
            out[offset] = M31.fromCanonical(access.logical_address);
            out[offset + 1] = M31.fromCanonical(access.value);
            out[offset + 3] = boolean(access.action == .read);
            out[offset + 4] = boolean(access.action == .write);
        }
        offset += execution.N_BUS_COLUMNS;
    }
    offset = 2 * execution.N_STATE_COLUMNS +
        execution.N_BUS_CYCLES * execution.N_BUS_COLUMNS;
    out[offset] = M31.fromCanonical(mcycle_before);
    out[offset + 1] = M31.fromCanonical(mcycle_after);
    return out;
}

pub fn evaluateBound(
    values: [N_MAIN_COLUMNS]M31,
    execution_values: [execution.N_MAIN_COLUMNS]M31,
    is_active: bool,
) !Shipped.BoundEvaluation {
    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, values) |*value, source|
        value.* = QM31.fromBase(source);
    for (&machine_values, execution_values) |*value, source|
        value.* = QM31.fromBase(source);
    return Shipped.evaluateBound(
        try Shipped.Row.fromColumns(&lifted),
        try execution.Row(QM31).fromColumns(&machine_values),
        QM31.fromBase(boolean(is_active)),
    );
}

fn writeBits(output: []M31, value: anytype) void {
    for (output, 0..) |*bit_value, index|
        bit_value.* = M31.fromCanonical((value >> @intCast(index)) & 1);
}

fn writeAlias(
    out: *[N_MAIN_COLUMNS]M31,
    flag_offset: usize,
    inverse_offset: usize,
    address: u16,
    target: u16,
) void {
    const delta =
        M31.fromCanonical(address).sub(M31.fromCanonical(target));
    if (address == target) {
        out[flag_offset] = M31.one();
    } else {
        out[inverse_offset] = delta.inv() catch unreachable;
    }
}

fn boolean(value: anytype) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

fn preservedRegisters(before: runner.Cpu, after: runner.Cpu) bool {
    return before.a == after.a and before.b == after.b and
        before.c == after.c and before.d == after.d and
        before.e == after.e and before.f == after.f and
        before.h == after.h and before.l == after.l;
}

test "service AIR accepts selected cancellation reprioritization and HALT" {
    for ([_]machine.CartridgeStepResult{
        testService(0x2345, 0xc102, 1, 1, false),
        testService(0, 0, 1, 1, false),
        testService(0x0200, 0, 1, 3, false),
        testService(0x2345, 0xc102, 1, 1, true),
    }) |result| {
        const validated = try ValidatedStep.init(result);
        const main = columns(validated);
        const machine_columns = try executionColumns(validated, 9);
        try std.testing.expect(
            (try evaluateBound(main, machine_columns, true)).allZero(),
        );
    }
}

test "service AIR rejects bus sample acknowledgement index and state mutations" {
    const result = testService(0x0200, 0, 1, 3, false);
    const validated = try ValidatedStep.init(result);
    const honest = columns(validated);
    const honest_machine = try executionColumns(validated, 9);

    var forged_machine = honest_machine;
    const bus = 2 * execution.N_STATE_COLUMNS;
    forged_machine[bus + 2 * execution.N_BUS_COLUMNS + 3] = M31.one();
    try expectRejected(honest, forged_machine);
    forged_machine = honest_machine;
    forged_machine[bus + 3 * execution.N_BUS_COLUMNS] =
        M31.fromCanonical(0xfffe);
    try expectRejected(honest, forged_machine);
    forged_machine = honest_machine;
    forged_machine[
        execution.N_STATE_COLUMNS +
            @intFromEnum(execution.StateIndex.pc)
    ] = M31.fromCanonical(0x40);
    try expectRejected(honest, forged_machine);

    var forged = honest;
    forged[IE_SAMPLE_OFFSET + 1] = M31.zero();
    try expectRejected(forged, honest_machine);
    forged = honest;
    forged[ACK_AFTER_OFFSET + 1] = M31.one();
    try expectRejected(forged, honest_machine);
    forged = honest;
    forged[SELECTED_OFFSET + 1] = M31.zero();
    forged[SELECTED_OFFSET] = M31.one();
    try expectRejected(forged, honest_machine);
    forged = honest;
    forged[IF_CYCLE_OFFSET] = M31.one();
    try expectRejected(forged, honest_machine);
}

test "service AIR rejects active and inactive vacuity" {
    const zero = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    const result = testService(0x2345, 0xc102, 1, 1, false);
    const validated = try ValidatedStep.init(result);
    const machine_columns = try executionColumns(validated, 0);
    try expectRejected(zero, machine_columns);

    var dirty = zero;
    dirty[IE_BEFORE_OFFSET] = M31.one();
    try std.testing.expect(
        !(try evaluateBound(dirty, machine_columns, false)).allZero(),
    );
}

fn expectRejected(
    main: [N_MAIN_COLUMNS]M31,
    machine_columns: [execution.N_MAIN_COLUMNS]M31,
) !void {
    try std.testing.expect(
        !(try evaluateBound(main, machine_columns, true)).allZero(),
    );
}

fn testService(
    pc: u16,
    sp: u16,
    ie: u8,
    interrupt_flags: u8,
    halted: bool,
) machine.CartridgeStepResult {
    const high = sp -% 1;
    const low = sp -% 2;
    const high_value: u8 = @truncate(pc >> 8);
    const low_value: u8 = @truncate(pc);
    const ie_sample = if (high == 0xffff) high_value else ie;
    const ie_after = if (low == 0xffff) low_value else ie_sample;
    const if_sample = interrupt_flags & 0x1f;
    const queue = ie_sample & if_sample;
    const selected: ?u3 =
        if (queue == 0) null else @intCast(@ctz(queue));
    const if_after_low = if (low == 0xff0f)
        low_value
    else
        interrupt_flags;
    const if_after = if (selected) |index|
        if_after_low & ~(@as(u8, 1) << index)
    else
        if_after_low;
    const offset: u3 = if (halted) 1 else 0;
    var service = machine.CartridgeServiceTrace{};
    if (halted) service.append(.halt_idle, null);
    service.append(.dummy_read, testAccess(pc, .read, 0x5a));
    service.append(.oam_bug, null);
    service.append(.no_access, null);
    service.append(.stack_high, testAccess(high, .write, high_value));
    service.ie_resample = .{
        .after_cycle = offset + 3,
        .value = ie_sample,
    };
    service.append(.stack_low, testAccess(low, .write, low_value));
    service.if_resample = .{
        .after_cycle = offset + 4,
        .value = if_sample,
    };
    if (selected) |index| service.acknowledgement = .{
        .during_cycle = offset + 4,
        .index = index,
        .before = if_after_low,
        .after = if_after,
    };
    const before_cpu = runner.Cpu{
        .a = 7,
        .sp = sp,
        .pc = pc,
        .ime = true,
        .halted = halted,
    };
    var after_cpu = before_cpu;
    after_cpu.sp -%= 2;
    after_cpu.pc = if (selected) |index|
        0x40 + @as(u16, index) * 8
    else
        0;
    after_cpu.ime = false;
    after_cpu.ime_enable_pending = false;
    after_cpu.halted = false;
    const before = testState(before_cpu, ie, interrupt_flags, if (halted)
        0x000f
    else
        0x0003);
    var after = testState(
        after_cpu,
        ie_after,
        if_after,
        before.div_counter +% @as(u16, 4) * (5 + offset),
    );
    after.tima = before.tima;
    return .{
        .before = before,
        .after = after,
        .event = .interrupt_service,
        .m_cycles = 5 + offset,
        .interrupt_index = selected,
        .service = service,
    };
}

fn testState(
    cpu: runner.Cpu,
    ie: u8,
    interrupt_flags: u8,
    div_counter: u16,
) machine.MachineState {
    return .{
        .cpu = cpu,
        .halt_bug = false,
        .div_counter = div_counter,
        .tima = 0x31,
        .tma = 0x42,
        .tac = 0x05,
        .timer_reload = .running,
        .interrupt_flags = interrupt_flags,
        .interrupt_enable = ie,
    };
}

fn testAccess(
    address: u16,
    action: runner.cartridge_memory.Action,
    value: u8,
) runner.cartridge_memory.Access {
    return .{
        .logical_address = address,
        .action = action,
        .region = if (action == .read and address <= 0x7fff)
            .cartridge_rom
        else
            .system,
        .physical_offset = if (action == .read and address <= 0x7fff)
            address
        else
            null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = value,
    };
}
