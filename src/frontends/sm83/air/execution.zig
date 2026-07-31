//! Canonical ordered SM83 execution-row constraints.
//!
//! Family AIRs own instruction semantics. This spine owns public boundaries,
//! consecutive CPU-state equality, M-cycle continuity, and canonical bus-row
//! shape. A full trace currently has no padding: every committed row executes.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const runner = @import("../runner/mod.zig");

pub const N_STATE_COLUMNS: usize = 14;
pub const N_BUS_CYCLES: usize = 6;
pub const N_BUS_COLUMNS: usize = 6;
pub const N_FAMILY_SELECTORS: usize = 16;
pub const N_FAMILY_CONSTRAINTS: usize = N_FAMILY_SELECTORS + 1;
pub const N_MAIN_COLUMNS: usize =
    2 * N_STATE_COLUMNS + N_BUS_CYCLES * N_BUS_COLUMNS + 3;
pub const N_CONSTRAINTS: usize =
    3 * N_STATE_COLUMNS + 3 + 11 * N_BUS_CYCLES +
    (N_BUS_CYCLES - 1) + 2;

pub const StateIndex = enum(usize) {
    a,
    b,
    c,
    d,
    e,
    f,
    h,
    l,
    sp,
    pc,
    ime,
    ime_enable_pending,
    halted,
    stopped,
};

pub const Boundary = struct {
    cpu: runner.Cpu,
    mcycle: u32,
};

pub fn familyConstraints(
    comptime S: type,
    selectors: [N_FAMILY_SELECTORS]S,
) [N_FAMILY_CONSTRAINTS]S {
    return familyConstraintsForActivity(S, selectors, S.one());
}

pub fn familyConstraintsForActivity(
    comptime S: type,
    selectors: [N_FAMILY_SELECTORS]S,
    expected_activity: S,
) [N_FAMILY_CONSTRAINTS]S {
    const one = S.one();
    var constraints: [N_FAMILY_CONSTRAINTS]S = undefined;
    var active = S.zero();
    for (selectors, 0..) |selector, index| {
        constraints[index] = selector.mul(selector.sub(one));
        active = active.add(selector);
    }
    constraints[N_FAMILY_SELECTORS] = active.sub(expected_activity);
    return constraints;
}

pub fn State(comptime S: type) type {
    return struct {
        values: [N_STATE_COLUMNS]S,

        pub fn at(self: @This(), index: StateIndex) S {
            return self.values[@intFromEnum(index)];
        }
    };
}

pub fn imeDelayConstraints(
    comptime S: type,
    before: State(S),
    after: State(S),
) [2]S {
    const before_ime = before.at(.ime);
    const before_pending = before.at(.ime_enable_pending);
    const promoted_ime = before_ime.add(before_pending)
        .sub(before_ime.mul(before_pending));
    return .{
        after.at(.ime).sub(promoted_ime),
        after.at(.ime_enable_pending),
    };
}

pub fn Bus(comptime S: type) type {
    return struct {
        address: S,
        value: S,
        active: S,
        read: S,
        write: S,
        program: S,
    };
}

pub fn Row(comptime S: type) type {
    return struct {
        before: State(S),
        after: State(S),
        bus: [N_BUS_CYCLES]Bus(S),
        mcycle_before: S,
        mcycle_after: S,
        branch_taken: S,

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
            var bus: [N_BUS_CYCLES]Bus(S) = undefined;
            var offset: usize = 2 * N_STATE_COLUMNS;
            for (&bus) |*cycle| {
                cycle.* = .{
                    .address = values[offset],
                    .value = values[offset + 1],
                    .active = values[offset + 2],
                    .read = values[offset + 3],
                    .write = values[offset + 4],
                    .program = values[offset + 5],
                };
                offset += N_BUS_COLUMNS;
            }
            return .{
                .before = .{ .values = values[0..N_STATE_COLUMNS].* },
                .after = .{
                    .values = values[N_STATE_COLUMNS .. 2 * N_STATE_COLUMNS].*,
                },
                .bus = bus,
                .mcycle_before = values[offset],
                .mcycle_after = values[offset + 1],
                .branch_taken = values[offset + 2],
            };
        }
    };
}

pub fn Semantics(comptime S: type) type {
    return struct {
        pub const Evaluation = struct {
            values: [N_CONSTRAINTS]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value| if (!value.isZero()) return false;
                return true;
            }
        };

        pub fn evaluate(
            current: Row(S),
            next: Row(S),
            is_first: S,
            is_last: S,
            initial: Boundary,
            final: Boundary,
        ) Evaluation {
            var out: [N_CONSTRAINTS]S = undefined;
            var index: usize = 0;
            const one = S.one();
            const not_last = one.sub(is_last);
            const initial_state = stateFromCpu(S, initial.cpu);
            const final_state = stateFromCpu(S, final.cpu);

            for (
                current.after.values,
                next.before.values,
                initial_state.values,
                final_state.values,
                current.before.values,
            ) |after, next_before, initial_value, final_value, before| {
                out[index] = not_last.mul(after.sub(next_before));
                index += 1;
                out[index] = is_first.mul(before.sub(initial_value));
                index += 1;
                out[index] = is_last.mul(after.sub(final_value));
                index += 1;
            }
            out[index] = not_last.mul(
                current.mcycle_after.sub(next.mcycle_before),
            );
            index += 1;
            out[index] = is_first.mul(
                current.mcycle_before.sub(base(S, initial.mcycle)),
            );
            index += 1;
            out[index] = is_last.mul(
                current.mcycle_after.sub(base(S, final.mcycle)),
            );
            index += 1;

            var active_cycles = S.zero();
            for (current.bus) |cycle| {
                out[index] = bit(cycle.active);
                index += 1;
                out[index] = bit(cycle.read);
                index += 1;
                out[index] = bit(cycle.write);
                index += 1;
                out[index] = bit(cycle.program);
                index += 1;
                out[index] = cycle.read.mul(cycle.write);
                index += 1;
                out[index] = cycle.program.mul(one.sub(cycle.read));
                index += 1;
                out[index] = cycle.read.mul(one.sub(cycle.active));
                index += 1;
                out[index] = cycle.write.mul(one.sub(cycle.active));
                index += 1;
                out[index] = cycle.program.mul(one.sub(cycle.active));
                index += 1;
                out[index] = one.sub(cycle.active).mul(cycle.address);
                index += 1;
                out[index] = one.sub(cycle.active).mul(cycle.value);
                index += 1;
                active_cycles = active_cycles.add(cycle.active);
            }
            for (0..N_BUS_CYCLES - 1) |cycle| {
                out[index] = current.bus[cycle + 1].active.mul(
                    one.sub(current.bus[cycle].active),
                );
                index += 1;
            }
            out[index] = current.mcycle_after
                .sub(current.mcycle_before)
                .sub(active_cycles);
            index += 1;
            out[index] = bit(current.branch_taken);
            index += 1;

            std.debug.assert(index == out.len);
            return .{ .values = out };
        }

        fn bit(value: S) S {
            return value.mul(value.sub(S.one()));
        }
    };
}

pub const Shipped = Semantics(QM31);

pub fn columns(step: runner.StepTrace, mcycle_before: u32) [N_MAIN_COLUMNS]M31 {
    var output = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    writeState(output[0..N_STATE_COLUMNS], step.before);
    writeState(output[N_STATE_COLUMNS .. 2 * N_STATE_COLUMNS], step.after);

    var offset: usize = 2 * N_STATE_COLUMNS;
    for (0..N_BUS_CYCLES) |cycle_index| {
        if (cycle_index < step.cycle_count) {
            const cycle = step.cycles[cycle_index];
            output[offset] = M31.fromCanonical(cycle.address);
            output[offset + 1] = M31.fromCanonical(cycle.value);
            output[offset + 2] = M31.one();
            output[offset + 3] = M31.fromCanonical(
                @intFromBool(cycle.action == .read),
            );
            output[offset + 4] = M31.fromCanonical(
                @intFromBool(cycle.action == .write),
            );
            output[offset + 5] = M31.fromCanonical(
                @intFromBool(
                    cycle.action == .read and
                        cycle_index < step.decoded.instruction.length,
                ),
            );
        }
        offset += N_BUS_COLUMNS;
    }
    output[offset] = M31.fromCanonical(mcycle_before);
    output[offset + 1] = M31.fromCanonical(
        mcycle_before + @as(u32, step.cycle_count),
    );
    output[offset + 2] = M31.fromCanonical(@intFromBool(step.branch_taken));
    return output;
}

pub fn evaluate(
    current_columns: [N_MAIN_COLUMNS]M31,
    next_columns: [N_MAIN_COLUMNS]M31,
    is_first: bool,
    is_last: bool,
    initial: Boundary,
    final: Boundary,
) !Shipped.Evaluation {
    var current: [N_MAIN_COLUMNS]QM31 = undefined;
    var next: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&current, current_columns) |*value, source| value.* = QM31.fromBase(source);
    for (&next, next_columns) |*value, source| value.* = QM31.fromBase(source);
    return Shipped.evaluate(
        try Row(QM31).fromColumns(&current),
        try Row(QM31).fromColumns(&next),
        QM31.fromBase(M31.fromCanonical(@intFromBool(is_first))),
        QM31.fromBase(M31.fromCanonical(@intFromBool(is_last))),
        initial,
        final,
    );
}

pub fn stateFromCpu(comptime S: type, cpu: runner.Cpu) State(S) {
    return .{ .values = .{
        base(S, cpu.a),
        base(S, cpu.b),
        base(S, cpu.c),
        base(S, cpu.d),
        base(S, cpu.e),
        base(S, cpu.f),
        base(S, cpu.h),
        base(S, cpu.l),
        base(S, cpu.sp),
        base(S, cpu.pc),
        base(S, @intFromBool(cpu.ime)),
        base(S, @intFromBool(cpu.ime_enable_pending)),
        base(S, @intFromBool(cpu.halted)),
        base(S, @intFromBool(cpu.stopped)),
    } };
}

fn writeState(destination: []M31, cpu: runner.Cpu) void {
    std.debug.assert(destination.len == N_STATE_COLUMNS);
    const state = stateFromCpu(M31, cpu);
    @memcpy(destination, &state.values);
}

fn base(comptime S: type, value: anytype) S {
    const canonical = M31.fromCanonical(@intCast(value));
    return if (S == M31) canonical else S.fromBase(canonical);
}

test "execution spine accepts a two-row chain and rejects continuity mutations" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x80);
    memory.write(1, 0x80);
    var cpu = runner.Cpu{ .a = 1, .b = 2 };
    const first = try runner.step(&cpu, &memory);
    const second = try runner.step(&cpu, &memory);
    const initial = Boundary{ .cpu = first.before, .mcycle = 0 };
    const final = Boundary{ .cpu = second.after, .mcycle = 2 };
    const first_columns = columns(first, 0);
    var second_columns = columns(second, 1);

    try std.testing.expect((try evaluate(
        first_columns,
        second_columns,
        true,
        false,
        initial,
        final,
    )).allZero());
    second_columns[@intFromEnum(StateIndex.a)] = M31.fromCanonical(9);
    try std.testing.expect(!(try evaluate(
        first_columns,
        second_columns,
        true,
        false,
        initial,
        final,
    )).allZero());
}

test "execution spine rejects vacuous inactive bus rows" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x80);
    var cpu = runner.Cpu{ .a = 1, .b = 2 };
    const step = try runner.step(&cpu, &memory);
    const boundary = Boundary{ .cpu = step.before, .mcycle = 0 };
    var witness = columns(step, 0);
    const bus_active = 2 * N_STATE_COLUMNS + 2;
    witness[bus_active] = M31.zero();
    try std.testing.expect(!(try evaluate(
        witness,
        witness,
        true,
        true,
        boundary,
        .{ .cpu = step.after, .mcycle = 1 },
    )).allZero());
}

test "ordinary EI-delay constraints accept promotion and reject mutations" {
    const before_cpu = runner.Cpu{
        .ime = false,
        .ime_enable_pending = true,
    };
    const after_cpu = runner.Cpu{ .ime = true };
    const before = stateFromCpu(QM31, before_cpu);
    var after = stateFromCpu(QM31, after_cpu);
    for (imeDelayConstraints(QM31, before, after)) |constraint|
        try std.testing.expect(constraint.isZero());

    after.values[@intFromEnum(StateIndex.ime)] = QM31.zero();
    var rejected = false;
    for (imeDelayConstraints(QM31, before, after)) |constraint|
        rejected = rejected or !constraint.isZero();
    try std.testing.expect(rejected);

    after = stateFromCpu(QM31, after_cpu);
    after.values[@intFromEnum(StateIndex.ime_enable_pending)] = QM31.one();
    rejected = false;
    for (imeDelayConstraints(QM31, before, after)) |constraint|
        rejected = rejected or !constraint.isZero();
    try std.testing.expect(rejected);
}

test "family selectors are canonical and exactly one is active" {
    for (0..N_FAMILY_SELECTORS) |active| {
        var selectors = [_]QM31{QM31.zero()} ** N_FAMILY_SELECTORS;
        selectors[active] = QM31.one();
        for (familyConstraints(QM31, selectors)) |constraint| {
            try std.testing.expect(constraint.isZero());
        }
    }

    for ([_][N_FAMILY_SELECTORS]QM31{
        [_]QM31{QM31.zero()} ** N_FAMILY_SELECTORS,
        .{ QM31.one(), QM31.one() } ++
            [_]QM31{QM31.zero()} ** (N_FAMILY_SELECTORS - 2),
        .{QM31.fromBase(M31.fromCanonical(2))} ++
            [_]QM31{QM31.zero()} ** (N_FAMILY_SELECTORS - 1),
    }) |selectors| {
        var all_zero = true;
        for (familyConstraints(QM31, selectors)) |constraint| {
            all_zero = all_zero and constraint.isZero();
        }
        try std.testing.expect(!all_zero);
    }

    const inactive = [_]QM31{QM31.zero()} ** N_FAMILY_SELECTORS;
    for (
        familyConstraintsForActivity(QM31, inactive, QM31.zero()),
    ) |constraint| try std.testing.expect(constraint.isZero());
    var forged = inactive;
    forged[0] = QM31.one();
    var rejected = false;
    for (
        familyConstraintsForActivity(QM31, forged, QM31.zero()),
    ) |constraint| rejected = rejected or !constraint.isZero();
    try std.testing.expect(rejected);
}
