//! LogUp joins between execution M-cycles and timer binding events.
//!
//! Three independently challenged multisets prevent omission, duplication, or
//! substitution of timer ticks, FF04..FF07 writes, and pre-tick reads.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const runner = @import("../runner/mod.zig");
const cartridge_access_component = @import("cartridge_access_component.zig");
const cartridge_machine_access = @import("cartridge_machine_access.zig");
const execution = @import("execution.zig");
const execution_input = @import("execution_input.zig");
const scheduler_machine = @import("../runner/machine.zig");
const timer_air = @import("timer.zig");
const timer_binding = @import("timer_binding.zig");

pub const N_RELATIONS: usize = 3;
pub const N_EXECUTION_SUMS: usize = execution.N_BUS_CYCLES;
pub const N_EXECUTION_INTERACTION_COLUMNS: usize =
    N_RELATIONS * N_EXECUTION_SUMS * 4;
pub const N_TIMER_INTERACTION_COLUMNS: usize = N_RELATIONS * 4;
pub const N_EXECUTION_CONSTRAINTS: usize =
    N_RELATIONS * N_EXECUTION_SUMS;
pub const N_TIMER_CONSTRAINTS: usize = N_RELATIONS;
pub const MAX_CONSTRAINT_DEGREE: u32 = 2;

pub const RelationIndex = enum(usize) { tick, write, read };

const TAGS = [N_RELATIONS]u32{
    0x544d_4d01,
    0x544d_4d02,
    0x544d_4d03,
};

pub const Relation = struct {
    z: QM31,
    address_alpha: QM31,
    value_alpha: QM31,

    pub fn draw(
        allocator: std.mem.Allocator,
        channel: anytype,
        tag: u32,
    ) !Relation {
        channel.mixU32s(&.{tag});
        const values = try channel.drawSecureFelts(allocator, 3);
        defer allocator.free(values);
        return .{
            .z = values[0],
            .address_alpha = values[1],
            .value_alpha = values[2],
        };
    }

    pub fn combine(
        self: Relation,
        clock: QM31,
        address: QM31,
        value: QM31,
    ) QM31 {
        return clock
            .add(self.address_alpha.mul(address))
            .add(self.value_alpha.mul(value))
            .sub(self.z);
    }
};

pub const Relations = struct {
    values: [N_RELATIONS]Relation,

    pub fn draw(
        allocator: std.mem.Allocator,
        channel: anytype,
    ) !Relations {
        var values: [N_RELATIONS]Relation = undefined;
        for (&values, TAGS) |*value, tag|
            value.* = try Relation.draw(allocator, channel, tag);
        return .{ .values = values };
    }

    pub fn dummy() Relations {
        return .{ .values = .{
            .{
                .z = QM31.fromU32Unchecked(3, 5, 7, 11),
                .address_alpha = QM31.fromU32Unchecked(13, 17, 19, 23),
                .value_alpha = QM31.fromU32Unchecked(29, 31, 37, 41),
            },
            .{
                .z = QM31.fromU32Unchecked(43, 47, 53, 59),
                .address_alpha = QM31.fromU32Unchecked(61, 67, 71, 73),
                .value_alpha = QM31.fromU32Unchecked(79, 83, 89, 97),
            },
            .{
                .z = QM31.fromU32Unchecked(101, 103, 107, 109),
                .address_alpha = QM31.fromU32Unchecked(113, 127, 131, 137),
                .value_alpha = QM31.fromU32Unchecked(139, 149, 151, 157),
            },
        } };
    }

    pub fn at(self: Relations, index: RelationIndex) Relation {
        return self.values[@intFromEnum(index)];
    }
};

pub const Pair = struct {
    numerator: QM31,
    denominator: QM31,
};

pub const Claims = struct {
    execution: [N_RELATIONS][N_EXECUTION_SUMS]QM31,
    timer: [N_RELATIONS]QM31,
};

pub const Interaction = struct {
    execution_columns: [N_EXECUTION_INTERACTION_COLUMNS][]M31,
    timer_columns: [N_TIMER_INTERACTION_COLUMNS][]M31,
    claims: Claims,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Interaction) void {
        for (self.execution_columns) |column| self.allocator.free(column);
        for (self.timer_columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    steps: anytype,
    initial_mcycle: u32,
    timer_log_size: u32,
    events: []const timer_binding.EventRow,
    relations: Relations,
) !Interaction {
    if (steps.len == 0 or !std.math.isPowerOfTwo(steps.len))
        return error.InvalidExecutionTraceLength;
    const timer_size = try traceSize(timer_log_size);
    if (events.len > timer_size) return error.TooManyTimerEvents;
    var result = Interaction{
        .execution_columns = undefined,
        .timer_columns = undefined,
        .claims = undefined,
        .allocator = allocator,
    };
    var execution_initialized: usize = 0;
    var timer_initialized: usize = 0;
    errdefer {
        for (result.execution_columns[0..execution_initialized]) |column|
            allocator.free(column);
        for (result.timer_columns[0..timer_initialized]) |column|
            allocator.free(column);
    }
    for (&result.execution_columns) |*column| {
        column.* = try allocator.alloc(M31, steps.len);
        @memset(column.*, M31.zero());
        execution_initialized += 1;
    }
    for (&result.timer_columns) |*column| {
        column.* = try allocator.alloc(M31, timer_size);
        @memset(column.*, M31.zero());
        timer_initialized += 1;
    }

    const execution_log: u32 =
        @intCast(std.math.log2_int(usize, steps.len));
    var execution_claims =
        [_][N_EXECUTION_SUMS]QM31{
            [_]QM31{QM31.zero()} ** N_EXECUTION_SUMS,
        } ** N_RELATIONS;
    var mcycle = initial_mcycle;
    for (steps, 0..) |step, row_index| {
        const m_cycles = stepMCycles(step);
        if (mcycle >= M31_MODULUS or
            m_cycles > M31_MODULUS - mcycle)
            return error.McycleOutsideField;
        const source = try stepColumns(step, mcycle);
        const execution_row = try liftExecution(source.execution);
        const access = try liftAccess(source.access);
        const pairs = executionPairs(execution_row, access, relations);
        const storage = try core_air_utils.circleBitReversedIndex(
            execution_log,
            row_index,
        );
        for (0..N_RELATIONS) |relation_index| {
            for (0..N_EXECUTION_SUMS) |sum_index| {
                execution_claims[relation_index][sum_index] =
                    try accumulate(
                        execution_claims[relation_index][sum_index],
                        pairs[relation_index][sum_index],
                    );
                const offset = 4 *
                    (relation_index * N_EXECUTION_SUMS + sum_index);
                writeSecure(
                    result.execution_columns[offset..][0..4],
                    storage,
                    execution_claims[relation_index][sum_index],
                );
            }
        }
        mcycle += m_cycles;
    }

    var timer_claims = [_]QM31{QM31.zero()} ** N_RELATIONS;
    for (0..timer_size) |row_index| {
        const values = if (row_index < events.len)
            try eventColumns(events[row_index], steps)
        else
            timer_binding.inactiveColumns();
        const pairs = timerPairs(
            try liftTimer(values),
            relations,
        );
        const storage = try core_air_utils.circleBitReversedIndex(
            timer_log_size,
            row_index,
        );
        for (0..N_RELATIONS) |relation_index| {
            timer_claims[relation_index] = try accumulate(
                timer_claims[relation_index],
                pairs[relation_index],
            );
            writeSecure(
                result.timer_columns[4 * relation_index ..][0..4],
                storage,
                timer_claims[relation_index],
            );
        }
    }
    result.claims = .{
        .execution = execution_claims,
        .timer = timer_claims,
    };
    return result;
}

const StepColumns = struct {
    execution: [execution.N_MAIN_COLUMNS]M31,
    access: [cartridge_access_component.N_MAIN_COLUMNS]M31,
};

fn stepColumns(step: anytype, mcycle: u32) !StepColumns {
    if (comptime @TypeOf(step) == scheduler_machine.CartridgeStepResult) {
        const input = try execution_input.fromCartridgeMachine(step);
        return .{
            .execution = try execution_input.cartridgeExecutionColumns(
                input,
                mcycle,
            ),
            .access = cartridge_machine_access.columns(
                try cartridge_machine_access.ValidatedStep.init(step),
            ),
        };
    }
    return .{
        .execution = execution.columns(step.instruction, mcycle),
        .access = try cartridge_access_component.columns(step),
    };
}

fn stepMCycles(step: anytype) u3 {
    if (comptime @TypeOf(step) == scheduler_machine.CartridgeStepResult)
        return step.m_cycles;
    return step.instruction.cycle_count;
}

fn eventColumns(event: anytype, steps: anytype) ![
    timer_binding.N_MAIN_COLUMNS
]M31 {
    if (comptime std.meta.Elem(@TypeOf(steps)) ==
        scheduler_machine.CartridgeStepResult)
        return timer_binding.machineColumns(event, steps);
    return timer_binding.columns(event, steps);
}

pub fn executionPairs(
    machine: execution.Row(QM31),
    access: cartridge_access_component.PackedRow(QM31),
    relations: Relations,
) [N_RELATIONS][N_EXECUTION_SUMS]Pair {
    var result: [N_RELATIONS][N_EXECUTION_SUMS]Pair = undefined;
    for (0..N_EXECUTION_SUMS) |cycle| {
        const clock = machine.mcycle_before.add(
            QM31.fromBase(M31.fromCanonical(@intCast(cycle))),
        );
        const active = machine.bus[cycle].active;
        const source = access.cycles[cycle];
        const timer_region = source.regions[
            @intFromEnum(runner.cartridge_memory.Region.timer_mmio)
        ];
        const read = timer_region.mul(source.access_actions[
            @intFromEnum(runner.cartridge_memory.Action.read)
        ]);
        const write = timer_region.mul(source.access_actions[
            @intFromEnum(runner.cartridge_memory.Action.write)
        ]);
        const address = compose(QM31, source.logical_address);
        const value = compose(QM31, source.access_value);
        result[@intFromEnum(RelationIndex.tick)][cycle] = pair(
            active.neg(),
            relations.at(.tick).combine(
                clock,
                QM31.zero(),
                QM31.zero(),
            ),
        );
        result[@intFromEnum(RelationIndex.write)][cycle] = pair(
            write.neg(),
            relations.at(.write).combine(clock, address, value),
        );
        result[@intFromEnum(RelationIndex.read)][cycle] = pair(
            read.neg(),
            relations.at(.read).combine(clock, address, value),
        );
    }
    return result;
}

pub fn TimerRow(comptime S: type) type {
    return struct {
        active: S,
        semantic: timer_air.Semantics(S).Row,
        mcycle: S,
        read_markers: [4]S,
        read_value: [8]S,
    };
}

pub fn timerRow(
    comptime S: type,
    values: []const S,
) !TimerRow(S) {
    if (values.len != timer_binding.N_MAIN_COLUMNS)
        return error.InvalidTimerBindingShape;
    return .{
        .active = values[0],
        .semantic = try timer_air.Semantics(S).Row.fromColumns(
            values[1..timer_binding.MCYCLE_OFFSET],
        ),
        .mcycle = values[timer_binding.MCYCLE_OFFSET],
        .read_markers = values[timer_binding.READ_MARKER_OFFSET..timer_binding.READ_VALUE_OFFSET].*,
        .read_value = values[timer_binding.READ_VALUE_OFFSET..timer_binding.N_MAIN_COLUMNS].*,
    };
}

pub fn timerPairs(
    row: TimerRow(QM31),
    relations: Relations,
) [N_RELATIONS]Pair {
    const tick = row.semantic.events[0];
    const write = sum(QM31, row.semantic.events[1..]);
    const read = sum(QM31, &row.read_markers);
    const write_address = selectedAddress(
        QM31,
        row.semantic.events[1..],
    );
    const read_address = selectedAddress(
        QM31,
        &row.read_markers,
    );
    return .{
        pair(
            tick,
            relations.at(.tick).combine(
                row.mcycle,
                QM31.zero(),
                QM31.zero(),
            ),
        ),
        pair(
            write,
            relations.at(.write).combine(
                row.mcycle,
                write_address,
                compose(QM31, row.semantic.action),
            ),
        ),
        pair(
            read,
            relations.at(.read).combine(
                row.mcycle,
                read_address,
                compose(QM31, &row.read_value),
            ),
        ),
    };
}

pub fn pairConstraint(
    comptime S: type,
    current: S,
    previous: S,
    is_first: S,
    claim: S,
    numerator: S,
    denominator: S,
) S {
    return current.sub(previous).add(is_first.mul(claim))
        .mul(denominator).sub(numerator);
}

pub fn verifyCancellation(claims: Claims) !void {
    for (0..N_RELATIONS) |relation_index| {
        var total = claims.timer[relation_index];
        for (claims.execution[relation_index]) |claim|
            total = total.add(claim);
        if (!total.isZero()) return error.TimerMmioLookupSumNonZero;
    }
}

fn pair(numerator: QM31, denominator: QM31) Pair {
    return .{
        .numerator = numerator,
        .denominator = if (numerator.isZero()) QM31.one() else denominator,
    };
}

fn accumulate(current: QM31, entry: Pair) !QM31 {
    return current.add(entry.numerator.mul(
        entry.denominator.inv() catch
            return error.TimerMmioLookupZeroDenominator,
    ));
}

fn traceSize(log_size: u32) !usize {
    if (log_size < 4 or log_size >= @bitSizeOf(usize))
        return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn liftExecution(
    columns: [execution.N_MAIN_COLUMNS]M31,
) !execution.Row(QM31) {
    var lifted: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, columns) |*target, source|
        target.* = QM31.fromBase(source);
    return execution.Row(QM31).fromColumns(&lifted);
}

fn liftAccess(
    columns: [cartridge_access_component.N_MAIN_COLUMNS]M31,
) !cartridge_access_component.PackedRow(QM31) {
    var lifted: [cartridge_access_component.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, columns) |*target, source|
        target.* = QM31.fromBase(source);
    return cartridge_access_component.PackedRow(QM31).fromColumns(&lifted);
}

fn liftTimer(
    columns: [timer_binding.N_MAIN_COLUMNS]M31,
) !TimerRow(QM31) {
    var lifted: [timer_binding.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, columns) |*target, source|
        target.* = QM31.fromBase(source);
    return timerRow(QM31, &lifted);
}

fn selectedAddress(
    comptime S: type,
    selectors: anytype,
) S {
    var result = S.zero();
    for (selectors, 0..) |selector, index|
        result = result.add(
            selector.mul(constant(
                S,
                timer_binding.FIRST_ADDRESS + @as(u32, @intCast(index)),
            )),
        );
    return result;
}

fn compose(comptime S: type, bits: anytype) S {
    var result = S.zero();
    var power = S.one();
    for (bits) |bit_value| {
        result = result.add(power.mul(bit_value));
        power = power.add(power);
    }
    return result;
}

fn sum(comptime S: type, values: anytype) S {
    var result = S.zero();
    for (values) |value| result = result.add(value);
    return result;
}

fn constant(comptime S: type, value: u32) S {
    var result = S.zero();
    var power = S.one();
    var remaining = value;
    while (remaining != 0) : (remaining >>= 1) {
        if (remaining & 1 == 1) result = result.add(power);
        power = power.add(power);
    }
    return result;
}

fn writeSecure(columns: []const []M31, row: usize, value: QM31) void {
    for (columns, value.toM31Array()) |column, coordinate|
        column[row] = coordinate;
}

test "machine timer lookup binds instruction HALT wake and exact service" {
    var flat = try runner.Memory.init(std.testing.allocator);
    defer flat.deinit();
    flat.write(0xc000, 0);
    var cpu = runner.Cpu{ .pc = 0xc000 };
    const cases = [_]scheduler_machine.CartridgeStepResult{
        timerMachineInstruction(try runner.step(&cpu, &flat)),
        timerMachineHalt(.halt_idle),
        timerMachineHalt(.halt_wake),
        timerMachineService(),
    };
    try std.testing.expect(cases[0].hasCanonicalShape());
    try std.testing.expect(cases[1].hasCanonicalShape());
    try std.testing.expect(cases[2].hasCanonicalShape());
    try std.testing.expect(cases[3].hasCanonicalShape());
    for (cases) |result| {
        const one = [_]scheduler_machine.CartridgeStepResult{result};
        var trace = try timer_binding.generateFromMachineExecution(
            std.testing.allocator,
            0,
            result.m_cycles,
            .{},
            &one,
        );
        defer trace.deinit(std.testing.allocator);
        var interaction = try generateInteraction(
            std.testing.allocator,
            &one,
            0,
            4,
            trace.rows,
            Relations.dummy(),
        );
        defer interaction.deinit();
        try verifyCancellation(interaction.claims);
    }

    const service = cases[3];
    const one = [_]scheduler_machine.CartridgeStepResult{service};
    var trace = try timer_binding.generateFromMachineExecution(
        std.testing.allocator,
        20,
        25,
        .{},
        &one,
    );
    defer trace.deinit(std.testing.allocator);
    trace.rows[0].mcycle += 1;
    var semantic = try generateInteraction(
        std.testing.allocator,
        &one,
        20,
        4,
        trace.rows,
        Relations.dummy(),
    );
    defer semantic.deinit();
    try std.testing.expectError(
        error.TimerMmioLookupSumNonZero,
        verifyCancellation(semantic.claims),
    );
    trace.rows[0].mcycle -= 1;
    trace.rows[0].provenance.execution_tick.cycle = 1;
    var provenance = try generateInteraction(
        std.testing.allocator,
        &one,
        20,
        4,
        trace.rows,
        Relations.dummy(),
    );
    defer provenance.deinit();
    try std.testing.expectError(
        error.TimerMmioLookupSumNonZero,
        verifyCancellation(provenance.claims),
    );
    var vacuous = try generateInteraction(
        std.testing.allocator,
        &one,
        20,
        4,
        &.{},
        Relations.dummy(),
    );
    defer vacuous.deinit();
    try std.testing.expectError(
        error.TimerMmioLookupSumNonZero,
        verifyCancellation(vacuous.claims),
    );
}

fn timerMachineInstruction(
    instruction: runner.StepTrace,
) scheduler_machine.CartridgeStepResult {
    var step = runner.CartridgeStepTrace{
        .instruction = instruction,
        .accesses = [_]?runner.cartridge_memory.Access{null} **
            runner.MAX_BUS_CYCLES,
    };
    step.accesses[0] = timerMachineAccess(0xc000, .read, 0);
    return .{
        .before = timerMachineState(instruction.before, 0, 0, 0),
        .after = timerMachineState(instruction.after, 4, 0, 0),
        .event = .instruction,
        .m_cycles = instruction.cycle_count,
        .instruction = step,
    };
}

fn timerMachineHalt(
    event: scheduler_machine.SchedulerEvent,
) scheduler_machine.CartridgeStepResult {
    const queued: u8 = @intFromBool(event == .halt_wake);
    const before = timerMachineState(
        .{ .halted = true },
        0,
        queued,
        queued,
    );
    var after = before;
    after.div_counter = 4;
    after.cpu.halted = event == .halt_idle;
    return .{
        .before = before,
        .after = after,
        .event = event,
        .m_cycles = 1,
    };
}

fn timerMachineService() scheduler_machine.CartridgeStepResult {
    const cpu = runner.Cpu{ .pc = 0xff04, .sp = 0xc100, .ime = true };
    var after_cpu = cpu;
    after_cpu.pc = 0x40;
    after_cpu.sp -%= 2;
    after_cpu.ime = false;
    var result = scheduler_machine.CartridgeStepResult{
        .before = timerMachineState(cpu, 0, 1, 1),
        .after = timerMachineState(after_cpu, 20, 0, 1),
        .event = .interrupt_service,
        .m_cycles = 5,
        .interrupt_index = 0,
    };
    result.service.count = 5;
    result.service.cycles[0] = .{
        .kind = .dummy_read,
        .access = timerMachineAccess(0xff04, .read, 0),
    };
    result.service.cycles[1].kind = .oam_bug;
    result.service.cycles[2].kind = .no_access;
    result.service.cycles[3] = .{
        .kind = .stack_high,
        .access = timerMachineAccess(0xc0ff, .write, 0xff),
    };
    result.service.cycles[4] = .{
        .kind = .stack_low,
        .access = timerMachineAccess(0xc0fe, .write, 0x04),
    };
    result.service.ie_resample = .{ .after_cycle = 3, .value = 1 };
    result.service.if_resample = .{ .after_cycle = 4, .value = 1 };
    result.service.acknowledgement = .{
        .during_cycle = 4,
        .index = 0,
        .before = 1,
        .after = 0,
    };
    return result;
}

fn timerMachineState(
    cpu: runner.Cpu,
    div_counter: u16,
    flags: u8,
    enable: u8,
) scheduler_machine.MachineState {
    return .{
        .cpu = cpu,
        .halt_bug = false,
        .div_counter = div_counter,
        .tima = 0,
        .tma = 0,
        .tac = 0,
        .timer_reload = .running,
        .interrupt_flags = flags,
        .interrupt_enable = enable,
    };
}

fn timerMachineAccess(
    address: u16,
    action: runner.cartridge_memory.Action,
    value: u8,
) runner.cartridge_memory.Access {
    return .{
        .logical_address = address,
        .action = action,
        .region = if (address >= timer_binding.FIRST_ADDRESS and
            address < timer_binding.FIRST_ADDRESS + 4)
            .timer_mmio
        else
            .system,
        .physical_offset = null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = value,
    };
}
