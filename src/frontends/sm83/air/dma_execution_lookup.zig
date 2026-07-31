//! LogUp cancellation between execution bus cycles and DMA binding rows.
//!
//! Every active execution M-cycle contributes one negative bus tuple and every
//! active DMA row contributes the matching positive tuple. A second,
//! independently challenged clock fraction makes omission/duplication checks
//! explicit and keeps the standard two-fraction recurrence exactly cubic.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const runner = @import("../runner/mod.zig");
const binding = @import("dma_binding.zig");
const execution = @import("execution.zig");
const execution_input = @import("execution_input.zig");
const scheduler_machine = @import("../runner/machine.zig");

pub const N_EXECUTION_SUMS: usize = execution.N_BUS_CYCLES;
pub const N_EXECUTION_INTERACTION_COLUMNS: usize =
    N_EXECUTION_SUMS * 4;
pub const N_DMA_INTERACTION_COLUMNS: usize = 4;
pub const N_EXECUTION_CONSTRAINTS: usize = N_EXECUTION_SUMS;
pub const N_DMA_CONSTRAINTS: usize = 1;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

const BUS_TAG: u32 = 0x444d_4101;
const CLOCK_TAG: u32 = 0x444d_4102;

pub const LinearRelation = struct {
    z: QM31,
    clock_alpha: QM31,
    address_alpha: QM31,
    value_alpha: QM31,
    action_alpha: QM31,

    pub fn draw(
        allocator: std.mem.Allocator,
        channel: anytype,
        tag: u32,
    ) !LinearRelation {
        channel.mixU32s(&.{tag});
        const values = try channel.drawSecureFelts(allocator, 5);
        defer allocator.free(values);
        return .{
            .z = values[0],
            .clock_alpha = values[1],
            .address_alpha = values[2],
            .value_alpha = values[3],
            .action_alpha = values[4],
        };
    }

    pub fn combine(
        self: LinearRelation,
        clock: QM31,
        address: QM31,
        value: QM31,
        action: QM31,
    ) QM31 {
        return self.clock_alpha.mul(clock)
            .add(self.address_alpha.mul(address))
            .add(self.value_alpha.mul(value))
            .add(self.action_alpha.mul(action))
            .sub(self.z);
    }
};

pub const Relations = struct {
    bus: LinearRelation,
    clock: LinearRelation,

    pub fn draw(
        allocator: std.mem.Allocator,
        channel: anytype,
    ) !Relations {
        return .{
            .bus = try LinearRelation.draw(allocator, channel, BUS_TAG),
            .clock = try LinearRelation.draw(allocator, channel, CLOCK_TAG),
        };
    }

    pub fn dummy() Relations {
        return .{
            .bus = .{
                .z = QM31.fromU32Unchecked(3, 5, 7, 11),
                .clock_alpha = QM31.fromU32Unchecked(13, 17, 19, 23),
                .address_alpha = QM31.fromU32Unchecked(29, 31, 37, 41),
                .value_alpha = QM31.fromU32Unchecked(43, 47, 53, 59),
                .action_alpha = QM31.fromU32Unchecked(61, 67, 71, 73),
            },
            .clock = .{
                .z = QM31.fromU32Unchecked(79, 83, 89, 97),
                .clock_alpha = QM31.fromU32Unchecked(101, 103, 107, 109),
                .address_alpha = QM31.zero(),
                .value_alpha = QM31.zero(),
                .action_alpha = QM31.zero(),
            },
        };
    }
};

pub const Pair = struct {
    n1: QM31,
    d1: QM31,
    n2: QM31,
    d2: QM31,
};

pub const Claims = struct {
    execution: [N_EXECUTION_SUMS]QM31,
    dma: QM31,
    execution_count: usize,
    dma_count: usize,
};

pub const Interaction = struct {
    execution_columns: [N_EXECUTION_INTERACTION_COLUMNS][]M31,
    dma_columns: [N_DMA_INTERACTION_COLUMNS][]M31,
    claims: Claims,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Interaction) void {
        for (self.execution_columns) |column| self.allocator.free(column);
        for (self.dma_columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    steps: anytype,
    initial_mcycle: u32,
    dma_log_size: u32,
    events: []const binding.EventRow,
    relations: Relations,
) !Interaction {
    if (steps.len == 0 or !std.math.isPowerOfTwo(steps.len))
        return error.InvalidExecutionTraceLength;
    const dma_size = try traceSize(dma_log_size);
    if (events.len == 0) return error.EmptyDmaTrace;
    if (events.len > dma_size) return error.TooManyDmaEvents;

    var expected_count: usize = 0;
    for (steps) |step| {
        expected_count = std.math.add(
            usize,
            expected_count,
            stepMCycles(step),
        ) catch return error.TooManyDmaEvents;
    }
    if (events.len != expected_count)
        return error.DmaExecutionCountMismatch;

    var result = Interaction{
        .execution_columns = undefined,
        .dma_columns = undefined,
        .claims = undefined,
        .allocator = allocator,
    };
    var execution_initialized: usize = 0;
    var dma_initialized: usize = 0;
    errdefer {
        for (result.execution_columns[0..execution_initialized]) |column|
            allocator.free(column);
        for (result.dma_columns[0..dma_initialized]) |column|
            allocator.free(column);
    }
    for (&result.execution_columns) |*column| {
        column.* = try allocator.alloc(M31, steps.len);
        @memset(column.*, M31.zero());
        execution_initialized += 1;
    }
    for (&result.dma_columns) |*column| {
        column.* = try allocator.alloc(M31, dma_size);
        @memset(column.*, M31.zero());
        dma_initialized += 1;
    }

    const execution_log: u32 =
        @intCast(std.math.log2_int(usize, steps.len));
    var execution_claims =
        [_]QM31{QM31.zero()} ** N_EXECUTION_SUMS;
    var mcycle = initial_mcycle;
    var execution_count: usize = 0;
    for (steps, 0..) |step, row_index| {
        const m_cycles = stepMCycles(step);
        if (mcycle >= M31_MODULUS or
            m_cycles > M31_MODULUS - mcycle)
            return error.McycleOutsideField;
        const execution_row = try liftExecution(
            try executionColumns(step, mcycle),
        );
        const pairs = executionPairs(execution_row, relations);
        const storage = try core_air_utils.circleBitReversedIndex(
            execution_log,
            row_index,
        );
        for (pairs, 0..) |entry, sum_index| {
            execution_claims[sum_index] = try accumulate(
                execution_claims[sum_index],
                entry,
            );
            writeSecure(
                result.execution_columns[4 * sum_index ..][0..4],
                storage,
                execution_claims[sum_index],
            );
            execution_count += @intFromBool(
                !entry.n1.isZero(),
            );
        }
        mcycle += m_cycles;
    }

    var dma_claim = QM31.zero();
    for (0..dma_size) |row_index| {
        const values = if (row_index < events.len)
            try eventColumns(events[row_index], steps)
        else
            binding.inactiveColumns();
        const entry = dmaPair(try dmaRow(QM31, &lift(values)), relations);
        dma_claim = try accumulate(dma_claim, entry);
        const storage = try core_air_utils.circleBitReversedIndex(
            dma_log_size,
            row_index,
        );
        writeSecure(&result.dma_columns, storage, dma_claim);
    }
    result.claims = .{
        .execution = execution_claims,
        .dma = dma_claim,
        .execution_count = execution_count,
        .dma_count = events.len,
    };
    try verifyCancellation(result.claims);
    return result;
}

fn executionColumns(
    step: anytype,
    mcycle: u32,
) ![execution.N_MAIN_COLUMNS]M31 {
    if (comptime @TypeOf(step) ==
        scheduler_machine.CartridgeStepResult)
        return execution_input.cartridgeExecutionColumns(
            try execution_input.fromCartridgeMachine(step),
            mcycle,
        );
    return execution.columns(step.instruction, mcycle);
}

fn stepMCycles(step: anytype) u3 {
    if (comptime @TypeOf(step) ==
        scheduler_machine.CartridgeStepResult)
        return step.m_cycles;
    return step.instruction.cycle_count;
}

fn eventColumns(event: binding.EventRow, steps: anytype) ![
    binding.N_MAIN_COLUMNS
]M31 {
    if (comptime std.meta.Elem(@TypeOf(steps)) ==
        scheduler_machine.CartridgeStepResult)
        return binding.machineColumns(event, steps);
    return binding.columns(event, steps);
}

pub fn executionPairs(
    machine: execution.Row(QM31),
    relations: Relations,
) [N_EXECUTION_SUMS]Pair {
    var result: [N_EXECUTION_SUMS]Pair = undefined;
    for (&result, machine.bus, 0..) |*entry, bus, cycle| {
        const clock = machine.mcycle_before.add(
            base(@intCast(cycle)),
        );
        entry.* = rowPair(
            bus.active.neg(),
            clock,
            bus.address,
            bus.value,
            bus.read.add(base(2).mul(bus.write)),
            relations,
        );
    }
    return result;
}

pub fn DmaRow(comptime S: type) type {
    return struct {
        active: S,
        mcycle: S,
        address: [16]S,
        value: [8]S,
        actions: [3]S,
    };
}

pub fn dmaRow(
    comptime S: type,
    values: []const S,
) !DmaRow(S) {
    if (values.len != binding.N_MAIN_COLUMNS)
        return error.InvalidDmaBindingShape;
    return .{
        .active = values[0],
        .mcycle = values[binding.MCYCLE_OFFSET],
        .address = values[binding.BUS_ADDRESS_OFFSET..binding.BUS_VALUE_OFFSET].*,
        .value = values[binding.BUS_VALUE_OFFSET..binding.BUS_ACTION_OFFSET].*,
        .actions = values[binding.BUS_ACTION_OFFSET..binding.CPU_CLASS_OFFSET].*,
    };
}

pub fn dmaPair(row: DmaRow(QM31), relations: Relations) Pair {
    return rowPair(
        row.active,
        row.mcycle,
        compose(QM31, &row.address),
        compose(QM31, &row.value),
        row.actions[1].add(base(2).mul(row.actions[2])),
        relations,
    );
}

pub fn pairConstraint(
    comptime S: type,
    current: S,
    previous: S,
    is_first: S,
    claim: S,
    n1: S,
    d1: S,
    n2: S,
    d2: S,
) S {
    const delta = current.sub(previous).add(is_first.mul(claim));
    return delta.mul(d1).mul(d2)
        .sub(n1.mul(d2))
        .sub(n2.mul(d1));
}

pub fn verifyCancellation(claims: Claims) !void {
    if (claims.execution_count == 0 or claims.dma_count == 0)
        return error.EmptyDmaExecutionLookup;
    if (claims.execution_count != claims.dma_count)
        return error.DmaExecutionCountMismatch;
    var total = claims.dma;
    for (claims.execution) |claim| total = total.add(claim);
    if (!total.isZero())
        return error.DmaExecutionLookupSumNonZero;
}

fn rowPair(
    numerator: QM31,
    clock: QM31,
    address: QM31,
    value: QM31,
    action: QM31,
    relations: Relations,
) Pair {
    if (numerator.isZero()) return .{
        .n1 = QM31.zero(),
        .d1 = QM31.one(),
        .n2 = QM31.zero(),
        .d2 = QM31.one(),
    };
    return .{
        .n1 = numerator,
        .d1 = relations.bus.combine(clock, address, value, action),
        .n2 = numerator,
        .d2 = relations.clock.combine(
            clock,
            QM31.zero(),
            QM31.zero(),
            QM31.zero(),
        ),
    };
}

fn accumulate(current: QM31, entry: Pair) !QM31 {
    return current
        .add(entry.n1.mul(entry.d1.inv() catch
            return error.DmaExecutionLookupZeroDenominator))
        .add(entry.n2.mul(entry.d2.inv() catch
        return error.DmaExecutionLookupZeroDenominator));
}

fn traceSize(log_size: u32) !usize {
    if (log_size < 4 or log_size >= @bitSizeOf(usize))
        return error.InvalidDmaLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn liftExecution(
    columns: [execution.N_MAIN_COLUMNS]M31,
) !execution.Row(QM31) {
    return execution.Row(QM31).fromColumns(&lift(columns));
}

fn lift(values: anytype) [values.len]QM31 {
    var result: [values.len]QM31 = undefined;
    for (&result, values) |*target, source|
        target.* = QM31.fromBase(source);
    return result;
}

fn compose(comptime S: type, bits: anytype) S {
    var result = S.zero();
    var power = S.one();
    for (bits) |value| {
        result = result.add(power.mul(value));
        power = power.add(power);
    }
    return result;
}

fn base(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}

fn writeSecure(columns: []const []M31, row: usize, value: QM31) void {
    for (columns, value.toM31Array()) |column, coordinate|
        column[row] = coordinate;
}

test "machine DMA lookup binds instruction HALT wake and exact services" {
    var flat = try runner.Memory.init(std.testing.allocator);
    defer flat.deinit();
    flat.write(0xc000, 0);
    var cpu = runner.Cpu{ .pc = 0xc000 };
    const cases = [_]scheduler_machine.CartridgeStepResult{
        dmaLookupInstruction(try runner.step(&cpu, &flat)),
        dmaLookupHalt(.halt_idle),
        dmaLookupHalt(.halt_wake),
        dmaLookupService(false),
        dmaLookupService(true),
    };
    for (cases) |result| {
        const one = [_]scheduler_machine.CartridgeStepResult{result};
        var trace = try binding.generateFromMachineExecution(
            std.testing.allocator,
            0,
            result.m_cycles,
            .{},
            &one,
            &.{},
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
    var trace = try binding.generateFromMachineExecution(
        std.testing.allocator,
        20,
        25,
        .{ .clock = 20 },
        &one,
        &.{},
    );
    defer trace.deinit(std.testing.allocator);
    trace.rows[0].provenance.cycle = 1;
    try std.testing.expectError(
        error.DmaExecutionLookupSumNonZero,
        generateInteraction(
            std.testing.allocator,
            &one,
            20,
            4,
            trace.rows,
            Relations.dummy(),
        ),
    );
    trace.rows[0].provenance.cycle = 0;
    trace.rows[0].mcycle += 1;
    try std.testing.expectError(
        error.DmaExecutionLookupSumNonZero,
        generateInteraction(
            std.testing.allocator,
            &one,
            20,
            4,
            trace.rows,
            Relations.dummy(),
        ),
    );
    trace.rows[0].mcycle -= 1;
    try std.testing.expectError(
        error.DmaExecutionCountMismatch,
        generateInteraction(
            std.testing.allocator,
            &one,
            20,
            4,
            trace.rows[0 .. trace.rows.len - 1],
            Relations.dummy(),
        ),
    );
    var forged = service;
    forged.service.cycles[1].kind = .no_access;
    const forged_one = [_]scheduler_machine.CartridgeStepResult{forged};
    try std.testing.expectError(
        error.NonCanonicalMachineResult,
        generateInteraction(
            std.testing.allocator,
            &forged_one,
            20,
            4,
            trace.rows,
            Relations.dummy(),
        ),
    );
}

fn dmaLookupInstruction(
    instruction: runner.StepTrace,
) scheduler_machine.CartridgeStepResult {
    var step = runner.CartridgeStepTrace{
        .instruction = instruction,
        .accesses = [_]?runner.cartridge_memory.Access{null} **
            runner.MAX_BUS_CYCLES,
    };
    step.accesses[0] = dmaLookupAccess(0xc000, .read, 0);
    return .{
        .before = dmaLookupState(instruction.before, 0, 0, 0),
        .after = dmaLookupState(instruction.after, 4, 0, 0),
        .event = .instruction,
        .m_cycles = instruction.cycle_count,
        .instruction = step,
    };
}

fn dmaLookupHalt(
    event: scheduler_machine.SchedulerEvent,
) scheduler_machine.CartridgeStepResult {
    const queued: u8 = @intFromBool(event == .halt_wake);
    const before = dmaLookupState(
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

fn dmaLookupService(
    halted: bool,
) scheduler_machine.CartridgeStepResult {
    const cpu = runner.Cpu{
        .pc = 0xc000,
        .sp = 0xc100,
        .ime = true,
        .halted = halted,
    };
    var after_cpu = cpu;
    after_cpu.pc = 0x40;
    after_cpu.sp -%= 2;
    after_cpu.ime = false;
    after_cpu.halted = false;
    const offset: u3 = @intFromBool(halted);
    var result = scheduler_machine.CartridgeStepResult{
        .before = dmaLookupState(cpu, 0, 1, 1),
        .after = dmaLookupState(
            after_cpu,
            @as(u16, 4) * (5 + offset),
            0,
            1,
        ),
        .event = .interrupt_service,
        .m_cycles = 5 + offset,
        .interrupt_index = 0,
    };
    result.service.count = 5 + offset;
    if (halted) result.service.cycles[0].kind = .halt_idle;
    result.service.cycles[offset] = .{
        .kind = .dummy_read,
        .access = dmaLookupAccess(0xc000, .read, 0),
    };
    result.service.cycles[offset + 1].kind = .oam_bug;
    result.service.cycles[offset + 2].kind = .no_access;
    result.service.cycles[offset + 3] = .{
        .kind = .stack_high,
        .access = dmaLookupAccess(0xc0ff, .write, 0xc0),
    };
    result.service.cycles[offset + 4] = .{
        .kind = .stack_low,
        .access = dmaLookupAccess(0xc0fe, .write, 0),
    };
    result.service.ie_resample = .{
        .after_cycle = offset + 3,
        .value = 1,
    };
    result.service.if_resample = .{
        .after_cycle = offset + 4,
        .value = 1,
    };
    result.service.acknowledgement = .{
        .during_cycle = offset + 4,
        .index = 0,
        .before = 1,
        .after = 0,
    };
    return result;
}

fn dmaLookupState(
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

fn dmaLookupAccess(
    address: u16,
    action: runner.cartridge_memory.Action,
    value: u8,
) runner.cartridge_memory.Access {
    return .{
        .logical_address = address,
        .action = action,
        .region = .system,
        .physical_offset = null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = value,
    };
}
