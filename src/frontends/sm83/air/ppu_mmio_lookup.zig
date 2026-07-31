//! LogUp joins between execution M-cycles and PPU binding events.
//!
//! Three independently challenged multisets prevent omission, duplication, or
//! substitution of one PPU tick per M-cycle and FF40/41/42/43/44/45/4A
//! writes/reads.
//! The ignored LY-write byte is lookup-owned: it has no PPU semantic effect,
//! but remains bound to the authenticated execution access.

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
const ppu_air = @import("ppu_timing.zig");
const ppu_binding = @import("ppu_binding.zig");
const ppu_mmio = @import("../runner/ppu_mmio.zig");

pub const N_RELATIONS: usize = 3;
pub const N_EXECUTION_SUMS: usize = execution.N_BUS_CYCLES;
pub const N_EXECUTION_INTERACTION_COLUMNS: usize =
    N_RELATIONS * N_EXECUTION_SUMS * 4;
pub const N_PPU_INTERACTION_COLUMNS: usize = N_RELATIONS * 4;
pub const N_EXECUTION_CONSTRAINTS: usize =
    N_RELATIONS * N_EXECUTION_SUMS;
pub const N_PPU_BINDING_CONSTRAINTS: usize = 2;
pub const N_PPU_CONSTRAINTS: usize =
    N_RELATIONS + N_PPU_BINDING_CONSTRAINTS;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

pub const RelationIndex = enum(usize) { tick, write, read };

const TAGS = [N_RELATIONS]u32{
    0x5050_4d01,
    0x5050_4d02,
    0x5050_4d03,
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
    ppu: [N_RELATIONS]QM31,
};

pub const AuxiliaryWitness = struct {
    log_size: u32,
    event_count: usize,
    ly_write_values: []M31,
    allocator: std.mem.Allocator,
    values_owned: bool = true,

    pub fn disown(self: *AuxiliaryWitness) void {
        self.values_owned = false;
    }

    pub fn deinit(self: *AuxiliaryWitness) void {
        if (self.values_owned)
            self.allocator.free(self.ly_write_values);
        self.* = undefined;
    }
};

pub const Interaction = struct {
    execution_columns: [N_EXECUTION_INTERACTION_COLUMNS][]M31,
    ppu_columns: [N_PPU_INTERACTION_COLUMNS][]M31,
    claims: Claims,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Interaction) void {
        for (self.execution_columns) |column| self.allocator.free(column);
        for (self.ppu_columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn generateAuxiliaryWitness(
    allocator: std.mem.Allocator,
    log_size: u32,
    events: []const ppu_binding.EventRow,
) !AuxiliaryWitness {
    const size = try traceSize(log_size);
    if (events.len > size) return error.TooManyPpuEvents;
    const values = try allocator.alloc(M31, size);
    errdefer allocator.free(values);
    @memset(values, M31.zero());
    for (events, 0..) |event, row| {
        _ = try ppu_binding.columns(event);
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row,
        );
        if (event.ignored_ly_write) |value|
            values[storage] = M31.fromCanonical(value);
    }
    return .{
        .log_size = log_size,
        .event_count = events.len,
        .ly_write_values = values,
        .allocator = allocator,
    };
}

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    steps: anytype,
    initial_mcycle: u32,
    events: []const ppu_binding.EventRow,
    auxiliary: *const AuxiliaryWitness,
    relations: Relations,
) !Interaction {
    if (steps.len == 0 or !std.math.isPowerOfTwo(steps.len))
        return error.InvalidExecutionTraceLength;
    if (comptime std.meta.Elem(@TypeOf(steps)) ==
        scheduler_machine.CartridgeStepResult)
        try ppu_binding.validateMachineExecutionRows(
            events,
            steps,
            initial_mcycle,
        )
    else
        try ppu_binding.validateExecutionRows(
            events,
            steps,
            initial_mcycle,
        );
    const ppu_size = try traceSize(auxiliary.log_size);
    if (events.len > ppu_size or
        auxiliary.event_count != events.len or
        auxiliary.ly_write_values.len != ppu_size)
        return error.InvalidPpuAuxiliaryShape;
    var result = Interaction{
        .execution_columns = undefined,
        .ppu_columns = undefined,
        .claims = undefined,
        .allocator = allocator,
    };
    var execution_initialized: usize = 0;
    var ppu_initialized: usize = 0;
    errdefer {
        for (result.execution_columns[0..execution_initialized]) |column|
            allocator.free(column);
        for (result.ppu_columns[0..ppu_initialized]) |column|
            allocator.free(column);
    }
    for (&result.execution_columns) |*column| {
        column.* = try allocator.alloc(M31, steps.len);
        @memset(column.*, M31.zero());
        execution_initialized += 1;
    }
    for (&result.ppu_columns) |*column| {
        column.* = try allocator.alloc(M31, ppu_size);
        @memset(column.*, M31.zero());
        ppu_initialized += 1;
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

    var ppu_claims = [_]QM31{QM31.zero()} ** N_RELATIONS;
    for (0..ppu_size) |row_index| {
        const storage = try core_air_utils.circleBitReversedIndex(
            auxiliary.log_size,
            row_index,
        );
        const columns = if (row_index < events.len)
            try ppu_binding.columns(events[row_index])
        else
            ppu_binding.inactiveColumns();
        const row = try liftPpu(
            columns,
            auxiliary.ly_write_values[storage],
        );
        const pairs = ppuPairs(row, relations);
        for (0..N_RELATIONS) |relation_index| {
            ppu_claims[relation_index] = try accumulate(
                ppu_claims[relation_index],
                pairs[relation_index],
            );
            writeSecure(
                result.ppu_columns[4 * relation_index ..][0..4],
                storage,
                ppu_claims[relation_index],
            );
        }
    }
    result.claims = .{
        .execution = execution_claims,
        .ppu = ppu_claims,
    };
    return result;
}

const StepColumns = struct {
    execution: [execution.N_MAIN_COLUMNS]M31,
    access: [cartridge_access_component.N_MAIN_COLUMNS]M31,
};

fn stepColumns(step: anytype, mcycle: u32) !StepColumns {
    if (comptime @TypeOf(step) ==
        scheduler_machine.CartridgeStepResult)
    {
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
    if (comptime @TypeOf(step) ==
        scheduler_machine.CartridgeStepResult)
        return step.m_cycles;
    return step.instruction.cycle_count;
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
        const region = source.regions[
            @intFromEnum(runner.cartridge_memory.Region.ppu_mmio)
        ];
        const read = region.mul(source.access_actions[
            @intFromEnum(runner.cartridge_memory.Action.read)
        ]);
        const write = region.mul(source.access_actions[
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

pub fn PpuRow(comptime S: type) type {
    return struct {
        active: S,
        semantic: ppu_air.Semantics(S).Row,
        mcycle: S,
        phases: [4]S,
        read_markers: [7]S,
        read_value: [8]S,
        ly_write_enabled: S,
        ly_write_value: S,
        latch_write_markers: [3]S,
        latch_write_value: S,
    };
}

pub fn ppuRow(
    comptime S: type,
    values: []const S,
    ly_write_value: S,
) !PpuRow(S) {
    if (values.len != ppu_binding.N_MAIN_COLUMNS)
        return error.InvalidPpuBindingShape;
    return .{
        .active = values[0],
        .semantic = try ppu_air.Semantics(S).Row.fromColumns(
            values[1..ppu_binding.MCYCLE_OFFSET],
        ),
        .mcycle = values[ppu_binding.MCYCLE_OFFSET],
        .phases = values[ppu_binding.PHASE_OFFSET..ppu_binding.READ_MARKER_OFFSET].*,
        .read_markers = values[ppu_binding.READ_MARKER_OFFSET..ppu_binding.READ_VALUE_OFFSET].*,
        .read_value = values[ppu_binding.READ_VALUE_OFFSET..ppu_binding.LY_WRITE_ENABLED_OFFSET].*,
        .ly_write_enabled = values[
            ppu_binding.LY_WRITE_ENABLED_OFFSET
        ],
        .ly_write_value = ly_write_value,
        .latch_write_markers = values[ppu_binding.LATCH_WRITE_MARKER_OFFSET..ppu_binding.LATCH_WRITE_VALUE_OFFSET].*,
        .latch_write_value = values[
            ppu_binding.LATCH_WRITE_VALUE_OFFSET
        ],
    };
}

pub fn ppuPairs(
    row: PpuRow(QM31),
    relations: Relations,
) [N_RELATIONS]Pair {
    const write_selectors = [7]QM31{
        row.semantic.events[1],
        row.semantic.events[2],
        row.latch_write_markers[0],
        row.latch_write_markers[1],
        row.ly_write_enabled,
        row.semantic.events[3],
        row.latch_write_markers[2],
    };
    const write = sum(QM31, &write_selectors);
    const read = sum(QM31, &row.read_markers);
    const write_value = compose(QM31, row.semantic.action)
        .add(row.ly_write_enabled.mul(row.ly_write_value))
        .add(sum(QM31, &row.latch_write_markers).mul(
        row.latch_write_value,
    ));
    return .{
        pair(
            row.phases[3],
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
                selectedAddress(QM31, &write_selectors),
                write_value,
            ),
        ),
        pair(
            read,
            relations.at(.read).combine(
                row.mcycle,
                selectedAddress(QM31, &row.read_markers),
                compose(QM31, &row.read_value),
            ),
        ),
    };
}

pub fn ppuBindingConstraints(
    comptime S: type,
    row: PpuRow(S),
) [N_PPU_BINDING_CONSTRAINTS]S {
    const one = S.one();
    return .{
        one.sub(row.active).mul(row.ly_write_value),
        one.sub(row.ly_write_enabled).mul(row.ly_write_value),
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
        var total = claims.ppu[relation_index];
        for (claims.execution[relation_index]) |claim|
            total = total.add(claim);
        if (!total.isZero()) return error.PpuMmioLookupSumNonZero;
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
            return error.PpuMmioLookupZeroDenominator,
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

fn liftPpu(
    columns: [ppu_binding.N_MAIN_COLUMNS]M31,
    ly_write_value: M31,
) !PpuRow(QM31) {
    var lifted: [ppu_binding.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, columns) |*target, source|
        target.* = QM31.fromBase(source);
    return ppuRow(
        QM31,
        &lifted,
        QM31.fromBase(ly_write_value),
    );
}

fn selectedAddress(
    comptime S: type,
    selectors: *const [7]S,
) S {
    const addresses = [_]u32{
        ppu_mmio.LCDC_ADDRESS,
        ppu_mmio.STAT_ADDRESS,
        ppu_mmio.SCY_ADDRESS,
        ppu_mmio.SCX_ADDRESS,
        ppu_mmio.LY_ADDRESS,
        ppu_mmio.LYC_ADDRESS,
        ppu_mmio.WY_ADDRESS,
    };
    var result = S.zero();
    for (selectors, addresses) |selector, address|
        result = result.add(selector.mul(constant(S, address)));
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

test "machine PPU lookup binds instruction HALT wake and exact services" {
    var flat = try runner.Memory.init(std.testing.allocator);
    defer flat.deinit();
    flat.write(0xc000, 0);
    var cpu = runner.Cpu{ .pc = 0xc000 };
    const cases = [_]scheduler_machine.CartridgeStepResult{
        ppuMachineInstruction(try runner.step(&cpu, &flat)),
        ppuMachineHalt(.halt_idle),
        ppuMachineHalt(.halt_wake),
        ppuMachineService(false),
        ppuMachineService(true),
    };
    for (cases) |result| {
        const one = [_]scheduler_machine.CartridgeStepResult{result};
        var trace = try ppu_binding.generateFromMachineExecution(
            std.testing.allocator,
            0,
            result.m_cycles,
            .{},
            &one,
        );
        defer trace.deinit(std.testing.allocator);
        var auxiliary = try generateAuxiliaryWitness(
            std.testing.allocator,
            5,
            trace.rows,
        );
        defer auxiliary.deinit();
        var interaction = try generateInteraction(
            std.testing.allocator,
            &one,
            0,
            trace.rows,
            &auxiliary,
            Relations.dummy(),
        );
        defer interaction.deinit();
        try verifyCancellation(interaction.claims);
    }

    const service = cases[3];
    const one = [_]scheduler_machine.CartridgeStepResult{service};
    var trace = try ppu_binding.generateFromMachineExecution(
        std.testing.allocator,
        20,
        25,
        .{},
        &one,
    );
    defer trace.deinit(std.testing.allocator);
    var auxiliary = try generateAuxiliaryWitness(
        std.testing.allocator,
        5,
        trace.rows,
    );
    defer auxiliary.deinit();
    trace.rows[0].provenance.execution_tick.position.cycle = 1;
    try std.testing.expectError(
        error.InvalidPpuTickProvenance,
        generateInteraction(
            std.testing.allocator,
            &one,
            20,
            trace.rows,
            &auxiliary,
            Relations.dummy(),
        ),
    );
    trace.rows[0].provenance.execution_tick.position.cycle = 0;
    trace.rows[0].mcycle += 1;
    try std.testing.expectError(
        error.DisconnectedPpuTrace,
        generateInteraction(
            std.testing.allocator,
            &one,
            20,
            trace.rows,
            &auxiliary,
            Relations.dummy(),
        ),
    );
    trace.rows[0].mcycle -= 1;
    var omitted = try generateAuxiliaryWitness(
        std.testing.allocator,
        5,
        trace.rows[0 .. trace.rows.len - 1],
    );
    defer omitted.deinit();
    try std.testing.expectError(
        error.InvalidPpuTraceEndpoint,
        generateInteraction(
            std.testing.allocator,
            &one,
            20,
            trace.rows[0 .. trace.rows.len - 1],
            &omitted,
            Relations.dummy(),
        ),
    );
}

fn ppuMachineInstruction(
    instruction: runner.StepTrace,
) scheduler_machine.CartridgeStepResult {
    var step = runner.CartridgeStepTrace{
        .instruction = instruction,
        .accesses = [_]?runner.cartridge_memory.Access{null} **
            runner.MAX_BUS_CYCLES,
    };
    step.accesses[0] = ppuMachineAccess(0xc000, .read, 0);
    return .{
        .before = ppuMachineState(instruction.before, 0, 0, 0),
        .after = ppuMachineState(instruction.after, 4, 0, 0),
        .event = .instruction,
        .m_cycles = instruction.cycle_count,
        .instruction = step,
    };
}

fn ppuMachineHalt(
    event: scheduler_machine.SchedulerEvent,
) scheduler_machine.CartridgeStepResult {
    const queued: u8 = @intFromBool(event == .halt_wake);
    const before = ppuMachineState(
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

fn ppuMachineService(
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
        .before = ppuMachineState(cpu, 0, 1, 1),
        .after = ppuMachineState(
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
        .access = ppuMachineAccess(0xc000, .read, 0),
    };
    result.service.cycles[offset + 1].kind = .oam_bug;
    result.service.cycles[offset + 2].kind = .no_access;
    result.service.cycles[offset + 3] = .{
        .kind = .stack_high,
        .access = ppuMachineAccess(0xc0ff, .write, 0xc0),
    };
    result.service.cycles[offset + 4] = .{
        .kind = .stack_low,
        .access = ppuMachineAccess(0xc0fe, .write, 0),
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

fn ppuMachineState(
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

fn ppuMachineAccess(
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
