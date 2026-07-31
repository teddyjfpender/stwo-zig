//! Direct, sampled, and prover-domain controls for scheduler provenance.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const cartridge = @import("../cartridge/mod.zig");
const runner = @import("../runner/mod.zig");
const machine = @import("../runner/machine.zig");
const execution = @import("execution.zig");
const scheduler = @import("scheduler.zig");
const scheduler_component = @import("scheduler_component.zig");
const subject = @import("scheduler_binding.zig");
const adapter = @import("scheduler_binding_component.zig");

const SCHEDULER_OFFSET: usize = 0;
const EXECUTION_OFFSET: usize = scheduler_component.N_MAIN_COLUMNS;
const PROVENANCE_OFFSET: usize =
    EXECUTION_OFFSET + execution.N_MAIN_COLUMNS;
const N_COMBINED_COLUMNS: usize =
    PROVENANCE_OFFSET + subject.N_PROVENANCE_COLUMNS;
const SCHEDULER_EVENT_OFFSET: usize = 2;
const SCHEDULER_IE_OFFSET: usize = 2 + 9;
const SCHEDULER_IF_OFFSET: usize = 2 + 14;
const SCHEDULER_POST_IF_OFFSET: usize = 2 + 26;
const SCHEDULER_BEFORE_IME_OFFSET: usize = 2 + 39;
const SCHEDULER_BEFORE_HALTED_OFFSET: usize = 2 + 41;
const SCHEDULER_BEFORE_HALT_BUG_OFFSET: usize = 2 + 42;
const SCHEDULER_AFTER_PENDING_OFFSET: usize = 2 + 44;
const SCHEDULER_AFTER_HALTED_OFFSET: usize = 2 + 45;
const SCHEDULER_AFTER_HALT_BUG_OFFSET: usize = 2 + 46;
const SCHEDULER_MCYCLE_BITS_OFFSET: usize =
    2 + scheduler.N_MAIN_COLUMNS - 5;
const EXECUTION_CLOCK_OFFSET: usize = execution.N_MAIN_COLUMNS - 3;
const EXECUTION_BUS_OFFSET: usize = 2 * execution.N_STATE_COLUMNS;
const PROGRAM_START: u16 = 0x0200;

const Fixture = struct {
    rom: *[cartridge.header.ROM_SIZE]u8,
    sram: *[cartridge.header.RAM_SIZE]u8,
    system: *[runner.cartridge_memory.SYSTEM_SIZE]u8,
    memory: runner.cartridge_memory.Memory,

    fn init(program: []const u8) !Fixture {
        const allocator = std.testing.allocator;
        const rom = try allocator.create([cartridge.header.ROM_SIZE]u8);
        errdefer allocator.destroy(rom);
        const sram = try allocator.create([cartridge.header.RAM_SIZE]u8);
        errdefer allocator.destroy(sram);
        const system = try allocator.create(
            [runner.cartridge_memory.SYSTEM_SIZE]u8,
        );
        errdefer allocator.destroy(system);
        @memset(rom, 0);
        @memset(sram, 0);
        @memset(system, 0);
        @memcpy(
            rom[PROGRAM_START .. PROGRAM_START + program.len],
            program,
        );
        rom[cartridge.header.CARTRIDGE_TYPE_OFFSET] =
            cartridge.header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
        rom[cartridge.header.ROM_SIZE_CODE_OFFSET] =
            cartridge.header.ROM_SIZE_CODE_1_MIB;
        rom[cartridge.header.RAM_SIZE_CODE_OFFSET] =
            cartridge.header.RAM_SIZE_CODE_32_KIB;
        rom[cartridge.header.HEADER_CHECKSUM_OFFSET] =
            cartridge.header.headerChecksum(rom);
        std.mem.writeInt(
            u16,
            rom[cartridge.header.GLOBAL_CHECKSUM_OFFSET..cartridge.header.HEADER_END][0..2],
            cartridge.header.globalChecksum(rom),
            .big,
        );
        const loaded = try cartridge.Cartridge.init(rom);
        return .{
            .rom = rom,
            .sram = sram,
            .system = system,
            .memory = runner.cartridge_memory.Memory.init(
                loaded,
                sram,
                system,
                .{},
                0xff,
            ),
        };
    }

    fn deinit(self: *Fixture) void {
        const allocator = std.testing.allocator;
        allocator.destroy(self.system);
        allocator.destroy(self.sram);
        allocator.destroy(self.rom);
        self.* = undefined;
    }
};

test "scheduler binding has exact cubic L plus one geometry" {
    const scheduler_values =
        [_]Degree{Degree.variable()} **
        scheduler_component.N_MAIN_COLUMNS;
    const execution_values =
        [_]Degree{Degree.variable()} ** execution.N_MAIN_COLUMNS;
    const provenance_values =
        [_]Degree{Degree.variable()} ** subject.N_PROVENANCE_COLUMNS;
    const evaluation = try subject.evaluate(
        Degree,
        &scheduler_values,
        &execution_values,
        &provenance_values,
    );
    var maximum: u32 = 0;
    for (evaluation.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    try std.testing.expectEqual(subject.MAX_CONSTRAINT_DEGREE, maximum);
    try std.testing.expectEqual(@as(usize, 31), subject.N_CONSTRAINTS);

    const component = adapter.Component{
        .log_size = 4,
        .scheduler_offset = 3,
        .execution_offset = 57,
        .provenance_offset = 124,
    };
    try std.testing.expectEqual(
        subject.N_CONSTRAINTS,
        component.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(u32, 5),
        component.maxConstraintLogDegreeBound(),
    );
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();
    var bounds =
        try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), bounds.items[0].len);
    try std.testing.expectEqual(@as(usize, 130), bounds.items[1].len);
    var mask = try component.maskPoints(
        std.testing.allocator,
        core.circle.SECURE_FIELD_CIRCLE_GEN,
        component.maxConstraintLogDegreeBound(),
    );
    defer mask.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), mask.items[0].len);
    try std.testing.expectEqual(@as(usize, 130), mask.items[1].len);

    var overlapping = component;
    overlapping.execution_offset = 20;
    try std.testing.expectError(
        error.OverlappingSchedulerBindingColumns,
        overlapping.traceLogDegreeBounds(std.testing.allocator),
    );
    overlapping = component;
    overlapping.provenance_offset = 60;
    try std.testing.expectError(
        error.OverlappingSchedulerBindingColumns,
        overlapping.traceLogDegreeBounds(std.testing.allocator),
    );
}

test "scheduler binding accepts only canonical instruction provenance" {
    const steps = try instructionSteps();
    var mcycle: u32 = 100;
    for (steps) |step| {
        const columns = try subject.columns(step, mcycle);
        try std.testing.expect(
            (try subject.evaluateM31(columns)).allZero(),
        );
        mcycle += step.m_cycles;
    }

    const idle = haltResult(false);
    const wake = haltResult(true);
    for ([_]machine.CartridgeStepResult{ idle, wake }, 0..) |
        result,
        index,
    | {
        try std.testing.expect(result.hasCanonicalShape());
        const columns = try subject.columns(result, @intCast(200 + index));
        try std.testing.expect(
            (try subject.evaluateM31(columns)).allZero(),
        );
    }

    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    var cartridge_machine = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START },
    );
    const cartridge_instruction = try cartridge_machine.step();
    try std.testing.expect(cartridge_instruction.hasCanonicalShape());
    try std.testing.expect(
        (try subject.evaluateM31(
            try subject.columns(cartridge_instruction, 300),
        )).allZero(),
    );
    fixture.system[0xffff] = 1;
    fixture.system[0xff0f] = 1;
    cartridge_machine = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START, .sp = 0xc000, .ime = true },
    );
    const service = try cartridge_machine.step();
    const service_columns = try subject.columns(service, 301);
    const service_evaluation = try subject.evaluateM31(service_columns);
    if (!service_evaluation.allZero()) {
        for (service_evaluation.values, 0..) |value, index|
            if (!value.isZero())
                std.debug.print(
                    "nonzero service binding constraint {d}: {any}\n",
                    .{ index, value },
                );
    }
    try std.testing.expect(service_evaluation.allZero());
    try std.testing.expectEqual(
        M31.one(),
        service_columns.provenance_main[
            subject.EVENT_OFFSET +
                @intFromEnum(machine.SchedulerEvent.interrupt_service)
        ],
    );
    const service_execution = try execution.Row(M31).fromColumns(
        &service_columns.execution_main,
    );
    for (service_execution.bus, 0..) |cycle, index| {
        try std.testing.expectEqual(
            M31.fromCanonical(@intFromBool(index < service.m_cycles)),
            cycle.active,
        );
        try std.testing.expectEqual(
            M31.fromCanonical(@intFromBool(index == 0)),
            cycle.read,
        );
        try std.testing.expectEqual(
            M31.fromCanonical(@intFromBool(index == 3 or index == 4)),
            cycle.write,
        );
    }

    fixture.system[0xff0f] = 1;
    cartridge_machine = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{
            .pc = PROGRAM_START,
            .sp = 0xc000,
            .ime = true,
            .halted = true,
        },
    );
    const halted_service = try cartridge_machine.step();
    const halted_service_columns = try subject.columns(halted_service, 307);
    try std.testing.expect(
        (try subject.evaluateM31(halted_service_columns)).allZero(),
    );
    const halted_service_execution = try execution.Row(M31).fromColumns(
        &halted_service_columns.execution_main,
    );
    try std.testing.expect(halted_service.before.cpu.halted);
    try std.testing.expectEqual(
        M31.zero(),
        halted_service_execution.bus[0].read,
    );
    try std.testing.expectEqual(
        M31.one(),
        halted_service_execution.bus[1].read,
    );

    var halt_bug_memory = try runner.Memory.init(std.testing.allocator);
    defer halt_bug_memory.deinit();
    halt_bug_memory.write(0, 0x76);
    halt_bug_memory.write(1, 0x06);
    halt_bug_memory.write(2, 0x99);
    halt_bug_memory.write(0xffff, 1);
    halt_bug_memory.write(0xff0f, 1);
    var halt_bug_machine = machine.Machine.init(&halt_bug_memory, .{});
    const halt_bug_start = try halt_bug_machine.step();
    const duplicated_fetch = try halt_bug_machine.step();
    try std.testing.expect(halt_bug_start.after.halt_bug);
    try std.testing.expect(duplicated_fetch.before.halt_bug);
    try std.testing.expect(
        (try subject.evaluateM31(
            try subject.columns(halt_bug_start, 400),
        )).allZero(),
    );
    try std.testing.expect(
        (try subject.evaluateM31(
            try subject.columns(duplicated_fetch, 401),
        )).allZero(),
    );

    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0xffff, 1);
    memory.write(0xff0f, 1);
    var service_machine = machine.Machine.init(
        &memory,
        .{ .ime = true, .sp = 0xc000 },
    );
    try std.testing.expectError(
        error.UnsupportedSchedulerEvent,
        subject.columns(try service_machine.step(), 0),
    );
}

test "scheduler binding rejects event clock cycle state and vacuity mutations" {
    const steps = try instructionSteps();
    const honest = try subject.columns(steps[0], 7);
    for ([_]Mutation{
        .scheduler_active,
        .scheduler_event,
        .provenance_event,
        .provenance_event_relabel,
        .scheduler_clock,
        .scheduler_cycles,
        .execution_clock,
        .scheduler_before_ime,
        .scheduler_after_pending,
        .scheduler_before_halted,
        .scheduler_after_halted,
        .scheduler_before_halt_bug,
        .scheduler_after_halt_bug,
        .provenance_before_halt_bug,
        .provenance_after_halt_bug,
        .before_ime,
        .after_pending,
        .before_halted,
        .after_halted,
        .before_stopped,
        .after_stopped,
        .bus_active,
        .bus_read,
        .bus_write,
        .bus_program,
    }) |mutation| {
        var forged = honest;
        mutate(&forged, mutation);
        try std.testing.expect(
            !(try subject.evaluateM31(forged)).allZero(),
        );
    }

    var halt = try subject.columns(haltResult(false), 17);
    halt.execution_main[EXECUTION_BUS_OFFSET] = M31.one();
    try std.testing.expect(
        !(try subject.evaluateM31(halt)).allZero(),
    );
    halt = try subject.columns(haltResult(true), 18);
    halt.execution_main[EXECUTION_BUS_OFFSET + 1] = M31.one();
    try std.testing.expect(
        !(try subject.evaluateM31(halt)).allZero(),
    );

    var vacuous = honest;
    @memset(&vacuous.scheduler_main, M31.zero());
    @memset(&vacuous.execution_main, M31.zero());
    @memset(&vacuous.provenance_main, M31.zero());
    try std.testing.expect(
        !(try subject.evaluateM31(vacuous)).allZero(),
    );
}

test "scheduler binding leaves IE and IF to the stated memory relation" {
    const steps = try instructionSteps();
    const honest = try subject.columns(steps[0], 0);
    for ([_]usize{
        SCHEDULER_IE_OFFSET,
        SCHEDULER_IF_OFFSET,
        SCHEDULER_POST_IF_OFFSET,
    }) |offset| {
        var columns = honest;
        columns.scheduler_main[offset] = M31.one();
        try std.testing.expect(
            (try subject.evaluateM31(columns)).allZero(),
        );
        try std.testing.expect(
            (try scheduler.evaluate(
                columns.scheduler_main[2..].*,
                true,
            )).allZero(),
        );
    }
}

test "scheduler binding sampled adapter rejects every provenance class" {
    const steps = try instructionSteps();
    const honest = try subject.columns(steps[0], 9);
    var values: [N_COMBINED_COLUMNS]QM31 = undefined;
    writeCombined(QM31, &values, honest);
    var columns: [N_COMBINED_COLUMNS][]QM31 = undefined;
    for (&columns, 0..) |*column, index|
        column.* = values[index .. index + 1];
    const component = adapter.Component{
        .log_size = 4,
        .scheduler_offset = SCHEDULER_OFFSET,
        .execution_offset = EXECUTION_OFFSET,
        .provenance_offset = PROVENANCE_OFFSET,
    };
    try std.testing.expect(
        (try component.evaluateSampled(&columns)).allZero(),
    );

    for ([_]usize{
        SCHEDULER_OFFSET,
        SCHEDULER_EVENT_OFFSET,
        PROVENANCE_OFFSET + subject.EVENT_OFFSET,
        SCHEDULER_MCYCLE_BITS_OFFSET,
        SCHEDULER_BEFORE_IME_OFFSET,
        SCHEDULER_BEFORE_HALT_BUG_OFFSET,
        EXECUTION_OFFSET + EXECUTION_CLOCK_OFFSET,
        EXECUTION_OFFSET + @intFromEnum(execution.StateIndex.ime),
        EXECUTION_OFFSET + execution.N_STATE_COLUMNS +
            @intFromEnum(execution.StateIndex.halted),
        EXECUTION_OFFSET + @intFromEnum(execution.StateIndex.stopped),
        EXECUTION_OFFSET + EXECUTION_BUS_OFFSET + 2,
    }) |column_index| {
        values[column_index] = flipSecure(values[column_index]);
        try std.testing.expect(
            !(try component.evaluateSampled(&columns)).allZero(),
        );
        values[column_index] = flipSecure(values[column_index]);
    }
}

test "scheduler binding domain rejects clock event state and vacuity" {
    const log_size: u32 = 4;
    const evaluation_log_size = log_size + 1;
    const evaluation_size: usize = 1 << evaluation_log_size;
    const steps = try instructionSteps();
    const honest = try subject.columns(steps[0], 0);
    var main_values =
        [_][evaluation_size]M31{
            [_]M31{M31.zero()} ** evaluation_size,
        } ** N_COMBINED_COLUMNS;
    var combined: [N_COMBINED_COLUMNS]M31 = undefined;
    writeCombined(M31, &combined, honest);
    for (&main_values, combined) |*values, value|
        @memset(values, value);

    var preprocessed = [_]prover_component.Poly{};
    var main: [N_COMBINED_COLUMNS]prover_component.Poly = undefined;
    for (&main, &main_values) |*polynomial, *values|
        polynomial.* = .{
            .log_size = evaluation_log_size,
            .values = values,
        };
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
    };
    const trace = prover_component.Trace{
        .polys = core.pcs.TreeVec(
            []const prover_component.Poly,
        ).initOwned(&trees),
    };
    const component = adapter.Component{
        .log_size = log_size,
        .scheduler_offset = SCHEDULER_OFFSET,
        .execution_offset = EXECUTION_OFFSET,
        .provenance_offset = PROVENANCE_OFFSET,
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);
    try expectDomain(
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        true,
    );

    for ([_]usize{
        SCHEDULER_EVENT_OFFSET,
        PROVENANCE_OFFSET + subject.EVENT_OFFSET,
        SCHEDULER_MCYCLE_BITS_OFFSET,
        SCHEDULER_AFTER_HALTED_OFFSET,
        SCHEDULER_AFTER_HALT_BUG_OFFSET,
        EXECUTION_OFFSET + EXECUTION_CLOCK_OFFSET,
        EXECUTION_OFFSET + @intFromEnum(execution.StateIndex.ime),
        EXECUTION_OFFSET + @intFromEnum(execution.StateIndex.stopped),
    }) |column| {
        main_values[column][0] = flip(main_values[column][0]);
        try expectDomain(
            &component,
            &trace,
            challenge,
            evaluation_log_size,
            false,
        );
        main_values[column][0] = flip(main_values[column][0]);
    }
    for (&main_values) |*values| @memset(values, M31.zero());
    try expectDomain(
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
}

const Mutation = enum {
    scheduler_active,
    scheduler_event,
    provenance_event,
    provenance_event_relabel,
    scheduler_clock,
    scheduler_cycles,
    execution_clock,
    scheduler_before_ime,
    scheduler_after_pending,
    scheduler_before_halted,
    scheduler_after_halted,
    scheduler_before_halt_bug,
    scheduler_after_halt_bug,
    provenance_before_halt_bug,
    provenance_after_halt_bug,
    before_ime,
    after_pending,
    before_halted,
    after_halted,
    before_stopped,
    after_stopped,
    bus_active,
    bus_read,
    bus_write,
    bus_program,
};

fn mutate(columns: *subject.Columns, mutation: Mutation) void {
    switch (mutation) {
        .scheduler_active => columns.scheduler_main[0] = flip(columns.scheduler_main[0]),
        .scheduler_event => columns.scheduler_main[SCHEDULER_EVENT_OFFSET] =
            flip(columns.scheduler_main[SCHEDULER_EVENT_OFFSET]),
        .provenance_event => columns.provenance_main[subject.EVENT_OFFSET] =
            flip(columns.provenance_main[subject.EVENT_OFFSET]),
        .provenance_event_relabel => {
            columns.provenance_main[subject.EVENT_OFFSET] = M31.zero();
            columns.provenance_main[
                subject.EVENT_OFFSET +
                    @intFromEnum(machine.SchedulerEvent.halt_idle)
            ] = M31.one();
        },
        .scheduler_clock => columns.scheduler_main[1] =
            columns.scheduler_main[1].add(M31.one()),
        .scheduler_cycles => columns.scheduler_main[SCHEDULER_MCYCLE_BITS_OFFSET] =
            flip(columns.scheduler_main[SCHEDULER_MCYCLE_BITS_OFFSET]),
        .execution_clock => columns.execution_main[EXECUTION_CLOCK_OFFSET] =
            columns.execution_main[EXECUTION_CLOCK_OFFSET]
                .add(M31.one()),
        .scheduler_before_ime => columns.scheduler_main[
            SCHEDULER_BEFORE_IME_OFFSET
        ] = flip(columns.scheduler_main[SCHEDULER_BEFORE_IME_OFFSET]),
        .scheduler_after_pending => columns.scheduler_main[
            SCHEDULER_AFTER_PENDING_OFFSET
        ] = flip(columns.scheduler_main[SCHEDULER_AFTER_PENDING_OFFSET]),
        .scheduler_before_halted => columns.scheduler_main[
            SCHEDULER_BEFORE_HALTED_OFFSET
        ] = flip(columns.scheduler_main[SCHEDULER_BEFORE_HALTED_OFFSET]),
        .scheduler_after_halted => columns.scheduler_main[
            SCHEDULER_AFTER_HALTED_OFFSET
        ] = flip(columns.scheduler_main[SCHEDULER_AFTER_HALTED_OFFSET]),
        .scheduler_before_halt_bug => columns.scheduler_main[
            SCHEDULER_BEFORE_HALT_BUG_OFFSET
        ] = flip(columns.scheduler_main[SCHEDULER_BEFORE_HALT_BUG_OFFSET]),
        .scheduler_after_halt_bug => columns.scheduler_main[
            SCHEDULER_AFTER_HALT_BUG_OFFSET
        ] = flip(columns.scheduler_main[SCHEDULER_AFTER_HALT_BUG_OFFSET]),
        .provenance_before_halt_bug => columns.provenance_main[
            subject.BEFORE_HALT_BUG_OFFSET
        ] = flip(columns.provenance_main[subject.BEFORE_HALT_BUG_OFFSET]),
        .provenance_after_halt_bug => columns.provenance_main[
            subject.AFTER_HALT_BUG_OFFSET
        ] = flip(columns.provenance_main[subject.AFTER_HALT_BUG_OFFSET]),
        .before_ime => columns.execution_main[
            @intFromEnum(execution.StateIndex.ime)
        ] = flip(columns.execution_main[
            @intFromEnum(execution.StateIndex.ime)
        ]),
        .after_pending => columns.execution_main[
            execution.N_STATE_COLUMNS +
                @intFromEnum(
                    execution.StateIndex.ime_enable_pending,
                )
        ] = flip(columns.execution_main[
            execution.N_STATE_COLUMNS +
                @intFromEnum(
                    execution.StateIndex.ime_enable_pending,
                )
        ]),
        .before_halted => columns.execution_main[
            @intFromEnum(execution.StateIndex.halted)
        ] = flip(columns.execution_main[
            @intFromEnum(execution.StateIndex.halted)
        ]),
        .after_halted => columns.execution_main[
            execution.N_STATE_COLUMNS +
                @intFromEnum(execution.StateIndex.halted)
        ] = flip(columns.execution_main[
            execution.N_STATE_COLUMNS +
                @intFromEnum(execution.StateIndex.halted)
        ]),
        .before_stopped => columns.execution_main[
            @intFromEnum(execution.StateIndex.stopped)
        ] = M31.one(),
        .after_stopped => columns.execution_main[
            execution.N_STATE_COLUMNS +
                @intFromEnum(execution.StateIndex.stopped)
        ] = M31.one(),
        .bus_active => columns.execution_main[
            EXECUTION_BUS_OFFSET + 2
        ] = M31.zero(),
        .bus_read => columns.execution_main[
            EXECUTION_BUS_OFFSET + 3
        ] = M31.zero(),
        .bus_write => columns.execution_main[
            EXECUTION_BUS_OFFSET + 4
        ] = M31.one(),
        .bus_program => columns.execution_main[
            EXECUTION_BUS_OFFSET + 5
        ] = M31.zero(),
    }
}

fn instructionSteps() ![16]machine.StepResult {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    @memset(memory.bytes[0..16], 0);
    var scheduler_machine = machine.Machine.init(&memory, .{});
    var result: [16]machine.StepResult = undefined;
    for (&result) |*step|
        step.* = try scheduler_machine.step();
    return result;
}

fn haltResult(wake: bool) machine.CartridgeStepResult {
    const interrupt: u8 = @intFromBool(wake);
    const before = machine.MachineState{
        .cpu = .{ .halted = true },
        .halt_bug = false,
        .div_counter = 0,
        .tima = 0,
        .tma = 0,
        .tac = 0,
        .timer_reload = .running,
        .interrupt_flags = interrupt,
        .interrupt_enable = interrupt,
    };
    var after = before;
    after.cpu.halted = !wake;
    return .{
        .before = before,
        .after = after,
        .event = if (wake) .halt_wake else .halt_idle,
        .m_cycles = 1,
    };
}

fn writeCombined(
    comptime S: type,
    output: *[N_COMBINED_COLUMNS]S,
    columns: subject.Columns,
) void {
    for (
        output[SCHEDULER_OFFSET..][0..scheduler_component.N_MAIN_COLUMNS],
        columns.scheduler_main,
    ) |*destination, source| destination.* = lift(S, source);
    for (
        output[EXECUTION_OFFSET..][0..execution.N_MAIN_COLUMNS],
        columns.execution_main,
    ) |*destination, source| destination.* = lift(S, source);
    for (
        output[PROVENANCE_OFFSET..][0..subject.N_PROVENANCE_COLUMNS],
        columns.provenance_main,
    ) |*destination, source| destination.* = lift(S, source);
}

fn lift(comptime S: type, value: M31) S {
    if (S == M31) return value;
    return S.fromBase(value);
}

fn expectDomain(
    component: *const adapter.Component,
    trace: *const prover_component.Trace,
    challenge: QM31,
    evaluation_log_size: u32,
    expected: bool,
) !void {
    var accumulator =
        try prover_accumulation.DomainEvaluationAccumulator.init(
            std.testing.allocator,
            challenge,
            evaluation_log_size,
            component.nConstraints(),
        );
    defer accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(
        trace,
        &accumulator,
    );
    var result = try accumulator.finalize();
    defer result.deinit(std.testing.allocator);
    var zero = true;
    for (0..result.len()) |row|
        zero = zero and result.at(row).isZero();
    try std.testing.expectEqual(expected, zero);
}

fn flip(value: M31) M31 {
    return if (value.isZero()) M31.one() else M31.zero();
}

fn flipSecure(value: QM31) QM31 {
    return if (value.isZero()) QM31.one() else QM31.zero();
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
