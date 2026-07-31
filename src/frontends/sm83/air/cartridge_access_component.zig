//! Execution-bound component for six packed cartridge-access cycle rows.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const cartridge = @import("../cartridge/mod.zig");
const isa = @import("../isa/mod.zig");
const cartridge_access = @import("cartridge_access.zig");
const component_domain = @import("component_domain.zig");
const execution = @import("execution.zig");
const runner = @import("../runner/mod.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const N_MAPPER_COLUMNS: usize = 11;
const N_BINDING_CONSTRAINTS: usize = 4;

pub const N_MAIN_COLUMNS: usize =
    execution.N_BUS_CYCLES * cartridge_access.N_MAIN_COLUMNS;
pub const N_CONSTRAINTS: usize =
    execution.N_BUS_CYCLES *
    (cartridge_access.N_CONSTRAINTS + N_BINDING_CONSTRAINTS + 2) +
    (execution.N_BUS_CYCLES - 1) * N_MAPPER_COLUMNS +
    2 * N_MAPPER_COLUMNS + 1;

pub fn PackedRow(comptime S: type) type {
    return struct {
        cycles: [execution.N_BUS_CYCLES]cartridge_access.Semantics(S).Row,

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != N_MAIN_COLUMNS)
                return error.InvalidMainTraceShape;
            var cycles: [execution.N_BUS_CYCLES]cartridge_access.Semantics(S).Row =
                undefined;
            for (&cycles, 0..) |*cycle, index| {
                const offset = index * cartridge_access.N_MAIN_COLUMNS;
                cycle.* = try cartridge_access.Semantics(S).Row.fromColumns(
                    values[offset..][0..cartridge_access.N_MAIN_COLUMNS],
                );
            }
            return .{ .cycles = cycles };
        }
    };
}

pub fn Evaluation(comptime S: type) type {
    return struct {
        values: [N_CONSTRAINTS]S,

        pub fn allZero(self: @This()) bool {
            for (self.values) |value|
                if (!value.isZero()) return false;
            return true;
        }
    };
}

pub fn evaluateRows(
    comptime S: type,
    machine: execution.Row(S),
    current: PackedRow(S),
    next: PackedRow(S),
    is_first: S,
    is_last: S,
    initial: cartridge.mbc3.State,
    final: cartridge.mbc3.State,
    allow_joypad_mmio: bool,
    allow_timer_mmio: bool,
    allow_ppu_mmio: bool,
    allow_apu_mmio: bool,
    allow_open_bus: bool,
) Evaluation(S) {
    var out: [N_CONSTRAINTS]S = undefined;
    var at: usize = 0;
    const one = S.one();
    for (current.cycles, machine.bus) |cycle, bus| {
        const semantic =
            cartridge_access.Semantics(S).evaluate(cycle, bus.active);
        @memcpy(out[at..][0..cartridge_access.N_CONSTRAINTS], &semantic.values);
        at += cartridge_access.N_CONSTRAINTS;
        out[at] = cycle.bus_actions[1].sub(bus.read);
        at += 1;
        out[at] = cycle.bus_actions[2].sub(bus.write);
        at += 1;
        out[at] = compose(S, cycle.bus_address).sub(bus.address);
        at += 1;
        out[at] = compose(S, cycle.bus_value).sub(bus.value);
        at += 1;
        out[at] =
            (if (allow_joypad_mmio) S.zero() else cycle.regions[
                @intFromEnum(runner.cartridge_memory.Region.joypad_mmio)
            ]).add(
                if (allow_timer_mmio) S.zero() else cycle.regions[
                    @intFromEnum(runner.cartridge_memory.Region.timer_mmio)
                ],
            ).add(
                if (allow_ppu_mmio) S.zero() else cycle.regions[
                    @intFromEnum(runner.cartridge_memory.Region.ppu_mmio)
                ],
            ).add(
                if (allow_apu_mmio) S.zero() else cycle.regions[
                    @intFromEnum(runner.cartridge_memory.Region.apu_mmio)
                ],
            );
        at += 1;
        out[at] = if (allow_open_bus)
            S.zero()
        else
            cycle.regions[
                @intFromEnum(
                    runner.cartridge_memory.Region.cartridge_open_bus,
                )
            ];
        at += 1;
    }
    for (0..execution.N_BUS_CYCLES - 1) |index| {
        const active = machine.bus[index + 1].active;
        for (
            mapperAfter(current.cycles[index]),
            mapperBefore(current.cycles[index + 1]),
        ) |after, before| {
            out[at] = active.mul(after.sub(before));
            at += 1;
        }
    }
    const initial_values = mapperConstants(S, initial);
    for (
        mapperBefore(current.cycles[0]),
        initial_values,
    ) |actual, expected| {
        out[at] = is_first.mul(actual.sub(expected));
        at += 1;
    }
    const final_values = mapperConstants(S, final);
    for (0..N_MAPPER_COLUMNS) |column| {
        var last = S.zero();
        for (0..execution.N_BUS_CYCLES) |cycle| {
            const next_active = if (cycle + 1 < execution.N_BUS_CYCLES)
                machine.bus[cycle + 1].active
            else
                S.zero();
            const selector =
                machine.bus[cycle].active.mul(one.sub(next_active));
            last = last.add(
                selector.mul(mapperAfter(current.cycles[cycle])[column]),
            );
        }
        const expected = is_last.mul(final_values[column]).add(
            one.sub(is_last).mul(
                mapperBefore(next.cycles[0])[column],
            ),
        );
        out[at] = last.sub(expected);
        at += 1;
    }
    out[at] = machine.bus[0].active.sub(one);
    at += 1;
    std.debug.assert(at == out.len);
    return .{ .values = out };
}

pub fn columns(
    trace: runner.CartridgeStepTrace,
) ![N_MAIN_COLUMNS]M31 {
    const validated = try cartridge_access.ValidatedStep.init(trace);
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    for (0..execution.N_BUS_CYCLES) |cycle| {
        const source = if (cycle < trace.instruction.cycle_count)
            cartridge_access.columnsForCycle(validated, cycle)
        else
            cartridge_access.inactiveColumns();
        const offset = cycle * cartridge_access.N_MAIN_COLUMNS;
        @memcpy(
            out[offset..][0..cartridge_access.N_MAIN_COLUMNS],
            &source,
        );
    }
    return out;
}

pub const Component = struct {
    log_size: u32,
    is_first_column: usize,
    is_last_column: usize,
    execution_offset: usize,
    main_offset: usize,
    initial: cartridge.mbc3.State,
    final: cartridge.mbc3.State,
    allow_joypad_mmio: bool = false,
    allow_timer_mmio: bool = false,
    allow_ppu_mmio: bool = false,
    allow_apu_mmio: bool = false,
    allow_open_bus: bool = true,

    const Self = @This();
    const Adapter = core_air_derive.ComponentAdapter(
        Self,
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn asVerifierComponent(self: *const Self) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const Self) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn nConstraints(_: *const Self) usize {
        return N_CONSTRAINTS;
    }

    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.dupe(u32, &.{
            self.log_size,
            self.log_size,
        });
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc(u32, N_MAIN_COLUMNS);
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{ preprocessed, main }),
        );
    }

    pub fn maskPoints(
        self: *const Self,
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        if (max_log_degree_bound < self.log_size)
            return error.InvalidProofShape;
        const preprocessed =
            try component_domain.currentPointColumns(allocator, 2, point);
        errdefer component_domain.freePointColumns(allocator, preprocessed);
        const main = try component_domain.currentAndNextPointColumns(
            allocator,
            N_MAIN_COLUMNS,
            point,
            nextRowPoint(max_log_degree_bound, point),
        );
        errdefer component_domain.freePointColumns(allocator, main);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{
                preprocessed,
                main,
            }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(usize, &.{
            self.is_first_column,
            self.is_last_column,
        });
    }

    pub fn evaluateRow(
        self: *const Self,
        machine_values: []const QM31,
        current_values: []const QM31,
        next_values: []const QM31,
        is_first: QM31,
        is_last: QM31,
    ) !Evaluation(QM31) {
        return evaluateRows(
            QM31,
            try execution.Row(QM31).fromColumns(machine_values),
            try PackedRow(QM31).fromColumns(current_values),
            try PackedRow(QM31).fromColumns(next_values),
            is_first,
            is_last,
            self.initial,
            self.final,
            self.allow_joypad_mmio,
            self.allow_timer_mmio,
            self.allow_ppu_mmio,
            self.allow_apu_mmio,
            self.allow_open_bus,
        );
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const Self,
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (max_log_degree_bound < self.log_size or mask.items.len < 2)
            return error.InvalidProofShape;
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        if (preprocessed.len <= self.is_first_column or
            preprocessed.len <= self.is_last_column or
            preprocessed[self.is_first_column].len < 1 or
            preprocessed[self.is_last_column].len < 1 or
            main.len < self.execution_offset + execution.N_MAIN_COLUMNS or
            main.len < self.main_offset + N_MAIN_COLUMNS)
            return error.InvalidProofShape;
        var machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
        for (
            &machine,
            main[self.execution_offset..][0..execution.N_MAIN_COLUMNS],
        ) |*value, column| {
            if (column.len < 1) return error.InvalidProofShape;
            value.* = column[0];
        }
        var current: [N_MAIN_COLUMNS]QM31 = undefined;
        var next: [N_MAIN_COLUMNS]QM31 = undefined;
        for (
            &current,
            &next,
            main[self.main_offset..][0..N_MAIN_COLUMNS],
        ) |*current_value, *next_value, column| {
            if (column.len != 2) return error.InvalidProofShape;
            current_value.* = column[0];
            next_value.* = column[1];
        }
        const evaluation = try self.evaluateRow(
            &machine,
            &current,
            &next,
            preprocessed[self.is_first_column][0],
            preprocessed[self.is_last_column][0],
        );
        const inverse = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.log_size),
        ).inv();
        for (evaluation.values) |constraint|
            accumulator.accumulate(constraint.mul(inverse));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const Self,
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace.polys.items.len < 2) return error.InvalidProofShape;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        if (preprocessed.len <= self.is_first_column or
            preprocessed.len <= self.is_last_column or
            main.len < self.execution_offset + execution.N_MAIN_COLUMNS or
            main.len < self.main_offset + N_MAIN_COLUMNS)
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const evaluations = try allocator.alloc(
            []const M31,
            2 + execution.N_MAIN_COLUMNS + N_MAIN_COLUMNS,
        );
        defer allocator.free(evaluations);
        var extensions = std.ArrayList([]M31).empty;
        defer {
            for (extensions.items) |values| allocator.free(values);
            extensions.deinit(allocator);
        }
        evaluations[0] = try component_domain.evaluationValues(
            allocator,
            preprocessed[self.is_first_column],
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        evaluations[1] = try component_domain.evaluationValues(
            allocator,
            preprocessed[self.is_last_column],
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        for (
            main[self.execution_offset..][0..execution.N_MAIN_COLUMNS],
            evaluations[2 .. 2 + execution.N_MAIN_COLUMNS],
        ) |polynomial, *values| {
            values.* = try component_domain.evaluationValues(
                allocator,
                polynomial,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extensions,
            );
        }
        for (
            main[self.main_offset..][0..N_MAIN_COLUMNS],
            evaluations[2 + execution.N_MAIN_COLUMNS ..],
        ) |polynomial, *values| {
            values.* = try component_domain.evaluationValues(
                allocator,
                polynomial,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extensions,
            );
        }
        if (extensions.items.len != 0) {
            var twiddles = try prover_twiddles.precomputeM31(
                allocator,
                domain.half_coset,
            );
            defer prover_twiddles.deinitM31(allocator, &twiddles);
            try prover_poly.evaluateBuffersWithTwiddles(
                extensions.items,
                domain,
                prover_twiddles.TwiddleTree([]const M31).init(
                    twiddles.root_coset,
                    twiddles.twiddles,
                    twiddles.itwiddles,
                ),
            );
        }
        const inverses = try component_domain.quotientDenominators(
            allocator,
            self.log_size,
            evaluation_log_size,
            domain,
        );
        defer allocator.free(inverses);
        var accumulators = try accumulator.columns(
            allocator,
            &.{.{
                .log_size = evaluation_log_size,
                .n_cols = N_CONSTRAINTS,
            }},
        );
        defer allocator.free(accumulators);
        const column = &accumulators[0];
        const shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        for (0..evaluation_size) |row| {
            const next_row = utils.offsetBitReversedCircleDomainIndex(
                row,
                self.log_size,
                evaluation_log_size,
                1,
            );
            var machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
            for (
                &machine,
                evaluations[2 .. 2 + execution.N_MAIN_COLUMNS],
            ) |*value, values|
                value.* = QM31.fromBase(values[row]);
            var current: [N_MAIN_COLUMNS]QM31 = undefined;
            var next: [N_MAIN_COLUMNS]QM31 = undefined;
            for (
                &current,
                &next,
                evaluations[2 + execution.N_MAIN_COLUMNS ..],
            ) |*current_value, *next_value, values| {
                current_value.* = QM31.fromBase(values[row]);
                next_value.* = QM31.fromBase(values[next_row]);
            }
            const evaluation = try self.evaluateRow(
                &machine,
                &current,
                &next,
                QM31.fromBase(evaluations[0][row]),
                QM31.fromBase(evaluations[1][row]),
            );
            var folded = QM31.zero();
            for (evaluation.values, 0..) |constraint, index| {
                const powers = column.random_coeff_powers;
                folded = folded.add(
                    powers[powers.len - 1 - index].mul(constraint),
                );
            }
            column.accumulate(
                row,
                folded.mulM31(inverses[row >> shift]),
            );
        }
    }
};

fn mapperBefore(row: anytype) [N_MAPPER_COLUMNS]@TypeOf(row.before_enabled) {
    return row.before_rom ++ row.before_ram ++ .{row.before_enabled};
}

fn mapperAfter(row: anytype) [N_MAPPER_COLUMNS]@TypeOf(row.after_enabled) {
    return row.after_rom ++ row.after_ram ++ .{row.after_enabled};
}

fn mapperConstants(
    comptime S: type,
    state: cartridge.mbc3.State,
) [N_MAPPER_COLUMNS]S {
    var result: [N_MAPPER_COLUMNS]S = undefined;
    for (0..7) |index|
        result[index] = fromBool(
            S,
            state.rom_bank_register >> @intCast(index) & 1 == 1,
        );
    for (0..3) |index|
        result[7 + index] = fromBool(
            S,
            state.ram_bank_register >> @intCast(index) & 1 == 1,
        );
    result[10] = fromBool(S, state.ram_enabled);
    return result;
}

fn fromBool(comptime S: type, value: bool) S {
    return if (value) S.one() else S.zero();
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

fn nextRowPoint(log_size: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.add(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}

test "cartridge access component binds execution bus and mapper boundary" {
    const trace = try syntheticRead(.{});
    const source = try columns(trace);
    var source_qm31: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&source_qm31, source) |*value, item|
        value.* = QM31.fromBase(item);
    const machine_source = execution.columns(trace.instruction, 0);
    var machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&machine, machine_source) |*value, item|
        value.* = QM31.fromBase(item);
    const component = Component{
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .execution_offset = 0,
        .main_offset = execution.N_MAIN_COLUMNS,
        .initial = .{},
        .final = .{},
    };
    try std.testing.expectEqual(
        @as(u32, 5),
        component.maxConstraintLogDegreeBound(),
    );
    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(N_MAIN_COLUMNS, bounds.items[1].len);
    var mask = try component.maskPoints(
        std.testing.allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        component.maxConstraintLogDegreeBound(),
    );
    defer mask.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(N_MAIN_COLUMNS, mask.items[1].len);
    try std.testing.expect(
        (try component.evaluateRow(
            &machine,
            &source_qm31,
            &source_qm31,
            QM31.one(),
            QM31.one(),
        )).allZero(),
    );
    machine[2 * execution.N_STATE_COLUMNS + 1] =
        QM31.fromBase(M31.fromCanonical(0x43));
    try std.testing.expect(
        !(try component.evaluateRow(
            &machine,
            &source_qm31,
            &source_qm31,
            QM31.one(),
            QM31.one(),
        )).allZero(),
    );

    const device_trace = try syntheticSpecialRead(
        runner.joypad.P1_ADDRESS,
        .joypad_mmio,
    );
    const device_source = try columns(device_trace);
    var device_source_qm31: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&device_source_qm31, device_source) |*value, item|
        value.* = QM31.fromBase(item);
    const device_machine_source = execution.columns(
        device_trace.instruction,
        0,
    );
    var device_machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&device_machine, device_machine_source) |*value, item|
        value.* = QM31.fromBase(item);
    var attached = component;
    attached.allow_joypad_mmio = true;
    try std.testing.expect(
        (try attached.evaluateRow(
            &device_machine,
            &device_source_qm31,
            &device_source_qm31,
            QM31.one(),
            QM31.one(),
        )).allZero(),
    );
    var detached = component;
    detached.allow_timer_mmio = true;
    try std.testing.expect(
        !(try detached.evaluateRow(
            &device_machine,
            &device_source_qm31,
            &device_source_qm31,
            QM31.one(),
            QM31.one(),
        )).allZero(),
    );

    const open_trace = try syntheticSpecialRead(
        cartridge.mbc3.RAM_START,
        .cartridge_open_bus,
    );
    const open_source = try columns(open_trace);
    var open_source_qm31: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&open_source_qm31, open_source) |*value, item|
        value.* = QM31.fromBase(item);
    const open_machine_source = execution.columns(
        open_trace.instruction,
        0,
    );
    var open_machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&open_machine, open_machine_source) |*value, item|
        value.* = QM31.fromBase(item);
    var no_open_bus = component;
    no_open_bus.allow_open_bus = false;
    try std.testing.expect(
        !(try no_open_bus.evaluateRow(
            &open_machine,
            &open_source_qm31,
            &open_source_qm31,
            QM31.one(),
            QM31.one(),
        )).allZero(),
    );
}

fn syntheticRead(
    mapper: cartridge.mbc3.State,
) !runner.CartridgeStepTrace {
    const offset: runner.cartridge_memory.PhysicalOffset =
        @as(runner.cartridge_memory.PhysicalOffset, mapper.selectedRomBank()) *
        @as(
            runner.cartridge_memory.PhysicalOffset,
            cartridge.header.ROM_BANK_SIZE,
        );
    var trace: runner.CartridgeStepTrace = undefined;
    trace.instruction.before = .{};
    trace.instruction.after = .{ .pc = 1 };
    trace.instruction.decoded = try isa.decode(&.{0x42});
    trace.instruction.cycle_count = 1;
    trace.instruction.branch_taken = false;
    trace.instruction.result = null;
    trace.instruction.cycles[0] = .{
        .address = 0x4000,
        .value = 0x42,
        .action = .read,
    };
    trace.accesses = [_]?runner.cartridge_memory.Access{null} ** 6;
    trace.accesses[0] = .{
        .logical_address = 0x4000,
        .action = .read,
        .region = .cartridge_rom,
        .physical_offset = offset,
        .mapper_before = mapper,
        .mapper_after = mapper,
        .value = 0x42,
    };
    return trace;
}

fn syntheticSpecialRead(
    address: u16,
    region: runner.cartridge_memory.Region,
) !runner.CartridgeStepTrace {
    var trace: runner.CartridgeStepTrace = undefined;
    trace.instruction.before = .{
        .h = @truncate(address >> 8),
        .l = @truncate(address),
    };
    trace.instruction.after = .{
        .a = 0xcf,
        .h = @truncate(address >> 8),
        .l = @truncate(address),
        .pc = 1,
    };
    trace.instruction.decoded = try isa.decode(&.{0x7e});
    trace.instruction.cycle_count = 2;
    trace.instruction.branch_taken = false;
    trace.instruction.result = 0xcf;
    trace.instruction.cycles[0] = .{
        .address = 0,
        .value = 0x7e,
        .action = .read,
    };
    trace.instruction.cycles[1] = .{
        .address = address,
        .value = 0xcf,
        .action = .read,
    };
    trace.accesses = [_]?runner.cartridge_memory.Access{null} ** 6;
    trace.accesses[0] = .{
        .logical_address = 0,
        .action = .read,
        .region = .cartridge_rom,
        .physical_offset = 0,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = 0x7e,
    };
    trace.accesses[1] = .{
        .logical_address = address,
        .action = .read,
        .region = region,
        .physical_offset = null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = 0xcf,
    };
    return trace;
}
