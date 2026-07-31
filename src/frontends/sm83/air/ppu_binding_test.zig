const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const prover_accumulation =
    @import("stwo_prover_engine").air.accumulation;
const prover_component =
    @import("stwo_prover_engine").air.component_prover;
const binding = @import("ppu_binding.zig");
const subject = @import("ppu_binding_component.zig");
const runner = @import("../runner/mod.zig");

test {
    _ = @import("ppu_binding_component_test.zig");
    _ = @import("ppu_binding_request_test.zig");
    _ = @import("ppu_binding_latch_test.zig");
}

test "PPU binding schedules access before exactly four dot phases" {
    const cycles = [_]binding.Cycle{
        .{ .access = .{ .write = .{
            .register = .lcdc,
            .value = 0x91,
        } } },
        .{ .access = .{ .read = .{
            .register = .lcdc,
            .value = 0x91,
        } } },
        .{ .access = .{ .write = .{
            .register = .ly,
            .value = 0xa5,
        } } },
        .{ .access = .{ .write = .{
            .register = .lyc,
            .value = 0x22,
        } } },
        .{ .access = .{ .read = .{
            .register = .lyc,
            .value = 0x22,
        } } },
    };
    var trace = try binding.generateTrace(
        std.testing.allocator,
        7,
        12,
        .{},
        &cycles,
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 22), trace.rows.len);
    try std.testing.expectEqual(@as(u32, 12), trace.final_mcycle);
    try std.testing.expectEqual(@as(u8, 0x91), trace.final_state.lcdc);
    try std.testing.expectEqual(@as(u8, 0x22), trace.final_state.timing.lyc);

    var dots: usize = 0;
    var timing_writes: usize = 0;
    var ignored_writes: usize = 0;
    var reads: usize = 0;
    for (trace.rows) |row| {
        const values = try binding.columns(row);
        if (row.dot_phase) |phase| {
            try std.testing.expect(
                values[binding.PHASE_OFFSET + phase].isOne(),
            );
            dots += 1;
        } else {
            timing_writes += 1;
        }
        ignored_writes += @intFromBool(row.ignored_ly_write != null);
        reads += @intFromBool(row.read_register != null);
    }
    try std.testing.expectEqual(@as(usize, 20), dots);
    try std.testing.expectEqual(@as(usize, 2), timing_writes);
    try std.testing.expectEqual(@as(usize, 1), ignored_writes);
    try std.testing.expectEqual(@as(usize, 2), reads);

    var witness = try binding.generateWitness(
        std.testing.allocator,
        trace,
    );
    defer witness.deinit();
    try std.testing.expectEqual(@as(u32, 5), witness.log_size);
    try std.testing.expectEqual(trace.rows.len, witness.event_count);
}

test "PPU binding exposes all pre-tick reads and rejects malformed rows" {
    const cycles = [_]binding.Cycle{
        .{ .access = .{ .read = .{
            .register = .lcdc,
            .value = 0,
        } } },
        .{ .access = .{ .read = .{
            .register = .stat,
            .value = 0x80,
        } } },
        .{ .access = .{ .read = .{
            .register = .scy,
            .value = 0x12,
        } } },
        .{ .access = .{ .read = .{
            .register = .scx,
            .value = 0x34,
        } } },
        .{ .access = .{ .read = .{
            .register = .ly,
            .value = 0,
        } } },
        .{ .access = .{ .read = .{
            .register = .lyc,
            .value = 0,
        } } },
        .{ .access = .{ .read = .{
            .register = .wy,
            .value = 0x56,
        } } },
    };
    var trace = try binding.generateTrace(
        std.testing.allocator,
        0,
        7,
        .{ .scy = 0x12, .scx = 0x34, .wy = 0x56 },
        &cycles,
    );
    defer trace.deinit(std.testing.allocator);
    for (0..7) |cycle| {
        const row = trace.rows[cycle * 4];
        try std.testing.expectEqual(
            @as(?binding.Register, @enumFromInt(cycle)),
            row.read_register,
        );
    }

    var wrong_read = cycles;
    wrong_read[1].access.?.read.value = 0;
    try std.testing.expectError(
        error.InvalidPpuReadValue,
        binding.generateTrace(
            std.testing.allocator,
            0,
            7,
            .{ .scy = 0x12, .scx = 0x34, .wy = 0x56 },
            &wrong_read,
        ),
    );
    var wrong_phase = trace.rows[0];
    wrong_phase.dot_phase = 1;
    try std.testing.expectError(
        error.InvalidPpuAccessPhase,
        binding.columns(wrong_phase),
    );
    var wrong_lcdc = trace.rows[0];
    wrong_lcdc.lcdc_after = 1;
    try std.testing.expectError(
        error.InvalidLcdcState,
        binding.columns(wrong_lcdc),
    );
}

test "execution metadata generates PPU rows and rejects relabeling" {
    const Region = runner.cartridge_memory.Region;
    const ppu = runner.ppu_mmio;
    const steps = [_]runner.CartridgeStepTrace{
        accessStep(ppu.LCDC_ADDRESS, .write, 0x91, .ppu_mmio),
        accessStep(ppu.STAT_ADDRESS, .write, 0x70, .ppu_mmio),
        accessStep(ppu.LY_ADDRESS, .write, 0xa5, .ppu_mmio),
        accessStep(ppu.LYC_ADDRESS, .write, 0x22, .ppu_mmio),
        accessStep(ppu.LCDC_ADDRESS, .read, 0x91, .ppu_mmio),
    };
    var trace = try binding.generateFromExecution(
        std.testing.allocator,
        0,
        steps.len,
        .{},
        &steps,
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 23), trace.rows.len);
    try std.testing.expectEqual(@as(u8, 0x91), trace.final_state.lcdc);
    try std.testing.expectEqual(@as(u8, 0x22), trace.final_state.timing.lyc);
    try std.testing.expectEqual(@as(?u8, 0xa5), trace.rows[10].ignored_ly_write);
    try std.testing.expectEqual(
        @as(?binding.Register, .lcdc),
        trace.rows[19].read_register,
    );
    var witness = try binding.generateExecutionWitness(
        std.testing.allocator,
        trace,
        &steps,
        0,
    );
    defer witness.deinit();

    for (0..steps.len) |index| {
        var relabeled = steps;
        relabeled[index].accesses[0].?.region = .system;
        try std.testing.expectError(
            error.InvalidExecutionStep,
            binding.generateFromExecution(
                std.testing.allocator,
                0,
                relabeled.len,
                .{},
                &relabeled,
            ),
        );
    }

    trace.rows[0].provenance = .detached;
    try std.testing.expectError(
        error.InvalidPpuWriteProvenance,
        binding.generateExecutionWitness(
            std.testing.allocator,
            trace,
            &steps,
            0,
        ),
    );

    const ordinary = accessStep(0xc000, .read, 0x42, Region.system);
    var ordinary_trace = try binding.generateFromExecution(
        std.testing.allocator,
        0,
        1,
        .{},
        &.{ordinary},
    );
    defer ordinary_trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 4), ordinary_trace.rows.len);
}

test "PPU execution metadata classifies exactly seven register addresses" {
    const exact = [_]struct {
        address: u16,
        register: binding.Register,
    }{
        .{ .address = 0xff40, .register = .lcdc },
        .{ .address = 0xff41, .register = .stat },
        .{ .address = 0xff42, .register = .scy },
        .{ .address = 0xff43, .register = .scx },
        .{ .address = 0xff44, .register = .ly },
        .{ .address = 0xff45, .register = .lyc },
        .{ .address = 0xff4a, .register = .wy },
    };
    var classified: usize = 0;
    for (0..1 << 16) |raw| {
        const address: u16 = @intCast(raw);
        if (binding.registerForAddress(address)) |_| classified += 1;
    }
    try std.testing.expectEqual(@as(usize, 7), classified);
    for (exact) |item|
        try std.testing.expectEqual(
            @as(?binding.Register, item.register),
            binding.registerForAddress(item.address),
        );

    for ([_]u16{ 0xff3f, 0xff46, 0xff49, 0xff4b }) |address| {
        const mislabeled = accessStep(
            address,
            .write,
            0,
            .ppu_mmio,
        );
        try std.testing.expectError(
            error.InvalidExecutionStep,
            binding.generateFromExecution(
                std.testing.allocator,
                0,
                1,
                .{},
                &.{mislabeled},
            ),
        );
    }
}

test "PPU binding component is exactly cubic and offset safe" {
    const variables =
        [_]Degree{Degree.variable()} ** binding.N_MAIN_COLUMNS;
    const evaluation = try subject.evaluateRows(
        Degree,
        &variables,
        &variables,
        Degree.variable(),
        Degree.variable(),
        7,
        8,
        .{},
        .{},
    );
    var maximum: u32 = 0;
    for (evaluation.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    try std.testing.expectEqual(subject.MAX_CONSTRAINT_DEGREE, maximum);
    try std.testing.expectEqual(@as(usize, 234), subject.N_CONSTRAINTS);

    const component = subject.Component{
        .log_size = 4,
        .is_first_column = 2,
        .is_last_column = 4,
        .main_offset = 7,
        .initial_mcycle = 7,
        .final_mcycle = 8,
        .initial = .{},
        .final = .{},
    };
    try std.testing.expectEqual(
        @as(u32, 5),
        component.maxConstraintLogDegreeBound(),
    );
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();
    var bounds = try component.traceLogDegreeBounds(
        std.testing.allocator,
    );
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), bounds.items[0].len);
    try std.testing.expectEqual(
        7 + binding.N_MAIN_COLUMNS,
        bounds.items[1].len,
    );
    var mask = try component.maskPoints(
        std.testing.allocator,
        core.circle.SECURE_FIELD_CIRCLE_GEN,
        component.maxConstraintLogDegreeBound(),
    );
    defer mask.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), mask.items[0].len);
    try std.testing.expectEqual(
        7 + binding.N_MAIN_COLUMNS,
        mask.items[1].len,
    );
}

test "PPU binding component binds phases reads clocks LCDC and endpoints" {
    var trace = try binding.generateTrace(
        std.testing.allocator,
        7,
        8,
        .{},
        &.{.{ .access = .{ .read = .{
            .register = .stat,
            .value = 0x80,
        } } }},
    );
    defer trace.deinit(std.testing.allocator);
    var rows: [4][binding.N_MAIN_COLUMNS]QM31 = undefined;
    for (&rows, trace.rows) |*target, source|
        target.* = try lift(try binding.columns(source));
    const inactive =
        [_]QM31{QM31.zero()} ** binding.N_MAIN_COLUMNS;
    const component = componentFor(trace);

    for (0..4) |index| {
        const next = if (index + 1 < rows.len)
            rows[index + 1][0..]
        else
            inactive[0..];
        try expect(
            &component,
            &rows[index],
            next,
            index == 0,
            false,
            true,
        );
    }

    var bad_phase = rows[1];
    bad_phase[binding.PHASE_OFFSET + 1] = QM31.zero();
    bad_phase[binding.PHASE_OFFSET + 2] = QM31.one();
    try expect(
        &component,
        &rows[0],
        &bad_phase,
        true,
        false,
        false,
    );
    var bad_read = rows[0];
    bad_read[binding.READ_VALUE_OFFSET + 7] = QM31.zero();
    try expect(
        &component,
        &bad_read,
        &rows[1],
        true,
        false,
        false,
    );
    var bad_clock = rows[3];
    bad_clock[binding.MCYCLE_OFFSET] =
        QM31.fromBase(M31.fromCanonical(8));
    try expect(
        &component,
        &bad_clock,
        &inactive,
        false,
        false,
        false,
    );
    var bad_lcdc = rows[2];
    bad_lcdc[binding.LCDC_AFTER_OFFSET] = QM31.one();
    try expect(
        &component,
        &bad_lcdc,
        &rows[3],
        false,
        false,
        false,
    );

    var forged_endpoint = component;
    forged_endpoint.initial.timing.lyc = 1;
    try expect(
        &forged_endpoint,
        &rows[0],
        &rows[1],
        true,
        false,
        false,
    );
    forged_endpoint = component;
    forged_endpoint.final.timing.lyc = 1;
    try expect(
        &forged_endpoint,
        &rows[3],
        &inactive,
        false,
        false,
        false,
    );

    for (binding.MCYCLE_OFFSET..binding.N_MAIN_COLUMNS) |column| {
        var forged = inactive;
        forged[column] = QM31.one();
        const evaluation = try subject.evaluateRows(
            QM31,
            &forged,
            &inactive,
            QM31.zero(),
            QM31.one(),
            7,
            8,
            .{},
            .{},
        );
        try std.testing.expect(!evaluation.allZero());
    }

    const empty = try subject.evaluateRows(
        QM31,
        &inactive,
        &inactive,
        QM31.one(),
        QM31.one(),
        7,
        8,
        .{},
        .{},
    );
    try std.testing.expect(!empty.allZero());
}

test "PPU binding component accepts every register-write schedule" {
    const cycles = [_]binding.Cycle{
        .{ .access = .{ .write = .{
            .register = .lcdc,
            .value = 0x91,
        } } },
        .{ .access = .{ .write = .{
            .register = .stat,
            .value = 0x70,
        } } },
        .{ .access = .{ .write = .{
            .register = .ly,
            .value = 0xa5,
        } } },
        .{ .access = .{ .write = .{
            .register = .lyc,
            .value = 0x22,
        } } },
    };
    var trace = try binding.generateTrace(
        std.testing.allocator,
        10,
        14,
        .{},
        &cycles,
    );
    defer trace.deinit(std.testing.allocator);
    const component = componentFor(trace);
    try expectTrace(&component, trace);

    var lcdc_write = try lift(try binding.columns(trace.rows[0]));
    const first_dot = try lift(try binding.columns(trace.rows[1]));
    lcdc_write[binding.LCDC_AFTER_OFFSET] =
        QM31.one().sub(lcdc_write[binding.LCDC_AFTER_OFFSET]);
    try expect(
        &component,
        &lcdc_write,
        &first_dot,
        true,
        false,
        false,
    );
}

test "PPU binding sampled and domain paths reject schedule mutation" {
    var trace = try binding.generateTrace(
        std.testing.allocator,
        7,
        8,
        .{},
        &.{.{}},
    );
    defer trace.deinit(std.testing.allocator);
    var rows: [4][binding.N_MAIN_COLUMNS]QM31 = undefined;
    var base_rows: [4][binding.N_MAIN_COLUMNS]M31 = undefined;
    for (&rows, &base_rows, trace.rows) |*lifted, *base, source| {
        base.* = try binding.columns(source);
        lifted.* = try lift(base.*);
    }
    const component = componentFor(trace);

    var preprocessed_storage =
        [_][1]QM31{.{QM31.zero()}} ** 2;
    preprocessed_storage[0][0] = QM31.one();
    var preprocessed: [2][]QM31 = undefined;
    for (&preprocessed, &preprocessed_storage) |*column, *values|
        column.* = values;
    var main_storage =
        [_][2]QM31{.{ QM31.zero(), QM31.zero() }} **
        binding.N_MAIN_COLUMNS;
    for (&main_storage, rows[0], rows[1]) |
        *values,
        current,
        next,
    | {
        values.* = .{ current, next };
    }
    var main: [binding.N_MAIN_COLUMNS][]QM31 = undefined;
    for (&main, &main_storage) |*column, *values|
        column.* = values;
    var trees = [_][][]QM31{ &preprocessed, &main };
    const mask = core.air.components.MaskValues.initOwned(&trees);
    var sampled =
        core.air.accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        core.circle.SECURE_FIELD_CIRCLE_GEN.mul(29),
        &mask,
        &sampled,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(sampled.finalize().isZero());
    main_storage[binding.PHASE_OFFSET + 1][1] = QM31.zero();
    var forged_sample =
        core.air.accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        core.circle.SECURE_FIELD_CIRCLE_GEN.mul(29),
        &mask,
        &forged_sample,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(!forged_sample.finalize().isZero());

    const log_size: u32 = 4;
    const evaluation_log_size: u32 = 5;
    const evaluation_size: usize = 1 << evaluation_log_size;
    var first_values = [_]M31{M31.zero()} ** evaluation_size;
    var last_values = [_]M31{M31.zero()} ** evaluation_size;
    var indices: [4]usize = undefined;
    indices[0] = 0;
    for (1..4) |index| indices[index] =
        core.utils.offsetBitReversedCircleDomainIndex(
            indices[index - 1],
            log_size,
            evaluation_log_size,
            1,
        );
    var last_index: ?usize = null;
    for (0..evaluation_size) |index| if (core.utils.offsetBitReversedCircleDomainIndex(
        index,
        log_size,
        evaluation_log_size,
        1,
    ) == 0) {
        last_index = index;
    };
    first_values[0] = M31.one();
    last_values[last_index orelse return error.InvalidProofShape] =
        M31.one();
    var main_values =
        [_][evaluation_size]M31{
            [_]M31{M31.zero()} ** evaluation_size,
        } ** binding.N_MAIN_COLUMNS;
    for (&main_values, 0..) |*values, column| {
        for (indices, base_rows) |index, row_value| {
            values[index] = row_value[column];
        }
    }
    var preprocessed_polys = [_]prover_component.Poly{
        .{ .log_size = evaluation_log_size, .values = &first_values },
        .{ .log_size = evaluation_log_size, .values = &last_values },
    };
    var main_polys: [binding.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    for (&main_polys, &main_values) |*polynomial, *values|
        polynomial.* = .{
            .log_size = evaluation_log_size,
            .values = values,
        };
    var poly_trees = [_][]const prover_component.Poly{
        &preprocessed_polys,
        &main_polys,
    };
    const domain_trace = prover_component.Trace{
        .polys = core.pcs.TreeVec(
            []const prover_component.Poly,
        ).initOwned(&poly_trees),
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);
    try expectDomain(
        &component,
        &domain_trace,
        challenge,
        evaluation_log_size,
        true,
    );
    main_values[binding.PHASE_OFFSET + 2][indices[2]] = M31.zero();
    try expectDomain(
        &component,
        &domain_trace,
        challenge,
        evaluation_log_size,
        false,
    );
}

fn componentFor(trace: binding.Trace) subject.Component {
    return .{
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial_mcycle = trace.rows[0].mcycle,
        .final_mcycle = trace.final_mcycle,
        .initial = .{
            .timing = trace.rows[0].transition.before,
            .lcdc = trace.rows[0].lcdc_before,
            .scy = trace.rows[0].latches_before[0],
            .scx = trace.rows[0].latches_before[1],
            .wy = trace.rows[0].latches_before[2],
        },
        .final = trace.final_state,
    };
}

fn accessStep(
    address: u16,
    action: runner.cartridge_memory.Action,
    value: u8,
    region: runner.cartridge_memory.Region,
) runner.CartridgeStepTrace {
    var step = std.mem.zeroes(runner.CartridgeStepTrace);
    step.instruction.cycle_count = 1;
    step.instruction.cycles[0] = .{
        .address = address,
        .value = value,
        .action = switch (action) {
            .read => .read,
            .write => .write,
        },
    };
    step.accesses[0] = .{
        .logical_address = address,
        .action = action,
        .region = region,
        .physical_offset = null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = value,
    };
    return step;
}

fn lift(
    values: [binding.N_MAIN_COLUMNS]M31,
) ![binding.N_MAIN_COLUMNS]QM31 {
    var result: [binding.N_MAIN_COLUMNS]QM31 = undefined;
    for (&result, values) |*target, source|
        target.* = QM31.fromBase(source);
    return result;
}

fn expect(
    component: *const subject.Component,
    current: []const QM31,
    next: []const QM31,
    is_first: bool,
    is_last: bool,
    expected: bool,
) !void {
    const evaluation = try component.evaluateRow(
        current,
        next,
        if (is_first) QM31.one() else QM31.zero(),
        if (is_last) QM31.one() else QM31.zero(),
    );
    try std.testing.expectEqual(expected, evaluation.allZero());
}

fn expectTrace(
    component: *const subject.Component,
    trace: binding.Trace,
) !void {
    const inactive =
        [_]QM31{QM31.zero()} ** binding.N_MAIN_COLUMNS;
    for (trace.rows, 0..) |row, index| {
        _ = row;
        const current = try lift(try canonicalColumns(trace, index));
        const next = if (index + 1 < trace.rows.len)
            try lift(try canonicalColumns(trace, index + 1))
        else
            inactive;
        try expect(
            component,
            &current,
            &next,
            index == 0,
            false,
            true,
        );
    }
}

fn canonicalColumns(
    trace: binding.Trace,
    index: usize,
) ![binding.N_MAIN_COLUMNS]M31 {
    var result = try binding.columns(trace.rows[index]);
    const mcycle = trace.rows[index].mcycle;
    var seen = false;
    for (trace.rows[0..index]) |row| {
        if (row.mcycle != mcycle) continue;
        seen = seen or row.transition.interrupts.vblank or
            row.transition.interrupts.stat;
    }
    result[binding.REQUEST_SEEN_OFFSET] =
        M31.fromCanonical(@intFromBool(seen));
    return result;
}

fn expectDomain(
    component: *const subject.Component,
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
    for (0..result.len()) |index|
        zero = zero and result.at(index).isZero();
    try std.testing.expectEqual(expected, zero);
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
    pub fn fromBase(_: M31) Degree {
        return .{ .degree = 0 };
    }
    pub fn add(left: Degree, right: Degree) Degree {
        return .{ .degree = @max(left.degree, right.degree) };
    }
    pub fn sub(left: Degree, right: Degree) Degree {
        return left.add(right);
    }
    pub fn mul(left: Degree, right: Degree) Degree {
        return .{ .degree = left.degree + right.degree };
    }
    pub fn isZero(_: Degree) bool {
        return false;
    }
};
