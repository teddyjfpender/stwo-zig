const std = @import("std");
const core = @import("stwo_core");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_accumulation =
    @import("stwo_prover_engine").air.accumulation;
const prover_component =
    @import("stwo_prover_engine").air.component_prover;
const binding = @import("dma_binding.zig");
const subject = @import("dma_binding_component.zig");
const dma = @import("../runner/dma.zig");

test "DMA binding component is exactly cubic with L plus one quotient" {
    const variables =
        [_]Degree{Degree.variable()} ** binding.N_MAIN_COLUMNS;
    const evaluation = try subject.evaluateRows(
        Degree,
        &variables,
        &variables,
        Degree.variable(),
        Degree.variable(),
        .{ .clock = 7 },
        .{ .clock = 9 },
    );
    var maximum: u32 = 0;
    for (evaluation.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    try std.testing.expectEqual(subject.MAX_CONSTRAINT_DEGREE, maximum);
    try std.testing.expectEqual(@as(usize, 238), subject.N_CONSTRAINTS);

    const component = subject.Component{
        .log_size = 4,
        .is_first_column = 2,
        .is_last_column = 4,
        .main_offset = 7,
        .initial_state = .{ .clock = 7 },
        .final_state = .{ .clock = 9 },
    };
    try std.testing.expectEqual(@as(u32, 5), component.maxConstraintLogDegreeBound());
    try std.testing.expectEqual(subject.N_CONSTRAINTS, component.nConstraints());
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();
    const indices = try component.preprocessedColumnIndices(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(indices);
    try std.testing.expectEqualSlices(usize, &.{ 2, 4 }, indices);
    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), bounds.items[0].len);
    try std.testing.expectEqual(
        7 + binding.N_MAIN_COLUMNS,
        bounds.items[1].len,
    );
}

test "DMA binding component accepts a complete row and rejects mutations" {
    const initial = dma.State{
        .clock = 20,
        .page = 0xc0,
        .phase = .transfer,
    };
    const transition = try dma.Transition.apply(
        initial,
        .{ .transfer = 0x42 },
    );
    var current = try syntheticColumns(20, transition, 0xff80, .read);
    const final = transition.after;
    const honest = try evaluate(
        current,
        binding.inactiveColumns(),
        true,
        true,
        initial,
        final,
    );
    try std.testing.expect(honest.allZero());

    const mutations = [_]usize{
        binding.MCYCLE_OFFSET,
        binding.BUS_ADDRESS_OFFSET,
        binding.BUS_ACTION_OFFSET,
        binding.CPU_CLASS_OFFSET,
        binding.COPIED_NONZERO_OFFSET,
        binding.PAGE_VRAM_OFFSET,
        binding.CPU_PAGE_VRAM_OFFSET,
        binding.HIGH_FE_CHAIN_OFFSET,
        binding.ADDRESS_VRAM_OFFSET,
        binding.ADDRESS_OAM_OFFSET,
        binding.OAM_BLOCKED_OFFSET,
        binding.SOURCE_BLOCKED_OFFSET,
        binding.BUS_MATCH_OFFSET,
        binding.FF46_MATCH_OFFSET,
    };
    for (mutations) |column| {
        const saved = current[column];
        current[column] = flip(saved);
        try std.testing.expect(!(try evaluate(
            current,
            binding.inactiveColumns(),
            true,
            true,
            initial,
            final,
        )).allZero());
        current[column] = saved;
    }

    var forged_initial = initial;
    forged_initial.clock -= 1;
    try std.testing.expect(!(try evaluate(
        current,
        binding.inactiveColumns(),
        true,
        true,
        forged_initial,
        final,
    )).allZero());
    var forged_final = final;
    forged_final.page +%= 1;
    try std.testing.expect(!(try evaluate(
        current,
        binding.inactiveColumns(),
        true,
        true,
        initial,
        forged_final,
    )).allZero());
}

test "DMA binding binds FF46 bus value to the restart page" {
    const initial = dma.State{ .clock = 40 };
    const transition = try dma.Transition.apply(
        initial,
        .{ .write_ff46 = 0xc0 },
    );
    var columns = try syntheticColumns(
        40,
        transition,
        dma.DMA_ADDRESS,
        .write,
    );
    try std.testing.expect((try evaluate(
        columns,
        binding.inactiveColumns(),
        true,
        true,
        initial,
        transition.after,
    )).allZero());
    columns[binding.BUS_VALUE_OFFSET] = M31.one();
    try std.testing.expect(!(try evaluate(
        columns,
        binding.inactiveColumns(),
        true,
        true,
        initial,
        transition.after,
    )).allZero());
}

test "DMA binding separates transfer and CPU buses across restart" {
    const initial = dma.State{
        .clock = 45,
        .page = 0xc0,
        .copied = 1,
        .phase = .transfer,
    };
    const transition = try dma.Transition.apply(initial, .{
        .transfer_and_write = .{
            .source_byte = 0x42,
            .page = 0x80,
        },
    });
    const columns = try syntheticColumns(
        45,
        transition,
        dma.DMA_ADDRESS,
        .write,
    );
    try std.testing.expectEqual(
        M31.zero(),
        columns[binding.PAGE_VRAM_OFFSET],
    );
    try std.testing.expectEqual(
        M31.one(),
        columns[binding.CPU_PAGE_VRAM_OFFSET],
    );
    try std.testing.expect((try evaluate(
        columns,
        binding.inactiveColumns(),
        true,
        true,
        initial,
        transition.after,
    )).allZero());
}

test "DMA binding rejects VRAM source transfers and selector mutation" {
    const initial = dma.State{
        .clock = 46,
        .page = 0x80,
        .phase = .transfer,
    };
    const transition = try dma.Transition.apply(
        initial,
        .{ .transfer = 0x42 },
    );
    var columns = try syntheticColumns(
        46,
        transition,
        0xff80,
        .read,
    );
    try std.testing.expect(!(try evaluate(
        columns,
        binding.inactiveColumns(),
        true,
        true,
        initial,
        transition.after,
    )).allZero());
    columns[binding.PAGE_VRAM_OFFSET] = M31.zero();
    try std.testing.expect(!(try evaluate(
        columns,
        binding.inactiveColumns(),
        true,
        true,
        initial,
        transition.after,
    )).allZero());
}

test "DMA binding rejects unsupported source and OAM blocking" {
    const first_state = dma.State{
        .clock = 29,
        .page = 0xc0,
        .phase = .transfer,
    };
    const first_transition = try dma.Transition.apply(
        first_state,
        .{ .transfer = 0xf0 },
    );
    const first_read = try syntheticColumns(
        29,
        first_transition,
        0xc123,
        .read,
    );
    try std.testing.expect(!(try evaluate(
        first_read,
        binding.inactiveColumns(),
        true,
        true,
        first_state,
        first_transition.after,
    )).allZero());
    const first_write = try syntheticColumns(
        29,
        first_transition,
        0xc000,
        .write,
    );
    try std.testing.expect(!(try evaluate(
        first_write,
        binding.inactiveColumns(),
        true,
        true,
        first_state,
        first_transition.after,
    )).allZero());

    const source_state = dma.State{
        .clock = 30,
        .page = 0xc0,
        .copied = 1,
        .phase = .transfer,
    };
    const source_transition = try dma.Transition.apply(
        source_state,
        .{ .transfer = 1 },
    );
    const source_columns = try syntheticColumns(
        30,
        source_transition,
        0xc000,
        .read,
    );
    try std.testing.expect(!(try evaluate(
        source_columns,
        binding.inactiveColumns(),
        true,
        true,
        source_state,
        source_transition.after,
    )).allZero());

    const oam_columns = try syntheticColumns(
        30,
        source_transition,
        0xfe00,
        .read,
    );
    try std.testing.expect(!(try evaluate(
        oam_columns,
        binding.inactiveColumns(),
        true,
        true,
        source_state,
        source_transition.after,
    )).allZero());

    const warm_state = dma.State{
        .clock = 31,
        .page = 0xc0,
        .phase = .startup,
    };
    const warm_transition = try dma.Transition.apply(warm_state, .tick);
    const warm_read = try syntheticColumns(
        31,
        warm_transition,
        dma.OAM_START,
        .read,
    );
    try std.testing.expect((try evaluate(
        warm_read,
        binding.inactiveColumns(),
        true,
        true,
        warm_state,
        warm_transition.after,
    )).allZero());
    const warm_write = try syntheticColumns(
        31,
        warm_transition,
        dma.OAM_START,
        .write,
    );
    try std.testing.expect(!(try evaluate(
        warm_write,
        binding.inactiveColumns(),
        true,
        true,
        warm_state,
        warm_transition.after,
    )).allZero());

    const finish_state = dma.State{
        .clock = 32,
        .page = 0xc0,
        .copied = dma.OAM_LENGTH,
        .phase = .finishing,
    };
    const finish_transition = try dma.Transition.apply(finish_state, .tick);
    var finish_columns = try syntheticColumns(
        32,
        finish_transition,
        0xc123,
        .read,
    );
    try std.testing.expect((try evaluate(
        finish_columns,
        binding.inactiveColumns(),
        true,
        true,
        finish_state,
        finish_transition.after,
    )).allZero());
    finish_columns[
        binding.CPU_CLASS_OFFSET + @intFromEnum(dma.CpuAccess.allowed)
    ] = M31.zero();
    finish_columns[
        binding.CPU_CLASS_OFFSET +
            @intFromEnum(dma.CpuAccess.blocked_source_bus)
    ] = M31.one();
    try std.testing.expect(!(try evaluate(
        finish_columns,
        binding.inactiveColumns(),
        true,
        true,
        finish_state,
        finish_transition.after,
    )).allZero());
}

test "DMA binding sampled and domain paths reject clock value and vacuity" {
    const initial = dma.State{ .clock = 7 };
    const first_transition = try dma.Transition.apply(
        initial,
        .{ .write_ff46 = 0xc0 },
    );
    const second_transition = try dma.Transition.apply(
        first_transition.after,
        .tick,
    );
    const final = second_transition.after;
    const first_m31 = try syntheticColumns(
        7,
        first_transition,
        dma.DMA_ADDRESS,
        .write,
    );
    const second_m31 = try syntheticColumns(
        8,
        second_transition,
        0xff80,
        .read,
    );
    const first = lift(first_m31);
    const second = lift(second_m31);
    const component = subject.Component{
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial_state = initial,
        .final_state = final,
    };

    var preprocessed_storage = [_][1]QM31{
        .{QM31.one()},
        .{QM31.zero()},
    };
    var preprocessed: [2][]QM31 = undefined;
    for (&preprocessed, &preprocessed_storage) |*column, *values|
        column.* = values;
    var main_storage =
        [_][2]QM31{.{ QM31.zero(), QM31.zero() }} **
        binding.N_MAIN_COLUMNS;
    for (&main_storage, first, second) |*values, current, next|
        values.* = .{ current, next };
    var main: [binding.N_MAIN_COLUMNS][]QM31 = undefined;
    for (&main, &main_storage) |*column, *values| column.* = values;
    var trees = [_][][]QM31{ &preprocessed, &main };
    const mask = core.air.components.MaskValues.initOwned(&trees);
    const point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    var honest =
        core.air.accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &honest,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(honest.finalize().isZero());

    main_storage[binding.MCYCLE_OFFSET][1] =
        QM31.fromBase(M31.fromCanonical(9));
    var sampled_mutation =
        core.air.accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &sampled_mutation,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(!sampled_mutation.finalize().isZero());
    main_storage[binding.MCYCLE_OFFSET][1] =
        QM31.fromBase(M31.fromCanonical(8));

    const evaluation_log_size: u32 = 5;
    const evaluation_size: usize = 32;
    const first_index: usize = 0;
    const second_index = core.utils.offsetBitReversedCircleDomainIndex(
        first_index,
        component.log_size,
        evaluation_log_size,
        1,
    );
    var last_index: ?usize = null;
    for (0..evaluation_size) |index| {
        if (core.utils.offsetBitReversedCircleDomainIndex(
            index,
            component.log_size,
            evaluation_log_size,
            1,
        ) == first_index) last_index = index;
    }
    var first_values = [_]M31{M31.zero()} ** evaluation_size;
    var last_values = [_]M31{M31.zero()} ** evaluation_size;
    first_values[first_index] = M31.one();
    last_values[last_index orelse return error.InvalidProofShape] = M31.one();
    var main_values =
        [_][evaluation_size]M31{
            [_]M31{M31.zero()} ** evaluation_size,
        } ** binding.N_MAIN_COLUMNS;
    for (&main_values, first_m31, second_m31) |
        *values,
        first_value,
        second_value,
    | {
        values[first_index] = first_value;
        values[second_index] = second_value;
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
    const trace = prover_component.Trace{
        .polys = core.pcs.TreeVec(
            []const prover_component.Poly,
        ).initOwned(&poly_trees),
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);
    try expectDomain(
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        true,
    );
    main_values[binding.BUS_VALUE_OFFSET][first_index] =
        flip(main_values[binding.BUS_VALUE_OFFSET][first_index]);
    try expectDomain(
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    main_values[binding.BUS_VALUE_OFFSET][first_index] =
        flip(main_values[binding.BUS_VALUE_OFFSET][first_index]);
    main_values[0][first_index] = M31.zero();
    try expectDomain(
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
}

fn syntheticColumns(
    mcycle: u32,
    transition: dma.Transition,
    address: u16,
    action: dmaTestBusAction(),
) ![binding.N_MAIN_COLUMNS]M31 {
    var result = binding.inactiveColumns();
    const validated = try @import("dma.zig").ValidatedStep.init(transition);
    const semantic = @import("dma_component.zig").columns(validated);
    @memcpy(result[0..@import("dma_component.zig").N_MAIN_COLUMNS], &semantic);
    result[binding.MCYCLE_OFFSET] = M31.fromCanonical(mcycle);
    writeBits(result[binding.BUS_ADDRESS_OFFSET..binding.BUS_VALUE_OFFSET], address);
    const bus_value: u8 = switch (transition.event) {
        .write_ff46 => |page| page,
        .transfer_and_write => |write| write.page,
        else => 0,
    };
    writeBits(
        result[binding.BUS_VALUE_OFFSET..binding.BUS_ACTION_OFFSET],
        bus_value,
    );
    result[binding.BUS_ACTION_OFFSET + @intFromEnum(action)] = M31.one();
    const class = switch (action) {
        .idle => dma.CpuAccess.allowed,
        .read => transition.after.cpuAccess(address),
        .write => transition.after.cpuWriteAccess(address),
    };
    result[binding.CPU_CLASS_OFFSET + @intFromEnum(class)] = M31.one();
    const copied = transition.after.copied;
    if (copied != 0) {
        result[binding.COPIED_NONZERO_OFFSET] = M31.one();
        result[binding.COPIED_INVERSE_OFFSET] =
            try M31.fromCanonical(copied).inv();
    }
    const page = transition.before.page;
    result[binding.PAGE_VRAM_OFFSET] =
        boolean(page >= 0x80 and page < 0xa0);
    const cpu_page = transition.after.page;
    result[binding.CPU_PAGE_VRAM_OFFSET] =
        boolean(cpu_page >= 0x80 and cpu_page < 0xa0);
    var prefix = true;
    for (0..7) |index| {
        prefix = prefix and
            ((address >> @intCast(15 - index)) & 1) == 1;
        result[binding.HIGH_FE_CHAIN_OFFSET + index] = boolean(prefix);
    }
    result[binding.ADDRESS_VRAM_OFFSET] =
        boolean(address >= 0x8000 and address < 0xa000);
    result[binding.ADDRESS_OAM_OFFSET] =
        boolean(address >= 0xfe00 and address < 0xff00);
    result[binding.OAM_BLOCKED_OFFSET] =
        boolean(transition.after.oamBlocked());
    result[binding.SOURCE_BLOCKED_OFFSET] = boolean(
        transition.after.phase == .finishing or
            (transition.after.phase == .transfer and copied != 0),
    );
    result[binding.BUS_MATCH_OFFSET] = boolean(
        address < 0xfe00 and
            ((cpu_page >= 0x80 and cpu_page < 0xa0) ==
                (address >= 0x8000 and address < 0xa000)),
    );
    if (address == dma.DMA_ADDRESS) {
        result[binding.FF46_MATCH_OFFSET] = M31.one();
    } else {
        result[binding.FF46_INVERSE_OFFSET] = try M31.fromCanonical(address)
            .sub(M31.fromCanonical(dma.DMA_ADDRESS)).inv();
    }
    return result;
}

fn evaluate(
    current: [binding.N_MAIN_COLUMNS]M31,
    next: [binding.N_MAIN_COLUMNS]M31,
    first: bool,
    last: bool,
    initial: dma.State,
    final: dma.State,
) !subject.Evaluation(QM31) {
    var current_q: [binding.N_MAIN_COLUMNS]QM31 = undefined;
    var next_q: [binding.N_MAIN_COLUMNS]QM31 = undefined;
    for (&current_q, current) |*out, value| out.* = QM31.fromBase(value);
    for (&next_q, next) |*out, value| out.* = QM31.fromBase(value);
    return subject.evaluateRows(
        QM31,
        &current_q,
        &next_q,
        QM31.fromBase(boolean(first)),
        QM31.fromBase(boolean(last)),
        initial,
        final,
    );
}

fn lift(
    values: [binding.N_MAIN_COLUMNS]M31,
) [binding.N_MAIN_COLUMNS]QM31 {
    var result: [binding.N_MAIN_COLUMNS]QM31 = undefined;
    for (&result, values) |*destination, value|
        destination.* = QM31.fromBase(value);
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

fn dmaTestBusAction() type {
    return @import("../runner/mod.zig").BusAction;
}

fn writeBits(destination: []M31, value: anytype) void {
    const integer: u64 = @intCast(value);
    for (destination, 0..) |*item, index|
        item.* = boolean(integer >> @intCast(index) & 1 != 0);
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

fn flip(value: M31) M31 {
    return if (value.isZero()) M31.one() else M31.zero();
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
