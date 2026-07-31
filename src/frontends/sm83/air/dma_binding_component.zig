//! Cubic execution-clock, FF46, and CPU-bus binding for OAM DMA rows.
//!
//! DMA transition semantics remain owned by `dma_component`. The bus columns
//! must be joined to execution in the composed frontend; this component makes
//! their classification and FF46 effect deterministic and binds public DMA
//! state/clock endpoints.

const std = @import("std");
const core = @import("stwo_core");
const core_air_accumulation = core.air.accumulation;
const core_air_components = core.air.components;
const core_air_derive = core.air.derive;
const core_constraints = core.constraints;
const M31_MODULUS = core.fields.m31.Modulus;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const canonic = core.poly.circle.canonic;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const binding = @import("dma_binding.zig");
const component_domain = @import("component_domain.zig");
const dma_air = @import("dma.zig");
const dma = @import("../runner/dma.zig");

const CirclePointQM31 = core.circle.CirclePointQM31;

pub const N_CONSTRAINTS: usize = 238;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

pub fn Row(comptime S: type) type {
    return struct {
        active: S,
        semantic: dma_air.Semantics(S).Row,
        mcycle: S,
        address: [16]S,
        value: [8]S,
        actions: [3]S,
        classes: [3]S,
        copied_nonzero: S,
        copied_inverse: S,
        page_vram: S,
        high_fe_chain: [7]S,
        address_vram: S,
        address_oam: S,
        oam_blocked: S,
        source_blocked: S,
        bus_match: S,
        ff46_match: S,
        ff46_inverse: S,
        cpu_page_vram: S,

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != binding.N_MAIN_COLUMNS)
                return error.InvalidDmaBindingShape;
            return .{
                .active = values[0],
                .semantic = try dma_air.Semantics(S).Row.fromColumns(
                    values[1..binding.MCYCLE_OFFSET],
                ),
                .mcycle = values[binding.MCYCLE_OFFSET],
                .address = values[binding.BUS_ADDRESS_OFFSET..binding.BUS_VALUE_OFFSET].*,
                .value = values[binding.BUS_VALUE_OFFSET..binding.BUS_ACTION_OFFSET].*,
                .actions = values[binding.BUS_ACTION_OFFSET..binding.CPU_CLASS_OFFSET].*,
                .classes = values[binding.CPU_CLASS_OFFSET..binding.COPIED_NONZERO_OFFSET].*,
                .copied_nonzero = values[binding.COPIED_NONZERO_OFFSET],
                .copied_inverse = values[binding.COPIED_INVERSE_OFFSET],
                .page_vram = values[binding.PAGE_VRAM_OFFSET],
                .high_fe_chain = values[binding.HIGH_FE_CHAIN_OFFSET..binding.ADDRESS_VRAM_OFFSET].*,
                .address_vram = values[binding.ADDRESS_VRAM_OFFSET],
                .address_oam = values[binding.ADDRESS_OAM_OFFSET],
                .oam_blocked = values[binding.OAM_BLOCKED_OFFSET],
                .source_blocked = values[binding.SOURCE_BLOCKED_OFFSET],
                .bus_match = values[binding.BUS_MATCH_OFFSET],
                .ff46_match = values[binding.FF46_MATCH_OFFSET],
                .ff46_inverse = values[binding.FF46_INVERSE_OFFSET],
                .cpu_page_vram = values[binding.CPU_PAGE_VRAM_OFFSET],
            };
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
    current_values: []const S,
    next_values: []const S,
    is_first: S,
    is_last: S,
    initial_state: dma.State,
    final_state: dma.State,
) !Evaluation(S) {
    try validateBoundaries(initial_state, final_state);
    const current = try Row(S).fromColumns(current_values);
    const next = try Row(S).fromColumns(next_values);
    const one = S.one();
    const inactive = one.sub(current.active);
    var out: [N_CONSTRAINTS]S = undefined;
    var at: usize = 0;

    out[at] = inactive.mul(current.mcycle);
    at += 1;
    for (current.address ++ current.value ++ current.actions ++
        current.classes) |value|
    {
        out[at] = bit(value);
        at += 1;
        out[at] = inactive.mul(value);
        at += 1;
    }
    const auxiliaries =
        [_]S{
            current.copied_nonzero,
            current.page_vram,
            current.cpu_page_vram,
        } ++
        current.high_fe_chain ++
        [_]S{
            current.address_vram,
            current.address_oam,
            current.oam_blocked,
            current.source_blocked,
            current.bus_match,
            current.ff46_match,
        };
    for (auxiliaries) |value| {
        out[at] = bit(value);
        at += 1;
        out[at] = inactive.mul(value);
        at += 1;
    }
    out[at] = inactive.mul(current.copied_inverse);
    at += 1;
    out[at] = inactive.mul(current.ff46_inverse);
    at += 1;

    const action_active = current.actions[1].add(current.actions[2]);
    out[at] = sum(current.actions[0..]).sub(current.active);
    at += 1;
    out[at] = sum(current.classes[0..]).sub(current.active);
    at += 1;
    out[at] = current.mcycle.sub(compose(current.semantic.before.clock));
    at += 1;

    const copied = compose(current.semantic.after.copied);
    out[at] = copied.mul(one.sub(current.copied_nonzero));
    at += 1;
    out[at] = copied.mul(current.copied_inverse)
        .sub(current.copied_nonzero);
    at += 1;
    out[at] = current.page_vram.sub(
        current.semantic.before.page[7]
            .mul(one.sub(current.semantic.before.page[6]))
            .mul(one.sub(current.semantic.before.page[5])),
    );
    at += 1;
    const transfer_event = current.semantic.events[2]
        .add(current.semantic.events[3]);
    out[at] = transfer_event.mul(current.page_vram);
    at += 1;
    out[at] = current.cpu_page_vram.sub(
        current.semantic.after.page[7]
            .mul(one.sub(current.semantic.after.page[6]))
            .mul(one.sub(current.semantic.after.page[5])),
    );
    at += 1;

    out[at] = current.high_fe_chain[0].sub(current.address[15]);
    at += 1;
    for (1..7) |index| {
        out[at] = current.high_fe_chain[index].sub(
            current.high_fe_chain[index - 1].mul(
                current.address[15 - index],
            ),
        );
        at += 1;
    }
    const high_fe = current.high_fe_chain[6];
    out[at] = current.address_vram.sub(
        current.address[15]
            .mul(one.sub(current.address[14]))
            .mul(one.sub(current.address[13])),
    );
    at += 1;
    out[at] = current.address_oam.sub(
        high_fe.mul(one.sub(current.address[8])),
    );
    at += 1;
    const phase = current.semantic.after.phases;
    const restart = current.semantic.after.restarting;
    out[at] = current.oam_blocked.sub(
        phase[@intFromEnum(dma.Phase.startup)]
            .add(phase[@intFromEnum(dma.Phase.finishing)])
            .add(phase[@intFromEnum(dma.Phase.transfer)].mul(
            current.copied_nonzero.add(restart)
                .sub(current.copied_nonzero.mul(restart)),
        )),
    );
    at += 1;
    const same_bus = current.active
        .sub(current.cpu_page_vram)
        .sub(current.address_vram)
        .add(constant(S, 2).mul(
        current.cpu_page_vram.mul(current.address_vram),
    ));
    out[at] = current.bus_match.sub(
        one.sub(high_fe).mul(same_bus),
    );
    at += 1;

    const source_active =
        phase[@intFromEnum(dma.Phase.finishing)].add(
            phase[@intFromEnum(dma.Phase.transfer)]
                .mul(current.copied_nonzero),
        );
    out[at] = current.source_blocked.sub(source_active);
    at += 1;
    out[at] = current.classes[
        @intFromEnum(
            dma.CpuAccess.blocked_source_bus,
        )
    ].sub(action_active.mul(current.source_blocked).mul(
        current.bus_match,
    ));
    at += 1;
    out[at] = current.classes[
        @intFromEnum(
            dma.CpuAccess.blocked_oam,
        )
    ].sub(current.address_oam.mul(
        action_active.mul(current.oam_blocked).add(
            current.actions[2].mul(one.sub(current.oam_blocked)),
        ),
    ));
    at += 1;
    out[at] = current.classes[@intFromEnum(dma.CpuAccess.allowed)]
        .sub(current.active
        .sub(current.classes[
            @intFromEnum(
                dma.CpuAccess.blocked_source_bus,
            )
        ])
        .sub(current.classes[@intFromEnum(dma.CpuAccess.blocked_oam)]));
    at += 1;
    // ponytail: reject blocked CPU bus rows; authenticate their returned or
    // redirected memory effects before admitting the runner's behavior.
    out[at] = current.classes[
        @intFromEnum(dma.CpuAccess.blocked_source_bus)
    ];
    at += 1;
    out[at] = current.classes[@intFromEnum(dma.CpuAccess.blocked_oam)];
    at += 1;

    const address_difference = compose(current.address)
        .sub(constant(S, dma.DMA_ADDRESS));
    out[at] = address_difference.mul(current.ff46_match);
    at += 1;
    out[at] = address_difference.mul(current.ff46_inverse)
        .sub(current.active.sub(current.ff46_match));
    at += 1;
    const write_event = current.semantic.events[1]
        .add(current.semantic.events[3]);
    out[at] = write_event.sub(
        current.actions[2].mul(current.ff46_match),
    );
    at += 1;
    for (current.value, current.semantic.write_page) |actual, page_bit| {
        out[at] = write_event.mul(actual.sub(page_bit));
        at += 1;
    }

    const chain = one.sub(is_last).mul(next.active);
    out[at] = chain.mul(
        next.mcycle.sub(current.mcycle).sub(one),
    );
    at += 1;
    out[at] = chain.mul(one.sub(current.active));
    at += 1;
    out[at] = is_first.mul(current.active.sub(one));
    at += 1;

    const initial_columns = stateColumns(S, initial_state);
    const final_columns = stateColumns(S, final_state);
    const before_columns = flattenState(S, current.semantic.before);
    const after_columns = flattenState(S, current.semantic.after);
    for (before_columns, initial_columns) |actual, expected| {
        out[at] = is_first.mul(actual.sub(expected));
        at += 1;
    }
    for (after_columns, final_columns) |actual, expected| {
        appendFinal(
            S,
            &out,
            &at,
            actual.sub(expected),
            current.active,
            next.active,
            is_last,
        );
    }
    out[at] = is_first.mul(
        current.mcycle.sub(constant(S, initial_state.clock)),
    );
    at += 1;
    appendFinal(
        S,
        &out,
        &at,
        current.mcycle.add(one).sub(constant(S, final_state.clock)),
        current.active,
        next.active,
        is_last,
    );
    std.debug.assert(at == out.len);
    return .{ .values = out };
}

pub const Component = struct {
    log_size: u32,
    is_first_column: usize,
    is_last_column: usize,
    main_offset: usize,
    initial_state: dma.State,
    final_state: dma.State,

    const Self = @This();
    const Adapter = core_air_derive.ComponentAdapter(
        Self,
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_accumulation.DomainEvaluationAccumulator,
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
        try self.validateConfiguration();
        const preprocessed = try allocator.alloc(
            u32,
            @max(self.is_first_column, self.is_last_column) + 1,
        );
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, self.log_size);
        const main = try allocator.alloc(
            u32,
            self.main_offset + binding.N_MAIN_COLUMNS,
        );
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
        try self.validateConfiguration();
        if (max_log_degree_bound < self.log_size)
            return error.InvalidProofShape;
        const preprocessed = try component_domain.currentPointColumns(
            allocator,
            @max(self.is_first_column, self.is_last_column) + 1,
            point,
        );
        errdefer component_domain.freePointColumns(allocator, preprocessed);
        const main = try component_domain.currentAndNextPointColumns(
            allocator,
            self.main_offset + binding.N_MAIN_COLUMNS,
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
        try self.validateConfiguration();
        return allocator.dupe(usize, &.{
            self.is_first_column,
            self.is_last_column,
        });
    }

    pub fn evaluateRow(
        self: *const Self,
        current: []const QM31,
        next: []const QM31,
        is_first: QM31,
        is_last: QM31,
    ) !Evaluation(QM31) {
        try self.validateConfiguration();
        return evaluateRows(
            QM31,
            current,
            next,
            is_first,
            is_last,
            self.initial_state,
            self.final_state,
        );
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const Self,
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        try self.validateConfiguration();
        if (max_log_degree_bound < self.log_size or mask.items.len < 2)
            return error.InvalidProofShape;
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        if (preprocessed.len <= self.is_first_column or
            preprocessed.len <= self.is_last_column or
            preprocessed[self.is_first_column].len != 1 or
            preprocessed[self.is_last_column].len != 1 or
            main.len < self.main_offset + binding.N_MAIN_COLUMNS)
            return error.InvalidProofShape;
        var current: [binding.N_MAIN_COLUMNS]QM31 = undefined;
        var next: [binding.N_MAIN_COLUMNS]QM31 = undefined;
        for (
            &current,
            &next,
            main[self.main_offset..][0..binding.N_MAIN_COLUMNS],
        ) |*current_value, *next_value, column| {
            if (column.len != 2) return error.InvalidProofShape;
            current_value.* = column[0];
            next_value.* = column[1];
        }
        const evaluation = try self.evaluateRow(
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
        accumulator: *prover_accumulation.DomainEvaluationAccumulator,
    ) !void {
        try self.validateConfiguration();
        if (trace.polys.items.len < 2) return error.InvalidProofShape;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        if (preprocessed.len <= self.is_first_column or
            preprocessed.len <= self.is_last_column or
            main.len < self.main_offset + binding.N_MAIN_COLUMNS)
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const evaluations = try allocator.alloc(
            []const M31,
            2 + binding.N_MAIN_COLUMNS,
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
            main[self.main_offset..][0..binding.N_MAIN_COLUMNS],
            evaluations[2..],
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
        for (0..evaluation_size) |row_index| {
            const next_row = core.utils.offsetBitReversedCircleDomainIndex(
                row_index,
                self.log_size,
                evaluation_log_size,
                1,
            );
            var current: [binding.N_MAIN_COLUMNS]QM31 = undefined;
            var next: [binding.N_MAIN_COLUMNS]QM31 = undefined;
            for (&current, &next, evaluations[2..]) |
                *current_value,
                *next_value,
                values,
            | {
                current_value.* = QM31.fromBase(values[row_index]);
                next_value.* = QM31.fromBase(values[next_row]);
            }
            const evaluation = try self.evaluateRow(
                &current,
                &next,
                QM31.fromBase(evaluations[0][row_index]),
                QM31.fromBase(evaluations[1][row_index]),
            );
            var folded = QM31.zero();
            for (evaluation.values, 0..) |constraint, index| {
                const powers = column.random_coeff_powers;
                folded = folded.add(
                    powers[powers.len - 1 - index].mul(constraint),
                );
            }
            column.accumulate(
                row_index,
                folded.mulM31(inverses[row_index >> shift]),
            );
        }
    }

    fn validateConfiguration(self: *const Self) !void {
        if (self.log_size < 4 or self.log_size > 24)
            return error.InvalidDmaBindingLogSize;
        try validateBoundaries(self.initial_state, self.final_state);
    }
};

fn flattenState(
    comptime S: type,
    state: dma_air.Semantics(S).StateRow,
) [51]S {
    return state.page ++ state.phases ++ state.copied ++
        [_]S{state.restarting} ++ state.clock;
}

fn stateColumns(comptime S: type, state: dma.State) [51]S {
    var result = [_]S{S.zero()} ** 51;
    writePublicBits(S, result[0..8], state.page);
    result[8 + @as(usize, @intFromEnum(state.phase))] = S.one();
    writePublicBits(S, result[12..20], state.copied);
    result[20] = constant(S, @intFromBool(state.restarting));
    writePublicBits(S, result[21..51], state.clock);
    return result;
}

fn writePublicBits(
    comptime S: type,
    destination: []S,
    value: anytype,
) void {
    const integer: u64 = @intCast(value);
    for (destination, 0..) |*item, index|
        item.* = constant(
            S,
            @as(u32, @intCast(integer >> @intCast(index) & 1)),
        );
}

fn appendFinal(
    comptime S: type,
    out: *[N_CONSTRAINTS]S,
    at: *usize,
    difference: S,
    active: S,
    next_active: S,
    is_last: S,
) void {
    const not_last = S.one().sub(is_last);
    out[at.*] = is_last.mul(active).mul(difference).add(
        not_last.mul(active.sub(next_active)).mul(difference),
    );
    at.* += 1;
}

fn bit(value: anytype) @TypeOf(value) {
    return value.mul(value.sub(@TypeOf(value).one()));
}

fn sum(values: anytype) @TypeOf(values[0]) {
    var result = @TypeOf(values[0]).zero();
    for (values) |value| result = result.add(value);
    return result;
}

fn compose(bits: anytype) @TypeOf(bits[0]) {
    var result = @TypeOf(bits[0]).zero();
    var power = @TypeOf(bits[0]).one();
    for (bits) |value| {
        result = result.add(power.mul(value));
        power = power.add(power);
    }
    return result;
}

fn constant(comptime S: type, value: anytype) S {
    return S.fromBase(M31.fromCanonical(@intCast(value)));
}

fn validateBoundaries(initial: dma.State, final: dma.State) !void {
    try initial.validate();
    try final.validate();
    if (initial.clock >= final.clock or final.clock >= M31_MODULUS)
        return error.InvalidDmaClockBoundary;
}

fn nextRowPoint(log_size: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.add(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}
