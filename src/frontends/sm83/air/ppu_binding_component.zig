//! Proof component for PPU M-cycle scheduling, MMIO values, and endpoints.
//!
//! The companion timing component owns transition semantics, state chaining,
//! and the activity prefix. This component owns write-before-four-dots order,
//! pre-tick register reads, full LCDC persistence, and public clock/state
//! endpoints. It does not claim an execution-side MMIO lookup or IF memory
//! update; both require shared memory relations not present in this leaf.

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
const binding = @import("ppu_binding.zig");
const component_domain = @import("component_domain.zig");
const ppu_air = @import("ppu_timing.zig");
const ppu = @import("../runner/ppu_timing.zig");

const CirclePointQM31 = core.circle.CirclePointQM31;

pub const N_CONSTRAINTS: usize = 234;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

pub fn Row(comptime S: type) type {
    return struct {
        active: S,
        semantic: ppu_air.Semantics(S).Row,
        mcycle: S,
        phases: [4]S,
        read_markers: [7]S,
        read_value: [8]S,
        ly_write_enabled: S,
        latch_write_markers: [3]S,
        latch_write_value: S,
        latches_before: [3]S,
        latches_after: [3]S,
        lcdc_before: [8]S,
        lcdc_after: [8]S,
        request_seen: S,

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != binding.N_MAIN_COLUMNS)
                return error.InvalidMainTraceShape;
            return .{
                .active = values[0],
                .semantic = try ppu_air.Semantics(S).Row.fromColumns(
                    values[1..binding.MCYCLE_OFFSET],
                ),
                .mcycle = values[binding.MCYCLE_OFFSET],
                .phases = values[binding.PHASE_OFFSET..binding.READ_MARKER_OFFSET].*,
                .read_markers = values[binding.READ_MARKER_OFFSET..binding.READ_VALUE_OFFSET].*,
                .read_value = values[binding.READ_VALUE_OFFSET..binding.LY_WRITE_ENABLED_OFFSET].*,
                .ly_write_enabled = values[
                    binding.LY_WRITE_ENABLED_OFFSET
                ],
                .latch_write_markers = values[binding.LATCH_WRITE_MARKER_OFFSET..binding.LATCH_WRITE_VALUE_OFFSET].*,
                .latch_write_value = values[
                    binding.LATCH_WRITE_VALUE_OFFSET
                ],
                .latches_before = values[binding.LATCH_BEFORE_OFFSET..binding.LATCH_AFTER_OFFSET].*,
                .latches_after = values[binding.LATCH_AFTER_OFFSET..binding.LCDC_BEFORE_OFFSET].*,
                .lcdc_before = values[binding.LCDC_BEFORE_OFFSET..binding.LCDC_AFTER_OFFSET].*,
                .lcdc_after = values[binding.LCDC_AFTER_OFFSET..binding.REQUEST_SEEN_OFFSET].*,
                .request_seen = values[binding.REQUEST_SEEN_OFFSET],
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
    initial_mcycle: u32,
    final_mcycle: u32,
    initial: binding.State,
    final: binding.State,
) !Evaluation(S) {
    try validateBoundaries(initial_mcycle, final_mcycle, initial, final);
    const current = try Row(S).fromColumns(current_values);
    const next = try Row(S).fromColumns(next_values);
    const one = S.one();
    const not_last = one.sub(is_last);
    const tick = current.semantic.events[0];
    const write_lcdc = current.semantic.events[1];
    const write = sum(current.semantic.events[1..]);
    const next_write = sum(next.semantic.events[1..]);
    const phase_sum = sum(current.phases[0..]);
    const read_sum = sum(current.read_markers[0..]);
    const next_read_sum = sum(next.read_markers[0..]);
    const latch_write_sum = sum(current.latch_write_markers[0..]);
    const next_latch_write_sum = sum(next.latch_write_markers[0..]);
    var out: [N_CONSTRAINTS]S = undefined;
    var at: usize = 0;

    out[at] = one.sub(current.active).mul(current.mcycle);
    at += 1;
    out[at] = is_first.mul(current.active.sub(one));
    at += 1;
    inline for (.{
        current.phases[0..],
        current.read_markers[0..],
        current.read_value[0..],
        current.latch_write_markers[0..],
        current.lcdc_before[0..],
        current.lcdc_after[0..],
    }) |values| for (values) |value| {
        out[at] = bit(value);
        at += 1;
        out[at] = one.sub(current.active).mul(value);
        at += 1;
    };
    out[at] = bit(current.ly_write_enabled);
    at += 1;
    out[at] = one.sub(current.active).mul(current.ly_write_enabled);
    at += 1;
    inline for (.{
        current.latch_write_value,
        current.latches_before[0],
        current.latches_before[1],
        current.latches_before[2],
        current.latches_after[0],
        current.latches_after[1],
        current.latches_after[2],
    }) |value| {
        out[at] = one.sub(current.active).mul(value);
        at += 1;
    }
    out[at] = bit(current.request_seen);
    at += 1;
    out[at] = one.sub(current.active).mul(current.request_seen);
    at += 1;
    out[at] = is_first.mul(current.request_seen);
    at += 1;
    const requested = boolOr(
        current.semantic.interrupts[0],
        current.semantic.interrupts[1],
    );
    out[at] = current.request_seen.mul(requested);
    at += 1;
    out[at] = one.sub(current.phases[3]).mul(
        next.request_seen.sub(current.request_seen).sub(requested),
    );
    at += 1;
    out[at] = current.phases[3].mul(next.request_seen);
    at += 1;

    out[at] = phase_sum.sub(tick);
    at += 1;
    out[at] = bit(read_sum);
    at += 1;
    const access_sum = read_sum.add(current.ly_write_enabled)
        .add(latch_write_sum);
    out[at] = bit(access_sum);
    at += 1;
    out[at] = read_sum.mul(one.sub(current.phases[0]));
    at += 1;
    out[at] = current.ly_write_enabled.mul(
        one.sub(current.phases[0]),
    );
    at += 1;
    out[at] = latch_write_sum.mul(one.sub(current.phases[0]));
    at += 1;
    out[at] = one.sub(latch_write_sum).mul(
        current.latch_write_value,
    );
    at += 1;
    const after_values = externalAfter(S, current);
    var expected_next_read = S.zero();
    for (next.read_markers, after_values) |marker, value|
        expected_next_read = expected_next_read.add(marker.mul(value));
    out[at] = composeBits(S, next.read_value).sub(expected_next_read);
    at += 1;
    const initial_values = externalConstants(S, initial);
    var expected_initial_read = S.zero();
    for (current.read_markers, initial_values) |marker, value|
        expected_initial_read = expected_initial_read.add(marker.mul(value));
    out[at] = is_first.mul(
        composeBits(S, current.read_value).sub(expected_initial_read),
    );
    at += 1;

    out[at] = current.lcdc_before[7].sub(
        current.semantic.before.lcd,
    );
    at += 1;
    out[at] = current.lcdc_after[7].sub(
        current.semantic.after.lcd,
    );
    at += 1;
    for (
        current.lcdc_before,
        current.lcdc_after,
        current.semantic.action,
    ) |before, after, action| {
        out[at] = after.sub(before).sub(
            write_lcdc.mul(action.sub(before)),
        );
        at += 1;
    }
    for (
        current.latches_before,
        current.latches_after,
        current.latch_write_markers,
    ) |before, after, marker| {
        out[at] = after.sub(before).sub(
            marker.mul(current.latch_write_value.sub(before)),
        );
        at += 1;
    }

    const chain = not_last.mul(next.active);
    for (current.lcdc_after, next.lcdc_before) |before, after| {
        out[at] = chain.mul(after.sub(before));
        at += 1;
    }
    for (current.latches_after, next.latches_before) |before, after| {
        out[at] = chain.mul(after.sub(before));
        at += 1;
    }
    out[at] = chain.mul(
        next.mcycle.sub(current.mcycle).sub(current.phases[3]),
    );
    at += 1;
    out[at] = chain.mul(
        next.phases[0].add(next_write)
            .sub(current.phases[3]).sub(write),
    );
    at += 1;
    inline for (0..3) |phase| {
        out[at] = chain.mul(
            next.phases[phase + 1].sub(current.phases[phase]),
        );
        at += 1;
    }
    out[at] = not_last.mul(write).mul(
        next_read_sum.add(next.ly_write_enabled)
            .add(next_latch_write_sum),
    );
    at += 1;
    out[at] = is_first.mul(
        current.phases[0].add(write).sub(one),
    );
    at += 1;

    const initial_state = stateConstants(S, initial.timing);
    for (current.semantic.before.values, initial_state) |actual, expected| {
        out[at] = is_first.mul(actual.sub(expected));
        at += 1;
    }
    const final_state = stateConstants(S, final.timing);
    for (current.semantic.after.values, final_state) |actual, expected|
        appendFinal(
            S,
            &out,
            &at,
            actual.sub(expected),
            current.active,
            next.active,
            is_last,
        );
    const initial_lcdc = byteConstants(S, initial.lcdc);
    for (current.lcdc_before, initial_lcdc) |actual, expected| {
        out[at] = is_first.mul(actual.sub(expected));
        at += 1;
    }
    const final_lcdc = byteConstants(S, final.lcdc);
    for (current.lcdc_after, final_lcdc) |actual, expected|
        appendFinal(
            S,
            &out,
            &at,
            actual.sub(expected),
            current.active,
            next.active,
            is_last,
        );
    const initial_latches = latchConstants(S, initial);
    for (current.latches_before, initial_latches) |actual, expected| {
        out[at] = is_first.mul(actual.sub(expected));
        at += 1;
    }
    const final_latches = latchConstants(S, final);
    for (current.latches_after, final_latches) |actual, expected|
        appendFinal(
            S,
            &out,
            &at,
            actual.sub(expected),
            current.active,
            next.active,
            is_last,
        );

    out[at] = is_first.mul(
        current.mcycle.sub(constant(S, initial_mcycle)),
    );
    at += 1;
    appendFinal(
        S,
        &out,
        &at,
        current.phases[3].sub(one),
        current.active,
        next.active,
        is_last,
    );
    appendFinal(
        S,
        &out,
        &at,
        current.mcycle.add(current.phases[3])
            .sub(constant(S, final_mcycle)),
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
    initial_mcycle: u32,
    final_mcycle: u32,
    initial: binding.State,
    final: binding.State,

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
            self.initial_mcycle,
            self.final_mcycle,
            self.initial,
            self.final,
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
            return error.InvalidPpuBindingLogSize;
        try validateBoundaries(
            self.initial_mcycle,
            self.final_mcycle,
            self.initial,
            self.final,
        );
    }
};

fn externalAfter(
    comptime S: type,
    row: Row(S),
) [7]S {
    return .{
        composeBits(S, row.lcdc_after),
        composeBits(S, row.semantic.stat_read),
        row.latches_after[0],
        row.latches_after[1],
        composeBits(S, row.semantic.ly_read),
        composeBits(S, row.semantic.after.lyc),
        row.latches_after[2],
    };
}

fn externalConstants(
    comptime S: type,
    state: binding.State,
) [7]S {
    return .{
        constant(S, state.lcdc),
        constant(S, state.timing.readStat()),
        constant(S, state.scy),
        constant(S, state.scx),
        constant(S, state.timing.readLy()),
        constant(S, state.timing.lyc),
        constant(S, state.wy),
    };
}

fn latchConstants(comptime S: type, state: binding.State) [3]S {
    return .{
        constant(S, state.scy),
        constant(S, state.scx),
        constant(S, state.wy),
    };
}

fn stateConstants(
    comptime S: type,
    state: ppu.State,
) [38]S {
    const value: u8 = if (state.lcd_enabled) 0x80 else 0;
    const transition = ppu.Transition.apply(
        state,
        .{ .write_lcdc = value },
    ) catch unreachable;
    const direct = ppu_air.columns(
        ppu_air.ValidatedStep.init(transition) catch unreachable,
    );
    const row = ppu_air.Semantics(M31).Row.fromColumns(&direct) catch
        unreachable;
    var result: [38]S = undefined;
    for (&result, row.before.values) |*target, source|
        target.* = S.fromBase(source);
    return result;
}

fn byteConstants(comptime S: type, value: u8) [8]S {
    var result: [8]S = undefined;
    for (&result, 0..) |*bit_value, index|
        bit_value.* = S.fromBase(M31.fromCanonical(
            @intCast(value >> @intCast(index) & 1),
        ));
    return result;
}

fn composeBits(comptime S: type, values: [8]S) S {
    var result = S.zero();
    inline for (values, 0..) |value, index|
        result = result.add(value.mul(constant(S, 1 << index)));
    return result;
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

fn boolOr(left: anytype, right: @TypeOf(left)) @TypeOf(left) {
    return left.add(right).sub(left.mul(right));
}

fn sum(values: anytype) @TypeOf(values[0]) {
    var result = @TypeOf(values[0]).zero();
    for (values) |value| result = result.add(value);
    return result;
}

fn constant(comptime S: type, value: u32) S {
    return S.fromBase(M31.fromCanonical(value));
}

fn validateBoundaries(
    initial_mcycle: u32,
    final_mcycle: u32,
    initial: binding.State,
    final: binding.State,
) !void {
    if (initial_mcycle >= M31_MODULUS or final_mcycle >= M31_MODULUS)
        return error.NonCanonicalPpuClock;
    if (initial_mcycle >= final_mcycle)
        return error.InvalidPpuClockBoundary;
    try initial.validate();
    try final.validate();
}

fn nextRowPoint(log_size: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.add(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}
