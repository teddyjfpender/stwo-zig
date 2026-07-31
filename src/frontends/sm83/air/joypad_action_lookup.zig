//! LogUp relation joining public actions to semantic joypad action events.
//!
//! This binds only `set_pressed` events. Tick scheduling and FF00 bus
//! reads/writes remain separate relations and are not claimed here.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const core_air_utils = @import("stwo_core").air.utils;
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const action_schedule = @import("../action_schedule.zig");
const joypad_trace = @import("../joypad_trace.zig");
const machine = @import("../runner/machine.zig");
const runner = @import("../runner/mod.zig");
const component_domain = @import("component_domain.zig");
const joypad_air = @import("joypad.zig");
const joypad_binding = @import("joypad_binding.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const RELATION_TAG: u32 = 0x4a41_4c01;
pub const N_PUBLIC_COLUMNS: usize = 3;
pub const N_EVENT_MAIN_COLUMNS: usize = joypad_binding.N_MAIN_COLUMNS;
pub const N_INTERACTION_COLUMNS: usize = 8;
pub const N_CONSTRAINTS: usize = 6;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

pub const Relation = struct {
    z: QM31,
    alpha: QM31,

    pub fn draw(
        allocator: std.mem.Allocator,
        channel: anytype,
    ) !Relation {
        channel.mixU32s(&.{RELATION_TAG});
        const values = try channel.drawSecureFelts(allocator, 2);
        defer allocator.free(values);
        return .{ .z = values[0], .alpha = values[1] };
    }

    pub fn dummy() Relation {
        return .{
            .z = QM31.fromU32Unchecked(3, 5, 7, 11),
            .alpha = QM31.fromU32Unchecked(13, 17, 19, 23),
        };
    }

    pub fn combine(
        self: Relation,
        mcycle: QM31,
        pressed: QM31,
    ) QM31 {
        return mcycle.add(self.alpha.mul(pressed)).sub(self.z);
    }
};

pub const Claims = struct {
    events: QM31,
    public: QM31,

    pub fn total(self: Claims) QM31 {
        return self.events.add(self.public);
    }
};

pub const PublicTable = struct {
    columns: [N_PUBLIC_COLUMNS][]M31,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *PublicTable) void {
        for (self.columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub const Witness = joypad_binding.Witness;

pub const Interaction = struct {
    columns: [N_INTERACTION_COLUMNS][]M31,
    claims: Claims,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Interaction) void {
        for (self.columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn generatePublicTable(
    allocator: std.mem.Allocator,
    log_size: u32,
    initial_mcycle: u32,
    final_mcycle: u32,
    actions: []const action_schedule.Action,
) !PublicTable {
    const size = try traceSize(log_size);
    if (actions.len > size) return error.TooManyActionsForTrace;
    try action_schedule.validate(
        initial_mcycle,
        final_mcycle,
        actions,
    );
    var result = PublicTable{
        .columns = undefined,
        .allocator = allocator,
    };
    var initialized: usize = 0;
    errdefer for (result.columns[0..initialized]) |column|
        allocator.free(column);
    for (&result.columns) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    for (actions, 0..) |action, row| {
        try validateMcycle(action.mcycle);
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row,
        );
        result.columns[0][storage] = M31.one();
        result.columns[1][storage] =
            M31.fromCanonical(action.mcycle);
        result.columns[2][storage] =
            M31.fromCanonical(action.pressed);
    }
    return result;
}

pub fn validatePublicTable(
    columns: []const []const M31,
    log_size: u32,
    initial_mcycle: u32,
    final_mcycle: u32,
    actions: []const action_schedule.Action,
) !void {
    if (columns.len != N_PUBLIC_COLUMNS)
        return error.InvalidPublicTableShape;
    var expected = try generatePublicTable(
        std.heap.page_allocator,
        log_size,
        initial_mcycle,
        final_mcycle,
        actions,
    );
    defer expected.deinit();
    for (columns, expected.columns) |actual, canonical| {
        if (actual.len != canonical.len)
            return error.NonCanonicalPublicTable;
        for (actual, canonical) |value, expected_value|
            if (value.v != expected_value.v)
                return error.NonCanonicalPublicTable;
    }
}

pub fn generateWitness(
    allocator: std.mem.Allocator,
    source: joypad_trace.Trace,
    steps: anytype,
) !Witness {
    if (comptime std.meta.Elem(@TypeOf(steps)) ==
        machine.CartridgeStepResult)
        return joypad_binding.generateMachineExecutionWitness(
            allocator,
            source,
            steps,
        );
    return joypad_binding.generateWitness(allocator, source, steps);
}

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    log_size: u32,
    initial_mcycle: u32,
    final_mcycle: u32,
    actions: []const action_schedule.Action,
    events: []const joypad_trace.EventRow,
    steps: anytype,
    relation: Relation,
) !Interaction {
    const size = try traceSize(log_size);
    if (actions.len > size) return error.TooManyActionsForTrace;
    if (events.len > size) return error.TooManyEventsForTrace;
    try action_schedule.validate(
        initial_mcycle,
        final_mcycle,
        actions,
    );
    for (actions) |action| try validateMcycle(action.mcycle);
    for (events) |event| {
        _ = if (comptime std.meta.Elem(@TypeOf(steps)) ==
            machine.CartridgeStepResult)
            try joypad_binding.machineColumns(event, steps)
        else
            try joypad_binding.columns(event, steps);
    }

    var result = Interaction{
        .columns = undefined,
        .claims = undefined,
        .allocator = allocator,
    };
    var initialized: usize = 0;
    errdefer for (result.columns[0..initialized]) |column|
        allocator.free(column);
    for (&result.columns) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }

    var event_sum = QM31.zero();
    var public_sum = QM31.zero();
    for (0..size) |row| {
        const event_pair = if (row < events.len)
            pairFromEvent(events[row], relation)
        else
            inactivePair();
        event_sum = try accumulate(event_sum, event_pair);
        const public_pair = if (row < actions.len)
            pairFromAction(actions[row], relation)
        else
            inactivePair();
        public_sum = try accumulate(public_sum, public_pair);
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row,
        );
        writeSecure(result.columns[0..4], storage, event_sum);
        writeSecure(result.columns[4..8], storage, public_sum);
    }
    result.claims = .{ .events = event_sum, .public = public_sum };
    return result;
}

pub fn verifyCancellation(claims: Claims) !void {
    if (!claims.total().isZero())
        return error.JoypadActionLookupSumNonZero;
}

const Pair = struct {
    numerator: QM31,
    denominator: QM31,
};

fn pairFromAction(action: action_schedule.Action, relation: Relation) Pair {
    return .{
        .numerator = QM31.one(),
        .denominator = relation.combine(
            QM31.fromBase(M31.fromCanonical(action.mcycle)),
            QM31.fromBase(M31.fromCanonical(action.pressed)),
        ),
    };
}

fn pairFromEvent(event: joypad_trace.EventRow, relation: Relation) Pair {
    return switch (event.transition.event) {
        .set_pressed => |pressed| .{
            .numerator = QM31.one().neg(),
            .denominator = relation.combine(
                QM31.fromBase(M31.fromCanonical(event.mcycle)),
                QM31.fromBase(M31.fromCanonical(pressed)),
            ),
        },
        else => inactivePair(),
    };
}

fn inactivePair() Pair {
    return .{ .numerator = QM31.zero(), .denominator = QM31.one() };
}
fn accumulate(current: QM31, pair: Pair) !QM31 {
    return current.add(pair.numerator.mul(
        pair.denominator.inv() catch
            return error.JoypadActionLookupZeroDenominator,
    ));
}
fn writeSecure(
    columns: []const []M31,
    row: usize,
    value: QM31,
) void {
    for (columns, value.toM31Array()) |column, coordinate|
        column[row] = coordinate;
}
fn traceSize(log_size: u32) !usize {
    if (log_size < 4 or log_size >= @bitSizeOf(usize))
        return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}
fn validateMcycle(mcycle: u32) !void {
    if (mcycle >= M31_MODULUS)
        return error.McycleOutsideField;
}

pub fn RelationValues(comptime S: type) type {
    return struct { z: S, alpha: S };
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
    public_values: [N_PUBLIC_COLUMNS]S,
    joypad_active: S,
    joypad_values: []const S,
    event_mcycle: S,
    event_current: S,
    event_previous: S,
    public_current: S,
    public_previous: S,
    is_first: S,
    event_claim: S,
    public_claim: S,
    relation: RelationValues(S),
) !Evaluation(S) {
    const one = S.one();
    const source =
        try joypad_air.Semantics(S).Row.fromColumns(joypad_values);
    const event_selector = source.events[0];
    const event_pressed = compose(S, source.action);
    const event_denominator = gatedDenominator(
        S,
        event_selector,
        combine(S, relation, event_mcycle, event_pressed),
    );
    const public_active = public_values[0];
    const public_denominator = gatedDenominator(
        S,
        public_active,
        combine(S, relation, public_values[1], public_values[2]),
    );
    return .{ .values = .{
        recurrence(
            S,
            event_current,
            event_previous,
            is_first,
            event_claim,
            event_selector.neg(),
            event_denominator,
        ),
        recurrence(
            S,
            public_current,
            public_previous,
            is_first,
            public_claim,
            public_active,
            public_denominator,
        ),
        one.sub(joypad_active).mul(event_mcycle),
        public_active.mul(public_active.sub(one)),
        one.sub(public_active).mul(public_values[1]),
        one.sub(public_active).mul(public_values[2]),
    } };
}

fn combine(
    comptime S: type,
    relation: RelationValues(S),
    mcycle: S,
    pressed: S,
) S {
    return mcycle.add(relation.alpha.mul(pressed)).sub(relation.z);
}

fn gatedDenominator(
    comptime S: type,
    active: S,
    denominator: S,
) S {
    return S.one().sub(active).add(active.mul(denominator));
}

fn recurrence(
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

fn compose(comptime S: type, bits: anytype) S {
    var result = S.zero();
    var power = S.one();
    for (bits) |bit_value| {
        result = result.add(power.mul(bit_value));
        power = power.add(power);
    }
    return result;
}

pub const Component = struct {
    log_size: u32,
    is_first_column: usize,
    public_active_column: usize,
    public_mcycle_column: usize,
    public_pressed_column: usize,
    binding_main_offset: usize,
    interaction_offset: usize,
    relation: *const Relation,
    claims: Claims,

    const Self = @This();
    const Adapter = core_air_derive.ComponentAdapter(
        Self,
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_accumulation.DomainEvaluationAccumulator,
    );

    pub fn asVerifierComponent(
        self: *const Self,
    ) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(
        self: *const Self,
    ) prover_component.ComponentProver {
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
        const preprocessed = try allocator.alloc(
            u32,
            self.maxPreprocessedIndex() + 1,
        );
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, self.log_size);
        const main = try allocator.alloc(
            u32,
            self.binding_main_offset + joypad_binding.MCYCLE_OFFSET + 1,
        );
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        const interaction = try allocator.alloc(
            u32,
            self.interaction_offset + N_INTERACTION_COLUMNS,
        );
        errdefer allocator.free(interaction);
        @memset(interaction, self.log_size);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{
                preprocessed,
                main,
                interaction,
            }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const Self,
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.dupe(usize, &.{
            self.is_first_column,
            self.public_active_column,
            self.public_mcycle_column,
            self.public_pressed_column,
        });
    }

    pub fn maskPoints(
        self: *const Self,
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        if (max_log_degree_bound < self.log_size)
            return error.InvalidProofShape;
        const preprocessed = try component_domain.currentPointColumns(
            allocator,
            self.maxPreprocessedIndex() + 1,
            point,
        );
        errdefer component_domain.freePointColumns(
            allocator,
            preprocessed,
        );
        const main = try component_domain.currentPointColumns(
            allocator,
            self.binding_main_offset + joypad_binding.MCYCLE_OFFSET + 1,
            point,
        );
        errdefer component_domain.freePointColumns(allocator, main);
        const interaction =
            try component_domain.currentAndPreviousPointColumns(
                allocator,
                self.interaction_offset + N_INTERACTION_COLUMNS,
                point,
                previousRowPoint(max_log_degree_bound, point),
            );
        errdefer component_domain.freePointColumns(
            allocator,
            interaction,
        );
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{
                preprocessed,
                main,
                interaction,
            }),
        );
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const Self,
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (max_log_degree_bound < self.log_size or mask.items.len < 3)
            return error.InvalidProofShape;
        const preprocessed = mask.items[0];
        const main = mask.items[1];
        const interaction = mask.items[2];
        try self.validateMask(preprocessed, main, interaction);
        var direct: [joypad_air.N_MAIN_COLUMNS]QM31 = undefined;
        for (
            &direct,
            main[self.binding_main_offset + 1 ..][0..joypad_air.N_MAIN_COLUMNS],
        ) |*value, column| value.* = column[0];
        const evaluation = try evaluateRows(
            QM31,
            .{
                preprocessed[self.public_active_column][0],
                preprocessed[self.public_mcycle_column][0],
                preprocessed[self.public_pressed_column][0],
            },
            main[self.binding_main_offset][0],
            &direct,
            main[
                self.binding_main_offset + joypad_binding.MCYCLE_OFFSET
            ][0],
            try sampledSecure(interaction, self.interaction_offset, 0),
            try sampledSecure(interaction, self.interaction_offset, 1),
            try sampledSecure(interaction, self.interaction_offset + 4, 0),
            try sampledSecure(interaction, self.interaction_offset + 4, 1),
            preprocessed[self.is_first_column][0],
            self.claims.events,
            self.claims.public,
            relationValues(self.relation.*),
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
        if (trace.polys.items.len < 3)
            return error.InvalidProofShape;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        const interaction = trace.polys.items[2];
        if (preprocessed.len <= self.maxPreprocessedIndex() or
            main.len <
                self.binding_main_offset + joypad_binding.MCYCLE_OFFSET + 1 or
            interaction.len <
                self.interaction_offset + N_INTERACTION_COLUMNS)
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const source_count =
            5 + joypad_binding.MCYCLE_OFFSET + N_INTERACTION_COLUMNS;
        const evaluations = try allocator.alloc(
            []const M31,
            source_count,
        );
        defer allocator.free(evaluations);
        var extensions = std.ArrayList([]M31).empty;
        defer {
            for (extensions.items) |values| allocator.free(values);
            extensions.deinit(allocator);
        }
        const sources = .{
            preprocessed[self.is_first_column],
            preprocessed[self.public_active_column],
            preprocessed[self.public_mcycle_column],
            preprocessed[self.public_pressed_column],
        };
        inline for (sources, 0..) |polynomial, index|
            evaluations[index] = try component_domain.evaluationValues(
                allocator,
                polynomial,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extensions,
            );
        var source: usize = 4;
        for (
            main[self.binding_main_offset..][0 .. joypad_binding.MCYCLE_OFFSET + 1],
        ) |polynomial| {
            evaluations[source] = try component_domain.evaluationValues(
                allocator,
                polynomial,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extensions,
            );
            source += 1;
        }
        for (
            interaction[self.interaction_offset..][0..N_INTERACTION_COLUMNS],
        ) |polynomial| {
            evaluations[source] = try component_domain.evaluationValues(
                allocator,
                polynomial,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extensions,
            );
            source += 1;
        }
        std.debug.assert(source == evaluations.len);
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
        var columns = try accumulator.columns(
            allocator,
            &.{.{
                .log_size = evaluation_log_size,
                .n_cols = N_CONSTRAINTS,
            }},
        );
        defer allocator.free(columns);
        const output = &columns[0];
        const shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        const joypad_start: usize = 4;
        const mcycle_index = joypad_start + joypad_binding.MCYCLE_OFFSET;
        const interaction_start = mcycle_index + 1;
        for (0..evaluation_size) |row| {
            const previous =
                utils.previousBitReversedCircleDomainIndex(
                    row,
                    self.log_size,
                    evaluation_log_size,
                );
            var direct: [joypad_air.N_MAIN_COLUMNS]QM31 = undefined;
            for (
                &direct,
                evaluations[joypad_start + 1 .. joypad_start + joypad_binding.MCYCLE_OFFSET],
            ) |*value, values|
                value.* = QM31.fromBase(values[row]);
            const evaluation = try evaluateRows(
                QM31,
                .{
                    QM31.fromBase(evaluations[1][row]),
                    QM31.fromBase(evaluations[2][row]),
                    QM31.fromBase(evaluations[3][row]),
                },
                QM31.fromBase(evaluations[joypad_start][row]),
                &direct,
                QM31.fromBase(evaluations[mcycle_index][row]),
                secureAt(
                    evaluations[interaction_start..][0..4],
                    row,
                ),
                secureAt(
                    evaluations[interaction_start..][0..4],
                    previous,
                ),
                secureAt(
                    evaluations[interaction_start + 4 ..][0..4],
                    row,
                ),
                secureAt(
                    evaluations[interaction_start + 4 ..][0..4],
                    previous,
                ),
                QM31.fromBase(evaluations[0][row]),
                self.claims.events,
                self.claims.public,
                relationValues(self.relation.*),
            );
            var folded = QM31.zero();
            for (evaluation.values, 0..) |constraint, index| {
                const powers = output.random_coeff_powers;
                folded = folded.add(
                    powers[powers.len - 1 - index].mul(constraint),
                );
            }
            output.accumulate(
                row,
                folded.mulM31(inverses[row >> shift]),
            );
        }
    }

    fn validateMask(
        self: *const Self,
        preprocessed: [][]QM31,
        main: [][]QM31,
        interaction: [][]QM31,
    ) !void {
        if (preprocessed.len <= self.maxPreprocessedIndex() or
            main.len <
                self.binding_main_offset + joypad_binding.MCYCLE_OFFSET + 1 or
            interaction.len <
                self.interaction_offset + N_INTERACTION_COLUMNS)
            return error.InvalidProofShape;
        for ([_]usize{
            self.is_first_column,
            self.public_active_column,
            self.public_mcycle_column,
            self.public_pressed_column,
        }) |index| if (preprocessed[index].len < 1)
            return error.InvalidProofShape;
        for (
            main[self.binding_main_offset..][0 .. joypad_binding.MCYCLE_OFFSET + 1],
        ) |column| if (column.len < 1)
            return error.InvalidProofShape;
    }

    fn maxPreprocessedIndex(self: *const Self) usize {
        return @max(
            @max(self.is_first_column, self.public_active_column),
            @max(
                self.public_mcycle_column,
                self.public_pressed_column,
            ),
        );
    }
};

fn relationValues(relation: Relation) RelationValues(QM31) {
    return .{ .z = relation.z, .alpha = relation.alpha };
}

fn previousRowPoint(
    log_size: u32,
    point: CirclePointQM31,
) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.sub(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}

fn sampledSecure(
    columns: [][]QM31,
    offset: usize,
    point: usize,
) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (&coordinates, 0..) |*coordinate, index| {
        if (columns.len <= offset + index or
            columns[offset + index].len <= point)
            return error.InvalidProofShape;
        coordinate.* = columns[offset + index][point];
    }
    return QM31.fromPartialEvals(coordinates);
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(
        columns[0][row],
        columns[1][row],
        columns[2][row],
        columns[3][row],
    );
}

test "machine action lookup rejects a vacuous witness" {
    var rows: [0]joypad_trace.EventRow = .{};
    try std.testing.expectError(
        error.EmptyJoypadTrace,
        generateWitness(
            std.testing.allocator,
            .{ .rows = &rows, .final_state = .{}, .final_mcycle = 0 },
            &[_]machine.CartridgeStepResult{},
        ),
    );
}
