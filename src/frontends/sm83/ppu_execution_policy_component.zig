//! Prover/verifier component adapter for the SM83 PPU execution policy.
//!
//! Semantic constraints and relation tuples remain owned by
//! `ppu_execution_policy.zig`; this leaf only maps them onto Stwo sampled
//! points and prover evaluation domains.

const std = @import("std");
const core = @import("stwo_core");
const core_air_accumulation = core.air.accumulation;
const core_air_components = core.air.components;
const core_air_derive = core.air.derive;
const core_constraints = core.constraints;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const canonic = core.poly.circle.canonic;
const prover_accumulation =
    @import("stwo_prover_engine").air.accumulation;
const prover_component =
    @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const component_domain = @import("air/component_domain.zig");
const dma_binding = @import("air/dma_binding.zig");
const dma_binding_component = @import("air/dma_binding_component.zig");
const dma_execution = @import("air/dma_execution_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const ppu_binding_component = @import("air/ppu_binding_component.zig");
const policy = @import("ppu_execution_policy_air.zig");

const CirclePointQM31 = core.circle.CirclePointQM31;
const Kind = policy.Kind;
const Claims = policy.Claims;
const N_MAIN_COLUMNS = policy.N_MAIN_COLUMNS;
const N_DMA_CONSTRAINTS = policy.N_DMA_CONSTRAINTS;
const N_PPU_CONSTRAINTS = policy.N_PPU_CONSTRAINTS;
const N_MAX_CONSTRAINTS = policy.N_MAX_CONSTRAINTS;
const dmaPairGeneric = policy.dmaPairGeneric;
const evaluatePpuRows = policy.evaluatePpuRows;
const verifyCancellation = policy.verifyCancellation;

/// Reuses the already challenged DMA bus relation. The DMA owner proves the
/// sensitive CPU-access clock; the PPU owner proves that exactly one matching
/// phase-zero selector exists and that its timing lies outside variable mode
/// 3. STAT uses the existing PPU-MMIO join and needs no additional selector.
pub const Component = struct {
    kind: Kind,
    log_size: u32,
    is_first_column: usize,
    binding_offset: usize,
    selector_offset: usize = 0,
    interaction_offset: usize,
    relations: *const dma_execution.Relations,
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

    pub fn nConstraints(self: *const Self) usize {
        return switch (self.kind) {
            .dma => N_DMA_CONSTRAINTS,
            .ppu => N_PPU_CONSTRAINTS,
        };
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
            self.is_first_column + 1,
        );
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, self.log_size);
        const main = try allocator.alloc(u32, self.mainEnd());
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        const interaction = try allocator.alloc(
            u32,
            self.interaction_offset + 4,
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
        try self.validateConfiguration();
        return allocator.dupe(usize, &.{self.is_first_column});
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
            self.is_first_column + 1,
            point,
        );
        errdefer component_domain.freePointColumns(
            allocator,
            preprocessed,
        );
        const main = try component_domain.currentPointColumns(
            allocator,
            self.mainEnd(),
            point,
        );
        errdefer component_domain.freePointColumns(allocator, main);
        const interaction =
            try component_domain.currentAndPreviousPointColumns(
                allocator,
                self.interaction_offset + 4,
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
        try self.validateConfiguration();
        if (max_log_degree_bound < self.log_size or mask.items.len < 3)
            return error.InvalidProofShape;
        var constraints: [N_MAX_CONSTRAINTS]QM31 = undefined;
        const count = try self.evaluateSampled(
            mask.items[0],
            mask.items[1],
            mask.items[2],
            &constraints,
        );
        const inverse = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.log_size),
        ).inv();
        for (constraints[0..count]) |constraint|
            accumulator.accumulate(constraint.mul(inverse));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const Self,
        trace: *const prover_component.Trace,
        accumulator: *prover_accumulation.DomainEvaluationAccumulator,
    ) !void {
        try self.validateConfiguration();
        if (trace.polys.items.len < 3) return error.InvalidProofShape;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        const interaction = trace.polys.items[2];
        if (preprocessed.len <= self.is_first_column or
            main.len < self.mainEnd() or
            interaction.len < self.interaction_offset + 4)
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const domain = canonic.CanonicCoset.new(
            evaluation_log_size,
        ).circleDomain();
        const evaluation_size = domain.size();
        const evaluations = try allocator.alloc(
            []const M31,
            1 + self.dataColumns() + 4,
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
        var at: usize = 1;
        at = try extendRange(
            allocator,
            main[self.binding_offset..][0..self.bindingColumns()],
            evaluations,
            at,
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        if (self.kind == .ppu)
            at = try extendRange(
                allocator,
                main[self.selector_offset..][0..N_MAIN_COLUMNS],
                evaluations,
                at,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extensions,
            );
        at = try extendRange(
            allocator,
            interaction[self.interaction_offset..][0..4],
            evaluations,
            at,
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extensions,
        );
        std.debug.assert(at == evaluations.len);
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
                .n_cols = self.nConstraints(),
            }},
        );
        defer allocator.free(columns);
        const output = &columns[0];
        const shift: std.math.Log2Int(usize) = @intCast(self.log_size);
        const interaction_start = 1 + self.dataColumns();
        for (0..evaluation_size) |row| {
            const previous = core.utils.previousBitReversedCircleDomainIndex(
                row,
                self.log_size,
                evaluation_log_size,
            );
            var constraints: [N_MAX_CONSTRAINTS]QM31 = undefined;
            const count = try self.evaluateDomainRow(
                evaluations,
                interaction_start,
                row,
                previous,
                &constraints,
            );
            var folded = QM31.zero();
            for (constraints[0..count], 0..) |constraint, index| {
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

    pub fn evaluateSampled(
        self: *const Self,
        preprocessed: [][]QM31,
        main: [][]QM31,
        interaction: [][]QM31,
        constraints: *[N_MAX_CONSTRAINTS]QM31,
    ) !usize {
        try self.validateConfiguration();
        if (preprocessed.len <= self.is_first_column or
            preprocessed[self.is_first_column].len < 1 or
            main.len < self.mainEnd() or
            interaction.len < self.interaction_offset + 4)
            return error.InvalidProofShape;
        const is_first = preprocessed[self.is_first_column][0];
        const current = try sampledSecure(
            interaction,
            self.interaction_offset,
            0,
        );
        const previous = try sampledSecure(
            interaction,
            self.interaction_offset,
            1,
        );
        if (self.kind == .dma) {
            var values: [dma_binding.N_MAIN_COLUMNS]QM31 = undefined;
            try sampledColumns(
                &values,
                main[self.binding_offset..][0..dma_binding.N_MAIN_COLUMNS],
            );
            const entry = dmaPairGeneric(
                QM31,
                try dma_binding_component.Row(QM31).fromColumns(&values),
                self.relations.*,
            );
            constraints[0] = dma_execution.pairConstraint(
                QM31,
                current,
                previous,
                is_first,
                self.claims.dma,
                entry.n1,
                entry.d1,
                entry.n2,
                entry.d2,
            );
            return N_DMA_CONSTRAINTS;
        }

        var values: [ppu_binding.N_MAIN_COLUMNS]QM31 = undefined;
        var selectors: [N_MAIN_COLUMNS]QM31 = undefined;
        try sampledColumns(
            &values,
            main[self.binding_offset..][0..ppu_binding.N_MAIN_COLUMNS],
        );
        try sampledColumns(
            &selectors,
            main[self.selector_offset..][0..N_MAIN_COLUMNS],
        );
        constraints.* = evaluatePpuRows(
            QM31,
            try ppu_binding_component.Row(QM31).fromColumns(&values),
            selectors,
            current,
            previous,
            is_first,
            self.claims.ppu,
            self.relations.*,
        );
        return N_PPU_CONSTRAINTS;
    }

    fn evaluateDomainRow(
        self: *const Self,
        evaluations: []const []const M31,
        interaction_start: usize,
        row: usize,
        previous: usize,
        constraints: *[N_MAX_CONSTRAINTS]QM31,
    ) !usize {
        const is_first = QM31.fromBase(evaluations[0][row]);
        const current_sum = secureAt(
            evaluations[interaction_start..][0..4],
            row,
        );
        const previous_sum = secureAt(
            evaluations[interaction_start..][0..4],
            previous,
        );
        if (self.kind == .dma) {
            var values: [dma_binding.N_MAIN_COLUMNS]QM31 = undefined;
            _ = domainColumns(&values, evaluations, 1, row);
            const entry = dmaPairGeneric(
                QM31,
                try dma_binding_component.Row(QM31).fromColumns(&values),
                self.relations.*,
            );
            constraints[0] = dma_execution.pairConstraint(
                QM31,
                current_sum,
                previous_sum,
                is_first,
                self.claims.dma,
                entry.n1,
                entry.d1,
                entry.n2,
                entry.d2,
            );
            return N_DMA_CONSTRAINTS;
        }

        var values: [ppu_binding.N_MAIN_COLUMNS]QM31 = undefined;
        var selectors: [N_MAIN_COLUMNS]QM31 = undefined;
        const at = domainColumns(&values, evaluations, 1, row);
        _ = domainColumns(&selectors, evaluations, at, row);
        constraints.* = evaluatePpuRows(
            QM31,
            try ppu_binding_component.Row(QM31).fromColumns(&values),
            selectors,
            current_sum,
            previous_sum,
            is_first,
            self.claims.ppu,
            self.relations.*,
        );
        return N_PPU_CONSTRAINTS;
    }

    fn bindingColumns(self: *const Self) usize {
        return switch (self.kind) {
            .dma => dma_binding.N_MAIN_COLUMNS,
            .ppu => ppu_binding.N_MAIN_COLUMNS,
        };
    }

    fn mainEnd(self: *const Self) usize {
        const binding_end = self.binding_offset + self.bindingColumns();
        return if (self.kind == .ppu)
            @max(binding_end, self.selector_offset + N_MAIN_COLUMNS)
        else
            binding_end;
    }

    fn dataColumns(self: *const Self) usize {
        return self.bindingColumns() +
            @as(usize, if (self.kind == .ppu) N_MAIN_COLUMNS else 0);
    }

    fn validateConfiguration(self: *const Self) !void {
        if (self.log_size < 4 or self.log_size > 24)
            return error.InvalidPpuExecutionPolicyLogSize;
        try verifyCancellation(self.claims);
    }
};

fn extendRange(
    allocator: std.mem.Allocator,
    polynomials: []const prover_component.Poly,
    evaluations: [][]const M31,
    start: usize,
    source_log_size: u32,
    evaluation_log_size: u32,
    evaluation_size: usize,
    extensions: *std.ArrayList([]M31),
) !usize {
    var at = start;
    for (polynomials) |polynomial| {
        evaluations[at] = try component_domain.evaluationValues(
            allocator,
            polynomial,
            source_log_size,
            evaluation_log_size,
            evaluation_size,
            extensions,
        );
        at += 1;
    }
    return at;
}

fn sampledColumns(output: []QM31, columns: [][]QM31) !void {
    if (output.len != columns.len) return error.InvalidProofShape;
    for (output, columns) |*value, column| {
        if (column.len < 1) return error.InvalidProofShape;
        value.* = column[0];
    }
}

fn domainColumns(
    output: []QM31,
    evaluations: []const []const M31,
    start: usize,
    row: usize,
) usize {
    for (output, evaluations[start..][0..output.len]) |*value, values|
        value.* = QM31.fromBase(values[row]);
    return start + output.len;
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

test "PPU policy AIR admits only early late and vblank access rows" {
    const relations = dma_execution.Relations.dummy();

    var early = policyTestRow(.early);
    try expectPolicyConstraints(
        early,
        .{ QM31.one(), QM31.zero() },
        relations,
        true,
    );
    early.phases[0] = QM31.zero();
    try expectPolicyConstraints(
        early,
        .{ QM31.one(), QM31.zero() },
        relations,
        false,
    );

    const late = policyTestRow(.late);
    try expectPolicyConstraints(
        late,
        .{ QM31.one(), QM31.zero() },
        relations,
        true,
    );
    try expectPolicyConstraints(
        late,
        .{ QM31.zero(), QM31.one() },
        relations,
        true,
    );

    const vblank = policyTestRow(.vblank);
    try expectPolicyConstraints(
        vblank,
        .{ QM31.one(), QM31.zero() },
        relations,
        true,
    );
    try expectPolicyConstraints(
        vblank,
        .{ QM31.zero(), QM31.one() },
        relations,
        true,
    );
}

test "PPU policy AIR rejects unsafe selectors STAT and forged recurrence" {
    const relations = dma_execution.Relations.dummy();
    const variable = policyTestRow(.variable);
    try expectPolicyConstraints(
        variable,
        .{ QM31.one(), QM31.zero() },
        relations,
        false,
    );
    try expectPolicyConstraints(
        variable,
        .{ QM31.zero(), QM31.one() },
        relations,
        false,
    );

    var inactive = policyTestRow(.late);
    inactive.active = QM31.zero();
    try expectPolicyConstraints(
        inactive,
        .{ QM31.one(), QM31.zero() },
        relations,
        false,
    );

    var stat_read = variable;
    stat_read.read_markers[policy.STAT_REGISTER] = QM31.one();
    try expectPolicyConstraints(
        stat_read,
        .{ QM31.zero(), QM31.zero() },
        relations,
        false,
    );
    var stat_write = variable;
    stat_write.semantic.events[policy.WRITE_STAT_EVENT] = QM31.one();
    try expectPolicyConstraints(
        stat_write,
        .{ QM31.zero(), QM31.zero() },
        relations,
        false,
    );

    const early = policyTestRow(.early);
    const forged = policy.evaluatePpuRows(
        QM31,
        early,
        .{ QM31.one(), QM31.zero() },
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        relations,
    );
    try std.testing.expect(!forged[policy.N_PPU_CONSTRAINTS - 1].isZero());
}

test "PPU policy DMA AIR rejects an omitted sensitive access" {
    const relations = dma_execution.Relations.dummy();
    var row = std.mem.zeroes(dma_binding_component.Row(QM31));
    row.mcycle = q(9);
    row.address_vram = QM31.one();
    const entry = policy.dmaPairGeneric(QM31, row, relations);
    const constraint = dma_execution.pairConstraint(
        QM31,
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        entry.n1,
        entry.d1,
        entry.n2,
        entry.d2,
    );
    try std.testing.expect(!constraint.isZero());
}

const PolicyWindow = enum { early, variable, late, vblank };

fn policyTestRow(
    window: PolicyWindow,
) ppu_binding_component.Row(QM31) {
    var row = std.mem.zeroes(ppu_binding_component.Row(QM31));
    row.active = QM31.one();
    row.mcycle = q(9);
    row.phases[0] = QM31.one();
    row.semantic.before.lcd = QM31.one();
    switch (window) {
        .early => row.semantic.before_aux.dot_segments[0] = QM31.one(),
        .variable => row.semantic.before_aux.dot_segments[
            policy.FIRST_MODE3_DOT_SEGMENT
        ] = QM31.one(),
        .late => row.semantic.before_aux.dot_segments[
            policy.FIRST_CERTAIN_HBLANK_DOT_SEGMENT
        ] = QM31.one(),
        .vblank => row.semantic.before_aux.line_segments[
            policy.FIRST_VBLANK_LINE_SEGMENT
        ] = QM31.one(),
    }
    return row;
}

fn expectPolicyConstraints(
    row: ppu_binding_component.Row(QM31),
    selectors: [policy.N_MAIN_COLUMNS]QM31,
    relations: dma_execution.Relations,
    expected_zero: bool,
) !void {
    const entry = policy.ppuPairGeneric(
        QM31,
        row.mcycle,
        selectors[policy.VRAM_SELECTOR],
        selectors[policy.OAM_SELECTOR],
        relations,
    );
    const current = entry.n1.mul(try entry.d1.inv())
        .add(entry.n2.mul(try entry.d2.inv()));
    const constraints = policy.evaluatePpuRows(
        QM31,
        row,
        selectors,
        current,
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
        relations,
    );
    var all_zero = true;
    for (constraints) |constraint|
        all_zero = all_zero and constraint.isZero();
    try std.testing.expectEqual(expected_zero, all_zero);
}

fn q(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}
