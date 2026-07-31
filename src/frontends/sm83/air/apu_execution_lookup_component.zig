//! Backend-generic AIR owners for ordered execution/APU LogUp cancellation.

const std = @import("std");
const core = @import("stwo_core");
const core_air_accumulation = core.air.accumulation;
const core_air_components = core.air.components;
const core_air_derive = core.air.derive;
const core_constraints = core.constraints;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const canonic = core.poly.circle.canonic;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const binding = @import("apu_binding.zig");
const component_support = @import("apu_execution_lookup_component_support.zig");
const cartridge_access = @import("cartridge_access_component.zig");
const component_domain = @import("component_domain.zig");
const execution = @import("execution.zig");
const lookup = @import("apu_execution_lookup.zig");

const CirclePointQM31 = core.circle.CirclePointQM31;

pub const Kind = enum { execution, apu };
pub const N_MAX_CONSTRAINTS: usize = @max(
    lookup.N_EXECUTION_CONSTRAINTS,
    lookup.N_APU_CONSTRAINTS,
);
pub const MAX_CONSTRAINT_DEGREE = lookup.MAX_CONSTRAINT_DEGREE;

pub const Component = struct {
    kind: Kind,
    log_size: u32,
    is_first_column: usize,
    is_last_column: usize,
    execution_offset: usize = 0,
    access_offset: usize = 0,
    binding_offset: usize = 0,
    auxiliary_offset: usize,
    interaction_offset: usize,
    relation: *const lookup.Relation,
    claims: lookup.Claims,

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
            .execution => lookup.N_EXECUTION_CONSTRAINTS,
            .apu => lookup.N_APU_CONSTRAINTS,
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
            @max(self.is_first_column, self.is_last_column) + 1,
        );
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, self.log_size);
        const main = try allocator.alloc(u32, self.mainEnd());
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        const interaction = try allocator.alloc(
            u32,
            self.interaction_offset + self.interactionColumns(),
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
        return allocator.dupe(usize, &.{
            self.is_first_column,
            self.is_last_column,
        });
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
        errdefer component_domain.freePointColumns(
            allocator,
            preprocessed,
        );
        const main = try component_domain.currentAndNextPointColumns(
            allocator,
            self.mainEnd(),
            point,
            component_support.nextRowPoint(max_log_degree_bound, point),
        );
        errdefer component_domain.freePointColumns(allocator, main);
        const interaction =
            try component_domain.currentAndPreviousPointColumns(
                allocator,
                self.interaction_offset + self.interactionColumns(),
                point,
                component_support.previousRowPoint(max_log_degree_bound, point),
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
            preprocessed.len <= self.is_last_column or
            main.len < self.mainEnd() or
            interaction.len <
                self.interaction_offset + self.interactionColumns())
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const data_columns = self.dataColumns();
        const interaction_columns = self.interactionColumns();
        const evaluations = try allocator.alloc(
            []const M31,
            2 + data_columns + interaction_columns,
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
        var at: usize = 2;
        switch (self.kind) {
            .execution => {
                at = try component_support.extendRange(
                    allocator,
                    main[self.execution_offset..][0..execution.N_MAIN_COLUMNS],
                    evaluations,
                    at,
                    self.log_size,
                    evaluation_log_size,
                    evaluation_size,
                    &extensions,
                );
                at = try component_support.extendRange(
                    allocator,
                    main[self.access_offset..][0..cartridge_access.N_MAIN_COLUMNS],
                    evaluations,
                    at,
                    self.log_size,
                    evaluation_log_size,
                    evaluation_size,
                    &extensions,
                );
                at = try component_support.extendRange(
                    allocator,
                    main[self.auxiliary_offset..][0..lookup.N_EXECUTION_AUXILIARY_COLUMNS],
                    evaluations,
                    at,
                    self.log_size,
                    evaluation_log_size,
                    evaluation_size,
                    &extensions,
                );
            },
            .apu => {
                at = try component_support.extendRange(
                    allocator,
                    main[self.binding_offset..][0..binding.layout.N_MAIN_COLUMNS],
                    evaluations,
                    at,
                    self.log_size,
                    evaluation_log_size,
                    evaluation_size,
                    &extensions,
                );
                at = try component_support.extendRange(
                    allocator,
                    main[self.auxiliary_offset..][0..lookup.N_APU_AUXILIARY_COLUMNS],
                    evaluations,
                    at,
                    self.log_size,
                    evaluation_log_size,
                    evaluation_size,
                    &extensions,
                );
            },
        }
        at = try component_support.extendRange(
            allocator,
            interaction[self.interaction_offset..][0..interaction_columns],
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
        const interaction_start = 2 + data_columns;
        for (0..evaluation_size) |row| {
            const next = core.utils.offsetBitReversedCircleDomainIndex(
                row,
                self.log_size,
                evaluation_log_size,
                1,
            );
            const previous =
                core.utils.previousBitReversedCircleDomainIndex(
                    row,
                    self.log_size,
                    evaluation_log_size,
                );
            var constraints: [N_MAX_CONSTRAINTS]QM31 = undefined;
            const count = try self.evaluateDomainRow(
                evaluations,
                interaction_start,
                row,
                next,
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
            preprocessed.len <= self.is_last_column or
            preprocessed[self.is_first_column].len < 1 or
            preprocessed[self.is_last_column].len < 1 or
            main.len < self.mainEnd() or
            interaction.len <
                self.interaction_offset + self.interactionColumns())
            return error.InvalidProofShape;
        const is_first = preprocessed[self.is_first_column][0];
        const is_last = preprocessed[self.is_last_column][0];
        if (self.kind == .execution) {
            var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
            var access_values: [cartridge_access.N_MAIN_COLUMNS]QM31 =
                undefined;
            try component_support.sampledCurrentColumns(
                &machine_values,
                main[self.execution_offset..][0..execution.N_MAIN_COLUMNS],
            );
            try component_support.sampledCurrentColumns(
                &access_values,
                main[self.access_offset..][0..cartridge_access.N_MAIN_COLUMNS],
            );
            if (main[self.auxiliary_offset].len < 2)
                return error.InvalidProofShape;
            return self.evaluateExecutionRow(
                try execution.Row(QM31).fromColumns(&machine_values),
                try cartridge_access.PackedRow(QM31).fromColumns(
                    &access_values,
                ),
                main[self.auxiliary_offset][0],
                main[self.auxiliary_offset][1],
                interaction,
                is_first,
                is_last,
                constraints,
            );
        }

        var current_values: [binding.layout.N_MAIN_COLUMNS]QM31 = undefined;
        var next_values: [binding.layout.N_MAIN_COLUMNS]QM31 = undefined;
        try component_support.sampledCurrentNextColumns(
            &current_values,
            &next_values,
            main[self.binding_offset..][0..binding.layout.N_MAIN_COLUMNS],
        );
        if (main.len < self.auxiliary_offset + 2 or
            main[self.auxiliary_offset].len < 1 or
            main[self.auxiliary_offset + 1].len < 2)
            return error.InvalidProofShape;
        return self.evaluateApuRow(
            try lookup.apuRow(QM31, &current_values),
            try lookup.apuRow(QM31, &next_values),
            main[self.auxiliary_offset][0],
            main[self.auxiliary_offset + 1][0],
            main[self.auxiliary_offset + 1][1],
            interaction,
            is_first,
            is_last,
            constraints,
        );
    }

    fn evaluateDomainRow(
        self: *const Self,
        evaluations: []const []const M31,
        interaction_start: usize,
        row: usize,
        next: usize,
        previous: usize,
        constraints: *[N_MAX_CONSTRAINTS]QM31,
    ) !usize {
        const is_first = QM31.fromBase(evaluations[0][row]);
        const is_last = QM31.fromBase(evaluations[1][row]);
        if (self.kind == .execution) {
            var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
            var access_values: [cartridge_access.N_MAIN_COLUMNS]QM31 =
                undefined;
            var at = component_support.domainColumns(
                &machine_values,
                evaluations,
                2,
                row,
            );
            at = component_support.domainColumns(
                &access_values,
                evaluations,
                at,
                row,
            );
            const current_order = QM31.fromBase(evaluations[at][row]);
            const next_order = QM31.fromBase(evaluations[at][next]);
            return self.evaluateExecutionDomainRow(
                try execution.Row(QM31).fromColumns(&machine_values),
                try cartridge_access.PackedRow(QM31).fromColumns(
                    &access_values,
                ),
                current_order,
                next_order,
                evaluations[interaction_start..],
                row,
                previous,
                is_first,
                is_last,
                constraints,
            );
        }

        var current_values: [binding.layout.N_MAIN_COLUMNS]QM31 = undefined;
        var next_values: [binding.layout.N_MAIN_COLUMNS]QM31 = undefined;
        var at = component_support.domainCurrentNextColumns(
            &current_values,
            &next_values,
            evaluations,
            2,
            row,
            next,
        );
        const clock = QM31.fromBase(evaluations[at][row]);
        at += 1;
        const order = QM31.fromBase(evaluations[at][row]);
        const next_order = QM31.fromBase(evaluations[at][next]);
        return self.evaluateApuDomainRow(
            try lookup.apuRow(QM31, &current_values),
            try lookup.apuRow(QM31, &next_values),
            clock,
            order,
            next_order,
            evaluations[interaction_start..],
            row,
            previous,
            is_first,
            is_last,
            constraints,
        );
    }

    fn evaluateExecutionRow(
        self: *const Self,
        machine: execution.Row(QM31),
        access: cartridge_access.PackedRow(QM31),
        order: QM31,
        next_order: QM31,
        interaction: [][]QM31,
        is_first: QM31,
        is_last: QM31,
        constraints: *[N_MAX_CONSTRAINTS]QM31,
    ) !usize {
        const pairs = lookup.executionPairs(
            machine,
            access,
            order,
            self.relation.*,
        );
        for (pairs, 0..) |entry, index| {
            constraints[index] = lookup.pairConstraint(
                QM31,
                try component_support.sampledSecure(
                    interaction,
                    self.interaction_offset + 4 * index,
                    0,
                ),
                try component_support.sampledSecure(
                    interaction,
                    self.interaction_offset + 4 * index,
                    1,
                ),
                is_first,
                self.claims.execution[index],
                entry.numerator,
                entry.denominator,
            );
        }
        return component_support.appendExecutionOrder(
            access,
            order,
            next_order,
            is_first,
            is_last,
            self.claims.execution_count,
            constraints,
        );
    }

    fn evaluateExecutionDomainRow(
        self: *const Self,
        machine: execution.Row(QM31),
        access: cartridge_access.PackedRow(QM31),
        order: QM31,
        next_order: QM31,
        interaction: []const []const M31,
        row: usize,
        previous: usize,
        is_first: QM31,
        is_last: QM31,
        constraints: *[N_MAX_CONSTRAINTS]QM31,
    ) !usize {
        const pairs = lookup.executionPairs(
            machine,
            access,
            order,
            self.relation.*,
        );
        for (pairs, 0..) |entry, index| {
            constraints[index] = lookup.pairConstraint(
                QM31,
                component_support.secureAt(
                    interaction[4 * index ..][0..4],
                    row,
                ),
                component_support.secureAt(
                    interaction[4 * index ..][0..4],
                    previous,
                ),
                is_first,
                self.claims.execution[index],
                entry.numerator,
                entry.denominator,
            );
        }
        return component_support.appendExecutionOrder(
            access,
            order,
            next_order,
            is_first,
            is_last,
            self.claims.execution_count,
            constraints,
        );
    }

    fn evaluateApuRow(
        self: *const Self,
        current: lookup.ApuRow(QM31),
        next: lookup.ApuRow(QM31),
        clock: QM31,
        order: QM31,
        next_order: QM31,
        interaction: [][]QM31,
        is_first: QM31,
        is_last: QM31,
        constraints: *[N_MAX_CONSTRAINTS]QM31,
    ) !usize {
        const entry = lookup.apuPair(
            current,
            clock,
            order,
            self.relation.*,
        );
        constraints[0] = lookup.pairConstraint(
            QM31,
            try component_support.sampledSecure(
                interaction,
                self.interaction_offset,
                0,
            ),
            try component_support.sampledSecure(
                interaction,
                self.interaction_offset,
                1,
            ),
            is_first,
            self.claims.apu,
            entry.numerator,
            entry.denominator,
        );
        return component_support.appendApuOrder(
            current.active,
            next.active,
            clock,
            order,
            next_order,
            is_first,
            is_last,
            self.claims.apu_count,
            constraints,
        );
    }

    fn evaluateApuDomainRow(
        self: *const Self,
        current: lookup.ApuRow(QM31),
        next: lookup.ApuRow(QM31),
        clock: QM31,
        order: QM31,
        next_order: QM31,
        interaction: []const []const M31,
        row: usize,
        previous: usize,
        is_first: QM31,
        is_last: QM31,
        constraints: *[N_MAX_CONSTRAINTS]QM31,
    ) !usize {
        const entry = lookup.apuPair(
            current,
            clock,
            order,
            self.relation.*,
        );
        constraints[0] = lookup.pairConstraint(
            QM31,
            component_support.secureAt(interaction[0..4], row),
            component_support.secureAt(interaction[0..4], previous),
            is_first,
            self.claims.apu,
            entry.numerator,
            entry.denominator,
        );
        return component_support.appendApuOrder(
            current.active,
            next.active,
            clock,
            order,
            next_order,
            is_first,
            is_last,
            self.claims.apu_count,
            constraints,
        );
    }

    fn mainEnd(self: *const Self) usize {
        return switch (self.kind) {
            .execution => @max(
                self.execution_offset + execution.N_MAIN_COLUMNS,
                @max(
                    self.access_offset + cartridge_access.N_MAIN_COLUMNS,
                    self.auxiliary_offset +
                        lookup.N_EXECUTION_AUXILIARY_COLUMNS,
                ),
            ),
            .apu => @max(
                self.binding_offset + binding.layout.N_MAIN_COLUMNS,
                self.auxiliary_offset + lookup.N_APU_AUXILIARY_COLUMNS,
            ),
        };
    }

    fn dataColumns(self: *const Self) usize {
        return switch (self.kind) {
            .execution => execution.N_MAIN_COLUMNS +
                cartridge_access.N_MAIN_COLUMNS +
                lookup.N_EXECUTION_AUXILIARY_COLUMNS,
            .apu => binding.layout.N_MAIN_COLUMNS +
                lookup.N_APU_AUXILIARY_COLUMNS,
        };
    }

    fn interactionColumns(self: *const Self) usize {
        return switch (self.kind) {
            .execution => lookup.N_EXECUTION_INTERACTION_COLUMNS,
            .apu => lookup.N_APU_INTERACTION_COLUMNS,
        };
    }

    fn validateConfiguration(self: *const Self) !void {
        if (self.log_size < 4 or self.log_size > 24)
            return error.InvalidApuExecutionLookupLogSize;
        const size = @as(usize, 1) << @intCast(self.log_size);
        if (self.claims.execution_count != self.claims.apu_count)
            return error.ApuExecutionCountMismatch;
        const maximum_events = switch (self.kind) {
            .execution => std.math.mul(
                usize,
                size,
                lookup.N_EXECUTION_SUMS,
            ) catch return error.ApuExecutionCountOutsideField,
            .apu => size,
        };
        if (self.claims.execution_count > maximum_events or
            self.claims.execution_count >= core.fields.m31.Modulus)
            return error.ApuExecutionCountOutsideField;
    }
};
