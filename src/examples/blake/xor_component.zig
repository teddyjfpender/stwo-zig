//! Exact fixed-height XOR multiplicity component for Blake.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_impl").air.accumulation;
const prover_component = @import("stwo_prover_impl").air.component_prover;
const support = @import("component_support.zig");
const geometry = @import("geometry.zig");
const logup = @import("logup_constraints.zig");
const statement_mod = @import("statement.zig");

pub const Component = struct {
    table_index: usize,
    preprocessed_offset: usize,
    main_offset: usize,
    interaction_offset: usize,
    elements: statement_mod.RelationElements,
    claimed_sum: QM31,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn nConstraints(self: *const @This()) usize {
        return self.tableConfig().interactionSecureColumns();
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.tableConfig().logSize() + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const table = self.tableConfig();
        return support.traceBounds(
            allocator,
            3,
            table.multiplicityColumns(),
            4 * table.interactionSecureColumns(),
            table.logSize(),
        );
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: support.CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        const table = self.tableConfig();
        return support.maskPoints(
            allocator,
            point,
            max_log_degree_bound,
            3,
            table.multiplicityColumns(),
            table.interactionSecureColumns(),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        const indices = try allocator.alloc(usize, 3);
        for (indices, 0..) |*index, local| {
            index.* = self.preprocessed_offset + local;
        }
        return indices;
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: support.CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        const table = self.tableConfig();
        const multiplicity_count = table.multiplicityColumns();
        const secure_count = table.interactionSecureColumns();
        if (mask.items.len < 3 or
            mask.items[0].len < self.preprocessed_offset + 3 or
            mask.items[1].len < self.main_offset + multiplicity_count or
            mask.items[2].len <
                self.interaction_offset + 4 * secure_count)
        {
            return error.InvalidProofShape;
        }
        var preprocessed: [3]QM31 = undefined;
        for (&preprocessed, mask.items[0][self.preprocessed_offset..][0..3]) |*out, column| {
            if (column.len != 1) return error.InvalidProofShape;
            out.* = column[0];
        }
        var multiplicities: [256]QM31 = undefined;
        for (
            multiplicities[0..multiplicity_count],
            mask.items[1][self.main_offset..][0..multiplicity_count],
        ) |*out, column| {
            if (column.len != 1) return error.InvalidProofShape;
            out.* = column[0];
        }
        var current: [128]QM31 = undefined;
        const previous = try support.pointSecureColumns(
            mask.items[2],
            self.interaction_offset,
            secure_count,
            current[0..secure_count],
        );
        var constraints: [128]QM31 = undefined;
        try self.evaluateRow(
            preprocessed,
            multiplicities[0..multiplicity_count],
            current[0..secure_count],
            previous,
            constraints[0..secure_count],
        );
        const denominator_inverse = try support.pointDenominatorInverse(
            point,
            table.logSize(),
            max_log_degree_bound,
        );
        for (constraints[0..secure_count]) |constraint| {
            accumulator.accumulate(constraint.mul(denominator_inverse));
        }
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        const table = self.tableConfig();
        const log_size = table.logSize();
        const multiplicity_count = table.multiplicityColumns();
        const secure_count = table.interactionSecureColumns();
        const interaction_columns = 4 * secure_count;
        if (trace.polys.items.len < 3 or
            trace.polys.items[0].len < self.preprocessed_offset + 3 or
            trace.polys.items[1].len < self.main_offset + multiplicity_count or
            trace.polys.items[2].len <
                self.interaction_offset + interaction_columns)
        {
            return error.InvalidProofShape;
        }

        const allocator = accumulator.allocator;
        const eval_log_size = log_size + 1;
        const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
        const eval_size = eval_domain.size();
        const main_start: usize = 3;
        const interaction_start = main_start + multiplicity_count;
        const source_count = interaction_start + interaction_columns;
        const evaluations = try allocator.alloc([]const M31, source_count);
        defer allocator.free(evaluations);
        var extension_buffers = std.ArrayList([]M31).empty;
        defer {
            for (extension_buffers.items) |values| allocator.free(values);
            extension_buffers.deinit(allocator);
        }
        for (0..3) |index| {
            evaluations[index] = try support.evaluateOnDomain(
                allocator,
                trace.polys.items[0][self.preprocessed_offset + index],
                log_size,
                eval_log_size,
                eval_size,
                &extension_buffers,
            );
        }
        for (0..multiplicity_count) |index| {
            evaluations[main_start + index] = try support.evaluateOnDomain(
                allocator,
                trace.polys.items[1][self.main_offset + index],
                log_size,
                eval_log_size,
                eval_size,
                &extension_buffers,
            );
        }
        for (0..interaction_columns) |index| {
            evaluations[interaction_start + index] = try support.evaluateOnDomain(
                allocator,
                trace.polys.items[2][self.interaction_offset + index],
                log_size,
                eval_log_size,
                eval_size,
                &extension_buffers,
            );
        }
        try support.extendEvaluations(
            allocator,
            eval_domain,
            extension_buffers.items,
        );

        const denominator_inverses =
            try support.domainDenominatorInverses(log_size, eval_domain);
        var accumulator_columns = try accumulator.columns(allocator, &.{.{
            .log_size = eval_log_size,
            .n_cols = secure_count,
        }});
        defer allocator.free(accumulator_columns);
        const column = &accumulator_columns[0];

        for (0..eval_size) |row| {
            const previous_row = utils.previousBitReversedCircleDomainIndex(
                row,
                log_size,
                eval_log_size,
            );
            const preprocessed = [3]QM31{
                QM31.fromBase(evaluations[0][row]),
                QM31.fromBase(evaluations[1][row]),
                QM31.fromBase(evaluations[2][row]),
            };
            var multiplicities: [256]QM31 = undefined;
            for (
                multiplicities[0..multiplicity_count],
                evaluations[main_start..interaction_start],
            ) |*out, values| {
                out.* = QM31.fromBase(values[row]);
            }
            var current: [128]QM31 = undefined;
            for (current[0..secure_count], 0..) |*out, secure_index| {
                out.* = support.secureAt(
                    evaluations,
                    interaction_start,
                    secure_index,
                    row,
                );
            }
            const previous = support.secureAt(
                evaluations,
                interaction_start,
                secure_count - 1,
                previous_row,
            );
            var constraints: [128]QM31 = undefined;
            try self.evaluateRow(
                preprocessed,
                multiplicities[0..multiplicity_count],
                current[0..secure_count],
                previous,
                constraints[0..secure_count],
            );
            try accumulate(
                column,
                row,
                constraints[0..secure_count],
                denominator_inverses[row >> @intCast(log_size)],
            );
        }
    }

    fn evaluateRow(
        self: *const @This(),
        preprocessed: [3]QM31,
        multiplicities: []const QM31,
        current: []const QM31,
        previous: QM31,
        constraints: []QM31,
    ) !void {
        const table = self.tableConfig();
        if (multiplicities.len != table.multiplicityColumns())
            return error.InvalidProofShape;
        var entries: [256]logup.Entry = undefined;
        for (multiplicities, 0..) |multiplicity, column| {
            const high = tableHighOffsets(table, column);
            entries[column] = .{
                .multiplicity = multiplicity.neg(),
                .denominator = self.elements.combineSecure(&.{
                    preprocessed[0].add(QM31.fromBase(high[0])),
                    preprocessed[1].add(QM31.fromBase(high[1])),
                    preprocessed[2].add(QM31.fromBase(high[2])),
                }),
            };
        }
        try logup.evaluate(
            entries[0..multiplicities.len],
            current,
            previous,
            self.claimed_sum,
            table.logSize(),
            constraints,
        );
    }

    fn tableConfig(self: *const @This()) geometry.XorTable {
        return geometry.XOR_TABLES[self.table_index];
    }
};

fn tableHighOffsets(
    table: geometry.XorTable,
    column: usize,
) [3]M31 {
    const ah: u32 = @intCast(column >> @intCast(table.expand_bits));
    const bh: u32 = @intCast(
        column & ((@as(usize, 1) << @intCast(table.expand_bits)) - 1),
    );
    const limb_bits = table.limbBits();
    return .{
        M31.fromCanonical(ah << @intCast(limb_bits)),
        M31.fromCanonical(bh << @intCast(limb_bits)),
        M31.fromCanonical((ah ^ bh) << @intCast(limb_bits)),
    };
}

fn accumulate(
    column: *prover_air_accumulation.ColumnAccumulator,
    row: usize,
    constraints: []const QM31,
    denominator_inverse: M31,
) !void {
    if (column.random_coeff_powers.len != constraints.len)
        return error.InvalidProofShape;
    var combined = QM31.zero();
    for (constraints, 0..) |constraint, index| {
        combined = combined.add(
            column.random_coeff_powers[constraints.len - 1 - index]
                .mul(constraint),
        );
    }
    column.accumulate(row, combined.mulM31(denominator_inverse));
}

test "exact Blake XOR components expose all fixed table shapes" {
    var preprocessed_offset: usize = 0;
    var main_offset: usize = geometry.XOR_MAIN_OFFSET;
    var interaction_offset: usize = geometry.XOR_INTERACTION_OFFSET;
    for (geometry.XOR_TABLES, 0..) |table, table_index| {
        const component = Component{
            .table_index = table_index,
            .preprocessed_offset = preprocessed_offset,
            .main_offset = main_offset,
            .interaction_offset = interaction_offset,
            .elements = undefined,
            .claimed_sum = QM31.zero(),
        };
        try std.testing.expectEqual(
            table.interactionSecureColumns(),
            component.nConstraints(),
        );
        preprocessed_offset += 3;
        main_offset += table.multiplicityColumns();
        interaction_offset += 4 * table.interactionSecureColumns();
    }
    try std.testing.expectEqual(geometry.PREPROCESSED_COLUMNS, preprocessed_offset);
    try std.testing.expectEqual(geometry.MAIN_COLUMNS, main_offset);
    try std.testing.expectEqual(geometry.INTERACTION_COLUMNS, interaction_offset);
}
