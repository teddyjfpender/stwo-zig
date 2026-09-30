//! In-circuit composition accumulation: the evaluator-facing part of
//! `crates/stark_verifier/src/constraint_eval.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230): `InteractionAtOods`,
//! `CompositionConstraintAccumulator` and `finalize_logup_in_pairs`.
//! Upstream's `RelationUse` lives with the other static component facts in
//! `common/component_list.zig`.
//!
//! `ComponentDataTrait` is a comptime duck type. A component-data value `data`
//! of type `Data` provides:
//!
//! - `data.traceColumns() []const Var`
//! - `data.interactionColumns() []const InteractionAtOods(Var)`
//! - `data.nInstances() Var`
//! - `data.getNInstancesBit(ctx, bit: usize) !Var` (bit 0 is the LSB)
//! - `data.maxComponentSizeBits() usize`

const std = @import("std");
const logup = @import("logup.zig");
const stwo_core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const circle = @import("circle.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const SECURE_EXTENSION_DEGREE = stwo_core.fields.qm31.SECURE_EXTENSION_DEGREE;

/// `proof::InteractionAtOods<Var>`: an interaction limb at the OODS point and,
/// for the last four limbs only, at the previous row.
pub fn InteractionAtOods(comptime Var: type) type {
    return struct { at_oods: Var, at_prev: ?Var = null };
}

/// Borrowed name-keyed maps; lookups only, never iterated.
pub fn ColumnMap(comptime Var: type) type {
    return std.StringHashMapUnmanaged(Var);
}

pub fn CompositionConstraintAccumulator(comptime Ctx: type) type {
    return struct {
        const Self = @This();
        const Var = Ctx.Var;
        const Term = logup.LogupTerm(Var);

        /// OODS samples of the preprocessed columns, keyed by column id.
        preprocessed_columns: *const ColumnMap(Var),
        public_params: *const ColumnMap(Var),
        composition_polynomial_coeff: Var,
        /// `[z, alpha]` of the common lookup elements.
        interaction_elements: [2]Var,
        accumulation: Var,
        terms: std.ArrayList(Term) = .empty,
        allocator: std.mem.Allocator,

        pub fn init(
            allocator: std.mem.Allocator,
            ctx: *const Ctx,
            preprocessed_columns: *const ColumnMap(Var),
            public_params: *const ColumnMap(Var),
            composition_polynomial_coeff: Var,
            interaction_elements: [2]Var,
        ) Self {
            return .{
                .preprocessed_columns = preprocessed_columns,
                .public_params = public_params,
                .composition_polynomial_coeff = composition_polynomial_coeff,
                .interaction_elements = interaction_elements,
                .accumulation = ctx.zero(),
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.terms.deinit(self.allocator);
            self.* = undefined;
        }

        /// `accumulation <- accumulation * coeff + constraint`.
        pub fn addConstraint(self: *Self, ctx: *Ctx, constraint_eval_at_oods: Var) !void {
            const shifted = try ctx.mul(self.accumulation, self.composition_polynomial_coeff);
            self.accumulation = try ctx.add(shifted, constraint_eval_at_oods);
        }

        pub fn finalize(self: *const Self) Var {
            return self.accumulation;
        }

        pub fn getPreprocessedColumn(self: *const Self, id: []const u8) !Var {
            return self.preprocessed_columns.get(id) orelse error.MissingPreprocessedColumn;
        }

        pub fn getPublicParam(self: *const Self, name: []const u8) !Var {
            return self.public_params.get(name) orelse error.MissingPublicParam;
        }

        pub fn addToRelation(self: *Self, ctx: *Ctx, numerator: Var, element: []const Var) !void {
            const term = try logup.logupTerm(Ctx, ctx, self.interaction_elements, numerator, element);
            try self.terms.append(self.allocator, term);
        }

        /// Pairs the relation terms into batch constraints. Every batch but
        /// the last is a cumulative-sum column delta; the last one also
        /// subtracts the previous row and shifts by `claimed_sum / n_instances`.
        pub fn finalizeLogupInPairs(
            self: *Self,
            ctx: *Ctx,
            interaction_columns: []const InteractionAtOods(Var),
            data: anytype,
            claimed_sum: Var,
        ) !void {
            const terms = self.terms.items;
            const n_batches = std.math.divCeil(usize, terms.len, 2) catch unreachable;
            if (n_batches == 0 or interaction_columns.len != n_batches * SECURE_EXTENSION_DEGREE)
                return error.InteractionColumnCountMismatch;
            const body = interaction_columns[0 .. interaction_columns.len - SECURE_EXTENSION_DEGREE];
            const last = interaction_columns[body.len..];

            var prev_col_cumsum = ctx.zero();
            for (0..n_batches - 1) |i| {
                const chunk = body[i * SECURE_EXTENSION_DEGREE ..][0..SECURE_EXTENSION_DEGREE];
                var limbs: [SECURE_EXTENSION_DEGREE]Var = undefined;
                for (chunk, &limbs) |column, *limb| {
                    if (column.at_prev != null) return error.UnexpectedPreviousRowSample;
                    limb.* = column.at_oods;
                }
                const cur_cumsum = try fromPartialEvals(Ctx, ctx, limbs);
                const diff = if (i > 0) try ctx.sub(cur_cumsum, prev_col_cumsum) else cur_cumsum;
                prev_col_cumsum = cur_cumsum;
                const constraint = try logup.pairLogupConstraint(Ctx, ctx, terms[2 * i], terms[2 * i + 1], diff);
                try self.addConstraint(ctx, constraint);
            }

            var prev_limbs: [SECURE_EXTENSION_DEGREE]Var = undefined;
            var cur_limbs: [SECURE_EXTENSION_DEGREE]Var = undefined;
            for (last, &prev_limbs, &cur_limbs) |column, *prev, *cur| {
                prev.* = column.at_prev orelse return error.MissingPreviousRowSample;
                cur.* = column.at_oods;
            }
            const prev_row_cumsum = try fromPartialEvals(Ctx, ctx, prev_limbs);
            const cur_cumsum = try fromPartialEvals(Ctx, ctx, cur_limbs);
            const row_diff = try ctx.sub(cur_cumsum, prev_row_cumsum);
            const diff = try ctx.sub(row_diff, prev_col_cumsum);
            // n_instances = 2^log_size is never zero.
            const n_instances_inv = try ctx.inv(data.nInstances());
            const cumsum_shift = try ctx.mul(claimed_sum, n_instances_inv);
            const shifted_diff = try ctx.add(diff, cumsum_shift);

            const first = 2 * (n_batches - 1);
            const constraint = if (terms.len % 2 == 0)
                try logup.pairLogupConstraint(Ctx, ctx, terms[first], terms[first + 1], shifted_diff)
            else
                try logup.singleLogupConstraint(Ctx, ctx, terms[first], shifted_diff);
            try self.addConstraint(ctx, constraint);
            self.terms.clearRetainingCapacity();
        }
    };
}

/// `ops::from_partial_evals`: `v0 + v1·i + v2·u + v3·iu`. The three basis
/// constants are interned first, in the order i, u, iu.
pub fn fromPartialEvals(comptime Ctx: type, ctx: *Ctx, values: [SECURE_EXTENSION_DEGREE]Ctx.Var) !Ctx.Var {
    const i = try ctx.constant(QM31.fromU32Unchecked(0, 1, 0, 0));
    const u = try ctx.constant(QM31.fromU32Unchecked(0, 0, 1, 0));
    const iu = try ctx.constant(QM31.fromU32Unchecked(0, 0, 0, 1));
    var sum = try ctx.add(values[0], try ctx.mul(values[1], i));
    sum = try ctx.add(sum, try ctx.mul(values[2], u));
    return ctx.add(sum, try ctx.mul(values[3], iu));
}

/// `ComponentData`: one component's OODS samples, its row count and the
/// bits of every component's row count (lane `index` is this one's).
pub fn ComponentData(comptime V: type) type {
    return struct {
        const Self = @This();
        const Var = builder.Var;

        trace: []const Var,
        interaction: []const InteractionAtOods(Var),
        n_instances: Var,
        index: usize,
        n_instances_bits: []const builder.simd.Simd,

        pub fn traceColumns(self: *const Self) []const Var {
            return self.trace;
        }

        pub fn interactionColumns(self: *const Self) []const InteractionAtOods(Var) {
            return self.interaction;
        }

        pub fn nInstances(self: *const Self) Var {
            return self.n_instances;
        }

        /// `get_n_instances_bit`: bit `bit` (LSB first) of the row count.
        pub fn getNInstancesBit(self: *const Self, ctx: *builder.Context(V), bit: usize) !Var {
            if (bit >= self.n_instances_bits.len) return error.InstanceBitOutOfRange;
            return builder.simd.unpackIdx(V, ctx, self.n_instances_bits[bit], self.index);
        }

        pub fn maxComponentSizeBits(self: *const Self) usize {
            return self.n_instances_bits.len;
        }
    };
}

/// `EvaluateArgs`: the OODS samples and challenges of one composition
/// evaluation.
pub const EvaluateArgs = struct {
    preprocessed_columns: []const builder.Var,
    trace: []const builder.Var,
    interaction: []const InteractionAtOods(builder.Var),
    pt: circle.Point(builder.Var),
    log_domain_size: usize,
    composition_polynomial_coeff: builder.Var,
    interaction_elements: [2]builder.Var,
    claimed_sums: []const builder.Var,
    component_sizes: []const builder.Var,
    n_instances_bits: []const builder.simd.Simd,
};

/// `compute_composition_polynomial`: every component's constraints and
/// LogUp batches, in statement order, accumulated and divided by the trace
/// coset's vanishing polynomial at the OODS point.
///
/// `statement` provides `preprocessedColumnIds()`, `publicParams(ctx,
/// *ColumnMap)`, `nComponents()` and `evaluateComponent(index, ctx, data,
/// acc)`; `component_shapes` gives each component's column counts in the
/// same order.
pub fn computeCompositionPolynomial(
    comptime V: type,
    ctx: *builder.Context(V),
    component_shapes: anytype,
    statement: anytype,
    args: EvaluateArgs,
) !builder.Var {
    const Ctx = builder.Context(V);
    const Var = builder.Var;
    const allocator = ctx.scratch();
    const ids = statement.preprocessedColumnIds();
    if (ids.len != args.preprocessed_columns.len) return error.PreprocessedColumnCountMismatch;
    var preprocessed: ColumnMap(Var) = .empty;
    for (ids, args.preprocessed_columns) |id, value| try preprocessed.put(allocator, id, value);
    var public_params: ColumnMap(Var) = .empty;
    try statement.publicParams(ctx, &public_params);

    var acc = CompositionConstraintAccumulator(Ctx).init(
        allocator,
        ctx,
        &preprocessed,
        &public_params,
        args.composition_polynomial_coeff,
        args.interaction_elements,
    );
    const n_components = statement.nComponents();
    if (component_shapes.len != n_components or args.claimed_sums.len != n_components or args.component_sizes.len != n_components)
        return error.ComponentCountMismatch;
    var trace = args.trace;
    var interaction = args.interaction;
    for (component_shapes, args.claimed_sums, args.component_sizes, 0..) |shape, claimed_sum, component_size, index| {
        if (trace.len < shape.trace_columns or interaction.len < shape.interaction_columns) return error.MissingOodsSamples;
        const data: ComponentData(V) = .{
            .trace = trace[0..shape.trace_columns],
            .interaction = interaction[0..shape.interaction_columns],
            .n_instances = component_size,
            .index = index,
            .n_instances_bits = args.n_instances_bits,
        };
        trace = trace[shape.trace_columns..];
        interaction = interaction[shape.interaction_columns..];
        try statement.evaluateComponent(index, ctx, &data, &acc);
        try acc.finalizeLogupInPairs(ctx, data.interaction, &data, claimed_sum);
    }
    if (trace.len != 0 or interaction.len != 0) return error.UnconsumedOodsSamples;

    const final_evaluation = acc.finalize();
    const denom_inverse = try circle.denomInverse(V, ctx, args.pt.x, args.log_domain_size);
    return ctx.mul(final_evaluation, denom_inverse);
}
