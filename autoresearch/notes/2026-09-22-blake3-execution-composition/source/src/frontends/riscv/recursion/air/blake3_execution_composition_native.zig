//! Native adapters replayed through the shared symbolic scalar and equations.
const std = @import("std");
const core = @import("stwo_core");
const r = @import("composition_graph_recorder.zig");
const S = r.Scalar;
const statement = @import("../../air/statement.zig");
const entries = @import("../../air/lookups/opcode_entries.zig");
const trace = @import("../../runner/trace.zig");
const logup = @import("../../air/logup.zig");
const tables = @import("../../air/lookups/tables/schema.zig");
const base = @import("../../air/relation_challenges.zig");
const Relation = struct {
    source: *const r.ChallengeSet.Element,
    pub fn combine(self: @This(), values: anytype) S {
        return self.source.combine(&values) catch unreachable;
    }
    pub fn combineBase(self: @This(), values: anytype) S {
        var secure: [values.len]S = undefined;
        inline for (values, &secure) |value, *target| target.* = S.fromBase(value);
        return self.combine(secure);
    }
    pub fn alphaValue(self: @This()) S {
        return self.source.alpha_powers[1];
    }
};
const Relations = blk: {
    const native_fields = @typeInfo(base.Relations).@"struct".fields;
    var fields: [native_fields.len]std.builtin.Type.StructField = undefined;
    for (&fields, native_fields) |*field, original| field.* = .{ .name = original.name, .type = Relation, .default_value_ptr = null, .is_comptime = false, .alignment = @alignOf(Relation) };
    break :blk @Type(.{ .@"struct" = .{ .layout = .auto, .fields = &fields, .decls = &.{}, .is_tuple = false } });
};
pub fn relations(challenges: *const r.ChallengeSet) Relations {
    var result: Relations = undefined;
    inline for (@typeInfo(Relations).@"struct".fields) |field| @field(result, field.name) = .{ .source = challenges.get(@field(@import("../../air/lang/relation.zig").Domain, field.name)) };
    return result;
}
pub fn record(shape: *const statement.Blake3ExecutionStatement, samples: anytype, claims: []const S, challenges: *const r.ChallengeSet, randomness: S, point: core.circle.CirclePoint(S), max_log: u32, cache: *r.DenominatorCache, accumulated: *S) !usize {
    const native = relations(challenges);
    var pp: usize = 0;
    var main: usize = 0;
    var interaction: usize = 0;
    var claim: usize = 0;
    var constraints: usize = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| {
        const denominator = try r.quotientDenominator(desc.log_size, max_log, point, cache);
        var row: [trace.MAX_FAMILY_COLUMNS]S = undefined;
        for (row[0..desc.n_columns], 0..) |*value, column| value.* = try samples.at(1, main + column, 0);
        const semantic = try @import("../../air/semantic_eval.zig").Eval(S).evaluate(desc.family, row[0..@import("../../air/semantic_eval.zig").mainColumnCount(desc.family)], try samples.at(0, pp + 1, 0));
        for (semantic.values[0..semantic.len]) |value| r.accumulate(accumulated, randomness, value, denominator);
        constraints += semantic.len;
        const lookups = try entries.Entries(S).fromMain(desc.family, row[0..desc.n_columns]);
        for (0..lookups.batchCount()) |batch| {
            const value = logup.pairConstraintGeneric(S, try samples.secure(interaction + 4 * batch, 0), try samples.secure(interaction + 4 * batch, 1), try samples.at(0, pp, 0), claims[claim], try lookups.pairWith(batch, &native));
            r.accumulate(accumulated, randomness, value, denominator);
            constraints += 1;
            claim += 1;
        }
        pp += 2;
        main += desc.n_columns;
        interaction += @import("../../air/lookups/opcode_interaction.zig").nColumns(desc.family);
    }
    for (shape.infra_descs[0..shape.n_infra]) |desc| {
        const denominator = try r.quotientDenominator(desc.log_size, max_log, point, cache);
        const first = try samples.at(0, pp, 0);
        if (desc.kind == .clock_update) {
            const clock = @import("../../air/clock_update_interaction.zig");
            var row: [@import("../../infra_trace.zig").CLOCK_UPDATE_COLS]S = undefined;
            for (&row, 0..) |*value, column| value.* = try samples.at(1, main + column, 0);
            var current: [clock.N_SUMS]S = undefined;
            var previous: [clock.N_SUMS]S = undefined;
            for (&current, &previous, 0..) |*now, *prev, batch| {
                now.* = try samples.secure(interaction + 4 * batch, 0);
                prev.* = try samples.secure(interaction + 4 * batch, 1);
            }
            const values = try @import("../../air/clock_update_component.zig").evaluateGeneric(S, &row, current, previous, first, try samples.at(0, pp + 1, 0), claims[claim..][0..clock.N_SUMS].*, &native);
            for (values) |value| r.accumulate(accumulated, randomness, value, denominator);
            constraints += values.len;
            claim += clock.N_SUMS;
        } else {
            const kind = statement.tableKind(desc.kind) orelse return error.LegacyCommitmentInBlake3Execution;
            var tuple: [tables.MAX_ARITY]S = undefined;
            for (tuple[0..tables.arity(kind)], 0..) |*value, i| value.* = try samples.at(0, pp + 1 + i, 0);
            const value = try @import("../../air/lookups/tables/interaction.zig").evaluateGeneric(S, kind, tuple[0..tables.arity(kind)], try samples.at(1, main, 0), try samples.secure(interaction, 0), try samples.secure(interaction, 1), first, claims[claim], &native);
            r.accumulate(accumulated, randomness, value, denominator);
            constraints += 1;
            claim += 1;
        }
        pp += statement.nPreprocessedColumnsForInfra(desc.kind);
        main += desc.n_columns;
        interaction += statement.nInteractionColsForInfra(desc.kind);
    }
    if (claim != claims.len or pp != shape.nPreprocessedColumns() or main != shape.nMainColumns() or interaction != shape.nInteractionColumns()) return error.InvalidExecutionComposition;
    return constraints;
}
