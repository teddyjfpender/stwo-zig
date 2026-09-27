//! Exact original PAGE equations recorded over symbolic Scalar. Component order
//! follows the original nine-tree composite, including both kernel and semantic
//! claim closures. This helper is not a proof or an admission shortcut.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const R = @import("composition_graph_recorder.zig");
const S = R.Scalar;
const Semantic = @import("../../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Components = @import("../../prover/block_v5_memory_source_unified_page_components_v1.zig");
const Frame = @import("../../prover/block_v5_memory_source_page_capture_frame_v1.zig");
const Input = @import("../../prover/block_v5_memory_source_page_input_component_v1.zig");
const Canonical = @import("../../prover/block_v5_memory_source_page_canonical_component_v1.zig");
const Tables = @import("../../air/lookups/tables/mod.zig");
const ArithAirs = @import("arithmetic_fusion_fixed_columns_v1.zig").Airs;
pub const Field = struct {
    symbol: S,
    pub fn zero() Field {
        return .{ .symbol = S.zero() };
    }
    pub fn one() Field {
        return .{ .symbol = S.one() };
    }
    pub fn fromBase(value: M) Field {
        return .{ .symbol = S.fromBase(value) };
    }
    pub fn add(self: Field, other: Field) Field {
        return .{ .symbol = self.symbol.add(other.symbol) };
    }
    pub fn sub(self: Field, other: Field) Field {
        return .{ .symbol = self.symbol.sub(other.symbol) };
    }
    pub fn mul(self: Field, other: Field) Field {
        return .{ .symbol = self.symbol.mul(other.symbol) };
    }
    pub fn neg(self: Field) Field {
        return .{ .symbol = self.symbol.neg() };
    }
    pub fn fromPartialEvals(values: [4]Field) Field {
        var parts: [4]S = undefined;
        for (&parts, values) |*part, value| part.* = value.symbol;
        return .{ .symbol = R.fromPartialEvals(parts) };
    }
};
pub const Samples = struct {
    offsets: [10][]usize,
    layouts: [10][]@import("../sample_point_layout.zig").Layout,
    values: []const S,
    pub fn at(self: Samples, tree: usize, column: usize, row: i8) !S {
        if (tree >= self.offsets.len or column >= self.offsets[tree].len or self.layouts[tree].len != self.offsets[tree].len) return error.InvalidSourcePageRecursiveSamples;
        for (self.layouts[tree][column].offsets(), 0..) |offset, i| if (offset == row) {
            const position = try std.math.add(usize, self.offsets[tree][column], i);
            if (position >= self.values.len) return error.InvalidSourcePageRecursiveSamples;
            return self.values[position];
        };
        return error.InvalidSourcePageRecursiveSamples;
    }
    pub fn secure(self: Samples, column: usize, row: i8) !S {
        var parts: [4]S = undefined;
        for (&parts, 0..) |*part, i| part.* = try self.at(8, column + i, row);
        return R.fromPartialEvals(parts);
    }
};
fn fields(comptime n: usize, samples: Samples, tree: usize, start: usize, row: i8) ![n]Field {
    var result: [n]Field = undefined;
    for (&result, 0..) |*value, i| value.* = .{ .symbol = try samples.at(tree, start + i, row) };
    return result;
}
fn normalized(comptime n: usize, claims: [n]S, log: u32) ![n]Field {
    if (log == 0 or log > 24) return error.InvalidSourcePageRecursiveGeometry;
    const inverse = S.fromBase(try M.fromU64(@as(u64, 1) << @intCast(log)).inv());
    var result: [n]Field = undefined;
    for (&result, claims) |*out, value| out.* = .{ .symbol = value.mul(inverse) };
    return result;
}
fn accumulate(values: anytype, randomness: S, denominator: S, output: *S) usize {
    for (values) |value| R.accumulate(output, randomness, value.symbol, denominator);
    return values.len;
}
pub fn ClaimSymbols(comptime kind: Semantic.Kind) type {
    const C = Components.ForKind(kind);
    return struct {
        core: [C.CoreAirs.len + 2]S,
        capture: [@typeInfo(@TypeOf(@as(C.CaptureClaim, undefined).sums)).array.len]S,
        source_inputs: [C.SourceInput.PAIRS]S,
        capture_inputs: [C.CaptureInput.PAIRS]S,
        arithmetic: [4]S,
    };
}
fn recordFramework(comptime Airs: anytype, owner: anytype, samples: Samples, fixed_tree: usize, fixed_first: usize, main_tree: usize, main_first: usize, interaction_first: usize, logs: [Airs.len]u32, claims: [Airs.len]S, challenges: *const R.ChallengeSet, randomness: S, point: core.circle.CirclePoint(S), mask_log: u32, cache: *R.DenominatorCache, output: *S) !usize {
    var fixed_offset = fixed_first;
    var main_offset = main_first;
    var interaction_offset = interaction_first;
    var count: usize = 0;
    inline for (Airs, 0..) |Air, i| {
        const Runtime = @import("universal_relation_binding.zig").Binding(Air).Runtime;
        var row: [Runtime.LOGICAL_INPUT_COUNT]S = undefined;
        for (row[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], 0..) |*value, column| value.* = try samples.at(main_tree, main_offset + column, 0);
        for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT..][0..Air.PREPROCESSED_COLUMN_COUNT], 0..) |*value, column| value.* = try samples.at(fixed_tree, fixed_offset + column, 0);
        for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT ..], owner.components[i].parameters) |*value, parameter| value.* = S.fromBase(parameter);
        var current: [Runtime.BATCH_COUNT]S = undefined;
        for (&current, 0..) |*value, batch| value.* = try samples.secure(interaction_offset + 4 * batch, 0);
        const previous = try samples.secure(interaction_offset + 4 * (Runtime.BATCH_COUNT - 1), -1);
        const denominator = try R.quotientDenominator(logs[i], mask_log, point, cache);
        const shift = claims[i].mul(S.fromBase(try M.fromU64(@as(u64, 1) << @intCast(logs[i])).inv()));
        count += try R.recordComponent(Runtime, &owner.components[i], row, current, previous, shift, challenges, randomness, denominator, output);
        fixed_offset += Air.PREPROCESSED_COLUMN_COUNT;
        main_offset += Air.PHYSICAL_MAIN_COLUMN_COUNT;
        interaction_offset += Air.INTERACTION_COLUMN_COUNT;
    }
    return count;
}
fn width(comptime Airs: anytype, comptime field: []const u8) usize {
    var result: usize = 0;
    inline for (Airs) |Air| result += @field(Air, field);
    return result;
}
fn boundary(plan: *const @import("verifier_arithmetic_lowering.zig").Plan, challenges: *const R.ChallengeSet) !S {
    var result = S.zero();
    const challenge = challenges.get(.recursion_wire);
    for (plan.public_terms) |term| {
        if (term.active_in != .segment) continue;
        // Reuse original tuple/sign/multiplicity admission; only field
        // arithmetic changes to the actual recorder Scalar.
        const original = try @import("verifier_wire_claims.zig").publicTermParts(term);
        var tuple: [6]S = undefined;
        for (&tuple, original.tuple) |*value, native| value.* = S.fromSecure(native);
        result = result.add(S.fromSecure(original.numerator).mul((try challenge.combine(&tuple)).inverse()));
    }
    return result;
}
/// The caller creates all sample/claim/challenge inputs before activating its
/// builder. Both local closures become actual graph equations, independently
/// of the PAGE-global exported semantic claims.
pub fn record(comptime kind: Semantic.Kind, builder: *R.Builder, owner: *const Components.ForKind(kind).Owner, plan: *const @import("verifier_arithmetic_lowering.zig").Plan, frame: *const Frame.ForKind(kind), samples: Samples, claims: ClaimSymbols(kind), challenges: *const R.ChallengeSet, randomness: S, seed: S) !S {
    return recordForCompiler(kind, builder, owner, plan, frame, samples, claims, challenges, randomness, seed);
}
/// Static compiler/geometry views carry no claims/challenges/verifier authority.
/// The original live entry above delegates this same exact equation body.
pub fn recordForCompiler(comptime kind: Semantic.Kind, builder: *R.Builder, owner: anytype, plan: *const @import("verifier_arithmetic_lowering.zig").Plan, frame: anytype, samples: Samples, claims: ClaimSymbols(kind), challenges: *const R.ChallengeSet, randomness: S, seed: S) !S {
    @setEvalBranchQuota(1000000);
    const C = Components.ForKind(kind);
    const mask_log = core.verifier_types.compositionMaskLogSize(frame.constraint_log, frame.split) orelse return error.InvalidSourcePageRecursiveGeometry;
    const point = R.pointFromSeed(seed);
    var cache: R.DenominatorCache = @splat(null);
    var output = S.zero();
    var count = try recordFramework(C.CoreAirs, owner.cores, samples, 2, 0, 3, 0, 0, frame.geometry.core_logs, claims.core[0..C.CoreAirs.len].*, challenges, randomness, point, mask_log, &cache, &output);
    const native_relations = @import("blake3_execution_composition_native.zig").relations(challenges);
    var fixed_offset = width(C.CoreAirs, "PREPROCESSED_COLUMN_COUNT");
    var main_offset = width(C.CoreAirs, "PHYSICAL_MAIN_COLUMN_COUNT");
    var interaction_offset = width(C.CoreAirs, "INTERACTION_COLUMN_COUNT");
    const kinds = [_]Tables.schema.Kind{ .bitwise, .range_check_8_8 };
    for (kinds, 0..) |table_kind, i| {
        var tuple: [Tables.schema.MAX_ARITY]S = undefined;
        const arity = Tables.schema.arity(table_kind);
        for (tuple[0..arity], 0..) |*value, column| value.* = try samples.at(2, fixed_offset + 1 + column, 0);
        const equation = try @import("../../air/lookups/tables/equations.zig").evaluateGeneric(S, table_kind, tuple[0..arity], try samples.at(3, main_offset, 0), try samples.secure(interaction_offset, 0), try samples.secure(interaction_offset, -1), try samples.at(2, fixed_offset, 0), claims.core[C.CoreAirs.len + i], &native_relations);
        R.accumulate(&output, randomness, equation, try R.quotientDenominator(Tables.schema.logSize(table_kind), mask_log, point, &cache));
        count += 1;
        fixed_offset += arity + 1;
        main_offset += 1;
        interaction_offset += 4;
    }
    if (interaction_offset != C.CORE_INTERACTION) return error.InvalidSourcePageRecursiveGeometry;
    const wire = challenges.get(.recursion_wire);
    var powers: [6]Field = undefined;
    for (&powers, wire.alpha_powers[0..6]) |*out, value| out.* = .{ .symbol = value };
    const current = try fields(C.CAPTURE_INTERACTION, samples, 8, C.CORE_INTERACTION, 0);
    const previous = try fields(C.CAPTURE_INTERACTION, samples, 8, C.CORE_INTERACTION, -1);
    const capture_denominator = try R.quotientDenominator(frame.geometry.capture_log, mask_log, point, &cache);
    const capture_claim = try normalized(claims.capture.len, claims.capture, frame.geometry.capture_log);
    if (kind == .raw) {
        const Air = @import("../../prover/block_v5_memory_source_sha_connector_air_v1.zig");
        var main: [Air.MAIN_COUNT]Field = undefined;
        main[0..Air.SOURCE_MAIN_COUNT].* = try fields(Air.SOURCE_MAIN_COUNT, samples, 1, 0, 0);
        main[Air.SOURCE_MAIN_COUNT..].* = try fields(Air.CAPTURE_MAIN_COUNT, samples, 5, 0, 0);
        count += accumulate(Air.Algebra(Field).constraints(try fields(Air.EXPANDED_FIXED_COUNT, samples, 4, 0, 0), main, current, previous, capture_claim, .{ .z = .{ .symbol = wire.z }, .powers = powers }), randomness, capture_denominator, &output);
    } else {
        const Air = @import("../../prover/block_v5_memory_source_blake_capture_air_v1.zig");
        count += accumulate(Air.Algebra(Field).constraints(try fields(Air.FIXED_COUNT, samples, 4, 0, 0), try fields(Air.MAIN_COUNT, samples, 5, 0, 0), current, previous, capture_claim, .{ .z = .{ .symbol = wire.z }, .powers = powers }), randomness, capture_denominator, &output);
    }
    const Canon = Canonical.ForKind(kind);
    const source_denominator = try R.quotientDenominator(frame.geometry.source_log, mask_log, point, &cache);
    count += accumulate(Canon.Algebra(Field).constraints(try fields(5, samples, 6, 0, 0), try fields(Canon.MAIN_COUNT, samples, 1, 0, 0)), randomness, source_denominator, &output);
    const SourceInput = C.SourceInput;
    const CaptureInput = C.CaptureInput;
    const supplier = C.CORE_INTERACTION + C.CAPTURE_INTERACTION;
    count += accumulate(SourceInput.Algebra(Field).constraints(try fields(SourceInput.FIXED_COUNT, samples, 6, 5, 0), try fields(SourceInput.MAIN_COUNT, samples, 1, 0, 0), try fields(SourceInput.INTERACTION_COUNT, samples, 8, supplier, 0), try fields(SourceInput.INTERACTION_COUNT, samples, 8, supplier, -1), try normalized(SourceInput.PAIRS, claims.source_inputs, frame.geometry.source_log), .{ .z = .{ .symbol = wire.z }, .powers = powers }), randomness, source_denominator, &output);
    count += accumulate(CaptureInput.Algebra(Field).constraints(try fields(CaptureInput.FIXED_COUNT, samples, 6, 5 + SourceInput.FIXED_COUNT, 0), try fields(CaptureInput.MAIN_COUNT, samples, 5, 0, 0), try fields(CaptureInput.INTERACTION_COUNT, samples, 8, supplier + SourceInput.INTERACTION_COUNT, 0), try fields(CaptureInput.INTERACTION_COUNT, samples, 8, supplier + SourceInput.INTERACTION_COUNT, -1), try normalized(CaptureInput.PAIRS, claims.capture_inputs, frame.geometry.capture_log), .{ .z = .{ .symbol = wire.z }, .powers = powers }), randomness, capture_denominator, &output);
    count += try recordFramework(ArithAirs, owner.arithmetic, samples, 6, C.ARITHMETIC_FIXED_OFFSET, 7, 0, C.ARITHMETIC_INTERACTION_OFFSET, frame.geometry.arithmetic_logs, claims.arithmetic, challenges, randomness, point, mask_log, &cache, &output);
    if (count != frame.constraint_count) return error.InvalidSourcePageRecursiveConstraintCensus;
    var kernel_sum = S.zero();
    for (claims.core) |claim| kernel_sum = kernel_sum.add(claim);
    for (claims.capture) |claim| kernel_sum = kernel_sum.add(claim);
    try builder.constrainZero(kernel_sum);
    var semantic_sum = try boundary(plan, challenges);
    for (claims.arithmetic) |claim| semantic_sum = semantic_sum.add(claim);
    for (claims.source_inputs) |claim| semantic_sum = semantic_sum.add(claim);
    for (claims.capture_inputs) |claim| semantic_sum = semantic_sum.add(claim);
    try builder.constrainZero(semantic_sum);
    return output;
}
