//! Original memory-first B5CF quotient, including all 68 access equations,
//! caller program/state and all six tables/register-memory projections.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const R = @import("composition_graph_recorder.zig");
const S = R.Scalar;
const Field = @import("block_v5_native_capacity_fused_composition_v1.zig").Field;
const Universal = @import("universal_challenges.zig");
const Admission = @import("../../prover/block_v5_caller_fused_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_caller_fused_recursive_capture_v1.zig");
const Algebra = @import("../../prover/block_v5_caller_fused_algebra_v1.zig");
const Shared = @import("blake3_execution_composition.zig");
pub const Prepared = Shared.Prepared;
pub const RELATION_COUNT: usize = Universal.RELATION_COUNT + 5;
pub const ACCESS_INPUTS: usize = 10;
pub fn publicCount(program: usize, tables: usize, memory: usize) !usize {
    return std.math.add(usize, try std.math.add(usize, 8, try std.math.add(usize, try std.math.mul(usize, 2, program), tables)), try std.math.mul(usize, ACCESS_INPUTS, memory));
}
pub fn publicInputs(a: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Admission.Fused.ClaimFrames) ![]Q {
    return publicInputsFor(Admission, a, admitted, claims);
}
/// Static family selection only. Readonly callers use these identical original
/// projection/access cells and append their own actual classifier claim cells.
pub fn publicInputsFor(comptime Admitted: type, a: std.mem.Allocator, admitted: *const Admitted.Prepared, claims: @import("../../prover/block_v5_caller_fused_proof_v1.zig").ClaimFrames) ![]Q {
    var channel = core.proof_suites.Blake3.Channel{};
    try @import("../../prover/block_v5_caller_fused_proof_v1.zig").mixClaims(&channel, admitted.binding, &admitted.schedule, claims.program_claims, claims.state_claims, claims.table_claims, claims.memory_claims);
    const inputs = try a.alloc(Q, try publicCount(admitted.schedule.program.len, admitted.schedule.tables.len, admitted.schedule.memory.len));
    errdefer a.free(inputs);
    @memcpy(inputs[0..8], &@import("../../prover/block_execution_integer_algebra_v1.zig").clockBytes(Q, try @import("../../prover/block_execution_integer_bridge_v2.zig").baseClockFromPublicFrame(admitted.frame)));
    var at: usize = 8;
    inline for (.{ claims.program_claims, claims.state_claims, claims.table_claims }) |partition| for (partition) |claim| {
        inputs[at] = claim.sum;
        at += 1;
    };
    for (claims.memory_claims) |claim| {
        inputs[at] = claim.transition_sum;
        inputs[at + 1] = claim.universal_sum;
        // Canonical mixClaims already bounds each count by its row capacity.
        inputs[at + 2] = Q.fromBase(M.fromU64(claim.active_count));
        @memcpy(inputs[at + 3 ..][0..7], &claim.range_claims);
        at += ACCESS_INPUTS;
    }
    if (at != inputs.len) return error.InvalidCallerFusedRecursiveClaims;
    return inputs;
}
pub const Samples = struct {
    offsets: [5][]usize,
    lengths: [5][]usize,
    values: []const S,
    pub fn at(self: Samples, tree: usize, column: usize, ordinal: usize) !S {
        if (tree >= 5 or column >= self.offsets[tree].len or ordinal >= self.lengths[tree][column]) return error.InvalidCallerFusedRecursiveSamples;
        return self.values[self.offsets[tree][column] + ordinal];
    }
};
const FieldSamples = struct {
    original: Samples,
    pub fn at(self: @This(), tree: usize, column: usize, ordinal: usize) !Field {
        return .{ .symbol = try self.original.at(tree, column, ordinal) };
    }
};
pub const Relations = struct {
    native: *const R.ChallengeSet,
    pub const Element = struct {
        element: *const R.ChallengeSet.Element,
        pub fn combineSecure(self: @This(), values: []const Field) !Field {
            if (values.len > Universal.MAX_ARITY) return error.InvalidRelationPlan;
            var symbols: [Universal.MAX_ARITY]S = undefined;
            for (values, symbols[0..values.len]) |value, *out| out.* = value.symbol;
            return .{ .symbol = try self.element.combine(symbols[0..values.len]) };
        }
        pub fn combine(self: @This(), values: anytype) Field {
            return self.combineSecure(&values) catch unreachable;
        }
        pub fn alphaValue(self: @This()) Field {
            return .{ .symbol = self.element.alpha_powers[1] };
        }
    };
    pub fn get(self: *const Relations, domain: @import("../../air/lang/relation.zig").Domain) Element {
        return .{ .element = self.native.get(domain) };
    }
    const Base = blk: {
        const original = @typeInfo(@import("../../air/relation_challenges.zig").Relations).@"struct".fields;
        var fields: [original.len]std.builtin.Type.StructField = undefined;
        for (&fields, original) |*field, old| field.* = .{ .name = old.name, .type = Element, .default_value_ptr = null, .is_comptime = false, .alignment = @alignOf(Element) };
        break :blk @Type(.{ .@"struct" = .{ .layout = .auto, .fields = &fields, .decls = &.{}, .is_tuple = false } });
    };
    pub fn base(self: *const Relations) Base {
        var out: Base = undefined;
        inline for (@typeInfo(Base).@"struct".fields) |field| @field(out, field.name) = self.get(@field(@import("../../air/lang/relation.zig").Domain, field.name));
        return out;
    }
};
/// The original coreEvents API constructs private arithmetic fractions as well
/// as public-table events. Those private fractions are excluded by the exact
/// admitted projection roster and belong to the separate arithmetic child.
/// Their placeholder never flows into a selected fraction or verifier output.
const ExcludedPrivate = struct {
    pub fn combine(_: @This(), _: anytype) Field {
        return Field.one();
    }
};
pub fn recordConstraints(admitted: *const Admission.Prepared, samples: Samples, public: []const S, draws: [Universal.RELATION_COUNT][2]S, word: [10]S, random: S, point: core.circle.CirclePoint(S), mask_log: u32, accumulated: *S) !usize {
    return recordConstraintsFor(Admission, admitted, samples, public, draws, word, random, point, mask_log, accumulated);
}
pub fn recordConstraintsFor(comptime Admitted: type, admitted: *const Admitted.Prepared, samples: Samples, public: []const S, draws: [Universal.RELATION_COUNT][2]S, word: [10]S, random: S, point: core.circle.CirclePoint(S), mask_log: u32, accumulated: *S) !usize {
    const schedule = &admitted.schedule;
    if (public.len != try publicCount(schedule.program.len, schedule.tables.len, schedule.memory.len)) return error.InvalidCallerFusedRecursiveClaims;
    const challenges = try R.ChallengeSet.init(draws);
    const relations = Relations{ .native = &challenges };
    const profile = .{ .sha = relations, .ethereum = .{ .keccak = .{ .base = relations.base(), .io = ExcludedPrivate{} }, .secp = .{ .base = relations.base(), .recovery = ExcludedPrivate{} } } };
    const Transition = struct {
        z: Field,
        powers: [11]Field,
        pub fn combineSecure(self: @This(), values: [11]Field) Field {
            return @import("../../air/relation_challenges.zig").combineGeneric(Field, self.z, self.powers, values);
        }
    };
    var transition = Transition{ .z = .{ .symbol = word[0] }, .powers = undefined };
    var power = Field.one();
    for (&transition.powers) |*out| {
        out.* = power;
        power = power.mul(.{ .symbol = word[1] });
    }
    const field_samples = FieldSamples{ .original = samples };
    var cache: R.DenominatorCache = @splat(null);
    var count: usize = 0;
    const access_begin = 8 + 2 * schedule.program.len + schedule.tables.len;
    // The original composite component owner puts all accesses first.
    for (schedule.memory, 0..) |slot, i| {
        const pair = try Algebra.externalPair(Field, slot, field_samples);
        var witness: [48]Field = undefined;
        for (&witness, 0..) |*out, column| out.* = try field_samples.at(2, i * 48 + column, 0);
        var current: [49]Field = undefined;
        var previous: [49]Field = undefined;
        const offset = schedule.projectionCount() * 4 + i * 49;
        for (&current, &previous, 0..) |*out, *prior, column| {
            out.* = try field_samples.at(3, offset + column, 0);
            prior.* = try field_samples.at(3, offset + column, 1);
        }
        var clock: [8]Field = undefined;
        for (&clock, public[0..8]) |*out, value| out.* = .{ .symbol = value };
        const start = access_begin + ACCESS_INPUTS * i;
        const normalize = S.fromBase(try M.fromCanonical(@as(u32, 1) << @intCast(slot.log_size)).inv());
        var ranges: [7]Field = undefined;
        for (&ranges, public[start + 3 ..][0..7]) |*out, value| out.* = .{ .symbol = value.mul(normalize) };
        const equations = try @import("../../prover/block_v5_native_fused_algebra_v1.zig").Algebra(Field).access(pair, witness, current, previous, clock, transition, &relations, .{ .symbol = public[start].mul(normalize) }, .{ .symbol = public[start + 2].mul(normalize) }, ranges, .{ .symbol = public[start + 1].mul(normalize) });
        const denominator = try R.quotientDenominator(slot.log_size, mask_log, point, &cache);
        for (equations) |equation| R.accumulate(accumulated, random, equation.symbol, denominator);
        count += equations.len;
    }
    for (0..2) |partition| for (schedule.program, 0..) |slot, i| {
        var fixed: [1]Field = undefined;
        if (slot.fixed_selector_offset) |offset| fixed[0] = try field_samples.at(0, offset, 0);
        var main: [@import("../../prover/block_v5_precompile_lookup_source_v1.zig").MAX_MAIN]Field = undefined;
        for (main[0..slot.main_columns], 0..) |*out, column| out.* = try field_samples.at(1, slot.main_offset + column, 0);
        var current: [4]Field = undefined;
        var previous: [4]Field = undefined;
        const index = partition * schedule.program.len + i;
        for (&current, &previous, 0..) |*out, *prior, column| {
            out.* = try field_samples.at(3, index * 4 + column, 0);
            prior.* = try field_samples.at(3, index * 4 + column, 1);
        }
        const shift = S.fromBase(try M.fromCanonical(@as(u32, 1) << @intCast(slot.log_size)).inv());
        const equation = try Algebra.programResidual(Field, partition == 1, slot, fixed[0..@intFromBool(slot.fixed_selector_offset != null)], main[0..slot.main_columns], current, previous, .{ .symbol = public[8 + index].mul(shift) }, &relations);
        R.accumulate(accumulated, random, equation.symbol, try R.quotientDenominator(slot.log_size, mask_log, point, &cache));
        count += 1;
    };
    const Source = @import("../../prover/block_v5_precompile_lookup_source_v1.zig");
    for (schedule.tables, 0..) |slot, i| {
        var fixed: [Source.MAX_FIXED]Field = undefined;
        var main: [Source.MAX_MAIN]Field = undefined;
        for (fixed[0..slot.fixed_width], 0..) |*out, column| out.* = try field_samples.at(0, slot.fixed_offset + column, 0);
        for (main[0..slot.width], 0..) |*out, column| out.* = try field_samples.at(1, slot.main_offset + column, 0);
        var current: [4]Field = undefined;
        var previous: [4]Field = undefined;
        const index = 2 * schedule.program.len + i;
        for (&current, &previous, 0..) |*out, *prior, column| {
            out.* = try field_samples.at(3, index * 4 + column, 0);
            prior.* = try field_samples.at(3, index * 4 + column, 1);
        }
        const shift = S.fromBase(try M.fromCanonical(@as(u32, 1) << @intCast(slot.log_size)).inv());
        const equation = try Algebra.tableResidual(Field, schedule.owner, slot, fixed[0..slot.fixed_width], main[0..slot.width], current, previous, .{ .symbol = public[8 + index].mul(shift) }, &profile);
        R.accumulate(accumulated, random, equation.symbol, try R.quotientDenominator(slot.log_size, mask_log, point, &cache));
        count += 1;
    }
    return count;
}
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !Prepared {
    try capture.validate(admitted, expected);
    var owner = try @import("block_v5_caller_fused_components_v1.zig").Owner.init(a, admitted, capture, expected);
    defer owner.deinit();
    const all = owner.all(admitted.logs[0].len);
    const composition_log = all.compositionLogDegreeBound();
    const split = try all.compositionLogSplit();
    const mask_log = core.verifier_types.compositionMaskLogSize(composition_log, split) orelse return error.InvalidCallerFusedRecursiveGeometry;
    const point = core.circle.secureFieldPointFromRandomSeed(capture.proof.oods_seed);
    var masks = try all.maskPoints(a, point, mask_log, false);
    defer masks.deinitDeep(a);
    if (masks.items.len != 4 or capture.proof.sampled_points.len != 5) return error.InvalidCallerFusedRecursiveSamples;
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var sources: std.ArrayList(Shared.Source) = .empty;
    var samples = Samples{ .offsets = undefined, .lengths = undefined, .values = undefined };
    var cursor: usize = 0;
    for (capture.proof.sampled_points, 0..) |columns, tree| {
        const wanted = if (tree < 4) admitted.logs[tree].len else core.verifier_types.compositionColumnCount(split, 4) orelse return error.InvalidCallerFusedRecursiveGeometry;
        if (columns.len != wanted) return error.InvalidCallerFusedRecursiveSamples;
        samples.offsets[tree] = try temp.alloc(usize, columns.len);
        samples.lengths[tree] = try temp.alloc(usize, columns.len);
        for (columns, 0..) |points, column| {
            if (tree < 4) {
                if (points.len != masks.items[tree][column].len) return error.InvalidCallerFusedRecursiveSamples;
                for (points, masks.items[tree][column]) |actual, wanted_point| if (!actual.eql(wanted_point)) return error.InvalidCallerFusedRecursiveSamples;
            } else if (points.len != 1 or !points[0].eql(point)) return error.InvalidCallerFusedRecursiveSamples;
            samples.offsets[tree][column] = cursor;
            samples.lengths[tree][column] = points.len;
            cursor = try std.math.add(usize, cursor, points.len);
        }
    }
    if (cursor != capture.proof.sampled_values.len or cursor > admitted.limits.max_samples) return error.CallerFusedRecursiveResourceLimit;
    const sampled = try temp.alloc(S, cursor);
    for (sampled, capture.proof.sampled_values, 0..) |*out, value, i| out.* = try input(&builder, temp, &inputs, &sources, .{ .sample = @intCast(i) }, value);
    samples.values = sampled;
    var draws: [Universal.RELATION_COUNT][2]S = undefined;
    for (&draws, capture.relations.elements, 0..) |*out, element, i| {
        out[0] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i) }, element.z);
        out[1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i + 1) }, element.alpha);
    }
    var word: [10]S = undefined;
    inline for (.{ "transition", "link", "initial", "endpoint", "range16" }, 0..) |name, i| {
        const element = @field(capture.word_challenges, name);
        word[2 * i] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * Universal.RELATION_COUNT + 2 * i) }, element.z);
        word[2 * i + 1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * Universal.RELATION_COUNT + 2 * i + 1) }, element.alpha);
    }
    const values = try publicInputs(temp, admitted, capture.original.claims);
    const public = try temp.alloc(S, values.len);
    for (public, values, 0..) |*out, value, i| out.* = try input(&builder, temp, &inputs, &sources, .{ .public_input = @intCast(i) }, value);
    const random = try input(&builder, temp, &inputs, &sources, .composition, capture.proof.composition_randomness);
    const seed = try input(&builder, temp, &inputs, &sources, .oods, capture.proof.oods_seed);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const symbolic_point = R.pointFromSeed(seed);
    var accumulated = S.zero();
    const count = try recordConstraints(admitted, samples, public, draws, word, random, symbolic_point, mask_log, &accumulated);
    var actual_count: usize = 0;
    for (owner.handles) |component| actual_count += component.nConstraints();
    if (count != actual_count) return error.InvalidCallerFusedRecursiveEquationCount;
    const chunks = try temp.alloc(S, core.verifier_types.compositionChunkCount(split) orelse return error.InvalidCallerFusedRecursiveGeometry);
    for (chunks, 0..) |*out, chunk| out.* = R.fromPartialEvals(.{ try samples.at(4, 4 * chunk, 0), try samples.at(4, 4 * chunk + 1, 0), try samples.at(4, 4 * chunk + 2, 0), try samples.at(4, 4 * chunk + 3, 0) });
    try builder.constrainZero((try R.reconstructSplitComposition(chunks, symbolic_point, composition_log, split)).sub(accumulated));
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const outputs = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, outputs);
    var result = Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .sources = sources.items, .values = outputs, .key_id = expected, .capture_seal = capture.seal, .seal = undefined };
    result.seal = result.identity();
    return result;
}
fn input(builder: *R.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), sources: *std.ArrayList(Shared.Source), source: Shared.Source, value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    try sources.append(a, source);
    return symbol.value;
}
