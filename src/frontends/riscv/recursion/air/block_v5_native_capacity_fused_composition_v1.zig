//! Complete B5CF quotient graph: projection recurrences, exact access68 and
//! appended B5CT activity links. Public claims stay open for block closure.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const R = @import("composition_graph_recorder.zig");
const S = R.Scalar;
const Shared = @import("blake3_execution_composition.zig");
const Admission = @import("../../prover/block_v5_native_capacity_fused_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_native_capacity_fused_recursive_capture_v1.zig");
const Components = @import("block_v5_native_capacity_fused_components_v1.zig");
const Algebra = @import("../../prover/block_v5_native_fused_algebra_v1.zig");
const Integer = @import("../../prover/block_execution_integer_algebra_v1.zig");
const Source = @import("../../prover/block_v5_native_capacity_fused_source_v1.zig");
const Access = @import("../../prover/block_execution_access_bridge_v2.zig");
const Opcode = @import("../../runner/trace.zig");
const Universal = @import("universal_challenges.zig");
pub const Prepared = Shared.Prepared;
pub const RELATION_COUNT: usize = Universal.RELATION_COUNT + 5;
pub const CLOCK_INPUTS: usize = 8;
pub const ACCESS_INPUTS: usize = 10;
pub fn publicCount(projections: usize, accesses: usize) !usize {
    return std.math.add(usize, try std.math.add(usize, CLOCK_INPUTS, projections), try std.math.mul(usize, ACCESS_INPUTS, accesses));
}
pub fn publicInputs(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture) ![]Q {
    return publicInputsFromClaims(a, admitted, capture.metadata.claims, capture.metadata.memory_claims);
}
pub fn publicInputsFromClaims(a: std.mem.Allocator, admitted: *const Admission.Prepared, projection_claims: []const @import("../../prover/block_v5_native_capacity_fused_proof_v1.zig").Claim, memory_claims: []const @import("../../prover/block_v5_opcode_memory_sidecar_proof_v1.zig").Claim) ![]Q {
    if (projection_claims.len != admitted.projections.len or memory_claims.len != admitted.slots.len) return error.InvalidCapacityFusedPublicClaims;
    const count = try publicCount(admitted.projections.len, admitted.slots.len);
    if (try std.math.mul(usize, count, @sizeOf(Q)) > admitted.limits.fused.max_metadata_bytes) return error.CapacityFusedRecursiveResourceLimit;
    const inputs = try a.alloc(Q, count);
    errdefer a.free(inputs);
    @memcpy(inputs[0..8], &Integer.clockBytes(Q, try @import("../../prover/block_execution_integer_bridge_v2.zig").baseClockFromPublicFrame(admitted.frame)));
    for (projection_claims, inputs[8..][0..admitted.projections.len]) |claim, *out| out.* = claim.sum;
    var offset: usize = 8 + admitted.projections.len;
    for (memory_claims) |claim| {
        inputs[offset] = claim.transition_sum;
        inputs[offset + 1] = claim.universal_sum;
        inputs[offset + 2] = Q.fromBase(M.fromU64(claim.active_count));
        @memcpy(inputs[offset + 3 ..][0..7], &claim.range_claims);
        offset += ACCESS_INPUTS;
    }
    if (offset != inputs.len) return error.InvalidCapacityFusedPublicClaims;
    return inputs;
}
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
    pub fn splat(value: Q) Field {
        return .{ .symbol = S.fromSecure(value) };
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
    pub fn square(self: Field) Field {
        return self.mul(self);
    }
    pub fn eql(self: Field, other: Field) bool {
        return switch (self.symbol.handle) {
            .constant => |value| switch (other.symbol.handle) {
                .constant => |rhs| value.eql(rhs),
                else => false,
            },
            else => false,
        };
    }
    pub fn fromPartialEvals(values: [4]Field) Field {
        return .{ .symbol = R.fromPartialEvals(.{ values[0].symbol, values[1].symbol, values[2].symbol, values[3].symbol }) };
    }
};
const Relations = struct {
    native: R.ChallengeSet,
    const Element = struct {
        element: *const R.ChallengeSet.Element,
        arity: u8,
        pub fn combineSecure(self: @This(), values: []const Field) !Field {
            if (values.len > Universal.MAX_ARITY) return error.InvalidRelationPlan;
            var symbols: [Universal.MAX_ARITY]S = undefined;
            for (values, symbols[0..values.len]) |value, *out| out.* = value.symbol;
            return .{ .symbol = try self.element.combine(symbols[0..values.len]) };
        }
    };
    pub fn get(self: *const Relations, domain: @import("../../air/lang/relation.zig").Domain) Element {
        const element = self.native.get(domain);
        return .{ .element = element, .arity = element.arity };
    }
};
const Transition = struct {
    z: Field,
    powers: [11]Field,
    fn init(z: S, alpha: S) Transition {
        var result = Transition{ .z = .{ .symbol = z }, .powers = undefined };
        var power = Field.one();
        for (&result.powers) |*out| {
            out.* = power;
            power = power.mul(.{ .symbol = alpha });
        }
        return result;
    }
    pub fn combineSecure(self: Transition, values: [11]Field) Field {
        return @import("../../air/relation_challenges.zig").combineGeneric(Field, self.z, self.powers, values);
    }
};
const Samples = struct {
    offsets: [5][]usize,
    lengths: [5][]usize,
    values: []const S,
    tree_count: usize,
    pub fn at(self: Samples, tree: usize, column: usize, sample: usize) !S {
        if (tree >= self.tree_count or column >= self.offsets[tree].len or sample >= self.lengths[tree][column]) return error.InvalidCapacityFusedSamples;
        return self.values[self.offsets[tree][column] + sample];
    }
};
pub fn recordConstraints(admitted: *const Admission.Prepared, samples: anytype, public: []const S, draws: [Universal.RELATION_COUNT][2]S, word_draws: [10]S, random: S, point: core.circle.CirclePoint(S), mask_log: u32, accumulated: *S) !usize {
    if (public.len != try publicCount(admitted.projections.len, admitted.slots.len)) return error.InvalidCapacityFusedPublicClaims;
    const A = Algebra.Algebra(Field);
    const relations = Relations{ .native = try R.ChallengeSet.init(draws) };
    const transition = Transition.init(word_draws[0], word_draws[1]);
    const interaction_tree = admitted.tree_count - 1;
    var cache: R.DenominatorCache = @splat(null);
    var count: usize = 0;
    for (admitted.projections, 0..) |slot, i| {
        var main: [Opcode.MAX_FAMILY_COLUMNS]Field = undefined;
        for (main[0..slot.width], 0..) |*out, column| out.* = .{ .symbol = try samples.at(1, slot.main_offset + column, 0) };
        var current: [4]Field = undefined;
        var previous: [4]Field = undefined;
        for (&current, &previous, 0..) |*out, *prior, column| {
            out.* = .{ .symbol = try samples.at(interaction_tree, 4 * i + column, 0) };
            prior.* = .{ .symbol = try samples.at(interaction_tree, 4 * i + column, 1) };
        }
        const inverse = try R.quotientDenominator(slot.log_size, mask_log, point, &cache);
        const normalized = public[8 + i].mul(S.fromBase(try M.fromCanonical(@as(u32, 1) << @intCast(slot.log_size)).inv()));
        R.accumulate(accumulated, random, A.projectionResidual(try A.projection(slot, main[0..slot.width], &relations), current, previous, .{ .symbol = normalized }).symbol, inverse);
        const binding = try Source.binding(admitted.native.shape, admitted.native.external_retirements, slot.main_offset, slot.log_size, slot.n_rows);
        R.accumulate(accumulated, random, (try A.activity(slot, main[0..slot.width])).symbol.sub(try samples.at(1, binding.main_index, 0)), inverse);
        count += 2;
    }
    for (admitted.slots, 0..) |slot, i| {
        const width = Opcode.nColumnsForFamily(slot.family);
        var main: [Opcode.MAX_FAMILY_COLUMNS]Field = undefined;
        for (main[0..width], 0..) |*out, column| out.* = .{ .symbol = try samples.at(1, slot.main_offset + column, 0) };
        const pairs = try Access.fromCommittedMain(Field, slot.family, main[0..width]);
        if (slot.slot >= pairs.len) return error.InvalidExecutionSidecarSlot;
        const pair = try Access.rwPairForMode(Field, slot.family, slot.slot, pairs.items[slot.slot], admitted.native.sealed.register_custody_mode);
        var witness: [48]Field = undefined;
        for (&witness, 0..) |*out, column| out.* = .{ .symbol = try samples.at(2, 48 * i + column, 0) };
        var current: [Algebra.INTERACTION_COUNT]Field = undefined;
        var previous: [Algebra.INTERACTION_COUNT]Field = undefined;
        const offset = 4 * admitted.projections.len + Algebra.INTERACTION_COUNT * i;
        for (&current, &previous, 0..) |*out, *prior, column| {
            out.* = .{ .symbol = try samples.at(interaction_tree, offset + column, 0) };
            prior.* = .{ .symbol = try samples.at(interaction_tree, offset + column, 1) };
        }
        var clock_bytes: [8]Field = undefined;
        for (&clock_bytes, public[0..8]) |*out, value| out.* = .{ .symbol = value };
        const shift = S.fromBase(try M.fromCanonical(@as(u32, 1) << @intCast(slot.log_size)).inv());
        const start = 8 + admitted.projections.len + ACCESS_INPUTS * i;
        var ranges: [7]Field = undefined;
        for (&ranges, public[start + 3 ..][0..7]) |*out, value| out.* = .{ .symbol = value.mul(shift) };
        const equations = try A.access(pair, witness, current, previous, clock_bytes, transition, &relations, .{ .symbol = public[start].mul(shift) }, .{ .symbol = public[start + 2].mul(shift) }, ranges, .{ .symbol = public[start + 1].mul(shift) });
        const inverse = try R.quotientDenominator(slot.log_size, mask_log, point, &cache);
        for (equations) |equation| R.accumulate(accumulated, random, equation.symbol, inverse);
        const binding = try Source.binding(admitted.native.shape, admitted.native.external_retirements, slot.main_offset, slot.log_size, null);
        R.accumulate(accumulated, random, (try A.opcodeActivity(slot.family, main[0..width])).symbol.sub(try samples.at(1, binding.main_index, 0)), inverse);
        count += equations.len + 1;
    }
    return count;
}
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !Prepared {
    try capture.validate(admitted, expected);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var owner = try Components.Owner.init(a, admitted, capture, expected);
    defer owner.deinit();
    const all = owner.all(admitted.logs[0].len);
    const composition_log = all.compositionLogDegreeBound();
    const split = try all.compositionLogSplit();
    const mask_log = core.verifier_types.compositionMaskLogSize(composition_log, split) orelse return error.InvalidCapacityFusedGeometry;
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var sources: std.ArrayList(Shared.Source) = .empty;
    if (capture.proof.sampled_points.len != admitted.tree_count + 1) return error.InvalidCapacityFusedSamples;
    var samples = Samples{ .offsets = undefined, .lengths = undefined, .values = undefined, .tree_count = admitted.tree_count + 1 };
    var cursor: usize = 0;
    for (capture.proof.sampled_points, 0..) |columns, tree| {
        samples.offsets[tree] = try temp.alloc(usize, columns.len);
        samples.lengths[tree] = try temp.alloc(usize, columns.len);
        for (columns, 0..) |points, column| {
            samples.offsets[tree][column] = cursor;
            samples.lengths[tree][column] = points.len;
            cursor = try std.math.add(usize, cursor, points.len);
        }
    }
    if (cursor != capture.proof.sampled_values.len) return error.InvalidCapacityFusedSamples;
    const symbols = try temp.alloc(S, cursor);
    for (symbols, capture.proof.sampled_values, 0..) |*out, value, i| out.* = try input(&builder, temp, &inputs, &sources, .{ .sample = @intCast(i) }, value);
    samples.values = symbols;
    var draws: [Universal.RELATION_COUNT][2]S = undefined;
    for (&draws, capture.relations.elements, 0..) |*out, element, i| {
        out[0] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i) }, element.z);
        out[1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i + 1) }, element.alpha);
    }
    var word_draws: [10]S = undefined;
    inline for (.{ capture.word_challenges.transition, capture.word_challenges.link, capture.word_challenges.initial, capture.word_challenges.endpoint, capture.word_challenges.range16 }, 0..) |element, i| {
        word_draws[2 * i] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * Universal.RELATION_COUNT + 2 * i) }, element.z);
        word_draws[2 * i + 1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * Universal.RELATION_COUNT + 2 * i + 1) }, element.alpha);
    }
    const public_values = try publicInputs(temp, admitted, capture);
    const public = try temp.alloc(S, public_values.len);
    for (public, public_values, 0..) |*out, value, i| out.* = try input(&builder, temp, &inputs, &sources, .{ .public_input = @intCast(i) }, value);
    const random = try input(&builder, temp, &inputs, &sources, .composition, capture.proof.composition_randomness);
    const seed = try input(&builder, temp, &inputs, &sources, .oods, capture.proof.oods_seed);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const point = R.pointFromSeed(seed);
    var accumulated = S.zero();
    const count = recordConstraints(admitted, samples, public, draws, word_draws, random, point, mask_log, &accumulated) catch |err| return builder.failure orelse err;
    if (builder.failure) |failure| return failure;
    var expected_count: usize = 0;
    for (owner.handles) |component| expected_count += component.nConstraints();
    if (count != expected_count) return error.InvalidCapacityFusedConstraintCount;
    const chunks = try temp.alloc(S, core.verifier_types.compositionChunkCount(split) orelse return error.InvalidCapacityFusedGeometry);
    for (chunks, 0..) |*out, chunk| out.* = R.fromPartialEvals(.{ try samples.at(admitted.tree_count, 4 * chunk, 0), try samples.at(admitted.tree_count, 4 * chunk + 1, 0), try samples.at(admitted.tree_count, 4 * chunk + 2, 0), try samples.at(admitted.tree_count, 4 * chunk + 3, 0) });
    try builder.constrainZero((try R.reconstructSplitComposition(chunks, point, composition_log, split)).sub(accumulated));
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, values);
    var result = Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .sources = sources.items, .values = values, .key_id = expected, .capture_seal = capture.seal, .seal = undefined };
    result.seal = result.identity();
    return result;
}
fn input(builder: *R.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), sources: *std.ArrayList(Shared.Source), source: Shared.Source, value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    try sources.append(a, source);
    return symbol.value;
}
