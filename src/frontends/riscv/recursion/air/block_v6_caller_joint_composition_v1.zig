//! Original arithmetic followed by original fused caller equations, with one
//! Horner sequence and one split-composition equality. Every sample is routed
//! from the genuine six-tree capture through independently rebuilt masks.
//! This is the composition leg, not a complete recursive PCS verifier/key.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const R = @import("composition_graph_recorder.zig");
const S = R.Scalar;
const Shared = @import("blake3_execution_composition.zig");
const Arithmetic = @import("block_v5_caller_arithmetic_composition_v1.zig");
const Fused = @import("block_v5_caller_fused_composition_v1.zig");
const Admission = @import("../../prover/block_v6_caller_joint_admission_v1.zig");
const Capture = @import("../../prover/block_v6_caller_joint_capture_v1.zig");
const Profile = @import("../../prover/blake3_ethereum_sha_profile.zig");
const Protocol = @import("../../prover/block_v5_precompile_protocol_v1.zig");
const Universal = @import("universal_challenges.zig");
pub const Prepared = Shared.Prepared;
pub const RELATION_COUNT = Universal.RELATION_COUNT + 14 + 5;
const Adapter = struct {
    pub const Scalar = S;
    pub const accumulate = R.accumulate;
    pub const quotientDenominator = R.quotientDenominator;
    pub fn diagnosticCheckpoint(_: []const u8, _: usize, _: u32, _: S) void {}
};
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !Prepared {
    @setEvalBranchQuota(800000);
    try capture.validate(admitted, expected);
    const original = &capture.original;
    const proof = &original.proof;
    const equations = try Admission.EquationOwner.create(a, admitted, &original.arithmetic, &original.claims);
    defer equations.destroy();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var sources: std.ArrayList(Shared.Source) = .empty;
    const sampled = try temp.alloc(S, proof.sampled_values.len);
    for (sampled, proof.sampled_values, 0..) |*out, value, i| out.* = try input(&builder, temp, &inputs, &sources, .{ .sample = @intCast(i) }, value);
    var offsets: [6][]usize = undefined;
    var at: usize = 0;
    for (proof.sampled_points, &offsets) |tree, *tree_offsets| {
        tree_offsets.* = try temp.alloc(usize, tree.len);
        for (tree, tree_offsets.*) |points, *offset| {
            offset.* = at;
            at += points.len;
        }
    }
    if (at != sampled.len) return error.InvalidJointCallerCompositionSamples;
    const point = core.circle.secureFieldPointFromRandomSeed(proof.oods_seed);
    const step = core.poly.circle.canonic.CanonicCoset.new(admitted.mask_log).step();
    const previous = point.sub(.{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) });
    var arithmetic_points = try (core.air.components.Components{ .components = equations.arithmetic.active(), .n_preprocessed_columns = admitted.logs()[0].len }).maskPoints(temp, point, admitted.mask_log, false);
    defer arithmetic_points.deinitDeep(temp);
    var fused_points = try (core.air.components.Components{ .components = equations.handles, .n_preprocessed_columns = admitted.logs()[0].len }).maskPoints(temp, point, admitted.mask_log, false);
    defer fused_points.deinitDeep(temp);
    const arithmetic_mapped = try mapSamples(temp, &arithmetic_points, &.{ 0, 1, 3 }, proof.sampled_points, offsets, sampled);
    const fused_mapped = try mapSamples(temp, &fused_points, &.{ 0, 1, 2, 4 }, proof.sampled_points, offsets, sampled);
    var arithmetic_samples = Arithmetic.Samples{ .offsets = .{ arithmetic_mapped.offsets[0], arithmetic_mapped.offsets[1], arithmetic_mapped.offsets[2], &.{} }, .layouts = undefined, .values = arithmetic_mapped.symbols };
    for (arithmetic_points.items, 0..) |columns, t| {
        arithmetic_samples.layouts[t] = try temp.alloc(@import("../sample_point_layout.zig").Layout, columns.len);
        for (columns, arithmetic_samples.layouts[t]) |points, *layout| layout.* = try @import("../sample_point_layout.zig").classifyColumn(points, point, previous);
    }
    arithmetic_samples.layouts[3] = &.{};
    const fused_samples = Fused.Samples{ .offsets = .{ fused_mapped.offsets[0], fused_mapped.offsets[1], fused_mapped.offsets[2], fused_mapped.offsets[3], &.{} }, .lengths = .{ fused_mapped.lengths[0], fused_mapped.lengths[1], fused_mapped.lengths[2], fused_mapped.lengths[3], &.{} }, .values = fused_mapped.symbols };
    var details: std.ArrayList(S) = .empty;
    var totals: [19]S = undefined;
    var public_at: u32 = 0;
    for (original.arithmetic.componentClaims(), &totals) |view, *total| {
        for (view.detailed) |value| {
            try details.append(temp, try input(&builder, temp, &inputs, &sources, .{ .public_input = public_at }, value));
            public_at += 1;
        }
        if (view.has_batch_frame) {
            total.* = try input(&builder, temp, &inputs, &sources, .{ .public_input = public_at }, view.total);
            public_at += 1;
        } else total.* = details.items[details.items.len - 1];
    }
    const open_sum = try input(&builder, temp, &inputs, &sources, .{ .public_input = public_at }, original.receipt.arithmetic_sum);
    public_at += 1;
    const fused_values = try Fused.publicInputs(temp, &admitted.relations, original.claims);
    const fused_public = try temp.alloc(S, fused_values.len);
    for (fused_public, fused_values) |*out, value| {
        out.* = try input(&builder, temp, &inputs, &sources, .{ .public_input = public_at }, value);
        public_at += 1;
    }
    var shared_channel = admitted.arithmetic.sealed.sharedChannel();
    const universal = try Universal.UniversalRelations.draw(temp, &shared_channel);
    const elements = try Protocol.drawRelations(temp, admitted.arithmetic.sealed);
    const extension = elements.draws();
    const word_elements = try @import("../../prover/block_v5_word_memory_protocol_v1.zig").Challenges.draw(temp, admitted.arithmetic.sealed);
    var draws: [Universal.RELATION_COUNT][2]S = undefined;
    for (&draws, universal.elements, 0..) |*out, element, i| {
        out[0] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i) }, element.z);
        out[1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i + 1) }, element.alpha);
    }
    var suffix: [14][2]S = undefined;
    for (&suffix, 0..) |*out, i| {
        out[0] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(94 + 2 * i) }, extension[2 * i]);
        out[1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(95 + 2 * i) }, extension[2 * i + 1]);
    }
    var word: [10]S = undefined;
    inline for (.{ "transition", "link", "initial", "endpoint", "range16" }, 0..) |name, i| {
        const element = @field(word_elements, name);
        word[2 * i] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(122 + 2 * i) }, element.z);
        word[2 * i + 1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(123 + 2 * i) }, element.alpha);
    }
    const random = try input(&builder, temp, &inputs, &sources, .composition, proof.composition_randomness);
    const seed = try input(&builder, temp, &inputs, &sources, .oods, proof.oods_seed);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const symbolic_point = R.pointFromSeed(seed);
    var cache: R.DenominatorCache = @splat(null);
    const challenges = try R.ChallengeSet.init(draws);
    const base = @import("blake3_execution_composition_native.zig").relations(&challenges);
    const Relations = @import("../ethereum_composition_relations_v2.zig").ForScalar(S, @TypeOf(base)).Bundle;
    const relations = Relations.fromBase(base, suffix[0..13].*);
    const eth = try @import("block_v5_caller_arithmetic_record_v1.zig").ForRecorder(Adapter, Arithmetic.Samples, Relations).record(&admitted.arithmetic, &arithmetic_samples, details.items[0 .. details.items.len - 5], &relations, symbolic_point, random, admitted.mask_log, &cache, S.zero());
    var accumulated = eth.accumulation;
    var sha_draws = draws;
    sha_draws[@intFromEnum(@import("../../air/lang/relation.zig").Domain.recursion_wire)] = suffix[13];
    const sha_challenges = try R.ChallengeSet.init(sha_draws);
    const sha_count = if (comptime Protocol.circuit_profile.localZeroCustody()) try recordSha(true, equations.arithmetic.sha_owner_local_zero.?, admitted, arithmetic_samples, totals[14..].*, &sha_challenges, random, symbolic_point, &cache, &accumulated) else try recordSha(false, equations.arithmetic.sha_owner, admitted, arithmetic_samples, totals[14..].*, &sha_challenges, random, symbolic_point, &cache, &accumulated);
    const fused_count = try Fused.recordConstraints(&admitted.relations, fused_samples, fused_public, draws, word, random, symbolic_point, admitted.mask_log, &accumulated);
    if (eth.instruction_count + sha_count != admitted.arithmetic.air_instruction_count or eth.instruction_count + sha_count + fused_count != admitted.constraint_count) return error.InvalidJointCallerEquationCensus;
    var detail: usize = 0;
    var total_sum = S.zero();
    for (original.arithmetic.componentClaims(), totals) |view, total| {
        if (view.has_batch_frame) {
            var sum = S.zero();
            for (details.items[detail..][0..view.detailed.len]) |value| sum = sum.add(value);
            try builder.constrainZero(total.sub(sum));
        }
        detail += view.detailed.len;
        total_sum = total_sum.add(total);
    }
    try builder.constrainZero(open_sum.sub(total_sum));
    const chunks = try temp.alloc(S, core.verifier_types.compositionChunkCount(admitted.composition_split) orelse return error.InvalidJointCallerCompositionSamples);
    for (chunks, 0..) |*out, chunk| {
        var limbs: [4]S = undefined;
        for (&limbs, 0..) |*value, i| value.* = sampled[offsets[5][4 * chunk + i]];
        out.* = R.fromPartialEvals(limbs);
    }
    try builder.constrainZero((try R.reconstructSplitComposition(chunks, symbolic_point, admitted.composition_log, admitted.composition_split)).sub(accumulated));
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, values);
    var result = Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .sources = sources.items, .values = values, .key_id = expected, .capture_seal = capture.seal, .seal = undefined };
    result.seal = result.identity();
    return result;
}
const Mapped = struct { offsets: [][]usize, lengths: [][]usize, symbols: []S };
fn mapSamples(a: std.mem.Allocator, original: *const core.air.components.MaskPoints, map: []const usize, joint: [][][]core.circle.CirclePointQM31, offsets: [6][]usize, sampled: []const S) !Mapped {
    const starts = try a.alloc([]usize, map.len);
    const lengths = try a.alloc([]usize, map.len);
    var symbols: std.ArrayList(S) = .empty;
    for (original.items, map, starts, lengths) |columns, t, *tree_starts, *tree_lengths| {
        if (columns.len != joint[t].len) return error.InvalidJointCallerCompositionSamples;
        tree_starts.* = try a.alloc(usize, columns.len);
        tree_lengths.* = try a.alloc(usize, columns.len);
        for (columns, tree_starts.*, tree_lengths.*, 0..) |points, *start, *length, c| {
            start.* = symbols.items.len;
            length.* = points.len;
            for (points) |point| {
                var found = false;
                for (joint[t][c], 0..) |candidate, i| if (candidate.eql(point)) {
                    try symbols.append(a, sampled[offsets[t][c] + i]);
                    found = true;
                    break;
                };
                if (!found) return error.InvalidJointCallerCompositionSamples;
            }
        }
    }
    return .{ .offsets = starts, .lengths = lengths, .symbols = try symbols.toOwnedSlice(a) };
}
/// Original five SHA equations, with the joint mask step explicit. The source
/// admission is left unchanged; a host-edited old admission is not authority.
fn recordSha(comptime local_zero: bool, owner: anytype, admitted: *const Admission.Prepared, samples: Arithmetic.Samples, totals: [5]S, challenges: *const R.ChallengeSet, random: S, point: core.circle.CirclePoint(S), cache: *R.DenominatorCache, accumulated: *S) !usize {
    const Sha = @import("../../air/guest_precompile/sha256_component_profile.zig");
    var count: usize = 0;
    inline for (Sha.AirsForRecipe(local_zero), 0..) |Air, i| {
        const component = admitted.arithmetic.components[i + 14];
        const Runtime = @import("universal_relation_binding.zig").Binding(Air).Runtime;
        var row: [Runtime.LOGICAL_INPUT_COUNT]S = undefined;
        for (row[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], 0..) |*value, c| value.* = try samples.at(1, component.spans[1].offset + c, 0);
        for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], 0..) |*value, c| value.* = try samples.at(0, component.spans[0].offset + c, 0);
        var current: [Runtime.BATCH_COUNT]S = undefined;
        for (&current, 0..) |*value, b| value.* = try samples.secure(component.spans[2].offset + 4 * b, 0);
        const previous = try samples.secure(component.spans[2].offset + 4 * (Runtime.BATCH_COUNT - 1), -1);
        const denominator = try R.quotientDenominator(component.log_size, admitted.mask_log, point, cache);
        const shift = totals[i].mul(S.fromBase(try M.fromU64(@as(u64, 1) << @intCast(component.log_size)).inv()));
        count += try R.recordComponent(Runtime, &owner.components[i], row, current, previous, shift, challenges, random, denominator, accumulated);
    }
    return count;
}
fn input(builder: *R.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), sources: *std.ArrayList(Shared.Source), source: Shared.Source, value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    try sources.append(a, source);
    return symbol.value;
}
