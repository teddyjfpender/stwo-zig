//! Exact production generic equations for all nineteen caller components.
//! Full detailed claims, aggregates and arithmetic-open sum are public inputs.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const r = @import("composition_graph_recorder.zig");
const S = r.Scalar;
const Source = @import("blake3_execution_composition.zig").Source;
const Admission = @import("../../prover/block_v5_caller_arithmetic_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_caller_arithmetic_recursive_capture_v1.zig");
const Profile = Admission.Profile;
pub const Prepared = @import("blake3_execution_composition.zig").Prepared;
pub const RELATION_COUNT = @import("universal_challenges.zig").RELATION_COUNT + 14;
pub const MAX_PUBLIC_CLAIMS: usize = Admission.MAX_CLAIM_VALUES;
pub fn claimValues(claims: *const Profile.ExtensionClaim, output: []Q) !usize {
    var n: usize = 0;
    for (claims.componentClaims()) |view| {
        if (n + view.detailed.len + @intFromBool(view.has_batch_frame) > output.len) return error.CallerRecursiveResourceLimit;
        @memcpy(output[n..][0..view.detailed.len], view.detailed);
        n += view.detailed.len;
        if (view.has_batch_frame) {
            output[n] = view.total;
            n += 1;
        }
    }
    return n;
}
pub const Samples = struct {
    offsets: [4][]usize,
    layouts: [4][]@import("../sample_point_layout.zig").Layout,
    values: []const S,
    pub fn at(self: Samples, tree: usize, column: usize, row: i8) !S {
        if (tree >= 4 or column >= self.offsets[tree].len) return error.InvalidCallerRecursiveSamples;
        for (self.layouts[tree][column].offsets(), 0..) |offset, i| if (offset == row) return self.values[self.offsets[tree][column] + i];
        return error.InvalidCallerRecursiveSamples;
    }
    pub fn atExtension(self: *const Samples, tree: usize, column: usize, row: i8) !S {
        return self.at(tree, column, row);
    }
    pub fn secure(self: Samples, column: usize, row: i8) !S {
        var limbs: [4]S = undefined;
        for (&limbs, 0..) |*value, i| value.* = try self.at(2, column + i, row);
        return r.fromPartialEvals(limbs);
    }
    pub fn sampledExtensionSecure(self: *const Samples, column: usize, row: i8) !S {
        return self.secure(column, row);
    }
};
const Adapter = struct {
    pub const Scalar = S;
    pub const accumulate = r.accumulate;
    pub const quotientDenominator = r.quotientDenominator;
    pub fn diagnosticCheckpoint(_: []const u8, _: usize, _: u32, _: S) void {}
};
pub fn recordSha(comptime local_zero: bool, owner: anytype, admitted: *const Admission.Prepared, samples: Samples, totals: [5]S, challenges: *const r.ChallengeSet, randomness: S, point: core.circle.CirclePoint(S), cache: *r.DenominatorCache, accumulated: *S) !usize {
    const sha = @import("../../air/guest_precompile/sha256_component_profile.zig");
    var constraints: usize = 0;
    inline for (sha.AirsForRecipe(local_zero), 0..) |Air, i| {
        const component = admitted.components[i + 14];
        const Runtime = @import("universal_relation_binding.zig").Binding(Air).Runtime;
        var row: [Runtime.LOGICAL_INPUT_COUNT]S = undefined;
        for (row[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], 0..) |*value, column| value.* = try samples.at(1, component.spans[1].offset + column, 0);
        for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], 0..) |*value, column| value.* = try samples.at(0, component.spans[0].offset + column, 0);
        var current: [Runtime.BATCH_COUNT]S = undefined;
        for (&current, 0..) |*value, batch| value.* = try samples.secure(component.spans[2].offset + 4 * batch, 0);
        // Framework cumulative columns use previous-first/current-last masks.
        current[Runtime.BATCH_COUNT - 1] = try samples.secure(component.spans[2].offset + 4 * (Runtime.BATCH_COUNT - 1), 0);
        const previous = try samples.secure(component.spans[2].offset + 4 * (Runtime.BATCH_COUNT - 1), -1);
        const denominator = try r.quotientDenominator(component.log_size, admitted.mask_log, point, cache);
        const shift = totals[i].mul(S.fromBase(try M.fromU64(@as(u64, 1) << @intCast(component.log_size)).inv()));
        constraints += try r.recordComponent(Runtime, &owner.components[i], row, current, previous, shift, challenges, randomness, denominator, accumulated);
    }
    return constraints;
}
pub fn recordEquations(admitted: *const Admission.Prepared, owner: anytype, samples: Samples, details: []const S, totals: [19]S, draws: [@import("universal_challenges.zig").RELATION_COUNT][2]S, suffix: [14][2]S, randomness: S, symbolic_point: core.circle.CirclePoint(S)) !S {
    @setEvalBranchQuota(400000);
    const challenges = try r.ChallengeSet.init(draws);
    var cache: r.DenominatorCache = @splat(null);
    var accumulated = S.zero();
    const base = @import("blake3_execution_composition_native.zig").relations(&challenges);
    const Relations = @import("../ethereum_composition_relations_v2.zig").ForScalar(S, @TypeOf(base)).Bundle;
    const relations = Relations.fromBase(base, suffix[0..13].*);
    const eth = try @import("block_v5_caller_arithmetic_record_v1.zig").ForRecorder(Adapter, Samples, Relations).record(admitted, &samples, details[0 .. details.len - 5], &relations, symbolic_point, randomness, admitted.mask_log, &cache, accumulated);
    accumulated = eth.accumulation;
    var sha_draws = draws;
    sha_draws[@intFromEnum(@import("../../air/lang/relation.zig").Domain.recursion_wire)] = suffix[13];
    const sha_challenges = try r.ChallengeSet.init(sha_draws);
    const sha_count = if (comptime Admission.Protocol.circuit_profile.localZeroCustody()) try recordSha(true, owner.sha_owner_local_zero.?, admitted, samples, totals[14..].*, &sha_challenges, randomness, symbolic_point, &cache, &accumulated) else try recordSha(false, owner.sha_owner, admitted, samples, totals[14..].*, &sha_challenges, randomness, symbolic_point, &cache, &accumulated);
    if (eth.instruction_count + sha_count != admitted.air_instruction_count) return error.InvalidCallerRecursiveConstraintCensus;
    return accumulated;
}
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !Prepared {
    try capture.validate(admitted, expected);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var builder = r.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var sources: std.ArrayList(Source) = .empty;
    const point = core.circle.secureFieldPointFromRandomSeed(capture.proof.oods_seed);
    var masks = try admitted.maskPoints(temp, point);
    defer masks.deinitDeep(temp);
    if (capture.proof.sampled_points.len != 4 or masks.items.len != 3) return error.InvalidCallerRecursiveSamples;
    const step = core.poly.circle.canonic.CanonicCoset.new(admitted.mask_log).step();
    const previous = point.sub(.{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) });
    var samples = Samples{ .offsets = undefined, .layouts = undefined, .values = undefined };
    var cursor: usize = 0;
    for (capture.proof.sampled_points, 0..) |columns, tree| {
        const wanted = if (tree < 3) admitted.logs[tree].len else core.verifier_types.compositionColumnCount(admitted.composition_split, 4) orelse return error.InvalidCallerRecursiveSamples;
        if (columns.len != wanted) return error.InvalidCallerRecursiveSamples;
        samples.offsets[tree] = try temp.alloc(usize, columns.len);
        samples.layouts[tree] = try temp.alloc(@import("../sample_point_layout.zig").Layout, columns.len);
        for (columns, 0..) |points, column| {
            if (tree < 3) {
                if (points.len != masks.items[tree][column].len) return error.InvalidCallerRecursiveSamples;
                for (points, masks.items[tree][column]) |actual, wanted_point| if (!actual.eql(wanted_point)) return error.InvalidCallerRecursiveSamples;
            } else if (points.len != 1 or !points[0].eql(point)) return error.InvalidCallerRecursiveSamples;
            samples.offsets[tree][column] = cursor;
            samples.layouts[tree][column] = try @import("../sample_point_layout.zig").classifyColumn(points, point, previous);
            cursor = try std.math.add(usize, cursor, points.len);
        }
    }
    if (cursor != capture.proof.sampled_values.len or cursor > admitted.limits.max_samples) return error.CallerRecursiveResourceLimit;
    const sampled = try temp.alloc(S, cursor);
    for (sampled, capture.proof.sampled_values, 0..) |*symbol, value, i| symbol.* = try input(&builder, temp, &inputs, &sources, .{ .sample = @intCast(i) }, value);
    samples.values = sampled;
    var details: std.ArrayList(S) = .empty;
    var totals: [19]S = undefined;
    var public_cursor: u32 = 0;
    for (capture.original.claims.componentClaims(), &totals) |view, *total| {
        for (view.detailed) |value| {
            try details.append(temp, try input(&builder, temp, &inputs, &sources, .{ .public_input = public_cursor }, value));
            public_cursor += 1;
        }
        if (view.has_batch_frame) {
            total.* = try input(&builder, temp, &inputs, &sources, .{ .public_input = public_cursor }, view.total);
            public_cursor += 1;
        } else total.* = details.items[details.items.len - 1];
    }
    const open_sum = try input(&builder, temp, &inputs, &sources, .{ .public_input = public_cursor }, capture.receipt.open_sum);
    var draws: [@import("universal_challenges.zig").RELATION_COUNT][2]S = undefined;
    for (&draws, capture.relations.elements, 0..) |*pair, element, i| {
        pair[0] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i) }, element.z);
        pair[1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i + 1) }, element.alpha);
    }
    var suffix: [14][2]S = undefined;
    for (&suffix, 0..) |*pair, i| {
        pair[0] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(94 + 2 * i) }, capture.extension_draws[2 * i]);
        pair[1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(95 + 2 * i) }, capture.extension_draws[2 * i + 1]);
    }
    const randomness = try input(&builder, temp, &inputs, &sources, .composition, capture.proof.composition_randomness);
    const seed = try input(&builder, temp, &inputs, &sources, .oods, capture.proof.oods_seed);
    const owner = try Profile.Assembly(.verifier).createBlockV5Standalone(a, &admitted.statement, admitted.total_steps, &capture.original.relations, &capture.original.claims);
    defer owner.destroy(a);
    try builder.activate();
    var active = true;
    defer if (active) builder.deactivate();
    const symbolic_point = r.pointFromSeed(seed);
    const accumulated = try recordEquations(admitted, owner, samples, details.items, totals, draws, suffix, randomness, symbolic_point);
    var detail: usize = 0;
    var total_sum = S.zero();
    for (capture.original.claims.componentClaims(), totals) |view, total| {
        if (view.has_batch_frame) {
            var sum = S.zero();
            for (details.items[detail..][0..view.detailed.len]) |value| sum = sum.add(value);
            try builder.constrainZero(total.sub(sum));
        }
        detail += view.detailed.len;
        total_sum = total_sum.add(total);
    }
    try builder.constrainZero(open_sum.sub(total_sum));
    const chunks = try temp.alloc(S, core.verifier_types.compositionChunkCount(admitted.composition_split) orelse return error.InvalidCallerRecursiveSamples);
    for (chunks, 0..) |*chunk, i| {
        var limbs: [4]S = undefined;
        for (&limbs, 0..) |*value, c| value.* = try samples.at(3, 4 * i + c, 0);
        chunk.* = r.fromPartialEvals(limbs);
    }
    try builder.constrainZero((try r.reconstructSplitComposition(chunks, symbolic_point, admitted.composition_log, admitted.composition_split)).sub(accumulated));
    builder.deactivate();
    active = false;
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, values);
    var result = Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .sources = sources.items, .values = values, .key_id = expected, .capture_seal = capture.seal, .seal = undefined };
    result.seal = result.identity();
    return result;
}
fn input(builder: *r.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), sources: *std.ArrayList(Source), source: Source, value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    try sources.append(a, source);
    return symbol.value;
}
