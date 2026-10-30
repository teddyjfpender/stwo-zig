//! Original arithmetic followed by original fused caller equations, with one
//! Horner sequence and one split-composition equality. Every sample is routed
//! from the genuine six-tree capture through independently rebuilt masks.
//! This is the composition leg, not a complete recursive PCS verifier/key.
//! Shared implementation: default and finite active caller families.
pub fn For(comptime Policy: type) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const Q = core.fields.qm31.QM31;
        const M = core.fields.m31.M31;
        const R = @import("composition_graph_recorder.zig");
        const S = R.Scalar;
        const Shared = @import("blake3_execution_composition.zig");
        const Arithmetic = @import("block_v5_caller_arithmetic_composition_v1.zig");
        const Fused = @import("block_v5_caller_fused_composition_v1.zig");
        const Admission = Policy.Admission;
        const Capture = Policy.Capture;
        const Profile = @import("../../prover/blake3_ethereum_sha_profile.zig");
        const Protocol = @import("../../prover/block_v5_precompile_protocol_v1.zig");
        const Universal = @import("universal_challenges.zig");
        pub const Prepared = Shared.Prepared;
        pub const RELATION_COUNT = Universal.RELATION_COUNT + 14 + 5 + 1;
        const Adapter = struct {
            pub const Scalar = S;
            pub const accumulate = R.accumulate;
            pub const quotientDenominator = R.quotientDenominator;
            pub fn diagnosticCheckpoint(_: []const u8, _: usize, _: u32, _: S) void {}
        };
        const Observation = struct {
            sampled_points: [][][]core.circle.CirclePointQM31,
            sampled_values: []const Q,
            oods_seed: Q,
            composition_randomness: Q,
        };
        pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !Prepared {
            try capture.validate(admitted, expected);
            const p = &capture.original.proof;
            return record(a, admitted, &capture.original.arithmetic, &capture.original.claims, .{ .sampled_points = p.sampled_points, .sampled_values = p.sampled_values, .oods_seed = p.oods_seed, .composition_randomness = p.composition_randomness }, expected, capture.seal, true);
        }
        pub const Compiled = struct {
            allocator: std.mem.Allocator,
            circuit: R.Circuit,
            sources: []Shared.Source,
            pub fn deinit(self: *Compiled) void {
                self.circuit.deinit();
                self.allocator.free(self.sources);
                self.* = undefined;
            }
        };
        /// Metadata-only equations. The sample route is independently built from the
        /// original component masks; synthetic operands are never a verified capture.
        pub fn compile(a: std.mem.Allocator, admitted: *const Admission.Prepared, arithmetic: *const Profile.ExtensionClaim, claims: *const @import("../../prover/block_v5_caller_fused_proof_v1.zig").ClaimFrames) !Compiled {
            try admitted.validate();
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const temp = arena.allocator();
            const equations = try Admission.EquationOwner.create(temp, admitted, arithmetic, claims);
            defer equations.destroy();
            const seed = Q.fromBase(M.fromCanonical(3));
            const point = core.circle.secureFieldPointFromRandomSeed(seed);
            var masks = try equations.joint.maskPoints(temp, point, admitted.mask_log);
            defer masks.deinitDeep(temp);
            const points = try temp.alloc([][]core.circle.CirclePointQM31, 6);
            @memcpy(points[0..5], masks.items);
            const count = core.verifier_types.compositionColumnCount(admitted.composition_split, 4) orelse return error.InvalidJointCallerCompositionSamples;
            points[5] = try temp.alloc([]core.circle.CirclePointQM31, count);
            for (points[5]) |*samples| samples.* = try temp.dupe(core.circle.CirclePointQM31, &.{point});
            var n: usize = 0;
            for (points) |tree| for (tree) |samples| {
                n = try std.math.add(usize, n, samples.len);
            };
            if (n > admitted.limits.max_samples) return error.V7CallerResourceLimit;
            const samples = try temp.alloc(Q, n);
            @memset(samples, Q.zero());
            var compiled = try record(a, admitted, arithmetic, claims, .{ .sampled_points = points, .sampled_values = samples, .oods_seed = seed, .composition_randomness = Q.one() }, admitted.template_id, @splat(0), false);
            errdefer compiled.deinit();
            const sources = try a.dupe(Shared.Source, compiled.sources);
            const circuit = compiled.circuit;
            compiled.arena.deinit();
            return .{ .allocator = a, .circuit = circuit, .sources = sources };
        }
        fn record(a: std.mem.Allocator, admitted: *const Admission.Prepared, arithmetic: *const Profile.ExtensionClaim, claims: *const @import("../../prover/block_v5_caller_fused_proof_v1.zig").ClaimFrames, observed: Observation, expected: [32]u8, capture_seal: [32]u8, comptime evaluate: bool) !Prepared {
            @setEvalBranchQuota(800000);
            const proof = &observed;
            const equations = try Admission.EquationOwner.create(a, admitted, arithmetic, claims);
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
            for (arithmetic.componentClaims(), &totals) |view, *total| {
                for (view.detailed) |value| {
                    try details.append(temp, try input(&builder, temp, &inputs, &sources, .{ .public_input = public_at }, value));
                    public_at += 1;
                }
                if (view.has_batch_frame) {
                    total.* = try input(&builder, temp, &inputs, &sources, .{ .public_input = public_at }, view.total);
                    public_at += 1;
                } else total.* = details.items[details.items.len - 1];
            }
            const open_sum = try input(&builder, temp, &inputs, &sources, .{ .public_input = public_at }, arithmetic.componentSum());
            public_at += 1;
            const fused_values = try Fused.publicInputsForSchedule(temp, &admitted.relations.schedule, admitted.relations.frame, claims.*);
            const fused_public = try temp.alloc(S, fused_values.len);
            for (fused_public, fused_values) |*out, value| {
                out.* = try input(&builder, temp, &inputs, &sources, .{ .public_input = public_at }, value);
                public_at += 1;
            }
            const elements = equations.drawn.relations;
            const universal = equations.drawn.epoch.word.universal_prefix;
            const extension = elements.draws();
            const word_elements = equations.drawn.epoch.word;
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
            _ = try input(&builder, temp, &inputs, &sources, .{ .challenge = 132 }, equations.drawn.epoch.memory.interval.z);
            _ = try input(&builder, temp, &inputs, &sources, .{ .challenge = 133 }, equations.drawn.epoch.memory.interval.powers[1]);
            const random = try input(&builder, temp, &inputs, &sources, .composition, proof.composition_randomness);
            const seed = try input(&builder, temp, &inputs, &sources, .oods, proof.oods_seed);
            try builder.activate();
            defer if (builder.active) builder.deactivate();
            const symbolic_point = R.pointFromSeed(seed);
            var accumulated = S.zero();
            try recordComponents(&builder, admitted, equations, arithmetic, arithmetic_samples, fused_samples, .{ .details = details.items, .totals = totals, .open_sum = open_sum, .fused = fused_public }, draws, suffix, word, random, symbolic_point, admitted.mask_log, &accumulated);
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
            if (evaluate) try circuit.evaluateInto(inputs.items, values);
            var result = Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .sources = sources.items, .values = values, .key_id = expected, .capture_seal = capture_seal, .seal = undefined };
            result.seal = result.identity();
            return result;
        }
        pub const SymbolicClaims = struct { details: []const S, totals: [19]S, open_sum: S, fused: []const S };
        /// Continue the enclosing proof's Horner sequence. The explicit mask
        /// step belongs to that enclosing proof; source admission stays intact.
        pub fn recordComponents(builder: *R.Builder, admitted: *const Admission.Prepared, equations: *const Admission.EquationOwner, arithmetic: *const Profile.ExtensionClaim, arithmetic_samples: Arithmetic.Samples, fused_samples: Fused.Samples, public: SymbolicClaims, draws: [Universal.RELATION_COUNT][2]S, suffix: [14][2]S, word: [10]S, random: S, symbolic_point: core.circle.CirclePoint(S), mask_log: u32, accumulated: *S) !void {
            const details = public.details;
            const totals = public.totals;
            const open_sum = public.open_sum;
            const fused_public = public.fused;
            var cache: R.DenominatorCache = @splat(null);
            const challenges = try R.ChallengeSet.init(draws);
            const base = @import("blake3_execution_composition_native.zig").relations(&challenges);
            const Relations = @import("../ethereum_composition_relations_v2.zig").ForScalar(S, @TypeOf(base)).Bundle;
            const relations = Relations.fromBase(base, suffix[0..13].*);
            const Recorder = @import("block_v5_caller_arithmetic_record_v1.zig").ForRecorder(Adapter, Arithmetic.Samples, Relations);
            const eth = if (Policy.active) try Recorder.recordSelected(&admitted.arithmetic, &arithmetic_samples, details[0 .. details.len - 5], &relations, symbolic_point, random, mask_log, &cache, accumulated.*, builder) else try Recorder.record(&admitted.arithmetic, &arithmetic_samples, details[0 .. details.len - 5], &relations, symbolic_point, random, mask_log, &cache, accumulated.*);
            accumulated.* = eth.accumulation;
            var sha_draws = draws;
            sha_draws[@intFromEnum(@import("../../air/lang/relation.zig").Domain.recursion_wire)] = suffix[13];
            const sha_challenges = try R.ChallengeSet.init(sha_draws);
            const sha_count = if (Policy.active) blk: {
                if (equations.arithmetic.sha_owner) |owner| break :blk try recordSha(false, owner, admitted, arithmetic_samples, totals[14..].*, &sha_challenges, random, symbolic_point, mask_log, &cache, accumulated);
                for (admitted.arithmetic.selected[14..]) |selected| if (selected) return error.InvalidJointCallerEquationCensus;
                break :blk 0;
            } else if (comptime Protocol.circuit_profile.localZeroCustody()) try recordSha(true, equations.arithmetic.sha_owner_local_zero.?, admitted, arithmetic_samples, totals[14..].*, &sha_challenges, random, symbolic_point, mask_log, &cache, accumulated) else try recordSha(false, equations.arithmetic.sha_owner, admitted, arithmetic_samples, totals[14..].*, &sha_challenges, random, symbolic_point, mask_log, &cache, accumulated);
            const fused_count = try Fused.recordConstraintsFor(Admission.Relations, &admitted.relations, fused_samples, fused_public, draws, word, random, symbolic_point, mask_log, accumulated);
            if (eth.instruction_count + sha_count != admitted.arithmetic.air_instruction_count or eth.instruction_count + sha_count + fused_count != admitted.constraint_count) return error.InvalidJointCallerEquationCensus;
            var detail: usize = 0;
            var total_sum = S.zero();
            for (arithmetic.componentClaims(), totals, 0..) |view, total, component_index| {
                if (Policy.active and !admitted.arithmetic.selected[component_index]) try builder.constrainZero(total);
                if (view.has_batch_frame) {
                    var sum = S.zero();
                    for (details[detail..][0..view.detailed.len]) |value| sum = sum.add(value);
                    try builder.constrainZero(total.sub(sum));
                }
                detail += view.detailed.len;
                total_sum = total_sum.add(total);
            }
            try builder.constrainZero(open_sum.sub(total_sum));
        }
        pub const Mapped = struct { offsets: [][]usize, lengths: [][]usize, symbols: []S };
        pub fn mapSamples(a: std.mem.Allocator, original: *const core.air.components.MaskPoints, map: []const usize, joint: [][][]core.circle.CirclePointQM31, offsets: [6][]usize, sampled: []const S) !Mapped {
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
        fn recordSha(comptime local_zero: bool, owner: anytype, admitted: *const Admission.Prepared, samples: Arithmetic.Samples, totals: [5]S, challenges: *const R.ChallengeSet, random: S, point: core.circle.CirclePoint(S), mask_log: u32, cache: *R.DenominatorCache, accumulated: *S) !usize {
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
                const denominator = try R.quotientDenominator(component.log_size, mask_log, point, cache);
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
    };
}
