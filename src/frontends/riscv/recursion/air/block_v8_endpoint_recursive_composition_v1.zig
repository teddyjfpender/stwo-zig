//! Shared finite-family implementation; original equation authorities remain independent.
const Family = @import("../block_v8_endpoint_recursive_source_v1.zig").Family;
pub fn For(comptime family: Family) type {
    return struct {
        const Traits = @import("../block_v8_endpoint_recursive_source_v1.zig").For(family);
        const is_local = Traits.is_local;
        // One original B8 quotient equation, replaying the original generic kernels
        // in original component order. Public operands include every physical claim.
        const std = @import("std");
        const core = @import("stwo_core");
        const Q = core.fields.qm31.QM31;
        const M = core.fields.m31.M31;
        const G = @import("composition_graph_recorder.zig");
        const S = G.Scalar;
        const F = @import("block_v5_ram_lanes_composition_v1.zig").Field;
        const Source = @import("blake3_execution_composition.zig").Source;
        const Whole = Traits.Proof;
        const Profile = @import("../block_v8_endpoint_recursive_profile_v1.zig").For(family);
        const Native = @import("block_v6_partitioned_composition_v1.zig");
        const Memory = @import("block_v7_window_memory_kernels_v1.zig");
        const MemoryCompiler = @import("block_v7_memory_joint_composition_mode_v1.zig").ForMode(true);
        const Lookup = @import("../../prover/block_v7_lookup_compact_algebra_v1.zig");
        const Endpoint = @import("../../prover/block_v8_ram_endpoint_component_v1.zig");
        const Provider = @import("../../prover/block_v8_endpoint_range_provider_v1.zig").Spec;
        const Relations = @import("../../prover/block_v7_memory_relations_v1.zig");
        const Placement = Traits.Placement;
        pub const Compiled = struct {
            allocator: std.mem.Allocator,
            circuit: G.Circuit,
            sources: []Source,
            pub fn deinit(self: *Compiled) void {
                self.circuit.deinit();
                self.allocator.free(self.sources);
                self.* = undefined;
            }
        };
        pub const Samples = struct {
            offsets: [][]usize,
            lengths: [][]usize,
            values: []S,
            pub fn init(a: std.mem.Allocator, b: *G.Builder, sources: *std.ArrayList(Source), profile: anytype) !Samples {
                const offsets = try a.alloc([]usize, profile.shape.columns.len);
                const lengths = try a.alloc([]usize, offsets.len);
                var count: usize = 0;
                for (profile.shape.layouts) |layout| count = try std.math.add(usize, count, layout.sampleCount());
                const values = try a.alloc(S, count);
                var cursor: usize = 0;
                var flat: usize = 0;
                for (offsets, lengths, profile.shape.columns) |*off, *len, columns| {
                    off.* = try a.alloc(usize, columns.len);
                    len.* = try a.alloc(usize, columns.len);
                    for (off.*, len.*) |*start, *n| {
                        start.* = cursor;
                        n.* = profile.shape.layouts[flat].sampleCount();
                        for (0..n.*) |_| {
                            values[cursor] = try input(b, a, sources, .{ .sample = @intCast(cursor) });
                            cursor += 1;
                        }
                        flat += 1;
                    }
                }
                if (cursor != values.len or flat != profile.shape.layouts.len) return error.InvalidEndpointCompositionSamples;
                return .{ .offsets = offsets, .lengths = lengths, .values = values };
            }
            pub fn at(self: Samples, tree: usize, column: usize, sample: usize) !S {
                if (tree >= self.offsets.len or column >= self.offsets[tree].len or sample >= self.lengths[tree][column]) return error.InvalidEndpointCompositionSamples;
                return self.values[self.offsets[tree][column] + sample];
            }
        };
        pub const Mapped = struct {
            samples: Samples,
            map: []const usize,
            fixed_start: usize,
            fixed_count: usize,
            pub fn at(self: Mapped, tree: usize, column: usize, sample: usize) !S {
                if (tree >= self.map.len or (tree == 0 and column >= self.fixed_count)) return error.InvalidEndpointCompositionPlacement;
                return self.samples.at(self.map[tree], if (tree == 0) self.fixed_start + column else column, sample);
            }
            pub fn offsets4(self: Mapped) ![4][]const usize {
                if (self.map.len != 3) return error.InvalidEndpointCompositionPlacement;
                return .{ self.samples.offsets[0][self.fixed_start..][0..self.fixed_count], self.samples.offsets[self.map[1]], self.samples.offsets[self.map[2]], &.{} };
            }
        };
        fn input(b: *G.Builder, a: std.mem.Allocator, sources: *std.ArrayList(Source), source: Source) !S {
            const value = try b.input();
            try sources.append(a, source);
            return value.value;
        }
        pub fn publicValues(a: std.mem.Allocator, profile: *const Profile.Owned) ![]Q {
            var out: std.ArrayList(Q) = .empty;
            errdefer out.deinit(a);
            // The common native recorder reserves clock operands for optional access
            // bridges. B8 has no access bridge and its frame is independently rejected.
            try out.appendNTimes(a, Q.zero(), 8);
            const c = profile.claims;
            for (c.native) |claim| try out.append(a, claim.sum);
            try out.appendSlice(a, &c.endpoint);
            try out.appendSlice(a, &c.endpoint_range);
            try out.append(a, c.program);
            try out.appendSlice(a, &c.lookup);
            if (!is_local) {
                const halt = try profile.scope.policy.window.?.nonhaltConstants();
                for (c.memory.ram) |ram| try out.appendSlice(a, &try Memory.ramPublic(ram.geometry, ram.sums, halt));
                try out.appendSlice(a, &c.memory.interval);
                try out.appendSlice(a, &c.memory.range16);
            }
            try @import("block_v8_endpoint_recursive_closure_v1.zig").For(family).appendPublic(a, profile, &out);
            return out.toOwnedSlice(a);
        }
        pub fn compile(a: std.mem.Allocator, profile: *const Profile.Owned) !Compiled {
            try profile.validate();
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const t = arena.allocator();
            var b = G.Builder.init(a);
            defer b.deinit();
            var sources: std.ArrayList(Source) = .empty;
            defer sources.deinit(a);
            var sample_sources: std.ArrayList(Source) = .empty;
            const samples = try Samples.init(t, &b, &sample_sources, profile);
            try sources.appendSlice(a, sample_sources.items);
            var draws: [53][2]S = undefined;
            for (&draws, 0..) |*pair, index| for (pair, 0..) |*v, half| {
                v.* = try input(&b, a, &sources, .{ .challenge = @intCast(2 * index + half) });
            };
            const values = try publicValues(t, profile);
            const public = try t.alloc(S, values.len);
            for (public, 0..) |*v, index| v.* = try input(&b, a, &sources, .{ .public_input = @intCast(index) });
            const random = try input(&b, a, &sources, .composition);
            const seed = try input(&b, a, &sources, .oods);
            try b.activate();
            defer if (b.active) b.deactivate();
            var accumulated = S.zero();
            var fixed_start: usize = 0;
            var at: usize = 0;
            var count: usize = 0;
            const context = profile.context;
            const local = context.local.?;
            const i = profile.statement.input;
            {
                const mapped = Mapped{ .samples = samples, .map = &Placement.native, .fixed_start = fixed_start, .fixed_count = local.native.fixed.len };
                const n = 8 + profile.claims.native.len;
                const projection_public = 8 + local.native.layout.slots.len;
                count += try Native.recordEquationsWithInterstitial(.{ .shape = i.shape, .external_retirements = 0, .register_custody_mode = 1, .projections = local.native.layout.slots, .slots = &.{}, .tree_count = 3, .direct_ram_clock_v3 = local.scope.native_profile.isDirect(), .projection_interaction_offset = 4 * local.native.clock_v3.len }, mapped, public[at..][0..projection_public], draws[0..47].*, flattenWord(draws), random, G.pointFromSeed(seed), profile.shape.mask_log, &accumulated, GuardRecorder{ .guards = local.native.guards, .gaps = local.native.clock_v3, .gap_sums = public[at + projection_public ..][0..local.native.clock_v3.len], .range16 = symbolicRelation(1, draws[51]) });
                at += n;
                fixed_start += mapped.fixed_count;
            }
            {
                const mapped = Mapped{ .samples = samples, .map = &Placement.endpoints, .fixed_start = fixed_start, .fixed_count = Endpoint.Spec.FIXED_COUNT };
                count += try endpoint(mapped, local.endpoint_log, profile.shape.mask_log, local.scope.policy, draws, public[at..][0..Endpoint.PLANES].*, random, seed, &accumulated);
                at += Endpoint.PLANES;
                fixed_start += mapped.fixed_count;
            }
            {
                const mapped = Mapped{ .samples = samples, .map = &Placement.endpoint_range, .fixed_start = fixed_start, .fixed_count = Provider.FIXED_COUNT };
                try provider(mapped, profile.shape.mask_log, draws, public[at..][0..Provider.PLANES].*, random, seed, &accumulated);
                count += Provider.CONSTRAINT_COUNT;
                at += Provider.PLANES;
                fixed_start += mapped.fixed_count;
            }
            {
                const mapped = Mapped{ .samples = samples, .map = &Placement.program, .fixed_start = fixed_start, .fixed_count = context.program.?.fixed_columns.len };
                try program(t, profile, mapped, public[at], draws[0..47].*, random, seed, profile.shape.mask_log, &accumulated);
                for (context.program.?.verifiers) |component| count += component.nConstraints();
                at += 1;
                fixed_start += mapped.fixed_count;
            }
            {
                const mapped = Mapped{ .samples = samples, .map = &Placement.lookup, .fixed_start = fixed_start, .fixed_count = context.lookup.?.fixed_columns.len };
                const offsets = try mapped.offsets4();
                inline for (0..6) |kind_index| {
                    const kind: Lookup.Schema.Kind = @enumFromInt(kind_index);
                    const domain = @field(@import("../../air/lang/relation.zig").Domain, @tagName(kind));
                    inline for (.{ Lookup.Mode.dense, Lookup.Mode.sparse }) |mode| if (i.lookup_layout.parts[kind_index].mode == mode) try @import("block_v7_lookup_compact_composition_v1.zig").recordPart(kind, mode, profile.shape.mask_log, i.lookup_layout.parts[kind_index], offsets, samples.values, public[at + kind_index], draws[@intFromEnum(domain)], random, seed, &accumulated);
                }
                for (context.lookup.?.verifiers) |component| count += component.nConstraints();
                at += 6;
                fixed_start += mapped.fixed_count;
            }
            if (!is_local) {
                {
                    const mapped = Mapped{ .samples = samples, .map = &Placement.memory, .fixed_start = fixed_start, .fixed_count = context.memory.?.fixed_columns.len };
                    const offsets = try mapped.offsets4();
                    var relations: [10]S = undefined;
                    for (Memory.relation_pair_indices, 0..) |pair, index| @memcpy(relations[2 * index ..][0..2], &draws[pair]);
                    for (context.memory.?.layout.parts) |part| switch (part.family) {
                        inline else => |kernel_family| {
                            const f = @field(Memory.Family, @tagName(kernel_family));
                            const n = comptime Memory.publicCount(f);
                            try MemoryCompiler.recordPart(f, profile.shape.mask_log, part, offsets, samples.values, public[at..][0..n].*, relations, random, seed, &accumulated);
                            at += n;
                            count += Memory.Spec(f).CONSTRAINT_COUNT;
                        },
                    };
                    fixed_start += mapped.fixed_count;
                }
            }
            if (count != profile.constraint_count) return error.InvalidEndpointCompositionConstraintCount;
            if (fixed_start != profile.shape.columns[0].len) return error.InvalidEndpointCompositionPublicFrame;
            const chunks = try t.alloc(S, core.verifier_types.compositionChunkCount(profile.shape.split) orelse return error.InvalidEndpointCompositionGeometry);
            for (chunks, 0..) |*chunk, index| {
                var limbs: [4]S = undefined;
                for (&limbs, 0..) |*limb, half| limb.* = try samples.at(Profile.TRACE_TREES, 4 * index + half, 0);
                chunk.* = G.fromPartialEvals(limbs);
            }
            try b.constrainZero((try G.reconstructSplitComposition(chunks, G.pointFromSeed(seed), profile.shape.composition_log, profile.shape.split)).sub(accumulated));
            try @import("block_v8_endpoint_recursive_closure_v1.zig").For(family).record(t, &b, profile, public[0..at], public[at..], draws);
            b.deactivate();
            var circuit = try b.finish();
            errdefer circuit.deinit();
            return .{ .allocator = a, .circuit = circuit, .sources = try sources.toOwnedSlice(a) };
        }
        pub const GuardRecorder = struct {
            guards: []const @import("../../prover/block_v8_native_halt_component_v1.zig").Component,
            gaps: []const @import("../../prover/block_v8_ram_clock_v3_component.zig").Component,
            gap_sums: []const S,
            range16: Relations.Relation(F, 1),
            pub fn record(self: @This(), samples: anytype, random: S, point: core.circle.CirclePoint(S), mask_log: u32, accumulated: *S) !usize {
                var cache: G.DenominatorCache = @splat(null);
                var count: usize = 0;
                for (self.guards) |*guard| {
                    var row: [50]F = undefined;
                    for (&row, 0..) |*value, index| value.* = .{ .symbol = try samples.at(1, guard.main_offset + index, 0) };
                    const aux = [2]F{ .{ .symbol = try samples.at(1, guard.aux_offset, 0) }, .{ .symbol = try samples.at(1, guard.aux_offset + 1, 0) } };
                    var buffer: [@import("../../prover/block_v8_native_halt_policy_v1.zig").CONSTRAINT_COUNT]F = undefined;
                    const equations = try guard.evaluate(F, &row, .{ .symbol = try samples.at(0, guard.active_column, 0) }, aux, &buffer);
                    const inverse = try G.quotientDenominator(guard.log_size, mask_log, point, &cache);
                    for (equations) |value| G.accumulate(accumulated, random, value.symbol, inverse);
                    count += equations.len;
                }
                const Gap = @import("../../prover/block_v8_ram_clock_v3_component.zig");
                if (self.gaps.len != self.gap_sums.len) return error.InvalidEndpointGapClaims;
                for (self.gaps, self.gap_sums) |gap, sum| {
                    var row: [9]F = undefined;
                    for (Gap.native_columns, row[0..6]) |column, *value| value.* = .{ .symbol = try samples.at(1, gap.main_offset + column, 0) };
                    for (row[6..9], 0..) |*value, column| value.* = .{ .symbol = try samples.at(1, gap.aux_offset + column, 0) };
                    var current: [4]F = undefined;
                    var previous: [4]F = undefined;
                    for (&current, &previous, 0..) |*value, *prior, column| {
                        value.* = .{ .symbol = try samples.at(2, gap.interaction_offset + column, 0) };
                        prior.* = .{ .symbol = try samples.at(2, gap.interaction_offset + column, 1) };
                    }
                    const normalized = F{ .symbol = sum.mul(S.fromBase(try M.fromCanonical(@as(u32, 1) << @intCast(gap.log_size)).inv())) };
                    const equations = Gap.equations(F, self.range16, .{ .symbol = try samples.at(0, gap.active_column, 0) }, row, current, previous, normalized);
                    const inverse = try G.quotientDenominator(gap.log_size, mask_log, point, &cache);
                    for (equations) |value| G.accumulate(accumulated, random, value.symbol, inverse);
                    count += equations.len;
                }
                return count;
            }
        };
        pub fn flattenWord(draws: [53][2]S) [10]S {
            var word: [10]S = undefined;
            for (draws[47..52], 0..) |pair, index| @memcpy(word[2 * index ..][0..2], &pair);
            return word;
        }
        fn wrap(comptime n: usize, values: [n]S) [n]F {
            var result: [n]F = undefined;
            for (&result, values) |*v, symbol| v.* = .{ .symbol = symbol };
            return result;
        }
        pub fn symbolicRelation(comptime arity: usize, pair: [2]S) Relations.Relation(F, arity) {
            var out: Relations.Relation(F, arity) = .{ .z = .{ .symbol = pair[0] }, .powers = undefined };
            var power = F.one();
            for (&out.powers) |*p| {
                p.* = power;
                power = power.mul(.{ .symbol = pair[1] });
            }
            return out;
        }
        fn memoryChallenges(draws: [53][2]S) Relations.Challenges(F) {
            return .{ .transition = symbolicRelation(11, draws[47]), .link = symbolicRelation(13, draws[48]), .interval = symbolicRelation(6, draws[52]), .range16 = symbolicRelation(1, draws[51]) };
        }
        pub fn endpoint(samples: Mapped, log: u32, mask_log: u32, policy: @import("../../prover/block_v8_ram_endpoint_kernel_v1.zig").Policy, draws: [53][2]S, sums: [Endpoint.PLANES]S, random: S, seed: S, accumulated: *S) !usize {
            const Spec = Endpoint.Spec;
            var fixed: [Spec.FIXED_COUNT]S = undefined;
            var row: [Spec.MAIN_COUNT]S = undefined;
            var prior: [Spec.MAIN_COUNT]S = @splat(S.zero());
            var current: [Spec.INTERACTION_COUNT]S = undefined;
            var previous: [Spec.INTERACTION_COUNT]S = undefined;
            for (&fixed, 0..) |*v, col| v.* = try samples.at(0, col, 0);
            for (&row, &prior, 0..) |*v, *p, col| {
                v.* = try samples.at(1, col, 0);
                if (Spec.PREVIOUS_MAIN_MASK[col]) p.* = try samples.at(1, col, 1);
            }
            for (&current, &previous, 0..) |*v, *p, col| {
                v.* = try samples.at(2, col, 0);
                p.* = try samples.at(2, col, 1);
            }
            const shift = S.fromBase(try M.fromCanonical(@as(u32, 1) << @intCast(log)).inv());
            var norm: [Endpoint.PLANES]S = undefined;
            for (&norm, sums) |*v, sum| v.* = sum.mul(shift);
            const ch: Endpoint.Challenges(F) = .{ .native = symbolicRelation(7, draws[@intFromEnum(@import("../../air/lang/relation.zig").Domain.memory_access)]), .transition = symbolicRelation(11, draws[47]), .range16 = symbolicRelation(1, draws[51]), .bytes = symbolicRelation(2, draws[@intFromEnum(@import("../../air/lang/relation.zig").Domain.range_check_8_8)]) };
            const eq = Endpoint.equations(F, policy, ch, wrap(fixed.len, fixed), wrap(row.len, row), wrap(prior.len, prior), wrap(current.len, current), wrap(previous.len, previous), wrap(norm.len, norm));
            var cache: G.DenominatorCache = @splat(null);
            const denominator = try G.quotientDenominator(log, mask_log, G.pointFromSeed(seed), &cache);
            for (eq) |value| G.accumulate(accumulated, random, value.symbol, denominator);
            return eq.len;
        }
        pub fn provider(samples: Mapped, mask_log: u32, draws: [53][2]S, sums: [Provider.PLANES]S, random: S, seed: S, accumulated: *S) !void {
            var fixed: [Provider.FIXED_COUNT]S = undefined;
            var row: [Provider.MAIN_COUNT]S = undefined;
            var current: [Provider.INTERACTION_COUNT]S = undefined;
            var previous: [Provider.INTERACTION_COUNT]S = undefined;
            for (&fixed, 0..) |*v, col| v.* = try samples.at(0, col, 0);
            for (&row, 0..) |*v, col| v.* = try samples.at(1, col, 0);
            for (&current, &previous, 0..) |*v, *p, col| {
                v.* = try samples.at(2, col, 0);
                p.* = try samples.at(2, col, 1);
            }
            var norm: [Provider.PLANES]S = undefined;
            const shift = S.fromBase(try M.fromCanonical(65536).inv());
            for (&norm, sums) |*v, sum| v.* = sum.mul(shift);
            const eq = Provider.equations(F, wrap(fixed.len, fixed), wrap(row.len, row), wrap(current.len, current), wrap(previous.len, previous), memoryChallenges(draws), wrap(norm.len, norm));
            var cache: G.DenominatorCache = @splat(null);
            const denominator = try G.quotientDenominator(16, mask_log, G.pointFromSeed(seed), &cache);
            for (eq) |value| G.accumulate(accumulated, random, value.symbol, denominator);
        }
        pub fn program(a: std.mem.Allocator, profile: anytype, samples: Mapped, claim: S, draws: [47][2]S, random: S, seed: S, mask_log: u32, accumulated: *S) !void {
            const program_log = profile.context.program.?.logs[0][0];
            const Original = @import("../../prover/block_v5_program_table_proof_v1.zig");
            var definition = try Original.Air.build(a);
            defer definition.deinit();
            const relation = try @import("universal_relation_binding.zig").Binding(Original.Air).authenticate(&definition);
            const drawn = try profile.scope.epoch.draw(a);
            const manifest = Original.Roster.Manifest{ .log_sizes = .{program_log} };
            const component = try Original.Roster.Component(Original.Air).init(&definition, relation, &manifest, .program, program_log, .{}, &drawn.word.universal_prefix, Q.zero());
            var fixed: [6]S = undefined;
            var current: [4]S = undefined;
            var previous: [4]S = undefined;
            for (&fixed, 0..) |*v, index| v.* = try samples.at(0, index, 0);
            for (&current, &previous, 0..) |*v, *p, index| {
                v.* = try samples.at(2, index, 1);
                p.* = try samples.at(2, index, 0);
            }
            const challenges = try G.ChallengeSet.init(draws);
            try @import("block_v5_program_table_composition_v1.zig").accumulate(&component, fixed, current, previous, claim, &challenges, random, G.pointFromSeed(seed), mask_log, accumulated);
        }
        pub fn prepare(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Whole.VerifiedCapture) !@import("blake3_execution_composition.zig").Prepared {
            try profile.requireCapture(capture);
            var compiled = try compile(a, profile);
            var owns_graph = true;
            defer if (owns_graph) compiled.deinit();
            var arena = std.heap.ArenaAllocator.init(a);
            errdefer arena.deinit();
            const t = arena.allocator();
            const public = try publicValues(t, profile);
            const draws = try @import("block_v7_memory_joint_inputs_mode_v1.zig").ForMode(true).challenges(t, profile.scope.epoch);
            const inputs = try t.alloc(Q, compiled.sources.len);
            for (inputs, compiled.sources) |*value, source| value.* = switch (source) {
                .sample => |index| if (index < capture.proof.sampled_values.len) capture.proof.sampled_values[index] else return error.InvalidEndpointCompositionSamples,
                .public_input => |index| if (index < public.len) public[index] else return error.InvalidEndpointCompositionPublicFrame,
                .challenge => |index| if (index < draws.len) draws[index] else return error.InvalidEndpointCompositionChallenge,
                .composition => capture.proof.composition_randomness,
                .oods => capture.proof.oods_seed,
                else => return error.InvalidEndpointCompositionSource,
            };
            const values = try t.alloc(Q, compiled.circuit.nodes.len);
            try compiled.circuit.evaluateInto(inputs, values);
            const sources = try t.dupe(Source, compiled.sources);
            var result = @import("blake3_execution_composition.zig").Prepared{ .arena = arena, .circuit = compiled.circuit, .inputs = inputs, .sources = sources, .values = values, .key_id = profile.seal, .capture_seal = capture.final_channel.digestBytes(), .seal = undefined };
            result.seal = result.identity();
            a.free(compiled.sources);
            owns_graph = false;
            return result;
        }
    };
}
