//! One composition equation for the heterogeneous v7 memory proof. All parts
//! use original equation authority and a shared Horner accumulator. No captured
//! OODS/public values are used to select code or construct fixed constants.
//! Finite protocol variants share implementation; window mode is a distinct key.
pub fn ForMode(comptime window: bool) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
        const Profile = @import("../block_v7_memory_joint_fixed_profile_v1.zig").ForMode(window);
        const Layout = if (window) @import("../../prover/block_v7_window_memory_joint_layout_v1.zig") else @import("../../prover/block_v7_memory_joint_layout_v1.zig");
        const G = @import("composition_graph_recorder.zig");
        const S = G.Scalar;
        const K = if (window) @import("block_v7_window_memory_kernels_v1.zig") else @import("block_v7_memory_composition_v1.zig");
        const RELATION_INPUTS: usize = if (window) 10 else 8;
        const Source = @import("blake3_execution_composition.zig").Source;
        pub const RELATION_COUNT = 53;
        pub const Compiled = struct {
            allocator: std.mem.Allocator,
            budget: ?*Budget,
            circuit: G.Circuit,
            sources: []Source,
            shape_id: [32]u8,
            seal: [32]u8,
            pub const fixed_setup_only = true;
            pub const complete_family_setup = false;
            pub fn identity(self: *const Compiled) [32]u8 {
                var ch = core.proof_suites.Blake3.Channel{};
                ch.mixU32s(&.{ if (window) 0x42375743 else 0x42374a43, 1, RELATION_COUNT });
                ch.mixRoot(self.shape_id);
                ch.mixRoot(self.circuit.identity_digest);
                ch.mixU64(self.sources.len);
                for (self.sources) |source| ch.mixU32s(&.{ @intFromEnum(std.meta.activeTag(source)), switch (source) {
                    .sample, .claim, .challenge, .public_input, .packed_public_input => |ordinal| ordinal,
                    .composition, .oods => 0,
                } });
                return ch.digestBytes();
            }
            pub fn validateAgainst(self: *const Compiled, profile: *const Profile.Owned) !void {
                try self.circuit.validate();
                if (self.sources.len != self.circuit.input_count or !std.meta.eql(self.shape_id, profile.seal) or !std.meta.eql(self.seal, self.identity())) return error.MutatedJointMemoryComposition;
                var expected = try compile(self.allocator, profile);
                defer expected.deinit();
                if (!std.meta.eql(self.seal, expected.seal)) return error.UntrustedJointMemoryComposition;
            }
            pub fn deinit(self: *Compiled) void {
                const a = self.allocator;
                const lease = self.budget;
                self.circuit.deinit();
                a.free(self.sources);
                self.* = undefined;
                if (lease) |owner| owner.destroy();
            }
        };
        pub fn compile(a: std.mem.Allocator, profile: *const Profile.Owned) !Compiled {
            try profile.validateAgainst(profile.input, profile.limits);
            if (profile.columns.len != 4 or profile.split != 2 or profile.composition_log != profile.max_log + 2 or profile.columns[3].len != 16) return error.InvalidJointCompositionShape;
            const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
            errdefer if (lease) |owner| owner.destroy();
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            var b = G.Builder.init(a);
            defer b.deinit();
            var sources: std.ArrayList(Source) = .empty;
            defer sources.deinit(a);
            const samples = try scratch.alloc(S, try profile.sampleCount());
            var offsets: [4][]usize = undefined;
            var cursor: usize = 0;
            var col: usize = 0;
            for (&offsets, profile.columns) |*tree, logs| {
                tree.* = try scratch.alloc(usize, logs.len);
                for (tree.*) |*offset| {
                    offset.* = cursor;
                    for (0..profile.layouts[col].sampleCount()) |_| {
                        samples[cursor] = try input(&b, a, &sources, .{ .sample = @intCast(cursor) });
                        cursor += 1;
                    }
                    col += 1;
                }
            }
            if (cursor != samples.len or col != profile.layouts.len) return error.InvalidJointCompositionSamples;
            var relation: [RELATION_INPUTS]S = undefined;
            for (0..2 * RELATION_COUNT) |draw| {
                const symbol = try input(&b, a, &sources, .{ .challenge = @intCast(draw) });
                for (K.relation_pair_indices, 0..) |pair, i| {
                    if (draw == 2 * pair) relation[2 * i] = symbol;
                    if (draw == 2 * pair + 1) relation[2 * i + 1] = symbol;
                }
            }
            const random = try input(&b, a, &sources, .composition);
            const seed = try input(&b, a, &sources, .oods);
            const public = try scratch.alloc(S, try profile.publicCount());
            for (public, 0..) |*symbol, i| symbol.* = try input(&b, a, &sources, .{ .public_input = @intCast(i) });
            try b.activate();
            var active = true;
            defer if (active) b.deactivate();
            var accumulated = S.zero();
            var public_offset: usize = 0;
            for (profile.layout.parts) |part| switch (part.family) {
                inline else => |family| {
                    const kernel_family = @field(K.Family, @tagName(family));
                    const count = comptime K.publicCount(kernel_family);
                    if (public_offset > public.len or count > public.len - public_offset) return error.InvalidJointCompositionPublic;
                    try recordPart(kernel_family, profile.max_log, part, offsets, samples, public[public_offset..][0..count].*, relation, random, seed, &accumulated);
                    public_offset += count;
                },
            };
            if (public_offset != public.len) return error.InvalidJointCompositionPublic;
            var chunks: [4]S = undefined;
            for (&chunks, 0..) |*chunk, i| {
                var partials: [4]S = undefined;
                for (&partials, 0..) |*part, j| part.* = samples[offsets[3][4 * i + j]];
                chunk.* = G.fromPartialEvals(partials);
            }
            const reconstructed = try G.reconstructSplitComposition(&chunks, G.pointFromSeed(seed), profile.composition_log, profile.split);
            try b.constrainZero(reconstructed.sub(accumulated));
            b.deactivate();
            active = false;
            var circuit = try b.finish();
            errdefer circuit.deinit();
            const owned = try sources.toOwnedSlice(a);
            var result = Compiled{ .allocator = a, .budget = lease, .circuit = circuit, .sources = owned, .shape_id = profile.seal, .seal = undefined };
            result.seal = result.identity();
            return result;
        }
        pub fn recordPart(comptime family: K.Family, max_log: u32, part: Layout.Part, offsets: [4][]const usize, samples: []const S, public: [K.publicCount(family)]S, relation: [RELATION_INPUTS]S, random: S, seed: S, acc: *S) !void {
            const Spec = K.Spec(family);
            if (!std.meta.eql(part.width, [3]u32{ Spec.FIXED_COUNT, Spec.MAIN_COUNT, Spec.INTERACTION_COUNT }) or part.claim_count != K.planes(family)) return error.InvalidJointCompositionPlacement;
            var fixed: [Spec.FIXED_COUNT]S = undefined;
            var main: [Spec.MAIN_COUNT]S = undefined;
            var prior: [Spec.MAIN_COUNT]S = @splat(S.zero());
            var current: [Spec.INTERACTION_COUNT]S = undefined;
            var previous: [Spec.INTERACTION_COUNT]S = undefined;
            for (&fixed, 0..) |*v, i| v.* = samples[offsets[0][part.offset[0] + i]];
            for (&main, 0..) |*v, i| {
                const index = offsets[1][part.offset[1] + i];
                v.* = samples[index];
                if (Spec.PREVIOUS_MAIN_MASK[i]) prior[i] = samples[index + 1];
            }
            for (&current, &previous, 0..) |*v, *p, i| {
                const index = offsets[2][part.offset[2] + i];
                v.* = samples[index];
                p.* = samples[index + 1];
            }
            try K.accumulate(family, part.log, max_log, fixed, main, prior, current, previous, public, relation, random, seed, acc);
        }
        fn input(b: *G.Builder, a: std.mem.Allocator, sources: *std.ArrayList(Source), source: Source) !S {
            const symbol = try b.input();
            try sources.append(a, source);
            return symbol.value;
        }
    };
}
