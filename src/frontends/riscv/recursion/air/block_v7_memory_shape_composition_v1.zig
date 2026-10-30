//! Metadata-only compiler for v7 original memory verifier equations. No proof
//! values, source receipts, endpoint values or transcript execution enter setup.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const G = @import("composition_graph_recorder.zig");
const S = G.Scalar;
const K = @import("block_v7_memory_composition_v1.zig");
const Source = @import("blake3_execution_composition.zig").Source;
pub const RELATION_COUNT = 53;
pub fn For(comptime family: K.Family) type {
    const Spec = K.Spec(family);
    return struct {
        pub const Shape = @import("../block_v5_word_recursive_shape_v1.zig").ForSpec(Spec).Shape;
        pub const Compiled = struct {
            allocator: std.mem.Allocator,
            budget: ?*Budget,
            circuit: G.Circuit,
            sources: []Source,
            shape_id: [32]u8,
            seal: [32]u8,
            pub const fixed_setup_only = true;
            pub const complete_family_setup = false;
            pub fn identity(self: *const @This()) [32]u8 {
                var ch = core.proof_suites.Blake3.Channel{};
                ch.mixU32s(&.{ 0x42374d43, 1, @intFromEnum(family), RELATION_COUNT, @intCast(K.publicCount(family)) });
                ch.mixRoot(self.shape_id);
                ch.mixRoot(self.circuit.identity_digest);
                ch.mixU64(self.sources.len);
                for (self.sources) |source| ch.mixU32s(&.{ @intFromEnum(std.meta.activeTag(source)), switch (source) {
                    .sample, .claim, .challenge, .public_input, .packed_public_input => |ordinal| ordinal,
                    .composition, .oods => 0,
                } });
                return ch.digestBytes();
            }
            pub fn validateAgainst(self: *const @This(), shape: *const Shape) !void {
                try self.circuit.validate();
                if (self.sources.len != self.circuit.input_count or !std.meta.eql(self.shape_id, shape.seal) or !std.meta.eql(self.seal, self.identity())) return error.MutatedV7MemoryComposition;
                var expected = try compile(self.allocator, shape);
                defer expected.deinit();
                if (!std.meta.eql(self.seal, expected.seal)) return error.UntrustedV7MemoryComposition;
            }
            pub fn deinit(self: *@This()) void {
                const a = self.allocator;
                const lease = self.budget;
                self.circuit.deinit();
                a.free(self.sources);
                self.* = undefined;
                if (lease) |owner| owner.destroy();
            }
        };
        pub fn compile(a: std.mem.Allocator, shape: *const Shape) !Compiled {
            try shape.validateAgainst(shape.row_log, shape.config);
            if ((family == .range16 and shape.row_log != 16) or (family == .terminal and shape.row_log != 4)) return error.InvalidV7ProviderGeometry;
            const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
            errdefer if (lease) |owner| owner.destroy();
            var b = G.Builder.init(a);
            defer b.deinit();
            var sources: std.ArrayList(Source) = .empty;
            defer sources.deinit(a);
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const samples = try arena.allocator().alloc(S, try shape.sampleCount());
            var offsets: [4][@max(Spec.FIXED_COUNT, Spec.MAIN_COUNT, Spec.INTERACTION_COUNT, 16)]usize = undefined;
            var cursor: usize = 0;
            var column_cursor: usize = 0;
            for (Shape.counts, 0..) |width, tree| for (0..width) |column| {
                offsets[tree][column] = cursor;
                for (0..shape.layouts[column_cursor].sampleCount()) |_| {
                    samples[cursor] = try input(&b, a, &sources, .{ .sample = @intCast(cursor) });
                    cursor += 1;
                }
                column_cursor += 1;
            };
            var relation: [8]S = undefined;
            for (0..2 * RELATION_COUNT) |draw| {
                const symbol = try input(&b, a, &sources, .{ .challenge = @intCast(draw) });
                for (K.relation_pair_indices, 0..) |pair, index| {
                    if (draw == 2 * pair) relation[2 * index] = symbol;
                    if (draw == 2 * pair + 1) relation[2 * index + 1] = symbol;
                }
            }
            const randomness = try input(&b, a, &sources, .composition);
            const seed = try input(&b, a, &sources, .oods);
            var public: [K.publicCount(family)]S = undefined;
            for (&public, 0..) |*p, i| p.* = try input(&b, a, &sources, .{ .public_input = @intCast(i) });
            var fixed: [Spec.FIXED_COUNT]S = undefined;
            var main: [Spec.MAIN_COUNT]S = undefined;
            var prior: [Spec.MAIN_COUNT]S = @splat(S.zero());
            var current: [Spec.INTERACTION_COUNT]S = undefined;
            var previous: [Spec.INTERACTION_COUNT]S = undefined;
            for (&fixed, 0..) |*v, i| v.* = samples[offsets[0][i]];
            for (&main, 0..) |*v, i| {
                v.* = samples[offsets[1][i]];
                if (Spec.PREVIOUS_MAIN_MASK[i]) prior[i] = samples[offsets[1][i] + 1];
            }
            for (&current, &previous, 0..) |*v, *p, i| {
                v.* = samples[offsets[2][i]];
                p.* = samples[offsets[2][i] + 1];
            }
            try b.activate();
            var active = true;
            defer if (active) b.deactivate();
            var chunks: [4]S = undefined;
            for (&chunks, 0..) |*chunk, i| {
                var parts: [4]S = undefined;
                for (&parts, 0..) |*part, limb| part.* = samples[offsets[3][4 * i + limb]];
                chunk.* = G.fromPartialEvals(parts);
            }
            try K.recordEquation(family, &b, shape.row_log, fixed, main, prior, current, previous, public, relation, randomness, seed, chunks);
            b.deactivate();
            active = false;
            var circuit = try b.finish();
            errdefer circuit.deinit();
            const owned = try sources.toOwnedSlice(a);
            var result = Compiled{ .allocator = a, .budget = lease, .circuit = circuit, .sources = owned, .shape_id = shape.seal, .seal = undefined };
            result.seal = result.identity();
            return result;
        }
    };
}
fn input(b: *G.Builder, a: std.mem.Allocator, sources: *std.ArrayList(Source), source: Source) !S {
    const symbol = try b.input();
    try sources.append(a, source);
    return symbol.value;
}
