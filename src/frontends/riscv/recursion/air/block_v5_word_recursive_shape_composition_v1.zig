//! Capture-free lowering of the ORIGINAL RAM/range verifier equation kernels.
//! Inputs/sources have exact native sample,52-pair draw and public-claim order.
//! No input values, transcript execution, successful verification or proof token.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const R = @import("composition_graph_recorder.zig");
const S = R.Scalar;
const Original = @import("blake3_execution_composition.zig");
const Ram = @import("block_v5_ram_lanes_composition_v1.zig");
const Range = @import("block_v5_range16_composition_v1.zig");
pub const Family = enum { ram_lanes, range16 };
pub fn ForFamily(comptime family: Family) type {
    const Spec = if (family == .ram_lanes) @import("../../prover/block_v5_ram_lanes_component_v1.zig").Spec else @import("../../prover/block_v5_range16_component_v1.zig").Spec;
    const Shape = @import("../block_v5_word_recursive_shape_v1.zig").ForSpec(Spec).Shape;
    const Kernel = if (family == .ram_lanes) Ram else Range;
    return struct {
        pub const PUBLIC_COUNT: usize = if (family == .ram_lanes) Ram.PUBLIC_COUNT else 2;
        pub const Compiled = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            budget: ?*Budget,
            circuit: R.Circuit,
            sources: []Original.Source,
            shape_id: [32]u8,
            seal: [32]u8,
            pub const fixed_setup_only = true;
            pub fn identity(self: *const Self) [32]u8 {
                var channel = core.channel.blake3.Channel{};
                channel.mixU32s(&.{ 0x42355743, 1, @intFromEnum(family), Kernel.RELATION_COUNT, PUBLIC_COUNT });
                channel.mixRoot(self.shape_id);
                channel.mixRoot(self.circuit.identity_digest);
                channel.mixU64(self.sources.len);
                for (self.sources) |source| channel.mixU32s(&.{ @intFromEnum(std.meta.activeTag(source)), switch (source) {
                    .sample, .claim, .challenge, .public_input, .packed_public_input => |ordinal| ordinal,
                    .composition, .oods => 0,
                } });
                return channel.digestBytes();
            }
            /// Re-emit the original algebra with independently admitted shape;
            /// merely recomputing a mutable circuit/source seal is insufficient.
            pub fn validateAgainst(self: *const Self, shape: *const Shape) !void {
                try self.circuit.validate();
                if (self.sources.len != self.circuit.input_count or !std.meta.eql(self.shape_id, shape.seal) or !std.meta.eql(self.seal, self.identity())) return error.MutatedWordShapeComposition;
                var independent = try compile(self.allocator, shape);
                defer independent.deinit();
                if (!std.meta.eql(self.seal, independent.seal)) return error.UntrustedWordShapeComposition;
            }
            pub fn deinit(self: *Self) void {
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
            if (family == .range16 and shape.row_log != @import("../../prover/block_v5_range16_v1.zig").TABLE_LOG) return error.InvalidRangeShapeComposition;
            const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
            errdefer if (lease) |owner| owner.destroy();
            var builder = R.Builder.init(a);
            defer builder.deinit();
            var sources: std.ArrayList(Original.Source) = .empty;
            defer sources.deinit(a);
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const temp = arena.allocator();
            const samples = try temp.alloc(S, try shape.sampleCount());
            var offsets: [4][Spec.INTERACTION_COUNT]usize = undefined;
            // RAM fixed/main/comp counts all fit92; range comp/fixed fit8.
            var cursor: usize = 0;
            var column_cursor: usize = 0;
            for (Shape.counts, 0..) |width, tree| {
                for (0..width) |column| {
                    offsets[tree][column] = cursor;
                    for (0..shape.layouts[column_cursor].sampleCount()) |_| {
                        samples[cursor] = try input(&builder, a, &sources, .{ .sample = @intCast(cursor) });
                        cursor += 1;
                    }
                    column_cursor += 1;
                }
            }
            var extra: [10]S = undefined;
            for (0..2 * Kernel.RELATION_COUNT) |draw| {
                const symbol = try input(&builder, a, &sources, .{ .challenge = @intCast(draw) });
                if (draw >= 2 * (Kernel.RELATION_COUNT - 5)) extra[draw - 2 * (Kernel.RELATION_COUNT - 5)] = symbol;
            }
            const randomness = try input(&builder, a, &sources, .composition);
            const seed = try input(&builder, a, &sources, .oods);
            var public: [PUBLIC_COUNT]S = undefined;
            for (&public, 0..) |*symbol, ordinal| symbol.* = try input(&builder, a, &sources, .{ .public_input = @intCast(ordinal) });
            var fixed: [Spec.FIXED_COUNT]S = undefined;
            for (&fixed, 0..) |*symbol, column| symbol.* = samples[offsets[0][column]];
            var main: [Spec.MAIN_COUNT]S = undefined;
            var prior_main: [Spec.MAIN_COUNT]S = @splat(S.zero());
            for (&main, 0..) |*symbol, column| {
                symbol.* = samples[offsets[1][column]];
                if (Spec.PREVIOUS_MAIN_MASK[column]) prior_main[column] = samples[offsets[1][column] + 1];
            }
            var current: [Spec.INTERACTION_COUNT]S = undefined;
            var previous: [Spec.INTERACTION_COUNT]S = undefined;
            for (&current, &previous, 0..) |*now, *prior, column| {
                now.* = samples[offsets[2][column]];
                prior.* = samples[offsets[2][column] + 1];
            }
            try builder.activate();
            var active = true;
            defer if (active) builder.deactivate();
            var chunks: [@as(usize, 1) << Spec.EXPANSION_BITS]S = undefined;
            for (&chunks, 0..) |*chunk, ordinal| {
                var parts: [4]S = undefined;
                for (&parts, 0..) |*part, coordinate| part.* = samples[offsets[3][4 * ordinal + coordinate]];
                chunk.* = R.fromPartialEvals(parts);
            }
            if (family == .ram_lanes) {
                try Ram.recordEquation(&builder, shape.row_log, fixed, main, prior_main, current, previous, public, extra, randomness, seed, chunks);
            } else {
                try Range.recordEquation(&builder, fixed, main, current, previous, public[0], public[1], extra[8], randomness, seed, chunks);
            }
            builder.deactivate();
            active = false;
            var circuit = try builder.finish();
            errdefer circuit.deinit();
            const owned_sources = try sources.toOwnedSlice(a);
            var result = Compiled{ .allocator = a, .budget = lease, .circuit = circuit, .sources = owned_sources, .shape_id = shape.seal, .seal = undefined };
            result.seal = result.identity();
            return result;
        }
    };
}
fn input(builder: *R.Builder, a: std.mem.Allocator, sources: *std.ArrayList(Original.Source), source: Original.Source) !S {
    const symbol = try builder.input();
    try sources.append(a, source);
    return symbol.value;
}
