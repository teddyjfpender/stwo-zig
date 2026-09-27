//! Exact original PAGE quotient compiler, no capture/frame/witness evaluation.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const R = @import("composition_graph_recorder.zig");
const Equation = @import("block_v5_memory_source_page_record_v1.zig");
const Masks = @import("block_v5_memory_source_page_shape_masks_v1.zig");
const Layout = @import("../sample_point_layout.zig");
const Semantic = @import("../../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Original = @import("blake3_execution_composition.zig");
const RELATION_COUNT = @import("universal_challenges.zig").RELATION_COUNT;
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Shape = @import("../block_v5_memory_source_page_recursive_shape_v1.zig").ForKind(kind);
    const Claims = Equation.ClaimSymbols(kind);
    const PUBLIC_COUNT: usize = blk: {
        var n: usize = 0;
        for (std.meta.fields(Claims)) |field| n += @typeInfo(field.type).array.len;
        break :blk n;
    };
    return struct {
        pub const Compiled = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            budget: ?*Budget,
            circuit: R.Circuit,
            sources: []Original.Source,
            template_id: [32]u8,
            graph_id: [32]u8,
            seal: [32]u8,
            pub const fixed_setup_only = true;
            pub fn identity(self: *const Self) [32]u8 {
                var channel = core.channel.blake3.Channel{};
                channel.mixU32s(&.{ 0x50474353, 1, @intFromEnum(kind), RELATION_COUNT, PUBLIC_COUNT });
                channel.mixRoot(self.template_id);
                channel.mixRoot(self.graph_id);
                channel.mixRoot(self.circuit.identity_digest);
                channel.mixU64(self.sources.len);
                for (self.sources) |source| channel.mixU32s(&.{ @intFromEnum(std.meta.activeTag(source)), switch (source) {
                    .sample, .claim, .challenge, .public_input, .packed_public_input => |ordinal| ordinal,
                    .composition, .oods => 0,
                } });
                return channel.digestBytes();
            }
            pub fn validateAgainst(self: *const Self, shape: *const Shape.Owned) !void {
                try self.circuit.validate();
                if (!std.meta.eql(self.seal, self.identity())) return error.MutatedPageShapeComposition;
                var independent = try compile(self.allocator, shape);
                defer independent.deinit();
                if (!std.meta.eql(self.seal, independent.seal)) return error.UntrustedPageShapeComposition;
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
        pub fn compile(a: std.mem.Allocator, shape: *const Shape.Owned) !Compiled {
            return compileView(a, shape.template_id, shape.original.graph.identity, &shape.original.fixed.plan, shape.compilerView(), try shape.geometryView(), shape.logViews(), shape.limits);
        }
        /// Original mathematical compiler port; this cannot verify or admit a
        /// received PAGE. The public factory derives every argument from policy.
        pub fn compileView(a: std.mem.Allocator, template_id: [32]u8, graph_id: [32]u8, plan: *const @import("verifier_arithmetic_lowering.zig").Plan, view: Shape.CompilerView, frame: Shape.GeometryView, column_logs: [9][]const u32, limits: @import("../block_v5_memory_source_page_recursive_shape_v1.zig").Limits) !Compiled {
            // The public factory performs full independent shape admission;
            // this synchronous compiler never turns a self-seal into policy.
            try Shape.validateLogs(column_logs, frame.geometry, limits);
            const mask_log = core.verifier_types.compositionMaskLogSize(frame.constraint_log, frame.split) orelse return error.InvalidPageShapeComposition;
            const point = core.circle.SECURE_FIELD_CIRCLE_GEN;
            const step = core.poly.circle.canonic.CanonicCoset.new(mask_log).step();
            const previous = point.sub(.{ .x = core.fields.qm31.QM31.fromBase(step.x), .y = core.fields.qm31.QM31.fromBase(step.y) });
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const temp = arena.allocator();
            var masks = try Masks.derive(kind, temp, frame.geometry, column_logs, .{ .max_columns = limits.max_columns }, point, mask_log);
            defer masks.deinitDeep(temp);
            const composition_count = core.verifier_types.compositionColumnCount(frame.split, 4) orelse return error.InvalidPageShapeComposition;
            var samples = Equation.Samples{ .offsets = undefined, .layouts = undefined, .values = undefined };
            var sample_count: usize = composition_count;
            for (masks.items) |columns| for (columns) |points| {
                sample_count = try std.math.add(usize, sample_count, points.len);
            };
            const values = try temp.alloc(R.Scalar, sample_count);
            const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
            errdefer if (lease) |owner| owner.destroy();
            var builder = R.Builder.init(a);
            defer builder.deinit();
            var sources: std.ArrayList(Original.Source) = .empty;
            defer sources.deinit(a);
            for (values, 0..) |*symbol, ordinal| symbol.* = try input(&builder, a, &sources, .{ .sample = @intCast(ordinal) });
            samples.values = values;
            var cursor: usize = 0;
            for (masks.items, 0..) |columns, tree| {
                samples.offsets[tree] = try temp.alloc(usize, columns.len);
                samples.layouts[tree] = try temp.alloc(Layout.Layout, columns.len);
                for (columns, 0..) |points, column| {
                    samples.offsets[tree][column] = cursor;
                    samples.layouts[tree][column] = try Layout.classifyColumn(points, point, previous);
                    cursor = try std.math.add(usize, cursor, points.len);
                }
            }
            samples.offsets[9] = try temp.alloc(usize, composition_count);
            samples.layouts[9] = try temp.alloc(Layout.Layout, composition_count);
            @memset(samples.layouts[9], .current);
            for (samples.offsets[9]) |*offset| {
                offset.* = cursor;
                cursor += 1;
            }
            if (cursor != sample_count) return error.InvalidPageShapeComposition;
            var draws: [RELATION_COUNT][2]R.Scalar = undefined;
            for (&draws, 0..) |*pair, ordinal| {
                pair[0] = try input(&builder, a, &sources, .{ .challenge = @intCast(2 * ordinal) });
                pair[1] = try input(&builder, a, &sources, .{ .challenge = @intCast(2 * ordinal + 1) });
            }
            const randomness = try input(&builder, a, &sources, .composition);
            const seed = try input(&builder, a, &sources, .oods);
            var claims: Claims = undefined;
            var ordinal: usize = 0;
            inline for (std.meta.fields(Claims)) |field| for (&@field(claims, field.name)) |*symbol| {
                symbol.* = try input(&builder, a, &sources, .{ .public_input = @intCast(ordinal) });
                ordinal += 1;
            };
            if (ordinal != PUBLIC_COUNT) return error.InvalidPageShapeComposition;
            try builder.activate();
            var active = true;
            defer if (active) builder.deactivate();
            const challenges = try R.ChallengeSet.init(draws);
            const quotient = try Equation.recordForCompiler(kind, &builder, &view, plan, &frame, samples, claims, &challenges, randomness, seed);
            const chunks = try temp.alloc(R.Scalar, composition_count / 4);
            for (chunks, 0..) |*chunk, index| {
                var parts: [4]R.Scalar = undefined;
                for (&parts, 0..) |*part, coordinate| part.* = try samples.at(9, 4 * index + coordinate, 0);
                chunk.* = R.fromPartialEvals(parts);
            }
            try builder.constrainZero((try R.reconstructSplitComposition(chunks, R.pointFromSeed(seed), frame.constraint_log, frame.split)).sub(quotient));
            builder.deactivate();
            active = false;
            var circuit = try builder.finish();
            errdefer circuit.deinit();
            const owned_sources = try sources.toOwnedSlice(a);
            var result = Compiled{ .allocator = a, .budget = lease, .circuit = circuit, .sources = owned_sources, .template_id = template_id, .graph_id = graph_id, .seal = undefined };
            result.seal = result.identity();
            return result;
        }
    };
}
fn input(builder: *R.Builder, a: std.mem.Allocator, sources: *std.ArrayList(Original.Source), source: Original.Source) !R.Scalar {
    const symbol = try builder.input();
    try sources.append(a, source);
    return symbol.value;
}
