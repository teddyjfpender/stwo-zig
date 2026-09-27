//! Actual PAGE-root and compact memory-root bytes linked in the same parent.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const R = @import("composition_graph_recorder.zig");
const Arena = @import("stable_graph_arena_v1.zig").Owned;
const OriginalBus = @import("../block_v5_source_ram_forest_join_public_v1.zig");
const A = @import("block_v5_source_ram_forest_join_algebra_v1.zig");
const G = @import("block_v5_heterogeneous_scoped_graph_rows_v1.zig").Graph;
/// ONE original reader/equation body for live and admitted setup serializers.
pub fn ForPublic(comptime Bus: type) type {
    return struct {
        const Self = @This();
        pub const Prepared = struct {
            arena: Arena,
            circuit: R.Circuit,
            inputs: []Q,
            values: []Q,
            sources: []Bus.Wire,
            pub fn deinit(self: *@This()) void {
                self.circuit.deinit();
                self.arena.deinit();
                self.* = undefined;
            }
            pub fn graph(self: *const @This()) G {
                return .{ .circuit = &self.circuit, .inputs = self.inputs, .values = self.values, .sources = self.sources };
            }
        };
        const Reader = struct {
            a: std.mem.Allocator,
            builder: *R.Builder,
            values: Bus.Values,
            inputs: std.ArrayList(Q) = .empty,
            sources: std.ArrayList(Bus.Wire) = .empty,
            fn word(self: *@This(), kind: @FieldType(Bus.Wire, "kind"), child: u32, coordinate: u32) ![4]R.Scalar {
                var symbols: [4]R.Scalar = undefined;
                for (&symbols, 0..) |*symbol, part| {
                    const wire = Bus.Wire{ .circuit = 0, .wire = 0, .uses = 1, .kind = kind, .child = child, .coordinate = coordinate, .part = @intCast(part) };
                    symbol.* = (try self.builder.input()).value;
                    try self.inputs.append(self.a, Q.fromM31Array(try self.values.at(wire)));
                    try self.sources.append(self.a, wire);
                }
                return symbols;
            }
            fn secure(self: *@This(), kind: @FieldType(Bus.Wire, "kind"), child: u32, coordinate: u32) ![4][4]R.Scalar {
                var symbols: [4][4]R.Scalar = undefined;
                for (&symbols, 0..) |*parts, limb| parts.* = try self.word(kind, child, coordinate + @as(u32, @intCast(limb)));
                return symbols;
            }
        };
        fn word(bytes: [4]R.Scalar) R.Scalar {
            var value = R.Scalar.zero();
            for (bytes, 0..) |byte, part| value = value.add(byte.mul(R.Scalar.fromBase(M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(8 * part))))));
            return value;
        }
        fn secure(bytes: [4][4]R.Scalar) R.Scalar {
            var limbs: [4]R.Scalar = undefined;
            for (&limbs, bytes) |*limb, b| limb.* = word(b);
            return R.fromPartialEvals(limbs);
        }
        const Sink = struct {
            builder: *R.Builder,
            pub fn zero(self: *@This(), value: R.Scalar) !void {
                try self.builder.constrainZero(value);
            }
        };
        pub fn prepare(backing: std.mem.Allocator, public: *const Bus.Owner) !Self.Prepared {
            try public.validate();
            const p = public.policy;
            const ctx = OriginalBus.pagePolicy(p.source).forest.context;
            var arena = try Arena.init(backing);
            errdefer arena.deinit();
            const a = arena.allocator();
            var builder = R.Builder.init(a);
            defer builder.deinit();
            var reader = Reader{ .a = a, .builder = &builder, .values = .{ .public = public } };
            var source_bytes: [22][4][4]R.Scalar = undefined;
            for (&source_bytes, 0..) |*b, i| b.* = try reader.secure(.child_cell, 0, (try p.source.claim(@intCast(i))).first_cell);
            const coordinates = try p.source.rangeCoordinates();
            const indices = [_]u32{ coordinates.first, coordinates.count, coordinates.raw_pages, coordinates.fold_pages, coordinates.raw_rows, coordinates.fold_rows };
            var census: [6][4]R.Scalar = undefined;
            for (&census, indices) |*b, i| b.* = try reader.word(.child_cell, 0, i);
            var memory_bytes: [22][4][4]R.Scalar = undefined;
            var memory_header: [12][4]R.Scalar = undefined;
            if (p.aggregate) |s| {
                for (&memory_bytes, 0..) |*b, i| b.* = try reader.secure(.child_cell, 1, (try s.claim(@intCast(i))).first_cell);
                const first = try s.headerFirst();
                for (&memory_header, 0..) |*b, i| b.* = try reader.word(.child_cell, 1, first + @as(u32, @intCast(i)));
            }
            const transition_output = try reader.secure(.output_slot, 0, Bus.CLAIM_FIRST);
            try builder.activate();
            defer if (builder.active) builder.deactivate();
            var sink = Sink{ .builder = &builder };
            const expected = [_]u64{ 0, ctx.raw.len + ctx.fold.len, ctx.raw.len, ctx.fold.len, ctx.raw_plan.total_chunks, try ctx.fold_plan.census.operations() };
            for (census, expected) |b, n| {
                if (n >= core.fields.m31.Modulus) return error.SourceRamForestFieldCensus;
                try sink.zero(word(b).sub(R.Scalar.fromBase(M.fromCanonical(@intCast(n)))));
            }
            var source: [22]R.Scalar = undefined;
            for (&source, source_bytes) |*v, b| v.* = secure(b);
            var memory: [22]R.Scalar = @splat(R.Scalar.zero());
            if (p.aggregate) |s| {
                for (&memory, memory_bytes) |*v, b| v.* = secure(b);
                // Independently required full coverage and closed-shard kind. Never
                // derive required spans/census from the received compact header.
                const root = p.memory.geometry.nodes[p.memory.geometry.root.?];
                if (root.kind == .partial or root.lanes.first != 0 or root.lanes.count != p.memory.memory.pins.len or root.shards.first != 0 or root.shards.count != p.memory.range_plan.shards.len or root.events != p.memory.memory.expected_total_events) return error.UntrustedSourceRamForestCensus;
                const header = OriginalBus.memorySummary(s).header;
                for (memory_header, header) |b, n| for (b, 0..) |byte, part| try sink.zero(byte.sub(R.Scalar.fromBase(M.fromCanonical((n >> @as(u5, @intCast(8 * part))) & 255))));
            }
            const transition = try A.close(R.Scalar, &sink, &ctx.admitted, source, memory);
            try sink.zero(transition.sub(secure(transition_output)));
            try builder.check();
            builder.deactivate();
            var circuit = try builder.finish();
            errdefer circuit.deinit();
            const inputs = try reader.inputs.toOwnedSlice(a);
            const sources = try reader.sources.toOwnedSlice(a);
            const values = try a.alloc(Q, circuit.nodes.len);
            try circuit.evaluateInto(inputs, values);
            return .{ .arena = arena, .circuit = circuit, .inputs = inputs, .values = values, .sources = sources };
        }
    };
}
const Default = ForPublic(OriginalBus);
pub const Prepared = Default.Prepared;
pub const prepare = Default.prepare;
