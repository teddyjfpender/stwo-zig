//! Packed SHA operation plus exact word-wire requests and weighted production.
//! A namespace is the caller's execution clock; CPU/memory boundary AIR must
//! supply inputs at boundary-offset wire IDs and consume final output wires.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../lang/definition.zig");
const arithmetic = @import("sha256_packed_arithmetic.zig");
const program = @import("sha256_word_program.zig");
const graph = @import("sha256_compression_graph.zig");
const effects = @import("../../recursion/air/relation_effect.zig");
const M = core.fields.m31.M31;
const span = lang.source.SourceSpan.generated();
pub fn ForKind(comptime kind: program.Kind) type {
    return struct {
        pub const production_active = false;
        pub const SEMANTIC_DIGEST = digest();
        fn digest() [32]u8 {
            const hex = switch (kind) {
                .round => "42675e1965b802d02c19d20f693a0b1090cda59a5e132f37237a344e8e8aa09c",
                .schedule => "f259f992cc18c0ea0f41b40df8e28430bda08fd782c92c0d39ab874e07a58ade",
                .feed_forward => "ef76a5c1a9ee0912e6b9efde5e2f8368a24e88a178bfbe63b88242d5d40f1106",
            };
            var result: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&result, hex) catch unreachable;
            return result;
        }
        pub const PHYSICAL_MAIN_COLUMN_COUNT = arithmetic.columnCount(kind) + 1;
        pub const PREPROCESSED_COLUMN_COUNT = 1 + program.inputCount(kind) + 2 * program.outputCount(kind);
        pub const LOGICAL_INPUT_COUNT = PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
        pub const DIRECT_CONSTRAINT_COUNT = arithmetic.constraintCount(kind);
        pub const RELATION_EVENT_COUNT = arithmetic.eventCount(kind) + program.inputCount(kind) + program.outputCount(kind);
        pub const LOOKUP_BATCH_SIZE: u8 = 2;
        pub const INTERACTION_BATCH_COUNT = (RELATION_EVENT_COUNT + 1) / 2;
        pub const INTERACTION_COLUMN_COUNT = INTERACTION_BATCH_COUNT * 4;
        pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 1;
        pub const Row = [LOGICAL_INPUT_COUNT]M;
        pub const Definition = struct {
            arena: lang.ir.Arena,
            events: [RELATION_EVENT_COUNT]lang.types.EffectId,
            pub fn validate(self: *const @This()) !void {
                try lang.validate.validate(&self.arena);
                const identity = try lang.digest.computeIdentity(&self.arena);
                if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or self.arena.effectsView().len != RELATION_EVENT_COUNT or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT) return error.InvalidShaCallSemantics;
            }
            pub fn deinit(self: *@This()) void {
                self.arena.deinit();
            }
        };
        pub fn build(a: std.mem.Allocator) !Definition {
            var bound = try arithmetic.buildBound(kind, PREPROCESSED_COLUMN_COUNT, a);
            errdefer bound.definition.deinit();
            const arena = &bound.definition.arena;
            const fixed = bound.fixed;
            for (bound.input, 0..) |word, i| _ = try effects.appendGroup(1, arena, .{.{ .domain = .recursion_wire, .role = .consume, .values = &(.{ bound.call_id, fixed[1 + i] } ++ word), .weight = fixed[0] }}, span);
            const output_at = 1 + program.inputCount(kind);
            for (bound.definition.output, 0..) |word, i| _ = try effects.appendGroup(1, arena, .{.{ .domain = .recursion_wire, .role = .emit, .values = &(.{ bound.call_id, fixed[output_at + i] } ++ word), .weight = fixed[output_at + program.outputCount(kind) + i] }}, span);
            try lang.validate.validate(arena);
            if (arena.effectsView().len != RELATION_EVENT_COUNT or arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT) return error.InvalidShaCallGeometry;
            var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
            for (&events, 0..) |*event, i| event.* = @enumFromInt(i);
            const result = Definition{ .arena = bound.definition.arena, .events = events };
            try result.validate();
            return result;
        }
        pub fn row(call_id: u32, op: graph.Operation(kind), uses: *const [graph.wire_count]u32, input: [program.inputCount(kind)]u32) !Row {
            if (call_id == 0 or call_id >= core.fields.m31.Modulus) return error.InvalidShaCallId;
            var result = try fixedRow(call_id, op, uses);
            try arithmetic.witnessInto(kind, input, result[0..arithmetic.columnCount(kind)]);
            return result;
        }
        pub fn fixedRow(call_id: u32, op: graph.Operation(kind), uses: *const [graph.wire_count]u32) !Row {
            if (call_id == 0 or call_id >= core.fields.m31.Modulus) return error.InvalidShaCallId;
            var result: Row = @splat(M.zero());
            result[arithmetic.columnCount(kind)] = M.fromCanonical(call_id);
            const pp = result[PHYSICAL_MAIN_COLUMN_COUNT..];
            pp[0] = M.one();
            for (op.input, 0..) |wire, i| {
                if (wire >= graph.wire_count) return error.InvalidShaWire;
                pp[1 + i] = M.fromCanonical(wire);
            }
            const output_at = 1 + program.inputCount(kind);
            for (op.output, 0..) |wire, i| {
                if (wire >= graph.wire_count) return error.InvalidShaWire;
                pp[output_at + i] = M.fromCanonical(wire);
                pp[output_at + program.outputCount(kind) + i] = M.fromCanonical(uses[wire]);
            }
            return result;
        }
    };
}
