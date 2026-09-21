//! Compact degree-three physical AIR lowered from the canonical typed permutation.
//! Every square/fifth-power cut is derived from the typed expression graph;
//! neither round scheduling nor permutation arithmetic is transcribed here.
const std = @import("std");
const ir = @import("ir.zig");
const types = @import("types.zig");
const source = @import("source.zig");
const poseidon = @import("typed_poseidon2.zig");
const validate = @import("validate.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const layout = @import("../memory_commitment/poseidon2_universal_layout_v1.zig");
const entries = @import("../lookups/entry.zig");
const Id = types.ValueId;
const absent = std.math.maxInt(usize);

pub const Definition = struct {
    arena: ir.Arena,
    columns: [layout.N_MAIN_COLUMNS]Id,
    roots: [layout.N_CONSTRAINTS]Id,
    outputs: [layout.WIDTH]Id,
    numerators: [4]Id,
    tuples: [4][32]Id,

    pub fn init(allocator: std.mem.Allocator) !Definition {
        var logical = ir.Arena.init(allocator);
        defer logical.deinit();
        const span = source.SourceSpan.generated();
        const semantic = try poseidon.define(&logical, poseidon.DefinitionSpans.uniform(span));
        try validate.validate(&logical);
        const cuts = try allocator.alloc(usize, logical.nodes.items.len);
        defer allocator.free(cuts);
        @memset(cuts, absent);
        var cut_count: usize = 0;
        // x^5 is exactly x * ((x*x)*(x*x)) in the canonical typed graph.
        // Matrix products cannot satisfy this structure. Reject ambiguous or
        // changed layouts instead of silently inventing a new protocol layout.
        for (logical.nodes.items, 0..) |node, index| {
            if (node.key.op != .mul) continue;
            const fifth = node.key.op.mul;
            const fourth_node = logical.nodes.items[types.idIndex(fifth.rhs)];
            if (fourth_node.key.op != .mul) continue;
            const fourth = fourth_node.key.op.mul;
            if (fourth.lhs != fourth.rhs) continue;
            const square_index = types.idIndex(fourth.lhs);
            const square_node = logical.nodes.items[square_index];
            if (square_node.key.op != .mul) continue;
            const square = square_node.key.op.mul;
            if (square.lhs != fifth.lhs or square.rhs != fifth.lhs) continue;
            if (cuts[square_index] != absent or cuts[index] != absent or cut_count + 2 > 2 * layout.N_SBOXES)
                return error.CompactTypedMaterializationMismatch;
            cuts[square_index] = 17 + cut_count;
            cuts[index] = 18 + cut_count;
            cut_count += 2;
        }
        if (cut_count != 2 * layout.N_SBOXES) return error.CompactTypedMaterializationMismatch;

        var result: Definition = .{ .arena = ir.Arena.init(allocator), .columns = undefined, .roots = undefined, .outputs = undefined, .numerators = undefined, .tuples = undefined };
        errdefer result.deinit();
        const arena = &result.arena;
        for (&result.columns, 0..) |*column, index| {
            var name: [48]u8 = undefined;
            column.* = try arena.input(try std.fmt.bufPrint(&name, "compact.main.{d}", .{index}), .felt, span);
        }
        const one = try arena.constantField(1, span);
        for ([_]usize{ 0, layout.WIDE_COLUMN, layout.IO_COLUMN }, 0..) |column, index|
            result.roots[index] = try arena.mul(result.columns[column], try arena.sub(one, result.columns[column], span), span);
        result.roots[3] = try arena.mul(result.columns[layout.WIDE_COLUMN], result.columns[layout.IO_COLUMN], span);
        const mapped = try allocator.alloc(Id, logical.nodes.items.len);
        defer allocator.free(mapped);
        const inputs = poseidon.values(semantic.inputs);
        for (logical.nodes.items, 0..) |node, index| {
            const lowered = switch (node.key.op) {
                .input => blk: {
                    for (inputs, 0..) |input, lane| {
                        if (types.idIndex(input) == index) break :blk result.columns[1 + lane];
                    }
                    return error.CompactTypedUnknownInput;
                },
                .constant => |constant| switch (constant) {
                    .field => |word| try arena.constantField(word, span),
                    else => return error.CompactTypedUnsupportedExpression,
                },
                .add => |binary| try arena.add(mapped[types.idIndex(binary.lhs)], mapped[types.idIndex(binary.rhs)], span),
                .sub => |binary| try arena.sub(mapped[types.idIndex(binary.lhs)], mapped[types.idIndex(binary.rhs)], span),
                .mul => |binary| try arena.mul(mapped[types.idIndex(binary.lhs)], mapped[types.idIndex(binary.rhs)], span),
                .neg => |operand| try arena.neg(mapped[types.idIndex(operand)], span),
                else => return error.CompactTypedUnsupportedExpression,
            };
            const column = cuts[index];
            if (column != absent) {
                result.roots[4 + column - 17] = try arena.sub(result.columns[column], lowered, span);
                mapped[index] = result.columns[column];
            } else mapped[index] = lowered;
        }
        for (poseidon.values(semantic.outputs), &result.outputs) |output, *value| value.* = mapped[types.idIndex(output)];
        const zero = try arena.constantField(0, span);
        const enabler = result.columns[0];
        const wide = result.columns[layout.WIDE_COLUMN];
        const io = result.columns[layout.IO_COLUMN];
        result.numerators = .{
            try arena.neg(try arena.mul(enabler, try arena.sub(one, io, span), span), span),
            try arena.mul(enabler, try arena.sub(try arena.sub(one, wide, span), io, span), span),
            try arena.mul(enabler, wide, span),
            try arena.mul(enabler, io, span),
        };
        for (&result.tuples) |*tuple| tuple.* = @splat(zero);
        @memcpy(result.tuples[0][0..16], result.columns[1..17]);
        result.tuples[1][0] = result.outputs[0];
        @memcpy(result.tuples[2][0..8], result.outputs[0..8]);
        @memcpy(result.tuples[3][0..16], result.columns[1..17]);
        @memcpy(result.tuples[3][16..32], &result.outputs);
        for (result.roots, 0..) |root, index| {
            var name: [48]u8 = undefined;
            _ = try arena.assertZero(try std.fmt.bufPrint(&name, "compact.constraint.{d}", .{index}), root, null, .semantic, span);
        }
        try validate.validate(arena);
        return result;
    }

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn Result(comptime S: type) type {
        return struct { direct: [layout.N_CONSTRAINTS]S, output: [layout.WIDTH]S, lookups: entries.Builder(S).List };
    }

    /// Cold replay for protocol identity and independent specialization checks.
    /// Input positions are bound explicitly; arena allocation order is irrelevant.
    pub fn evaluate(self: *const Definition, comptime S: type, allocator: std.mem.Allocator, main: [layout.N_MAIN_COLUMNS]S) !Result(S) {
        const values = try allocator.alloc(S, self.arena.nodes.items.len);
        defer allocator.free(values);
        for (self.arena.nodes.items, 0..) |node, index| {
            values[index] = switch (node.key.op) {
                .input => blk: {
                    for (self.columns, main) |column, value| if (types.idIndex(column) == index) {
                        break :blk value;
                    };
                    return error.CompactTypedUnknownInput;
                },
                .constant => |constant| switch (constant) {
                    .field => |word| if (S == M31) M31.fromCanonical(word) else S.fromBase(M31.fromCanonical(word)),
                    else => return error.CompactTypedUnsupportedExpression,
                },
                .add => |binary| values[types.idIndex(binary.lhs)].add(values[types.idIndex(binary.rhs)]),
                .sub => |binary| values[types.idIndex(binary.lhs)].sub(values[types.idIndex(binary.rhs)]),
                .mul => |binary| values[types.idIndex(binary.lhs)].mul(values[types.idIndex(binary.rhs)]),
                .neg => |operand| values[types.idIndex(operand)].neg(),
                else => return error.CompactTypedUnsupportedExpression,
            };
        }
        var result: Result(S) = undefined;
        for (self.roots, &result.direct) |root, *value| value.* = values[types.idIndex(root)];
        for (self.outputs, &result.output) |output, *value| value.* = values[types.idIndex(output)];
        result.lookups = .{};
        for (self.numerators, self.tuples, 0..) |numerator, tuple, index| {
            const arity: u8 = if (index == 3) 32 else 16;
            var event = entries.Builder(S).Entry{ .domain = if (index == 3) .poseidon2_io else .poseidon2, .arity = arity, .numerator = values[types.idIndex(numerator)] };
            for (tuple[0..arity], event.values[0..arity]) |value, *word| word.* = values[types.idIndex(value)];
            result.lookups.append(event);
        }
        return result;
    }
};
