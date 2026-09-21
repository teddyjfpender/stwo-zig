//! Wide physical AIR lowered from the authenticated typed degree-three plan.
//! The binding chooses slots; the typed graph supplies every equality body.
const std = @import("std");
const ir = @import("ir.zig");
const types = @import("types.zig");
const source = @import("source.zig");
const poseidon = @import("typed_poseidon2.zig");
const compat = @import("typed_poseidon2_compat.zig");
const relations = @import("typed_poseidon2_relation_contract.zig");
const Program = @import("typed_poseidon2_bound_program.zig").Program;
const entries = @import("../lookups/entry.zig");
const Id = types.ValueId;
const absent = std.math.maxInt(usize);
pub const MAIN_COLUMNS = compat.N_MAIN_COLUMNS;
pub const DIRECT_CONSTRAINTS = 1 + compat.N_MATERIALIZATIONS + 3;
pub const SUMS = relations.N_SUMS;

pub const Definition = struct {
    arena: ir.Arena,
    columns: [MAIN_COLUMNS]Id,
    roots: [DIRECT_CONSTRAINTS]Id,
    events: [relations.N_EVENTS]relations.EventPlan,
    numerators: [relations.N_EVENTS]Id,
    tuples: [relations.N_EVENTS][relations.MAX_ARITY]Id,

    pub fn init(allocator: std.mem.Allocator) !Definition {
        var program = try Program.init(allocator);
        defer program.deinit();
        const cuts = try allocator.alloc(usize, program.arena.nodes.items.len);
        defer allocator.free(cuts);
        @memset(cuts, absent);
        for (program.binding.entries, 0..) |entry, index| {
            const node_index = types.idIndex(entry.value);
            if (cuts[node_index] != absent) return error.WideTypedDuplicateCut;
            cuts[node_index] = index;
        }
        var result: Definition = .{
            .arena = ir.Arena.init(allocator),
            .columns = undefined,
            .roots = undefined,
            .events = .{ relations.canonicalEvent(0), relations.canonicalEvent(1), relations.canonicalEvent(2), relations.canonicalEvent(3) },
            .numerators = undefined,
            .tuples = undefined,
        };
        errdefer result.deinit();
        const arena = &result.arena;
        const span = source.SourceSpan.generated();
        for (&result.columns, 0..) |*column, index| {
            var name: [48]u8 = undefined;
            column.* = try arena.input(try std.fmt.bufPrint(&name, "wide.main.{d}", .{index}), .felt, span);
        }
        const one = try arena.constantField(1, span);
        const zero = try arena.constantField(0, span);
        const enabled = result.columns[compat.ENABLER_COLUMN];
        const wide = result.columns[compat.WIDE_COLUMN];
        const io = result.columns[compat.IO_COLUMN];
        result.roots[0] = try arena.mul(enabled, try arena.sub(one, enabled, span), span);
        result.roots[1 + compat.N_MATERIALIZATIONS] = try arena.mul(wide, try arena.sub(one, wide, span), span);
        result.roots[2 + compat.N_MATERIALIZATIONS] = try arena.mul(io, try arena.sub(one, io, span), span);
        result.roots[3 + compat.N_MATERIALIZATIONS] = try arena.mul(wide, io, span);
        const mapped = try allocator.alloc(Id, program.arena.nodes.items.len);
        defer allocator.free(mapped);
        const inputs = poseidon.values(program.definition.inputs);
        for (program.arena.nodes.items, 0..) |node, index| {
            const lowered = switch (node.key.op) {
                .input => blk: {
                    if (index == types.idIndex(program.gate)) break :blk enabled;
                    for (inputs, 0..) |input, lane|
                        if (types.idIndex(input) == index) break :blk result.columns[compat.INPUT_START + lane];
                    return error.WideTypedUnknownInput;
                },
                .constant => |constant| switch (constant) {
                    .field => |word| try arena.constantField(word, span),
                    else => return error.WideTypedUnsupportedExpression,
                },
                .add => |b| try arena.add(mapped[types.idIndex(b.lhs)], mapped[types.idIndex(b.rhs)], span),
                .sub => |b| try arena.sub(mapped[types.idIndex(b.lhs)], mapped[types.idIndex(b.rhs)], span),
                .mul => |b| try arena.mul(mapped[types.idIndex(b.lhs)], mapped[types.idIndex(b.rhs)], span),
                .neg => |v| try arena.neg(mapped[types.idIndex(v)], span),
                else => return error.WideTypedUnsupportedExpression,
            };
            if (cuts[index] != absent) {
                const slot = program.binding.entries[cuts[index]].materialization;
                const column = result.columns[slot.column];
                result.roots[slot.constraint] = try arena.mul(enabled, try arena.sub(column, lowered, span), span);
                mapped[index] = column;
            } else mapped[index] = lowered;
        }
        var outputs: [poseidon.WIDTH]Id = undefined;
        for (poseidon.values(program.definition.outputs), &outputs) |output, *value| value.* = mapped[types.idIndex(output)];
        for (result.events, &result.numerators, &result.tuples) |event, *numerator, *tuple| {
            numerator.* = switch (event.numerator) {
                .negative_enabled_non_io => try arena.neg(try arena.mul(enabled, try arena.sub(one, io, span), span), span),
                .enabled_narrow => try arena.mul(enabled, try arena.sub(try arena.sub(one, wide, span), io, span), span),
                .enabled_wide => try arena.mul(enabled, wide, span),
                .enabled_io => try arena.mul(enabled, io, span),
            };
            tuple.* = @splat(zero);
            switch (event.projection) {
                .input => @memcpy(tuple[0..poseidon.WIDTH], result.columns[compat.INPUT_START..][0..poseidon.WIDTH]),
                .narrow_output => tuple[0] = outputs[0],
                .wide_output => @memcpy(tuple[0 .. poseidon.WIDTH / 2], outputs[0 .. poseidon.WIDTH / 2]),
                .input_output => {
                    @memcpy(tuple[0..poseidon.WIDTH], result.columns[compat.INPUT_START..][0..poseidon.WIDTH]);
                    @memcpy(tuple[poseidon.WIDTH..], &outputs);
                },
            }
        }
        for (result.roots, 0..) |root, index| {
            var name: [48]u8 = undefined;
            _ = try arena.assertZero(try std.fmt.bufPrint(&name, "wide.constraint.{d}", .{index}), root, null, .semantic, span);
        }
        try @import("validate.zig").validate(arena);
        return result;
    }

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn Result(comptime S: type) type {
        return struct { direct: [DIRECT_CONSTRAINTS]S, lookups: entries.Builder(S).List };
    }

    pub fn evaluate(self: *const Definition, comptime S: type, allocator: std.mem.Allocator, main: [MAIN_COLUMNS]S) !Result(S) {
        const values = try @import("polynomial_replay.zig").evaluate(S, allocator, &self.arena, &self.columns, &main);
        defer allocator.free(values);
        var result: Result(S) = .{ .direct = undefined, .lookups = .{} };
        for (self.roots, &result.direct) |root, *value| value.* = values[types.idIndex(root)];
        for (self.events, self.numerators, self.tuples) |event, numerator, tuple| {
            var entry = entries.Builder(S).Entry{
                .domain = @enumFromInt(@intFromEnum(event.domain)),
                .role = @enumFromInt(@intFromEnum(event.role)),
                .access_ordinal = event.access_ordinal,
                .arity = event.relation_arity,
                .numerator = values[types.idIndex(numerator)],
            };
            for (tuple[0..entry.arity], entry.values[0..entry.arity]) |value, *word| word.* = values[types.idIndex(value)];
            result.lookups.append(entry);
        }
        return result;
    }
};
