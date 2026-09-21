//! Typed polynomial authority for the native sparse-Merkle node AIR.
//! Physical positions and ordered lookup tuples are explicit protocol bindings.
//! This definition does not import the native executable specialization.
const std = @import("std");
const ir = @import("ir.zig");
const types = @import("types.zig");
const source = @import("source.zig");
const validate = @import("validate.zig");
const entries = @import("../lookups/entry.zig");
const Id = types.ValueId;
pub const MAIN_COLUMNS = 10;
pub const DIRECT_CONSTRAINTS = 7;
pub const LOOKUPS = 5;
pub const SUMS = 3;
pub const Definition = struct {
    arena: ir.Arena,
    columns: [MAIN_COLUMNS]Id,
    active: Id,
    roots: [DIRECT_CONSTRAINTS]Id,
    numerators: [LOOKUPS]Id,
    tuples: [LOOKUPS][16]Id,

    pub fn init(allocator: std.mem.Allocator) !Definition {
        var result: Definition = undefined;
        result.arena = ir.Arena.init(allocator);
        errdefer result.arena.deinit();
        const a = &result.arena;
        const span = source.SourceSpan.generated();
        const names = [_][]const u8{ "enabled", "index", "depth", "left", "right", "current", "left_multiplicity", "right_multiplicity", "current_multiplicity", "root" };
        for (names, &result.columns) |name, *column| column.* = try a.input(name, .felt, span);
        result.active = try a.input("active", .felt, span);
        const c = result.columns;
        const zero = try a.constantField(0, span);
        const one = try a.constantField(1, span);
        const two = try a.constantField(2, span);
        const half = try a.constantField(1073741824, span);
        const padding = try a.sub(one, result.active, span);
        result.roots[0] = try a.sub(c[0], result.active, span);
        for (c[6..9], 0..) |multiplicity, i| {
            result.roots[1 + i] = try a.mul(try a.mul(multiplicity, try a.sub(multiplicity, one, span), span), try a.sub(multiplicity, two, span), span);
            result.roots[4 + i] = try a.mul(multiplicity, padding, span);
        }
        for (result.roots, 0..) |root, i| {
            var name: [48]u8 = undefined;
            _ = try a.assertZero(try std.fmt.bufPrint(&name, "merkle.direct.{d}", .{i}), root, null, .semantic, span);
        }
        result.numerators = .{ c[6], c[7], try a.neg(c[8], span), c[0], try a.neg(c[0], span) };
        result.tuples = .{.{zero} ** 16} ** LOOKUPS;
        result.tuples[0][0..4].* = .{ c[1], c[2], c[3], c[9] };
        result.tuples[1][0..4].* = .{ try a.add(c[1], one, span), c[2], c[4], c[9] };
        result.tuples[2][0..4].* = .{ try a.mul(c[1], half, span), try a.sub(c[2], one, span), c[5], c[9] };
        result.tuples[3][0..2].* = .{ c[3], c[4] };
        result.tuples[4][0] = c[5];
        try validate.validate(a);
        return result;
    }

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn Result(comptime S: type) type {
        return struct { direct: [DIRECT_CONSTRAINTS]S, lookups: entries.Builder(S).List };
    }

    pub fn evaluate(self: *const Definition, comptime S: type, allocator: std.mem.Allocator, main: [MAIN_COLUMNS]S, active: S) !Result(S) {
        const inputs = self.columns ++ [_]Id{self.active};
        const arguments = main ++ [_]S{active};
        const values = try @import("polynomial_replay.zig").evaluate(S, allocator, &self.arena, &inputs, &arguments);
        defer allocator.free(values);
        var result: Result(S) = .{ .direct = undefined, .lookups = .{} };
        for (self.roots, &result.direct) |root, *value| value.* = values[types.idIndex(root)];
        for (self.numerators, self.tuples, 0..) |numerator, tuple, i| {
            const arity: u8 = if (i < 3) 4 else 16;
            var event = entries.Builder(S).Entry{ .domain = if (i < 3) .merkle else .poseidon2, .arity = arity, .numerator = values[types.idIndex(numerator)] };
            for (tuple[0..arity], event.values[0..arity]) |value, *word| word.* = values[types.idIndex(value)];
            result.lookups.append(event);
        }
        return result;
    }
};
