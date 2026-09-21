//! Typed definitions for program, memory, clock and fixed lookup providers.
//! These definitions own polynomial roots and ordered lookup events independently
//! of native executable specializations. Policies retain their existing wire ABI.
const std = @import("std");
const ir = @import("ir.zig");
const types = @import("types.zig");
const source = @import("source.zig");
const validation = @import("validate.zig");
const entries = @import("../lookups/entry.zig");
const Id = types.ValueId;
pub const Kind = enum { program, program_fixed, memory, memory_full, clock, bitwise, range_check_20, range_check_8_11, range_check_8_8_4, range_check_8_8, range_check_m31 };
pub fn isTable(kind: Kind) bool {
    return switch (kind) {
        .program, .program_fixed, .memory, .memory_full, .clock => false,
        else => true,
    };
}
pub fn tableArity(kind: Kind) usize {
    return switch (kind) {
        .bitwise => 4,
        .range_check_20 => 1,
        .range_check_8_8_4 => 3,
        .range_check_8_11, .range_check_8_8, .range_check_m31 => 2,
        else => unreachable,
    };
}
pub fn tableLogSize(kind: Kind) u32 {
    return switch (kind) {
        .bitwise => 18,
        .range_check_20, .range_check_8_8_4 => 20,
        .range_check_8_11 => 19,
        .range_check_8_8 => 16,
        .range_check_m31 => 15,
        else => unreachable,
    };
}
const Event = struct { domain: entries.Domain, numerator: Id, arity: u8, tuple: [7]Id };
const Author = struct {
    arena: *ir.Arena,
    fn q(self: Author, v: u32) !Id {
        return self.arena.constantField(v, source.SourceSpan.generated());
    }
    fn add(self: Author, a: Id, b: Id) !Id {
        return self.arena.add(a, b, source.SourceSpan.generated());
    }
    fn sub(self: Author, a: Id, b: Id) !Id {
        return self.arena.sub(a, b, source.SourceSpan.generated());
    }
    fn mul(self: Author, a: Id, b: Id) !Id {
        return self.arena.mul(a, b, source.SourceSpan.generated());
    }
    fn neg(self: Author, a: Id) !Id {
        return self.arena.neg(a, source.SourceSpan.generated());
    }
};
fn event(domain: entries.Domain, numerator: Id, tuple: anytype, zero: Id) Event {
    var result = Event{ .domain = domain, .numerator = numerator, .arity = tuple.len, .tuple = .{zero} ** 7 };
    inline for (tuple, 0..) |v, i| result.tuple[i] = v;
    return result;
}
pub fn Definition(comptime kind: Kind) type {
    return struct {
        const Self = @This();
        pub const MAIN_COLUMNS = if (isTable(kind)) 1 else if (kind == .memory or kind == .memory_full) 8 else 10;
        pub const FIXED_COLUMNS = if (isTable(kind)) tableArity(kind) else if (kind == .program_fixed) 6 else 0;
        pub const SUMS = if (isTable(kind)) 1 else if (kind == .clock) 2 else 4;
        pub const DIRECT_CONSTRAINTS = if (isTable(kind)) 0 else switch (kind) {
            .program_fixed => 9,
            .memory, .memory_full => 2,
            else => 3,
        };
        pub const LOOKUPS = if (isTable(kind)) 1 else switch (kind) {
            .program_fixed => 3,
            .clock => 4,
            else => 7,
        };
        arena: ir.Arena,
        columns: [MAIN_COLUMNS]Id,
        fixed: [FIXED_COLUMNS]Id,
        active: Id,
        roots: [DIRECT_CONSTRAINTS]Id,
        events: [LOOKUPS]Event,

        pub fn init(allocator: std.mem.Allocator) !Self {
            var self: Self = undefined;
            self.arena = ir.Arena.init(allocator);
            errdefer self.arena.deinit();
            const span = source.SourceSpan.generated();
            const a = Author{ .arena = &self.arena };
            for (&self.columns, 0..) |*v, i| {
                var name: [32]u8 = undefined;
                v.* = try self.arena.input(try std.fmt.bufPrint(&name, "main.{d}", .{i}), .felt, span);
            }
            for (&self.fixed, 0..) |*v, i| {
                var name: [32]u8 = undefined;
                v.* = try self.arena.input(try std.fmt.bufPrint(&name, "fixed.{d}", .{i}), .felt, span);
            }
            self.active = try self.arena.input("active", .felt, span);
            const c = self.columns;
            const zero = try a.q(0);
            const one = try a.q(1);
            switch (kind) {
                .program, .program_fixed => {
                    const negative = try a.neg(c[0]);
                    self.roots[0] = try a.sub(c[0], self.active);
                    self.roots[1] = try a.mul(c[6], try a.sub(one, self.active));
                    const word_address = try a.add(c[8], try a.mul(c[9], try a.q(1 << 20)));
                    self.roots[2] = try a.mul(c[0], try a.sub(c[1], try a.mul(word_address, try a.q(4))));
                    if (kind == .program_fixed) for ([_]usize{ 1, 2, 3, 4, 5, 7 }, self.fixed, 0..) |column, fixed, i| {
                        self.roots[3 + i] = try a.mul(self.active, try a.sub(c[column], fixed));
                    };
                    self.events[0] = event(.program_access, c[6], .{ c[1], c[2], c[3], c[4], c[5] }, zero);
                    if (kind == .program) for (0..4) |i| {
                        const address = if (i == 0) c[1] else try a.add(c[1], try a.q(@intCast(i)));
                        self.events[1 + i] = event(.merkle, negative, .{ address, try a.q(30), c[2 + i], c[7] }, zero);
                    };
                    self.events[LOOKUPS - 2] = event(.range_check_20, negative, .{c[8]}, zero);
                    self.events[LOOKUPS - 1] = event(.range_check_8_8, negative, .{ c[9], zero }, zero);
                },
                .memory, .memory_full => {
                    const square = try a.mul(c[6], c[6]);
                    self.roots[0] = try a.mul(c[6], try a.sub(square, one));
                    self.roots[1] = if (kind == .memory) try a.sub(square, self.active) else try a.mul(c[6], try a.sub(self.active, one));
                    const negative = try a.neg(self.active);
                    self.events[0] = event(.range_check_8_8, negative, .{ c[2], c[3] }, zero);
                    self.events[1] = event(.range_check_8_8, negative, .{ c[4], c[5] }, zero);
                    self.events[2] = event(.memory_access, c[6], .{ one, c[0], c[1], c[2], c[3], c[4], c[5] }, zero);
                    for (0..4) |i| {
                        const address = if (i == 0) c[0] else try a.add(c[0], try a.q(@intCast(i)));
                        self.events[3 + i] = event(.merkle, negative, .{ address, try a.q(30), c[2 + i], c[7] }, zero);
                    }
                },
                .clock => {
                    self.roots[0] = try a.mul(c[0], try a.sub(one, c[0]));
                    self.roots[1] = try a.sub(c[0], self.active);
                    self.roots[2] = try a.mul(c[0], try a.sub(c[3], try a.add(c[8], try a.mul(c[9], try a.q(1 << 20)))));
                    const negative = try a.neg(c[0]);
                    self.events[0] = event(.memory_access, negative, .{ c[1], c[2], c[3], c[4], c[5], c[6], c[7] }, zero);
                    self.events[1] = event(.memory_access, c[0], .{ c[1], c[2], try a.add(c[3], try a.q((1 << 20) - 1)), c[4], c[5], c[6], c[7] }, zero);
                    self.events[2] = event(.range_check_20, negative, .{c[8]}, zero);
                    self.events[3] = event(.range_check_8_8, negative, .{ c[9], try a.mul(c[9], try a.q(4)) }, zero);
                },
                else => {
                    std.debug.assert(isTable(kind));
                    self.events[0] = .{
                        .domain = @field(entries.Domain, @tagName(kind)),
                        .numerator = try a.neg(c[0]),
                        .arity = FIXED_COLUMNS,
                        .tuple = .{zero} ** 7,
                    };
                    @memcpy(self.events[0].tuple[0..FIXED_COLUMNS], &self.fixed);
                },
            }
            for (self.roots, 0..) |root, i| {
                var name: [64]u8 = undefined;
                _ = try self.arena.assertZero(try std.fmt.bufPrint(&name, "{s}.direct.{d}", .{ @tagName(kind), i }), root, null, .semantic, span);
            }
            try validation.validate(&self.arena);
            return self;
        }
        pub fn deinit(self: *Self) void {
            self.arena.deinit();
            self.* = undefined;
        }
        pub fn Result(comptime S: type) type {
            return struct { direct: [DIRECT_CONSTRAINTS]S, lookups: entries.Builder(S).List };
        }
        pub fn evaluate(self: *const Self, comptime S: type, allocator: std.mem.Allocator, main: [MAIN_COLUMNS]S, active: S, fixed: [FIXED_COLUMNS]S) !Result(S) {
            const inputs = self.columns ++ self.fixed ++ [_]Id{self.active};
            const arguments = main ++ fixed ++ [_]S{active};
            const values = try @import("polynomial_replay.zig").evaluate(S, allocator, &self.arena, &inputs, &arguments);
            defer allocator.free(values);
            var result: Result(S) = .{ .direct = undefined, .lookups = .{} };
            for (self.roots, &result.direct) |root, *v| v.* = values[types.idIndex(root)];
            for (self.events) |e| {
                var item = entries.Builder(S).Entry{ .domain = e.domain, .numerator = values[types.idIndex(e.numerator)], .arity = e.arity };
                for (e.tuple[0..e.arity], item.values[0..e.arity]) |v, *slot| slot.* = values[types.idIndex(v)];
                result.lookups.append(item);
            }
            return result;
        }
    };
}
