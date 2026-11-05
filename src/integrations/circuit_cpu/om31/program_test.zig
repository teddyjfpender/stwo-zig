const std = @import("std");
const C = @import("stwo_cairo_frontend").witness;
const E = @import("program.zig");
const P = @import("protocol.zig");
const O = P.O;
const M = P.M;
const Fixture = struct {
    base: [5]C.eval_program.BaseInst = .{
        .{ .op = .trace_col, .interaction = 2, .dst = 0, .a = 0, .b = 0, .imm = -1 },
        .{ .op = .trace_col, .interaction = 2, .dst = 1, .a = 1, .b = 0, .imm = -1 },
        .{ .op = .trace_col, .interaction = 2, .dst = 2, .a = 2, .b = 0, .imm = -1 },
        .{ .op = .trace_col, .interaction = 2, .dst = 3, .a = 3, .b = 0, .imm = -1 },
        .{ .op = .neg, .interaction = 0, .dst = 4, .a = 0, .b = 0, .imm = 0 },
    },
    ext: [1]C.eval_program.ExtInst = .{.{ .op = .secure_col, .dst = 0, .a = 0, .b = 1, .c = 2, .d = 3 }},
    roots: [1]u32 = .{0},
    fn program(self: *Fixture) E.Program {
        return .{ .allocator = std.testing.allocator, .header = .{ .flags = 0, .semantic_hash = 0, .capability_bits = 0, .n_interactions = 3, .n_base_params = 0, .n_ext_params = 0, .n_constraints = 1, .max_base_regs = 5, .max_ext_regs = 1, .domain_log_size = 5 }, .base_consts = &.{}, .ext_consts = &.{}, .base_insts = self.base[0..4], .ext_insts = &self.ext, .constraint_roots = &self.roots };
    }
};
const Rows = struct {
    values: [8]O,
    fn read(raw: *const anyopaque, tree: u8, column: u32, offset: i32) !O {
        const self: *const Rows = @ptrCast(@alignCast(raw));
        if (tree > 2 or column >= self.values.len or offset != -1) return error.BadRead;
        return self.values[column];
    }
    fn reader(self: *const Rows) E.Reader {
        return .{ .context = self, .get = read };
    }
};
test "om31 outer IR packs both interaction halves and preserves quartic MAIN" {
    const a = std.testing.allocator;
    var fixture = Fixture{};
    const p = fixture.program();
    try E.validateLens(a, p);
    var rows: Rows = undefined;
    var expected: [8]M = undefined;
    for (&rows.values, &expected, 0..) |*v, *m, i| {
        m.* = M.fromCanonical(@intCast(i + 1));
        v.* = O.fromBase(m.*);
    }
    const roots = try E.evaluate(a, p, rows.reader(), &.{});
    defer a.free(roots);
    try std.testing.expect(roots[0].eql(O.fromM31Array(expected)));
    rows.values[4] = rows.values[4].add(O.one());
    const mutated = try E.evaluate(a, p, rows.reader(), &.{});
    defer a.free(mutated);
    try std.testing.expect(!mutated[0].eql(roots[0]));
    for (fixture.base[0..4]) |*i| i.interaction = 1;
    const main = try E.evaluate(a, fixture.program(), rows.reader(), &.{});
    defer a.free(main);
    try std.testing.expect(main[0].eql(E.embed(P.Q.fromM31Array(expected[0..4].*))));
}
test "om31 outer IR lens also reconstructs arbitrary secure OODS evaluations" {
    const a = std.testing.allocator;
    var fixture = Fixture{};
    var rows: Rows = undefined;
    for (&rows.values, 0..) |*v, i| {
        var limbs: [8]M = undefined;
        for (&limbs, 0..) |*m, j| m.* = M.fromCanonical(@intCast(17 * i + j + 1));
        v.* = O.fromM31Array(limbs);
    }
    const roots = try E.evaluate(a, fixture.program(), rows.reader(), &.{});
    defer a.free(roots);
    try std.testing.expect(roots[0].eql(O.fromPartialEvals(rows.values)));
    fixture.ext[0] = .{ .op = .param, .dst = 0, .a = 0, .b = 0, .c = 0, .d = 0 };
    var p = fixture.program();
    p.header.n_ext_params = 1;
    const parameter = try E.evaluate(a, p, rows.reader(), &.{rows.values[7]});
    defer a.free(parameter);
    try std.testing.expect(parameter[0].eql(rows.values[7]));
}
test "om31 outer IR rejects mixed offset misaligned and arithmetic interaction packs" {
    const a = std.testing.allocator;
    var fixture = Fixture{};
    fixture.base[3].imm = 0;
    try std.testing.expectError(error.InvalidOm31InteractionPack, E.validateLens(a, fixture.program()));
    fixture = Fixture{};
    fixture.base[0].a = 1;
    try std.testing.expectError(error.InvalidOm31InteractionPack, E.validateLens(a, fixture.program()));
    fixture = Fixture{};
    var p = fixture.program();
    p.base_insts = &fixture.base;
    try std.testing.expectError(error.UnsupportedOm31InteractionArithmetic, E.validateLens(a, p));
}
test "om31 outer IR admission covers every original pinned circuit component" {
    const a = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(a, "vectors/circuit/official/circuit_air.air_programs_v1.bin", 64 << 20);
    defer a.free(bytes);
    var bundle = try @import("../air.zig").parse(a, bytes);
    defer bundle.deinit();
    try std.testing.expectEqual(@as(usize, 11), bundle.components.len);
    for (bundle.components) |c| for (c.parts) |part| try E.validateLens(a, part.program);
}

test "om31 outer masks authenticate both physical interaction halves" {
    const a = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(a, "vectors/circuit/official/circuit_air.air_programs_v1.bin", 64 << 20);
    defer a.free(bytes);
    var bundle = try @import("../air.zig").parse(a, bytes);
    defer bundle.deinit();
    const G = @import("geometry.zig");
    const Original = C.resident_geometry;
    for (bundle.components) |c| {
        const logical = try Original.componentOffsets(a, c, 2);
        defer Original.freeOffsetLists(a, logical);
        const physical = try G.offsets(a, c, 2);
        defer G.freeOffsets(a, physical);
        try std.testing.expectEqual(logical.len * 2, physical.len);
        for (logical, 0..) |list, i| {
            const low = 8 * (i / 4) + i % 4;
            try std.testing.expectEqualSlices(i32, list.items, physical[low].items);
            try std.testing.expectEqualSlices(i32, list.items, physical[low + 4].items);
        }
        const old_span = try Original.componentSpan(c, 2);
        const new_span = try G.span(c, 2);
        try std.testing.expectEqual(old_span.start * 2, new_span.start);
        try std.testing.expectEqual(old_span.end * 2, new_span.end);
    }
}
