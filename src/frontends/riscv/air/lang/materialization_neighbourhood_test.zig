const std = @import("std");
const cut_set = @import("materialization_cut_set.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const neighbourhood = @import("materialization_neighbourhood.zig");
const poseidon = @import("typed_poseidon2.zig");
const source = @import("source.zig");
const types = @import("types.zig");

test "semantic-edge edits have one canonical interleaved sequence and prefix cap" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var cut = try fixture.makeCut(std.testing.allocator, false);
    defer cut.deinit();

    const expected = [_]cut_set.Edit{
        .{ .remove = fixture.x },
        .{ .add = fixture.p },
        .{ .swap = .{ .remove = fixture.y, .add = fixture.p } },
        .{ .remove = fixture.y },
        .{ .add = fixture.q },
        .{ .swap = .{ .remove = fixture.y, .add = fixture.q } },
        .{ .add = fixture.joined },
    };
    for (0..expected.len + 2) |cap| {
        var actual = try neighbourhood.Neighbourhood.init(
            std.testing.allocator,
            &fixture.arena,
            &cut,
            cap,
        );
        defer actual.deinit();

        const retained = @min(cap, expected.len);
        try std.testing.expectEqual(retained, actual.edits.len);
        try std.testing.expectEqual(cap < expected.len, actual.truncated);
        for (expected[0..retained], actual.edits) |wanted, observed|
            try std.testing.expect(std.meta.eql(wanted, observed));
    }
}

test "duplicate ordered roots do not duplicate semantic-edge edits" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var single = try fixture.makeCut(std.testing.allocator, false);
    defer single.deinit();
    var repeated = try fixture.makeCut(std.testing.allocator, true);
    defer repeated.deinit();

    var single_edges = try neighbourhood.Neighbourhood.init(
        std.testing.allocator,
        &fixture.arena,
        &single,
        32,
    );
    defer single_edges.deinit();
    var repeated_edges = try neighbourhood.Neighbourhood.init(
        std.testing.allocator,
        &fixture.arena,
        &repeated,
        32,
    );
    defer repeated_edges.deinit();

    try std.testing.expect(!single_edges.truncated);
    try std.testing.expect(!repeated_edges.truncated);
    try std.testing.expectEqual(single_edges.edits.len, repeated_edges.edits.len);
    for (single_edges.edits, repeated_edges.edits) |wanted, observed|
        try std.testing.expect(std.meta.eql(wanted, observed));
}

test "canonical Poseidon first neighbourhood pins every edit class" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const gate = try arena.input(
        "riscv.poseidon2_m31.enabled",
        .selector,
        generated,
    );
    const definition = try poseidon.define(
        &arena,
        poseidon.DefinitionSpans.uniform(generated),
    );
    const roots = poseidon.values(definition.outputs);
    var plan = try materializer.plan(std.testing.allocator, &arena, .{
        .roots = &roots,
        .gate = gate,
    });
    defer plan.deinit();
    var cut = try cut_set.fromDegree3Plan(std.testing.allocator, &arena, &plan);
    defer cut.deinit();
    var edits = try neighbourhood.Neighbourhood.init(
        std.testing.allocator,
        &arena,
        &cut,
        2_048,
    );
    defer edits.deinit();

    var removals: usize = 0;
    var additions: usize = 0;
    var swaps: usize = 0;
    for (edits.edits) |edit| switch (edit) {
        .remove => removals += 1,
        .add => additions += 1,
        .swap => swaps += 1,
    };
    try std.testing.expect(!edits.truncated);
    try std.testing.expectEqual(@as(usize, 410), removals);
    try std.testing.expectEqual(@as(usize, 304), additions);
    try std.testing.expectEqual(@as(usize, 410), swaps);
    try std.testing.expectEqual(@as(usize, 1_124), edits.edits.len);
    try std.testing.expectEqual(edits.edits.len, removals + additions + swaps);
}

test "public neighbourhood rejects forged out-of-range cut ids" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var cut = try fixture.makeCut(std.testing.allocator, false);
    defer cut.deinit();
    const unknown: types.ValueId = @enumFromInt(fixture.arena.nodeCount() + 7);

    const last = cut.values.len - 1;
    const saved_value = cut.values[last];
    cut.values[last] = unknown;
    try std.testing.expectError(error.InvalidSelection, neighbourhood.Neighbourhood.init(
        std.testing.allocator,
        &fixture.arena,
        &cut,
        32,
    ));
    cut.values[last] = saved_value;

    const saved_root = cut.roots[0];
    cut.roots[0] = unknown;
    try std.testing.expectError(error.InvalidRoot, neighbourhood.Neighbourhood.init(
        std.testing.allocator,
        &fixture.arena,
        &cut,
        32,
    ));
    cut.roots[0] = saved_root;
}

const Fixture = struct {
    arena: ir.Arena,
    x: types.ValueId,
    y: types.ValueId,
    p: types.ValueId,
    q: types.ValueId,
    joined: types.ValueId,
    root: types.ValueId,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const span = source.SourceSpan.generated();
        const a = try arena.input("neighbourhood.a", .felt, span);
        const b = try arena.input("neighbourhood.b", .felt, span);
        const c = try arena.input("neighbourhood.c", .felt, span);
        const d = try arena.input("neighbourhood.d", .felt, span);
        const e = try arena.input("neighbourhood.e", .felt, span);
        const f = try arena.input("neighbourhood.f", .felt, span);
        const x = try arena.mul(a, b, span);
        const y = try arena.mul(x, c, span);
        const p = try arena.mul(y, d, span);
        const q = try arena.mul(y, e, span);
        const joined = try arena.add(p, q, span);
        const root = try arena.mul(joined, f, span);
        return .{
            .arena = arena,
            .x = x,
            .y = y,
            .p = p,
            .q = q,
            .joined = joined,
            .root = root,
        };
    }

    fn deinit(self: *Fixture) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn makeCut(
        self: *const Fixture,
        allocator: std.mem.Allocator,
        duplicate_root: bool,
    ) !cut_set.CutSet {
        const roots = [_]types.ValueId{ self.root, self.root };
        const root_count: usize = if (duplicate_root) 2 else 1;
        return cut_set.build(
            allocator,
            &self.arena,
            .{ .roots = roots[0..root_count], .gate = null },
            &.{ self.root, self.y, self.x },
        );
    }
};
