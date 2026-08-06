const std = @import("std");
const cost = @import("materialization_cost.zig");
const fixed = @import("materialization_fixed_direct.zig");
const ir = @import("ir.zig");
const poseidon_fixed = @import("typed_poseidon2_fixed_direct.zig");
const source = @import("source.zig");
const types = @import("types.zig");

test "fixed cost rejects missing programs gates and physical placement overflow" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const roots = [_]types.ValueId{fixture.root};

    try std.testing.expectError(error.FixedRootCountMismatch, cost.analyze(
        std.testing.allocator,
        &fixture.arena,
        .{
            .roots = &roots,
            .gate = fixture.gate,
            .selected = &roots,
            .geometry = .{ .fixed_direct_roots = 1 },
        },
    ));
    try std.testing.expectError(error.MissingFixedGate, cost.analyze(
        std.testing.allocator,
        &fixture.arena,
        .{
            .roots = &roots,
            .gate = null,
            .selected = &roots,
            .geometry = .{ .fixed_direct_roots = poseidon_fixed.fixed_root_count },
            .fixed_direct_program = poseidon_fixed.program,
        },
    ));
    try std.testing.expectError(error.FixedColumnOutOfBounds, cost.analyze(
        std.testing.allocator,
        &fixture.arena,
        .{
            .roots = &roots,
            .gate = fixture.gate,
            .selected = &roots,
            .geometry = .{
                .base_main_columns = 1,
                .fixed_direct_roots = poseidon_fixed.fixed_root_count,
            },
            .fixed_direct_program = poseidon_fixed.program,
        },
    ));
}

test "fixed cost enforces the candidate degree budget" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const roots = [_]types.ValueId{fixture.root};
    const columns = [_]fixed.Column{.{
        .role = "gate",
        .binding = .gate,
        .tree = .main,
        .placement = .{ .absolute = 0 },
    }};
    const nodes = [_]fixed.Node{
        .{ .op = .column, .value = 0 },
        .{ .op = .mul, .lhs = 0, .rhs = 0 },
        .{ .op = .mul, .lhs = 1, .rhs = 1 },
    };
    const fixed_roots = [_]fixed.NodeId{@enumFromInt(2)};
    const program = fixed.Program{
        .scope_id = "test.degree-four",
        .scope_version = 1,
        .materialization_tree = .main,
        .materialization_column_start = 1,
        .columns = &columns,
        .nodes = &nodes,
        .prefix_roots = &fixed_roots,
        .suffix_roots = &.{},
    };
    try std.testing.expectEqual(
        @as(u64, 4),
        try program.maximumRootDegree(std.testing.allocator),
    );
    try std.testing.expectError(error.FixedDegreeExceedsBudget, cost.analyze(
        std.testing.allocator,
        &fixture.arena,
        .{
            .roots = &roots,
            .gate = fixture.gate,
            .selected = &roots,
            .geometry = .{ .base_main_columns = 1, .fixed_direct_roots = 1 },
            .fixed_direct_program = program,
        },
    ));
}

test "fixed cost rejects component columns that alias materializations" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const roots = [_]types.ValueId{fixture.root};
    const columns = [_]fixed.Column{.{
        .role = "alias",
        .binding = .component,
        .tree = .main,
        .placement = .{ .absolute = 19 },
    }};
    const nodes = [_]fixed.Node{.{ .op = .column, .value = 0 }};
    const fixed_roots = [_]fixed.NodeId{@enumFromInt(0)};
    const program = fixed.Program{
        .scope_id = "test.materialization-alias",
        .scope_version = 1,
        .materialization_tree = .main,
        .materialization_column_start = 19,
        .columns = &columns,
        .nodes = &nodes,
        .prefix_roots = &fixed_roots,
        .suffix_roots = &.{},
    };

    try std.testing.expectError(error.FixedColumnAliasesMaterialization, cost.analyze(
        std.testing.allocator,
        &fixture.arena,
        .{
            .roots = &roots,
            .gate = fixture.gate,
            .selected = &roots,
            .geometry = .{ .base_main_columns = 19, .fixed_direct_roots = 1 },
            .fixed_direct_program = program,
        },
    ));
}

test "fixed cost rejects non-main materialization trees before accounting" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const roots = [_]types.ValueId{fixture.root};

    inline for (.{ fixed.CommitmentTree.preprocessed, .interaction }) |tree| {
        var program = poseidon_fixed.program;
        program.materialization_tree = tree;
        try std.testing.expectError(error.UnsupportedMaterializationTree, cost.analyze(
            std.testing.allocator,
            &fixture.arena,
            .{
                .roots = &roots,
                .gate = fixture.gate,
                .selected = &roots,
                .geometry = .{
                    .preprocessed_columns = 32,
                    .base_main_columns = 19,
                    .fixed_direct_roots = poseidon_fixed.fixed_root_count,
                    .interaction_columns = 32,
                },
                .fixed_direct_program = program,
            },
        ));
    }
}

const Fixture = struct {
    arena: ir.Arena,
    gate: types.ValueId,
    root: types.ValueId,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const generated = source.SourceSpan.generated();
        return .{
            .gate = try arena.input("gate", .selector, generated),
            .root = try arena.input("root", .felt, generated),
            .arena = arena,
        };
    }

    fn deinit(self: *Fixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
