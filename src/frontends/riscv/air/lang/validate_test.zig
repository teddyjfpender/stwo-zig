const std = @import("std");
const effects = @import("effects.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const test_support = @import("test_support.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

test "validator rejects InvalidName" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.names.items[0];
    defer fixture.arena.names.items[0] = saved;
    fixture.arena.names.items[0] = saved[0..0];
    try std.testing.expectError(error.InvalidName, validate.validate(&fixture.arena));
}

test "validator rejects DuplicateName" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.names.items[1];
    defer fixture.arena.names.items[1] = saved;
    fixture.arena.names.items[1] = fixture.arena.names.items[0];
    try std.testing.expectError(error.DuplicateName, validate.validate(&fixture.arena));
}

test "validator rejects InvalidSource" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.sources.items[0].path;
    defer fixture.arena.sources.items[0].path = saved;
    fixture.arena.sources.items[0].path = try types.idFromIndex(types.NameId, 999);
    try std.testing.expectError(error.InvalidSource, validate.validate(&fixture.arena));
}

test "validator rejects DuplicateSource" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.sources.items[1].path;
    defer fixture.arena.sources.items[1].path = saved;
    fixture.arena.sources.items[1].path = fixture.arena.sources.items[0].path;
    try std.testing.expectError(error.DuplicateSource, validate.validate(&fixture.arena));
}

test "validator rejects InvalidSourceSpan" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.hints.items[0].source_span;
    defer fixture.arena.hints.items[0].source_span = saved;
    fixture.arena.hints.items[0].source_span = .{
        .source = null,
        .start = .{ .byte_offset = 0, .line = 1, .column = 1 },
        .end = source.Position.generated,
    };
    try std.testing.expectError(
        error.InvalidSourceSpan,
        validate.validate(&fixture.arena),
    );
}

test "validator rejects InvalidType" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const index = types.idIndex(fixture.lhs);
    const saved = fixture.arena.nodes.items[index].key.ty;
    defer fixture.arena.nodes.items[index].key.ty = saved;
    fixture.arena.nodes.items[index].key.ty = .{ .bounded_uint = .{
        .bits = 0,
        .representation = .canonical_field,
    } };
    try std.testing.expectError(error.InvalidType, validate.validate(&fixture.arena));
}

test "validator rejects InvalidNodeReference" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const index = types.idIndex(fixture.sum);
    const saved = fixture.arena.nodes.items[index].key;
    defer fixture.arena.nodes.items[index].key = saved;
    fixture.arena.nodes.items[index].key.op = .{ .add = .{
        .lhs = try types.idFromIndex(types.ValueId, 999),
        .rhs = fixture.rhs,
    } };
    try std.testing.expectError(
        error.InvalidNodeReference,
        validate.validate(&fixture.arena),
    );
}

test "validator rejects InvalidNodeOrder" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const index = types.idIndex(fixture.sum);
    const saved = fixture.arena.nodes.items[index].key;
    defer fixture.arena.nodes.items[index].key = saved;
    fixture.arena.nodes.items[index].key.op = .{ .add = .{
        .lhs = fixture.sum,
        .rhs = fixture.rhs,
    } };
    try std.testing.expectError(error.InvalidNodeOrder, validate.validate(&fixture.arena));
}

test "validator rejects InvalidNodeShape" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const index = types.idIndex(fixture.negated);
    const saved = fixture.arena.nodes.items[index].key.ty;
    defer fixture.arena.nodes.items[index].key.ty = saved;
    fixture.arena.nodes.items[index].key.ty = .word32;
    try std.testing.expectError(error.InvalidNodeShape, validate.validate(&fixture.arena));
}

test "validator rejects NonCanonicalNode" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const index = types.idIndex(fixture.sum);
    const saved = fixture.arena.nodes.items[index].key;
    defer fixture.arena.nodes.items[index].key = saved;
    fixture.arena.nodes.items[index].key.op = .{ .add = .{
        .lhs = fixture.rhs,
        .rhs = fixture.lhs,
    } };
    try std.testing.expectError(error.NonCanonicalNode, validate.validate(&fixture.arena));
}

test "validator rejects DuplicateNode" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const index = types.idIndex(fixture.negated);
    const saved = fixture.arena.nodes.items[index].key;
    defer fixture.arena.nodes.items[index].key = saved;
    fixture.arena.nodes.items[index].key =
        fixture.arena.nodes.items[types.idIndex(fixture.sum)].key;
    try std.testing.expectError(error.DuplicateNode, validate.validate(&fixture.arena));
}

test "validator rejects InvalidInternTable" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const index = types.idIndex(fixture.sum);
    const saved = fixture.arena.nodes.items[index].key;
    defer fixture.arena.nodes.items[index].key = saved;
    fixture.arena.nodes.items[index].key.op = .{ .sub = .{
        .lhs = fixture.lhs,
        .rhs = fixture.rhs,
    } };
    try std.testing.expectError(
        error.InvalidInternTable,
        validate.validate(&fixture.arena),
    );
}

test "validator rejects InvalidRange" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.hints.items[0].inputs.start;
    defer fixture.arena.hints.items[0].inputs.start = saved;
    fixture.arena.hints.items[0].inputs.start = 1;
    try std.testing.expectError(error.InvalidRange, validate.validate(&fixture.arena));
}

test "validator rejects InvalidHint" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.hint_inputs.items[0];
    defer fixture.arena.hint_inputs.items[0] = saved;
    fixture.arena.hint_inputs.items[0] = fixture.word;
    try std.testing.expectError(error.InvalidHint, validate.validate(&fixture.arena));
}

test "validator rejects UnknownHintRecipe" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.hints.items[0].recipe;
    defer fixture.arena.hints.items[0].recipe = saved;
    fixture.arena.hints.items[0].recipe = try types.idFromIndex(
        types.HintRecipeId,
        999,
    );
    try std.testing.expectError(
        error.UnknownHintRecipe,
        validate.validate(&fixture.arena),
    );
}

test "validator rejects InvalidHintOutput" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.hint_outputs.items[0];
    defer fixture.arena.hint_outputs.items[0] = saved;
    fixture.arena.hint_outputs.items[0] = fixture.lhs;
    try std.testing.expectError(
        error.InvalidHintOutput,
        validate.validate(&fixture.arena),
    );
}

test "validator rejects InvalidHintBinding" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.hint_binding_values.items[0];
    defer fixture.arena.hint_binding_values.items[0] = saved;
    fixture.arena.hint_binding_values.items[0] = fixture.lhs;
    try std.testing.expectError(
        error.InvalidHintBinding,
        validate.validate(&fixture.arena),
    );
}

test "validator rejects UnboundHintOutput" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.hints.items[0].bindings;
    defer fixture.arena.hints.items[0].bindings = saved;
    fixture.arena.hints.items[0].bindings = null;
    try std.testing.expectError(
        error.UnboundHintOutput,
        validate.validate(&fixture.arena),
    );
}

test "validator rejects InvalidCall for a missing callee" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.calls.items[0].callee;
    defer fixture.arena.calls.items[0].callee = saved;
    fixture.arena.calls.items[0].callee = try types.idFromIndex(
        types.FunctionId,
        999,
    );
    try std.testing.expectError(error.InvalidCall, validate.validate(&fixture.arena));
}

test "validator rejects InvalidCallGraph for a recursive self-cycle" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.calls.items[0].callee;
    defer fixture.arena.calls.items[0].callee = saved;
    fixture.arena.calls.items[0].callee = fixture.arena.calls.items[0].caller.?;
    try std.testing.expectError(
        error.InvalidCallGraph,
        validate.validate(&fixture.arena),
    );
}

test "validator rejects InvalidCallOutput" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.call_outputs.items[0];
    defer fixture.arena.call_outputs.items[0] = saved;
    fixture.arena.call_outputs.items[0] = fixture.lhs;
    try std.testing.expectError(
        error.InvalidCallOutput,
        validate.validate(&fixture.arena),
    );
}

test "validator rejects InvalidConstraint" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.constraints.items[0].root;
    defer fixture.arena.constraints.items[0].root = saved;
    fixture.arena.constraints.items[0].root = fixture.word;
    try std.testing.expectError(
        error.InvalidConstraint,
        validate.validate(&fixture.arena),
    );
}

test "validator rejects DuplicateConstraintName" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.constraints.items[1].name;
    defer fixture.arena.constraints.items[1].name = saved;
    fixture.arena.constraints.items[1].name = fixture.arena.constraints.items[0].name;
    try std.testing.expectError(
        error.DuplicateConstraintName,
        validate.validate(&fixture.arena),
    );
}

test "validator rejects InvalidEffect" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.effect_values.items[0];
    defer fixture.arena.effect_values.items[0] = saved;
    fixture.arena.effect_values.items[0] = try types.idFromIndex(types.ValueId, 999);
    try std.testing.expectError(error.InvalidEffect, validate.validate(&fixture.arena));
}

test "validator rejects InvalidAccessOrdinal" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.effects.items[0].access_ordinal;
    defer fixture.arena.effects.items[0].access_ordinal = saved;
    fixture.arena.effects.items[0].access_ordinal = null;
    try std.testing.expectError(
        error.InvalidAccessOrdinal,
        validate.validate(&fixture.arena),
    );
}

test "validator rejects DuplicateAccessOrdinal" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.effects.items[1].access_ordinal;
    defer fixture.arena.effects.items[1].access_ordinal = saved;
    fixture.arena.effects.items[1].access_ordinal = 0;
    try std.testing.expectError(
        error.DuplicateAccessOrdinal,
        validate.validate(&fixture.arena),
    );
}

test "all-unbound mode retains provisional legacy effect validation" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const value = try arena.input("value", .felt, generated);
    _ = try arena.addEffect(
        .state_consume,
        &.{value},
        null,
        null,
        generated,
    );
    try validate.validate(&arena);
}

test "typed mode rejects mixed unbound relation effects but permits public effects" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const pc = try arena.input("pc", .pc, generated);
    const value = try arena.input("value", .felt, generated);
    const active = try arena.input("active", .bit, generated);

    _ = try effects.programFetch(
        &arena,
        .{
            .pc = pc,
            .opcode_id = value,
            .rd = value,
            .rs1 = value,
            .operand = value,
        },
        active,
        generated,
    );
    _ = try arena.addEffect(
        .register_read,
        &.{value},
        active,
        0,
        generated,
    );
    try std.testing.expectError(error.InvalidEffect, validate.validate(&arena));

    arena.effects.items[1].kind = .component_call;
    arena.effects.items[1].access_ordinal = null;
    try std.testing.expectError(error.InvalidEffect, validate.validate(&arena));

    arena.effects.items[1].kind = .public_consume;
    try validate.validate(&arena);
}

test "unreviewed bound effect families fail closed" {
    const Shape = enum { memory, range, program };
    const Case = struct {
        kind: program.EffectKind,
        domain: relation.Domain,
        role: relation.Role,
        ordinal: ?u8,
        shape: Shape,
    };
    const cases = [_]Case{
        .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .ordinal = 0, .shape = .memory },
        .{ .kind = .register_write, .domain = .memory_access, .role = .emit, .ordinal = 0, .shape = .memory },
        .{ .kind = .memory_read, .domain = .memory_access, .role = .consume, .ordinal = 1, .shape = .memory },
        .{ .kind = .memory_write, .domain = .memory_access, .role = .emit, .ordinal = 1, .shape = .memory },
        .{ .kind = .range_request, .domain = .range_check_20, .role = .request, .ordinal = null, .shape = .range },
        .{ .kind = .component_call, .domain = .program_access, .role = .request, .ordinal = null, .shape = .program },
    };

    for (cases) |case| {
        var arena = ir.Arena.init(std.testing.allocator);
        defer arena.deinit();
        const generated = source.SourceSpan.generated();
        const felt = try arena.input("felt", .felt, generated);
        const pc = try arena.input("pc", .pc, generated);
        const address = try arena.input("address", .address, generated);
        const clock = try arena.input("clock", .clock, generated);
        const byte = try arena.input("byte", .byte, generated);
        const uint20 = try arena.input("uint20", .uint20, generated);
        const active = try arena.input("active", .bit, generated);
        const memory_values = [_]types.ValueId{
            felt, address, clock, byte, byte, byte, byte,
        };
        const range_values = [_]types.ValueId{uint20};
        const program_values = [_]types.ValueId{ pc, felt, felt, felt, felt };
        const values: []const types.ValueId = switch (case.shape) {
            .memory => &memory_values,
            .range => &range_values,
            .program => &program_values,
        };
        const schema = relation.get(case.domain);
        _ = try arena.addBoundEffectUnchecked(
            case.kind,
            .{
                .schema = schema.id,
                .schema_version = schema.version,
                .role = case.role,
            },
            values,
            active,
            case.ordinal,
            generated,
        );
        try std.testing.expectError(error.InvalidEffect, validate.validate(&arena));
    }
}

test "validator rejects InvalidFunction" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.function_inputs.items[0];
    defer fixture.arena.function_inputs.items[0] = saved;
    fixture.arena.function_inputs.items[0] = fixture.sum;
    try std.testing.expectError(error.InvalidFunction, validate.validate(&fixture.arena));
}

test "validator rejects DuplicateFunctionName" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const saved = fixture.arena.functions.items[1].name;
    defer fixture.arena.functions.items[1].name = saved;
    fixture.arena.functions.items[1].name = fixture.arena.functions.items[0].name;
    try std.testing.expectError(
        error.DuplicateFunctionName,
        validate.validate(&fixture.arena),
    );
}
