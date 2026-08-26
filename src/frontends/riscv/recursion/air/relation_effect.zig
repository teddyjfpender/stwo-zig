//! Reviewed, failure-atomic authoring path for universal relation effects.
//!
//! Components supply typed value IDs and a field-valued multiplicity. This
//! boundary validates exact registry geometry, semantic field types, roles,
//! and all weights before reserving both arena effect pools. No component is
//! allowed to write a relation binding by hand.

const std = @import("std");
const ir = @import("../../air/lang/ir.zig");
const program = @import("../../air/lang/program.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");

pub const Error = ir.Error || relation.Error || error{
    EmptyRelationGroup,
    InvalidComponentWeight,
    RelationValueCountOverflow,
};

pub const EventSpec = struct {
    domain: relation.Domain,
    role: relation.Role,
    values: []const types.ValueId,
    weight: types.ValueId,
};

/// Append one statically sized semantic relation group. Every semantic check
/// happens before capacity reservation, and both backing pools are reserved
/// before the first append. The checkpoint protects the existing prefix if an
/// allocator implementation violates the expected post-reservation contract.
pub fn appendGroup(
    comptime count: usize,
    arena: *ir.Arena,
    events: [count]EventSpec,
    span: source.SourceSpan,
) Error![count]types.EffectId {
    comptime if (count == 0)
        @compileError("universal relation event group cannot be empty");
    try arena.validateSpan(span);

    var value_count: usize = 0;
    for (events) |event| {
        const schema = try relation.requireExactUniversalSchema(event.domain);
        value_count = std.math.add(
            usize,
            value_count,
            event.values.len,
        ) catch return error.RelationValueCountOverflow;

        const weight = arena.node(event.weight) orelse return error.UnknownValue;
        if (!weight.key.ty.isFieldScalar()) return error.InvalidComponentWeight;

        var field_types: [@import("../../air/lang/effects.zig").MAX_ARITY]types.Type =
            undefined;
        if (event.values.len > field_types.len)
            return error.InvalidArity;
        for (event.values, field_types[0..event.values.len]) |value, *field_type| {
            const node = arena.node(value) orelse return error.UnknownValue;
            field_type.* = node.key.ty;
        }
        try relation.validateEvent(
            schema.id,
            event.role,
            field_types[0..event.values.len],
            null,
        );
    }

    try arena.ensureUnusedEffectCapacity(count, value_count);
    const checkpoint = arena.effectCheckpoint();
    errdefer arena.rollbackToEffectCheckpoint(checkpoint);
    var result: [count]types.EffectId = undefined;
    for (&result, events) |*effect, event| {
        effect.* = try arena.addBoundEffectUnchecked(
            .component_call,
            binding(event.domain, event.role),
            event.values,
            event.weight,
            null,
            span,
        );
    }
    return result;
}

pub fn append(
    arena: *ir.Arena,
    event: EventSpec,
    span: source.SourceSpan,
) Error!types.EffectId {
    return (try appendGroup(1, arena, .{event}, span))[0];
}

pub fn binding(
    domain: relation.Domain,
    role: relation.Role,
) program.RelationBinding {
    const schema = relation.get(domain);
    return .{
        .schema = schema.id,
        .schema_version = schema.version,
        .role = role,
    };
}

test "R-012 universal relation group authors multiple schemas atomically" {
    const validate = @import("../../air/lang/validate.zig");
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const span = source.SourceSpan.generated();
    const active = try arena.input("active", .selector, span);
    const scope = try arena.input("scope", .felt, span);
    const index = try arena.input("index", .felt, span);
    const value = try arena.input("value", .felt, span);
    const low = try arena.input("low", .byte, span);
    const high = try arena.input("high", .byte, span);
    const statement = [_]types.ValueId{ scope, index, value };
    const bytes = [_]types.ValueId{ low, high };

    const effects = try appendGroup(2, &arena, .{
        .{
            .domain = .recursion_statement_word,
            .role = .emit,
            .values = &statement,
            .weight = active,
        },
        .{
            .domain = .range_check_8_8,
            .role = .request,
            .values = &bytes,
            .weight = active,
        },
    }, span);
    try std.testing.expectEqual(@as(usize, 0), types.idIndex(effects[0]));
    try std.testing.expectEqual(@as(usize, 1), types.idIndex(effects[1]));
    try std.testing.expectEqual(@as(usize, 2), arena.effectsView().len);
    try std.testing.expectEqual(@as(usize, 5), arena.effectValuesView().len);
    try validate.validate(&arena);
}

test "R-012 universal relation authoring fails closed on base Merkle ABI gap" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const span = source.SourceSpan.generated();
    const active = try arena.input("active", .selector, span);
    var values: [relation.BASE_MERKLE_UNIVERSAL_ARITY]types.ValueId = undefined;
    for (&values, 0..) |*value, index| {
        var name: [24]u8 = undefined;
        value.* = try arena.input(
            try std.fmt.bufPrint(&name, "merkle.{d}", .{index}),
            .felt,
            span,
        );
    }
    try std.testing.expectError(
        error.UniversalSchemaMismatch,
        append(&arena, .{
            .domain = .merkle,
            .role = .request,
            .values = &values,
            .weight = active,
        }, span),
    );
    try std.testing.expectEqual(@as(usize, 0), arena.effectsView().len);
    try std.testing.expectEqual(@as(usize, 0), arena.effectValuesView().len);
}

test "R-012 universal relation authoring rejects every group before mutation" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const span = source.SourceSpan.generated();
    const active = try arena.input("active", .selector, span);
    const scope = try arena.input("scope", .felt, span);
    const index = try arena.input("index", .felt, span);
    const value = try arena.input("value", .felt, span);
    const wrong = [_]types.ValueId{ scope, index };
    const honest = [_]types.ValueId{ scope, index, value };
    try std.testing.expectError(
        error.InvalidArity,
        appendGroup(2, &arena, .{
            .{
                .domain = .recursion_statement_word,
                .role = .emit,
                .values = &honest,
                .weight = active,
            },
            .{
                .domain = .recursion_statement_word,
                .role = .consume,
                .values = &wrong,
                .weight = active,
            },
        }, span),
    );
    try std.testing.expectEqual(@as(usize, 0), arena.effectsView().len);
    try std.testing.expectEqual(@as(usize, 0), arena.effectValuesView().len);
}

test "R-012 universal relation group releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var arena = ir.Arena.init(allocator);
    defer arena.deinit();
    const span = source.SourceSpan.generated();
    const active = try arena.input("active", .selector, span);
    const scope = try arena.input("scope", .felt, span);
    const index = try arena.input("index", .felt, span);
    const value = try arena.input("value", .felt, span);
    const tuple = [_]types.ValueId{ scope, index, value };
    _ = try appendGroup(3, &arena, .{
        .{ .domain = .recursion_statement_word, .role = .emit, .values = &tuple, .weight = active },
        .{ .domain = .recursion_statement_word, .role = .consume, .values = &tuple, .weight = active },
        .{ .domain = .recursion_vm_public_claim_word, .role = .emit, .values = &tuple, .weight = active },
    }, span);
}
