const std = @import("std");
const production = @import("../lookups/entry.zig");
const relation = @import("relation.zig");
const types = @import("types.zig");

test "relation registry covers the exact production domain order and arity" {
    const production_domains = std.meta.tags(production.Domain);
    try std.testing.expectEqual(production_domains.len, relation.schemas.len);
    for (production_domains, 0..) |domain, index| {
        const logical = fromProduction(domain);
        const schema = relation.get(logical);
        try std.testing.expectEqual(index, types.idIndex(schema.id));
        try std.testing.expectEqual(logical, schema.domain);
        try std.testing.expectEqual(
            @as(usize, production.expectedArity(domain)),
            schema.fields.len,
        );
        try std.testing.expect(schema.version != 0);
        try std.testing.expect(schema.name.len != 0);
        for (relation.schemas[0..index]) |prior| {
            try std.testing.expect(!std.mem.eql(u8, schema.name, prior.name));
        }
    }
}

test "relation registry accepts only declared roles" {
    try relation.validateEvent(
        relation.id(.registers_state),
        .consume,
        &.{ .pc, .clock },
        null,
    );
    try relation.validateEvent(
        relation.id(.registers_state),
        .emit,
        &.{ .pc, .clock },
        null,
    );
    try std.testing.expectError(
        error.InvalidRole,
        relation.validateEvent(
            relation.id(.range_check_20),
            .emit,
            &.{.uint20},
            null,
        ),
    );
}

test "relation registry rejects invalid arity before field matching" {
    try std.testing.expectError(
        error.InvalidArity,
        relation.validateEvent(
            relation.id(.range_check_8_8),
            .request,
            &.{.byte},
            null,
        ),
    );
}

test "relation registry rejects invalid semantic field types" {
    try relation.validateEvent(
        relation.id(.bitwise),
        .request,
        &.{ .byte, .byte, .byte, try types.Type.boundedField(2) },
        null,
    );
    try std.testing.expectError(
        error.InvalidFieldType,
        relation.validateEvent(
            relation.id(.bitwise),
            .request,
            &.{ .byte, .byte, .felt, try types.Type.boundedField(2) },
            null,
        ),
    );
}

test "relation registry rejects unexpected access ordinals" {
    try relation.validateEvent(
        relation.id(.range_check_20),
        .request,
        &.{.uint20},
        2,
    );
    try std.testing.expectError(
        error.UnexpectedAccessOrdinal,
        relation.validateEvent(
            relation.id(.program_access),
            .request,
            &.{ .pc, .byte, .register_index, .register_index, .felt },
            0,
        ),
    );
}

test "relation registry rejects unknown typed schema IDs" {
    const unknown = try types.idFromIndex(types.RelationSchemaId, 999);
    try std.testing.expect(relation.getById(unknown) == null);
    try std.testing.expectError(
        error.UnknownSchema,
        relation.validateEvent(unknown, .request, &.{}, null),
    );
}

fn fromProduction(domain: production.Domain) relation.Domain {
    return switch (domain) {
        .registers_state => .registers_state,
        .memory_access => .memory_access,
        .program_access => .program_access,
        .merkle => .merkle,
        .poseidon2 => .poseidon2,
        .poseidon2_io => .poseidon2_io,
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
    };
}
