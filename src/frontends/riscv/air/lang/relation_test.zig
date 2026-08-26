const std = @import("std");
const production = @import("../lookups/entry.zig");
const relation = @import("relation.zig");
const types = @import("types.zig");

test "relation domain and role wire tags are pinned to production" {
    const logical_domains = std.meta.tags(relation.Domain);
    const production_domains = std.meta.tags(production.Domain);
    try std.testing.expectEqual(@as(usize, 47), logical_domains.len);
    try std.testing.expectEqual(@as(usize, 12), production_domains.len);
    for (logical_domains[0..production_domains.len], production_domains, 0..) |logical, shipped, index| {
        try std.testing.expectEqual(index, @intFromEnum(logical));
        try std.testing.expectEqual(index, @intFromEnum(shipped));
    }
    try std.testing.expectEqual(relation.Domain.recursion_merkle_node, logical_domains[12]);
    try std.testing.expectEqual(relation.Domain.recursion_wire, logical_domains[13]);
    try std.testing.expectEqual(relation.Domain.recursion_step, logical_domains[14]);

    const logical_roles = std.meta.tags(relation.Role);
    const production_roles = std.meta.tags(production.EventRole);
    try std.testing.expectEqual(@as(usize, 3), logical_roles.len);
    try std.testing.expectEqual(logical_roles.len, production_roles.len);
    for (logical_roles, production_roles, 0..) |logical, shipped, index| {
        try std.testing.expectEqual(index, @intFromEnum(logical));
        try std.testing.expectEqual(index, @intFromEnum(shipped));
    }
}

test "relation registry appends exact universal recursion order without changing production prefix" {
    try std.testing.expectEqual(@as(usize, 12), relation.schemas.len);
    try std.testing.expectEqual(@as(usize, 35), relation.extension_schemas.len);
    const merkle_node = relation.get(.recursion_merkle_node);
    try std.testing.expectEqual(@as(usize, 12), types.idIndex(merkle_node.id));
    try std.testing.expectEqualStrings("MerkleNodeRelation", merkle_node.name);
    try std.testing.expectEqual(@as(usize, 11), merkle_node.fields.len);
    const schema = relation.get(.recursion_wire);
    try std.testing.expectEqual(@as(usize, 13), types.idIndex(schema.id));
    try std.testing.expectEqualStrings("WireRelation", schema.name);
    try std.testing.expectEqual(@as(usize, 6), schema.fields.len);
    const step = relation.get(.recursion_step);
    try std.testing.expectEqual(@as(usize, 14), types.idIndex(step.id));
    try std.testing.expectEqualStrings("VerifierStepRelation", step.name);
    try std.testing.expectEqual(@as(usize, 7), step.fields.len);
    const tail = relation.get(.recursion_fri_verifier_route_word);
    try std.testing.expectEqual(@as(usize, 46), types.idIndex(tail.id));
    try std.testing.expectEqualStrings("FriVerifierRouteWordRelation", tail.name);
    try std.testing.expectEqual(@as(usize, 6), tail.fields.len);
    const fields = [_]types.Type{.felt} ** 6;
    try relation.validateEvent(schema.id, .consume, &fields, null);
    try relation.validateEvent(schema.id, .emit, &fields, null);
    try std.testing.expectError(
        error.InvalidRole,
        relation.validateEvent(schema.id, .request, &fields, null),
    );
}

test "universal relation registry order digest is pinned" {
    try std.testing.expectEqualStrings(
        relation.REGISTRY_ORDER_DIGEST_HEX,
        &std.fmt.bytesToHex(relation.registryOrderDigest(), .lower),
    );
}

test "universal relation registry digest rejects order name and arity mutation" {
    const honest = relation.registryOrderDigest();
    var descriptors = relation.universal_descriptors;
    std.mem.swap(
        relation.UniversalDescriptor,
        &descriptors[0],
        &descriptors[1],
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &honest,
        &relation.computeRegistryOrderDigest(&descriptors),
    ));
    descriptors = relation.universal_descriptors;
    descriptors[0].reference_name = "memory_access";
    try std.testing.expect(!std.mem.eql(
        u8,
        &honest,
        &relation.computeRegistryOrderDigest(&descriptors),
    ));
    descriptors = relation.universal_descriptors;
    descriptors[0].arity -= 1;
    try std.testing.expect(!std.mem.eql(
        u8,
        &honest,
        &relation.computeRegistryOrderDigest(&descriptors),
    ));
}

test "universal registry exposes and fails closed on base Merkle ABI gap" {
    const descriptor = relation.universalDescriptor(.merkle);
    const shipped = relation.get(.merkle);
    try std.testing.expectEqual(
        @as(u8, relation.BASE_MERKLE_UNIVERSAL_ARITY),
        descriptor.arity,
    );
    try std.testing.expectEqual(
        @as(usize, relation.BASE_MERKLE_SHIPPED_ARITY),
        shipped.fields.len,
    );
    try std.testing.expectEqualStrings(
        "base_merkle_abi_4_vs_recursion_18",
        relation.BASE_MERKLE_ABI_GAP,
    );
    try std.testing.expectError(
        error.UniversalSchemaMismatch,
        relation.requireExactUniversalSchema(.merkle),
    );
    try std.testing.expectEqual(
        relation.get(.recursion_wire),
        try relation.requireExactUniversalSchema(.recursion_wire),
    );
}

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
    try relation.validateEvent(
        relation.id(.range_check_8_8),
        .request,
        &.{ .byte, .byte },
        null,
    );
    try std.testing.expectError(
        error.InvalidRole,
        relation.validateEvent(
            relation.id(.range_check_8_8),
            .consume,
            &.{ .byte, .byte },
            null,
        ),
    );
    try std.testing.expectError(
        error.InvalidRole,
        relation.validateEvent(
            relation.id(.range_check_8_8),
            .emit,
            &.{ .byte, .byte },
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

test "universal recursion relations preserve bounded scalar refinements" {
    try relation.validateEvent(
        relation.id(.recursion_vm_public_claim_byte),
        .emit,
        &.{ .felt, .felt, .byte },
        null,
    );
    try std.testing.expectError(
        error.InvalidFieldType,
        relation.validateEvent(
            relation.id(.recursion_vm_public_claim_byte),
            .emit,
            &.{ .felt, .felt, try types.Type.staticArray(.byte, 1) },
            null,
        ),
    );
    // The broader BaseField ABI applies only to universal recursion schemas.
    // Exact VM table schemas must still reject a different scalar refinement.
    try std.testing.expectError(
        error.InvalidFieldType,
        relation.validateEvent(
            relation.id(.range_check_8_8),
            .request,
            &.{ .selector, .byte },
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

test "relation shape validation preserves metadata without claiming field types" {
    const schema = try relation.validateEventShape(
        relation.id(.memory_access),
        .consume,
        7,
        1,
    );
    try std.testing.expectEqual(relation.Domain.memory_access, schema.domain);
    try std.testing.expectError(
        error.InvalidArity,
        relation.validateEventShape(
            relation.id(.memory_access),
            .consume,
            6,
            1,
        ),
    );
    try std.testing.expectError(
        error.UnexpectedAccessOrdinal,
        relation.validateEventShape(
            relation.id(.program_access),
            .request,
            5,
            1,
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
