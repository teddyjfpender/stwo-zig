const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const air = @import("recursion/air/vm_public_claim_hash_authority_v2.zig");
const relation = @import("recursion/air/vm_public_claim_hash_authority_relation_v2.zig");
const subject = @import("recursion/segment_public_claim_hash_authority_v2.zig");
const public_source = @import("recursion/segment_public_outer_source_v2.zig");
const fixture_support = @import("recursion/segment_public_outer_test_support.zig");
const poseidon2_air = @import("air/memory_commitment/poseidon2_air.zig");

test "isolated row13 V2 identity and authenticated relation plan" {
    const actual = try air.computeSemanticDigest(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &air.SEMANTIC_DIGEST, &actual);
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const profile = try air.staticProfile(&definition);
    try std.testing.expectEqualDeep(air.EXPECTED_STATIC_PROFILE, profile);
    try std.testing.expectEqual(
        @as(u16, air.DIRECT_CONSTRAINT_COUNT),
        profile.direct_constraints,
    );
    try std.testing.expectEqual(
        @as(u16, air.RELATION_EVENT_COUNT),
        profile.relation_events,
    );
    _ = try relation.authenticate(&definition);
}

test "isolated row13 V2 witness replays authority calls and bind step atomically" {
    var fixture = try fixture_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const public_prepared = try public_source.preflight(fixture.inputs());
    const prepared = try subject.PreparedV2.init(
        &public_prepared,
        fixture.inputs(),
    );
    try std.testing.expect(!prepared.productionReady());

    const call_count = try prepared.callCount();
    const event_count = try prepared.eventCount();
    const calls = try std.testing.allocator.alloc(poseidon2_air.Call, call_count);
    defer std.testing.allocator.free(calls);
    const rows = try std.testing.allocator.alloc(
        subject.LogicalRowV2,
        prepared.logical_row_count,
    );
    defer std.testing.allocator.free(rows);
    const events = try std.testing.allocator.alloc(
        subject.RelationEventV2,
        event_count,
    );
    defer std.testing.allocator.free(events);
    var relays = relayRows(&public_prepared);

    try subject.writeInto(
        &prepared,
        &public_prepared,
        fixture.inputs(),
        &relays,
        calls,
        rows,
        events,
    );
    try std.testing.expectEqual(@as(u32, 1), rows[0][5].toU32());
    try std.testing.expectEqual(@as(u32, 1), rows[0][4].toU32());
    try std.testing.expectEqual(@as(u32, 1), rows[0][3].toU32());
    for (events) |event| try event.validate();
    try std.testing.expectEqual(
        @import("air/lang/relation.zig").Domain.recursion_step,
        events[1].domain,
    );
    try std.testing.expectEqual(@as(u8, 4), events[1].event_ordinal);
    try std.testing.expectEqual(@as(u32, 1), events[1].tuple[2].toU32());

    @memset(std.mem.sliceAsBytes(rows), 0xa5);
    @memset(std.mem.sliceAsBytes(events), 0xa5);
    const before_rows = digestBytes(std.mem.sliceAsBytes(rows));
    const before_events = digestBytes(std.mem.sliceAsBytes(events));
    relays[0].arithmetic_node_id += 1;
    try std.testing.expectError(
        error.InvalidRelayRow,
        subject.writeInto(
            &prepared,
            &public_prepared,
            fixture.inputs(),
            &relays,
            calls,
            rows,
            events,
        ),
    );
    try std.testing.expectEqual(before_rows, digestBytes(std.mem.sliceAsBytes(rows)));
    try std.testing.expectEqual(before_events, digestBytes(std.mem.sliceAsBytes(events)));
}

fn relayRows(
    prepared: *const public_source.PreparedV2,
) [subject.RELAY_ROW_COUNT]public_source.RelayRowV2 {
    const values = prepared.public_sums.registers_state.toM31Array() ++
        prepared.public_sums.memory_access.toM31Array() ++
        prepared.public_sums.program_access.toM31Array() ++
        prepared.public_sums.merkle.toM31Array();
    var result: [subject.RELAY_ROW_COUNT]public_source.RelayRowV2 = undefined;
    for (&result, values, 0..) |*row, value, index| row.* = .{
        .source_kind = .publication_bridge,
        .source_fields = .{
            public_source.PUBLICATION_BRIDGE_CIRCUIT_ID,
            @intCast(public_source.PUBLICATION_SUM_START + index),
            0,
            0,
            0,
        },
        .value = value,
        .arithmetic_mask = 1,
        .arithmetic_node_id = prepared.manifest.wire_word_count +
            @as(u32, @intCast(index)),
        .arithmetic_use_count = 1,
    };
    return result;
}

fn digestBytes(bytes: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(bytes);
    return hash.finalResult();
}
