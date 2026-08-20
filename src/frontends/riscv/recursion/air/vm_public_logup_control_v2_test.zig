//! Exactness, mutation, custody, and hot-path gates for V2 roster row 17.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const air = @import("vm_public_logup_control_v2.zig");
const binding = @import("vm_public_logup_control_relation_v2.zig");
const direct_program = @import("direct_constraint_program.zig");
const fixed_profile = @import("../fixed_profile.zig");
const channel = @import("../poseidon2_channel.zig");
const protocol = @import("../protocol.zig");
const schedule = @import("verifier_schedule.zig");
const witness = @import("vm_public_logup_control_witness_v2.zig");

test "V2 row17 typed AIR pins exact semantic and performance profiles" {
    try std.testing.expectEqualStrings(
        air.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(
            try air.computeSemanticDigest(std.testing.allocator),
            .lower,
        ),
    );
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    try definition.validate();

    const identity = try digest.computeIdentity(&definition.arena);
    try std.testing.expectEqual(air.SEMANTIC_DIGEST, identity.bytes);
    try std.testing.expectEqual(
        air.EXPECTED_STATIC_PROFILE,
        try air.staticProfile(&definition),
    );
    const direct = try direct_program.authenticate(
        &definition.arena,
        air.SEMANTIC_DIGEST,
        air.LOGICAL_INPUT_COUNT,
    );
    try std.testing.expectEqual(@as(u16, 21), direct.node_count);
    try std.testing.expectEqual(@as(u16, 11), direct.compiled_node_count);
    try std.testing.expectEqual(@as(u16, 4), direct.constraint_count);

    const relation_plan = try binding.authenticate(&definition);
    try std.testing.expectEqual(@as(u16, 2), relation_plan.compiled_node_count);
    try std.testing.expectEqual(@as(usize, 1), binding.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 4), binding.Runtime.INTERACTION_COLUMN_COUNT);
    try std.testing.expectEqual(
        relation.Domain.recursion_step,
        relation_plan.events[0].domain,
    );
    try std.testing.expectEqual(relation.Role.consume, relation_plan.events[0].role);
    try std.testing.expectEqual(
        relation.Domain.recursion_wire,
        relation_plan.events[1].domain,
    );
    try std.testing.expectEqual(relation.Role.consume, relation_plan.events[1].role);
    for (relation_plan.events) |event|
        try std.testing.expect(event.role != .emit);
}

test "V2 row17 materializes 70 terms one assertion and one external relay consume" {
    var plan = try testPlan(std.testing.allocator, schedule.VM_PROGRAM_SPEC_V1);
    defer plan.deinit();
    const relay = witness.ControlRelayV2{
        .value = M31.fromCanonical(0x1234_567),
    };
    const prepared = try witness.preflight(&plan, &relay);
    try prepared.validate();
    try prepared.validateAgainst(&plan, &relay);
    try std.testing.expectEqual(@as(usize, 71), prepared.rows.len);
    try std.testing.expectEqual(@as(usize, 72), witness.ACTIVE_RELATION_EVENT_COUNT);
    try std.testing.expectEqual(@as(usize, 0), witness.HOT_HEAP_ALLOCATIONS);

    for (prepared.rows[0..witness.PUBLIC_TERM_COUNT], 0..) |row, term| {
        try std.testing.expectEqual(witness.ACCUMULATE_TAG, row.tag);
        try std.testing.expectEqual(@as(u32, @intCast(term)), row.args[0]);
        try std.testing.expectEqual(
            witness.PUBLIC_PHASE_FIRST_SEQUENCE + @as(u32, @intCast(term)),
            row.sequence,
        );
        try std.testing.expectEqual(@as(u32, 0), row.control_mask);
        try std.testing.expect(row.control_value.isZero());
    }
    const assertion = prepared.rows[witness.PUBLIC_TERM_COUNT];
    try std.testing.expectEqual(witness.GLOBAL_ASSERT_TAG, assertion.tag);
    try std.testing.expectEqual(witness.GLOBAL_ASSERT_SEQUENCE, assertion.sequence);
    try std.testing.expectEqual(@as(u32, 1), assertion.control_mask);
    try std.testing.expect(assertion.control_value.eql(relay.value));

    var owned = OwnedDestinations.sentinel();
    try witness.writeInto(&prepared, owned.view());
    try expectExactTrace(&owned, relay.value);

    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const direct = try direct_program.authenticate(
        &definition.arena,
        air.SEMANTIC_DIGEST,
        air.LOGICAL_INPUT_COUNT,
    );
    var scratch: [direct_program.MAX_NODES]M31 = undefined;
    var roots: [air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (owned.logical_rows) |row| {
        try direct.evaluateBaseInto(&row, &scratch, &roots);
        for (roots) |root| try std.testing.expect(root.isZero());
    }

    const relation_plan = try binding.authenticate(&definition);
    const event_ids = binding.events(&definition);
    const first = try relation_plan.entries(
        &definition.arena,
        air.SEMANTIC_DIGEST,
        event_ids,
        owned.logical_rows[0],
    );
    try std.testing.expect(first[0].numerator.eql(QM31.one().neg()));
    try std.testing.expect(first[1].numerator.isZero());
    const final = try relation_plan.entries(
        &definition.arena,
        air.SEMANTIC_DIGEST,
        event_ids,
        owned.logical_rows[witness.PUBLIC_TERM_COUNT],
    );
    try std.testing.expect(final[0].numerator.eql(QM31.one().neg()));
    try std.testing.expect(final[1].numerator.eql(QM31.one().neg()));
}

test "V2 row17 prepared-source mutation fleet rejects before every destination write" {
    var plan = try testPlan(std.testing.allocator, schedule.VM_PROGRAM_SPEC_V1);
    defer plan.deinit();
    const relay = witness.ControlRelayV2{ .value = M31.fromCanonical(77) };
    const prepared = try witness.preflight(&plan, &relay);

    var mutations = [_]witness.PreparedV2{
        prepared,
        prepared,
        prepared,
        prepared,
        prepared,
        prepared,
        prepared,
    };
    mutations[0].format_version -= 1;
    mutations[1].schedule_digest[0] ^= 1;
    mutations[2].rows[0].sequence += 1;
    mutations[3].rows[17].args[0] += 1;
    mutations[4].rows[42].tag = witness.GLOBAL_ASSERT_TAG;
    mutations[5].rows[witness.PUBLIC_TERM_COUNT].control_mask = 0;
    mutations[6].relay.node_id = 1;

    for (&mutations) |*mutated| {
        var owned = OwnedDestinations.sentinel();
        const before = owned;
        try std.testing.expectError(
            error.InvalidPreparedSource,
            witness.writeInto(mutated, owned.view()),
        );
        try std.testing.expect(std.meta.eql(before, owned));
    }
}

test "V2 row17 rejects schedule relay geometry and alias drift fail-atomically" {
    var plan = try testPlan(std.testing.allocator, schedule.VM_PROGRAM_SPEC_V1);
    defer plan.deinit();
    const relay = witness.ControlRelayV2{ .value = M31.fromCanonical(99) };
    const prepared = try witness.preflight(&plan, &relay);

    var bad_relay = relay;
    bad_relay.circuit_id += 1;
    try std.testing.expectError(
        error.InvalidControlRelay,
        witness.preflight(&plan, &bad_relay),
    );

    var wrong_plan = try testPlan(
        std.testing.allocator,
        try schedule.ProgramSpec.init(.vm, 12, 69, 101, 12),
    );
    defer wrong_plan.deinit();
    try std.testing.expectError(
        error.InvalidPlanProfile,
        witness.preflight(&wrong_plan, &relay),
    );

    var changed_plan = try testPlan(std.testing.allocator, schedule.VM_PROGRAM_SPEC_V1);
    defer changed_plan.deinit();
    const term_index: usize = witness.PUBLIC_PHASE_FIRST_SEQUENCE + 9;
    changed_plan.steps[term_index].accumulate_public_logup_term.term += 1;
    var destination = prepared;
    const before_destination = destination;
    try std.testing.expectError(
        error.ScheduleDigestMismatch,
        witness.prepareInto(&destination, &changed_plan, &relay),
    );
    try std.testing.expectEqual(before_destination, destination);

    var owned = OwnedDestinations.sentinel();
    const before = owned;
    var short = owned.view();
    short.logical_rows = short.logical_rows[0 .. short.logical_rows.len - 1];
    try std.testing.expectError(
        error.DestinationLengthMismatch,
        witness.writeInto(&prepared, short),
    );
    try std.testing.expect(std.meta.eql(before, owned));

    var aliased = owned.view();
    aliased.preprocessed[0] = aliased.main[0];
    try std.testing.expectError(
        error.AliasedDestination,
        witness.writeInto(&prepared, aliased),
    );
    try std.testing.expect(std.meta.eql(before, owned));
}

fn expectExactTrace(owned: *const OwnedDestinations, control_value: M31) !void {
    var step_count: usize = 0;
    var wire_count: usize = 0;
    for (owned.relation_events, 0..) |event, event_index| {
        try event.validate();
        try std.testing.expectEqual(relation.Role.consume, event.role);
        switch (event.domain) {
            .recursion_step => {
                step_count += 1;
                try std.testing.expectEqual(witness.VERIFIER_ID, event.tuple[0].toU32());
                try std.testing.expect(event.tuple[2].toU32() != 1);
            },
            .recursion_wire => {
                wire_count += 1;
                try std.testing.expectEqual(
                    witness.ACTIVE_RELATION_EVENT_COUNT - 1,
                    event_index,
                );
                try std.testing.expectEqual(
                    air.CONTROL_RELAY_CIRCUIT_ID,
                    event.tuple[0].toU32(),
                );
                try std.testing.expectEqual(
                    air.CONTROL_RELAY_NODE_ID,
                    event.tuple[1].toU32(),
                );
                try std.testing.expect(event.tuple[2].eql(control_value));
            },
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqual(witness.LOGICAL_ROW_COUNT, step_count);
    try std.testing.expectEqual(@as(usize, 1), wire_count);

    for (0..witness.TRACE_ROW_COUNT) |row| {
        const active = row < witness.LOGICAL_ROW_COUNT;
        const control = row == witness.PUBLIC_TERM_COUNT;
        try std.testing.expectEqual(
            @as(u32, @intFromBool(active)),
            owned.preprocessed[0][row].toU32(),
        );
        try std.testing.expectEqual(
            @as(u32, @intFromBool(control)),
            owned.preprocessed[1][row].toU32(),
        );
        if (control) {
            try std.testing.expect(owned.main[0][row].eql(control_value));
        } else {
            try std.testing.expect(owned.main[0][row].isZero());
        }
        if (!active) for (owned.logical_rows[row]) |value|
            try std.testing.expect(value.isZero());
    }
}

fn testPlan(
    allocator: std.mem.Allocator,
    spec: schedule.ProgramSpec,
) !schedule.Plan {
    return schedule.Plan.initShape(allocator, spec, .{
        .protocol_id = id("row17-v2-protocol"),
        .shape_id = id("row17-v2-shape"),
        .interaction_pow_bits = 0,
        .pcs_pow_bits = protocol.PCS_POW_BITS,
        .query_count = 1,
        .table_count = 4,
        .claimed_sum_count = 4,
        .sampled_value_count = 8,
        .tree_heights = .{ 9, 9, 9, 9 },
        .fri = try fixed_profile.FriSchedule.init(
            8,
            protocol.PCS_CONFIG.fri_config,
        ),
    });
}

fn id(label: []const u8) [8]u32 {
    return channel.hashBytes(label, 0x5231_3756); // "R17V"
}

const OwnedDestinations = struct {
    main: [air.PHYSICAL_MAIN_COLUMN_COUNT][witness.TRACE_ROW_COUNT]M31,
    preprocessed: [air.PREPROCESSED_COLUMN_COUNT][witness.TRACE_ROW_COUNT]M31,
    logical_rows: [witness.TRACE_ROW_COUNT][air.LOGICAL_INPUT_COUNT]M31,
    relation_events: [witness.ACTIVE_RELATION_EVENT_COUNT]witness.RelationEventV2,

    fn sentinel() OwnedDestinations {
        const value = M31.fromCanonical(0x55aa);
        const event = witness.RelationEventV2{
            .roster_row = 0xff,
            .logical_row = std.math.maxInt(u32),
            .event_ordinal = 0xff,
            .domain = .recursion_step,
            .role = .emit,
            .multiplicity = 0x55aa,
            .arity = 7,
            .tuple = [_]M31{value} ** @import("universal_challenges.zig").MAX_ARITY,
        };
        return .{
            .main = [_][witness.TRACE_ROW_COUNT]M31{
                [_]M31{value} ** witness.TRACE_ROW_COUNT,
            } ** air.PHYSICAL_MAIN_COLUMN_COUNT,
            .preprocessed = [_][witness.TRACE_ROW_COUNT]M31{
                [_]M31{value} ** witness.TRACE_ROW_COUNT,
            } ** air.PREPROCESSED_COLUMN_COUNT,
            .logical_rows = [_][air.LOGICAL_INPUT_COUNT]M31{
                [_]M31{value} ** air.LOGICAL_INPUT_COUNT,
            } ** witness.TRACE_ROW_COUNT,
            .relation_events = [_]witness.RelationEventV2{event} **
                witness.ACTIVE_RELATION_EVENT_COUNT,
        };
    }

    fn view(self: *OwnedDestinations) witness.DestinationsV2 {
        var result: witness.DestinationsV2 = undefined;
        for (&result.main, &self.main) |*target, *source_column|
            target.* = source_column[0..];
        for (&result.preprocessed, &self.preprocessed) |*target, *source_column|
            target.* = source_column[0..];
        result.logical_rows = self.logical_rows[0..];
        result.relation_events = self.relation_events[0..];
        return result;
    }
};
