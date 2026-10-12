const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const air = @import("../vm_public_logup_control_v6.zig");
const witness = @import("../vm_public_logup_control_witness_v6.zig");
const binding = @import("../vm_public_logup_control_relation_v6.zig");
const direct_program = @import("../direct_constraint_program.zig");
const schedule = @import("../verifier_schedule.zig");
const fixed_profile = @import("../../fixed_profile.zig");
const protocol = @import("../../protocol.zig");
const channel = @import("../../poseidon2_channel.zig");
const relation = @import("../../../air/lang/relation.zig");

test "V6 row17 typed identity stays separate from frozen V2" {
    const actual = try air.computeSemanticDigest(std.testing.allocator);
    try std.testing.expectEqualStrings(
        air.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(actual, .lower),
    );
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    try definition.validate();
    const plan = try binding.authenticate(&definition);
    try std.testing.expectEqual(relation.Domain.recursion_step, plan.events[0].domain);
    try std.testing.expectEqual(relation.Domain.recursion_wire, plan.events[1].domain);
    try std.testing.expectEqual(@as(usize, 1), binding.Runtime.BATCH_COUNT);
    try std.testing.expect(!air.PROOF_ACTIVATION);
    try std.testing.expect(!witness.PROOF_ACTIVATION);
}

test "V6 row17 q193 102 terms write exact 128-row trace and 104 active events" {
    var plan = try testPlan(16, 16);
    defer plan.deinit();
    const relay = witness.ControlRelayV6{ .value = M31.fromCanonical(91) };
    const prepared = try witness.preflight(&plan, &relay);
    try prepared.validateAgainst(&plan, &relay);
    try std.testing.expectEqual(@as(u16, 102), prepared.term_count);
    try std.testing.expectEqual(@as(usize, 103), try air.logicalRowCount(prepared.term_count));
    try std.testing.expectEqual(@as(usize, 104), try air.activeRelationEventCount(prepared.term_count));
    try std.testing.expectEqual(@as(u32, 7), air.TRACE_LOG_SIZE);

    var owned = Destinations.sentinel();
    try witness.writeInto(&prepared, owned.view(prepared.term_count));
    for (0..witness.TRACE_ROW_COUNT) |row| {
        const active = row <= prepared.term_count;
        try std.testing.expectEqual(@as(u32, @intFromBool(active)), owned.preprocessed[0][row].toU32());
        try std.testing.expectEqual(@as(u32, @intFromBool(row == prepared.term_count)), owned.preprocessed[1][row].toU32());
        if (row < prepared.term_count) {
            try std.testing.expectEqual(witness.ACCUMULATE_TAG, owned.preprocessed[4][row].toU32());
            try std.testing.expectEqual(@as(u32, @intCast(row)), owned.preprocessed[5][row].toU32());
        } else if (row == prepared.term_count) {
            try std.testing.expectEqual(witness.GLOBAL_ASSERT_TAG, owned.preprocessed[4][row].toU32());
            try std.testing.expect(owned.main[0][row].eql(relay.value));
        } else {
            for (owned.logical_rows[row]) |word| try std.testing.expect(word.isZero());
        }
    }
    for (owned.relation_events[0..103], 0..) |event, row| {
        try event.validate();
        try std.testing.expectEqual(relation.Domain.recursion_step, event.domain);
        try std.testing.expectEqual(@as(u32, @intCast(row)), event.logical_row);
        try std.testing.expectEqual(witness.PUBLIC_PHASE_FIRST_SEQUENCE + @as(u32, @intCast(row)), event.tuple[1].toU32());
    }
    const final = owned.relation_events[103];
    try final.validate();
    try std.testing.expectEqual(relation.Domain.recursion_wire, final.domain);
    try std.testing.expectEqual(@as(u32, 102), final.logical_row);
    try std.testing.expect(final.tuple[2].eql(relay.value));

    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const direct = try direct_program.authenticate(&definition.arena, air.SEMANTIC_DIGEST, air.LOGICAL_INPUT_COUNT);
    var scratch: [direct_program.MAX_NODES]M31 = undefined;
    var roots: [air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (owned.logical_rows) |row| {
        try direct.evaluateBaseInto(&row, &scratch, &roots);
        for (roots) |root| try std.testing.expect(root.isZero());
    }
    const relation_plan = try binding.authenticate(&definition);
    const entries = try relation_plan.entries(
        &definition.arena,
        air.SEMANTIC_DIGEST,
        binding.events(&definition),
        owned.logical_rows[102],
    );
    try std.testing.expect(entries[0].numerator.eql(QM31.one().neg()));
    try std.testing.expect(entries[1].numerator.eql(QM31.one().neg()));
}

test "V6 row17 variable cardinality rejects overflow and mutated prepared source before writes" {
    var minimum = try testPlan(0, 0);
    defer minimum.deinit();
    const relay = witness.ControlRelayV6{ .value = M31.fromCanonical(7) };
    const min_prepared = try witness.preflight(&minimum, &relay);
    try std.testing.expectEqual(@as(u16, 70), min_prepared.term_count);
    var min_destination = Destinations.sentinel();
    try witness.writeInto(&min_prepared, min_destination.view(70));
    try std.testing.expectEqual(@as(u32, 1), min_destination.preprocessed[1][70].toU32());
    var maximum = try testPlan(28, 29);
    defer maximum.deinit();
    const max_prepared = try witness.preflight(&maximum, &relay);
    try std.testing.expectEqual(@as(u16, 127), max_prepared.term_count);
    var max_destination = Destinations.sentinel();
    try witness.writeInto(&max_prepared, max_destination.view(127));
    try std.testing.expectEqual(@as(u32, 1), max_destination.preprocessed[1][127].toU32());
    try max_destination.relation_events[128].validate();
    var overflow = try testPlan(29, 29);
    defer overflow.deinit();
    try std.testing.expectError(error.InvalidPublicTermCount, witness.preflight(&overflow, &relay));
    var wrong_relay = relay;
    wrong_relay.node_id = 1;
    try std.testing.expectError(error.InvalidControlRelay, witness.preflight(&minimum, &wrong_relay));

    var plan = try testPlan(16, 16);
    defer plan.deinit();
    const prepared = try witness.preflight(&plan, &relay);
    var mutations = [_]witness.PreparedV6{prepared} ** 5;
    mutations[0].term_count = 101;
    mutations[1].rows[25].args[0] += 1;
    mutations[2].rows[102].control_mask = 0;
    mutations[3].rows[103].tag = 1;
    mutations[4].schedule_digest[0] ^= 1;
    for (&mutations) |*mutated| {
        var owned = Destinations.sentinel();
        const before = owned;
        try std.testing.expectError(error.InvalidPreparedSource, witness.writeInto(mutated, owned.view(102)));
        try std.testing.expect(std.meta.eql(before, owned));
    }
    var owned = Destinations.sentinel();
    const before = owned;
    var short = owned.view(102);
    short.relation_events = short.relation_events[0..103];
    try std.testing.expectError(error.DestinationLengthMismatch, witness.writeInto(&prepared, short));
    try std.testing.expect(std.meta.eql(before, owned));
    var aliased = owned.view(102);
    aliased.preprocessed[0] = aliased.main[0];
    try std.testing.expectError(error.AliasedDestination, witness.writeInto(&prepared, aliased));
    try std.testing.expect(std.meta.eql(before, owned));

    var changed_plan = try testPlan(16, 16);
    defer changed_plan.deinit();
    const mutable_steps = try std.testing.allocator.dupe(schedule.VerifierStep, changed_plan.steps);
    std.testing.allocator.free(changed_plan.steps);
    changed_plan.steps = mutable_steps;
    mutable_steps[witness.PUBLIC_PHASE_FIRST_SEQUENCE + 5].accumulate_public_logup_term.term += 1;
    try std.testing.expectError(error.ScheduleDigestMismatch, witness.preflight(&changed_plan, &relay));
}

fn testPlan(input_words: u32, output_words: u32) !schedule.Plan {
    return schedule.Plan.initShape(std.testing.allocator, try schedule.vmProgramSpec(input_words, output_words), .{
        .protocol_id = channel.hashBytes("row17-v6-protocol", 0x5231_3656),
        .shape_id = channel.hashBytes("row17-v6-shape", 0x5231_3656),
        .interaction_pow_bits = 10,
        .pcs_pow_bits = 16,
        .query_count = 193,
        .table_count = 4,
        .claimed_sum_count = 4,
        .sampled_value_count = 8,
        .tree_heights = .{ 9, 9, 9, 9 },
        .fri = try fixed_profile.FriSchedule.init(8, protocol.PCS_CONFIG.fri_config),
    });
}

const Destinations = struct {
    main: [air.PHYSICAL_MAIN_COLUMN_COUNT][air.TRACE_ROW_COUNT]M31,
    preprocessed: [air.PREPROCESSED_COLUMN_COUNT][air.TRACE_ROW_COUNT]M31,
    logical_rows: [air.TRACE_ROW_COUNT][air.LOGICAL_INPUT_COUNT]M31,
    relation_events: [air.TRACE_ROW_COUNT + 1]witness.RelationEventV6,

    fn sentinel() Destinations {
        const value = M31.fromCanonical(0x55aa);
        return .{
            .main = [_][air.TRACE_ROW_COUNT]M31{[_]M31{value} ** air.TRACE_ROW_COUNT} ** air.PHYSICAL_MAIN_COLUMN_COUNT,
            .preprocessed = [_][air.TRACE_ROW_COUNT]M31{[_]M31{value} ** air.TRACE_ROW_COUNT} ** air.PREPROCESSED_COLUMN_COUNT,
            .logical_rows = [_][air.LOGICAL_INPUT_COUNT]M31{[_]M31{value} ** air.LOGICAL_INPUT_COUNT} ** air.TRACE_ROW_COUNT,
            .relation_events = [_]witness.RelationEventV6{.{
                .roster_row = 0xff,
                .logical_row = std.math.maxInt(u32),
                .event_ordinal = 0xff,
                .domain = .recursion_step,
                .role = .emit,
                .multiplicity = 0,
                .arity = 7,
                .tuple = [_]M31{value} ** @import("../universal_challenges.zig").MAX_ARITY,
            }} ** (air.TRACE_ROW_COUNT + 1),
        };
    }

    fn view(self: *Destinations, term_count: usize) witness.DestinationsV6 {
        var result: witness.DestinationsV6 = undefined;
        for (&result.main, &self.main) |*target, *column| target.* = column[0..];
        for (&result.preprocessed, &self.preprocessed) |*target, *column| target.* = column[0..];
        result.logical_rows = self.logical_rows[0..];
        result.relation_events = self.relation_events[0 .. term_count + 2];
        return result;
    }
};
