const std = @import("std");
const stwo_core = @import("stwo_core");
const planner = @import("lookup_batch_planner.zig");
const protocol_degree = @import("protocol_degree.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const static_registry = @import("static_profile_registry.zig");
const production_entry = @import("../lookups/entry.zig");
const trace = @import("../../runner/trace.zig");

const QM31 = stwo_core.fields.qm31.QM31;

const PROGRAM_DIGEST = planner.Digest{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

fn policy(maximum_degree: u32) planner.PolicyV1 {
    return .{ .maximum_interaction_degree = maximum_degree };
}

test "lookup batch planner: pairs linear events without expanding composition" {
    const events = [_]planner.Event{
        .{ .ordinal = 0, .numerator_degree = 1, .denominator_degree = 1 },
        .{ .ordinal = 1, .numerator_degree = 1, .denominator_degree = 1 },
        .{ .ordinal = 2, .numerator_degree = 1, .denominator_degree = 1 },
        .{ .ordinal = 3, .numerator_degree = 1, .denominator_degree = 1 },
        .{ .ordinal = 4, .numerator_degree = 1, .denominator_degree = 1 },
    };
    var plan = try planner.select(
        std.testing.allocator,
        PROGRAM_DIGEST,
        3,
        &events,
        policy(5),
    );
    defer plan.deinit();
    try plan.validate(&events);
    try std.testing.expectEqual(@as(usize, 3), plan.batches.len);
    try std.testing.expectEqual(@as(u8, 2), plan.batches[0].event_count);
    try std.testing.expectEqual(@as(u8, 2), plan.batches[1].event_count);
    try std.testing.expectEqual(@as(u8, 1), plan.batches[2].event_count);
    try std.testing.expectEqual(@as(u8, 1), plan.score.quotient_expansion_bits);
    try std.testing.expectEqual(@as(u32, 12), plan.score.interaction_columns);
    try std.testing.expectEqual(@as(u32, 2), plan.score.paired_batch_count);
    try std.testing.expectEqual(@as(u32, 6), plan.score.pair_cross_multiplications);
    try std.testing.expectEqualStrings(
        "6c26c035b31e80cae8082a78947fb1d4d7eec7faaf20e03c32d7d5948536fffc",
        &std.fmt.bytesToHex(plan.plan_digest, .lower),
    );
}

test "lookup batch planner: avoids a pair that raises global quotient expansion" {
    const events = [_]planner.Event{
        .{ .ordinal = 0, .numerator_degree = 1, .denominator_degree = 2 },
        .{ .ordinal = 1, .numerator_degree = 1, .denominator_degree = 2 },
    };
    var plan = try planner.select(
        std.testing.allocator,
        PROGRAM_DIGEST,
        3,
        &events,
        policy(5),
    );
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 2), plan.batches.len);
    try std.testing.expectEqual(@as(u8, 1), plan.batches[0].event_count);
    try std.testing.expectEqual(@as(u8, 1), plan.batches[1].event_count);
    try std.testing.expectEqual(@as(u32, 3), plan.score.maximum_interaction_degree);
    try std.testing.expectEqual(@as(u8, 1), plan.score.quotient_expansion_bits);
}

test "lookup batch planner: dynamic program finds a later legal pair" {
    const events = [_]planner.Event{
        .{ .ordinal = 0, .numerator_degree = 1, .denominator_degree = 2 },
        .{ .ordinal = 1, .numerator_degree = 1, .denominator_degree = 2 },
        .{ .ordinal = 2, .numerator_degree = 1, .denominator_degree = 0 },
    };
    var plan = try planner.select(
        std.testing.allocator,
        PROGRAM_DIGEST,
        3,
        &events,
        policy(3),
    );
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 2), plan.batches.len);
    try std.testing.expectEqual(@as(u8, 1), plan.batches[0].event_count);
    try std.testing.expectEqual(@as(u32, 1), plan.batches[1].first_event);
    try std.testing.expectEqual(@as(u8, 2), plan.batches[1].event_count);
}

test "lookup batch planner: malformed inputs and plan mutations reject" {
    const events = [_]planner.Event{
        .{ .ordinal = 0, .numerator_degree = 1, .denominator_degree = 2 },
    };
    try std.testing.expectError(
        error.NoFeasiblePartition,
        planner.select(
            std.testing.allocator,
            PROGRAM_DIGEST,
            3,
            &events,
            policy(2),
        ),
    );
    var wrong_order = events;
    wrong_order[0].ordinal = 1;
    try std.testing.expectError(
        error.InvalidEvent,
        planner.select(
            std.testing.allocator,
            PROGRAM_DIGEST,
            3,
            &wrong_order,
            policy(3),
        ),
    );
    try std.testing.expectError(
        error.InvalidDigest,
        planner.select(
            std.testing.allocator,
            [_]u8{0} ** 32,
            3,
            &events,
            policy(3),
        ),
    );

    var plan = try planner.select(
        std.testing.allocator,
        PROGRAM_DIGEST,
        3,
        &events,
        policy(3),
    );
    defer plan.deinit();
    plan.plan_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidDigest, plan.validate(&events));
    plan.plan_digest[0] ^= 1;
    plan.batches[0].terms.final += 1;
    try std.testing.expectError(error.InvalidBatch, plan.validate(&events));
}

test "lookup batch planner: all production families have a no-worse expansion candidate" {
    var total_current_batches: u32 = 0;
    var total_candidate_batches: u32 = 0;
    var lower_expansion_families: u32 = 0;
    var changed_families: u32 = 0;
    var maximum_candidate_degree: u32 = 0;
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var imported = try shadow_program.buildProduction(
            std.testing.allocator,
            family,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        var analysis = try protocol_degree.analyze(
            std.testing.allocator,
            &imported,
            10,
        );
        defer analysis.deinit();
        var storage: [production_entry.MAX_ENTRIES]planner.Event = undefined;
        for (analysis.lookups, storage[0..analysis.lookups.len]) |lookup, *event| {
            event.* = .{
                .ordinal = lookup.index,
                .numerator_degree = lookup.numerator,
                .denominator_degree = lookup.denominator,
            };
        }
        var candidate = try planner.select(
            std.testing.allocator,
            static_registry.DESCRIPTORS[family_index].semantic_program_digest,
            3, // Proof-wide ambient degree; other native components are cubic.
            storage[0..analysis.lookups.len],
            policy(5),
        );
        defer candidate.deinit();

        const current_composition_degree = @max(
            analysis.maximum_direct_degree,
            analysis.maximum_interaction_degree,
        );
        const current_expansion = protocol_degree.quotientExpansionBits(
            current_composition_degree,
        );
        try std.testing.expect(candidate.score.quotient_expansion_bits <= current_expansion);
        if (candidate.score.quotient_expansion_bits == current_expansion) {
            try std.testing.expect(candidate.batches.len <= imported.batchCount());
        } else {
            lower_expansion_families += 1;
        }
        const expected_candidate_count: usize = switch (family) {
            .mul => 11,
            .mulh => 16,
            .div => 18,
            else => imported.batchCount(),
        };
        try std.testing.expectEqual(expected_candidate_count, candidate.batches.len);
        if (candidate.batches.len != imported.batchCount()) changed_families += 1;
        total_current_batches += @intCast(imported.batchCount());
        total_candidate_batches += @intCast(candidate.batches.len);
        maximum_candidate_degree = @max(
            maximum_candidate_degree,
            candidate.score.maximum_interaction_degree,
        );
    }
    try std.testing.expectEqual(@as(u32, 155), total_current_batches);
    try std.testing.expectEqual(@as(u32, 137), total_candidate_batches);
    try std.testing.expectEqual(@as(u32, 0), lower_expansion_families);
    try std.testing.expectEqual(@as(u32, 3), changed_families);
    try std.testing.expectEqual(@as(u32, 3), maximum_candidate_degree);
}

test "lookup batch planner: pair and singleton algebra agree and zero denominators reject" {
    var state: u64 = 0x5a17_9d03_e2c4_b681;
    for (0..1_024) |_| {
        const n0 = randomQm31(&state);
        const n1 = randomQm31(&state);
        var d0 = randomQm31(&state);
        var d1 = randomQm31(&state);
        if (d0.eql(QM31.zero())) d0 = QM31.one();
        if (d1.eql(QM31.zero())) d1 = QM31.one();
        const singleton_sum = n0.mul(try d0.inv()).add(n1.mul(try d1.inv()));
        const combined_numerator = n0.mul(d1).add(n1.mul(d0));
        const denominator_product = d0.mul(d1);
        try std.testing.expect(singleton_sum.eql(
            combined_numerator.mul(try denominator_product.inv()),
        ));
    }
    const d0 = randomQm31(&state);
    try std.testing.expectError(error.DivisionByZero, QM31.zero().inv());
    try std.testing.expectError(
        error.DivisionByZero,
        d0.mul(QM31.zero()).inv(),
    );
}

fn randomQm31(state: *u64) QM31 {
    var limbs: [4]u32 = undefined;
    for (&limbs) |*limb| {
        state.* = state.* *% 6_364_136_223_846_793_005 +% 1_442_695_040_888_963_407;
        limb.* = @intCast((state.* >> 32) % 0x7fff_ffff);
    }
    return QM31.fromU32Unchecked(limbs[0], limbs[1], limbs[2], limbs[3]);
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    const events = [_]planner.Event{
        .{ .ordinal = 0, .numerator_degree = 1, .denominator_degree = 1 },
        .{ .ordinal = 1, .numerator_degree = 1, .denominator_degree = 2 },
        .{ .ordinal = 2, .numerator_degree = 2, .denominator_degree = 1 },
        .{ .ordinal = 3, .numerator_degree = 1, .denominator_degree = 1 },
    };
    var plan = try planner.select(
        allocator,
        PROGRAM_DIGEST,
        3,
        &events,
        policy(5),
    );
    defer plan.deinit();
}

test "lookup batch planner: every partial allocation is released" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}
