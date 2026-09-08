const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const subject = @import("recursive_common_ethereum_incremental_leaf_publication_hash_v4.zig");
const shared = @import("recursive_public_hash_rows_v1.zig");
const schema = @import("recursive_common_ethereum_incremental_leaf_field_public_v4_schema3.zig");

/// Reuses the existing independent projected schedule fixture. This does not
/// mint a native owner or claim that all publication source routes are closed.
pub fn exercise(canonical: []const u32, schedule: *schema.OwnedPoseidonScheduleV4) !void {
    const input = .{ .schedule = schedule.*, .role_aware_io = .{ .canonical_words = canonical } };
    var prepared = try subject.Prepared.initAdmitted(std.testing.allocator, &input, 1500);
    defer prepared.deinit();
    try std.testing.expectEqual(schedule.calls.len, prepared.rows.len);
    const Air = frontend.recursion.air.ethereum_publication_hash_v1;
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try Air.Relation.authenticate(&definition);
    var digest_consumers: usize = 0;
    for (prepared.rows) |row| {
        const entries = try plan.entries(&definition.arena, Air.SEMANTIC_DIGEST, definition.events, row);
        for (entries) |entry| {
            if (entry.domain != .recursion_verifier_input_word or entry.numerator.isZero()) continue;
            // Exactly the five publication endpoints have a public source.
            // Ethereum has no inherited verifier-0 VM-claim-digest endpoint.
            const verifier = entry.values[0].toM31Array();
            try std.testing.expect(verifier[1].isZero() and verifier[2].isZero() and verifier[3].isZero());
            try std.testing.expect(verifier[0].toU32() >= subject.hashScope(.io_stream));
            try std.testing.expect(verifier[0].toU32() <= subject.hashScope(.output));
            digest_consumers += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 5 * 8), digest_consumers);
    // Exact calls, phase boundaries, and output digests are independently
    // authenticated in construction; mutations must fail before returning rows.
    for (schedule.phases) |phase| {
        schedule.calls[phase.first_call].input[0] ^= 1;
        const changed = .{ .schedule = schedule.*, .role_aware_io = .{ .canonical_words = canonical } };
        const result = subject.Prepared.initAdmitted(std.testing.allocator, &changed, 1500);
        schedule.calls[phase.first_call].input[0] ^= 1;
        try std.testing.expectError(error.InvalidEthereumPublicationSchedule, result);
    }
    var bad_digest = input;
    bad_digest.schedule.phases[0].output_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidEthereumPublicationSchedule, subject.Prepared.initAdmitted(std.testing.allocator, &bad_digest, 1500));
    var bad_phase = input;
    bad_phase.schedule.phases[1].first_call += 1;
    try std.testing.expectError(error.InvalidEthereumPublicationSchedule, subject.Prepared.initAdmitted(std.testing.allocator, &bad_phase, 1500));
    try std.testing.expectEqualDeep(subject.Source{ .role_io_word = 3 }, try subject.sourceForWord(.source, 94, canonical.len));
    try std.testing.expectEqualDeep(subject.Source{ .role_io_word = 4 }, try subject.sourceForWord(.source, 95, canonical.len));
    try std.testing.expectEqualDeep(subject.Source{ .hash_digest = .{ .phase = .io_stream, .limb = 7 } }, try subject.sourceForWord(.source, 103, canonical.len));
    try std.testing.expectEqualDeep(subject.Source{ .hash_digest = .{ .phase = .subtree, .limb = 7 } }, try subject.sourceForWord(.output, 441, canonical.len));
    try std.testing.expectError(error.InvalidEthereumPublicationWord, subject.sourceForWord(.output, 442, canonical.len));
}

test "ethereum publication hash shared generator matches canonical sponge boundaries" {
    const channel = frontend.recursion.poseidon2_channel;
    const words = [_]u32{ 1, 3, 7, 11, 13, 17, 19, 23, 29 };
    for ([_]usize{ 0, 1, 7, 8, 9 }) |length| {
        const count = try shared.rowCount(length);
        const rows = try std.testing.allocator.alloc(shared.Row, count);
        defer std.testing.allocator.free(rows);
        const calls = try std.testing.allocator.alloc(shared.Call, count);
        defer std.testing.allocator.free(calls);
        const output = try shared.write(words[0..length], .{ .domain = 123, .scope = 1100, .verifier = 1100, .input_kind = 11 }, 10, rows, calls);
        try std.testing.expectEqualDeep(channel.hashCanonicalU32s(words[0..length], 123), output);
    }
}
