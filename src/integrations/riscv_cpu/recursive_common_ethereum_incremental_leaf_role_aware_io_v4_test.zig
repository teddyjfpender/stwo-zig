const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const subject =
    @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const relations_mod = frontend.air.relation_challenges;
const channel = frontend.recursion.poseidon2_channel;

test "schema3 role-aware IO stream is ordered injective and zero padded" {
    const input = try subject.TupleV4.init(.input_memory, &.{
        1, 0xffff_fffc, 0, 0xef, 0xbe, 0xad, 0xde,
    });
    const output = try subject.TupleV4.init(.output_memory, &.{
        1, 0x4000, 91, 4, 3, 2, 1,
    });
    const program = try subject.TupleV4.init(.program_completion, &.{
        0x1004, 46, 0, 5, 0,
    });
    const recovered = try input.values();
    try std.testing.expectEqual(@as(u32, 0xffff_fffc), recovered[1]);
    try std.testing.expectEqual(@as(u32, 0xdead_beef), recovered[3] | recovered[4] << 8 |
        recovered[5] << 16 | recovered[6] << 24);

    var tuples = [_]subject.TupleV4{
        input,
        output,
        program,
        subject.TupleV4.zero(),
    };
    try subject.testingValidateTupleSequence(&tuples, 3);
    const words = try subject.testingCanonicalWordsAlloc(
        std.testing.allocator,
        &tuples,
        3,
    );
    defer std.testing.allocator.free(words);
    try std.testing.expectEqual(
        @as(usize, subject.HEADER_WORD_COUNT + 4 * subject.TUPLE_WORD_COUNT),
        words.len,
    );
    try std.testing.expectEqualSlices(u32, &.{
        subject.STREAM_DOMAIN_WORD,
        subject.FORMAT_VERSION,
        subject.SCHEMA_VERSION,
        3,
        4,
        subject.TUPLE_WORD_COUNT,
    }, words[0..subject.HEADER_WORD_COUNT]);
    try std.testing.expect(std.mem.allEqual(
        u32,
        words[words.len - subject.TUPLE_WORD_COUNT ..],
        0,
    ));

    const calls = try subject.testingBuildCallsAlloc(
        std.testing.allocator,
        words,
    );
    defer std.testing.allocator.free(calls);
    const commitment = subject.testingDigestFromCalls(calls);
    try std.testing.expectEqualSlices(
        u32,
        &channel.hashCanonicalU32s(words, subject.COMMITMENT_DOMAIN),
        &commitment,
    );

    var reordered = tuples;
    std.mem.swap(subject.TupleV4, &reordered[0], &reordered[1]);
    try std.testing.expectError(
        error.RoleAwareIoWitnessMismatchV4,
        subject.testingValidateTupleSequence(&reordered, 3),
    );
    tuples[3] = output;
    try std.testing.expectError(
        error.RoleAwareIoWitnessMismatchV4,
        subject.testingValidateTupleSequence(&tuples, 3),
    );
    tuples[3] = subject.TupleV4.zero();
    tuples[1] = subject.TupleV4.zero();
    try std.testing.expectError(
        error.InvalidRoleAwareIoTupleV4,
        subject.testingValidateTupleSequence(&tuples, 3),
    );
}

test "schema3 role-aware IO claims share the committed tuple witness" {
    const relations = relations_mod.Relations.dummy();
    const input = try subject.TupleV4.init(.input_memory, &.{
        1, 0x2000, 0, 1, 2, 3, 4,
    });
    const output = try subject.TupleV4.init(.output_memory, &.{
        1, 0x3000, 17, 5, 6, 7, 8,
    });
    const program = try subject.TupleV4.init(.program_completion, &.{
        0x1004, 46, 0, 5, 0,
    });
    const tuples = [_]subject.TupleV4{ input, output, program };
    const claims = try subject.testingClaimsFromTuples(&tuples, &relations);

    const input_denominator = relations.memory_access.combineBase(.{
        M31.fromU64(1), M31.fromU64(0x2000), M31.zero(),
        M31.fromU64(1), M31.fromU64(2),      M31.fromU64(3),
        M31.fromU64(4),
    });
    const output_denominator = relations.memory_access.combineBase(.{
        M31.fromU64(1), M31.fromU64(0x3000), M31.fromU64(17),
        M31.fromU64(5), M31.fromU64(6),      M31.fromU64(7),
        M31.fromU64(8),
    });
    const program_denominator = relations.program_access.combineBase(.{
        M31.fromU64(0x1004), M31.fromU64(46), M31.zero(),
        M31.fromU64(5),      M31.zero(),
    });
    try std.testing.expect(claims.memory_access.eql(
        (try input_denominator.inv()).sub(try output_denominator.inv()),
    ));
    try std.testing.expect(claims.program_access.eql(
        (try program_denominator.inv()).neg(),
    ));
    try std.testing.expectEqual(@as(u32, 8), try subject.providerLogSize(129));
    try std.testing.expectError(
        error.RoleAwareIoCapacityNotFrozenV4,
        subject.requireFrozenCampaignCapacity(),
    );
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.CAMPAIGN_CAPACITY_FROZEN);
}
