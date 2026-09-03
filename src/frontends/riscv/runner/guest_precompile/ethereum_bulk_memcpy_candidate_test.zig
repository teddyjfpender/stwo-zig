//! Candidate-only authority, session, and transactional retirement tests.

const std = @import("std");

const execution_profile = @import("../../isa/execution_profile.zig");
const authority_mod = @import("../../isa/ethereum_bulk_memcpy_candidate_v1.zig");
const segment_session = @import("../segment_session.zig");
const test_elf = @import("test_elf.zig");

test "Ethereum bulk memcpy candidate retires one exact authority-bound call" {
    const elf = test_elf.buildEthereumBulkMemcpyCandidate();
    const authority = try authorityForElf(&elf);
    const CandidateSession =
        segment_session.EthereumBulkMemcpyCandidateExecutionSessionV1();

    try std.testing.expectError(
        error.EthereumBulkMemcpyAuthorityRequired,
        CandidateSession.initLegacy(std.testing.allocator, &elf, .{}),
    );

    var session = try CandidateSession.initCandidateLegacy(
        std.testing.allocator,
        &elf,
        .{},
        authority,
    );
    defer session.deinit();

    var result = try session.runLegacy(16);
    defer result.deinit();
    try result.validateAgainst(authority, 0);
    try std.testing.expectEqual(@as(usize, 1), result.bulk_memcpy.records().len);
    try std.testing.expectEqual(@as(usize, 8), result.bulk_memcpy.wordRows().len);
    try std.testing.expectEqual(@as(usize, 1), result.bulk_memcpy.rows().len);
    try std.testing.expectEqual(@as(usize, 0), result.bulk_memcpy.externalStepOrigin());
    try std.testing.expectEqual(@as(u32, 6), result.bulk_memcpy.rows()[0].execution_clock);

    var destination: [test_elf.ethereum_bulk_memcpy_length]u8 = undefined;
    session.memory.readSlice(test_elf.ethereum_bulk_memcpy_destination, &destination);
    for (destination, 0..) |byte, index|
        try std.testing.expectEqual(@as(u8, @intCast(index + 1)), byte);
}

test "ordinary Ethereum session has no candidate authority constructor" {
    const elf = test_elf.buildEthereumBulkMemcpyCandidate();
    const DefaultSession = segment_session.ExecutionSession(
        execution_profile.ExecutionProfile.rv32im_zkvm_ethereum_v1,
    );
    try std.testing.expectError(
        error.EthereumCandidatePolicyUnavailable,
        DefaultSession.initCandidateLegacy(
            std.testing.allocator,
            &elf,
            .{},
            {},
        ),
    );
}

fn authorityForElf(elf: []const u8) !authority_mod.Authority {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(elf, &digest, .{});
    return authority_mod.Authority.create(digest);
}
