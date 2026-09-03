//! Final synthetic `{bulk memcpy, SWAP}` session and decoder regressions.

const std = @import("std");

const authority_mod =
    @import("../../isa/ethereum_candidate_combined_authority_v1.zig");
const combined_decode =
    @import("../../prover/guest_precompile/ethereum_candidate_combined_decode_v1.zig");
const receipt_mod = @import("ethereum_candidate_combined_elf_receipt_v1.zig");
const segment_session = @import("../segment_session.zig");
const test_elf = @import("test_elf.zig");

test "combined candidate retires ordered bulk and SWAP under one authority" {
    const elf = test_elf.buildEthereumCombinedCandidate();
    const authority = try authorityForElf(&elf);
    try authority.validateElf(&elf);
    const CandidateSession =
        segment_session.EthereumCombinedCandidateExecutionSessionV1();

    try std.testing.expectError(
        error.EthereumCombinedCandidateAuthorityRequired,
        CandidateSession.initLegacy(std.testing.allocator, &elf, .{}),
    );
    var session = try CandidateSession.initCandidateLegacy(
        std.testing.allocator,
        &elf,
        .{},
        authority,
    );
    defer session.deinit();

    var result = try session.runLegacy(24);
    defer result.deinit();
    try result.validateAgainst(authority, 0);
    try std.testing.expectEqual(@as(usize, 1), result.bulk_memcpy.records().len);
    try std.testing.expectEqual(@as(usize, 8), result.bulk_memcpy.wordRows().len);
    try std.testing.expectEqual(@as(usize, 1), result.stack_swap.records().len);
    try std.testing.expectEqual(@as(usize, 8), result.stack_swap.wordRows().len);
    try std.testing.expectEqual(
        @as(u32, 6),
        result.bulk_memcpy.rows()[0].execution_clock,
    );
    try std.testing.expectEqual(
        @as(u32, 11),
        result.stack_swap.rows()[0].execution_clock,
    );

    var lhs: [test_elf.ethereum_combined_word_bytes]u8 = undefined;
    var rhs: [test_elf.ethereum_combined_word_bytes]u8 = undefined;
    session.memory.readSlice(test_elf.ethereum_combined_bulk_destination, &lhs);
    session.memory.readSlice(test_elf.ethereum_combined_swap_rhs, &rhs);
    for (lhs, rhs, 0..) |lhs_byte, rhs_byte, index| {
        try std.testing.expectEqual(@as(u8, @intCast(0x80 + index)), lhs_byte);
        try std.testing.expectEqual(@as(u8, @intCast(index + 1)), rhs_byte);
    }
}

test "combined declared decoder binds both private program rows" {
    const elf = test_elf.buildEthereumCombinedCandidate();
    const authority = try authorityForElf(&elf);
    const decoder = try combined_decode.DeclaredDecodeAuthority.init(authority);
    try std.testing.expectEqualDeep(
        [4]u32{ 48, 10, 11, 12 },
        try decoder.decodeFetchedWord(authority.bulk_memcpy.bulk_memcpy.fixed_word),
    );
    try std.testing.expectEqualDeep(
        [4]u32{ 49, 0, 10, 11 },
        try decoder.decodeFetchedWord(authority.stack_swap.stack_swap.fixed_word),
    );
}

test "combined ELF receipt reopens program and bounded source custody" {
    const elf = test_elf.buildEthereumCombinedCandidate();
    const elf_sha256 = receipt_mod.hashBytes(&elf);
    const source_files = [_]receipt_mod.FileIdentity{
        .{ .path = "guest/combined.rs", .bytes = 1, .sha256 = .{1} ** 32 },
        .{ .path = "guest/bulk.rs", .bytes = 2, .sha256 = .{2} ** 32 },
        .{ .path = "guest/swap.rs", .bytes = 3, .sha256 = .{3} ** 32 },
    };
    const source_closure = try receipt_mod.SourceClosure.create(&source_files);
    const receipt = try receipt_mod.createFromReopened(
        std.testing.allocator,
        "/candidate/ethereum-combined.elf",
        &elf,
        elf_sha256,
        .{
            .path = "/checker/check-ethereum-combined-candidate",
            .bytes = 4,
            .sha256 = .{4} ** 32,
        },
        "/candidate/source",
        source_closure,
        false,
    );
    try receipt.validate();
    try receipt_mod.validateReopened(
        std.testing.allocator,
        receipt,
        &elf,
        source_closure,
    );
    const encoded = try receipt_mod.encodeAlloc(std.testing.allocator, receipt);
    defer std.testing.allocator.free(encoded);
    var parsed = try receipt_mod.decodeAlloc(std.testing.allocator, encoded);
    defer parsed.deinit();
    const decoded = try receipt_mod.fromWire(parsed.value);
    try receipt_mod.validateReopened(
        std.testing.allocator,
        decoded,
        &elf,
        source_closure,
    );
    const canonical = try receipt_mod.encodeAlloc(std.testing.allocator, decoded);
    defer std.testing.allocator.free(canonical);
    try std.testing.expectEqualSlices(u8, encoded, canonical);
    try std.testing.expectEqual(@as(u32, 1), receipt.inventory.bulk_memcpy_word_count);
    try std.testing.expectEqual(@as(u32, 1), receipt.inventory.stack_swap_word_count);

    var changed_source = source_files;
    changed_source[0].sha256[0] ^= 1;
    const changed_closure = try receipt_mod.SourceClosure.create(&changed_source);
    try std.testing.expectError(
        error.CombinedCandidateReopenMismatch,
        receipt_mod.validateReopened(
            std.testing.allocator,
            receipt,
            &elf,
            changed_closure,
        ),
    );
    try std.testing.expectError(
        error.InvalidCombinedCandidateFileIdentity,
        receipt_mod.SourceClosure.create(&.{.{
            .path = "../guest/combined.rs",
            .bytes = 1,
            .sha256 = .{1} ** 32,
        }}),
    );
}

fn authorityForElf(elf: []const u8) !authority_mod.Authority {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(elf, &digest, .{});
    return authority_mod.Authority.create(digest);
}
