const std = @import("std");
const profile = @import("../../../isa/execution_profile.zig");
const sha = @import("../../../isa/sha256_compression_v1.zig");
const fixture = @import("../test_elf.zig");
const runner = @import("../../mod.zig");

test "SHA profile exact admission and declared program operands preserve legacy identities" {
    try std.testing.expectEqual(@as(u16, 4), @intFromEnum(profile.ExecutionProfile.rv32im_zkvm_ethereum_sha_v1));
    try std.testing.expectEqual(@as(u64, 14), profile.ExecutionProfile.rv32im_zkvm_ethereum_sha_v1.requiredCapabilities());
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("riscv.ethereum.keccakf_1600.secp256k1_recover.sha256_compress.v1", &digest, .{});
    try std.testing.expectEqualDeep(digest, profile.ethereum_sha_semantic_digest);
    const elf = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    try std.testing.expectEqual(profile.ExecutionProfile.rv32im_zkvm_ethereum_sha_v1, try @import("../../elf_admission.zig").parseAfterIdentityValidation(&elf));
    const descriptor = std.mem.indexOf(u8, &elf, profile.admission.descriptor_magic).?;
    var invalid = elf;
    invalid[descriptor + 12] ^= 8;
    try std.testing.expectError(error.UnsupportedRequiredCapabilities, @import("../../elf_admission.zig").parseAfterIdentityValidation(&invalid));
    invalid = elf;
    invalid[descriptor + 20] ^= 2;
    try std.testing.expectError(error.UnsupportedEthereumShaAbi, @import("../../elf_admission.zig").parseAfterIdentityValidation(&invalid));
    invalid = elf;
    invalid[descriptor + 24] ^= 1;
    try std.testing.expectError(error.EthereumShaSemanticDigestMismatch, @import("../../elf_admission.zig").parseAfterIdentityValidation(&invalid));
    const program = @import("../../../air/program/decode.zig");
    for (0..32) |s| for (0..32) |b| {
        const word = sha.encode(@intCast(s), @intCast(b));
        try std.testing.expectEqualDeep(program.ProgramValues{ 50, 0, @intCast(s), @intCast(b) }, try program.decodeProgramWordForProfile(.rv32im_zkvm_ethereum_sha_v1, word));
        try std.testing.expectError(error.InvalidPrecompileEncoding, program.decodeProgramWordForProfile(.rv32im_zkvm_ethereum_v1, word));
    };
}

fn execute(a: std.mem.Allocator, frame: runner.SegmentClockFrame) !void {
    const elf = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    var session = try runner.EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = frame, .trace_retention = if (frame == .leaf_local) .segment_owned else .cumulative });
    defer session.deinit();
    var first = try session.startSegment(4);
    var first_alive = true;
    defer if (first_alive) first.deinit();
    const token = first.base.continuation.?;
    try std.testing.expectEqual(@as(usize, 1), first.extension.sha_calls.len());
    try std.testing.expectEqual(@as(usize, 0), first.extension.keccakf_calls.len());
    try std.testing.expectEqual(@as(u32, 4), first.extension.sha_calls.records()[0].call.execution_clock);
    first.deinit(); // Resume cannot borrow any of the prior segment's buffers.
    first_alive = false;
    var second = try session.resumeSegment(token, 4);
    defer second.deinit();
    try std.testing.expect(second.base.continuation == null);
    try std.testing.expectEqual(runner.CompletionReason.self_loop, second.base.completion_reason.?);
    try std.testing.expectEqual(@as(usize, 1), second.extension.sha_calls.len());
    try std.testing.expectEqual(@as(usize, 1), second.extension.keccakf_calls.len());
    try std.testing.expectEqual(@as(u32, if (frame == .leaf_local) 2 else 6), second.extension.sha_calls.records()[0].call.execution_clock);
}

test "SHA profile segmented execution owns frozen tapes across both clock frames" {
    try execute(std.testing.allocator, .global_continuous);
    try execute(std.testing.allocator, .leaf_local);
}

test "SHA profile one shot result uses the canonical session and old ELF rejects SHA" {
    const a = std.testing.allocator;
    const elf = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    var session = try runner.EthereumShaExecutionSession.initLegacy(a, &elf, .{});
    defer session.deinit();
    var run = try session.runLegacy(16);
    defer run.deinit();
    try std.testing.expectEqual(@as(usize, 2), run.extension.sha_calls.len());
    try std.testing.expectEqual(@as(usize, 1), run.extension.keccakf_calls.len());
    const old_elf = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_v1);
    var old = try runner.EthereumExecutionSession.initLegacy(a, &old_elf, .{});
    defer old.deinit();
    try std.testing.expectError(error.InvalidPrecompileEncoding, old.runLegacy(16));
}
