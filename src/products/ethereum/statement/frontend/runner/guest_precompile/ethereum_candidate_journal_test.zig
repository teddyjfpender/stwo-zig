//! Original custody, mutation and ordered member projection qualification.
const std = @import("std");
const registry_mod =
    @import("../../isa/ethereum_candidate_private_registry.zig");
const combined_authority_mod =
    @import("../../isa/ethereum_candidate_combined_authority.zig");
const zero_digest = @import("ethereum_candidate_journal_identity.zig").zero_digest;
const CanonicalArtifactCustody = @import("ethereum_candidate_execution_journal.zig").CanonicalArtifactCustody;
const CaptureKind = @import("ethereum_candidate_execution_journal.zig").CaptureKind;
const Digest = @import("ethereum_candidate_execution_journal.zig").Digest;
const MemberCapture = @import("ethereum_candidate_execution_journal.zig").MemberCapture;
const captureCombinedResultMembers = @import("ethereum_candidate_execution_journal.zig").captureCombinedResultMembers;
const upgradeBulkMemcpyExecutionMember = @import("ethereum_candidate_execution_journal.zig").upgradeBulkMemcpyExecutionMember;

test "combined candidate contract v1: journal slots reject tape and custody mutation" {
    const registry = try registry_mod.Registry.canonical();
    const empty_bulk = try MemberCapture.empty(registry, 0, 3, 9);
    try empty_bulk.validateAgainst(registry, 3);

    var relabelled = empty_bulk;
    relabelled.kind = .stack_swap_v1;
    try std.testing.expectError(
        error.InvalidEthereumCandidateMemberCapture,
        relabelled.validateAgainst(registry, 3),
    );
    var changed_tape = empty_bulk;
    changed_tape.tape_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidEthereumCandidateEmptyCapture,
        changed_tape.validateAgainst(registry, 3),
    );
    var changed_custody = empty_bulk;
    changed_custody.capture_custody_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidEthereumCandidateEmptyCapture,
        changed_custody.validateAgainst(registry, 3),
    );
}

test "combined candidate contract v1: artifact custody stays external and fail closed" {
    var custody = CanonicalArtifactCustody{
        .tape_artifact_identity = patternedDigest(1),
        .joint_receipt_custody_identity = patternedDigest(2),
        .cold_fresh_verified = true,
        .external_base_tables_required = true,
    };
    try custody.validate();
    custody.cold_fresh_verified = false;
    try std.testing.expectError(
        error.InvalidEthereumCandidateArtifactCustody,
        custody.validate(),
    );
}

test "combined candidate contract v1: execution artifact cannot self-promote" {
    const registry = try registry_mod.Registry.canonical();
    const execution = MemberCapture{
        .registry_index = 0,
        .kind = .bulk_memcpy_v1,
        .capture_kind = .canonical_execution_artifact,
        .external_step_origin = 7,
        .retirement_count = 2,
        .component_witness_row_count = 18,
        .tape_identity = patternedDigest(30),
        .capture_custody_identity = patternedDigest(31),
    };
    try execution.validateAgainst(registry, 4);

    const proof_custody = CanonicalArtifactCustody{
        .tape_artifact_identity = execution.tape_identity,
        .joint_receipt_custody_identity = patternedDigest(32),
        .cold_fresh_verified = true,
        .external_base_tables_required = true,
    };
    const upgraded = try upgradeBulkMemcpyExecutionMember(
        registry,
        4,
        execution,
        proof_custody,
    );
    try std.testing.expectEqual(
        CaptureKind.canonical_artifact,
        upgraded.capture_kind,
    );

    var mismatched = proof_custody;
    mismatched.tape_artifact_identity[0] ^= 1;
    try std.testing.expectError(
        error.EthereumCandidateExecutionArtifactProofMismatch,
        upgradeBulkMemcpyExecutionMember(registry, 4, execution, mismatched),
    );
}

test "combined candidate contract v1: final result projects both ordered member captures" {
    const test_elf = @import("stwo_riscv_rv32").testing.execution.guest_precompile.test_elf;
    const segment_session = @import("../../../frontend.zig").runner.segment_session;
    const elf = test_elf.buildEthereumCombinedCandidate();
    var elf_identity: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(&elf, &elf_identity, .{});
    const authority = try combined_authority_mod.Authority.create(elf_identity);
    const CandidateSession =
        segment_session.EthereumCombinedCandidateExecutionSessionV1();
    var session = try CandidateSession.initCandidate(
        std.testing.allocator,
        &elf,
        .{},
        authority,
    );
    defer session.deinit();
    var result = try session.startSegment(24);
    defer result.deinit();

    const custody = CanonicalArtifactCustody{
        .tape_artifact_identity = patternedDigest(10),
        .joint_receipt_custody_identity = patternedDigest(11),
        .cold_fresh_verified = true,
        .external_base_tables_required = true,
    };
    const captures = try captureCombinedResultMembers(
        authority.registry,
        result.ethereum.base.segment_index,
        0,
        authority,
        &result,
        custody,
        patternedDigest(12),
    );
    try std.testing.expectEqual(
        registry_mod.MemberKind.bulk_memcpy_v1,
        captures[0].?.kind,
    );
    try std.testing.expectEqual(@as(u32, 1), captures[0].?.retirement_count);
    try std.testing.expectEqual(@as(u64, 9), captures[0].?.component_witness_row_count);
    try std.testing.expectEqual(
        registry_mod.MemberKind.stack_swap_v1,
        captures[1].?.kind,
    );
    try std.testing.expectEqual(@as(u32, 1), captures[1].?.retirement_count);
    try std.testing.expectEqual(@as(u64, 9), captures[1].?.component_witness_row_count);

    try std.testing.expectError(
        error.InvalidEthereumCandidateStackSwapCustody,
        captureCombinedResultMembers(
            authority.registry,
            result.ethereum.base.segment_index,
            0,
            authority,
            &result,
            custody,
            zero_digest,
        ),
    );
}

fn patternedDigest(seed: u8) Digest {
    var result: Digest = undefined;
    for (&result, 0..) |*byte, index| byte.* = seed +% @as(u8, @truncate(index));
    return result;
}
