//! Hostile custody tests for the authenticated parent statement source.

const std = @import("std");

const admission = @import("outer_parent_child_admission.zig");
const pair_node = @import("pair_node.zig");
const protocol = @import("protocol.zig");
const source = @import("outer_parent_statement_source.zig");
const support = @import("outer_parent_transcript_source_test.zig");

const Dimensions = support.TEST_DIMENSIONS;
const Bundle = source.ChildBundle(Dimensions);
const Prepared = source.Prepared(Dimensions);

test "outer parent statement source is an allocation-free non-production boundary" {
    try std.testing.expectEqual(
        source.ProductionStatus.verifier_subsystem_only,
        source.CURRENT_STATUS,
    );
    try std.testing.expect(!source.COMPLETE_PARENT_STARK_VERIFIED);
    try std.testing.expectEqual(@as(usize, 0), source.HEAP_ALLOCATIONS_PER_PREPARE);
}

test "outer parent statement source authenticates exact ordered checkpoints and relation closure" {
    var fixture = try HonestFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const scratch = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(Dimensions),
    );
    defer std.testing.allocator.free(scratch);

    var prepared: Prepared = undefined;
    try Prepared.prepareInto(
        &prepared,
        scratch,
        fixture.authorityInputs(),
        fixture.bundles(),
    );
    try prepared.validate(&fixture.suite);
    try prepared.validateAgainst(
        scratch,
        fixture.authorityInputs(),
        fixture.bundles(),
    );

    try std.testing.expect(!prepared.productionReady());
    try std.testing.expectEqual(fixture.pair.context.session_id, prepared.statement.session_id);
    try std.testing.expectEqual(fixture.pair.context.job_id, prepared.statement.job_id);
    try std.testing.expectEqual(
        fixture.pair.context.execution_statement_id,
        prepared.statement.execution_statement_id,
    );
    try std.testing.expectEqual(
        fixture.pair.context.public_call_commitment,
        prepared.statement.public_call_commitment,
    );
    try std.testing.expectEqual(
        fixture.pair.context.aggregator_vk_id,
        prepared.statement.parent_vk_id,
    );
    try std.testing.expectEqual(
        try fixture.pair.context.challengeContextId(),
        prepared.statement.challenge_context_id,
    );
    try std.testing.expectEqual(
        try fixture.pair.context.contextId(),
        prepared.statement.authority_context_id,
    );
    try std.testing.expectEqual(
        prepared.witness.authenticated_root.pair.node_id,
        prepared.statement.authenticated_pair.node_id,
    );
    try std.testing.expectEqual(
        prepared.transcript.source_id,
        prepared.statement.transcript_source_id,
    );
    try std.testing.expect(prepared.witness.relation_closure.folded_total.isZero());

    const admitted = [_]*const support.AdmittedChild{ &fixture.left, &fixture.right };
    for (admitted, 0..) |child, index| {
        try std.testing.expectEqual(
            child.fixture.receipt.pre_core_channel,
            prepared.witness.checkpoints[index].pre_core,
        );
        try std.testing.expectEqual(
            child.candidate.receipt_id,
            prepared.witness.checkpoints[index].receipt_id,
        );
        try std.testing.expectEqual(
            child.candidate.transcript_id,
            prepared.witness.checkpoints[index].transcript_id,
        );
        try std.testing.expectEqual(
            child.candidate.profile_id,
            prepared.witness.custody[index].profile_id,
        );
        try std.testing.expectEqual(
            child.candidate.capture_id,
            prepared.witness.custody[index].capture_id,
        );
    }

    try std.testing.expectEqual(
        pair_node.AuthenticationPermutationCostV1.successful_prepared_root,
        prepared.performance.pair_authentication_permutations,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        prepared.performance.suite_preparation_permutations,
    );
    try std.testing.expectEqual(@as(usize, 0), prepared.performance.heap_allocations);
    try std.testing.expectEqual(
        @sizeOf(Prepared),
        prepared.performance.retained_witness_bytes,
    );
    try std.testing.expect(prepared.performance.source_identity_permutations > 0);
}

test "outer parent statement source rejects non-verifier authority atomically" {
    var fixture = try HonestFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const scratch = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(Dimensions),
    );
    defer std.testing.allocator.free(scratch);
    var destination: Prepared = undefined;
    const snapshot = poison(Prepared, &destination, 0xa7);

    var forged = fixture.authority;
    forged.children[0].summary_id[0] +%= 1;
    var inputs = fixture.authorityInputs();
    inputs.verified = &forged;
    try std.testing.expectError(
        error.AuthorityMismatch,
        Prepared.prepareInto(&destination, scratch, inputs, fixture.bundles()),
    );
    try expectUnchanged(Prepared, &destination, &snapshot);

    forged = fixture.authority;
    forged.children[0].signed_relation_total = pair_node.SecureFelt.zero();
    inputs.verified = &forged;
    try std.testing.expectError(
        error.AuthorityMismatch,
        Prepared.prepareInto(&destination, scratch, inputs, fixture.bundles()),
    );
    try expectUnchanged(Prepared, &destination, &snapshot);

    const bundles = fixture.bundles();
    try std.testing.expectError(
        error.ChildOrderMismatch,
        Prepared.prepareInto(
            &destination,
            scratch,
            fixture.authorityInputs(),
            .{ bundles[1], bundles[0] },
        ),
    );
    try expectUnchanged(Prepared, &destination, &snapshot);
}

test "outer parent statement source rejects checkpoint and VK substitutions atomically" {
    var fixture = try HonestFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const scratch = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(Dimensions),
    );
    defer std.testing.allocator.free(scratch);
    var destination: Prepared = undefined;
    const snapshot = poison(Prepared, &destination, 0xc3);

    fixture.left.fixture.receipt.pre_core_channel.digest[0] +%= 1;
    try std.testing.expectError(
        error.TranscriptMismatch,
        Prepared.prepareInto(
            &destination,
            scratch,
            fixture.authorityInputs(),
            fixture.bundles(),
        ),
    );
    try expectUnchanged(Prepared, &destination, &snapshot);
    fixture.left.fixture.receipt.pre_core_channel.digest[0] -%= 1;

    var wrong_pair = fixture.pair;
    wrong_pair.root_pin.expected_aggregator_vk_id[0] +%= 1;
    var inputs = fixture.authorityInputs();
    inputs.pair = wrong_pair;
    try std.testing.expectError(
        error.ChildBindingMismatch,
        Prepared.prepareInto(&destination, scratch, inputs, fixture.bundles()),
    );
    try expectUnchanged(Prepared, &destination, &snapshot);
}

test "outer parent statement retained witness rejects every authority-layer mutation" {
    var fixture = try HonestFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const scratch = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(Dimensions),
    );
    defer std.testing.allocator.free(scratch);
    var honest: Prepared = undefined;
    try Prepared.prepareInto(
        &honest,
        scratch,
        fixture.authorityInputs(),
        fixture.bundles(),
    );

    var mutated = honest;
    mutated.witness.checkpoints[0].pre_core.digest[0] +%= 1;
    try std.testing.expectError(error.PreparedSourceMismatch, mutated.validate(&fixture.suite));

    mutated = honest;
    mutated.statement.job_id[0] +%= 1;
    try std.testing.expectError(error.StatementMismatch, mutated.validate(&fixture.suite));

    mutated = honest;
    mutated.witness.relation_closure.folded_total.limbs[0] = 1;
    try std.testing.expectError(error.RelationClosureMismatch, mutated.validate(&fixture.suite));

    mutated = honest;
    mutated.witness.authenticated_root.pair.node_id[0] +%= 1;
    try std.testing.expectError(error.AuthorityMismatch, mutated.validate(&fixture.suite));

    mutated = honest;
    mutated.witness.record.children[0].summary_id[0] +%= 1;
    try std.testing.expectError(error.ChildAuthorityMismatch, mutated.validate(&fixture.suite));
}

test "outer parent statement source rejects aliased workspaces before publication" {
    var fixture = try HonestFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const scratch_len = admission.serializedByteCount(Dimensions);
    const backing = try std.testing.allocator.alignedAlloc(
        u8,
        .of(Prepared),
        @sizeOf(Prepared) + scratch_len,
    );
    defer std.testing.allocator.free(backing);
    const destination: *Prepared = @ptrCast(backing.ptr);
    const aliased_scratch = backing[1 .. 1 + scratch_len];
    const snapshot = poison(Prepared, destination, 0xe9);

    try std.testing.expectError(
        error.AliasedWorkspace,
        Prepared.prepareInto(
            destination,
            aliased_scratch,
            fixture.authorityInputs(),
            fixture.bundles(),
        ),
    );
    try expectUnchanged(Prepared, destination, &snapshot);

    const authority_scratch = try std.testing.allocator.alignedAlloc(
        u8,
        .of(pair_node.VerifierAuthorityV1),
        scratch_len,
    );
    defer std.testing.allocator.free(authority_scratch);
    const aliased_authority: *pair_node.VerifierAuthorityV1 =
        @ptrCast(authority_scratch.ptr);
    aliased_authority.* = fixture.authority;
    var aliased_inputs = fixture.authorityInputs();
    aliased_inputs.verified = aliased_authority;
    var separate_destination: Prepared = undefined;
    const separate_snapshot = poison(Prepared, &separate_destination, 0xb5);
    try std.testing.expectError(
        error.AliasedWorkspace,
        Prepared.prepareInto(
            &separate_destination,
            authority_scratch,
            aliased_inputs,
            fixture.bundles(),
        ),
    );
    try expectUnchanged(Prepared, &separate_destination, &separate_snapshot);

    const scratch = try std.testing.allocator.alloc(u8, scratch_len);
    defer std.testing.allocator.free(scratch);
    var honest: Prepared = undefined;
    try Prepared.prepareInto(
        &honest,
        scratch,
        fixture.authorityInputs(),
        fixture.bundles(),
    );
    destination.* = honest;
    const validation_snapshot = std.mem.asBytes(destination)[0..@sizeOf(Prepared)].*;
    try std.testing.expectError(
        error.AliasedWorkspace,
        destination.validateAgainst(
            aliased_scratch,
            fixture.authorityInputs(),
            fixture.bundles(),
        ),
    );
    try expectUnchanged(Prepared, destination, &validation_snapshot);
}

const HonestFixture = struct {
    left: support.AdmittedChild,
    right: support.AdmittedChild,
    pair: @import("outer_parent_transcript_source.zig").PairInputsV1,
    left_binding: admission.PairChildInputsV1,
    right_binding: admission.PairChildInputsV1,
    authority: pair_node.VerifierAuthorityV1,
    suite: pair_node.PreparedProtocolSuiteV1,

    fn init(allocator: std.mem.Allocator) !HonestFixture {
        var left = try support.AdmittedChild.init(allocator, 0, support.digest(11));
        errdefer left.deinit();
        var right = try support.AdmittedChild.init(allocator, 1, support.digest(11));
        errdefer right.deinit();
        const pair = try support.honestPairInputs();
        const total = pair_node.SecureFelt{ .limbs = .{ 17, 19, 23, 29 } };
        const left_binding = try support.childBinding(&left, pair, 0, total);
        const right_binding = try support.childBinding(&right, pair, 1, total.neg());
        const authority = authorityFromBindings(
            pair.context,
            .{ left_binding, right_binding },
            .{ left.candidate, right.candidate },
        );
        return .{
            .left = left,
            .right = right,
            .pair = pair,
            .left_binding = left_binding,
            .right_binding = right_binding,
            .authority = authority,
            .suite = try pair_node.prepareProtocolSuite(),
        };
    }

    fn deinit(self: *HonestFixture) void {
        self.right.deinit();
        self.left.deinit();
        self.* = undefined;
    }

    fn bundles(self: *const HonestFixture) [source.CHILD_COUNT]Bundle {
        return .{
            self.left.bundle(self.left_binding),
            self.right.bundle(self.right_binding),
        };
    }

    fn authorityInputs(self: *const HonestFixture) source.AuthorityInputsV1 {
        return .{
            .pair = self.pair,
            .verified = &self.authority,
            .suite = &self.suite,
        };
    }
};

fn authorityFromBindings(
    context: pair_node.VerifierContextV1,
    bindings: [source.CHILD_COUNT]admission.PairChildInputsV1,
    candidates: [source.CHILD_COUNT]admission.BinaryPairCandidateV1,
) pair_node.VerifierAuthorityV1 {
    var children: [source.CHILD_COUNT]pair_node.VerifiedChildV1 = undefined;
    for (&children, bindings, candidates) |*target, binding, candidate| target.* = .{
        .position = binding.position,
        .role = binding.role,
        .leaf_index = binding.leaf_index,
        .pair_index = binding.pair_index,
        .leaf_count = binding.leaf_count,
        .protocol_id = protocol.PROTOCOL_ID_WORDS,
        .session_id = binding.session_id,
        .challenge_context_id = binding.challenge_context_id,
        .authority_context_id = binding.authority_context_id,
        .parent_vk_id = binding.parent_vk_id,
        .statement_id = binding.statement_id,
        .proof_id = candidate.proof_id,
        .transcript_id = candidate.transcript_id,
        .summary_id = binding.summary_id,
        .event_count = binding.event_count,
        .signed_relation_total = binding.signed_relation_total,
    };
    return .{ .context = context, .children = children };
}

fn poison(comptime T: type, destination: *T, value: u8) [@sizeOf(T)]u8 {
    const bytes = std.mem.asBytes(destination);
    @memset(bytes, value);
    return bytes[0..@sizeOf(T)].*;
}

fn expectUnchanged(
    comptime T: type,
    destination: *const T,
    snapshot: *const [@sizeOf(T)]u8,
) !void {
    try std.testing.expectEqualSlices(u8, snapshot, std.mem.asBytes(destination));
}
