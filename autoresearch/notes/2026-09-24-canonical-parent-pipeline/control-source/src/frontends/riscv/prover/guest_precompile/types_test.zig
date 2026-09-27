const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const caller_component = @import("../../air/guest_precompile/caller_component.zig");
const artifact_identity = @import("../../air/guest_precompile/artifact_identity.zig");
const proof_transcript = @import("../../air/guest_precompile/proof_transcript.zig");
const provider_component = @import("../../air/guest_precompile/provider_component.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const support = @import("../../air/guest_precompile/main_trace_test_support.zig");
const base_statement = @import("../../air/statement.zig");
const base_types = @import("../types.zig");
const subject = @import("types.zig");

const Fixture = struct {
    core_statement: base_statement.RiscVStatement,
    extension: guest_statement.ExtensionStatement,
    artifact: artifact_identity.Identity,

    fn init(n_guest: u32) !Fixture {
        const core_statement = support.coreFixture(n_guest);
        const extension = try guest_statement.ExtensionStatement.canonical(
            &core_statement,
            n_guest,
        );
        return .{
            .core_statement = core_statement,
            .extension = extension,
            .artifact = try artifact_identity.Identity.canonical(
                &core_statement,
                &extension,
            ),
        };
    }
};

const ComponentSums = struct {
    caller: [subject.caller_batch_count]QM31,
    provider: [subject.provider_batch_count]QM31,

    fn balanced(value: u32) ComponentSums {
        var result = zero();
        const sum = felt(value);
        result.caller[result.caller.len - 1] = sum.neg();
        result.provider[result.provider.len - 1] = sum;
        return result;
    }

    fn zero() ComponentSums {
        return .{
            .caller = [_]QM31{QM31.zero()} ** subject.caller_batch_count,
            .provider = [_]QM31{QM31.zero()} ** subject.provider_batch_count,
        };
    }
};

fn felt(value: u32) QM31 {
    return QM31.fromU32Unchecked(value, 0, 0, 0);
}

fn expectFelt(expected: QM31, actual: QM31) !void {
    try std.testing.expect(expected.eql(actual));
}

fn initFinishedClaim(
    allocator: std.mem.Allocator,
    fixture: *const Fixture,
    sums: *const ComponentSums,
    interaction_pow: u64,
) !*subject.InteractionClaim {
    const claim = try subject.InteractionClaim.initBaseInto(
        allocator,
        &fixture.core_statement,
        &fixture.extension,
    );
    errdefer claim.destroy(allocator);
    claim.base.initZeroInto();
    claim.base.n_components = fixture.core_statement.n_components;
    claim.base.n_infra = fixture.core_statement.n_infra;
    claim.base.interaction_pow = interaction_pow;
    try claim.finishCanonical(
        &fixture.core_statement,
        &fixture.extension,
        &sums.caller,
        &sums.provider,
    );
    return claim;
}

fn exerciseClaimAllocation(
    allocator: std.mem.Allocator,
    fixture: *const Fixture,
) !void {
    const claim = try subject.InteractionClaim.initBaseInto(
        allocator,
        &fixture.core_statement,
        &fixture.extension,
    );
    claim.destroy(allocator);
}

test "one-box claim receives base in place and publishes canonical statement" {
    const fixture = try Fixture.init(1);
    const sums = ComponentSums.balanced(19);
    var counter = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = counter.allocator();
    const claim = try subject.InteractionClaim.initBaseInto(
        allocator,
        &fixture.core_statement,
        &fixture.extension,
    );
    defer claim.destroy(allocator);

    try std.testing.expectEqual(@as(usize, 1), subject.claim_box_allocation_count);
    try std.testing.expectEqual(@as(usize, 1), counter.alloc_index);
    try std.testing.expectEqual(@sizeOf(subject.InteractionClaim), counter.allocated_bytes);
    try std.testing.expect(!claim.finalized);
    try std.testing.expectError(
        error.InteractionClaimNotFinalized,
        claim.validate(&fixture.core_statement, &fixture.extension),
    );

    // Mirrors Tree-2 generation: initialize the embedded destination directly,
    // without ever materializing a second fixed-capacity base claim.
    claim.base.initZeroInto();
    claim.base.n_components = fixture.core_statement.n_components;
    claim.base.n_infra = fixture.core_statement.n_infra;
    claim.base.interaction_pow = 37;
    try claim.finishCanonical(
        &fixture.core_statement,
        &fixture.extension,
        &sums.caller,
        &sums.provider,
    );
    try claim.validate(&fixture.core_statement, &fixture.extension);
    try std.testing.expect(claim.finalized);
    try std.testing.expectEqual(@as(u64, 37), claim.interactionPow());
    try expectFelt(felt(19).neg(), claim.caller.component_sum);
    try expectFelt(felt(19), claim.provider.component_sum);
    try std.testing.expect(std.meta.eql(
        fixture.extension.components[0],
        claim.caller.descriptor,
    ));
    try std.testing.expect(std.meta.eql(
        fixture.extension.components[1],
        claim.provider.descriptor,
    ));
    try std.testing.expectError(
        error.InteractionClaimAlreadyFinalized,
        claim.finishCanonical(
            &fixture.core_statement,
            &fixture.extension,
            &sums.caller,
            &sums.provider,
        ),
    );

    const scratch = try std.testing.allocator.create(
        base_statement.CanonicalInteractionClaim,
    );
    defer std.testing.allocator.destroy(scratch);
    const statement_claim = try claim.canonicalStatementClaim(
        &fixture.core_statement,
        &fixture.extension,
        scratch,
    );
    try expectFelt(claim.caller.component_sum, statement_claim.extension_sums[0]);
    try expectFelt(claim.provider.component_sum, statement_claim.extension_sums[1]);
    try std.testing.expectEqual(
        fixture.core_statement.nInteractionColumns(),
        statement_claim.base.log_sizes.len,
    );
    try std.testing.expect(statement_claim.total().isZero());

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseClaimAllocation,
        .{&fixture},
    );
}

test "claim validation rejects detailed aggregate descriptor count and cancellation tampering" {
    const fixture = try Fixture.init(1);
    const sums = ComponentSums.balanced(23);
    const claim = try initFinishedClaim(
        std.testing.allocator,
        &fixture,
        &sums,
        41,
    );
    defer claim.destroy(std.testing.allocator);
    const delta = felt(1);

    const detailed = claim.caller.batch_sums[0];
    claim.caller.batch_sums[0] = detailed.add(delta);
    try std.testing.expectError(
        error.ComponentClaimMismatch,
        claim.validate(&fixture.core_statement, &fixture.extension),
    );
    claim.caller.batch_sums[0] = detailed;

    const aggregate = claim.provider.component_sum;
    claim.provider.component_sum = aggregate.add(delta);
    try std.testing.expectError(
        error.ComponentClaimMismatch,
        claim.validate(&fixture.core_statement, &fixture.extension),
    );
    claim.provider.component_sum = aggregate;

    claim.caller.descriptor.n_rows += 1;
    try std.testing.expectError(
        error.ClaimDescriptorMismatch,
        claim.validate(&fixture.core_statement, &fixture.extension),
    );
    claim.caller.descriptor.n_rows -= 1;

    claim.base.n_components += 1;
    try std.testing.expectError(
        error.BaseClaimCountMismatch,
        claim.validate(&fixture.core_statement, &fixture.extension),
    );
    claim.base.n_components -= 1;

    var changed_extension = fixture.extension;
    changed_extension.counts.frozen_call_count += 1;
    try std.testing.expectError(
        error.CallCountMismatch,
        claim.validate(&fixture.core_statement, &changed_extension),
    );

    const caller_last = claim.caller.batch_sums.len - 1;
    claim.caller.batch_sums[caller_last] = claim.caller.batch_sums[caller_last].add(delta);
    claim.caller.component_sum = claim.caller.component_sum.add(delta);
    try std.testing.expectError(
        error.UnbalancedGuestRelation,
        claim.validate(&fixture.core_statement, &fixture.extension),
    );
    claim.caller.batch_sums[caller_last] = claim.caller.batch_sums[caller_last].sub(delta);
    claim.caller.component_sum = claim.caller.component_sum.sub(delta);
    try claim.validate(&fixture.core_statement, &fixture.extension);
}

test "finish is transactional and zero-row claims are exactly zero" {
    const fixture = try Fixture.init(0);
    const claim = try subject.InteractionClaim.initBaseInto(
        std.testing.allocator,
        &fixture.core_statement,
        &fixture.extension,
    );
    defer claim.destroy(std.testing.allocator);
    claim.base.initZeroInto();
    claim.base.n_components = fixture.core_statement.n_components;
    claim.base.n_infra = fixture.core_statement.n_infra;

    var sums = ComponentSums.zero();
    sums.caller[0] = felt(1);
    try std.testing.expectError(
        error.NonZeroEmptyClaim,
        claim.finishCanonical(
            &fixture.core_statement,
            &fixture.extension,
            &sums.caller,
            &sums.provider,
        ),
    );
    try std.testing.expect(!claim.finalized);

    sums = ComponentSums.zero();
    sums.provider[0] = felt(1);
    try std.testing.expectError(
        error.NonzeroLegacyBatchClaim,
        claim.finishCanonical(
            &fixture.core_statement,
            &fixture.extension,
            &sums.caller,
            &sums.provider,
        ),
    );
    try std.testing.expect(!claim.finalized);

    sums = ComponentSums.zero();
    sums.provider[1] = felt(1);
    try std.testing.expectError(
        error.NonZeroEmptyClaim,
        claim.finishCanonical(
            &fixture.core_statement,
            &fixture.extension,
            &sums.caller,
            &sums.provider,
        ),
    );
    try std.testing.expect(!claim.finalized);

    sums = ComponentSums.zero();
    try claim.finishCanonical(
        &fixture.core_statement,
        &fixture.extension,
        &sums.caller,
        &sums.provider,
    );
    try claim.validate(&fixture.core_statement, &fixture.extension);
    try std.testing.expect(claim.caller.component_sum.isZero());
    try std.testing.expect(claim.provider.component_sum.isZero());
}

test "embedded base nonce remains the only PoW source and verifier authenticates it" {
    const fixture = try Fixture.init(1);
    const sums = ComponentSums.balanced(29);
    var prover_channel = base_types.Channel{};
    const prover_result = try proof_transcript.proveToRelations(
        std.testing.allocator,
        &prover_channel,
        &fixture.core_statement,
        &fixture.extension,
    );
    const claim = try initFinishedClaim(
        std.testing.allocator,
        &fixture,
        &sums,
        prover_result.interaction_pow,
    );
    defer claim.destroy(std.testing.allocator);

    var verifier_channel = base_types.Channel{};
    _ = try proof_transcript.verifyToRelations(
        std.testing.allocator,
        &verifier_channel,
        &fixture.core_statement,
        &fixture.extension,
        claim.interactionPow(),
    );

    const invalid = try findInvalidPow(&fixture, claim.interactionPow() +% 1);
    claim.base.interaction_pow = invalid;
    try claim.validate(&fixture.core_statement, &fixture.extension);
    var rejected_channel = base_types.Channel{};
    try std.testing.expectError(
        error.InvalidInteractionProofOfWork,
        proof_transcript.verifyToRelations(
            std.testing.allocator,
            &rejected_channel,
            &fixture.core_statement,
            &fixture.extension,
            claim.interactionPow(),
        ),
    );
}

fn findInvalidPow(fixture: *const Fixture, first: u64) !u64 {
    var candidate = first;
    for (0..4096) |_| {
        var channel = base_types.Channel{};
        if (proof_transcript.verifyToRelations(
            std.testing.allocator,
            &channel,
            &fixture.core_statement,
            &fixture.extension,
            candidate,
        )) |_| {
            candidate +%= 1;
        } else |err| {
            if (err == error.InvalidInteractionProofOfWork) return candidate;
            return err;
        }
    }
    return error.InvalidPowSearchExhausted;
}

test "profile output releases proof and claim across both ownership paths" {
    const fixture = try Fixture.init(1);
    const sums = ComponentSums.balanced(31);
    var counter = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = counter.allocator();

    var owned = try makeOutput(allocator, &fixture, &sums);
    owned.deinit(allocator);
    try std.testing.expectEqual(counter.allocated_bytes, counter.freed_bytes);

    var moved = try makeOutput(allocator, &fixture, &sums);
    var proof = moved.proof;
    moved.deinitAfterProofMoved(allocator);
    proof.deinit(allocator);
    try std.testing.expectEqual(counter.allocated_bytes, counter.freed_bytes);
}

fn makeOutput(
    allocator: std.mem.Allocator,
    fixture: *const Fixture,
    sums: *const ComponentSums,
) !subject.ProveOutput {
    const claim = try initFinishedClaim(allocator, fixture, sums, 43);
    errdefer claim.destroy(allocator);
    var proof = try emptyProof(allocator);
    errdefer proof.deinit(allocator);
    return .{
        .proof = proof,
        .statement = fixture.core_statement,
        .extension = fixture.extension,
        .artifact = fixture.artifact,
        .interaction_claim = claim,
    };
}

fn emptyProof(allocator: std.mem.Allocator) !base_types.Proof {
    const Hasher = base_types.Hasher;
    const MerkleDecommitment = core.vcs_lifted.verifier.MerkleDecommitmentLifted(Hasher);
    const FriLayer = core.fri.FriLayerProof(Hasher);

    const commitments = try allocator.alloc(Hasher.Hash, 0);
    errdefer allocator.free(commitments);
    const sampled_values = try allocator.alloc([][]QM31, 0);
    errdefer allocator.free(sampled_values);
    const decommitments = try allocator.alloc(MerkleDecommitment, 0);
    errdefer allocator.free(decommitments);
    const queried_values = try allocator.alloc([][]M31, 0);
    errdefer allocator.free(queried_values);
    const first_witness = try allocator.alloc(QM31, 0);
    errdefer allocator.free(first_witness);
    const first_hashes = try allocator.alloc(Hasher.Hash, 0);
    errdefer allocator.free(first_hashes);
    const inner_layers = try allocator.alloc(FriLayer, 0);
    errdefer allocator.free(inner_layers);
    const last_coefficients = try allocator.dupe(QM31, &.{QM31.one()});
    errdefer allocator.free(last_coefficients);

    return .{ .commitment_scheme_proof = .{
        .config = core.pcs.PcsConfig.default(),
        .commitments = core.pcs.TreeVec(Hasher.Hash).initOwned(commitments),
        .sampled_values = core.pcs.TreeVec([][]QM31).initOwned(sampled_values),
        .decommitments = core.pcs.TreeVec(MerkleDecommitment).initOwned(decommitments),
        .queried_values = core.pcs.TreeVec([][]M31).initOwned(queried_values),
        .proof_of_work = 0,
        .fri_proof = .{
            .first_layer = .{
                .fri_witness = first_witness,
                .decommitment = .{ .hash_witness = first_hashes },
                .commitment = [_]u8{0} ** 32,
            },
            .inner_layers = inner_layers,
            .last_layer_poly = core.poly.line.LinePoly.initOwned(last_coefficients),
        },
    } };
}

comptime {
    if (subject.caller_batch_count != 77 or
        subject.provider_batch_count != 2 or
        caller_component.batch_count != subject.caller_batch_count or
        provider_component.batch_count != subject.provider_batch_count)
    {
        @compileError("ownership test geometry drifted");
    }
}
