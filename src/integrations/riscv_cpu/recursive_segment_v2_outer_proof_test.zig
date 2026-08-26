//! Real proof wrapper for the complete 39-row SegmentV2 outer AIR.
//!
//! The CPU engine reconstructs an independent verifier cohort and commits its
//! proof capture, pointer-free temporal-child publication, and fixed recursive
//! witness in one fail-atomic transaction. The legacy frontend-generic cohort remains
//! explicitly unavailable; production uses the concrete integration cohort.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const integration = @import("stwo_riscv_cpu_integration");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const cohort_mod = recursion.segment_outer_cohort_v2;
const boundary = recursion.segment_leaf_outer_authority_v2;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const leaf_outer = integration.recursive_segment_v2_leaf_outer;
const outer_cohort = integration.recursive_segment_v2_outer_cohort;
const proof_engine = integration.recursive_segment_v2_outer_engine;

pub const VerifiedOuterProof = struct {
    receipt: proof_engine.Receipt,
    capture: proof_engine.OuterProofCapture,
    publication: proof_engine.VerifiedSegmentV2PublicationV1,
    recursive_witness: proof_engine.RecursiveWitnessV1,
};

/// The real proof path, ready to instantiate when a concrete cohort alias is
/// exported. `EngineKernel.proveAndVerify` constructs the prover and verifier
/// cohorts independently and writes all three outputs only after the verifier,
/// private publication, and recursive-witness validation accept. No detached claim, component,
/// closure audit, or prover-side receipt crosses that boundary.
pub fn provePreparedNativeLeaf(
    comptime Cohort: type,
    allocator: std.mem.Allocator,
    prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
    authority_inputs: Cohort.AuthorityInputs,
    execution: proof_engine.ExecutionOptions,
) !VerifiedOuterProof {
    try prepared.validate();
    const Kernel = proof_engine.EngineKernel(Cohort);
    var capture: proof_engine.OuterProofCapture = undefined;
    var publication: proof_engine.VerifiedSegmentV2PublicationV1 = undefined;
    var recursive_witness: proof_engine.RecursiveWitnessV1 = undefined;
    const receipt = try Kernel.proveAndVerifyWithExecution(
        allocator,
        authority_inputs,
        execution,
        &capture,
        &publication,
        &recursive_witness,
    );
    errdefer capture.deinit(allocator);
    try receipt.validate();
    try publication.validate();
    if (receipt.canonical_proof_bytes !=
        publication.canonical_proof_byte_count or
        !std.meta.eql(receipt.canonical_proof_id, publication.proof_id) or
        !std.mem.eql(
            u8,
            &receipt.canonical_proof_sha256,
            &publication.canonical_proof_sha_id,
        ))
    {
        return error.VerifierPublicationMismatch;
    }
    std.debug.print(
        "\nSEGMENT_V2_OUTER status=verified rows={d} domains={d} " ++
            "proof_size_estimate_bytes={d} canonical_proof_bytes={d} " ++
            "canonicalize_ms={d:.3} prove_ms={d:.3} verify_ms={d:.3} " ++
            "publication_ms={d:.3} " ++
            "draws={d} cols={d}/{d}/{d} workers={d}\n",
        .{
            receipt.roster_count,
            cohort_mod.DOMAIN_COUNT,
            receipt.proof_size_estimate,
            receipt.canonical_proof_bytes,
            milliseconds(receipt.proof_canonicalize_ns),
            milliseconds(receipt.prove_ns),
            milliseconds(receipt.verify_ns),
            milliseconds(receipt.publication_ns),
            receipt.transcript_draws,
            receipt.preprocessed_columns,
            receipt.main_columns,
            receipt.interaction_columns,
            receipt.worker_count,
        },
    );
    return .{
        .receipt = receipt,
        .capture = capture,
        .publication = publication,
        .recursive_witness = recursive_witness,
    };
}

test "SegmentV2 real outer proof remains explicitly unavailable without a concrete cohort" {
    std.testing.refAllDeclsRecursive(leaf_outer.PreparedNativeV2LeafOuter);
    std.testing.refAllDeclsRecursive(proof_engine);

    try std.testing.expectEqual(@as(usize, 39), proof_engine.COMPLETE_ROW_COUNT);
    try std.testing.expectEqual(@as(usize, 39), cohort_mod.COMPONENT_COUNT);
    try std.testing.expectEqual(@as(usize, 47), cohort_mod.DOMAIN_COUNT);
    try std.testing.expectEqual(@as(usize, 3), cohort_mod.TREE_COUNT);
    try std.testing.expectEqual(
        cohort_mod.ALL_COMPONENT_MASK,
        (@as(u64, 1) << 39) - 1,
    );
    try std.testing.expectEqual(
        cohort_mod.ALL_DOMAIN_MASK,
        (@as(u64, 1) << 47) - 1,
    );

    const capabilities = cohort_mod.CapabilityLedgerV2.current();
    try capabilities.validate();
    try std.testing.expect(!capabilities.production_ready);
    try std.testing.expect(!capabilities.has(.core_components));
    try std.testing.expect(!capabilities.has(.complete_proof_gate));
    try std.testing.expect(!capabilities.has(.verifier_domain_audit_custody));
    try std.testing.expect(!capabilities.has(.independent_outer_prove_verify));
    try std.testing.expect(!cohort_mod.CONCRETE_PRODUCTION_COHORT_AVAILABLE);
    try std.testing.expectError(
        error.ProductionReadinessUnavailable,
        requireConcreteProofCohort(),
    );

    // Output aliasing is rejected before the concrete cohort dereferences its
    // authority input, so this gate is allocation-free and performs no proof.
    const Kernel = proof_engine.EngineKernel(outer_cohort.Cohort);
    comptime std.debug.assert(
        @sizeOf(proof_engine.VerifiedSegmentV2PublicationV1) >=
            @sizeOf(proof_engine.OuterProofCapture),
    );
    comptime std.debug.assert(
        @alignOf(proof_engine.VerifiedSegmentV2PublicationV1) >=
            @alignOf(proof_engine.OuterProofCapture),
    );
    var unpublished: proof_engine.VerifiedSegmentV2PublicationV1 = undefined;
    @memset(std.mem.asBytes(&unpublished), 0x6d);
    const before = std.mem.asBytes(&unpublished)[0..@sizeOf(
        proof_engine.VerifiedSegmentV2PublicationV1,
    )].*;
    const aliased_capture: *proof_engine.OuterProofCapture = @ptrCast(
        @alignCast(&unpublished),
    );
    var unpublished_witness: proof_engine.RecursiveWitnessV1 = undefined;
    try std.testing.expectError(
        error.TransactionOutputAlias,
        Kernel.proveAndVerify(
            std.testing.allocator,
            undefined,
            aliased_capture,
            &unpublished,
            &unpublished_witness,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &before,
        std.mem.asBytes(&unpublished),
    );

    std.debug.print(
        "\nSEGMENT_V2_OUTER status=blocked rows={d} domains={d} trees={d} " ++
            "missing_capabilities={d} missing_rows={d} " ++
            "proof_size_estimate_bytes=NA " ++
            "prove_ms=NA verify_ms=NA capture=false\n",
        .{
            cohort_mod.COMPONENT_COUNT,
            cohort_mod.DOMAIN_COUNT,
            cohort_mod.TREE_COUNT,
            @popCount(capabilities.missing_mask),
            @popCount(capabilities.missing_component_rows),
        },
    );
}

test "SegmentV2 outer harness rejects boundary-claim and provider-schedule mutation" {
    const statement = QM31.fromU32Unchecked(3, 5, 7, 11);
    const verifier_input = QM31.fromU32Unchecked(13, 17, 19, 23);
    const publication_bridge = QM31.fromU32Unchecked(29, 31, 37, 41);
    const honest = boundary.BoundaryClosureV2.init(
        statement,
        verifier_input,
        publication_bridge,
    );
    try honest.validate();

    var mutated_claim = honest;
    mutated_claim.publication_bridge_emit =
        mutated_claim.publication_bridge_emit.add(QM31.one());
    try std.testing.expectError(
        error.CrossDomainClosureMismatch,
        mutated_claim.validate(),
    );

    const calls = [_]poseidon2_air.Call{
        poseidonCall(11),
        poseidonCall(29),
        poseidonCall(47),
    };
    const honest_schedule =
        try leaf_outer.SharedPoseidonCallLayoutV2.initBoundaryPrefix(
            2,
            1,
            &calls,
        );
    try honest_schedule.validate(&calls);
    try std.testing.expect(!honest_schedule.call_set_complete);

    var mutated_schedule = honest_schedule;
    mutated_schedule.statement_authority.start -= 1;
    try std.testing.expectError(
        error.CallLayoutMismatch,
        mutated_schedule.validate(&calls),
    );
}

fn requireConcreteProofCohort() !void {
    if (!cohort_mod.CONCRETE_PRODUCTION_COHORT_AVAILABLE)
        return error.ProductionReadinessUnavailable;
}

fn poseidonCall(seed: u32) poseidon2_air.Call {
    var input: [poseidon2_air.WIDTH]u32 = undefined;
    for (&input, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return .{
        .input = input,
        .wide = false,
        .io = true,
        .narrow_output = null,
    };
}

fn milliseconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_ms;
}
