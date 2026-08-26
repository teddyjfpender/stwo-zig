//! Exact ordered SegmentV2 cohort replay for the composition recorder.

pub fn record(self: anytype, components: anytype) @TypeOf(self.finishProgram()) {
    // Rows 0--9: authenticated transcript spine.
    _ = try self.recordTypedComponent(
        .control,
        &components.noncore.transcript.control,
    );
    _ = try self.recordTypedComponent(
        .transcript_air,
        &components.noncore.transcript.transcript_air,
    );
    _ = try self.recordTypedComponent(
        .transcript_binding,
        &components.noncore.transcript.transcript_binding,
    );
    _ = try self.recordTypedComponent(
        .transcript_state,
        &components.noncore.transcript.transcript_state,
    );
    _ = try self.recordTypedComponent(
        .transcript_word,
        &components.noncore.transcript.transcript_word,
    );
    _ = try self.recordTypedComponent(
        .transcript_payload,
        &components.noncore.transcript.transcript_payload,
    );
    _ = try self.recordTypedComponent(
        .pow_check,
        &components.noncore.transcript.pow_check,
    );
    _ = try self.recordTypedComponent(
        .pow_frame,
        &components.noncore.transcript.pow_frame,
    );
    _ = try self.recordTypedComponent(
        .relation_challenge,
        &components.noncore.transcript.relation_challenge,
    );
    _ = try self.recordTypedComponent(
        .verifier_randomness,
        &components.noncore.transcript.verifier_randomness,
    );

    // Rows 10--17: statement and public-data spines.
    _ = try self.recordTypedComponent(
        .statement_input,
        &components.noncore.statement.row10_inactive,
    );
    _ = try self.recordTypedComponent(
        .statement_semantics_input,
        &components.noncore.statement.row11_statement,
    );
    _ = try self.recordTypedComponent(
        .vm_public_claim_input,
        &components.noncore.public.publication_header,
    );
    _ = try self.recordTypedComponent(
        .vm_public_claim_hash,
        &components.noncore.public.native_public_sums,
    );
    _ = try self.recordTypedComponent(
        .vm_public_io_hash,
        &components.noncore.public.publication_seal,
    );
    _ = try self.recordTypedComponent(
        .vm_public_claim_semantics_input,
        &components.noncore.public.boundary_bridge,
    );
    _ = try self.recordTypedComponent(
        .vm_public_logup_input,
        &components.noncore.public.native_challenges,
    );
    _ = try self.recordTypedComponent(
        .vm_public_logup_control,
        &components.noncore.public.control_relay,
    );

    // Rows 18--34: captured native verifier core and its one shared
    // Poseidon provider.
    if (@hasField(@TypeOf(components.core), "composition_input")) {
        _ = try self.recordTypedComponent(
            .vm_air_composition_input,
            &components.core.composition_input,
        );
    } else {
        _ = try self.recordTypedComponent(
            .vm_air_composition_input,
            &components.core.vm_input,
        );
    }
    _ = try self.recordTypedComponent(
        .vm_air_composition_control,
        &components.core.composition_control,
    );
    _ = try self.recordTypedComponent(
        .query_bits,
        &components.core.query_bits,
    );
    _ = try self.recordTypedComponent(
        .query_mapping,
        &components.core.query_mapping,
    );
    _ = try self.recordTypedComponent(
        .merkle_root,
        &components.core.merkle_root,
    );
    _ = try self.recordTypedComponent(
        .trace_merkle,
        &components.core.trace_merkle,
    );
    _ = try self.recordTypedComponent(
        .pcs_deep_input,
        &components.core.pcs_deep,
    );
    _ = try self.recordTypedComponent(
        .fri_merkle_leaf,
        &components.core.fri_leaf,
    );
    _ = try self.recordTypedComponent(
        .fri_merkle_node,
        &components.core.fri_node,
    );
    _ = try self.recordTypedComponent(
        .fri_merkle_anchor,
        &components.core.fri_anchor,
    );
    if (@hasField(@TypeOf(components.core), "fri_control")) {
        _ = try self.recordTypedComponent(
            .fri_verifier_control,
            &components.core.fri_control,
        );
        _ = try self.recordTypedComponent(
            .fri_verifier_input,
            &components.core.fri_input,
        );
    } else {
        _ = try self.recordTypedComponent(
            .fri_verifier_control,
            &components.core.control,
        );
        _ = try self.recordTypedComponent(
            .fri_verifier_input,
            &components.core.input,
        );
    }
    _ = try self.recordTypedComponent(
        .qm31_mul,
        &components.core.multiply,
    );
    _ = try self.recordTypedComponent(
        .qm31_inv,
        &components.core.inverse,
    );
    _ = try self.recordTypedComponent(
        .linear_ops,
        &components.core.linear,
    );
    _ = try self.recordTypedComponent(
        .merkle_path,
        &components.core.merkle_path,
    );
    _ = try self.recordPoseidonProvider(&components.core.poseidon2);

    // Rows 35--38: shared range table, boundary sources, and the committed
    // verifier-input publisher.
    _ = try self.recordRangeCheck8x8Provider(&components.noncore.range);
    _ = try self.recordTypedComponent(
        .statement_source_v2,
        &components.noncore.boundary.statement,
    );
    _ = try self.recordTypedComponent(
        .public_logup_source_v2,
        &components.noncore.boundary.public_logup,
    );
    _ = try self.recordTypedComponent(
        .segment_publication_input_provider_v2,
        &components.noncore.verifier_input_provider,
    );
    return self.finishProgram();
}
