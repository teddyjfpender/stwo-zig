//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const QM31 = context.d_QM31;
        const composition_control_witness = context.d_composition_control_witness;
        const fri_leaf_witness = context.d_fri_leaf_witness;
        const input_witness = context.d_input_witness;
        const lowering = context.d_lowering;
        const linear_witness = context.d_linear_witness;
        const manifest_v2 = context.d_manifest_v2;
        const shared_provider = context.d_shared_provider;
        const universal = context.d_universal;
        const LogIndex = context.d_LogIndex;
        const V2VmInputAdapter = context.d_V2VmInputAdapter;
        const V2CompositionControlAdapter = context.d_V2CompositionControlAdapter;
        const V2QueryBitsAdapter = context.d_V2QueryBitsAdapter;
        const V2QueryMappingAdapter = context.d_V2QueryMappingAdapter;
        const V2MerkleRootAdapter = context.d_V2MerkleRootAdapter;
        const V2TraceMerkleAdapter = context.d_V2TraceMerkleAdapter;
        const V2PcsAdapter = context.d_V2PcsAdapter;
        const V2FriLeafAdapter = context.d_V2FriLeafAdapter;
        const V2FriNodeAdapter = context.d_V2FriNodeAdapter;
        const V2FriAnchorAdapter = context.d_V2FriAnchorAdapter;
        const V2ControlAdapter = context.d_V2ControlAdapter;
        const V2InputAdapter = context.d_V2InputAdapter;
        const V2MultiplyAdapter = context.d_V2MultiplyAdapter;
        const V2InverseAdapter = context.d_V2InverseAdapter;
        const V2LinearAdapter = context.d_V2LinearAdapter;
        const V2MerklePathAdapter = context.d_V2MerklePathAdapter;
        const V2Poseidon2Adapter = context.d_V2Poseidon2Adapter;
        const CLOSURE_DIAGNOSTIC_ENV = context.d_CLOSURE_DIAGNOSTIC_ENV;
        const NativeSegmentCoreGeneratedV2 = context.d_NativeSegmentCoreGeneratedV2;
        const NativeSegmentCoreComponentsV2 = context.d_NativeSegmentCoreComponentsV2;
        const NativeSegmentCoreV2 = context.d_NativeSegmentCoreV2;
        const InvocationBuffers = context.d_InvocationBuffers;
        const vmInputParameters = context.d_vmInputParameters;
        const merkleRootParameters = context.d_merkleRootParameters;
        const traceMerkleParameters = context.d_traceMerkleParameters;
        const friLeafParameters = context.d_friLeafParameters;
        const friAnchorParameters = context.d_friAnchorParameters;
        const queryBitsParameters = context.d_queryBitsParameters;
        const queryMappingParameters = context.d_queryMappingParameters;
        const controlParameters = context.d_controlParameters;
        const inputParameters = context.d_inputParameters;
        const pcsParameters = context.d_pcsParameters;

        pub fn initNativeSegmentCoreComponents(
            self: *NativeSegmentCoreV2,
            manifest: *const manifest_v2.Manifest,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            generated: *const NativeSegmentCoreGeneratedV2,
        ) !NativeSegmentCoreComponentsV2 {
            try self.validateAgainstManifest(manifest);
            try generated.validateAgainst(self, relations, provider_relations);
            const authority = &self.authority;
            const logs = authority.log_sizes;
            return .{
                .vm_input = try V2VmInputAdapter.init(
                    &authority.vm_air.?.definition,
                    authority.vm_air.?.relation,
                    manifest,
                    .vm_air_composition_input,
                    logs[LogIndex.vm_input],
                    vmInputParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.vm_input],
                ),
                .composition_control = try V2CompositionControlAdapter.init(
                    &authority.composition_control_definition,
                    authority.composition_control_relation,
                    manifest,
                    .vm_air_composition_control,
                    logs[LogIndex.composition_control],
                    composition_control_witness.ProofKind.segment_leaf.selectors()[0..2].*,
                    relations,
                    generated.claims[LogIndex.composition_control],
                ),
                .query_bits = try V2QueryBitsAdapter.init(
                    &authority.query_bits_definition,
                    authority.query_bits_relation,
                    manifest,
                    .query_bits,
                    logs[LogIndex.query_bits],
                    try queryBitsParameters(
                        authority.query_bits_reference,
                        .segment_leaf,
                    ),
                    relations,
                    generated.claims[LogIndex.query_bits],
                ),
                .query_mapping = try V2QueryMappingAdapter.init(
                    &authority.query_mapping_definition,
                    authority.query_mapping_relation,
                    manifest,
                    .query_mapping,
                    logs[LogIndex.query_mapping],
                    queryMappingParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.query_mapping],
                ),
                .merkle_root = try V2MerkleRootAdapter.init(
                    &authority.merkle_root_definition,
                    authority.merkle_root_relation,
                    manifest,
                    .merkle_root,
                    logs[LogIndex.merkle_root],
                    merkleRootParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.merkle_root],
                ),
                .trace_merkle = try V2TraceMerkleAdapter.init(
                    &authority.trace_merkle_definition,
                    authority.trace_merkle_relation,
                    manifest,
                    .trace_merkle,
                    logs[LogIndex.trace_merkle],
                    traceMerkleParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.trace_merkle],
                ),
                .pcs_deep = try V2PcsAdapter.init(
                    &authority.pcs_definition,
                    authority.pcs_relation,
                    manifest,
                    .pcs_deep_input,
                    logs[LogIndex.pcs_deep],
                    pcsParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.pcs_deep],
                ),
                .fri_leaf = try V2FriLeafAdapter.init(
                    &authority.fri_leaf_definition,
                    authority.fri_leaf_relation,
                    manifest,
                    .fri_merkle_leaf,
                    logs[LogIndex.fri_leaf],
                    friLeafParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.fri_leaf],
                ),
                .fri_node = try V2FriNodeAdapter.init(
                    &authority.fri_node_definition,
                    authority.fri_node_relation,
                    manifest,
                    .fri_merkle_node,
                    logs[LogIndex.fri_node],
                    fri_leaf_witness.ProofKind.segment_leaf.selectors()[0..2].*,
                    relations,
                    generated.claims[LogIndex.fri_node],
                ),
                .fri_anchor = try V2FriAnchorAdapter.init(
                    &authority.fri_anchor_definition,
                    authority.fri_anchor_relation,
                    manifest,
                    .fri_merkle_anchor,
                    logs[LogIndex.fri_anchor],
                    friAnchorParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.fri_anchor],
                ),
                .control = try V2ControlAdapter.init(
                    &authority.control_definition,
                    authority.control_relation,
                    manifest,
                    .fri_verifier_control,
                    logs[LogIndex.fri_control],
                    controlParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.fri_control],
                ),
                .input = try V2InputAdapter.init(
                    &authority.input_definition,
                    authority.input_relation,
                    manifest,
                    .fri_verifier_input,
                    logs[LogIndex.fri_input],
                    inputParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.fri_input],
                ),
                .multiply = try V2MultiplyAdapter.init(
                    &authority.multiply_definition,
                    authority.multiply_relation,
                    manifest,
                    .qm31_mul,
                    logs[LogIndex.multiply],
                    input_witness.ProofKind.segment_leaf.selectors(),
                    relations,
                    generated.claims[LogIndex.multiply],
                ),
                .inverse = try V2InverseAdapter.init(
                    &authority.inverse_definition,
                    authority.inverse_relation,
                    manifest,
                    .qm31_inv,
                    logs[LogIndex.inverse],
                    input_witness.ProofKind.segment_leaf.selectors(),
                    relations,
                    generated.claims[LogIndex.inverse],
                ),
                .linear = try V2LinearAdapter.init(
                    &authority.linear_definition,
                    authority.linear_relation,
                    manifest,
                    .linear_ops,
                    logs[LogIndex.linear],
                    input_witness.ProofKind.segment_leaf.selectors(),
                    relations,
                    generated.claims[LogIndex.linear],
                ),
                .merkle_path = try V2MerklePathAdapter.init(
                    &authority.merkle_path_definition,
                    authority.merkle_path_relation,
                    manifest,
                    .merkle_path,
                    logs[LogIndex.merkle_path],
                    .{},
                    relations,
                    generated.claims[LogIndex.merkle_path],
                ),
                .poseidon2 = try V2Poseidon2Adapter.init(
                    manifest,
                    logs[LogIndex.poseidon2],
                    @intCast(self.poseidon_calls.calls.len),
                    provider_relations,
                    relations,
                    generated.poseidon2_partials,
                ),
            };
        }

        /// Allocation-free post-materialization audit for one arithmetic lane.  The
        /// lowering plan authenticates graph coordinates and evaluation shape, but a
        /// shape-correct evaluation can still be stale or belong to a different
        /// replay of the same graph.  Checking the concrete provider invocations here
        /// keeps that value-custody failure from reaching Tree 1, where it otherwise
        /// appears only as hundreds of unrelated `recursion_wire` residuals.
        pub fn validateMaterializedArithmeticLane(
            reference: lowering.Reference,
            evaluations: lowering.Evaluations,
            proof_kind: lowering.ProofKind,
            invocations: lowering.InvocationBuffers,
            target_circuit_id: u32,
        ) !void {
            try evaluations.validateAgainst(reference);
            const selected_mode: lowering.Mode = switch (proof_kind) {
                .segment_leaf => .segment,
                .binary_node => .binary,
                .empty_leaf => return error.AuthorityMismatch,
            };
            var multiply_cursor: usize = 0;
            var inverse_cursor: usize = 0;
            var linear_cursor: usize = 0;
            var target_count: usize = 0;

            for (reference.lanes, evaluations.lanes) |lane, evaluation| {
                if (lane.active_in != selected_mode) continue;
                const selected = lane.circuit_id == target_circuit_id;
                if (selected) target_count += 1;
                for (lane.graph.nodes, 0..) |node, node_id| switch (node.op) {
                    .input => {},
                    .constant => |words| {
                        if (!evaluation.values[node_id].eql(
                            QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]),
                        )) return error.MaterializedArithmeticConstantMismatch;
                    },
                    .mul => |operation| {
                        if (multiply_cursor >= invocations.multiply.len)
                            return error.MaterializedArithmeticScheduleMismatch;
                        const invocation = invocations.multiply[multiply_cursor];
                        multiply_cursor += 1;
                        const metadata = invocation.circuit orelse
                            return error.MaterializedArithmeticScheduleMismatch;
                        if (!materializedMetadataMatches(
                            metadata,
                            lane.circuit_id,
                            node_id,
                            operation.lhs,
                            operation.rhs,
                        )) return error.MaterializedArithmeticScheduleMismatch;
                        if (!invocation.a.eql(evaluation.values[operation.lhs]) or
                            !invocation.b.eql(evaluation.values[operation.rhs]))
                            return error.MaterializedArithmeticOperandMismatch;
                        const result = invocation.a.mul(invocation.b);
                        if (!result.eql(evaluation.values[node_id])) return reportMaterializedArithmeticResultMismatch(
                            lane.circuit_id,
                            node_id,
                            result,
                            evaluation.values[node_id],
                        );
                    },
                    .inverse => |operand| {
                        if (inverse_cursor >= invocations.inverse.len)
                            return error.MaterializedArithmeticScheduleMismatch;
                        const invocation = invocations.inverse[inverse_cursor];
                        inverse_cursor += 1;
                        const metadata = invocation.circuit orelse
                            return error.MaterializedArithmeticScheduleMismatch;
                        if (metadata.circuit_id.toU32() != lane.circuit_id or
                            metadata.node_id.toU32() != node_id or
                            metadata.lhs_id.toU32() != operand)
                            return error.MaterializedArithmeticScheduleMismatch;
                        if (!invocation.a.eql(evaluation.values[operand]))
                            return error.MaterializedArithmeticOperandMismatch;
                        const result = try invocation.a.inv();
                        if (!result.eql(evaluation.values[node_id])) return reportMaterializedArithmeticResultMismatch(
                            lane.circuit_id,
                            node_id,
                            result,
                            evaluation.values[node_id],
                        );
                    },
                    .add, .sub => |operation| {
                        if (linear_cursor >= invocations.linear.len)
                            return error.MaterializedArithmeticScheduleMismatch;
                        const invocation = invocations.linear[linear_cursor];
                        linear_cursor += 1;
                        const expected_operation: linear_witness.Operation =
                            switch (node.op) {
                                .add => .add,
                                .sub => .sub,
                                else => unreachable,
                            };
                        if (invocation.operation != expected_operation or
                            !materializedMetadataMatches(
                                invocation.circuit,
                                lane.circuit_id,
                                node_id,
                                operation.lhs,
                                operation.rhs,
                            )) return error.MaterializedArithmeticScheduleMismatch;
                        if (!invocation.lhs.eql(evaluation.values[operation.lhs]) or
                            !invocation.rhs.eql(evaluation.values[operation.rhs]))
                            return error.MaterializedArithmeticOperandMismatch;
                        const result = invocation.operation.apply(
                            invocation.lhs,
                            invocation.rhs,
                        );
                        if (!result.eql(evaluation.values[node_id])) return reportMaterializedArithmeticResultMismatch(
                            lane.circuit_id,
                            node_id,
                            result,
                            evaluation.values[node_id],
                        );
                    },
                    .neg => |operand| {
                        if (linear_cursor >= invocations.linear.len)
                            return error.MaterializedArithmeticScheduleMismatch;
                        const invocation = invocations.linear[linear_cursor];
                        linear_cursor += 1;
                        if (invocation.operation != .neg or
                            invocation.circuit.circuit_id.toU32() != lane.circuit_id or
                            invocation.circuit.node_id.toU32() != node_id or
                            invocation.circuit.lhs_id.toU32() != operand or
                            !invocation.circuit.rhs_id.isZero())
                            return error.MaterializedArithmeticScheduleMismatch;
                        if (!invocation.lhs.eql(evaluation.values[operand]))
                            return error.MaterializedArithmeticOperandMismatch;
                        const result = invocation.lhs.neg();
                        if (!result.eql(evaluation.values[node_id])) return reportMaterializedArithmeticResultMismatch(
                            lane.circuit_id,
                            node_id,
                            result,
                            evaluation.values[node_id],
                        );
                    },
                };
                for (lane.graph.outputs) |output| {
                    if (!evaluation.values[output].isZero())
                        return error.MaterializedArithmeticOutputMismatch;
                }
            }
            if (target_count != 1 or
                multiply_cursor != invocations.multiply.len or
                inverse_cursor != invocations.inverse.len or
                linear_cursor != invocations.linear.len)
            {
                return error.MaterializedArithmeticScheduleMismatch;
            }
        }

        pub fn reportMaterializedArithmeticResultMismatch(
            circuit_id: u32,
            node_id: usize,
            replayed: QM31,
            evaluated: QM31,
        ) anyerror {
            if (std.process.hasEnvVarConstant(CLOSURE_DIAGNOSTIC_ENV)) {
                std.debug.print(
                    "materialized arithmetic replay mismatch: circuit={d} node={d} " ++
                        "replayed={any} evaluated={any}\n",
                    .{
                        circuit_id,
                        node_id,
                        replayed.toM31Array(),
                        evaluated.toM31Array(),
                    },
                );
            }
            return error.MaterializedArithmeticResultMismatch;
        }

        /// Opt-in error provenance for the wide concrete cohort.  Keeping the helper
        /// here makes core-owned failures distinguishable from the surrounding
        /// non-core/provider assembly without widening any public error set.
        pub fn nativeV2CoreStageFailure(stage: []const u8, err: anyerror) anyerror {
            if (std.process.hasEnvVarConstant(CLOSURE_DIAGNOSTIC_ENV)) {
                std.debug.print(
                    "native-v2-core stage={s} error={s}\n",
                    .{ stage, @errorName(err) },
                );
            }
            return err;
        }

        pub fn materializedMetadataMatches(
            metadata: anytype,
            circuit_id: u32,
            node_id: usize,
            lhs_id: u32,
            rhs_id: u32,
        ) bool {
            return metadata.circuit_id.toU32() == circuit_id and
                metadata.node_id.toU32() == node_id and
                metadata.lhs_id.toU32() == lhs_id and
                metadata.rhs_id.toU32() == rhs_id;
        }
    };
}
