//! Additive manifest-generic projection of native verifier rows 18--34.
//!
//! The legacy SegmentV2 component family remains unchanged. This sibling
//! instantiates the same typed AIR definitions against a caller-selected
//! versioned universal manifest only after every row-18--34 geometry entry is
//! exactly equal to the native core's authenticated SegmentV2 placement.

pub fn Namespace(comptime context: type) type {
    return struct {
        const adapter = context.d_adapter;
        const composition_control_air = context.d_composition_control_air;
        const composition_control_witness = context.d_composition_control_witness;
        const control_air = context.d_control_air;
        const fri_anchor_air = context.d_fri_anchor_air;
        const fri_leaf_air = context.d_fri_leaf_air;
        const fri_leaf_witness = context.d_fri_leaf_witness;
        const fri_node_air = context.d_fri_node_air;
        const input_air = context.d_input_air;
        const input_witness = context.d_input_witness;
        const inverse_air = context.d_inverse_air;
        const linear_air = context.d_linear_air;
        const merkle_path_air = context.d_merkle_path_air;
        const merkle_root_air = context.d_merkle_root_air;
        const multiply_air = context.d_multiply_air;
        const pcs_air = context.d_pcs_air;
        const query_bits_air = context.d_query_bits_air;
        const query_mapping_air = context.d_query_mapping_air;
        const trace_merkle_air = context.d_trace_merkle_air;
        const vm_input_air = context.d_vm_input_air;
        const shared_provider = context.d_shared_provider;
        const universal = context.d_universal;
        const InputRelation = context.d_InputRelation;
        const VmInputRelation = context.d_VmInputRelation;
        const CompositionControlRelation = context.d_CompositionControlRelation;
        const QueryBitsRelation = context.d_QueryBitsRelation;
        const QueryMappingRelation = context.d_QueryMappingRelation;
        const MerkleRootRelation = context.d_MerkleRootRelation;
        const TraceMerkleRelation = context.d_TraceMerkleRelation;
        const PcsRelation = context.d_PcsRelation;
        const FriLeafRelation = context.d_FriLeafRelation;
        const FriNodeRelation = context.d_FriNodeRelation;
        const FriAnchorRelation = context.d_FriAnchorRelation;
        const ControlRelation = context.d_ControlRelation;
        const MultiplyRelation = context.d_MultiplyRelation;
        const InverseRelation = context.d_InverseRelation;
        const LinearRelation = context.d_LinearRelation;
        const MerklePathRelation = context.d_MerklePathRelation;
        const LogIndex = context.d_LogIndex;
        const NativeSegmentCoreGeneratedV2 = context.d_NativeSegmentCoreGeneratedV2;
        const NativeSegmentCoreV2 = context.d_NativeSegmentCoreV2;
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

        pub fn NativeSegmentCoreComponentsForManifest(
            comptime manifest_contract: type,
        ) type {
            const VmInputAdapter = adapter.ComponentForManifest(
                vm_input_air,
                VmInputRelation,
                manifest_contract,
            );
            const CompositionControlAdapter = adapter.ComponentForManifest(
                composition_control_air,
                CompositionControlRelation,
                manifest_contract,
            );
            const QueryBitsAdapter = adapter.ComponentForManifest(
                query_bits_air,
                QueryBitsRelation,
                manifest_contract,
            );
            const QueryMappingAdapter = adapter.ComponentForManifest(
                query_mapping_air,
                QueryMappingRelation,
                manifest_contract,
            );
            const MerkleRootAdapter = adapter.ComponentForManifest(
                merkle_root_air,
                MerkleRootRelation,
                manifest_contract,
            );
            const TraceMerkleAdapter = adapter.ComponentForManifest(
                trace_merkle_air,
                TraceMerkleRelation,
                manifest_contract,
            );
            const PcsAdapter = adapter.ComponentForManifest(
                pcs_air,
                PcsRelation,
                manifest_contract,
            );
            const FriLeafAdapter = adapter.ComponentForManifest(
                fri_leaf_air,
                FriLeafRelation,
                manifest_contract,
            );
            const FriNodeAdapter = adapter.ComponentForManifest(
                fri_node_air,
                FriNodeRelation,
                manifest_contract,
            );
            const FriAnchorAdapter = adapter.ComponentForManifest(
                fri_anchor_air,
                FriAnchorRelation,
                manifest_contract,
            );
            const ControlAdapter = adapter.ComponentForManifest(
                control_air,
                ControlRelation,
                manifest_contract,
            );
            const InputAdapter = adapter.ComponentForManifest(
                input_air,
                InputRelation,
                manifest_contract,
            );
            const MultiplyAdapter = adapter.ComponentForManifest(
                multiply_air,
                MultiplyRelation,
                manifest_contract,
            );
            const InverseAdapter = adapter.ComponentForManifest(
                inverse_air,
                InverseRelation,
                manifest_contract,
            );
            const LinearAdapter = adapter.ComponentForManifest(
                linear_air,
                LinearRelation,
                manifest_contract,
            );
            const MerklePathAdapter = adapter.ComponentForManifest(
                merkle_path_air,
                MerklePathRelation,
                manifest_contract,
            );
            const Poseidon2Adapter = shared_provider.Poseidon2AdapterForManifest(
                manifest_contract,
            );
            return struct {
                vm_input: VmInputAdapter,
                composition_control: CompositionControlAdapter,
                query_bits: QueryBitsAdapter,
                query_mapping: QueryMappingAdapter,
                merkle_root: MerkleRootAdapter,
                trace_merkle: TraceMerkleAdapter,
                pcs_deep: PcsAdapter,
                fri_leaf: FriLeafAdapter,
                fri_node: FriNodeAdapter,
                fri_anchor: FriAnchorAdapter,
                control: ControlAdapter,
                input: InputAdapter,
                multiply: MultiplyAdapter,
                inverse: InverseAdapter,
                linear: LinearAdapter,
                merkle_path: MerklePathAdapter,
                poseidon2: Poseidon2Adapter,

                pub fn appendToGate(
                    self: *const @This(),
                    manifest: *const manifest_contract.Manifest,
                    gate: *manifest_contract.ProofGate,
                ) !void {
                    try gate.append(manifest, try self.vm_input.binding(manifest));
                    try gate.append(manifest, try self.composition_control.binding(manifest));
                    try gate.append(manifest, try self.query_bits.binding(manifest));
                    try gate.append(manifest, try self.query_mapping.binding(manifest));
                    try gate.append(manifest, try self.merkle_root.binding(manifest));
                    try gate.append(manifest, try self.trace_merkle.binding(manifest));
                    try gate.append(manifest, try self.pcs_deep.binding(manifest));
                    try gate.append(manifest, try self.fri_leaf.binding(manifest));
                    try gate.append(manifest, try self.fri_node.binding(manifest));
                    try gate.append(manifest, try self.fri_anchor.binding(manifest));
                    try gate.append(manifest, try self.control.binding(manifest));
                    try gate.append(manifest, try self.input.binding(manifest));
                    try gate.append(manifest, try self.multiply.binding(manifest));
                    try gate.append(manifest, try self.inverse.binding(manifest));
                    try gate.append(manifest, try self.linear.binding(manifest));
                    try gate.append(manifest, try self.merkle_path.binding(manifest));
                    try gate.append(manifest, try self.poseidon2.binding(manifest));
                }

                pub fn deinit(self: *@This()) void {
                    self.* = undefined;
                }
            };
        }

        pub fn initNativeSegmentCoreComponentsForManifest(
            comptime manifest_contract: type,
            self: *NativeSegmentCoreV2,
            manifest: *const manifest_contract.Manifest,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            generated: *const NativeSegmentCoreGeneratedV2,
        ) !NativeSegmentCoreComponentsForManifest(manifest_contract) {
            try validateManifestProjection(manifest_contract, self, manifest);
            try generated.validateAgainst(self, relations, provider_relations);
            const Components = NativeSegmentCoreComponentsForManifest(
                manifest_contract,
            );
            const authority = &self.authority;
            const logs = authority.log_sizes;
            return Components{
                .vm_input = try @FieldType(Components, "vm_input").init(
                    &authority.vm_air.?.definition,
                    authority.vm_air.?.relation,
                    manifest,
                    .vm_air_composition_input,
                    logs[LogIndex.vm_input],
                    vmInputParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.vm_input],
                ),
                .composition_control = try @FieldType(Components, "composition_control").init(
                    &authority.composition_control_definition,
                    authority.composition_control_relation,
                    manifest,
                    .vm_air_composition_control,
                    logs[LogIndex.composition_control],
                    composition_control_witness.ProofKind.segment_leaf.selectors()[0..2].*,
                    relations,
                    generated.claims[LogIndex.composition_control],
                ),
                .query_bits = try @FieldType(Components, "query_bits").init(
                    &authority.query_bits_definition,
                    authority.query_bits_relation,
                    manifest,
                    .query_bits,
                    logs[LogIndex.query_bits],
                    try queryBitsParameters(authority.query_bits_reference, .segment_leaf),
                    relations,
                    generated.claims[LogIndex.query_bits],
                ),
                .query_mapping = try @FieldType(Components, "query_mapping").init(
                    &authority.query_mapping_definition,
                    authority.query_mapping_relation,
                    manifest,
                    .query_mapping,
                    logs[LogIndex.query_mapping],
                    queryMappingParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.query_mapping],
                ),
                .merkle_root = try @FieldType(Components, "merkle_root").init(
                    &authority.merkle_root_definition,
                    authority.merkle_root_relation,
                    manifest,
                    .merkle_root,
                    logs[LogIndex.merkle_root],
                    merkleRootParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.merkle_root],
                ),
                .trace_merkle = try @FieldType(Components, "trace_merkle").init(
                    &authority.trace_merkle_definition,
                    authority.trace_merkle_relation,
                    manifest,
                    .trace_merkle,
                    logs[LogIndex.trace_merkle],
                    traceMerkleParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.trace_merkle],
                ),
                .pcs_deep = try @FieldType(Components, "pcs_deep").init(
                    &authority.pcs_definition,
                    authority.pcs_relation,
                    manifest,
                    .pcs_deep_input,
                    logs[LogIndex.pcs_deep],
                    pcsParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.pcs_deep],
                ),
                .fri_leaf = try @FieldType(Components, "fri_leaf").init(
                    &authority.fri_leaf_definition,
                    authority.fri_leaf_relation,
                    manifest,
                    .fri_merkle_leaf,
                    logs[LogIndex.fri_leaf],
                    friLeafParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.fri_leaf],
                ),
                .fri_node = try @FieldType(Components, "fri_node").init(
                    &authority.fri_node_definition,
                    authority.fri_node_relation,
                    manifest,
                    .fri_merkle_node,
                    logs[LogIndex.fri_node],
                    fri_leaf_witness.ProofKind.segment_leaf.selectors()[0..2].*,
                    relations,
                    generated.claims[LogIndex.fri_node],
                ),
                .fri_anchor = try @FieldType(Components, "fri_anchor").init(
                    &authority.fri_anchor_definition,
                    authority.fri_anchor_relation,
                    manifest,
                    .fri_merkle_anchor,
                    logs[LogIndex.fri_anchor],
                    friAnchorParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.fri_anchor],
                ),
                .control = try @FieldType(Components, "control").init(
                    &authority.control_definition,
                    authority.control_relation,
                    manifest,
                    .fri_verifier_control,
                    logs[LogIndex.fri_control],
                    controlParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.fri_control],
                ),
                .input = try @FieldType(Components, "input").init(
                    &authority.input_definition,
                    authority.input_relation,
                    manifest,
                    .fri_verifier_input,
                    logs[LogIndex.fri_input],
                    inputParameters(.segment_leaf),
                    relations,
                    generated.claims[LogIndex.fri_input],
                ),
                .multiply = try @FieldType(Components, "multiply").init(
                    &authority.multiply_definition,
                    authority.multiply_relation,
                    manifest,
                    .qm31_mul,
                    logs[LogIndex.multiply],
                    input_witness.ProofKind.segment_leaf.selectors(),
                    relations,
                    generated.claims[LogIndex.multiply],
                ),
                .inverse = try @FieldType(Components, "inverse").init(
                    &authority.inverse_definition,
                    authority.inverse_relation,
                    manifest,
                    .qm31_inv,
                    logs[LogIndex.inverse],
                    input_witness.ProofKind.segment_leaf.selectors(),
                    relations,
                    generated.claims[LogIndex.inverse],
                ),
                .linear = try @FieldType(Components, "linear").init(
                    &authority.linear_definition,
                    authority.linear_relation,
                    manifest,
                    .linear_ops,
                    logs[LogIndex.linear],
                    input_witness.ProofKind.segment_leaf.selectors(),
                    relations,
                    generated.claims[LogIndex.linear],
                ),
                .merkle_path = try @FieldType(Components, "merkle_path").init(
                    &authority.merkle_path_definition,
                    authority.merkle_path_relation,
                    manifest,
                    .merkle_path,
                    logs[LogIndex.merkle_path],
                    .{},
                    relations,
                    generated.claims[LogIndex.merkle_path],
                ),
                .poseidon2 = try @FieldType(Components, "poseidon2").init(
                    manifest,
                    logs[LogIndex.poseidon2],
                    @intCast(self.poseidon_calls.calls.len),
                    provider_relations,
                    relations,
                    generated.poseidon2_partials,
                ),
            };
        }

        fn validateManifestProjection(
            comptime manifest_contract: type,
            self: *NativeSegmentCoreV2,
            manifest: *const manifest_contract.Manifest,
        ) !void {
            try self.validateCoreReady();
            try self.authority.manifest.validate();
            try manifest.validate();
            inline for (18..35) |row| {
                const source = self.authority.manifest.placements[row] orelse
                    return error.V2CoreCohortMismatch;
                const target = manifest.placements[row] orelse
                    return error.V2CoreCohortMismatch;
                if (!@import("std").meta.eql(source.geometry, target.geometry))
                    return error.V2CoreCohortMismatch;
            }
        }
    };
}
