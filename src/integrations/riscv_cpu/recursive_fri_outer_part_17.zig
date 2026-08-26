//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const outer_admission = context.d_outer_admission;
        const vm_input_witness = context.d_vm_input_witness;
        const composition_control_witness = context.d_composition_control_witness;
        const fri_leaf_witness = context.d_fri_leaf_witness;
        const schedule = context.d_schedule;
        const input_witness = context.d_input_witness;
        const manifest_mod = context.d_manifest_mod;
        const catalog = context.d_catalog;
        const shared_provider = context.d_shared_provider;
        const range_bridge = context.d_range_bridge;
        const universal = context.d_universal;
        const universal_binding = context.d_universal_binding;
        const adapter = context.d_adapter;
        const LogIndex = context.d_LogIndex;
        const POSEIDON2_ROSTER_ROW = context.d_POSEIDON2_ROSTER_ROW;
        const POSEIDON2_PARTIAL_COUNT = context.d_POSEIDON2_PARTIAL_COUNT;
        const POSEIDON2_COMPOSITION_CLAIM_INDICES = context.d_POSEIDON2_COMPOSITION_CLAIM_INDICES;
        const POSEIDON2_AUXILIARY_CLAIM_FORMAT_VERSION = context.d_POSEIDON2_AUXILIARY_CLAIM_FORMAT_VERSION;
        const POSEIDON2_AUXILIARY_CLAIM_SEAL_DOMAIN = context.d_POSEIDON2_AUXILIARY_CLAIM_SEAL_DOMAIN;
        const Poseidon2AuxiliaryClaimSealV1 = context.d_Poseidon2AuxiliaryClaimSealV1;
        const InputAdapter = context.d_InputAdapter;
        const VmInputAdapter = context.d_VmInputAdapter;
        const CompositionControlAdapter = context.d_CompositionControlAdapter;
        const QueryBitsAdapter = context.d_QueryBitsAdapter;
        const QueryMappingAdapter = context.d_QueryMappingAdapter;
        const MerkleRootAdapter = context.d_MerkleRootAdapter;
        const TraceMerkleAdapter = context.d_TraceMerkleAdapter;
        const PcsAdapter = context.d_PcsAdapter;
        const FriLeafAdapter = context.d_FriLeafAdapter;
        const FriNodeAdapter = context.d_FriNodeAdapter;
        const FriAnchorAdapter = context.d_FriAnchorAdapter;
        const ControlAdapter = context.d_ControlAdapter;
        const MultiplyAdapter = context.d_MultiplyAdapter;
        const InverseAdapter = context.d_InverseAdapter;
        const LinearAdapter = context.d_LinearAdapter;
        const MerklePathAdapter = context.d_MerklePathAdapter;
        const FORMAT_VERSION = context.d_FORMAT_VERSION;
        const INACTIVE_MIDDLE_FIRST = context.d_INACTIVE_MIDDLE_FIRST;
        const INACTIVE_MIDDLE_COUNT = context.d_INACTIVE_MIDDLE_COUNT;
        const Claims = context.d_Claims;
        const Authority = context.d_Authority;
        const checkedSegmentLeafBundle = context.d_checkedSegmentLeafBundle;
        const qm31Wire = context.d_qm31Wire;
        const validateAuxiliaryQm31 = context.d_validateAuxiliaryQm31;
        const validateAuxiliaryDigest = context.d_validateAuxiliaryDigest;
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
        const digestWords = context.d_digestWords;

        pub fn validatePoseidon2AuxiliaryClaimCustody(
            receipt: *const outer_admission.VerifierReceiptV1,
            verifier_seal: outer_admission.VerifierSealV1,
            relation_replay_identity: recursion.poseidon2_channel.Digest,
            partials: [POSEIDON2_PARTIAL_COUNT]QM31,
            auxiliary_seal: Poseidon2AuxiliaryClaimSealV1,
        ) !void {
            try validatePoseidon2AuxiliaryClaimInputs(
                receipt,
                verifier_seal,
                relation_replay_identity,
                partials,
            );
            try auxiliary_seal.validate();
            const expected = derivePoseidon2AuxiliaryClaimSeal(
                receipt,
                verifier_seal,
                relation_replay_identity,
                partials,
            );
            if (!std.meta.eql(expected, auxiliary_seal))
                return error.AuxiliaryClaimSealMismatch;
        }

        pub fn validatePoseidon2AuxiliaryClaimInputs(
            receipt: *const outer_admission.VerifierReceiptV1,
            verifier_seal: outer_admission.VerifierSealV1,
            relation_replay_identity: recursion.poseidon2_channel.Digest,
            partials: [POSEIDON2_PARTIAL_COUNT]QM31,
        ) !void {
            try receipt.validate();
            try verifier_seal.validate();
            try validateAuxiliaryDigest(relation_replay_identity);
            for (partials) |partial| try validateAuxiliaryQm31(partial);
            const total = partials[0].add(partials[1]);
            if (!std.meta.eql(
                qm31Wire(total),
                receipt.claimed_sums[POSEIDON2_ROSTER_ROW],
            )) return error.AuxiliaryClaimTotalMismatch;
        }

        /// Producer-only derivation used after native core verification. The existing
        /// verifier seal anchors this auxiliary record to the exact capture/receipt;
        /// explicit tail indices prevent swapping the two recurrence coordinates from
        /// becoming an alternate encoding with the same roster-row total.
        pub fn derivePoseidon2AuxiliaryClaimSeal(
            receipt: *const outer_admission.VerifierReceiptV1,
            verifier_seal: outer_admission.VerifierSealV1,
            relation_replay_identity: recursion.poseidon2_channel.Digest,
            partials: [POSEIDON2_PARTIAL_COUNT]QM31,
        ) Poseidon2AuxiliaryClaimSealV1 {
            var channel = recursion.poseidon2_channel.Channel{};
            channel.mixU32s(&.{
                POSEIDON2_AUXILIARY_CLAIM_SEAL_DOMAIN,
                POSEIDON2_AUXILIARY_CLAIM_FORMAT_VERSION,
                FORMAT_VERSION,
                outer_admission.FORMAT_VERSION,
                @intCast(POSEIDON2_ROSTER_ROW),
                POSEIDON2_PARTIAL_COUNT,
            });
            channel.mixU32s(&recursion.poseidon2_channel.parameterId());
            channel.mixU32s(&verifier_seal.profile_id);
            channel.mixU32s(&verifier_seal.capture_id);
            channel.mixU32s(&verifier_seal.receipt_id);
            channel.mixU32s(&verifier_seal.transcript_id);
            channel.mixU32s(&verifier_seal.claimed_sums_id);
            channel.mixU32s(&verifier_seal.verifier_input_boundary);
            channel.mixU32s(&relation_replay_identity);
            channel.mixU32s(&receipt.claimed_sums[POSEIDON2_ROSTER_ROW]);
            inline for (partials, POSEIDON2_COMPOSITION_CLAIM_INDICES) |partial, index| {
                channel.mixU32s(&.{index});
                channel.mixFelts(&.{partial});
            }
            return .{ .digest = channel.digestWords() };
        }

        /// Row 18 is verifier-owned once the prepared graph, input schedule, and
        /// captured values have passed admission. Recompute its complete interaction
        /// claim before consuming proof bytes so a substituted public claim cannot
        /// become statement authority.
        pub fn vmInputClaim(
            authority: *const Authority,
            relations: *const universal.UniversalRelations,
        ) !QM31 {
            const vm_air = authority.vm_air orelse return QM31.zero();
            var result = QM31.zero();
            for (
                vm_air.prepared.preprocessing.rows,
                vm_air.prepared.schedule_values,
            ) |row, value| {
                const pairs = try vm_air.relation.preparedRowPairs(
                    try vm_input_witness.logicalRow(row, value, .segment_leaf),
                    relations,
                );
                for (pairs) |pair| {
                    const first = pair.n1.mul(pair.d1.inv() catch
                        return error.AuthorityMismatch);
                    const second = pair.n2.mul(pair.d2.inv() catch
                        return error.AuthorityMismatch);
                    result = result.add(first).add(second);
                }
            }
            return result;
        }

        /// Row 19 has no witness columns: its claim is a deterministic function of
        /// verifier-owned preprocessing, proof kind, and drawn relation challenges.
        /// Recompute it before proof consumption so a forged public claim rejects
        /// failure-atomically and cannot be mistaken for statement authority.
        pub fn compositionControlClaim(
            authority: *const Authority,
            relations: *const universal.UniversalRelations,
        ) !QM31 {
            var result = QM31.zero();
            for (authority.composition_control_preprocessing.rows) |row| {
                const pairs = try authority.composition_control_relation.preparedRowPairs(
                    composition_control_witness.logicalRow(row, .segment_leaf),
                    relations,
                );
                for (pairs) |pair| {
                    const first = pair.n1.mul(pair.d1.inv() catch
                        return error.AuthorityMismatch);
                    const second = pair.n2.mul(pair.d2.inv() catch
                        return error.AuthorityMismatch);
                    result = result.add(first).add(second);
                }
            }
            return result;
        }

        /// Rows 0--17 are installed as authenticated inactive components while their
        /// proof-derived producers are connected incrementally.  This keeps the live
        /// rows 18--34 inside the final 36-row manifest immediately: offsets, claim
        /// order, and PCS geometry can no longer drift behind a development-only
        /// subset proof.
        pub fn InactivePrefixOwner(comptime entry: catalog.Entry) type {
            const Air = entry.Air;
            const Relation = universal_binding.Binding(Air);
            const TypedAdapter = adapter.Component(Air, Relation);
            return struct {
                definition: Air.Definition,
                component: TypedAdapter,

                fn init(
                    allocator: std.mem.Allocator,
                    manifest: *const manifest_mod.Manifest,
                    relations: *const universal.UniversalRelations,
                ) !@This() {
                    var definition = if (entry.requires_location)
                        try Air.build(allocator, .generated)
                    else
                        try Air.build(allocator);
                    errdefer definition.deinit();
                    const relation_plan = try Relation.authenticate(&definition);
                    const placement = try manifest.placement(entry.row);
                    const parameters = [_]M31{M31.zero()} **
                        TypedAdapter.PARAMETER_COLUMN_COUNT;
                    const component = try TypedAdapter.init(
                        &definition,
                        relation_plan,
                        manifest,
                        entry.row,
                        placement.geometry.log_size,
                        parameters,
                        relations,
                        QM31.zero(),
                    );
                    return .{ .definition = definition, .component = component };
                }

                fn deinit(self: *@This()) void {
                    self.definition.deinit();
                    self.* = undefined;
                }
            };
        }

        pub fn PrefixOwnerTuple() type {
            var types: [INACTIVE_MIDDLE_COUNT]type = undefined;
            inline for (0..INACTIVE_MIDDLE_COUNT) |index|
                types[index] = InactivePrefixOwner(
                    catalog.LOGICAL_ROWS[INACTIVE_MIDDLE_FIRST + index],
                );
            return std.meta.Tuple(&types);
        }

        pub const InactivePrefix = struct {
            owners: PrefixOwnerTuple(),
            initialized: usize,

            fn init(
                allocator: std.mem.Allocator,
                manifest: *const manifest_mod.Manifest,
                relations: *const universal.UniversalRelations,
            ) !InactivePrefix {
                var result: InactivePrefix = .{
                    .owners = undefined,
                    .initialized = 0,
                };
                errdefer result.deinit();
                inline for (0..INACTIVE_MIDDLE_COUNT) |index| {
                    result.owners[index] = try InactivePrefixOwner(
                        catalog.LOGICAL_ROWS[INACTIVE_MIDDLE_FIRST + index],
                    ).init(allocator, manifest, relations);
                    result.initialized += 1;
                }
                return result;
            }

            fn deinit(self: *InactivePrefix) void {
                inline for (0..INACTIVE_MIDDLE_COUNT) |index| {
                    if (index < self.initialized) self.owners[index].deinit();
                }
                self.* = undefined;
            }

            fn append(
                self: *InactivePrefix,
                gate: *manifest_mod.ProofGate,
                manifest: *const manifest_mod.Manifest,
            ) !void {
                inline for (0..INACTIVE_MIDDLE_COUNT) |index|
                    try gate.append(
                        manifest,
                        try self.owners[index].component.binding(manifest),
                    );
            }
        };

        pub const InactiveRange = struct {
            definition: range_bridge.Definition,
            executor: range_bridge.Executor,
            component: shared_provider.RangeCheck8x8Adapter,

            fn init(
                allocator: std.mem.Allocator,
                manifest: *const manifest_mod.Manifest,
                provider_relations: *const shared_provider.SharedProviderRelations,
                relations: *const universal.UniversalRelations,
            ) !InactiveRange {
                var definition = try range_bridge.build(allocator);
                errdefer definition.deinit();
                const binding_value = try range_bridge.Binding.canonical(&definition);
                const executor = try range_bridge.Executor.init(
                    &definition,
                    &binding_value,
                );
                return .{
                    .definition = definition,
                    .executor = executor,
                    .component = try shared_provider.RangeCheck8x8Adapter.init(
                        &definition,
                        &executor,
                        manifest,
                        provider_relations,
                        relations,
                        QM31.zero(),
                    ),
                };
            }

            fn deinit(self: *InactiveRange) void {
                self.definition.deinit();
                self.* = undefined;
            }
        };

        pub const Components = struct {
            segment_leaf: ?recursion.segment_leaf_outer_bundle.Components,
            vm_input: ?VmInputAdapter,
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
            poseidon2: shared_provider.Poseidon2Adapter,

            fn init(
                authority: *const Authority,
                relations: *const universal.UniversalRelations,
                provider_relations: *const shared_provider.SharedProviderRelations,
                claims: Claims,
            ) !Components {
                return .{
                    .segment_leaf = if (authority.segment_transcript_inputs != null) blk: {
                        const bundle = try checkedSegmentLeafBundle(authority);
                        break :blk try bundle.initComponents(
                            &authority.manifest,
                            relations,
                            provider_relations,
                            claims.segment_leaf.?,
                        );
                    } else null,
                    .vm_input = if (authority.vm_air) |*vm_air| try VmInputAdapter.init(
                        &vm_air.definition,
                        vm_air.relation,
                        &authority.manifest,
                        .vm_air_composition_input,
                        authority.log_sizes[LogIndex.vm_input],
                        vmInputParameters(.segment_leaf),
                        relations,
                        claims.vm_input,
                    ) else null,
                    .composition_control = try CompositionControlAdapter.init(
                        &authority.composition_control_definition,
                        authority.composition_control_relation,
                        &authority.manifest,
                        .vm_air_composition_control,
                        authority.log_sizes[LogIndex.composition_control],
                        composition_control_witness.ProofKind.segment_leaf.selectors()[0..2].*,
                        relations,
                        claims.composition_control,
                    ),
                    .query_bits = try QueryBitsAdapter.init(
                        &authority.query_bits_definition,
                        authority.query_bits_relation,
                        &authority.manifest,
                        .query_bits,
                        authority.log_sizes[LogIndex.query_bits],
                        try queryBitsParameters(
                            authority.query_bits_reference,
                            .segment_leaf,
                        ),
                        relations,
                        claims.query_bits,
                    ),
                    .query_mapping = try QueryMappingAdapter.init(
                        &authority.query_mapping_definition,
                        authority.query_mapping_relation,
                        &authority.manifest,
                        .query_mapping,
                        authority.log_sizes[LogIndex.query_mapping],
                        queryMappingParameters(.segment_leaf),
                        relations,
                        claims.query_mapping,
                    ),
                    .merkle_root = try MerkleRootAdapter.init(
                        &authority.merkle_root_definition,
                        authority.merkle_root_relation,
                        &authority.manifest,
                        .merkle_root,
                        authority.log_sizes[LogIndex.merkle_root],
                        merkleRootParameters(.segment_leaf),
                        relations,
                        claims.merkle_root,
                    ),
                    .trace_merkle = try TraceMerkleAdapter.init(
                        &authority.trace_merkle_definition,
                        authority.trace_merkle_relation,
                        &authority.manifest,
                        .trace_merkle,
                        authority.log_sizes[LogIndex.trace_merkle],
                        traceMerkleParameters(.segment_leaf),
                        relations,
                        claims.trace_merkle,
                    ),
                    .pcs_deep = try PcsAdapter.init(
                        &authority.pcs_definition,
                        authority.pcs_relation,
                        &authority.manifest,
                        .pcs_deep_input,
                        authority.log_sizes[LogIndex.pcs_deep],
                        pcsParameters(.segment_leaf),
                        relations,
                        claims.pcs_deep,
                    ),
                    .fri_leaf = try FriLeafAdapter.init(
                        &authority.fri_leaf_definition,
                        authority.fri_leaf_relation,
                        &authority.manifest,
                        .fri_merkle_leaf,
                        authority.log_sizes[LogIndex.fri_leaf],
                        friLeafParameters(.segment_leaf),
                        relations,
                        claims.fri_leaf,
                    ),
                    .fri_node = try FriNodeAdapter.init(
                        &authority.fri_node_definition,
                        authority.fri_node_relation,
                        &authority.manifest,
                        .fri_merkle_node,
                        authority.log_sizes[LogIndex.fri_node],
                        fri_leaf_witness.ProofKind.segment_leaf.selectors()[0..2].*,
                        relations,
                        claims.fri_node,
                    ),
                    .fri_anchor = try FriAnchorAdapter.init(
                        &authority.fri_anchor_definition,
                        authority.fri_anchor_relation,
                        &authority.manifest,
                        .fri_merkle_anchor,
                        authority.log_sizes[LogIndex.fri_anchor],
                        friAnchorParameters(.segment_leaf),
                        relations,
                        claims.fri_anchor,
                    ),
                    .control = try ControlAdapter.init(
                        &authority.control_definition,
                        authority.control_relation,
                        &authority.manifest,
                        .fri_verifier_control,
                        authority.log_sizes[LogIndex.fri_control],
                        controlParameters(.segment_leaf),
                        relations,
                        claims.control,
                    ),
                    .input = try InputAdapter.init(
                        &authority.input_definition,
                        authority.input_relation,
                        &authority.manifest,
                        .fri_verifier_input,
                        authority.log_sizes[LogIndex.fri_input],
                        inputParameters(.segment_leaf),
                        relations,
                        claims.input,
                    ),
                    .multiply = try MultiplyAdapter.init(
                        &authority.multiply_definition,
                        authority.multiply_relation,
                        &authority.manifest,
                        .qm31_mul,
                        authority.log_sizes[LogIndex.multiply],
                        input_witness.ProofKind.segment_leaf.selectors(),
                        relations,
                        claims.multiply,
                    ),
                    .inverse = try InverseAdapter.init(
                        &authority.inverse_definition,
                        authority.inverse_relation,
                        &authority.manifest,
                        .qm31_inv,
                        authority.log_sizes[LogIndex.inverse],
                        input_witness.ProofKind.segment_leaf.selectors(),
                        relations,
                        claims.inverse,
                    ),
                    .linear = try LinearAdapter.init(
                        &authority.linear_definition,
                        authority.linear_relation,
                        &authority.manifest,
                        .linear_ops,
                        authority.log_sizes[LogIndex.linear],
                        input_witness.ProofKind.segment_leaf.selectors(),
                        relations,
                        claims.linear,
                    ),
                    .merkle_path = try MerklePathAdapter.init(
                        &authority.merkle_path_definition,
                        authority.merkle_path_relation,
                        &authority.manifest,
                        .merkle_path,
                        authority.log_sizes[LogIndex.merkle_path],
                        .{},
                        relations,
                        claims.merkle_path,
                    ),
                    .poseidon2 = try shared_provider.Poseidon2Adapter.init(
                        &authority.manifest,
                        authority.log_sizes[LogIndex.poseidon2],
                        authority.poseidon2_row_count,
                        provider_relations,
                        relations,
                        claims.poseidon2,
                    ),
                };
            }

            fn deinit(self: *Components) void {
                self.* = undefined;
            }

            fn append(
                self: *Components,
                gate: *manifest_mod.ProofGate,
                manifest: *const manifest_mod.Manifest,
            ) !void {
                if (self.segment_leaf) |*segment_leaf|
                    try segment_leaf.appendPrefixToGate(manifest, gate);
                if (self.vm_input) |*vm_input| {
                    try gate.append(manifest, try vm_input.binding(manifest));
                }
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
                if (self.segment_leaf) |*segment_leaf|
                    try segment_leaf.appendSharedProviderToGate(manifest, gate);
            }
        };
    };
}
