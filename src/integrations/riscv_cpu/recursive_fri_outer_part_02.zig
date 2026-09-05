//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const lowering = context.d_lowering;
        const air = context.d_air;
        const schedule = context.d_schedule;
        const manifest_v2 = context.d_manifest_v2;
        const shared_provider = context.d_shared_provider;
        const universal = context.d_universal;
        const poseidon2_air = context.d_poseidon2_air;
        const shared_schedule_v2 = context.d_shared_schedule_v2;
        const segment_transcript_source_v2 = context.d_segment_transcript_source_v2;
        const public_native_sum = context.d_public_native_sum;
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
        const STAGE_TELEMETRY_ENV = context.d_STAGE_TELEMETRY_ENV;
        const NATIVE_V2_CORE_FORMAT_VERSION = context.d_NATIVE_V2_CORE_FORMAT_VERSION;
        const NATIVE_V2_CORE_FIRST_ROW = context.d_NATIVE_V2_CORE_FIRST_ROW;
        const NATIVE_V2_CORE_ROW_COUNT = context.d_NATIVE_V2_CORE_ROW_COUNT;
        const NativeSegmentCoreV2 = context.d_NativeSegmentCoreV2;
        const VerifierPlans = context.d_VerifierPlans;
        const RelationDomain = context.d_RelationDomain;
        const DomainAudit = context.d_DomainAudit;
        const validateAuxiliaryQm31 = context.d_validateAuxiliaryQm31;
        const validateCoreDomainAudit = context.d_validateCoreDomainAudit;
        const nativeCoreGeneratedIdentity = context.d_nativeCoreGeneratedIdentity;

        pub const NATIVE_V2_CORE_GENERATED_ID_DOMAIN =
            "stwo-zig/typed-air/native-segment-core-v2/generated/v1\x00";
        pub const NATIVE_V2_CORE_AUTHORITY_TRANSCRIPT_DOMAIN: u32 = 0x4e43_5632; // "NCV2"

        /// Borrowed native-leaf inputs. No binary child or synthetic second segment is
        /// accepted here: the active verifier lane is always `segment_leaf`; the left
        /// and right circuit lanes are canonical inactive evaluations rebuilt from the
        /// captured circuit itself.
        pub const NativeSegmentCoreAuthorityInputsV2 = struct {
            captured: *const recursion.captured_fri.Owned,
            vm_air: *const recursion.vm_air_composition_circuit.Prepared,
            verifier_plans: VerifierPlans,
            transcript_prepared: *const segment_transcript_source_v2.PreparedV2,
            transcript_program: *const recursion.transcript_program_v2.Program,
            transcript_execution: *const recursion.transcript_program_v2.Execution,
            transcript_plan: *const schedule.Plan,
            public_native_sum_source: *const public_native_sum.SourceV2,
            public_native_sum_evaluation: *const public_native_sum.OwnedEvaluationV2,
            boundary_layout: *const shared_schedule_v2.SharedPoseidonCallLayoutV2,
            boundary_calls: []const shared_schedule_v2.Call,

            pub fn validate(self: NativeSegmentCoreAuthorityInputsV2) !void {
                try self.captured.evaluation.validateAgainst(&self.captured.circuit);
                try self.captured.pcs_evaluation.validateAgainst(
                    &self.captured.pcs_circuit,
                );
                try self.vm_air.validate();
                try self.verifier_plans.vm.validate();
                try self.verifier_plans.recursion.validate();
                try self.public_native_sum_evaluation.validateAgainst(
                    self.public_native_sum_source,
                );
                const public_lane = self.public_native_sum_source.loweringLane();
                if (self.verifier_plans.vm.schema != .vm or
                    self.verifier_plans.recursion.schema != .recursion or
                    self.transcript_plan != self.verifier_plans.vm or
                    public_lane.circuit_id != public_native_sum.CIRCUIT_ID or
                    public_lane.active_in != .segment or
                    !std.mem.eql(
                        u8,
                        &public_lane.circuit_identity,
                        &self.public_native_sum_source.authority_digest,
                    ) or !std.mem.eql(
                    u8,
                    &self.public_native_sum_evaluation.source_authority_digest,
                    &self.public_native_sum_source.authority_digest,
                )) {
                    return error.V2CoreCohortMismatch;
                }
                self.boundary_layout.validate(self.boundary_calls) catch
                    return error.V2CoreCohortMismatch;
                if (self.boundary_layout.call_set_complete or
                    self.boundary_layout.verifier_core_range_populated or
                    self.boundary_layout.verifier_core.count() catch 1 != 0 or
                    self.boundary_layout.boundary_prefix_call_count !=
                        self.boundary_calls.len)
                {
                    return error.V2CoreCohortMismatch;
                }
            }
        };

        /// Borrowed inputs for a versioned native verifier whose transcript
        /// and public-sum arithmetic have already been authenticated by their
        /// own typed owners.  Unlike `NativeSegmentCoreAuthorityInputsV2`,
        /// this boundary does not nominally reinterpret a newer public source
        /// as the frozen SegmentV2 source.  It accepts the common lowering
        /// capability only after checking the complete graph/evaluation pair,
        /// and it accepts full q193 query words only after the core checks
        /// their low-bit projection against the native PCS capture.
        pub const NativeSegmentCoreAuthorityInputsV4 = struct {
            captured: *const recursion.captured_fri.Owned,
            vm_air: *const recursion.vm_air_composition_circuit.Prepared,
            verifier_plans: VerifierPlans,
            public_native_sum_lane: lowering.Lane,
            public_native_sum_evaluation: lowering.Evaluation,
            public_native_sum_evaluation_id: [32]u8,
            full_query_words: []const M31,
            boundary_layout: *const shared_schedule_v2.SharedPoseidonCallLayoutV2,
            boundary_calls: []const shared_schedule_v2.Call,

            pub fn validate(self: NativeSegmentCoreAuthorityInputsV4) !void {
                try self.captured.evaluation.validateAgainst(&self.captured.circuit);
                try self.captured.pcs_evaluation.validateAgainst(
                    &self.captured.pcs_circuit,
                );
                try self.vm_air.validate();
                try self.verifier_plans.vm.validate();
                try self.verifier_plans.recursion.validate();
                try self.public_native_sum_lane.graph.validate();
                if (self.verifier_plans.vm.schema != .vm or
                    self.verifier_plans.recursion.schema != .recursion or
                    self.public_native_sum_lane.circuit_id !=
                        public_native_sum.CIRCUIT_ID or
                    self.public_native_sum_lane.active_in != .segment or
                    self.public_native_sum_evaluation.values.len !=
                        self.public_native_sum_lane.graph.nodes.len or
                    !std.mem.eql(
                        u8,
                        &self.public_native_sum_evaluation.circuit_identity,
                        &self.public_native_sum_lane.circuit_identity,
                    ) or std.mem.allEqual(
                    u8,
                    &self.public_native_sum_evaluation_id,
                    0,
                )) return error.V2CoreCohortMismatch;
                for (self.public_native_sum_lane.graph.outputs) |output| {
                    if (output >= self.public_native_sum_evaluation.values.len or
                        !self.public_native_sum_evaluation.values[output].isZero())
                    {
                        return error.V2CoreCohortMismatch;
                    }
                }
                self.boundary_layout.validate(self.boundary_calls) catch
                    return error.V2CoreCohortMismatch;
                if (self.boundary_layout.call_set_complete or
                    self.boundary_layout.verifier_core_range_populated or
                    self.boundary_layout.verifier_core.count() catch 1 != 0 or
                    self.boundary_layout.boundary_prefix_call_count !=
                        self.boundary_calls.len)
                {
                    return error.V2CoreCohortMismatch;
                }
            }
        };

        pub const NativeSegmentCoreGeneratedV2 = struct {
            format_version: u16 = NATIVE_V2_CORE_FORMAT_VERSION,
            padding: [6]u8 = [_]u8{0} ** 6,
            authority_id: [32]u8,
            schedule_id: [32]u8,
            relation_registry_id: [32]u8,
            provider_relation_id: [32]u8,
            claims: [NATIVE_V2_CORE_ROW_COUNT]QM31,
            poseidon2_partials: [poseidon2_air.N_SUMS]QM31,
            audits: [NATIVE_V2_CORE_ROW_COUNT]DomainAudit,
            identity: [32]u8,

            pub fn validateAgainst(
                self: *const NativeSegmentCoreGeneratedV2,
                owner: *const NativeSegmentCoreV2,
                relations: *const universal.UniversalRelations,
                provider_relations: *const shared_provider.SharedProviderRelations,
            ) !void {
                try owner.validateComplete();
                try relations.validate();
                try provider_relations.validateAgainst(relations);
                if (self.format_version != NATIVE_V2_CORE_FORMAT_VERSION or
                    !std.mem.allEqual(u8, &self.padding, 0) or
                    !std.mem.eql(u8, &self.authority_id, &owner.authority_id) or
                    !std.mem.eql(
                        u8,
                        &self.schedule_id,
                        &owner.complete_layout.identity,
                    ) or !std.mem.eql(
                    u8,
                    &self.relation_registry_id,
                    &relations.registry_order_digest,
                ) or !std.mem.eql(
                    u8,
                    &self.provider_relation_id,
                    &(try provider_relations.identityDigest()),
                )) {
                    if (std.process.hasEnvVarConstant(STAGE_TELEMETRY_ENV))
                        std.debug.print("  native-v2-core mismatch=generated-envelope\n", .{});
                    return error.V2CoreCohortMismatch;
                }
                for (self.claims, self.audits, 0..) |claim, audit, index| {
                    try validateAuxiliaryQm31(claim);
                    validateCoreDomainAudit(audit, claim) catch |err| {
                        if (std.process.hasEnvVarConstant(STAGE_TELEMETRY_ENV))
                            std.debug.print(
                                "  native-v2-core mismatch=domain-audit row={d}\n",
                                .{NATIVE_V2_CORE_FIRST_ROW + index},
                            );
                        return err;
                    };
                }
                const poseidon_total = self.poseidon2_partials[0].add(
                    self.poseidon2_partials[1],
                );
                if (!poseidon_total.eql(self.claims[NATIVE_V2_CORE_ROW_COUNT - 1]) or
                    !self.audits[NATIVE_V2_CORE_ROW_COUNT - 1]
                        .values[@intFromEnum(RelationDomain.poseidon2)]
                        .eql(self.poseidon2_partials[0]) or
                    !self.audits[NATIVE_V2_CORE_ROW_COUNT - 1]
                        .values[@intFromEnum(RelationDomain.poseidon2_io)]
                        .eql(self.poseidon2_partials[1]) or
                    !std.mem.eql(u8, &self.identity, &nativeCoreGeneratedIdentity(self)))
                {
                    if (std.process.hasEnvVarConstant(STAGE_TELEMETRY_ENV))
                        std.debug.print("  native-v2-core mismatch=provider-or-identity\n", .{});
                    return error.V2CoreCohortMismatch;
                }
            }

            pub fn bindClaimsInto(
                self: *const NativeSegmentCoreGeneratedV2,
                vector: *manifest_v2.ClaimVector,
            ) !void {
                for (self.claims, NATIVE_V2_CORE_FIRST_ROW..) |claim, row|
                    try vector.bind(@enumFromInt(row), claim);
            }
        };

        pub const NativeSegmentCoreComponentsV2 = struct {
            vm_input: V2VmInputAdapter,
            composition_control: V2CompositionControlAdapter,
            query_bits: V2QueryBitsAdapter,
            query_mapping: V2QueryMappingAdapter,
            merkle_root: V2MerkleRootAdapter,
            trace_merkle: V2TraceMerkleAdapter,
            pcs_deep: V2PcsAdapter,
            fri_leaf: V2FriLeafAdapter,
            fri_node: V2FriNodeAdapter,
            fri_anchor: V2FriAnchorAdapter,
            control: V2ControlAdapter,
            input: V2InputAdapter,
            multiply: V2MultiplyAdapter,
            inverse: V2InverseAdapter,
            linear: V2LinearAdapter,
            merkle_path: V2MerklePathAdapter,
            poseidon2: V2Poseidon2Adapter,

            pub fn appendToGate(
                self: *const NativeSegmentCoreComponentsV2,
                manifest: *const manifest_v2.Manifest,
                gate: *manifest_v2.ProofGate,
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

            pub fn deinit(self: *NativeSegmentCoreComponentsV2) void {
                self.* = undefined;
            }
        };

        // Concrete owner for one native SegmentV2 leaf's universal verifier core.
        // Tree 0 and rows 18--33 of Tree 1 are prepared once in the cold constructor.
        // That preparation derives the core Poseidon suffix before row 34 is
        // evaluated, making the single complete provider schedule observable and
        // independently authenticatable at the intended seam.
    };
}
