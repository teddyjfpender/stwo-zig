//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const air = context.d_air;
        const composition_control_witness = context.d_composition_control_witness;
        const query_bits_witness = context.d_query_bits_witness;
        const query_mapping_witness = context.d_query_mapping_witness;
        const merkle_root_witness = context.d_merkle_root_witness;
        const pcs_witness = context.d_pcs_witness;
        const input_witness = context.d_input_witness;
        const lowering = context.d_lowering;
        const multiply_witness = context.d_multiply_witness;
        const inverse_witness = context.d_inverse_witness;
        const linear_witness = context.d_linear_witness;
        const merkle_path_witness = context.d_merkle_path_witness;
        const shared_provider = context.d_shared_provider;
        const universal = context.d_universal;
        const poseidon2_air = context.d_poseidon2_air;
        const MAX_ARITHMETIC_EVALUATION_LANES = context.d_MAX_ARITHMETIC_EVALUATION_LANES;
        const InputRelation = context.d_InputRelation;
        const CompositionControlRelation = context.d_CompositionControlRelation;
        const QueryBitsRelation = context.d_QueryBitsRelation;
        const QueryMappingRelation = context.d_QueryMappingRelation;
        const MerkleRootRelation = context.d_MerkleRootRelation;
        const PcsRelation = context.d_PcsRelation;
        const MultiplyRelation = context.d_MultiplyRelation;
        const InverseRelation = context.d_InverseRelation;
        const LinearRelation = context.d_LinearRelation;
        const MerklePathRelation = context.d_MerklePathRelation;
        const CLOSURE_DIAGNOSTIC_ENV = context.d_CLOSURE_DIAGNOSTIC_ENV;
        const NATIVE_V2_CORE_FIRST_ROW = context.d_NATIVE_V2_CORE_FIRST_ROW;
        const NATIVE_V2_CORE_LAST_ROW = context.d_NATIVE_V2_CORE_LAST_ROW;
        const NATIVE_V2_CORE_ROW_COUNT = context.d_NATIVE_V2_CORE_ROW_COUNT;
        const NATIVE_V2_CORE_HOT_TREE_HEAP_ALLOCATIONS = context.d_NATIVE_V2_CORE_HOT_TREE_HEAP_ALLOCATIONS;
        const NATIVE_V2_CORE_PROVIDER_INSTANCE_COUNT = context.d_NATIVE_V2_CORE_PROVIDER_INSTANCE_COUNT;
        const NATIVE_V2_CORE_RETAINS_SELF_POINTERS = context.d_NATIVE_V2_CORE_RETAINS_SELF_POINTERS;
        const NativeSegmentCoreAuthorityInputsV2 = context.d_NativeSegmentCoreAuthorityInputsV2;
        const NativeSegmentCoreGeneratedV2 = context.d_NativeSegmentCoreGeneratedV2;
        const NativeSegmentCoreComponentsV2 = context.d_NativeSegmentCoreComponentsV2;
        const NativeSegmentCoreV2 = context.d_NativeSegmentCoreV2;
        const testSingleArithmeticLaneTupleClosure = context.d_testSingleArithmeticLaneTupleClosure;
        const validateQueryWordProjection = context.d_validateQueryWordProjection;
        const TupleLedger = context.d_TupleLedger;
        const relationDomainBit = context.d_relationDomainBit;
        const PoseidonCallBuffers = context.d_PoseidonCallBuffers;
        const appendWireBoundaryTuples = context.d_appendWireBoundaryTuples;
        const tupleGroupEnd = context.d_tupleGroupEnd;

        pub fn appendNativeSegmentCoreTupleContributions(
            owner: *const NativeSegmentCoreV2,
            allocator: std.mem.Allocator,
            ledger: *TupleLedger,
            domain_mask: u64,
        ) !void {
            const authority = &owner.authority;
            const vm_air = authority.vm_air orelse return error.AuthorityMismatch;
            const evaluations = owner.evaluations();
            const pcs_inputs = owner.pcsInputs();
            const query_witness = owner.prepared_query.value;

            try appendNativeCoreTupleRows(
                &vm_air.relation,
                ledger,
                .vm_air_composition_input,
                owner.prepared_relation_rows.vm_input,
                domain_mask,
            );
            {
                const rows = try allocator.alloc(
                    CompositionControlRelation.Row,
                    authority.composition_control_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (
                    authority.composition_control_preprocessing.rows,
                    rows,
                ) |source, *destination| destination.* =
                    composition_control_witness.logicalRow(source, .segment_leaf);
                try appendNativeCoreTupleRows(
                    &authority.composition_control_relation,
                    ledger,
                    .vm_air_composition_control,
                    rows,
                    domain_mask,
                );
            }
            {
                const parameters = try query_bits_witness.parameterValues(
                    authority.query_bits_reference,
                    query_witness.proofKind(),
                );
                const rows = try allocator.alloc(
                    QueryBitsRelation.Row,
                    authority.query_bits_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (
                    authority.query_bits_preprocessing.rows,
                    rows,
                ) |source, *destination| destination.* =
                    try query_bits_witness.logicalRow(
                        source,
                        query_witness,
                        parameters,
                    );
                try appendNativeCoreTupleRows(
                    &authority.query_bits_relation,
                    ledger,
                    .query_bits,
                    rows,
                    domain_mask,
                );
            }
            {
                const rows = try allocator.alloc(
                    QueryMappingRelation.Row,
                    authority.query_mapping_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (
                    authority.query_mapping_preprocessing.rows,
                    rows,
                ) |source, *destination| destination.* =
                    try query_mapping_witness.logicalRow(source, query_witness);
                try appendNativeCoreTupleRows(
                    &authority.query_mapping_relation,
                    ledger,
                    .query_mapping,
                    rows,
                    domain_mask,
                );
            }
            {
                const rows = try allocator.alloc(
                    MerkleRootRelation.Row,
                    authority.merkle_root_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                const root_witness = owner.captured.merkleRootWitness();
                for (
                    authority.merkle_root_preprocessing.rows,
                    rows,
                ) |source, *destination| destination.* =
                    try merkle_root_witness.logicalRow(source, root_witness);
                try appendNativeCoreTupleRows(
                    &authority.merkle_root_relation,
                    ledger,
                    .merkle_root,
                    rows,
                    domain_mask,
                );
            }
            try appendNativeCoreTupleRows(
                &authority.trace_merkle_relation,
                ledger,
                .trace_merkle,
                owner.prepared_relation_rows.trace_merkle,
                domain_mask,
            );
            {
                const rows = try allocator.alloc(
                    PcsRelation.Row,
                    authority.pcs_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (authority.pcs_preprocessing.rows, rows) |source, *destination| {
                    const value = pcs_inputs.lanes[source.lane]
                        .input_values[source.binding];
                    destination.* = pcs_witness.logicalInputs(
                        (pcs_witness.MainRow{
                            .enabler = M31.one(),
                            .value = value,
                        }).values(),
                        source.values(),
                        .segment_leaf,
                    );
                }
                try appendNativeCoreTupleRows(
                    &authority.pcs_relation,
                    ledger,
                    .pcs_deep_input,
                    rows,
                    domain_mask,
                );
            }
            try appendNativeCoreTupleRows(
                &authority.fri_leaf_relation,
                ledger,
                .fri_merkle_leaf,
                owner.prepared_relation_rows.fri_leaf,
                domain_mask,
            );
            try appendNativeCoreTupleRows(
                &authority.fri_node_relation,
                ledger,
                .fri_merkle_node,
                owner.prepared_relation_rows.fri_node,
                domain_mask,
            );
            try appendNativeCoreTupleRows(
                &authority.fri_anchor_relation,
                ledger,
                .fri_merkle_anchor,
                owner.prepared_relation_rows.fri_anchor,
                domain_mask,
            );
            try appendNativeCoreTupleRows(
                &authority.control_relation,
                ledger,
                .fri_verifier_control,
                owner.prepared_relation_rows.control,
                domain_mask,
            );
            {
                const rows = try allocator.alloc(
                    InputRelation.Row,
                    authority.input_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (authority.input_preprocessing.rows, rows) |source, *destination| {
                    const value = evaluations.at(source.lane).values[source.node_id]
                        .tryIntoM31() catch return error.AuthorityMismatch;
                    destination.* = input_witness.logicalInputs(
                        (input_witness.MainRow{
                            .enabler = M31.one(),
                            .value = value,
                        }).values(),
                        source.values(),
                        .segment_leaf,
                    );
                }
                try appendNativeCoreTupleRows(
                    &authority.input_relation,
                    ledger,
                    .fri_verifier_input,
                    rows,
                    domain_mask,
                );
            }
            {
                const rows = try allocator.alloc(
                    MultiplyRelation.Row,
                    owner.invocations.multiply.len,
                );
                defer allocator.free(rows);
                for (owner.invocations.multiply, rows, 0..) |
                    invocation,
                    *destination,
                    index,
                | destination.* = multiply_witness.logicalInputs(
                    multiply_witness.mainRow(invocation),
                    multiply_witness.preprocessedRow(
                        authority.lowering_plan.multiply_rows[index],
                    ),
                    .segment_leaf,
                );
                try appendNativeCoreTupleRows(
                    &authority.multiply_relation,
                    ledger,
                    .qm31_mul,
                    rows,
                    domain_mask,
                );
            }
            {
                const rows = try allocator.alloc(
                    InverseRelation.Row,
                    owner.invocations.inverse.len,
                );
                defer allocator.free(rows);
                for (owner.invocations.inverse, rows, 0..) |
                    invocation,
                    *destination,
                    index,
                | destination.* = inverse_witness.logicalInputs(
                    try inverse_witness.mainRow(invocation),
                    inverse_witness.preprocessedRow(
                        authority.lowering_plan.inverse_rows[index],
                    ),
                    .segment_leaf,
                );
                try appendNativeCoreTupleRows(
                    &authority.inverse_relation,
                    ledger,
                    .qm31_inv,
                    rows,
                    domain_mask,
                );
            }
            {
                const rows = try allocator.alloc(
                    LinearRelation.Row,
                    owner.invocations.linear.len,
                );
                defer allocator.free(rows);
                for (owner.invocations.linear, rows, 0..) |
                    invocation,
                    *destination,
                    index,
                | destination.* = linear_witness.logicalInputs(
                    try linear_witness.mainRow(invocation),
                    linear_witness.preprocessedRow(
                        authority.lowering_plan.linear_rows[index],
                    ),
                    .segment_leaf,
                );
                try appendNativeCoreTupleRows(
                    &authority.linear_relation,
                    ledger,
                    .linear_ops,
                    rows,
                    domain_mask,
                );
            }
            if (!owner.merkle_paths.ready) return error.AuthorityMismatch;
            {
                const rows = try allocator.alloc(
                    MerklePathRelation.Row,
                    owner.merkle_paths.invocations.len,
                );
                defer allocator.free(rows);
                for (owner.merkle_paths.invocations, rows) |invocation, *destination|
                    destination.* = try merkle_path_witness.logicalRow(invocation);
                try appendNativeCoreTupleRows(
                    &authority.merkle_path_relation,
                    ledger,
                    .merkle_path,
                    rows,
                    domain_mask,
                );
            }
            try appendNativePoseidonProviderTuples(
                &owner.poseidon_calls,
                ledger,
                domain_mask,
            );
            if (domain_mask & relationDomainBit(.recursion_wire) != 0) {
                try appendWireBoundaryTuples(
                    ledger,
                    &authority.lowering_plan,
                );
            }
            if (std.process.hasEnvVarConstant(CLOSURE_DIAGNOSTIC_ENV)) {
                reportNativeArithmeticTupleFrontier(
                    authority.arithmetic_reference,
                    &authority.lowering_plan,
                    ledger,
                );
            }
        }

        /// Bounded, allocation-free provenance for the final arithmetic closure seam.
        /// Prefix coordinates are retained by `TupleLedger` itself, so this does not
        /// create a second tuple authority or copy attacker-sized witness material.
        pub fn reportNativeArithmeticTupleFrontier(
            reference: lowering.Reference,
            plan: *const lowering.Plan,
            ledger: *TupleLedger,
        ) void {
            for (reference.lanes) |lane| {
                if (lane.active_in != .segment) continue;
                var multiply: usize = 0;
                var inverse: usize = 0;
                var linear: usize = 0;
                var boundary_emits: usize = 0;
                var boundary_consumes: usize = 0;
                for (lane.graph.nodes) |node| switch (node.op) {
                    .mul => multiply += 1,
                    .inverse => inverse += 1,
                    .add, .sub, .neg => linear += 1,
                    .input, .constant => {},
                };
                for (plan.public_terms) |term| {
                    if (term.active_in != .segment or
                        term.circuit_id != lane.circuit_id) continue;
                    switch (term.role) {
                        .emit => boundary_emits += 1,
                        .consume => boundary_consumes += 1,
                        .request => {},
                    }
                }
                std.debug.print(
                    "native-v2-core arithmetic lane circuit={d} nodes={d} " ++
                        "outputs={d} mul={d} inv={d} linear={d} " ++
                        "boundary_emits={d} boundary_consumes={d}\n",
                    .{
                        lane.circuit_id,
                        lane.graph.nodes.len,
                        lane.graph.outputs.len,
                        multiply,
                        inverse,
                        linear,
                        boundary_emits,
                        boundary_consumes,
                    },
                );
            }

            const report = ledger.classify();
            std.debug.print(
                "native-v2-core tuple frontier contributions={d} unmatched={d}\n",
                .{ report.contribution_count, report.unmatched_tuple_count },
            );
            var printed: usize = 0;
            var cursor: usize = 0;
            while (cursor < ledger.contributions.items.len and printed < 16) {
                const start = cursor;
                const first = ledger.contributions.items[start];
                const end = tupleGroupEnd(ledger.contributions.items, start);
                cursor = end;
                if (first.domain != .recursion_wire) continue;
                var residual = QM31.zero();
                var arithmetic_owned = false;
                for (ledger.contributions.items[start..end]) |item| {
                    residual = residual.add(item.signed_weight);
                    arithmetic_owned = arithmetic_owned or
                        item.component == @intFromEnum(
                            air.universal_roster.Component.qm31_mul,
                        ) or
                        item.component == @intFromEnum(
                            air.universal_roster.Component.linear_ops,
                        );
                }
                if (residual.isZero() or !arithmetic_owned) continue;
                const circuit = first.tuple_prefix[0].toM31Array();
                const node = first.tuple_prefix[1].toM31Array();
                const value_0 = first.tuple_prefix[2].toM31Array();
                const value_1 = first.tuple_prefix[3].toM31Array();
                const value_2 = first.tuple_prefix[4].toM31Array();
                const residual_words = residual.toM31Array();
                std.debug.print(
                    "native-v2-core unmatched circuit={d} node={d} " ++
                        "value_prefix=[{d},{d},{d}] residual=[{d},{d},{d},{d}] " ++
                        "records={d}\n",
                    .{
                        circuit[0].toU32(),
                        node[0].toU32(),
                        value_0[0].toU32(),
                        value_1[0].toU32(),
                        value_2[0].toU32(),
                        residual_words[0].toU32(),
                        residual_words[1].toU32(),
                        residual_words[2].toU32(),
                        residual_words[3].toU32(),
                        end - start,
                    },
                );
                printed += 1;
            }
        }

        pub fn appendNativeCoreTupleRows(
            plan: anytype,
            ledger: *TupleLedger,
            component: air.universal_roster.Component,
            rows: anytype,
            domain_mask: u64,
        ) !void {
            try plan.appendPreparedTupleContributions(
                ledger,
                @intCast(@intFromEnum(component)),
                rows,
                domain_mask,
            );
        }

        pub fn appendNativePoseidonProviderTuples(
            poseidon_calls: *const PoseidonCallBuffers,
            ledger: *TupleLedger,
            domain_mask: u64,
        ) !void {
            if (domain_mask & relationDomainBit(.poseidon2_io) == 0) return;
            const calls = try poseidon_calls.callsView();
            const outputs = try poseidon_calls.outputsView();
            for (calls, outputs) |call, output| {
                var tuple: [2 * poseidon2_air.WIDTH]QM31 = undefined;
                for (tuple[0..poseidon2_air.WIDTH], call.input) |*word, value|
                    word.* = QM31.fromBase(M31.fromCanonical(value));
                for (tuple[poseidon2_air.WIDTH..], output) |*word, value|
                    word.* = QM31.fromBase(M31.fromCanonical(value));
                try ledger.append(
                    .poseidon2_io,
                    @intCast(@intFromEnum(air.universal_roster.Component.poseidon2)),
                    3,
                    .emit,
                    QM31.one(),
                    &tuple,
                );
            }
        }

        /// Independent verifier-side reconstruction from the same authenticated
        /// capture and boundary prefix. It owns a fresh authority, inactive lanes,
        /// row schedules, and provider outputs; no prover-generated row or claim is
        /// imported.
        pub fn independentlyRebuildNativeSegmentCoreV2(
            allocator: std.mem.Allocator,
            inputs: NativeSegmentCoreAuthorityInputsV2,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !NativeSegmentCoreGeneratedV2 {
            var rebuilt = try NativeSegmentCoreV2.init(allocator, inputs);
            defer rebuilt.deinit();
            try rebuilt.finalizeSharedProviderMain();
            return rebuilt.rebuildGeneratedInteractions(
                allocator,
                relations,
                provider_relations,
            );
        }

        pub fn testNativeSegmentCoreOwnerApi() !void {
            std.testing.refAllDeclsRecursive(NativeSegmentCoreAuthorityInputsV2);
            std.testing.refAllDeclsRecursive(NativeSegmentCoreGeneratedV2);
            std.testing.refAllDeclsRecursive(NativeSegmentCoreComponentsV2);
            std.testing.refAllDeclsRecursive(NativeSegmentCoreV2);
            try std.testing.expectEqual(@as(u8, 18), NATIVE_V2_CORE_FIRST_ROW);
            try std.testing.expectEqual(@as(u8, 34), NATIVE_V2_CORE_LAST_ROW);
            try std.testing.expectEqual(@as(usize, 17), NATIVE_V2_CORE_ROW_COUNT);
            try std.testing.expectEqual(
                @as(usize, 1),
                NATIVE_V2_CORE_PROVIDER_INSTANCE_COUNT,
            );
            try std.testing.expectEqual(
                [_]usize{ 0, 0, 0 },
                NATIVE_V2_CORE_HOT_TREE_HEAP_ALLOCATIONS,
            );
            try std.testing.expectEqual(
                @as(usize, 8),
                MAX_ARITHMETIC_EVALUATION_LANES,
            );
            try std.testing.expect(!NATIVE_V2_CORE_RETAINS_SELF_POINTERS);

            // A captured Merkle position proves only the selected low-bit projection;
            // row 20 must retain and decompose the complete authenticated row-9 word.
            const full_words = [_]M31{
                M31.fromCanonical(0x4000_0003),
                M31.fromCanonical(0x2000_001d),
            };
            const positions = [_]M31{
                M31.fromCanonical(3),
                M31.fromCanonical(29),
            };
            try validateQueryWordProjection(5, &full_words, &positions);
            try std.testing.expectEqual(@as(u32, 0x4000_0003), full_words[0].toU32());
            var wrong_positions = positions;
            wrong_positions[1] = M31.fromCanonical(28);
            try std.testing.expectError(
                error.AuthorityMismatch,
                validateQueryWordProjection(5, &full_words, &wrong_positions),
            );
            try std.testing.expectError(
                error.InvalidProofShape,
                validateQueryWordProjection(5, full_words[0..1], &positions),
            );
            try testSingleArithmeticLaneTupleClosure();
        }
    };
}
