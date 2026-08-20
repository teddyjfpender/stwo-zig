//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const air = context.d_air;
        const vm_input_witness = context.d_vm_input_witness;
        const schedule = context.d_schedule;
        const lowering = context.d_lowering;
        const manifest_mod = context.d_manifest_mod;
        const universal = context.d_universal;
        const Engine = context.d_Engine;
        const FORMAT_VERSION = context.d_FORMAT_VERSION;
        const TRANSCRIPT_DOMAIN = context.d_TRANSCRIPT_DOMAIN;
        const Claims = context.d_Claims;
        const TupleLedger = context.d_TupleLedger;
        const Authority = context.d_Authority;
        const digestWords = context.d_digestWords;

        pub fn appendWireBoundaryTuples(
            ledger: *TupleLedger,
            plan: *const lowering.Plan,
        ) !void {
            for (plan.public_terms) |term| {
                if (term.active_in != .segment) continue;
                const value_words = term.value.toM31Array();
                const tuple = [_]QM31{
                    QM31.fromBase(M31.fromCanonical(term.circuit_id)),
                    QM31.fromBase(M31.fromCanonical(term.node_id)),
                    QM31.fromBase(value_words[0]),
                    QM31.fromBase(value_words[1]),
                    QM31.fromBase(value_words[2]),
                    QM31.fromBase(value_words[3]),
                };
                var signed_weight = QM31.fromBase(
                    M31.fromCanonical(term.multiplicity),
                );
                if (term.role != .emit) signed_weight = signed_weight.neg();
                try ledger.append(
                    .recursion_wire,
                    @intCast(air.universal_roster.COMPONENT_COUNT),
                    0,
                    term.role,
                    signed_weight,
                    &tuple,
                );
            }
        }

        /// Positive verifier-input boundary for the declaration-ordered detailed VM
        /// claims consumed by row 18. These are not the 28 canonical transcript
        /// aggregates consumed by row 16: the successful native verifier publishes
        /// the exact per-component values in `vm_air`, and both outer prover and
        /// verifier recompute this boundary from that authenticated schedule.
        pub fn verifierInputBoundaryClaim(
            authority: *const Authority,
            relations: *const universal.UniversalRelations,
        ) !QM31 {
            const vm_air = authority.vm_air orelse return QM31.zero();
            const challenge = try relations.getExact(.recursion_verifier_input_word);
            var result = QM31.zero();
            var contribution_count: usize = 0;
            for (
                vm_air.prepared.preprocessing.rows,
                vm_air.prepared.schedule_values,
            ) |row, value| {
                const coordinate = detailedClaimCoordinate(row) orelse continue;
                const tuple = verifierInputBoundaryTuple(coordinate, value);
                const denominator = try challenge.combineBase(&tuple);
                result = result.add(denominator.inv() catch
                    return error.WireClosureMismatch);
                contribution_count += 1;
            }
            try validateDetailedClaimBoundaryCount(vm_air.prepared, contribution_count);
            return result;
        }

        pub fn appendVerifierInputBoundaryTuples(
            ledger: *TupleLedger,
            authority: *const Authority,
        ) !void {
            const vm_air = authority.vm_air orelse return;
            var contribution_count: usize = 0;
            for (
                vm_air.prepared.preprocessing.rows,
                vm_air.prepared.schedule_values,
            ) |row, value| {
                const coordinate = detailedClaimCoordinate(row) orelse continue;
                const base_tuple = verifierInputBoundaryTuple(coordinate, value);
                var tuple: [base_tuple.len]QM31 = undefined;
                for (&tuple, base_tuple) |*destination, word|
                    destination.* = QM31.fromBase(word);
                try ledger.append(
                    .recursion_verifier_input_word,
                    @intCast(air.universal_roster.COMPONENT_COUNT),
                    1,
                    .emit,
                    QM31.one(),
                    &tuple,
                );
                contribution_count += 1;
            }
            try validateDetailedClaimBoundaryCount(vm_air.prepared, contribution_count);
        }

        pub fn detailedClaimCoordinate(
            row: vm_input_witness.Row,
        ) ?vm_input_witness.SecureCoordinate {
            return switch (row.classification) {
                .vm_input => |source_value| switch (source_value) {
                    .claimed_sum => |coordinate| coordinate,
                    else => null,
                },
                else => null,
            };
        }

        pub fn verifierInputBoundaryTuple(
            coordinate: vm_input_witness.SecureCoordinate,
            value: M31,
        ) [5]M31 {
            return .{
                M31.fromCanonical(vm_input_witness.SEGMENT_VERIFIER_ID),
                M31.fromCanonical(vm_input_witness.VM_CLAIMED_SUM_KIND),
                M31.fromCanonical(coordinate.item_index),
                M31.fromCanonical(coordinate.word_index),
                value,
            };
        }

        pub fn validateDetailedClaimBoundaryCount(
            prepared: *const recursion.vm_air_composition_circuit.Prepared,
            actual: usize,
        ) !void {
            const expected = std.math.mul(
                usize,
                @as(usize, prepared.circuit.input_profile.claimed_sum_count),
                vm_input_witness.SECURE_VALUE_WORD_COUNT,
            ) catch return error.ArithmeticOverflow;
            if (actual != expected) return error.AuthorityMismatch;
        }

        pub fn claimVector(
            manifest: *const manifest_mod.Manifest,
            claims: Claims,
        ) !manifest_mod.ClaimVector {
            var result = try manifest_mod.ClaimVector.init(manifest);
            if (manifest.placements[
                @intFromEnum(
                    air.universal_roster.Component.control,
                )
            ] != null) {
                try claims.segment_leaf.?.bindPrefixInto(&result);
            }
            if (manifest.placements[
                @intFromEnum(
                    air.universal_roster.Component.vm_air_composition_input,
                )
            ] != null) {
                try result.bind(.vm_air_composition_input, claims.vm_input);
            }
            try result.bind(.vm_air_composition_control, claims.composition_control);
            try result.bind(.query_bits, claims.query_bits);
            try result.bind(.query_mapping, claims.query_mapping);
            try result.bind(.merkle_root, claims.merkle_root);
            try result.bind(.trace_merkle, claims.trace_merkle);
            try result.bind(.pcs_deep_input, claims.pcs_deep);
            try result.bind(.fri_merkle_leaf, claims.fri_leaf);
            try result.bind(.fri_merkle_node, claims.fri_node);
            try result.bind(.fri_merkle_anchor, claims.fri_anchor);
            try result.bind(.fri_verifier_control, claims.control);
            try result.bind(.fri_verifier_input, claims.input);
            try result.bind(.qm31_mul, claims.multiply);
            try result.bind(.qm31_inv, claims.inverse);
            try result.bind(.linear_ops, claims.linear);
            try result.bind(.merkle_path, claims.merkle_path);
            try result.bind(
                .poseidon2,
                claims.poseidon2[0].add(claims.poseidon2[1]),
            );
            if (claims.segment_leaf) |segment_leaf|
                try segment_leaf.bindSharedProviderInto(&result);
            try result.sealClaims(manifest);
            return result;
        }

        pub fn mixAuthority(channel: *Engine.Channel, authority: *const Authority) void {
            channel.mixU32s(&.{ TRANSCRIPT_DOMAIN, FORMAT_VERSION });
            channel.mixU32s(&.{@intFromBool(authority.vm_air != null)});
            if (authority.vm_air) |vm_air| {
                channel.mixU32s(&digestWords(vm_air.prepared.circuit.identity_digest));
                channel.mixU32s(&digestWords(vm_air.prepared.circuit.reference_digest));
                channel.mixU32s(&digestWords(vm_air.prepared.circuit.schedule_digest));
                channel.mixU32s(&digestWords(vm_air.prepared.circuit.air_profile_digest));
                channel.mixU32s(&digestWords(
                    vm_air.prepared.preprocessing.authority_digest,
                ));
            }
            channel.mixU32s(&authority.vm_schedule.authority_digest);
            channel.mixU32s(&authority.recursion_schedule.authority_digest);
            if (authority.segment_transcript) |source| {
                const inputs = authority.segment_transcript_inputs.?;
                const prepared = inputs.prepared;
                channel.mixU32s(&digestWords(prepared.execution.identity_digest));
                channel.mixU32s(&source.log_sizes);
                var final_digest: [recursion.poseidon2_channel.RATE]u32 = undefined;
                for (&final_digest, prepared.execution.final_digest) |*target, word|
                    target.* = word.toU32();
                channel.mixU32s(&final_digest);
                channel.mixU32s(&.{prepared.execution.final_draw_count});
                channel.mixU32s(&digestWords(inputs.public.source.authority_seal));
                channel.mixU32s(&digestWords(inputs.public.prepared.authority_seal));
                channel.mixU32s(&inputs.public.source.log_sizes);
                channel.mixU32s(&digestWords(
                    inputs.statement.authority.circuit.identity_digest,
                ));
                channel.mixU32s(&digestWords(
                    inputs.statement.authority.lowering_graph.identity_digest,
                ));
            }
            channel.mixU32s(&.{
                authority.composition_control_preprocessing.vm_air_instruction_count,
                authority.composition_control_preprocessing.vm_sampled_value_count,
                authority.composition_control_preprocessing.recursion_air_instruction_count,
                authority.composition_control_preprocessing.recursion_sampled_value_count,
            });
            const query_bits_words = digestWords(
                authority.query_bits_reference.authority_digest,
            );
            channel.mixU32s(&query_bits_words);
            const query_mapping_words = digestWords(
                authority.query_mapping_reference.authority_digest,
            );
            channel.mixU32s(&query_mapping_words);
            const merkle_root_words = digestWords(
                authority.merkle_root_reference.authority_digest,
            );
            channel.mixU32s(&merkle_root_words);
            const merkle_root_pp_words = digestWords(
                authority.merkle_root_preprocessing.authority_digest,
            );
            channel.mixU32s(&merkle_root_pp_words);
            const trace_merkle_words = digestWords(
                authority.trace_merkle_reference.authority_digest,
            );
            channel.mixU32s(&trace_merkle_words);
            const trace_merkle_pp_words = digestWords(
                authority.trace_merkle_preprocessing.authority_digest,
            );
            channel.mixU32s(&trace_merkle_pp_words);
            const fri_words = digestWords(authority.fri_reference.authority_digest);
            channel.mixU32s(&fri_words);
            const fri_leaf_pp_words = digestWords(
                authority.fri_leaf_preprocessing.authority_digest,
            );
            channel.mixU32s(&fri_leaf_pp_words);
            const fri_node_pp_words = digestWords(
                authority.fri_node_preprocessing.authority_digest,
            );
            channel.mixU32s(&fri_node_pp_words);
            const fri_anchor_pp_words = digestWords(
                authority.fri_anchor_preprocessing.authority_digest,
            );
            channel.mixU32s(&fri_anchor_pp_words);
            const control_words = digestWords(authority.control_reference.authority_digest);
            channel.mixU32s(&control_words);
            const pcs_reference_words = digestWords(
                authority.pcs_reference.authority_digest,
            );
            channel.mixU32s(&pcs_reference_words);
            const pcs_preprocessing_words = digestWords(
                authority.pcs_preprocessing.authority_digest,
            );
            channel.mixU32s(&pcs_preprocessing_words);
            const reference_words = digestWords(authority.reference.authority_digest);
            channel.mixU32s(&reference_words);
            const lowering_words = digestWords(authority.lowering_plan.authority_digest);
            channel.mixU32s(&lowering_words);
        }

        pub fn mixPublicBoundaries(channel: *Engine.Channel, claims: Claims) void {
            channel.mixU32s(&.{ TRANSCRIPT_DOMAIN, FORMAT_VERSION, 2 });
            channel.mixFelts(&.{
                claims.input_wire,
                claims.public_boundaries.wire,
                claims.public_boundaries.verifier_input,
            });
        }

        // Independent verifier-side reconstruction of the exact 36 x 47 relation
        // decomposition. It regenerates consumer rows from authenticated captures and
        // prepared authorities and retains the two Poseidon provider coordinates
        // already checked by the STARK verifier; no prover audit, interaction column,
        // or tuple ledger crosses this boundary. Scratch is protocol-bounded and
        // released one row family at a time where possible.
    };
}
