//! Role-0 verifier-rerecorded composition graph contract.
//!
//! The graph records the genuine schema-3 36-component cohort in physical
//! order. It is parameterized by the live campaign manifest and consumes the
//! two independently reconstructed row-34 Poseidon partials; no canonical-
//! empty graph or digest is promoted into this authority.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const cohort_mod =
    @import("recursive_common_ethereum_incremental_leaf_secure_cohort_v4.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");

const recursion = frontend.recursion;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const capture_layout = composition_v3.capture_layout_v3;
const segment_recorder = composition_v3.segment_recorder_v3;
const QM31 = stwo_core.fields.qm31.QM31;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const PRODUCTION_ACTIVATION = false;
pub const MANIFEST_FAMILY = capture_layout.ManifestFamily
    .ethereum_incremental_leaf_wrapper_v4;
pub const CLAIM_MANIFEST_FAMILY =
    composition_v3.ManifestFamilyV3.universal_v1;
pub const CLAIM_POLICY =
    composition_v3.ClaimPolicyV3.universal_with_zero_tail;
pub const PHYSICAL_CLAIM_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const PROVIDER_PARTIAL_COUNT: usize = 2;
pub const PROVIDER_PARTIAL_START = composition_v3.POSEIDON_AUX_START;
pub const PROVIDER_ROW: usize = 34;

pub fn Types(comptime Engine: type) type {
    const Cohort = cohort_mod.CohortV4(Engine);
    const Kernel = secure_engine.EngineKernelForManifest(
        Cohort,
        manifest_mod,
        .ethereum_incremental_leaf_wrapper_v4,
    );
    const ProgramRecorder = segment_recorder.ProgramRecorderForManifest(
        manifest_mod,
        .binary_node,
        manifest_mod.COMPONENT_COUNT,
    );

    return struct {
        pub const CohortV4 = Cohort;
        pub const KernelV4 = Kernel;
        pub const VerifiedReplay = Kernel.VerifiedReplay;
        pub const ProgramRecorderV4 = ProgramRecorder;

        pub const ClaimInputsV4 = struct {
            values: [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31,

            pub fn init(replay: *const VerifiedReplay) !ClaimInputsV4 {
                const result = try initUnchecked(replay);
                try result.validateAgainst(replay);
                return result;
            }

            pub fn validateAgainst(
                self: *const ClaimInputsV4,
                replay: *const VerifiedReplay,
            ) !void {
                try composition_v3.validateClaimInputsForManifestPolicy(
                    .binary_node,
                    CLAIM_MANIFEST_FAMILY,
                    CLAIM_POLICY,
                    &self.values,
                );
                const expected = try initUnchecked(replay);
                if (!qm31SliceEql(&self.values, &expected.values))
                    return error.EthereumIncrementalCompositionClaimMismatchV4;
            }

            fn initUnchecked(
                replay: *const VerifiedReplay,
            ) !ClaimInputsV4 {
                var result = ClaimInputsV4{ .values = undefined };
                try composition_v3.writeClaimInputs(
                    .binary_node,
                    &replay.claims.values,
                    &replay.generated.native.poseidon2_partials,
                    &result.values,
                );
                return result;
            }
        };

        pub fn initCaptureLayout(
            allocator: std.mem.Allocator,
            manifest: *const manifest_mod.Manifest,
            capture: anytype,
        ) !capture_layout.CaptureLayoutV3 {
            return capture_layout.CaptureLayoutV3
                .initAuthenticatedBinaryWithProviderRow(
                allocator,
                MANIFEST_FAMILY,
                PROVIDER_ROW,
                manifest,
                capture,
            );
        }

        pub fn recordCohort(
            program: *ProgramRecorder,
            components: *const Cohort.Components,
        ) !segment_recorder.ProgramResultV3 {
            _ = try program.recordTypedComponent(.control, &components.prefix.control);
            _ = try program.recordTypedComponent(.transcript_air, &components.prefix.transcript_air);
            _ = try program.recordTypedComponent(.transcript_binding, &components.prefix.transcript_binding);
            _ = try program.recordTypedComponent(.transcript_state, &components.prefix.transcript_state);
            _ = try program.recordTypedComponent(.transcript_word, &components.prefix.transcript_word);
            _ = try program.recordTypedComponent(.transcript_payload, &components.prefix.transcript_payload);
            _ = try program.recordTypedComponent(.pow_check, &components.prefix.pow_check);
            _ = try program.recordTypedComponent(.pow_frame, &components.prefix.pow_frame);
            _ = try program.recordTypedComponent(.relation_challenge, &components.prefix.relation_challenge);
            _ = try program.recordTypedComponent(.verifier_randomness, &components.prefix.verifier_randomness);
            _ = try program.recordTypedComponent(.statement_input, &components.suffix.statement_input);
            _ = try program.recordTypedComponent(.statement_semantics_input, &components.suffix.statement_semantics);
            _ = try program.recordTypedComponent(.vm_public_claim_input, &components.suffix.claim_input);
            _ = try program.recordTypedComponent(.vm_public_claim_hash, &components.suffix.claim_hash);
            _ = try program.recordTypedComponent(.vm_public_io_hash, &components.suffix.io_hash);
            _ = try program.recordTypedComponent(.vm_public_claim_semantics_input, &components.suffix.claim_semantics);
            _ = try program.recordTypedComponent(.vm_public_logup_input, &components.suffix.public_logup);
            _ = try program.recordTypedComponent(.vm_public_logup_control, &components.suffix.public_logup_control);
            _ = try program.recordTypedComponent(.vm_air_composition_input, &components.native.vm_input);
            _ = try program.recordTypedComponent(.vm_air_composition_control, &components.native.composition_control);
            _ = try program.recordTypedComponent(.query_bits, &components.native.query_bits);
            _ = try program.recordTypedComponent(.query_mapping, &components.native.query_mapping);
            _ = try program.recordTypedComponent(.merkle_root, &components.native.merkle_root);
            _ = try program.recordTypedComponent(.trace_merkle, &components.native.trace_merkle);
            _ = try program.recordTypedComponent(.pcs_deep_input, &components.native.pcs_deep);
            _ = try program.recordTypedComponent(.fri_merkle_leaf, &components.native.fri_leaf);
            _ = try program.recordTypedComponent(.fri_merkle_node, &components.native.fri_node);
            _ = try program.recordTypedComponent(.fri_merkle_anchor, &components.native.fri_anchor);
            _ = try program.recordTypedComponent(.fri_verifier_control, &components.native.control);
            _ = try program.recordTypedComponent(.fri_verifier_input, &components.native.input);
            _ = try program.recordTypedComponent(.qm31_mul, &components.native.multiply);
            _ = try program.recordTypedComponent(.qm31_inv, &components.native.inverse);
            _ = try program.recordTypedComponent(.linear_ops, &components.native.linear);
            _ = try program.recordTypedComponent(.merkle_path, &components.native.merkle_path);
            _ = try program.recordPoseidonProvider(&components.native.poseidon2);
            _ = try program.recordRangeCheck8x8Provider(&components.range);
            return program.finishProgram();
        }
    };
}

fn qm31SliceEql(left: []const QM31, right: []const QM31) bool {
    if (left.len != right.len) return false;
    for (left, right) |lhs, rhs| if (!lhs.eql(rhs)) return false;
    return true;
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        PRODUCTION_ACTIVATION or PHYSICAL_CLAIM_COUNT != 36 or
        PROVIDER_ROW != 34 or PROVIDER_PARTIAL_COUNT != 2 or
        PROVIDER_PARTIAL_START != 39 or
        @intFromEnum(MANIFEST_FAMILY) != 7)
    {
        @compileError("Ethereum incremental composition graph V4 drifted");
    }
}
