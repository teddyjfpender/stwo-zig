//! Composition-graph contract for the genuine field-native common fold.
//!
//! The graph records the complete universal-36 cohort in physical order.  It
//! consumes the fixed-wire verifier rows and the full row-34 provider; no
//! canonical-empty recorder program is reused as semantic authority.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const cohort_mod = @import("recursive_common_fold_secure_cohort_v2.zig");
const manifest_mod = @import("recursive_common_fold_universal_manifest_v2.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");

const recursion = frontend.recursion;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const capture_layout = composition_v3.capture_layout_v3;
const segment_recorder = composition_v3.segment_recorder_v3;
const QM31 = stwo_core.fields.qm31.QM31;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const MANIFEST_FAMILY = capture_layout.ManifestFamily.common_fold_field_v2;
pub const CLAIM_MANIFEST_FAMILY =
    composition_v3.ManifestFamilyV3.common_fold_field_v2;
pub const CLAIM_POLICY = composition_v3.ClaimPolicyV3.common_fold_field_v2;
pub const PHYSICAL_CLAIM_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const PROVIDER_PARTIAL_START = composition_v3.POSEIDON_AUX_START;
pub const PROVIDER_ROW: usize = 34;

pub fn Types(comptime dimensions: recursion.fixed_wire.Dimensions) type {
    const Cohort = cohort_mod.CohortV2(dimensions);
    return TypesForCohort(dimensions, Cohort);
}

pub fn TypesForCohort(
    comptime dimensions: recursion.fixed_wire.Dimensions,
    comptime Cohort: type,
) type {
    dimensions.validate();
    const Kernel = secure_engine.EngineKernelForManifest(
        Cohort,
        manifest_mod,
        .common_fold_field_v2,
    );
    const ProgramRecorder = segment_recorder.ProgramRecorderForManifest(
        manifest_mod,
        .binary_node,
        manifest_mod.COMPONENT_COUNT,
    );

    return struct {
        pub const CohortV2 = Cohort;
        pub const KernelV2 = Kernel;
        pub const VerifiedReplay = Kernel.VerifiedReplay;
        pub const ProgramRecorderV2 = ProgramRecorder;

        pub const ClaimInputsV2 = struct {
            values: [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31,

            pub fn init(replay: *const VerifiedReplay) !ClaimInputsV2 {
                const result = try initUnchecked(replay);
                try result.validateAgainst(replay);
                return result;
            }

            pub fn validateAgainst(
                self: *const ClaimInputsV2,
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
                    return error.CommonFoldCompositionClaimMismatch;
            }

            fn initUnchecked(replay: *const VerifiedReplay) !ClaimInputsV2 {
                var result = ClaimInputsV2{ .values = undefined };
                try composition_v3.writeClaimInputsForManifest(
                    .binary_node,
                    CLAIM_MANIFEST_FAMILY,
                    &replay.claims.values,
                    &replay.generated.suffix.claims.poseidon2_partials,
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
            inline for (manifest_mod.COMPONENT_KEYS[0..18], 0..) |key, index|
                _ = try program.recordTypedComponent(
                    key,
                    &components.logical[index],
                );
            _ = try program.recordTypedComponent(
                .vm_air_composition_input,
                &components.suffix.composition_input,
            );
            _ = try program.recordTypedComponent(
                .vm_air_composition_control,
                &components.suffix.composition_control,
            );
            _ = try program.recordTypedComponent(.query_bits, &components.suffix.query_bits);
            _ = try program.recordTypedComponent(.query_mapping, &components.suffix.query_mapping);
            _ = try program.recordTypedComponent(.merkle_root, &components.suffix.merkle_root);
            _ = try program.recordTypedComponent(.trace_merkle, &components.suffix.trace_merkle);
            _ = try program.recordTypedComponent(.pcs_deep_input, &components.suffix.pcs_deep);
            _ = try program.recordTypedComponent(.fri_merkle_leaf, &components.suffix.fri_leaf);
            _ = try program.recordTypedComponent(.fri_merkle_node, &components.suffix.fri_node);
            _ = try program.recordTypedComponent(.fri_merkle_anchor, &components.suffix.fri_anchor);
            _ = try program.recordTypedComponent(.fri_verifier_control, &components.suffix.fri_control);
            _ = try program.recordTypedComponent(.fri_verifier_input, &components.suffix.fri_input);
            _ = try program.recordTypedComponent(.qm31_mul, &components.suffix.multiply);
            _ = try program.recordTypedComponent(.qm31_inv, &components.suffix.inverse);
            _ = try program.recordTypedComponent(.linear_ops, &components.suffix.linear);
            _ = try program.recordTypedComponent(.merkle_path, &components.suffix.merkle_path);
            _ = try program.recordPoseidonProvider(&components.suffix.poseidon2);
            _ = try program.recordRangeCheck8x8Provider(&components.range);
            return program.finishProgram();
        }
    };
}

fn qm31SliceEql(left: []const QM31, right: []const QM31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!a.eql(b)) return false;
    return true;
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or PHYSICAL_CLAIM_COUNT != 36 or
        PROVIDER_ROW != 34 or PROVIDER_PARTIAL_START != 39)
    {
        @compileError("common-fold composition graph contract drifted");
    }
}
