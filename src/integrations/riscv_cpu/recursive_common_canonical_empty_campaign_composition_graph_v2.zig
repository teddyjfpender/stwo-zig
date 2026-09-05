//! Campaign canonical-empty field wrapper composition graph authority.
//!
//! This module owns only the manifest-parametric layout and component order.
//! It has no codec and cannot mint freshness.  The retained capture module
//! supplies verifier-replayed claims, relations, PCS samples, and the exact
//! cold cohort before any graph value becomes a fold-child capability.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const cohort_mod =
    @import("recursive_common_canonical_empty_campaign_universal_cohort_v2.zig");
const manifest_mod =
    @import("recursive_common_canonical_empty_campaign_universal_manifest_v2.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");

const recursion = frontend.recursion;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const capture_layout = composition_v3.capture_layout_v3;
const segment_recorder = composition_v3.segment_recorder_v3;
const QM31 = stwo_core.fields.qm31.QM31;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 2;
pub const PRODUCTION_ACTIVATION = false;
pub const MANIFEST_FAMILY =
    capture_layout.ManifestFamily.canonical_empty_field_v2;
pub const CLAIM_MANIFEST_FAMILY =
    composition_v3.ManifestFamilyV3.universal_v1;
pub const CLAIM_POLICY =
    composition_v3.ClaimPolicyV3.universal_with_zero_tail;
pub const PHYSICAL_CLAIM_COUNT = manifest_mod.COMPONENT_COUNT;
pub const PROVIDER_PARTIAL_COUNT: usize = 2;
pub const PROVIDER_PARTIAL_START = composition_v3.POSEIDON_AUX_START;
pub const PROVIDER_ROW = manifest_mod.keyIndex(.poseidon2);

pub const Kernel = secure_engine.EngineKernelForManifest(
    cohort_mod.CohortV2,
    manifest_mod,
    .canonical_empty_campaign_v2,
);
pub const VerifiedReplay = Kernel.VerifiedReplay;

pub const ProgramRecorder = segment_recorder.ProgramRecorderForManifest(
    manifest_mod,
    .binary_node,
    manifest_mod.COMPONENT_COUNT,
);

/// Fixed shared 41-claim ABI: physical roster claims occupy 0..35 and the
/// native Poseidon subclaims occupy the frozen universal slots 39/40.
pub const ClaimInputsV2 = struct {
    values: [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31,

    pub fn init(replay: *const VerifiedReplay) !ClaimInputsV2 {
        const partials = providerPartials(replay);
        var result = ClaimInputsV2{ .values = undefined };
        try composition_v3.writeClaimInputs(
            .binary_node,
            &replay.claims.values,
            &partials,
            &result.values,
        );
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
            return error.CanonicalEmptyCompositionClaimMismatch;
    }

    fn initUnchecked(replay: *const VerifiedReplay) !ClaimInputsV2 {
        const partials = providerPartials(replay);
        var result = ClaimInputsV2{ .values = undefined };
        try composition_v3.writeClaimInputs(
            .binary_node,
            &replay.claims.values,
            &partials,
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

/// Rerecords every universal component in the sealed physical order.  The
/// component adapters are cold-cohort owners, never caller-authored claims.
pub fn recordCohort(
    program: *ProgramRecorder,
    components: *const cohort_mod.ComponentSetV2,
) !segment_recorder.ProgramResultV3 {
    inline for (manifest_mod.COMPONENT_KEYS[0..PROVIDER_ROW], 0..) |
        key,
        ordinal,
    | _ = try program.recordTypedComponent(
        key,
        &components.logical[ordinal],
    );
    _ = try program.recordPoseidonProvider(&components.poseidon);
    _ = try program.recordRangeCheck8x8Provider(&components.range);
    return program.finishProgram();
}

fn providerPartials(replay: *const VerifiedReplay) [2]QM31 {
    return .{
        replay.generated.provider_claims.poseidon2,
        replay.generated.provider_claims.poseidon2_io,
    };
}

fn qm31SliceEql(left: []const QM31, right: []const QM31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!a.eql(b)) return false;
    return true;
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 2 or
        PRODUCTION_ACTIVATION or PHYSICAL_CLAIM_COUNT != 36 or
        PROVIDER_ROW != 34 or PROVIDER_PARTIAL_COUNT != 2 or
        PROVIDER_PARTIAL_START != 39)
    {
        @compileError("campaign canonical-empty composition graph contract drifted");
    }
}
