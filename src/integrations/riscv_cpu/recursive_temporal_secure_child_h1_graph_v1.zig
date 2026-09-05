//! H1-specific composition layout, claim policy, and component recorder.
//!
//! The frozen V3 heterogeneous parent has three child kinds and a 39+2 claim
//! ABI. This sibling does not change that parent ABI. It supplies the exact
//! graph-mint pieces for the 12-placement Ethereum H1 child: a distinct
//! authenticated capture-layout family, physical claims 0..11, native
//! Poseidon partials 12/13, zero unused shared slots, and canonical component
//! replay in manifest order. Parent-program selection remains unavailable.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const reconstruction_mod =
    @import("recursive_temporal_secure_child_composition_v1.zig");
const manifest_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_manifest_v1.zig");
const components_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_components_v1.zig");

const recursion = frontend.recursion;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const capture_layout = composition_v3.capture_layout_v3;
const segment_recorder = composition_v3.segment_recorder_v3;
const QM31 = stwo_core.fields.qm31.QM31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const PARENT_PROGRAM_SELECTOR_AVAILABLE = false;
pub const MANIFEST_FAMILY =
    capture_layout.ManifestFamily.ethereum_poseidon_h1_v1;
pub const CLAIM_MANIFEST_FAMILY =
    composition_v3.ManifestFamilyV3.ethereum_poseidon_h1_v1;
pub const SHARED_CLAIM_INPUT_COUNT =
    composition_v3.COMPOSITION_CLAIM_INPUT_COUNT;
pub const PHYSICAL_CLAIM_COUNT = reconstruction_mod.H1_PHYSICAL_CLAIM_COUNT;
pub const PROVIDER_PARTIAL_COUNT =
    reconstruction_mod.H1_PROVIDER_PARTIAL_COUNT;
pub const PROVIDER_PARTIAL_START = PHYSICAL_CLAIM_COUNT;
pub const SEMANTIC_CLAIM_INPUT_COUNT =
    reconstruction_mod.H1_COMPOSITION_CLAIM_INPUT_COUNT;

pub const ProgramRecorder = segment_recorder.ProgramRecorderForManifest(
    manifest_mod,
    .binary_node,
    manifest_mod.COMPONENT_COUNT,
);

const CLAIM_INPUT_DOMAIN =
    "stwo-zig/typed-air/secure-child-h1-claim-inputs/v1\x00";

/// Fixed shared storage with an H1-specific policy. Slots 14..40 are not
/// available to the H1 program and must remain zero; they are retained only
/// until a versioned parent input ABI admits a 14-element child profile.
pub const ClaimInputsV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    values: [SHARED_CLAIM_INPUT_COUNT]QM31,
    identity_sha256: [32]u8,

    pub fn init(
        physical_claims: *const [PHYSICAL_CLAIM_COUNT]QM31,
        provider_partials: *const [PROVIDER_PARTIAL_COUNT]QM31,
    ) !ClaimInputsV1 {
        if (!provider_partials[0].add(provider_partials[1]).eql(
            physical_claims[manifest_mod.keyIndex(.poseidon2)],
        )) return error.SecureChildProviderPartialMismatch;
        var result = ClaimInputsV1{
            .values = undefined,
            .identity_sha256 = undefined,
        };
        try composition_v3.writeClaimInputsForManifest(
            .binary_node,
            CLAIM_MANIFEST_FAMILY,
            physical_claims,
            provider_partials,
            &result.values,
        );
        result.identity_sha256 = claimInputIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn initFromReconstruction(
        reconstruction: *const reconstruction_mod.VerifiedReconstructionV1,
    ) !ClaimInputsV1 {
        try reconstruction.validateRetained();
        return init(
            &reconstruction.claims.values,
            &reconstruction.provider_partial_claims,
        );
    }

    pub fn validate(self: *const ClaimInputsV1) !void {
        try composition_v3.validateClaimInputsForManifestPolicy(
            .binary_node,
            CLAIM_MANIFEST_FAMILY,
            .ethereum_poseidon_h1,
            &self.values,
        );
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &claimInputIdentity(self),
            )) return error.InvalidSecureChildH1ClaimInputs;
    }

    pub fn validateAgainst(
        self: *const ClaimInputsV1,
        reconstruction: *const reconstruction_mod.VerifiedReconstructionV1,
    ) !void {
        try self.validate();
        try reconstruction.validateRetained();
        if (!qm31SliceEql(
            self.values[0..PHYSICAL_CLAIM_COUNT],
            &reconstruction.claims.values,
        ) or !qm31SliceEql(
            self.values[PROVIDER_PARTIAL_START .. PROVIDER_PARTIAL_START + PROVIDER_PARTIAL_COUNT],
            &reconstruction.provider_partial_claims,
        )) return error.SecureChildH1ClaimInputMismatch;
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
        manifest_mod.keyIndex(.poseidon2),
        manifest,
        capture,
    );
}

/// Replays the initialized H1 components in the exact sealed 12-placement
/// order. The returned graph remains a child-local program until the parent
/// admits this manifest-family policy under its existing binary selector.
pub fn recordCohort(
    program: *ProgramRecorder,
    components: *const components_mod.ComponentsV1,
) !segment_recorder.ProgramResultV3 {
    _ = try program.recordTypedComponent(.link_source, &components.source);
    _ = try program.recordTypedComponent(
        .link_projection,
        &components.projection,
    );
    _ = try program.recordTypedComponent(
        .child_field_router,
        &components.router,
    );
    inline for (manifest_mod.COMPONENT_KEYS[3..11], 0..) |key, ordinal|
        _ = try program.recordTypedComponent(key, &components.hashes[ordinal]);
    _ = try program.recordPoseidonProviderAt(
        .poseidon2,
        PROVIDER_PARTIAL_START,
        &components.provider,
    );
    return program.finishProgram();
}

pub fn requireParentProgramSelector() !void {
    if (!PARENT_PROGRAM_SELECTOR_AVAILABLE)
        return error.SecureChildH1ParentProgramSelectorUnavailable;
    if (!PRODUCTION_ACTIVATION)
        return error.SecureChildH1ProductionUnavailable;
}

fn claimInputIdentity(value: *const ClaimInputsV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CLAIM_INPUT_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hash.update(&value.reserved);
    hashInt(&hash, u8, PHYSICAL_CLAIM_COUNT);
    hashInt(&hash, u8, manifest_mod.keyIndex(.poseidon2));
    hashInt(&hash, u8, PROVIDER_PARTIAL_START);
    hashInt(&hash, u8, PROVIDER_PARTIAL_COUNT);
    hashInt(&hash, u8, SEMANTIC_CLAIM_INPUT_COUNT);
    hashInt(&hash, u8, SHARED_CLAIM_INPUT_COUNT);
    for (value.values) |claim| hashQm31(&hash, claim);
    return hash.finalResult();
}

fn qm31SliceEql(left: []const QM31, right: []const QM31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!a.eql(b)) return false;
    return true;
}

fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (PRODUCTION_ACTIVATION or PARENT_PROGRAM_SELECTOR_AVAILABLE or
        PHYSICAL_CLAIM_COUNT != 12 or PROVIDER_PARTIAL_COUNT != 2 or
        PROVIDER_PARTIAL_START != 12 or SEMANTIC_CLAIM_INPUT_COUNT != 14 or
        SHARED_CLAIM_INPUT_COUNT != 41 or
        manifest_mod.keyIndex(.poseidon2) != 11)
    {
        @compileError("secure child H1 graph contract drifted");
    }
}
