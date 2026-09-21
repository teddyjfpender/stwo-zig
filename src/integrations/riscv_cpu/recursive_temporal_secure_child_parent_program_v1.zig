//! Append-only composition-program authority for a verified temporal parent.
//!
//! The selector remains `.binary_node`; only the authenticated manifest family
//! and claim policy differ from the frozen universal binary program.  This
//! module owns the temporal descriptor so the legacy three-selector roster and
//! its default bytes remain unchanged.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const manifest_mod = @import("recursive_temporal_parent_manifest_v3.zig");

const composition_v3 = frontend.recursion.recursion_air_composition_circuit_v3;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const MANIFEST_FAMILY = composition_v3.ManifestFamilyV3.temporal_parent_v3;
pub const CLAIM_POLICY = composition_v3.ClaimPolicyV3.temporal_parent;
pub const PRODUCTION_ACTIVATION = false;

const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/secure-child-temporal-program/v1\x00";

pub const AuthorityV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    descriptor: composition_v3.ProgramDescriptorV3,
    identity_sha256: [32]u8,

    pub fn init(
        manifest: *const manifest_mod.Manifest,
        air_program_id: composition_v3.AirProgramId,
    ) !AuthorityV1 {
        try manifest.validate();
        const shape = composition_v3.temporalParentDescriptorShape();
        if (manifest.roster_count != shape.program_roster_count or
            manifest.roster_rows[@as(usize, shape.poseidon_roster_row)] !=
                shape.poseidon_roster_row)
        {
            return error.InvalidSecureTemporalParentProgram;
        }
        var descriptor = composition_v3.ProgramDescriptorV3{
            .proof_kind = .binary_node,
            .manifest_family = MANIFEST_FAMILY,
            .claim_policy = CLAIM_POLICY,
            .source_claim_count = shape.source_claim_count,
            .program_roster_count = shape.program_roster_count,
            .poseidon_partial_count = shape.poseidon_partial_count,
            .composition_claim_count = composition_v3.COMPOSITION_CLAIM_INPUT_COUNT,
            .poseidon_roster_row = shape.poseidon_roster_row,
            .manifest_format_version = manifest.format_version,
            .manifest_seal = manifest.seal,
            .catalog_identity = [_]u8{0} ** 32,
            .air_program_id = air_program_id,
            .ordered_program_identity = orderedProgramIdentity(manifest),
            .identity = undefined,
        };
        descriptor.identity = composition_v3.programDescriptorIdentity(
            descriptor,
        );
        try descriptor.validate();
        var result = AuthorityV1{
            .descriptor = descriptor,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = authorityIdentity(&result);
        try result.validateAgainst(manifest, air_program_id);
        return result;
    }

    pub fn validateAgainst(
        self: *const AuthorityV1,
        manifest: *const manifest_mod.Manifest,
        air_program_id: composition_v3.AirProgramId,
    ) !void {
        try manifest.validate();
        try self.descriptor.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.descriptor.proof_kind != .binary_node or
            self.descriptor.manifest_family != MANIFEST_FAMILY or
            self.descriptor.claim_policy != CLAIM_POLICY or
            !std.meta.eql(self.descriptor.air_program_id, air_program_id) or
            !std.mem.eql(
                u8,
                &self.descriptor.manifest_seal,
                &manifest.seal,
            ) or !std.mem.eql(
            u8,
            &self.descriptor.ordered_program_identity,
            &orderedProgramIdentity(manifest),
        ) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &authorityIdentity(self),
        )) {
            return error.InvalidSecureTemporalParentProgram;
        }
    }
};

fn orderedProgramIdentity(
    manifest: *const manifest_mod.Manifest,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(composition_v3.ORDERED_PROGRAM_DOMAIN);
    hashInt(&hash, u16, composition_v3.FORMAT_VERSION);
    hashInt(&hash, u8, @intFromEnum(MANIFEST_FAMILY));
    hash.update(&manifest.seal);
    composition_v3.hashManifestRows(&hash, manifest);
    return hash.finalResult();
}

fn authorityIdentity(value: *const AuthorityV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hash.update(&value.reserved);
    hash.update(&value.descriptor.identity);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (PRODUCTION_ACTIVATION or
        @intFromEnum(MANIFEST_FAMILY) != 4 or
        @intFromEnum(CLAIM_POLICY) != 6 or
        manifest_mod.COMPONENT_COUNT != 36)
    {
        @compileError("secure temporal-parent program authority drifted");
    }
}
