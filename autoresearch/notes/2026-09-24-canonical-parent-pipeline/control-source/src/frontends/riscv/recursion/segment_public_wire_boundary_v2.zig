//! Verifier-only public-wire boundary value, identity and validation.
const std = @import("std");
const stwo_core = @import("stwo_core");
const QM31 = stwo_core.fields.qm31.QM31;
const digest = @import("../air/lang/digest.zig");
const relation = @import("../air/lang/relation.zig");
const manifest_mod = @import("air/segment_outer_manifest_contract_v2.zig");

pub const PUBLIC_WIRE_BOUNDARY_FORMAT_VERSION: u16 = 1;

pub const PUBLIC_WIRE_BOUNDARY_ID_DOMAIN =
    "stwo-zig/typed-air/segment-v2-public-wire-boundary/v1\x00";

pub const Error = manifest_mod.Error || error{
    ArithmeticOverflow,
    CapabilityEscalation,
    ClaimMismatch,
    ClosureIdentityMismatch,
    CohortIdentityMismatch,
    ComponentCoverageMismatch,
    DomainOrderMismatch,
    GateIdentityMismatch,
    InvalidAuditGeometry,
    InvalidProviderSchedule,
    NonCanonicalField,
    ProductionReadinessUnavailable,
    PublicWireBoundaryMismatch,
    ProviderDomainMismatch,
    RelationNotClosed,
    RosterIdentityMismatch,
    SourceManifestMismatch,
    TreeAccountingMismatch,
    TreePlanIdentityMismatch,
};

pub const PublicWireBoundaryV2 = struct {
    format_version: u16 = PUBLIC_WIRE_BOUNDARY_FORMAT_VERSION,
    domain: relation.Domain = .recursion_wire,
    term_count: u32,
    source_authority_id: digest.Digest,
    claimed_sum: QM31,
    identity: digest.Digest,

    pub fn init(
        source_authority_id: digest.Digest,
        term_count: u32,
        claimed_sum: QM31,
    ) Error!PublicWireBoundaryV2 {
        var result = PublicWireBoundaryV2{
            .term_count = term_count,
            .source_authority_id = source_authority_id,
            .claimed_sum = claimed_sum,
            .identity = undefined,
        };
        result.identity = publicWireBoundaryIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const PublicWireBoundaryV2) Error!void {
        try requireCanonical(self.claimed_sum);
        if (self.format_version != PUBLIC_WIRE_BOUNDARY_FORMAT_VERSION or
            self.domain != .recursion_wire or self.term_count == 0 or
            allZero(&self.source_authority_id) or
            !std.mem.eql(
                u8,
                &self.identity,
                &publicWireBoundaryIdentity(self),
            ))
        {
            return error.PublicWireBoundaryMismatch;
        }
    }
};

pub fn publicWireBoundaryIdentity(
    boundary: *const PublicWireBoundaryV2,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PUBLIC_WIRE_BOUNDARY_ID_DOMAIN);
    hashInt(&hash, u16, boundary.format_version);
    hashInt(&hash, u8, @intFromEnum(boundary.domain));
    hashInt(&hash, u32, boundary.term_count);
    hash.update(&boundary.source_authority_id);
    hashQM31(&hash, boundary.claimed_sum);
    return hash.finalResult();
}

pub fn requireCanonical(value: QM31) Error!void {
    for (value.toM31Array()) |limb| {
        if (limb.toU32() >= stwo_core.fields.m31.Modulus)
            return error.NonCanonicalField;
    }
}

pub fn allZero(bytes: []const u8) bool {
    var aggregate: u8 = 0;
    for (bytes) |byte| aggregate |= byte;
    return aggregate == 0;
}

pub fn hashQM31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
