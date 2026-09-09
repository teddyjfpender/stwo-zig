//! Canonical process-local identities for the campaign empty cohort.
//!
//! These helpers are generic over the owning cohort structs so the identity
//! code remains acyclic. They do not mint admission: callers still validate
//! all live relations, boundaries, claims, and schedule ownership first.

const std = @import("std");
const stwo_core = @import("stwo_core");

const QM31 = stwo_core.fields.qm31.QM31;

const COHORT_IDENTITY_DOMAIN =
    "stwo-zig/common-canonical-empty-campaign-universal-cohort/v2\x00";
const GENERATED_IDENTITY_DOMAIN =
    "stwo-zig/common-canonical-empty-campaign-universal-interactions/v2\x00";
const AUDIT_IDENTITY_DOMAIN =
    "stwo-zig/common-canonical-empty-campaign-universal-audit/v2\x00";
const BOUNDARY_IDENTITY_DOMAIN =
    "stwo-zig/common-canonical-empty-campaign-universal-boundary/v2\x00";

pub fn generatedEql(left: anytype, right: anytype) bool {
    if (!std.meta.eql(left.format_version, right.format_version) or
        !std.meta.eql(left.schema_version, right.schema_version) or
        left.production_activation != right.production_activation or
        left.provider_closed != right.provider_closed or
        !std.mem.eql(u8, &left.manifest_seal, &right.manifest_seal) or
        !std.mem.eql(
            u8,
            &left.cohort_identity_sha256,
            &right.cohort_identity_sha256,
        ) or !std.mem.eql(
        u8,
        &left.relations_identity_sha256,
        &right.relations_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &left.provider_relations_identity_sha256,
        &right.provider_relations_identity_sha256,
    )) return false;
    inline for (.{
        .{ left.provider_claims.poseidon2, right.provider_claims.poseidon2 },
        .{
            left.provider_claims.poseidon2_io,
            right.provider_claims.poseidon2_io,
        },
        .{ left.public_request_claim, right.public_request_claim },
    }) |pair| if (!pair[0].eql(pair[1])) return false;
    for (left.claims, right.claims) |lhs, rhs|
        if (!lhs.eql(rhs)) return false;
    for (left.domain_totals, right.domain_totals) |lhs, rhs|
        if (!lhs.eql(rhs)) return false;
    return std.mem.eql(u8, &left.identity_sha256, &right.identity_sha256);
}

pub fn cohortIdentity(
    value: anytype,
    format_version: u16,
    schema_version: u16,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(COHORT_IDENTITY_DOMAIN);
    hashInt(&hash, u16, format_version);
    hashInt(&hash, u16, schema_version);
    hash.update(&value.manifest_value.seal);
    const words = value.schedule.node_public.canonicalAirWords() catch
        return [_]u8{0} ** 32;
    for (words) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

pub fn relationsIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/common-canonical-empty-relations/v2\x00");
    hash.update(&value.registry_order_digest);
    for (&value.elements) |element| {
        hashQm31(&hash, element.z);
        hashQm31(&hash, element.alpha);
    }
    return hash.finalResult();
}

pub fn generatedIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(GENERATED_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.provider_closed));
    hash.update(&value.manifest_seal);
    hash.update(&value.cohort_identity_sha256);
    hash.update(&value.relations_identity_sha256);
    hash.update(&value.provider_relations_identity_sha256);
    hashQm31(&hash, value.provider_claims.poseidon2);
    hashQm31(&hash, value.provider_claims.poseidon2_io);
    hashQm31(&hash, value.public_request_claim);
    for (value.claims) |claim| hashQm31(&hash, claim);
    for (value.domain_totals) |claim| hashQm31(&hash, claim);
    return hash.finalResult();
}

pub fn boundaryIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(BOUNDARY_IDENTITY_DOMAIN);
    hashInt(&hash, u8, @intFromEnum(value.domain));
    hashInt(&hash, u64, value.tuple_count);
    hashQm31(&hash, value.claimed_sum);
    return hash.finalResult();
}

pub fn auditIdentity(value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUDIT_IDENTITY_DOMAIN);
    hash.update(&value.wire_boundary.tuple_provenance_sha256);
    hash.update(&value.verifier_input_boundary.tuple_provenance_sha256);
    hash.update(&value.closure.closure_id);
    return hash.finalResult();
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
