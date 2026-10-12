//! Direct native V3 row-39/40 witness, without a separate outer proof.
//!
//! This prepares the corrected schedule from one verified native SegmentV2
//! capture, local metadata/link, and its native program/root. It checks the
//! exact LAS2 public authority and verifier-input multiplicities. The final
//! wrapper AIR must still bind program words and root to the base verifier;
//! host-side agreement here cannot activate production proof acceptance.

const std = @import("std");
const core = @import("stwo_core");
const program_mod = @import("ethereum_leaf_link_program_v3.zig");
const authority_mod = @import("ethereum_leaf_direct_public_authority_v3.zig");
const shared = @import("segment_leaf_wrapper_source_projection_v3.zig");
const field_witness = @import("segment_leaf_wrapper_field_witness_v3.zig");
const metadata_mod = @import("segment_leaf_local_authority_v3.zig");
const link_mod = @import("segment_leaf_local_verified_link_v3.zig");
const source_air = @import("air/ethereum_leaf_link_source_v1.zig");

const M31 = core.fields.m31.M31;
const Digest = authority_mod.Digest;

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const WitnessV3 = shared.WitnessV3;

pub fn initFromNative(
    allocator: std.mem.Allocator,
    program: *const program_mod.ProgramV3,
    prepared: anytype,
    metadata: *const metadata_mod.MetadataV3,
    link: *const link_mod.VerifiedLinkV3,
    native: *const field_witness.NativeV1,
) !WitnessV3 {
    try prepared.validate();
    try program.validate();
    try native.validateAgainst(prepared);
    try link.validateAgainst(metadata, &prepared.capture.public_data.data, &prepared.capture.receipt);
    const claims = prepared.capture.vm_air.canonical_claims;
    if (claims.len != program_mod.TRANSCRIPT_CLAIM_COUNT)
        return error.InvalidDirectLeafSource;
    var transcript_claims: [program_mod.TRANSCRIPT_CLAIM_COUNT][4]M31 = undefined;
    for (claims, 0..) |claim, index| transcript_claims[index] = .{
        claim.c0.a, claim.c0.b, claim.c1.a, claim.c1.b,
    };
    const authority = try authority_mod.AuthorityV1.fromDigests(
        link.identity,
        native.program.digest,
        native.tree0_root,
    );
    const zero_digest: Digest = .{0} ** authority_mod.DIGEST_WORD_COUNT;
    const sources = shared.Sources{
        .metadata = try metadata.identityWords(),
        .link = try link.identityWords(),
        .metadata_digest = try canonicalDigest(try metadata.identity()),
        .link_digest = try canonicalDigest(link.identity),
        .local_authority = try canonicalDigest(prepared.capture.receipt.authority_id),
        .local_wire = try canonicalDigest(prepared.capture.receipt.wire_id),
        .local_receipt = try canonicalDigest(prepared.capture.receipt.identity),
        .fields = .{
            .program = try canonicalDigest(native.program.digest),
            .preprocessed_root = try canonicalDigest(native.tree0_root),
            .provider_digest = zero_digest,
        },
        .transcript_claims = transcript_claims,
        .local_statement = prepared.capture.public_data.data.words(),
    };
    var witness = try shared.buildWithSources(allocator, program, &sources, false);
    errdefer witness.deinit();
    try checkDirectVerifierMultiplicity(program);
    try authority_mod.validateProjectionSchedule(program.projection_rows);
    const public_start = program.projection_rows.len - authority_mod.WORD_COUNT;
    for (witness.projection_values[public_start..], authority.words) |actual, expected|
        if (actual.toU32() != expected) return error.DirectLeafPublicAuthorityMismatch;
    return witness;
}

fn canonicalDigest(value: Digest) !Digest {
    for (value) |word| if (word >= core.fields.m31.Modulus)
        return error.InvalidDirectLeafVerifierCoordinate;
    return value;
}

/// PRG1 is consumed once by row 40 and once by native ProgramV2 hash row 43.
/// PPR1 is consumed by row 40 and the versioned direct Tree0 AIR bridge.
fn checkDirectVerifierMultiplicity(program: *const program_mod.ProgramV3) !void {
    var program_source = [_]u32{0} ** authority_mod.DIGEST_WORD_COUNT;
    var root_source = [_]u32{0} ** authority_mod.DIGEST_WORD_COUNT;
    var program_projection = [_]u32{0} ** authority_mod.DIGEST_WORD_COUNT;
    var root_projection = [_]u32{0} ** authority_mod.DIGEST_WORD_COUNT;
    for (program.source_rows) |row| {
        const count: *[authority_mod.DIGEST_WORD_COUNT]u32 = switch (row.kind) {
            source_air.PROGRAM_AUTHORITY_KIND => &program_source,
            source_air.PREPROCESSED_ROOT_KIND => &root_source,
            else => continue,
        };
        const expected_use: u32 = 2;
        if (row.active != 1 or row.verifier_mask != 1 or row.index_0 != 0 or
            row.index_1 >= count.len or row.use_count != expected_use)
            return error.DirectLeafVerifierMultiplicityMismatch;
        count[row.index_1] += 1;
    }
    for (program.projection_rows) |row| {
        const count: *[authority_mod.DIGEST_WORD_COUNT]u32 = switch (row.verifier_kind) {
            source_air.PROGRAM_AUTHORITY_KIND => &program_projection,
            source_air.PREPROCESSED_ROOT_KIND => &root_projection,
            else => continue,
        };
        if (row.active != 1 or row.verifier_mask != 1 or row.verifier_index_0 != 0 or
            row.verifier_index_1 >= count.len)
            return error.DirectLeafVerifierMultiplicityMismatch;
        count[row.verifier_index_1] += 1;
    }
    for (0..authority_mod.DIGEST_WORD_COUNT) |limb| {
        if (program_source[limb] != 1 or root_source[limb] != 1 or
            program_projection[limb] != 1 or root_projection[limb] != 1)
            return error.DirectLeafVerifierMultiplicityMismatch;
    }
}

test "direct row 39 verifier emitters have exact distinct consumers" {
    var program = try program_mod.ProgramV3.init(std.testing.allocator);
    defer program.deinit();
    try checkDirectVerifierMultiplicity(&program);
    const first = program.source_rows.len - 2 * authority_mod.DIGEST_WORD_COUNT;
    program.source_rows[first].use_count = 1;
    try std.testing.expectError(error.DirectLeafVerifierMultiplicityMismatch, checkDirectVerifierMultiplicity(&program));
    program.source_rows[first].use_count = 2;
    program.source_rows[first + authority_mod.DIGEST_WORD_COUNT].active = 0;
    try std.testing.expectError(error.DirectLeafVerifierMultiplicityMismatch, checkDirectVerifierMultiplicity(&program));
    program.source_rows[first + authority_mod.DIGEST_WORD_COUNT].active = 1;
    program.source_rows[first + authority_mod.DIGEST_WORD_COUNT].use_count = 1;
    try std.testing.expectError(error.DirectLeafVerifierMultiplicityMismatch, checkDirectVerifierMultiplicity(&program));
    program.source_rows[first + authority_mod.DIGEST_WORD_COUNT].use_count = 2;
    program.projection_rows[program.projection_rows.len - 1].verifier_kind = source_air.PROGRAM_AUTHORITY_KIND;
    try std.testing.expectError(error.DirectLeafVerifierMultiplicityMismatch, checkDirectVerifierMultiplicity(&program));
}
