//! Verifier-owned SegmentV2 VM-AIR instance authority.
//!
//! ProfileV2 contains the cold-reconstructible public AIR schedule. ContextV2
//! adds only proof-instance values: selected detailed claims, the canonical 28
//! transcript aggregates, relation draws, and exact public/receipt/capture
//! custody. SHA-256 is a transport seal; recursive AIR consumes the retained
//! field values and the validated ProfileV2, never the SHA digest alone.

const std = @import("std");
const stwo_core = @import("stwo_core");
const core_components = stwo_core.air.components;
const m31 = stwo_core.fields.m31;
const QM31 = stwo_core.fields.qm31.QM31;

const component_order = @import("../air/component_order.zig");
const lookup_physical_v2 =
    @import("../air/lang/lookup_physical_manifest_v2.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const statement = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const transcript_claims = @import("../air/transcript/claims.zig");
const proof_capture_sha256 = @import("../prover/proof_capture_sha256.zig");
const profile_v2 = @import("vm_air_profile_v2.zig");
const base_geometry_v2 = @import("vm_composition_base_geometry_v2.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA_VERSION: u16 = 2;
pub const CONTEXT_DOMAIN =
    "stwo-zig/riscv/recursion/vm-leaf-context/v2\x00";
pub const Digest = [8]u32;

pub const Error = std.mem.Allocator.Error || profile_v2.Error || error{
    ContextDigestMismatch,
    InvalidCaptureAuthority,
    InvalidContextCounts,
    InvalidContextDescriptor,
    InvalidPublicAuthority,
    InvalidRelationDraw,
};

pub const CaptureAuthority = struct {
    full_sampled_value_count: u32,
    sha256: [32]u8,

    pub fn init(capture: anytype) Error!CaptureAuthority {
        const count = std.math.cast(u32, capture.sampled_values.len) orelse
            return error.InvalidCaptureAuthority;
        const result = CaptureAuthority{
            .full_sampled_value_count = count,
            .sha256 = proof_capture_sha256.compute(capture),
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: CaptureAuthority) Error!void {
        if (self.full_sampled_value_count == 0 or allZeroBytes(&self.sha256))
            return error.InvalidCaptureAuthority;
    }
};

pub const ContextV2 = struct {
    allocator: std.mem.Allocator,
    schema_version: u16 = SCHEMA_VERSION,
    profile: profile_v2.ProfileV2,
    component_descs: []statement.FamilyComponentDesc,
    infra_descs: []statement.InfraComponentDesc,
    detailed_claims: []QM31,
    canonical_claims: [transcript_claims.COMPONENT_COUNT]QM31,
    relation_draws: [relation_challenges.DRAW_COUNT]QM31,
    statement_authority_id: Digest,
    public_wire_id: Digest,
    verified_receipt_identity: Digest,
    native_public_sums_identity: Digest,
    /// Exact OODS values consumed by the authenticated base VM profile.
    base_sampled_value_count: u32,
    /// Exact flattened OODS values retained from the complete verified proof.
    /// For Ethereum SegmentV3 this includes the base plus all fourteen
    /// extension components; it must never size the base-only ProfileV2.
    full_proof_capture_sampled_value_count: u32,
    proof_capture_sha256: [32]u8,
    identity_digest: [32]u8,

    pub fn initVerified(
        allocator: std.mem.Allocator,
        native: *const statement_v2.RiscVStatementV2,
        claim: *const statement.RiscVInteractionClaim,
        relations: *const relation_challenges.Relations,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated: *const lookup_physical_v2.AuthenticatedStatement,
        components: []const core_components.Component,
        proof_capture: anytype,
        receipt: *const statement_v2.VerifiedReceipt,
        native_public_sums: *const statement_v2.NativePublicSums,
    ) !ContextV2 {
        const capture_authority = try CaptureAuthority.init(proof_capture);
        const base_sampled_value_count =
            try base_geometry_v2.expectedSampledValueCount(
                &native.core,
                manifest,
            );
        const profile = try profile_v2.derive(
            allocator,
            &native.core,
            manifest,
            authenticated,
            components,
            base_sampled_value_count,
        );
        return initWithProfile(
            allocator,
            native,
            claim,
            relations,
            manifest,
            authenticated,
            profile,
            base_sampled_value_count,
            capture_authority,
            receipt,
            native_public_sums,
        );
    }

    fn initWithProfile(
        allocator: std.mem.Allocator,
        native: *const statement_v2.RiscVStatementV2,
        claim: *const statement.RiscVInteractionClaim,
        relations: *const relation_challenges.Relations,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated: *const lookup_physical_v2.AuthenticatedStatement,
        profile_source: profile_v2.ProfileV2,
        base_sampled_value_count: u32,
        capture_authority: CaptureAuthority,
        receipt: *const statement_v2.VerifiedReceipt,
        native_public_sums: *const statement_v2.NativePublicSums,
    ) !ContextV2 {
        var profile = profile_source;
        errdefer profile.deinit();
        try native.validate();
        try authenticated.validateAgainst(&native.core, manifest);
        try profile.validateAuthority(
            allocator,
            &native.core,
            manifest,
            authenticated,
        );
        try capture_authority.validate();
        const expected_base_sampled_value_count =
            try base_geometry_v2.expectedSampledValueCount(
                &native.core,
                manifest,
            );
        if (base_sampled_value_count != expected_base_sampled_value_count or
            base_sampled_value_count !=
                profile.input_profile.sampled_value_count or
            capture_authority.full_sampled_value_count <
                base_sampled_value_count)
        {
            return error.InvalidCaptureAuthority;
        }
        try receipt.validateAgainst(&native.public_data);
        try native_public_sums.validateAgainst(&native.public_data, relations);
        if (!std.meta.eql(receipt.authority_id, native.authority_id))
            return error.InvalidPublicAuthority;

        const component_descs = try allocator.dupe(
            statement.FamilyComponentDesc,
            native.core.component_descs[0..native.core.n_components],
        );
        errdefer allocator.free(component_descs);
        const infra_descs = try allocator.dupe(
            statement.InfraComponentDesc,
            native.core.infra_descs[0..native.core.n_infra],
        );
        errdefer allocator.free(infra_descs);
        const detailed_claims = try allocator.alloc(
            QM31,
            profile.input_profile.claimed_sum_count,
        );
        errdefer allocator.free(detailed_claims);
        try writeSelectedDetailedClaims(
            &native.core,
            manifest,
            authenticated,
            claim,
            detailed_claims,
        );
        const canonical = try authenticated.canonicalInteractionClaim(
            &native.core,
            manifest,
            claim,
        );
        const derived = try deriveCanonicalClaims(&profile, detailed_claims);
        if (!qm31ArraysEqual(&canonical.claimed_sums, &derived))
            return error.InvalidContextCounts;

        var relation_draws: [relation_challenges.DRAW_COUNT]QM31 = undefined;
        try relations.writeDraws(&relation_draws);
        var result = ContextV2{
            .allocator = allocator,
            .profile = profile,
            .component_descs = component_descs,
            .infra_descs = infra_descs,
            .detailed_claims = detailed_claims,
            .canonical_claims = canonical.claimed_sums,
            .relation_draws = relation_draws,
            .statement_authority_id = native.authority_id,
            .public_wire_id = native.public_data.wireId(),
            .verified_receipt_identity = receipt.identity,
            .native_public_sums_identity = native_public_sums.identity,
            .base_sampled_value_count = base_sampled_value_count,
            .full_proof_capture_sampled_value_count = capture_authority.full_sampled_value_count,
            .proof_capture_sha256 = capture_authority.sha256,
            .identity_digest = undefined,
        };
        try result.validateShape();
        result.identity_digest = result.computeIdentityDigest();
        return result;
    }

    pub fn deinit(self: *ContextV2) void {
        self.allocator.free(self.detailed_claims);
        self.allocator.free(self.infra_descs);
        self.allocator.free(self.component_descs);
        self.profile.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const ContextV2) Error!void {
        try self.validateShape();
        const expected = self.computeIdentityDigest();
        if (!std.mem.eql(u8, &expected, &self.identity_digest))
            return error.ContextDigestMismatch;
    }

    /// Reopens every retained authority without requiring the destroyed
    /// verifier assembly. ProfileV2 reconstructs the closed component facts;
    /// the proof capture digest is recomputed from the owned capture itself.
    pub fn validateCaptureAuthorities(
        self: *const ContextV2,
        public_data: *const statement_v2.OwnedPublicDataV2,
        receipt: *const statement_v2.VerifiedReceipt,
        native_public_sums: *const statement_v2.NativePublicSums,
        proof_capture: anytype,
    ) !void {
        const capture_authority = try CaptureAuthority.init(proof_capture);
        return self.validateAuthorityValues(
            public_data,
            receipt,
            native_public_sums,
            capture_authority,
        );
    }

    pub fn validateAuthorityValues(
        self: *const ContextV2,
        public_data: *const statement_v2.OwnedPublicDataV2,
        receipt: *const statement_v2.VerifiedReceipt,
        native_public_sums: *const statement_v2.NativePublicSums,
        capture_authority: CaptureAuthority,
    ) !void {
        try self.validate();
        try public_data.validate();
        const native = try self.reconstructStatement(&public_data.data);
        var manifest = lookup_physical_v2.Manifest.native();
        const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
            &native.core,
            &manifest,
        );
        try self.profile.validateAuthority(
            self.allocator,
            &native.core,
            &manifest,
            &authenticated,
        );
        const expected_base_sampled_value_count =
            try base_geometry_v2.expectedSampledValueCount(
                &native.core,
                &manifest,
            );
        try receipt.validateAgainst(&public_data.data);
        const relations = relation_challenges.Relations.fromDrawSequence(
            &self.relation_draws,
        );
        try native_public_sums.validateAgainst(&public_data.data, &relations);
        try capture_authority.validate();
        if (!std.meta.eql(native.authority_id, self.statement_authority_id) or
            !std.meta.eql(public_data.data.wireId(), self.public_wire_id) or
            !std.meta.eql(receipt.authority_id, self.statement_authority_id) or
            !std.meta.eql(receipt.identity, self.verified_receipt_identity) or
            !std.meta.eql(
                native_public_sums.identity,
                self.native_public_sums_identity,
            ) or
            self.base_sampled_value_count !=
                expected_base_sampled_value_count or
            self.base_sampled_value_count !=
                self.profile.input_profile.sampled_value_count or
            capture_authority.full_sampled_value_count !=
                self.full_proof_capture_sampled_value_count or
            !std.mem.eql(
                u8,
                &capture_authority.sha256,
                &self.proof_capture_sha256,
            ))
        {
            return error.InvalidPublicAuthority;
        }
    }

    pub fn reconstructStatement(
        self: *const ContextV2,
        public_data: *const @import("../air/public_data_v2.zig").PublicDataV2,
    ) !statement_v2.RiscVStatementV2 {
        try self.validate();
        const projected = try statement_v2.canonicalCorePublicData(public_data);
        var component_descs: [statement.MAX_COMPONENTS]statement.FamilyComponentDesc =
            undefined;
        @memcpy(component_descs[0..self.component_descs.len], self.component_descs);
        var infra_descs: [statement.MAX_INFRA_COMPONENTS]statement.InfraComponentDesc =
            undefined;
        @memcpy(infra_descs[0..self.infra_descs.len], self.infra_descs);
        const core = statement.RiscVStatement{
            .n_components = @intCast(self.component_descs.len),
            .component_descs = component_descs,
            .initial_pc = projected.initial_pc,
            .final_pc = projected.final_pc,
            .total_steps = projected.clock,
            .public_data = projected,
            .n_infra = @intCast(self.infra_descs.len),
            .infra_descs = infra_descs,
        };
        return statement_v2.RiscVStatementV2.init(core, public_data.*);
    }

    fn validateShape(self: *const ContextV2) Error!void {
        if (self.schema_version != SCHEMA_VERSION or
            self.component_descs.len == 0 or
            self.component_descs.len > statement.MAX_COMPONENTS or
            self.infra_descs.len == 0 or
            self.infra_descs.len > statement.MAX_INFRA_COMPONENTS or
            @as(usize, self.profile.physical_component_count) !=
                2 * self.component_descs.len + self.infra_descs.len or
            self.detailed_claims.len !=
                @as(usize, self.profile.input_profile.claimed_sum_count) or
            self.base_sampled_value_count == 0 or
            self.base_sampled_value_count !=
                self.profile.input_profile.sampled_value_count or
            self.full_proof_capture_sampled_value_count <
                self.base_sampled_value_count)
        {
            return error.InvalidContextCounts;
        }
        try self.profile.validate();
        for (self.detailed_claims) |value| try validateQm31(value);
        const expected = try deriveCanonicalClaims(
            &self.profile,
            self.detailed_claims,
        );
        for (self.canonical_claims, expected) |actual, wanted| {
            try validateQm31(actual);
            if (!actual.eql(wanted)) return error.ContextDigestMismatch;
        }
        for (self.relation_draws) |value| try validateQm31(value);
        if (allZeroDigest(self.statement_authority_id) or
            allZeroDigest(self.public_wire_id) or
            allZeroDigest(self.verified_receipt_identity) or
            allZeroDigest(self.native_public_sums_identity) or
            allZeroBytes(&self.proof_capture_sha256))
        {
            return error.InvalidPublicAuthority;
        }
    }

    fn computeIdentityDigest(self: *const ContextV2) [32]u8 {
        var hash = Sha256.init(.{});
        hash.update(CONTEXT_DOMAIN);
        hashInt(&hash, u16, self.schema_version);
        hash.update(&self.profile.identity_digest);
        hashDescriptors(&hash, self.component_descs, self.infra_descs);
        hashQm31Slice(&hash, self.detailed_claims);
        hashQm31Slice(&hash, &self.canonical_claims);
        hashQm31Slice(&hash, &self.relation_draws);
        hashDigest(&hash, self.statement_authority_id);
        hashDigest(&hash, self.public_wire_id);
        hashDigest(&hash, self.verified_receipt_identity);
        hashDigest(&hash, self.native_public_sums_identity);
        hashInt(&hash, u32, self.base_sampled_value_count);
        hashInt(
            &hash,
            u32,
            self.full_proof_capture_sampled_value_count,
        );
        hash.update(&self.proof_capture_sha256);
        return hash.finalResult();
    }
};

fn writeSelectedDetailedClaims(
    core: *const statement.RiscVStatement,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    claim: *const statement.RiscVInteractionClaim,
    destination: []QM31,
) !void {
    _ = try authenticated.canonicalInteractionClaim(core, manifest, claim);
    var expected_count: usize = authenticated.detailed_claim_count;
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        expected_count = std.math.add(
            usize,
            expected_count,
            statement.nClaimedSumsForInfra(descriptor.kind),
        ) catch return error.InvalidContextCounts;
    }
    if (destination.len != expected_count)
        return error.InvalidContextCounts;
    var cursor: usize = 0;
    for (core.component_descs[0..core.n_components], 0..) |descriptor, index| {
        const count = manifest.entryForFamily(descriptor.family)
            .detailed_claim_count;
        const values = try claim.opcodeClaims(descriptor.family, index);
        const selected: usize = count;
        @memcpy(destination[cursor..][0..selected], values[0..selected]);
        cursor += selected;
    }
    for (core.infra_descs[0..core.n_infra], 0..) |descriptor, index| {
        const values = try claim.infraClaims(descriptor.kind, index);
        @memcpy(destination[cursor..][0..values.len], values);
        cursor += values.len;
    }
    if (cursor != destination.len) return error.InvalidContextCounts;
}

fn deriveCanonicalClaims(
    profile: *const profile_v2.ProfileV2,
    detailed_claims: []const QM31,
) Error![transcript_claims.COMPONENT_COUNT]QM31 {
    var result = [_]QM31{QM31.zero()} ** transcript_claims.COMPONENT_COUNT;
    for (profile.entries) |entry| switch (entry.registry) {
        .opcode_semantic => {},
        .opcode_lookup => |key| try addClaimSpan(
            &result[
                @intFromEnum(
                    component_order.transcriptComponentForOpcodeFamily(key.family),
                )
            ],
            detailed_claims,
            entry.claimed_sum_offset,
            entry.claimed_sum_count,
        ),
        .infrastructure => |key| try addClaimSpan(
            &result[@intFromEnum(transcriptComponentForInfra(key.kind))],
            detailed_claims,
            entry.claimed_sum_offset,
            entry.claimed_sum_count,
        ),
    };
    return result;
}

fn addClaimSpan(
    destination: *QM31,
    claims: []const QM31,
    offset: u32,
    count: u32,
) Error!void {
    const start: usize = offset;
    const end = std.math.add(usize, start, @as(usize, count)) catch
        return error.InvalidContextCounts;
    if (end > claims.len) return error.InvalidContextCounts;
    for (claims[start..end]) |claim| destination.* = destination.add(claim);
}

fn transcriptComponentForInfra(
    kind: statement.InfraKind,
) transcript_claims.Component {
    return switch (kind) {
        .program => .program,
        .memory => .memory,
        .merkle => .merkle,
        .poseidon2 => .poseidon2,
        .clock_update => .clock_update,
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
    };
}

fn hashDescriptors(
    hash: *Sha256,
    components: []const statement.FamilyComponentDesc,
    infrastructure: []const statement.InfraComponentDesc,
) void {
    hashInt(hash, u32, components.len);
    for (components) |descriptor| {
        hashInt(hash, u8, @intFromEnum(descriptor.family));
        hashInt(hash, u32, descriptor.log_size);
        hashInt(hash, u32, descriptor.n_rows);
        hashInt(hash, u32, descriptor.n_columns);
    }
    hashInt(hash, u32, infrastructure.len);
    for (infrastructure) |descriptor| {
        hashInt(hash, u32, @intFromEnum(descriptor.kind));
        hashInt(hash, u32, descriptor.log_size);
        hashInt(hash, u32, descriptor.n_rows);
        hashInt(hash, u32, descriptor.n_columns);
    }
}

fn hashQm31Slice(hash: *Sha256, values: []const QM31) void {
    hashInt(hash, u32, values.len);
    for (values) |value| {
        for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
    }
}

fn hashDigest(hash: *Sha256, value: Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn validateQm31(value: QM31) Error!void {
    for (value.toM31Array()) |limb| {
        if (limb.toU32() >= m31.Modulus) return error.InvalidRelationDraw;
    }
}

fn qm31ArraysEqual(lhs: anytype, rhs: anytype) bool {
    for (lhs.*, rhs.*) |left, right| if (!left.eql(right)) return false;
    return true;
}

fn allZeroDigest(value: Digest) bool {
    var aggregate: u32 = 0;
    for (value) |word| aggregate |= word;
    return aggregate == 0;
}

fn allZeroBytes(value: []const u8) bool {
    var aggregate: u8 = 0;
    for (value) |byte| aggregate |= byte;
    return aggregate == 0;
}

pub const testing = struct {
    pub fn initFromFacts(
        allocator: std.mem.Allocator,
        native: *const statement_v2.RiscVStatementV2,
        claim: *const statement.RiscVInteractionClaim,
        relations: *const relation_challenges.Relations,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated: *const lookup_physical_v2.AuthenticatedStatement,
        facts: []const profile_v2.Facts,
        capture_authority: CaptureAuthority,
        receipt: *const statement_v2.VerifiedReceipt,
        native_public_sums: *const statement_v2.NativePublicSums,
    ) !ContextV2 {
        const base_sampled_value_count =
            try base_geometry_v2.expectedSampledValueCount(
                &native.core,
                manifest,
            );
        const profile = try profile_v2.testing.deriveFromFacts(
            allocator,
            &native.core,
            manifest,
            authenticated,
            facts,
            base_sampled_value_count,
        );
        return ContextV2.initWithProfile(
            allocator,
            native,
            claim,
            relations,
            manifest,
            authenticated,
            profile,
            base_sampled_value_count,
            capture_authority,
            receipt,
            native_public_sums,
        );
    }
};
