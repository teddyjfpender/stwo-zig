const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const manifest_mod = recursion.air.segment_outer_adapter_manifest_v2;
const transcript_components = recursion.segment_transcript_outer_components_v2;
const statement_components = recursion.segment_statement_outer_components_v2;
const public_components = recursion.segment_public_outer_components_v2;
const range_authority = recursion.segment_range_authority_v2;
const boundary_components = recursion.air.segment_boundary_components_v2;
const input_provider_component = recursion.air.segment_publication_input_provider_component_v2;
const shared_provider = recursion.air.universal_shared_provider;
const universal = recursion.air.universal_challenges;
const relation_interaction = recursion.air.relation_interaction;
const noncore_audits = recursion.segment_outer_noncore_audits_v2;

const FORMAT_VERSION: u16 = 1;
const SCHEMA_VERSION: u16 = 1;
pub const OWNER_ID_DOMAIN =
    "stwo-zig/typed-air/recursive-segment-v2-noncore-owner/v1\x00";
pub const GENERATED_ID_DOMAIN =
    "stwo-zig/typed-air/recursive-segment-v2-noncore-generated/v1\x00";
const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
const OWNED_ROW_INDICES = noncore_audits.NONCORE_ROW_INDICES;
const OWNED_ROW_MASK: u64 = componentBit(0) | componentBit(1) | componentBit(2) |
    componentBit(3) | componentBit(4) | componentBit(5) | componentBit(6) |
    componentBit(7) | componentBit(8) | componentBit(9) | componentBit(10) |
    componentBit(11) | componentBit(12) | componentBit(13) | componentBit(14) |
    componentBit(15) | componentBit(16) | componentBit(17) | componentBit(35) |
    componentBit(36) | componentBit(37) | componentBit(38);
const DomainAudit = relation_interaction.DomainAudit;
const Manifest = manifest_mod.Manifest;

pub const GeneratedInteractionsV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    generation: u64,
    row_mask: u64 = OWNED_ROW_MASK,
    owner_identity: [32]u8,
    transcript: transcript_components.Claims,
    statement: statement_components.ClaimsV2,
    public: public_components.Claims,
    range: QM31,
    boundary: [2]QM31,
    verifier_input_provider: QM31,
    audits: noncore_audits.AuditsV2,
    identity: [32]u8,

    pub fn validate(self: *const GeneratedInteractionsV2) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or self.generation == 0 or
            self.row_mask != OWNED_ROW_MASK or allZero(&self.owner_identity))
        {
            return error.GeneratedIdentityMismatch;
        }
        try self.statement.validate();
        const expected_claims = self.claimsArray();
        for (OWNED_ROW_INDICES, self.audits.claims) |row, claim| {
            if (!expected_claims[row].eql(claim))
                return error.GeneratedIdentityMismatch;
        }
        if (!std.mem.eql(u8, &self.identity, &generatedIdentity(self)))
            return error.GeneratedIdentityMismatch;
    }

    pub fn validateAgainst(
        self: *const GeneratedInteractionsV2,
        owner: anytype,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        return self.validateCachedAgainst(owner, relations, provider_relations);
    }

    /// Allocation-free proof-path validation. Exact equality to the owner's
    /// internally generated receipt pins source custody; bounded receipt and
    /// challenge checks do not replay the 21 typed ledgers.
    pub fn validateCachedAgainst(
        self: *const GeneratedInteractionsV2,
        owner: anytype,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        try self.validate();
        try owner.validate();
        try provider_relations.validateAgainst(relations);
        if (owner.generation != self.generation or
            !std.mem.eql(u8, &owner.identity, &self.owner_identity) or
            owner.active_generated == null or
            !std.meta.eql(owner.active_generated.?, self.*))
        {
            return error.InteractionGenerationMismatch;
        }
        try self.audits.validateAgainst(&owner.manifest, relations);
    }

    /// Explicit cold diagnostic: independently replays every authenticated
    /// non-core source and compares the reconstructed audit receipt.
    pub fn validateAgainstInputs(
        self: *const GeneratedInteractionsV2,
        audit_allocator: std.mem.Allocator,
        owner: anytype,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        try self.validateCachedAgainst(owner, relations, provider_relations);
        try noncore_audits.validateAgainstInputs(
            &self.audits,
            audit_allocator,
            try owner.activeAuditInputs(relations, provider_relations, self),
        );
    }

    pub fn bindClaimsInto(
        self: *const GeneratedInteractionsV2,
        vector: *manifest_mod.ClaimVector,
    ) !void {
        try self.validate();
        try self.transcript.bindInto(vector);
        try self.statement.bindInto(vector);
        try self.public.bindInto(vector);
        try vector.bind(.range_check_8_8, self.range);
        try vector.bind(.statement_source_v2, self.boundary[0]);
        try vector.bind(.public_logup_source_v2, self.boundary[1]);
        try vector.bind(
            .segment_publication_input_provider_v2,
            self.verifier_input_provider,
        );
    }

    /// Fail-atomic installation. The receipt identity and every claim/audit
    /// correspondence are checked before either destination is modified.
    pub fn installClaimsAndAudits(
        self: *const GeneratedInteractionsV2,
        destination_claims: *[COMPONENT_COUNT]QM31,
        destination_audits: *[COMPONENT_COUNT]DomainAudit,
        occupied_mask: *u64,
    ) !void {
        try self.validate();
        if (occupied_mask.* & OWNED_ROW_MASK != 0)
            return error.OccupiedRowOverlap;
        const self_bytes = std.mem.asBytes(self);
        const claims_bytes = std.mem.asBytes(destination_claims);
        const audits_bytes = std.mem.asBytes(destination_audits);
        const mask_bytes = std.mem.asBytes(occupied_mask);
        if (overlap(self_bytes, claims_bytes) or
            overlap(self_bytes, audits_bytes) or overlap(self_bytes, mask_bytes) or
            overlap(claims_bytes, audits_bytes) or overlap(claims_bytes, mask_bytes) or
            overlap(audits_bytes, mask_bytes))
        {
            return error.AliasedDestination;
        }
        const claims = self.claimsArray();
        for (OWNED_ROW_INDICES, self.audits.rows) |row, audit| {
            destination_claims[row] = claims[row];
            destination_audits[row] = audit;
        }
        occupied_mask.* |= OWNED_ROW_MASK;
    }

    pub fn claimsArray(self: *const GeneratedInteractionsV2) [COMPONENT_COUNT]QM31 {
        var result = [_]QM31{QM31.zero()} ** COMPONENT_COUNT;
        for (self.transcript.asArray(), 0..) |claim, row| result[row] = claim;
        for (self.statement.asArray(), 0..) |claim, index| result[10 + index] = claim;
        for (self.public.asArray(), 0..) |claim, index| result[12 + index] = claim;
        result[35] = self.range;
        result[36] = self.boundary[0];
        result[37] = self.boundary[1];
        result[38] = self.verifier_input_provider;
        return result;
    }
};

pub const Components = struct {
    transcript: transcript_components.Components,
    statement: statement_components.ComponentsV2,
    public: public_components.Components,
    range: range_authority.AdapterV2,
    boundary: boundary_components.Components,
    verifier_input_provider: input_provider_component.AdapterForManifest(manifest_mod),

    pub fn appendRows0Through17ToGate(
        self: *const Components,
        manifest: *const Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        try self.transcript.appendToGate(manifest, gate);
        try self.statement.appendToGate(manifest, gate);
        try self.public.appendToGate(manifest, gate);
    }

    pub fn appendRows35Through38ToGate(
        self: *const Components,
        manifest: *const Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        try gate.append(manifest, try self.range.binding(manifest));
        try self.boundary.appendToGate(manifest, gate);
        try gate.append(
            manifest,
            try self.verifier_input_provider.binding(manifest),
        );
    }

    pub fn deinit(self: *Components) void {
        self.* = undefined;
    }
};

pub fn generatedIdentity(value: *const GeneratedInteractionsV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(GENERATED_ID_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u64, value.generation);
    hashInt(&hash, u64, value.row_mask);
    hash.update(&value.owner_identity);
    for (value.claimsArray()) |claim| hashQM31(&hash, claim);
    hash.update(&value.audits.identity);
    return hash.finalResult();
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

fn allZero(bytes: []const u8) bool {
    var aggregate: u8 = 0;
    for (bytes) |byte| aggregate |= byte;
    return aggregate == 0;
}

fn hashQM31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn componentBit(index: anytype) u64 {
    return @as(u64, 1) << @intCast(index);
}
