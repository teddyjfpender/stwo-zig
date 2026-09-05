//! Verifier-reconstructible algebraic closure for the schema-3 role-0 cohort.
//!
//! All 36 row claims are decomposed by their authenticated relation plans.
//! The only non-row term is the native arithmetic graph's typed public-wire
//! boundary, derived from that same retained lowering authority.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const prefix_components =
    @import("recursive_common_ethereum_incremental_leaf_transcript_components_v4.zig");
const suffix_components =
    @import("recursive_common_ethereum_incremental_leaf_suffix_components_v4.zig");
const range_provider =
    @import("recursive_common_ethereum_incremental_leaf_range_provider_v4.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const air = frontend.recursion.air;
const relation_interaction = air.relation_interaction;
const universal = air.universal_challenges;
const RelationDomain = @FieldType(
    relation_interaction.TupleContribution,
    "domain",
);

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const DOMAIN_COUNT: usize = universal.RELATION_COUNT;
pub const PUBLIC_WIRE_DOMAIN: RelationDomain = .recursion_wire;
pub const COMPLETE_36_CLAIM_CLOSURE_AVAILABLE = true;
pub const DETACHED_BOUNDARY_ADMITTED = false;
pub const PRODUCTION_ACTIVATION = false;

const BOUNDARY_IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-wire-boundary/v4-schema3\x00";
const CLOSURE_IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-closure/v4-schema3\x00";

pub const Error = error{
    EthereumIncrementalClosureMismatchV4,
    EthereumIncrementalRelationNotClosedV4,
};

pub const PublicWireBoundaryV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    domain: RelationDomain = PUBLIC_WIRE_DOMAIN,
    term_count: u32,
    source_authority_identity_sha256: [32]u8,
    claimed_sum: QM31,
    identity_sha256: [32]u8,

    pub fn derive(native: anytype, relations: *const universal.UniversalRelations) !PublicWireBoundaryV4 {
        var result = PublicWireBoundaryV4{
            .term_count = try native.publicWireBoundaryTermCount(),
            .source_authority_identity_sha256 = try native.authorityIdentity(),
            .claimed_sum = try native.publicWireBoundaryClaim(relations),
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = boundaryIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const PublicWireBoundaryV4) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.domain != PUBLIC_WIRE_DOMAIN or self.term_count == 0 or
            std.mem.allEqual(u8, &self.source_authority_identity_sha256, 0) or
            !secureCanonical(self.claimed_sum) or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &boundaryIdentity(self),
            ))
        {
            return error.EthereumIncrementalClosureMismatchV4;
        }
    }
};

pub const ReceiptV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    manifest_seal: [32]u8,
    public_wire: PublicWireBoundaryV4,
    domain_totals: [DOMAIN_COUNT]QM31,
    framework_total: QM31,
    active_domain_mask: u64,
    logical_rows: u64,
    event_terms: u64,
    identity_sha256: [32]u8,

    pub fn validate(self: *const ReceiptV4) Error!void {
        try self.public_wire.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            std.mem.allEqual(u8, &self.manifest_seal, 0) or
            self.active_domain_mask == 0 or self.logical_rows == 0 or
            self.event_terms == 0 or !self.framework_total.isZero() or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &closureIdentity(self),
            ))
        {
            return error.EthereumIncrementalClosureMismatchV4;
        }
        for (self.domain_totals) |total| {
            if (!secureCanonical(total) or !total.isZero())
                return error.EthereumIncrementalRelationNotClosedV4;
        }
    }
};

/// Cold, exact claim decomposition. `native_generated.audits` are already
/// verifier-owned; every remaining audit is rebuilt from retained typed rows.
pub fn auditAndClose(
    manifest: *const manifest_mod.Manifest,
    claims: *const manifest_mod.ClaimVector,
    prefix: anytype,
    prefix_claims: prefix_components.ClaimsV4,
    suffix: anytype,
    suffix_claims: suffix_components.ClaimsV4,
    native: anytype,
    native_generated: anytype,
    range: *const range_provider.OwnerV4,
    range_generated: range_provider.GeneratedV4,
    relations: *const universal.UniversalRelations,
) !ReceiptV4 {
    try manifest.validate();
    try claims.validate(manifest);
    try relations.validate();
    const prefix_audits = try prefix.auditClaims(relations, prefix_claims);
    const suffix_audits = try suffix.auditClaims(relations, suffix_claims);
    const range_audit = try range.auditGenerated(relations, range_generated);
    var audits: [COMPONENT_COUNT]relation_interaction.DomainAudit = undefined;
    @memcpy(audits[0..prefix_audits.len], &prefix_audits);
    @memcpy(
        audits[prefix_audits.len..][0..suffix_audits.len],
        &suffix_audits,
    );
    @memcpy(audits[18..35], &native_generated.audits);
    audits[35] = range_audit;

    const public_wire = try PublicWireBoundaryV4.derive(native, relations);
    var domain_totals = [_]QM31{QM31.zero()} ** DOMAIN_COUNT;
    var framework_total = QM31.zero();
    var active_domain_mask: u64 = 0;
    var logical_rows: u64 = 0;
    var event_terms: u64 = 0;
    for (audits, claims.values, 0..) |audit, claim, row| {
        try validateAudit(audit, claim);
        logical_rows = std.math.add(u64, logical_rows, audit.logical_rows) catch
            return error.ArithmeticOverflow;
        event_terms = std.math.add(u64, event_terms, audit.event_terms) catch
            return error.ArithmeticOverflow;
        framework_total = framework_total.add(claim);
        for (audit.values, 0..) |value, domain_index| {
            domain_totals[domain_index] = domain_totals[domain_index].add(value);
            if (!value.isZero()) active_domain_mask |= domainBit(domain_index);
        }
        if (row == 34) try requireProviderDomains(
            &audit.values,
            domainBit(@intFromEnum(RelationDomain.poseidon2)) |
                domainBit(@intFromEnum(RelationDomain.poseidon2_io)),
        );
        if (row == 35) try requireProviderDomains(
            &audit.values,
            domainBit(@intFromEnum(RelationDomain.range_check_8_8)),
        );
        if (row == 10 and !claim.isZero())
            return error.EthereumIncrementalClosureMismatchV4;
    }
    const wire_index = @intFromEnum(public_wire.domain);
    domain_totals[wire_index] = domain_totals[wire_index].add(
        public_wire.claimed_sum,
    );
    framework_total = framework_total.add(public_wire.claimed_sum);
    active_domain_mask |= domainBit(wire_index);

    var result = ReceiptV4{
        .manifest_seal = manifest.seal,
        .public_wire = public_wire,
        .domain_totals = domain_totals,
        .framework_total = framework_total,
        .active_domain_mask = active_domain_mask,
        .logical_rows = logical_rows,
        .event_terms = event_terms,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = closureIdentity(&result);
    try result.validate();
    return result;
}

fn validateAudit(
    audit: relation_interaction.DomainAudit,
    claim: QM31,
) Error!void {
    if (!secureCanonical(claim) or audit.logical_rows == 0 or
        audit.event_terms == 0 or !secureCanonical(audit.total) or
        !audit.total.eql(claim))
    {
        return error.EthereumIncrementalClosureMismatchV4;
    }
    var total = QM31.zero();
    for (audit.values) |value| {
        if (!secureCanonical(value))
            return error.EthereumIncrementalClosureMismatchV4;
        total = total.add(value);
    }
    if (!total.eql(audit.total))
        return error.EthereumIncrementalClosureMismatchV4;
}

fn requireProviderDomains(
    values: *const [DOMAIN_COUNT]QM31,
    allowed_mask: u64,
) Error!void {
    for (values, 0..) |value, index| if (!value.isZero() and
        allowed_mask & domainBit(index) == 0)
    {
        return error.EthereumIncrementalClosureMismatchV4;
    };
}

fn domainBit(index: usize) u64 {
    return @as(u64, 1) << @intCast(index);
}

fn boundaryIdentity(value: *const PublicWireBoundaryV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(BOUNDARY_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.domain));
    hashInt(&hash, u32, value.term_count);
    hash.update(&value.source_authority_identity_sha256);
    hashQm31(&hash, value.claimed_sum);
    return hash.finalResult();
}

fn closureIdentity(value: *const ReceiptV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CLOSURE_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.manifest_seal);
    hash.update(&value.public_wire.identity_sha256);
    for (value.domain_totals) |total| hashQm31(&hash, total);
    hashQm31(&hash, value.framework_total);
    hashInt(&hash, u64, value.active_domain_mask);
    hashInt(&hash, u64, value.logical_rows);
    hashInt(&hash, u64, value.event_terms);
    return hash.finalResult();
}

fn secureCanonical(value: QM31) bool {
    for (value.toM31Array()) |limb| if (limb.toU32() >=
        stwo_core.fields.m31.Modulus)
    {
        return false;
    };
    return true;
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        COMPONENT_COUNT != 36 or DOMAIN_COUNT >= 64 or
        PUBLIC_WIRE_DOMAIN != .recursion_wire or
        !COMPLETE_36_CLAIM_CLOSURE_AVAILABLE or
        DETACHED_BOUNDARY_ADMITTED or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental universal closure V4 drifted");
    }
}
