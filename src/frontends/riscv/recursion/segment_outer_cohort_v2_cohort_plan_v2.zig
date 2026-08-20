//! Internal segment outer cohort v2 authority shard; use segment_outer_cohort_v2.zig publicly.

const dependency_0 = @import("segment_outer_cohort_v2_contract.zig");

const ALL_CAPABILITY_MASK = dependency_0.ALL_CAPABILITY_MASK;
const ALL_COMPONENT_MASK = dependency_0.ALL_COMPONENT_MASK;
const AUDIT_ID_DOMAIN = dependency_0.AUDIT_ID_DOMAIN;
const BOUNDARY_AUDIT_ID_DOMAIN = dependency_0.BOUNDARY_AUDIT_ID_DOMAIN;
const CAPABILITY_COUNT = dependency_0.CAPABILITY_COUNT;
const CAPABILITY_ID_DOMAIN = dependency_0.CAPABILITY_ID_DOMAIN;
const CLOSURE_DIAGNOSTIC_ENV = dependency_0.CLOSURE_DIAGNOSTIC_ENV;
const COMPONENT_COUNT = dependency_0.COMPONENT_COUNT;
const Capability = dependency_0.Capability;
const DOMAIN_COUNT = dependency_0.DOMAIN_COUNT;
const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const GATE_RECEIPT_FORMAT_VERSION = dependency_0.GATE_RECEIPT_FORMAT_VERSION;
const GATE_RECEIPT_ID_DOMAIN = dependency_0.GATE_RECEIPT_ID_DOMAIN;
const LANDED_CAPABILITY_MASK = dependency_0.LANDED_CAPABILITY_MASK;
const LANDED_COMPONENT_ROW_MASK = dependency_0.LANDED_COMPONENT_ROW_MASK;
const MISSING_COMPONENT_ROW_MASK = dependency_0.MISSING_COMPONENT_ROW_MASK;
const PLAN_ID_DOMAIN = dependency_0.PLAN_ID_DOMAIN;
const PUBLIC_WIRE_BOUNDARY_FORMAT_VERSION = dependency_0.PUBLIC_WIRE_BOUNDARY_FORMAT_VERSION;
const PUBLIC_WIRE_BOUNDARY_ID_DOMAIN = dependency_0.PUBLIC_WIRE_BOUNDARY_ID_DOMAIN;
const ProviderCallCountsV2 = dependency_0.ProviderCallCountsV2;
const ProviderScheduleV2 = dependency_0.ProviderScheduleV2;
const QM31 = dependency_0.QM31;
const ROW_10 = dependency_0.ROW_10;
const ROW_34 = dependency_0.ROW_34;
const ROW_35 = dependency_0.ROW_35;
const RosterPlanV2 = dependency_0.RosterPlanV2;
const TreePlanV2 = dependency_0.TreePlanV2;
const capabilityBit = dependency_0.capabilityBit;
const checkedAdd = dependency_0.checkedAdd;
const componentBit = dependency_0.componentBit;
const digest = dependency_0.digest;
const hashInt = dependency_0.hashInt;
const manifest_mod = dependency_0.manifest_mod;
const relation = dependency_0.relation;
const relation_interaction = dependency_0.relation_interaction;
const roster = dependency_0.roster;
const shared_schedule = dependency_0.shared_schedule;
const std = dependency_0.std;
const stwo_core = dependency_0.stwo_core;
const universal = dependency_0.universal;

pub const CapabilityLedgerV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    capability_count: u8 = CAPABILITY_COUNT,
    production_ready: bool = false,
    landed_mask: u64 = LANDED_CAPABILITY_MASK,
    missing_mask: u64 = ALL_CAPABILITY_MASK & ~LANDED_CAPABILITY_MASK,
    landed_component_rows: u64 = LANDED_COMPONENT_ROW_MASK,
    missing_component_rows: u64 = MISSING_COMPONENT_ROW_MASK,
    identity: digest.Digest,

    pub fn current() CapabilityLedgerV2 {
        var result = CapabilityLedgerV2{ .identity = undefined };
        result.identity = capabilityIdentity(&result);
        return result;
    }

    pub fn validate(self: *const CapabilityLedgerV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.capability_count != CAPABILITY_COUNT or self.production_ready or
            self.landed_mask != LANDED_CAPABILITY_MASK or
            self.missing_mask != ALL_CAPABILITY_MASK & ~LANDED_CAPABILITY_MASK or
            self.landed_mask & self.missing_mask != 0 or
            self.landed_mask | self.missing_mask != ALL_CAPABILITY_MASK or
            self.landed_component_rows != LANDED_COMPONENT_ROW_MASK or
            self.missing_component_rows != MISSING_COMPONENT_ROW_MASK or
            self.landed_component_rows & self.missing_component_rows != 0 or
            self.landed_component_rows | self.missing_component_rows !=
                ALL_COMPONENT_MASK or
            !std.mem.eql(u8, &self.identity, &capabilityIdentity(self)))
        {
            return error.CapabilityEscalation;
        }
    }

    pub fn has(self: CapabilityLedgerV2, capability: Capability) bool {
        return self.landed_mask & capabilityBit(capability) != 0;
    }
};

/// Allocation-free protocol plan. It authenticates only immutable geometry
/// and scheduling; runtime claims/components are admitted separately through
/// `GateReceiptV2` after a complete proof gate seals.
pub const CohortPlanV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    manifest_seal: digest.Digest,
    catalog_identity: digest.Digest,
    relation_registry_identity: digest.Digest,
    roster: RosterPlanV2,
    trees: TreePlanV2,
    provider: ProviderScheduleV2,
    capabilities: CapabilityLedgerV2,
    identity: digest.Digest,

    pub fn init(
        manifest: *const manifest_mod.Manifest,
        provider_layout: *const shared_schedule.SharedPoseidonCallLayoutV2,
        provider_calls: []const shared_schedule.Call,
    ) Error!CohortPlanV2 {
        try manifest.validate();
        var result = CohortPlanV2{
            .manifest_seal = manifest.seal,
            .catalog_identity = manifest.catalog_identity,
            .relation_registry_identity = relation.registryOrderDigest(),
            .roster = try RosterPlanV2.init(manifest),
            .trees = try TreePlanV2.init(manifest),
            .provider = try ProviderScheduleV2.initFromAuthenticatedLayout(
                manifest,
                provider_layout,
                provider_calls,
            ),
            .capabilities = CapabilityLedgerV2.current(),
            .identity = undefined,
        };
        result.identity = planIdentity(&result);
        try result.validateAgainst(manifest);
        return result;
    }

    pub fn measuredCanonical(
        manifest: *const manifest_mod.Manifest,
        provider_layout: *const shared_schedule.SharedPoseidonCallLayoutV2,
        provider_calls: []const shared_schedule.Call,
    ) Error!CohortPlanV2 {
        const counts = try ProviderCallCountsV2.fromLayout(provider_layout);
        if (!std.meta.eql(counts, ProviderCallCountsV2.measuredCanonical()))
            return error.InvalidProviderSchedule;
        return init(manifest, provider_layout, provider_calls);
    }

    pub fn validateAgainst(
        self: *const CohortPlanV2,
        manifest: *const manifest_mod.Manifest,
    ) Error!void {
        try manifest.validate();
        if (self.format_version != FORMAT_VERSION or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
            !std.mem.eql(u8, &self.catalog_identity, &manifest.catalog_identity) or
            !std.mem.eql(
                u8,
                &self.relation_registry_identity,
                &relation.registryOrderDigest(),
            ))
        {
            return error.CohortIdentityMismatch;
        }
        try self.roster.validateAgainst(manifest);
        try self.trees.validateAgainst(manifest);
        try self.provider.validateAgainst(manifest);
        try self.capabilities.validate();
        if (!std.mem.eql(u8, &self.identity, &planIdentity(self)))
            return error.CohortIdentityMismatch;
    }
};

/// Exact claims/components capture from the sealed 39-row gate. This is the
/// only cohort API which may report complete component coverage.
pub const GateReceiptV2 = struct {
    format_version: u16 = GATE_RECEIPT_FORMAT_VERSION,
    component_count: u8 = COMPONENT_COUNT,
    padding: [5]u8 = [_]u8{0} ** 5,
    plan_identity: digest.Digest,
    manifest_seal: digest.Digest,
    catalog_identity: digest.Digest,
    component_mask: u64 = ALL_COMPONENT_MASK,
    claim_mask: u64 = ALL_COMPONENT_MASK,
    claim_seal: digest.Digest,
    claims: [COMPONENT_COUNT]QM31,
    identity: digest.Digest,

    pub fn capture(
        plan: *const CohortPlanV2,
        manifest: *const manifest_mod.Manifest,
        gate: *const manifest_mod.ProofGate,
    ) Error!GateReceiptV2 {
        try plan.validateAgainst(manifest);
        try gate.validate(manifest);
        if (gate.count != COMPONENT_COUNT or
            gate.claims.admitted_mask != ALL_COMPONENT_MASK or
            gate.claims.bound_mask != ALL_COMPONENT_MASK)
        {
            return error.ComponentCoverageMismatch;
        }
        var result = GateReceiptV2{
            .plan_identity = plan.identity,
            .manifest_seal = manifest.seal,
            .catalog_identity = manifest.catalog_identity,
            .claim_seal = gate.claims.seal,
            .claims = gate.claims.values,
            .identity = undefined,
        };
        result.identity = gateReceiptIdentity(&result);
        try result.validateAgainst(plan, manifest, gate);
        return result;
    }

    pub fn validateAgainst(
        self: *const GateReceiptV2,
        plan: *const CohortPlanV2,
        manifest: *const manifest_mod.Manifest,
        gate: *const manifest_mod.ProofGate,
    ) Error!void {
        try plan.validateAgainst(manifest);
        try gate.validate(manifest);
        if (self.format_version != GATE_RECEIPT_FORMAT_VERSION or
            self.component_count != COMPONENT_COUNT or !allZero(&self.padding) or
            !std.mem.eql(u8, &self.plan_identity, &plan.identity) or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
            !std.mem.eql(u8, &self.catalog_identity, &manifest.catalog_identity) or
            self.component_mask != ALL_COMPONENT_MASK or
            self.claim_mask != ALL_COMPONENT_MASK or
            gate.count != COMPONENT_COUNT or
            gate.claims.admitted_mask != ALL_COMPONENT_MASK or
            gate.claims.bound_mask != ALL_COMPONENT_MASK or
            !std.mem.eql(u8, &self.claim_seal, &gate.claims.seal))
        {
            return error.ComponentCoverageMismatch;
        }
        for (self.claims, gate.claims.values) |actual, expected| {
            try requireCanonical(actual);
            if (!actual.eql(expected)) return error.ClaimMismatch;
        }
        if (!std.mem.eql(u8, &self.identity, &gateReceiptIdentity(self)))
            return error.GateIdentityMismatch;
    }
};

/// Versioned verifier-owned boundary for the arithmetic lowering's live
/// constants and designated zero outputs.  It is not a fabricated component
/// claim: the concrete cohort derives it from its pre-challenge-sealed core and
/// the already drawn universal relation.  `term_count` retains geometry that
/// is intentionally disjoint from committed logical/event row accounting.
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

pub const ClosureSummaryV2 = struct {
    domain_totals: [DOMAIN_COUNT]QM31,
    framework_total: QM31,
    active_domain_mask: u64,
    logical_rows: u64,
    event_terms: u64,
    public_wire_boundary: ?PublicWireBoundaryV2,
    audit_identity: digest.Digest,
};

/// Verifies every row claim and every universal domain. It also enforces that
/// the two shared providers contribute only in their respective domains.
/// Audit custody is deliberately addressed by the receipt layer below.
pub fn verifyInteractionClosure(
    manifest: *const manifest_mod.Manifest,
    claims: *const [COMPONENT_COUNT]QM31,
    audits: *const [COMPONENT_COUNT]relation_interaction.DomainAudit,
) Error!ClosureSummaryV2 {
    try manifest.validate();
    return verifyClosureValues(claims, audits, null);
}

/// Boundary-aware whole-cohort closure used by the concrete SegmentV2 proof.
/// The boundary is a typed, identity-bound scalar projection of canonical base
/// tuples; omission and sign substitution therefore remain distinguishable
/// from an ordinary row-claim failure.
pub fn verifyInteractionClosureV2(
    manifest: *const manifest_mod.Manifest,
    claims: *const [COMPONENT_COUNT]QM31,
    audits: *const [COMPONENT_COUNT]relation_interaction.DomainAudit,
    public_wire_boundary: *const PublicWireBoundaryV2,
) Error!ClosureSummaryV2 {
    try manifest.validate();
    try public_wire_boundary.validate();
    return verifyClosureValues(claims, audits, public_wire_boundary);
}

pub fn verifyClosureValues(
    claims: *const [COMPONENT_COUNT]QM31,
    audits: *const [COMPONENT_COUNT]relation_interaction.DomainAudit,
    public_wire_boundary: ?*const PublicWireBoundaryV2,
) Error!ClosureSummaryV2 {
    var domain_totals = [_]QM31{QM31.zero()} ** DOMAIN_COUNT;
    var framework_total = QM31.zero();
    var active_domain_mask: u64 = 0;
    var logical_rows: u64 = 0;
    var event_terms: u64 = 0;

    for (audits, claims, 0..) |audit, claim, row| {
        try requireCanonical(claim);
        const empty_geometry = audit.logical_rows == 0 and
            audit.event_terms == 0;
        if ((audit.logical_rows == 0) != (audit.event_terms == 0) or
            (empty_geometry and !claim.isZero()))
        {
            return error.InvalidAuditGeometry;
        }
        logical_rows = try checkedAdd(logical_rows, audit.logical_rows);
        event_terms = try checkedAdd(event_terms, audit.event_terms);
        var row_total = QM31.zero();
        for (audit.values, 0..) |value, domain| {
            try requireCanonical(value);
            if (empty_geometry and !value.isZero())
                return error.InvalidAuditGeometry;
            row_total = row_total.add(value);
            domain_totals[domain] = domain_totals[domain].add(value);
            if (!value.isZero()) active_domain_mask |= componentBit(domain);
        }
        try requireCanonical(audit.total);
        if (empty_geometry and !audit.total.isZero())
            return error.InvalidAuditGeometry;
        if (!row_total.eql(audit.total) or !audit.total.eql(claim))
            return error.ClaimMismatch;
        framework_total = framework_total.add(claim);

        // The shared Poseidon component owns both recurrence sums exported by
        // the typed AIR: call/input custody in `poseidon2` and carried-output
        // custody in `poseidon2_io`.  Row 35 is the single-domain range table.
        // Keeping these as explicit masks rejects a provider claim that is
        // numerically balanced only by leaking into an unrelated registry.
        if (row == ROW_34) try requireProviderDomains(
            &audit.values,
            componentBit(@intFromEnum(relation.Domain.poseidon2)) |
                componentBit(@intFromEnum(relation.Domain.poseidon2_io)),
        );
        if (row == ROW_35) try requireProviderDomains(
            &audit.values,
            componentBit(@intFromEnum(relation.Domain.range_check_8_8)),
        );
        if (row == ROW_10 and !claim.isZero())
            return error.ClaimMismatch;
    }
    if (public_wire_boundary) |boundary| {
        try boundary.validate();
        const domain = @intFromEnum(boundary.domain);
        domain_totals[domain] = domain_totals[domain].add(
            boundary.claimed_sum,
        );
        framework_total = framework_total.add(boundary.claimed_sum);
        active_domain_mask |= componentBit(domain);
    }
    var relation_not_closed = false;
    for (domain_totals) |total| {
        try requireCanonical(total);
        relation_not_closed = relation_not_closed or !total.isZero();
    }
    relation_not_closed = relation_not_closed or !framework_total.isZero();
    if (relation_not_closed) {
        if (std.process.hasEnvVarConstant(CLOSURE_DIAGNOSTIC_ENV))
            printClosureDiagnostic(
                audits,
                claims,
                public_wire_boundary,
                &domain_totals,
                framework_total,
            );
        return error.RelationNotClosed;
    }

    return .{
        .domain_totals = domain_totals,
        .framework_total = framework_total,
        .active_domain_mask = active_domain_mask,
        .logical_rows = logical_rows,
        .event_terms = event_terms,
        .public_wire_boundary = if (public_wire_boundary) |boundary|
            boundary.*
        else
            null,
        .audit_identity = if (public_wire_boundary) |boundary|
            boundaryAuditIdentity(audits, boundary)
        else
            auditIdentity(audits),
    };
}

/// Failure-path-only observability for the complete conservation equation.
/// The diagnostic consumes the already authenticated audits and never changes
/// a claim, residual, protocol transcript, or proof-path return value.
pub fn printClosureDiagnostic(
    audits: *const [COMPONENT_COUNT]relation_interaction.DomainAudit,
    claims: *const [COMPONENT_COUNT]QM31,
    public_wire_boundary: ?*const PublicWireBoundaryV2,
    domain_totals: *const [DOMAIN_COUNT]QM31,
    framework_total: QM31,
) void {
    std.debug.print(
        "\nSEGMENT_V2_CLOSURE_DIAGNOSTIC components={d} domains={d}\n",
        .{ COMPONENT_COUNT, DOMAIN_COUNT },
    );
    for (domain_totals, 0..) |total, domain| {
        if (total.isZero()) continue;
        const domain_name = @tagName(
            @as(relation.Domain, @enumFromInt(domain)),
        );
        std.debug.print(
            "  domain={d}:{s} residual={any}\n",
            .{ domain, domain_name, total.toM31Array() },
        );
        for (audits, claims, 0..) |audit, claim, row| {
            const contribution = audit.values[domain];
            if (contribution.isZero()) continue;
            std.debug.print(
                "    row={d} contribution={any} claim={any} " ++
                    "logical_rows={d} event_terms={d}\n",
                .{
                    row,
                    contribution.toM31Array(),
                    claim.toM31Array(),
                    audit.logical_rows,
                    audit.event_terms,
                },
            );
        }
        if (public_wire_boundary) |boundary| {
            if (domain == @intFromEnum(boundary.domain)) std.debug.print(
                "    public_wire_boundary contribution={any} terms={d} " ++
                    "authority={x}\n",
                .{
                    boundary.claimed_sum.toM31Array(),
                    boundary.term_count,
                    boundary.source_authority_id[0..8],
                },
            );
        }
    }
    if (!framework_total.isZero()) std.debug.print(
        "  framework_residual={any}\n",
        .{framework_total.toM31Array()},
    );
}

pub const AuditCustody = enum(u8) {
    generator_diagnostic = 0,
};

pub fn capabilityIdentity(value: *const CapabilityLedgerV2) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CAPABILITY_ID_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u8, value.capability_count);
    hashInt(&hash, u8, @intFromBool(value.production_ready));
    hashInt(&hash, u64, value.landed_mask);
    hashInt(&hash, u64, value.missing_mask);
    hashInt(&hash, u64, value.landed_component_rows);
    hashInt(&hash, u64, value.missing_component_rows);
    return hash.finalResult();
}

pub fn planIdentity(value: *const CohortPlanV2) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PLAN_ID_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hash.update(&value.manifest_seal);
    hash.update(&value.catalog_identity);
    hash.update(&value.relation_registry_identity);
    hash.update(&value.roster.identity);
    hash.update(&value.trees.identity);
    hash.update(&value.provider.shared_layout.identity);
    hash.update(&value.capabilities.identity);
    return hash.finalResult();
}

pub fn gateReceiptIdentity(value: *const GateReceiptV2) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(GATE_RECEIPT_ID_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u8, value.component_count);
    hash.update(&value.padding);
    hash.update(&value.plan_identity);
    hash.update(&value.manifest_seal);
    hash.update(&value.catalog_identity);
    hashInt(&hash, u64, value.component_mask);
    hashInt(&hash, u64, value.claim_mask);
    hash.update(&value.claim_seal);
    for (value.claims) |claim| hashQM31(&hash, claim);
    return hash.finalResult();
}

pub fn auditIdentity(
    audits: *const [COMPONENT_COUNT]relation_interaction.DomainAudit,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUDIT_ID_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u8, COMPONENT_COUNT);
    hashInt(&hash, u8, DOMAIN_COUNT);
    for (audits) |audit| {
        for (audit.values) |value| hashQM31(&hash, value);
        hashQM31(&hash, audit.total);
        hashInt(&hash, u64, audit.logical_rows);
        hashInt(&hash, u64, audit.event_terms);
    }
    return hash.finalResult();
}

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

pub fn boundaryAuditIdentity(
    audits: *const [COMPONENT_COUNT]relation_interaction.DomainAudit,
    boundary: *const PublicWireBoundaryV2,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(BOUNDARY_AUDIT_ID_DOMAIN);
    hash.update(&auditIdentity(audits));
    hashInt(&hash, u16, boundary.format_version);
    hashInt(&hash, u8, @intFromEnum(boundary.domain));
    hashInt(&hash, u32, boundary.term_count);
    hash.update(&boundary.source_authority_id);
    hashQM31(&hash, boundary.claimed_sum);
    hash.update(&boundary.identity);
    return hash.finalResult();
}

pub fn requireCanonical(value: QM31) Error!void {
    for (value.toM31Array()) |limb| {
        if (limb.toU32() >= stwo_core.fields.m31.Modulus)
            return error.NonCanonicalField;
    }
}

pub fn requireProviderDomains(
    values: *const [DOMAIN_COUNT]QM31,
    allowed_mask: u64,
) Error!void {
    for (values, 0..) |value, index| {
        if (allowed_mask & componentBit(index) == 0 and !value.isZero())
            return error.ProviderDomainMismatch;
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
