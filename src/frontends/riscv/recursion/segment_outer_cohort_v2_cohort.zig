//! Internal segment outer cohort v2 authority shard; use segment_outer_cohort_v2.zig publicly.

const dependency_0 = @import("segment_outer_cohort_v2_contract.zig");
const dependency_1 = @import("segment_outer_cohort_v2_cohort_plan_v2.zig");

const AuditCustody = dependency_1.AuditCustody;
const CLOSURE_RECEIPT_FORMAT_VERSION = dependency_0.CLOSURE_RECEIPT_FORMAT_VERSION;
const CLOSURE_RECEIPT_ID_DOMAIN = dependency_0.CLOSURE_RECEIPT_ID_DOMAIN;
const COMPONENT_COUNT = dependency_0.COMPONENT_COUNT;
const ClosureSummaryV2 = dependency_1.ClosureSummaryV2;
const CohortPlanV2 = dependency_1.CohortPlanV2;
const DOMAIN_COUNT = dependency_0.DOMAIN_COUNT;
const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const GateReceiptV2 = dependency_1.GateReceiptV2;
const M31 = dependency_0.M31;
const MEASURED_AUTHORITY_POSEIDON_CALLS = dependency_0.MEASURED_AUTHORITY_POSEIDON_CALLS;
const MEASURED_CORE_POSEIDON_CALLS = dependency_0.MEASURED_CORE_POSEIDON_CALLS;
const MEASURED_TOTAL_POSEIDON_CALLS = dependency_0.MEASURED_TOTAL_POSEIDON_CALLS;
const MEASURED_TRANSCRIPT_POSEIDON_CALLS = dependency_0.MEASURED_TRANSCRIPT_POSEIDON_CALLS;
const PRODUCTION_ACTIVATION = dependency_0.PRODUCTION_ACTIVATION;
const READINESS_RECEIPT_FORMAT_VERSION = dependency_0.READINESS_RECEIPT_FORMAT_VERSION;
const READINESS_RECEIPT_ID_DOMAIN = dependency_0.READINESS_RECEIPT_ID_DOMAIN;
const ROW_10 = dependency_0.ROW_10;
const ROW_34 = dependency_0.ROW_34;
const ROW_35 = dependency_0.ROW_35;
const TREE_COUNT = dependency_0.TREE_COUNT;
const allZero = dependency_1.allZero;
const auditIdentity = dependency_1.auditIdentity;
const boundary_components = dependency_0.boundary_components;
const catalog_mod = dependency_0.catalog_mod;
const digest = dependency_0.digest;
const gateReceiptIdentity = dependency_1.gateReceiptIdentity;
const hashInt = dependency_0.hashInt;
const manifest_mod = dependency_0.manifest_mod;
const planIdentity = dependency_1.planIdentity;
const public_components = dependency_0.public_components;
const range_authority = dependency_0.range_authority;
const relation = dependency_0.relation;
const relation_interaction = dependency_0.relation_interaction;
const statement_components = dependency_0.statement_components;
const statement_source = dependency_0.statement_source;
const std = dependency_0.std;
const transcript_components = dependency_0.transcript_components;
const transcript_source = dependency_0.transcript_source;
const verifier_input_provider = dependency_0.verifier_input_provider;
const verifyClosureValues = dependency_1.verifyClosureValues;
const verifyInteractionClosure = dependency_1.verifyInteractionClosure;

/// Algebraically exact closure receipt tied to a complete gate. Its custody is
/// explicit and cannot be confused with independent-verifier evidence.
pub const GeneratedClosureReceiptV2 = struct {
    format_version: u16 = CLOSURE_RECEIPT_FORMAT_VERSION,
    component_count: u8 = COMPONENT_COUNT,
    domain_count: u8 = DOMAIN_COUNT,
    custody: AuditCustody = .generator_diagnostic,
    padding: [2]u8 = .{ 0, 0 },
    plan_identity: digest.Digest,
    gate_identity: digest.Digest,
    relation_registry_identity: digest.Digest,
    audit_identity: digest.Digest,
    active_domain_mask: u64,
    logical_rows: u64,
    event_terms: u64,
    identity: digest.Digest,

    pub fn capture(
        plan: *const CohortPlanV2,
        manifest: *const manifest_mod.Manifest,
        gate: *const manifest_mod.ProofGate,
        audits: *const [COMPONENT_COUNT]relation_interaction.DomainAudit,
    ) Error!GeneratedClosureReceiptV2 {
        const gate_receipt = try GateReceiptV2.capture(plan, manifest, gate);
        const summary = try verifyInteractionClosure(
            manifest,
            &gate_receipt.claims,
            audits,
        );
        var result = GeneratedClosureReceiptV2{
            .plan_identity = plan.identity,
            .gate_identity = gate_receipt.identity,
            .relation_registry_identity = relation.registryOrderDigest(),
            .audit_identity = summary.audit_identity,
            .active_domain_mask = summary.active_domain_mask,
            .logical_rows = summary.logical_rows,
            .event_terms = summary.event_terms,
            .identity = undefined,
        };
        result.identity = closureReceiptIdentity(&result);
        try result.validateAgainst(plan, &gate_receipt, audits);
        return result;
    }

    pub fn validateAgainst(
        self: *const GeneratedClosureReceiptV2,
        plan: *const CohortPlanV2,
        gate: *const GateReceiptV2,
        audits: *const [COMPONENT_COUNT]relation_interaction.DomainAudit,
    ) Error!void {
        const summary = try verifyClosureValues(&gate.claims, audits, null);
        if (self.format_version != CLOSURE_RECEIPT_FORMAT_VERSION or
            self.component_count != COMPONENT_COUNT or
            self.domain_count != DOMAIN_COUNT or
            self.custody != .generator_diagnostic or !allZero(&self.padding) or
            !std.mem.eql(u8, &self.plan_identity, &plan.identity) or
            !std.mem.eql(u8, &self.gate_identity, &gate.identity) or
            !std.mem.eql(
                u8,
                &self.relation_registry_identity,
                &relation.registryOrderDigest(),
            ) or !std.mem.eql(u8, &self.audit_identity, &auditIdentity(audits)))
        {
            return error.ClosureIdentityMismatch;
        }
        if (!std.mem.eql(u8, &gate.identity, &gateReceiptIdentity(gate)) or
            !std.mem.eql(u8, &plan.identity, &planIdentity(plan)) or
            !std.mem.eql(u8, &self.audit_identity, &summary.audit_identity) or
            self.active_domain_mask != summary.active_domain_mask or
            self.logical_rows != summary.logical_rows or
            self.event_terms != summary.event_terms)
        {
            return error.ClosureIdentityMismatch;
        }
        if (!std.mem.eql(u8, &self.identity, &closureReceiptIdentity(self)))
            return error.ClosureIdentityMismatch;
    }
};

/// Pointer-free statement of exactly what remains before this cohort may be
/// handed to the proof engine.  A receipt is useful while red: it prevents a
/// caller from turning source availability into proof evidence and gives
/// review tooling one deterministic object to compare across revisions.
pub const ProductionReadinessReceiptV2 = struct {
    format_version: u16 = READINESS_RECEIPT_FORMAT_VERSION,
    component_count: u8 = COMPONENT_COUNT,
    domain_count: u8 = DOMAIN_COUNT,
    production_ready: bool = false,
    padding: [3]u8 = .{ 0, 0, 0 },
    plan_identity: digest.Digest,
    capability_identity: digest.Digest,
    landed_capability_mask: u64,
    missing_capability_mask: u64,
    landed_component_mask: u64,
    missing_component_mask: u64,
    /// These identities may become non-zero only after the corresponding
    /// independently checked evidence exists.  V1 deliberately admits no
    /// constructor for a green receipt.
    proof_gate_identity: digest.Digest = [_]u8{0} ** 32,
    verifier_closure_identity: digest.Digest = [_]u8{0} ** 32,
    committed_trees_identity: digest.Digest = [_]u8{0} ** 32,
    independent_proof_identity: digest.Digest = [_]u8{0} ** 32,
    identity: digest.Digest,

    pub fn current(plan: *const CohortPlanV2) Error!ProductionReadinessReceiptV2 {
        try plan.capabilities.validate();
        var result = ProductionReadinessReceiptV2{
            .plan_identity = plan.identity,
            .capability_identity = plan.capabilities.identity,
            .landed_capability_mask = plan.capabilities.landed_mask,
            .missing_capability_mask = plan.capabilities.missing_mask,
            .landed_component_mask = plan.capabilities.landed_component_rows,
            .missing_component_mask = plan.capabilities.missing_component_rows,
            .identity = undefined,
        };
        result.identity = readinessReceiptIdentity(&result);
        try result.validateAgainst(plan);
        return result;
    }

    pub fn validateAgainst(
        self: *const ProductionReadinessReceiptV2,
        plan: *const CohortPlanV2,
    ) Error!void {
        try plan.capabilities.validate();
        if (self.format_version != READINESS_RECEIPT_FORMAT_VERSION or
            self.component_count != COMPONENT_COUNT or
            self.domain_count != DOMAIN_COUNT or self.production_ready or
            !allZero(&self.padding) or
            !std.mem.eql(u8, &plan.identity, &planIdentity(plan)) or
            !std.mem.eql(u8, &self.plan_identity, &plan.identity) or
            !std.mem.eql(
                u8,
                &self.capability_identity,
                &plan.capabilities.identity,
            ) or
            self.landed_capability_mask != plan.capabilities.landed_mask or
            self.missing_capability_mask != plan.capabilities.missing_mask or
            self.landed_component_mask !=
                plan.capabilities.landed_component_rows or
            self.missing_component_mask !=
                plan.capabilities.missing_component_rows or
            !allZero(&self.proof_gate_identity) or
            !allZero(&self.verifier_closure_identity) or
            !allZero(&self.committed_trees_identity) or
            !allZero(&self.independent_proof_identity) or
            !std.mem.eql(u8, &self.identity, &readinessReceiptIdentity(self)))
        {
            return error.CapabilityEscalation;
        }
    }

    pub fn requireProductionReady(
        self: *const ProductionReadinessReceiptV2,
        plan: *const CohortPlanV2,
    ) Error!void {
        try self.validateAgainst(plan);
        return error.ProductionReadinessUnavailable;
    }
};

/// Compile-valid engine surface while the two missing authority owners are
/// being completed.  It is intentionally unconstructible: this keeps the CPU
/// engine contract type-checkable without inventing trace data, detached
/// claims, or a green readiness bit.  Once both owners expose concrete input
/// and generated-interaction types, this seam is replaced by composition and
/// a named production alias is exported.
pub fn Cohort(comptime StatementOwner: type, comptime CoreOwner: type) type {
    comptime assertPendingOwnerContract(StatementOwner, "statement");
    comptime assertPendingOwnerContract(CoreOwner, "core");
    return struct {
        const Self = @This();

        pub const AuthorityInputs = struct {
            statement: StatementOwner.AuthorityInputs,
            core: CoreOwner.AuthorityInputs,
        };
        pub const GeneratedInteractionsV2 = struct {
            statement: StatementOwner.GeneratedInteractionsV2,
            core: CoreOwner.GeneratedInteractionsV2,
        };
        pub const Components = struct {
            statement: StatementOwner.Components,
            core: CoreOwner.Components,

            pub fn appendToGate(
                _: *const Components,
                _: *const manifest_mod.Manifest,
                _: *manifest_mod.ProofGate,
            ) Error!void {
                return error.ProductionReadinessUnavailable;
            }

            pub fn deinit(_: *Components) void {}
        };

        manifest_value: manifest_mod.Manifest,

        pub fn init(
            _: std.mem.Allocator,
            _: AuthorityInputs,
        ) Error!Self {
            return error.ProductionReadinessUnavailable;
        }

        pub fn deinit(self: *Self) void {
            self.* = undefined;
        }

        pub fn validate(_: *const Self) Error!void {
            return error.ProductionReadinessUnavailable;
        }

        pub fn manifest(self: *const Self) *const manifest_mod.Manifest {
            return &self.manifest_value;
        }

        pub fn mixAuthority(_: *const Self, _: anytype) Error!void {
            return error.ProductionReadinessUnavailable;
        }

        pub fn mixPublicWireBoundary(
            _: *const Self,
            _: anytype,
            _: anytype,
        ) Error!void {
            return error.ProductionReadinessUnavailable;
        }

        pub fn fillPreprocessedInto(
            _: *const Self,
            _: *const manifest_mod.Manifest,
            _: [][]M31,
        ) Error!void {
            return error.ProductionReadinessUnavailable;
        }

        pub fn fillMainInto(
            _: *const Self,
            _: *const manifest_mod.Manifest,
            _: [][]M31,
        ) Error!void {
            return error.ProductionReadinessUnavailable;
        }

        pub fn fillInteractionInto(
            _: *const Self,
            _: anytype,
            _: anytype,
            _: anytype,
            _: [][]M31,
        ) Error!GeneratedInteractionsV2 {
            return error.ProductionReadinessUnavailable;
        }

        pub fn validateGenerated(
            _: *const Self,
            _: *const GeneratedInteractionsV2,
            _: anytype,
            _: anytype,
        ) Error!void {
            return error.ProductionReadinessUnavailable;
        }

        pub fn auditGlobalClosure(
            _: *const Self,
            _: *const GeneratedInteractionsV2,
            _: *const manifest_mod.ClaimVector,
            _: anytype,
            _: anytype,
        ) Error!ClosureSummaryV2 {
            return error.ProductionReadinessUnavailable;
        }

        pub fn claimVector(
            _: *const Self,
            _: *const GeneratedInteractionsV2,
        ) Error!manifest_mod.ClaimVector {
            return error.ProductionReadinessUnavailable;
        }

        pub fn rebuildGeneratedInteractions(
            _: *const Self,
            _: anytype,
            _: anytype,
        ) Error!GeneratedInteractionsV2 {
            return error.ProductionReadinessUnavailable;
        }

        pub fn initComponents(
            _: *const Self,
            _: *const GeneratedInteractionsV2,
            _: anytype,
            _: anytype,
        ) Error!Components {
            return error.ProductionReadinessUnavailable;
        }
    };
}

pub const CONCRETE_PRODUCTION_COHORT_AVAILABLE = false;

pub fn closureReceiptIdentity(
    value: *const GeneratedClosureReceiptV2,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CLOSURE_RECEIPT_ID_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u8, value.component_count);
    hashInt(&hash, u8, value.domain_count);
    hashInt(&hash, u8, @intFromEnum(value.custody));
    hash.update(&value.padding);
    hash.update(&value.plan_identity);
    hash.update(&value.gate_identity);
    hash.update(&value.relation_registry_identity);
    hash.update(&value.audit_identity);
    hashInt(&hash, u64, value.active_domain_mask);
    hashInt(&hash, u64, value.logical_rows);
    hashInt(&hash, u64, value.event_terms);
    return hash.finalResult();
}

pub fn readinessReceiptIdentity(
    value: *const ProductionReadinessReceiptV2,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(READINESS_RECEIPT_ID_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u8, value.component_count);
    hashInt(&hash, u8, value.domain_count);
    hashInt(&hash, u8, @intFromBool(value.production_ready));
    hash.update(&value.padding);
    hash.update(&value.plan_identity);
    hash.update(&value.capability_identity);
    hashInt(&hash, u64, value.landed_capability_mask);
    hashInt(&hash, u64, value.missing_capability_mask);
    hashInt(&hash, u64, value.landed_component_mask);
    hashInt(&hash, u64, value.missing_component_mask);
    hash.update(&value.proof_gate_identity);
    hash.update(&value.verifier_closure_identity);
    hash.update(&value.committed_trees_identity);
    hash.update(&value.independent_proof_identity);
    return hash.finalResult();
}

pub fn assertPendingOwnerContract(comptime Owner: type, comptime label: []const u8) void {
    inline for (.{ "AuthorityInputs", "GeneratedInteractionsV2", "Components" }) |
        name,
    | if (!@hasDecl(Owner, name))
        @compileError("pending SegmentV2 " ++ label ++ " owner missing " ++ name);
}

comptime {
    if (COMPONENT_COUNT != 39 or DOMAIN_COUNT != 47 or TREE_COUNT != 3 or
        ROW_34 != 34 or ROW_35 != 35 or ROW_10 != 10 or
        MEASURED_TRANSCRIPT_POSEIDON_CALLS +
            MEASURED_AUTHORITY_POSEIDON_CALLS +
            MEASURED_CORE_POSEIDON_CALLS !=
            MEASURED_TOTAL_POSEIDON_CALLS or
        transcript_components.FIRST_ROW != 0 or
        transcript_components.ROW_COUNT != 10 or
        transcript_components.HOT_HEAP_ALLOCATIONS != 0 or
        statement_components.FIRST_ROW != 10 or
        statement_components.ROW_COUNT != 2 or
        statement_components.HOT_HEAP_ALLOCATIONS != 0 or
        public_components.FIRST_ROW != 12 or
        public_components.ROW_COUNT != 6 or
        public_components.HOT_HEAP_ALLOCATIONS != 0 or
        !range_authority.ROW_35_COMPLETE or
        !range_authority.PRODUCTION_ACTIVATION or
        boundary_components.SOURCE_COMPONENT_COUNT != 2 or
        verifier_input_provider.PROPOSED_ROSTER_ROW != 38 or
        verifier_input_provider.PROPOSED_COMPONENT_COUNT != COMPONENT_COUNT or
        PRODUCTION_ACTIVATION or CONCRETE_PRODUCTION_COHORT_AVAILABLE)
    {
        @compileError("SegmentV2 cohort capability or geometry drifted");
    }
    _ = catalog_mod.FORMAT_VERSION;
    _ = statement_source.FORMAT_VERSION;
    _ = transcript_source.FORMAT_VERSION;
}
