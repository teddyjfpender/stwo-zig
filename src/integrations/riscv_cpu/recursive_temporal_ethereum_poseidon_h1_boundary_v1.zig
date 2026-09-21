//! Exact public-boundary residual authority for the Ethereum h1 cohort.
//!
//! Tree2 closes every internal tuple and both native Poseidon domains. The
//! remaining statement-word and verifier-input tuples are genuine public
//! residuals reconstructed from the verifier-minted leaf witnesses. This file
//! seals those residuals without relabeling the statement domain as the
//! existing temporal parent's `recursion_wire` domain. Production admission
//! therefore remains explicitly unavailable until a reviewed fixed-wire join
//! and an independent verifier-input boundary source are bound.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const ingress_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_ingress_v1.zig");
const manifest_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_manifest_v1.zig");
const materializer_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_materializer_v1.zig");
const cohort_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_cohort_v1.zig");
const components_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_components_v1.zig");
const trace_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_trace_v1.zig");
const interactions_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_interactions_v1.zig");

const recursion = frontend.recursion;
const universal = recursion.air.universal_challenges;
const shared_provider = recursion.air.universal_shared_provider;
const relation_interaction = recursion.air.relation_interaction;
const global_closure = recursion.binary_global_closure_outer_source;
const RelationDomain = @TypeOf(global_closure.WIRE_BOUNDARY_DOMAIN);
const QM31 = stwo_core.fields.qm31.QM31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-boundary/v1\x00";
pub const TUPLE_DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-boundary-tuples/v1\x00";
pub const STATEMENT_DOMAIN: RelationDomain = .recursion_statement_word;
pub const VERIFIER_INPUT_DOMAIN: RelationDomain =
    .recursion_verifier_input_word;
pub const REQUIRED_SECURE_WIRE_DOMAIN: RelationDomain =
    global_closure.WIRE_BOUNDARY_DOMAIN;

pub const BoundaryResidualV1 = struct {
    domain: RelationDomain,
    tuple_count: u32,
    /// Exact unmatched component claim in this public boundary domain.
    claimed_sum: QM31,
    tuple_provenance_sha256: [32]u8,

    pub fn validate(
        self: BoundaryResidualV1,
        expected_domain: RelationDomain,
    ) !void {
        if (self.domain != expected_domain or
            std.mem.allEqual(u8, &self.tuple_provenance_sha256, 0))
        {
            return error.InvalidEthereumPoseidonH1BoundaryResidual;
        }
    }
};

pub const ClosureReceiptV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    provider_closed: bool,
    internal_tuple_frontier_closed: bool,
    statement_to_secure_wire_join_admitted: bool = false,
    verifier_input_source_admitted: bool = false,
    reserved: u8 = 0,
    custody_identity_sha256: [32]u8,
    materialized_identity_sha256: [32]u8,
    generated_interactions_sha256: [32]u8,
    parent_statement_sha256: [32]u8,
    statement: BoundaryResidualV1,
    verifier_input: BoundaryResidualV1,
    identity_sha256: [32]u8,

    pub fn validate(self: *const ClosureReceiptV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or !self.provider_closed or
            !self.internal_tuple_frontier_closed or
            self.statement_to_secure_wire_join_admitted or
            self.verifier_input_source_admitted or self.reserved != 0 or
            std.mem.allEqual(u8, &self.custody_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.materialized_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.generated_interactions_sha256, 0) or
            std.mem.allEqual(u8, &self.parent_statement_sha256, 0))
        {
            return error.InvalidEthereumPoseidonH1BoundaryReceipt;
        }
        try self.statement.validate(STATEMENT_DOMAIN);
        try self.verifier_input.validate(VERIFIER_INPUT_DOMAIN);
        if (!std.mem.eql(u8, &self.identity_sha256, &receiptIdentity(self)))
            return error.InvalidEthereumPoseidonH1BoundaryReceipt;
    }

    /// The first missing proof-visible seam is deliberately terminal. A
    /// caller cannot reinterpret the statement-word scalar as a recursion-wire
    /// scalar merely because both live in QM31.
    pub fn requireSecureParentAdmission(
        self: *const ClosureReceiptV1,
    ) !void {
        try self.validate();
        if (STATEMENT_DOMAIN != REQUIRED_SECURE_WIRE_DOMAIN or
            !self.statement_to_secure_wire_join_admitted)
        {
            return error.EthereumPoseidonH1StatementWireJoinUnavailable;
        }
        if (!self.verifier_input_source_admitted)
            return error.EthereumPoseidonH1VerifierInputBoundaryUnavailable;
        if (!PRODUCTION_ACTIVATION)
            return error.EthereumPoseidonH1BoundaryPublicationUnavailable;
    }
};

pub fn audit(
    allocator: std.mem.Allocator,
    owners: *const components_mod.OwnersV1,
    materialized: *const materializer_mod.MaterializedV1,
    cohort: *const cohort_mod.CohortV1,
    custody: *const ingress_mod.CustodyV1,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    provider_relations: *const shared_provider.SharedProviderRelations,
    generated: *const interactions_mod.GeneratedInteractionsV1,
) !ClosureReceiptV1 {
    try trace_mod.validateInputs(materialized, cohort, custody, manifest);
    try generated.validate(
        materialized,
        cohort,
        manifest,
        relations,
        provider_relations,
    );
    var ledger = relation_interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    try interactions_mod.appendTupleContributions(
        owners,
        materialized,
        &ledger,
    );
    const report = ledger.classify();
    if (report.unmatched_tuple_count !=
        report.unmatched_by_domain[@intFromEnum(STATEMENT_DOMAIN)] +
            report.unmatched_by_domain[@intFromEnum(VERIFIER_INPUT_DOMAIN)])
    {
        return error.EthereumPoseidonH1TupleClosureMismatch;
    }
    const statement = try residualFromSortedLedger(
        &ledger,
        STATEMENT_DOMAIN,
        generated.boundaryClaims().statement,
        generated.identity_sha256,
    );
    const verifier_input = try residualFromSortedLedger(
        &ledger,
        VERIFIER_INPUT_DOMAIN,
        generated.boundaryClaims().verifier_input,
        generated.identity_sha256,
    );
    if (statement.tuple_count !=
        report.unmatched_by_domain[@intFromEnum(STATEMENT_DOMAIN)] or
        verifier_input.tuple_count !=
            report.unmatched_by_domain[@intFromEnum(VERIFIER_INPUT_DOMAIN)])
    {
        return error.EthereumPoseidonH1TupleClosureMismatch;
    }
    var result = ClosureReceiptV1{
        .provider_closed = generated.provider_closed,
        .internal_tuple_frontier_closed = true,
        .custody_identity_sha256 = custody.identity_sha256,
        .materialized_identity_sha256 = materialized.identity_sha256,
        .generated_interactions_sha256 = generated.identity_sha256,
        .parent_statement_sha256 = custody.parent_statement_sha256,
        .statement = statement,
        .verifier_input = verifier_input,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = receiptIdentity(&result);
    try result.validate();
    return result;
}

fn residualFromSortedLedger(
    ledger: *const relation_interaction.TupleLedger,
    target_domain: RelationDomain,
    claimed_sum: QM31,
    generated_identity: [32]u8,
) !BoundaryResidualV1 {
    var hash = Sha256.init(.{});
    hash.update(TUPLE_DOMAIN);
    hashInt(&hash, u8, @intFromEnum(target_domain));
    hash.update(&generated_identity);
    var count: u32 = 0;
    var cursor: usize = 0;
    while (cursor < ledger.contributions.items.len) {
        const first = ledger.contributions.items[cursor];
        var end = cursor + 1;
        var signed_weight = first.signed_weight;
        while (end < ledger.contributions.items.len and
            sameTupleGroup(first, ledger.contributions.items[end])) : (end += 1)
        {
            signed_weight = signed_weight.add(
                ledger.contributions.items[end].signed_weight,
            );
        }
        if (first.domain == target_domain and !signed_weight.isZero()) {
            hash.update(&first.tuple_hash);
            hashQm31(&hash, signed_weight);
            count = std.math.add(u32, count, 1) catch
                return error.ArithmeticOverflow;
        }
        cursor = end;
    }
    hashInt(&hash, u32, count);
    hashQm31(&hash, claimed_sum);
    const result = BoundaryResidualV1{
        .domain = target_domain,
        .tuple_count = count,
        .claimed_sum = claimed_sum,
        .tuple_provenance_sha256 = hash.finalResult(),
    };
    try result.validate(target_domain);
    return result;
}

fn sameTupleGroup(
    left: relation_interaction.TupleContribution,
    right: relation_interaction.TupleContribution,
) bool {
    return left.domain == right.domain and
        std.mem.eql(u8, &left.tuple_hash, &right.tuple_hash);
}

fn receiptIdentity(value: *const ClosureReceiptV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hashInt(&hash, u8, @intFromBool(value.provider_closed));
    hashInt(&hash, u8, @intFromBool(value.internal_tuple_frontier_closed));
    hashInt(
        &hash,
        u8,
        @intFromBool(value.statement_to_secure_wire_join_admitted),
    );
    hashInt(
        &hash,
        u8,
        @intFromBool(value.verifier_input_source_admitted),
    );
    hashInt(&hash, u8, value.reserved);
    hash.update(&value.custody_identity_sha256);
    hash.update(&value.materialized_identity_sha256);
    hash.update(&value.generated_interactions_sha256);
    hash.update(&value.parent_statement_sha256);
    hashResidual(&hash, value.statement);
    hashResidual(&hash, value.verifier_input);
    return hash.finalResult();
}

fn hashResidual(hash: *Sha256, value: BoundaryResidualV1) void {
    hashInt(hash, u8, @intFromEnum(value.domain));
    hashInt(hash, u32, value.tuple_count);
    hashQm31(hash, value.claimed_sum);
    hash.update(&value.tuple_provenance_sha256);
}

fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub const testing = struct {
    pub fn reseal(value: *ClosureReceiptV1) void {
        value.identity_sha256 = receiptIdentity(value);
    }
};

comptime {
    if (STATEMENT_DOMAIN == REQUIRED_SECURE_WIRE_DOMAIN or
        VERIFIER_INPUT_DOMAIN != global_closure.VERIFIER_INPUT_BOUNDARY_DOMAIN or
        PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum Poseidon h1 boundary contract drifted");
    }
}
