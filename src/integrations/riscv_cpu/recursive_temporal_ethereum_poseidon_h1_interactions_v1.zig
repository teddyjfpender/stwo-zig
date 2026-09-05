//! Authenticated Tree2 generation and provider closure for Ethereum h1.
//!
//! Every wrapper placement consumes the same joined universal challenge set.
//! The native Poseidon2 provider is appended last and must cancel both of its
//! relation domains exactly. A challenge-independent tuple ledger additionally
//! proves that every unmatched tuple is confined to the two explicit parent
//! boundary domains; no balancing tuple is synthesized here.

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

const recursion = frontend.recursion;
const relation_interaction = recursion.air.relation_interaction;
const universal = recursion.air.universal_challenges;
const shared_provider = recursion.air.universal_shared_provider;
const global_closure = recursion.binary_global_closure_outer_source;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const Sha256 = std.crypto.hash.sha2.Sha256;
const RelationDomain = @TypeOf(global_closure.VERIFIER_INPUT_BOUNDARY_DOMAIN);
const STATEMENT_DOMAIN_INDEX = @intFromEnum(
    @as(RelationDomain, .recursion_statement_word),
);
const VERIFIER_INPUT_DOMAIN_INDEX = @intFromEnum(
    @as(RelationDomain, .recursion_verifier_input_word),
);
const POSEIDON2_DOMAIN_INDEX = @intFromEnum(
    @as(RelationDomain, .poseidon2),
);
const POSEIDON2_IO_DOMAIN_INDEX = @intFromEnum(
    @as(RelationDomain, .poseidon2_io),
);

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-interactions/v1\x00";

pub const BoundaryClaimsV1 = struct {
    statement: QM31,
    verifier_input: QM31,

    pub fn total(self: BoundaryClaimsV1) QM31 {
        return self.statement.add(self.verifier_input);
    }
};

pub const GeneratedInteractionsV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    provider_closed: bool,
    reserved: [2]u8 = .{ 0, 0 },
    manifest_seal: [32]u8,
    materialized_identity_sha256: [32]u8,
    cohort_identity_sha256: [32]u8,
    universal_relations_sha256: [32]u8,
    provider_relations_sha256: [32]u8,
    claims: components_mod.ClaimsV1,
    domain_totals: [universal.RELATION_COUNT]QM31,
    tuple_closure: relation_interaction.TupleClosureReport,
    identity_sha256: [32]u8,

    pub fn boundaryClaims(self: *const GeneratedInteractionsV1) BoundaryClaimsV1 {
        return .{
            .statement = self.domain_totals[STATEMENT_DOMAIN_INDEX],
            .verifier_input = self.domain_totals[VERIFIER_INPUT_DOMAIN_INDEX],
        };
    }

    pub fn validate(
        self: *const GeneratedInteractionsV1,
        materialized: *const materializer_mod.MaterializedV1,
        cohort: *const cohort_mod.CohortV1,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        try manifest.validate();
        try cohort.validate();
        try relations.validate();
        try provider_relations.validateAgainst(relations);
        const provider_digest = try provider_relations.identityDigest();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or !self.provider_closed or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
            !std.mem.eql(
                u8,
                &self.materialized_identity_sha256,
                &materialized.identity_sha256,
            ) or !std.mem.eql(
            u8,
            &self.cohort_identity_sha256,
            &cohort.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.universal_relations_sha256,
            &relationsDigest(relations),
        ) or !std.mem.eql(
            u8,
            &self.provider_relations_sha256,
            &provider_digest,
        )) return error.EthereumPoseidonH1InteractionAuthorityMismatch;

        const claim_vector = try self.claims.bindInto(manifest);
        try claim_vector.validate(manifest);
        var domain_total = QM31.zero();
        for (self.domain_totals) |value| domain_total = domain_total.add(value);
        if (!domain_total.eql(claimTotal(self.claims)) or
            !internalDomainsClosed(&self.domain_totals) or
            !tupleReportConfinedToBoundaries(self.tuple_closure) or
            !std.mem.eql(u8, &self.identity_sha256, &interactionIdentity(self)))
        {
            return error.EthereumPoseidonH1InteractionAuthorityMismatch;
        }
    }

    pub fn requireProductionClosure(
        self: *const GeneratedInteractionsV1,
    ) !void {
        if (!PRODUCTION_ACTIVATION)
            return error.EthereumPoseidonH1ProductionClosureUnavailable;
        if (!self.boundaryClaims().total().isZero())
            return error.EthereumPoseidonH1BoundaryNotClosed;
    }
};

/// Generates all eleven wrapper interactions followed by the one native
/// provider interaction. The returned authority is minted only after both the
/// algebraic per-domain audit and exact tuple-frontier audit have closed.
pub fn fillInteractionInto(
    allocator: std.mem.Allocator,
    owners: *const components_mod.OwnersV1,
    materialized: *const materializer_mod.MaterializedV1,
    cohort: *const cohort_mod.CohortV1,
    custody: *const ingress_mod.CustodyV1,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    provider_relations: *const shared_provider.SharedProviderRelations,
    destination: []const []M31,
) !GeneratedInteractionsV1 {
    try owners.validate();
    try trace_mod.validateInputs(materialized, cohort, custody, manifest);
    try relations.validate();
    try provider_relations.validateAgainst(relations);
    try trace_mod.preflightFreshTree(
        materialized,
        manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
        destination,
    );
    errdefer trace_mod.clearTree(destination);

    var claims: components_mod.ClaimsV1 = undefined;
    var domain_totals = [_]QM31{QM31.zero()} ** universal.RELATION_COUNT;

    const source = try generateFramework(
        components_mod.SourceFramework,
        allocator,
        &owners.source.relation,
        materialized.source_rows,
        manifest.placements[manifest_mod.keyIndex(.link_source)].?,
        relations,
        destination,
    );
    claims.source = source.claimed_sum;
    addDomains(&domain_totals, source.by_domain);

    const projection = try generateFramework(
        components_mod.ProjectionFramework,
        allocator,
        &owners.projection.relation,
        materialized.projection_rows,
        manifest.placements[manifest_mod.keyIndex(.link_projection)].?,
        relations,
        destination,
    );
    claims.projection = projection.claimed_sum;
    addDomains(&domain_totals, projection.by_domain);

    const router = try generateFramework(
        components_mod.RouterFramework,
        allocator,
        &owners.router.relation,
        materialized.child_router_rows,
        manifest.placements[manifest_mod.keyIndex(.child_field_router)].?,
        relations,
        destination,
    );
    claims.router = router.claimed_sum;
    addDomains(&domain_totals, router.by_domain);

    inline for (manifest_mod.COMPONENT_KEYS[3..11], 0..) |key, ordinal| {
        const generated = try generateFramework(
            components_mod.HashFramework,
            allocator,
            &owners.hash.relation,
            trace_mod.hashRows(materialized, ordinal),
            manifest.placements[manifest_mod.keyIndex(key)].?,
            relations,
            destination,
        );
        claims.hashes[ordinal] = generated.claimed_sum;
        addDomains(&domain_totals, generated.by_domain);
    }

    const provider_placement =
        manifest.placements[manifest_mod.keyIndex(.poseidon2)].?;
    var provider = try poseidon2_air.generateInteraction(
        allocator,
        materialized.poseidon_calls,
        provider_placement.geometry.log_size,
        &provider_relations.native,
    );
    defer provider.deinit(allocator);
    for (
        destination[provider_placement.interaction_offset..][0..poseidon2_air.N_INTERACTION_COLUMNS],
        &provider.columns,
    ) |target, source_column| @memcpy(target, source_column);
    claims.provider = provider.claims.sums;
    domain_totals[POSEIDON2_DOMAIN_INDEX] =
        domain_totals[POSEIDON2_DOMAIN_INDEX].add(
            claims.provider[0],
        );
    domain_totals[POSEIDON2_IO_DOMAIN_INDEX] =
        domain_totals[POSEIDON2_IO_DOMAIN_INDEX].add(
            claims.provider[1],
        );

    if (!internalDomainsClosed(&domain_totals))
        return error.EthereumPoseidonH1ProviderClosureMismatch;
    const tuple_closure = try auditTupleFrontier(
        allocator,
        owners,
        materialized,
    );
    if (!tupleReportConfinedToBoundaries(tuple_closure))
        return error.EthereumPoseidonH1TupleClosureMismatch;

    const provider_digest = try provider_relations.identityDigest();
    var result = GeneratedInteractionsV1{
        .provider_closed = true,
        .manifest_seal = manifest.seal,
        .materialized_identity_sha256 = materialized.identity_sha256,
        .cohort_identity_sha256 = cohort.identity_sha256,
        .universal_relations_sha256 = relationsDigest(relations),
        .provider_relations_sha256 = provider_digest,
        .claims = claims,
        .domain_totals = domain_totals,
        .tuple_closure = tuple_closure,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = interactionIdentity(&result);
    try result.validate(
        materialized,
        cohort,
        manifest,
        relations,
        provider_relations,
    );
    return result;
}

fn generateFramework(
    comptime Framework: type,
    allocator: std.mem.Allocator,
    plan: *const Framework.Plan,
    rows: []const Framework.Row,
    placement: manifest_mod.Placement,
    relations: *const universal.UniversalRelations,
    destination: []const []M31,
) !Framework.DomainClaims {
    var columns: [Framework.INTERACTION_COLUMN_COUNT][]M31 = undefined;
    for (
        &columns,
        destination[placement.interaction_offset..][0..Framework.INTERACTION_COLUMN_COUNT],
    ) |*bound, column| bound.* = column;
    var workspace = try Framework.Workspace.init(
        allocator,
        placement.geometry.log_size,
    );
    defer workspace.deinit();
    return Framework.generatePreparedIntoWithDomainSums(
        &workspace,
        plan,
        rows,
        placement.geometry.log_size,
        relations,
        &columns,
    );
}

fn auditTupleFrontier(
    allocator: std.mem.Allocator,
    owners: *const components_mod.OwnersV1,
    materialized: *const materializer_mod.MaterializedV1,
) !relation_interaction.TupleClosureReport {
    var ledger = relation_interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    try appendTupleContributions(owners, materialized, &ledger);
    return ledger.classify();
}

pub fn appendTupleContributions(
    owners: *const components_mod.OwnersV1,
    materialized: *const materializer_mod.MaterializedV1,
    ledger: *relation_interaction.TupleLedger,
) !void {
    const mask = relation_interaction.allDomainMask();
    try owners.source.relation.appendPreparedTupleContributions(
        ledger,
        manifest_mod.keyIndex(.link_source),
        materialized.source_rows,
        mask,
    );
    try owners.projection.relation.appendPreparedTupleContributions(
        ledger,
        manifest_mod.keyIndex(.link_projection),
        materialized.projection_rows,
        mask,
    );
    try owners.router.relation.appendPreparedTupleContributions(
        ledger,
        manifest_mod.keyIndex(.child_field_router),
        materialized.child_router_rows,
        mask,
    );
    inline for (manifest_mod.COMPONENT_KEYS[3..11], 0..) |key, ordinal| {
        try owners.hash.relation.appendPreparedTupleContributions(
            ledger,
            manifest_mod.keyIndex(key),
            trace_mod.hashRows(materialized, ordinal),
            mask,
        );
    }
    try appendProviderTuples(ledger, materialized.poseidon_calls);
}

fn appendProviderTuples(
    ledger: *relation_interaction.TupleLedger,
    calls: []const poseidon2_air.Call,
) !void {
    for (calls) |call| {
        if (!call.io or call.wide or call.narrow_output != null)
            return error.EthereumPoseidonH1ProviderClosureMismatch;
        const row = poseidon2_air.fill(call);
        const output = poseidon2_air.output(row);
        var tuple: [2 * poseidon2_air.WIDTH]QM31 = undefined;
        for (tuple[0..poseidon2_air.WIDTH], call.input) |*word, value|
            word.* = QM31.fromBase(M31.fromCanonical(value));
        for (tuple[poseidon2_air.WIDTH..], output) |*word, value|
            word.* = QM31.fromBase(value);
        try ledger.append(
            .poseidon2_io,
            manifest_mod.keyIndex(.poseidon2),
            3,
            .emit,
            QM31.one(),
            &tuple,
        );
    }
}

fn addDomains(
    destination: *[universal.RELATION_COUNT]QM31,
    source: [universal.RELATION_COUNT]QM31,
) void {
    for (destination, source) |*target, value|
        target.* = target.*.add(value);
}

fn internalDomainsClosed(
    totals: *const [universal.RELATION_COUNT]QM31,
) bool {
    for (totals, 0..) |value, index| {
        if (index == STATEMENT_DOMAIN_INDEX or
            index == VERIFIER_INPUT_DOMAIN_INDEX) continue;
        if (!value.isZero()) return false;
    }
    return true;
}

fn tupleReportConfinedToBoundaries(
    report: relation_interaction.TupleClosureReport,
) bool {
    var sum: usize = 0;
    for (report.unmatched_by_domain, 0..) |count, index| {
        sum += count;
        if (index != STATEMENT_DOMAIN_INDEX and
            index != VERIFIER_INPUT_DOMAIN_INDEX and count != 0)
        {
            return false;
        }
    }
    return sum == report.unmatched_tuple_count;
}

fn claimTotal(claims: components_mod.ClaimsV1) QM31 {
    var result = claims.source.add(claims.projection).add(claims.router);
    for (claims.hashes) |claim| result = result.add(claim);
    return result.add(claims.providerTotal());
}

fn relationsDigest(relations: *const universal.UniversalRelations) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/typed-air/ethereum-poseidon-h1-relations/v1\x00");
    hashInt(&hash, u16, relations.format_version);
    hash.update(&relations.registry_order_digest);
    for (relations.elements) |element| {
        hashInt(&hash, u8, element.arity);
        hashQm31(&hash, element.z);
        hashQm31(&hash, element.alpha);
    }
    return hash.finalResult();
}

fn interactionIdentity(value: *const GeneratedInteractionsV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hashInt(&hash, u8, @intFromBool(value.provider_closed));
    hash.update(&value.reserved);
    hash.update(&value.manifest_seal);
    hash.update(&value.materialized_identity_sha256);
    hash.update(&value.cohort_identity_sha256);
    hash.update(&value.universal_relations_sha256);
    hash.update(&value.provider_relations_sha256);
    hashQm31(&hash, value.claims.source);
    hashQm31(&hash, value.claims.projection);
    hashQm31(&hash, value.claims.router);
    for (value.claims.hashes) |claim| hashQm31(&hash, claim);
    for (value.claims.provider) |claim| hashQm31(&hash, claim);
    for (value.domain_totals) |claim| hashQm31(&hash, claim);
    hashInt(&hash, u64, value.tuple_closure.contribution_count);
    hashInt(&hash, u64, value.tuple_closure.unmatched_tuple_count);
    for (value.tuple_closure.unmatched_by_domain) |count|
        hashInt(&hash, u64, count);
    return hash.finalResult();
}

fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (universal.RELATION_COUNT >= @bitSizeOf(u64) or
        poseidon2_air.N_SUMS != 2 or
        poseidon2_air.N_INTERACTION_COLUMNS != 8 or
        manifest_mod.COMPONENT_COUNT != 12 or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum Poseidon h1 Tree2 contract drifted");
    }
}
