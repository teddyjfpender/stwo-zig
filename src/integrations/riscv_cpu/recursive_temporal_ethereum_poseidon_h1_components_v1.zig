//! Authenticated component owners for the 12-placement Ethereum h1 cohort.
//!
//! The module compiles exactly four reviewed wrapper AIR definitions.  One
//! hash definition is reused by eight component instances whose five verifier
//! constants come from the sealed structural cohort.  Placement twelve reuses
//! the existing native Poseidon2 component through the compact adapter.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const manifest_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_manifest_v1.zig");
const cohort_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_cohort_v1.zig");
const provider_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_provider_v1.zig");

const recursion = frontend.recursion;
const source_air = recursion.air.ethereum_leaf_link_source_v1;
const projection_air = recursion.air.ethereum_leaf_link_projection_v1;
const router_air = recursion.air.ethereum_leaf_child_field_router_v1;
const hash_air = recursion.air.vm_public_claim_hash;
const binding = recursion.air.universal_relation_binding;
const direct_program = recursion.air.direct_constraint_program;
const framework = recursion.air.framework_interaction;
const typed_component = recursion.air.universal_typed_component;
const universal = recursion.air.universal_challenges;
const shared_provider = recursion.air.universal_shared_provider;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

pub const SourceRelation = binding.Binding(source_air);
pub const ProjectionRelation = binding.Binding(projection_air);
pub const RouterRelation = binding.Binding(router_air);
pub const HashRelation = binding.Binding(hash_air);

pub const SourceFramework = framework.Runtime(SourceRelation.Runtime);
pub const ProjectionFramework = framework.Runtime(ProjectionRelation.Runtime);
pub const RouterFramework = framework.Runtime(RouterRelation.Runtime);
pub const HashFramework = framework.Runtime(HashRelation.Runtime);

pub const SourceAdapter = typed_component.ComponentForManifest(
    source_air,
    SourceRelation,
    manifest_mod,
);
pub const ProjectionAdapter = typed_component.ComponentForManifest(
    projection_air,
    ProjectionRelation,
    manifest_mod,
);
pub const RouterAdapter = typed_component.ComponentForManifest(
    router_air,
    RouterRelation,
    manifest_mod,
);
pub const HashAdapter = typed_component.ComponentForManifest(
    hash_air,
    HashRelation,
    manifest_mod,
);

pub fn AirOwner(comptime Air: type, comptime Relation: type) type {
    return struct {
        definition: Air.Definition,
        relation: Relation.Plan,
        direct: direct_program.Program,

        fn init(allocator: std.mem.Allocator) !@This() {
            var definition = try Air.build(allocator);
            errdefer definition.deinit();
            return .{
                .relation = try Relation.authenticate(&definition),
                .direct = try direct_program.authenticate(
                    &definition.arena,
                    Air.SEMANTIC_DIGEST,
                    Air.LOGICAL_INPUT_COUNT,
                ),
                .definition = definition,
            };
        }

        fn validate(self: *const @This()) !void {
            try self.definition.validate();
            try self.relation.validateAgainst(
                &self.definition.arena,
                Air.SEMANTIC_DIGEST,
                Relation.events(&self.definition),
            );
            const expected = try direct_program.authenticate(
                &self.definition.arena,
                Air.SEMANTIC_DIGEST,
                Air.LOGICAL_INPUT_COUNT,
            );
            if (!std.meta.eql(expected, self.direct))
                return error.EthereumPoseidonH1ComponentAuthorityMismatch;
        }

        fn deinit(self: *@This()) void {
            self.definition.deinit();
            self.* = undefined;
        }
    };
}

pub const OwnersV1 = struct {
    source: AirOwner(source_air, SourceRelation),
    projection: AirOwner(projection_air, ProjectionRelation),
    router: AirOwner(router_air, RouterRelation),
    hash: AirOwner(hash_air, HashRelation),

    pub fn init(allocator: std.mem.Allocator) !OwnersV1 {
        var source = try AirOwner(source_air, SourceRelation).init(allocator);
        errdefer source.deinit();
        var projection = try AirOwner(
            projection_air,
            ProjectionRelation,
        ).init(allocator);
        errdefer projection.deinit();
        var router = try AirOwner(router_air, RouterRelation).init(allocator);
        errdefer router.deinit();
        var hash = try AirOwner(hash_air, HashRelation).init(allocator);
        errdefer hash.deinit();
        const result = OwnersV1{
            .source = source,
            .projection = projection,
            .router = router,
            .hash = hash,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: *const OwnersV1) !void {
        try self.source.validate();
        try self.projection.validate();
        try self.router.validate();
        try self.hash.validate();
    }

    pub fn deinit(self: *OwnersV1) void {
        self.hash.deinit();
        self.router.deinit();
        self.projection.deinit();
        self.source.deinit();
        self.* = undefined;
    }
};

pub const ClaimsV1 = struct {
    source: QM31,
    projection: QM31,
    router: QM31,
    hashes: [cohort_mod.HASH_INSTANCE_COUNT]QM31,
    provider: [poseidon2_air.N_SUMS]QM31,

    pub fn providerTotal(self: ClaimsV1) QM31 {
        return self.provider[0].add(self.provider[1]);
    }

    pub fn bindInto(
        self: ClaimsV1,
        manifest: *const manifest_mod.Manifest,
    ) !manifest_mod.ClaimVector {
        var result = try manifest_mod.ClaimVector.init(manifest);
        try result.bind(.link_source, self.source);
        try result.bind(.link_projection, self.projection);
        try result.bind(.child_field_router, self.router);
        inline for (
            manifest_mod.COMPONENT_KEYS[3..11],
            0..,
        ) |key, ordinal| try result.bind(key, self.hashes[ordinal]);
        try result.bind(.poseidon2, self.providerTotal());
        try result.sealClaims(manifest);
        return result;
    }
};

pub const ComponentsV1 = struct {
    source: SourceAdapter,
    projection: ProjectionAdapter,
    router: RouterAdapter,
    hashes: [cohort_mod.HASH_INSTANCE_COUNT]HashAdapter,
    provider: provider_mod.Adapter,

    pub fn appendToGate(
        self: *const ComponentsV1,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        if (gate.count != 0) return error.AdapterOrderMismatch;
        try gate.append(manifest, try self.source.binding(manifest));
        try gate.append(manifest, try self.projection.binding(manifest));
        try gate.append(manifest, try self.router.binding(manifest));
        for (&self.hashes) |*hash|
            try gate.append(manifest, try hash.binding(manifest));
        try gate.append(manifest, try self.provider.binding(manifest));
        if (gate.count != manifest_mod.COMPONENT_COUNT)
            return error.AdapterCountMismatch;
    }
};

pub fn initComponents(
    owners: *const OwnersV1,
    cohort: *const cohort_mod.CohortV1,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    provider_relations: *const shared_provider.SharedProviderRelations,
    claims: ClaimsV1,
) !ComponentsV1 {
    try owners.validate();
    try cohort.validate();
    try manifest.validate();
    try relations.validate();
    try provider_relations.validateAgainst(relations);
    if (!std.mem.eql(u8, &cohort.manifest_seal, &manifest.seal))
        return error.EthereumPoseidonH1ComponentAuthorityMismatch;
    const empty_parameters = [_]M31{};
    var hashes: [cohort_mod.HASH_INSTANCE_COUNT]HashAdapter = undefined;
    inline for (
        manifest_mod.COMPONENT_KEYS[3..11],
        0..,
    ) |key, ordinal| {
        const instance = cohort.hashes[ordinal];
        var parameters: [HashAdapter.PARAMETER_COLUMN_COUNT]M31 = undefined;
        for (&parameters, instance.parameters) |*destination, word|
            destination.* = M31.fromCanonical(word);
        hashes[ordinal] = try HashAdapter.init(
            &owners.hash.definition,
            owners.hash.relation,
            manifest,
            key,
            manifest.log_sizes[manifest_mod.keyIndex(key)],
            parameters,
            relations,
            claims.hashes[ordinal],
        );
    }
    return .{
        .source = try SourceAdapter.init(
            &owners.source.definition,
            owners.source.relation,
            manifest,
            .link_source,
            manifest.log_sizes[manifest_mod.keyIndex(.link_source)],
            empty_parameters,
            relations,
            claims.source,
        ),
        .projection = try ProjectionAdapter.init(
            &owners.projection.definition,
            owners.projection.relation,
            manifest,
            .link_projection,
            manifest.log_sizes[manifest_mod.keyIndex(.link_projection)],
            empty_parameters,
            relations,
            claims.projection,
        ),
        .router = try RouterAdapter.init(
            &owners.router.definition,
            owners.router.relation,
            manifest,
            .child_field_router,
            manifest.log_sizes[manifest_mod.keyIndex(.child_field_router)],
            empty_parameters,
            relations,
            claims.router,
        ),
        .hashes = hashes,
        .provider = try provider_mod.Adapter.init(
            manifest,
            manifest.log_sizes[manifest_mod.keyIndex(.poseidon2)],
            cohort.provider_active_rows,
            provider_relations,
            relations,
            claims.provider,
        ),
    };
}

comptime {
    if (SourceAdapter.PARAMETER_COLUMN_COUNT != 0 or
        ProjectionAdapter.PARAMETER_COLUMN_COUNT != 0 or
        RouterAdapter.PARAMETER_COLUMN_COUNT != 0 or
        HashAdapter.PARAMETER_COLUMN_COUNT != 5 or
        cohort_mod.HASH_INSTANCE_COUNT != 8 or
        manifest_mod.COMPONENT_COUNT != 12)
    {
        @compileError("Ethereum Poseidon h1 component topology drifted");
    }
}
