//! Native-provider admission for universal-recursion rows 34 and 35.
//!
//! These rows deliberately do not acquire a second recursion-local equation
//! owner.  The manifest instead binds the canonical typed Poseidon2 identity
//! and the authenticated `(8, 8)` table bridge to their existing native STWO
//! components.  Relation challenges are copied once at the cold admission
//! boundary and revalidated against the sealed 47-relation universal bundle;
//! the proof hot path then calls the native components directly.

const std = @import("std");
const stwo_core = @import("stwo_core");
const m31 = stwo_core.fields.m31;
const QM31 = stwo_core.fields.qm31.QM31;
const base_relations = @import("../../air/relation_challenges.zig");
const relation = @import("../../air/lang/relation.zig");
const poseidon_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const poseidon_component = @import("../../air/memory_commitment/hash_component.zig");
const poseidon_compat = @import("../../air/lang/typed_poseidon2_compat.zig");
const compact_identity = @import("../../air/memory_commitment/poseidon2_universal_identity_v2.zig");
const table_component = @import("../../air/lookups/tables/component.zig");
const range_bridge = @import("range_check_8_8_bridge.zig");
const manifest_mod = @import("universal_adapter_manifest.zig");
const admission = @import("universal_provider_admission.zig");
const geometry = @import("universal_shared_geometry.zig");
const universal = @import("universal_challenges.zig");

const authority = @import("universal_provider_authority.zig");
pub const STARK_V_REVISION = authority.STARK_V_REVISION;
pub const STARK_V_POSEIDON_PATH = authority.STARK_V_POSEIDON_PATH;
pub const STARK_V_AIR_FNS_PATH = authority.STARK_V_AIR_FNS_PATH;
pub const STARK_V_POSEIDON_SHA256 = authority.STARK_V_POSEIDON_SHA256;
pub const STARK_V_AIR_FNS_SHA256 = authority.STARK_V_AIR_FNS_SHA256;
pub const POSEIDON_SOURCE_AUTHORITY_FORMAT_VERSION = authority.POSEIDON_SOURCE_AUTHORITY_FORMAT_VERSION;
pub const POSEIDON_SOURCE_AUTHORITY_DOMAIN = authority.POSEIDON_SOURCE_AUTHORITY_DOMAIN;
pub const SHARED_RELATION_BINDING_DOMAIN = @import("universal_provider_relations.zig").SHARED_RELATION_BINDING_DOMAIN;
pub const POSEIDON_SOURCE_AUTHORITY_DIGEST = geometry.POSEIDON_SOURCE_AUTHORITY_DIGEST;

pub const Error = manifest_mod.Error ||
    universal.Error ||
    range_bridge.Error ||
    range_bridge.DefinitionError ||
    authority.Error ||
    error{
        ChallengeBindingMismatch,
        ProviderAuthorityMismatch,
        ProviderGeometryMismatch,
        ProviderTraceShapeMismatch,
    };

pub const POSEIDON_PREPROCESSED_COLUMN_COUNT = geometry.POSEIDON_PREPROCESSED_COLUMN_COUNT;
pub const POSEIDON_MAIN_COLUMN_COUNT = geometry.POSEIDON_MAIN_COLUMN_COUNT;
pub const POSEIDON_INTERACTION_BATCH_COUNT = geometry.POSEIDON_INTERACTION_BATCH_COUNT;
pub const POSEIDON_INTERACTION_COLUMN_COUNT = geometry.POSEIDON_INTERACTION_COLUMN_COUNT;
pub const POSEIDON_DIRECT_CONSTRAINT_COUNT = geometry.POSEIDON_DIRECT_CONSTRAINT_COUNT;
pub const POSEIDON_PROTOCOL_CONSTRAINT_DEGREE = geometry.POSEIDON_PROTOCOL_CONSTRAINT_DEGREE;
pub const POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT = geometry.POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT;
pub const RANGE_PREPROCESSED_COLUMN_COUNT = geometry.RANGE_PREPROCESSED_COLUMN_COUNT;
pub const RANGE_MAIN_COLUMN_COUNT = geometry.RANGE_MAIN_COLUMN_COUNT;
pub const RANGE_INTERACTION_BATCH_COUNT = geometry.RANGE_INTERACTION_BATCH_COUNT;
pub const RANGE_INTERACTION_COLUMN_COUNT = geometry.RANGE_INTERACTION_COLUMN_COUNT;
pub const RANGE_DIRECT_CONSTRAINT_COUNT = geometry.RANGE_DIRECT_CONSTRAINT_COUNT;
pub const RANGE_PROTOCOL_CONSTRAINT_DEGREE = geometry.RANGE_PROTOCOL_CONSTRAINT_DEGREE;
pub const POSEIDON_OUTPUT_COLUMN_START: usize =
    poseidon_compat.TEMPORARY_START + poseidon_compat.OUTPUT_START;

pub const PoseidonSourceAuthority = authority.PoseidonSourceAuthority;

pub const SharedProviderRelations = @import("universal_provider_relations.zig").SharedProviderRelations;

/// Concrete manifest/proof binding for the existing Poseidon2 component.
/// Like every STWO type-erased component, this adapter and its borrowed
/// relation storage must remain at stable, immutable addresses from `binding`
/// through the prove/verify call. Admission revalidates both immediately
/// before that type-erasure boundary.
pub const Poseidon2Adapter = Poseidon2AdapterForManifest(manifest_mod);

/// Reuses the one native Poseidon2 provider under any versioned outer
/// manifest that implements the universal placement contract.  The default
/// alias above preserves the frozen V1 API; V2 obtains a distinct adapter
/// type without copying a provider equation or challenge binding.
pub fn Poseidon2AdapterForManifest(comptime manifest_contract: type) type {
    return Poseidon2AdapterForLayout(manifest_contract, false, .canonical_only);
}

/// Explicitly versioned compact universal provider; legacy keys keep their AIR.
pub fn Poseidon2Degree3AdapterForManifest(comptime manifest_contract: type) type {
    return Poseidon2Degree3AdapterWithCompatibility(manifest_contract, .canonical_only);
}

/// Retained compact proofs require an explicit, reviewed identity mapping.
/// Compatibility changes only the accepted identity; all geometry and challenge
/// checks remain identical to canonical admission.
pub fn Poseidon2Degree3AdapterWithCompatibility(comptime manifest_contract: type, comptime compatibility: compact_identity.Compatibility) type {
    return Poseidon2AdapterForLayout(manifest_contract, true, compatibility);
}

fn Poseidon2AdapterForLayout(comptime manifest_contract: type, comptime compact: bool, comptime compatibility: compact_identity.Compatibility) type {
    const Geometry = geometry.PoseidonForManifest(manifest_contract, compact, compatibility);
    const selected_air = if (compact) @import("../../air/memory_commitment/poseidon2_universal_equations_v1.zig") else poseidon_air;
    const Component = if (compact) @import("../../air/memory_commitment/poseidon2_universal_component_v1.zig").Component else poseidon_component.HashComponent;
    return struct {
        const Self = @This();
        pub const Air = selected_air;

        placement: manifest_contract.Placement,
        component: Component,
        provider_relations: *const SharedProviderRelations,
        challenge_binding_digest: [32]u8,
        admitted_claims: [poseidon_air.N_SUMS]QM31,

        pub const manifestGeometry = Geometry.manifestGeometry;
        pub const acceptsGeometry = Geometry.acceptsGeometry;

        pub fn init(
            manifest: *const manifest_contract.Manifest,
            log_size: u32,
            n_rows: u32,
            provider_relations: *const SharedProviderRelations,
            universal_relations: *const universal.UniversalRelations,
            claims: [poseidon_air.N_SUMS]QM31,
        ) !Self {
            return initWithAllocator(std.heap.page_allocator, manifest, log_size, n_rows, provider_relations, universal_relations, claims);
        }

        /// Record equations once at cold admission using caller-owned scratch.
        pub fn initWithAllocator(
            allocator: std.mem.Allocator,
            manifest: *const manifest_contract.Manifest,
            log_size: u32,
            n_rows: u32,
            provider_relations: *const SharedProviderRelations,
            universal_relations: *const universal.UniversalRelations,
            claims: [poseidon_air.N_SUMS]QM31,
        ) !Self {
            const placement = try admission.poseidon(manifest_contract, compact, compatibility, allocator, manifest, log_size, n_rows, provider_relations, universal_relations, claims);
            const preprocessed_offset: usize = placement.preprocessed_offset;
            const main_offset: usize = placement.main_offset;
            const interaction_offset: usize = placement.interaction_offset;
            return .{
                .placement = placement,
                .provider_relations = provider_relations,
                .challenge_binding_digest = try provider_relations.identityDigest(),
                .admitted_claims = claims,
                .component = if (compact) .{
                    .log_size = log_size,
                    .n_rows = n_rows,
                    .is_first_col_idx = preprocessed_offset,
                    .is_active_col_idx = preprocessed_offset,
                    .main_col_offset = main_offset,
                    .interaction_col_offset = interaction_offset,
                    .relations = &provider_relations.native,
                    .claims = claims,
                } else .{
                    .kind = .poseidon2,
                    .log_size = log_size,
                    .n_rows = n_rows,
                    .is_first_col_idx = preprocessed_offset,
                    // General-mode Poseidon has no verifier-owned activity
                    // selector.  Keep this field equal to the first-row selector;
                    // the `.universal` shell never reads it.
                    .is_active_col_idx = preprocessed_offset,
                    .main_col_offset = main_offset,
                    .interaction_col_offset = interaction_offset,
                    .relations = &provider_relations.native,
                    .poseidon_shell = .universal,
                    .poseidon_claims = claims,
                },
            };
        }

        pub fn binding(
            self: *const Self,
            manifest: *const manifest_contract.Manifest,
        ) !manifest_contract.AdapterBinding {
            if (!acceptsGeometry(self.placement.geometry)) return error.ProviderGeometryMismatch;
            try validatePlacementForManifest(manifest_contract, manifest, self.placement, self.placement.geometry);
            if (!compact) try PoseidonSourceAuthority.pinned().validate();
            const challenge_digest = try self.provider_relations.identityDigest();
            if (!std.mem.eql(
                u8,
                &challenge_digest,
                &self.challenge_binding_digest,
            ) or self.component.relations != &self.provider_relations.native) {
                return error.ChallengeBindingMismatch;
            }
            for (0..poseidon_air.N_SUMS) |index| {
                const actual = if (compact) &self.component.claims[index] else &self.component.poseidon_claims[index];
                const expected = &self.admitted_claims[index];
                if (!secureIsCanonical(actual) or !secureEql(actual, expected))
                    return error.ChallengeBindingMismatch;
            }
            if ((!compact and (self.component.kind != .poseidon2 or
                self.component.poseidon_shell != .universal)) or
                self.component.log_size != self.placement.geometry.log_size or
                self.component.log_size == 0 or
                self.component.log_size >= POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT)
            {
                return error.ProviderAuthorityMismatch;
            }
            const trace_size = @as(u64, 1) << @intCast(self.component.log_size);
            if (self.component.n_rows > trace_size or
                self.component.is_first_col_idx != self.placement.preprocessed_offset or
                self.component.is_active_col_idx != self.placement.preprocessed_offset or
                self.component.main_col_offset != self.placement.main_offset or
                self.component.interaction_col_offset != self.placement.interaction_offset or
                self.component.nPreprocessedColumns() != POSEIDON_PREPROCESSED_COLUMN_COUNT or
                self.component.nConstraints() !=
                    selected_air.N_CONSTRAINTS + POSEIDON_INTERACTION_BATCH_COUNT)
            {
                return error.ProviderAuthorityMismatch;
            }
            return .{
                .manifest_seal = manifest.seal,
                .placement = self.placement,
                .claimed_sum = if (compact) self.component.claims[0].add(self.component.claims[1]) else self.component.poseidon_claims[0].add(self.component.poseidon_claims[1]),
                .verifier = self.component.asVerifierComponent(),
                .prover = self.component.asProverComponent(),
            };
        }
    };
}

/// Concrete manifest/proof binding for the existing `(8, 8)` table component.
/// The adapter and its borrowed relations share the stable-address lifetime
/// contract documented on `Poseidon2Adapter`.
pub const RangeCheck8x8Adapter = RangeCheck8x8AdapterForManifest(manifest_mod);

/// Version-parametric shell for the one authenticated `(8,8)` table.  Its
/// table definition, executor binding, relation challenges, and native
/// component remain identical across manifests.
pub fn RangeCheck8x8AdapterForManifest(comptime manifest_contract: type) type {
    return struct {
        const Self = @This();

        placement: manifest_contract.Placement,
        component: table_component.LookupTableComponent,
        provider_relations: *const SharedProviderRelations,
        challenge_binding_digest: [32]u8,
        admitted_claim: QM31,

        pub const manifestGeometry = geometry.RangeForManifest(manifest_contract).manifestGeometry;

        pub fn init(
            definition: *const range_bridge.Definition,
            executor: *const range_bridge.Executor,
            manifest: *const manifest_contract.Manifest,
            provider_relations: *const SharedProviderRelations,
            universal_relations: *const universal.UniversalRelations,
            claim: QM31,
        ) !Self {
            try executor.validate();
            const placement = try admission.rangeCheck(manifest_contract, definition, &executor.binding, manifest, provider_relations, universal_relations, claim);
            const preprocessed_offset: usize = placement.preprocessed_offset;
            const tuple_indices = [_]usize{
                preprocessed_offset + 1,
                preprocessed_offset + 2,
            };
            return .{
                .placement = placement,
                .provider_relations = provider_relations,
                .challenge_binding_digest = try provider_relations.identityDigest(),
                .admitted_claim = claim,
                .component = try table_component.LookupTableComponent.initProver(
                    range_bridge.TABLE_KIND,
                    preprocessed_offset,
                    &tuple_indices,
                    placement.main_offset,
                    placement.interaction_offset,
                    &provider_relations.native,
                    claim,
                ),
            };
        }

        pub fn binding(
            self: *const Self,
            manifest: *const manifest_contract.Manifest,
        ) !manifest_contract.AdapterBinding {
            try validatePlacementForManifest(
                manifest_contract,
                manifest,
                self.placement,
                manifestGeometry(),
            );
            const challenge_digest = try self.provider_relations.identityDigest();
            if (!std.mem.eql(
                u8,
                &challenge_digest,
                &self.challenge_binding_digest,
            ) or self.component.relations != &self.provider_relations.native) {
                return error.ChallengeBindingMismatch;
            }
            if (!secureIsCanonical(&self.component.claim) or
                !secureEql(&self.component.claim, &self.admitted_claim))
            {
                return error.ChallengeBindingMismatch;
            }
            const tuple_start = std.math.add(
                usize,
                self.placement.preprocessed_offset,
                1,
            ) catch return error.ProviderGeometryMismatch;
            if (self.component.kind != range_bridge.TABLE_KIND or
                self.component.is_first_col_idx != self.placement.preprocessed_offset or
                self.component.tuple_col_indices[0] != tuple_start or
                self.component.tuple_col_indices[1] != tuple_start + 1 or
                self.component.main_col_offset != self.placement.main_offset or
                self.component.interaction_col_offset != self.placement.interaction_offset or
                self.component.nConstraints() !=
                    RANGE_DIRECT_CONSTRAINT_COUNT + RANGE_INTERACTION_BATCH_COUNT)
            {
                return error.ProviderAuthorityMismatch;
            }
            for (self.component.tuple_col_indices[range_bridge.TUPLE_ARITY..]) |index| {
                if (index != 0) return error.ProviderAuthorityMismatch;
            }
            var prover = self.component.asProverComponent();
            prover.backend_composition_capability = .{ .framework_polynomial_v1 = range_bridge.frameworkCapability() };
            return .{
                .manifest_seal = manifest.seal,
                .placement = self.placement,
                .claimed_sum = self.component.claim,
                .verifier = self.component.asVerifierComponent(),
                .prover = prover,
            };
        }
    };
}

const secureEql = @import("universal_provider_relations.zig").secureEql;
const secureIsCanonical = @import("universal_provider_relations.zig").secureIsCanonical;

fn validatePlacementForManifest(
    comptime manifest_contract: type,
    manifest: *const manifest_contract.Manifest,
    placement: manifest_contract.Placement,
    expected_geometry: manifest_contract.Geometry,
) !void {
    try manifest.validate();
    const expected = try manifest.placement(@enumFromInt(
        expected_geometry.roster_row,
    ));
    if (!placement.eql(expected) or
        !std.meta.eql(placement.geometry, expected_geometry))
    {
        return error.ProviderGeometryMismatch;
    }
}
