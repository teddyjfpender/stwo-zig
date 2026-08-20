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
const poseidon_identity = @import("../../air/lang/typed_poseidon2_identity.zig");
const table_component = @import("../../air/lookups/tables/component.zig");
const range_bridge = @import("range_check_8_8_bridge.zig");
const manifest_mod = @import("universal_adapter_manifest.zig");
const roster = @import("universal_roster.zig");
const universal = @import("universal_challenges.zig");

pub const STARK_V_REVISION: [40]u8 =
    "59172a201bd01f2f4b699bc2f7d4442d8ee81597".*;
pub const STARK_V_POSEIDON_PATH = "crates/air/src/poseidon2.rs";
pub const STARK_V_AIR_FNS_PATH = "crates/stwo-macros/src/air_fns.rs";
pub const STARK_V_POSEIDON_SHA256 = hexDigest(
    "d029f2ee6b3b63b6d7c992a208038b1d451d16e9bc8f0770f49aecc8b4b17b8a",
    "invalid pinned Stark-V poseidon2.rs digest",
);
pub const STARK_V_AIR_FNS_SHA256 = hexDigest(
    "cd3922d517bb96dcb660ed25e1bd58811109ab21721936f8e56b0a74fe582e79",
    "invalid pinned Stark-V air_fns.rs digest",
);
pub const POSEIDON_SOURCE_AUTHORITY_FORMAT_VERSION: u16 = 1;
pub const POSEIDON_SOURCE_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursion-poseidon2-provider-source/v1\x00";
pub const SHARED_RELATION_BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-shared-provider-relations/v1\x00";
pub const POSEIDON_SOURCE_AUTHORITY_DIGEST = hexDigest(
    "eb2603d73ce1dd3d71c67bb380a751303782ca668ef0a657eccc668658c57252",
    "invalid recursion Poseidon2 source-authority digest",
);

pub const Error = manifest_mod.Error ||
    universal.Error ||
    range_bridge.Error ||
    range_bridge.DefinitionError ||
    poseidon_identity.IdentityError ||
    error{
        ChallengeBindingMismatch,
        ProviderAuthorityMismatch,
        ProviderGeometryMismatch,
        ProviderTraceShapeMismatch,
    };

pub const POSEIDON_PREPROCESSED_COLUMN_COUNT: u16 = 1;
pub const POSEIDON_MAIN_COLUMN_COUNT: u16 = poseidon_air.N_MAIN_COLUMNS;
pub const POSEIDON_OUTPUT_COLUMN_START: usize =
    poseidon_compat.TEMPORARY_START + poseidon_compat.OUTPUT_START;
pub const POSEIDON_INTERACTION_BATCH_COUNT: u16 = poseidon_air.N_SUMS;
pub const POSEIDON_INTERACTION_COLUMN_COUNT: u16 =
    poseidon_air.N_INTERACTION_COLUMNS;
pub const POSEIDON_DIRECT_CONSTRAINT_COUNT: u16 =
    poseidon_air.N_CONSTRAINTS;
pub const POSEIDON_PROTOCOL_CONSTRAINT_DEGREE: u8 =
    poseidon_compat.MAXIMUM_CONSTRAINT_DEGREE;
/// A degree-three component evaluates its quotient on `log_size + 1`.
/// M31's largest constructible circle domain has log size 30, so a trace at
/// log size 30 would be admitted successfully and fail only inside proving.
pub const POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT: u32 = 30;

pub const RANGE_PREPROCESSED_COLUMN_COUNT: u16 =
    range_bridge.FRAMEWORK_PREPROCESSED_COLUMN_COUNT;
pub const RANGE_MAIN_COLUMN_COUNT: u16 =
    range_bridge.PHYSICAL_MAIN_COLUMN_COUNT;
pub const RANGE_INTERACTION_BATCH_COUNT: u16 =
    range_bridge.INTERACTION_BATCH_COUNT;
pub const RANGE_INTERACTION_COLUMN_COUNT: u16 =
    range_bridge.INTERACTION_COLUMN_COUNT;
pub const RANGE_DIRECT_CONSTRAINT_COUNT: u16 = 0;
pub const RANGE_PROTOCOL_CONSTRAINT_DEGREE: u8 = 3;

/// Exact source, compiler, typed-program, and physical-geometry receipt for
/// Stark-V's generated general-mode Poseidon2 component.  This is separate
/// from the program identity because a backend-neutral graph alone does not
/// prove which external DSL source or component shell was reviewed.
pub const PoseidonSourceAuthority = struct {
    format_version: u16,
    revision: [40]u8,
    poseidon_source_sha256: [32]u8,
    air_fns_source_sha256: [32]u8,
    program_identity_digest: [32]u8,
    preprocessed_columns: u16,
    main_columns: u16,
    interaction_columns: u16,
    direct_constraints: u16,
    interaction_batches: u16,
    maximum_constraint_degree: u8,

    pub fn pinned() PoseidonSourceAuthority {
        return .{
            .format_version = POSEIDON_SOURCE_AUTHORITY_FORMAT_VERSION,
            .revision = STARK_V_REVISION,
            .poseidon_source_sha256 = STARK_V_POSEIDON_SHA256,
            .air_fns_source_sha256 = STARK_V_AIR_FNS_SHA256,
            .program_identity_digest = poseidon_identity.CANONICAL_COMBINED_DIGEST,
            .preprocessed_columns = POSEIDON_PREPROCESSED_COLUMN_COUNT,
            .main_columns = POSEIDON_MAIN_COLUMN_COUNT,
            .interaction_columns = POSEIDON_INTERACTION_COLUMN_COUNT,
            .direct_constraints = POSEIDON_DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = POSEIDON_INTERACTION_BATCH_COUNT,
            .maximum_constraint_degree = POSEIDON_PROTOCOL_CONSTRAINT_DEGREE,
        };
    }

    pub fn validate(self: PoseidonSourceAuthority) Error!void {
        if (!std.meta.eql(self, pinned()) or
            !std.mem.eql(u8, &self.identityDigest(), &POSEIDON_SOURCE_AUTHORITY_DIGEST))
        {
            return error.ProviderAuthorityMismatch;
        }
        const identity_value = poseidon_identity.ProgramIdentity.canonical();
        try identity_value.validate();
        if (!identity_value.isCanonical() or
            !std.mem.eql(
                u8,
                &identity_value.combined_digest,
                &self.program_identity_digest,
            ))
        {
            return error.ProviderAuthorityMismatch;
        }
    }

    pub fn identityDigest(self: PoseidonSourceAuthority) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(POSEIDON_SOURCE_AUTHORITY_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hash.update(&self.revision);
        hashBytes(&hash, STARK_V_POSEIDON_PATH);
        hash.update(&self.poseidon_source_sha256);
        hashBytes(&hash, STARK_V_AIR_FNS_PATH);
        hash.update(&self.air_fns_source_sha256);
        hash.update(&self.program_identity_digest);
        hashInt(&hash, u16, self.preprocessed_columns);
        hashInt(&hash, u16, self.main_columns);
        hashInt(&hash, u16, self.interaction_columns);
        hashInt(&hash, u16, self.direct_constraints);
        hashInt(&hash, u16, self.interaction_batches);
        hashInt(&hash, u8, self.maximum_constraint_degree);
        return hash.finalResult();
    }
};

/// Stable, caller-owned challenge storage for the two native providers.
///
/// The shipped base Merkle relation has a known 4-vs-18 arity gap and is
/// intentionally initialized to its deterministic dummy value.  No adapter
/// in this module exposes a Merkle component.  Every other base relation has
/// exact universal geometry and is copied from the corresponding `(z, alpha)`
/// draw, preserving the original alpha-power convention.
pub const SharedProviderRelations = struct {
    native: base_relations.Relations,
    registry_order_digest: [32]u8,

    pub fn init(
        source: *const universal.UniversalRelations,
    ) Error!SharedProviderRelations {
        try source.validate();
        // Every exact-schema arity, canonical limb, and cached alpha power is
        // checked while copying. Avoid rebuilding all twelve power tables a
        // second time on this common admission path.
        return SharedProviderRelations.initFromValidatedSource(source);
    }

    /// Validates the copied challenge representation without retaining the
    /// much larger universal bundle. This catches mutable-alias drift in both
    /// `(z, alpha)` and the cached alpha powers before component type erasure.
    pub fn validate(self: *const SharedProviderRelations) Error!void {
        if (!std.mem.eql(
            u8,
            &self.registry_order_digest,
            &relation.registryOrderDigest(),
        )) return error.ChallengeBindingMismatch;
        try validateNativeElement(2, &self.native.registers_state);
        try validateNativeElement(7, &self.native.memory_access);
        try validateNativeElement(5, &self.native.program_access);
        const dummy_merkle = base_relations.RelationElements(4).dummy();
        if (!relationEql(
            4,
            &self.native.merkle,
            &dummy_merkle,
        )) return error.ChallengeBindingMismatch;
        try validateNativeElement(16, &self.native.poseidon2);
        try validateNativeElement(32, &self.native.poseidon2_io);
        try validateNativeElement(4, &self.native.bitwise);
        try validateNativeElement(1, &self.native.range_check_20);
        try validateNativeElement(2, &self.native.range_check_8_11);
        try validateNativeElement(3, &self.native.range_check_8_8_4);
        try validateNativeElement(2, &self.native.range_check_8_8);
        try validateNativeElement(2, &self.native.range_check_m31);
    }

    /// Canonical cold-path receipt used by adapters to detect any mutation of
    /// their caller-owned relation storage between admission and binding.
    pub fn identityDigest(self: *const SharedProviderRelations) Error![32]u8 {
        try self.validate();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(SHARED_RELATION_BINDING_DOMAIN);
        hash.update(&self.registry_order_digest);
        hashRelation(&hash, &self.native.registers_state);
        hashRelation(&hash, &self.native.memory_access);
        hashRelation(&hash, &self.native.program_access);
        hashRelation(&hash, &self.native.merkle);
        hashRelation(&hash, &self.native.poseidon2);
        hashRelation(&hash, &self.native.poseidon2_io);
        hashRelation(&hash, &self.native.bitwise);
        hashRelation(&hash, &self.native.range_check_20);
        hashRelation(&hash, &self.native.range_check_8_11);
        hashRelation(&hash, &self.native.range_check_8_8_4);
        hashRelation(&hash, &self.native.range_check_8_8);
        hashRelation(&hash, &self.native.range_check_m31);
        return hash.finalResult();
    }

    pub fn validateAgainst(
        self: *const SharedProviderRelations,
        source: *const universal.UniversalRelations,
    ) Error!void {
        try source.validate();
        try self.validate();
        if (!std.mem.eql(
            u8,
            &self.registry_order_digest,
            &source.registry_order_digest,
        )) return error.ChallengeBindingMismatch;
        const expected = try SharedProviderRelations.initFromValidatedSource(source);
        if (!nativeRelationsEql(&self.native, &expected.native))
            return error.ChallengeBindingMismatch;
    }

    fn initFromValidatedSource(
        source: *const universal.UniversalRelations,
    ) Error!SharedProviderRelations {
        return .{
            .native = .{
                .registers_state = try relationElements(2, source, .registers_state),
                .memory_access = try relationElements(7, source, .memory_access),
                .program_access = try relationElements(5, source, .program_access),
                .merkle = base_relations.RelationElements(4).dummy(),
                .poseidon2 = try relationElements(16, source, .poseidon2),
                .poseidon2_io = try relationElements(32, source, .poseidon2_io),
                .bitwise = try relationElements(4, source, .bitwise),
                .range_check_20 = try relationElements(1, source, .range_check_20),
                .range_check_8_11 = try relationElements(2, source, .range_check_8_11),
                .range_check_8_8_4 = try relationElements(3, source, .range_check_8_8_4),
                .range_check_8_8 = try relationElements(2, source, .range_check_8_8),
                .range_check_m31 = try relationElements(2, source, .range_check_m31),
            },
            .registry_order_digest = source.registry_order_digest,
        };
    }
};

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
    return struct {
        const Self = @This();

        placement: manifest_contract.Placement,
        component: poseidon_component.HashComponent,
        provider_relations: *const SharedProviderRelations,
        challenge_binding_digest: [32]u8,
        admitted_claims: [poseidon_air.N_SUMS]QM31,

        pub fn manifestGeometry(log_size: u32) manifest_contract.Geometry {
            return .{
                .roster_row = @intFromEnum(roster.Component.poseidon2),
                .log_size = log_size,
                .preprocessed_columns = POSEIDON_PREPROCESSED_COLUMN_COUNT,
                .main_columns = POSEIDON_MAIN_COLUMN_COUNT,
                .interaction_columns = POSEIDON_INTERACTION_COLUMN_COUNT,
                .direct_constraints = POSEIDON_DIRECT_CONSTRAINT_COUNT,
                .interaction_batches = POSEIDON_INTERACTION_BATCH_COUNT,
                .protocol_constraint_degree = POSEIDON_PROTOCOL_CONSTRAINT_DEGREE,
                .profiled_constraint_degree = POSEIDON_PROTOCOL_CONSTRAINT_DEGREE,
                .semantic_digest = POSEIDON_SOURCE_AUTHORITY_DIGEST,
            };
        }

        pub fn init(
            manifest: *const manifest_contract.Manifest,
            log_size: u32,
            n_rows: u32,
            provider_relations: *const SharedProviderRelations,
            universal_relations: *const universal.UniversalRelations,
            claims: [poseidon_air.N_SUMS]QM31,
        ) !Self {
            try manifest.validate();
            try provider_relations.validateAgainst(universal_relations);
            try PoseidonSourceAuthority.pinned().validate();
            for (&claims) |*claim| if (!secureIsCanonical(claim))
                return error.ChallengeBindingMismatch;
            if (log_size == 0 or log_size >= POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT)
                return error.ProviderTraceShapeMismatch;
            const trace_size = @as(u64, 1) << @intCast(log_size);
            if (n_rows > trace_size) return error.ProviderTraceShapeMismatch;
            const placement = try manifest.placement(.poseidon2);
            if (!std.meta.eql(placement.geometry, manifestGeometry(log_size)))
                return error.ProviderGeometryMismatch;
            const preprocessed_offset: usize = placement.preprocessed_offset;
            const main_offset: usize = placement.main_offset;
            const interaction_offset: usize = placement.interaction_offset;
            return .{
                .placement = placement,
                .provider_relations = provider_relations,
                .challenge_binding_digest = try provider_relations.identityDigest(),
                .admitted_claims = claims,
                .component = .{
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
            try validatePlacementForManifest(manifest_contract, manifest, self.placement, manifestGeometry(
                self.placement.geometry.log_size,
            ));
            try PoseidonSourceAuthority.pinned().validate();
            const challenge_digest = try self.provider_relations.identityDigest();
            if (!std.mem.eql(
                u8,
                &challenge_digest,
                &self.challenge_binding_digest,
            ) or self.component.relations != &self.provider_relations.native) {
                return error.ChallengeBindingMismatch;
            }
            for (0..poseidon_air.N_SUMS) |index| {
                const actual = &self.component.poseidon_claims[index];
                const expected = &self.admitted_claims[index];
                if (!secureIsCanonical(actual) or !secureEql(actual, expected))
                    return error.ChallengeBindingMismatch;
            }
            if (self.component.kind != .poseidon2 or
                self.component.poseidon_shell != .universal or
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
                    POSEIDON_DIRECT_CONSTRAINT_COUNT + POSEIDON_INTERACTION_BATCH_COUNT)
            {
                return error.ProviderAuthorityMismatch;
            }
            return .{
                .manifest_seal = manifest.seal,
                .placement = self.placement,
                .claimed_sum = self.component.poseidon_claims[0].add(
                    self.component.poseidon_claims[1],
                ),
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

        pub fn manifestGeometry() manifest_contract.Geometry {
            return .{
                .roster_row = @intFromEnum(roster.Component.range_check_8_8),
                .log_size = range_bridge.LOG_SIZE,
                .preprocessed_columns = RANGE_PREPROCESSED_COLUMN_COUNT,
                .main_columns = RANGE_MAIN_COLUMN_COUNT,
                .interaction_columns = RANGE_INTERACTION_COLUMN_COUNT,
                .direct_constraints = RANGE_DIRECT_CONSTRAINT_COUNT,
                .interaction_batches = RANGE_INTERACTION_BATCH_COUNT,
                .protocol_constraint_degree = RANGE_PROTOCOL_CONSTRAINT_DEGREE,
                .profiled_constraint_degree = RANGE_PROTOCOL_CONSTRAINT_DEGREE,
                .semantic_digest = range_bridge.BINDING_DIGEST,
            };
        }

        pub fn init(
            definition: *const range_bridge.Definition,
            executor: *const range_bridge.Executor,
            manifest: *const manifest_contract.Manifest,
            provider_relations: *const SharedProviderRelations,
            universal_relations: *const universal.UniversalRelations,
            claim: QM31,
        ) !Self {
            try manifest.validate();
            try provider_relations.validateAgainst(universal_relations);
            if (!secureIsCanonical(&claim)) return error.ChallengeBindingMismatch;
            try definition.validate();
            try executor.validate();
            const canonical = try range_bridge.Binding.canonical(definition);
            if (!std.meta.eql(canonical, executor.binding))
                return error.ProviderAuthorityMismatch;
            const placement = try manifest.placement(.range_check_8_8);
            if (!std.meta.eql(placement.geometry, manifestGeometry()))
                return error.ProviderGeometryMismatch;
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
            return .{
                .manifest_seal = manifest.seal,
                .placement = self.placement,
                .claimed_sum = self.component.claim,
                .verifier = self.component.asVerifierComponent(),
                .prover = self.component.asProverComponent(),
            };
        }
    };
}

fn relationElements(
    comptime arity: usize,
    source: *const universal.UniversalRelations,
    domain: relation.Domain,
) Error!base_relations.RelationElements(arity) {
    const schema = try relation.requireExactUniversalSchema(domain);
    const element = source.get(domain);
    if (schema.fields.len != arity or element.arity != arity)
        return error.ChallengeBindingMismatch;
    if (!secureIsCanonical(&element.z) or !secureIsCanonical(&element.alpha))
        return error.ChallengeBindingMismatch;
    for (element.alpha_powers[0..arity]) |*power| {
        if (!secureIsCanonical(power)) return error.ChallengeBindingMismatch;
    }
    const result = base_relations.RelationElements(arity).init(
        element.z,
        element.alpha,
    );
    for (0..arity) |index| {
        if (!secureEql(&result.alpha_powers[index], &element.alpha_powers[index]))
            return error.ChallengeBindingMismatch;
    }
    return result;
}

fn validateNativeElement(
    comptime arity: usize,
    element: *const base_relations.RelationElements(arity),
) Error!void {
    if (!secureIsCanonical(&element.z) or !secureIsCanonical(&element.alpha))
        return error.ChallengeBindingMismatch;
    for (&element.alpha_powers) |*power| {
        if (!secureIsCanonical(power)) return error.ChallengeBindingMismatch;
    }
    const expected = base_relations.RelationElements(arity).init(
        element.z,
        element.alpha,
    );
    if (!relationEql(arity, element, &expected))
        return error.ChallengeBindingMismatch;
}

fn nativeRelationsEql(
    lhs: *const base_relations.Relations,
    rhs: *const base_relations.Relations,
) bool {
    return relationEql(2, &lhs.registers_state, &rhs.registers_state) and
        relationEql(7, &lhs.memory_access, &rhs.memory_access) and
        relationEql(5, &lhs.program_access, &rhs.program_access) and
        relationEql(4, &lhs.merkle, &rhs.merkle) and
        relationEql(16, &lhs.poseidon2, &rhs.poseidon2) and
        relationEql(32, &lhs.poseidon2_io, &rhs.poseidon2_io) and
        relationEql(4, &lhs.bitwise, &rhs.bitwise) and
        relationEql(1, &lhs.range_check_20, &rhs.range_check_20) and
        relationEql(2, &lhs.range_check_8_11, &rhs.range_check_8_11) and
        relationEql(3, &lhs.range_check_8_8_4, &rhs.range_check_8_8_4) and
        relationEql(2, &lhs.range_check_8_8, &rhs.range_check_8_8) and
        relationEql(2, &lhs.range_check_m31, &rhs.range_check_m31);
}

fn relationEql(
    comptime arity: usize,
    lhs: *const base_relations.RelationElements(arity),
    rhs: *const base_relations.RelationElements(arity),
) bool {
    if (!secureEql(&lhs.z, &rhs.z) or !secureEql(&lhs.alpha, &rhs.alpha))
        return false;
    for (0..arity) |index| {
        if (!secureEql(&lhs.alpha_powers[index], &rhs.alpha_powers[index]))
            return false;
    }
    return lhs.alpha_powers.len == arity;
}

fn secureEql(lhs: *const QM31, rhs: *const QM31) bool {
    return lhs.c0.a.v == rhs.c0.a.v and
        lhs.c0.b.v == rhs.c0.b.v and
        lhs.c1.a.v == rhs.c1.a.v and
        lhs.c1.b.v == rhs.c1.b.v;
}

fn secureIsCanonical(value: *const QM31) bool {
    return value.c0.a.v < m31.Modulus and
        value.c0.b.v < m31.Modulus and
        value.c1.a.v < m31.Modulus and
        value.c1.b.v < m31.Modulus;
}

fn hashRelation(hash: anytype, element: anytype) void {
    hashInt(hash, u8, element.alpha_powers.len);
    hashSecure(hash, &element.z);
    hashSecure(hash, &element.alpha);
    for (&element.alpha_powers) |*power| hashSecure(hash, power);
}

fn hashSecure(hash: anytype, value: *const QM31) void {
    hashInt(hash, u32, value.c0.a.v);
    hashInt(hash, u32, value.c0.b.v);
    hashInt(hash, u32, value.c1.a.v);
    hashInt(hash, u32, value.c1.b.v);
}

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

fn hashBytes(hash: anytype, value: []const u8) void {
    hashInt(hash, u32, value.len);
    hash.update(value);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn hexDigest(
    comptime value: []const u8,
    comptime message: []const u8,
) [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

comptime {
    if (POSEIDON_MAIN_COLUMN_COUNT != 445 or
        POSEIDON_INTERACTION_COLUMN_COUNT != 8 or
        POSEIDON_DIRECT_CONSTRAINT_COUNT != 430 or
        RANGE_PREPROCESSED_COLUMN_COUNT != 3 or
        RANGE_MAIN_COLUMN_COUNT != 1 or
        RANGE_INTERACTION_COLUMN_COUNT != 4 or
        POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT != 30)
    {
        @compileError("universal shared-provider geometry drifted");
    }
}
