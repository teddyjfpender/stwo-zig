//! Internal shard of binary_fri_outer_bundle.zig; use the public facade.

const dependency_1 = @import("binary_fri_outer_bundle_bundle_for_source_schedule_and_manifest.zig");
const dependency_2 = @import("binary_fri_outer_bundle_bind_owned_columns.zig");

const BundleForSourceScheduleAndManifest = dependency_1.BundleForSourceScheduleAndManifest;
const validateAudits = dependency_2.validateAudits;
const hashClaims = dependency_2.hashClaims;
const hashSecure = dependency_2.hashSecure;
const hashInt = dependency_2.hashInt;
const allZero = dependency_2.allZero;
const sum = dependency_2.sum;

pub const std = @import("std");

pub const component_init = @import("binary_fri_outer_bundle_component_init.zig");

pub const bundle_init = @import("binary_fri_outer_bundle_init.zig");

pub const main_fill = @import("binary_fri_outer_bundle_main_fill.zig");

pub const generated_audit = @import("binary_fri_outer_bundle_generated_audit.zig");

pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;

pub const QM31 = stwo_core.fields.qm31.QM31;

pub const source_mod = @import("binary_fri_outer_source.zig");

pub const fixed_wire = @import("fixed_wire.zig");

pub const digest = @import("../air/lang/digest.zig");

pub const logup = @import("../air/logup.zig");

pub const poseidon_air = @import("../air/memory_commitment/poseidon2_air.zig");

pub const poseidon_authority_mod = @import("../air/lang/typed_poseidon2_authority.zig");

pub const poseidon_identity = @import("../air/lang/typed_poseidon2_identity.zig");

pub const composition_input_air = @import("air/vm_air_composition_input.zig");

pub const composition_input_relation = @import("air/vm_air_composition_input_relation.zig");

pub const composition_control_air = @import("air/vm_air_composition_control.zig").Air;

pub const query_bits_air = @import("air/query_bits.zig");

pub const query_bits_relation = @import("air/query_bits_relation.zig");

pub const query_mapping_air = @import("air/query_mapping.zig");

pub const query_mapping_relation = @import("air/query_mapping_relation.zig");

pub const merkle_root_air = @import("air/merkle_root.zig");

pub const merkle_root_relation = @import("air/merkle_root_relation.zig");

pub const trace_merkle_air = @import("air/trace_merkle.zig");

pub const trace_merkle_relation = @import("air/trace_merkle_relation.zig");

pub const pcs_air = @import("air/pcs_deep_input.zig");

pub const pcs_relation = @import("air/pcs_deep_input_relation.zig");

pub const fri_leaf_air = @import("air/fri_merkle_leaf.zig");

pub const fri_leaf_relation = @import("air/fri_merkle_leaf_relation.zig");

pub const fri_node_air = @import("air/fri_merkle_node.zig");

pub const fri_node_relation = @import("air/fri_merkle_node_relation.zig");

pub const fri_anchor_air = @import("air/fri_merkle_anchor.zig");

pub const fri_anchor_relation = @import("air/fri_merkle_anchor_relation.zig");

pub const fri_control_air = @import("air/fri_verifier_control.zig");

pub const fri_control_relation = @import("air/fri_verifier_control_relation.zig");

pub const fri_input_air = @import("air/fri_verifier_input.zig");

pub const fri_input_relation = @import("air/fri_verifier_input_relation.zig");

pub const multiply_air = @import("air/qm31_mul_full.zig");

pub const inverse_air = @import("air/qm31_inv.zig");

pub const linear_air = @import("air/linear_ops.zig");

pub const merkle_path_air = @import("air/merkle_path.zig");

pub const merkle_path_relation = @import("air/merkle_path_relation.zig");

pub const default_manifest = @import("air/universal_adapter_manifest.zig");

pub const relation_interaction = @import("air/relation_interaction.zig");

pub const shared_provider = @import("air/universal_shared_provider.zig");

pub const shared_schedule_v2 = @import("segment_shared_poseidon_schedule_v2.zig");

pub const typed_component = @import("air/universal_typed_component.zig");

pub const universal = @import("air/universal_challenges.zig");

pub const universal_binding = @import("air/universal_relation_binding.zig");

pub const CompositionControlRelation = universal_binding.Binding(composition_control_air);

pub const MultiplyRelation = universal_binding.Binding(multiply_air);

pub const InverseRelation = universal_binding.Binding(inverse_air);

pub const LinearRelation = universal_binding.Binding(linear_air);

pub fn AdaptersForManifest(comptime manifest_contract: type) type {
    return struct {
        pub const CompositionInput = typed_component.ComponentForManifest(
            composition_input_air,
            composition_input_relation,
            manifest_contract,
        );
        pub const CompositionControl = typed_component.ComponentForManifest(
            composition_control_air,
            CompositionControlRelation,
            manifest_contract,
        );
        pub const QueryBits = typed_component.ComponentForManifest(
            query_bits_air,
            query_bits_relation,
            manifest_contract,
        );
        pub const QueryMapping = typed_component.ComponentForManifest(
            query_mapping_air,
            query_mapping_relation,
            manifest_contract,
        );
        pub const MerkleRoot = typed_component.ComponentForManifest(
            merkle_root_air,
            merkle_root_relation,
            manifest_contract,
        );
        pub const TraceMerkle = typed_component.ComponentForManifest(
            trace_merkle_air,
            trace_merkle_relation,
            manifest_contract,
        );
        pub const Pcs = typed_component.ComponentForManifest(
            pcs_air,
            pcs_relation,
            manifest_contract,
        );
        pub const FriLeaf = typed_component.ComponentForManifest(
            fri_leaf_air,
            fri_leaf_relation,
            manifest_contract,
        );
        pub const FriNode = typed_component.ComponentForManifest(
            fri_node_air,
            fri_node_relation,
            manifest_contract,
        );
        pub const FriAnchor = typed_component.ComponentForManifest(
            fri_anchor_air,
            fri_anchor_relation,
            manifest_contract,
        );
        pub const FriControl = typed_component.ComponentForManifest(
            fri_control_air,
            fri_control_relation,
            manifest_contract,
        );
        pub const FriInput = typed_component.ComponentForManifest(
            fri_input_air,
            fri_input_relation,
            manifest_contract,
        );
        pub const Multiply = typed_component.ComponentForManifest(
            multiply_air,
            MultiplyRelation,
            manifest_contract,
        );
        pub const Inverse = typed_component.ComponentForManifest(
            inverse_air,
            InverseRelation,
            manifest_contract,
        );
        pub const Linear = typed_component.ComponentForManifest(
            linear_air,
            LinearRelation,
            manifest_contract,
        );
        pub const MerklePath = typed_component.ComponentForManifest(
            merkle_path_air,
            merkle_path_relation,
            manifest_contract,
        );
        pub const Poseidon2 = shared_provider.Poseidon2AdapterForManifest(
            manifest_contract,
        );
    };
}

pub const DefaultAdapters = AdaptersForManifest(default_manifest);

pub const CompositionInputAdapter = DefaultAdapters.CompositionInput;

pub const CompositionControlAdapter = DefaultAdapters.CompositionControl;

pub const QueryBitsAdapter = DefaultAdapters.QueryBits;

pub const QueryMappingAdapter = DefaultAdapters.QueryMapping;

pub const MerkleRootAdapter = DefaultAdapters.MerkleRoot;

pub const TraceMerkleAdapter = DefaultAdapters.TraceMerkle;

pub const PcsAdapter = DefaultAdapters.Pcs;

pub const FriLeafAdapter = DefaultAdapters.FriLeaf;

pub const FriNodeAdapter = DefaultAdapters.FriNode;

pub const FriAnchorAdapter = DefaultAdapters.FriAnchor;

pub const FriControlAdapter = DefaultAdapters.FriControl;

pub const FriInputAdapter = DefaultAdapters.FriInput;

pub const MultiplyAdapter = DefaultAdapters.Multiply;

pub const InverseAdapter = DefaultAdapters.Inverse;

pub const LinearAdapter = DefaultAdapters.Linear;

pub const MerklePathAdapter = DefaultAdapters.MerklePath;

pub const FORMAT_VERSION: u16 = 1;

pub const GENERATED_FORMAT_VERSION: u16 = 1;

pub const AUDITED_FORMAT_VERSION: u16 = 1;

pub const PROTOCOL_SUBSTRATE_ONLY = true;

pub const WHOLE_FRONTEND_VERIFIED = false;

pub const COMPLETE_PARENT_STARK_VERIFIED = false;

pub const PRODUCTION_ACTIVATION = false;

pub const CHILD_ROLE_SESSION_AUTHORITY_VERSION: ?u16 = null;

pub const ProviderCustody = enum(u8) {
    local_core = 0,
    complete_shared_schedule_v2 = 1,
    pending_shared_schedule = 2,
};

pub const FIRST_ROW = source_mod.FIRST_ROW;

pub const LAST_ROW = source_mod.LAST_ROW;

pub const ROW_COUNT = source_mod.ROW_COUNT;

pub const TYPED_ROW_COUNT = source_mod.TYPED_RELATION_ROW_COUNT;

pub const PREPROCESSED_COLUMNS_PER_ROW =
    source_mod.COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW ++
    source_mod.PREPROCESSED_COLUMNS_PER_ROW ++
    source_mod.ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW ++
    .{ 0, shared_provider.POSEIDON_PREPROCESSED_COLUMN_COUNT };

pub const MAIN_COLUMNS_PER_ROW =
    source_mod.COMPOSITION_MAIN_COLUMNS_PER_ROW ++
    source_mod.MAIN_COLUMNS_PER_ROW ++
    source_mod.ARITHMETIC_MAIN_COLUMNS_PER_ROW ++
    .{ source_mod.MERKLE_PATH_MAIN_COLUMN_COUNT, poseidon_air.N_MAIN_COLUMNS };

pub const INTERACTION_COLUMNS_PER_ROW =
    source_mod.TYPED_INTERACTION_COLUMNS_PER_ROW ++
    .{poseidon_air.N_INTERACTION_COLUMNS};

pub const PREPROCESSED_COLUMN_COUNT = sum(&PREPROCESSED_COLUMNS_PER_ROW);

pub const MAIN_COLUMN_COUNT = sum(&MAIN_COLUMNS_PER_ROW);

pub const INTERACTION_COLUMN_COUNT = sum(&INTERACTION_COLUMNS_PER_ROW);

pub const HOT_TREE_HEAP_ALLOCATIONS = [_]usize{0} ** default_manifest.TREE_COUNT;

pub const HOT_ALL_TREES_HEAP_ALLOCATIONS: usize = 0;

pub const ROW34_REPLAYED_SCALAR_PERMUTATIONS: usize = 0;

pub const BUNDLE_ID_DOMAIN =
    "stwo-zig/typed-air/binary-fri-outer-bundle/v1\x00";

pub const GENERATED_ID_DOMAIN =
    "stwo-zig/typed-air/binary-fri-outer-generated/v1\x00";

pub const AUDITED_ID_DOMAIN =
    "stwo-zig/typed-air/binary-fri-outer-audited/v1\x00";

pub const Error = error{
    ArithmeticOverflow,
    AuditIdentityMismatch,
    BundleIdentityMismatch,
    DestinationAlias,
    DestinationNotZero,
    GeneratedIdentityMismatch,
    InvalidTraceShape,
    NonCanonicalField,
    ParameterMismatch,
    ProviderClaimMismatch,
    ProviderIdentityMismatch,
    ProviderScratchExhausted,
    RowsNotPrepared,
};

pub const Claims = source_mod.Claims;

pub const DomainAudits = source_mod.DomainAudits;

/// Pointer-free publication emitted only after all 17 interaction rows have
/// been generated from retained authority. Row 34 keeps its two native
/// recurrence claims; `poseidon2Total` is only the roster projection.
pub const GeneratedInteractionsV1 = struct {
    format_version: u16 = GENERATED_FORMAT_VERSION,
    padding: [6]u8 = [_]u8{0} ** 6,
    bundle_id: digest.Digest,
    relation_registry_id: digest.Digest,
    provider_relation_id: digest.Digest,
    provider_program_id: digest.Digest,
    retained_rows_id: digest.Digest,
    merkle_provider_batch_id: digest.Digest,
    claims: Claims,
    identity: digest.Digest,

    pub fn validateAgainst(
        self: *const GeneratedInteractionsV1,
        bundle: anytype,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        try bundle.validateGeneratedInteractions(self, relations, provider_relations);
    }

    /// Canonical pointer-free receipt identity. This is an integrity seal, not
    /// claim authority; independently rebuilding the domains is what rejects
    /// a consistently re-sealed claim forgery.
    pub fn identityDigest(self: *const GeneratedInteractionsV1) digest.Digest {
        return generatedIdentity(self);
    }
};

/// Independent domain replay of the generated claims. This remains a
/// prover-side/cold audit receipt; it is not mislabeled as final recursive
/// verifier custody while the parent protocol is substrate-only.
pub const AuditedInteractionsV1 = struct {
    format_version: u16 = AUDITED_FORMAT_VERSION,
    padding: [6]u8 = [_]u8{0} ** 6,
    generated: GeneratedInteractionsV1,
    audits: DomainAudits,
    identity: digest.Digest,

    pub fn validateAgainst(
        self: *const AuditedInteractionsV1,
        bundle: anytype,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
    ) !void {
        if (self.format_version != AUDITED_FORMAT_VERSION or
            !allZero(&self.padding)) return error.AuditIdentityMismatch;
        try self.generated.validateAgainst(bundle, relations, provider_relations);
        try validateAudits(self.audits, self.generated.claims);
        if (!std.mem.eql(u8, &self.identity, &auditedIdentity(self)))
            return error.AuditIdentityMismatch;
    }
};

pub fn ComponentsForManifest(comptime manifest_contract: type) type {
    const Adapters = AdaptersForManifest(manifest_contract);
    return struct {
        const Self = @This();

        composition_input: Adapters.CompositionInput,
        composition_control: Adapters.CompositionControl,
        query_bits: Adapters.QueryBits,
        query_mapping: Adapters.QueryMapping,
        merkle_root: Adapters.MerkleRoot,
        trace_merkle: Adapters.TraceMerkle,
        pcs_deep: Adapters.Pcs,
        fri_leaf: Adapters.FriLeaf,
        fri_node: Adapters.FriNode,
        fri_anchor: Adapters.FriAnchor,
        fri_control: Adapters.FriControl,
        fri_input: Adapters.FriInput,
        multiply: Adapters.Multiply,
        inverse: Adapters.Inverse,
        linear: Adapters.Linear,
        merkle_path: Adapters.MerklePath,
        poseidon2: Adapters.Poseidon2,

        /// Appends rows 18--34 in exact roster order for the selected
        /// versioned manifest contract.
        pub fn appendToGate(
            self: *const Self,
            manifest: *const manifest_contract.Manifest,
            gate: *manifest_contract.ProofGate,
        ) !void {
            try gate.append(manifest, try self.composition_input.binding(manifest));
            try gate.append(manifest, try self.composition_control.binding(manifest));
            try gate.append(manifest, try self.query_bits.binding(manifest));
            try gate.append(manifest, try self.query_mapping.binding(manifest));
            try gate.append(manifest, try self.merkle_root.binding(manifest));
            try gate.append(manifest, try self.trace_merkle.binding(manifest));
            try gate.append(manifest, try self.pcs_deep.binding(manifest));
            try gate.append(manifest, try self.fri_leaf.binding(manifest));
            try gate.append(manifest, try self.fri_node.binding(manifest));
            try gate.append(manifest, try self.fri_anchor.binding(manifest));
            try gate.append(manifest, try self.fri_control.binding(manifest));
            try gate.append(manifest, try self.fri_input.binding(manifest));
            try gate.append(manifest, try self.multiply.binding(manifest));
            try gate.append(manifest, try self.inverse.binding(manifest));
            try gate.append(manifest, try self.linear.binding(manifest));
            try gate.append(manifest, try self.merkle_path.binding(manifest));
            try gate.append(manifest, try self.poseidon2.binding(manifest));
        }
    };
}

pub const Components = ComponentsForManifest(default_manifest);

/// Owns every cold workspace needed by the neutral rows-18--34 cohort.
pub fn Bundle(comptime dimensions: fixed_wire.Dimensions) type {
    return BundleForManifest(dimensions, default_manifest);
}

/// Version-parametric concrete owner for rows 18--34. The AIR programs and
/// witness source remain unique; only manifest/claim/gate placement changes.
pub fn BundleForManifest(
    comptime dimensions: fixed_wire.Dimensions,
    comptime manifest_contract: type,
) type {
    return BundleForSourceAndManifest(
        dimensions,
        source_mod.Source(dimensions),
        manifest_contract,
    );
}

/// Authority-parametric owner for rows 18--34.  The source type is a narrow
/// dependency-injection seam for independently authenticated child-proof
/// profiles (for example the 39-claim SegmentV2 temporal child).  It must
/// expose the exact `binary_fri_outer_source.Source` contract; all AIR,
/// witness, provider, and hot-writer implementations remain unique here.
///
/// Keeping this seam at comptime preserves direct calls and monomorphized hot
/// loops.  There is no virtual dispatch, function-pointer table, or runtime
/// proof-kind branch in the trace-generation path.
pub fn BundleForSourceAndManifest(
    comptime dimensions: fixed_wire.Dimensions,
    comptime Source: type,
    comptime manifest_contract: type,
) type {
    const FrozenV2Schedule = struct {
        pub const Layout = shared_schedule_v2.SharedPoseidonCallLayoutV2;
        pub const Call = shared_schedule_v2.Call;
    };
    return BundleForSourceScheduleAndManifest(
        dimensions,
        Source,
        FrozenV2Schedule,
        manifest_contract,
    );
}

pub fn generatedIdentity(value: *const GeneratedInteractionsV1) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(GENERATED_ID_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hash.update(&value.padding);
    hash.update(&value.bundle_id);
    hash.update(&value.relation_registry_id);
    hash.update(&value.provider_relation_id);
    hash.update(&value.provider_program_id);
    hash.update(&value.retained_rows_id);
    hash.update(&value.merkle_provider_batch_id);
    hashClaims(&hash, value.claims);
    return hash.finalResult();
}

pub fn auditedIdentity(value: *const AuditedInteractionsV1) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUDITED_ID_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hash.update(&value.padding);
    hash.update(&value.generated.identity);
    for (value.audits.typed_rows) |audit| {
        for (audit.values) |item| hashSecure(&hash, item);
        hashSecure(&hash, audit.total);
        hashInt(&hash, u64, audit.logical_rows);
        hashInt(&hash, u64, audit.event_terms);
    }
    hashSecure(&hash, value.audits.poseidon2.poseidon2);
    hashSecure(&hash, value.audits.poseidon2.poseidon2_io);
    hashSecure(&hash, value.audits.poseidon2.total);
    return hash.finalResult();
}
